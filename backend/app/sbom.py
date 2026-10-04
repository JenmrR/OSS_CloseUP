"""SBOM(SPDX JSON) 다운로드.

worker가 저장한 artifact를 그대로 전달한다. 내용을 다시 만들거나 고치지 않는다.
전달 전에 DB에 기록된 크기와 SHA-256으로 파일이 그대로인지 확인한다.
"""
import hashlib
import logging
import os
from pathlib import Path, PurePosixPath
from uuid import UUID

import psycopg
from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse
from psycopg.rows import dict_row

from .db import connect

router = APIRouter()
log = logging.getLogger(__name__)

# worker의 SCAN_RESULTS_ROOT와 같은 볼륨을 backend에 읽기 전용으로 마운트해야 한다.
RESULTS_ROOT = Path(os.environ.get("SCAN_RESULTS_ROOT", "/work/results"))

# 해시 재계산 상한. 넘으면 크기만 확인하고 그 사실을 응답 헤더로 알린다.
HASH_VERIFY_MAX_BYTES = 64 * 1024 * 1024

# DB의 media_type을 헤더에 그대로 넣지 않는다(헤더 주입 방지). 허용 목록만 통과.
ALLOWED_MEDIA_TYPES = {"application/json", "application/spdx+json"}
DEFAULT_MEDIA_TYPE = "application/json"

# 최신 성공 도구 실행의 SBOM을 우선한다. tool_run_id가 비어 있는 과거 행도 버리지 않는다.
SBOM_ARTIFACT_SQL = """
SELECT a.artifact_id, a.storage_key, a.sha256, a.size_bytes, a.media_type, a.created_at,
       r.tool_name, r.attempt_no, r.status AS tool_run_status
  FROM scan_artifacts a
  LEFT JOIN scan_tool_runs r
         ON r.scan_id = a.scan_id AND r.tool_run_id = a.tool_run_id
 WHERE a.scan_id = %s AND a.kind = 'sbom' AND a.deleted_at IS NULL
 ORDER BY (r.status = 'completed') DESC NULLS LAST,
          r.attempt_no DESC NULLS LAST,
          a.created_at DESC
 LIMIT 1
"""

SYFT_RUN_SQL = """
SELECT status, attempt_no, error_message, tool_version
  FROM scan_tool_runs
 WHERE scan_id = %s AND lower(tool_name) = 'syft'
 ORDER BY attempt_no DESC
 LIMIT 1
"""


def _syft_state(run):
    """아직 안 돈 것과 돌았는데 없는 것을 구분해서 돌려준다."""
    if run is None:
        return {"status": "pending"}
    return {
        "status": run["status"],
        "attempt_no": run["attempt_no"],
        "tool_version": run["tool_version"],
        "error_message": run["error_message"],
    }


def _lookup(scan_id: UUID):
    try:
        with connect() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute("SELECT status FROM scan_runs WHERE scan_id=%s", (scan_id,))
                scan = cur.fetchone()
                if scan is None:
                    return None, None, None
                cur.execute(SBOM_ARTIFACT_SQL, (scan_id,))
                artifact = cur.fetchone()
                cur.execute(SYFT_RUN_SQL, (scan_id,))
                run = cur.fetchone()
    except psycopg.Error:
        log.exception("SBOM lookup failed; scan_id=%s", scan_id)
        raise HTTPException(503, "DB 조회에 실패했습니다.") from None
    return scan, artifact, run


def _resolve(storage_key: str, scan_id: UUID) -> Path:
    """storage_key를 결과 루트 안쪽으로만 해석한다. 밖으로 나가면 거부."""
    if "\\" in storage_key or "\x00" in storage_key:
        log.error("Rejected storage_key with unexpected characters; scan_id=%s", scan_id)
        raise HTTPException(500, "SBOM 경로가 올바르지 않습니다.")
    key = PurePosixPath(storage_key)
    if key.is_absolute() or any(part in ("..", "") for part in key.parts):
        log.error("Rejected non-relative storage_key; scan_id=%s", scan_id)
        raise HTTPException(500, "SBOM 경로가 올바르지 않습니다.")

    root = RESULTS_ROOT.resolve()
    # resolve()가 심볼릭 링크까지 따라간 뒤에 포함 관계를 확인해야 링크 탈출을 막는다.
    path = (root / key).resolve()
    if path != root and root not in path.parents:
        log.error("Rejected storage_key escaping results root; scan_id=%s", scan_id)
        raise HTTPException(500, "SBOM 경로가 올바르지 않습니다.")
    return path


def _digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _not_available(scan, run):
    """SBOM 없음을 '0건'이 아니라 '아직 없음'으로 구분해서 알린다."""
    return HTTPException(
        status_code=404,
        detail={
            "reason": "sbom_not_available",
            "scan_status": scan["status"],
            "syft": _syft_state(run),
            "message": "SBOM이 아직 생성되지 않았습니다. 패키지가 0개라는 뜻이 아닙니다.",
        },
    )


@router.get("/scans/{scan_id}/sbom/info")
def sbom_info(scan_id: UUID):
    """대시보드가 다운로드 버튼을 켤지 정할 때 쓰는 가벼운 조회."""
    scan, artifact, run = _lookup(scan_id)
    if scan is None:
        raise HTTPException(404, "검사를 찾을 수 없습니다.")
    if artifact is None:
        return {
            "scan_id": str(scan_id),
            "available": False,
            "scan_status": scan["status"],
            "syft": _syft_state(run),
        }
    return {
        "scan_id": str(scan_id),
        "available": True,
        "scan_status": scan["status"],
        "syft": _syft_state(run),
        "artifact": {
            "artifact_id": str(artifact["artifact_id"]),
            "sha256": artifact["sha256"],
            "size_bytes": artifact["size_bytes"],
            "media_type": artifact["media_type"],
            "created_at": artifact["created_at"],
            "tool_run_status": artifact["tool_run_status"],
            "attempt_no": artifact["attempt_no"],
        },
        "download_url": f"/scans/{scan_id}/sbom",
        "filename": f"sbom-{scan_id}.spdx.json",
    }


@router.get("/scans/{scan_id}/sbom")
def download_sbom(scan_id: UUID):
    scan, artifact, run = _lookup(scan_id)
    if scan is None:
        raise HTTPException(404, "검사를 찾을 수 없습니다.")
    if artifact is None:
        raise _not_available(scan, run)

    path = _resolve(artifact["storage_key"], scan_id)
    try:
        stat = path.stat()
    except OSError:
        log.error("SBOM artifact row exists but file is missing; scan_id=%s artifact_id=%s",
                  scan_id, artifact["artifact_id"])
        raise HTTPException(500, "SBOM 파일을 찾을 수 없습니다. 서버 로그를 확인해 주세요.") from None
    if not path.is_file():
        log.error("SBOM path is not a regular file; scan_id=%s", scan_id)
        raise HTTPException(500, "SBOM 파일을 찾을 수 없습니다. 서버 로그를 확인해 주세요.")

    if stat.st_size != artifact["size_bytes"]:
        log.error("SBOM size mismatch; scan_id=%s db=%s disk=%s",
                  scan_id, artifact["size_bytes"], stat.st_size)
        raise HTTPException(500, "SBOM 파일이 기록과 다릅니다. 서버 로그를 확인해 주세요.")

    if stat.st_size <= HASH_VERIFY_MAX_BYTES:
        if _digest(path) != artifact["sha256"]:
            log.error("SBOM digest mismatch; scan_id=%s artifact_id=%s", scan_id, artifact["artifact_id"])
            raise HTTPException(500, "SBOM 파일 무결성 검증에 실패했습니다. 서버 로그를 확인해 주세요.")
        verified = "sha256"
    else:
        verified = "size-only"

    media_type = artifact["media_type"] if artifact["media_type"] in ALLOWED_MEDIA_TYPES else DEFAULT_MEDIA_TYPE
    # 파일명에 scan_id(UUID)만 쓴다. 사용자가 올린 원본 파일명은 헤더에 넣지 않는다.
    return FileResponse(
        path,
        media_type=media_type,
        headers={
            "Content-Disposition": f'attachment; filename="sbom-{scan_id}.spdx.json"',
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store",
            "X-Artifact-Sha256": artifact["sha256"],
            "X-Artifact-Verified": verified,
            "X-Tool-Run-Status": artifact["tool_run_status"] or "unknown",
        },
    )
