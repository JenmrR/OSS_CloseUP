"""AI 설명 조회 API.

LLM 호출은 아직 붙이지 않았다(API 미선정). 이 모듈은 저장된 설명을 상태와 함께 돌려주기만 한다.
- 설명이 없으면 404가 아니라 status='not_generated'로 응답한다. 검사 결과 화면을 막지 않기 위해서다.
- succeeded일 때만 본문(output)을 내보낸다. failed/rejected는 사유 코드만 보여준다.
- 검사 사실(심각도·우선순위·수정 후보)은 여기서 다루지 않는다.
"""
from uuid import UUID

from fastapi import APIRouter, HTTPException
from psycopg.rows import dict_row

from .db import connect

router = APIRouter()

SCAN_SQL = "SELECT scan_id, status FROM scan_runs WHERE scan_id = %s"

REPORT_SQL = """
SELECT analysis_id, scope, finding_id, status, attempt_no, provider, model, prompt_version,
       input_fingerprint, output, validation, error_code, created_at, finished_at
  FROM ai_analyses
 WHERE scan_id = %s AND scope = 'scan_report'
 ORDER BY created_at DESC, attempt_no DESC
 LIMIT 1
"""

FINDINGS_SQL = """
SELECT DISTINCT ON (finding_id)
       analysis_id, scope, finding_id, status, attempt_no, provider, model, prompt_version,
       input_fingerprint, output, validation, error_code, created_at, finished_at
  FROM ai_analyses
 WHERE scan_id = %s AND scope = 'finding'
 ORDER BY finding_id, created_at DESC, attempt_no DESC
"""

# 화면에 그대로 노출해도 되는 실패 사유 안내. 원문 오류 메시지는 내보내지 않는다.
ERROR_MESSAGES = {
    "timeout": "설명 생성 시간이 초과되었습니다.",
    "provider_error": "설명 생성 서비스에서 오류가 발생했습니다.",
    "validation_failed": "생성된 설명이 검사 결과와 맞지 않아 표시하지 않습니다.",
    "budget_exceeded": "설명 생성 한도를 넘었습니다.",
}


def _load_scan(scan_id: UUID):
    with connect() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(SCAN_SQL, (scan_id,))
        return cur.fetchone()


def _load_report(scan_id: UUID):
    with connect() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(REPORT_SQL, (scan_id,))
        return cur.fetchone()


def _load_findings(scan_id: UUID):
    with connect() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(FINDINGS_SQL, (scan_id,))
        return cur.fetchall()


def _present(row):
    """DB 행을 화면용 응답으로 바꾼다. 본문은 succeeded일 때만 포함한다."""
    if row is None:
        return {"status": "not_generated"}
    body = {
        "status": row["status"],
        "analysis_id": str(row["analysis_id"]),
        "attempt_no": row["attempt_no"],
        "model": row["model"],
        "prompt_version": row["prompt_version"],
        "input_fingerprint": row["input_fingerprint"],
        "created_at": row["created_at"].isoformat() if row["created_at"] else None,
        "finished_at": row["finished_at"].isoformat() if row["finished_at"] else None,
    }
    if row["status"] == "succeeded":
        body["output"] = row["output"]
        body["validation"] = row["validation"]
    elif row["status"] in {"failed", "rejected"}:
        body["error_code"] = row["error_code"]
        body["message"] = ERROR_MESSAGES.get(row["error_code"], "설명을 만들지 못했습니다.")
    return body


def _require_scan(scan_id: UUID):
    scan = _load_scan(scan_id)
    if scan is None:
        raise HTTPException(404, "검사를 찾을 수 없습니다.")
    return scan


@router.get("/scans/{scan_id}/ai/report")
def ai_report(scan_id: UUID):
    _require_scan(scan_id)
    return {"scan_id": str(scan_id), **_present(_load_report(scan_id))}


@router.get("/scans/{scan_id}/ai/findings")
def ai_findings(scan_id: UUID):
    _require_scan(scan_id)
    items = []
    for row in _load_findings(scan_id):
        items.append({"finding_id": str(row["finding_id"]), **_present(row)})
    return {"scan_id": str(scan_id), "total": len(items), "items": items}
