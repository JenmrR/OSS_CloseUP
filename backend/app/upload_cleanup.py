"""업로드 원본 정리 (소개서 3.10: 검사가 끝나면 업로드된 원본 파일은 삭제한다).

- 대상: 끝난 검사(completed/partial/failed)의 package.json, package-lock.json 원본만.
- 검사 결과·원시 결과·SBOM은 지우지 않는다. 입력 해시는 scan_runs와 scan_artifacts에 남는다.
- worker는 업로드 볼륨을 읽기 전용으로 쓰므로(최소 권한), 파일을 만든 backend가 지운다.
- 원본이 지워지면 같은 검사를 서버에서 다시 돌릴 수 없다. 다시 검사하려면 새로 업로드한다.
- 파일 삭제 후 deleted_at을 기록한다. 같은 행을 여러 번 처리해도 결과가 같다(멱등).
"""
import logging
import os
import threading
from pathlib import Path

from psycopg.rows import dict_row

from .db import connect

log = logging.getLogger(__name__)

TERMINAL = ['completed', 'partial', 'failed']
INPUT_KINDS = ['package_json', 'package_lock']

CANDIDATES_SQL = """
SELECT a.artifact_id, a.scan_id, a.storage_key
  FROM scan_artifacts a
  JOIN scan_runs s ON s.scan_id = a.scan_id
 WHERE a.kind = ANY(%s)
   AND a.deleted_at IS NULL
   AND s.status = ANY(%s)
   AND COALESCE(s.finished_at, s.created_at) <= now() - make_interval(secs => %s)
 ORDER BY COALESCE(s.finished_at, s.created_at), a.artifact_id
 LIMIT %s
"""

MARK_SQL = "UPDATE scan_artifacts SET deleted_at = now() WHERE artifact_id = ANY(%s) AND deleted_at IS NULL"


def _settings():
    return {
        'root': Path(os.getenv('SCAN_STORAGE_ROOT', '/work/uploads')),
        # 0이면 검사가 끝나는 즉시 삭제 대상. 디버깅 중에는 늘려서 잠시 보관할 수 있다.
        'retention': max(int(os.getenv('UPLOAD_RETENTION_SECONDS', '0')), 0),
        # 0 이하이면 자동 정리를 끈다.
        'interval': int(os.getenv('UPLOAD_CLEANUP_INTERVAL_SECONDS', '60')),
        'batch': 200,
    }


def _candidates(conn, retention, batch):
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(CANDIDATES_SQL, (INPUT_KINDS, TERMINAL, retention, batch))
        return cur.fetchall()


def _mark_deleted(conn, artifact_ids):
    if artifact_ids:
        with conn.cursor() as cur:
            cur.execute(MARK_SQL, (artifact_ids,))


def _resolve(root: Path, scan_id, storage_key: str):
    """storage_key가 해당 검사 폴더 안의 파일일 때만 경로를 돌려준다."""
    if not isinstance(storage_key, str) or '\\' in storage_key or '\x00' in storage_key:
        return None
    base = (root / str(scan_id)).resolve()
    path = (root / storage_key).resolve()
    if path == base or not path.is_relative_to(base):
        return None
    return path


def purge(conn, root: Path, retention: int = 0, batch: int = 200):
    """끝난 검사의 업로드 원본을 삭제하고 기록한다. 처리 결과 건수를 돌려준다."""
    deleted, skipped, folders = [], 0, set()
    for row in _candidates(conn, retention, batch):
        path = _resolve(root, row['scan_id'], row['storage_key'])
        if path is None:
            log.warning('upload cleanup: unsafe storage_key skipped (artifact=%s)', row['artifact_id'])
            skipped += 1
            continue
        try:
            path.unlink(missing_ok=True)  # 이미 없으면 지워진 것으로 본다
        except OSError:
            log.exception('upload cleanup: delete failed (artifact=%s)', row['artifact_id'])
            skipped += 1
            continue
        deleted.append(row['artifact_id'])
        folders.add(path.parent)
    _mark_deleted(conn, deleted)
    for folder in folders:
        try:
            folder.rmdir()  # 비어 있을 때만 지워진다
        except OSError:
            pass
    return {'deleted': len(deleted), 'skipped': skipped}


def _loop(stop: threading.Event, settings):
    while not stop.is_set():
        try:
            with connect() as conn:
                result = purge(conn, settings['root'], settings['retention'], settings['batch'])
            if result['deleted'] or result['skipped']:
                log.info('upload cleanup: %s', result)
        except Exception:  # 정리 실패가 API를 멈추면 안 된다
            log.exception('upload cleanup failed')
        stop.wait(settings['interval'])


def start_cleanup():
    """백그라운드 정리 스레드를 시작한다. 끄려면 UPLOAD_CLEANUP_INTERVAL_SECONDS=0."""
    settings = _settings()
    if settings['interval'] <= 0:
        log.info('upload cleanup disabled')
        return None
    stop = threading.Event()
    thread = threading.Thread(target=_loop, args=(stop, settings), name='upload-cleanup', daemon=True)
    thread.start()
    return stop
