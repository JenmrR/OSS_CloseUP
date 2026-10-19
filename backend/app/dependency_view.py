"""Recorded dependency paths for one finding; never infer runtime usage."""
import logging
from uuid import UUID
import psycopg
from fastapi import APIRouter, HTTPException
from psycopg.rows import dict_row
from .db import connect
from .ai_narrative import dependency_paths

router = APIRouter()
log = logging.getLogger(__name__)

@router.get('/scans/{scan_id}/findings/{finding_id}/dependency-paths')
def finding_paths(scan_id: UUID, finding_id: UUID):
    try:
        with connect() as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute('SELECT 1 FROM findings WHERE scan_id=%s AND finding_id=%s', (scan_id, finding_id))
            if cur.fetchone() is None:
                raise HTTPException(404, '이 검사에서 취약점을 찾을 수 없습니다.')
            cur.execute('SELECT package_id::text,name,installed_version,relationship FROM packages WHERE scan_id=%s ORDER BY package_id LIMIT 20001', (scan_id,))
            packages = cur.fetchall()
            cur.execute('SELECT parent_package_id::text,child_package_id::text FROM dependencies WHERE scan_id=%s ORDER BY parent_package_id,child_package_id LIMIT 50001', (scan_id,))
            edges = cur.fetchall()
            if len(packages) > 20000 or len(edges) > 50000:
                raise HTTPException(413, '의존 경로 조회 한도를 초과했습니다.')
            cur.execute('SELECT package_id::text FROM finding_packages WHERE scan_id=%s AND finding_id=%s ORDER BY package_id', (scan_id, finding_id))
            affected = {r['package_id'] for r in cur.fetchall()}
    except psycopg.Error:
        log.warning('Dependency path lookup failed; scan_id=%s', scan_id)
        raise HTTPException(503, '의존 경로를 불러오지 못했습니다.') from None
    paths = dependency_paths(packages, edges)
    return {'scan_id': str(scan_id), 'finding_id': str(finding_id), 'items': [
        {'package_id': p['package_id'], 'name': p['name'], 'installed_version': p['installed_version'],
         'status': 'available' if p['package_id'] in paths else 'not_recorded',
         'path': paths.get(p['package_id'], [])}
        for p in packages if p['package_id'] in affected],
        'scope': 'one_shortest_recorded_path', 'runtime_usage_analyzed': False}
