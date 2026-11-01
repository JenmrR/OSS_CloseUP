"""Read the authoritative package view using the caller's transaction."""
from fastapi import HTTPException
from psycopg.rows import dict_row
from .priority_view import load_priority
from .package_view import build_view


def load_package_view(conn, scan_id):
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute('SELECT scan_id,status,attempt_count,worker_id,tool_status FROM scan_runs WHERE scan_id=%s', (scan_id,))
        scan = cur.fetchone()
        if scan is None:
            raise HTTPException(404, 'scan_not_found')
        cur.execute('SELECT package_id,ecosystem,name,installed_version,lockfile_path,relationship,licenses,purl,repository_url,repository_full_name FROM packages WHERE scan_id=%s ORDER BY package_id', (scan_id,))
        packages = cur.fetchall()
        cur.execute("SELECT * FROM findings WHERE scan_id=%s AND type='vulnerability' ORDER BY finding_id", (scan_id,))
        findings = cur.fetchall()
        cur.execute('SELECT * FROM finding_packages WHERE scan_id=%s ORDER BY finding_id,package_id', (scan_id,))
        links = cur.fetchall()
    state, result = load_priority(conn, scan_id, scan['tool_status'])
    return build_view(scan, packages, findings, links, state, result)
