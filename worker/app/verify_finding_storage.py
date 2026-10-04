"""Real PostgreSQL integration check; all fixture writes roll back, even on failure.
Usage: docker compose exec -T worker python -m app.verify_finding_storage < normalized-final.json
"""
import json
import sys
from copy import deepcopy
from uuid import uuid4
import psycopg
from .finding_storage import persist
from .main import connect


def verify(conn, source):
    doc = deepcopy(source)
    sid = uuid4()
    original_scope = doc['scan_id']
    doc['scan_id'] = str(sid)
    for collection in ('packages','findings','alias_groups'):
        for row in doc[collection]: row['scan_id'] = str(sid)
    provenance = {'fixture': {'original_scan_id': original_scope, 'isolated_test': True}}
    with conn.transaction():
        project = conn.execute("INSERT INTO projects(name) VALUES('normalization rollback test') RETURNING project_id").fetchone()['project_id']
        conn.execute("INSERT INTO scan_runs(scan_id,project_id,status) VALUES(%s,%s,'partial')",(sid,project))
        for p in doc['packages']:
            conn.execute('''INSERT INTO packages(scan_id,name,installed_version,lockfile_path,relationship)
                VALUES(%s,%s,%s,%s,%s)''',(sid,p['name'],p['version'],p['lock_path'],p['dependency_type']))
        first = persist(conn,sid,doc,provenance)
        ids_before = conn.execute('SELECT finding_id FROM findings WHERE scan_id=%s ORDER BY finding_id',(sid,)).fetchall()
        second = persist(conn,sid,doc,provenance)
        assert first == second
        assert ids_before == conn.execute('SELECT finding_id FROM findings WHERE scan_id=%s ORDER BY finding_id',(sid,)).fetchall()
        # A deliberately corrupted evidence object must be detected, then rolled back.
        detected = False
        try:
            with conn.transaction():
                conn.execute("UPDATE findings SET evidence='{}'::jsonb WHERE scan_id=%s",(sid,))
                persist(conn,sid,doc,provenance)
        except ValueError as exc:
            assert str(exc) == 'roundtrip_finding_content_mismatch'
            detected = True
        assert detected
        persist(conn,sid,doc,provenance)
        result = {**first,'idempotent':True,'corruption_detected':True,'fixture_rolled_back':True}
        raise psycopg.Rollback()
    return result


def main():
    source = json.load(sys.stdin)
    with connect() as conn:
        result = verify(conn,source)
    print(json.dumps(result,ensure_ascii=False,indent=2))

if __name__ == '__main__': main()
