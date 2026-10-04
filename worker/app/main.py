"""Single active worker MVP: session lock, atomic claim, raw scanner artifacts.
Normalization/GitHub adapters are not wired yet: successful raw scans remain partial.
"""
import hashlib
import json
import logging
import os
from pathlib import Path
import signal
import subprocess
import threading
import time
from uuid import uuid4

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from .package_storage import store_packages

log = logging.getLogger('worker')
STOP = threading.Event()
LOCK_ID = 784932010  # project-local exclusive consumer; held on the same DB session
INPUT_ROOT = Path(os.getenv('SCAN_STORAGE_ROOT', '/work/uploads'))
OUTPUT_ROOT = Path(os.getenv('SCAN_RESULTS_ROOT', '/work/results'))
TIMEOUT = int(os.getenv('SCAN_TOOL_TIMEOUT_SECONDS', '660'))


def connect():
    return psycopg.connect(host=os.getenv('DB_HOST', 'db'), port=os.getenv('DB_PORT', '5432'),
        user=os.environ['DB_USER'], password=os.environ['DB_PASSWORD'], dbname=os.environ['DB_NAME'],
        connect_timeout=5, autocommit=True, row_factory=dict_row,
        options='-c statement_timeout=15000', tcp_user_timeout=15000,
        keepalives=1, keepalives_idle=10, keepalives_interval=5, keepalives_count=3)


def recover(conn):
    # Safe only while holding the project-wide session lock. Never auto-retry.
    with conn.transaction():
        conn.execute("""UPDATE scan_tool_runs SET status='failed', finished_at=now(),
            error_message='worker_interrupted' WHERE status='running' AND scan_id IN
            (SELECT scan_id FROM scan_runs WHERE status='running')""")
        conn.execute("""UPDATE scan_runs SET status='failed', finished_at=now(),
            error_message='worker_interrupted; upload again to retry',
            tool_status=tool_status || '{"worker":{"status":"failed","reason":"worker_interrupted"}}'::jsonb
            WHERE status='running'""")


def claim(conn, worker_id):
    with conn.transaction():
        return conn.execute("""WITH next AS (
            SELECT scan_id FROM scan_runs WHERE status='queued'
            ORDER BY created_at,scan_id FOR UPDATE SKIP LOCKED LIMIT 1)
            UPDATE scan_runs s SET status='running', started_at=now(), finished_at=NULL,
            heartbeat_at=now(), worker_id=%s, attempt_count=attempt_count+1,
            tool_status='{}'::jsonb, error_message=NULL
            FROM next WHERE s.scan_id=next.scan_id RETURNING s.*""", (worker_id,)).fetchone()


def heartbeat(conn, scan_id):
    conn.execute("UPDATE scan_runs SET heartbeat_at=now() WHERE scan_id=%s AND status='running'", (scan_id,))


def status(conn, scan_id, name, value):
    conn.execute('UPDATE scan_runs SET tool_status=tool_status || %s WHERE scan_id=%s',
                 (Jsonb({name:value}), scan_id))


def verify_inputs(conn, scan_id):
    rows=conn.execute("SELECT kind,storage_key,sha256,size_bytes FROM scan_artifacts WHERE scan_id=%s AND kind IN ('package_json','package_lock') AND deleted_at IS NULL",(scan_id,)).fetchall()
    if {r['kind'] for r in rows} != {'package_json','package_lock'} or len(rows)!=2:
        raise ValueError('missing_input_artifacts')
    paths={}
    for r in rows:
        path=(INPUT_ROOT/r['storage_key']).resolve()
        if not path.is_relative_to((INPUT_ROOT/str(scan_id)).resolve()):
            raise ValueError('invalid_input_path')
        data=path.read_bytes()
        if len(data)!=r['size_bytes'] or hashlib.sha256(data).hexdigest()!=r['sha256']:
            raise ValueError('input_hash_mismatch')
        paths[r['kind']]=path
    return paths


def commands(lock, out):
    return [
        ('trivy', ['trivy','fs','--scanners','vuln','--format','json','--output',str(out/'trivy.json'),
            '--cache-dir',os.getenv('TRIVY_CACHE_DIR','/cache/trivy'),'--db-repository','ghcr.io/aquasecurity/trivy-db:2',
            '--disable-telemetry','--skip-version-check','--no-progress','--timeout','10m',str(lock)],
            [('raw_result','trivy.json')], {0}),
        ('osv', ['osv-scanner','scan','source','-L',str(lock),'--format','json','--output-file',str(out/'osv.json')],
            [('raw_result','osv.json')], {0,1}),
        ('syft', ['syft',f'file:{lock}','-o',f'syft-json={out / "syft.json"}','-o',f'spdx-json={out / "sbom.spdx.json"}','-q'],
            [('raw_result','syft.json'),('sbom','sbom.spdx.json')], {0}),
    ]


def execute(argv, log_path, tick, timeout, stop=STOP):
    """No shell; kill the process group on timeout, shutdown, or lost DB session."""
    with log_path.open('wb') as output:
        proc=subprocess.Popen(argv, stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
        start=time.monotonic()
        try:
            while proc.poll() is None:
                if stop.is_set():
                    raise InterruptedError('worker_shutdown')
                if time.monotonic()-start >= timeout:
                    raise TimeoutError('tool_timeout')
                tick()
                stop.wait(1)
            return proc.returncode
        finally:
            if proc.poll() is None:
                try: os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError: pass
                proc.wait()


def artifact(conn, scan_id, run_id, kind, path):
    digest=hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda:stream.read(1024*1024),b''): digest.update(chunk)
    conn.execute("""INSERT INTO scan_artifacts(scan_id,tool_run_id,kind,storage_key,sha256,size_bytes,media_type)
        VALUES(%s,%s,%s,%s,%s,%s,%s)""",(scan_id,run_id,kind,
        path.relative_to(OUTPUT_ROOT).as_posix(),digest.hexdigest(),path.stat().st_size,
        'application/json' if path.suffix=='.json' else 'text/plain'))


def run_tool(conn, scan, name, argv, outputs, accepted, out):
    sid=scan['scan_id'];rid=uuid4();error=None;code=None;state='failed'
    version_cmd=[argv[0], 'version' if name=='syft' else '--version']
    try:
        version=subprocess.run(version_cmd,capture_output=True,text=True,timeout=10).stdout.strip()[:1000]
    except (OSError,subprocess.TimeoutExpired): version=None
    conn.execute("""INSERT INTO scan_tool_runs(tool_run_id,scan_id,tool_name,attempt_no,tool_version,status,started_at)
        VALUES(%s,%s,%s,%s,%s,'running',now())""",(rid,sid,name,scan['attempt_count'],version))
    status(conn,sid,name,{'status':'running'})
    logfile=out/f'{name}.log'
    try:
        code=execute(argv,logfile,lambda:heartbeat(conn,sid),TIMEOUT)
        if code not in accepted: raise ValueError('tool_exit_error')
        for _,filename in outputs:
            with (out/filename).open() as f: data=json.load(f)
            if not isinstance(data,dict): raise ValueError('invalid_output_json')
        state='completed'
    except TimeoutError: state='timeout';error='tool_timeout'
    except InterruptedError: raise
    except (OSError,ValueError): error='tool_failed_or_invalid_output'
    # Keep even failed output for diagnosis; status distinguishes success from 0 findings.
    with conn.transaction():
        for kind,filename in outputs+[('log',f'{name}.log')]:
            if (out/filename).is_file(): artifact(conn,sid,rid,kind,out/filename)
        conn.execute('UPDATE scan_tool_runs SET status=%s,finished_at=now(),exit_code=%s,error_message=%s WHERE tool_run_id=%s',
            (state,code,error,rid))
        status(conn,sid,name,{'status':state,'exit_code':code,'reason':error})
    return state


def process(conn, scan):
    sid=scan['scan_id']
    try:
        paths=verify_inputs(conn,sid)
        out=OUTPUT_ROOT/str(sid)/str(scan['attempt_count'])
        out.mkdir(parents=True,exist_ok=False)
        states=[]
        for spec in commands(paths['package_lock'],out):
            if STOP.is_set(): raise InterruptedError('worker_shutdown')
            states.append(run_tool(conn,scan,*spec,out))
        try:
            summary=store_packages(conn,sid,paths,OUTPUT_ROOT,allow_running=True)
            log.info('scan=%s package_storage=%s',sid,summary)
        except (OSError,ValueError,KeyError,TypeError):
            log.exception('package storage failed: %s',sid)
            status(conn,sid,'package_storage',{'status':'failed','reason':'invalid_package_or_syft_data'})
        status(conn,sid,'normalization',{'status':'skipped','reason':'adapter_not_connected'})
        status(conn,sid,'github',{'status':'skipped','reason':'adapter_not_connected'})
        final='partial' if 'completed' in states else 'failed'
        conn.execute('UPDATE scan_runs SET status=%s,finished_at=now(),heartbeat_at=now(),error_message=%s WHERE scan_id=%s',
            (final,'normalization_and_github_pending' if final=='partial' else 'all_scanners_failed',sid))
        log.info('scan=%s status=%s',sid,final)
    except (OSError,ValueError,InterruptedError) as exc:
        with conn.transaction():
            conn.execute("UPDATE scan_tool_runs SET status='failed',finished_at=now(),error_message='worker_failed' WHERE scan_id=%s AND status='running'",(sid,))
            status(conn,sid,'worker',{'status':'failed','reason':type(exc).__name__})
            conn.execute("UPDATE scan_runs SET status='failed',finished_at=now(),error_message=%s WHERE scan_id=%s",(type(exc).__name__,sid))
        log.exception('scan failed: %s',sid)


def main():
    logging.basicConfig(level=logging.INFO,format='%(asctime)s %(levelname)s %(message)s')
    for sig in (signal.SIGINT,signal.SIGTERM): signal.signal(sig,lambda *_:STOP.set())
    worker_id=str(uuid4())
    while not STOP.is_set():
        try:
            with connect() as conn:
                if not conn.execute('SELECT pg_try_advisory_lock(%s) AS acquired',(LOCK_ID,)).fetchone()['acquired']:
                    STOP.wait(5);continue
                recover(conn)
                log.info('active worker=%s; raw scans only, normalization pending',worker_id)
                while not STOP.is_set():
                    scan=claim(conn,worker_id)
                    if scan: process(conn,scan)
                    else: STOP.wait(2)
        except psycopg.Error:
            log.exception('DB session lost; reconnecting after 5s')
            STOP.wait(5)

if __name__=='__main__': main()
