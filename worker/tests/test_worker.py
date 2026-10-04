import importlib.util
from pathlib import Path
import hashlib
import json
import sys
import threading
from unittest.mock import MagicMock
import pytest

from worker.app import main as w

def test_osv_one_is_success(tmp_path,monkeypatch):
    (tmp_path/'osv.json').write_text('{}')
    monkeypatch.setattr(w,'OUTPUT_ROOT',tmp_path)
    monkeypatch.setattr(w,'execute',lambda *a:1)
    monkeypatch.setattr(w.subprocess,'run',lambda *a,**k:MagicMock(stdout='v2'))
    c=MagicMock()
    assert w.run_tool(c,{'scan_id':'s','attempt_count':1},'osv',['osv-scanner'],[('raw_result','osv.json')],{0,1},tmp_path)=='completed'

def test_zero_without_valid_json_is_failed(tmp_path,monkeypatch):
    monkeypatch.setattr(w,'execute',lambda *a:0)
    monkeypatch.setattr(w.subprocess,'run',lambda *a,**k:MagicMock(stdout='v2'))
    assert w.run_tool(MagicMock(),{'scan_id':'s','attempt_count':1},'osv',['osv-scanner'],[('raw_result','missing.json')],{0,1},tmp_path)=='failed'

def test_timeout_kills_child(tmp_path):
    with pytest.raises(TimeoutError):
        w.execute([sys.executable,'-c','import time;time.sleep(60)'],tmp_path/'log',lambda:None,0,threading.Event())

def test_shutdown_kills_child(tmp_path):
    stop=threading.Event();stop.set()
    with pytest.raises(InterruptedError):
        w.execute([sys.executable,'-c','import time;time.sleep(60)'],tmp_path/'log',lambda:None,60,stop)

def test_database_failure_aborts_process(tmp_path):
    def tick(): raise w.psycopg.OperationalError('lost connection')
    with pytest.raises(w.psycopg.OperationalError):
        w.execute([sys.executable,'-c','import time;time.sleep(60)'],tmp_path/'log',tick,60,threading.Event())

def test_input_hash_and_path(tmp_path,monkeypatch):
    monkeypatch.setattr(w,'INPUT_ROOT',tmp_path)
    d=tmp_path/'s';d.mkdir()
    rows=[]
    for kind in ('package_json','package_lock'):
        (d/kind).write_bytes(b'{}')
        rows.append(dict(kind=kind,storage_key=f's/{kind}',size_bytes=2,sha256=hashlib.sha256(b'{}').hexdigest()))
    c=MagicMock();c.execute.return_value.fetchall.return_value=rows
    assert len(w.verify_inputs(c,'s'))==2
    rows[0]['sha256']='0'*64
    with pytest.raises(ValueError,match='hash'): w.verify_inputs(c,'s')
    rows[0]['storage_key']='../outside'
    with pytest.raises(ValueError,match='path'): w.verify_inputs(c,'s')

def test_raw_success_is_partial(tmp_path,monkeypatch):
    monkeypatch.setattr(w,'OUTPUT_ROOT',tmp_path)
    monkeypatch.setattr(w,'verify_inputs',lambda *a:{'package_lock':tmp_path/'lock'})
    monkeypatch.setattr(w,'store_packages',lambda *a,**kw: {})
    monkeypatch.setattr(w,'run_tool',lambda *a:'completed')
    c=MagicMock();w.process(c,{'scan_id':'s','attempt_count':1})
    assert c.execute.call_args.args[1][0]=='partial'

def test_all_failed(tmp_path,monkeypatch):
    monkeypatch.setattr(w,'OUTPUT_ROOT',tmp_path)
    monkeypatch.setattr(w,'verify_inputs',lambda *a:{'package_lock':tmp_path/'lock'})
    monkeypatch.setattr(w,'store_packages',lambda *a,**kw: {})
    monkeypatch.setattr(w,'run_tool',lambda *a:'failed')
    c=MagicMock();w.process(c,{'scan_id':'s','attempt_count':1})
    assert c.execute.call_args.args[1][0]=='failed'
