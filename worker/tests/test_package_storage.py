import json
from pathlib import Path
from unittest.mock import MagicMock
import pytest
from worker.app import package_storage as p


def fixture():
    package={'name':'root','version':'1','dependencies':{'a':'1','@scope/b':'2'}}
    lock={'packages':{'':package,
        'node_modules/a':{'version':'1','dependencies':{'x':'1'}},
        'node_modules/@scope/b':{'version':'2'},
        'node_modules/x':{'version':'2'},
        'node_modules/a/node_modules/x':{'version':'1'}}}
    syft={'artifacts':[{'type':'npm','id':'a','name':'a','version':'1','purl':'pkg:npm/a@1',
        'licenses':[{'type':'declared','value':'MIT','spdxExpression':'MIT'}]}]}
    return package,lock,syft


def test_scoped_nested_and_direct():
    rows,edges,_=p.build_packages(*fixture())
    by_path={r['path']:r for r in rows}
    assert by_path['node_modules/@scope/b']['name']=='@scope/b'
    assert by_path['node_modules/a']['relationship']=='direct'
    assert by_path['node_modules/a/node_modules/x']['relationship']=='indirect'
    assert ('node_modules/a','node_modules/a/node_modules/x','runtime') in edges
    assert by_path['node_modules/a']['licenses']==['MIT']


def test_real_lock_counts():
    d=Path(__file__).resolve().parents[2]/'samples/poc77'
    rows,edges,unresolved=p.build_packages(json.loads((d/'package.json').read_text()),json.loads((d/'package-lock.json').read_text()),None)
    assert len(rows)==77
    assert sum(r['relationship']=='root' for r in rows)==1
    assert sum(r['relationship']=='direct' for r in rows)==10
    assert sum(r['relationship']=='indirect' for r in rows)==66
    assert all(r['licenses']==[] for r in rows)
    assert edges and not unresolved


def test_ambiguous_license_not_invented():
    a,b,c=fixture();other=dict(c['artifacts'][0]);other['licenses']=[{'type':'declared','value':'GPL-3.0-only'}]
    c['artifacts'].append(other)
    rows,_,_=p.build_packages(a,b,c)
    r=next(r for r in rows if r['name']=='a')
    assert r['licenses']==[] and r['evidence']['syft_match']=='ambiguous'


def test_integrity_mismatch_not_joined():
    a,b,c=fixture();b['packages']['node_modules/a']['integrity']='sha512-one';c['artifacts'][0]['metadata']={'integrity':'sha512-two'}
    rows,_,_=p.build_packages(a,b,c)
    assert next(r for r in rows if r['name']=='a')['evidence']['syft_match']=='missing'


def test_alias_install_path_keeps_identity():
    a,b,c=fixture();b['packages']['node_modules/a']['name']='actual-name'
    rows,_,_=p.build_packages(a,b,c)
    r=next(r for r in rows if r['path']=='node_modules/a')
    assert r['name']=='actual-name' and r['relationship']=='direct'


def test_unknown_license_preserves_lock_evidence():
    a,b,c=fixture();b['packages']['node_modules/a']['license']='MIT'
    rows,_,_=p.build_packages(a,b,None)
    r=next(r for r in rows if r['name']=='a')
    assert r['licenses']==[] and r['evidence']['lockfile_license']=='MIT'


def test_unresolved_optional_is_visible():
    a,b,c=fixture();a['optionalDependencies']={'absent':'1'}
    _,_,missing=p.build_packages(a,b,c)
    assert {'parent':'','name':'absent','kind':'optional'} in missing


def test_running_backfill_rejected(tmp_path):
    conn=MagicMock();conn.execute.return_value.fetchone.return_value={'status':'running'}
    with pytest.raises(ValueError,match='scan_not_finished'):p.store_packages(conn,'x',{},tmp_path)


def test_storage_uses_conflict_updates_and_transaction(tmp_path,monkeypatch):
    a,b,c=fixture();paths={}
    for key,data in [('package_json',a),('package_lock',b)]:
        paths[key]=tmp_path/key;paths[key].write_text(json.dumps(data))
    monkeypatch.setattr(p,'load_syft',lambda *a:(c,'artifact'))
    conn=MagicMock();conn.execute.return_value.fetchone.return_value={'status':'partial','package_id':'id'}
    result=p.store_packages(conn,'scan',paths,tmp_path)
    assert result['total_including_root']==5
    statements=[str(call.args[0]) for call in conn.execute.call_args_list]
    assert all('ON CONFLICT' in q for q in statements if q.startswith('INSERT'))
    assert 'FOR UPDATE' in statements[0]
    conn.transaction.assert_called_once()
