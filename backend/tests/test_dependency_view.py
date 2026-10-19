from unittest.mock import MagicMock
from uuid import uuid4
import pytest
from fastapi import HTTPException
from app import dependency_view as view


def test_finding_must_belong_to_requested_scan(monkeypatch):
    conn = MagicMock(); conn.__enter__.return_value = conn; cur = conn.cursor.return_value.__enter__.return_value
    cur.fetchone.return_value = None
    monkeypatch.setattr(view, 'connect', lambda: conn)
    with pytest.raises(HTTPException) as error:
        view.finding_paths(uuid4(), uuid4())
    assert error.value.status_code == 404
    assert cur.execute.call_count == 1


def test_path_missing_and_cycles_are_distinguished(monkeypatch):
    conn = MagicMock(); conn.__enter__.return_value = conn; cur = conn.cursor.return_value.__enter__.return_value
    cur.fetchone.return_value = {'exists': 1}
    packages = [{'package_id': k, 'name': k, 'installed_version': '1', 'relationship': 'root' if k == 'root' else 'indirect'} for k in ['root','axios','form-data','orphan']]
    cur.fetchall.side_effect = [packages, [
        {'parent_package_id':'root','child_package_id':'axios'},
        {'parent_package_id':'axios','child_package_id':'form-data'},
        {'parent_package_id':'form-data','child_package_id':'axios'},
    ], [{'package_id':'form-data'},{'package_id':'orphan'}]]
    monkeypatch.setattr(view, 'connect', lambda: conn)
    output = view.finding_paths(uuid4(), uuid4())
    assert [n['name'] for n in output['items'][0]['path']] == ['root','axios','form-data']
    assert output['items'][1]['status'] == 'not_recorded'
    assert output['runtime_usage_analyzed'] is False
