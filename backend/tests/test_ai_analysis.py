from datetime import datetime, timezone
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app import ai_analysis

NOW = datetime(2026, 10, 10, tzinfo=timezone.utc)


def row(status, **extra):
    base = dict(analysis_id=uuid4(), scope='scan_report', finding_id=None, status=status, attempt_no=1,
                provider='p', model='m', prompt_version='v0.1', input_fingerprint='a' * 64,
                output=None, validation={}, error_code=None, created_at=NOW, finished_at=None)
    base.update(extra)
    return base


@pytest.fixture
def client(monkeypatch):
    state = {'scan': {'status': 'completed'}, 'report': None, 'findings': []}
    monkeypatch.setattr(ai_analysis, '_load_scan', lambda _: state['scan'])
    monkeypatch.setattr(ai_analysis, '_load_report', lambda _: state['report'])
    monkeypatch.setattr(ai_analysis, '_load_findings', lambda _: state['findings'])
    return TestClient(app), state, uuid4()


def test_unknown_scan_is_404(client):
    c, state, sid = client
    state['scan'] = None
    assert c.get(f'/scans/{sid}/ai/report').status_code == 404
    assert c.get(f'/scans/{sid}/ai/findings').status_code == 404


def test_missing_report_is_not_an_error(client):
    c, _, sid = client
    r = c.get(f'/scans/{sid}/ai/report')
    assert r.status_code == 200
    assert r.json()['status'] == 'not_generated'


def test_succeeded_report_includes_output(client):
    c, state, sid = client
    state['report'] = row('succeeded', output={'summary': 's'}, validation={'passed': True}, finished_at=NOW)
    body = c.get(f'/scans/{sid}/ai/report').json()
    assert body['status'] == 'succeeded'
    assert body['output'] == {'summary': 's'}
    assert body['prompt_version'] == 'v0.1'


@pytest.mark.parametrize('status,code', [('rejected', 'validation_failed'), ('failed', 'timeout')])
def test_failed_or_rejected_hides_output(client, status, code):
    c, state, sid = client
    state['report'] = row(status, output={'summary': 'should not leak'}, error_code=code)
    body = c.get(f'/scans/{sid}/ai/report').json()
    assert body['status'] == status
    assert 'output' not in body
    assert body['error_code'] == code
    assert body['message']


def test_unknown_error_code_gets_generic_message(client):
    c, state, sid = client
    state['report'] = row('failed', error_code='weird_internal')
    assert c.get(f'/scans/{sid}/ai/report').json()['message'] == '설명을 만들지 못했습니다.'


@pytest.mark.parametrize('status', ['pending', 'running'])
def test_in_progress_has_no_output(client, status):
    c, state, sid = client
    state['report'] = row(status)
    body = c.get(f'/scans/{sid}/ai/report').json()
    assert body['status'] == status and 'output' not in body


def test_findings_list_keeps_each_status(client):
    c, state, sid = client
    f1, f2 = uuid4(), uuid4()
    state['findings'] = [
        row('succeeded', scope='finding', finding_id=f1, output={'what': 'x'}),
        row('rejected', scope='finding', finding_id=f2, error_code='validation_failed'),
    ]
    body = c.get(f'/scans/{sid}/ai/findings').json()
    assert body['total'] == 2
    by_id = {i['finding_id']: i for i in body['items']}
    assert by_id[str(f1)]['output'] == {'what': 'x'}
    assert 'output' not in by_id[str(f2)]
