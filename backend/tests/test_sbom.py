import hashlib
from uuid import uuid4
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app import sbom

@pytest.fixture
def sample(tmp_path, monkeypatch):
    sid = uuid4()
    data = b'{"spdxVersion":"SPDX-2.3"}'
    (tmp_path / 'sbom.json').write_bytes(data)
    artifact = dict(artifact_id=uuid4(), storage_key='sbom.json',
                    sha256=hashlib.sha256(data).hexdigest(), size_bytes=len(data),
                    media_type='application/json', created_at=None, tool_name='syft',
                    tool_run_status='completed', attempt_no=1)
    run = dict(status='completed', attempt_no=1, tool_version='1', error_message=None)
    scan = dict(status='partial')
    monkeypatch.setattr(sbom, 'RESULTS_ROOT', tmp_path)
    monkeypatch.setattr(sbom, '_lookup', lambda _: (scan, artifact, run))
    return TestClient(app), f'/scans/{sid}/sbom', scan, artifact, run, tmp_path, data

def test_success_exact_bytes(sample):
    client, url, _, _, _, _, data = sample
    assert client.get(url + '/info').json()['available'] is True
    response = client.get(url)
    assert response.status_code == 200
    assert response.content == data
    assert response.headers['x-artifact-verified'] == 'sha256'

@pytest.mark.parametrize('case', ['both_failed', 'retry_failed', 'retry_running', 'old_artifact', 'unlinked', 'scan_failed'])
def test_unavailable_consistently(sample, case):
    client, url, scan, artifact, run, _, _ = sample
    if case == 'both_failed':
        scan['status'] = run['status'] = artifact['tool_run_status'] = 'failed'
    elif case in {'retry_failed', 'retry_running'}:
        run.update(attempt_no=2, status='failed' if case == 'retry_failed' else 'running')
    elif case == 'old_artifact':
        run['attempt_no'] = 2
    elif case == 'unlinked':
        artifact['tool_run_status'] = None
    else:
        scan['status'] = 'failed'
    assert client.get(url + '/info').json()['available'] is False
    response = client.get(url)
    assert response.status_code == 404
    assert response.json()['detail']['reason'] == 'sbom_not_available'

@pytest.mark.parametrize('case', ['missing', 'size', 'hash', 'escape'])
def test_integrity_still_blocks_download(sample, case):
    client, url, _, artifact, _, root, data = sample
    if case == 'missing': (root / 'sbom.json').unlink()
    elif case == 'size': (root / 'sbom.json').write_bytes(b'x')
    elif case == 'hash': (root / 'sbom.json').write_bytes(b'x' * len(data))
    else: artifact['storage_key'] = '../outside.json'
    assert client.get(url).status_code == 500
