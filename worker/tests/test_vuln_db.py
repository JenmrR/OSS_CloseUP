from worker.app import vuln_db as v


def _trivy_db(d):
    (d/'db').mkdir(parents=True);(d/'db'/'trivy.db').write_bytes(b'x')


def test_fresh_only_with_recent_marker_and_existing_db(tmp_path):
    assert not v.is_fresh(tmp_path,'trivy',now=1000)            # never downloaded
    v.mark_downloaded(tmp_path,'trivy',now=1000)
    assert not v.is_fresh(tmp_path,'trivy',now=1001)            # marker but DB wiped
    _trivy_db(tmp_path)
    assert v.is_fresh(tmp_path,'trivy',now=1000+v.REFRESH_SECONDS-1)
    assert not v.is_fresh(tmp_path,'trivy',now=1000+v.REFRESH_SECONDS)   # a day later: refresh
    assert not v.is_fresh(tmp_path,'trivy',now=999)             # clock moved back: refresh


def test_osv_archive_location_and_corrupt_marker(tmp_path):
    v.mark_downloaded(tmp_path,'osv',now=50)
    assert not v.is_fresh(tmp_path,'osv',now=60)
    (tmp_path/'osv-scalibr'/'npm').mkdir(parents=True);(tmp_path/'osv-scalibr'/'npm'/'all.zip').write_bytes(b'z')
    assert v.is_fresh(tmp_path,'osv',now=60)
    (tmp_path/'.osv-downloaded-at').write_text('not a time')
    assert not v.is_fresh(tmp_path,'osv',now=60)
