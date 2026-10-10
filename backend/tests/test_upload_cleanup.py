from uuid import uuid4

import pytest

from app import upload_cleanup as uc


@pytest.fixture
def env(tmp_path, monkeypatch):
    marked = []
    state = {'rows': []}
    monkeypatch.setattr(uc, '_candidates', lambda conn, retention, batch: state['rows'])
    monkeypatch.setattr(uc, '_mark_deleted', lambda conn, ids: marked.extend(ids))

    def make_scan():
        sid = uuid4()
        folder = tmp_path / str(sid)
        folder.mkdir()
        rows = []
        for name in ('package.json', 'package-lock.json'):
            (folder / name).write_text('{}')
            rows.append({'artifact_id': uuid4(), 'scan_id': sid, 'storage_key': f'{sid}/{name}'})
        return sid, folder, rows

    return tmp_path, state, marked, make_scan


def test_deletes_inputs_marks_rows_and_removes_empty_folder(env):
    root, state, marked, make_scan = env
    _, folder, rows = make_scan()
    state['rows'] = rows
    assert uc.purge(None, root) == {'deleted': 2, 'skipped': 0}
    assert not folder.exists()
    assert sorted(map(str, marked)) == sorted(str(r['artifact_id']) for r in rows)


def test_already_missing_file_is_still_marked(env):
    root, state, marked, make_scan = env
    _, folder, rows = make_scan()
    (folder / 'package.json').unlink()
    state['rows'] = rows
    assert uc.purge(None, root)['deleted'] == 2
    assert len(marked) == 2


def test_folder_with_other_files_is_kept(env):
    root, state, _, make_scan = env
    _, folder, rows = make_scan()
    (folder / 'note.txt').write_text('keep')
    state['rows'] = rows
    uc.purge(None, root)
    assert folder.exists() and (folder / 'note.txt').exists()
    assert not (folder / 'package.json').exists()


@pytest.mark.parametrize('key', ['../outside.json', '{sid}', 'other-scan/package.json', 'a\\b', '/etc/passwd'])
def test_unsafe_storage_key_is_skipped_and_not_marked(env, key):
    root, state, marked, make_scan = env
    sid, _, _ = make_scan()
    outside = root.parent / 'outside.json'
    outside.write_text('x')
    state['rows'] = [{'artifact_id': uuid4(), 'scan_id': sid, 'storage_key': key.format(sid=sid)}]
    assert uc.purge(None, root) == {'deleted': 0, 'skipped': 1}
    assert marked == []
    assert outside.exists()


def test_other_scans_files_are_untouched(env):
    root, state, _, make_scan = env
    _, folder_a, rows_a = make_scan()
    _, folder_b, _ = make_scan()
    state['rows'] = rows_a
    uc.purge(None, root)
    assert not folder_a.exists()
    assert (folder_b / 'package.json').exists() and (folder_b / 'package-lock.json').exists()


def test_cleanup_can_be_disabled(monkeypatch):
    monkeypatch.setenv('UPLOAD_CLEANUP_INTERVAL_SECONDS', '0')
    assert uc.start_cleanup() is None
