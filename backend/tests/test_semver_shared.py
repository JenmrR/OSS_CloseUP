import json
from pathlib import Path
import pytest
from app.fix_versions import compare, range_fix, _affected

CASES = json.loads((Path(__file__).resolve().parents[2] / 'tests/fixtures/semver-cases.json').read_text())

@pytest.mark.parametrize('a,b,expected', CASES['compare'])
def test_compare(a, b, expected):
    assert compare(a, b) == expected
    if expected is not None:
        assert compare(b, a) == -expected

@pytest.mark.parametrize('case', CASES['ranges'], ids=lambda c: c['name'])
def test_ranges(case):
    assert range_fix(case['installed'], case['candidates']) == case['fix']
    assert _affected(case['installed'], case['candidates']) == case['affected']
