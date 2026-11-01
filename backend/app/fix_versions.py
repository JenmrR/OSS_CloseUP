"""Conservative SEMVER range candidates; a candidate is not a remediation guarantee.
Keep behavior aligned with frontend/src/semver.js and the shared JSON cases.
"""
import re

_SEMVER = re.compile(r'v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?')


def parse(value):
    if not isinstance(value, str):
        return None
    m = _SEMVER.fullmatch(value.strip())
    if not m or (m[4] and any(x.isdigit() and len(x) > 1 and x[0] == '0' for x in m[4].split('.'))):
        return None
    return (tuple(int(m[i]) for i in (1, 2, 3)), m[4])


def compare(a, b):
    x, y = parse(a), parse(b)
    if not x or not y:
        return None
    if x[0] != y[0]:
        return -1 if x[0] < y[0] else 1
    if x[1] == y[1]:
        return 0
    if not x[1]:
        return 1
    if not y[1]:
        return -1
    xs, ys = x[1].split('.'), y[1].split('.')
    for a, b in zip(xs, ys):
        if a == b:
            continue
        if a.isdigit() and b.isdigit():
            return -1 if int(a) < int(b) else 1
        if a.isdigit() != b.isdigit():
            return -1 if a.isdigit() else 1
        return -1 if a < b else 1
    return -1 if len(xs) < len(ys) else 1


def _intervals(candidates):
    """Return validated intervals, or None for malformed/unsupported range evidence."""
    intervals = []
    for c in candidates or []:
        r = c.get('range') if isinstance(c, dict) else None
        if r is None:
            continue
        if not isinstance(r, dict) or r.get('type', 'SEMVER') != 'SEMVER':
            return None
        events = r.get('events')
        if not isinstance(events, list) or not events:
            return None
        start, previous = None, None
        previous_inclusive = False
        for e in events:
            if not isinstance(e, dict) or len(e) != 1:
                return None
            kind, value = next(iter(e.items()))
            if kind not in ('introduced', 'fixed', 'last_affected', 'limit') or not isinstance(value, str):
                return None
            if not (kind == 'introduced' and value == '0') and not parse(value):
                return None
            if kind == 'introduced':
                if start is not None:
                    return None
                if previous is not None and (value == '0' or compare(value, previous) < 0 or
                                             (previous_inclusive and compare(value, previous) == 0)):
                    return None
                start = value
            else:
                if start is None or (start != '0' and (compare(start, value) > 0 or
                                                       (kind != 'last_affected' and compare(start, value) == 0))):
                    return None
                intervals.append((start, value, kind))
                start, previous, previous_inclusive = None, value, kind == 'last_affected'
        if start is not None:
            intervals.append((start, None, None))
    return intervals


def _contains(version, start, end, kind):
    return (start == '0' or compare(version, start) >= 0) and (end is None or
            (compare(version, end) <= 0 if kind == 'last_affected' else compare(version, end) < 0))


def _affected(version, candidates):
    if not parse(version):
        return None
    intervals = _intervals(candidates)
    if not intervals:
        return None
    if any(_contains(version, *i) for i in intervals):
        return True
    # A limit bounds known data; it is not evidence of a fix above that limit.
    if any(kind == 'limit' and compare(version, end) >= 0 for _, end, kind in intervals):
        return None
    return False


def range_fix(installed, candidates):
    """Exact recorded fix for an affected interval; never infer all later versions safe."""
    if not parse(installed):
        return None
    intervals = _intervals(candidates)
    if not intervals:
        return None
    matches = [end for start, end, kind in intervals if kind == 'fixed'
               and _contains(installed, start, end, kind)]
    if not matches:
        return None
    best = matches[0]
    for v in matches[1:]:
        if compare(v, best) == 1:
            best = v
    return best if _affected(best, candidates) is False else None


def _major_change(a, b):
    x, y = parse(a), parse(b)
    if not x or not y:
        return False
    return x[0][0] != y[0][0] or (x[0][0] == 0 and x[0][1] != y[0][1])


def common_fix(installed, candidate_lists):
    """candidate_lists: one candidate list per finding of the same installed package."""
    total = len(candidate_lists)
    targets = [t for t in (range_fix(installed, c) for c in candidate_lists) if t]
    if not targets:
        return {'status': 'none', 'total': total, 'covered': 0}
    version = targets[0]
    for t in targets[1:]:
        if compare(t, version) == 1:
            version = t
    checks = [_affected(version, c) for c in candidate_lists]
    base = {'version': version, 'total': total, 'major_change': _major_change(installed, version)}
    if any(range_fix(installed, c) and checks[i] is True for i, c in enumerate(candidate_lists)):
        return {**base, 'status': 'conflict', 'covered': 0}
    covered = sum(1 for x in checks if x is False)
    return {**base, 'status': 'all' if covered == total else 'partial', 'covered': covered}
