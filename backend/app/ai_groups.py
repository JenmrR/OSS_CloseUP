"""Presentation contract consuming stored priority; never computes a P grade."""
from .ai_generation import GenerationError, REASONS, fingerprint

GROUP_ORDER = ['P0', 'P1', 'P2', 'P3', 'INFO', 'unranked-CRITICAL', 'unranked-HIGH', 'unranked-MEDIUM', 'unranked-LOW', 'unranked', 'unknown', 'license', 'maintenance']
TITLES = {'P0': '가장 먼저 확인', 'P1': '이어서 우선 확인', 'P2': '다음 조치 계획',
          'P3': '낮은 우선순위 항목', 'INFO': '참고 항목', 'unranked': '우선순위 산정 대기',
          'unknown': '심각도 확인 필요', 'license': '라이선스 별도 검토', 'maintenance': '유지보수 별도 검토'}


def group_key(item):
    if item['type'] in ('license', 'maintenance'):
        return item['type']
    if item['severity'] in (None, 'UNKNOWN'):
        return 'unknown'
    priority = item['priority']
    if priority in ('P0', 'P1', 'P2', 'P3', 'INFO'):
        return priority
    return 'unranked-' + item['severity'] if item['severity'] in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW') else 'unranked'


def group_facts(rows, scan_status, tools):
    """Counts are unique findings per group; a finding can span priority groups."""
    grouped = {}
    for row in rows:
        grouped.setdefault(group_key(row), []).append(row)
    items = []
    for key in GROUP_ORDER:
        if key not in grouped:
            continue
        members = grouped[key]
        package_ids = {x['package_id'] for x in members if x['package_id']}
        names = sorted({x['package_name'] for x in members if x['package_name']})
        codes = ['unranked'] if key.startswith('unranked') else ['priority'] if key in ('P0', 'P1', 'P2', 'P3', 'INFO') else [
            {'unranked': 'unranked', 'unknown': 'unknown', 'license': 'license', 'maintenance': 'maintenance'}[key]]
        if key not in ('license', 'maintenance'):
            codes.append('candidate' if any(x['has_fixed_candidates'] for x in members) else 'no_candidate')
        else:
            codes.append('check_context')
        if any(x['relationship'] == 'indirect' for x in members):
            codes.append('indirect')
        items.append({
            'evidence_id': key, 'group_key': key, 'title': (key.split('-', 1)[1] + ' · 우선순위 산정 대기') if key.startswith('unranked-') else TITLES[key],
            'finding_count': len({x['finding_id'] for x in members}), 'package_count': len(package_ids),
            'example_packages': names[:3], 'remaining_package_names': max(0, len(names) - 3),
            'candidate_package_count': len({x['package_id'] for x in members if x['package_id'] and x['has_fixed_candidates']}),
            'allowed_reasons': codes,
        })
    return {'layout': 'grouped-v2', 'source_fingerprint': fingerprint(rows), 'scan_status': scan_status, 'tools': tools,
            'finding_count': len({x['finding_id'] for x in rows}),
            'package_count': len({x['package_id'] for x in rows if x['package_id']}), 'items': items}


def render_groups(snapshot, selection):
    if not isinstance(selection, dict) or set(selection) != {'items'} or not isinstance(selection['items'], list):
        raise GenerationError('validation_failed')
    if len(selection['items']) != len(snapshot['items']):
        raise GenerationError('validation_failed')
    groups = []
    for fact, choice in zip(snapshot['items'], selection['items']):
        if not isinstance(choice, dict) or set(choice) != {'evidence_id', 'reasons'} or choice['evidence_id'] != fact['evidence_id']:
            raise GenerationError('validation_failed')
        codes = choice['reasons']
        if (not isinstance(codes, list) or not 2 <= len(codes) <= 4 or not all(isinstance(x, str) for x in codes)
                or len(set(codes)) != len(codes) or not set(codes) <= set(fact['allowed_reasons'])):
            raise GenerationError('validation_failed')
        group = {k: v for k, v in fact.items() if k not in ('allowed_reasons', 'evidence_id')}
        # The action is about the group; it must not imply every member has a candidate.
        actions = {
            'candidate': f'이 그룹에서 수정 후보가 보고된 패키지 {fact["candidate_package_count"]}개의 상세를 먼저 확인하고 적용 범위·호환성을 검토하세요.',
            'no_candidate': '이 그룹에 보고된 수정 후보가 없습니다. 상세 근거와 수정 정보의 조회 상태를 확인하세요.',
            'priority': '시스템이 저장한 조치 우선순위 기준입니다. 개별 항목에서 영향 범위와 수정 정보를 확인하세요.',
            'unranked': '아직 조치 우선순위가 산정되지 않았습니다. 해당 항목의 영향 범위와 검사 근거를 확인하세요.',
            'indirect': '간접 의존성이 포함돼 있습니다. 해당 항목에서 어떤 상위 패키지를 통해 사용되는지 확인하세요.',
        }
        group['guidance'] = [actions.get(code, REASONS[code]) for code in codes[:2]]
        groups.append(group)
    pending = any(x['group_key'].startswith('unranked') for x in groups)
    return {'layout': 'grouped-v2', 'summary': f'검사 항목 {snapshot["finding_count"]}건을 확인 목적별로 묶었습니다. '
            + ('우선순위 미산정 항목은 심각도별로만 묶었습니다. 조치 우선순위가 확정된 것은 아닙니다.' if pending else '저장된 우선순위가 있는 항목부터 확인하고, 정보가 부족한 항목은 별도로 검토하세요.'),
            'groups': groups, 'count_note': '건수는 그룹 내 중복을 제거한 검사 항목 수입니다. 같은 항목이 여러 패키지의 다른 등급에 걸리면 그룹 간 중복될 수 있습니다.',
            'uncertainty': '검사가 부분 완료되어 확인되지 않은 결과가 있을 수 있습니다.' if snapshot['scan_status'] != 'completed'
                           or any(t['status'] != 'completed' for t in snapshot['tools']) else '검사에 잡히지 않은 문제가 없다는 뜻은 아닙니다.'}
