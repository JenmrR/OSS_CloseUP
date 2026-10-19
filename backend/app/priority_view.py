"""Read only the published evaluation; never expose historical grades as current."""
from psycopg.rows import dict_row


def load_priority(conn, scan_id, tool_status):
    marker = (tool_status or {}).get('priority') or {}
    state = {k: marker[k] for k in ('status','evaluation_id','attempt_id','priority_rule_version',
                                   'error_code','security_status','summary') if k in marker}
    state.setdefault('status', 'not_computed')
    state['current_result_available'] = False
    if marker.get('status') != 'completed' or marker.get('current_result_available') is not True:
        return state, None
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute('''SELECT e.result FROM priority_evaluations e JOIN scan_runs s USING(scan_id)
            WHERE e.scan_id=%s AND e.evaluation_id=%s AND e.status='completed'
            AND e.attempt_count=s.attempt_count AND e.worker_id=s.worker_id''',
            (scan_id, marker.get('evaluation_id')))
        row = cur.fetchone()
    if not row:
        state['status'] = 'unavailable'
        return state, None
    state['current_result_available'] = True
    return state, row['result']


def present_findings(items, state, result):
    links = {(x['finding_id'],x['package_id']): (i,x) for i,x in enumerate((result or {}).get('link_results', []))}
    for finding in items:
        fid = str(finding['finding_id'])
        ranks = []
        for pkg in finding.get('packages', []):
            ranked = links.get((fid,str(pkg['package_id'])))
            link = ranked[1] if ranked else {}
            pkg['priority'] = link.get('priority')
            pkg['priority_rule_version'] = link.get('priority_rule_version')
            pkg['priority_status'] = link.get('priority_status', state['status'])
            pkg['fix_information'] = link.get('fix_information', pkg.get('fix_information', 'unknown'))
            pkg['priority_rank'] = ranked[0] if ranked else None
            if ranked:
                ranks.append(ranked[0])
        finding['priority_evaluation_status'] = state['status']
        finding['priority_rank'] = min(ranks) if ranks else None
    return items
