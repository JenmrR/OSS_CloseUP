import { SEVERITIES, findingLabel, fixSummary } from './display'

function SeverityBadge({ severity, count }) {
  const value = SEVERITIES.includes(severity) ? severity : 'UNKNOWN'
  return <span className={`oc-severity-badge oc-severity-${value}`}>
    <span className={`oc-dot sev-${value}`} aria-hidden="true" />
    <span>{value === 'UNKNOWN' ? '심각도 미확인' : value}</span>
    {count != null && <span className="oc-severity-count">{count}</span>}
  </span>
}

export default function PackageFindingList({ groups, onOpen }) {
  return <div className="oc-package-groups">
    {groups.map(group => <details className="oc-package-group" key={group.key}>
      <summary>
        <strong>{group.name}@{group.version}</strong>
        <span className="oc-pill">{group.displayRank ? `${group.displayRank}위` : '미산정·확인 필요'}</span>
        <span>{group.entries.length}건</span>
        <span className="oc-group-counts">{SEVERITIES.filter(s => group.counts[s]).map(s =>
          <SeverityBadge key={s} severity={s} count={group.counts[s]} />)}</span>
        <span className="muted">취약점 펼치기</span>
      </summary>
      <p className="oc-hint">각 취약점의 수정 정보를 확인하세요. 패키지의 모든 취약점을 해결하는 공통 버전은 확인하지 않았습니다.</p>
      <ul className="oc-group-findings">{group.entries.map(({ finding, packages }, i) =>
        <li key={finding.finding_id || i}>
          <button type="button" className="oc-link" aria-label={`${findingLabel(finding)} 상세 열기`} disabled={!finding.finding_id} onClick={() => onOpen(finding.finding_id)}>{findingLabel(finding)}</button>
          <SeverityBadge severity={finding.severity} />
          {finding.manual_review_required && <span className="oc-tag warn">수동 확인</span>}
          <span className="muted">{[...new Set(packages.map(p => fixSummary(p).text))].join(' · ')}</span>
        </li>)}</ul>
    </details>)}
  </div>
}
