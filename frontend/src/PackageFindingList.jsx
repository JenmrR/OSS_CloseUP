import { SEVERITIES } from './display'

export function SeverityBadge({ severity, count }) {
  const value = SEVERITIES.includes(severity) ? severity : 'UNKNOWN'
  return <span className={`oc-severity-badge oc-severity-${value}`}>
    <span className={`oc-dot sev-${value}`} aria-hidden="true" />
    <span>{value === 'UNKNOWN' ? '심각도 미확인' : value}</span>
    {count != null && <span className="oc-severity-count">{count}</span>}
  </span>
}

export function CommonFix({ fix }) {
  if (!fix || (fix.status !== 'all' && fix.status !== 'partial')) return <span className="muted">공통 수정 버전 확인 안 됨</span>
  return <span className="oc-common-fix">
    공통 수정 버전 <strong>{fix.version}</strong>
    {fix.status === 'partial' && <span className="muted"> ({fix.covered}/{fix.total}건 확인)</span>}
    {fix.majorChange && <span className="oc-tag warn">주요 버전 변경</span>}
  </span>
}

// 패키지 한 줄을 누르면 바로 패키지 상세로 간다. 개별 취약점은 패키지 상세에서 본다.
export default function PackageFindingList({ groups, onPackage }) {
  return <div className="oc-package-groups">
    {groups.map(group => <button type="button" className="oc-package-group" key={group.key}
      aria-label={`${group.name}@${group.version} 패키지 상세 열기`} onClick={() => onPackage(group.name, group.version)}>
      <strong>{group.name}@{group.version}</strong>
      <span className="oc-pill">{group.displayRank ? `${group.displayRank}위` : '미산정·확인 필요'}</span>
      <span>{group.entries.length}건</span>
      <span className="oc-group-counts">{SEVERITIES.filter(s => group.counts[s]).map(s =>
        <SeverityBadge key={s} severity={s} count={group.counts[s]} />)}</span>
      <CommonFix fix={group.commonFix} />
      <span className="oc-package-go" aria-hidden="true">›</span>
    </button>)}
  </div>
}
