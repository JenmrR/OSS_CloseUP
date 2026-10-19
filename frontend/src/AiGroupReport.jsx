import { findingLabel } from './display'
import { matchesAiGroup } from './aiPresentation'

export default function AiGroupReport({ output, findings, onFinding }) {
  return (
    <div className="oc-ai-groups">
      <p className="oc-ai-intro">{output.summary}</p>
      {(output.groups || []).map((group) => {
        const members = (findings?.items || []).filter((f) => matchesAiGroup(f, group.group_key))
        return (
          <article className="oc-ai-group" key={group.group_key}>
            <div className="oc-ai-group-head">
              <h3>{group.title}</h3>
              <span>{group.finding_count}건 · {group.package_count}개 패키지</span>
            </div>
            <p className="oc-ai-packages">{group.example_packages.join(' · ') || '연결 패키지 정보 없음'}{group.remaining_package_names > 0 ? ` 외 ${group.remaining_package_names}종` : ''}</p>
            <ul>{group.guidance.map((text) => <li key={text}>{text}</li>)}</ul>
            {members.length > 0 && onFinding && !['license', 'maintenance'].includes(group.group_key) && (
              <details className="oc-ai-members">
                <summary>이 그룹의 취약점 보기 ({members.length}건)</summary>
                <div>{members.map((f) => (
                  <button type="button" className="oc-btn" key={f.finding_id} onClick={() => onFinding(f.finding_id)}>
                    {[...new Set((f.packages || []).map((p) => p.name))].slice(0, 2).join(', ') || '패키지 미확인'}
                    {' · '}{f.canonical_id || (findingLabel(f) === f.finding_id ? '식별자 미확인' : findingLabel(f))}
                  </button>
                ))}</div>
              </details>
            )}
          </article>
        )
      })}
      <p className="note">{output.uncertainty}</p>
      <details className="oc-ai-count-note"><summary>집계 기준</summary><p className="note">{output.count_note}</p></details>
    </div>
  )
}
