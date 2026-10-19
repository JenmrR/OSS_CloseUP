const HEADINGS = {
  priority: '우선 확인 사항',
  related: '관련 취약점',
  action: '조치 방향',
  uncertainty: '판단에 필요한 정보',
}

function RelatedFindings({ findings, onFinding }) {
  const groups = new Map()
  for (const item of findings) {
    const key = `${item.package_name}@${item.installed_version}`
    if (!groups.has(key)) groups.set(key, [])
    groups.get(key).push(item)
  }
  return <div className="oc-report-related-list">{[...groups].map(([label, items]) => (
    <div key={label}>
      <p className="oc-report-package-label">{label} <span>· {items.length}건</span></p>
      <ul>{items.map((item) => <li key={item.finding_id}>
        <button type="button" className="oc-report-text-link" disabled={!onFinding} onClick={() => onFinding?.(item.finding_id)}>
          {item.advisories?.find((source) => source.title)?.title || '취약점 상세'}
        </button>
      </li>)}</ul>
    </div>
  ))}</div>
}

export default function AiNarrativeReport({ output, onFinding }) {
  const evidence = new Map((output.evidence || []).map((item) => [item.evidence_id, item]))
  const primary = (output.evidence || []).find((item) => item.finding_id === output.primary_finding_id)
  const sections = Object.keys(HEADINGS).map((kind) => ({
    kind,
    paragraphs: (output.paragraphs || []).filter((paragraph) => paragraph.kind === kind),
  })).filter((section) => section.paragraphs.length)
  return (
    <div className="oc-ai-narrative">
      {sections.map(({ kind, paragraphs }) => {
        const references = [...new Set(paragraphs.flatMap((paragraph) => paragraph.evidence_ids))]
          .map((id) => evidence.get(id)).filter(Boolean)
        const findings = [...new Map(references.map((item) => [item.finding_id, item])).values()]
        const body = <>
          {kind === 'related' && <RelatedFindings findings={findings} onFinding={onFinding} />}
          {paragraphs.map((paragraph, index) => <p className="oc-report-body" key={index}>{paragraph.text}</p>)}
        </>
        return (
          <section className="oc-report-section" key={kind}>
            <h3>{HEADINGS[kind]}</h3>
            {kind === 'priority' && <button type="button" className="oc-report-primary-link" disabled={!onFinding} onClick={() => onFinding?.(output.primary_finding_id)}>
              {primary?.package_name || '우선 항목'} <span aria-hidden="true">→</span>
            </button>}
            {kind === 'related' && (findings.length > 2 || paragraphs.length > 1)
              ? <details className="oc-report-related-more"><summary>관련 취약점 {findings.length}건 펼쳐보기</summary>{body}</details>
              : body}
          </section>
        )
      })}
    </div>
  )
}
