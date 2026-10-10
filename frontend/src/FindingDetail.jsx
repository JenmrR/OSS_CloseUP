import { useEffect, useState } from 'react'
import { getAiFindings } from './api'
import { aiReportView, findingLabel, fixGuide, uniqueFixVersions } from './display'

const REL = { direct: '직접 설치한 패키지', indirect: '다른 패키지가 사용하는 패키지', root: '프로젝트 자체', unknown: '확인 불가' }

function CopyCommand({ command }) {
  const [copied, setCopied] = useState(false)
  async function copy() {
    try {
      await navigator.clipboard.writeText(command)
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } catch {
      setCopied(false) // 복사가 막힌 환경에서도 명령어는 화면에 보인다
    }
  }
  return (
    <div className="stage-progress" style={{ gap: 8 }}>
      <code className="mono" style={{ flex: 1 }}>{command}</code>
      <button type="button" onClick={copy}>{copied ? '복사됨' : '복사'}</button>
    </div>
  )
}

// 패키지별 고치는 방법. 범위 데이터로 확인된 버전만 명령어에 쓴다.
function FixGuide({ pkg }) {
  const guide = fixGuide(pkg)
  return (
    <div style={{ marginBottom: 12 }}>
      <p><strong className="mono">{pkg.name}@{pkg.installed_version}</strong> <span className="muted">· {REL[pkg.relationship] || '확인 불가'}</span></p>
      {guide.kind === 'direct' && (
        <>
          <CopyCommand command={guide.commands[0]} />
          <p className="hint">수정 버전 {guide.target}은 이 설치 버전에 해당하는 영향 범위에서 확인된 값입니다. 변경 후 앱이 정상 동작하는지 테스트하고, 다시 검사해서 해결됐는지 확인하세요.</p>
        </>
      )}
      {guide.kind === 'indirect' && (
        <>
          <p className="muted">직접 설치한 패키지가 아니라서 <code className="mono">npm install {pkg.name}</code>로는 고쳐지지 않을 수 있습니다. 먼저 어떤 패키지가 쓰는지 확인하고, 허용 범위 안에서 올려 보세요.</p>
          <CopyCommand command={guide.commands[0]} />
          <CopyCommand command={guide.commands[1]} />
          <p className="hint">목표 버전은 {guide.target}입니다. 상위 패키지가 허용하는 범위 안에서만 올라가므로 해결되지 않을 수 있습니다. 그럴 때는 상위 패키지 업데이트가 필요합니다. 다시 검사해서 확인하세요.</p>
        </>
      )}
      {guide.kind === 'unverified' && (
        <p className="muted">수정 후보 {guide.candidates.join(', ')}가 보고되었지만, 이 설치 버전에 어느 값이 맞는지 범위 데이터로 확인하지 못해 명령어를 만들지 않았습니다. 근거 보기에서 후보별 범위를 확인하세요.</p>
      )}
      {guide.kind === 'none' && (
        <p className="muted">검사 결과에 수정 버전 정보가 없습니다. 수정이 불가능하다는 뜻은 아니며, 이 패키지를 계속 쓸지 검토가 필요합니다.</p>
      )}
    </div>
  )
}

function candidateBasis(c) {
  if (c && c.range && Array.isArray(c.range.events)) {
    return c.range.events.map((e) => Object.entries(e).map(([k, v]) => `${k} ${v}`).join('')).join(' ~ ')
  }
  return (c && c.raw) || '—'
}

export default function FindingDetail({ scanId, finding, index, total, onBack, onPrev, onNext }) {
  // 응답을 요청 키와 함께 저장하고, 키가 다르면(새 요청 중) 불러오는 중으로 본다.
  const requestKey = `${scanId}:${finding.finding_id}`
  const [aiResult, setAiResult] = useState({ key: null })

  useEffect(() => {
    let cancelled = false
    const findingId = requestKey.split(':')[1]
    getAiFindings(scanId)
      .then((data) => {
        if (cancelled) return
        const item = (data.items || []).find((x) => x.finding_id === findingId)
        setAiResult({ key: requestKey, data: item || { status: 'not_generated' } })
      })
      .catch((error) => { if (!cancelled) setAiResult({ key: requestKey, error }) })
    return () => { cancelled = true }
  }, [scanId, requestKey])
  const ai = aiResult.key === requestKey ? aiResult : { loading: true }

  useEffect(() => {
    function onKey(event) {
      if (event.key === 'Escape') onBack()
      else if (event.key === 'ArrowLeft' && onPrev) onPrev()
      else if (event.key === 'ArrowRight' && onNext) onNext()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onBack, onPrev, onNext])

  const packages = Array.isArray(finding.packages) ? finding.packages : []
  const byTool = finding.severity_by_tool && typeof finding.severity_by_tool === 'object' ? finding.severity_by_tool : {}
  const toolRows = Object.entries(byTool).flatMap(([tool, list]) => (Array.isArray(list) ? list : []).map((s) => ({ tool, ...s })))
  const aiView = aiReportView(ai)

  return (
    <section className="card">
      <div className="card-head">
        <button type="button" onClick={onBack}>← 목록으로</button>
        <span>
          <button type="button" onClick={onPrev} disabled={!onPrev}>‹ 이전</button>
          <span className="muted"> {index + 1} / {total} </span>
          <button type="button" onClick={onNext} disabled={!onNext}>다음 ›</button>
        </span>
      </div>

      <h2 className="mono">
        {findingLabel(finding)}{' '}
        <span className={`sev sev-${finding.severity || 'UNKNOWN'}`}>{finding.severity || 'UNKNOWN'}</span>
        {finding.manual_review_required && <span className="flag flag-warn">수동 확인</span>}
      </h2>

      <h3>검사 결과</h3>
      <dl className="meta">
        <div><dt>영향 패키지</dt><dd>{packages.length
          ? packages.map((p) => `${p.name}@${p.installed_version} (${REL[p.relationship] || '확인 불가'})`).join(', ')
          : '—'}</dd></div>
        <div><dt>수정 후보</dt><dd>{packages.map((p) => {
          const fixes = uniqueFixVersions(p.fixed_version_candidates)
          return fixes.length ? fixes.join(', ') : '수정 정보 확인 필요'
        }).join(' / ') || '—'}</dd></div>
        <div><dt>검출</dt><dd>
          검사 엔진 {(finding.source_tools || []).length}개
          {finding.severity_conflict ? ' · 엔진마다 심각도가 다름(근거 보기 참고)' : ' · 심각도 일치'}
        </dd></div>
        {finding.manual_review_reason && <div><dt>수동 확인 사유</dt><dd>{finding.manual_review_reason}</dd></div>}
      </dl>

      <h3>고치는 방법</h3>
      {packages.length === 0
        ? <p className="muted">연결된 패키지가 없어 안내할 수 없습니다.</p>
        : packages.map((p) => <FixGuide key={p.package_id} pkg={p} />)}

      <h3>AI 설명</h3>
      <p className={aiView.tone === 'error' ? 'error-text' : 'muted'}>{aiView.message}</p>
      {aiView.output && <pre className="mono" style={{ whiteSpace: 'pre-wrap' }}>{JSON.stringify(aiView.output, null, 2)}</pre>}

      <details>
        <summary>근거 보기</summary>
        <h3>도구별 심각도</h3>
        {toolRows.length === 0 ? <p className="muted">—</p> : (
          <table>
            <thead><tr><th>도구</th><th>원본 표기</th><th>정규화</th><th>출처 필드</th></tr></thead>
            <tbody>
              {toolRows.map((r, i) => (
                <tr key={`${r.tool}-${i}`}>
                  <td className="mono">{r.tool}</td><td>{r.raw ?? '—'}</td><td>{r.normalized ?? '—'}</td><td className="mono">{r.source ?? '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        <h3>수정 후보 근거</h3>
        {packages.every((p) => !(p.fixed_version_candidates || []).length) ? <p className="muted">보고된 수정 후보가 없습니다.</p> : (
          <table>
            <thead><tr><th>패키지</th><th>도구</th><th>권고 ID</th><th>수정 버전</th><th>근거</th></tr></thead>
            <tbody>
              {packages.flatMap((p) => (p.fixed_version_candidates || []).map((c, i) => (
                <tr key={`${p.package_id}-${i}`}>
                  <td className="mono">{p.name}</td><td className="mono">{c.source_tool || '—'}</td>
                  <td className="mono">{c.advisory_id || '—'}</td><td className="mono">{c.value || '—'}</td>
                  <td className="mono">{candidateBasis(c)}</td>
                </tr>
              )))}
            </tbody>
          </table>
        )}

        <h3>식별자</h3>
        <p className="mono">{(finding.identifiers || []).map((x) => (typeof x === 'string' ? x : x.value || x.id)).join(', ') || '—'}</p>
        <p className="hint">같은 취약점으로 묶인 식별자입니다. 도구 결과에 명시된 대응 관계로만 묶습니다.</p>

        <details>
          <summary>원시 근거 JSON</summary>
          <pre className="mono" style={{ whiteSpace: 'pre-wrap', maxHeight: 480, overflow: 'auto' }}>
            {JSON.stringify(finding.evidence ?? {}, null, 2)}
          </pre>
        </details>
      </details>

      <p className="hint">Esc: 목록으로 · ← →: 이전/다음</p>
    </section>
  )
}
