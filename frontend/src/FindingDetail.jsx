import { useEffect, useState } from 'react'
import { findingLabel, fixGuide, relationLabel, uniqueFixVersions } from './display'
import AiReport from './AiReport'
import Icon from './Icons'
import DependencyPaths from './DependencyPaths'

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
    <div className="oc-cmd">
      <code>{command}</code>
      <button type="button" onClick={copy}>{copied ? '복사됨' : '복사'}</button>
    </div>
  )
}

// 패키지별 고치는 방법. 범위 데이터로 확인된 버전만 명령어에 쓴다.
function FixGuide({ pkg, many }) {
  const guide = fixGuide(pkg)
  return (
    <div className="oc-fix">
      {many && <p><strong className="mono">{pkg.name}@{pkg.installed_version}</strong> <span className="muted">· {relationLabel(pkg.relationship)}</span></p>}
      {guide.kind === 'direct' && (
        <>
          <CopyCommand command={guide.commands[0]} />
          <p className="muted" style={{ fontSize: 12 }}>수정 버전 {guide.target}은 이 설치 버전에 해당하는 영향 범위에서 확인된 값입니다. 변경 후 앱이 정상 동작하는지 테스트하고, 다시 검사해서 해결됐는지 확인하세요.</p>
        </>
      )}
      {guide.kind === 'indirect' && (
        <>
          <p className="sub">직접 설치한 패키지가 아니라서 <code className="mono">npm install {pkg.name}</code>로는 고쳐지지 않을 수 있습니다. 먼저 어떤 패키지가 쓰는지 확인하고, 허용 범위 안에서 올려 보세요.</p>
          <CopyCommand command={guide.commands[0]} />
          <CopyCommand command={guide.commands[1]} />
          <p className="muted" style={{ fontSize: 12 }}>목표 버전은 {guide.target}입니다. 상위 패키지가 허용하는 범위 안에서만 올라가므로 해결되지 않을 수 있습니다. 그럴 때는 상위 패키지 업데이트가 필요합니다. 다시 검사해서 확인하세요.</p>
        </>
      )}
      {guide.kind === 'unverified' && (
        <p className="sub">수정 후보 {guide.candidates.join(', ')}가 보고되었지만, 이 설치 버전에 어느 값이 맞는지 범위 데이터로 확인하지 못해 명령어를 만들지 않았습니다. 근거 보기에서 후보별 범위를 확인하세요.</p>
      )}
      {guide.kind === 'none' && (
        <p className="sub">검사 결과에 수정 버전 정보가 없습니다. 수정이 불가능하다는 뜻은 아니며, 이 패키지를 계속 쓸지 검토가 필요합니다.</p>
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

const idText = (x) => (typeof x === 'string' ? x : x && (x.value || x.id))

export default function FindingDetail({ scanId, scanStatus, actionRank, finding, index, total, onBack, onPrev, onNext }) {
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
  const severity = finding.severity || 'UNKNOWN'
  const ids = (finding.identifiers || []).map(idText).filter(Boolean)
  const title = packages.length === 1 ? `${packages[0].name}@${packages[0].installed_version}` : findingLabel(finding)

  return (
    <div className="oc-detail">
      <div className="oc-detailnav">
        <button type="button" className="oc-btn" onClick={onBack}>← 목록으로</button>
        <div className="pn">
          <button type="button" className="oc-btn" onClick={onPrev} disabled={!onPrev}>‹ 이전</button>
          <span>{index + 1} / {total}</span>
          <button type="button" className="oc-btn" onClick={onNext} disabled={!onNext}>다음 ›</button>
        </div>
      </div>

      <div>
        <div className="oc-dtitle">
          <h1>{title}</h1>
          <span className="oc-pill"><span className={`oc-dot sev-${severity}`} />{severity}</span>
          {finding.manual_review_required && <span className="oc-tag warn">수동 확인</span>}
        </div>
        <p className="oc-ids">{(ids.length ? ids : [findingLabel(finding)]).join(' · ')}</p>
      </div>

      <DependencyPaths scanId={scanId} findingId={finding.finding_id} />

      <section className="oc-panel">
        <h2 className="oc-ptitle" style={{ marginBottom: 10 }}>검사 결과</h2>
        <dl className="oc-dl">
          <div><dt>영향 패키지</dt><dd>{packages.length
            ? packages.map((p) => `${p.name}@${p.installed_version} · ${relationLabel(p.relationship)}`).join(', ')
            : '—'}</dd></div>
          {(finding.title || finding.description) && <div><dt>내용</dt><dd>{finding.title || finding.description}</dd></div>}
          <div><dt>수정 정보</dt><dd>{packages.map((p) => {
            const fixes = uniqueFixVersions(p.fixed_version_candidates)
            return fixes.length ? `수정 후보 ${fixes.join(', ')}` : '보고된 수정 버전 없음'
          }).join(' / ') || '—'}</dd></div>
          <div><dt>검출</dt><dd>
            검사 엔진 {(finding.source_tools || []).length}개
            {finding.severity_conflict ? ' · 엔진마다 심각도가 다름(근거 보기 참고)' : ' · 심각도 일치'}
          </dd></div>
          {actionRank != null && <div><dt>조치 우선순위</dt><dd>{actionRank}위</dd></div>}
          {finding.manual_review_reason && <div><dt>수동 확인 사유</dt><dd>{finding.manual_review_reason}</dd></div>}
        </dl>
      </section>

      <section className="oc-panel">
        <h2 className="oc-ptitle" style={{ marginBottom: 14 }}>고치는 방법</h2>
        {packages.length === 0
          ? <p className="sub">연결된 패키지가 없어 안내할 수 없습니다.</p>
          : packages.map((p) => <FixGuide key={p.package_id} pkg={p} many={packages.length > 1} />)}
      </section>

      <AiReport scanId={scanId} scanStatus={scanStatus} findingId={finding.finding_id} />

      <details className="oc-panel oc-evidence">
        <summary>
          <span className="t"><b>근거 보기</b><span className="muted" style={{ fontSize: 13 }}>엔진별 심각도 · 수정 후보 근거 · 식별자 · 원시 JSON</span></span>
          <Icon name="chevron" />
        </summary>
        <h3>엔진별 심각도</h3>
        {toolRows.length === 0 ? <p className="muted">—</p> : (
          <table className="oc-table">
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
          <table className="oc-table">
            <thead><tr><th>패키지</th><th>도구</th><th>권고 ID</th><th>수정 버전</th><th>근거</th></tr></thead>
            <tbody>
              {packages.flatMap((p) => (p.fixed_version_candidates || []).map((c, i) => (
                <tr key={`${p.package_id}-${i}`}>
                  <td className="mono">{p.name}</td><td className="mono">{(c && c.source_tool) || '—'}</td>
                  <td className="mono">{(c && c.advisory_id) || '—'}</td><td className="mono">{(c && c.value) || (typeof c === 'string' ? c : '—')}</td>
                  <td className="mono">{candidateBasis(c)}</td>
                </tr>
              )))}
            </tbody>
          </table>
        )}

        <h3>식별자</h3>
        <p className="mono" style={{ fontSize: 13 }}>{ids.join(', ') || '—'}</p>
        <p className="oc-hint" style={{ marginTop: 4 }}>같은 취약점으로 묶인 식별자입니다. 도구 결과에 명시된 대응 관계로만 묶습니다.</p>

        <details>
          <summary className="oc-link" style={{ marginTop: 16, cursor: 'pointer' }}>원시 근거 JSON</summary>
          <pre>{JSON.stringify(finding.evidence ?? {}, null, 2)}</pre>
        </details>
      </details>

      <p className="oc-hint" style={{ marginTop: 0 }}>Esc: 목록으로 · ← →: 이전/다음</p>
    </div>
  )
}
