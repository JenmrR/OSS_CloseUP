import { useEffect, useState } from 'react'
import { getPackageDetail } from './api'
import AiReport from './AiReport'
import { findingLabel, relationLabel, SEVERITIES } from './display'
import { buildFixPrompt } from './fixPrompt'
import { SeverityBadge } from './PackageFindingList'

export function PackageFindings({ findings, onFinding }) {
  return <ul className="oc-group-findings">{[...findings].sort((a, b) =>
    SEVERITIES.indexOf(a.severity || 'UNKNOWN') - SEVERITIES.indexOf(b.severity || 'UNKNOWN')).map(f =>
    <li key={f.finding_id} style={{ display: 'block' }}>
      <button type="button" className="oc-link" onClick={() => onFinding(f.finding_id)}>{findingLabel(f)}</button>{' '}
      <SeverityBadge severity={f.severity} />
      {f.manual_review_required && <span className="oc-tag warn">수동 확인</span>}
      {(f.installation_links || []).map(l => <div key={l.package_id} className="oc-hint">
        <span>{l.lockfile_path || '설치 위치 미제공'} · {relationLabel(l.relationship)}</span>
        {l.fixed_version_candidates?.length ? l.fixed_version_candidates.map((c, i) =>
          <div key={i}>수정 후보: <strong>{c.value || c.raw || '값 미제공'}</strong> · 출처: {c.source_tool || '미제공'}
            {c.advisory_id ? ` · ${c.advisory_id}` : ''}
            {(c.range || c.raw || c.json_pointer) && <details><summary>후보 원문·범위</summary><pre className="oc-fix-prompt">{JSON.stringify(c, null, 2)}</pre></details>}
          </div>) : <div>보고된 수정 후보 없음 · 수정 불가 판정은 아닙니다.</div>}
      </div>)}
    </li>)}</ul>
}

export default function PackageDetail({ scanId, groupId, snapshot, onBack, onFinding, onRefresh }) {
  const [state, setState] = useState(null)
  const [copied, setCopied] = useState('')
  const key = `${scanId}:${groupId}:${snapshot || ''}`
  useEffect(() => {
    let cancelled = false
    getPackageDetail(scanId, groupId, snapshot).then(data => {
      if (!cancelled) setState({ key, data })
    }).catch(error => { if (!cancelled) setState({ key, error }) })
    return () => { cancelled = true }
  }, [scanId, groupId, snapshot, key])
  const current = state?.key === key ? state : null
  const response = current?.data
  const group = response?.item
  let text = '', promptError = ''
  if (response) {
    try { text = buildFixPrompt(response) } catch (e) { promptError = e.message }
  }
  async function copy() {
    try {
      // Revalidate before copying so an older rendered snapshot is not silently reused.
      const fresh = await getPackageDetail(scanId, groupId, response.snapshot_id)
      await navigator.clipboard.writeText(buildFixPrompt(fresh))
      setCopied('복사했습니다.')
    } catch (e) {
      if (e.status === 409) setState({ key, error: e })
      else setCopied('복사하지 못했습니다. 아래 문구를 직접 선택해 복사해 주세요.')
    }
  }
  return <div className="oc-detail">
    <div className="oc-detailnav"><button type="button" className="oc-btn" onClick={onBack}>← 목록으로</button></div>
    {!current ? <p role="status">패키지 상세를 불러오는 중…</p> : current.error ?
      <section className="oc-panel" role="alert"><p>{current.error.status === 409 ? '검사 결과가 변경되었거나 아직 준비되지 않았습니다. 최신 자료를 다시 불러와 주세요.' : '패키지 상세를 불러오지 못했습니다.'}</p>
        <button className="oc-btn" onClick={onRefresh}>최신 결과 다시 불러오기</button></section> : <>
      <div><div className="oc-dtitle"><h1>{group.name}@{group.installed_version || '버전 미확인'}</h1>
        <span className="oc-pill">{group.global_rank != null ? `${group.global_rank}위` : group.priority_status === 'severity_unknown' ? '심각도 확인 필요' : '순위 미산정'}</span>
        <span className="oc-tag">{group.ecosystem}</span></div>
        <p className="oc-group-counts"><span>취약점 {group.finding_count}건</span>
          {SEVERITIES.filter(s => group.severity_counts[s]).map(s => <SeverityBadge key={s} severity={s} count={group.severity_counts[s]} />)}</p>
        <p className="oc-hint">전체 취약점 해결 여부 미확인 · 수정 후보는 취약점·설치별 근거입니다.</p>
        {response.result_state === 'partial' && <p className="err">부분 결과입니다. 확인하지 못한 취약점이 있을 수 있습니다.</p>}
        <p className="oc-hint">중복 검토: {response.deduplication_status === 'completed' ? '완료' : '확인 대기'}</p>
      </div>
      <section className="oc-panel"><h2 className="oc-ptitle">설치 정보</h2>
        {group.installations.map(p => <div key={p.package_id} style={{ marginTop: 10 }}>
          <strong>{p.lockfile_path || '설치 위치 미제공'}</strong> · {relationLabel(p.relationship)}
          <div className="oc-hint">라이선스: {p.licenses?.length ? p.licenses.join(' · ') : '정보 없음'}</div>
        </div>)}
        <p className="oc-hint">설치 위치는 상위 의존 경로나 수정할 파일명을 뜻하지 않습니다.</p>
      </section>
      <section className="oc-panel" aria-label="이 패키지의 취약점"><h2 className="oc-ptitle">이 패키지의 취약점과 수정 근거</h2>
        <PackageFindings findings={group.findings || []} onFinding={onFinding} />
      </section>
      {group.ecosystem === 'npm' && group.installed_version && <><p className="oc-hint">AI 설명은 별도로 생성된 요약입니다. 수정 프롬프트의 전체 취약점 근거를 함께 확인해 주세요.</p><AiReport scanId={scanId} scanStatus={response.result_state === 'partial' ? 'partial' : 'completed'} pkg={{ name: group.name, version: group.installed_version }} onFinding={onFinding} hideFindingList /></>}
      <section className="oc-panel" aria-label="수정 프롬프트"><div className="oc-phead"><h2 className="oc-ptitle">수정 프롬프트</h2>
        <button type="button" className="oc-btn" disabled={!text} onClick={copy}>복사</button></div>
        <p className="oc-hint">관련 취약점 전체와 설치별 근거를 AI 코딩 도구에 전달합니다. 복사 시 서버 AI를 호출하지 않습니다.</p>
        {promptError ? <p role="alert">{promptError}</p> : <pre className="oc-fix-prompt">{text}</pre>}
        <p role="status">{copied}</p>
      </section>
    </>}
  </div>
}
