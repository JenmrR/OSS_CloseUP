import { useEffect, useRef, useState } from 'react'
import {
  createScan, getScan, getPackages, getMaintenance,
  getFindings, getSbomInfo, downloadSbom,
} from './api'
import {
  STAGES, ACTIVE, stageProgress, computeProgress,
  uniqueFixVersions, licenseState, vulnScanFailed,
} from './display'
import AiReport from './AiReport'

const STATUS_LABEL = {
  pending: '대기', queued: '대기', running: '진행 중', completed: '완료',
  partial: '부분 완료', failed: '실패', timeout: '시간 초과', skipped: '건너뜀',
}

const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']

const label = (status) => STATUS_LABEL[status] || status || '대기'
const cls = (status) => `badge badge-${status || 'pending'}`

// null은 false가 아니다. 확인되지 않은 값을 '아니오'로 표시하지 않는다.
function triState(value, yes, no) {
  if (value === true) return <span className="flag flag-on">{yes}</span>
  if (value === false) return <span className="muted">{no}</span>
  return <span className="muted">확인 불가</span>
}

function formatDate(value) {
  if (!value) return '—'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? '—' : date.toLocaleDateString('ko-KR')
}

// syft의 tool_version에는 CLI 출력이 통째로 들어온다. 버전 줄만 뽑는다.
function shortVersion(raw) {
  if (!raw) return null
  const match = String(raw).match(/Version:\s*(\S+)/)
  return match ? match[1] : String(raw).split('\n')[0]
}

// 진행 바 한 줄 + 접어 둔 단계별 상세.
function Progress({ scan }) {
  const [open, setOpen] = useState(false)
  const progress = computeProgress(scan)
  if (!progress) return null
  const toolStatus = scan.tool_status || {}
  const failedAll = progress.status === 'failed'
  const partial = progress.status === 'partial' || (progress.failed.length > 0 && !failedAll)
  const active = ACTIVE.has(progress.status)

  let message
  if (failedAll) message = '검사에 실패했습니다. 파일을 다시 올려 검사해 주세요.'
  else if (active) message = progress.current
    ? `${progress.current.name} 중${progress.current.detail ? ` (${progress.current.detail.done}/${progress.current.detail.total})` : ''}`
    : '검사를 준비하고 있습니다.'
  else if (partial) message = '검사가 끝났지만 일부 단계를 확인하지 못했습니다.'
  else message = '검사가 끝났습니다.'

  return (
    <section className="card">
      <div className="card-head">
        <h2>검사 진행</h2>
        <span className={cls(progress.status)}>{label(progress.status)}</span>
      </div>
      <div className="stage-progress" role="progressbar" aria-valuemin={0} aria-valuemax={100}
        aria-valuenow={progress.percent} aria-label="검사 진행률">
        <span className="bar" style={{ flex: 1 }}>
          <span style={{
            width: `${progress.percent}%`,
            ...(failedAll ? { background: '#c62828' } : partial ? { background: '#d9480f' } : {}),
          }} />
        </span>
        <strong>{progress.percent}%</strong>
      </div>
      <p className={failedAll ? 'error-text' : 'muted'}>{message}</p>
      {progress.failed.length > 0 && (
        <p className="error-text">확인하지 못한 단계: {progress.failed.join(', ')}. 이 단계의 결과는 "확인 불가"로 표시됩니다.</p>
      )}
      {progress.workerReason && (
        <p className="error-text">검사 시작 단계에서 실패했습니다 ({progress.workerReason}).</p>
      )}

      <button type="button" className="link" onClick={() => setOpen((v) => !v)} aria-expanded={open}>
        {open ? '자세히 닫기 ▴' : '자세히 보기 ▾'}
      </button>
      {open && (
        <ul className="stages">
          {STAGES.map(([key, name]) => {
            const stage = toolStatus[key] || {}
            const detail = stageProgress(stage)
            return (
              <li key={key}>
                <span className="stage-name">{name}</span>
                <span className={cls(stage.status)}>{label(stage.status)}</span>
                {detail && <span className="muted">{detail.done} / {detail.total}개</span>}
                {stage.error_message && <span className="error-text">{stage.error_message}</span>}
              </li>
            )
          })}
        </ul>
      )}
    </section>
  )
}

function Upload({ onCreated, busy }) {
  const [files, setFiles] = useState({ pkg: null, lock: null })
  const [error, setError] = useState(null)
  const [manual, setManual] = useState('')

  async function submit(event) {
    event.preventDefault()
    setError(null)
    if (!files.pkg || !files.lock) {
      setError('package.json과 package-lock.json 두 파일이 모두 필요합니다.')
      return
    }
    try {
      const result = await createScan(files.pkg, files.lock)
      onCreated(result.scan_id)
    } catch (err) {
      setError(err.message)
    }
  }

  return (
    <section className="card">
      <div className="card-head"><h2>검사 시작</h2></div>
      <form onSubmit={submit} className="upload">
        <label>
          package.json
          <input type="file" accept=".json,application/json"
            onChange={(e) => setFiles((f) => ({ ...f, pkg: e.target.files[0] || null }))} />
        </label>
        <label>
          package-lock.json
          <input type="file" accept=".json,application/json"
            onChange={(e) => setFiles((f) => ({ ...f, lock: e.target.files[0] || null }))} />
        </label>
        <button type="submit" disabled={busy}>검사 실행</button>
      </form>
      <p className="hint">lockfileVersion 2 또는 3만 지원합니다. zip 등 다른 파일은 받지 않습니다.</p>

      <form className="manual" onSubmit={(e) => { e.preventDefault(); if (manual.trim()) onCreated(manual.trim()) }}>
        <input value={manual} onChange={(e) => setManual(e.target.value)}
          placeholder="기존 scan_id로 결과 보기" />
        <button type="submit">불러오기</button>
      </form>
      {error && <p className="error-text">{error}</p>}
    </section>
  )
}

function Sbom({ scanId, info }) {
  const [error, setError] = useState(null)
  const [downloading, setDownloading] = useState(false)
  async function download() {
    setError(null); setDownloading(true)
    try {
      const blob = await downloadSbom(scanId)
      const url = URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url; link.download = info.filename
      document.body.appendChild(link); link.click(); link.remove()
      setTimeout(() => URL.revokeObjectURL(url), 1000)
    } catch (err) {
      setError(err.message)
    } finally {
      setDownloading(false)
    }
  }
  if (!info) return null
  if (!info.available) {
    const status = info.syft && info.syft.status
    return (
      <section className="card">
        <div className="card-head"><h2>SBOM</h2></div>
        <p className="muted">
          다운로드 가능한 최신 성공 SBOM이 없습니다 (Syft: {label(status)}).
          패키지가 0개라는 뜻이 아닙니다.
        </p>
        {info.syft && info.syft.error_message && <p className="error-text">{info.syft.error_message}</p>}
      </section>
    )
  }
  const size = (info.artifact.size_bytes / 1024).toFixed(0)
  return (
    <section className="card">
      <div className="card-head"><h2>SBOM</h2></div>
      <button onClick={download} disabled={downloading}>
        {downloading ? '내려받는 중…' : 'SPDX JSON 내려받기'}
      </button>
      {error && <p role="alert" className="error-text">{error} 다시 내려받기를 시도해 주세요.</p>}
      <dl className="meta">
        <div><dt>크기</dt><dd>{size} KB</dd></div>
        <div><dt>생성 도구</dt><dd>Syft {shortVersion(info.syft && info.syft.tool_version) || '—'}</dd></div>
        <div><dt>SHA-256</dt><dd className="mono">{info.artifact.sha256.slice(0, 16)}…</dd></div>
      </dl>
      <p className="hint">다운로드 시 서버가 저장된 해시와 대조해 파일이 그대로인지 확인합니다.</p>
    </section>
  )
}

function Packages({ data }) {
  if (!data) return <p className="muted">불러오는 중…</p>
  const status = (data.package_storage || {}).status
  const items = data.items || []
  const external = items.filter((item) => item.relationship !== 'root')
  if (status !== 'completed' && external.length === 0) {
    return <p className="muted">패키지 저장이 아직 끝나지 않았습니다 ({label(status)}). 0개라는 뜻이 아닙니다.</p>
  }
  const direct = external.filter((item) => item.relationship === 'direct').length
  return (
    <>
      <p className="summary">
        외부 의존성 {external.length}개 · 직접 {direct}개 · 간접 {external.length - direct}개
        <span className="muted"> (루트 프로젝트 제외)</span>
      </p>
      <table>
        <thead>
          <tr><th>패키지</th><th>버전</th><th>구분</th><th>라이선스</th><th>설치 경로</th></tr>
        </thead>
        <tbody>
          {external.map((item) => (
            <tr key={item.package_id}>
              <td className="mono">{item.name}</td>
              <td className="mono">{item.installed_version || '—'}</td>
              <td>{item.relationship === 'direct' ? '직접' : item.relationship === 'indirect' ? '간접' : '확인 불가'}</td>
              <td>{item.licenses && item.licenses.length
                ? item.licenses.join(', ')
                : <span className="muted">정보 없음</span>}
                {licenseState(item.licenses) === 'review' && <span className="flag flag-warn">확인 필요</span>}</td>
              <td className="mono path">{item.lockfile_path}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  )
}

// 라이선스 탭: 확인이 필요한 패키지만 모아서 보여준다. 법적 판정은 하지 않는다.
function Licenses({ data }) {
  if (!data) return <p className="muted">불러오는 중…</p>
  const status = (data.package_storage || {}).status
  const external = (data.items || []).filter((item) => item.relationship !== 'root')
  if (status !== 'completed' && external.length === 0) {
    return <p className="muted">패키지 저장이 아직 끝나지 않았습니다 ({label(status)}). 라이선스 정보가 없다는 뜻이 아닙니다.</p>
  }
  const review = external.filter((item) => licenseState(item.licenses) === 'review')
  const unknown = external.filter((item) => licenseState(item.licenses) === 'unknown')
  const rows = [...review, ...unknown]
  return (
    <>
      <p className="summary">
        확인 필요 {review.length}개 · 정보 없음 {unknown.length}개 · 그 외 {external.length - rows.length}개
      </p>
      {rows.length === 0 ? (
        <p className="muted">따로 확인을 안내할 라이선스가 없습니다. 패키지에 선언된 정보 기준이며, 법적 검토를 대신하지 않습니다.</p>
      ) : (
        <table>
          <thead>
            <tr><th>패키지</th><th>버전</th><th>구분</th><th>선언 라이선스</th><th>안내</th></tr>
          </thead>
          <tbody>
            {rows.map((item) => (
              <tr key={item.package_id}>
                <td className="mono">{item.name}</td>
                <td className="mono">{item.installed_version || '—'}</td>
                <td>{item.relationship === 'direct' ? '직접' : item.relationship === 'indirect' ? '간접' : '확인 불가'}</td>
                <td>{(item.licenses || []).join(', ') || <span className="muted">정보 없음</span>}</td>
                <td>{licenseState(item.licenses) === 'review'
                  ? <><span className="flag flag-warn">확인 필요</span> 배포 방식에 따라 지켜야 할 의무가 있을 수 있습니다.</>
                  : <span className="muted">선언된 라이선스를 찾지 못했습니다.</span>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <p className="hint">패키지에 선언된 라이선스 기준입니다. 위험하다는 판정이 아니라 확인이 필요하다는 안내입니다.</p>
    </>
  )
}

function Findings({ data, scan }) {
  if (!data) return <p className="muted">불러오는 중…</p>
  const status = (data.normalization || {}).status
  const items = data.items || []
  if (status !== 'completed' && items.length === 0) {
    return <p className="muted">취약점 정규화가 아직 연결되지 않았습니다 ({label(status)}). 취약점 0건이라는 뜻이 아닙니다.</p>
  }
  const scanFailed = vulnScanFailed(scan)
  if (items.length === 0) {
    return scanFailed
      ? <p className="error-text">취약점 검사 일부가 실패했습니다. 발견된 항목이 없는 것처럼 보여도 확인하지 못한 취약점이 있을 수 있습니다.</p>
      : <p className="muted">취약점 검사가 정상 완료되었고, 알려진 취약점은 발견되지 않았습니다. 코드에 문제가 없다는 보장은 아닙니다.</p>
  }
  const counts = SEVERITY_ORDER.map((level) => [level, items.filter((i) => i.severity === level).length])
    .filter(([, n]) => n > 0)
  return (
    <>
      {scanFailed && <p className="error-text">취약점 검사 일부가 실패해 이 목록이 전부가 아닐 수 있습니다.</p>}
      <p className="summary">
        Finding {items.length}건
        {counts.map(([level, n]) => <span key={level} className={`sev sev-${level}`}>{level} {n}</span>)}
      </p>
      <table>
        <thead>
          <tr><th>식별자</th><th>심각도</th><th>출처</th><th>영향 패키지</th><th>조치 우선순위</th></tr>
        </thead>
        <tbody>
          {items.map((item) => {
            const ids = Array.isArray(item.identifiers) ? item.identifiers : []
            const packages = Array.isArray(item.packages) ? item.packages : []
            const priorities = [...new Set(packages.map((p) => p.priority).filter(Boolean))]
            return (
              <tr key={item.finding_id}>
                <td className="mono">
                  {item.canonical_id || ids.map((x) => (typeof x === 'string' ? x : x.value || x.id)).filter(Boolean).join(', ') || item.finding_key}
                  {item.manual_review_required && <span className="flag flag-warn">수동 확인</span>}
                </td>
                <td style={{ whiteSpace: 'nowrap' }}><span className={`sev sev-${item.severity || 'UNKNOWN'}`}>{item.severity || 'UNKNOWN'}</span></td>
                <td className="muted" style={{ whiteSpace: 'nowrap' }} title={(item.source_tools || []).join(', ')}>
                  {(item.source_tools || []).length ? `엔진 ${item.source_tools.length}개` : '—'}
                </td>
                <td>
                  {packages.length === 0 ? <span className="muted">—</span> : (
                    <ul className="pkg-list">
                      {packages.map((p) => {
                        const fixes = uniqueFixVersions(p.fixed_version_candidates)
                        return (
                          <li key={p.package_id}>
                            <span className="mono">{p.name}@{p.installed_version}</span>
                            <span className="muted"> {p.relationship === 'direct' ? '직접' : '간접'}</span>
                            {p.recommended_fixed_version
                              ? <span className="fix">→ {p.recommended_fixed_version}</span>
                              : fixes.length === 0
                                ? <span className="muted"> 수정 정보 확인 필요</span>
                                : <span className="muted"> 수정 후보 {fixes.join(', ')} (호환성 확인 필요)</span>}
                          </li>
                        )
                      })}
                    </ul>
                  )}
                </td>
                <td style={{ whiteSpace: 'nowrap' }}>{priorities.length ? priorities.join(', ') : <span className="muted">산정 전</span>}</td>
              </tr>
            )
          })}
        </tbody>
      </table>
      <p className="hint">
        심각도는 검사 엔진 값을 그대로 씁니다. 조치 우선순위는 별도 규칙으로 계산하며 심각도를 낮추지 않습니다.
      </p>
    </>
  )
}

function Maintenance({ data }) {
  if (!data) return <p className="muted">불러오는 중…</p>
  const status = (data.collection || {}).status
  const items = data.items || []
  if (status !== 'completed' && items.length === 0) {
    return <p className="muted">유지보수 정보 조회가 아직 끝나지 않았습니다 ({label(status)}).</p>
  }
  return (
    <>
      <p className="summary">{items.length}개 패키지 · 활동이 낮다고 해서 취약한 것은 아닙니다</p>
      <table>
        <thead>
          <tr><th>패키지</th><th>저장소</th><th>최근 커밋</th><th>archived</th><th>deprecated</th><th>조회 상태</th></tr>
        </thead>
        <tbody>
          {items.map((item) => (
            <tr key={item.package_id}>
              <td className="mono">{item.name}</td>
              <td className="mono">{item.repository_full_name || <span className="muted">매핑 없음</span>}</td>
              <td>{formatDate(item.latest_commit_at)}</td>
              <td>{triState(item.archived, 'archived', '아니오')}</td>
              <td>{triState(item.deprecated, 'deprecated', '아니오')}</td>
              <td>
                <span className={cls(item.github_status === 'success' ? 'completed' : item.github_status)}>
                  GitHub {item.github_status}
                </span>
                {item.github_error && <span className="error-text"> {item.github_error}</span>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  )
}

export default function App() {
  const [scanId, setScanId] = useState('')
  const [scan, setScan] = useState(null)
  const [packages, setPackages] = useState(null)
  const [findings, setFindings] = useState(null)
  const [maintenance, setMaintenance] = useState(null)
  const [sbom, setSbom] = useState(null)
  const [tab, setTab] = useState('packages')
  const [error, setError] = useState(null)
  const timer = useRef(null)

  const [reload, setReload] = useState(0)
  const generation = useRef(0)

  useEffect(() => {
    if (!scanId) return undefined
    let scheduledTimer
    const currentGeneration = ++generation.current
    const stale = () => generation.current !== currentGeneration

    async function tick() {
      try {
        const current = await getScan(scanId)
        if (stale()) return
        setScan(current)
        const results = await Promise.allSettled([
          getPackages(scanId), getFindings(scanId), getMaintenance(scanId), getSbomInfo(scanId),
        ])
        if (stale()) return
        const setters = [setPackages, setFindings, setMaintenance, setSbom]
        const names = ['패키지', '취약점', '유지보수', 'SBOM']
        const errors = []
        results.forEach((result, index) => {
          setters[index](result.status === 'fulfilled' ? result.value : null)
          if (result.status === 'rejected') errors.push(`${names[index]}: ${result.reason.message}`)
        })
        setError(errors.length ? errors.join(' / ') : null)
        if (ACTIVE.has(current.status)) {
          scheduledTimer = setTimeout(tick, 3000)
          timer.current = scheduledTimer
        }
      } catch (err) {
        if (!stale()) setError(err.message)
      }
    }

    tick()
    return () => { generation.current = currentGeneration + 1; clearTimeout(scheduledTimer) }
  }, [scanId, reload])

  function start(id) {
    generation.current++
    setReload((value) => value + 1)
    if (timer.current) clearTimeout(timer.current)
    setScan(null); setPackages(null); setFindings(null); setMaintenance(null); setSbom(null)
    setError(null); setScanId(id)
  }

  const busy = scan ? ACTIVE.has(scan.status) : false

  return (
    <div className="app">
      <header>
        <h1>OSS 클로즈업</h1>
        <p>오픈소스 의존성의 취약점·라이선스·유지보수 상태를 한 화면에서 확인합니다.</p>
      </header>

      <Upload onCreated={start} busy={busy} />
      {error && <div role="alert" className="error-text">{error}
        <button onClick={() => start(scanId)}>다시 불러오기</button>
      </div>}

      {scanId && (
        <>
          <p className="scan-id">검사 ID <span className="mono">{scanId}</span></p>
          <Progress scan={scan} />
          <AiReport scanId={scanId} scanStatus={scan && scan.status} />
          <Sbom key={`${scanId}-${reload}`} scanId={scanId} info={sbom} />

          <section className="card">
            <nav className="tabs">
              <button className={tab === 'packages' ? 'on' : ''} onClick={() => setTab('packages')}>패키지</button>
              <button className={tab === 'findings' ? 'on' : ''} onClick={() => setTab('findings')}>취약점</button>
              <button className={tab === 'licenses' ? 'on' : ''} onClick={() => setTab('licenses')}>라이선스</button>
              <button className={tab === 'maintenance' ? 'on' : ''} onClick={() => setTab('maintenance')}>유지보수</button>
            </nav>
            <div className="tab-body">
              {tab === 'packages' && <Packages data={packages} />}
              {tab === 'findings' && <Findings data={findings} scan={scan} />}
              {tab === 'licenses' && <Licenses data={packages} />}
              {tab === 'maintenance' && <Maintenance data={maintenance} />}
            </div>
          </section>
        </>
      )}
    </div>
  )
}
