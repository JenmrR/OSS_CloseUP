// 화면 표시용 계산 모음. React와 분리해 node --test로 검증한다.

// 검사 단계. 메인 화면에는 도구 이름 대신 역할 이름을 쓴다.
export const STAGES = [
  ['trivy', '취약점 검사 (1차)'],
  ['osv', '취약점 검사 (2차)'],
  ['syft', '패키지 목록·라이선스 확인'],
  ['package_storage', '패키지 저장'],
  ['normalization', '결과 정리'],
  ['github', '유지보수 정보 조회'],
]

export const VULN_STAGES = ['trivy', 'osv']
export const ACTIVE = new Set(['queued', 'running'])
const DONE = new Set(['completed', 'partial', 'failed', 'timeout', 'skipped'])
const FAILED = new Set(['failed', 'timeout'])

// 단계 안의 세부 진행(예: 유지보수 34/76). 필드가 없으면 null.
export function stageProgress(stage) {
  if (!stage || typeof stage !== 'object') return null
  const done = stage.completed ?? stage.processed ?? stage.progress ?? stage.done
  const total = stage.total ?? stage.count ?? stage.packages
  if (typeof done === 'number' && typeof total === 'number' && total > 0) {
    const clamped = Math.min(Math.max(done, 0), total)
    return { done: clamped, total, percent: Math.round((clamped / total) * 100) }
  }
  return null
}

// 전체 진행률. 실제로 끝난 단계와 진행 중 단계의 세부 진행만 반영한다.
// 시간이 지나면 저절로 오르는 값은 만들지 않는다.
export function computeProgress(scan) {
  if (!scan) return null
  const toolStatus = scan.tool_status || {}
  let sum = 0
  let current = null
  const failed = []
  for (const [key, name] of STAGES) {
    const stage = toolStatus[key] || {}
    if (DONE.has(stage.status)) {
      sum += 1
    } else if (stage.status === 'running') {
      const detail = stageProgress(stage)
      if (detail) sum += detail.done / detail.total
      if (!current) current = { name, detail }
    }
    if (FAILED.has(stage.status)) failed.push(name)
  }
  // 도구 실행 전에 worker 자체가 실패한 경우(예: 결과 폴더 권한)
  const worker = toolStatus.worker
  const workerReason = worker && FAILED.has(worker.status) ? (worker.reason || '알 수 없는 오류') : null

  let percent = Math.round((sum / STAGES.length) * 100)
  if (scan.status === 'completed' || scan.status === 'partial') percent = 100
  if (ACTIVE.has(scan.status) && percent >= 100) percent = 99 // 끝나기 전에는 100%를 보이지 않는다

  return { percent, status: scan.status, current, failed, workerReason }
}

// 같은 수정 후보 값을 도구별로 중복 보고하는 경우가 있어 고유 값만 남긴다.
// 어떤 값이 설치 버전에 맞는지는 판정하지 않는다(priority·추천 규칙의 영역).
export function uniqueFixVersions(candidates) {
  const seen = new Set()
  const out = []
  for (const c of candidates || []) {
    const value = c && typeof c === 'object' ? c.value : c
    if (typeof value === 'string' && value && !seen.has(value)) {
      seen.add(value)
      out.push(value)
    }
  }
  return out
}

// 배포 방식에 따라 의무가 생길 수 있어 확인을 안내할 라이선스(잠정 목록, 공동 합의 필요).
// 위험 판정이 아니라 '확인 필요' 안내 기준이다.
export const LICENSE_REVIEW_PATTERNS = [/\b(A|L)?GPL\b/i, /\bSSPL\b/i, /\bEUPL\b/i]

export function licenseState(licenses) {
  const list = (licenses || []).filter((x) => typeof x === 'string' && x.trim())
  if (list.length === 0) return 'unknown'
  if (list.some((l) => LICENSE_REVIEW_PATTERNS.some((re) => re.test(l)))) return 'review'
  return 'ok'
}

// AI 보고서 상태를 화면 문구로 바꾼다. 본문은 succeeded일 때만 보여준다.
export function aiReportView({ loading, data, error } = {}) {
  if (loading) return { tone: 'muted', message: 'AI 설명을 불러오는 중입니다.' }
  if (error) return { tone: 'error', message: 'AI 설명을 불러오지 못했습니다. 검사 결과는 아래에서 그대로 확인할 수 있습니다.' }
  const status = data && data.status
  const meta = data && data.prompt_version
    ? `${data.model || '모델 미기록'} · 프롬프트 ${data.prompt_version}${data.created_at ? ` · ${data.created_at.slice(0, 16).replace('T', ' ')} 생성` : ''}`
    : null
  switch (status) {
    case 'succeeded':
      return { tone: 'muted', message: '이 검사 결과를 바탕으로 만든 설명입니다.', output: data.output, meta }
    case 'pending':
    case 'running':
      return { tone: 'muted', message: 'AI 설명을 만들고 있습니다.', meta }
    case 'failed':
    case 'rejected':
      return { tone: 'error', message: data.message || '설명을 만들지 못했습니다.', meta }
    default:
      return { tone: 'muted', message: 'AI 설명은 아직 준비되지 않았습니다.' }
  }
}

// 취약점 검사 단계 중 실패한 것이 있는지. 0건 안내 문구를 고르는 데 쓴다.
export function vulnScanFailed(scan) {
  const toolStatus = (scan && scan.tool_status) || {}
  return VULN_STAGES.some((key) => FAILED.has((toolStatus[key] || {}).status))
}

// ── 취약점 상세: 고치는 방법 ──────────────────────────────

const SEMVER = /^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/

export function parseSemver(value) {
  const m = SEMVER.exec(String(value ?? '').trim())
  return m ? { nums: [Number(m[1]), Number(m[2]), Number(m[3])], pre: m[4] || null } : null
}

// a<b: -1, a=b: 0, a>b: 1, 비교 불가: null. 정식 버전이 같은 숫자의 pre-release보다 크다.
export function compareSemver(a, b) {
  const x = parseSemver(a)
  const y = parseSemver(b)
  if (!x || !y) return null
  for (let i = 0; i < 3; i += 1) {
    if (x.nums[i] !== y.nums[i]) return x.nums[i] < y.nums[i] ? -1 : 1
  }
  if (x.pre === y.pre) return 0
  if (!x.pre) return 1
  if (!y.pre) return -1
  return x.pre < y.pre ? -1 : 1
}

// OSV 영향 범위(introduced ~ fixed)에 설치 버전이 들어가는 수정 버전만 고른다.
// 추측이 아니라 범위 데이터로 확인되는 값만 쓴다. 확인할 수 없으면 null.
export function rangeFixFor(installed, candidates) {
  if (!parseSemver(installed)) return null
  const matches = []
  for (const c of candidates || []) {
    const range = c && c.range
    if (!range || !Array.isArray(range.events) || (range.type && range.type !== 'SEMVER')) continue
    let introduced = null
    for (const event of range.events) {
      if (event && event.introduced !== undefined) {
        introduced = String(event.introduced)
      } else if (event && event.fixed !== undefined && introduced !== null) {
        const fixed = String(event.fixed)
        const afterStart = introduced === '0' || compareSemver(installed, introduced) >= 0
        const beforeFix = compareSemver(installed, fixed) === -1
        if (afterStart && beforeFix && parseSemver(fixed)) matches.push(fixed)
        introduced = null
      }
    }
  }
  if (matches.length === 0) return null
  // 여러 권고가 있으면 모두를 만족하는 가장 높은 값
  return matches.sort((a, b) => compareSemver(a, b)).at(-1)
}

// 복사용 명령어에 들어갈 값은 npm 이름·버전 형식일 때만 쓴다(이상한 문자열이 명령어에 섞이지 않게).
const NPM_NAME = /^(@[a-z0-9][a-z0-9._~-]*\/)?[a-z0-9][a-z0-9._~-]*$/

// 패키지별 고치는 방법. kind: direct | indirect | none | unverified
export function fixGuide(pkg) {
  const candidates = uniqueFixVersions(pkg && pkg.fixed_version_candidates)
  if (candidates.length === 0) return { kind: 'none', candidates }
  const target = rangeFixFor(pkg.installed_version, pkg.fixed_version_candidates)
  const safe = NPM_NAME.test(pkg.name || '') && parseSemver(target)
  if (!target || !safe) return { kind: 'unverified', candidates }
  if (pkg.relationship === 'direct') {
    return { kind: 'direct', target, candidates, commands: [`npm install ${pkg.name}@${target}`] }
  }
  if (pkg.relationship === 'indirect') {
    return { kind: 'indirect', target, candidates, commands: [`npm ls ${pkg.name}`, `npm update ${pkg.name}`] }
  }
  return { kind: 'unverified', candidates }
}

export function findingLabel(item) {
  const ids = Array.isArray(item && item.identifiers) ? item.identifiers : []
  return (item && item.canonical_id)
    || ids.map((x) => (typeof x === 'string' ? x : x.value || x.id)).filter(Boolean).join(', ')
    || (item && item.finding_key) || '—'
}

// ── 주소(#) 기반 화면 위치: 새로고침·뒤로 가기·주소 공유용 ──
const ROUTE = /^#\/scan\/([0-9a-fA-F-]{36})(?:\/finding\/([0-9a-fA-F-]{36}))?$/

export function parseRoute(hash) {
  const m = ROUTE.exec(hash || '')
  return m ? { scanId: m[1], findingId: m[2] || null } : { scanId: null, findingId: null }
}

export function routeHash(scanId, findingId) {
  if (!scanId) return ''
  return findingId ? `#/scan/${scanId}/finding/${findingId}` : `#/scan/${scanId}`
}
