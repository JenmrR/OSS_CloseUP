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

// 취약점 검사 단계 중 실패한 것이 있는지. 0건 안내 문구를 고르는 데 쓴다.
export function vulnScanFailed(scan) {
  const toolStatus = (scan && scan.tool_status) || {}
  return VULN_STAGES.some((key) => FAILED.has((toolStatus[key] || {}).status))
}
