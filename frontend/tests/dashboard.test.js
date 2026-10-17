import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  vulnItems, severityCounts, bestPriority, firstLook, priorityComputed, packageSummary,
  licenseSummary, maintenanceSummary, fixSummary, stagesDone, scanDuration, aiFindingView, aiSections,
} from '../src/display.js'

const f = (id, severity, priorities, extra = {}) => ({
  finding_id: id, canonical_id: id, severity, type: 'vulnerability',
  packages: priorities.map((p) => ({ name: 'x', installed_version: '1.0.0', priority: p })), ...extra,
})

test('취약점 유형만 고른다', () => {
  const items = vulnItems({ items: [f('a', 'HIGH', []), { type: 'license', finding_id: 'l' }, { finding_id: 'n' }] })
  assert.deepEqual(items.map((i) => i.finding_id), ['a', 'n'])
})

test('심각도 건수: 모르는 값은 UNKNOWN', () => {
  const c = severityCounts([f('a', 'CRITICAL', []), f('b', 'MEDIUM', []), f('c', 'MEDIUM', []), f('d', 'weird', [])])
  assert.deepEqual(c, { CRITICAL: 1, HIGH: 0, MEDIUM: 2, LOW: 0, UNKNOWN: 1 })
})

test('가장 급한 우선순위, 계산 전이면 null', () => {
  assert.equal(bestPriority(f('a', 'HIGH', ['P2', 'P0'])), 'P0')
  assert.equal(bestPriority(f('a', 'HIGH', [null])), null)
  assert.equal(bestPriority({ priority: 'P1', packages: [] }), 'P1')
})

test('먼저 볼 항목은 우선순위 순, 같으면 심각도 순, P3·INFO·산정 전 제외', () => {
  const items = [f('m', 'MEDIUM', ['P1']), f('c', 'CRITICAL', ['P1']), f('h', 'HIGH', ['P0']), f('x', 'CRITICAL', ['P3']), f('n', 'CRITICAL', [])]
  assert.deepEqual(firstLook(items).map((i) => i.finding_id), ['h', 'c', 'm'])
  assert.equal(firstLook(items)[0].best_priority, 'P0')
  assert.equal(priorityComputed([f('n', 'CRITICAL', [])]), false)
})

test('먼저 볼 항목은 최대 5개', () => {
  const items = Array.from({ length: 8 }, (_, i) => f(`id${i}`, 'HIGH', ['P1']))
  assert.equal(firstLook(items).length, 5)
})

test('패키지 요약은 루트를 빼고 센다', () => {
  const s = packageSummary({ package_storage: { status: 'completed' }, items: [
    { relationship: 'root', name: 'my-app' }, { relationship: 'direct' }, { relationship: 'indirect' }, { relationship: 'unknown' }] })
  assert.deepEqual([s.total, s.direct, s.indirect, s.unknown, s.root.name, s.status], [3, 1, 1, 1, 'my-app', 'completed'])
})

test('라이선스 요약: 확인 필요와 정보 없음', () => {
  const s = licenseSummary({ items: [{ licenses: ['GPL-3.0'] }, { licenses: [] }, { licenses: ['MIT'] }, { relationship: 'root', licenses: [] }] })
  assert.deepEqual(s, { review: 1, unknown: 1, total: 2 })
})

test('유지보수 요약은 true만 센다(null은 아니오가 아님)', () => {
  const s = maintenanceSummary({ collection: { status: 'completed' }, items: [{ archived: true, deprecated: null }, { archived: null, deprecated: true }, { archived: true, deprecated: true }, { archived: null }] })
  assert.deepEqual([s.archived, s.deprecated, s.flagged, s.status], [2, 2, 3, 'completed'])
})

test('수정 정보 요약', () => {
  const ranged = { name: 'form-data', installed_version: '4.0.0', relationship: 'indirect', fixed_version_candidates: [
    { value: '4.0.4', range: { type: 'SEMVER', events: [{ introduced: '4.0.0' }, { fixed: '4.0.4' }] } }] }
  assert.equal(fixSummary(ranged).text, '수정 버전 4.0.4')
  assert.equal(fixSummary({ ...ranged, recommended_fixed_version: '4.0.5' }).text, '수정 버전 4.0.5')
  assert.equal(fixSummary({ name: 'a', installed_version: '1.0.0', fixed_version_candidates: ['1.2.0'] }).text, '수정 후보 1.2.0 (확인 필요)')
  assert.equal(fixSummary({ name: 'a', installed_version: '1.0.0', fixed_version_candidates: [] }).text, '보고된 수정 버전 없음')
})

test('끝난 단계 수와 소요 시간', () => {
  assert.equal(stagesDone({ tool_status: { trivy: { status: 'completed' }, osv: { status: 'failed' }, syft: { status: 'running' } } }), 2)
  assert.equal(scanDuration({ started_at: '2026-10-11T12:20:00Z', finished_at: '2026-10-11T12:21:12Z' }), '1분 12초')
  assert.equal(scanDuration({ started_at: '2026-10-11T12:20:00Z' }), null)
})

test('AI 설명 상태: 자동 대상이 아닌 심각도는 대상 아님', () => {
  assert.equal(aiFindingView({ data: { status: 'not_generated' } }, 'MEDIUM').kind, 'skipped')
  assert.equal(aiFindingView({ data: { status: 'not_generated' } }, 'HIGH').kind, 'none')
  assert.equal(aiFindingView({ data: { status: 'succeeded', output: {}, prompt_version: 'v1' } }, 'MEDIUM').kind, 'done')
  assert.equal(aiFindingView({ data: { status: 'failed' } }, 'CRITICAL').kind, 'failed')
  assert.equal(aiFindingView({ loading: true }, 'MEDIUM').kind, 'loading')
})

test('AI 출력 섹션: 아는 키만 문장, 나머지는 원문', () => {
  const r = aiSections({ summary: 's', reason: 'r', evidence: ['CVE-1', { label: '수정 버전 1.0' }], score: 3 })
  assert.deepEqual(r.sections.map((s) => s.label), ['요약', '왜 먼저 봐야 하나'])
  assert.deepEqual(r.evidence, ['CVE-1', '수정 버전 1.0'])
  assert.deepEqual(r.extra, { score: 3 })
  assert.deepEqual(aiSections(null), { sections: [], evidence: [], extra: null })
})
