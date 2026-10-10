import { test } from 'node:test'
import assert from 'node:assert/strict'
import { compareSemver, rangeFixFor, fixGuide, parseRoute, routeHash, findingLabel } from '../src/display.js'

// 실제 indirect-critical 검사의 form-data 수정 후보(Trivy 3개 + OSV 범위 3개)
const formData = {
  name: 'form-data', installed_version: '4.0.0', relationship: 'indirect',
  fixed_version_candidates: [
    { raw: '2.5.4, 3.0.4, 4.0.4', kind: 'tool_expression', value: '2.5.4', source_tool: 'trivy' },
    { raw: '2.5.4, 3.0.4, 4.0.4', kind: 'tool_expression', value: '3.0.4', source_tool: 'trivy' },
    { raw: '2.5.4, 3.0.4, 4.0.4', kind: 'tool_expression', value: '4.0.4', source_tool: 'trivy' },
    { kind: 'range_fixed_event', value: '2.5.4', source_tool: 'osv', range: { type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '2.5.4' }] } },
    { kind: 'range_fixed_event', value: '3.0.4', source_tool: 'osv', range: { type: 'SEMVER', events: [{ introduced: '3.0.0' }, { fixed: '3.0.4' }] } },
    { kind: 'range_fixed_event', value: '4.0.4', source_tool: 'osv', range: { type: 'SEMVER', events: [{ introduced: '4.0.0' }, { fixed: '4.0.4' }] } },
  ],
}

test('semver compare including pre-release', () => {
  assert.equal(compareSemver('4.0.0', '4.0.4'), -1)
  assert.equal(compareSemver('4.17.21', '4.17.21'), 0)
  assert.equal(compareSemver('1.10.0', '1.9.9'), 1)
  assert.equal(compareSemver('2.0.0-beta.1', '2.0.0'), -1)
  assert.equal(compareSemver('latest', '1.0.0'), null)
})

test('form-data 4.0.0 picks only 4.0.4 from its own range', () => {
  assert.equal(rangeFixFor('4.0.0', formData.fixed_version_candidates), '4.0.4')
  assert.equal(rangeFixFor('3.0.1', formData.fixed_version_candidates), '3.0.4')
  assert.equal(rangeFixFor('2.3.0', formData.fixed_version_candidates), '2.5.4')
})

test('already fixed or outside any range gives no target', () => {
  assert.equal(rangeFixFor('4.0.4', formData.fixed_version_candidates), null)
  assert.equal(rangeFixFor('5.0.0', formData.fixed_version_candidates), null)
})

test('tool expressions alone (no range) are not enough to build a command', () => {
  const onlyTrivy = { ...formData, fixed_version_candidates: formData.fixed_version_candidates.slice(0, 3) }
  const g = fixGuide(onlyTrivy)
  assert.equal(g.kind, 'unverified')
  assert.deepEqual(g.candidates, ['2.5.4', '3.0.4', '4.0.4'])
  assert.equal(g.commands, undefined)
})

test('indirect package: inspect + update, never a direct npm install', () => {
  const g = fixGuide(formData)
  assert.equal(g.kind, 'indirect')
  assert.equal(g.target, '4.0.4')
  assert.deepEqual(g.commands, ['npm ls form-data', 'npm update form-data'])
  assert.ok(!g.commands.some((c) => c.startsWith('npm install')))
})

test('direct package: npm install with the range-verified version', () => {
  const lodash = { name: 'lodash', installed_version: '4.17.15', relationship: 'direct',
    fixed_version_candidates: [{ kind: 'range_fixed_event', value: '4.17.21', range: { type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.21' }] } }] }
  assert.deepEqual(fixGuide(lodash).commands, ['npm install lodash@4.17.21'])
  const scoped = { ...lodash, name: '@scope/pkg' }
  assert.deepEqual(fixGuide(scoped).commands, ['npm install @scope/pkg@4.17.21'])
})

test('no fix info: no command (request 2.88.2 case)', () => {
  const g = fixGuide({ name: 'request', installed_version: '2.88.2', relationship: 'direct', fixed_version_candidates: [] })
  assert.equal(g.kind, 'none')
  assert.equal(g.commands, undefined)
})

test('unsafe package names or versions never reach a command', () => {
  const evil = { ...formData, relationship: 'direct', name: 'x; rm -rf ~' }
  assert.equal(fixGuide(evil).kind, 'unverified')
  const evilVer = { name: 'a', installed_version: '1.0.0', relationship: 'direct',
    fixed_version_candidates: [{ value: '1.0.1;ls', range: { type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '1.0.1;ls' }] } }] }
  assert.equal(fixGuide(evilVer).kind, 'unverified')
})

test('unknown relationship does not get a command', () => {
  assert.equal(fixGuide({ ...formData, relationship: 'unknown' }).kind, 'unverified')
})

test('route hash round trip', () => {
  const s = 'fe1627df-7c25-4beb-9e75-a5ec405c8b2a'
  const f = '1db9cd9f-87e8-4648-9125-78852ec5f0df'
  assert.deepEqual(parseRoute(routeHash(s, f)), { scanId: s, findingId: f })
  assert.deepEqual(parseRoute(routeHash(s)), { scanId: s, findingId: null })
  assert.deepEqual(parseRoute('#/scan/not-a-uuid'), { scanId: null, findingId: null })
  assert.equal(routeHash(''), '')
})

test('finding label prefers canonical id, then identifiers', () => {
  assert.equal(findingLabel({ canonical_id: 'C', identifiers: ['A'] }), 'C')
  assert.equal(findingLabel({ identifiers: ['CVE-1', 'GHSA-2'] }), 'CVE-1, GHSA-2')
  assert.equal(findingLabel({ identifiers: [], finding_key: 'k' }), 'k')
})
