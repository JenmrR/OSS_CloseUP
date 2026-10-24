import test from 'node:test'
import assert from 'node:assert/strict'
import { packageGroups, selectPackageGroups } from '../src/packageGroups.js'

const link = (name, version = '1', priority = 'P1', rank = 0) =>
  ({ name, installed_version: version, priority, priority_rank: rank })
const finding = (id, packages, severity = 'HIGH') => ({ finding_id: id, canonical_id: id, severity, packages })

test('groups by name and version, counts a finding once per group across install paths', () => {
  const input = [finding('CVE-a', [link('a'), link('a'), link('b')]), finding('CVE-b', [link('a')]), finding('CVE-c', [link('a', '2')])]
  const before = JSON.stringify(input)
  const { groups } = packageGroups(input)
  assert.equal(groups.length, 3)
  assert.deepEqual(groups.map(g => g.entries.length), [2, 1, 1])
  assert.equal(groups[0].counts.HIGH, 2)
  assert.equal(JSON.stringify(input), before)
})
test('retains missing links and UNKNOWN; never infers grade from severity', () => {
  const result = packageGroups([finding('a', []), finding('b', [link('x', '1', null)], 'CRITICAL'), finding('c', [link('x', '1', null)], null)])
  assert.equal(result.unlinked.length, 1)
  assert.equal(result.groups[0].priority, null)
  assert.equal(result.groups[0].counts.UNKNOWN, 1)
})
test('representative grade uses only this package links and preserves stored order', () => {
  const { groups } = packageGroups([
    finding('a', [link('x', '1', 'P2', 8), link('y', '1', 'P0', 0)]),
    finding('b', [link('x', '1', 'P1', 5)]),
    finding('c', [link('z', '1', 'P1', 2)]),
  ])
  assert.deepEqual(selectPackageGroups(groups).map(g => g.name), ['y', 'z', 'x'])
  assert.deepEqual(selectPackageGroups(groups, '', 'P1').map(g => g.name), ['z', 'x'])
})
test('identifier search retains full package counts and all related findings', () => {
  const { groups } = packageGroups([finding('CVE-a', [link('x')]), finding('CVE-b', [link('x')])])
  const rows = selectPackageGroups(groups, 'cve-a')
  assert.equal(rows.length, 1)
  assert.equal(rows[0].entries.length, 2)
  assert.equal(selectPackageGroups(groups, 'missing').length, 0)
})
