import test from 'node:test'
import assert from 'node:assert/strict'
import { firstLook, representativePackage, priorityStateText, topFindingRank } from '../src/display.js'

test('only the global first five have ranks, including ties within the same grade', () => {
  const items = Array.from({ length: 7 }, (_, i) => ({ finding_id: String(i), priority_rank: i,
    packages: [{ priority: 'P1' }] })).reverse()
  for (let i = 0; i < 5; i++) assert.equal(topFindingRank(items, String(i)), i + 1)
  assert.equal(topFindingRank(items, '5'), null)
  assert.equal(topFindingRank(items, '6'), null)
  assert.equal(topFindingRank(items, 'missing'), null)
})

test('representative package matches priority and candidate instead of first package', () => {
  const f = { finding_id: 'f', packages: [
    { package_id: 'other', name: 'other', priority: 'P2', fixed_version_candidates: ['9.0.0'] },
    { package_id: 'correct', name: 'correct', priority: 'P0', fixed_version_candidates: [], priority_rank: 0 },
  ] }
  assert.equal(representativePackage(f).package_id, 'correct')
  assert.deepEqual(representativePackage(f).fixed_version_candidates, [])
})

test('first look follows stored rank inside a grade', () => {
  const f = (id, rank) => ({ finding_id: id, priority_rank: rank, packages: [{ priority: 'P0' }] })
  assert.deepEqual(firstLook([f('a', 10), f('z', 1)]).map(x => x.finding_id), ['z', 'a'])
})

test('failed and uncomputed messages are distinct', () => {
  assert.match(priorityStateText({ status: 'invalid_input' }), /사용할 수 없습니다/)
  assert.match(priorityStateText({ status: 'not_computed' }), /산정 전/)
  assert.match(priorityStateText({ status: 'completed', current_result_available: true }), /완료/)
})
