import { test } from 'node:test'
import assert from 'node:assert/strict'
import { computeProgress, uniqueFixVersions, licenseState, vulnScanFailed, stageProgress, aiReportView } from '../src/display.js'

const all = (status) => Object.fromEntries(
  ['trivy', 'osv', 'syft', 'package_storage', 'normalization', 'github'].map((k) => [k, { status }]))

test('progress: queued with nothing done is 0%', () => {
  assert.equal(computeProgress({ status: 'queued', tool_status: {} }).percent, 0)
})

test('progress: half of the stages done is 50%', () => {
  const ts = { trivy: { status: 'completed' }, osv: { status: 'completed' }, syft: { status: 'completed' } }
  assert.equal(computeProgress({ status: 'running', tool_status: ts }).percent, 50)
})

test('progress: running stage contributes its own detail', () => {
  const ts = { ...all('completed'), github: { status: 'running', completed: 38, total: 76 } }
  const p = computeProgress({ status: 'running', tool_status: ts })
  assert.equal(p.percent, Math.round((5.5 / 6) * 100))
  assert.equal(p.current.name, '유지보수 정보 조회')
  assert.deepEqual([p.current.detail.done, p.current.detail.total], [38, 76])
})

test('progress: never shows 100% while still active', () => {
  assert.equal(computeProgress({ status: 'running', tool_status: all('completed') }).percent, 99)
})

test('progress: completed is 100% with no failures', () => {
  const p = computeProgress({ status: 'completed', tool_status: all('completed') })
  assert.equal(p.percent, 100)
  assert.deepEqual(p.failed, [])
})

test('progress: partial lists failed stages by role name, not tool name', () => {
  const ts = { ...all('completed'), osv: { status: 'failed' } }
  const p = computeProgress({ status: 'partial', tool_status: ts })
  assert.equal(p.percent, 100)
  assert.deepEqual(p.failed, ['취약점 검사 (2차)'])
  assert.ok(!p.failed.join().includes('OSV'))
})

test('progress: worker failure before tools is reported (today\'s permission case)', () => {
  const p = computeProgress({ status: 'failed', tool_status: { worker: { status: 'failed', reason: 'PermissionError' } } })
  assert.equal(p.percent, 0)
  assert.equal(p.workerReason, 'PermissionError')
})

test('stageProgress: github stage counts use packages as total', () => {
  assert.deepEqual(stageProgress({ processed: 34, packages: 76 }), { done: 34, total: 76, percent: 45 })
  assert.equal(stageProgress({ status: 'running' }), null)
})

test('fix candidates: duplicates from two tools collapse to unique values', () => {
  const c = ['2.5.4', '3.0.4', '4.0.4', '2.5.4', '3.0.4', '4.0.4'].map((value) => ({ value }))
  assert.deepEqual(uniqueFixVersions(c), ['2.5.4', '3.0.4', '4.0.4'])
  assert.deepEqual(uniqueFixVersions([]), [])
  assert.deepEqual(uniqueFixVersions(null), [])
})

test('license: GPL family is review, MIT ok, empty unknown', () => {
  assert.equal(licenseState(['GPL-3.0-or-later']), 'review')
  assert.equal(licenseState(['LGPL-2.1-only']), 'review')
  assert.equal(licenseState(['AGPL-3.0']), 'review')
  assert.equal(licenseState(['MIT']), 'ok')
  assert.equal(licenseState(['Apache-2.0', 'MIT']), 'ok')
  assert.equal(licenseState([]), 'unknown')
  assert.equal(licenseState(null), 'unknown')
})

test('vuln scan failure detection for the 0-finding message', () => {
  assert.equal(vulnScanFailed({ tool_status: all('completed') }), false)
  assert.equal(vulnScanFailed({ tool_status: { ...all('completed'), trivy: { status: 'timeout' } } }), true)
  assert.equal(vulnScanFailed(null), false)
})


test('ai report: not generated is a neutral message, not an error', () => {
  const v = aiReportView({ data: { status: 'not_generated' } })
  assert.equal(v.tone, 'muted')
  assert.equal(v.output, undefined)
})

test('ai report: only succeeded exposes output', () => {
  assert.deepEqual(aiReportView({ data: { status: 'succeeded', output: { summary: 's' }, prompt_version: 'v0.1' } }).output, { summary: 's' })
  assert.equal(aiReportView({ data: { status: 'rejected', output: { summary: 'leak' }, message: 'm' } }).output, undefined)
})

test('ai report: fetch error does not claim results are missing', () => {
  const v = aiReportView({ error: new Error('x') })
  assert.equal(v.tone, 'error')
  assert.match(v.message, /검사 결과는 아래에서 그대로/)
})
