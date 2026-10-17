import test from 'node:test'
import assert from 'node:assert/strict'
import { generateAiReport } from '../src/api.js'
import { aiReportView, aiSections } from '../src/display.js'

test('manual generation uses POST and does not send a client API key', async () => {
  const original = globalThis.fetch
  let received
  globalThis.fetch = async (...args) => {
    received = args
    return { ok: true, text: async () => JSON.stringify({ status: 'succeeded', output: { summary: 'ok' } }) }
  }
  try {
    assert.equal((await generateAiReport('scan-1')).status, 'succeeded')
    assert.deepEqual(received, ['/api/scans/scan-1/ai/report', { method: 'POST' }])
  } finally { globalThis.fetch = original }
})

test('backend configuration errors are understandable', async () => {
  const original = globalThis.fetch
  globalThis.fetch = async () => ({ ok: false, status: 503, text: async () => JSON.stringify({ detail: '모델을 설정하세요.' }) })
  try { await assert.rejects(generateAiReport('scan-1'), /모델을 설정하세요/) }
  finally { globalThis.fetch = original }
})

test('stale and rejected reports never expose old explanation text', () => {
  for (const status of ['stale', 'rejected', 'failed']) {
    assert.equal(aiReportView({ data: { status, output: { summary: 'old' } } }).output, undefined)
  }
  const parsed = aiSections({ uncertainty: '일부 검사 실패' })
  assert.equal(parsed.sections[0].label, '확인할 한계')
  assert.equal(parsed.extra, null)
})
