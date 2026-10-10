import { test, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import { getPackages, getFindings, getMaintenance, downloadSbom } from '../src/api.js'
const originalFetch = globalThis.fetch
afterEach(() => { globalThis.fetch = originalFetch })
for (const [name, get] of [['packages', getPackages], ['findings', getFindings], ['maintenance', getMaintenance]]) {
  for (const total of [0, 500, 501, 1001]) {
    test(`${name}: retrieves all ${total} records`, async () => {
      const calls = []
      globalThis.fetch = async (url) => {
        calls.push(url)
        const offset = Number(new URL(url, 'http://localhost').searchParams.get('offset'))
        return Response.json({ total, items: Array.from({ length: Math.min(500, total - offset) }, (_, i) => ({ id: offset + i })) })
      }
      const result = await get('scan')
      assert.equal(result.items.length, total)
      assert.equal(new Set(result.items.map(x => x.id)).size, total)
      if (total > 500) assert.equal(result.items[500].id, 500)
      assert.equal(calls.length, Math.max(1, Math.ceil(total / 500)))
    })
  }
}
test('a failed second page is not returned as a complete list', async () => {
  let count = 0
  globalThis.fetch = async () => ++count === 1
    ? Response.json({total:501,items:Array.from({length:500},(_,id)=>({id}))})
    : Response.json({detail:'DB 조회 실패'}, {status:503})
  await assert.rejects(getPackages('scan'), /DB 조회 실패/)
})
test('empty page before total is reached reports an error', async () => {
  globalThis.fetch = async () => Response.json({total:501,items:[]})
  await assert.rejects(getFindings('scan'), /전체 목록/)
})
test('failed SBOM response is not saved as a file', async () => {
  globalThis.fetch = async () => Response.json({detail:{message:'최신 성공 SBOM 없음'}}, {status:404})
  await assert.rejects(downloadSbom('scan'), /최신 성공 SBOM 없음/)
})
test('successful SBOM preserves content', async () => {
  globalThis.fetch = async () => new Response('{"spdxVersion":"SPDX-2.3"}')
  assert.equal(await (await downloadSbom('scan')).text(), '{"spdxVersion":"SPDX-2.3"}')
})
