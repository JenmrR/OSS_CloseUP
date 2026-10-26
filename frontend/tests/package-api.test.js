import { test, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import { getPackageResults, getPackageDetail } from '../src/api.js'
import { parseRoute, routeHash } from '../src/display.js'
const original = globalThis.fetch
afterEach(() => { globalThis.fetch = original })
const meta = { snapshot_id: 's1', result_state: 'ready', unlinked_finding_count: 1 }
test('all pages and unlinked rows use one snapshot; ranks remain unchanged', async () => {
  const calls = []
  globalThis.fetch = async path => {
    const u = new URL(path, 'http://localhost'); calls.push(u)
    if (u.pathname.endsWith('unlinked-vulnerabilities')) return Response.json({ ...meta, total: 1, items: [{ finding_id: 'u1' }] })
    const offset = Number(u.searchParams.get('offset'))
    return Response.json({ ...meta, total: 501, items: Array.from({ length: offset ? 1 : 500 }, (_, i) => ({ package_group_id: `g${offset+i}`, global_rank: offset+i+1 })) })
  }
  const data = await getPackageResults('scan')
  assert.equal(data.items.length, 501); assert.equal(data.items[500].global_rank, 501); assert.equal(data.unlinked.length, 1)
  assert.equal(calls[0].searchParams.has('snapshot_id'), false)
  assert.ok(calls.slice(1).every(u => u.searchParams.get('snapshot_id') === 's1'))
})
test('409 or failed later requests never return a partial successful catalog', async () => {
  let n = 0
  globalThis.fetch = async () => ++n === 1 ? Response.json({ ...meta, total: 1, items: [{ package_group_id: 'g' }] }) : Response.json({ detail: { code: 'snapshot_changed' } }, { status: 409 })
  await assert.rejects(getPackageResults('scan'), e => e.status === 409)
})
test('processing is preserved rather than converted to normal zero findings', async () => {
  globalThis.fetch = async () => Response.json({ ...meta, result_state: 'processing', total: null, items: [], zero_findings_confirmed: false })
  const data = await getPackageResults('scan')
  assert.equal(data.total, null); assert.equal(data.zero_findings_confirmed, false)
})
test('changed snapshot and duplicate pagination are rejected', async () => {
  let n = 0
  globalThis.fetch = async () => Response.json({ ...meta, snapshot_id: ++n === 1 ? 's1' : 's2', total: 2, items: [{ package_group_id: 'g' }] })
  await assert.rejects(getPackageResults('scan'), /변경/)
  globalThis.fetch = async () => Response.json({ ...meta, total: 2, items: [{ package_group_id: 'g' }] })
  await assert.rejects(getPackageResults('scan'), /중복/)
})
test('group detail requests pass the snapshot and stable group routes survive reload', async () => {
  let path
  globalThis.fetch = async p => { path = p; return Response.json({ item: {} }) }
  await getPackageDetail('scan', 'group', 's1')
  assert.match(path, /vulnerable-packages\/group\?snapshot_id=s1/)
  const scan = '11111111-1111-1111-1111-111111111111', pkg = { groupId: 'pkg_group_' + 'a'.repeat(64) }
  assert.deepEqual(parseRoute(routeHash(scan, null, 'first', pkg)), { scanId: scan, findingId: null, pkg })
})
