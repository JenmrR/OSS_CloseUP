import test from 'node:test'
import assert from 'node:assert/strict'
import { parseRoute, routeHash } from '../src/display.js'
const scan = '326ca7d4-0177-434b-ac3b-9649a7bd5df0'
for (const section of ['findings','licenses','maintenance','packages']) {
  test(`${section} route survives reload`, () => {
    assert.deepEqual(parseRoute(routeHash(scan, null, section)), { scanId: scan, findingId: null, section })
  })
}
test('unknown section does not produce a list route', () => {
  assert.equal(parseRoute(`#/scan/${scan}/other`).scanId, null)
})
