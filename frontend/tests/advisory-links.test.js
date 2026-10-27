import test from 'node:test'
import assert from 'node:assert/strict'
import { advisoryLink, sourceList } from '../src/advisoryLinks.js'

test('only well-formed GHSA/CVE ids become links', () => {
  assert.equal(advisoryLink('GHSA-fjxv-7rqg-78g4').url, 'https://github.com/advisories/GHSA-fjxv-7rqg-78g4')
  assert.equal(advisoryLink('CVE-2025-7783').url, 'https://nvd.nist.gov/vuln/detail/CVE-2025-7783')
  for (const bad of ['NSWG-ECO-516', 'GHSA-xxxx-xxxx-xxxx/../evil', 'CVE-2025-1"onmouseover', 'javascript:alert(1)', null]) {
    assert.equal(advisoryLink(bad), null)
  }
})

test('sources are de-duplicated with GHSA first per finding', () => {
  const list = sourceList([
    { identifiers: ['CVE-2025-7783', 'GHSA-fjxv-7rqg-78g4'] },
    { identifiers: [{ value: 'GHSA-fjxv-7rqg-78g4' }, 'NSWG-ECO-516'] },
  ])
  assert.deepEqual(list.map((x) => x.id), ['GHSA-fjxv-7rqg-78g4', 'CVE-2025-7783'])
})
