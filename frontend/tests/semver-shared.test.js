import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import { compareSemver, rangeFixFor, affectedBy } from '../src/semver.js'
const cases = JSON.parse(fs.readFileSync(new URL('../../tests/fixtures/semver-cases.json', import.meta.url)))
for (const [a, b, expected] of cases.compare) test(`compare ${a} / ${b}`, () => {
  assert.equal(compareSemver(a, b), expected)
  if (expected !== null) assert.equal(compareSemver(b, a), expected === 0 ? 0 : -expected)
})
for (const c of cases.ranges) test(c.name, () => {
  assert.equal(rangeFixFor(c.installed, c.candidates), c.fix)
  assert.equal(affectedBy(c.installed, c.candidates), c.affected)
})
