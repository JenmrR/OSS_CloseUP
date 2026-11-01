// Keep aligned with backend/app/fix_versions.py and tests/fixtures/semver-cases.json.
const SEMVER = /^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/
const numeric = s => /^[0-9]+$/.test(s)
const compareNumeric = (a, b) => a.length === b.length ? (a === b ? 0 : a < b ? -1 : 1) : a.length < b.length ? -1 : 1

export function parseSemver(value) {
  if (typeof value !== 'string') return null
  const m = SEMVER.exec(value.trim())
  if (!m || (m[4] && m[4].split('.').some(x => numeric(x) && x.length > 1 && x[0] === '0'))) return null
  return { nums: m.slice(1, 4).map(Number), core: m.slice(1, 4), pre: m[4] || null }
}

export function compareSemver(a, b) {
  const x = parseSemver(a), y = parseSemver(b)
  if (!x || !y) return null
  for (let i = 0; i < 3; i++) {
    const c = compareNumeric(x.core[i], y.core[i])
    if (c) return c
  }
  if (x.pre === y.pre) return 0
  if (!x.pre) return 1
  if (!y.pre) return -1
  const xs = x.pre.split('.'), ys = y.pre.split('.')
  for (let i = 0; i < Math.min(xs.length, ys.length); i++) {
    const a = xs[i], b = ys[i]
    if (a === b) continue
    if (numeric(a) && numeric(b)) return compareNumeric(a, b)
    if (numeric(a) !== numeric(b)) return numeric(a) ? -1 : 1
    return a < b ? -1 : 1
  }
  return xs.length < ys.length ? -1 : 1
}

function intervals(candidates) {
  const result = []
  for (const c of candidates || []) {
    const r = c && c.range
    if (r === undefined || r === null) continue
    if (typeof r !== 'object' || (r.type !== undefined && r.type !== 'SEMVER') || !Array.isArray(r.events) || !r.events.length) return null
    let start = null, previous = null, previousInclusive = false
    for (const e of r.events) {
      if (!e || typeof e !== 'object' || Array.isArray(e) || Object.keys(e).length !== 1) return null
      const [kind, value] = Object.entries(e)[0]
      if (!['introduced', 'fixed', 'last_affected', 'limit'].includes(kind) || typeof value !== 'string') return null
      if (!(kind === 'introduced' && value === '0') && !parseSemver(value)) return null
      if (kind === 'introduced') {
        if (start !== null || (previous !== null && (value === '0' || compareSemver(value, previous) < 0 || (previousInclusive && compareSemver(value, previous) === 0)))) return null
        start = value
      } else {
        if (start === null || (start !== '0' && (compareSemver(start, value) > 0 || (kind !== 'last_affected' && compareSemver(start, value) === 0)))) return null
        result.push([start, value, kind])
        start = null
        previous = value
        previousInclusive = kind === 'last_affected'
      }
    }
    if (start !== null) result.push([start, null, null])
  }
  return result
}
const contains = (version, start, end, kind) => (start === '0' || compareSemver(version, start) >= 0)
  && (end === null || (kind === 'last_affected' ? compareSemver(version, end) <= 0 : compareSemver(version, end) < 0))

export function affectedBy(version, candidates) {
  if (!parseSemver(version)) return null
  const ranges = intervals(candidates)
  if (!ranges || !ranges.length) return null
  if (ranges.some(i => contains(version, ...i))) return true
  if (ranges.some(([, end, kind]) => kind === 'limit' && compareSemver(version, end) >= 0)) return null
  return false
}

export function rangeFixFor(installed, candidates) {
  if (!parseSemver(installed)) return null
  const ranges = intervals(candidates)
  if (!ranges || !ranges.length) return null
  const matches = ranges.filter(([start, end, kind]) => kind === 'fixed' && contains(installed, start, end, kind)).map(([, end]) => end)
  if (!matches.length) return null
  const best = matches.sort(compareSemver).at(-1)
  return affectedBy(best, candidates) === false ? best : null
}
