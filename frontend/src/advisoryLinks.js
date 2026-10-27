// 취약점 식별자 → 공개 권고 페이지 링크. 형식이 확실한 ID만 링크로 만든다(그 밖의 값은 링크하지 않음).
const GHSA = /^GHSA(-[23456789cfghjmpqrvwx]{4}){3}$/
const CVE = /^CVE-\d{4}-\d{4,}$/

export function advisoryLink(id) {
  if (typeof id !== 'string') return null
  if (GHSA.test(id)) return { id, label: 'GitHub Advisory', url: `https://github.com/advisories/${id}` }
  if (CVE.test(id)) return { id, label: 'NVD', url: `https://nvd.nist.gov/vuln/detail/${id}` }
  return null
}

const idsOf = (finding) => (finding?.identifiers || []).map((x) => (typeof x === 'string' ? x : x?.value || x?.id)).filter(Boolean)

// 여러 취약점의 출처를 중복 없이 모은다. GHSA를 먼저, 같은 취약점의 CVE를 이어서 둔다.
export function sourceList(findings) {
  const seen = new Set()
  const out = []
  for (const f of findings || []) {
    const ids = idsOf(f).sort((a, b) => Number(b.startsWith('GHSA')) - Number(a.startsWith('GHSA')))
    for (const id of ids) {
      const link = advisoryLink(id)
      if (link && !seen.has(id)) { seen.add(id); out.push(link) }
    }
  }
  return out
}

export { idsOf }
