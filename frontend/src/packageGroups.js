import { SEVERITIES, findingLabel } from './display.js'

const grades = { P0: 0, P1: 1, P2: 2, P3: 3 }

// Presentation grouping only. Never merge advisory aliases or infer priority from severity.
export function packageGroups(findings) {
  const groups = new Map()
  const unlinked = []
  for (const finding of findings || []) {
    const links = (finding.packages || []).filter(p => p.name && p.installed_version)
    if (!links.length) unlinked.push(finding)
    for (const pkg of links) {
      const key = JSON.stringify([pkg.name, pkg.installed_version])
      if (!groups.has(key)) groups.set(key, { key, name: pkg.name, version: pkg.installed_version, entries: [], priority: null, rank: Infinity })
      const group = groups.get(key)
      const id = finding.finding_id || finding.finding_key || finding
      let entry = group.entries.find(e => e.id === id)
      if (!entry) {
        entry = { id, finding, packages: [] }
        group.entries.push(entry)
      }
      entry.packages.push(pkg)
      if (pkg.priority in grades) {
        if (group.priority === null || grades[pkg.priority] < grades[group.priority]) {
          group.priority = pkg.priority
          group.rank = pkg.priority_rank ?? Infinity
        } else if (pkg.priority === group.priority) {
          group.rank = Math.min(group.rank, pkg.priority_rank ?? Infinity)
        }
      }
    }
  }
  for (const group of groups.values()) {
    group.counts = Object.fromEntries(SEVERITIES.map(s => [s, 0]))
    for (const { finding } of group.entries) {
      group.counts[SEVERITIES.includes(finding.severity) ? finding.severity : 'UNKNOWN']++
    }
  }
  return { groups: [...groups.values()], unlinked }
}

export function selectPackageGroups(groups, query = '', priority = 'all', order = 'priority') {
  const q = query.trim().toLowerCase()
  const rows = groups.filter(g => (priority === 'all' || (g.priority || 'unranked') === priority)
    && (!q || [g.name, g.version, ...g.entries.map(e => findingLabel(e.finding))].some(v => String(v).toLowerCase().includes(q))))
  // Preserve published link rank until the package-sort API is supplied.
  return order === 'original' ? rows : [...rows].sort((a, b) =>
    (grades[a.priority] ?? 4) - (grades[b.priority] ?? 4) || a.rank - b.rank
    || a.name.localeCompare(b.name) || a.version.localeCompare(b.version))
}
