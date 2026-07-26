import type { DomainSlug, Severity, ThreatEntry } from '@/types/threat'

export function searchThreats(threats: ThreatEntry[], query: string): ThreatEntry[] {
  const q = query.trim().toLowerCase()
  if (!q) return threats

  return threats.filter((t) => {
    const haystack = [
      t.title,
      t.shortDesc,
      t.category,
      t.id,
      ...(t.mitre?.map((m) => `${m.id} ${m.name}`) ?? []),
      ...(t.atrm?.map((m) => `${m.id} ${m.name}`) ?? []),
    ]
      .join(' ')
      .toLowerCase()

    return haystack.includes(q)
  })
}

export function filterBySeverity(threats: ThreatEntry[], severities: Set<Severity>): ThreatEntry[] {
  if (severities.size === 0) return threats
  return threats.filter((t) => severities.has(t.severity))
}

export function filterByDomain(threats: ThreatEntry[], domain: DomainSlug | undefined): ThreatEntry[] {
  if (!domain) return threats
  return threats.filter((t) => t.domain === domain)
}

/** Parse a comma-separated severity query param into a validated Set. */
export function parseSeverityParam(value: string | null, valid: readonly Severity[]): Set<Severity> {
  if (!value) return new Set()
  const set = new Set<Severity>()
  for (const raw of value.split(',')) {
    const candidate = raw.trim() as Severity
    if ((valid as readonly string[]).includes(candidate)) {
      set.add(candidate)
    }
  }
  return set
}
