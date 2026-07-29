import { ThreatEntrySchema, type ThreatEntry, type DomainSlug } from '@/types/threat'

/**
 * Every file under ./entries/<domain>/*.ts is picked up automatically.
 * Adding a new threat is just adding a new file — nothing to register by
 * hand. Each file's default export is validated against ThreatEntrySchema
 * at load time so a malformed entry fails loudly instead of silently
 * vanishing from the catalog.
 *
 * Loading is intentionally lazy (no `eager: true`): with 58+ entries' worth
 * of KQL and runbook text, eagerly bundling every entry into the initial
 * chunk regardless of which view is showing became the dominant contributor
 * to bundle size. Vite code-splits each dynamic import into its own chunk,
 * so the app shell loads fast and entry data streams in afterward. Results
 * are cached after the first resolution — see getThreats().
 *
 * This file is Vite-only (import.meta.glob doesn't exist outside Vite).
 * scripts/validate-content.ts re-implements discovery with plain fs for
 * use in CI, outside the Vite pipeline, and is unaffected by this file's
 * loading strategy.
 */
const moduleLoaders = import.meta.glob('./entries/**/*.ts') as Record<
  string,
  () => Promise<{ default: unknown }>
>

let cachedThreats: ThreatEntry[] | null = null
let loadingPromise: Promise<ThreatEntry[]> | null = null

async function loadAllThreats(): Promise<ThreatEntry[]> {
  const parsed: ThreatEntry[] = []
  const errors: string[] = []
  const seenIds = new Map<string, string>()

  const resolved = await Promise.all(
    Object.entries(moduleLoaders).map(async ([path, loader]) => {
      const mod = await loader()
      return [path, mod] as const
    }),
  )

  for (const [path, mod] of resolved) {
    const result = ThreatEntrySchema.safeParse(mod.default)

    if (!result.success) {
      const issues = result.error.issues
        .map((issue) => `${issue.path.join('.') || '(root)'} — ${issue.message}`)
        .join('; ')
      errors.push(`${path}: ${issues}`)
      continue
    }

    const existing = seenIds.get(result.data.id)
    if (existing) {
      errors.push(`${path}: duplicate id "${result.data.id}" (already used by ${existing})`)
      continue
    }

    seenIds.set(result.data.id, path)
    parsed.push(result.data)
  }

  if (errors.length > 0) {
    console.error(
      `[threats] ${errors.length} threat file(s) failed validation and were excluded from the catalog:\n${errors.join('\n')}`,
    )
  }

  return parsed.sort((a, b) => a.title.localeCompare(b.title))
}

/** Resolves once, then serves cached results — safe to call from multiple components. */
export function getThreats(): Promise<ThreatEntry[]> {
  if (cachedThreats) return Promise.resolve(cachedThreats)
  if (!loadingPromise) {
    loadingPromise = loadAllThreats().then((result) => {
      cachedThreats = result
      return result
    })
  }
  return loadingPromise
}

export function getThreatById(threats: ThreatEntry[], id: string): ThreatEntry | undefined {
  return threats.find((t) => t.id === id)
}

export function getThreatsByDomain(threats: ThreatEntry[], domain: DomainSlug): ThreatEntry[] {
  return threats.filter((t) => t.domain === domain)
}

export function countByDomain(threats: ThreatEntry[]): Record<DomainSlug, number> {
  const counts = {} as Record<DomainSlug, number>
  for (const t of threats) {
    counts[t.domain] = (counts[t.domain] ?? 0) + 1
  }
  return counts
}
