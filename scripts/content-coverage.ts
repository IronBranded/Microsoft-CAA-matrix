/**
 * Content coverage report — NOT a validity gate like validate-content.ts.
 * A schema-valid entry can still be incomplete (single-platform KQL, no
 * error codes catalogued yet). This surfaces exactly which ones and where,
 * so the AADSTS/diagnostic sweep and dual-KQL passes have a re-runnable
 * source of truth instead of a hand count each session.
 *
 * Informational only — not wired into predeploy. A low coverage number is
 * expected mid-sweep, not a broken build.
 *
 * Run with: npm run coverage
 */
import { readdirSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'
import { pathToFileURL } from 'node:url'
import { ThreatEntrySchema, DOMAIN_META, ORDERED_DOMAINS, type DomainSlug } from '../src/types/threat'

const ENTRIES_ROOT = join(import.meta.dirname, '..', 'src', 'data', 'threats', 'entries')

function findEntryFiles(dir: string): string[] {
  const files: string[] = []
  for (const name of readdirSync(dir)) {
    const fullPath = join(dir, name)
    if (statSync(fullPath).isDirectory()) files.push(...findEntryFiles(fullPath))
    else if (name.endsWith('.ts')) files.push(fullPath)
  }
  return files
}

interface DomainStats {
  total: number
  stub: string[]
  dualKql: string[]
  sentinelOnly: string[]
  defenderOnly: string[]
  noKql: string[]
  noErrorCodes: string[]
}

function emptyStats(): DomainStats {
  return { total: 0, stub: [], dualKql: [], sentinelOnly: [], defenderOnly: [], noKql: [], noErrorCodes: [] }
}

function mergeInto(totals: DomainStats, stats: DomainStats) {
  totals.total += stats.total
  totals.stub.push(...stats.stub)
  totals.dualKql.push(...stats.dualKql)
  totals.sentinelOnly.push(...stats.sentinelOnly)
  totals.defenderOnly.push(...stats.defenderOnly)
  totals.noKql.push(...stats.noKql)
  totals.noErrorCodes.push(...stats.noErrorCodes)
}

async function main() {
  const files = findEntryFiles(ENTRIES_ROOT).sort()
  const byDomain = new Map<DomainSlug, DomainStats>()
  for (const domain of ORDERED_DOMAINS) byDomain.set(domain, emptyStats())

  let schemaFailures = 0

  for (const filePath of files) {
    const mod = await import(pathToFileURL(filePath).href)
    const result = ThreatEntrySchema.safeParse(mod.default)
    if (!result.success) {
      schemaFailures++
      console.error(`SCHEMA FAIL: ${relative(process.cwd(), filePath)} — run "npm run validate:content" for details`)
      continue
    }

    const t = result.data
    const stats = byDomain.get(t.domain)!
    stats.total++

    if (t.status === 'stub') stats.stub.push(t.id)

    const hasSentinel = Boolean(t.kql?.sentinel && Object.keys(t.kql.sentinel).length > 0)
    const hasDefender = Boolean(t.kql?.defender && Object.keys(t.kql.defender).length > 0)
    if (hasSentinel && hasDefender) stats.dualKql.push(t.id)
    else if (hasSentinel) stats.sentinelOnly.push(t.id)
    else if (hasDefender) stats.defenderOnly.push(t.id)
    else stats.noKql.push(t.id)

    if (!t.telemetry?.relevantErrorCodes || t.telemetry.relevantErrorCodes.length === 0) {
      stats.noErrorCodes.push(t.id)
    }
  }

  if (schemaFailures > 0) {
    console.error(
      `\n${schemaFailures} file(s) failed schema validation and were excluded below — run "npm run validate:content" for details. This report is incomplete until they're fixed.\n`,
    )
  }

  const totals = emptyStats()
  for (const stats of byDomain.values()) mergeInto(totals, stats)

  console.log('CONTENT COVERAGE')
  console.log('================')
  console.log(`${totals.total} entries  |  ${totals.total - totals.stub.length} complete, ${totals.stub.length} stub`)
  console.log(
    `KQL — dual-platform: ${totals.dualKql.length}  |  Sentinel-only: ${totals.sentinelOnly.length}  |  Defender-only: ${totals.defenderOnly.length}  |  neither: ${totals.noKql.length}`,
  )
  console.log(
    `Entries with zero relevantErrorCodes: ${totals.noErrorCodes.length}/${totals.total} — this is a raw count, not a gap count: some entries (e.g. a well-executed AiTM sign-in) have no distinguishing code by design and document that inline. Read the entry before assuming it's unworked.`,
  )
  console.log('')
  console.log('--- Per domain ---')

  for (const domain of ORDERED_DOMAINS) {
    const stats = byDomain.get(domain)!
    const label = DOMAIN_META[domain].label
    console.log(`\n${label} (${stats.total})`)
    if (stats.stub.length > 0) console.log(`  stub: ${stats.stub.join(', ')}`)
    if (stats.sentinelOnly.length > 0) console.log(`  Sentinel-only: ${stats.sentinelOnly.join(', ')}`)
    if (stats.defenderOnly.length > 0) console.log(`  Defender-only: ${stats.defenderOnly.join(', ')}`)
    if (stats.noKql.length > 0) console.log(`  no KQL at all: ${stats.noKql.join(', ')}`)
    console.log(
      `  zero relevantErrorCodes: ${stats.noErrorCodes.length}/${stats.total}${
        stats.noErrorCodes.length > 0 ? ` — ${stats.noErrorCodes.join(', ')}` : ''
      }`,
    )
  }
}

main().catch((err) => {
  console.error('coverage script crashed:', err)
  process.exit(1)
})
