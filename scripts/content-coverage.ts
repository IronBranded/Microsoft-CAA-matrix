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
  noErrorCodesDocumented: string[]
  noErrorCodesUnreviewed: string[]
  noAuthFlowDocumented: string[]
  noAuthFlowUnreviewed: string[]
  noTokenTimelineDocumented: string[]
  noTokenTimelineUnreviewed: string[]
}

function emptyStats(): DomainStats {
  return {
    total: 0,
    stub: [],
    dualKql: [],
    sentinelOnly: [],
    defenderOnly: [],
    noKql: [],
    noErrorCodesDocumented: [],
    noErrorCodesUnreviewed: [],
    noAuthFlowDocumented: [],
    noAuthFlowUnreviewed: [],
    noTokenTimelineDocumented: [],
    noTokenTimelineUnreviewed: [],
  }
}

function mergeInto(totals: DomainStats, stats: DomainStats) {
  totals.total += stats.total
  totals.stub.push(...stats.stub)
  totals.dualKql.push(...stats.dualKql)
  totals.sentinelOnly.push(...stats.sentinelOnly)
  totals.defenderOnly.push(...stats.defenderOnly)
  totals.noKql.push(...stats.noKql)
  totals.noErrorCodesDocumented.push(...stats.noErrorCodesDocumented)
  totals.noErrorCodesUnreviewed.push(...stats.noErrorCodesUnreviewed)
  totals.noAuthFlowDocumented.push(...stats.noAuthFlowDocumented)
  totals.noAuthFlowUnreviewed.push(...stats.noAuthFlowUnreviewed)
  totals.noTokenTimelineDocumented.push(...stats.noTokenTimelineDocumented)
  totals.noTokenTimelineUnreviewed.push(...stats.noTokenTimelineUnreviewed)
}

/**
 * An entry with zero relevantErrorCodes is either genuinely unreviewed, or
 * it's been looked at and there's deliberately nothing to put there (e.g.
 * AiTM: a well-executed proxy produces a normal successful sign-in with no
 * distinguishing code). The convention for the latter, used consistently
 * wherever it applies, is a correlationMarkers entry starting with this
 * phrase — detected here so the report doesn't keep flagging reviewed,
 * intentionally-empty entries as if they were still open work.
 *
 * The same convention extends to authFlow and tokenTimeline (added for the
 * per-scenario auth-code-flow / token-lifecycle sweep): plenty of entries
 * — a transport rule backdoor, a UAL disablement — have no sign-in or
 * token dimension at all, and that's a reviewed conclusion, not a gap.
 */
const DELIBERATE_ABSENCE_MARKER = 'deliberately no relevantErrorCodes'
const NO_AUTH_FLOW_MARKER = 'deliberately no authFlow'
const NO_TOKEN_TIMELINE_MARKER = 'deliberately no tokenTimeline'

function hasDocumentedAbsence(correlationMarkers: string[] | undefined, marker: string): boolean {
  return (correlationMarkers ?? []).some((m) => m.includes(marker))
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
      if (hasDocumentedAbsence(t.telemetry?.correlationMarkers, DELIBERATE_ABSENCE_MARKER)) {
        stats.noErrorCodesDocumented.push(t.id)
      } else {
        stats.noErrorCodesUnreviewed.push(t.id)
      }
    }

    if (!t.authFlow) {
      if (hasDocumentedAbsence(t.telemetry?.correlationMarkers, NO_AUTH_FLOW_MARKER)) {
        stats.noAuthFlowDocumented.push(t.id)
      } else {
        stats.noAuthFlowUnreviewed.push(t.id)
      }
    }

    if (!t.tokenTimeline) {
      if (hasDocumentedAbsence(t.telemetry?.correlationMarkers, NO_TOKEN_TIMELINE_MARKER)) {
        stats.noTokenTimelineDocumented.push(t.id)
      } else {
        stats.noTokenTimelineUnreviewed.push(t.id)
      }
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
  const totalNoCodes = totals.noErrorCodesDocumented.length + totals.noErrorCodesUnreviewed.length
  console.log(
    `Entries with zero relevantErrorCodes: ${totalNoCodes}/${totals.total} — ${totals.noErrorCodesDocumented.length} of those are reviewed with a documented reason (e.g. a well-executed AiTM sign-in has no distinguishing code by design), ${totals.noErrorCodesUnreviewed.length} are genuinely unreviewed. Only the unreviewed count is open work.`,
  )
  console.log(
    `Entries with no authFlow: ${totals.noAuthFlowDocumented.length + totals.noAuthFlowUnreviewed.length}/${totals.total} — ${totals.noAuthFlowDocumented.length} documented absence, ${totals.noAuthFlowUnreviewed.length} unreviewed.`,
  )
  console.log(
    `Entries with no tokenTimeline: ${totals.noTokenTimelineDocumented.length + totals.noTokenTimelineUnreviewed.length}/${totals.total} — ${totals.noTokenTimelineDocumented.length} documented absence, ${totals.noTokenTimelineUnreviewed.length} unreviewed.`,
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
    if (stats.noErrorCodesUnreviewed.length > 0) {
      console.log(`  relevantErrorCodes NOT reviewed yet: ${stats.noErrorCodesUnreviewed.join(', ')}`)
    }
    if (stats.noErrorCodesDocumented.length > 0) {
      console.log(`  relevantErrorCodes deliberately absent (documented): ${stats.noErrorCodesDocumented.join(', ')}`)
    }
    if (stats.noAuthFlowUnreviewed.length > 0) {
      console.log(`  authFlow NOT reviewed yet: ${stats.noAuthFlowUnreviewed.join(', ')}`)
    }
    if (stats.noAuthFlowDocumented.length > 0) {
      console.log(`  authFlow deliberately absent (documented): ${stats.noAuthFlowDocumented.join(', ')}`)
    }
    if (stats.noTokenTimelineUnreviewed.length > 0) {
      console.log(`  tokenTimeline NOT reviewed yet: ${stats.noTokenTimelineUnreviewed.join(', ')}`)
    }
    if (stats.noTokenTimelineDocumented.length > 0) {
      console.log(`  tokenTimeline deliberately absent (documented): ${stats.noTokenTimelineDocumented.join(', ')}`)
    }
  }
}

main().catch((err) => {
  console.error('coverage script crashed:', err)
  process.exit(1)
})
