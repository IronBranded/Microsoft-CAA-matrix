/**
 * Interactive scaffolding for a new threat entry.
 * Run with: npm run new:threat
 */
import { existsSync, mkdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { createInterface } from 'node:readline/promises'
import { DOMAINS, DOMAIN_META, SEVERITIES, type DomainSlug, type Severity } from '../src/types/threat'

const ENTRIES_ROOT = join(import.meta.dirname, '..', 'src', 'data', 'threats', 'entries')

function slugify(input: string): string {
  return input
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
}

async function main() {
  if (!process.stdin.isTTY) {
    console.error(
      'new-threat.ts is an interactive wizard and needs a real terminal — ' +
        'run `npm run new:threat` directly rather than piping input into it.\n' +
        'To scaffold a file non-interactively instead, copy the shape of an existing\n' +
        'stub entry (see CONTRIBUTING.md) and fill it in by hand.',
    )
    process.exit(1)
  }

  const rl = createInterface({ input: process.stdin, output: process.stdout })
  const ask = (q: string) => rl.question(q)

  console.log('New threat scenario\n')

  const title = (await ask('Title: ')).trim()
  if (!title) {
    console.error('Title is required.')
    rl.close()
    process.exit(1)
  }

  const suggestedId = slugify(title)
  const idInput = (await ask(`ID [${suggestedId}]: `)).trim()
  const id = idInput ? slugify(idInput) : suggestedId

  console.log('\nDomains:')
  DOMAINS.forEach((d, i) => console.log(`  ${i + 1}. ${DOMAIN_META[d].label} (${d})`))
  const domainRaw = (await ask('Domain (number): ')).trim()
  const domainIndex = Number.parseInt(domainRaw, 10) - 1
  const domain: DomainSlug | undefined = DOMAINS[domainIndex]
  if (!domain) {
    console.error('Invalid domain selection.')
    rl.close()
    process.exit(1)
  }

  const category = (await ask('Category (e.g. "Initial Access / Credential Access"): ')).trim()

  console.log('\nSeverities:', SEVERITIES.join(', '))
  const severityRaw = (await ask('Severity: ')).trim().toLowerCase()
  const severity = SEVERITIES.find((s) => s === severityRaw) as Severity | undefined
  if (!severity) {
    console.error(`Invalid severity. Must be one of: ${SEVERITIES.join(', ')}`)
    rl.close()
    process.exit(1)
  }

  const shortDesc = (await ask('Short description (max 220 chars): ')).trim()
  const description = (await ask('Full description: ')).trim()

  rl.close()

  const dir = join(ENTRIES_ROOT, domain)
  mkdirSync(dir, { recursive: true })
  const filePath = join(dir, `${id}.ts`)

  if (existsSync(filePath)) {
    console.error(`\nA file already exists at ${filePath} — aborting so nothing gets overwritten.`)
    process.exit(1)
  }

  const esc = (str: string) => str.replace(/\\/g, '\\\\').replace(/"/g, '\\"')

  const contents = `import type { ThreatEntry } from '../../../../types/threat'

const entry: ThreatEntry = {
  id: "${esc(id)}",
  title: "${esc(title)}",
  domain: "${esc(domain)}",
  category: "${esc(category)}",
  severity: "${esc(severity)}",
  status: 'stub',
  shortDesc: "${esc(shortDesc)}",
  description: "${esc(description)}",

  // Optional sections — add as the write-up is fleshed out, then flip
  // status to 'complete':
  // forensicArtifacts: [{ source: '...', artifact: '...' }],
  // telemetry: { authenticationProtocols: [], correlationMarkers: [], relevantErrorCodes: [] },
  // mitre: [{ id: 'T....', name: '...', tactic: '...' }],
  // atrm: [{ id: 'AZT...', name: '...', tactic: '...' }],
  // kql: {
  //   sentinel: { triage: { title: '...', query: \`...\` } },
  //   defender: { triage: { title: '...', query: \`...\` } },
  // },
  // runbook: { triage: [], contain: [], investigate: [], recover: [] },
}

export default entry
`

  writeFileSync(filePath, contents, 'utf8')
  console.log(`\nWrote ${filePath}`)
  console.log('Run `npm run validate:content` to confirm it passes schema validation.')
}

main().catch((err) => {
  console.error('new-threat crashed:', err)
  process.exit(1)
})
