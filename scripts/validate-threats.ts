/**
 * Standalone validation for all schema-governed catalog content — threat
 * entries and the Acquisition Guide's log sources — meant to run outside
 * the Vite pipeline (in CI, pre-commit, or locally via
 * `npm run validate:content`).
 *
 * This intentionally does NOT use import.meta.glob — that's a Vite-only
 * API. Discovery here is plain fs recursion so this script works anywhere
 * `tsx` runs, with no bundler involved.
 */
import { readdirSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'
import { pathToFileURL } from 'node:url'
import { ZodError } from 'zod'
import { ThreatEntrySchema } from '../src/types/threat'
import type { LogSource } from '../src/types/logSource'

const ENTRIES_ROOT = join(import.meta.dirname, '..', 'src', 'data', 'threats', 'entries')
const LOG_SOURCES_PATH = join(import.meta.dirname, '..', 'src', 'data', 'logSources', 'index.ts')

function findEntryFiles(dir: string): string[] {
  const files: string[] = []
  for (const name of readdirSync(dir)) {
    const fullPath = join(dir, name)
    const stat = statSync(fullPath)
    if (stat.isDirectory()) {
      files.push(...findEntryFiles(fullPath))
    } else if (name.endsWith('.ts')) {
      files.push(fullPath)
    }
  }
  return files
}

async function validateThreats(): Promise<number> {
  const files = findEntryFiles(ENTRIES_ROOT)
  console.log(`Found ${files.length} threat file(s) under src/data/threats/entries.\n`)

  let errorCount = 0
  const seenIds = new Map<string, string>()

  for (const filePath of files) {
    const relPath = relative(process.cwd(), filePath)
    const mod = await import(pathToFileURL(filePath).href)
    const result = ThreatEntrySchema.safeParse(mod.default)

    if (!result.success) {
      errorCount++
      console.error(`✗ ${relPath}`)
      for (const issue of result.error.issues) {
        console.error(`    ${issue.path.join('.') || '(root)'}: ${issue.message}`)
      }
      continue
    }

    const { id, domain } = result.data
    const expectedDir = join(ENTRIES_ROOT, domain)
    if (!filePath.startsWith(expectedDir)) {
      errorCount++
      console.error(`✗ ${relPath}`)
      console.error(`    domain "${domain}" doesn't match the folder this file lives in`)
      continue
    }

    const existing = seenIds.get(id)
    if (existing) {
      errorCount++
      console.error(`✗ ${relPath}`)
      console.error(`    duplicate id "${id}" (already used by ${existing})`)
      continue
    }
    seenIds.set(id, relPath)
  }

  console.log(`${files.length - errorCount}/${files.length} threat file(s) passed validation.`)
  return errorCount
}

async function validateLogSources(): Promise<number> {
  const relPath = relative(process.cwd(), LOG_SOURCES_PATH)
  console.log(`\nValidating src/data/logSources/index.ts.\n`)

  // The module itself calls LogSourceListSchema.parse() at the top level,
  // so an invalid entry throws on import rather than returning a result we
  // can inspect — caught below and reported in the same itemized style as
  // threat entries, rather than surfacing as a raw crash.
  let sources: LogSource[]
  try {
    const mod = await import(pathToFileURL(LOG_SOURCES_PATH).href)
    sources = mod.logSources
  } catch (err) {
    console.error(`✗ ${relPath}`)
    if (err instanceof ZodError) {
      for (const issue of err.issues) {
        console.error(`    ${issue.path.join('.') || '(root)'}: ${issue.message}`)
      }
    } else {
      console.error(`    ${err instanceof Error ? err.message : String(err)}`)
    }
    console.log(`\n0/? log source(s) passed validation.`)
    return 1
  }

  let errorCount = 0
  const seenIds = new Set<string>()
  for (const source of sources) {
    if (seenIds.has(source.id)) {
      errorCount++
      console.error(`✗ ${relPath}`)
      console.error(`    duplicate log source id "${source.id}"`)
    }
    seenIds.add(source.id)
  }

  console.log(`${sources.length - errorCount}/${sources.length} log source(s) passed validation.`)
  return errorCount
}

async function main() {
  const threatErrors = await validateThreats()
  const logSourceErrors = await validateLogSources()
  const totalErrors = threatErrors + logSourceErrors

  if (totalErrors > 0) {
    console.error(`\n${totalErrors} item(s) failed validation. See details above.`)
    process.exit(1)
  }

  console.log('\nAll catalog content is valid.')
}

main().catch((err) => {
  console.error('validate-content crashed:', err)
  process.exit(1)
})
