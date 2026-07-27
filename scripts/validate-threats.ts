/**
 * Standalone validation for the threat catalog, meant to run outside the
 * Vite pipeline (in CI, pre-commit, or locally via `npm run validate:threats`).
 *
 * This intentionally does NOT use import.meta.glob — that's a Vite-only API.
 * Discovery here is plain fs recursion so this script works anywhere `tsx`
 * runs, with no bundler involved.
 */
import { readdirSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'
import { pathToFileURL } from 'node:url'
import { ThreatEntrySchema } from '../src/types/threat'

const ENTRIES_ROOT = join(import.meta.dirname, '..', 'src', 'data', 'threats', 'entries')

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

async function main() {
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

  console.log(`\n${files.length - errorCount}/${files.length} file(s) passed validation.`)

  if (errorCount > 0) {
    console.error(`\n${errorCount} threat file(s) failed validation. See details above.`)
    process.exit(1)
  }

  console.log('All threat entries are valid.')
}

main().catch((err) => {
  console.error('validate-threats crashed:', err)
  process.exit(1)
})
