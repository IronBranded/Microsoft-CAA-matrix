# Contributing

The most useful contribution this project can take right now is turning a
`stub` entry into a `complete` one. This guide covers the schema, the
conventions the existing entries follow, and how to validate your work.

## Adding or editing a threat entry

**Easiest path:** run `npm run new:threat` and answer the prompts — it
generates a correctly-placed, correctly-shaped stub file for you.

**Manual path:** create a file at
`src/data/threats/entries/<domain>/<id>.ts`, where `<domain>` is one of the
eight fixed domain slugs (see `DOMAINS` in `src/types/threat.ts`) and `<id>`
matches the filename. No import or registration step needed — every file
under `entries/**/*.ts` is picked up automatically.

### The relative import

Every entry file imports the type like this:

```ts
import type { ThreatEntry } from '../../../../types/threat'
```

Use the relative path, **not** the `@/` alias. Entry files are loaded two
different ways — by Vite (`import.meta.glob`, which understands the alias
fine) and by `scripts/validate-threats.ts` via plain `tsx` outside the Vite
pipeline, where alias resolution isn't guaranteed. The relative import works
identically in both, which is why it's the convention everywhere under
`entries/`.

### Minimal (stub) entry

```ts
import type { ThreatEntry } from '../../../../types/threat'

const entry: ThreatEntry = {
  id: 'example-threat-id',
  title: 'Example Threat',
  domain: 'identity-authentication',
  category: 'Initial Access / Credential Access',
  severity: 'high',
  status: 'stub',
  shortDesc: 'One or two sentences, max 220 characters, shown on the catalog card.',
  description: 'A fuller paragraph shown at the top of the detail page.',
}

export default entry
```

### Full (complete) entry — field reference

All fields below `description` are optional; include whichever apply. Look
at `src/data/threats/entries/identity-authentication/device-code-phishing.ts`
for a complete worked example.

| Field                | Type                                    | Notes |
| --------------------- | ---------------------------------------- | ----- |
| `id`                  | kebab-case string                        | Must match the filename. Validated by regex. |
| `title`               | string                                   | |
| `domain`              | one of the 8 domain slugs                | Must match the folder the file lives in. |
| `category`            | free-text string                         | MITRE-tactic-style label, e.g. `"Initial Access / Credential Access"`. Not the same as the fixed `domain` — this is richer, per-entry framing. |
| `severity`            | `critical` \| `high` \| `medium` \| `low`| |
| `status`              | `complete` \| `stub`                     | Defaults to `stub` if omitted. Set to `complete` once the detail sections below are filled in. |
| `shortDesc`           | string, ≤220 chars                       | Shown on catalog cards. Keep it tight. |
| `description`         | string                                   | Shown at the top of the detail page. |
| `forensicArtifacts`   | `{ source, artifact }[]`                 | Where to look and what you'd see. |
| `telemetry`           | see below                                | |
| `mitre`               | `{ id, name, tactic }[]`                 | MITRE ATT&CK technique mappings. |
| `atrm`                | `{ id, name, tactic }[]`                 | [Azure Threat Research Matrix](https://microsoft.github.io/Azure-Threat-Research-Matrix/) mappings. **Only include IDs you've actually verified against the current matrix — leave this field off rather than guess.** Not every scenario has a clean ATRM mapping; that's fine. |
| `kql`                 | see below                                | |
| `runbook`             | see below                                | |

**`telemetry`** — all three sub-fields are independently optional:

```ts
telemetry: {
  authenticationProtocols: ['deviceCode'],       // string[]
  correlationMarkers: ['...'],                    // string[] — freeform notes on what ties events together
  relevantErrorCodes: [
    { code: 'AADSTS...', type: '...', description: '...', dfirValue: '...' },
  ],
}
```

**`kql`** — two platform groups, each an optional *named record* of queries
(not fixed to `triage`/`investigate` — call them whatever fits: `triage`,
`investigate`, `hunt`, `baseline`, anything):

```ts
kql: {
  sentinel: {
    triage: { title: '...', description: '...', query: `KqlGoesHere | ...` },
  },
  defender: {
    triage: { title: '...', query: `KqlGoesHere | ...` },
  },
}
```

**Both platforms, every time you can.** Sentinel (Log Analytics workspace
tables — `SigninLogs`, `AuditLogs`, `OfficeActivity`, `AzureActivity`, and
so on) and Defender Advanced Hunting (the XDR schema — `CloudAppEvents`,
`IdentityLogonEvents`, `DeviceProcessEvents`, and so on) draw from different
table sets and are frequently run by different people on the same team. If
you're only confident in one platform's query, it's fine to include just
that one — but if a table or column name isn't something you've verified
against current Microsoft documentation, say so in the query's
`description` or as a comment inside the `query` string itself, the way the
existing entries do. A hedged, honest query that tells the next analyst
what to double-check is more useful than a confident-looking one that's
wrong.

**`runbook`** — four independently-optional phases, each a string array:

```ts
runbook: {
  triage: ['...', '...'],
  contain: ['...', '...'],
  investigate: ['...', '...'],
  recover: ['...', '...'],
}
```

Steps render in a numbered list automatically — don't prefix them with your
own `"1. "` (if a string already starts with a number, the UI strips it
rather than double-numbering, but it's cleaner to just leave it off).

## Validating your work

```bash
npm run validate:threats
```

This runs outside the Vite pipeline (plain `tsx` + `fs`, mirroring what CI
runs) and checks every entry against the Zod schema, plus that each file's
`domain` field matches the folder it's in and that no `id` is duplicated
across the catalog. Run it before opening a PR — `ci.yml` will run it again
regardless, but it's much faster to catch issues locally.

`npm run build` (type-check + Vite build) and `npm run lint` are worth
running too; both also run in CI.
