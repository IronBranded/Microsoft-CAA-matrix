# Contributing

All 59 scenarios in the current taxonomy are complete, so the most useful
contribution right now is either a new scenario beyond the original 58, or
keeping existing content accurate as Microsoft's documentation, licensing,
and product surface changes — table names get deprecated, license tiers
get restructured, retention windows change. This guide covers both the
threat entry schema and the Acquisition Guide's log source schema, the
conventions the existing content follows, and how to validate your work.

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
fine) and by `scripts/validate-content.ts` via plain `tsx` outside the Vite
pipeline, where alias resolution isn't guaranteed. The relative import works
identically in both, which is why it's the convention everywhere under
`entries/` (and in `src/data/logSources/index.ts`, for the same reason).

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
| `atrm`                | `{ id, name, tactic }[]`                 | [Azure Threat Research Matrix](https://microsoft.github.io/Azure-Threat-Research-Matrix/) mappings. **Only include IDs you've actually verified against the current matrix — leave this field off rather than guess.** ATRM covers 7 tactics only — Reconnaissance, Initial Access, Execution, Privilege Escalation, Persistence, Credential Access, and Impact. There's no Defense Evasion, Discovery beyond Reconnaissance, Lateral Movement, Collection, or Exfiltration tactic in the matrix at all, so entries in those areas (most of Email & Messaging, Defense Evasion & Audit, much of Data Exfiltration & AI) genuinely have no ATRM mapping to find — that's not a gap in your research, it's outside the matrix's scope. |
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

## Adding or editing a log source

The Acquisition Guide (`/acquisition`) is a much smaller, flatter dataset
than the threat catalog — one file, `src/data/logSources/index.ts`, holding
an array rather than one file per entry. There's no scaffolding CLI for it;
add or edit an object directly.

| Field                | Type                                     | Notes |
| --------------------- | ----------------------------------------- | ----- |
| `id`                  | kebab-case string                         | Must be unique across the array. Validated by regex, same as threat `id`. |
| `name`                | string                                    | Shown as the row's log source name. |
| `priority`            | `critical` \| `high` \| `medium` \| `low` | How important this source is to have acquired — a different axis from threat `severity`, even though it renders with the same badge styling (`PriorityBadge` reuses `SeverityBadge`'s stylesheet directly rather than duplicating it). |
| `licenseRequirement`  | string                                    | Free text — license/plan tier and retention, e.g. `'Free (7d) / P1 (30d) / P2 (30d)'`. Keep it scannable; this is the column people actually read. |
| `notes`               | string, optional                          | Operational detail that doesn't fit in the requirement field — retention nuances, Diagnostic Settings gates, deprecation timelines, per-agent licensing mechanics. **Direct facts about the data only — never process narration.** Don't write "corrected from X" or "confirmed as given" or "added because"; a reader of the deployed tool has no use for what changed between drafts or how confident the last edit was, only for what's actually true about the log source today. If a note would only make sense as a diff against a previous version, cut it down to just the current fact. |

Every figure in this file should be checked against current Microsoft
Learn documentation before it's added or changed — the same standard as
`atrm` IDs above, and for the same reason: licensing tiers, retention
windows, and feature availability all drift, and a wrong number here is
actively worse than no number, since it looks authoritative. Recent
examples worth knowing about, since they're easy to get wrong by pattern-matching
against an older or more familiar number: Microsoft changed UAL's default
E3 retention from 90 to 180 days in October 2023; the old `Get-MessageTrace`
cmdlets were retired at the end of August 2025 in favor of
`Get-MessageTraceV2`; NSG Flow Logs were deprecated in June 2025 in favor of
Virtual Network Flow Logs. None of these are things you'd necessarily know
from general Microsoft 365/Azure familiarity — they're the kind of change
that's easy to miss unless you specifically go and check.

## Validating your work

```bash
npm run validate:content
```

This runs outside the Vite pipeline (plain `tsx` + `fs`, mirroring what CI
runs) and checks every threat entry against the Zod schema, plus that each
file's `domain` field matches the folder it's in and that no `id` is
duplicated across the catalog. It validates the Acquisition Guide's log
sources too — same schema-and-duplicate-id checks, reported the same way.
Run it before opening a PR — `ci.yml` will run it again regardless, but
it's much faster to catch issues locally.

`npm run build` (type-check + Vite build) and `npm run lint` are worth
running too; both also run in CI.
