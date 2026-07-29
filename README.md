# Microsoft Cloud Attack & Abuse Matrix

A browsable, searchable DFIR reference catalog for Microsoft 365, Entra ID,
and Azure Infrastructure attack and abuse scenarios — forensic artifacts,
telemetry, MITRE ATT&CK / Azure Threat Research Matrix (ATRM) mappings,
dual-platform KQL (Microsoft Sentinel **and** Defender Advanced Hunting),
and 4-phase incident response runbooks.

This is a modular rebuild of an earlier single-file HTML prototype, restructured
for ongoing maintenance: each threat scenario lives in its own file, validated
against a shared schema, and the whole catalog deploys automatically to GitHub
Pages on every merge to `main`.

## Stack

- [Vite](https://vite.dev/) + [React](https://react.dev/) + TypeScript
- [Zod](https://zod.dev/) for runtime schema validation of every threat entry
- CSS Modules with a small design-token system (no CSS framework)
- A dependency-free ~90-line hash router (see [`src/lib/router.tsx`](src/lib/router.tsx)
  for why — this app's routing needs are simple enough not to justify a
  full routing library, and it sidesteps that dependency's churn)
- GitHub Actions → GitHub Pages, via the modern `actions/deploy-pages` flow
  (no `gh-pages` branch)

## Getting started

Requires Node 20+ (see [`.nvmrc`](.nvmrc)).

```bash
npm install
npm run dev
```

Other scripts:

| Command                    | What it does                                            |
| --------------------------- | -------------------------------------------------------- |
| `npm run dev`               | Local dev server with HMR                                |
| `npm run build`             | Type-check + production build to `dist/`                 |
| `npm run preview`           | Preview the production build locally                     |
| `npm run lint`               | ESLint over the whole project                            |
| `npm run validate:content`  | Schema-validate every threat entry and log source (also runs in CI) |
| `npm run new:threat`        | Interactive scaffold for a new threat entry               |

## Project structure

```
src/
  types/
    threat.ts                Zod schema + inferred types for threat entries
    logSource.ts              Zod schema + inferred types for the Acquisition Guide
  data/
    threats/
      index.ts                Lazy-loaded discovery (import.meta.glob) + validation + caching
      entries/<domain>/*.ts   One file per threat scenario
    logSources/
      index.ts                Acquisition Guide log source data (single file, small dataset)
  components/
    common/                 SeverityBadge, PriorityBadge, SearchInput, CopyButton, LoadingState
    layout/                 AppShell, Header, Sidebar
    home/                   ThreatCard, ThreatTable
    views/                  CatalogView (grid/table toggle), ThreatDetailView (lazy-loaded),
                             AcquisitionView, NotFoundView
    detail/                 ForensicArtifactsTable, TelemetryPanel,
                             FrameworkMappings, KqlExplorer, RunbookPanel
  lib/                      router.tsx, severity.ts, filter.ts, frameworkLinks.ts, useThreats.ts
  styles/                   tokens.css (design tokens), global.css
scripts/
  validate-content.ts       Standalone validation for threats + log sources (used by CI, not Vite-dependent)
  new-threat.ts             Interactive scaffolding CLI
.github/workflows/
  ci.yml                    Validate + lint + build on every PR
  deploy.yml                Validate + build + deploy to Pages on push to main
```

Adding a new threat scenario is just adding a new file under
`src/data/threats/entries/<domain>/` — nothing to register by hand. See
[CONTRIBUTING.md](CONTRIBUTING.md) for the full schema guide.

### Acquisition Guide

Alongside the 58 threat scenarios, `/acquisition` (linked from the header)
is a separate reference table answering a question the threat entries
themselves assume is already solved: can you actually collect a given
piece of telemetry, given your licensing? Each row is a log source with
its priority, license/plan requirement, and operational caveats — retention
windows, Diagnostic Settings gates, deprecations. It's plain data
(`src/data/logSources/index.ts`), validated the same way threat entries
are, with no separate content pipeline.

### Data loading

Each threat entry is its own file and, correspondingly, its own build chunk
— `src/data/threats/index.ts` loads them via a non-eager
`import.meta.glob`, so Vite code-splits every entry individually rather than
bundling all of them into the initial payload. `getThreats()` resolves and
caches the full set once; `useThreats()` (in `src/lib/useThreats.ts`) is the
hook components use to read it, with a loading state while entries stream
in. `ThreatDetailView` itself is also lazy-loaded (`React.lazy`), since it
pulls in five detail-only sub-components that `CatalogView` — the default,
first-loaded view — never needs. This keeps the initial bundle to what the
catalog view actually requires; detail content loads on demand.

## Content status

All 58 scenarios in the matrix are complete: forensic artifacts, telemetry,
MITRE ATT&CK mappings (plus ATRM where independently verified — see the
note in [CONTRIBUTING.md](CONTRIBUTING.md)), Sentinel and Defender Advanced
Hunting KQL, and a 4-phase runbook. The Acquisition Guide (18 log sources
as of this writing) is similarly kept current against official Microsoft
documentation rather than assumed — see the note in CONTRIBUTING.md for
how to add to it.

New scenarios can still be added as `stub` entries (metadata only) via
`npm run new:threat` and completed later. The catalog grid and table don't
show a status badge — with all 58 entries complete, one would carry no
information — but the detail page checks for actual forensic content and
shows a notice when a scenario genuinely doesn't have a full write-up yet,
pointing to CONTRIBUTING.md. See CONTRIBUTING.md for the schema.

## Deploying your own copy

1. In your repo's **Settings → Pages**, set **Source** to **GitHub Actions**.
2. Update `GH_PAGES_BASE` in [`vite.config.ts`](vite.config.ts) to match your
   repository name (it must equal `/<repo-name>/`).
3. Update `REPO_URL` in [`src/config.ts`](src/config.ts).
4. Push to `main` — `deploy.yml` handles the rest.

## KQL accuracy note

KQL in this catalog is written for readability and to point an analyst in
the right direction, not copy-pasted as certified-correct for every tenant.
Table and column names are called out with a comment wherever a query
depends on something worth double-checking against your own environment —
a diagnostic setting that needs enabling, a schema that's changed recently,
or a table naming convention that varies by license tier. Treat every query
here as a strong starting point, not a guarantee.
