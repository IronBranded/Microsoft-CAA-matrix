# Microsoft Cloud Attack & Abuse Matrix

A browsable, searchable DFIR reference catalog for Microsoft 365, Entra ID,
and Azure Infrastructure attack and abuse scenarios — forensic artifacts,
telemetry, MITRE ATT&CK / Azure Threat Research Matrix (ATRM) mappings,
dual-platform KQL (Microsoft Sentinel **and** Defender Advanced Hunting),
and 4-phase incident response runbooks.

---

<h3 align="center">
  <a href="https://ironbranded.github.io/microsoft-cloud-attack-matrix/" target="_blank" rel="noopener noreferrer">
    🟢 NAVIGATE THE ATLAS 🟢
  </a>
</h3>

---

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
| `npm run validate:threats`  | Schema-validate every threat entry (also runs in CI)      |
| `npm run new:threat`        | Interactive scaffold for a new threat entry               |

## Project structure

```
src/
  types/threat.ts          Zod schema + inferred types — the single source of truth
  data/threats/
    index.ts                Lazy-loaded discovery (import.meta.glob) + validation + caching
    entries/<domain>/*.ts   One file per threat scenario
  components/
    common/                 SeverityBadge, SearchInput, CopyButton
    layout/                 AppShell, Header, Sidebar
    home/                   ThreatCard
    views/                  CatalogView, ThreatDetailView (lazy-loaded), NotFoundView
    detail/                 ForensicArtifactsTable, TelemetryPanel,
                             FrameworkMappings, KqlExplorer, RunbookPanel
  lib/                      router.tsx, severity.ts, filter.ts, frameworkLinks.ts, useThreats.ts
  styles/                   tokens.css (design tokens), global.css
scripts/
  validate-threats.ts       Standalone validation (used by CI, not Vite-dependent)
  new-threat.ts             Interactive scaffolding CLI
.github/workflows/
  ci.yml                    Validate + lint + build on every PR
  deploy.yml                Validate + build + deploy to Pages on push to main
```

Adding a new threat scenario is just adding a new file under
`src/data/threats/entries/<domain>/` — nothing to register by hand. See
[CONTRIBUTING.md](CONTRIBUTING.md) for the full schema guide.

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
Hunting KQL, and a 4-phase runbook.

New scenarios can still be added as `stub` entries (metadata only) via
`npm run new:threat` and completed later — the `status` field and the
detail page's stub notice exist for exactly that workflow. See
[CONTRIBUTING.md](CONTRIBUTING.md) for the schema.

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
