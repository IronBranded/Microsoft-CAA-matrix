# Microsoft Cloud Attack & Abuse (CAA) Matrix

A browsable, searchable DFIR reference catalog for Microsoft 365, Entra ID,
and Azure Infrastructure attack and abuse scenarios.

<h3 align="center">
  <a href="https://ironbranded.github.io/Microsoft-CAA-matrix/" target="_blank" rel="noopener noreferrer">
    🟢 START THE MATRIX 🟢
  </a>
</h3>

## What's in it

**59 scenarios across 8 domains:**

| Domain | Scenarios | Focus |
|---|---|---|
| Identity & Authentication | 13 | Tokens, PRTs, passkeys, AiTM, device code phishing |
| Access Control & Escalation | 6 | Conditional Access, role groups, PIM |
| Azure Infrastructure & Compute | 7 | IMDS, Run Command, VM extensions, snapshots |
| App & Workload Identity | 11 | OAuth, service principals, workload identity federation, Power Platform |
| Persistence & Pivoting | 7 | Cross-tenant trust, app proxies, AD FS, federation |
| Email & Messaging (BEC) | 5 | Transport rules, inbox rules, Teams |
| Data Exfiltration & AI | 7 | Graph API, Copilot, eDiscovery, DLP |
| Defense Evasion & Audit | 3 | Log disablement, diagnostic tampering |

Every scenario includes forensic artifacts, telemetry and correlation
markers, MITRE ATT&CK and Azure Threat Research Matrix (ATRM) mappings
where a mapping genuinely exists, dual-platform KQL (Microsoft Sentinel
**and** Defender Advanced Hunting), and a 4-phase incident response
runbook (triage / contain / investigate / recover).

**The Acquisition Guide** (`/acquisition`, linked in the header) is a
second reference table alongside the scenario catalog: 18 log sources with
their priority, license/plan requirement, and retention — the question the
scenario entries assume is already answered, of whether you can actually
collect a given piece of telemetry given your licensing.

## Using it

- **Search** the header bar matches on title, description, and MITRE/ATRM
  IDs.
- **Filter** by domain or severity from the sidebar; both are shareable/
  bookmarkable URLs.
- **Grid or Table view**, toggled from the catalog header — grid for
  browsing, table for scanning or comparing across a column at a glance.
- Every KQL block has a **copy button**; queries are labeled by which
  platform (Sentinel / Defender) and phase they're for.
- Every scenario page links out to its MITRE and ATRM technique pages
  directly.

## Running it locally

Requires Node 20+ (see [`.nvmrc`](.nvmrc)).

```bash
npm install
npm run dev
```

| Command                    | What it does                                            |
| --------------------------- | -------------------------------------------------------- |
| `npm run dev`               | Local dev server with HMR                                |
| `npm run build`             | Type-check + production build to `dist/`                 |
| `npm run preview`           | Preview the production build locally                     |
| `npm run lint`               | ESLint over the whole project                            |
| `npm run validate:content`  | Schema-validate every threat entry and log source (also runs in CI) |
| `npm run new:threat`        | Interactive scaffold for a new threat entry               |

## Deploying your own copy

1. In your repo's **Settings → Pages**, set **Source** to **GitHub Actions**.
2. Update `GH_PAGES_BASE` in [`vite.config.ts`](vite.config.ts) to match your
   repository name (it must equal `/<repo-name>/`).
3. Update `REPO_URL` in [`src/config.ts`](src/config.ts).
4. Push to `main` — `deploy.yml` handles validation, build, and deploy.

## Stack

- [Vite](https://vite.dev/) + [React](https://react.dev/) + TypeScript
- [Zod](https://zod.dev/) for schema validation
- CSS Modules, no CSS framework
- Dependency-free hash router ([`src/lib/router.tsx`](src/lib/router.tsx))
- GitHub Actions → GitHub Pages

## Project structure

```
src/
  types/                    threat.ts and logSource.ts — Zod schemas + inferred types
  data/
    threats/entries/<domain>/*.ts   One file per threat scenario
    logSources/index.ts             Acquisition Guide data
  components/
    common/                 SeverityBadge, PriorityBadge, SearchInput, CopyButton, LoadingState
    layout/                 AppShell, Header, Sidebar
    home/                   ThreatCard, ThreatTable
    views/                  CatalogView, ThreatDetailView, AcquisitionView, NotFoundView
    detail/                 ForensicArtifactsTable, TelemetryPanel,
                             FrameworkMappings, KqlExplorer, RunbookPanel
  lib/                      router.tsx, severity.ts, filter.ts, frameworkLinks.ts, useThreats.ts
  styles/                   tokens.css, global.css
scripts/
  validate-content.ts       CI validation for threats + log sources
  new-threat.ts             Interactive scaffolding CLI
```

## Contributing

Adding a scenario is just a new file under
`src/data/threats/entries/<domain>/` — nothing to register by hand. See
[CONTRIBUTING.md](CONTRIBUTING.md) for the full schema reference, for both
threat entries and Acquisition Guide log sources.

## KQL accuracy note

KQL in this catalog is written for readability and to point an analyst in
the right direction, not copy-pasted as certified-correct for every tenant.
Table and column names are called out with a comment wherever a query
depends on something worth double-checking against your own environment —
a diagnostic setting that needs enabling, a schema that's changed recently,
or a table naming convention that varies by license tier. Treat every query
here as a strong starting point, not a guarantee.

## License

[MIT](LICENSE)
