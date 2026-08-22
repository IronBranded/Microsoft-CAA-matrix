import { z } from 'zod'

/**
 * Single source of truth for the threat entry shape. Runtime validation
 * (Zod) and compile-time types (z.infer) are derived from the same
 * definitions here so they can never drift apart.
 */

// ---------------------------------------------------------------------------
// Severity
// ---------------------------------------------------------------------------
export const SEVERITIES = ['critical', 'high', 'medium', 'low'] as const
export const SeveritySchema = z.enum(SEVERITIES)
export type Severity = z.infer<typeof SeveritySchema>

// ---------------------------------------------------------------------------
// Domain taxonomy — fixed and used for sidebar filtering, matching the
// Microsoft Cloud Attack & Abuse Matrix's 8 operational domains. `category`
// on a threat stays free text, for the richer MITRE-tactic-style labeling
// used in detail views (e.g. "Initial Access / Credential Access").
// ---------------------------------------------------------------------------
export const DOMAINS = [
  'identity-authentication',
  'access-control-escalation',
  'azure-infrastructure-compute',
  'app-workload-identity',
  'persistence-pivoting',
  'email-messaging-bec',
  'data-exfiltration-ai',
  'defense-evasion-audit',
] as const

export const DomainSchema = z.enum(DOMAINS)
export type DomainSlug = z.infer<typeof DomainSchema>

export interface DomainMeta {
  slug: DomainSlug
  order: number
  label: string
  focus: string
}

export const DOMAIN_META: Record<DomainSlug, DomainMeta> = {
  'identity-authentication': {
    slug: 'identity-authentication',
    order: 1,
    label: 'Identity & Authentication',
    focus: 'Tokens, PRTs, Passkeys, AiTM',
  },
  'access-control-escalation': {
    slug: 'access-control-escalation',
    order: 2,
    label: 'Access Control & Escalation',
    focus: 'Conditional Access, Role Groups, PIM',
  },
  'azure-infrastructure-compute': {
    slug: 'azure-infrastructure-compute',
    order: 3,
    label: 'Azure Infrastructure & Compute',
    focus: 'IMDS, RunCommand, Extensions, Snapshots',
  },
  'app-workload-identity': {
    slug: 'app-workload-identity',
    order: 4,
    label: 'App & Workload Identity',
    focus: 'OAuth, Service Principals, WIF, Power Platform',
  },
  'persistence-pivoting': {
    slug: 'persistence-pivoting',
    order: 5,
    label: 'Persistence & Pivoting',
    focus: 'Cross-Tenant, App Proxies, ADFS, Federation',
  },
  'email-messaging-bec': {
    slug: 'email-messaging-bec',
    order: 6,
    label: 'Email & Messaging (BEC)',
    focus: 'Transport Rules, Inbox Rules, Teams',
  },
  'data-exfiltration-ai': {
    slug: 'data-exfiltration-ai',
    order: 7,
    label: 'Data Exfiltration & AI',
    focus: 'Graph API, Copilot RAG, eDiscovery, DLP',
  },
  'defense-evasion-audit': {
    slug: 'defense-evasion-audit',
    order: 8,
    label: 'Defense Evasion & Audit',
    focus: 'Log Disablement, Diagnostic Poisoning',
  },
}

export const ORDERED_DOMAINS: DomainSlug[] = [...DOMAINS].sort(
  (a, b) => DOMAIN_META[a].order - DOMAIN_META[b].order,
)

// ---------------------------------------------------------------------------
// Forensic artifacts & telemetry
// ---------------------------------------------------------------------------
export const ForensicArtifactSchema = z.object({
  source: z.string().min(1),
  artifact: z.string().min(1),
  /**
   * Optional cross-reference to a LogSource.id in the Acquisition Guide —
   * lets ForensicArtifactsTable render a "how do I actually get this"
   * deep-link next to the artifact instead of leaving licensing/collection
   * questions implicit.
   */
  logSourceId: z.string().optional(),
})
export type ForensicArtifact = z.infer<typeof ForensicArtifactSchema>

export const TelemetryErrorCodeSchema = z.object({
  code: z.string().min(1),
  type: z.string().min(1),
  description: z.string().min(1),
  dfirValue: z.string().min(1),
})
export type TelemetryErrorCode = z.infer<typeof TelemetryErrorCodeSchema>

export const TelemetrySchema = z.object({
  authenticationProtocols: z.array(z.string()).optional(),
  correlationMarkers: z.array(z.string()).optional(),
  relevantErrorCodes: z.array(TelemetryErrorCodeSchema).optional(),
})
export type Telemetry = z.infer<typeof TelemetrySchema>

// ---------------------------------------------------------------------------
// Framework mappings — shared shape for both MITRE ATT&CK and the Azure
// Threat Research Matrix (ATRM). Kept as separate arrays on the entry since
// the two catalogs use different ID formats and cover different scopes.
// ---------------------------------------------------------------------------
export const FrameworkMappingSchema = z.object({
  id: z.string().min(1),
  name: z.string().min(1),
  tactic: z.string().min(1),
})
export type FrameworkMapping = z.infer<typeof FrameworkMappingSchema>

// ---------------------------------------------------------------------------
// KQL — Sentinel (Log Analytics workspace tables, e.g. SigninLogs,
// AuditLogs, OfficeActivity) and Defender Advanced Hunting (XDR schema,
// e.g. CloudAppEvents, IdentityLogonEvents) draw from different table sets,
// so queries are kept in two separate named groups rather than one flat
// list. Each platform holds a free-form record of named queries (not fixed
// to "triage"/"investigate") so an entry can add as many as the write-up
// needs — "triage", "investigate", "hunt", "baseline", etc.
// ---------------------------------------------------------------------------
export const KqlQuerySchema = z.object({
  title: z.string().min(1),
  description: z.string().optional(),
  query: z.string().min(1),
})
export type KqlQuery = z.infer<typeof KqlQuerySchema>

export const KqlPlatformSchema = z.record(z.string(), KqlQuerySchema)
export type KqlPlatform = z.infer<typeof KqlPlatformSchema>

export const KqlQueriesSchema = z.object({
  sentinel: KqlPlatformSchema.optional(),
  defender: KqlPlatformSchema.optional(),
})
export type KqlQueries = z.infer<typeof KqlQueriesSchema>

// ---------------------------------------------------------------------------
// Runbook
// ---------------------------------------------------------------------------
export const RunbookSchema = z.object({
  triage: z.array(z.string()).optional(),
  contain: z.array(z.string()).optional(),
  investigate: z.array(z.string()).optional(),
  recover: z.array(z.string()).optional(),
})
export type Runbook = z.infer<typeof RunbookSchema>

// ---------------------------------------------------------------------------
// Content status — lets the catalog stay complete (all scenarios present
// and browsable) while being explicit about which entries have full DFIR
// write-ups versus scaffolded metadata still awaiting one.
// ---------------------------------------------------------------------------
export const CONTENT_STATUSES = ['complete', 'stub'] as const
export const ContentStatusSchema = z.enum(CONTENT_STATUSES)
export type ContentStatus = z.infer<typeof ContentStatusSchema>

// ---------------------------------------------------------------------------
// Threat entry
// ---------------------------------------------------------------------------
export const ThreatEntrySchema = z.object({
  id: z
    .string()
    .regex(/^[a-z0-9]+(-[a-z0-9]+)*$/, 'id must be kebab-case (e.g. "device-code-phishing")'),
  title: z.string().min(1),
  domain: DomainSchema,
  category: z.string().min(1),
  severity: SeveritySchema,
  status: ContentStatusSchema.default('stub'),
  shortDesc: z.string().min(1).max(220),
  description: z.string().min(1),

  forensicArtifacts: z.array(ForensicArtifactSchema).optional(),
  telemetry: TelemetrySchema.optional(),
  mitre: z.array(FrameworkMappingSchema).optional(),
  atrm: z.array(FrameworkMappingSchema).optional(),
  kql: KqlQueriesSchema.optional(),
  runbook: RunbookSchema.optional(),
})

export type ThreatEntry = z.infer<typeof ThreatEntrySchema>
