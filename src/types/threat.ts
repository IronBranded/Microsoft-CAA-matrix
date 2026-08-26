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
// Auth flow — the *typical* sign-in code sequence for this scenario, as
// opposed to telemetry.relevantErrorCodes' unordered catalog of individual
// code meanings. This is deliberately a separate field rather than an
// ordering hint bolted onto relevantErrorCodes: a step here can reference a
// code that has no relevantErrorCodes entry (a plain "0" success, or a
// non-code milestone like a device-registration audit event), and the two
// serve different reader intents — one is "what does this code mean", the
// other is "what does the sequence of codes for THIS attack look like, and
// how do I tell it apart from a lookalike elsewhere in the matrix".
//
// `pattern` matters and isn't cosmetic: 'sequence' means the steps are
// causally ordered — the technique doesn't work unless they happen in that
// order (e.g. device code issued, then victim authenticates, then attacker
// polls). 'cluster' means the codes co-occur and are diagnostic together,
// but no single fixed order is load-bearing (e.g. scripted sign-in
// probing throwing a mix of failure/interrupt codes before an eventual
// success, in whatever order the tooling happens to hit them). Getting this
// wrong in either direction actively misleads triage — don't default to
// 'sequence' just because steps happen to be listed in an array.
// ---------------------------------------------------------------------------
export const AuthFlowStepSchema = z.object({
  /** ResultType/ErrorCode value ("50126", "0"), or a short non-numeric
   *  milestone label ("device-registration") when the step isn't a sign-in
   *  result code at all. */
  code: z.string().min(1),
  label: z.string().min(1),
  detail: z.string().optional(),
})
export type AuthFlowStep = z.infer<typeof AuthFlowStepSchema>

export const AuthFlowSchema = z.object({
  pattern: z.enum(['sequence', 'cluster']),
  /** 1-2 sentences framing how to read the steps below — required even
   *  when it feels repetitive, because 'pattern' alone doesn't carry
   *  enough nuance for a reader who lands straight on this section. */
  narrative: z.string().min(1),
  steps: z.array(AuthFlowStepSchema).min(1),
  /** What tells this apart from another entry with an overlapping or
   *  similar-looking code pattern — the actual "help link investigation
   *  pivots to the right scenario" payoff. Omit if nothing else in the
   *  matrix plausibly overlaps. */
  distinguishingNotes: z.string().optional(),
})
export type AuthFlow = z.infer<typeof AuthFlowSchema>

// ---------------------------------------------------------------------------
// Token timeline — token/session lifecycle guidance specific to this
// scenario: issuance and refresh cadence, effective lifetime, and what the
// auth_time/amr claims (when present) or their SigninLogs equivalents
// reveal for this particular attack.
//
// Two accuracy points that matter enough to repeat at every call site
// rather than assume the reader already knows:
//
// 1. auth_time and amr are OPTIONAL claims in Microsoft Entra ID access
//    tokens — an app has to explicitly request them, so a captured token
//    may simply not have them regardless of how relevant they'd be. Never
//    write entry content that assumes a captured token will have these.
// 2. There is no separate "MFA timestamp" claim. Where MFA timing matters,
//    SigninLogs.AuthenticationDetails (a per-step array with its own
//    nested authenticationStepDateTime, authenticationMethod, and
//    succeeded/authenticationStepResultDetail fields) is the more reliable
//    and more consistently available source than anything decoded from a
//    token — it doesn't depend on optional-claim configuration or on an
//    investigator having captured a raw token at all. mfaInstant guidance
//    should point there first and treat token claims as a secondary,
//    supplementary check when one happens to have been captured.
// ---------------------------------------------------------------------------
export const TokenTimelineSchema = z.object({
  /** iat behavior — typical issuance/refresh cadence for this attack, and
   *  what an anomalous cadence would look like. */
  issuance: z.string().min(1),
  /** exp / effective lifetime — typical pattern, including anything that
   *  extends it beyond the default (e.g. a PRT backing silent refresh). */
  expiration: z.string().min(1),
  /** auth_time behavior across refreshes — static (pinned to one original
   *  interactive moment) vs. moving, and what that reveals here. */
  authInstant: z.string().min(1),
  /** amr behavior — typical values for this attack and what a mismatch or
   *  absence means; note plainly when amr won't be present at all. */
  authMethods: z.string().min(1),
  /** When/whether MFA occurred for this attack — SigninLogs
   *  AuthenticationDetails first, token amr+auth_time as a secondary
   *  corroborating check per the module-level note above. */
  mfaInstant: z.string().min(1),
  /** Anything else worth pulling from token/session metadata for this
   *  specific attack — reliance on prior auth context, a new interactive
   *  auth where one shouldn't be, device/PRT binding, etc. */
  otherContext: z.string().optional(),
})
export type TokenTimeline = z.infer<typeof TokenTimelineSchema>

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
  authFlow: AuthFlowSchema.optional(),
  tokenTimeline: TokenTimelineSchema.optional(),
  runbook: RunbookSchema.optional(),
})

export type ThreatEntry = z.infer<typeof ThreatEntrySchema>
