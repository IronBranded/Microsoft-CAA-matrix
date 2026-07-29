import { LogSourceListSchema, type LogSource } from '@/types/logSource'

const rawLogSources: LogSource[] = [
  {
    id: 'unified-audit-log',
    name: 'Unified Audit Log (UAL)',
    priority: 'critical',
    licenseRequirement: 'E3 (180d) / E5 (1yr, 4 workloads only)',
    notes:
      "The E5 1-year default only applies to four specific workloads — Exchange, SharePoint, OneDrive, and Microsoft Entra ID — Teams, Power Platform, and Defender events default to 180 days on E5 too unless a custom retention policy is configured for them. E5 can extend to 10 years with the Audit (Premium) retention add-on. A single portal search is also capped at a 180-day window regardless of how far back data is retained; older records need pagination or the Management Activity API.",
  },
  {
    id: 'mail-items-accessed',
    name: 'MailItemsAccessed',
    priority: 'critical',
    licenseRequirement: 'E5 / Audit (Premium) only — not available on E3',
    notes:
      'An E3 tenant can get this via the Microsoft 365 E5 Compliance or E5 eDiscovery and Audit add-on, applied per-user rather than tenant-wide — a practical option for your highest-risk mailboxes (executives, finance, IT admins) without licensing E5 broadly. Not retroactive: upgrading mid-investigation does not backfill events from before the upgrade.',
  },
  {
    id: 'sign-in-logs',
    name: 'Sign-in Logs (Interactive & Non-Interactive)',
    priority: 'critical',
    licenseRequirement: 'Free (7d) / P1 (30d) / P2 (30d)',
    notes:
      "P1 and P2 give the same 30-day portal retention — there's no 90-day tier for sign-in logs specifically. (P2 does add an extra 60 days of retention for risky sign-in data specifically, via Identity Protection — a different, narrower thing than general sign-in log retention.) M365 E3 bundles Entra ID P1, so 'E3' and 'P1' land on the same 30-day figure in practice, but retention itself is governed by Entra edition, not the M365 SKU.",
  },
  {
    id: 'entra-audit-logs',
    name: 'Entra ID Audit Logs',
    priority: 'high',
    licenseRequirement: 'Free (7d) / P1+P2 (30d)',
  },
  {
    id: 'mailbox-audit-log',
    name: 'Mailbox Audit Log',
    priority: 'high',
    licenseRequirement: 'All plans, default enabled',
  },
  {
    id: 'message-trace-log',
    name: 'Message Trace Log',
    priority: 'high',
    licenseRequirement: 'All plans — 10d real-time / 90d historical',
  },
  {
    id: 'graph-activity-logs',
    name: 'Microsoft Graph Activity Logs',
    priority: 'high',
    licenseRequirement: 'Requires Entra ID P1 or P2 — must enable via Diagnostic Settings',
    notes: "Diagnostic Settings aren't offered on the Free tier at all, so anything gated behind them — this included — inherits the P1/P2 requirement.",
  },
  {
    id: 'service-principal-signin-logs',
    name: 'Service Principal Sign-in Logs',
    priority: 'high',
    licenseRequirement: 'Requires Entra ID P1 or P2 — must enable via Diagnostic Settings',
    notes: 'This is a Diagnostic Settings category, and Diagnostic Settings require at least P1.',
  },
  {
    id: 'intune-audit-logs',
    name: 'Intune Audit Logs',
    priority: 'high',
    licenseRequirement: 'Any Intune license — requires Diagnostic Settings',
    notes: "Not gated behind Entra P1/P2 — this is Intune's own Diagnostic Settings, a separate licensing surface.",
  },
  {
    id: 'azure-devops-audit-logs',
    name: 'Azure DevOps Audit Logs',
    priority: 'high',
    licenseRequirement: 'DevOps Basic — must enable in Org Settings',
  },
  {
    id: 'azure-activity-log',
    name: 'Azure Activity Log (AzureActivity)',
    priority: 'critical',
    licenseRequirement: 'Free, always generated — requires a Diagnostic Setting to reach a workspace',
    notes:
      'The Activity Log itself is always generated at the platform level regardless of licensing, but nothing routes it into a queryable Sentinel/Log Analytics workspace until a Diagnostic Setting explicitly does so. An empty query result more often means missing routing than a clean environment.',
  },
  {
    id: 'nsg-flow-logs',
    name: 'NSG Flow Logs',
    priority: 'high',
    licenseRequirement: 'Requires Network Watcher — consumption-based cost, not gated by M365/Entra licensing',
    notes: 'Not on by default per NSG, and billed separately by volume rather than bundled into a license tier.',
  },
  {
    id: 'managed-identity-signin-logs',
    name: 'Managed Identity Sign-in Logs (AADManagedIdentitySignInLogs)',
    priority: 'high',
    licenseRequirement: 'Requires Entra ID P1 or P2 — must enable via Diagnostic Settings',
    notes: 'Same Diagnostic Settings / P1+P2 gate as Service Principal Sign-in Logs above.',
  },
  {
    id: 'adfs-signin-logs',
    name: 'AD FS Sign-in Logs (ADFSSignInLogs)',
    priority: 'medium',
    licenseRequirement: 'Requires Microsoft Entra Connect Health for AD FS',
    notes:
      'Worth confirming against current Microsoft Entra Connect Health documentation before relying on it operationally — a less standardized area than the Entra ID P1/P2 licensing that governs most of the rest of this table.',
  },
]

export const logSources: LogSource[] = LogSourceListSchema.parse(rawLogSources)
