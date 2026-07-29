import { LogSourceListSchema, type LogSource } from '../../types/logSource'

const rawLogSources: LogSource[] = [
  {
    id: 'unified-audit-log',
    name: 'Unified Audit Log (UAL)',
    priority: 'critical',
    licenseRequirement: 'E3 (180d) / E5 (1yr, 4 workloads only)',
    notes:
      "The E5 1-year default applies only to four workloads — Exchange, SharePoint, OneDrive, and Microsoft Entra ID. Teams, Power Platform, and Defender events default to 180 days on E5 too unless a custom retention policy is configured for them. E5 extends to 10 years with the Audit (Premium) retention add-on. A single portal search is capped at a 180-day window regardless of total retention; older records need pagination or the Management Activity API.",
  },
  {
    id: 'mail-items-accessed',
    name: 'MailItemsAccessed',
    priority: 'critical',
    licenseRequirement: 'E5 / Audit (Premium) only — not available on E3',
    notes:
      'An E3 tenant can get this via the Microsoft 365 E5 Compliance or E5 eDiscovery and Audit add-on, applied per-user rather than tenant-wide — useful for high-risk mailboxes (executives, finance, IT admins) without licensing E5 broadly. Not retroactive: upgrading mid-investigation does not backfill events from before the upgrade.',
  },
  {
    id: 'sign-in-logs',
    name: 'Sign-in Logs (Interactive & Non-Interactive)',
    priority: 'critical',
    licenseRequirement: 'Free (7d) / P1 (30d) / P2 (30d)',
    notes:
      "P1 and P2 give the same 30-day portal retention. P2 adds an extra 60 days of retention for risky sign-in data specifically, via Identity Protection — narrower than general sign-in log retention. M365 E3 bundles Entra ID P1, so 'E3' and 'P1' land on the same 30-day figure in practice; retention is governed by Entra edition, not the M365 SKU.",
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
    name: 'Message Trace Log (Get-MessageTraceV2)',
    priority: 'high',
    licenseRequirement: 'All plans — 90d retention, 10d returned per query',
    notes:
      'The legacy Get-MessageTrace / Get-MessageTraceDetail cmdlets and the old Exchange admin center UI (10-day window, historical search job required for anything older) were retired at the end of August 2025. The current Get-MessageTraceV2 / Get-MessageTraceDetailV2 cmdlets and EAC experience hold 90 days of searchable data, but a single query returns 10 days at a time — cover a wider window with repeated queries across date ranges.',
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
    notes: 'Sign-in log ingestion specifically requires P1 or P2; any Entra ID license, including Free, is sufficient for other log types such as Audit Logs.',
  },
  {
    id: 'defender-endpoint-hunting',
    name: 'Defender for Endpoint Advanced Hunting (DeviceProcessEvents, DeviceNetworkEvents, etc.)',
    priority: 'critical',
    licenseRequirement: 'Defender for Endpoint Plan 2 — Plan 1 does not include Advanced Hunting',
    notes:
      '180 days of retention. Plan 2 is included with Microsoft 365 E5 and Microsoft 365 E5 Security, and available standalone. Plan 1, bundled into Microsoft 365 E3, covers antivirus and basic response actions like device isolation, but not the raw telemetry tables or KQL access the Defender-side queries throughout this catalog rely on.',
  },
  {
    id: 'defender-office365-hunting',
    name: 'Defender for Office 365 Advanced Hunting (EmailEvents, EmailAttachmentInfo)',
    priority: 'high',
    licenseRequirement: 'Defender for Office 365 Plan 2 — Plan 1 does not include Advanced Hunting',
    notes:
      "30 days of queryable retention. As of July 1, 2026, Plan 1 is bundled into Microsoft 365 E3 and Office 365 E3, covering Safe Links, Safe Attachments, anti-phishing, and real-time detections. Advanced Hunting and Threat Explorer remain Plan 2 only, included with Microsoft 365 E5.",
  },
  {
    id: 'cloud-app-events',
    name: 'Defender for Cloud Apps (CloudAppEvents)',
    priority: 'high',
    licenseRequirement: 'Included in Microsoft 365 E5 / E5 Security, or standalone',
    notes:
      'Must be connected via Defender portal → Settings → Cloud apps → App connectors before CloudAppEvents populates with Microsoft 365 activity — a connection gap that looks identical to an empty query result.',
  },
  {
    id: 'identity-protection-risk-data',
    name: 'Identity Protection Risk Data (RiskyUsers, UserRiskEvents)',
    priority: 'high',
    licenseRequirement: 'Requires Entra ID P2 specifically',
    notes:
      "Free and P1 tenants still surface risk detections, but only as a generic 'Additional risk detected' entry with no further detail. The underlying detection type and detail, and the riskyUsers Graph API itself, require P2.",
  },
  {
    id: 'intune-audit-logs',
    name: 'Intune Audit Logs',
    priority: 'high',
    licenseRequirement: 'Any Intune license — requires Diagnostic Settings',
    notes:
      "Not gated behind Entra P1/P2 — this is Intune's own Diagnostic Settings, a separate licensing surface. Retained for 2 years in the Intune admin center by default and auto-deleted after that; route to a Log Analytics workspace, storage account, or Event Hub via Diagnostic Settings for longer retention.",
  },
  {
    id: 'azure-devops-audit-logs',
    name: 'Azure DevOps Audit Logs',
    priority: 'high',
    licenseRequirement: 'Entra ID-backed organization — must enable in Org Settings',
    notes: 'Currently in public preview and off by default for every organization.',
  },
  {
    id: 'azure-activity-log',
    name: 'Azure Activity Log (AzureActivity)',
    priority: 'critical',
    licenseRequirement: 'Free, always generated — requires a Diagnostic Setting to reach a workspace',
    notes:
      'Generated at the platform level regardless of licensing, but nothing routes it into a queryable Sentinel/Log Analytics workspace until a Diagnostic Setting explicitly does so. An empty query result more often means missing routing than a clean environment.',
  },
  {
    id: 'nsg-flow-logs',
    name: 'NSG Flow Logs (deprecated — see notes)',
    priority: 'medium',
    licenseRequirement: 'Requires Network Watcher — consumption-based cost, not gated by M365/Entra licensing',
    notes:
      "Deprecated June 30, 2025 — no new ones can be created — scheduled for full retirement September 30, 2027. Microsoft's replacement is Virtual Network (VNet) Flow Logs; use that for any new deployment. Existing configurations and log data continue working until the retirement date.",
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
    licenseRequirement: 'Requires Microsoft Entra Connect Health for AD FS — Entra ID P1 or P2',
    notes:
      'Licensing scales with monitoring footprint: each additional registered health agent, across AD FS, Microsoft Entra Connect Sync, and AD DS roles combined, requires 25 more P1/P2 licenses.',
  },
]

export const logSources: LogSource[] = LogSourceListSchema.parse(rawLogSources)
