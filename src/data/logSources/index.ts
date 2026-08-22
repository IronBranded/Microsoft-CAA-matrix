import { LogSourceListSchema, type LogSource } from '../../types/logSource'

const rawLogSources: LogSource[] = [
  {
    id: 'unified-audit-log',
    name: 'Unified Audit Log (UAL)',
    priority: 'critical',
    licenseRequirement: 'E3 (180d) / E5 (1yr, 4 workloads only)',
    acquisition: {
      steps: [
        'Quick/one-off: Microsoft Purview portal (purview.microsoft.com) → Solutions → Audit → Search tab. Set a date range and filters, run the search, then Export.',
        'Repeatable/scripted: Connect-ExchangeOnline, then Search-UnifiedAuditLog. Requires the Audit Logs or View-Only Audit Logs role. Returns up to 5,000 results per call — use SessionId/SessionCommand to page through more.',
        'Bulk or continuous SIEM ingestion: the Office 365 Management Activity API, built for polling at scale rather than one-off pulls.',
        'Before relying on any of the above mid-incident: Get-AdminAuditLogConfig | Select-Object UnifiedAuditLogIngestionEnabled — confirm ingestion is actually on. It can be silently disabled (see Unified Audit Log Disablement elsewhere in this matrix), and a clean-looking empty result and a disabled UAL look identical until checked.',
      ],
      command: 'Search-UnifiedAuditLog -StartDate 06/01/2026 -EndDate 06/30/2026 -ResultSize 5000',
      commandType: 'powershell',
    },
    notes:
      "The E5 1-year default applies only to four workloads — Exchange, SharePoint, OneDrive, and Microsoft Entra ID. Teams, Power Platform, and Defender events default to 180 days on E5 too unless a custom retention policy is configured for them. E5 extends to 10 years with the Audit (Premium) retention add-on. A single portal search is capped at a 180-day window regardless of total retention; older records need pagination or the Management Activity API.",
  },
  {
    id: 'mail-items-accessed',
    name: 'MailItemsAccessed',
    priority: 'critical',
    licenseRequirement: 'E5 / Audit (Premium) only — not available on E3',
    acquisition: {
      steps: [
        "Not a separately-collected source — it's a specific Operations value inside the Unified Audit Log above, retrieved the same way (Purview portal Audit search, or Search-UnifiedAuditLog), just filtered to this operation.",
        'Confirm licensing before concluding a mailbox was never accessed: an empty result more often means the tenant lacks E5 or the Audit (Premium) add-on for this specific event type than that nothing happened.',
      ],
      command: "Search-UnifiedAuditLog -StartDate 06/01/2026 -EndDate 06/30/2026 -Operations MailItemsAccessed -UserIds user@domain.com",
      commandType: 'powershell',
    },
    notes:
      'An E3 tenant can get this via the Microsoft 365 E5 Compliance or E5 eDiscovery and Audit add-on, applied per-user rather than tenant-wide — useful for high-risk mailboxes (executives, finance, IT admins) without licensing E5 broadly. Not retroactive: upgrading mid-investigation does not backfill events from before the upgrade.',
  },
  {
    id: 'sign-in-logs',
    name: 'Sign-in Logs (Interactive & Non-Interactive)',
    priority: 'critical',
    licenseRequirement: 'Free (7d) / P1 (30d) / P2 (30d)',
    acquisition: {
      steps: [
        'Quick/one-off: Entra admin center (entra.microsoft.com) → Monitoring & health → Sign-in logs. Filter, then Download. Requires at least the Reports Reader role.',
        'Extended retention/SIEM: Entra admin center → Monitoring & health → Diagnostic settings → Add diagnostic setting → select the SignInLogs and NonInteractiveUserSignInLogs categories → choose a destination (Log Analytics workspace, Storage account, or Event Hub) → Save. Requires Security Administrator.',
        'Programmatic: Microsoft Graph GET /auditLogs/signIns. Needs the Reports Reader or Security Reader role for delegated access, or the AuditLog.Read.All application permission for unattended/scripted access.',
      ],
      command: 'GET https://graph.microsoft.com/v1.0/auditLogs/signIns?$filter=createdDateTime ge 2026-06-01T00:00:00Z',
      commandType: 'graph-api',
    },
    notes:
      "P1 and P2 give the same 30-day portal retention. P2 adds an extra 60 days of retention for risky sign-in data specifically, via Identity Protection — narrower than general sign-in log retention. M365 E3 bundles Entra ID P1, so 'E3' and 'P1' land on the same 30-day figure in practice; retention is governed by Entra edition, not the M365 SKU.",
  },
  {
    id: 'entra-audit-logs',
    name: 'Entra ID Audit Logs',
    priority: 'high',
    licenseRequirement: 'Free (7d) / P1+P2 (30d)',
    acquisition: {
      steps: [
        'Quick/one-off: Entra admin center → Monitoring & health → Audit logs. Filter, then Download. Requires at least the Reports Reader role.',
        'Extended retention/SIEM: same Diagnostic settings blade as Sign-in Logs above — select the AuditLogs category specifically, choose a destination, Save.',
        'Programmatic: Microsoft Graph GET /auditLogs/directoryAudits.',
      ],
      command: 'GET https://graph.microsoft.com/v1.0/auditLogs/directoryAudits',
      commandType: 'graph-api',
    },
  },
  {
    id: 'mailbox-audit-log',
    name: 'Mailbox Audit Log',
    priority: 'high',
    licenseRequirement: 'All plans, default enabled',
    acquisition: {
      steps: [
        'On by default for every plan — no separate enablement step, unlike most sources in this guide.',
        'Not a separate tool to learn: retrieved through the same Unified Audit Log mechanism above (Purview portal Audit search, or Search-UnifiedAuditLog) rather than its own dedicated path — mailbox audit events are folded into the unified log.',
      ],
    },
  },
  {
    id: 'message-trace-log',
    name: 'Message Trace Log (Get-MessageTraceV2)',
    priority: 'high',
    licenseRequirement: 'All plans — 90d retention, 10d returned per query',
    acquisition: {
      steps: [
        'Quick/one-off: Exchange admin center (admin.exchange.microsoft.com) → Mail flow → Message trace.',
        'Scripted: Connect-ExchangeOnline, then Get-MessageTraceV2 (or Get-MessageTraceDetailV2 for the per-message delivery timeline).',
        'A single query returns a 10-day window within the 90-day retention — cover a wider span with repeated queries across date ranges, not one large request.',
      ],
      command: 'Get-MessageTraceV2 -StartDate 06/01/2026 -EndDate 06/10/2026 -RecipientAddress user@domain.com',
      commandType: 'powershell',
    },
    notes:
      'The legacy Get-MessageTrace / Get-MessageTraceDetail cmdlets and the old Exchange admin center UI (10-day window, historical search job required for anything older) were retired at the end of August 2025. The current Get-MessageTraceV2 / Get-MessageTraceDetailV2 cmdlets and EAC experience hold 90 days of searchable data, but a single query returns 10 days at a time — cover a wider window with repeated queries across date ranges.',
  },
  {
    id: 'graph-activity-logs',
    name: 'Microsoft Graph Activity Logs',
    priority: 'high',
    licenseRequirement: 'Requires Entra ID P1 or P2 — must enable via Diagnostic Settings',
    acquisition: {
      steps: [
        'Entra admin center → Monitoring & health → Diagnostic settings → Add diagnostic setting → select the MicrosoftGraphActivityLogs category → choose a destination (Log Analytics workspace, Storage account, or Event Hub) → Save.',
        'Security Administrator is the only built-in role that can configure this — narrower than the Reports Reader role that suffices just to view Sign-in/Audit logs.',
        'Unlike Sign-in Logs and Audit Logs, there is no portal page to browse this data directly — a destination has to be configured before any of it is retrievable at all, even for a one-off look.',
      ],
    },
  },
  {
    id: 'service-principal-signin-logs',
    name: 'Service Principal Sign-in Logs',
    priority: 'high',
    licenseRequirement: 'Requires Entra ID P1 or P2 — must enable via Diagnostic Settings',
    acquisition: {
      steps: [
        'Same Diagnostic settings blade as Sign-in Logs — Entra admin center → Monitoring & health → Diagnostic settings → select the ServicePrincipalSignInLogs category specifically → destination → Save. Requires Security Administrator.',
        "Quick/one-off viewing exists too: Entra admin center → Monitoring & health → Sign-in logs → Service principal sign-ins tab, without needing the diagnostic setting configured first — the portal tab and the exported log category are two different access paths to related but not identical views of the same underlying data.",
      ],
    },
    notes: 'Sign-in log ingestion specifically requires P1 or P2; any Entra ID license, including Free, is sufficient for other log types such as Audit Logs.',
  },
  {
    id: 'defender-endpoint-hunting',
    name: 'Defender for Endpoint Advanced Hunting (DeviceProcessEvents, DeviceNetworkEvents, etc.)',
    priority: 'critical',
    licenseRequirement: 'Defender for Endpoint Plan 2 — Plan 1 does not include Advanced Hunting',
    acquisition: {
      steps: [
        'Immediate/ad-hoc: Microsoft Defender portal (security.microsoft.com) → Hunting → Advanced hunting. Run KQL directly against DeviceProcessEvents, DeviceNetworkEvents, and the rest of the Device* tables — no export needed for a single investigation.',
        'Continuous/SIEM: Defender portal → Settings → Data export settings (Streaming API) → Add → forward selected event tables to an Azure Event Hub or Storage account. Requires Security Administrator at minimum.',
        'Programmatic/scripted pull: Microsoft Graph Security API POST /security/runHuntingQuery, requiring the ThreatHunting.Read.All permission.',
      ],
      command: 'DeviceProcessEvents | where Timestamp > ago(1d)',
      commandType: 'kql',
    },
    notes:
      '180 days of retention. Plan 2 is included with Microsoft 365 E5 and Microsoft 365 E5 Security, and available standalone. Plan 1, bundled into Microsoft 365 E3, covers antivirus and basic response actions like device isolation, but not the raw telemetry tables or KQL access the Defender-side queries throughout this catalog rely on.',
  },
  {
    id: 'defender-office365-hunting',
    name: 'Defender for Office 365 Advanced Hunting (EmailEvents, EmailAttachmentInfo)',
    priority: 'high',
    licenseRequirement: 'Defender for Office 365 Plan 2 — Plan 1 does not include Advanced Hunting',
    acquisition: {
      steps: [
        'Same portal, same mechanism as Defender for Endpoint Advanced Hunting above — Defender portal → Hunting → Advanced hunting, querying EmailEvents, EmailAttachmentInfo, EmailUrlInfo, and EmailPostDeliveryEvents instead of the Device* tables.',
        'Continuous/SIEM: same Data export settings (Streaming API) page, same Security Administrator requirement, just select the email-related tables when configuring the export.',
      ],
      command: 'EmailEvents | where Timestamp > ago(1d)',
      commandType: 'kql',
    },
    notes:
      "30 days of queryable retention. As of July 1, 2026, Plan 1 is bundled into Microsoft 365 E3 and Office 365 E3, covering Safe Links, Safe Attachments, anti-phishing, and real-time detections. Advanced Hunting and Threat Explorer remain Plan 2 only, included with Microsoft 365 E5.",
  },
  {
    id: 'cloud-app-events',
    name: 'Defender for Cloud Apps (CloudAppEvents)',
    priority: 'high',
    licenseRequirement: 'Included in Microsoft 365 E5 / E5 Security, or standalone',
    acquisition: {
      steps: [
        'Prerequisite before any of the below will return Office 365 data: Defender portal → Settings → Cloud apps → App connectors → Microsoft 365. Without this connector enabled, CloudAppEvents stays empty regardless of licensing.',
        'Once connected: same Advanced Hunting portal and Streaming API export mechanism as the other two Defender sources above — Defender portal → Hunting → Advanced hunting, querying CloudAppEvents directly.',
      ],
      command: 'CloudAppEvents | where Timestamp > ago(1d)',
      commandType: 'kql',
    },
    notes:
      'Must be connected via Defender portal → Settings → Cloud apps → App connectors before CloudAppEvents populates with Microsoft 365 activity — a connection gap that looks identical to an empty query result.',
  },
  {
    id: 'identity-protection-risk-data',
    name: 'Identity Protection Risk Data (RiskyUsers, UserRiskEvents)',
    priority: 'high',
    licenseRequirement: 'Requires Entra ID P2 specifically',
    acquisition: {
      steps: [
        'Quick/one-off: Entra admin center → Protection → Identity Protection → Risky users / Risk detections. View directly or download.',
        'Extended retention/SIEM: same Diagnostic settings blade as Sign-in/Audit Logs — select the RiskyUsers and UserRiskEvents categories (also RiskyServicePrincipals and ServicePrincipalRiskEvents if workload identity risk matters) → destination → Save. Requires Security Administrator.',
        'Programmatic: Microsoft Graph GET /identityProtection/riskyUsers and /identityProtection/riskDetections, requiring the IdentityRiskyUser.Read.All / IdentityRiskEvent.Read.All permissions.',
      ],
      command: 'GET https://graph.microsoft.com/v1.0/identityProtection/riskyUsers',
      commandType: 'graph-api',
    },
    notes:
      "Free and P1 tenants still surface risk detections, but only as a generic 'Additional risk detected' entry with no further detail. The underlying detection type and detail, and the riskyUsers Graph API itself, require P2.",
  },
  {
    id: 'intune-audit-logs',
    name: 'Intune Audit Logs',
    priority: 'high',
    licenseRequirement: 'Any Intune license — requires Diagnostic Settings',
    acquisition: {
      steps: [
        'Quick/one-off: Intune admin center → Tenant administration → Audit logs → Export. Produces a local .csv.',
        'Extended retention/SIEM: Intune admin center → Tenant administration → Diagnostic settings → route the AuditLogs category to a Storage account, Event Hub, or Log Analytics workspace. Requires the Intune Service Administrator Entra role, plus Log Analytics Contributor on the destination workspace if that\'s the target.',
        'Programmatic: Microsoft Graph GET /deviceManagement/auditEvents — covers roughly the same 2-year window the portal does.',
      ],
      command: 'GET https://graph.microsoft.com/v1.0/deviceManagement/auditEvents',
      commandType: 'graph-api',
    },
    notes:
      "Not gated behind Entra P1/P2 — this is Intune's own Diagnostic Settings, a separate licensing surface. Retained for 2 years in the Intune admin center by default and auto-deleted after that; route to a Log Analytics workspace, storage account, or Event Hub via Diagnostic Settings for longer retention.",
  },
  {
    id: 'azure-devops-audit-logs',
    name: 'Azure DevOps Audit Logs',
    priority: 'high',
    licenseRequirement: 'Entra ID-backed organization — must enable in Org Settings',
    acquisition: {
      steps: [
        "In the Azure DevOps organization itself, not the Azure portal: Organization Settings → Auditing. View and export directly. Requires the 'View audit log' organization-level permission (distinct from and narrower than 'Manage audit streams').",
        'Extended retention/SIEM: from the same Auditing page, add an audit stream to a Log Analytics workspace — events land in the AzureDevOpsAuditing table, typically within about 30 minutes.',
      ],
    },
    notes: 'Currently in public preview and off by default for every organization.',
  },
  {
    id: 'azure-activity-log',
    name: 'Azure Activity Log (AzureActivity)',
    priority: 'critical',
    licenseRequirement: 'Free, always generated — requires a Diagnostic Setting to reach a workspace',
    acquisition: {
      steps: [
        'Always-on at the platform level, no enablement step needed for the data to exist. Quick/one-off: Azure portal → Monitor → Activity log, or the Azure CLI.',
        'Extended retention/SIEM: Azure portal → Monitor → Activity log → Export Activity Logs (or a Diagnostic setting on the subscription itself) → route to a Log Analytics workspace, Storage account, or Event Hub.',
      ],
      command: 'az monitor activity-log list --start-time 2026-06-01T00:00:00Z --end-time 2026-06-30T00:00:00Z',
      commandType: 'azure-cli',
    },
    notes:
      'Generated at the platform level regardless of licensing, but nothing routes it into a queryable Sentinel/Log Analytics workspace until a Diagnostic Setting explicitly does so. An empty query result more often means missing routing than a clean environment.',
  },
  {
    id: 'nsg-flow-logs',
    name: 'NSG Flow Logs (deprecated — see notes)',
    priority: 'medium',
    licenseRequirement: 'Requires Network Watcher — consumption-based cost, not gated by M365/Entra licensing',
    acquisition: {
      steps: [
        'Azure portal → Network Watcher → Flow logs → select the NSG (or, for the current replacement, the VNet) → enable → choose a Storage account destination.',
        'Enable Traffic Analytics on the same blade for the processed, KQL-queryable version in a Log Analytics workspace — raw flow logs alone are JSON blobs in storage, not directly queryable without this step.',
      ],
    },
    notes:
      "Deprecated June 30, 2025 — no new ones can be created — scheduled for full retirement September 30, 2027. Microsoft's replacement is Virtual Network (VNet) Flow Logs; use that for any new deployment. Existing configurations and log data continue working until the retirement date.",
  },
  {
    id: 'managed-identity-signin-logs',
    name: 'Managed Identity Sign-in Logs (AADManagedIdentitySignInLogs)',
    priority: 'high',
    licenseRequirement: 'Requires Entra ID P1 or P2 — must enable via Diagnostic Settings',
    acquisition: {
      steps: [
        'Same Diagnostic settings blade as the other sign-in log categories — Entra admin center → Monitoring & health → Diagnostic settings → select the ManagedIdentitySignInLogs category specifically → destination → Save. Requires Security Administrator.',
      ],
    },
    notes: 'Same Diagnostic Settings / P1+P2 gate as Service Principal Sign-in Logs above.',
  },
  {
    id: 'adfs-signin-logs',
    name: 'AD FS Sign-in Logs (ADFSSignInLogs)',
    priority: 'medium',
    licenseRequirement: 'Requires Microsoft Entra Connect Health for AD FS — Entra ID P1 or P2',
    acquisition: {
      steps: [
        'Hard prerequisite, not optional configuration: the Microsoft Entra Connect Health agent for AD FS installed and current on every AD FS server. There is no alternative collection path without it.',
        'In the Connect Health blade (Entra admin center → Microsoft Entra Connect → Connect Health), enable the Log Analytics stream and select the ADFSSignIns option.',
        'Once enabled, query the ADFSSignInLogs table in the linked Log Analytics workspace — the same workspace Sign-in Logs can route to, so both can be correlated together in one place.',
        'Reports Reader is sufficient to view the resulting sign-ins report; enabling the stream itself needs a role with Connect Health configuration rights.',
      ],
      command: 'ADFSSignInLogs | where TimeGenerated > ago(1d)',
      commandType: 'kql',
    },
    notes:
      'Licensing scales with monitoring footprint: each additional registered health agent, across AD FS, Microsoft Entra Connect Sync, and AD DS roles combined, requires 25 more P1/P2 licenses.',
  },
]

export const logSources: LogSource[] = LogSourceListSchema.parse(rawLogSources)
