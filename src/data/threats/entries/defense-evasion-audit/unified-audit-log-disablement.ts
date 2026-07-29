import type { ThreatEntry } from '../../../../types/threat'

const entry: ThreatEntry = {
  id: 'unified-audit-log-disablement',
  title: 'Unified Audit Log (UAL) Disablement',
  domain: 'defense-evasion-audit',
  category: 'Defense Evasion',
  severity: 'critical',
  status: 'complete',
  shortDesc:
    'An attacker with sufficient privilege disables tenant-wide Unified Audit Logging, blinding SOC visibility into all subsequent Exchange, SharePoint, and Teams activity.',
  description:
    "The Unified Audit Log (UAL) is the backbone of M365 audit visibility. `Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $false` turns it off tenant-wide, meaning all subsequent user and admin actions across Exchange, SharePoint, OneDrive, and Teams stop being recorded — a broad defense-evasion move typically executed early in a high-privilege compromise specifically to blind investigators to everything that follows. Critically, the disablement command itself IS captured, but in the Entra ID/Exchange admin audit pipeline — a separate ingestion path from the UAL it's disabling — so it survives, but only if someone is actively watching for that specific event, since the very thing that would normally surface it during routine review is what's being blinded.",

  forensicArtifacts: [
    {
      source: 'AuditLogs (admin pipeline, separate from the UAL itself)',
      artifact: "OperationName == 'Set-AdminAuditLogConfig' with UnifiedAuditLogIngestionEnabled set to False",
    },
    {
      source: 'OfficeActivity',
      artifact: 'An abrupt, complete cessation of all OfficeActivity events tenant-wide from a specific timestamp onward — the absence of data is itself the artifact',
    },
    {
      source: 'Exchange Online PowerShell — Get-AdminAuditLogConfig',
      artifact: 'Get-AdminAuditLogConfig | Format-List UnifiedAuditLogIngestionEnabled showing False when queried live, if the attacker has not yet re-enabled it to cover their tracks — must be run in Exchange Online PowerShell specifically, not Security & Compliance PowerShell, where this property always reads False regardless of actual state',
    },
    {
      source: 'Exchange Online PowerShell — Search-UnifiedAuditLog',
      artifact:
        'Search-UnifiedAuditLog -Operations Set-AdminAuditLogConfig finds this specific event directly, per Microsoft\'s own documented method, and returns who made the change and the source IP — the historical counterpart to the live-status check above',
    },
    {
      source: 'Entra ID SigninLogs',
      artifact: 'The admin session (interactive, PowerShell, or Graph) that issued the disablement command — identify account, IP, and whether privileged-role MFA was enforced',
    },
    {
      source: 'Downstream SIEM ingestion (if UAL feeds an external system via the Management Activity API)',
      artifact: 'A corresponding ingestion gap — often the first place this is actually noticed, since internal M365 audit search goes quiet too',
    },
  ],

  telemetry: {
    correlationMarkers: [
      "The disablement and any subsequent re-enablement — attackers sometimes flip it back on briefly to avoid 'audit log disabled for N days' alerting — both land in the same separate audit pipeline. Search for both events bracketing the OfficeActivity gap.",
      "Actor's role at time of action: this requires Exchange Administrator or Global Administrator — cross-reference the account's PIM activation history if the privilege itself was only recently obtained.",
      'OfficeActivity coverage gap: rather than searching FOR an event, search for the boundary where events STOP — bin event counts hourly and look for a cliff-edge drop to zero.',
    ],
  },

  mitre: [{ id: 'T1562.008', name: 'Impair Defenses: Disable Cloud Logs', tactic: 'Defense Evasion' }],

  kql: {
    sentinel: {
      triage: {
        title: 'UAL disablement command',
        description: 'Captured in the admin audit pipeline, separate from the Unified Audit Log it turns off.',
        query: `AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName == "Set-AdminAuditLogConfig"
| where TargetResources has "UnifiedAuditLogIngestionEnabled"
| project TimeGenerated, InitiatedBy, OperationName, TargetResources, Result, CorrelationId
| order by TimeGenerated desc`,
      },
      investigate: {
        title: 'OfficeActivity volume cliff-edge',
        description:
          'Corroborating evidence independent of whether the Set-AdminAuditLogConfig event was captured — useful belt-and-suspenders in case that pipeline was also tampered with or predates your retention window.',
        query: `OfficeActivity
| where TimeGenerated > ago(30d)
| summarize EventCount = count() by bin(TimeGenerated, 1h)
| order by TimeGenerated asc
| serialize
| extend PriorHourCount = prev(EventCount, 1)
| where PriorHourCount > 50 and EventCount == 0  // tune "50" to your tenant's normal hourly floor`,
      },
    },
    defender: {
      triage: {
        title: 'UAL disablement command',
        query: `CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType == "Set-AdminAuditLogConfig"
| project Timestamp, AccountDisplayName, ActionType, IPAddress, RawEventData
| order by Timestamp desc`,
      },
    },
  },

  runbook: {
    triage: [
      'Confirm current UAL status immediately: `Get-AdminAuditLogConfig | Select UnifiedAuditLogIngestionEnabled` — if false, this is an active, ongoing gap, not just historical.',
      'Identify exactly when it was disabled, via the admin-pipeline event or by finding the OfficeActivity cliff-edge if that event itself is unavailable.',
      'Identify the acting account and how it obtained the necessary privilege — standing Exchange/Global Admin, or a recent PIM activation.',
      'Check whether it has been re-enabled and disabled again multiple times, suggesting deliberate evasion of duration-based alerting.',
    ],
    contain: [
      'Re-enable the Unified Audit Log immediately: `Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true`. Per Microsoft\'s own documentation this can take up to 60 minutes to propagate — don\'t conclude re-enablement failed if OfficeActivity doesn\'t resume within minutes.',
      'Treat the acting account as compromised pending investigation — suspend it and revoke sessions.',
      "Review and restrict which roles can toggle this setting if not already tightly scoped — this should be a rare, change-controlled operation.",
      'Stand up a high-priority alert for this specific operation going forward — silence after a first occurrence is exactly what allows repeat abuse.',
    ],
    investigate: [
      'Treat the entire disabled window as an intelligence blind spot — pull whatever can still be reconstructed from adjacent sources: Microsoft Graph Activity Logs, Defender for Endpoint telemetry, message trace (separate retention from UAL), and Azure Activity Logs.',
      'Determine what else the acting account/session did in the surrounding window using logging that was NOT disabled — SigninLogs and core AuditLogs are separate pipelines and remain intact.',
      'Assume the disablement was purposeful cover for other malicious activity, and actively hunt for common follow-on actions elsewhere in this matrix that would otherwise have been visible in the missing UAL data.',
      'Check whether any external SIEM ingesting the Management Activity API has an independent copy of data from just before the gap that can partially backfill it.',
      "Be aware of your tenant's actual UAL retention when scoping how far back you can pull corroborating data even outside the disabled window — 180 days on standard E3/Business Premium licensing, 365 days on E5, extendable to 10 years only with Audit (Premium) retention policies specifically configured.",
    ],
    recover: [
      'Confirm UAL ingestion is stable and re-enabled, and validate with a test action that it is actually capturing events again.',
      'Implement a standing, high-priority alert specifically for Set-AdminAuditLogConfig and similar disable-logging operations across the estate.',
      'Review and reduce the population of accounts/roles capable of disabling tenant-wide audit logging.',
      "Consider forwarding UAL/Management Activity API data to an independent, attacker-inaccessible destination, so even a fully compromised M365 admin can't retroactively erase the trail.",
    ],
  },
}

export default entry
