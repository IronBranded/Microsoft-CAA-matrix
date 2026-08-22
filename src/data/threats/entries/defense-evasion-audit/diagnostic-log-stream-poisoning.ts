import type { ThreatEntry } from '../../../../types/threat'

const entry: ThreatEntry = {
  id: 'diagnostic-log-stream-poisoning',
  title: 'Diagnostic Log Stream Poisoning',
  domain: 'defense-evasion-audit',
  category: 'Defense Evasion',
  severity: 'critical',
  status: 'complete',
  shortDesc:
    'Removing or modifying Entra ID or Azure Resource Diagnostic Settings that forward logs to Log Analytics or Sentinel, cutting off detection at the source rather than after ingestion.',
  description:
    "Rather than disabling logging at the source system, this technique targets the diagnostic settings that route logs onward to a SIEM — deleting or narrowing the categories forwarded from Entra ID, or removing a resource's diagnostic setting sending logs to a Log Analytics workspace. The source system may keep logging normally, but the SOC's actual visibility goes dark, a subtler and sometimes longer-lived blind spot than disabling logging outright.",

  forensicArtifacts: [
    {
      logSourceId: 'azure-activity-log',
      source: 'AzureActivity',
      artifact: "Microsoft.Insights/diagnosticSettings write or delete operations against a resource's diagnostic settings — removing or narrowing which log categories get forwarded to a Log Analytics workspace, Event Hub, or Storage account",
    },
    {
      logSourceId: 'azure-activity-log',
      source: 'AzureActivity',
      artifact:
        "For Entra ID's own tenant-level diagnostic settings specifically — the configuration forwarding SigninLogs/AuditLogs into Sentinel — these live under a separate resource provider, microsoft.aadiam/diagnosticSettings, distinct from the Microsoft.Insights provider general Azure resources use. Changes here are logged as a control-plane action distinct from the data-plane logs being forwarded, similar in spirit to the Unified Audit Log's own separate admin pipeline. A KQL query written only against Microsoft.Insights/diagnosticSettings will miss this provider entirely — see the triage query below.",
    },
    {
      source: 'Sentinel / Log Analytics workspace',
      artifact: 'A sudden drop in ingested volume for a specific table without a corresponding drop in actual tenant activity — the absence of data is itself the artifact, the same pattern as Unified Audit Log Disablement',
    },
    {
      source: 'Log Analytics workspace configuration',
      artifact: 'Changes to data collection rules (DCRs) or their associations, the newer mechanism some log types route through as an alternative or companion to classic diagnostic settings',
    },
    {
      source: 'Azure Policy / Resource Graph posture query',
      artifact: "Point-in-time comparison of every resource's diagnostic settings against a known-good baseline — since there's no single disablement event to catch across an entire estate, periodic posture comparison is a necessary complement to alerting on individual change events",
    },
  ],

  telemetry: {
    correlationMarkers: [
      "Diagnostic settings changes are scoped per-resource — an attacker doesn't need to find and disable one central switch, they can quietly narrow logging on just the specific resource(s) relevant to whatever they're about to do next, which is both more targeted and easier to miss than a tenant-wide toggle.",
      "Removing a diagnostic setting doesn't delete already-ingested data, only stops future ingestion — the gap starts exactly at the change and continues until someone notices and fixes it.",
      'Cross-reference the timing of any diagnostic settings change against other suspicious activity on the SAME resource — this technique is rarely the end goal, it\'s cover for something else happening on that resource right after.',
      'There is deliberately no relevantErrorCodes entry for this scenario: removing or narrowing a diagnostic setting with sufficient rights succeeds cleanly. The change event itself, and the ingestion gap it opens, are the only signal.',
    ],
  },

  mitre: [{ id: 'T1562.008', name: 'Impair Defenses: Disable Cloud Logs', tactic: 'Defense Evasion' }],

  kql: {
    sentinel: {
      triage: {
        title: 'Diagnostic settings removed or narrowed',
        description:
          'Covers both providers: Microsoft.Insights for general Azure resources, and microsoft.aadiam for Entra ID\'s own tenant-level diagnostic settings specifically — a query checking only the former misses Entra ID changes entirely.',
        query: `AzureActivity
| where TimeGenerated > ago(30d)
| where OperationNameValue in (
    "MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/WRITE",
    "MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/DELETE",
    "MICROSOFT.AADIAM/DIAGNOSTICSETTINGS/WRITE",
    "MICROSOFT.AADIAM/DIAGNOSTICSETTINGS/DELETE"
)
| project TimeGenerated, Caller, CallerIpAddress, ResourceGroup, Resource, ActivityStatusValue, CorrelationId
| order by TimeGenerated desc`,
      },
      investigate: {
        title: 'Volume cliff-edge across core tables',
        description:
          'Corroborating evidence independent of catching the change event itself — the same pattern used for Unified Audit Log Disablement, but relevant to any log stream this technique might target.',
        query: `union SigninLogs, AuditLogs, OfficeActivity, AzureActivity
| where TimeGenerated > ago(30d)
| summarize EventCount = count() by bin(TimeGenerated, 1h), Type
| order by TimeGenerated asc`,
      },
    },
    defender: {
      triage: {
        title: 'Diagnostic settings activity',
        query: `CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType has "diagnosticSettings"
| project Timestamp, AccountDisplayName, ActionType, IPAddress, RawEventData
| order by Timestamp desc`,
      },
    },
  },

  runbook: {
    triage: [
      'Confirm current diagnostic settings state for the resource(s) in question against your documented baseline.',
      'Identify exactly when the change was made and by whom.',
      'Determine which specific log categories were removed or narrowed — a full removal is more alarming than dropping one verbose category while keeping security-relevant ones.',
      "Check what else that same identity or resource was involved in around the same time — this is rarely the attacker's actual objective.",
    ],
    contain: [
      'Restore the diagnostic settings to their intended configuration immediately.',
      'Treat the acting identity as compromised pending investigation, and revoke its sessions/credentials.',
      'Review diagnostic settings across every resource the same identity had access to, not just the one first noticed.',
      'Restrict who can modify diagnostic settings tenant-wide via Azure RBAC — a scoped Monitoring Contributor-style role rather than broad Contributor.',
    ],
    investigate: [
      "Treat the affected window as a genuine intelligence gap for that specific resource, and lean on whatever adjacent telemetry wasn't affected to reconstruct activity.",
      'Determine what happened on the affected resource during the gap that the attacker may have been trying to hide.',
      'Check whether this is an isolated action or part of a broader pattern — see also Unified Audit Log Disablement and Defender/Purview Collector Suppression elsewhere in this domain, frequently used together.',
      'Review change history for the Log Analytics workspace and its data collection rules as well, in case the narrowing happened there instead of at the resource\'s diagnostic settings.',
    ],
    recover: [
      'Implement the AzureActivity-based alert above as a standing detection across the estate, not a one-off hunt.',
      "Periodically run a posture comparison of every resource's diagnostic settings against a known-good baseline, to catch drift that individual event alerting might miss.",
      'Consider Azure Policy with a deny or deploy-if-not-exists effect to prevent diagnostic settings from being removed, or to automatically re-create them if they are.',
      "Forward diagnostic settings themselves to an independent, less-easily-reachable destination where feasible, so even a compromised resource-level admin can't fully erase the trail.",
    ],
  },
}

export default entry
