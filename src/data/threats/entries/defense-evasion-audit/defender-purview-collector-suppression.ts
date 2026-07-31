import type { ThreatEntry } from '../../../../types/threat'

const entry: ThreatEntry = {
  id: 'defender-purview-collector-suppression',
  title: 'Microsoft Defender / Purview Collector Suppression',
  domain: 'defense-evasion-audit',
  category: 'Defense Evasion',
  severity: 'high',
  status: 'complete',
  shortDesc: 'Silencing security agents, Defender for Cloud Apps log collectors, or API-based integrations specifically during an active intrusion, to prevent real-time detection of what\'s happening.',
  description:
    'Beyond turning off logging pipelines wholesale, a more targeted approach disables or reconfigures the specific collectors and connectors an attacker knows are watching the activity they are about to perform — pausing a Defender for Cloud Apps API connector, disabling a Defender for Endpoint sensor on a specific host, or revoking a security tool\'s own service principal permissions. This is typically a narrow, deliberate action taken immediately before a specific high-risk step, rather than a broad, tenant-wide blackout that would itself draw attention.',

  forensicArtifacts: [
    {
      source: 'Entra ID AuditLogs / AzureActivity',
      artifact: "Changes to a security connector's configuration or health status — for Defender for Cloud Apps, app connector authorization changes; for Sentinel-side data connectors, changes to their enabled/connected state",
    },
    {
      source: 'Entra ID AuditLogs',
      artifact: "Revocation or modification of a security tool's own service principal permissions — many integrations run as an app registration with its own Graph/API permissions, which can itself be tampered with",
    },
    {
      source: 'Microsoft Defender XDR — AlertInfo (Tamper Protection)',
      artifact:
        "Defender for Endpoint's built-in tamper protection raises alerts with specific, documented titles rather than a generic health warning — Attempt to stop Microsoft Defender for Endpoint sensor, Attempt to bypass Microsoft Defender for Endpoint client protection, Attempt to tamper with Microsoft Defender on multiple devices, and Attempt to turn off Microsoft Defender Antivirus protection are the titles to alert on directly, per Microsoft's own tamper-resiliency documentation",
    },
    {
      source: 'Microsoft Purview — DLP policy health / Insider Risk Management',
      artifact:
        "A DLP policy silently moved to 'test mode' (or 'test with notifications', still not actually blocking anything) rather than being deleted outright — a subtler suppression than removing the policy, since the policy still appears to exist and be assigned when briefly reviewed, but no longer actually enforces. Insider Risk Management policies have an equivalent scoped-condition change worth the same scrutiny: narrowing which users/groups a policy actually watches is functionally the same suppression as disabling it, without the policy's own existence ever changing.",
    },
    {
      source: 'Defender for Endpoint / Defender for Cloud Apps admin console',
      artifact:
        'Sensor/agent health status showing an unexpected offline or degraded state for specific hosts or connectors, rather than a broad platform-wide outage — this reactive health check matters as a backstop precisely because a bypass technique tamper protection does not specifically recognize will not raise any of the named alerts above',
    },
    {
      source: 'AzureActivity',
      artifact: 'Changes to Microsoft Sentinel data connector configuration specifically, since Sentinel itself is a resource whose connectors can be individually disabled',
    },
    {
      source: 'Change/maintenance records',
      artifact: 'Whether any disablement corresponds to a documented, approved maintenance window — the same principle used for Unified Audit Log Disablement and Diagnostic Log Stream Poisoning elsewhere in this domain',
    },
  ],

  telemetry: {
    correlationMarkers: [
      'This is closely related to Unified Audit Log Disablement and Diagnostic Log Stream Poisoning elsewhere in this domain — all three share the same underlying pattern but target different components; check all three when investigating any one.',
      'Suppression is often narrow and targeted — one sensor, one connector — specifically to avoid the kind of obvious, tenant-wide outage that would draw immediate attention.',
      'Cross-reference the timing of any suppression against other suspicious activity on the same host/resource — like the other defense-evasion entries in this domain, this is cover for something else, not usually the end goal itself.',
    ],
  },

  mitre: [{ id: 'T1562.001', name: 'Impair Defenses: Disable or Modify Tools', tactic: 'Defense Evasion' }],

  kql: {
    sentinel: {
      triage: {
        title: 'Sentinel data connector configuration changes',
        query: `AzureActivity
| where TimeGenerated > ago(30d)
| where ResourceProviderValue has "SecurityInsights" or OperationNameValue has "dataConnectors"
| project TimeGenerated, Caller, CallerIpAddress, ResourceGroup, Resource, OperationNameValue
| order by TimeGenerated desc`,
      },
      investigate: {
        title: 'Security tool service principal permission changes',
        description: 'Many integrations run as their own app registration.',
        query: `AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName has_any ("Remove app role assignment", "Update application")
| where TargetResources has_any ("Sentinel", "Defender", "Security")
| project TimeGenerated, InitiatedBy, TargetResources, OperationName
| order by TimeGenerated desc`,
      },
    },
    defender: {
      triage: {
        title: 'Connector / app authorization activity',
        query: `CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType has_any ("connector", "app authorization")
| project Timestamp, AccountDisplayName, ActionType, RawEventData
| order by Timestamp desc`,
      },
      investigate: {
        title: 'Documented Defender tamper-protection alerts',
        description:
          "Queries AlertInfo directly for the specific, named alert titles Microsoft's own tamper-resiliency documentation lists — a more precise signal than general sensor health status, since these fire specifically when a known tampering technique is attempted.",
        query: `AlertInfo
| where Timestamp > ago(30d)
| where Title has_any (
    "Attempt to stop Microsoft Defender for Endpoint sensor",
    "Attempt to bypass Microsoft Defender for Endpoint client protection",
    "Attempt to tamper with Microsoft Defender on multiple devices",
    "Attempt to turn off Microsoft Defender Antivirus protection"
)
| project Timestamp, AlertId, Title, Severity, Category
| order by Timestamp desc`,
      },
    },
  },

  runbook: {
    triage: [
      'Identify which specific sensor/connector/integration was affected and when.',
      'Confirm whether it corresponds to a documented maintenance window.',
      'Check what else was happening on the same host/resource around the same time.',
      'Determine the acting identity and their normal responsibility for that integration.',
    ],
    contain: [
      'Restore the affected sensor/connector/integration immediately.',
      'Revoke sessions for the acting identity if the change looks unauthorized.',
      'Review other security tool integrations for similar tampering.',
      'Treat the resource/host the suppression targeted as higher-priority for investigation.',
    ],
    investigate: [
      "Treat the affected coverage gap as a blind spot and lean on whatever adjacent telemetry wasn't affected.",
      'Determine what happened during the gap that the attacker may have been trying to hide.',
      'Cross-reference with Unified Audit Log Disablement and Diagnostic Log Stream Poisoning elsewhere in this domain.',
      'Check whether multiple security tools were suppressed together, suggesting a coordinated effort.',
    ],
    recover: [
      'Restrict who can modify security tool configurations and connector health.',
      'Implement independent health monitoring for security sensors/connectors that alerts on unexpected state changes.',
      'Treat any disablement of security tooling as a high-priority event requiring immediate justification.',
      'Periodically verify that all expected sensors/connectors are actually online and reporting, not just configured.',
    ],
  },
}

export default entry
