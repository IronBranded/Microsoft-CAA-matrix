import type { ThreatEntry } from '../../../../types/threat'

const entry: ThreatEntry = {
  id: 'entra-private-access-app-proxy-tunneling',
  title: 'Entra Private Access / App Proxy Tunneling',
  domain: 'persistence-pivoting',
  category: 'Persistence / Command and Control',
  severity: 'high',
  status: 'complete',
  shortDesc: 'Misusing Private Access connectors or Application Proxy connector agents as a persistent reverse-proxy tunnel into the on-prem network.',
  description:
    'Application Proxy and Entra Private Access connectors are deliberately designed to let cloud-authenticated traffic reach on-prem resources without opening inbound firewall ports. An attacker who can register their own connector, or repurpose an existing one, gains an outbound-initiated, cloud-mediated tunnel directly into the internal network that blends in with normal remote-access traffic.',

  forensicArtifacts: [
    {
      source: 'Entra ID Application Proxy / Private Access',
      artifact: 'An unfamiliar or unexpectedly-registered connector — similar in principle to a rogue PTA agent, a new connector extends whoever controls it a path into the internal network',
    },
    {
      logSourceId: 'entra-audit-logs',
      source: 'Entra ID AuditLogs',
      artifact: 'Connector registration events and the identity that performed them — requires sufficient Application Administrator-equivalent privilege',
    },
    {
      source: 'Connector host — network telemetry',
      artifact: "The connector's own outbound connections to Entra ID's relay service, and separately, unusual traffic patterns on the connector host that don't match its expected narrow proxying role",
    },
    {
      source: 'Entra ID Private Access application/segment configuration',
      artifact: 'The specific internal targets each Private Access app or segment is scoped to reach — an overly broad segment defeats the purpose of a segmented, least-privilege remote access model',
    },
    {
      source: 'Entra ID SigninLogs / AuditLogs',
      artifact: 'Access patterns through the proxy/connector reaching internal targets outside its documented intended scope',
    },
  ],

  telemetry: {
    correlationMarkers: [
      'A connector is a durable piece of infrastructure, not a one-time event — treat its continued presence and health status as an ongoing thing to monitor, not just its initial registration.',
      'Connectors are outbound-initiated by design, which is exactly what makes a rogue one hard to spot at the network perimeter — it looks like normal egress traffic to a Microsoft service, not inbound access.',
      'Compare the actual internal targets being reached through Private Access/App Proxy against the documented, intended scope for each published app or segment — scope creep here is the practical version of this technique.',
    ],
  },

  mitre: [
    { id: 'T1090', name: 'Proxy', tactic: 'Command and Control' },
    { id: 'T1133', name: 'External Remote Services', tactic: 'Initial Access' },
  ],

  kql: {
    sentinel: {
      triage: {
        title: 'Connector registration events',
        query: `AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName has_any ("connector", "Application Proxy", "Private Access")
| where OperationName has_any ("Add", "Register", "Create")
| project TimeGenerated, InitiatedBy, TargetResources, Result
| order by TimeGenerated desc`,
      },
      investigate: {
        title: 'Access through App Proxy / Private Access apps',
        description: 'For review against documented intended scope per application.',
        query: `SigninLogs
| where TimeGenerated > ago(14d)
| where ResultType == "0"
| where AppDisplayName has_any ("App Proxy", "Private Access") or ResourceDisplayName has_any ("App Proxy", "Private Access")
| project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName, ResourceDisplayName
| order by TimeGenerated desc`,
      },
    },
    defender: {
      triage: {
        title: 'Connector / App Proxy activity',
        query: `CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType has_any ("connector", "Application Proxy")
| project Timestamp, AccountDisplayName, ActionType, RawEventData
| order by Timestamp desc`,
      },
    },
  },

  runbook: {
    triage: [
      'Enumerate all registered connectors and confirm each against expected inventory.',
      'Identify who registered any unfamiliar connector.',
      'Review the actual internal targets reachable through each published app/segment.',
      'Check connector health status for anything recently added or recently changed.',
    ],
    contain: [
      'Disable or remove the rogue connector immediately.',
      'Isolate its host at the network layer, since this implies a compromised or attacker-controlled system.',
      'Revoke sessions established through it.',
      'Temporarily narrow or disable affected Private Access apps/segments while investigating.',
    ],
    investigate: [
      'Determine what internal resources were reached through the tunnel.',
      'Check the connector host for separate signs of compromise if it is a legitimate host that was repurposed.',
      'Review who registered it and how they obtained sufficient privilege.',
      'Establish the full timeline of internal access gained through the tunnel.',
    ],
    recover: [
      'Restrict who can register connectors and publish Private Access/App Proxy apps.',
      'Scope every published app/segment as narrowly as possible rather than broad internal network ranges.',
      'Monitor connector health and registration as a standing detection.',
      'Periodically audit actual traffic against documented intended scope per app.',
    ],
  },
}

export default entry
