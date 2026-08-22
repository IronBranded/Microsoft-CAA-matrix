import type { ThreatEntry } from '../../../../types/threat'

const entry: ThreatEntry = {
  id: 'app-governance-policy-gap',
  title: 'App Governance Policy Gap',
  domain: 'app-workload-identity',
  category: 'Defense Evasion',
  severity: 'low',
  status: 'complete',
  shortDesc: 'The absence of continuous, automated monitoring on application behavior and permission scope, letting over-permissioned or anomalous apps persist undetected.',
  description:
    'Many of the other scenarios in this domain — malicious registrations, credential injection, privilege escalation via app permissions — are most dangerous specifically where no ongoing governance process exists to catch them. Without continuous monitoring for anomalous app behavior or newly-granted high-risk permissions, a tenant relies entirely on point-in-time reviews that miss activity between them. Unlike most entries in this matrix, this one describes a control gap rather than a specific attacker action — there is no single event to hunt for, which is why its detection section below is thinner and more posture-focused than most.',

  forensicArtifacts: [
    {
      source: 'Microsoft Defender for Cloud Apps app governance',
      artifact: 'Whether the app governance add-on is licensed and actively configured — its absence is the finding for this entry, not a specific log event',
    },
    {
      source: 'Entra ID App registrations',
      artifact: 'The total count and permission scope of registered applications compared against any active monitoring/alerting coverage',
    },
    {
      source: 'Historical incident review',
      artifact: 'Whether any of the other app-related scenarios in this domain went undetected for an extended period specifically because no continuous monitoring existed — the clearest evidence this gap has real consequences',
    },
    {
      source: 'Organizational policy documentation',
      artifact: 'Whether a formal app registration/consent policy exists at all, versus relying purely on default tenant settings',
    },
    {
      source: 'Entra ID enterprise application consent settings',
      artifact: 'Default user consent settings — whether users can consent to apps requesting any permission level without administrative review, which compounds the impact of a governance gap',
    },
  ],

  telemetry: {
    correlationMarkers: [
      'This entry describes an absence of capability rather than a detectable event — assessment here is a one-time or periodic posture review, not a KQL hunt for a specific indicator.',
      'The real cost of this gap only becomes visible in retrospect, when another scenario in this domain goes undetected longer than it should have specifically because no continuous monitoring existed.',
      'User consent settings and app governance tooling are complementary — tightening one without the other leaves a partial gap.',
      'The Advanced Hunting proxy below depends on a specific connector, not just a Defender license: Defender for Cloud Apps > App connectors > Microsoft 365 activities has to be enabled, or CloudAppEvents holds no Office 365 audit data regardless of licensing.',
      'There is deliberately no relevantErrorCodes entry for this scenario, consistent with its posture-gap framing above: there is no attacker action to fail or succeed, only an absence of governance capacity to measure.',
    ],
  },

  kql: {
    sentinel: {
      triage: {
        title: 'Application-related audit activity volume (posture proxy)',
        description:
          'This entry describes a governance gap, not a specific attacker action — there is no single event to hunt for. This query sizes how much application-related activity is being reviewed via AuditLogs, as a rough proxy; comparing that against your actual total app registration count, retrieved via Microsoft Graph directly rather than KQL, is what actually reveals the gap.',
        query: `AuditLogs
| where TimeGenerated > ago(90d)
| where Category == "ApplicationManagement"
| summarize EventCount = count(), DistinctApps = dcount(tostring(TargetResources[0].id))`,
      },
    },
    defender: {
      triage: {
        title: 'Application-governance activity volume via CloudAppEvents (posture proxy)',
        description:
          "Advanced Hunting equivalent of the Sentinel proxy — same posture-review intent, not a detection. CloudAppEvents only carries Office 365 audit data (including app-consent and service-principal-credential events) when the Microsoft 365 activities connector is enabled under Defender for Cloud Apps; an empty result here more often means the connector is off than that no activity occurred. ActionType strings are matched loosely with has_any rather than pinned to exact literal text — Microsoft's own published examples for this table are inconsistent even in casing/spacing, so treat any exact-string match as something to verify against your tenant's actual data rather than trust outright.",
        query: `CloudAppEvents
| where Timestamp > ago(90d)
| where Application == "Office 365"
| where ActionType has_any ("consent", "service principal", "application", "certificate")
| summarize EventCount = count() by ActionType
| order by EventCount desc`,
      },
    },
  },

  runbook: {
    triage: [
      'Assess current app governance tooling licensing/configuration status.',
      'Inventory current app registration count and growth rate over time.',
      'Review whether any past incident in this domain went undetected longer than expected due to this gap.',
    ],
    contain: [
      'Not applicable in the traditional incident-response sense, since this is a posture gap rather than an active incident — prioritize closing the gap directly.',
    ],
    investigate: [
      'Review historical AuditLogs coverage of app-related events to gauge how much visibility currently exists.',
      'Identify which of the other scenarios in this domain the organization would currently be blind to.',
    ],
    recover: [
      'License and configure Microsoft Defender for Cloud Apps app governance, or equivalent tooling.',
      'Establish continuous automated monitoring for the patterns described in Malicious App Registration, Suspicious Credential Addition, and Service Principal Privilege Escalation elsewhere in this domain.',
      'Formalize a recurring app registration review cadence independent of any specific tooling.',
    ],
  },
}

export default entry
