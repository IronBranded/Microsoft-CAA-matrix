import type { ThreatEntry } from '../../../../types/threat'

const entry: ThreatEntry = {
  id: 'administrative-unit-boundary-evasion',
  title: 'Administrative Unit (AU) Boundary Evasion',
  domain: 'access-control-escalation',
  category: 'Privilege Escalation',
  severity: 'medium',
  status: 'complete',
  shortDesc: 'Exploiting unrestricted or misconfigured Administrative Unit scoping to pivot administrative access across boundaries it was meant to contain.',
  description:
    'Administrative Units are designed to scope delegated admin roles to a subset of users or devices. Misconfigured AU membership rules, restricted-management settings, or delegated roles granted at the tenant level instead of AU level can let an attacker with seemingly-scoped administrative rights reach objects and settings well outside the intended boundary.',

  forensicArtifacts: [
    {
      source: 'Entra ID AuditLogs',
      artifact: "Administrative Unit membership rule changes (for dynamic AUs) or direct membership additions (static AUs) that expand which objects fall under a delegated admin's scope",
    },
    {
      source: 'Entra ID AuditLogs',
      artifact: "Changes to an AU's restricted-management setting — restricted AUs have stronger isolation guarantees, and disabling this weakens the boundary",
    },
    {
      source: 'Entra ID Administrative Units',
      artifact: "The actual scoped role assignments within an AU compared to what the delegated admin is supposed to manage — scope creep here often accumulates gradually",
    },
    {
      source: 'Entra ID AuditLogs',
      artifact: "A scoped admin's actions on objects outside their AU's boundary succeeding when they should have been denied — the practical symptom of a boundary gap being exploited",
    },
    {
      source: 'Entra ID AuditLogs',
      artifact: 'Dynamic AU membership rule syntax — an overly broad rule accomplishes the same boundary expansion as a direct membership change but is easier to overlook',
    },
  ],

  telemetry: {
    correlationMarkers: [
      'Dynamic AU membership rules are declarative and can silently expand scope as new objects are created that happen to match the rule — review rule logic itself, not just a point-in-time membership snapshot.',
      "A scoped admin role's real reach is the intersection of the role's inherent permissions and the AU's membership — a change to either side changes effective scope.",
      'Restricted management AUs are meaningfully more isolated than standard ones — confirm which type is in use before assuming a given AU provides strong isolation.',
    ],
  },

  mitre: [{ id: 'T1484', name: 'Domain or Tenant Policy Modification', tactic: 'Privilege Escalation' }],

  kql: {
    sentinel: {
      triage: {
        title: 'Administrative Unit configuration changes',
        query: `AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName has_any ("administrative unit", "Administrative Unit")
| project TimeGenerated, InitiatedBy, OperationName, TargetResources, Result
| order by TimeGenerated desc`,
      },
      investigate: {
        title: 'Scoped-admin actions for review against AU boundary',
        query: `AuditLogs
| where TimeGenerated > ago(30d)
| where InitiatedBy has "<scoped admin UPN under investigation>"
| project TimeGenerated, OperationName, TargetResources, Result
| order by TimeGenerated desc`,
      },
    },
    defender: {
      triage: {
        title: 'Administrative Unit activity',
        query: `CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType has "administrative unit"
| project Timestamp, AccountDisplayName, ActionType, RawEventData
| order by Timestamp desc`,
      },
    },
  },

  runbook: {
    triage: [
      "Review the AU's current membership (static or dynamic rule) against its originally intended scope.",
      'Check whether it is configured as restricted-management.',
      'Identify any recent changes to membership or role assignments within it.',
    ],
    contain: [
      'Revert unauthorized membership/rule changes.',
      'Remove any role assignment that exceeds intended scope.',
      'Revoke sessions for the scoped admin if their access was itself misused.',
    ],
    investigate: [
      'Determine what the scoped admin did with expanded access.',
      'Check whether the boundary expansion was deliberate tampering or gradual, unnoticed scope creep.',
      'Review other AUs for the same pattern.',
    ],
    recover: [
      'Use restricted-management AUs for genuinely sensitive delegation boundaries.',
      'Periodically review AU membership, both static and dynamic rule logic, against intended scope.',
      'Alert on AU configuration changes as a standing detection.',
    ],
  },
}

export default entry
