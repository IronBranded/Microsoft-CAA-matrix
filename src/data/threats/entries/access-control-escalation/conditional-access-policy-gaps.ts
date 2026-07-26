import type { ThreatEntry } from '../../../../types/threat'

const entry: ThreatEntry = {
  id: 'conditional-access-policy-gaps',
  title: 'Conditional Access Policy Gaps',
  domain: 'access-control-escalation',
  category: 'Defense Evasion',
  severity: 'high',
  status: 'complete',
  shortDesc: 'Misconfigurations, excluded user groups, or legacy protocol exceptions that leave a hole in otherwise-comprehensive Conditional Access coverage.',
  description:
    "Conditional Access policies are only as strong as their weakest scoping decision. Common gaps include break-glass accounts excluded from every policy and never revisited, legacy authentication exceptions kept temporarily for a stubborn app, or a pilot group exclusion that was never removed after the pilot ended. Attackers who reconnoiter a tenant's policy set can route around coverage entirely rather than trying to defeat it.",

  forensicArtifacts: [
    {
      source: 'Entra ID AuditLogs',
      artifact: "OperationName == 'Update conditional access policy' with a change narrowing scope, adding an exclusion, or reducing enforcement (e.g. moving to report-only)",
    },
    {
      source: 'Entra ID SigninLogs (break-glass / emergency-access accounts)',
      artifact: 'Any sign-in activity for accounts specifically provisioned as CA-policy-excluded break-glass accounts, outside a documented emergency',
    },
    {
      source: 'Conditional Access "What If" tool / posture review',
      artifact: 'Periodic review of which users/groups/apps are currently excluded from each policy — not an event, but a state worth checking regularly since gaps often predate any single detectable action',
    },
    {
      source: 'Entra ID SigninLogs',
      artifact: 'A sign-in that completed without MFA or device compliance for a user/app combination that should be covered by an existing policy — the practical symptom of a gap being actively exploited',
    },
    {
      source: 'Entra ID AuditLogs',
      artifact: 'The identity making CA policy changes and whether that activity fits their normal administrative pattern',
    },
  ],

  telemetry: {
    correlationMarkers: [
      'Break-glass accounts are, by design, excluded from Conditional Access — any sign-in for one is inherently notable and should be rare and well-documented, not routine.',
      "A policy set to report-only mode provides zero actual protection despite appearing configured — confirm the policy's enabled state, not just that it exists.",
      'Compare the current exclusion list against a documented baseline/change history; an exclusion added without a corresponding approved change is the core anomaly.',
    ],
  },

  mitre: [{ id: 'T1556.009', name: 'Modify Authentication Process: Conditional Access Policies', tactic: 'Defense Evasion' }],

  kql: {
    sentinel: {
      triage: {
        title: 'Conditional Access policy changes',
        query: `AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName in ("Update conditional access policy", "Update policy")
| project TimeGenerated, InitiatedBy, TargetResources, Result, CorrelationId
| order by TimeGenerated desc`,
      },
      investigate: {
        title: 'Accounts consistently signing in without an MFA claim',
        description: 'Worth checking each one against your CA policy exclusion list, since this is exactly the population a policy gap would produce.',
        query: `SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType == "0"
| where AuthenticationRequirement != "multiFactorAuthentication"
| summarize Count = count(), Apps = make_set(AppDisplayName, 5) by UserPrincipalName
| where Count > 5
| order by Count desc`,
      },
    },
    defender: {
      triage: {
        title: 'Conditional Access policy activity',
        query: `CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType has "conditional access"
| project Timestamp, AccountDisplayName, ActionType, RawEventData
| order by Timestamp desc`,
      },
    },
  },

  runbook: {
    triage: [
      'Review current CA policy exclusions and confirm each against a change/approval record.',
      'Check break-glass account sign-in activity for anything outside a documented emergency.',
      'Confirm policies are in an enforced, not report-only, state.',
      'If a compromise is already underway, identify the specific gap being exploited.',
    ],
    contain: [
      'Close the identified gap — remove the exclusion, or switch report-only to enabled.',
      'Force re-authentication for accounts that signed in via the gap.',
      'Revoke sessions for any account whose access relied on the gap.',
      'Temporarily tighten related policies while the root cause is addressed.',
    ],
    investigate: [
      'Determine how the gap was discovered or exploited — reconnaissance, insider knowledge, or trial and error.',
      'Check what access was gained through it.',
      'Review whether the gap was long-standing configuration debt or recently introduced tampering.',
      "Assess whether similar gaps exist in other policies with similar exclusion patterns.",
    ],
    recover: [
      'Implement a recurring CA policy review process rather than relying on one-time configuration.',
      'Use the What If tool to validate coverage against realistic scenarios.',
      'Minimize and tightly govern break-glass account usage with dedicated monitoring.',
      'Avoid leaving policies in report-only mode longer than the evaluation period actually requires.',
    ],
  },
}

export default entry
