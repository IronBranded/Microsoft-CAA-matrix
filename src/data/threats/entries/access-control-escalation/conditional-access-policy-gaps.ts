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
      logSourceId: 'entra-audit-logs',
      source: 'Entra ID AuditLogs',
      artifact: "OperationName == 'Update conditional access policy' with a change narrowing scope, adding an exclusion, or reducing enforcement (e.g. moving to report-only)",
    },
    {
      logSourceId: 'sign-in-logs',
      source: 'Entra ID SigninLogs (break-glass / emergency-access accounts)',
      artifact: 'Any sign-in activity for accounts specifically provisioned as CA-policy-excluded break-glass accounts, outside a documented emergency',
    },
    {
      source: 'Conditional Access "What If" tool / posture review',
      artifact: 'Periodic review of which users/groups/apps are currently excluded from each policy — not an event, but a state worth checking regularly since gaps often predate any single detectable action',
    },
    {
      logSourceId: 'sign-in-logs',
      source: 'Entra ID SigninLogs',
      artifact: 'A sign-in that completed without MFA or device compliance for a user/app combination that should be covered by an existing policy — the practical symptom of a gap being actively exploited',
    },
    {
      logSourceId: 'entra-audit-logs',
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
    relevantErrorCodes: [
      {
        code: 'AADSTS53003',
        type: 'Conditional Access',
        description: 'Access has been blocked by Conditional Access policies. The access policy does not allow token issuance.',
        dfirValue:
          "Confirms a policy actually fired and blocked the attempt — useful to verify containment worked. Its ABSENCE for a sign-in that should have triggered a specific policy is the more important signal for this scenario: it means the policy didn't apply as expected, which is exactly what a gap looks like from the sign-in log alone.",
      },
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

  authFlow: {
    pattern: 'sequence',
    narrative:
      "Like identity-protection-evasion elsewhere in this matrix, the notable event here is an absence rather than a presence — a sign-in that completes without a challenge a policy was supposed to apply. Unlike that entry, the gap itself is usually a static configuration state that predates any specific attacker action, not something actively defeated in the moment.",
    steps: [
      {
        code: '0',
        label: 'Sign-in completes without the challenge an intended policy should have applied',
        detail: 'No AADSTS53003 (blocked) and no step-up challenge — just a plain success, for a user/app combination that a properly-scoped policy would have caught. The absence of the expected friction is the entire signal.',
      },
      {
        code: '53003',
        label: '(For comparison) what a working policy produces on the same combination',
        detail: "This is the code you'd expect to see if the policy actually applied. Its absence on the sign-in in question is what confirms a gap rather than a policy simply not existing at all — check both.",
      },
    ],
    distinguishingNotes:
      "This entry and identity-protection-evasion share the same shape (a normal-looking success where friction was expected) but different causes: evasion is an attacker actively shaping behavior to stay under a detection threshold; a policy gap is a standing misconfiguration that would let the same sign-in through regardless of how it was conducted. If tightening detection thresholds doesn't fix the problem, you're likely looking at a gap, not evasion.",
  },

  tokenTimeline: {
    issuance: "Issued exactly as it would be for any successful sign-in — a policy gap doesn't change how or when the token is issued, only whether a challenge happened first.",
    expiration: 'Standard lifetimes, unaffected by this scenario specifically.',
    authInstant: 'auth_time reflects an ordinary sign-in moment with nothing distinguishing it from a fully-covered, policy-compliant sign-in at the claim level.',
    authMethods:
      'amr shows whatever the user actually provided — which may be password alone, less than what a properly-scoped policy would have required. A single-factor amr on an account that should be MFA-covered is itself the practical symptom worth checking, cross-referenced against current policy scope rather than assumed to mean compromise on its own.',
    mfaInstant: "Absent, for the accounts actually affected by the gap — there's no MFA instant to find because no MFA was required, which is precisely the finding.",
    otherContext:
      'Because this is a standing configuration state rather than a discrete event, the useful posture here is periodic review (the What If tool, a recurring exclusion-list audit) rather than trying to catch a specific moment in the logs. By the time a sign-in through the gap shows up in SigninLogs, the gap has usually existed for a while already.',
  },

  runbook: {
    triage: [
      'Review current CA policy exclusions and confirm each against a change/approval record.',
      'Check break-glass account sign-in activity for anything outside a documented emergency.',
      'Confirm policies are in an enforced, not report-only, state.',
      'If a compromise is already underway, identify the specific gap being exploited.',
    ],
    contain: [
      "Close the identified gap — remove the exclusion or switch report-only to enabled. `Update-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId <id> -BodyParameter @{ state = 'enabled' }` covers the report-only case directly; the nested condition/exclusion structure for other changes is complex enough that the portal is often more practical and less error-prone for that specific edit.",
      'Force re-authentication for accounts that signed in via the gap.',
      'Revoke sessions for any account whose access relied on the gap: `Revoke-MgUserSignInSession -UserId <UPN>`.',
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
