import type { ThreatEntry } from '../../../../types/threat'

const entry: ThreatEntry = {
  id: 'pim-eligible-role-abuse',
  title: 'PIM Eligible Role Abuse',
  domain: 'access-control-escalation',
  category: 'Privilege Escalation',
  severity: 'critical',
  status: 'complete',
  shortDesc:
    'An attacker with a compromised account activates a dormant PIM-eligible role assignment, self-elevating to Global Admin or Owner without ever triggering a net-new role grant.',
  description:
    "Privileged Identity Management (PIM) lets accounts hold 'eligible' — rather than standing — role assignments, activated on demand for a time-bound window. If an attacker compromises an account that already has a dormant eligible assignment, they can simply activate it. Depending on tenant policy, this may not require approval or even re-authentication, and because the eligibility already existed, the activation doesn't look like an anomalous new role grant — it looks like routine PIM usage. This makes PIM abuse a quiet, fast path from 'compromised standard account' to 'Global Admin' when eligible assignments are broad or activation policy is weak.",

  forensicArtifacts: [
    {
      logSourceId: 'entra-audit-logs',
      source: 'Entra ID AuditLogs',
      artifact:
        "Category == 'RoleManagement' with an OperationName indicating a PIM activation (directory role or Azure resource role)",
    },
    {
      logSourceId: 'entra-audit-logs',
      source: 'Entra ID AuditLogs',
      artifact: "TargetResources containing the activated role name and the requestor's stated justification, if your tenant requires one",
    },
    {
      logSourceId: 'sign-in-logs',
      source: 'Entra ID SigninLogs',
      artifact: "The activating user's sign-in immediately preceding the activation event, correlated by UserId and timestamp proximity",
    },
    {
      source: 'PIM Alerts (Entra ID ▸ Identity Governance ▸ PIM ▸ Alerts)',
      artifact:
        "Built-in alerts such as 'Roles are being activated too frequently', 'Potential stale accounts in a privileged role', and 'Roles don't require multi-factor authentication for activation' — that last one is worth checking as a standing configuration issue independent of any specific incident, since an MFA-optional activation policy is exactly what makes a compromised-but-not-attacker-controlled-MFA account able to activate a role at all.",
    },
    {
      logSourceId: 'azure-activity-log',
      source: 'AzureActivity',
      artifact:
        'Microsoft.Authorization/roleAssignments/write correlating to a PIM-eligible Owner/Contributor activation on a subscription or resource group',
    },
  ],

  telemetry: {
    correlationMarkers: [
      "TargetResources[].modifiedProperties -> Role.DisplayName: the activated role name.",
      'Actor UPN vs activation requestor: for legitimate PIM these match; a mismatch, or an activation initiated via Graph API/PowerShell instead of the portal, is a strong anomaly signal.',
      'Activation duration: PIM activations are time-bound (commonly 1–8 hours) — an attacker will often request the maximum allowed window.',
      "There is deliberately no relevantErrorCodes entry for this scenario: a successful activation is, by definition, PIM correctly doing what it was configured to do for an account that already held the eligible assignment — there's no failure code to point at. Where activation policy requires MFA or approval and the attacker can't satisfy it, that shows up as an activation request that never completes in AuditLogs, not as a numbered error.",
    ],
  },

  mitre: [
    { id: 'T1078.004', name: 'Valid Accounts: Cloud Accounts', tactic: 'Privilege Escalation' },
    { id: 'T1098.003', name: 'Account Manipulation: Additional Cloud Roles', tactic: 'Privilege Escalation' },
  ],

  kql: {
    sentinel: {
      triage: {
        title: 'PIM role activation events',
        description:
          'modifiedProperties structure in AuditLogs can vary by activation type (directory role vs. Azure resource role) — inspect a sample with a plain `| take 5` first and adjust parsing to match what your tenant emits.',
        query: `// Detect PIM role activation events in Entra ID.
AuditLogs
| where TimeGenerated > ago(7d)
| where Category == "RoleManagement"
| where OperationName has "PIM activation" or OperationName has "Add member to role completed"
| project TimeGenerated, OperationName, InitiatedBy, TargetResources, Result, CorrelationId
| order by TimeGenerated desc`,
      },
      investigate: {
        title: 'Correlate activation with the requestor\'s recent sign-in',
        description: 'Flags activations that immediately follow a suspicious sign-in — new device, new location, or a session riding a stolen token.',
        query: `// Correlate a PIM activation with the requestor's most recent interactive sign-in.
let activations = AuditLogs
| where TimeGenerated > ago(7d)
| where Category == "RoleManagement"
| where OperationName has "PIM activation"
| extend Requestor = tostring(InitiatedBy.user.userPrincipalName), ActivationTime = TimeGenerated;
activations
| join kind=leftouter (
    SigninLogs
    | where TimeGenerated > ago(7d)
    | where ResultType == "0"
    | project SignInTime = TimeGenerated, UserPrincipalName, IPAddress, Location, DeviceDetail
) on $left.Requestor == $right.UserPrincipalName
| where SignInTime between ((ActivationTime - 30m) .. ActivationTime)
| project ActivationTime, Requestor, SignInTime, IPAddress, Location, DeviceDetail
| order by ActivationTime desc`,
      },
    },
    defender: {
      triage: {
        title: 'PIM activation events via CloudAppEvents',
        description:
          'PIM activation audit events are not part of the core Defender XDR schema the way endpoint/identity/email tables are — availability here depends on the Entra ID app connector into Defender for Cloud Apps, or a unified Sentinel+Defender workspace. Verify ActivityType naming against your own tenant before relying on this.',
        query: `CloudAppEvents
| where Timestamp > ago(7d)
| where Application in ("Microsoft Entra ID", "Office 365")
| where ActivityType has_any ("Add member to role", "PIM")
| project Timestamp, AccountDisplayName, ActivityType, IPAddress, RawEventData`,
      },
    },
  },

  authFlow: {
    pattern: 'sequence',
    narrative:
      "This flow lives in AuditLogs role-activation events, not AADSTS sign-in codes — same shape as tap-misuse elsewhere in this matrix, where the interesting sequence isn't at the sign-in layer at all. As this entry's own correlationMarkers already note, there's no failure code for a successful activation, because PIM is, by definition, doing exactly what it was configured to do.",
    steps: [
      {
        code: 'account-compromised',
        label: 'Attacker obtains any authenticated session on an account holding a dormant PIM-eligible assignment',
        detail: "Not this entry's mechanism — see whichever other entry in this matrix actually applies (token theft, AiTM, password compromise, etc.). What matters here is only that the session exists and the account happens to hold unused eligibility.",
      },
      {
        code: 'role-activation-requested',
        label: 'PIM activation requested for the eligible role',
        detail: 'An AuditLogs RoleManagement event, not a sign-in event. Whether this succeeds depends entirely on activation policy — MFA-on-activation and approval requirements are real friction here, where they exist; their absence is a standing configuration gap, not something the attacker has to defeat.',
      },
      {
        code: 'role-activation-completed',
        label: 'Role becomes active for the configured time-bound window',
        detail: "From this moment, the account's elevated privilege is real and unrestricted by anything PIM-specific — a Global Admin session behaves like any other Global Admin session for the duration of the window.",
      },
    ],
    distinguishingNotes:
      "The activation event itself looks completely routine if the account genuinely holds the eligible assignment — there's no 'this activation is malicious' flag. The signal is entirely in context: does the requestor's recent sign-in look like their normal pattern, and does the account's holding this eligibility in the first place make sense for its actual job function. An overly broad population of eligible assignments is itself a finding independent of any specific incident — see recover.",
  },

  tokenTimeline: {
    issuance:
      "The token/session predates the activation — PIM elevates what an already-authenticated session is authorized to do, it doesn't mint a fresh sign-in. Whatever authenticated the underlying session in the first place is a separate question this entry doesn't answer.",
    expiration:
      "The elevated privilege itself is time-bound by PIM's activation window (commonly 1-8 hours, tenant-configured) — a genuinely distinctive expiration concept versus most of this matrix, where token expiration and privilege expiration are the same thing. Here they're not: the underlying session token may outlive the PIM activation window, or vice versa, and re-checking whether a role is still active (not just whether it was activated) matters for scoping what the account could actually do at any given moment during an incident.",
    authInstant:
      "auth_time reflects whatever authenticated the underlying session, unrelated to the activation timestamp — for this entry specifically, the AuditLogs activation timestamp is the more useful anchor than any JWT claim.",
    authMethods:
      "amr reflects the underlying session's authentication, not anything about the PIM activation itself — activation may separately require its own MFA challenge depending on policy, which shows up in AuditLogs' activation event context rather than in amr on any token.",
    mfaInstant:
      "Where MFA-on-activation is enforced, the activation event itself carries that context in AuditLogs — check there rather than in sign-in-log MFA timing fields, which describe the original sign-in, not the later activation.",
    otherContext:
      "This is a genuinely different shape from most Domain 1 entries: the interesting lifecycle isn't the token's, it's the privilege's, and PIM tracks that separately from any single sign-in or token. Treat the activation window, not any token expiration, as the operative clock during investigation and containment.",
  },

  runbook: {
    triage: [
      "Confirm whether the activation followed the tenant's normal approval workflow — was an approval actually granted, or does the role not require approval (a common misconfiguration)?",
      'Identify the activated role\'s scope (Global Admin, Privileged Role Admin, or something narrower) and exactly what resources it grants.',
      "Check whether the requestor's recent sign-in pattern (device, location, IP) is consistent with their normal baseline.",
      "Verify the stated justification or ticket reference, if your tenant requires one, against an actual change ticket.",
    ],
    contain: [
      "Deactivate the active PIM role assignment immediately. PIM models this as creating a new schedule request with a removal action, not updating the assignment directly: `New-MgRoleManagementDirectoryRoleAssignmentScheduleRequest -BodyParameter @{ action = 'adminRemove'; principalId = '<user object id>'; roleDefinitionId = '<role definition id>'; directoryScopeId = '/' }`. The Entra portal does the same thing under the hood if you'd rather not script it.",
      'Revoke the user\'s sessions: `Revoke-MgUserSignInSession -UserId <UPN>`.',
      'Suspend the account pending investigation if the activation is confirmed malicious.',
      'Temporarily tighten PIM policy for the affected role — require approval and MFA-on-activation if not already enforced.',
    ],
    investigate: [
      'Pull the full audit trail of everything the elevated session did while the role was active, via AuditLogs (directory changes) and AzureActivity (resource changes) for the activation window.',
      'Check for new eligible-role assignments created during the window — a Privileged Role Admin session may grant itself new standing eligibility as persistence.',
      'Review Conditional Access policy changes made during the window (a common target: relaxing MFA requirements or excluding the attacker\'s own account).',
      'Check for new federated domains, high-privilege app registrations, or guest invitations created during the window.',
    ],
    recover: [
      'Revert any policy or permission changes made during the malicious activation.',
      'Tighten PIM activation policy tenant-wide: require justification, approval, and MFA for all sensitive roles, and reduce maximum activation duration.',
      'Review and reduce the population of standing PIM-eligible assignments — the smaller the pool of who CAN activate what, the smaller this attack surface.',
      "Enable and actively monitor PIM's built-in alerts (frequent activations, stale privileged accounts, unused roles).",
    ],
  },
}

export default entry
