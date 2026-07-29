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
      source: 'Entra ID AuditLogs',
      artifact:
        "Category == 'RoleManagement' with an OperationName indicating a PIM activation (directory role or Azure resource role)",
    },
    {
      source: 'Entra ID AuditLogs',
      artifact: "TargetResources containing the activated role name and the requestor's stated justification, if your tenant requires one",
    },
    {
      source: 'Entra ID SigninLogs',
      artifact: "The activating user's sign-in immediately preceding the activation event, correlated by UserId and timestamp proximity",
    },
    {
      source: 'PIM Alerts (Entra ID ▸ Identity Governance ▸ PIM ▸ Alerts)',
      artifact:
        "Built-in alerts such as 'Roles are being activated too frequently' or 'Potential stale accounts in a privileged role'",
    },
    {
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

  runbook: {
    triage: [
      "Confirm whether the activation followed the tenant's normal approval workflow — was an approval actually granted, or does the role not require approval (a common misconfiguration)?",
      'Identify the activated role\'s scope (Global Admin, Privileged Role Admin, or something narrower) and exactly what resources it grants.',
      "Check whether the requestor's recent sign-in pattern (device, location, IP) is consistent with their normal baseline.",
      "Verify the stated justification or ticket reference, if your tenant requires one, against an actual change ticket.",
    ],
    contain: [
      'Deactivate the active PIM role assignment immediately, via the Entra portal or `Update-MgRoleManagementDirectoryRoleAssignmentScheduleRequest`.',
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
