import type { ThreatEntry } from '../../../../types/threat'

const entry: ThreatEntry = {
  id: 'privilege-escalation-role-assignment',
  title: 'Privilege Escalation via Role Assignment',
  domain: 'access-control-escalation',
  category: 'Privilege Escalation',
  severity: 'critical',
  status: 'complete',
  shortDesc:
    "Direct, standing assignment of high-privilege directory roles or Azure RBAC Owner/Contributor roles, bypassing PIM's time-bound activation model entirely.",
  description:
    'Where PIM-eligible abuse exploits a time-bound activation, this technique targets accounts holding privileged roles as permanent, standing assignments — Global Administrator, Privileged Role Administrator, or subscription-level Owner/Contributor granted directly rather than through PIM. An attacker who compromises such an account gets full privilege immediately, with no activation event to detect.',

  forensicArtifacts: [
    {
      source: 'Entra ID AuditLogs',
      artifact: "OperationName == 'Add member to role' with no PIM-activation qualifier — a direct, permanent role assignment rather than a time-bound PIM activation",
    },
    {
      source: 'Entra ID AuditLogs',
      artifact: "TargetResources showing the role name and the assigning admin's identity — unlike PIM activation, there's no subsequent expiration event to corroborate; the assignment persists until someone removes it",
    },
    {
      source: 'Entra ID Access Reviews (Identity Governance)',
      artifact:
        "Whether the privileged role is actually in scope for a recurring access review, and if so, the review's own history — a standing assignment that has never been reviewed, or was auto-approved by inactivity/default-decision settings rather than an explicit reviewer action, is a governance gap independent of whether the current incident involves a genuine compromise.",
    },
    {
      source: 'AzureActivity',
      artifact: 'Microsoft.Authorization/roleAssignments/write for a standing (non-eligible) Owner/Contributor/User Access Administrator assignment at subscription or management-group scope',
    },
    {
      source: 'Periodic access review / posture query',
      artifact: "The current, standing set of directory role and Azure RBAC assignments — since there's no activation event to alert on, detection here leans heavily on regularly querying who currently holds privileged access, not just watching for a moment-in-time trigger",
    },
    {
      source: 'Entra ID SigninLogs',
      artifact: "The assigning admin's sign-in immediately preceding the assignment — establishes whether it came from their normal pattern or a compromised session",
    },
  ],

  telemetry: {
    correlationMarkers: [
      "Unlike PIM activation, a standing role assignment has no natural 'end' event — treat the assignment itself, not just its creation, as the ongoing finding until it's explicitly removed.",
      "TargetResources[].modifiedProperties -> Role.DisplayName and the assignee's object ID pinpoint exactly who was granted what.",
      'Compare against your own change-management record: a standing privileged grant with no corresponding approved request is the core anomaly, since the raw event alone looks identical to a legitimate one.',
    ],
  },

  mitre: [
    { id: 'T1078.004', name: 'Valid Accounts: Cloud Accounts', tactic: 'Privilege Escalation' },
    { id: 'T1098.003', name: 'Account Manipulation: Additional Cloud Roles', tactic: 'Privilege Escalation' },
  ],

  kql: {
    sentinel: {
      triage: {
        title: 'Direct (non-PIM) role assignments',
        query: `AuditLogs
| where TimeGenerated > ago(30d)
| where Category == "RoleManagement"
| where OperationName == "Add member to role"
| where OperationName !has "PIM"
| project TimeGenerated, InitiatedBy, TargetResources, Result, CorrelationId
| order by TimeGenerated desc`,
      },
      investigate: {
        title: 'Current standing assignments to sensitive roles',
        description: 'Point-in-time posture — run this periodically rather than only in response to an alert.',
        query: `AuditLogs
| where TimeGenerated > ago(90d)
| where Category == "RoleManagement"
| where OperationName == "Add member to role"
| extend Role = tostring(TargetResources[0].displayName)
| where Role has_any ("Global Administrator", "Privileged Role Administrator", "Security Administrator")
| project TimeGenerated, InitiatedBy, Role, TargetResources
| order by TimeGenerated desc`,
      },
    },
    defender: {
      triage: {
        title: 'Direct role assignment activity',
        query: `CloudAppEvents
| where Timestamp > ago(30d)
| where Application in ("Microsoft Entra ID", "Office 365")
| where ActivityType has "Add member to role"
| project Timestamp, AccountDisplayName, ActivityType, IPAddress, RawEventData
| order by Timestamp desc`,
      },
    },
  },

  runbook: {
    triage: [
      'Confirm whether the assignment corresponds to an approved change request — a technically-valid assignment with no change record behind it is the core finding here.',
      'Identify the assigning admin and their own privilege level — assigning a directory role itself requires already holding sufficient privilege.',
      "Determine the assigned role's actual scope in case the role name alone undersells its reach.",
      'Check whether PIM is enabled tenant-wide for this role category — if so, a standing assignment existing at all may indicate a PIM enforcement gap.',
    ],
    contain: [
      'Remove the standing role assignment immediately if unauthorized.',
      "Revoke sessions for both the assignee and, if the assigning action itself looks compromised, the assigning admin.",
      'Audit for other standing assignments made around the same time by the same actor.',
      "If PIM is available but this role isn't yet enrolled in it, treat closing that gap as an immediate priority.",
    ],
    investigate: [
      'Reconstruct what the newly-privileged account did with its access before the assignment was caught and removed.',
      "Check whether the assigning admin's own account shows other signs of compromise.",
      'Review whether this is isolated or part of a broader pattern — several standing assignments made in a short window suggests an attacker moving quickly while they have access.',
      'Cross-reference with PIM Eligible Role Abuse elsewhere in this matrix — the two are often complementary attacker choices depending on what a compromised account can reach.',
    ],
    recover: [
      'Migrate standing privileged role assignments to PIM-eligible wherever feasible, so future grants require activation, approval, and time-bound expiry.',
      'Establish a recurring, not just incident-triggered, access review cadence for every standing privileged assignment.',
      'Restrict who can assign directory roles to a small, tightly monitored set of accounts.',
      'Alert on every new "Add member to role" event for high-privilege roles going forward, standing or eligible, rather than relying solely on periodic review.',
    ],
  },
}

export default entry
