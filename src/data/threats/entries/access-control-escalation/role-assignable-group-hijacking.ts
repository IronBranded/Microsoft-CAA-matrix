import type { ThreatEntry } from '../../../../types/threat'

const entry: ThreatEntry = {
  id: 'role-assignable-group-hijacking',
  title: 'Role-Assignable Group Hijacking',
  domain: 'access-control-escalation',
  category: 'Privilege Escalation',
  severity: 'high',
  status: 'complete',
  shortDesc: 'Modifying membership or ownership of an isAssignableToRole=true group to inherit administrative rights indirectly.',
  description:
    "Groups flagged isAssignableToRole can themselves be assigned directory roles, meaning membership confers the role. If an attacker compromises an account that owns such a group, they can add any account they control as a member and inherit its privileges — a path that's easy to overlook since the compromised account never appears in the role assignment list directly.",

  forensicArtifacts: [
    {
      source: 'Entra ID AuditLogs',
      artifact: "OperationName == 'Add member to group' where the target group has isAssignableToRole = true — inheriting whatever directory role the group itself holds",
    },
    {
      source: 'Entra ID AuditLogs',
      artifact: 'The acting identity\'s relationship to the group — group owners can typically add members without holding the underlying role themselves, which is the crux of this technique',
    },
    {
      source: 'Entra ID Groups',
      artifact: 'The specific directory role(s) assigned to the role-assignable group — this defines the actual privilege inherited by any new member',
    },
    {
      source: 'Entra ID AuditLogs',
      artifact: "A change to the group's ownership immediately preceding a suspicious membership change — an attacker may need to gain ownership before adding a member",
    },
    {
      source: 'Entra ID SigninLogs',
      artifact: "The newly-added member's subsequent sign-in activity exercising the inherited privilege",
    },
  ],

  telemetry: {
    correlationMarkers: [
      'Role-assignable groups are a smaller, specifically-flagged population — enumerate this list directly rather than trying to infer it from membership-change volume alone.',
      'Group ownership and group membership are separate permissions — a compromised owner account can add members without ever itself holding the role the group grants.',
      "The new member's activity after being added is the practical confirmation that the inherited privilege was actually used, not just granted.",
    ],
  },

  mitre: [{ id: 'T1098.003', name: 'Account Manipulation: Additional Cloud Roles', tactic: 'Privilege Escalation' }],

  atrm: [{ id: 'AZT501.1', name: 'User Account Manipulation', tactic: 'Persistence' }],

  kql: {
    sentinel: {
      triage: {
        title: 'Membership changes to groups',
        description:
          'Requires first identifying which groups in your tenant are role-assignable (isAssignableToRole) — cross-reference TargetResources against that list, or query Microsoft Graph directly for the authoritative set before running this at scale.',
        query: `AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName == "Add member to group"
| project TimeGenerated, InitiatedBy, TargetResources, Result, CorrelationId
| order by TimeGenerated desc`,
      },
      investigate: {
        title: 'Group ownership changes (a frequent precursor step)',
        query: `AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName has_any ("Add owner to group", "Add group owner")
| project TimeGenerated, InitiatedBy, TargetResources, Result
| order by TimeGenerated desc`,
      },
    },
    defender: {
      triage: {
        title: 'Group membership and ownership activity',
        query: `CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType has_any ("Add member to group", "Add owner to group")
| project Timestamp, AccountDisplayName, ActionType, RawEventData
| order by Timestamp desc`,
      },
    },
  },

  runbook: {
    triage: [
      'Enumerate role-assignable groups tenant-wide and cross-reference against the flagged membership change.',
      'Identify what directory role the group actually grants.',
      "Confirm whether the acting identity legitimately owns the group and whether that ownership itself is expected.",
      'Check whether the group ownership itself changed recently.',
    ],
    contain: [
      'Remove the unauthorized member immediately.',
      'Revoke sessions for the newly-added, now de-privileged, account.',
      'Review the group\'s ownership list for other unexpected entries.',
      'Audit other role-assignable groups the same owner controls.',
    ],
    investigate: [
      'Determine how the acting identity obtained group ownership if that itself looks anomalous.',
      'Check what the newly-privileged account did with its inherited role before removal.',
      'Review for a pattern of similar changes across other role-assignable groups.',
      'Establish the full timeline from ownership change (if any) through membership change through privilege use.',
    ],
    recover: [
      'Minimize the number of role-assignable groups and tightly govern their ownership.',
      'Treat group ownership changes for role-assignable groups with the same scrutiny as direct role assignments.',
      'Consider PIM for Groups to bring time-bound activation to this privilege path as well.',
      'Periodically review the full set of role-assignable groups and their current owners against expected baseline.',
    ],
  },
}

export default entry
