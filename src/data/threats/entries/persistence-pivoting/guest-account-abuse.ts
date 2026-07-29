import type { ThreatEntry } from '../../../../types/threat'

const entry: ThreatEntry = {
  id: 'guest-account-abuse',
  title: 'Guest Account Abuse',
  domain: 'persistence-pivoting',
  category: 'Persistence',
  severity: 'medium',
  status: 'complete',
  shortDesc: 'Maintaining long-term, low-visibility access through stale or compromised External/B2B guest accounts that fall outside normal internal-user lifecycle review.',
  description:
    "Guest accounts, invited for cross-organization collaboration, frequently receive far less lifecycle scrutiny than internal accounts. An attacker who compromises a legitimate guest account, or has one invited under false pretenses, can use it as a quiet, durable foothold that's less likely to be caught by controls tuned for internal identities.",

  forensicArtifacts: [
    {
      source: 'Entra ID Guest users',
      artifact: 'Guest accounts with no sign-in activity for an extended period suddenly becoming active — a stale, forgotten invitation being exploited',
    },
    {
      source: 'Entra ID AuditLogs',
      artifact: 'Guest account creation events and the inviting user — establishes whether the invitation itself followed a legitimate business process',
    },
    {
      source: 'Entra ID External collaboration settings',
      artifact:
        "Who is permitted to invite guests tenant-wide — if set to 'anyone' rather than restricted to admins/specific roles, any compromised standard account can itself be the source of a stale-guest invitation later exploited, not just an admin account.",
    },
    {
      source: 'Entra ID SigninLogs',
      artifact: "Guest account sign-in patterns compared to the inviting organization's typical collaboration activity — access far beyond what the original collaboration purpose would suggest",
    },
    {
      source: 'Entra ID access reviews',
      artifact: 'Whether guest accounts are subject to periodic access review at all — their absence from a review cycle is itself a gap',
    },
    {
      source: 'Entra ID AuditLogs',
      artifact: 'Role or group membership changes granting a guest account access beyond typical guest-level permissions',
    },
  ],

  telemetry: {
    correlationMarkers: [
      'Guest accounts often fall outside the same lifecycle processes built for internal accounts — this gap, not any single technical control failure, is usually the actual root cause.',
      'A long-dormant guest account suddenly active is a strong signal regardless of what it is doing, given how much less scrutiny guest activity typically receives day to day.',
      'Guest access scope should map to a specific, documented collaboration purpose — access broader than that purpose, even if technically authorized at some point, is worth periodic re-justification.',
    ],
  },

  mitre: [{ id: 'T1078.004', name: 'Valid Accounts: Cloud Accounts', tactic: 'Persistence' }],

  atrm: [{ id: 'AZT502.3', name: 'Guest Account Creation', tactic: 'Persistence' }],

  kql: {
    sentinel: {
      triage: {
        title: 'Guest accounts newly active after long dormancy',
        query: `SigninLogs
| where TimeGenerated > ago(7d)
| where UserType == "Guest"
| where ResultType == "0"
| summarize FirstSeenRecent = min(TimeGenerated) by UserPrincipalName
| join kind=leftouter (
    SigninLogs
    | where TimeGenerated between (ago(180d) .. ago(7d))
    | where UserType == "Guest"
    | distinct UserPrincipalName
    | extend HadPriorActivity = true
) on UserPrincipalName
| where isnull(HadPriorActivity)
| project UserPrincipalName, FirstSeenRecent
| order by FirstSeenRecent desc`,
      },
      investigate: {
        title: 'Guest account access scope',
        query: `SigninLogs
| where TimeGenerated > ago(30d)
| where UserType == "Guest"
| where ResultType == "0"
| summarize SignInCount = count(), Apps = make_set(AppDisplayName, 10) by UserPrincipalName, HomeTenantId
| order by SignInCount desc`,
      },
    },
    defender: {
      triage: {
        title: 'Guest account activity',
        query: `CloudAppEvents
| where Timestamp > ago(30d)
| where AccountType == "Guest"
| project Timestamp, AccountDisplayName, ActionType, IPAddress
| order by Timestamp desc`,
      },
    },
  },

  runbook: {
    triage: [
      "Confirm the guest account's original invitation purpose and inviting user.",
      'Review its actual current access scope against that purpose.',
      'Check for a long dormancy period preceding recent activity.',
    ],
    contain: [
      'Disable or remove the guest account if no longer needed.',
      'Revoke sessions.',
      'Tighten its access scope if broader than the original collaboration purpose.',
    ],
    investigate: [
      'Determine what the guest account accessed, particularly anything beyond the original collaboration scope.',
      "Check whether the guest's home tenant/identity itself may be compromised.",
    ],
    recover: [
      'Implement periodic access review specifically for guest accounts.',
      "Set expiration policies on guest invitations tied to the collaboration's expected duration.",
      'Remove guest accounts as part of a defined offboarding process when a collaboration ends.',
    ],
  },
}

export default entry
