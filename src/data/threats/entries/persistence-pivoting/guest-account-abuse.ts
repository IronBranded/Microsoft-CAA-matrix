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
      logSourceId: 'entra-audit-logs',
      source: 'Entra ID AuditLogs',
      artifact: 'Guest account creation events and the inviting user — establishes whether the invitation itself followed a legitimate business process',
    },
    {
      source: 'Entra ID External collaboration settings',
      artifact:
        "Who is permitted to invite guests tenant-wide — if set to 'anyone' rather than restricted to admins/specific roles, any compromised standard account can itself be the source of a stale-guest invitation later exploited, not just an admin account.",
    },
    {
      logSourceId: 'sign-in-logs',
      source: 'Entra ID SigninLogs',
      artifact: "Guest account sign-in patterns compared to the inviting organization's typical collaboration activity — access far beyond what the original collaboration purpose would suggest",
    },
    {
      source: 'Entra ID access reviews',
      artifact: 'Whether guest accounts are subject to periodic access review at all — their absence from a review cycle is itself a gap',
    },
    {
      logSourceId: 'entra-audit-logs',
      source: 'Entra ID AuditLogs',
      artifact: 'Role or group membership changes granting a guest account access beyond typical guest-level permissions',
    },
  ],

  telemetry: {
    correlationMarkers: [
      'Guest accounts often fall outside the same lifecycle processes built for internal accounts — this gap, not any single technical control failure, is usually the actual root cause.',
      'A long-dormant guest account suddenly active is a strong signal regardless of what it is doing, given how much less scrutiny guest activity typically receives day to day.',
      'Guest access scope should map to a specific, documented collaboration purpose — access broader than that purpose, even if technically authorized at some point, is worth periodic re-justification.',
      'There is deliberately no relevantErrorCodes entry for this scenario: using an already-existing, already-invited guest account is a normal successful sign-in — there is no failure event distinguishing it from legitimate collaboration. Dormancy-then-activity and scope-versus-purpose review are the only detection paths.',
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

  authFlow: {
    pattern: 'sequence',
    narrative:
      "As this entry's own correlationMarkers already note, there's no distinguishing error code — using an already-existing, already-invited guest account produces a completely normal successful sign-in. The signal is entirely in the account's activity pattern over time (dormancy, then sudden activity; access broader than the original collaboration purpose), not in any single event.",
    steps: [
      {
        code: 'guest-invited',
        label: 'Guest account created via B2B invitation',
        detail: 'AuditLogs event, tied to a specific inviting user and (ideally) a documented business purpose. This is the moment the standing access is created — everything after this is just whether and how it gets used.',
      },
      {
        code: '0',
        label: 'Guest account authenticates, potentially after an extended dormant period',
        detail: 'A fully ordinary success. The account genuinely is an authorized guest — the concern is about scope and staleness, not about the authentication event\'s legitimacy.',
      },
    ],
    distinguishingNotes:
      'This shares a family resemblance with cross-tenant-trust-exploitation — both involve a standing trust relationship with an external identity rather than a discrete attack moment — but at individual-account granularity rather than tenant-wide policy. A single stale guest account is a much narrower blast radius than an overly broad inbound cross-tenant policy, but the investigative logic (check the relationship\'s scope against its actual current use, not just whether the sign-in succeeded) is the same.',
  },

  tokenTimeline: {
    issuance:
      "Issued through the normal guest sign-in flow — HomeTenantId reflects the guest's actual home organization (or personal Microsoft account), distinct from your own ResourceTenantId. Nothing about issuance itself is unusual regardless of how long the account has been dormant.",
    expiration:
      'Standard token lifetimes. The durable risk isn\'t any single token — it\'s the standing guest account object and its access grants, which persist across any number of individual sign-in/token cycles until explicitly reviewed and removed.',
    authInstant:
      "auth_time reflects the guest's actual authentication, in whatever identity system their home tenant uses — genuinely valid, not forged. This scenario is about scope and lifecycle, not about the authentication event's own legitimacy.",
    authMethods: "amr reflects whatever the guest's home identity provider required — which may be entirely outside your own tenant's control or visibility, similar to the provenance concern in cross-tenant-trust-exploitation.",
    mfaInstant:
      "Governed by whatever cross-tenant access settings apply to guest sign-ins specifically — if your tenant trusts the guest's home MFA claim rather than re-evaluating it, there's no local MFA instant for this sign-in at all.",
    otherContext:
      "The object worth tracking over time isn't a token or even a single sign-in — it's the guest account's full access history against its original documented purpose. A guest account that's accumulated access via ad hoc group additions over months, well beyond whatever the original invitation was for, is the practical shape this risk actually takes.",
  },

  runbook: {
    triage: [
      "Confirm the guest account's original invitation purpose and inviting user.",
      'Review its actual current access scope against that purpose.',
      'Check for a long dormancy period preceding recent activity.',
    ],
    contain: [
      'Disable or remove the guest account if no longer needed: `Update-MgUser -UserId <guest object id> -AccountEnabled:$false` to disable, or `Remove-MgUser -UserId <guest object id>` to remove it entirely.',
      'Revoke sessions: `Revoke-MgUserSignInSession -UserId <guest object id>`.',
      'Tighten its access scope if broader than the original collaboration purpose — review and remove group/role memberships that exceed the documented collaboration need.',
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
