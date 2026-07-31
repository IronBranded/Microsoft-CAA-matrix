import type { ThreatEntry } from '../../../../types/threat'

const entry: ThreatEntry = {
  id: 'tap-misuse',
  title: 'Temporary Access Pass (TAP) Misuse',
  domain: 'identity-authentication',
  category: 'Persistence / Credential Access',
  severity: 'high',
  status: 'complete',
  shortDesc: 'Exploiting weak governance around Temporary Access Pass issuance to register a rogue authentication method on a target account.',
  description:
    "A Temporary Access Pass is meant to let a user, or a help desk on their behalf, bootstrap MFA registration without a password. If TAP issuance isn't tightly governed — long validity windows, no additional identity verification, reusable passes — an attacker who social-engineers a help desk agent can have a TAP issued for a target account and use it to register their own MFA method, gaining access that survives a subsequent password reset.",

  forensicArtifacts: [
    {
      source: 'Entra ID AuditLogs',
      artifact: 'A Temporary Access Pass issuance event, showing who issued it and to which target account',
    },
    {
      source: 'Entra ID AuditLogs',
      artifact: 'A new MFA method (Authenticator app, phone number, FIDO2 key) registered using the TAP shortly after issuance — the actual persistence-establishing step',
    },
    {
      source: 'Help desk / ticketing system (outside Entra telemetry)',
      artifact: 'The support interaction that led to TAP issuance — verify it corresponds to a real, verified user request rather than a social-engineered one',
    },
    {
      source: 'Entra ID AuditLogs',
      artifact:
        "The TAP's configured lifetime and one-time-use setting — a long-lived, reusable TAP is a much larger exposure window than a short, one-time one. Also worth checking: whether the account already had another MFA method registered before the TAP was issued — TAP is meant for bootstrap/recovery scenarios, so a TAP issued to an account that wasn't actually locked out is itself an anomaly worth the same scrutiny as the registration event it enabled.",
    },
    {
      source: 'Entra ID SigninLogs',
      artifact: "The TAP-based sign-in and the immediately following registration session's IP/device, compared against the legitimate account owner's normal pattern",
    },
  ],

  telemetry: {
    correlationMarkers: [
      'The TAP issuance event and the subsequent MFA method registration are two separate events worth correlating — a TAP issued but never used to register anything is far less concerning than one immediately followed by a new registration.',
      'Issuing admin identity: was this issued by a help desk account with a normal, auditable justification, or does the issuance itself look anomalous for that admin?',
      'TAP lifetime and reuse settings directly determine exposure window — check tenant policy for how long TAPs are valid and whether they are single-use by default.',
    ],
  },

  mitre: [
    { id: 'T1098', name: 'Account Manipulation', tactic: 'Persistence' },
    { id: 'T1556', name: 'Modify Authentication Process', tactic: 'Persistence' },
  ],

  kql: {
    sentinel: {
      triage: {
        title: 'Temporary Access Pass issuance events',
        query: `AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName has_any ("Temporary Access Pass", "TAP")
| project TimeGenerated, InitiatedBy, TargetResources, OperationName, Result
| order by TimeGenerated desc`,
      },
      investigate: {
        title: 'MFA registration immediately following TAP issuance',
        query: `let tap_issuances = AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName has_any ("Temporary Access Pass", "TAP")
| extend TargetUser = tostring(TargetResources[0].userPrincipalName), IssuedTime = TimeGenerated;
AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName has_any ("Register security info", "User registered")
| extend RegUser = tostring(InitiatedBy.user.userPrincipalName)
| join kind=inner tap_issuances on $left.RegUser == $right.TargetUser
| where TimeGenerated between (IssuedTime .. (IssuedTime + 1h))
| project TimeGenerated, RegUser, OperationName, IssuedTime
| order by TimeGenerated desc`,
      },
    },
    defender: {
      triage: {
        title: 'TAP and security info registration activity',
        query: `CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType has_any ("Temporary Access Pass", "Register security info")
| project Timestamp, AccountDisplayName, ActionType, RawEventData
| order by Timestamp desc`,
      },
    },
  },

  runbook: {
    triage: [
      'Identify the issuing admin/help desk agent and the justification on record.',
      'Confirm whether the requesting "user" was actually verified through a secure process.',
      'Check what was registered using the TAP.',
      'Establish the TAP\'s configured lifetime and reuse settings at issuance time.',
    ],
    contain: [
      'Remove the newly-registered MFA method if fraudulent.',
      "Reset the account's authentication methods entirely.",
      'Revoke sessions.',
      'Suspend the account pending investigation if broader compromise is suspected.',
    ],
    investigate: [
      'Review the help desk interaction/ticket that led to issuance for signs of social engineering.',
      'Check whether the same help desk agent or process has issued other TAPs recently.',
      'Determine what the account accessed after the fraudulent registration.',
      'Assess whether help desk verification procedures need broader review, not just this one incident.',
    ],
    recover: [
      'Tighten TAP issuance policy — shorter lifetimes, one-time-use enforcement, and stronger identity verification before help desk staff can issue one.',
      'Train help desk staff specifically on TAP-related social engineering.',
      'Alert on every TAP issuance as a standing rule, given how infrequent legitimate use should be.',
      'Consider requiring a second approver for TAP issuance to privileged accounts specifically.',
    ],
  },
}

export default entry
