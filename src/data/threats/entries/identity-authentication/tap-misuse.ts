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
      logSourceId: 'entra-audit-logs',
      source: 'Entra ID AuditLogs',
      artifact: 'A Temporary Access Pass issuance event, showing who issued it and to which target account',
    },
    {
      logSourceId: 'entra-audit-logs',
      source: 'Entra ID AuditLogs',
      artifact: 'A new MFA method (Authenticator app, phone number, FIDO2 key) registered using the TAP shortly after issuance — the actual persistence-establishing step',
    },
    {
      source: 'Help desk / ticketing system (outside Entra telemetry)',
      artifact: 'The support interaction that led to TAP issuance — verify it corresponds to a real, verified user request rather than a social-engineered one',
    },
    {
      logSourceId: 'entra-audit-logs',
      source: 'Entra ID AuditLogs',
      artifact:
        "The TAP's configured lifetime and one-time-use setting — a long-lived, reusable TAP is a much larger exposure window than a short, one-time one. Also worth checking: whether the account already had another MFA method registered before the TAP was issued — TAP is meant for bootstrap/recovery scenarios, so a TAP issued to an account that wasn't actually locked out is itself an anomaly worth the same scrutiny as the registration event it enabled.",
    },
    {
      logSourceId: 'sign-in-logs',
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
    relevantErrorCodes: [
      {
        code: 'AADSTS53010',
        type: 'Location/Device-Restricted Registration',
        description:
          "ProofUpBlockedDueToSecurityInfoAcr — the same control that gates FIDO2/passkey registration elsewhere in this matrix applies here too, since redeeming a TAP to register a new MFA method is itself a registration event. If the tenant requires registration from a trusted location/device, a remote attacker holding only a social-engineered TAP still can't complete it.",
        dfirValue:
          "Confirms whether this specific containment control is actually in place before assuming a TAP-driven registration attempt succeeded versus was blocked. If your tenant doesn't have this restriction configured, a valid TAP is sufficient on its own — there's nothing here to detect the misuse, only the TAP issuance event itself.",
      },
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

  authFlow: {
    pattern: 'sequence',
    narrative:
      "The flow that matters here isn't a single sign-in's AADSTS codes — it's the relationship between two AuditLogs events (TAP issuance, then registration) with a short gap between them. Individually, either event can be entirely legitimate; it's the pairing and the timing that turns this into a persistence mechanism.",
    steps: [
      {
        code: 'tap-issued',
        label: 'Temporary Access Pass issued to the target account',
        detail: "An AuditLogs event, not a sign-in event — recorded regardless of whether the pass is ever redeemed. The issuing admin's identity and stated justification live here.",
      },
      {
        code: '0',
        label: 'TAP redeemed as the sign-in credential',
        detail: "A successful sign-in using the TAP in place of a password. Structurally an ordinary success code — the TAP-ness of it isn't visible without correlating back to the issuance event above.",
      },
      {
        code: 'security-info-registered',
        label: 'New MFA method registered using the TAP-authenticated session',
        detail: 'The actual persistence-establishing step — this is what survives a later password reset. The tighter this follows the TAP issuance, the more it looks like a single social-engineered transaction rather than a legitimate, separately-timed bootstrap.',
      },
    ],
    distinguishingNotes:
      "There's no code unique to fraudulent TAP use — AADSTS53010 (see telemetry) only tells you whether device/location restrictions blocked the registration attempt, not whether the TAP itself was legitimately requested. The whole signal lives in correlating three things that are each unremarkable alone: who issued it, how fast it was redeemed and used to register something new, and whether the account actually needed a bootstrap credential in the first place.",
  },

  tokenTimeline: {
    issuance:
      "The token from the TAP-based sign-in is issued at redemption, not at TAP creation — the pass itself isn't a token, it's a credential that stands in for a password for one sign-in. Nothing distinguishes this token from a password-based sign-in's token at the claim level.",
    expiration:
      "Standard token lifetimes apply to whatever's issued at redemption. The actual persistence doesn't live in this token at all — it lives in the newly-registered MFA method, which outlives the TAP itself (TAPs typically expire within hours) and survives a subsequent password reset, unlike a stolen password or session alone.",
    authInstant:
      "auth_time pins to the TAP redemption moment specifically, not to any separate password-based authentication — there isn't one in this flow. Optional claim, as elsewhere; don't assume presence.",
    authMethods:
      "amr for the redemption sign-in should reflect the TAP as the method used, which is at least a genuine, honest signal — unlike some other scenarios in this matrix, amr here isn't misleading, it's just rarely the first place people think to look. Compare it against whether a TAP redemption was actually expected for this account at this time.",
    mfaInstant:
      "Less relevant here than in most Domain 1 entries — the TAP itself functions as the initial factor being bootstrapped from, so there typically isn't a separate MFA challenge to time during the redemption sign-in. The registration event that follows is the moment worth timing precisely, and that lives in AuditLogs, not in sign-in MFA timing fields.",
    otherContext:
      "This is one of the few scenarios in this matrix where the identity side of the investigation (who issued the TAP, what the help desk ticket says) matters as much as anything in SigninLogs or AuditLogs. Token and sign-in telemetry can confirm the mechanics happened; they can't tell you whether the original request was legitimate.",
  },

  runbook: {
    triage: [
      'Identify the issuing admin/help desk agent and the justification on record.',
      'Confirm whether the requesting "user" was actually verified through a secure process.',
      'Check what was registered using the TAP.',
      'Establish the TAP\'s configured lifetime and reuse settings at issuance time.',
    ],
    contain: [
      'Remove the fraudulently-registered MFA method. List methods first to get its ID — `Get-MgUserAuthenticationMethod -UserId <UPN>` — then remove it with the method-specific cmdlet, e.g. `Remove-MgUserAuthenticationPhoneMethod -UserId <UPN> -PhoneAuthenticationMethodId <id>` for a phone number, or the FIDO2/Authenticator-equivalent cmdlet if that\'s what was registered.',
      'If any unexpired or unused TAP still exists on the account, remove it too rather than leave it valid: `Remove-MgUserAuthenticationTemporaryAccessPassMethod -UserId <UPN> -TemporaryAccessPassAuthenticationMethodId <id>`.',
      'Revoke sessions: `Revoke-MgUserSignInSession -UserId <UPN>`.',
      "Reset the account's password too, so nothing from this window persists: `Update-MgUser -UserId <UPN> -PasswordProfile @{ Password = '<new password>'; ForceChangePasswordNextSignIn = $true }`.",
      'Suspend the account pending investigation if broader compromise — not just this one registration — is suspected.',
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
