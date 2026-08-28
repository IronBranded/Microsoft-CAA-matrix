import type { ThreatEntry } from '../../../../types/threat'

const entry: ThreatEntry = {
  id: 'mfa-fatigue-push-bombing',
  title: 'MFA Fatigue / Push Bombing',
  domain: 'identity-authentication',
  category: 'Credential Access',
  severity: 'medium',
  status: 'complete',
  shortDesc: 'Repeatedly triggering push-based MFA prompts to wear down a user into approving one by accident or out of annoyance.',
  description:
    "Once an attacker has a valid password, triggering repeated Microsoft Authenticator push notifications — often late at night or in rapid succession — banks on the target eventually tapping Approve just to make the prompts stop, or mistaking it for a legitimate sign-in. Number-matching and additional context in push prompts substantially reduce this risk, but tenants that haven't enabled these mitigations remain exposed.",

  forensicArtifacts: [
    {
      logSourceId: 'sign-in-logs',
      source: 'Entra ID SigninLogs',
      artifact: 'Multiple consecutive MFA push notification attempts for the same user within a short window, most showing a denial or timeout before an eventual approval',
    },
    {
      logSourceId: 'sign-in-logs',
      source: 'Entra ID SigninLogs',
      artifact: "The approving sign-in's time-of-day and IP compared to the account's normal pattern — push bombing often succeeds late at night or during a moment the user is likely to approve reflexively",
    },
    {
      source: 'Microsoft Authenticator',
      artifact:
        "Whether number matching was enabled and used correctly — a push approved without the correct number entered is a strong signal the approval was made carelessly. Also check whether the user tapped 'Report suspicious activity' on any of the denied prompts rather than just dismissing them — this specifically flags the account's risk state and is a distinct, stronger signal than a plain denial, but only if users know the feature exists and use it.",
    },
    {
      logSourceId: 'identity-protection-risk-data',
      source: 'Entra ID Identity Protection',
      artifact: "'MFA fatigue' or unusual MFA prompt volume risk detection, if configured",
    },
    {
      source: 'User report',
      artifact: 'The user themselves reporting unexpected push notifications — often the most direct signal',
    },
  ],

  telemetry: {
    correlationMarkers: [
      'Push count and timing density are the core signal — a handful of pushes over hours looks very different from a dozen in ten minutes.',
      'Number matching, if enabled, changes the shape of what a successful fatigue attack looks like — without it, a random tap approves; with it, the user has to actively enter a displayed number, a meaningfully higher bar.',
      "The eventual successful approval's context compared to the account's baseline helps distinguish a fatigue-induced accidental approval from a legitimate delayed response.",
    ],
    relevantErrorCodes: [
      {
        code: 'AADSTS50074',
        type: 'Multi-Factor Authentication',
        description: 'UserStrongAuthClientAuthNRequiredInterrupt — strong authentication is required and the user did not pass the MFA challenge.',
        dfirValue: "Each denied or ignored push in the bombing sequence produces this code — the volume and timing density of these across a short window is the triage query's actual signal, ending in the one approval that broke the pattern.",
      },
    ],
  },

  mitre: [{ id: 'T1621', name: 'Multi-Factor Authentication Request Generation', tactic: 'Credential Access' }],

  kql: {
    sentinel: {
      triage: {
        title: 'MFA prompt bursts',
        query: `SigninLogs
| where TimeGenerated > ago(1d)
| where AuthenticationRequirement == "multiFactorAuthentication"
| summarize PromptCount = count(), Results = make_set(ResultType) by UserPrincipalName, bin(TimeGenerated, 15m)
| where PromptCount > 5
| order by PromptCount desc`,
      },
      investigate: {
        title: 'Successful sign-in following a prompt burst',
        query: `SigninLogs
| where TimeGenerated > ago(1d)
| where ResultType == "0"
| where AuthenticationRequirement == "multiFactorAuthentication"
| project TimeGenerated, UserPrincipalName, IPAddress, Location, DeviceDetail
| order by TimeGenerated desc`,
      },
    },
    defender: {
      triage: {
        title: 'MFA prompt volume',
        query: `CloudAppEvents
| where Timestamp > ago(1d)
| where ActionType has "MFA"
| summarize PromptCount = count() by AccountDisplayName, bin(Timestamp, 15m)
| where PromptCount > 5
| order by PromptCount desc`,
      },
    },
  },

  authFlow: {
    pattern: 'cluster',
    narrative:
      "There's no single ordered path here the way there is in a token-theft or phishing flow — what a fatigue attack produces in SigninLogs is a cluster of near-identical MFA challenge codes repeating in a tight window, distinguished from routine denied-then-retried MFA only by volume and density. The one code that breaks the pattern (a success) is the point of the exercise, not a separate causal step building on the others.",
    steps: [
      {
        code: '50074',
        label: 'Strong auth required, prompt sent',
        detail: 'The routine per-attempt code. On its own this is completely unremarkable — every MFA challenge produces it while pending.',
      },
      {
        code: '50074',
        label: 'Prompt denied or timed out',
        detail: "Same code as above — Entra ID doesn't distinguish a user-denied push from a timed-out one at the ResultType level. Repeated instances of this within minutes, for the same user, is the actual signal; see the triage query, which counts rather than inspects any single event.",
      },
      {
        code: '0',
        label: 'Eventual approval',
        detail: 'The tap that ends the sequence. Nothing about this event is technically different from a legitimate MFA approval — same code, same claims. Only its position at the tail of an unusually dense prompt cluster marks it as suspicious.',
      },
    ],
    distinguishingNotes:
      "A single 50074 followed by a 0 minutes later is completely normal MFA behavior — most people fumble a push once or twice. What marks this as fatigue rather than routine friction is density: several 50074s inside a short window for one user, per the triage query's own threshold. There's no code that means \"this was bombing\" — only a count that crosses a line you have to set for your own environment.",
  },

  tokenTimeline: {
    issuance:
      'Issued at the moment of the successful approval, whichever push that turns out to be. Nothing about the token itself is unusual — the victim genuinely completed a real MFA challenge, just not necessarily on purpose.',
    expiration:
      'Standard access/refresh token lifetimes. No PRT or device-registration escalation is inherent to this technique on its own — the attacker only has whatever the password-plus-one-approval combination grants, unless they chain into a separate escalation step afterward.',
    authInstant:
      "auth_time, where present, pins to the successful approval and is indistinguishable from a legitimate one at the claim level. Optional claim — don't assume it's there.",
    authMethods:
      "amr shows the MFA method actually used (typically an authenticator-app push) exactly as it would for a legitimate sign-in — the claim has no concept of 'approved under duress from repetition.' This is not a place to look for the signal.",
    mfaInstant:
      "SigninLogs.AuthenticationDetails carries the per-push timestamps that make the density pattern visible in the first place — this is a case where the MFA timing detail in the sign-in log is doing essentially all the diagnostic work, more so than in most other Domain 1 scenarios.",
    otherContext:
      "This technique assumes the password is already compromised — it's a second-factor bypass, not a first-factor one. The password-compromise vector itself (spray, stuffing, a prior phish, a credential-stuffing list) is a separate open question worth chasing in parallel; push-bombing telemetry alone won't answer it.",
  },

  runbook: {
    triage: [
      "Confirm the push volume/timing against the user's own account of what happened.",
      'Identify whether number matching was enabled and whether it was actually used correctly.',
      "Check the eventual approving sign-in's context against the account's baseline.",
    ],
    contain: [
      'Revoke active sessions from the approved sign-in: `Revoke-MgUserSignInSession -UserId <UPN>` (Microsoft.Graph.Users.Actions module, User.RevokeSessions.All scope).',
      "Reset the account's password as a precaution: `Update-MgUser -UserId <UPN> -PasswordProfile @{ Password = '<new password>'; ForceChangePasswordNextSignIn = $true }`.",
      "If there's real doubt about which approval was legitimate, don't just trust the existing MFA method going forward — list it and remove it. `Get-MgUserAuthenticationMethod -UserId <UPN>` to find the method ID, then the method-specific removal cmdlet, e.g. `Remove-MgUserAuthenticationMicrosoftAuthenticatorMethod -UserId <UPN> -MicrosoftAuthenticatorAuthenticationMethodId <id>` — then have the user re-register from a known-good device.",
    ],
    investigate: [
      'Determine what the attacker did with the access gained.',
      'Check whether this account was targeted specifically or as part of a broader spray of push-bombing attempts across many accounts.',
    ],
    recover: [
      'Enable number matching tenant-wide if not already.',
      'Enable and tune Identity Protection risk detections for MFA fatigue patterns.',
      'Train users specifically to report, not just dismiss, unexpected push notifications.',
      "Consider moving privileged accounts to phishing-resistant MFA, which isn't vulnerable to this pattern at all.",
    ],
  },
}

export default entry
