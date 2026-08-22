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

  runbook: {
    triage: [
      "Confirm the push volume/timing against the user's own account of what happened.",
      'Identify whether number matching was enabled and whether it was actually used correctly.',
      "Check the eventual approving sign-in's context against the account's baseline.",
    ],
    contain: [
      'Revoke sessions from the approved sign-in.',
      "Reset the account's password as a precaution.",
      "Require re-registration of MFA if there's doubt about which approval was legitimate.",
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
