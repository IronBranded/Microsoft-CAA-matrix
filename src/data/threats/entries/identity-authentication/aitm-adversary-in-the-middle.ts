import type { ThreatEntry } from '../../../../types/threat'

const entry: ThreatEntry = {
  id: 'aitm-adversary-in-the-middle',
  title: 'AiTM — Adversary-in-the-Middle Phishing',
  domain: 'identity-authentication',
  category: 'Initial Access / Credential Access',
  severity: 'critical',
  status: 'complete',
  shortDesc:
    'A reverse-proxy phishing kit sits between the user and the real Microsoft login page, harvesting the live, post-MFA session cookie in real time.',
  description:
    "Unlike traditional credential phishing, AiTM kits proxy the victim's entire session to the real Microsoft sign-in flow — the user really does authenticate, and really does complete MFA — while the attacker's proxy captures the resulting session cookie as it's issued. This defeats most MFA methods that don't involve phishing-resistant standards like FIDO2/passkeys, since the attacker isn't guessing a code, they're stealing the fully-authenticated session itself.",

  forensicArtifacts: [
    {
      source: 'Entra ID SigninLogs',
      artifact:
        'A successful sign-in for a session/token later reused from a materially different IP address or device — the replay of a stolen cookie from attacker infrastructure, separate from the sign-in the victim actually completed',
    },
    {
      source: 'Entra ID SigninLogs',
      artifact: "The originating IP on the initial sign-in resolving to known reverse-proxy/phishing infrastructure ranges rather than the victim's typical residential or corporate range",
    },
    {
      source: 'Microsoft Defender for Cloud Apps',
      artifact: 'Built-in alerts tuned specifically for AiTM patterns — suspicious session cookie reuse and related token-replay detections',
    },
    {
      source: 'Entra ID Identity Protection',
      artifact: "'Anomalous token' and 'token issuer anomaly' risk detections, which Identity Protection maintains specifically for this scenario",
    },
    {
      source: "JWT Token Claims (if captured)",
      artifact: 'The `auth_time` claim staying fixed to the original phishing moment across any subsequent refreshes — decode a captured token and match it against Interactive SigninLogs, the same technique used for device code phishing',
    },
  ],

  telemetry: {
    correlationMarkers: [
      'The same session/token identifier reused across two sign-ins with materially different IP, device, or location properties is the core signal — the legitimate auth completes once, and the stolen cookie gets replayed separately.',
      "auth_time in the token stays fixed to the original phishing moment across any subsequent refreshes.",
      "Because the AiTM proxy relays the victim's real browser/device signals during the initial phish, device-compliance Conditional Access may not block the initial theft — Conditional Access Token Protection, which invalidates the token when replayed from a different device, is the control actually designed to defeat this, rather than trying to catch the phishing page in the moment.",
    ],
  },

  mitre: [
    { id: 'T1557', name: 'Adversary-in-the-Middle', tactic: 'Credential Access' },
    { id: 'T1550.004', name: 'Use Alternate Authentication Material: Web Session Cookie', tactic: 'Defense Evasion' },
  ],

  kql: {
    sentinel: {
      triage: {
        title: 'Identity Protection risk detections tuned for token theft',
        description:
          'Prefer these purpose-built detections over reinventing impossible-travel logic — Identity Protection is specifically tuned for this pattern. Exact RiskEventType string casing may vary slightly from the display name; if this returns nothing, check the AADUserRiskEvents schema in your workspace.',
        query: `AADUserRiskEvents
| where TimeGenerated > ago(7d)
| where RiskEventType in ("anomalousToken", "tokenIssuerAnomaly", "suspiciousAPITraffic")
| project TimeGenerated, UserPrincipalName, RiskEventType, RiskLevel, RiskState, IpAddress, Location
| order by TimeGenerated desc`,
      },
      investigate: {
        title: 'Sign-in activity for flagged users',
        description: 'Pivots from a risky sign-in to what the session did across the tenant.',
        query: `let risky_users = AADUserRiskEvents
| where TimeGenerated > ago(7d)
| where RiskEventType in ("anomalousToken", "tokenIssuerAnomaly")
| distinct UserPrincipalName;
SigninLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName in (risky_users)
| project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName, Location, CorrelationId
| order by TimeGenerated desc`,
      },
    },
    defender: {
      triage: {
        title: 'AiTM / session cookie replay alerts',
        description:
          'Microsoft documents that Defender for Cloud Apps connectors and Defender for Endpoint raise AiTM-specific alerts; exact ActionType string values are worth confirming against your own tenant rather than assumed from this query alone.',
        query: `CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType has_any ("AiTM", "Suspicious session cookie", "Token replay")
| project Timestamp, AccountDisplayName, ActionType, IPAddress, RawEventData
| order by Timestamp desc`,
      },
    },
  },

  runbook: {
    triage: [
      "Identify the flagged sign-in(s) and confirm whether Identity Protection's anomalous-token detection actually fired, or whether this surfaced by other means (user report, help desk).",
      'Pull every SigninLogs entry sharing the same session/correlation identifiers to see every IP/device/location the "same" authenticated session touched.',
      'Determine what app/resource the phishing lure actually targeted — the AiTM proxy has to pick a specific target app to relay to.',
      "Check whether the user's account is covered by Conditional Access Token Protection — if not, that's both why the theft succeeded and the first thing to fix.",
    ],
    contain: [
      'Revoke the sessions and tokens immediately: `Revoke-MgUserSignInSession`.',
      "Reset the user's password as a precaution — the same phishing page frequently captures it too, even though token theft alone doesn't strictly require a password reset to contain.",
      'Block the phishing domain and proxy infrastructure at your email security and web filtering layers.',
      'Force MFA re-registration if there is any indication the attacker used the session to register their own MFA method.',
    ],
    investigate: [
      'Reconstruct what the stolen session was used for between theft and revocation, via AuditLogs/OfficeActivity/CloudAppEvents on the shared correlation/session identifiers.',
      'Check for persistence set during the compromised window — new OAuth app consents, new MFA methods, new forwarding rules, new app registrations.',
      'Identify how the phishing lure was delivered and whether it reached other users.',
      'If a raw token was captured, decode it and match `auth_time` against Interactive SigninLogs to pin down the exact phishing moment.',
    ],
    recover: [
      'Enable Conditional Access Token Protection for high-value users and apps at minimum — the control specifically designed to make a replayed AiTM token useless on any device but the one it was issued to.',
      'Move privileged accounts toward phishing-resistant authentication (FIDO2, Windows Hello for Business, certificate-based auth), since AiTM specifically defeats OTP/push-based MFA.',
      'Tune Identity Protection risk policies to automatically challenge or block on anomalous-token detections rather than only alerting.',
      'Run user awareness training on this specific pattern — the login page in an AiTM attack is functionally real, so URL/domain scrutiny matters more than generic phishing advice.',
    ],
  },
}

export default entry
