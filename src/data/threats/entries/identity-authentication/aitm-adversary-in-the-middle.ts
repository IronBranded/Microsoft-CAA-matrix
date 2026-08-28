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
      logSourceId: 'sign-in-logs',
      source: 'Entra ID SigninLogs',
      artifact:
        'A successful sign-in for a session/token later reused from a materially different IP address or device — the replay of a stolen cookie from attacker infrastructure, separate from the sign-in the victim actually completed',
    },
    {
      logSourceId: 'sign-in-logs',
      source: 'Entra ID SigninLogs',
      artifact: "The originating IP on the initial sign-in resolving to known reverse-proxy/phishing infrastructure ranges rather than the victim's typical residential or corporate range",
    },
    {
      logSourceId: 'cloud-app-events',
      source: 'Microsoft Defender for Cloud Apps',
      artifact:
        "The named Defender alert 'Suspicious activity likely indicative of a connection to an adversary-in-the-middle (AiTM) phishing site' — a specific, documented alert title rather than a generic anomaly score, worth alerting on directly rather than only hunting for it manually.",
    },
    {
      logSourceId: 'unified-audit-log',
      source: 'OfficeActivity — mail flow / message headers',
      artifact:
        "Phishing lures delivered via legitimate bulk-email infrastructure (SendGrid and similar services) disguised as payment or receipt notifications — a documented delivery pattern for EvilProxy-based AiTM activity generally. A spike in mail from these services to a small set of users shortly before an anomalous-token detection is a meaningful correlation, not a coincidence.",
    },
    {
      source: 'OfficeActivity (SharePoint) + SigninLogs',
      artifact:
        "A SharePoint file-share notification immediately preceding an AiTM sign-in — SharePoint sharing notifications are a documented initial lure delivery mechanism for multi-stage attacks that pivot from AiTM into BEC via inbox rules. If present, this pattern also produces two other named signals worth checking directly: 'Unfamiliar Signin Correlation with AzurePortal Signin Attempts and AuditLogs' and 'Multiple users email forwarded to same destination'.",
    },
    {
      logSourceId: 'identity-protection-risk-data',
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
      "AiTM activity today is overwhelmingly delivered through phishing-as-a-service (PhaaS) kits — Tycoon2FA is currently the dominant platform by volume, with Evilginx and EvilProxy as the other widely-used open-source/commercial proxy frameworks. This matters for detection because these kits' proxy infrastructure and page templates are well-fingerprinted; a fresh Defender TI or threat-intel feed lookup against the observed proxy domain is often faster than building detection from first principles.",
      "There is deliberately no relevantErrorCodes entry for this scenario: a well-executed AiTM proxy produces a fully successful sign-in with no distinguishing AADSTS code at all, which is precisely what makes it dangerous — the risk-detection and session-correlation signals above are the only real handle DFIR has on it.",
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

  authFlow: {
    pattern: 'sequence',
    narrative:
      "The relayed authentication itself is deliberately unremarkable — that's the whole design of an AiTM proxy. The AADSTS-level view of the victim's own sign-in looks completely normal, MFA included; this entry's own correlationMarkers note above explains why there's no relevantErrorCodes entry at all. What actually creates a detectable signature is downstream of the token, not in how it was obtained: the same session/token reused from a materially different context.",
    steps: [
      {
        code: '0',
        label: "Victim completes a genuinely real sign-in, including MFA, through the attacker's transparent proxy",
        detail: "Indistinguishable from a legitimate sign-in at the AADSTS level — the proxy relays real traffic to the real Microsoft endpoint. This is precisely why there's no relevantErrorCodes entry on this scenario; there's nothing here to flag.",
      },
      {
        code: 'cookie-captured',
        label: "Session cookie captured by the proxy as it's issued",
        detail: "No separate Entra ID telemetry — this happens on the attacker's infrastructure, sitting between the victim and the real sign-in response.",
      },
      {
        code: '0',
        label: 'Cookie replayed from attacker infrastructure',
        detail: "Same session/token identifier as the first step's success, now appearing from a materially different IP, device, or location. This — not the original sign-in — is the actual detection point, and it's what the correlationMarkers and KQL above are built around.",
      },
    ],
    distinguishingNotes:
      "Resist framing this as a code-based detection problem — it isn't one. The two success events (original and replay) are each, individually, completely ordinary AADSTS 0s. The signal lives entirely in comparing session/token identifiers across sign-ins with inconsistent context, which is a correlation problem, not a code-lookup one. If you find yourself searching for an AiTM-specific error code, that search will come back empty by design.",
  },

  tokenTimeline: {
    issuance:
      "Issued once, at the victim's genuinely real (proxied) sign-in — the replay doesn't mint a new token, it reuses the one already issued. Same fundamental shape as token-theft-session-hijacking, just with a specific, well-fingerprinted delivery mechanism (the AiTM proxy) rather than malware or LSASS access.",
    expiration:
      "Standard token lifetimes, with the same Continuous Access Evaluation caveat as elsewhere in this matrix — a stolen token can outlive its nominal expiry if nothing triggers revocation in the meantime. See token-theft-session-hijacking for the fuller CAE discussion, which applies identically here.",
    authInstant:
      "auth_time stays fixed to the original phishing moment across any subsequent refreshes, exactly as this entry's own correlationMarkers already note — the basis for the auth_time-matching technique in the investigate runbook. Optional claim; a captured token may not carry it.",
    authMethods:
      "amr reflects whatever real MFA method the victim actually used to get through the proxy — genuinely accurate, since the victim really did complete that authentication. This is exactly what makes AiTM dangerous: amr shows real, strong-looking factors even though the resulting session is fully attacker-controlled. Phishing-resistant methods (FIDO2, Windows Hello for Business) are the exception — their cryptographic origin-binding is what actually stops a proxy from relaying them successfully, not anything visible in amr after the fact.",
    mfaInstant:
      "SigninLogs.AuthenticationDetails on the original (proxied) sign-in shows a real, on-time MFA completion — there's no timing anomaly to find here, unlike some other scenarios in this matrix. The anomaly is entirely in the IP/device/location mismatch on the later replay, not in when MFA happened.",
    otherContext:
      "Because every individual event in this flow is genuinely ordinary, this is one of the strongest cases in the whole matrix for leaning on Identity Protection's purpose-built risk detections (anomalousToken, tokenIssuerAnomaly) rather than trying to hand-build detection logic from token claims.",
  },

  runbook: {
    triage: [
      "Identify the flagged sign-in(s) and confirm whether Identity Protection's anomalous-token detection actually fired, or whether this surfaced by other means (user report, help desk).",
      'Pull every SigninLogs entry sharing the same session/correlation identifiers to see every IP/device/location the "same" authenticated session touched.',
      'Determine what app/resource the phishing lure actually targeted — the AiTM proxy has to pick a specific target app to relay to.',
      "Check whether the user's account is covered by Conditional Access Token Protection — if not, that's both why the theft succeeded and the first thing to fix.",
    ],
    contain: [
      'Revoke the sessions and tokens immediately: `Revoke-MgUserSignInSession -UserId <UPN>`.',
      "Reset the user's password too — the same phishing page frequently captures it as well, even though token theft alone doesn't strictly require a password reset to contain: `Update-MgUser -UserId <UPN> -PasswordProfile @{ Password = '<new password>'; ForceChangePasswordNextSignIn = $true }`.",
      'Block the phishing domain and proxy infrastructure at your email security and web filtering layers.',
      "If there's any indication the attacker used the session to register their own MFA method, remove it and force re-registration: `Get-MgUserAuthenticationMethod -UserId <UPN>` to find the ID, then the method-specific removal cmdlet.",
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
