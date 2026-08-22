import type { ThreatEntry } from '../../../../types/threat'

const entry: ThreatEntry = {
  id: 'token-theft-session-hijacking',
  title: 'Token Theft / Session Hijacking',
  domain: 'identity-authentication',
  category: 'Credential Access',
  severity: 'high',
  status: 'complete',
  shortDesc: "Stealing ESTSAUTH cookies, access tokens, or Primary Refresh Tokens directly from an endpoint to impersonate a user without their password.",
  description:
    "Malware or an attacker with local access to a compromised endpoint can extract browser session cookies, cached OAuth access/refresh tokens, or the device's Primary Refresh Token from browser storage, LSASS memory, or the token cache. Because these artifacts represent an already-completed, already-MFA'd authentication, replaying them elsewhere lets the attacker impersonate the user without needing their password or a fresh MFA challenge. This is the general case that AiTM and PRT-specific abuse elsewhere in this matrix are particular mechanisms of — commodity infostealer malware is the most common source in volume.",

  forensicArtifacts: [
    {
      logSourceId: 'sign-in-logs',
      source: 'Entra ID SigninLogs',
      artifact: 'A session or token reused from an IP or device inconsistent with the original issuance — the core signature of any stolen-and-replayed credential',
    },
    {
      source: 'Endpoint browser storage / EDR',
      artifact: 'Malware or a malicious browser extension with access to cookie storage (ESTSAUTH/ESTSAUTHPERSISTENT) or local token caches',
    },
    {
      logSourceId: 'defender-endpoint-hunting',
      source: 'DeviceProcessEvents / DeviceFileEvents',
      artifact: "A process reading browser profile directories or known token cache locations outside of the browser's own normal operation — the signature of commodity infostealer malware",
    },
    {
      logSourceId: 'sign-in-logs',
      source: 'Entra ID NonInteractiveUserSignInLogs',
      artifact: 'Token refresh activity continuing from a device/IP with no corresponding interactive sign-in — reuse without the original authentication event',
    },
    {
      logSourceId: 'identity-protection-risk-data',
      source: 'Entra ID Identity Protection',
      artifact: "'Anomalous token' risk detection — the same purpose-built signal used for AiTM, since the underlying pattern is shared regardless of how the credential was obtained",
    },
    {
      source: "Entra ID's built-in Continuous Access Evaluation (CAE) workbook",
      artifact:
        "The 'potential IP address mismatch between Microsoft Entra ID and resource provider' table in this Microsoft-provided workbook directly surfaces sessions where the sign-in IP and the resource-access IP diverge — precisely the pattern a replayed token produces, without needing to hand-build the correlation query. Worth checking before writing custom KQL for this.",
    },
  ],

  telemetry: {
    correlationMarkers: [
      'This is the general case that AiTM and Primary Refresh Token Abuse elsewhere in this matrix are specific mechanisms of — the detection principle is shared across all three.',
      'Commodity infostealer malware is a common source of bulk cookie theft, distinct from the more targeted AiTM/PRT techniques — check endpoint telemetry for known infostealer indicators alongside the identity-side signals.',
      'auth_time / iat claim analysis on a captured token pinpoints the original theft moment, the same technique used for device code phishing and AiTM.',
      "If the target resource supports Continuous Access Evaluation, a stolen token can actually have a longer useful lifetime for the attacker than the pre-CAE default (up to 28 hours rather than the standard 60-90 minutes), since CAE trades shorter default expiry for real-time backchannel revocation — but that revocation only helps if something actually triggers it (password reset, session revoke, risk detection). A stolen CAE token that never trips a revocation event outlives what most responders would assume is the token's natural expiry.",
    ],
  },

  mitre: [
    { id: 'T1539', name: 'Steal Web Session Cookie', tactic: 'Credential Access' },
    { id: 'T1528', name: 'Steal Application Access Token', tactic: 'Credential Access' },
  ],

  kql: {
    sentinel: {
      triage: {
        title: 'Anomalous token risk detections',
        query: `AADUserRiskEvents
| where TimeGenerated > ago(7d)
| where RiskEventType == "anomalousToken"
| project TimeGenerated, UserPrincipalName, RiskLevel, RiskState, IpAddress, Location
| order by TimeGenerated desc`,
      },
      investigate: {
        title: 'Sign-in activity for flagged sessions',
        query: `let flagged = AADUserRiskEvents
| where TimeGenerated > ago(7d)
| where RiskEventType == "anomalousToken"
| distinct UserPrincipalName;
SigninLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName in (flagged)
| project TimeGenerated, UserPrincipalName, IPAddress, DeviceDetail, AppDisplayName, CorrelationId
| order by TimeGenerated desc`,
      },
    },
    defender: {
      hunt: {
        title: 'Non-browser process reading browser credential storage',
        description: 'Requires Defender for Endpoint on the device. The classic commodity-infostealer pattern.',
        query: `DeviceProcessEvents
| where Timestamp > ago(7d)
| where FolderPath has_any ("Cookies", "Login Data")
| where InitiatingProcessFileName !in~ ("chrome.exe", "msedge.exe", "firefox.exe")
| project Timestamp, DeviceName, AccountName, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc`,
      },
    },
  },

  runbook: {
    triage: [
      'Identify the theft mechanism — commodity malware, AiTM, or another vector — and confirm the session-reuse pattern.',
      'Scope which app/resource the stolen credential was used against.',
      "Check the source endpoint for known infostealer malware indicators.",
      "Determine the credential's actual privilege — a stolen token for a privileged account is a different severity than for a standard user.",
    ],
    contain: [
      'Revoke sessions and tokens (`Revoke-MgUserSignInSession`).',
      "Reset the user's password as a precaution.",
      'Run malware scan/remediation on the source endpoint.',
      "Block the attacker's identified infrastructure at the network layer.",
    ],
    investigate: [
      'Reconstruct what the stolen session was used for before revocation.',
      'Identify the malware family and infection vector on the source endpoint, if applicable.',
      'Check for persistence set during the compromised window.',
      'If a raw token was captured, decode it and match `auth_time` against Interactive SigninLogs.',
    ],
    recover: [
      'Enable Conditional Access Token Protection for high-value users and apps.',
      'Deploy and tune anti-malware / browser protection on managed endpoints.',
      'Review browser extension governance, since many infostealers propagate via malicious extensions.',
      'Run user awareness training on this pattern alongside AiTM-specific training.',
    ],
  },
}

export default entry
