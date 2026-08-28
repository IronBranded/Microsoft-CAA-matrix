import type { ThreatEntry } from '../../../../types/threat'

const entry: ThreatEntry = {
  id: 'illicit-consent-grant-oauth-phishing',
  title: 'Illicit Consent Grant / OAuth Phishing',
  domain: 'app-workload-identity',
  category: 'Initial Access / Credential Access',
  severity: 'high',
  status: 'complete',
  shortDesc:
    'An attacker registers a malicious OAuth app and phishes a user into granting it delegated Graph permissions, gaining durable API access to their data without ever needing a password.',
  description:
    'The attacker registers an app — often disguised with a legitimate-sounding name and logo — and sends a phishing link that starts a real Microsoft OAuth authorization flow requesting broad delegated permissions (Mail.Read, Files.ReadWrite.All, offline_access). If the user clicks "Accept" and no admin consent policy blocks it, the attacker\'s app receives a refresh token valid for as long as the consent stands. Because this is an app-level grant rather than a session, it survives password resets and, depending on the permissions granted, can survive MFA re-registration too.',

  forensicArtifacts: [
    {
      logSourceId: 'entra-audit-logs',
      source: 'Entra ID AuditLogs',
      artifact: "OperationName == 'Consent to application' performed by the affected user themselves against an unfamiliar or newly-registered application",
    },
    {
      logSourceId: 'entra-audit-logs',
      source: 'Entra ID AuditLogs',
      artifact: "TargetResources showing the exact delegated scopes granted — especially 'offline_access', which is what makes the grant durable via refresh tokens",
    },
    {
      source: 'Entra ID App registrations',
      artifact: "The consented app's publisher verification status (unverified is a strong signal), creation date, and reply URL/redirect URI pointing to a non-Microsoft domain",
    },
    {
      source: 'CloudAppEvents / OfficeActivity',
      artifact: "Graph API or Exchange Online activity performed by the application's Service Principal immediately following the consent grant",
    },
    {
      logSourceId: 'cloud-app-events',
      source: 'Microsoft Defender for Cloud Apps',
      artifact: "OAuth app anomaly alerts such as 'Suspicious OAuth app file download activity' or 'Misleading OAuth app name', if licensed",
    },
    {
      source: 'Entra ID App registrations',
      artifact:
        "App display name and logo impersonating a specific, real business tool (a CRM data-loader utility, a common productivity integration) rather than a generic or obviously-fake name — disguising a malicious app as a plausible, expected admin/integration tool is the current dominant pattern, not the more easily-spotted generic-name registrations of a few years ago.",
    },
    {
      logSourceId: 'entra-audit-logs',
      source: 'Entra ID AuditLogs — absence as the signal',
      artifact:
        "A technique known as 'ConsentFix' specifically avoids the app registration and consent-prompt steps this entry's other artifacts depend on: it abuses a pre-trusted first-party application's OAuth authorization code flow directly, inheriting the victim's delegated permissions without any new app or 'Consent to application' event ever appearing. If the standard consent-grant artifacts above are absent but SigninLogs/OfficeActivity still show unexplained delegated-scope API activity, this is why — check the client AppId against Microsoft's own first-party app list rather than assuming a clean audit trail means nothing happened.",
    },
  ],

  telemetry: {
    correlationMarkers: [
      'AppId / Service Principal object ID of the consented app: pivot across AuditLogs (the consent event), CloudAppEvents/OfficeActivity (post-consent API activity), and SigninLogs.',
      "ConsentType on the audit event: 'Principal' (a single user granted it) vs 'AllPrincipals' (an admin granted tenant-wide consent) — the latter is far more severe and should be triaged immediately.",
      "Requested scopes containing 'offline_access': this is what grants a refresh token, making access durable rather than a one-time code.",
    ],
    relevantErrorCodes: [
      {
        code: 'AADSTS65001',
        type: 'Consent Required',
        description: 'The user or administrator has not consented to use the application.',
        dfirValue:
          "A preceding AADSTS65001 immediately before a successful 'Consent to application' audit event pinpoints the exact moment the user clicked through the OAuth prompt.",
      },
    ],
  },

  mitre: [
    { id: 'T1528', name: 'Steal Application Access Token', tactic: 'Credential Access' },
    { id: 'T1566.002', name: 'Spearphishing Link', tactic: 'Initial Access' },
  ],

  atrm: [{ id: 'AZT203', name: 'Malicious Application Consent', tactic: 'Initial Access' }],

  kql: {
    sentinel: {
      triage: {
        title: 'User-initiated consent grants',
        query: `// Flag consent grants performed by the end user themselves (not an admin).
AuditLogs
| where TimeGenerated > ago(14d)
| where OperationName == "Consent to application"
| extend AppDisplayName = tostring(TargetResources[0].displayName)
| extend InitiatedByUser = tostring(InitiatedBy.user.userPrincipalName)
| project TimeGenerated, InitiatedByUser, AppDisplayName, Result, CorrelationId
| order by TimeGenerated desc`,
      },
      investigate: {
        title: "Suspect app's post-consent activity",
        description:
          'OfficeActivity coverage of raw Graph calls is partial without Microsoft Graph Activity Logs enabled — see the Data Exfiltration domain for a query against that table.',
        query: `let suspect_app = "<AppId from triage step>";
OfficeActivity
| where TimeGenerated > ago(14d)
| where ClientAppId == suspect_app or AppAccessContext has suspect_app
| project TimeGenerated, UserId, Operation, OfficeWorkload, ClientIP, ResultStatus
| order by TimeGenerated desc`,
      },
    },
    defender: {
      triage: {
        title: 'OAuth consent activity',
        query: `CloudAppEvents
| where Timestamp > ago(14d)
| where ActionType has_any ("Consent to application", "OAuth")
| project Timestamp, AccountDisplayName, ActionType, Application, RawEventData
| order by Timestamp desc`,
      },
    },
  },

  authFlow: {
    pattern: 'sequence',
    narrative:
      'This is a genuinely interactive flow — the victim really does see and click through a real Microsoft consent prompt, which is what makes it effective. The deception is entirely in what app is asking, not in the platform surface doing the asking.',
    steps: [
      {
        code: '65001',
        label: 'Consent Required — user reaches the OAuth authorization prompt for an app they have not yet approved',
        detail: 'A normal, expected code at this stage of any first-time OAuth consent flow, malicious or not. Its value here is purely as a timing anchor — the moment immediately preceding consent.',
      },
      {
        code: 'consent-granted',
        label: 'User accepts the prompt (AuditLogs: Consent to application)',
        detail: 'The actual grant. ConsentType (Principal vs AllPrincipals) and whether offline_access is among the scopes are the two things that most determine severity from this single event.',
      },
      {
        code: '0',
        label: "The app's service principal begins using the granted scopes",
        detail: 'A normal delegated-permission token issuance and use — nothing here looks different from a legitimate app the user genuinely intended to authorize.',
      },
    ],
    distinguishingNotes:
      "Watch for the absence variant, not just the presence variant: the ConsentFix technique noted in forensicArtifacts skips the app-registration and consent-prompt steps entirely by riding a pre-trusted first-party app's own authorization flow, so this code sequence never appears at all for that path. Unexplained delegated-scope activity with no matching consent event in AuditLogs is the tell — check the client AppId against Microsoft's first-party app list before concluding a clean audit trail means nothing happened.",
  },

  tokenTimeline: {
    issuance:
      'The refresh token is issued at the moment of consent, not derived from any later action — offline_access in the granted scopes is specifically what makes a refresh token part of the grant at all, rather than a one-time authorization code.',
    expiration:
      "This is the entry's defining characteristic: the grant persists independent of the user's own credential lifecycle. A password reset doesn't revoke it. MFA re-registration doesn't revoke it. Only removing the app's service principal or the specific OAuth2 permission grant actually ends it — see the runbook contain steps, which is why they're structured the way they are.",
    authInstant:
      'auth_time reflects the original consent-flow sign-in, which for a returning session may itself have happened well before the consent click if the user was already signed in. Less useful here than in Domain 1, since the interesting timestamp for this scenario is the consent AuditLogs event, not any token claim.',
    authMethods:
      "amr reflects whatever the user's normal sign-in required — this scenario doesn't depend on or interact with MFA strength at all. A phishing-resistant MFA method stops credential theft; it does nothing to stop a user from clicking Accept on a consent prompt.",
    mfaInstant: 'Not the relevant clock here. The moment that matters is the consent grant itself, in AuditLogs, not any MFA completion in SigninLogs.',
    otherContext:
      "This is one of the few Domain 4 scenarios where the durable artifact is neither a token nor a credential in the usual sense — it's a standing authorization grant, tracked as its own object (the OAuth2PermissionGrant) independent of any specific token. Investigate and remediate at that layer, not by chasing individual tokens.",
  },

  runbook: {
    triage: [
      'Pull the consent audit event: who consented (self vs. admin), which app, and exactly which scopes.',
      "Check the app's publisher verification status and creation date — unverified plus recently created is high-confidence malicious.",
      "Determine whether 'offline_access' was among the granted scopes versus a one-time authorization code.",
      'Identify how many other users in the tenant have consented to the same application, to size the blast radius.',
    ],
    contain: [
      "Disable or delete the malicious app's service principal: `Remove-MgServicePrincipal -ServicePrincipalId <id>` — this immediately invalidates all its tokens and refresh tokens tenant-wide.",
      "If removing tenant-wide isn't immediately feasible, revoke the specific user-to-app grant instead: `Remove-MgOauth2PermissionGrant -OAuth2PermissionGrantId <id>`.",
      "Revoke the affected user's own sessions as a precaution, since the phishing lure may have also harvested other credentials: `Revoke-MgUserSignInSession -UserId <UPN>`.",
      'Enable or tighten the admin consent workflow so future grants for high-risk scopes require administrator review.',
    ],
    investigate: [
      "Review everything the app's service principal accessed via its granted scopes, using OfficeActivity/CloudAppEvents/Microsoft Graph Activity Logs.",
      'Check AuditLogs for any credentials (client secrets/certificates) added to the malicious app registration afterward, indicating attacker-maintained persistence into the app itself.',
      'Identify and notify any other users tenant-wide who consented to the same application.',
      'Trace the phishing delivery vector to identify the initial lure and whether it reached other targets.',
    ],
    recover: [
      'Confirm the app registration is fully removed/disabled and its refresh tokens no longer work.',
      'Tighten tenant-wide user consent policy — restrict to admin-verified publishers, or require admin approval for high-risk scopes.',
      'Deploy Microsoft Defender for Cloud Apps OAuth app governance policies, if licensed, for ongoing automated detection.',
      'Brief users specifically on OAuth consent phishing — the prompt looks like a real Microsoft login page because it is one; the deception is in the app identity, not a spoofed domain.',
    ],
  },
}

export default entry
