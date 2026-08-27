import type { ThreatEntry } from '../../../../types/threat'

const entry: ThreatEntry = {
  id: 'dynamic-device-code-phishing',
  title: 'Dynamic Device Code Phishing (On-Demand Code Generation)',
  domain: 'identity-authentication',
  category: 'Initial Access / Credential Access',
  severity: 'critical',
  status: 'complete',
  shortDesc:
    'Attacker backend mints the device code live, the moment the victim clicks the lure — resetting the 15-minute expiration on demand and enabling automated, campaign-scale device code phishing.',
  description:
    "A variant of device code phishing where the authorization code is minted in real time by attacker-controlled backend infrastructure at the moment the victim clicks the lure, rather than being pre-generated and embedded in the phishing message. Static device codes expire 15 minutes after issuance, which forces the static variant to race a fixed clock from send-time; delaying generation until click-time means the 15-minute window always starts fresh, removing the single biggest reliability constraint on the technique and making it viable at much larger scale. The lure chain runs through several disposable redirect hops — compromised legitimate domains, brand-impersonating subdomains, and serverless platforms (Cloudflare Workers, AWS Lambda, Railway.com-hosted Node.js backends) — before landing the victim on a page that silently calls Microsoft's real device-authorization endpoint on their behalf, displays the live code, and commonly auto-copies it to the victim's clipboard. A background poller then checks authentication status every few seconds and hands the resulting token to automated post-compromise tooling the moment it succeeds — Graph-driven reconnaissance immediately, then either rogue device registration for Primary Refresh Token persistence or inbox-rule-based mail exfiltration, chosen per victim based on the account's apparent value. The underlying OAuth2 device flow abuse, and the resulting token, are identical to device-code-phishing — see that entry for the shared Authentication Broker / Primary Refresh Token escalation path. What's different here is entirely upstream of the token: infrastructure-automated delivery, on-demand code minting, and a compressed, largely unattended window from lure click to token issuance to first post-compromise action.",

  forensicArtifacts: [
    {
      logSourceId: 'defender-office365-hunting',
      source: 'Defender for Office 365 UrlClickEvents',
      artifact:
        'A URL click event for the same user immediately (commonly within minutes) preceding a successful deviceCode sign-in. This tight click-to-auth window is the clearest fingerprint of on-demand generation — the code cannot have existed before the click, unlike a static/pre-generated code where no such correlation exists. Requires Safe Links to be in scope for the message.',
    },
    {
      logSourceId: 'sign-in-logs',
      source: 'Entra ID SigninLogs / EntraIdSignInEvents',
      artifact:
        "AuthenticationProtocol == 'deviceCode' paired with a CmsiInterrupt (AADSTS50199) on the same CorrelationId/SessionId shortly before the success — the confirmation-prompt pause while the victim reads and enters the displayed code. This pairing is the primary detection signal for this variant; see the kql section below.",
    },
    {
      logSourceId: 'sign-in-logs',
      source: 'Entra ID SigninLogs',
      artifact:
        "Sign-in IPAddress resolving to disposable PaaS/serverless hosting (short-lived Node.js backends on platforms like Railway.com, or Cloudflare Workers / AWS Lambda acting as a proxy) rather than a conventional VPS/VPN range. Treat the infrastructure class as the durable signal — specific IP ranges churn per campaign and get reused by unrelated legitimate tenants on the same platforms, so hardcoding any one range into a long-lived detection is a false-positive risk waiting to happen.",
    },
    {
      logSourceId: 'entra-audit-logs',
      source: 'Entra ID AuditLogs',
      artifact:
        'A new device registration event within roughly 10 minutes of the device-code success, in the subset of cases that pursue the Primary Refresh Token persistence path — noticeably faster than a human operator typically manages, since this step is also automated here.',
    },
    {
      logSourceId: 'cloud-app-events',
      source: 'CloudAppEvents (Exchange Online admin actions)',
      artifact:
        "New-InboxRule / Set-InboxRule / Set-TransportRule events where the rule name consists entirely of non-alphanumeric characters — an observed persistence pattern from this campaign, used so the rule doesn't display a readable name in the mailbox rules UI.",
    },
    {
      logSourceId: 'mail-items-accessed',
      source: 'CloudAppEvents MailItemsAccessed',
      artifact:
        'MailItemsAccessed events flagged with an ISP uncommon for the user — the Graph-driven mailbox reconnaissance this campaign runs immediately after token issuance, prioritized against financial, executive, and administrative personas specifically.',
    },
    {
      source: "Microsoft Entra ID GetCredentialType endpoint (target validation)",
      artifact:
        "Attackers commonly validate a target address exists and is active in the tenant via this endpoint 10-15 days before the actual phishing send. The endpoint doesn't require authentication and this reconnaissance step has no corresponding Entra ID log event — there is no direct artifact to hunt for here. Treat it as a known precursor TTP rather than something discoverable in tenant telemetry after the fact.",
    },
  ],

  telemetry: {
    authenticationProtocols: ['deviceCode'],
    correlationMarkers: [
      'CorrelationId / SessionId: ties a UrlClickEvents click, the CmsiInterrupt, and the eventual success together into one compressed session. The compression itself — minutes, not the hours-to-days gap a mailed static code allows — is the primary signature distinguishing this variant from device-code-phishing, more than any single code in isolation.',
      'RequestId: pivot from the successful sign-in into downstream Graph/Exchange activity, same as device-code-phishing.',
      "The lure chain's redirect hops (compromised domains, brand-impersonating subdomains, serverless proxy endpoints) aren't visible in Entra ID telemetry at all — only in mail flow and URL click telemetry (Defender for Office 365) upstream of the sign-in. Don't expect SigninLogs alone to show the delivery mechanism.",
    ],
    relevantErrorCodes: [
      {
        code: 'AADSTS50199',
        type: 'CmsiInterrupt',
        description: 'For security reasons, user confirmation is required for this request.',
        dfirValue:
          "The primary signal for this variant, not a secondary one. A 50199 immediately followed by a 0 (success) on the same CorrelationId/SessionId is the pairing Microsoft's own published hunting guidance for this technique checks for, since it captures the moment a real user paused to read and enter a device code — true regardless of how or when that code happened to be generated.",
      },
      {
        code: 'AADSTS70016',
        type: 'OAuth2 Device Flow',
        description: 'Authorization pending or user code expired.',
        dfirValue:
          "Less central here than in the static variant. Because the code is minted at click-time rather than pre-generated, a well-executed run of this technique may produce very few of these before success. Frequent 70016 spikes point more toward the static/pre-generated variant, unoptimized tooling, or an abandoned attempt — not toward the absence of an attack.",
      },
      {
        code: 'AADSTS70020',
        type: 'Token Revocation',
        description: 'The provided grant has expired due to it being revoked.',
        dfirValue:
          'Confirms containment succeeded, same as device-code-phishing. Revocation reliably invalidates refresh tokens but can leave an already-issued access token usable for up to an hour — see the runbook contain step below.',
      },
    ],
  },

  mitre: [
    { id: 'T1583.007', name: 'Acquire Infrastructure: Serverless', tactic: 'Resource Development' },
    { id: 'T1566.002', name: 'Spearphishing Link', tactic: 'Initial Access' },
    { id: 'T1204.001', name: 'Malicious Link', tactic: 'Execution' },
    { id: 'T1528', name: 'Steal Application Access Token', tactic: 'Credential Access' },
  ],

  atrm: [{ id: 'AZT201.1', name: 'Valid Credentials: User Account', tactic: 'Initial Access' }],

  kql: {
    sentinel: {
      triage: {
        title: 'Compressed URL-click-to-device-code window',
        description:
          "Requires the Microsoft Defender connector into the Sentinel workspace for UrlClickEvents (Defender for Office 365 Safe Links data) alongside SigninLogs — they don't share a workspace by default. The tight (minutes, not hours) gap between click and a successful deviceCode sign-in is the clearest sign the code was generated on demand rather than mailed pre-generated; a static-code phish shows no such correlation, since that code exists independently of when the victim happens to open the email.",
        query: `let suspiciousClicks = UrlClickEvents
| where TimeGenerated > ago(7d)
| project ClickTime = TimeGenerated, AccountUpn = tolower(AccountUpn), Url;
SigninLogs
| where TimeGenerated > ago(7d)
| where AuthenticationProtocol =~ "deviceCode"
| where ResultType == "0"
| extend AccountUpn = tolower(UserPrincipalName)
| join kind=inner suspiciousClicks on AccountUpn
| where (TimeGenerated - ClickTime) between (0min .. 10min)
| project TimeGenerated, ClickTime, AccountUpn, IPAddress, Url, OriginalRequestId, CorrelationId`,
      },
      investigate: {
        title: 'Symbol-only inbox rule creation',
        description:
          "Campaign-specific persistence artifact: rule names built entirely of non-alphanumeric characters, observed used so the rule doesn't display readably in the mailbox rules UI. For the general CorrelationId-based post-compromise pivot into Graph/Exchange/ARM activity, reuse device-code-phishing's investigate query — the token-side behavior is identical; this only adds the artifact unique to this variant's persistence mechanics. For MailItemsAccessed follow-up, Sentinel's OfficeActivity lacks the UncommonForUser ISP-anomaly enrichment that CloudAppEvents has in Defender (see the defender query below) — treat that as a manual IP/ISP review here rather than an automatic flag.",
        query: `OfficeActivity
| where TimeGenerated > ago(7d)
| where Operation in ("New-InboxRule", "Set-InboxRule", "Set-TransportRule", "New-TransportRule")
| where Name matches regex @"^[^a-zA-Z0-9]+$"
| project TimeGenerated, UserId, Operation, Name, ClientIP`,
      },
    },
    defender: {
      triage: {
        title: 'URL click correlated with risky device code sign-in',
        description:
          'Advanced Hunting equivalent of the Sentinel triage query, following the same click-to-auth correlation. UrlClickEvents and EntraIdSignInEvents are both native Advanced Hunting tables, so no cross-product connector is needed here — unlike the Sentinel version, which needs the Microsoft Defender connector to get UrlClickEvents into the workspace at all. EntraIdSignInEvents replaces the deprecated AADSignInEventsBeta (old queries auto-migrate 2026-10-19).',
        query: `let suspiciousUserClicks = materialize(
    UrlClickEvents
    | where Timestamp > ago(7d)
    | extend AccountUpn = tolower(AccountUpn)
    | project ClickTime = Timestamp, UrlChain, NetworkMessageId, Url, AccountUpn);
let interestedUsersUpn = suspiciousUserClicks | where isnotempty(AccountUpn) | distinct AccountUpn;
EntraIdSignInEvents
| where Timestamp > ago(7d)
| where ErrorCode == 0
| where AccountUpn in~ (interestedUsersUpn)
| where RiskLevelDuringSignIn in (10, 50, 100) // low/medium/high — 0 means "not set" and is excluded on purpose
| extend AccountUpn = tolower(AccountUpn)
| join kind=inner suspiciousUserClicks on AccountUpn
| where (Timestamp - ClickTime) between (-2min .. 10min)
| project Timestamp, ClickTime, AccountUpn, RiskLevelDuringSignIn, SessionId, IPAddress, Url`,
      },
      investigate: {
        title: 'Symbol-only inbox rule creation via CloudAppEvents',
        description:
          "CloudAppEvents equivalent of the Sentinel OfficeActivity query above. ApplicationId 20893 here is Defender for Cloud Apps' own internal app-catalog identifier for Exchange Online — a small integer, not an Entra ID application GUID, which trips people up the first time they see it. MDCA catalog IDs aren't guaranteed stable indefinitely; verify against your tenant before relying on it in production.",
        query: `CloudAppEvents
| where Timestamp > ago(7d)
| where ApplicationId == "20893" // Microsoft Exchange Online, per Defender for Cloud Apps' app catalog — not an Entra ID app GUID
| where ActionType in ("New-InboxRule", "Set-InboxRule", "Set-TransportRule", "New-TransportRule")
| where isnotempty(IPAddress)
| mv-expand ActivityObjects
| extend FieldName = tostring(parse_json(tostring(ActivityObjects)).Name)
| extend FieldValue = tostring(parse_json(tostring(ActivityObjects)).Value)
| where FieldName == "Name"
| where FieldValue matches regex @"^[^a-zA-Z0-9]+$"
| project Timestamp, AccountDisplayName, ActionType, RuleName = FieldValue, IPAddress`,
      },
    },
  },

  authFlow: {
    pattern: 'sequence',
    narrative:
      "The AADSTS-level sequence is nearly identical to device-code-phishing — the distinguishing signal for this variant is timing, not a different set of codes. What marks this as the on-demand variant specifically is the near-zero gap between the upstream lure interaction and the code being minted, visible as a tight time correlation between a URL click event and the SigninLogs/EntraIdSignInEvents entries below, rather than anything in the codes themselves.",
    steps: [
      {
        code: 'url-click',
        label: 'Victim clicks the phishing link',
        detail:
          "No Entra ID telemetry yet. This is the trigger that causes attacker infrastructure to call the real device-authorization endpoint on the victim's behalf — logged only in Defender for Office 365 UrlClickEvents (Safe Links), and only if Safe Links scanning is enabled for the tenant.",
      },
      {
        code: '50199',
        label: 'CmsiInterrupt at the devicelogin confirmation prompt',
        detail:
          'A routine part of the device code flow on its own, not unique to phishing — diagnostic here specifically because of how soon it follows the click above.',
      },
      {
        code: '0',
        label: 'Successful device code authentication',
        detail: "Token issued to the attacker's polling session, typically captured within seconds given automated polling every 3-5 seconds.",
      },
      {
        code: 'device-registration',
        label: 'Rogue device registration via the Authentication Broker, within roughly 10 minutes (observed in a subset of cases)',
        detail:
          "Same escalation path as device-code-phishing — Authentication Broker AppId requesting the Device Registration Service resource, then a new device object in AuditLogs. Not every compromise reaches this step; observed cases split between this path and a slower inbox-rule/exfiltration path chosen per victim based on the account's apparent value.",
      },
    ],
    distinguishingNotes:
      "Don't try to tell this apart from device-code-phishing using the AADSTS codes alone — they overlap almost completely. The tell is the click-to-success gap: minutes here, versus the static variant, where a pre-generated code sits in an email and the usable window is bounded only by the original 15-minute expiration with no upstream click event to correlate against at all if Safe Links isn't in play.",
  },

  tokenTimeline: {
    issuance:
      "Issued the moment the victim completes the devicelogin confirmation — typically captured by the attacker's poller within 3-5 seconds given the automated checkStatus loop this technique relies on. Refresh cadence afterward is unremarkable and matches normal token behavior once the attacker's session starts using it.",
    expiration:
      "Standard access/refresh token lifetimes apply to the initial grant. Where the Authentication Broker / Device Registration Service escalation path is used (see authFlow), effective persistence extends indefinitely via the resulting Primary Refresh Token, independent of the original token's expiration — same as device-code-phishing.",
    authInstant:
      "auth_time, where present, pins to the single interactive moment the victim completed the devicelogin flow and stays static across later refreshes. auth_time is an optional claim — don't assume a captured token will have it. SigninLogs/EntraIdSignInEvents Timestamp on the ResultType 0 event is the reliable anchor regardless of token capture.",
    authMethods:
      "amr reflects whatever authentication the victim's account legitimately required (password, MFA method) — nothing about this technique forces a specific amr value, since the victim is completing a real, unmodified sign-in. amr is absent unless the relying app requested it; don't treat its absence here as suspicious on its own.",
    mfaInstant:
      "SigninLogs.AuthenticationDetails (or EntraIdSignInEvents' equivalent per-event detail) is the reliable source for exactly when MFA completed. In this specific scenario, the CmsiInterrupt-to-success gap in the same table is usually a faster, simpler proxy for the same moment, since that pause is where the victim is reading and entering the code.",
    otherContext:
      "The reconnaissance that selects and validates targets (GetCredentialType queries) typically happens 10-15 days before the token event itself, with no session or token relationship connecting the two — don't expect a single investigable session to explain both. Post-token automation is near-immediate: Graph reconnaissance begins as soon as the token is confirmed valid, well inside the window a human operator would need to log in and start clicking around manually.",
  },

  runbook: {
    triage: [
      'Check whether the successful deviceCode sign-in (ResultType 0) is preceded by a CmsiInterrupt (AADSTS50199) on the same CorrelationId or SessionId within a few minutes — this pairing, more than the deviceCode protocol marker alone, is the highest-fidelity signal for this specific technique.',
      'If Defender for Office 365 Safe Links is in use, pull UrlClickEvents for the same user around the sign-in time. A click landing within minutes of the auth event confirms the on-demand generation pattern; no correlated click at all doesn\'t rule out phishing, but points toward the static/pre-generated variant in device-code-phishing instead.',
      "Identify the AppId requested. Microsoft Graph or Exchange Online is the baseline token-theft case; AppId 29d9ed98-a469-4536-ade2-f981bc1d605e (Authentication Broker) combined with a Device Registration Service resource is the escalation path — jump straight to checking AuditLogs for a new device registration event, same as device-code-phishing.",
      "Check AuditLogs and CloudAppEvents for downstream activity in the minutes immediately after the sign-in. This technique's automated polling and post-compromise tooling act far faster than a human operator, so a large gap between token issuance and any follow-on activity is somewhat atypical here — though not impossible, e.g. if the attacker deliberately delayed for stealth.",
    ],
    contain: [
      'Suspend the compromised account immediately.',
      "Revoke sessions via Microsoft Graph PowerShell (Revoke-MgUserSignInSession). Revocation reliably invalidates refresh tokens but can leave an already-issued access token valid for up to an hour — given this technique's fast, automated post-compromise tooling, that window is meaningful. Disable the account outright rather than relying on revocation alone for immediate containment.",
      "Block the sign-in IP and its hosting endpoint via Named Locations and a blocking Conditional Access policy. Expect the specific IP or hostname to be short-lived and reused across other targets in the same campaign — flag the hosting provider/ASN internally for a broader sweep across recent sign-in IPs tenant-wide, rather than treating the one IP as the full scope.",
      "If the escalation path was used: find and remove any device object registered in the incident window, and check for any new authentication method (security key, Windows Hello for Business credential) registered in that same window — same as device-code-phishing's contain steps.",
      "Purge any inbox rule whose name is entirely non-alphanumeric characters, created since the compromise. This is a known pattern for this campaign, not an exhaustive one — don't assume a rule with an ordinary-looking name is safe to leave unreviewed.",
    ],
    investigate: [
      'Pivot on CorrelationId/SessionId into CloudAppEvents, OfficeActivity, and AzureActivity to reconstruct the full post-compromise timeline — same core pivot as device-code-phishing.',
      "Check MailItemsAccessed for the compromised account, particularly access from an ISP uncommon for that user. Defender for Cloud Apps flags this natively in CloudAppEvents via UncommonForUser; Sentinel's OfficeActivity lacks that enrichment, so this means manually reviewing the IP/ISP of each MailItemsAccessed event against the user's normal pattern.",
      "If the account holds financial, executive, or administrative privileges, treat it as a probable priority target rather than an incidental catch — this campaign specifically filters compromised accounts for these personas before committing to deeper reconnaissance and targeted exfiltration, so the depth of follow-on activity tends to track the account's apparent value.",
      'Check for Graph API reconnaissance (directory enumeration, permission mapping) beginning within minutes of the token event — the compressed timing itself is investigative signal, distinguishing automated tooling from a human operator exploring manually.',
      'If other users in the organization received a similar lure (check Defender for Office 365 campaign views), assume this was a coordinated send rather than a one-off. This technique is deployed at scale by design, and other likely-targeted users are usually identifiable from the same delivery infrastructure or message theme.',
    ],
    recover: [
      "Confirm revocation propagated (AADSTS70020 from the attacker's IP in NonInteractive logs), and reset the password regardless, since revocation's access-token gap makes a reset the more reliable backstop.",
      "Require MFA re-registration from a known-good network, and confirm no device object or authentication method tied to the incident window remains — a password reset alone doesn't remove either.",
      'Sweep other users flagged in the same campaign (see investigate) even if their own sign-in logs show no successful device-code completion — a failed or abandoned attempt on one user is still evidence the same lure reached others.',
      "(Preventative) Restrict device code flow to compliant devices via Conditional Access, same as device-code-phishing. This technique doesn't bypass a device-code CA restriction — it only changes how convincingly, and how fast, the lure operates upstream of it.",
    ],
  },
}

export default entry
