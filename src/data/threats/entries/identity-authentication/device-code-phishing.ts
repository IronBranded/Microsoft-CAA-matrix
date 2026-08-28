import type { ThreatEntry } from '../../../../types/threat'

const entry: ThreatEntry = {
  id: 'device-code-phishing',
  title: 'Device Code Phishing (OAuth2 Device Flow)',
  domain: 'identity-authentication',
  category: 'Initial Access / Credential Access',
  severity: 'critical',
  status: 'complete',
  shortDesc:
    "Attacker intercepts an OAuth token by tricking a user into authenticating a device code on their behalf.",
  description:
    "An attacker initiates a device code authentication flow, generating a code. They send this code via a phishing lure instructing the target to visit microsoft.com/devicelogin. Once the user authenticates (including MFA), the Entra ID token is delivered directly to the attacker's polling session. In its basic form this hands the attacker a plain access or refresh token — but a more severe, actively-exploited variant exists: by requesting the token using the Microsoft Authentication Broker's own client ID (29d9ed98-a469-4536-ade2-f981bc1d605e) against the Device Registration Service, the attacker can register a rogue device in Entra ID that appears fully legitimate, then request a Primary Refresh Token (PRT) from it — bypassing device-based Conditional Access entirely, not just MFA.",

  forensicArtifacts: [
    { logSourceId: 'sign-in-logs', source: 'Entra ID SigninLogs', artifact: "AuthenticationProtocol == 'deviceCode'" },
    {
      logSourceId: 'sign-in-logs',
      source: 'Entra ID SigninLogs',
      artifact:
        "originalTransferMethod == 'deviceCodeFlow' — a separate field from AuthenticationProtocol, not part of the JWT itself, that corroborates the same finding. Check both; relying on only one leaves a detection gap if that specific field is ever renamed or restructured.",
    },
    {
      logSourceId: 'sign-in-logs',
      source: 'Entra ID SigninLogs',
      artifact:
        "AppId == '29d9ed98-a469-4536-ade2-f981bc1d605e' (Microsoft Authentication Broker) combined with AuthenticationProtocol == 'deviceCode' is a high-fidelity indicator on its own — this specific client ID is what lets a stolen token be upgraded to register a rogue device and mint a PRT. Legitimate use exists (genuine Windows Hello for Business enrollment, shared/kiosk device onboarding), so treat as a strong prioritization signal rather than an automatic block.",
    },
    {
      logSourceId: 'sign-in-logs',
      source: 'Entra ID SigninLogs',
      artifact:
        "ClientAppUsed == 'Microsoft Azure CLI' or 'Microsoft Azure PowerShell' (often default for attack tools like TokenTactics)",
    },
    {
      source: 'CloudAppEvents / OfficeActivity',
      artifact: 'High-volume Graph API or Exchange Online API calls immediately following the device code sign-in',
    },
    {
      logSourceId: 'sign-in-logs',
      source: 'Entra ID NonInteractiveUserSignInLogs',
      artifact: "Subsequent token refreshes originating from the attacker's IP address (often VPS or VPN providers)",
    },
    {
      logSourceId: 'entra-audit-logs',
      source: 'Entra ID AuditLogs',
      artifact:
        "A new device registration event immediately following a device-code sign-in that used the Broker AppId — this is the moment the attacker's rogue device becomes a 'legitimate' object in your tenant, and the highest-value single event to alert on in this entire chain.",
    },
    {
      source: 'JWT Token Claims (If Captured)',
      artifact:
        'The `auth_time` claim inside the access token remains static across refreshes, pointing to the exact original time the victim entered the device code.',
    },
  ],

  telemetry: {
    authenticationProtocols: ['deviceCode'],
    correlationMarkers: [
      'OriginalRequestId: Use this to track the specific authentication session in Entra ID.',
      'CorrelationId: Pivot on this across AzureActivity, CloudAppEvents, and OfficeActivity to track post-compromise actions tied to the stolen token.',
      "Resource/audience 01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9 (Device Registration Service): a device-code sign-in requesting this specific resource, combined with the Broker AppId above, is the exact combination used to obtain a device-registration token — the step immediately before rogue device registration and PRT issuance.",
      "JWT auth_time: If you capture a raw token (e.g., memory dump, reverse proxy logs), decode it. The `auth_time` claim represents the original authentication instance date/time, while the `iat` (Issued At) claim represents when that specific token was refreshed. Match `auth_time` against Interactive SigninLogs to find the exact phishing moment.",
      "amr_values=ngcmfa in the request / ngcmfa claim in the resulting token: a request parameter legitimately used by the Authentication Broker to force a 'next generation credential' (Windows Hello/PIN) MFA claim during genuine device registration — security researchers have demonstrated it can be included in a phished device code request to force the same claim into an attacker-controlled token. A token carrying ngcmfa can register a new FIDO2 security key or WHfB credential on the account, independent of what CA policy would otherwise require. The claim is only valid for roughly 15 minutes after authentication — a narrow but real window where fast containment can still prevent the credential registration even if the initial phish already succeeded.",
      "Generative AI is increasingly used to hyper-personalize the phishing lure itself — emails themed around role-specific content (RFPs, invoices, manufacturing workflows) tailored to the individual victim, sometimes with AI-generated infrastructure handling device code generation end-to-end through post-compromise activity. This doesn't change any of the technical indicators above, but it means the initial lure is less likely to be caught by generic phishing-language detection than in earlier, more templated attempts — weight the technical signals in this entry over lure content when triaging.",
    ],
    relevantErrorCodes: [
      {
        code: 'AADSTS70016',
        type: 'OAuth2 Device Flow',
        description: 'Authorization pending or user code expired.',
        dfirValue:
          'A massive spike from a single IP indicates attacker tooling aggressively polling the endpoint waiting for the victim to enter the code.',
      },
      {
        code: 'AADSTS50097',
        type: 'Conditional Access',
        description: 'Device authentication required.',
        dfirValue: "Indicates a CAP successfully blocked the flow because the attacker's polling machine is unmanaged.",
      },
      {
        code: 'AADSTS70020',
        type: 'Token Revocation',
        description: 'The provided grant has expired due to it being revoked.',
        dfirValue: 'Confirms that your containment actions (token revocation) were successful.',
      },
      {
        code: 'AADSTS50199',
        type: 'CmsiInterrupt',
        description: 'For security reasons, user confirmation is required for this request.',
        dfirValue:
          "Generic and usually benign on its own — but seen specifically in Authentication Broker sign-ins tied to an interrupted device registration attempt, it's worth checking the Conditional Access tab on that sign-in event before dismissing it as routine.",
      },
    ],
  },

  mitre: [
    { id: 'T1528', name: 'Steal Application Access Token', tactic: 'Credential Access' },
    { id: 'T1566.002', name: 'Spearphishing Link', tactic: 'Initial Access' },
  ],

  atrm: [{ id: 'AZT201.1', name: 'Valid Credentials: User Account', tactic: 'Initial Access' }],

  kql: {
    sentinel: {
      triage: {
        title: 'Successful device code sign-ins (non-service accounts)',
        description: 'Surfaces successful deviceCode auth events outside expected first-party dev tooling.',
        query: `// Detect successful Device Code flow sign-ins by non-service accounts
SigninLogs
| where TimeGenerated > ago(7d)
| where AuthenticationProtocol =~ "deviceCode"
| where UserType != "Guest"
| where AppDisplayName !in ("Visual Studio Code", "Microsoft Azure CLI") // Exclude known dev apps if applicable
| where ResultType == "0"
| project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName, ClientAppUsed, Location, OriginalRequestId, CorrelationId`,
      },
      investigate: {
        title: 'Post-compromise activity via CorrelationId',
        description: 'Pivots from a compromised device-code session into downstream Graph/Exchange/ARM activity.',
        query: `// Pivot on CorrelationId to find post-compromise activity (Requires M365 Defender / Sentinel)
let compromised_sessions = SigninLogs
| where TimeGenerated > ago(7d)
| where AuthenticationProtocol =~ "deviceCode" and ResultType == "0"
| distinct CorrelationId;
union CloudAppEvents, OfficeActivity, AzureActivity
| where TimeGenerated > ago(7d)
| where CorrelationId in (compromised_sessions)
| project TimeGenerated, ActionType, Operation, UserPrincipalName, IPAddress, CountryCode
| sort by TimeGenerated desc`,
      },
      escalation: {
        title: 'Device code sign-in via Authentication Broker targeting Device Registration Service',
        description:
          "Higher-fidelity than the generic triage query above — this is the specific escalation combination (Broker AppId + DRS resource) used to obtain a device-registration token ahead of rogue device registration and PRT issuance. Confirm against legitimate WHfB enrollment or kiosk/shared-device onboarding in your tenant before treating every hit as confirmed malicious.",
        query: `SigninLogs
| where TimeGenerated > ago(7d)
| where AuthenticationProtocol =~ "deviceCode"
| where AppId == "29d9ed98-a469-4536-ade2-f981bc1d605e" // Microsoft Authentication Broker
| where ResourceIdentity == "01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9" // Device Registration Service
| where ResultType == "0"
| project TimeGenerated, UserPrincipalName, IPAddress, Location, OriginalRequestId, CorrelationId`,
      },
    },
    defender: {
      triage: {
        title: 'Successful device code sign-ins',
        description:
          'AADSignInEventsBeta is deprecated in favor of EntraIdSignInEvents (old queries auto-migrate 2026-10-19, but this reference should read correctly today rather than rely on that). The new table drops AdditionalFields entirely, so this no longer parses JSON for the protocol marker — instead it mirrors the ErrorCode 50199-then-0 pairing Microsoft itself hunts on for this exact technique: a CmsiInterrupt immediately followed by success is the fingerprint of a user pausing to read/enter a device code, which is protocol-agnostic and doesn\'t depend on an unverified column.',
        query: `EntraIdSignInEvents
| where Timestamp > ago(7d)
| where Application !in ("Visual Studio Code", "Microsoft Azure CLI")
| summarize ErrorCodes = make_set(ErrorCode), Apps = make_set(Application) by AccountUpn, CorrelationId, SessionId, bin(Timestamp, 1h)
| where ErrorCodes has_all (0, 50199)
// Secondary, less-verified check: the EndpointCall column (new in this table) carries
// endpoint/request-type detail that may narrow this further to device-code specifically —
// Microsoft's own April 2026 hunting guidance for this technique checks EndpointCall
// (referenced there as "Call") for a "Cmsi:cmsi" substring on the confirmation step.
// Confirm the exact value your tenant populates before adding it as a hard filter.
| project TimeGenerated = Timestamp, AccountUpn, CorrelationId, SessionId, ErrorCodes, Apps`,
      },
      escalation: {
        title: 'Device code sign-in via Authentication Broker targeting Device Registration Service',
        description:
          'EntraIdSignInEvents equivalent of the Sentinel escalation query. ResourceId is a native top-level column on this table (unlike the deprecated AADSignInEventsBeta, which needed AdditionalFields parsing for it) — one less thing to verify against a JSON blob.',
        query: `EntraIdSignInEvents
| where Timestamp > ago(7d)
| where ApplicationId == "29d9ed98-a469-4536-ade2-f981bc1d605e" // Microsoft Authentication Broker
| where ResourceId == "01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9" // Device Registration Service
| where ErrorCode == 0
| project Timestamp, AccountUpn, IPAddress, Country, RequestId, CorrelationId, SessionId`,
      },
    },
  },

  authFlow: {
    pattern: 'sequence',
    narrative:
      "A single victim's flow is linear and maps cleanly onto Entra ID telemetry — this is the canonical shape that the AI-orchestrated, on-demand-generation variant (see dynamic-device-code-phishing) deliberately compresses in time but doesn't otherwise change at the code level. Where escalation to a Primary Refresh Token is attempted, the flow extends through an additional, higher-fidelity step rather than ending at plain token issuance.",
    steps: [
      {
        code: 'device-code-request',
        label: "Attacker requests a device code from Microsoft's device authorization endpoint",
        detail: 'No victim-side telemetry yet — this happens entirely on attacker infrastructure, using the real Microsoft endpoint. The code and its 15-minute clock exist from this moment.',
      },
      {
        code: '70016',
        label: 'Attacker polling begins (authorization pending)',
        detail: "Repeats every few seconds until the victim completes the code entry or the code expires. A high-volume burst of this code from a single IP, with no corresponding success yet, is attacker tooling waiting — see the relevantErrorCodes note above.",
      },
      {
        code: '50199',
        label: 'CmsiInterrupt at the devicelogin confirmation prompt (often, not always)',
        detail: 'A routine confirmation step in the device code flow generally, not unique to phishing — but combined with the Broker AppId and Device Registration Service resource (escalation path), its presence on that specific combination is worth checking against the Conditional Access tab before dismissing as routine.',
      },
      {
        code: '0',
        label: 'Victim completes authentication, including any MFA their account requires',
        detail: "The token is delivered to the attacker's polling session at this moment, not to the victim's own device — that's the entire mechanism of this technique.",
      },
      {
        code: 'device-registration',
        label: '(Escalation path only) Broker AppId + Device Registration Service resource requested, then a new device object created',
        detail: 'Requires the attacker to have specifically requested the token using AppId 29d9ed98-a469-4536-ade2-f981bc1d605e against resource 01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9 — what turns a plain stolen token into a Primary Refresh Token bound to an attacker-controlled device, bypassing device-based Conditional Access, not just MFA.',
      },
    ],
    distinguishingNotes:
      "The plain-token path (first four steps) and the PRT-escalation path (all five) look identical in SigninLogs right up until the AppId/resource combination in the last step — don't assume a device-code compromise is contained just because the token from the first four steps has been revoked; confirm whether AuditLogs shows a device registration event before calling this fully remediated. If the AI-orchestrated variant's tight click-to-success timing is present instead (see dynamic-device-code-phishing), layer that read on top of this same code sequence rather than expecting a different set of codes.",
  },

  tokenTimeline: {
    issuance:
      "Issued the moment the victim completes the devicelogin confirmation, delivered to the attacker's polling session rather than the victim's own device. Where the escalation path is used, a second, higher-value issuance follows: the Primary Refresh Token from the Device Registration Service exchange.",
    expiration:
      "Standard access/refresh token lifetimes for the plain-token path. Where the escalation path succeeds, effective persistence extends indefinitely via the resulting PRT, independent of the original token's expiration — precisely why the escalation path is treated as critical severity rather than just high.",
    authInstant:
      "auth_time, where present, pins to the single interactive moment the victim completed the devicelogin flow and stays static across later refreshes — the basis for the auth_time-matching technique in the investigate runbook (decode a captured token, match against Interactive SigninLogs). Optional claim; don't assume a captured token has it.",
    authMethods:
      "amr reflects whatever the victim's account legitimately required (password, MFA method) — a real, unmodified sign-in from the victim's own perspective. One exception worth knowing: amr_values=ngcmfa can be requested as a parameter on the Broker-mediated escalation path specifically, forcing an ngcmfa claim into the resulting token even though the victim didn't use a next-generation credential to authenticate — see the correlationMarkers note above. Outside that specific escalation path, amr is unremarkable and shouldn't be treated as a signal on its own.",
    mfaInstant:
      "SigninLogs.AuthenticationDetails is the reliable source for exactly when MFA completed, regardless of which path was taken. For the escalation path specifically, the ngcmfa claim's roughly 15-minute validity window after authentication is a hard external clock worth tracking against — a new FIDO2/WHfB credential registered more than 15 minutes after the original auth_time likely reflects a separate, later action, not the same phishing event.",
    otherContext:
      "This is the base scenario the rest of the device-code-phishing family builds on — dynamic-device-code-phishing shares this exact code sequence and escalation path, differing only in how the code gets in front of the victim and how fast the whole thing moves. If you're triaging a device-code incident and unsure which specific entry applies, this one's forensic artifacts and KQL are the right starting point regardless.",
  },

  runbook: {
    triage: [
      "Verify the 'ResultType' in SigninLogs. Did the user actually complete the authentication (0) or was it blocked by a CAP?",
      "Extract the 'OriginalRequestId' and 'CorrelationId' from the successful sign-in.",
      "Identify the 'AppDisplayName' and 'AppId' requested by the attacker to understand the scope of the token — Microsoft Graph or Exchange Online is a straightforward token-theft case, but AppId 29d9ed98-a469-4536-ade2-f981bc1d605e (Authentication Broker) combined with a Device Registration Service resource is the escalation path: treat this specific combination as the higher-severity case and jump straight to checking AuditLogs for a new device registration event.",
      'Locate the initial phishing vector (check Defender for Office 365, Teams logs, or user reports) to identify other potential targets.',
    ],
    contain: [
      'Suspend the compromised account immediately.',
      'Revoke all active sessions and tokens: `Revoke-MgUserSignInSession -UserId <UPN>`.',
      "Reset the account's password too, alongside revocation: `Update-MgUser -UserId <UPN> -PasswordProfile @{ Password = '<new password>'; ForceChangePasswordNextSignIn = $true }`.",
      "Block the attacker's IP in Entra ID Named Locations and apply to a blocking CAP.",
      'Purge any malicious inbox rules or forwarding SMTP addresses created during the session.',
      'If the escalation path was used (Broker AppId + DRS resource confirmed at triage): find and remove any device object registered during the incident window — `Remove-MgDevice -DeviceId <deviceObjectId>` (verify the parameter name against your installed Microsoft.Graph module version) — and check the user\'s authentication methods for a security key or WHfB credential registered in that same window: `Get-MgUserAuthenticationMethod -UserId <UPN>`, then remove anything unrecognized with the method-specific cmdlet, e.g. `Remove-MgUserAuthenticationFido2Method -UserId <UPN> -Fido2AuthenticationMethodId <id>`.',
    ],
    investigate: [
      "Pivot using the 'CorrelationId' into `CloudAppEvents` and `OfficeActivity` to reconstruct the timeline of data accessed.",
      'Look for persistence mechanisms: check `AuditLogs` for new OAuth app consents, new guest accounts created, and specifically for a new authentication method (security key or Windows Hello for Business credential) registered within roughly 15 minutes of the phishing sign-in — that window matches how long an ngcmfa-carrying token stays valid for registration, and a new credential registered there is a durable backdoor that survives a password reset.',
      'Identify if the stolen token was used to access the Azure Resource Manager (ARM) via `AzureActivity`. Look for enumeration of subscriptions or key vaults.',
      'Analyze `NonInteractiveUserSignInLogs` to identify if the attacker is attempting to refresh the token post-containment.',
      'If a raw access token is recovered during the investigation, decode it (e.g., via jwt.ms). Extract the `auth_time` claim and match this timestamp against Interactive `SigninLogs` to identify the precise minute the original device code was authorized.',
    ],
    recover: [
      'Confirm revocation propagated: look for AADSTS70020 errors from the attacker IP in NonInteractive logs.',
      "Reset the user's password if not already done in contain — this breaks existing PRTs and prevents legacy auth fallback: `Update-MgUser -UserId <UPN> -PasswordProfile @{ Password = '<new password>'; ForceChangePasswordNextSignIn = $true }`.",
      'Require the user to re-register MFA devices from a known-good network.',
      'Confirm no device object or authentication method tied to the incident window remains — password reset alone does not remove a rogue registered device or a security key registered via the ngcmfa escalation path; both need to be found and removed independently (see contain).',
      '(Preventative) Create a Conditional Access policy restricting device code flow to compliant devices only.',
    ],
  },
}

export default entry
