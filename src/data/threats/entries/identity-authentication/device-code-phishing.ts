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
          'Advanced Hunting equivalent of the Sentinel triage query. Device-code is not always a flat column in this table — verify against your current schema, or parse AdditionalFields as shown.',
        query: `// Device code sign-ins are not surfaced as a dedicated top-level column in
// AADSignInEventsBeta the way AuthenticationProtocol is in Sentinel's SigninLogs.
// Parse the AdditionalFields JSON blob for the protocol marker, and confirm the
// exact field name against the current Advanced Hunting schema reference for
// your tenant before relying on this in production detections.
AADSignInEventsBeta
| where Timestamp > ago(7d)
| where ApplicationName !in ("Visual Studio Code", "Microsoft Azure CLI")
| where ErrorCode == 0
| where IsManagedIdentity == false
| extend AuthProtocol = tostring(AdditionalFields.authenticationProtocol)
| where AuthProtocol =~ "deviceCode"
| project Timestamp, AccountUpn, IPAddress, ApplicationName, Country, RequestId, CorrelationId`,
      },
      escalation: {
        title: 'Device code sign-in via Authentication Broker targeting Device Registration Service',
        description:
          "Advanced Hunting equivalent of the Sentinel escalation query. ApplicationId and resource fields for this table have shifted across schema updates before — confirm the exact field names against your current Advanced Hunting schema reference rather than assuming this matches Sentinel's column naming.",
        query: `AADSignInEventsBeta
| where Timestamp > ago(7d)
| where ApplicationId == "29d9ed98-a469-4536-ade2-f981bc1d605e" // Microsoft Authentication Broker
| where ErrorCode == 0
| extend AuthProtocol = tostring(AdditionalFields.authenticationProtocol)
| where AuthProtocol =~ "deviceCode"
| extend ResourceId = tostring(AdditionalFields.resourceId)
| where ResourceId == "01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9" // Device Registration Service
| project Timestamp, AccountUpn, IPAddress, Country, RequestId, CorrelationId`,
      },
    },
  },

  runbook: {
    triage: [
      "1. Verify the 'ResultType' in SigninLogs. Did the user actually complete the authentication (0) or was it blocked by a CAP?",
      "2. Extract the 'OriginalRequestId' and 'CorrelationId' from the successful sign-in.",
      "3. Identify the 'AppDisplayName' and 'AppId' requested by the attacker to understand the scope of the token — Microsoft Graph or Exchange Online is a straightforward token-theft case, but AppId 29d9ed98-a469-4536-ade2-f981bc1d605e (Authentication Broker) combined with a Device Registration Service resource is the escalation path: treat this specific combination as the higher-severity case and jump straight to checking AuditLogs for a new device registration event.",
      "4. Locate the initial phishing vector (check Defender for Office 365, Teams logs, or user reports) to identify other potential targets.",
    ],
    contain: [
      "1. Suspend the compromised account immediately.",
      "2. Revoke all active sessions and tokens. Execute via Microsoft Graph PowerShell: `Revoke-MgUserSignInSession -UserId <UPN>`",
      "3. Block the attacker's IP in Entra ID Named Locations and apply to a blocking CAP.",
      "4. Purge any malicious inbox rules or forwarding SMTP addresses created during the session.",
      "5. If the escalation path was used (Broker AppId + DRS resource confirmed at triage): find and delete any device object registered during the incident window (Entra ID > Devices), and check the user's authentication methods via Graph API for a security key or WHfB credential registered in that same window — remove anything the user doesn't recognize.",
    ],
    investigate: [
      "1. Pivot using the 'CorrelationId' into `CloudAppEvents` and `OfficeActivity` to reconstruct the timeline of data accessed.",
      "2. Look for persistence mechanisms: check `AuditLogs` for new OAuth app consents, new guest accounts created, and specifically for a new authentication method (security key or Windows Hello for Business credential) registered within roughly 15 minutes of the phishing sign-in — that window matches how long an ngcmfa-carrying token stays valid for registration, and a new credential registered there is a durable backdoor that survives a password reset.",
      "3. Identify if the stolen token was used to access the Azure Resource Manager (ARM) via `AzureActivity`. Look for enumeration of subscriptions or key vaults.",
      "4. Analyze `NonInteractiveUserSignInLogs` to identify if the attacker is attempting to refresh the token post-containment.",
      "5. If a raw access token is recovered during the investigation, decode it (e.g., via jwt.ms). Extract the `auth_time` claim and match this timestamp against Interactive `SigninLogs` to identify the precise minute the original device code was authorized.",
    ],
    recover: [
      "1. Ensure 'Revoke-MgUserSignInSession' successfully propagated (look for AADSTS70020 errors from the attacker IP in NonInteractive logs).",
      "2. Reset the user's password (this breaks existing PRTs and prevents legacy auth fallback).",
      "3. Require the user to re-register MFA devices from a known good network.",
      "4. Confirm no device object or authentication method tied to the incident window remains — password reset alone does not remove a rogue registered device or a security key registered via the ngcmfa escalation path; both need to be found and removed independently (see contain step 5).",
      "5. (Preventative) Create a Conditional Access Policy restricting 'Device code flow' to compliant devices only.",
    ],
  },
}

export default entry
