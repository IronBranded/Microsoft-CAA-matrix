import type { ThreatEntry } from '../../../../types/threat'

const entry: ThreatEntry = {
  id: 'device-code-phishing',
  title: 'Device Code Phishing (OAuth2 Device Flow)',
  domain: 'identity-authentication',
  category: 'Initial Access / Credential Access',
  severity: 'high',
  status: 'complete',
  shortDesc:
    "Attacker intercepts an OAuth token by tricking a user into authenticating a device code on their behalf.",
  description:
    "An attacker initiates a device code authentication flow, generating a code. They send this code via a phishing lure instructing the target to visit microsoft.com/devicelogin. Once the user authenticates (including MFA), the Entra ID token is delivered directly to the attacker's polling session. The attacker now holds a Primary Refresh Token (PRT) or access token without needing the user's password or device.",

  forensicArtifacts: [
    { source: 'Entra ID SigninLogs', artifact: "AuthenticationProtocol == 'deviceCode'" },
    {
      source: 'Entra ID SigninLogs',
      artifact:
        "ClientAppUsed == 'Microsoft Azure CLI' or 'Microsoft Azure PowerShell' (often default for attack tools like TokenTactics)",
    },
    {
      source: 'CloudAppEvents / OfficeActivity',
      artifact: 'High-volume Graph API or Exchange Online API calls immediately following the device code sign-in',
    },
    {
      source: 'Entra ID NonInteractiveUserSignInLogs',
      artifact: "Subsequent token refreshes originating from the attacker's IP address (often VPS or VPN providers)",
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
      "JWT auth_time: If you capture a raw token (e.g., memory dump, reverse proxy logs), decode it. The `auth_time` claim represents the original authentication instance date/time, while the `iat` (Issued At) claim represents when that specific token was refreshed. Match `auth_time` against Interactive SigninLogs to find the exact phishing moment.",
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
    },
  },

  runbook: {
    triage: [
      "1. Verify the 'ResultType' in SigninLogs. Did the user actually complete the authentication (0) or was it blocked by a CAP?",
      "2. Extract the 'OriginalRequestId' and 'CorrelationId' from the successful sign-in.",
      "3. Identify the 'AppDisplayName' requested by the attacker to understand the scope of the token (e.g., Microsoft Graph vs. Exchange Online).",
      "4. Locate the initial phishing vector (check Defender for Office 365, Teams logs, or user reports) to identify other potential targets.",
    ],
    contain: [
      "1. Suspend the compromised account immediately.",
      "2. Revoke all active sessions and tokens. Execute via Microsoft Graph PowerShell: `Revoke-MgUserSignInSession -UserId <UPN>`",
      "3. Block the attacker's IP in Entra ID Named Locations and apply to a blocking CAP.",
      "4. Purge any malicious inbox rules or forwarding SMTP addresses created during the session.",
    ],
    investigate: [
      "1. Pivot using the 'CorrelationId' into `CloudAppEvents` and `OfficeActivity` to reconstruct the timeline of data accessed.",
      "2. Look for persistence mechanisms: Check `AuditLogs` for new OAuth app consents, new MFA devices registered, or new guest accounts created.",
      "3. Identify if the stolen token was used to access the Azure Resource Manager (ARM) via `AzureActivity`. Look for enumeration of subscriptions or key vaults.",
      "4. Analyze `NonInteractiveUserSignInLogs` to identify if the attacker is attempting to refresh the token post-containment.",
      "5. If a raw access token is recovered during the investigation, decode it (e.g., via jwt.ms). Extract the `auth_time` claim and match this timestamp against Interactive `SigninLogs` to identify the precise minute the original device code was authorized.",
    ],
    recover: [
      "1. Ensure 'Revoke-MgUserSignInSession' successfully propagated (look for AADSTS70020 errors from the attacker IP in NonInteractive logs).",
      "2. Reset the user's password (this breaks existing PRTs and prevents legacy auth fallback).",
      "3. Require the user to re-register MFA devices from a known good network.",
      "4. (Preventative) Create a Conditional Access Policy restricting 'Device code flow' to compliant devices only.",
    ],
  },
}

export default entry
