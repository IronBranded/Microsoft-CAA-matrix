import type { ThreatEntry } from '../../../../types/threat'

const entry: ThreatEntry = {
  id: 'entra-id-tenant-reconnaissance',
  title: 'Entra ID Tenant Reconnaissance',
  domain: 'identity-authentication',
  category: 'Reconnaissance',
  severity: 'medium',
  status: 'complete',
  shortDesc: 'Enumeration of users, groups, roles, and applications via Microsoft Graph API or purpose-built recon tooling ahead of a targeted attack.',
  description:
    "Before or after gaining a foothold, attackers commonly enumerate a tenant's directory structure — user principal names, group memberships, directory role assignments, and registered applications — using Microsoft Graph, PowerShell modules, or open-source tools like AADInternals/ROADtools. This reconnaissance shapes subsequent targeting and often produces a distinctive burst of low-privilege but high-volume Graph API read calls.",

  forensicArtifacts: [
    {
      logSourceId: 'sign-in-logs',
      source: 'Entra ID SigninLogs',
      artifact: 'A burst of Graph API calls against /users, /groups, /directoryRoles, or /applications list endpoints from a single session/token in a short window, especially from an account with no prior history of such calls',
    },
    {
      logSourceId: 'sign-in-logs',
      source: 'Entra ID AADNonInteractiveUserSignInLogs',
      artifact: 'High-volume, sustained token usage against Microsoft Graph, consistent with a scripted enumeration tool rather than interactive browsing',
    },
    {
      logSourceId: 'cloud-app-events',
      source: 'CloudAppEvents',
      artifact:
        "Anomalous or unrecognized User-Agent strings making Graph API list/enumerate calls — reconnaissance tools often don't disguise their tooling's default HTTP client signature. Purpose-built enumeration tools (AzureHound, ROADrecon, and similar BloodHound-style Entra/Azure collectors) are common enough in both legitimate red-team use and real attacks that their default User-Agent or request patterns are worth having on a watchlist independent of any specific campaign.",
    },
    {
      logSourceId: 'entra-audit-logs',
      source: 'Entra ID AuditLogs',
      artifact: "Absence of a corresponding audit trail — pure read enumeration doesn't generate AuditLogs entries the way write operations do, meaning sign-in/Graph activity volume is often the only visible signal",
    },
    {
      logSourceId: 'cloud-app-events',
      source: 'Microsoft Defender for Cloud Apps',
      artifact: 'Built-in anomaly detections for unusual Graph API query volume or pattern, if configured',
    },
  ],

  telemetry: {
    correlationMarkers: [
      'Reconnaissance is a read-only activity, so it is largely invisible in AuditLogs (which tracks changes) — Graph API request volume/pattern in SigninLogs and Microsoft Graph Activity Logs is the primary signal, not the audit trail.',
      'Distinct endpoint diversity combined with high request volume in a short window is more indicative of automated enumeration than a human admin browsing the portal.',
      'This is frequently a precursor to a more targeted attack elsewhere in this matrix — treat confirmed reconnaissance as a signal to increase monitoring sensitivity tenant-wide for a period, not just to investigate the recon itself.',
    ],
    relevantErrorCodes: [
      {
        code: 'TooManyRequests',
        type: 'Microsoft Graph Throttling (HTTP 429)',
        description:
          'Microsoft Graph throttles by user + resource combination, not total request count. A burst of low-privilege enumeration calls against many different users/groups/apps in a short window is exactly the pattern that trips this, even though each individual call looks unremarkable.',
        dfirValue:
          "A 429 in isolation is routine noise — legitimate apps get throttled constantly. What matters is 429s clustered around a single identity making broad, generic reads (users, groups, directoryRoles, applications) rather than the narrow, repetitive call pattern of a normal app. Not every Graph resource returns a Retry-After header, so its absence doesn't mean absence of throttling — check the response code itself, not just the header.",
      },
    ],
  },

  mitre: [
    { id: 'T1087.004', name: 'Account Discovery: Cloud Account', tactic: 'Discovery' },
    { id: 'T1526', name: 'Cloud Service Discovery', tactic: 'Discovery' },
  ],

  atrm: [
    { id: 'AZT104', name: 'Gather User Information', tactic: 'Reconnaissance' },
    { id: 'AZT106', name: 'Gather Role Information', tactic: 'Reconnaissance' },
  ],

  kql: {
    sentinel: {
      triage: {
        title: 'High-volume directory enumeration via Graph API',
        description: 'Requires Microsoft Graph Activity Logs enabled via Entra ID diagnostic settings — confirm ingestion before treating an empty result as clean.',
        query: `MicrosoftGraphActivityLogs
| where TimeGenerated > ago(1d)
| where RequestUri has_any ("/users", "/groups", "/directoryRoles", "/applications")
| where RequestMethod == "GET"
| summarize RequestCount = count(), DistinctEndpoints = dcount(RequestUri) by AppId, IPAddress, UserId
| where RequestCount > 200  // tune against your tenant's baseline
| order by RequestCount desc`,
      },
      investigate: {
        title: 'Non-interactive token usage volume',
        query: `AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(1d)
| summarize RequestCount = count() by UserPrincipalName, AppDisplayName, IPAddress
| where RequestCount > 200
| order by RequestCount desc`,
      },
    },
    defender: {
      triage: {
        title: 'Directory enumeration activity',
        query: `CloudAppEvents
| where Timestamp > ago(1d)
| where ActionType has_any ("List users", "List groups", "List directoryRoles")
| summarize RequestCount = count() by AccountDisplayName, IPAddress
| where RequestCount > 200
| order by RequestCount desc`,
      },
    },
  },

  authFlow: {
    pattern: 'sequence',
    narrative:
      "This entry is deliberately thin on auth-flow content, because reconnaissance isn't really an authentication pattern — it's a way of using whatever access already exists, obtained through any mechanism documented elsewhere in this matrix (a compromised credential, an overprivileged guest account, a genuine admin session). The one code-level event that matters is the token issuance itself; everything distinctive about this scenario happens after that, in Graph API call volume and pattern, not in the auth flow.",
    steps: [
      {
        code: '0',
        label: 'Token issued via whatever mechanism actually applies (out of scope for this entry)',
        detail: "Could be a legitimate admin sign-in, a compromised low-privilege account, a guest invite, or a stolen token from any other entry in this matrix. Nothing about the sign-in event itself distinguishes reconnaissance intent — that only shows up afterward, in what the token gets used for.",
      },
      {
        code: 'graph-enumeration-burst',
        label: 'High-volume, broad-scope Graph API read calls using that token',
        detail: 'Not an authentication event at all — a usage pattern. This is genuinely the entire signal for this scenario, which is why the KQL above keys entirely on request volume and endpoint diversity rather than any sign-in-side property.',
      },
    ],
    distinguishingNotes:
      "Don't treat this entry's authFlow as a template the way you would device-code-phishing's — there's no phishing moment, no registration event, no code sequence unique to reconnaissance. If you're investigating a suspected recon burst, your actual job is identifying what got the attacker their token in the first place (a different entry's flow) and then scoping what they read with it (this entry's forensicArtifacts and KQL).",
  },

  tokenTimeline: {
    issuance:
      'Whenever the underlying access was obtained — out of scope for this entry specifically, since reconnaissance uses whatever token already exists rather than following a distinctive issuance pattern of its own.',
    expiration:
      "Standard lifetimes for whatever token type is in use. Reconnaissance itself doesn't extend or otherwise affect token validity — it's simply usage within the token's normal lifetime, potentially refreshed repeatedly if the enumeration burst runs long enough to need it.",
    authInstant:
      'auth_time reflects whatever the underlying authentication was — not informative for reconnaissance specifically, since this claim describes how the access was obtained, not what it was subsequently used for.',
    authMethods: "amr reflects the underlying authentication's methods, same caveat as authInstant — this field tells you about the entry point, not about the enumeration activity itself.",
    mfaInstant: "Not a useful lens for this scenario. If you're trying to time MFA completion, you're really investigating the access-acquisition entry that applies here, not reconnaissance specifically.",
    otherContext:
      'The absence of a corresponding AuditLogs trail (noted in forensicArtifacts) is itself a structural fact worth internalizing: pure read activity generally doesn\'t get audited the way write operations do, so sign-in and Graph request volume is genuinely the primary — sometimes only — visibility this matrix has into reconnaissance, regardless of which token or account performed it.',
  },

  runbook: {
    triage: [
      "Identify the account/app/token performing enumeration and its normal baseline behavior.",
      'Determine the scope of what was enumerated — users only, versus full directory structure including roles and apps.',
      'Check whether this correlates with a known compromised credential.',
      'Establish whether enumeration is still ongoing or was a discrete, completed burst.',
    ],
    contain: [
      'Revoke the session/token performing enumeration if tied to a compromised account: `Revoke-MgUserSignInSession -UserId <UPN>`.',
      'Block the source IP if external and clearly malicious.',
      'Increase monitoring sensitivity tenant-wide for a period following confirmed reconnaissance.',
    ],
    investigate: [
      'Determine whether enumeration was followed by any targeted action elsewhere in the tenant.',
      'Identify what specific information was gathered — admin identification, dormant account discovery, app inventory — since it shapes what follow-on attack to watch for.',
      'Check for the same enumeration signature across other accounts or IP ranges.',
    ],
    recover: [
      'Enable Microsoft Graph Activity Logs if not already, since it is the primary detection surface for this scenario.',
      'Tune volume-based alerting for Graph API enumeration patterns.',
      "Review whether any legitimate tool's normal behavior needs to be baselined or excluded to reduce false positives.",
    ],
  },
}

export default entry
