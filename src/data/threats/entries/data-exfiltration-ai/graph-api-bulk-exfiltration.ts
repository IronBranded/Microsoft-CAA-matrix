import type { ThreatEntry } from '../../../../types/threat'

const entry: ThreatEntry = {
  id: 'graph-api-bulk-exfiltration',
  title: 'Graph API Bulk Exfiltration',
  domain: 'data-exfiltration-ai',
  category: 'Collection / Exfiltration',
  severity: 'high',
  status: 'complete',
  shortDesc:
    "An attacker holding a valid token — stolen, phished, or via an over-consented OAuth app — scripts high-volume Microsoft Graph calls to systematically dump a user's or tenant's mail, files, and Teams chat history.",
  description:
    "Once an attacker holds a valid access token, from any of the credential-theft techniques elsewhere in this matrix, Microsoft Graph provides a single, well-documented API surface for reading essentially every category of M365 data the compromised identity's permissions allow: mail via /me/messages, files via /me/drive, Teams chats via /chats, contacts, and calendar. Because this uses the exact same API surface legitimate apps use, distinguishing bulk exfiltration from unusual-but-legitimate automation requires volume- and pattern-based detection rather than any single smoking-gun signal.",

  forensicArtifacts: [
    {
      logSourceId: 'graph-activity-logs',
      source: 'Microsoft Graph Activity Logs',
      artifact:
        "High request-rate patterns against /me/messages, /me/drive/root/children, /users/{id}/messages, or similar bulk-list endpoints from a single client/token in a short window (requires enabling via Entra diagnostic settings). Repeated pagination through the same result set (sequential @odata.nextLink follows) or a delta query (/delta endpoints) pulling a full initial sync rather than incremental changes are both specific, checkable signatures of programmatic bulk retrieval rather than a human browsing.",
    },
    {
      logSourceId: 'sign-in-logs',
      source: 'AADNonInteractiveUserSignInLogs',
      artifact: 'Token refresh volume far exceeding normal client behavior — bulk exfil scripts typically hold a session open and refresh repeatedly rather than the natural start/stop pattern of interactive use',
    },
    {
      logSourceId: 'cloud-app-events',
      source: 'CloudAppEvents (Defender for Cloud Apps)',
      artifact: "'Mass download' or 'unusual file access' anomaly detections, particularly volume-based policies on file/message access counts per session",
    },
    {
      logSourceId: 'unified-audit-log',
      source: 'OfficeActivity — the Unified Audit Log (UAL)',
      artifact: 'MailItemsAccessed at anomalously high volume for a short window, consistent with programmatic enumeration rather than a human reading mail',
    },
    {
      logSourceId: 'graph-activity-logs',
      source: 'Microsoft Graph Activity Logs',
      artifact: 'The full HTTP request trail against Microsoft Graph itself, including endpoints and volume — this is a diagnostic log category that must be explicitly enabled via Entra ID diagnostic settings; it is not on by default and is easy to assume exists when it does not',
    },
    {
      source: 'Application/Service Principal sign-in logs',
      artifact: "If access came via an OAuth app rather than a stolen user token directly, the app's own sign-in pattern shows the same volume anomaly, and its granted scopes define what it could pull",
    },
  ],

  telemetry: {
    correlationMarkers: [
      'CorrelationId on the originating sign-in: ties bulk API activity back to whichever initial-access technique delivered the token — cross-reference the relevant scenario elsewhere in this matrix.',
      'Client/App ID making the calls: legitimate high-volume automation is usually a small, known set of approved apps — an unrecognized App ID at high volume is the core anomaly signal.',
      'Request rate and endpoint diversity: a human using web/desktop clients naturally paginates and pauses; scripted exfiltration tends toward sustained, mechanically regular request intervals against list/enumerate endpoints specifically.',
    ],
  },

  mitre: [
    { id: 'T1567', name: 'Exfiltration Over Web Service', tactic: 'Exfiltration' },
    { id: 'T1213', name: 'Data from Information Repositories', tactic: 'Collection' },
  ],

  kql: {
    sentinel: {
      triage: {
        title: 'High-volume Graph API requests',
        description:
          'Requires Microsoft Graph Activity Logs enabled via Entra ID diagnostic settings (a separate log category from SigninLogs/AuditLogs) — confirm ingestion before treating an empty result as clean. This log category is newer and has seen schema additions; verify exact column names against the current Microsoft Learn reference.',
        query: `MicrosoftGraphActivityLogs
| where TimeGenerated > ago(1d)
| where RequestUri has_any ("/messages", "/drive", "/chats", "/contacts")
| summarize RequestCount = count(), DistinctEndpoints = dcount(RequestUri) by AppId, IPAddress, UserId
| where RequestCount > 500  // tune this threshold against your own tenant's baseline
| order by RequestCount desc`,
      },
      investigate: {
        title: 'Token refresh frequency for the same identity',
        description: 'Sustained scripted access tends to refresh far more often than an interactive client naturally would.',
        query: `AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(1d)
| summarize RefreshCount = count(), DistinctIPs = dcount(IPAddress) by UserPrincipalName, AppDisplayName
| where RefreshCount > 200  // tune against your baseline
| order by RefreshCount desc`,
      },
    },
    defender: {
      triage: {
        title: 'High-volume file/mail access',
        query: `CloudAppEvents
| where Timestamp > ago(1d)
| where ActionType has_any ("FileAccessed", "FileDownloaded", "MailItemsAccessed")
| summarize EventCount = count() by AccountDisplayName, IPAddress, bin(Timestamp, 1h)
| where EventCount > 300  // tune against your baseline
| order by EventCount desc`,
      },
    },
  },

  runbook: {
    triage: [
      'Establish the request volume and time window — a burst suggests an automated dump script; sustained low-and-slow suggests deliberate evasion of volume-based alerting.',
      'Identify the App ID/client making the calls and check whether it\'s a recognized, approved application.',
      'Determine what scopes/permissions the token or app actually holds — this defines the maximum possible exposure, whether or not everything available was actually pulled.',
      'Cross-reference other scenarios in this matrix for how the underlying token was likely obtained, to understand the full attack chain rather than just this final stage.',
    ],
    contain: [
      "Revoke the compromised user's sessions and tokens, or disable/delete the offending application's service principal if access was via an OAuth app.",
      'Rotate any credentials or sensitive content that may have been exposed in exfiltrated mail/files.',
      'Apply Conditional Access session controls (app-enforced restrictions, blocking legacy/unmanaged clients) to limit further bulk API access.',
      'If a Defender for Cloud Apps session policy exists, consider tightening download/access volume thresholds while the incident is active.',
    ],
    investigate: [
      'Reconstruct what was accessed by correlating request patterns against the endpoints hit — messages vs. files vs. chats carry very different sensitivity and notification implications.',
      'Determine whether the exfiltrated data included regulated categories (PII, financial, health) that may trigger breach notification obligations.',
      "Check whether the same App ID/token pattern touched other users' data, especially if access came via an over-privileged application rather than a single stolen token.",
      'Review Purview DLP and eDiscovery logs for any related alerts that may already have flagged pieces of this activity independently.',
    ],
    recover: [
      'Stand up the volume-based detections above as standing analytics rules rather than one-off hunts.',
      'Review and reduce standing OAuth app permissions tenant-wide — least-privilege scopes cap the maximum exposure of any future token theft.',
      'Enable Microsoft Purview DLP policies for the data categories most impacted, to catch future exfiltration attempts closer to real time.',
      'Brief legal/compliance on the scope of data accessed for any required regulatory notification assessment.',
    ],
  },
}

export default entry
