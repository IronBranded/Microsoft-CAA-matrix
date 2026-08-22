import type { ThreatEntry } from '../../../../types/threat'

const entry: ThreatEntry = {
  id: 'sharepoint-onedrive-ransomware-versioning-abuse',
  title: 'SharePoint/OneDrive Ransomware via Versioning Abuse',
  domain: 'data-exfiltration-ai',
  category: 'Impact',
  severity: 'critical',
  status: 'complete',
  shortDesc:
    'Mass-encrypting cloud files and then reducing version history retention to as little as one version, specifically to prevent restoration from version history.',
  description:
    "Cloud ransomware in the M365 context doesn't need to touch an endpoint at all — an attacker with sufficient access can use the Graph API to download, encrypt, and re-upload files in bulk. Many attackers also reduce the document library's version history limit before or during the encryption pass, specifically to defeat the most obvious recovery path and pressure the victim toward paying rather than simply restoring prior versions.",

  forensicArtifacts: [
    {
      logSourceId: 'unified-audit-log',
      source: 'OfficeActivity — the Unified Audit Log (UAL)',
      artifact: "A high-volume burst of file-modification operations across many files in a short window — the signature of automated, scripted mass encryption rather than normal user editing",
    },
    {
      logSourceId: 'unified-audit-log',
      source: 'OfficeActivity',
      artifact: "Audit events for changes to organization-, site-, or library-level version history limits — Microsoft's own documentation confirms these are logged, occurring shortly before or during the mass-modification burst; exact operation names are worth confirming against a live tenant since this is a newer audit category",
    },
    {
      source: 'Microsoft Graph / SharePoint API activity',
      artifact: 'Bulk API calls against drive item endpoints performing download-then-reupload cycles at a rate far exceeding normal user or even normal sync-client behavior',
    },
    {
      source: 'SharePoint/OneDrive version history state',
      artifact: 'For files where prior versions still exist, comparing the current (encrypted) version against the last known-good version is the most direct path to both scoping the damage and recovering content — check before any retention window on old versions expires',
    },
    {
      logSourceId: 'sign-in-logs',
      source: 'Entra ID SigninLogs / AADNonInteractiveUserSignInLogs',
      artifact: 'The identity and session performing the bulk modifications — the same account-compromise or over-permissioned-app patterns as Graph API Bulk Exfiltration, since the access method is the same',
    },
  ],

  telemetry: {
    correlationMarkers: [
      "The version-limit reduction and the mass file modification are typically close together in time but are TWO separate events — don't assume finding one means you've found the other; check for both independently.",
      'CorrelationId / client App ID performing the mass modification: the same identity/app pivot used in Graph API Bulk Exfiltration applies directly here, since this is the same access pattern used destructively instead of for reading.',
      'Files with version history still intact — where the limit reduction never reached every library, or happened after some files were already touched — are recoverable; prioritize scoping which libraries were and were not affected by the limit change specifically.',
    ],
  },

  mitre: [
    { id: 'T1486', name: 'Data Encrypted for Impact', tactic: 'Impact' },
    { id: 'T1490', name: 'Inhibit System Recovery', tactic: 'Impact' },
  ],

  kql: {
    sentinel: {
      triage: {
        title: 'High-volume file modification burst',
        query: `OfficeActivity
| where TimeGenerated > ago(2d)
| where Operation in ("FileModified", "FileModifiedExtended")
| summarize ModifiedCount = count(), DistinctFiles = dcount(SourceRelativeUrl) by UserId, bin(TimeGenerated, 15m)
| where ModifiedCount > 100  // tune against your own tenant's normal editing baseline
| order by TimeGenerated desc`,
      },
      investigate: {
        title: 'Version history / retention configuration changes',
        description:
          'Purview logs these per Microsoft documentation; confirm the exact Operation string against a live tenant if this returns nothing — this is a newer audit category and naming may vary by tenant/licensing.',
        query: `OfficeActivity
| where TimeGenerated > ago(2d)
| where Operation has_any ("VersionLimit", "VersionHistory", "VersioningSettings")
| project TimeGenerated, UserId, Operation, Parameters, SiteUrl
| order by TimeGenerated desc`,
      },
    },
    defender: {
      triage: {
        title: 'High-volume file modification burst',
        query: `CloudAppEvents
| where Timestamp > ago(2d)
| where ActionType in ("FileModified", "FileUploaded")
| summarize ModifiedCount = count() by AccountDisplayName, IPAddress, bin(Timestamp, 15m)
| where ModifiedCount > 100  // tune against your baseline
| order by Timestamp desc`,
      },
    },
  },

  runbook: {
    triage: [
      'Identify the account/app performing the mass modification and how it obtained access — compromised session or over-permissioned OAuth app.',
      'Scope which sites/libraries were affected and, critically, which still have intact version history versus which had retention reduced first.',
      'Determine whether files were actually encrypted (unreadable) versus just modified, and confirm the extent.',
      'Check whether a ransom note or similar artifact was dropped alongside the encrypted files, and what it references.',
    ],
    contain: [
      'Revoke the compromised identity\'s sessions and tokens, or disable the offending application\'s service principal, immediately to stop further encryption.',
      'Restore organization/site/library version history limits to their normal values immediately, to stop further legitimate version loss on any files not yet touched.',
      'Temporarily restrict write access on affected sites while recovery is underway, to prevent re-encryption of restored files.',
      'Do not pay any ransom demand as a first response — engage your incident response process and legal counsel first.',
    ],
    investigate: [
      'Determine the full scope of affected files across all sites/libraries, not just the ones first noticed.',
      'For each affected library, establish whether version history was reduced before, after, or not at all during the encryption pass — this directly determines recoverability.',
      'Identify the initial access vector, consistent with other scenarios in this matrix.',
      'Check whether data was also exfiltrated before encryption (double-extortion pattern), via the same detections used in Graph API Bulk Exfiltration.',
    ],
    recover: [
      'Restore from the most recent intact version for every file where history survived; fall back to a separate backup solution for files where it did not — native versioning is not a substitute for a true backup, precisely because of this scenario.',
      'Reset organization-level version history limits to a sensible default and restrict who can lower them at the site/library level.',
      'Implement alerting on both mass file modification bursts and version-limit changes as standing detections, ideally correlated together.',
      'Review whether a dedicated backup solution external to native versioning is in place, since it was never designed as ransomware-resilient backup on its own.',
    ],
  },
}

export default entry
