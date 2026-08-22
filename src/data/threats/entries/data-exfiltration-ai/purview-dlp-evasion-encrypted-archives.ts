import type { ThreatEntry } from '../../../../types/threat'

const entry: ThreatEntry = {
  id: 'purview-dlp-evasion-encrypted-archives',
  title: 'Purview DLP Evasion via Encrypted Archives',
  domain: 'data-exfiltration-ai',
  category: 'Exfiltration / Defense Evasion',
  severity: 'medium',
  status: 'complete',
  shortDesc: 'Wrapping exfiltrated data inside a password-protected .zip or .pdf container specifically to defeat inline content inspection before it leaves the tenant.',
  description:
    "Purview Data Loss Prevention policies generally work by inspecting content for sensitive patterns as it moves. An attacker aware of this simply encrypts the data before it's sent, most commonly as a password-protected archive attached to an email, which DLP's content inspection cannot see inside, letting genuinely sensitive data pass through a control specifically built to catch it.",

  forensicArtifacts: [
    {
      logSourceId: 'unified-audit-log',
      source: 'OfficeActivity / Exchange mail flow — the Unified Audit Log (UAL)',
      artifact: "Outbound email with password-protected .zip, .7z, or encrypted .pdf attachments — DLP content inspection can't see inside these, so the attachment type and encryption state itself is the detectable signal",
    },
    {
      source: 'Defender for Office 365 / Exchange transport rules',
      artifact:
        "Whether a policy exists at all for flagging/blocking password-protected archive attachments outbound — many tenants have no specific control for this pattern. The same evasion works identically via a SharePoint/OneDrive external share link to an encrypted archive rather than an email attachment — DLP content inspection has the same blind spot there, so check sharing activity for encrypted archives alongside mail flow, not instead of it.",
    },
    {
      logSourceId: 'unified-audit-log',
      source: 'OfficeActivity',
      artifact: 'A spike in outbound messages with archive-type attachments from an account with no normal business reason to routinely send them',
    },
    {
      logSourceId: 'cloud-app-events',
      source: 'CloudAppEvents',
      artifact: 'A similar pattern for cloud-storage uploads carrying encrypted archives to external recipients',
    },
    {
      logSourceId: 'message-trace-log',
      source: 'Message Trace',
      artifact: 'The recipient domain(s) for messages carrying encrypted archives — external, unfamiliar domains are more concerning than known business partners',
    },
  ],

  telemetry: {
    correlationMarkers: [
      'The defining characteristic of this technique is that it defeats content inspection specifically — metadata-level signals (attachment type, size, recipient, sender behavior) remain visible and are the actual detection surface.',
      "A password-protected archive by itself isn't inherently malicious — the anomaly is in who is sending them, how often, and to whom, compared to that account's normal pattern.",
      'Combine this signal with mailbox access volume beforehand, as in BEC and exfiltration scenarios elsewhere in this matrix, for a stronger composite picture of deliberate collection-then-exfiltration.',
      'There is deliberately no relevantErrorCodes entry for this scenario: the entire technique is built on DLP content inspection simply not seeing inside the archive, so by design nothing fires — no block, no alert, no error. Metadata-level pattern review is the only detection surface, as the correlation markers above describe.',
    ],
  },

  mitre: [{ id: 'T1560.001', name: 'Archive Collected Data: Archive via Utility', tactic: 'Collection' }],

  kql: {
    sentinel: {
      triage: {
        title: 'Outbound send activity for a specific mailbox',
        description:
          "Attachment-level detail (filenames, types) isn't reliably present on basic OfficeActivity Send records — this pattern is better hunted via Defender for Office 365's email security tables if licensed, or via Exchange mail flow/transport rule reporting. Verify attachment metadata is actually present in your OfficeActivity records before relying on filtering by attachment type here.",
        query: `OfficeActivity
| where TimeGenerated > ago(14d)
| where Operation == "Send"
| where UserId == "<mailbox under investigation>"
| project TimeGenerated, UserId, ClientIP
| order by TimeGenerated desc`,
      },
    },
    defender: {
      triage: {
        title: 'Outbound archive attachments',
        description: "EmailAttachmentInfo is part of Defender for Office 365's Advanced Hunting schema and is the more reliable source for attachment-level detail.",
        query: `EmailAttachmentInfo
| where Timestamp > ago(14d)
| where FileType in ("zip", "7z", "rar")
| project Timestamp, NetworkMessageId, SenderFromAddress, RecipientEmailAddress, FileName, FileType
| order by Timestamp desc`,
      },
    },
  },

  runbook: {
    triage: [
      'Identify the specific outbound messages with encrypted/password-protected archive attachments.',
      "Determine the sender's normal behavior baseline and the recipient domain(s).",
    ],
    contain: [
      'Hold/quarantine the message if still in transit and policy allows.',
      "If already delivered, notify the sender's manager/security team for follow-up.",
      'Consider whether the sending account itself is compromised.',
    ],
    investigate: [
      'Determine the actual content if the password can be obtained through other means.',
      'Assess whether this is a one-off or a pattern from the same account.',
      'Correlate with any preceding bulk data access.',
    ],
    recover: [
      'Implement Exchange transport rules or Defender for Office 365 policies specifically flagging/holding password-protected archive attachments outbound for review.',
      'In especially sensitive environments, consider blocking them outright rather than just flagging.',
      'Extend the same treatment to cloud-storage sharing links carrying similarly-protected content.',
    ],
  },
}

export default entry
