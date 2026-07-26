import type { ThreatEntry } from '../../../../types/threat'

const entry: ThreatEntry = {
  id: 'bec-internal-impact',
  title: 'BEC — Internal Impact',
  domain: 'email-messaging-bec',
  category: 'Collection / Impact',
  severity: 'high',
  status: 'complete',
  shortDesc: 'Compromised internal mailboxes lateral-phishing other staff or manipulating internal business workflows, trading on the built-in trust of an internal sender.',
  description:
    "Once an attacker controls a mailbox, messages sent from it carry an internal sender's implicit trust — no external-sender warning banner, a familiar name, and often visibility into real ongoing conversations to reference. This makes internal-impact BEC unusually effective for lateral phishing, requests to approve fraudulent internal processes, or gathering further intelligence for a larger fraud attempt.",

  forensicArtifacts: [
    {
      source: 'OfficeActivity',
      artifact: "Outbound messages from the compromised mailbox to other internal recipients requesting fund transfers, credential entry, or clicking links — distinguishable from external BEC by recipient domain matching the tenant's own",
    },
    {
      source: 'OfficeActivity',
      artifact: 'MailItemsAccessed on internal correspondence threads immediately before crafting a convincing internal lateral-phish reply',
    },
    {
      source: 'Entra ID SigninLogs',
      artifact: "The session sending internal lateral-phishing messages, for IP/device consistency check against the mailbox owner's normal pattern",
    },
    {
      source: 'Microsoft Defender for Office 365',
      artifact: "Internal mail flow doesn't always receive the same scrutiny as external mail by default — check whether internal-to-internal phishing detection is actually enabled, since gaps here are common",
    },
    {
      source: "Recipients' own reports",
      artifact: 'Coworkers reporting a suspicious message from a colleague — often the first real signal, since internal mail is trusted by default',
    },
  ],

  telemetry: {
    correlationMarkers: [
      "Recipient domain matching the tenant's own domain is the key differentiator from BEC External Impact — same underlying mailbox compromise, different blast pattern.",
      'Internal lateral phishing often targets a specific follow-on objective — spreading further, or a specific fraud like an internal approval or gift card request — the actual ask shapes the urgency of response.',
      'Check whether your mail flow rules/EOP policies apply the same scrutiny to internal-to-internal mail as external — a common gap this technique exploits.',
    ],
  },

  mitre: [{ id: 'T1534', name: 'Internal Spearphishing', tactic: 'Lateral Movement' }],

  kql: {
    sentinel: {
      triage: {
        title: 'Outbound internal mail volume from a specific mailbox',
        description: "A coarse metadata proxy — content itself requires Purview Content Search, the same limitation as BEC External Impact.",
        query: `OfficeActivity
| where TimeGenerated > ago(3d)
| where Operation == "Send"
| where UserId == "<mailbox under investigation>"
| summarize SendCount = count() by bin(TimeGenerated, 1h)
| order by TimeGenerated desc`,
      },
      investigate: {
        title: 'Access-then-send pattern for a specific mailbox',
        query: `OfficeActivity
| where TimeGenerated > ago(3d)
| where Operation in ("MailItemsAccessed", "Send")
| where UserId == "<mailbox under investigation>"
| project TimeGenerated, Operation, ClientIP
| order by TimeGenerated asc`,
      },
    },
    defender: {
      triage: {
        title: 'Mail access and send activity',
        query: `CloudAppEvents
| where Timestamp > ago(3d)
| where ActionType in ("Send", "MailItemsAccessed")
| where AccountDisplayName == "<mailbox under investigation>"
| project Timestamp, ActionType, IPAddress, RawEventData
| order by Timestamp desc`,
      },
    },
  },

  runbook: {
    triage: [
      'Identify the specific internal message(s) and their actual ask.',
      'Determine which coworkers received it and whether any acted on it.',
      'Establish the compromise window via sign-in/mailbox access telemetry.',
      'Check for a companion inbox rule hiding evidence, as in BEC Inbox Rule Manipulation.',
    ],
    contain: [
      "Reset the compromised mailbox owner's password and revoke sessions.",
      'Notify all internal recipients directly, not via reply, that the message was fraudulent.',
      'Remove any hidden inbox rules.',
      'Check whether any recipient acted on the lateral phish and needs their own containment.',
    ],
    investigate: [
      'Use content search to pull the actual message content and full recipient list.',
      "Check whether any recipient's own account was subsequently compromised by acting on the lateral phish.",
      'Determine the initial access vector for the original compromise.',
      'Assess the actual business impact of any internal process that was manipulated.',
    ],
    recover: [
      'Extend the same scrutiny (Safe Links, Safe Attachments, phishing detection) to internal-to-internal mail flow.',
      'Brief staff that internal-looking mail is not automatically trustworthy.',
      'Review whether the organization\'s mail flow/EOP policies have an internal-mail gap.',
      'Reinforce verification procedures for any internally-requested financial or credential action.',
    ],
  },
}

export default entry
