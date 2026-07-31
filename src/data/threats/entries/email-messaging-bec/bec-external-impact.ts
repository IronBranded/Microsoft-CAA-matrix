import type { ThreatEntry } from '../../../../types/threat'

const entry: ThreatEntry = {
  id: 'bec-external-impact',
  title: 'BEC — External Impact',
  domain: 'email-messaging-bec',
  category: 'Impact',
  severity: 'critical',
  status: 'complete',
  shortDesc:
    'A compromised mailbox is used to conduct invoice fraud, vendor payment redirection, or supply-chain phishing against external partners.',
  description:
    'The most financially damaging form of Business Email Compromise targets external relationships directly — intercepting a real invoice thread and redirecting payment to attacker-controlled bank details, or impersonating an executive to authorize an urgent transfer. Because the messages originate from a genuine, previously-trusted mailbox, they routinely bypass both technical email-authentication controls and the human skepticism that would catch a spoofed sender.',

  forensicArtifacts: [
    {
      source: 'OfficeActivity — the Unified Audit Log (UAL)',
      artifact: 'Outbound replies or new messages from the compromised mailbox to external recipients discussing payment, invoicing, or banking details — most reliably found via Message Trace / content search rather than metadata alone, since the fraud lives in the message body',
    },
    {
      source: 'OfficeActivity',
      artifact:
        "MailItemsAccessed events immediately preceding the fraudulent reply, showing the attacker reading an existing invoice/payment thread before crafting a convincing reply into it — this specific event type requires E5 or the Audit (Premium) add-on and isn't available on E3 (see the Acquisition Guide); if the tenant is E3-only, this particular artifact won't exist regardless of how thoroughly you search, and the investigation needs to rely on Message Trace and the surrounding sign-in telemetry instead.",
    },
    {
      source: 'Entra ID SigninLogs',
      artifact: "The session that sent the fraudulent message — IP, device, and timing, to distinguish attacker activity from the legitimate mailbox owner's own correspondence",
    },
    {
      source: 'BEC Inbox Rule Manipulation (see elsewhere in this matrix)',
      artifact: 'A companion inbox rule hiding replies from the real vendor/bank, which is what buys the attacker time before the fraud is discovered',
    },
    {
      source: "External party's own reporting",
      artifact: "Often the first real signal: the legitimate vendor or customer noticing a change in payment instructions and contacting the organization directly, arriving before any internal telemetry flags it",
    },
  ],

  telemetry: {
    correlationMarkers: [
      "This scenario's core evidence is in message CONTENT — payment instructions, bank details, urgency language — which metadata-only KQL against OfficeActivity generally can't see. Purview Content Search or eDiscovery against the mailbox is usually necessary to fully scope it; that's an honest limitation of log-based detection here, not a gap in the queries below.",
      'Look for reply-chain hijacking specifically: the fraudulent message is very often a reply within an existing, legitimate thread rather than a new message, since that inherits the thread\'s credibility.',
      'Timing correlation between MailItemsAccessed and an outbound Send, especially outside the mailbox owner\'s normal working hours, is a reasonable metadata-only proxy signal even without reading content.',
    ],
  },

  mitre: [{ id: 'T1657', name: 'Financial Theft', tactic: 'Impact' }],

  kql: {
    sentinel: {
      triage: {
        title: 'Mailbox access immediately followed by an outbound send',
        description: "A metadata-only proxy signal — can't see message content. Pair with Purview Content Search for the content itself.",
        query: `OfficeActivity
| where TimeGenerated > ago(14d)
| where Operation in ("MailItemsAccessed", "Send")
| summarize Operations = make_set(Operation), Times = make_list(TimeGenerated) by UserId, bin(TimeGenerated, 10m)
| where array_length(Operations) > 1
| order by TimeGenerated desc`,
      },
      investigate: {
        title: 'Send activity for a specific mailbox under investigation',
        description:
          "OfficeActivity confirms a Send happened but carries little message content itself — use this to scope which window to pull via Message Trace (recipients, subject) and Purview Content Search (body) for the actual fraud evidence.",
        query: `OfficeActivity
| where TimeGenerated > ago(14d)
| where Operation == "Send"
| where UserId == "<mailbox under investigation>"
| project TimeGenerated, UserId, ClientIP, ClientInfoString
| order by TimeGenerated desc`,
      },
    },
    defender: {
      triage: {
        title: 'Mail access and send activity for a specific mailbox',
        query: `CloudAppEvents
| where Timestamp > ago(14d)
| where ActionType in ("Send", "MailItemsAccessed")
| where AccountDisplayName == "<mailbox under investigation>"
| project Timestamp, ActionType, IPAddress, RawEventData
| order by Timestamp desc`,
      },
    },
  },

  runbook: {
    triage: [
      'Identify the specific fraudulent message(s) — most often surfaced by the external party themselves, or by content search once a compromise is suspected for other reasons.',
      'Determine what payment/banking details were communicated and to whom, and whether any payment was actually made based on them.',
      'Check for a companion inbox rule hiding the real vendor/bank replies.',
      'Establish the full compromise window using sign-in and mailbox access telemetry, not just the date of the fraudulent message itself.',
    ],
    contain: [
      "Reset the mailbox owner's password and revoke sessions immediately.",
      'Remove any hidden inbox rules or forwarding configured during the compromise.',
      'Contact your financial institution immediately if a fraudulent payment was made — wire recalls have a narrow window to succeed.',
      'Notify the external party directly through a verified, out-of-band channel — not by replying to the same email thread, which may still be attacker-monitored.',
    ],
    investigate: [
      "Use Purview Content Search / eDiscovery to pull the full content of messages sent during the compromise window, since metadata alone won't show the fraud itself.",
      "Reconstruct the attacker's research phase — MailItemsAccessed activity in the days before the fraudulent message, showing what threads they read to craft a convincing reply.",
      'Check whether other mailboxes were similarly compromised or targeted, especially if the organization handles many vendor/customer payment relationships.',
      'Determine the initial access vector that compromised the mailbox in the first place.',
    ],
    recover: [
      'Work with legal/finance on any required fraud reporting and recovery process for funds already transferred.',
      'Implement a verified, out-of-band confirmation step for any payment-detail change request, regardless of how legitimate the email appears — the single most effective process-level control against this scenario.',
      'Review and tighten Conditional Access and forwarding-rule controls tenant-wide to reduce the chance of the underlying mailbox compromise recurring.',
      'Brief finance/accounts-payable teams specifically on this pattern, since they are the most common target.',
    ],
  },
}

export default entry
