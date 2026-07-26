import type { ThreatEntry } from '../../../../types/threat'

const entry: ThreatEntry = {
  id: 'malicious-email-forwarding-rules',
  title: 'Malicious Email Forwarding Rules',
  domain: 'email-messaging-bec',
  category: 'Collection / Exfiltration',
  severity: 'high',
  status: 'complete',
  shortDesc:
    'An attacker with mailbox access sets up a hidden forwarding rule or SMTP forwarding address to silently exfiltrate a copy of all incoming mail, often the first durable foothold after a BEC-style compromise.',
  description:
    "After compromising a mailbox — via phishing, password spray, or a stolen token — attackers commonly configure either a client-side Outlook inbox rule ('forward all mail matching X to external@attacker.com, then delete') or a transport-level forwarding property on the mailbox itself (`Set-Mailbox -ForwardingSmtpAddress`). The latter is especially dangerous: it doesn't appear in the user's own visible rules list in Outlook, and it keeps operating even after the compromised password is reset, since it's a mailbox property rather than a client-side setting.",

  forensicArtifacts: [
    {
      source: 'OfficeActivity (Exchange Online)',
      artifact:
        "Operation == 'New-InboxRule' or 'Set-InboxRule' with ForwardTo/RedirectTo/ForwardAsAttachmentTo parameters pointing to an external domain, especially combined with DeleteMessage or MarkAsRead actions used to hide the forwarded copies",
    },
    {
      source: 'OfficeActivity (Exchange Online)',
      artifact:
        "Operation == 'Set-Mailbox' with a populated ForwardingSmtpAddress or ForwardingAddress parameter — the mailbox-level, more persistent forwarding vector",
    },
    {
      source: 'Exchange Online Message Trace',
      artifact: "A 'Forward' or 'Redirect' event immediately after delivery to the compromised mailbox, en route to an external recipient with no legitimate business relationship",
    },
    {
      source: 'Entra ID SigninLogs',
      artifact: 'The sign-in immediately preceding the rule creation — establishes whether it came from the normal device/location or attacker infrastructure',
    },
    {
      source: 'Microsoft Defender for Office 365',
      artifact: "Alert 'Suspicious email forwarding activity' or 'Creation of forwarding/redirect rule to external domain', if Plan 2 is licensed",
    },
  ],

  telemetry: {
    correlationMarkers: [
      'CorrelationId / SessionId on the rule-creation event: pivot back to the SigninLogs entry for the session that created the rule.',
      'ForwardingSmtpAddress vs. ForwardingAddress on Set-Mailbox: ForwardingSmtpAddress takes a raw external SMTP address (most common in BEC); ForwardingAddress must resolve to a recipient object in the org.',
      'DeliverToMailboxAndForward flag: if false, the legitimate user never receives a copy at all — the forward is the only delivery, making the compromise fully invisible from the mailbox alone.',
    ],
  },

  mitre: [{ id: 'T1114.003', name: 'Email Collection: Email Forwarding Rule', tactic: 'Collection' }],

  kql: {
    sentinel: {
      triage: {
        title: 'Inbox rules forwarding to external domains',
        query: `OfficeActivity
| where TimeGenerated > ago(14d)
| where Operation in ("New-InboxRule", "Set-InboxRule")
| where Parameters has_any ("ForwardTo", "RedirectTo", "ForwardAsAttachmentTo")
| project TimeGenerated, UserId, ClientIP, Operation, Parameters
| order by TimeGenerated desc`,
      },
      investigate: {
        title: 'Mailbox-level forwarding (Set-Mailbox)',
        description: "The more persistent variant — survives password resets and doesn't appear in the user's own Outlook rules list.",
        query: `OfficeActivity
| where TimeGenerated > ago(14d)
| where Operation == "Set-Mailbox"
| where Parameters has "ForwardingSmtpAddress" or Parameters has "ForwardingAddress"
| project TimeGenerated, UserId, ClientIP, Parameters
| order by TimeGenerated desc`,
      },
    },
    defender: {
      triage: {
        title: 'Forwarding rule and mailbox forwarding activity',
        query: `CloudAppEvents
| where Timestamp > ago(14d)
| where ActionType in ("New-InboxRule", "Set-InboxRule", "Set-Mailbox")
| where RawEventData has_any ("ForwardTo", "RedirectTo", "ForwardingSmtpAddress", "ForwardingAddress")
| project Timestamp, AccountDisplayName, ActionType, IPAddress, RawEventData
| order by Timestamp desc`,
      },
    },
  },

  runbook: {
    triage: [
      'Determine the exact mechanism used — client-side inbox rule vs. Set-Mailbox forwarding property — since this changes both urgency and remediation.',
      'Identify the external destination address/domain and check it against known threat intel or prior BEC cases.',
      'Establish whether DeliverToMailboxAndForward is true or false — false means the user has had zero visibility into the compromise via their own mailbox.',
      'Pull the rule/forwarding creation timestamp and cross-reference message trace for actual forwarded message volume.',
    ],
    contain: [
      'Remove the malicious rule/forwarding immediately: `Remove-InboxRule` for client rules, or `Set-Mailbox -ForwardingSmtpAddress $null -ForwardingAddress $null` for mailbox-level forwarding.',
      "Reset the user's password and revoke sessions — mailbox forwarding survives a password reset, but the reset stops the attacker creating new rules or accessing the mailbox further.",
      'Block the external destination domain/address at the mail flow level tenant-wide as a precaution.',
      'Check for and remove any other persistence set alongside the forwarding rule, such as delegate access grants.',
    ],
    investigate: [
      'Use Message Trace to determine exactly which messages were forwarded during the compromise window, prioritizing financial, legal, and HR content.',
      'Check for related BEC activity — outbound replies sent from the compromised mailbox attempting invoice fraud or payment redirection.',
      'Search tenant-wide for the same external forwarding destination across other mailboxes — attackers often spray this technique broadly.',
      'Identify the initial access vector that led to the mailbox compromise in the first place.',
    ],
    recover: [
      'Notify any external parties who may have received fraudulent follow-up communications originating from the compromised mailbox.',
      "Enable a tenant-wide policy that flags or blocks new external auto-forwarding (Exchange Online's outbound anti-spam policy has a tenant-wide external forwarding control).",
      'Deploy or tune Defender for Office 365 alerts for forwarding-rule creation and mailbox forwarding property changes.',
      'Reinforce user training on this specific pattern, since forwarding rules are often set up within minutes of a successful phish.',
    ],
  },
}

export default entry
