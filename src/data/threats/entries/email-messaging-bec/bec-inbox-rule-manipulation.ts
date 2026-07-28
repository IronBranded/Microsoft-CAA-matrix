import type { ThreatEntry } from '../../../../types/threat'

const entry: ThreatEntry = {
  id: 'bec-inbox-rule-manipulation',
  title: 'BEC — Inbox Rule Manipulation',
  domain: 'email-messaging-bec',
  category: 'Defense Evasion',
  severity: 'high',
  status: 'complete',
  shortDesc: 'Hidden inbox rules — DeleteMessage, MoveToFolder — created specifically to hide the attacker\'s activity and any replies related to an in-progress fraud attempt.',
  description:
    "A common companion technique to BEC fraud: alongside or instead of full forwarding, the attacker sets narrow inbox rules targeting specific senders or subject keywords — replies from a bank confirming a fraudulent transfer, or messages from the real vendor noticing something is wrong — and silently deletes or files them away where the legitimate mailbox owner won't see them, buying time before the fraud is discovered.",

  forensicArtifacts: [
    {
      source: 'OfficeActivity — the Unified Audit Log (UAL)',
      artifact: "Operation == 'New-InboxRule' or 'Set-InboxRule' with DeleteMessage, MoveToFolder targeting an obscure folder, or MarkAsRead actions, scoped to specific senders or subject keywords rather than broad criteria",
    },
    {
      source: 'OfficeActivity',
      artifact: "Rule conditions targeting keywords like 'invoice', 'payment', 'wire', 'confirm', or a specific bank/vendor domain — the rule's targeting criteria often reveal the fraud's actual subject matter",
    },
    {
      source: 'Message Trace',
      artifact: 'Messages matching the rule criteria that were actually moved/deleted/marked-read, confirming the rule had real effect rather than sitting unused',
    },
    {
      source: 'Entra ID SigninLogs',
      artifact: 'The session that created the rule, for IP/device consistency check',
    },
    {
      source: 'Mailbox folder contents',
      artifact: 'Messages sitting in the target folder or in Deleted Items that the legitimate user never saw — the direct evidence of what the rule successfully hid',
    },
  ],

  telemetry: {
    correlationMarkers: [
      'This is a companion technique, not usually the objective itself — its presence strongly indicates BEC Internal or External Impact is also underway, and should trigger a broader investigation, not just rule removal.',
      'Rule scope precision is informative: a rule targeting one specific external domain or a handful of keywords is far more likely deliberate fraud-concealment than a broad, generic rule.',
      "DeleteMessage is more aggressive than MoveToFolder — the former destroys the user's own visibility entirely, subject to Deleted Items recovery windows, while the latter merely relocates it.",
    ],
  },

  mitre: [{ id: 'T1564.008', name: 'Hide Artifacts: Email Hiding Rules', tactic: 'Defense Evasion' }],

  kql: {
    sentinel: {
      triage: {
        title: 'Hide-pattern inbox rules',
        query: `OfficeActivity
| where TimeGenerated > ago(14d)
| where Operation in ("New-InboxRule", "Set-InboxRule")
| where Parameters has_any ("DeleteMessage", "MoveToFolder", "MarkAsRead")
| project TimeGenerated, UserId, ClientIP, Operation, Parameters
| order by TimeGenerated desc`,
      },
      investigate: {
        title: 'Hide-pattern rules with financial/fraud-related keywords',
        description: 'Narrow rules (few conditions, specific keywords/senders) are more likely deliberate than broad ones — review Parameters manually for scope.',
        query: `OfficeActivity
| where TimeGenerated > ago(14d)
| where Operation in ("New-InboxRule", "Set-InboxRule")
| where Parameters has_any ("invoice", "payment", "wire", "bank", "confirm")
| project TimeGenerated, UserId, ClientIP, Parameters
| order by TimeGenerated desc`,
      },
    },
    defender: {
      triage: {
        title: 'Hide-pattern inbox rule activity',
        query: `CloudAppEvents
| where Timestamp > ago(14d)
| where ActionType in ("New-InboxRule", "Set-InboxRule")
| where RawEventData has_any ("DeleteMessage", "MoveToFolder", "MarkAsRead")
| project Timestamp, AccountDisplayName, ActionType, IPAddress, RawEventData
| order by Timestamp desc`,
      },
    },
  },

  runbook: {
    triage: [
      'Pull the full rule definition and its actual match criteria.',
      'Check the target folder and Deleted Items for hidden messages.',
      "Use Message Trace to confirm the rule's real effect and volume.",
      'Identify what the rule\'s keywords/senders reveal about the underlying fraud.',
    ],
    contain: [
      'Remove the rule immediately.',
      'Recover any messages it hid where still possible.',
      "Reset the mailbox owner's password and revoke sessions.",
      'Check for other rules or forwarding configured alongside this one.',
    ],
    investigate: [
      'Determine what fraud or compromise this rule was concealing — cross-reference with BEC Internal/External Impact elsewhere in this matrix.',
      'Identify every message the rule successfully hid, and their content and senders.',
      'Establish the rule\'s full active window.',
      'Check whether the same pattern appears on other mailboxes.',
    ],
    recover: [
      'Alert on inbox rules matching hide-pattern actions combined with financial or vendor-related keywords specifically.',
      'Periodically audit inbox rules tenant-wide for this pattern.',
      'Brief users to periodically check rarely-used folders and Deleted Items during any suspected compromise.',
      'Consider a policy limiting or reviewing rules with DeleteMessage actions specifically, given how rarely legitimate that combination is.',
    ],
  },
}

export default entry
