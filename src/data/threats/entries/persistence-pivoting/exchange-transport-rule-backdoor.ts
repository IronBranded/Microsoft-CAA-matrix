import type { ThreatEntry } from '../../../../types/threat'

const entry: ThreatEntry = {
  id: 'exchange-transport-rule-backdoor',
  title: 'Exchange Transport Rule Backdoor',
  domain: 'persistence-pivoting',
  category: 'Defense Evasion / Persistence',
  severity: 'critical',
  status: 'complete',
  shortDesc:
    'Setting a hidden, tenant-wide mail flow rule to silently blind-copy sensitive communications externally, or to strip sensitivity labels and evade DLP.',
  description:
    'Transport rules operate at the organization level, applying to all mail flowing through Exchange Online — making them an unusually powerful backdoor once an attacker gains Exchange Administrator access. A rule can blind-copy specific senders or subjects to an external address, or strip sensitivity labels that would otherwise trigger DLP, all without touching any individual mailbox a user might notice.',

  forensicArtifacts: [
    {
      source: 'OfficeActivity (Exchange Admin Audit Log)',
      artifact: "Operation == 'New-TransportRule' or 'Set-TransportRule' with BlindCopyTo, RedirectMessageTo, or similar recipient-manipulation parameters — org-wide, applying regardless of the target mailbox's own settings",
    },
    {
      source: 'OfficeActivity',
      artifact: 'Transport rule parameters that strip or downgrade sensitivity labels (removing or modifying classification headers) — used to evade DLP that keys off those labels',
    },
    {
      source: 'OfficeActivity',
      artifact: 'A transport rule scoped narrowly — specific senders, specific keywords, or a specific distribution list — rather than broadly; narrow scoping is itself a signal, suggesting deliberate targeting rather than a legitimate org-wide compliance rule',
    },
    {
      source: 'Exchange Online admin role assignment history',
      artifact: 'How the acting account obtained Exchange Administrator or an equivalent custom role — this technique requires that privilege, so its origin matters',
    },
    {
      source: 'Message Trace',
      artifact: 'Messages matching the rule criteria showing the blind-copy or redirect action actually firing — confirms the rule was live and had real effect, not just configured',
    },
  ],

  telemetry: {
    correlationMarkers: [
      "Transport rules apply org-wide and silently — unlike an inbox rule, there's no mailbox-owner-visible artifact at all; the admin audit trail and the rule's own configuration are the only places this is visible.",
      'Rule priority and enabled state matter — a rule can be created disabled, or ordered to fire only after other rules, both ways to keep it dormant or narrowly effective without drawing attention during a cursory review of active rules.',
      'CorrelationId on the New-TransportRule/Set-TransportRule event ties back to the admin session that created it, establishing whether that session\'s other activity looks legitimate.',
    ],
  },

  mitre: [
    { id: 'T1114.003', name: 'Email Collection: Email Forwarding Rule', tactic: 'Collection' },
    { id: 'T1078.004', name: 'Valid Accounts: Cloud Accounts', tactic: 'Persistence' },
  ],

  kql: {
    sentinel: {
      triage: {
        title: 'Transport rules with recipient-manipulation actions',
        query: `OfficeActivity
| where TimeGenerated > ago(30d)
| where Operation in ("New-TransportRule", "Set-TransportRule")
| where Parameters has_any ("BlindCopyTo", "RedirectMessageTo", "Bcc", "CopyTo")
| project TimeGenerated, UserId, ClientIP, Operation, Parameters
| order by TimeGenerated desc`,
      },
      investigate: {
        title: 'Transport rules touching classification/sensitivity headers',
        description: 'Evidence of DLP evasion alongside covert copying.',
        query: `OfficeActivity
| where TimeGenerated > ago(30d)
| where Operation in ("New-TransportRule", "Set-TransportRule")
| where Parameters has_any ("RemoveHeader", "SetHeader", "ApplyClassification")
| project TimeGenerated, UserId, ClientIP, Operation, Parameters
| order by TimeGenerated desc`,
      },
    },
    defender: {
      triage: {
        title: 'Transport rule creation/modification',
        query: `CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType in ("New-TransportRule", "Set-TransportRule")
| project Timestamp, AccountDisplayName, ActionType, IPAddress, RawEventData
| order by Timestamp desc`,
      },
    },
  },

  runbook: {
    triage: [
      'Pull the full rule definition — conditions, actions, priority, and enabled state.',
      'Determine how narrowly or broadly the rule is scoped; a rule targeting a small specific group of senders is more likely deliberate targeting than broad organizational policy.',
      'Identify the creating/modifying admin and how they obtained Exchange Administrator privilege.',
      'Use Message Trace to confirm whether the rule has actually fired and on how many messages.',
    ],
    contain: [
      'Disable or delete the malicious transport rule immediately.',
      'Revoke sessions for the acting admin account and treat it as compromised pending investigation.',
      'Review every other transport rule in the tenant for similar patterns — attackers who find this technique often create more than one.',
      'Restrict who holds Exchange Administrator, or equivalent custom roles capable of transport rule management, if the population is broader than necessary.',
    ],
    investigate: [
      'Use Message Trace to identify exactly which messages were affected and where copies/redirects were sent.',
      "Determine whether any sensitivity-labeled or DLP-protected content was specifically targeted by the rule's header-stripping actions.",
      'Check whether the compromised admin account shows other signs of broader tenant compromise, given the privilege required for this technique.',
      "Establish the rule's full active window, not just when it was first noticed — Message Trace retention may outlast casual awareness of the rule's existence.",
    ],
    recover: [
      'Notify any parties whose communications were exposed via the blind-copy/redirect destination.',
      'Implement alerting on every New-TransportRule/Set-TransportRule event involving recipient-manipulation or classification-header actions.',
      'Reduce and tightly monitor the population of accounts holding Exchange Administrator.',
      "Periodically export and diff the full transport rule set against a known-good baseline, since this technique's value to an attacker depends entirely on going unnoticed.",
    ],
  },
}

export default entry
