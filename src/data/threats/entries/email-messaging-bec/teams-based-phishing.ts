import type { ThreatEntry } from '../../../../types/threat'

const entry: ThreatEntry = {
  id: 'teams-based-phishing',
  title: 'Teams-Based Phishing',
  domain: 'email-messaging-bec',
  category: 'Initial Access',
  severity: 'high',
  status: 'complete',
  shortDesc: 'Using external Teams messaging via federation, or a compromised internal account, to push malicious links or files through a channel with generally lower user suspicion than email.',
  description:
    "Microsoft Teams' external access and federation features let users message people outside their own tenant, and many users treat Teams messages with more trust than email. Attackers exploit this gap using external federation to send phishing links from a lookalike tenant, or by using an already-compromised internal account to push malicious content to coworkers who wouldn't think twice clicking a link from a colleague.",

  forensicArtifacts: [
    {
      source: 'Entra ID Cross-tenant access settings / Teams external access',
      artifact: 'External Teams federation configuration — whether restricted to specific known partner domains or open broadly, which shapes how easily an attacker-controlled tenant can initiate contact',
    },
    {
      logSourceId: 'unified-audit-log',
      source: 'Microsoft Teams message logs (via OfficeActivity)',
      artifact: 'Messages received from external tenants with no prior collaboration history and a display name impersonating a known contact or brand',
    },
    {
      logSourceId: 'entra-audit-logs',
      source: 'Entra ID AuditLogs',
      artifact: "The external tenant's domain age/reputation where determinable — attacker-created tenants for this purpose are often very recently established",
    },
    {
      source: 'User reports',
      artifact: "Users reporting suspicious Teams messages — this technique often succeeds specifically because users don't expect phishing on this platform",
    },
    {
      logSourceId: 'unified-audit-log',
      source: 'OfficeActivity — the Unified Audit Log (UAL)',
      artifact: 'Link-click or file-download activity following receipt of an external Teams message, if the lure included a malicious link/attachment',
    },
    {
      source: 'Microsoft Teams call logs',
      artifact:
        "Inbound Teams voice calls from external/unfamiliar tenants, particularly impersonating IT support — voice-based Teams phishing has grown into a high-volume vector in its own right, not a rare edge case, with observed activity concentrated on weekdays during business hours. This is a distinct telemetry surface from the message-based artifacts above; a tenant only monitoring chat/message logs will miss this entirely.",
    },
    {
      source: 'DeviceProcessEvents / remote-access tool telemetry',
      artifact:
        "Quick Assist (or similar remote-access tooling — AnyDesk, ConnectWise) launched shortly after an unsolicited Teams call — a documented attack chain: a vishing call impersonating IT support, the victim talked through granting remote-access tool permissions, leading to full device compromise. This chain has been observed moving from initial contact to ransomware deployment in under 24 hours in some cases, which is fast enough that this specific combination (unsolicited call + remote-access tool launch) warrants immediate escalation rather than routine triage.",
    },
  ],

  telemetry: {
    correlationMarkers: [
      "External Teams federation defaults and scope vary — confirm your tenant's actual configuration rather than assuming it's restricted, since an overly open default is common and is the root enabler here.",
      'A newly-created external tenant with no prior collaboration history messaging your users out of the blue is a strong signal, distinguishable from a genuine, established partner relationship.',
      "This technique's effectiveness comes largely from user unfamiliarity with the threat model on this specific platform — training coverage gaps here are as much a root cause as any technical control gap.",
      "Fraudulent, purpose-created tenants used specifically to initiate Teams meeting chats with target users — and, increasingly, to place direct voice calls — is a documented pattern distinct from a compromised-account variant of this same technique. Both end up in the artifacts above, but the fraudulent-tenant variant is worth distinguishing during triage since it implies no internal account is actually compromised yet.",
    ],
  },

  mitre: [{ id: 'T1566.003', name: 'Phishing: Spearphishing via Service', tactic: 'Initial Access' }],

  kql: {
    sentinel: {
      triage: {
        title: 'External Teams chat/message activity',
        query: `OfficeActivity
| where TimeGenerated > ago(14d)
| where RecordType == "MicrosoftTeams" or Workload == "MicrosoftTeams"
| where Operation has_any ("MessageSent", "ChatCreated")
| where UserId has_any ("#EXT#", "external")
| project TimeGenerated, UserId, Operation
| order by TimeGenerated desc`,
      },
      investigate: {
        title: 'New external chats created',
        query: `OfficeActivity
| where TimeGenerated > ago(14d)
| where Workload == "MicrosoftTeams"
| where Operation == "ChatCreated"
| project TimeGenerated, UserId, Members = Parameters
| order by TimeGenerated desc`,
      },
    },
    defender: {
      triage: {
        title: 'Teams chat/message activity',
        query: `CloudAppEvents
| where Timestamp > ago(14d)
| where Application == "Microsoft Teams"
| where ActionType has_any ("ChatCreated", "MessageSent")
| project Timestamp, AccountDisplayName, ActionType, RawEventData
| order by Timestamp desc`,
      },
    },
  },

  runbook: {
    triage: [
      "Identify the external tenant/account initiating contact and its apparent legitimacy.",
      'Determine which internal users received the message and whether any interacted with a malicious link/file.',
      'Review current external Teams federation scope.',
    ],
    contain: [
      'Block the external tenant/domain at the Teams federation level.',
      'Warn affected users directly.',
      'Remove any malicious content if it was shared into internal channels.',
    ],
    investigate: [
      "Determine the lure's actual content and objective — credential phishing, malware delivery, further social engineering.",
      "Check whether any user's credentials or device were compromised as a result.",
    ],
    recover: [
      'Restrict external Teams access to specifically known, approved partner domains rather than open federation.',
      'Extend phishing awareness training to explicitly cover Teams and other collaboration platforms.',
      'Deploy Defender for Office 365 protections that extend to Teams where licensed.',
    ],
  },
}

export default entry
