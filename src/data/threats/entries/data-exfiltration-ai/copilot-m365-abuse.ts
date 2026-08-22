import type { ThreatEntry } from '../../../../types/threat'

const entry: ThreatEntry = {
  id: 'copilot-m365-abuse',
  title: 'Microsoft Copilot for M365 Abuse',
  domain: 'data-exfiltration-ai',
  category: 'Collection',
  severity: 'medium',
  status: 'complete',
  shortDesc: "Exploiting a user's over-permissioned access through Copilot's RAG retrieval, letting one query surface and summarize sensitive content the attacker couldn't efficiently find by hand.",
  description:
    "Copilot answers queries using retrieval grounded in whatever content the querying identity already has permission to access — it doesn't grant new access, but it dramatically lowers the effort required to find and synthesize sensitive information scattered across mail, files, and Teams. An attacker operating through a compromised account can use a handful of well-crafted prompts to do in minutes what would otherwise take extensive manual searching.",

  forensicArtifacts: [
    {
      logSourceId: 'unified-audit-log',
      source: 'Microsoft Purview audit log (the Unified Audit Log, UAL)',
      artifact: 'Copilot interaction records, where audit coverage exists — as with Indirect Prompt Injection elsewhere in this matrix, exact coverage is still evolving; confirm current logging against Microsoft\'s own documentation',
    },
    {
      source: 'User/account behavior baseline',
      artifact: 'A sudden shift in how an account interacts with M365 content — heavy Copilot query volume replacing what was previously manual browsing/search',
    },
    {
      logSourceId: 'unified-audit-log',
      source: 'SharePoint/OneDrive/Exchange access logs — OfficeActivity in the UAL',
      artifact: 'Content access patterns immediately following Copilot queries, showing what was actually retrieved and surfaced in response',
    },
    {
      logSourceId: 'sign-in-logs',
      source: 'Entra ID SigninLogs',
      artifact: "The session context of unusually heavy Copilot usage, for consistency check against the account's normal behavior",
    },
    {
      source: 'Data classification / sensitivity labels',
      artifact: 'Whether sensitive or highly-classified content was surfaced via a Copilot response, which may warrant the same scrutiny as any other access to that content regardless of retrieval method',
    },
  ],

  telemetry: {
    correlationMarkers: [
      "Copilot doesn't grant new access — every scenario here depends on the querying identity already having legitimate permission to the underlying content. The abuse is in efficiency of discovery, not in access itself, which changes what a defensible response looks like.",
      'As with prompt injection, audit coverage specific to Copilot interactions is still maturing — treat gaps in this area as a known, current limitation rather than a sign nothing happened.',
      'A compromised account using Copilot to rapidly aggregate sensitive information it already had scattered access to is functionally similar in outcome to Graph API Bulk Exfiltration elsewhere in this matrix, just via a different, higher-level interface.',
    ],
  },

  mitre: [{ id: 'T1213', name: 'Data from Information Repositories', tactic: 'Collection' }],

  kql: {
    sentinel: {
      triage: {
        title: 'High-volume Copilot query activity',
        description:
          'Illustrative only — exact audit coverage and operation names for Copilot interactions are still evolving in Purview. Confirm current event names against Microsoft\'s documentation before relying on this as written.',
        query: `OfficeActivity
| where TimeGenerated > ago(7d)
| where Operation has_any ("Copilot", "AIInteraction")
| summarize QueryCount = count() by UserId, bin(TimeGenerated, 1h)
| where QueryCount > 20  // tune against your tenant's baseline
| order by QueryCount desc`,
      },
    },
    defender: {
      triage: {
        title: 'Copilot query volume',
        query: `CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType has "Copilot"
| summarize QueryCount = count() by AccountDisplayName, bin(Timestamp, 1h)
| where QueryCount > 20
| order by Timestamp desc`,
      },
    },
  },

  runbook: {
    triage: [
      'Identify the account with anomalous Copilot usage volume/pattern.',
      'Determine what the underlying account permissions actually grant access to.',
      'Review what content was surfaced via recent queries if recoverable.',
    ],
    contain: [
      'Revoke sessions if the account itself is compromised.',
      'Treat this the same as any other bulk-access incident given the underlying permission scope.',
    ],
    investigate: [
      'Cross-reference with Graph API Bulk Exfiltration elsewhere in this matrix for the same underlying access pattern via a different interface.',
      "Determine what sensitive content the account was already over-permissioned to reach, independent of Copilot's involvement.",
    ],
    recover: [
      'The durable fix is reducing standing over-permissioning tenant-wide, since Copilot inherits whatever access already exists rather than expanding it.',
      "Enable and monitor Copilot-specific audit logging as coverage matures.",
      'Apply Purview sensitivity labels and DLP consistently so highly sensitive content is protected regardless of retrieval method.',
    ],
  },
}

export default entry
