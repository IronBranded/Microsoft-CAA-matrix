import type { ThreatEntry } from '../../../../types/threat'

const entry: ThreatEntry = {
  id: 'copilot-indirect-prompt-injection',
  title: 'Copilot Indirect Prompt Injection',
  domain: 'data-exfiltration-ai',
  category: 'Defense Evasion / Collection',
  severity: 'high',
  status: 'complete',
  shortDesc: 'Embedding hidden instructions in a SharePoint file or email that Copilot later ingests as context, causing it to follow attacker-supplied instructions and leak unauthorized content back to the querying user.',
  description:
    'Because Copilot grounds its responses in retrieved organizational content, an attacker who can get malicious instructions into any document or email that might later be retrieved — hidden in white-on-white text, an HTML comment, or metadata — can potentially manipulate Copilot\'s behavior when a legitimate user\'s unrelated query happens to pull that content in as context. This is a genuinely newer, still-maturing risk category specific to RAG-based AI assistants, and detection here is correspondingly less mature than for most other scenarios in this matrix — treat the guidance below as a starting point rather than a complete detection story.',

  forensicArtifacts: [
    {
      source: 'SharePoint/OneDrive/Exchange content',
      artifact:
        "Hidden or obscured instruction-like text embedded in a document or email — white-on-white text, tiny font sizes, HTML comments, or metadata fields — designed to be invisible to a human reader but ingested as context by an AI assistant. Format-specific hiding spots worth checking directly rather than just eyeballing the rendered document: Excel cell comments/notes and far-off-screen cells, PDF hidden layers or embedded-but-not-displayed text objects, and Word document properties/custom XML parts, all of which render invisibly but are still part of the extracted text content a retrieval system ingests.",
    },
    {
      logSourceId: 'unified-audit-log',
      source: 'Microsoft Purview audit log (the Unified Audit Log, UAL)',
      artifact: "Copilot interaction/activity logging, where available — Microsoft has been expanding audit coverage for Copilot interactions, but exact operation names and level of detail are still evolving; confirm current coverage against Microsoft's own documentation rather than assuming a specific event name",
    },
    {
      source: 'User reports',
      artifact: 'A user noticing Copilot returned unexpected, out-of-context, or instruction-like content in a response — often the most reliable signal in practice given the immaturity of automated detection for this class',
    },
    {
      source: 'File/email version history',
      artifact: 'The specific point a suspicious document or email was created or modified to include injected content, and by whom',
    },
    {
      source: 'Access patterns following a Copilot interaction',
      artifact: 'Unusual file or mailbox access immediately correlating with a Copilot query, if the injection successfully caused Copilot to retrieve or act on content beyond the original intent',
    },
  ],

  telemetry: {
    correlationMarkers: [
      "This is a newer attack class without mature, standardized log-based detection — the queries below cover what IS realistically detectable (the planted content itself, and gross usage patterns), not a complete detection story the way most other entries in this matrix offer.",
      'The injected content has to actually get retrieved to matter — a poisoned document sitting unread is inert; correlate suspicious content discovery with evidence it was actually part of a Copilot grounding context.',
      "Because Copilot only surfaces content the querying user already has permission to access, this technique doesn't grant new access on its own — it manipulates what a user with legitimate access ends up seeing or being told.",
    ],
  },

  kql: {
    sentinel: {
      triage: {
        title: 'Copilot interaction activity',
        description:
          'Illustrative only — exact audit coverage and operation names for Copilot interactions are still evolving in Purview. Confirm current event names against Microsoft\'s own documentation before relying on this as written.',
        query: `OfficeActivity
| where TimeGenerated > ago(14d)
| where Operation has_any ("Copilot", "AIInteraction")
| project TimeGenerated, UserId, Operation, Parameters
| order by TimeGenerated desc`,
      },
    },
    defender: {
      triage: {
        title: 'Copilot-related activity',
        query: `CloudAppEvents
| where Timestamp > ago(14d)
| where ActionType has "Copilot"
| project Timestamp, AccountDisplayName, ActionType, RawEventData
| order by Timestamp desc`,
      },
    },
  },

  runbook: {
    triage: [
      'Identify the specific document/email suspected of containing injected content.',
      'Review what a user reported or noticed as unexpected Copilot output.',
      'Determine who has access to, and could have edited, the suspect content.',
      "Assess how broadly the content was shared/accessible, which bounds the potential blast radius.",
    ],
    contain: [
      'Remove or quarantine the offending document/email — the content itself is effectively the payload here.',
      'Notify users who may have queried content that included it.',
      'Review sharing/edit permissions on the source content to determine who could have planted it.',
      'Restrict broad content access where feasible while investigating.',
    ],
    investigate: [
      'Determine how the injected content was introduced — external sharing, a compromised account, or a malicious insider.',
      'Assess what Copilot actually surfaced or acted on as a result, across any users who queried it.',
      'Check whether this is an isolated document or part of a broader pattern.',
      "Review the content's edit history for when the injection was actually added.",
    ],
    recover: [
      'Apply DLP/sensitivity controls to reduce over-broad content access, which limits what any single injection could reach.',
      "Review and apply Microsoft's evolving Copilot governance and content controls as they mature.",
      'Brief users that Copilot output should be treated with the same skepticism as any other content source, especially when it includes instructions or requests.',
      'Periodically scan high-visibility, broadly-shared content for hidden-text indicators as a precautionary measure.',
    ],
  },
}

export default entry
