import type { ThreatEntry } from '../../../../types/threat'

const entry: ThreatEntry = {
  id: 'ediscovery-compliance-search-abuse',
  title: 'eDiscovery / Compliance Search Abuse',
  domain: 'data-exfiltration-ai',
  category: 'Collection / Exfiltration',
  severity: 'high',
  status: 'complete',
  shortDesc: 'Leveraging legitimate legal-hold search functions like New-ComplianceSearch to silently aggregate and export tenant-wide PSTs, disguised as routine compliance activity.',
  description:
    "eDiscovery and Compliance Search are powerful, intentionally broad tools — by design, they can search and export content across the entire tenant, including mailboxes and sites the searching user wouldn't otherwise access directly. An attacker who compromises an account with eDiscovery Manager permissions can construct a search matching exactly the content they want and export it in bulk, superficially resembling routine legal or compliance work rather than an obvious attack.",

  forensicArtifacts: [
    {
      source: 'OfficeActivity — the Unified Audit Log (UAL)',
      artifact: "Operation == 'New-ComplianceSearch' or 'Set-ComplianceSearch' with the search query and target mailbox/site scope — a search scoped tenant-wide or across many unrelated mailboxes is the primary anomaly signal",
    },
    {
      source: 'OfficeActivity',
      artifact: "Operation == 'New-ComplianceSearchAction' with an Export action type — the actual exfiltration step; a Purge action type is a separate, even more concerning destructive variant",
    },
    {
      source: 'Entra ID role assignment',
      artifact: 'How the acting identity obtained eDiscovery Manager or an equivalent compliance role — this requires a specific, normally small population of privileged accounts',
    },
    {
      source: 'Exported content location',
      artifact: 'Where the exported PST/data package was downloaded to or stored, and whether that destination is monitored/expected for legal/compliance workflows',
    },
    {
      source: 'Legal/compliance case management (outside Entra telemetry)',
      artifact: "Whether the search corresponds to an actual, documented legal hold or investigation case — the search technically being compliant tooling use doesn't mean it's legitimate use",
    },
  ],

  telemetry: {
    correlationMarkers: [
      "Search scope is the single most informative signal — a search targeting the CEO's mailbox, all Finance mailboxes, or the entire tenant deserves more scrutiny than one scoped to a single named custodian consistent with a specific case.",
      'The search creation and the export are separate steps — a search alone doesn\'t move data anywhere; watch specifically for New-ComplianceSearchAction with an Export type to catch the actual exfiltration moment.',
      "Cross-reference against your organization's actual legal/HR case tracking — a compliance search with no corresponding case record is the core anomaly, since the tooling itself can't distinguish legitimate from abusive use.",
    ],
  },

  mitre: [{ id: 'T1213', name: 'Data from Information Repositories', tactic: 'Collection' }],

  kql: {
    sentinel: {
      triage: {
        title: 'Compliance search creation',
        query: `OfficeActivity
| where TimeGenerated > ago(30d)
| where Operation in ("New-ComplianceSearch", "Set-ComplianceSearch")
| project TimeGenerated, UserId, ClientIP, Operation, Parameters
| order by TimeGenerated desc`,
      },
      investigate: {
        title: 'Export actions — the step that actually moves data out',
        query: `OfficeActivity
| where TimeGenerated > ago(30d)
| where Operation == "New-ComplianceSearchAction"
| where Parameters has "Export"
| project TimeGenerated, UserId, ClientIP, Parameters
| order by TimeGenerated desc`,
      },
    },
    defender: {
      triage: {
        title: 'Compliance search and export activity',
        query: `CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType has_any ("ComplianceSearch", "New-ComplianceSearchAction")
| project Timestamp, AccountDisplayName, ActionType, RawEventData
| order by Timestamp desc`,
      },
    },
  },

  runbook: {
    triage: [
      'Pull the full search definition — query and scope — and any associated export/purge actions.',
      "Identify the acting identity and confirm their eDiscovery Manager role is expected.",
      'Cross-reference against actual legal/compliance case records.',
      'Determine the volume and sensitivity of content the search actually matched.',
    ],
    contain: [
      'Revoke sessions for the acting identity if abuse is confirmed.',
      'Disable/remove the compliance search and any pending export.',
      'Restrict eDiscovery role membership if broader than necessary.',
      'Secure or delete the exported content if it was not yet distributed further.',
    ],
    investigate: [
      'Determine exactly what content was exported and to where.',
      'Check whether the export destination is secure/monitored or represents actual exfiltration.',
      'Review the acting account for broader compromise indicators.',
      'Establish whether this is an isolated event or part of a broader pattern of compliance tooling misuse.',
    ],
    recover: [
      'Implement an approval workflow for compliance searches scoped broadly (multiple custodians, tenant-wide) or including export/purge actions.',
      'Tightly govern and monitor eDiscovery Manager role membership.',
      'Alert on every export action from a compliance search as a standing high-priority detection, given how infrequent and high-stakes legitimate use should be.',
      'Require a documented case reference for every new compliance search as a matter of process.',
    ],
  },
}

export default entry
