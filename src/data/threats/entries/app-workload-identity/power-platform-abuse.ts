import type { ThreatEntry } from '../../../../types/threat'

const entry: ThreatEntry = {
  id: 'power-platform-abuse',
  title: 'Power Platform Abuse',
  domain: 'app-workload-identity',
  category: 'Collection / Exfiltration',
  severity: 'medium',
  status: 'complete',
  shortDesc: 'Exploiting Power Automate or Power Apps for ambient, low-visibility data exfiltration or automated credential gathering.',
  description:
    "Power Automate flows and Power Apps run with the permissions of their creator and can be built by any licensed user, often outside IT's normal application governance. An attacker with access to an account can build a flow that quietly forwards emails, copies files to an external location, or harvests form submissions — activity that blends into the volume of legitimate low-code automation most tenants already run.",

  forensicArtifacts: [
    {
      source: 'Power Platform admin center / audit logs',
      artifact: 'New Power Automate flows or Power Apps created by an account with no prior history of building automation, especially ones with HTTP/webhook actions pointing to external URLs',
    },
    {
      source: 'OfficeActivity — the Unified Audit Log (UAL)',
      artifact: 'Flow creation/modification events and the specific connectors used, particularly HTTP or connectors to external/personal cloud storage — Power Platform activity is captured in the same UAL as Exchange/SharePoint, provided it is enabled for the tenant',
    },
    {
      source: 'Power Platform Data Loss Prevention policies',
      artifact:
        "Whether a DLP policy exists that would block mixing business connectors (Exchange, SharePoint) with non-business ones (arbitrary HTTP, personal email) — the absence of such a policy is what makes this technique viable. Also check whether the environment the flow was created in is a Managed Environment — unmanaged environments generally have looser default governance (maker permissions, sharing limits, DLP enforcement scope) than Managed Environments, so which type of environment this happened in affects both root cause and how tightly remediation needs to scope.",
    },
    {
      source: 'Flow run history',
      artifact: 'Actual execution history showing the flow firing and the volume/content of data it moved — confirms real effect, not just configuration',
    },
    {
      source: 'Entra ID SigninLogs',
      artifact: "The creating account's sign-in context, to establish whether flow creation itself followed a known-compromise pattern",
    },
  ],

  telemetry: {
    correlationMarkers: [
      'Power Platform DLP policies, separate from Purview DLP, are the primary preventive control here — their absence, not just a specific malicious flow, is often the actual root-cause finding.',
      "A flow mixing a business-data connector with an HTTP or personal-cloud connector in the same flow is the classic exfiltration pattern — DLP policies are specifically designed to block exactly this combination.",
      "Flow ownership can be reassigned and flows can run under a service account context — verify which identity's permissions the flow actually executes with, which may differ from who created it.",
    ],
  },

  mitre: [
    { id: 'T1213', name: 'Data from Information Repositories', tactic: 'Collection' },
    { id: 'T1567', name: 'Exfiltration Over Web Service', tactic: 'Exfiltration' },
  ],

  kql: {
    sentinel: {
      triage: {
        title: 'Flow/app creation activity',
        query: `OfficeActivity
| where TimeGenerated > ago(14d)
| where Operation has_any ("CreateFlow", "EditFlow", "PowerAppCreate")
| project TimeGenerated, UserId, Operation, Parameters
| order by TimeGenerated desc`,
      },
      investigate: {
        title: 'Flows using HTTP/webhook actions',
        query: `OfficeActivity
| where TimeGenerated > ago(14d)
| where Operation has_any ("CreateFlow", "EditFlow")
| where Parameters has_any ("HTTP", "webhook")
| project TimeGenerated, UserId, Operation, Parameters
| order by TimeGenerated desc`,
      },
    },
    defender: {
      triage: {
        title: 'Flow creation/modification activity',
        query: `CloudAppEvents
| where Timestamp > ago(14d)
| where ActionType has_any ("CreateFlow", "EditFlow")
| project Timestamp, AccountDisplayName, ActionType, RawEventData
| order by Timestamp desc`,
      },
    },
  },

  runbook: {
    triage: [
      'Identify the specific flow, its connectors, and what data it touches.',
      'Determine the creating/owning account and their normal role.',
      'Check flow run history for actual execution and data volume.',
    ],
    contain: [
      'Disable the flow immediately.',
      'Revoke the connection references it used.',
      'Review the creating account for broader compromise.',
    ],
    investigate: [
      'Determine what data was actually moved and to where.',
      'Check for similar flows created by the same account or around the same time.',
      "Review whether Power Platform DLP policies were in place and why they didn't block this combination.",
    ],
    recover: [
      'Implement Power Platform DLP policies segregating business and non-business connectors.',
      'Restrict who can create flows with HTTP/webhook or external-storage connectors.',
      'Enable and monitor Power Platform audit logging as a standing part of the security monitoring program.',
    ],
  },
}

export default entry
