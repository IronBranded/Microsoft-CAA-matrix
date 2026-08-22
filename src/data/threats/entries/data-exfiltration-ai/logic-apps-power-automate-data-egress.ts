import type { ThreatEntry } from '../../../../types/threat'

const entry: ThreatEntry = {
  id: 'logic-apps-power-automate-data-egress',
  title: 'Logic Apps / Power Automate Data Egress',
  domain: 'data-exfiltration-ai',
  category: 'Exfiltration',
  severity: 'medium',
  status: 'complete',
  shortDesc: 'Building a covert HTTP webhook trigger inside a Logic App or Power Automate flow to continuously stream internal events to an external listener.',
  description:
    'Both Logic Apps and Power Automate can trigger on internal events and take an HTTP action as a response, including posting to an arbitrary external URL. An attacker with the ability to create or modify a flow can build an automation that mirrors a continuous stream of internal activity out to attacker-controlled infrastructure, looking to a casual reviewer like unremarkable business automation. This spans two related but distinct platforms — Azure Logic Apps and Power Automate — with different audit surfaces worth checking together.',

  forensicArtifacts: [
    {
      logSourceId: 'azure-activity-log',
      source: 'AzureActivity',
      artifact: 'Logic App creation/modification defining an HTTP action posting to an external, unfamiliar endpoint — the Azure-resource-side equivalent of a malicious Power Automate flow (requires a Diagnostic Setting routing the Activity Log to your workspace)',
    },
    {
      source: 'Logic App run history',
      artifact:
        "Actual execution history and the volume/frequency of data sent to the external endpoint — confirms ongoing operation, not just configuration. Run history in the portal has a default retention window (commonly 90 days) after which older runs age out; for anything beyond that window, the Logic App's own Diagnostic Settings (WorkflowRuntime logs, a separate diagnostic category from the AzureActivity control-plane log above) need to already have been routed to a workspace, or that history is simply gone.",
    },
    {
      logSourceId: 'unified-audit-log',
      source: 'OfficeActivity (Power Automate) — the Unified Audit Log (UAL)',
      artifact: 'Flow definitions with a recurrence trigger combined with an HTTP action — the continuous-streaming pattern that distinguishes this from a one-time export',
    },
    {
      source: 'Network telemetry / firewall logs',
      artifact: "Sustained, regular outbound connections to an external endpoint matching the Logic App/flow's configured schedule — visible at the network layer independent of the Azure/M365 audit trail",
    },
    {
      source: 'AzureActivity / OfficeActivity',
      artifact: 'The creating/owning identity and whether Logic App or Power Automate creation is expected for that role',
    },
  ],

  telemetry: {
    correlationMarkers: [
      'A recurrence-triggered flow with an external HTTP destination is functionally a standing exfiltration channel, distinct from and more concerning than a one-time manual export — the recurrence is the key differentiator.',
      'This spans two related but distinct platforms — Azure Logic Apps (ARM-managed, AzureActivity-visible) and Power Automate (M365-managed, OfficeActivity-visible) — check both, since an attacker with access to either could use it similarly.',
      "Network-layer visibility can corroborate or even precede audit-log-based detection, especially if the flow's own configuration audit trail is incomplete.",
    ],
  },

  mitre: [{ id: 'T1567', name: 'Exfiltration Over Web Service', tactic: 'Exfiltration' }],

  atrm: [{ id: 'AZT503.1', name: 'Logic Application HTTP Trigger', tactic: 'Persistence' }],

  kql: {
    sentinel: {
      triage: {
        title: 'Logic App creation/modification (Azure-side)',
        query: `AzureActivity
| where TimeGenerated > ago(14d)
| where OperationNameValue =~ "Microsoft.Logic/workflows/write"
| project TimeGenerated, Caller, CallerIpAddress, ResourceGroup, Resource, CorrelationId
| order by TimeGenerated desc`,
      },
      investigate: {
        title: 'Power Automate flows with recurrence + HTTP action (M365-side)',
        query: `OfficeActivity
| where TimeGenerated > ago(14d)
| where Operation in ("CreateFlow", "EditFlow")
| where Parameters has_any ("Recurrence", "HTTP")
| project TimeGenerated, UserId, Operation, Parameters
| order by TimeGenerated desc`,
      },
    },
    defender: {
      triage: {
        title: 'Flow creation with HTTP action',
        query: `CloudAppEvents
| where Timestamp > ago(14d)
| where ActionType has_any ("CreateFlow", "EditFlow")
| where RawEventData has "HTTP"
| project Timestamp, AccountDisplayName, ActionType, RawEventData
| order by Timestamp desc`,
      },
    },
  },

  runbook: {
    triage: [
      'Identify the specific Logic App or flow, its trigger type (recurrence vs. manual), and destination endpoint.',
      'Determine the creating/owning account and their normal role.',
      'Check run history for actual data volume moved.',
    ],
    contain: [
      'Disable the Logic App/flow immediately.',
      'Block the destination endpoint at the network/firewall layer.',
      'Review the creating account for broader compromise.',
    ],
    investigate: [
      'Determine what data was actually sent and its sensitivity.',
      'Establish how long the flow had been running before detection.',
      'Check for similar flows/Logic Apps created by the same actor.',
    ],
    recover: [
      'Implement Power Platform DLP policies and Azure Policy restricting Logic App HTTP actions to approved endpoints.',
      'Monitor for recurrence-triggered automation with external HTTP destinations as a standing detection.',
      'Require an approval workflow for both Logic App and Power Automate flows using HTTP/webhook actions.',
    ],
  },
}

export default entry
