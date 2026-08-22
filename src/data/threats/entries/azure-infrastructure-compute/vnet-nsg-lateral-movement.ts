import type { ThreatEntry } from '../../../../types/threat'

const entry: ThreatEntry = {
  id: 'vnet-nsg-lateral-movement',
  title: 'VNet / NSG Lateral Movement',
  domain: 'azure-infrastructure-compute',
  category: 'Lateral Movement',
  severity: 'medium',
  status: 'complete',
  shortDesc: 'Bypassing flat, under-segmented Azure Virtual Networks due to overly permissive Network Security Groups or a lack of microsegmentation.',
  description:
    'Many Azure environments grow organically into large, flat VNets where NSG rules permit broad any-to-any traffic within the address space. An attacker who compromises any single VM inside such a network can move laterally to reach far more sensitive resources than that initial foothold\'s own role would suggest, since network segmentation was the only real boundary — and it wasn\'t actually enforced.',

  forensicArtifacts: [
    {
      logSourceId: 'nsg-flow-logs',
      source: 'NSG Flow Logs (deprecated) / Virtual Network Flow Logs (current)',
      artifact:
        "Internal east-west traffic between VMs/subnets that shouldn't have a legitimate reason to communicate directly, given an overly permissive any-to-any NSG rule — this data doesn't exist at all unless Flow Logs are explicitly enabled, and NSG Flow Logs specifically stopped accepting new configurations in mid-2025 in favor of Virtual Network Flow Logs, the current recommended path. Check which one, if either, is actually configured before treating an empty result as clean — an environment predating the deprecation may still be relying on the older, no-longer-creatable NSG version.",
    },
    {
      logSourceId: 'azure-activity-log',
      source: 'AzureActivity',
      artifact: 'The NSG rule configuration itself — broad source/destination ranges rather than specific, narrow rules between the subnets that actually need to talk',
    },
    {
      logSourceId: 'defender-endpoint-hunting',
      source: 'DeviceNetworkEvents (VM guest OS)',
      artifact: "A compromised VM initiating connections to other internal VMs on ports/services beyond its own normal role",
    },
    {
      logSourceId: 'defender-endpoint-hunting',
      source: 'DeviceLogonEvents (destination VM)',
      artifact: "Successful or attempted authentication on a second VM originating from the first compromised VM's internal IP, rather than from any expected management/jump-host source",
    },
    {
      source: 'Microsoft Defender for Cloud',
      artifact: 'Built-in recommendations flagging overly permissive NSG rules or lack of network segmentation as a posture issue',
    },
  ],

  telemetry: {
    correlationMarkers: [
      "NSGs default to deny for inbound internet traffic but are frequently left permissive for internal VNet-to-VNet or subnet-to-subnet traffic — the assumption that 'internal' means 'trusted' is exactly what this technique exploits.",
      'A compromised VM reaching internal targets it has no legitimate business reason to reach is the core signal — baseline expected internal communication patterns per VM/subnet role to make deviations visible.',
      'Combine network-layer evidence with host-layer evidence (DeviceLogonEvents on the destination) for the strongest case — network connectivity alone doesn\'t confirm a genuine lateral movement attempt succeeded.',
      'There is deliberately no relevantErrorCodes entry for this scenario either: NSG Flow Logs record Allow/Deny decisions, not error codes, and a permissive rule allowing lateral movement means the connection succeeds cleanly with no error at all — the absence of any denial is the problem, and that absence doesn\'t show up as a code to alert on.',
    ],
  },

  mitre: [
    { id: 'T1210', name: 'Exploitation of Remote Services', tactic: 'Lateral Movement' },
    { id: 'T1021', name: 'Remote Services', tactic: 'Lateral Movement' },
  ],

  kql: {
    sentinel: {
      triage: {
        title: 'NSG rule changes permitting broad internal traffic',
        query: `AzureActivity
| where TimeGenerated > ago(30d)
| where OperationNameValue =~ "Microsoft.Network/networkSecurityGroups/securityRules/write"
| project TimeGenerated, Caller, ResourceGroup, Resource, CorrelationId
| order by TimeGenerated desc`,
      },
      investigate: {
        title: 'NSG Flow Log traffic analysis (requires Traffic Analytics)',
        description:
          'Requires NSG Flow Logs with Traffic Analytics enabled. The exact ingested table name varies by configuration — check your workspace for what was actually provisioned and adapt the query below, shown here as a shape rather than a verified-as-is reference.',
        query: `// AzureNetworkAnalytics_CL
// | where TimeGenerated > ago(1d)
// | where FlowDirection_s == "Internal"
// | summarize FlowCount = count() by SrcIP_s, DestIP_s, DestPort_d
// | where FlowCount > 100`,
      },
    },
    defender: {
      hunt: {
        title: 'Internal port-scanning-like connection pattern',
        description: 'Requires Defender for Endpoint on the VM guest OS.',
        query: `DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemoteIPType == "Private"
| summarize ConnectionCount = count(), DistinctPorts = dcount(RemotePort) by DeviceName, RemoteIP
| where DistinctPorts > 5
| order by ConnectionCount desc`,
      },
    },
  },

  runbook: {
    triage: [
      'Review NSG rules for overly permissive internal traffic allowances.',
      'Identify the source (compromised) VM and its intended normal role.',
      'Check destination VM(s) for signs of actual compromise versus just connection attempts.',
    ],
    contain: [
      'Tighten NSG rules to deny unnecessary internal traffic immediately.',
      'Isolate the source VM at the network layer.',
      'Monitor/isolate any destination VM showing signs of successful lateral movement.',
    ],
    investigate: [
      'Determine the full scope of internal systems reached or attempted.',
      'Establish the original entry point that compromised the source VM.',
      'Assess what data/access the destination VM(s) exposed if reached successfully.',
    ],
    recover: [
      'Implement microsegmentation — narrow, specific NSG rules between only the subnets/VMs that genuinely need to communicate.',
      'Deploy Azure Firewall or NVA-based inspection for internal traffic where warranted.',
      'Enable NSG Flow Logs with Traffic Analytics for ongoing visibility into internal traffic patterns.',
    ],
  },
}

export default entry
