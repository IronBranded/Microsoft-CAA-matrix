import type { ThreatEntry } from '../../../../types/threat'

const entry: ThreatEntry = {
  id: 'vm-extension-abuse',
  title: 'VM Extension Abuse',
  domain: 'azure-infrastructure-compute',
  category: 'Persistence / Execution',
  severity: 'high',
  status: 'complete',
  shortDesc: 'Deploying a malicious Azure VM Extension, most commonly CustomScriptExtension, via the ARM API to gain persistent OS-level code execution.',
  description:
    'VM Extensions are the standard mechanism for post-provisioning configuration and execute with full administrative privilege inside the guest OS. An attacker with ARM-level write access to a VM resource can deploy a CustomScriptExtension that runs attacker-supplied code, functioning as both an execution primitive and a durable persistence mechanism, since extensions can be configured to re-run on a schedule or reboot.',

  forensicArtifacts: [
    {
      source: 'AzureActivity',
      artifact: 'Microsoft.Compute/virtualMachines/extensions/write — deployment of a new VM extension, most commonly CustomScriptExtension or its Linux equivalent',
    },
    {
      source: 'AzureActivity',
      artifact: "The extension's publisher/type and settings/protectedSettings parameters — protectedSettings are encrypted at rest but still readable by anyone with sufficient RBAC to view the extension configuration, or by the VM Agent at execution time",
    },
    {
      source: 'VM guest OS — extension working directories',
      artifact: 'The deployed script content and execution logs under the extension handler\'s local directory, recoverable shortly after execution',
    },
    {
      source: 'DeviceProcessEvents (VM guest OS)',
      artifact: 'A process tree rooted in the extension handler rather than an interactive session, similar in signature to Run Command abuse',
    },
    {
      source: 'AzureActivity',
      artifact: "The caller's Azure RBAC role and whether extension deployment is expected for that identity — requires the same class of Contributor-level access as Run Command",
    },
  ],

  telemetry: {
    correlationMarkers: [
      'Extensions deployed outside your normal provisioning/configuration-management pipeline are the core anomaly — baseline what deploys extensions normally first.',
      'CustomScriptExtension specifically is the most common vector since it accepts an arbitrary script URL or inline command — treat its use with proportionally more scrutiny than other extension types.',
      'Unlike Run Command, an extension persists on the VM as a resource and can be configured to re-run — check for extensions still present on affected VMs after initial remediation, not just the deployment event.',
    ],
  },

  mitre: [
    { id: 'T1072', name: 'Software Deployment Tools', tactic: 'Execution' },
    { id: 'T1078.004', name: 'Valid Accounts: Cloud Accounts', tactic: 'Privilege Escalation' },
  ],

  kql: {
    sentinel: {
      triage: {
        title: 'VM extension deployments',
        query: `AzureActivity
| where TimeGenerated > ago(14d)
| where OperationNameValue =~ "Microsoft.Compute/virtualMachines/extensions/write"
| where ActivityStatusValue == "Success"
| project TimeGenerated, Caller, CallerIpAddress, ResourceGroup, Resource, CorrelationId
| order by TimeGenerated desc`,
      },
      investigate: {
        title: "Caller's broader activity in the surrounding window",
        query: `let suspect_caller = "<Caller from triage step>";
AzureActivity
| where TimeGenerated > ago(14d)
| where Caller == suspect_caller
| project TimeGenerated, OperationNameValue, ResourceGroup, Resource, ActivityStatusValue
| order by TimeGenerated desc`,
      },
    },
    defender: {
      hunt: {
        title: 'Process activity rooted in an extension handler',
        description: 'Requires Defender for Endpoint on the VM guest OS.',
        query: `DeviceProcessEvents
| where Timestamp > ago(14d)
| where FolderPath has_any ("Extensions", "CustomScript")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc`,
      },
    },
  },

  runbook: {
    triage: [
      'Identify the extension type/publisher and pull the script content if recoverable.',
      "Confirm the caller's RBAC and whether extension deployment is expected for that identity or pipeline.",
      'Check whether the same extension was deployed across multiple VMs.',
      "Determine whether the extension is still present and active, not just when it was first deployed.",
    ],
    contain: [
      'Remove the malicious extension from affected VM(s).',
      "Scope down the caller's Azure RBAC.",
      'Isolate affected VM(s) at the network layer.',
      "Rotate credentials or secrets reachable from the VM's local context.",
    ],
    investigate: [
      'Determine what the script actually did on the guest OS.',
      'Check for the same extension or pattern deployed across other VMs.',
      'Cross-reference with Run Command and IMDS & Managed Identity Token Theft elsewhere in this domain.',
      "Confirm the caller's own access was itself compromised, versus an over-permissioned but legitimate identity being misused.",
    ],
    recover: [
      'Restrict extension deployment permissions via least-privilege RBAC or Azure Policy.',
      'Monitor extension deployments as a standing detection, not just a one-off hunt.',
      'Require extensions to deploy only through an approved, monitored pipeline.',
      'Periodically audit currently-deployed extensions across the estate against expected baseline.',
    ],
  },
}

export default entry
