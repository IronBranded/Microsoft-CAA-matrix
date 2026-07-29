import type { ThreatEntry } from '../../../../types/threat'

const entry: ThreatEntry = {
  id: 'azure-run-command-serial-console-execution',
  title: 'Azure Run Command / Serial Console Execution',
  domain: 'azure-infrastructure-compute',
  category: 'Execution',
  severity: 'critical',
  status: 'complete',
  shortDesc:
    "Abusing Azure Resource Manager's Run Command capability to execute arbitrary root/SYSTEM-level scripts on a VM without ever needing OS-level credentials.",
  description:
    'Run Command is a legitimate management capability that lets anyone with sufficient Azure RBAC permissions on a VM resource execute a script inside it, at the highest OS privilege level, entirely through the Azure control plane. An attacker who compromises an identity with Contributor on a VM, without ever touching its OS credentials, can use Run Command or the Serial Console as a fully-privileged remote code execution primitive.',

  forensicArtifacts: [
    {
      source: 'AzureActivity',
      artifact: 'Microsoft.Compute/virtualMachines/runCommand/action — the RBAC action for Run Command; appears regardless of which script was executed, so the operation itself is the primary signal (requires a Diagnostic Setting routing the Activity Log to your workspace — confirm this exists before trusting an empty result)',
    },
    {
      source: 'VM guest OS — Azure VM Agent working directories',
      artifact:
        'RunCommand scripts execute via the Azure VM Agent and leave process/execution artifacts under the agent\'s working directories (e.g. the RunCommandHandler plugin path on Windows, or /var/lib/waagent on Linux) — the script content itself may be recoverable shortly after execution',
    },
    {
      source: 'DeviceProcessEvents (VM guest OS)',
      artifact: 'A process tree rooted in the Azure VM Agent / Run Command handler rather than an interactive logon session — legitimate interactive administration does not look like this',
    },
    {
      source: 'Serial Console session activity',
      artifact: 'Boot Diagnostics / Serial Console access is a distinct control-plane action from Run Command, but with the same net effect: OS-level access without needing OS credentials',
    },
    {
      source: 'AzureActivity',
      artifact: "The caller's identity and Azure RBAC role on the specific VM resource — Run Command requires only a Contributor-level (or custom role with the specific action) grant, not any OS-level credential",
    },
  ],

  telemetry: {
    correlationMarkers: [
      "The RunCommand action itself doesn't log the script's full content or output into AzureActivity — correlate with the VM Agent's local execution artifacts, or whatever the script was designed to do, to know what actually ran.",
      "CorrelationId on the AzureActivity entry ties the RunCommand call back to the caller's broader session — pivot into what else that identity did in the same window.",
      "A caller with only Contributor, not Owner, can still execute Run Command — don't assume lower RBAC roles are lower-risk for this specific action.",
    ],
  },

  mitre: [
    { id: 'T1651', name: 'Cloud Administration Command', tactic: 'Execution' },
    { id: 'T1078.004', name: 'Valid Accounts: Cloud Accounts', tactic: 'Privilege Escalation' },
  ],

  atrm: [
    { id: 'AZT301.1', name: 'RunCommand', tactic: 'Execution' },
    { id: 'AZT301.7', name: 'Serial Console', tactic: 'Execution' },
  ],

  kql: {
    sentinel: {
      triage: {
        title: 'Run Command executions',
        query: `AzureActivity
| where TimeGenerated > ago(14d)
| where OperationNameValue =~ "Microsoft.Compute/virtualMachines/runCommand/action"
| where ActivityStatusValue == "Success"
| project TimeGenerated, Caller, CallerIpAddress, ResourceGroup, Resource, ActivityStatusValue, CorrelationId
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
        title: 'VM Agent Run Command handler process activity',
        description: 'Requires Defender for Endpoint on the VM guest OS. Exact folder paths vary by OS/agent version — adjust to match what you observe.',
        query: `DeviceProcessEvents
| where Timestamp > ago(14d)
| where FolderPath has_any ("RunCommandHandler", "waagent", "Plugins")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, AccountName, InitiatingProcessFileName
| order by Timestamp desc`,
      },
    },
  },

  runbook: {
    triage: [
      'Identify the caller and confirm whether Run Command usage is expected for that identity — some legitimate automation does use it, so baseline first.',
      'Pull whatever script content/output can still be recovered from the VM Agent local artifacts.',
      "Check the caller's Azure RBAC scope — Run Command works with resource-level Contributor, so confirm exactly which resources the caller could reach.",
      'Establish whether this was a one-off or part of a broader pattern across multiple VMs.',
    ],
    contain: [
      "Remove or scope down the caller's Azure RBAC permissions on the affected VM(s) immediately.",
      'Isolate the affected VM(s) at the network layer pending investigation, since Run Command implies attacker-controlled code has already executed inside the guest OS.',
      "Rotate any credentials or secrets accessible from the VM's local context, including its Managed Identity token if any (see IMDS & Managed Identity Token Theft elsewhere in this matrix).",
      'Review and restrict which roles/identities can invoke the runCommand action tenant-wide.',
    ],
    investigate: [
      'Determine what the executed script actually did, via recovered content, VM Agent logs, and any resulting file/process/network changes on the guest OS.',
      "Check whether the caller's own credentials were compromised, or whether this was an over-permissioned but otherwise-legitimate identity being misused.",
      'Look for follow-on activity consistent with further persistence — new scheduled tasks, new local accounts, new listening services.',
      'Cross-reference with VM Extension Abuse and IMDS & Managed Identity Token Theft elsewhere in this domain — Run Command is frequently a stepping stone into one of those.',
    ],
    recover: [
      'Apply least-privilege Azure RBAC so Run Command capability is scoped only to identities and resources that genuinely need it.',
      'Consider Azure Policy to restrict or gate the runCommand action tenant-wide.',
      'Stand up the AzureActivity-based detection above as a permanent alert — Run Command executions are infrequent enough in most environments that even a simple volume/baseline alert is high-value.',
      'Remediate whatever gave the attacker Azure-level access in the first place — this technique depends entirely on already holding sufficient Azure RBAC, not a vulnerability in Run Command itself.',
    ],
  },
}

export default entry
