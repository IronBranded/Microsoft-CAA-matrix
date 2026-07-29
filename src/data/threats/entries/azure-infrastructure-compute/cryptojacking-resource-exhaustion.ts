import type { ThreatEntry } from '../../../../types/threat'

const entry: ThreatEntry = {
  id: 'cryptojacking-resource-exhaustion',
  title: 'Cryptojacking & Resource Exhaustion',
  domain: 'azure-infrastructure-compute',
  category: 'Impact',
  severity: 'medium',
  status: 'complete',
  shortDesc: "Deploying unauthorized compute workloads — miners or high-scale GPU instances — using a compromised subscription's spending limits and quota.",
  description:
    "Once an attacker holds sufficient Azure permissions, a common financially-motivated follow-on action is standing up large numbers of compute instances, frequently GPU-optimized SKUs, to run cryptocurrency mining at the victim's expense. This is often the most visible sign of compromise, since it triggers cost alerts, but by the time it's noticed the same access may already have been used for quieter, more damaging activity.",

  forensicArtifacts: [
    {
      source: 'AzureActivity',
      artifact: 'A burst of VM creation operations deploying many VMs in a short window, often GPU-optimized SKUs, from a caller with no prior history of provisioning at that scale (requires a Diagnostic Setting routing the Activity Log to your workspace)',
    },
    {
      source: 'Azure Cost Management',
      artifact: 'A sudden, sharp spend increase concentrated in compute — often the first signal noticed in practice, since it triggers billing alerts before any security-specific detection',
    },
    {
      source: 'AzureActivity',
      artifact:
        "VM deployments across unusual regions, geographically distant from the organization's normal footprint, sometimes chosen for GPU SKU availability or lower cost. A quota increase request (Microsoft.Capacity/resourceProviders/locations/serviceLimits or a support-ticket-driven quota bump) immediately preceding the deployment burst is often the actual first move — default subscription vCPU quotas are usually too low to deploy at cryptomining scale without one, making the quota request itself a checkable precursor event rather than just the resulting VMs.",
    },
    {
      source: 'DeviceProcessEvents (VM guest OS)',
      artifact: 'Known cryptomining process names/command-line patterns, or sustained near-100% CPU/GPU utilization with no corresponding legitimate workload',
    },
    {
      source: 'AzureActivity',
      artifact: 'The caller\'s identity and how they obtained sufficient quota/permissions to provision at this scale — often a compromised service principal rather than a human admin acting deliberately',
    },
  ],

  telemetry: {
    correlationMarkers: [
      'Volume and SKU choice together are the strongest signal — many VMs, especially GPU-optimized ones, deployed in a short window is a shape legitimate provisioning rarely takes.',
      'Cost anomaly detection often beats security telemetry to this one in practice — treat a finance/billing alert as a legitimate, high-value security signal source, not just a security tool alert.',
      'The compute itself is usually the least interesting part of the incident — the compromised identity/credential that enabled it is the real finding and may have broader implications beyond the mining itself.',
    ],
  },

  mitre: [{ id: 'T1496', name: 'Resource Hijacking', tactic: 'Impact' }],

  kql: {
    sentinel: {
      triage: {
        title: 'High-volume VM provisioning',
        query: `AzureActivity
| where TimeGenerated > ago(1d)
| where OperationNameValue =~ "Microsoft.Compute/virtualMachines/write"
| where ActivityStatusValue == "Success"
| summarize VmCount = count(), Regions = make_set(Resource, 10) by Caller, bin(TimeGenerated, 1h)
| where VmCount > 5  // tune against your tenant's normal provisioning baseline
| order by VmCount desc`,
      },
      investigate: {
        title: "Caller's broader activity in the surrounding window",
        query: `let suspect_caller = "<Caller from triage step>";
AzureActivity
| where TimeGenerated > ago(1d)
| where Caller == suspect_caller
| project TimeGenerated, OperationNameValue, ResourceGroup, Resource, ActivityStatusValue
| order by TimeGenerated desc`,
      },
    },
    defender: {
      hunt: {
        title: 'Cryptomining process indicators',
        description: 'Requires Defender for Endpoint on the VM guest OS.',
        query: `DeviceProcessEvents
| where Timestamp > ago(1d)
| where ProcessCommandLine has_any ("xmrig", "minerd", "stratum+tcp")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc`,
      },
    },
  },

  runbook: {
    triage: [
      'Identify the full set of unauthorized VMs and their regions/SKUs.',
      'Determine the caller identity and how it obtained sufficient quota/permissions.',
      'Confirm via guest OS telemetry whether mining processes are actually running.',
    ],
    contain: [
      'Deallocate and delete the unauthorized VMs immediately.',
      'Revoke/rotate the compromised credential that enabled provisioning.',
      'Request an Azure subscription quota/spend review to cap further damage while remediating.',
    ],
    investigate: [
      'Determine the root compromise that gave the attacker sufficient access — leaked service principal credential, compromised account.',
      'Check whether the same access was used for anything beyond mining.',
      'Calculate actual cost impact for any required reporting.',
    ],
    recover: [
      'Implement resource/spend anomaly alerting as a standing detection independent of security tooling.',
      'Apply least-privilege RBAC and quota limits to reduce the blast radius of any future credential compromise.',
      'Review and rotate all credentials the same identity had access to.',
    ],
  },
}

export default entry
