import type { ThreatEntry } from '../../../../types/threat'

const entry: ThreatEntry = {
  id: 'os-disk-snapshot-vhd-exfiltration',
  title: 'OS Disk Snapshot & VHD Exfiltration',
  domain: 'azure-infrastructure-compute',
  category: 'Collection / Exfiltration',
  severity: 'high',
  status: 'complete',
  shortDesc: 'Creating an unmonitored disk snapshot or exporting a VM\'s OS/data disk to an unauthenticated storage blob, to dump SAM/LSASS material offline.',
  description:
    'Rather than attacking a running VM\'s defenses directly, an attacker with sufficient Azure permissions can snapshot its disk and export the resulting VHD to a storage account — potentially with an overly-permissive SAS token — then mount and analyze it entirely offline. This sidesteps any endpoint detection on the live VM and gives the attacker unhurried access to registry hives and credential material.',

  forensicArtifacts: [
    {
      source: 'AzureActivity',
      artifact: 'Microsoft.Compute/snapshots/write creating a new disk snapshot, or a disk write operation referencing an existing snapshot for export',
    },
    {
      source: 'AzureActivity',
      artifact: 'Generation of a SAS access grant against the snapshot (beginGetAccess) — the actual mechanism that makes a normally-inaccessible managed disk downloadable (requires a Diagnostic Setting routing the Activity Log to your workspace — confirm this exists before trusting an empty result)',
    },
    {
      source: 'AzureActivity',
      artifact: 'The destination of any export — a storage account, and specifically whether it is within the same subscription/tenant or belongs to an external subscription entirely',
    },
    {
      source: 'AzureActivity',
      artifact: 'The caller\'s Azure RBAC role and whether snapshot creation/export is expected for that identity — requires Contributor-level access on the source disk/VM',
    },
    {
      source: 'Storage account access logs',
      artifact: 'A large blob upload matching the size of the source disk, landing in a storage account shortly after the export operation, if the destination is monitored',
    },
  ],

  telemetry: {
    correlationMarkers: [
      'Snapshot creation alone is often benign — many backup solutions do this routinely. The SAS/beginGetAccess step is what actually makes exfiltration possible, and is the more specific signal to alert on.',
      "Cross-subscription or cross-tenant export destinations are far more suspicious than exports staying within the source's own subscription.",
      'SAS token expiry duration: a short-lived token consistent with a legitimate one-time need looks very different from a long-lived one clearly intended for extended, repeated access.',
    ],
  },

  mitre: [
    { id: 'T1578.001', name: 'Modify Cloud Compute Infrastructure: Create Snapshot', tactic: 'Defense Evasion' },
    { id: 'T1537', name: 'Transfer Data to Cloud Account', tactic: 'Exfiltration' },
  ],

  atrm: [{ id: 'AZT701.1', name: 'VM Disk SAS URI', tactic: 'Impact' }],

  kql: {
    sentinel: {
      triage: {
        title: 'Snapshot creation and SAS/export access grants',
        query: `AzureActivity
| where TimeGenerated > ago(14d)
| where OperationNameValue in (
    "Microsoft.Compute/snapshots/write",
    "Microsoft.Compute/snapshots/beginGetAccess/action",
    "Microsoft.Compute/disks/beginGetAccess/action"
)
| project TimeGenerated, Caller, CallerIpAddress, ResourceGroup, Resource, OperationNameValue, CorrelationId
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
      triage: {
        title: 'Snapshot and access-grant activity',
        query: `CloudAppEvents
| where Timestamp > ago(14d)
| where ActionType has_any ("snapshot", "beginGetAccess")
| project Timestamp, AccountDisplayName, ActionType, IPAddress, RawEventData
| order by Timestamp desc`,
      },
    },
  },

  runbook: {
    triage: [
      'Identify the snapshot/export operation and its destination.',
      'Determine whether the destination is same-subscription, cross-subscription, or fully external.',
      "Check the caller's RBAC and whether this matches expected backup/DR tooling.",
      'Establish the SAS token\'s configured expiry and access scope.',
    ],
    contain: [
      'Revoke the SAS token / access grant immediately (`az disk revoke-access` or the snapshot equivalent).',
      'Delete the unauthorized snapshot if no longer needed for investigation.',
      "Scope down the caller's Azure RBAC.",
      'Block the destination storage account if external and unauthorized.',
    ],
    investigate: [
      'Determine whether the export was actually downloaded — storage account access logs, network egress volume — versus just prepared.',
      'Identify what data was on the source disk, particularly credential material or sensitive application data.',
      'Check for repeated exports across multiple disks/VMs.',
      "Confirm the caller's own access was itself compromised, versus legitimate access being misused.",
    ],
    recover: [
      'Restrict snapshot creation and access-grant permissions via least-privilege RBAC.',
      'Require snapshot exports to flow only through an approved, monitored backup pipeline.',
      'Alert on beginGetAccess/SAS generation against snapshots and disks as a standing high-priority detection, given how infrequent legitimate use should be.',
      'Consider disk encryption with customer-managed keys, which adds a further barrier to offline analysis of an exported disk.',
    ],
  },
}

export default entry
