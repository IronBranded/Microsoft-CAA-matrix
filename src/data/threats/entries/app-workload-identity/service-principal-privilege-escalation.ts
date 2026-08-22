import type { ThreatEntry } from '../../../../types/threat'

const entry: ThreatEntry = {
  id: 'service-principal-privilege-escalation',
  title: 'Service Principal Privilege Escalation',
  domain: 'app-workload-identity',
  category: 'Privilege Escalation',
  severity: 'critical',
  status: 'complete',
  shortDesc:
    'Granting a directory role or a high-privilege application permission such as AppRoleAssignment.ReadWrite.All to an application, turning it into a privilege-escalation primitive.',
  description:
    "Certain Microsoft Graph application permissions are effectively equivalent to Global Administrator if granted to an app — AppRoleAssignment.ReadWrite.All lets its holder grant any application permission, including to itself, to any service principal in the tenant. An attacker who can get even a low-privilege-looking permission grant approved, if it's the right one, can bootstrap their way to full tenant control entirely through application permissions.",

  forensicArtifacts: [
    {
      logSourceId: 'entra-audit-logs',
      source: 'Entra ID AuditLogs',
      artifact: "OperationName == 'Add app role assignment to service principal' granting a high-privilege Graph application permission (AppRoleAssignment.ReadWrite.All, RoleManagement.ReadWrite.Directory, or similar) to an app",
    },
    {
      logSourceId: 'entra-audit-logs',
      source: 'Entra ID AuditLogs',
      artifact: 'TargetResources showing which app role/permission was granted and to which service principal — AppRoleAssignment.ReadWrite.All specifically is notable since it lets its holder grant further app roles, including to itself',
    },
    {
      source: 'Entra ID App registrations / Enterprise applications',
      artifact: "The granting identity's own permissions at the time of the grant — a Global Admin performing legitimate one-time consent looks very different from a service principal using an already-held escalation-capable permission to grant itself more",
    },
    {
      source: 'CloudAppEvents / OfficeActivity',
      artifact: 'API activity from the newly-escalated service principal immediately following the grant, using its new permission scope',
    },
    {
      logSourceId: 'entra-audit-logs',
      source: 'Entra ID AuditLogs',
      artifact: 'Any subsequent directory role assignment to the same service principal — application permissions and directory roles are separate privilege paths, and a sophisticated escalation chain often uses one to obtain the other',
    },
  ],

  telemetry: {
    correlationMarkers: [
      'AppRoleAssignment.ReadWrite.All is the single most dangerous Graph application permission to see granted — holding it lets a service principal grant itself, or any other app, any other application permission in the tenant.',
      'Self-granting: check whether the service principal performing the grant is the SAME service principal receiving the new permission — that specific pattern has very few legitimate explanations.',
      'AppId / Service Principal object ID: pivot across AuditLogs (the grant), CloudAppEvents/OfficeActivity (subsequent use), and SigninLogs (the app\'s own authentication activity).',
    ],
  },

  mitre: [
    { id: 'T1098.003', name: 'Account Manipulation: Additional Cloud Roles', tactic: 'Privilege Escalation' },
    { id: 'T1078.004', name: 'Valid Accounts: Cloud Accounts', tactic: 'Privilege Escalation' },
  ],

  atrm: [{ id: 'AZT405.1', name: 'Application API Permissions', tactic: 'Privilege Escalation' }],

  kql: {
    sentinel: {
      triage: {
        title: 'High-privilege application permission grants',
        query: `AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName == "Add app role assignment to service principal"
| extend AppRole = tostring(TargetResources[0].modifiedProperties[0].newValue)
| where AppRole has_any ("AppRoleAssignment.ReadWrite.All", "RoleManagement.ReadWrite.Directory", "Directory.ReadWrite.All")
| project TimeGenerated, InitiatedBy, TargetResources, Result, CorrelationId
| order by TimeGenerated desc`,
      },
      investigate: {
        title: 'Self-granted permissions (highest-risk pattern)',
        description: 'Flags a service principal granting a permission to itself.',
        query: `AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName == "Add app role assignment to service principal"
| extend InitiatorAppId = tostring(InitiatedBy.app.appId)
| extend TargetAppId = tostring(TargetResources[0].id)
| where isnotempty(InitiatorAppId) and InitiatorAppId == TargetAppId
| project TimeGenerated, InitiatorAppId, TargetResources, Result
| order by TimeGenerated desc`,
      },
    },
    defender: {
      triage: {
        title: 'App role assignment activity',
        query: `CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType has "Add app role assignment"
| project Timestamp, AccountDisplayName, ActionType, RawEventData
| order by Timestamp desc`,
      },
    },
  },

  runbook: {
    triage: [
      'Identify exactly which application permission was granted and to which service principal — several are effectively tenant-admin-equivalent.',
      'Determine who or what performed the grant — a human Global Admin doing legitimate app consent looks very different from a service principal granting itself new permissions.',
      'Check what the service principal has done with its new permission scope since the grant.',
      'Establish whether this application is one your organization recognizes and intended to have this level of access.',
    ],
    contain: [
      'Remove the granted app role assignment immediately: `Remove-MgServicePrincipalAppRoleAssignment`.',
      "If the service principal's own credentials appear compromised, rotate or remove its client secret/certificate.",
      'Audit for and remove any further permissions or role assignments the service principal granted using its escalated access.',
      'Review and restrict which identities hold AppRoleAssignment.ReadWrite.All or similar escalation-capable permissions tenant-wide — very few applications genuinely need it.',
    ],
    investigate: [
      'Reconstruct the full chain: how did the initiating identity get the privilege to make this grant? If self-granted, when and how did that service principal first obtain the escalation-capable permission?',
      'Check for downstream damage — what did the now-escalated service principal do with its new permissions before it was caught?',
      'Look for the same pattern across other service principals, in case this is a broader, scripted escalation rather than an isolated event.',
      'Review app registration credential history for the implicated service principal — a suspicious credential addition often precedes this kind of abuse.',
    ],
    recover: [
      'Require Privileged Access Management / PIM-for-Groups-style justification and approval for AppRoleAssignment.ReadWrite.All and equivalent permissions, rather than standing grants.',
      'Deploy Microsoft Defender for Cloud Apps app governance policies to continuously monitor for over-permissioned or newly-escalated applications.',
      'Establish a recurring review specifically of which applications hold high-risk Graph application permissions, independent of any single incident.',
      'Alert on every future "Add app role assignment" event involving a Tier-0-equivalent permission, rather than relying on periodic review alone.',
    ],
  },
}

export default entry
