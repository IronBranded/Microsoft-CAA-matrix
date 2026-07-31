import type { ThreatEntry } from '../../../../types/threat'

const entry: ThreatEntry = {
  id: 'ghost-device-registration',
  title: 'Ghost Device Registration',
  domain: 'persistence-pivoting',
  category: 'Persistence / Defense Evasion',
  severity: 'high',
  status: 'complete',
  shortDesc: 'Injecting a rogue, non-compliant, or unmanaged device object into Entra ID specifically to satisfy device-based Conditional Access requirements.',
  description:
    'Where Conditional Access policies require a compliant or hybrid-joined device, an attacker who can register a device object under a compromised identity creates a durable bypass for that control. Once registered, the ghost device can be reused across sessions, giving the attacker a standing way to satisfy device-trust requirements without ever controlling a real, managed endpoint.',

  forensicArtifacts: [
    {
      source: 'Entra ID AuditLogs',
      artifact: "OperationName == 'Add device' — new device object registration, worth reviewing against expected enrollment sources rather than direct join from an unexpected context",
    },
    {
      source: 'Entra ID Devices',
      artifact: "Device compliance state — a device registered but never actually managed, yet still satisfying a 'require compliant device' check, points to either a Conditional Access gap or a spoofed compliance signal",
    },
    {
      source: 'Entra ID AuditLogs',
      artifact: 'The registering user/session — device registration is typically self-service, so this technique is usually a second step after some other compromise',
    },
    {
      source: 'Entra ID Devices — device settings',
      artifact:
        "The tenant's configured 'Maximum number of devices per user' setting (default is a moderate cap, but tenants sometimes raise or unlimit it for legitimate reasons) — a user suddenly approaching or exceeding what would normally be a reasonable personal device count is a quota-based signal independent of any single registration event looking suspicious on its own.",
    },
    {
      source: 'Entra ID SigninLogs',
      artifact: 'Subsequent sign-ins where the Conditional Access decision references the newly-registered device — confirms the device is actively being used to satisfy device-trust policy',
    },
    {
      source: 'Intune / MDM enrollment records',
      artifact: 'Absence of a corresponding MDM enrollment for a device that Conditional Access is treating as compliant — a device object existing without genuine management is the core anomaly',
    },
  ],

  telemetry: {
    correlationMarkers: [
      "Device join type (Entra joined, Entra registered, hybrid joined) has different trust implications — know which type your policies actually check, since 'hybrid or compliant' is defeated differently than 'compliant' specifically.",
      "A device object's DeviceId is the durable pivot to trace everywhere that device was subsequently used to satisfy Conditional Access.",
      'This technique is almost always a second stage — trace the registering session backward to how that access was originally obtained.',
    ],
  },

  mitre: [{ id: 'T1098.005', name: 'Account Manipulation: Device Registration', tactic: 'Persistence' }],

  kql: {
    sentinel: {
      triage: {
        title: 'New device registrations',
        query: `AuditLogs
| where TimeGenerated > ago(14d)
| where OperationName == "Add device"
| project TimeGenerated, InitiatedBy, TargetResources, Result, CorrelationId
| order by TimeGenerated desc`,
      },
      investigate: {
        title: 'Sign-ins referencing a recently-registered device',
        query: `let new_devices = AuditLogs
| where TimeGenerated > ago(14d)
| where OperationName == "Add device"
| extend DeviceId = tostring(TargetResources[0].id);
SigninLogs
| where TimeGenerated > ago(14d)
| extend SignInDeviceId = tostring(DeviceDetail.deviceId)
| where SignInDeviceId in (new_devices)
| project TimeGenerated, UserPrincipalName, IPAddress, SignInDeviceId, DeviceDetail
| order by TimeGenerated desc`,
      },
    },
    defender: {
      triage: {
        title: 'Device registration activity',
        query: `CloudAppEvents
| where Timestamp > ago(14d)
| where ActionType == "Add device"
| project Timestamp, AccountDisplayName, ActionType, RawEventData
| order by Timestamp desc`,
      },
    },
  },

  runbook: {
    triage: [
      'Identify the registering session and trace it back to how that access was obtained.',
      "Check the device's actual compliance/management state versus what Conditional Access is treating it as.",
      'Review which Conditional Access policies the device is being used to satisfy.',
      'Determine the account this device is registered to and its privilege level.',
    ],
    contain: [
      'Remove or disable the rogue device object.',
      'Revoke sessions tied to it.',
      "Tighten the Conditional Access policy if it's evaluating join-type alone rather than genuine compliance.",
      'Suspend the registering account if it appears compromised.',
    ],
    investigate: [
      'Determine what the device was used to access after registration.',
      'Check for a pattern of multiple rogue device registrations from the same actor.',
      'Review device registration settings tenant-wide for overly permissive self-service policy.',
      'Establish how the registering session itself was originally compromised.',
    ],
    recover: [
      'Require genuine compliance, not just join type, in device-based Conditional Access policies where feasible.',
      'Restrict device registration/join settings to expected scenarios.',
      'Monitor new device registrations as a standing detection, especially for privileged accounts.',
      'Periodically audit registered devices against actual managed-device inventory.',
    ],
  },
}

export default entry
