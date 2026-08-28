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
      logSourceId: 'entra-audit-logs',
      source: 'Entra ID AuditLogs',
      artifact: "OperationName == 'Add device' — new device object registration, worth reviewing against expected enrollment sources rather than direct join from an unexpected context",
    },
    {
      source: 'Entra ID Devices',
      artifact: "Device compliance state — a device registered but never actually managed, yet still satisfying a 'require compliant device' check, points to either a Conditional Access gap or a spoofed compliance signal",
    },
    {
      logSourceId: 'entra-audit-logs',
      source: 'Entra ID AuditLogs',
      artifact: 'The registering user/session — device registration is typically self-service, so this technique is usually a second step after some other compromise',
    },
    {
      source: 'Entra ID Devices — device settings',
      artifact:
        "The tenant's configured 'Maximum number of devices per user' setting (default is a moderate cap, but tenants sometimes raise or unlimit it for legitimate reasons) — a user suddenly approaching or exceeding what would normally be a reasonable personal device count is a quota-based signal independent of any single registration event looking suspicious on its own.",
    },
    {
      logSourceId: 'sign-in-logs',
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
    relevantErrorCodes: [
      {
        code: 'AADSTS53000',
        type: 'Device Compliance Requirement',
        description: "DeviceNotCompliant — Conditional Access requires a compliant device, and this one isn't.",
        dfirValue:
          "A registered device object failing this specifically because it was never actually enrolled with Intune (or another approved MDM) is the tell that reveals a 'ghost' registration for what it is — real managed devices satisfy this cleanly. A burst of these from one identity, immediately after a new device registration, is worth investigating even though each individual failure looks routine.",
      },
      {
        code: 'AADSTS53001',
        type: 'Domain-Join Requirement',
        description: "DeviceNotDomainJoined — Conditional Access requires a domain-joined device, and this one isn't.",
        dfirValue: 'Same tell as AADSTS53000 above, for tenants whose Conditional Access policy checks hybrid/domain-join specifically rather than Intune compliance.',
      },
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

  authFlow: {
    pattern: 'sequence',
    narrative:
      "Same structural pattern as fido2-passkey-registration-hijacking and suspicious-credential-addition-oauth-app elsewhere in this matrix — a registration event that only becomes a real persistence mechanism after some other compromise already granted the registering session in the first place.",
    steps: [
      {
        code: 'session-established',
        label: 'Attacker obtains any authenticated session on the target account',
        detail: "Not this entry's mechanism — see whichever compromise scenario elsewhere in this matrix actually applies. Device registration is typically self-service, so this step is what makes it possible at all.",
      },
      {
        code: 'device-registered',
        label: 'A new, unmanaged device object is registered against the account',
        detail: "AuditLogs 'Add device' event. The device exists as an object from this moment, but isn't yet proven to satisfy anything — that depends on how the relevant Conditional Access policy actually evaluates trust.",
      },
      {
        code: '53000',
        label: '(Where compliance is genuinely required and correctly checked) the device fails the compliance check',
        detail: 'What should happen for a never-enrolled device — its absence for subsequent sign-ins from this device is the actual finding, meaning the policy is checking join-type alone rather than real compliance.',
      },
      {
        code: '0',
        label: 'Subsequent sign-in succeeds with the ghost device satisfying device-based Conditional Access',
        detail: 'The point the registration converts from a standing object into active bypass. Confirms the policy gap is actually being exploited, not just theoretically present.',
      },
    ],
    distinguishingNotes:
      "The device registration event and its later use can be separated by any amount of time — don't assume they're close together the way a phishing-to-token flow would be. Trace both ends: backward to how the registering session was obtained, and forward to confirm the device is actually being used to satisfy policy, not just sitting registered and unused.",
  },

  tokenTimeline: {
    issuance:
      "Tokens issued from sign-ins using the ghost device are otherwise ordinary — the device's DeviceId simply appears in DeviceDetail, and Conditional Access evaluates it like any other registered device would be evaluated.",
    expiration:
      "The device object itself doesn't expire the way a token does — it persists as a standing object until explicitly removed, which is exactly what makes this durable persistence rather than a one-time bypass.",
    authInstant:
      "auth_time reflects whatever authentication actually happened at sign-in — unremarkable on its own. The device-trust bypass is a separate, additive factor evaluated alongside the user's authentication, not something that changes this claim.",
    authMethods: "amr reflects the user's actual authentication methods, same as any sign-in — this scenario is about device trust specifically, not about weakening the user-authentication side at all.",
    mfaInstant:
      'Unaffected by this scenario — if the account also requires MFA independent of device compliance, that still has to be cleared separately. Ghost device registration defeats device-based checks specifically, not MFA.',
    otherContext:
      "The interesting object to track over time isn't a token — it's the device object's DeviceId, and everywhere it subsequently appears in SigninLogs.DeviceDetail. A single device can be reused across many sessions over an extended period, so pulling the full history for that DeviceId, not just the registration event, is necessary to scope the actual impact.",
  },

  runbook: {
    triage: [
      'Identify the registering session and trace it back to how that access was obtained.',
      "Check the device's actual compliance/management state versus what Conditional Access is treating it as.",
      'Review which Conditional Access policies the device is being used to satisfy.',
      'Determine the account this device is registered to and its privilege level.',
    ],
    contain: [
      'Remove or disable the rogue device object: `Remove-MgDevice -DeviceId <deviceObjectId>` (verify the parameter name against your installed Microsoft.Graph module version, as noted elsewhere in this matrix).',
      'Revoke sessions tied to the account: `Revoke-MgUserSignInSession -UserId <UPN>`.',
      "Tighten the Conditional Access policy if it's evaluating join-type alone rather than genuine compliance.",
      'Suspend the registering account if it appears compromised: `Update-MgUser -UserId <UPN> -AccountEnabled:$false`.',
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
