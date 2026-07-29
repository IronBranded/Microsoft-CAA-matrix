import type { ThreatEntry } from '../../../../types/threat'

const entry: ThreatEntry = {
  id: 'prt-abuse',
  title: 'Primary Refresh Token (PRT) Abuse',
  domain: 'identity-authentication',
  category: 'Credential Access',
  severity: 'critical',
  status: 'complete',
  shortDesc:
    "Direct memory or TPM dumping of a device's Primary Refresh Token to bypass MFA entirely on an unmanaged or compromised endpoint.",
  description:
    "The Primary Refresh Token is a device-bound credential that lets a Windows endpoint silently renew access and ID tokens for its signed-in user without repeated prompts. An attacker with SYSTEM-level access to a compromised device can extract the PRT and its session key directly from LSASS memory, then replay it from attacker infrastructure to mint fresh tokens as the user, without triggering an interactive MFA challenge.",

  forensicArtifacts: [
    {
      source: 'Entra ID SigninLogs',
      artifact:
        'Token-broker-issued sign-ins from an IP/device inconsistent with the device the PRT actually claims to be bound to — a PRT extracted and replayed from a different machine than the one it was issued on',
    },
    {
      source: 'Windows Security / Sysmon Event Log (device hosting the PRT)',
      artifact:
        'LSASS access from an unexpected process (Sysmon Event ID 10 / ProcessAccess targeting lsass.exe), especially combined with SeDebugPrivilege usage — the mechanism tools like sekurlsa::cloudap or ROADtoken use to extract the PRT and session key',
    },
    {
      source: 'Entra ID device object',
      artifact:
        "The device object the PRT claims to be bound to — check `dsregcmd /status` on the purported device, or its TPM attestation state, for consistency with how and where the token is actually being used. Where TPM-bound key storage is properly enforced, the session key itself can't be extracted even with LSASS access — a successful extraction despite this control being nominally enabled is itself worth investigating as a possible TPM/attestation bypass or misconfiguration, not just the token theft.",
    },
    {
      source: 'Entra ID NonInteractiveUserSignInLogs',
      artifact: "A burst of token refresh activity from a device object with no recent normal interactive activity, or from an IP geographically inconsistent with that device's usual pattern",
    },
    {
      source: 'Entra ID AuditLogs',
      artifact: "Device object anomalies — TPM-bound status or compliance state changing unexpectedly around the time of suspected abuse",
    },
  ],

  telemetry: {
    correlationMarkers: [
      'DeviceId inside a decoded PRT/access token should match a real, known-good device object — a mismatch is the core signal, though it usually requires token capture (EDR, proxy logs) to observe directly.',
      'PRTs are meant to be non-exportable when TPM-backed — successful extraction is far more likely from an unmanaged or non-TPM device than from a properly Windows Hello for Business-protected one.',
      "The session key protecting the PRT is often extractable alongside it — tooling that dumps one usually dumps both, since the PRT alone can't be used to request new tokens without it.",
    ],
  },

  mitre: [
    { id: 'T1003.001', name: 'OS Credential Dumping: LSASS Memory', tactic: 'Credential Access' },
    { id: 'T1528', name: 'Steal Application Access Token', tactic: 'Credential Access' },
  ],

  kql: {
    sentinel: {
      triage: {
        title: 'Non-interactive token activity with no matching interactive device',
        description:
          "A heuristic, not a definitive detection — legitimate background refresh without a recent interactive sign-in (e.g. 'stay signed in' sessions) can also produce this pattern, so treat hits as leads to investigate rather than confirmed compromise.",
        query: `let interactive_devices = SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType == "0"
| extend DeviceId = tostring(DeviceDetail.deviceId)
| where isnotempty(DeviceId)
| distinct DeviceId;
AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(7d)
| where ResultType == "0"
| extend DeviceId = tostring(DeviceDetail.deviceId)
| where isnotempty(DeviceId) and DeviceId !in (interactive_devices)
| project TimeGenerated, UserPrincipalName, IPAddress, DeviceId, CorrelationId
| order by TimeGenerated desc`,
      },
    },
    defender: {
      hunt: {
        title: 'Known PRT-dumping tool invocation',
        description:
          "Command-line detection of known tooling. Defender's own built-in 'suspicious LSASS access' alerts are a complementary signal worth checking alongside this — this query covers the tool-invocation angle specifically, not raw LSASS access itself.",
        query: `DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has_any ("sekurlsa::cloudap", "ROADtoken", "RequestAADRefreshToken", "AADInternals")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc`,
      },
    },
  },

  runbook: {
    triage: [
      'Identify which device the abused PRT claims to be bound to, and verify whether that matches where it is actually being used from.',
      "Check the source device for LSASS access by unexpected tooling — Sysmon Event ID 10, or Defender's own suspicious LSASS access alerts.",
      'Determine whether the device was TPM-backed and Windows Hello for Business-protected, which makes extraction both harder and more suspicious if it still happened.',
      "Establish scope — a stolen PRT for a Global Admin's device is a very different severity than for a low-privilege user's.",
    ],
    contain: [
      'Revoke sessions and tokens (`Revoke-MgUserSignInSession`) — this invalidates the PRT and forces re-authentication.',
      'Isolate the source device if still reachable, and treat it as compromised pending investigation.',
      "If hardware-backed device protections weren't in place, treat that itself as a finding.",
      'Consider requiring re-registration of the device (remove and re-join to Entra ID) rather than trusting its continued state.',
    ],
    investigate: [
      'Determine how the attacker got the access needed to dump LSASS in the first place — PRT theft is a late-stage capability on an already-compromised endpoint, not an entry point.',
      'Review what the replayed PRT/derived tokens were used for before revocation.',
      'Check whether the session key, not just the PRT, was also captured.',
      'Assess whether other devices built the same way (same imaging, same missing protections) are similarly exposed.',
    ],
    recover: [
      'Ensure devices for privileged users specifically are TPM-backed and Windows Hello for Business-enrolled.',
      'Deploy Credential Guard where supported, which isolates LSASS secrets — including PRT-related material — from even a SYSTEM-level process.',
      'Stand up the LSASS-access and command-line detections above as ongoing rules, not one-off hunts.',
      'Review Conditional Access Token Protection as a complementary control, since it reduces the value of a PRT stolen from one device and replayed on another.',
    ],
  },
}

export default entry
