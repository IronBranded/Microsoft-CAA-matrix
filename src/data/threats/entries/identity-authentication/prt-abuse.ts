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
      logSourceId: 'sign-in-logs',
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
      logSourceId: 'sign-in-logs',
      source: 'Entra ID NonInteractiveUserSignInLogs',
      artifact: "A burst of token refresh activity from a device object with no recent normal interactive activity, or from an IP geographically inconsistent with that device's usual pattern",
    },
    {
      logSourceId: 'entra-audit-logs',
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
    relevantErrorCodes: [
      {
        code: 'AADSTS50173',
        type: 'Revoked Grant',
        description:
          "The provided grant has expired due to it being revoked — a fresh auth is needed. Fires when a token's issue time predates the account's TokensValidFrom timestamp, which containment actions like a password reset advance.",
        dfirValue:
          "This is your containment-confirmation signal, the same role AADSTS70020 plays for stolen access tokens elsewhere in this matrix: after resetting the compromised user's password, watch for this code from the attacker's infrastructure attempting to keep using the extracted PRT. Its appearance confirms the token is now dead; its absence after containment means either the attacker has stopped trying or is using something a password reset doesn't invalidate.",
      },
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

  authFlow: {
    pattern: 'sequence',
    narrative:
      "The honest answer is that there isn't much of an interactive sequence to document. The theft itself — LSASS memory access — is a local OS event with no Entra ID telemetry at all, and the replay that follows is designed specifically to look like ordinary silent token renewal, not a distinguishable flow of its own. What's below is less a sequence of diagnostic codes and more a record of what doesn't happen (no interactive challenge, no MFA prompt) compared to a legitimate parallel case.",
    steps: [
      {
        code: 'lsass-access',
        label: 'PRT and session key extracted from LSASS memory on the source device',
        detail: "No Entra ID telemetry — entirely local to the compromised endpoint. Sysmon Event ID 10 or Defender's suspicious LSASS access alerting is the only visibility into this step, and only where EDR coverage exists on that specific device.",
      },
      {
        code: '0',
        label: 'Non-interactive token refresh using the replayed PRT',
        detail: 'Structurally identical to a legitimate silent SSO refresh — same ResultType, no MFA challenge because none is required for PRT-backed refresh by design. This is the one event that actually reaches Entra ID logging, and on its own it is not distinguishable from normal background token renewal.',
      },
    ],
    distinguishingNotes:
      "Resist the urge to look for a code that means \"this was PRT theft\" — there isn't one. The refresh event is deliberately unremarkable; the tell is everything around it (DeviceId consistency, IP/geography against the claimed device's pattern, whether the source device shows LSASS access at all), not anything in the AADSTS vocabulary itself. If you're expecting this entry to read like device-code-phishing's tight code sequence, that's the wrong mental model for this technique.",
  },

  tokenTimeline: {
    issuance:
      "The replayed PRT/derived tokens are issued whenever the attacker's infrastructure chooses to use them — potentially long after the actual LSASS extraction, since a stolen PRT remains usable until revoked or independently invalidated. There's no reliable way to pin \"issuance\" to a single moment from Entra ID telemetry alone; the extraction and the replay are separate events with no session linking them in the logs.",
    expiration:
      "PRTs are long-lived by design (rolling validity with continuous silent renewal) specifically so a device never has to re-prompt the user — exactly what makes a stolen one so durable. Effective persistence lasts until the account's TokensValidFrom is advanced (password reset, explicit revocation) or the PRT is independently invalidated some other way.",
    authInstant:
      "auth_time on tokens derived from a replayed PRT reflects whenever the device last did a real interactive sign-in — potentially weeks earlier, with zero relationship to when the theft or replay actually happened. Don't treat this claim as telling you anything about the incident timeline for this specific technique.",
    authMethods:
      "amr reflects the original interactive sign-in's methods, not anything about the replay. A PRT stolen from a device where the user completed real MFA carries amr values that make the resulting tokens look fully legitimate — close to the worst case for relying on amr as a signal anywhere in this matrix.",
    mfaInstant:
      "There isn't a fresh MFA instant to find for the replay itself — that's the entire point of a PRT. SigninLogs.AuthenticationDetails for the non-interactive refresh event typically shows no MFA step at all, which is expected, normal behavior here, not itself suspicious. Don't misread its absence as a red flag on its own.",
    otherContext:
      "Token-level evidence is genuinely limited by design for this technique, and the investigation has to lean on the device/endpoint side (Sysmon, EDR, TPM/attestation state) more than the identity side. If you only have Entra ID logs and nothing from the endpoint, be upfront with stakeholders that PRT abuse may be difficult to fully confirm or rule out from that vantage point alone.",
  },

  runbook: {
    triage: [
      'Identify which device the abused PRT claims to be bound to, and verify whether that matches where it is actually being used from.',
      "Check the source device for LSASS access by unexpected tooling — Sysmon Event ID 10, or Defender's own suspicious LSASS access alerts.",
      'Determine whether the device was TPM-backed and Windows Hello for Business-protected, which makes extraction both harder and more suspicious if it still happened.',
      "Establish scope — a stolen PRT for a Global Admin's device is a very different severity than for a low-privilege user's.",
    ],
    contain: [
      "Revoke sessions and tokens: `Revoke-MgUserSignInSession -UserId <UPN>` — this invalidates the PRT's refresh capability and forces re-authentication.",
      "Reset the account's password as well, alongside revocation rather than instead of it: `Update-MgUser -UserId <UPN> -PasswordProfile @{ Password = '<new password>'; ForceChangePasswordNextSignIn = $true }`. This is what advances TokensValidFrom — the timestamp behind the AADSTS50173 signal above.",
      'Isolate the source device if still reachable, and treat it as compromised pending investigation.',
      "If hardware-backed device protections weren't in place, treat that itself as a finding.",
      "Don't just re-trust the device once you're done with it — remove the object and require re-registration from a clean state: `Remove-MgDevice -DeviceId <deviceObjectId>` (verify the parameter name against your installed Microsoft.Graph module version; it has shifted across SDK releases).",
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
