import type { ThreatEntry } from '../../../../types/threat'

const entry: ThreatEntry = {
  id: 'hybrid-identity-aadconnect-attack',
  title: 'Hybrid Identity Attack / AADConnect',
  domain: 'identity-authentication',
  category: 'Credential Access / Persistence',
  severity: 'critical',
  status: 'complete',
  shortDesc:
    "Exploiting Entra Connect's Password Hash Sync, Pass-through Authentication, or direct server access to compromise both on-prem AD and the connected cloud tenant.",
  description:
    "The Entra Connect (formerly Azure AD Connect) server is a uniquely high-value target: it holds credentials capable of writing to both on-prem Active Directory and Entra ID. Compromising the server itself, or abusing its sync agents, can let an attacker pivot between on-prem and cloud identity planes, extract the highly-privileged AD DS Connector account, or manipulate synchronization rules to grant themselves cloud privileges from an on-prem foothold.",

  forensicArtifacts: [
    {
      source: 'Entra admin center / PTA agent registration',
      artifact:
        'An unfamiliar or unexpectedly-added Pass-through Authentication agent registered against the tenant, visible under Microsoft Entra Connect — legitimate additions are rare after initial setup',
    },
    {
      source: 'AzureADConnectAuthenticationAgentService.exe (PTA agent host)',
      artifact:
        "An unsigned or non-Microsoft-signed DLL loaded into the PTA agent process — the documented mechanism (publicly demonstrated against the process's LogonUserW/ValidateCredential handling) for hooking credential validation to force authentication success or capture cleartext credentials in transit",
    },
    {
      source: 'Entra Connect server — SQL/config store',
      artifact:
        "Access to or extraction of the encrypted AD DS Connector account credential from the Entra Connect server's local SQL/LocalDB instance — the credential a fully compromised Connect server can decrypt and use directly against on-prem AD",
    },
    {
      logSourceId: 'entra-audit-logs',
      source: 'Entra ID AuditLogs',
      artifact: 'A new PTA agent registration, or Global Administrator activity immediately preceding one — registering a rogue agent from attacker-controlled infrastructure requires a compromised Global Admin session',
    },
    {
      logSourceId: 'sign-in-logs',
      source: 'Entra ID SigninLogs',
      artifact:
        'Successful PTA sign-ins under implausible conditions — an account whose on-prem password is known to have just been changed still authenticating successfully is the signature of a hooked validator returning true unconditionally',
    },
  ],

  telemetry: {
    correlationMarkers: [
      "A PTA agent's bootstrap doesn't rotate its source IP when reused, and certificate-based agent impersonation isn't reliably visible from IP alone — don't treat 'the IP looks normal' as clearance; corroborate with the registered-agent list and host-level DLL integrity instead.",
      'The AD DS Connector account authenticating from somewhere other than the actual Entra Connect server is a strong signal of extracted-and-reused connector credentials.',
      "Correlate any successful PTA sign-in against known on-prem AD password/account state — a successful cloud sign-in for an account whose password shouldn't currently work is the clearest sign of a hooked always-true validator.",
    ],
    relevantErrorCodes: [
      {
        code: 'AADSTS80001',
        type: 'Pass-through Authentication',
        description: 'No Microsoft Entra Connect Authentication Agent was found, or none currently reachable, to service the request.',
        dfirValue:
          "A burst of these right before or after suspected tampering is worth investigating — legitimate agents going offline exactly when a rogue agent appears, or when the legitimate host is being tampered with, is a timing pattern worth correlating against the agent registration list.",
      },
    ],
  },

  mitre: [
    { id: 'T1556.007', name: 'Modify Authentication Process: Hybrid Identity', tactic: 'Persistence' },
    { id: 'T1078.004', name: 'Valid Accounts: Cloud Accounts', tactic: 'Credential Access' },
  ],

  kql: {
    sentinel: {
      triage: {
        title: 'New PTA agent / connector registrations',
        description:
          "Exact OperationName strings for PTA-specific events can vary — if this returns nothing, inspect a sample of ApplicationManagement/Device category events with a plain `| take 20` first and adjust the filter to match what you observe.",
        query: `AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName has_any ("passthrough", "PTA", "connector", "Add registered agent")
| project TimeGenerated, InitiatedBy, OperationName, TargetResources, Result
| order by TimeGenerated desc`,
      },
    },
    defender: {
      hunt: {
        title: 'DLL loads into the PTA agent process',
        description:
          'Requires Defender for Endpoint on the PTA agent host itself. Surfaces every DLL loaded into the agent process for review; cross-reference FileName/SHA256 against DeviceFileCertificateInfo (joining on the file hash) to narrow down to unsigned or non-Microsoft-signed images specifically — exact signature columns and join keys vary by schema version, so validate before automating this as a standing rule.',
        query: `DeviceImageLoadEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName =~ "AzureADConnectAuthenticationAgentService.exe"
| project Timestamp, DeviceName, FileName, FolderPath, SHA256
| order by Timestamp desc`,
      },
    },
  },

  runbook: {
    triage: [
      'Check the Entra Connect admin center (or the PTA agent management APIs) for the full list of registered agents and confirm every one is a known, expected on-prem server.',
      "If a suspicious agent is found, identify when it was registered and which admin's session did it — that account is now a primary suspect.",
      'On the legitimate PTA agent host(s), inventory DLLs loaded into AzureADConnectAuthenticationAgentService.exe and check signatures against a known-good baseline.',
      'Check whether the Entra Connect / PTA agent server itself shows separate signs of compromise — this technique requires local admin access to install a DLL hook.',
    ],
    contain: [
      'Deregister and delete any rogue or unrecognized PTA agent immediately.',
      'If a local DLL hook is confirmed on a legitimate agent host, take that host offline and treat it as fully compromised — reinstall the PTA agent from a clean source only after the host itself is remediated.',
      "Rotate the AD DS Connector account's on-prem AD password, since a compromised Connect server may have extracted it.",
      "Require re-registration of the affected device(s) rather than trusting continued device state.",
    ],
    investigate: [
      'Determine how far back the rogue agent or DLL hook has been in place — every authentication that could have transited it should be treated as potentially observed or manipulated.',
      'Check for accounts that authenticated successfully via PTA under implausible conditions, as evidence of a hooked always-true validator.',
      'Review what the AD DS Connector account is capable of in on-prem AD (typically significant directory replication/read rights) and whether it was used for anything beyond normal sync.',
      'Determine the initial access that gave the attacker admin rights on the Connect/PTA server, or the compromised Global Admin account used to register a rogue agent — this is a late-stage capability, not an entry point.',
    ],
    recover: [
      'Rebuild the Connect/PTA agent server from clean media if local compromise is confirmed, rather than just removing the malicious DLL.',
      'Consider migrating from Pass-through Authentication to Password Hash Sync where operationally acceptable — PHS removes the on-prem, real-time credential-validation dependency entirely, closing this specific attack surface.',
      'Harden PTA agent server access: restrict local admin rights to a small, monitored group, and deploy EDR/image-load monitoring on it specifically.',
      'Review and restrict who holds Global Administrator, since rogue agent registration is a direct consequence of that privilege being compromised.',
    ],
  },
}

export default entry
