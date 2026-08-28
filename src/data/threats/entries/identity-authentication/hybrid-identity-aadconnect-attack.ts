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

  authFlow: {
    pattern: 'sequence',
    narrative:
      "The distinctive part of this flow isn't a set of AADSTS codes — it's that a hooked PTA agent breaks the normal semantics of what a success code means. Every PTA-mediated sign-in normally requires genuine on-prem AD validation; once a validator is hooked, cloud-side SigninLogs shows exactly the same success code for a genuine validation and a forced one, with the difference only visible by correlating against ground truth on the AD side.",
    steps: [
      {
        code: 'agent-compromise',
        label: 'Attacker gains local admin on a PTA agent host, or registers a rogue agent using a compromised Global Admin session',
        detail: "No cloud-side telemetry for the local-admin path — that's an on-prem endpoint compromise. The rogue-agent-registration path does show in AuditLogs, and is the more detectable of the two routes into this technique.",
      },
      {
        code: 'dll-hook-installed',
        label: "AzureADConnectAuthenticationAgentService.exe's credential-validation handling is hooked",
        detail: 'Local to the compromised host — DeviceImageLoadEvents (see the Defender query above) is the only visibility, and only where EDR coverage exists on that specific server.',
      },
      {
        code: '0',
        label: 'Subsequent PTA sign-ins validate successfully regardless of the actual on-prem password',
        detail: 'Structurally identical to a genuine PTA success — same AADSTS 0, same claims shape. The only way to tell these apart from legitimate successes is correlating against known on-prem password/account state, which is exactly what the forensicArtifacts and correlationMarkers above are built around.',
      },
    ],
    distinguishingNotes:
      "The rogue-agent-registration path and the local-DLL-hook path converge on the same outcome (fraudulent validation) but leave very different evidence — one lives in AuditLogs and is comparatively easy to spot, the other lives entirely on a specific on-prem host and requires EDR coverage there specifically to see at all. Establish which path applies early, since it determines whether you're pulling cloud logs or doing host forensics next.",
  },

  tokenTimeline: {
    issuance:
      'Issued at the moment of the (potentially fraudulent) PTA validation success — structurally identical whether the validation was genuine or forced by a hook. Nothing at the token level distinguishes the two; the distinguishing evidence lives entirely outside the token, in agent registration state and on-prem password ground truth.',
    expiration:
      "Standard token lifetimes for whatever's issued at successful PTA validation. This technique doesn't itself extend token life or open a PRT/device-registration path the way some other Domain 1 entries do — its value to an attacker is repeatable fraudulent authentication, not a single high-value token.",
    authInstant: "auth_time pins to the (possibly fraudulent) PTA validation moment, indistinguishable from a genuine one at the claim level. Optional claim, as elsewhere.",
    authMethods:
      "amr for a PTA sign-in reflects password as the primary factor, same as it would for a genuine one — a hooked validator doesn't change what the token claims about how authentication happened, only whether the underlying validation was actually performed correctly.",
    mfaInstant:
      "Orthogonal to this technique specifically — PTA governs password/first-factor validation; whatever MFA policy applies afterward is unaffected by whether the PTA validation itself was hooked. If the account also requires MFA, that challenge still has to be cleared separately and would time normally.",
    otherContext:
      "This is a case where token/session evidence is close to useless on its own — the compromise lives in the trust relationship between the cloud service and the on-prem validator, not in anything the resulting token carries. Ground-truth correlation against on-prem AD state (was this password actually valid at this moment?) is doing more investigative work here than anywhere else in Domain 1.",
  },

  runbook: {
    triage: [
      'Check the Entra Connect admin center (or the PTA agent management APIs) for the full list of registered agents and confirm every one is a known, expected on-prem server.',
      "If a suspicious agent is found, identify when it was registered and which admin's session did it — that account is now a primary suspect.",
      'On the legitimate PTA agent host(s), inventory DLLs loaded into AzureADConnectAuthenticationAgentService.exe and check signatures against a known-good baseline.',
      'Check whether the Entra Connect / PTA agent server itself shows separate signs of compromise — this technique requires local admin access to install a DLL hook.',
    ],
    contain: [
      'Deregister and delete any rogue or unrecognized PTA agent from the Entra admin center — there is no clean Graph PowerShell cmdlet to remove a single specific agent from the cloud side; this is a portal action, or uninstalling the agent software directly on the host it runs on.',
      "If you need an immediate, blunt stop rather than surgical removal of one agent, `Disable-PassthroughAuthentication` (run locally on a legitimate agent host, via the PassthroughAuthPSModule bundled with the agent install) turns off PTA tenant-wide. This is a real, documented cmdlet, but it's an emergency lever, not a scalpel — confirm Password Hash Sync is already enabled as a fallback before using it, or you risk locking out sign-in entirely rather than just cutting off the rogue agent.",
      'If a local DLL hook is confirmed on a legitimate agent host, take that host offline and treat it as fully compromised — reinstall the PTA agent from a clean source only after the host itself is remediated.',
      "Rotate the AD DS Connector account's on-prem AD password, since a compromised Connect server may have extracted it.",
      'Require re-registration of the affected device(s) rather than trusting continued device state.',
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
