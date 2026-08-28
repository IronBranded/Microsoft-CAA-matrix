import type { ThreatEntry } from '../../../../types/threat'

const entry: ThreatEntry = {
  id: 'imds-managed-identity-token-theft',
  title: 'IMDS & Managed Identity Token Theft',
  domain: 'azure-infrastructure-compute',
  category: 'Credential Access',
  severity: 'critical',
  status: 'complete',
  shortDesc:
    "An attacker with code execution on an Azure VM queries the Instance Metadata Service to mint a JWT for the VM's Managed Identity, inheriting its Azure RBAC roles with no credentials required.",
  description:
    "Every Azure VM can reach the Instance Metadata Service at the link-local, non-routable address 169.254.169.254 — including its Managed Identity token endpoint. An attacker with any code execution on the VM (webshell, RCE in a hosted app, or an SSRF vulnerability that can reach the metadata endpoint) can request a token for whatever resource they like and use it directly against Azure Resource Manager or Microsoft Graph with the VM's inherited permissions. This entirely bypasses the VM's own OS credentials, and if the managed identity is over-privileged — Owner or Contributor at the subscription level is a common finding — the blast radius extends far beyond the single VM that was actually compromised.",

  forensicArtifacts: [
    {
      logSourceId: 'azure-activity-log',
      source: 'AzureActivity',
      artifact:
        "ARM API calls authenticated via the VM's Managed Identity object ID, from IPs outside the expected Azure datacenter range, or against resources unrelated to the VM's normal function — the Activity Log itself is always generated at the platform level, but reaching this table in a Sentinel workspace requires a Diagnostic Setting explicitly routing it there; confirm that routing exists before treating an empty query result as a clean finding",
    },
    {
      logSourceId: 'managed-identity-signin-logs',
      source: 'AADManagedIdentitySignInLogs',
      artifact: "Sign-in events for the managed identity's Service Principal ID correlating in time with suspicious VM process activity",
    },
    {
      logSourceId: 'defender-endpoint-hunting',
      source: 'DeviceProcessEvents (VM guest OS)',
      artifact:
        "Outbound HTTP requests to 169.254.169.254 from unexpected processes (curl, PowerShell Invoke-RestMethod, python, or a web app worker process) carrying the 'Metadata: true' header",
    },
    {
      logSourceId: 'defender-endpoint-hunting',
      source: 'DeviceNetworkEvents (VM guest OS)',
      artifact:
        'Connections to 169.254.169.254:80 from a process context tied to a web application rather than the expected system agents (WindowsAzureGuestAgent, WALinuxAgent)',
    },
    {
      source: 'Application logs (SSRF-vulnerable app)',
      artifact: 'A crafted request where a user-supplied URL parameter was redirected to the metadata endpoint — the classic SSRF-to-IMDS chain',
    },
  ],

  telemetry: {
    correlationMarkers: [
      "ServicePrincipalId / managed identity object ID: pivot AADManagedIdentitySignInLogs against AzureActivity's Caller/Identity fields on this value.",
      "Resource ID of the source VM: confirms which specific compute resource's identity was used, especially important if a user-assigned identity is shared across multiple resources.",
      "IMDS requests always have 169.254.169.254 as the DESTINATION, not source — filter DeviceNetworkEvents on RemoteIP == '169.254.169.254' to find the requesting process on the VM itself.",
    ],
    relevantErrorCodes: [
      {
        code: '400 Bad Request',
        type: 'IMDS Response',
        description:
          '"Required metadata header not specified" — IMDS rejects any request missing the Metadata: true header.',
        dfirValue:
          "Only useful if you can capture the SSRF-vulnerable application's own request/error logs — IMDS calls themselves generate no Azure platform-level log regardless of outcome. Also not a control to lean on: the header requirement isn't enforced consistently across every IMDS endpoint, and is bypassable if the attacker controls request headers, e.g. via a CRLF injection in the vulnerable app. Treat a header check as a speed bump, not proof a request came from legitimate in-VM code.",
      },
      {
        code: 'AADSTS53003',
        type: 'Conditional Access — Workload Identity',
        description: '"Access has been blocked by Conditional Access policies" for a service principal / managed identity sign-in.',
        dfirValue:
          'Only fires if Conditional Access for Workload Identities (requires Workload ID Premium) is actually configured and scoped to this managed identity — most tenants have nothing here, so its absence proves nothing either way. Where it IS configured, it is a strong signal: a stolen token replayed from outside the policy\'s allowed locations or networks will trip it, visible in AADManagedIdentitySignInLogs — and is worth deploying as a containment measure going forward if this scenario is a live concern.',
      },
    ],
  },

  mitre: [
    { id: 'T1552.005', name: 'Unsecured Credentials: Cloud Instance Metadata API', tactic: 'Credential Access' },
    { id: 'T1078.004', name: 'Valid Accounts: Cloud Accounts', tactic: 'Privilege Escalation' },
  ],

  kql: {
    sentinel: {
      triage: {
        title: 'Managed identity sign-ins from multiple IPs',
        description: 'Managed identity sign-ins are logged separately from regular service principal sign-ins.',
        query: `// A managed identity should typically sign in from a small, stable set of
// IPs tied to its host resource — multiple distinct IPs is anomalous.
AADManagedIdentitySignInLogs
| where TimeGenerated > ago(7d)
| where ResultType == "0"
| summarize SignInCount = count(), DistinctIPs = dcount(IPAddress), IPList = make_set(IPAddress, 10) by ServicePrincipalId, ServicePrincipalName
| where DistinctIPs > 1
| order by DistinctIPs desc`,
      },
      investigate: {
        title: "Suspect identity's Azure Resource Manager activity",
        description: 'Flags a managed identity being used well outside its host VM\'s normal footprint.',
        query: `// Filter AzureActivity directly on the caller identity — more reliable than
// joining on CorrelationId, which isn't guaranteed to line up cleanly
// between AADManagedIdentitySignInLogs and AzureActivity for every operation.
let suspect_spn = "<ServicePrincipalId from triage step>";
AzureActivity
| where TimeGenerated > ago(7d)
| where Caller == suspect_spn or Identity has suspect_spn
| project TimeGenerated, OperationNameValue, ResourceGroup, ResourceId, ActivityStatusValue, CallerIpAddress
| order by TimeGenerated desc`,
      },
    },
    defender: {
      triage: {
        title: 'Managed identity sign-ins from multiple IPs',
        description:
          'EntraIdSpnSignInEvents replaces the deprecated AADSpnSignInEventsBeta (old queries auto-migrate 2026-10-19) and covers both service principal and managed identity sign-ins in Advanced Hunting. The table rename is confirmed against current Microsoft Learn documentation; the SPN-specific columns below (ServicePrincipalId, ServicePrincipalName, IsManagedIdentity) carried over unchanged on the sign-in-events side of this same rename, but weren\'t independently re-checked column-by-column — verify against your tenant\'s live schema before relying on this in production.',
        query: `EntraIdSpnSignInEvents
| where Timestamp > ago(7d)
| where IsManagedIdentity == true
| summarize SignInCount = count(), DistinctIPs = dcount(IPAddress) by ServicePrincipalId, ServicePrincipalName
| where DistinctIPs > 1
| order by DistinctIPs desc`,
      },
      hunt: {
        title: 'IMDS request on the VM guest OS',
        description: 'Requires Defender for Endpoint on the guest OS (or Arc-onboarded for on-prem/hybrid).',
        query: `DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteIP == "169.254.169.254"
| where InitiatingProcessFileName !in~ ("WindowsAzureGuestAgent.exe", "WaAppAgent.exe", "waagent")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc`,
      },
    },
  },

  authFlow: {
    pattern: 'sequence',
    narrative:
      "The token-minting step itself happens entirely between the VM and IMDS — a link-local call that never touches Entra ID's sign-in surface at all, which is what makes this different from every Domain 1 phishing/credential scenario. The only Entra-ID-visible event is the managed identity's own sign-in once IMDS has already handed the attacker a valid token.",
    steps: [
      {
        code: 'imds-request',
        label: 'Attacker code on the VM requests a token from 169.254.169.254 with the Metadata: true header',
        detail: 'No Azure platform-level log captures this regardless of outcome — only guest-OS-level EDR (DeviceNetworkEvents/DeviceProcessEvents) sees it, and only where Defender for Endpoint is deployed on that specific VM.',
      },
      {
        code: '0',
        label: "IMDS mints the token, and the managed identity's sign-in appears in AADManagedIdentitySignInLogs",
        detail: 'The first event this entire chain produces in Entra ID telemetry — everything before this step is invisible from the identity side.',
      },
    ],
    distinguishingNotes:
      "Don't expect this to look like a Domain 1 credential-theft flow with a rich AADSTS code sequence — the interesting part of this technique happens entirely outside Entra ID, on the compromised VM itself, before any identity-side telemetry exists at all. If your only visibility is Entra ID logs and you don't have EDR on the VM's guest OS, you'll see the sign-in but never the actual IMDS query that produced it.",
  },

  tokenTimeline: {
    issuance:
      'Issued directly by IMDS on request, with no interactive or delegated flow of any kind — a managed identity token is minted the moment the local metadata call succeeds, using the header check as the only gate (and a weak one — see relevantErrorCodes).',
    expiration:
      'Managed identity tokens follow standard access token lifetimes. Because reissuing one requires only another IMDS call from the same compromised VM, expiration provides little real containment on its own if the underlying code-execution access on the VM remains open — the attacker simply requests a fresh token.',
    authInstant:
      "Not really applicable in the JWT auth_time sense this matrix uses elsewhere — managed identity tokens are non-interactive by construction, so there's no interactive authentication moment to pin. The AADManagedIdentitySignInLogs event timestamp is the closest equivalent anchor.",
    authMethods: "amr is not a meaningful field for managed identity tokens the way it is for user tokens — there's no user authentication method involved at all. Don't go looking for it here.",
    mfaInstant: "Not applicable — managed identities cannot complete MFA, and nothing in this flow involves it. If you're used to Domain 1 entries where this field always has something to say, this is the exception.",
    otherContext:
      "The real containment lever for this scenario isn't token-level at all — it's identity-level (disable the managed identity, or strip its role assignments) and VM-level (remediate the code-execution access). A stolen managed identity token, once issued, behaves exactly like a legitimate one for its full lifetime; there's no revocation-by-session mechanism analogous to Revoke-MgUserSignInSession for this identity type.",
  },

  runbook: {
    triage: [
      'Identify which VM/compute resource owns the managed identity (system-assigned ties 1:1 to a resource; user-assigned may be shared — check assignment scope).',
      "Enumerate the Azure RBAC role assignments actually held by the identity — this defines the real blast radius, which is very often broader than the VM's owners realize.",
      "Check DeviceNetworkEvents/DeviceProcessEvents on the VM's guest OS for the actual IMDS request and which local process made it.",
      'Determine the initial access vector that gave the attacker code execution on the VM — this scenario is almost always a second stage, not the initial compromise.',
    ],
    contain: [
      'Remove or scope down the managed identity\'s role assignments immediately: `Remove-AzRoleAssignment -ObjectId <managed identity object id> -RoleDefinitionName "<role>" -Scope "<scope>"` (Az.Resources module) — this cuts off what a stolen token can do even before the VM compromise is fully remediated.',
      "If the identity is system-assigned, disable it on the VM to immediately invalidate all outstanding tokens. Az.Compute has a cmdlet for removing a VM's system-assigned identity — verify the exact current name against your installed Az module version before scripting this specific step, since that corner of Az.Compute has shifted across versions more than Az.Resources has. The portal path (VM > Identity > System assigned > Off) is a reliable fallback either way.",
      "Isolate the VM at the network layer (NSG deny-all, or Defender for Endpoint's device isolation) to stop further IMDS abuse while investigating.",
      'Rotate any secrets or downstream credentials the identity had access to (e.g. Key Vault secrets), since a minted token may already have retrieved them.',
    ],
    investigate: [
      "Pull the full AzureActivity history for the identity's object ID across ALL subscriptions it can reach, not just the one hosting the VM.",
      "Check for resources touched that are unrelated to the VM's normal function — Key Vault reads, storage access, new role assignments granted to other principals.",
      'Review whether the identity was used to pull additional credentials that could extend the compromise beyond Azure.',
      "Confirm the original code-execution vector on the VM is fully remediated — token theft will recur if the underlying access is left open.",
    ],
    recover: [
      'Re-provision the managed identity with least-privilege role assignments scoped to what the application actually needs, instead of Contributor/Owner.',
      'Use Azure Policy or a custom detection to alert on managed identities being assigned high-privilege roles going forward.',
      'Enforce IMDS hardening where supported to mitigate basic SSRF-to-IMDS chains.',
      'Stand up the DeviceNetworkEvents-based query above as a permanent detection — IMDS access from an unexpected process is high-fidelity with very few legitimate exceptions.',
    ],
  },
}

export default entry
