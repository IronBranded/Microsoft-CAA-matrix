import type { ThreatEntry } from '../../../../types/threat'

const entry: ThreatEntry = {
  id: 'federated-identity-golden-saml',
  title: 'Federated Identity / Golden SAML',
  domain: 'persistence-pivoting',
  category: 'Persistence / Defense Evasion',
  severity: 'critical',
  status: 'complete',
  shortDesc:
    "An attacker who compromises an AD FS token-signing certificate can forge SAML assertions for any federated user, including Global Admins, bypassing MFA and Conditional Access entirely.",
  description:
    "Golden SAML requires prior compromise of the AD FS server, or at minimum the private key material of its token-signing certificate. Once obtained, the attacker can craft arbitrary SAML responses asserting to be any user in the federated domain, with any claims they choose — UPN, group memberships, role claims. Because Entra ID's trust in a federated domain amounts to 'I trust whatever this IdP signs,' a forged-but-validly-signed assertion is indistinguishable from a real one at the relying-party layer. It bypasses Conditional Access controls that depend on real-time signals, since the sign-in itself is fabricated, and MFA, since no interactive challenge ever happens. This is a devastating persistence technique specifically because resetting the victim's password does nothing — the forgery never depended on the password at all.",

  forensicArtifacts: [
    {
      source: 'AD FS Server — Security/Admin event log',
      artifact: "Access to the token-signing certificate's private key store, or unusual `Get-AdfsCertificate` / certificate export activity",
    },
    {
      source: 'Entra ID SigninLogs',
      artifact:
        "AuthenticationProtocol == 'SAML' or 'WsFed' for sign-ins that are implausible given the asserted user's normal behavior — service accounts, or disabled-but-not-deleted federated accounts",
    },
    {
      source: 'ADFSSignInLogs (requires diagnostic logging enabled on the federation server)',
      artifact:
        "A SAML/WsFed sign-in present in Entra ID SigninLogs with NO corresponding entry in ADFSSignInLogs for the same user/time — a forged assertion is minted offline and submitted directly, so the real AD FS server never processes it",
    },
    {
      source: 'Entra ID AuditLogs',
      artifact:
        "Federation configuration changes — new or modified federated domain trust settings, or a change to the token-signing certificate thumbprint Entra ID trusts (`Update-MgDomainFederationConfiguration`)",
    },
    {
      source: 'Entra ID UEBA / IdentityInfo (if enabled)',
      artifact: 'Anomalous sign-in risk flags for a federated user with no corresponding real authentication event at the on-prem IdP',
    },
  ],

  telemetry: {
    authenticationProtocols: ['SAML', 'WsFed'],
    correlationMarkers: [
      'The single most reliable signal: a SAML/WsFed sign-in Entra ID accepted, with no corresponding entry in the AD FS server\'s own sign-in log for the same user/time window. A forged assertion never touches the real federation server.',
      "SAML assertion NotBefore/NotOnOrAfter window length: forgeries built with generic toolkits sometimes use unusually long or oddly round validity windows compared to your AD FS server's actual configured token lifetime.",
      "Token-signing certificate thumbprint: confirm the thumbprint Entra ID currently trusts (`Get-MgDomainFederationConfiguration`) matches what's actually configured on the AD FS server.",
    ],
  },

  mitre: [
    { id: 'T1606.002', name: 'Forge Web Credentials: SAML Tokens', tactic: 'Credential Access' },
    { id: 'T1078.004', name: 'Valid Accounts: Cloud Accounts', tactic: 'Persistence' },
  ],

  kql: {
    sentinel: {
      triage: {
        title: 'SAML/WsFed sign-ins missing a matching AD FS server event',
        description:
          'Requires ADFSSignInLogs diagnostic logging to be enabled — an empty result is not evidence of a clean environment until you confirm ingestion is actually on. Column names for ADFSSignInLogs are illustrative; confirm exact fields against the current Azure Monitor reference before deploying as a scheduled rule.',
        query: `// A SAML/WsFed sign-in Entra ID accepted, with no corresponding entry in the
// real AD FS server's own sign-in log for the same user/time window, is
// strong evidence of an offline-forged assertion.
let entra_saml_signins = SigninLogs
| where TimeGenerated > ago(7d)
| where AuthenticationProtocol in ("SAML", "WsFed")
| where ResultType == "0"
| extend TimeWindow = bin(TimeGenerated, 5m);
let adfs_signins = ADFSSignInLogs
| where TimeGenerated > ago(7d)
| extend TimeWindow = bin(TimeGenerated, 5m);
entra_saml_signins
| join kind=leftanti adfs_signins on TimeWindow, $left.UserPrincipalName == $right.UserId
| project TimeGenerated, UserPrincipalName, IPAddress, CorrelationId
| order by TimeGenerated desc`,
      },
      investigate: {
        title: 'Federation trust / certificate configuration changes',
        query: `AuditLogs
| where TimeGenerated > ago(30d)
| where Category == "Directory Management"
| where OperationName has_any ("Set federation settings on domain", "Set domain authentication")
| project TimeGenerated, InitiatedBy, OperationName, TargetResources, Result
| order by TimeGenerated desc`,
      },
    },
    defender: {
      hunt: {
        title: 'AD FS server certificate / private key access',
        description:
          "Defender for Identity's on-prem tables can surface AD FS server access, but availability depends on the servers being onboarded as sensors. Treat this as a starting point to adapt to your own schema, not a verified-as-is detection.",
        query: `IdentityDirectoryEvents
| where Timestamp > ago(7d)
| where ActionType has_any ("Certificate", "Private key")
| where DeviceName has "adfs" // adjust to your AD FS server naming convention
| project Timestamp, DeviceName, ActionType, AccountName, AdditionalFields
| order by Timestamp desc`,
      },
    },
  },

  runbook: {
    triage: [
      'Confirm ADFSSignInLogs ingestion is actually enabled before trusting an "all clear" from the correlation query — a silent logging gap looks identical to a clean environment.',
      'Treat any SAML/WsFed sign-in lacking a corresponding AD FS server-side event as a suspected forgery until proven otherwise — this is an assume-breach scenario.',
      'Identify every user asserted via the suspect assertion(s), with special urgency for any privileged/admin accounts.',
      'Check AD FS server security/admin logs for any access to the token-signing certificate\'s private key material in the preceding weeks.',
    ],
    contain: [
      "This cannot be contained by resetting the affected user's password — Golden SAML doesn't depend on it. Roll the token-signing certificate: `Update-AdfsCertificate -CertificateType Token-Signing -Urgent`, then push the new thumbprint to Entra ID via `Update-MgDomainFederationConfiguration`.",
      'Immediately after rotation, revoke sessions for every user in the federated domain — assertions signed by the old key remain cryptographically valid until rotation.',
      'Consider temporarily converting the highest-value accounts to cloud-managed (non-federated) authentication with a fresh strong password and phishing-resistant MFA.',
      'Isolate and forensically image the AD FS server(s) — a certificate compromise implies attacker code execution on the federation server itself, a separate serious incident.',
    ],
    investigate: [
      'Determine how the AD FS server was initially compromised — this is almost always the real patient zero; Golden SAML itself is a late-stage capability, not an entry point.',
      'Review everything every forged-assertion sign-in did post-authentication, via AuditLogs, AzureActivity, OfficeActivity, and CloudAppEvents.',
      'Check whether the attacker used forged assertions to grant additional persistence — new app registrations, federated domains, Global Admin role assignments, or backdoor accounts.',
      'Assume all assertions signed since the earliest plausible compromise date are suspect, not just the ones you first detected.',
    ],
    recover: [
      'Rebuild or thoroughly re-image the AD FS server(s) from known-good media rather than cleaning in place, given the severity of a signing-key compromise.',
      "After certificate rotation and remediation, audit and re-baseline every federated domain's trust configuration.",
      "Strongly evaluate migrating away from AD FS federation toward Entra ID's native Password Hash Sync or Passthrough Authentication with cloud Conditional Access and phishing-resistant MFA, removing this entire class of on-prem-signing-key risk.",
      "If migration isn't immediately feasible, harden AD FS: restrict token-signing certificate private key access, enable extranet lockout and diagnostic logging, and monitor certificate store access as a high-priority alert.",
    ],
  },
}

export default entry
