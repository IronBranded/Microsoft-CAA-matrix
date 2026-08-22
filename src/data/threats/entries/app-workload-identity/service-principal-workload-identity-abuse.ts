import type { ThreatEntry } from '../../../../types/threat'

const entry: ThreatEntry = {
  id: 'service-principal-workload-identity-abuse',
  title: 'Service Principal / Workload Identity Abuse',
  domain: 'app-workload-identity',
  category: 'Credential Access',
  severity: 'high',
  status: 'complete',
  shortDesc: 'Exploiting static secrets or long-lived certificates on a high-privilege application to authenticate as it, without touching any human user\'s credentials.',
  description:
    'Applications and their service principals frequently hold direct Azure RBAC roles or Graph API application permissions, sometimes exceeding what any single human admin holds. Where these use client secrets or certificates rather than federated credentials, any exposure — a leaked secret in source control, an insecurely copied certificate — gives an attacker a durable, non-interactive way to authenticate as the application and inherit its full permission set.',

  forensicArtifacts: [
    {
      logSourceId: 'service-principal-signin-logs',
      source: 'Entra ID AADServicePrincipalSignInLogs',
      artifact: "Sign-ins for a service principal from an IP inconsistent with its expected hosting environment — the signature of credential reuse from attacker infrastructure (this table requires its own Diagnostic Setting; it isn't bundled automatically with interactive SigninLogs routing)",
    },
    {
      source: 'Source code repositories / secret scanning tools',
      artifact: 'A client secret or certificate committed to source control, found via secret-scanning tools — the most common real-world leak vector for this technique',
    },
    {
      source: 'Entra ID App registrations',
      artifact:
        "The service principal's actual granted permissions — defines the blast radius regardless of how the credential leaked. Also check the credential's own configured expiry: a client secret or certificate with a multi-year validity window (or one that's been silently rotated to a fresh multi-year window repeatedly) represents a standing risk independent of any specific leak, since it gives a one-time credential exposure a correspondingly long useful life for an attacker.",
    },
    {
      source: 'AzureActivity / CloudAppEvents / OfficeActivity',
      artifact: 'API activity from the service principal immediately following an anomalous sign-in, using its full permission scope',
    },
    {
      source: 'Entra ID App registrations — credential configuration',
      artifact: 'Whether the application uses a client secret, certificate, or federated credential — the credential type itself is a leak-risk signal, since static secrets are inherently more exposure-prone than federation',
    },
  ],

  telemetry: {
    correlationMarkers: [
      'Service principals have far more predictable behavior than human users — a consistent source IP range, consistent timing, consistent API call pattern. Any deviation is proportionally more significant than the same deviation for a human account.',
      'Static secrets are inherently more leak-prone than certificates, and both are more leak-prone than federated credentials, which require no stored secret at all.',
      "AppId / Service Principal object ID: pivot across AADServicePrincipalSignInLogs (auth), CloudAppEvents/OfficeActivity/AzureActivity (usage), and the app registration's own credential history.",
    ],
    relevantErrorCodes: [
      {
        code: 'AADSTS7000215',
        type: 'Invalid Client Secret',
        description: 'The provided client secret is invalid — expired, deleted, or simply wrong.',
        dfirValue:
          "Your primary containment-confirmation signal: after rotating/removing a compromised secret, watch for this code from the identity that was previously authenticating successfully. Its appearance confirms the old credential is dead. It's also a leading indicator on its own — a spike of this code against a service principal that normally authenticates cleanly can mean someone is retrying a credential that was already rotated out, i.e. a leaked-but-stale secret still circulating.",
      },
      {
        code: 'AADSTS700027',
        type: 'Invalid Client Assertion',
        description: 'Client assertion failed signature validation — the certificate-based equivalent of an invalid secret.',
        dfirValue: 'Same containment-confirmation role as AADSTS7000215, for certificate-based service principals rather than secret-based ones.',
      },
    ],
  },

  mitre: [
    { id: 'T1528', name: 'Steal Application Access Token', tactic: 'Credential Access' },
    { id: 'T1550.001', name: 'Use Alternate Authentication Material: Application Access Token', tactic: 'Defense Evasion' },
  ],

  atrm: [
    { id: 'AZT602', name: 'Steal Service Principal Certificate', tactic: 'Credential Access' },
    { id: 'AZT603', name: 'Service Principal Secret Reveal', tactic: 'Credential Access' },
  ],

  kql: {
    sentinel: {
      triage: {
        title: 'Service principal sign-ins from multiple IPs',
        query: `AADServicePrincipalSignInLogs
| where TimeGenerated > ago(7d)
| where ResultType == "0"
| summarize SignInCount = count(), DistinctIPs = dcount(IPAddress), IPList = make_set(IPAddress, 10) by ServicePrincipalId, ServicePrincipalName
| where DistinctIPs > 2  // tune against expected hosting environment diversity
| order by DistinctIPs desc`,
      },
      investigate: {
        title: 'ARM activity for the suspect service principal',
        description: 'Check CloudAppEvents/OfficeActivity separately with similar filtering for Graph/Office-side activity by the same AppId.',
        query: `let suspect_spn = "<ServicePrincipalId from triage step>";
AzureActivity
| where TimeGenerated > ago(7d)
| where Caller == suspect_spn
| project TimeGenerated, OperationNameValue, ResourceGroup, Resource, CallerIpAddress
| order by TimeGenerated desc`,
      },
    },
    defender: {
      triage: {
        title: 'Activity volume/IP diversity for a specific application',
        description: 'Exact fields identifying service-principal-driven events can vary — inspect a sample of rows for your tenant before relying on a specific filter.',
        query: `CloudAppEvents
| where Timestamp > ago(7d)
| where AccountDisplayName == "<service principal display name>"
| summarize EventCount = count(), DistinctIPs = dcount(IPAddress) by bin(Timestamp, 1h)
| where DistinctIPs > 2
| order by Timestamp desc`,
      },
    },
  },

  runbook: {
    triage: [
      'Identify the credential type (secret, certificate, or federated) and how it may have leaked.',
      "Check the service principal's actual granted permissions.",
      'Review sign-in IP consistency against expected hosting environment.',
      'Determine the timeline — when did the anomalous activity start relative to any known leak event?',
    ],
    contain: [
      'Rotate or revoke the compromised credential immediately.',
      "Scope down the service principal's permissions if over-privileged relative to actual need.",
      'Review and remove any credentials added by an unexpected actor.',
      'Block identified attacker infrastructure at the network layer where applicable.',
    ],
    investigate: [
      'Search source control and CI/CD logs for accidental secret exposure.',
      'Reconstruct what the service principal did with the leaked credential.',
      'Check whether the same secret was reused across multiple applications, a common anti-pattern that multiplies blast radius.',
      'Determine how long the credential had been exposed before detection.',
    ],
    recover: [
      'Migrate to Workload Identity Federation where possible to eliminate stored secrets entirely.',
      'Implement secret scanning on source repositories.',
      'Enforce credential expiration and rotation policies tenant-wide.',
      "Monitor service principal sign-in patterns for baseline deviation as a standing detection.",
    ],
  },
}

export default entry
