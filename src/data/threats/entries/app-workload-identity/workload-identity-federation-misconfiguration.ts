import type { ThreatEntry } from '../../../../types/threat'

const entry: ThreatEntry = {
  id: 'workload-identity-federation-misconfiguration',
  title: 'Workload Identity Federation (WIF) Misconfiguration',
  domain: 'app-workload-identity',
  category: 'Initial Access / Credential Access',
  severity: 'high',
  status: 'complete',
  shortDesc: 'Exploiting a misconfigured external OIDC trust relationship — GitHub Actions, AWS, or another external identity provider — to issue rogue Entra ID tokens without ever needing a secret.',
  description:
    'Workload Identity Federation lets an external OIDC-compliant identity provider exchange its own token for an Entra ID token, entirely secretless. If the federated credential\'s subject/issuer/audience matching is configured too broadly — trusting any workflow in a GitHub org rather than one specific repository and branch, for example — an attacker who can get a workflow to run in that broader scope can mint valid Entra ID tokens for the trusting application without ever needing a client secret.',

  forensicArtifacts: [
    {
      source: 'Entra ID App registrations — Federated credentials',
      artifact:
        "The configured subject identifier pattern — overly broad patterns (trusting any branch/workflow in an org rather than one specific repo and branch) are the root cause of this technique's exploitability. A common concrete mistake: a subject pattern scoped to an entire organization or repository (e.g., anything matching repo:org/* or a pull_request-triggered workflow, which runs with the PR branch's own code) rather than a specific branch/environment/ref — a pull-request-scoped trust in particular means anyone who can open a PR, not just anyone who can merge to main, can mint a token.",
    },
    {
      source: 'Entra ID AuditLogs',
      artifact: 'Federated identity credential creation or modification on an app registration',
    },
    {
      source: 'Entra ID AADServicePrincipalSignInLogs',
      artifact: "A sign-in via federated credential from an external OIDC issuer, where the actual originating workflow/subject doesn't match the intended, narrowly-scoped trust",
    },
    {
      source: 'External CI/CD platform logs (GitHub Actions, GitLab CI, etc.)',
      artifact: 'The actual workflow run that requested and received an Entra ID token via OIDC federation — cross-reference against what the subject pattern was supposed to restrict to',
    },
    {
      source: 'Entra ID AuditLogs',
      artifact: "A recent broadening of a federated credential's subject/issuer/audience matching — narrowing from a specific repo+branch pattern to an org-wide wildcard is the direct enabler",
    },
  ],

  telemetry: {
    correlationMarkers: [
      "The federated credential's subject identifier is the entire security boundary here — review its exact pattern rather than assuming federation itself is inherently safe.",
      "No client secret is ever generated or leaked in this technique — the 'credential' is the trust relationship configuration itself, which is why this is a configuration-review problem more than a secret-hunting one.",
      "Cross-reference Entra ID sign-in activity via the federated credential against the external platform's own logs — a token issued for a workflow run the external platform has no record of is the clearest sign of exploitation.",
    ],
  },

  mitre: [{ id: 'T1078.004', name: 'Valid Accounts: Cloud Accounts', tactic: 'Initial Access' }],

  kql: {
    sentinel: {
      triage: {
        title: 'Sign-ins via workload identity federation',
        description:
          'Exact field/value marking a sign-in as federated-credential-based can vary — inspect a sample of rows for a known WIF-configured app first (`| take 5`) to confirm which column surfaces it in your tenant.',
        query: `AADServicePrincipalSignInLogs
| where TimeGenerated > ago(14d)
| where ResultType == "0"
| project TimeGenerated, ServicePrincipalName, IPAddress, ResourceDisplayName, AuthenticationProcessingDetails, CorrelationId
| order by TimeGenerated desc`,
      },
      investigate: {
        title: 'Federated credential configuration changes',
        query: `AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName has_any ("federated identity credential", "Add federated", "Update federated")
| project TimeGenerated, InitiatedBy, TargetResources, Result
| order by TimeGenerated desc`,
      },
    },
    defender: {
      triage: {
        title: 'Federated credential activity',
        query: `CloudAppEvents
| where Timestamp > ago(14d)
| where ActionType has "federated"
| project Timestamp, AccountDisplayName, ActionType, RawEventData
| order by Timestamp desc`,
      },
    },
  },

  runbook: {
    triage: [
      'Pull the exact configured subject/issuer/audience pattern for the federated credential.',
      "Cross-reference recent sign-ins against the external platform's own run/workflow history.",
      'Identify whether the pattern is scoped narrowly (specific repo and branch) or broadly (org-wide wildcard).',
      'Determine what the token was actually used for once obtained.',
    ],
    contain: [
      "Narrow the federated credential's subject pattern immediately to the minimum necessary scope.",
      'Remove the federated credential entirely if the application no longer needs it.',
      'Revoke any tokens/sessions obtained via the overly-broad trust.',
      'Review the external platform account/workflow that triggered the issue for its own compromise.',
    ],
    investigate: [
      'Determine what the token was used for once obtained.',
      'Check whether other applications in the tenant have similarly broad federated credential configurations.',
      'Review the external platform for how the triggering workflow or identity was itself obtained or created.',
      'Establish whether the broad pattern was a deliberate change or a default that was never tightened.',
    ],
    recover: [
      'Adopt narrowly-scoped subject patterns as a standing policy for all federated credentials — specific repo, specific branch or environment, never a bare wildcard.',
      "Periodically audit every federated credential's configured pattern against this standard.",
      'Prefer federation over client secrets for CI/CD generally, while ensuring the trust boundary itself stays tight.',
      'Alert on federated credential configuration changes that broaden scope, specifically.',
    ],
  },
}

export default entry
