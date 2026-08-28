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
      logSourceId: 'entra-audit-logs',
      source: 'Entra ID AuditLogs',
      artifact: 'Federated identity credential creation or modification on an app registration',
    },
    {
      logSourceId: 'service-principal-signin-logs',
      source: 'Entra ID AADServicePrincipalSignInLogs',
      artifact: "A sign-in via federated credential from an external OIDC issuer, where the actual originating workflow/subject doesn't match the intended, narrowly-scoped trust",
    },
    {
      source: 'External CI/CD platform logs (GitHub Actions, GitLab CI, etc.)',
      artifact: 'The actual workflow run that requested and received an Entra ID token via OIDC federation — cross-reference against what the subject pattern was supposed to restrict to',
    },
    {
      logSourceId: 'entra-audit-logs',
      source: 'Entra ID AuditLogs',
      artifact: "A recent broadening of a federated credential's subject/issuer/audience matching — narrowing from a specific repo+branch pattern to an org-wide wildcard is the direct enabler",
    },
  ],

  telemetry: {
    correlationMarkers: [
      "The federated credential's subject identifier is the entire security boundary here — review its exact pattern rather than assuming federation itself is inherently safe.",
      "No client secret is ever generated or leaked in this technique — the 'credential' is the trust relationship configuration itself, which is why this is a configuration-review problem more than a secret-hunting one.",
      "Cross-reference Entra ID sign-in activity via the federated credential against the external platform's own logs — a token issued for a workflow run the external platform has no record of is the clearest sign of exploitation.",
      'There is deliberately no relevantErrorCodes entry for this scenario: a federated credential configured too broadly means an out-of-scope workflow run successfully exchanges its token for a valid Entra ID token — a fully successful, intended-to-work token issuance from Entra ID\'s perspective. The misconfiguration is what makes it exploitable, not any error in the flow itself.',
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

  authFlow: {
    pattern: 'sequence',
    narrative:
      "As this entry's own correlationMarkers already note, there's no distinguishing error code here — a misconfigured federated credential means an out-of-scope workflow successfully exchanges its token, exactly as the flow is designed to work. The only way to see the problem is comparing what the trust was supposed to allow against what actually triggered it, on the external platform's own side.",
    steps: [
      {
        code: 'external-token-issued',
        label: 'External OIDC provider (GitHub Actions, GitLab CI, etc.) issues its own token for the workflow run',
        detail: "Outside Entra ID entirely — this exists only in the external platform's own logs, which is why cross-referencing them against Entra ID's side is the core investigative move for this scenario.",
      },
      {
        code: '0',
        label: 'Entra ID exchanges the external token for its own token, because the presented subject/issuer/audience matches the configured (and too-broad) trust pattern',
        detail: "A fully successful, correctly-functioning token exchange from Entra ID's perspective — the platform has no way to know the subject match was broader than intended.",
      },
    ],
    distinguishingNotes:
      "This is genuinely the cleanest 'absence is the signal' case in the whole matrix, because there isn't even a leaked secret to hunt for — the vulnerability is entirely in a configuration field's specificity. If you're looking for a moment something went wrong, there isn't one; the exchange worked exactly as configured, and the configuration is the finding.",
  },

  tokenTimeline: {
    issuance:
      "Issued immediately on successful token exchange — no delay, no secret to present, no interactive step. The entire security boundary is upstream of issuance, in whether the presented external token's subject/issuer/audience matched the configured pattern.",
    expiration:
      "Standard app-only access token lifetimes for whatever's exchanged. As with service-principal-workload-identity-abuse, the durable asset isn't any single token — it's the ongoing ability to trigger the trust relationship again, which persists until the federated credential's subject pattern is actually tightened.",
    authInstant: 'Not meaningful in the interactive sense — this is a machine-to-machine exchange with no user or device-bound authentication moment at all.',
    authMethods: 'amr is not populated for this token type — there\'s no authentication method claim to speak of in a federated app-only exchange.',
    mfaInstant: 'Not applicable — nothing about this flow involves or could involve MFA.',
    otherContext:
      "Unlike service-principal-workload-identity-abuse, there's no credential to rotate here at all — that's the whole appeal of federation, and also what makes remediation different. Fixing this means editing the trust configuration itself (the subject pattern), not revoking a secret or certificate.",
  },

  runbook: {
    triage: [
      'Pull the exact configured subject/issuer/audience pattern for the federated credential.',
      "Cross-reference recent sign-ins against the external platform's own run/workflow history.",
      'Identify whether the pattern is scoped narrowly (specific repo and branch) or broadly (org-wide wildcard).',
      'Determine what the token was actually used for once obtained.',
    ],
    contain: [
      "Narrow the federated credential's subject pattern immediately to the minimum necessary scope: `Update-MgApplicationFederatedIdentityCredential -ApplicationId <id> -FederatedIdentityCredentialId <id> -BodyParameter @{ subject = '<narrowed subject pattern>' }`.",
      'Remove the federated credential entirely if the application no longer needs it: `Remove-MgApplicationFederatedIdentityCredential -ApplicationId <id> -FederatedIdentityCredentialId <id>`.',
      "There's no session to revoke the way there is for user or service-principal-secret compromises — app-only tokens from this exchange simply expire on their own standard lifetime once the trust pattern is fixed, since no new tokens can be minted against the corrected scope. Treat closing the configuration gap as the actual containment action, not a follow-up to one.",
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
