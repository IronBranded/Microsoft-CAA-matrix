import type { ThreatEntry } from '../../../../types/threat'

const entry: ThreatEntry = {
  id: 'suspicious-credential-addition-oauth-app',
  title: 'Suspicious Credential Addition to OAuth App',
  domain: 'app-workload-identity',
  category: 'Persistence',
  severity: 'high',
  status: 'complete',
  shortDesc: 'Injecting a secondary client secret or certificate into an existing, already-trusted enterprise application to gain a covert, independent path to authenticate as it.',
  description:
    'Rather than registering a brand-new application, an attacker who compromises an account with sufficient rights over an existing app registration can simply add a new client secret or certificate to it. The original application keeps functioning normally, but the attacker now holds an independent, durable credential that lets them authenticate as that app without disturbing anything a defender would notice at a glance.',

  forensicArtifacts: [
    {
      source: 'Entra ID AuditLogs',
      artifact: "Certificates-and-secrets management operations showing a new client secret or certificate added to an existing, already-trusted application",
    },
    {
      source: 'Entra ID AuditLogs',
      artifact: "The acting identity and whether they're expected to manage that specific application's credentials — often requires only Application Administrator or ownership of the specific app, not a directory-wide role",
    },
    {
      source: 'Entra ID App registrations',
      artifact: "The new credential's expiry — an attacker-added secret often has an unusually long expiry compared to the organization's normal rotation practice",
    },
    {
      source: 'Entra ID AADServicePrincipalSignInLogs',
      artifact: 'The first sign-in using the newly-added credential, and from where — attacker infrastructure rather than the application\'s normal deployment environment',
    },
    {
      source: 'CloudAppEvents / OfficeActivity / AzureActivity',
      artifact: "Activity from the application immediately following use of the new credential, especially anything outside the app's established normal behavior pattern",
    },
  ],

  telemetry: {
    correlationMarkers: [
      "The application itself doesn't change — its existing, already-granted permissions carry over to whoever holds any of its valid credentials, old or newly-added. This is what makes credential addition quieter than registering a new app.",
      "Multiple valid credentials can coexist — the original legitimate one keeps working, so the app owner may not notice anything is wrong until the attacker's credential is actually used maliciously.",
      'Compare the credential\'s added-by identity against who normally manages that specific application — Application Administrators and app owners are a much smaller population than the full admin population.',
    ],
  },

  mitre: [{ id: 'T1098.001', name: 'Account Manipulation: Additional Cloud Credentials', tactic: 'Persistence' }],

  atrm: [{ id: 'AZT501.2', name: 'Service Principal Manipulation', tactic: 'Persistence' }],

  kql: {
    sentinel: {
      triage: {
        title: 'Credentials added to existing applications',
        query: `AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName has_any ("Update application", "Add service principal credentials", "Certificates and secrets")
| project TimeGenerated, InitiatedBy, TargetResources, Result, CorrelationId
| order by TimeGenerated desc`,
      },
      investigate: {
        title: 'First sign-in following a credential addition',
        description: 'Catches first use of the newly-added (potentially attacker) credential.',
        query: `let cred_additions = AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName has_any ("Update application", "Add service principal credentials")
| extend AppId = tostring(TargetResources[0].id), AddedTime = TimeGenerated;
AADServicePrincipalSignInLogs
| where TimeGenerated > ago(30d)
| where ResultType == "0"
| join kind=inner cred_additions on $left.ServicePrincipalId == $right.AppId
| where TimeGenerated > AddedTime
| project TimeGenerated, ServicePrincipalName, IPAddress, AddedTime
| order by TimeGenerated asc`,
      },
    },
    defender: {
      triage: {
        title: 'Credential management activity',
        query: `CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType has_any ("Update application", "Add service principal credentials")
| project Timestamp, AccountDisplayName, ActionType, RawEventData
| order by Timestamp desc`,
      },
    },
  },

  runbook: {
    triage: [
      'Identify which application had a credential added and by whom.',
      'Confirm whether that identity normally manages the app.',
      "Check the new credential's configured expiry.",
      'Determine whether the app has multiple active credentials currently, and whether that count is expected.',
    ],
    contain: [
      'Remove the unauthorized credential immediately — the legitimate one continues working, so this doesn\'t disrupt the app.',
      'Revoke any sessions established using the malicious credential.',
      'Review for other unexpected credentials on the same app.',
      'Audit other applications the same actor has access to manage.',
    ],
    investigate: [
      'Determine what the credential was used for before removal.',
      "Check whether the acting identity's own account is compromised, or whether app ownership itself was the actual gap.",
      'Review other applications the same actor has access to manage for the same pattern.',
      'Establish the full timeline from credential addition through first use through detection.',
    ],
    recover: [
      'Implement alerting on every credential addition to high-privilege applications.',
      'Enforce credential expiration limits tenant-wide.',
      "Periodically audit each app's full credential list against expected count and owners.",
      'Prefer certificate-based or federated credentials over client secrets where the application supports it.',
    ],
  },
}

export default entry
