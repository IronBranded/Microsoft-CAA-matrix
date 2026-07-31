import type { ThreatEntry } from '../../../../types/threat'

const entry: ThreatEntry = {
  id: 'rogue-shadow-app-registration',
  title: 'Rogue / Shadow Application Registration',
  domain: 'app-workload-identity',
  category: 'Defense Evasion',
  severity: 'medium',
  status: 'complete',
  shortDesc: 'Unmonitored, non-catalog application registrations created for ad hoc testing or unauthorized integrations, outside formal app governance.',
  description:
    'In tenants where application registration isn\'t tightly restricted, developers routinely spin up temporary app registrations for testing that are never cleaned up and never enter formal inventory or governance review. These shadow apps accumulate real permissions and credentials over time, and because they were never flagged as sanctioned, they\'re rarely revisited when permissions should be tightened or credentials rotated.',

  forensicArtifacts: [
    {
      source: 'Entra ID App registrations inventory',
      artifact: 'The full population of app registrations compared against a maintained, approved inventory — shadow apps are definitionally the ones not on that list',
    },
    {
      source: 'Entra ID AuditLogs',
      artifact: 'App registration creation events attributed to individual developer/power-user accounts rather than a managed CI/CD or platform-team identity',
    },
    {
      source: "Entra ID User settings — 'Users can register applications'",
      artifact:
        "Whether this tenant-wide setting is enabled for all users or restricted to specific roles — if it's open to everyone, every account in the tenant is a potential source of shadow registrations, which reframes remediation from 'find the bad apps' to 'close the governance gap that let them all happen'.",
    },
    {
      source: 'Entra ID App registrations',
      artifact: 'Apps with no recent sign-in activity that still hold active credentials and permissions — dormant but not disabled, an easy target if rediscovered by an attacker',
    },
    {
      source: 'Entra ID App registrations',
      artifact: "Apps whose owner has left the organization or changed roles, with no ownership transfer — an orphaned app with nobody actively responsible for it",
    },
    {
      source: 'App registration credential expiry data',
      artifact: 'Apps with very long-dated or non-expiring credentials, common in ad hoc developer-created apps never brought under standard credential-rotation policy',
    },
  ],

  telemetry: {
    correlationMarkers: [
      'This is fundamentally an inventory/governance gap rather than a single detectable event — the finding is the state of unmanaged apps existing, more than any specific action.',
      'Dormant apps with live credentials and real permissions are a latent risk — they don\'t need to be actively abused to matter; their mere existence expands what a future attacker could target.',
      'Cross-reference app ownership against current HR/directory status — an app owned by a departed employee with nobody having taken over responsibility is a common, specific finding worth searching for directly.',
    ],
  },

  kql: {
    sentinel: {
      triage: {
        title: 'Dormant service principals',
        description: "A proxy for dormancy based on sign-in absence — combine with a separate inventory/ownership review for full context.",
        query: `AADServicePrincipalSignInLogs
| where TimeGenerated > ago(90d)
| summarize LastSeen = max(TimeGenerated) by ServicePrincipalId, ServicePrincipalName
| where LastSeen < ago(60d)
| order by LastSeen asc`,
      },
      investigate: {
        title: 'App registration creation history',
        query: `AuditLogs
| where TimeGenerated > ago(180d)
| where OperationName == "Add application"
| project TimeGenerated, InitiatedBy, TargetResources
| order by TimeGenerated desc`,
      },
    },
    defender: {
      triage: {
        title: 'App registration activity',
        query: `CloudAppEvents
| where Timestamp > ago(90d)
| where ActionType == "Add application"
| project Timestamp, AccountDisplayName, ActionType, RawEventData
| order by Timestamp desc`,
      },
    },
  },

  runbook: {
    triage: [
      'Compile the full current app registration inventory and compare against any maintained approved list.',
      'Identify apps with no recent activity but active credentials/permissions.',
      'Identify apps whose owner has left or changed roles.',
    ],
    contain: [
      'Disable credentials on dormant apps pending review.',
      'Reassign ownership for orphaned apps, or disable them if no longer needed.',
    ],
    investigate: [
      'For any app found with unexpectedly broad permissions, treat it with the same scrutiny as Malicious App Registration elsewhere in this matrix.',
      'Determine whether any shadow app was actually exploited or remains only a latent risk.',
    ],
    recover: [
      'Establish a formal app registration approval and inventory process.',
      'Implement periodic review of all registrations against expected ownership and activity.',
      'Require ownership transfer as part of the offboarding process.',
      'Apply credential expiration policy retroactively to existing apps.',
    ],
  },
}

export default entry
