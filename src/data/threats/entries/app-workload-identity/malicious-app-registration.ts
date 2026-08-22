import type { ThreatEntry } from '../../../../types/threat'

const entry: ThreatEntry = {
  id: 'malicious-app-registration',
  title: 'Malicious App Registration',
  domain: 'app-workload-identity',
  category: 'Persistence',
  severity: 'high',
  status: 'complete',
  shortDesc: 'Registering a new multi-tenant application specifically to establish persistent access or a command-and-control channel that survives normal account remediation.',
  description:
    'An attacker with sufficient privilege, or exploiting a tenant setting that allows any user to register applications, can create a new app registration configured for their own long-term use: multi-tenant so it can be consented to from anywhere, with broad requested permissions and its own credentials under attacker control. Because it\'s a new object rather than a modification to something already monitored, it can be easy to miss.',

  forensicArtifacts: [
    {
      logSourceId: 'entra-audit-logs',
      source: 'Entra ID AuditLogs',
      artifact: "OperationName == 'Add application' — a new app registration created, worth reviewing especially where registration isn't restricted to approved admins",
    },
    {
      source: 'Entra ID App registrations',
      artifact: 'Multi-tenant configuration — multi-tenant apps can be consented to from any tenant, useful for an attacker wanting persistent, portable access',
    },
    {
      logSourceId: 'entra-audit-logs',
      source: 'Entra ID AuditLogs',
      artifact: 'Credentials added to the new app registration immediately after creation — establishing how the attacker intends to authenticate as it going forward',
    },
    {
      logSourceId: 'entra-audit-logs',
      source: 'Entra ID AuditLogs',
      artifact: 'Requested API permissions/scopes on the new registration — broad Graph permissions on a brand-new, unfamiliar app are a strong signal',
    },
    {
      source: 'Entra ID App registrations',
      artifact:
        "Redirect URI(s) configured on the registration — a URI pointing to a non-Microsoft domain, a URL shortener, or infrastructure with no connection to any legitimate business purpose is a direct, checkable artifact independent of the app's stated name or permissions.",
    },
    {
      source: 'Entra ID SigninLogs / AADServicePrincipalSignInLogs',
      artifact: "The new app's first sign-in activity and from where — attacker-controlled infrastructure rather than a legitimate deployment environment",
    },
  ],

  telemetry: {
    correlationMarkers: [
      'A new app registration created by an account not normally associated with app development/registration is itself worth flagging, independent of what the app requests.',
      'Time from creation to first use: a legitimate app typically has some gap for testing; an attacker-created app is often used almost immediately.',
      'AppId is the durable pivot across every subsequent event this app generates — capture it early in the investigation.',
    ],
    relevantErrorCodes: [
      {
        code: 'AADSTS65001',
        type: 'Consent Required',
        description: "DelegationDoesNotExist — the user or administrator hasn't consented to use the application. A newly-registered malicious app needs exactly this consent to actually activate.",
        dfirValue:
          "A cluster of AADSTS65001 for a brand-new AppId, followed by a successful sign-in, brackets the exact moment the app went from registered-but-inert to actually granted access — often the more important timestamp than the registration event itself for scoping what the app could subsequently touch.",
      },
      {
        code: 'AADSTS90094',
        type: 'Admin Consent Required',
        description: 'AdminConsentRequired — the app requested permissions high-privilege enough that admin consent, not user consent, is required.',
        dfirValue:
          "If this fires instead of a clean consent, the attacker's app requested permissions the tenant's consent policy classified as needing admin approval — meaningful scoping information even if the attempt was blocked, since it reveals intended scope regardless of outcome.",
      },
    ],
  },

  mitre: [{ id: 'T1136.003', name: 'Create Account: Cloud Account', tactic: 'Persistence' }],

  atrm: [{ id: 'AZT502.2', name: 'Service Principal Creation', tactic: 'Persistence' }],

  kql: {
    sentinel: {
      triage: {
        title: 'New app registrations',
        query: `AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName == "Add application"
| project TimeGenerated, InitiatedBy, TargetResources, Result, CorrelationId
| order by TimeGenerated desc`,
      },
      investigate: {
        title: 'Credentials added following registration',
        query: `AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName has_any ("Add application", "Add service principal credentials")
| project TimeGenerated, InitiatedBy, OperationName, TargetResources
| order by TimeGenerated desc`,
      },
    },
    defender: {
      triage: {
        title: 'App registration activity',
        query: `CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType == "Add application"
| project Timestamp, AccountDisplayName, ActionType, RawEventData
| order by Timestamp desc`,
      },
    },
  },

  runbook: {
    triage: [
      'Identify who registered the app and whether that is expected/approved.',
      'Review requested permissions and multi-tenant configuration.',
      "Check credentials added and the app's first real usage.",
      'Determine whether the registering account shows other signs of compromise.',
    ],
    contain: [
      "Disable or delete the app's service principal.",
      'Revoke any tokens/sessions associated with it.',
      'Restrict app registration to approved administrators if not already scoped.',
      'Suspend the registering account if it appears compromised.',
    ],
    investigate: [
      'Determine what the app was used for before removal.',
      'Check whether other similar registrations exist from the same actor.',
      'Review the registering account for broader compromise indicators.',
      'Assess whether the tenant setting allowing broad app registration should be tightened.',
    ],
    recover: [
      'Implement app registration governance — an approval workflow and a restricted population of who can register apps.',
      'Deploy Defender for Cloud Apps app governance for ongoing monitoring.',
      'Periodically audit the full app registration inventory against an expected/approved list.',
      'Alert on new multi-tenant app registrations specifically, given their higher potential for abuse.',
    ],
  },
}

export default entry
