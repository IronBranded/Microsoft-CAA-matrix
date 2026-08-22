import type { ThreatEntry } from '../../../../types/threat'

const entry: ThreatEntry = {
  id: 'anomalous-api-calls-service-principal',
  title: 'Anomalous API Calls by Service Principal',
  domain: 'app-workload-identity',
  category: 'Collection / Exfiltration',
  severity: 'medium',
  status: 'complete',
  shortDesc: 'A sudden spike in Graph or Azure Resource Manager API activity from a workload identity that normally operates at low, predictable volume.',
  description:
    'Most service principals in a tenant have a narrow, repetitive operational pattern. A sharp deviation from that baseline, in call volume, endpoint diversity, or time of day, is one of the more reliable signals that a service principal\'s credentials have been compromised and are now being driven by an attacker rather than its normal automation.',

  forensicArtifacts: [
    {
      logSourceId: 'service-principal-signin-logs',
      source: 'AADServicePrincipalSignInLogs',
      artifact: "Sign-in frequency, timing, or IP pattern deviating from the service principal's own historical baseline (requires its own Diagnostic Setting to reach a Sentinel workspace, separate from interactive SigninLogs)",
    },
    {
      source: 'Microsoft Graph Activity Logs / AzureActivity',
      artifact: "API call volume or endpoint diversity for the service principal exceeding its normal operational pattern",
    },
    {
      logSourceId: 'cloud-app-events',
      source: 'CloudAppEvents',
      artifact: "New API scopes or resource types being accessed by the service principal that it hasn't touched before",
    },
    {
      source: 'Entra ID App registrations',
      artifact: "The service principal's granted permissions, to distinguish anomalous-but-within-scope activity from an attempt to exceed granted scope",
    },
    {
      logSourceId: 'azure-activity-log',
      source: 'AzureActivity',
      artifact: 'Failed authorization attempts (403s) for the service principal against resources outside its granted scope — reconnaissance-like probing behavior',
    },
  ],

  telemetry: {
    correlationMarkers: [
      'Service principals should have among the most predictable behavior of any identity type in a tenant — narrow, repetitive, scheduled. Baseline deviation is proportionally more meaningful here than for human accounts.',
      'This entry is the general detection pattern; Service Principal / Workload Identity Abuse elsewhere in this matrix covers the credential-theft root cause most commonly behind it — investigate both together.',
      'A service principal suddenly calling endpoints or resource types it has never touched, even within its technically-granted permission scope, is worth investigating even without a specific credential-leak indicator.',
    ],
    relevantErrorCodes: [
      {
        code: 'TooManyRequests',
        type: 'Microsoft Graph Throttling (HTTP 429)',
        description: "Throttling is scoped to user/app + resource, not total volume — a service principal driven by an attacker into unfamiliar endpoints at unfamiliar volume is a strong candidate to trip this, precisely because its normal automation doesn't.",
        dfirValue:
          "Because service principals should have the most predictable behavior of any identity type in a tenant (per the correlation markers above), a service principal that suddenly starts getting throttled when it normally never does is a meaningfully stronger signal here than the same pattern would be for a human user's traffic.",
      },
    ],
  },

  mitre: [{ id: 'T1078.004', name: 'Valid Accounts: Cloud Accounts', tactic: 'Defense Evasion' }],

  kql: {
    sentinel: {
      triage: {
        title: 'Service principal sign-in volume by day',
        query: `AADServicePrincipalSignInLogs
| where TimeGenerated > ago(7d)
| summarize DailyCount = count() by ServicePrincipalId, ServicePrincipalName, bin(TimeGenerated, 1d)
| order by ServicePrincipalId, TimeGenerated asc`,
      },
      investigate: {
        title: 'Operation diversity for a suspect service principal',
        query: `let suspect_spn = "<ServicePrincipalId from triage step>";
AzureActivity
| where TimeGenerated > ago(7d)
| where Caller == suspect_spn
| summarize Operations = make_set(OperationNameValue, 20) by bin(TimeGenerated, 1d)
| order by TimeGenerated desc`,
      },
    },
    defender: {
      triage: {
        title: 'Activity volume and diversity for a specific application',
        query: `CloudAppEvents
| where Timestamp > ago(7d)
| where AccountDisplayName == "<service principal display name>"
| summarize EventCount = count(), DistinctActionTypes = dcount(ActionType) by bin(Timestamp, 1d)
| order by Timestamp desc`,
      },
    },
  },

  runbook: {
    triage: [
      "Establish the service principal's historical baseline — volume, timing, endpoints touched.",
      'Compare current activity against it.',
      'Check whether granted permissions changed recently.',
    ],
    contain: [
      "Rotate the service principal's credentials as a precaution.",
      'Scope down permissions if broader than actually needed.',
      'Revoke active sessions.',
    ],
    investigate: [
      'Determine the cause of the deviation — credential compromise, a legitimate but undocumented application change, or a bug.',
      'Cross-reference with Service Principal / Workload Identity Abuse elsewhere in this matrix for the credential-theft angle.',
    ],
    recover: [
      'Establish and monitor baseline behavior profiles for high-privilege service principals specifically.',
      'Alert on statistically significant deviation rather than only on specific known-bad patterns.',
      "Document expected behavior changes as part of any application update process so legitimate changes don't trigger unnecessary investigation.",
    ],
  },
}

export default entry
