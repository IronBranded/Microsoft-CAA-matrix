import type { ThreatEntry } from '../../../../types/threat'

const entry: ThreatEntry = {
  id: 'abnormal-user-agent-api-abuse',
  title: 'Abnormal User Agent / API Abuse',
  domain: 'app-workload-identity',
  category: 'Defense Evasion',
  severity: 'medium',
  status: 'complete',
  shortDesc: 'Anomalous or high-velocity Microsoft Graph API requests originating from custom, non-standard User-Agent strings rather than recognized first-party or approved clients.',
  description:
    'Legitimate Graph API traffic overwhelmingly comes from a recognizable set of clients, each with a predictable User-Agent signature. Custom scripts and attack tooling often carry generic or absent User-Agent headers, or ones tied to common HTTP libraries, which stand out against a tenant\'s normal traffic baseline once profiled.',

  forensicArtifacts: [
    {
      source: 'Entra ID SigninLogs / AADServicePrincipalSignInLogs',
      artifact:
        "UserAgent values inconsistent with known first-party or approved third-party clients — generic HTTP library defaults or entirely absent User-Agent headers. Common default signatures worth a standing watchlist entry, since they show up across many different tools rather than one specific attacker: python-requests/, curl/, Go-http-client/, axios/, PostmanRuntime/. None of these are inherently malicious — plenty of legitimate automation uses them too — but an unexplained one against a sensitive resource is worth checking.",
    },
    {
      logSourceId: 'graph-activity-logs',
      source: 'Microsoft Graph Activity Logs',
      artifact: "API request volume/velocity from a given UserAgent+AppId combination inconsistent with the claimed client's normal behavior",
    },
    {
      logSourceId: 'cloud-app-events',
      source: 'CloudAppEvents',
      artifact: "A UserAgent string that's new/unrecognized against the tenant's established baseline of client signatures",
    },
    {
      logSourceId: 'entra-audit-logs',
      source: 'Entra ID AuditLogs',
      artifact: 'Whether the app/account associated with the anomalous UserAgent has any corresponding legitimate registration or purpose',
    },
    {
      source: 'Threat intelligence',
      artifact: 'Whether the specific UserAgent string matches known attack tooling with published, recognizable defaults',
    },
  ],

  telemetry: {
    correlationMarkers: [
      "UserAgent is trivially spoofable, so its absence of anomaly doesn't prove legitimacy — but its presence of anomaly is still a useful, low-cost signal, especially combined with other factors.",
      "Baseline your tenant's actual normal UserAgent population first — what counts as abnormal is relative to your own traffic, not a universal list.",
      'Combine UserAgent anomaly with volume/velocity and endpoint-diversity signals for a stronger composite signal than UserAgent alone.',
    ],
    relevantErrorCodes: [
      {
        code: 'TooManyRequests',
        type: 'Microsoft Graph Throttling (HTTP 429)',
        description: 'Scripted tooling with a generic or absent User-Agent is also frequently unaware of, or indifferent to, Graph throttling limits — driving straight into 429s rather than pacing requests the way a mature SDK-based client would.',
        dfirValue:
          "A combination of unusual UserAgent AND throttling responses is a stronger composite signal than either alone — legitimate low-quality scripts exist too, but the pairing narrows the field considerably. Check whether the same identity's *normal* traffic also gets throttled regularly before treating this as anomalous; some legitimate integrations are simply chatty.",
      },
    ],
  },

  mitre: [{ id: 'T1550.001', name: 'Use Alternate Authentication Material: Application Access Token', tactic: 'Defense Evasion' }],

  kql: {
    sentinel: {
      triage: {
        title: 'Sign-ins with non-standard User-Agent strings',
        query: `SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType == "0"
| where UserAgent has_any ("python-requests", "curl", "Go-http-client", "PowerShell")
| project TimeGenerated, UserPrincipalName, IPAddress, UserAgent, AppDisplayName
| order by TimeGenerated desc`,
      },
      investigate: {
        title: 'Graph API request volume for non-standard clients',
        query: `MicrosoftGraphActivityLogs
| where TimeGenerated > ago(7d)
| where UserAgent has_any ("python-requests", "curl", "Go-http-client")
| summarize RequestCount = count(), DistinctEndpoints = dcount(RequestUri) by AppId, UserAgent, IPAddress
| order by RequestCount desc`,
      },
    },
    defender: {
      triage: {
        title: 'Non-standard User-Agent activity',
        query: `CloudAppEvents
| where Timestamp > ago(7d)
| where UserAgent has_any ("python-requests", "curl", "Go-http-client")
| project Timestamp, AccountDisplayName, UserAgent, IPAddress, RawEventData
| order by Timestamp desc`,
      },
    },
  },

  runbook: {
    triage: [
      'Confirm whether the flagged UserAgent corresponds to any known/approved automation.',
      'Check request volume and endpoint diversity for that session/token.',
      "Determine the account/app's own baseline behavior.",
    ],
    contain: [
      'Revoke the session/token if tied to unauthorized activity.',
      'Block the source IP if clearly malicious.',
    ],
    investigate: [
      'Determine what was accessed via the anomalous client.',
      'Check whether this correlates with a known attack tooling signature.',
      'Review for the same UserAgent pattern across other accounts if threat-intel sharing is available.',
    ],
    recover: [
      'Baseline expected UserAgent population for your tenant and alert on deviations.',
      'Combine with volume/endpoint-diversity signals for a stronger composite detection.',
      'Consider Conditional Access client-app restrictions where feasible to limit which clients can authenticate at all.',
    ],
  },
}

export default entry
