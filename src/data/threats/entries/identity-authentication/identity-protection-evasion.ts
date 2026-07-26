import type { ThreatEntry } from '../../../../types/threat'

const entry: ThreatEntry = {
  id: 'identity-protection-evasion',
  title: 'Identity Protection Evasion',
  domain: 'identity-authentication',
  category: 'Defense Evasion',
  severity: 'medium',
  status: 'complete',
  shortDesc: "Deliberately shaping sign-in behavior to stay under Entra ID Identity Protection's risk-detection thresholds — impossible travel, unfamiliar properties, anonymous IP.",
  description:
    'Entra ID Identity Protection scores sign-ins against behavioral baselines and known-bad indicators. Sophisticated attackers shape their activity specifically to avoid triggering these detections — routing through residential proxies instead of flagged VPS ranges, mimicking the victim\'s usual browser/OS fingerprint, or pacing activity to avoid velocity-based flags — to keep their sign-ins scored as low-risk and avoid step-up authentication or automated remediation.',

  forensicArtifacts: [
    {
      source: 'Entra ID Identity Protection',
      artifact: 'Consistently low-risk-scored sign-ins for an account later confirmed compromised — the absence of risk flags despite a real compromise is itself the retrospective artifact',
    },
    {
      source: 'Entra ID SigninLogs',
      artifact: "Device/browser fingerprint closely matching the victim's own known devices — attacker infrastructure deliberately spoofing these values rather than using default tooling signatures",
    },
    {
      source: 'Entra ID SigninLogs',
      artifact: 'Sign-in velocity/geography carefully paced to avoid triggering impossible-travel detection — a gap consistent with plausible travel time rather than an obvious instantaneous jump',
    },
    {
      source: 'Threat intelligence / IP reputation',
      artifact: 'Source IPs from residential proxy services rather than flagged datacenter/VPS ranges — a deliberate choice to avoid known-bad IP reputation lists',
    },
    {
      source: 'Entra ID Identity Protection risk detection history',
      artifact: 'A pattern of risk being detected then manually dismissed by an admin — worth checking whether that dismissal was itself legitimate or part of the same compromise',
    },
  ],

  telemetry: {
    correlationMarkers: [
      "This scenario is fundamentally about absence of signal rather than presence — the retrospective question is why Identity Protection didn't catch this, comparing what was available against what a real compromise later revealed.",
      'Residential proxy usage specifically defeats IP-reputation-based detection while doing nothing to defeat behavioral/device-based signals — a sophisticated evasion attempt often still slips up on a device fingerprint inconsistency somewhere in the session.',
      "Manual risk dismissal by an admin is a legitimate, necessary workflow but also a potential attacker lever if the dismissing admin's own account is compromised — verify the dismissal's own legitimacy during any retrospective review.",
    ],
  },

  mitre: [{ id: 'T1036', name: 'Masquerading', tactic: 'Defense Evasion' }],

  kql: {
    sentinel: {
      triage: {
        title: 'Risk detection history for a confirmed-compromised account',
        description: 'Retrospective query — pull the account\'s risk history to see what was and wasn\'t flagged.',
        query: `let compromised_user = "<UserPrincipalName under investigation>";
AADUserRiskEvents
| where TimeGenerated > ago(90d)
| where UserPrincipalName == compromised_user
| project TimeGenerated, RiskEventType, RiskLevel, RiskState, IpAddress, Location
| order by TimeGenerated desc`,
      },
      investigate: {
        title: 'Sign-ins not flagged as risky, for comparison',
        query: `let compromised_user = "<UserPrincipalName under investigation>";
SigninLogs
| where TimeGenerated > ago(90d)
| where UserPrincipalName == compromised_user
| project TimeGenerated, IPAddress, Location, DeviceDetail, RiskLevelDuringSignIn, RiskState
| order by TimeGenerated desc`,
      },
    },
    defender: {
      triage: {
        title: 'Full activity history for a specific account',
        query: `CloudAppEvents
| where Timestamp > ago(90d)
| where AccountDisplayName == "<compromised account>"
| project Timestamp, ActionType, IPAddress, RawEventData
| order by Timestamp desc`,
      },
    },
  },

  runbook: {
    triage: [
      'Pull the full risk detection history for the affected account.',
      'Compare flagged versus unflagged sign-ins for what distinguished them.',
      'Identify the specific evasion technique apparent from the pattern — proxy usage, fingerprint spoofing, paced velocity.',
    ],
    contain: [
      'Revoke sessions and reset credentials as with any confirmed compromise.',
      "Manually elevate the account's risk state if Identity Protection itself didn't catch it.",
    ],
    investigate: [
      'Determine how sophisticated the evasion was and whether it suggests a specific, resourced threat actor versus opportunistic reuse of known techniques.',
      "Review whether any risk dismissals in the account's history were themselves legitimate.",
    ],
    recover: [
      'Tune Identity Protection risk policies to weight behavioral/device signals more heavily alongside IP reputation, since IP-based evasion is comparatively easy.',
      'Review admin risk-dismissal practices and require justification/audit for dismissals.',
      "Consider Conditional Access Token Protection and phishing-resistant MFA as controls that don't depend on risk-scoring accuracy at all.",
    ],
  },
}

export default entry
