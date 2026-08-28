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
      logSourceId: 'identity-protection-risk-data',
      source: 'Entra ID Identity Protection',
      artifact: 'Consistently low-risk-scored sign-ins for an account later confirmed compromised — the absence of risk flags despite a real compromise is itself the retrospective artifact',
    },
    {
      logSourceId: 'sign-in-logs',
      source: 'Entra ID SigninLogs',
      artifact: "Device/browser fingerprint closely matching the victim's own known devices — attacker infrastructure deliberately spoofing these values rather than using default tooling signatures",
    },
    {
      logSourceId: 'sign-in-logs',
      source: 'Entra ID SigninLogs',
      artifact: 'Sign-in velocity/geography carefully paced to avoid triggering impossible-travel detection — a gap consistent with plausible travel time rather than an obvious instantaneous jump',
    },
    {
      source: 'Threat intelligence / IP reputation',
      artifact: 'Source IPs from residential proxy services rather than flagged datacenter/VPS ranges — a deliberate choice to avoid known-bad IP reputation lists',
    },
    {
      logSourceId: 'identity-protection-risk-data',
      source: 'Entra ID Identity Protection risk detection history',
      artifact: 'A pattern of risk being detected then manually dismissed by an admin — worth checking whether that dismissal was itself legitimate or part of the same compromise',
    },
    {
      logSourceId: 'identity-protection-risk-data',
      source: 'Entra ID Identity Protection — licensing context',
      artifact:
        "What 'evasion' actually means depends on tenant licensing: Free and P1 tenants only ever see a generic 'Additional risk detected' entry with no further detail behind it, even for detections that would show a specific type (impossible travel, anomalous token, etc.) on P2. An evasion analysis assuming P2-level detection granularity when the tenant is actually P1 will misjudge what the attacker needed to avoid in the first place — confirm licensing before concluding a gap in detection was evasion rather than a licensing ceiling.",
    },
  ],

  telemetry: {
    correlationMarkers: [
      "This scenario is fundamentally about absence of signal rather than presence — the retrospective question is why Identity Protection didn't catch this, comparing what was available against what a real compromise later revealed.",
      'Residential proxy usage specifically defeats IP-reputation-based detection while doing nothing to defeat behavioral/device-based signals — a sophisticated evasion attempt often still slips up on a device fingerprint inconsistency somewhere in the session.',
      "Manual risk dismissal by an admin is a legitimate, necessary workflow but also a potential attacker lever if the dismissing admin's own account is compromised — verify the dismissal's own legitimacy during any retrospective review.",
      'There is deliberately no relevantErrorCodes entry for this scenario: successful evasion means none of the codes that would normally signal trouble — AADSTS53003 (Conditional Access block), AADSTS53004 (risk-based registration block), or a risk-driven step-up challenge — ever fire. Their absence is the point, not a gap in this catalog entry.',
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

  authFlow: {
    pattern: 'sequence',
    narrative:
      "This is the purest case in the whole matrix of a flow defined by absence rather than presence — successful evasion means every step below produces exactly the code a legitimate sign-in would, by design. There's no distinguishing 'evasion code'; the entry's own correlationMarkers note above already makes this point about relevantErrorCodes, and it applies equally here.",
    steps: [
      {
        code: '0',
        label: 'Sign-in completes successfully, scored low-risk by Identity Protection',
        detail: "Indistinguishable from a genuine low-risk sign-in — that's the entire objective of the technique. Nothing about this event alone tells you evasion occurred.",
      },
      {
        code: 'risk-not-elevated',
        label: 'Behavioral signals (device fingerprint, velocity, IP reputation) each individually stay under whatever threshold would trigger a risk detection',
        detail: 'Not a code at all — an absence. This is why the forensicArtifacts above lean on retrospective comparison (flagged versus unflagged sign-ins for a later-confirmed-compromised account) rather than anything findable in real time from a single event.',
      },
    ],
    distinguishingNotes:
      "You cannot detect this scenario by looking for it directly — there is nothing positive to alert on. The only way this entry's content becomes actionable is retrospectively, after a compromise is confirmed some other way, when you go back and ask why Identity Protection didn't catch it. If you're trying to build a real-time detection for 'evasion specifically,' that's the wrong goal; the goal is reducing how much evasion is possible in the first place (see recover).",
  },

  tokenTimeline: {
    issuance: "Issued at a sign-in that's, by design, indistinguishable from a legitimate one — nothing about issuance timing or context flags this scenario specifically.",
    expiration: 'Standard token lifetimes. This scenario is about avoiding detection at the point of authentication, not about anything unusual in what happens to the token afterward.',
    authInstant:
      'auth_time reflects a genuine-looking sign-in moment with nothing anomalous about it — the entire technique depends on this claim, like everything else about the event, looking ordinary.',
    authMethods: 'amr reflects whatever the account\'s real methods are, used normally — evasion targets risk scoring, not the authentication mechanism itself, so amr carries no signal here.',
    mfaInstant: 'Unremarkable, same reasoning as authInstant — if the sign-in successfully evaded risk-based step-up, MFA (if required at all) completed at a normal pace with nothing to flag.',
    otherContext:
      "This entry's tokenTimeline is deliberately unremarkable across every field, and that's not a gap — it's the finding. If you're reading this entry hoping to find a claim or timing pattern that reveals evasion, that hope is itself worth recalibrating: the retrospective, comparative approach in forensicArtifacts and the KQL above is the only real path in.",
  },

  runbook: {
    triage: [
      'Pull the full risk detection history for the affected account.',
      'Compare flagged versus unflagged sign-ins for what distinguished them.',
      'Identify the specific evasion technique apparent from the pattern — proxy usage, fingerprint spoofing, paced velocity.',
    ],
    contain: [
      "Revoke sessions and reset credentials as with any confirmed compromise: `Revoke-MgUserSignInSession -UserId <UPN>`, then `Update-MgUser -UserId <UPN> -PasswordProfile @{ Password = '<new password>'; ForceChangePasswordNextSignIn = $true }`.",
      'Manually elevate the account\'s risk state if Identity Protection itself didn\'t catch it: `Confirm-MgRiskyUserCompromised -UserIds <userObjectId>` (Microsoft.Graph.Identity.SignIns module). This closes the gap between what actually happened and what Identity Protection\'s own risk history shows — the exact gap this scenario is about.',
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
