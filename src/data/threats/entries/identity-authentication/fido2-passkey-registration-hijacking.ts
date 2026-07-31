import type { ThreatEntry } from '../../../../types/threat'

const entry: ThreatEntry = {
  id: 'fido2-passkey-registration-hijacking',
  title: 'FIDO2 / Passkey Registration Hijacking',
  domain: 'identity-authentication',
  category: 'Persistence',
  severity: 'high',
  status: 'complete',
  shortDesc: 'Adding an attacker-controlled security key or passkey during an active session or weak onboarding flow, creating durable, MFA-satisfying persistence.',
  description:
    "If an attacker gains any authenticated session on a target account, even briefly, registering their own FIDO2 security key or passkey against that account creates a standing, phishing-resistant credential the attacker controls going forward. Because the newly-registered method itself satisfies MFA, this converts a temporary compromise into durable, MFA-bypassing persistence unless the registration event is specifically monitored and challenged.",

  forensicArtifacts: [
    {
      source: 'Entra ID AuditLogs',
      artifact: "'User registered security info' operations for a FIDO2 security key or passkey, on an account with no expected reason to be re-registering MFA",
    },
    {
      source: 'Entra ID AuditLogs',
      artifact: "The registration event's initiating session — IP, device, and whether it followed a known token-theft or account-compromise event elsewhere in this matrix",
    },
    {
      source: 'Entra ID authentication methods policy',
      artifact: 'Whether FIDO2/passkey self-service registration requires re-authentication with an existing strong factor, or can be added with only a recently-obtained session — the latter is what makes this technique viable',
    },
    {
      source: 'Entra ID SigninLogs',
      artifact: 'Subsequent sign-ins authenticating via the newly-registered FIDO2 key/passkey — confirms the attacker is actively using their new persistent credential',
    },
    {
      source: 'JWT token claims (if the initiating session token is captured)',
      artifact:
        "The ngcmfa claim specifically authorizes registering a new security key or WHfB credential and is only valid for roughly 15 minutes after the session was authenticated — a token carrying this claim is the specific mechanism that makes registration possible without a fresh, independent MFA challenge. See Device Code Phishing elsewhere in this matrix for one documented way an attacker can force this claim into a token they don't otherwise have.",
    },
    {
      source: 'Help desk / self-service registration portal',
      artifact: 'Whether registration happened through the normal self-service flow (implying an already-compromised session) or an admin-assisted path (implying social engineering of staff)',
    },
  ],

  telemetry: {
    correlationMarkers: [
      'A new authentication method registration event is only as trustworthy as the session that performed it — always trace back to how that session was originally established.',
      "FIDO2/passkey registration, once complete, is itself now a valid, phishing-resistant-looking credential from Entra ID's perspective — this is what makes it durable persistence rather than a temporary foothold.",
      "Compare the newly-registered method's metadata against your organization's approved hardware key inventory, where such an inventory is maintained.",
    ],
  },

  mitre: [
    { id: 'T1556', name: 'Modify Authentication Process', tactic: 'Persistence' },
    { id: 'T1098', name: 'Account Manipulation', tactic: 'Persistence' },
  ],

  atrm: [{ id: 'AZT501.1', name: 'User Account Manipulation', tactic: 'Persistence' }],

  kql: {
    sentinel: {
      triage: {
        title: 'FIDO2 / passkey registration events',
        query: `AuditLogs
| where TimeGenerated > ago(14d)
| where OperationName has_any ("Register security info", "User registered")
| where TargetResources has_any ("FIDO2", "Passkey")
| project TimeGenerated, InitiatedBy, TargetResources, Result, CorrelationId
| order by TimeGenerated desc`,
      },
      investigate: {
        title: 'Sign-ins using a newly-registered method',
        query: `SigninLogs
| where TimeGenerated > ago(14d)
| where AuthenticationRequirement == "multiFactorAuthentication"
| where AuthenticationDetails has_any ("FIDO2", "passkey")
| project TimeGenerated, UserPrincipalName, IPAddress, AuthenticationDetails, Location
| order by TimeGenerated desc`,
      },
    },
    defender: {
      triage: {
        title: 'Security info registration activity',
        query: `CloudAppEvents
| where Timestamp > ago(14d)
| where ActionType has_any ("Register security info", "User registered")
| project Timestamp, AccountDisplayName, ActionType, IPAddress, RawEventData
| order by Timestamp desc`,
      },
    },
  },

  runbook: {
    triage: [
      'Identify what was registered and trace the registering session back to its origin.',
      'Check whether the account has any other recent compromise indicators.',
      'Confirm with the actual user whether they registered it.',
      'Determine the timing relative to any other suspicious activity on the account.',
    ],
    contain: [
      'Remove the attacker-registered method immediately.',
      'Revoke sessions.',
      'If the account is confirmed compromised, treat all currently-registered auth methods as suspect and require full re-registration from a verified state.',
      'Suspend the account if the scope of compromise is unclear.',
    ],
    investigate: [
      'Determine how the registering session was obtained — correlate with other scenarios in this matrix (token theft, AiTM, PRT abuse).',
      'Check what the attacker did using their new persistent credential before it was caught.',
      'Review whether other accounts show the same registration pattern in the same window.',
      "Assess the authentication methods policy's re-authentication requirement for new registrations, since a gap there is what enables this technique.",
    ],
    recover: [
      'Require re-authentication with an existing strong factor before allowing new method registration.',
      'Alert on every new FIDO2/passkey registration for privileged accounts specifically.',
      'Maintain an approved-hardware-key inventory where feasible.',
      'Periodically review registered authentication methods against expected device/user assignments.',
    ],
  },
}

export default entry
