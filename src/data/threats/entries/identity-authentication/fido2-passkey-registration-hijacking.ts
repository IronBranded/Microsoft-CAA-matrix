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
      logSourceId: 'entra-audit-logs',
      source: 'Entra ID AuditLogs',
      artifact: "'User registered security info' operations for a FIDO2 security key or passkey, on an account with no expected reason to be re-registering MFA",
    },
    {
      logSourceId: 'entra-audit-logs',
      source: 'Entra ID AuditLogs',
      artifact: "The registration event's initiating session — IP, device, and whether it followed a known token-theft or account-compromise event elsewhere in this matrix",
    },
    {
      source: 'Entra ID authentication methods policy',
      artifact: 'Whether FIDO2/passkey self-service registration requires re-authentication with an existing strong factor, or can be added with only a recently-obtained session — the latter is what makes this technique viable',
    },
    {
      logSourceId: 'sign-in-logs',
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
    relevantErrorCodes: [
      {
        code: 'AADSTS53004',
        type: 'Risk-Based Registration Block',
        description: 'ProofUpBlockedDueToRisk — the session is flagged risky enough that Identity Protection blocks registering a new authentication method until the risk is resolved.',
        dfirValue:
          "Confirms Identity Protection risk scoring caught the session before the attacker could complete registration — a strong containment signal if you see this immediately followed by no successful registration. Its absence proves nothing on its own: this only fires if the session actually scored as risky, and a patient or well-blended attacker may not trip it at all.",
      },
      {
        code: 'AADSTS53010',
        type: 'Location/Device-Restricted Registration',
        description:
          'ProofUpBlockedDueToSecurityInfoAcr — the tenant requires authentication method registration to happen from a specific trusted location or device, and this session doesn\'t qualify.',
        dfirValue:
          'Where configured, this is a genuinely strong control: an attacker with only a stolen session token, not physical presence on a trusted network/device, cannot complete registration even after passing MFA. Worth checking whether this restriction is actually in place before assuming a registration event represents a real compromise versus a blocked attempt.',
      },
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

  authFlow: {
    pattern: 'sequence',
    narrative:
      "The registration event itself is a single AuditLogs entry, but it's meaningless read in isolation — the flow that matters spans from whatever established the initiating session (a separate compromise, documented elsewhere in this matrix) through to the attacker's first subsequent sign-in using their new credential. This entry's job is that middle link, not the whole chain.",
    steps: [
      {
        code: 'session-established',
        label: 'Attacker obtains any authenticated session on the target account',
        detail: "Not this entry's mechanism — see token-theft-session-hijacking, AiTM, device-code-phishing, or user-account-compromise for how. What matters here is only that a session exists, however briefly.",
      },
      {
        code: 'security-info-registered',
        label: 'FIDO2 security key or passkey registered against the account',
        detail: 'The persistence-establishing step. Whether this succeeds depends entirely on tenant policy — specifically whether registration demands re-authentication with an existing strong factor, or accepts the session alone. See relevantErrorCodes for the two controls (AADSTS53004, AADSTS53010) that can block this step even after the initiating session was obtained.',
      },
      {
        code: '0',
        label: "Attacker's first sign-in using the newly-registered credential",
        detail: "Confirms the persistence is live and being used. From this point forward, the attacker's access no longer depends on whatever got them the original session — a password reset alone won't remove it.",
      },
    ],
    distinguishingNotes:
      "Don't investigate this entry's registration event in isolation — always trace backward to how the initiating session was obtained (that's a different entry's flow) and forward to confirm whether the new credential was actually used (this entry's last step). A registration event with no subsequent sign-in on the new method might still be caught in time; one with confirmed subsequent use means the persistence is already active.",
  },

  tokenTimeline: {
    issuance:
      "Two separate issuances matter here: the token from the initiating session (out of scope for this entry — see whichever compromise scenario actually applies), and the token from the attacker's first sign-in using their newly-registered method, which is a fully ordinary, independently-issued token going forward.",
    expiration:
      'Once registered, the new credential has no special expiration tied to the original compromise — it persists exactly as long as any legitimately-registered FIDO2 key/passkey would, which is indefinitely until explicitly removed. This is the entire point of the technique.',
    authInstant:
      "auth_time on sign-ins using the new credential reflects that sign-in specifically, with no relationship to whatever compromise originally enabled registration. Once this technique succeeds, the attacker's ongoing access looks like any other passkey user's, at the claim level.",
    authMethods:
      "amr on post-registration sign-ins shows the new method (fido2 or equivalent) — and looks exactly as strong and legitimate as any real user's phishing-resistant credential, since Entra ID has no way to distinguish a maliciously-registered key from a real one after the fact. This is a case where a 'strong' amr value should not be read as reassuring.",
    mfaInstant:
      "The registration event itself is the moment worth timing precisely — see AuditLogs for the registration timestamp, and cross-reference against the ngcmfa claim's roughly 15-minute validity window if the initiating session's token is available. Once registered, subsequent MFA timing on the attacker's sign-ins is unremarkable.",
    otherContext:
      'This entry is a persistence mechanism, not an initial access one — it only becomes relevant after some other compromise already happened. When writing up an incident, present it as a stage in a chain (see distinguishingNotes) rather than a standalone event, since a reader who only sees the registration without the preceding compromise is missing the more important half of the story.',
  },

  runbook: {
    triage: [
      'Identify what was registered and trace the registering session back to its origin.',
      'Check whether the account has any other recent compromise indicators.',
      'Confirm with the actual user whether they registered it.',
      'Determine the timing relative to any other suspicious activity on the account.',
    ],
    contain: [
      'Remove the attacker-registered method immediately: `Get-MgUserAuthenticationMethod -UserId <UPN>` to find its ID, then `Remove-MgUserAuthenticationFido2Method -UserId <UPN> -Fido2AuthenticationMethodId <id>`.',
      'Revoke sessions: `Revoke-MgUserSignInSession -UserId <UPN>`.',
      'If the account is confirmed compromised, treat all currently-registered auth methods as suspect — list them all with `Get-MgUserAuthenticationMethod -UserId <UPN>`, remove each with its method-specific cmdlet, and require full re-registration from a verified state.',
      'Suspend the account if the scope of compromise is unclear: `Update-MgUser -UserId <UPN> -AccountEnabled:$false`.',
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
