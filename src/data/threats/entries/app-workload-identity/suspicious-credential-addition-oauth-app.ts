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
      logSourceId: 'entra-audit-logs',
      source: 'Entra ID AuditLogs',
      artifact: "Certificates-and-secrets management operations showing a new client secret or certificate added to an existing, already-trusted application",
    },
    {
      logSourceId: 'entra-audit-logs',
      source: 'Entra ID AuditLogs',
      artifact:
        "The acting identity and whether they're expected to manage that specific application's credentials — often requires only Application Administrator or ownership of the specific app, not a directory-wide role. Note that the credential's own displayName field (shown in the portal as a label like 'Prod cert' or a date) is a free-text value the adding identity sets — an attacker can label a newly-added secret to blend in with existing, legitimate-looking entries, so don't rely on the label alone to distinguish it from real credentials; the addition timestamp and acting identity are the reliable signals.",
    },
    {
      source: 'Entra ID App registrations',
      artifact: "The new credential's expiry — an attacker-added secret often has an unusually long expiry compared to the organization's normal rotation practice",
    },
    {
      logSourceId: 'service-principal-signin-logs',
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
    relevantErrorCodes: [
      {
        code: 'AADSTS7000215',
        type: 'Invalid Client Secret',
        description: 'The provided client secret is invalid. Multiple valid secrets can coexist on one app, so this fires per-credential, not per-app — the original legitimate secret keeps working even while an attacker-added one is separately valid.',
        dfirValue:
          "Once you identify and remove the attacker-added credential specifically (not the original one), this code confirms removal took effect for anything still trying to use it. Because the app has multiple valid credentials simultaneously, don't assume the app is clean just because a credential still authenticates successfully — verify it's the legitimate one.",
      },
      {
        code: 'AADSTS700027',
        type: 'Invalid Client Assertion',
        description: 'Certificate-based equivalent of an invalid secret, relevant if the added credential was a certificate rather than a client secret.',
        dfirValue: 'Same removal-confirmation role as AADSTS7000215, for certificate-based credential additions.',
      },
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

  authFlow: {
    pattern: 'sequence',
    narrative:
      "Same structural pattern as fido2-passkey-registration-hijacking in Domain 1 — a persistence mechanism that only becomes relevant after some other compromise already granted the attacker rights to manage the app. This entry's job is the middle link: the credential addition itself, and its first subsequent use.",
    steps: [
      {
        code: 'admin-access-obtained',
        label: "Attacker obtains rights sufficient to manage the target application's credentials",
        detail: "Not this entry's mechanism — could be Application Administrator, or ownership of just the one app. See whichever compromise scenario elsewhere in this matrix actually applies to how that access was obtained.",
      },
      {
        code: 'credential-added',
        label: 'A new client secret or certificate is added to the existing application',
        detail: "AuditLogs event under Certificates and secrets management. The original credential is untouched and keeps working, which is precisely why this persists quietly — nothing about the app's normal operation changes.",
      },
      {
        code: '0',
        label: 'First sign-in using the newly-added credential',
        detail: "AADServicePrincipalSignInLogs — the point this stops being a configuration change and becomes active use. Multiple credentials can be valid simultaneously, so this event alone doesn't tell you the original credential is compromised too.",
      },
    ],
    distinguishingNotes:
      "Don't stop at removing the added credential and calling it done — trace backward to how the acting identity got rights to manage that app in the first place, the same discipline fido2-passkey-registration-hijacking calls for. If that access itself is still open, the attacker can simply add another credential after you remove this one.",
  },

  tokenTimeline: {
    issuance: "Tokens from the newly-added credential are issued exactly like tokens from the original one — nothing at the token level distinguishes which of an app's multiple valid credentials was used to obtain it.",
    expiration:
      'Standard app-only token lifetimes apply per-issuance, but the credential itself is the durable asset — as with service-principal-workload-identity-abuse, the attacker can mint fresh tokens on demand for as long as the added credential remains valid, and attacker-added secrets often carry unusually long configured expiry (see forensicArtifacts).',
    authInstant: 'Not meaningful in the interactive sense — this is the same non-interactive, machine-to-machine pattern as the rest of this domain.',
    authMethods: 'amr is not populated for app-only tokens of this kind.',
    mfaInstant: 'Not applicable.',
    otherContext:
      "The critical operational fact for this entry: removing the malicious credential does not tell you whether the app's original credential is also compromised, since AADSTS7000215/AADSTS700027 fire per-credential, not per-app. Confirm which specific credential is being used for any given sign-in before concluding the app is clean.",
  },

  runbook: {
    triage: [
      'Identify which application had a credential added and by whom.',
      'Confirm whether that identity normally manages the app.',
      "Check the new credential's configured expiry.",
      'Determine whether the app has multiple active credentials currently, and whether that count is expected.',
    ],
    contain: [
      "Remove the unauthorized credential specifically — not the original one. For a secret: `Remove-MgApplicationPassword -ApplicationId <id> -KeyId <keyId>`. For a certificate: `Remove-MgApplicationKey -ApplicationId <id> -BodyParameter @{ keyId = '<keyId>'; proof = '<proof-of-possession token>' }` (see service-principal-workload-identity-abuse for why the proof requirement makes this path more awkward mid-incident than the secret path). The legitimate credential continues working either way, so this doesn't disrupt the app.",
      "There's no session to revoke for the malicious credential's own use — app-only tokens simply stop being mintable once the credential is removed, and any already-issued ones expire on their normal lifetime.",
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
