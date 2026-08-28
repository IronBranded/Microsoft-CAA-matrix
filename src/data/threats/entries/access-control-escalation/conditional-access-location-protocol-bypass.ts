import type { ThreatEntry } from '../../../../types/threat'

const entry: ThreatEntry = {
  id: 'conditional-access-location-protocol-bypass',
  title: 'Conditional Access Location / Protocol Bypasses',
  domain: 'access-control-escalation',
  category: 'Defense Evasion',
  severity: 'high',
  status: 'complete',
  shortDesc: "Spoofing trusted network signals — IPv6 routes, named-location exemptions, or tenant-edge mismatches — to make a sign-in appear to originate somewhere it doesn't.",
  description:
    'Location-based Conditional Access controls generally trust the IP address of the sign-in request, and some tenants configure trusted locations more broadly than intended. Attackers have used IPv6-routed traffic that doesn\'t match IPv4-based trusted ranges, or cloud-hosted infrastructure inside a trusted IP block, to make a malicious sign-in present as originating from a trusted network, sidestepping location-based policy without defeating the policy logic itself.',

  forensicArtifacts: [
    {
      logSourceId: 'sign-in-logs',
      source: 'Entra ID SigninLogs',
      artifact: "A successful sign-in from an IP within a trusted/named location range, for an account whose normal behavior doesn't otherwise match that location",
    },
    {
      source: 'Entra ID Named Locations configuration',
      artifact: "The actual configured IP ranges for each trusted location — verify they're still accurate and not broader than intended, such as an entire cloud provider's block instead of one office's static IP",
    },
    {
      logSourceId: 'sign-in-logs',
      source: 'Entra ID SigninLogs',
      artifact: 'IPv6 sign-ins where the corresponding policy or named location was only ever configured with IPv4 ranges — a protocol-family gap rather than an IP-range gap',
    },
    {
      logSourceId: 'entra-audit-logs',
      source: 'Entra ID AuditLogs',
      artifact: "Changes to named location definitions themselves — an expanded IP range or a location marked trusted that shouldn't be",
    },
    {
      source: 'External IP intelligence',
      artifact: "Whether the sign-in's source IP is a known VPS/hosting range that happens to fall inside a trusted location's configured CIDR block, rather than genuinely being the network it was meant to represent",
    },
  ],

  telemetry: {
    correlationMarkers: [
      'A trusted named location is only as good as the IP ranges configured in it — periodically verify those ranges are still accurate, since IP space gets reassigned and broad "to be safe" CIDR blocks often end up including infrastructure never intended to be trusted.',
      'IPv6 and IPv4 need to be considered together — a policy or named location built only against IPv4 ranges leaves an IPv6 path open, since Entra ID evaluates whichever protocol the request actually arrives on.',
      'Compare the sign-in\'s ASN/organization from IP intelligence against what the named location is supposed to represent — a mismatch between "labeled as corporate office" and "actually a cloud hosting provider" is the core signal.',
    ],
    relevantErrorCodes: [
      {
        code: 'AADSTS53003',
        type: 'Conditional Access',
        description: 'Access has been blocked by Conditional Access policies. The access policy does not allow token issuance.',
        dfirValue:
          'A successful bypass means this code never fires for a sign-in that should have triggered it — the absence is the finding. If you can reproduce the same source IP/network conditions in a controlled test and it does NOT produce this error where a legitimate location-based policy should apply, that confirms the bypass path.',
      },
    ],
  },

  mitre: [
    { id: 'T1556.009', name: 'Modify Authentication Process: Conditional Access Policies', tactic: 'Defense Evasion' },
    { id: 'T1090', name: 'Proxy', tactic: 'Command and Control' },
  ],

  kql: {
    sentinel: {
      triage: {
        title: 'Sign-ins from trusted named locations',
        description: 'Exact NetworkLocationDetails formatting can vary — inspect a sample row with `| take 5` first to confirm the field shape in your tenant.',
        query: `SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType == "0"
| where NetworkLocationDetails has "trustedNamedLocation"
| project TimeGenerated, UserPrincipalName, IPAddress, Location, NetworkLocationDetails
| order by TimeGenerated desc`,
      },
      investigate: {
        title: 'IPv6 sign-ins',
        description: 'Checks for protocol-family coverage gaps against named locations built only with IPv4 ranges.',
        query: `SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType == "0"
| where IPAddress has ":"
| project TimeGenerated, UserPrincipalName, IPAddress, Location, ConditionalAccessStatus
| order by TimeGenerated desc`,
      },
    },
    defender: {
      triage: {
        title: 'IPv6 sign-in activity',
        query: `CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType has "Sign-in"
| where IPAddress has ":"
| project Timestamp, AccountDisplayName, IPAddress, RawEventData
| order by Timestamp desc`,
      },
    },
  },

  authFlow: {
    pattern: 'sequence',
    narrative:
      "Same fundamental shape as conditional-access-policy-gaps — a sign-in that completes without the friction a location-based policy should have applied — but the mechanism is different: here the policy itself is working correctly, evaluating exactly the IP/network signal it's configured to check. The gap is in what that signal actually represents, not in whether the policy fires.",
    steps: [
      {
        code: '0',
        label: 'Sign-in evaluated as originating from a trusted location, completes without location-based friction',
        detail: "The policy engine did its job correctly given the input — the IP genuinely falls inside the configured trusted range, or the request arrived on a protocol (IPv6) the range was never built to cover. This isn't a policy failure the way a report-only or excluded-user gap is; it's a scoping failure in what the trusted range represents.",
      },
      {
        code: '53003',
        label: '(For comparison) what the same account/app combination produces from a genuinely untrusted network',
        detail: "Confirms the policy logic itself is intact and would have blocked this sign-in if the network signal hadn't misrepresented itself as trusted.",
      },
    ],
    distinguishingNotes:
      "Don't conflate this with conditional-access-policy-gaps even though the sign-in-log symptom looks identical (a plain 0 where you'd expect 53003) — the fix is completely different. A policy gap needs a configuration change to the policy or its exclusions; this needs a correction to what the named location actually represents (narrower CIDR ranges, IPv6 coverage), since the policy logic itself was never broken.",
  },

  tokenTimeline: {
    issuance: 'Issued exactly as it would be for any successful sign-in — the bypass affects whether location-based friction applies, not the token issuance mechanics themselves.',
    expiration: 'Standard lifetimes, unaffected by this scenario specifically.',
    authInstant: 'auth_time reflects an ordinary sign-in moment — nothing about this claim distinguishes a spoofed-trusted-network sign-in from a genuinely trusted one.',
    authMethods:
      'amr reflects whatever the user actually provided, which may be less than a properly location-scoped policy would have demanded — same practical symptom as conditional-access-policy-gaps, worth checking for the same reason.',
    mfaInstant: "Absent where the bypassed policy would have required a step-up — there's no MFA instant because the location signal made that requirement never apply.",
    otherContext:
      'This scenario is discoverable largely through IP intelligence correlation (is this ASN/organization actually what the named location claims to represent?) rather than anything in the token or sign-in event itself — the token side of this is deliberately unremarkable, same as the sibling policy-gaps entry.',
  },

  runbook: {
    triage: [
      'Verify the actual configured IP ranges for each named location against what they are supposed to represent.',
      'Check for IPv6 coverage gaps across affected policies.',
      'Run IP intelligence on any suspicious trusted-location sign-in to check for VPS/hosting ranges masquerading as trusted infrastructure.',
      'Identify which policies and resources were actually reachable through the bypass.',
    ],
    contain: [
      "Remove or narrow the overly-broad named location range: `Update-MgIdentityConditionalAccessNamedLocation -NamedLocationId <id> -BodyParameter @{ ... }`. The exact body shape depends on whether it's an IP-based or country-based location object — worth checking against the portal first if you're not already scripting named-location management regularly.",
      'Add explicit IPv6 blocking or coverage to affected CA policies.',
      'Revoke sessions relying on the bypass: `Revoke-MgUserSignInSession -UserId <UPN>`.',
      'Temporarily tighten the affected policy while remediation is underway.',
    ],
    investigate: [
      'Determine how the attacker identified the gap — external scanning of IP ranges, insider knowledge, or trial and error.',
      'Check what access was obtained via the bypassed policy.',
      'Review whether other named locations share the same class of misconfiguration.',
      'Establish how long the gap has existed versus when it was first exploited.',
    ],
    recover: [
      'Periodically audit named location definitions against actual intended scope.',
      'Ensure CA policies explicitly account for both IPv4 and IPv6.',
      'Avoid overly broad CIDR ranges in trusted location definitions.',
      'Consider Global Secure Access / compliant network signals as a more robust trusted-network indicator than static IP ranges alone.',
    ],
  },
}

export default entry
