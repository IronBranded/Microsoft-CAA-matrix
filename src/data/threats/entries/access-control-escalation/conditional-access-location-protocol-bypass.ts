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
      source: 'Entra ID SigninLogs',
      artifact: "A successful sign-in from an IP within a trusted/named location range, for an account whose normal behavior doesn't otherwise match that location",
    },
    {
      source: 'Entra ID Named Locations configuration',
      artifact: "The actual configured IP ranges for each trusted location — verify they're still accurate and not broader than intended, such as an entire cloud provider's block instead of one office's static IP",
    },
    {
      source: 'Entra ID SigninLogs',
      artifact: 'IPv6 sign-ins where the corresponding policy or named location was only ever configured with IPv4 ranges — a protocol-family gap rather than an IP-range gap',
    },
    {
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

  runbook: {
    triage: [
      'Verify the actual configured IP ranges for each named location against what they are supposed to represent.',
      'Check for IPv6 coverage gaps across affected policies.',
      'Run IP intelligence on any suspicious trusted-location sign-in to check for VPS/hosting ranges masquerading as trusted infrastructure.',
      'Identify which policies and resources were actually reachable through the bypass.',
    ],
    contain: [
      'Remove or narrow the overly-broad named location range.',
      'Add explicit IPv6 blocking or coverage to affected CA policies.',
      'Revoke sessions relying on the bypass.',
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
