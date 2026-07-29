import type { ThreatEntry } from '../../../../types/threat'

const entry: ThreatEntry = {
  id: 'subdomain-custom-domain-hijacking',
  title: 'Subdomain / Custom Domain Hijacking',
  domain: 'persistence-pivoting',
  category: 'Initial Access / Persistence',
  severity: 'medium',
  status: 'complete',
  shortDesc: 'Taking over an unverified custom domain or an orphaned CNAME record still pointing at a decommissioned Azure resource.',
  description:
    'When an Azure resource with a custom domain is deleted without first removing the DNS CNAME record pointing to it, that dangling record becomes claimable by anyone who provisions a new resource with the matching name — a well-known class of subdomain takeover. This can also apply to custom domains added to a tenant but never fully verified, which can sometimes be claimed by another party who completes verification first.',

  forensicArtifacts: [
    {
      source: 'DNS records',
      artifact: 'A CNAME record still pointing to a decommissioned Azure resource that no longer exists but has not been cleaned up',
    },
    {
      source: 'Entra ID Custom domain names',
      artifact: 'Domains added to the tenant but never completed DNS verification — an unverified domain remains claimable by another party who completes verification first',
    },
    {
      source: 'Certificate Transparency logs',
      artifact: "A new TLS certificate issued for the organization's subdomain by a party unaffiliated with the organization — often the first externally-visible sign a takeover has occurred",
    },
    {
      source: 'Web traffic / DNS query logs',
      artifact: 'Traffic to the affected subdomain being served by unexpected, non-organizational infrastructure',
    },
    {
      source: 'Entra ID AuditLogs',
      artifact: 'Domain verification or federation configuration changes on a custom domain, if the takeover was leveraged toward tenant-level impact rather than just the subdomain itself',
    },
  ],

  telemetry: {
    correlationMarkers: [
      'This vulnerability class exists entirely outside Entra ID/M365 telemetry until and unless it is leveraged toward a tenant-level action — DNS hygiene is the actual preventive control, not log monitoring.',
      'Certificate Transparency logs are a genuinely useful, free, external early-warning source for this specific class of issue, since anyone claiming a dangling subdomain typically needs a certificate for it.',
      'An unverified custom domain sitting in a tenant\'s domain list indefinitely is a specific, checkable configuration state worth periodic review, distinct from the DNS-dangling-record variant.',
    ],
  },

  mitre: [{ id: 'T1583.001', name: 'Acquire Infrastructure: Domains', tactic: 'Resource Development' }],

  kql: {
    sentinel: {
      triage: {
        title: 'Domain verification and federation configuration changes',
        description: 'If the takeover was leveraged toward domain verification or federation changes within the tenant, that step shows up here — but the initial DNS-level takeover itself is invisible to Entra ID telemetry.',
        query: `AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName has_any ("Verify domain", "Add domain", "Set domain authentication")
| project TimeGenerated, InitiatedBy, TargetResources, Result
| order by TimeGenerated desc`,
      },
    },
    defender: {
      triage: {
        title: 'Domain configuration activity',
        query: `CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType has_any ("Verify domain", "Add domain")
| project Timestamp, AccountDisplayName, ActionType, RawEventData
| order by Timestamp desc`,
      },
    },
  },

  runbook: {
    triage: [
      'Audit DNS records for CNAMEs pointing to deprovisioned Azure resources.',
      "Review the tenant's custom domain list for any unverified entries.",
      'Check Certificate Transparency logs for unexpected certificates on organizational subdomains.',
    ],
    contain: [
      'Remove the dangling DNS record immediately, or reclaim the resource name if still available.',
      "Remove any unverified custom domain that's no longer needed.",
    ],
    investigate: [
      'Determine whether the subdomain was actually claimed and used maliciously, versus just theoretically vulnerable.',
      'Assess what content/functionality was served from the hijacked subdomain if takeover occurred.',
      'Check whether it was used for phishing (a trusted-looking subdomain) or any tenant-level action.',
    ],
    recover: [
      'Implement a decommissioning checklist that includes DNS record cleanup as a mandatory step.',
      'Periodically audit DNS records against active Azure resources.',
      'Monitor Certificate Transparency logs for organizational domains as an ongoing external-facing detection.',
      'Remove unverified custom domains from the tenant promptly rather than leaving them indefinitely.',
    ],
  },
}

export default entry
