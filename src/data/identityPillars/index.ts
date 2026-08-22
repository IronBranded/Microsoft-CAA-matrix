import { IdentityPillarListSchema, type IdentityPillar } from '../../types/identityPillar'

const rawPillars: IdentityPillar[] = [
  {
    id: 'interactive',
    name: 'Interactive',
    whatItIs:
      'A human is physically present at the moment of sign-in, actively supplying a factor such as a password, an MFA approval, a touched security key, or a face or fingerprint scan.',
    howItWorks:
      "The client redirects to Entra ID's own sign-in page. The user completes primary authentication and any required step-up, and a token comes back to whichever app asked for it.",
    securityContext:
      "The richest signal Entra ID collects, including risk scoring, MFA method, and device state. It's also the most heavily targeted surface, because it's the one a human can be phished, fatigued, or talked into approving.",
    relatedDomain: 'identity-authentication',
    domainTagLabel: 'Identity & Authentication',
  },
  {
    id: 'non-interactive',
    name: 'Non-interactive',
    whatItIs:
      "A sign-in performed on a user's behalf by a client that already holds a valid token. There's no prompt, no factor, nothing for a human to do at that moment.",
    howItWorks:
      'The client silently trades a refresh token for a new access token. This happens constantly and invisibly, whether it\'s Outlook renewing its session, a phone checking in, or one app hopping to another via SSO.',
    securityContext:
      "Exactly what token theft and PRT abuse exploit. Because it inherits an earlier sign-in's trust without repeating MFA, a stolen refresh token or PRT lets an attacker keep this stream running indefinitely.",
    relatedDomain: 'identity-authentication',
    domainTagLabel: 'Token & Session Theft',
  },
  {
    id: 'service-principal',
    name: 'Service Principal',
    whatItIs:
      "The identity of an application itself, not a person. It's the tenant-local presence of an app registration, authenticating with a credential the app holds directly.",
    howItWorks:
      'The app presents its own client secret, certificate, or federated credential to the token endpoint. There\'s no browser, no MFA prompt, no human involved, ever, by design.',
    securityContext:
      'Often holds more standing privilege than any human admin, rarely sits behind Conditional Access the same way a person does, and a leaked secret keeps working until someone notices and rotates it.',
    relatedDomain: 'app-workload-identity',
    domainTagLabel: 'App & Workload Identity',
  },
  {
    id: 'managed-identity',
    name: 'Managed Identity',
    whatItIs:
      'A special-case service principal Azure creates and rotates automatically for one specific resource, such as a VM or a Function App. No one ever generates, stores, or sees the credential.',
    howItWorks:
      "The resource asks the Instance Metadata Service, locally, and Azure hands back a token. Nothing is ever written down, so there's nothing to leak in the usual sense.",
    securityContext:
      "The inversion of the other three. The attack isn't stealing a credential at all. It's getting any code execution on the resource and simply asking for the token that resource was always entitled to.",
    relatedDomain: 'azure-infrastructure-compute',
    domainTagLabel: 'Azure Infrastructure',
  },
]

export const identityPillars: IdentityPillar[] = IdentityPillarListSchema.parse(rawPillars)
