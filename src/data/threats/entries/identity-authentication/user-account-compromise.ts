import type { ThreatEntry } from '../../../../types/threat'

const entry: ThreatEntry = {
  id: 'user-account-compromise',
  title: 'User Account Compromise',
  domain: 'identity-authentication',
  category: 'Initial Access / Credential Access',
  severity: 'high',
  status: 'complete',
  shortDesc: 'Direct account takeover via credential stuffing, brute force, or password spraying against Entra ID sign-in endpoints.',
  description:
    "Attackers use lists of previously breached credentials (credential stuffing), automated guessing (brute force), or low-and-slow attempts across many accounts with common passwords (password spraying) to gain direct access to a user's account. Because these attacks target the standard sign-in flow rather than exploiting a specific vulnerability, they're often only visible through sign-in volume, failure-rate, and geographic/velocity anomalies rather than any single distinguishing signal.",

  forensicArtifacts: [
    {
      source: 'Entra ID SigninLogs',
      artifact: 'A high volume of failed sign-ins for a single account (brute force) or many accounts from a single source (password spray), followed by an eventual success',
    },
    {
      source: 'Entra ID SigninLogs',
      artifact:
        "AADSTS50126 (invalid username or password) or AADSTS50053 (account locked) error codes clustering around the attack window. Note that Smart Lockout, on by default, tracks familiar vs. unfamiliar location/device separately — an attacker spraying from consistent infrastructure can trigger lockout faster than the raw failure count suggests, while a spray rotating through many source IPs/proxies can partially evade it by never looking 'familiar enough' to lock in the way a single persistent attacker would. The pattern of AADSTS50053 events (or their absence) says as much about the attacker's infrastructure discipline as it does about the account itself.",
    },
    {
      source: 'Entra ID Identity Protection',
      artifact: "'Password spray' risk detection — a purpose-built Identity Protection signal for exactly this pattern",
    },
    {
      source: 'Entra ID SigninLogs',
      artifact: "The eventual successful sign-in's IP/device/location compared against the account's historical baseline — attack infrastructure rarely matches",
    },
    {
      source: 'Entra ID AuditLogs',
      artifact: 'Changes made immediately after a successful sign-in (MFA registration, app consent) — the first few minutes after a brute-force success are usually spent establishing persistence',
    },
  ],

  telemetry: {
    relevantErrorCodes: [
      {
        code: 'AADSTS50126',
        type: 'Sign-in Failure',
        description: 'Invalid username or password.',
        dfirValue: 'A high-volume spike, especially spread across many distinct accounts from one source, is the raw signal both brute force and spray detections key off.',
      },
      {
        code: 'AADSTS50053',
        type: 'Account Lockout',
        description: 'The account is locked because the user tried to sign in too many times with an incorrect password.',
        dfirValue: 'Confirms smart lockout is engaging, but also confirms an active attack is in progress against those specific accounts.',
      },
    ],
    correlationMarkers: [
      'Password spray shows low attempts-per-account but high distinct-account count from one source; brute force shows the inverse — many attempts against one account. Distinguishing the two shapes the response.',
      'IPAddress and UserAgent consistency across many different targeted accounts in a short window is the fingerprint of a single automated tool, not many separate legitimate login attempts.',
      'Correlate any eventual success against what that specific account did immediately afterward — the attack itself is rarely the objective, what happens next is.',
    ],
  },

  mitre: [
    { id: 'T1110.003', name: 'Brute Force: Password Spraying', tactic: 'Credential Access' },
    { id: 'T1110.004', name: 'Brute Force: Credential Stuffing', tactic: 'Credential Access' },
  ],

  atrm: [{ id: 'AZT202', name: 'Password Spraying', tactic: 'Initial Access' }],

  kql: {
    sentinel: {
      triage: {
        title: 'Password spray shape — many accounts, one source',
        query: `SigninLogs
| where TimeGenerated > ago(1d)
| where ResultType != "0"
| summarize FailedAccounts = dcount(UserPrincipalName), AttemptCount = count() by IPAddress, bin(TimeGenerated, 1h)
| where FailedAccounts > 10 and AttemptCount < (FailedAccounts * 3)
| order by FailedAccounts desc`,
      },
      investigate: {
        title: 'Brute force shape — many attempts, one account',
        query: `SigninLogs
| where TimeGenerated > ago(1d)
| where ResultType != "0"
| summarize AttemptCount = count(), DistinctIPs = dcount(IPAddress) by UserPrincipalName, bin(TimeGenerated, 1h)
| where AttemptCount > 20
| order by AttemptCount desc`,
      },
    },
    defender: {
      triage: {
        title: 'Failed sign-in volume by source',
        query: `CloudAppEvents
| where Timestamp > ago(1d)
| where ActionType has "Sign-in activity"
| summarize FailedAccounts = dcount(AccountDisplayName), AttemptCount = count() by IPAddress, bin(Timestamp, 1h)
| where FailedAccounts > 10
| order by FailedAccounts desc`,
      },
    },
  },

  runbook: {
    triage: [
      'Identify the attack shape — spray versus brute force — and the full list of targeted accounts.',
      'Check for any account with a successful sign-in amid the failures; that account is the real compromise.',
      'Review Identity Protection risk detections for corroborating signals.',
      "Check whether legacy authentication was involved, since it historically bypasses some of the same protections modern auth gets.",
    ],
    contain: [
      'Block the source IP at the network/CA layer.',
      'Force a password reset for any account with a successful sign-in in the attack window.',
      'Confirm smart lockout is active and functioning as expected.',
      'Require MFA re-registration for compromised accounts from a verified, known-good session.',
    ],
    investigate: [
      'Determine what the compromised account(s) did post-compromise.',
      'Check whether the attack pattern suggests a known breached-credential list (common passwords repeated across many accounts) versus targeted guessing.',
      'Review whether legacy authentication was used as the delivery mechanism.',
      'Check for persistence set during the compromised window — new MFA methods, forwarding rules, app consents.',
    ],
    recover: [
      "Enforce banned/weak password lists via Entra ID Password Protection.",
      'Ensure MFA is required tenant-wide with no unmonitored exceptions.',
      'Tune Conditional Access sign-in risk policies to automatically challenge or block on high risk.',
      'Block legacy authentication tenant-wide, since it does not receive the same smart-lockout and Conditional Access protections as modern auth.',
    ],
  },
}

export default entry
