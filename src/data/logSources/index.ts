import { LogSourceListSchema, type LogSource } from '@/types/logSource'

const rawLogSources: LogSource[] = [
  { id: 'unified-audit-log', name: 'Unified Audit Log (UAL)', priority: 'critical', licenseRequirement: 'E3 (180d) / E5 (1yr, 4 workloads only)' },
  { id: 'mail-items-accessed', name: 'MailItemsAccessed', priority: 'critical', licenseRequirement: 'E5 / Audit (Premium) only — not available on E3' },
  { id: 'sign-in-logs', name: 'Sign-in Logs (Interactive & Non-Interactive)', priority: 'critical', licenseRequirement: 'Free (7d) / P1 (30d) / P2 (30d)' },
  { id: 'entra-audit-logs', name: 'Entra ID Audit Logs', priority: 'high', licenseRequirement: 'Free (7d) / P1+P2 (30d)' },
  { id: 'mailbox-audit-log', name: 'Mailbox Audit Log', priority: 'high', licenseRequirement: 'All plans, default enabled' },
  { id: 'message-trace-log', name: 'Message Trace Log', priority: 'high', licenseRequirement: 'All plans — 10d real-time / 90d historical' },
  { id: 'graph-activity-logs', name: 'Microsoft Graph Activity Logs', priority: 'high', licenseRequirement: 'Requires Entra ID P1 or P2 — must enable via Diagnostic Settings' },
  { id: 'service-principal-signin-logs', name: 'Service Principal Sign-in Logs', priority: 'high', licenseRequirement: 'Requires Entra ID P1 or P2 — must enable via Diagnostic Settings' },
  { id: 'intune-audit-logs', name: 'Intune Audit Logs', priority: 'high', licenseRequirement: 'Any Intune license — requires Diagnostic Settings' },
  { id: 'azure-devops-audit-logs', name: 'Azure DevOps Audit Logs', priority: 'high', licenseRequirement: 'DevOps Basic — must enable in Org Settings' },
  { id: 'azure-activity-log', name: 'Azure Activity Log (AzureActivity)', priority: 'critical', licenseRequirement: 'Free, always generated — requires a Diagnostic Setting to reach a workspace' },
  { id: 'nsg-flow-logs', name: 'NSG Flow Logs', priority: 'high', licenseRequirement: 'Requires Network Watcher — consumption-based cost, not gated by M365/Entra licensing' },
  { id: 'managed-identity-signin-logs', name: 'Managed Identity Sign-in Logs (AADManagedIdentitySignInLogs)', priority: 'high', licenseRequirement: 'Requires Entra ID P1 or P2 — must enable via Diagnostic Settings' },
  { id: 'adfs-signin-logs', name: 'AD FS Sign-in Logs (ADFSSignInLogs)', priority: 'medium', licenseRequirement: 'Requires Microsoft Entra Connect Health for AD FS' },
]

export const logSources: LogSource[] = LogSourceListSchema.parse(rawLogSources)
