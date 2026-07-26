/**
 * Best-effort outbound links for framework mappings. Both MITRE ATT&CK and
 * the Azure Threat Research Matrix (ATRM) publish techniques/sub-techniques
 * at predictable URL shapes; these helpers construct them from the id and
 * tactic already on the mapping rather than hardcoding a URL per entry.
 */

export function mitreUrl(id: string): string {
  const [base, sub] = id.split('.')
  return sub
    ? `https://attack.mitre.org/techniques/${base}/${sub}/`
    : `https://attack.mitre.org/techniques/${base}/`
}

export function atrmUrl(id: string, tactic: string): string {
  const tacticSlug = tactic.replace(/[^a-zA-Z]/g, '')
  const parentId = id.split('.')[0]
  const urlId = id.replace('.', '-')
  return `https://microsoft.github.io/Azure-Threat-Research-Matrix/${tacticSlug}/${parentId}/${urlId}`
}
