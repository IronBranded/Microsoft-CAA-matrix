import { SEVERITY_LABEL } from '@/lib/severity'
import type { Severity } from '@/types/threat'
import styles from './SeverityBadge.module.css'

interface SeverityBadgeProps {
  severity: Severity
  size?: 'sm' | 'md'
}

export default function SeverityBadge({ severity, size = 'md' }: SeverityBadgeProps) {
  return (
    <span className={styles.badge} data-severity={severity} data-size={size}>
      {SEVERITY_LABEL[severity]}
    </span>
  )
}
