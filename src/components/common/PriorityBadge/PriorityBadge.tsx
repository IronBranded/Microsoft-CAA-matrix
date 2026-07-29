import type { AcquisitionPriority } from '@/types/logSource'
// Reuses SeverityBadge's stylesheet directly rather than duplicating it —
// the visual scale (critical/high/medium/low → red/orange/yellow/green) is
// identical, only what the color represents differs. The data-severity
// attribute below is just keying into those existing CSS selectors; the
// component's own prop name stays "priority" so callers aren't misled into
// thinking this measures the same thing as a threat's severity.
import styles from '@/components/common/SeverityBadge/SeverityBadge.module.css'

const PRIORITY_LABEL: Record<AcquisitionPriority, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
}

interface PriorityBadgeProps {
  priority: AcquisitionPriority
  size?: 'sm' | 'md'
}

export default function PriorityBadge({ priority, size = 'md' }: PriorityBadgeProps) {
  return (
    <span className={styles.badge} data-severity={priority} data-size={size}>
      {PRIORITY_LABEL[priority]}
    </span>
  )
}
