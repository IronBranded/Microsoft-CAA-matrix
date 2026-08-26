import type { AuthFlow } from '@/types/threat'
import styles from './AuthFlowPanel.module.css'

interface AuthFlowPanelProps {
  authFlow: AuthFlow
}

const PATTERN_LABEL: Record<AuthFlow['pattern'], string> = {
  sequence: 'Ordered sequence',
  cluster: 'Code cluster',
}

/**
 * 'sequence' renders as a connected timeline (order is load-bearing).
 * 'cluster' renders as unconnected cards (codes co-occur; order isn't
 * meaningful) — same data shape, deliberately different visual treatment
 * driven off `data-pattern` so the two aren't visually confusable.
 */
export default function AuthFlowPanel({ authFlow }: AuthFlowPanelProps) {
  const { pattern, narrative, steps, distinguishingNotes } = authFlow

  return (
    <div className={styles.wrap}>
      <div className={styles.header}>
        <span className={styles.patternBadge} data-pattern={pattern}>
          {PATTERN_LABEL[pattern]}
        </span>
        <p className={styles.narrative}>{narrative}</p>
      </div>

      <ul className={styles.steps} data-pattern={pattern}>
        {steps.map((step, i) => (
          <li key={`${step.code}-${i}`} className={styles.step}>
            <span className={styles.stepCode}>{step.code}</span>
            <div className={styles.stepBody}>
              <span className={styles.stepLabel}>{step.label}</span>
              {step.detail && <p className={styles.stepDetail}>{step.detail}</p>}
            </div>
          </li>
        ))}
      </ul>

      {distinguishingNotes && (
        <div className={styles.distinguish}>
          <div className={styles.blockLabel}>Distinguishing From Other Scenarios</div>
          <p>{distinguishingNotes}</p>
        </div>
      )}
    </div>
  )
}
