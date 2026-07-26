import { useState } from 'react'
import type { Runbook } from '@/types/threat'
import styles from './RunbookPanel.module.css'

interface RunbookPanelProps {
  runbook: Runbook
}

type Phase = 'triage' | 'contain' | 'investigate' | 'recover'
const PHASES: Phase[] = ['triage', 'contain', 'investigate', 'recover']
const PHASE_LABEL: Record<Phase, string> = {
  triage: 'Triage',
  contain: 'Contain',
  investigate: 'Investigate',
  recover: 'Recover',
}

export default function RunbookPanel({ runbook }: RunbookPanelProps) {
  const availablePhases = PHASES.filter((p) => {
    const steps = runbook[p]
    return steps && steps.length > 0
  })
  const [phase, setPhase] = useState<Phase | undefined>(availablePhases[0])

  if (!phase) {
    return null
  }

  const steps = runbook[phase] ?? []

  return (
    <div className={styles.wrap}>
      <div className={styles.phaseTabs}>
        {availablePhases.map((p) => (
          <button
            key={p}
            type="button"
            className={styles.phaseTab}
            data-active={phase === p}
            data-phase={p}
            onClick={() => setPhase(p)}
          >
            {PHASE_LABEL[p]}
          </button>
        ))}
      </div>

      <ol className={styles.steps}>
        {steps.map((step, i) => (
          <li key={i} className={styles.step}>
            <span className={styles.stepIndex}>{String(i + 1).padStart(2, '0')}</span>
            <span className={styles.stepText}>{stripLeadingNumber(step)}</span>
          </li>
        ))}
      </ol>
    </div>
  )
}

/** Runbook steps are sometimes authored with a leading "1. " of their own —
 *  strip it since the list already numbers itself, to avoid a double index. */
function stripLeadingNumber(text: string): string {
  return text.replace(/^\d+\.\s*/, '')
}
