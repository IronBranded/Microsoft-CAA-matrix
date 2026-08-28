import { useMemo, useState } from 'react'
import { useQueryParams, setQueryParams } from '@/lib/router'
import type { Runbook } from '@/types/threat'
import { getCheckedSteps, setStepChecked, clearPhaseProgress } from '@/lib/runbookProgress'
import CopyButton from '@/components/common/CopyButton/CopyButton'
import styles from './RunbookPanel.module.css'

interface RunbookPanelProps {
  runbook: Runbook
  threatId: string
}

type Phase = 'triage' | 'contain' | 'investigate' | 'recover'
const PHASES: Phase[] = ['triage', 'contain', 'investigate', 'recover']
const PHASE_LABEL: Record<Phase, string> = {
  triage: 'Triage',
  contain: 'Contain',
  investigate: 'Investigate',
  recover: 'Recover',
}

export default function RunbookPanel({ runbook, threatId }: RunbookPanelProps) {
  const queryParams = useQueryParams()
  const availablePhases = PHASES.filter((p) => {
    const steps = runbook[p]
    return steps && steps.length > 0
  })

  const requestedPhase = queryParams.get('phase') as Phase | null
  const phase = requestedPhase && availablePhases.includes(requestedPhase) ? requestedPhase : availablePhases[0]

  // Bumped after every localStorage write so the useMemo below re-reads —
  // checked state is derived from storage, not independently tracked, so
  // there's nothing to synchronize via effect.
  const [version, setVersion] = useState(0)

  const checked = useMemo(() => {
    if (!phase) return new Set<number>()
    return getCheckedSteps(threatId, phase)
    // version is intentionally a dependency purely to force recomputation
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [threatId, phase, version])

  if (!phase) {
    return null
  }

  const steps = runbook[phase] ?? []
  const allChecked = steps.length > 0 && checked.size === steps.length

  function changePhase(next: Phase) {
    const params = new URLSearchParams(queryParams)
    params.set('phase', next)
    setQueryParams(params)
  }

  function toggleStep(i: number) {
    if (!phase) return
    setStepChecked(threatId, phase, i, !checked.has(i))
    setVersion((v) => v + 1)
  }

  function resetPhase() {
    if (!phase) return
    clearPhaseProgress(threatId, phase)
    setVersion((v) => v + 1)
  }

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
            onClick={() => changePhase(p)}
          >
            {PHASE_LABEL[p]}
          </button>
        ))}
      </div>

      <div className={styles.progressRow}>
        <span className={styles.progressText}>
          {checked.size} / {steps.length} complete
        </span>
        <div className={styles.progressActions}>
          <CopyButton
            text={steps.map((s, i) => `[${checked.has(i) ? 'x' : ' '}] ${stripLeadingNumber(s)}`).join('\n')}
          />
          {checked.size > 0 && (
            <button type="button" className={styles.resetBtn} onClick={resetPhase}>
              Reset
            </button>
          )}
        </div>
      </div>

      <ol className={styles.steps} data-all-checked={allChecked}>
        {steps.map((step, i) => (
          <li key={i} className={styles.step}>
            <label className={styles.stepLabel}>
              <input
                type="checkbox"
                className={styles.checkbox}
                checked={checked.has(i)}
                onChange={() => toggleStep(i)}
              />
              <span className={styles.stepIndex}>{String(i + 1).padStart(2, '0')}</span>
              <span className={styles.stepText} data-checked={checked.has(i)}>
                {renderStepText(step)}
              </span>
            </label>
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

/** Steps often contain `backtick-wrapped` PowerShell cmdlets or KQL
 *  fragments — render those segments as styled inline code instead of
 *  showing literal backtick characters. Plain-text segments pass through
 *  unchanged, so steps with no backticks render exactly as before. */
function renderStepText(text: string) {
  const clean = stripLeadingNumber(text)
  const parts = clean.split(/(`[^`]+`)/g)
  return parts.map((part, i) =>
    part.startsWith('`') && part.endsWith('`') && part.length > 1 ? (
      <code key={i} className={styles.stepCode}>
        {part.slice(1, -1)}
      </code>
    ) : (
      part
    ),
  )
}
