import styles from './LoadingState.module.css'

interface LoadingStateProps {
  label?: string
}

/**
 * A signature moment rather than bare "Loading…" text — a system-status
 * scan motif in the warm --flag accent, reserved for exactly this purpose
 * so it reads as distinct from the cyan-dominant rest of the interface.
 */
export default function LoadingState({ label = 'Loading…' }: LoadingStateProps) {
  return (
    <div className={styles.wrap} role="status" aria-live="polite">
      <span className={styles.eyebrow}>§ Initializing</span>
      <div className={styles.track}>
        <div className={styles.sweep} />
      </div>
      <p className={styles.label}>{label}</p>
    </div>
  )
}
