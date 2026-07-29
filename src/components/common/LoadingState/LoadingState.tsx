import styles from './LoadingState.module.css'

interface LoadingStateProps {
  label?: string
}

/**
 * A restrained loading indicator — a simple rotating ring, the same pattern
 * GitHub, Linear, and most professional dashboards use, rather than a more
 * stylized effect. Enterprise-mature favors the boring, familiar choice here.
 */
export default function LoadingState({ label = 'Loading…' }: LoadingStateProps) {
  return (
    <div className={styles.wrap} role="status" aria-live="polite">
      <span className={styles.spinner} aria-hidden="true" />
      <p className={styles.label}>{label}</p>
    </div>
  )
}
