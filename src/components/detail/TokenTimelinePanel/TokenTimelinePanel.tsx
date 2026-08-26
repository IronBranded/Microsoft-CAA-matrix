import type { TokenTimeline } from '@/types/threat'
import styles from './TokenTimelinePanel.module.css'

interface TokenTimelinePanelProps {
  tokenTimeline: TokenTimeline
}

type DisplayField = { key: keyof Omit<TokenTimeline, 'otherContext'>; label: string }

const FIELDS: DisplayField[] = [
  { key: 'issuance', label: 'Issuance (iat)' },
  { key: 'expiration', label: 'Expiration (exp)' },
  { key: 'authInstant', label: 'Auth Instant (auth_time)' },
  { key: 'authMethods', label: 'Auth Methods (amr)' },
  { key: 'mfaInstant', label: 'MFA Timing' },
]

export default function TokenTimelinePanel({ tokenTimeline }: TokenTimelinePanelProps) {
  return (
    <div className={styles.wrap}>
      <dl className={styles.grid}>
        {FIELDS.map(({ key, label }) => (
          <div key={key} className={styles.field}>
            <dt className={styles.term}>{label}</dt>
            <dd className={styles.desc}>{tokenTimeline[key]}</dd>
          </div>
        ))}
      </dl>

      {tokenTimeline.otherContext && (
        <div className={styles.other}>
          <div className={styles.blockLabel}>Other Context</div>
          <p>{tokenTimeline.otherContext}</p>
        </div>
      )}
    </div>
  )
}
