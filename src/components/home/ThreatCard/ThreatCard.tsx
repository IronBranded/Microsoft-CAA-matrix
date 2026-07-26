import { Link } from '@/lib/router'
import SeverityBadge from '@/components/common/SeverityBadge/SeverityBadge'
import { DOMAIN_META } from '@/types/threat'
import type { ThreatEntry } from '@/types/threat'
import styles from './ThreatCard.module.css'

interface ThreatCardProps {
  threat: ThreatEntry
}

export default function ThreatCard({ threat }: ThreatCardProps) {
  const domainMeta = DOMAIN_META[threat.domain]

  return (
    <Link to={`/threat/${threat.id}`} className={styles.card} data-severity={threat.severity}>
      <div className={styles.top}>
        <SeverityBadge severity={threat.severity} size="sm" />
        {threat.status === 'stub' && <span className={styles.stubTag}>Stub</span>}
      </div>
      <h3 className={styles.title}>{threat.title}</h3>
      <p className={styles.desc}>{threat.shortDesc}</p>
      <div className={styles.footer}>
        <span className={styles.domain}>{domainMeta.label}</span>
        <span className={styles.category}>{threat.category}</span>
      </div>
    </Link>
  )
}
