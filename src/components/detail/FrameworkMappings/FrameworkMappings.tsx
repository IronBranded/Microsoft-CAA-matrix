import type { FrameworkMapping } from '@/types/threat'
import { mitreUrl, atrmUrl } from '@/lib/frameworkLinks'
import styles from './FrameworkMappings.module.css'

interface FrameworkMappingsProps {
  mitre?: FrameworkMapping[]
  atrm?: FrameworkMapping[]
}

function ChipRow({
  label,
  items,
  hrefFor,
}: {
  label: string
  items: FrameworkMapping[]
  hrefFor: (item: FrameworkMapping) => string
}) {
  return (
    <div className={styles.row}>
      <span className={styles.rowLabel}>{label}</span>
      <div className={styles.chips}>
        {items.map((item) => (
          <a
            key={item.id}
            className={styles.chip}
            title={item.tactic}
            href={hrefFor(item)}
            target="_blank"
            rel="noreferrer"
          >
            <span className={styles.chipId}>{item.id}</span>
            <span className={styles.chipName}>{item.name}</span>
          </a>
        ))}
      </div>
    </div>
  )
}

export default function FrameworkMappings({ mitre, atrm }: FrameworkMappingsProps) {
  const hasMitre = mitre && mitre.length > 0
  const hasAtrm = atrm && atrm.length > 0

  if (!hasMitre && !hasAtrm) {
    return null
  }

  return (
    <div className={styles.wrap}>
      {hasMitre && (
        <ChipRow label="MITRE ATT&CK" items={mitre} hrefFor={(item) => mitreUrl(item.id)} />
      )}
      {hasAtrm && (
        <ChipRow label="ATRM" items={atrm} hrefFor={(item) => atrmUrl(item.id, item.tactic)} />
      )}
    </div>
  )
}
