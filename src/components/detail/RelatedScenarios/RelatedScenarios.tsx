import type { ThreatEntry } from '@/types/threat'
import ThreatCard from '@/components/home/ThreatCard/ThreatCard'
import styles from './RelatedScenarios.module.css'

interface RelatedScenariosProps {
  threat: ThreatEntry
  allThreats: ThreatEntry[]
}

const MAX_RELATED = 4

/**
 * Relatedness is scored, not filtered by a single rule. A shared MITRE
 * technique is a much stronger signal than merely sharing a domain (a
 * domain holds up to 12 otherwise-unrelated scenarios), so technique
 * overlap is weighted well above a bare domain match rather than treated
 * as an equal, separate tier.
 */
function relatedScore(current: ThreatEntry, candidate: ThreatEntry): number {
  const currentTechniques = new Set((current.mitre ?? []).map((m) => m.id))
  const sharedTechniques = (candidate.mitre ?? []).filter((m) => currentTechniques.has(m.id)).length
  const sameDomain = candidate.domain === current.domain ? 1 : 0
  return sharedTechniques * 3 + sameDomain
}

export default function RelatedScenarios({ threat, allThreats }: RelatedScenariosProps) {
  const related = allThreats
    .filter((t) => t.id !== threat.id)
    .map((t) => ({ entry: t, score: relatedScore(threat, t) }))
    .filter((r) => r.score > 0)
    .sort((a, b) => b.score - a.score)
    .slice(0, MAX_RELATED)
    .map((r) => r.entry)

  if (related.length === 0) {
    return null
  }

  return (
    <section className={styles.wrap} aria-label="Related scenarios">
      <h2 className={styles.label}>§ Related Scenarios</h2>
      <div className={styles.grid}>
        {related.map((t) => (
          <ThreatCard key={t.id} threat={t} />
        ))}
      </div>
    </section>
  )
}
