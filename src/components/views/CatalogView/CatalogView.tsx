import { useQueryParams } from '@/lib/router'
import { getThreatsByDomain } from '@/data/threats'
import { useThreats } from '@/lib/useThreats'
import { searchThreats, filterBySeverity, parseSeverityParam } from '@/lib/filter'
import { compareSeverity } from '@/lib/severity'
import { DOMAIN_META, SEVERITIES, type DomainSlug } from '@/types/threat'
import ThreatCard from '@/components/home/ThreatCard/ThreatCard'
import LoadingState from '@/components/common/LoadingState/LoadingState'
import styles from './CatalogView.module.css'

interface CatalogViewProps {
  domain?: DomainSlug
}

export default function CatalogView({ domain }: CatalogViewProps) {
  const queryParams = useQueryParams()
  const { threats: allThreats, loading } = useThreats()
  const query = queryParams.get('q') ?? ''
  const activeSeverities = parseSeverityParam(queryParams.get('severity'), SEVERITIES)

  const base = domain ? getThreatsByDomain(allThreats, domain) : allThreats
  const searched = searchThreats(base, query)
  const filtered = filterBySeverity(searched, activeSeverities)
  const sorted = [...filtered].sort(
    (a, b) => compareSeverity(a.severity, b.severity) || a.title.localeCompare(b.title),
  )

  const heading = domain ? DOMAIN_META[domain].label : 'All Domains'
  const focus = domain
    ? DOMAIN_META[domain].focus
    : loading
      ? 'Loading catalog…'
      : `${allThreats.length} scenarios across 8 operational domains`

  return (
    <div className={styles.view}>
      <div className={styles.head}>
        <h1 className={styles.heading}>{heading}</h1>
        <p className={styles.focus}>{focus}</p>
      </div>

      {loading ? (
        <LoadingState label="Loading scenarios…" />
      ) : sorted.length === 0 ? (
        <div className={styles.empty}>
          <p>No scenarios match the current filters.</p>
        </div>
      ) : (
        <div className={styles.grid}>
          {sorted.map((threat) => (
            <ThreatCard key={threat.id} threat={threat} />
          ))}
        </div>
      )}
    </div>
  )
}
