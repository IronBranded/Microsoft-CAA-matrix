import { useRoute, useQueryParams, setQueryParams, navigate, Link } from '@/lib/router'
import { countByDomain } from '@/data/threats'
import { useThreats } from '@/lib/useThreats'
import { DOMAIN_META, ORDERED_DOMAINS, SEVERITIES, type Severity } from '@/types/threat'
import { parseSeverityParam } from '@/lib/filter'
import { SEVERITY_LABEL } from '@/lib/severity'
import styles from './Sidebar.module.css'

interface SidebarProps {
  mobileOpen: boolean
  onCloseMobile: () => void
}

export default function Sidebar({ mobileOpen, onCloseMobile }: SidebarProps) {
  const { segments } = useRoute()
  const queryParams = useQueryParams()
  const { threats } = useThreats()
  const counts = countByDomain(threats)
  const activeSeverities = parseSeverityParam(queryParams.get('severity'), SEVERITIES)

  const isCatalogRoute = segments.length === 0 || segments[0] === 'domain'
  const activeDomainSlug = segments[0] === 'domain' ? segments[1] : undefined
  const preservedQuery = isCatalogRoute ? queryParams.toString() : ''

  function toggleSeverity(sev: Severity) {
    const params = new URLSearchParams(preservedQuery)
    const next = new Set(activeSeverities)
    if (next.has(sev)) {
      next.delete(sev)
    } else {
      next.add(sev)
    }
    if (next.size > 0) {
      params.set('severity', Array.from(next).join(','))
    } else {
      params.delete('severity')
    }

    if (isCatalogRoute) {
      setQueryParams(params)
    } else {
      navigate('/', params.toString() || undefined)
    }
  }

  return (
    <>
      {mobileOpen && (
        <div className={styles.backdrop} onClick={onCloseMobile} aria-hidden="true" />
      )}
      <nav className={styles.sidebar} aria-label="Threat catalog filters" data-mobile-open={mobileOpen}>
        <button type="button" className={styles.closeBtn} onClick={onCloseMobile} aria-label="Close filters">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" aria-hidden="true">
            <path d="M6 6l12 12M18 6L6 18" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
          </svg>
        </button>

        <div className={styles.section}>
          <div className={styles.sectionLabel}>Domains</div>
          <Link
            to={preservedQuery ? `/?${preservedQuery}` : '/'}
            className={segments.length === 0 ? `${styles.domainLink} ${styles.active}` : styles.domainLink}
          >
            <span className={styles.domainIndex}>ALL</span>
            <span className={styles.domainLabel}>All domains</span>
            <span className={styles.domainCount}>
              {ORDERED_DOMAINS.reduce((sum, d) => sum + (counts[d] ?? 0), 0)}
            </span>
          </Link>

          {ORDERED_DOMAINS.map((slug) => {
            const meta = DOMAIN_META[slug]
            const href = preservedQuery ? `/domain/${slug}?${preservedQuery}` : `/domain/${slug}`
            return (
              <Link
                key={slug}
                to={href}
                className={activeDomainSlug === slug ? `${styles.domainLink} ${styles.active}` : styles.domainLink}
                title={meta.focus}
              >
                <span className={styles.domainIndex}>{String(meta.order).padStart(2, '0')}</span>
                <span className={styles.domainLabel}>{meta.label}</span>
                <span className={styles.domainCount}>{counts[slug] ?? 0}</span>
              </Link>
            )
          })}
        </div>

        <div className={styles.section}>
          <div className={styles.sectionLabel}>Severity</div>
          <div className={styles.severityGrid}>
            {SEVERITIES.map((sev) => (
              <button
                key={sev}
                type="button"
                className={styles.severityChip}
                data-severity={sev}
                data-active={activeSeverities.has(sev)}
                onClick={() => toggleSeverity(sev)}
                aria-pressed={activeSeverities.has(sev)}
              >
                {SEVERITY_LABEL[sev]}
              </button>
            ))}
          </div>
        </div>
      </nav>
    </>
  )
}
