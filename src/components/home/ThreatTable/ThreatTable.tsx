import { useState } from 'react'
import { Link } from '@/lib/router'
import { DOMAIN_META, type ThreatEntry } from '@/types/threat'
import { compareSeverity, SEVERITY_LABEL } from '@/lib/severity'
import styles from './ThreatTable.module.css'

interface ThreatTableProps {
  threats: ThreatEntry[]
}

type SortKey = 'severity' | 'title' | 'domain'
type SortDirection = 'asc' | 'desc'

/**
 * A dense, sortable data table — structural inspiration from Cortex XDR's
 * endpoint management view, which presents its inventory as columns and
 * compact status chips rather than cards. An alternate view alongside the
 * card grid, not a replacement for it: the grid reads better for browsing,
 * this reads better for scanning all 58 at once or comparing across a
 * specific column.
 */
export default function ThreatTable({ threats }: ThreatTableProps) {
  const [sortKey, setSortKey] = useState<SortKey>('severity')
  const [sortDir, setSortDir] = useState<SortDirection>('asc')

  function toggleSort(key: SortKey) {
    if (key === sortKey) {
      setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'))
    } else {
      setSortKey(key)
      setSortDir('asc')
    }
  }

  const sorted = [...threats].sort((a, b) => {
    let cmp = 0
    switch (sortKey) {
      case 'severity':
        cmp = compareSeverity(a.severity, b.severity)
        break
      case 'title':
        cmp = a.title.localeCompare(b.title)
        break
      case 'domain':
        cmp = DOMAIN_META[a.domain].label.localeCompare(DOMAIN_META[b.domain].label)
        break
    }
    return sortDir === 'asc' ? cmp : -cmp
  })

  function headerProps(key: SortKey) {
    return {
      onClick: () => toggleSort(key),
      'data-sorted': sortKey === key ? sortDir : undefined,
      role: 'columnheader' as const,
      tabIndex: 0,
      onKeyDown: (e: React.KeyboardEvent) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault()
          toggleSort(key)
        }
      },
    }
  }

  return (
    <div className={styles.tableWrap}>
      <table className={styles.table}>
        <thead>
          <tr>
            <th className={styles.sortable} {...headerProps('severity')}>
              Severity
            </th>
            <th className={styles.sortable} {...headerProps('title')}>
              Scenario
            </th>
            <th className={styles.sortable} {...headerProps('domain')}>
              Domain
            </th>
            <th>Category</th>
            <th className={styles.centerCol}>Frameworks</th>
          </tr>
        </thead>
        <tbody>
          {sorted.map((threat) => {
            const frameworkCount = (threat.mitre?.length ?? 0) + (threat.atrm?.length ?? 0)
            return (
              <tr key={threat.id}>
                <td>
                  <span className={styles.sevChip} data-severity={threat.severity}>
                    <span className={styles.sevDot} data-severity={threat.severity} />
                    {SEVERITY_LABEL[threat.severity]}
                  </span>
                </td>
                <td className={styles.titleCell}>
                  <Link to={`/threat/${threat.id}`} className={styles.titleLink}>
                    {threat.title}
                  </Link>
                </td>
                <td className={styles.mutedCell}>{DOMAIN_META[threat.domain].label}</td>
                <td className={styles.mutedCell}>{threat.category}</td>
                <td className={styles.centerCol}>
                  <span className={styles.frameworkCount}>{frameworkCount || '—'}</span>
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}
