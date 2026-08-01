import { useEffect } from 'react'
import { useQueryParams } from '@/lib/router'
import { useDocumentTitle } from '@/lib/useDocumentTitle'
import { logSources } from '@/data/logSources'
import { compareSeverity } from '@/lib/severity'
import PriorityBadge from '@/components/common/PriorityBadge/PriorityBadge'
import styles from './AcquisitionView.module.css'

/**
 * The Artifact Acquisition Guide — what most threat maps skip: whether you
 * can actually collect the evidence a given entry asks for. The 58 threat
 * entries assume their forensic artifacts exist; this view is the reality
 * check underneath that assumption, license tier by license tier.
 */
export default function AcquisitionView() {
  useDocumentTitle('Acquisition Guide')
  const queryParams = useQueryParams()
  const highlightId = queryParams.get('highlight')
  const sorted = [...logSources].sort((a, b) => compareSeverity(a.priority, b.priority))

  useEffect(() => {
    if (!highlightId) return
    // Deferred a tick so the row exists in the DOM before we try to scroll
    // to it — this view can itself still be settling right after navigation.
    const t = setTimeout(() => {
      document.getElementById(highlightId)?.scrollIntoView({ behavior: 'smooth', block: 'center' })
    }, 50)
    return () => clearTimeout(t)
  }, [highlightId])

  return (
    <div className={styles.view}>
      <div className={styles.viewHead}>
        <h1 className={styles.heading}>Artifact Acquisition Guide</h1>
        <p className={styles.focus}>
          {sorted.length} log sources — what most threat maps skip entirely: whether you can actually collect the
          evidence, given your licensing
        </p>
      </div>

      <div className={styles.tableWrap}>
        <table className={styles.table}>
          <thead>
            <tr>
              <th className={styles.priorityCol}>Priority</th>
              <th className={styles.sourceCol}>Log Source</th>
              <th>License Requirement</th>
            </tr>
          </thead>
          <tbody>
            {sorted.map((source) => (
              <tr key={source.id} id={source.id} data-highlighted={source.id === highlightId}>
                <td className={styles.priorityCol}>
                  <PriorityBadge priority={source.priority} />
                </td>
                <td className={styles.sourceCol}>{source.name}</td>
                <td>
                  <div className={styles.requirement}>{source.licenseRequirement}</div>
                  {source.notes && <div className={styles.notes}>{source.notes}</div>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
