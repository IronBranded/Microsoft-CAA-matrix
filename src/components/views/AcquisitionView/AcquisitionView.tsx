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
  const sorted = [...logSources].sort((a, b) => compareSeverity(a.priority, b.priority))

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
              <tr key={source.id}>
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
