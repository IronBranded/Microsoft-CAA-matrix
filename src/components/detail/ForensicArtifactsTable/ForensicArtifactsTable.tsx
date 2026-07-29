import type { ForensicArtifact } from '@/types/threat'
import styles from './ForensicArtifactsTable.module.css'

interface ForensicArtifactsTableProps {
  artifacts: ForensicArtifact[]
}

export default function ForensicArtifactsTable({ artifacts }: ForensicArtifactsTableProps) {
  return (
    <div className={styles.tableWrap}>
      <table className={styles.table}>
        <thead>
          <tr>
            <th className={styles.sourceCol}>Source</th>
            <th>Artifact</th>
          </tr>
        </thead>
        <tbody>
          {artifacts.map((a, i) => (
            <tr key={i}>
              <td className={styles.sourceCol}>{a.source}</td>
              <td className={styles.artifactCell}>{a.artifact}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
