import { Link } from '@/lib/router'
import type { ForensicArtifact } from '@/types/threat'
import CopyButton from '@/components/common/CopyButton/CopyButton'
import styles from './ForensicArtifactsTable.module.css'

interface ForensicArtifactsTableProps {
  artifacts: ForensicArtifact[]
}

export default function ForensicArtifactsTable({ artifacts }: ForensicArtifactsTableProps) {
  const copyText = artifacts.map((a) => `Source: ${a.source}\nArtifact: ${a.artifact}`).join('\n\n')

  return (
    <div className={styles.wrap}>
      <div className={styles.copyRow}>
        <CopyButton text={copyText} />
      </div>
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
                <td className={styles.sourceCol}>
                  {a.source}
                  {a.logSourceId && (
                    <Link to={`/acquisition?highlight=${a.logSourceId}`} className={styles.acqLink}>
                      Acquisition Guide →
                    </Link>
                  )}
                </td>
                <td className={styles.artifactCell}>{a.artifact}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
