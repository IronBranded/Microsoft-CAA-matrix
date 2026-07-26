import type { Telemetry } from '@/types/threat'
import styles from './TelemetryPanel.module.css'

interface TelemetryPanelProps {
  telemetry: Telemetry
}

export default function TelemetryPanel({ telemetry }: TelemetryPanelProps) {
  const { authenticationProtocols, correlationMarkers, relevantErrorCodes } = telemetry

  return (
    <div className={styles.wrap}>
      {authenticationProtocols && authenticationProtocols.length > 0 && (
        <div className={styles.block}>
          <div className={styles.blockLabel}>Authentication Protocols</div>
          <div className={styles.protocolChips}>
            {authenticationProtocols.map((p) => (
              <span key={p} className={styles.protocolChip}>
                {p}
              </span>
            ))}
          </div>
        </div>
      )}

      {correlationMarkers && correlationMarkers.length > 0 && (
        <div className={styles.block}>
          <div className={styles.blockLabel}>Correlation Markers</div>
          <ul className={styles.markerList}>
            {correlationMarkers.map((marker, i) => (
              <li key={i}>{marker}</li>
            ))}
          </ul>
        </div>
      )}

      {relevantErrorCodes && relevantErrorCodes.length > 0 && (
        <div className={styles.block}>
          <div className={styles.blockLabel}>Relevant Error Codes</div>
          <div className={styles.tableWrap}>
            <table className={styles.table}>
              <thead>
                <tr>
                  <th>Code</th>
                  <th>Type</th>
                  <th>Description</th>
                  <th>DFIR Value</th>
                </tr>
              </thead>
              <tbody>
                {relevantErrorCodes.map((ec) => (
                  <tr key={ec.code}>
                    <td className={styles.codeCell}>{ec.code}</td>
                    <td>{ec.type}</td>
                    <td>{ec.description}</td>
                    <td>{ec.dfirValue}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}
