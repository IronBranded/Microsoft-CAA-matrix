import { Link } from '@/lib/router'
import { getThreatById } from '@/data/threats'
import { useThreats } from '@/lib/useThreats'
import { DOMAIN_META } from '@/types/threat'
import SeverityBadge from '@/components/common/SeverityBadge/SeverityBadge'
import LoadingState from '@/components/common/LoadingState/LoadingState'
import FrameworkMappings from '@/components/detail/FrameworkMappings/FrameworkMappings'
import ForensicArtifactsTable from '@/components/detail/ForensicArtifactsTable/ForensicArtifactsTable'
import TelemetryPanel from '@/components/detail/TelemetryPanel/TelemetryPanel'
import KqlExplorer from '@/components/detail/KqlExplorer/KqlExplorer'
import RunbookPanel from '@/components/detail/RunbookPanel/RunbookPanel'
import NotFoundView from '@/components/views/NotFoundView/NotFoundView'
import styles from './ThreatDetailView.module.css'

interface ThreatDetailViewProps {
  id: string
}

export default function ThreatDetailView({ id }: ThreatDetailViewProps) {
  const { threats, loading } = useThreats()

  if (loading) {
    return <LoadingState label="Loading scenario…" />
  }

  const threat = getThreatById(threats, id)

  if (!threat) {
    return <NotFoundView />
  }

  const domainMeta = DOMAIN_META[threat.domain]
  const hasDetail = Boolean(
    (threat.forensicArtifacts && threat.forensicArtifacts.length > 0) ||
      threat.telemetry ||
      threat.kql?.sentinel ||
      threat.kql?.defender ||
      threat.runbook,
  )

  return (
    <article className={styles.view}>
      <Link to={`/domain/${threat.domain}`} className={styles.back}>
        ← {domainMeta.label}
      </Link>

      <header className={styles.header}>
        <div className={styles.headerTop}>
          <SeverityBadge severity={threat.severity} />
          <span className={styles.category}>{threat.category}</span>
        </div>
        <h1 className={styles.title}>{threat.title}</h1>
        <p className={styles.description}>{threat.description}</p>
        <FrameworkMappings mitre={threat.mitre} atrm={threat.atrm} />
      </header>

      {!hasDetail && (
        <div className={styles.stubNotice}>
          Full forensic write-up not yet published for this scenario — metadata only. See
          CONTRIBUTING.md if you&rsquo;d like to help complete it.
        </div>
      )}

      {threat.forensicArtifacts && threat.forensicArtifacts.length > 0 && (
        <section className={styles.section}>
          <h2 className={styles.sectionLabel}>§ Forensic Artifacts</h2>
          <ForensicArtifactsTable artifacts={threat.forensicArtifacts} />
        </section>
      )}

      {threat.telemetry && (
        <section className={styles.section}>
          <h2 className={styles.sectionLabel}>§ Telemetry</h2>
          <TelemetryPanel telemetry={threat.telemetry} />
        </section>
      )}

      {threat.kql && (threat.kql.sentinel || threat.kql.defender) && (
        <section className={styles.section}>
          <h2 className={styles.sectionLabel}>§ Detection — KQL</h2>
          <KqlExplorer kql={threat.kql} />
        </section>
      )}

      {threat.runbook && (
        <section className={styles.section}>
          <h2 className={styles.sectionLabel}>§ Response Runbook</h2>
          <RunbookPanel runbook={threat.runbook} />
        </section>
      )}
    </article>
  )
}
