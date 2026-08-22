import { Link } from '@/lib/router'
import { getThreatById } from '@/data/threats'
import { useThreats } from '@/lib/useThreats'
import { useDocumentTitle } from '@/lib/useDocumentTitle'
import { DOMAIN_META } from '@/types/threat'
import SeverityBadge from '@/components/common/SeverityBadge/SeverityBadge'
import LoadingState from '@/components/common/LoadingState/LoadingState'
import FrameworkMappings from '@/components/detail/FrameworkMappings/FrameworkMappings'
import ForensicArtifactsTable from '@/components/detail/ForensicArtifactsTable/ForensicArtifactsTable'
import TelemetryPanel from '@/components/detail/TelemetryPanel/TelemetryPanel'
import KqlExplorer from '@/components/detail/KqlExplorer/KqlExplorer'
import RunbookPanel from '@/components/detail/RunbookPanel/RunbookPanel'
import SectionNav from '@/components/detail/SectionNav/SectionNav'
import RelatedScenarios from '@/components/detail/RelatedScenarios/RelatedScenarios'
import NotFoundView from '@/components/views/NotFoundView/NotFoundView'
import styles from './ThreatDetailView.module.css'

interface ThreatDetailViewProps {
  id: string
}

export default function ThreatDetailView({ id }: ThreatDetailViewProps) {
  const { threats, loading } = useThreats()
  const threat = getThreatById(threats, id)
  useDocumentTitle(threat?.title)

  if (loading) {
    return <LoadingState label="Loading scenario…" />
  }

  if (!threat) {
    return <NotFoundView />
  }

  const domainMeta = DOMAIN_META[threat.domain]
  const hasArtifacts = Boolean(threat.forensicArtifacts && threat.forensicArtifacts.length > 0)
  const hasTelemetry = Boolean(threat.telemetry)
  const hasKql = Boolean(threat.kql && (threat.kql.sentinel || threat.kql.defender))
  const hasRunbook = Boolean(threat.runbook)
  const hasDetail = hasArtifacts || hasTelemetry || hasKql || hasRunbook

  const sections = [
    hasArtifacts && { id: 'artifacts', label: 'Artifacts' },
    hasTelemetry && { id: 'telemetry', label: 'Telemetry' },
    hasKql && { id: 'kql', label: 'Detection' },
    hasRunbook && { id: 'runbook', label: 'Runbook' },
  ].filter((s): s is { id: string; label: string } => Boolean(s))

  return (
    <article className={styles.view}>
      <nav className={styles.breadcrumb} aria-label="Breadcrumb">
        <Link to="/">All Domains</Link>
        <span className={styles.crumbSep} aria-hidden="true">/</span>
        <Link to={`/domain/${threat.domain}`}>{domainMeta.label}</Link>
        <span className={styles.crumbSep} aria-hidden="true">/</span>
        <span className={styles.crumbCurrent} aria-current="page">{threat.title}</span>
      </nav>

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

      <SectionNav sections={sections} />

      {hasArtifacts && (
        <section id="artifacts" className={styles.section}>
          <h2 className={styles.sectionLabel}>§ Forensic Artifacts</h2>
          <ForensicArtifactsTable artifacts={threat.forensicArtifacts!} />
        </section>
      )}

      {hasTelemetry && (
        <section id="telemetry" className={styles.section}>
          <h2 className={styles.sectionLabel}>§ Telemetry</h2>
          <TelemetryPanel telemetry={threat.telemetry!} />
        </section>
      )}

      {hasKql && (
        <section id="kql" className={styles.section}>
          <h2 className={styles.sectionLabel}>§ Detection — KQL</h2>
          <KqlExplorer kql={threat.kql!} />
        </section>
      )}

      {hasRunbook && (
        <section id="runbook" className={styles.section}>
          <h2 className={styles.sectionLabel}>§ Response Runbook</h2>
          <RunbookPanel runbook={threat.runbook!} threatId={threat.id} />
        </section>
      )}

      <RelatedScenarios threat={threat} allThreats={threats} />
    </article>
  )
}
