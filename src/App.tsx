import { Suspense, lazy } from 'react'
import { useRoute } from '@/lib/router'
import { DomainSchema } from '@/types/threat'
import AppShell from '@/components/layout/AppShell/AppShell'
import CatalogView from '@/components/views/CatalogView/CatalogView'
import NotFoundView from '@/components/views/NotFoundView/NotFoundView'

// Lazy-loaded as its own chunk: ThreatDetailView pulls in five detail-only
// sub-components (KqlExplorer, RunbookPanel, ForensicArtifactsTable,
// TelemetryPanel, FrameworkMappings) that CatalogView — the default,
// first-loaded view — never needs.
const ThreatDetailView = lazy(() => import('@/components/views/ThreatDetailView/ThreatDetailView'))
const AcquisitionView = lazy(() => import('@/components/views/AcquisitionView/AcquisitionView'))
const IdentityPillarsView = lazy(() => import('@/components/views/IdentityPillarsView/IdentityPillarsView'))

export default function App() {
  const { segments } = useRoute()

  function renderPage() {
    if (segments.length === 0) {
      return <CatalogView />
    }
    if (segments[0] === 'domain' && segments[1]) {
      const parsed = DomainSchema.safeParse(segments[1])
      return parsed.success ? <CatalogView domain={parsed.data} /> : <NotFoundView />
    }
    if (segments[0] === 'threat' && segments[1]) {
      return (
        <Suspense fallback={null}>
          <ThreatDetailView id={segments[1]} />
        </Suspense>
      )
    }
    if (segments[0] === 'acquisition') {
      return (
        <Suspense fallback={null}>
          <AcquisitionView />
        </Suspense>
      )
    }
    if (segments[0] === 'identity-pillars') {
      return (
        <Suspense fallback={null}>
          <IdentityPillarsView />
        </Suspense>
      )
    }
    return <NotFoundView />
  }

  return <AppShell>{renderPage()}</AppShell>
}
