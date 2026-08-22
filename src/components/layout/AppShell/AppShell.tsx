import { useState, type ReactNode } from 'react'
import { useRoute } from '@/lib/router'
import Header from '@/components/layout/Header/Header'
import Sidebar from '@/components/layout/Sidebar/Sidebar'
import styles from './AppShell.module.css'

interface AppShellProps {
  children: ReactNode
}

export default function AppShell({ children }: AppShellProps) {
  const { segments } = useRoute()
  const path = segments.join('/')
  const [mobileNavOpen, setMobileNavOpen] = useState(false)
  const [lastPath, setLastPath] = useState(path)

  // Closes the drawer whenever the route's path changes (e.g. picking a
  // domain) — but NOT on query-param-only changes like toggling a severity
  // chip, so multi-selecting severities doesn't slam the drawer shut after
  // every tap. Adjusting state during render (React's documented pattern
  // for "reset state when a prop changes") rather than an effect, since
  // setState synchronously inside an effect just to mirror a render-time
  // value is the cascading-render anti-pattern the hooks linter flags.
  if (path !== lastPath) {
    setLastPath(path)
    setMobileNavOpen(false)
  }

  return (
    <div className={styles.shell}>
      <Header onToggleMobileNav={() => setMobileNavOpen((v) => !v)} />
      <div className={styles.body}>
        <Sidebar mobileOpen={mobileNavOpen} onCloseMobile={() => setMobileNavOpen(false)} />
        <main className={styles.main}>{children}</main>
      </div>
    </div>
  )
}
