import type { ReactNode } from 'react'
import Header from '@/components/layout/Header/Header'
import Sidebar from '@/components/layout/Sidebar/Sidebar'
import styles from './AppShell.module.css'

interface AppShellProps {
  children: ReactNode
}

export default function AppShell({ children }: AppShellProps) {
  return (
    <div className={styles.shell}>
      <Header />
      <div className={styles.body}>
        <Sidebar />
        <main className={styles.main}>{children}</main>
      </div>
    </div>
  )
}
