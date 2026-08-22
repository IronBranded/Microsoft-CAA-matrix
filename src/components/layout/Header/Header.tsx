import { useEffect, useRef, useState } from 'react'
import { useRoute, useQueryParams, setQueryParams, navigate, Link } from '@/lib/router'
import SearchInput from '@/components/common/SearchInput/SearchInput'
import { useThreats } from '@/lib/useThreats'
import { REPO_URL } from '@/config'
import styles from './Header.module.css'

function HamburgerIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path d="M3 6h18M3 12h18M3 18h18" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
    </svg>
  )
}

function SearchIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <circle cx="11" cy="11" r="7" stroke="currentColor" strokeWidth="2" />
      <path d="M21 21l-4.3-4.3" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
    </svg>
  )
}

function CloseIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path d="M6 6l12 12M18 6L6 18" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
    </svg>
  )
}

interface HeaderProps {
  onToggleMobileNav: () => void
}

export default function Header({ onToggleMobileNav }: HeaderProps) {
  const { segments } = useRoute()
  const queryParams = useQueryParams()
  const { threats, loading } = useThreats()
  const isCatalogRoute = segments.length === 0 || segments[0] === 'domain'
  const currentQuery = isCatalogRoute ? (queryParams.get('q') ?? '') : ''
  const searchRef = useRef<HTMLInputElement>(null)
  const [mobileSearchOpen, setMobileSearchOpen] = useState(false)

  useEffect(() => {
    function handleKeydown(e: KeyboardEvent) {
      if (e.key !== '/') return
      const target = e.target as HTMLElement | null
      const isTypingElsewhere =
        target?.tagName === 'INPUT' || target?.tagName === 'TEXTAREA' || target?.isContentEditable
      if (isTypingElsewhere) return
      e.preventDefault()
      searchRef.current?.focus()
    }
    window.addEventListener('keydown', handleKeydown)
    return () => window.removeEventListener('keydown', handleKeydown)
  }, [])

  // Mirrors the desktop "/" focus behavior for the mobile search row: the
  // input only exists in the DOM once mobileSearchOpen is true, so focus it
  // the moment it mounts rather than requiring a second tap.
  useEffect(() => {
    if (mobileSearchOpen) {
      searchRef.current?.focus()
    }
  }, [mobileSearchOpen])

  function handleSearchChange(value: string) {
    if (isCatalogRoute) {
      const params = new URLSearchParams(queryParams)
      if (value) {
        params.set('q', value)
      } else {
        params.delete('q')
      }
      setQueryParams(params)
    } else {
      navigate('/', value ? `q=${encodeURIComponent(value)}` : undefined)
    }
  }

  if (mobileSearchOpen) {
    return (
      <header className={styles.header}>
        <div className={styles.mobileSearchRow}>
          <SearchInput ref={searchRef} value={currentQuery} onChange={handleSearchChange} />
          <button
            type="button"
            className={styles.iconBtn}
            onClick={() => setMobileSearchOpen(false)}
            aria-label="Close search"
          >
            <CloseIcon />
          </button>
        </div>
      </header>
    )
  }

  return (
    <header className={styles.header}>
      <button
        type="button"
        className={`${styles.iconBtn} ${styles.navToggle}`}
        onClick={onToggleMobileNav}
        aria-label="Toggle domain and severity filters"
      >
        <HamburgerIcon />
      </button>

      <Link to="/" className={styles.brand}>
        <span className={styles.brandMark}>M365 / ENTRA / AZURE</span>
        <span className={styles.brandTitle}>Cloud Attack &amp; Abuse Matrix</span>
      </Link>

      <div className={styles.search}>
        <SearchInput ref={searchRef} value={currentQuery} onChange={handleSearchChange} />
      </div>

      <button
        type="button"
        className={`${styles.iconBtn} ${styles.mobileSearchToggle}`}
        onClick={() => setMobileSearchOpen(true)}
        aria-label="Search scenarios"
      >
        <SearchIcon />
      </button>

      <div className={styles.meta}>
        {!loading && <span className={styles.count}>{threats.length} scenarios</span>}
        <Link
          to="/identity-pillars"
          className={styles.navLink}
          data-active={segments[0] === 'identity-pillars'}
        >
          Identity Pillars
        </Link>
        <Link to="/acquisition" className={styles.navLink} data-active={segments[0] === 'acquisition'}>
          Acquisition Guide
        </Link>
        <a className={styles.repoLink} href={REPO_URL} target="_blank" rel="noreferrer">
          GitHub
        </a>
      </div>
    </header>
  )
}
