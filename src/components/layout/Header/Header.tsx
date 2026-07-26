import { useRoute, useQueryParams, setQueryParams, navigate, Link } from '@/lib/router'
import SearchInput from '@/components/common/SearchInput/SearchInput'
import { useThreats } from '@/lib/useThreats'
import { REPO_URL } from '@/config'
import styles from './Header.module.css'

export default function Header() {
  const { segments } = useRoute()
  const queryParams = useQueryParams()
  const { threats, loading } = useThreats()
  const isCatalogRoute = segments.length === 0 || segments[0] === 'domain'
  const currentQuery = isCatalogRoute ? (queryParams.get('q') ?? '') : ''

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

  return (
    <header className={styles.header}>
      <Link to="/" className={styles.brand}>
        <span className={styles.brandMark}>M365 / ENTRA / AZURE</span>
        <span className={styles.brandTitle}>Cloud Attack &amp; Abuse Matrix</span>
      </Link>

      <div className={styles.search}>
        <SearchInput value={currentQuery} onChange={handleSearchChange} />
      </div>

      <div className={styles.meta}>
        {!loading && <span className={styles.count}>{threats.length} scenarios</span>}
        <a className={styles.repoLink} href={REPO_URL} target="_blank" rel="noreferrer">
          GitHub
        </a>
      </div>
    </header>
  )
}
