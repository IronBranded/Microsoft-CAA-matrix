import { Link } from '@/lib/router'
import styles from './NotFoundView.module.css'

export default function NotFoundView() {
  return (
    <div className={styles.wrap}>
      <span className={styles.code}>404</span>
      <h1 className={styles.title}>Scenario not found</h1>
      <p className={styles.desc}>
        That threat ID or domain doesn&rsquo;t exist in the catalog. It may have been renamed, or
        the link may be out of date.
      </p>
      <Link to="/" className={styles.link}>
        ← Back to the full catalog
      </Link>
    </div>
  )
}
