import { useQueryParams, setQueryParams } from '@/lib/router'
import type { KqlQueries } from '@/types/threat'
import CopyButton from '@/components/common/CopyButton/CopyButton'
import styles from './KqlExplorer.module.css'

interface KqlExplorerProps {
  kql: KqlQueries
}

type Platform = 'sentinel' | 'defender'
const PLATFORMS: Platform[] = ['sentinel', 'defender']
const PLATFORM_LABEL: Record<Platform, string> = {
  sentinel: 'Microsoft Sentinel',
  defender: 'Defender Advanced Hunting',
}

/**
 * Platform and active-query selection live in the URL (kqlPlatform /
 * kqlQuery), not local state — so a link to "the Defender query
 * specifically" actually lands there instead of always the default tab.
 */
export default function KqlExplorer({ kql }: KqlExplorerProps) {
  const queryParams = useQueryParams()

  const availablePlatforms = PLATFORMS.filter((p) => {
    const group = kql[p]
    return group && Object.keys(group).length > 0
  })

  const requestedPlatform = queryParams.get('kqlPlatform') as Platform | null
  const platform =
    requestedPlatform && availablePlatforms.includes(requestedPlatform) ? requestedPlatform : availablePlatforms[0]

  const queriesForPlatform = platform ? (kql[platform] ?? {}) : {}
  const queryKeys = Object.keys(queriesForPlatform)

  const requestedKey = queryParams.get('kqlQuery')
  const activeKey = requestedKey && queryKeys.includes(requestedKey) ? requestedKey : queryKeys[0]

  function handlePlatformChange(next: Platform) {
    const params = new URLSearchParams(queryParams)
    params.set('kqlPlatform', next)
    const nextKeys = Object.keys(kql[next] ?? {})
    if (nextKeys[0]) {
      params.set('kqlQuery', nextKeys[0])
    } else {
      params.delete('kqlQuery')
    }
    setQueryParams(params)
  }

  function handleQueryChange(key: string) {
    const params = new URLSearchParams(queryParams)
    if (platform) params.set('kqlPlatform', platform)
    params.set('kqlQuery', key)
    setQueryParams(params)
  }

  if (!platform) {
    return null
  }

  const activeQuery = activeKey ? queriesForPlatform[activeKey] : undefined

  return (
    <div className={styles.wrap}>
      <div className={styles.platformTabs}>
        {availablePlatforms.map((p) => (
          <button
            key={p}
            type="button"
            className={styles.platformTab}
            data-active={platform === p}
            onClick={() => handlePlatformChange(p)}
          >
            {PLATFORM_LABEL[p]}
          </button>
        ))}
      </div>

      {queryKeys.length > 1 && (
        <div className={styles.queryTabs}>
          {queryKeys.map((key) => (
            <button
              key={key}
              type="button"
              className={styles.queryTab}
              data-active={activeKey === key}
              onClick={() => handleQueryChange(key)}
            >
              {queriesForPlatform[key].title}
            </button>
          ))}
        </div>
      )}

      {activeQuery && (
        <div className={styles.queryBlock}>
          <div className={styles.queryHead}>
            <div>
              <div className={styles.queryTitle}>{activeQuery.title}</div>
              {activeQuery.description && (
                <div className={styles.queryDesc}>{activeQuery.description}</div>
              )}
            </div>
            <CopyButton text={activeQuery.query} />
          </div>
          <pre className={styles.code}>
            <code>{activeQuery.query}</code>
          </pre>
        </div>
      )}
    </div>
  )
}
