import { useState } from 'react'
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

export default function KqlExplorer({ kql }: KqlExplorerProps) {
  const availablePlatforms = PLATFORMS.filter((p) => {
    const group = kql[p]
    return group && Object.keys(group).length > 0
  })

  const [platform, setPlatform] = useState<Platform | undefined>(availablePlatforms[0])
  const queriesForPlatform = platform ? (kql[platform] ?? {}) : {}
  const queryKeys = Object.keys(queriesForPlatform)
  const [activeKey, setActiveKey] = useState<string | undefined>(queryKeys[0])

  function handlePlatformChange(next: Platform) {
    setPlatform(next)
    setActiveKey(Object.keys(kql[next] ?? {})[0])
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
              onClick={() => setActiveKey(key)}
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
