import { useEffect, useState } from 'react'
import { getThreats } from '@/data/threats'
import type { ThreatEntry } from '@/types/threat'

interface UseThreatsResult {
  threats: ThreatEntry[]
  loading: boolean
}

/**
 * Multiple components can call this independently — getThreats() caches
 * after the first resolution, so this doesn't trigger redundant loads.
 */
export function useThreats(): UseThreatsResult {
  const [threats, setThreats] = useState<ThreatEntry[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let cancelled = false
    getThreats().then((result) => {
      if (!cancelled) {
        setThreats(result)
        setLoading(false)
      }
    })
    return () => {
      cancelled = true
    }
  }, [])

  return { threats, loading }
}
