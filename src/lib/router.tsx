import {
  createContext,
  useContext,
  useEffect,
  useState,
  type AnchorHTMLAttributes,
  type ReactNode,
} from 'react'

/**
 * A small, dependency-free hash router.
 *
 * This app only needs four route shapes ("/", "/domain/:slug",
 * "/threat/:id", plus flat top-level pages like "/acquisition" and
 * "/identity-pillars") with no nested routes, loaders, or server
 * rendering — not enough surface to justify a routing library.
 * react-router-dom in particular has had a run of high-severity advisories
 * through 2026 (RSC-mode CSRF, XSS via redirects, SSR issues); none apply
 * to a static, client-only SPA like this one, but there's no reason to
 * carry the dependency (or its churn) for a handful of patterns a
 * ~60-line file can own outright, fully auditable in one read.
 */

export interface RouteState {
  /** Path segments, e.g. ['threat', 'device-code-phishing'] */
  segments: string[]
  /** Raw query string after '?', if any (without the leading '?') */
  query: string
}

function parseHash(): RouteState {
  const raw = window.location.hash.replace(/^#/, '')
  const [path, query = ''] = raw.split('?')
  const segments = path.split('/').filter(Boolean)
  return { segments, query }
}

const RouteContext = createContext<RouteState>(parseHash())

export function RouterProvider({ children }: { children: ReactNode }) {
  const [route, setRoute] = useState<RouteState>(() => parseHash())

  useEffect(() => {
    const onHashChange = () => setRoute(parseHash())
    window.addEventListener('hashchange', onHashChange)
    return () => window.removeEventListener('hashchange', onHashChange)
  }, [])

  return <RouteContext.Provider value={route}>{children}</RouteContext.Provider>
}

export function useRoute(): RouteState {
  return useContext(RouteContext)
}

/** Read-and-parse the query portion of the current hash into URLSearchParams. */
export function useQueryParams(): URLSearchParams {
  const { query } = useRoute()
  return new URLSearchParams(query)
}

/** Push a new hash path, optionally with a query string (no leading '?'). */
export function navigate(path: string, query?: string): void {
  window.location.hash = query ? `${path}?${query}` : path
}

/** Replace only the query portion of the current hash, keeping the path. */
export function setQueryParams(params: URLSearchParams): void {
  const { segments } = parseHash()
  const path = `/${segments.join('/')}`
  const qs = params.toString()
  const target = qs ? `#${path}?${qs}` : `#${path}`
  history.replaceState(null, '', target)
  // history.replaceState doesn't fire 'hashchange' — dispatch manually so
  // any component reading useRoute()/useQueryParams() re-renders.
  window.dispatchEvent(new HashChangeEvent('hashchange'))
}

interface LinkProps extends AnchorHTMLAttributes<HTMLAnchorElement> {
  to: string
}

export function Link({ to, children, ...rest }: LinkProps) {
  return (
    <a href={`#${to}`} {...rest}>
      {children}
    </a>
  )
}
