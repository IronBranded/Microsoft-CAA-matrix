import { useEffect } from 'react'

const BASE_TITLE = 'Microsoft Cloud Attack & Abuse Matrix'

/**
 * Sets document.title for the current page. Pass nothing (or an empty
 * string) for the base catalog title itself.
 */
export function useDocumentTitle(pageTitle?: string): void {
  useEffect(() => {
    document.title = pageTitle ? `${pageTitle} — ${BASE_TITLE}` : BASE_TITLE
  }, [pageTitle])
}
