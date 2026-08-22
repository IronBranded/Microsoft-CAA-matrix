import { useEffect, useState } from 'react'
import styles from './SectionNav.module.css'

interface Section {
  id: string
  label: string
}

interface SectionNavProps {
  sections: Section[]
}

/**
 * Sticky in-page nav for the detail view's variable section set (a stub
 * entry might only render Runbook; a complete one renders all four).
 * Renders as buttons, not anchors — this app's router reads
 * `window.location.hash` for its own routes (`#/threat/:id`), so an
 * `<a href="#artifacts">` would hijack the hash and navigate away from the
 * page instead of scrolling within it.
 *
 * Active section is derived from IntersectionObserver against each
 * heading, not scroll-position math — more robust to sections of very
 * different heights (a two-line Telemetry block next to a long KQL block).
 */
export default function SectionNav({ sections }: SectionNavProps) {
  const [activeId, setActiveId] = useState<string | undefined>(sections[0]?.id)

  useEffect(() => {
    if (sections.length === 0) return

    const elements = sections
      .map((s) => document.getElementById(s.id))
      .filter((el): el is HTMLElement => el !== null)

    if (elements.length === 0) return

    const observer = new IntersectionObserver(
      (entries) => {
        // Among sections currently in the trigger band, pick the one
        // closest to the top — mirrors reading order rather than
        // whichever callback happened to fire last.
        const visible = entries
          .filter((e) => e.isIntersecting)
          .sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top)

        if (visible[0]) {
          setActiveId(visible[0].target.id)
        }
      },
      {
        // Trigger band near the top of the viewport — a section should
        // activate as it arrives under the sticky nav, not merely when
        // any pixel of it first enters the screen.
        rootMargin: '-15% 0px -70% 0px',
        threshold: 0,
      },
    )

    for (const el of elements) {
      observer.observe(el)
    }

    return () => observer.disconnect()
  }, [sections])

  if (sections.length === 0) {
    return null
  }

  function handleClick(id: string) {
    document.getElementById(id)?.scrollIntoView({ behavior: 'smooth', block: 'start' })
    setActiveId(id)
  }

  return (
    <nav className={styles.nav} aria-label="Section navigation">
      {sections.map((s) => (
        <button
          key={s.id}
          type="button"
          className={styles.link}
          data-active={activeId === s.id}
          onClick={() => handleClick(s.id)}
        >
          {s.label}
        </button>
      ))}
    </nav>
  )
}
