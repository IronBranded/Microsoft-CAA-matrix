import type { ReactNode } from 'react'
import { Link } from '@/lib/router'
import { useDocumentTitle } from '@/lib/useDocumentTitle'
import { identityPillars } from '@/data/identityPillars'
import { DOMAIN_META } from '@/types/threat'
import type { IdentityPillar } from '@/types/identityPillar'
import styles from './IdentityPillarsView.module.css'

function CursorIcon() {
  return (
    <svg viewBox="0 0 40 40" fill="none" stroke="currentColor" strokeWidth="2" strokeLinejoin="round" strokeLinecap="round">
      <path d="M12 8 L12 28 L17 23.5 L20.5 30.5 L24 29 L20.5 22 L27 22 Z" />
    </svg>
  )
}

function RefreshIcon() {
  return (
    <svg viewBox="0 0 40 40" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round">
      <path d="M28 13 A11 11 0 1 0 29.5 21" />
      <path d="M23 8 L28.5 12.5 L24 17.5" strokeLinejoin="round" />
    </svg>
  )
}

function BracketsIcon() {
  return (
    <svg viewBox="0 0 40 40" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M16 11 L9 20 L16 29" />
      <path d="M24 11 L31 20 L24 29" />
    </svg>
  )
}

function CloudIcon() {
  return (
    <svg viewBox="0 0 40 40" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M11 25 a6 6 0 0 1 1-11.9 a7.5 7.5 0 0 1 14 -2.3 a6 6 0 0 1 1.5 11.9 Z" />
      <circle cx="27" cy="26" r="5.5" strokeWidth="1.8" />
      <path d="M27 23.5 L27 26 L28.8 27.5" strokeWidth="1.4" />
    </svg>
  )
}

const PILLAR_ICONS: Record<string, ReactNode> = {
  interactive: <CursorIcon />,
  'non-interactive': <RefreshIcon />,
  'service-principal': <BracketsIcon />,
  'managed-identity': <CloudIcon />,
}

function PillarCard({ pillar }: { pillar: IdentityPillar }) {
  const domain = DOMAIN_META[pillar.relatedDomain]
  return (
    <div className={styles.card}>
      <div className={styles.iconBadge}>{PILLAR_ICONS[pillar.id]}</div>
      <h3 className={styles.cardTitle}>{pillar.name}</h3>

      <div className={styles.field}>
        <div className={styles.fieldLabel}>What it is</div>
        <div className={styles.fieldBody}>{pillar.whatItIs}</div>
      </div>
      <div className={styles.field}>
        <div className={styles.fieldLabel}>How it works</div>
        <div className={styles.fieldBody}>{pillar.howItWorks}</div>
      </div>
      <div className={styles.field}>
        <div className={styles.fieldLabel}>Security context</div>
        <div className={styles.fieldBody}>{pillar.securityContext}</div>
      </div>

      <Link to={`/domain/${domain.slug}`} className={styles.tag}>
        <span className={styles.arrow}>→</span>
        {`Domain ${domain.order} · ${pillar.domainTagLabel}`}
      </Link>
    </div>
  )
}

/**
 * The conceptual primer behind the whole catalog: the network perimeter is
 * mostly gone for cloud services, so identity is what actually gates
 * access now. This explains the four ways Entra ID represents "who's
 * asking" — the axis most of the matrix's 58 scenarios attack in one form
 * or another. Not a threat, not a log source — foundational reference,
 * same tier as the Acquisition Guide.
 */
export default function IdentityPillarsView() {
  useDocumentTitle('Identity Pillars')

  return (
    <div className={styles.view}>
      <div className={styles.eyebrow}>§ Foundational Concept</div>
      <h1 className={styles.heading}>Identity Is the New Perimeter</h1>
      <p className={styles.thesis}>
        Traditional security drew its main boundary at the network edge — a firewall separating trusted inside from
        untrusted outside. Cloud services are reachable from anywhere by design, so that boundary is mostly gone.
        What actually gates access now is proving <strong>who, or what, is asking</strong>. Every scenario this
        matrix catalogs is ultimately an attack against one of the four ways Entra ID answers that question.
      </p>

      <div className={styles.grid}>
        {identityPillars.map((pillar) => (
          <PillarCard key={pillar.id} pillar={pillar} />
        ))}
      </div>
    </div>
  )
}
