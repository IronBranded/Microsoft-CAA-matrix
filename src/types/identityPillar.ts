import { z } from 'zod'
import { DomainSchema } from './threat'

/**
 * The four Entra ID sign-in types (Interactive, Non-interactive, Service
 * Principal, Managed Identity) explained as a standalone reference —
 * not a threat, not a log source, but the conceptual foundation the rest
 * of the catalog assumes. See src/components/views/IdentityPillarsView.
 */
export const IdentityPillarSchema = z.object({
  id: z.string().min(1),
  name: z.string().min(1),
  whatItIs: z.string().min(1),
  howItWorks: z.string().min(1),
  securityContext: z.string().min(1),
  /** The domain this pillar's attack surface lives in — powers the card's cross-reference link. */
  relatedDomain: DomainSchema,
  /**
   * Label shown on the cross-reference tag. Often narrower than the
   * domain's own DOMAIN_META label — e.g. "Token & Session Theft" for
   * Non-interactive, which shares a domain with Interactive but points at
   * a distinct sub-theme within it.
   */
  domainTagLabel: z.string().min(1),
})
export type IdentityPillar = z.infer<typeof IdentityPillarSchema>

export const IdentityPillarListSchema = z.array(IdentityPillarSchema)
