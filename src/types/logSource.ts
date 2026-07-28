import { z } from 'zod'

/**
 * Schema for the Artifact Acquisition Guide — a reference table answering
 * the question most of the 58 threat entries assume is already solved:
 * can you actually get this telemetry, given your licensing? Priority is
 * "how important is this source to acquire," deliberately the same visual
 * scale as threat severity for consistency, but a different axis — it's
 * about acquisition urgency, not about how dangerous a finding is.
 */

export const AcquisitionPrioritySchema = z.enum(['critical', 'high', 'medium', 'low'])
export type AcquisitionPriority = z.infer<typeof AcquisitionPrioritySchema>

export const LogSourceSchema = z.object({
  id: z.string().regex(/^[a-z0-9]+(-[a-z0-9]+)*$/, 'id must be kebab-case'),
  name: z.string().min(1),
  priority: AcquisitionPrioritySchema,
  licenseRequirement: z.string().min(1),
  /**
   * Optional caveat, correction, or additional context — used in particular
   * to flag where a commonly-repeated figure turned out to be outdated or
   * imprecise once checked against current Microsoft Learn documentation,
   * rather than silently changing a number with no explanation.
   */
  notes: z.string().optional(),
})
export type LogSource = z.infer<typeof LogSourceSchema>

export const LogSourceListSchema = z.array(LogSourceSchema)
