/**
 * Runbook checklist progress, persisted to localStorage per threat + phase.
 *
 * Storage can throw (private browsing, disabled storage, quota exceeded) —
 * every operation here fails quietly rather than crashing the checklist UI,
 * the same fail-quiet posture CopyButton already uses for the Clipboard API.
 * Worst case on a storage failure: checked state still works for the
 * current session via RunbookPanel's local `version` counter, it just won't
 * survive a reload.
 */

const PREFIX = 'caa-matrix:runbook'

function storageKey(threatId: string, phase: string): string {
  return `${PREFIX}:${threatId}:${phase}`
}

function readIndices(threatId: string, phase: string): number[] {
  try {
    const raw = window.localStorage.getItem(storageKey(threatId, phase))
    if (!raw) return []
    const parsed: unknown = JSON.parse(raw)
    return Array.isArray(parsed) ? parsed.filter((n): n is number => typeof n === 'number') : []
  } catch {
    return []
  }
}

function writeIndices(threatId: string, phase: string, indices: number[]): void {
  try {
    window.localStorage.setItem(storageKey(threatId, phase), JSON.stringify(indices))
  } catch {
    // Storage unavailable or full — see file header.
  }
}

export function getCheckedSteps(threatId: string, phase: string): Set<number> {
  return new Set(readIndices(threatId, phase))
}

export function setStepChecked(threatId: string, phase: string, index: number, checked: boolean): void {
  const current = new Set(readIndices(threatId, phase))
  if (checked) {
    current.add(index)
  } else {
    current.delete(index)
  }
  writeIndices(threatId, phase, [...current])
}

export function clearPhaseProgress(threatId: string, phase: string): void {
  try {
    window.localStorage.removeItem(storageKey(threatId, phase))
  } catch {
    // See file header.
  }
}
