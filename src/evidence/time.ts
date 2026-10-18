/**
 * Time handling: UTC is stored and hashed everywhere; Indian Standard Time is
 * rendered for official reports and certificates (checklist §1).
 */
const IST_OFFSET_MS = 5.5 * 3600 * 1000;

/** "2026-10-18 12:00:00 IST" (24-hour clock). IST has no daylight saving. */
export function formatIst(at: Date | string | number): string {
  const d = new Date(new Date(at).getTime() + IST_OFFSET_MS);
  const p = (n: number) => String(n).padStart(2, '0');
  return `${d.getUTCFullYear()}-${p(d.getUTCMonth() + 1)}-${p(d.getUTCDate())} ${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())} IST`;
}

/** DD/MM/YYYY and hh:mm (IST, 24 h) as used by the BSA 2023 Schedule certificate. */
export function istDateAndTime(at: Date | string | number): { date: string; time: string } {
  const d = new Date(new Date(at).getTime() + IST_OFFSET_MS);
  const p = (n: number) => String(n).padStart(2, '0');
  return { date: `${p(d.getUTCDate())}/${p(d.getUTCMonth() + 1)}/${d.getUTCFullYear()}`, time: `${p(d.getUTCHours())}:${p(d.getUTCMinutes())}` };
}

export interface ClockStatus {
  source: string;
  sync_verified: boolean;
  offset_ms: number | null;
  recorded_at: string | null;
  /** Age of the recorded fact when it was attached to an attempt. */
  age_seconds?: number | null;
  note?: string;
}

/** A clock fact older than this is reported as stale rather than verified. */
export const CLOCK_FACT_MAX_AGE_SECONDS = 26 * 3600;

export function effectiveClockStatus(raw: Partial<ClockStatus> | null | undefined, now = Date.now()): ClockStatus {
  const recordedAt = raw?.recorded_at ?? null;
  const age = recordedAt ? Math.round((now - Date.parse(recordedAt)) / 1000) : null;
  const stale = age === null || age > CLOCK_FACT_MAX_AGE_SECONDS;
  return {
    source: raw?.source ?? 'unrecorded',
    sync_verified: Boolean(raw?.sync_verified) && !stale,
    offset_ms: raw?.offset_ms ?? null,
    recorded_at: recordedAt,
    age_seconds: age,
    ...(stale ? { note: recordedAt ? 'clock synchronisation fact is stale; re-run preflight' : 'no clock synchronisation fact recorded; run scripts/preflight.sh' } : {}),
  };
}
