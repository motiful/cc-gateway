// Live rate-limit / quota snapshot for the shared OAuth (Claude subscription)
// account. Anthropic returns an `anthropic-ratelimit-unified-*` header family on
// EVERY /v1/messages response (not just 429s) describing how much of the account's
// 5-hour rolling window and 7-day (weekly) window is consumed. Claude Code reads
// these headers but doesn't persist them; the gateway can, so the admin dashboard
// can show "session used %", "weekly used %", and when each window resets.
//
// The account is shared across all gateway clients, so a single module-level
// snapshot (the most recent response we saw) is the right granularity. It's kept
// in memory only — it's inherently live state, and the next request repopulates it
// after a restart.
//
// Design note: we capture EVERY `anthropic-ratelimit-*` header verbatim into `raw`
// and parse the families we recognise on top. That way the dashboard degrades
// gracefully if Anthropic renames or adds fields — the known windows render as
// bars, and `raw` is always available as a fallback view.

const FIVE_HOURS_MS = 5 * 60 * 60 * 1000

export interface QuotaWindow {
  /** '5h' (rolling session) or '7d' (weekly). */
  key: '5h' | '7d'
  /** e.g. 'allowed', 'allowed_warning', 'rejected', 'rate_limited'. */
  status?: string
  /** Epoch ms when this window resets, from the `-reset` unix-seconds header. */
  resetMs?: number
  /** Percent of the window consumed (0–100), from the `-utilization` fraction. */
  usedPct?: number
}

export interface RateLimitSnapshot {
  /** When we last saw these headers (epoch ms). */
  capturedAt: number
  /** Overall unified status across windows. */
  overallStatus?: string
  /** Which window is authoritative right now: 'five_hour' | 'seven_day'. */
  representative?: string
  windows: QuotaWindow[]
  /** Start of the current 5h window (resetMs − 5h), for "models this session". */
  sessionWindowStartMs?: number
  /** Every captured `anthropic-ratelimit-*` header, verbatim. */
  raw: Record<string, string>
}

let latest: RateLimitSnapshot | null = null

const PREFIX = 'anthropic-ratelimit-'

function headerValue(v: string | string[] | undefined): string | undefined {
  if (v == null) return undefined
  return Array.isArray(v) ? v.join(', ') : String(v)
}

function num(raw: Record<string, string>, key: string): number | undefined {
  const v = raw[key]
  if (v == null || v === '') return undefined
  const n = Number(v)
  return Number.isFinite(n) ? n : undefined
}

function buildWindow(raw: Record<string, string>, key: '5h' | '7d'): QuotaWindow | null {
  const base = `${PREFIX}unified-${key}-`
  const status = raw[`${base}status`]
  const util = num(raw, `${base}utilization`)
  const resetSec = num(raw, `${base}reset`)
  if (status == null && util == null && resetSec == null) return null
  return {
    key,
    status,
    usedPct: util != null ? Math.max(0, Math.min(100, util * 100)) : undefined,
    resetMs: resetSec != null ? resetSec * 1000 : undefined,
  }
}

/**
 * Capture the `anthropic-ratelimit-*` headers from an upstream response. No-op if
 * the response carries none (e.g. non-messages endpoints), so callers can invoke
 * it unconditionally on every proxied response.
 */
export function captureRateLimitHeaders(
  headers: Record<string, string | string[] | undefined>,
): void {
  const raw: Record<string, string> = {}
  for (const [k, v] of Object.entries(headers)) {
    const lk = k.toLowerCase()
    if (!lk.startsWith(PREFIX)) continue
    const val = headerValue(v)
    if (val != null) raw[lk] = val
  }
  if (Object.keys(raw).length === 0) return

  const windows = [buildWindow(raw, '5h'), buildWindow(raw, '7d')].filter(
    (w): w is QuotaWindow => w != null,
  )
  const fiveH = windows.find((w) => w.key === '5h')

  latest = {
    capturedAt: Date.now(),
    overallStatus: raw[`${PREFIX}unified-status`],
    representative: raw[`${PREFIX}unified-representative-claim`],
    windows,
    sessionWindowStartMs:
      fiveH?.resetMs != null ? fiveH.resetMs - FIVE_HOURS_MS : undefined,
    raw,
  }
}

/** Latest captured quota snapshot, or null if we haven't seen any headers yet. */
export function getRateLimitSnapshot(): RateLimitSnapshot | null {
  return latest
}

/** Test hook — clear the in-memory snapshot. */
export function _resetRateLimitSnapshot(): void {
  latest = null
}
