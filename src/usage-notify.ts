import { readFileSync, writeFileSync } from 'fs'
import { resolve } from 'path'
import { log } from './logger.js'
import { sendDiscord } from './discord.js'
import { resetCounters } from './usage-meter.js'

// Fire a Discord notification each time the shared account's 7-day usage
// crosses a new BAND_STEP% band (5, 10, 15, … 100). Anthropic returns the
// current utilization on every upstream response, so we just watch the headers.
//
// The 7-day unified window is a rolling window: it can wiggle downward a little
// as old usage ages out. So we only re-notify on UPWARD band crossings, and
// treat a large drop (window reset) as a reset — never spam on small dithers.

// Notification granularity, in percentage points.
const BAND_STEP = 5
// A downward move of at least this many points means the window rolled over.
const RESET_DROP = 20

const H_7D_UTIL = 'anthropic-ratelimit-unified-7d-utilization'
const H_7D_STATUS = 'anthropic-ratelimit-unified-7d-status'
const H_7D_RESET = 'anthropic-ratelimit-unified-7d-reset'
const H_5H_UTIL = 'anthropic-ratelimit-unified-5h-utilization'

let webhookUrl: string | null = null
let statePath: string | null = null
// Highest band we've already notified for (negative = nothing yet).
let lastBand = -BAND_STEP

type State = { band: number; util: number; ts: string }

function loadState(): void {
  if (!statePath) return
  try {
    const s = JSON.parse(readFileSync(statePath, 'utf-8')) as State
    if (typeof s.band === 'number') lastBand = s.band
  } catch {
    // no state yet — start fresh
  }
}

function saveState(util: number): void {
  if (!statePath) return
  try {
    const s: State = { band: lastBand, util, ts: new Date().toISOString() }
    writeFileSync(statePath, JSON.stringify(s), { mode: 0o600 })
  } catch (err) {
    log('warn', `usage-notify: could not persist state: ${err}`)
  }
}

export function initUsageNotify(webhook?: string, path?: string): void {
  webhookUrl = webhook || null
  statePath = path || resolve(process.cwd(), 'usage-notify-state.json')
  if (!webhookUrl) {
    log('info', 'Usage notifier disabled (no notify.discord_webhook in config)')
    return
  }
  loadState()
  log('info', `Usage notifier armed (last notified band: ${lastBand >= 0 ? lastBand + '%' : 'none'})`)
}

function header(
  headers: Record<string, string | string[] | undefined>,
  name: string,
): string | undefined {
  const v = headers[name]
  return Array.isArray(v) ? v[0] : v
}

/**
 * Inspect an upstream response's rate-limit headers and notify Discord if the
 * 7-day usage has crossed into a new 10% band. Safe to call on every response —
 * never throws, and only sends when a band boundary is actually crossed.
 */
export function maybeNotifyUsage(
  headers: Record<string, string | string[] | undefined>,
): void {
  if (!webhookUrl) return

  const raw = header(headers, H_7D_UTIL)
  if (raw === undefined) return
  const util = Number(raw)
  if (!Number.isFinite(util)) return

  const pct = Math.max(0, Math.min(100, util * 100))
  const band = Math.floor(pct / BAND_STEP) * BAND_STEP // 0,5,10,…,100

  // Rolling-window reset: a big drop means the window rolled over. Re-arm so
  // future climbs notify again, and send a reset note.
  if (band <= lastBand - RESET_DROP) {
    lastBand = band
    saveState(util)
    resetCounters() // re-baseline per-user metering to the new 7-day window
    if (webhookUrl) {
      void sendDiscord(
        webhookUrl,
        `🔄 **CC Gateway usage reset** — 7-day window rolled over, now at **${pct.toFixed(1)}%**. Per-user counters reset.`,
      )
    }
    return
  }

  if (band <= lastBand) return // still inside an already-notified band

  // Crossed one or more upward bands — notify for the new (highest) band.
  lastBand = band // update in-memory first so concurrent requests don't double-fire
  saveState(util)

  const status = header(headers, H_7D_STATUS) || 'unknown'
  const fiveH = header(headers, H_5H_UTIL)
  const resetRaw = header(headers, H_7D_RESET)
  const resetStr = resetRaw
    ? new Date(Number(resetRaw) * 1000).toISOString().replace('T', ' ').slice(0, 16) + ' UTC'
    : 'unknown'
  const emoji = band >= 90 ? '🚨' : band >= 75 ? '⚠️' : '📊'

  const lines = [
    `${emoji} **CC Gateway usage crossed ${band}%**`,
    `7-day: **${pct.toFixed(1)}%** (status: \`${status}\`)`,
    fiveH !== undefined ? `5-hour: ${(Number(fiveH) * 100).toFixed(1)}%` : null,
    `7-day resets: ${resetStr}`,
  ].filter(Boolean)

  if (webhookUrl) {
    void sendDiscord(webhookUrl, lines.join('\n'))
    log('info', `usage-notify: sent Discord alert (band ${band}%)`)
  }
}
