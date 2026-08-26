// Anthropic public list prices in USD per 1M tokens, as of 2026-07.
// Source: https://platform.claude.com/docs/en/about-claude/pricing
//
// Only base input/output prices are listed per model. Every cache rate is a
// fixed multiplier on that model's input price, so we derive them rather than
// restate four numbers per row:
//   cache read (hit)     = 0.1x  input
//   cache write, 5m TTL  = 1.25x input
//   cache write, 1h TTL  = 2x    input
//
// When a request reports a model id we don't recognise, we fall back to the
// most specific family match (fable/mythos/opus/haiku) and finally to sonnet.

/** Base per-1M list prices; cache rates are derived from `input`. */
interface BaseRate {
  input: number
  output: number
}

/** A model's fully expanded per-1M rates for every token category. */
export interface Pricing {
  input: number
  output: number
  cacheRead: number
  cacheWrite5m: number
  cacheWrite1h: number
}

// Derived rates are rounded so they land exactly on the published figures
// (3 * 0.1 is 0.30000000000000004 in binary floating point, not 0.3).
const exact = (n: number) => Math.round(n * 1e6) / 1e6

function expand(b: BaseRate, multiplier = 1): Pricing {
  const input = exact(b.input * multiplier)
  return {
    input,
    output:       exact(b.output * multiplier),
    cacheRead:    exact(input * 0.1),
    cacheWrite5m: exact(input * 1.25),
    cacheWrite1h: exact(input * 2),
  }
}

const RATES: Record<string, BaseRate> = {
  // Fable / Mythos family (top tier, above opus)
  'claude-fable-5':        { input: 10.00, output: 50.00 },
  'claude-mythos-5':       { input: 10.00, output: 50.00 },
  'claude-mythos-preview': { input: 10.00, output: 50.00 },
  // Opus family (current)
  'claude-opus-5':         { input:  5.00, output: 25.00 },
  'claude-opus-4-8':       { input:  5.00, output: 25.00 },
  'claude-opus-4-7':       { input:  5.00, output: 25.00 },
  'claude-opus-4-6':       { input:  5.00, output: 25.00 },
  'claude-opus-4-5':       { input:  5.00, output: 25.00 },
  // Opus 4.1 and Opus 4 predate the Opus price drop and are still 3x the
  // current Opus rate — they must stay listed or they'd be badly underpriced.
  'claude-opus-4-1':       { input: 15.00, output: 75.00 },
  'claude-opus-4':         { input: 15.00, output: 75.00 },
  // Sonnet family. Sonnet 5 list price is $3/$15; see SONNET_5_INTRO below for
  // the promotional rate that applies through 2026-08-31.
  'claude-sonnet-5':       { input:  3.00, output: 15.00 },
  'claude-sonnet-4-6':     { input:  3.00, output: 15.00 },
  'claude-sonnet-4-5':     { input:  3.00, output: 15.00 },
  'claude-sonnet-4':       { input:  3.00, output: 15.00 },
  'claude-haiku-4-5':      { input:  1.00, output:  5.00 },
  // 3.x family (retired, but may still appear in historical usage records)
  'claude-3-7-sonnet':     { input:  3.00, output: 15.00 },
  'claude-3-5-sonnet':     { input:  3.00, output: 15.00 },
  'claude-3-5-haiku':      { input:  0.80, output:  4.00 },
  'claude-3-opus':         { input: 15.00, output: 75.00 },
}

// Longest id first, so "claude-opus-4-8" wins over "claude-opus-4" regardless
// of declaration order in RATES.
const RATE_IDS = Object.keys(RATES).sort((a, b) => b.length - a.length)

// Fast mode (research preview) bills at a premium across the whole context
// window. Only these two models support it; anything else reports
// usage.speed: "standard" and is priced from RATES.
const FAST_RATES: Record<string, BaseRate> = {
  'claude-opus-5':         { input: 10.00, output: 50.00 },
  'claude-opus-4-8':       { input: 10.00, output: 50.00 },
}

// Sonnet 5 introductory pricing: $2/$10 per 1M through 2026-08-31, then the
// $3/$15 list price in RATES takes over automatically.
const SONNET_5_INTRO: BaseRate = { input: 2.00, output: 10.00 }
const SONNET_5_INTRO_ENDS_AT = Date.UTC(2026, 8, 1) // 2026-09-01T00:00Z

// inference_geo: "us" pins inference to US regions for a 1.1x premium on every
// token category. "global" (the default) is standard priced.
const US_GEO_MULTIPLIER = 1.1

/**
 * Collapse a reported model id onto a key in RATES. `exact` is false when we
 * only guessed from the family name (or defaulted), which suppresses
 * promotional pricing — we won't discount a model we couldn't identify.
 */
function resolveId(model: string): { id: string; exact: boolean } {
  const key = model.toLowerCase()
  // Prefix match strips date suffixes: "claude-sonnet-4-5-20250929" → "claude-sonnet-4-5"
  for (const id of RATE_IDS) {
    if (key === id || key.startsWith(id + '-')) return { id, exact: true }
  }
  // Family fallback — newest model in each family
  if (key.includes('fable'))  return { id: 'claude-fable-5', exact: false }
  if (key.includes('mythos')) return { id: 'claude-mythos-5', exact: false }
  if (key.includes('opus'))   return { id: 'claude-opus-5', exact: false }
  if (key.includes('haiku'))  return { id: 'claude-haiku-4-5', exact: false }
  return { id: 'claude-sonnet-5', exact: false }
}

function lookupRate(model: string, at: number, speed: string, geo: string): Pricing {
  const { id, exact: isKnown } = resolveId(model)
  // Fast mode replaces the base rate. A 'fast' flag on a model that can't do
  // fast mode falls through to standard, matching how upstream bills it.
  let base = (speed === 'fast' && FAST_RATES[id]) || RATES[id]
  if (isKnown && id === 'claude-sonnet-5' && at < SONNET_5_INTRO_ENDS_AT) base = SONNET_5_INTRO
  return expand(base, geo === 'us' ? US_GEO_MULTIPLIER : 1)
}

export interface UsageBreakdown {
  inputTokens: number
  outputTokens: number
  cacheReadTokens: number
  cacheCreationTokens: number
  /**
   * Optional TTL split of cacheCreationTokens (they sum to it). When neither is
   * reported the whole cache-creation figure is priced at the 5-minute rate,
   * which is what a request that never asks for a 1h TTL actually incurs.
   */
  cacheCreation5mTokens?: number
  cacheCreation1hTokens?: number
  /** From usage.speed; 'fast' selects premium fast-mode rates. */
  speed?: string
  /** From usage.inference_geo; 'us' applies the 1.1x data-residency premium. */
  inferenceGeo?: string
}

export function computeCost(model: string, u: UsageBreakdown, at: number = Date.now()): number {
  const r = lookupRate(model || '', at, u.speed || '', u.inferenceGeo || '')
  // Split the cache write by TTL. If upstream reported only one side, the rest
  // of the total belongs to the other; if it reported neither, it's all 5m.
  const write1h = u.cacheCreation1hTokens ?? 0
  const write5m = u.cacheCreation5mTokens ?? Math.max(0, u.cacheCreationTokens - write1h)
  return (
    (u.inputTokens     / 1_000_000) * r.input +
    (u.outputTokens    / 1_000_000) * r.output +
    (u.cacheReadTokens / 1_000_000) * r.cacheRead +
    (write5m           / 1_000_000) * r.cacheWrite5m +
    (write1h           / 1_000_000) * r.cacheWrite1h
  )
}

export function formatCost(usd: number): string {
  if (usd < 0.0001) return '$0.0000'
  if (usd < 1) return '$' + usd.toFixed(4)
  if (usd < 100) return '$' + usd.toFixed(2)
  return '$' + Math.round(usd).toLocaleString()
}

export function formatTokens(n: number): string {
  if (n < 1000) return String(n)
  if (n < 1_000_000) return (n / 1000).toFixed(1).replace(/\.0$/, '') + 'k'
  return (n / 1_000_000).toFixed(2).replace(/\.00$/, '') + 'M'
}
