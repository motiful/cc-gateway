import type { IncomingMessage } from 'http'
import { readFileSync, writeFileSync } from 'fs'
import { resolve } from 'path'
import { log } from './logger.js'
import { sendDiscord } from './discord.js'

// Per-sub-user (per client-token) usage metering. Anthropic's rate-limit
// headers are account-wide for the shared OAuth account, so the only place we
// can attribute usage to an individual client is here, by tapping each
// upstream response and reading its `usage` block.
//
// Counters accumulate over the current 7-day account window; usage-notify calls
// resetCounters() when that window rolls over so per-user totals line up with
// the same window as the account's utilization %.

type Counters = {
  requests: number
  errors: number
  inputTokens: number
  outputTokens: number
  cacheReadTokens: number
  cacheCreationTokens: number
}

const emptyCounters = (): Counters => ({
  requests: 0,
  errors: 0,
  inputTokens: 0,
  outputTokens: 0,
  cacheReadTokens: 0,
  cacheCreationTokens: 0,
})

const clients = new Map<string, Counters>()
let since = new Date().toISOString()
let statePath: string | null = null
let webhookUrl: string | null = null
let dirty = false

function get(name: string): Counters {
  let c = clients.get(name)
  if (!c) {
    c = emptyCounters()
    clients.set(name, c)
  }
  return c
}

export function recordRequest(client: string, status: number): void {
  const c = get(client)
  c.requests++
  if (status >= 400) c.errors++
  dirty = true
}

type UsageLike = {
  input_tokens?: number
  output_tokens?: number
  cache_read_input_tokens?: number
  cache_creation_input_tokens?: number
}

type Acc = { input: number; output: number; cacheRead: number; cacheCreate: number }

function applyUsage(acc: Acc, u?: UsageLike): void {
  if (!u) return
  if (typeof u.input_tokens === 'number') acc.input = u.input_tokens
  if (typeof u.output_tokens === 'number') acc.output = u.output_tokens
  if (typeof u.cache_read_input_tokens === 'number') acc.cacheRead = u.cache_read_input_tokens
  if (typeof u.cache_creation_input_tokens === 'number') acc.cacheCreate = u.cache_creation_input_tokens
}

function parseSSE(data: string, acc: Acc): void {
  if (!data || data === '[DONE]') return
  let obj: { type?: string; usage?: UsageLike; message?: { usage?: UsageLike } }
  try {
    obj = JSON.parse(data)
  } catch {
    return
  }
  // message_start carries input+cache tokens; message_delta carries the final
  // (authoritative) totals. Overwrite-on-present means the last one wins.
  if (obj?.type === 'message_start' && obj.message?.usage) applyUsage(acc, obj.message.usage)
  else if (obj?.type === 'message_delta' && obj.usage) applyUsage(acc, obj.usage)
}

/**
 * Tap an upstream response to attribute token usage to `client`. Non-destructive:
 * it only listens to 'data'/'end' events, so the existing pipe() to the client
 * is unaffected. MUST be called in the same tick as pipe() (after it) so no
 * chunks are missed. Handles both streaming (SSE) and single-JSON responses.
 */
export function attachUsage(client: string, res: IncomingMessage): void {
  const ct = String(res.headers['content-type'] || '')
  const isSSE = ct.includes('event-stream')
  const acc: Acc = { input: 0, output: 0, cacheRead: 0, cacheCreate: 0 }
  let tail = ''
  let jsonBuf = ''
  const MAX_JSON = 2_000_000

  res.on('data', (chunk: Buffer) => {
    try {
      const s = chunk.toString('utf8')
      if (isSSE) {
        tail += s
        let nl: number
        while ((nl = tail.indexOf('\n')) >= 0) {
          const line = tail.slice(0, nl).trim()
          tail = tail.slice(nl + 1)
          if (line.startsWith('data:')) parseSSE(line.slice(5).trim(), acc)
        }
        // Safety cap: never let an unterminated line grow unbounded.
        if (tail.length > 65536) tail = tail.slice(-4096)
      } else if (jsonBuf.length < MAX_JSON) {
        jsonBuf += s
      }
    } catch {
      // metering must never disrupt the proxied response
    }
  })

  res.on('end', () => {
    try {
      if (!isSSE && jsonBuf) {
        const j = JSON.parse(jsonBuf) as { usage?: UsageLike }
        applyUsage(acc, j.usage)
      }
      if (acc.input || acc.output || acc.cacheRead || acc.cacheCreate) {
        const c = get(client)
        c.inputTokens += acc.input
        c.outputTokens += acc.output
        c.cacheReadTokens += acc.cacheRead
        c.cacheCreationTokens += acc.cacheCreate
        dirty = true
      }
    } catch {
      // ignore malformed bodies
    }
  })

  res.on('error', () => {})
}

function load(): void {
  if (!statePath) return
  try {
    const s = JSON.parse(readFileSync(statePath, 'utf-8')) as {
      since?: string
      clients?: Record<string, Partial<Counters>>
    }
    if (s.since) since = s.since
    if (s.clients) {
      for (const [k, v] of Object.entries(s.clients)) {
        clients.set(k, { ...emptyCounters(), ...v })
      }
    }
  } catch {
    // no prior state
  }
}

function persist(): void {
  if (!statePath || !dirty) return
  try {
    const obj = {
      since,
      updated: new Date().toISOString(),
      clients: Object.fromEntries(clients),
    }
    writeFileSync(statePath, JSON.stringify(obj, null, 2), { mode: 0o600 })
    dirty = false
  } catch (err) {
    log('warn', `usage-meter: persist failed: ${err}`)
  }
}

/** Reset per-user counters — called when the 7-day account window rolls over. */
export function resetCounters(): void {
  clients.clear()
  since = new Date().toISOString()
  dirty = true
  persist()
  log('info', 'usage-meter: per-user counters reset (new 7-day window)')
}

function fmt(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}k`
  return String(n)
}

export function summaryText(): string {
  const rows = [...clients.entries()].sort(
    (a, b) => b[1].inputTokens + b[1].outputTokens - (a[1].inputTokens + a[1].outputTokens),
  )
  const sinceStr = since.slice(0, 16).replace('T', ' ') + ' UTC'
  if (!rows.length) {
    return `📇 **CC Gateway — per-user usage**\nNo requests recorded since ${sinceStr}.`
  }
  let tReq = 0
  let tIn = 0
  let tOut = 0
  const lines = rows.map(([name, c]) => {
    tReq += c.requests
    tIn += c.inputTokens
    tOut += c.outputTokens
    const tot = c.inputTokens + c.outputTokens
    const errStr = c.errors ? ` (${c.errors} err)` : ''
    return `• **${name}** — ${c.requests} req${errStr}, ${fmt(tot)} tok (in ${fmt(c.inputTokens)} / out ${fmt(c.outputTokens)})`
  })
  return [
    `📇 **CC Gateway — per-user usage** (since ${sinceStr})`,
    ...lines,
    `— total: ${tReq} req, ${fmt(tIn + tOut)} tok (in ${fmt(tIn)} / out ${fmt(tOut)})`,
  ].join('\n')
}

export async function postReport(): Promise<void> {
  if (!webhookUrl) return
  await sendDiscord(webhookUrl, summaryText())
  log('info', 'usage-meter: posted per-user report to Discord')
}

export function initUsageMeter(opts: {
  webhook?: string
  statePath?: string
  reportIntervalHours?: number
}): void {
  webhookUrl = opts.webhook || null
  statePath = opts.statePath || resolve(process.cwd(), 'usage-meter-state.json')
  load()

  const persistTimer = setInterval(persist, 30_000)
  persistTimer.unref?.()

  const hrs = opts.reportIntervalHours ?? 0
  if (webhookUrl && hrs > 0) {
    const reportTimer = setInterval(() => void postReport(), hrs * 3_600_000)
    reportTimer.unref?.()
    log('info', `Usage meter armed: per-user report every ${hrs}h to Discord`)
  } else {
    log('info', 'Usage meter armed: metering on (no scheduled Discord report)')
  }
}
