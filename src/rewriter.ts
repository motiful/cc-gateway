import { createHash, randomBytes } from 'crypto'
import { StringDecoder } from 'string_decoder'
import type { Config } from './config.js'
import { log } from './logger.js'

export type PathPair = {
  from: string
  to: string
  // When true, the replacer only substitutes `from` if the character that
  // follows it is a word boundary (non [A-Za-z0-9_-]) or end-of-stream. Used for
  // a bare home dir (`/Users/jack`) so it never matches inside `/Users/jackson`.
  boundary?: boolean
}

/**
 * Real ↔ canonical path mapping derived once from a request, shared by the
 * forward masker (real→canonical) and the reverse map (canonical→real) so the
 * two directions can never drift apart.
 */
type PathContext = {
  canonicalHome: string // '/Users/jack/' — trailing slash
  homeReal?: string // '/Users/mac/' — real POSIX home prefix, undefined if none
  // Distinct non-home cwds (e.g. /workspace/app) → distinct canonical roots,
  // longest-real-first so the most specific prefix wins. Structure-preserving:
  // any number of separate non-home projects reverse exactly.
  nonHome: { real: string; canon: string }[]
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

// A path token ends at whitespace, quotes, brackets, or common shell/JSON/markup
// delimiters. ONE definition feeds both the boundary lookahead (PATH_BOUNDARY)
// and the username char class (excludes the same chars) so the two can never
// disagree about what terminates a path — disagreement was dropping the delimiter
// and corrupting the masked text. `.` is deliberately NOT a boundary: paths
// legitimately contain dots, and treating it as one would mis-split sibling dirs
// that share a prefix (e.g. /srv/api vs /srv/api.bak).
const PATH_BOUNDARY_INNER = '\\s"\'`<>(){}\\[\\];:,=|&$!?*'
const PATH_BOUNDARY = `[${PATH_BOUNDARY_INNER}]`

function canonicalHomeOf(config: Config): string {
  return config.prompt_env?.working_dir?.match(/^\/[^/]+\/[^/]+\//)?.[0] || '/Users/user/'
}

/**
 * Discover the real cwd / home paths a request will mask, and the canonical
 * targets they map to. Built from the authoritative env "Working directory:"
 * line(s) — NOT a generic first-/Users/ scan of the whole body, because in a
 * multi-turn session the serialized history (which precedes the system env
 * block) can already contain the canonical home from an earlier masked turn.
 */
function buildPathContext(text: string, config: Config): PathContext {
  const pe = config.prompt_env
  const canonicalHome = canonicalHomeOf(config)
  if (!pe?.working_dir) return { canonicalHome, nonHome: [] }

  // Strip trailing sentence/markup punctuation a cwd line may carry (e.g.
  // "Working directory: /srv/api.") so the captured root is exact — otherwise the
  // bogus root never matches its own subpaths and the real path leaks unmasked.
  const trimCwd = (p: string) => p.replace(/[.,;:!?)\]}>'"`]+$/, '')

  // The env block holds the primary cwd as `(Primary )?Working directory: /path`,
  // and extra roots (from --add-dir) under an `Additional working directories:`
  // header as a bullet list, one `- /abs/path` per line. Capture BOTH — missing
  // the bullet list would let those real roots leak unmasked. (We scan the raw
  // request text where newlines are JSON-escaped, but the literal space after
  // each `-` and the backslash that ends the escape keep the path captures exact.)
  const roots: string[] = [...text.matchAll(/(?:Primary )?[Ww]orking directory:\s*(\/[^\s"\\]+)/g)].map(
    (m) => m[1],
  )
  const additional = text.match(/Additional working directories:((?:(?:\\n|\n)\s*-\s*\/[^\s"\\]+)+)/)
  if (additional) {
    for (const m of additional[1].matchAll(/\/[^\s"\\]+/g)) roots.push(m[0])
  }
  const cwds = [...new Set(roots.map(trimCwd))]

  // Real POSIX home prefix. Prefer an env cwd line whose prefix differs from the
  // canonical home; fall back to a first-match body scan only when no env line
  // is present (keeps un-masking alive across multi-turn sessions).
  const homePrefixes = cwds
    .map((c) => c.match(/^\/(?:Users|home)\/[^/]+\//)?.[0])
    .filter((h): h is string => !!h)
  const homeCandidate =
    homePrefixes.find((h) => h !== canonicalHome) ??
    homePrefixes[0] ??
    text.match(/\/(?:Users|home)\/[^/\s"\\]+\//)?.[0]
  const homeReal = homeCandidate && homeCandidate !== canonicalHome ? homeCandidate : undefined

  // Distinct non-home cwds → distinct canonical roots, each a path-safe sibling of
  // working_dir so every root round-trips even with several non-home projects in
  // one request. The first reuses the bare working_dir ONLY when no home prefix is
  // in play; if a home IS masked too, even index 0 takes the -cwd0 suffix so it
  // can't alias a real home subpath that happens to share working_dir's basename
  // (e.g. real /Users/mac/projects masking to the same /Users/jack/projects).
  const nonHome: { real: string; canon: string }[] = []
  let idx = 0
  for (const c of cwds) {
    if (/^\/(?:Users|home)\/[^/]+\//.test(c)) continue // home-based, handled above
    if (nonHome.some((n) => n.real === c)) continue
    const canon = idx === 0 && !homeReal ? pe.working_dir : `${pe.working_dir}-cwd${idx}`
    nonHome.push({ real: c, canon })
    idx++
  }
  nonHome.sort((a, b) => b.real.length - a.real.length)
  return { canonicalHome, homeReal, nonHome }
}

// ── CCH hash algorithm (reverse-engineered from cli.js) ──
const CCH_SALT = '59cf53e54c78'
const CCH_POSITIONS = [4, 7, 20]

// Fallback for non-message requests where no user message exists
const FALLBACK_HASH = randomBytes(2).toString('hex').slice(0, 3)

function computeCCH(firstUserMessageText: string, version: string): string {
  const chars = CCH_POSITIONS.map(i => firstUserMessageText[i] || '0').join('')
  return createHash('sha256')
    .update(`${CCH_SALT}${chars}${version}`)
    .digest('hex')
    .slice(0, 3)
}

/**
 * Extract first user message text from API request messages array.
 * API format uses role: "user", content can be string or array of blocks.
 */
function extractFirstUserMessage(messages: any[]): string {
  if (!Array.isArray(messages)) return ''
  const firstUser = messages.find((m: any) => m.role === 'user')
  if (!firstUser) return ''
  if (typeof firstUser.content === 'string') return firstUser.content
  if (Array.isArray(firstUser.content)) {
    const textBlock = firstUser.content.find((b: any) => b.type === 'text')
    if (textBlock?.text) return textBlock.text
  }
  return ''
}

/**
 * Rewrite identity fields in the API request body.
 *
 * Handles two request types:
 * 1. /v1/messages - rewrite metadata.user_id JSON blob
 * 2. /api/event_logging/batch - rewrite event_data identity/env/process fields
 */
export type RewriteInfo = {
  // The model this request sends upstream (read-only capture, never modified).
  // Lets the proxy attribute FAILED requests to a model in metrics — the usage
  // parser only yields a model on 2xx responses, so without this every
  // 429/5xx row is model-less and per-model throttling (e.g. an exhausted
  // Opus bucket) is invisible.
  model?: string
}

export function rewriteBody(body: Buffer, path: string, config: Config, info?: RewriteInfo): Buffer {
  const text = body.toString('utf-8')

  let parsed: unknown
  try {
    parsed = JSON.parse(text)
  } catch {
    // Not JSON - pass through unchanged
    return body
  }

  if (path.startsWith('/v1/messages')) {
    rewriteMessagesBody(parsed, config, buildPathContext(text, config), info)
  } else if (path.includes('/event_logging/batch')) {
    rewriteEventBatch(parsed, config)
  } else if (path.includes('/policy_limits') || path.includes('/settings')) {
    rewriteGenericIdentity(parsed, config)
  }

  return Buffer.from(JSON.stringify(parsed), 'utf-8')
}

/**
 * Rewrite /v1/messages request body.
 *
 * Order matters:
 * 1. Rewrite user message content (paths, etc.) FIRST
 * 2. Extract first user message from REWRITTEN content
 * 3. Compute hash from rewritten message (so it matches what server sees)
 * 4. Rewrite system prompt billing header using computed hash
 */
function rewriteMessagesBody(body: any, config: Config, ctx: PathContext, info?: RewriteInfo) {
  if (info && typeof body?.model === 'string') info.model = body.model

  // Rewrite metadata.user_id
  if (body?.metadata?.user_id) {
    try {
      const userId = JSON.parse(body.metadata.user_id)
      userId.device_id = config.identity.device_id
      body.metadata.user_id = JSON.stringify(userId)
      log('debug', `Rewrote metadata.user_id device_id`)
    } catch {
      log('warn', `Failed to parse metadata.user_id`)
    }
  }

  // Step 1: Rewrite <system-reminder> blocks in messages (injected by CC, not user content).
  // We do NOT rewrite general user message text — that would corrupt user intent.
  if (Array.isArray(body.messages)) {
    for (const msg of body.messages) {
      if (typeof msg.content === 'string') {
        msg.content = rewriteSystemReminders(msg.content, config, ctx)
      } else if (Array.isArray(msg.content)) {
        for (const block of msg.content) {
          if (block?.text) {
            block.text = rewriteSystemReminders(block.text, config, ctx)
          }
        }
      }
    }
  }

  // Step 2: Extract first user message from content (after system-reminder rewrite)
  const firstUserText = extractFirstUserMessage(body.messages)

  // Step 3: Compute hash from rewritten message + canonical version
  const version = String(config.env.version)
  const hash = firstUserText ? computeCCH(firstUserText, version) : FALLBACK_HASH
  log('debug', `Computed CCH: ${hash} (from ${firstUserText.length} char message)`)

  // Step 4: Strip billing header block from system prompt (cache optimization).
  // If client set CLAUDE_CODE_ATTRIBUTION_HEADER=false, the block won't exist.
  // This is the gateway-side safety net for clients that didn't set it.
  if (Array.isArray(body.system)) {
    // Remove system blocks that are purely the billing header
    body.system = body.system.filter((item: any) => {
      const text = typeof item === 'string' ? item : item?.text
      if (typeof text === 'string' && /^\s*x-anthropic-billing-header:/.test(text)) {
        log('debug', 'Stripped billing header block from system prompt')
        return false
      }
      return true
    })

    // Rewrite remaining system blocks (env, paths, etc.)
    for (let i = 0; i < body.system.length; i++) {
      const item = body.system[i]
      if (typeof item === 'string') {
        body.system[i] = rewritePromptText(item, config, hash, ctx)
      } else if (item?.text) {
        item.text = rewritePromptText(item.text, config, hash, ctx)
      }
    }
  } else if (typeof body.system === 'string') {
    // Strip inline billing header if embedded in a single string
    body.system = body.system.replace(/x-anthropic-billing-header:[^\n]+\n?/g, '')
    body.system = rewritePromptText(body.system, config, hash, ctx)
  }
}

/**
 * Comprehensive text rewriter for system prompt and user messages.
 *
 * When hash is provided, rewrites the billing header hash.
 * When hash is null, only rewrites env/path fields (used for messages before hash computation).
 */
function rewritePromptText(
  text: string,
  config: Config,
  hash: string | null,
  ctx: PathContext,
): string {
  const pe = config.prompt_env
  if (!pe) return text

  let result = text

  // 1. Billing header fingerprint (only when hash is available)
  if (hash !== null) {
    result = result.replace(
      /cc_version=[\d.]+\.[a-f0-9]{3}/g,
      `cc_version=${config.env.version}.${hash}`,
    )
  }

  // 2. <env> block format:
  //    Platform: linux → Platform: darwin
  //    Shell: bash → Shell: zsh
  //    OS Version: Linux 6.5.0-xxx → OS Version: Darwin 24.4.0
  result = result.replace(
    /Platform:\s*\S+/g,
    `Platform: ${pe.platform}`,
  )
  result = result.replace(
    /Shell:\s*\S+/g,
    `Shell: ${pe.shell}`,
  )
  result = result.replace(
    /OS Version:\s*[^\n<]+/g,
    `OS Version: ${pe.os_version}`,
  )

  // 3. Non-home cwds (/workspace/app, /srv/api, …) → their distinct canonical
  //    roots, applied as a GLOBAL prefix swap (not just the cwd line) so every
  //    subpath under each project is masked and reverses exactly. Longest real
  //    prefix first (ctx.nonHome is pre-sorted) so /a/b wins over /a.
  for (const n of ctx.nonHome) {
    const re = new RegExp(`${escapeRegExp(n.real)}(/|(?=${PATH_BOUNDARY}|$))`, 'g')
    result = result.replace(re, (_m, slash) => `${n.canon}${slash || ''}`)
  }

  // 4. Home directory paths: /Users/xxx/… and /home/xxx/… → swap username only,
  //    keeping the rest of the path so it round-trips. Also matches a BARE home
  //    dir (/Users/xxx with no trailing slash, e.g. `cd $HOME`, `HOME=…`) via the
  //    boundary lookahead — that form previously leaked the real username.
  result = result.replace(
    new RegExp(`/(?:Users|home)/[^/${PATH_BOUNDARY_INNER}]+(/|(?=${PATH_BOUNDARY}|$))`, 'g'),
    (_m, slash) => (slash === '/' ? ctx.canonicalHome : ctx.canonicalHome.replace(/\/$/, '')),
  )

  // 5. Windows home paths: C:\Users\xxx\… → swap username only, preserving the
  //    drive and backslash structure. Forward-only privacy mask (a Windows client
  //    posed as darwin can't round-trip backslash tool paths, so it is not
  //    reverse-mapped) — the point is to not leak the real Windows username. The
  //    canonical name reuses the POSIX home username so the model sees one
  //    consistent fake identity across both path styles.
  const winUser = ctx.canonicalHome.replace(/^\/[^/]+\//, '').replace(/\/$/, '')
  result = result.replace(
    new RegExp(`([A-Za-z]:\\\\Users\\\\)[^\\\\/${PATH_BOUNDARY_INNER}]+(\\\\|(?=${PATH_BOUNDARY}|$))`, 'g'),
    (_m, head, sep) => `${head}${winUser}${sep === '\\' ? '\\' : ''}`,
  )

  return result
}

/**
 * Scan the ORIGINAL (pre-rewrite) request body for the real cwd / home paths
 * that rewritePromptText is about to mask, and return the inverse mappings
 * (canonical → real). The proxy applies these to the model's streamed response
 * so bash/file tool calls reference real paths even though the prompt was
 * masked. Returns [] when masking can't be reversed (no working_dir, no real
 * path found, or already identical) — the caller then streams through untouched.
 */
export function extractReversePathMap(
  body: Buffer,
  config: Config,
  clientHomeDir?: string,
): PathPair[] {
  const pe = config.prompt_env
  if (!pe?.working_dir || pe.reverse_paths === false) return []

  // Same context the forward masker used, inverted (canonical → real). Sharing
  // buildPathContext guarantees the two directions stay exact inverses.
  const ctx = buildPathContext(body.toString('utf-8'), config)
  const pairs: PathPair[] = []

  // Non-home projects: each distinct canonical root reverses to its real cwd.
  for (const n of ctx.nonHome) pairs.push({ from: n.canon, to: n.real })

  // Home prefix: covers ANY number of distinct projects/cwds under that home,
  // since the username swap is structure-preserving. Prefer an EXPLICIT per-client
  // home (config auth.tokens[].home_dir) over env auto-detection — it's
  // authoritative and works even when the request env line is missing or already
  // carries the canonical path. Windows homes reverse too (see winReversePairs).
  const explicit = clientHomeDir ? homeReversePairs(clientHomeDir, ctx.canonicalHome) : null
  if (explicit && explicit.length) {
    pairs.push(...explicit)
  } else if (ctx.homeReal) {
    // The bare-home pair (no trailing slash) reverses `cd $HOME` / `HOME=…` refs;
    // it is boundary-guarded so /Users/mac never matches inside /Users/jackson.
    pairs.push({ from: ctx.canonicalHome, to: ctx.homeReal })
    pairs.push({
      from: ctx.canonicalHome.replace(/\/$/, ''),
      to: ctx.homeReal.replace(/\/$/, ''),
      boundary: true,
    })
  }

  // Apply the most specific (longest) prefix first so working_dir wins over the
  // bare home prefix it contains (e.g. /Users/jack/projects before /Users/jack/).
  pairs.sort((a, b) => b.from.length - a.from.length)
  return pairs
}

/**
 * Reverse pairs (canonical → real) for an explicit per-client home dir, native
 * form autodetected:
 *   POSIX  /Users/alice, /home/alice → maps canonicalHome back to it.
 *   Windows C:\Users\alice          → maps C:\Users\<canonUser>\ back to it, in
 *     the JSON-escaped form (\\) the model's response actually carries on the
 *     wire, which is why the plain backslash form never matched before.
 */
function homeReversePairs(clientHomeDir: string, canonicalHome: string): PathPair[] {
  const real = clientHomeDir.trim().replace(/[\\/]+$/, '')
  if (!real) return []

  // Windows: C:\Users\alice
  if (/^[A-Za-z]:\\/.test(real)) {
    const drive = real[0]
    const canonUser = canonicalHome.replace(/^\/[^/]+\//, '').replace(/\/$/, '') // 'dev'
    const canonWin = `${drive}:\\Users\\${canonUser}` // C:\Users\dev
    // The SSE JSON response escapes every backslash, so a path on the wire looks
    // like C:\\Users\\dev\\foo. Match/emit in that escaped form.
    const esc = (s: string) => s.replace(/\\/g, '\\\\')
    const sep = '\\\\' // one on-wire escaped separator (two chars: \ \)
    return [
      { from: esc(canonWin) + sep, to: esc(real) + sep },
      { from: esc(canonWin), to: esc(real), boundary: true },
    ]
  }

  // POSIX: /Users/alice or /home/alice (or any absolute path)
  if (real.startsWith('/')) {
    return [
      { from: canonicalHome, to: real + '/' },
      { from: canonicalHome.replace(/\/$/, ''), to: real, boundary: true },
    ]
  }

  return []
}

/**
 * Streaming literal replacer that is safe across chunk boundaries. Holds back up
 * to (longest 'from' length − 1) chars between pushes so a search target split
 * between two network chunks still matches. StringDecoder guarantees multi-byte
 * UTF-8 characters are never cut mid-sequence. Call push() per chunk, flush() at
 * end.
 */
export function createPathReplacer(pairs: PathPair[]) {
  const decoder = new StringDecoder('utf8')
  // Longest 'from' first so a specific prefix (/Users/jack/projects) wins over a
  // shorter one it contains (/Users/jack/), and the trailing-slash home pair wins
  // over the bare-home boundary pair.
  const ordered = [...pairs].sort((a, b) => b.from.length - a.from.length)
  const maxFrom = Math.max(...ordered.map((p) => p.from.length), 1)
  let pending = '' // unreplaced carry-over: a partial prefix of some 'from'
  const isWord = (ch: string) => /[A-Za-z0-9_-]/.test(ch)

  // Positional left-to-right scan (needed for boundary pairs, which depend on the
  // char that follows the match). `atEnd` marks end-of-stream, where a boundary
  // pair's missing follow char counts as a boundary.
  const apply = (s: string, atEnd: boolean): string => {
    let out = ''
    let i = 0
    while (i < s.length) {
      let matched = false
      for (const p of ordered) {
        if (!s.startsWith(p.from, i)) continue
        if (p.boundary) {
          const next = s[i + p.from.length]
          if (next === undefined ? !atEnd : isWord(next)) continue
        }
        out += p.to
        i += p.from.length
        matched = true
        break
      }
      if (!matched) {
        out += s[i]
        i++
      }
    }
    return out
  }

  // Chars to hold back until the next chunk: (a) a suffix that is a STRICT prefix
  // of some 'from' (might still grow into a match, or into a longer one that
  // supersedes a shorter shared prefix), and (b) a full boundary-'from' sitting
  // at the very end (we need its follow char to confirm the boundary).
  const heldBack = (s: string): number => {
    const max = Math.min(s.length, maxFrom)
    for (let k = max; k >= 1; k--) {
      const suf = s.slice(s.length - k)
      for (const p of ordered) {
        const f = p.from
        if (f.length > k && f.startsWith(suf)) return k
        if (p.boundary && f.length === k && f === suf) return k
      }
    }
    return 0
  }

  return {
    push(buf: Buffer): string {
      pending += decoder.write(buf)
      const cut = pending.length - heldBack(pending)
      const head = pending.slice(0, cut)
      pending = pending.slice(cut)
      return apply(head, false)
    },
    flush(): string {
      const out = apply(pending + decoder.end(), true)
      pending = ''
      return out
    },
  }
}

/**
 * Rewrite only <system-reminder> blocks within message text.
 * These are injected by Claude Code (env info, git status, etc.) — not user-authored.
 * User-written text outside these tags is left untouched to preserve intent.
 */
function rewriteSystemReminders(text: string, config: Config, ctx: PathContext): string {
  return text.replace(
    /(<system-reminder>)([\s\S]*?)(<\/system-reminder>)/g,
    (_match, open, content, close) => {
      return open + rewritePromptText(content, config, null, ctx) + close
    },
  )
}

/**
 * Rewrite /api/event_logging/batch payload.
 * Each event has event_data with identity, env, and process fields.
 */
function rewriteEventBatch(body: any, config: Config) {
  if (!Array.isArray(body?.events)) return

  for (const event of body.events) {
    if (!event?.event_data) continue
    const data = event.event_data

    // Identity fields
    if (data.device_id) data.device_id = config.identity.device_id
    if (data.email) data.email = config.identity.email

    // Environment fingerprint - replace entirely with canonical
    if (data.env) {
      data.env = buildCanonicalEnv(config)
    }

    // Process metrics - generate realistic values
    if (data.process) {
      data.process = buildCanonicalProcess(data.process, config)
    }

    // Strip fields that leak gateway URL or proxy usage
    delete data.baseUrl
    delete data.base_url
    delete data.gateway

    // Additional metadata - rewrite base64-encoded blob if present
    if (data.additional_metadata) {
      data.additional_metadata = rewriteAdditionalMetadata(data.additional_metadata, config)
    }

    log('debug', `Rewrote event: ${data.event_name || 'unknown'}`)
  }
}

function rewriteGenericIdentity(body: any, config: Config) {
  if (typeof body !== 'object' || body === null) return
  if (body.device_id) body.device_id = config.identity.device_id
  if (body.email) body.email = config.identity.email
}

function buildCanonicalEnv(config: Config): Record<string, unknown> {
  return {
    platform: config.env.platform,
    platform_raw: config.env.platform_raw || config.env.platform,
    arch: config.env.arch,
    node_version: config.env.node_version,
    terminal: config.env.terminal,
    package_managers: config.env.package_managers,
    runtimes: config.env.runtimes,
    is_running_with_bun: config.env.is_running_with_bun ?? false,
    is_ci: false,
    is_claubbit: false,
    is_claude_code_remote: false,
    is_local_agent_mode: false,
    is_conductor: false,
    is_github_action: false,
    is_claude_code_action: false,
    is_claude_ai_auth: config.env.is_claude_ai_auth ?? true,
    version: config.env.version,
    version_base: config.env.version_base || config.env.version,
    build_time: config.env.build_time,
    deployment_environment: config.env.deployment_environment,
    vcs: config.env.vcs,
  }
}

function buildCanonicalProcess(original: any, config: Config): any {
  if (typeof original === 'string') {
    try {
      const decoded = JSON.parse(Buffer.from(original, 'base64').toString('utf-8'))
      const rewritten = rewriteProcessFields(decoded, config)
      return Buffer.from(JSON.stringify(rewritten)).toString('base64')
    } catch {
      return original
    }
  }
  if (typeof original === 'object') {
    return rewriteProcessFields(original, config)
  }
  return original
}

function rewriteProcessFields(proc: any, config: Config): any {
  const { constrained_memory, rss_range, heap_total_range, heap_used_range } = config.process
  return {
    ...proc,
    constrainedMemory: constrained_memory,
    rss: randomInRange(rss_range[0], rss_range[1]),
    heapTotal: randomInRange(heap_total_range[0], heap_total_range[1]),
    heapUsed: randomInRange(heap_used_range[0], heap_used_range[1]),
  }
}

function rewriteAdditionalMetadata(original: string, config: Config): string {
  try {
    const decoded = JSON.parse(Buffer.from(original, 'base64').toString('utf-8'))
    delete decoded.baseUrl
    delete decoded.base_url
    delete decoded.gateway
    return Buffer.from(JSON.stringify(decoded)).toString('base64')
  } catch {
    return original
  }
}

function randomInRange(min: number, max: number): number {
  return Math.floor(min + Math.random() * (max - min))
}

/**
 * Rewrite HTTP headers to canonical identity.
 * Uses the hash computed during body rewriting (getCurrentHash).
 */
export function rewriteHeaders(
  headers: Record<string, string | string[] | undefined>,
  config: Config,
): Record<string, string> {
  const out: Record<string, string> = {}

  for (const [key, value] of Object.entries(headers)) {
    if (!value) continue
    const v = Array.isArray(value) ? value.join(', ') : value
    const lower = key.toLowerCase()

    // Skip hop-by-hop headers and auth (gateway injects the real OAuth token)
    if (['host', 'connection', 'proxy-authorization', 'proxy-connection', 'transfer-encoding', 'authorization', 'x-api-key'].includes(lower)) {
      continue
    }

    if (lower === 'user-agent') {
      out[key] = `claude-code/${config.env.version} (external, cli)`
    } else if (lower === 'x-anthropic-billing-header') {
      // Strip billing header entirely — consistent with CLAUDE_CODE_ATTRIBUTION_HEADER=false
      // This also maximizes cross-session prompt cache sharing
      continue
    } else {
      out[key] = v
    }
  }

  return out
}
