import { request as httpsRequest } from 'https'
import { createHash, randomBytes } from 'crypto'
import { log } from './logger.js'
import { getProxyAgent } from './proxy-agent.js'

const TOKEN_URL = 'https://platform.claude.com/v1/oauth/token'
// Manual ("paste the code") login flow, mirroring what the Claude Code CLI does
// when it cannot open a localhost listener. Verified against Claude Code 2.1.243.
const AUTHORIZE_URL = 'https://claude.com/cai/oauth/authorize'
const MANUAL_REDIRECT_URI = 'https://platform.claude.com/oauth/code/callback'
const CLIENT_ID = '9d1c250a-e61b-44d9-88ed-5944d1962f5e'
const DEFAULT_SCOPES = [
  'user:inference',
  'user:profile',
  'user:sessions:claude_code',
  'user:mcp_servers',
  'user:file_upload',
]

type OAuthTokens = {
  accessToken: string
  refreshToken: string
  expiresAt: number
}

/**
 * ok          — a valid access token is cached and auto-refresh is scheduled.
 * refreshing  — the access token is stale; a refresh is in flight or backing off.
 * expired     — the refresh_token itself is dead (revoked / rotated away / past
 *               its own expiry). Only an admin re-login can recover; we stop
 *               retrying so we don't hammer the token endpoint forever.
 * uninitialized — initOAuth has not run yet.
 */
export type OAuthState = 'uninitialized' | 'ok' | 'refreshing' | 'expired'

let cachedTokens: OAuthTokens | null = null
let onTokensUpdated: ((tokens: OAuthTokens) => void) | null = null

let state: OAuthState = 'uninitialized'
let lastError: string | null = null
let lastRefreshAt: number | null = null
let refreshTokenExpiresAt: number | null = null
let refreshTimer: NodeJS.Timeout | null = null
let failureCount = 0
let lastMissingTokenLog = 0

/** Thrown when the refresh_token is definitively unusable — retrying won't help. */
class OAuthPermanentError extends Error {}

export function setOnTokensUpdated(cb: (tokens: OAuthTokens) => void) {
  onTokensUpdated = cb
}

function persistTokens(tokens: OAuthTokens) {
  if (!onTokensUpdated) return
  try {
    onTokensUpdated(tokens)
  } catch (err) {
    log('warn', `Token persist callback threw: ${err instanceof Error ? err.message : err}`)
  }
}

export function getOAuthStatus() {
  return {
    state,
    expires_at: cachedTokens?.expiresAt ?? null,
    refresh_token_expires_at: refreshTokenExpiresAt,
    last_refresh_at: lastRefreshAt,
    last_error: lastError,
    login_pending: pendingLogin !== null && pendingLogin.expiresAt > Date.now(),
  }
}

/**
 * Initialize OAuth.
 * If a valid access_token is provided, use it immediately — no network call.
 * Only refresh when the token is expired or about to expire.
 *
 * Never throws: a dead refresh_token must not take the whole gateway down, or
 * the admin loses the dashboard they need in order to log in again.
 * Returns false when the gateway starts without a usable token.
 */
export async function initOAuth(oauth: {
  access_token?: string
  refresh_token: string
  expires_at?: number
}): Promise<boolean> {
  const now = Date.now()
  const expiresAt = oauth.expires_at ?? 0
  const fiveMinutes = 5 * 60 * 1000

  // Use existing access token if still valid (with 5-min buffer)
  if (oauth.access_token && expiresAt > now + fiveMinutes) {
    cachedTokens = {
      accessToken: oauth.access_token,
      refreshToken: oauth.refresh_token,
      expiresAt,
    }
    state = 'ok'
    lastError = null
    const remaining = Math.round((expiresAt - now) / 60_000)
    log('info', `Using existing access token (expires in ${remaining} min)`)
    scheduleRefresh()
    return true
  }

  // Token missing or expired — must refresh
  if (oauth.access_token) {
    log('info', 'Access token expired, refreshing...')
  } else {
    log('info', 'No access token provided, refreshing...')
  }

  state = 'refreshing'
  try {
    cachedTokens = await refreshOAuthToken(oauth.refresh_token)
  } catch (err) {
    // Keep the configured refresh_token around so the scheduled retry (for a
    // transient failure) still has something to try.
    cachedTokens = {
      accessToken: '',
      refreshToken: oauth.refresh_token,
      expiresAt: 0,
    }
    handleRefreshFailure(err)
    return false
  }

  state = 'ok'
  lastError = null
  failureCount = 0
  lastRefreshAt = Date.now()
  persistTokens(cachedTokens)
  log('info', `OAuth token acquired, expires at ${new Date(cachedTokens.expiresAt).toISOString()}`)
  scheduleRefresh()
  return true
}

function clearRefreshTimer() {
  if (refreshTimer) {
    clearTimeout(refreshTimer)
    refreshTimer = null
  }
}

/**
 * Log the failure and either schedule a backed-off retry or park in `expired`.
 * A permanent failure (invalid_grant) means the refresh_token is gone for good,
 * so we stop the retry loop and wait for an admin re-login instead.
 */
function handleRefreshFailure(err: unknown) {
  const message = err instanceof Error ? err.message : String(err)
  lastError = message
  failureCount++

  if (err instanceof OAuthPermanentError) {
    state = 'expired'
    clearRefreshTimer()
    log('error', `OAuth refresh_token is no longer valid: ${message}`)
    log('error', '  The gateway will return 503 for /v1/* until you re-authenticate.')
    log('error', '  Sign in again from the admin dashboard: /dashboard → "Re-login with Claude".')
    return
  }

  state = 'refreshing'
  // 30s, 60s, 2m, 4m, … capped at 10 minutes.
  const delay = Math.min(30_000 * 2 ** (failureCount - 1), 10 * 60_000)
  log('error', `OAuth refresh failed (attempt ${failureCount}): ${message}. Retrying in ${Math.round(delay / 1000)}s`)
  clearRefreshTimer()
  refreshTimer = setTimeout(runRefresh, delay)
}

/** (Re)arm the auto-refresh timer 5 minutes before the access token expires. */
function scheduleRefresh() {
  clearRefreshTimer()
  if (!cachedTokens) return

  const msUntilExpiry = cachedTokens.expiresAt - Date.now()
  const refreshIn = Math.max(msUntilExpiry - 5 * 60 * 1000, 10_000)
  refreshTimer = setTimeout(runRefresh, refreshIn)
}

async function runRefresh() {
  refreshTimer = null
  const refreshToken = cachedTokens?.refreshToken
  if (!refreshToken) {
    state = 'expired'
    lastError = 'no refresh_token available'
    return
  }
  try {
    log('info', 'Auto-refreshing OAuth token...')
    cachedTokens = await refreshOAuthToken(refreshToken)
    state = 'ok'
    lastError = null
    failureCount = 0
    lastRefreshAt = Date.now()
    persistTokens(cachedTokens)
    log('info', `OAuth token refreshed, expires at ${new Date(cachedTokens.expiresAt).toISOString()}`)
    scheduleRefresh()
  } catch (err) {
    handleRefreshFailure(err)
  }
}

export function getAccessToken(): string | null {
  if (!cachedTokens || !cachedTokens.accessToken) {
    logMissingToken()
    return null
  }
  if (Date.now() >= cachedTokens.expiresAt) {
    logMissingToken()
    return null
  }
  return cachedTokens.accessToken
}

/** Throttled so a burst of proxied requests can't flood the log. */
function logMissingToken() {
  const now = Date.now()
  if (now - lastMissingTokenLog < 30_000) return
  lastMissingTokenLog = now
  if (state === 'expired') {
    log('warn', 'No OAuth access token: refresh_token expired — re-login from the admin dashboard')
  } else {
    log('warn', 'No OAuth access token available, waiting for refresh...')
  }
}

// ── HTTP plumbing ──

type TokenResponse = {
  status: number
  data: Record<string, unknown> | null
  raw: string
}

/**
 * POST a JSON body to the OAuth token endpoint.
 *
 * Every failure path resolves or rejects the promise — nothing is allowed to
 * throw synchronously inside a socket event handler, because that would surface
 * as an uncaughtException and kill the process. A non-JSON body (an upstream
 * HTML error page, a captive-portal interstitial) is reported, not parsed.
 */
function postToken(body: Record<string, unknown>): Promise<TokenResponse> {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify(body)
    const url = new URL(TOKEN_URL)
    const agent = getProxyAgent()
    let settled = false
    const fail = (err: Error) => {
      if (settled) return
      settled = true
      reject(err)
    }

    const req = httpsRequest(
      {
        hostname: url.hostname,
        port: 443,
        path: url.pathname,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': String(Buffer.byteLength(payload)),
        },
        ...(agent && { agent }),
      },
      (res) => {
        const chunks: Buffer[] = []
        res.on('error', (err) => fail(err instanceof Error ? err : new Error(String(err))))
        res.on('data', (chunk) => chunks.push(chunk))
        res.on('end', () => {
          if (settled) return
          settled = true
          const raw = Buffer.concat(chunks).toString('utf-8')
          let data: Record<string, unknown> | null = null
          try {
            const parsed = JSON.parse(raw)
            if (parsed && typeof parsed === 'object') data = parsed as Record<string, unknown>
          } catch {
            data = null
          }
          resolve({ status: res.statusCode || 0, data, raw })
        })
      },
    )
    req.on('error', fail)
    req.setTimeout(30_000, () => {
      req.destroy(new Error('OAuth token request timed out after 30s'))
    })
    req.write(payload)
    req.end()
  })
}

/** Truncated response body, safe to put in a log line or the dashboard. */
function describeFailure(res: TokenResponse): string {
  if (res.data) {
    const err = typeof res.data.error === 'string' ? res.data.error : null
    const desc = typeof res.data.error_description === 'string' ? res.data.error_description : null
    if (err || desc) return `${res.status}: ${[err, desc].filter(Boolean).join(' — ')}`
    return `${res.status}: ${JSON.stringify(res.data).slice(0, 300)}`
  }
  const snippet = res.raw.replace(/\s+/g, ' ').trim().slice(0, 200)
  return `${res.status}: non-JSON response (${snippet || 'empty body'})`
}

/**
 * A 400/401 from the token endpoint means the grant itself was rejected — a
 * consumed, rotated, or revoked refresh_token. Retrying replays the same dead
 * credential, so treat it as permanent. 429/5xx stay retryable.
 */
function isPermanent(res: TokenResponse): boolean {
  if (res.status !== 400 && res.status !== 401 && res.status !== 403) return false
  const err = res.data && typeof res.data.error === 'string' ? res.data.error : ''
  if (!err) return true
  return err !== 'server_error' && err !== 'temporarily_unavailable'
}

function tokensFromResponse(data: Record<string, unknown>, fallbackRefresh: string): OAuthTokens {
  const accessToken = typeof data.access_token === 'string' ? data.access_token : ''
  if (!accessToken) throw new Error('OAuth response contained no access_token')
  const expiresIn = typeof data.expires_in === 'number' ? data.expires_in : 3600
  if (typeof data.refresh_token_expires_in === 'number') {
    refreshTokenExpiresAt = Date.now() + data.refresh_token_expires_in * 1000
  }
  return {
    accessToken,
    refreshToken: typeof data.refresh_token === 'string' && data.refresh_token
      ? data.refresh_token
      : fallbackRefresh,
    expiresAt: Date.now() + expiresIn * 1000,
  }
}

async function refreshOAuthToken(refreshToken: string): Promise<OAuthTokens> {
  const res = await postToken({
    grant_type: 'refresh_token',
    refresh_token: refreshToken,
    client_id: CLIENT_ID,
    scope: DEFAULT_SCOPES.join(' '),
  })
  if (res.status !== 200 || !res.data) {
    const message = `OAuth refresh failed (${describeFailure(res)})`
    throw isPermanent(res) ? new OAuthPermanentError(message) : new Error(message)
  }
  return tokensFromResponse(res.data, refreshToken)
}

// ── Admin re-login (OAuth 2.0 authorization code + PKCE, manual paste flow) ──

type PendingLogin = {
  verifier: string
  state: string
  expiresAt: number
}

const LOGIN_TTL_MS = 15 * 60 * 1000
let pendingLogin: PendingLogin | null = null

function b64url(buf: Buffer): string {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/**
 * Start a re-login. Returns the URL the admin opens in their own browser; the
 * PKCE verifier stays here in memory so the pasted code is worthless to anyone
 * who intercepts it. Calling this again discards any previous pending login.
 */
export function beginOAuthLogin(): { url: string; expires_in_ms: number } {
  const verifier = b64url(randomBytes(32))
  const challenge = b64url(createHash('sha256').update(verifier).digest())
  const loginState = b64url(randomBytes(24))

  pendingLogin = { verifier, state: loginState, expiresAt: Date.now() + LOGIN_TTL_MS }

  const url = new URL(AUTHORIZE_URL)
  url.searchParams.append('code', 'true')
  url.searchParams.append('client_id', CLIENT_ID)
  url.searchParams.append('response_type', 'code')
  url.searchParams.append('redirect_uri', MANUAL_REDIRECT_URI)
  url.searchParams.append('scope', DEFAULT_SCOPES.join(' '))
  url.searchParams.append('code_challenge', challenge)
  url.searchParams.append('code_challenge_method', 'S256')
  url.searchParams.append('state', loginState)

  return { url: url.toString(), expires_in_ms: LOGIN_TTL_MS }
}

export function cancelOAuthLogin() {
  pendingLogin = null
}

/**
 * The callback page shows the code as `<code>#<state>`; some browsers hand back
 * the whole redirect URL instead. Accept both, plus a bare code.
 */
function parsePastedCode(input: string): { code: string; state: string | null } {
  let value = input.trim()
  if (/^https?:\/\//i.test(value)) {
    try {
      const url = new URL(value)
      const code = url.searchParams.get('code') || ''
      return { code: code.trim(), state: url.searchParams.get('state') }
    } catch {
      // fall through to the plain-string handling below
    }
  }
  value = value.replace(/^code=/i, '')
  const hash = value.indexOf('#')
  if (hash === -1) return { code: value, state: null }
  return { code: value.slice(0, hash).trim(), state: value.slice(hash + 1).trim() || null }
}

/**
 * Finish a re-login: exchange the pasted authorization code for a fresh token
 * pair, swap it in live, and persist it. On success the gateway is serving
 * again with no restart.
 */
export async function completeOAuthLogin(pasted: string): Promise<{ expires_at: number }> {
  const pending = pendingLogin
  if (!pending) {
    throw new Error('No login in progress — start a new one')
  }
  if (pending.expiresAt <= Date.now()) {
    pendingLogin = null
    throw new Error('Login request expired — start a new one')
  }

  const { code, state: pastedState } = parsePastedCode(pasted)
  if (!code) throw new Error('No authorization code found in the pasted value')
  if (pastedState && pastedState !== pending.state) {
    throw new Error('State mismatch — the pasted code belongs to a different login attempt')
  }

  const res = await postToken({
    grant_type: 'authorization_code',
    code,
    redirect_uri: MANUAL_REDIRECT_URI,
    client_id: CLIENT_ID,
    code_verifier: pending.verifier,
    state: pending.state,
  })
  if (res.status !== 200 || !res.data) {
    throw new Error(`Token exchange failed (${describeFailure(res)})`)
  }

  const tokens = tokensFromResponse(res.data, '')
  if (!tokens.refreshToken) {
    throw new Error('Token exchange returned no refresh_token')
  }

  pendingLogin = null
  cachedTokens = tokens
  state = 'ok'
  lastError = null
  failureCount = 0
  lastRefreshAt = Date.now()
  persistTokens(tokens)
  scheduleRefresh()
  log('info', `OAuth re-login succeeded, token expires at ${new Date(tokens.expiresAt).toISOString()}`)
  return { expires_at: tokens.expiresAt }
}
