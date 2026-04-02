import { request as httpsRequest } from 'https'
import { log } from './logger.js'
import { getProxyAgent } from './proxy-agent.js'

const TOKEN_URL = 'https://platform.claude.com/v1/oauth/token'
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

let cachedTokens: OAuthTokens | null = null

/**
 * Initialize OAuth.
 * If a valid access_token is provided, use it immediately — no network call.
 * Only refresh when the token is expired or about to expire.
 */
export async function initOAuth(oauth: {
  access_token?: string
  refresh_token: string
  expires_at?: number
}): Promise<void> {
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
    const remaining = Math.round((expiresAt - now) / 60_000)
    log('info', `Using existing access token (expires in ${remaining} min)`)
    scheduleRefresh(oauth.refresh_token)
    return
  }

  // Token missing or expired — must refresh
  if (oauth.access_token) {
    log('info', 'Access token expired, refreshing...')
  } else {
    log('info', 'No access token provided, refreshing...')
  }

  cachedTokens = await refreshOAuthToken(oauth.refresh_token)
  log('info', `OAuth token acquired, expires at ${new Date(cachedTokens.expiresAt).toISOString()}`)
  scheduleRefresh(oauth.refresh_token)
}

function scheduleRefresh(refreshToken: string) {
  if (!cachedTokens) return

  const msUntilExpiry = cachedTokens.expiresAt - Date.now()
  const refreshIn = Math.max(msUntilExpiry - 5 * 60 * 1000, 10_000)

  setTimeout(async () => {
    try {
      log('info', 'Auto-refreshing OAuth token...')
      cachedTokens = await refreshOAuthToken(
        cachedTokens?.refreshToken || refreshToken,
      )
      log('info', `OAuth token refreshed, expires at ${new Date(cachedTokens.expiresAt).toISOString()}`)
      scheduleRefresh(cachedTokens.refreshToken || refreshToken)
    } catch (err) {
      log('error', `OAuth refresh failed: ${err}. Retrying in 30s...`)
      setTimeout(() => scheduleRefresh(refreshToken), 30_000)
    }
  }, refreshIn)
}

export function getAccessToken(): string | null {
  if (!cachedTokens) return null
  if (Date.now() >= cachedTokens.expiresAt) {
    log('warn', 'OAuth token expired, waiting for refresh...')
    return null
  }
  return cachedTokens.accessToken
}

function refreshOAuthToken(refreshToken: string): Promise<OAuthTokens> {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      client_id: CLIENT_ID,
      scope: DEFAULT_SCOPES.join(' '),
    })

    const url = new URL(TOKEN_URL)
    const agent = getProxyAgent()
    const req = httpsRequest(
      {
        hostname: url.hostname,
        port: 443,
        path: url.pathname,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': String(Buffer.byteLength(body)),
        },
        ...(agent && { agent }),
      },
      (res) => {
        const chunks: Buffer[] = []
        res.on('data', (chunk) => chunks.push(chunk))
        res.on('end', () => {
          const data = JSON.parse(Buffer.concat(chunks).toString('utf-8'))
          if (res.statusCode !== 200) {
            reject(new Error(`OAuth refresh failed (${res.statusCode}): ${JSON.stringify(data)}`))
            return
          }
          resolve({
            accessToken: data.access_token,
            refreshToken: data.refresh_token || refreshToken,
            expiresAt: Date.now() + (data.expires_in || 3600) * 1000,
          })
        })
      },
    )
    req.on('error', reject)
    req.write(body)
    req.end()
  })
}
