import { request as httpsRequest } from 'https'
import { log } from './logger.js'
import { persistRefreshToken } from './config.js'

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
 * Initialize OAuth with a refresh token.
 * The gateway holds the refresh token and manages access token lifecycle.
 * Client machines never need to contact platform.claude.com.
 */
export async function initOAuth(refreshToken: string): Promise<void> {
  log('info', 'Refreshing OAuth token...')
  cachedTokens = await refreshOAuthToken(refreshToken)
  log('info', `OAuth token acquired, expires at ${new Date(cachedTokens.expiresAt).toISOString()}`)

  // Auto-refresh 5 minutes before expiry
  scheduleRefresh(refreshToken)
}

function scheduleRefresh(refreshToken: string) {
  if (!cachedTokens) return

  const msUntilExpiry = cachedTokens.expiresAt - Date.now()
  const refreshIn = Math.max(msUntilExpiry - 5 * 60 * 1000, 10_000) // 5 min before expiry, minimum 10s

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

/**
 * Get the current valid access token.
 * Returns null if no token available.
 */
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
          const newRefreshToken = data.refresh_token || refreshToken
          if (data.refresh_token && data.refresh_token !== refreshToken) {
            log('info', 'Refresh token rotated, persisting to config...')
            try {
              persistRefreshToken(data.refresh_token)
            } catch (err) {
              log('error', `Failed to persist rotated refresh token: ${err}`)
            }
          }
          resolve({
            accessToken: data.access_token,
            refreshToken: newRefreshToken,
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
