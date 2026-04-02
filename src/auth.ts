import type { IncomingMessage } from 'http'
import type { Config, TokenEntry } from './config.js'

const tokenMap = new Map<string, TokenEntry>()

export function initAuth(config: Config) {
  tokenMap.clear()
  for (const entry of config.auth.tokens) {
    tokenMap.set(entry.token, entry)
  }
}

/**
 * Authenticate incoming request by Bearer token.
 * Returns the token entry name (for audit logging) or null if unauthorized.
 */
export function authenticate(req: IncomingMessage): string | null {
  // CC with ANTHROPIC_API_KEY sends x-api-key header
  const apiKey = req.headers['x-api-key']
  if (apiKey && typeof apiKey === 'string') {
    const entry = tokenMap.get(apiKey)
    if (entry) return entry.name
  }

  // Fallback: Bearer token in Authorization or Proxy-Authorization
  const authHeader = req.headers['proxy-authorization'] || req.headers['authorization']
  if (!authHeader || typeof authHeader !== 'string') return null

  const match = authHeader.match(/^Bearer\s+(.+)$/i)
  if (!match) return null

  const entry = tokenMap.get(match[1])
  return entry?.name ?? null
}
