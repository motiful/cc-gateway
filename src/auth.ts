import type { IncomingMessage } from 'http'
import type { Config, TokenEntry } from './config.js'

const tokenMap = new Map<string, TokenEntry>()

export function initAuth(config: Config) {
  setAuthTokens(config.auth.tokens)
}

/** Replace the in-memory token map. Call after mutating config.yaml's auth.tokens. */
export function setAuthTokens(tokens: TokenEntry[]) {
  tokenMap.clear()
  for (const entry of tokens) {
    tokenMap.set(entry.token, entry)
  }
}

/** Look up a client entry by its raw token (used by the client self-service portal login). */
export function lookupToken(token: string): TokenEntry | null {
  if (!token) return null
  return tokenMap.get(token) ?? null
}

/**
 * Authenticate incoming request by Bearer token.
 * Returns the matched TokenEntry (so callers can read name + cost limit) or null.
 */
export function authenticate(req: IncomingMessage): TokenEntry | null {
  // CC with ANTHROPIC_API_KEY sends x-api-key header
  const apiKey = req.headers['x-api-key']
  if (apiKey && typeof apiKey === 'string') {
    const entry = tokenMap.get(apiKey)
    if (entry) return entry
  }

  // Bearer token in Authorization or Proxy-Authorization
  const authHeader = req.headers['proxy-authorization'] || req.headers['authorization']
  if (authHeader && typeof authHeader === 'string') {
    const match = authHeader.match(/^Bearer\s+(.+)$/i)
    if (match) {
      const entry = tokenMap.get(match[1])
      if (entry) return entry
    }
  }

  return null
}
