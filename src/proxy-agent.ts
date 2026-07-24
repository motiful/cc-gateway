import { HttpsProxyAgent } from 'https-proxy-agent'
import type { Agent } from 'https'
import { readFileSync } from 'fs'
import { resolve } from 'path'
import { log } from './logger.js'

// cc-health.sh switches egress tiers by writing the chosen proxy URL here and
// sending SIGHUP, so a tier flap doesn't require restarting the whole process
// (which would drop every in-flight client request and re-run OAuth init).
// Falls back to the env vars for a fresh process that hasn't been reloaded yet.
const PROXY_FILE = resolve(process.cwd(), 'active-proxy.txt')

let agent: Agent | null = null

function resolveProxyUrl(): string | undefined {
  try {
    const fromFile = readFileSync(PROXY_FILE, 'utf-8').trim()
    if (fromFile) return fromFile
  } catch {
    // no state file yet — fall back to env
  }
  return (
    process.env.HTTPS_PROXY ||
    process.env.https_proxy ||
    process.env.HTTP_PROXY ||
    process.env.http_proxy ||
    process.env.ALL_PROXY ||
    process.env.all_proxy
  )
}

function buildAgent(): void {
  const proxyUrl = resolveProxyUrl()
  agent = proxyUrl ? new HttpsProxyAgent(proxyUrl) : null
  log('info', proxyUrl ? `Using proxy: ${proxyUrl}` : 'No proxy configured')
}

buildAgent()

export function getProxyAgent(): Agent | null {
  return agent
}

/** Re-read the active proxy (file or env) and rebuild the agent in place. */
export function reloadProxyAgent(): void {
  buildAgent()
}
