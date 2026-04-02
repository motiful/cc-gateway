import { HttpsProxyAgent } from 'https-proxy-agent'
import type { Agent } from 'https'
import { log } from './logger.js'

let agent: Agent | null = null

const proxyUrl =
  process.env.HTTPS_PROXY ||
  process.env.https_proxy ||
  process.env.HTTP_PROXY ||
  process.env.http_proxy ||
  process.env.ALL_PROXY ||
  process.env.all_proxy

if (proxyUrl) {
  agent = new HttpsProxyAgent(proxyUrl)
  log('info', `Using proxy: ${proxyUrl}`)
}

export function getProxyAgent(): Agent | null {
  return agent
}
