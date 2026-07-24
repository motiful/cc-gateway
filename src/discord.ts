import { request as httpsRequest } from 'https'
import { log } from './logger.js'
import { getProxyAgent } from './proxy-agent.js'

// Shared Discord webhook sender. Routes through the gateway's egress proxy,
// caps content at Discord's 2000-char limit, and never throws — a webhook
// failure must never affect a client request.
export function sendDiscord(webhook: string, content: string): Promise<void> {
  return new Promise((done) => {
    let url: URL
    try {
      url = new URL(webhook)
    } catch {
      log('warn', 'discord: invalid webhook URL')
      return done()
    }

    const body = JSON.stringify({ content: content.slice(0, 1990), username: 'CC Gateway' })
    const agent = getProxyAgent()
    const req = httpsRequest(
      {
        hostname: url.hostname,
        port: 443,
        path: url.pathname + url.search,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': String(Buffer.byteLength(body)),
        },
        ...(agent && { agent }),
      },
      (res) => {
        res.on('data', () => {})
        res.on('end', () => {
          if (res.statusCode && res.statusCode >= 400) {
            log('warn', `discord: webhook returned ${res.statusCode}`)
          }
          done()
        })
      },
    )
    req.on('error', (err) => {
      log('warn', `discord: webhook failed: ${err.message}`)
      done()
    })
    req.write(body)
    req.end()
  })
}
