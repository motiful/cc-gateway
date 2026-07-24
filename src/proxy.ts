import { createServer as createHttpsServer, type ServerOptions } from 'https'
import { createServer as createHttpServer, type IncomingMessage, type ServerResponse } from 'http'
import { readFileSync } from 'fs'
import { request as httpsRequest } from 'https'
import { URL } from 'url'
import type { Config } from './config.js'
import { authenticate, initAuth } from './auth.js'
import { getAccessToken } from './oauth.js'
import { audit, log } from './logger.js'
import { getProxyAgent } from './proxy-agent.js'
import { maybeNotifyUsage } from './usage-notify.js'
import { attachUsage, recordRequest } from './usage-meter.js'

// Headers that must NOT be forwarded upstream: hop-by-hop framing headers and
// the client's own auth (the gateway injects the real OAuth token below).
// Everything else passes through unchanged — this gateway is an OAuth-swap
// passthrough, no identity/env/path masking.
const STRIP_HEADERS = new Set([
  'host',
  'connection',
  'keep-alive',
  'upgrade',
  'proxy-authorization',
  'proxy-connection',
  'transfer-encoding',
  'content-length',
  'authorization',
  'x-api-key',
])

/**
 * Copy client request headers through unchanged, dropping only hop-by-hop
 * framing headers and the client's auth. No User-Agent / identity rewriting.
 */
function sanitizeHeaders(
  headers: Record<string, string | string[] | undefined>,
): Record<string, string> {
  const out: Record<string, string> = {}
  for (const [key, value] of Object.entries(headers)) {
    if (!value) continue
    if (STRIP_HEADERS.has(key.toLowerCase())) continue
    out[key] = Array.isArray(value) ? value.join(', ') : value
  }
  return out
}

export function startProxy(config: Config) {
  initAuth(config)

  const upstream = new URL(config.upstream.url)
  const useTls = config.server.tls?.cert && config.server.tls?.key

  // Client aborts (Ctrl+C, timeout, disconnect) surface as an 'error' event
  // on req/res or a rejection from handleRequest (e.g. the `for await` body
  // read throwing "aborted"). Left unhandled, either one crashes the whole
  // process and drops every other client's in-flight requests. Log and move
  // on instead.
  const handler = (req: IncomingMessage, res: ServerResponse) => {
    req.on('error', (err) => {
      log('warn', `Client request error: ${err.message}`)
    })
    res.on('error', (err) => {
      log('warn', `Client response error: ${err.message}`)
    })

    handleRequest(req, res, config, upstream).catch((err) => {
      log('error', `Unhandled error in handleRequest: ${err instanceof Error ? err.message : err}`)
      if (!res.headersSent) {
        try {
          res.writeHead(500, { 'Content-Type': 'application/json' })
          res.end(JSON.stringify({ error: 'Internal gateway error' }))
        } catch {
          // response socket is already gone; nothing to do
        }
      }
    })
  }

  let server
  if (useTls) {
    const tlsOptions: ServerOptions = {
      cert: readFileSync(config.server.tls.cert),
      key: readFileSync(config.server.tls.key),
    }
    server = createHttpsServer(tlsOptions, handler)
  } else {
    server = createHttpServer(handler)
    log('warn', 'Running without TLS - only use for local development')
  }

  server.listen(config.server.port, () => {
    log('info', `CC Gateway listening on ${useTls ? 'https' : 'http'}://0.0.0.0:${config.server.port}`)
    log('info', `Upstream: ${config.upstream.url}`)
    log('info', `Mode: OAuth-swap passthrough (no identity/env masking)`)
    log('info', `Authorized clients: ${config.auth.tokens.map(t => t.name).join(', ')}`)
  })

  return server
}

async function handleRequest(
  req: IncomingMessage,
  res: ServerResponse,
  config: Config,
  upstream: URL,
) {
  const method = req.method || 'GET'
  const path = req.url || '/'
  const clientIp = req.socket.remoteAddress || 'unknown'

  log('info', `← ${method} ${path} from ${clientIp}`)

  // Health check - no auth required
  if (path === '/_health') {
    const oauthOk = !!getAccessToken()
    const status = oauthOk ? 200 : 503
    res.writeHead(status, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify({
      status: oauthOk ? 'ok' : 'degraded',
      oauth: oauthOk ? 'valid' : 'expired/refreshing',
      mode: 'oauth-swap-passthrough',
      upstream: config.upstream.url,
      clients: config.auth.tokens.map(t => t.name),
    }))
    return
  }

  // Dry-run verification - shows gateway behavior (auth required)
  if (path === '/_verify') {
    const clientName = authenticate(req)
    if (!clientName) {
      res.writeHead(401, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ error: 'Unauthorized' }))
      return
    }
    const sample = buildVerificationPayload(config)
    res.writeHead(200, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify(sample, null, 2))
    return
  }

  // Authenticate client (proxy-level auth)
  const clientName = authenticate(req)
  if (!clientName) {
    res.writeHead(401, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify({ error: 'Unauthorized - provide client token via x-api-key header' }))
    log('warn', `Unauthorized request: ${method} ${path}`)
    return
  }

  log('info', `Client "${clientName}" → ${method} ${path}`)

  // Get the real OAuth token (managed by gateway)
  const oauthToken = getAccessToken()
  if (!oauthToken) {
    res.writeHead(503, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify({ error: 'OAuth token not available - gateway is refreshing' }))
    log('error', 'No valid OAuth token available')
    return
  }

  // Collect request body
  const chunks: Buffer[] = []
  for await (const chunk of req) {
    chunks.push(typeof chunk === 'string' ? Buffer.from(chunk) : chunk)
  }
  const body = Buffer.concat(chunks)

  // OAuth-swap passthrough: forward the body unchanged (no identity/env masking).
  // Only strip hop-by-hop + client-auth headers; everything else passes through.
  const forwardHeaders = sanitizeHeaders(
    req.headers as Record<string, string | string[] | undefined>,
  )

  // OAuth tokens (sk-ant-oat01-) need Authorization: Bearer; API keys (sk-ant-api03-) use x-api-key
  if (oauthToken.startsWith("sk-ant-oat01-")) {
    delete forwardHeaders["x-api-key"]
    forwardHeaders["authorization"] = "Bearer " + oauthToken
  } else {
    forwardHeaders["x-api-key"] = oauthToken
  }

  // Forward to upstream
  const upstreamUrl = new URL(path, upstream)

  const agent = getProxyAgent()
  const proxyReq = httpsRequest(
    upstreamUrl,
    {
      method,
      headers: {
        ...forwardHeaders,
        host: upstream.host,
        'content-length': String(body.length),
      },
      ...(agent && { agent }),
    },
    (proxyRes) => {
      const status = proxyRes.statusCode || 502

      const responseHeaders = { ...proxyRes.headers }
      delete responseHeaders['transfer-encoding']

      res.writeHead(status, responseHeaders)

      // Stream response directly (SSE for Claude responses)
      proxyRes.pipe(res)

      // Attribute this response's token usage to the client (non-destructive
      // tap — must be attached right after pipe() so no chunks are missed).
      attachUsage(clientName, proxyRes)
      recordRequest(clientName, status)

      // Watch the shared account's usage headers and ping Discord on 5% bands.
      maybeNotifyUsage(proxyRes.headers)

      if (config.logging.audit) {
        audit(clientName, method, path, status)
      }
    },
  )

  proxyReq.on('error', (err) => {
    log('error', `Upstream error: ${err.message}`)
    if (!res.headersSent) {
      res.writeHead(502, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ error: 'Bad gateway', detail: err.message }))
    }
    recordRequest(clientName, 502)
    if (config.logging.audit) {
      audit(clientName, method, path, 502)
    }
  })

  proxyReq.write(body)
  proxyReq.end()
}

/**
 * Describe gateway behavior for the /_verify endpoint.
 * The gateway is an OAuth-swap passthrough: request bodies and headers are
 * forwarded unchanged; only the client token is swapped for the shared OAuth
 * token and hop-by-hop/auth headers are stripped.
 */
function buildVerificationPayload(config: Config) {
  return {
    _info: 'OAuth-swap passthrough gateway',
    behavior: {
      body: 'forwarded unchanged (no identity/env/path masking)',
      headers_stripped: Array.from(STRIP_HEADERS),
      auth: 'client token swapped for shared OAuth token (Authorization: Bearer)',
    },
    upstream: config.upstream.url,
    clients: config.auth.tokens.map(t => t.name),
  }
}
