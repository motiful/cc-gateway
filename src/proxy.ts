import { createServer as createHttpsServer, type ServerOptions } from 'https'
import { createServer as createHttpServer, type IncomingMessage, type ServerResponse } from 'http'
import { readFileSync } from 'fs'
import { request as httpsRequest } from 'https'
import { URL } from 'url'
import zlib from 'zlib'
import type { Config } from './config.js'
import { authenticate, initAuth, setAuthTokens } from './auth.js'
import {
  getAccessToken,
  getOAuthStatus,
  beginOAuthLogin,
  completeOAuthLogin,
  cancelOAuthLogin,
} from './oauth.js'
import { rewriteBody, rewriteHeaders, extractReversePathMap, createPathReplacer, type RewriteInfo } from './rewriter.js'
import { extractRequestPreview } from './preview.js'
import { audit, log } from './logger.js'
import { getProxyAgent } from './proxy-agent.js'
import { recordRequest, getMetricsSnapshot, getClientCostSince, getClientStats, getClientModels, getClientRecent, periodStart } from './metrics.js'
import { SSEUsageParser } from './usage-parser.js'
import { computeCost } from './pricing.js'
import { captureRateLimitHeaders } from './ratelimit.js'
import { renderDashboard, renderLogin } from './dashboard.js'
import { renderPortal, renderPortalLogin } from './portal.js'
import { renderLanding } from './landing.js'
import { authenticateUser } from './users.js'
import {
  generateAndSetClientPassword,
  verifyClientPassword,
  changeClientPassword,
  removeClientPassword,
  getClientCredentialMeta,
} from './client-auth.js'
import { getClientProfile, setClientProfile, removeClientProfile } from './client-profile.js'
import {
  createSessionCookie,
  setCookieHeader,
  clearCookieHeader,
  getSessionFromRequest,
  createPortalCookie,
  setPortalCookieHeader,
  clearPortalCookieHeader,
  getPortalSessionFromRequest,
  createInstallGrant,
  verifyInstallGrant,
} from './session.js'
import { addClient, listClients, removeClient, setClientLimit, setClientHomeDir, buildLauncherScript, buildPowerShellLauncherScript, buildUnixInstaller, buildPowerShellInstaller } from './clients.js'
import type { CostLimitPeriod } from './config.js'

/** Refresh in-memory token map from current config.yaml on disk. */
function reloadAuthFromConfig(): void {
  setAuthTokens(listClients())
}

export function startProxy(config: Config) {
  initAuth(config)

  const upstream = new URL(config.upstream.url)
  const useTls = config.server.tls?.cert && config.server.tls?.key

  const handler = (req: IncomingMessage, res: ServerResponse) => {
    handleRequest(req, res, config, upstream)
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
    log('info', `Canonical device_id: ${config.identity.device_id.slice(0, 8)}...`)
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
  const pathname = path.split('?')[0]
  const clientIp = req.socket.remoteAddress || 'unknown'
  const startedAt = Date.now()

  log('info', `← ${method} ${path} from ${clientIp}`)

  // Health check - no auth required
  if (pathname === '/_health') {
    const oauthOk = !!getAccessToken()
    const oauthStatus = getOAuthStatus()
    const status = oauthOk ? 200 : 503
    res.writeHead(status, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify({
      status: oauthOk ? 'ok' : 'degraded',
      oauth: oauthOk ? 'valid' : 'expired/refreshing',
      oauth_state: oauthStatus.state,
      oauth_error: oauthStatus.last_error,
      canonical_device: config.identity.device_id.slice(0, 8) + '...',
      canonical_platform: config.env.platform,
      upstream: config.upstream.url,
      clients: config.auth.tokens.map(t => t.name),
    }))
    return
  }

  // Public landing + admin area (admin login moved to /admin) + dashboard APIs.
  if (
    pathname === '/' ||
    pathname === '/admin' ||
    pathname === '/admin/login' ||
    pathname === '/admin/logout' ||
    pathname === '/login' ||
    pathname === '/logout' ||
    pathname === '/dashboard' ||
    pathname === '/_metrics' ||
    pathname === '/api/clients' ||
    pathname.startsWith('/api/clients/') ||
    pathname === '/api/oauth' ||
    pathname.startsWith('/api/oauth/')
  ) {
    await handleDashboardArea(req, res, pathname, method)
    return
  }

  // Client self-service portal (token-authenticated, separate from admin area)
  if (pathname === '/portal' || pathname.startsWith('/portal/')) {
    await handlePortalArea(req, res, pathname, method)
    return
  }

  // Dry-run verification - shows what would be rewritten (auth required)
  if (pathname === '/_verify') {
    const entry = authenticate(req)
    if (!entry) {
      res.writeHead(401, { 'Content-Type': 'application/json', 'x-ccg-error': 'unauthorized' })
      res.end(JSON.stringify({ error: 'Unauthorized' }))
      return
    }
    const sample = buildVerificationPayload(config)
    res.writeHead(200, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify(sample, null, 2))
    return
  }

  // Authenticate client (proxy-level auth)
  const tokenEntry = authenticate(req)
  if (!tokenEntry) {
    res.writeHead(401, { 'Content-Type': 'application/json', 'x-ccg-error': 'unauthorized' })
    res.end(JSON.stringify({ error: 'Unauthorized - provide client token via x-api-key header' }))
    log('warn', `Unauthorized request: ${method} ${path}`)
    return
  }
  const clientName = tokenEntry.name

  // Cost limit enforcement: only gates billable inference (/v1/messages).
  // Health, settings, event_logging, etc. are free and shouldn't be blocked.
  if (pathname.startsWith('/v1/messages') && tokenEntry.cost_limit_usd && tokenEntry.cost_limit_usd > 0) {
    const since = periodStart(tokenEntry.cost_limit_period)
    const used = getClientCostSince(clientName, since)
    if (used >= tokenEntry.cost_limit_usd) {
      const periodLabel = tokenEntry.cost_limit_period || 'lifetime'
      res.writeHead(429, { 'Content-Type': 'application/json', 'x-ccg-error': 'cost-limit' })
      res.end(JSON.stringify({
        error: 'Cost limit reached',
        client: clientName,
        period: periodLabel,
        used_usd: Number(used.toFixed(4)),
        limit_usd: tokenEntry.cost_limit_usd,
      }))
      log('warn', `Client "${clientName}" blocked: ${periodLabel} cost ${used.toFixed(4)} >= limit ${tokenEntry.cost_limit_usd}`)
      recordRequest({
        ts: startedAt,
        client: clientName,
        method,
        path: pathname,
        status: 429,
        durationMs: Date.now() - startedAt,
        errorSource: 'gateway',
        errorDetail: `cost limit reached: ${used.toFixed(4)}/${tokenEntry.cost_limit_usd} USD (${periodLabel})`,
      })
      if (config.logging.audit) audit(clientName, method, path, 429)
      return
    }
  }

  log('info', `Client "${clientName}" → ${method} ${path}`)

  // Get the real OAuth token (managed by gateway)
  const oauthToken = getAccessToken()
  if (!oauthToken) {
    res.writeHead(503, { 'Content-Type': 'application/json', 'x-ccg-error': 'oauth-refreshing' })
    res.end(JSON.stringify({ error: 'OAuth token not available - gateway is refreshing' }))
    log('error', 'No valid OAuth token available')
    recordRequest({
      ts: startedAt,
      client: clientName,
      method,
      path: pathname,
      status: 503,
      durationMs: Date.now() - startedAt,
      errorSource: 'gateway',
      errorDetail: 'oauth token unavailable (refreshing)',
    })
    if (config.logging.audit) audit(clientName, method, path, 503)
    return
  }

  // Collect request body
  const chunks: Buffer[] = []
  for await (const chunk of req) {
    chunks.push(typeof chunk === 'string' ? Buffer.from(chunk) : chunk)
  }
  let body = Buffer.concat(chunks)

  // Capture a preview of the request's actual last message (human prompt,
  // tool_result payload, classifier text, …) for the dashboard, before rewrite
  // so parsing isn't re-done on a JSON we just serialized. Best-effort — never
  // blocks the call.
  let userMessage = ''
  if (body.length > 0 && pathname.startsWith('/v1/messages') && method === 'POST') {
    userMessage = extractRequestPreview(body)
  }

  // Capture the real cwd / home paths BEFORE masking so the model's response
  // can be reversed back to them. Keeps path masking on (privacy) while bash /
  // file tool calls still hit real paths instead of the canonical /Users/jack.
  const reversePairs =
    body.length > 0 && pathname.startsWith('/v1/messages')
      ? extractReversePathMap(body, config, tokenEntry.home_dir)
      : []

  // Rewrite identity fields in body
  const rewriteInfo: RewriteInfo = {}
  if (body.length > 0) {
    try {
      body = rewriteBody(body, path, config, rewriteInfo) as Buffer<ArrayBuffer>
    } catch (err) {
      log('error', `Body rewrite failed for ${path}: ${err}`)
    }
  }

  // Rewrite headers (strips client auth, normalizes identity headers)
  const rewrittenHeaders = rewriteHeaders(
    req.headers as Record<string, string | string[] | undefined>,
    config,
  )

  // Inject the OAuth access_token. Anthropic OAuth tokens (sk-ant-oat01-) must
  // be sent via Authorization: Bearer with the anthropic-beta: oauth-2025-04-20
  // flag — sending them via x-api-key returns 401 "Invalid authentication
  // credentials". rewriteHeaders() already stripped any inbound auth headers.
  delete rewrittenHeaders['x-api-key']
  rewrittenHeaders['authorization'] = `Bearer ${oauthToken}`

  const oauthBetaFlag = 'oauth-2025-04-20'
  const existingBeta = rewrittenHeaders['anthropic-beta']
  if (existingBeta) {
    if (!existingBeta.split(',').map((s) => s.trim()).includes(oauthBetaFlag)) {
      rewrittenHeaders['anthropic-beta'] = `${existingBeta},${oauthBetaFlag}`
    }
  } else {
    rewrittenHeaders['anthropic-beta'] = oauthBetaFlag
  }

  // Forward to upstream
  const upstreamUrl = new URL(path, upstream)

  const agent = getProxyAgent()
  const proxyReq = httpsRequest(
    upstreamUrl,
    {
      method,
      headers: {
        ...rewrittenHeaders,
        host: upstream.host,
        'content-length': String(body.length),
      },
      ...(agent && { agent }),
    },
    (proxyRes) => {
      const status = proxyRes.statusCode || 502

      // Snapshot the account-wide quota headers (anthropic-ratelimit-unified-*)
      // Anthropic returns on every /v1/messages response — the dashboard surfaces
      // 5h/weekly "session used %" and reset times from this. No-op when absent.
      captureRateLimitHeaders(proxyRes.headers)

      // Surface upstream throttling distinctly from the gateway's own
      // cost-limit 429 (handled above). Anthropic returns 429 (rate_limit_error)
      // or 529 (overloaded) when our shared OAuth account hits its rate cap; the
      // client retries per retry-after and usually gets 200 on the next attempt,
      // which is the "429 rồi lại 200" pattern. Logging it explicitly makes the
      // shared-account throttling visible instead of looking like a cost block.
      if (status === 429 || status === 529) {
        const retryAfter = proxyRes.headers['retry-after']
        // Anthropic tells us exactly which bucket is exhausted via its
        // anthropic-ratelimit-* headers (requests / input-tokens / output-tokens
        // / tokens), and for OAuth/Claude-subscription accounts via the
        // anthropic-ratelimit-unified-* family (5h + weekly usage windows).
        // Surfacing them turns "mystery 429" into a named limit so we can tell a
        // big-single-request ITPM hit apart from a shared-account usage cap.
        const rateLimitHeaders = Object.entries(proxyRes.headers)
          .filter(([k]) => k.toLowerCase().startsWith('anthropic-ratelimit'))
          .map(([k, v]) => `${k}=${v}`)
        log(
          'warn',
          `Upstream throttled "${clientName}": ${status} ${method} ${path}` +
            (retryAfter ? ` (retry-after: ${retryAfter}s)` : '') +
            (rateLimitHeaders.length ? ` [${rateLimitHeaders.join(' ')}]` : ''),
        )
      }

      // Three response modes for /v1/messages:
      //  - wantRewrite: decode → reverse masked paths → stream identity bytes
      //    (needed so the model's tool calls hit real paths). Also parses usage.
      //  - parser only: forward raw bytes byte-identical, decode a copy for usage.
      //  - neither: cheap passthrough.
      const isMessages = pathname.startsWith('/v1/messages')
      const wantUsage = isMessages && status >= 200 && status < 300
      const wantRewrite = isMessages && reversePairs.length > 0

      const responseHeaders = { ...proxyRes.headers }
      delete responseHeaders['transfer-encoding']
      if (wantRewrite) {
        // We re-emit path-rewritten bytes RE-COMPRESSED with the same
        // content-encoding (so the wire stays gzip/br/deflate exactly as
        // upstream sent it), but the byte length changes — drop content-length
        // and let the response be chunked. content-encoding is kept as-is.
        delete responseHeaders['content-length']
      }

      res.writeHead(status, responseHeaders)

      const parser = wantUsage ? new SSEUsageParser() : null

      // Anything >=400 reaching this callback came FROM upstream (gateway-
      // generated errors return before forwarding). The detail is filled once
      // the error body has been buffered and decoded below.
      let errorSource: 'gateway' | 'upstream' | '' = ''
      let errorDetail = ''

      let finalized = false
      const finalize = () => {
        if (finalized) return
        finalized = true
        const usage = parser?.result()
        const cost = usage && usage.model
          ? computeCost(usage.model, usage, startedAt)
          : 0
        recordRequest({
          ts: startedAt,
          client: clientName,
          method,
          path: pathname,
          status,
          durationMs: Date.now() - startedAt,
          // Usage parser only yields a model on 2xx — fall back to the model we
          // sent upstream so 429/5xx rows are attributable per-model in the
          // dashboard (e.g. an exhausted Opus bucket vs a healthy Sonnet one).
          model: usage?.model ?? rewriteInfo.model,
          inputTokens: usage?.inputTokens,
          outputTokens: usage?.outputTokens,
          cacheReadTokens: usage?.cacheReadTokens,
          cacheCreationTokens: usage?.cacheCreationTokens,
          costUsd: cost,
          userMessage,
          errorSource,
          errorDetail,
        })
        if (config.logging.audit) {
          audit(clientName, method, path, status)
        }
      }

      const encoding = String(proxyRes.headers['content-encoding'] || '')
        .toLowerCase()
        .trim()
      const makeDecoder = (): zlib.Gunzip | zlib.BrotliDecompress | zlib.Inflate | null =>
        encoding === 'gzip' ? zlib.createGunzip()
        : encoding === 'br' ? zlib.createBrotliDecompress()
        : encoding === 'deflate' ? zlib.createInflate()
        : null
      const makeEncoder = (): zlib.Gzip | zlib.BrotliCompress | zlib.Deflate | null =>
        encoding === 'gzip' ? zlib.createGzip()
        : encoding === 'br' ? zlib.createBrotliCompress()
        : encoding === 'deflate' ? zlib.createDeflate()
        : null

      if (status >= 400) {
        errorSource = 'upstream'
        // Error responses (4xx/5xx) are small JSON, not SSE — buffer a copy
        // while forwarding the raw bytes byte-identical to the client, then
        // decode and log Anthropic's actual error payload (type + message). This
        // turns an opaque "429/400/500" into the real reason upstream gave us
        // (rate_limit_error vs invalid_request_error vs overloaded_error, etc.).
        const ERR_LOG_CAP = 4096
        const errChunks: Buffer[] = []
        let errBytes = 0
        proxyRes.on('data', (chunk: Buffer) => {
          res.write(chunk)
          if (errBytes < ERR_LOG_CAP) {
            errChunks.push(chunk)
            errBytes += chunk.length
          }
        })
        proxyRes.on('end', () => {
          res.end()
          const raw = Buffer.concat(errChunks)
          let text = ''
          try {
            text =
              encoding === 'gzip' ? zlib.gunzipSync(raw).toString('utf8')
              : encoding === 'br' ? zlib.brotliDecompressSync(raw).toString('utf8')
              : encoding === 'deflate' ? zlib.inflateSync(raw).toString('utf8')
              : raw.toString('utf8')
          } catch {
            text = raw.toString('utf8')
          }
          const body = text.replace(/\s+/g, ' ').trim().slice(0, ERR_LOG_CAP)
          errorDetail = body.slice(0, 500)
          log('warn', `Upstream ${status} for "${clientName}" ${method} ${path}: ${body}`)
          finalize()
        })
        proxyRes.on('error', (err) => {
          log('error', `Upstream stream error: ${err.message}`)
          res.end()
          finalize()
        })
      } else if (wantRewrite) {
        // upstream → [decoder] → reverse paths → [encoder] → client.
        // The encoder re-compresses with the SAME content-encoding so the wire
        // stays gzip/br/deflate; when upstream sent identity, both are null and
        // plaintext flows straight through.
        const decoder = makeDecoder()
        const encoder = makeEncoder()
        const replacer = createPathReplacer(reversePairs)
        let ended = false

        // Sink for rewritten plaintext: through the encoder if re-compressing,
        // else straight to the client.
        const writeOut = (s: string) => {
          if (!s) return
          if (encoder) encoder.write(s)
          else res.write(s)
        }
        const onDecoded = (buf: Buffer) => {
          if (parser) parser.feed(buf)
          writeOut(replacer.push(buf))
        }
        const done = () => {
          if (ended) return
          ended = true
          writeOut(replacer.flush())
          parser?.end()
          // Closing the encoder flushes the final compressed bytes; its 'end'
          // event ends the client response. Without an encoder, end directly.
          if (encoder) encoder.end()
          else res.end()
          finalize()
        }

        if (encoder) {
          encoder.on('data', (b: Buffer) => res.write(b))
          encoder.on('end', () => res.end())
          encoder.on('error', (err: Error) => {
            log('error', `Reverse-path encoder failed (${encoding}): ${err.message}`)
            res.end()
          })
        }
        if (decoder) {
          decoder.on('data', onDecoded)
          decoder.on('end', done)
          decoder.on('error', (err: Error) => {
            log('warn', `Reverse-path decoder failed (${encoding}): ${err.message}`)
            done()
          })
        }
        proxyRes.on('data', (chunk: Buffer) => {
          if (decoder) decoder.write(chunk)
          else onDecoded(chunk)
        })
        proxyRes.on('end', () => {
          if (decoder) decoder.end()
          else done()
        })
        proxyRes.on('error', (err) => {
          log('error', `Upstream stream error: ${err.message}`)
          done()
        })
      } else if (parser) {
        // Forward raw upstream bytes to the client untouched so the response
        // is byte-identical to a direct Anthropic call (preserves whatever
        // Content-Encoding upstream chose). For the parser, decompress a
        // local copy in-process so token counts stay readable regardless of
        // gzip/br/deflate.
        const decoder = makeDecoder()
        if (decoder) {
          decoder.on('data', (decoded: Buffer) => parser.feed(decoded))
          decoder.on('error', (err: Error) => {
            log('warn', `Usage decoder failed (${encoding}): ${err.message}`)
          })
        }

        proxyRes.on('data', (chunk: Buffer) => {
          res.write(chunk)
          if (decoder) decoder.write(chunk)
          else parser.feed(chunk)
        })
        proxyRes.on('end', () => {
          if (decoder) decoder.end()
          parser.end()
          res.end()
          finalize()
        })
        proxyRes.on('error', (err) => {
          log('error', `Upstream stream error: ${err.message}`)
          if (decoder) decoder.destroy()
          res.end()
          finalize()
        })
      } else {
        proxyRes.pipe(res)
        proxyRes.on('end', finalize)
        proxyRes.on('close', finalize)
      }
    },
  )

  proxyReq.on('error', (err) => {
    log('error', `Upstream error: ${err.message}`)
    if (!res.headersSent) {
      res.writeHead(502, { 'Content-Type': 'application/json', 'x-ccg-error': 'upstream-unreachable' })
      res.end(JSON.stringify({ error: 'Bad gateway', detail: err.message }))
    }
    recordRequest({
      ts: startedAt,
      client: clientName,
      method,
      path: pathname,
      status: 502,
      durationMs: Date.now() - startedAt,
      model: rewriteInfo.model,
      userMessage,
      errorSource: 'gateway',
      errorDetail: `upstream unreachable: ${err.message}`,
    })
    if (config.logging.audit) {
      audit(clientName, method, path, 502)
    }
  })

  proxyReq.write(body)
  proxyReq.end()
}

/**
 * Build a sample payload showing what the rewriter produces.
 * Used by /_verify endpoint for admin validation.
 */
function buildVerificationPayload(config: Config) {
  // Simulate a /v1/messages request body
  const sampleInput = {
    metadata: {
      user_id: JSON.stringify({
        device_id: 'REAL_DEVICE_ID_FROM_CLIENT_abc123',
        account_uuid: 'shared-account-uuid',
        session_id: 'session-xxx',
      }),
    },
    system: [
      {
        type: 'text',
        text: `x-anthropic-billing-header: cc_version=2.1.81.a1b; cc_entrypoint=cli;`,
      },
      {
        type: 'text',
        text: `Here is useful information about the environment:\n<env>\nWorking directory: /home/bob/myproject\nPlatform: linux\nShell: bash\nOS Version: Linux 6.5.0-generic\n</env>`,
      },
    ],
    messages: [{ role: 'user', content: 'hello' }],
  }

  const rewritten = JSON.parse(
    rewriteBody(Buffer.from(JSON.stringify(sampleInput)), '/v1/messages', config).toString('utf-8'),
  )

  return {
    _info: 'This shows how the gateway rewrites a sample request',
    before: {
      'metadata.user_id': JSON.parse(sampleInput.metadata.user_id),
      billing_header: sampleInput.system[0].text,
      system_prompt_env: sampleInput.system[1].text,
      system_block_count: sampleInput.system.length,
    },
    after: {
      'metadata.user_id': JSON.parse(rewritten.metadata.user_id),
      billing_header: '(stripped)',
      system_prompt_env: rewritten.system[0]?.text ?? '(empty)',
      system_block_count: rewritten.system.length,
    },
  }
}

function isSecureRequest(req: IncomingMessage): boolean {
  const proto = req.headers['x-forwarded-proto']
  if (typeof proto === 'string' && proto.split(',')[0].trim() === 'https') return true
  return (req.socket as { encrypted?: boolean }).encrypted === true
}

async function readBody(req: IncomingMessage, limit = 64 * 1024): Promise<Buffer> {
  const chunks: Buffer[] = []
  let total = 0
  for await (const chunk of req) {
    const buf = typeof chunk === 'string' ? Buffer.from(chunk) : chunk
    total += buf.length
    if (total > limit) throw new Error('body too large')
    chunks.push(buf)
  }
  return Buffer.concat(chunks)
}

async function handleDashboardArea(
  req: IncomingMessage,
  res: ServerResponse,
  pathname: string,
  method: string,
) {
  const secure = isSecureRequest(req)

  // Public landing page.
  if (pathname === '/') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' })
    res.end(renderLanding())
    return
  }

  // Legacy /login → canonical admin login at /admin.
  if (pathname === '/login' && method === 'GET') {
    res.writeHead(302, { Location: '/admin' })
    res.end()
    return
  }

  // Admin login: GET shows form, POST authenticates. Accept POST on both
  // /admin (canonical) and /login (legacy form action) for compatibility.
  if (pathname === '/admin' || (pathname === '/login' && method === 'POST')) {
    if (method === 'GET') {
      // If already logged in, send to dashboard
      if (getSessionFromRequest(req)) {
        res.writeHead(302, { Location: '/dashboard' })
        res.end()
        return
      }
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' })
      res.end(renderLogin())
      return
    }
    if (method === 'POST') {
      let body: Buffer
      try {
        body = await readBody(req)
      } catch {
        res.writeHead(413, { 'Content-Type': 'text/plain' })
        res.end('Payload too large')
        return
      }
      const params = new URLSearchParams(body.toString('utf-8'))
      const username = (params.get('username') || '').trim()
      const password = params.get('password') || ''
      if (!username || !password) {
        res.writeHead(400, { 'Content-Type': 'text/html; charset=utf-8' })
        res.end(renderLogin('err.adminCreds'))
        return
      }
      const user = authenticateUser(username, password)
      if (!user) {
        log('warn', `Failed login for "${username}" from ${req.socket.remoteAddress}`)
        res.writeHead(401, { 'Content-Type': 'text/html; charset=utf-8' })
        res.end(renderLogin('err.adminInvalid'))
        return
      }
      const cookie = createSessionCookie(user.username)
      log('info', `User "${user.username}" logged in`)
      res.writeHead(302, {
        Location: '/dashboard',
        'Set-Cookie': setCookieHeader(cookie, secure),
      })
      res.end()
      return
    }
    res.writeHead(405, { Allow: 'GET, POST' })
    res.end()
    return
  }

  // Logout: clear cookie, redirect to admin login
  if (pathname === '/admin/logout' || pathname === '/logout') {
    res.writeHead(302, {
      Location: '/admin',
      'Set-Cookie': clearCookieHeader(),
    })
    res.end()
    return
  }

  // Session-protected: dashboard + metrics
  const session = getSessionFromRequest(req)
  if (!session) {
    if (pathname === '/_metrics') {
      res.writeHead(401, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ error: 'Unauthorized' }))
    } else {
      res.writeHead(302, { Location: '/admin' })
      res.end()
    }
    return
  }

  if (pathname === '/dashboard') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' })
    res.end(renderDashboard())
    return
  }

  if (pathname === '/_metrics') {
    res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' })
    res.end(JSON.stringify({ ...getMetricsSnapshot(), oauth: getOAuthStatus() }))
    return
  }

  // ── OAuth re-login (authorization code + PKCE, manual paste flow) ──
  // Lets an admin re-authenticate the gateway's upstream Claude account from
  // the browser when the refresh_token dies, instead of editing config.yaml
  // and restarting the container.
  if (pathname === '/api/oauth') {
    if (method !== 'GET') {
      res.writeHead(405, { Allow: 'GET' })
      res.end()
      return
    }
    res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' })
    res.end(JSON.stringify(getOAuthStatus()))
    return
  }

  if (pathname === '/api/oauth/login') {
    if (method !== 'POST') {
      res.writeHead(405, { Allow: 'POST' })
      res.end()
      return
    }
    const started = beginOAuthLogin()
    log('info', `User "${session.u}" started an OAuth re-login`)
    res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' })
    res.end(JSON.stringify(started))
    return
  }

  if (pathname === '/api/oauth/complete') {
    if (method !== 'POST') {
      res.writeHead(405, { Allow: 'POST' })
      res.end()
      return
    }
    let body: Buffer
    try {
      body = await readBody(req)
    } catch {
      res.writeHead(413, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ error: 'Payload too large' }))
      return
    }
    let code = ''
    try {
      const parsed = JSON.parse(body.toString('utf-8'))
      code = typeof parsed?.code === 'string' ? parsed.code : ''
    } catch {
      res.writeHead(400, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ error: 'Invalid JSON body' }))
      return
    }
    if (!code.trim()) {
      res.writeHead(400, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ error: 'Authorization code is required' }))
      return
    }
    try {
      const result = await completeOAuthLogin(code)
      log('info', `User "${session.u}" completed an OAuth re-login`)
      res.writeHead(200, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ ok: true, ...result, status: getOAuthStatus() }))
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err)
      log('warn', `OAuth re-login by "${session.u}" failed: ${message}`)
      res.writeHead(400, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ error: message }))
    }
    return
  }

  if (pathname === '/api/oauth/cancel') {
    if (method !== 'POST') {
      res.writeHead(405, { Allow: 'POST' })
      res.end()
      return
    }
    cancelOAuthLogin()
    res.writeHead(200, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify({ ok: true }))
    return
  }

  if (pathname === '/api/clients') {
    if (method === 'GET') {
      const clients = listClients().map((c) => {
        const since = periodStart(c.cost_limit_period)
        const used = c.cost_limit_usd ? getClientCostSince(c.name, since) : 0
        return {
          name: c.name,
          token_preview: c.token.slice(0, 8) + '…' + c.token.slice(-4),
          cost_limit_usd: c.cost_limit_usd ?? null,
          cost_limit_period: c.cost_limit_period ?? null,
          cost_used_usd: c.cost_limit_usd ? Number(used.toFixed(4)) : null,
          home_dir: c.home_dir ?? null,
        }
      })
      res.writeHead(200, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ clients }))
      return
    }
    if (method === 'POST') {
      let body: Buffer
      try {
        body = await readBody(req)
      } catch {
        res.writeHead(413, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ error: 'Payload too large' }))
        return
      }
      let payload: {
        name?: string
        gateway_addr?: string
        scheme?: string
        format?: string
        platform?: string
        cost_limit_usd?: number | null
        cost_limit_period?: CostLimitPeriod | null
      }
      try {
        payload = JSON.parse(body.toString('utf-8'))
      } catch {
        res.writeHead(400, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ error: 'Invalid JSON' }))
        return
      }
      const name = (payload.name || '').trim()
      const scheme = payload.scheme === 'http' ? 'http' : 'https'
      const gatewayAddr =
        (payload.gateway_addr || '').trim() ||
        (typeof req.headers.host === 'string' ? req.headers.host : 'localhost:8443')
      if (!name) {
        res.writeHead(400, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ error: 'name required' }))
        return
      }
      let entry
      try {
        entry = addClient(name, {
          cost_limit_usd: payload.cost_limit_usd ?? undefined,
          cost_limit_period: payload.cost_limit_period ?? undefined,
        })
      } catch (err) {
        res.writeHead(400, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ error: err instanceof Error ? err.message : 'failed' }))
        return
      }
      reloadAuthFromConfig()
      // Generate a one-time portal password the admin hands to the client.
      let portalPassword = ''
      try {
        portalPassword = generateAndSetClientPassword(entry.name)
      } catch (err) {
        log('warn', `Failed to set portal password for "${entry.name}": ${err instanceof Error ? err.message : err}`)
      }
      log('info', `User "${session.u}" added client "${entry.name}"`)
      const isWindows = payload.platform === 'windows'
      const opts = {
        name: entry.name,
        token: entry.token,
        gatewayAddr,
        scheme: scheme as 'http' | 'https',
      }
      const script = isWindows ? buildPowerShellLauncherScript(opts) : buildLauncherScript(opts)
      if (payload.format === 'json') {
        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ name: entry.name, token: entry.token, portal_password: portalPassword, script }))
        return
      }
      const filename = isWindows ? `cc-${entry.name}.ps1` : `cc-${entry.name}`
      const ctype = isWindows
        ? 'text/plain; charset=utf-8'
        : 'application/x-shellscript; charset=utf-8'
      res.writeHead(200, {
        'Content-Type': ctype,
        'Content-Disposition': `attachment; filename="${filename}"`,
        'X-Client-Token': entry.token,
        'X-Portal-Password': portalPassword,
      })
      res.end(script)
      return
    }
    res.writeHead(405, { Allow: 'GET, POST' })
    res.end()
    return
  }

  if (pathname.startsWith('/api/clients/')) {
    const rest = pathname.slice('/api/clients/'.length)

    // GET /api/clients/:name/launcher — re-download launcher for an existing
    // client (reuses token from config.yaml — does not rotate it).
    if (rest.endsWith('/launcher')) {
      if (method !== 'GET') {
        res.writeHead(405, { Allow: 'GET' })
        res.end()
        return
      }
      const name = decodeURIComponent(rest.slice(0, -('/launcher'.length)))
      const existing = listClients().find((c) => c.name === name)
      if (!existing) {
        res.writeHead(404, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ error: 'client not found' }))
        return
      }
      const query = new URLSearchParams((req.url || '').split('?')[1] || '')
      const platform = query.get('platform') || 'unix'
      const scheme = query.get('scheme') === 'http' ? 'http' : 'https'
      const gatewayAddr =
        (query.get('gateway_addr') || '').trim() ||
        (typeof req.headers.host === 'string' ? req.headers.host : 'localhost:8443')
      const isWindows = platform === 'windows'
      const opts = {
        name: existing.name,
        token: existing.token,
        gatewayAddr,
        scheme: scheme as 'http' | 'https',
      }
      const script = isWindows ? buildPowerShellLauncherScript(opts) : buildLauncherScript(opts)
      const filename = isWindows ? `cc-${existing.name}.ps1` : `cc-${existing.name}`
      const ctype = isWindows
        ? 'text/plain; charset=utf-8'
        : 'application/x-shellscript; charset=utf-8'
      log('info', `User "${session.u}" re-downloaded launcher for client "${name}"`)
      res.writeHead(200, {
        'Content-Type': ctype,
        'Content-Disposition': `attachment; filename="${filename}"`,
      })
      res.end(script)
      return
    }

    // POST /api/clients/:name/password — regenerate the client's portal password.
    if (rest.endsWith('/password')) {
      if (method !== 'POST') {
        res.writeHead(405, { Allow: 'POST' })
        res.end()
        return
      }
      const name = decodeURIComponent(rest.slice(0, -('/password'.length)))
      const existing = listClients().find((c) => c.name === name)
      if (!existing) {
        res.writeHead(404, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ error: 'client not found' }))
        return
      }
      let password: string
      try {
        password = generateAndSetClientPassword(name)
      } catch (err) {
        res.writeHead(400, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ error: err instanceof Error ? err.message : 'failed' }))
        return
      }
      log('info', `User "${session.u}" reset portal password for client "${name}"`)
      res.writeHead(200, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ name, password }))
      return
    }

    const name = decodeURIComponent(rest)
    if (method === 'DELETE') {
      let removed = false
      try {
        removed = removeClient(name)
      } catch (err) {
        res.writeHead(400, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ error: err instanceof Error ? err.message : 'failed' }))
        return
      }
      if (!removed) {
        res.writeHead(404, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ error: 'not found' }))
        return
      }
      reloadAuthFromConfig()
      removeClientPassword(name)
      removeClientProfile(name)
      log('info', `User "${session.u}" removed client "${name}"`)
      res.writeHead(204)
      res.end()
      return
    }
    if (method === 'PATCH') {
      let body: Buffer
      try {
        body = await readBody(req)
      } catch {
        res.writeHead(413, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ error: 'Payload too large' }))
        return
      }
      let payload: {
        cost_limit_usd?: number | null
        cost_limit_period?: CostLimitPeriod | null
        home_dir?: string | null
      }
      try {
        payload = JSON.parse(body.toString('utf-8'))
      } catch {
        res.writeHead(400, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ error: 'Invalid JSON' }))
        return
      }
      // Cost-limit and workdir edits arrive as independent PATCHes; apply whatever
      // keys are present so one call can't clobber the other.
      let updated
      try {
        if ('home_dir' in payload) {
          updated = setClientHomeDir(name, payload.home_dir ?? null)
        }
        if ('cost_limit_usd' in payload || 'cost_limit_period' in payload) {
          updated = setClientLimit(name, {
            cost_limit_usd: payload.cost_limit_usd ?? null,
            cost_limit_period: payload.cost_limit_period ?? null,
          })
        }
        if (!updated) {
          updated = listClients().find((c) => c.name === name)
          if (!updated) throw new Error(`client "${name}" not found`)
        }
      } catch (err) {
        res.writeHead(400, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ error: err instanceof Error ? err.message : 'failed' }))
        return
      }
      reloadAuthFromConfig()
      log('info', `User "${session.u}" updated client "${name}"`)
      res.writeHead(200, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({
        name: updated.name,
        cost_limit_usd: updated.cost_limit_usd ?? null,
        cost_limit_period: updated.cost_limit_period ?? null,
        home_dir: updated.home_dir ?? null,
      }))
      return
    }
    res.writeHead(405, { Allow: 'DELETE, PATCH' })
    res.end()
    return
  }
}

/**
 * Client self-service portal. A client authenticates with their own token
 * (the value from auth.tokens), and can then view the credit they've been
 * granted + their usage, and download their personal launcher. Everything is
 * scoped to that single client — no cross-client visibility, no admin powers.
 */
async function handlePortalArea(
  req: IncomingMessage,
  res: ServerResponse,
  pathname: string,
  method: string,
) {
  const secure = isSecureRequest(req)

  // Portal home: login form, or the portal SPA once authenticated.
  if (pathname === '/portal') {
    if (getPortalSessionFromRequest(req)) {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' })
      res.end(renderPortal())
      return
    }
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' })
    res.end(renderPortalLogin())
    return
  }

  // Login: POST a client token.
  if (pathname === '/portal/login') {
    if (method === 'GET') {
      res.writeHead(302, { Location: '/portal' })
      res.end()
      return
    }
    if (method === 'POST') {
      let body: Buffer
      try {
        body = await readBody(req)
      } catch {
        res.writeHead(413, { 'Content-Type': 'text/plain' })
        res.end('Payload too large')
        return
      }
      const params = new URLSearchParams(body.toString('utf-8'))
      const name = (params.get('name') || '').trim()
      const password = params.get('password') || ''
      // Always run the verify (it burns a dummy hash when there's no row) so a
      // missing client can't be distinguished by timing. Also require the client
      // to still exist in config.yaml.
      const pwOk = verifyClientPassword(name, password)
      const inConfig = name ? listClients().some((c) => c.name === name) : false
      if (!pwOk || !inConfig) {
        log('warn', `Failed portal login for "${name}" from ${req.socket.remoteAddress}`)
        res.writeHead(401, { 'Content-Type': 'text/html; charset=utf-8' })
        res.end(renderPortalLogin('err.portalInvalid'))
        return
      }
      const cookie = createPortalCookie(name)
      log('info', `Client "${name}" signed in to portal`)
      res.writeHead(302, {
        Location: '/portal',
        'Set-Cookie': setPortalCookieHeader(cookie, secure),
      })
      res.end()
      return
    }
    res.writeHead(405, { Allow: 'GET, POST' })
    res.end()
    return
  }

  // Logout.
  if (pathname === '/portal/logout') {
    res.writeHead(302, {
      Location: '/portal',
      'Set-Cookie': clearPortalCookieHeader(),
    })
    res.end()
    return
  }

  // One-line installers — authorized by a short-lived signed grant in the URL
  // (no cookie), so they work under `curl … | bash` and `irm … | iex`. The
  // response is plain text meant to be piped straight into a shell.
  if (pathname === '/portal/install.sh' || pathname === '/portal/install.ps1') {
    if (method !== 'GET') {
      res.writeHead(405, { Allow: 'GET' })
      res.end()
      return
    }
    const query = new URLSearchParams((req.url || '').split('?')[1] || '')
    const grant = query.get('t') || ''
    const g = grant ? verifyInstallGrant(grant) : null
    if (!g) {
      res.writeHead(401, { 'Content-Type': 'text/plain; charset=utf-8' })
      res.end('# Invalid or expired install link. Open the portal and copy a fresh command.\n')
      return
    }
    const existing = listClients().find((c) => c.name === g.c)
    if (!existing) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' })
      res.end('# Client no longer exists.\n')
      return
    }
    const scheme = query.get('scheme') === 'http'
      ? 'http'
      : query.get('scheme') === 'https'
        ? 'https'
        : (isSecureRequest(req) ? 'https' : 'http')
    const gatewayAddr =
      (query.get('gateway_addr') || '').trim() ||
      (typeof req.headers.host === 'string' ? req.headers.host : 'localhost:8443')
    const opts = {
      name: existing.name,
      token: existing.token,
      gatewayAddr,
      scheme: scheme as 'http' | 'https',
    }
    const isWindows = pathname.endsWith('.ps1')
    const script = isWindows ? buildPowerShellInstaller(opts) : buildUnixInstaller(opts)
    log('info', `Client "${existing.name}" fetched ${isWindows ? 'PowerShell' : 'shell'} one-line installer`)
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' })
    res.end(script)
    return
  }

  // Everything below requires a valid portal session.
  const session = getPortalSessionFromRequest(req)
  if (!session) {
    if (pathname === '/portal/me') {
      res.writeHead(401, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ error: 'Unauthorized' }))
    } else {
      res.writeHead(302, { Location: '/portal' })
      res.end()
    }
    return
  }

  // Resolve the client from current config. If it was removed/renamed since the
  // cookie was issued, drop the session.
  const client = listClients().find((c) => c.name === session.c)
  if (!client) {
    if (pathname === '/portal/me') {
      res.writeHead(401, { 'Content-Type': 'application/json', 'Set-Cookie': clearPortalCookieHeader() })
      res.end(JSON.stringify({ error: 'Client no longer exists' }))
    } else {
      res.writeHead(302, { Location: '/portal', 'Set-Cookie': clearPortalCookieHeader() })
      res.end()
    }
    return
  }

  // Usage + credit + profile JSON for this client only.
  if (pathname === '/portal/me') {
    const stats = getClientStats(client.name)
    const limit = client.cost_limit_usd ?? null
    const period = client.cost_limit_period ?? 'lifetime'
    const used = getClientCostSince(client.name, periodStart(client.cost_limit_period))
    const profile = getClientProfile(client.name)
    const credMeta = getClientCredentialMeta(client.name)
    res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' })
    res.end(JSON.stringify({
      name: client.name,
      token: client.token,
      gateway_addr: typeof req.headers.host === 'string' ? req.headers.host : '',
      install_token: createInstallGrant(client.name),
      profile: { display_name: profile.display_name, email: profile.email, home_dir: client.home_dir ?? null },
      account: {
        created_at: credMeta?.created_at ?? null,
        password_updated_at: credMeta?.updated_at ?? null,
        cost_limit_usd: limit,
        cost_limit_period: period,
      },
      credit: {
        limit_usd: limit,
        period,
        used_usd: Number(used.toFixed(4)),
        remaining_usd: limit != null ? Number(Math.max(0, limit - used).toFixed(4)) : null,
      },
      lifetime: stats.lifetime,
      periods: stats.periods,
      models: getClientModels(client.name),
      recent: getClientRecent(client.name, 20),
    }))
    return
  }

  // Update this client's editable personal info.
  if (pathname === '/portal/profile') {
    if (method !== 'POST') {
      res.writeHead(405, { Allow: 'POST' })
      res.end()
      return
    }
    let body: Buffer
    try {
      body = await readBody(req)
    } catch {
      res.writeHead(413, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ error: 'Payload too large' }))
      return
    }
    let payload: { display_name?: string; email?: string; home_dir?: string | null }
    try {
      payload = JSON.parse(body.toString('utf-8'))
    } catch {
      res.writeHead(400, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ error: 'Invalid JSON' }))
      return
    }
    let saved
    let homeDir = client.home_dir ?? null
    try {
      saved = setClientProfile(client.name, {
        display_name: payload.display_name,
        email: payload.email,
      })
      // Clients may self-set their real home dir so the gateway maps masked paths
      // back to their machine. Same writer the admin uses.
      if ('home_dir' in payload) {
        homeDir = setClientHomeDir(client.name, payload.home_dir ?? null).home_dir ?? null
        reloadAuthFromConfig()
      }
    } catch (err) {
      res.writeHead(400, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ error: err instanceof Error ? err.message : 'failed' }))
      return
    }
    log('info', `Client "${client.name}" updated their profile`)
    res.writeHead(200, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify({ display_name: saved.display_name, email: saved.email, home_dir: homeDir }))
    return
  }

  // Change this client's own portal password.
  if (pathname === '/portal/password') {
    if (method !== 'POST') {
      res.writeHead(405, { Allow: 'POST' })
      res.end()
      return
    }
    let body: Buffer
    try {
      body = await readBody(req)
    } catch {
      res.writeHead(413, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ error: 'Payload too large' }))
      return
    }
    let payload: { current?: string; new?: string }
    try {
      payload = JSON.parse(body.toString('utf-8'))
    } catch {
      res.writeHead(400, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ error: 'Invalid JSON' }))
      return
    }
    try {
      changeClientPassword(client.name, payload.current || '', payload.new || '')
    } catch (err) {
      res.writeHead(400, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ error: err instanceof Error ? err.message : 'failed' }))
      return
    }
    log('info', `Client "${client.name}" changed their portal password`)
    res.writeHead(200, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify({ ok: true }))
    return
  }

  // Download this client's launcher (reuses their existing token).
  if (pathname === '/portal/launcher') {
    if (method !== 'GET') {
      res.writeHead(405, { Allow: 'GET' })
      res.end()
      return
    }
    const query = new URLSearchParams((req.url || '').split('?')[1] || '')
    const platform = query.get('platform') || 'unix'
    const scheme = query.get('scheme') === 'http' ? 'http' : 'https'
    const gatewayAddr =
      (query.get('gateway_addr') || '').trim() ||
      (typeof req.headers.host === 'string' ? req.headers.host : 'localhost:8443')
    const isWindows = platform === 'windows'
    const opts = {
      name: client.name,
      token: client.token,
      gatewayAddr,
      scheme: scheme as 'http' | 'https',
    }
    const script = isWindows ? buildPowerShellLauncherScript(opts) : buildLauncherScript(opts)
    const filename = isWindows ? `cc-${client.name}.ps1` : `cc-${client.name}`
    const ctype = isWindows
      ? 'text/plain; charset=utf-8'
      : 'application/x-shellscript; charset=utf-8'
    log('info', `Client "${client.name}" downloaded their launcher from the portal`)
    res.writeHead(200, {
      'Content-Type': ctype,
      'Content-Disposition': `attachment; filename="${filename}"`,
    })
    res.end(script)
    return
  }

  res.writeHead(404, { 'Content-Type': 'application/json' })
  res.end(JSON.stringify({ error: 'Not found' }))
}
