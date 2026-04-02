import { request as httpsRequest } from 'https'
import { HttpsProxyAgent } from 'https-proxy-agent'
import type { Config } from './config.js'
import { log } from './logger.js'

const REGISTRY_URL = 'https://registry.npmjs.org/@anthropic-ai/claude-code'
const REFRESH_INTERVAL = 60 * 60 * 1000 // 1 hour
const TIMEOUT = 5_000

type NpmRegistryInfo = {
  'dist-tags': { latest: string }
  time: Record<string, string>
}

function fetchLatestVersion(proxyAgent?: HttpsProxyAgent<string>): Promise<{ version: string; buildTime: string }> {
  return new Promise((resolve, reject) => {
    const url = new URL(REGISTRY_URL)
    const req = httpsRequest(
      {
        hostname: url.hostname,
        port: 443,
        path: url.pathname,
        method: 'GET',
        headers: {
          'Accept': 'application/vnd.npm.install-v1+json',
        },
        timeout: TIMEOUT,
        ...(proxyAgent ? { agent: proxyAgent } : {}),
      },
      (res) => {
        const chunks: Buffer[] = []
        res.on('data', (chunk) => chunks.push(chunk))
        res.on('end', () => {
          try {
            const data = JSON.parse(Buffer.concat(chunks).toString('utf-8')) as NpmRegistryInfo
            const latest = data['dist-tags']?.latest
            if (!latest) {
              reject(new Error('No latest version in registry response'))
              return
            }
            const buildTime = data.time?.[latest] || new Date().toISOString()
            resolve({ version: latest, buildTime })
          } catch (err) {
            reject(new Error(`Failed to parse registry response: ${err}`))
          }
        })
      },
    )
    req.on('timeout', () => {
      req.destroy()
      reject(new Error('Registry request timed out'))
    })
    req.on('error', reject)
    req.end()
  })
}

function applyVersion(config: Config, version: string, buildTime: string) {
  config.env.version = version
  config.env.version_base = version
  config.env.build_time = buildTime
}

async function syncVersion(config: Config, proxyAgent?: HttpsProxyAgent<string>): Promise<void> {
  try {
    const { version, buildTime } = await fetchLatestVersion(proxyAgent)
    const prev = config.env.version
    applyVersion(config, version, buildTime)
    if (prev !== version) {
      log('info', `Version synced: ${prev} -> ${version} (build: ${buildTime})`)
    } else {
      log('debug', `Version unchanged: ${version}`)
    }
  } catch (err) {
    log('warn', `Version sync failed, keeping ${config.env.version}: ${err}`)
  }
}

export async function initVersion(config: Config): Promise<void> {
  const proxyAgent = config.upstream.proxy ? new HttpsProxyAgent(config.upstream.proxy) : undefined
  await syncVersion(config, proxyAgent)

  setInterval(() => syncVersion(config, proxyAgent), REFRESH_INTERVAL)
  log('info', `Version auto-refresh scheduled every ${REFRESH_INTERVAL / 60000} min`)
}
