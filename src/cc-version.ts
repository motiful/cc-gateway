import { log } from './logger.js'
import type { Config } from './config.js'
import { updateConfigEnvVersion } from './bootstrap-config.js'

const DAY_MS = 24 * 60 * 60 * 1000

// npm dist-tag endpoint for the official Claude Code CLI. Returns the metadata
// of whatever is currently published under the "latest" tag.
const NPM_LATEST_URL = 'https://registry.npmjs.org/@anthropic-ai/claude-code/latest'

/**
 * Fetch the latest published Claude Code CLI version from the npm registry.
 * Returns a semver string (e.g. "2.1.95") or null on any network/parse failure.
 *
 * Never throws — callers fall back to the version already in config so a
 * registry outage can never block gateway startup.
 */
export async function fetchLatestClaudeCodeVersion(timeoutMs = 4000): Promise<string | null> {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeoutMs)
  try {
    const res = await fetch(NPM_LATEST_URL, {
      signal: controller.signal,
      headers: { accept: 'application/json' },
    })
    if (!res.ok) {
      log('warn', `Claude Code version check failed: registry returned ${res.status}`)
      return null
    }
    const data = (await res.json()) as { version?: unknown }
    const version = typeof data.version === 'string' ? data.version.trim() : ''
    if (!/^\d+\.\d+\.\d+/.test(version)) {
      log('warn', `Claude Code version check: unexpected version field "${version}"`)
      return null
    }
    return version
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err)
    log('warn', `Claude Code version check failed: ${msg}`)
    return null
  } finally {
    clearTimeout(timer)
  }
}

/**
 * Fetch the latest Claude Code version and, if it differs from what the running
 * config carries, update both the in-memory config (so the forwarded user-agent
 * + cc_version take effect immediately) and config.yaml on disk (so the value
 * survives restarts and is visible to operators).
 *
 * Best-effort: a failed fetch keeps the existing version untouched. Returns the
 * version now in effect, or null if it could not be determined.
 */
export async function syncClaudeCodeVersion(
  configPath: string,
  config: Config,
): Promise<string | null> {
  const latest = await fetchLatestClaudeCodeVersion()
  const current = String(config.env.version || '')

  if (!latest) {
    log('warn', `Keeping configured Claude Code version (${current || 'unset'}); could not fetch latest`)
    return current || null
  }
  if (latest === current) {
    log('info', `Claude Code version up to date (${latest})`)
    return latest
  }

  config.env.version = latest
  config.env.version_base = latest
  updateConfigEnvVersion(configPath, latest)
  log('info', `Updated Claude Code version: ${current || '(unset)'} → ${latest}`)
  return latest
}

/**
 * Start an in-process daily scheduler that re-syncs the spoofed Claude Code
 * version once every 24h — a built-in cron so the gateway tracks new Claude Code
 * releases between deploys without an external crontab. Unref'd so it never
 * holds the process open. Override the cadence with CCG_VERSION_SYNC_INTERVAL_MS.
 */
export function startDailyVersionAutoUpdate(configPath: string, config: Config): NodeJS.Timeout {
  const envInterval = Number(process.env.CCG_VERSION_SYNC_INTERVAL_MS)
  const interval = Number.isFinite(envInterval) && envInterval > 0 ? envInterval : DAY_MS
  const timer = setInterval(() => {
    void syncClaudeCodeVersion(configPath, config)
  }, interval)
  timer.unref()
  log('info', `Daily Claude Code version auto-update scheduled (every ${Math.round(interval / 3_600_000)}h)`)
  return timer
}
