// Standalone Claude Code version sync — fetches the latest released CLI version
// and writes it into config.yaml (env.version + env.version_base).
//
// Intended for an OS-level daily cron when you prefer that over the gateway's
// built-in scheduler. A running gateway picks up the change live via its
// config.yaml watcher (no restart needed).
//
//   npm run update-version                       # uses CCG_CONFIG_PATH or /app/data/config.yaml
//   npm run update-version -- /path/config.yaml  # explicit config path
//
// Crontab (daily at 04:00):
//   0 4 * * * cd /app && /usr/bin/npm run update-version >> /app/data/version-cron.log 2>&1
import { loadConfig } from '../config.js'
import { syncClaudeCodeVersion } from '../cc-version.js'

async function main() {
  const configPath =
    process.argv[2] ||
    process.env.CCG_CONFIG_PATH ||
    '/app/data/config.yaml'

  const config = loadConfig(configPath)
  const version = await syncClaudeCodeVersion(configPath, config)
  if (!version) {
    console.error('Could not determine latest Claude Code version')
    process.exit(1)
  }
}

main().catch((err) => {
  console.error(`Error: ${err instanceof Error ? err.message : err}`)
  process.exit(1)
})
