import { loadConfig } from './config.js'
import { setLogLevel, log } from './logger.js'
import { initOAuth } from './oauth.js'
import { startProxy } from './proxy.js'
import { reloadProxyAgent } from './proxy-agent.js'
import { initUsageNotify } from './usage-notify.js'
import { initUsageMeter, postReport } from './usage-meter.js'

const configPath = process.argv[2]

// Defense-in-depth: proxy.ts now catches per-request errors so a client
// abort can't crash the process, but keep a process-level backstop too —
// one stray unhandled error taking down the gateway drops every other
// client's connection and forces a full oauth re-init on restart.
process.on('uncaughtException', (err) => {
  log('error', `Uncaught exception (gateway staying up): ${err instanceof Error ? err.stack || err.message : err}`)
})
process.on('unhandledRejection', (reason) => {
  const msg = reason instanceof Error ? reason.stack || reason.message : String(reason)
  log('error', `Unhandled rejection (gateway staying up): ${msg}`)
})

// cc-health.sh switches egress proxy tiers by writing active-proxy.txt and
// sending SIGHUP, instead of a full systemctl restart — avoids dropping
// in-flight requests and re-running OAuth init on every tier flap.
process.on('SIGHUP', () => {
  reloadProxyAgent()
  log('info', 'Reloaded proxy agent (SIGHUP)')
})

try {
  const config = loadConfig(configPath)
  setLogLevel(config.logging.level)

  log('info', 'CC Gateway starting...')

  // Initialize OAuth — uses existing access token if valid, only refreshes when expired.
  // Pass configPath so rotated tokens can be persisted back to config.yaml.
  await initOAuth(config.oauth, configPath)

  // Arm the Discord usage notifier (no-op if notify.discord_webhook is unset).
  initUsageNotify(config.notify?.discord_webhook)

  // Per-user token/request metering + scheduled Discord report.
  initUsageMeter({
    webhook: config.notify?.discord_webhook,
    reportIntervalHours: config.notify?.usage_report_interval_hours,
  })

  // `kill -USR1 <pid>` posts the per-user report to Discord immediately —
  // handy for testing and ad-hoc snapshots without waiting for the interval.
  process.on('SIGUSR1', () => {
    log('info', 'SIGUSR1 received — posting per-user usage report')
    void postReport()
  })

  startProxy(config)
} catch (err) {
  console.error(`Fatal: ${err instanceof Error ? err.message : err}`)
  process.exit(1)
}
