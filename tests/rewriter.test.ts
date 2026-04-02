import { rewriteBody, rewriteHeaders } from '../src/rewriter.js'
import type { Config } from '../src/config.js'
import { strict as assert } from 'assert'

const config: Config = {
  server: { port: 8443, tls: { cert: '', key: '' } },
  upstream: { url: 'https://api.anthropic.com' },
  auth: { tokens: [{ name: 'test', token: 'test-token' }] },
  oauth: { refresh_token: 'test-refresh' },
  identity: {
    device_id: 'canonical_device_id_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
    email: 'canonical@example.com',
  },
  env: {
    platform: 'darwin',
    platform_raw: 'darwin',
    arch: 'arm64',
    node_version: 'v24.3.0',
    terminal: 'iTerm2.app',
    package_managers: 'npm,pnpm',
    runtimes: 'node',
    is_running_with_bun: false,
    is_ci: false,
    is_claude_ai_auth: true,
    version: '2.1.81',
    version_base: '2.1.81',
    build_time: '2026-03-20T21:26:18Z',
    deployment_environment: 'unknown-darwin',
    vcs: 'git',
  },
  prompt_env: {
    platform: 'darwin',
    shell: 'zsh',
    os_version: 'Darwin 24.4.0',
    working_dir: '/Users/jack/projects',
  },
  process: {
    constrained_memory: 34359738368,
    rss_range: [300000000, 500000000],
    heap_total_range: [40000000, 80000000],
    heap_used_range: [100000000, 200000000],
  },
  logging: { level: 'error', audit: false },
}

let passed = 0
let failed = 0

function test(name: string, fn: () => void) {
  try {
    fn()
    passed++
    console.log(`  ✓ ${name}`)
  } catch (err) {
    failed++
    console.log(`  ✗ ${name}`)
    console.log(`    ${err}`)
  }
}

// ============================================================
console.log('\n/v1/messages - metadata.user_id rewriting')
// ============================================================

test('rewrites device_id in metadata.user_id', () => {
  const body = {
    metadata: {
      user_id: JSON.stringify({
        device_id: 'original_device_id',
        account_uuid: 'acct-123',
        session_id: 'sess-456',
      }),
    },
    messages: [{ role: 'user', content: 'hello' }],
  }

  const result = JSON.parse(
    rewriteBody(Buffer.from(JSON.stringify(body)), '/v1/messages', config).toString(),
  )
  const userId = JSON.parse(result.metadata.user_id)

  assert.equal(userId.device_id, config.identity.device_id)
  assert.equal(userId.account_uuid, 'acct-123', 'account_uuid should be preserved')
  assert.equal(userId.session_id, 'sess-456', 'session_id should be preserved')
})

// ============================================================
console.log('\n/v1/messages - system prompt environment rewriting')
// ============================================================

test('rewrites Platform in system prompt', () => {
  const body = {
    system: [{ type: 'text', text: 'Platform: linux\nShell: bash\nOS Version: Linux 6.5.0' }],
    messages: [],
  }
  const result = JSON.parse(
    rewriteBody(Buffer.from(JSON.stringify(body)), '/v1/messages', config).toString(),
  )
  assert.ok(result.system[0].text.includes('Platform: darwin'))
  assert.ok(result.system[0].text.includes('Shell: zsh'))
  assert.ok(result.system[0].text.includes('OS Version: Darwin 24.4.0'))
})

test('rewrites working directory path', () => {
  const body = {
    system: 'Primary working directory: /home/bob/myproject',
    messages: [],
  }
  const result = JSON.parse(
    rewriteBody(Buffer.from(JSON.stringify(body)), '/v1/messages', config).toString(),
  )
  assert.ok(result.system.includes('/Users/jack/projects'), `Got: ${result.system}`)
  assert.ok(!result.system.includes('/home/bob/'), 'Original path should be replaced')
})

test('strips billing header from system prompt (string format)', () => {
  const body = {
    system: 'x-anthropic-billing-header: cc_version=2.1.81.a1b; cc_entrypoint=cli; cch=00000;\nOther content here.',
    messages: [],
  }
  const result = JSON.parse(
    rewriteBody(Buffer.from(JSON.stringify(body)), '/v1/messages', config).toString(),
  )
  assert.ok(!result.system.includes('billing-header'), 'Billing header should be stripped')
  assert.ok(!result.system.includes('cc_version'), 'cc_version should be stripped')
  assert.ok(result.system.includes('Other content'), 'Non-billing content should remain')
})

test('strips billing header from system prompt (array format)', () => {
  const body = {
    system: [
      { type: 'text', text: 'x-anthropic-billing-header: cc_version=2.1.81.a1b; cc_entrypoint=cli;' },
      { type: 'text', text: 'Platform: linux\nShell: bash' },
    ],
    messages: [],
  }
  const result = JSON.parse(
    rewriteBody(Buffer.from(JSON.stringify(body)), '/v1/messages', config).toString(),
  )
  assert.equal(result.system.length, 1, 'Billing header block should be removed')
  assert.ok(result.system[0].text.includes('Platform: darwin'), 'Remaining block should be rewritten')
})

test('rewrites home paths in user messages with system-reminder', () => {
  const body = {
    system: '',
    messages: [{
      role: 'user',
      content: '<system-reminder>Working directory: /home/alice/code</system-reminder>',
    }],
  }
  const result = JSON.parse(
    rewriteBody(Buffer.from(JSON.stringify(body)), '/v1/messages', config).toString(),
  )
  assert.ok(!result.messages[0].content.includes('/home/alice/'))
})

// ============================================================
console.log('\n/api/event_logging/batch - event data rewriting')
// ============================================================

test('rewrites device_id and email in events', () => {
  const body = {
    events: [{
      event_type: 'ClaudeCodeInternalEvent',
      event_data: {
        device_id: 'real_device_id',
        email: 'real@email.com',
        event_name: 'tengu_init',
        env: { platform: 'linux', arch: 'x64' },
      },
    }],
  }
  const result = JSON.parse(
    rewriteBody(Buffer.from(JSON.stringify(body)), '/api/event_logging/batch', config).toString(),
  )
  const data = result.events[0].event_data
  assert.equal(data.device_id, config.identity.device_id)
  assert.equal(data.email, config.identity.email)
})

test('replaces entire env object with canonical', () => {
  const body = {
    events: [{
      event_type: 'ClaudeCodeInternalEvent',
      event_data: {
        device_id: 'x',
        env: {
          platform: 'linux',
          arch: 'x64',
          node_version: 'v20.0.0',
          terminal: 'xterm',
          is_ci: true,
          deployment_environment: 'unknown-linux',
        },
      },
    }],
  }
  const result = JSON.parse(
    rewriteBody(Buffer.from(JSON.stringify(body)), '/api/event_logging/batch', config).toString(),
  )
  const env = result.events[0].event_data.env
  assert.equal(env.platform, 'darwin')
  assert.equal(env.arch, 'arm64')
  assert.equal(env.node_version, 'v24.3.0')
  assert.equal(env.terminal, 'iTerm2.app')
  assert.equal(env.is_ci, false, 'is_ci should be forced to false')
  assert.equal(env.deployment_environment, 'unknown-darwin')
})

test('strips baseUrl that leaks gateway address', () => {
  const body = {
    events: [{
      event_type: 'ClaudeCodeInternalEvent',
      event_data: {
        device_id: 'x',
        baseUrl: 'https://gateway.office.com:8443',
        gateway: 'custom',
      },
    }],
  }
  const result = JSON.parse(
    rewriteBody(Buffer.from(JSON.stringify(body)), '/api/event_logging/batch', config).toString(),
  )
  const data = result.events[0].event_data
  assert.equal(data.baseUrl, undefined, 'baseUrl should be stripped')
  assert.equal(data.gateway, undefined, 'gateway should be stripped')
})

test('rewrites process metrics (base64 encoded)', () => {
  const processData = {
    uptime: 100,
    rss: 999999999,
    heapTotal: 999999999,
    heapUsed: 999999999,
    constrainedMemory: 68719476736, // 64GB - different from canonical 32GB
    cpuUsage: { user: 1000, system: 500 },
  }
  const body = {
    events: [{
      event_type: 'ClaudeCodeInternalEvent',
      event_data: {
        device_id: 'x',
        process: Buffer.from(JSON.stringify(processData)).toString('base64'),
      },
    }],
  }
  const result = JSON.parse(
    rewriteBody(Buffer.from(JSON.stringify(body)), '/api/event_logging/batch', config).toString(),
  )
  const decoded = JSON.parse(
    Buffer.from(result.events[0].event_data.process, 'base64').toString(),
  )
  assert.equal(decoded.constrainedMemory, 34359738368, 'Should be canonical 32GB')
  assert.equal(decoded.uptime, 100, 'uptime should be preserved')
  assert.ok(decoded.rss >= 300000000 && decoded.rss <= 500000000, 'rss should be in range')
})

// ============================================================
console.log('\nHTTP header rewriting')
// ============================================================

test('rewrites User-Agent to canonical version', () => {
  const headers = rewriteHeaders(
    { 'user-agent': 'claude-code/2.0.50 (external, cli)', 'x-app': 'cli' },
    config,
  )
  assert.equal(headers['user-agent'], 'claude-code/2.1.81 (external, cli)')
  assert.equal(headers['x-app'], 'cli')
})

test('strips authorization header (gateway injects its own)', () => {
  const headers = rewriteHeaders(
    { 'authorization': 'Bearer client-placeholder-token', 'x-app': 'cli' },
    config,
  )
  assert.equal(headers['authorization'], undefined)
})

test('strips proxy-authorization header', () => {
  const headers = rewriteHeaders(
    { 'proxy-authorization': 'Bearer proxy-token' },
    config,
  )
  assert.equal(headers['proxy-authorization'], undefined)
})

test('strips x-api-key header (gateway injects real token)', () => {
  const headers = rewriteHeaders(
    { 'x-api-key': 'client-gateway-token', 'x-app': 'cli' },
    config,
  )
  assert.equal(headers['x-api-key'], undefined)
  assert.equal(headers['x-app'], 'cli')
})

test('strips x-anthropic-billing-header', () => {
  const headers = rewriteHeaders(
    { 'x-anthropic-billing-header': 'cc_version=2.1.81.a1b; cc_entrypoint=cli;' },
    config,
  )
  assert.equal(headers['x-anthropic-billing-header'], undefined)
})

// ============================================================
console.log('\nNon-JSON passthrough')
// ============================================================

test('passes non-JSON body through unchanged', () => {
  const raw = Buffer.from('not json content')
  const result = rewriteBody(raw, '/v1/messages', config)
  assert.equal(result.toString(), 'not json content')
})

// ============================================================
console.log(`\n${passed} passed, ${failed} failed\n`)
if (failed > 0) process.exit(1)
