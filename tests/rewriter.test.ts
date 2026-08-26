import { rewriteBody, rewriteHeaders, extractReversePathMap, createPathReplacer, type RewriteInfo } from '../src/rewriter.js'
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
console.log('\n/v1/messages - request model passthrough')
// ============================================================

test('model passes through unchanged — upstream sees exactly what the client sent', () => {
  const body = { model: 'claude-opus-4-8', messages: [] }
  const result = JSON.parse(
    rewriteBody(Buffer.from(JSON.stringify(body)), '/v1/messages', config).toString(),
  )
  assert.equal(result.model, 'claude-opus-4-8')
})

test('RewriteInfo.model records the model sent upstream', () => {
  const info: RewriteInfo = {}
  const body = { model: 'claude-opus-4-8', messages: [] }
  rewriteBody(Buffer.from(JSON.stringify(body)), '/v1/messages', config, info)
  assert.equal(info.model, 'claude-opus-4-8')
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

test('masks home-based working directory structurally (username only)', () => {
  const body = {
    system: 'Primary working directory: /home/bob/myproject',
    messages: [],
  }
  const result = JSON.parse(
    rewriteBody(Buffer.from(JSON.stringify(body)), '/v1/messages', config).toString(),
  )
  // Home prefix swapped, project subpath preserved (so it can be reversed).
  assert.ok(result.system.includes('/Users/jack/myproject'), `Got: ${result.system}`)
  assert.ok(!result.system.includes('/home/bob/'), 'Original username should be replaced')
})

test('collapses non-home working directory to canonical working_dir', () => {
  const body = {
    system: 'Primary working directory: /workspace/app',
    messages: [],
  }
  const result = JSON.parse(
    rewriteBody(Buffer.from(JSON.stringify(body)), '/v1/messages', config).toString(),
  )
  assert.ok(result.system.includes('/Users/jack/projects'), `Got: ${result.system}`)
  assert.ok(!result.system.includes('/workspace/app'), 'Non-home cwd should be collapsed')
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
console.log('\nReverse path mapping (response un-masking)')
// ============================================================

test('extractReversePathMap maps home prefix (home-based cwd needs no extra pair)', () => {
  const body = Buffer.from(JSON.stringify({
    system: 'Primary working directory: /Users/mac/Documents/builderx_api',
    messages: [{
      role: 'user',
      content: '<system-reminder>see /Users/mac/notes.md</system-reminder>',
    }],
  }))
  const pairs = extractReversePathMap(body, config)
  // Home-based cwd is structure-preserved, so the single home-prefix pair
  // reverses it (and everything else under that home). No working_dir pair.
  assert.ok(pairs.some(p => p.from === '/Users/jack/' && p.to === '/Users/mac/'))
  assert.ok(!pairs.some(p => p.from === '/Users/jack/projects'), 'no working_dir pair for home cwd')
})

test('extractReversePathMap maps working_dir for a non-home cwd', () => {
  const body = Buffer.from(JSON.stringify({
    system: 'Primary working directory: /workspace/app',
    messages: [],
  }))
  const pairs = extractReversePathMap(body, config)
  assert.ok(pairs.some(p => p.from === '/Users/jack/projects' && p.to === '/workspace/app'))
})

test('reverse handles multiple projects under one home (multi-cwd)', () => {
  const body = Buffer.from(JSON.stringify({
    system: 'Primary working directory: /Users/mac/projA',
    messages: [{
      role: 'user',
      content: '<system-reminder>also /Users/mac/projB/lib/x.ex</system-reminder>',
    }],
  }))
  const pairs = extractReversePathMap(body, config)
  const r = createPathReplacer(pairs)
  // Model response referencing BOTH masked projects must reverse to both reals.
  let out = r.push(Buffer.from('cat /Users/jack/projB/lib/x.ex; cd /Users/jack/projA/sub'))
  out += r.flush()
  assert.equal(out, 'cat /Users/mac/projB/lib/x.ex; cd /Users/mac/projA/sub')
})

test('reverse survives history already containing the canonical /Users/jack/ path', () => {
  // Real multi-turn shape: `messages` (history) serialize BEFORE `system`, and an
  // earlier masked turn left /Users/jack/ in the history. A first-match scan would
  // grab that canonical path, decide there is nothing to reverse, and break un-
  // masking for the rest of the session. The env "Working directory:" line is the
  // real anchor and must win.
  const body = Buffer.from(JSON.stringify({
    messages: [{
      role: 'assistant',
      content: 'Earlier I ran `ls /Users/jack/Documents/webcake/builderx_api/`',
    }],
    system: 'Primary working directory: /Users/mac/Documents/webcake/builderx_api',
  }))
  const pairs = extractReversePathMap(body, config)
  assert.ok(
    pairs.some(p => p.from === '/Users/jack/' && p.to === '/Users/mac/'),
    `Expected jack→mac reverse pair, got: ${JSON.stringify(pairs)}`,
  )
  const r = createPathReplacer(pairs)
  let out = r.push(Buffer.from('ls /Users/jack/Documents/webcake/builderx_api/'))
  out += r.flush()
  assert.equal(out, 'ls /Users/mac/Documents/webcake/builderx_api/')
})

test('extractReversePathMap returns [] when nothing to reverse', () => {
  const body = Buffer.from(JSON.stringify({ system: 'no paths here', messages: [] }))
  assert.equal(extractReversePathMap(body, config).length, 0)
})

test('extractReversePathMap returns [] when reverse_paths is off', () => {
  const off = { ...config, prompt_env: { ...config.prompt_env, reverse_paths: false } }
  const body = Buffer.from(JSON.stringify({
    system: 'Primary working directory: /Users/mac/Documents/builderx_api',
    messages: [],
  }))
  assert.equal(extractReversePathMap(body, off).length, 0)
})

test('createPathReplacer reverses masked paths in one chunk', () => {
  const pairs = [
    { from: '/Users/jack/projects', to: '/Users/mac/Documents/builderx_api' },
    { from: '/Users/jack/', to: '/Users/mac/' },
  ]
  const r = createPathReplacer(pairs)
  let out = r.push(Buffer.from('cd /Users/jack/projects/lib && cat /Users/jack/.zshrc'))
  out += r.flush()
  assert.equal(out, 'cd /Users/mac/Documents/builderx_api/lib && cat /Users/mac/.zshrc')
})

test('createPathReplacer reverses a path split across chunk boundaries', () => {
  const pairs = [
    { from: '/Users/jack/projects', to: '/Users/mac/Documents/builderx_api' },
    { from: '/Users/jack/', to: '/Users/mac/' },
  ]
  const r = createPathReplacer(pairs)
  const full = 'open /Users/jack/projects/main.ex now'
  // Feed one byte at a time — the worst case for boundary splitting.
  let out = ''
  for (const ch of Buffer.from(full)) out += r.push(Buffer.from([ch]))
  out += r.flush()
  assert.equal(out, 'open /Users/mac/Documents/builderx_api/main.ex now')
})

// ============================================================
console.log('\nNewly covered edge cases (#1 multi non-home, #2 bare home, #4 windows)')
// ============================================================

// Full round-trip helper: mask a request, then reverse the model's response.
function roundTrip(systemText: string, modelResponse: string): { masked: string; reversed: string } {
  const buf = Buffer.from(JSON.stringify({ system: systemText, messages: [] }))
  const masked = JSON.parse(rewriteBody(buf, '/v1/messages', config).toString()).system
  const r = createPathReplacer(extractReversePathMap(buf, config))
  let reversed = r.push(Buffer.from(modelResponse))
  reversed += r.flush()
  return { masked, reversed }
}

test('#1 multiple distinct non-home cwds get distinct canonical roots', () => {
  // Two separate "Working directory:" lines (multi-root session). Non-home roots
  // are only discovered via cwd lines — there is no username heuristic for them.
  const buf = Buffer.from(JSON.stringify({
    system: 'Primary working directory: /workspace/app\nWorking directory: /srv/api',
    messages: [{ role: 'user', content: '<system-reminder>also building /srv/api/main.go</system-reminder>' }],
  }))
  const masked = JSON.parse(rewriteBody(buf, '/v1/messages', config).toString())
  // Both roots masked, but to DIFFERENT canonical targets (no lossy collapse).
  assert.ok(masked.system.includes('/Users/jack/projects'), `system: ${masked.system}`)
  const reminder = masked.messages[0].content
  assert.ok(reminder.includes('/Users/jack/projects-cwd1/main.go'), `reminder: ${reminder}`)
  assert.ok(!reminder.includes('/srv/api'), 'second non-home root must be masked')
})

test('#1 both non-home roots reverse back to their own real paths', () => {
  const buf = Buffer.from(JSON.stringify({
    system: 'Primary working directory: /workspace/app\nWorking directory: /srv/api',
    messages: [],
  }))
  const r = createPathReplacer(extractReversePathMap(buf, config))
  let out = r.push(Buffer.from('edit /Users/jack/projects-cwd1/main.go and /Users/jack/projects/app.ts'))
  out += r.flush()
  assert.equal(out, 'edit /srv/api/main.go and /workspace/app/app.ts')
})

test('#1 additional working directories (real bullet-list env format) are masked + reversed', () => {
  // The real Claude Code env block: primary `Working directory:` line plus extra
  // roots under an `Additional working directories:` header as a `- /path` list.
  const system = [
    'Here is useful information about the environment:',
    '<env>',
    'Working directory: /workspace/app',
    'Is directory a git repo: Yes',
    'Additional working directories:',
    '- /srv/api',
    '- /opt/data',
    'Platform: linux',
    '</env>',
  ].join('\n')
  const buf = Buffer.from(JSON.stringify({
    system,
    messages: [{ role: 'user', content: '<system-reminder>edit /srv/api/x.go and /opt/data/y.csv</system-reminder>' }],
  }))
  const masked = JSON.parse(rewriteBody(buf, '/v1/messages', config).toString())
  const reminder = masked.messages[0].content
  // Neither bullet-listed root may leak upstream.
  assert.ok(!reminder.includes('/srv/api/'), `srv/api leaked: ${reminder}`)
  assert.ok(!reminder.includes('/opt/data/'), `opt/data leaked: ${reminder}`)
  assert.ok(!masked.system.includes('/srv/api'), `env block leaked srv/api: ${masked.system}`)
  // And the model's response un-masks each back to its OWN real root.
  const r = createPathReplacer(extractReversePathMap(buf, config))
  let out = r.push(Buffer.from(reminder.replace(/<\/?system-reminder>/g, '')))
  out += r.flush()
  assert.ok(out.includes('/srv/api/x.go'), `srv reverse: ${out}`)
  assert.ok(out.includes('/opt/data/y.csv'), `opt reverse: ${out}`)
})

test('#2 bare home (no trailing slash) is masked, not leaked', () => {
  const { masked } = roundTrip('Primary working directory: /Users/mac/proj\nHOME is /Users/mac right now', '')
  assert.ok(!masked.includes('/Users/mac'), `real username leaked: ${masked}`)
  assert.ok(/HOME is \/Users\/jack right now/.test(masked), `masked: ${masked}`)
})

test('#2 bare home reverses, but does NOT corrupt a longer sibling username', () => {
  const buf = Buffer.from(JSON.stringify({
    system: 'Primary working directory: /Users/mac/proj',
    messages: [],
  }))
  const r = createPathReplacer(extractReversePathMap(buf, config))
  // `cd /Users/jack` (bare, boundary) → /Users/mac; but /Users/jackson untouched.
  let out = r.push(Buffer.from('cd /Users/jack && stat /Users/jackson/x'))
  out += r.flush()
  assert.equal(out, 'cd /Users/mac && stat /Users/jackson/x')
})

test('#2 bare home reverses when split one byte at a time', () => {
  const buf = Buffer.from(JSON.stringify({ system: 'Primary working directory: /Users/mac/proj', messages: [] }))
  const r = createPathReplacer(extractReversePathMap(buf, config))
  let out = ''
  for (const ch of Buffer.from('echo /Users/jack done')) out += r.push(Buffer.from([ch]))
  out += r.flush()
  assert.equal(out, 'echo /Users/mac done')
})

test('#2 bare home at end-of-stream still reverses', () => {
  const buf = Buffer.from(JSON.stringify({ system: 'Primary working directory: /Users/mac/proj', messages: [] }))
  const r = createPathReplacer(extractReversePathMap(buf, config))
  let out = r.push(Buffer.from('cwd is /Users/jack'))
  out += r.flush()
  assert.equal(out, 'cwd is /Users/mac')
})

test('home mask preserves trailing delimiters (PATH-style and shell)', () => {
  const { masked } = roundTrip(
    'env PATH=/Users/mac:/usr/bin then cd /Users/mac; ls and (/Users/mac), done',
    '',
  )
  assert.ok(masked.includes('PATH=/Users/jack:/usr/bin'), `colon dropped: ${masked}`)
  assert.ok(masked.includes('cd /Users/jack; ls'), `semicolon dropped: ${masked}`)
  assert.ok(masked.includes('(/Users/jack),'), `paren/comma dropped: ${masked}`)
  assert.ok(!masked.includes('/Users/mac'), `real username leaked: ${masked}`)
})

test('#2 trailing-punctuation cwd line does not leak its subpaths', () => {
  const buf = Buffer.from(JSON.stringify({
    system: 'Working directory: /srv/api.',
    messages: [{ role: 'user', content: '<system-reminder>open /srv/api/secret.txt</system-reminder>' }],
  }))
  const masked = JSON.parse(rewriteBody(buf, '/v1/messages', config).toString())
  const reminder = masked.messages[0].content
  assert.ok(reminder.includes('/Users/jack/projects/secret.txt'), `subpath not masked: ${reminder}`)
  assert.ok(!reminder.includes('/srv/api/'), `real subpath leaked: ${reminder}`)
})

test('mixed home + non-home cwd: each reverses to its OWN real path (no canon collision)', () => {
  // Real home /Users/mac with a `projects` dir, AND a non-home cwd. The non-home
  // root must not alias /Users/mac/projects when masked.
  const buf = Buffer.from(JSON.stringify({
    system: 'Primary working directory: /Users/mac/projA\nWorking directory: /workspace/app',
    messages: [],
  }))
  const masked = JSON.parse(rewriteBody(buf, '/v1/messages', config).toString())
  assert.ok(!masked.system.includes('/Users/mac'), 'home username must be masked')
  assert.ok(!masked.system.includes('/workspace/app'), 'non-home root must be masked')
  const r = createPathReplacer(extractReversePathMap(buf, config))
  let out = r.push(Buffer.from('edit /Users/jack/projects/x and /Users/jack/projects-cwd0/y'))
  out += r.flush()
  // /Users/jack/projects/x is a real HOME subpath → back to /Users/mac; the
  // non-home canon (-cwd0) is the only thing that maps to /workspace/app.
  assert.equal(out, 'edit /Users/mac/projects/x and /workspace/app/y')
})

test('#4 windows home masks username only, preserving drive + backslashes', () => {
  const body = { system: 'Primary working directory: C:\\Users\\bob\\code\\app', messages: [] }
  const masked = JSON.parse(rewriteBody(Buffer.from(JSON.stringify(body)), '/v1/messages', config).toString())
  assert.ok(masked.system.includes('C:\\Users\\jack\\code\\app'), `masked: ${masked.system}`)
  assert.ok(!masked.system.includes('bob'), 'windows username must not leak')
})

// ============================================================
// Per-client home_dir override (cross-platform reverse mapping)
// ============================================================

// Env block whose "Working directory:" is ALREADY the canonical path — the
// Case-B scenario where auto-detection finds no real home and yields [].
const canonicalEnvBody = () =>
  Buffer.from(JSON.stringify({ system: 'Working directory: /Users/jack/app', messages: [] }))

test('override: without home_dir, canonical-only env yields no reverse (Case B)', () => {
  const pairs = extractReversePathMap(canonicalEnvBody(), config)
  assert.equal(pairs.length, 0)
})

test('override: POSIX home_dir reverses canonical → real even in Case B', () => {
  const pairs = extractReversePathMap(canonicalEnvBody(), config, '/home/alice')
  const r = createPathReplacer(pairs)
  const out = r.push(Buffer.from('open /Users/jack/app/main.ts and cd /Users/jack')) + r.flush()
  assert.equal(out, 'open /home/alice/app/main.ts and cd /home/alice')
})

test('override: macOS home_dir maps to /Users/<real>', () => {
  const pairs = extractReversePathMap(canonicalEnvBody(), config, '/Users/bob')
  const r = createPathReplacer(pairs)
  const out = r.push(Buffer.from('/Users/jack/x')) + r.flush()
  assert.equal(out, '/Users/bob/x')
})

test('override: Windows home_dir reverses the JSON-escaped wire form', () => {
  const pairs = extractReversePathMap(canonicalEnvBody(), config, 'C:\\Users\\alice')
  const r = createPathReplacer(pairs)
  // On the SSE wire, backslashes are doubled: C:\\Users\\jack\\proj\\a.ts
  const wire = 'run C:\\\\Users\\\\jack\\\\proj\\\\a.ts'
  const out = r.push(Buffer.from(wire)) + r.flush()
  assert.equal(out, 'run C:\\\\Users\\\\alice\\\\proj\\\\a.ts')
})

test('override: Windows bare home (end of JSON value) reverses too', () => {
  const pairs = extractReversePathMap(canonicalEnvBody(), config, 'C:\\Users\\alice')
  const r = createPathReplacer(pairs)
  const wire = '"cwd":"C:\\\\Users\\\\jack"'
  const out = r.push(Buffer.from(wire)) + r.flush()
  assert.equal(out, '"cwd":"C:\\\\Users\\\\alice"')
})

test('override: Windows reverse survives a chunk split mid-path', () => {
  const pairs = extractReversePathMap(canonicalEnvBody(), config, 'C:\\Users\\alice')
  const r = createPathReplacer(pairs)
  const wire = 'C:\\\\Users\\\\jack\\\\z'
  let out = ''
  for (const ch of wire) out += r.push(Buffer.from(ch))
  out += r.flush()
  assert.equal(out, 'C:\\\\Users\\\\alice\\\\z')
})

// ============================================================
console.log(`\n${passed} passed, ${failed} failed\n`)
if (failed > 0) process.exit(1)
