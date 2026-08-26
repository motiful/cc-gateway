import { extractRequestPreview, stripSyntheticBlocks } from '../src/preview.js'
import { strict as assert } from 'assert'

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

const buf = (obj: unknown) => Buffer.from(JSON.stringify(obj))

// ============================================================
console.log('\nextractRequestPreview - request message previews')
// ============================================================

test('plain user prompt shows its text', () => {
  const body = { messages: [{ role: 'user', content: 'sửa giúp tôi cái bug login' }] }
  assert.equal(extractRequestPreview(buf(body)), 'sửa giúp tôi cái bug login')
})

test('shows the LAST message, not an earlier human prompt', () => {
  const body = {
    messages: [
      { role: 'user', content: 'original prompt' },
      { role: 'assistant', content: [{ type: 'tool_use', id: 't1', name: 'Bash', input: { command: 'ls' } }] },
      {
        role: 'user',
        content: [{ type: 'tool_result', tool_use_id: 't1', content: 'file-a file-b' }],
      },
    ],
  }
  const preview = extractRequestPreview(buf(body))
  assert.ok(preview.startsWith('[tool_result]'), `got: ${preview}`)
  assert.ok(preview.includes('file-a'), `got: ${preview}`)
  assert.ok(!preview.includes('original prompt'), 'must not repeat the old human prompt')
})

test('errored tool_result is marked', () => {
  const body = {
    messages: [
      {
        role: 'user',
        content: [{ type: 'tool_result', tool_use_id: 't1', is_error: true, content: 'command not found' }],
      },
    ],
  }
  assert.equal(extractRequestPreview(buf(body)), '[tool_result error] command not found')
})

test('assistant prefill message gets a role prefix', () => {
  const body = {
    messages: [
      { role: 'user', content: 'q' },
      { role: 'assistant', content: 'Here is' },
    ],
  }
  assert.equal(extractRequestPreview(buf(body)), '[assistant] Here is')
})

test('tool_use blocks show name + args', () => {
  const body = {
    messages: [
      { role: 'assistant', content: [{ type: 'tool_use', id: 't1', name: 'Edit', input: { file_path: '/a.ts' } }] },
    ],
  }
  assert.equal(extractRequestPreview(buf(body)), '[assistant] [tool_use Edit] {"file_path":"/a.ts"}')
})

test('synthetic-only message shows a tag marker instead of empty', () => {
  const body = {
    messages: [{ role: 'user', content: '<system-reminder>internal stuff</system-reminder>' }],
  }
  assert.equal(extractRequestPreview(buf(body)), '[system-reminder]')
})

test('synthetic blocks are stripped from mixed text', () => {
  const body = {
    messages: [
      { role: 'user', content: 'real question <system-reminder>noise</system-reminder> here' },
    ],
  }
  assert.equal(extractRequestPreview(buf(body)), 'real question here')
})

test('non-text blocks fall back to a type tag', () => {
  const body = {
    messages: [
      { role: 'user', content: [{ type: 'image', source: {} }, { type: 'text', text: 'what is this' }] },
    ],
  }
  assert.equal(extractRequestPreview(buf(body)), '[image] what is this')
})

test('long previews truncate at 200 chars with ellipsis', () => {
  const body = { messages: [{ role: 'user', content: 'x'.repeat(500) }] }
  const preview = extractRequestPreview(buf(body))
  assert.equal(preview.length, 201)
  assert.ok(preview.endsWith('…'))
})

test('non-JSON, empty, and message-less bodies return empty string', () => {
  assert.equal(extractRequestPreview(Buffer.from('not json')), '')
  assert.equal(extractRequestPreview(Buffer.alloc(0)), '')
  assert.equal(extractRequestPreview(buf({ messages: [] })), '')
})

// ============================================================
console.log('\nstripSyntheticBlocks')
// ============================================================

test('strips all synthetic tag pairs and collapses whitespace', () => {
  const text = 'a <command-name>/foo</command-name>  b\n<local-command-stdout>out</local-command-stdout> c'
  assert.equal(stripSyntheticBlocks(text), 'a b c')
})

// ============================================================
console.log(`\n${passed} passed, ${failed} failed\n`)
if (failed > 0) process.exit(1)
