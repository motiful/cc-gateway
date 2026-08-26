import { computeCost, type UsageBreakdown } from '../src/pricing.js'
import { SSEUsageParser } from '../src/usage-parser.js'
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

const M = 1_000_000
// Mid-July 2026: inside the Sonnet 5 introductory-pricing window.
const NOW = Date.UTC(2026, 6, 15)
const AFTER_INTRO = Date.UTC(2026, 8, 15)

function zero(): UsageBreakdown {
  return { inputTokens: 0, outputTokens: 0, cacheReadTokens: 0, cacheCreationTokens: 0 }
}
/** Cost of 1M tokens of a single category, in dollars. */
const perM = (model: string, field: keyof UsageBreakdown, at = NOW, extra: Partial<UsageBreakdown> = {}) =>
  computeCost(model, { ...zero(), [field]: M, ...extra }, at)

const rateOf = (model: string, at = NOW, extra: Partial<UsageBreakdown> = {}) => ({
  input: perM(model, 'inputTokens', at, extra),
  output: perM(model, 'outputTokens', at, extra),
  cacheRead: perM(model, 'cacheReadTokens', at, extra),
  cacheWrite: perM(model, 'cacheCreationTokens', at, extra),
})

console.log('\ncomputeCost — list prices match the published pricing table\n')

// [model id as reported by upstream, input, output, cache read, 5m cache write]
const TABLE: [string, number, number, number, number][] = [
  ['claude-fable-5', 10, 50, 1, 12.5],
  ['claude-mythos-5', 10, 50, 1, 12.5],
  ['claude-opus-5', 5, 25, 0.5, 6.25],
  ['claude-opus-4-8', 5, 25, 0.5, 6.25],
  ['claude-opus-4-7', 5, 25, 0.5, 6.25],
  ['claude-opus-4-6', 5, 25, 0.5, 6.25],
  ['claude-opus-4-5', 5, 25, 0.5, 6.25],
  ['claude-opus-4-1-20250805', 15, 75, 1.5, 18.75],
  ['claude-opus-4-20250514', 15, 75, 1.5, 18.75],
  ['claude-sonnet-4-6', 3, 15, 0.3, 3.75],
  ['claude-sonnet-4-5-20250929', 3, 15, 0.3, 3.75],
  ['claude-sonnet-4-20250514', 3, 15, 0.3, 3.75],
  ['claude-haiku-4-5-20251001', 1, 5, 0.1, 1.25],
  ['claude-3-5-haiku-20241022', 0.8, 4, 0.08, 1],
  ['claude-3-opus-20240229', 15, 75, 1.5, 18.75],
]

for (const [model, input, output, cacheRead, cacheWrite] of TABLE) {
  test(model, () => {
    assert.deepEqual(rateOf(model), { input, output, cacheRead, cacheWrite })
  })
}

test('Opus 4.1 and Opus 4 keep pre-drop pricing (3x current Opus)', () => {
  // Regression guard: these once fell through to the `opus` family fallback and
  // were billed at $5/$25 instead of $15/$75.
  assert.equal(perM('claude-opus-4-1', 'inputTokens'), 15)
  assert.equal(perM('claude-opus-4-0', 'inputTokens'), 15)
})

test('longest model id wins regardless of declaration order', () => {
  // "claude-opus-4" is a prefix of "claude-opus-4-8"; the more specific id must win.
  assert.equal(perM('claude-opus-4-8-20260101', 'inputTokens'), 5)
  assert.equal(perM('claude-opus-4-20250514', 'inputTokens'), 15)
})

test('bedrock-style prefix and [1m] suffix still resolve to the right family', () => {
  assert.equal(perM('anthropic.claude-opus-5', 'inputTokens'), 5)
  assert.equal(perM('claude-opus-5[1m]', 'inputTokens'), 5)
})

test('unknown model falls back to Sonnet list price, not intro price', () => {
  assert.equal(perM('some-unreleased-model', 'inputTokens'), 3)
  assert.equal(perM('some-unreleased-model', 'outputTokens'), 15)
})

test('empty model id does not throw', () => {
  assert.equal(perM('', 'inputTokens'), 3)
})

console.log('\ncomputeCost — Sonnet 5 introductory pricing\n')

test('Sonnet 5 bills $2/$10 through 2026-08-31', () => {
  assert.deepEqual(rateOf('claude-sonnet-5', NOW), {
    input: 2, output: 10, cacheRead: 0.2, cacheWrite: 2.5,
  })
})

test('Sonnet 5 reverts to $3/$15 from 2026-09-01', () => {
  assert.deepEqual(rateOf('claude-sonnet-5', AFTER_INTRO), {
    input: 3, output: 15, cacheRead: 0.3, cacheWrite: 3.75,
  })
})

test('the cutoff is exact', () => {
  const lastMoment = Date.UTC(2026, 8, 1) - 1
  assert.equal(perM('claude-sonnet-5', 'inputTokens', lastMoment), 2)
  assert.equal(perM('claude-sonnet-5', 'inputTokens', Date.UTC(2026, 8, 1)), 3)
})

test('a past request is priced at the rate in effect back then', () => {
  // Cost is computed from the request timestamp, so replaying/backfilling an
  // old row must not apply today's price.
  assert.equal(perM('claude-sonnet-5', 'inputTokens', Date.UTC(2026, 5, 1)), 2)
})

console.log('\ncomputeCost — fast mode\n')

test('fast mode doubles Opus 5 and Opus 4.8 rates', () => {
  assert.deepEqual(rateOf('claude-opus-5', NOW, { speed: 'fast' }), {
    input: 10, output: 50, cacheRead: 1, cacheWrite: 12.5,
  })
  assert.equal(perM('claude-opus-4-8', 'outputTokens', NOW, { speed: 'fast' }), 50)
})

test("speed: 'standard' is priced as standard", () => {
  assert.equal(perM('claude-opus-5', 'inputTokens', NOW, { speed: 'standard' }), 5)
})

test('fast flag on a model without fast mode falls back to standard rates', () => {
  // Opus 4.6 silently runs at standard speed and is billed at standard rates.
  assert.equal(perM('claude-opus-4-6', 'inputTokens', NOW, { speed: 'fast' }), 5)
  assert.equal(perM('claude-sonnet-5', 'inputTokens', NOW, { speed: 'fast' }), 2)
})

console.log('\ncomputeCost — cache write TTL split\n')

test('1h cache writes cost 2x input, 5m writes 1.25x', () => {
  const u = { ...zero(), cacheCreationTokens: M, cacheCreation1hTokens: M, cacheCreation5mTokens: 0 }
  assert.equal(computeCost('claude-opus-5', u, NOW), 10) // 5.00 * 2
  const v = { ...zero(), cacheCreationTokens: M, cacheCreation1hTokens: 0, cacheCreation5mTokens: M }
  assert.equal(computeCost('claude-opus-5', v, NOW), 6.25) // 5.00 * 1.25
})

test('a mixed-TTL write is billed per tier', () => {
  const u = {
    ...zero(),
    cacheCreationTokens: M,
    cacheCreation5mTokens: M / 2,
    cacheCreation1hTokens: M / 2,
  }
  // 0.5M @ 6.25 + 0.5M @ 10 = 3.125 + 5
  assert.equal(computeCost('claude-opus-5', u, NOW), 8.125)
})

test('missing breakdown bills the whole write at the 5m rate', () => {
  // Regression guard: when the parser reported 0/0 instead of undefined, this
  // priced a real cache write at $0.
  const u = { ...zero(), cacheCreationTokens: M }
  assert.equal(computeCost('claude-opus-5', u, NOW), 6.25)
})

test('a 1h-only breakdown infers the 5m remainder from the total', () => {
  const u = { ...zero(), cacheCreationTokens: M, cacheCreation1hTokens: M / 4 }
  // 0.25M @ 10 + 0.75M @ 6.25 = 2.5 + 4.6875
  assert.equal(computeCost('claude-opus-5', u, NOW), 7.1875)
})

test('a breakdown larger than the total never yields a negative charge', () => {
  const u = { ...zero(), cacheCreationTokens: 0, cacheCreation1hTokens: M }
  assert.equal(computeCost('claude-opus-5', u, NOW), 10)
})

console.log('\ncomputeCost — data residency and stacking\n')

test("inference_geo 'us' applies 1.1x to every category", () => {
  assert.deepEqual(rateOf('claude-opus-5', NOW, { inferenceGeo: 'us' }), {
    input: 5.5, output: 27.5, cacheRead: 0.55, cacheWrite: 6.875,
  })
})

test("inference_geo 'global' is standard priced", () => {
  assert.equal(perM('claude-opus-5', 'inputTokens', NOW, { inferenceGeo: 'global' }), 5)
})

test('fast mode and US residency stack multiplicatively', () => {
  assert.equal(perM('claude-opus-5', 'outputTokens', NOW, { speed: 'fast', inferenceGeo: 'us' }), 55)
})

test('a full realistic request adds up', () => {
  const u: UsageBreakdown = {
    inputTokens: 10_000,
    outputTokens: 15_000,
    cacheReadTokens: 40_000,
    cacheCreationTokens: 8_000,
    cacheCreation5mTokens: 8_000,
    cacheCreation1hTokens: 0,
  }
  // Mirrors the worked example in Anthropic's pricing docs, plus the cache write:
  // 10k@$5 = 0.05, 15k@$25 = 0.375, 40k@$0.50 = 0.02, 8k@$6.25 = 0.05
  assert.equal(computeCost('claude-opus-5', u, NOW).toFixed(4), '0.4950')
})

console.log('\nSSEUsageParser — pricing modifiers off the wire\n')

function sse(...events: object[]): string {
  return events.map((e) => `event: x\ndata: ${JSON.stringify(e)}\n\n`).join('')
}

test('captures the cache_creation TTL breakdown from message_start', () => {
  const p = new SSEUsageParser()
  p.feed(sse({
    type: 'message_start',
    message: {
      model: 'claude-opus-5',
      usage: {
        input_tokens: 100,
        cache_read_input_tokens: 1800,
        cache_creation_input_tokens: 248,
        cache_creation: { ephemeral_5m_input_tokens: 148, ephemeral_1h_input_tokens: 100 },
      },
    },
  }))
  p.end()
  const r = p.result()
  assert.equal(r.cacheCreationTokens, 248)
  assert.equal(r.cacheCreation5mTokens, 148)
  assert.equal(r.cacheCreation1hTokens, 100)
})

test('leaves the breakdown undefined when the response omits it', () => {
  const p = new SSEUsageParser()
  p.feed(sse({
    type: 'message_start',
    message: { model: 'claude-opus-5', usage: { input_tokens: 5, cache_creation_input_tokens: 248 } },
  }))
  p.end()
  const r = p.result()
  assert.equal(r.cacheCreation5mTokens, undefined)
  assert.equal(r.cacheCreation1hTokens, undefined)
  // ...and the total is still billed, at the 5m rate.
  assert.ok(computeCost(r.model, r, NOW) > 0)
})

test('captures usage.speed and usage.inference_geo', () => {
  const p = new SSEUsageParser()
  p.feed(sse({
    type: 'message_start',
    message: { model: 'claude-opus-5', usage: { input_tokens: 8, speed: 'fast', inference_geo: 'us' } },
  }))
  p.end()
  const r = p.result()
  assert.equal(r.speed, 'fast')
  assert.equal(r.inferenceGeo, 'us')
})

test('speed and geo default to empty when absent', () => {
  const p = new SSEUsageParser()
  p.feed(sse({ type: 'message_start', message: { model: 'claude-opus-5', usage: { input_tokens: 8 } } }))
  p.end()
  const r = p.result()
  assert.equal(r.speed, '')
  assert.equal(r.inferenceGeo, '')
  assert.equal(perM('claude-opus-5', 'inputTokens', NOW, { speed: r.speed, inferenceGeo: r.inferenceGeo }), 5)
})

test('an ignored non-enum speed value does not become a fast-mode charge', () => {
  const p = new SSEUsageParser()
  p.feed(sse({ type: 'message_start', message: { model: 'claude-opus-5', usage: { speed: 'turbo' } } }))
  p.end()
  assert.equal(p.result().speed, '')
})

test('modifiers survive a later message_delta that omits them', () => {
  const p = new SSEUsageParser()
  p.feed(sse(
    {
      type: 'message_start',
      message: {
        model: 'claude-opus-5',
        usage: {
          input_tokens: 100,
          speed: 'fast',
          inference_geo: 'us',
          cache_creation_input_tokens: 200,
          cache_creation: { ephemeral_5m_input_tokens: 200, ephemeral_1h_input_tokens: 0 },
        },
      },
    },
    { type: 'message_delta', usage: { output_tokens: 500 } },
  ))
  p.end()
  const r = p.result()
  assert.equal(r.speed, 'fast')
  assert.equal(r.inferenceGeo, 'us')
  assert.equal(r.outputTokens, 500)
  assert.equal(r.cacheCreation5mTokens, 200)
})

test('non-streaming JSON body carries the same fields', () => {
  const p = new SSEUsageParser()
  p.feed(JSON.stringify({
    model: 'claude-opus-4-8',
    usage: {
      input_tokens: 10,
      output_tokens: 20,
      speed: 'fast',
      cache_creation_input_tokens: 64,
      cache_creation: { ephemeral_5m_input_tokens: 0, ephemeral_1h_input_tokens: 64 },
    },
  }))
  p.end()
  const r = p.result()
  assert.equal(r.speed, 'fast')
  assert.equal(r.cacheCreation1hTokens, 64)
  // 10@$10 + 20@$50 + 64@$20 (1h write at 2x fast input)
  assert.equal(computeCost(r.model, r, NOW).toFixed(6), '0.002380')
})

console.log(`\n${passed} passed, ${failed} failed`)
if (failed > 0) process.exit(1)
