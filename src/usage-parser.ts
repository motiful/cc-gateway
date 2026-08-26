/**
 * Streaming SSE parser for Anthropic /v1/messages responses.
 *
 * Anthropic streams events like:
 *   event: message_start
 *   data: {"type":"message_start","message":{"id":"...","model":"claude-...","usage":{"input_tokens":N,...}}}
 *
 *   event: content_block_delta
 *   data: {"type":"content_block_delta",...}
 *
 *   event: message_delta
 *   data: {"type":"message_delta","usage":{"output_tokens":N}}
 *
 *   event: message_stop
 *   data: {"type":"message_stop"}
 *
 * `message_start` carries the model id and initial usage (input + cache fields).
 * `message_delta` is emitted just before stop and carries the final output_tokens.
 *
 * Non-streaming responses (rare for claude-code) return a single JSON body
 * with `usage` at the root — handle both.
 */
export interface ParsedUsage {
  model: string
  inputTokens: number
  outputTokens: number
  cacheReadTokens: number
  cacheCreationTokens: number
  /**
   * TTL split of cacheCreationTokens, from `usage.cache_creation`. The two sum
   * to cacheCreationTokens. Left `undefined` — not zero — when the response
   * omits the breakdown, so pricing can tell "no 1h writes" apart from
   * "unknown" and fall back to charging the whole figure at the 5m rate.
   */
  cacheCreation5mTokens?: number
  cacheCreation1hTokens?: number
  /** `usage.speed` — 'fast' bills at premium rates. Absent → standard. */
  speed: 'standard' | 'fast' | ''
  /** `usage.inference_geo` — 'us' carries a 1.1x price multiplier. */
  inferenceGeo: string
}

export class SSEUsageParser {
  private buffer = ''
  private model = ''
  private inputTokens = 0
  private outputTokens = 0
  private cacheReadTokens = 0
  private cacheCreationTokens = 0
  private cacheCreation5mTokens: number | undefined
  private cacheCreation1hTokens: number | undefined
  private speed: 'standard' | 'fast' | '' = ''
  private inferenceGeo = ''
  private isStreaming = false

  feed(chunk: Buffer | string): void {
    this.buffer += typeof chunk === 'string' ? chunk : chunk.toString('utf-8')

    // Detect SSE format on first useful bytes
    if (!this.isStreaming) {
      const trimmed = this.buffer.trimStart()
      if (trimmed.startsWith('event:') || trimmed.startsWith('data:')) {
        this.isStreaming = true
      }
    }

    if (this.isStreaming) {
      this.flushSseEvents()
    }
  }

  /** Call when the response stream has ended. */
  end(): void {
    if (this.isStreaming) {
      // Drain any partial event left in buffer (shouldn't usually happen)
      this.flushSseEvents()
      return
    }
    // Non-streaming path: buffer holds a single JSON document
    const text = this.buffer.trim()
    if (!text) return
    try {
      const obj = JSON.parse(text)
      this.absorbMessageObject(obj)
    } catch {
      // body wasn't JSON or got truncated — just leave usage at zero
    }
  }

  result(): ParsedUsage {
    return {
      model: this.model,
      inputTokens: this.inputTokens,
      outputTokens: this.outputTokens,
      cacheReadTokens: this.cacheReadTokens,
      cacheCreationTokens: this.cacheCreationTokens,
      cacheCreation5mTokens: this.cacheCreation5mTokens,
      cacheCreation1hTokens: this.cacheCreation1hTokens,
      speed: this.speed,
      inferenceGeo: this.inferenceGeo,
    }
  }

  // ── internals ──────────────────────────────────────────────────────────

  private flushSseEvents(): void {
    let idx
    while ((idx = this.buffer.indexOf('\n\n')) !== -1) {
      const block = this.buffer.slice(0, idx)
      this.buffer = this.buffer.slice(idx + 2)
      this.parseEventBlock(block)
    }
    // Some servers use \r\n\r\n
    while ((idx = this.buffer.indexOf('\r\n\r\n')) !== -1) {
      const block = this.buffer.slice(0, idx)
      this.buffer = this.buffer.slice(idx + 4)
      this.parseEventBlock(block)
    }
  }

  private parseEventBlock(block: string): void {
    // Block is one or more lines like "event: foo" / "data: {...}"
    const lines = block.split(/\r?\n/)
    let dataPayload = ''
    for (const line of lines) {
      if (line.startsWith('data:')) {
        // Per SSE spec, multiple data: lines join with \n
        dataPayload += (dataPayload ? '\n' : '') + line.slice(5).trimStart()
      }
    }
    if (!dataPayload || dataPayload === '[DONE]') return
    try {
      const obj = JSON.parse(dataPayload)
      this.absorbStreamingEvent(obj)
    } catch {
      // ignore malformed
    }
  }

  private absorbStreamingEvent(obj: any): void {
    if (!obj || typeof obj !== 'object') return
    if (obj.type === 'message_start' && obj.message) {
      if (typeof obj.message.model === 'string') this.model = obj.message.model
      this.absorbUsage(obj.message.usage)
    } else if (obj.type === 'message_delta') {
      this.absorbUsage(obj.usage)
    }
  }

  private absorbMessageObject(obj: any): void {
    if (!obj || typeof obj !== 'object') return
    if (typeof obj.model === 'string') this.model = obj.model
    this.absorbUsage(obj.usage)
  }

  private absorbUsage(u: any): void {
    if (!u || typeof u !== 'object') return
    // message_delta only sends fields that changed — take max so we keep the
    // largest value seen for each counter (handles partial updates safely).
    if (typeof u.input_tokens === 'number')
      this.inputTokens = Math.max(this.inputTokens, u.input_tokens)
    if (typeof u.output_tokens === 'number')
      this.outputTokens = Math.max(this.outputTokens, u.output_tokens)
    if (typeof u.cache_read_input_tokens === 'number')
      this.cacheReadTokens = Math.max(this.cacheReadTokens, u.cache_read_input_tokens)
    if (typeof u.cache_creation_input_tokens === 'number')
      this.cacheCreationTokens = Math.max(this.cacheCreationTokens, u.cache_creation_input_tokens)

    // Per-TTL breakdown of the cache write. Priced differently: 5m writes are
    // 1.25x base input, 1h writes are 2x.
    const cc = u.cache_creation
    if (cc && typeof cc === 'object') {
      if (typeof cc.ephemeral_5m_input_tokens === 'number')
        this.cacheCreation5mTokens = Math.max(this.cacheCreation5mTokens ?? 0, cc.ephemeral_5m_input_tokens)
      if (typeof cc.ephemeral_1h_input_tokens === 'number')
        this.cacheCreation1hTokens = Math.max(this.cacheCreation1hTokens ?? 0, cc.ephemeral_1h_input_tokens)
    }

    // Pricing modifiers. Both are stable for a given request, so first
    // non-empty value wins — no need to reconcile across message_delta.
    if (u.speed === 'fast' || u.speed === 'standard') this.speed = u.speed
    if (typeof u.inference_geo === 'string' && u.inference_geo) this.inferenceGeo = u.inference_geo
  }
}
