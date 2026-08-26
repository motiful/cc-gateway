// Request preview for the dashboard "message" column: a compact, faithful
// rendering of the LAST message in a /v1/messages request — the thing this
// request is actually asking the model to act on. Unlike the old
// "last user-authored prompt" preview, tool-continuation requests show their
// tool_result payload and side-channel requests (e.g. the auto-mode safety
// classifier) show their real text, instead of repeating the same human
// prompt for every request in a turn.

// Claude Code wraps a lot of synthetic context (hook output, slash-command
// metadata, reminders) inside the user message stream. None of it is text the
// human typed, so it is stripped from previews — but a message that was ONLY
// synthetic still gets a `[tag]` marker rather than an empty cell.
const SYNTHETIC_TAGS =
  'system-reminder|command-name|command-message|command-args|local-command-stdout|local-command-stderr|user-prompt-submit-hook'
const SYNTHETIC_BLOCK_RE = new RegExp(`<(${SYNTHETIC_TAGS})>[\\s\\S]*?</\\1>`, 'gi')
const FIRST_SYNTHETIC_TAG_RE = new RegExp(`<(${SYNTHETIC_TAGS})>`, 'i')

export function stripSyntheticBlocks(text: string): string {
  return text.replace(SYNTHETIC_BLOCK_RE, '').replace(/\s+/g, ' ').trim()
}

const PREVIEW_MAX = 200

/** Flatten a message's content (string or block array) into one preview line. */
function flattenContent(content: unknown): string {
  if (typeof content === 'string') return content
  if (!Array.isArray(content)) return ''
  const parts: string[] = []
  for (const block of content) {
    if (!block || typeof block !== 'object') continue
    const b = block as Record<string, unknown>
    if (b.type === 'text' && typeof b.text === 'string') {
      parts.push(b.text)
    } else if (b.type === 'tool_result') {
      const inner = flattenContent(b.content)
      parts.push(`[tool_result${b.is_error ? ' error' : ''}] ${inner}`.trim())
    } else if (b.type === 'tool_use') {
      let args = ''
      try {
        args = JSON.stringify(b.input)
      } catch {
        // non-serializable input — tag alone still identifies the call
      }
      parts.push(`[tool_use ${typeof b.name === 'string' ? b.name : ''}] ${args}`.trim())
    } else if (typeof b.type === 'string') {
      parts.push(`[${b.type}]`) // image, document, thinking, …
    }
  }
  return parts.join(' ')
}

/**
 * Pull a display preview of the request's last message out of a /v1/messages
 * body. Returns truncated text suitable for the dashboard, or '' if not
 * parseable.
 */
export function extractRequestPreview(body: Buffer): string {
  if (!body.length) return ''
  try {
    const obj = JSON.parse(body.toString('utf-8'))
    const msgs = obj?.messages
    if (!Array.isArray(msgs) || msgs.length === 0) return ''
    const last = msgs[msgs.length - 1]
    // Non-user senders are called out; a plain user message needs no prefix.
    const prefix = last?.role && last.role !== 'user' ? `[${last.role}] ` : ''
    const raw = flattenContent(last?.content)
    let flat = stripSyntheticBlocks(raw)
    if (!flat && raw.trim()) {
      const tag = raw.match(FIRST_SYNTHETIC_TAG_RE)?.[1]
      flat = tag ? `[${tag}]` : raw.replace(/\s+/g, ' ').trim()
    }
    const text = (prefix + flat).trim()
    if (!text) return ''
    return text.length > PREVIEW_MAX ? text.slice(0, PREVIEW_MAX) + '…' : text
  } catch {
    return ''
  }
}
