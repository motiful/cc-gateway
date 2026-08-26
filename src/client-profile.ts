import { getDb } from './db.js'

// Editable personal info a client manages from their portal. Purely
// informational — the client name in config.yaml remains the identity used for
// auth, metrics, and the launcher.

export interface ClientProfile {
  display_name: string
  email: string
  updated_at: number
}

const DISPLAY_NAME_MAX = 64
const EMAIL_MAX = 254
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/

export function getClientProfile(name: string): ClientProfile {
  const row = getDb()
    .prepare('SELECT display_name, email, updated_at FROM client_profiles WHERE client_name = ?')
    .get(name) as ClientProfile | undefined
  return row ?? { display_name: '', email: '', updated_at: 0 }
}

export function setClientProfile(
  name: string,
  input: { display_name?: string; email?: string },
): ClientProfile {
  const display_name = (input.display_name ?? '').trim()
  const email = (input.email ?? '').trim()
  if (display_name.length > DISPLAY_NAME_MAX) {
    throw new Error(`display name must be at most ${DISPLAY_NAME_MAX} characters`)
  }
  if (email.length > EMAIL_MAX) {
    throw new Error('email is too long')
  }
  if (email && !EMAIL_RE.test(email)) {
    throw new Error('email is not valid')
  }
  const db = getDb()
  const now = Date.now()
  db.prepare(
    `INSERT INTO client_profiles (client_name, display_name, email, updated_at)
     VALUES (?, ?, ?, ?)
     ON CONFLICT(client_name) DO UPDATE SET
       display_name = excluded.display_name,
       email = excluded.email,
       updated_at = excluded.updated_at`,
  ).run(name, display_name, email, now)
  return { display_name, email, updated_at: now }
}

export function removeClientProfile(name: string): void {
  getDb().prepare('DELETE FROM client_profiles WHERE client_name = ?').run(name)
}
