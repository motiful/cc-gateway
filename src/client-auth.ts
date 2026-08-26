import { getDb } from './db.js'
import { hashPassword, verifyPassword, dummyHash, generatePassword } from './password.js'

// Portal login credentials for clients. Distinct from admin `users`: keyed by
// client name and gated on a password the admin generates at creation time.
// Clients can rotate their own password from the portal.

const MIN_PASSWORD_LEN = 8

interface CredentialRow {
  client_name: string
  password_hash: string
  created_at: number
  updated_at: number
}

export function setClientPassword(name: string, password: string): void {
  if (password.length < MIN_PASSWORD_LEN) {
    throw new Error(`password must be at least ${MIN_PASSWORD_LEN} characters`)
  }
  const db = getDb()
  const now = Date.now()
  const hash = hashPassword(password)
  db.prepare(
    `INSERT INTO client_credentials (client_name, password_hash, created_at, updated_at)
     VALUES (?, ?, ?, ?)
     ON CONFLICT(client_name) DO UPDATE SET password_hash = excluded.password_hash, updated_at = excluded.updated_at`,
  ).run(name, hash, now, now)
}

/** Generate a fresh random password for the client, store its hash, return the plaintext (shown once). */
export function generateAndSetClientPassword(name: string): string {
  const password = generatePassword(16)
  setClientPassword(name, password)
  return password
}

export function hasClientPassword(name: string): boolean {
  const row = getDb()
    .prepare('SELECT 1 FROM client_credentials WHERE client_name = ?')
    .get(name)
  return !!row
}

/** Credential timestamps for the portal "account" view, or null if no password set. */
export function getClientCredentialMeta(name: string): { created_at: number; updated_at: number } | null {
  const row = getDb()
    .prepare('SELECT created_at, updated_at FROM client_credentials WHERE client_name = ?')
    .get(name) as { created_at: number; updated_at: number } | undefined
  return row ?? null
}

export function verifyClientPassword(name: string, password: string): boolean {
  const row = getDb()
    .prepare('SELECT * FROM client_credentials WHERE client_name = ?')
    .get(name) as CredentialRow | undefined
  if (!row) {
    dummyHash(password)
    return false
  }
  return verifyPassword(password, row.password_hash)
}

/** Verify the current password, then set a new one. Throws on mismatch or weak password. */
export function changeClientPassword(name: string, currentPassword: string, newPassword: string): void {
  if (!verifyClientPassword(name, currentPassword)) {
    throw new Error('current password is incorrect')
  }
  setClientPassword(name, newPassword)
}

export function removeClientPassword(name: string): void {
  getDb().prepare('DELETE FROM client_credentials WHERE client_name = ?').run(name)
}
