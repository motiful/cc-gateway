import { getDb } from './db.js'
import { hashPassword, verifyPassword, dummyHash } from './password.js'

export interface User {
  id: number
  username: string
  password_hash: string
  created_at: number
}

export function createUser(username: string, password: string): User {
  if (!/^[a-zA-Z0-9_.-]{3,32}$/.test(username)) {
    throw new Error('username must be 3-32 chars, [a-zA-Z0-9_.-]')
  }
  if (password.length < 8) {
    throw new Error('password must be at least 8 characters')
  }
  const db = getDb()
  const hash = hashPassword(password)
  const now = Date.now()
  const result = db
    .prepare('INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)')
    .run(username, hash, now)
  return { id: Number(result.lastInsertRowid), username, password_hash: hash, created_at: now }
}

export function findUser(username: string): User | null {
  const row = getDb().prepare('SELECT * FROM users WHERE username = ?').get(username) as User | undefined
  return row ?? null
}

export function authenticateUser(username: string, password: string): User | null {
  const user = findUser(username)
  if (!user) {
    // Constant-time-ish: still run a hash to avoid leaking existence via timing
    dummyHash(password)
    return null
  }
  return verifyPassword(password, user.password_hash) ? user : null
}

export function countUsers(): number {
  const row = getDb().prepare('SELECT COUNT(*) as c FROM users').get() as { c: number }
  return row.c
}
