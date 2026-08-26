import { randomBytes, scryptSync, timingSafeEqual } from 'crypto'

// Shared scrypt password hashing used by both admin users and client portal
// credentials. Format: scrypt$N$r$p$saltHex$hashHex
const SCRYPT_N = 16384
const SCRYPT_r = 8
const SCRYPT_p = 1
const KEY_LEN = 64
const SALT_LEN = 16

export function hashPassword(password: string): string {
  const salt = randomBytes(SALT_LEN)
  const derived = scryptSync(password, salt, KEY_LEN, { N: SCRYPT_N, r: SCRYPT_r, p: SCRYPT_p })
  return `scrypt$${SCRYPT_N}$${SCRYPT_r}$${SCRYPT_p}$${salt.toString('hex')}$${derived.toString('hex')}`
}

export function verifyPassword(password: string, stored: string): boolean {
  const parts = stored.split('$')
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false
  const N = parseInt(parts[1], 10)
  const r = parseInt(parts[2], 10)
  const p = parseInt(parts[3], 10)
  const salt = Buffer.from(parts[4], 'hex')
  const expected = Buffer.from(parts[5], 'hex')
  const derived = scryptSync(password, salt, expected.length, { N, r, p })
  if (derived.length !== expected.length) return false
  return timingSafeEqual(derived, expected)
}

/**
 * Burn one scrypt cycle without comparing — used to keep "user not found" and
 * "wrong password" paths roughly constant-time so existence can't be timed.
 */
export function dummyHash(password: string): void {
  scryptSync(password, randomBytes(SALT_LEN), KEY_LEN, { N: SCRYPT_N, r: SCRYPT_r, p: SCRYPT_p })
}

/**
 * Generate a human-typable random password. Avoids ambiguous characters
 * (0/O, 1/l/I) so it can be read off a screen and retyped without confusion.
 */
export function generatePassword(length = 16): string {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789'
  const bytes = randomBytes(length)
  let out = ''
  for (let i = 0; i < length; i++) {
    out += alphabet[bytes[i] % alphabet.length]
  }
  return out
}
