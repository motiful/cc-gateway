import { loadConfig } from '../config.js'
import { initDb } from '../db.js'
import { createUser, findUser } from '../users.js'
import { stdin, stdout } from 'process'

async function promptPassword(question: string): Promise<string> {
  return new Promise((resolve) => {
    process.stdout.write(question)
    let buf = ''
    const wasRaw = stdin.isRaw
    const onData = (ch: Buffer) => {
      for (const byte of ch) {
        if (byte === 0x0d || byte === 0x0a) {
          stdin.removeListener('data', onData)
          if (stdin.setRawMode) stdin.setRawMode(wasRaw)
          stdin.pause()
          process.stdout.write('\n')
          resolve(buf)
          return
        }
        if (byte === 0x03) {
          process.stdout.write('\n')
          process.exit(130)
        }
        if (byte === 0x7f || byte === 0x08) {
          buf = buf.slice(0, -1)
          continue
        }
        if (byte >= 0x20) {
          buf += String.fromCharCode(byte)
        }
      }
    }
    if (stdin.setRawMode) stdin.setRawMode(true)
    stdin.resume()
    stdin.on('data', onData)
  })
}

async function main() {
  const username = process.argv[2]
  if (!username) {
    console.error('Usage: npm run add-user <username> [-- <config-path>]')
    console.error('Or set PASSWORD env var to skip the interactive prompt')
    process.exit(1)
  }

  const configPath =
    process.argv[3] ||
    process.env.CCG_CONFIG_PATH ||
    '/app/data/config.yaml'
  const config = loadConfig(configPath)
  if (!config.db?.path) {
    console.error('config: db.path is required')
    process.exit(1)
  }

  initDb(config.db.path)

  if (findUser(username)) {
    console.error(`User "${username}" already exists`)
    process.exit(1)
  }

  let password = process.env.PASSWORD
  if (!password) {
    password = await promptPassword(`Password for ${username}: `)
    const confirm = await promptPassword('Confirm password: ')
    if (password !== confirm) {
      console.error('Passwords do not match')
      process.exit(1)
    }
  }

  if (!password || password.length < 8) {
    console.error('Password must be at least 8 characters')
    process.exit(1)
  }

  const user = createUser(username, password)
  console.log(`\nCreated user "${user.username}" (id=${user.id})`)
  console.log(`Login at: https://<your-domain>/login`)
}

main().catch((err) => {
  console.error(`Error: ${err instanceof Error ? err.message : err}`)
  process.exit(1)
})
