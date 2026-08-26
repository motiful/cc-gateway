// Set the gateway's CANONICAL working dir (the fake identity every client's real
// path is masked to). Edits config.yaml → prompt_env.working_dir in place,
// preserving comments/formatting.
//
// Usage:
//   npm run set-workdir -- /Users/dev            # → working_dir: /Users/dev/workspace
//   npm run set-workdir -- /Users/dev/projects   # used as-is
//   CCG_CONFIG_PATH=/app/data/config.yaml npm run set-workdir -- /Users/dev
//
// canonicalHomeOf() derives the home prefix as the first two path segments plus a
// trailing slash (/Users/dev/), so working_dir needs a segment AFTER the home;
// a bare two-segment home like /Users/dev gets /workspace appended automatically.
import { readFileSync, writeFileSync } from 'fs'
import { resolve } from 'path'
import { parseDocument, YAMLMap } from 'yaml'

function configPath(): string {
  return resolve(process.env.CCG_CONFIG_PATH || '/app/data/config.yaml')
}

function main() {
  const input = (process.argv[2] || '/Users/dev').trim()

  if (!/^\/[^/]+\/[^/]+/.test(input.replace(/\/+$/, '') + '/')) {
    console.error(`Invalid workdir "${input}".`)
    console.error('Give an absolute POSIX path with at least a home, e.g. /Users/dev')
    process.exit(1)
  }

  let workingDir = input.replace(/\/+$/, '')
  // Bare two-segment home (/Users/dev) → append a subdir so the derived home
  // prefix (/Users/dev/) is well-formed.
  if (/^\/[^/]+\/[^/]+$/.test(workingDir)) workingDir += '/workspace'

  const path = configPath()
  const raw = readFileSync(path, 'utf-8')
  const doc = parseDocument(raw)

  let pe = doc.getIn(['prompt_env'], true) as YAMLMap | undefined
  if (!pe) {
    pe = new YAMLMap()
    ;(doc.contents as YAMLMap).set('prompt_env', pe)
  }
  const before = pe.get('working_dir')
  pe.set('working_dir', workingDir)

  writeFileSync(path, doc.toString(), 'utf-8')

  const canonicalHome = workingDir.match(/^\/[^/]+\/[^/]+\//)?.[0] || `${workingDir}/`
  console.log(`✓ Updated ${path}`)
  console.log(`  prompt_env.working_dir: ${before ?? '(unset)'} → ${workingDir}`)
  console.log(`  canonical home prefix : ${canonicalHome}`)
  console.log('')
  console.log('Restart the gateway for it to take effect (e.g. docker compose restart, or restart the process).')
  console.log('Note: this changes the fake identity the model sees, so the prompt cache misses once.')
}

main()
