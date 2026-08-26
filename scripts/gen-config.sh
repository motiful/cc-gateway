#!/bin/bash
# Generate config.yaml for CC Gateway from existing Claude Code OAuth login.
#
# Usage:
#   bash scripts/gen-config.sh                              # print to stdout
#   bash scripts/gen-config.sh > config.yaml                # save to file
#   bash scripts/gen-config.sh --client whiletrue0x         # set seed client name
#   bash scripts/gen-config.sh --out /path/to/config.yaml   # write directly
#
# Server use (Coolify host):
#   bash scripts/gen-config.sh --out /data/coolify/applications/<id>/config.yaml \
#     && docker restart <container_id>
set -e

CLIENT_NAME="whiletrue0x"
OUT_FILE=""
DEVICE_ID=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --client) CLIENT_NAME="$2"; shift 2 ;;
    --out)    OUT_FILE="$2";    shift 2 ;;
    --device) DEVICE_ID="$2";   shift 2 ;;
    -h|--help)
      sed -n '2,11p' "$0" | sed 's/^# \?//'
      exit 0
      ;;
    *) echo "Unknown arg: $1" >&2; exit 1 ;;
  esac
done

[[ -z "$DEVICE_ID" ]] && DEVICE_ID=$(openssl rand -hex 32)
CLIENT_TOKEN=$(openssl rand -hex 32)

# Extract OAuth from macOS Keychain or Linux credentials file
CREDS=$(security find-generic-password -a "$USER" -s "Claude Code-credentials" -w 2>/dev/null || true)
if [[ -z "$CREDS" ]]; then
  for f in "$HOME/.claude/.credentials.json" "$HOME/.config/claude/.credentials.json"; do
    if [[ -f "$f" ]]; then CREDS=$(cat "$f"); break; fi
  done
fi
if [[ -z "$CREDS" ]]; then
  echo "Error: No Claude Code OAuth credentials found." >&2
  echo "Run 'claude' first to login, then re-run this script." >&2
  exit 1
fi

eval "$(echo "$CREDS" | python3 -c "
import sys, json
d = json.load(sys.stdin)['claudeAiOauth']
print(f'ACCESS_TOKEN=\"{d[\"accessToken\"]}\"')
print(f'REFRESH_TOKEN=\"{d[\"refreshToken\"]}\"')
print(f'EXPIRES_AT={d.get(\"expiresAt\", 0)}')
")"

if [[ -z "$REFRESH_TOKEN" ]]; then
  echo "Error: Could not extract refresh_token from credentials." >&2
  exit 1
fi

NODE_VER=$(node -v 2>/dev/null || echo "v22.0.0")
OS_VER=$(uname -sr)

read -r -d '' CONFIG_BODY <<YAML || true
server:
  port: 8443

upstream:
  url: https://api.anthropic.com

oauth:
  access_token: "${ACCESS_TOKEN}"
  refresh_token: "${REFRESH_TOKEN}"
  expires_at: ${EXPIRES_AT}

auth:
  tokens:
    - name: ${CLIENT_NAME}
      token: ${CLIENT_TOKEN}

identity:
  device_id: "${DEVICE_ID}"
  email: "user@example.com"

env:
  platform: darwin
  platform_raw: darwin
  arch: arm64
  node_version: ${NODE_VER}
  terminal: iTerm2.app
  package_managers: npm,pnpm
  runtimes: node
  is_running_with_bun: false
  is_ci: false
  is_claude_ai_auth: true
  version: "2.1.81"
  version_base: "2.1.81"
  build_time: "2026-03-20T21:26:18Z"
  deployment_environment: unknown-darwin
  vcs: git

prompt_env:
  platform: darwin
  shell: zsh
  os_version: "${OS_VER}"
  working_dir: /Users/jack/projects

process:
  constrained_memory: 34359738368
  rss_range: [300000000, 500000000]
  heap_total_range: [40000000, 80000000]
  heap_used_range: [100000000, 200000000]

logging:
  level: info
  audit: true

db:
  path: /app/data/ccg.db
YAML

if [[ -n "$OUT_FILE" ]]; then
  mkdir -p "$(dirname "$OUT_FILE")"
  printf '%s\n' "$CONFIG_BODY" > "$OUT_FILE"
  chmod 600 "$OUT_FILE"
  echo "✓ Wrote $OUT_FILE" >&2
  echo "  seed client: ${CLIENT_NAME}" >&2
  echo "  client token: ${CLIENT_TOKEN}" >&2
  echo "  device_id: ${DEVICE_ID:0:8}..." >&2
else
  printf '%s\n' "$CONFIG_BODY"
fi
