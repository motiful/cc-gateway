#!/bin/bash
# One-command setup: generates config.yaml, extracts OAuth, and starts the gateway.
# Usage: bash scripts/quick-setup.sh
set -e

cd "$(dirname "$0")/.."

CONFIG="config.yaml"

if [[ -f "$CONFIG" ]]; then
  echo "config.yaml already exists. Starting gateway..."
  exec npm run dev
fi

echo "=== CC Gateway Quick Setup ==="
echo ""

# 1. Generate identity + client token
DEVICE_ID=$(openssl rand -hex 32)
CLIENT_TOKEN=$(openssl rand -hex 32)
CLIENT_NAME="${1:-whiletrue0x}"

# 2. Extract full OAuth credentials from macOS Keychain / fallback file
CREDS=$(security find-generic-password -a "$USER" -s "Claude Code-credentials" -w 2>/dev/null || true)
if [[ -z "$CREDS" ]]; then
  CRED_FILE="$HOME/.claude/.credentials.json"
  if [[ -f "$CRED_FILE" ]]; then
    CREDS=$(cat "$CRED_FILE")
  else
    echo "Error: No Claude Code credentials found."
    echo "Run 'claude' first and complete browser OAuth login, then re-run this script."
    exit 1
  fi
fi

# Extract all three: access_token, refresh_token, expires_at
eval "$(echo "$CREDS" | python3 -c "
import sys, json
d = json.load(sys.stdin)['claudeAiOauth']
print(f'ACCESS_TOKEN=\"{d[\"accessToken\"]}\"')
print(f'REFRESH_TOKEN=\"{d[\"refreshToken\"]}\"')
print(f'EXPIRES_AT={d.get(\"expiresAt\", 0)}')
")"

if [[ -z "$REFRESH_TOKEN" ]]; then
  echo "Error: Could not extract tokens."
  exit 1
fi

# 3. Write config.yaml
cat > "$CONFIG" <<YAML
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
  node_version: $(node -v)
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
  os_version: "Darwin $(uname -r)"
  working_dir: /Users/jack/projects

process:
  constrained_memory: 34359738368
  rss_range: [300000000, 500000000]
  heap_total_range: [40000000, 80000000]
  heap_used_range: [100000000, 200000000]

logging:
  level: info
  audit: true
YAML

echo ""
echo "config.yaml created."
echo ""

# Generate client launcher
mkdir -p clients
bash scripts/add-client.sh "${CLIENT_NAME}" "${CLIENT_TOKEN}" "localhost:8443"

echo ""
echo "Starting gateway..."
echo ""

exec npm run dev
