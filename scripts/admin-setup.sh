#!/bin/bash
# Production deployment: generate config, TLS certs, build Docker, start gateway.
# Usage: bash scripts/admin-setup.sh
set -e

cd "$(dirname "$0")/.."

CONFIG="config.yaml"

# ── If config exists, just start ──
if [[ -f "$CONFIG" ]]; then
  echo "config.yaml exists. Starting gateway..."
  if command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
    docker compose up -d --build
  else
    echo "Docker not available, starting with Node..."
    npm run build && npm start
  fi
  echo ""
  echo "Gateway running. Add clients with:"
  echo "  bash scripts/add-client.sh <name>"
  exit 0
fi

echo "=== CC Gateway Admin Setup ==="
echo ""

# ── 1. Extract OAuth credentials ──
CREDS=$(security find-generic-password -a "$USER" -s "Claude Code-credentials" -w 2>/dev/null || true)
if [[ -z "$CREDS" ]]; then
  CRED_FILE="$HOME/.claude/.credentials.json"
  if [[ -f "$CRED_FILE" ]]; then
    CREDS=$(cat "$CRED_FILE")
  else
    echo "Error: No Claude Code credentials found."
    echo "Run 'claude' and complete browser login first."
    exit 1
  fi
fi

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
echo "✓ OAuth credentials extracted"

# ── 2. Deployment mode ──
echo ""
echo "Deployment mode:"
echo "  1) Public / LAN  — clients connect over network (HTTPS, auto-generates TLS cert)"
echo "  2) Tailscale/VPN — tunnel already encrypts traffic (HTTP, no cert needed)"
echo ""
read -p "Choose [1/2]: " DEPLOY_MODE
DEPLOY_MODE="${DEPLOY_MODE:-1}"

# ── 3. Gateway address ──
DEFAULT_IP=$(ipconfig getifaddr en0 2>/dev/null || hostname -I 2>/dev/null | awk '{print $1}' || echo "0.0.0.0")
read -p "Gateway address for clients [${DEFAULT_IP}]: " GATEWAY_HOST
GATEWAY_HOST="${GATEWAY_HOST:-${DEFAULT_IP}}"

# ── 4. TLS setup ──
TLS_CONFIG=""
GATEWAY_SCHEME="http"
GATEWAY_PORT="8443"

if [[ "$DEPLOY_MODE" == "1" ]]; then
  GATEWAY_SCHEME="https"
  mkdir -p certs

  if [[ -f certs/cert.pem && -f certs/key.pem ]]; then
    echo "✓ Existing TLS certs found in certs/"
  else
    echo "Generating self-signed TLS certificate..."
    openssl req -x509 -newkey rsa:2048 \
      -keyout certs/key.pem -out certs/cert.pem \
      -days 365 -nodes \
      -subj "/CN=${GATEWAY_HOST}" \
      -addext "subjectAltName=IP:${GATEWAY_HOST},DNS:${GATEWAY_HOST}" \
      2>/dev/null
    echo "✓ TLS cert generated (valid 365 days)"
  fi

  TLS_CONFIG="
  tls:
    cert: ./certs/cert.pem
    key: ./certs/key.pem"
fi

GATEWAY_URL="${GATEWAY_SCHEME}://${GATEWAY_HOST}:${GATEWAY_PORT}"

# ── 5. Generate identity + admin token ──
DEVICE_ID=$(openssl rand -hex 32)
ADMIN_TOKEN=$(openssl rand -hex 32)
ADMIN_NAME=$(hostname -s)
echo "✓ Device ID: ${DEVICE_ID:0:8}..."

# ── 6. Write config.yaml ──
cat > "$CONFIG" <<YAML
server:
  port: ${GATEWAY_PORT}${TLS_CONFIG}

upstream:
  url: https://api.anthropic.com

oauth:
  access_token: "${ACCESS_TOKEN}"
  refresh_token: "${REFRESH_TOKEN}"
  expires_at: ${EXPIRES_AT}

auth:
  tokens:
    - name: ${ADMIN_NAME}
      token: ${ADMIN_TOKEN}

identity:
  device_id: "${DEVICE_ID}"
  email: "user@example.com"

env:
  platform: darwin
  platform_raw: darwin
  arch: arm64
  node_version: $(node -v 2>/dev/null || echo "v22.0.0")
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

echo "✓ config.yaml created"

# ── 7. Generate admin launcher ──
mkdir -p clients
bash scripts/add-client.sh "${ADMIN_NAME}" "${ADMIN_TOKEN}" "${GATEWAY_HOST}:${GATEWAY_PORT}" "${GATEWAY_SCHEME}"
echo ""

# ── 8. Start gateway ──
echo "Starting gateway..."
if command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
  if docker compose up -d --build 2>&1; then
    echo "✓ Gateway running (Docker): ${GATEWAY_URL}"
  else
    echo ""
    echo "Docker build failed. If behind a proxy, configure Docker daemon:"
    echo '  ~/.docker/config.json → { "proxies": { "default": { "httpProxy": "http://127.0.0.1:7890", "httpsProxy": "http://127.0.0.1:7890" } } }'
    echo "Then retry: docker compose up -d --build"
    echo ""
    echo "Or skip Docker:  HTTPS_PROXY=http://127.0.0.1:7890 npm run dev"
  fi
else
  echo "Docker not available. Start with:"
  echo "  npm run build && npm start"
  echo "  # or: npm run dev"
fi

echo ""
echo "=== Setup Complete ==="
echo "  Gateway:        ${GATEWAY_URL}"
echo "  Admin launcher: ./clients/cc-${ADMIN_NAME}"
echo "  Health check:   curl ${GATEWAY_URL}/_health"
echo ""
echo "  Add more clients:"
echo "    bash scripts/add-client.sh alice"
echo "    bash scripts/add-client.sh bob"
echo "  Then send ./clients/cc-<name> to each user."
