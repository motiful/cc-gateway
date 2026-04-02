#!/bin/bash
# Generate a launcher script for a client.
# Usage: bash scripts/add-client.sh <client-name> [token] [gateway-addr] [scheme]
#
# If token/addr are omitted, generates a new token and uses localhost defaults.
# scheme: "http" (default) or "https" (adds NODE_TLS_REJECT_UNAUTHORIZED=0 for self-signed certs)
set -e

cd "$(dirname "$0")/.."

CLIENT_NAME="${1:?Usage: add-client.sh <client-name> [token] [gateway-addr] [scheme]}"
CLIENT_TOKEN="${2:-$(openssl rand -hex 32)}"
GATEWAY_ADDR="${3:-localhost:8443}"
GATEWAY_SCHEME="${4:-http}"

CONFIG="config.yaml"
CLIENTS_DIR="clients"
mkdir -p "$CLIENTS_DIR"

# If token was auto-generated, append to config.yaml
if [[ -z "$2" ]]; then
  python3 -c "
import yaml, sys
with open('$CONFIG') as f:
    cfg = yaml.safe_load(f)
cfg['auth']['tokens'].append({'name': '$CLIENT_NAME', 'token': '$CLIENT_TOKEN'})
with open('$CONFIG', 'w') as f:
    yaml.dump(cfg, f, default_flow_style=False, sort_keys=False)
" 2>/dev/null || {
    echo "Note: Could not auto-update config.yaml. Add this manually:"
    echo "  - name: ${CLIENT_NAME}"
    echo "    token: ${CLIENT_TOKEN}"
  }
  echo "✓ Token added to config.yaml (restart gateway to pick up)"
fi

# Generate the launcher script
LAUNCHER="${CLIENTS_DIR}/cc-${CLIENT_NAME}"
cat > "$LAUNCHER" <<'SCRIPT_HEAD'
#!/bin/bash
# CC Gateway Client Launcher
#
# Usage:
#   ./cc-<name>                    Start Claude Code through gateway
#   ./cc-<name> --print "hello"    Single-shot mode
#   ./cc-<name> install            Install as 'ccg' command system-wide
#   ./cc-<name> uninstall          Remove 'ccg' and restore native claude
#   ./cc-<name> native             Run native claude (bypass gateway, one-time)
SCRIPT_HEAD

cat >> "$LAUNCHER" <<SCRIPT_VARS
GATEWAY_URL="${GATEWAY_SCHEME}://${GATEWAY_ADDR}"
CLIENT_TOKEN="${CLIENT_TOKEN}"
SCRIPT_VARS

# Add TLS bypass for self-signed certs (HTTPS mode only)
if [[ "$GATEWAY_SCHEME" == "https" ]]; then
  cat >> "$LAUNCHER" <<'SCRIPT_TLS'

# Accept self-signed TLS cert from gateway
export NODE_TLS_REJECT_UNAUTHORIZED=0
SCRIPT_TLS
fi

cat >> "$LAUNCHER" <<'SCRIPT_BODY'

INSTALL_PATH="/usr/local/bin/ccg"
SELF_PATH="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
# Detect shell RC file
case "$SHELL" in
  */zsh)  RC_FILE="${ZDOTDIR:-$HOME}/.zshrc" ;;
  */bash) RC_FILE="$HOME/.bashrc" ;;
  */fish) RC_FILE="${XDG_CONFIG_HOME:-$HOME/.config}/fish/config.fish" ;;
  *)      RC_FILE="$HOME/.profile" ;;
esac
ALIAS_TAG="# cc-gateway alias"

# ── Subcommands ──

case "$1" in
  install)
    cp "$0" "$INSTALL_PATH" 2>/dev/null || sudo cp "$0" "$INSTALL_PATH"
    chmod +x "$INSTALL_PATH"
    echo "Installed as 'ccg'."
    echo ""
    echo "  ccg              Start Claude Code through gateway"
    echo "  ccg hijack       Make 'claude' also go through gateway"
    echo "  ccg release      Restore 'claude' to native"
    echo "  ccg status       Show gateway connection status"
    echo "  ccg help         Show this help"
    exit 0
    ;;

  uninstall)
    rm "$INSTALL_PATH" 2>/dev/null || sudo rm "$INSTALL_PATH"
    if grep -q "$ALIAS_TAG" "$RC_FILE" 2>/dev/null; then
      sed -i.bak "/$ALIAS_TAG/d" "$RC_FILE"
      rm -f "${RC_FILE}.bak"
    fi
    echo "Removed. Native 'claude' restored."
    exit 0
    ;;

  hijack)
    if grep -q "$ALIAS_TAG" "$RC_FILE" 2>/dev/null; then
      echo "Already active. Run 'ccg release' to undo."
    else
      if [[ "$SHELL" == */fish ]]; then
        echo "alias claude 'ccg' $ALIAS_TAG" >> "$RC_FILE"
      else
        echo "alias claude='ccg' $ALIAS_TAG" >> "$RC_FILE"
      fi
      echo "Done. 'claude' now goes through gateway."
      echo "  New terminals: automatic."
      echo "  This terminal: reopen or run: source $RC_FILE"
      echo "  Undo anytime: ccg release"
    fi
    exit 0
    ;;

  release)
    if grep -q "$ALIAS_TAG" "$RC_FILE" 2>/dev/null; then
      sed -i.bak "/$ALIAS_TAG/d" "$RC_FILE"
      rm -f "${RC_FILE}.bak"
      # Unalias in current shell
      unalias claude 2>/dev/null
      echo "Done. 'claude' is back to native."
    else
      echo "Nothing to undo — 'claude' is already native."
    fi
    exit 0
    ;;

  native)
    shift
    exec command claude "$@"
    ;;

  status)
    echo "Gateway:  $GATEWAY_URL"
    if grep -q "$ALIAS_TAG" "$RC_FILE" 2>/dev/null; then
      echo "Hijack:   ON  (claude → gateway)"
    else
      echo "Hijack:   OFF (claude = native)"
    fi
    HEALTH=$(curl -sk --max-time 3 "${GATEWAY_URL}/_health" 2>/dev/null)
    if [[ -n "$HEALTH" ]]; then
      echo "Health:   OK"
    else
      echo "Health:   UNREACHABLE"
    fi
    exit 0
    ;;

  help|--help|-h)
    echo "ccg — Claude Code Gateway Client"
    echo ""
    echo "Usage:"
    echo "  ccg                    Start Claude Code through gateway"
    echo "  ccg [claude args]      Pass any arguments to Claude Code"
    echo "  ccg --print \"hi\"       Single-shot mode"
    echo ""
    echo "Setup:"
    echo "  ccg install            Install as 'ccg' system command"
    echo "  ccg uninstall          Remove 'ccg' and clean up"
    echo ""
    echo "Routing:"
    echo "  ccg hijack             Make 'claude' go through gateway"
    echo "  ccg release            Restore 'claude' to native"
    echo "  ccg native [args]      Run native claude once (bypass gateway)"
    echo ""
    echo "Info:"
    echo "  ccg status             Show gateway and hijack status"
    echo "  ccg help               Show this help"
    exit 0
    ;;
esac

# ── Main: launch through gateway ──

# Check claude is installed
if ! command -v claude &>/dev/null; then
  echo "Error: 'claude' not found. Install Claude Code first:"
  echo "  npm install -g @anthropic-ai/claude-code"
  exit 1
fi

# Set env vars for this process only — nothing is written to disk
export ANTHROPIC_API_KEY="$CLIENT_TOKEN"
export ANTHROPIC_BASE_URL="$GATEWAY_URL"
export CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1
export CLAUDE_CODE_ATTRIBUTION_HEADER=false

# Check gateway is reachable
HEALTH=$(curl -sk --max-time 3 "${GATEWAY_URL}/_health" 2>/dev/null)
if [[ -z "$HEALTH" ]]; then
  echo "Warning: Gateway at ${GATEWAY_URL} is not reachable."
  echo "Make sure the gateway is running."
  echo ""
fi

# Pass all arguments through to claude
exec claude "$@"
SCRIPT_BODY

chmod +x "$LAUNCHER"

echo "✓ Client launcher: ${LAUNCHER}"
echo "  Send this file to ${CLIENT_NAME}."
echo "  They run: chmod +x cc-${CLIENT_NAME} && ./cc-${CLIENT_NAME}"
