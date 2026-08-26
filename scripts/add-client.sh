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
  echo "✓ Token added to config.yaml (gateway will hot-reload within ~2s)"
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

# Pick a writable install dir. Apple Silicon Macs ship without /usr/local/bin
# by default; Intel Macs and most Linux distros have it. Fall back to
# ~/.local/bin so install always works without sudo as a last resort.
if [[ -d /opt/homebrew/bin ]]; then
  INSTALL_DIR="/opt/homebrew/bin"
elif [[ -d /usr/local/bin ]]; then
  INSTALL_DIR="/usr/local/bin"
else
  INSTALL_DIR="$HOME/.local/bin"
  mkdir -p "$INSTALL_DIR"
fi
INSTALL_PATH="$INSTALL_DIR/ccg"
SELF_PATH="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
# Detect shell RC file
case "$SHELL" in
  */zsh)  RC_FILE="${ZDOTDIR:-$HOME}/.zshrc" ;;
  */bash) RC_FILE="$HOME/.bashrc" ;;
  */fish) RC_FILE="${XDG_CONFIG_HOME:-$HOME/.config}/fish/config.fish" ;;
  *)      RC_FILE="$HOME/.profile" ;;
esac
ALIAS_TAG="# cc-gateway alias"

# Pre-approve this token in ~/.claude.json so Claude Code never shows the
# "Detected a custom API key ... Do you want to use this API key?" prompt.
# Claude Code records approval as the key's last 20 characters.
approve_token() {
  CLAUDE_JSON="$HOME/.claude.json"
  KEY_TAIL="${CLIENT_TOKEN: -20}"
  [[ ${#CLIENT_TOKEN} -lt 20 ]] && return 0
  if command -v node >/dev/null 2>&1; then
    node -e 'const fs=require("fs");const[p,t]=process.argv.slice(1);let j={};try{j=JSON.parse(fs.readFileSync(p,"utf8"))}catch(e){};if(typeof j!=="object"||j===null||Array.isArray(j))j={};const r=j.customApiKeyResponses=j.customApiKeyResponses||{};const a=r.approved=Array.isArray(r.approved)?r.approved:[];if(!a.includes(t)){a.push(t);fs.writeFileSync(p,JSON.stringify(j,null,2)+"\n")}' "$CLAUDE_JSON" "$KEY_TAIL" 2>/dev/null && return 0
  fi
  if command -v python3 >/dev/null 2>&1; then
    python3 -c 'import json,sys
p,t=sys.argv[1],sys.argv[2]
try:
    j=json.load(open(p))
except Exception:
    j={}
if not isinstance(j,dict): j={}
r=j.setdefault("customApiKeyResponses",{})
if not isinstance(r,dict):
    r={}; j["customApiKeyResponses"]=r
a=r.setdefault("approved",[])
if not isinstance(a,list):
    a=[]; r["approved"]=a
if t not in a:
    a.append(t)
    open(p,"w").write(json.dumps(j,indent=2)+"\n")' "$CLAUDE_JSON" "$KEY_TAIL" 2>/dev/null
  fi
  return 0
}

# ── Subcommands ──

case "$1" in
  install)
    if cp "$0" "$INSTALL_PATH" 2>/dev/null; then :; else
      sudo cp "$0" "$INSTALL_PATH" || { echo "Install failed: cannot write to $INSTALL_PATH"; exit 1; }
    fi
    chmod +x "$INSTALL_PATH" 2>/dev/null || sudo chmod +x "$INSTALL_PATH"
    echo "Installed as 'ccg' at $INSTALL_PATH."
    # Overwrite stale ccg copies from earlier installs (possibly pointing at
    # another gateway) so this launcher wins regardless of PATH order.
    for d in /opt/homebrew/bin /usr/local/bin "$HOME/.local/bin"; do
      OTHER="$d/ccg"
      if [[ "$OTHER" != "$INSTALL_PATH" && -f "$OTHER" ]]; then
        if cp "$0" "$OTHER" 2>/dev/null; then
          echo "Updated stale ccg at $OTHER."
        else
          echo "Warning: stale ccg at $OTHER could not be updated and may shadow this one."
          echo "  Remove it with: sudo rm $OTHER"
        fi
      fi
    done
    case ":$PATH:" in
      *":$INSTALL_DIR:"*) ;;
      *)
        echo ""
        echo "Note: $INSTALL_DIR is not on your PATH."
        echo "  Add this line to $RC_FILE and reopen your terminal:"
        echo "    export PATH=\"$INSTALL_DIR:\$PATH\""
        ;;
    esac
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

# Skip the one-time "use this API key?" confirmation for this token.
approve_token

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
