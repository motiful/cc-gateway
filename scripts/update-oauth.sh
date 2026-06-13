#!/bin/bash
# CC Gateway OAuth re-login script.
# Generates a browser login URL, waits for you to paste the redirect URL back,
# exchanges the code for tokens, updates config.yaml, and restarts cc-gateway.

set -e

GATEWAY_DIR="/root/cc-gateway"
CONFIG="$GATEWAY_DIR/config.yaml"
CREDS_FILE="/root/.claude/.credentials.json"

CLIENT_ID="9d1c250a-e61b-44d9-88ed-5944d1962f5e"
AUTH_BASE="https://claude.ai/oauth/authorize"
TOKEN_URL="https://platform.claude.com/v1/oauth/token"
REDIRECT_URI="http://localhost/callback"
SCOPES="user:inference user:profile user:sessions:claude_code user:mcp_servers user:file_upload"

echo "=== CC Gateway OAuth Login ==="
echo ""

# Generate PKCE code_verifier (43+ chars, base64url of 32 random bytes)
CODE_VERIFIER=$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n')

# Generate code_challenge = base64url(sha256(code_verifier))
CODE_CHALLENGE=$(printf '%s' "$CODE_VERIFIER" | openssl dgst -sha256 -binary | openssl base64 | tr '+/' '-_' | tr -d '=\n')

# Random state
STATE=$(openssl rand -hex 16)

# Build authorization URL via python3 to handle URL encoding correctly
FULL_AUTH_URL=$(python3 -c "
import urllib.parse
params = {
    'response_type': 'code',
    'client_id': '$CLIENT_ID',
    'redirect_uri': '$REDIRECT_URI',
    'scope': '$SCOPES',
    'code_challenge': '$CODE_CHALLENGE',
    'code_challenge_method': 'S256',
    'state': '$STATE',
}
print('$AUTH_BASE?' + urllib.parse.urlencode(params))
")

echo "1. Open this URL in your browser:"
echo ""
echo "   $FULL_AUTH_URL"
echo ""
echo "2. Log in with your Anthropic account."
echo ""
echo "3. Your browser will redirect to http://localhost/callback?code=...&state=..."
echo "   (It will show a connection error — that is expected)"
echo ""
echo "4. Copy the FULL URL from your browser's address bar and paste it below."
echo ""
read -rp "Paste the redirect URL here: " CALLBACK_URL

# Save CODE_VERIFIER and callback URL to temp files to avoid shell injection
TMPDIR_WORK=$(mktemp -d)
trap 'rm -rf "$TMPDIR_WORK"' EXIT

echo -n "$CODE_VERIFIER" > "$TMPDIR_WORK/verifier"
echo -n "$CALLBACK_URL" > "$TMPDIR_WORK/callback"

# Extract code from pasted value: accepts a full callback URL,
# the "code#state" string claude.ai shows, or a bare code.
CODE=$(python3 - "$TMPDIR_WORK/callback" << 'PY'
import sys, urllib.parse
raw = open(sys.argv[1]).read().strip()
code = None
if '://' in raw or raw.lower().startswith('http'):
    params = urllib.parse.parse_qs(urllib.parse.urlparse(raw).query)
    code = params.get('code', [None])[0]
if not code:
    # claude.ai returns "code#state"; a bare code is also accepted.
    code = raw.split('#', 1)[0].strip()
if not code:
    raise SystemExit("Error: could not parse an authorization code from the pasted value.")
print(code)
PY
)

echo ""
echo "Code received. Exchanging for tokens..."

# Exchange code for tokens — write result to temp file
python3 - "$TMPDIR_WORK/verifier" "$CODE" "$TMPDIR_WORK/tokens.json" << 'PY'
import sys, json, time
from urllib.request import urlopen, Request
from urllib.error import HTTPError
from urllib.parse import urlencode

verifier_file, code, out_file = sys.argv[1:]
code_verifier = open(verifier_file).read().strip()

CLIENT_ID    = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
TOKEN_URL    = "https://platform.claude.com/v1/oauth/token"
REDIRECT_URI = "http://localhost/callback"

body = urlencode({
    "grant_type":    "authorization_code",
    "code":          code,
    "redirect_uri":  REDIRECT_URI,
    "client_id":     CLIENT_ID,
    "code_verifier": code_verifier,
}).encode()

req = Request(TOKEN_URL, data=body, headers={
    "Content-Type": "application/x-www-form-urlencoded",
    "Accept": "application/json",
    "Accept-Language": "en-US,en;q=0.9",
    # Cloudflare returns error 1010 (banned client signature) for the default
    # Python-urllib User-Agent; present a normal browser UA instead.
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
})
try:
    with urlopen(req) as resp:
        data = json.load(resp)
except HTTPError as e:
    body_bytes = e.read()
    raise SystemExit(f"Token exchange failed ({e.code}): {body_bytes.decode()}")

if "error" in data:
    raise SystemExit(f"OAuth error: {data['error']}: {data.get('error_description', '')}")

access_token  = data["access_token"]
refresh_token = data.get("refresh_token", "")
expires_in    = data.get("expires_in", 3600)
expires_at    = int(time.time() * 1000) + expires_in * 1000

result = {
    "access_token":  access_token,
    "refresh_token": refresh_token,
    "expires_at":    expires_at,
}
with open(out_file, "w") as f:
    json.dump(result, f)
print("Token exchange OK.")
PY

echo ""

# Read tokens from temp file and apply
python3 - "$TMPDIR_WORK/tokens.json" "$CONFIG" "$CREDS_FILE" << 'PY'
import sys, json, re, shutil, time

tokens_file, config_path, creds_file = sys.argv[1:]

with open(tokens_file) as f:
    tok = json.load(f)

access_token  = tok["access_token"]
refresh_token = tok["refresh_token"]
expires_at    = tok["expires_at"]

# Update ~/.claude/.credentials.json
creds = {"claudeAiOauth": {
    "accessToken":  access_token,
    "refreshToken": refresh_token,
    "expiresAt":    expires_at,
    "scopes": [
        "user:file_upload","user:inference","user:mcp_servers",
        "user:profile","user:sessions:claude_code"
    ],
}}
with open(creds_file, "w") as f:
    json.dump(creds, f)
print(f"Updated {creds_file}")

# Backup and update config.yaml
shutil.copy(config_path, config_path + ".bak." + time.strftime("%Y%m%d_%H%M%S"))
with open(config_path) as f:
    content = f.read()

# Line-anchored replacement so it works whether the field already holds a
# token or is empty, and preserves the YAML indentation. Lambdas avoid any
# backreference issues if a token contained a backslash.
content = re.sub(r"(?m)^(\s*access_token:).*$",  lambda m: m.group(1) + " " + access_token,    content)
content = re.sub(r"(?m)^(\s*refresh_token:).*$", lambda m: m.group(1) + " " + refresh_token,   content)
content = re.sub(r"(?m)^(\s*expires_at:).*$",    lambda m: m.group(1) + " " + str(expires_at), content)

with open(config_path, "w") as f:
    f.write(content)
print(f"Updated {config_path}")
PY

echo ""
echo "Restarting cc-gateway..."
systemctl restart cc-gateway.service
sleep 3

if systemctl is-active --quiet cc-gateway.service; then
    echo "cc-gateway is running."
    journalctl -u cc-gateway.service -n 5 --no-pager | grep -E 'INFO|WARN|Fatal'
else
    echo "ERROR: cc-gateway failed to start."
    journalctl -u cc-gateway.service -n 20 --no-pager
    exit 1
fi
