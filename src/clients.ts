import { readFileSync, writeFileSync } from 'fs'
import { resolve } from 'path'
import { randomBytes } from 'crypto'
import { parseDocument, YAMLSeq, YAMLMap } from 'yaml'
import type { CostLimitPeriod } from './config.js'

export interface ClientEntry {
  name: string
  token: string
  cost_limit_usd?: number
  cost_limit_period?: CostLimitPeriod
  home_dir?: string
}

export interface ClientLimitInput {
  cost_limit_usd?: number | null
  cost_limit_period?: CostLimitPeriod | null
}

const NAME_RE = /^[a-zA-Z0-9_.-]{1,64}$/
const VALID_PERIODS: CostLimitPeriod[] = ['lifetime', 'monthly', 'daily']

// A client's real home dir: POSIX absolute (/Users/alice, /home/alice, …) or a
// Windows path (C:\Users\alice). Kept deliberately loose but anchored so a stray
// value can't inject unrelated reverse pairs.
const POSIX_HOME_RE = /^\/[^\s]{1,200}$/
const WIN_HOME_RE = /^[A-Za-z]:\\[^\s]{1,200}$/

export function normalizeHomeDir(raw: string): string | null {
  const t = raw.trim().replace(/[\\/]+$/, '') // drop any trailing separator
  if (!t) return null
  if (POSIX_HOME_RE.test(t) || WIN_HOME_RE.test(t)) return t
  return null
}

function configPath(): string {
  return resolve(
    process.argv[2] ||
    process.env.CCG_CONFIG_PATH ||
    '/app/data/config.yaml',
  )
}

function loadDoc(path: string) {
  const raw = readFileSync(path, 'utf-8')
  return parseDocument(raw)
}

function getTokensSeq(doc: ReturnType<typeof parseDocument>): YAMLSeq {
  const auth = doc.getIn(['auth'], true) as YAMLMap | undefined
  if (!auth) throw new Error('config: auth section missing')
  let tokens = auth.get('tokens', true) as YAMLSeq | undefined
  if (!tokens) {
    tokens = new YAMLSeq()
    auth.set('tokens', tokens)
  }
  return tokens
}

function readEntry(item: YAMLMap): ClientEntry | null {
  const name = item.get('name')
  const token = item.get('token')
  if (typeof name !== 'string' || typeof token !== 'string') return null
  const limitRaw = item.get('cost_limit_usd')
  const periodRaw = item.get('cost_limit_period')
  const cost_limit_usd = typeof limitRaw === 'number' && limitRaw > 0 ? limitRaw : undefined
  const cost_limit_period =
    typeof periodRaw === 'string' && (VALID_PERIODS as string[]).includes(periodRaw)
      ? (periodRaw as CostLimitPeriod)
      : undefined
  const homeRaw = item.get('home_dir')
  const home_dir = typeof homeRaw === 'string' && homeRaw.trim() ? homeRaw.trim() : undefined
  return { name, token, cost_limit_usd, cost_limit_period, home_dir }
}

/** Set or clear a client's real home dir. Pass null/'' to clear (→ auto-detect). */
export function setClientHomeDir(name: string, homeDir: string | null): ClientEntry {
  const path = configPath()
  const doc = loadDoc(path)
  const tokens = getTokensSeq(doc)
  let target: YAMLMap | null = null
  for (const item of tokens.items) {
    if (item instanceof YAMLMap && item.get('name') === name) {
      target = item
      break
    }
  }
  if (!target) throw new Error(`client "${name}" not found`)
  const normalized = homeDir == null || homeDir.trim() === '' ? null : normalizeHomeDir(homeDir)
  if (homeDir != null && homeDir.trim() !== '' && normalized === null) {
    throw new Error('home_dir must be an absolute path (e.g. /Users/alice, /home/alice, or C:\\Users\\alice)')
  }
  if (normalized) target.set('home_dir', normalized)
  else target.delete('home_dir')
  writeFileSync(path, doc.toString(), 'utf-8')
  const result = readEntry(target)
  if (!result) throw new Error('failed to read updated entry')
  return result
}

function applyLimitToYamlEntry(entry: YAMLMap, input: ClientLimitInput): void {
  if (input.cost_limit_usd === null || input.cost_limit_usd === 0) {
    entry.delete('cost_limit_usd')
    entry.delete('cost_limit_period')
    return
  }
  if (typeof input.cost_limit_usd === 'number' && input.cost_limit_usd > 0) {
    entry.set('cost_limit_usd', input.cost_limit_usd)
    const period =
      typeof input.cost_limit_period === 'string' &&
      (VALID_PERIODS as string[]).includes(input.cost_limit_period)
        ? input.cost_limit_period
        : 'lifetime'
    entry.set('cost_limit_period', period)
  } else if (input.cost_limit_period !== undefined && input.cost_limit_period !== null) {
    // period without limit: ignore
  }
}

export function listClients(): ClientEntry[] {
  const doc = loadDoc(configPath())
  const tokens = getTokensSeq(doc)
  const out: ClientEntry[] = []
  for (const item of tokens.items) {
    if (item instanceof YAMLMap) {
      const e = readEntry(item)
      if (e) out.push(e)
    }
  }
  return out
}

export function addClient(name: string, limit?: ClientLimitInput): ClientEntry {
  if (!NAME_RE.test(name)) {
    throw new Error('client name must be 1-64 chars, [a-zA-Z0-9_.-]')
  }
  const path = configPath()
  const doc = loadDoc(path)
  const tokens = getTokensSeq(doc)

  for (const item of tokens.items) {
    if (item instanceof YAMLMap && item.get('name') === name) {
      throw new Error(`client "${name}" already exists`)
    }
  }

  const token = randomBytes(32).toString('hex')
  const entry = new YAMLMap()
  entry.set('name', name)
  entry.set('token', token)
  if (limit) applyLimitToYamlEntry(entry, limit)
  tokens.add(entry)

  writeFileSync(path, doc.toString(), 'utf-8')
  const result = readEntry(entry)
  return result || { name, token }
}

export function setClientLimit(name: string, limit: ClientLimitInput): ClientEntry {
  const path = configPath()
  const doc = loadDoc(path)
  const tokens = getTokensSeq(doc)
  let target: YAMLMap | null = null
  for (const item of tokens.items) {
    if (item instanceof YAMLMap && item.get('name') === name) {
      target = item
      break
    }
  }
  if (!target) throw new Error(`client "${name}" not found`)
  applyLimitToYamlEntry(target, limit)
  writeFileSync(path, doc.toString(), 'utf-8')
  const result = readEntry(target)
  if (!result) throw new Error('failed to read updated entry')
  return result
}

export function removeClient(name: string): boolean {
  const path = configPath()
  const doc = loadDoc(path)
  const tokens = getTokensSeq(doc)

  let removedAt = -1
  for (let i = 0; i < tokens.items.length; i++) {
    const item = tokens.items[i]
    if (item instanceof YAMLMap && item.get('name') === name) {
      removedAt = i
      break
    }
  }
  if (removedAt === -1) return false

  tokens.delete(removedAt)
  if (tokens.items.length === 0) {
    throw new Error('cannot remove the last client — at least one token must remain')
  }
  writeFileSync(path, doc.toString(), 'utf-8')
  return true
}

export interface LauncherOptions {
  name: string
  token: string
  gatewayAddr: string  // e.g. "ccg.example.com" or "host:port"
  scheme: 'http' | 'https'
}

export function buildPowerShellLauncherScript(opts: LauncherOptions): string {
  const tlsBypass =
    opts.scheme === 'https'
      ? '\n# Accept self-signed TLS cert from gateway\n$env:NODE_TLS_REJECT_UNAUTHORIZED = "0"\n'
      : ''
  return `# CC Gateway Client Launcher (Windows / PowerShell)
#
# Usage:
#   .\\cc-${opts.name}.ps1                  Start Claude Code through gateway
#   .\\cc-${opts.name}.ps1 --print "hi"     Single-shot mode
#   .\\cc-${opts.name}.ps1 install          Install as 'ccg' system command (user PATH)
#   .\\cc-${opts.name}.ps1 uninstall        Remove 'ccg' and restore native claude
#   .\\cc-${opts.name}.ps1 hijack           Alias claude -> ccg in PowerShell profile
#   .\\cc-${opts.name}.ps1 release          Undo shell hijack
#   .\\cc-${opts.name}.ps1 hijack-gui       Persist user env vars so VS Code / Cursor extension uses gateway
#   .\\cc-${opts.name}.ps1 release-gui      Undo GUI hijack
#   .\\cc-${opts.name}.ps1 native           Run native claude (bypass gateway, one-time)
#   .\\cc-${opts.name}.ps1 status           Show gateway URL + hijack state + health
[CmdletBinding()]
param([Parameter(ValueFromRemainingArguments=$true)][string[]]$RestArgs)

$GatewayUrl  = "${opts.scheme}://${opts.gatewayAddr}"
$ClientToken = "${opts.token}"
${tlsBypass}
$InstallDir  = Join-Path $env:LOCALAPPDATA "ccg-bin"
$InstallPs1  = Join-Path $InstallDir "ccg.ps1"
$InstallCmd  = Join-Path $InstallDir "ccg.cmd"
$ProfilePath = $PROFILE.CurrentUserAllHosts
$AliasTag    = "# cc-gateway alias"

function Add-ToUserPath {
  param([string]$Dir)
  $userPath = [Environment]::GetEnvironmentVariable("PATH", "User")
  if (-not $userPath) { $userPath = "" }
  $parts = $userPath -split ';' | Where-Object { $_ -ne "" }
  if ($parts -notcontains $Dir) {
    $new = (@($Dir) + $parts) -join ';'
    [Environment]::SetEnvironmentVariable("PATH", $new, "User")
    return $true
  }
  return $false
}

function Test-AliasInProfile {
  if (-not (Test-Path $ProfilePath)) { return $false }
  return [bool](Select-String -Path $ProfilePath -Pattern ([regex]::Escape($AliasTag)) -Quiet -ErrorAction SilentlyContinue)
}

function Remove-AliasFromProfile {
  if (-not (Test-Path $ProfilePath)) { return }
  (Get-Content $ProfilePath) | Where-Object { $_ -notlike "*$AliasTag*" } | Set-Content $ProfilePath
}

function Invoke-Install {
  if (-not (Test-Path $InstallDir)) { New-Item -ItemType Directory -Path $InstallDir | Out-Null }
  Copy-Item -Path $PSCommandPath -Destination $InstallPs1 -Force
  $cmdContent = @'
@echo off
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0ccg.ps1" %*
'@
  Set-Content -Path $InstallCmd -Value $cmdContent -Encoding ASCII
  $added = Add-ToUserPath $InstallDir
  Write-Host "Installed as 'ccg' at $InstallDir."
  if ($added) {
    Write-Host ""
    Write-Host "Added $InstallDir to your user PATH. Open a NEW terminal for 'ccg' to be found."
  }
  Write-Host ""
  Write-Host "  ccg              Start Claude Code through gateway"
  Write-Host "  ccg hijack       Make shell 'claude' also go through gateway"
  Write-Host "  ccg hijack-gui   Make VS Code / Cursor extension go through gateway"
  Write-Host "  ccg release      Restore shell 'claude' to native"
  Write-Host "  ccg release-gui  Restore GUI extension to native"
  Write-Host "  ccg status       Show gateway connection status"
  Write-Host "  ccg help         Show this help"
}

function Test-GuiHijack {
  # Either var counts as "still hijacked" - a half-cleared state (one var unset
  # by hand) must not read as clean, or release-gui would refuse to finish the job.
  $url = [Environment]::GetEnvironmentVariable("ANTHROPIC_BASE_URL", "User")
  $key = [Environment]::GetEnvironmentVariable("ANTHROPIC_API_KEY", "User")
  return ((-not [string]::IsNullOrEmpty($url)) -or (-not [string]::IsNullOrEmpty($key)))
}

# Pre-approve this token in ~/.claude.json so Claude Code never shows the
# "Detected a custom API key ... Do you want to use this API key?" prompt.
# Claude Code records approval as the key's last 20 characters. Requires node
# (a real JSON parser) - PowerShell's ConvertTo-Json can silently truncate
# deep structures in the user's ~/.claude.json, so we skip rather than risk it.
function Approve-Token {
  $node = Get-Command node -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
  if (-not $node) { return }
  $cj = Join-Path $env:USERPROFILE ".claude.json"
  if ($ClientToken.Length -lt 20) { return }
  $tail = $ClientToken.Substring($ClientToken.Length - 20)
  $js = 'const fs=require("fs");const[p,t]=process.argv.slice(1);let j={};try{j=JSON.parse(fs.readFileSync(p,"utf8"))}catch(e){};if(typeof j!=="object"||j===null||Array.isArray(j))j={};const r=j.customApiKeyResponses=j.customApiKeyResponses||{};const a=r.approved=Array.isArray(r.approved)?r.approved:[];const d=r.rejected=Array.isArray(r.rejected)?r.rejected:[];let ch=false;if(!a.includes(t)){a.push(t);ch=true}for(let i=d.length-1;i>=0;i--){if(d[i]===t){d.splice(i,1);ch=true}}if(ch)fs.writeFileSync(p,JSON.stringify(j,null,2)+"\\n")'
  try { & $node.Source -e $js $cj $tail 2>$null | Out-Null } catch {}
}

# Reverse of Approve-Token. Clears both lists so uninstall leaves ~/.claude.json
# as it was before ccg touched it.
function Revoke-Token {
  $node = Get-Command node -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
  if (-not $node) { return }
  $cj = Join-Path $env:USERPROFILE ".claude.json"
  if (-not (Test-Path $cj)) { return }
  if ($ClientToken.Length -lt 20) { return }
  $tail = $ClientToken.Substring($ClientToken.Length - 20)
  $js = 'const fs=require("fs");const[p,t]=process.argv.slice(1);let j=null;try{j=JSON.parse(fs.readFileSync(p,"utf8"))}catch(e){};if(j&&typeof j==="object"){const r=j.customApiKeyResponses;let ch=false;if(r&&typeof r==="object"){for(const k of["approved","rejected"]){const l=r[k];if(!Array.isArray(l))continue;for(let i=l.length-1;i>=0;i--){if(l[i]===t){l.splice(i,1);ch=true}}}}if(ch)fs.writeFileSync(p,JSON.stringify(j,null,2)+"\\n")}'
  try { & $node.Source -e $js $cj $tail 2>$null | Out-Null } catch {}
}

function Invoke-HijackGui {
  [Environment]::SetEnvironmentVariable("ANTHROPIC_API_KEY", $ClientToken, "User")
  [Environment]::SetEnvironmentVariable("ANTHROPIC_BASE_URL", $GatewayUrl, "User")
  Approve-Token
  Write-Host "Done. GUI apps (VS Code / Cursor) will route through gateway."
  Write-Host "  Fully Quit and reopen VS Code / Cursor for the extension to pick up the env vars."
  Write-Host "  Undo: ccg release-gui"
}

function Invoke-ReleaseGui {
  if (Test-GuiHijack) {
    [Environment]::SetEnvironmentVariable("ANTHROPIC_API_KEY", $null, "User")
    [Environment]::SetEnvironmentVariable("ANTHROPIC_BASE_URL", $null, "User")
    Write-Host "Done. GUI env vars removed. Restart VS Code / Cursor."
  } else {
    Write-Host "Nothing to undo - GUI hijack not active."
  }
}

function Invoke-Uninstall {
  Remove-Item -Path $InstallPs1 -ErrorAction SilentlyContinue
  Remove-Item -Path $InstallCmd -ErrorAction SilentlyContinue
  if (Test-AliasInProfile) { Remove-AliasFromProfile }
  # Unconditional, and not gated on Test-GuiHijack: clearing a var that is
  # already unset is a no-op, whereas skipping leaves a half-cleared HKCU
  # Environment behind that every new GUI app keeps inheriting.
  [Environment]::SetEnvironmentVariable("ANTHROPIC_API_KEY", $null, "User")
  [Environment]::SetEnvironmentVariable("ANTHROPIC_BASE_URL", $null, "User")
  Revoke-Token
  Write-Host "Removed. Native 'claude' restored."
  Write-Host "Note: apps already open may still hold the old ANTHROPIC_API_KEY /"
  Write-Host "  ANTHROPIC_BASE_URL - reopen them to fully detach."
}

function Invoke-Hijack {
  if (Test-AliasInProfile) {
    Write-Host "Already active. Run 'ccg release' to undo."
    return
  }
  $dir = Split-Path -Parent $ProfilePath
  if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
  if (-not (Test-Path $ProfilePath)) { New-Item -ItemType File -Path $ProfilePath -Force | Out-Null }
  Add-Content -Path $ProfilePath -Value "Set-Alias claude ccg $AliasTag"
  Write-Host "Done. 'claude' now goes through gateway."
  Write-Host "  New PowerShell terminals: automatic."
  Write-Host '  This terminal: reopen or run: . $PROFILE'
  Write-Host "  Undo anytime: ccg release"
}

function Invoke-Release {
  if (Test-AliasInProfile) {
    Remove-AliasFromProfile
    Remove-Item Alias:claude -ErrorAction SilentlyContinue
    Write-Host "Done. 'claude' is back to native."
  } else {
    Write-Host "Nothing to undo - 'claude' is already native."
  }
}

function Invoke-Native {
  $rest = if ($RestArgs.Count -gt 1) { $RestArgs[1..($RestArgs.Count - 1)] } else { @() }
  $app = Get-Command claude -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
  if (-not $app) { Write-Error "claude not found"; exit 1 }
  & $app.Source @rest
  exit $LASTEXITCODE
}

function Test-GatewayHealth {
  try {
    $params = @{ Uri = "$GatewayUrl/_health"; TimeoutSec = 3; UseBasicParsing = $true; ErrorAction = 'Stop' }
    if ($PSVersionTable.PSVersion.Major -ge 6) { $params.SkipCertificateCheck = $true }
    else { [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true } }
    $r = Invoke-WebRequest @params
    return ($r.StatusCode -lt 500)
  } catch { return $false }
}

function Invoke-Status {
  Write-Host "Gateway:  $GatewayUrl"
  if (Test-AliasInProfile) {
    Write-Host "Shell:    ON  (claude -> ccg)"
  } else {
    Write-Host "Shell:    OFF (claude = native)"
  }
  if (Test-GuiHijack) {
    Write-Host "GUI:      ON  (VS Code / Cursor -> gateway)"
  } else {
    Write-Host "GUI:      OFF (VS Code / Cursor uses native)"
  }
  if (Test-GatewayHealth) { Write-Host "Health:   OK" } else { Write-Host "Health:   UNREACHABLE" }
}

function Invoke-Help {
  Write-Host "ccg - Claude Code Gateway Client (Windows)"
  Write-Host ""
  Write-Host "Usage:"
  Write-Host "  ccg                  Start Claude Code through gateway"
  Write-Host "  ccg [claude args]    Pass any arguments to Claude Code"
  Write-Host "  ccg --print 'hi'     Single-shot mode"
  Write-Host ""
  Write-Host "Setup:"
  Write-Host "  ccg install          Install as 'ccg' system command (user PATH)"
  Write-Host "  ccg uninstall        Remove 'ccg' and clean up"
  Write-Host ""
  Write-Host "Routing (shell):"
  Write-Host "  ccg hijack           Make 'claude' (in terminal) go through gateway"
  Write-Host "  ccg release          Restore shell 'claude' to native"
  Write-Host "  ccg native [args]    Run native claude once (bypass gateway)"
  Write-Host ""
  Write-Host "Routing (GUI extension):"
  Write-Host "  ccg hijack-gui       Make VS Code / Cursor extension use gateway"
  Write-Host "  ccg release-gui      Restore GUI extension to native"
  Write-Host ""
  Write-Host "Info:"
  Write-Host "  ccg status           Show gateway and hijack status"
  Write-Host "  ccg help             Show this help"
}

# Subcommand dispatch
if ($RestArgs -and $RestArgs.Count -gt 0) {
  switch ($RestArgs[0]) {
    'install'   { Invoke-Install; exit 0 }
    'uninstall' { Invoke-Uninstall; exit 0 }
    'hijack'      { Invoke-Hijack; exit 0 }
    'release'     { Invoke-Release; exit 0 }
    'hijack-gui'  { Invoke-HijackGui; exit 0 }
    'release-gui' { Invoke-ReleaseGui; exit 0 }
    'native'    { Invoke-Native }
    'status'    { Invoke-Status; exit 0 }
    'help'      { Invoke-Help; exit 0 }
    '--help'    { Invoke-Help; exit 0 }
    '-h'        { Invoke-Help; exit 0 }
  }
}

# Main: launch through gateway
# Pick first match — on Windows npm installs both 'claude' and 'claude.cmd';
# without -First 1, $claudeApp is an array and '& $claudeApp.Source' joins paths.
$claudeApp = Get-Command claude -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $claudeApp) {
  Write-Error "Error: 'claude' not found. Install Claude Code first:"
  Write-Error "  npm install -g @anthropic-ai/claude-code"
  exit 1
}

$env:ANTHROPIC_API_KEY = $ClientToken
$env:ANTHROPIC_BASE_URL = $GatewayUrl
$env:CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC = "1"
$env:CLAUDE_CODE_ATTRIBUTION_HEADER = "false"

# Skip the one-time "use this API key?" confirmation for this token.
Approve-Token

if (-not (Test-GatewayHealth)) {
  Write-Host "Warning: Gateway at $GatewayUrl is not reachable."
  Write-Host "Make sure the gateway is running."
  Write-Host ""
}

& $claudeApp.Source @RestArgs
exit $LASTEXITCODE
`
}

export function buildLauncherScript(opts: LauncherOptions): string {
  const tlsBypass =
    opts.scheme === 'https'
      ? '\n# Accept self-signed TLS cert from gateway\nexport NODE_TLS_REJECT_UNAUTHORIZED=0\n'
      : ''
  return `#!/bin/bash
# CC Gateway Client Launcher
#
# Usage:
#   ./cc-${opts.name}                    Start Claude Code through gateway
#   ./cc-${opts.name} --print "hello"    Single-shot mode
#   ./cc-${opts.name} install            Install as 'ccg' command system-wide
#   ./cc-${opts.name} uninstall          Remove 'ccg' and restore native claude
#   ./cc-${opts.name} hijack             Alias claude -> ccg in shell rc
#   ./cc-${opts.name} release            Undo shell hijack
#   ./cc-${opts.name} hijack-gui         Persist env vars so VS Code / Cursor extension uses gateway
#   ./cc-${opts.name} release-gui        Undo GUI hijack
#   ./cc-${opts.name} native             Run native claude (bypass gateway, one-time)
GATEWAY_URL="${opts.scheme}://${opts.gatewayAddr}"
CLIENT_TOKEN="${opts.token}"
${tlsBypass}
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
  */zsh)  RC_FILE="\${ZDOTDIR:-$HOME}/.zshrc" ;;
  */bash) RC_FILE="$HOME/.bashrc" ;;
  */fish) RC_FILE="\${XDG_CONFIG_HOME:-$HOME/.config}/fish/config.fish" ;;
  *)      RC_FILE="$HOME/.profile" ;;
esac
ALIAS_TAG="# cc-gateway alias"

# Pre-approve this token in ~/.claude.json so Claude Code never shows the
# "Detected a custom API key ... Do you want to use this API key?" prompt.
# Claude Code records approval as the key's last 20 characters.
approve_token() {
  CLAUDE_JSON="$HOME/.claude.json"
  KEY_TAIL="\${CLIENT_TOKEN: -20}"
  [[ \${#CLIENT_TOKEN} -lt 20 ]] && return 0
  if command -v node >/dev/null 2>&1; then
    node -e 'const fs=require("fs");const[p,t]=process.argv.slice(1);let j={};try{j=JSON.parse(fs.readFileSync(p,"utf8"))}catch(e){};if(typeof j!=="object"||j===null||Array.isArray(j))j={};const r=j.customApiKeyResponses=j.customApiKeyResponses||{};const a=r.approved=Array.isArray(r.approved)?r.approved:[];const d=r.rejected=Array.isArray(r.rejected)?r.rejected:[];let ch=false;if(!a.includes(t)){a.push(t);ch=true}for(let i=d.length-1;i>=0;i--){if(d[i]===t){d.splice(i,1);ch=true}}if(ch)fs.writeFileSync(p,JSON.stringify(j,null,2)+"\\n")' "$CLAUDE_JSON" "$KEY_TAIL" 2>/dev/null && return 0
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
d=r.setdefault("rejected",[])
if not isinstance(d,list):
    d=[]; r["rejected"]=d
ch=False
if t not in a:
    a.append(t); ch=True
while t in d:
    d.remove(t); ch=True
if ch:
    open(p,"w").write(json.dumps(j,indent=2)+"\\n")' "$CLAUDE_JSON" "$KEY_TAIL" 2>/dev/null
  fi
  return 0
}

# Reverse of approve_token: drop this token from ~/.claude.json so uninstall
# leaves no trace of the gateway key behind. Clears BOTH lists — a token the
# user once declined sits in "rejected" forever otherwise, and a later reinstall
# would land the same tail in both lists at once.
revoke_token() {
  CLAUDE_JSON="$HOME/.claude.json"
  [[ -f "$CLAUDE_JSON" ]] || return 0
  KEY_TAIL="\${CLIENT_TOKEN: -20}"
  [[ \${#CLIENT_TOKEN} -lt 20 ]] && return 0
  if command -v node >/dev/null 2>&1; then
    node -e 'const fs=require("fs");const[p,t]=process.argv.slice(1);let j=null;try{j=JSON.parse(fs.readFileSync(p,"utf8"))}catch(e){};if(j&&typeof j==="object"){const r=j.customApiKeyResponses;let ch=false;if(r&&typeof r==="object"){for(const k of["approved","rejected"]){const l=r[k];if(!Array.isArray(l))continue;for(let i=l.length-1;i>=0;i--){if(l[i]===t){l.splice(i,1);ch=true}}}}if(ch)fs.writeFileSync(p,JSON.stringify(j,null,2)+"\\n")}' "$CLAUDE_JSON" "$KEY_TAIL" 2>/dev/null && return 0
  fi
  if command -v python3 >/dev/null 2>&1; then
    python3 -c 'import json,sys
p,t=sys.argv[1],sys.argv[2]
try:
    j=json.load(open(p))
except Exception:
    sys.exit(0)
r=j.get("customApiKeyResponses") if isinstance(j,dict) else None
if not isinstance(r,dict): sys.exit(0)
ch=False
for k in ("approved","rejected"):
    l=r.get(k)
    if isinstance(l,list):
        while t in l:
            l.remove(t); ch=True
if ch:
    open(p,"w").write(json.dumps(j,indent=2)+"\\n")' "$CLAUDE_JSON" "$KEY_TAIL" 2>/dev/null
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
    echo "  ccg hijack       Make shell 'claude' also go through gateway"
    echo "  ccg hijack-gui   Make VS Code / Cursor extension go through gateway"
    echo "  ccg release      Restore shell 'claude' to native"
    echo "  ccg release-gui  Restore GUI extension to native"
    echo "  ccg status       Show gateway connection status"
    echo "  ccg help         Show this help"
    exit 0
    ;;

  uninstall)
    # Remove every ccg copy: install may have written to more than one dir,
    # and the quick installer targets ~/.local/bin while INSTALL_PATH here can
    # resolve to /opt/homebrew/bin. Mirror the install loop so uninstall is its
    # exact inverse regardless of platform or PATH order.
    for d in /opt/homebrew/bin /usr/local/bin "$HOME/.local/bin"; do
      TARGET="$d/ccg"
      if [[ -f "$TARGET" ]]; then
        if rm -f "$TARGET" 2>/dev/null || sudo rm -f "$TARGET"; then
          echo "Removed $TARGET"
        else
          echo "Warning: could not remove $TARGET — try: sudo rm $TARGET"
        fi
      fi
    done
    # Also delete the launcher we were invoked from if it lives elsewhere
    # (e.g. a downloaded cc-*.sh that was never 'install'ed).
    if [[ -f "$SELF_PATH" && "$SELF_PATH" != */ccg ]]; then
      rm -f "$SELF_PATH" 2>/dev/null && echo "Removed $SELF_PATH"
    fi
    if grep -q "$ALIAS_TAG" "$RC_FILE" 2>/dev/null; then
      sed -i.bak "/$ALIAS_TAG/d" "$RC_FILE"
      rm -f "\${RC_FILE}.bak"
    fi
    # Also clean up GUI hijack if present
    case "$(uname -s)" in
      Darwin)
        PLIST_PATH="$HOME/Library/LaunchAgents/com.ccg.env.plist"
        if [[ -f "$PLIST_PATH" ]]; then
          launchctl unload "$PLIST_PATH" 2>/dev/null
          rm -f "$PLIST_PATH"
        fi
        # Unconditional: 'launchctl setenv' values live in the user's launchd
        # session, not in the plist. If the plist was already gone (release-gui
        # ran first, or it was deleted by hand) the vars would otherwise stay
        # set for every GUI app until the next logout. Same reasoning as
        # release-gui, which has always unset these unconditionally.
        launchctl unsetenv ANTHROPIC_API_KEY 2>/dev/null
        launchctl unsetenv ANTHROPIC_BASE_URL 2>/dev/null
        ;;
      Linux)
        rm -f "\${XDG_CONFIG_HOME:-$HOME/.config}/environment.d/ccg.conf"
        ;;
    esac
    # Reverse the token approval that install / hijack-gui wrote.
    revoke_token
    echo "Removed 'ccg' and cleaned up. Native 'claude' restored."
    echo "Note: terminals or editors already open may still hold the old"
    echo "  ANTHROPIC_API_KEY / ANTHROPIC_BASE_URL — reopen them (or run"
    echo "  'unset ANTHROPIC_API_KEY ANTHROPIC_BASE_URL') to fully detach."
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
      rm -f "\${RC_FILE}.bak"
      # Unalias in current shell
      unalias claude 2>/dev/null
      echo "Done. 'claude' is back to native."
    else
      echo "Nothing to undo — 'claude' is already native."
    fi
    exit 0
    ;;

  hijack-gui)
    # Persist ANTHROPIC_* env vars so GUI apps (VS Code / Cursor) inherit them.
    # macOS: LaunchAgent + launchctl setenv. Linux: ~/.config/environment.d/.
    case "$(uname -s)" in
      Darwin)
        PLIST_PATH="$HOME/Library/LaunchAgents/com.ccg.env.plist"
        mkdir -p "$(dirname "$PLIST_PATH")"
        cat > "$PLIST_PATH" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.ccg.env</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/sh</string>
    <string>-c</string>
    <string>launchctl setenv ANTHROPIC_API_KEY '$CLIENT_TOKEN'; launchctl setenv ANTHROPIC_BASE_URL '$GATEWAY_URL'</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
</dict>
</plist>
PLIST
        chmod 600 "$PLIST_PATH"
        launchctl unload "$PLIST_PATH" 2>/dev/null
        launchctl load "$PLIST_PATH"
        launchctl setenv ANTHROPIC_API_KEY "$CLIENT_TOKEN"
        launchctl setenv ANTHROPIC_BASE_URL "$GATEWAY_URL"
        approve_token
        echo "Done. GUI apps (VS Code / Cursor) will route through gateway."
        echo "  Fully Quit and reopen VS Code / Cursor (Cmd+Q, not just close window)."
        echo "  Undo: ccg release-gui"
        ;;
      Linux)
        ENV_DIR="\${XDG_CONFIG_HOME:-$HOME/.config}/environment.d"
        ENV_FILE="$ENV_DIR/ccg.conf"
        mkdir -p "$ENV_DIR"
        cat > "$ENV_FILE" <<ENVCONF
ANTHROPIC_API_KEY=$CLIENT_TOKEN
ANTHROPIC_BASE_URL=$GATEWAY_URL
ENVCONF
        chmod 600 "$ENV_FILE"
        approve_token
        echo "Done. Wrote $ENV_FILE."
        echo "  Log out and back in (or restart) for the systemd user session to pick this up."
        echo "  Undo: ccg release-gui"
        ;;
      *)
        echo "hijack-gui is not supported on $(uname -s)."
        exit 1
        ;;
    esac
    exit 0
    ;;

  release-gui)
    case "$(uname -s)" in
      Darwin)
        PLIST_PATH="$HOME/Library/LaunchAgents/com.ccg.env.plist"
        if [[ -f "$PLIST_PATH" ]]; then
          launchctl unload "$PLIST_PATH" 2>/dev/null
          rm -f "$PLIST_PATH"
        fi
        launchctl unsetenv ANTHROPIC_API_KEY 2>/dev/null
        launchctl unsetenv ANTHROPIC_BASE_URL 2>/dev/null
        echo "Done. GUI env vars removed. Restart VS Code / Cursor."
        ;;
      Linux)
        ENV_FILE="\${XDG_CONFIG_HOME:-$HOME/.config}/environment.d/ccg.conf"
        if [[ -f "$ENV_FILE" ]]; then
          rm -f "$ENV_FILE"
          echo "Done. Removed $ENV_FILE. Log out and back in for the change to take effect."
        else
          echo "Nothing to undo — GUI hijack not active."
        fi
        ;;
      *)
        echo "release-gui is not supported on $(uname -s)."
        exit 1
        ;;
    esac
    exit 0
    ;;

  native)
    shift
    exec command claude "$@"
    ;;

  status)
    echo "Gateway:  $GATEWAY_URL"
    if grep -q "$ALIAS_TAG" "$RC_FILE" 2>/dev/null; then
      echo "Shell:    ON  (claude → ccg)"
    else
      echo "Shell:    OFF (claude = native)"
    fi
    GUI_STATE="OFF (VS Code / Cursor uses native)"
    case "$(uname -s)" in
      Darwin)
        [[ -f "$HOME/Library/LaunchAgents/com.ccg.env.plist" ]] && GUI_STATE="ON  (VS Code / Cursor → gateway)"
        ;;
      Linux)
        [[ -f "\${XDG_CONFIG_HOME:-$HOME/.config}/environment.d/ccg.conf" ]] && GUI_STATE="ON  (VS Code / Cursor → gateway)"
        ;;
    esac
    echo "GUI:      $GUI_STATE"
    HEALTH=$(curl -sk --max-time 3 "\${GATEWAY_URL}/_health" 2>/dev/null)
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
    echo "  ccg --print \\"hi\\"       Single-shot mode"
    echo ""
    echo "Setup:"
    echo "  ccg install            Install as 'ccg' system command"
    echo "  ccg uninstall          Remove 'ccg' and clean up"
    echo ""
    echo "Routing (shell):"
    echo "  ccg hijack             Make 'claude' (in terminal) go through gateway"
    echo "  ccg release            Restore shell 'claude' to native"
    echo "  ccg native [args]      Run native claude once (bypass gateway)"
    echo ""
    echo "Routing (GUI extension):"
    echo "  ccg hijack-gui         Make VS Code / Cursor extension use gateway"
    echo "  ccg release-gui        Restore GUI extension to native"
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
HEALTH=$(curl -sk --max-time 3 "\${GATEWAY_URL}/_health" 2>/dev/null)
if [[ -z "$HEALTH" ]]; then
  echo "Warning: Gateway at \${GATEWAY_URL} is not reachable."
  echo "Make sure the gateway is running."
  echo ""
fi

# Pass all arguments through to claude
exec claude "$@"
`
}

// ── One-line installers ──
// Designed to be run via `curl -fsSL <url> | bash` (macOS/Linux) or
// `irm <url> | iex` (Windows). Piping into the shell avoids the friction of a
// downloaded file: no Gatekeeper quarantine, no chmod, no Unblock-File / execution
// policy change, and no sudo (installs into a user-writable dir).

export function buildUnixInstaller(opts: LauncherOptions): string {
  const launcher = buildLauncherScript(opts)
  const DELIM = '__CCG_LAUNCHER_PAYLOAD__'
  return `#!/bin/bash
# CC Gateway quick installer (macOS / Linux)
# Run with:  curl -fsSL "<gateway>/portal/install.sh?t=..." | bash
set -e

INSTALL_DIR="$HOME/.local/bin"
mkdir -p "$INSTALL_DIR"

# Write the launcher (token baked in). Heredoc is quoted so nothing expands.
cat > "$INSTALL_DIR/ccg" <<'${DELIM}'
${launcher}${DELIM}
chmod +x "$INSTALL_DIR/ccg"

# A previous install (possibly for another gateway) may have left a ccg in a
# dir that shadows ~/.local/bin on PATH. Overwrite those copies too so this
# gateway always wins.
for d in /opt/homebrew/bin /usr/local/bin; do
  if [ -f "$d/ccg" ]; then
    if cp "$INSTALL_DIR/ccg" "$d/ccg" 2>/dev/null; then
      echo "   • Updated existing ccg at $d/ccg"
    else
      echo "   ⚠ Stale ccg at $d/ccg may shadow the new one — remove it: sudo rm $d/ccg"
    fi
  fi
done

# Make sure ~/.local/bin is on PATH for future shells.
case "$SHELL" in
  */zsh)  RC_FILE="\${ZDOTDIR:-$HOME}/.zshrc" ;;
  */bash) RC_FILE="$HOME/.bashrc" ;;
  */fish) RC_FILE="\${XDG_CONFIG_HOME:-$HOME/.config}/fish/config.fish" ;;
  *)      RC_FILE="$HOME/.profile" ;;
esac
ON_PATH=0
case ":$PATH:" in *":$INSTALL_DIR:"*) ON_PATH=1 ;; esac
if [ "$ON_PATH" = "0" ] && [ -n "$RC_FILE" ]; then
  mkdir -p "$(dirname "$RC_FILE")" 2>/dev/null || true
  if ! grep -q "# cc-gateway path" "$RC_FILE" 2>/dev/null; then
    if [ "\${SHELL##*/}" = "fish" ]; then
      printf 'fish_add_path %s # cc-gateway path\\n' "$INSTALL_DIR" >> "$RC_FILE" 2>/dev/null || true
    else
      printf 'export PATH="%s:$PATH" # cc-gateway path\\n' "$INSTALL_DIR" >> "$RC_FILE" 2>/dev/null || true
    fi
  fi
fi

# Claude Code itself is required — the launcher just wraps it. Install it if missing.
CLAUDE_OK=1
if ! command -v claude >/dev/null 2>&1; then
  CLAUDE_OK=0
  if command -v npm >/dev/null 2>&1; then
    echo ""
    echo "Claude Code not found — installing it (npm install -g @anthropic-ai/claude-code)…"
    if npm install -g @anthropic-ai/claude-code; then CLAUDE_OK=1; fi
  fi
fi

# Route the native 'claude' CLI and the VS Code / Cursor extension through the
# gateway automatically. Both are idempotent and reversible:
#   undo shell: ccg release   •   undo GUI: ccg release-gui
"$INSTALL_DIR/ccg" hijack >/dev/null 2>&1 || true
GUI_OK=0
if "$INSTALL_DIR/ccg" hijack-gui >/dev/null 2>&1; then GUI_OK=1; fi

echo ""
echo "✅ Installed 'ccg' to $INSTALL_DIR"
echo "   • 'claude' now routes through the gateway too (shell alias)"
if [ "$GUI_OK" = "1" ]; then
  echo "   • VS Code / Cursor extension routed through the gateway — fully quit & reopen the editor"
fi
echo ""
if [ "$ON_PATH" = "0" ]; then
  echo "   Open a NEW terminal (or run: source $RC_FILE), then:"
else
  echo "   Open a NEW terminal (so the 'claude' alias loads), then:"
fi
echo "     claude         # or 'ccg' — both go through the gateway now"
echo "     ccg status     # check the connection + routing state"
echo ""
echo "   Run right now without reopening:  \\"$INSTALL_DIR/ccg\\""
echo "   Undo routing anytime:  ccg release   /   ccg release-gui"
if [ "$CLAUDE_OK" = "0" ]; then
  echo ""
  echo "⚠ Claude Code is required but not installed. Install it with:"
  echo "    npm install -g @anthropic-ai/claude-code"
  echo "  (no npm? install Node.js first: https://nodejs.org)"
fi
`
}

export function buildPowerShellInstaller(opts: LauncherOptions): string {
  const launcher = buildPowerShellLauncherScript(opts)
  // base64 to sidestep PowerShell here-string nesting collisions.
  const b64 = Buffer.from(launcher, 'utf8').toString('base64')
  return `# CC Gateway quick installer (Windows / PowerShell)
# Run with:  irm "<gateway>/portal/install.ps1?t=..." | iex
$ErrorActionPreference = "Stop"

$dir = Join-Path $env:LOCALAPPDATA "ccg-bin"
New-Item -ItemType Directory -Force -Path $dir | Out-Null

$b64 = "${b64}"
$content = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b64))
Set-Content -Path (Join-Path $dir "ccg.ps1") -Value $content -Encoding UTF8

$cmd = '@echo off' + [Environment]::NewLine + 'powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0ccg.ps1" %*'
Set-Content -Path (Join-Path $dir "ccg.cmd") -Value $cmd -Encoding ASCII

$userPath = [Environment]::GetEnvironmentVariable("PATH","User"); if (-not $userPath) { $userPath = "" }
if (($userPath -split ';') -notcontains $dir) {
  [Environment]::SetEnvironmentVariable("PATH", ($dir + ';' + $userPath), "User")
}

# Claude Code itself is required — install it if missing.
$claudeOk = $true
if (-not (Get-Command claude -ErrorAction SilentlyContinue)) {
  $claudeOk = $false
  if (Get-Command npm -ErrorAction SilentlyContinue) {
    Write-Host ""
    Write-Host "Claude Code not found - installing (npm install -g @anthropic-ai/claude-code)..."
    try { npm install -g @anthropic-ai/claude-code; if (Get-Command claude -ErrorAction SilentlyContinue) { $claudeOk = $true } } catch {}
  }
}

# Route the native 'claude' CLI and the VS Code / Cursor extension through the
# gateway automatically. Both are idempotent and reversible (ccg release / release-gui).
$ps1 = Join-Path $dir "ccg.ps1"
try { & $ps1 hijack     | Out-Null } catch {}
$guiOk = $false
try { & $ps1 hijack-gui | Out-Null; $guiOk = $true } catch {}

Write-Host ""
Write-Host "Installed 'ccg' to $dir"
Write-Host "  - 'claude' now routes through the gateway too (shell alias)"
if ($guiOk) {
  Write-Host "  - VS Code / Cursor extension routed through the gateway - fully quit & reopen the editor"
}
Write-Host ""
Write-Host "  Open a NEW terminal (so the 'claude' alias loads), then run:"
Write-Host "    claude         # or 'ccg' - both go through the gateway now"
Write-Host "    ccg status     # check the connection + routing state"
Write-Host "  Undo routing anytime: ccg release / ccg release-gui"
if (-not $claudeOk) {
  Write-Host ""
  Write-Host "Claude Code is required but not installed. Install it with:"
  Write-Host "    npm install -g @anthropic-ai/claude-code"
  Write-Host "  (no npm? install Node.js first: https://nodejs.org)"
}
`
}
