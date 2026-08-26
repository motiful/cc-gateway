// Client self-service portal. Clients sign in with their name + password and can
// manage their personal info, review credit + usage (totals, per-model, recent
// activity), rotate their password, and follow a detailed install guide or grab
// their launcher. Everything is scoped to the one authenticated client.

import { i18nHead, langSwitcher, icon } from './i18n.js'

const SHARED_HEAD_STYLE = `
  :root {
    --bg: #0b0d10; --panel: #14181d; --panel-2: #1b2027; --border: #232a33;
    --fg: #e6edf3; --muted: #8b949e; --accent: #58a6ff; --ok: #3fb950;
    --warn: #d29922; --err: #f85149;
    --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; background: var(--bg); color: var(--fg);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    font-size: 14px;
  }
  a { color: var(--accent); }
  button, select {
    background: var(--panel-2); color: var(--fg);
    border: 1px solid var(--border); border-radius: 6px;
    padding: 8px 12px; font-size: 13px; font-family: inherit; cursor: pointer;
  }
  button:hover, select:hover { border-color: var(--accent); }
  button.primary { background: #1f6feb; border-color: #1f6feb; color: #fff; }
  button.primary:hover { background: #388bfd; border-color: #388bfd; }
  button.ghost { background: transparent; }
  .error { background: rgba(248,81,73,.1); border: 1px solid rgba(248,81,73,.3); color: var(--err); padding: 10px 12px; border-radius: 6px; font-size: 13px; }
`

export function renderPortalLogin(errorKey?: string): string {
  const errBlock = errorKey
    ? `<div class="error" data-i18n="${errorKey}" style="margin-bottom:8px"></div>`
    : ''
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title data-i18n="plogin.title">CC Gateway — Client Portal</title>
<meta name="viewport" content="width=device-width,initial-scale=1" />
${i18nHead()}
<style>
${SHARED_HEAD_STYLE}
  body { min-height: 100vh; display: flex; align-items: center; justify-content: center;
    background: radial-gradient(900px 500px at 50% -10%, #161b22 0%, var(--bg) 60%); }
  .box { background: var(--panel); border: 1px solid var(--border); border-radius: 12px; padding: 32px; width: 380px; max-width: 90vw; }
  .topbar { display: flex; align-items: center; justify-content: space-between; margin-bottom: 18px; }
  .brand { font-weight: 700; font-size: 15px; }
  .brand .dot { color: var(--accent); }
  h1 { font-size: 18px; margin: 0 0 6px; }
  p.sub { color: var(--muted); font-size: 13px; margin: 0 0 22px; }
  label { display: block; font-size: 12px; color: var(--muted); margin: 14px 0 4px; text-transform: uppercase; letter-spacing: .04em; }
  input {
    width: 100%; padding: 10px 12px; box-sizing: border-box;
    background: var(--bg); color: var(--fg);
    border: 1px solid var(--border); border-radius: 6px;
    font-size: 14px; font-family: var(--mono);
  }
  input:focus { outline: none; border-color: var(--accent); }
  button[type=submit] { margin-top: 22px; width: 100%; padding: 10px; font-size: 14px; font-weight: 500; }
  .back { display: block; text-align: center; margin-top: 16px; font-size: 12px; color: var(--muted); }
</style>
</head>
<body>
  <form class="box" method="post" action="/portal/login">
    <div class="topbar">
      <div class="brand">CC <span class="dot">Gateway</span></div>
      ${langSwitcher('padding:6px 8px')}
    </div>
    <h1 data-i18n="plogin.h1">Client Portal</h1>
    <p class="sub" data-i18n="plogin.sub">Sign in with the client name and password your admin gave you.</p>
    ${errBlock}
    <label for="name" data-i18n="plogin.name">Client name</label>
    <input id="name" name="name" autocomplete="username" autofocus required data-i18n-ph="plogin.namePh" />
    <label for="password" data-i18n="plogin.password">Password</label>
    <input id="password" name="password" type="password" autocomplete="current-password" required data-i18n-ph="plogin.passwordPh" />
    <button type="submit" class="primary" data-i18n="common.signin">Sign in</button>
    <a class="back" href="/" data-i18n="common.back">← Back to home</a>
  </form>
</body>
</html>`
}

export function renderPortal(): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title data-i18n="plogin.title">CC Gateway — Client Portal</title>
<meta name="viewport" content="width=device-width,initial-scale=1" />
${i18nHead()}
<style>
${SHARED_HEAD_STYLE}
  header {
    padding: 14px 24px; border-bottom: 1px solid var(--border);
    display: flex; align-items: center; justify-content: space-between; gap: 12px;
    background: var(--panel); position: sticky; top: 0; z-index: 20;
  }
  header .left { display: flex; align-items: center; gap: 12px; min-width: 0; }
  header .right { display: flex; align-items: center; gap: 10px; }
  header .avatar {
    width: 34px; height: 34px; border-radius: 50%; flex-shrink: 0;
    background: linear-gradient(135deg, #1f6feb, #58a6ff); color: #fff;
    display: flex; align-items: center; justify-content: center; font-weight: 700; font-size: 14px;
  }
  header .title { font-size: 15px; font-weight: 600; line-height: 1.2; }
  header .sub { color: var(--muted); font-size: 12px; font-family: var(--mono); }
  nav.tabs {
    display: flex; gap: 4px; overflow-x: auto; padding: 0 16px;
    background: var(--panel); border-bottom: 1px solid var(--border);
    position: sticky; top: 63px; z-index: 19; scrollbar-width: none;
  }
  nav.tabs::-webkit-scrollbar { display: none; }
  nav.tabs a {
    padding: 12px 14px; font-size: 13px; color: var(--muted); text-decoration: none;
    border-bottom: 2px solid transparent; white-space: nowrap;
  }
  nav.tabs a:hover { color: var(--fg); }
  nav.tabs a.active { color: var(--accent); border-bottom-color: var(--accent); }
  main { padding: 22px 24px; max-width: 1000px; margin: 0 auto; }
  section.block { scroll-margin-top: 110px; margin-bottom: 26px; }
  section.block > h2.section-title { font-size: 13px; text-transform: uppercase; letter-spacing: .05em; color: var(--muted); margin: 0 0 12px; }
  .grid { display: grid; gap: 16px; }
  .row { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px,1fr)); gap: 12px; }
  .two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
  .card { background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 18px; }
  .card h3 { margin: 0 0 12px; font-size: 13px; }
  .stat .value { font-size: 22px; font-weight: 600; font-family: var(--mono); }
  .stat .label { font-size: 11px; color: var(--muted); text-transform: uppercase; margin-top: 4px; letter-spacing: .03em; }
  .credit-card { background: linear-gradient(135deg, #11161d, #1a2230); }
  .credit-big { font-size: 36px; font-weight: 700; font-family: var(--mono); }
  .credit-sub { color: var(--muted); font-size: 13px; margin-top: 4px; }
  .meter { height: 10px; background: var(--panel-2); border-radius: 6px; overflow: hidden; margin: 16px 0 6px; }
  .meter > span { display: block; height: 100%; background: var(--ok); width: 0; transition: width .3s; }
  .meter > span.warn { background: var(--warn); }
  .meter > span.err { background: var(--err); }
  table { width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 13px; }
  th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--border); }
  th { color: var(--muted); font-weight: 500; font-size: 11px; text-transform: uppercase; letter-spacing: .04em; }
  tr:last-child td { border-bottom: none; }
  td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }
  .table-wrap { overflow-x: auto; }
  .table-wrap table { min-width: 520px; }
  .pill { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 11px; font-family: var(--mono); }
  .pill.ok { background: rgba(63,185,80,.15); color: var(--ok); }
  .pill.warn { background: rgba(210,153,34,.15); color: var(--warn); }
  .pill.err { background: rgba(248,81,73,.15); color: var(--err); }
  .pill.muted { background: var(--panel-2); color: var(--muted); }
  .kv { display: grid; grid-template-columns: 130px 1fr; gap: 8px 14px; font-size: 13px; align-items: center; }
  .kv .k { color: var(--muted); }
  .kv .v { font-family: var(--mono); word-break: break-word; }
  label.field { display: block; font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: .04em; margin: 0 0 4px; }
  input.text {
    width: 100%; padding: 9px 11px; background: var(--bg); color: var(--fg);
    border: 1px solid var(--border); border-radius: 6px; font-size: 14px; box-sizing: border-box;
  }
  input.text:focus { outline: none; border-color: var(--accent); }
  .muted { color: var(--muted); }
  .controls { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }
  .step-label { margin: 18px 0 6px; font-size: 12px; text-transform: uppercase; letter-spacing: .04em; color: var(--fg); }
  .step-label .num { display: inline-block; min-width: 18px; height: 18px; line-height: 18px; text-align: center; background: var(--panel-2); border: 1px solid var(--border); border-radius: 4px; font-size: 11px; margin-right: 6px; }
  .snippet-block { position: relative; }
  .snippet { background: var(--bg); border: 1px solid var(--border); border-radius: 6px; padding: 10px 64px 10px 12px; font-family: var(--mono); font-size: 12px; color: var(--fg); margin: 0; overflow-x: auto; white-space: pre; scrollbar-width: thin; scrollbar-color: #2c333d var(--bg); }
  .snippet::-webkit-scrollbar { height: 7px; }
  .snippet::-webkit-scrollbar-thumb { background: #2c333d; border-radius: 4px; }
  .snippet.wrap { white-space: pre-wrap; word-break: break-all; overflow-x: visible; }
  .copy-btn { position: absolute; top: 6px; right: 6px; padding: 4px 10px; font-size: 11px; background: var(--panel-2); color: var(--fg); border: 1px solid var(--border); border-radius: 4px; cursor: pointer; }
  .copy-btn:hover { border-color: var(--accent); color: var(--accent); }
  .copy-btn.copied { color: var(--ok); border-color: var(--ok); }
  .warnbox { color: var(--warn); font-size: 12px; margin: 8px 0 0; }
  .cmd-table { display: grid; grid-template-columns: max-content 1fr; gap: 6px 14px; background: var(--bg); border: 1px solid var(--border); border-radius: 6px; padding: 10px 12px; font-size: 12px; }
  .cmd-table code { font-family: var(--mono); color: var(--accent); white-space: nowrap; }
  .cmd-table span { color: var(--muted); }
  .ok-msg { color: var(--ok); font-size: 13px; }
  @media (max-width: 720px) {
    .two-col { grid-template-columns: 1fr; }
    nav.tabs { top: 60px; }
    main { padding: 16px 14px; }
  }
</style>
</head>
<body>
<header>
  <div class="left">
    <div class="avatar" id="avatar">·</div>
    <div>
      <div class="title" id="headerName">…</div>
      <div class="sub" id="headerSub"></div>
    </div>
  </div>
  <div class="right">
    ${langSwitcher('padding:6px 8px')}
    <form action="/portal/logout" method="post"><button type="submit" data-i18n="common.logout">Logout</button></form>
  </div>
</header>
<nav class="tabs" id="tabs">
  <a href="#overview" class="active" data-i18n="portal.tab.overview">Overview</a>
  <a href="#profile" data-i18n="portal.tab.profile">Profile</a>
  <a href="#usage" data-i18n="portal.tab.usage">Usage</a>
  <a href="#install" data-i18n="portal.tab.install">Install guide</a>
  <a href="#security" data-i18n="portal.tab.security">Security</a>
</nav>
<main>
  <!-- Overview -->
  <section id="overview" class="block">
    <h2 class="section-title" data-i18n="portal.sec.overview">Overview</h2>
    <div class="grid">
      <div class="card credit-card">
        <h3 data-i18n="portal.credit.h">Your credit</h3>
        <div id="creditBig" class="credit-big">…</div>
        <div id="creditSub" class="credit-sub"></div>
        <div class="meter" id="creditMeterWrap"><span id="creditMeter"></span></div>
        <div id="creditUsed" class="muted" style="font-size:12px"></div>
      </div>
      <div class="row" id="lifetimeStats"></div>
    </div>
  </section>

  <!-- Profile -->
  <section id="profile" class="block">
    <h2 class="section-title" data-i18n="portal.sec.profile">Profile &amp; account</h2>
    <div class="two-col">
      <div class="card">
        <h3 data-i18n="portal.profile.h">Personal info</h3>
        <p class="muted" style="margin:0 0 14px;font-size:12px" data-i18n="portal.profile.note"></p>
        <div id="profileMsg" style="display:none;margin-bottom:10px"></div>
        <label class="field" for="pfDisplay" data-i18n="portal.profile.display">Display name</label>
        <input class="text" id="pfDisplay" maxlength="64" data-i18n-ph="portal.profile.displayPh" style="margin-bottom:12px" />
        <label class="field" for="pfEmail" data-i18n="portal.profile.email">Email</label>
        <input class="text" id="pfEmail" maxlength="254" type="email" placeholder="you@example.com" style="margin-bottom:14px" />
        <label class="field" for="pfWorkdir" data-i18n="portal.profile.workdir">Your home folder</label>
        <input class="text" id="pfWorkdir" maxlength="220" spellcheck="false" placeholder="/Users/alice" data-i18n-ph="portal.profile.workdirPh" style="margin-bottom:6px" />
        <p class="muted" style="margin:0 0 14px;font-size:11px" data-i18n-html="portal.profile.workdirNote">macOS <code>/Users/&lt;name&gt;</code> · Linux <code>/home/&lt;name&gt;</code> · Windows <code>C:\\Users\\&lt;name&gt;</code>. Run <code>echo $HOME</code> (or <code>echo %USERPROFILE%</code> on Windows) and paste it. Lets file/bash paths in Claude's replies point at your real machine. Leave empty to auto-detect.</p>
        <button id="pfSave" class="primary" type="button" data-i18n="portal.profile.save">Save profile</button>
      </div>
      <div class="card">
        <h3 data-i18n="portal.account.h">Account</h3>
        <div class="kv">
          <div class="k" data-i18n="portal.account.name">Client name</div><div class="v" id="acName">—</div>
          <div class="k" data-i18n="portal.account.plan">Plan / limit</div><div class="v" id="acPlan">—</div>
          <div class="k" data-i18n="portal.account.since">Member since</div><div class="v" id="acSince">—</div>
          <div class="k" data-i18n="portal.account.pwSet">Password set</div><div class="v" id="acPwUpdated">—</div>
        </div>
        <h3 style="margin:18px 0 8px" data-i18n="portal.token.h">API token</h3>
        <p class="muted" style="margin:0 0 8px;font-size:12px" data-i18n="portal.token.note"></p>
        <div class="snippet-block">
          <pre class="snippet" id="acToken">••••••••</pre>
          <button id="acTokenReveal" type="button" class="copy-btn" style="right:74px" data-i18n="portal.token.reveal">Reveal</button>
          <button id="acTokenCopy" type="button" class="copy-btn" data-i18n="common.copy">Copy</button>
        </div>
      </div>
    </div>
  </section>

  <!-- Usage -->
  <section id="usage" class="block">
    <h2 class="section-title" data-i18n="portal.sec.usage">Usage</h2>
    <div class="grid">
      <div class="card">
        <h3 data-i18n="portal.usage.byPeriod">By period</h3>
        <div class="table-wrap" id="periodTable"></div>
      </div>
      <div class="card">
        <h3 data-i18n="portal.usage.byModel">By model</h3>
        <div class="table-wrap" id="modelsTable"></div>
      </div>
      <div class="card">
        <h3 data-i18n="portal.usage.recent">Recent activity</h3>
        <div class="table-wrap" id="recentTable"></div>
      </div>
    </div>
  </section>

  <!-- Install guide -->
  <section id="install" class="block">
    <h2 class="section-title" data-i18n="portal.sec.install">Install guide</h2>
    <div class="card">
      <p class="muted" style="margin:0 0 12px" data-i18n="portal.install.intro"></p>
      <div class="controls" style="margin-bottom:6px">
        <select id="dlPlatform">
          <option value="unix">macOS / Linux (bash)</option>
          <option value="windows">Windows (PowerShell)</option>
        </select>
        <select id="dlScheme">
          <option value="https">https</option>
          <option value="http">http</option>
        </select>
        <button id="dlBtn" class="primary" type="button" data-i18n="portal.install.download">Download launcher</button>
        <span class="muted" style="font-size:12px"><span data-i18n="portal.install.file">File:</span> <code id="dlFile">cc-…</code></span>
      </div>

      <div style="background:linear-gradient(135deg,#11161d,#1a2230);border:1px solid var(--border);border-radius:10px;padding:16px;margin:14px 0 6px">
        <div style="font-size:13px;font-weight:600;margin-bottom:4px" data-i18n="portal.install.quickH">⚡ Quick install</div>
        <p class="muted" style="margin:0 0 10px;font-size:12px" data-i18n="portal.install.quickNote"></p>
        <div class="muted" style="font-size:11px;margin-bottom:4px" data-i18n="os.unix">macOS / Linux</div>
        <div class="snippet-block" style="margin-bottom:10px"><pre class="snippet wrap" id="cmdOneLineUnix">…</pre><button class="copy-btn" data-copy="cmdOneLineUnix" type="button" data-i18n="common.copy">Copy</button></div>
        <div class="muted" style="font-size:11px;margin-bottom:4px" data-i18n="os.win">Windows (PowerShell)</div>
        <div class="snippet-block"><pre class="snippet wrap" id="cmdOneLineWin">…</pre><button class="copy-btn" data-copy="cmdOneLineWin" type="button" data-i18n="common.copy">Copy</button></div>
        <p class="muted" style="margin:8px 0 0;font-size:11px" data-i18n="portal.install.quickExpire"></p>
      </div>

      <p class="step-label" data-i18n="portal.install.prereqH">Manual install — prerequisite</p>
      <p class="muted" style="margin:0 0 6px;font-size:12px" data-i18n="portal.install.prereqNote"></p>
      <div class="snippet-block"><pre class="snippet" id="cmdPrereq">npm install -g @anthropic-ai/claude-code</pre><button class="copy-btn" data-copy="cmdPrereq" type="button" data-i18n="common.copy">Copy</button></div>

      <p class="step-label" id="step1Label"><span class="num">1</span><span id="step1Text"></span></p>
      <p class="muted" id="step1Meta" style="margin:0 0 6px;font-size:12px"></p>
      <div class="snippet-block"><pre class="snippet" id="cmdUnblock"></pre><button class="copy-btn" data-copy="cmdUnblock" type="button" data-i18n="common.copy">Copy</button></div>

      <p class="step-label"><span class="num">2</span><span id="step2Text"></span></p>
      <p class="muted" id="step2Meta" style="margin:0 0 6px;font-size:12px"></p>
      <div class="snippet-block"><pre class="snippet" id="cmdRun"></pre><button class="copy-btn" data-copy="cmdRun" type="button" data-i18n="common.copy">Copy</button></div>
      <p class="warnbox" id="s2warn" data-i18n="portal.install.s2warn"></p>

      <p class="step-label"><span class="num">3</span><span id="step3Text"></span></p>
      <p class="muted" id="step3Meta" style="margin:0 0 6px;font-size:12px"></p>
      <div class="snippet-block"><pre class="snippet" id="cmdInstall"></pre><button class="copy-btn" data-copy="cmdInstall" type="button" data-i18n="common.copy">Copy</button></div>

      <p class="step-label"><span class="num">4</span><span data-i18n="portal.install.s4"></span></p>
      <p class="muted" style="margin:0 0 6px;font-size:12px" data-i18n="portal.install.s4meta"></p>
      <div class="snippet-block"><pre class="snippet" id="cmdHijack">ccg hijack</pre><button class="copy-btn" data-copy="cmdHijack" type="button" data-i18n="common.copy">Copy</button></div>

      <p class="step-label"><span class="num">5</span><span data-i18n="portal.install.s5"></span></p>
      <p class="muted" style="margin:0 0 6px;font-size:12px" data-i18n="portal.install.s5meta"></p>
      <div class="snippet-block"><pre class="snippet" id="cmdHijackGui">ccg hijack-gui</pre><button class="copy-btn" data-copy="cmdHijackGui" type="button" data-i18n="common.copy">Copy</button></div>

      <p class="step-label" data-i18n="portal.install.subcmds">All ccg subcommands</p>
      <div class="cmd-table">
        <code>ccg</code><span data-i18n="cmd.ccg"></span>
        <code>ccg [claude args]</code><span data-i18n="cmd.ccgArgs"></span>
        <code>ccg --print "hi"</code><span data-i18n="cmd.ccgPrint"></span>
        <code>ccg install</code><span data-i18n="cmd.install"></span>
        <code>ccg uninstall</code><span data-i18n="cmd.uninstall"></span>
        <code>ccg hijack</code><span data-i18n="cmd.hijack"></span>
        <code>ccg release</code><span data-i18n="cmd.release"></span>
        <code>ccg hijack-gui</code><span data-i18n="cmd.hijackGui"></span>
        <code>ccg release-gui</code><span data-i18n="cmd.releaseGui"></span>
        <code>ccg native [args]</code><span data-i18n="cmd.native"></span>
        <code>ccg status</code><span data-i18n="cmd.status"></span>
        <code>ccg help</code><span data-i18n="cmd.help"></span>
      </div>

      <p class="step-label" data-i18n="portal.install.manualH">Manual setup (no launcher)</p>
      <p class="muted" style="margin:0 0 6px;font-size:12px" data-i18n="portal.install.manualNote"></p>
      <div class="snippet-block"><pre class="snippet wrap" id="cmdManual"></pre><button class="copy-btn" data-copy="cmdManual" type="button" data-i18n="common.copy">Copy</button></div>
    </div>
  </section>

  <!-- Security -->
  <section id="security" class="block">
    <h2 class="section-title" data-i18n="portal.sec.security">Security</h2>
    <div class="card" style="max-width:420px">
      <h3 data-i18n="portal.sec.changePw">Change password</h3>
      <p class="muted" style="margin:0 0 12px" data-i18n="portal.sec.changePwNote"></p>
      <div id="pwMsg" style="display:none;margin-bottom:10px"></div>
      <div style="display:grid;gap:10px">
        <input class="text" id="pwCurrent" type="password" autocomplete="current-password" data-i18n-ph="portal.sec.current" />
        <input class="text" id="pwNew" type="password" autocomplete="new-password" data-i18n-ph="portal.sec.new" />
        <input class="text" id="pwConfirm" type="password" autocomplete="new-password" data-i18n-ph="portal.sec.confirm" />
        <div><button id="pwBtn" class="primary" type="button" data-i18n="portal.sec.update">Update password</button></div>
      </div>
    </div>
  </section>
</main>
<script>
(() => {
  const t = (k, v) => (window.t ? window.t(k, v) : k);
  const esc = (s) => String(s == null ? '' : s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
  const fmtNum = (n) => (n || 0).toLocaleString();
  const fmtTokens = (n) => {
    n = n || 0;
    if (n < 1000) return String(n);
    if (n < 1e6) return (n/1000).toFixed(1).replace(/\\.0$/,'') + 'k';
    return (n/1e6).toFixed(2).replace(/\\.00$/,'') + 'M';
  };
  const fmtCost = (n) => {
    n = n || 0;
    if (n === 0) return '$0';
    if (n < 0.01) return '$' + n.toFixed(4);
    if (n < 100) return '$' + n.toFixed(2);
    return '$' + Math.round(n).toLocaleString();
  };
  const shortModel = (m) => !m ? '—' : m.replace(/^claude-/, '').replace(/-\\d{8}$/, '');
  const fmtAgo = (ts) => {
    const d = Math.max(0, Date.now() - ts);
    if (d < 60000) return Math.floor(d/1000) + 's';
    if (d < 3600000) return Math.floor(d/60000) + 'm';
    if (d < 86400000) return Math.floor(d/3600000) + 'h';
    return Math.floor(d/86400000) + 'd';
  };
  const fmtDate = (ts) => !ts ? '—' : new Date(ts).toLocaleDateString(undefined, { year:'numeric', month:'short', day:'numeric' });
  const periodLabel = (p) => t('portal.period.' + p);

  let CLIENT = '', TOKEN = '', GATEWAY = location.host, INSTALL_TOKEN = '', tokenShown = false, firstRender = true;

  const render = (d) => {
    CLIENT = d.name; TOKEN = d.token || '';
    GATEWAY = d.gateway_addr || location.host;
    // Freeze the install token on first load so the one-line command stays
    // stable instead of changing on every background refresh.
    if (firstRender) INSTALL_TOKEN = d.install_token || '';
    const display = (d.profile && d.profile.display_name) || d.name;
    document.getElementById('headerName').textContent = display;
    document.getElementById('headerSub').textContent = '@' + d.name;
    document.getElementById('avatar').textContent = (display[0] || '?').toUpperCase();

    // Credit
    const c = d.credit;
    const big = document.getElementById('creditBig');
    const sub = document.getElementById('creditSub');
    const meterWrap = document.getElementById('creditMeterWrap');
    const meter = document.getElementById('creditMeter');
    const used = document.getElementById('creditUsed');
    if (c.limit_usd == null) {
      big.textContent = t('portal.credit.unlimited');
      sub.textContent = t('portal.credit.noLimit');
      meterWrap.style.display = 'none';
      used.textContent = t('portal.credit.usedSoFar', { used: fmtCost(c.used_usd) });
    } else {
      meterWrap.style.display = '';
      big.textContent = fmtCost(c.remaining_usd) + t('portal.credit.leftSuffix');
      sub.textContent = t('portal.credit.ofCredit', { limit: fmtCost(c.limit_usd), period: periodLabel(c.period) });
      const pct = c.limit_usd > 0 ? Math.min(100, (c.used_usd / c.limit_usd) * 100) : 0;
      meter.style.width = pct + '%';
      meter.className = pct >= 100 ? 'err' : pct >= 80 ? 'warn' : '';
      used.textContent = t('portal.credit.usedOf', { used: fmtCost(c.used_usd), limit: fmtCost(c.limit_usd), pct: pct.toFixed(0) });
    }

    // Lifetime stats
    const lt = d.lifetime;
    document.getElementById('lifetimeStats').innerHTML = [
      ['portal.stat.requests', fmtNum(lt.total)],
      ['portal.stat.cost', fmtCost(lt.costUsd)],
      ['portal.stat.input', fmtTokens(lt.inputTokens)],
      ['portal.stat.output', fmtTokens(lt.outputTokens)],
      ['portal.stat.cacheRead', fmtTokens(lt.cacheReadTokens)],
      ['portal.stat.lastActive', lt.lastSeen ? fmtAgo(lt.lastSeen) : '—'],
    ].map(([key, value]) => '<div class="card stat"><div class="value">' + value + '</div><div class="label">' + esc(t(key)) + '</div></div>').join('');

    // Account
    const a = d.account || {};
    document.getElementById('acName').textContent = d.name;
    document.getElementById('acPlan').textContent = a.cost_limit_usd == null
      ? t('portal.credit.unlimited')
      : fmtCost(a.cost_limit_usd) + ' / ' + periodLabel(a.cost_limit_period || 'lifetime');
    document.getElementById('acSince').textContent = fmtDate(a.created_at);
    document.getElementById('acPwUpdated').textContent = fmtDate(a.password_updated_at);

    // Profile inputs — seed only on first load so a background refresh doesn't
    // wipe out what the user is currently typing.
    if (firstRender) {
      document.getElementById('pfDisplay').value = (d.profile && d.profile.display_name) || '';
      document.getElementById('pfEmail').value = (d.profile && d.profile.email) || '';
      document.getElementById('pfWorkdir').value = (d.profile && d.profile.home_dir) || '';
    }

    // Periods
    document.getElementById('periodTable').innerHTML = renderPeriodTable(d.periods || []);

    // Models
    const models = d.models || [];
    document.getElementById('modelsTable').innerHTML = models.length
      ? '<table><thead><tr><th>' + esc(t('th.model')) + '</th><th class="num">' + esc(t('th.calls')) + '</th><th class="num">' + esc(t('th.input')) + '</th><th class="num">' + esc(t('th.output')) + '</th><th class="num">' + esc(t('th.cache')) + '</th><th class="num">' + esc(t('th.cost')) + '</th></tr></thead><tbody>'
        + models.map(m => '<tr><td><strong>' + esc(shortModel(m.model)) + '</strong></td>'
          + '<td class="num">' + fmtNum(m.total) + '</td>'
          + '<td class="num">' + fmtTokens(m.inputTokens) + '</td>'
          + '<td class="num">' + fmtTokens(m.outputTokens) + '</td>'
          + '<td class="num">' + fmtTokens((m.cacheReadTokens||0)+(m.cacheCreationTokens||0)) + '</td>'
          + '<td class="num"><strong>' + fmtCost(m.costUsd) + '</strong></td></tr>').join('')
        + '</tbody></table>'
      : '<p class="muted" style="margin:0">' + esc(t('portal.usage.noModel')) + '</p>';

    // Recent
    const recent = d.recent || [];
    document.getElementById('recentTable').innerHTML = recent.length
      ? '<table><thead><tr><th>' + esc(t('th.when')) + '</th><th>' + esc(t('th.model')) + '</th><th>' + esc(t('th.status')) + '</th><th class="num">' + esc(t('th.dur')) + '</th><th class="num">' + esc(t('th.in')) + '</th><th class="num">' + esc(t('th.out')) + '</th><th class="num">' + esc(t('th.cost')) + '</th><th>' + esc(t('th.message')) + '</th></tr></thead><tbody>'
        + recent.map(r => {
          const cls = r.status >= 500 ? 'err' : r.status >= 400 ? 'warn' : 'ok';
          const hasUsage = r.inputTokens || r.outputTokens;
          return '<tr><td class="muted">' + fmtAgo(r.ts) + '</td>'
            + '<td><span class="muted">' + esc(shortModel(r.model)) + '</span></td>'
            + '<td><span class="pill ' + cls + '"' + (r.errorDetail ? ' title="' + esc(r.errorDetail) + '"' : '') + '>' + r.status + (r.errorSource ? ' · ' + esc(r.errorSource) : '') + '</span></td>'
            + '<td class="num">' + r.durationMs + 'ms</td>'
            + '<td class="num">' + (hasUsage ? fmtTokens(r.inputTokens) : '—') + '</td>'
            + '<td class="num">' + (hasUsage ? fmtTokens(r.outputTokens) : '—') + '</td>'
            + '<td class="num">' + (r.costUsd ? fmtCost(r.costUsd) : '—') + '</td>'
            + '<td class="muted" title="' + esc(r.userMessage||'') + '" style="max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + (esc(r.userMessage||'') || '—') + '</td></tr>';
        }).join('')
        + '</tbody></table>'
      : '<p class="muted" style="margin:0">' + esc(t('portal.usage.noReq')) + '</p>';

    if (firstRender) { updateInstall(); firstRender = false; }
  };

  const renderPeriodTable = (periods) => {
    if (!periods.length) return '<p class="muted" style="margin:0">' + esc(t('portal.usage.noUsage')) + '</p>';
    return '<table><thead><tr><th>' + esc(t('th.period')) + '</th><th class="num">' + esc(t('th.calls')) + '</th><th class="num">' + esc(t('th.input')) + '</th><th class="num">' + esc(t('th.output')) + '</th><th class="num">' + esc(t('th.cost')) + '</th></tr></thead><tbody>'
      + periods.map(p => '<tr><td><strong>' + esc(p.label) + '</strong></td>'
        + '<td class="num">' + fmtNum(p.total) + '</td>'
        + '<td class="num">' + fmtTokens(p.inputTokens) + '</td>'
        + '<td class="num">' + fmtTokens(p.outputTokens) + '</td>'
        + '<td class="num"><strong>' + fmtCost(p.costUsd) + '</strong></td></tr>').join('')
      + '</tbody></table>';
  };

  // ── Install guide (platform-aware) ──
  const updateInstall = () => {
    const platform = document.getElementById('dlPlatform').value;
    const scheme = document.getElementById('dlScheme').value;
    const name = CLIENT || 'client';
    const isWin = platform === 'windows';
    const fname = isWin ? 'cc-' + name + '.ps1' : 'cc-' + name;
    document.getElementById('dlFile').textContent = fname;
    const gw = scheme + '://' + GATEWAY;

    // One-line install commands — both OSes shown at once.
    const unixEl = document.getElementById('cmdOneLineUnix');
    const winEl = document.getElementById('cmdOneLineWin');
    if (INSTALL_TOKEN) {
      const url = (ext) => location.origin + '/portal/install.' + ext
        + '?t=' + encodeURIComponent(INSTALL_TOKEN) + '&scheme=' + scheme;
      unixEl.textContent = 'curl -fsSL "' + url('sh') + '" | bash';
      winEl.textContent = 'irm "' + url('ps1') + '" | iex';
    } else {
      unixEl.textContent = winEl.textContent = t('portal.install.reloadLink');
    }

    document.getElementById('step1Text').textContent = t(isWin ? 'portal.install.s1.win' : 'portal.install.s1.unix');
    document.getElementById('step1Meta').textContent = t(isWin ? 'portal.install.s1meta.win' : 'portal.install.s1meta.unix');
    document.getElementById('step2Text').textContent = t('portal.install.s2');
    document.getElementById('step2Meta').textContent = t(isWin ? 'portal.install.s2meta.win' : 'portal.install.s2meta.unix');
    document.getElementById('step3Text').textContent = t('portal.install.s3');
    document.getElementById('step3Meta').textContent = t(isWin ? 'portal.install.s3meta.win' : 'portal.install.s3meta.unix');

    if (isWin) {
      document.getElementById('cmdUnblock').textContent = 'Set-ExecutionPolicy -Scope CurrentUser RemoteSigned -Force; Unblock-File .\\\\' + fname;
      document.getElementById('cmdRun').textContent = '.\\\\' + fname;
      document.getElementById('cmdInstall').textContent = '.\\\\' + fname + ' install';
      document.getElementById('cmdManual').textContent =
        '$env:ANTHROPIC_BASE_URL = "' + gw + '"\\n$env:ANTHROPIC_API_KEY = "' + (TOKEN || '<your-token>') + '"\\nclaude';
    } else {
      document.getElementById('cmdUnblock').textContent = 'xattr -d com.apple.quarantine ' + fname;
      document.getElementById('cmdRun').textContent = 'chmod +x ' + fname + ' && ./' + fname;
      document.getElementById('cmdInstall').textContent = 'chmod +x ' + fname + ' && ./' + fname + ' install';
      document.getElementById('cmdManual').textContent =
        'export ANTHROPIC_BASE_URL="' + gw + '"\\nexport ANTHROPIC_API_KEY="' + (TOKEN || '<your-token>') + '"\\nclaude';
    }
  };
  document.getElementById('dlPlatform').addEventListener('change', updateInstall);
  document.getElementById('dlScheme').addEventListener('change', updateInstall);
  document.getElementById('dlScheme').value = location.protocol === 'http:' ? 'http' : 'https';

  document.getElementById('dlBtn').addEventListener('click', () => {
    const qs = new URLSearchParams({
      platform: document.getElementById('dlPlatform').value,
      scheme: document.getElementById('dlScheme').value,
    });
    window.location.href = '/portal/launcher?' + qs.toString();
  });

  // ── Token reveal / copy ──
  document.getElementById('acTokenReveal').addEventListener('click', (e) => {
    tokenShown = !tokenShown;
    document.getElementById('acToken').textContent = tokenShown ? (TOKEN || '—') : '••••••••';
    e.currentTarget.textContent = tokenShown ? t('portal.token.hide') : t('portal.token.reveal');
  });

  // ── Copy buttons ──
  const copyText = async (btn, text) => {
    try {
      await navigator.clipboard.writeText(text);
      btn.textContent = t('common.copied'); btn.classList.add('copied');
      setTimeout(() => { btn.textContent = t('common.copy'); btn.classList.remove('copied'); }, 1500);
    } catch {}
  };
  document.querySelectorAll('[data-copy]').forEach(btn => {
    btn.addEventListener('click', () => copyText(btn, document.getElementById(btn.getAttribute('data-copy')).textContent));
  });
  document.getElementById('acTokenCopy').addEventListener('click', (e) => copyText(e.currentTarget, TOKEN));

  // ── Profile save ──
  const profileMsg = (text, ok) => {
    const el = document.getElementById('profileMsg');
    el.style.display = 'block'; el.className = ok ? 'ok-msg' : 'error'; el.textContent = text;
  };
  document.getElementById('pfSave').addEventListener('click', async () => {
    const btn = document.getElementById('pfSave');
    btn.disabled = true;
    try {
      const res = await fetch('/portal/profile', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          display_name: document.getElementById('pfDisplay').value,
          email: document.getElementById('pfEmail').value,
          home_dir: document.getElementById('pfWorkdir').value.trim() || null,
        }),
      });
      if (res.ok) {
        const d = await res.json();
        profileMsg(t('portal.profile.saved'), true);
        const display = d.display_name || CLIENT;
        document.getElementById('headerName').textContent = display;
        document.getElementById('avatar').textContent = (display[0] || '?').toUpperCase();
      } else if (res.status === 401) {
        window.location.href = '/portal';
      } else {
        const err = await res.json().catch(() => ({}));
        profileMsg(err.error || ('Error ' + res.status), false);
      }
    } catch { profileMsg(t('portal.msg.netErr'), false); }
    finally { btn.disabled = false; }
  });

  // ── Change password ──
  const pwMsg = (text, ok) => {
    const el = document.getElementById('pwMsg');
    el.style.display = 'block'; el.className = ok ? 'ok-msg' : 'error'; el.textContent = text;
  };
  document.getElementById('pwBtn').addEventListener('click', async () => {
    const current = document.getElementById('pwCurrent').value;
    const next = document.getElementById('pwNew').value;
    const confirm = document.getElementById('pwConfirm').value;
    if (!current || !next) { pwMsg(t('portal.msg.fillPw'), false); return; }
    if (next.length < 8) { pwMsg(t('portal.msg.pwLen'), false); return; }
    if (next !== confirm) { pwMsg(t('portal.msg.pwMatch'), false); return; }
    const btn = document.getElementById('pwBtn');
    btn.disabled = true;
    try {
      const res = await fetch('/portal/password', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ current, new: next }),
      });
      if (res.ok) {
        pwMsg(t('portal.msg.pwUpdated'), true);
        document.getElementById('pwCurrent').value = '';
        document.getElementById('pwNew').value = '';
        document.getElementById('pwConfirm').value = '';
      } else if (res.status === 401) {
        window.location.href = '/portal';
      } else {
        const err = await res.json().catch(() => ({}));
        pwMsg(err.error || ('Error ' + res.status), false);
      }
    } catch { pwMsg(t('portal.msg.netErr'), false); }
    finally { btn.disabled = false; }
  });

  // ── Tab highlighting ──
  const tabLinks = Array.from(document.querySelectorAll('#tabs a'));
  const sections = tabLinks.map(a => document.getElementById(a.getAttribute('href').slice(1))).filter(Boolean);
  if ('IntersectionObserver' in window) {
    const ratios = new Map();
    const io = new IntersectionObserver((entries) => {
      for (const e of entries) ratios.set(e.target.id, e.intersectionRatio);
      let best = null, bestR = 0;
      for (const [id, r] of ratios) if (r > bestR) { bestR = r; best = id; }
      if (best) tabLinks.forEach(a => a.classList.toggle('active', a.getAttribute('href') === '#' + best));
    }, { rootMargin: '-120px 0px -55% 0px', threshold: [0, 0.2, 0.6, 1] });
    sections.forEach(s => io.observe(s));
  }

  // ── Load ──
  const load = () => fetch('/portal/me', { headers: { 'Accept': 'application/json' } })
    .then(r => { if (r.status === 401) { window.location.href = '/portal'; return null; } return r.json(); })
    .then(d => { if (d) render(d); })
    .catch(() => { document.getElementById('creditBig').textContent = t('portal.msg.loadErr'); });
  load();
  setInterval(load, 30000);
})();
</script>
</body>
</html>`
}
