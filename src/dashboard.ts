import { i18nHead, langSwitcher } from './i18n.js'

export function renderLogin(error?: string): string {
  const errBlock = error
    ? `<div class="error" data-i18n="${error}"></div>`
    : ''
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title data-i18n="alogin.title">CC Gateway — Login</title>
<meta name="viewport" content="width=device-width,initial-scale=1" />
${i18nHead()}
<style>
  .topbar { display: flex; align-items: center; justify-content: space-between; margin-bottom: 16px; }
  .topbar .brand { font-weight: 700; font-size: 15px; color: #e6edf3; }
  .topbar select { background: #1b2027; color: #e6edf3; border: 1px solid #232a33; border-radius: 6px; padding: 6px 8px; font-size: 13px; font-family: inherit; cursor: pointer; }
  body {
    margin: 0; min-height: 100vh;
    display: flex; align-items: center; justify-content: center;
    background: #0b0d10; color: #e6edf3;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  }
  .box {
    background: #14181d; border: 1px solid #232a33; border-radius: 10px;
    padding: 32px; width: 360px; max-width: 90vw;
  }
  h1 { font-size: 18px; margin: 0 0 6px; }
  p.sub { color: #8b949e; font-size: 13px; margin: 0 0 22px; }
  label { display: block; font-size: 12px; color: #8b949e; margin: 14px 0 4px; text-transform: uppercase; letter-spacing: .04em; }
  input {
    width: 100%; padding: 10px 12px; box-sizing: border-box;
    background: #0b0d10; color: #e6edf3;
    border: 1px solid #232a33; border-radius: 6px;
    font-size: 14px; font-family: inherit;
  }
  input:focus { outline: none; border-color: #58a6ff; }
  button {
    margin-top: 22px; width: 100%; padding: 10px;
    background: #1f6feb; color: white; border: 0; border-radius: 6px;
    font-size: 14px; font-weight: 500; cursor: pointer;
  }
  button:hover { background: #388bfd; }
  .error { background: rgba(248,81,73,.1); border: 1px solid rgba(248,81,73,.3); color: #f85149; padding: 10px 12px; border-radius: 6px; font-size: 13px; margin-bottom: 8px; }
</style>
</head>
<body>
  <form class="box" method="post" action="/admin">
    <div class="topbar">
      <div class="brand">CC Gateway</div>
      ${langSwitcher('padding:6px 8px')}
    </div>
    <h1 data-i18n="alogin.h1">CC Gateway · Admin</h1>
    <p class="sub" data-i18n="alogin.sub">Sign in to access the dashboard</p>
    ${errBlock}
    <label for="username" data-i18n="alogin.username">Username</label>
    <input id="username" name="username" autocomplete="username" autofocus required />
    <label for="password" data-i18n="alogin.password">Password</label>
    <input id="password" name="password" type="password" autocomplete="current-password" required />
    <button type="submit" data-i18n="common.signin">Sign in</button>
    <p style="margin:18px 0 0;text-align:center;font-size:12px;color:#8b949e">
      <span data-i18n="alogin.clientPrompt">Are you a client?</span> <a href="/portal" style="color:#58a6ff" data-i18n="alogin.openPortal">Open the client portal</a>
    </p>
  </form>
</body>
</html>`
}

export function renderDashboard(): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title data-i18n="admin.title">CC Gateway — Dashboard</title>
<meta name="viewport" content="width=device-width,initial-scale=1" />
${i18nHead()}
<style>
  :root {
    --bg: #0b0d10;
    --panel: #14181d;
    --panel-2: #1b2027;
    --border: #232a33;
    --fg: #e6edf3;
    --muted: #8b949e;
    --accent: #58a6ff;
    --ok: #3fb950;
    --warn: #d29922;
    --err: #f85149;
    --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; padding: 0;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: var(--bg); color: var(--fg);
    font-size: 14px;
    display: flex; min-height: 100vh;
  }
  aside.sidebar {
    width: 220px; flex-shrink: 0;
    background: var(--panel); border-right: 1px solid var(--border);
    display: flex; flex-direction: column;
    position: sticky; top: 0; height: 100vh;
  }
  aside.sidebar .brand {
    padding: 18px 20px; border-bottom: 1px solid var(--border);
    font-weight: 600; font-size: 14px;
  }
  aside.sidebar .brand .sub {
    display: block; color: var(--muted); font-size: 11px;
    font-weight: 400; margin-top: 2px; letter-spacing: .02em;
  }
  aside.sidebar nav {
    flex: 1; overflow-y: auto; padding: 12px 8px;
    display: flex; flex-direction: column; gap: 2px;
  }
  aside.sidebar nav a {
    display: flex; align-items: center; gap: 10px;
    padding: 8px 12px; border-radius: 6px;
    color: var(--fg); text-decoration: none; font-size: 13px;
    opacity: .8;
  }
  aside.sidebar nav a:hover { background: var(--panel-2); opacity: 1; }
  aside.sidebar nav a.active { background: var(--panel-2); opacity: 1; color: var(--accent); }
  aside.sidebar nav a .icon { font-family: var(--mono); width: 16px; text-align: center; opacity: .7; }
  aside.sidebar .sidebar-footer {
    padding: 12px 16px; border-top: 1px solid var(--border);
    font-size: 11px; color: var(--muted); display: flex;
    flex-direction: column; gap: 8px;
  }
  aside.sidebar .sidebar-footer form { display: block; }
  aside.sidebar .sidebar-footer form button { width: 100%; }
  .content { flex: 1; min-width: 0; display: flex; flex-direction: column; }
  header {
    padding: 14px 24px; border-bottom: 1px solid var(--border);
    display: flex; align-items: center; justify-content: space-between;
    background: var(--panel); position: sticky; top: 0; z-index: 10;
    gap: 12px;
  }
  header h1 { font-size: 16px; margin: 0; font-weight: 600; }
  header .meta { color: var(--muted); font-size: 12px; font-family: var(--mono); }
  main { padding: 20px 24px; max-width: 1400px; margin: 0 auto; width: 100%; }

  /* Tablet: collapse the sidebar into a sticky horizontal nav at the top. */
  @media (max-width: 800px) {
    body { flex-direction: column; }
    aside.sidebar {
      width: 100%; height: auto;
      position: sticky; top: 0; z-index: 20;
      flex-direction: row; align-items: center;
      padding: 0 12px;
    }
    aside.sidebar .brand {
      padding: 12px 8px 12px 4px; border-bottom: 0; border-right: 1px solid var(--border);
      flex-shrink: 0;
    }
    aside.sidebar .brand .sub { display: none; }
    aside.sidebar nav {
      flex: 1; flex-direction: row; padding: 8px;
      overflow-x: auto; overflow-y: hidden;
      scrollbar-width: none;
    }
    aside.sidebar nav::-webkit-scrollbar { display: none; }
    aside.sidebar nav a {
      padding: 6px 10px; flex-shrink: 0; font-size: 12px;
    }
    aside.sidebar .sidebar-footer { display: none; }
    header { position: static; }
  }

  /* Phone: rework the layout to feel mobile-native instead of a shrunk PC.
     - Header stacks; toolbar wraps onto its own row with full-width touch targets
     - Stat tiles sit in a 2-column grid
     - Wide data tables turn into stacked cards via [data-label] pseudo-labels,
       so each row reads top-to-bottom without horizontal scroll */
  @media (max-width: 600px) {
    body { font-size: 13px; }
    header {
      flex-direction: column; align-items: stretch;
      padding: 10px 14px; gap: 10px;
    }
    header h1 { font-size: 14px; }
    .toolbar { flex-wrap: wrap; gap: 8px; }
    .toolbar #updated { flex-basis: 100%; order: -1; font-size: 11px; }
    .toolbar select, .toolbar button { flex: 1 1 0; min-width: 0; font-size: 13px; padding: 8px 10px; }
    .toolbar form { display: contents; }

    main { padding: 12px 14px; }
    .grid { gap: 12px; }
    .card { padding: 14px; }
    .card h2 {
      margin-bottom: 10px; font-size: 11px;
      display: flex; align-items: center; justify-content: space-between; gap: 8px;
    }
    .card h2 button { float: none !important; margin: 0 !important; }

    /* Compact 2-up stat tiles */
    .row { grid-template-columns: repeat(2, 1fr); gap: 8px; }
    .card.stat { padding: 10px 12px; }
    .stat .value { font-size: 18px; }
    .stat .label { font-size: 10px; }

    /* iOS won't auto-zoom inputs at >= 16px */
    .modal-box input, .modal-box select { font-size: 16px; }

    /* Turn wide data tables into stacked cards.
       Each <tr> renders as a small card; each <td data-label="..."> shows
       its column name as a left-aligned pseudo-label. */
    #periodTable, #modelsTable, #clientsTable, #clientsConfig, .scroll-y { overflow-x: visible; }
    .scroll-y { max-height: 70vh; }
    #periodTable table, #modelsTable table, #clientsTable table,
    #clientsConfig table, .scroll-y table { min-width: 0; font-size: 13px; }

    #periodTable table, #modelsTable table, #clientsTable table,
    #clientsConfig table, .scroll-y table,
    #periodTable tbody, #modelsTable tbody, #clientsTable tbody,
    #clientsConfig tbody, .scroll-y tbody,
    #periodTable tr, #modelsTable tr, #clientsTable tr,
    #clientsConfig tr, .scroll-y tr,
    #periodTable td, #modelsTable td, #clientsTable td,
    #clientsConfig td, .scroll-y td { display: block; width: auto; }

    #periodTable thead, #modelsTable thead, #clientsTable thead,
    #clientsConfig thead, .scroll-y thead { display: none; }

    #periodTable tr, #modelsTable tr, #clientsTable tr,
    #clientsConfig tr, .scroll-y tr {
      background: var(--panel-2); border: 1px solid var(--border);
      border-radius: 8px; padding: 10px 12px; margin-bottom: 8px;
    }
    #periodTable tr:last-child, #modelsTable tr:last-child,
    #clientsTable tr:last-child, #clientsConfig tr:last-child,
    .scroll-y tr:last-child { margin-bottom: 0; }

    #periodTable td, #modelsTable td, #clientsTable td,
    #clientsConfig td, .scroll-y td {
      border: 0; padding: 4px 0;
      max-width: none !important; white-space: normal;
      display: flex; justify-content: space-between; gap: 12px; align-items: baseline;
      text-align: left;
    }
    #periodTable td.num, #modelsTable td.num, #clientsTable td.num,
    #clientsConfig td.num, .scroll-y td.num { text-align: right; }

    #periodTable td[data-label]::before, #modelsTable td[data-label]::before,
    #clientsTable td[data-label]::before, #clientsConfig td[data-label]::before,
    .scroll-y td[data-label]::before {
      content: attr(data-label);
      color: var(--muted); font-size: 11px;
      text-transform: uppercase; letter-spacing: .04em;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      flex-shrink: 0;
    }
    #periodTable td[data-label=""]::before, #modelsTable td[data-label=""]::before,
    #clientsTable td[data-label=""]::before, #clientsConfig td[data-label=""]::before,
    .scroll-y td[data-label=""]::before { content: none; }

    /* Empty-label cells render as full-width blocks (no two-column flex) so
       things like the row title and action-button rows lay out naturally. */
    #periodTable td[data-label=""], #modelsTable td[data-label=""],
    #clientsTable td[data-label=""], #clientsConfig td[data-label=""],
    .scroll-y td[data-label=""] { display: block; }

    /* First cell becomes the card title */
    #periodTable tr td:first-child, #modelsTable tr td:first-child,
    #clientsTable tr td:first-child, #clientsConfig tr td:first-child,
    .scroll-y tr td:first-child {
      padding: 0 0 8px; margin-bottom: 6px;
      border-bottom: 1px solid var(--border);
      font-size: 14px; font-family: var(--mono);
    }

    /* Action buttons in clientsConfig: wrap and size for touch */
    #clientsConfig td[data-label=""]:last-child {
      display: flex; flex-wrap: wrap; gap: 8px;
      padding-top: 8px; margin-top: 6px;
      border-top: 1px solid var(--border);
    }
    #clientsConfig td button { padding: 8px 12px; font-size: 13px; flex: 1 1 0; min-width: 0; }

    /* Recent message/path get full row width — no more truncation needed */
    .msg, .path { max-width: none; white-space: normal; word-break: break-word; }

    /* Filter bar: search spans full width, selects sit two per row, button
       and count each take their own line so touch targets stay large. */
    .filter-bar { gap: 6px; }
    .filter-bar input[type="search"] { flex: 1 1 100%; font-size: 16px; padding: 8px 10px; }
    .filter-bar select { flex: 1 1 calc(50% - 4px); font-size: 13px; padding: 8px 10px; }
    .filter-bar button { flex: 1 1 100%; padding: 8px 10px; font-size: 13px; }
    .filter-bar .count { flex: 1 1 100%; margin-left: 0; text-align: center; }

    .modal-box {
      width: 100%; max-width: 100vw; height: 100vh; max-height: 100vh;
      border-radius: 0; border: 0; padding: 18px;
      overflow-y: auto;
    }
    .modal { align-items: stretch; justify-content: stretch; }
  }

  /* All table containers get horizontal scroll so wide tables stay usable
     on narrow screens without breaking the card layout. */
  .table-wrap, #periodTable, #modelsTable, #clientsTable, #clientsConfig {
    overflow-x: auto;
    scrollbar-width: thin;
  }
  .table-wrap::-webkit-scrollbar,
  #periodTable::-webkit-scrollbar,
  #modelsTable::-webkit-scrollbar,
  #clientsTable::-webkit-scrollbar,
  #clientsConfig::-webkit-scrollbar { height: 8px; }
  .table-wrap::-webkit-scrollbar-thumb,
  #periodTable::-webkit-scrollbar-thumb,
  #modelsTable::-webkit-scrollbar-thumb,
  #clientsTable::-webkit-scrollbar-thumb,
  #clientsConfig::-webkit-scrollbar-thumb { background: #2c333d; border-radius: 4px; }
  /* Force tables inside the scroll wrappers to take their natural width so the
     overflow actually triggers instead of squishing columns. */
  #periodTable table, #modelsTable table, #clientsTable table, #clientsConfig table {
    min-width: 520px;
  }
  .scroll-y { overflow-x: auto; }
  .scroll-y table { min-width: 900px; }
  .grid { display: grid; gap: 16px; }
  .row { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px,1fr)); gap: 12px; }
  .card {
    background: var(--panel); border: 1px solid var(--border);
    border-radius: 8px; padding: 16px;
  }
  .card h2 {
    margin: 0 0 12px; font-size: 12px; letter-spacing: .04em;
    text-transform: uppercase; color: var(--muted); font-weight: 600;
  }
  .stat .value { font-size: 26px; font-weight: 600; font-family: var(--mono); }
  .stat .label { font-size: 11px; color: var(--muted); text-transform: uppercase; margin-top: 4px; letter-spacing: .03em; }
  table { width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 13px; }
  th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--border); }
  th { color: var(--muted); font-weight: 500; font-size: 11px; text-transform: uppercase; letter-spacing: .04em; }
  tr:last-child td { border-bottom: none; }
  .scroll-y {
    max-height: 480px; overflow-y: auto;
    border: 1px solid var(--border); border-radius: 6px;
    background: var(--panel); color: var(--fg);
    color-scheme: dark;
    scrollbar-color: #2c333d var(--panel);
    scrollbar-width: thin;
  }
  .scroll-y::-webkit-scrollbar { width: 10px; }
  .scroll-y::-webkit-scrollbar-track { background: var(--panel); }
  .scroll-y::-webkit-scrollbar-thumb { background: #2c333d; border-radius: 6px; border: 2px solid var(--panel); }
  .scroll-y::-webkit-scrollbar-thumb:hover { background: #3a4250; }
  .scroll-y table { font-size: 13px; background: var(--panel); }
  .scroll-y thead th {
    position: sticky; top: 0;
    background: var(--panel-2); color: var(--muted);
    z-index: 1; box-shadow: 0 1px 0 var(--border);
  }
  td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }
  .pill { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 11px; font-family: var(--mono); }
  .pill.ok { background: rgba(63,185,80,.15); color: var(--ok); }
  .pill.warn { background: rgba(210,153,34,.15); color: var(--warn); }
  .pill.err { background: rgba(248,81,73,.15); color: var(--err); }
  .chart { display: flex; align-items: flex-end; gap: 1px; height: 70px; padding-top: 4px; }
  .bar { flex: 1; background: var(--accent); opacity: .85; border-radius: 1px 1px 0 0; min-height: 1px; }
  .bar:hover { opacity: 1; }
  .ago { color: var(--muted); }
  .path { color: var(--fg); opacity: .9; max-width: 380px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .msg { color: var(--fg); opacity: .85; max-width: 320px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
  .msg.empty { color: var(--muted); font-style: italic; }
  .limit-bar {
    display: inline-block; width: 70px; height: 5px;
    background: var(--panel-2); border-radius: 3px; overflow: hidden;
    vertical-align: middle; margin-left: 6px;
  }
  .limit-bar > span { display: block; height: 100%; background: var(--ok); }
  .limit-bar > span.warn { background: var(--warn); }
  .limit-bar > span.err { background: var(--err); }
  /* Session-quota panel: one card per rolling window (5h / weekly). */
  .quota-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 12px; }
  .quota-win { background: var(--panel-2); border: 1px solid var(--border); border-radius: 8px; padding: 14px; }
  .quota-win .top { display: flex; align-items: baseline; justify-content: space-between; gap: 8px; margin-bottom: 8px; }
  .quota-win .name { font-size: 12px; text-transform: uppercase; letter-spacing: .04em; color: var(--muted); font-weight: 600; }
  .quota-win .name .rep { margin-left: 6px; color: var(--accent); font-size: 10px; }
  .quota-win .pct { font-family: var(--mono); font-size: 24px; font-weight: 600; line-height: 1; margin-bottom: 10px; }
  .quota-win .pct .unit { font-size: 13px; color: var(--muted); margin-left: 5px; }
  .quota-bar { height: 8px; background: var(--bg); border-radius: 5px; overflow: hidden; }
  .quota-bar > span { display: block; height: 100%; background: var(--ok); transition: width .4s ease; }
  .quota-bar > span.warn { background: var(--warn); }
  .quota-bar > span.err { background: var(--err); }
  .quota-win .foot { display: flex; align-items: baseline; justify-content: space-between; gap: 8px; margin-top: 8px; font-size: 12px; color: var(--muted); font-family: var(--mono); }
  .quota-raw { margin-top: 12px; }
  .quota-raw summary { cursor: pointer; font-size: 11px; text-transform: uppercase; letter-spacing: .04em; color: var(--muted); }
  .quota-raw table { margin-top: 8px; }
  .quota-raw td { font-size: 12px; word-break: break-all; }
  .toolbar { display: flex; align-items: center; gap: 12px; }
  select, button {
    background: var(--panel-2); color: var(--fg);
    border: 1px solid var(--border); border-radius: 6px;
    padding: 6px 10px; font-size: 13px; font-family: inherit;
    cursor: pointer;
  }
  button:hover, select:hover { border-color: var(--accent); }
  .empty { color: var(--muted); padding: 24px; text-align: center; font-style: italic; }
  button.primary { background: #1f6feb; border-color: #1f6feb; color: white; }
  button.primary:hover { background: #388bfd; border-color: #388bfd; }
  button.danger { background: transparent; color: var(--err); border-color: rgba(248,81,73,.4); }
  button.danger:hover { background: rgba(248,81,73,.1); border-color: var(--err); }
  .modal {
    position: fixed; inset: 0; background: rgba(0,0,0,.6);
    display: flex; align-items: center; justify-content: center; z-index: 100;
  }
  .modal-box {
    background: var(--panel); border: 1px solid var(--border); border-radius: 10px;
    padding: 24px; width: 420px; max-width: 92vw;
    max-height: 92vh; overflow-y: auto;
  }
  .modal-box.wide { width: 560px; }
  .modal-box h3 { margin: 0 0 4px; }
  .step-label { margin: 16px 0 6px !important; color: var(--fg) !important; font-size: 12px !important; font-family: inherit !important; text-transform: uppercase; letter-spacing: .04em; }
  .step-label .num { display: inline-block; min-width: 18px; height: 18px; line-height: 18px; text-align: center; background: var(--panel-2); border: 1px solid var(--border); border-radius: 4px; font-size: 11px; margin-right: 6px; }
  .cmd-table { display: grid; grid-template-columns: max-content 1fr; gap: 6px 14px; background: var(--bg); border: 1px solid var(--border); border-radius: 6px; padding: 10px 12px; font-size: 12px; }
  .cmd-table code { font-family: var(--mono); color: var(--accent); white-space: nowrap; }
  .cmd-table span { color: var(--muted); }
  .modal-box label { display: block; font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: .04em; margin: 14px 0 4px; }
  .modal-box input, .modal-box select {
    width: 100%; padding: 8px 10px; box-sizing: border-box;
    background: var(--bg); color: var(--fg);
    border: 1px solid var(--border); border-radius: 6px;
    font-size: 14px; font-family: inherit;
  }
  .modal-box input:focus, .modal-box select:focus { outline: none; border-color: var(--accent); }
  .error { background: rgba(248,81,73,.1); border: 1px solid rgba(248,81,73,.3); color: var(--err); padding: 8px 10px; border-radius: 6px; font-size: 13px; }
  .config-info { background: var(--panel-2); border: 1px solid var(--border); border-radius: 6px; padding: 8px 12px; font-size: 12px; color: var(--muted); font-family: var(--mono); }
  .snippet-block { position: relative; }
  .snippet-block pre {
    background: var(--bg); border: 1px solid var(--border); border-radius: 6px;
    padding: 10px 12px; font-family: var(--mono); font-size: 12px;
    color: var(--fg); margin: 0; overflow-x: auto; white-space: pre;
  }
  .copy-btn {
    position: absolute; top: 6px; right: 6px;
    padding: 4px 10px; font-size: 11px;
    background: var(--panel-2); color: var(--fg);
    border: 1px solid var(--border); border-radius: 4px; cursor: pointer;
  }
  .copy-btn:hover { border-color: var(--accent); color: var(--accent); }
  .copy-btn.copied { color: var(--ok); border-color: var(--ok); }

  /* Compact filter bar for the Recent requests table. Inputs share the same
     dark-panel styling as the toolbar selects but at a smaller, denser scale
     so a row of 5 filters + a count fits comfortably above the table. */
  .filter-bar {
    display: flex; flex-wrap: wrap; gap: 8px; align-items: center;
    margin-bottom: 12px;
  }
  .filter-bar input, .filter-bar select {
    background: var(--panel-2); color: var(--fg);
    border: 1px solid var(--border); border-radius: 6px;
    padding: 6px 10px; font-size: 12px; font-family: inherit;
  }
  .filter-bar input:focus, .filter-bar select:focus { outline: none; border-color: var(--accent); }
  .filter-bar input[type="search"] { flex: 1 1 220px; min-width: 180px; }
  .filter-bar select { min-width: 110px; }
  .filter-bar button { padding: 6px 10px; font-size: 12px; }
  .filter-bar .count {
    margin-left: auto; font-size: 11px; color: var(--muted);
    font-family: var(--mono); white-space: nowrap;
  }
  .filter-bar .count.active { color: var(--accent); }
</style>
</head>
<body>
<aside class="sidebar">
  <div class="brand">
    CC Gateway
    <span class="sub" data-i18n="admin.brand.sub">Request Dashboard</span>
  </div>
  <nav id="sideNav">
    <a href="#topStats" class="active"><span class="icon">▦</span><span data-i18n="admin.nav.overview">Overview</span></a>
    <a href="#quota"><span class="icon">◔</span><span data-i18n="admin.nav.quota">Session quota</span></a>
    <a href="#periods"><span class="icon">$</span><span data-i18n="admin.nav.periods">Cost &amp; periods</span></a>
    <a href="#charts"><span class="icon">∿</span><span data-i18n="admin.nav.traffic">Traffic</span></a>
    <a href="#models"><span class="icon">◇</span><span data-i18n="admin.nav.models">By model</span></a>
    <a href="#clients"><span class="icon">◎</span><span data-i18n="admin.nav.clients">Clients</span></a>
    <a href="#recent"><span class="icon">»</span><span data-i18n="admin.nav.recent">Recent requests</span></a>
    <a href="#install"><span class="icon">⤓</span><span data-i18n="admin.nav.install">Install guide</span></a>
    <a href="#about"><span class="icon">?</span><span data-i18n="admin.nav.about">How to use</span></a>
  </nav>
</aside>
<div class="content">
<header>
  <h1 id="pageTitle" data-i18n="admin.nav.overview">Overview</h1>
  <div class="toolbar">
    <span class="meta" id="updated" data-i18n="admin.toolbar.loading">loading…</span>
    <select id="rangeSel">
      <option value="minute" data-i18n="admin.range.minute">Last 60 min</option>
      <option value="hour" data-i18n="admin.range.hour">Last 24 h</option>
    </select>
    <button id="refreshBtn" data-i18n="admin.toolbar.refresh">Refresh</button>
    ${langSwitcher('padding:6px 10px')}
    <form action="/admin/logout" method="post">
      <button type="submit" data-i18n="common.logout">Logout</button>
    </form>
  </div>
</header>
<main>
  <div class="grid">
    <div id="oauthBanner" class="error" style="display:none;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:4px">
      <span id="oauthBannerMsg" style="flex:1;min-width:240px"></span>
      <button id="oauthBannerBtn" type="button" class="primary" data-i18n="admin.oauth.reloginBtn">Re-login with Claude</button>
    </div>
    <div class="row" id="topStats"></div>
    <section id="quota" class="card">
      <h2 data-i18n="admin.sec.quota">Session quota · Anthropic account</h2>
      <p class="meta" style="margin:-4px 0 12px" data-i18n="admin.quota.note">
        Live 5-hour rolling and weekly usage for the shared subscription account,
        read from Anthropic's response headers. This is the whole account's quota,
        shared across every client on this gateway.
      </p>
      <div id="quotaBody"></div>
      <h2 style="margin-top:18px" data-i18n="admin.sec.sessionModels">Models used this session (5h)</h2>
      <div id="sessionModelsTable"></div>
    </section>
    <section id="periods" class="card">
      <h2 data-i18n="admin.sec.periods">Cost &amp; usage by period</h2>
      <div id="periodTable"></div>
    </section>
    <section id="charts-section" class="card">
      <h2 data-i18n="admin.sec.charts">Requests over time (per client)</h2>
      <div id="charts" class="grid"></div>
    </section>
    <section id="models" class="card">
      <h2 data-i18n="admin.sec.models">By model</h2>
      <div id="modelsTable"></div>
    </section>
    <section id="clients" class="card">
      <h2>
        <span data-i18n="admin.sec.clients">Clients</span>
        <button id="addClientBtn" style="float:right;margin-top:-4px" data-i18n="admin.addClient">+ Add client</button>
      </h2>
      <div id="clientsConfig" style="margin-bottom:12px"></div>
      <div id="clientsTable"></div>
    </section>
    <section id="recent" class="card">
      <h2>
        <span data-i18n="admin.sec.recent">Recent requests</span>
        <span id="pauseHint" class="meta" style="float:right;font-weight:400;text-transform:none;letter-spacing:0;font-size:12px;color:var(--muted)"></span>
      </h2>
      <div id="recentFilters" class="filter-bar" style="display:none">
        <input id="rfSearch" type="search" data-i18n-ph="admin.recent.searchPh" placeholder="Search client / path / model / message…" autocomplete="off" />
        <select id="rfClient"><option value="" data-i18n="admin.recent.allClients">All clients</option></select>
        <select id="rfModel"><option value="" data-i18n="admin.recent.allModels">All models</option></select>
        <select id="rfStatus">
          <option value="" data-i18n="admin.recent.allStatus">All status</option>
          <option value="2xx" data-i18n="admin.recent.status2xx">2xx success</option>
          <option value="3xx" data-i18n="admin.recent.status3xx">3xx redirect</option>
          <option value="4xx" data-i18n="admin.recent.status4xx">4xx client error</option>
          <option value="5xx" data-i18n="admin.recent.status5xx">5xx server error</option>
        </select>
        <select id="rfMethod">
          <option value="" data-i18n="admin.recent.allMethods">All methods</option>
          <option>GET</option>
          <option>POST</option>
          <option>PUT</option>
          <option>DELETE</option>
        </select>
        <button id="rfClear" type="button" data-i18n="admin.recent.clear">Clear</button>
        <span id="rfCount" class="count"></span>
      </div>
      <div id="recentTable"></div>
    </section>
    <section id="install" class="card">
      <h2 data-i18n="admin.sec.install">Install guide</h2>
      <p class="meta" style="margin:0 0 12px" data-i18n="admin.install.reference">
        Reference copy of the steps shown in the "Client created" panel — kept on the page so you can
        review and copy them even after closing the modal. Pick a client and platform to fill in the exact file name.
      </p>
      <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:4px">
        <select id="igClient" style="min-width:160px"><option value="" data-i18n="admin.install.clientNamePh">&lt;client name&gt;</option></select>
        <select id="igPlatform" style="min-width:190px">
          <option value="unix" data-i18n="admin.modal.platform.unix">macOS / Linux (bash)</option>
          <option value="windows" data-i18n="admin.modal.platform.windows">Windows (PowerShell)</option>
        </select>
      </div>

      <p class="step-label" id="igStep1Label"><span class="num">1</span>macOS — if Gatekeeper blocks the file</p>
      <p class="meta" id="igStep1Meta" style="margin:0 0 6px"></p>
      <div class="snippet-block">
        <pre id="igUnblockCmd"></pre>
        <button id="igCopyUnblock" type="button" class="copy-btn" data-i18n="common.copy">Copy</button>
      </div>

      <p class="step-label"><span class="num">2</span><span data-i18n="admin.step.runTest">Run the launcher (quick test)</span></p>
      <p class="meta" id="igRunMeta" style="margin:0 0 6px"></p>
      <div class="snippet-block">
        <pre id="igRunCmd"></pre>
        <button id="igCopyRun" type="button" class="copy-btn" data-i18n="common.copy">Copy</button>
      </div>
      <p class="meta" style="margin:6px 0 0;color:var(--warn);font-size:12px" data-i18n-html="admin.step.warn">
        ⚠ On first run, Claude Code asks <em>"Do you want to use this custom API?"</em> with options <strong>Yes</strong> / <strong>No (recommended)</strong>. Choose <strong>Yes</strong> — picking <em>No (recommended)</em> drops the gateway env vars and Claude Code falls back to its native endpoint.
      </p>

      <p class="step-label"><span class="num">3</span><span data-i18n-html="admin.step.installSystem">Install system-wide as <code>ccg</code></span></p>
      <p class="meta" id="igInstallMeta" style="margin:0 0 6px"></p>
      <div class="snippet-block">
        <pre id="igInstallCmd"></pre>
        <button id="igCopyInstall" type="button" class="copy-btn" data-i18n="common.copy">Copy</button>
      </div>

      <p class="step-label"><span class="num">4</span><span data-i18n-html="admin.step.hijack">Hijack <code>claude</code> → gateway (optional)</span></p>
      <p class="meta" id="igHijackMeta" style="margin:0 0 6px"></p>
      <div class="snippet-block">
        <pre id="igHijackCmd">ccg hijack</pre>
        <button id="igCopyHijack" type="button" class="copy-btn" data-i18n="common.copy">Copy</button>
      </div>

      <p class="step-label"><span class="num">5</span><span data-i18n="admin.step.hijackGui">Hijack Claude Code in VS Code / Cursor (optional)</span></p>
      <p class="meta" style="margin:0 0 6px" data-i18n-html="admin.step.hijackGuiMeta">Persists gateway env vars at the user level so the Claude Code extension inside VS Code / Cursor also routes through this gateway. Restart the editor afterwards. Undo with <code>ccg release-gui</code>.</p>
      <div class="snippet-block">
        <pre id="igHijackGuiCmd">ccg hijack-gui</pre>
        <button id="igCopyHijackGui" type="button" class="copy-btn" data-i18n="common.copy">Copy</button>
      </div>

      <p class="step-label" data-i18n-html="admin.subcmds">All <code>ccg</code> subcommands</p>
      <div class="cmd-table">
        <code>ccg</code><span data-i18n="cmd.ccg">Start Claude Code through this gateway.</span>
        <code>ccg [claude args]</code><span data-i18n-html="cmd.ccgArgs">Forward any flags to Claude Code (e.g. <code>--model</code>, <code>--resume</code>).</span>
        <code>ccg --print "hi"</code><span data-i18n="cmd.ccgPrint">Single-shot non-interactive mode.</span>
        <code>ccg install</code><span data-i18n-html="cmd.install">Install this launcher as the <code>ccg</code> system command.</span>
        <code>ccg uninstall</code><span data-i18n-html="admin.cmd.uninstall">Remove <code>ccg</code> and undo any hijack alias.</span>
        <code>ccg hijack</code><span data-i18n-html="admin.cmd.hijack">Alias <code>claude</code> to <code>ccg</code> so the native CLI routes through the gateway.</span>
        <code>ccg release</code><span data-i18n-html="admin.cmd.release">Remove the alias — <code>claude</code> goes back to native.</span>
        <code>ccg hijack-gui</code><span data-i18n="admin.cmd.hijackGui">Persist gateway env vars so the VS Code / Cursor extension uses the gateway.</span>
        <code>ccg release-gui</code><span data-i18n="admin.cmd.releaseGui">Remove those env vars — the extension goes back to native.</span>
        <code>ccg native [args]</code><span data-i18n-html="admin.cmd.native">Run native <code>claude</code> once, bypassing the gateway (no permanent change).</span>
        <code>ccg status</code><span data-i18n="admin.cmd.status">Show the configured gateway URL, hijack state, and a health check.</span>
        <code>ccg help</code><span data-i18n="admin.cmd.help">Print the same command list inside the terminal.</span>
      </div>

      <p class="meta" style="margin:14px 0 0;font-size:12px" data-i18n-html="admin.install.prereqNote">
        Prerequisite: Claude Code installed (<code>npm install -g @anthropic-ai/claude-code</code>).
        The launcher only sets env vars for its own process — nothing is written to the user's shell config unless they run <code>ccg hijack</code>.
        Need a fresh launcher file? Use <strong>Re-download</strong> next to the client above.
      </p>
    </section>
    <details id="about" class="card">
      <summary style="cursor:pointer;font-weight:600;font-size:13px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em" data-i18n="admin.about.summary">
        How to use this dashboard
      </summary>
      <div style="margin-top:12px;font-size:13px;line-height:1.6;color:var(--fg)">
        <p style="margin:0 0 10px" data-i18n-html="admin.about.statsRow"><strong>Stats row</strong> — totals across the gateway's full history (persisted in SQLite): requests, accumulated cost (USD list price), tokens, active clients, errors, uptime.</p>
        <p style="margin:0 0 10px" data-i18n-html="admin.about.periods"><strong>Cost &amp; usage by period</strong> — same totals split by Today / Last 7d / Last 30d / All time so you can track spend trend.</p>
        <p style="margin:0 0 10px" data-i18n-html="admin.about.charts"><strong>Requests over time</strong> — per-client traffic. Toggle <em>Last 60 min</em> / <em>Last 24 h</em>.</p>
        <p style="margin:0 0 10px" data-i18n-html="admin.about.models"><strong>By model</strong> — per-model totals: calls, input/output/cache tokens, and cost. Cost uses Anthropic public list prices.</p>
        <p style="margin:0 0 10px" data-i18n-html="admin.about.clients"><strong>Clients</strong> — every entry under <code>auth.tokens</code>, with their lifetime calls / tokens / cost. Click <strong>+ Add client</strong> to generate a token, append it to <code>config.yaml</code>, and download a launcher script.</p>
        <p style="margin:0 0 10px" data-i18n-html="admin.about.recent"><strong>Recent requests</strong> — last 50 requests with model, tokens, cost, and duration. New rows stream in at the top; updates pause while you're hovering so the view doesn't jump.</p>
        <p style="margin:0" data-i18n-html="admin.about.platform">Pick a target platform — <strong>macOS / Linux</strong> downloads <code>cc-&lt;name&gt;</code> (bash), <strong>Windows</strong> downloads <code>cc-&lt;name&gt;.ps1</code> (PowerShell). The "Client created" panel shows OS-specific install steps to copy into a terminal.</p>
      </div>
    </details>
  </div>
</main>
</div>

<div id="oauthModal" class="modal" style="display:none">
  <div class="modal-box">
    <h3 data-i18n="admin.modal.oauth.title">Re-login with Claude</h3>
    <p class="meta" style="margin:0 0 16px" data-i18n-html="admin.modal.oauth.note">Re-authenticates the gateway's shared Claude account.</p>

    <label data-i18n="admin.modal.oauth.step1">1. Open the Claude sign-in page</label>
    <p class="meta" style="margin:0 0 8px;font-size:12px" data-i18n="admin.modal.oauth.step1note">Sign in with the account this gateway proxies, then approve access.</p>
    <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
      <button id="oaLink" type="button" data-i18n="admin.modal.oauth.openLink">Generate sign-in link</button>
      <a id="oaOpen" href="#" target="_blank" rel="noopener noreferrer" style="display:none;color:var(--accent);font-size:13px" data-i18n="admin.modal.oauth.openTab">Open sign-in page ↗</a>
    </div>

    <label style="margin-top:16px" data-i18n="admin.modal.oauth.step2">2. Paste the authorization code</label>
    <p class="meta" style="margin:0 0 8px;font-size:12px" data-i18n-html="admin.modal.oauth.step2note">Claude shows a code after you approve.</p>
    <input id="oaCode" placeholder="Paste the code from Claude" data-i18n-ph="admin.modal.oauth.codePh" autocomplete="off" spellcheck="false" />

    <div id="oaError" class="error" style="display:none;margin-top:12px"></div>
    <div id="oaOk" class="meta" style="display:none;margin-top:12px;color:var(--ok)"></div>
    <div style="display:flex;gap:8px;margin-top:18px;justify-content:flex-end">
      <button id="oaCancel" type="button" data-i18n="common.cancel">Cancel</button>
      <button id="oaSubmit" type="button" class="primary" data-i18n="admin.modal.oauth.submit">Finish sign-in</button>
    </div>
  </div>
</div>

<div id="addClientModal" class="modal" style="display:none">
  <div class="modal-box">
    <div id="modalForm">
      <h3 data-i18n="admin.modal.addClient.title">Add client</h3>
      <p class="meta" style="margin:0 0 16px" data-i18n-html="admin.modal.addClient.note">Generates a token, appends it to <code>config.yaml</code>, and downloads a launcher script.</p>
      <label data-i18n="admin.modal.addClient.name">Client name</label>
      <input id="cName" placeholder="e.g. vuluu2k" data-i18n-ph="admin.modal.addClient.namePh" autocomplete="off" />
      <label data-i18n="admin.modal.gatewayAddr">Gateway address</label>
      <input id="cAddr" placeholder="ccg.example.com" data-i18n-ph="admin.modal.gatewayAddrPh" autocomplete="off" />
      <label data-i18n="admin.modal.scheme">Scheme</label>
      <select id="cScheme">
        <option value="https">https</option>
        <option value="http">http</option>
      </select>
      <label data-i18n="admin.modal.platform">Target platform</label>
      <select id="cPlatform">
        <option value="unix" data-i18n="admin.modal.platform.unix">macOS / Linux (bash)</option>
        <option value="windows" data-i18n="admin.modal.platform.windows">Windows (PowerShell)</option>
      </select>
      <label data-i18n="admin.modal.costLimit.optional">Cost limit (USD) — optional, 0 = unlimited</label>
      <input id="cLimit" type="number" min="0" step="0.01" placeholder="0" autocomplete="off" />
      <label data-i18n="admin.modal.limitWindow">Limit window</label>
      <select id="cLimitPeriod">
        <option value="lifetime" data-i18n="admin.modal.period.lifetime">Lifetime</option>
        <option value="monthly" data-i18n="admin.modal.period.monthly">Monthly (UTC)</option>
        <option value="daily" data-i18n="admin.modal.period.daily">Daily (UTC)</option>
      </select>
      <div id="cError" class="error" style="display:none;margin-top:12px"></div>
      <div style="display:flex;gap:8px;margin-top:18px;justify-content:flex-end">
        <button id="cCancel" type="button" data-i18n="common.cancel">Cancel</button>
        <button id="cSubmit" type="button" class="primary" data-i18n="admin.modal.createDownload">Create &amp; download</button>
      </div>
    </div>

    <div id="modalSuccess" style="display:none">
      <h3><span data-i18n="admin.success.title">Client created</span> · <span id="successName"></span></h3>
      <p class="meta" style="margin:0 0 4px"><span data-i18n="admin.success.fileLabel">File</span> <code id="successFile"></code> <span data-i18n="admin.success.fileNote">has been downloaded. Send it to the user and follow the steps below.</span></p>

      <div style="background:var(--panel-2);border:1px solid var(--border);border-radius:8px;padding:12px 14px;margin:12px 0 4px">
        <div style="font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);margin-bottom:8px" data-i18n="admin.success.portalH">Client portal login — share these with the client</div>
        <div class="cmd-table" style="background:var(--bg)">
          <code data-i18n="admin.success.portal">Portal</code><span><a id="portalUrl" href="/portal" target="_blank" style="color:var(--accent)">/portal</a></span>
          <code data-i18n="admin.success.name">Name</code><span id="portalLoginName"></span>
          <code data-i18n="admin.success.password">Password</code><span><code id="portalPassword" style="color:var(--ok)"></code></span>
        </div>
        <p class="meta" style="margin:8px 0 0;font-size:11px" data-i18n-html="admin.success.pwNote">Shown once. The client can change it after first login. Lost it? Use <strong>Reset password</strong> on the client row.</p>
      </div>

      <p class="step-label" id="step1Label"><span class="num">1</span>macOS — if Gatekeeper blocks the file</p>
      <p class="meta" id="step1Meta" style="margin:0 0 6px">Removes the quarantine attribute Safari/Chrome adds to downloads. Skip on Linux, or if the launcher runs without warning.</p>
      <div class="snippet-block">
        <pre id="xattrCmd"></pre>
        <button id="copyXattrBtn" type="button" class="copy-btn" data-i18n="common.copy">Copy</button>
      </div>

      <p class="step-label"><span class="num">2</span><span data-i18n="admin.step.runTest">Run the launcher (quick test)</span></p>
      <p class="meta" id="step2Meta" style="margin:0 0 6px">Make it executable and start Claude Code through the gateway.</p>
      <div class="snippet-block">
        <pre id="successCmd"></pre>
        <button id="copyCmdBtn" type="button" class="copy-btn" data-i18n="common.copy">Copy</button>
      </div>
      <p class="meta" style="margin:6px 0 0;color:var(--warn);font-size:12px" data-i18n-html="admin.step.warn">
        ⚠ On first run, Claude Code asks <em>"Do you want to use this custom API?"</em> with options <strong>Yes</strong> / <strong>No (recommended)</strong>. Choose <strong>Yes</strong> — picking <em>No (recommended)</em> drops the gateway env vars and Claude Code falls back to its native endpoint.
      </p>

      <p class="step-label"><span class="num">3</span><span data-i18n-html="admin.step.installSystem">Install system-wide as <code>ccg</code></span></p>
      <p class="meta" id="step3Meta" style="margin:0 0 6px">Copies the launcher into <code>$PATH</code> so it can be invoked from anywhere.</p>
      <div class="snippet-block">
        <pre id="installCmd"></pre>
        <button id="copyInstallBtn" type="button" class="copy-btn" data-i18n="common.copy">Copy</button>
      </div>

      <p class="step-label"><span class="num">4</span><span data-i18n-html="admin.step.hijack">Hijack <code>claude</code> → gateway (optional)</span></p>
      <p class="meta" id="step4Meta" style="margin:0 0 6px">Aliases the native <code>claude</code> command so every invocation routes through this gateway. New terminals pick it up automatically; reopen the current one or <code>source</code> the shell rc. Undo any time with <code>ccg release</code>.</p>
      <div class="snippet-block">
        <pre id="hijackCmd">ccg hijack</pre>
        <button id="copyHijackBtn" type="button" class="copy-btn" data-i18n="common.copy">Copy</button>
      </div>

      <p class="step-label"><span class="num">5</span><span data-i18n="admin.step.hijackGui">Hijack Claude Code in VS Code / Cursor (optional)</span></p>
      <p class="meta" id="step5Meta" style="margin:0 0 6px" data-i18n-html="admin.step.hijackGuiMeta">Persists gateway env vars at the user level so the Claude Code extension inside VS Code / Cursor also routes through this gateway. Restart the editor afterwards. Undo with <code>ccg release-gui</code>.</p>
      <div class="snippet-block">
        <pre id="hijackGuiCmd">ccg hijack-gui</pre>
        <button id="copyHijackGuiBtn" type="button" class="copy-btn" data-i18n="common.copy">Copy</button>
      </div>

      <p class="step-label" data-i18n-html="admin.subcmds">All <code>ccg</code> subcommands</p>
      <div class="cmd-table">
        <code>ccg</code><span data-i18n="cmd.ccg">Start Claude Code through this gateway.</span>
        <code>ccg [claude args]</code><span data-i18n-html="cmd.ccgArgs">Forward any flags to Claude Code (e.g. <code>--model</code>, <code>--resume</code>).</span>
        <code>ccg --print "hi"</code><span data-i18n="cmd.ccgPrint">Single-shot non-interactive mode.</span>
        <code>ccg install</code><span data-i18n-html="cmd.install">Install this launcher as the <code>ccg</code> system command.</span>
        <code>ccg uninstall</code><span data-i18n-html="admin.cmd.uninstall">Remove <code>ccg</code> and undo any hijack alias.</span>
        <code>ccg hijack</code><span data-i18n-html="admin.cmd.hijack">Alias <code>claude</code> to <code>ccg</code> so the native CLI routes through the gateway.</span>
        <code>ccg release</code><span data-i18n-html="admin.cmd.release">Remove the alias — <code>claude</code> goes back to native.</span>
        <code>ccg hijack-gui</code><span data-i18n="admin.cmd.hijackGui">Persist gateway env vars so the VS Code / Cursor extension uses the gateway.</span>
        <code>ccg release-gui</code><span data-i18n="admin.cmd.releaseGui">Remove those env vars — the extension goes back to native.</span>
        <code>ccg native [args]</code><span data-i18n-html="admin.cmd.native">Run native <code>claude</code> once, bypassing the gateway (no permanent change).</span>
        <code>ccg status</code><span data-i18n="admin.cmd.status">Show the configured gateway URL, hijack state, and a health check.</span>
        <code>ccg help</code><span data-i18n="admin.cmd.help">Print the same command list inside the terminal.</span>
      </div>

      <p class="meta" style="margin:14px 0 0;font-size:12px" data-i18n-html="admin.prereqNote">
        Prerequisite: Claude Code installed (<code>npm install -g @anthropic-ai/claude-code</code>).
        The launcher only sets env vars for its own process — nothing is written to the user's shell config unless they run <code>ccg hijack</code>.
      </p>
      <div style="display:flex;gap:8px;margin-top:18px;justify-content:flex-end">
        <button id="successDone" type="button" class="primary" data-i18n="common.done">Done</button>
      </div>
    </div>
  </div>
</div>

<div id="regenModal" class="modal" style="display:none">
  <div class="modal-box">
    <h3><span data-i18n="admin.modal.regen.title">Re-download launcher</span> · <span id="regenName"></span></h3>
    <p class="meta" style="margin:0 0 16px" data-i18n-html="admin.modal.regen.note">Generates a fresh launcher file using the existing token. Token, billing, and cost limit are <strong>not</strong> changed — use this to ship updates (e.g. <code>ccg hijack-gui</code>) to existing clients.</p>
    <label data-i18n="admin.modal.gatewayAddr">Gateway address</label>
    <input id="rAddr" placeholder="ccg.example.com" data-i18n-ph="admin.modal.gatewayAddrPh" autocomplete="off" />
    <label data-i18n="admin.modal.scheme">Scheme</label>
    <select id="rScheme">
      <option value="https">https</option>
      <option value="http">http</option>
    </select>
    <label data-i18n="admin.modal.platform">Target platform</label>
    <select id="rPlatform">
      <option value="unix" data-i18n="admin.modal.platform.unix">macOS / Linux (bash)</option>
      <option value="windows" data-i18n="admin.modal.platform.windows">Windows (PowerShell)</option>
    </select>
    <div id="rError" class="error" style="display:none;margin-top:12px"></div>
    <div style="display:flex;gap:8px;margin-top:18px;justify-content:flex-end">
      <button id="rCancel" type="button" data-i18n="common.cancel">Cancel</button>
      <button id="rSubmit" type="button" class="primary" data-i18n="admin.modal.download">Download</button>
    </div>
  </div>
</div>

<div id="limitModal" class="modal" style="display:none">
  <div class="modal-box">
    <h3><span data-i18n="admin.modal.limit.title">Set cost limit</span> · <span id="limitName"></span></h3>
    <p class="meta" style="margin:0 0 16px" data-i18n-html="admin.modal.limit.note">Block this client from <code>/v1/messages</code> when the window's cost reaches the limit. Other endpoints (free) keep working.</p>
    <label data-i18n="admin.modal.limit.costLimit">Cost limit (USD) — 0 / empty = unlimited</label>
    <input id="lLimit" type="number" min="0" step="0.01" placeholder="0" autocomplete="off" />
    <label data-i18n="admin.modal.window">Window</label>
    <select id="lPeriod">
      <option value="lifetime" data-i18n="admin.modal.period.lifetime">Lifetime</option>
      <option value="monthly" data-i18n="admin.modal.period.monthly">Monthly (UTC)</option>
      <option value="daily" data-i18n="admin.modal.period.daily">Daily (UTC)</option>
    </select>
    <div id="lError" class="error" style="display:none;margin-top:12px"></div>
    <div style="display:flex;gap:8px;margin-top:18px;justify-content:flex-end">
      <button id="lCancel" type="button" data-i18n="common.cancel">Cancel</button>
      <button id="lSubmit" type="button" class="primary" data-i18n="common.save">Save</button>
    </div>
  </div>
</div>

<div id="workdirModal" class="modal" style="display:none">
  <div class="modal-box">
    <h3><span data-i18n="admin.modal.workdir.title">Set client workdir</span> · <span id="workdirName"></span></h3>
    <p class="meta" style="margin:0 0 12px" data-i18n-html="admin.modal.workdir.note">This client's <strong>real home folder</strong>. The gateway maps the masked canonical path back to it in Claude's replies, so bash/file tool calls hit real paths. Leave empty to auto-detect from each request.</p>
    <label data-i18n="admin.modal.workdir.label">Home directory</label>
    <input id="wDir" placeholder="/Users/alice" data-i18n-ph="admin.modal.workdir.ph" autocomplete="off" spellcheck="false" />
    <div class="cmd-table" style="margin-top:10px">
      <code>macOS</code><span>/Users/&lt;name&gt;</span>
      <code>Linux</code><span>/home/&lt;name&gt;</span>
      <code>Windows</code><span>C:\\Users\\&lt;name&gt;</span>
    </div>
    <p class="meta" style="margin:8px 0 0;font-size:11px" data-i18n="admin.modal.workdir.hint">Tip: on the client machine run <code>echo $HOME</code> (macOS/Linux) or <code>echo %USERPROFILE%</code> (Windows) and paste the result.</p>
    <div id="wError" class="error" style="display:none;margin-top:12px"></div>
    <div style="display:flex;gap:8px;margin-top:18px;justify-content:flex-end">
      <button id="wCancel" type="button" data-i18n="common.cancel">Cancel</button>
      <button id="wSubmit" type="button" class="primary" data-i18n="common.save">Save</button>
    </div>
  </div>
</div>

<div id="pwResetModal" class="modal" style="display:none">
  <div class="modal-box">
    <h3><span data-i18n="admin.modal.pwReset.title">Password reset</span> · <span id="pwResetName"></span></h3>
    <p class="meta" style="margin:0 0 12px" data-i18n="admin.modal.pwReset.note">New portal password — copy it now, it won't be shown again. The client can change it after logging in.</p>
    <div class="snippet-block">
      <pre id="pwResetValue"></pre>
      <button id="pwResetCopy" type="button" class="copy-btn" data-i18n="common.copy">Copy</button>
    </div>
    <div style="display:flex;gap:8px;margin-top:18px;justify-content:flex-end">
      <button id="pwResetDone" type="button" class="primary" data-i18n="common.done">Done</button>
    </div>
  </div>
</div>
<script>
(() => {
  const t = (k, v) => (window.t ? window.t(k, v) : k);
  const range = () => document.getElementById('rangeSel').value;

  const esc = (s) => String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  const fmtNum = (n) => (n || 0).toLocaleString();
  const fmtTokens = (n) => {
    n = n || 0;
    if (n < 1000) return String(n);
    if (n < 1_000_000) return (n / 1000).toFixed(1).replace(/\\.0$/, '') + 'k';
    return (n / 1_000_000).toFixed(2).replace(/\\.00$/, '') + 'M';
  };
  const fmtCost = (n) => {
    n = n || 0;
    if (n === 0) return '$0';
    if (n < 0.01) return '$' + n.toFixed(4);
    if (n < 100) return '$' + n.toFixed(2);
    return '$' + Math.round(n).toLocaleString();
  };
  const shortModel = (m) => {
    if (!m) return '—';
    return m.replace(/^claude-/, '').replace(/-\\d{8}$/, '');
  };
  const fmtAgo = (ts) => {
    const d = Math.max(0, Date.now() - ts);
    if (d < 1000) return 'just now';
    if (d < 60_000) return Math.floor(d / 1000) + 's ago';
    if (d < 3_600_000) return Math.floor(d / 60_000) + 'm ago';
    if (d < 86_400_000) return Math.floor(d / 3_600_000) + 'h ago';
    return Math.floor(d / 86_400_000) + 'd ago';
  };
  const fmtUptime = (ms) => {
    const s = Math.floor(ms / 1000);
    const d = Math.floor(s / 86400);
    const h = Math.floor((s % 86400) / 3600);
    const m = Math.floor((s % 3600) / 60);
    if (d) return d + 'd ' + h + 'h';
    if (h) return h + 'h ' + m + 'm';
    return m + 'm';
  };
  const statusClass = (status) => {
    const ok = (status['2xx'] || 0) + (status['3xx'] || 0);
    const warn = status['4xx'] || 0;
    const err = status['5xx'] || 0;
    return { ok, warn, err };
  };

  const renderTopStats = (data) => {
    const tot = data.totals;
    const errRate = tot.total ? ((tot.errors / tot.total) * 100).toFixed(1) : '0.0';
    const html = [
      [t('admin.stat.totalRequests'), fmtNum(tot.total)],
      [t('admin.stat.totalCost'), fmtCost(tot.costUsd)],
      [t('admin.stat.input'), fmtTokens(tot.inputTokens)],
      [t('admin.stat.output'), fmtTokens(tot.outputTokens)],
      [t('admin.stat.cacheRead'), fmtTokens(tot.cacheReadTokens)],
      [t('admin.stat.cacheWrite'), fmtTokens(tot.cacheCreationTokens)],
      [t('admin.stat.activeClients'), fmtNum(data.clients.length)],
      [t('admin.stat.errors'), fmtNum(tot.errors) + ' (' + errRate + '%)'],
      [t('admin.stat.uptime'), fmtUptime(data.uptimeMs)],
    ].map(([label, value]) => \`
      <div class="card stat">
        <div class="value">\${value}</div>
        <div class="label">\${label}</div>
      </div>\`).join('');
    document.getElementById('topStats').innerHTML = html;
  };

  const renderPeriods = (data) => {
    const tot = data.totals;
    const periods = (data.periods || []).concat([{
      key: 'all', label: t('admin.period.allTime'),
      total: tot.total,
      inputTokens: tot.inputTokens,
      outputTokens: tot.outputTokens,
      cacheReadTokens: tot.cacheReadTokens,
      cacheCreationTokens: tot.cacheCreationTokens,
      costUsd: tot.costUsd,
    }]);
    const rows = periods.map(p => \`<tr>
      <td data-label=""><strong>\${p.label}</strong></td>
      <td class="num" data-label="\${esc(t('th.calls'))}">\${fmtNum(p.total)}</td>
      <td class="num" data-label="\${esc(t('th.input'))}" title="\${fmtNum(p.inputTokens)} tokens">\${fmtTokens(p.inputTokens)}</td>
      <td class="num" data-label="\${esc(t('th.output'))}" title="\${fmtNum(p.outputTokens)} tokens">\${fmtTokens(p.outputTokens)}</td>
      <td class="num" data-label="\${esc(t('th.cache'))}" title="cache read \${fmtNum(p.cacheReadTokens)} · cache write \${fmtNum(p.cacheCreationTokens)}">\${fmtTokens((p.cacheReadTokens || 0) + (p.cacheCreationTokens || 0))}</td>
      <td class="num" data-label="\${esc(t('th.cost'))}"><strong>\${fmtCost(p.costUsd)}</strong></td>
    </tr>\`).join('');
    document.getElementById('periodTable').innerHTML = \`
      <table>
        <thead><tr>
          <th>\${esc(t('th.period'))}</th>
          <th class="num">\${esc(t('th.calls'))}</th>
          <th class="num">\${esc(t('th.input'))}</th>
          <th class="num">\${esc(t('th.output'))}</th>
          <th class="num">\${esc(t('th.cache'))}</th>
          <th class="num">\${esc(t('th.cost'))}</th>
        </tr></thead>
        <tbody>\${rows}</tbody>
      </table>\`;
  };

  const renderModels = (data) => {
    const el = document.getElementById('modelsTable');
    if (!data.models || !data.models.length) {
      el.innerHTML = '<div class="empty">' + esc(t('admin.empty.noModels')) + '</div>';
      return;
    }
    const rows = data.models.map(m => \`<tr>
      <td data-label=""><strong>\${shortModel(m.model)}</strong></td>
      <td class="num" data-label="\${esc(t('th.calls'))}">\${fmtNum(m.total)}</td>
      <td class="num" data-label="\${esc(t('th.input'))}">\${fmtTokens(m.inputTokens)}</td>
      <td class="num" data-label="\${esc(t('th.output'))}">\${fmtTokens(m.outputTokens)}</td>
      <td class="num" data-label="\${esc(t('admin.stat.cacheRead'))}">\${fmtTokens(m.cacheReadTokens)}</td>
      <td class="num" data-label="\${esc(t('admin.stat.cacheWrite'))}">\${fmtTokens(m.cacheCreationTokens)}</td>
      <td class="num" data-label="\${esc(t('th.cost'))}"><strong>\${fmtCost(m.costUsd)}</strong></td>
    </tr>\`).join('');
    el.innerHTML = \`
      <table>
        <thead><tr>
          <th>\${esc(t('th.model'))}</th>
          <th class="num">\${esc(t('th.calls'))}</th>
          <th class="num">\${esc(t('th.input'))}</th>
          <th class="num">\${esc(t('th.output'))}</th>
          <th class="num">\${esc(t('admin.stat.cacheRead'))}</th>
          <th class="num">\${esc(t('admin.stat.cacheWrite'))}</th>
          <th class="num">\${esc(t('th.cost'))}</th>
        </tr></thead>
        <tbody>\${rows}</tbody>
      </table>\`;
  };

  // ── Session quota (Anthropic account 5h + weekly windows) ──
  const statusPill = (status) => {
    const s = String(status || '').toLowerCase();
    if (!s) return '';
    if (s.includes('reject') || s.includes('limit') || s.includes('exceed')) return 'err';
    if (s.includes('warn')) return 'warn';
    return 'ok';
  };
  const fmtCountdown = (resetMs) => {
    const d = resetMs - Date.now();
    if (d <= 0) return t('admin.quota.resetting');
    const s = Math.floor(d / 1000);
    const days = Math.floor(s / 86400);
    const h = Math.floor((s % 86400) / 3600);
    const m = Math.floor((s % 3600) / 60);
    const sec = s % 60;
    if (days) return days + 'd ' + h + 'h ' + m + 'm';
    if (h) return h + 'h ' + m + 'm';
    if (m) return m + 'm ' + sec + 's';
    return sec + 's';
  };

  const renderQuota = (data) => {
    const host = document.getElementById('quotaBody');
    const q = data.quota;
    if (!q || !q.windows || !q.windows.length) {
      host.innerHTML = '<div class="empty">' + esc(t('admin.quota.none')) + '</div>';
      return;
    }
    const winLabel = { '5h': t('admin.quota.win5h'), '7d': t('admin.quota.win7d') };
    const repKey = q.representative === 'seven_day' ? '7d'
      : q.representative === 'five_hour' ? '5h' : '';
    const cards = q.windows.map(w => {
      const hasPct = w.usedPct != null;
      const pct = hasPct ? Math.round(w.usedPct) : null;
      const barCls = !hasPct ? '' : pct >= 90 ? 'err' : pct >= 75 ? 'warn' : '';
      const rep = repKey && w.key === repKey
        ? '<span class="rep">● ' + esc(t('admin.quota.rep')) + '</span>' : '';
      const pctBlock = hasPct
        ? '<div class="pct">' + pct + '<span class="unit">% ' + esc(t('admin.quota.usedWord')) + '</span></div>'
        : '<div class="pct" style="font-size:15px">' + esc(w.status || '—') + '</div>';
      const bar = hasPct
        ? '<div class="quota-bar"><span class="' + barCls + '" style="width:' + pct + '%"></span></div>'
        : '';
      const leftTxt = hasPct ? t('admin.quota.leftLabel', { pct: Math.max(0, 100 - pct) }) : '';
      const resetTxt = w.resetMs
        ? '<span class="reset" data-reset="' + w.resetMs + '">'
          + esc(t('admin.quota.resetIn', { t: fmtCountdown(w.resetMs) })) + '</span>'
        : '';
      return \`
        <div class="quota-win">
          <div class="top">
            <span class="name">\${esc(winLabel[w.key] || w.key)}\${rep}</span>
            \${w.status ? '<span class="pill ' + statusPill(w.status) + '">' + esc(w.status) + '</span>' : ''}
          </div>
          \${pctBlock}
          \${bar}
          <div class="foot"><span>\${esc(leftTxt)}</span>\${resetTxt}</div>
        </div>\`;
    }).join('');
    const rawRows = Object.keys(q.raw || {}).sort().map(k =>
      '<tr><td>' + esc(k) + '</td><td class="num">' + esc(q.raw[k]) + '</td></tr>').join('');
    const raw = rawRows
      ? \`<details class="quota-raw"><summary>\${esc(t('admin.quota.rawSummary'))}</summary>
          <table><tbody>\${rawRows}</tbody></table></details>\`
      : '';
    host.innerHTML = '<div class="quota-grid">' + cards + '</div>' + raw;
  };

  const tickQuotaResets = () => {
    document.querySelectorAll('#quotaBody .reset[data-reset]').forEach(el => {
      const rm = Number(el.getAttribute('data-reset'));
      if (Number.isFinite(rm)) el.textContent = t('admin.quota.resetIn', { t: fmtCountdown(rm) });
    });
  };

  const renderSessionModels = (data) => {
    const el = document.getElementById('sessionModelsTable');
    if (!data.sessionModels || !data.sessionModels.length) {
      el.innerHTML = '<div class="empty">' + esc(t('admin.empty.noSessionModels')) + '</div>';
      return;
    }
    const rows = data.sessionModels.map(m => \`<tr>
      <td data-label=""><strong>\${shortModel(m.model)}</strong></td>
      <td class="num" data-label="\${esc(t('th.calls'))}">\${fmtNum(m.total)}</td>
      <td class="num" data-label="\${esc(t('th.input'))}">\${fmtTokens(m.inputTokens)}</td>
      <td class="num" data-label="\${esc(t('th.output'))}">\${fmtTokens(m.outputTokens)}</td>
      <td class="num" data-label="\${esc(t('admin.stat.cacheRead'))}">\${fmtTokens(m.cacheReadTokens)}</td>
      <td class="num" data-label="\${esc(t('admin.stat.cacheWrite'))}">\${fmtTokens(m.cacheCreationTokens)}</td>
      <td class="num" data-label="\${esc(t('th.cost'))}"><strong>\${fmtCost(m.costUsd)}</strong></td>
    </tr>\`).join('');
    el.innerHTML = \`
      <table>
        <thead><tr>
          <th>\${esc(t('th.model'))}</th>
          <th class="num">\${esc(t('th.calls'))}</th>
          <th class="num">\${esc(t('th.input'))}</th>
          <th class="num">\${esc(t('th.output'))}</th>
          <th class="num">\${esc(t('admin.stat.cacheRead'))}</th>
          <th class="num">\${esc(t('admin.stat.cacheWrite'))}</th>
          <th class="num">\${esc(t('th.cost'))}</th>
        </tr></thead>
        <tbody>\${rows}</tbody>
      </table>\`;
  };

  const renderCharts = (data) => {
    const series = range() === 'hour' ? data.hourSeries : data.minuteSeries;
    const unit = range() === 'hour' ? 'h' : 'm';
    const clients = Object.keys(series);
    if (!clients.length) {
      document.getElementById('charts').innerHTML = '<div class="empty">' + esc(t('admin.empty.noTraffic')) + '</div>';
      return;
    }
    const max = Math.max(1, ...clients.flatMap(c => series[c].map(b => b.count)));
    document.getElementById('charts').innerHTML = clients.map(c => {
      const points = series[c];
      const total = points.reduce((s, p) => s + p.count, 0);
      const bars = points.map(p => {
        const h = Math.round((p.count / max) * 100);
        return \`<div class="bar" style="height:\${Math.max(1, h)}%" title="\${new Date(p.ts).toLocaleString()} — \${p.count} req"></div>\`;
      }).join('');
      return \`
        <div>
          <div style="display:flex;justify-content:space-between;align-items:baseline;margin-bottom:4px">
            <strong>\${c}</strong>
            <span class="meta">\${esc(t('admin.charts.reqUnit', { total: total, n: points.length, unit: unit }))}</span>
          </div>
          <div class="chart">\${bars}</div>
        </div>\`;
    }).join('');
  };

  const renderClients = (data) => {
    if (!data.clients.length) {
      document.getElementById('clientsTable').innerHTML = '<div class="empty">' + esc(t('admin.empty.noClientsCalled')) + '</div>';
      return;
    }
    const rows = data.clients.map(c => {
      const s = statusClass(c.byStatus);
      return \`<tr>
        <td data-label=""><strong>\${c.name}</strong></td>
        <td class="num" data-label="\${esc(t('th.calls'))}">\${fmtNum(c.total)}</td>
        <td class="num" data-label="\${esc(t('th.input'))}" title="\${fmtNum(c.inputTokens)} tokens">\${fmtTokens(c.inputTokens)}</td>
        <td class="num" data-label="\${esc(t('th.output'))}" title="\${fmtNum(c.outputTokens)} tokens">\${fmtTokens(c.outputTokens)}</td>
        <td class="num" data-label="\${esc(t('th.cache'))}" title="cache read \${fmtNum(c.cacheReadTokens)} · cache write \${fmtNum(c.cacheCreationTokens)}">\${fmtTokens((c.cacheReadTokens || 0) + (c.cacheCreationTokens || 0))}</td>
        <td class="num" data-label="\${esc(t('th.cost'))}"><strong>\${fmtCost(c.costUsd)}</strong></td>
        <td data-label="\${esc(t('th.statusGroup'))}"><span class="pill ok">\${s.ok}</span> <span class="pill warn">\${s.warn}</span> <span class="pill err">\${s.err}</span></td>
        <td class="num" data-label="\${esc(t('th.avg'))}">\${c.avgDurationMs}ms</td>
        <td class="ago" data-label="\${esc(t('th.lastSeen'))}">\${fmtAgo(c.lastSeen)}</td>
      </tr>\`;
    }).join('');
    document.getElementById('clientsTable').innerHTML = \`
      <table>
        <thead><tr>
          <th>\${esc(t('th.client'))}</th>
          <th class="num">\${esc(t('th.calls'))}</th>
          <th class="num" title="\${esc(t('admin.tip.inputTokens'))}">\${esc(t('th.input'))}</th>
          <th class="num" title="\${esc(t('admin.tip.outputTokens'))}">\${esc(t('th.output'))}</th>
          <th class="num" title="\${esc(t('admin.tip.cacheTokens'))}">\${esc(t('th.cache'))}</th>
          <th class="num">\${esc(t('th.cost'))}</th>
          <th>\${esc(t('th.statusGroup'))}</th>
          <th class="num">\${esc(t('th.avg'))}</th>
          <th>\${esc(t('th.lastSeen'))}</th>
        </tr></thead>
        <tbody>\${rows}</tbody>
      </table>\`;
  };

  const RECENT_TABLE_HTML = \`
    <div class="scroll-y" id="recentScroll">
      <table>
        <thead><tr>
          <th>\${esc(t('th.when'))}</th>
          <th>\${esc(t('th.client'))}</th>
          <th>\${esc(t('th.model'))}</th>
          <th>\${esc(t('th.message'))}</th>
          <th>\${esc(t('th.path'))}</th>
          <th>\${esc(t('th.status'))}</th>
          <th>\${esc(t('th.errorSource'))}</th>
          <th class="num">\${esc(t('th.duration'))}</th>
          <th class="num">\${esc(t('th.input'))}</th>
          <th class="num">\${esc(t('th.output'))}</th>
          <th class="num">\${esc(t('th.cache'))}</th>
          <th class="num">\${esc(t('th.cost'))}</th>
        </tr></thead>
        <tbody id="recentBody"></tbody>
      </table>
    </div>\`;

  const buildRecentRow = (r) => {
    const cls = r.status >= 500 ? 'err' : r.status >= 400 ? 'warn' : 'ok';
    const hasUsage = (r.inputTokens || r.outputTokens || r.cacheReadTokens || r.cacheCreationTokens);
    const msg = r.userMessage || '';
    const msgCell = msg
      ? \`<td class="msg" data-label="\${esc(t('th.message'))}" title="\${esc(msg)}">\${esc(msg)}</td>\`
      : '<td class="msg empty" data-label="' + esc(t('th.message')) + '">—</td>';
    // Error origin: 'gateway' = response generated by this proxy (auth, cost
    // limit, oauth, unreachable upstream), 'upstream' = relayed from the Claude
    // API. Hover shows the decoded error payload.
    const srcCell = r.errorSource
      ? \`<td data-label="\${esc(t('th.errorSource'))}" title="\${esc(r.errorDetail || '')}"><span class="pill \${r.errorSource === 'gateway' ? 'warn' : 'err'}">\${esc(r.errorSource)}</span></td>\`
      : '<td class="empty" data-label="' + esc(t('th.errorSource')) + '">—</td>';
    const tr = document.createElement('tr');
    tr.dataset.ts = String(r.ts);
    tr.innerHTML = \`
      <td class="ago" data-ts="\${r.ts}" data-label="">\${fmtAgo(r.ts)}</td>
      <td data-label="\${esc(t('th.client'))}">\${esc(r.client)}</td>
      <td data-label="\${esc(t('th.model'))}"><span class="meta">\${esc(shortModel(r.model))}</span></td>
      \${msgCell}
      <td class="path" data-label="\${esc(t('th.path'))}" title="\${esc(r.method + ' ' + r.path)}">\${esc(r.path)}</td>
      <td data-label="\${esc(t('th.status'))}"><span class="pill \${cls}">\${r.status}</span></td>
      \${srcCell}
      <td class="num" data-label="\${esc(t('th.duration'))}">\${r.durationMs}ms</td>
      <td class="num" data-label="\${esc(t('th.input'))}" title="\${fmtNum(r.inputTokens)} input tokens">\${hasUsage ? fmtTokens(r.inputTokens) : '—'}</td>
      <td class="num" data-label="\${esc(t('th.output'))}" title="\${fmtNum(r.outputTokens)} output tokens">\${hasUsage ? fmtTokens(r.outputTokens) : '—'}</td>
      <td class="num" data-label="\${esc(t('th.cache'))}" title="cache read \${fmtNum(r.cacheReadTokens)} · cache write \${fmtNum(r.cacheCreationTokens)}">\${hasUsage ? fmtTokens((r.cacheReadTokens || 0) + (r.cacheCreationTokens || 0)) : '—'}</td>
      <td class="num" data-label="\${esc(t('th.cost'))}">\${r.costUsd ? fmtCost(r.costUsd) : '—'}</td>\`;
    return tr;
  };

  const RECENT_KEEP = 50;
  let pendingRecent = [];        // queued rows while paused (deduped by ts)
  let recentPaused = false;      // user is hovering the table
  let recentSeenTs = new Set();  // every ts considered (DOM-rendered OR filtered out)

  const recentFilters = { search: '', client: '', model: '', status: '', method: '' };

  const recentFilterActive = () =>
    !!(recentFilters.search || recentFilters.client || recentFilters.model
      || recentFilters.status || recentFilters.method);

  const matchesRecentFilter = (r) => {
    const f = recentFilters;
    if (f.client && r.client !== f.client) return false;
    if (f.model && (r.model || '') !== f.model) return false;
    if (f.method && r.method !== f.method) return false;
    if (f.status) {
      const bucket = r.status >= 500 ? '5xx'
        : r.status >= 400 ? '4xx'
        : r.status >= 300 ? '3xx'
        : '2xx';
      if (bucket !== f.status) return false;
    }
    if (f.search) {
      const q = f.search.toLowerCase();
      const hay = ((r.client||'') + ' ' + (r.path||'') + ' ' + (r.model||'')
        + ' ' + (r.userMessage||'') + ' ' + (r.errorSource||'') + ' ' + (r.errorDetail||'')).toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  };

  const fillSelectKeepingValue = (sel, values) => {
    const cur = sel.value;
    const placeholder = sel.firstElementChild ? sel.firstElementChild.outerHTML : '';
    sel.innerHTML = placeholder
      + values.map(v => '<option value="' + esc(v) + '">' + esc(v) + '</option>').join('');
    sel.value = values.includes(cur) ? cur : '';
  };

  const populateRecentFilterOptions = (data) => {
    // Union with the full clients/models tables so dropdowns still list a
    // client even if they haven't shown up in the last 50 requests yet.
    const clientsSet = new Set();
    const modelsSet = new Set();
    for (const r of data.recent) {
      if (r.client) clientsSet.add(r.client);
      if (r.model) modelsSet.add(r.model);
    }
    for (const c of (data.clients || [])) if (c.name) clientsSet.add(c.name);
    for (const m of (data.models  || [])) if (m.model) modelsSet.add(m.model);
    fillSelectKeepingValue(
      document.getElementById('rfClient'),
      Array.from(clientsSet).sort(),
    );
    fillSelectKeepingValue(
      document.getElementById('rfModel'),
      Array.from(modelsSet).sort(),
    );
  };

  const updateRecentCount = (data) => {
    const el = document.getElementById('rfCount');
    if (!el) return;
    const total = data ? data.recent.length : 0;
    if (!total) { el.textContent = ''; el.classList.remove('active'); return; }
    if (recentFilterActive()) {
      const shown = data.recent.filter(matchesRecentFilter).length;
      el.textContent = t('admin.recent.showingOf', { shown: shown, total: total });
      el.classList.add('active');
    } else {
      el.textContent = t('admin.recent.rows', { total: total });
      el.classList.remove('active');
    }
  };

  // Rebuild the table body from currentData under the active filter.
  // Reseeds recentSeenTs so the next refresh's diff path stays consistent.
  const applyRecentFilters = () => {
    if (!currentData) return;
    const body = document.getElementById('recentBody');
    if (!body) return;
    recentSeenTs = new Set();
    pendingRecent = [];
    body.innerHTML = '';
    const ordered = currentData.recent.slice().reverse();
    for (const r of ordered) {
      recentSeenTs.add(String(r.ts));
      if (matchesRecentFilter(r)) body.appendChild(buildRecentRow(r));
    }
    const scroll = document.getElementById('recentScroll');
    if (scroll) scroll.scrollTop = scroll.scrollHeight;
    updatePauseHint();
    updateRecentCount(currentData);
  };

  // Refresh just the relative-time cells without touching the rest of the row,
  // so an idle viewer sees "1m ago" tick to "2m ago" without the whole table
  // re-rendering and losing their scroll/selection.
  const tickAgoCells = () => {
    const body = document.getElementById('recentBody');
    if (!body) return;
    body.querySelectorAll('td.ago[data-ts]').forEach(td => {
      const ts = Number(td.getAttribute('data-ts'));
      if (Number.isFinite(ts)) td.textContent = fmtAgo(ts);
    });
  };

  const flushPendingRecent = () => {
    const body = document.getElementById('recentBody');
    const scroll = document.getElementById('recentScroll');
    if (!body || !pendingRecent.length) {
      updatePauseHint();
      return;
    }
    // Chat-style: newest at the bottom. Stick to bottom only if the user was
    // already there; if they scrolled UP to inspect older rows, leave their
    // viewport alone (appending at the bottom doesn't shift content above).
    const wasAtBottom = !scroll
      || (scroll.scrollHeight - scroll.scrollTop - scroll.clientHeight) < 32;
    // Append oldest-first so the newest ends up at the bottom. Drop rows that
    // don't match the active filter — they stay tracked in recentSeenTs so we
    // don't keep re-evaluating them on every refresh tick.
    pendingRecent.sort((a, b) => a.ts - b.ts);
    for (const r of pendingRecent) {
      if (matchesRecentFilter(r)) body.appendChild(buildRecentRow(r));
    }
    pendingRecent = [];
    while (body.children.length > RECENT_KEEP) {
      body.removeChild(body.firstChild);
    }
    if (scroll && wasAtBottom) {
      scroll.scrollTop = scroll.scrollHeight;
    }
    updatePauseHint();
    updateRecentCount(currentData);
  };

  const updatePauseHint = () => {
    const hint = document.getElementById('pauseHint');
    if (!hint) return;
    if (recentPaused && pendingRecent.length) {
      hint.textContent = t('admin.recent.pausedNew', { n: pendingRecent.length });
    } else if (recentPaused) {
      hint.textContent = t('admin.recent.pausedHover');
    } else {
      hint.textContent = '';
    }
  };

  const renderRecent = (data) => {
    const host = document.getElementById('recentTable');
    const filterBar = document.getElementById('recentFilters');
    if (!data.recent.length) {
      host.innerHTML = '<div class="empty">' + esc(t('admin.empty.noRequests')) + '</div>';
      pendingRecent = [];
      recentSeenTs = new Set();
      if (filterBar) filterBar.style.display = 'none';
      return;
    }

    if (filterBar) filterBar.style.display = '';
    populateRecentFilterOptions(data);

    let body = document.getElementById('recentBody');
    if (!body) {
      host.innerHTML = RECENT_TABLE_HTML;
      body = document.getElementById('recentBody');
      // Initial paint: server returns newest-first, but we want chat-style
      // (newest at the bottom), so reverse before appending. Apply the active
      // filter as we go; non-matching rows are still tracked in recentSeenTs.
      const ordered = data.recent.slice().reverse();
      for (const r of ordered) {
        recentSeenTs.add(String(r.ts));
        if (matchesRecentFilter(r)) body.appendChild(buildRecentRow(r));
      }

      // Pause refresh while the user is interacting so the table stops moving
      // under their cursor. Resume + flush when they leave.
      const scroll = document.getElementById('recentScroll');
      scroll.addEventListener('mouseenter', () => { recentPaused = true; updatePauseHint(); });
      scroll.addEventListener('mouseleave', () => { recentPaused = false; flushPendingRecent(); });
      // Start anchored at the bottom so the latest request is in view.
      scroll.scrollTop = scroll.scrollHeight;
      updateRecentCount(data);
      return;
    }

    // Diff against everything we've already considered (DOM rows + filtered-out
    // rows + queued rows). ts is monotonic per-request and unique enough at our
    // request rate to use as a row key.
    for (const r of pendingRecent) recentSeenTs.add(String(r.ts));
    const fresh = data.recent.filter(r => !recentSeenTs.has(String(r.ts)));
    if (!fresh.length) {
      tickAgoCells();
      updatePauseHint();
      updateRecentCount(data);
      return;
    }

    for (const r of fresh) recentSeenTs.add(String(r.ts));
    pendingRecent.push(...fresh);
    if (recentPaused) {
      // Hold back — let the user finish reading. Hint shows the backlog.
      tickAgoCells();
      updatePauseHint();
      updateRecentCount(data);
    } else {
      flushPendingRecent();
      tickAgoCells();
    }
  };

  let currentData = null;

  const refresh = async () => {
    try {
      const res = await fetch('/_metrics', { cache: 'no-store', credentials: 'same-origin' });
      if (res.status === 401) {
        location.href = '/admin';
        return;
      }
      if (!res.ok) {
        document.getElementById('updated').textContent = t('admin.toolbar.errStatus', { status: res.status });
        return;
      }
      currentData = await res.json();
      renderOAuthBanner(currentData.oauth);
      renderTopStats(currentData);
      renderPeriods(currentData);
      renderCharts(currentData);
      renderQuota(currentData);
      renderSessionModels(currentData);
      renderModels(currentData);
      renderClients(currentData);
      renderRecent(currentData);
      document.getElementById('updated').textContent = t('admin.toolbar.updated', { time: new Date().toLocaleTimeString() });
    } catch (e) {
      document.getElementById('updated').textContent = t('admin.toolbar.fetchErr');
    }
  };

  // ── OAuth account health + re-login ──
  // The gateway proxies one shared Claude account. When its refresh_token dies
  // every /v1/* call 503s, so surface that here with a one-click recovery
  // instead of making the admin edit config.yaml and restart the container.
  const renderOAuthBanner = (oauth) => {
    const banner = document.getElementById('oauthBanner');
    if (!oauth || oauth.state === 'ok' || oauth.state === 'uninitialized') {
      banner.style.display = 'none';
      return;
    }
    const msgKey = oauth.state === 'expired'
      ? 'admin.oauth.bannerExpired'
      : 'admin.oauth.bannerRefreshing';
    let msg = t(msgKey);
    if (oauth.last_error) msg += ' ' + t('admin.oauth.detail', { error: oauth.last_error });
    document.getElementById('oauthBannerMsg').textContent = msg;
    banner.style.display = 'flex';
  };

  const showOaError = (msg) => {
    const el = document.getElementById('oaError');
    if (msg) { el.textContent = msg; el.style.display = 'block'; }
    else { el.style.display = 'none'; }
  };
  const showOaOk = (msg) => {
    const el = document.getElementById('oaOk');
    if (msg) { el.textContent = msg; el.style.display = 'block'; }
    else { el.style.display = 'none'; }
  };
  let oaLinkReady = false;
  const openOauthModal = () => {
    oaLinkReady = false;
    document.getElementById('oaCode').value = '';
    document.getElementById('oaOpen').style.display = 'none';
    showOaError(null);
    showOaOk(null);
    document.getElementById('oauthModal').style.display = 'flex';
  };
  const closeOauthModal = () => {
    document.getElementById('oauthModal').style.display = 'none';
  };
  const startOauthLogin = async () => {
    const btn = document.getElementById('oaLink');
    btn.disabled = true;
    showOaError(null);
    showOaOk(null);
    try {
      const res = await fetch('/api/oauth/login', { method: 'POST', credentials: 'same-origin' });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        showOaError(t('admin.modal.oauth.linkErr', { error: err.error || res.status }));
        return;
      }
      const data = await res.json();
      const link = document.getElementById('oaOpen');
      link.href = data.url;
      link.style.display = 'inline';
      oaLinkReady = true;
      window.open(data.url, '_blank', 'noopener');
      document.getElementById('oaCode').focus();
    } catch (e) {
      showOaError(t('admin.alert.networkErr'));
    } finally {
      btn.disabled = false;
    }
  };
  const submitOauthCode = async () => {
    if (!oaLinkReady) { showOaError(t('admin.modal.oauth.needLink')); return; }
    const code = document.getElementById('oaCode').value.trim();
    if (!code) { showOaError(t('admin.modal.oauth.needCode')); return; }
    const btn = document.getElementById('oaSubmit');
    btn.disabled = true;
    showOaError(null);
    showOaOk(t('admin.modal.oauth.working'));
    try {
      const res = await fetch('/api/oauth/complete', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        showOaOk(null);
        showOaError(t('admin.alert.failed', { error: data.error || res.status }));
        return;
      }
      showOaOk(t('admin.modal.oauth.ok', { time: new Date(data.expires_at).toLocaleTimeString() }));
      renderOAuthBanner(data.status);
      setTimeout(() => { closeOauthModal(); refresh(); }, 1200);
    } catch (e) {
      showOaOk(null);
      showOaError(t('admin.alert.networkErr'));
    } finally {
      btn.disabled = false;
    }
  };
  document.getElementById('oauthBannerBtn').addEventListener('click', openOauthModal);
  document.getElementById('oaLink').addEventListener('click', startOauthLogin);
  document.getElementById('oaSubmit').addEventListener('click', submitOauthCode);
  document.getElementById('oaCancel').addEventListener('click', closeOauthModal);
  document.getElementById('oauthModal').addEventListener('click', (e) => {
    if (e.target.id === 'oauthModal') closeOauthModal();
  });
  document.getElementById('oaCode').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') submitOauthCode();
  });

  document.getElementById('refreshBtn').addEventListener('click', refresh);
  document.getElementById('rangeSel').addEventListener('change', () => {
    if (currentData) renderCharts(currentData);
  });

  // ── Recent requests filter bar ──
  // All filters operate client-side on the 50-row window the server returns,
  // so we can swap filters without re-querying.
  (() => {
    const onChange = () => {
      recentFilters.search = document.getElementById('rfSearch').value.trim();
      recentFilters.client = document.getElementById('rfClient').value;
      recentFilters.model  = document.getElementById('rfModel').value;
      recentFilters.status = document.getElementById('rfStatus').value;
      recentFilters.method = document.getElementById('rfMethod').value;
      applyRecentFilters();
    };
    let searchTimer = null;
    const onSearchInput = () => {
      clearTimeout(searchTimer);
      searchTimer = setTimeout(onChange, 120);
    };
    document.getElementById('rfSearch').addEventListener('input', onSearchInput);
    document.getElementById('rfClient').addEventListener('change', onChange);
    document.getElementById('rfModel').addEventListener('change', onChange);
    document.getElementById('rfStatus').addEventListener('change', onChange);
    document.getElementById('rfMethod').addEventListener('change', onChange);
    document.getElementById('rfClear').addEventListener('click', () => {
      document.getElementById('rfSearch').value = '';
      document.getElementById('rfClient').value = '';
      document.getElementById('rfModel').value = '';
      document.getElementById('rfStatus').value = '';
      document.getElementById('rfMethod').value = '';
      onChange();
    });
  })();

  // ── Clients management ──
  const renderLimitCell = (c) => {
    if (!c.cost_limit_usd) {
      return '<span class="meta">' + esc(t('admin.client.unlimited')) + '</span>';
    }
    const used = c.cost_used_usd || 0;
    const pct = Math.min(100, Math.round((used / c.cost_limit_usd) * 100));
    const cls = pct >= 100 ? 'err' : pct >= 80 ? 'warn' : '';
    const period = c.cost_limit_period || 'lifetime';
    return \`<span title="\${esc(t('admin.client.windowTitle', { period: period }))}">\${fmtCost(used)} / \${fmtCost(c.cost_limit_usd)} (\${pct}%)</span>\` +
      \`<span class="limit-bar"><span class="\${cls}" style="width:\${pct}%"></span></span>\`;
  };

  const renderClientsConfig = (clients) => {
    const el = document.getElementById('clientsConfig');
    if (!clients.length) {
      el.innerHTML = '<div class="empty">' + esc(t('admin.empty.noClientsConfigured')) + '</div>';
      return;
    }
    const rows = clients.map(c => \`
      <tr>
        <td data-label=""><strong>\${esc(c.name)}</strong></td>
        <td data-label="\${esc(t('th.token'))}"><code class="config-info">\${esc(c.token_preview)}</code></td>
        <td data-label="\${esc(t('th.costLimit'))}">\${renderLimitCell(c)}</td>
        <td data-label="\${esc(t('th.workdir'))}">\${c.home_dir
          ? '<code class="config-info">' + esc(c.home_dir) + '</code>'
          : '<span class="meta">' + esc(t('admin.client.workdirAuto')) + '</span>'}</td>
        <td data-label="" style="text-align:right;white-space:nowrap">
          <button data-edit-workdir="\${esc(c.name)}" data-workdir="\${esc(c.home_dir || '')}">\${esc(t('admin.client.setWorkdir'))}</button>
          <button data-edit-limit="\${esc(c.name)}"
                  data-limit="\${c.cost_limit_usd || ''}"
                  data-period="\${esc(c.cost_limit_period || 'lifetime')}">\${esc(t('admin.client.setLimit'))}</button>
          <button data-regen="\${esc(c.name)}">\${esc(t('admin.client.redownload'))}</button>
          <button data-reset-pw="\${esc(c.name)}">\${esc(t('admin.client.resetPw'))}</button>
          <button class="danger" data-del-client="\${esc(c.name)}">\${esc(t('admin.client.delete'))}</button>
        </td>
      </tr>\`).join('');
    el.innerHTML = \`
      <table>
        <thead><tr><th>\${esc(t('th.configuredClient'))}</th><th>\${esc(t('th.token'))}</th><th>\${esc(t('th.costLimit'))}</th><th>\${esc(t('th.workdir'))}</th><th></th></tr></thead>
        <tbody>\${rows}</tbody>
      </table>\`;
    el.querySelectorAll('[data-edit-workdir]').forEach(btn => {
      btn.addEventListener('click', () => {
        openWorkdirModal(btn.getAttribute('data-edit-workdir'), btn.getAttribute('data-workdir') || '');
      });
    });
    el.querySelectorAll('[data-del-client]').forEach(btn => {
      btn.addEventListener('click', async () => {
        const name = btn.getAttribute('data-del-client');
        if (!confirm(t('admin.confirm.delClient', { name: name }))) return;
        const res = await fetch('/api/clients/' + encodeURIComponent(name), {
          method: 'DELETE', credentials: 'same-origin',
        });
        if (!res.ok) {
          const err = await res.json().catch(() => ({}));
          alert(t('admin.alert.failed', { error: err.error || res.status }));
          return;
        }
        loadClients();
      });
    });
    el.querySelectorAll('[data-edit-limit]').forEach(btn => {
      btn.addEventListener('click', () => {
        openLimitModal(
          btn.getAttribute('data-edit-limit'),
          btn.getAttribute('data-limit'),
          btn.getAttribute('data-period') || 'lifetime',
        );
      });
    });
    el.querySelectorAll('[data-regen]').forEach(btn => {
      btn.addEventListener('click', () => openRegenModal(btn.getAttribute('data-regen')));
    });
    el.querySelectorAll('[data-reset-pw]').forEach(btn => {
      btn.addEventListener('click', () => resetClientPassword(btn.getAttribute('data-reset-pw')));
    });
  };

  // Generate a fresh portal password for a client and show it once.
  const resetClientPassword = async (name) => {
    if (!confirm(t('admin.confirm.resetPw', { name: name }))) return;
    const res = await fetch('/api/clients/' + encodeURIComponent(name) + '/password', {
      method: 'POST', credentials: 'same-origin',
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      alert(t('admin.alert.failed', { error: err.error || res.status }));
      return;
    }
    const data = await res.json();
    document.getElementById('pwResetName').textContent = name;
    document.getElementById('pwResetValue').textContent = data.password || '';
    document.getElementById('pwResetModal').style.display = 'flex';
  };

  const loadClients = async () => {
    const res = await fetch('/api/clients', { credentials: 'same-origin' });
    if (!res.ok) return;
    const data = await res.json();
    renderClientsConfig(data.clients || []);
    populateInstallGuideClients(data.clients || []);
  };

  const showError = (msg) => {
    const el = document.getElementById('cError');
    if (msg) { el.textContent = msg; el.style.display = 'block'; }
    else { el.style.display = 'none'; }
  };

  const modalBoxEl = () => document.querySelector('#addClientModal .modal-box');

  const openModal = () => {
    document.getElementById('cName').value = '';
    document.getElementById('cAddr').value = location.host;
    document.getElementById('cScheme').value = location.protocol === 'http:' ? 'http' : 'https';
    document.getElementById('cPlatform').value = 'unix';
    document.getElementById('cLimit').value = '';
    document.getElementById('cLimitPeriod').value = 'lifetime';
    showError(null);
    modalBoxEl().classList.remove('wide');
    document.getElementById('modalForm').style.display = 'block';
    document.getElementById('modalSuccess').style.display = 'none';
    document.getElementById('addClientModal').style.display = 'flex';
    setTimeout(() => document.getElementById('cName').focus(), 0);
  };
  const closeModal = () => { document.getElementById('addClientModal').style.display = 'none'; };

  // Shared command/copy text for the modal success panel and the on-page
  // Install guide section, so both always show identical instructions.
  const launcherSteps = (name, platform) => {
    const isWin = platform === 'windows';
    const fname = isWin ? 'cc-' + name + '.ps1' : 'cc-' + name;
    if (isWin) {
      return {
        fname,
        step1Label: '<span class="num">1</span>' + t('admin.step.winUnblock'),
        step1Meta: t('admin.step.winUnblockMeta'),
        unblockCmd: 'Set-ExecutionPolicy -Scope CurrentUser RemoteSigned -Force; Unblock-File .\\\\' + fname,
        runMeta: t('admin.step.runMetaWin'),
        runCmd: '.\\\\' + fname,
        installMeta: t('admin.step.installMetaWin'),
        installCmd: '.\\\\' + fname + ' install',
        hijackMeta: t('admin.step.hijackMetaWin'),
      };
    }
    return {
      fname,
      step1Label: '<span class="num">1</span>' + t('admin.step.gatekeeper'),
      step1Meta: t('admin.step.gatekeeperMeta'),
      unblockCmd: 'xattr -d com.apple.quarantine ' + fname,
      runMeta: t('admin.step.runMetaUnix'),
      runCmd: 'chmod +x ' + fname + ' && ./' + fname,
      installMeta: t('admin.step.installMetaUnix'),
      installCmd: 'chmod +x ' + fname + ' && ./' + fname + ' install',
      hijackMeta: t('admin.step.hijackMetaUnix'),
    };
  };

  const showSuccess = (name, platform, password) => {
    document.getElementById('modalForm').style.display = 'none';
    const sucEl = document.getElementById('modalSuccess');
    sucEl.style.display = 'block';
    modalBoxEl().classList.add('wide');
    document.getElementById('successName').textContent = name;
    document.getElementById('portalLoginName').textContent = name;
    document.getElementById('portalPassword').textContent = password || t('admin.success.pwUnavailable');
    document.getElementById('portalUrl').href = location.origin + '/portal';
    const s = launcherSteps(name, platform);
    document.getElementById('successFile').textContent = s.fname;
    document.getElementById('step1Label').innerHTML = s.step1Label;
    document.getElementById('step1Meta').innerHTML = s.step1Meta;
    document.getElementById('xattrCmd').textContent = s.unblockCmd;
    document.getElementById('step2Meta').textContent = s.runMeta;
    document.getElementById('successCmd').textContent = s.runCmd;
    document.getElementById('step3Meta').innerHTML = s.installMeta;
    document.getElementById('installCmd').textContent = s.installCmd;
    document.getElementById('step4Meta').innerHTML = s.hijackMeta;
    document.getElementById('hijackCmd').textContent = 'ccg hijack';
    // Mirror the freshly created client into the on-page Install guide so the
    // commands stay visible after the modal closes.
    syncInstallGuide(name, platform);
  };

  // ── Install guide section (on-page copy of the modal steps) ──
  const updateInstallGuide = () => {
    const name = document.getElementById('igClient').value || '<name>';
    const platform = document.getElementById('igPlatform').value;
    const s = launcherSteps(name, platform);
    document.getElementById('igStep1Label').innerHTML = s.step1Label;
    document.getElementById('igStep1Meta').innerHTML = s.step1Meta;
    document.getElementById('igUnblockCmd').textContent = s.unblockCmd;
    document.getElementById('igRunMeta').textContent = s.runMeta;
    document.getElementById('igRunCmd').textContent = s.runCmd;
    document.getElementById('igInstallMeta').innerHTML = s.installMeta;
    document.getElementById('igInstallCmd').textContent = s.installCmd;
    document.getElementById('igHijackMeta').innerHTML = s.hijackMeta;
  };

  // Point the Install guide at a specific client (called after creating one).
  const syncInstallGuide = (name, platform) => {
    const sel = document.getElementById('igClient');
    if (![...sel.options].some(o => o.value === name)) {
      sel.insertAdjacentHTML('beforeend',
        '<option value="' + esc(name) + '">' + esc(name) + '</option>');
    }
    sel.value = name;
    document.getElementById('igPlatform').value = platform;
    updateInstallGuide();
  };

  const populateInstallGuideClients = (clients) => {
    const sel = document.getElementById('igClient');
    const cur = sel.value;
    sel.innerHTML = '<option value="">' + esc(t('admin.install.clientNamePh')) + '</option>'
      + clients.map(c => '<option value="' + esc(c.name) + '">' + esc(c.name) + '</option>').join('');
    sel.value = clients.some(c => c.name === cur) ? cur : '';
    updateInstallGuide();
  };

  document.getElementById('igClient').addEventListener('change', updateInstallGuide);
  document.getElementById('igPlatform').addEventListener('change', updateInstallGuide);
  updateInstallGuide();

  const wireCopyButton = (btnId, sourceId) => {
    document.getElementById(btnId).addEventListener('click', async (e) => {
      const btn = e.currentTarget;
      const text = document.getElementById(sourceId).textContent;
      try {
        await navigator.clipboard.writeText(text);
        btn.textContent = t('common.copied');
        btn.classList.add('copied');
        setTimeout(() => {
          btn.textContent = t('common.copy');
          btn.classList.remove('copied');
        }, 1500);
      } catch {
        // fallback: select text
        const range = document.createRange();
        range.selectNodeContents(document.getElementById(sourceId));
        const sel = window.getSelection();
        sel.removeAllRanges();
        sel.addRange(range);
      }
    });
  };

  const submitClient = async () => {
    const name = document.getElementById('cName').value.trim();
    const gateway_addr = document.getElementById('cAddr').value.trim();
    const scheme = document.getElementById('cScheme').value;
    const platform = document.getElementById('cPlatform').value;
    const limitRaw = document.getElementById('cLimit').value.trim();
    const cost_limit_usd = limitRaw === '' ? null : Number(limitRaw);
    const cost_limit_period = document.getElementById('cLimitPeriod').value;
    if (!name) { showError(t('admin.err.nameRequired')); return; }
    if (cost_limit_usd !== null && (!Number.isFinite(cost_limit_usd) || cost_limit_usd < 0)) {
      showError(t('admin.err.costNonNeg')); return;
    }
    const submitBtn = document.getElementById('cSubmit');
    submitBtn.disabled = true;
    try {
      const res = await fetch('/api/clients', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, gateway_addr, scheme, platform, cost_limit_usd, cost_limit_period }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        showError(err.error || t('admin.err.requestFailed', { status: res.status }));
        return;
      }
      const password = res.headers.get('X-Portal-Password') || '';
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = platform === 'windows' ? 'cc-' + name + '.ps1' : 'cc-' + name;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      showSuccess(name, platform, password);
      loadClients();
    } finally {
      submitBtn.disabled = false;
    }
  };

  // ── Set-limit modal ──
  const showLimitError = (msg) => {
    const el = document.getElementById('lError');
    if (msg) { el.textContent = msg; el.style.display = 'block'; }
    else { el.style.display = 'none'; }
  };
  const openLimitModal = (name, currentLimit, currentPeriod) => {
    document.getElementById('limitName').textContent = name;
    document.getElementById('lLimit').value = currentLimit && Number(currentLimit) > 0 ? currentLimit : '';
    document.getElementById('lPeriod').value = currentPeriod || 'lifetime';
    showLimitError(null);
    document.getElementById('limitModal').style.display = 'flex';
    document.getElementById('limitModal').setAttribute('data-name', name);
    setTimeout(() => document.getElementById('lLimit').focus(), 0);
  };
  const closeLimitModal = () => { document.getElementById('limitModal').style.display = 'none'; };
  const submitLimit = async () => {
    const name = document.getElementById('limitModal').getAttribute('data-name');
    const raw = document.getElementById('lLimit').value.trim();
    const cost_limit_usd = raw === '' ? null : Number(raw);
    const cost_limit_period = document.getElementById('lPeriod').value;
    if (cost_limit_usd !== null && (!Number.isFinite(cost_limit_usd) || cost_limit_usd < 0)) {
      showLimitError(t('admin.err.costNonNeg')); return;
    }
    const btn = document.getElementById('lSubmit');
    btn.disabled = true;
    try {
      const res = await fetch('/api/clients/' + encodeURIComponent(name), {
        method: 'PATCH',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ cost_limit_usd, cost_limit_period }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        showLimitError(err.error || t('admin.err.requestFailed', { status: res.status }));
        return;
      }
      closeLimitModal();
      loadClients();
    } finally {
      btn.disabled = false;
    }
  };
  document.getElementById('lCancel').addEventListener('click', closeLimitModal);
  document.getElementById('lSubmit').addEventListener('click', submitLimit);
  document.getElementById('limitModal').addEventListener('click', (e) => {
    if (e.target.id === 'limitModal') closeLimitModal();
  });

  // ── Set-workdir modal ──
  const showWorkdirError = (msg) => {
    const el = document.getElementById('wError');
    if (msg) { el.textContent = msg; el.style.display = 'block'; }
    else { el.style.display = 'none'; }
  };
  const openWorkdirModal = (name, current) => {
    document.getElementById('workdirName').textContent = name;
    document.getElementById('workdirModal').setAttribute('data-name', name);
    document.getElementById('wDir').value = current || '';
    showWorkdirError(null);
    document.getElementById('workdirModal').style.display = 'flex';
    setTimeout(() => document.getElementById('wDir').focus(), 0);
  };
  const closeWorkdirModal = () => { document.getElementById('workdirModal').style.display = 'none'; };
  const submitWorkdir = async () => {
    const name = document.getElementById('workdirModal').getAttribute('data-name');
    const home_dir = document.getElementById('wDir').value.trim();
    const btn = document.getElementById('wSubmit');
    btn.disabled = true;
    try {
      const res = await fetch('/api/clients/' + encodeURIComponent(name), {
        method: 'PATCH',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ home_dir: home_dir === '' ? null : home_dir }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        showWorkdirError(err.error || t('admin.err.requestFailed', { status: res.status }));
        return;
      }
      closeWorkdirModal();
      loadClients();
    } finally {
      btn.disabled = false;
    }
  };
  document.getElementById('wCancel').addEventListener('click', closeWorkdirModal);
  document.getElementById('wSubmit').addEventListener('click', submitWorkdir);
  document.getElementById('workdirModal').addEventListener('click', (e) => {
    if (e.target.id === 'workdirModal') closeWorkdirModal();
  });

  document.getElementById('addClientBtn').addEventListener('click', openModal);
  document.getElementById('cCancel').addEventListener('click', closeModal);
  document.getElementById('cSubmit').addEventListener('click', submitClient);
  document.getElementById('successDone').addEventListener('click', closeModal);
  wireCopyButton('copyCmdBtn', 'successCmd');
  wireCopyButton('copyInstallBtn', 'installCmd');
  wireCopyButton('copyHijackBtn', 'hijackCmd');
  wireCopyButton('copyHijackGuiBtn', 'hijackGuiCmd');
  wireCopyButton('copyXattrBtn', 'xattrCmd');
  wireCopyButton('pwResetCopy', 'pwResetValue');
  document.getElementById('pwResetDone').addEventListener('click', () => {
    document.getElementById('pwResetModal').style.display = 'none';
  });
  document.getElementById('pwResetModal').addEventListener('click', (e) => {
    if (e.target.id === 'pwResetModal') document.getElementById('pwResetModal').style.display = 'none';
  });
  wireCopyButton('igCopyUnblock', 'igUnblockCmd');
  wireCopyButton('igCopyRun', 'igRunCmd');
  wireCopyButton('igCopyInstall', 'igInstallCmd');
  wireCopyButton('igCopyHijack', 'igHijackCmd');
  wireCopyButton('igCopyHijackGui', 'igHijackGuiCmd');
  document.getElementById('addClientModal').addEventListener('click', (e) => {
    if (e.target.id === 'addClientModal') closeModal();
  });

  // Re-download launcher (for existing clients) — reuses the token in
  // config.yaml, so billing/cost history are preserved.
  let regenClientName = null;
  const showRegenError = (msg) => {
    const el = document.getElementById('rError');
    if (msg) { el.textContent = msg; el.style.display = 'block'; }
    else { el.style.display = 'none'; }
  };
  const openRegenModal = (name) => {
    regenClientName = name;
    document.getElementById('regenName').textContent = name;
    document.getElementById('rAddr').value = location.host;
    document.getElementById('rScheme').value = location.protocol === 'http:' ? 'http' : 'https';
    document.getElementById('rPlatform').value = 'unix';
    showRegenError(null);
    document.getElementById('regenModal').style.display = 'flex';
  };
  const closeRegenModal = () => {
    document.getElementById('regenModal').style.display = 'none';
    regenClientName = null;
  };
  const submitRegen = async () => {
    if (!regenClientName) return;
    const platform = document.getElementById('rPlatform').value;
    const scheme = document.getElementById('rScheme').value;
    const addr = document.getElementById('rAddr').value.trim() || location.host;
    const params = new URLSearchParams({ platform, scheme, gateway_addr: addr });
    const url = '/api/clients/' + encodeURIComponent(regenClientName) + '/launcher?' + params.toString();
    const btn = document.getElementById('rSubmit');
    btn.disabled = true;
    try {
      const res = await fetch(url, { credentials: 'same-origin' });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        showRegenError(t('admin.alert.failed', { error: err.error || res.status }));
        return;
      }
      const blob = await res.blob();
      const fname = platform === 'windows' ? 'cc-' + regenClientName + '.ps1' : 'cc-' + regenClientName;
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = fname;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(a.href);
      closeRegenModal();
    } catch (e) {
      showRegenError(t('admin.alert.networkErr'));
    } finally {
      btn.disabled = false;
    }
  };
  document.getElementById('rCancel').addEventListener('click', closeRegenModal);
  document.getElementById('rSubmit').addEventListener('click', submitRegen);
  document.getElementById('regenModal').addEventListener('click', (e) => {
    if (e.target.id === 'regenModal') closeRegenModal();
  });

  // Sidebar nav: highlight the section currently in view and keep page title
  // in sync. Uses IntersectionObserver — much cheaper than scroll listeners.
  const sectionToTitle = {
    'topStats': 'admin.nav.overview',
    'quota': 'admin.nav.quota',
    'periods': 'admin.nav.periods',
    'charts-section': 'admin.nav.traffic',
    'models': 'admin.nav.models',
    'clients': 'admin.nav.clients',
    'recent': 'admin.nav.recent',
    'install': 'admin.nav.install',
    'about': 'admin.nav.about',
  };
  const navLinks = Array.from(document.querySelectorAll('#sideNav a'));
  const setActive = (id) => {
    for (const a of navLinks) {
      const target = a.getAttribute('href').slice(1);
      const matchTarget = target === 'charts' ? 'charts-section' : target;
      a.classList.toggle('active', matchTarget === id);
    }
    const title = document.getElementById('pageTitle');
    if (title && sectionToTitle[id]) title.textContent = t(sectionToTitle[id]);
  };
  const observed = ['topStats', 'quota', 'periods', 'charts-section', 'models', 'clients', 'recent', 'install', 'about']
    .map(id => document.getElementById(id))
    .filter(Boolean);
  if ('IntersectionObserver' in window) {
    const visible = new Map();
    const io = new IntersectionObserver((entries) => {
      for (const e of entries) {
        visible.set(e.target.id, e.intersectionRatio);
      }
      let bestId = null, bestRatio = 0;
      for (const [id, ratio] of visible) {
        if (ratio > bestRatio) { bestRatio = ratio; bestId = id; }
      }
      if (bestId) setActive(bestId);
    }, { rootMargin: '-80px 0px -50% 0px', threshold: [0, 0.1, 0.5, 1] });
    for (const el of observed) io.observe(el);
  }

  loadClients();
  refresh();
  setInterval(refresh, 5000);
  setInterval(tickAgoCells, 15000);
  setInterval(tickQuotaResets, 1000);
})();
</script>
</body>
</html>`
}
