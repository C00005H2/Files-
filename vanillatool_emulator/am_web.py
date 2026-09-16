"""Browser GUI for the Account Manager automatic build (stdlib-only).

The desktop Tk GUI (``am_gui.py``) mirrors the original Windows look, but it
needs Tk and Windows to be useful.  This module is the *portable* GUI: a
single-page dashboard served over HTTP with zero dependencies.  It drives the
exact same :mod:`am_pipeline` backend, so everything done here is identical to
the desktop GUI:

* edit every original option (server preset, checkboxes, delays, slots),
* manage ``logins.ini`` accounts,
* one-click **Automatic Run** (workspace + mapper + emulator + target + plan),
* start/stop a persistent emulator server for a real client to talk to,
* watch the ``Status: ...`` line and the step log live.

Run::

    python -m vanillatool_emulator.am_web --port 8090

then open http://127.0.0.1:8090/ in a browser.  On Windows with the preview
proxy, bind ``0.0.0.0`` so the preview host can reach it.
"""

from __future__ import annotations

import argparse
import configparser
import html
import json
import logging
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from . import am_config as C
from .am_pipeline import run_automatic
from .am_workspace import (
    DEFAULT_WORKSPACE,
    build_default_logins,
    list_accounts,
    load_settings_file,
    read_logins,
    save_settings_file,
    write_logins,
)
from .server import EmulatorConfig, EmulatorHTTPServer

LOG = logging.getLogger("am_web")

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Account Manager - Automatic Lab</title>
<style>
:root { --bg:#101418; --panel:#1a2129; --line:#2c3642; --txt:#e8eef4; --mut:#93a1b0;
       --acc:#4da3ff; --ok:#3fd68c; --bad:#ff5d5d; --warn:#ffb84d; }
* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--txt);
       font:14px/1.45 system-ui,Segoe UI,Roboto,Arial,sans-serif; }
header { padding:12px 18px; border-bottom:1px solid var(--line); background:#151b22;
         position:sticky; top:0; z-index:5; }
header h1 { margin:0; font-size:18px; }
header h1 small { color:var(--mut); font-weight:normal; }
#statusbar { margin-top:8px; padding:8px 12px; border:1px solid var(--line);
             border-radius:6px; background:#0c1015; font-family:Consolas,monospace;
             font-size:13px; white-space:pre-wrap; }
#statusbar.ok { border-color:var(--ok); } #statusbar.bad { border-color:var(--bad); }
main { display:grid; grid-template-columns:340px 1fr; gap:14px; padding:14px 18px 40px; }
@media (max-width:1000px){ main{grid-template-columns:1fr;} }
section.panel { background:var(--panel); border:1px solid var(--line); border-radius:8px;
                padding:12px 14px; margin-bottom:14px; }
section.panel h2 { margin:0 0 10px; font-size:15px; color:var(--acc); }
label.row { display:flex; align-items:center; gap:8px; margin:6px 0; }
label.row span { flex:0 0 170px; color:var(--mut); }
input[type=text],input[type=number],select,textarea { flex:1; min-width:0;
  background:#0c1015; color:var(--txt); border:1px solid var(--line);
  border-radius:5px; padding:6px 8px; font-size:13px; }
input[type=checkbox]{ width:16px; height:16px; }
button { background:var(--acc); color:#06121f; border:0; border-radius:6px;
         padding:8px 14px; font-weight:600; cursor:pointer; margin:4px 6px 4px 0; }
button.ghost { background:transparent; color:var(--acc); border:1px solid var(--acc); }
button.danger { background:var(--bad); color:#fff; }
button:disabled { opacity:.45; cursor:wait; }
.grid2 { display:grid; grid-template-columns:1fr 1fr; gap:2px 14px; }
.chk { display:flex; align-items:center; gap:8px; margin:5px 0; }
.chk small { color:var(--mut); }
table { width:100%; border-collapse:collapse; font-size:13px; }
th,td { border-bottom:1px solid var(--line); padding:6px 8px; text-align:left; }
th { color:var(--mut); font-weight:600; }
#log { background:#0c1015; border:1px solid var(--line); border-radius:6px;
       height:300px; overflow:auto; padding:8px 10px; font-family:Consolas,monospace;
       font-size:12px; white-space:pre-wrap; }
.step { border:1px solid var(--line); border-radius:6px; padding:8px 10px; margin:6px 0; }
.step.ok { border-left:4px solid var(--ok); } .step.bad { border-left:4px solid var(--bad); }
.step h3 { margin:0 0 4px; font-size:13px; } .step pre { margin:4px 0 0; font-size:11px;
  color:var(--mut); white-space:pre-wrap; word-break:break-word; }
.warn { color:var(--warn); } .bad { color:var(--bad); } .ok { color:var(--ok); }
details { margin-top:8px; } summary { cursor:pointer; color:var(--mut); }
footer { padding:10px 18px 30px; color:var(--mut); font-size:12px; }
a { color:var(--acc); }
</style>
</head>
<body>
<header>
  <h1>Para's Account Manager <small>automatic lab &mdash; emulator + local files + target, one click</small></h1>
  <div id="statusbar">Status: loading..</div>
</header>
<main>
<div>
  <section class="panel">
    <h2>1 &mdash; Target &amp; Server</h2>
    <label class="row"><span>Target EXE</span>
      <input id="target_exe" type="text" placeholder="C:\Aion\bin64\aion.bin (or a copy)"></label>
    <label class="row"><span>Server preset</span><select id="server"></select></label>
    <label class="row"><span>Virtual slot</span><select id="VirtualClientSlot"></select></label>
    <label class="row"><span>Device name (11 chars)</span>
      <input id="device_name" type="text" maxlength="11" placeholder="auto-random"></label>
    <label class="row"><span>Blocked providers</span>
      <input id="missing_providers" type="text" placeholder="e.g. 1,2"></label>
    <div class="chk"><input id="login_all" type="checkbox"><label for="login_all">Login All (simulate every checked account)</label></div>
    <div class="chk"><input id="dry_run_launch" type="checkbox" checked><label for="dry_run_launch">Dry-run launch (never start a process)</label></div>
  </section>
  <section class="panel">
    <h2>2 &mdash; Emulator service</h2>
    <label class="row"><span>Bind</span><input id="emulator_host" type="text"></label>
    <label class="row"><span>Port</span><input id="emulator_port" type="number" min="1" max="65535"></label>
    <label class="row"><span>Version.txt</span><input id="version" type="text"></label>
    <label class="row"><span>ORythm / PRythm</span>
      <span style="flex:1;display:flex;gap:6px">
        <input id="orythm" type="text" style="width:60px;flex:0 0 60px">
        <input id="prythm" type="text" style="width:60px;flex:0 0 60px">
      </span></label>
    <div class="chk"><input id="account_manager_startup" type="checkbox" checked>
      <label for="account_manager_startup">AM pre-GUI markers (60 zero placeholders)</label></div>
    <label class="row"><span>Response file</span><input id="response_file" type="text" placeholder="optional real profile"></label>
    <label class="row"><span>Offsets file</span><input id="offsets_file" type="text" placeholder="optional Offsets.txt"></label>
    <div>
      <button id="btnEmuStart" class="ghost">Start emulator</button>
      <button id="btnEmuStop" class="ghost">Stop</button>
    </div>
    <div id="emuState" style="margin-top:6px;color:var(--mut)">emulator: stopped</div>
  </section>
  <section class="panel">
    <h2>3 &mdash; Options (original checkboxes)</h2>
    <div id="hive" class="grid2"></div>
  </section>
</div>
<div>
  <section class="panel">
    <h2>Automatic run</h2>
    <div>
      <button id="btnRun">▶ Automatic Run</button>
      <button id="btnSave" class="ghost">Save options</button>
      <button id="btnReload" class="ghost">Reload</button>
    </div>
    <div id="steps"></div>
    <details><summary>Raw JSON report</summary><pre id="reportJson"
      style="font-size:11px;color:var(--mut);white-space:pre-wrap"></pre></details>
  </section>
  <section class="panel">
    <h2>Accounts (logins.ini)</h2>
    <table><thead><tr><th>Slot</th><th>Account</th><th>Client</th><th>GameAccount</th><th>LoginAll</th><th></th></tr></thead>
    <tbody id="accounts"></tbody></table>
    <details><summary>Add / update account</summary>
      <div style="margin-top:8px">
      <label class="row"><span>Slot</span><input id="a_slot" type="text" placeholder="0"></label>
      <label class="row"><span>Account</span><input id="a_Account" type="text"></label>
      <label class="row"><span>Password</span><input id="a_Password" type="text" placeholder="stored plaintext like the original"></label>
      <label class="row"><span>Client</span><select id="a_Client"></select></label>
      <label class="row"><span>GameAccount</span><input id="a_GameAccount" type="text"></label>
      <label class="row"><span>Notes</span><input id="a_Notes" type="text"></label>
      <div class="chk"><input id="a_LoginAll" type="checkbox" checked><label for="a_LoginAll">include in Login All</label></div>
      <button id="btnAccountSave" class="ghost">Save account</button>
      </div>
    </details>
    <div style="color:var(--warn);font-size:12px;margin-top:6px">
      Passwords are stored plaintext in logins.ini exactly like the original.
      Keep the workspace private; passwords are never written to the log.</div>
  </section>
  <section class="panel">
    <h2>Delays (logins.ini [Delay])</h2>
    <details><summary>Show / edit delay table</summary><div id="delays" class="grid2" style="margin-top:8px"></div>
    <button id="btnDelays" class="ghost">Save delays</button></details>
  </section>
  <section class="panel">
    <h2>Log</h2>
    <div id="log"></div>
  </section>
</div>
</main>
<footer>
  Lab build: mapper runs are emulated transcripts, NCGuard/target scans are read-only,
  Auto-Inject is plan-only. Nothing here loads a driver, writes process memory or injects a DLL.
</footer>
<script>
const $ = id => document.getElementById(id);
let HIVE = [], SERVERS = [], DELAYS = {}, ACCOUNTS = [];
function log(msg){ const el=$('log'); el.textContent += msg + "\n"; el.scrollTop = el.scrollHeight; }
function setStatus(txt, cls){ const el=$('statusbar'); el.textContent = txt; el.className = cls||''; }
async function api(path, opts){
  const r = await fetch(path, Object.assign({headers:{'Content-Type':'application/json'}}, opts||{}));
  const t = await r.text();
  try { return JSON.parse(t); } catch(e){ return {error:t}; }
}
function fillServers(){
  for (const id of ['server','a_Client']){
    const sel = $(id); sel.innerHTML='';
    for (const s of SERVERS){ const o=document.createElement('option'); o.value=s; o.textContent=s; sel.appendChild(o); }
  }
  const slots = ['Original','Virtual Client [1]','Virtual Client [2]','Virtual Client [3]',
    'Virtual Client [4]','Virtual Client [5]','Virtual Client [6]','Virtual Client [7]',
    'Virtual Client [8]','Virtual Client [9]'];
  const vs=$('VirtualClientSlot'); vs.innerHTML='';
  for (const s of slots){ const o=document.createElement('option'); o.value=s; o.textContent=s; vs.appendChild(o); }
}
function buildHive(settings){
  const box=$('hive'); box.innerHTML='';
  for (const h of HIVE){
    const div=document.createElement('div'); div.className='chk';
    if (h.kind==='bool'){
      const c=document.createElement('input'); c.type='checkbox'; c.id='h_'+h.key;
      c.checked = (settings[h.key]||h.default)==='True';
      const l=document.createElement('label'); l.htmlFor=c.id; l.textContent=h.label;
      l.title=h.tooltip||''; div.appendChild(c); div.appendChild(l);
    } else {
      const l=document.createElement('label'); l.textContent=h.label;
      l.style.cssText='display:block;color:var(--mut);font-size:12px';
      const inp=document.createElement('input'); inp.type = h.kind==='int'?'number':'text';
      inp.id='h_'+h.key; inp.value=settings[h.key]||h.default;
      const wrap=document.createElement('div'); wrap.appendChild(l); wrap.appendChild(inp);
      wrap.style.gridColumn='1 / -1'; box.appendChild(wrap); continue;
    }
    box.appendChild(div);
  }
}
function buildDelays(){
  const box=$('delays'); box.innerHTML='';
  for (const k of Object.keys(DELAYS).sort()){
    const l=document.createElement('label'); l.className='row';
    const s=document.createElement('span'); s.textContent=k;
    const i=document.createElement('input'); i.type='number'; i.id='d_'+k; i.value=DELAYS[k];
    l.appendChild(s); l.appendChild(i); box.appendChild(l);
  }
}
function collectOptions(){
  const g = id => $(id).value;
  const settings={};
  for (const h of HIVE){
    const el=$('h_'+h.key); if(!el) continue;
    settings[h.key] = h.kind==='bool' ? (el.checked?'True':'False') : el.value;
  }
  settings['VirtualClientSlot']=$('VirtualClientSlot').value;
  const delays={};
  for (const k of Object.keys(DELAYS)){
    const el=$('d_'+k); if(el) delays[k]=parseInt(el.value||'0',10);
  }
  return { target_exe:g('target_exe'), server:g('server'),
    emulator_host:g('emulator_host'), emulator_port:parseInt(g('emulator_port')||'8080',10),
    version:g('version'), orythm:g('orythm'), prythm:g('prythm'),
    account_manager_startup:$('account_manager_startup').checked,
    response_file:g('response_file'), offsets_file:g('offsets_file'),
    device_name:g('device_name'), missing_providers:g('missing_providers'),
    login_all:$('login_all').checked, dry_run_launch:$('dry_run_launch').checked,
    settings, delays };
}
async function refresh(){
  const st = await api('/api/state');
  if (st.error){ setStatus('Status: cannot reach backend: '+st.error,'bad'); return; }
  HIVE=st.hive; SERVERS=st.servers; DELAYS=st.delays;
  fillServers(); buildHive(st.settings||{}); buildDelays();
  const o=st.options||{};
  $('target_exe').value=o.target_exe||''; $('server').value=o.server||SERVERS[4];
  $('VirtualClientSlot').value=(st.settings||{}).VirtualClientSlot||'Original';
  $('device_name').value=o.device_name||'';
  $('missing_providers').value=o.missing_providers||'';
  $('login_all').checked=!!o.login_all; $('dry_run_launch').checked=o.dry_run_launch!==false;
  $('emulator_host').value=o.emulator_host||'127.0.0.1';
  $('emulator_port').value=o.emulator_port||8080;
  $('version').value=o.version||'11.31'; $('orythm').value=o.orythm||'1'; $('prythm').value=o.prythm||'2';
  $('account_manager_startup').checked=o.account_manager_startup!==false;
  $('response_file').value=o.response_file||''; $('offsets_file').value=o.offsets_file||'';
  $('emuState').textContent='emulator: '+(st.emulator&&st.emulator.running
    ? ('RUNNING on '+st.emulator.url+' ('+st.emulator.auth_requests+' auth)') : 'stopped');
  renderAccounts(st.accounts||[]);
  if (st.last_report){
    renderReport(st.last_report);
    setStatus(st.last_report.status||'Status: ready', st.last_report.ok?'ok':'bad');
  } else setStatus('Status: ready','ok');
  if (st.workspace&&st.workspace.notes) for (const n of st.workspace.notes) log('note: '+n);
}
function renderAccounts(rows){
  ACCOUNTS=rows;
  const tb=$('accounts'); tb.innerHTML='';
  for (const r of rows){
    const tr=document.createElement('tr');
    for (const k of ['slot','Account','Client','GameAccount','LoginAll'])
      { const td=document.createElement('td'); td.textContent=r[k]||''; tr.appendChild(td); }
    const td=document.createElement('td');
    const b=document.createElement('button'); b.textContent='✕'; b.className='danger';
    b.style.padding='2px 8px';
    b.onclick=async()=>{ await api('/api/accounts?slot='+encodeURIComponent(r.slot),{method:'DELETE'});
      log('Status: deleted account ['+r.slot+']'); refresh(); };
    td.appendChild(b); tr.appendChild(td); tb.appendChild(tr);
  }
}
function renderReport(rep){
  const box=$('steps'); box.innerHTML='';
  for (const s of (rep.steps||[])){
    const d=document.createElement('div'); d.className='step '+(s.ok?'ok':'bad');
    const h=document.createElement('h3'); h.textContent=(s.ok?'✓ ':'✕ ')+s.name+' — '+s.status;
    d.appendChild(h);
    for (const w of (s.warnings||[])){ const p=document.createElement('div');
      p.className='warn'; p.textContent='warn: '+w; d.appendChild(p); }
    const pre=document.createElement('pre');
    pre.textContent=JSON.stringify(s.details||{},null,1).slice(0,2000);
    d.appendChild(pre); box.appendChild(d);
  }
  $('reportJson').textContent=JSON.stringify(rep,null,1);
}
$('btnRun').onclick=async()=>{
  $('btnRun').disabled=true; setStatus('Status: running automatic..');
  log('Status: starting automatic run..');
  try{
    const rep=await api('/api/run',{method:'POST',body:JSON.stringify(collectOptions())});
    renderReport(rep);
    setStatus(rep.status||'Status: done', rep.ok?'ok':'bad');
    log(rep.status||'done');
    for (const s of (rep.steps||[])) log('  ['+(s.ok?'OK':'FAIL')+'] '+s.name+': '+s.status);
  }catch(e){ setStatus('Status: run failed: '+e,'bad'); log('run failed: '+e); }
  $('btnRun').disabled=false; refresh();
};
$('btnSave').onclick=async()=>{
  const r=await api('/api/options',{method:'POST',body:JSON.stringify(collectOptions())});
  log(r.ok?'Status: options saved':'save failed: '+(r.error||'unknown'));
};
$('btnReload').onclick=refresh;
$('btnEmuStart').onclick=async()=>{
  const r=await api('/api/emulator/start',{method:'POST',body:JSON.stringify(collectOptions())});
  log(r.ok?('Status: emulator running on '+r.url):('emulator start failed: '+(r.error||'')));
  refresh();
};
$('btnEmuStop').onclick=async()=>{ await api('/api/emulator/stop',{method:'POST'}); log('Status: emulator stopped'); refresh(); };
$('btnAccountSave').onclick=async()=>{
  const acc={slot:$('a_slot').value,Account:$('a_Account').value,Password:$('a_Password').value,
    Client:$('a_Client').value,GameAccount:$('a_GameAccount').value,Notes:$('a_Notes').value,
    LoginAll:$('a_LoginAll').checked?'1':'0'};
  if(!acc.slot){ log('account slot is required'); return; }
  const r=await api('/api/accounts',{method:'POST',body:JSON.stringify(acc)});
  log(r.ok?('Status: saved account ['+acc.slot+']'):('save failed: '+(r.error||'')));
  $('a_Password').value=''; refresh();
};
$('btnDelays').onclick=async()=>{
  const delays={}; for (const k of Object.keys(DELAYS)){ delays[k]=parseInt($('d_'+k).value||'0',10); }
  const r=await api('/api/delays',{method:'POST',body:JSON.stringify(delays)});
  log(r.ok?'Status: delays saved':'delays failed: '+(r.error||''));
};
refresh();
setInterval(async()=>{ const st=await api('/api/state');
  if(st&&st.emulator) $('emuState').textContent='emulator: '+(st.emulator.running
    ?('RUNNING on '+st.emulator.url+' ('+st.emulator.auth_requests+' auth)'):'stopped'); },5000);
</script>
</body>
</html>
"""


class WebState:
    """Mutable backend state shared by the request handler."""

    def __init__(self, workspace: Path, options: C.AutomaticOptions):
        self.workspace = workspace
        self.options = options
        self.lock = threading.Lock()
        self.last_report: dict[str, Any] | None = None
        self.log_lines: list[str] = []
        self.emulator: EmulatorHTTPServer | None = None
        self.emulator_thread: threading.Thread | None = None
        self.emulator_url: str = ""

    def log(self, message: str) -> None:
        with self.lock:
            self.log_lines.append(message)
            del self.log_lines[:-500]


def _options_from_json(payload: dict[str, Any],
                       base: C.AutomaticOptions) -> C.AutomaticOptions:
    opts = C.AutomaticOptions(
        target_exe=str(payload.get("target_exe", base.target_exe or "")),
        server=str(payload.get("server", base.server)),
        emulator_host=str(payload.get("emulator_host", base.emulator_host)),
        emulator_port=int(payload.get("emulator_port", base.emulator_port)),
        version=str(payload.get("version", base.version)),
        orythm=str(payload.get("orythm", base.orythm)),
        prythm=str(payload.get("prythm", base.prythm)),
        account_manager_startup=bool(payload.get("account_manager_startup", True)),
        response_file=str(payload.get("response_file", "")),
        offsets_file=str(payload.get("offsets_file", "")),
        device_name=str(payload.get("device_name", "")),
        missing_providers=str(payload.get("missing_providers", "")),
        login_all=bool(payload.get("login_all", False)),
        dry_run_launch=bool(payload.get("dry_run_launch", True)),
        settings=dict(payload.get("settings", base.settings or {})),
        delays={k: int(v) for k, v in dict(payload.get("delays", {})).items()},
    )
    return opts


class WebHandler(BaseHTTPRequestHandler):
    server: WebServer  # type: ignore[name-defined]
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: object) -> None:
        LOG.info("%s - %s", self.address_string(), fmt % args)

    # -- helpers ------------------------------------------------------
    def _json(self, status: int, payload: Any) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body_json(self) -> dict[str, Any]:
        try:
            length = max(0, int(self.headers.get("Content-Length", "0")))
        except ValueError:
            length = 0
        raw = self.rfile.read(min(length, 4 * 1024 * 1024))
        if not raw:
            return {}
        try:
            value = json.loads(raw.decode("utf-8"))
            return value if isinstance(value, dict) else {}
        except ValueError:
            return {}

    @property
    def state(self) -> WebState:
        return self.server.state

    # -- routes --------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802
        route = urlsplit(self.path).path
        if route in {"/", "/index.html"}:
            body = DASHBOARD_HTML.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if route == "/api/state":
            self._json(200, self._state_payload())
            return
        if route == "/api/log":
            with self.state.lock:
                lines = list(self.state.log_lines)
            self._json(200, {"lines": lines})
            return
        self._json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        route = urlsplit(self.path).path
        if route == "/api/options":
            payload = self._body_json()
            with self.state.lock:
                self.state.options = _options_from_json(payload, self.state.options)
                self._persist_options_locked()
            self._json(200, {"ok": True})
            return
        if route == "/api/run":
            payload = self._body_json()
            with self.state.lock:
                self.state.options = _options_from_json(payload, self.state.options)
                options = self.state.options
            report = run_automatic(options, self.state.workspace, log=self.state.log)
            with self.state.lock:
                self.state.last_report = report.as_dict()
                self._persist_options_locked()
            self._json(200, report.as_dict())
            return
        if route == "/api/emulator/start":
            payload = self._body_json()
            if payload:
                with self.state.lock:
                    self.state.options = _options_from_json(payload, self.state.options)
            result = self._emulator_start()
            self._json(200 if result.get("ok") else 500, result)
            return
        if route == "/api/emulator/stop":
            self._json(200, self._emulator_stop())
            return
        if route == "/api/accounts":
            payload = self._body_json()
            self._json(200, self._save_account(payload))
            return
        if route == "/api/delays":
            payload = self._body_json()
            self._json(200, self._save_delays(payload))
            return
        self._json(404, {"error": "not found"})

    def do_DELETE(self) -> None:  # noqa: N802
        split = urlsplit(self.path)
        if split.path == "/api/accounts":
            from urllib.parse import parse_qs
            query = parse_qs(split.query)
            slot = (query.get("slot") or [""])[-1]
            self._json(200, self._delete_account(slot))
            return
        self._json(404, {"error": "not found"})

    # -- payload builders ----------------------------------------------
    def _state_payload(self) -> dict[str, Any]:
        with self.state.lock:
            options = self.state.options
            last = self.state.last_report
            emu_running = self.state.emulator is not None
            emu_url = self.state.emulator_url
            auth_count = 0
            req_count = 0
            if self.state.emulator is not None:
                auth_count = self.state.emulator.config.auth_count
                req_count = self.state.emulator.config.request_count
        settings_path = self.state.workspace / "settings.json"
        settings = dict(C.HIVE_DEFAULTS)
        settings.update(load_settings_file(settings_path))
        settings.update(options.settings or {})
        logins_path = self.state.workspace / "logins.ini"
        parser = read_logins(logins_path)
        delays = dict(C.DELAY_DEFAULTS)
        if parser.has_section("Delay"):
            for key, value in parser["Delay"].items():
                try:
                    delays[key] = int(value)
                except ValueError:
                    pass
        delays.update(options.delays or {})
        accounts = [
            {k: v for k, v in row.items() if k != "Password"}
            | {"Password": "***" if row.get("Password") else ""}
            for row in list_accounts(parser)
        ]
        hive = [{"key": o.key, "label": o.label, "default": o.default,
                 "kind": o.kind, "tooltip": o.tooltip} for o in C.HIVE_OPTIONS]
        return {
            "options": options.as_dict(),
            "settings": settings,
            "servers": list(C.SERVERS),
            "hive": hive,
            "delays": delays,
            "accounts": accounts,
            "last_report": last,
            "workspace": str(self.state.workspace),
            "logins_ini": str(logins_path),
            "emulator": {"running": emu_running, "url": emu_url,
                         "auth_requests": auth_count, "requests": req_count},
        }

    def _persist_options_locked(self) -> None:
        ws = self.state.workspace
        ws.mkdir(parents=True, exist_ok=True)
        try:
            (ws / "web_options.json").write_text(
                json.dumps(self.state.options.as_dict(), indent=2) + "\n",
                encoding="utf-8")
            settings = self.state.options.merged_settings()
            save_settings_file(ws / "settings.json", settings)
            logins_path = ws / "logins.ini"
            parser = read_logins(logins_path)
            if not parser.has_section("Delay"):
                parser = build_default_logins(self.state.options.merged_delays())
                write_logins(logins_path, parser)
        except OSError as exc:
            LOG.warning("cannot persist web options: %s", exc)

    # -- emulator lifecycle ---------------------------------------------
    def _emulator_start(self) -> dict[str, Any]:
        with self.state.lock:
            if self.state.emulator is not None:
                return {"ok": True, "url": self.state.emulator_url,
                        "note": "already running"}
            options = self.state.options
        config = EmulatorConfig(
            version=options.version, orythm=options.orythm,
            prythm=options.prythm,
            account_manager_startup=options.account_manager_startup,
        )
        if options.response_file:
            p = Path(options.response_file)
            if not p.is_file():
                return {"ok": False, "error": f"response file not found: {p}"}
            config.response_file = p
            config.account_manager_startup = False
        if options.offsets_file:
            from .offsets import load_offsets_file
            try:
                config.offsets_text = load_offsets_file(Path(options.offsets_file))
            except (OSError, ValueError) as exc:
                return {"ok": False, "error": f"bad offsets file: {exc}"}
        try:
            httpd = EmulatorHTTPServer((options.emulator_host, options.emulator_port),
                                       config)
        except OSError as exc:
            return {"ok": False, "error": f"cannot bind: {exc}"}
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        url = f"http://{options.emulator_host}:{httpd.server_address[1]}"
        with self.state.lock:
            self.state.emulator = httpd
            self.state.emulator_thread = thread
            self.state.emulator_url = url
        self.state.log(f"Status: emulator running on {url}")
        return {"ok": True, "url": url}

    def _emulator_stop(self) -> dict[str, Any]:
        with self.state.lock:
            httpd = self.state.emulator
            thread = self.state.emulator_thread
            self.state.emulator = None
            self.state.emulator_thread = None
            self.state.emulator_url = ""
        if httpd is None:
            return {"ok": True, "note": "already stopped"}
        httpd.shutdown()
        httpd.server_close()
        if thread is not None:
            thread.join(timeout=2)
        self.state.log("Status: emulator stopped")
        return {"ok": True}

    # -- accounts / delays -----------------------------------------------
    def _save_account(self, payload: dict[str, Any]) -> dict[str, Any]:
        slot = str(payload.get("slot", "")).strip()
        if not slot:
            return {"ok": False, "error": "slot is required"}
        if len(slot) > 32 or any(c in slot for c in "[]=\n\r"):
            return {"ok": False, "error": "bad slot name"}
        logins_path = self.state.workspace / "logins.ini"
        parser = read_logins(logins_path)
        if not parser.sections():
            parser = build_default_logins(self.state.options.merged_delays())
        for section in C.PER_ACCOUNT_SECTIONS:
            if not parser.has_section(section):
                parser[section] = {}
        for section in ("Account", "Password", "NCAccount", "NCMultiAccount",
                        "GFAccount", "GameAccount", "Client", "Notes", "LoginAll"):
            if section in payload and payload[section] != "":
                parser[section][slot] = str(payload[section])
            elif section == "LoginAll" and "LoginAll" in payload:
                parser[section][slot] = str(payload[section])
        client = str(payload.get("Client", ""))
        if client and client not in C.SERVERS:
            return {"ok": False, "error": f"unknown client preset: {client!r}"}
        try:
            count = len([s for s in parser["Account"].keys()]) if parser.has_section("Account") else 0
            if not parser.has_section("Main"):
                parser["Main"] = {}
            parser["Main"]["Accounts"] = str(count)
            write_logins(logins_path, parser)
        except OSError as exc:
            return {"ok": False, "error": str(exc)}
        # Never log the password.
        self.state.log(f"Status: saved account [{slot}]")
        return {"ok": True}

    def _delete_account(self, slot: str) -> dict[str, Any]:
        slot = (slot or "").strip()
        if not slot:
            return {"ok": False, "error": "slot is required"}
        logins_path = self.state.workspace / "logins.ini"
        parser = read_logins(logins_path)
        for section in C.PER_ACCOUNT_SECTIONS:
            if parser.has_section(section) and slot in parser[section]:
                del parser[section][slot]
        try:
            write_logins(logins_path, parser)
        except OSError as exc:
            return {"ok": False, "error": str(exc)}
        self.state.log(f"Status: deleted account [{slot}]")
        return {"ok": True}

    def _save_delays(self, payload: dict[str, Any]) -> dict[str, Any]:
        logins_path = self.state.workspace / "logins.ini"
        parser = read_logins(logins_path)
        if not parser.sections():
            parser = build_default_logins(self.state.options.merged_delays())
        if not parser.has_section("Delay"):
            parser["Delay"] = {}
        for key, value in payload.items():
            if key in C.DELAY_DEFAULTS:
                try:
                    parser["Delay"][key] = str(int(value))
                except (TypeError, ValueError):
                    return {"ok": False, "error": f"bad delay value for {key!r}"}
        try:
            write_logins(logins_path, parser)
        except OSError as exc:
            return {"ok": False, "error": str(exc)}
        self.state.log("Status: delays saved")
        return {"ok": True}


class WebServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], state: WebState):
        super().__init__(address, WebHandler)
        self.state = state


def load_saved_options(workspace: Path) -> C.AutomaticOptions:
    path = workspace / "web_options.json"
    if not path.is_file():
        # Seed the target from the repo's game.dll copy when present so the
        # first run has something to audit.
        seed = ""
        guess = Path(__file__).resolve().parents[1] / "game.dll"
        if guess.is_file():
            seed = str(guess)
        return C.AutomaticOptions(target_exe=seed)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return C.AutomaticOptions()
    base = C.AutomaticOptions()
    if isinstance(payload, dict):
        return _options_from_json(payload, base)
    return base


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Browser GUI for the Account Manager automatic lab")
    parser.add_argument("--bind", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8090)
    parser.add_argument("--workspace", type=Path, default=DEFAULT_WORKSPACE)
    parser.add_argument("-v", "--verbose", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING,
                        format="%(asctime)s %(levelname)s %(message)s")
    workspace = Path(args.workspace)
    workspace.mkdir(parents=True, exist_ok=True)
    state = WebState(workspace, load_saved_options(workspace))
    httpd = WebServer((args.bind, args.port), state)
    LOG.warning("Account Manager automatic GUI at http://%s:%d",
                args.bind, httpd.server_address[1])
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
