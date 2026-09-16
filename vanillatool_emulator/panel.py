"""Browser control panel for Account Manager 5.43 local automation.

The tkinter desktop GUI (:mod:`vanillatool_emulator.gui`) is the
Windows-first front-end.  This module serves the *same* options and the
same one-click :class:`~vanillatool_emulator.local.AutoFlow` chain over
plain HTTP using only the standard library, so the full workflow can be
driven from any browser — including this sandbox's live preview, where no
Windows desktop exists::

    python -m vanillatool_emulator.panel --port 8090

Then open the preview URL.  All automation itself lives in
:mod:`vanillatool_emulator.local`; this file only renders forms and shows
results.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import argparse
import html
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

from . import local as L


@dataclass
class PanelState:
    flow: L.AutoFlow = field(default_factory=L.AutoFlow)
    logs: list[str] = field(default_factory=list)
    last_report: dict[str, Any] | None = None
    last_transcripts: str = ""
    lock: threading.Lock = field(default_factory=threading.Lock)

    def log(self, message: str) -> None:
        with self.lock:
            self.logs.append(message)
            del self.logs[:-300]


def _form(body: bytes) -> dict[str, str]:
    values = parse_qs(body.decode("utf-8", errors="replace"),
                      keep_blank_values=True)
    return {key: items[-1] for key, items in values.items()}


def _options_from_form(form: dict[str, str], state: PanelState) -> L.AutoOptions:
    workdir = Path(form.get("workdir", "") or (Path.cwd() / "am_workdir"))
    game_dir_raw = form.get("game_dir", "").strip()
    try:
        port = int(form.get("port", "8080") or 8080)
    except ValueError:
        port = 8080
    providers: list[int | None] = []
    for key, prv in (("prv1", 1), ("prv2", 2), ("prv3", 3), ("prv0", None)):
        if form.get(key, "on" if key != "prv0" else "on") == "on":
            providers.append(prv)
    # HTML checkboxes only submit when checked; default everything on.
    if not any(k in form for k in ("prv1", "prv2", "prv3", "prv0")):
        providers = [1, 2, 3, None]
    response_raw = form.get("response_file", "").strip()
    offsets_raw = form.get("offsets_file", "").strip()
    logins_raw = form.get("logins_path", "").strip()
    target_raw = form.get("target_exe", "").strip()
    return L.AutoOptions(
        workdir=workdir,
        game_dir=Path(game_dir_raw) if game_dir_raw else None,
        server_preset=form.get("server_preset", L.SERVER_PRESETS[0]),
        device_name_value=form.get("device_name", "").strip(),
        providers=tuple(providers) or (None,),
        bind=form.get("bind", "127.0.0.1") or "127.0.0.1",
        port=port,
        orythm=form.get("orythm", "1") or "1",
        prythm=form.get("prythm", "2") or "2",
        account_manager_startup=form.get("am_startup", "on") == "on",
        response_file=Path(response_raw) if response_raw else None,
        offsets_file=Path(offsets_raw) if offsets_raw else None,
        apply_hosts=form.get("apply_hosts", "off") == "on",
        run_mapping=form.get("run_mapping", "on") == "on",
        force_simulated_mapping=form.get("force_sim", "off") == "on",
        prepare_gamedll=form.get("prepare_gamedll", "on") == "on",
        start_server=form.get("start_server", "on") == "on",
        logins_path=Path(logins_raw) if logins_raw else workdir / "logins.ini",
        target_exe=Path(target_raw) if target_raw else None,
    )


CSS = """
body{font-family:system-ui,Segoe UI,Roboto,sans-serif;max-width:1020px;margin:0 auto;
padding:16px;background:#14161a;color:#e8e8e8}
h1{font-size:20px}h2{font-size:16px;margin-top:22px;border-bottom:1px solid #333;padding-bottom:4px}
.card{background:#1d2026;border:1px solid #333;border-radius:8px;padding:12px;margin:10px 0}
label{display:inline-block;min-width:170px;margin:3px 0}
input[type=text],input[type=number],select{width:340px;max-width:60vw;background:#111;color:#eee;
border:1px solid #444;border-radius:4px;padding:4px}
button,.btn{background:#2f6fed;color:#fff;border:0;border-radius:6px;padding:8px 14px;
font-size:14px;cursor:pointer;margin:4px 6px 4px 0}
button.secondary{background:#3a3f47}
pre{background:#0e0f12;border:1px solid #333;border-radius:6px;padding:10px;overflow:auto;
max-height:300px;white-space:pre-wrap}
.ok{color:#7dffa8}.err{color:#ff9d9d}.warn{color:#ffd479}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:10px}
@media(max-width:800px){.grid{grid-template-columns:1fr}}
small{color:#999}
"""


def render_dashboard(state: PanelState, notice: str = "") -> str:
    with state.lock:
        logs = list(state.logs[-40:])
        report = state.last_report
        transcripts = state.last_transcripts
    running = state.flow.supervisor.running
    sup = state.flow.supervisor.status() if running else None

    def esc(value: Any) -> str:
        return html.escape(str(value))

    if report is not None:
        steps = "".join(
            f"<div class=\"{'ok' if s['ok'] else 'err'}\">"
            f"{'OK' if s['ok'] else 'FAIL'} {esc(s['step'])}: {esc(s['detail'])}</div>"
            for s in report.get("steps", []))
        warns = "".join(f"<div class=\"warn\">warning: {esc(w)}</div>"
                        for w in report.get("warnings", []))
        report_html = (f"<div class=\"card\"><h2>Last Full Auto: "
                       f"{esc(report.get('status', ''))}</h2>{steps}{warns}</div>")
    else:
        report_html = ""

    server_html = ("<b class=\"ok\">running</b> "
                   f"{esc(sup.bind)}:{esc(sup.port)} "
                   f"(requests={sup.requests}, auth={sup.auth_requests}, "
                   f"profile={esc(sup.auth_profile)})" if sup
                   else "<b>stopped</b>")
    payload_rows = "".join(
        f"<div>[{'OK' if i.found else 'MISS'}] {esc(i.spec.staged_name)} "
        f"({i.actual_size or '-'}/{i.spec.expected_size}) — "
        f"{esc(i.spec.description)}</div>"
        for i in state.flow.stager.inventory())
    options = "".join(f"<option>{esc(p)}</option>" for p in L.SERVER_PRESETS)
    log_html = esc("\n".join(logs)) if logs else "(no log lines yet)"
    transcript_html = (f"<h2>Mapper transcripts</h2><pre>{esc(transcripts)}</pre>"
                       if transcripts else "")
    notice_html = f"<div class=\"card\">{notice}</div>" if notice else ""
    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>Account Manager 5.43 — Local Console</title><style>{CSS}</style></head><body>
<h1>Para's Account Manager — Local Console (5.43)</h1>
<p><small>Emulator: {server_html} &nbsp;|&nbsp; Admin: {esc(L.is_admin())} &nbsp;|&nbsp;
Platform: {esc(sys.platform)} &nbsp;|&nbsp;
<a style="color:#8ab4ff" href="/api/status">/api/status</a></small></p>
{notice_html}
{report_html}
<form method="post" action="/api/full-auto"><div class="card"><h2>Full Auto chain</h2>
<div class="grid"><div>
<label>Workdir</label><input type="text" name="workdir" value="am_workdir"><br>
<label>Device name (11 chars)</label><input type="text" name="device_name" value="" placeholder="empty = reuse registry"><br>
<label>Game dir</label><input type="text" name="game_dir" value="" placeholder="holds bin64/aion.bin"><br>
<label>Server preset</label><select name="server_preset">{options}</select><br>
<label>logins.ini</label><input type="text" name="logins_path" value="am_workdir/logins.ini"><br>
<label>Target EXE</label><input type="text" name="target_exe" value="" placeholder="original Account Manager exe"><br>
</div><div>
<label>Bind</label><input type="text" name="bind" value="127.0.0.1"><br>
<label>Port</label><input type="text" name="port" value="8080"><br>
<label>ORythm</label><input type="text" name="orythm" value="1"><br>
<label>PRythm</label><input type="text" name="prythm" value="2"><br>
<label>Response file</label><input type="text" name="response_file" value=""><br>
<label>Offsets file</label><input type="text" name="offsets_file" value=""><br>
</div></div>
<label><input type="checkbox" name="am_startup" checked> pre-GUI markers</label>
<label><input type="checkbox" name="run_mapping" checked> run mapping</label>
<label><input type="checkbox" name="force_sim"> force simulated mapping</label>
<label><input type="checkbox" name="prepare_gamedll" checked> prepare game.dll</label>
<label><input type="checkbox" name="start_server" checked> start emulator</label>
<label><input type="checkbox" name="apply_hosts"> apply hosts redirect</label><br>
<label><input type="checkbox" name="prv1" checked> -prv 1 RTCore64</label>
<label><input type="checkbox" name="prv2" checked> -prv 2 Gdrv</label>
<label><input type="checkbox" name="prv3" checked> -prv 3 ATSZIO64</label>
<label><input type="checkbox" name="prv0" checked> bare -map</label><br>
<button type="submit">FULL AUTO</button>
<small>Stages drivers/DLLs → patches device names → runs the mapper ladder →
preps game.dll → (hosts) → starts the emulator, in AM's order.</small>
</div></form>
<div class="grid">
<div class="card"><h2>Steps</h2>
<form method="post" action="/api/stage"><button class="secondary" type="submit">Stage drivers/DLLs</button>
<input type="text" name="workdir" value="am_workdir" style="width:170px"></form>
<form method="post" action="/api/map"><button class="secondary" type="submit">Run mapping</button>
<input type="text" name="workdir" value="am_workdir" style="width:170px"></form>
<form method="post" action="/api/server-stop"><button class="secondary" type="submit">Stop emulator</button></form>
<form method="post" action="/api/hosts-restore"><button class="secondary" type="submit">Restore hosts</button></form>
</div>
<div class="card"><h2>Payload inventory</h2>{payload_rows}</div>
</div>
<div class="card"><h2>NCGuard plan</h2>
<small>aion.bin+{hex(L.AION_BIN_NCGUARD_OFFSET)} / CrySystem.dll+{hex(L.CRYSYSTEM_NCGUARD_OFFSET)}
({L.NCGUARD_SLOT_SIZE}B) → {esc(L.NCGUARD_REPLACEMENT.decode())} &nbsp;|&nbsp;
{esc(L.WINDOW_CLASS_ORIGINAL)} → {esc(L.WINDOW_CLASS_SPOOFED)} &nbsp;|&nbsp;
hooks {esc(L.NCGUARD_HOOK_PATTERN)}</small></div>
{transcript_html}
<h2>Log</h2><pre>{log_html}</pre>
</body></html>"""


class PanelHandler(BaseHTTPRequestHandler):
    server: ThreadingHTTPServer  # type: ignore[assignment]
    protocol_version = "HTTP/1.1"

    @property
    def state(self) -> PanelState:
        return self.server.state  # type: ignore[attr-defined]

    def log_message(self, format: str, *args: object) -> None:  # noqa: N802
        pass

    def _body(self) -> bytes:
        try:
            length = max(0, int(self.headers.get("Content-Length", "0")))
        except ValueError:
            length = 0
        return self.rfile.read(min(length, 256 * 1024))

    def _write(self, status: int, body: bytes | str,
               content_type: str = "text/html; charset=utf-8") -> None:
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _redirect(self, location: str) -> None:
        self.send_response(303)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        route = urlsplit(self.path).path.rstrip("/") or "/"
        if route == "/":
            self._write(200, render_dashboard(self.state))
        elif route == "/api/status":
            sup = (self.state.flow.supervisor.status()
                   if self.state.flow.supervisor.running
                   else {"running": False})
            if not isinstance(sup, dict):
                sup = {"running": sup.running, "bind": sup.bind,
                       "port": sup.port, "scheme": sup.scheme,
                       "requests": sup.requests,
                       "auth_requests": sup.auth_requests,
                       "auth_profile": sup.auth_profile}
            with self.state.lock:
                payload = {"supervisor": sup,
                           "last_report": self.state.last_report,
                           "logs": self.state.logs[-40:]}
            self._write(200, json.dumps(payload, indent=2),
                        "application/json; charset=utf-8")
        else:
            self._write(404, "not found", "text/plain; charset=utf-8")

    def do_POST(self) -> None:  # noqa: N802
        route = urlsplit(self.path).path.rstrip("/") or "/"
        form = _form(self._body())
        try:
            if route == "/api/full-auto":
                options = _options_from_form(form, self.state)
                self.state.log(f"[start] {options.workdir} preset={options.server_preset}")
                report = self.state.flow.run(
                    options, progress=lambda s, m: self.state.log(f"[{s}] {m}"))
                with self.state.lock:
                    self.state.last_report = {
                        "ok": report.ok, "status": report.status,
                        "steps": report.steps, "hints": report.hints,
                        "warnings": report.warnings,
                    }
                self.state.log(report.status)
                self._redirect("/")
            elif route == "/api/stage":
                workdir = Path(form.get("workdir", "am_workdir"))
                result = self.state.flow.stager.stage(workdir)
                self.state.log(f"staged={result.staged} missing={result.missing}")
                self._redirect("/")
            elif route == "/api/map":
                workdir = Path(form.get("workdir", "am_workdir"))
                ladder = L.MapperRunner(workdir).run_ladder()
                chunks = []
                for step in ladder.steps:
                    chunks.append(f"$ udk {' '.join(step.argv)} -> {step.outcome}")
                    chunks.append(step.transcript)
                with self.state.lock:
                    self.state.last_transcripts = "\n".join(chunks)
                self.state.log(f"mapping: mapped={ladder.mapped}")
                self._redirect("/")
            elif route == "/api/server-stop":
                self.state.flow.supervisor.stop()
                self.state.log("emulator stopped")
                self._redirect("/")
            elif route == "/api/hosts-restore":
                ok = L.HostsManager().restore()
                self.state.log(f"hosts restore: {ok}")
                self._redirect("/")
            else:
                self._write(404, "not found", "text/plain; charset=utf-8")
        except Exception as exc:
            self.state.log(f"error: {exc}")
            self._write(200, render_dashboard(
                self.state, notice=f"<b class=\"err\">error: "
                                   f"{html.escape(str(exc))}</b>"))


class PanelServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], state: PanelState | None = None):
        super().__init__(address, PanelHandler)
        self.state = state or PanelState()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Browser control panel for Account Manager local automation")
    parser.add_argument("--bind", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8090)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    server = PanelServer((args.bind, args.port))
    print(f"Account Manager console at http://{args.bind}:{server.server_address[1]}",
          flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
