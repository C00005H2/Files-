"""Desktop (Tk) GUI for the Account Manager automatic build.

This is the Windows-familiar front-end: same options, same one-click
Automatic Run, same ``Status: ...`` line as the original tool, but driving
the safe :mod:`am_pipeline` backend (emulated mapper, read-only target audit,
plan-only Auto-Inject).

Tkinter ships with CPython on Windows, so there is nothing to install::

    python -m vanillatool_emulator.am_gui

On machines without Tk (minimal Linux containers) use the browser GUI
instead::

    python -m vanillatool_emulator.am_web --port 8090

The module imports safely without Tk (``tkinter`` is only required inside
:func:`main`) so tests and headless hosts can still import the option
definitions.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from . import am_config as C
from .am_workspace import DEFAULT_WORKSPACE


def describe_layout() -> dict[str, Any]:
    """Return the GUI structure (used by tests without needing Tk)."""
    return {
        "title": f"{C.APP_NAME} {C.APP_VERSION}",
        "tabs": ["Run", "Accounts", "Options", "Delays", "Files", "Log"],
        "servers": list(C.SERVERS),
        "slots": ["Original"] + [f"Virtual Client [{i}]" for i in range(1, 10)],
        "checkboxes": [o.key for o in C.HIVE_OPTIONS if o.kind == "bool"],
        "int_fields": [o.key for o in C.HIVE_OPTIONS if o.kind == "int"],
        "text_fields": [o.key for o in C.HIVE_OPTIONS if o.kind == "text"],
        "primary_action": "Automatic Run",
    }


def main(argv: list[str] | None = None) -> int:  # pragma: no cover - needs a display
    import argparse
    import queue
    import threading
    import tkinter as tk
    from tkinter import filedialog, messagebox, scrolledtext, ttk

    from .am_pipeline import run_automatic
    from .am_workspace import list_accounts, read_logins
    from .server import EmulatorConfig, EmulatorHTTPServer

    parser = argparse.ArgumentParser(description="Account Manager automatic desktop GUI")
    parser.add_argument("--workspace", type=Path, default=DEFAULT_WORKSPACE)
    args = parser.parse_args(argv)
    workspace = Path(args.workspace)
    workspace.mkdir(parents=True, exist_ok=True)

    root = tk.Tk()
    root.title(f"{C.APP_NAME} {C.APP_VERSION}")
    root.geometry("980x720")

    status_var = tk.StringVar(value="Status: ready")
    log_queue: queue.Queue[str] = queue.Queue()
    emulator_holder: dict[str, Any] = {"httpd": None, "thread": None}

    # -- state variables -------------------------------------------------
    target_var = tk.StringVar()
    guess = Path(__file__).resolve().parents[1] / "game.dll"
    if guess.is_file():
        target_var.set(str(guess))
    server_var = tk.StringVar(value="EuroAion")
    slot_var = tk.StringVar(value="Original")
    device_var = tk.StringVar()
    missing_var = tk.StringVar()
    login_all_var = tk.BooleanVar(value=False)
    dry_run_var = tk.BooleanVar(value=True)
    host_var = tk.StringVar(value="127.0.0.1")
    port_var = tk.StringVar(value="8080")
    version_var = tk.StringVar(value=C.EMULATOR_VERSION_DEFAULT)
    orythm_var = tk.StringVar(value=C.DEFAULT_ORYTHM)
    prythm_var = tk.StringVar(value=C.DEFAULT_PRHYTHM)
    startup_var = tk.BooleanVar(value=True)
    response_var = tk.StringVar()
    offsets_var = tk.StringVar()
    hive_vars: dict[str, Any] = {}
    for opt in C.HIVE_OPTIONS:
        if opt.kind == "bool":
            hive_vars[opt.key] = tk.BooleanVar(value=opt.default == "True")
        else:
            hive_vars[opt.key] = tk.StringVar(value=opt.default)

    def log(msg: str) -> None:
        log_queue.put(msg)

    def collect_options() -> C.AutomaticOptions:
        try:
            port = int(port_var.get() or "8080")
        except ValueError:
            port = 8080
        settings: dict[str, str] = {}
        for opt in C.HIVE_OPTIONS:
            var = hive_vars[opt.key]
            if opt.kind == "bool":
                settings[opt.key] = "True" if var.get() else "False"
            else:
                settings[opt.key] = var.get()
        settings["VirtualClientSlot"] = slot_var.get()
        return C.AutomaticOptions(
            target_exe=target_var.get().strip(),
            server=server_var.get(),
            emulator_host=host_var.get().strip() or "127.0.0.1",
            emulator_port=port,
            version=version_var.get().strip() or C.EMULATOR_VERSION_DEFAULT,
            orythm=orythm_var.get().strip() or "1",
            prythm=prythm_var.get().strip() or "2",
            account_manager_startup=startup_var.get(),
            response_file=response_var.get().strip(),
            offsets_file=offsets_var.get().strip(),
            device_name=device_var.get().strip(),
            missing_providers=missing_var.get().strip(),
            login_all=login_all_var.get(),
            dry_run_launch=dry_run_var.get(),
            settings=settings,
        )

    # -- top status --------------------------------------------------------
    top = ttk.Frame(root, padding=8)
    top.pack(fill=tk.X)
    ttk.Label(top, textvariable=status_var, font=("Consolas", 10)).pack(side=tk.LEFT)

    notebook = ttk.Notebook(root)
    notebook.pack(fill=tk.BOTH, expand=True, padx=8, pady=4)

    # -- Run tab -----------------------------------------------------------
    run_tab = ttk.Frame(notebook, padding=8)
    notebook.add(run_tab, text="Run")
    row = ttk.Frame(run_tab)
    row.pack(fill=tk.X, pady=2)
    ttk.Label(row, text="Target EXE:", width=14).pack(side=tk.LEFT)
    ttk.Entry(row, textvariable=target_var, width=70).pack(side=tk.LEFT, fill=tk.X, expand=True)

    def browse_target() -> None:
        path = filedialog.askopenfilename(title="Select target exe (aion.bin or copy)")
        if path:
            target_var.set(path)

    ttk.Button(row, text="Browse..", command=browse_target).pack(side=tk.LEFT, padx=4)
    row2 = ttk.Frame(run_tab)
    row2.pack(fill=tk.X, pady=2)
    ttk.Label(row2, text="Server:", width=14).pack(side=tk.LEFT)
    ttk.Combobox(row2, textvariable=server_var, values=list(C.SERVERS),
                 state="readonly", width=20).pack(side=tk.LEFT)
    ttk.Label(row2, text="Slot:").pack(side=tk.LEFT, padx=(12, 2))
    ttk.Combobox(row2, textvariable=slot_var,
                 values=["Original"] + [f"Virtual Client [{i}]" for i in range(1, 10)],
                 state="readonly", width=20).pack(side=tk.LEFT)
    ttk.Checkbutton(row2, text="Login All", variable=login_all_var).pack(side=tk.LEFT, padx=8)
    ttk.Checkbutton(row2, text="Dry-run launch", variable=dry_run_var).pack(side=tk.LEFT)
    row3 = ttk.Frame(run_tab)
    row3.pack(fill=tk.X, pady=2)
    ttk.Label(row3, text="Device name:", width=14).pack(side=tk.LEFT)
    ttk.Entry(row3, textvariable=device_var, width=16).pack(side=tk.LEFT)
    ttk.Label(row3, text="Blocked providers:").pack(side=tk.LEFT, padx=(12, 2))
    ttk.Entry(row3, textvariable=missing_var, width=10).pack(side=tk.LEFT)
    ttk.Label(row3, text="Emu host:").pack(side=tk.LEFT, padx=(12, 2))
    ttk.Entry(row3, textvariable=host_var, width=12).pack(side=tk.LEFT)
    ttk.Label(row3, text="port:").pack(side=tk.LEFT, padx=(6, 2))
    ttk.Entry(row3, textvariable=port_var, width=7).pack(side=tk.LEFT)

    steps_box = scrolledtext.ScrolledText(run_tab, height=16, font=("Consolas", 9))
    steps_box.pack(fill=tk.BOTH, expand=True, pady=6)

    btn_row = ttk.Frame(run_tab)
    btn_row.pack(fill=tk.X)

    def set_status(msg: str) -> None:
        status_var.set(msg)
        log(msg)

    def do_run() -> None:
        options = collect_options()
        set_status("Status: running automatic..")
        steps_box.delete("1.0", tk.END)

        def worker() -> None:
            report = run_automatic(options, workspace, log=log)
            log_queue.put(f"__REPORT__:{report.ok}:{report.status}")
            for step in report.steps:
                log_queue.put(f"  [{'OK' if step.ok else 'FAIL'}] "
                              f"{step.name}: {step.status}")

        threading.Thread(target=worker, daemon=True).start()

    ttk.Button(btn_row, text="▶ Automatic Run", command=do_run).pack(side=tk.LEFT)
    emu_label = tk.StringVar(value="emulator: stopped")

    def emu_start() -> None:
        if emulator_holder["httpd"] is not None:
            return
        options = collect_options()
        config = EmulatorConfig(version=options.version, orythm=options.orythm,
                                prythm=options.prythm,
                                account_manager_startup=options.account_manager_startup)
        try:
            httpd = EmulatorHTTPServer((options.emulator_host, options.emulator_port),
                                       config)
        except OSError as exc:
            messagebox.showerror("Emulator", f"cannot bind: {exc}")
            return
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        emulator_holder["httpd"] = httpd
        emulator_holder["thread"] = thread
        url = f"http://{options.emulator_host}:{httpd.server_address[1]}"
        emu_label.set(f"emulator: RUNNING {url}")
        log(f"Status: emulator running on {url}")

    def emu_stop() -> None:
        httpd = emulator_holder.pop("httpd", None)
        thread = emulator_holder.pop("thread", None)
        if httpd is None:
            return
        httpd.shutdown()
        httpd.server_close()
        if thread:
            thread.join(timeout=2)
        emu_label.set("emulator: stopped")
        log("Status: emulator stopped")

    ttk.Button(btn_row, text="Start emulator", command=emu_start).pack(side=tk.LEFT, padx=6)
    ttk.Button(btn_row, text="Stop", command=emu_stop).pack(side=tk.LEFT)
    ttk.Label(btn_row, textvariable=emu_label).pack(side=tk.LEFT, padx=8)

    # -- Accounts tab -------------------------------------------------------
    acc_tab = ttk.Frame(notebook, padding=8)
    notebook.add(acc_tab, text="Accounts")
    acc_tree = ttk.Treeview(acc_tab, columns=("slot", "account", "client", "game", "loginall"),
                            show="headings", height=12)
    for col, title in (("slot", "Slot"), ("account", "Account"),
                       ("client", "Client"), ("game", "GameAccount"),
                       ("loginall", "LoginAll")):
        acc_tree.heading(col, text=title)
        acc_tree.column(col, width=140)
    acc_tree.pack(fill=tk.BOTH, expand=True)

    def acc_refresh() -> None:
        for item in acc_tree.get_children():
            acc_tree.delete(item)
        parser = read_logins(workspace / "logins.ini")
        for row in list_accounts(parser):
            acc_tree.insert("", tk.END, values=(row.get("slot"), row.get("Account"),
                                                row.get("Client"), row.get("GameAccount"),
                                                row.get("LoginAll")))

    ttk.Button(acc_tab, text="Refresh",
               command=acc_refresh).pack(side=tk.LEFT, pady=4)
    ttk.Label(acc_tab, text="Edit accounts in the browser GUI or logins.ini "
                            "(passwords stay out of this view).").pack(side=tk.LEFT, padx=8)
    acc_refresh()

    # -- Options tab ----------------------------------------------------------
    opt_tab = ttk.Frame(notebook, padding=8)
    notebook.add(opt_tab, text="Options")
    canvas = tk.Canvas(opt_tab)
    scrollbar = ttk.Scrollbar(opt_tab, orient="vertical", command=canvas.yview)
    inner = ttk.Frame(canvas)
    inner.bind("<Configure>", lambda _e: canvas.configure(scrollregion=canvas.bbox("all")))
    canvas.create_window((0, 0), window=inner, anchor="nw")
    canvas.configure(yscrollcommand=scrollbar.set)
    canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    for i, opt in enumerate(C.HIVE_OPTIONS):
        if opt.kind == "bool":
            ttk.Checkbutton(inner, text=f"{opt.label} [{opt.key}]",
                            variable=hive_vars[opt.key]).grid(row=i, column=0, sticky="w")
        else:
            ttk.Label(inner, text=f"{opt.label} [{opt.key}]:").grid(row=i, column=0, sticky="w")
            ttk.Entry(inner, textvariable=hive_vars[opt.key], width=30).grid(
                row=i, column=1, sticky="w", padx=6)

    # -- Delays tab ------------------------------------------------------------
    delay_tab = ttk.Frame(notebook, padding=8)
    notebook.add(delay_tab, text="Delays")
    ttk.Label(delay_tab, text="Delay table lives in logins.ini [Delay]; "
                              "defaults are pre-filled on first run.").pack(anchor="w")
    delay_text = scrolledtext.ScrolledText(delay_tab, height=18, font=("Consolas", 9))
    delay_text.pack(fill=tk.BOTH, expand=True)
    delay_text.insert(tk.END, "\n".join(f"{k}={v}" for k, v in sorted(C.DELAY_DEFAULTS.items())))
    delay_text.configure(state="disabled")

    # -- Files tab --------------------------------------------------------------
    files_tab = ttk.Frame(notebook, padding=8)
    notebook.add(files_tab, text="Files")
    ttk.Label(files_tab, text="Recovered at <workspace>/bin (fHide_* renames honoured):").pack(anchor="w")
    files_text = scrolledtext.ScrolledText(files_tab, height=18, font=("Consolas", 9))
    files_text.pack(fill=tk.BOTH, expand=True)
    files_text.insert(tk.END, "\n".join(
        f"{e.source}  ->  {e.runtime}   ({e.role})" for e in C.LOCAL_FILES))
    files_text.configure(state="disabled")

    # -- Log tab -----------------------------------------------------------------
    log_tab = ttk.Frame(notebook, padding=8)
    notebook.add(log_tab, text="Log")
    log_text = scrolledtext.ScrolledText(log_tab, height=20, font=("Consolas", 9))
    log_text.pack(fill=tk.BOTH, expand=True)

    def pump_queue() -> None:
        try:
            while True:
                msg = log_queue.get_nowait()
                if msg.startswith("__REPORT__:"):
                    _, ok, status = msg.split(":", 2)
                    status_var.set(status)
                    steps_box.insert(tk.END, status + "\n")
                else:
                    log_text.insert(tk.END, msg + "\n")
                    log_text.see(tk.END)
                    if msg.startswith("Status:") or msg.startswith("  ["):
                        steps_box.insert(tk.END, msg + "\n")
                        steps_box.see(tk.END)
        except queue.Empty:
            pass
        root.after(200, pump_queue)

    root.after(200, pump_queue)
    root.protocol("WM_DELETE_WINDOW", lambda: (emu_stop(), root.destroy()))
    root.mainloop()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
