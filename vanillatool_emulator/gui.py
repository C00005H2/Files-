"""Desktop GUI for Account Manager 5.43 local automation (tkinter).

This is the Windows-first front-end over :mod:`vanillatool_emulator.local`:
it exposes every option the original ``Para's Account Manager`` GUI offers
— emulator/auth, driver + DLL staging and mapping, NCGuard/Game setup,
accounts + delays + toggles, hosts redirect and target launch — and wires
each button to the automated implementation, with a one-click **Full Auto**
chain that runs everything in the order the original tool needs.

Run with::

    python -m vanillatool_emulator.gui

``tkinter`` ships with CPython on Windows.  On machines without it (minimal
Linux containers) importing this module still works, but :func:`main`
raises a clear error — use :mod:`vanillatool_emulator.panel` (browser UI)
or :mod:`vanillatool_emulator.local` (CLI) there instead.
"""

from __future__ import annotations

from pathlib import Path
import queue
import threading
from typing import Any

from . import local as L

try:
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk

    TK_AVAILABLE = True
    _TK_ERROR: Exception | None = None
except Exception as exc:  # pragma: no cover - environment dependent
    tk = None  # type: ignore[assignment]
    filedialog = None  # type: ignore[assignment]
    messagebox = None  # type: ignore[assignment]
    ttk = None  # type: ignore[assignment]
    TK_AVAILABLE = False
    _TK_ERROR = exc


def require_tk() -> None:
    if not TK_AVAILABLE:
        raise RuntimeError(
            "tkinter is not available in this Python. On Windows it ships with "
            "CPython; on minimal Linux installs add the python3-tk package. "
            "Alternatively use the browser panel: "
            "`python -m vanillatool_emulator.panel`. "
            f"(import error: {_TK_ERROR})"
        )


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------


class AccountManagerApp:
    """tkinter front-end; all work happens in :mod:`vanillatool_emulator.local`."""

    TITLE = "Para's Account Manager — Local Console (5.43)"

    def __init__(self, root: Any) -> None:
        require_tk()
        self.root = root
        self.root.title(self.TITLE)
        self.root.geometry("920x680")
        self.flow = L.AutoFlow()
        self.registry = L.RegistryStore()
        self.registry.ensure_defaults()
        self.log_queue: queue.Queue[str] = queue.Queue()
        self.status_var = tk.StringVar(value="Status: loaded..")

        # -- shared option variables -------------------------------------
        home = Path.home()
        self.workdir_var = tk.StringVar(value=str(Path.cwd() / "am_workdir"))
        self.device_var = tk.StringVar(value=self.registry.device_name())
        self.bind_var = tk.StringVar(value="127.0.0.1")
        self.port_var = tk.StringVar(value="8080")
        self.orythm_var = tk.StringVar(value="1")
        self.prythm_var = tk.StringVar(value="2")
        self.am_startup_var = tk.BooleanVar(value=True)
        self.response_file_var = tk.StringVar(value="")
        self.offsets_file_var = tk.StringVar(value="")
        self.game_dir_var = tk.StringVar(value="")
        self.server_preset_var = tk.StringVar(value=L.SERVER_PRESETS[0])
        self.logins_path_var = tk.StringVar(
            value=str(Path.cwd() / "am_workdir" / "logins.ini"))
        self.hosts_path_var = tk.StringVar(value=str(L.default_hosts_path()))
        self.target_exe_var = tk.StringVar(value="")
        self.apply_hosts_var = tk.BooleanVar(value=False)
        self.use_winreg_var = tk.BooleanVar(value=False)
        self.server_state_var = tk.StringVar(value="emulator: stopped")

        # provider ladder toggles
        self.prv_vars = {
            1: tk.BooleanVar(value=True),
            2: tk.BooleanVar(value=True),
            3: tk.BooleanVar(value=True),
            0: tk.BooleanVar(value=True),  # 0 == bare -map default call
        }
        # AM settings toggles (persisted to the hive mirror on change)
        self.toggle_vars: dict[str, tk.BooleanVar] = {}
        for key in ("BypassBan", "Anonify", "AutoInject", "VirtualClient",
                    "AMInstaScriptSilent", "AMAionClientSilent",
                    "AMCrashedClients", "AMLogChars", "RandomizeMAC",
                    "Compatibility"):
            current = self.registry.get(key, L.REGISTRY_DEFAULTS.get(key, "False"))
            self.toggle_vars[key] = tk.BooleanVar(value=current == "True")
        self.slot_var = tk.StringVar(
            value=self.registry.get("VirtualClientSlot", "Original Client"))
        self.login_delay_var = tk.StringVar(
            value=self.registry.get("AMLoginAllDelay", "0"))
        self.login_cap_var = tk.StringVar(
            value=self.registry.get("LoginAllCap", "999"))

        self._build()
        self._poll_logs()

    # -- layout ---------------------------------------------------------
    def _build(self) -> None:
        top = ttk.Frame(self.root, padding=8)
        top.pack(fill=tk.BOTH, expand=True)

        notebook = ttk.Notebook(top)
        notebook.pack(fill=tk.BOTH, expand=True)

        notebook.add(self._tab_emulator(notebook), text="Emulator")
        notebook.add(self._tab_driver(notebook), text="Driver & DLLs")
        notebook.add(self._tab_game(notebook), text="NCGuard / Game")
        notebook.add(self._tab_accounts(notebook), text="Accounts")
        notebook.add(self._tab_hosts(notebook), text="Hosts & Launch")

        # console + status bar
        console_frame = ttk.LabelFrame(top, text="Log", padding=4)
        console_frame.pack(fill=tk.BOTH, expand=False, pady=(8, 0))
        self.console = tk.Text(console_frame, height=9, wrap=tk.WORD,
                               state=tk.DISABLED)
        self.console.pack(fill=tk.BOTH, expand=True)
        status = ttk.Label(self.root, textvariable=self.status_var,
                           relief=tk.SUNKEN, anchor=tk.W)
        status.pack(fill=tk.X, side=tk.BOTTOM)
        self.set_status("Status: loaded..")

    def _tab_emulator(self, parent: Any) -> Any:
        frame = ttk.Frame(parent, padding=10)
        row = 0

        def entry(label: str, var: Any, width: int = 24) -> None:
            nonlocal row
            ttk.Label(frame, text=label).grid(row=row, column=0, sticky=tk.W,
                                              padx=4, pady=3)
            ttk.Entry(frame, textvariable=var, width=width).grid(
                row=row, column=1, sticky=tk.W, padx=4, pady=3)
            row += 1

        entry("Bind address", self.bind_var)
        entry("Port", self.port_var)
        entry("ORythm", self.orythm_var)
        entry("PRythm (2 = regions on)", self.prythm_var)
        ttk.Checkbutton(frame, text="Account-Manager pre-GUI markers "
                                    "(--account-manager-startup)",
                        variable=self.am_startup_var).grid(
            row=row, column=0, columnspan=3, sticky=tk.W, padx=4, pady=3)
        row += 1
        ttk.Label(frame, text="Response file (real profile)").grid(
            row=row, column=0, sticky=tk.W, padx=4, pady=3)
        ttk.Entry(frame, textvariable=self.response_file_var, width=40).grid(
            row=row, column=1, sticky=tk.W, padx=4, pady=3)
        ttk.Button(frame, text="Browse..",
                   command=lambda: self._browse_file(self.response_file_var)
                   ).grid(row=row, column=2, padx=4)
        row += 1
        ttk.Label(frame, text="Offsets file").grid(
            row=row, column=0, sticky=tk.W, padx=4, pady=3)
        ttk.Entry(frame, textvariable=self.offsets_file_var, width=40).grid(
            row=row, column=1, sticky=tk.W, padx=4, pady=3)
        ttk.Button(frame, text="Browse..",
                   command=lambda: self._browse_file(self.offsets_file_var)
                   ).grid(row=row, column=2, padx=4)
        row += 1
        buttons = ttk.Frame(frame)
        buttons.grid(row=row, column=0, columnspan=3, sticky=tk.W, pady=8)
        ttk.Button(buttons, text="Start emulator",
                   command=self.start_server).pack(side=tk.LEFT, padx=4)
        ttk.Button(buttons, text="Stop",
                   command=self.stop_server).pack(side=tk.LEFT, padx=4)
        ttk.Label(buttons, textvariable=self.server_state_var).pack(
            side=tk.LEFT, padx=12)
        row += 1
        ttk.Label(frame, text="Auth: POST /data/auth.php -> C:<hex>; "
                              "(ORythm/PRythm).  Version/Offsets/Log routes "
                              "included.",
                  wraplength=820, justify=tk.LEFT).grid(
            row=row, column=0, columnspan=3, sticky=tk.W, padx=4, pady=6)
        return frame

    def _tab_driver(self, parent: Any) -> Any:
        frame = ttk.Frame(parent, padding=10)
        ttk.Label(frame, text="Workdir (udk.bin / udk_1.dll / udk_2.bin live here)").grid(
            row=0, column=0, sticky=tk.W, padx=4, pady=3)
        ttk.Entry(frame, textvariable=self.workdir_var, width=46).grid(
            row=0, column=1, sticky=tk.W, padx=4, pady=3)
        ttk.Button(frame, text="Browse..",
                   command=lambda: self._browse_dir(self.workdir_var)).grid(
            row=0, column=2, padx=4)

        ttk.Label(frame, text="Device name (11 chars, fHide_UDK)").grid(
            row=1, column=0, sticky=tk.W, padx=4, pady=3)
        ttk.Entry(frame, textvariable=self.device_var, width=24).grid(
            row=1, column=1, sticky=tk.W, padx=4, pady=3)
        ttk.Button(frame, text="Randomize",
                   command=self.randomize_device).grid(row=1, column=2, padx=4)

        ttk.Label(frame, text="Payloads").grid(row=2, column=0, sticky=tk.NW,
                                               padx=4, pady=3)
        self.payload_list = tk.Listbox(frame, height=6, width=72)
        self.payload_list.grid(row=2, column=1, columnspan=2, sticky=tk.W,
                               padx=4, pady=3)
        self.refresh_payloads()

        btns = ttk.Frame(frame)
        btns.grid(row=3, column=0, columnspan=3, sticky=tk.W, pady=6)
        ttk.Button(btns, text="Stage drivers/DLLs",
                   command=self.stage_payloads).pack(side=tk.LEFT, padx=4)
        ttk.Button(btns, text="Patch device names",
                   command=self.patch_driver).pack(side=tk.LEFT, padx=4)

        ladder = ttk.LabelFrame(frame, text="Provider ladder (udk.bin -prv)", padding=6)
        ladder.grid(row=4, column=0, columnspan=3, sticky=tk.EW, padx=4, pady=6)
        ttk.Checkbutton(ladder, text="-prv 1 RTCore64 (MSI Afterburner)",
                        variable=self.prv_vars[1]).pack(anchor=tk.W)
        ttk.Checkbutton(ladder, text="-prv 2 Gdrv (Gigabyte)",
                        variable=self.prv_vars[2]).pack(anchor=tk.W)
        ttk.Checkbutton(ladder, text="-prv 3 ATSZIO64 (ASUSTeK WinFlash)",
                        variable=self.prv_vars[3]).pack(anchor=tk.W)
        ttk.Checkbutton(ladder, text="bare -map (mapper default)",
                        variable=self.prv_vars[0]).pack(anchor=tk.W)
        ttk.Button(ladder, text="Run mapping",
                   command=self.run_mapping).pack(anchor=tk.W, pady=(6, 0))

        ttk.Label(frame, text="Transcript").grid(row=5, column=0, sticky=tk.NW,
                                                 padx=4, pady=3)
        self.transcript = tk.Text(frame, height=7, width=82, wrap=tk.WORD)
        self.transcript.grid(row=5, column=1, columnspan=2, sticky=tk.W,
                             padx=4, pady=3)
        return frame

    def _tab_game(self, parent: Any) -> Any:
        frame = ttk.Frame(parent, padding=10)
        ttk.Label(frame, text="Game dir (holds bin64\\aion.bin)").grid(
            row=0, column=0, sticky=tk.W, padx=4, pady=3)
        ttk.Entry(frame, textvariable=self.game_dir_var, width=46).grid(
            row=0, column=1, sticky=tk.W, padx=4, pady=3)
        ttk.Button(frame, text="Browse..",
                   command=lambda: self._browse_dir(self.game_dir_var)).grid(
            row=0, column=2, padx=4)
        ttk.Label(frame, text="Server preset").grid(row=1, column=0, sticky=tk.W,
                                                    padx=4, pady=3)
        ttk.Combobox(frame, textvariable=self.server_preset_var,
                     values=list(L.SERVER_PRESETS), state="readonly",
                     width=22).grid(row=1, column=1, sticky=tk.W, padx=4, pady=3)
        btns = ttk.Frame(frame)
        btns.grid(row=2, column=0, columnspan=3, sticky=tk.W, pady=8)
        ttk.Button(btns, text="Verify client",
                   command=self.verify_game).pack(side=tk.LEFT, padx=4)
        ttk.Button(btns, text="Prepare game.dll",
                   command=self.prepare_gamedll).pack(side=tk.LEFT, padx=4)
        info = (
            f"NCGuard slots: aion.bin+{hex(L.AION_BIN_NCGUARD_OFFSET)} / "
            f"CrySystem.dll+{hex(L.CRYSYSTEM_NCGUARD_OFFSET)} "
            f"({L.NCGUARD_SLOT_SIZE} bytes) -> {L.NCGUARD_REPLACEMENT.decode()}\n"
            f"Window class: {L.WINDOW_CLASS_ORIGINAL} -> {L.WINDOW_CLASS_SPOOFED}\n"
            f"Hooks: {L.NCGUARD_HOOK_PATTERN}   "
            f"Thread magics: {L.NCGUARD_THREAD_MAGICS[0]} / {L.NCGUARD_THREAD_MAGICS[1]}"
        )
        ttk.Label(frame, text=info, wraplength=820, justify=tk.LEFT).grid(
            row=3, column=0, columnspan=3, sticky=tk.W, padx=4, pady=6)
        self.game_report = tk.Text(frame, height=10, width=82, wrap=tk.WORD)
        self.game_report.grid(row=4, column=0, columnspan=3, sticky=tk.W,
                              padx=4, pady=3)
        return frame

    def _tab_accounts(self, parent: Any) -> Any:
        frame = ttk.Frame(parent, padding=10)
        ttk.Label(frame, text="logins.ini").grid(row=0, column=0, sticky=tk.W,
                                                 padx=4, pady=3)
        ttk.Entry(frame, textvariable=self.logins_path_var, width=46).grid(
            row=0, column=1, sticky=tk.W, padx=4, pady=3)
        ttk.Button(frame, text="Browse..",
                   command=lambda: self._browse_file(self.logins_path_var)
                   ).grid(row=0, column=2, padx=4)

        ttk.Label(frame, text="Accounts").grid(row=1, column=0, sticky=tk.NW,
                                               padx=4, pady=3)
        self.account_list = tk.Listbox(frame, height=7, width=34)
        self.account_list.grid(row=1, column=1, sticky=tk.W, padx=4, pady=3)
        self.account_list.bind("<<ListboxSelect>>", lambda _e: self.show_account())
        abtns = ttk.Frame(frame)
        abtns.grid(row=1, column=2, sticky=tk.N, padx=4)
        ttk.Button(abtns, text="Refresh", command=self.refresh_accounts).pack(
            fill=tk.X, pady=2)
        ttk.Button(abtns, text="Add..", command=self.add_account).pack(
            fill=tk.X, pady=2)
        ttk.Button(abtns, text="Delete", command=self.delete_account).pack(
            fill=tk.X, pady=2)
        ttk.Button(abtns, text="Ensure [Delay]",
                   command=self.ensure_delays).pack(fill=tk.X, pady=2)

        self.account_view = tk.Text(frame, height=7, width=82, wrap=tk.WORD)
        self.account_view.grid(row=2, column=0, columnspan=3, sticky=tk.W,
                               padx=4, pady=3)

        toggles = ttk.LabelFrame(frame, text="Settings (HKCU .. Para's NoAnimation)",
                                 padding=6)
        toggles.grid(row=3, column=0, columnspan=3, sticky=tk.EW, padx=4, pady=6)
        labels = {
            "BypassBan": "[ ]/[x] Bypass Launcher ban",
            "Anonify": "[ ]/[x] Anonify Login",
            "AutoInject": "[ ]/[x] Auto Inject Vanillatool",
            "VirtualClient": "[ ]/[x] Create Virtual Clients",
            "AMInstaScriptSilent": "[ ]/[x] Hide Script Editor",
            "AMAionClientSilent": "[ ]/[x] Hide Aion Client",
            "AMCrashedClients": "[ ]/[x] Auto restart crashed clients",
            "AMLogChars": "[ ]/[x] Log Charnames to Status",
            "RandomizeMAC": "Randomize MAC",
            "Compatibility": "Compatibility",
        }
        for i, (key, label) in enumerate(labels.items()):
            ttk.Checkbutton(toggles, text=label,
                            variable=self.toggle_vars[key],
                            command=lambda k=key: self.save_toggle(k)).grid(
                row=i // 2, column=i % 2, sticky=tk.W, padx=8, pady=2)
        ttk.Label(toggles, text="Virtual slot").grid(row=5, column=0, sticky=tk.W,
                                                     padx=8, pady=4)
        ttk.Combobox(toggles, textvariable=self.slot_var,
                     values=list(L.VIRTUAL_CLIENT_SLOTS), state="readonly",
                     width=20).grid(row=5, column=1, sticky=tk.W, padx=8, pady=4)
        ttk.Button(toggles, text="Save slot + delays",
                   command=self.save_slot).grid(row=5, column=1, sticky=tk.E,
                                                padx=8)
        ttk.Label(toggles, text="Login All Delay").grid(row=6, column=0,
                                                        sticky=tk.W, padx=8)
        ttk.Entry(toggles, textvariable=self.login_delay_var, width=10).grid(
            row=6, column=1, sticky=tk.W, padx=8)
        ttk.Label(toggles, text="Max Clients (LoginAllCap)").grid(
            row=7, column=0, sticky=tk.W, padx=8)
        ttk.Entry(toggles, textvariable=self.login_cap_var, width=10).grid(
            row=7, column=1, sticky=tk.W, padx=8)
        self.refresh_accounts()
        return frame

    def _tab_hosts(self, parent: Any) -> Any:
        frame = ttk.Frame(parent, padding=10)
        ttk.Label(frame, text="Target EXE (original Account Manager)").grid(
            row=0, column=0, sticky=tk.W, padx=4, pady=3)
        ttk.Entry(frame, textvariable=self.target_exe_var, width=46).grid(
            row=0, column=1, sticky=tk.W, padx=4, pady=3)
        ttk.Button(frame, text="Browse..",
                   command=lambda: self._browse_file(self.target_exe_var)
                   ).grid(row=0, column=2, padx=4)
        ttk.Label(frame, text="Hosts file").grid(row=1, column=0, sticky=tk.W,
                                                 padx=4, pady=3)
        ttk.Entry(frame, textvariable=self.hosts_path_var, width=46).grid(
            row=1, column=1, sticky=tk.W, padx=4, pady=3)
        ttk.Checkbutton(frame, text="Apply hosts redirect during Full Auto",
                        variable=self.apply_hosts_var).grid(
            row=2, column=0, columnspan=2, sticky=tk.W, padx=4, pady=3)
        ttk.Checkbutton(frame, text="Sync hive to real registry (winreg)",
                        variable=self.use_winreg_var).grid(
            row=3, column=0, columnspan=2, sticky=tk.W, padx=4, pady=3)
        btns = ttk.Frame(frame)
        btns.grid(row=4, column=0, columnspan=3, sticky=tk.W, pady=8)
        ttk.Button(btns, text="FULL AUTO",
                   command=self.full_auto).pack(side=tk.LEFT, padx=4)
        ttk.Button(btns, text="Launch target",
                   command=self.launch_target).pack(side=tk.LEFT, padx=4)
        ttk.Button(btns, text="Hosts: apply",
                   command=self.hosts_apply).pack(side=tk.LEFT, padx=4)
        ttk.Button(btns, text="Hosts: restore",
                   command=self.hosts_restore).pack(side=tk.LEFT, padx=4)
        help_text = L.HostsManager.tls_help()
        ttk.Label(frame, text="Admin rights: " +
                  ("yes" if L.is_admin() else "no — driver mapping, hosts "
                   "edit and target launch need elevation on Windows."),
                  wraplength=820).grid(row=5, column=0, columnspan=3,
                                       sticky=tk.W, padx=4, pady=4)
        tls = tk.Text(frame, height=8, width=82, wrap=tk.WORD)
        tls.grid(row=6, column=0, columnspan=3, sticky=tk.W, padx=4, pady=3)
        tls.insert(tk.END, help_text)
        tls.configure(state=tk.DISABLED)
        return frame

    # -- helpers --------------------------------------------------------
    def set_status(self, message: str) -> None:
        self.status_var.set(message)

    def log(self, message: str) -> None:
        self.log_queue.put(message)

    def _poll_logs(self) -> None:
        try:
            while True:
                message = self.log_queue.get_nowait()
                self.console.configure(state=tk.NORMAL)
                self.console.insert(tk.END, message + "\n")
                self.console.see(tk.END)
                self.console.configure(state=tk.DISABLED)
        except queue.Empty:
            pass
        self.root.after(150, self._poll_logs)

    def _browse_file(self, var: Any) -> None:
        path = filedialog.askopenfilename()
        if path:
            var.set(path)

    def _browse_dir(self, var: Any) -> None:
        path = filedialog.askdirectory()
        if path:
            var.set(path)

    def _run_bg(self, func: Any) -> None:
        thread = threading.Thread(target=func, daemon=True)
        thread.start()

    def _options(self) -> L.AutoOptions:
        providers: list[int | None] = []
        for prv_id, var in ((1, self.prv_vars[1]), (2, self.prv_vars[2]),
                            (3, self.prv_vars[3])):
            if var.get():
                providers.append(prv_id)
        if self.prv_vars[0].get():
            providers.append(None)
        try:
            port = int(self.port_var.get().strip() or "8080")
        except ValueError:
            port = 8080
        return L.AutoOptions(
            workdir=Path(self.workdir_var.get()),
            game_dir=Path(self.game_dir_var.get()) if self.game_dir_var.get() else None,
            server_preset=self.server_preset_var.get(),
            device_name_value=self.device_var.get().strip(),
            providers=tuple(providers) or (None,),
            bind=self.bind_var.get().strip() or "127.0.0.1",
            port=port,
            orythm=self.orythm_var.get().strip() or "1",
            prythm=self.prythm_var.get().strip() or "2",
            account_manager_startup=self.am_startup_var.get(),
            response_file=Path(self.response_file_var.get())
            if self.response_file_var.get() else None,
            offsets_file=Path(self.offsets_file_var.get())
            if self.offsets_file_var.get() else None,
            apply_hosts=self.apply_hosts_var.get(),
            hosts_path=Path(self.hosts_path_var.get()),
            logins_path=Path(self.logins_path_var.get()),
            target_exe=Path(self.target_exe_var.get())
            if self.target_exe_var.get() else None,
            use_winreg=self.use_winreg_var.get(),
        )

    # -- emulator tab ---------------------------------------------------
    def start_server(self) -> None:
        def work() -> None:
            try:
                options = self._options()
                offsets_text = None
                if options.offsets_file:
                    from .offsets import load_offsets_file
                    offsets_text = load_offsets_file(options.offsets_file)
                status = self.flow.supervisor.start(
                    bind=options.bind, port=options.port,
                    version="5.43", orythm=options.orythm,
                    prythm=options.prythm,
                    response_file=options.response_file,
                    account_manager_startup=options.account_manager_startup,
                    offsets_text=offsets_text,
                )
                self.server_state_var.set(
                    f"emulator: {status.scheme}://{status.bind}:{status.port}")
                self.set_status("Status: successfully started emulator")
                self.log(f"emulator listening on {status.bind}:{status.port}")
            except Exception as exc:
                self.set_status("Status: Error 21")
                self.log(f"server start failed: {exc}")
                messagebox.showerror("Emulator", str(exc))
        self._run_bg(work)

    def stop_server(self) -> None:
        self.flow.supervisor.stop()
        self.server_state_var.set("emulator: stopped")
        self.set_status("Status: loaded..")
        self.log("emulator stopped")

    # -- driver tab -----------------------------------------------------
    def refresh_payloads(self) -> None:
        self.payload_list.delete(0, tk.END)
        for info in self.flow.stager.inventory():
            mark = "OK " if info.found else "MISS"
            size = f"{info.actual_size}" if info.actual_size is not None else "-"
            self.payload_list.insert(
                tk.END, f"[{mark}] {info.spec.staged_name} "
                        f"({size}/{info.spec.expected_size})")

    def randomize_device(self) -> None:
        name = L.random_device_name()
        self.device_var.set(name)
        self.registry.set("fHide_UDK", name)
        self.registry.save()
        self.set_status(f"Status: device {name}")
        self.log(f"new device name: {name}")

    def stage_payloads(self) -> None:
        def work() -> None:
            report = self.flow.stager.stage(Path(self.workdir_var.get()))
            self.set_status("Status: staged.." if report.ok else "Status: Error 14")
            self.log(f"staged={report.staged} missing={report.missing} "
                     f"errors={report.errors}")
            self.root.after(0, self.refresh_payloads)
        self._run_bg(work)

    def patch_driver(self) -> None:
        def work() -> None:
            try:
                name = self.device_var.get().strip()
                dev, dos = self.flow.stager.patch_driver(
                    Path(self.workdir_var.get()), name)
                self.registry.set("fHide_UDK", name)
                self.registry.save()
                self.set_status("Status: driver patched..")
                self.log(f"patched: {dev} / {dos}")
            except Exception as exc:
                self.set_status("Status: Error 16")
                self.log(f"patch failed: {exc}")
                messagebox.showerror("Patch", str(exc))
        self._run_bg(work)

    def _selected_providers(self) -> list[int | None]:
        providers: list[int | None] = []
        for prv_id in (1, 2, 3):
            if self.prv_vars[prv_id].get():
                providers.append(prv_id)
        if self.prv_vars[0].get():
            providers.append(None)
        return providers or [None]

    def run_mapping(self) -> None:
        def work() -> None:
            runner = L.MapperRunner(Path(self.workdir_var.get()))
            ladder = runner.run_ladder(providers=self._selected_providers())
            chunks: list[str] = []
            for step in ladder.steps:
                chunks.append(f"$ udk {' '.join(step.argv)} "
                              f"(simulated={step.simulated}) -> {step.outcome}")
                chunks.append(step.transcript)
                if step.hint:
                    chunks.append(step.hint)
            self.transcript.delete("1.0", tk.END)
            self.transcript.insert(tk.END, "\n".join(chunks))
            if ladder.hints:
                self.set_status(ladder.hints[0])
            elif ladder.mapped:
                self.set_status("Status: driver mapped..")
            else:
                self.set_status("Status: Error 16")
            self.log(f"mapping done: mapped={ladder.mapped} "
                     f"probe={ladder.device_probe}")
        self._run_bg(work)

    # -- game tab -------------------------------------------------------
    def verify_game(self) -> None:
        def work() -> None:
            game_dir = self.game_dir_var.get().strip()
            if not game_dir:
                messagebox.showwarning("Game", "Pick a game directory first.")
                return
            info = L.verify_game_dir(game_dir)
            self.game_report.delete("1.0", tk.END)
            import json as _json
            self.game_report.insert(tk.END, _json.dumps(info, indent=2))
            self.set_status(info.get("client_hint", "Status: loaded.."))
            self.log(f"verify {game_dir}: aion.bin={info['aion_bin']}")
        self._run_bg(work)

    def prepare_gamedll(self) -> None:
        def work() -> None:
            game_dir = self.game_dir_var.get().strip()
            if not game_dir:
                messagebox.showwarning("Game", "Pick a game directory first.")
                return
            try:
                src = Path(self.workdir_var.get()) / "game.dll"
                if not src.is_file():
                    src = self.flow.repo_root / "game.dll"
                dest = L.prepare_game_dll(src, Path(game_dir) / "bin64")
                self.set_status("Status: NCGuard redirect ready..")
                self.log(f"game.dll -> {dest}")
            except Exception as exc:
                self.set_status("Status: Error 21")
                self.log(f"game.dll failed: {exc}")
                messagebox.showerror("game.dll", str(exc))
        self._run_bg(work)

    # -- accounts tab ---------------------------------------------------
    def _logins(self) -> L.LoginsStore:
        return L.LoginsStore(Path(self.logins_path_var.get()))

    def refresh_accounts(self) -> None:
        self.account_list.delete(0, tk.END)
        try:
            for name in self._logins().list_accounts():
                self.account_list.insert(tk.END, name)
        except Exception as exc:
            self.log(f"accounts refresh failed: {exc}")

    def show_account(self) -> None:
        selection = self.account_list.curselection()
        if not selection:
            return
        name = self.account_list.get(selection[0])
        values = self._logins().get_account(name)
        self.account_view.delete("1.0", tk.END)
        self.account_view.insert(tk.END, f"[{name}]\n")
        for key, value in sorted(values.items()):
            display = value if "password" not in key.lower() else "***"
            self.account_view.insert(tk.END, f"{key}={display}\n")

    def add_account(self) -> None:
        dialog = tk.Toplevel(self.root)
        dialog.title("Add account")
        name_var = tk.StringVar()
        server_var = tk.StringVar(value=self.server_preset_var.get())
        ttk.Label(dialog, text="Account section name").pack(padx=10, pady=4)
        ttk.Entry(dialog, textvariable=name_var, width=34).pack(padx=10, pady=4)
        ttk.Label(dialog, text="Server").pack(padx=10, pady=4)
        ttk.Combobox(dialog, textvariable=server_var,
                     values=list(L.SERVER_PRESETS), state="readonly",
                     width=30).pack(padx=10, pady=4)

        def save() -> None:
            name = name_var.get().strip()
            if not name:
                messagebox.showwarning("Add", "Name is required.")
                return
            store = self._logins()
            store.ensure_delay_defaults()
            store.set_account(name, {"Server": server_var.get(),
                                     "Enabled": "True",
                                     "Client": server_var.get()})
            store.save()
            dialog.destroy()
            self.refresh_accounts()
            self.set_status(f"Status: saved {name}..")
            self.log(f"account added: {name}")

        ttk.Button(dialog, text="Save", command=save).pack(pady=8)

    def delete_account(self) -> None:
        selection = self.account_list.curselection()
        if not selection:
            return
        name = self.account_list.get(selection[0])
        if messagebox.askyesno("Delete", f"Delete [{name}]?"):
            store = self._logins()
            store.delete_account(name)
            store.save()
            self.refresh_accounts()
            self.set_status("Status: Deleted Account")

    def ensure_delays(self) -> None:
        store = self._logins()
        added = store.ensure_delay_defaults()
        store.save()
        self.set_status("Status: saving..")
        self.log(f"delay defaults added: {len(added)}")

    def save_toggle(self, key: str) -> None:
        self.registry.set(key, "True" if self.toggle_vars[key].get() else "False")
        mark = "[x]" if self.toggle_vars[key].get() else "[ ]"
        self.registry.save()
        self.log(f"{mark} {key} -> {self.registry.get(key)}")

    def save_slot(self) -> None:
        self.registry.set("VirtualClientSlot", self.slot_var.get())
        self.registry.set("AMLoginAllDelay", self.login_delay_var.get().strip() or "0")
        self.registry.set("LoginAllCap", self.login_cap_var.get().strip() or "999")
        self.registry.save()
        self.set_status("Status: saving..")
        self.log("slot + login-all settings saved")

    # -- hosts tab ------------------------------------------------------
    def hosts_apply(self) -> None:
        manager = L.HostsManager(Path(self.hosts_path_var.get()))
        if not L.is_admin():
            self.log("hosts apply needs admin; showing dry-run line:")
            self.log(manager.apply_redirect(dry_run=True))
            messagebox.showwarning(
                "Hosts",
                "Administrator rights are required to edit the hosts file.\n"
                "Re-run elevated, or add the shown line manually.")
            return
        try:
            line = manager.apply_redirect()
            self.set_status("Status: hosts redirected..")
            self.log(f"hosts: {line}")
        except OSError as exc:
            self.log(f"hosts apply failed: {exc}")
            messagebox.showerror("Hosts", str(exc))

    def hosts_restore(self) -> None:
        manager = L.HostsManager(Path(self.hosts_path_var.get()))
        if manager.restore():
            self.set_status("Status: hosts restored..")
            self.log("hosts restored")
        else:
            self.log("hosts restore failed (needs admin?)")

    def full_auto(self) -> None:
        def work() -> None:
            self.set_status("Status: Preparing.. (0/3)")
            report = self.flow.run(
                self._options(), progress=lambda s, m: self.log(f"[{s}] {m}"))
            self.set_status(report.status)
            for warning in report.warnings:
                self.log(f"warning: {warning}")
            self.server_state_var.set(
                "emulator: running" if self.flow.supervisor.running
                else "emulator: stopped")
            if self.flow.stager:
                self.root.after(0, self.refresh_payloads)
            self.root.after(0, self.refresh_accounts)
            if not report.ok:
                messagebox.showwarning("Full Auto", report.status)
        self._run_bg(work)

    def launch_target(self) -> None:
        target = self.target_exe_var.get().strip()
        if not target:
            messagebox.showwarning("Launch", "Pick the target EXE first.")
            return
        try:
            pid = L.AutoFlow.launch_target(target)
            self.set_status(f"Status: successfully started [{pid}]")
            self.log(f"launched {target} pid={pid}")
        except OSError as exc:
            self.log(f"launch failed: {exc}")
            messagebox.showerror("Launch", str(exc))


def main() -> int:
    require_tk()
    root = tk.Tk()
    AccountManagerApp(root)
    root.mainloop()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
