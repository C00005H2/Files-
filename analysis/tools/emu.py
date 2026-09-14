#!/usr/bin/env python3
"""crackme.exe unicorn harness v4 (clean rewrite of emu3.py).

Runs the PE under unicorn with a fake Win64 environment and captures everything
needed to model the password check offline:

  * the VM setup state (LCG seed, bytecode pointer, opcode table, handler table,
    operand-arity table)
  * the complete ordered list of VM handler invocations with their operands
    (i.e. the decoded bytecode *program*, independent of the per-run shuffle)
  * the memory window the VM can address (scratch base = state+0xd0)
  * the sponge output block and R[] at the gate / at exit

Usage:  python3 emu.py <password> [-o out.json] [--trace]
"""
import sys, os, json, struct, argparse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pefile
from unicorn import *
from unicorn.x86_const import *
from make_fake_dll import build_pe

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BIN = os.path.join(ROOT, '6aa4b6d3585e8875bcbebf80', 'crackme.exe')
BASE = 0x140000000   # = PE ImageBase: the binary holds absolute handler pointers
DLLBASE = 0x77000000
TRAMP = 0x78000000
STACK_TOP = 0x2FFFE000

# --- interesting RVAs (from static analysis) ---
RVA_VM_LOOP = 0xB2A0        # VM dispatcher top
RVA_VM_DISPATCH = 0xB36D    # just before `call rax` (handler call)
RVA_VM_OPC = 0xB2FA         # movsxd r11,[rsp+rax*4+0x20]  (opcode->handler idx)
RVA_VM_RET = 0xB37A         # instruction right after `call rax`
STATE = 0x2B650             # VM state base
SCRATCH = 0x2B720           # state+0xd0 holds the *pointer* to the VM data window
SPONGE_OUT = 0x2B7A0        # rdi of the sponge


class StopRun(Exception):
    pass


class Harness:
    def __init__(self, password=b'test123', rdtsc=0x1122334455667788, verbose=False,
                 snap_every=0, inject_mac=None):
        self.inject_mac = inject_mac
        self.snap_every = snap_every
        self.rsnaps = {}
        self.PASSWORD = password
        self.rdtsc_val = rdtsc
        self.verbose = verbose
        self.exit_code = None
        self.api_log = []
        self.trace = []          # (handler_rva, c1,c2,c3,c4,c5)
        self.vm_setup = None
        self.captures = {}
        self.pe = pefile.PE(BIN)
        self.ep = BASE + self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
        self.mu = Uc(UC_ARCH_X86, UC_MODE_64)
        self.NAME2IDX = {}
        self.stub_dispatch = {}
        self._build()

    # ------------------------------------------------------------------ setup
    def log(self, *a):
        if self.verbose:
            print(*a, file=sys.stderr)

    def _build(self):
        mu = self.mu
        mu.mem_map(BASE, 0x400000)
        for s in self.pe.sections:
            mu.mem_write(BASE + s.VirtualAddress, s.get_data())
        mu.mem_map(BASE + 0x400000, 0x400000)
        mu.mem_map(0x2FF00000, 0x100000)      # stack
        mu.mem_map(0x60000000, 0x1000000)     # heap
        mu.mem_map(0x63000000, 0x100000)      # TEB/PEB fakes
        mu.mem_map(TRAMP, 0x40000)
        mu.mem_map(DLLBASE, 0x400000)

        # ---- TEB / PEB ----
        TEB, FAKEPEB, ENT1, ENT2 = 0x60001000, 0x63001000, 0x63004000, 0x63004100

        def make_entry(addr, name):
            buf = addr + 0x80
            wb = name.encode('utf-16-le')
            ent = bytearray(0x100)
            struct.pack_into('<Q', ent, 0x18, DLLBASE)
            struct.pack_into('<Q', ent, 0x20, DLLBASE)
            struct.pack_into('<H', ent, 0x48, len(wb))
            struct.pack_into('<H', ent, 0x4A, len(wb) * 2)
            struct.pack_into('<Q', ent, 0x50, buf)
            mu.mem_write(addr, bytes(ent))
            mu.mem_write(buf, wb + b'\x00\x00')

        make_entry(ENT1, 'kernel32.dll')
        make_entry(ENT2, 'ntdll.dll')
        e1 = bytearray(mu.mem_read(ENT1, 0x100)); e2 = bytearray(mu.mem_read(ENT2, 0x100))
        struct.pack_into('<Q', e1, 0x00, ENT2); struct.pack_into('<Q', e1, 0x08, ENT2)
        struct.pack_into('<Q', e2, 0x00, ENT1); struct.pack_into('<Q', e2, 0x08, ENT1)
        mu.mem_write(ENT1, bytes(e1)); mu.mem_write(ENT2, bytes(e2))
        fpeb = bytearray(0x1000)
        struct.pack_into('<Q', fpeb, 0x00, ENT1)
        struct.pack_into('<Q', fpeb, 0x20, ENT1)
        struct.pack_into('<Q', fpeb, 0x50, ENT1)
        mu.mem_write(FAKEPEB, bytes(fpeb))
        teb = bytearray(0x1000)
        struct.pack_into('<Q', teb, 0x18, FAKEPEB)
        struct.pack_into('<Q', teb, 0x30, FAKEPEB)
        struct.pack_into('<Q', teb, 0x60, TEB)
        mu.mem_write(TEB, bytes(teb))
        mu.reg_write(UC_X86_REG_GS_BASE, TEB)

        # ---- stack ----
        sp = STACK_TOP - 0x1000
        mu.mem_write(sp, struct.pack('<Q', 0xC0DE))
        mu.reg_write(UC_X86_REG_RSP, sp)
        mu.reg_write(UC_X86_REG_RIP, self.ep)
        mu.mem_write(0x60010000, '"crackme.exe"'.encode('utf-16-le') + b'\x00\x00')

        # ---- trampolines ----
        for i in range(1024):
            mu.mem_write(TRAMP + i * 0x40, b'\x0f\x0b' + b'\x00' * 0x3e)
        mu.hook_add(UC_HOOK_CODE, self._trampoline_hook, begin=TRAMP, end=TRAMP + 1024 * 0x40)
        self.NAME2IDX['LoadLibraryW'] = 0
        self.NAME2IDX['GetProcAddress'] = 1
        self.stub_dispatch[0] = self.api_loadlibraryw
        self.stub_dispatch[1] = self.api_getprocaddress
        for n in DEFAULT_APIS:
            if n not in self.NAME2IDX:
                self.NAME2IDX[n] = len(self.NAME2IDX)
                self.stub_dispatch[self.NAME2IDX[n]] = getattr(
                    self, HANDLERS.get(n, 'api_ok'))

        # ---- fake kernel32 export table ----
        apis = [(n, (TRAMP + self.NAME2IDX[n] * 0x40) - DLLBASE) for n in self.NAME2IDX]
        dll, _ = build_pe(apis, image_base=DLLBASE)
        mu.mem_write(DLLBASE, dll)

        # ---- deterministic rdtsc (unicorn 2.1 cannot hook the insn itself, so
        #      patch the single `rdtsc` site at RVA 0x1300 and step over it) ----
        def rdtsc_hook(uc, address, size, user):
            v = self.rdtsc_val
            uc.reg_write(UC_X86_REG_RAX, v & 0xFFFFFFFF)
            uc.reg_write(UC_X86_REG_RDX, (v >> 32) & 0xFFFFFFFF)
            uc.reg_write(UC_X86_REG_RIP, address + 2)
        mu.hook_add(UC_HOOK_CODE, rdtsc_hook, begin=BASE + 0x1300, end=BASE + 0x1301)

        # ---- int3 (anti-debug) ----
        self.int3_skips = 0

        def intr_hook(uc, intno, user):
            if intno != 3:
                return
            rip = uc.reg_read(UC_X86_REG_RIP)
            uc.reg_write(UC_X86_REG_RIP, rip + 1)
            self.int3_skips += 1
        mu.hook_add(UC_HOOK_INTR, intr_hook)

        # ---- VM instrumentation ----
        mu.hook_add(UC_HOOK_CODE, self._vm_setup_hook, begin=BASE + RVA_VM_LOOP,
                    end=BASE + RVA_VM_LOOP + 1)
        mu.hook_add(UC_HOOK_CODE, self._vm_opc_hook, begin=BASE + RVA_VM_OPC,
                    end=BASE + RVA_VM_OPC + 1)
        mu.hook_add(UC_HOOK_CODE, self._vm_dispatch_hook, begin=BASE + RVA_VM_DISPATCH,
                    end=BASE + RVA_VM_DISPATCH + 1)

    # ------------------------------------------------------------ api helpers
    def _after_call(self, uc, ret_val=0):
        rsp = uc.reg_read(UC_X86_REG_RSP)
        ra = struct.unpack('<Q', bytes(uc.mem_read(rsp, 8)))[0]
        uc.reg_write(UC_X86_REG_RSP, rsp + 8)
        uc.reg_write(UC_X86_REG_RAX, ret_val)
        uc.reg_write(UC_X86_REG_RIP, ra)

    def _read_wstr(self, addr, maxlen=1024):
        try:
            raw = bytes(self.mu.mem_read(addr, maxlen * 2))
        except Exception:
            return ''
        i = raw.find(b'\x00\x00')
        if i >= 0:
            raw = raw[:i]
        return raw.decode('utf-16-le', 'replace')

    def _trampoline_hook(self, uc, address, size, user):
        idx = (address - TRAMP) // 0x40
        fn = self.stub_dispatch.get(idx)
        if fn:
            fn(uc)
        else:
            self.log(f'  [stub {idx} unknown] -> 1')
            self._after_call(uc, 1)

    # ------------------------------------------------------------------- APIs
    def api_loadlibraryw(self, uc):
        self._after_call(uc, DLLBASE)

    def api_getprocaddress(self, uc):
        namep = uc.reg_read(UC_X86_REG_RDX)
        name = self._read_wstr(namep)
        if name not in self.NAME2IDX:
            self.NAME2IDX[name] = len(self.NAME2IDX)
            self.stub_dispatch[self.NAME2IDX[name]] = self.api_generic_ok
        self._after_call(uc, TRAMP + self.NAME2IDX[name] * 0x40)

    def api_exitprocess(self, uc):
        code = uc.reg_read(UC_X86_REG_ECX) & 0xFFFFFFFF
        self.exit_code = code
        self.capture('exit')
        raise StopRun(code)

    def api_readconsolew(self, uc):
        inp = uc.reg_read(UC_X86_REG_RDX)
        nchars = uc.reg_read(UC_X86_REG_R8D) & 0xFFFF
        readc = uc.reg_read(UC_X86_REG_R9)
        wide = (self.PASSWORD + b'\r\n').decode().encode('utf-16-le')
        take = min(len(wide) // 2, nchars)
        self.mu.mem_write(inp, wide[:take * 2])
        self.mu.mem_write(readc, struct.pack('<I', take))
        self.api_log.append(('ReadConsoleW', take))
        self._after_call(uc, 1)

    def api_getcommandlinew(self, uc):
        buf = uc.reg_read(UC_X86_REG_RCX)
        self.mu.mem_write(buf, '"crackme.exe"'.encode('utf-16-le') + b'\x00\x00')
        self._after_call(uc, buf)

    def api_writeconsolew(self, uc):
        out = uc.reg_read(UC_X86_REG_RDX)
        n = uc.reg_read(UC_X86_REG_R8D) & 0xFFFF
        try:
            self.api_log.append(('WriteConsoleW', self._read_wstr(out, n)))
        except Exception:
            pass
        self._after_call(uc, 1)

    def api_ok(self, uc):
        self._after_call(uc, 1)

    def api_one(self, uc):
        self._after_call(uc, 1)

    def api_tick(self, uc):
        self._after_call(uc, 1000)

    def api_qpf(self, uc):
        self._after_call(uc, 10000000)

    def api_modhandle(self, uc):
        self._after_call(uc, 0x7FFF0000)

    def api_openproc(self, uc):
        self._after_call(uc, 0x12345678)

    def api_lstrlenw(self, uc):
        self._after_call(uc, len(self._read_wstr(uc.reg_read(UC_X86_REG_RCX))))

    def api_zero(self, uc):
        self._after_call(uc, 0)

    def api_getstdhandle(self, uc):
        self._after_call(uc, 0xFFFFFFFFFFFFFBD0)

    def api_qpc(self, uc):
        self._after_call(uc, self.rdtsc_val & 0xFFFFFFFF)

    # ------------------------------------------------------------- VM capture
    def _vm_setup_hook(self, uc, address, size, user):
        if self.vm_setup is not None:
            return
        r10 = uc.reg_read(UC_X86_REG_R10)
        r11 = uc.reg_read(UC_X86_REG_R11)
        r14 = uc.reg_read(UC_X86_REG_R14)
        rsp = uc.reg_read(UC_X86_REG_RSP)
        self.vm_setup = {'r10_bytecode': r10, 'r11_seed': r11 & 0xFFFFFFFF, 'r14': r14,
                         'rsp': rsp, 'n_loop': 0}
        # handler fn table + arity table
        try:
            htab = bytes(uc.mem_read(r14 + 0xC650, 8 * 64))
            atab = bytes(uc.mem_read(r14 + 0xC5E0, 4 * 64))
            self.captures['handler_table'] = htab.hex()
            self.captures['arity_table'] = atab.hex()
            self.captures['bytecode'] = bytes(uc.mem_read(r10, 0x2000)).hex()
        except Exception as e:
            self.log('  [setup dump err]', e)
        self.capture('vm_start')
        if self.inject_mac:
            wbase = struct.unpack('<Q', bytes(uc.mem_read(BASE + STATE + 0xD0, 8)))[0]
            uc.mem_write(wbase + 0x140, bytes.fromhex(self.inject_mac))
            self.log(f'  [inject] wrote MAC {self.inject_mac} at {wbase + 0x140:#x}')

    def _vm_opc_hook(self, uc, address, size, user):
        """Capture the opcode->handler-index table once (256 dwords at rsp+0x20)."""
        if 'optable' in self.captures:
            return
        rsp = uc.reg_read(UC_X86_REG_RSP)
        self.captures['optable'] = bytes(uc.mem_read(rsp + 0x20, 4 * 256)).hex()

    def _vm_dispatch_hook(self, uc, address, size, user):
        """Log every handler invocation: (handler rva, c1..c5)."""
        r11 = uc.reg_read(UC_X86_REG_R11)
        hfn = struct.unpack('<Q', bytes(uc.mem_read(
            uc.reg_read(UC_X86_REG_R14) + 0xC650 + (r11 & 0x3F) * 8, 8)))[0]
        st = bytes(uc.mem_read(BASE + STATE + 0xC1, 8))
        self.trace.append((hfn - BASE, st[0], st[1], st[2], st[3], st[4]))
        if self.snap_every and len(self.trace) % self.snap_every == 0:
            self.rsnaps[len(self.trace)] = bytes(
                uc.mem_read(BASE + STATE + 0x28, 8 * 18)).hex()
        if hfn - BASE in (0x1270, 0x12A0, 0x12E0):     # the comparisons
            R = bytes(uc.mem_read(BASE + STATE + 0x28, 8 * 32))
            self.captures.setdefault('cmps', []).append(
                (len(self.trace) - 1, hfn - BASE, st[0], st[1], st[2], st[3], st[4], R.hex()))
        self.vm_setup['n_loop'] += 1
        if self.vm_setup['n_loop'] == 1:
            self.capture('first_handler')

    def capture(self, tag):
        mu = self.mu
        d = {}
        d['R'] = bytes(mu.mem_read(BASE + STATE + 0x28, 8 * 32)).hex()
        d['flags'] = bytes(mu.mem_read(BASE + STATE, 0x28)).hex()
        d['c'] = bytes(mu.mem_read(BASE + STATE + 0xC0, 0x10)).hex()
        d['scratch140'] = bytes(mu.mem_read(BASE + STATE + 0x140, 0x20)).hex()
        d['sponge_out'] = bytes(mu.mem_read(BASE + SPONGE_OUT, 0x180)).hex()
        wbase = struct.unpack('<Q', bytes(mu.mem_read(BASE + STATE + 0xD0, 8)))[0]
        d['wbase'] = wbase
        d['window'] = bytes(mu.mem_read(wbase, 0x10000)).hex()
        d['state148'] = bytes(mu.mem_read(BASE + STATE + 0x148, 8)).hex()
        d['trace_len'] = len(self.trace)
        self.captures[tag] = d
        self.log(f'  [capture {tag}] MAC={d["sponge_out"][0x140*2:0x140*2+32]} '
                 f'R0..7={d["R"][:16]} trace={len(self.trace)}')

    # -------------------------------------------------------------------- run
    def run(self, max_instr=200_000_000):
        try:
            self.mu.emu_start(self.ep, 0, timeout=0, count=max_instr)
        except StopRun as e:
            self.log(f'  exit={e}')
        except UcError as e:
            self.log(f'  UcError {e} rip=0x{self.mu.reg_read(UC_X86_REG_RIP):x}')
        return self

    def gate_R(self):
        """R[0..7] as seen by the 8 gate checks (handler 0x1270)."""
        return None


HANDLERS = {
    'ExitProcess': 'api_exitprocess', 'TerminateProcess': 'api_exitprocess',
    'ReadConsoleW': 'api_readconsolew', 'GetCommandLineW': 'api_getcommandlinew',
    'WriteConsoleW': 'api_writeconsolew', 'GetStdHandle': 'api_getstdhandle',
    'GetConsoleMode': 'api_zero', 'SetConsoleMode': 'api_ok',
    'FlushConsoleInputBuffer': 'api_ok', 'GetKeyState': 'api_zero',
    'GetAsyncKeyState': 'api_zero', 'IsDebuggerPresent': 'api_zero',
    'CheckRemoteDebuggerPresent': 'api_zero',
    'QueryPerformanceCounter': 'api_qpc', 'QueryPerformanceFrequency': 'api_qpf',
    'GetTickCount': 'api_tick', 'GetTickCount64': 'api_tick', 'Sleep': 'api_ok',
    'GetLastError': 'api_zero', 'SetLastError': 'api_ok', 'CloseHandle': 'api_ok',
    'GetModuleHandleW': 'api_modhandle', 'NtQueryInformationProcess': 'api_zero',
    'OutputDebugStringW': 'api_ok', 'FindWindowW': 'api_zero',
    'GetForegroundWindow': 'api_zero', 'GetCurrentProcessId': 'api_one',
    'GetCurrentThreadId': 'api_one', 'GetConsoleCP': 'api_zero',
    'OpenProcess': 'api_openproc', 'RtlNtStatusToDosError': 'api_zero',
    'GetConsoleOutputCP': 'api_zero', 'SetConsoleCtrlHandler': 'api_ok',
    'GetEnvironmentVariableW': 'api_zero', 'FreeConsole': 'api_ok',
    'AttachConsole': 'api_zero', 'SetConsoleTextAttribute': 'api_ok',
    'WriteFile': 'api_ok', 'ReadFile': 'api_ok', 'CreateFileW': 'api_zero',
    'VirtualAlloc': 'api_ok', 'VirtualProtect': 'api_ok', 'HeapAlloc': 'api_ok',
    'HeapFree': 'api_ok', 'GetProcessHeap': 'api_ok', 'lstrlenW': 'api_lstrlenw',
    'GetWindowTextW': 'api_ok', 'EnumWindows': 'api_ok', 'ShowWindow': 'api_ok',
    'GetWindowThreadProcessId': 'api_ok', 'NtSetInformationThread': 'api_ok',
    'NtClose': 'api_ok', 'NtQuerySystemInformation': 'api_zero',
    'UnhandledExceptionFilter': 'api_zero', 'SetUnhandledExceptionFilter': 'api_zero',
    'lstrcpyW': 'api_ok', 'MultiByteToWideChar': 'api_ok', 'WideCharToMultiByte': 'api_ok',
}

# API names the binary's own resolver looks up in the (fake) kernel32 export
# table.  Anything without a specific handler below behaves as `return 1`.
EXTRA_APIS = [
    'LoadLibraryW', 'GetProcAddress', 'ExitProcess', 'ReadConsoleW', 'GetCommandLineW', 'WriteConsoleW',
    'GetStdHandle', 'GetConsoleMode', 'SetConsoleMode', 'FlushConsoleInputBuffer', 'GetKeyState', 'GetAsyncKeyState',
    'IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'QueryPerformanceCounter', 'QueryPerformanceFrequency', 'GetTickCount', 'GetTickCount64',
    'Sleep', 'RtlNtStatusToDosError', 'GetLastError', 'CloseHandle', 'GetModuleHandleW', 'GetVersionExW',
    'CreateFileW', 'ReadFile', 'WriteFile', 'GetFileSize', 'FindFirstFileW', 'FindNextFileW',
    'FindClose', 'GetCurrentDirectoryW', 'SetCurrentDirectoryW', 'MultiByteToWideChar', 'WideCharToMultiByte', 'lstrlenW',
    'MessageBoxW', 'GetForegroundWindow', 'EnumWindows', 'GetWindowTextW', 'ShowWindow', 'FindWindowW',
    'GetWindowThreadProcessId', 'OpenProcess', 'OutputDebugStringW', 'GetCurrentThreadId', 'GetCurrentProcessId', 'NtQueryInformationProcess',
    'NtClose', 'GetSystemDirectoryW', 'GetTempPathW', 'TerminateProcess', 'VirtualAlloc', 'CreateThread',
    'CreateToolhelp32Snapshot', 'Process32FirstW', 'Process32NextW', 'GetThreadContext', 'NtSetInformationThread', 'RtlAddVectoredExceptionHandler',
    'RtlRemoveVectoredExceptionHandler', 'VirtualProtect', 'SetThreadContext', 'SuspendThread', 'ResumeThread', 'GetLastErrorMessage',
    'FormatMessageW', 'LocalFree', 'HeapAlloc', 'HeapFree', 'TlsAlloc', 'TlsGetValue',
    'TlsSetValue', 'TlsFree', 'InterlockedIncrement', 'InterlockedDecrement', 'EnterCriticalSection', 'LeaveCriticalSection',
    'InitializeCriticalSection', 'GetCP', 'IsValidCodePage', 'GetLocaleInfoW', 'UnhandledExceptionFilter', 'SetUnhandledExceptionFilter',
    'AddVectoredExceptionHandler', 'RemoveVectoredExceptionHandler', 'RaiseException', 'TerminateThread', 'GetCurrentThread', 'DuplicateHandle',
    'WaitForSingleObject', 'WaitForMultipleObjects', 'ResetEvent', 'SetEvent', 'CreateEventW', 'CreateMutexW',
    'ReleaseMutex', 'CRITICAL_SECTION', 'GetModuleFileNameW', 'GetShortPathNameW', 'GetLongPathNameW', 'CompareStringW',
    'LCMapStringW', 'GetUserDefaultLCID', 'SystemTimeToFileTime', 'FileTimeToSystemTime', 'GetFileAttributesW', 'SetFileAttributesW',
    'DeleteFileW', 'MoveFileW', 'CopyFileW', 'CreateDirectoryW', 'RemoveDirectoryW', 'FindFirstFileExW',
    'GetFileInformationByHandle', 'GetDiskFreeSpaceExW', 'DeviceIoControl', 'CreateNamedPipeW', 'ConnectNamedPipe', 'DisconnectNamedPipe',
    'TransmitFile', 'SendDlgItemMessageW', 'CreateWindowExW', 'DestroyWindow', 'DefWindowProcW', 'RegisterClassW',
    'UnregisterClassW', 'PostMessageW', 'SendMessageW', 'PeekMessageW', 'TranslateMessage', 'DispatchMessageW',
    'BeginPaint', 'EndPaint', 'GetDC', 'ReleaseDC', 'FillRect', 'InvertRect',
    'TextOutW', 'DrawTextW', 'CreateFontW', 'SelectObject', 'DeleteObject', 'GetTextMetricsW',
    'GetStockObject', 'GetSystemMetrics', 'LoadCursorW', 'LoadIconW', 'LoadImageW', 'SetCursor',
    'SetIcon', 'SetFocus', 'GetFocus', 'SetActiveWindow', 'SetActiveWindow', 'GetClientRect',
    'GetWindowRect', 'ScreenToClient', 'ClientToScreen', 'MapWindowPoints', 'GetAncestor', 'SetParent',
    'ChildWindowFromPointEx', 'WindowFromPoint', 'IsWindowVisible', 'IsWindowEnabled', 'EnableWindow', 'ShowCursor',
    'GetSysColor', 'SetSysColors', 'GetSysColorBrush', 'GetSysColorPtr', 'GetKeyboardState', 'GetKeyboardType',
    'ToUnicode', 'ToAscii', 'VkKeyScanW', 'GetOEMCP', 'GetACP', 'GetPrivateProfileStringW',
    'WritePrivateProfileStringW', 'GetPrivateProfileIntW', 'GetPrivateProfileSectionW', 'GetPrivateProfileSectionNamesW', 'GetPrivateProfileStructW', 'WritePrivateProfileStructW',
]


# APIs that must report "nothing found / failed", otherwise the anti-debug
# process/window scans loop forever under emulation.
ZERO_APIS = ['CreateFileW', 'ReadFile', 'FindFirstFileW', 'FindNextFileW',
             'FindFirstFileExW', 'CreateToolhelp32Snapshot', 'Process32FirstW',
             'Process32NextW', 'Thread32First', 'Thread32Next', 'Module32FirstW',
             'Module32NextW', 'FindWindowW', 'FindWindowExW', 'GetForegroundWindow',
             'GetKeyState',
             'GetAsyncKeyState', 'IsDebuggerPresent', 'CheckRemoteDebuggerPresent',
             'NtQueryInformationProcess', 'NtSetInformationThread',
             'GetLastError', 'GetConsoleMode', 'GetCP', 'GetOEMCP',
             'GetACP', 'GetUserDefaultUILanguage', 'GetVersionExW', 'GetFileAttributesW',
             'DeviceIoControl', 'GetProcessId', 'GetExitCodeProcess', 'WaitForSingleObject',
             'CheckRemoteDebuggerPresent', 'IsWow64Process', 'GetConsoleScreenBufferInfo',
             'CreateThread', 'NtClose', 'GetThreadContext', 'SetThreadContext',
             'SuspendThread', 'ResumeThread', 'TerminateThread', 'DuplicateHandle']
for _n in ZERO_APIS:
    HANDLERS.setdefault(_n, 'api_zero')

DEFAULT_APIS = sorted(set(list(HANDLERS.keys()) + EXTRA_APIS))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('password', nargs='?', default='test123')
    ap.add_argument('-o', '--out', default=None)
    ap.add_argument('-v', '--verbose', action='store_true')
    ap.add_argument('--snap-every', type=int, default=0)
    ap.add_argument('--inject-mac', default=None,
                    help='overwrite window[0x140..0x14f] after the sponge runs')
    a = ap.parse_args()
    h = Harness(a.password.encode(), verbose=a.verbose,
                snap_every=a.snap_every, inject_mac=a.inject_mac).run()
    print(f'password={a.password!r} exit_code={h.exit_code} handlers={len(h.trace)}')
    if h.captures.get('exit'):
        c = h.captures['exit']
        print('MAC       =', c['sponge_out'][0x140 * 2:0x140 * 2 + 32])
        print('R[0..7]   =', c['R'][:16])
    out = a.out
    if out:
        data = {'password': a.password, 'exit_code': h.exit_code,
                'vm_setup': h.vm_setup, 'captures': h.captures,
                'trace': h.trace, 'api_log': h.api_log, 'rsnaps': h.rsnaps,
                'int3_skips': h.int3_skips}
        with open(out, 'w') as f:
            json.dump(data, f)
        print('wrote', out, os.path.getsize(out), 'bytes')


if __name__ == '__main__':
    main()
