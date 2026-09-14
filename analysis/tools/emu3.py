#!/usr/bin/env python3
"""crackme.exe unicorn harness v3. Loads the no-import PE, fakes a minimal Win64
environment (TEB/PEB, console), and stubs the [rip+slot] APIs so the program runs
to the password gate. Goal: capture ground-truth sponge traces (driver buffer +
0x5C10 inner-loop bound) and validate the Python sponge model."""
import sys, struct
import pefile
from unicorn import *
from unicorn.x86_const import *

BIN = '/home/user/Files-/6aa4b6d3585e8875bcbebf80/crackme.exe'
BASE = 0x140000000
DLLBASE = 0x77000000
STACK_TOP = 0x2FFFE000
PASSWORD = sys.argv[1].encode() if len(sys.argv) > 1 else b'test123'

pe = pefile.PE(BIN)
ep = BASE + pe.OPTIONAL_HEADER.AddressOfEntryPoint

mu = Uc(UC_ARCH_X86, UC_MODE_64)

# --- memory mapping ---
def mp(addr, size, name=''):
    mu.mem_map(addr, size)
mu.mem_map(BASE, 0x400000)          # image
for s in pe.sections:
    va = BASE + s.VirtualAddress
    data = s.get_data()
    try:
        mu.mem_write(va, data)
    except Exception:
        mu.mem_write(va, b'\x00'*len(data))
# BSS / .data tail (image may not carry zero-filled sections fully)
mu.mem_map(BASE+0x400000, 0x400000)
mu.mem_map(0x2FF00000, 0x100000)     # stack (top ~0x2FFFE000)
mu.mem_map(0x60000000, 0x1000000)    # heap (console buffers etc.)

# --- TEB / PEB (custom layout: module-list struct at TEB+0x18) ---
TEB = 0x60001000
FAKEPEB = 0x63001000
MODLIST = 0x63003000
MODENTRY = 0x63004000
mu.mem_map(0x63000000, 0x100000)
mu.mem_write(TEB, b'\x00'*0x1000)
mu.mem_write(FAKEPEB, b'\x00'*0x1000)
mu.reg_write(UC_X86_REG_GS_BASE, TEB)
# Module entry (PEB_LDR_DATA_DLL-like). 0x6DD0 reads DllName.Buffer at entry+0x50.
ENT1 = 0x63004000   # kernel32
ENT2 = 0x63004100   # ntdll
def make_entry(addr, name, dllbase):
    buf = addr + 0x80
    wb = name.encode('utf-16-le')
    ent = bytearray(0x100)
    struct.pack_into('<Q', ent, 0x18, dllbase)                    # DllBase
    struct.pack_into('<Q', ent, 0x20, dllbase)                    # returned as module base @+0x20
    struct.pack_into('<H', ent, 0x48, len(wb))                    # DllName.Length
    struct.pack_into('<H', ent, 0x4A, len(wb)*2)                  # DllName.MaximumLength
    struct.pack_into('<Q', ent, 0x50, buf)                        # DllName.Buffer (read @+0x50)
    mu.mem_write(addr, bytes(ent))
    mu.mem_write(buf, wb + b'\x00\x00')   # write name AFTER entry (entry covers +0x80)
    _chk = bytes(mu.mem_read(buf, 8))
    print(f"[make_entry] {name} -> buf=0x{buf:x} first8={_chk.hex()}", file=sys.stderr)
make_entry(ENT1, 'kernel32.dll', DLLBASE)
make_entry(ENT2, 'ntdll.dll', DLLBASE)
# circular InLoadOrderLinks: ENT1.Flink=ENT2, ENT2.Flink=ENT1
e1 = bytearray(mu.mem_read(ENT1, 0x100)); e2 = bytearray(mu.mem_read(ENT2, 0x100))
struct.pack_into('<Q', e1, 0x00, ENT2); struct.pack_into('<Q', e1, 0x08, ENT2)
struct.pack_into('<Q', e2, 0x00, ENT1); struct.pack_into('<Q', e2, 0x08, ENT1)
mu.mem_write(ENT1, bytes(e1)); mu.mem_write(ENT2, bytes(e2))
# Fake PEB: +0x00/+0x20 first entry, +0x50 kept.
fpeb = bytearray(0x1000)
struct.pack_into('<Q', fpeb, 0x00, ENT1)
struct.pack_into('<Q', fpeb, 0x20, ENT1)
struct.pack_into('<Q', fpeb, 0x50, ENT1)
mu.mem_write(FAKEPEB, bytes(fpeb))
# verify name present after setup
_dbg = bytes(mu.mem_read(ENT1+0x80, 24))
print(f"[setup] ENT1+0x80 name bytes = {_dbg.hex()}", file=sys.stderr)
# TEB+0x18 -> FAKEPEB ; keep standard-ish fields too.
teb = bytearray(0x1000)
struct.pack_into('<Q', teb, 0x18, FAKEPEB)
struct.pack_into('<Q', teb, 0x30, FAKEPEB)        # in case code uses std offset
struct.pack_into('<Q', teb, 0x60, TEB)            # Self
mu.mem_write(TEB, bytes(teb))

# --- stack ---
stack = bytearray(STACK_TOP - 0x40000)
# argv for GetCommandLineW-ish paths: store one wide string at 0x60010000
cmdline_w = ('"crackme.exe"').encode('utf-16-le') + b'\x00\x00'
mu.mem_write(0x60010000, cmdline_w)
sp = STACK_TOP - 0x1000
mu.mem_write(sp, struct.pack('<Q', 0xC0DE))     # return addr marker
mu.reg_write(UC_X86_REG_RSP, sp)
mu.reg_write(UC_X86_REG_RIP, ep)

# --- state ---
exit_code = {'code': None}
api_log = []

def read_wstr(addr, maxlen=1024):
    try:
        raw = bytes(mu.mem_read(addr, maxlen*2))
    except Exception:
        return ''
    i = raw.find(b'\x00\x00')
    if i >= 0: raw = raw[:i]
    return raw.decode('utf-16-le', 'replace')

def write_wstr(buf_addr, s):
    mu.mem_write(buf_addr, s.encode('utf-16-le') + b'\x00\x00')

# The binary resolves APIs into slots 0xE000..0xE158 via its own code that calls
# LoadLibraryW / GetProcAddress. We provide those two primitives; the rest are
# dispatched by whatever address lands in each slot. We emulate by hooking the
# slot-indirect CALLs: when rip is about to execute `call [slot]`, we intercept.
# Simpler: hook MEM_READ of the slots is unreliable; instead we let the loader run
# and it will call LoadLibraryW/GetProcAddress which we must expose. But the loader
# reaches them through slots too (chicken/egg). So we pre-fill the bootstrap slots
# with our trampoline addresses for LoadLibraryW & GetProcAddress.

TRAMP = 0x78000000
mu.mem_map(TRAMP, 0x40000)
# Build a tiny stub function for each primitive: sets rax, ret. We'll implement
# via code hooks on the trampoline region using UC_HOOK_CODE ranges.

# Slot indices (rva): we know from static analysis the resolver writes many slots.
# Provide LoadLibraryW & GetProcAddress at fixed trampolines and point the FIRST
# two slots used by the resolver there. From EP trace, first API call @0xB5B9 uses
# [rip+0x2ae9] -> slot 0xE0xx. We'll fill ALL slots lazily: hook reads of 0xE000..0xE160.

API_NAMES = {
    # filled dynamically; see resolve below
}

def make_stub(idx, fn):
    """Return trampoline addr for api idx; installs a code hook over a 0x20 block."""
    base = TRAMP + idx*0x40
    # placeholder instruction sequence: ud2 (we hook before execution)
    mu.mem_write(base, b'\x0f\x0b\xcc\xcc\xcc\xcc\xcc\xcc')
    def h(uc, address, size, user):
        uc.code_delete(hh)
        try:
            fn(uc)
        finally:
            uc.code_add(hh, base, base+0x40, 0)
    hh = mu.hook_add(UC_HOOK_CODE, h, begin=base, end=base+0x40)
    return base

# Instead of per-stub hooks (heavy), use ONE code hook over the whole trampoline
# range and dispatch by address.
stub_dispatch = {}
def taddr(idx): return TRAMP + idx*0x40

def trampoline_hook(uc, address, size, user):
    idx = (address - TRAMP)//0x40
    fn = stub_dispatch.get(idx)
    if fn:
        try: fn(uc)
        except UcError as e: print(f"[stub {idx}] error {e}")
    else:
        # unknown API: return 1 (generic success) and advance past the call
        rsp = uc.reg_read(UC_X86_REG_RSP)
        ret = struct.unpack('<Q', bytes(uc.mem_read(rsp,8)))[0]
        uc.reg_write(UC_X86_REG_RAX, 1)
        uc.reg_write(UC_X86_REG_RSP, rsp+8)
        uc.reg_write(UC_X86_REG_RIP, ret)
        print(f"    [stub {idx} unknown] -> ret 1 @0x{ret:x}", file=sys.stderr)

def install_trampolines():
    for i in range(256):
        mu.mem_write(taddr(i), b'\x0f\x0b'+b'\x00'*0x3e)
    mu.hook_add(UC_HOOK_CODE, trampoline_hook, begin=TRAMP, end=TRAMP+256*0x40)

install_trampolines()

# ---- API implementations (each sets rax then advances RIP past the call) ----
def after_call(uc, ret_val=None):
    # caller did `call [slot]`; next ip = slot_target? No: we replaced the target.
    # We set rip to the instruction AFTER the original call. The original call's
    # return address is on the stack (pushed by call). So pop it.
    ra = struct.unpack('<Q', bytes(uc.mem_read(uc.reg_read(UC_X86_REG_RSP), 8)))[0]
    uc.reg_write(UC_X86_REG_RSP, uc.reg_read(UC_X86_REG_RSP)+8)
    uc.reg_write(UC_X86_REG_RAX, ret_val or 0)
    uc.reg_write(UC_X86_REG_RIP, ra)

def api_loadlibraryw(uc):
    name = read_wstr(uc.reg_read(UC_X86_REG_RCX))
    api_log.append(('LoadLibraryW', name))
    after_call(uc, DLLBASE)   # return the fake DLL base so 0x6BA0 can walk its exports

def api_getprocaddress(uc):
    mod = uc.reg_read(UC_X86_REG_RCX)
    namep = uc.reg_read(UC_X86_REG_RDX)
    name = read_wstr(namep)
    api_log.append(('GetProcAddress', name))
    # assign a trampoline index for this API name
    key = name
    if key not in NAME2IDX:
        NAME2IDX[key] = len(NAME2IDX)
    idx = NAME2IDX[key]
    after_call(uc, taddr(idx))

NAME2IDX = {}

def api_exitprocess(uc):
    code = uc.reg_read(UC_X86_REG_ECX) & 0xFFFFFFFF
    rip = uc.reg_read(UC_X86_REG_RIP)
    # the trampoline is at TRAMP+idx*0x40; the caller's return addr is on stack
    ra = struct.unpack('<Q', bytes(uc.mem_read(uc.reg_read(UC_X86_REG_RSP), 8)))[0]
    print(f"  [EXIT] code={code} rip=0x{rip:x} retaddr=0x{ra:x}", file=sys.stderr)
    try:
        MAC=bytes(mu.mem_read(BASE+0x2B8E0,16))
        R=bytes(mu.mem_read(BASE+0x2B650+0x28,8))
        acc=struct.unpack('<I', bytes(mu.mem_read(BASE+0x2B650+0x10,4)))[0]
        print(f"  [DUMP-MAC] MAC={MAC.hex()} R[0..7]={R.hex()} acc={acc}", file=sys.stderr)
        # full scratch: 0x2B7A0 (scratch base), 64B static + 16B MAC
        scratch=bytes(mu.mem_read(BASE+0x2B7A0,0x80))
        print(f"  [DUMP-SCRATCH] {scratch.hex()}", file=sys.stderr)
        # all R registers (0x28..0x28+16)
        rall=bytes(mu.mem_read(BASE+0x2B650+0x28,16))
        print(f"  [DUMP-RALL] {rall.hex()}", file=sys.stderr)
    except Exception as e:
        print(f"  [DUMP-MAC err] {e}", file=sys.stderr)
    exit_code['code'] = code
    api_log.append(('ExitProcess', code))
    raise StopRun(code)

class StopRun(Exception): pass

def api_readconsolew(uc):
    # hConsoleInput, InBuf, nChars, Read, events
    inp = uc.reg_read(UC_X86_REG_RDX)
    nchars = uc.reg_read(UC_X86_REG_R8D) & 0xFFFF
    readc = uc.reg_read(UC_X86_REG_R9)
    # feed PASSWORD as wide chars (+ newline)
    pw = PASSWORD + b'\r\n'
    wide = pw.decode().encode('utf-16-le')
    take = min(len(wide)//2, nchars)
    mu.mem_write(inp, wide[:take*2])
    # write read count
    mu.mem_write(readc, struct.pack('<I', take))
    api_log.append(('ReadConsoleW', take))
    after_call(uc, 1)

def api_getcommandlinew(uc):
    buf = uc.reg_read(UC_X86_REG_RCX)
    write_wstr(buf, '"crackme.exe"')
    after_call(uc, buf)

def api_writeconsolew(uc):
    out = uc.reg_read(UC_X86_REG_RDX)
    n = uc.reg_read(UC_X86_REG_R8D) & 0xFFFF
    try:
        txt = read_wstr(out, n)
        api_log.append(('WriteConsoleW', txt[:80]))
    except Exception: pass
    after_call(uc, 1)

def api_generic_ok(uc):
    after_call(uc, 1)

def api_zero(uc):
    after_call(uc, 0)

# Map known names -> handlers; unknown -> generic ok.
HANDLERS = {
    'ExitProcess': api_exitprocess,
    'ReadConsoleW': api_readconsolew,
    'GetCommandLineW': api_getcommandlinew,
    'WriteConsoleW': api_writeconsolew,
    'GetStdHandle': lambda uc: after_call(uc, 0xFFFFFFFFFFFFFBD0),
    'GetConsoleMode': lambda uc: after_call(uc, 0),
    'SetConsoleMode': api_generic_ok,
    'FlushConsoleInputBuffer': api_generic_ok,
    'GetKeyState': api_zero,
    'GetAsyncKeyState': api_zero,
    'IsDebuggerPresent': api_zero,
    'CheckRemoteDebuggerPresent': api_zero,
    'QueryPerformanceCounter': lambda uc: after_call(uc, 1234567),
    'QueryPerformanceFrequency': lambda uc: after_call(uc, 10000000),
    'GetTickCount': lambda uc: after_call(uc, 1000),
    'GetTickCount64': lambda uc: after_call(uc, 1000),
    'Sleep': api_generic_ok,
    'RtlNtStatusToDosError': lambda uc: after_call(uc, 0),
    'GetLastError': api_zero,
    ' SetLastError': api_generic_ok,
    'CloseHandle': api_generic_ok,
    'GetModuleHandleW': lambda uc: after_call(uc, 0x7FFF0000),
    'GetVersionExW': api_generic_ok,
    'CreateFileW': api_zero,
    'ReadFile': api_generic_ok,
    'WriteFile': api_generic_ok,
    'GetFileSize': lambda uc: after_call(uc, 0),
    'FindFirstFileW': api_zero,
    'FindNextFileW': api_zero,
    'FindClose': api_generic_ok,
    'GetCurrentDirectoryW': api_generic_ok,
    'SetCurrentDirectoryW': api_generic_ok,
    'MultiByteToWideChar': api_generic_ok,
    'WideCharToMultiByte': api_generic_ok,
    'lstrlenW': lambda uc: after_call(uc, len(read_wstr(uc.reg_read(UC_X86_REG_RCX)))),
    'lstrcpyW': api_generic_ok,
    'MessageBoxW': api_generic_ok,
    'GetForegroundWindow': api_zero,
    'EnumWindows': api_generic_ok,
    'GetWindowTextW': api_generic_ok,
    'ShowWindow': api_generic_ok,
    'FindWindowW': api_zero,
    'GetWindowThreadProcessId': api_generic_ok,
    'OpenProcess': lambda uc: after_call(uc, 0x12345678),
    'Toolhelp32Snapshot': api_zero,
    'Process32FirstW': api_zero,
    'Process32NextW': api_zero,
    'TerminateProcess': api_exitprocess,
    'NtQueryInformationProcess': api_zero,
    'NtSetInformationThread': api_generic_ok,
    'NtClose': api_generic_ok,
    'NtQuerySystemInformation': api_zero,
    'GetSystemDirectoryW': api_generic_ok,
    'GetTempPathW': api_generic_ok,
    'GetUserDefaultUILanguage': api_zero,
    'GetCurrentThreadId': lambda uc: after_call(uc, 1),
    'GetCurrentProcessId': lambda uc: after_call(uc, 1),
    'OutputDebugStringW': api_generic_ok,
    'UnhandledExceptionFilter': api_zero,
    'SetUnhandledExceptionFilter': api_zero,
    'GetCP': api_zero,
    'IsValidCodePage': api_generic_ok,
    'GetLocaleInfoW': api_zero,
    'InterlockedCompareExchange': api_generic_ok,
}
# LoadLibraryW/GetProcAddress handled specially (they drive resolution).
NAME2IDX['LoadLibraryW'] = 0
NAME2IDX['GetProcAddress'] = 1
stub_dispatch[0] = api_loadlibraryw
stub_dispatch[1] = api_getprocaddress

def register_api(name):
    if name in NAME2IDX: return
    idx = len(NAME2IDX)
    NAME2IDX[name] = idx
    handler = HANDLERS.get(name, api_generic_ok)
    stub_dispatch[idx] = handler

# Pre-register all known names so their tramps exist.
for n in list(HANDLERS.keys()):
    register_api(n)

# --- Fake kernel32-like DLL with an export table so 0x6BA0 can resolve APIs ---
mu.mem_map(DLLBASE, 0x400000)
import os, json as _json
API_NAMES_LIST = ['LoadLibraryW','GetProcAddress','ExitProcess','ReadConsoleW','GetCommandLineW',
    'WriteConsoleW','GetStdHandle','GetConsoleMode','SetConsoleMode','FlushConsoleInputBuffer',
    'GetKeyState','GetAsyncKeyState','IsDebuggerPresent','CheckRemoteDebuggerPresent',
    'QueryPerformanceCounter','QueryPerformanceFrequency','GetTickCount','GetTickCount64','Sleep',
    'RtlNtStatusToDosError','GetLastError','CloseHandle','GetModuleHandleW','GetVersionExW',
    'CreateFileW','ReadFile','WriteFile','GetFileSize','FindFirstFileW','FindNextFileW','FindClose',
    'GetCurrentDirectoryW','SetCurrentDirectoryW','MultiByteToWideChar','WideCharToMultiByte',
    'lstrlenW','MessageBoxW','GetForegroundWindow','EnumWindows','GetWindowTextW','ShowWindow',
    'FindWindowW','GetWindowThreadProcessId','OpenProcess','OutputDebugStringW',
    'GetCurrentThreadId','GetCurrentProcessId','NtQueryInformationProcess','NtClose',
    'GetSystemDirectoryW','GetTempPathW','TerminateProcess',
    # extra APIs the binary resolves at runtime
    'VirtualAlloc','CreateThread','CreateToolhelp32Snapshot','Process32FirstW','Process32NextW',
    'GetThreadContext','NtSetInformationThread','RtlAddVectoredExceptionHandler',
    'RtlRemoveVectoredExceptionHandler','VirtualProtect','SetThreadContext','SuspendThread',
    'ResumeThread','GetLastErrorMessage','FormatMessageW','LocalFree','HeapAlloc','HeapFree',
    'TlsAlloc','TlsGetValue','TlsSetValue','TlsFree','InterlockedIncrement','InterlockedDecrement',
    'EnterCriticalSection','LeaveCriticalSection','InitializeCriticalSection',
    'GetCP','IsValidCodePage','GetLocaleInfoW','UnhandledExceptionFilter',
    'SetUnhandledExceptionFilter','AddVectoredExceptionHandler','RemoveVectoredExceptionHandler',
    'RaiseException','TerminateThread','GetCurrentThread','DuplicateHandle','WaitForSingleObject',
    'WaitForMultipleObjects','ResetEvent','SetEvent','CreateEventW','CreateMutexW',
    'ReleaseMutex','CRITICAL_SECTION','GetModuleFileNameW','GetShortPathNameW',
    'GetLongPathNameW','CompareStringW','LCMapStringW','GetUserDefaultLCID',
    'SystemTimeToFileTime','FileTimeToSystemTime','GetFileAttributesW','SetFileAttributesW',
    'DeleteFileW','MoveFileW','CopyFileW','CreateDirectoryW','RemoveDirectoryW',
    'FindFirstFileExW','GetFileInformationByHandle','GetDiskFreeSpaceExW',
    'DeviceIoControl','CreateNamedPipeW','ConnectNamedPipe','DisconnectNamedPipe',
    'TransmitFile','SendDlgItemMessageW','CreateWindowExW','DestroyWindow','DefWindowProcW',
    'RegisterClassW','UnregisterClassW','PostMessageW','SendMessageW','PeekMessageW',
    'TranslateMessage','DispatchMessageW','BeginPaint','EndPaint','GetDC','ReleaseDC',
    'FillRect','InvertRect','TextOutW','DrawTextW','CreateFontW','SelectObject',
    'DeleteObject','GetTextMetricsW','GetStockObject','GetSystemMetrics','LoadCursorW',
    'LoadIconW','LoadImageW','SetCursor','SetIcon','SetFocus','GetFocus','SetActiveWindow',
    'SetActiveWindow','GetClientRect','GetWindowRect','ScreenToClient','ClientToScreen',
    'MapWindowPoints','GetAncestor','SetParent','ChildWindowFromPointEx','WindowFromPoint',
    'IsWindowVisible','IsWindowEnabled','EnableWindow','ShowCursor','GetSysColor',
    'SetSysColors','GetSysColorBrush','GetSysColorPtr','GetKeyboardState','GetKeyboardType',
    'ToUnicode','ToAscii','VkKeyScanW','GetOEMCP','GetACP','GetPrivateProfileStringW',
    'WritePrivateProfileStringW','GetPrivateProfileIntW','GetPrivateProfileSectionW',
    'GetPrivateProfileSectionNamesW','GetPrivateProfileStructW','WritePrivateProfileStructW']
spec={'base':DLLBASE,'out':'/home/user/Files-/analysis/work/fake.dll',
      'apis':[{'name':n,'addr':(TRAMP+NAME2IDX[n]*0x40 - DLLBASE) if n in NAME2IDX else (TRAMP+len(NAME2IDX)*0x40-DLLBASE)} for n in API_NAMES_LIST]}
os.system(f"{sys.executable} /home/user/Files-/analysis/tools/make_fake_dll.py '{_json.dumps(spec)}'")
dllbytes=open('/home/user/Files-/analysis/work/fake.dll','rb').read()
mu.mem_write(DLLBASE, dllbytes)

# --- PatchGuard / checksum self-check: the binary verifies its own code. Since we
#     don't patch anything, the checksum passes naturally. Good.

# --- Hook 0x6BA0 (custom GetProcAddress) to log args ---
gpa_calls = []
def gpa_hook(uc, address, size, user):
    modbase = uc.reg_read(UC_X86_REG_RCX)
    namep = uc.reg_read(UC_X86_REG_RDX)
    try:
        raw = bytes(uc.mem_read(namep, 48)).split(b'\x00')[0]
        nm = raw.decode('latin-1')
    except Exception:
        nm = f'<bad {namep:x}>'
    gpa_calls.append((modbase, nm))
    print(f"  [GPA-{len(gpa_calls)}] searching {nm!r} (cmp_iter={cmp_iters['n']})", file=sys.stderr)
    if len(gpa_calls) <= 25 or len(gpa_calls) % 20 == 0:
        print(f"  [GPA] modbase=0x{modbase:x} name={nm!r}", file=sys.stderr)
    # one-time deep dump of what the resolver sees
    if len(gpa_calls) == 1:
        try:
            pe_off = struct.unpack_from('<I', bytes(uc.mem_read(modbase+0x3C,4)),0)[0]
            ed_rva,ed_size = struct.unpack_from('<II', bytes(uc.mem_read(modbase+pe_off+0x88,8)),0)
            ed = bytes(uc.mem_read(modbase+ed_rva,40))
            nnames = struct.unpack_from('<I',ed,0x18)[0]; npt_rva = struct.unpack_from('<I',ed,0x20)[0]
            npt = struct.unpack_from(f'<{min(nnames,3)}I', bytes(uc.mem_read(modbase+npt_rva, 4*min(nnames,3))),0)
            print(f"    [GPA-ed] ed_rva=0x{ed_rva:x} nnames={nnames} npt[:3]={[hex(p) for p in npt]}", file=sys.stderr)
            for p in npt:
                nb = bytes(uc.mem_read(modbase+p, 16))
                print(f"      name@0x{modbase+p:x} utf16={nb.decode('utf-16-le','replace')!r} raw={nb.hex()}", file=sys.stderr)
            an = bytes(uc.mem_read(namep,16))
            print(f"    [GPA] api_name_raw={an.hex()}", file=sys.stderr)
        except Exception as e:
            print(f"    [GPA-ed] err {e}", file=sys.stderr)
mu.hook_add(UC_HOOK_CODE, gpa_hook, begin=BASE+0x6BA0, end=BASE+0x6BA1)

# Hook 0x6DD0 (PEB module-name lookup) to log args + result
def findmod_hook(uc, address, size, user):
    if address != BASE+0x6DD0: return
    rcx = uc.reg_read(UC_X86_REG_RCX); rdx = uc.reg_read(UC_X86_REG_RDX)
    try:
        raw = bytes(uc.mem_read(rcx, rdx))
        nm = raw.decode('latin-1')
    except Exception:
        nm = f'<bad {rcx:x}>'
    print(f"  [FINDMOD] name={nm!r} len=0x{rdx:x}", file=sys.stderr)
mu.hook_add(UC_HOOK_CODE, findmod_hook, begin=BASE+0x6DD0, end=BASE+0x6DD1)

# Hook the resolver's return point (0x6DB3) to see what it returns
ret_hook_count = {'n':0}
def ret_hook(uc, address, size, user):
    if address != BASE+0x6DB3: return
    ret_hook_count['n'] += 1
    n = ret_hook_count['n']
    rax = uc.reg_read(UC_X86_REG_RAX)
    # log the last few returns (around the 28th API)
    if 25 <= n <= 30:
        print(f"    [RET #{n}] rax=0x{rax:x}", file=sys.stderr)
mu.hook_add(UC_HOOK_CODE, ret_hook, begin=BASE+0x6DB3, end=BASE+0x6DB4)

# Hook the resolver's name-compare loop (0x6C70) to see what it compares
cmp_iters = {'n':0}
def cmp_hook(uc, address, size, user):
    if address != BASE+0x6C70: return
    cmp_iters['n'] += 1
    n = cmp_iters['n']
    # Log iterations in a window around the 28th API search (starts ~1579)
    if n >= 1579 and n <= 1640:
        rax = uc.reg_read(UC_X86_REG_RAX); r8 = uc.reg_read(UC_X86_REG_R8)
        try:
            api_ctx = bytes(uc.mem_read(rax+r8,16)).split(b'\x00')[0]
            exp_ctx = bytes(uc.mem_read(rax,16)).split(b'\x00')[0]
            print(f"    [LOOP #{n}] rax=0x{rax:x} api='{api_ctx.decode('latin-1')}' exp='{exp_ctx.decode('latin-1')}'", file=sys.stderr)
        except Exception as e:
            print(f"    [LOOP #{n}] err {e}", file=sys.stderr)
mu.hook_add(UC_HOOK_CODE, cmp_hook, begin=BASE+0x6C70, end=BASE+0x6C71)

# Hook the module-lookup returns (after call 0x6DD0 at 0x2098 and 0x20EC)
def ret209d_hook(uc, address, size, user):
    if address != BASE+0x209D: return
    rax = uc.reg_read(UC_X86_REG_RAX)
    print(f"    [MOD kernel32] = 0x{rax:x}", file=sys.stderr)
mu.hook_add(UC_HOOK_CODE, ret209d_hook, begin=BASE+0x209D, end=BASE+0x209E)
def ret20f1_hook(uc, address, size, user):
    if address != BASE+0x20F1: return
    rax = uc.reg_read(UC_X86_REG_RAX)
    print(f"    [MOD ntdll] = 0x{rax:x}", file=sys.stderr)
mu.hook_add(UC_HOOK_CODE, ret20f1_hook, begin=BASE+0x20F1, end=BASE+0x20F2)

# After r11=[entry+0x50] is loaded (at 0x6E14), log the name pointer + rsi/rax
def nameptr_hook(uc, address, size, user):
    if address != BASE+0x6E14: return
    r11 = uc.reg_read(UC_X86_REG_R11); rsi = uc.reg_read(UC_X86_REG_RSI)
    nm = ''
    try: nm = read_wstr(r11, 32) if r11 else '<null>'
    except Exception: nm = f'<bad {r11:x}>'
    print(f"  [NAMEPTR] rsi(entry)=0x{rsi:x} r11(name)=0x{r11:x} name={nm!r}", file=sys.stderr)
mu.hook_add(UC_HOOK_CODE, nameptr_hook, begin=BASE+0x6E14, end=BASE+0x6E15)

# --- CPU interrupt handler: skip int3 (interrupt 3) anti-debug breakpoints ---
_int3_skips = [0]
def intr_hook(uc, intno, user):
    if intno != 3: return
    if _int3_skips[0] > 100: return
    rip = uc.reg_read(UC_X86_REG_RIP)
    # after int3, rip points at the byte after the 0xCC
    uc.reg_write(UC_X86_REG_RIP, rip+1)
    _int3_skips[0] += 1
    print(f"    [int3] skipped @0x{rip-1:x}", file=sys.stderr)
mu.hook_add(UC_HOOK_INTR, intr_hook)

# --- Run ---
instr_count = 0
rip_trace = []
def code_hook(uc, address, size, user):
    global instr_count
    instr_count += 1
mu.hook_add(UC_HOOK_CODE, code_hook, begin=BASE, end=BASE+0x800000)

try:
    mu.emu_start(ep, 0, timeout=0, count=200_000_000)
except StopRun as e:
    print(f"EXIT via exception: {e}")
except UcError as e:
    rip = mu.reg_read(UC_X86_REG_RIP)
    print(f"UcError: {e} at rip=0x{rip:x}")
    try:
        import capstone
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        raw = bytes(mu.mem_read(rip-8, 24))
        for i in md.disasm(raw, rip-8):
            print(f"  0x{i.address:x}: {i.mnemonic} {i.op_str}{'  <==' if i.address==rip else ''}")
    except Exception as ex:
        print("  (disasm fail)", ex)

try:
    print(f"\n[final rip=0x{mu.reg_read(UC_X86_REG_RIP):x} instr_count={instr_count}]")
except Exception as e:
    print("[final rip err]", e)
print("\n=== API log ===")
for a in api_log[-60:]:
    print(" ", a)
print(f"\nexit_code={exit_code['code']}")
