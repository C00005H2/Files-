# `game.dll` dynamic probe

`GameDllProbe.ps1` is a **load-time** dynamic-analysis harness for an isolated Windows x64 VM.
It exercises the Windows loader and the DLL's TLS/DllMain path, but deliberately does not call
`CreateGameInstance` or `CryModuleGetMemoryInfo` because their ABI is game-specific and calling
unknown native exports would add unnecessary behavior.

## Safety requirements

1. Use a disposable Windows x64 snapshot. Do not use a workstation or a machine containing game
   accounts, credentials, personal files, or development keys.
2. Disable the VM network adapter before running, or apply an outbound firewall rule for the child
   PowerShell process. The `-NetworkIsolated` switch records the operator's assertion; it does
   **not** configure the firewall itself.
3. Put `game.dll` and only the **matching original dependencies** in a staging directory. The
   repository does not contain `Awesomium.dll`, `binkw64.dll`, `LIBEAY32.dll`,
   `SecureEngineSDK64.dll`, or the VC80 runtime, so a standalone load may fail with a dependency
   error. That failure is still useful evidence and is recorded.
4. Do not register the embedded `NcSoft.MacInfo` COM resource, copy the DLL into a live AION
   installation, disable driver protections, or run the Account Manager as part of this probe.

## Run

From 64-bit Windows PowerShell 5.1:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\GameDllProbe.ps1 `
  -DllPath C:\Lab\game.dll `
  -DependencyDirectory C:\Lab\deps `
  -NetworkIsolated `
  -Seconds 45 `
  -OutputDirectory C:\Lab\probe-output
```

The parent starts a separate 64-bit child PowerShell process and terminates it if the loader hangs
for more than `Seconds + 20`. Output includes:

* exact DLL SHA-256 and host/bits information;
* `LoadLibraryExW` success/failure and Win32 error text;
* resolved addresses for the two coherent exports, without invoking them;
* loaded modules before and after load;
* process list, TCP endpoints owned by the probe, and files in the DLL directory at intervals;
* partial output if the child crashes or times out.

The JSON file is named `game_dll_probe_<UTC timestamp>.json`. Child stdout/stderr and the temporary
configuration file are retained beside it.

## Recommended companion capture

For higher-fidelity behavior, run Procmon or Sysmon in the VM with filters for the child PID and
capture these classes: Process Create/Exit, Image Load, File, Registry, TCP/UDP, and Thread. Also
capture DNS and firewall logs. Useful Procmon filters are:

```text
Process Name is powershell.exe       Include
Path contains C:\Lab\                Include
Operation is TCP Connect             Include
Operation is Load Image              Include
```

If the standalone loader fails, repeat only after placing the exact AION build's dependencies in
the staging directory. A full game-behavior trace requires loading the DLL in the matching AION
client, which is a separate experiment and should remain network-isolated with a disposable client
profile.
