<#!
.SYNOPSIS
    Safe load-time probe for the workspace's x64 game.dll.

.DESCRIPTION
    Runs in a disposable Windows x64 VM.  The parent process launches a child
    PowerShell process so a loader crash or hang can be terminated without
    taking the analyst's interactive shell with it.  The child calls only
    LoadLibraryExW; it resolves (but never calls) the exported functions and
    records loaded modules, processes, TCP endpoints, and files in the DLL
    directory.  It does not install the COM resource, patch a game process,
    invoke exported functions, or alter the hosts file.

    Network access is refused unless -NetworkIsolated or -AllowNetwork is
    explicitly supplied.  -NetworkIsolated is an assertion by the operator,
    not a firewall: disable networking or apply an outbound firewall rule in
    the disposable VM before running this script.

.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -File .\GameDllProbe.ps1 `
        -DllPath C:\Lab\game.dll -NetworkIsolated -Seconds 45
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string] $DllPath,

    [string] $DependencyDirectory,

    [int] $Seconds = 30,

    [string] $OutputDirectory = (Join-Path (Get-Location) 'game-dll-dynamic-output'),

    [switch] $NetworkIsolated,

    [switch] $AllowNetwork,

    [switch] $Child,

    [string] $ConfigPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-ProbeJson {
    param(
        [Parameter(Mandatory = $true)] [System.Collections.IEnumerable] $Events,
        [Parameter(Mandatory = $true)] [string] $Path
    )
    $parent = Split-Path -Parent $Path
    if ($parent) { New-Item -ItemType Directory -Force -Path $parent | Out-Null }
    @($Events) | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $Path -Encoding UTF8
}

function Start-ProbeChild {
    if (-not $DllPath) { throw '-DllPath is required.' }
    if (-not (Test-Path -LiteralPath $DllPath -PathType Leaf)) {
        throw "DLL not found: $DllPath"
    }
    if ($Seconds -lt 1 -or $Seconds -gt 3600) {
        throw '-Seconds must be between 1 and 3600.'
    }
    if (-not $NetworkIsolated -and -not $AllowNetwork) {
        throw 'Refusing to execute a native DLL without -NetworkIsolated or -AllowNetwork.'
    }
    if ([IntPtr]::Size -ne 8) {
        throw 'Use 64-bit Windows PowerShell. This DLL is PE32+ / x86-64.'
    }

    $out = [IO.Path]::GetFullPath($OutputDirectory)
    New-Item -ItemType Directory -Force -Path $out | Out-Null
    $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
    $jsonPath = Join-Path $out "game_dll_probe_$stamp.json"
    $childLog = Join-Path $out "game_dll_probe_$stamp.child.log"
    $resolvedDll = [IO.Path]::GetFullPath((Resolve-Path -LiteralPath $DllPath).Path)
    $resolvedDeps = $null
    if ($DependencyDirectory) { $resolvedDeps = [IO.Path]::GetFullPath((Resolve-Path -LiteralPath $DependencyDirectory).Path) }
    $networkMode = 'operator-explicitly-allowed-network'
    if ($NetworkIsolated) { $networkMode = 'operator-asserted-network-isolated' }
    $config = [ordered]@{
        DllPath = $resolvedDll
        DependencyDirectory = $resolvedDeps
        Seconds = $Seconds
        OutputPath = $jsonPath
        NetworkMode = $networkMode
        StartedUtc = (Get-Date).ToUniversalTime().ToString('o')
    }
    $configPath = Join-Path $out "game_dll_probe_$stamp.config.json"
    $config | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $configPath -Encoding UTF8

    $ps = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $script = [IO.Path]::GetFullPath($PSCommandPath)
    $args = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -Child -ConfigPath "{1}"' -f $script, $configPath
    $proc = Start-Process -FilePath $ps -ArgumentList $args -PassThru -RedirectStandardOutput $childLog -RedirectStandardError ($childLog + '.err')
    $deadline = (Get-Date).AddSeconds($Seconds + 20)
    $timedOut = $false
    while (-not $proc.HasExited -and (Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 250
        $proc.Refresh()
    }
    if (-not $proc.HasExited) {
        $timedOut = $true
        Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
        $proc.Refresh()
    }
    $exitCode = $null
    if (-not $timedOut) { $exitCode = $proc.ExitCode }
    [pscustomobject]@{
        mode = 'parent'
        pid = $proc.Id
        exit_code = $exitCode
        timed_out = $timedOut
        output_json = $jsonPath
        child_stdout = $childLog
        child_stderr = $childLog + '.err'
        config = $configPath
        note = 'The child only invokes LoadLibraryExW and never calls the DLL exports.'
    } | ConvertTo-Json -Depth 5
}

function Get-ProcessSnapshot {
    $result = @()
    try {
        foreach ($p in (Get-Process -ErrorAction Stop)) {
            $result += [pscustomobject]@{ pid = $p.Id; name = $p.ProcessName }
        }
    } catch {
        $result = @([pscustomobject]@{ error = $_.Exception.Message })
    }
    return @($result)
}

function Get-ModuleSnapshot {
    $result = @()
    try {
        $p = Get-Process -Id $PID -ErrorAction Stop
        foreach ($m in $p.Modules) {
            $result += [pscustomobject]@{
                name = $m.ModuleName
                path = $m.FileName
                base = ('0x{0:X}' -f $m.BaseAddress.ToInt64())
                size = $m.ModuleMemorySize
            }
        }
    } catch {
        $result = @([pscustomobject]@{ error = $_.Exception.Message })
    }
    return @($result)
}

function Get-TcpSnapshot {
    $result = @()
    try {
        $rows = Get-NetTCPConnection -OwningProcess $PID -ErrorAction Stop
        foreach ($r in $rows) {
            $result += [pscustomobject]@{
                local = "$($r.LocalAddress):$($r.LocalPort)"
                remote = "$($r.RemoteAddress):$($r.RemotePort)"
                state = [string]$r.State
            }
        }
    } catch {
        try {
            $lines = netstat.exe -ano | Select-String -Pattern "\s$PID$"
            foreach ($line in $lines) { $result += [string]$line.Line }
        } catch {
            $result = @([pscustomobject]@{ error = $_.Exception.Message })
        }
    }
    return @($result)
}

function Get-DirectorySnapshot {
    param([string] $Directory)
    $result = @()
    try {
        foreach ($f in (Get-ChildItem -LiteralPath $Directory -File -Force -ErrorAction Stop)) {
            $hash = $null
            try { $hash = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash } catch { }
            $result += [pscustomobject]@{
                name = $f.Name
                length = $f.Length
                last_write_utc = $f.LastWriteTimeUtc.ToString('o')
                sha256 = $hash
            }
        }
    } catch {
        $result = @([pscustomobject]@{ error = $_.Exception.Message })
    }
    return @($result)
}

function Start-ProbeChildProcess {
    if (-not $ConfigPath) { throw '-ConfigPath is required in child mode.' }
    $cfg = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
    if ([IntPtr]::Size -ne 8) { throw 'Child is not 64-bit.' }

    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class GameDllProbeNative {
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true, EntryPoint="LoadLibraryExW")]
    public static extern IntPtr LoadLibraryEx(string fileName, IntPtr file, uint flags);
    [DllImport("kernel32.dll", SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool SetDefaultDllDirectories(uint flags);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true, EntryPoint="AddDllDirectory")]
    public static extern IntPtr AddDllDirectory(string path);
    [DllImport("kernel32.dll", CharSet=CharSet.Ansi, SetLastError=true, EntryPoint="GetProcAddress")]
    public static extern IntPtr GetProcAddress(IntPtr module, string name);
}
'@

    $events = New-Object 'System.Collections.Generic.List[object]'
    function Emit {
        param([string] $Type, [object] $Data)
        $events.Add([pscustomobject]@{
            utc = (Get-Date).ToUniversalTime().ToString('o')
            pid = $PID
            type = $Type
            data = $Data
        })
        Write-ProbeJson -Events $events -Path $cfg.OutputPath
    }

    $dll = [string]$cfg.DllPath
    $dllDir = Split-Path -Parent $dll
    $beforeFiles = Get-DirectorySnapshot -Directory $dllDir
    $dllHash = $null
    try { $dllHash = (Get-FileHash -LiteralPath $dll -Algorithm SHA256).Hash } catch { }
    Emit 'start' ([ordered]@{
        dll = $dll
        dll_sha256 = $dllHash
        host = [Environment]::OSVersion.VersionString
        powershell = $PSVersionTable.PSVersion.ToString()
        bitness = [IntPtr]::Size * 8
        network_mode = [string]$cfg.NetworkMode
        dependency_directory = [string]$cfg.DependencyDirectory
        files_before = $beforeFiles
    })

    try {
        # Keep dependency resolution constrained to the DLL directory plus the
        # normal Windows DLL directories. Do not search the current directory.
        [void][GameDllProbeNative]::SetDefaultDllDirectories(0x1000 -bor 0x400)
        if ($cfg.DependencyDirectory) {
            $cookie = [GameDllProbeNative]::AddDllDirectory([string]$cfg.DependencyDirectory)
            Emit 'dependency_search_path' ([ordered]@{ path = [string]$cfg.DependencyDirectory; added = ($cookie -ne [IntPtr]::Zero); last_error = [Runtime.InteropServices.Marshal]::GetLastWin32Error() })
        }
        Emit 'pre_load_processes' (Get-ProcessSnapshot)
        Emit 'pre_load_modules' (Get-ModuleSnapshot)

        # LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR (0x100) and
        # LOAD_LIBRARY_SEARCH_DEFAULT_DIRS (0x1000).
        $flags = 0x100 -bor 0x1000
        $handle = [GameDllProbeNative]::LoadLibraryEx($dll, [IntPtr]::Zero, $flags)
        $lastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        if ($handle -eq [IntPtr]::Zero) {
            Emit 'load_failed' ([ordered]@{ win32_error = $lastError; message = ([System.ComponentModel.Win32Exception]::new([int]$lastError)).Message })
            return
        }
        Emit 'load_succeeded' ([ordered]@{ module_base = ('0x{0:X}' -f $handle.ToInt64()); win32_error_after_load = $lastError })

        # Resolve names only. Calling either export would require the AION ABI
        # and could execute arbitrary protected code beyond the loader path.
        foreach ($name in @('CreateGameInstance', 'CryModuleGetMemoryInfo')) {
            $address = [GameDllProbeNative]::GetProcAddress($handle, $name)
            $addressText = $null
            if ($address -ne [IntPtr]::Zero) { $addressText = '0x{0:X}' -f $address.ToInt64() }
            Emit 'export_resolved' ([ordered]@{ name = $name; address = $addressText })
        }
        Emit 'post_load_modules' (Get-ModuleSnapshot)
        Emit 'post_load_processes' (Get-ProcessSnapshot)
        Emit 'post_load_tcp' (Get-TcpSnapshot)

        $end = (Get-Date).AddSeconds([int]$cfg.Seconds)
        while ((Get-Date) -lt $end) {
            Start-Sleep -Seconds 2
            Emit 'sample' ([ordered]@{
                modules = Get-ModuleSnapshot
                processes = Get-ProcessSnapshot
                tcp = Get-TcpSnapshot
                files = Get-DirectorySnapshot -Directory $dllDir
            })
        }
        Emit 'complete' ([ordered]@{
            files_after = Get-DirectorySnapshot -Directory $dllDir
            final_modules = Get-ModuleSnapshot
            final_tcp = Get-TcpSnapshot
            unload = 'not_called; process exit will unload the DLL'
        })
    } catch {
        Emit 'exception' ([ordered]@{ message = $_.Exception.Message; type = $_.Exception.GetType().FullName; stack = $_.ScriptStackTrace })
        exit 1
    }
}

if ($Child) {
    Start-ProbeChildProcess
} else {
    Start-ProbeChild
}
