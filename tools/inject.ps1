# Runs the legacy-driver probe inside another process, so the driver allocates from that process's heap. Meant
# for a quarantine mpc-hc64.exe: the player's own themed-menu vectors are then the driver's heap neighbours,
# which is the condition #4257 needs and the one a standalone harness is said not to have.
#
#   tools\inject.ps1 -ProcessId 1234
#   tools\inject.ps1 -Player C:\dev\mpc-freehunt-daily\mpc-hc64.exe -Clip C:\path\clip.mkv
#
# Nothing is installed, and no kernel call is forwarded unless --kmt-forward is passed in -ProbeArgs. The
# injection itself is done by build\inject.exe: a DLL cannot be loaded from this shell.
[CmdletBinding()]
param(
    [int] $ProcessId,
    [string] $Player,
    [string] $Clip,
    [string] $Dll,
    # The invented adapter fields are the minimum the 2015 driver checks before it will open: record size,
    # family 8, and a chip id and revision in the TeraScale range. Without them OpenAdapter faults early.
    [string] $ProbeArgs = '--rounds 1 --decoys 256 --redzone --device --workload --workload-dangle --workload-stale-draw --workload-rounds 16 --gpu-va-base 0x20000 --qai-set 0=0x260,0x30=0x5a,0x3c=8,0x1f4=0x480,0xd4=2 --qai-set2 0x2a00=1,0x2a04=1,0x2c2c=1,0x2c30=1',
    [string] $LogPath,
    [string] $JsonPath,
    [int] $SettleSeconds = 10,
    [int] $RunSeconds = 30,
    [switch] $KeepPlayer
)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$hook = Join-Path $root 'build\legacy9hook.dll'
$inject = Join-Path $root 'build\inject.exe'
foreach ($f in $hook, $inject) { if (-not (Test-Path $f)) { throw "not built: $f" } }
$Dll = & (Join-Path $PSScriptRoot 'Find-LegacyDriver.ps1') -Path $Dll
if (-not $Dll) { throw 'no legacy driver found: put atiumd64.dll in drivers\ or set MPC_TEST_AMDUMD (see drivers\README.md)' }
if (-not $LogPath) { $LogPath = Join-Path $root ('build\inproc-{0}.log' -f (Get-Date -Format 'HHmmss')) }

# The probe reads its options from a file beside the hook DLL: a thread started in an already-running process
# cannot be handed a command line or an environment.
$line = "--dll `"$Dll`" --log `"$LogPath`" $ProbeArgs"
if ($JsonPath) { $line += " --json `"$JsonPath`"" }
Set-Content -LiteralPath (Join-Path $root 'build\legacy9hook.args') -Encoding UTF8 -Value $line

$started = $null
if (-not $ProcessId) {
    if (-not $Player) { throw 'pass -ProcessId <pid> or -Player <path to mpc-hc64.exe>' }
    $argv = if ($Clip) { @("`"$Clip`"") } else { @() }
    $started = Start-Process -FilePath $Player -ArgumentList $argv -PassThru
    $ProcessId = $started.Id
    Write-Host "started $Player as pid $ProcessId; settling for $SettleSeconds s so the menus are built"
    Start-Sleep -Seconds $SettleSeconds
}

& $inject --pid $ProcessId --dll $hook
if ($LASTEXITCODE) { throw "inject.exe failed ($LASTEXITCODE)" }

# The log is opened for shared reading, so it can be followed while the probe is still running.
$deadline = (Get-Date).AddSeconds($RunSeconds)
$text = ''
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 2
    if (-not (Test-Path $LogPath)) { continue }
    $fs = [IO.FileStream]::new($LogPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    $sr = [IO.StreamReader]::new($fs)
    $text = $sr.ReadToEnd()
    $sr.Close(); $fs.Close()
    if ($text -match 'PROBE DONE') { break }
}
if ($started -and -not $KeepPlayer) {
    [void]$started.CloseMainWindow()
    Start-Sleep 4
    if (-not $started.HasExited) { Write-Warning "pid $ProcessId did not close; leaving it alone" }
}
if ($text) { $text } else { Write-Warning "no log at $LogPath" }
