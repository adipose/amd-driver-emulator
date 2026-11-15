# Runs build\legacy9.exe against the legacy D3D9 user-mode driver and prints its log.
#
#   tools\legacy9.ps1 -NoDriver                 measure the heap and check the detector, no driver loaded
#   tools\legacy9.ps1 -Rounds 6 -Decoys 128     open and close the adapter six times
#   tools\legacy9.ps1 -Redzone                  guard zones on every driver allocation
#
# The knobs are named rather than passed through: PowerShell binds a bare --flag against this script's own
# parameters first and quietly drops it. Use -Extra, or call build\legacy9.exe directly, for anything else.
[CmdletBinding()]
param(
    [string] $Dll,
    [switch] $NoDriver,
    [int]    $Rounds = 1,
    [int]    $Decoys = 128,
    [switch] $Redzone,
    [switch] $TraceAllocs,
    [switch] $NoSelfTest,
    [string] $Json,
    [string] $Log,
    [string[]] $Extra
)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$build = Join-Path $root 'build'
$exe = Join-Path $build 'legacy9.exe'
if (-not (Test-Path $exe)) { throw "not built: $exe (run build.ps1)" }
if (-not $Log) { $Log = Join-Path $build 'legacy9.log' }

$argv = @('--log', $Log, '--decoys', $Decoys)
if ($NoDriver) {
    $argv += '--no-driver'
} else {
    $resolved = & (Join-Path $PSScriptRoot 'Find-LegacyDriver.ps1') -Path $Dll
    if (-not $resolved) { throw 'no legacy driver found: put atiumd64.dll in drivers\ or set MPC_TEST_AMDUMD (see drivers\README.md)' }
    # The fields the 2015 driver checks in the adapter record before it will open: record size, family 8, and a
    # chip id and revision in the TeraScale range. Without them OpenAdapter faults.
    $argv += @('--dll', $resolved, '--qai-set', '0=0x260,0x3c=8,0x30=0x5a,0x34=0x3c', '--rounds', $Rounds)
}
if ($Redzone)     { $argv += '--redzone' }
if ($TraceAllocs) { $argv += '--trace-allocs' }
if ($NoSelfTest)  { $argv += '--no-self-test' }
if ($Json)        { $argv += @('--json', $Json) }
if ($Extra)       { $argv += $Extra }

Push-Location $build
try {
    & $exe @argv *> $null
    "exit=$LASTEXITCODE"
    if (Test-Path $Log) { Get-Content $Log }
} finally { Pop-Location }
