# Returns the path of the legacy D3D9 user-mode driver to drive, or $null.
#
# In order: -Path, $env:MPC_TEST_AMDUMD, then drivers\atiumd64.dll in this repository. Dot-source this or call
# it; it prints the path and nothing else, so it is safe to assign.
[CmdletBinding()]
param([string] $Path, [string] $Leaf = 'atiumd64.dll')

$candidates = @()
if ($Path) { $candidates += $Path }
if ($env:MPC_TEST_AMDUMD) { $candidates += $env:MPC_TEST_AMDUMD }
$candidates += Join-Path (Split-Path $PSScriptRoot -Parent) "drivers\$Leaf"

foreach ($c in $candidates) {
    if (-not $c) { continue }
    # A directory is accepted and the leaf looked for inside it, since that is how the package extracts.
    $try = if (Test-Path $c -PathType Container) { Join-Path $c $Leaf } else { $c }
    if (Test-Path $try -PathType Leaf) { return (Resolve-Path $try).Path }
}
$null
