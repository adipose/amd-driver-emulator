# test-patch-verify.ps1
#
# Pure byte-level verification of Patch-AtiumD6a.ps1. No MPC-HC needed.
# Exercises: dry-run, real patch, read-back of 90 90, restore from .orig,
# read-back of F3 AA.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$dllPath    = 'C:\dev\amd-driver-emulator--patcher\drivers\atiumd6a.dll'
$backupPath = "$dllPath.orig"
$patcher    = 'C:\dev\amd-driver-emulator--patcher\tools\Patch-AtiumD6a.ps1'
$targetRva  = 0x2a1b7f

function Fail([string]$msg) {
    Write-Host "FAIL: $msg"
    exit 1
}

# --- Precondition checks ---
if (-not (Test-Path -LiteralPath $dllPath)) {
    Write-Host "SKIP: DLL not present at $dllPath"
    exit 0
}

$patcherText = [System.IO.File]::ReadAllText($patcher)
$hashMatch = [regex]::Match($patcherText, "\`$expectedHash\s*=\s*'([^']*)'")
if (-not $hashMatch.Success) { Fail "could not parse `$expectedHash from $patcher" }
$expectedHash = $hashMatch.Groups[1].Value
if ($expectedHash -like 'TODO:*') {
    Write-Host "SKIP: expectedHash not filled in"
    exit 0
}

# --- Compute file offset for the RVA (same PE walk as the patcher) ---
$bytes = [System.IO.File]::ReadAllBytes($dllPath)
$eLfanew = [System.BitConverter]::ToInt32($bytes, 0x3C)
$coffHeaderOffset = $eLfanew + 4
$numSections = [System.BitConverter]::ToInt16($bytes, $coffHeaderOffset + 2)
$sizeOfOptionalHeader = [System.BitConverter]::ToInt16($bytes, $coffHeaderOffset + 16)
$sectionTableOffset = $coffHeaderOffset + 20 + $sizeOfOptionalHeader
$fileOffset = -1
for ($i = 0; $i -lt $numSections; $i++) {
    $secBase = $sectionTableOffset + $i * 40
    $secRva = [System.BitConverter]::ToInt32($bytes, $secBase + 12)
    $secSize = [System.BitConverter]::ToInt32($bytes, $secBase + 8)
    $secFileOff = [System.BitConverter]::ToInt32($bytes, $secBase + 20)
    if ($targetRva -ge $secRva -and $targetRva -lt ($secRva + $secSize)) {
        $fileOffset = $targetRva - $secRva + $secFileOff
        break
    }
}
if ($fileOffset -lt 0) { Fail ("RVA 0x{0:X} not covered by any section" -f $targetRva) }
Write-Host ("File offset for RVA 0x{0:X}: 0x{1:X}" -f $targetRva, $fileOffset)

function Get-TargetBytes {
    $b = [System.IO.File]::ReadAllBytes($dllPath)
    return $b[$fileOffset], $b[$fileOffset + 1]
}

# --- Step 1: dry run ---
$dryOut = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $patcher -DllPath $dllPath -DryRun 2>&1 | Out-String
Write-Host $dryOut
if ($LASTEXITCODE -ne 0) { Fail "dry run exited $LASTEXITCODE" }
if ($dryOut -notmatch 'DRY RUN') { Fail "dry run output missing 'DRY RUN'" }
$b = Get-TargetBytes
if ($b[0] -ne 0xF3 -or $b[1] -ne 0xAA) { Fail ("dry run modified the file: bytes now {0:X2} {1:X2}" -f $b[0], $b[1]) }
Write-Host "Dry run OK (file untouched, still F3 AA)"

# --- Step 2: real patch ---
$patchOut = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $patcher -DllPath $dllPath 2>&1 | Out-String
Write-Host $patchOut
if ($LASTEXITCODE -ne 0) { Fail "patch run exited $LASTEXITCODE" }

# --- Step 3: read back patched bytes ---
$b = Get-TargetBytes
if ($b[0] -ne 0x90 -or $b[1] -ne 0x90) { Fail ("after patch, expected 90 90, found {0:X2} {1:X2}" -f $b[0], $b[1]) }
Write-Host "Patch verified: 90 90 at offset 0x$($fileOffset.ToString('X'))"

if (-not (Test-Path -LiteralPath $backupPath)) { Fail "backup $backupPath was not created" }

# --- Step 4: restore from .orig ---
Copy-Item -LiteralPath $backupPath -Destination $dllPath -Force
Write-Host "Restored $dllPath from $backupPath"

# --- Step 5: verify restored bytes ---
$b = Get-TargetBytes
if ($b[0] -ne 0xF3 -or $b[1] -ne 0xAA) { Fail ("after restore, expected F3 AA, found {0:X2} {1:X2}" -f $b[0], $b[1]) }
Write-Host "Restore verified: F3 AA back in place"

Write-Host "PASS"
exit 0
