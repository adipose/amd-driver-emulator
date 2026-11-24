# Patch-AtiumD6a.ps1
#
# Patches AMD Catalyst 15.7.1 atiumd6a.dll to NOP the use-after-free write
# behind MPC-HC #4257. The driver's state-flush routine (clear.A, RVA
# 0x2a1b60) zeroes [inner+0x48]+0x64 via a rep-stosb at RVA 0x2a1b7f without
# checking whether the owning pool object has been freed. Replacing the
# 2-byte F3 AA (rep stosb) with 90 90 (nop nop) removes the stale write.
#
# NOTE: Never commit or publish a patched AMD binary

param(
    [string]$DllPath = 'C:\dev\amd-driver-emulator--patcher\drivers\atiumd6a.dll',
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$targetRva   = 0x2a1b7f
$expectedHash = 'TODO: run Get-FileHash <dll> -Algorithm SHA256 and fill in here'
$expectedBytes = [byte[]](0xF3, 0xAA)
$patchedBytes  = [byte[]](0x90, 0x90)

if (-not (Test-Path -LiteralPath $DllPath)) {
    Write-Error "DLL not found: $DllPath"
    exit 1
}

# --- Hash check (guard against patching the wrong driver build) ---
if ($expectedHash -like 'TODO:*') {
    Write-Warning "expectedHash is a placeholder. Run:"
    Write-Warning "  Get-FileHash '$DllPath' -Algorithm SHA256"
    Write-Warning "and fill the result into `$expectedHash in $PSCommandPath"
    Write-Warning "Continuing WITHOUT hash verification."
} else {
    $actualHash = (Get-FileHash -LiteralPath $DllPath -Algorithm SHA256).Hash
    if ($actualHash -ne $expectedHash) {
        Write-Error "Hash mismatch. Expected $expectedHash, got $actualHash. Refusing to patch an unrecognized build."
        exit 1
    }
    Write-Host "Hash OK: $actualHash"
}

# --- Read the file and locate the target RVA via the PE section table ---
$bytes = [System.IO.File]::ReadAllBytes($DllPath)

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

if ($fileOffset -lt 0) {
    Write-Error ("RVA 0x{0:X} not covered by any section in {1}" -f $targetRva, $DllPath)
    exit 1
}

Write-Host ("RVA 0x{0:X} maps to file offset 0x{1:X}" -f $targetRva, $fileOffset)

# --- Verify current bytes ---
$cur0 = $bytes[$fileOffset]
$cur1 = $bytes[$fileOffset + 1]

$alreadyPatched = ($cur0 -eq $patchedBytes[0] -and $cur1 -eq $patchedBytes[1])
$matchesExpected = ($cur0 -eq $expectedBytes[0] -and $cur1 -eq $expectedBytes[1])

if ($alreadyPatched) {
    Write-Host ("Bytes at 0x{0:X} are already 90 90 - patch already applied, nothing to do." -f $fileOffset)
    exit 0
}
if (-not $matchesExpected) {
    Write-Error ("Expected F3 AA at file offset 0x{0:X}, found {1:X2} {2:X2}. Wrong build or wrong RVA - refusing to patch." -f $fileOffset, $cur0, $cur1)
    exit 1
}

Write-Host ("Verified expected bytes F3 AA at file offset 0x{0:X}" -f $fileOffset)

if ($DryRun) {
    Write-Host "DRY RUN: would replace F3 AA with 90 90. No changes written."
    exit 0
}

# --- Backup (skip silently if the backup already exists) ---
$backupPath = "$DllPath.orig"
if (-not (Test-Path -LiteralPath $backupPath)) {
    Copy-Item -LiteralPath $DllPath -Destination $backupPath
    Write-Host "Backup created: $backupPath"
}

# --- Apply ---
$bytes[$fileOffset]     = $patchedBytes[0]
$bytes[$fileOffset + 1] = $patchedBytes[1]
[System.IO.File]::WriteAllBytes($DllPath, $bytes)

# --- Verify after write ---
$verify = [System.IO.File]::ReadAllBytes($DllPath)
if ($verify[$fileOffset] -eq 0x90 -and $verify[$fileOffset + 1] -eq 0x90) {
    Write-Host ("PATCHED: 90 90 verified at file offset 0x{0:X} in {1}" -f $fileOffset, $DllPath)
    exit 0
} else {
    Write-Error ("Post-write verification failed at file offset 0x{0:X}: found {1:X2} {2:X2}" -f $fileOffset, $verify[$fileOffset], $verify[$fileOffset + 1])
    exit 1
}
