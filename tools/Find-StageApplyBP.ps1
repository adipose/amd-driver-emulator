# Find-StageApplyBP.ps1
# Locates the stateApply entry-point RVA in atiumd6a.dll by scanning for its function prologue.
#
# The stateApply function is the innermost deferred-flush handler called ~86x/second by the
# AMD TeraScale D3D9 UMD.  Its address is used as a breakpoint in the FENCE UAF shim (d3d9shim)
# to drive the driver's command-buffer processing during the regression test.
#
# Signature coverage:
#   14.4  (8.14.10.0448) -> RVA 0x1BA0
#   15.7.1(8.14.10.0513) -> RVA 0x2180
#   16.2.1(8.14.10.0533) -> RVA 0x2180
#   13.9  (8.14.10.0359) -> NOT FOUND (different codegen; needs dynamic profiling)
#
# Usage:
#   .\tools\Find-StageApplyBP.ps1 -DllPath C:\temp\amd-drivers\14.4\atiumd6a.dll

param(
    [Parameter(Mandatory)]
    [string]$DllPath
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path $DllPath)) { throw "Not found: $DllPath" }

$bytes = [System.IO.File]::ReadAllBytes($DllPath)
$ver   = (Get-Item $DllPath).VersionInfo.FileVersion
Write-Host "atiumd6a.dll  FileVersion=$ver  Size=$($bytes.Length) bytes"

# -- PE helpers ---------------------------------------------------------------

function Get-CodeSection {
    param([byte[]]$b)
    $peOff   = [BitConverter]::ToInt32($b, 0x3C)
    $numSec  = [BitConverter]::ToInt16($b, $peOff + 6)
    $optSz   = [BitConverter]::ToInt16($b, $peOff + 20)
    $secBase = $peOff + 24 + $optSz
    # Return the first executable section (.text)
    for ($i = 0; $i -lt $numSec; $i++) {
        $s       = $secBase + $i * 40
        $chars   = [BitConverter]::ToUInt32($b, $s + 36)
        $isExec  = ($chars -band 0x20000000) -ne 0  # IMAGE_SCN_MEM_EXECUTE
        $isCode  = ($chars -band 0x00000020) -ne 0  # IMAGE_SCN_CNT_CODE
        if ($isExec -or $isCode) {
            return [PSCustomObject]@{
                VAddr  = [BitConverter]::ToUInt32($b, $s + 12)
                VSize  = [BitConverter]::ToUInt32($b, $s + 16)
                RawOff = [BitConverter]::ToUInt32($b, $s + 20)
            }
        }
    }
    return $null
}

function FileOff-To-RVA {
    param([byte[]]$b, [int]$fileOff)
    $peOff   = [BitConverter]::ToInt32($b, 0x3C)
    $numSec  = [BitConverter]::ToInt16($b, $peOff + 6)
    $optSz   = [BitConverter]::ToInt16($b, $peOff + 20)
    $secBase = $peOff + 24 + $optSz
    for ($i = 0; $i -lt $numSec; $i++) {
        $s      = $secBase + $i * 40
        $vAddr  = [BitConverter]::ToUInt32($b, $s + 12)
        $vSize  = [BitConverter]::ToUInt32($b, $s + 16)
        $rawOff = [BitConverter]::ToUInt32($b, $s + 20)
        # RawSz is 0 in AMD driver DLLs -- sections are contiguous; use VSize as upper bound
        if ($fileOff -ge $rawOff -and $fileOff -lt ($rawOff + $vSize)) {
            return [int]($vAddr + ($fileOff - $rawOff))
        }
    }
    return -1
}

# -- Signatures ---------------------------------------------------------------
# Primary: 14.4 / 15.7.1 / 16.2.1 (REX PUSH prologue with frame-pointer trick)
#   40 55        PUSH RBP  (with REX.B prefix)
#   57           PUSH RDI
#   41 55        PUSH R13
#   41 56        PUSH R14
#   48 8D 6C 24 C1  LEA RBP, [RSP-0x3F]   (dynamic frame base)
#   48 81 EC B8 00 00 00  SUB RSP, 0xB8
# Use the comma operator to force an array-of-arrays (not an unwrapped byte array)
$sig0 = [byte[]]@(0x40,0x55,0x57,0x41,0x55,0x41,0x56,0x48,0x8D,0x6C,0x24,0xC1,0x48,0x81,0xEC,0xB8)
$sigs = @(,$sig0)  # 16-byte exact match (14.4, 15.7.1, 16.2.1)

# -- Scan ---------------------------------------------------------------------
$cs = Get-CodeSection -b $bytes
if (-not $cs) { throw "No executable section found in $DllPath" }

Write-Host ("Code section: VAddr=0x{0:X}  VSize=0x{1:X}  RawOff=0x{2:X}" -f $cs.VAddr, $cs.VSize, $cs.RawOff)

$found = $null
foreach ($sig in $sigs) {
    $hits = [System.Collections.Generic.List[int]]::new()
    $limit = $cs.RawOff + $cs.VSize - $sig.Length
    for ($i = [int]$cs.RawOff; $i -lt $limit; $i++) {
        $ok = $true
        for ($j = 0; $j -lt $sig.Length; $j++) {
            if ($bytes[$i + $j] -ne $sig[$j]) { $ok = $false; break }
        }
        if ($ok) { $hits.Add($i) }
    }
    if ($hits.Count -eq 1) {
        $rva = FileOff-To-RVA -b $bytes -fileOff $hits[0]
        $found = [PSCustomObject]@{ FileOff = $hits[0]; RVA = $rva; SigLen = $sig.Length }
        break
    } elseif ($hits.Count -gt 1) {
        Write-Host "WARNING: signature matched $($hits.Count) times -- ambiguous, trying next"
    }
}

if ($found) {
    Write-Host ""
    Write-Host ("stateApply found:  RVA=0x{0:X}  (file offset 0x{1:X})" -f $found.RVA, $found.FileOff)
    Write-Host ""
    Write-Host "Set this in d3d9shim.cpp:"
    Write-Host ("    static const DWORD kStateApplyRVA = 0x{0:X};" -f $found.RVA)
    exit 0
} else {
    Write-Host ""
    Write-Host "stateApply NOT FOUND with known signatures."
    Write-Host "This driver version predates the 14.x codegen (FileVersion < 8.14.10.0400)."
    Write-Host "Use dynamic profiling: run with -ProfileMode to sample RIP distribution."
    exit 1
}
