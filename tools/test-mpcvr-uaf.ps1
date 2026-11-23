# test-mpcvr-uaf.ps1
# Regression test for the atiumd6a.dll UAF write (MPC-HC bug #4257), with the
# driver observed, not simulated.
#
# Runs mpc-hc64.exe twice with the d3d9shim proxy d3d9.dll in place:
#   CASE 1: Old MPCVR (pre-fix, ae87a3f)   -- expects a UAF write to be observed
#   CASE 2: New MPCVR (post-fix, c229e43)  -- expects none
#
# What the shim does (and does not do):
#
#   The proxy forwards MPCVR's real D3D9 calls into the 2015 AMD driver:
#   CreateTexture/CreateResource, SetTexture, SetRenderTarget/SetDepthStencil,
#   SetFVF/CreateVertexDeclaration/SetVertexDeclaration, DrawPrimitiveUP,
#   Present, Reset.  The driver builds its own channel, draw-param descriptors
#   and state objects from those calls.  Nothing in the shim substitutes its
#   own objects for them anymore.
#
#   Below the driver, the kernel is faked: adapter records (QAI), device
#   callbacks, D3DKMT thunks, fences -- and the driver-package capabilities
#   file atiumd6a.cap, which the driver's engine discovery reads from the
#   system directory and which is answered from memory for that one path.
#   The QAI record also carries the adapter registry path string at +0xE8,
#   without which atiumd6a's device init refuses to build its objects.
#
#   One readback (pfnCaptureToSysMem) per Present drives the driver's batch
#   recorder, the only entry to its deferred state flush.
#
#   Detection, two independent mechanisms on driver-owned memory:
#     1. Fence pages: the driver's 0x98-byte pool allocator is hooked, so each
#        pool object lives on its own VirtualAlloc page; when the driver frees
#        it, the page becomes PAGE_NOACCESS.  A later write through the stale
#        stage binding faults and is logged as "FENCE UAF".
#     2. DR0 write watchpoint: when a texture is released while still bound,
#        the shim captures the driver inner-object pointer from the released
#        resource's [hRes+0x48] and arms a hardware watchpoint on inner+0x64
#        (the clear.A write target).  A hit is logged as "REAL UAF WRITE".
#
# CURRENT STATE (2026-11-22): PASSES on 15.7.1.  OLD faults on a fenced page at
# atiumd6a+0x1856, a read (cmp qword [rcx+8],0) of a texture released while
# still bound to stage 0.  NEW fences more pages and runs more flushes with no
# fault.  The clear.A +0x64 write path itself still never runs, so the
# watchpoint (mechanism 2) has not fired and what is proven is the stale use
# of the freed texture, not the write.
#
# PASS = OLD observes a use after free (either mechanism) with evidence, NEW does not.
#
# Prerequisites:
#   MPCVR must run the D3D9 path.  Set once before running:
#     reg add "HKCU\Software\MPC-BE Filters\MPC Video Renderer" /v UseD3D11 /t REG_DWORD /d 0 /f
#
# Usage:
#   .\tools\test-mpcvr-uaf.ps1
#   .\tools\test-mpcvr-uaf.ps1 -WaitSec 12   # longer wait on a slow machine

param(
    [int]$WaitSec = 30
)
$ErrorActionPreference = 'Stop'

$root       = Split-Path $PSScriptRoot -Parent
$shimSrc    = "$root\build\d3d9.dll"
# The testplayer release binary loads d3d9 via LOAD_LIBRARY_SEARCH_SYSTEM32, bypassing our shim.
# The debug build (compiled from source) uses the standard search order so our proxy DLL is found.
$testplayer = "C:\dev\mpc-hc\bin\mpc-hc_x64_Debug"
$mpcHc      = "$testplayer\mpc-hc64.exe"
$mpcvrDir   = "$testplayer\MPCVR"
$mpcvrDll   = "$mpcvrDir\MpcVideoRenderer64.ax"
$newMpcvr   = "C:\dev\VideoRenderer--w1\_bin\Filter_x64\MpcVideoRenderer64.ax"           # post-fix build (c229e43)
$oldMpcvr   = "C:\dev\VideoRenderer--w-unfixed\_bin\Filter_x64\MpcVideoRenderer64.ax"   # pre-fix build (ae87a3f)
$shim       = "$testplayer\d3d9.dll"
$log        = "$testplayer\d3d9-pid0.log"
$testVideo  = "c:\temp\claude\02ba7d1fedb6afbd\9f610303-24dc-4a9f-b266-db0adda7770a\scratchpad\fmtchange2.ts"

# ---- sanity checks -----------------------------------------------------------
foreach ($f in $shimSrc, $mpcHc, $oldMpcvr, $newMpcvr, $testVideo) {
    if (-not (Test-Path $f)) { throw "Required file not found: $f" }
}

# Verify MPCVR is set to D3D9 mode (UseD3D11 must be 0).
$mpcvrRegKey = "HKCU:\Software\MPC-BE Filters\MPC Video Renderer"
$useD3D11 = (Get-ItemProperty $mpcvrRegKey -ErrorAction SilentlyContinue).UseD3D11
if ($useD3D11 -ne 0) {
    throw "MPCVR must be in D3D9 mode.  Run: reg add `"HKCU\Software\MPC-BE Filters\MPC Video Renderer`" /v UseD3D11 /t REG_DWORD /d 0 /f"
}

# ---- helper ------------------------------------------------------------------
function Invoke-Case {
    param([string]$mpcvrSrc, [string]$label, [bool]$expectUaf, [string]$tag)

    $ver = (Get-Item $mpcvrSrc).VersionInfo.FileVersion
    Write-Host ""
    Write-Host "=== $label (v$ver) ==="

    Copy-Item -Force $mpcvrSrc $mpcvrDll
    Remove-Item $log -ErrorAction SilentlyContinue

    # The shim loads the driver from this worktree, not the main checkout.
    $env:LEGACY9_DRIVER = "$root\drivers\atiumd64.dll"
    $proc = $null
    try {
        $proc = Start-Process -FilePath $mpcHc `
            -ArgumentList "/play `"$testVideo`"" `
            -PassThru
        Write-Host "  pid $($proc.Id) launched, waiting ${WaitSec}s..."
        Start-Sleep -Seconds $WaitSec
        # Close gracefully: the UAF window is MPCVR's ReleaseDevice/ReleaseVP teardown,
        # which a force-kill never runs.  Post WM_CLOSE, give it time to run the
        # release sequence, then force-kill whatever is left.  The player sometimes
        # exits on its own before the wait is over (end of stream); that is fine --
        # the log up to the exit is the evidence either way.
        $closed = $false
        try { $closed = $proc.CloseMainWindow() } catch { Write-Host "  (process already exited before WM_CLOSE)" }
        Write-Host "  CloseMainWindow: $closed; waiting 6s for teardown..."
        Start-Sleep -Seconds 6
    } finally {
        if ($proc) {
            Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
            $proc.WaitForExit(3000) | Out-Null
        }
        $env:LEGACY9_DRIVER = ""
    }

    $lines = if (Test-Path $log) { Get-Content $log } else { @() }

    # Keep a copy of each run's log in the worktree as evidence.
    $logCopy = "$root\build\d3d9-$tag.log"
    if (Test-Path $log) { Copy-Item -Force $log $logCopy }

    # "FENCE UAF:" (with colon) is a real fault hit; "FENCE UAF armed" is only the
    # arming notice printed at texture release and must not count as a detection.
    $fenceLine  = $lines | Select-String "FENCE UAF:" | Where-Object { $_ -match "atiumd(64|6a)" } | Select-Object -First 1
    $wpLine     = $lines | Select-String "REAL UAF WRITE"         | Select-Object -First 1
    $boundLine  = $lines | Select-String "STILL BOUND"            | Select-Object -First 1
    $zozLine    = $lines | Select-String "ZERO-OF-ZERO"           | Select-Object -First 1
    $twCount    = ($lines | Select-String "fenced driverAlloc").Count
    $armLine    = $lines | Select-String "armed DR\d write WP on REAL freed inner" | Select-Object -First 1
    $chanLine   = $lines | Select-String "\[holder\+0x20\]=0{0,15}[1-9a-fA-F]" | Select-Object -First 1
    # The state-flush entry BP is "st.flush" (atiumd6a:0x2180); the older "flush(#N)"
    # counter BP is only armed in --bp-clear mode, which the shim does not use.
    $flushCount = ($lines | Select-String "       st\.flush: chan=").Count
    $uafFound   = ($null -ne $fenceLine) -or ($null -ne $wpLine)

    if ($uafFound) {
        if ($fenceLine) { Write-Host "  FENCE UAF : $($fenceLine.Line.Trim())" }
        if ($wpLine)    { Write-Host "  WATCHPNT  : $($wpLine.Line.Trim())" }
    } else {
        Write-Host "  UAF       : none"
    }
    if ($boundLine)  { Write-Host "  Bound@rel : $($boundLine.Line.Trim())" }
    Write-Host "  Fenced    : $twCount driverAlloc pages fenced$(if ($zozLine) { "  (ZERO-OF-ZERO seen: $($zozLine.Line.Trim()))" })"
    if ($armLine)    { Write-Host "  Watchpoint: $($armLine.Line.Trim())" }
    Write-Host "  Evidence  : real flush ran $flushCount times; channel created: $(if ($chanLine) {'yes'} else {'NO'})"

    $pass = $true
    if ($expectUaf -and -not $uafFound) {
        Write-Host "  FAIL: expected a use after free but none seen"
        if (-not $boundLine) {
            Write-Host "        (no STILL BOUND line -- no texture was seen released while bound,"
            Write-Host "         so the UAF condition never arose in this run; result is inconclusive)"
        }
        $pass = $false
    }
    if ($expectUaf -and $twCount -eq 0) {
        Write-Host "  FAIL: no driverAlloc pages fenced -- CreateResource recorded no driver heap allocs"
        $pass = $false
    }
    if ($expectUaf -and -not $boundLine -and -not $uafFound) {
        Write-Host "  FAIL: zero-of-zero -- nothing was watched (no released-while-bound texture captured)"
        $pass = $false
    }
    if ($expectUaf -and $flushCount -eq 0) {
        Write-Host "  FAIL: the real flush never ran in this run; a quiet log proves nothing"
        $pass = $false
    }
    if (-not $expectUaf -and $uafFound) {
        Write-Host "  FAIL: unexpected use after free (fix did not suppress the UAF)"
        $pass = $false
    }
    if ($pass) { Write-Host "  PASS" }
    return $pass
}

# ---- deploy and run ----------------------------------------------------------
$procPattern = "mpc-hc64"
Get-Process $procPattern -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $mpcHc } | Stop-Process -Force -ErrorAction SilentlyContinue

Copy-Item -Force $shimSrc $shim

# Back up the debug build's original MPCVR so we can restore it at the end
$origMpcvr = "$mpcvrDir\MpcVideoRenderer64.ax.orig"
if (-not (Test-Path $origMpcvr)) { Copy-Item $mpcvrDll $origMpcvr }

# Loop playback so the player does not stop at EOF before WM_CLOSE.  mpc-hc has
# no /loop CLI switch (it shows "Command line help"); the registry setting is the
# supported way.  LoopNum is a COUNT, not a boolean: 0 means "don't repeat", so
# use a large count.  Saved and restored in the finally below.
$mpcHcSettings = 'HKCU:\Software\MPC-HC\MPC-HC\Settings'
$savedLoop    = (Get-ItemProperty $mpcHcSettings -ErrorAction SilentlyContinue).Loop
$savedLoopNum = (Get-ItemProperty $mpcHcSettings -ErrorAction SilentlyContinue).LoopNum
Set-ItemProperty $mpcHcSettings -Name Loop -Value 1 -Type DWord
Set-ItemProperty $mpcHcSettings -Name LoopNum -Value 999 -Type DWord

try {
    # OLD (ae87a3f): textures released while bound -> UAF write expected
    # NEW (c229e43): SetTexture(null) before release -> no UAF write expected
    $p1 = Invoke-Case -mpcvrSrc $oldMpcvr -label "OLD MPCVR (bug present)"  -expectUaf $true  -tag "old"
    $p2 = Invoke-Case -mpcvrSrc $newMpcvr -label "NEW MPCVR (bug absent)"   -expectUaf $false -tag "new"
} finally {
    # Always restore the debug build's original MPCVR (kept separately so this
    # test doesn't permanently alter the debug build), remove the proxy d3d9.dll,
    # and kill any player instance we started.
    if (Test-Path $origMpcvr) { Copy-Item -Force $origMpcvr $mpcvrDll }
    Remove-Item $shim -ErrorAction SilentlyContinue
    Get-Process $procPattern -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $mpcHc } | Stop-Process -Force -ErrorAction SilentlyContinue
    if ($null -ne $savedLoop)    { Set-ItemProperty $mpcHcSettings -Name Loop    -Value $savedLoop    -Type DWord }
    if ($null -ne $savedLoopNum) { Set-ItemProperty $mpcHcSettings -Name LoopNum -Value $savedLoopNum -Type DWord }
}

# ---- result ------------------------------------------------------------------
Write-Host ""
if ($p1 -and $p2) {
    Write-Host "RESULT: PASS"
    exit 0
} else {
    Write-Host "RESULT: FAIL"
    exit 1
}
