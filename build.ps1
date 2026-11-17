# Builds build\harness.exe with the VS 2022 x64 toolchain.
param(
    [string]$Target = ""
)
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot

# The DDI headers are Microsoft's and are not committed, so a fresh checkout has none. Fetch them here rather
# than making every caller remember to: a clone of this repository should build with one command.
if (-not (Test-Path (Join-Path $root 'third_party\wdk-include\d3d10umddi.h'))) {
    & (Join-Path $root 'tools\Fetch-WdkHeaders.ps1')
}
$vs = & "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" -version '[17.0,18.0)' -products * -latest -property installationPath
if (-not $vs) { throw 'Visual Studio 2022 not found' }
$out = Join-Path $root 'build'
New-Item -ItemType Directory -Force $out | Out-Null
$cl = "cl /nologo /std:c++20 /EHsc /W3 /Zi /Od /MD /I`"$root\third_party\wdk-include`" /Fo`"$out\\`" /Fd`"$out\\`" /Fe`"$out\harness.exe`" `"$root\src\harness.cpp`" /link /DEBUG gdi32.lib"
$cl9 = "cl /nologo /std:c++20 /EHsc /W3 /Zi /Od /MD /I`"$root\third_party\wdk-include`" /Fo`"$out\e_`" /Fd`"$out\e_`" /Fe`"$out\legacy9.exe`" `"$root\src\amd\legacy9.cpp`" /link /DEBUG gdi32.lib shell32.lib"
# Same probe as a DLL, for running inside another process (see tools\inject.ps1). Static CRT: the DLL has to load
# in a host that knows nothing about it, so it must not depend on the redistributable runtime being findable there.
$cl9dll = "cl /nologo /std:c++20 /EHsc /W3 /Zi /Od /MT /LD /DLEGACY9_DLL /I`"$root\third_party\wdk-include`" /Fo`"$out\d_`" /Fd`"$out\d_`" /Fe`"$out\legacy9hook.dll`" `"$root\src\amd\legacy9.cpp`" /link /DEBUG gdi32.lib shell32.lib"
$clinj = "cl /nologo /std:c++20 /EHsc /W3 /Zi /Od /MT /Fo`"$out\i_`" /Fd`"$out\i_`" /Fe`"$out\inject.exe`" `"$root\src\inject.cpp`" /link /DEBUG"
if ($Target -eq 'legacy9') {
    cmd /c "`"$vs\VC\Auxiliary\Build\vcvars64.bat`" >nul && $cl9 && $cl9dll"
} else {
    cmd /c "`"$vs\VC\Auxiliary\Build\vcvars64.bat`" >nul && $cl && $cl9 && $cl9dll && $clinj"
}
if ($LASTEXITCODE) { throw "build failed ($LASTEXITCODE)" }
