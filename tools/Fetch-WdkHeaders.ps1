# Fetches the WDK display-driver DDI headers this repository builds against, from Microsoft's NuGet package,
# into third_party\wdk-include\. Neither the package nor the headers are committed: they are Microsoft's, and
# this is the same arrangement the sibling device repositories use for the SDK and WDK.
#
#   .\tools\Fetch-WdkHeaders.ps1            fetch what is missing
#   .\tools\Fetch-WdkHeaders.ps1 -Force     fetch again over what is there
#
# No WDK installation is needed, and nothing is installed by this script.
[CmdletBinding()]
param(
    [string] $Version = '10.0.26100.6584',
    [switch] $Force
)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$include = Join-Path $root 'third_party\wdk-include'
$cacheDir = Join-Path $root 'third_party\wdk-nupkg'

# Where each header sits inside the package. The SDK version inside the package is the first three parts of the
# package version, which is why it is derived rather than written out twice.
$sdk = ($Version -split '\.')[0..2] -join '.'
$sdk = "$sdk.0"
$wanted = @{
    "c/Include/$sdk/um/d3d10umddi.h"                      = 'd3d10umddi.h'
    "c/Include/$sdk/um/d3d12umddi.h"                      = 'd3d12umddi.h'
    "c/Include/$sdk/um/d3dumddi.h"                        = 'd3dumddi.h'
    "c/Include/$sdk/um/umdprovider.h"                     = 'umdprovider.h'
    "c/Include/$sdk/um/d3d10TokenizedProgramFormat.hpp"   = 'd3d10TokenizedProgramFormat.hpp'
    "c/Include/$sdk/um/d3d11TokenizedProgramFormat.hpp"   = 'd3d11TokenizedProgramFormat.hpp'
    "c/Include/$sdk/um/d3d12TokenizedProgramFormat.hpp"   = 'd3d12TokenizedProgramFormat.hpp'
    "c/Include/$sdk/shared/d3dkmddi.h"                    = 'd3dkmddi.h'
}

New-Item -ItemType Directory -Force $include | Out-Null
$missing = $wanted.Values | Where-Object { -not (Test-Path (Join-Path $include $_)) }
if (-not $missing -and -not $Force) {
    Write-Host "third_party\wdk-include is already populated ($($wanted.Count) headers); -Force to refetch" -ForegroundColor DarkGray
    return
}

New-Item -ItemType Directory -Force $cacheDir | Out-Null
$nupkg = Join-Path $cacheDir "Microsoft.Windows.WDK.x64.$Version.nupkg"
if (-not (Test-Path $nupkg)) {
    $url = "https://www.nuget.org/api/v2/package/Microsoft.Windows.WDK.x64/$Version"
    Write-Host "downloading $url" -ForegroundColor Cyan
    Invoke-WebRequest -Uri $url -OutFile $nupkg -UseBasicParsing
}
Write-Host "extracting from $nupkg" -ForegroundColor Cyan

Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [IO.Compression.ZipFile]::OpenRead($nupkg)
try {
    foreach ($entryPath in $wanted.Keys) {
        $entry = $zip.Entries | Where-Object { $_.FullName -eq $entryPath }
        if (-not $entry) { throw "not in the package: $entryPath (wrong -Version for this layout?)" }
        $out = Join-Path $include $wanted[$entryPath]
        [IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $out, $true)
        Write-Host ("  {0,-36} {1,9:N0} bytes" -f $wanted[$entryPath], $entry.Length)
    }
} finally { $zip.Dispose() }

Write-Host "headers in $include" -ForegroundColor Green
