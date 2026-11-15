# Runs build\harness.exe with the given arguments and prints a short summary of harness.log:
# how far it got, which unimplemented callbacks were hit, and the last few events.
param([Parameter(ValueFromRemainingArguments = $true)] [string[]] $HarnessArgs)
$build = Join-Path (Split-Path $PSScriptRoot -Parent) 'build'
Push-Location $build
try {
    & .\harness.exe @HarnessArgs *> $null
    $code = $LASTEXITCODE
    $log = Get-Content .\harness.log
    "args: $($HarnessArgs -join ' ')   exit=$code   log lines=$($log.Count)"
    $log | Where-Object { $_ -match '^(OpenAdapter10_2 =|using |CalcPrivateDeviceSize|CreateDevice =|device funcs filled)' }
    $bad = $log | Where-Object { $_ -match '\[stub\]|!!|SetErrorCb|not a device|unknown hResource|unrecognised' } |
        ForEach-Object { ($_ -replace '\(h=.*', '').Trim() } | Group-Object | ForEach-Object { "  $($_.Count) x $($_.Name)" }
    if ($bad) { 'problems:'; $bad }
    $fails = $log | Where-Object { $_ -match '-> (D3DKMT\w+ = )?[c8][0-9a-f]{7}\b' -or $_ -match '^\s*km .* = [c8][0-9a-f]{7}' } |
        ForEach-Object { $_.Trim() } | Group-Object | ForEach-Object { "  $($_.Count) x $($_.Name)" }
    if ($fails) { 'failed kernel calls:'; $fails }
} finally { Pop-Location }
