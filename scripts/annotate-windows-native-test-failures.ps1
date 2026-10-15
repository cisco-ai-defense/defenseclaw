# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

# GitHub's public job page shows annotations even when its test logs and
# diagnostic artifacts require sign-in. Emit only bounded source test names.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$StateRoot,
    [Parameter(Mandatory)][ValidateSet('Go', 'Python')][string]$Suite,
    [ValidateRange(1, 8)][int]$Shard = 1
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$names = [Collections.Generic.List[string]]::new()
$seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$limit = 8

$logs = if ($Suite -eq 'Go') {
    @(Join-Path $StateRoot 'go-test-failure-summary.log')
} else {
    @(Get-ChildItem -LiteralPath $StateRoot -Filter "pytest-shard-$Shard-*.log" -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -ne "pytest-shard-$Shard-files.log" } |
        ForEach-Object { $_.FullName })
}

foreach ($log in $logs) {
    if (-not (Test-Path -LiteralPath $log -PathType Leaf)) { continue }
    # The harness already bounds these files to 256 KiB (Go) or 1 MiB
    # (Python). Refuse an unexpected larger file before reading it.
    if ((Get-Item -LiteralPath $log).Length -gt 1048576) { continue }
    foreach ($line in [IO.File]::ReadLines($log)) {
        $name = ''
        if ($Suite -eq 'Go') {
            if ($line -match '^--- FAIL: ((?:Test|Fuzz|Example)[A-Za-z0-9_]{1,127})(?:/[^ ]*)? \(') {
                $name = $Matches[1]
            }
        } elseif ($line -match '^(?:FAILED|ERROR) (cli/tests/[A-Za-z0-9_./-]+[.]py)(?:::([A-Za-z0-9_]+(?:::[A-Za-z0-9_]+)*))?') {
            $name = if ($Matches[2]) { "$($Matches[1])::$($Matches[2])" } else { $Matches[1] }
        }
        if ($name -and $seen.Add($name)) {
            $names.Add($name)
            if ($names.Count -ge $limit) { break }
        }
    }
    if ($names.Count -ge $limit) { break }
}

$title = "Windows native $Suite test failure"
$message = if ($names.Count) { $names -join ', ' } else { 'No test name was captured; see the diagnostics artifact.' }
Write-Host "::error title=$title::$message"
