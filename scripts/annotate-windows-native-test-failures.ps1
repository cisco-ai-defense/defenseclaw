# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

# GitHub's public job page shows annotations even when its test logs and
# diagnostic artifacts require sign-in. Emit only bounded source test names.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$StateRoot,
    [Parameter(Mandatory)][ValidateSet('Go', 'Python')][string]$Suite,
    [ValidateRange(1, 12)][int]$Shard = 1
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
        } elseif ($line -match '^(?:FAILED|ERROR) (cli/tests/[A-Za-z0-9_./-]+[.]py)(?:::([A-Za-z0-9_]+(?:::[A-Za-z0-9_]+)*))?(\[(?:powershell|pwsh)-enterprise-(?:standalone|profile)-[a-z0-9-]+-smoke[.]ps1\])?') {
            $name = if ($Matches[2]) { "$($Matches[1])::$($Matches[2])" } else { $Matches[1] }
            # This one native smoke matrix needs its parameter ID to identify
            # the failing engine and script. Admit only the fixed, non-secret
            # engine/script shape; arbitrary pytest parameter values remain hidden.
            if ($Matches[3] -and
                $Matches[1] -eq 'cli/tests/test_windows_enterprise_standalone_contract.py' -and
                $Matches[2] -eq 'test_standalone_smokes_run_on_every_engine') {
                $name += $Matches[3]
            }
        }
        if ($name.Length -gt 256) { continue }
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
