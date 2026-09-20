# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not [OperatingSystem]::IsWindows()) {
    throw 'The pinned Windows Cosign installer requires Windows.'
}
if ($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted') {
    throw 'The pinned Windows Cosign installer is restricted to GitHub-hosted CI.'
}
if ([string]::IsNullOrWhiteSpace($env:RUNNER_TEMP) -or
    [string]::IsNullOrWhiteSpace($env:GITHUB_PATH)) {
    throw 'RUNNER_TEMP and GITHUB_PATH are required to stage pinned Cosign.'
}

$cosignVersion = '2.6.2'
$cosignUrl = 'https://github.com/sigstore/cosign/releases/download/v2.6.2/cosign-windows-amd64.exe'
$cosignSha256 = 'DD6C61E510DA627BCAED4CD9DB844EC11CACD09826D814D89F7F68D40FEB07BE'
$maximumBytes = 268435456
$curl = [IO.Path]::GetFullPath((Join-Path $env:SystemRoot 'System32\curl.exe'))
if (-not [IO.File]::Exists($curl)) {
    throw 'The hosted Windows curl.exe is unavailable.'
}

# Each hosted job gets a fresh final-name path. Deliberately do not execute,
# move, or delete the verifier here: this helper authenticates the exact digest
# before its first execution, and avoiding post-execution cleanup removes the
# upstream action's Windows executable-lock race.
$toolRoot = Join-Path ([IO.Path]::GetFullPath($env:RUNNER_TEMP)) (
    'defenseclaw-cosign-' + [guid]::NewGuid().ToString('N')
)
[IO.Directory]::CreateDirectory($toolRoot) | Out-Null
$cosign = Join-Path $toolRoot 'cosign.exe'

$curlArguments = @(
    '--fail',
    '--silent',
    '--show-error',
    '--location',
    '--proto', '=https',
    '--proto-redir', '=https',
    '--tlsv1.2',
    '--connect-timeout', '30',
    '--max-time', '300',
    '--max-filesize', [string]$maximumBytes,
    '--retry', '3',
    '--retry-max-time', '300',
    '--output', $cosign,
    $cosignUrl
)
& $curl @curlArguments
if ($LASTEXITCODE -ne 0) {
    throw "Pinned Cosign $cosignVersion download failed with exit $LASTEXITCODE."
}

$cosignItem = Get-Item -LiteralPath $cosign -Force -ErrorAction Stop
if ($cosignItem.PSIsContainer -or
    ($cosignItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
    $cosignItem.Length -le 0 -or
    $cosignItem.Length -gt $maximumBytes) {
    throw "Pinned Cosign $cosignVersion download is not a bounded regular file."
}
if ((Get-FileHash -LiteralPath $cosign -Algorithm SHA256).Hash -cne $cosignSha256) {
    throw "Pinned Cosign $cosignVersion digest mismatch."
}

[IO.File]::AppendAllLines(
    [IO.Path]::GetFullPath($env:GITHUB_PATH),
    [string[]]@($toolRoot)
)
Write-Host "Staged digest-authenticated Cosign $cosignVersion for subsequent Windows steps."
