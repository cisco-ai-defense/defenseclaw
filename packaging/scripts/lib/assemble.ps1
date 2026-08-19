# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
#
# assemble.ps1 — PowerShell mirror of packaging/scripts/lib/assemble.sh.
# Ships inside the build kit produced by
# packaging/scripts/build-managed-windows-bundle.sh when
# --script-host pwsh is passed. Semantically identical to the bash
# version; the cross-shell parity lint in
# scripts/check-assemble-parity.sh keeps the two aligned.
#
# See docs/specs/002-windows-avc-packaging/design.md § Data flow.
# REQ-09 (requirements.md) is this file's contract.
#
# EXIT CODES (design.md § Interfaces) — throw'd through $LASTEXITCODE:
#   0 — success
#   2 — invalid CLI args
#   3 — preflight failure (missing env from repro-flags.ps1)
#   4 — Cisco-signature assertion failed (non-allow-unsigned only)
#   5 — go build failure
#   6 — I/O error

#Requires -Version 7.0

[CmdletBinding()]
param(
    [string]$PayloadDir = './payload',
    [string]$SourceDir  = './source',
    [string]$OutDir     = './out',
    [Parameter(Mandatory)][string]$SourceCommit,
    [Parameter(Mandatory)][string]$Version,
    [Parameter(Mandatory)][string]$CmidPseudoVersion,
    [switch]$AllowUnsigned
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function DefenseClaw-Die {
    param(
        [Parameter(Mandatory)][int]$Code,
        [Parameter(Mandatory)][string]$Message
    )
    [Console]::Error.WriteLine("assemble: $Message")
    exit $Code
}

function DefenseClaw-Stage {
    param([Parameter(Mandatory)][string]$Message)
    Microsoft.PowerShell.Utility\Write-Host "==> $Message"
}

# ---------------------------------------------------------------------------
# Layout probe: same rule as assemble.sh — the lib/ dir lives next to
# this script (shipped kit layout) OR at packaging/scripts/lib/ under
# the repo root (in-repo dev loop).
# ---------------------------------------------------------------------------
$scriptDir = Split-Path -Parent $PSCommandPath
if (Test-Path -LiteralPath (Join-Path $scriptDir 'repro-flags.ps1')) {
    $libDir = $scriptDir
} elseif (Test-Path -LiteralPath (Join-Path $scriptDir 'packaging/scripts/lib/repro-flags.ps1')) {
    $libDir = Join-Path $scriptDir 'packaging/scripts/lib'
} else {
    DefenseClaw-Die -Code 6 -Message "could not locate packaging/scripts/lib/ next to assemble.ps1"
}

# ---------------------------------------------------------------------------
# CLI validation (Mandatory params handle the missing case; validate shape).
# ---------------------------------------------------------------------------
if ($SourceCommit -notmatch '^[0-9a-f]{40}$') {
    DefenseClaw-Die -Code 2 -Message "--source-commit must be a 40-char lowercase git OID (got: '$SourceCommit')"
}
if (-not (Test-Path -LiteralPath $PayloadDir -PathType Container)) {
    DefenseClaw-Die -Code 6 -Message "payload-dir not found: $PayloadDir"
}
if (-not (Test-Path -LiteralPath $SourceDir -PathType Container)) {
    DefenseClaw-Die -Code 6 -Message "source-dir not found: $SourceDir"
}
[void](New-Item -ItemType Directory -Force -Path $OutDir)

DefenseClaw-Stage "assemble.ps1 — DefenseClaw enterprise Setup kit assembler"
DefenseClaw-Stage "payload=$PayloadDir source=$SourceDir out=$OutDir"
$commitPrefix = $SourceCommit.Substring(0, 12)
DefenseClaw-Stage "version=$Version source-commit=${commitPrefix}... allow-unsigned=$AllowUnsigned"

# ---------------------------------------------------------------------------
# Stage 0: build cmd/windows-repro-manifest for the CI host (native arch).
# repro-flags.ps1 will pin GOOS=windows / GOARCH=amd64 shortly, so we build
# the emitter BEFORE sourcing it, in a clean env.
# ---------------------------------------------------------------------------
$emitter = Join-Path $OutDir '.windows-repro-manifest'
if ($IsWindows) { $emitter += '.exe' }
DefenseClaw-Stage "stage 0/6  build native windows-repro-manifest"

$savedEnv = @{}
foreach ($k in @('GOFLAGS','GOOS','GOARCH','GOTOOLCHAIN','CGO_ENABLED')) {
    $savedEnv[$k] = [Environment]::GetEnvironmentVariable($k, 'Process')
    [Environment]::SetEnvironmentVariable($k, $null, 'Process')
}
try {
    Push-Location $SourceDir
    try {
        & go build -trimpath -buildvcs=false -o $emitter ./cmd/windows-repro-manifest
        if ($LASTEXITCODE -ne 0) {
            DefenseClaw-Die -Code 5 -Message "windows-repro-manifest native build failed (exit=$LASTEXITCODE)"
        }
    } finally {
        Pop-Location
    }
} finally {
    foreach ($k in $savedEnv.Keys) {
        [Environment]::SetEnvironmentVariable($k, $savedEnv[$k], 'Process')
    }
}

# ---------------------------------------------------------------------------
# Stage (b): repro-flags preflight. From here on `go build` is the
# outer-Setup cross-build.
# ---------------------------------------------------------------------------
foreach ($k in @('GOFLAGS','GOOS','GOARCH','CGO_ENABLED')) {
    [Environment]::SetEnvironmentVariable($k, $null, 'Process')
}
. (Join-Path $libDir 'repro-flags.ps1')

if ([string]::IsNullOrEmpty([Environment]::GetEnvironmentVariable('SOURCE_DATE_EPOCH', 'Process'))) {
    DefenseClaw-Die -Code 3 -Message "SOURCE_DATE_EPOCH must be exported by the caller (see README-AVC.md)"
}
$env:DEFENSECLAW_BUILDID = "defenseclaw-enterprise-setup-$SourceCommit"

DefenseClaw-Stage "stage 1/6  preflight"
try {
    Invoke-DefenseClawReproPreflight
} catch {
    DefenseClaw-Die -Code 3 -Message "repro-flags preflight failed: $($_.Exception.Message)"
}

# ---------------------------------------------------------------------------
# Stage (c): Cisco-signature assertion for every payload file, unless
# -AllowUnsigned.
# ---------------------------------------------------------------------------
DefenseClaw-Stage "stage 2/6  verify-signatures"
$expectedPayload = @(
    'DefenseClawEnterprise.psm1',
    'defenseclaw-gateway.exe',
    'defenseclaw-hook.exe',
    'defenseclaw.exe',
    'install-enterprise.ps1'
)
foreach ($name in $expectedPayload) {
    $p = Join-Path $PayloadDir $name
    if (-not (Test-Path -LiteralPath $p -PathType Leaf)) {
        DefenseClaw-Die -Code 6 -Message "payload-dir missing required file: $name"
    }
}
$extras = Get-ChildItem -LiteralPath $PayloadDir | Where-Object { $_.Name -notin $expectedPayload }
if ($extras) {
    DefenseClaw-Die -Code 6 -Message "payload-dir contains unexpected entries: $(($extras.Name) -join ', ')"
}

if (-not $AllowUnsigned) {
    . (Join-Path $libDir 'assert-cisco-signature.ps1')
    foreach ($name in $expectedPayload) {
        try {
            Assert-CiscoSignature -Path (Join-Path $PayloadDir $name)
        } catch {
            DefenseClaw-Die -Code 4 -Message $_.Exception.Message
        }
    }
}

# ---------------------------------------------------------------------------
# Stage (d): emit manifest.json into the Go embed dir.
# ---------------------------------------------------------------------------
$embedDir = Join-Path (Join-Path (Join-Path $SourceDir 'cmd') 'defenseclaw-enterprise-setup') 'payload'
[void](New-Item -ItemType Directory -Force -Path $embedDir)

DefenseClaw-Stage "stage 3/6  emit-manifest"
$manifestArgs = @(
    'emit-manifest',
    '--version',       $Version,
    '--source-commit', $SourceCommit,
    '--payload-dir',   $PayloadDir,
    '--out',           (Join-Path $embedDir 'manifest.json')
)
if ($AllowUnsigned) { $manifestArgs += '--unsigned' }
& $emitter @manifestArgs
if ($LASTEXITCODE -ne 0) {
    DefenseClaw-Die -Code 6 -Message "emit-manifest failed (exit=$LASTEXITCODE)"
}

# ---------------------------------------------------------------------------
# Stage (e): copy the signed payload into the embed dir.
# ---------------------------------------------------------------------------
DefenseClaw-Stage "stage 4/6  stage-payload"
foreach ($name in $expectedPayload) {
    Copy-Item -LiteralPath (Join-Path $PayloadDir $name) -Destination (Join-Path $embedDir $name) -Force
}

# ---------------------------------------------------------------------------
# Stage (f): outer Setup EXE cross-build.
# ---------------------------------------------------------------------------
DefenseClaw-Stage "stage 5/6  go-build DefenseClawSetup-Enterprise-x64.exe"
$outerExe = Join-Path $OutDir 'DefenseClawSetup-Enterprise-x64.exe'
Push-Location $SourceDir
try {
    Invoke-DefenseClawReproBuild -Output $outerExe -Package './cmd/defenseclaw-enterprise-setup'
} catch {
    DefenseClaw-Die -Code 5 -Message "outer Setup EXE go build failed: $($_.Exception.Message)"
} finally {
    Pop-Location
}

# ---------------------------------------------------------------------------
# Stage (g): emit-provenance. setup_sha256 is left empty; AVC fills it
# after step-3 signtool sign. We do NOT write the .sha256 sidecar for
# the same reason (design.md § Decisions).
# ---------------------------------------------------------------------------
DefenseClaw-Stage "stage 6/6  emit-provenance"
$provArgs = @(
    'emit-provenance',
    '--version',       $Version,
    '--source-commit', $SourceCommit,
    '--setup-exe',     $outerExe,
    '--out',           (Join-Path $OutDir 'DefenseClawSetup-Enterprise-x64.exe.provenance.json'),
    '--setup-sha256-placeholder'
)
if ($AllowUnsigned) { $provArgs += '--unsigned' }
& $emitter @provArgs
if ($LASTEXITCODE -ne 0) {
    DefenseClaw-Die -Code 6 -Message "emit-provenance failed (exit=$LASTEXITCODE)"
}

Remove-Item -LiteralPath $emitter -Force -ErrorAction SilentlyContinue

DefenseClaw-Stage "done  out/DefenseClawSetup-Enterprise-x64.exe + provenance.json ready"
DefenseClaw-Stage "next  AVC signs the outer EXE, then invokes finalize.ps1 (or"
DefenseClaw-Stage "      populates .sha256 + provenance.setup_sha256 in-pipeline)"
