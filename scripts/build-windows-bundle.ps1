# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
#
# Assemble the machine-level Windows bundle wrapped by AVC's WiX MSI:
# cross-build the gateway + hook + hook-launcher + mgr, copy the config /
# targets templates, generate the README, then produce a zip + sha256.
#
# Called by the `packaging-windows-bundle` Make target so the recipe stays a
# thin wrapper (per repo lint policy against oversized Make recipes).
#
# Positional args mirror scripts/build-macos-bundle.sh so the two build
# scripts can be diffed side-by-side:
#
#   $BundleGoos    "windows"
#   $BundleGoarch  "amd64" | "arm64"
#   $BundleName    e.g. defenseclaw-windows-0.8.0-amd64
#   $BundleDir     e.g. dist/defenseclaw-windows-0.8.0-amd64
#   $DistDir       e.g. dist
#   $Version       e.g. 0.8.0
#   $Ldflags       e.g. "-X main.version=0.8.0"
#   $Tags          (optional) go build -tags value. Defaults to "cmid".
#   $CmidOverlay   (optional) path to private cloudreg provider_cisco.go.
#   $CmidVersion   (optional) pseudo-version to `go get` after the overlay swap.
#
# Runs on Windows PowerShell 5.1+ and PowerShell 7+. Cross-compilation from
# Linux/macOS is supported via `pwsh` when the Go toolchain is present — the
# bundle itself is architecture-agnostic (pure Go binaries + text files);
# only the Authenticode signing step requires a Windows signing host.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $BundleGoos,
    [Parameter(Mandatory = $true)] [string] $BundleGoarch,
    [Parameter(Mandatory = $true)] [string] $BundleName,
    [Parameter(Mandatory = $true)] [string] $BundleDir,
    [Parameter(Mandatory = $true)] [string] $DistDir,
    [Parameter(Mandatory = $true)] [string] $Version,
    [Parameter(Mandatory = $true)] [string] $Ldflags,
    [string] $Tags = "cmid",
    [string] $CmidOverlay = "",
    [string] $CmidVersion = ""
)

$ErrorActionPreference = "Stop"

# ---- input validation ---------------------------------------------------

if ($BundleGoos -ne "windows") {
    Write-Error "build-windows-bundle: BundleGoos must be 'windows' (got '$BundleGoos')"
}
if ($BundleGoarch -notin @("amd64", "arm64")) {
    Write-Error "build-windows-bundle: BundleGoarch must be 'amd64' or 'arm64' (got '$BundleGoarch')"
}

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

Write-Host "==> packaging Windows bundle: $BundleName"

# ---- clean + skeleton ---------------------------------------------------

if (Test-Path $BundleDir) { Remove-Item -Recurse -Force $BundleDir }
New-Item -ItemType Directory -Force -Path (Join-Path $BundleDir "bin") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $BundleDir "etc") | Out-Null

# ---- optional CMID overlay swap ----------------------------------------

$overlayApplied = $false
$overlayTarget  = Join-Path $RepoRoot "internal/managed/cloudreg/provider_cisco.go"
$overlayBackup  = "$overlayTarget.oss.snapshot"

if ($CmidOverlay -ne "" -and $Tags -match "\bcmid\b") {
    if ($CmidVersion -eq "") {
        Write-Error "build-windows-bundle: CmidVersion is required when CmidOverlay is set"
    }
    if (-not (Test-Path $CmidOverlay)) {
        Write-Error "build-windows-bundle: CmidOverlay does not exist: $CmidOverlay"
    }
    Copy-Item -Path $overlayTarget -Destination $overlayBackup -Force
    Copy-Item -Path $CmidOverlay -Destination $overlayTarget -Force
    & go -C $RepoRoot get "github.com/cisco/managed-cloud-auth@$CmidVersion"
    if ($LASTEXITCODE -ne 0) {
        Write-Error "go get managed-cloud-auth@$CmidVersion failed"
    }
    $overlayApplied = $true
}

try {
    # ---- cross-build every PE that ships in the bundle -----------------
    #
    # `defenseclaw-mgr` is amd64-only for now — the Makefile's `gateway-cross`
    # target refuses GOARCH=arm64 on the stamped-resource path, and the
    # lifecycle exe uses the same resource stamper. On an arm64 host the
    # amd64 mgr runs under x64 emulation; that is the ARM64 posture
    # documented in packaging/windows/PACKAGING.md.

    $binDir = Join-Path $BundleDir "bin"

    $env:GOOS   = "windows"
    $env:GOARCH = $BundleGoarch
    $env:CGO_ENABLED = "0"

    $tagsArg = @()
    if ($Tags -ne "") { $tagsArg = @("-tags", $Tags) }

    # Gateway ships native for whatever the bundle arch is.
    & go -C $RepoRoot build @tagsArg -ldflags $Ldflags -o (Join-Path $binDir "defenseclaw-gateway.exe") ./cmd/defenseclaw
    if ($LASTEXITCODE -ne 0) { Write-Error "gateway build failed" }

    # Hook + hook-launcher + mgr are amd64-only. On an arm64 bundle build,
    # switch GOARCH back to amd64 for these three targets so they run under
    # x64 emulation on arm64 Windows.
    $env:GOARCH = "amd64"

    & go -C $RepoRoot build @tagsArg -ldflags $Ldflags -o (Join-Path $binDir "defenseclaw-hook.exe") ./cmd/defenseclaw-hook
    if ($LASTEXITCODE -ne 0) { Write-Error "hook build failed" }

    & go -C $RepoRoot build @tagsArg -ldflags $Ldflags -o (Join-Path $binDir "defenseclaw-hook-launcher.exe") ./cmd/defenseclaw-hook-launcher
    if ($LASTEXITCODE -ne 0) { Write-Error "hook-launcher build failed" }

    & go -C $RepoRoot build -ldflags $Ldflags -o (Join-Path $binDir "defenseclaw-mgr.exe") ./cmd/defenseclaw-mgr
    if ($LASTEXITCODE -ne 0) { Write-Error "mgr build failed" }

    # ---- config + manifest templates -----------------------------------
    #
    # A follow-up port of packaging/macos/lib/installer_lib.sh
    # `render_config` writes byte-compatible templates here. For now the
    # bundle ships an empty placeholder so the archive layout is stable
    # while the config renderer lands.
    $configTemplate = Join-Path $BundleDir "etc/config.yaml.template"
    $targetsTemplate = Join-Path $BundleDir "etc/targets.yaml.template"
    Set-Content -Path $configTemplate -Value "# DefenseClaw managed config template — rendered by defenseclaw-mgr install" -NoNewline
    Set-Content -Path $targetsTemplate -Value "# DefenseClaw hook-guardian targets template — rendered by defenseclaw-mgr install" -NoNewline

    # ---- README --------------------------------------------------------
    $readme = @"
# DefenseClaw Windows bundle $Version ($BundleGoarch)

This archive is consumed by Cisco Secure Client AnyConnect's WiX MSI. The
canonical contract lives in [`packaging/windows/PACKAGING.md`](https://github.com/cisco-ai-defense/defenseclaw/blob/main/packaging/windows/PACKAGING.md).

Layout:

    bin/
      defenseclaw-mgr.exe        # machine-level lifecycle CLI
      defenseclaw-gateway.exe    # gateway service host
      defenseclaw-hook.exe
      defenseclaw-hook-launcher.exe
    etc/
      config.yaml.template
      targets.yaml.template

Every PE in ``bin/`` is Authenticode-signed by ``scripts/windows-authenticode.ps1``.
"@
    Set-Content -Path (Join-Path $BundleDir "README.md") -Value $readme

    # ---- archive + checksum -------------------------------------------
    $zipPath = Join-Path $DistDir "$BundleName.zip"
    if (Test-Path $zipPath) { Remove-Item -Force $zipPath }
    Compress-Archive -Path (Join-Path $BundleDir "*") -DestinationPath $zipPath

    $hash = (Get-FileHash -Algorithm SHA256 -Path $zipPath).Hash.ToLower()
    Set-Content -Path "$zipPath.sha256" -Value "$hash  $BundleName.zip"

    Write-Host "==> wrote $zipPath"
    Write-Host "==> sha256 $hash"
}
finally {
    if ($overlayApplied) {
        Move-Item -Force -Path $overlayBackup -Destination $overlayTarget
    }
}
