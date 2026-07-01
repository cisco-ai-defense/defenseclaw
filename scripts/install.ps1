# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

<#
.SYNOPSIS
    DefenseClaw installer for Windows (PowerShell).

.DESCRIPTION
    Installs DefenseClaw from pre-built release artifacts on Windows. The Go
    gateway ships as defenseclaw_<version>_windows_<arch>.zip (containing
    defenseclaw.exe) and the CLI ships as a pure-Python wheel. This is the
    Windows counterpart to scripts/install.sh; it lands:

      * <home>\bin\defenseclaw-gateway.exe  (the Go gateway/sidecar binary)
      * <home>\bin\defenseclaw.cmd          (shim to the CLI in the venv)

    and adds that bin dir to the user PATH. Only Python + uv are required; no Go,
    Node.js, or git. Connector-specific wiring (Codex, Claude Code, ...) is done
    by the cross-platform CLI via `defenseclaw init` / `quickstart`.

    Layout matches scripts/install.sh and `defenseclaw upgrade`: binaries land in
    %USERPROFILE%\.local\bin and the CLI venv lives in
    %USERPROFILE%\.defenseclaw\.venv, so an installed setup upgrades in place.

.EXAMPLE
    irm https://raw.githubusercontent.com/cisco-ai-defense/defenseclaw/main/scripts/install.ps1 | iex

.EXAMPLE
    # Pin a version and pick a connector, non-interactively:
    .\install.ps1 -Version 0.7.0 -Connector codex -Yes -Quickstart

.EXAMPLE
    # Install from a locally built dist directory (for testing):
    .\install.ps1 -Local .\dist
#>

[CmdletBinding()]
param(
    [string]$Connector = "",
    [string]$Version = "",
    [string]$Local = "",
    [ValidateSet("observe", "action", "")]
    [string]$QuickstartMode = "",
    [switch]$Quickstart,
    [switch]$NoOpenclaw,
    [switch]$Yes,
    [switch]$Help
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Prefer TLS 1.2+ on older Windows PowerShell (5.1) where the default can still
# be TLS 1.0/1.1; PowerShell 7 already negotiates modern protocols.
try {
    [Net.ServicePointManager]::SecurityProtocol = `
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch {
    # Property is read-only / unavailable on this host; ignore.
}

# ── Configuration ─────────────────────────────────────────────────────────────

$Repo = "cisco-ai-defense/defenseclaw"
$DefenseClawHome = if ($env:DEFENSECLAW_HOME) { $env:DEFENSECLAW_HOME } else { Join-Path $env:USERPROFILE ".defenseclaw" }
$Venv = Join-Path $DefenseClawHome ".venv"
# Binaries go to %USERPROFILE%\.local\bin to match scripts/install.sh and
# `defenseclaw upgrade` (which replaces the gateway there). The venv stays under
# DEFENSECLAW_HOME so a custom home still relocates the heavy CLI environment.
$InstallDir = Join-Path $env:USERPROFILE ".local\bin"

# Keep in sync with cli/defenseclaw/connector_paths.py KNOWN_CONNECTORS.
# PowerShell runs on Windows, where OpenClaw/ZeptoClaw proxy connectors are
# intentionally hidden because the native Windows path is hook-only.
$ConnectorChoices = @(
    "codex", "claudecode", "hermes", "cursor",
    "windsurf", "geminicli", "copilot", "openhands",
    "antigravity", "opencode", "omnigent", "none"
)

# ── Logging ───────────────────────────────────────────────────────────────────

function Write-Info  { param([string]$Msg) Write-Host "  > $Msg" -ForegroundColor Blue }
function Write-Ok    { param([string]$Msg) Write-Host "  + $Msg" -ForegroundColor Green }
function Write-Warn2 { param([string]$Msg) Write-Host "  ! $Msg" -ForegroundColor Yellow }
function Write-Err2  { param([string]$Msg) Write-Host "  x $Msg" -ForegroundColor Red }
function Write-Step  { param([string]$Msg) Write-Host "`n--- $Msg" -ForegroundColor Cyan }
function Die         { param([string]$Msg) Write-Err2 $Msg; exit 1 }

function Show-Help {
    @"

DefenseClaw Installer (Windows)

Usage:
  irm https://raw.githubusercontent.com/$Repo/main/scripts/install.ps1 | iex
  .\install.ps1 -Local .\dist                 # from a local build
  .\install.ps1 -Yes                          # non-interactive
  .\install.ps1 -Connector codex -Quickstart  # pick connector + bootstrap

Options:
  -Connector <name>    Pick agent connector ($($ConnectorChoices -join '|'))
  -NoOpenclaw          Install gateway/CLI only when no connector is selected
  -Version <x.y.z>     Install a specific release version
  -Local <dir>         Install from a local dist directory instead of downloading
  -Quickstart          Run 'defenseclaw quickstart --non-interactive' post-install
  -QuickstartMode <m>  Pass --mode m to quickstart (observe|action)
  -Yes                 Skip confirmation prompts (for CI/automation)
  -Help                Show this help

Environment variables:
  DEFENSECLAW_HOME     Install root (default: %USERPROFILE%\.defenseclaw)

"@ | Write-Host
}

# ── Utilities ─────────────────────────────────────────────────────────────────

function Test-HasCommand {
    param([string]$Name)
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

# ── Platform detection ────────────────────────────────────────────────────────

function Get-Arch {
    Write-Step "Detecting platform"
    # PROCESSOR_ARCHITEW6432 is set when a 32-bit process runs on 64-bit Windows;
    # prefer it so we never mistake WOW64 for a real 32-bit OS.
    $raw = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
    switch ($raw.ToUpper()) {
        "AMD64" { $arch = "amd64" }
        "ARM64" { $arch = "arm64" }
        "X86"   { Die "32-bit Windows is not supported (need amd64 or arm64)." }
        default { Die "Unsupported architecture: $raw" }
    }
    Write-Ok "Windows ($arch)"
    return $arch
}

# ── Dependency: uv ────────────────────────────────────────────────────────────

function Install-Uv {
    Write-Step "Checking uv"
    if (Test-HasCommand "uv") {
        Write-Ok "uv found"
        return
    }
    Write-Info "Installing uv..."
    try {
        Invoke-RestMethod -Uri "https://astral.sh/uv/install.ps1" | Invoke-Expression
    } catch {
        Die "Failed to install uv. Install manually: https://docs.astral.sh/uv/"
    }
    # uv's installer drops the binary in %USERPROFILE%\.local\bin; surface it on
    # PATH for the rest of this process so subsequent calls resolve.
    $uvDir = Join-Path $env:USERPROFILE ".local\bin"
    if (Test-Path $uvDir) { $env:PATH = "$uvDir;$env:PATH" }
    if (-not (Test-HasCommand "uv")) {
        Die "uv installed but not found on PATH. Open a new terminal and re-run."
    }
    Write-Ok "uv installed"
}

# ── Dependency: Python ────────────────────────────────────────────────────────

function Ensure-Python {
    Write-Step "Checking Python"
    # uv manages an interpreter for us; ask it for 3.12 and install on demand.
    # This avoids depending on a system Python being present or new enough.
    & uv python install 3.12 *> $null
    Write-Ok "Python 3.12 (managed by uv)"
}

# ── Resolve release version ───────────────────────────────────────────────────

function Resolve-Version {
    if ($Local) { return $null }
    Write-Step "Resolving version"
    if ($Version) {
        Write-Ok "Using specified version: $Version"
        return $Version
    }
    try {
        $rel = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" `
            -Headers @{ "User-Agent" = "defenseclaw-installer" }
    } catch {
        Die "Failed to fetch latest release. Use -Version x.y.z or -Local <dir>."
    }
    $tag = $rel.tag_name
    if ($tag -notmatch '^\d+\.\d+\.\d+$') {
        Die "Could not parse release version from tag '$tag'."
    }
    Write-Ok "Latest release: $tag"
    return $tag
}

# ── Artifact fetch + checksum verification ────────────────────────────────────

function Get-Artifact {
    param([string]$Name, [string]$Dest)
    if ($Local) {
        $match = Get-ChildItem -Path (Join-Path $Local $Name) -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $match) { Die "Artifact not found: $Local\$Name" }
        Copy-Item $match.FullName $Dest -Force
        return $match.Name
    }
    $url = "https://github.com/$Repo/releases/download/$script:ReleaseVersion/$Name"
    try {
        Invoke-WebRequest -Uri $url -OutFile $Dest -UseBasicParsing
    } catch {
        Die "Failed to download: $url"
    }
    return $Name
}

# Verify a downloaded file against the release checksums.txt. Skipped for -Local
# installs (the operator built the artifacts themselves). Returns nothing; dies
# on mismatch so a corrupted or tampered download never gets installed.
function Test-Checksum {
    param([string]$File, [string]$FileName)
    if ($Local) { return }
    if (-not $script:ChecksumsFile) {
        $tmp = [System.IO.Path]::GetTempFileName()
        try {
            Invoke-WebRequest -Uri "https://github.com/$Repo/releases/download/$script:ReleaseVersion/checksums.txt" `
                -OutFile $tmp -UseBasicParsing
            $script:ChecksumsFile = $tmp
        } catch {
            Write-Warn2 "Could not download checksums.txt - skipping verification"
            return
        }
    }
    $expected = $null
    foreach ($line in Get-Content $script:ChecksumsFile) {
        $parts = $line -split '\s+', 2
        if ($parts.Count -eq 2 -and $parts[1].Trim() -eq $FileName) {
            $expected = $parts[0].Trim().ToLower()
            break
        }
    }
    if (-not $expected) {
        Write-Warn2 "No checksum entry for $FileName - skipping verification"
        return
    }
    $actual = (Get-FileHash -Path $File -Algorithm SHA256).Hash.ToLower()
    if ($expected -ne $actual) {
        Die "Checksum mismatch for ${FileName}: expected $expected, got $actual"
    }
}

# ── Install: gateway binary ───────────────────────────────────────────────────

function Install-Gateway {
    param([string]$Arch)
    Write-Step "Installing gateway"
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("dc-gw-" + [guid]::NewGuid())
    New-Item -ItemType Directory -Force -Path $tmp | Out-Null
    try {
        if ($Local) {
            # Accept either the zip or a raw defenseclaw.exe in the local dir.
            $zip = Get-ChildItem -Path (Join-Path $Local "defenseclaw_*_windows_$Arch.zip") -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($zip) {
                Expand-Archive -Path $zip.FullName -DestinationPath $tmp -Force
            } else {
                $exe = Get-ChildItem -Path (Join-Path $Local "defenseclaw*.exe") -ErrorAction SilentlyContinue | Select-Object -First 1
                if (-not $exe) { Die "No windows zip or defenseclaw.exe found in $Local" }
                Copy-Item $exe.FullName (Join-Path $tmp "defenseclaw.exe") -Force
            }
        } else {
            $zipName = "defenseclaw_${script:ReleaseVersion}_windows_${Arch}.zip"
            $zipPath = Join-Path $tmp $zipName
            $resolved = Get-Artifact -Name $zipName -Dest $zipPath
            Test-Checksum -File $zipPath -FileName $resolved
            Expand-Archive -Path $zipPath -DestinationPath $tmp -Force
        }
        $binary = Join-Path $tmp "defenseclaw.exe"
        if (-not (Test-Path $binary)) { Die "defenseclaw.exe missing from archive" }
        Copy-Item $binary (Join-Path $InstallDir "defenseclaw-gateway.exe") -Force
    } finally {
        Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
    }
    Write-Ok "Gateway installed -> $InstallDir\defenseclaw-gateway.exe"
}

# ── Install: Python CLI (from wheel) ──────────────────────────────────────────

function Install-Cli {
    Write-Step "Installing DefenseClaw CLI"
    Write-Info "Creating Python environment..."
    & uv venv $Venv --python 3.12 --quiet 2>$null
    if ($LASTEXITCODE -ne 0) {
        & uv venv $Venv --quiet
        if ($LASTEXITCODE -ne 0) { Die "Failed to create Python virtual environment" }
    }
    $venvPython = Join-Path $Venv "Scripts\python.exe"

    Write-Info "Installing from wheel..."
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("dc-cli-" + [guid]::NewGuid())
    New-Item -ItemType Directory -Force -Path $tmp | Out-Null
    try {
        if ($Local) {
            $whl = Get-ChildItem -Path (Join-Path $Local "defenseclaw-*.whl") -ErrorAction SilentlyContinue | Select-Object -First 1
            if (-not $whl) { Die "No wheel found in $Local" }
            $whlPath = $whl.FullName
        } else {
            $whlName = "defenseclaw-${script:ReleaseVersion}-py3-none-any.whl"
            $whlPath = Join-Path $tmp $whlName
            $resolved = Get-Artifact -Name $whlName -Dest $whlPath
            Test-Checksum -File $whlPath -FileName $resolved
        }
        & uv pip install --python $venvPython --quiet $whlPath
        if ($LASTEXITCODE -ne 0) { Die "Failed to install CLI from wheel" }
    } finally {
        Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
    }

    # A .cmd shim on PATH is more robust than relying on the venv's Scripts dir
    # (which would also expose uv/python). PATHEXT includes .CMD, so
    # `defenseclaw` and shutil.which("defenseclaw") both resolve to it.
    $cliExe = Join-Path $Venv "Scripts\defenseclaw.exe"
    $shim = Join-Path $InstallDir "defenseclaw.cmd"
    "@echo off`r`n`"$cliExe`" %*`r`n" | Set-Content -Path $shim -Encoding Ascii -NoNewline

    if (Test-Path $cliExe) {
        Write-Ok "CLI installed -> $shim"
    } else {
        Write-Warn2 "CLI installed but $cliExe not found - check dependencies"
    }
}

# ── Connector selection ───────────────────────────────────────────────────────

function Select-Connector {
    if ($script:PickedConnector) { return }
    if ($Yes) { $script:PickedConnector = "none"; return }

    Write-Step "Pick agent connector"
    Write-Info "DefenseClaw can guard several agent frameworks. Pick one to integrate now;"
    Write-Info "you can switch later with 'defenseclaw init --connector <name>'."
    Write-Host ""
    $i = 1
    foreach ($v in $ConnectorChoices) {
        switch ($v) {
            "codex"      { Write-Host "    $i) codex      - patch %USERPROFILE%\.codex\config.toml + hooks" }
            "claudecode" { Write-Host "    $i) claudecode - patch %USERPROFILE%\.claude\settings.json hooks" }
            "hermes"     { Write-Host "    $i) hermes     - configure Hermes Agent hooks" }
            "cursor"     { Write-Host "    $i) cursor     - configure Cursor hooks" }
            "windsurf"   { Write-Host "    $i) windsurf   - configure Windsurf hooks" }
            "geminicli"  { Write-Host "    $i) geminicli  - configure Gemini CLI hooks" }
            "copilot"    { Write-Host "    $i) copilot    - configure GitHub Copilot CLI hooks" }
            "openhands"  { Write-Host "    $i) openhands  - configure OpenHands hooks" }
            "antigravity" { Write-Host "    $i) antigravity - configure Antigravity hooks" }
            "opencode"   { Write-Host "    $i) opencode   - configure OpenCode hooks" }
            "omnigent"   { Write-Host "    $i) omnigent   - configure OmniGent hooks" }
            "none"       { Write-Host "    $i) none       - install gateway/CLI only; pick later" }
        }
        $i++
    }
    Write-Host ""
    $choice = Read-Host "  Choice [1-$($ConnectorChoices.Count), default 1=codex]"
    if ([string]::IsNullOrWhiteSpace($choice)) { $choice = "1" }
    $idx = 0
    if ([int]::TryParse($choice, [ref]$idx) -and $idx -ge 1 -and $idx -le $ConnectorChoices.Count) {
        $script:PickedConnector = $ConnectorChoices[$idx - 1]
    } else {
        Write-Warn2 "Invalid choice '$choice', defaulting to codex"
        $script:PickedConnector = "codex"
    }
    Write-Ok "Picked connector: $script:PickedConnector"
}

function Save-PickedConnector {
    if (-not $script:PickedConnector -or $script:PickedConnector -eq "none") { return }
    New-Item -ItemType Directory -Force -Path $DefenseClawHome | Out-Null
    Set-Content -Path (Join-Path $DefenseClawHome "picked_connector") -Value $script:PickedConnector
}

# ── Optional: quickstart ──────────────────────────────────────────────────────

function Invoke-Quickstart {
    if (-not $Quickstart) { return }
    Write-Step "Running quickstart"
    if (-not $script:PickedConnector -or $script:PickedConnector -eq "none") {
        Write-Warn2 "Quickstart skipped (no connector). Run 'defenseclaw init' when ready."
        return
    }
    $cliExe = Join-Path $Venv "Scripts\defenseclaw.exe"
    if (-not (Test-Path $cliExe)) { Write-Warn2 "CLI not found - skipping quickstart"; return }
    $args = @("quickstart", "--non-interactive", "--yes", "--connector", $script:PickedConnector)
    if ($QuickstartMode) { $args += @("--mode", $QuickstartMode) }
    & $cliExe @args
    if ($LASTEXITCODE -eq 0) { Write-Ok "Quickstart completed" } else { Write-Warn2 "Quickstart reported errors - run 'defenseclaw doctor'" }
}

# ── PATH configuration ────────────────────────────────────────────────────────

function Add-ToPath {
    # Persist InstallDir on the user PATH (idempotent) and add it to this
    # process so quickstart and `defenseclaw-gateway` resolve immediately.
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if (-not $userPath) { $userPath = "" }
    $entries = $userPath -split ';' | Where-Object { $_ -ne "" }
    if ($entries -notcontains $InstallDir) {
        $newPath = if ($userPath) { "$userPath;$InstallDir" } else { $InstallDir }
        [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
        Write-Step "PATH updated"
        Write-Info "Added $InstallDir to your user PATH."
        Write-Info "Open a new terminal for it to take effect."
    }
    if (($env:PATH -split ';') -notcontains $InstallDir) {
        $env:PATH = "$InstallDir;$env:PATH"
    }
}

# ── Success ───────────────────────────────────────────────────────────────────

function Write-Success {
    Write-Host ""
    Write-Host "  ============================================================" -ForegroundColor Green
    Write-Host "         DefenseClaw installed successfully!" -ForegroundColor Green
    Write-Host "  ============================================================" -ForegroundColor Green
    Write-Host ""
    switch ($script:PickedConnector) {
        "codex"      { Write-Host "  Get started (Codex):`n`n    defenseclaw init --connector codex`n" -ForegroundColor Cyan }
        "claudecode" { Write-Host "  Get started (Claude Code):`n`n    defenseclaw init --connector claudecode`n" -ForegroundColor Cyan }
        { $_ -in @("hermes", "cursor", "windsurf", "geminicli", "copilot", "openhands", "antigravity", "opencode", "omnigent") } {
            Write-Host "  Get started ($script:PickedConnector):`n`n    defenseclaw init --connector $script:PickedConnector`n" -ForegroundColor Cyan
        }
        default      { Write-Host "  Get started (pick a connector later):`n`n    defenseclaw init`n" -ForegroundColor Cyan }
    }
}

# ── Entry point ───────────────────────────────────────────────────────────────

function Main {
    if ($Help) { Show-Help; return }

    Write-Host ""
    Write-Host "  DefenseClaw Installer (Windows)" -ForegroundColor White
    Write-Host "  Enterprise Governance for Agentic AI" -ForegroundColor DarkGray

    $script:PickedConnector = ""
    $script:ChecksumsFile = $null
    $script:ReleaseVersion = $null

    # Validate -Connector and reconcile with -NoOpenclaw.
    if ($Connector) {
        if ($ConnectorChoices -notcontains $Connector) {
            Die "Invalid -Connector '$Connector'. Choices: $($ConnectorChoices -join ', ')"
        }
        $script:PickedConnector = $Connector
    }
    if ($NoOpenclaw) {
        if (-not $script:PickedConnector) {
            $script:PickedConnector = "none"
        }
    }

    if ($Local) {
        $Local = (Resolve-Path $Local).Path
        Write-Info "Installing from local directory: $Local"
    }

    $arch = Get-Arch
    Install-Uv
    Ensure-Python
    $script:ReleaseVersion = Resolve-Version
    Select-Connector
    Install-Gateway -Arch $arch
    Install-Cli

    switch ($script:PickedConnector) {
        { $_ -in @("codex", "claudecode", "hermes", "cursor", "windsurf", "geminicli", "copilot", "openhands", "antigravity", "opencode", "omnigent") } {
            Write-Info "Connector '$script:PickedConnector' wires up via the CLI (no OpenClaw runtime needed)."
        }
        default      { Write-Info "Skipping connector setup - run 'defenseclaw init' when ready" }
    }

    Save-PickedConnector
    Invoke-Quickstart
    Add-ToPath
    Write-Success
}

Main
