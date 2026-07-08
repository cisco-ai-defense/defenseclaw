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
    defenseclaw.exe and defenseclaw-hook.exe) and the CLI ships as a
    pure-Python wheel. This is the
    Windows counterpart to scripts/install.sh; it lands:

      * <home>\.local\bin\defenseclaw-gateway.exe  (gateway/sidecar)
      * <home>\.local\bin\defenseclaw-hook.exe     (no-console hook launcher)
      * <home>\.local\bin\defenseclaw.cmd          (CLI shim)

    and adds that bin dir to the user PATH. Only Python + uv are required; no Go,
    Node.js, or git. Connector-specific wiring (Codex CLI or Claude Code) is done
    by the cross-platform CLI via `defenseclaw init` / `quickstart`.

    Layout matches scripts/install.sh and `defenseclaw upgrade`: binaries land in
    %USERPROFILE%\.local\bin and the CLI venv lives in
    %USERPROFILE%\.defenseclaw\.venv, so an installed setup upgrades in place.

.EXAMPLE
    $Version = "0.8.3"
    $InstallUrl = "https://raw.githubusercontent.com/cisco-ai-defense/defenseclaw/$Version/scripts/install.ps1"
    & ([scriptblock]::Create((irm $InstallUrl))) -Version $Version

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
# Certified native-Windows x64 release surface. Keep this in sync with
# cli/defenseclaw/platform_support.py WINDOWS_SUPPORTED_CONNECTORS.
$ConnectorChoices = @(
    "codex",
    "claudecode",
    "none"
)
$HookConnectors = $ConnectorChoices | Where-Object { $_ -notin @("codex", "claudecode", "none") }

# ── Logging ───────────────────────────────────────────────────────────────────

function Write-Info  { param([string]$Msg) Write-Host "  > $Msg" -ForegroundColor Blue }
function Write-Ok    { param([string]$Msg) Write-Host "  + $Msg" -ForegroundColor Green }
function Write-Warn2 { param([string]$Msg) Write-Host "  ! $Msg" -ForegroundColor Yellow }
function Write-Err2  { param([string]$Msg) Write-Host "  x $Msg" -ForegroundColor Red }
function Write-Step  { param([string]$Msg) Write-Host "`n--- $Msg" -ForegroundColor Cyan }
function Die         { param([string]$Msg) throw $Msg }

function Show-Help {
    @"

DefenseClaw Installer (Windows)

Usage:
  `$Version = "0.8.3"
  `$InstallUrl = "https://raw.githubusercontent.com/$Repo/`$Version/scripts/install.ps1"
  & ([scriptblock]::Create((irm `$InstallUrl))) -Version `$Version
  .\install.ps1 -Local .\dist                 # from a local build
  .\install.ps1 -Yes                          # non-interactive
  .\install.ps1 -Connector codex -Quickstart  # pick connector + bootstrap

Options:
  -Connector <name>    Pick agent connector ($($ConnectorChoices -join '|'))
  -NoOpenclaw          Legacy alias for -Connector none; installs gateway/CLI only
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

function Invoke-Uv {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,
        [switch]$ShowFailureOutput
    )

    # Windows PowerShell 5.1 turns any native stderr text into an ErrorRecord.
    # With the installer's global ErrorActionPreference=Stop, harmless uv
    # progress/status output would therefore abort even when uv exits zero.
    # Capture both streams under Continue and make the native exit status the
    # only success criterion. PowerShell 7 does not need the workaround, but
    # follows the same explicit status contract here.
    $previousErrorActionPreference = $ErrorActionPreference
    $output = @()
    $exitCode = 1
    try {
        $ErrorActionPreference = "Continue"
        $output = & uv --no-config @Arguments 2>&1
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }

    if ($ShowFailureOutput -and $exitCode -ne 0) {
        foreach ($line in $output) {
            Write-Host "    $line" -ForegroundColor DarkGray
        }
    }
    return [int]$exitCode
}

function Invoke-ManagedCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Executable,
        [string[]]$Arguments = @()
    )

    $hadPythonPath = Test-Path Env:\PYTHONPATH
    $hadPythonHome = Test-Path Env:\PYTHONHOME
    $savedPythonPath = $env:PYTHONPATH
    $savedPythonHome = $env:PYTHONHOME
    $previousErrorActionPreference = $ErrorActionPreference
    $lastExitVariable = Get-Variable -Name LASTEXITCODE -Scope Global -ErrorAction SilentlyContinue
    $hadLastExitCode = $null -ne $lastExitVariable
    $savedLastExitCode = if ($hadLastExitCode) { $lastExitVariable.Value } else { $null }
    $output = @()
    $exitCode = 1
    try {
        Remove-Item Env:\PYTHONPATH -ErrorAction SilentlyContinue
        Remove-Item Env:\PYTHONHOME -ErrorAction SilentlyContinue
        $ErrorActionPreference = "Continue"
        $global:LASTEXITCODE = 1
        $output = & $Executable @Arguments 2>&1
        $exitCode = $global:LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousErrorActionPreference
        if ($hadLastExitCode) { $global:LASTEXITCODE = $savedLastExitCode }
        else { Remove-Variable -Name LASTEXITCODE -Scope Global -ErrorAction SilentlyContinue }
        if ($hadPythonPath) { $env:PYTHONPATH = $savedPythonPath }
        else { Remove-Item Env:\PYTHONPATH -ErrorAction SilentlyContinue }
        if ($hadPythonHome) { $env:PYTHONHOME = $savedPythonHome }
        else { Remove-Item Env:\PYTHONHOME -ErrorAction SilentlyContinue }
    }
    return [pscustomobject]@{ ExitCode = [int]$exitCode; Output = @($output) }
}

function Test-ManagedCli {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Venv,
        [Parameter(Mandatory = $true)]
        [string]$CliExe
    )

    if (-not (Test-Path -LiteralPath $CliExe -PathType Leaf)) {
        throw "Managed CLI executable not found after repair: $CliExe"
    }

    $versionResult = Invoke-ManagedCommand -Executable $CliExe -Arguments @("--version")
    if ($versionResult.ExitCode -ne 0) {
        $detail = ($versionResult.Output | Select-Object -First 5) -join " | "
        throw "Managed CLI smoke test failed (exit $($versionResult.ExitCode)): $detail"
    }

    $venvPython = Join-Path $Venv "Scripts\python.exe"
    $importCode = "import pathlib, defenseclaw; print(pathlib.Path(defenseclaw.__file__).resolve())"
    $importResult = Invoke-ManagedCommand -Executable $venvPython -Arguments @("-I", "-c", $importCode)
    if ($importResult.ExitCode -ne 0) {
        $detail = ($importResult.Output | Select-Object -First 5) -join " | "
        throw "Managed CLI import validation failed (exit $($importResult.ExitCode)): $detail"
    }

    $importedPath = [System.IO.Path]::GetFullPath((($importResult.Output | Select-Object -Last 1).ToString()).Trim())
    $siteRoot = [System.IO.Path]::GetFullPath((Join-Path $Venv "Lib\site-packages")).TrimEnd('\') + '\'
    if (-not $importedPath.StartsWith($siteRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Managed CLI import escaped the target venv: $importedPath"
    }
}

function Test-ManagedEnvironment {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Venv
    )

    $venvPython = Join-Path $Venv "Scripts\python.exe"
    $cliExe = Join-Path $Venv "Scripts\defenseclaw.exe"
    Test-ManagedCli -Venv $Venv -CliExe $cliExe

    $pipCheck = Invoke-Uv -Arguments @("pip", "check", "--python", $venvPython) -ShowFailureOutput
    if ($pipCheck -ne 0) {
        throw "Managed CLI dependency validation failed (uv pip check exit $pipCheck)"
    }

    $integrityCode = @'
import importlib.metadata as metadata
import pathlib
import re
import shutil
import sys

site_packages = pathlib.Path(sys.argv[1]).resolve()
scripts = pathlib.Path(sys.argv[2]).resolve()
projects = {}
problems = []
separator = ' | '
for distribution in metadata.distributions(path=[str(site_packages)]):
    name = distribution.metadata.get('Name')
    if not name:
        problems.append('distribution without Name metadata: ' + str(distribution.locate_file('')))
        continue
    normalized = re.sub(r'[-_.]+', '-', name).lower()
    projects.setdefault(normalized, []).append(str(distribution.locate_file('')))
for normalized, paths in sorted(projects.items()):
    if len(paths) != 1:
        problems.append(f'duplicate distribution {normalized}: {separator.join(paths)}')
if len(projects.get('defenseclaw', [])) != 1:
    problems.append('expected exactly one defenseclaw distribution')
for command in ('defenseclaw', 'skill-scanner', 'mcp-scanner'):
    resolved = shutil.which(command, path=str(scripts))
    if not resolved:
        problems.append(f'missing managed console entry point: {command}')
        continue
    resolved_path = pathlib.Path(resolved).resolve()
    try:
        resolved_path.relative_to(scripts)
    except ValueError:
        problems.append(f'console entry point escaped managed Scripts: {resolved_path}')
if problems:
    print('; '.join(problems), file=sys.stderr)
    raise SystemExit(1)
'@
    $sitePackages = Join-Path $Venv "Lib\site-packages"
    $scripts = Join-Path $Venv "Scripts"
    $integrityResult = Invoke-ManagedCommand -Executable $venvPython `
        -Arguments @("-I", "-c", $integrityCode, $sitePackages, $scripts)
    if ($integrityResult.ExitCode -ne 0) {
        $detail = ($integrityResult.Output | Select-Object -First 5) -join " | "
        throw "Managed distribution integrity validation failed: $detail"
    }

    $doctorResult = Invoke-ManagedCommand -Executable $cliExe -Arguments @("doctor", "--help")
    if ($doctorResult.ExitCode -ne 0) {
        $detail = ($doctorResult.Output | Select-Object -First 5) -join " | "
        throw "Managed doctor startup validation failed (exit $($doctorResult.ExitCode)): $detail"
    }
}

function Assert-ManagedDirectoryPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [string]$ExpectedPath,
        [Parameter(Mandatory = $true)]
        [string]$ManagedHome,
        [switch]$AllowMissing
    )

    $homeFull = [System.IO.Path]::GetFullPath($ManagedHome).TrimEnd('\')
    $pathFull = [System.IO.Path]::GetFullPath($Path).TrimEnd('\')
    $expectedFull = [System.IO.Path]::GetFullPath($ExpectedPath).TrimEnd('\')
    if (-not $pathFull.Equals($expectedFull, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing unverified managed directory path: $pathFull"
    }
    $parentFull = [System.IO.Path]::GetDirectoryName($pathFull).TrimEnd('\')
    if (-not $parentFull.Equals($homeFull, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Managed directory escaped its install root: $pathFull"
    }

    $homeItem = Get-Item -LiteralPath $homeFull -Force -ErrorAction Stop
    if (-not $homeItem.PSIsContainer -or ($homeItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
        throw "Managed install root must be a real directory, not a reparse point: $homeFull"
    }

    $entry = $null
    try {
        $entry = Get-Item -LiteralPath $pathFull -Force -ErrorAction Stop
    } catch [System.Management.Automation.ItemNotFoundException] {
        if (-not $AllowMissing) { throw }
    }
    if ($null -ne $entry) {
        if (-not $entry.PSIsContainer -or ($entry.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
            throw "Managed venv path must be a real directory, not a reparse point: $pathFull"
        }
    }
    return $pathFull
}

function Remove-ManagedDirectory {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [string]$ExpectedPath,
        [Parameter(Mandatory = $true)]
        [string]$ManagedHome
    )

    $safePath = Assert-ManagedDirectoryPath -Path $Path -ExpectedPath $ExpectedPath `
        -ManagedHome $ManagedHome -AllowMissing
    if (-not (Test-Path -LiteralPath $safePath)) { return }

    foreach ($item in @(Get-ChildItem -LiteralPath $safePath -Force -ErrorAction Stop)) {
        if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
            Remove-Item -LiteralPath $item.FullName -Force -ErrorAction Stop
        } elseif ($item.PSIsContainer) {
            Remove-ManagedDirectory -Path $item.FullName -ExpectedPath $item.FullName `
                -ManagedHome $safePath
        } else {
            Remove-Item -LiteralPath $item.FullName -Force -ErrorAction Stop
        }
    }
    Remove-Item -LiteralPath $safePath -Force -ErrorAction Stop
}

function Install-ManagedWheel {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetVenv,
        [Parameter(Mandatory = $true)]
        [string]$WheelPath
    )

    $venvExit = Invoke-Uv -Arguments @("venv", $TargetVenv, "--python", "3.12", "--quiet")
    if ($venvExit -ne 0) {
        $venvExit = Invoke-Uv -Arguments @("venv", $TargetVenv, "--python", "3.12", "--allow-existing", "--quiet") `
            -ShowFailureOutput
        if ($venvExit -ne 0) { throw "Failed to create Python virtual environment at $TargetVenv" }
    }

    $venvPython = Join-Path $TargetVenv "Scripts\python.exe"
    $pipExit = Invoke-Uv -Arguments @(
        "pip", "install", "--python", $venvPython, "--quiet",
        "--reinstall", "--no-cache", "--strict", $WheelPath
    ) -ShowFailureOutput
    if ($pipExit -ne 0) { throw "Failed to install CLI wheel into $TargetVenv" }
}

function Invoke-ManagedVenvRebuild {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Venv,
        [Parameter(Mandatory = $true)]
        [string]$WheelPath
    )

    $managedHome = [System.IO.Path]::GetDirectoryName([System.IO.Path]::GetFullPath($Venv))
    $expectedVenv = Join-Path $managedHome ".venv"
    $null = Assert-ManagedDirectoryPath -Path $Venv -ExpectedPath $expectedVenv `
        -ManagedHome $managedHome -AllowMissing

    $suffix = [guid]::NewGuid().ToString("N")
    $staging = Join-Path $managedHome ".venv.rebuild.$suffix"
    $backup = Join-Path $managedHome ".venv.backup.$suffix"
    $null = Assert-ManagedDirectoryPath -Path $staging -ExpectedPath $staging `
        -ManagedHome $managedHome -AllowMissing
    $null = Assert-ManagedDirectoryPath -Path $backup -ExpectedPath $backup `
        -ManagedHome $managedHome -AllowMissing

    $backupCreated = $false
    $newAtFinalPath = $false
    try {
        Install-ManagedWheel -TargetVenv $staging -WheelPath $WheelPath
        $null = Assert-ManagedDirectoryPath -Path $staging -ExpectedPath $staging `
            -ManagedHome $managedHome
        Test-ManagedEnvironment -Venv $staging

        if (Test-Path -LiteralPath $Venv) {
            Move-Item -LiteralPath $Venv -Destination $backup -ErrorAction Stop
            $backupCreated = $true
        }
        Move-Item -LiteralPath $staging -Destination $Venv -ErrorAction Stop
        $newAtFinalPath = $true
        $null = Assert-ManagedDirectoryPath -Path $Venv -ExpectedPath $expectedVenv `
            -ManagedHome $managedHome

        # Windows console launchers embed the interpreter path. Reinstall every
        # package after the rename so all entry points target the final venv.
        Install-ManagedWheel -TargetVenv $Venv -WheelPath $WheelPath
        Test-ManagedEnvironment -Venv $Venv
    } catch {
        $rebuildError = $_.Exception.Message
        $rollbackError = $null
        try {
            if ($newAtFinalPath -and (Test-Path -LiteralPath $Venv)) {
                Remove-ManagedDirectory -Path $Venv -ExpectedPath $expectedVenv -ManagedHome $managedHome
                $newAtFinalPath = $false
            }
            if ($backupCreated -and (Test-Path -LiteralPath $backup)) {
                Move-Item -LiteralPath $backup -Destination $Venv -ErrorAction Stop
                $backupCreated = $false
            }
        } catch {
            $rollbackError = $_.Exception.Message
        }

        if ($backupCreated) {
            throw "Managed venv rebuild failed: $rebuildError. Rollback failed: $rollbackError. " + `
                "Prior environment retained at '$backup'."
        }
        if ($rollbackError) {
            throw "Managed venv rebuild failed: $rebuildError. Rollback failed: $rollbackError"
        }
        throw "Managed venv rebuild failed; prior environment restored: $rebuildError"
    } finally {
        if (Test-Path -LiteralPath $staging) {
            try {
                Remove-ManagedDirectory -Path $staging -ExpectedPath $staging -ManagedHome $managedHome
            } catch {
                Write-Warn2 "Rebuild staging directory requires manual cleanup: $staging"
            }
        }
    }

    if ($backupCreated) {
        try {
            Remove-ManagedDirectory -Path $backup -ExpectedPath $backup -ManagedHome $managedHome
        } catch {
            throw "Managed venv rebuilt successfully, but backup cleanup failed. " + `
                "Recovery data remains at '$backup': $($_.Exception.Message)"
        }
    }
}

function Publish-CliLauncher {
    param(
        [Parameter(Mandatory = $true)]
        [string]$CliExe,
        [Parameter(Mandatory = $true)]
        [string]$InstallDir
    )

    if (-not (Test-Path -LiteralPath $CliExe -PathType Leaf)) {
        throw "Managed CLI executable not found: $CliExe"
    }

    $shim = Join-Path $InstallDir "defenseclaw.cmd"
    $shadow = Join-Path $InstallDir "defenseclaw.exe"
    $temporaryShim = Join-Path $InstallDir (".defenseclaw.cmd." + [guid]::NewGuid() + ".tmp")

    try {
        $contents = "@echo off`r`nsetlocal`r`nset `"PYTHONPATH=`"`r`nset `"PYTHONHOME=`"`r`n" + `
            "`"$CliExe`" %*`r`nset `"defenseclawExit=%errorlevel%`"`r`n" + `
            "endlocal & exit /b %defenseclawExit%`r`n"
        [System.IO.File]::WriteAllText($temporaryShim, $contents, [System.Text.Encoding]::ASCII)

        $shadowEntry = $null
        try {
            $shadowEntry = Get-Item -LiteralPath $shadow -Force -ErrorAction Stop
        } catch [System.Management.Automation.ItemNotFoundException] {
            # Idempotent: there is no same-directory .exe shadow to remove.
        }

        if ($null -ne $shadowEntry) {
            try {
                # Remove only this exact entry.  No recursion and no execution or
                # inspection of the untrusted executable is permitted here.
                Remove-Item -LiteralPath $shadow -Force -ErrorAction Stop
            } catch {
                throw "Cannot remove shadowing CLI launcher '$shadow': $($_.Exception.Message)"
            }
            try {
                $null = Get-Item -LiteralPath $shadow -Force -ErrorAction Stop
                throw "Cannot remove shadowing CLI launcher '$shadow': entry still exists"
            } catch [System.Management.Automation.ItemNotFoundException] {
                # The exact shadow entry is gone.
            }
        }

        Move-Item -LiteralPath $temporaryShim -Destination $shim -Force -ErrorAction Stop
        return $shim
    } finally {
        Remove-Item -LiteralPath $temporaryShim -Force -ErrorAction SilentlyContinue
    }
}

function Confirm-YesNo {
    param([string]$Prompt, [string]$Default = "y")
    if ($Yes) { return $true }
    $suffix = if ($Default -eq "y") { "[Y/n]" } else { "[y/N]" }
    $answer = Read-Host "  $Prompt $suffix"
    if ([string]::IsNullOrWhiteSpace($answer)) { $answer = $Default }
    return $answer -match '^[Yy]'
}

# ── Platform detection ────────────────────────────────────────────────────────

function Get-Arch {
    Write-Step "Detecting platform"
    # PROCESSOR_ARCHITEW6432 is set when a 32-bit process runs on 64-bit Windows;
    # prefer it so we never mistake WOW64 for a real 32-bit OS.
    $raw = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
    switch ($raw.ToUpper()) {
        "AMD64" { $arch = "amd64" }
        "ARM64" { Die "Windows ARM64 is not certified for this release; use certified Windows x64 (amd64)." }
        "X86"   { Die "32-bit Windows is not supported (need x64/amd64)." }
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
    $exitCode = Invoke-Uv -Arguments @("python", "install", "3.12") -ShowFailureOutput
    if ($exitCode -ne 0) { Die "Failed to install Python 3.12 via uv" }
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
            # Accept either the release-shaped zip or explicit raw binaries.
            $zip = Get-ChildItem -Path (Join-Path $Local "defenseclaw_*_windows_$Arch.zip") -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($zip) {
                Expand-Archive -Path $zip.FullName -DestinationPath $tmp -Force
            } else {
                $gatewayExe = Join-Path $Local "defenseclaw.exe"
                if (-not (Test-Path $gatewayExe)) {
                    $gatewayExe = Join-Path $Local "defenseclaw-gateway.exe"
                }
                $hookExe = Join-Path $Local "defenseclaw-hook.exe"
                if (-not (Test-Path $gatewayExe)) { Die "No windows zip or gateway executable found in $Local" }
                if (-not (Test-Path $hookExe)) { Die "defenseclaw-hook.exe missing from $Local" }
                Copy-Item $gatewayExe (Join-Path $tmp "defenseclaw.exe") -Force
                Copy-Item $hookExe (Join-Path $tmp "defenseclaw-hook.exe") -Force
            }
        } else {
            $zipName = "defenseclaw_${script:ReleaseVersion}_windows_${Arch}.zip"
            $zipPath = Join-Path $tmp $zipName
            $resolved = Get-Artifact -Name $zipName -Dest $zipPath
            Test-Checksum -File $zipPath -FileName $resolved
            Expand-Archive -Path $zipPath -DestinationPath $tmp -Force
        }
        $binary = Join-Path $tmp "defenseclaw.exe"
        $hookBinary = Join-Path $tmp "defenseclaw-hook.exe"
        if (-not (Test-Path $binary)) { Die "defenseclaw.exe missing from archive" }
        if (-not (Test-Path $hookBinary)) { Die "defenseclaw-hook.exe missing from archive" }
        Copy-Item $binary (Join-Path $InstallDir "defenseclaw-gateway.exe") -Force
        Copy-Item $hookBinary (Join-Path $InstallDir "defenseclaw-hook.exe") -Force
    } finally {
        Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
    }
    Write-Ok "Gateway installed -> $InstallDir\defenseclaw-gateway.exe"
    Write-Ok "No-console hook launcher installed -> $InstallDir\defenseclaw-hook.exe"
}

# ── Install: Python CLI (from wheel) ──────────────────────────────────────────

function Install-Cli {
    param(
        [string]$WheelPath = "",
        [switch]$DeferLauncher
    )
    Write-Step "Installing DefenseClaw CLI"
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("dc-cli-" + [guid]::NewGuid())
    New-Item -ItemType Directory -Force -Path $tmp | Out-Null
    $installError = $null
    $shim = $null
    try {
        $selectedWheel = $WheelPath
        if ($selectedWheel) {
            $selectedWheel = [System.IO.Path]::GetFullPath($selectedWheel)
        } elseif ($Local) {
            $whl = Get-ChildItem -Path (Join-Path $Local "defenseclaw-*.whl") -ErrorAction SilentlyContinue | Select-Object -First 1
            if (-not $whl) { Die "No wheel found in $Local" }
            $selectedWheel = $whl.FullName
        } else {
            $whlName = "defenseclaw-${script:ReleaseVersion}-py3-none-any.whl"
            $selectedWheel = Join-Path $tmp $whlName
            $resolved = Get-Artifact -Name $whlName -Dest $selectedWheel
            Test-Checksum -File $selectedWheel -FileName $resolved
        }

        Write-Info "Reconciling managed Python environment..."
        $reconcileError = $null
        try {
            Install-ManagedWheel -TargetVenv $Venv -WheelPath $selectedWheel
            Test-ManagedEnvironment -Venv $Venv
        } catch {
            $reconcileError = $_.Exception.Message
        }
        if ($reconcileError) {
            Write-Warn2 "Managed environment reconciliation failed: $reconcileError"
            Write-Info "Rebuilding managed Python environment safely..."
            Invoke-ManagedVenvRebuild -Venv $Venv -WheelPath $selectedWheel
        }

        if (-not $DeferLauncher) {
            $cliExe = Join-Path $Venv "Scripts\defenseclaw.exe"
            # PowerShell resolves .EXE before .CMD. Publish the managed-venv shim
            # only after removing the exact same-directory stale launcher.
            $shim = Publish-CliLauncher -CliExe $cliExe -InstallDir $InstallDir
        }
    } catch {
        $installError = $_.Exception.Message
    } finally {
        Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
    }
    if ($installError) { Die $installError }
    if (-not $DeferLauncher) { Write-Ok "CLI installed -> $shim" }
}

function Test-StagedReleaseFile {
    param([string]$Path, [string]$Label)
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (-not $item.PSIsContainer -and
        -not ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
        return
    }
    throw "$Label must be a regular non-reparse file: $Path"
}

function Stage-ReleaseArtifacts {
    param([string]$Arch)

    $stageRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("dc-release-" + [guid]::NewGuid())
    New-Item -ItemType Directory -Path $stageRoot -ErrorAction Stop | Out-Null
    try {
        $gateway = Join-Path $stageRoot "defenseclaw-gateway.exe"
        $hook = Join-Path $stageRoot "defenseclaw-hook.exe"
        if ($Local) {
            $zip = Get-ChildItem -Path (Join-Path $Local "defenseclaw_*_windows_$Arch.zip") `
                -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($zip) {
                $archiveDir = Join-Path $stageRoot "archive"
                Expand-Archive -LiteralPath $zip.FullName -DestinationPath $archiveDir
                Copy-Item -LiteralPath (Join-Path $archiveDir "defenseclaw.exe") `
                    -Destination $gateway -ErrorAction Stop
                Copy-Item -LiteralPath (Join-Path $archiveDir "defenseclaw-hook.exe") `
                    -Destination $hook -ErrorAction Stop
            } else {
                $sourceGateway = Join-Path $Local "defenseclaw.exe"
                if (-not (Test-Path -LiteralPath $sourceGateway)) {
                    $sourceGateway = Join-Path $Local "defenseclaw-gateway.exe"
                }
                Copy-Item -LiteralPath $sourceGateway -Destination $gateway -ErrorAction Stop
                Copy-Item -LiteralPath (Join-Path $Local "defenseclaw-hook.exe") `
                    -Destination $hook -ErrorAction Stop
            }
            $wheel = Get-ChildItem -Path (Join-Path $Local "defenseclaw-*.whl") `
                -ErrorAction SilentlyContinue | Select-Object -First 1
            if (-not $wheel) { throw "No wheel found in $Local" }
            $wheelPath = Join-Path $stageRoot $wheel.Name
            Copy-Item -LiteralPath $wheel.FullName -Destination $wheelPath -ErrorAction Stop
        } else {
            $zipName = "defenseclaw_${script:ReleaseVersion}_windows_${Arch}.zip"
            $zipPath = Join-Path $stageRoot $zipName
            $resolvedZip = Get-Artifact -Name $zipName -Dest $zipPath
            Test-Checksum -File $zipPath -FileName $resolvedZip
            $archiveDir = Join-Path $stageRoot "archive"
            Expand-Archive -LiteralPath $zipPath -DestinationPath $archiveDir
            Copy-Item -LiteralPath (Join-Path $archiveDir "defenseclaw.exe") `
                -Destination $gateway -ErrorAction Stop
            Copy-Item -LiteralPath (Join-Path $archiveDir "defenseclaw-hook.exe") `
                -Destination $hook -ErrorAction Stop

            $wheelName = "defenseclaw-${script:ReleaseVersion}-py3-none-any.whl"
            $wheelPath = Join-Path $stageRoot $wheelName
            $resolvedWheel = Get-Artifact -Name $wheelName -Dest $wheelPath
            Test-Checksum -File $wheelPath -FileName $resolvedWheel
        }

        Test-StagedReleaseFile -Path $gateway -Label "Gateway artifact"
        Test-StagedReleaseFile -Path $hook -Label "Hook artifact"
        Test-StagedReleaseFile -Path $wheelPath -Label "CLI wheel"
        $gatewayVersion = Invoke-ManagedCommand -Executable $gateway -Arguments @("--version")
        if ($gatewayVersion.ExitCode -ne 0) {
            throw "Staged gateway failed --version validation"
        }

        $validationVenv = Join-Path $stageRoot "validation-venv"
        Install-ManagedWheel -TargetVenv $validationVenv -WheelPath $wheelPath
        Test-ManagedEnvironment -Venv $validationVenv
        Remove-Item -LiteralPath $validationVenv -Recurse -Force -ErrorAction Stop

        return [pscustomobject]@{
            Root = $stageRoot
            Gateway = $gateway
            Hook = $hook
            Wheel = $wheelPath
            GatewayVersion = ($gatewayVersion.Output -join " ").Trim()
        }
    } catch {
        Remove-Item -LiteralPath $stageRoot -Recurse -Force -ErrorAction SilentlyContinue
        throw
    }
}

function Assert-ManagedInstallFile {
    param([string]$Path, [string]$ExpectedPath, [string]$InstallRoot, [switch]$AllowMissing)
    $rootFull = [System.IO.Path]::GetFullPath($InstallRoot).TrimEnd('\')
    $pathFull = [System.IO.Path]::GetFullPath($Path)
    $expectedFull = [System.IO.Path]::GetFullPath($ExpectedPath)
    if (-not $pathFull.Equals($expectedFull, [System.StringComparison]::OrdinalIgnoreCase) -or
        -not [System.IO.Path]::GetDirectoryName($pathFull).Equals(
            $rootFull, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing unverified managed install path: $pathFull"
    }
    $rootItem = Get-Item -LiteralPath $rootFull -Force -ErrorAction Stop
    if (-not $rootItem.PSIsContainer -or
        ($rootItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
        throw "Managed install root must be a real directory: $rootFull"
    }
    try {
        $item = Get-Item -LiteralPath $pathFull -Force -ErrorAction Stop
        if ($item.PSIsContainer -or
            ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
            throw "Managed install artifact must be a regular file: $pathFull"
        }
    } catch [System.Management.Automation.ItemNotFoundException] {
        if (-not $AllowMissing) { throw }
    }
    return $pathFull
}

function Copy-VerifiedDirectory {
    param([string]$Source, [string]$Destination)
    $sourceItem = Get-Item -LiteralPath $Source -Force -ErrorAction Stop
    if (-not $sourceItem.PSIsContainer -or
        ($sourceItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
        throw "Refusing to copy non-directory or reparse source: $Source"
    }
    if (Test-Path -LiteralPath $Destination) {
        throw "Refusing to overwrite backup directory: $Destination"
    }
    New-Item -ItemType Directory -Path $Destination -ErrorAction Stop | Out-Null
    foreach ($item in @(Get-ChildItem -LiteralPath $Source -Force -ErrorAction Stop)) {
        if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
            throw "Refusing to copy reparse entry from managed venv: $($item.FullName)"
        }
        $target = Join-Path $Destination $item.Name
        if ($item.PSIsContainer) {
            Copy-VerifiedDirectory -Source $item.FullName -Destination $target
        } else {
            [System.IO.File]::Copy($item.FullName, $target, $false)
        }
    }
}

function Get-ManagedGatewayProcess {
    param([string]$GatewayPath, [string]$DataDir)
    $pidFile = Join-Path $DataDir "gateway.pid"
    if (-not (Test-Path -LiteralPath $pidFile)) { return $null }
    $pidItem = Get-Item -LiteralPath $pidFile -Force -ErrorAction Stop
    if ($pidItem.PSIsContainer -or
        ($pidItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
        return $null
    }
    try {
        $state = Get-Content -LiteralPath $pidFile -Raw -ErrorAction Stop | ConvertFrom-Json
    } catch {
        throw "Invalid managed gateway PID file '$pidFile': $($_.Exception.Message)"
    }
    $managedPid = 0
    if (-not [int]::TryParse([string]$state.pid, [ref]$managedPid) -or $managedPid -le 0) {
        throw "Invalid managed gateway PID in '$pidFile'"
    }
    if ([string]::IsNullOrWhiteSpace([string]$state.executable)) {
        throw "Managed gateway PID file is missing executable identity: $pidFile"
    }
    $expected = [System.IO.Path]::GetFullPath($GatewayPath)
    $recorded = [System.IO.Path]::GetFullPath([string]$state.executable)
    if (-not $recorded.Equals($expected, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $null
    }
    $process = Get-CimInstance Win32_Process -Filter "ProcessId = $managedPid" -ErrorAction Stop
    if ($null -eq $process -or -not $process.ExecutablePath) { return $null }
    $live = [System.IO.Path]::GetFullPath([string]$process.ExecutablePath)
    if (-not $live.Equals($expected, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $null
    }
    if (-not [string]::IsNullOrWhiteSpace([string]$state.start_identity)) {
        $liveProcess = Get-Process -Id $managedPid -ErrorAction Stop
        $epoch = [datetime]::SpecifyKind([datetime]'1970-01-01', 'Utc')
        $liveIdentity = (($liveProcess.StartTime.ToUniversalTime().Ticks - $epoch.Ticks) * 100).ToString()
        if ($liveIdentity -ne [string]$state.start_identity) { return $null }
    }
    return [pscustomobject]@{ PID = $managedPid; Path = $expected; PIDFile = $pidFile }
}

function Get-ManagedWatchdogProcess {
    param([string]$GatewayPath, [string]$DataDir)
    $pidFile = Join-Path $DataDir "watchdog.pid"
    if (-not (Test-Path -LiteralPath $pidFile)) { return $null }
    $pidItem = Get-Item -LiteralPath $pidFile -Force -ErrorAction Stop
    if ($pidItem.PSIsContainer -or
        ($pidItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
        throw "Managed watchdog PID path must be a regular file: $pidFile"
    }
    try {
        $state = Get-Content -LiteralPath $pidFile -Raw -ErrorAction Stop | ConvertFrom-Json
    } catch {
        throw "Invalid managed watchdog PID file '$pidFile': $($_.Exception.Message)"
    }
    $watchdogPid = 0
    if (-not [int]::TryParse([string]$state.pid, [ref]$watchdogPid) -or $watchdogPid -le 0 -or
        [string]::IsNullOrWhiteSpace([string]$state.executable) -or
        [string]::IsNullOrWhiteSpace([string]$state.start_time)) {
        throw "Managed watchdog PID file lacks a complete process identity: $pidFile"
    }
    $expected = [System.IO.Path]::GetFullPath($GatewayPath)
    $recorded = [System.IO.Path]::GetFullPath([string]$state.executable)
    if (-not $recorded.Equals($expected, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Managed watchdog PID file names an untrusted executable: $recorded"
    }
    $process = Get-CimInstance Win32_Process -Filter "ProcessId = $watchdogPid" -ErrorAction Stop
    if ($null -eq $process -or -not $process.ExecutablePath) { return $null }
    $live = [System.IO.Path]::GetFullPath([string]$process.ExecutablePath)
    if (-not $live.Equals($expected, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Managed watchdog PID belongs to a different executable: $live"
    }
    $liveProcess = Get-Process -Id $watchdogPid -ErrorAction Stop
    $epoch = [datetime]::SpecifyKind([datetime]'1970-01-01', 'Utc')
    $liveStartSeconds = [int64][math]::Floor(
        ($liveProcess.StartTime.ToUniversalTime() - $epoch).TotalSeconds
    )
    $recordedStartSeconds = 0L
    if (-not [int64]::TryParse([string]$state.start_time, [ref]$recordedStartSeconds) -or
        [math]::Abs($liveStartSeconds - $recordedStartSeconds) -gt 2) {
        throw "Managed watchdog PID start identity does not match the live process"
    }
    return [pscustomobject]@{ PID = $watchdogPid; Path = $expected; PIDFile = $pidFile }
}

function Test-ManagedFileRenameRoundTrip {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $true }
    $probe = Join-Path ([System.IO.Path]::GetDirectoryName($Path)) (
        "." + [System.IO.Path]::GetFileName($Path) + "." +
        [guid]::NewGuid().ToString("N") + ".release-probe"
    )
    try {
        [System.IO.File]::Move($Path, $probe)
    } catch [System.IO.IOException] {
        return $false
    } catch [System.UnauthorizedAccessException] {
        return $false
    }
    try {
        [System.IO.File]::Move($probe, $Path)
    } catch {
        throw "Gateway replaceability probe could not restore '$Path'; recovery file: $probe"
    }
    return $true
}

function Wait-GatewayFileRelease {
    param(
        [string]$GatewayPath,
        [int]$ProcessId = 0,
        [int]$Attempts = 40,
        [int]$DelayMilliseconds = 250
    )
    for ($attempt = 1; $attempt -le $Attempts; $attempt++) {
        $processExited = $true
        if ($ProcessId -gt 0) {
            $processExited = $null -eq (Get-Process -Id $ProcessId -ErrorAction SilentlyContinue)
        }
        $fileReleased = $processExited -and (Test-ManagedFileRenameRoundTrip -Path $GatewayPath)
        if ($processExited -and $fileReleased) { return }
        if ($attempt -lt $Attempts -and $DelayMilliseconds -gt 0) {
            Start-Sleep -Milliseconds $DelayMilliseconds
        }
    }
    throw "Managed gateway did not exit and release '$GatewayPath' within the grace period"
}

function Stop-ManagedGateway {
    param([string]$GatewayPath, [string]$DataDir)
    $managedProcess = Get-ManagedGatewayProcess -GatewayPath $GatewayPath -DataDir $DataDir
    if ($null -eq $managedProcess) { return $false }
    $watchdogProcess = Get-ManagedWatchdogProcess -GatewayPath $GatewayPath -DataDir $DataDir
    $stopResult = Invoke-ManagedCommand -Executable $GatewayPath -Arguments @("stop")
    if ($stopResult.ExitCode -ne 0) {
        throw "Managed gateway stop failed (exit $($stopResult.ExitCode))"
    }
    Wait-GatewayFileRelease -GatewayPath $GatewayPath -ProcessId $managedProcess.PID
    if ($null -ne $watchdogProcess -and
        $null -ne (Get-Process -Id $watchdogProcess.PID -ErrorAction SilentlyContinue)) {
        throw "Managed watchdog did not exit during gateway stop (PID $($watchdogProcess.PID))"
    }
    return $true
}

function Get-ManagedGatewayEndpoint {
    param([string]$Venv, [string]$ExpectedDataDir)
    $python = Join-Path $Venv "Scripts\python.exe"
    $code = @'
import json
from defenseclaw.config import load
cfg = load()
print(json.dumps({'host': cfg.gateway.api_bind or '127.0.0.1', 'port': cfg.gateway.api_port, 'data_dir': cfg.data_dir, 'token': cfg.gateway.resolved_token()}))
'@
    $result = Invoke-ManagedCommand -Executable $python -Arguments @("-I", "-c", $code)
    if ($result.ExitCode -ne 0) { throw "Could not load managed gateway endpoint" }
    $endpoint = ($result.Output | Select-Object -Last 1).ToString() | ConvertFrom-Json
    $actualDataDir = [System.IO.Path]::GetFullPath([string]$endpoint.data_dir).TrimEnd('\')
    $expected = [System.IO.Path]::GetFullPath($ExpectedDataDir).TrimEnd('\')
    if (-not $actualDataDir.Equals($expected, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Gateway configuration serves a different DEFENSECLAW_HOME: $actualDataDir"
    }
    $hostName = [string]$endpoint.host
    if ($hostName -eq "0.0.0.0" -or $hostName -eq "::") { $hostName = "127.0.0.1" }
    $address = $null
    if ($hostName -ne "localhost" -and
        (-not [System.Net.IPAddress]::TryParse($hostName, [ref]$address) -or
         -not [System.Net.IPAddress]::IsLoopback($address))) {
        throw "Refusing non-loopback gateway health target: $hostName"
    }
    return [pscustomobject]@{ Host = $hostName; Port = [int]$endpoint.port; Token = [string]$endpoint.token }
}

function Start-ManagedGateway {
    param([string]$GatewayPath, [string]$DataDir, [string]$Venv)
    $startResult = Invoke-ManagedCommand -Executable $GatewayPath -Arguments @("start")
    if ($startResult.ExitCode -ne 0) {
        throw "Managed gateway start failed (exit $($startResult.ExitCode))"
    }
    $endpoint = Get-ManagedGatewayEndpoint -Venv $Venv -ExpectedDataDir $DataDir
    $uri = "http://$($endpoint.Host):$($endpoint.Port)/health"
    $headers = @{}
    if (-not [string]::IsNullOrWhiteSpace($endpoint.Token)) {
        $headers["Authorization"] = "Bearer $($endpoint.Token)"
        $headers["X-DefenseClaw-Token"] = $endpoint.Token
    }
    for ($attempt = 1; $attempt -le 40; $attempt++) {
        $managedProcess = Get-ManagedGatewayProcess -GatewayPath $GatewayPath -DataDir $DataDir
        if ($null -ne $managedProcess) {
            try {
                $health = Invoke-RestMethod -Uri $uri -Method Get -Headers $headers -TimeoutSec 1
                if ($health.api.state -eq "running") { return }
            } catch {
                # Continue the bounded readiness wait.
            }
        }
        if ($attempt -lt 40) { Start-Sleep -Milliseconds 250 }
    }
    throw "Managed gateway did not become healthy at $uri"
}

function New-PairedInstallBackup {
    param([string]$ManagedHome, [string]$InstallRoot, [string]$Venv)
    $suffix = [guid]::NewGuid().ToString("N")
    $backupRoot = Join-Path $ManagedHome ".install-backup.$suffix"
    $null = Assert-ManagedDirectoryPath -Path $backupRoot -ExpectedPath $backupRoot `
        -ManagedHome $ManagedHome -AllowMissing
    New-Item -ItemType Directory -Path $backupRoot -ErrorAction Stop | Out-Null
    $filesRoot = Join-Path $backupRoot "files"
    New-Item -ItemType Directory -Path $filesRoot -ErrorAction Stop | Out-Null
    $names = @(
        "defenseclaw-gateway.exe",
        "defenseclaw-hook.exe",
        "defenseclaw.cmd",
        "defenseclaw.exe"
    )
    $present = @{}
    try {
        foreach ($name in $names) {
            $source = Join-Path $InstallRoot $name
            $null = Assert-ManagedInstallFile -Path $source -ExpectedPath $source `
                -InstallRoot $InstallRoot -AllowMissing
            $present[$name] = Test-Path -LiteralPath $source
            if ($present[$name]) {
                [System.IO.File]::Copy($source, (Join-Path $filesRoot $name), $false)
            }
        }
        $venvBackup = Join-Path $backupRoot "venv"
        $null = Assert-ManagedDirectoryPath -Path $Venv -ExpectedPath $Venv `
            -ManagedHome $ManagedHome -AllowMissing
        $hasVenv = Test-Path -LiteralPath $Venv
        if ($hasVenv) {
            Copy-VerifiedDirectory -Source $Venv -Destination $venvBackup
        }
        return [pscustomobject]@{
            Root = $backupRoot
            Files = $filesRoot
            Present = $present
            Venv = $venvBackup
            HasVenv = $hasVenv
        }
    } catch {
        if (Test-Path -LiteralPath $backupRoot) {
            Remove-ManagedDirectory -Path $backupRoot -ExpectedPath $backupRoot `
                -ManagedHome $ManagedHome
        }
        throw
    }
}

function Restore-PairedInstallBackup {
    param(
        [object]$Backup,
        [string]$ManagedHome,
        [string]$InstallRoot,
        [string]$Venv,
        [switch]$RestoreGateway,
        [switch]$RestoreHook,
        [switch]$RestoreCli,
        [switch]$RestoreLauncher
    )
    $names = @()
    if ($RestoreGateway) { $names += "defenseclaw-gateway.exe" }
    if ($RestoreHook) { $names += "defenseclaw-hook.exe" }
    if ($RestoreLauncher) { $names += @("defenseclaw.cmd", "defenseclaw.exe") }
    foreach ($name in $names) {
        $target = Join-Path $InstallRoot $name
        $null = Assert-ManagedInstallFile -Path $target -ExpectedPath $target `
            -InstallRoot $InstallRoot -AllowMissing
        if ($Backup.Present[$name]) {
            Replace-ManagedInstallFile -Source (Join-Path $Backup.Files $name) `
                -Target $target -InstallRoot $InstallRoot
        } elseif (Test-Path -LiteralPath $target) {
            Remove-Item -LiteralPath $target -Force -ErrorAction Stop
        }
    }

    if ($RestoreCli) {
        if (Test-Path -LiteralPath $Venv) {
            Remove-ManagedDirectory -Path $Venv -ExpectedPath $Venv -ManagedHome $ManagedHome
        }
        if ($Backup.HasVenv) {
            Move-Item -LiteralPath $Backup.Venv -Destination $Venv -ErrorAction Stop
        }
    }
}

function Replace-ManagedInstallFile {
    param([string]$Source, [string]$Target, [string]$InstallRoot)
    Test-StagedReleaseFile -Path $Source -Label "Staged release artifact"
    $null = Assert-ManagedInstallFile -Path $Target -ExpectedPath $Target `
        -InstallRoot $InstallRoot -AllowMissing
    $temporary = Join-Path $InstallRoot ("." + [System.IO.Path]::GetFileName($Target) + "." + `
        [guid]::NewGuid().ToString("N") + ".tmp")
    try {
        [System.IO.File]::Copy($Source, $temporary, $false)
        if (Test-Path -LiteralPath $Target) {
            if ($null -eq ("DefenseClawWindowsFile" -as [type])) {
                Add-Type -TypeDefinition @'
using System.Runtime.InteropServices;
public static class DefenseClawWindowsFile {
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool MoveFileEx(
        string existingFile, string replacementFile, int flags);
}
'@
            }
            # MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH. Unlike
            # Move-Item -Force, this has an explicit Windows overwrite contract.
            if (-not [DefenseClawWindowsFile]::MoveFileEx($temporary, $Target, 9)) {
                $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                throw [System.ComponentModel.Win32Exception]::new(
                    $errorCode, "Could not atomically replace '$Target'"
                )
            }
        } else {
            [System.IO.File]::Move($temporary, $Target)
        }
    } finally {
        Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
    }
}

function Test-PairedInstalledState {
    param([object]$Artifacts, [string]$GatewayPath, [string]$HookPath, [string]$Venv, [string]$InstallRoot)
    if ((Get-FileHash -LiteralPath $GatewayPath -Algorithm SHA256).Hash -ne
        (Get-FileHash -LiteralPath $Artifacts.Gateway -Algorithm SHA256).Hash) {
        throw "Installed gateway does not match the staged artifact"
    }
    if ((Get-FileHash -LiteralPath $HookPath -Algorithm SHA256).Hash -ne
        (Get-FileHash -LiteralPath $Artifacts.Hook -Algorithm SHA256).Hash) {
        throw "Installed hook does not match the staged artifact"
    }
    $version = Invoke-ManagedCommand -Executable $GatewayPath -Arguments @("--version")
    if ($version.ExitCode -ne 0 -or ($version.Output -join " ").Trim() -ne $Artifacts.GatewayVersion) {
        throw "Installed gateway version identity does not match the staged artifact"
    }
    Test-ManagedEnvironment -Venv $Venv

    $shim = Join-Path $InstallRoot "defenseclaw.cmd"
    $shadow = Join-Path $InstallRoot "defenseclaw.exe"
    if (-not (Test-Path -LiteralPath $shim -PathType Leaf) -or
        (Test-Path -LiteralPath $shadow)) {
        throw "Public Windows CLI launcher state is invalid"
    }
    $savedPath = $env:PATH
    $savedPathExt = $env:PATHEXT
    try {
        $env:PATH = "$InstallRoot;$savedPath"
        $env:PATHEXT = ".EXE;.CMD"
        $resolved = @(Get-Command defenseclaw -CommandType Application -ErrorAction Stop)[0]
        if (-not [System.IO.Path]::GetFullPath($resolved.Source).Equals(
            [System.IO.Path]::GetFullPath($shim),
            [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Unqualified defenseclaw did not resolve to the managed .cmd launcher"
        }
    } finally {
        $env:PATH = $savedPath
        $env:PATHEXT = $savedPathExt
    }
}

function Invoke-PairedInstallTransaction {
    param([object]$Artifacts)
    $gatewayPath = Join-Path $InstallDir "defenseclaw-gateway.exe"
    $hookPath = Join-Path $InstallDir "defenseclaw-hook.exe"
    $null = Assert-ManagedDirectoryPath -Path $Venv -ExpectedPath $Venv `
        -ManagedHome $DefenseClawHome -AllowMissing
    $null = Assert-ManagedInstallFile -Path $gatewayPath -ExpectedPath $gatewayPath `
        -InstallRoot $InstallDir -AllowMissing
    $null = Assert-ManagedInstallFile -Path $hookPath -ExpectedPath $hookPath `
        -InstallRoot $InstallDir -AllowMissing
    $managedProcess = Get-ManagedGatewayProcess -GatewayPath $gatewayPath `
        -DataDir $DefenseClawHome
    $wasRunning = $null -ne $managedProcess
    $phase = "preflight"
    $backup = $null
    $oldStopped = $false
    $gatewayReplaced = $false
    $hookReplaced = $false
    $cliMutationStarted = $false
    $launcherMutationStarted = $false
    $newGatewayStartAttempted = $false

    try {
        if ($wasRunning) {
            $phase = "stop-old-gateway"
            $null = Stop-ManagedGateway -GatewayPath $gatewayPath -DataDir $DefenseClawHome
            $oldStopped = $true
        } else {
            # A planted/unrelated PID is never stopped. The file must still be
            # unlocked before any mutation can begin.
            Wait-GatewayFileRelease -GatewayPath $gatewayPath
        }
    } catch {
        $stopError = $_.Exception.Message
        if ($wasRunning -and $null -eq (Get-ManagedGatewayProcess `
            -GatewayPath $gatewayPath -DataDir $DefenseClawHome)) {
            try {
                Start-ManagedGateway -GatewayPath $gatewayPath -DataDir $DefenseClawHome -Venv $Venv
            } catch {
                throw "Preflight stop failed: $stopError. Prior gateway restart also failed: " + `
                    $_.Exception.Message
            }
        }
        throw "Preflight stop failed before artifact mutation: $stopError"
    }

    try {
        $phase = "backup"
        $backup = New-PairedInstallBackup -ManagedHome $DefenseClawHome `
            -InstallRoot $InstallDir -Venv $Venv

        $phase = "replace-gateway"
        Replace-ManagedInstallFile -Source $Artifacts.Gateway -Target $gatewayPath `
            -InstallRoot $InstallDir
        $gatewayReplaced = $true
        $phase = "replace-hook"
        Replace-ManagedInstallFile -Source $Artifacts.Hook -Target $hookPath `
            -InstallRoot $InstallDir
        $hookReplaced = $true

        $phase = "repair-cli"
        $cliMutationStarted = $true
        Install-Cli -WheelPath $Artifacts.Wheel -DeferLauncher
        $phase = "publish-launcher"
        $launcherMutationStarted = $true
        $cliExe = Join-Path $Venv "Scripts\defenseclaw.exe"
        $null = Publish-CliLauncher -CliExe $cliExe -InstallDir $InstallDir

        $phase = "validate-installed-state"
        Test-PairedInstalledState -Artifacts $Artifacts -GatewayPath $gatewayPath `
            -HookPath $hookPath -Venv $Venv -InstallRoot $InstallDir

        if ($wasRunning) {
            $phase = "restart-new-gateway"
            $newGatewayStartAttempted = $true
            Start-ManagedGateway -GatewayPath $gatewayPath -DataDir $DefenseClawHome -Venv $Venv
        }

        $phase = "cleanup-backup"
        try {
            Remove-ManagedDirectory -Path $backup.Root -ExpectedPath $backup.Root `
                -ManagedHome $DefenseClawHome
            $backup = $null
        } catch {
            Write-Warn2 "Install succeeded; recovery backup cleanup failed: $($backup.Root)"
        }
    } catch {
        $transactionError = $_.Exception.Message
        $rollbackOutcomes = @()
        try {
            if ($newGatewayStartAttempted) {
                $newProcess = Get-ManagedGatewayProcess -GatewayPath $gatewayPath `
                    -DataDir $DefenseClawHome
                if ($null -ne $newProcess) {
                    $null = Stop-ManagedGateway -GatewayPath $gatewayPath -DataDir $DefenseClawHome
                    $rollbackOutcomes += "stopped partial gateway"
                } else {
                    Wait-GatewayFileRelease -GatewayPath $gatewayPath
                }
            }
            $artifactMutationOccurred = $gatewayReplaced -or $hookReplaced -or
                $cliMutationStarted -or $launcherMutationStarted
            if ($null -ne $backup -and $artifactMutationOccurred) {
                Restore-PairedInstallBackup -Backup $backup -ManagedHome $DefenseClawHome `
                    -InstallRoot $InstallDir -Venv $Venv `
                    -RestoreGateway:$gatewayReplaced -RestoreHook:$hookReplaced `
                    -RestoreCli:$cliMutationStarted -RestoreLauncher:$launcherMutationStarted
                $rollbackOutcomes += "restored paired artifacts"
            }
            if ($wasRunning -and ($oldStopped -or $gatewayReplaced)) {
                Start-ManagedGateway -GatewayPath $gatewayPath -DataDir $DefenseClawHome -Venv $Venv
                $rollbackOutcomes += "restarted prior gateway"
            }
            if ($null -ne $backup -and (Test-Path -LiteralPath $backup.Root)) {
                Remove-ManagedDirectory -Path $backup.Root -ExpectedPath $backup.Root `
                    -ManagedHome $DefenseClawHome
                $backup = $null
                $rollbackOutcomes += "cleaned recovery backup"
            }
        } catch {
            $recoveryPath = if ($null -ne $backup) { $backup.Root } else { "none" }
            throw "Install failed during $phase`: $transactionError. Rollback failed: " + `
                "$($_.Exception.Message). Recovery path: $recoveryPath"
        }
        throw "Install failed during $phase`: $transactionError. Rollback: " + `
            ($rollbackOutcomes -join "; ")
    }

    Write-Ok "Paired gateway, hook, and CLI installation validated"
}

# ── Connector selection ───────────────────────────────────────────────────────

function Select-Connector {
    if ($script:PickedConnector) { return }
    if ($Yes) { $script:PickedConnector = "none"; return }

    Write-Step "Pick agent connector"
    Write-Info "DefenseClaw certifies two connectors on native Windows x64. Pick one to integrate now;"
    Write-Info "you can switch later with 'defenseclaw init --connector <name>'."
    Write-Host ""
    $i = 1
    foreach ($v in $ConnectorChoices) {
        switch ($v) {
            "codex"       { Write-Host "    $i) codex       - Codex CLI native hooks" }
            "claudecode"  { Write-Host "    $i) claudecode  - Claude Code native hooks" }
            "none"        { Write-Host "    $i) none        - install gateway/CLI only; pick later" }
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
    if ($script:PickedConnector -and $script:PickedConnector -ne "none") {
        Write-Host "  Get started ($script:PickedConnector):`n`n    defenseclaw init --connector $script:PickedConnector`n" -ForegroundColor Cyan
    } else {
        Write-Host "  Get started (pick a connector later):`n`n    defenseclaw init`n" -ForegroundColor Cyan
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

    # Validate against the native-Windows connector surface. -NoOpenclaw is
    # retained only as a backwards-compatible alias for selecting none.
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
    Write-Step "Staging and validating release artifacts"
    $artifacts = Stage-ReleaseArtifacts -Arch $arch
    try {
        New-Item -ItemType Directory -Force -Path $DefenseClawHome | Out-Null
        New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
        Invoke-PairedInstallTransaction -Artifacts $artifacts
    } finally {
        if ($null -ne $artifacts -and (Test-Path -LiteralPath $artifacts.Root)) {
            Remove-Item -LiteralPath $artifacts.Root -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    if ($script:PickedConnector -and $script:PickedConnector -ne "none") {
        Write-Info "Connector '$script:PickedConnector' wires up through the native Windows CLI."
    } else {
        Write-Info "Skipping connector setup - run 'defenseclaw init' when ready"
    }

    Save-PickedConnector
    Add-ToPath
    Invoke-Quickstart
    Write-Success
}

try {
    Main
} catch {
    Write-Err2 $_.Exception.Message
    throw
}
