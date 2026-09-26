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
    End-to-end install/upgrade/rollback test for scripts/install.ps1.

.DESCRIPTION
      powershell -File scripts\test-install-lifecycle.ps1 -Assets DIR [-PreviousAssets DIR]
          [-Lanes "fresh setup-import files-in-use failure-drill policy upgrade-previous shim"] [-Root DIR] [-Keep]

    upgrade-previous and shim need -PreviousAssets (an older 1.x release); the
    other lanes start from it when it is given, else from -Assets. The policy
    lane sets the HKLM DisableSelfUpdate policy for its duration, so it needs
    an elevated shell.

    Every lane runs with its own USERPROFILE, LOCALAPPDATA, APPDATA and TEMP,
    -NoPersistPath, and the gateway on a free port, so it never touches the
    real install. DIR holds release-shaped assets (scripts/build-release-assets.sh
    or a downloaded release). The setup-import lane also writes the registry
    values of a synthetic DefenseClaw Setup install (HKCU Run, Uninstall and
    Path) and puts the originals back afterwards.
#>

param(
    [Parameter(Mandatory = $true)][string]$Assets,
    [string]$PreviousAssets = "",
    [string]$Lanes = "fresh",
    [string]$Root = "",
    [switch]$Keep
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$Assets = (Resolve-Path -LiteralPath $Assets).ProviderPath
if ($PreviousAssets) { $PreviousAssets = (Resolve-Path -LiteralPath $PreviousAssets).ProviderPath }
if (-not $Root) { $Root = Join-Path ([IO.Path]::GetTempPath()) ("dc-lifecycle-" + [guid]::NewGuid().ToString("N").Substring(0, 8)) }
New-Item -ItemType Directory -Path $Root -Force | Out-Null
# Real path: DefenseClaw refuses a data dir reached through a junction.
$Root = (Get-Item -LiteralPath $Root).FullName
# Windows PowerShell 5.1 runs the installer, as for users and `defenseclaw
# upgrade`, even when this test runs in PowerShell 7.
$PowerShell = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
$Tools = Join-Path $Root "tools"
New-Item -ItemType Directory -Path $Tools -Force | Out-Null
$uv = Get-Command uv.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $uv) { throw "uv must be on PATH (the lanes share its cache)" }
Copy-Item -LiteralPath $uv.Source -Destination $Tools -Force
$UvCache = if ($env:UV_CACHE_DIR) { $env:UV_CACHE_DIR } else { Join-Path $Root "uv-cache" }
$UvPython = if ($env:UV_PYTHON_INSTALL_DIR) { $env:UV_PYTHON_INSTALL_DIR } else { Join-Path $Root "uv-python" }
$MachinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
$script:Failures = 0
$script:LaneHomes = @()
$script:Held = @()

function Get-VersionOf([string]$Text) { if ($Text -match '\d+\.\d+\.\d+') { return $Matches[0] } return "" }
function Get-AssetVersion([string]$Dir) {
    return Get-VersionOf (Get-ChildItem -LiteralPath $Dir -Filter "defenseclaw-*-py3-none-any.whl" | Select-Object -First 1).Name
}
$Target = Get-AssetVersion $Assets
# What the files-in-use and setup-import lanes install first.
$Seed = if ($PreviousAssets) { $PreviousAssets } else { $Assets }

# Native programs may write to stderr, which "Stop" would turn into an exception.
function Invoke-Exe([string]$File, [string[]]$Arguments = @(), [switch]$Quiet) {
    $ErrorActionPreference = "Continue"
    if ($Quiet) { & $File @Arguments *> $null } else { & $File @Arguments 2>&1 | ForEach-Object { Write-Host "$_" } }
    return $LASTEXITCODE
}
function Get-ExeOutput([string]$File, [string[]]$Arguments = @()) {
    $ErrorActionPreference = "Continue"
    return ((& $File @Arguments 2>&1) | ForEach-Object { "$_" }) -join "`n"
}

function Write-Log([string]$Message) { Write-Host ""; Write-Host "[lifecycle] $Message" -ForegroundColor White }
function Fail([string]$Message) { Write-Host "[lifecycle] FAIL: $Message" -ForegroundColor Red; $script:Failures++ }
function Check([bool]$Condition, [string]$Message) { if (-not $Condition) { Fail $Message } }

# Enter-Lane NAME: fresh profile directories and environment for one lane.
function Enter-Lane([string]$Name) {
    $script:Lane = Join-Path $Root $Name
    $script:LaneHome = Join-Path $Lane "home"
    if (Test-Path -LiteralPath $Lane) {
        # Left by an earlier -Keep run.
        $env:USERPROFILE = $LaneHome
        $gateway = Join-Path $LaneHome ".local\bin\defenseclaw-gateway.exe"
        if (Test-Path -LiteralPath $gateway) { [void](Invoke-Exe $gateway @("stop") -Quiet) }
        Remove-Item -LiteralPath $Lane -Recurse -Force
    }
    # Laid out like a real profile: .NET resolves the known folders from
    # USERPROFILE and answers "" when they are missing, which sends caches
    # (PowerShell's module analysis cache) to the working directory.
    foreach ($dir in "AppData\Local", "AppData\Roaming", "AppData\Local\Temp") {
        New-Item -ItemType Directory -Path (Join-Path $LaneHome $dir) -Force | Out-Null
    }
    $script:LaneHomes += $LaneHome
    $env:USERPROFILE = $LaneHome
    $env:HOME = $LaneHome
    $env:LOCALAPPDATA = Join-Path $LaneHome "AppData\Local"
    $env:APPDATA = Join-Path $LaneHome "AppData\Roaming"
    $env:TEMP = Join-Path $LaneHome "AppData\Local\Temp"
    $env:TMP = $env:TEMP
    $env:Path = "$LaneHome\.local\bin;$Tools;$MachinePath"
    $env:DEFENSECLAW_NO_UPDATE_CHECK = "1"
    $env:UV_CACHE_DIR = $UvCache
    $env:UV_PYTHON_INSTALL_DIR = $UvPython
    foreach ($name in "DEFENSECLAW_HOME", "DEFENSECLAW_CONFIG", "DEFENSECLAW_UPGRADE_FRESH_PROCESS", "DEFENSECLAW_UPGRADE_LOCAL_DIR") {
        Remove-Item "Env:$name" -ErrorAction SilentlyContinue
    }
    $script:Bin = Join-Path $LaneHome ".local\bin"
    $script:DcHome = Join-Path $LaneHome ".defenseclaw"
}

# Invoke-Installer SCRIPT ARGS...: run an installer as `defenseclaw upgrade` would; returns its exit code.
function Invoke-Installer([string]$Script, [string[]]$Arguments) {
    $started = Get-Date
    $code = Invoke-Exe $PowerShell (@("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $Script) + $Arguments)
    Write-Host ("[lifecycle] {0} {1} -> exit {2} in {3:n0}s" -f (Split-Path -Leaf $Script), ($Arguments -join " "), $code, ((Get-Date) - $started).TotalSeconds)
    return $code
}

function Install-Candidate([string]$Dir, [string[]]$Extra = @()) {
    return Invoke-Installer (Join-Path $Dir "install.ps1") (@("-Local", $Dir, "-Yes", "-NoPersistPath") + $Extra)
}

function Get-FreePort {
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    $listener.Start()
    $port = $listener.LocalEndpoint.Port
    $listener.Stop()
    return $port
}

# Windows PowerShell 5.1 drops double quotes inside native arguments: $Code
# must use single quotes only.
function Invoke-Python([string]$Code, [string[]]$Arguments = @()) {
    $output = Get-ExeOutput (Join-Path $DcHome ".venv\Scripts\python.exe") (@("-I", "-c", $Code) + $Arguments)
    if ($LASTEXITCODE -ne 0) { throw "python failed: $output" }
    return $output
}

# Initialize-Gateway: create a config, move the gateway to a free port, start it.
function Initialize-Gateway {
    $code = Invoke-Exe (Join-Path $Bin "defenseclaw.cmd") @("init", "--non-interactive", "--connector", "none",
        "--no-start-gateway", "--no-verify", "--skip-install") -Quiet
    if ($code -ne 0) { Fail "defenseclaw init failed ($code)"; return $false }
    $port = Get-FreePort
    Invoke-Python @'
import sys, yaml
path, port = sys.argv[1], int(sys.argv[2])
with open(path, encoding='utf-8') as stream:
    config = yaml.safe_load(stream)
config.setdefault('gateway', {})['api_port'] = port
with open(path, 'w', encoding='utf-8') as stream:
    yaml.safe_dump(config, stream, sort_keys=False)
'@ @((Join-Path $DcHome "config.yaml"), [string]$port) | Out-Null
    Set-Content -LiteralPath (Join-Path $DcHome "lifecycle-marker.txt") -Value "lifecycle-marker" -Encoding Ascii
    $code = Invoke-Exe (Join-Path $Bin "defenseclaw-gateway.exe") @("start")
    if ($code -ne 0) { Fail "gateway start failed ($code)"; return $false }
    return $true
}

function Assert-Versions([string]$Want) {
    $cli = Get-VersionOf (Get-ExeOutput (Join-Path $Bin "defenseclaw.cmd") @("--version"))
    $gateway = Get-VersionOf (Get-ExeOutput (Join-Path $Bin "defenseclaw-gateway.exe") @("--version"))
    Check ($cli -eq $Want -and $gateway -eq $Want) "expected $Want, got cli=$cli gateway=$gateway"
}

function Get-GatewayPort {
    return [int](Invoke-Python "import sys, yaml; print(yaml.safe_load(open(sys.argv[1], encoding='utf-8'))['gateway']['api_port'])" @((Join-Path $DcHome "config.yaml")))
}

function Assert-Healthy {
    $port = Get-GatewayPort
    try { $status = (Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:$port/health" -TimeoutSec 10).StatusCode } catch { $status = 0 }
    Check ($status -eq 200) "gateway on port $port is not healthy"
}

# The gateway that gateway.pid names, running from this lane's .local\bin.
function Get-GatewayImage {
    try {
        $record = Get-Content -Raw -LiteralPath (Join-Path $DcHome "gateway.pid") | ConvertFrom-Json
        return (Get-Process -Id $record.pid -ErrorAction Stop).Path
    } catch { return "" }
}

function Assert-DataKept {
    $marker = Get-Content -LiteralPath (Join-Path $DcHome "lifecycle-marker.txt") -ErrorAction SilentlyContinue
    Check ($marker -eq "lifecycle-marker") "data dir lost the marker file"
    Check (Test-Path -LiteralPath (Join-Path $DcHome "config.yaml")) "config.yaml is missing"
}

function Get-Sha256([string]$Path) { return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash }

function Stop-Lane {
    if (Test-Path -LiteralPath (Join-Path $Bin "defenseclaw-gateway.exe")) {
        [void](Invoke-Exe (Join-Path $Bin "defenseclaw-gateway.exe") @("stop") -Quiet)
    }
}

# Wait-Detached: wait for the installer `defenseclaw upgrade`/`rollback` started in
# its own console, then return the text of the newest install log.
function Wait-Detached([int]$TimeoutSeconds = 900) {
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        Start-Sleep -Seconds 2
        $running = @(Get-CimInstance Win32_Process -Filter "Name = 'powershell.exe'" |
            Where-Object { $_.CommandLine -and $_.CommandLine.Contains($Lane) -and $_.CommandLine.Contains("install.ps1") })
    } while ($running.Count -and (Get-Date) -lt $deadline)
    if ($running.Count) { Fail "the detached installer did not finish in $TimeoutSeconds s"; return "" }
    $log = Get-ChildItem -LiteralPath (Join-Path $DcHome "logs") -Filter "install-*.log" | Sort-Object LastWriteTime | Select-Object -Last 1
    $text = if ($log) { Get-Content -Raw -LiteralPath $log.FullName } else { "" }
    Write-Host "[lifecycle] detached installer log $($log.Name):"
    ($text -split "`r?`n") | Where-Object { $_ -match '^\s+[>+!x] |^--- |is installed|Now running' } | ForEach-Object { Write-Host "    | $_" }
    return $text
}

# The temporary directories `defenseclaw upgrade`/`rollback` run the installer from.
function Get-LaunchDirCount {
    return @(Get-ChildItem -LiteralPath $env:TEMP -Directory -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^defenseclaw-(upgrade|rollback)-' }).Count
}

# Start-Held FILE ARGS...: a process that keeps running (stdin open) until Stop-Held.
# New-DrillAssets NAME EDIT: a copy of -Assets whose Windows zip EDIT changed
# (EDIT gets the expanded zip directory), with checksums.txt rewritten.
function New-DrillAssets([string]$Name, [scriptblock]$Edit) {
    $drill = Join-Path $Lane $Name
    $zip = Join-Path $Lane "$Name-zip"
    New-Item -ItemType Directory -Path $drill, $zip -Force | Out-Null
    Copy-Item -Path (Join-Path $Assets "*") -Destination $drill
    $archive = "defenseclaw-$Target-windows-amd64.zip"
    Expand-Archive -LiteralPath (Join-Path $Assets $archive) -DestinationPath $zip
    & $Edit $zip
    Remove-Item -LiteralPath (Join-Path $drill $archive)
    Compress-Archive -Path (Join-Path $zip "*") -DestinationPath (Join-Path $drill $archive)
    # The release signature no longer matches the rewritten checksums.txt.
    Remove-Item -Path (Join-Path $drill "checksums.txt.*") -Force -ErrorAction SilentlyContinue
    $sums = foreach ($file in Get-ChildItem -LiteralPath $drill -File | Where-Object { $_.Name -notlike "checksums.txt*" } | Sort-Object Name) {
        "$((Get-Sha256 $file.FullName).ToLowerInvariant())  $($file.Name)"
    }
    [IO.File]::WriteAllText((Join-Path $drill "checksums.txt"), (($sums -join "`n") + "`n"))
    return $drill
}

function Start-Held([string]$File, [string[]]$Arguments = @()) {
    $info = New-Object Diagnostics.ProcessStartInfo $File
    $info.Arguments = ($Arguments | ForEach-Object { '"' + $_ + '"' }) -join " "
    $info.UseShellExecute = $false
    $info.RedirectStandardInput = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $process = [Diagnostics.Process]::Start($info)
    $script:Held += $process
    return $process
}

function Stop-Held {
    foreach ($process in $script:Held) { if (-not $process.HasExited) { $process.Kill(); [void]$process.WaitForExit(10000) } }
    $script:Held = @()
}

function Invoke-Lane([string]$Name, [scriptblock]$Body) {
    $before = $script:Failures
    $started = Get-Date
    try { & $Body } catch {
        Fail "lane $Name stopped: $($_.Exception.Message) at $($_.InvocationInfo.PositionMessage)"
    } finally {
        Stop-Held
        Stop-Lane
    }
    $result = if ($script:Failures -eq $before) { "passed" } else { "FAILED" }
    Write-Log ("lane {0} {1} in {2:n0}s" -f $Name, $result, ((Get-Date) - $started).TotalSeconds)
}

# -- Lanes ---------------------------------------------------------------------

function Test-Fresh {
    Enter-Lane fresh
    $pathBefore = Get-UserPathRaw
    Write-Log "fresh install of $Target"
    Check ((Install-Candidate $Assets) -eq 0) "fresh install failed"
    Assert-Versions $Target
    Check (-not (Test-Path -LiteralPath (Join-Path $DcHome "previous"))) "a fresh install must not leave a rollback slot"
    Check (Test-Path -LiteralPath (Join-Path $DcHome "installer\install.ps1")) "installer copy was not saved"
    $shim = [IO.File]::ReadAllText((Join-Path $Bin "defenseclaw.cmd"))
    Check ($shim -ceq "@echo off`r`n`"$DcHome\.venv\Scripts\defenseclaw.exe`" %*`r`n") "unexpected defenseclaw.cmd: $shim"
    foreach ($name in "defenseclaw-gateway.exe", "defenseclaw-hook.exe", "defenseclaw-acp.exe", "skill-scanner.cmd", "mcp-scanner.cmd") {
        Check (Test-Path -LiteralPath (Join-Path $Bin $name)) "$name is missing"
    }
    $scanner = (Get-Command skill-scanner -ErrorAction SilentlyContinue | Select-Object -First 1).Source
    Check ($scanner -eq (Join-Path $Bin "skill-scanner.cmd")) "skill-scanner resolves to '$scanner'"
    Check ((Get-UserPathRaw) -ceq $pathBefore) "-NoPersistPath still changed the user PATH"
    if (-not (Initialize-Gateway)) { return }
    Assert-Healthy
    Check ((Get-GatewayImage) -eq (Join-Path $Bin "defenseclaw-gateway.exe")) "the gateway does not run from $Bin"
    # The gateway runs skill-scanner by bare name through PATH.
    $skill = Join-Path $Lane "skill"
    New-Item -ItemType Directory -Path $skill -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $skill "SKILL.md") -Encoding Ascii -Value "---`nname: lifecycle`ndescription: A test skill.`n---`nSay hello."
    $scan = Invoke-Python @'
import json, sys
from defenseclaw.config import load
from defenseclaw.gateway import OrchestratorClient
cfg = load()
client = OrchestratorClient(port=cfg.gateway.api_port, token=cfg.gateway.resolved_token())
print(json.dumps(client.scan_skill(target=sys.argv[1], name='lifecycle')))
'@ @($skill)
    Write-Host "[lifecycle] gateway skill scan: $($scan.Substring(0, [Math]::Min(300, $scan.Length)))"
    Check ($scan -match '"scanner":\s*"skill-scanner"') "the gateway could not run skill-scanner: $scan"

    # The source copy is not stamped: with -Local it installs the version of the wheel there.
    $unstamped = Join-Path $PSScriptRoot "install.ps1"
    Write-Log "re-run the same version (repair) as & ([scriptblock]::Create(...)) of the source copy"
    $before = Get-Sha256 (Join-Path $DcHome "config.yaml")
    $command = "& ([scriptblock]::Create([IO.File]::ReadAllText('$unstamped'))) -Local '$Assets' -Yes -NoPersistPath; 'session-alive'"
    $output = Get-ExeOutput $PowerShell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", $command)
    Write-Host $output
    Check ($LASTEXITCODE -eq 0 -and $output.Contains("session-alive")) "the script-block re-run failed"
    Assert-Versions $Target
    Assert-Healthy
    Assert-DataKept
    Check ((Get-Sha256 (Join-Path $DcHome "config.yaml")) -eq $before) "re-run changed config.yaml"
    Check (-not (Test-Path -LiteralPath (Join-Path $DcHome "previous"))) "a same-version re-run must not create a rollback slot"
    Check (-not (Test-Path -LiteralPath (Join-Path $DcHome ".repair"))) "the repair slot was left behind"

    Write-Log "irm | iex of an unpublished release throws instead of closing the session"
    $unpublished = Join-Path $Lane "install-9.9.9.ps1"
    [IO.File]::WriteAllText($unpublished, [IO.File]::ReadAllText($unstamped).Replace("__DEFENSECLAW_" + "VERSION__", "9.9.9"))
    $command = "try { [IO.File]::ReadAllText('$unpublished') | Invoke-Expression } catch { 'threw: ' + `$_.Exception.Message }; 'session-alive'"
    $output = Get-ExeOutput $PowerShell @("-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", $command)
    Check ($output.Contains("threw: ") -and $output.Contains("session-alive")) "irm | iex did not fail by throwing: $output"
    Check ((Invoke-Installer $unstamped @("-Version", "0.8.10", "-Yes")) -eq 1) "-Version 0.8.10 must be refused"
    Assert-Versions $Target
    Assert-Healthy
}

# Upgrade from the previous 1.x release, `defenseclaw rollback`, then roll forward.
function Test-UpgradePrevious {
    Enter-Lane upgrade-previous
    $from = Get-AssetVersion $PreviousAssets
    Write-Log "install $from"
    Check ((Install-Candidate $PreviousAssets) -eq 0) "install of $from failed"
    if (-not (Initialize-Gateway)) { return }
    Assert-Versions $from
    Write-Log "upgrade $from -> $Target"
    Check ((Install-Candidate $Assets) -eq 0) "upgrade failed"
    Assert-Versions $Target
    Assert-Healthy
    Assert-DataKept
    Check ((Get-Content -LiteralPath (Join-Path $DcHome "previous\VERSION") -ErrorAction SilentlyContinue) -eq $from) "previous\VERSION is not $from"

    Write-Log "defenseclaw rollback --yes (detached installer)"
    $launchDirs = Get-LaunchDirCount
    $code = Invoke-Exe (Join-Path $Bin "defenseclaw.cmd") @("rollback", "--yes")
    Check ($code -eq 0) "defenseclaw rollback exited $code"
    $log = Wait-Detached
    Check ($log.Contains("Now running DefenseClaw $from")) "the rollback log does not report success"
    Check ((Get-LaunchDirCount) -eq $launchDirs) "the installer left its temporary directory in $env:TEMP"
    Assert-Versions $from
    Assert-Healthy
    Assert-DataKept

    Write-Log "roll forward with install.ps1 -Rollback"
    Check ((Invoke-Installer (Join-Path $DcHome "installer\install.ps1") @("-Rollback", "-Yes")) -eq 0) "roll forward failed"
    Assert-Versions $Target
    Assert-Healthy
    Assert-DataKept
}

# `defenseclaw upgrade --yes` starts the installer in a new console and exits.
function Test-Shim {
    Enter-Lane shim
    $from = Get-AssetVersion $PreviousAssets
    Check ((Install-Candidate $PreviousAssets) -eq 0) "install of $from failed"
    if (-not (Initialize-Gateway)) { return }
    Write-Log "defenseclaw upgrade --yes ($from -> $Target, detached installer)"
    # The shim cannot pass -NoPersistPath: the installer adds this lane's bin
    # dir to the real user PATH, which is checked and put back.
    $pathRaw = Get-UserPathRaw
    $pathKind = Get-UserPathKind
    try {
        $launchDirs = Get-LaunchDirCount
        $env:DEFENSECLAW_UPGRADE_LOCAL_DIR = $Assets
        $output = Get-ExeOutput (Join-Path $Bin "defenseclaw.cmd") @("upgrade", "--yes")
        $code = $LASTEXITCODE
        Remove-Item Env:DEFENSECLAW_UPGRADE_LOCAL_DIR
        Write-Host $output
        Check ($code -eq 0) "defenseclaw upgrade exited $code"
        $log = Wait-Detached
        Check ($log.Contains("DefenseClaw $Target is installed.")) "the upgrade log does not report success"
        Check ((Get-LaunchDirCount) -eq $launchDirs) "the installer left its temporary directory in $env:TEMP"
        Check ((Get-UserPathRaw) -ceq "$Bin;$pathRaw" -and (Get-UserPathKind) -eq $pathKind) "unexpected user PATH '$(Get-UserPathRaw)'"
    } finally {
        Set-UserPath $pathRaw $pathKind
    }
    Assert-Versions $Target
    Assert-Healthy
    Assert-DataKept
    Check ((Get-Content -LiteralPath (Join-Path $DcHome "previous\VERSION") -ErrorAction SilentlyContinue) -eq $from) "previous\VERSION is not $from"
}

# Upgrade while DefenseClaw programs hold files: running .exe files are renamed
# aside, and a program running from the venv stops the install before any change.
function Test-FilesInUse {
    Enter-Lane files-in-use
    Check ((Install-Candidate $Seed) -eq 0) "install of $(Get-AssetVersion $Seed) failed"
    if (-not (Initialize-Gateway)) { return }
    $next = $Assets
    if ($Seed -eq $Assets) {
        # Without an older release, a release with a different hook build makes
        # the re-run replace the running one.
        $next = New-DrillAssets "hook-assets" {
            param([string]$Zip)
            [IO.File]::AppendAllText((Join-Path $Zip "defenseclaw-hook.exe"), "rebuilt")
        }
    }
    # A hook waiting for its payload, as an agent runs it.
    $hook = Start-Held (Join-Path $Bin "defenseclaw-hook.exe") @("hook", "--connector", "codex")
    Start-Sleep -Seconds 2
    Check (-not $hook.HasExited) "defenseclaw-hook.exe did not stay running"
    Write-Log "install $Target while defenseclaw-hook.exe runs"
    Check ((Install-Candidate $next) -eq 0) "an install with a running hook failed"
    Assert-Versions $Target
    Assert-Healthy
    Check (-not $hook.HasExited) "the running hook was stopped"
    Check (@(Get-ChildItem -LiteralPath $Bin -Filter "defenseclaw-hook.exe.old-*").Count -eq 1) "the running defenseclaw-hook.exe was not renamed aside"
    Stop-Held

    Write-Log "re-run while the CLI runs from the venv (must stop, nothing changed)"
    $holder = Start-Held (Join-Path $DcHome ".venv\Scripts\python.exe") @("-c", "import time; time.sleep(900)")
    $gatewayBefore = Get-GatewayImage
    $pidBefore = (Get-Content -Raw -LiteralPath (Join-Path $DcHome "gateway.pid") | ConvertFrom-Json).pid
    Check ((Install-Candidate $Assets) -eq 1) "an install with the venv in use must fail with exit 1"
    $log = Get-ChildItem -LiteralPath (Join-Path $DcHome "logs") -Filter "install-*.log" | Sort-Object LastWriteTime | Select-Object -Last 1
    Check ((Get-Content -Raw -LiteralPath $log.FullName).Contains("pid $($holder.Id)")) "the failure does not name the program using the venv"
    Check ((Get-Content -Raw -LiteralPath (Join-Path $DcHome "gateway.pid") | ConvertFrom-Json).pid -eq $pidBefore) "the gateway was restarted"
    Check ((Get-GatewayImage) -eq $gatewayBefore) "the gateway changed"
    Assert-Versions $Target
    Assert-Healthy
    Stop-Held

    Write-Log "re-run while a CLI that exits after 15 s holds the venv (must wait, then succeed)"
    [void](Start-Held (Join-Path $DcHome ".venv\Scripts\python.exe") @("-c", "import time; time.sleep(15)"))
    Check ((Install-Candidate $Assets) -eq 0) "an install must wait for an exiting CLI"
    Assert-Versions $Target
    Assert-Healthy
    Assert-DataKept
    Check (-not @(Get-ChildItem -LiteralPath $Bin -Filter "*.old-*").Count) "stale .old-* files were not removed"
}

# A release whose gateway reports its version but does not start: the
# install is undone. A start that exits 3 (a connector needs attention)
# keeps the new version and exits 3.
function Test-FailureDrill {
    Enter-Lane failure-drill
    Check ((Install-Candidate $Assets) -eq 0) "install of $Target failed"
    if (-not (Initialize-Gateway)) { return }
    $gateway = Join-Path $Bin "defenseclaw-gateway.exe"
    $goodGateway = Get-Sha256 $gateway
    $config = Get-Sha256 (Join-Path $DcHome "config.yaml")
    $source = Join-Path $Lane "DrillGateway.cs"
    [IO.File]::WriteAllText($source, @"
public static class DrillGateway {
    public static int Main(string[] args) {
        if (args.Length > 0 && args[0] == "--version") { System.Console.WriteLine("defenseclaw-gateway version $Target"); return 0; }
        if (args.Length > 0 && args[0] == "start") { return int.Parse(System.Environment.GetEnvironmentVariable("DC_DRILL_START_EXIT") ?? "1"); }
        return 0;
    }
}
"@)
    $drill = New-DrillAssets "drill-assets" {
        param([string]$Zip)
        Remove-Item -LiteralPath (Join-Path $Zip "defenseclaw-gateway.exe")
        # Only Windows PowerShell's Add-Type builds a standalone .exe.
        $built = Invoke-Exe $PowerShell @("-NoProfile", "-Command",
            "Add-Type -Path '$source' -OutputAssembly '$(Join-Path $Zip "defenseclaw-gateway.exe")' -OutputType ConsoleApplication")
        Check ($built -eq 0) "could not build the drill gateway"
    }

    Write-Log "an install whose gateway does not start is undone"
    Check ((Install-Candidate $drill) -eq 1) "an install whose gateway does not start must exit 1"
    Check ((Get-Sha256 $gateway) -eq $goodGateway) "the working gateway was not put back"
    Assert-Versions $Target
    Assert-Healthy
    Assert-DataKept
    Check ((Get-Sha256 (Join-Path $DcHome "config.yaml")) -eq $config) "the failed install changed config.yaml"
    Check (@(Get-ChildItem -LiteralPath $DcHome -Directory -Force -Filter ".failed-*").Count -eq 1) "the failed install was not kept in .failed-*"
    Check (-not (Test-Path -LiteralPath (Join-Path $DcHome ".repair"))) "the repair slot was left behind"

    Write-Log "a gateway start that exits 3 keeps the new version and exits 3"
    $env:DC_DRILL_START_EXIT = "3"
    try { Check ((Install-Candidate $drill) -eq 3) "an install whose gateway start exits 3 must exit 3" } finally { Remove-Item Env:DC_DRILL_START_EXIT }
    Check ((Get-Sha256 $gateway) -ne $goodGateway) "exit 3 must keep the new version"
    Assert-DataKept
}

# HKLM\SOFTWARE\Policies\Cisco\DefenseClaw\DisableSelfUpdate stops install,
# upgrade and rollback alike, before anything changes. Needs elevation.
function Test-Policy {
    Enter-Lane policy
    $cisco = "HKLM:\SOFTWARE\Policies\Cisco"
    $key = "$cisco\DefenseClaw"
    if (Test-Path -LiteralPath $key) { Fail "an enterprise policy for DefenseClaw is set on this machine; not touching it"; return }
    $ciscoExisted = Test-Path -LiteralPath $cisco
    try {
        New-Item -Path $key -Force | Out-Null
        New-ItemProperty -Path $key -Name "DisableSelfUpdate" -PropertyType DWord -Value 1 | Out-Null
        foreach ($arguments in @(@("-Local", $Assets, "-Yes", "-NoPersistPath"), @("-Rollback", "-Yes"))) {
            Check ((Invoke-Installer (Join-Path $Assets "install.ps1") $arguments) -eq 1) "install.ps1 $($arguments -join ' ') must refuse under the policy"
        }
        Check (-not (Test-Path -LiteralPath $DcHome) -and -not (Test-Path -LiteralPath $Bin)) "a refused install changed $LaneHome"
    } finally {
        Remove-Item -LiteralPath $key -Recurse -Force -ErrorAction SilentlyContinue
        if (-not $ciscoExisted) { Remove-Item -LiteralPath $cisco -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

function Get-UserPathRaw {
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey("Environment")
    try { return [string]$key.GetValue("Path", "", [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) } finally { $key.Close() }
}

function Get-UserPathKind {
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey("Environment")
    try { return $key.GetValueKind("Path") } finally { $key.Close() }
}

function Set-UserPath([string]$Value, $Kind) {
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey("Environment", $true)
    try { $key.SetValue("Path", $Value, $Kind) } finally { $key.Close() }
}

# A synthetic 0.8.x DefenseClaw Setup install (the layout of
# cmd/defenseclaw-setup at 0.8.10) with a running gateway; the upgrade must
# remove it and run the gateway from .local\bin.
function Test-SetupImport {
    Enter-Lane setup-import
    $runKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    $uninstallKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\DefenseClaw"
    if (Test-Path -LiteralPath $uninstallKey) { Fail "a real DefenseClaw Setup install is registered; not touching it"; return }
    $pathRaw = Get-UserPathRaw
    $pathKind = Get-UserPathKind
    try {
        # Data written by an earlier DefenseClaw, and a gateway, as Setup left them.
        Check ((Install-Candidate $Seed) -eq 0) "seeding the data dir failed"
        if (-not (Initialize-Gateway)) { return }
        Stop-Lane
        $setupRoot = Join-Path $env:LOCALAPPDATA "Programs\DefenseClaw"
        $cache = Join-Path $env:LOCALAPPDATA "DefenseClaw\InstallerCache"
        $hookRuntime = Join-Path $env:LOCALAPPDATA "DefenseClaw\HookRuntime"
        foreach ($dir in "bin", "installer", "runtime\python") { New-Item -ItemType Directory -Path (Join-Path $setupRoot $dir) -Force | Out-Null }
        New-Item -ItemType Directory -Path $cache, $hookRuntime -Force | Out-Null
        foreach ($name in "defenseclaw-gateway.exe", "defenseclaw-hook.exe") { Move-Item -LiteralPath (Join-Path $Bin $name) -Destination (Join-Path $setupRoot "bin") }
        Copy-Item -LiteralPath (Join-Path $setupRoot "bin\defenseclaw-gateway.exe") -Destination (Join-Path $setupRoot "bin\defenseclaw-startup.exe")
        Copy-Item -LiteralPath (Join-Path $setupRoot "bin\defenseclaw-hook.exe") -Destination (Join-Path $hookRuntime "defenseclaw-hook.exe")
        Get-ChildItem -LiteralPath $Bin -Force | Remove-Item -Force
        Remove-Item -LiteralPath (Join-Path $DcHome ".venv"), (Join-Path $DcHome "installer") -Recurse -Force
        Set-Content -LiteralPath (Join-Path $cache "DefenseClawSetup-x64.exe") -Value "setup" -Encoding Ascii
        Set-Content -LiteralPath (Join-Path $hookRuntime "hook-runtime-state.json") -Value '{"schema_version":2,"status":"active"}' -Encoding Ascii
        [ordered]@{
            schema_version = 1; version = "0.8.10"; distribution_flavor = "oss"; install_kind = "native-windows-exe"
            install_scope = "user"; install_root = $setupRoot; command_dir = (Join-Path $setupRoot "bin"); data_root = $DcHome
            runtime = (Join-Path $setupRoot "runtime\python"); maintenance_path = (Join-Path $cache "DefenseClawSetup-x64.exe")
            path_entry_owned = $true; connector = "none"; mode = "observe"
        } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $setupRoot "installer\install-state.json") -Encoding Ascii
        New-Item -Path $uninstallKey -Force | Out-Null
        foreach ($value in @(@("DisplayName", "DefenseClaw"), @("DisplayVersion", "0.8.10"), @("InstallLocation", $setupRoot),
                @("Publisher", "Cisco Systems, Inc."), @("UninstallString", "`"$cache\DefenseClawSetup-x64.exe`" /uninstall"))) {
            New-ItemProperty -Path $uninstallKey -Name $value[0] -Value $value[1] -PropertyType String -Force | Out-Null
        }
        New-ItemProperty -Path $runKey -Name "DefenseClawGateway" -PropertyType ExpandString -Force `
            -Value "`"$setupRoot\bin\defenseclaw-startup.exe`"".Replace($env:LOCALAPPDATA, "%LOCALAPPDATA%") | Out-Null
        New-ItemProperty -Path $runKey -Name "DefenseClawDeferredUninstallCleanup" -PropertyType String -Force `
            -Value "`"$cache\DefenseClawSetup-x64.exe`" /cleanup /quiet CLEANUPTRANSACTION=0123456789abcdef0123456789abcdef" | Out-Null
        New-ItemProperty -Path $runKey -Name "DefenseClawLifecycleUnrelated" -PropertyType String -Force -Value "`"$env:SystemRoot\notepad.exe`"" | Out-Null
        Set-UserPath "$setupRoot\bin;$pathRaw" $pathKind
        # Setup's gateway runs from its own tree, and so does another of its programs.
        [void](Invoke-Exe (Join-Path $setupRoot "bin\defenseclaw-gateway.exe") @("start"))
        $other = Start-Held (Join-Path $setupRoot "bin\defenseclaw-startup.exe") @("hook", "--connector", "codex")
        Check ((Get-GatewayImage) -eq (Join-Path $setupRoot "bin\defenseclaw-gateway.exe")) "the Setup gateway is not running"

        Write-Log "upgrade DefenseClaw Setup 0.8.10 -> $Target (persisting PATH)"
        Check ((Invoke-Installer (Join-Path $Assets "install.ps1") @("-Local", $Assets, "-Yes")) -eq 0) "the Setup import failed"
        Assert-Versions $Target
        Assert-Healthy
        Assert-DataKept
        Check ((Get-GatewayImage) -eq (Join-Path $Bin "defenseclaw-gateway.exe")) "the gateway does not run from $Bin"
        Check $other.HasExited "a program running from the Setup tree was not stopped"
        Check (-not (Test-Path -LiteralPath $setupRoot)) "the Setup tree was not removed"
        Check (Test-Path -LiteralPath (Join-Path $DcHome "previous\legacy-setup\DefenseClaw\installer\install-state.json")) "the Setup tree was not kept in previous\legacy-setup"
        Check (Test-Path -LiteralPath (Join-Path $DcHome "previous\legacy-setup\hook-runtime-state.json")) "the Setup hook runtime was not disabled"
        Check ((Get-Content -LiteralPath (Join-Path $DcHome "previous\VERSION")) -eq "0.8.10") "previous\VERSION is not 0.8.10"
        Check (Test-Path -LiteralPath (Join-Path $hookRuntime "defenseclaw-hook.exe")) "HookRuntime must be left in place"
        Check (-not (Test-Path -LiteralPath $cache)) "InstallerCache was not removed"
        Check (-not (Test-Path -LiteralPath $uninstallKey)) "the Uninstall key was not removed"
        $run = Get-ItemProperty -LiteralPath $runKey
        Check (-not $run.PSObject.Properties["DefenseClawGateway"]) "the Setup autostart Run value was not removed"
        Check (-not $run.PSObject.Properties["DefenseClawDeferredUninstallCleanup"]) "the Setup cleanup Run value was not removed"
        Check ([bool]$run.PSObject.Properties["DefenseClawLifecycleUnrelated"]) "an unrelated Run value was removed"
        $pathNow = Get-UserPathRaw
        Check ((Get-UserPathKind) -eq $pathKind) "the user PATH changed kind to $(Get-UserPathKind)"
        Check ($pathNow -ceq "$Bin;$pathRaw") "unexpected user PATH '$pathNow'"

        Write-Log "-Rollback must refuse to restore a Setup install"
        Check ((Invoke-Installer (Join-Path $DcHome "installer\install.ps1") @("-Rollback", "-Yes")) -eq 1) "-Rollback into Setup must fail"
        Assert-Versions $Target
        Assert-Healthy
    } finally {
        Set-UserPath $pathRaw $pathKind
        foreach ($name in "DefenseClawGateway", "DefenseClawDeferredUninstallCleanup", "DefenseClawLifecycleUnrelated") {
            Remove-ItemProperty -LiteralPath $runKey -Name $name -ErrorAction SilentlyContinue
        }
        Remove-Item -LiteralPath $uninstallKey -Recurse -Force -ErrorAction SilentlyContinue
    }
}

$startPath = Get-UserPathRaw
$startKind = Get-UserPathKind
try {
    foreach ($lane in @($Lanes -split '[\s,]+' | Where-Object { $_ })) {
        if ($lane -in @("upgrade-previous", "shim") -and -not $PreviousAssets) { throw "lane $lane needs -PreviousAssets" }
        switch ($lane) {
            "fresh" { Invoke-Lane $lane { Test-Fresh } }
            "upgrade-previous" { Invoke-Lane $lane { Test-UpgradePrevious } }
            "shim" { Invoke-Lane $lane { Test-Shim } }
            "files-in-use" { Invoke-Lane $lane { Test-FilesInUse } }
            "setup-import" { Invoke-Lane $lane { Test-SetupImport } }
            "failure-drill" { Invoke-Lane $lane { Test-FailureDrill } }
            "policy" { Invoke-Lane $lane { Test-Policy } }
            default { throw "unknown lane: $lane" }
        }
    }
} finally {
    Stop-Held
    if ((Get-UserPathRaw) -cne $startPath -or (Get-UserPathKind) -ne $startKind) {
        Fail "a lane left the user PATH changed; restoring it"
        Set-UserPath $startPath $startKind
    }
    foreach ($laneHome in $script:LaneHomes) {
        $gateway = Join-Path $laneHome ".local\bin\defenseclaw-gateway.exe"
        if (Test-Path -LiteralPath $gateway) { $env:USERPROFILE = $laneHome; [void](Invoke-Exe $gateway @("stop") -Quiet) }
    }
    if ($Keep) { Write-Host "kept $Root" } else { Remove-Item -LiteralPath $Root -Recurse -Force -ErrorAction SilentlyContinue }
}
if ($script:Failures) {
    Write-Host "[lifecycle] $($script:Failures) check(s) failed" -ForegroundColor Red
    exit 1
}
Write-Host "[lifecycle] all lanes passed ($Lanes)" -ForegroundColor Green
