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
    DefenseClaw installer and upgrader for Windows.

.DESCRIPTION
      irm https://github.com/cisco-ai-defense/defenseclaw/releases/latest/download/install.ps1 | iex

    The same command installs, upgrades, repairs, and imports a 0.x install
    (including a DefenseClaw Setup install); `defenseclaw upgrade` runs it for
    you. Each release's copy installs exactly that release, so the upgrade
    logic always comes from the version being installed. Config and data in
    %USERPROFILE%\.defenseclaw are kept; the replaced install is kept in
    %USERPROFILE%\.defenseclaw\previous for -Rollback.

    Permanent interface (never remove or change these): -Yes, -Version X.Y.Z,
    -Local DIR, -Rollback. An unknown argument stops the installer with exit 2
    before it changes anything (GAP-0361). Only the copy that `defenseclaw
    upgrade` or `rollback` runs (from a defenseclaw-upgrade-* or
    defenseclaw-rollback-* folder) ignores one with a warning, so an older
    release's installer accepts the flags of a newer client.

    Windows PowerShell 5.1 or later. Run it as the user who uses DefenseClaw;
    it does not need administrator rights.
#>

[CmdletBinding(PositionalBinding = $false)]
param(
    [switch]$Yes,
    [string]$Version = "",
    [string]$Local = "",
    [switch]$Rollback,
    [string]$Connector = "",
    [switch]$NoOpenclaw,
    [switch]$Quickstart,
    [string]$QuickstartMode = "",
    [switch]$NoPersistPath,
    [string]$CosignPath = "",
    [switch]$AcceptCurrentInstall,
    [switch]$Help,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$UnknownArguments = @()
)

# The whole installer is one script block, so a truncated download does not
# parse, and nothing it defines leaks into a session that ran `irm | iex`.
& {
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
# -Local "" (an empty value) binds like no -Local at all (GAP-1336).
$LocalGiven = [bool](Get-Variable -Name PSBoundParameters -Scope 1 -ValueOnly -ErrorAction SilentlyContinue |
    Where-Object { $_.ContainsKey("Local") })
# -Version "" picked the latest release, as no -Version (GAP-0012, GAP-0069).
$VersionGiven = [bool](Get-Variable -Name PSBoundParameters -Scope 1 -ValueOnly -ErrorAction SilentlyContinue |
    Where-Object { $_.ContainsKey("Version") })
try {
    [Net.ServicePointManager]::SecurityProtocol =
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch { }

$DcVersion = "__DEFENSECLAW_VERSION__"
# This installer checks active recovery before snapshots in both version directions.
$DcVersionChangeGuard = 1
# This installer reads the lifecycle record (.lifecycle-txn.json) and finishes
# its step before it changes anything.
$DcLifecycleRecord = 1
$DefaultRepo = "cisco-ai-defense/defenseclaw"
$Repo = if ($env:DEFENSECLAW_REPO) { $env:DEFENSECLAW_REPO } else { $DefaultRepo }
# DEFENSECLAW_REPO (the deprecated alias of config.yaml update.source) is a
# GitHub owner/name or an https mirror base URL. It only changes where release
# bytes come from: signatures are always checked against the official release
# identity, and a mirror's downloads are refused without cosign.
$ReleaseBase = if ($Repo -like "https://*") { $Repo.TrimEnd("/") } else { "https://github.com/$Repo" }
$OfficialReleaseBase = "https://github.com/$DefaultRepo"
$ReleaseSigner = '^https://github\.com/cisco-ai-defense/defenseclaw/\.github/workflows/release\.yaml@refs/heads/main$'
$DataDir = if ($env:DEFENSECLAW_HOME) { $env:DEFENSECLAW_HOME } else { Join-Path $env:USERPROFILE ".defenseclaw" }
$Venv = Join-Path $DataDir ".venv"
$BinDir = Join-Path $env:USERPROFILE ".local\bin"
$Previous = Join-Path $DataDir "previous"
$Staging = Join-Path $DataDir ".staging"
$InstallerDir = Join-Path $DataDir "installer"
$LockDir = Join-Path $DataDir ".install.lock"
$RunKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
# The per-user DefenseClaw Setup of 0.8.7-0.8.10, which an upgrade replaces.
$SetupRoot = Join-Path $env:LOCALAPPDATA "Programs\DefenseClaw"
$Setup = $null
$SetupUninstallKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\DefenseClaw"
$SetupCache = Join-Path $env:LOCALAPPDATA "DefenseClaw\InstallerCache"
$SetupHookState = Join-Path $env:LOCALAPPDATA "DefenseClaw\HookRuntime\hook-runtime-state.json"
# Real files in BinDir. Connector hooks record these paths, so they never move.
$ManagedBinaries = @("defenseclaw-gateway.exe", "defenseclaw-hook.exe", "defenseclaw-acp.exe")
# .cmd shims in BinDir for console scripts in the venv; the gateway runs them by name.
$ManagedShims = @("defenseclaw", "skill-scanner", "mcp-scanner")
# Git Bash does not run a .cmd file by its bare name, so `defenseclaw` there
# runs this extensionless script. cmd.exe and PowerShell ignore it: it has no
# PATHEXT extension.
$PosixShim = "defenseclaw"
# PowerShell and cmd.exe run `defenseclaw` through this copy of the venv's
# native console-script launcher: PATHEXT puts .exe before .cmd. Through the
# .cmd shim, cmd.exe asked "Terminate batch job (Y/N)?" after every Ctrl+C
# (GAP-2237); defenseclaw.cmd stays for callers that name it.
$CliLauncher = "defenseclaw.exe"
# defenseclaw-hook.exe reads its data dir from the state file beside it, never
# from the environment an agent runs it with (a custom DEFENSECLAW_HOME too).
$HookState = "defenseclaw-hook-state.json"
$ManagedFiles = $ManagedBinaries + @($ManagedShims | ForEach-Object { "$_.cmd" }) + @($PosixShim, $CliLauncher, $HookState)
# What a `make all` developer install publishes to BinDir besides the managed
# binaries (cmd_uninstall._WINDOWS_DEVELOPER_FILES), except its defenseclaw.exe,
# which Install-New replaces with $CliLauncher. These must go.
$DeveloperFiles = @("litellm.exe", "skill-scanner.exe", "skill-scanner-api.exe",
    "skill-scanner-pre-commit.exe", "mcp-scanner.exe", "mcp-scanner-api.exe", ".defenseclaw-source-root")
# Data-dir entries that are install machinery, not user data.
$NotData = @(".venv", ".venv.busy", ".uv", "previous", "previous.new", ".repair", ".staging", ".failed-*",
    "installer", "logs", ".install.lock", "backups", ".rollback-hold", ".rollback-hold.done",
    ".lifecycle-txn.json", ".lifecycle-txn.json.new", ".lifecycle-closer")
# Connectors supported on Windows (cli/defenseclaw/platform_support.py).
$ConnectorChoices = @("codex", "claudecode", "hermes", "cursor", "devin", "copilot", "antigravity",
    "opencode", "amp", "kiro", "none")
# -File runs return exit codes; `irm | iex` and script blocks must never exit
# (that would close the user's window), so they throw instead.
$RunAsFile = -not [string]::IsNullOrEmpty($PSCommandPath)
# Windows PowerShell 5.1 started from a PowerShell 7 session (through cmd, or
# an older `defenseclaw upgrade`) inherits the PowerShell 7 module folders and
# then cannot load its own built-in modules, so Get-Acl fails. Drop them.
if ($RunAsFile -and $PSVersionTable.PSEdition -ne "Core" -and $env:PSModulePath) {
    $modulePath = @($env:PSModulePath -split ";" | Where-Object { $_ -and $_ -notmatch '\\PowerShell\\(7[^\\]*\\)?Modules\\?$' })
    if ($modulePath -notcontains (Join-Path $PSHOME "Modules")) { $modulePath += Join-Path $PSHOME "Modules" }
    $env:PSModulePath = $modulePath -join ";"
}
$RunByUpgrade = $RunAsFile -and (Split-Path -Leaf (Split-Path -Parent $PSCommandPath)) -match '^defenseclaw-(upgrade|rollback)-'
$Run = @{ Lock = $false; Transcript = $false; Log = ""; Owner = [IntPtr]::Zero; QuickstartRerun = ""; QuickstartRc = 0; OldGatewayDown = $false; UsageError = $false; UndoPending = $false; RestorePending = $false; UnprovenReplacement = $null; UnprovenReplacementUnchanged = $false; UnprovenGatewayWasRunning = $false; UnprovenAcceptedBins = $null; UnprovenConnectors = @(); UnprovenCloserSha256 = "" }

function Write-Info([string]$Message) { Write-Host "  > $Message" -ForegroundColor Blue }
function Write-Ok([string]$Message) { Write-Host "  + $Message" -ForegroundColor Green }
function Write-Warn([string]$Message) { Write-Host "  ! $Message" -ForegroundColor Yellow }
function Write-Err([string]$Message) { Write-Host "  x $Message" -ForegroundColor Red }
function Get-UtcClock { return (Get-Date).ToUniversalTime().ToString("HH:mm:ss") + "Z" }
# Step headers and gateway lines carry the UTC time, so the install log can time a run (GAP-1797).
function Write-Step([string]$Message) { Write-Host ""; Write-Host "--- $Message  [$(Get-UtcClock)]" -ForegroundColor Cyan }
function Die([string]$Message) { throw $Message }
# A wrong option or value: exit 2, before anything changed.
function Stop-Usage([string]$Message) { $Run.UsageError = $true; throw "$Message; nothing was changed. Run with -Help for the options." }

function Test-Version([string]$Value) {
    return $Value -match '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'
}

function Get-OSArchitectureName {
    # In an interactive Windows PowerShell 5.1 console (the `irm | iex` path)
    # [Runtime.InteropServices.RuntimeInformation] resolves to PSReadLine's
    # polyfill, which has no OSArchitecture. Ask the core library instead.
    $type = [object].Assembly.GetType("System.Runtime.InteropServices.RuntimeInformation")
    $property = if ($type) { $type.GetProperty("OSArchitecture") } else { $null }
    if ($property) { return $property.GetValue($null).ToString().ToUpperInvariant() }
    $name = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { [string]$env:PROCESSOR_ARCHITECTURE }
    if ($name -eq "AMD64") { return "X64" }
    return $name.ToUpperInvariant()
}

function Confirm-Step([string]$Prompt, [switch]$DefaultNo) {
    if ($Yes) { return $true }
    $choices = if ($DefaultNo) { "[y/N]" } else { "[Y/n]" }
    try { $answer = Read-Host "  $Prompt $choices" } catch { $answer = "" }
    if ([string]::IsNullOrWhiteSpace($answer)) { return -not $DefaultNo }
    return $answer -match '^[Yy]'
}

function Get-Field($Object, [string]$Name) {
    # A newly written lifecycle record is an OrderedDictionary until the
    # next process reads its JSON. Its keys are not PSObject properties in
    # Windows PowerShell 5.1; use dictionary lookup for that in-memory path.
    if ($Object -is [Collections.IDictionary]) {
        if ($Object.Contains($Name)) { return $Object[$Name] }
        return $null
    }
    if ($null -ne $Object -and $Object.PSObject.Properties[$Name]) { return $Object.PSObject.Properties[$Name].Value }
    return $null
}

function Read-Json([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    try { return [IO.File]::ReadAllText($Path) | ConvertFrom-Json } catch { return $null }
}

function Read-Text([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return "" }
    return [IO.File]::ReadAllText($Path).Trim()
}

function Test-SamePath([string]$Entry, [string]$Path) {
    $expanded = [Environment]::ExpandEnvironmentVariables($Entry.Trim().Trim('"')).TrimEnd("\")
    return $expanded -and $expanded -eq $Path.TrimEnd("\")
}

function Remove-Tree([string]$Path) {
    # Antivirus and the search indexer hold freshly written files for a moment,
    # so a delete that fails is retried for up to 30 seconds. Windows PowerShell
    # cannot delete below MAX_PATH (a venv's bundled data goes deeper under a
    # long profile path), so a failed attempt retries through the \\?\ path.
    # Only the last attempt may stop: a caught stopping error on an earlier one still
    # lands in the run log as a TerminatingError although the retry worked.
    # The .NET delete goes first: Remove-Item took minutes for a venv in Windows
    # PowerShell 5.1 (GAP-1600), and its -Force first resets each file's
    # attributes, which a read-only key copy refuses (GAP-1645). Remove-Item then
    # takes what .NET leaves (read-only files).
    for ($attempt = 1; Test-Path -LiteralPath $Path; $attempt++) {
        if ($attempt -ge 30) { Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop; return }
        try { [IO.Directory]::Delete("\\?\" + [IO.Path]::GetFullPath($Path), $true) } catch { }
        if (-not (Test-Path -LiteralPath $Path)) { return }
        Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue
        if (-not (Test-Path -LiteralPath $Path)) { return }
        Start-Sleep -Seconds 1
    }
}

function Set-DirectoryAcl([string]$Path, $Acl) {
    # Writes only the parts of $Acl that changed. Set-Acl writes them all and
    # was refused for a standard user on a second NTFS volume he has full
    # control of, so a DEFENSECLAW_HOME there failed at once (GAP-2004).
    $dir = New-Object IO.DirectoryInfo ([IO.Path]::GetFullPath($Path))
    if ($dir.PSObject.Methods["SetAccessControl"]) { $dir.SetAccessControl($Acl) }
    else { [IO.FileSystemAclExtensions]::SetAccessControl($dir, $Acl) }
}

function New-InstallDirectory([string]$Path) {
    # A fresh directory for the venv or install machinery (staging, the
    # rollback slot) that does not inherit the data dir's permissions.
    # DefenseClaw re-applies those on every private write, and Windows then
    # revisits each file below that inherits them: with venvs (hardlinked
    # from the uv cache) that takes seconds, longer than the gateway may take
    # to start.
    Remove-Tree $Path
    New-Item -ItemType Directory -Path $Path | Out-Null
    $acl = Get-Acl -LiteralPath $Path
    $acl.SetAccessRuleProtection($true, $true)
    try { Set-DirectoryAcl $Path $acl } catch { Die "Could not set the permissions of ${Path}: $($_.Exception.Message)" }
}

function Protect-UvDirectory {
    param([switch]$Create)
    # New-InstallDirectory for the uv folder, which must keep its contents.
    # Its cache and Python (about 23,000 files) inherited the data dir's
    # permissions, so a 1.0.0 gateway, which re-applies those on every private
    # write, missed its 5-second start window after a rollback (GAP-1988).
    # Empty, this is instant; the first run over a full folder takes a while.
    $uvDir = Join-Path $DataDir ".uv"
    if (-not (Test-Path -LiteralPath $uvDir -PathType Container)) {
        if (-not $Create) { return }
        New-Item -ItemType Directory -Path $uvDir | Out-Null
    }
    $acl = Get-Acl -LiteralPath $uvDir
    if ($acl.AreAccessRulesProtected) { return }
    if (Get-ChildItem -LiteralPath $uvDir -Force -ErrorAction SilentlyContinue | Select-Object -First 1) {
        Write-Info "Setting the permissions of $uvDir (once; this can take a minute)"
    }
    $acl.SetAccessRuleProtection($true, $true)
    try { Set-DirectoryAcl $uvDir $acl } catch {
        Write-Warn "Could not set the permissions of ${uvDir}: $($_.Exception.Message)"
    }
}

function Repair-DataOwner {
    # An elevated 0.x installer left its connector backups, and the agent
    # configs its connectors wrote (such as ~\.codex\config.toml), owned by
    # the Administrators group; the 1.x gateway refuses to manage those unless
    # its user owns them. icacls changes only the owner: Set-Acl would also
    # mark the SACL protected, which a replacement file cannot reproduce. This
    # runs after the snapshot, so a rollback puts the old owners back.
    $user = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $admins = New-Object Security.Principal.SecurityIdentifier "S-1-5-32-544"
    $items = @()
    $backups = Join-Path $DataDir "connector_backups"
    if (Test-Path -LiteralPath $backups -PathType Container) {
        $items += @(Get-Item -LiteralPath $backups -Force) + @(Get-ChildItem -LiteralPath $backups -Recurse -Force -ErrorAction SilentlyContinue)
    }
    try {
        $lock = Get-Content -Raw -LiteralPath (Join-Path $DataDir "hook_contract_lock.json") -ErrorAction Stop | ConvertFrom-Json
        foreach ($entry in @($lock.connectors.PSObject.Properties | ForEach-Object { $_.Value })) {
            foreach ($path in @($entry.locations.hook_config_paths)) {
                if (-not $path -or -not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
                $items += @(Get-Item -LiteralPath $path -Force) + @(Get-Item -LiteralPath (Split-Path $path) -Force)
            }
        }
    } catch { }
    foreach ($item in $items) {
        try { $owner = (Get-Acl -LiteralPath $item.FullName).GetOwner([Security.Principal.SecurityIdentifier]) } catch { continue }
        if ($owner -ne $admins) { continue }
        & icacls.exe $item.FullName /setowner "*$($user.Value)" /C /Q *> $null
        if ($LASTEXITCODE -ne 0) { Write-Warn "Could not take ownership of $($item.FullName)" }
    }
}

function Move-Path([string]$From, [string]$To, [int]$Seconds = 10) {
    # A rename, which either happens or changes nothing. (Move-Item copies a
    # directory it cannot rename and leaves both halves behind.) Windows
    # refuses to rename what another program has open, or a virus scanner is
    # reading: retry for a while.
    if (Test-Path -LiteralPath $To) { throw "Cannot move $From to ${To}: it already exists" }
    $directory = Test-Path -LiteralPath $From -PathType Container
    for ($waited = 0; ; $waited++) {
        try {
            if ($directory) { [IO.Directory]::Move($From, $To) } else { [IO.File]::Move($From, $To) }
            return
        } catch {
            if ($waited -ge $Seconds) { throw }
        }
        Start-Sleep -Seconds 1
    }
}

function Move-AuditStore([string]$From, [string]$To) {
    # An SQLite store moves with its -wal, -shm and -journal as one unit: when
    # a move fails, what moved goes back and the error is thrown, so a store is
    # never separated from its WAL (SQLite would drop the WAL's transactions;
    # rel-1-0-2:GAP-0491, as move_audit_store in install.sh).
    $moved = New-Object System.Collections.Generic.List[string]
    try {
        foreach ($suffix in @("", "-wal", "-shm", "-journal")) {
            if (-not (Test-Path -LiteralPath "$From$suffix")) { continue }
            Move-Path "$From$suffix" "$To$suffix"
            $moved.Add($suffix)
        }
    } catch {
        $failure = $_
        $stuck = @()
        for ($i = $moved.Count - 1; $i -ge 0; $i--) {
            try { Move-Path "$To$($moved[$i])" "$From$($moved[$i])" } catch { $stuck += "$To$($moved[$i])" }
        }
        if ($stuck.Count) { throw "$($failure.Exception.Message); $($stuck -join ', ') could not be moved back to $From" }
        throw $failure
    }
}

function Copy-Kept([string]$Source, [string]$DestinationDir) {
    # Copy into DestinationDir with robocopy, which keeps each file's
    # permissions: DefenseClaw refuses keys and tokens that come back from a
    # rollback with inherited ones.
    $item = Get-Item -LiteralPath $Source -Force
    $copy = if ($item.PSIsContainer) { @($Source, (Join-Path $DestinationDir $item.Name), "/E") } else { @($item.DirectoryName, $DestinationDir, $item.Name) }
    $options = @("/COPY:DATS", "/DCOPY:DAT", "/IS", "/IT", "/R:2", "/W:1", "/NFL", "/NDL", "/NJH", "/NJS", "/NP")
    $result = Invoke-Robocopy ($copy + $options)
    if ($result.Code -lt 8) { return }
    $why = if ($result.Error) { $result.Error } else { "robocopy exit $($result.Code)" }
    if (-not $item.PSIsContainer) {
        # robocopy refused one file, as it did for an audit.db a failed 0.8.10
        # Setup left (GAP-1048): copy its bytes, then its access list where
        # Windows allows it; otherwise the copy keeps the rollback folder's
        # private permissions.
        $target = Join-Path $DestinationDir $item.Name
        try {
            [IO.File]::Copy($Source, $target, $true)
            try {
                $from = New-Object IO.FileInfo $Source
                $to = New-Object IO.FileInfo $target
                $acl = if ($from.PSObject.Methods["GetAccessControl"]) { $from.GetAccessControl("Access") } else { [IO.FileSystemAclExtensions]::GetAccessControl($from, "Access") }
                if ($to.PSObject.Methods["SetAccessControl"]) { $to.SetAccessControl($acl) } else { [IO.FileSystemAclExtensions]::SetAccessControl($to, $acl) }
            } catch { }
            return
        } catch { if (-not $result.Error) { $why = $_.Exception.GetBaseException().Message } }
    }
    # Name what may hold it: a gateway or hook a failed Setup left running.
    $running = @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -like "defenseclaw*" } | ForEach-Object { "$($_.ProcessName) (PID $($_.Id))" })
    $held = if ($running.Count) { "; DefenseClaw programs still running: $($running -join ', ') (stop them with Stop-Process -Id <PID>)" } else { "" }
    throw "Could not copy $Source ($why)$held. Check that this account can read it and that no program has it open (icacls `"$Source`"), then run the installer again"
}

function Invoke-Robocopy([string[]]$Arguments) {
    # robocopy says why a file failed only in its output: keep the first
    # error line and the reason on the line after it.
    $ErrorActionPreference = "Continue"
    $lines = @(& (Join-Path $env:SystemRoot "System32\robocopy.exe") @Arguments 2>&1 | ForEach-Object { "$_".Trim() })
    $code = $LASTEXITCODE
    $detail = ""
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match "(ERROR \d+ \(0x[0-9A-Fa-f]+\).*)$") {
            $detail = $Matches[1]
            if ($i + 1 -lt $lines.Count -and $lines[$i + 1]) { $detail += " $($lines[$i + 1])" }
            break
        }
    }
    return [pscustomobject]@{ Code = $code; Error = $detail }
}

function Invoke-Quietly([scriptblock]$Action) {
    try { & $Action } catch { Write-Warn $_.Exception.Message }
}

function Invoke-Native([string]$FilePath, [string[]]$Arguments = @(), [switch]$Quiet) {
    # Output goes through the host, so the install log (a transcript) keeps it.
    $ErrorActionPreference = "Continue"
    # Failure to launch a native image does not set LASTEXITCODE. Never
    # mistake an earlier successful command for this command's result.
    $global:LASTEXITCODE = -1
    if ($Quiet) { & $FilePath @Arguments *> $null } else { & $FilePath @Arguments 2>&1 | ForEach-Object { Write-Host "$_" } }
    return $LASTEXITCODE
}

function Get-NativeProbe([string]$FilePath, [string[]]$Arguments = @()) {
    # A native command's output and exit code (-1 when it could not run).
    $ErrorActionPreference = "Continue"
    try {
        $output = ((& $FilePath @Arguments 2>&1) | Out-String)
        return [pscustomobject]@{ Exit = $LASTEXITCODE; Output = $output }
    } catch { return [pscustomobject]@{ Exit = -1; Output = "" } }
}

function Get-NativeOutput([string]$FilePath, [string[]]$Arguments = @()) {
    $ErrorActionPreference = "Continue"
    try { return ((& $FilePath @Arguments 2>&1) | Out-String) } catch { return "" }
}

function Get-Sha256([string]$Path) {
    # A file this account cannot read printed PowerShell's raw ReadError and
    # "The property 'Hash' cannot be found" before the sentence that said what
    # happened (GAP-0007): say once which file could not be read.
    try { $hash = Get-FileHash -Algorithm SHA256 -LiteralPath $Path -ErrorAction Stop } catch {
        throw "Could not read $Path; restore read access to it, then try again"
    }
    return $hash.Hash.ToLowerInvariant()
}

function Get-ListedSha256([string]$Checksums, [string]$Name) {
    foreach ($line in [IO.File]::ReadAllLines($Checksums)) {
        $fields = @($line.Trim() -split '\s+')
        if ($fields.Count -eq 2 -and $fields[1].TrimStart("*") -eq $Name) { return $fields[0].ToLowerInvariant() }
    }
    return ""
}

function Test-Checksum([string]$File, [string]$Name = (Split-Path -Leaf $File)) {
    $expected = Get-ListedSha256 (Join-Path $Staging "checksums.txt") $Name
    return $expected -and $expected -eq (Get-Sha256 $File)
}

function Save-Url([string]$Url, [string]$Destination) {
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        try { Invoke-WebRequest -UseBasicParsing -Uri $Url -OutFile $Destination; return $true } catch {
            $response = if ($_.Exception -is [Net.WebException]) { $_.Exception.Response } else { $null }
            if ($null -ne $response -and [int]$response.StatusCode -eq 404) { return $false }
            Start-Sleep -Seconds $attempt
        }
    }
    return $false
}

function Get-Asset([string]$Name, [string]$Destination) {
    # Copy from -Local, or download from this installer's release.
    if ($LocalDir) {
        $source = Join-Path $LocalDir $Name
        if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { return $false }
        Copy-Item -LiteralPath $source -Destination $Destination -Force
        return $true
    }
    return Save-Url "$ReleaseBase/releases/download/$Ver/$Name" $Destination
}

function Get-LatestRelease {
    # releases/latest redirects to the latest tag: no API call, no rate limit.
    $tag = ""
    try {
        $request = [Net.HttpWebRequest]::Create("$ReleaseBase/releases/latest")
        $request.Method = "HEAD"
        $request.AllowAutoRedirect = $false
        $request.UserAgent = "defenseclaw-install"
        $response = $request.GetResponse()
        $location = [string]$response.Headers["Location"]
        $response.Close()
        if ($location -match '/tag/v?([^/]+)$') { $tag = $Matches[1] }
    } catch { }
    if (-not (Test-Version $tag)) { Die "Could not determine the latest release of $Repo" }
    return $tag
}

function ConvertTo-ProcessArgument([string]$Value) {
    # Quote for CommandLineToArgvW: backslashes before a quote, and trailing
    # ones before the closing quote, are doubled.
    if ($Value -and $Value -notmatch '[\s"]') { return $Value }
    return '"' + (($Value -replace '(\\*)"', '$1$1\"') -replace '(\\+)$', '$1$1') + '"'
}

# uv, when it is missing: a pinned release, checked against this digest (from
# the release's .sha256 file) before anything runs. Bump them together.
$UvVersion = "0.12.13"
$UvZipSha256 = "a86c9dc7bad9b03f388583b7187c05fe9951c2e0d392217e8fd43d97787f6ec2"

function Install-Uv([string]$Destination = $BinDir) {
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("defenseclaw-uv-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
    New-Item -ItemType Directory -Path $tmp | Out-Null
    try {
        $zip = Join-Path $tmp "uv.zip"
        if (-not (Save-Url "https://github.com/astral-sh/uv/releases/download/$UvVersion/uv-x86_64-pc-windows-msvc.zip" $zip)) { return "" }
        if ((Get-Sha256 $zip) -ne $UvZipSha256) { Write-Err "The uv download does not match its pinned checksum"; return "" }
        Expand-Archive -LiteralPath $zip -DestinationPath (Join-Path $tmp "uv") -Force
        New-Item -ItemType Directory -Path $Destination -Force | Out-Null
        $record = @()
        foreach ($name in @("uv.exe", "uvx.exe", "uvw.exe")) {
            $file = Join-Path $tmp "uv\$name"
            if (Test-Path -LiteralPath $file) {
                Copy-Item -LiteralPath $file -Destination (Join-Path $Destination $name) -Force
                $record += "$(Get-Sha256 (Join-Path $Destination $name))  $name"
            }
        }
        # Only a bin-folder install is recorded for `uninstall --binaries`;
        # a recovery copy kept outside that folder is not an installed tool.
        if (Test-SamePath $Destination $BinDir) {
            Invoke-Quietly { [IO.File]::WriteAllText((Join-Path $BinDir "defenseclaw-uv.sha256"), (($record -join "`n") + "`n")) }
        }
        $uv = Join-Path $Destination "uv.exe"
        if (Test-Path -LiteralPath $uv) { return $uv }
        return ""
    } catch {
        Write-Err $_.Exception.Message
        return ""
    } finally {
        Invoke-Quietly { Remove-Tree $tmp }
    }
}

function Get-Cosign {
    # cosign 2.0 or later if it is installed, else "". A -CosignPath that is
    # not one stops the install rather than silently skipping the check.
    $cosign = if ($CosignPath) { $CosignPath } else {
        [string](Get-Command cosign.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty Source)
    }
    if ($cosign -and (Test-Path -LiteralPath $cosign) -and (Get-NativeOutput $cosign @("version")) -match 'GitVersion:\s*v?(\d+)\.' -and [int]$Matches[1] -ge 2) {
        return $cosign
    }
    if ($CosignPath) { Die "-CosignPath $CosignPath is not cosign 2.0 or later; nothing was changed" }
    return ""
}

function Test-ReleaseSignature([string]$Cosign, [string]$Bundle, [string]$Checksums) {
    # 0 when checksums.txt carries the official Release workflow signature.
    return Invoke-Native $Cosign @("verify-blob", "--bundle", $Bundle, "--certificate-identity-regexp", $ReleaseSigner,
        "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com", $Checksums) -Quiet
}

function Invoke-ReleaseInstaller([string]$ReleaseVersion, [string[]]$Forward) {
    # Download that release's installer, verify it, and run it (-Version, or
    # an unstamped copy from the source tree). Named like the directories of
    # `defenseclaw upgrade`, so the installer it runs removes it.
    $installed = Get-InstalledVersion
    $target = $ReleaseVersion.TrimStart("v")
    $versionChange = (Test-Version $installed) -and (Test-Version $target) -and [version]$target -ne [version]$installed
    if ($versionChange) { Assert-NoActiveConnectorRecovery "Version change to $target" }
    $downgrade = $versionChange -and [version]$target -lt [version]$installed
    $restartCurrent = $false
    $childCode = $null
    $restartFailed = $false
    $restartCode = 0
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("defenseclaw-upgrade-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
    New-Item -ItemType Directory -Path $tmp | Out-Null
    try {
        Write-Info "Fetching the installer for DefenseClaw $ReleaseVersion"
        $base = "$ReleaseBase/releases/download/$ReleaseVersion"
        if (-not (Save-Url "$base/install.ps1" "$tmp\install.ps1")) {
            Die "Release $ReleaseVersion has no install.ps1 (1.x releases start at 1.0.0)"
        }
        if (-not (Save-Url "$base/checksums.txt" "$tmp\checksums.txt")) { Die "Release $ReleaseVersion has no checksums.txt" }
        if ((Get-ListedSha256 "$tmp\checksums.txt" "install.ps1") -ne (Get-Sha256 "$tmp\install.ps1")) {
            Die "install.ps1 for $ReleaseVersion does not match its checksums.txt"
        }
        # With cosign, the installer about to run is checked like the assets it installs.
        $cosign = Get-Cosign
        if ($cosign) {
            if (-not (Save-Url "$base/checksums.txt.bundle" "$tmp\checksums.txt.bundle")) {
                Die "Release $ReleaseVersion has no checksums.txt.bundle to verify with cosign"
            }
            if ((Test-ReleaseSignature $cosign "$tmp\checksums.txt.bundle" "$tmp\checksums.txt") -ne 0) {
                Die "The release signature on the checksums.txt of $ReleaseVersion did not verify"
            }
        } elseif ($ReleaseBase -ne $OfficialReleaseBase) {
            Die "Releases from $ReleaseBase are verified by their signature: install cosign 2.0 or later"
        }
        # Every release is signed by the same identity, so the signature alone
        # would let a mirror serve another (older) release under this version.
        $stamped = ""
        $match = Select-String -LiteralPath "$tmp\install.ps1" -Pattern '^\$DcVersion = "(.*)"$' | Select-Object -First 1
        if ($match) { $stamped = $match.Matches[0].Groups[1].Value }
        if ($stamped.TrimStart("v") -ne $ReleaseVersion.TrimStart("v")) {
            Die "The installer served for $ReleaseVersion is release $(if ($stamped) { $stamped } else { 'unknown' }); refusing a mismatched release"
        }
        # Trust this capability only in the verified, correctly stamped script.
        # Unknown or duplicate declarations take the conservative legacy path.
        $guard = @(Select-String -LiteralPath "$tmp\install.ps1" -Pattern '^\s*\$DcVersionChangeGuard\b')
        $childGuardsVersionChanges = $guard.Count -eq 1 -and $guard[0].Line -ceq '$DcVersionChangeGuard = 1'
        # An installer that does not read the lifecycle record would install
        # over the install that record still has to prove (1.0.3 and earlier
        # clear its lock): the step it records is finished first, here.
        $pending = [string](Get-Variable -Name LifecycleManifest -ValueOnly -ErrorAction SilentlyContinue)
        if ($pending -and (Test-Path -LiteralPath $pending)) {
            $record = @(Select-String -LiteralPath "$tmp\install.ps1" -Pattern '^\s*\$DcLifecycleRecord\b')
            if (-not ($record.Count -eq 1 -and $record[0].Line -ceq '$DcLifecycleRecord = 1')) {
                Die ("An earlier install step is not finished: its record $pending is still here, and the installer of DefenseClaw $ReleaseVersion " +
                    "does not read it, so it was not started. Finish that step first with: $(Get-LifecycleNextStep); then run the version change again")
            }
        }
        if ($versionChange -and ($downgrade -or -not $childGuardsVersionChanges)) {
            # A verified newer child with the guard owns stopping and startup
            # rollback. Older/unrecognized installers need this outer check.
            Wait-VenvFree
            $restartCurrent = [bool](Get-GatewayProcess)
            if (-not (Stop-Gateway)) { Die "The gateway did not stop; the release installer was not started" }
            Stop-Watchdog
            Assert-GatewayQuiescent "Version change to $target"
            Assert-NoActiveConnectorRecovery "Version change to $target"
        }
        $shell = if ($PSVersionTable.PSEdition -eq "Core") { "pwsh.exe" } else { "powershell.exe" }
        # Start the child on this console rather than through the pipeline, so its
        # output and prompts reach the user and only its exit code is returned.
        # WaitForExit, not -Wait: -Wait would also wait for the gateway it starts.
        $arguments = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "$tmp\install.ps1") + @($Forward)
        $child = Start-Process -FilePath (Join-Path $PSHOME $shell) -NoNewWindow -PassThru `
            -ArgumentList @($arguments | ForEach-Object { ConvertTo-ProcessArgument $_ })
        $null = $child.Handle
        $child.WaitForExit()
        $childCode = $child.ExitCode
    } finally {
        if ($restartCurrent) {
            $restartIssue = ""
            try {
                if (-not (Get-GatewayProcess)) {
                    $restartCode = Start-Gateway
                    if ($restartCode -notin @(0, 3)) { $restartIssue = "exit $restartCode" }
                }
            } catch { $restartIssue = $_.Exception.Message }
            if ($restartIssue) {
                $restartFailed = $true
                Write-Warn "The installed gateway could not restart ($restartIssue)"
                Write-Info "Retry the installed version with 'defenseclaw-gateway start' and check its log."
                if ($null -ne $childCode) {
                    Write-Info "To undo a completed version change, run 'defenseclaw rollback', then 'defenseclaw-gateway start'."
                }
            }
        }
        Invoke-Quietly { Remove-Tree $tmp }
    }
    # A wrapped child saw a stopped gateway, so it may have committed without
    # checking startup. Keep its failure/attention code, but never report its
    # success when the gateway that was running could not be brought back.
    if ($restartFailed -and $childCode -eq 0) { return 1 }
    if ($childCode -eq 0 -and $restartCode -eq 3) { return 3 }
    return $childCode
}

function Initialize-Native {
    if ("DefenseClawInstall.Native" -as [type]) { return }
    Add-Type -Namespace DefenseClawInstall -Name Native -MemberDefinition @'
[DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint msg, UIntPtr wParam, string lParam,
    uint flags, uint timeout, out UIntPtr result);
[DllImport("kernel32.dll")]
public static extern uint GetConsoleProcessList(uint[] processList, uint processCount);
[DllImport("advapi32.dll", SetLastError = true)]
static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
[DllImport("advapi32.dll", SetLastError = true)]
static extern bool GetTokenInformation(IntPtr token, int infoClass, IntPtr info, int length, out int returned);
[DllImport("advapi32.dll", SetLastError = true)]
static extern bool SetTokenInformation(IntPtr token, int infoClass, IntPtr info, int length);
[DllImport("kernel32.dll")]
static extern IntPtr GetCurrentProcess();
[DllImport("kernel32.dll")]
static extern bool CloseHandle(IntPtr handle);

// A TOKEN_OWNER for sid.
public static IntPtr NewOwner(byte[] sid) {
    IntPtr owner = Marshal.AllocHGlobal(IntPtr.Size + sid.Length);
    Marshal.WriteIntPtr(owner, IntPtr.Add(owner, IntPtr.Size));
    Marshal.Copy(sid, 0, IntPtr.Add(owner, IntPtr.Size), sid.Length);
    return owner;
}

// Sets the owner of the objects this process (and the processes it starts)
// creates; returns the previous TOKEN_OWNER, or IntPtr.Zero.
public static IntPtr SwapDefaultOwner(IntPtr owner) {
    IntPtr token, previous = Marshal.AllocHGlobal(256);
    int length;
    if (!OpenProcessToken(GetCurrentProcess(), 0x88, out token)) return IntPtr.Zero;
    bool ok = GetTokenInformation(token, 4, previous, 256, out length) && SetTokenInformation(token, 4, owner, IntPtr.Size);
    CloseHandle(token);
    return ok ? previous : IntPtr.Zero;
}
'@
}

function Update-UserPath([string]$Add = "", [string]$Remove = "") {
    # Edit HKCU\Environment directly: reading it unexpanded and writing it back
    # with its own kind keeps REG_EXPAND_SZ and %VAR% entries, which
    # [Environment]::SetEnvironmentVariable would flatten. Returns whether it changed.
    if ($NoPersistPath) { return $false }
    $key = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey("Environment")
    try {
        $kind = [Microsoft.Win32.RegistryValueKind]::ExpandString
        if ($key.GetValueNames() -contains "Path") { $kind = $key.GetValueKind("Path") }
        $raw = [string]$key.GetValue("Path", "", [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        $value = $raw
        if ($Remove) { $value = @($raw -split ";" | Where-Object { -not ($_ -and (Test-SamePath $_ $Remove)) }) -join ";" }
        if ($Add -and -not @($value -split ";" | Where-Object { $_ -and (Test-SamePath $_ $Add) }).Count) {
            $value = if ($value) { "$Add;$value" } else { $Add }
        }
        if ($value -ceq $raw) { return $false }
        $key.SetValue("Path", $value, $kind)
    } finally {
        $key.Close()
    }
    # Tell Explorer, so terminals opened from now on get the new PATH.
    Initialize-Native
    $result = [UIntPtr]::Zero
    [void][DefenseClawInstall.Native]::SendMessageTimeout([IntPtr]0xffff, 0x1a, [UIntPtr]::Zero, "Environment", 2, 5000, [ref]$result)
    return $true
}

function Wait-BeforeClose([int]$Code) {
    # `defenseclaw upgrade` and `rollback` run this installer in a console of
    # their own, which closes when it exits: keep the outcome on screen. With
    # -Yes nobody may be watching, so wait a bounded time instead of forever.
    if (-not $RunAsFile) { return }
    try {
        Initialize-Native
        # Windows PowerShell 5.1 has no [uint] accelerator, so a uint array threw here
        # and the catch below closed the window at once.
        if ([DefenseClawInstall.Native]::GetConsoleProcessList((New-Object "uint32[]" 4), 4) -ne 1) { return }
        if ($Run.Log) { Write-Host "  Install log: $($Run.Log)" }
        # A shell the user typed `& install.ps1` into is alone on its console as
        # well (Windows Terminal), but it stays open: only a process started for
        # this script (-File, or Explorer's "Run with PowerShell") closes with it.
        $scriptName = Split-Path -Leaf $PSCommandPath
        if ([Environment]::CommandLine.IndexOf($scriptName, [StringComparison]::OrdinalIgnoreCase) -lt 0) { return }
        if (-not $Yes) {
            [void](Read-Host "  Press Enter to close this window")
            return
        }
        $seconds = if ($Code -eq 0) { 15 } else { 120 }
        Write-Host "  This window closes in $seconds seconds (press any key to close it now)."
        $deadline = (Get-Date).AddSeconds($seconds)
        while ((Get-Date) -lt $deadline) {
            if ([Console]::KeyAvailable) { [void][Console]::ReadKey($true); break }
            Start-Sleep -Milliseconds 200
        }
    } catch { }
}

# -- Existing install ---------------------------------------------------------

function Get-InstalledVersion {
    # The gateway on PATH is the install that runs; a source install leaves an
    # older release venv behind, so its version is only the fallback (GAP-2454).
    $gateway = Join-Path $BinDir "defenseclaw-gateway.exe"
    # A later installer can put binaries beside a pending first-install
    # record. Never execute one of those unproven binaries for discovery.
    $unproven = $Run.ContainsKey("UnprovenReplacement") -and $Run.UnprovenReplacement
    if (-not $unproven -and (Test-Path -LiteralPath $gateway) -and (Get-NativeOutput $gateway @("--version")) -match '\d+\.\d+\.\d+') {
        return $Matches[0]
    }
    $info = Get-ChildItem -LiteralPath (Join-Path $Venv "Lib\site-packages") -Filter "defenseclaw-*.dist-info" `
        -Directory -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($info) { return $info.Name -replace '^defenseclaw-', '' -replace '\.dist-info$', '' }
    return ""
}

function Assert-NoActiveConnectorRecovery([string]$Operation, [string]$Root = $DataDir) {
    # Inspect names only: phase and GC records (including malformed names)
    # still need the current protocol. Archives and publication temps are not
    # active receipts; the permanent protocol lock is not a receipt either.
    try {
        $ancestor = New-Object IO.DirectoryInfo ([IO.Path]::GetFullPath($Root))
        while ($ancestor) {
            $directory = Get-Item -LiteralPath $ancestor.FullName -Force -ErrorAction Stop
            if (-not $directory.PSIsContainer -or ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                throw "not a regular directory: $($ancestor.FullName)"
            }
            $ancestor = $ancestor.Parent
        }
        $pending = @(Get-ChildItem -LiteralPath $Root -Force -ErrorAction Stop |
            Where-Object { $_.Name -like ".defenseclaw-cas-v2-*" })
    } catch {
        throw "${Operation} refused: cannot inspect connector recovery in $Root ($($_.Exception.Message))"
    }
    if ($pending.Count) {
        throw ("${Operation} refused: active connector recovery remains in $Root. " +
            "Resolve it with the current DefenseClaw version before retrying; do not remove or replay its receipts.")
    }
}

function Get-GatewayProcess {
    # gateway.pid is JSON ({"pid": N, "executable": ...}); accept a bare number too.
    $file = Join-Path $DataDir "gateway.pid"
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { return $null }
    $text = [IO.File]::ReadAllText($file)
    $record = $null
    try { $record = $text | ConvertFrom-Json } catch { }
    $id = Get-Field $record "pid"
    if (-not $id -and $text.Trim() -match '^\d+$') { $id = $text.Trim() }
    if (-not $id) { return $null }
    $process = Get-Process -Id ([int]$id) -ErrorAction SilentlyContinue
    # A stale file, or a pid Windows gave to another program: not running,
    # and never stopped or killed.
    if (-not $process -or $process.ProcessName -ne "defenseclaw-gateway") { return $null }
    $recorded = [string](Get-Field $record "executable")
    if ($recorded -and $process.Path -ne $recorded) { return $null }
    return $process
}

function Get-InstallGatewayState {
    # "running", "down" or "unknown": whether this install's gateway, or its
    # watchdog that can start it again, still runs. gateway.pid alone proves
    # nothing down: a gateway removes the file before it exits, and a failed
    # stop or recovery can leave one running with the file gone or unreadable.
    # So every process whose image is this install's gateway counts too (a
    # prefix: a binary renamed aside, .old-*, as well), and so does DefenseClaw
    # Setup's. A pid file or a process list that cannot be read, or a recorded
    # gateway whose image cannot be read, is "unknown": nothing proves it down.
    $images = @(Join-Path $BinDir "defenseclaw-gateway")
    $setupInstall = Get-Variable -Name Setup -ValueOnly -ErrorAction SilentlyContinue
    if ($setupInstall -and (Get-Field $setupInstall "Root")) { $images += Join-Path $setupInstall.Root "bin\defenseclaw-gateway" }
    try { if (Get-GatewayProcess) { return "running" } } catch { return "unknown" }
    try { if (@(Get-ProcessesUnder $images).Count) { return "running" } } catch { return "unknown" }
    $file = Join-Path $DataDir "gateway.pid"
    if (-not (Test-Path -LiteralPath $file)) { return "down" }
    try {
        $text = [IO.File]::ReadAllText($file).Trim()
        $record = $null
        try { $record = $text | ConvertFrom-Json } catch { }
        $id = Get-Field $record "pid"
        if (-not $id -and $text -match '^\d+$') { $id = $text }
        if (-not $id) { return "down" }
        $process = Get-Process -Id ([int]$id) -ErrorAction SilentlyContinue
        if ($process -and $process.ProcessName -eq "defenseclaw-gateway" -and -not $process.Path) { return "unknown" }
    } catch { return "unknown" }
    return "down"
}

function Stop-Gateway {
    # Stop the running gateway with its own (the old) binary; kill it as a last
    # resort. Wait for the process itself, not its pid file: a gateway removes
    # the file before it exits, and while it runs Windows will not let the
    # migration replace the config it holds open.
    $process = Get-GatewayProcess
    if (-not $process) { Stop-Watchdog; return $true }
    $image = $process.Path
    Invoke-Native $image @("stop") -Quiet | Out-Null
    if (-not $process.WaitForExit(15000)) {
        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        [void]$process.WaitForExit(15000)
    }
    # Its watchdog runs the same binary; nothing of this install may keep running.
    for ($waited = 0; $waited -lt 10; $waited++) {
        $left = @(Get-ProcessesUnder @($image) | Where-Object { $_.ExecutablePath -eq $image })
        if (-not $left.Count) { break }
        if ($waited -eq 5) { $left | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue } }
        Start-Sleep -Seconds 1
    }
    Stop-Watchdog
    return $process.HasExited -and -not (Get-GatewayProcess)
}

function Stop-UnprovenGateway {
    # A binary added after a first-install record has no recorded hash. Do
    # not run its `stop` command (or its watchdog's command): terminate every
    # process whose image is this install's gateway, then verify they left.
    # By prefix, as Get-InstallGatewayState counts them: a gateway or
    # watchdog run from a copy an earlier swap renamed aside (.old-*) keeps
    # the watchdog lock and can render hooks as well. Returns how many it
    # terminated.
    $prefix = Join-Path $BinDir "defenseclaw-gateway"
    $stopped = 0
    for ($attempt = 0; $attempt -lt 10; $attempt++) {
        $running = @(Get-ProcessesUnder @($prefix))
        if (-not $running.Count -and -not (Get-GatewayProcess)) { return $stopped }
        foreach ($row in $running) {
            $process = Get-Process -Id $row.ProcessId -ErrorAction SilentlyContinue
            if (-not $process) { continue }
            # A pid Windows gave to another program since the list was read.
            if (-not ([string]$process.Path).StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { continue }
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
            $stopped++
        }
        Start-Sleep -Seconds 1
    }
    throw "The unproven gateway or watchdog from $prefix* is still running; stop it, then run: $(Get-LifecycleNextStep -Accept)"
}

function Stop-Watchdog {
    # The watchdog outlives a gateway that crashed or was stopped. Left running
    # from the old binary (which the swap renames aside), it keeps its
    # ownership lock, and the new gateway's watchdog cannot start (GAP-1833).
    # The prefix also matches a binary an earlier run renamed aside.
    $image = Join-Path $BinDir "defenseclaw-gateway.exe"
    if (-not @(Get-ProcessesUnder @($image)).Count) { return }
    Write-Info "Stopping the watchdog"
    if (Test-Path -LiteralPath $image -PathType Leaf) { Invoke-Native $image @("watchdog", "stop") -Quiet | Out-Null }
    for ($waited = 0; $waited -lt 10; $waited++) {
        $left = @(Get-ProcessesUnder @($image))
        if (-not $left.Count) { return }
        if ($waited -eq 3) { $left | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue } }
        Start-Sleep -Seconds 1
    }
    Write-Warn "The previous watchdog is still running; stop it with: defenseclaw-gateway watchdog stop"
}

function Assert-GatewayQuiescent([string]$Operation) {
    $image = Join-Path $BinDir "defenseclaw-gateway.exe"
    if ((Get-GatewayProcess) -or @(Get-ProcessesUnder @($image)).Count) {
        throw "${Operation} refused: the current gateway or watchdog is still running; stop it before retrying"
    }
}

# A 1.0.0 gateway cannot start on a WAL-mode audit.db whose 5-second startup
# check times out (a large store): SQLite drops and recreates audit.db-wal,
# and 1.0.0 refuses the new file (fixed in 1.0.1). In rollback-journal mode
# it starts, and switches the database back to WAL itself (GAP-1988).
$AuditJournalPy = "import sqlite3,sys;c=sqlite3.connect(sys.argv[1],timeout=10);c.execute('pragma journal_mode').fetchone()[0]=='wal' and c.execute('pragma journal_mode=delete').fetchone();c.close()"

function Reset-AuditJournalMode {
    $db = Join-Path $DataDir "audit.db"
    $python = Join-Path $Venv "Scripts\python.exe"
    if ((Test-Path -LiteralPath $db -PathType Leaf) -and (Test-Path -LiteralPath $python -PathType Leaf)) {
        [void](Invoke-Native $python @("-c", $AuditJournalPy, $db) -Quiet)
    }
}

# GAP-1388: a 0.x release has no recovery for a damaged audit store, so its
# gateway does not start on one. Before a rollback to 0.x changes anything,
# Test-RollbackData runs SQLite's integrity check on each database the
# rollback restores, with the same code as install.sh (ROLLBACK_DB_CHECK_PY).
$RollbackDbCheckPy = @'
import os, shutil, sqlite3, sys, tempfile
from pathlib import Path


def damaged(path):
    logs = [suffix for suffix in ("-wal", "-journal") if os.path.exists(path + suffix)]
    with tempfile.TemporaryDirectory() as tmp:
        uri = Path(os.path.abspath(path)).as_uri() + "?immutable=1"
        if logs:
            copy = os.path.join(tmp, "check.db")
            for suffix in ["", *logs]:
                shutil.copyfile(path + suffix, copy + suffix)
            uri = Path(copy).as_uri()
        try:
            conn = sqlite3.connect(uri, uri=True)
            try:
                result = conn.execute("pragma integrity_check(1)").fetchone()[0]
            finally:
                conn.close()
        except sqlite3.DatabaseError as exc:
            result = str(exc)
            if "malformed" not in result and "not a database" not in result:
                return False
    if result != "ok":
        print(path + ": " + " ".join(result.split()), file=sys.stderr)
    return result != "ok"


for path in sys.argv[1:]:
    try:
        bad = os.path.isfile(path) and not os.path.islink(path) and damaged(path)
    except OSError:
        bad = False
    if bad:
        print(path)
'@

function Test-RollbackData([string]$BackTo) {
    # $true when the saved audit store is damaged; other damaged databases are only named.
    $python = Join-Path $Venv "Scripts\python.exe"
    $data = Join-Path $Previous "data"
    if (-not (Test-Path -LiteralPath $python -PathType Leaf)) { return $false }
    $stores = @(Get-ChildItem -LiteralPath $data -Filter "*.db" -File -Force -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
    if (-not $stores.Count) { return $false }
    $check = Join-Path ([IO.Path]::GetTempPath()) "defenseclaw-rollback-check-$PID.py"
    $ErrorActionPreference = "Continue"
    try {
        [IO.File]::WriteAllText($check, $RollbackDbCheckPy)
        $damaged = @(& $python -I $check @stores 2>$null | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    } catch {
        return $false
    } finally {
        Remove-Item -LiteralPath $check -Force -ErrorAction SilentlyContinue
    }
    $audit = Join-Path $data "audit.db"
    foreach ($store in $damaged) {
        if ($store -ne $audit) { Write-Warn "The saved database $store of DefenseClaw $BackTo failed SQLite's integrity check; $BackTo may not start with it" }
    }
    return $damaged -contains $audit
}

function Move-DamagedAuditStore([string]$BackTo) {
    # After the swap, move the damaged store aside under the name the 1.0
    # gateway and doctor use (audit.db.corrupt-<UTC time>), so the restored
    # release starts on a new one. Returns the archive's path.
    $db = Join-Path $DataDir "audit.db"
    if (-not (Test-Path -LiteralPath $db -PathType Leaf)) { return "" }
    $moved = "$db.corrupt-" + (Get-Date).ToUniversalTime().ToString("yyyyMMdd'T'HHmmss'Z'")
    if (Test-Path -LiteralPath $moved) { $moved += "-$PID" }
    Move-AuditStore $db $moved
    Write-Warn ("The saved $BackTo audit store failed SQLite's integrity check; it was kept as $moved and $BackTo starts on a new " +
        "audit store (its block/allow entries are not carried over; check them with defenseclaw mcp, skill, plugin and tool list)")
    return $moved
}

function Start-Gateway {
    # Its readiness wait is the health check. Exit code 3: running, but a
    # connector refused admission (upgrading again would not change that).
    Write-Info "Starting the gateway [$(Get-UtcClock)]"
    $gateway = Join-Path $BinDir "defenseclaw-gateway.exe"
    if (-not (Test-Path -LiteralPath $gateway -PathType Leaf)) {
        # A restored DefenseClaw Setup install has its gateway elsewhere (GAP-1839).
        Write-Warn "$gateway is missing, so the gateway was not started"
        return 1
    }
    $version = Get-InstalledVersion
    if ((Test-Version $version) -and [version]$version -lt [version]"1.0.1") { Reset-AuditJournalMode }
    $rc = Invoke-Native $gateway @("start")
    if ($rc -in @(0, 3) -or -not (Get-GatewayProcess)) { return $rc }
    # A first start over a large audit database can outlast start's own
    # 60-second readiness wait while the gateway keeps starting (GAP-1348).
    # Wall-clock wait; up once status answers twice in a row.
    Write-Info "The gateway is still starting (a large audit database takes a while); waiting up to 3 minutes"
    $deadline = (Get-Date).AddMinutes(3)
    $up = 0
    while ((Get-Date) -lt $deadline -and (Get-GatewayProcess)) {
        Start-Sleep -Seconds 3
        if ((Invoke-Native $gateway @("status") -Quiet) -eq 0) {
            $up++
            if ($up -ge 2) { Write-Ok "The gateway finished starting"; return 0 }
        } else {
            $up = 0
        }
    }
    return $rc
}

function Get-ProcessesUnder([string[]]$Prefixes) {
    # Win32_Process names every process's image, but WMI refuses a standard
    # user signed in over the network (an SSH session). Get-Process then still
    # reads the image of this account's own processes, the only ones that can
    # run from this install.
    # The refusal is expected: SilentlyContinue keeps it out of the run log,
    # where a caught -ErrorAction Stop error reads as a TerminatingError (GAP-1347).
    $cimError = $null
    try { $all = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue -ErrorVariable cimError) } catch { $cimError = $_; $all = @() }
    if ($cimError -or -not $all.Count) {
        $all = @(Get-Process | ForEach-Object {
            [pscustomobject]@{ ProcessId = $_.Id; Name = "$($_.ProcessName).exe"; ExecutablePath = $_.Path }
        })
    }
    return @($all | Where-Object {
        $image = $_.ExecutablePath
        $image -and @($Prefixes | Where-Object { $image.StartsWith($_, [StringComparison]::OrdinalIgnoreCase) }).Count
    })
}

function Stop-ProcessesUnder([string]$Root) {
    for ($attempt = 0; $attempt -lt 10; $attempt++) {
        $running = @(Get-ProcessesUnder @("$Root\"))
        if (-not $running.Count) { return }
        foreach ($process in $running) {
            if ($attempt -eq 0) { Write-Info "Stopping $($process.Name) (pid $($process.ProcessId))" }
            Stop-Process -Id $process.ProcessId -Force -ErrorAction SilentlyContinue
        }
        Start-Sleep -Seconds 1
    }
}

function Wait-VenvFree {
    # A program running from the venv (the TUI, or the CLI that started this
    # installer and is still exiting) keeps its files from being deleted, and
    # an open file keeps the venv from being moved. Wait for them, then give
    # up before anything has changed.
    if (-not (Test-Path -LiteralPath $Venv)) { return }
    for ($waited = 0; $waited -le 60; $waited++) {
        if (-not @(Get-ProcessesUnder @("$Venv\")).Count) {
            $moved = $true
            try { Move-Path $Venv "$Venv.busy" 0 } catch { $moved = $false }
            if ($moved) { Move-Path "$Venv.busy" $Venv 60; return }
        }
        if ($waited -eq 0) { Write-Info "Waiting for programs that use $Venv to exit" }
        Start-Sleep -Seconds 1
    }
    $users = @(Get-ProcessesUnder @("$Venv\", "$BinDir\defenseclaw") | Where-Object { $_.Name -ne "defenseclaw-gateway.exe" } |
        ForEach-Object { "$($_.Name) (pid $($_.ProcessId))" })
    $list = if ($users.Count) { $users -join ", " } else { "another program" }
    Die "DefenseClaw is in use by $list. Close it (for example the DefenseClaw TUI) and run the installer again; nothing was changed"
}

# -- DefenseClaw Setup (0.8.7-0.8.10) -----------------------------------------
# Setup refuses to run elevated, over SSH, or unattended, so the installer
# removes it itself. It shares the data dir, so config and audit data carry
# over; its files are kept in previous\legacy-setup (no automatic rollback).

function Find-SetupInstall {
    $roots = @($SetupRoot)
    $location = [string](Get-Field (Get-ItemProperty -LiteralPath $SetupUninstallKey -ErrorAction SilentlyContinue) "InstallLocation")
    if ($location) { $roots = @($location) + $roots }
    foreach ($root in $roots) {
        $state = Read-Json (Join-Path $root "installer\install-state.json")
        if ((Get-Field $state "install_kind") -ne "native-windows-exe" -or -not (Test-Version ([string](Get-Field $state "version")))) {
            continue
        }
        $dataRoot = [string](Get-Field $state "data_root")
        if ($dataRoot -and -not (Test-SamePath $dataRoot $DataDir)) {
            Write-Warn "DefenseClaw Setup at $root uses $dataRoot, not $DataDir; leaving it alone"
            return $null
        }
        return [pscustomobject]@{
            Root = $root.TrimEnd("\")
            Version = [string](Get-Field $state "version")
            CodexHome = [string](Get-Field $state "codex_home")
            ClaudeConfigDir = [string](Get-Field $state "claude_config_dir")
        }
    }
    return $null
}

function Disable-SetupHooks {
    # Setup's hook launcher runs Setup's hook and restarts Setup's gateway on
    # demand; without its state file it does nothing.
    if (Test-Path -LiteralPath $SetupHookState) { Move-Path $SetupHookState (Join-Path $Staging "hook-runtime-state.json") }
}

function Restore-SetupInstall([switch]$KeepStopped) {
    $state = Join-Path $Staging "hook-runtime-state.json"
    if (Test-Path -LiteralPath $state) { Move-Path $state $SetupHookState }
    if ($WasRunning -and -not $KeepStopped) { Start-SetupGateway $Setup.Root }
}

function Start-SetupGateway([string]$Root) {
    $startup = Join-Path $Root "bin\defenseclaw-startup.exe"
    if (Test-Path -LiteralPath $startup) {
        [void][Diagnostics.Process]::Start($startup).WaitForExit(120000)
    } else {
        Invoke-Native (Join-Path $Root "bin\defenseclaw-gateway.exe") @("start") -Quiet | Out-Null
    }
}

function Remove-SetupInstall {
    Write-Info "Removing DefenseClaw Setup $($Setup.Version); its files are kept in $Previous\legacy-setup"
    $keep = Join-Path $Previous "legacy-setup"
    New-Item -ItemType Directory -Path $keep -Force | Out-Null
    Invoke-Quietly {
        Stop-ProcessesUnder $Setup.Root
        Move-Path $Setup.Root (Join-Path $keep "DefenseClaw") 30
    }
    Invoke-Quietly {
        $state = Join-Path $Staging "hook-runtime-state.json"
        if (Test-Path -LiteralPath $state) { Move-Path $state (Join-Path $keep "hook-runtime-state.json") }
    }
    Invoke-Quietly {
        # Its logon autostart and its post-uninstall cleanup both start from its tree or its cache.
        $run = Get-Item -LiteralPath $RunKey
        foreach ($name in $run.GetValueNames()) {
            $command = [Environment]::ExpandEnvironmentVariables(
                [string]$run.GetValue($name, "", [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames))
            if ($command.IndexOf("$($Setup.Root)\", [StringComparison]::OrdinalIgnoreCase) -ge 0 -or
                $command.IndexOf("$SetupCache\", [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                Remove-ItemProperty -LiteralPath $RunKey -Name $name
            }
        }
    }
    Invoke-Quietly {
        $location = [string](Get-Field (Get-ItemProperty -LiteralPath $SetupUninstallKey -ErrorAction SilentlyContinue) "InstallLocation")
        if ($location -and (Test-SamePath $location $Setup.Root)) { Remove-Item -LiteralPath $SetupUninstallKey -Recurse -Force }
    }
    Invoke-Quietly { Remove-Tree $SetupCache }
    foreach ($setting in @(@("CODEX_HOME", "Codex", ".codex", $Setup.CodexHome),
            @("CLAUDE_CONFIG_DIR", "Claude Code", ".claude", $Setup.ClaudeConfigDir))) {
        $name, $agent, $folder, $value = $setting
        # The agent's default folder needs no variable, and neither does a
        # value the account already has.
        if (-not $value -or (Test-SamePath $value (Join-Path $env:USERPROFILE $folder)) -or
            (Test-SamePath ([string][Environment]::GetEnvironmentVariable($name, "User")) $value)) { continue }
        Write-Warn "DefenseClaw guards $agent in $value, but only DefenseClaw Setup had $name set to it"
        Write-Host "  Set it for your account so $agent keeps using that folder, then open a new terminal:"
        Write-Host "    [Environment]::SetEnvironmentVariable('$name', '$value', 'User')" -ForegroundColor Cyan
    }
}

# True when the config sets guardrail.enabled to false, as 'uninstall' and
# 'setup guardrail --disable' write it (a direct child of the top-level block).
function Test-GuardrailOff {
    $path = if ($env:DEFENSECLAW_CONFIG) { $env:DEFENSECLAW_CONFIG } else { Join-Path $DataDir "config.yaml" }
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $false }
    $block = $false
    $indent = 0
    foreach ($line in [IO.File]::ReadAllLines($path)) {
        if ($line -match '^guardrail:\s*$') { $block = $true; $indent = 0; continue }
        if (-not $block) { continue }
        if ($line -match '^[^\s#]') { $block = $false; continue }
        if ($line -notmatch '^([ \t]+)[^\s#]') { continue }
        if (-not $indent) { $indent = $Matches[1].Length }
        if ($Matches[1].Length -eq $indent -and $line -match '^\s+enabled:\s*false\s*(#.*)?$') { return $true }
    }
    return $false
}

function Test-FleetEnabled {
    $path = if ($env:DEFENSECLAW_CONFIG) { $env:DEFENSECLAW_CONFIG } else { Join-Path $DataDir "config.yaml" }
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $false }
    $python = Join-Path $Venv "Scripts\python.exe"
    $code = 'import sys,yaml; c=yaml.safe_load(open(sys.argv[1],encoding=''utf-8'')); sys.exit(0 if isinstance(c,dict) and isinstance(c.get(''fleet''),dict) and c[''fleet''].get(''enabled'') is True else 1)'
    return ((Invoke-Native $python @("-I", "-c", $code, $path) -Quiet) -eq 0)
}

function Get-ConfiguredConnectors {
    # The connectors the config names (active_connector.json).
    $state = Read-Json (Join-Path $DataDir "active_connector.json")
    return @(@(Get-Field $state "names") + @(Get-Field $state "name") | Where-Object { $_ -and $_ -ne "none" } | ForEach-Object { [string]$_ })
}

function Get-EffectiveConfigConnectors {
    # Older gateways may not have status --json. In that case the installed
    # connector roster must come from the effective config, including an
    # external DEFENSECLAW_CONFIG, before this run records its rollback point.
    # Every release defaults guardrail.enabled to false and a disabled
    # guardrail tears every connector down, so such a config guards none.
    # Get-HeldConnectors still keeps any connector the running gateway reports.
    $path = if ($env:DEFENSECLAW_CONFIG) { $env:DEFENSECLAW_CONFIG } else { Join-Path $DataDir "config.yaml" }
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return @() }
    $python = Join-Path $Staging "venv\Scripts\python.exe"
    if (-not (Test-Path -LiteralPath $python -PathType Leaf)) { $python = Join-Path $Venv "Scripts\python.exe" }
    if (-not (Test-Path -LiteralPath $python -PathType Leaf)) { throw "Cannot read the effective config's connectors without a checked Python environment: $path" }
    # Windows PowerShell 5.1 strips embedded double quotes from native argv.
    # Keep Python's string literals single-quoted so -c receives valid code.
    $code = 'import json,sys,yaml; from defenseclaw.connector_paths import normalize; c=yaml.safe_load(open(sys.argv[1],encoding=''utf-8'')); c=c if isinstance(c,dict) else {}; g=c.get(''guardrail'') or {}; g=g if isinstance(g,dict) else {}; m=g.get(''connectors'') or {}; claw=c.get(''claw'') or {}; claw=claw if isinstance(claw,dict) else {}; names=[n for n,v in m.items() if isinstance(n,str) and n.strip() and not (isinstance(v,dict) and v.get(''enabled'') is False)] if isinstance(m,dict) and m else [g.get(''connector'') or claw.get(''mode'')]; names=names if str(g.get(''enabled'')).strip().lower() in (''1'',''t'',''true'') else []; print(json.dumps(sorted({normalize(n) for n in names if isinstance(n,str) and n.strip()})))'
    $probe = Get-NativeProbe $python @("-I", "-c", $code, $path)
    if ($probe.Exit -ne 0) { throw "Cannot read the effective config's connectors: $path" }
    try {
        $decoded = $probe.Output | ConvertFrom-Json -ErrorAction Stop
        # Windows PowerShell 5.1 emits a JSON array as one object. Enumerate
        # it explicitly or the caller sees one "System.Object[]" connector.
        return @($decoded | ForEach-Object { [string]$_ })
    } catch { throw "Cannot parse the effective config's connector roster: $path" }
}

function Test-ConnectorConfigured {
    return @(Get-ConfiguredConnectors).Count -gt 0
}

# -- Snapshot, swap, restore --------------------------------------------------

function Get-DataEntries {
    return @(Get-ChildItem -LiteralPath $DataDir -Force | Where-Object {
        $name = $_.Name
        -not @($NotData | Where-Object { $name -like $_ }).Count
    })
}

# What an install writes besides the rollback copy of the data folder: the
# staged release with its check environment, the final environment, and the
# uv cache and Python they come from (about 1.4 GB on a first install).
$InstallRoom = 1500MB
# The final environment alone, built after the release is staged.
$FinalEnvRoom = 600MB

function Get-DataSize {
    $size = [long]0
    if (-not (Test-Path -LiteralPath $DataDir -PathType Container)) { return $size }
    foreach ($entry in Get-DataEntries) { $size += Get-TreeSize $entry.FullName }
    return $size
}

function Assert-InstallRoom([long]$Extra, [string]$ForWhat) {
    # Checked before the step that needs the room, while nothing has changed
    # and the gateway still runs (GAP-1839, GAP-1841). Save-Snapshot checks
    # the rollback copy once more.
    $free = [long]-1
    try { $free = ([IO.DriveInfo][IO.Path]::GetPathRoot([IO.Path]::GetFullPath($DataDir))).AvailableFreeSpace } catch { }
    if ($free -lt 0) { return }
    $data = Get-DataSize
    if ($free -ge $data + $Extra + 100MB) { return }
    if (-not $PrevVersion) { Write-KeptUvCache }
    Die ("Not enough free disk space next to ${DataDir}: the install needs about {0:N0} MB ({1:N0} MB for a rollback copy of the data folder and {2:N0} MB for $ForWhat), and {3:N0} MB is free. Free up space, then run the installer again; nothing was changed" -f
        ([double]($data + $Extra + 100MB) / 1MB), ([double]$data / 1MB), ([double]$Extra / 1MB), ([double]$free / 1MB))
}

function Write-KeptUvCache {
    # A failed first install keeps only uv's download cache: say how large it
    # is and how to remove it (GAP-1883). Get-TreeSize, not Measure-Object:
    # under StrictMode an empty or missing cache has no .Sum (GAP-2616).
    $uvDir = Join-Path $DataDir ".uv"
    $bytes = Get-TreeSize $uvDir
    if ($bytes) {
        Write-Info ("The download cache in $uvDir ({0:N0} MB) was kept so the next run is faster; remove it with: cmd /c rd /s /q `"$uvDir`"" -f ([double]$bytes / 1MB))
    }
}

function Test-DiskFull {
    $free = [long]-1
    try { $root = [IO.Path]::GetPathRoot([IO.Path]::GetFullPath($DataDir)); $free = ([IO.DriveInfo]$root).AvailableFreeSpace } catch { }
    if ($free -lt 0 -or $free -ge 300MB) { return $false }
    Write-Err ("The disk $root is full ({0:N0} MB free). Free at least {1:N0} MB on it, then run the installer again" -f
        ([double]$free / 1MB), ([double]((Get-DataSize) + $InstallRoom + 100MB) / 1MB))
    return $true
}

function Clear-StagedRelease {
    # The staged release (about 900 MB) is not needed once the install stops
    # or is undone, and on a full disk the restore and the old gateway need
    # its room (GAP-1839, GAP-1841). DefenseClaw Setup's hook state parked
    # there stays until it is put back.
    foreach ($item in @(Get-ChildItem -LiteralPath $Staging -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne "hook-runtime-state.json" })) {
        Invoke-Quietly { Remove-Tree $item.FullName }
    }
    if ((Test-Path -LiteralPath $Staging) -and -not @(Get-ChildItem -LiteralPath $Staging -Force -ErrorAction SilentlyContinue).Count) {
        Invoke-Quietly { Remove-Tree $Staging }
    }
}

function Get-TreeSize([string]$Path) {
    $size = [long]0
    foreach ($file in @(Get-ChildItem -LiteralPath $Path -Recurse -Force -File -ErrorAction SilentlyContinue)) { $size += $file.Length }
    return $size
}

function Remove-Aside([string]$Path) {
    # A running .exe cannot be replaced or deleted, but it can be renamed.
    $aside = "$Path.old-" + (Get-Date -Format "yyyyMMddTHHmmssfff")
    Move-Path $Path $aside
    Remove-Item -LiteralPath $aside -Force -ErrorAction SilentlyContinue
}

function Remove-DeveloperFiles {
    # The source ownership marker proves the files came from `make all`.
    if (-not (Test-Path -LiteralPath (Join-Path $BinDir ".defenseclaw-source-root") -PathType Leaf)) { return }
    $removed = @()
    foreach ($name in $DeveloperFiles) {
        $path = Join-Path $BinDir $name
        if (Test-Path -LiteralPath $path -PathType Leaf) { Remove-Aside $path; $removed += $name }
    }
    if ($removed) { Write-Info "Removed the developer install ('make all') files from ${BinDir}: $($removed -join ', ')" }
}

function Install-File([string]$Source, [string]$Destination) {
    if ((Test-Path -LiteralPath $Destination) -and (Get-Sha256 $Source) -eq (Get-Sha256 $Destination)) { return }
    # The new file is written beside the installed one and must be a whole
    # copy before anything is switched: the installed file stays until then.
    Copy-Item -LiteralPath $Source -Destination "$Destination.new" -Force
    if ((Get-Sha256 "$Destination.new") -ne (Get-Sha256 $Source)) {
        Remove-Item -LiteralPath "$Destination.new" -Force -ErrorAction SilentlyContinue
        throw "The copy of $Source beside $Destination is not whole; $Destination was left as it was"
    }
    Publish-File "$Destination.new" $Destination
}

function Publish-File([string]$New, [string]$Destination) {
    # Put $New at $Destination. An installed file (a binary, a shim, the hook
    # state the native hook reads) is swapped in place, so the path a hook or
    # a shim names is never missing; only a first install or a directory in
    # the way takes the rename.
    if (Test-Path -LiteralPath $Destination -PathType Leaf) { Switch-InPlace $New $Destination; return }
    if (Test-Path -LiteralPath $Destination) { Remove-Aside $Destination }
    Move-Path $New $Destination
}

function Invoke-AtomicReplace([string]$New, [string]$Destination) {
    # FileRenameInfoEx atomically replaces a name when existing open handles
    # permit it. A mapped executable image can still refuse the replacement;
    # Switch-InPlace retries for a short idle window (GAP-0732).
    if (-not ("DefenseClawInstall.Rename" -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace DefenseClawInstall {
    public static class Rename {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFileW(string name, uint access, uint share,
            IntPtr security, uint creation, uint flags, IntPtr templateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetFileInformationByHandle(SafeFileHandle file, int infoClass,
            IntPtr info, uint length);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool MoveFileExW(string oldName, string newName, int flags);

        public static void Replace(string source, string destination) {
            // DELETE is the access needed to rename the staged source. Share
            // read, write and delete so readers cannot strand this handle.
            using (SafeFileHandle file = CreateFileW(source, 0x10000, 7, IntPtr.Zero, 3, 0x80, IntPtr.Zero)) {
                if (file.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
                byte[] name = Encoding.Unicode.GetBytes(Path.GetFullPath(destination));
                int rootOffset = IntPtr.Size == 8 ? 8 : 4;
                int lengthOffset = IntPtr.Size == 8 ? 16 : 8;
                int nameOffset = IntPtr.Size == 8 ? 20 : 12;
                IntPtr info = Marshal.AllocHGlobal(nameOffset + name.Length + 2);
                try {
                    // FILE_RENAME_FLAG_REPLACE_IF_EXISTS |
                    // FILE_RENAME_FLAG_POSIX_SEMANTICS, FileRenameInfoEx = 22.
                    Marshal.WriteInt32(info, 3);
                    Marshal.WriteIntPtr(info, rootOffset, IntPtr.Zero);
                    Marshal.WriteInt32(info, lengthOffset, name.Length);
                    Marshal.Copy(name, 0, IntPtr.Add(info, nameOffset), name.Length);
                    Marshal.WriteInt16(info, nameOffset + name.Length, 0);
                    if (SetFileInformationByHandle(file, 22, info, (uint)(nameOffset + name.Length + 2))) return;
                    int error = Marshal.GetLastWin32Error();
                    // Older Windows/filesystems do not support FileRenameInfoEx.
                    // Keep the original atomic rename for those hosts.
                    if ((error == 1 || error == 87) && MoveFileExW(source, destination, 0x9)) return;
                    if (error == 1 || error == 87) error = Marshal.GetLastWin32Error();
                    throw new Win32Exception(error);
                } finally {
                    Marshal.FreeHGlobal(info);
                }
            }
        }
    }
    }
'@
    }
    [DefenseClawInstall.Rename]::Replace($New, $Destination)
}

function Switch-InPlace([string]$New, [string]$Destination, [int]$Seconds = 10) {
    # Only one atomic rename publishes an installed file. ReplaceFile opens
    # the old launcher for replacement and can deny a concurrent hook's
    # execution with a sharing violation (GAP-0352); its partial-failure
    # recovery also cannot prove uninterrupted availability. A running hook
    # or scanner may refuse the rename. Windows will also refuse replacing a
    # mapped executable image, even with POSIX rename semantics. Registered
    # calls arriving once a second can phase-lock a 500 ms retry to the busy
    # part of every call. Probe each 25 ms gap while the whole old launcher
    # remains callable, then refuse without changing it if no gap appears.
    for ($attempt = 0; ; $attempt++) {
        try {
            Invoke-AtomicReplace $New $Destination
            return
        } catch {
            $reason = $_.Exception.Message
        }
        if (-not (Test-Path -LiteralPath $New) -or $attempt -ge 40 * $Seconds) {
            Remove-Item -LiteralPath $New -Force -ErrorAction SilentlyContinue
            throw "Could not replace $Destination in place ($reason); it was left as it was. Retry the same install command after the running hook finishes"
        }
        Start-Sleep -Milliseconds 25
    }
}

function Write-PosixShim([string]$Target) {
    # `defenseclaw uninstall` recognizes this launcher by its exec line.
    $path = Join-Path $BinDir $PosixShim
    $text = "#!/bin/sh`n# Git Bash runs this; cmd.exe and PowerShell run defenseclaw.exe.`nexec `"$($Target -replace '\\', '/')`" `"`$@`"`n"
    if ((Test-Path -LiteralPath $path) -and [IO.File]::ReadAllText($path) -ceq $text) { return }
    [IO.File]::WriteAllText("$path.new", $text, (New-Object Text.UTF8Encoding $false))
    Publish-File "$path.new" $path
}

function Write-Shim([string]$Name, [string]$Target) {
    # `defenseclaw uninstall` recognizes the CLI shim by this exact command line.
    $path = Join-Path $BinDir "$Name.cmd"
    $text = "@echo off`r`n`"$Target`" %*`r`n"
    # cmd.exe reads batch files in the OEM code page.
    $encoding = [Text.Encoding]::GetEncoding([Globalization.CultureInfo]::CurrentCulture.TextInfo.OEMCodePage)
    if ((Test-Path -LiteralPath $path) -and [IO.File]::ReadAllText($path, $encoding) -ceq $text) { return }
    [IO.File]::WriteAllText("$path.new", $text, $encoding)
    Publish-File "$path.new" $path
}

function Write-HookState {
    $root = [IO.Path]::GetFullPath($BinDir).TrimEnd('\')
    $state = [ordered]@{
        schema_version = 1; install_kind = "powershell-windows"; install_scope = "user"
        install_root = $root; command_dir = $root; data_root = [IO.Path]::GetFullPath($DataDir).TrimEnd('\')
    }
    $path = Join-Path $BinDir $HookState
    $text = ($state | ConvertTo-Json -Compress) + "`n"
    if ((Test-Path -LiteralPath $path) -and [IO.File]::ReadAllText($path) -ceq $text) { return }
    [IO.File]::WriteAllText("$path.new", $text, (New-Object Text.UTF8Encoding $false))
    Publish-File "$path.new" $path
}

function Copy-BinDir([string]$To) {
    New-Item -ItemType Directory -Path $To -Force | Out-Null
    # Remember that there was no bin folder (a first install, DefenseClaw
    # Setup), and whether ~\.local was missing too, so a restore does not
    # leave either behind empty (GAP-2614).
    if (-not (Test-Path -LiteralPath $BinDir -PathType Container)) {
        $made = @($BinDir)
        $parent = Split-Path -Parent $BinDir
        if (-not (Test-Path -LiteralPath $parent -PathType Container)) { $made += $parent }
        Set-Content -LiteralPath (Join-Path $To "NO_BINDIR") -Value $made -Encoding UTF8
        return
    }
    foreach ($name in $ManagedFiles) {
        $live = Join-Path $BinDir $name
        if (Test-Path -LiteralPath $live -PathType Leaf) { Copy-Item -LiteralPath $live -Destination (Join-Path $To $name) }
    }
}

function Restore-BinDir([string]$From) {
    $marker = Join-Path $From "NO_BINDIR"
    if (Test-Path -LiteralPath $marker) {
        # There was no bin folder: take out this run's files, and the .new
        # copies a run killed mid-copy leaves (GAP-2618), then the folders it
        # made (bin first, then ~\.local) when they are empty.
        foreach ($name in $ManagedFiles) {
            foreach ($live in @((Join-Path $BinDir $name), (Join-Path $BinDir "$name.new"))) {
                if (Test-Path -LiteralPath $live) { Remove-Aside $live }
            }
        }
        $made = @(Get-Content -LiteralPath $marker | Where-Object { $_ })
        if (-not $made.Count) { $made = @($BinDir) }
        foreach ($dir in $made) {
            if ((Test-Path -LiteralPath $dir -PathType Container) -and
                -not (Get-ChildItem -LiteralPath $dir -Force -ErrorAction SilentlyContinue | Select-Object -First 1)) {
                Remove-Item -LiteralPath $dir -Force -ErrorAction SilentlyContinue
            }
        }
        Assert-BinDirRestored $From
        return
    }
    New-Item -ItemType Directory -Path $BinDir -Force | Out-Null
    # A hook still running refuses its in-place switch (Switch-InPlace): put
    # back every file that can be, then stop on the rest, so the caller keeps
    # the copy in $From and the run can be repeated. The gateway goes back
    # last, and only once every other program is back: until then the one in
    # place stays, so a refused restore keeps the gateway that can close the
    # hooks while the install is unfinished (Close-UnfinishedInstallHooks).
    $gatewayName = "defenseclaw-gateway.exe"
    $order = @($ManagedFiles | Where-Object { $_ -ne $gatewayName })
    if ($ManagedFiles -contains $gatewayName) { $order += $gatewayName }
    $refused = @()
    foreach ($name in $order) {
        if ($name -eq $gatewayName -and $refused.Count) { continue }
        $saved = Join-Path $From $name
        $live = Join-Path $BinDir $name
        try {
            if (Test-Path -LiteralPath $saved -PathType Leaf) { Install-File $saved $live }
            elseif (Test-Path -LiteralPath $live) { Remove-Aside $live }
        } catch { $refused += $_.Exception.Message }
    }
    if ($refused.Count) { throw "Could not put back every program in ${BinDir}: $($refused -join '; ')" }
    Assert-BinDirRestored $From
}

function Assert-BinDirRestored([string]$From) {
    # A restore is claimed only when $BinDir holds exactly the files saved in
    # $From, byte for byte: a hook or gateway of the failed install left
    # beside the previous data is not the previous install.
    $wrong = @()
    $noBinDir = Test-Path -LiteralPath (Join-Path $From "NO_BINDIR")
    foreach ($name in $ManagedFiles) {
        $saved = Join-Path $From $name
        $live = Join-Path $BinDir $name
        if (-not $noBinDir -and (Test-Path -LiteralPath $saved -PathType Leaf)) {
            if (-not (Test-Path -LiteralPath $live -PathType Leaf) -or (Get-Sha256 $live) -ne (Get-Sha256 $saved)) { $wrong += $name }
        } elseif (Test-Path -LiteralPath $live) {
            $wrong += $name
        }
    }
    if ($wrong.Count) { throw "$BinDir does not hold the saved copy of $($wrong -join ', ')" }
}

# $Where names the environment in the progress lines: the installer builds
# a staging one to check the release, then the final one (GAP-1727).
function New-Venv([string]$Path, [string]$Where) {
    $python = Join-Path $Path "Scripts\python.exe"
    New-InstallDirectory $Path
    if ((Invoke-Native $Uv @("venv", $Path, "--quiet", "--python", "3.12") -Quiet) -ne 0) {
        New-InstallDirectory $Path
        if ((Invoke-Native $Uv @("venv", $Path, "--quiet", "--python", ">=3.11,<3.14")) -ne 0) { return $false }
    }
    # The requirements file is the complete hashed lock, so nothing resolves.
    # Compile the bytecode now: uv skips it by default, and the first start of
    # the CLI and the scanners would otherwise compile thousands of modules
    # (over a minute on a Windows host while the files are also first scanned).
    $lockArgs = @("pip", "install", "--quiet", "--compile-bytecode", "--python", $python, "--require-hashes", "--no-deps",
        "-r", (Join-Path $Staging $Requirements))
    Write-Info "Installing the Python packages into $Where"
    if (-not (Invoke-UvPipInstall $lockArgs)) { return $false }
    Write-Info "Installing the DefenseClaw package into $Where and compiling it"
    return (Invoke-UvPipInstall @("pip", "install", "--quiet", "--compile-bytecode", "--python", $python, "--no-deps", (Join-Path $Staging $Wheel)))
}

function Invoke-UvPipInstall([string[]]$UvArgs) {
    if ((Invoke-Native $Uv $UvArgs) -eq 0) { return $true }
    # A scanner holding a file uv just wrote fails its cache rename with
    # os error 32 or 5 (GAP-1315). On a busy host that hits the next package
    # too (GAP-1941), so back off a few times; what reached the cache stays
    # there, so each attempt gets further.
    $waits = @(5, 15, 30)
    for ($i = 0; $i -lt $waits.Count; $i++) {
        # A disk that filled up is not a busy host, and a retry cannot help (GAP-1883).
        if (Test-DiskFull) { return $false }
        Write-Warn ("Retrying the Python package install in {0} s (attempt {1} of {2}; a busy host can hold uv's cache files)" -f $waits[$i], ($i + 2), ($waits.Count + 1))
        Start-Sleep -Seconds $waits[$i]
        if ((Invoke-Native $Uv $UvArgs) -eq 0) { return $true }
    }
    Write-Warn "uv kept failing; if it reported a file in use or access denied (os error 32 or 5), another program held the file: run the same command again"
    return $false
}

# Lifecycle transaction (fix/r104-windows)
# Every step that changes an install (upgrade, repair, rollback, and the
# restore of an interrupted one) is one transaction:
#   1. Before acting, Write-LifecycleManifest records the working state it
#      starts from (the managed binaries' SHA-256, the hook outage modes, the
#      config bytes, the bin folder's ACL, whether the gateway ran and which
#      connectors it guarded) in .lifecycle-txn.json, flushed to the disk.
#   2. The step runs.
#   3. Test-LifecycleProof proves the result from the live install: the
#      gateway runs from this install with the expected bytes and answers its
#      health check, every connector it guarded before is guarded again, the
#      gateway reports the policy digest of the live config, and the bin
#      folder is protected.
#   4. Only then the step reports success (Complete-LifecycleManifest, then
#      Remove-LifecycleManifest).
#   5. On a failure or an interruption the previous install is restored and
#      proven against the manifest (Assert-LifecycleRestored), its gateway
#      started. The manifest stays until that proof passes; until then the
#      install stays locked and its hooks closed, and the run exits non-zero
#      with the next step.
$LifecycleManifest = Join-Path $DataDir ".lifecycle-txn.json"
# A copy of the checked staged gateway, kept while the record is: once a
# restore has consumed the snapshot (and its closer\), it is the gateway that
# can close every hook, also over an older release's hooks.
$LifecycleCloser = Join-Path $DataDir ".lifecycle-closer"

function Write-DurableText([string]$Path, [string]$Text) {
    # A crash leaves the old file or the whole new one: the bytes are flushed
    # to the disk (FlushFileBuffers) before one rename publishes them.
    $tmp = "$Path.new"
    $bytes = (New-Object Text.UTF8Encoding $false).GetBytes($Text)
    $stream = New-Object IO.FileStream($tmp, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
    if (Test-Path -LiteralPath $Path) { [IO.File]::Replace($tmp, $Path, [NullString]::Value) }
    else { [IO.File]::Move($tmp, $Path) }
}

function ConvertTo-Map($Value) {
    # A JSON object read back (PSCustomObject) or a hashtable, as a hashtable.
    $map = [ordered]@{}
    if ($null -eq $Value) { return $map }
    if ($Value -is [Collections.IDictionary]) { foreach ($key in $Value.Keys) { $map[[string]$key] = [string]$Value[$key] }; return $map }
    foreach ($property in $Value.PSObject.Properties) { $map[$property.Name] = [string]$property.Value }
    return $map
}

function Get-BinariesState([string]$Dir) {
    # SHA-256 of each managed binary in $Dir.
    $bins = [ordered]@{}
    foreach ($name in $ManagedBinaries) {
        $path = Join-Path $Dir $name
        if (Test-Path -LiteralPath $path -PathType Leaf) { $bins[$name] = Get-Sha256 $path }
    }
    return $bins
}

function Get-OptionalSha256([string]$Path) {
    if ($Path -and (Test-Path -LiteralPath $Path -PathType Leaf)) { return Get-Sha256 $Path }
    return ""
}

function Get-GatewayHealthReport([string]$Gateway) {
    # status --json of $Gateway, or $null when it does not answer with JSON
    # (a release without --json, or no gateway).
    if (-not (Test-Path -LiteralPath $Gateway -PathType Leaf)) { return $null }
    $probe = Get-NativeProbe $Gateway @("status", "--json")
    if (-not $probe.Output) { return $null }
    try { return ($probe.Output | ConvertFrom-Json -ErrorAction Stop) } catch { return $null }
}

function Get-GuardedConnectors($Report) {
    # The connectors the gateway's health reports running.
    $names = @()
    foreach ($entry in @(Get-Field (Get-Field $Report "health") "connectors")) {
        if ($entry -and [string](Get-Field $entry "state") -eq "running") { $names += [string](Get-Field $entry "name") }
    }
    return $names
}

function Get-HeldConnectors($Report) {
    # The connectors a lifecycle proof holds a gateway to, from its status
    # --json ($Report, $null when it gave none): every connector it reports
    # running, and every connector the effective config enables unless an
    # answering gateway explicitly reports that one unhealthy. An older
    # gateway's JSON can be absent or omit an enabled connector, so neither
    # silence nor an empty roster drops one. A connector that already needed
    # attention was not guarded before the change, and requiring it would
    # make upgrade and rollback impossible; one still starting is held. The
    # effective config is authoritative over a stale active_connector.json,
    # including with an external DEFENSECLAW_CONFIG. Every lifecycle record
    # (Get-LifecycleState, Save-AcceptedConnectors) takes its roster here.
    $reported = @(); $unhealthy = @()
    if ($Report) {
        $reported = @(Get-GuardedConnectors $Report)
        if (Get-Field $Report "running") {
            $unhealthy = @(@(Get-Field (Get-Field $Report "health") "connectors") |
                Where-Object { $_ -and @("running", "starting") -notcontains [string](Get-Field $_ "state") } |
                ForEach-Object { [string](Get-Field $_ "name") })
        }
    }
    $enabled = @(Get-EffectiveConfigConnectors)
    return @(@($reported) + @($enabled | Where-Object { $unhealthy -notcontains $_ }) |
        Where-Object { $_ -and $_ -ne "none" } | ForEach-Object { [string]$_ } | Sort-Object -Unique)
}

function Get-GatewayDigestProblem([string]$Gateway) {
    # "" when the running gateway reports the effective policy digest of the
    # live config (policy digest --json --check-gateway: the digest is read
    # back from the live config and the gateway, never from matching bytes),
    # "unsupported" when this gateway cannot say, else what is wrong.
    $help = Get-NativeProbe $Gateway @("policy", "digest", "--help")
    if ($help.Exit -ne 0 -or $help.Output -notmatch "check-gateway") { return "unsupported" }
    $probe = Get-NativeProbe $Gateway @("policy", "digest", "--json", "--check-gateway")
    $report = $null
    try { $report = $probe.Output | ConvertFrom-Json -ErrorAction Stop } catch { }
    if (-not $report) { return "the policy digest of the live config could not be read (exit $($probe.Exit))" }
    $reloadError = [string](Get-Field $report "gateway_last_reload_error")
    if ($reloadError) { return "the gateway rejected the live config and keeps its previous policy: $reloadError" }
    $live = [string](Get-Field $report "effective_digest")
    $reported = [string](Get-Field $report "gateway_reported_digest")
    if (-not $reported) { return "unsupported" }
    if ($probe.Exit -ne 0 -or -not $live -or $live -ne $reported) {
        return "the gateway does not enforce the live config (its policy digest $reported, the live config's $live)"
    }
    return ""
}

function Get-BinDirOpenRules {
    # Allow entries that give an account other than this one, LocalSystem,
    # CREATOR OWNER or Administrators (matched by SID) a write right the
    # CLI's custody check counts (GENERIC_ALL/WRITE included).
    $user = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $trusted = @($user.Value, "S-1-5-18", "S-1-3-4", "S-1-5-32-544")
    $write = 0x500D0156
    $acl = Get-Acl -LiteralPath $BinDir
    return @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | Where-Object {
        $_.AccessControlType -eq "Allow" -and ([int]$_.FileSystemRights -band $write) -and $trusted -notcontains $_.IdentityReference.Value
    })
}

function Test-BinDirProtected {
    if (-not (Test-Path -LiteralPath $BinDir -PathType Container)) { return $false }
    try { return -not @(Get-BinDirOpenRules).Count } catch { return $false }
}

function Get-LifecycleState {
    $gateway = Join-Path $BinDir "defenseclaw-gateway.exe"
    $running = [bool](Get-GatewayProcess)
    $connectors = @()
    if ($running) { $connectors = @(Get-HeldConnectors (Get-GatewayHealthReport $gateway)) }
    $external = Get-ExternalConfig
    return [ordered]@{
        Bins = Get-BinariesState $BinDir
        GatewayWasRunning = $running
        Connectors = $connectors
        Config = Get-OptionalSha256 (Join-Path $DataDir "config.yaml")
        ExternalConfig = $external
        ExternalConfigSha256 = Get-OptionalSha256 $external
        HookFailModes = Get-OptionalSha256 (Join-Path $DataDir "hooks\.hookcfg")
        BinDirProtected = Test-BinDirProtected
    }
}

function Test-SameBinaries($Live, $Expected) {
    $live = ConvertTo-Map $Live
    $expected = ConvertTo-Map $Expected
    if ($live.Count -ne $expected.Count) { return $false }
    foreach ($name in $expected.Keys) { if (-not $live.Contains($name) -or $live[$name] -ne $expected[$name]) { return $false } }
    return $true
}

function Write-LifecycleManifest([string]$Operation, [string]$From, [string]$To, [string]$Slot, [hashtable]$Extra = @{}) {
    # Step 1: the working state this step starts from, durable before
    # anything changes. A manifest an earlier run left is still being
    # restored: Resume-InterruptedRun finished it before this run got here.
    $unproven = $Run.ContainsKey("UnprovenReplacement") -and $Run.UnprovenReplacement
    if ($unproven) {
        # -AcceptCurrentInstall accepted the programs an older installer
        # added over an empty first-install record (Resume-InterruptedRun
        # hashed them). They are this step's rollback preimage: those hashes,
        # whether their gateway ran, and the live config. A failed or
        # interrupted step restores them, starts their gateway again when it
        # ran (Start-AcceptedReplacement) and proves them like any record,
        # with every connector that gateway guarded before its stop
        # (Save-AcceptedConnectors): it is stopped by now, so it is not asked.
        $original = $Run.UnprovenReplacement
        $bins = Get-BinariesState $BinDir
        if (-not $Run.UnprovenAcceptedBins -or -not (Test-SameBinaries $bins $Run.UnprovenAcceptedBins)) {
            throw "the programs in $BinDir changed after -AcceptCurrentInstall accepted them"
        }
        $external = Get-ExternalConfig
        $state = [ordered]@{
            Bins = $bins
            GatewayWasRunning = [bool]$Run.UnprovenGatewayWasRunning
            Connectors = @(if ($Run.ContainsKey("UnprovenConnectors")) { $Run.UnprovenConnectors })
            Config = Get-OptionalSha256 (Join-Path $DataDir "config.yaml")
            ExternalConfig = $external
            ExternalConfigSha256 = Get-OptionalSha256 $external
            HookFailModes = Get-OptionalSha256 (Join-Path $DataDir "hooks\.hookcfg")
            BinDirProtected = Test-BinDirProtected
        }
    } else {
        $state = Get-LifecycleState
    }
    $state["Schema"] = 1
    $state["Operation"] = $Operation
    $state["From"] = $From
    $state["To"] = $To
    $state["Slot"] = $Slot
    # Rollback enters before the install path discovers a legacy Setup install.
    $state["SetupRoot"] = $(if ($unproven) { [string](Get-Field $original "SetupRoot") } elseif ($Operation -eq "rollback") { "" } elseif ($Setup) { [string]$Setup.Root } else { "" })
    $state["Committed"] = $false
    $state["Created"] = (Get-Date).ToUniversalTime().ToString("o")
    if ($unproven) {
        # Interrupted-run recovery stops a gateway of this step only with the
        # checked closer whose digest is recorded here, never by running the
        # accepted programs' own stop (Stop-UnprovenRecoveryGateway).
        if (-not $Run.UnprovenCloserSha256) {
            throw "The checked release hook closer was not recorded before the replacement transaction"
        }
        $state["UnprovenReplacement"] = $true
        $state["ReplacementCloserSha256"] = [string]$Run.UnprovenCloserSha256
    }
    foreach ($key in $Extra.Keys) { $state[$key] = $Extra[$key] }
    Write-DurableText $LifecycleManifest ($state | ConvertTo-Json -Depth 4)
    # The record as read back, which every proof reads with Get-Field: an
    # in-memory dictionary has none of its keys as properties, so a restore
    # or rollback proven against it saw no binaries and no running gateway.
    return Read-LifecycleManifest
}

function Read-LifecycleManifest {
    if (-not (Test-Path -LiteralPath $LifecycleManifest -PathType Leaf)) { return $null }
    try { $manifest = [IO.File]::ReadAllText($LifecycleManifest) | ConvertFrom-Json -ErrorAction Stop } catch {
        throw "The lifecycle record $LifecycleManifest cannot be read, so the install it protects cannot be proven; restore it from a backup or reinstall the release named in it, then run the installer again"
    }
    if ((Get-Field $manifest "Schema") -ne 1) { throw "The lifecycle record $LifecycleManifest is from a newer installer; run that installer again to finish its step" }
    return $manifest
}

function New-RecoveryManifest([string]$Slot, [bool]$WasRunning, [string]$BinsFrom = "", [switch]$NoConfig) {
    # A run of an installer from before the lifecycle record (1.0.3 and
    # earlier) left only its snapshot: record what the snapshot holds, so a
    # restore that fails is retried, and proven, by every later run.
    $complete = Test-Path -LiteralPath (Join-Path $Slot "COMPLETE")
    $savedBin = Join-Path $Slot "bin"
    $binSaved = (Test-Path -LiteralPath $savedBin -PathType Container) -and ($complete -or
        (Test-Path -LiteralPath (Join-Path $Slot "BIN_SAVED")) -or (Test-Path -LiteralPath (Join-Path $Slot "HOOK_FIRST")))
    $config = if ($complete) { Join-Path $Slot "data\config.yaml" } else { Join-Path $DataDir "config.yaml" }
    $state = [ordered]@{
        Schema = 1; Operation = "recover"; From = (Read-Text (Join-Path $Slot "VERSION")); To = ""; Slot = $Slot; SetupRoot = ""
        Bins = $(if ($BinsFrom) { Get-BinariesState $BinsFrom } elseif ($binSaved) { Get-BinariesState $savedBin } else { Get-BinariesState $BinDir })
        GatewayWasRunning = $WasRunning; Connectors = @(); Config = $(if ($NoConfig) { "" } else { Get-OptionalSha256 $config })
        ExternalConfig = ""; ExternalConfigSha256 = ""; HookFailModes = ""; BinDirProtected = $false
        Committed = $false; Created = (Get-Date).ToUniversalTime().ToString("o")
    }
    Write-DurableText $LifecycleManifest ($state | ConvertTo-Json -Depth 4)
    return Read-LifecycleManifest
}

function Complete-LifecycleManifest {
    # The new state is proven: an interruption from here on keeps it.
    $manifest = Read-LifecycleManifest
    if (-not $manifest) { return }
    $manifest.Committed = $true
    Write-DurableText $LifecycleManifest ($manifest | ConvertTo-Json -Depth 4)
}

function Remove-LifecycleManifest {
    if (Test-Path -LiteralPath $LifecycleManifest) { Remove-Item -LiteralPath $LifecycleManifest -Force -ErrorAction Stop }
    $closer = Get-Variable -Name LifecycleCloser -ValueOnly -ErrorAction SilentlyContinue
    if ($closer -and (Test-Path -LiteralPath $closer)) { Remove-Item -LiteralPath $closer -Recurse -Force -ErrorAction SilentlyContinue }
}

function Save-LifecycleCloser([string]$Slot) {
    # Keep the slot's closer (the checked staged gateway) beside the record
    # before a restore consumes the slot. Best effort: without it the gateway
    # in place or the previous one closes the hooks if it can.
    $closer = Join-Path $Slot "closer\defenseclaw-gateway.exe"
    if (-not (Test-Path -LiteralPath $closer -PathType Leaf)) { return }
    try {
        New-Item -ItemType Directory -Path $LifecycleCloser -Force -ErrorAction Stop | Out-Null
        Copy-Item -LiteralPath $closer -Destination (Join-Path $LifecycleCloser "defenseclaw-gateway.exe") -Force -ErrorAction Stop
    } catch { Write-Warn "Could not keep the hook closer in ${LifecycleCloser}: $($_.Exception.Message)" }
}

function Close-AllHooks([string[]]$Gateways) {
    # Close every installed hook (refresh-fail-modes --closed) with the first
    # of $Gateways that can; true once one did.
    foreach ($gateway in $Gateways) {
        if (-not $gateway -or -not (Test-Path -LiteralPath $gateway -PathType Leaf)) { continue }
        $probe = Get-NativeProbe $gateway @("connector", "refresh-fail-modes", "--help")
        if ($probe.Exit -ne 0 -or $probe.Output -notmatch "--closed") { continue }
        if ((Invoke-Native $gateway @("connector", "refresh-fail-modes", "--closed", "--data-dir", $DataDir.TrimEnd([char]92))) -eq 0) { return $true }
    }
    return $false
}

function Test-LifecycleProof($Bins, [bool]$GatewayRunning, [string[]]$Connectors = @(), [switch]$RequireDigest, [bool]$RequireProtected = $true,
        [string]$SetupRoot = "", [switch]$AllowLegacyStatus) {
    # Step 3: what is wrong with the live install, empty when it is proven.
    # $Bins: the SHA-256 each managed binary must have. $GatewayRunning: the
    # gateway must run from this install. $Connectors: those it must guard.
    # -RequireDigest: a gateway that cannot report the live config's policy
    # digest fails too (this release's gateway can; an older restored one
    # may not).
    # -AllowLegacyStatus applies only to restoring a recorded pre-1.0.4
    # binary set. Those gateways may have no JSON status, but exact binary
    # and config hashes plus their legacy status still permit recovery.
    $problems = @()
    $expected = ConvertTo-Map $Bins
    foreach ($name in $ManagedBinaries) {
        $live = Join-Path $BinDir $name
        $present = Test-Path -LiteralPath $live -PathType Leaf
        if ($expected.Contains($name)) {
            if (-not $present) { $problems += "$live is missing" }
            elseif ((Get-Sha256 $live) -ne $expected[$name]) { $problems += "$live is not the expected $name" }
        } elseif ($present) {
            $problems += "$live does not belong to this install"
        }
    }
    # A restore never needs a tighter folder than the one it started from.
    if ($RequireProtected -and -not (Test-BinDirProtected)) { $problems += "$BinDir can be written by another account" }
    $gateway = Join-Path $BinDir "defenseclaw-gateway.exe"
    if (-not $GatewayRunning) { return $problems }
    if ($SetupRoot) {
        # A restored DefenseClaw Setup install runs its own gateway (GAP-1839).
        $setupGateway = Join-Path $SetupRoot "bin\defenseclaw-gateway.exe"
        if (-not (Test-Path -LiteralPath $setupGateway -PathType Leaf) -or (Invoke-Native $setupGateway @("status") -Quiet) -ne 0) {
            $problems += "the DefenseClaw Setup gateway in $SetupRoot does not answer its health check"
        }
        return $problems
    }
    $process = Get-GatewayProcess
    if (-not $process) { return ($problems + "the gateway is not running") }
    $path = [string](Get-Field $process "Path")
    if (-not $path -or -not [string]::Equals([IO.Path]::GetFullPath($path), [IO.Path]::GetFullPath($gateway), [StringComparison]::OrdinalIgnoreCase)) {
        return ($problems + "the running gateway is $path, not $gateway")
    }
    $report = Get-GatewayHealthReport $gateway
    if ($report) {
        if (-not (Get-Field $report "running")) { $problems += "the gateway does not answer its health check" }
        $guarded = @(Get-GuardedConnectors $report)
        foreach ($name in @($Connectors | Where-Object { $_ })) {
            if ($guarded -notcontains $name) { $problems += "connector $name is not guarded again: the gateway does not report its hooks running" }
        }
    } else {
        if (-not $AllowLegacyStatus) {
            $problems += "a usable JSON health report is unavailable, so the gateway's connectors cannot be proven"
        }
        if ((Invoke-Native $gateway @("status") -Quiet) -ne 0) {
            $problems += "the gateway does not answer its health check"
        }
    }
    $digest = Get-GatewayDigestProblem $gateway
    if ($digest -eq "unsupported") {
        if ($RequireDigest) { $problems += "the gateway does not report the policy digest of the live config" }
    } elseif ($digest) {
        $problems += $digest
    }
    return $problems
}

function Set-RecoveryPending([string]$Flag = "RestorePending") {
    $runState = Get-Variable -Name Run -ValueOnly -ErrorAction SilentlyContinue
    if ($runState) { $runState.$Flag = $true }
}

function Wait-LifecycleProof($Bins, [bool]$GatewayRunning, [string[]]$Connectors = @(), [switch]$RequireDigest,
        [bool]$RequireProtected = $true, [string]$SetupRoot = "", [switch]$AllowLegacyStatus) {
    # Test-LifecycleProof, asked again for a while when a running gateway is
    # part of the proof: a gateway that just passed its start readiness can
    # take a few seconds to report its connectors and its policy generation.
    # $LifecycleProofSeconds (30) bounds the wait.
    $limit = Get-Variable -Name LifecycleProofSeconds -ValueOnly -ErrorAction SilentlyContinue
    if ($null -eq $limit) { $limit = 30 }
    $clock = [Diagnostics.Stopwatch]::StartNew()
    while ($true) {
        $problems = @(Test-LifecycleProof $Bins $GatewayRunning $Connectors -RequireDigest:$RequireDigest -RequireProtected $RequireProtected -SetupRoot $SetupRoot -AllowLegacyStatus:$AllowLegacyStatus)
        if (-not $problems.Count -or -not $GatewayRunning -or $clock.Elapsed.TotalSeconds -ge $limit) { return $problems }
        Start-Sleep -Seconds 2
    }
}

function Get-LifecycleNextStep([switch]$Accept) {
    # The command that finishes the step: this installer again, with the
    # same release and local assets (-Accept: and -AcceptCurrentInstall).
    # A PowerShell command on every path, so the switch can always be added:
    # the copy `defenseclaw upgrade` or `rollback` ran is deleted when it
    # ends, and an older CLI does not carry the switch; those, and a run
    # from `irm | iex`, get this release's installer from the release.
    $version = [string](Get-Variable -Name Ver -ValueOnly -ErrorAction SilentlyContinue)
    $released = $version -match '^\d+\.\d+\.\d+$'
    $byUpgrade = [bool](Get-Variable -Name RunByUpgrade -ValueOnly -ErrorAction SilentlyContinue)
    if ($PSCommandPath -and -not $byUpgrade) {
        $retry = "& '$($PSCommandPath.Replace("'", "''"))'"
    } else {
        $base = [string](Get-Variable -Name ReleaseBase -ValueOnly -ErrorAction SilentlyContinue)
        if (-not $base) { $base = "https://github.com/cisco-ai-defense/defenseclaw" }
        $url = if ($released) { "$base/releases/download/$version/install.ps1" } else { "$base/releases/latest/download/install.ps1" }
        $retry = "& ([scriptblock]::Create((irm '$($url.Replace("'", "''"))')))"
    }
    if ($released) { $retry += " -Version '$version'" }
    $retry += " -Yes"
    $local = [string](Get-Variable -Name Local -ValueOnly -ErrorAction SilentlyContinue)
    if ($local) { $retry += " -Local '$($local.Replace("'", "''"))'" }
    if ($Accept) { $retry += " -AcceptCurrentInstall" }
    return $retry
}

function Assert-LifecycleRestored($Manifest, [switch]$KeepStopped, [switch]$Outlived) {
    # Step 5: the restored install is the one the manifest recorded, and its
    # gateway runs again when it ran (unless the restore keeps it stopped on
    # purpose, GAP-0407). The manifest goes only once that is proven; on a
    # failure it stays, the install stays locked and its hooks closed
    # (Close-InstallLock, Close-UnfinishedInstallHooks), and the error names
    # the next step.
    # -Outlived: the record outlived its restore (no snapshot is left), so
    # the live config and connectors may have changed on purpose since. Those
    # differences alone are accepted once the gateway proves it enforces the
    # live config, or when -AcceptCurrentInstall asks for it; every trust
    # check (the recorded binaries, the bin folder, the gateway's health and
    # its acceptance of the live config) still applies.
    if (-not $Manifest) { return }
    $running = [bool](Get-Field $Manifest "GatewayWasRunning") -and -not $KeepStopped
    $bins = Get-Field $Manifest "Bins"
    $protected = [bool](Get-Field $Manifest "BinDirProtected")
    $setupRoot = [string](Get-Field $Manifest "SetupRoot")
    $allowLegacyStatus = [string](Get-Field $Manifest "From") -match '^(?:0\.8\.10|1\.0\.[0-3])$'
    $problems = @(Wait-LifecycleProof $bins $running @(Get-Field $Manifest "Connectors") -RequireProtected $protected -SetupRoot $setupRoot -AllowLegacyStatus:$allowLegacyStatus)
    $drift = @()
    $configChanged = $false
    $config = [string](Get-Field $Manifest "Config")
    $liveConfig = Get-OptionalSha256 (Join-Path $DataDir "config.yaml")
    if ($config -and $liveConfig -ne $config) { $drift += "$(Join-Path $DataDir 'config.yaml') is not the config the previous install ran with"; $configChanged = $true }
    $external = [string](Get-Field $Manifest "ExternalConfig")
    if ($external -and (Get-OptionalSha256 $external) -ne [string](Get-Field $Manifest "ExternalConfigSha256")) {
        $drift += "$external is not the config the previous install ran with"; $configChanged = $true
    }
    # Changes only -AcceptCurrentInstall keeps: a recorded connector that is
    # not guarded although the live effective config still enables it, or
    # the running gateway still lists it, was not turned off, and the live
    # config's digest says nothing about its hooks. One the effective config
    # no longer enables (removed, disabled with its own enabled: false, or
    # under a disabled guardrail) was changed on purpose: the gateway's proof
    # that it enforces the live config accepts it. Its name left in the YAML
    # or in a restored active_connector.json says nothing about that. A
    # roster that cannot be read keeps every connector.
    $unguarded = @()
    if ($Outlived -and $problems.Count -and
        -not @(Test-LifecycleProof $bins $running @() -RequireProtected $protected -SetupRoot $setupRoot -AllowLegacyStatus:$allowLegacyStatus).Count) {
        # Only connectors the record names are not guarded.
        $report = if ($setupRoot) { $null } else { Get-GatewayHealthReport (Join-Path $BinDir "defenseclaw-gateway.exe") }
        $listed = @(@(Get-Field (Get-Field $report "health") "connectors") | ForEach-Object { [string](Get-Field $_ "name") })
        $enabled = $null
        try { $enabled = @(Get-EffectiveConfigConnectors) } catch { $enabled = $null }
        foreach ($problem in $problems) {
            $name = if ($problem -match '^connector (\S+) is not guarded again') { $Matches[1] } else { "" }
            $kept = -not $name -or $null -eq $enabled -or $enabled -contains $name -or $listed -contains $name
            if ($kept) { $unguarded += $problem } else { $drift += $problem }
        }
        $problems = @()
    }
    $changes = @($drift) + @($unguarded)
    if ($changes.Count) {
        $override = [bool](Get-Variable -Name AcceptCurrentInstall -ValueOnly -ErrorAction SilentlyContinue)
        $enforced = $configChanged -and $running -and -not $setupRoot -and -not $unguarded.Count -and
            (Get-GatewayDigestProblem (Join-Path $BinDir "defenseclaw-gateway.exe")) -eq ""
        if ($Outlived -and -not $problems.Count -and ($enforced -or $override)) {
            $why = if ($enforced) { "its gateway enforces the live config" } else { "-AcceptCurrentInstall" }
            Write-Warn "The install an earlier run recorded is back with changes made since ($($changes -join '; ')); accepted as it is now ($why)"
        } else {
            $problems += $changes
        }
    }
    if ([string](Get-Field $Manifest "HookFailModes") -and -not (Test-Path -LiteralPath (Join-Path $DataDir "hooks\.hookcfg") -PathType Leaf)) {
        $problems += "the hooks' outage modes ($(Join-Path $DataDir 'hooks\.hookcfg')) are missing"
    }
    if (-not $problems.Count -and $KeepStopped -and [bool](Get-Field $Manifest "GatewayWasRunning") -and
        (Test-Path -LiteralPath (Join-Path $DataDir "hooks") -PathType Container)) {
        # The gateway stays stopped on purpose (GAP-0407): its hooks block
        # until it runs again, an outage open the config chooses included,
        # because the gateway that ran before is down.
        $gateways = @((Join-Path $LifecycleCloser "defenseclaw-gateway.exe"), (Join-Path $BinDir "defenseclaw-gateway.exe"))
        if (Close-AllHooks $gateways) {
            Write-Warn "Every agent hook blocks tool calls until the gateway runs again"
        } else {
            $problems += "the hooks could not be closed while the restored gateway stays stopped"
        }
    }
    if ($problems.Count) {
        Set-RecoveryPending
        $accept = ""
        if ($Outlived -and $changes.Count -and -not @($problems | Where-Object { $changes -notcontains $_ }).Count) {
            # Only the changes made since stand in the way.
            $accept = " If you changed the config or the connectors on purpose, keep the install as it is now (-AcceptCurrentInstall): $(Get-LifecycleNextStep -Accept)"
        }
        throw ("The previous install is not proven back: $($problems -join '; '). The record of it stays in $LifecycleManifest and the install stays locked; " +
            "fix the cause, then run: $(Get-LifecycleNextStep)$accept")
    }
    Remove-LifecycleManifest
}

function Save-BinarySnapshot {
    # Only immutable binaries are copied while the gateway runs. The new
    # hook understands .install.lock, including when upgrading from 1.0.2.
    # HOOK_FIRST lets interrupted-run recovery restore it before any data
    # snapshot or process shutdown has started.
    New-InstallDirectory $Snap
    # Recovery needs the running state even if copying the snapshot is
    # interrupted before COMPLETE can be written.
    Set-Content -LiteralPath (Join-Path $Snap "GATEWAY_WAS_RUNNING") -Value ([string]$WasRunning).ToLowerInvariant() -Encoding Ascii
    Copy-BinDir (Join-Path $Snap "bin")
    Install-HookFirst $Snap
    Set-Content -LiteralPath (Join-Path $Snap "BIN_SAVED") -Value "" -Encoding Ascii
}

function Finish-EarlySnapshotRestore($Recorded) {
    if (Test-RecoveryPending) { return }
    if ($Run.UnprovenReplacement) {
        # The copy in the slot was put back, but a still-open transaction
        # from an older installer did not prove its binary baseline.
        # Comparing the restored files with that empty map falsely reports
        # every binary as foreign. Retain the record for the next run.
        Set-RecoveryPending
        Write-Warn "The hook snapshot was restored, but an earlier interrupted install never proved its binary baseline. Its lifecycle record remains; retry after the previous hook call finishes"
        return
    }
    try { Assert-LifecycleRestored $Recorded } catch { Write-Err $_.Exception.Message }
}

function Save-Snapshot {
    if (-not (Test-Path -LiteralPath (Join-Path $Snap "BIN_SAVED"))) { Save-BinarySnapshot }
    New-Item -ItemType Directory -Path (Join-Path $Snap "data") | Out-Null
    $entries = Get-DataEntries
    $need = [long]0
    foreach ($entry in $entries) { $need += Get-TreeSize $entry.FullName }
    $free = [long]-1
    try { $free = ([IO.DriveInfo][IO.Path]::GetPathRoot([IO.Path]::GetFullPath($DataDir))).AvailableFreeSpace } catch { }
    # A large audit.db makes this copy (and the antivirus scan of it) slow;
    # say how big it is and what is free (GAP-1519).
    $freeText = if ($free -ge 0) { ", {0:N0} MB free" -f ([double]$free / 1MB) } else { "" }
    if ($PrevVersion -or $need -gt 0) {
        Write-Info ("Saving a rollback copy of the data folder ({0:N0} MB needed{1})" -f ([double]$need / 1MB), $freeText)
    }
    if ($free -ge 0 -and $free -lt $need + 100MB) {
        Write-Err "Not enough free disk space next to $DataDir for a rollback copy"
        return $false
    }
    foreach ($entry in $entries) { Copy-Kept $entry.FullName (Join-Path $Snap "data") }
    Save-ExternalConfig $Snap
    if (Test-Path -LiteralPath $Venv) { Move-Path $Venv (Join-Path $Snap "venv") 60 }
    if (Test-Path -LiteralPath $InstallerDir) { Move-Path $InstallerDir (Join-Path $Snap "installer") }
    Set-Content -LiteralPath (Join-Path $Snap "VERSION") -Value $PrevVersion -Encoding Ascii
    Set-Content -LiteralPath (Join-Path $Snap "COMPLETE") -Value "" -Encoding Ascii
    return $true
}

function Test-HookFailModeRefresh([string]$Gateway) {
    # 0: the staged gateway has 'connector refresh-fail-modes'. 1: an older
    # one (a downgrade), which prints the connector help for an unknown
    # subcommand and sets its own modes when it starts. 2: any other answer
    # (an error, no output): the hooks cannot be shown safe.
    $probe = Get-NativeProbe $Gateway @("connector", "refresh-fail-modes", "--help")
    if ($probe.Exit -eq 0 -and $probe.Output -match "connector refresh-fail-modes") { return 0 }
    if ($probe.Exit -eq 0 -and $probe.Output -match "defenseclaw-gateway connector \[command\]") { return 1 }
    Write-Warn "The new gateway did not answer 'connector refresh-fail-modes --help' (exit $($probe.Exit))"
    return 2
}

function Update-HookFailModes([string]$Gateway) {
    # Set the hooks' outage fail modes (hooks\.hookcfg and the adapters) from
    # the config with this release's gateway before the new hook goes in: an
    # earlier release may have recorded open for a mode nobody set (0.8.x and
    # 1.0.2 resolved an unset mode from the guardrail mode), and the old hook
    # would follow it while the gateway is down. An open the config sets
    # stays open, from a DEFENSECLAW_CONFIG outside the data folder too.
    # False when the hooks could not be made safe. Used when no gateway runs;
    # a running one gets Start-HookFailModeHold.
    if (-not (Test-Path -LiteralPath (Join-Path $DataDir "hooks\.hookcfg") -PathType Leaf)) { return $true }
    switch (Test-HookFailModeRefresh $Gateway) {
        0 { return ((Invoke-Native $Gateway @("connector", "refresh-fail-modes", "--data-dir", $DataDir)) -eq 0) }
        1 { return $true }
    }
    return $false
}

$script:FailModeHold = $null

function Start-HookFailModeHold([string]$Gateway, [int]$GatewayId, [switch]$Closed) {
    # Update-HookFailModes for the running gateway $GatewayId, which is about
    # to stop. The staged gateway refreshes, holds the lock every release's
    # hook writer takes until that gateway has exited, and refreshes again:
    # the old gateway may render its hooks again while it runs or shuts down
    # (a 1.0.x Codex registration check does), and the old hook would follow
    # that open while it is down. True once the first refresh is written and
    # the lock held; Complete-HookFailModeHold waits for the rest.
    if (-not (Test-Path -LiteralPath (Join-Path $DataDir "hooks") -PathType Container)) { return $true }
    if (-not $Closed -and -not (Test-Path -LiteralPath (Join-Path $DataDir "hooks\.hookcfg") -PathType Leaf)) { return $true }
    switch (Test-HookFailModeRefresh $Gateway) {
        0 { }
        1 { if ($Closed) { return $false }; return $true }
        default { return $false }
    }
    $info = New-Object System.Diagnostics.ProcessStartInfo
    $info.FileName = $Gateway
    $info.Arguments = "connector refresh-fail-modes --data-dir `"$($DataDir.TrimEnd([char]92))`" --hold-until-exit $GatewayId$(if ($Closed) { ' --closed' })"
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $process = [System.Diagnostics.Process]::Start($info)
    $script:FailModeHold = [pscustomobject]@{ Process = $process; Rest = $null; Errors = $process.StandardError.ReadToEndAsync() }
    $pending = $process.StandardOutput.ReadLineAsync()
    $clock = [System.Diagnostics.Stopwatch]::StartNew()
    while ($clock.Elapsed.TotalSeconds -lt 60) {
        if (-not $pending.Wait(100)) { continue }
        $line = $pending.Result
        if ($null -eq $line) { [void](Complete-HookFailModeHold); return $false }
        if ($line.Contains("Holding the hook fail modes")) {
            $script:FailModeHold.Rest = $process.StandardOutput.ReadToEndAsync()
            return $true
        }
        Write-Host $line
        $pending = $process.StandardOutput.ReadLineAsync()
    }
    Write-Warn "The new gateway did not set the hooks' fail modes within a minute"
    Stop-HookFailModeHold
    return $false
}

function Complete-HookFailModeHold {
    # Wait for the hold, which ends once the gateway it holds for has exited,
    # and show what it said. True when it set the modes.
    $hold = $script:FailModeHold
    if (-not $hold) { return $true }
    $script:FailModeHold = $null
    $hold.Process.WaitForExit()
    $rest = if ($hold.Rest) { $hold.Rest.GetAwaiter().GetResult() } else { $hold.Process.StandardOutput.ReadToEnd() }
    $errors = $hold.Errors.GetAwaiter().GetResult()
    foreach ($text in @($rest, $errors)) {
        if ($text) { $text.TrimEnd() -split "`r?`n" | ForEach-Object { Write-Host $_ } }
    }
    $ok = $hold.Process.ExitCode -eq 0
    $hold.Process.Dispose()
    return $ok
}

function Stop-HookFailModeHold {
    # Let go of the hold early: the gateway did not stop.
    $hold = $script:FailModeHold
    if (-not $hold) { return }
    $script:FailModeHold = $null
    try {
        if (-not $hold.Process.HasExited) {
            $hold.Process.Kill()
            [void]$hold.Process.WaitForExit(5000)
        }
    } catch { }
    $hold.Process.Dispose()
}

function Install-HookFirst([string]$Slot) {
    # The previous version's hook keeps answering the agents while the data
    # folder is copied and the new Python environment is built, a minute or
    # more on a busy host. A 1.0.2 hook takes the stopped gateway for an
    # operator stop and tries to start it (GAP-0196); the new hook reads
    # .install.lock, waits for the install and names it. So the new hook goes
    # in as soon as the rollback copy holds the old one. HOOK_FIRST, written
    # once that copy is whole, tells Undo-Snapshot to put the old hook back.
    # Until the new gateway is published, the gateways in place are older and
    # cannot close the hooks, so the slot first keeps the staged (checked)
    # gateway in closer\: a run that stops in that window (killed, or a
    # restore the running new hook refuses, now or in the next run's
    # Resume-InterruptedRun) closes the hooks with it
    # (Close-UnfinishedInstallHooks). No closer, no new hook.
    # It holds the old hook's SHA-256, so an undo tells the old hook back in
    # place from a rollback copy that went missing or changed after the swap
    # (an antivirus quarantine): that copy is then the only old hook.
    $live = Join-Path $BinDir "defenseclaw-hook.exe"
    $saved = Join-Path $Slot "bin\defenseclaw-hook.exe"
    $staged = Join-Path $Staging "bin\defenseclaw-hook.exe"
    $gateway = Join-Path $Staging "bin\defenseclaw-gateway.exe"
    foreach ($path in @($live, $staged, $gateway)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return }
    }
    $old = Get-Sha256 $live
    if (-not (Test-Path -LiteralPath $saved -PathType Leaf) -or (Get-Sha256 $saved) -ne $old) {
        throw "Could not keep a whole rollback copy of $live in $(Split-Path -Parent $saved) (an antivirus may have removed it); nothing was changed. Run the installer again"
    }
    Save-HookCloser $Slot $gateway
    Set-Content -LiteralPath (Join-Path $Slot "HOOK_FIRST") -Value $old -Encoding Ascii
    Install-File $staged $live
    Wait-PreviousHookExit ([DateTime]::UtcNow)
}

function Wait-PreviousHookExit([DateTime]$PublishedAt) {
    # A hook already running the previous image can still cold-start its
    # gateway after the swap. Drain only calls born before publication while
    # the old gateway remains available; new hook traffic keeps running.
    $image = Join-Path $BinDir 'defenseclaw-hook.exe'
    $clock = [Diagnostics.Stopwatch]::StartNew()
    while ($true) {
        $pending = $false
        foreach ($row in @(Get-ProcessesUnder @($image))) {
            $process = Get-Process -Id $row.ProcessId -ErrorAction SilentlyContinue
            if (-not $process) { $pending = $true; continue }
            try { $started = $process.StartTime.ToUniversalTime() } catch {
                throw "Cannot prove that previous hook calls finished before stopping the gateway. Close the agents, then run: & '<checked install.ps1>' -Local '<checked release assets directory>' -Yes"
            }
            if ($started -le $PublishedAt) { $pending = $true }
        }
        if (-not $pending) { return }
        if ($clock.Elapsed.TotalSeconds -ge 30) {
            throw "Previous hook calls did not finish within 30 seconds before stopping the gateway. Close the agents, then run: & '<checked install.ps1>' -Local '<checked release assets directory>' -Yes"
        }
        Start-Sleep -Milliseconds 25
    }
}

function Save-HookCloser([string]$Slot, [string]$Gateway) {
    # A hard link takes no room and stays when the staged release is cleared;
    # a copy where the volume cannot link. Either is proven byte for byte, and
    # any failure stops the run before the hook changes.
    $closer = Join-Path $Slot "closer\defenseclaw-gateway.exe"
    try {
        New-Item -ItemType Directory -Path (Split-Path -Parent $closer) -Force -ErrorAction Stop | Out-Null
        if (Test-Path -LiteralPath $closer) { Remove-Item -LiteralPath $closer -Force -ErrorAction Stop }
        try { New-Item -ItemType HardLink -Path $closer -Target $Gateway -ErrorAction Stop | Out-Null } catch {
            if (Test-Path -LiteralPath $closer) { Remove-Item -LiteralPath $closer -Force -ErrorAction Stop }
            Copy-Item -LiteralPath $Gateway -Destination $closer -ErrorAction Stop
        }
        if (-not (Test-Path -LiteralPath $closer -PathType Leaf) -or (Get-Sha256 $closer) -ne (Get-Sha256 $Gateway)) {
            throw "the kept copy does not match $Gateway"
        }
    } catch {
        throw ("Could not keep the new gateway in $(Split-Path -Parent $closer), which closes the agent hooks if this install stops " +
            "unfinished ($($_.Exception.Message)); the installed hook was left as it was")
    }
}

function Save-AcceptedConnectors([string]$Closer, $Running) {
    # The connectors the gateway -AcceptCurrentInstall accepted guards. Its
    # restore (the journal, Restore-AcceptedReplacement) must show each one
    # guarded again before the record goes. Asked of the running gateway
    # with the checked closer, so the accepted programs do not run before
    # their stop, and held to the same roster as any record
    # (Get-HeldConnectors): what it reports running and every connector the
    # effective config enables that it does not explicitly report
    # unhealthy, so a connector its health omits is still proven. One an
    # earlier run stopped without recording them is held to every connector
    # the effective config enables. Merged with what an earlier run
    # recorded, and kept in the record before the stop, so a run interrupted
    # after it still proves them.
    $names = @(if ($Run.ContainsKey("UnprovenConnectors")) { $Run.UnprovenConnectors })
    $record = Read-LifecycleManifest
    $recorded = $record -and $record.PSObject.Properties["ReplacementConnectors"]
    if ($recorded) { $names += @($record.ReplacementConnectors) }
    if ($Running) {
        $names += @(Get-HeldConnectors (Get-GatewayHealthReport $Closer))
    } elseif ($Run.ContainsKey("UnprovenGatewayWasRunning") -and $Run.UnprovenGatewayWasRunning -and -not $recorded) {
        $names += @(Get-HeldConnectors $null)
    }
    $Run.UnprovenConnectors = @($names | Where-Object { $_ } | ForEach-Object { [string]$_ } | Sort-Object -Unique)
    if ($record) {
        # Copied into a dictionary: Windows PowerShell 5.1 can write an array
        # added with Add-Member as {"value": [...], "Count": n}.
        $copy = [ordered]@{}
        foreach ($property in $record.PSObject.Properties) { $copy[$property.Name] = $property.Value }
        $copy["ReplacementConnectors"] = [string[]]@($Run.UnprovenConnectors)
        Write-DurableText $LifecycleManifest ($copy | ConvertTo-Json -Depth 4)
    }
}

function Prepare-UnprovenReplacement([string]$Gateway, $ExpectedBins) {
    # The empty first-install record remains the journal. Keep the checked
    # release gateway beside it before touching the older running install.
    # A retry can then close hooks even if the staged release is gone.
    if (-not (Test-SameBinaries (Get-BinariesState (Split-Path -Parent $Gateway)) $ExpectedBins)) {
        throw "The staged release changed before the older gateway could be stopped"
    }
    $closer = Join-Path $LifecycleCloser "defenseclaw-gateway.exe"
    $temporary = "$closer.new"
    New-Item -ItemType Directory -Path $LifecycleCloser -Force -ErrorAction Stop | Out-Null
    Copy-Item -LiteralPath $Gateway -Destination $temporary -Force -ErrorAction Stop
    $stream = New-Object IO.FileStream($temporary, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::Read)
    try { $stream.Flush($true) } finally { $stream.Dispose() }
    if ((Get-Sha256 $temporary) -ne (Get-Sha256 $Gateway)) { throw "The kept hook closer differs from the checked gateway" }
    if (Test-Path -LiteralPath $closer) { [IO.File]::Replace($temporary, $closer, [NullString]::Value) }
    else { [IO.File]::Move($temporary, $closer) }
    if ((Get-Sha256 $closer) -ne (Get-Sha256 $Gateway)) { throw "The published hook closer differs from the checked gateway" }
    $Run.UnprovenCloserSha256 = Get-Sha256 $closer
    $running = Get-GatewayProcess
    Save-AcceptedConnectors $closer $running
    if ((Test-Path -LiteralPath (Join-Path $DataDir "hooks") -PathType Container) -and -not (Close-AllHooks @($closer))) {
        throw "Could not close the older install's hooks with the checked gateway"
    }
    # From here a failed retry keeps the record: every installed hook was
    # closed with the hash-checked gateway before a stop is possible. It keeps
    # the install lock only once the older gateway is down; while that
    # gateway runs it can render its hooks again (Finish-InstallLock).
    $Run.UnprovenReplacementUnchanged = $false
    if ($running -and -not (Start-HookFailModeHold $closer $running.Id -Closed)) {
        throw "Could not hold the older install's hooks closed while its gateway exits"
    }
    try { $stopped = Stop-UnprovenGateway } catch { Stop-HookFailModeHold; throw }
    if (-not (Complete-HookFailModeHold)) { throw "Could not keep the older install's hooks closed after its gateway exited" }
    # The hold covers only the gateway gateway.pid names. One run from a copy
    # renamed aside could render its hooks until it was stopped: close them
    # again now that no gateway or watchdog of this install runs.
    if ($stopped -and (Test-Path -LiteralPath (Join-Path $DataDir "hooks") -PathType Container) -and -not (Close-AllHooks @($closer))) {
        throw "Could not close the older install's hooks again after its gateway exited"
    }
}

function Stop-UnprovenRecoveryGateway($Manifest, [string]$Slot) {
    # A completed interrupted snapshot may contain a restarted old gateway.
    # Use only the release closer whose digest the transaction recorded after
    # checking the staged release; never run the older unproven binary.
    # A gateway or watchdog gateway.pid does not name (one run from a copy
    # renamed aside, .old-*) is stopped too (Stop-UnprovenGateway).
    $running = Get-GatewayProcess
    $hooks = Test-Path -LiteralPath (Join-Path $DataDir "hooks") -PathType Container
    $images = @(Get-ProcessesUnder @(Join-Path $BinDir "defenseclaw-gateway"))
    if (-not $running -and -not $hooks -and -not $images.Count) { return }
    $checked = $null
    if ($running -or $hooks) {
        $expected = [string](Get-Field $Manifest "ReplacementCloserSha256")
        if (-not $expected) {
            throw "The interrupted replacement record has no checked closer digest, so the gateway was left alone. Restore the last proven install from $Slot under administrator supervision, then rerun its installer"
        }
        $candidates = @((Join-Path $LifecycleCloser "defenseclaw-gateway.exe"),
            (Join-Path $Slot "closer\defenseclaw-gateway.exe"),
            (Join-Path $Staging "bin\defenseclaw-gateway.exe"),
            (Join-Path $BinDir "defenseclaw-gateway.exe"))
        foreach ($candidate in $candidates) {
            if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) { continue }
            try { if ((Get-Sha256 $candidate) -eq $expected) { $checked = $candidate; break } } catch { }
        }
        if (-not $checked) {
            throw "The checked release hook closer is missing or changed; restore its SHA-256 $expected at $LifecycleCloser, then run: $(Get-LifecycleNextStep -Accept)"
        }
    }
    if ($hooks -and -not (Close-AllHooks @($checked))) {
        throw "Could not close the interrupted install's hooks with the checked release gateway; run: $(Get-LifecycleNextStep -Accept)"
    }
    if ($running -and -not (Start-HookFailModeHold $checked $running.Id -Closed)) {
        throw "Could not hold the interrupted install's hooks closed while its gateway exits; run: $(Get-LifecycleNextStep -Accept)"
    }
    try { $stopped = Stop-UnprovenGateway } catch { Stop-HookFailModeHold; throw }
    if (-not (Complete-HookFailModeHold)) {
        throw "Could not keep the interrupted install's hooks closed after its gateway exited; run: $(Get-LifecycleNextStep -Accept)"
    }
    if ($stopped -and $hooks -and -not (Close-AllHooks @($checked))) {
        throw "Could not close the interrupted install's hooks again after its gateway exited; run: $(Get-LifecycleNextStep -Accept)"
    }
}

function Undo-HookFirst([string]$Slot) {
    $marker = Join-Path $Slot "HOOK_FIRST"
    if (-not (Test-Path -LiteralPath $marker)) { return }
    $saved = Join-Path $Slot "bin\defenseclaw-hook.exe"
    $live = Join-Path $BinDir "defenseclaw-hook.exe"
    # The old hook's SHA-256. A 1.0.3 installer wrote the marker empty; then
    # the rollback copy is all there is to compare with.
    $old = Read-Text $marker
    $copy = if (Test-Path -LiteralPath $saved -PathType Leaf) { Get-Sha256 $saved } else { "" }
    if (-not $old) { $old = $copy }
    # Only the old hook's bytes in place are a restore.
    $back = { $old -and (Test-Path -LiteralPath $live -PathType Leaf) -and (Get-Sha256 $live) -eq $old }
    if (& $back) { return }
    # A rollback copy that is gone or changed restores nothing: the new hook
    # stays live, so the slot and .install.lock stay too (Undo-EarlySnapshot).
    if (-not $copy -or $copy -ne $old) {
        throw "The rollback copy of the previous defenseclaw-hook.exe ($saved) is missing or changed, so the new hook is still in $BinDir. Put that file back (an antivirus may have quarantined it), then run the installer again"
    }
    Install-File $saved $live
    if (-not (& $back)) { throw "The previous defenseclaw-hook.exe is not back in $BinDir" }
}

function Undo-Snapshot([string]$Slot) {
    # Put back what an unfinished Save-Snapshot moved. The slot holds the
    # only copy of the previous hook until it is back in place: when a
    # running hook refuses that switch, the slot stays and the error says so,
    # and the next run finishes the undo (Resume-InterruptedRun).
    $hookRefused = ""
    try { Undo-HookFirst $Slot } catch { $hookRefused = $_.Exception.Message }
    if ((Test-Path -LiteralPath (Join-Path $Slot "venv")) -and -not (Test-Path -LiteralPath $Venv)) { Move-Path (Join-Path $Slot "venv") $Venv 60 }
    if ((Test-Path -LiteralPath (Join-Path $Slot "installer")) -and -not (Test-Path -LiteralPath $InstallerDir)) {
        Move-Path (Join-Path $Slot "installer") $InstallerDir
    }
    if ($hookRefused) { throw "Could not put the previous hook back in $BinDir ($hookRefused); its copy was kept in $Slot. Run the installer again to finish putting it back" }
    Remove-Tree $Slot
}

function Undo-EarlySnapshot([string]$Slot) {
    # Undo-Snapshot removes the slot last, so a slot still here is an undo
    # that did not finish: a hook reader or a scanner held the old hook or
    # the environment, and the new hook may still be live. The install then
    # stays locked (Close-InstallLock) and the next run of the installer
    # finishes the undo (Resume-InterruptedRun).
    try { Undo-Snapshot $Slot } catch { Write-Err "Could not put the previous install back: $($_.Exception.Message)" }
    $Run.UndoPending = [bool](Test-Path -LiteralPath $Slot)
}

function Protect-BinDir {
    # The CLI runs only a gateway whose file and folder no account other than
    # this one, LocalSystem and the built-in Administrators group (matched by
    # SID) can write. A ~\.local\bin another tool created with a looser ACL
    # (Users or Everyone may write) fails that check, and the CLI then refuses
    # the gateway installed there. Keep only this account and LocalSystem on
    # such a folder; what it holds inherits that.
    $user = [Security.Principal.WindowsIdentity]::GetCurrent().User
    if (-not @(Get-BinDirOpenRules).Count) { return }
    $secure = New-Object Security.AccessControl.DirectorySecurity
    $secure.SetAccessRuleProtection($true, $false)
    foreach ($sid in @($user, (New-Object Security.Principal.SecurityIdentifier "S-1-5-18"))) {
        $secure.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule $sid, "FullControl", "ContainerInherit, ObjectInherit", "None", "Allow"))
    }
    try {
        Set-Acl -LiteralPath $BinDir -AclObject $secure
        Write-Info "Restricted $BinDir to this account and SYSTEM"
    } catch {
        Write-Warn "Could not restrict $BinDir to this account ($($_.Exception.Message)); DefenseClaw refuses a gateway other accounts can write"
    }
}

function Install-New {
    Write-Info "Installing DefenseClaw $Ver"
    Write-Info "Building the final Python environment in $Venv (the checked packages come from the uv cache)"
    if (-not (New-Venv $Venv "the final environment")) { return $false }
    # The core install does not require Fleet. An enabled Fleet receives the
    # matching compiler inside installer/, which rollback snapshots preserve.
    if (Test-FleetEnabled) {
        $compiler = Join-Path $Staging "bin\edge-connector\tools\policy_compiler.py"
        if (-not (Test-Path -LiteralPath $compiler -PathType Leaf)) {
            Write-Warn "Fleet is enabled but this release has no Fleet policy compiler"
            return $false
        }
        New-Item -ItemType Directory -Path $InstallerDir -Force | Out-Null
        Install-File $compiler (Join-Path $InstallerDir "policy_compiler.py")
    }
    New-Item -ItemType Directory -Path $BinDir -Force | Out-Null
    Protect-BinDir
    # Binaries an earlier run renamed aside while they were running.
    foreach ($name in $ManagedFiles) {
        Get-ChildItem -LiteralPath $BinDir -Filter "$name.old-*" -Force | Remove-Item -Force -ErrorAction SilentlyContinue
    }
    foreach ($name in $ManagedBinaries) {
        $staged = Join-Path $Staging "bin\$name"
        if (Test-Path -LiteralPath $staged) { Install-File $staged (Join-Path $BinDir $name) }
    }
    foreach ($name in $ManagedShims) {
        $target = Join-Path $Venv "Scripts\$name.exe"
        if (Test-Path -LiteralPath $target) { Write-Shim $name $target }
        elseif (Test-Path -LiteralPath (Join-Path $BinDir "$name.cmd")) { Remove-Aside (Join-Path $BinDir "$name.cmd") }
    }
    $target = Join-Path $Venv "Scripts\defenseclaw.exe"
    if (Test-Path -LiteralPath $target) { Write-PosixShim $target; Install-File $target (Join-Path $BinDir $CliLauncher) }
    else {
        foreach ($name in @($PosixShim, $CliLauncher)) {
            if (Test-Path -LiteralPath (Join-Path $BinDir $name)) { Remove-Aside (Join-Path $BinDir $name) }
        }
    }
    Write-HookState
    if ((Test-Path -LiteralPath (Join-Path $DataDir "config.yaml")) -or $env:DEFENSECLAW_CONFIG) {
        Write-Info "Migrating config and data"
        if ($PrevVersion -and [version]$PrevVersion -lt [version]"1.0.0") { Repair-DataOwner }
        $migrateArgs = @("migrate")
        if ($PrevVersion) { $migrateArgs += @("--from-version", $PrevVersion) }
        $env:DEFENSECLAW_GATEWAY_BIN = Join-Path $BinDir "defenseclaw-gateway.exe"
        if ((Invoke-Native (Join-Path $Venv "Scripts\defenseclaw.exe") $migrateArgs) -ne 0) { return $false }
        # The previous version's agent discovery is absent or stale. Refresh
        # it (bounded --version probes, no telemetry) before the gateway
        # starts, so the gateway records each agent's version in the hook
        # contract lock and doctor can check compatibility. Best effort.
        Write-Info "Refreshing agent discovery"
        Invoke-Native (Join-Path $Venv "Scripts\defenseclaw.exe") @("agent", "discover", "--refresh", "--no-emit-otel") -Quiet | Out-Null
        # The new defenseclaw-acp has a new digest: re-pin it in configured
        # editor entries, which would otherwise fail closed. Best effort.
        $oldGuard = Join-Path $Snap "bin\defenseclaw-acp.exe"
        if (Test-Path -LiteralPath $oldGuard) {
            Invoke-Native (Join-Path $Venv "Scripts\defenseclaw.exe") @("acp", "refresh", "--from-sha256", (Get-Sha256 $oldGuard)) | Out-Null
        }
        # A rollback by an earlier release left hook entries of a connector
        # this install does not configure (GAP-0009). Best effort.
        Invoke-PruneOrphanedHooks @((Join-Path $BinDir "defenseclaw-gateway.exe"))
    }
    return $true
}

function Restart-Old([switch]$KeepStopped) {
    # An unfinished snapshot left by a failed undo is undone once more. The
    # old gateway starts either way, unless -KeepStopped: with the new hook
    # still live (the pair an upgrade runs until it stops the gateway) the
    # agents stay guarded.
    $earlySlot = Get-Variable -Name Snap -ValueOnly -ErrorAction SilentlyContinue
    if ($earlySlot -and (Test-Path -LiteralPath $earlySlot) -and -not (Test-Path -LiteralPath (Join-Path $earlySlot "COMPLETE"))) {
        Undo-EarlySnapshot $earlySlot
    } elseif ($earlySlot -and (Test-Path -LiteralPath (Join-Path $earlySlot "HOOK_FIRST"))) {
        try { Undo-HookFirst $earlySlot } catch {
            Write-Err "Could not put the previous hook back: $($_.Exception.Message)"
            $Run.RestorePending = $true
        }
    }
    # A failure here (a gateway.pid that cannot be read, DefenseClaw Setup's
    # hook state that cannot be moved back) must not end the restore it is
    # part of: it is reported like a gateway that did not start.
    # An accepted retry stopped its older gateway before $WasRunning was read.
    $oldRan = [bool]$WasRunning -or [bool]($Run.UnprovenReplacement -and $Run.UnprovenGatewayWasRunning)
    try {
        if ($Setup) { Restore-SetupInstall -KeepStopped:$KeepStopped } elseif ($WasRunning -and -not $KeepStopped) { [void](Start-Gateway) }
        elseif (-not $KeepStopped) { Start-AcceptedReplacement }
        # Say plainly when the gateway that ran before is down now (GAP-1349).
        $Run.OldGatewayDown = $oldRan -and -not (Get-GatewayProcess)
    } catch {
        Write-Err "Could not start the previous gateway again: $($_.Exception.Message)"
        $Run.OldGatewayDown = $oldRan
        if ($Setup) { $Run.RestorePending = $true }
    }
    if ($KeepStopped) {
        # An old release may tear down the still-working hooks when its own
        # setup meets the same sharing error (GAP-0407). Keep the restored
        # registration callable in fail-closed mode until the cause is fixed.
        $gateway = if ($Setup) { Join-Path $Setup.Root "bin\defenseclaw-gateway.exe" } else { Join-Path $BinDir "defenseclaw-gateway.exe" }
        $gatewayCommand = "& '" + $gateway.Replace("'", "''") + "' start"
        Write-Warn "The previous install is restored with its gateway kept stopped to preserve its hook registration"
        Write-Info "Fix the startup error above (close the agent if its settings are in use), then run: $gatewayCommand"
        return
    }
    if ($Run.OldGatewayDown) {
        Write-Warn "The gateway that was running before did not start again, so agent hooks are not guarded until it runs (connectors in fail-closed mode block tool calls)"
        Write-Info "Start it with: defenseclaw-gateway start (log: $(Join-Path $DataDir 'gateway.log')). On a large audit database its first start can take several minutes"
    }
}

function Start-AcceptedReplacement {
    # Prepare-UnprovenReplacement stopped the gateway of the install
    # -AcceptCurrentInstall accepted, without running it. A run that fails
    # before the checked release is committed starts that gateway again, so
    # the failure does not strand the working install: only when it ran, is
    # down, and the programs are still the ones accepted. The caller proves it.
    if (-not ($Run.UnprovenReplacement -and $Run.UnprovenGatewayWasRunning)) { return }
    if (Get-GatewayProcess) { return }
    if (-not $Run.UnprovenAcceptedBins -or -not (Test-SameBinaries (Get-BinariesState $BinDir) $Run.UnprovenAcceptedBins)) {
        Write-Warn "The programs in $BinDir are not the ones -AcceptCurrentInstall accepted, so their gateway is not started again"
        return
    }
    try { [void](Start-Gateway) } catch { Write-Err "Could not start the accepted install's gateway again: $($_.Exception.Message)" }
}

function Restore-AcceptedReplacement {
    # A failure before this run's journal: the record is still the empty
    # first-install one, which proves nothing about the accepted programs.
    # A gateway this run stopped is started again and proven against the
    # accepted hashes; one still running was never stopped (a refusal before
    # the stop, or a stop that failed) and is left alone. Returns what to add
    # to the error.
    if (-not ($Run.UnprovenReplacement -and $Run.UnprovenGatewayWasRunning) -or (Get-GatewayProcess)) { return "" }
    Start-AcceptedReplacement
    $problems = @(Wait-LifecycleProof $Run.UnprovenAcceptedBins $true @(if ($Run.ContainsKey("UnprovenConnectors")) { $Run.UnprovenConnectors }) -RequireProtected $false)
    if ($problems.Count) { return " The accepted install's gateway is not proven running ($($problems -join '; '))." }
    return " The accepted install's gateway is running."
}

function Test-RecoveryPending { return [bool]($Run.UndoPending -or $Run.RestorePending) }

function Get-UnchangedNote {
    if (Test-RecoveryPending) { return "the previous install is not fully back (see above); run the installer again to finish restoring it" }
    return "nothing was changed"
}

function Close-InstallLock {
    # An undo or a restore that did not finish keeps .install.lock, so hooks
    # wait for the install instead of starting a gateway for a mixed install.
    # The next run takes the lock over and finishes the restore. A failed run
    # keeps it only with every hook closed and no gateway of this install
    # running (Finish-InstallLock).
    Invoke-Quietly { Clear-StagedRelease }
    if (Test-RecoveryPending) {
        if ($Run.ContainsKey("UnprovenReplacement") -and $Run.UnprovenReplacement) {
            Write-Warn "The install stays locked ($LockDir); retry the checked release with: $(Get-LifecycleNextStep -Accept)"
        } else {
            Write-Warn "The install stays locked ($LockDir) until the installer runs again and finishes restoring the previous install; until then hooks do not start the gateway"
        }
        return
    }
    Invoke-Quietly { Remove-Tree $LockDir }
}

function Finish-InstallLock([int]$ExitCode) {
    if (-not $Run.Lock) { return }
    # A refusal that changed nothing (a record whose programs another
    # installer added or replaced), or a failure before the checked closer
    # closed its hooks, did not change the older install. Leave its record
    # for the next retry but let its own hooks cold-start the gateway.
    $closed = $false
    if ($ExitCode -ne 0 -and -not $Run.UnprovenReplacementUnchanged) {
        $result = @(Invoke-Quietly { Close-UnfinishedInstallHooks })
        $closed = $result.Count -gt 0 -and $result[-1] -is [bool] -and $result[-1]
        if (Test-Path -LiteralPath $LifecycleManifest -PathType Leaf) { Set-RecoveryPending }
    }
    if (Test-RecoveryPending) {
        # While the lock is held, hooks do not cold-start a gateway and follow
        # their outage mode, which the config may set open. So the lock stays
        # only on proof: this run closed every hook (Close-UnfinishedInstallHooks)
        # and afterwards no gateway or watchdog of this install runs, by
        # gateway.pid and by image (Get-InstallGatewayState). A gateway still
        # running was left alone by a refusal, survived a stop that failed, or
        # was started by a recovery whose proof failed; it renders its own
        # hooks, and once it exits a kept lock would leave them on their outage
        # mode. Without that proof the lock goes, so hooks cold-start the
        # gateway as before 1.0.4, and the record stays for the next run.
        $state = Get-InstallGatewayState
        if ($state -ne "down" -or -not $closed) {
            $accept = $Run.ContainsKey("UnprovenReplacement") -and $Run.UnprovenReplacement
            $retry = if ($accept) { Get-LifecycleNextStep -Accept } else { Get-LifecycleNextStep }
            $why = if ($state -eq "running") { "its gateway is still running and can rewrite its hooks" }
                elseif ($state -eq "unknown") { "this run cannot tell whether its gateway is still running" }
                else { "this run could not prove every agent hook closed" }
            Write-Warn ("The earlier install is not finished, but $why, so the install lock is released " +
                "and the hooks start or keep using that gateway. Finish it with: $retry")
            $Run.UndoPending = $false
            $Run.RestorePending = $false
        }
    }
    Close-InstallLock
}

function Get-RestoredNote {
    if (Test-RecoveryPending) { return "Your previous install is not fully back (see above); run the installer again to finish restoring it." }
    if (-not $PrevVersion) { return "Nothing was left installed." }
    if ($Run.OldGatewayDown) { return "Your previous install is back, but its gateway is not running (see above)." }
    return "Your previous install is back."
}

function Get-ExternalConfig {
    # DEFENSECLAW_CONFIG can name a config outside the data dir, which the
    # migration changes too.
    $config = [string]$env:DEFENSECLAW_CONFIG
    if (-not $config -or -not (Test-Path -LiteralPath $config -PathType Leaf)) { return "" }
    $config = (Resolve-Path -LiteralPath $config).ProviderPath
    if ($config.StartsWith($DataDir.TrimEnd("\") + "\", [StringComparison]::OrdinalIgnoreCase)) { return "" }
    return $config
}

function Save-ExternalConfig([string]$Slot) {
    $config = Get-ExternalConfig
    if (-not $config) { return }
    New-Item -ItemType Directory -Path (Join-Path $Slot "config") -Force | Out-Null
    Copy-Kept $config (Join-Path $Slot "config")
    Set-Content -LiteralPath (Join-Path $Slot "CONFIG") -Value $config -Encoding UTF8
}

function Restore-ExternalConfig([string]$Slot) {
    $config = Read-Text (Join-Path $Slot "CONFIG")
    if ($config) {
        $saved = Join-Path $Slot "config\$(Split-Path -Leaf $config)"
        Copy-Kept $saved (Split-Path -Parent $config)
        if ((Get-Sha256 $saved) -cne (Get-Sha256 $config)) { throw "The restored config at $config does not match $saved" }
    }
}

function Test-ConnectorRecoveryArtifactName([string]$Name) {
    # Keep the reserved namespace opaque: a malformed or future receipt is
    # evidence too, never an instruction for the installer to replay.
    return $Name -like ".defenseclaw-cas-*" -or $Name -like ".tmp-cas-*"
}

function Save-FailedConnectorRecovery([string]$Failed) {
    # The gateway can fail after changing an agent config outside DataDir.
    # Its private CAS receipts are the ownership evidence for the retained
    # external artifacts. They must outlive cleanup of a failed environment.
    $data = Join-Path $Failed "data"
    if (-not (Test-Path -LiteralPath $Failed)) { return }
    $root = Get-Item -LiteralPath $Failed -Force -ErrorAction Stop
    if (-not $root.PSIsContainer -or ($root.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "Refusing connector recovery cleanup through $Failed; the failed copy was kept"
    }
    if (-not (Test-Path -LiteralPath $data)) { return }
    $source = Get-Item -LiteralPath $data -Force -ErrorAction Stop
    if (-not $source.PSIsContainer -or ($source.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "Refusing connector recovery cleanup through $data; the failed copy was kept"
    }
    $evidence = @(Get-ChildItem -LiteralPath $data -Force -ErrorAction Stop | Where-Object {
        Test-ConnectorRecoveryArtifactName $_.Name
    } | Sort-Object Name)
    if (-not $evidence.Count) { return }
    foreach ($entry in $evidence) {
        if ($entry.PSIsContainer -or ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw "Connector recovery evidence is not a regular file: $($entry.FullName); the failed copy was kept"
        }
    }

    $backups = Join-Path $DataDir "backups"
    if (-not (Test-Path -LiteralPath $backups)) { New-Item -ItemType Directory -Path $backups -ErrorAction Stop | Out-Null }
    $parent = Get-Item -LiteralPath $backups -Force -ErrorAction Stop
    if (-not $parent.PSIsContainer -or ($parent.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "Refusing connector recovery archive through $backups; the failed copy was kept"
    }
    $keep = Join-Path $backups ("connector-recovery-" + [Guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $keep -ErrorAction Stop | Out-Null
    $user = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $secure = New-Object Security.AccessControl.DirectorySecurity
    $secure.SetOwner($user)
    $secure.SetAccessRuleProtection($true, $false)
    foreach ($sid in @($user, (New-Object Security.Principal.SecurityIdentifier "S-1-5-18"))) {
        $secure.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule $sid, "FullControl", "ContainerInherit, ObjectInherit", "None", "Allow"))
    }
    Set-DirectoryAcl $keep $secure
    $note = @"
These opaque connector transaction files came from the failed install at $Failed.
Their original stable state directory is $DataDir. They are not active recovery state.
Keep the corresponding external .tmp-cas-* files beside the agent configuration.
Do not copy these receipts into the restored data directory or replace agent settings by hand.
Recovery must validate the recorded directory, file identities and metadata before changing anything.
"@
    [IO.File]::WriteAllText((Join-Path $keep "README.txt"), $note)
    Write-Warn "Keeping failed connector transaction evidence in $keep; external agent settings may still need recovery"
    try {
        # Rename on the same volume: retain receipt file identities and ACLs.
        foreach ($entry in $evidence) { Move-Path $entry.FullName (Join-Path $keep $entry.Name) }
    } catch {
        throw "Could not preserve all connector recovery evidence in $keep; keep that archive and $Failed. $($_.Exception.Message)"
    }
    Write-Info "The archived receipts are inactive; keep external .tmp-cas-* artifacts and do not restore receipts or agent settings by hand"
}

function Remove-FailedInstall([string]$Failed) {
    # On any preservation failure, do not reach the destructive cleanup.
    Save-FailedConnectorRecovery $Failed
    Remove-Tree $Failed
}

function New-FailedInstallDirectory {
    # A retained failed copy may have the same second-resolution timestamp.
    # Never let the destructive initializer reuse it, even after archiving
    # its evidence failed. Create-new also refuses a pre-existing leaf.
    $failed = Join-Path $DataDir (".failed-" + (Get-Date -Format "yyyyMMddTHHmmss") + "-" + [Guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $failed -ErrorAction Stop | Out-Null
    $acl = Get-Acl -LiteralPath $failed
    $acl.SetAccessRuleProtection($true, $true)
    Set-DirectoryAcl $failed $acl
    return $failed
}

function Restore-Slot([string]$Slot) {
    # Keep a write-ahead move plan in the marked snapshot. A failed rename,
    # or an interruption after a rename but before its checkpoint, must be
    # resumable without moving already restored data aside a second time.
    $planPath = Join-Path $Slot "RESTORE.json"
    $failed = ""
    $digest = {
        param([string]$Path)
        $root = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        $items = @($root)
        if ($root.PSIsContainer) { $items += @(Get-ChildItem -LiteralPath $Path -Force -Recurse -ErrorAction Stop | Sort-Object FullName) }
        $lines = foreach ($item in $items) {
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Cannot prove restored contents through $($item.FullName)" }
            $name = $item.FullName.Substring($root.FullName.Length)
            if ($item.PSIsContainer) { "directory:$name" } else { "file:$name`:$(Get-Sha256 $item.FullName)" }
        }
        $hash = [Security.Cryptography.SHA256]::Create()
        try { return ([BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes(($lines -join "`n"))))).Replace("-", "").ToLowerInvariant() }
        finally { $hash.Dispose() }
    }
    $save = {
        [IO.File]::WriteAllText("$planPath.new", ($plan | ConvertTo-Json -Depth 6), (New-Object Text.UTF8Encoding $false))
        if (Test-Path -LiteralPath $planPath) {
            [IO.File]::Replace("$planPath.new", $planPath, "$planPath.old")
            Remove-Item -LiteralPath "$planPath.old" -Force -ErrorAction Stop
        }
        else { [IO.File]::Move("$planPath.new", $planPath) }
    }
    try {
        # Programs first: a program that cannot go back (a hook of the failed
        # install still running refuses its in-place switch) stops the
        # restore before any data or environment moves, with the slot and its
        # COMPLETE marker kept. Restore-BinDir is idempotent, so a resumed
        # restore runs it again and proves the bytes.
        Restore-BinDir (Join-Path $Slot "bin")
        if (Test-Path -LiteralPath $planPath) {
            $plan = [IO.File]::ReadAllText($planPath) | ConvertFrom-Json -ErrorAction Stop
            if ($plan.Schema -ne 1 -or $plan.FailedName -notmatch '^\.failed-[A-Za-z0-9-]+$') { throw "Invalid restore plan at $planPath" }
            $failed = Join-Path $DataDir $plan.FailedName
        } else {
            $failed = New-FailedInstallDirectory
            New-Item -ItemType Directory -Path (Join-Path $failed "data") -ErrorAction Stop | Out-Null
            $moves = New-Object System.Collections.Generic.List[object]
            $add = {
                param([string]$From, [string]$To)
                if (Test-Path -LiteralPath $From) { $moves.Add(@{ From = $From; To = $To; Digest = (& $digest $From); Done = $false }) }
            }
            $liveData = @(Get-DataEntries)
            $savedData = @(Get-ChildItem -LiteralPath (Join-Path $Slot "data") -Force -ErrorAction Stop)
            # Move receipts, never copy them: their file identities are part
            # of connector recovery proof. Ordinary data follows that phase.
            foreach ($entry in @($liveData | Where-Object { Test-ConnectorRecoveryArtifactName $_.Name })) {
                & $add $entry.FullName (Join-Path $failed "data\$($entry.Name)")
            }
            foreach ($entry in @($savedData | Where-Object { Test-ConnectorRecoveryArtifactName $_.Name })) {
                & $add $entry.FullName (Join-Path $DataDir $entry.Name)
            }
            foreach ($part in @(@($Venv, "venv"), @($InstallerDir, "installer"))) {
                & $add $part[0] (Join-Path $failed $part[1])
                & $add (Join-Path $Slot $part[1]) $part[0]
            }
            foreach ($entry in @($liveData | Where-Object { -not (Test-ConnectorRecoveryArtifactName $_.Name) })) {
                & $add $entry.FullName (Join-Path $failed "data\$($entry.Name)")
            }
            foreach ($entry in @($savedData | Where-Object { -not (Test-ConnectorRecoveryArtifactName $_.Name) })) {
                & $add $entry.FullName (Join-Path $DataDir $entry.Name)
            }
            $plan = @{ Schema = 1; FailedName = (Split-Path -Leaf $failed); Moves = @($moves.ToArray()) }
            & $save
        }
        $parent = Get-Item -LiteralPath $failed -Force -ErrorAction Stop
        if (-not $parent.PSIsContainer -or ($parent.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw "Invalid failed-copy directory $failed" }
        $prefix = [IO.Path]::GetFullPath($DataDir).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
        foreach ($move in $plan.Moves) {
            foreach ($path in @($move.From, $move.To)) {
                if (-not [IO.Path]::GetFullPath($path).StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { throw "Restore path is outside $DataDir" }
            }
            if ($move.Done) { continue }
            if ((Test-Path -LiteralPath $move.From) -and -not (Test-Path -LiteralPath $move.To)) {
                if ((& $digest $move.From) -cne $move.Digest) { throw "Restore source changed: $($move.From)" }
                Move-Path $move.From $move.To 60
            }
            if ((Test-Path -LiteralPath $move.From) -or -not (Test-Path -LiteralPath $move.To) -or
                (& $digest $move.To) -cne $move.Digest) { throw "Could not prove the restore move from $($move.From) to $($move.To)" }
            $move.Done = $true
            & $save
        }
        Restore-ExternalConfig $Slot
        Assert-BinDirRestored (Join-Path $Slot "bin")
        foreach ($move in $plan.Moves) {
            if ((& $digest $move.To) -cne $move.Digest) { throw "Restored contents changed: $($move.To)" }
        }
        # Retire COMPLETE only after all data and environment proofs pass.
        # Partial cleanup can then never masquerade as a restorable snapshot.
        Remove-Item -LiteralPath (Join-Path $Slot "COMPLETE") -Force -ErrorAction Stop
        Invoke-Quietly { Remove-Tree $Slot }
        foreach ($old in @(Get-ChildItem -LiteralPath $DataDir -Directory -Force -Filter ".failed-*" -ErrorAction Stop)) {
            if ($old.Name -ne $plan.FailedName) { Invoke-Quietly { Remove-FailedInstall $old.FullName } }
        }
        return $failed
    } catch {
        $retry = Get-LifecycleNextStep
        # The slot keeps COMPLETE: the caller keeps the install locked
        # (RestorePending, Close-InstallLock) and the hooks closed
        # (Close-UnfinishedInstallHooks) until a run proves the restore.
        throw ("$($_.Exception.Message); restoration is incomplete: the previous install's copy was kept in $Slot$(if ($failed) { " and the failed install in $failed" }). " +
            "Close the program holding the reported path. Run the installer again to finish restoring it: $retry")
    }
}

function Close-UnfinishedInstallHooks {
    # A run that stops with its install unfinished (a restore or rollback a
    # running hook refused: Restore-Slot, Switch-WithPrevious) leaves its
    # snapshot or rollback hold, programs and data that do not match, and the
    # gateway down. Before the install lock goes, close every hook, an outage
    # open the config chooses included, until the gateway renders them again
    # (the next run of the installer, or a gateway start). The gateway in
    # place, or a saved one, that has 'refresh-fail-modes --closed' does it.
    # A lifecycle record still pending (a restore not proven yet, whose
    # snapshot may already be consumed) is an unfinished install too.
    # True only when the hooks are closed (or there are none) with no
    # gateway of this install running: Finish-InstallLock keeps the lock
    # on nothing less.
    $record = Get-Variable -Name LifecycleManifest -ValueOnly -ErrorAction SilentlyContinue
    $closer = Get-Variable -Name LifecycleCloser -ValueOnly -ErrorAction SilentlyContinue
    $unfinished = @(@((Join-Path $DataDir "previous.new"), (Join-Path $DataDir ".repair"), (Join-Path $DataDir ".rollback-hold")) |
        Where-Object { Test-Path -LiteralPath $_ })
    $pending = $record -and (Test-Path -LiteralPath $record -PathType Leaf)
    if (-not $unfinished.Count -and -not $pending) { return $false }
    if ((Get-InstallGatewayState) -ne "down") { return $false }
    if (-not (Test-Path -LiteralPath (Join-Path $DataDir "hooks") -PathType Container)) { return $true }
    $gateways = @()
    if ($closer) { $gateways += Join-Path $closer "defenseclaw-gateway.exe" }
    $gateways += @((Join-Path $BinDir "defenseclaw-gateway.exe")) +
        @($unfinished | ForEach-Object { (Join-Path $_ "closer\defenseclaw-gateway.exe"), (Join-Path $_ "bin\defenseclaw-gateway.exe") }) +
        @(Join-Path $Previous "bin\defenseclaw-gateway.exe")
    if (Close-AllHooks $gateways) {
        Write-Warn "The install is not finished, so every agent hook blocks tool calls until the gateway runs again. Run the installer again to finish it"
        return $true
    }
    Write-Err "The install is not finished and the agent hooks could not be closed. Run the installer again to finish it"
    return $false
}

function Clear-SetupDataDir([string]$Failed) {
    # DefenseClaw Setup's gateway re-applies the permissions of its whole data
    # folder before it starts and gives its child 5 seconds, so the failed
    # copy and uv's cache (about 28,000 files) kept it from starting after a
    # restore (GAP-1839). Setup cannot use either of them.
    Invoke-Quietly { Remove-FailedInstall $Failed }
    Invoke-Quietly { Remove-Tree (Join-Path $DataDir ".uv") }
}

function Restore-Snapshot {
    Clear-StagedRelease
    $keepStopped = Test-Path -LiteralPath (Join-Path $Snap "GATEWAY_RESTART_UNPROVEN")
    Save-LifecycleCloser $Snap
    try { $failed = Restore-Slot $Snap } catch {
        # The snapshot stays marked complete, so the next run restores it.
        $Run.RestorePending = $true
        Write-Err $_.Exception.Message
        Die "Could not restore $previousLabel; run the installer again to finish restoring it. Log: $($Run.Log)"
    }
    if ($Setup) {
        Clear-SetupDataDir $failed
    } elseif (-not $PrevVersion) {
        # A first install has nothing to look back at, and the copy it kept
        # (about 2 GB) held a full disk full for every account (GAP-1883).
        Invoke-Quietly { Remove-FailedInstall $failed }
    }
    Restart-Old -KeepStopped:$keepStopped
    try { Assert-LifecycleRestored (Get-Variable -Name Manifest -ValueOnly -ErrorAction SilentlyContinue) -KeepStopped:$keepStopped } catch {
        Write-Err $_.Exception.Message
        Die "DefenseClaw $Ver was not installed, and the previous install is not proven back (see above). Log: $($Run.Log)"
    }
    if (-not $PrevVersion) { Write-KeptUvCache; return }
    if ($Setup) {
        if (Test-Path -LiteralPath $failed) {
            Write-Warn "The failed install copy remains at $failed; keep it until connector recovery evidence is safely preserved"
        } else {
            Write-Info "The failed $Ver install and its download cache were removed, so DefenseClaw Setup's gateway can start"
        }
        return
    }
    $bytes = Get-TreeSize $failed
    Write-Warn ("The failed $Ver install was kept in $failed ({0:N1} MB) for troubleshooting" -f ([double]$bytes / 1MB))
    Write-Info "Your previous install and its data are back; keep this copy until any connector recovery is complete"
}

function Save-RolledBackData {
    # A rollback parks the data written since the upgrade in previous\, and a
    # 0.x install kept there holds the only copy of the audit history 1.0 does
    # not carry over (GAP-1360). Keep either when a later upgrade reuses the slot.
    if (-not (Test-Path -LiteralPath (Join-Path $Previous "data"))) { return }
    $version = Read-Text (Join-Path $Previous "VERSION")
    if (Test-Path -LiteralPath (Join-Path $Previous "ROLLED_BACK")) {
        $label = "rolled-back"
    } elseif ((Test-Version $version) -and [version]$version -lt [version]"1.0.0" -and (Test-Path -LiteralPath (Join-Path $Previous "data\audit.db"))) {
        $label = "audit-history"
    } else {
        return
    }
    $kept = Join-Path $DataDir ("backups\$label-$version-" + (Get-Date -Format "yyyyMMddTHHmmss"))
    New-Item -ItemType Directory -Path (Join-Path $DataDir "backups") -Force | Out-Null
    Move-Path (Join-Path $Previous "data") $kept
    $bytes = Get-TreeSize $kept
    $what = if ($label -eq "rolled-back") { "the data from before the last rollback" } else { "the audit history DefenseClaw $version recorded" }
    Write-Info ("Kept $what in $kept ({0:N1} MB)" -f ([double]$bytes / 1MB))
    Write-Info "It is not used again; once you no longer need its audit history, remove it with: cmd /c rd /s /q `"$kept`""
}

function Save-Live([string]$Slot) {
    # Set the live install aside in $Slot\{bin,data,venv,installer}: binaries
    # are copied (they may be running), everything else is renamed.
    Copy-BinDir (Join-Path $Slot "bin")
    New-Item -ItemType Directory -Path (Join-Path $Slot "data") -Force | Out-Null
    foreach ($entry in Get-DataEntries) { Move-Path $entry.FullName (Join-Path $Slot "data\$($entry.Name)") }
    if (Test-Path -LiteralPath $Venv) { Move-Path $Venv (Join-Path $Slot "venv") 60 }
    if (Test-Path -LiteralPath $InstallerDir) { Move-Path $InstallerDir (Join-Path $Slot "installer") }
    Save-ExternalConfig $Slot
}

function Restore-Live([string]$Slot) {
    # Make $Slot the live install again (the inverse of Save-Live).
    Restore-BinDir (Join-Path $Slot "bin")
    Restore-LiveTree $Slot
    Restore-ExternalConfig $Slot
}

function Restore-LiveTree([string]$Slot) {
    # Move $Slot's data, venv and installer back into place. Alone it undoes a
    # Save-Live that failed part-way: that one only copied the binaries.
    foreach ($entry in @(Get-ChildItem -LiteralPath (Join-Path $Slot "data") -Force -ErrorAction SilentlyContinue)) {
        Move-Path $entry.FullName (Join-Path $DataDir $entry.Name)
    }
    if ((Test-Path -LiteralPath (Join-Path $Slot "venv")) -and -not (Test-Path -LiteralPath $Venv)) { Move-Path (Join-Path $Slot "venv") $Venv 60 }
    if ((Test-Path -LiteralPath (Join-Path $Slot "installer")) -and -not (Test-Path -LiteralPath $InstallerDir)) {
        Move-Path (Join-Path $Slot "installer") $InstallerDir
    }
}

function Move-LiveTo([string]$Slot) {
    # Move what Restore-Live brought in from $Slot back into it. Only valid
    # while the install it replaced is set aside in full elsewhere.
    New-Item -ItemType Directory -Path (Join-Path $Slot "data") -Force | Out-Null
    foreach ($entry in Get-DataEntries) { Move-Path $entry.FullName (Join-Path $Slot "data\$($entry.Name)") }
    if (Test-Path -LiteralPath $Venv) { Move-Path $Venv (Join-Path $Slot "venv") 60 }
    if (Test-Path -LiteralPath $InstallerDir) { Move-Path $InstallerDir (Join-Path $Slot "installer") }
}

function Resume-InterruptedRun {
    # A run killed mid-swap (closed laptop, power loss) leaves its snapshot
    # behind. Put the install it saved back before doing anything else, so
    # re-running the installer is always the recovery. The lifecycle record
    # (Write-LifecycleManifest) says what that install was; it goes only once
    # the restore is proven against it (Assert-LifecycleRestored).
    $manifest = Read-LifecycleManifest
    # A snapshot or rollback hold may be consumed during this recovery. A
    # later empty-record refusal must not release a lock after such a change.
    $hadRecoveryWork = (Test-Path -LiteralPath (Join-Path $DataDir "previous.new")) -or
        (Test-Path -LiteralPath (Join-Path $DataDir ".repair")) -or
        (Test-Path -LiteralPath (Join-Path $DataDir ".rollback-hold"))
    if ($manifest -and (Get-Field $manifest "Committed")) {
        # The new install was proven before the run stopped: finish moving
        # the previous one aside (Complete-Swap) instead of undoing it.
        foreach ($slot in @((Join-Path $DataDir "previous.new"), (Join-Path $DataDir ".repair"))) {
            if (-not (Test-Path -LiteralPath $slot)) { continue }
            Write-Warn "An earlier install finished but was interrupted while it cleaned up; finishing that"
            foreach ($marker in @("COMPLETE", "HOOK_FIRST", "GATEWAY_RESTART_UNPROVEN")) {
                Remove-Item -LiteralPath (Join-Path $slot $marker) -Force -ErrorAction SilentlyContinue
            }
            Invoke-Quietly { Remove-Tree (Join-Path $slot "closer") }
            if ($slot -eq (Join-Path $DataDir "previous.new") -and (Read-Text (Join-Path $slot "VERSION"))) {
                Remove-Tree $Previous
                Move-Path $slot $Previous
            } else {
                Remove-Tree $slot
            }
        }
        Remove-LifecycleManifest
        $manifest = $null
    }
    foreach ($slot in @((Join-Path $DataDir "previous.new"), (Join-Path $DataDir ".repair"))) {
        if (-not (Test-Path -LiteralPath $slot)) { continue }
        # This installer records the running state before it changes
        # anything (the lifecycle record, and GATEWAY_WAS_RUNNING first in
        # the snapshot); a 1.0.3 or earlier snapshot cut off before COMPLETE
        # may have neither. An installed binary does not prove its gateway
        # ran, so a gateway stopped on purpose stays stopped.
        $runningState = Read-Text (Join-Path $slot "GATEWAY_WAS_RUNNING")
        $wasRunning = $runningState -eq "true"
        if ($manifest) {
            $wasRunning = [bool](Get-Field $manifest "GatewayWasRunning")
        } else {
            if (-not $runningState) {
                Write-Warn "The interrupted installer did not record whether the gateway was running, so it is not started; if it should run, start it with 'defenseclaw-gateway start' once this install finishes"
            }
            $manifest = New-RecoveryManifest $slot $wasRunning
        }
        $state = Join-Path $Staging "hook-runtime-state.json"
        if ((Test-Path -LiteralPath $state) -and -not (Test-Path -LiteralPath $SetupHookState)) { Move-Path $state $SetupHookState }
        if (Test-Path -LiteralPath (Join-Path $slot "COMPLETE")) {
            # An interrupted first install replaced nothing (GAP-2618).
            $firstInstall = -not (Read-Text (Join-Path $slot "VERSION"))
            if ($firstInstall) {
                Write-Warn "An earlier first install was interrupted; removing what it had copied"
            } else {
                Write-Warn "An earlier install was interrupted; restoring the install it replaced"
            }
            if ($manifest -and $manifest.PSObject.Properties["UnprovenReplacement"] -and $manifest.UnprovenReplacement) {
                Stop-UnprovenRecoveryGateway $manifest $slot
            } else {
                [void](Stop-Gateway)
            }
            $keepStopped = Test-Path -LiteralPath (Join-Path $slot "GATEWAY_RESTART_UNPROVEN")
            Save-LifecycleCloser $slot
            $failed = Restore-Slot $slot
            # A DefenseClaw Setup install that was replaced runs its own gateway (GAP-1839).
            $setupInstall = Find-SetupInstall
            $setupBack = $setupInstall -and -not (Test-Path -LiteralPath (Join-Path $BinDir "defenseclaw-gateway.exe"))
            if ($setupBack) { Clear-SetupDataDir $failed }
            # Nothing was installed before, so the copy holds nothing to go back to.
            if ($firstInstall -and -not $setupBack) { Invoke-Quietly { Remove-FailedInstall $failed } }
            if ($keepStopped) {
                $gateway = if ($setupBack) { Join-Path $setupInstall.Root "bin\defenseclaw-gateway.exe" } else { Join-Path $BinDir "defenseclaw-gateway.exe" }
                $gatewayCommand = "& '" + $gateway.Replace("'", "''") + "' start"
                $Run.OldGatewayDown = $wasRunning
                Write-Warn "The previous install is restored with its gateway kept stopped to preserve its hook registration"
                Write-Info "Resolve the earlier startup error (close the agent if its settings are in use), then run: $gatewayCommand"
            } elseif ($wasRunning) {
                Start-RecoveredGateway "restored"
            }
            if ($setupBack -and $manifest) { $manifest.SetupRoot = [string]$setupInstall.Root }
            Assert-LifecycleRestored $manifest -KeepStopped:$keepStopped
            $manifest = $null
            if ($firstInstall -and -not $setupBack) {
                Write-Info "Nothing was left installed"
            } elseif (-not $setupBack) {
                Write-Warn "The interrupted install was kept in $failed"
            }
        } else {
            # The snapshot never finished, so live data was only copied, not changed.
            try { Undo-Snapshot $slot } catch { Set-RecoveryPending "UndoPending"; throw }
            if ($wasRunning -and -not (Get-GatewayProcess)) { Start-RecoveredGateway "recovered" }
            Set-RecoverySetupRoot $manifest
            Assert-LifecycleRestored $manifest
            $manifest = $null
        }
    }
    $hold = Join-Path $DataDir ".rollback-hold"
    # A hold is deleted by renaming it first, so a half-deleted one is never read.
    Remove-Tree "$hold.done"
    $restart = (Read-Text (Join-Path $hold "GATEWAY_WAS_RUNNING")) -eq "true"
    if (-not $manifest -and (Test-Path -LiteralPath $hold)) {
        # A rollback hold an installer from before the lifecycle record left:
        # record the install it goes back to, so a failed restart is retried.
        $finished = Test-Path -LiteralPath (Join-Path $hold "ROLLED_BACK")
        $from = if (-not $finished -and (Test-Path -LiteralPath (Join-Path $hold "STASHED"))) { Join-Path $hold "bin" } else { $BinDir }
        $wanted = $restart -or ($finished -and (Read-Text (Join-Path $hold "START_AFTER")) -eq "true")
        $manifest = New-RecoveryManifest $hold $wanted -BinsFrom $from -NoConfig
    }
    if (Test-Path -LiteralPath (Join-Path $hold "ROLLED_BACK")) {
        # The rollback itself had finished; only renaming its hold was left.
        # START_AFTER is its own decision; previous\ may be half deleted.
        Write-Warn "An earlier rollback was interrupted; finishing it"
        $restart = $restart -or (Read-Text (Join-Path $hold "START_AFTER")) -eq "true"
        Remove-Tree $Previous
        Move-Path $hold $Previous
        # The rollback's record proves its target, not the install it left.
        if ($manifest -and (Get-Field $manifest "Operation") -eq "rollback") {
            if ($restart -and -not (Get-GatewayProcess)) { Start-RecoveredGateway "rolled-back" }
            $legacyTarget = [string](Get-Field $manifest "To") -match '^(?:0\.8\.10|1\.0\.[0-3])$'
            $problems = @(Wait-LifecycleProof (Get-Field $manifest "TargetBins") $restart -AllowLegacyStatus:$legacyTarget)
            if ($problems.Count) {
                Set-RecoveryPending
                Die "The finished rollback is not proven: $($problems -join '; '). Fix the cause, then run: $(Get-LifecycleNextStep)"
            }
            Remove-LifecycleManifest
            $manifest = $null
        }
    } elseif (Test-Path -LiteralPath $hold) {
        Write-Warn "An earlier rollback was interrupted; restoring the install it started from"
        [void](Stop-Gateway)
        if (Test-Path -LiteralPath (Join-Path $hold "STASHED")) {
            # The live install was set aside in full, so anything live now came
            # from previous\, unless the undo had already returned it (RETURNED).
            $returned = Join-Path $hold "RETURNED"
            if (-not (Test-Path -LiteralPath $returned)) {
                Move-LiveTo $Previous
                Set-Content -LiteralPath $returned -Value "" -Encoding Ascii
            }
            Restore-Live $hold
        } else {
            # Setting it aside stopped part-way; the live binaries were only copied.
            Restore-LiveTree $hold
        }
        Remove-Hold $hold
    } else {
        $restart = $false
    }
    # A record with no snapshot left: the run stopped after its record and
    # before its first change, or after its restore and before the proof.
    if ($manifest -and (Get-Field $manifest "Operation") -eq "rollback") {
        # A rollback whose swap finished (its hold already renamed into
        # previous\) and that stopped before its proof: the live install is
        # its target, proven as the finished rollback is.
        $target = Get-Field $manifest "TargetBins"
        if (Test-SameBinaries (Get-BinariesState $BinDir) $target) {
            $wanted = [bool](Get-Field $manifest "StartAfter")
            if ($wanted -and -not (Get-GatewayProcess)) { Start-RecoveredGateway "rolled-back" }
            $legacyTarget = [string](Get-Field $manifest "To") -match '^(?:0\.8\.10|1\.0\.[0-3])$'
            $problems = @(Wait-LifecycleProof $target $wanted -AllowLegacyStatus:$legacyTarget)
            if ($problems.Count) {
                Set-RecoveryPending
                Die "The finished rollback is not proven: $($problems -join '; '). Fix the cause, then run: $(Get-LifecycleNextStep)"
            }
            Remove-LifecycleManifest
            return
        }
    }
    $recordedBins = if ($manifest) { ConvertTo-Map (Get-Field $manifest "Bins") } else { @{} }
    $liveBinNames = @()
    if ($manifest) { $liveBinNames = @($ManagedBinaries | Where-Object { Test-Path -LiteralPath (Join-Path $BinDir $_) -PathType Leaf }) }
    if ($manifest -and $recordedBins.Count -and -not $liveBinNames.Count -and -not (Find-SetupInstall)) {
        # The install the record names was uninstalled since (none of its
        # programs is left, and no snapshot): nothing to restore or start.
        Write-Warn "The install an earlier run recorded is no longer there (uninstalled); its record is dropped"
        Remove-LifecycleManifest
        return
    }
    if ($manifest -and -not $recordedBins.Count -and $liveBinNames.Count) {
        # No binary was present when the interrupted first install wrote its
        # record. A legacy installer can populate the folder without reading
        # it. Those bytes are not a proven restore; -AcceptCurrentInstall
        # accepts them as hashed here, before anything stops.
        $added = @(Test-LifecycleProof $recordedBins $false -RequireProtected $false)
        $Run.UnprovenReplacementUnchanged = -not $hadRecoveryWork
        $override = [bool](Get-Variable -Name AcceptCurrentInstall -ValueOnly -ErrorAction SilentlyContinue)
        if (-not $override -or [bool](Get-Variable -Name Rollback -ValueOnly -ErrorAction SilentlyContinue)) {
            throw ("The previous install is not proven back: $($added -join '; '). An older installer added programs after this first install recorded none; its running gateway was left alone. " +
                "The record stays in $LifecycleManifest. To install this release over them, run: $(Get-LifecycleNextStep -Accept)")
        }
        $wasRunningUnproven = [bool](Get-GatewayProcess) -or [bool](Get-Field $manifest "ReplacementGatewayWasRunning")
        if ($wasRunningUnproven -and -not (Get-Field $manifest "ReplacementGatewayWasRunning")) {
            # Record the observed running state before the checked release
            # closes its hooks and stops it later. Recovery then knows whether
            # the replacement gateway must be started after a power loss.
            $manifest | Add-Member -NotePropertyName ReplacementGatewayWasRunning -NotePropertyValue $true -Force
            Write-DurableText $LifecycleManifest ($manifest | ConvertTo-Json -Depth 4)
        }
        $Run.UnprovenReplacement = $manifest
        $Run.UnprovenGatewayWasRunning = $wasRunningUnproven
        $Run.UnprovenAcceptedBins = Get-BinariesState $BinDir
        Write-Warn "An older installer added programs after the interrupted first install recorded none ($($added -join '; ')); they are accepted as they are now (-AcceptCurrentInstall). Its gateway stays running while this release is staged; if this release is not installed and proven, they are restored and proven instead"
        return
    }
    if ($manifest -and $recordedBins.Count -and -not (Test-SameBinaries (Get-BinariesState $BinDir) $recordedBins)) {
        # Another installer (an older release's, which does not read the
        # record) replaced the recorded programs since: nothing proves them,
        # so they are never started. -AcceptCurrentInstall retires the record
        # and this run installs its staged, verified release over them; a
        # rollback has no proven install to go back from.
        $replaced = @(Test-LifecycleProof $recordedBins $false -RequireProtected $false)
        $override = [bool](Get-Variable -Name AcceptCurrentInstall -ValueOnly -ErrorAction SilentlyContinue)
        if ($override -and -not [bool](Get-Variable -Name Rollback -ValueOnly -ErrorAction SilentlyContinue)) {
            Write-Warn "The programs an earlier run recorded were replaced since ($($replaced -join '; ')); its record is retired (-AcceptCurrentInstall) and they are not started: this release is installed over them"
            Remove-LifecycleManifest
            return
        }
        # Unless a snapshot or rollback hold was recovered above, this refusal
        # stopped and changed nothing: the other installer's programs stay as
        # they are, so the lock goes and only the record stays (as for an
        # empty record above). Their hooks can then cold-start their gateway.
        $Run.UnprovenReplacementUnchanged = -not $hadRecoveryWork
        if (-not $Run.UnprovenReplacementUnchanged) { Set-RecoveryPending }
        throw ("The previous install is not proven back: $($replaced -join '; '). Another installer replaced the programs it recorded, so they are not started. " +
            "The record of it stays in $LifecycleManifest. To install this release over them, run: $(Get-LifecycleNextStep -Accept)")
    }
    if ($manifest) { $restart = $restart -or [bool](Get-Field $manifest "GatewayWasRunning") }
    if ($restart -and -not (Get-GatewayProcess)) { Start-RecoveredGateway "recovered" }
    Set-RecoverySetupRoot $manifest
    Assert-LifecycleRestored $manifest -Outlived
}

function Set-RecoverySetupRoot($Manifest) {
    # A restored DefenseClaw Setup install runs its own gateway (GAP-1839):
    # the proof of the restore checks that one.
    if (-not $Manifest -or [string](Get-Field $Manifest "SetupRoot")) { return }
    $setupInstall = Find-SetupInstall
    if ($setupInstall -and -not (Test-Path -LiteralPath (Join-Path $BinDir "defenseclaw-gateway.exe") -PathType Leaf)) {
        $Manifest.SetupRoot = [string]$setupInstall.Root
    }
}

function Start-RecoveredGateway([string]$What) {
    # Recovery goes on only once the gateway it put back answers; until then
    # the lifecycle record stays, so every retry starts the same gateway again.
    # A DefenseClaw Setup install has no ~\.local\bin gateway: it runs its own
    # (GAP-1839), with its hooks' state back in place.
    $setupInstall = Find-SetupInstall
    if ($setupInstall -and -not (Test-Path -LiteralPath (Join-Path $BinDir "defenseclaw-gateway.exe") -PathType Leaf)) {
        $state = Join-Path $Staging "hook-runtime-state.json"
        if ((Test-Path -LiteralPath $state) -and -not (Test-Path -LiteralPath $SetupHookState)) { Move-Path $state $SetupHookState }
        Write-Info "Starting DefenseClaw Setup's gateway"
        Start-SetupGateway $setupInstall.Root
        $gateway = Join-Path $setupInstall.Root "bin\defenseclaw-gateway.exe"
        for ($try = 0; $try -lt 10; $try++) {
            if ((Get-GatewayProcess) -and (Invoke-Native $gateway @("status") -Quiet) -eq 0) { return }
            Start-Sleep -Seconds 3
        }
        $startup = Join-Path $setupInstall.Root "bin\defenseclaw-startup.exe"
        $command = if (Test-Path -LiteralPath $startup) { "& '$startup'" } else { "& '$gateway' start" }
        Die "The $What gateway of DefenseClaw Setup did not become healthy; start it with $command, then run the installer again"
    }
    if ((Start-Gateway) -in @(0, 3)) { return }
    Die "The $What gateway did not become healthy; run 'defenseclaw-gateway start', then run the installer again"
}

function Remove-Hold([string]$Hold) {
    # The rename makes the hold vanish at once: recovery must never find a
    # half-deleted one and read its markers.
    Move-Path $Hold "$Hold.done"
    Remove-Tree "$Hold.done"
}

function Save-Installer {
    New-Item -ItemType Directory -Path $InstallerDir -Force | Out-Null
    $next = Join-Path $InstallerDir ".install.ps1.new"
    if ((Get-Asset "install.ps1" $next) -and (Test-Checksum $next "install.ps1")) {
        Move-Item -LiteralPath $next -Destination (Join-Path $InstallerDir "install.ps1") -Force
    } elseif ($RunAsFile -and (Select-String -LiteralPath $PSCommandPath -SimpleMatch -Quiet "`$DcVersion = `"$Ver`"")) {
        Copy-Item -LiteralPath $PSCommandPath -Destination (Join-Path $InstallerDir "install.ps1") -Force
    }
    Remove-Item -LiteralPath $next -Force -ErrorAction SilentlyContinue
}

function Complete-Swap {
    # The new install is live: a run killed from here on must not restore the old one.
    Remove-Item -LiteralPath (Join-Path $Snap "COMPLETE") -Force
    # Deleting the old venv and staging copies takes a minute or two on Windows (GAP-1347).
    # A first install has no previous install, only its staging copies (GAP-1827).
    if ($PrevVersion) { Write-Info "Cleaning up the previous install's files (this can take a minute or two)" }
    else { Write-Info "Removing the staging files" }
    # The closer (Install-HookFirst) is only for an unfinished install.
    Invoke-Quietly { Remove-Tree (Join-Path $Snap "closer") }
    Invoke-Quietly {
        if ($Snap -eq (Join-Path $DataDir "previous.new") -and $PrevVersion) {
            Save-RolledBackData
            Remove-Tree $Previous
            Move-Path $Snap $Previous
        } else {
            Remove-Tree $Snap
        }
    }
    if ($Setup) { Remove-SetupInstall }
    Save-Installer
    foreach ($leftover in @($Staging, (Join-Path $DataDir ".upgrade-recovery"), (Join-Path $DataDir ".upgrade-receipts"),
            (Join-Path $env:USERPROFILE ".defenseclaw-install-custody"),
            (Join-Path (Split-Path -Parent $DataDir) ".defenseclaw-install-custody"))) {
        Invoke-Quietly { Remove-Tree $leftover }
    }
    Get-ChildItem -LiteralPath ([IO.Path]::GetTempPath()) -Filter ".defenseclaw-install-custody-*" -Directory -Force -ErrorAction SilentlyContinue |
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    Write-Ok "Installed DefenseClaw $Ver"
}

function Switch-WithPrevious([string]$Current, [bool]$GatewayWasRunning, [bool]$StartAfter) {
    # Exchange the live install and previous\ by renaming, so a second
    # -Rollback rolls forward again. Each half undoes itself on failure.
    # Returns 0 when swapped, 1 when the current install is back in place, 2
    # when it could not be put back (the next run of the installer recovers it).
    $hold = Join-Path $DataDir ".rollback-hold"
    New-InstallDirectory $hold
    # First, so recovery from any later point knows the version and gateway state.
    Set-Content -LiteralPath (Join-Path $hold "VERSION") -Value $Current -Encoding Ascii
    Set-Content -LiteralPath (Join-Path $hold "GATEWAY_WAS_RUNNING") -Value ([string]$GatewayWasRunning).ToLowerInvariant() -Encoding Ascii
    try { Save-Live $hold } catch {
        Write-Err $_.Exception.Message
        try { Restore-LiveTree $hold } catch {
            Write-Err "Could not set the current install aside or put it back; run the installer again to recover it"
            return 2
        }
        Invoke-Quietly { Remove-Hold $hold }
        Write-Err "Could not set the current install aside; nothing was changed"
        return 1
    }
    Set-Content -LiteralPath (Join-Path $hold "STASHED") -Value "" -Encoding Ascii
    try { Restore-Live $Previous } catch {
        Write-Err $_.Exception.Message
        # Restore-Live only copies previous\bin, so returning the rest restores previous\.
        # RETURNED tells an interrupted run's recovery that previous\ is whole again.
        try { Move-LiveTo $Previous; Set-Content -LiteralPath (Join-Path $hold "RETURNED") -Value "" -Encoding Ascii; Restore-Live $hold } catch {
            Write-Err "Could not restore the previous install or put the current one back; run the installer again to recover it"
            return 2
        }
        Invoke-Quietly { Remove-Hold $hold }
        Write-Err "Could not restore the previous install; the current one is back in place"
        return 1
    }
    # Its data was written after the upgrade being undone: a later upgrade keeps it.
    Set-Content -LiteralPath (Join-Path $hold "START_AFTER") -Value ([string]$StartAfter).ToLowerInvariant() -Encoding Ascii
    Set-Content -LiteralPath (Join-Path $hold "ROLLED_BACK") -Value (Get-Date -Format "yyyyMMddTHHmmss") -Encoding Ascii
    Remove-Tree $Previous
    Move-Path $hold $Previous
    return 0
}

# -- First install ------------------------------------------------------------

function Select-Connector {
    Write-Step "Pick an agent to guard"
    for ($index = 0; $index -lt $ConnectorChoices.Count; $index++) {
        Write-Host ("    {0,2}) {1}" -f ($index + 1), $ConnectorChoices[$index])
    }
    # An answer that is neither a number on the list nor a name is asked
    # again, never replaced with another agent (GAP-0333).
    for ($try = 1; $try -le 3; $try++) {
        # Enter, or no console to answer on: no agent. A default never picks
        # one the machine may not have; 'defenseclaw init' finds the installed
        # agents (GAP-0568).
        try { $choice = Read-Host "  Choice (number or name) [default none]" } catch { $choice = "" }
        $answer = "$choice".Trim().ToLowerInvariant()
        if (-not $answer) { $answer = "none" }
        $number = 0
        $picked = ""
        if ([int]::TryParse($answer, [ref]$number) -and $number -ge 1 -and $number -le $ConnectorChoices.Count) {
            $picked = $ConnectorChoices[$number - 1]
        } elseif ($ConnectorChoices -contains $answer) {
            $picked = $answer
        }
        if ($picked) {
            Write-Ok "Connector: $picked"
            return $picked
        }
        if ($try -lt 3) { Write-Warn "'$choice' is not on the list: type a number from 1 to $($ConnectorChoices.Count) or an agent name such as claudecode" }
    }
    Stop-Usage "No agent picked ('$choice' is not on the list). Run the installer again and pick one, or pass -Connector NAME"
}

function Invoke-FirstInstallExtras {
    if ($Connector -and $Connector -ne "none") {
        Set-Content -LiteralPath (Join-Path $DataDir "picked_connector") -Value $Connector -Encoding Ascii
    }
    if ($Quickstart) {
        if (-not $Connector -or $Connector -eq "none") {
            Write-Warn "Quickstart needs a connector; run 'defenseclaw init' when ready"
        } else {
            $quickstartArgs = @("quickstart", "--connector", $Connector)
            if ($QuickstartMode) { $quickstartArgs += @("--mode", $QuickstartMode) }
            $quickstartRc = Invoke-Native (Join-Path $Venv "Scripts\defenseclaw.exe") $quickstartArgs
            if ($quickstartRc -ne 0) {
                # The install stays; the summary names the failure and the re-run.
                $Run.QuickstartRc = $quickstartRc
                $Run.QuickstartRerun = "defenseclaw " + ($quickstartArgs -join " ")
            }
        }
    } elseif ($Connector -and $Connector -ne "none") {
        Write-Host ""; Write-Host "  Next: defenseclaw init --connector $Connector" -ForegroundColor Cyan
    } else {
        Write-Host ""; Write-Host "  Next: defenseclaw init" -ForegroundColor Cyan
    }
}

function Show-Usage {
    @"

Usage:
  irm https://github.com/$DefaultRepo/releases/latest/download/install.ps1 | iex
  & ([scriptblock]::Create((irm https://github.com/$DefaultRepo/releases/latest/download/install.ps1))) [options]

Installs DefenseClaw, or upgrades an existing install in place (config and data
are kept; the replaced install is kept for -Rollback).

Options:
  -Yes                  Do not prompt
  -Version X.Y.Z        Install release X.Y.Z (runs that release's installer)
  -Local DIR            Take every release asset from DIR instead of GitHub
  -Rollback             Restore the install that the last upgrade replaced
  -Connector NAME       First install only: agent to guard ($($ConnectorChoices -join ', '))
  -NoOpenclaw           First install only: same as -Connector none
  -Quickstart           Run 'defenseclaw quickstart' afterwards if nothing is configured yet
  -QuickstartMode MODE  observe or action (implies -Quickstart)
  -NoPersistPath        Do not change the user PATH in the registry
  -CosignPath FILE      cosign to check the release signature with (default: cosign on PATH)
  -AcceptCurrentInstall Keep the config and connectors changed since an earlier
                        run that is not proven back (its binaries and gateway
                        are still checked), or, when another installer
                        replaced its programs, install this release over them.
                        An empty first-install record stays until the checked
                        replacement is installed and proven; its added
                        programs stay stopped during recovery
  -Help                 Show this help

Exit codes (run as a file):
  0  Installed        1  Not installed (a previous install is restored)
  2  Not installed: an unknown option or value (nothing was changed)
  3  Installed; a connector needs attention before it is guarded again
  4  Installed; the first-run quickstart failed (re-run it as shown)

Environment:
  DEFENSECLAW_HOME      Data directory (default: %USERPROFILE%\.defenseclaw)
"@ | Write-Host
}

# -- Main ---------------------------------------------------------------------

function Test-HookRollbackRestoreAvailable {
    $gateway = Join-Path $BinDir "defenseclaw-gateway.exe"
    # A missing reader cannot convert anything; keep that existing repair path.
    if (-not (Test-Path -LiteralPath $gateway -PathType Leaf)) { return $false }
    $global:LASTEXITCODE = $null
    $help = Get-NativeOutput $gateway @("connector", "prepare-rollback", "--help")
    if ($global:LASTEXITCODE -ne 0 -or $help -notmatch '(?m)^[ \t]+--restore(?:[ \t]|$)') {
        throw ("The current gateway cannot safely restore converted rollback hooks. " +
            "Repair this DefenseClaw version first, then retry rollback; nothing was changed")
    }
    return $true
}

function Convert-HooksForRollback([string]$From, [string]$BackTo) {
    # A hook entry this install wrote in a shape the older release does not
    # recognise (the per-user Claude Code cmd.exe launcher guard, GAP-1284)
    # outlived that release's uninstall. This install's gateway rewrites those
    # entries in the shape every earlier release removes; rolling forward runs
    # setup, which writes the current shape again. A failure warns; pending
    # connector recovery below prevents the version swap.
    $gateway = Join-Path $BinDir "defenseclaw-gateway.exe"
    if (-not (Test-Path -LiteralPath $gateway)) { return }
    if ((Invoke-Native $gateway @("connector", "prepare-rollback", "--data-dir", $DataDir)) -ne 0) {
        Write-Warn ("Could not rewrite the agent hook entries of DefenseClaw $From in the form $BackTo reads (see above). " +
            "After the rollback, 'defenseclaw uninstall' may leave those DefenseClaw entries in the agent settings, such as " +
            "the cmd.exe entries that run defenseclaw-hook.exe in %USERPROFILE%\.claude\settings.json; remove them by hand")
    }
}

function Restore-HooksAfterAbortedRollback {
    # Only the current reader may recover a published conversion and restore
    # its exact owned hooks. A saved settings copy is not overwrite authority.
    $gateway = Join-Path $BinDir "defenseclaw-gateway.exe"
    $failure = ""
    try {
        if (-not (Test-Path -LiteralPath $gateway -PathType Leaf)) {
            throw "the current gateway executable is unavailable"
        }
        # A failed native launch must not inherit a previous command's success.
        $global:LASTEXITCODE = $null
        $restored = Invoke-Native $gateway @("connector", "prepare-rollback", "--restore", "--data-dir", $DataDir)
        if ($null -eq $restored -or $restored -ne 0) { throw "the current reader did not verify hook restoration" }
    } catch { $failure = $_.Exception.Message }
    if ($failure) {
        Write-Warn "Current hook protection is unverified after the aborted rollback ($failure)"
        Write-Info "Keep the connector recovery receipts and repair with the current DefenseClaw release before continuing agent tool calls."
        Write-Info "Retry the current reader: & `"$gateway`" connector prepare-rollback --restore --data-dir `"$DataDir`""
    }
}

function Invoke-PruneOrphanedHooks([string[]]$Gateways) {
    # GAP-0009: remove the DefenseClaw hook entries of every connector the
    # live install does not configure, with the first gateway that has the
    # command: a connector set up after an upgrade kept its entries after the
    # rollback, and its agent ran a hook the restored install cannot serve.
    # Only DefenseClaw-owned entries go. An older gateway prints its
    # connector help for the unknown command, so the help is checked first.
    foreach ($gateway in $Gateways) {
        if (-not (Test-Path -LiteralPath $gateway)) { continue }
        if ((Get-NativeOutput $gateway @("connector", "prune-orphans", "--help")) -notmatch "connector prune-orphans") { continue }
        if ((Invoke-Native $gateway @("connector", "prune-orphans", "--data-dir", $DataDir)) -ne 0) {
            Write-Warn "Could not remove the DefenseClaw hook entries of connectors that are not configured (see above); 'defenseclaw doctor' lists them"
        }
        return
    }
}

function Undo-Rollback([string]$Reason, [string]$Current, [string]$BackTo, [string]$SavedWasRunning, [string]$Quarantined, [bool]$RestoreHooks = $false) {
    # Put back the install the rollback replaced, and return 1 (GAP-1388): a
    # restored 0.x release whose gateway is not running leaves agents
    # unguarded, and it has no rollback command to come back with.
    $forward = if ($Current) { $Current } else { "1.x" }
    Write-Warn "$Reason, so the rollback is being undone"
    [void](Stop-Gateway)
    # The same swap the other way: previous\ holds the install just left.
    $undone = @(Switch-WithPrevious $BackTo $false $true)[-1]
    if ($undone -ne 0) {
        $Run.RestorePending = $true
        Write-Err "DefenseClaw $BackTo is installed, but its gateway is not running, so agent hooks are not guarded"
        if ($undone -eq 1) {
            Write-Info "To return to $forward, run: powershell -ExecutionPolicy Bypass -File `"$Previous\installer\install.ps1`" -Rollback"
        }
        return 1
    }
    if ($RestoreHooks) { Restore-HooksAfterAbortedRollback }
    # previous\ is again the install this rollback started from, as it was.
    foreach ($marker in @("ROLLED_BACK", "START_AFTER")) { Remove-Item -LiteralPath (Join-Path $Previous $marker) -Force -ErrorAction SilentlyContinue }
    $state = if ($SavedWasRunning) { $SavedWasRunning } else { "false" }
    Set-Content -LiteralPath (Join-Path $Previous "GATEWAY_WAS_RUNNING") -Value $state -Encoding Ascii
    $audit = Join-Path $Previous "data\audit.db"
    $kept = if ($Quarantined) { Join-Path $Previous "data\$(Split-Path -Leaf $Quarantined)" } else { "" }
    if ($kept -and (Test-Path -LiteralPath $kept -PathType Leaf)) {
        # rel-1-0-2:GAP-0492: the failed start of $BackTo made a new, empty
        # audit.db here, which a later rollback then used without a word. It
        # goes aside, and the saved store goes back with its WAL, so that
        # rollback checks it again (as undo_rollback in install.sh).
        if (Test-Path -LiteralPath $audit) {
            $fresh = "$audit.failed-start-" + (Get-Date).ToUniversalTime().ToString("yyyyMMdd'T'HHmmss'Z'")
            if (Test-Path -LiteralPath $fresh) { $fresh += "-$PID" }
            try { Move-AuditStore $audit $fresh } catch {
                Write-Warn "Could not move aside the new audit store the failed start of $BackTo made ($($_.Exception.Message))"
            }
        }
        if (-not (Test-Path -LiteralPath $audit)) {
            try { Move-AuditStore $kept $audit } catch {
                Write-Warn "Could not put back the saved $BackTo audit store ($($_.Exception.Message))"
            }
        }
        if (Test-Path -LiteralPath $kept) {
            Write-Warn "The saved $BackTo audit store is still $kept; before 'defenseclaw rollback' again, move it and its -wal and -shm files to $audit"
        }
    }
    [void](Start-Gateway)
    # The install the rollback left is back only once it is proven against
    # the rollback's record (its binaries, config and running gateway).
    try {
        Assert-LifecycleRestored (Get-Variable -Name Manifest -ValueOnly -ErrorAction SilentlyContinue)
        Write-Ok "DefenseClaw $forward is back, with its gateway"
    } catch {
        Write-Err $_.Exception.Message
    }
    # Paths in the older release's errors above now hold this install's files.
    Write-Info "The files of DefenseClaw $BackTo are in $Previous\data again; fix them there (paths above under $DataDir named them)"
    Write-Info "Fix the cause above, then run 'defenseclaw rollback' again (log: $($Run.Log))"
    return 1
}

function Invoke-Rollback {
    $backTo = Read-Text (Join-Path $Previous "VERSION")
    if (-not (Test-Version $backTo)) { Write-Step "Rolling back"; Die "No previous install to roll back to ($Previous is missing)" }
    if (Test-Path -LiteralPath (Join-Path $Previous "legacy-setup")) {
        Die ("The previous install is DefenseClaw Setup $backTo, which cannot be restored automatically. To go back to it, " +
            "run 'defenseclaw uninstall', then download DefenseClawSetup-x64.exe from $ReleaseBase/releases/tag/$backTo " +
            "and run it in your desktop session. Its files and your data from before the upgrade are in $Previous; nothing was changed")
    }
    $current = Get-InstalledVersion
    $currentLabel = if ($current) { $current } else { "?" }
    # Run again after a rollback, this goes forward to the newer install (GAP-1497).
    $rollForward = $current -and (Test-Version $current) -and [version]$current -lt [version]$backTo
    if ($rollForward) {
        Write-Step "Rolling forward to DefenseClaw $backTo"
        $question = "Replace DefenseClaw $current with DefenseClaw $backTo (the install you rolled back from)?"
    } else {
        Write-Step "Rolling back to DefenseClaw $backTo"
        $question = "Replace DefenseClaw $currentLabel with the previous install ($backTo)?"
    }
    Assert-NoActiveConnectorRecovery "Rollback to $backTo"
    if (-not $rollForward) {
        Assert-NoActiveConnectorRecovery "Rollback to $backTo" (Join-Path $Previous "data")
    }
    if (-not (Confirm-Step $question)) {
        Die "Rollback cancelled; nothing was changed"
    }
    $canConvertHooks = $false
    if (-not $rollForward) { $canConvertHooks = Test-HookRollbackRestoreAvailable }
    Wait-VenvFree
    # GAP-1388: check the saved data before anything of this install changes.
    $toLegacy = [version]$backTo -lt [version]"1.0.0"
    $auditDamaged = $toLegacy -and (Test-RollbackData $backTo)
    $wasRunning = [bool](Get-GatewayProcess)
    $savedWasRunning = Read-Text (Join-Path $Previous "GATEWAY_WAS_RUNNING")
    $startAfter = $wasRunning -or $savedWasRunning -eq "true"
    # The rollback's lifecycle transaction: the install it leaves (proven
    # back by Undo-Rollback on any failure) and the one it goes to, which
    # stays in previous\ until this rollback is proven.
    try {
        $Manifest = Write-LifecycleManifest "rollback" $current $backTo "" @{ TargetBins = (Get-BinariesState (Join-Path $Previous "bin")); StartAfter = $startAfter }
    } catch { Die "Could not record the current install before the rollback ($($_.Exception.Message)); nothing was changed" }
    if (-not (Stop-Gateway)) {
        Remove-LifecycleManifest
        Die "The gateway did not stop; nothing was changed"
    }
    $conversionAttempted = $false
    try {
        Stop-Watchdog
        Assert-GatewayQuiescent "Rollback to $backTo"
        Assert-NoActiveConnectorRecovery "Rollback to $backTo"
        if (-not $rollForward) {
            Assert-NoActiveConnectorRecovery "Rollback to $backTo" (Join-Path $Previous "data")
        }
        if ($canConvertHooks) {
            $conversionAttempted = $true
            Convert-HooksForRollback $currentLabel $backTo
        }
        # Conversion can itself leave recovery work even when it only warns.
        if (-not $rollForward) {
            Assert-NoActiveConnectorRecovery "Rollback to $backTo"
            Assert-NoActiveConnectorRecovery "Rollback to $backTo" (Join-Path $Previous "data")
        }
    } catch {
        $abort = $_
        if ($conversionAttempted) { Restore-HooksAfterAbortedRollback }
        if ($wasRunning) {
            try { [void](Start-Gateway) } catch { Write-Warn "The current gateway could not restart: $($_.Exception.Message)" }
        }
        try { Assert-LifecycleRestored $Manifest } catch { Write-Err $_.Exception.Message }
        throw $abort
    }
    $swapped = @(Switch-WithPrevious $current $wasRunning $startAfter)[-1]
    if ($swapped -ne 0) {
        # 1: the swap undid itself, so this install is back and may run again.
        if ($swapped -eq 1 -and $conversionAttempted) { Restore-HooksAfterAbortedRollback }
        if ($swapped -eq 1 -and $wasRunning) { [void](Start-Gateway) }
        if ($swapped -eq 1) {
            try { Assert-LifecycleRestored $Manifest } catch { Die "Rollback failed part-way. $($_.Exception.Message)" }
        } else {
            $Run.RestorePending = $true
        }
        Die "Rollback failed part-way; see $($Run.Log)"
    }
    # Homes upgraded before the uv folder was protected (GAP-1988).
    Protect-UvDirectory
    if (-not $toLegacy) {
        Invoke-PruneOrphanedHooks @((Join-Path $BinDir "defenseclaw-gateway.exe"), (Join-Path $Previous "bin\defenseclaw-gateway.exe"))
    }
    $quarantined = ""
    if ($auditDamaged) {
        try { $quarantined = Move-DamagedAuditStore $backTo } catch {
            $why = "The damaged audit store of DefenseClaw $backTo could not be moved aside ($($_.Exception.Message))"
            return Undo-Rollback $why $current $backTo $savedWasRunning "" $conversionAttempted
        }
    }
    # Prove the rollback: the binaries of $backTo, its gateway running when
    # one ran before, and the bin folder protected. A gateway that does not
    # start or a rollback that is not proven is undone, for a 1.x release as
    # for a 0.x one (GAP-0486): never "Now running" with the gateway down.
    $problems = @()
    if ($startAfter -and (Start-Gateway) -notin @(0, 3)) { $problems += "the gateway of DefenseClaw $backTo did not start" }
    else {
        $legacyTarget = $backTo -match '^(?:0\.8\.10|1\.0\.[0-3])$'
        $problems = @(Wait-LifecycleProof (Get-Field $Manifest "TargetBins") $startAfter -AllowLegacyStatus:$legacyTarget)
    }
    if ($problems.Count) {
        return Undo-Rollback "DefenseClaw $backTo is not proven running ($($problems -join '; '))" $current $backTo $savedWasRunning $quarantined $conversionAttempted
    }
    Remove-LifecycleManifest
    $forward = if ($current) { $current } else { "1.x" }
    # Each install shows only its own audit window, so say how to read the
    # other one (GAP-0126). The newer build's gateway reads either log.
    $otherAudit = Join-Path $Previous "data\audit.db"
    if (Test-Path -LiteralPath $otherAudit) {
        $newerGateway = if ($current -and (Test-Version $current) -and [version]$backTo -lt [version]$current) {
            Join-Path $Previous "bin\defenseclaw-gateway.exe"
        } else { "defenseclaw-gateway" }
        $newerGatewayCommand = if ($newerGateway -eq "defenseclaw-gateway") {
            $newerGateway
        } else {
            '& "' + $newerGateway + '"'
        }
        Write-Info "The other install's audit events (written while $forward ran) are kept apart: $newerGatewayCommand audit export --db `"$otherAudit`""
    }
    if ([version]$backTo -lt [version]"1.0.0") {
        # 0.x has no `defenseclaw rollback`; the 1.x installer is parked in previous\.
        Write-Ok ("Now running DefenseClaw $backTo. To return to $forward, run: " +
            "powershell -ExecutionPolicy Bypass -File `"$Previous\installer\install.ps1`" -Rollback")
    } else {
        Write-Ok "Now running DefenseClaw $backTo. Run 'defenseclaw rollback' again to return to $forward."
    }
    return 0
}

# On Windows `defenseclaw uninstall` finishes in a helper that runs after the
# CLI exits: it deletes the data dir while %TEMP%\defenseclaw-uninstall-*\
# plan.json exists, then a cmd.exe renames the helper's own Python folders
# (plan.json interpreter_dirs) aside. An install started sooner lost its
# files to that cleanup (GAP-1647), so wait for both. A plan.json older than
# 10 minutes is a helper that died, not one that is still running.
function Wait-UninstallCleanup([int]$Seconds = 300) {
    $temp = [IO.Path]::GetTempPath()
    $deadline = (Get-Date).AddSeconds($Seconds)
    $waiting = $false
    $folders = @()
    while ($true) {
        $plans = @(Get-ChildItem -LiteralPath $temp -Directory -Filter "defenseclaw-uninstall-*" -ErrorAction SilentlyContinue |
            ForEach-Object { Get-Item -LiteralPath (Join-Path $_.FullName "plan.json") -ErrorAction SilentlyContinue } |
            Where-Object { $_ -and $_.LastWriteTime -gt (Get-Date).AddMinutes(-10) } | ForEach-Object { $_.FullName })
        foreach ($plan in $plans) {
            $folders += @(Get-Field (Read-Json $plan) "interpreter_dirs") |
                Where-Object { $_ -and ([string]$_).StartsWith($DataDir, [StringComparison]::OrdinalIgnoreCase) }
        }
        $folders = @($folders | Select-Object -Unique)
        $pending = @($plans) + @($folders | Where-Object { Test-Path -LiteralPath $_ })
        if (-not $pending.Count) { break }
        if (-not $waiting) { Write-Info "Waiting for the cleanup of an earlier 'defenseclaw uninstall' to finish"; $waiting = $true }
        if ((Get-Date) -gt $deadline) {
            Die "An earlier 'defenseclaw uninstall' is still cleaning up ($($pending[0])); wait a minute, then run the installer again. Nothing was changed."
        }
        Start-Sleep -Seconds 2
    }
    if ($waiting) { Write-Ok "The earlier uninstall finished" }
}

function Invoke-Install {
    # -h binds to -Help; the --help of install.sh lands in UnknownArguments
    # and shows the same help, before anything else runs (GAP-0466).
    if ($Help -or $UnknownArguments -contains "--help") { Show-Usage; return 0 }
    foreach ($argument in $UnknownArguments) {
        if ($argument -match '^-(Version|Local|Connector|QuickstartMode|CosignPath)=(.*)$') {
            # -Name=value is the same option as -Name value (GAP-0361).
            Set-Variable -Name $Matches[1] -Value $Matches[2]
            if ($Matches[1] -eq "Local") { $LocalGiven = $true }
            if ($Matches[1] -eq "Version") { $VersionGiven = $true }
        } elseif ($RunByUpgrade) {
            Write-Warn "Ignoring unknown option: $argument"
        } else {
            Stop-Usage "Unknown option: $argument"
        }
    }
    $Connector = $Connector.Trim().ToLowerInvariant()
    if ($Connector -and $ConnectorChoices -notcontains $Connector) {
        Stop-Usage "Invalid -Connector '$Connector'. Choices on Windows: $($ConnectorChoices -join ', ')"
    }
    if ($NoOpenclaw -and -not $Connector) { $Connector = "none" }
    if ($QuickstartMode -and $QuickstartMode -notin @("observe", "action")) { Stop-Usage "Invalid -QuickstartMode '$QuickstartMode': use observe or action" }
    if ($QuickstartMode) { $Quickstart = $true }
    $TargetVersion = $Version -replace '^v', ''
    if ($VersionGiven -and -not $TargetVersion) { Stop-Usage "-Version needs a value such as 1.2.3" }
    if ($TargetVersion -and -not (Test-Version $TargetVersion)) { Stop-Usage "-Version must look like 1.2.3, got '$Version'" }
    $LocalDir = ""
    if ($LocalGiven -and -not $Local.Trim()) { Stop-Usage "-Local needs the folder that holds the release assets" }
    if ($Local) {
        if (-not (Test-Path -LiteralPath $Local -PathType Container)) { Stop-Usage "-Local: directory not found: $Local" }
        $LocalDir = (Resolve-Path -LiteralPath $Local).ProviderPath
    }

    Write-Host ""
    Write-Host "  DefenseClaw Installer" -ForegroundColor White

    if ($env:OS -ne "Windows_NT") { Die "This installer is for Windows; use install.sh on macOS and Linux" }
    # The OS, not this process: x64 PowerShell also runs, emulated, on Windows ARM64.
    switch (Get-OSArchitectureName) {
        "X64" { }
        "ARM64" { Die "Windows ARM64 is not certified, including x64 emulation; use Windows x64. Nothing was changed." }
        default { Die "Unsupported architecture: $_ (DefenseClaw for Windows needs x64). Nothing was changed." }
    }
    # An enterprise that deploys DefenseClaw itself (Intune, SCCM) turns this installer off.
    $policy = $null
    try {
        $hklm = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
        $key = $hklm.OpenSubKey("SOFTWARE\Policies\Cisco\DefenseClaw")
        if ($key) { $policy = $key.GetValue("DisableSelfUpdate"); $key.Close() }
        if ($null -ne $policy) { $policy = [int64]$policy }
    } catch {
        Die "Could not read the enterprise update policy: $($_.Exception.Message). Nothing was changed."
    }
    if ($policy) { Die "DefenseClaw self-update is disabled by enterprise policy; use the managed deployment channel. Nothing was changed." }
    # A machine-wide managed deployment registers this marker; a per-user
    # install beside it would run a second, unmanaged gateway.
    $managedProfile = $null
    try {
        $marker = $hklm.OpenSubKey("SOFTWARE\Cisco\DefenseClaw\Enterprise")
        if ($marker) { $managedProfile = [string]$marker.GetValue("Profile", "managed"); $marker.Close() }
    } catch {
        Die "Could not read the managed deployment marker: $($_.Exception.Message). Nothing was changed."
    }
    if ($managedProfile) { Die "A managed DefenseClaw enterprise deployment ($managedProfile) is installed on this computer; use the managed deployment channel. Nothing was changed." }
    $user = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Warn "Running as administrator; DefenseClaw is installed for $env:USERNAME only (in $env:USERPROFILE)"
        # Elevated, new files would belong to the Administrators group, and
        # DefenseClaw refuses data its user does not own: create them as the
        # user, as without elevation.
        $sid = New-Object byte[] $user.BinaryLength
        $user.GetBinaryForm($sid, 0)
        Initialize-Native
        $Run.Owner = [DefenseClawInstall.Native]::SwapDefaultOwner([DefenseClawInstall.Native]::NewOwner($sid))
    }

    # Which version does this installer install?
    $Forward = @()
    if ($Yes) { $Forward += "-Yes" }
    if ($Connector) { $Forward += @("-Connector", $Connector) }
    if ($Quickstart) { $Forward += "-Quickstart" }
    if ($QuickstartMode) { $Forward += @("-QuickstartMode", $QuickstartMode) }
    if ($NoPersistPath) { $Forward += "-NoPersistPath" }
    if ($CosignPath) { $Forward += @("-CosignPath", $CosignPath) }
    if ($TargetVersion -and -not $Rollback -and [version]$TargetVersion -lt [version]"1.0.0") {
        Die "DefenseClaw $TargetVersion predates this installer; see $ReleaseBase/releases/tag/$TargetVersion"
    }
    $Ver = $DcVersion
    if (-not (Test-Version $Ver)) {
        # Not stamped by a release (a copy from the source tree).
        if ($LocalDir) {
            $wheel = Get-ChildItem -LiteralPath $LocalDir -Filter "defenseclaw-*-py3-none-any.whl" | Select-Object -First 1
            $Ver = if ($wheel) { $wheel.Name -replace '^defenseclaw-', '' -replace '-py3-none-any\.whl$', '' } else { "" }
            if (-not (Test-Version $Ver)) { Die "No defenseclaw-X.Y.Z-py3-none-any.whl in $LocalDir" }
        } elseif (-not $Rollback) {
            $target = if ($TargetVersion) { $TargetVersion } else { Get-LatestRelease }
            if ([version]$target -lt [version]"1.0.0") { Die "The latest DefenseClaw release, $target, predates this installer" }
            return Invoke-ReleaseInstaller $target $Forward
        }
    }
    if ($LocalDir -and $TargetVersion -and (Test-Version $Ver) -and [version]$TargetVersion -lt [version]$Ver -and -not $Rollback) {
        # A saved current controller also owns local downgrades. Select only
        # the explicitly requested wheel; all assets and runtime versions are
        # verified below before this controller can replace anything live.
        $targetWheel = Join-Path $LocalDir "defenseclaw-$TargetVersion-py3-none-any.whl"
        if (-not (Test-Path -LiteralPath $targetWheel -PathType Leaf)) {
            Die "-Local $LocalDir has no wheel for the requested DefenseClaw $TargetVersion"
        }
        $Ver = $TargetVersion
    }
    if ($TargetVersion -and $TargetVersion -ne $Ver -and -not $Rollback) {
        if ($LocalDir) { Die "-Local $LocalDir holds $Ver, not $TargetVersion" }
        return Invoke-ReleaseInstaller $TargetVersion $Forward
    }

    Wait-UninstallCleanup

    # Lock and log.
    New-Item -ItemType Directory -Path (Join-Path $DataDir "logs") -Force | Out-Null
    $acl = Get-Acl -LiteralPath $DataDir
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]) -ne $user) {
        # Created by an elevated installer of an older release.
        $acl.SetOwner($user)
        Set-DirectoryAcl $DataDir $acl
    }
    try { New-Item -ItemType Directory -Path $LockDir -ErrorAction Stop | Out-Null } catch {
        $holder = [string](Get-Content -LiteralPath (Join-Path $LockDir "pid") -ErrorAction SilentlyContinue | Select-Object -First 1)
        $process = if ($holder -match '^\d+$' -and [int]$holder -ne $PID) { Get-Process -Id ([int]$holder) -ErrorAction SilentlyContinue } else { $null }
        if ($process -and $process.ProcessName -match '^(powershell|pwsh)$') { Die "Another DefenseClaw install is running (pid $holder)" }
        Remove-Tree $LockDir
        try { New-Item -ItemType Directory -Path $LockDir -ErrorAction Stop | Out-Null } catch { Die "Could not take the install lock at $LockDir" }
    }
    $Run.Lock = $true
    Set-Content -LiteralPath (Join-Path $LockDir "pid") -Value $PID -Encoding Ascii
    $Run.Log = Join-Path $DataDir ("logs\install-" + (Get-Date -Format "yyyyMMddTHHmmss") + ".log")
    try { Start-Transcript -LiteralPath $Run.Log -Append | Out-Null; $Run.Transcript = $true } catch {
        Write-Warn "Could not write the install log $($Run.Log)"
    }
    # The gateway and the migration run DefenseClaw commands by name.
    if (-not @($env:Path -split ";" | Where-Object { $_ -and (Test-SamePath $_ $BinDir) }).Count) { $env:Path = "$BinDir;$env:Path" }
    # A 0.8.x upgrade controller's marker would skip the readiness check that is our health check.
    Remove-Item Env:DEFENSECLAW_UPGRADE_FRESH_PROCESS -ErrorAction SilentlyContinue
    # A run that died inside Wait-VenvFree leaves the venv renamed.
    if (Test-Path -LiteralPath "$Venv.busy") {
        if (Test-Path -LiteralPath $Venv) { Remove-Tree "$Venv.busy" } else { Move-Path "$Venv.busy" $Venv }
    }
    try { Resume-InterruptedRun } catch {
        if (-not $Run.UnprovenReplacementUnchanged) { Set-RecoveryPending }
        throw
    }

    if ($Rollback) { return Invoke-Rollback }

    # Stage: nothing live changes until the swap.
    Write-Step "Preparing DefenseClaw $Ver (windows/amd64)"
    $PrevVersion = Get-InstalledVersion
    $Setup = Find-SetupInstall
    if ($PrevVersion) {
        Write-Info "Installed: $PrevVersion"
    } elseif ($Setup) {
        $PrevVersion = $Setup.Version
        Write-Info "Installed: DefenseClaw Setup $PrevVersion ($($Setup.Root))"
    } elseif (Test-Path -LiteralPath (Join-Path $BinDir "defenseclaw.cmd")) {
        Write-Warn "Found a broken DefenseClaw install ($BinDir\defenseclaw.cmd without its venv); repairing it"
    }
    $versionChange = (Test-Version $PrevVersion) -and [version]$Ver -ne [version]$PrevVersion
    if ($versionChange) { Assert-NoActiveConnectorRecovery "Version change to $Ver" }

    # Before anything is created (the uv folder, uv itself), so a refusal
    # really changes nothing (GAP-2614).
    Assert-InstallRoom $InstallRoom "the new version"
    # Never pick up uv settings (overrides, indexes) from a project in the cwd.
    $env:UV_NO_CONFIG = "1"
    # The download cache and the Python uv fetches for the venv stay in the
    # data dir, so `uninstall --all` leaves nothing of them in AppData.
    if (-not $env:UV_CACHE_DIR) { $env:UV_CACHE_DIR = Join-Path $DataDir ".uv\cache" }
    if (-not $env:UV_PYTHON_INSTALL_DIR) { $env:UV_PYTHON_INSTALL_DIR = Join-Path $DataDir ".uv\python" }
    Protect-UvDirectory -Create
    # uv's defaults (60 s to compile one file, 30 s per download read) fail
    # on a Windows host busy with Defender and other accounts (GAP-1776).
    if (-not $env:UV_COMPILE_BYTECODE_TIMEOUT) { $env:UV_COMPILE_BYTECODE_TIMEOUT = "600" }
    if (-not $env:UV_HTTP_TIMEOUT) { $env:UV_HTTP_TIMEOUT = "300" }
    $Uv = [string](Get-Command uv.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty Source)
    if ($Run.UnprovenReplacement -and $Uv -and (Test-SamePath (Split-Path -Parent $Uv) $BinDir)) { $Uv = "" }
    # A uv already in the bin folder belongs to the user (or an earlier run)
    # even when that folder is not on PATH yet: use it, never overwrite it.
    if (-not $Uv -and -not $Run.UnprovenReplacement -and (Test-Path -LiteralPath (Join-Path $BinDir "uv.exe") -PathType Leaf)) { $Uv = Join-Path $BinDir "uv.exe" }
    if (-not $Uv) {
        Write-Info "Installing uv $UvVersion (Python package manager)"
        $Uv = if ($Run.UnprovenReplacement) { Install-Uv (Join-Path $DataDir ".uv\bin") } else { Install-Uv }
        if (-not $Uv) { Die "Could not install uv; install it from https://docs.astral.sh/uv/ and retry" }
    }

    New-InstallDirectory $Staging
    New-Item -ItemType Directory -Path (Join-Path $Staging "bin") | Out-Null
    $Archive = "defenseclaw-$Ver-windows-amd64.zip"
    $Wheel = "defenseclaw-$Ver-py3-none-any.whl"
    $Requirements = "defenseclaw-$Ver-requirements.txt"

    # -Local copies the assets, so it says so instead of "Downloading" (GAP-0190).
    if ($LocalDir) { Write-Info "Verifying the release assets in $LocalDir" } else { Write-Info "Downloading and verifying release assets" }
    if (-not (Get-Asset "checksums.txt" (Join-Path $Staging "checksums.txt"))) { Die "Could not get checksums.txt for $Ver" }
    $cosign = Get-Cosign
    if ($cosign) {
        $bundle = Join-Path $Staging "checksums.txt.bundle"
        if (Get-Asset "checksums.txt.bundle" $bundle) {
            if ((Test-ReleaseSignature $cosign $bundle (Join-Path $Staging "checksums.txt")) -ne 0) {
                Die "The release signature on checksums.txt did not verify; nothing was changed"
            }
            Write-Ok "Release signature verified"
        } elseif (-not $Local) {
            # Every published release carries the bundle; a missing one is not a
            # release this workflow produced.
            Die "This release has no checksums.txt.bundle to verify with cosign; nothing was changed"
        } else {
            Write-Warn "No checksums.txt.bundle to verify with cosign; relying on checksums"
        }
    } elseif (-not $Local -and $ReleaseBase -ne $OfficialReleaseBase) {
        Die "Releases from $ReleaseBase are verified by their signature: install cosign 2.0 or later; nothing was changed"
    } elseif (-not $Local) {
        Write-Info "cosign 2.0 or later is not installed; downloads are checked against checksums.txt only"
    }
    foreach ($asset in @($Archive, $Wheel, $Requirements)) {
        if (-not (Get-Asset $asset (Join-Path $Staging $asset))) { Die "Could not get $asset for $Ver" }
        if (-not (Test-Checksum (Join-Path $Staging $asset))) { Die "$asset does not match checksums.txt; nothing was changed" }
    }
    Write-Ok "Assets match checksums.txt"

    try { Expand-Archive -LiteralPath (Join-Path $Staging $Archive) -DestinationPath (Join-Path $Staging "bin") -Force } catch {
        Die "Could not unpack $Archive"
    }
    $stagedGateway = Join-Path $Staging "bin\defenseclaw-gateway.exe"
    if (-not (Test-Path -LiteralPath $stagedGateway)) { Die "$Archive has no defenseclaw-gateway.exe" }
    if (-not (Get-NativeOutput $stagedGateway @("--version")).Contains($Ver)) { Die "The gateway in $Archive does not report version $Ver" }

    # A first install with an empty uv cache downloads Python and every
    # package, then compiles the bytecode: about 7 minutes on a busy Windows
    # host with nothing printed (GAP-1665), so say so up front.
    Write-Info "Building the Python environment (a first install can take several minutes)"
    if (-not (New-Venv (Join-Path $Staging "venv") "the staging environment")) {
        if (-not $PrevVersion) { Write-KeptUvCache }
        Die "Could not install the DefenseClaw $Ver Python package; nothing was changed"
    }
    $stagedCli = Join-Path $Staging "venv\Scripts\defenseclaw.exe"
    if (-not (Get-NativeOutput $stagedCli @("--version")).Contains($Ver)) { Die "The staged CLI does not start; nothing was changed" }
    $checkArgs = @("migrate", "--check", "--gateway-binary", $stagedGateway)
    if ($PrevVersion) { $checkArgs += @("--from-version", $PrevVersion) }
    switch (Invoke-Native $stagedCli $checkArgs) {
        0 { }
        2 { Die "Your configuration is from a newer DefenseClaw than $Ver; nothing was changed" }
        default { Die "Your configuration cannot be migrated to $Ver; nothing was changed (see above)" }
    }
    Write-Ok "DefenseClaw $Ver is staged and checked"
    # What the proof of this install compares the live binaries with.
    $stagedBinaries = Get-BinariesState (Join-Path $Staging "bin")

    # Swap.
    if ($PrevVersion -and $PrevVersion -eq $Ver) {
        if (-not (Confirm-Step "Reinstall DefenseClaw ${Ver}?")) { Die "Cancelled; nothing was changed" }
    } elseif ($PrevVersion) {
        $auditDb = Join-Path $DataDir "audit.db"
        if ([version]$PrevVersion -lt [version]"1.0.0" -and (Test-Path -LiteralPath $auditDb)) {
            # Audit migration 33 (privacy cutover) empties the pre-1.0 history.
            $auditMb = "{0:N0} MB" -f ((Get-Item -LiteralPath $auditDb).Length / 1MB)
            Write-Warn "DefenseClaw 1.0 starts a new audit history: the audit events, scan results and findings $PrevVersion recorded ($auditDb, $auditMb) are deleted when DefenseClaw $Ver first opens its audit database"
            Write-Info "A copy is kept in $(Join-Path $Previous 'data\audit.db'); 'defenseclaw rollback' brings it back, and later upgrades keep it in $(Join-Path $DataDir 'backups')"
        }
        if ((Test-Version $PrevVersion) -and [version]$Ver -lt [version]$PrevVersion) {
            # An older release over a newer one is a downgrade: ask with no as
            # the answer, and say so even with -Yes (GAP-0287).
            if ($Yes) { Write-Warn "Downgrading DefenseClaw $PrevVersion -> $Ver (-Yes)" }
            if (-not (Confirm-Step "Downgrade DefenseClaw $PrevVersion -> ${Ver}? (an older release; 'defenseclaw rollback' undoes it)" -DefaultNo)) {
                Die "Cancelled; nothing was changed"
            }
        } elseif (-not (Confirm-Step "Upgrade DefenseClaw $PrevVersion -> ${Ver}?")) { Die "Cancelled; nothing was changed" }
    }
    if (-not $PrevVersion -and -not $Yes -and -not $Connector) { $Connector = Select-Connector }

    Assert-InstallRoom $FinalEnvRoom "the final Python environment"
    Wait-VenvFree
    if ($Run.UnprovenReplacement) {
        try { Prepare-UnprovenReplacement $stagedGateway $stagedBinaries } catch {
            $reason = $_.Exception.Message
            if (-not $Run.UnprovenReplacementUnchanged) { Set-RecoveryPending }
            Die "${reason}; the lifecycle record stays.$(Restore-AcceptedReplacement) Run: $(Get-LifecycleNextStep -Accept)"
        }
    }
    if ($Setup) {
        Disable-SetupHooks
        if ($Setup.CodexHome -and -not $env:CODEX_HOME) { $env:CODEX_HOME = $Setup.CodexHome }
        if ($Setup.ClaudeConfigDir -and -not $env:CLAUDE_CONFIG_DIR) { $env:CLAUDE_CONFIG_DIR = $Setup.ClaudeConfigDir }
    }
    if ($Run.UnprovenReplacement -and (Get-GatewayProcess)) {
        try { Prepare-UnprovenReplacement $stagedGateway $stagedBinaries } catch {
            $reason = $_.Exception.Message
            if (-not $Run.UnprovenReplacementUnchanged) { Set-RecoveryPending }
            Die "${reason}; the lifecycle record stays.$(Restore-AcceptedReplacement) Run: $(Get-LifecycleNextStep -Accept)"
        }
    }
    $gatewayProcess = Get-GatewayProcess
    if ($Run.ContainsKey("UnprovenReplacement") -and $Run.UnprovenReplacement -and $gatewayProcess) {
        Die "The unproven gateway restarted after it was stopped; the lifecycle record stays. Run: $(Get-LifecycleNextStep -Accept)"
    }
    $WasRunning = [bool]$gatewayProcess
    if ($Run.ContainsKey("UnprovenReplacement") -and $Run.UnprovenReplacement) {
        # Prepare-UnprovenReplacement held the closed mode until the older
        # gateway exited. Do not restore a configured open while it is down.
    } elseif ($WasRunning) {
        if (-not (Start-HookFailModeHold $stagedGateway $gatewayProcess.Id)) {
            if ($Setup) { Restore-SetupInstall }
            Die "Could not set the hooks' fail modes from your config, so they could fail open while the gateway is down; nothing was changed (see above)"
        }
    } elseif (-not (Update-HookFailModes $stagedGateway)) {
        if ($Setup) { Restore-SetupInstall }
        Die "Could not set the hooks' fail modes from your config, so they could fail open while the gateway is down; nothing was changed (see above)"
    }
    $Snap = if ($PrevVersion -and $PrevVersion -eq $Ver) { Join-Path $DataDir ".repair" } else { Join-Path $DataDir "previous.new" }
    # The lifecycle transaction starts here: the working state is on the
    # disk before the first program changes (the hook swap). The outage
    # modes the hold or the refresh above set only ever tighten.
    $operation = if ($PrevVersion -and $PrevVersion -eq $Ver) { "repair" } elseif ($PrevVersion) { "upgrade" } else { "install" }
    try { $Manifest = Write-LifecycleManifest $operation $PrevVersion $Ver $Snap } catch {
        $reason = $_.Exception.Message
        Stop-HookFailModeHold
        if ($Setup) { Restore-SetupInstall }
        if ($Run.ContainsKey("UnprovenReplacement") -and $Run.UnprovenReplacement) {
            Die "Could not record the current install before changing it ($reason); the lifecycle record stays.$(Restore-AcceptedReplacement) Run: $(Get-LifecycleNextStep -Accept)"
        }
        Die "Could not record the current install before changing it ($reason); nothing was changed"
    }
    try { Save-BinarySnapshot } catch {
        $failure = $_
        Stop-HookFailModeHold
        Undo-EarlySnapshot $Snap
        Start-AcceptedReplacement
        # Nothing else changed yet: a proven baseline retires its record; a
        # prior unproven baseline stays locked without claiming the current
        # attempt changed binaries. An unfinished undo keeps it and the lock.
        Finish-EarlySnapshotRestore $Manifest
        throw $failure
    }
    # From here to the rollback copy the new hook is live while the old
    # gateway stops. Any failure, a refusal or a thrown error (a gateway.pid
    # read that fails after the old gateway exited), puts the old hook back
    # and starts the old gateway again; an undo that does not finish keeps
    # .install.lock (Close-InstallLock) for the next run to finish.
    $stopRefused = $false
    try {
        if ($WasRunning) {
            Write-Info "Stopping the gateway [$(Get-UtcClock)]"
            if (-not (Stop-Gateway)) {
                $stopRefused = $true
                Die "The running gateway did not stop"
            }
            # The hold refreshes again once the gateway has exited: it may
            # have rendered them while it ran or shut down.
            if (-not (Complete-HookFailModeHold)) {
                Die "Could not set the hooks' fail modes from your config, so they could fail open while the gateway is down"
            }
        }
        if ($Run.ContainsKey("UnprovenReplacement") -and $Run.UnprovenReplacement) {
            Prepare-UnprovenReplacement $stagedGateway $stagedBinaries
        } else { Stop-Watchdog }
        if ($versionChange) {
            Assert-GatewayQuiescent "Version change to $Ver"
            Assert-NoActiveConnectorRecovery "Version change to $Ver"
        } elseif ($Run.ContainsKey("UnprovenReplacement") -and $Run.UnprovenReplacement) {
            # A same-version repair over an accepted install: nothing of it may still run.
            Assert-GatewayQuiescent "Installing $Ver over the accepted install"
        }
        if ($Setup) { Stop-ProcessesUnder $Setup.Root }
    } catch {
        $reason = ([string]$_.Exception.Message).TrimEnd('.', ' ')
        # A stop that was refused or threw leaves the hold waiting for a
        # gateway that still runs.
        Stop-HookFailModeHold
        Undo-EarlySnapshot $Snap
        Clear-StagedRelease
        if ($stopRefused) {
            # The old gateway still runs; only DefenseClaw Setup's hook state goes back.
            if ($Setup) {
                try { Restore-SetupInstall } catch {
                    Write-Err "Could not put DefenseClaw Setup's hook state back: $($_.Exception.Message)"
                    $Run.RestorePending = $true
                }
            }
            if (-not (Test-RecoveryPending)) { Assert-LifecycleRestored $Manifest }
            Die "${reason}; $(Get-UnchangedNote)"
        }
        Restart-Old
        if (-not (Test-RecoveryPending)) {
            try { Assert-LifecycleRestored $Manifest } catch { Die "$reason. $($_.Exception.Message)" }
        }
        Die "$reason. $(Get-RestoredNote)"
    }

    # Ctrl+C now would leave a half-swapped install; it is ignored until the swap is done.
    try { [Console]::TreatControlCAsInput = $true } catch { }
    try { $saved = Save-Snapshot } catch { Write-Err $_.Exception.Message; [void](Test-DiskFull); $saved = $false }
    if (-not $saved) {
        Undo-EarlySnapshot $Snap
        Clear-StagedRelease
        Restart-Old
        if (-not (Test-RecoveryPending)) {
            try { Assert-LifecycleRestored $Manifest } catch { Die "Could not save the current install; it was not changed, but it is not proven back: $($_.Exception.Message)" }
        }
        Die "Could not save the current install; $(Get-UnchangedNote)"
    }
    $previousLabel = if ($PrevVersion) { $PrevVersion } else { "the previous state" }
    try { $installed = Install-New } catch { Write-Err $_.Exception.Message; [void](Test-DiskFull); $installed = $false }
    if (-not $installed) {
        Write-Err "Installing $Ver failed; restoring $previousLabel"
        Restore-Snapshot
        Die "DefenseClaw $Ver was not installed. $(Get-RestoredNote) Log: $($Run.Log)"
    }
    $startRc = 0
    # A 0.x import leaves the agent executables its connectors run in a receipt
    # (see defenseclaw migrate) that the gateway must seal within minutes, so
    # the new gateway starts once even if the old one was stopped, and stops
    # again. The old gateway was not running, so that start is not a health
    # gate for the install.
    $sealOnly = -not $WasRunning -and -not $Setup -and $PrevVersion -and [version]$PrevVersion -lt [version]"1.0.0" -and
        (Test-Path -LiteralPath (Join-Path $DataDir "agent_selection.json"))
    $startNew = $WasRunning -or $Run.UnprovenGatewayWasRunning -or $sealOnly -or ($Setup -and (Test-ConnectorConfigured))
    if ($startNew -and -not (Test-Path -LiteralPath (Join-Path $DataDir "config.yaml")) -and -not $env:DEFENSECLAW_CONFIG) {
        # 0.x gateways ran on defaults without a config; 1.x needs one.
        $startNew = $false
        Write-Warn "The gateway was running without a configuration; run 'defenseclaw init' to set it up"
    }
    if ($startNew) {
        # A failed or interrupted start must not run an older setup against
        # the same busy agent settings during automatic rollback. Record the
        # refusal before starting so interrupted recovery keeps it too.
        Set-Content -LiteralPath (Join-Path $Snap "GATEWAY_RESTART_UNPROVEN") -Value "" -Encoding Ascii
        $startedAt = Get-Date
        # A start that throws is a start that failed: the install is restored.
        try { $startRc = Start-Gateway } catch { Write-Err $_.Exception.Message; $startRc = 1 }
        if ($sealOnly) {
            try { [void](Stop-Gateway) } catch { Write-Warn "Could not stop the $Ver gateway after its first start: $($_.Exception.Message)" }
        }
        if ($startRc -ne 0 -and $startRc -ne 3) {
            Write-Err ("The $Ver gateway did not become healthy within {0:N0} s [{1}]; restoring $previousLabel" -f ((Get-Date) - $startedAt).TotalSeconds, (Get-UtcClock))
            try { [void](Stop-Gateway) } catch { Write-Err "Could not stop the $Ver gateway: $($_.Exception.Message)" }
            Restore-Snapshot
            Die "DefenseClaw $Ver was not installed. $(Get-RestoredNote) Log: $($Run.Log)"
        }
    }
    # Prove the new install before anything of the previous one goes: the
    # gateway runs from this install with the checked bytes and answers its
    # health check, every connector it guarded before is guarded again, it
    # enforces the policy digest of the live config, and the bin folder is
    # protected. A start that reported a connector needing attention (exit
    # 3) already said which one. Anything else restores the previous install.
    $provenGateway = $startNew -and -not $sealOnly
    # Only connectors this release supports on Windows are required again: a
    # retired one (or the default openclaw entry) has no hooks to put back.
    $guardedBefore = @(@(Get-Field $Manifest "Connectors") | Where-Object { $ConnectorChoices -contains $_ -and $_ -ne "none" })
    $problems = @(Wait-LifecycleProof $stagedBinaries $provenGateway $guardedBefore -RequireDigest:$provenGateway)
    if ($problems.Count) {
        foreach ($problem in $problems) { Write-Err $problem }
        Write-Err "DefenseClaw $Ver is not proven installed; restoring $previousLabel"
        try { [void](Stop-Gateway) } catch { Write-Err "Could not stop the $Ver gateway: $($_.Exception.Message)" }
        Restore-Snapshot
        Die "DefenseClaw $Ver was not installed. $(Get-RestoredNote) Log: $($Run.Log)"
    }
    if ($startNew) { Remove-Item -LiteralPath (Join-Path $Snap "GATEWAY_RESTART_UNPROVEN") -Force -ErrorAction Stop }
    Complete-LifecycleManifest
    Complete-Swap
    Remove-LifecycleManifest
    Remove-DeveloperFiles
    try { [Console]::TreatControlCAsInput = $false } catch { }

    if ($startRc -eq 3) { Write-Warn "A connector needs attention before it is guarded again (see the gateway output above)" }
    $configured = (Test-Path -LiteralPath (Join-Path $DataDir "config.yaml")) -or $env:DEFENSECLAW_CONFIG
    if (-not $PrevVersion) {
        Invoke-FirstInstallExtras
    } elseif ($Quickstart -and -not $configured) {
        # Installed but never set up, so the asked-for quickstart is still the first run.
        Invoke-FirstInstallExtras
    } elseif ($Quickstart) {
        $rerun = "defenseclaw quickstart"
        if ($Connector -and $Connector -ne "none") { $rerun += " --connector $Connector" }
        if ($QuickstartMode) { $rerun += " --mode $QuickstartMode" }
        Write-Warn "Skipped -Quickstart: DefenseClaw is already configured. To run it now: $rerun"
    }
    $setupBin = if ($Setup) { Join-Path $Setup.Root "bin" } else { "" }
    $pathChanged = Update-UserPath -Add $BinDir -Remove $setupBin
    Write-Host ""
    Write-Host "  DefenseClaw $Ver is installed." -ForegroundColor Green
    if ($Setup) {
        Write-Host "  Replaced DefenseClaw Setup $PrevVersion; your config and data were kept."
    } elseif ($PrevVersion -and $PrevVersion -ne $Ver) {
        $changed = if ((Test-Version $PrevVersion) -and [version]$Ver -lt [version]$PrevVersion) { "Downgraded" } else { "Upgraded" }
        Write-Host "  $changed from $PrevVersion. Undo with: defenseclaw rollback"
    }
    if ($PrevVersion -and $configured -and -not (Get-GatewayProcess)) {
        # GAP-1496: it was not running before the upgrade, so it was not started.
        if (Test-GuardrailOff) {
            # GAP-2481: 'uninstall --binaries' turned the guardrail off and tore the
            # connector hooks down; a gateway start alone does not set them up again.
            Write-Warn "Protection is off in the kept config (guardrail.enabled = false), so agent hooks are not guarded"
            Write-Host "  Turn it back on with: defenseclaw setup guardrail" -ForegroundColor Cyan
        } else {
            Write-Warn "The gateway is not running, so agent hooks are not guarded until it is"
            # GAP-0384: when another process holds its API port, that start fails too.
            $portProblem = (Get-NativeOutput (Join-Path $BinDir "defenseclaw-gateway.exe") @("check-api-port", "--installed")).Trim()
            if ($LASTEXITCODE -ne 0 -and $portProblem) {
                Write-Info ($portProblem -replace '^Error: ', '')
            } else {
                Write-Host "  Start it with: defenseclaw-gateway start" -ForegroundColor Cyan
            }
        }
    }
    if ($PrevVersion -and -not $Setup -and -not $Quickstart -and -not $configured) {
        # An earlier install that was never initialized: say how to start, as a
        # fresh install does. The connector an earlier install recorded is not
        # named: it may be the codex picked with no console to ask on (GAP-0568).
        if ($Connector -and $Connector -ne "none") {
            Write-Host "  DefenseClaw is not set up yet. Next: defenseclaw init --connector $Connector" -ForegroundColor Cyan
        } else {
            Write-Host "  DefenseClaw is not set up yet. Next: defenseclaw init" -ForegroundColor Cyan
        }
    }
    if ($PrevVersion -and [version]$PrevVersion -lt [version]"1.0.0" -and (Test-Path -LiteralPath (Join-Path $Previous "data\audit.db"))) {
        Write-Host "  The audit history $PrevVersion recorded is not carried over to 1.0; a copy is in $(Join-Path $Previous 'data\audit.db')"
    }
    if ($NoPersistPath) {
        Write-Host "  Add $BinDir to your PATH to run defenseclaw from any terminal."
    } elseif ($pathChanged -and $RunAsFile) {
        Write-Host "  Open a new terminal to use defenseclaw."
    }
    Write-Host ""
    if ($Run.QuickstartRerun) {
        Write-Err "Quickstart failed (exit $($Run.QuickstartRc)): DefenseClaw $Ver is installed, but $Connector is not set up yet"
        Write-Host "  Fix what quickstart reported above ('defenseclaw doctor' helps), then run:"
        Write-Host "    $($Run.QuickstartRerun)" -ForegroundColor Cyan
        Write-Host ""
        return 4
    }
    return $startRc
}

$savedEnv = @{}
foreach ($name in @("UV_NO_CONFIG", "UV_CACHE_DIR", "UV_PYTHON_INSTALL_DIR", "UV_INSTALL_DIR", "UV_NO_MODIFY_PATH",
        "UV_COMPILE_BYTECODE_TIMEOUT", "UV_HTTP_TIMEOUT", "DEFENSECLAW_GATEWAY_BIN",
        "DEFENSECLAW_UPGRADE_FRESH_PROCESS", "CODEX_HOME", "CLAUDE_CONFIG_DIR")) {
    $savedEnv[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
}
$code = 1
try {
    $code = [int](@(Invoke-Install) | Select-Object -Last 1)
} catch {
    Write-Err $_.Exception.Message
    if ($_.FullyQualifiedErrorId -ne $_.Exception.Message) { Write-Host $_.InvocationInfo.PositionMessage -ForegroundColor DarkGray }
    $code = if ($Run.UsageError) { 2 } else { 1 }
} finally {
    try { [Console]::TreatControlCAsInput = $false } catch { }
    Finish-InstallLock $code
    if ($Run.Transcript) { try { Stop-Transcript | Out-Null } catch { } }
    if ($Run.Owner -ne [IntPtr]::Zero) { [void][DefenseClawInstall.Native]::SwapDefaultOwner($Run.Owner) }
    # A variable that was unset stays unset. PowerShell 7 passes $null to
    # SetEnvironmentVariable as "", which leaves an empty variable behind
    # (an empty CLAUDE_CONFIG_DIR signs Claude Code out).
    foreach ($name in $savedEnv.Keys) {
        if ($null -eq $savedEnv[$name]) { Remove-Item -LiteralPath "Env:$name" -ErrorAction SilentlyContinue }
        else { [Environment]::SetEnvironmentVariable($name, $savedEnv[$name], "Process") }
    }
    # `defenseclaw upgrade` and `rollback` run a copy of this installer from a
    # temporary directory of their own (with it as the working directory),
    # holding only the installer and checksums.txt.
    $launchDir = if ($RunAsFile) { Split-Path -Parent $PSCommandPath } else { "" }
    if ($launchDir -and (Split-Path -Leaf $launchDir) -match '^defenseclaw-(upgrade|rollback)-[a-z0-9_]+$' -and
        -not @(Get-ChildItem -LiteralPath $launchDir -Force | Where-Object { $_.Name -notin @("install.ps1", "checksums.txt", "checksums.txt.bundle") }).Count) {
        Set-Location -LiteralPath $env:SystemRoot
        [Environment]::CurrentDirectory = $env:SystemRoot
        Invoke-Quietly { Remove-Tree $launchDir }
    }
}
Wait-BeforeClose $code
if ($RunAsFile) { exit $code }
# `irm | iex` cannot exit, so a failure ends in a terminating error. Raising
# it from a one-line script block keeps PowerShell 7 from printing an excerpt
# of this file under the failure that was already reported above.
if ($code -eq 4) { & ([scriptblock]::Create('throw "DefenseClaw is installed, but quickstart failed; see above"')) }
if ($code -ne 0 -and $code -ne 3) { & ([scriptblock]::Create('throw "DefenseClaw was not installed; see above"')) }
}
# DefenseClaw Windows installer complete v2
