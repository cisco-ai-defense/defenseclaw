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

    Permanent interface (never remove or change these; unknown arguments are
    ignored with a warning): -Yes, -Version X.Y.Z, -Local DIR, -Rollback.

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
try {
    [Net.ServicePointManager]::SecurityProtocol =
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch { }

$DcVersion = "__DEFENSECLAW_VERSION__"
$DefaultRepo = "cisco-ai-defense/defenseclaw"
$Repo = if ($env:DEFENSECLAW_REPO) { $env:DEFENSECLAW_REPO } else { $DefaultRepo }
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
# defenseclaw-hook.exe reads its data dir from the state file beside it, never
# from the environment an agent runs it with (a custom DEFENSECLAW_HOME too).
$HookState = "defenseclaw-hook-state.json"
$ManagedFiles = $ManagedBinaries + @($ManagedShims | ForEach-Object { "$_.cmd" }) + @($PosixShim, $HookState)
# What a `make all` developer install publishes to BinDir besides the managed
# binaries (cmd_uninstall._WINDOWS_DEVELOPER_FILES). PATHEXT runs
# defenseclaw.exe before the defenseclaw.cmd shim, so these must go.
$DeveloperFiles = @("defenseclaw.exe", "litellm.exe", "skill-scanner.exe", "skill-scanner-api.exe",
    "skill-scanner-pre-commit.exe", "mcp-scanner.exe", "mcp-scanner-api.exe", ".defenseclaw-source-root")
# Data-dir entries that are install machinery, not user data.
$NotData = @(".venv", ".venv.busy", ".uv", "previous", "previous.new", ".repair", ".staging", ".failed-*",
    "installer", "logs", ".install.lock", "backups", ".rollback-hold", ".rollback-hold.done")
# Connectors supported on Windows (cli/defenseclaw/platform_support.py).
$ConnectorChoices = @("codex", "claudecode", "hermes", "cursor", "devin", "copilot", "antigravity",
    "opencode", "amp", "omnigent", "kiro", "none")
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
$Run = @{ Lock = $false; Transcript = $false; Log = ""; Owner = [IntPtr]::Zero; QuickstartRerun = ""; QuickstartRc = 0; OldGatewayDown = $false }

function Write-Info([string]$Message) { Write-Host "  > $Message" -ForegroundColor Blue }
function Write-Ok([string]$Message) { Write-Host "  + $Message" -ForegroundColor Green }
function Write-Warn([string]$Message) { Write-Host "  ! $Message" -ForegroundColor Yellow }
function Write-Err([string]$Message) { Write-Host "  x $Message" -ForegroundColor Red }
function Write-Step([string]$Message) { Write-Host ""; Write-Host "--- $Message" -ForegroundColor Cyan }
function Die([string]$Message) { throw $Message }

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

function Confirm-Step([string]$Prompt) {
    if ($Yes) { return $true }
    try { $answer = Read-Host "  $Prompt [Y/n]" } catch { $answer = "" }
    return [string]::IsNullOrWhiteSpace($answer) -or $answer -match '^[Yy]'
}

function Get-Field($Object, [string]$Name) {
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
    Set-Acl -LiteralPath $Path -AclObject $acl
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

function Copy-Kept([string]$Source, [string]$DestinationDir) {
    # Copy into DestinationDir with robocopy, which keeps each file's
    # permissions: DefenseClaw refuses keys and tokens that come back from a
    # rollback with inherited ones.
    $item = Get-Item -LiteralPath $Source -Force
    $copy = if ($item.PSIsContainer) { @($Source, (Join-Path $DestinationDir $item.Name), "/E") } else { @($item.DirectoryName, $DestinationDir, $item.Name) }
    $options = @("/COPY:DATS", "/DCOPY:DAT", "/IS", "/IT", "/R:2", "/W:1", "/NFL", "/NDL", "/NJH", "/NJS", "/NP")
    $rc = Invoke-Native (Join-Path $env:SystemRoot "System32\robocopy.exe") ($copy + $options) -Quiet
    if ($rc -ge 8) { throw "Could not copy $Source (robocopy exit $rc)" }
}

function Invoke-Quietly([scriptblock]$Action) {
    try { & $Action } catch { Write-Warn $_.Exception.Message }
}

function Invoke-Native([string]$FilePath, [string[]]$Arguments = @(), [switch]$Quiet) {
    # Output goes through the host, so the install log (a transcript) keeps it.
    $ErrorActionPreference = "Continue"
    if ($Quiet) { & $FilePath @Arguments *> $null } else { & $FilePath @Arguments 2>&1 | ForEach-Object { Write-Host "$_" } }
    return $LASTEXITCODE
}

function Get-NativeOutput([string]$FilePath, [string[]]$Arguments = @()) {
    $ErrorActionPreference = "Continue"
    try { return ((& $FilePath @Arguments 2>&1) | Out-String) } catch { return "" }
}

function Get-Sha256([string]$Path) {
    return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
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
    return Save-Url "https://github.com/$Repo/releases/download/$Ver/$Name" $Destination
}

function Get-LatestRelease {
    # releases/latest redirects to the latest tag: no API call, no rate limit.
    $tag = ""
    try {
        $request = [Net.HttpWebRequest]::Create("https://github.com/$Repo/releases/latest")
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

function Install-Uv {
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("defenseclaw-uv-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
    New-Item -ItemType Directory -Path $tmp | Out-Null
    try {
        $zip = Join-Path $tmp "uv.zip"
        if (-not (Save-Url "https://github.com/astral-sh/uv/releases/download/$UvVersion/uv-x86_64-pc-windows-msvc.zip" $zip)) { return "" }
        if ((Get-Sha256 $zip) -ne $UvZipSha256) { Write-Err "The uv download does not match its pinned checksum"; return "" }
        Expand-Archive -LiteralPath $zip -DestinationPath (Join-Path $tmp "uv") -Force
        New-Item -ItemType Directory -Path $BinDir -Force | Out-Null
        $record = @()
        foreach ($name in @("uv.exe", "uvx.exe", "uvw.exe")) {
            $file = Join-Path $tmp "uv\$name"
            if (Test-Path -LiteralPath $file) {
                Copy-Item -LiteralPath $file -Destination (Join-Path $BinDir $name) -Force
                $record += "$(Get-Sha256 (Join-Path $BinDir $name))  $name"
            }
        }
        # `defenseclaw uninstall --binaries` removes the uv this installed
        # while it still matches this record.
        Invoke-Quietly { [IO.File]::WriteAllText((Join-Path $BinDir "defenseclaw-uv.sha256"), (($record -join "`n") + "`n")) }
        $uv = Join-Path $BinDir "uv.exe"
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
    # 0 when checksums.txt carries this repository's Release workflow signature.
    $signer = "^https://github\.com/" + [regex]::Escape($Repo) + "/\.github/workflows/release\.yaml@refs/heads/main$"
    return Invoke-Native $Cosign @("verify-blob", "--bundle", $Bundle, "--certificate-identity-regexp", $signer,
        "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com", $Checksums) -Quiet
}

function Invoke-ReleaseInstaller([string]$ReleaseVersion, [string[]]$Forward) {
    # Download that release's installer, verify it, and run it (-Version, or
    # an unstamped copy from the source tree). Named like the directories of
    # `defenseclaw upgrade`, so the installer it runs removes it.
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("defenseclaw-upgrade-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
    New-Item -ItemType Directory -Path $tmp | Out-Null
    try {
        Write-Info "Fetching the installer for DefenseClaw $ReleaseVersion"
        $base = "https://github.com/$Repo/releases/download/$ReleaseVersion"
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
        return $child.ExitCode
    } finally {
        Invoke-Quietly { Remove-Tree $tmp }
    }
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
    $info = Get-ChildItem -LiteralPath (Join-Path $Venv "Lib\site-packages") -Filter "defenseclaw-*.dist-info" `
        -Directory -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($info) { return $info.Name -replace '^defenseclaw-', '' -replace '\.dist-info$', '' }
    $gateway = Join-Path $BinDir "defenseclaw-gateway.exe"
    if ((Test-Path -LiteralPath $gateway) -and (Get-NativeOutput $gateway @("--version")) -match '\d+\.\d+\.\d+') {
        return $Matches[0]
    }
    return ""
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

function Stop-Gateway {
    # Stop the running gateway with its own (the old) binary; kill it as a last
    # resort. Wait for the process itself, not its pid file: a gateway removes
    # the file before it exits, and while it runs Windows will not let the
    # migration replace the config it holds open.
    $process = Get-GatewayProcess
    if (-not $process) { return $true }
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
    return $process.HasExited -and -not (Get-GatewayProcess)
}

function Start-Gateway {
    # Its readiness wait is the health check. Exit code 3: running, but a
    # connector refused admission (upgrading again would not change that).
    Write-Info "Starting the gateway"
    $gateway = Join-Path $BinDir "defenseclaw-gateway.exe"
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

function Restore-SetupInstall {
    $state = Join-Path $Staging "hook-runtime-state.json"
    if (Test-Path -LiteralPath $state) { Move-Path $state $SetupHookState }
    if (-not $WasRunning) { return }
    $startup = Join-Path $Setup.Root "bin\defenseclaw-startup.exe"
    if (Test-Path -LiteralPath $startup) {
        [void][Diagnostics.Process]::Start($startup).WaitForExit(120000)
    } else {
        Invoke-Native (Join-Path $Setup.Root "bin\defenseclaw-gateway.exe") @("start") -Quiet | Out-Null
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

function Test-ConnectorConfigured {
    $state = Read-Json (Join-Path $DataDir "active_connector.json")
    return @(@(Get-Field $state "names") + @(Get-Field $state "name") | Where-Object { $_ -and $_ -ne "none" }).Count -gt 0
}

# -- Snapshot, swap, restore --------------------------------------------------

function Get-DataEntries {
    return @(Get-ChildItem -LiteralPath $DataDir -Force | Where-Object {
        $name = $_.Name
        -not @($NotData | Where-Object { $name -like $_ }).Count
    })
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
    Copy-Item -LiteralPath $Source -Destination "$Destination.new" -Force
    if (Test-Path -LiteralPath $Destination) { Remove-Aside $Destination }
    Move-Path "$Destination.new" $Destination
}

function Write-PosixShim([string]$Target) {
    # `defenseclaw uninstall` recognizes this launcher by its exec line.
    $path = Join-Path $BinDir $PosixShim
    $text = "#!/bin/sh`n# Git Bash runs this; cmd.exe and PowerShell run defenseclaw.cmd.`nexec `"$($Target -replace '\\', '/')`" `"`$@`"`n"
    if ((Test-Path -LiteralPath $path) -and [IO.File]::ReadAllText($path) -ceq $text) { return }
    [IO.File]::WriteAllText("$path.new", $text, (New-Object Text.UTF8Encoding $false))
    if (Test-Path -LiteralPath $path) { Remove-Aside $path }
    Move-Path "$path.new" $path
}

function Write-Shim([string]$Name, [string]$Target) {
    # `defenseclaw uninstall` recognizes the CLI shim by this exact command line.
    $path = Join-Path $BinDir "$Name.cmd"
    $text = "@echo off`r`n`"$Target`" %*`r`n"
    if ((Test-Path -LiteralPath $path) -and [IO.File]::ReadAllText($path) -ceq $text) { return }
    # cmd.exe reads batch files in the OEM code page.
    $encoding = [Text.Encoding]::GetEncoding([Globalization.CultureInfo]::CurrentCulture.TextInfo.OEMCodePage)
    [IO.File]::WriteAllText("$path.new", $text, $encoding)
    if (Test-Path -LiteralPath $path) { Remove-Aside $path }
    Move-Path "$path.new" $path
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
    if (Test-Path -LiteralPath $path) { Remove-Aside $path }
    Move-Path "$path.new" $path
}

function Copy-BinDir([string]$To) {
    New-Item -ItemType Directory -Path $To -Force | Out-Null
    foreach ($name in $ManagedFiles) {
        $live = Join-Path $BinDir $name
        if (Test-Path -LiteralPath $live -PathType Leaf) { Copy-Item -LiteralPath $live -Destination (Join-Path $To $name) }
    }
}

function Restore-BinDir([string]$From) {
    New-Item -ItemType Directory -Path $BinDir -Force | Out-Null
    foreach ($name in $ManagedFiles) {
        $saved = Join-Path $From $name
        $live = Join-Path $BinDir $name
        if (Test-Path -LiteralPath $saved -PathType Leaf) { Install-File $saved $live }
        elseif (Test-Path -LiteralPath $live) { Remove-Aside $live }
    }
}

function New-Venv([string]$Path) {
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
    Write-Info "Installing the Python packages"
    if (-not (Invoke-UvPipInstall $lockArgs)) { return $false }
    Write-Info "Installing the DefenseClaw package and compiling it"
    return (Invoke-UvPipInstall @("pip", "install", "--quiet", "--compile-bytecode", "--python", $python, "--no-deps", (Join-Path $Staging $Wheel)))
}

function Invoke-UvPipInstall([string[]]$UvArgs) {
    if ((Invoke-Native $Uv $UvArgs) -eq 0) { return $true }
    # A scanner holding a file uv just wrote fails its cache rename with
    # os error 32 or 5 (GAP-1315); the cache makes a second attempt cheap.
    Write-Warn "Retrying the Python package install once"
    Start-Sleep -Seconds 5
    return (Invoke-Native $Uv $UvArgs) -eq 0
}

function Save-Snapshot {
    New-InstallDirectory $Snap
    New-Item -ItemType Directory -Path (Join-Path $Snap "data") | Out-Null
    $entries = Get-DataEntries
    $need = [long]0
    foreach ($entry in $entries) { $need += Get-TreeSize $entry.FullName }
    $free = [long]-1
    try { $free = ([IO.DriveInfo][IO.Path]::GetPathRoot([IO.Path]::GetFullPath($DataDir))).AvailableFreeSpace } catch { }
    # A large audit.db makes this copy (and the antivirus scan of it) slow;
    # say how big it is and what is free (GAP-1519).
    $freeText = if ($free -ge 0) { ", {0:N0} MB free" -f ([double]$free / 1MB) } else { "" }
    Write-Info ("Saving a rollback copy of the data folder ({0:N0} MB needed{1})" -f ([double]$need / 1MB), $freeText)
    if ($free -ge 0 -and $free -lt $need + 100MB) {
        Write-Err "Not enough free disk space next to $DataDir for a rollback copy"
        return $false
    }
    Copy-BinDir (Join-Path $Snap "bin")
    foreach ($entry in $entries) { Copy-Kept $entry.FullName (Join-Path $Snap "data") }
    Save-ExternalConfig $Snap
    if (Test-Path -LiteralPath $Venv) { Move-Path $Venv (Join-Path $Snap "venv") 60 }
    if (Test-Path -LiteralPath $InstallerDir) { Move-Path $InstallerDir (Join-Path $Snap "installer") }
    Set-Content -LiteralPath (Join-Path $Snap "VERSION") -Value $PrevVersion -Encoding Ascii
    Set-Content -LiteralPath (Join-Path $Snap "GATEWAY_WAS_RUNNING") -Value ([string]$WasRunning).ToLowerInvariant() -Encoding Ascii
    Set-Content -LiteralPath (Join-Path $Snap "COMPLETE") -Value "" -Encoding Ascii
    return $true
}

function Undo-Snapshot([string]$Slot) {
    # Put back what an unfinished Save-Snapshot moved.
    if ((Test-Path -LiteralPath (Join-Path $Slot "venv")) -and -not (Test-Path -LiteralPath $Venv)) { Move-Path (Join-Path $Slot "venv") $Venv 60 }
    if ((Test-Path -LiteralPath (Join-Path $Slot "installer")) -and -not (Test-Path -LiteralPath $InstallerDir)) {
        Move-Path (Join-Path $Slot "installer") $InstallerDir
    }
    Remove-Tree $Slot
}

function Protect-BinDir {
    # The CLI runs only a gateway whose file and folder no account other than
    # this one, LocalSystem and the built-in Administrators group (matched by
    # SID) can write. A ~\.local\bin another tool created with a looser ACL
    # (Users or Everyone may write) fails that check, and the CLI then refuses
    # the gateway installed there. Keep only this account and LocalSystem on
    # such a folder; what it holds inherits that.
    $user = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $trusted = @($user.Value, "S-1-5-18", "S-1-3-4", "S-1-5-32-544")
    # The write rights the CLI's custody check counts (GENERIC_ALL/WRITE included).
    $write = 0x500D0156
    $acl = Get-Acl -LiteralPath $BinDir
    $open = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | Where-Object {
        $_.AccessControlType -eq "Allow" -and ([int]$_.FileSystemRights -band $write) -and $trusted -notcontains $_.IdentityReference.Value
    })
    if (-not $open.Count) { return }
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
    if (-not (New-Venv $Venv)) { return $false }
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
    if (Test-Path -LiteralPath $target) { Write-PosixShim $target }
    elseif (Test-Path -LiteralPath (Join-Path $BinDir $PosixShim)) { Remove-Aside (Join-Path $BinDir $PosixShim) }
    Write-HookState
    if ((Test-Path -LiteralPath (Join-Path $DataDir "config.yaml")) -or $env:DEFENSECLAW_CONFIG) {
        Write-Info "Migrating config and data"
        if ($PrevVersion -and [version]$PrevVersion -lt [version]"1.0.0") { Repair-DataOwner }
        $migrateArgs = @("migrate", "--yes")
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
    }
    return $true
}

function Restart-Old {
    if ($Setup) { Restore-SetupInstall } elseif ($WasRunning) { [void](Start-Gateway) }
    # Say plainly when the gateway that ran before is down now (GAP-1349).
    $Run.OldGatewayDown = $WasRunning -and -not (Get-GatewayProcess)
    if ($Run.OldGatewayDown) {
        Write-Warn "The gateway that was running before did not start again, so agent hooks are not guarded until it runs (connectors in fail-closed mode block tool calls)"
        Write-Info "Start it with: defenseclaw-gateway start (log: $(Join-Path $DataDir 'gateway.log')). On a large audit database its first start can take several minutes"
    }
}

function Get-RestoredNote {
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
    if ($config) { Copy-Kept (Join-Path $Slot "config\$(Split-Path -Leaf $config)") (Split-Path -Parent $config) }
}

function Restore-Slot([string]$Slot) {
    # Put the install saved in $Slot back; what it replaces goes to .failed-<time>.
    # Only the latest failed install is kept: with a large audit database
    # each copy holds gigabytes, and an earlier one is not used again.
    foreach ($old in @(Get-ChildItem -LiteralPath $DataDir -Directory -Force -Filter ".failed-*" -ErrorAction SilentlyContinue)) {
        Invoke-Quietly { Remove-Tree $old.FullName }
    }
    $failed = Join-Path $DataDir (".failed-" + (Get-Date -Format "yyyyMMddTHHmmss"))
    New-InstallDirectory $failed
    New-Item -ItemType Directory -Path (Join-Path $failed "data") | Out-Null
    Invoke-Quietly { Restore-BinDir (Join-Path $Slot "bin") }
    foreach ($part in @(@($Venv, "venv"), @($InstallerDir, "installer"))) {
        Invoke-Quietly { if (Test-Path -LiteralPath $part[0]) { Move-Path $part[0] (Join-Path $failed $part[1]) 60 } }
        Invoke-Quietly { if (Test-Path -LiteralPath (Join-Path $Slot $part[1])) { Move-Path (Join-Path $Slot $part[1]) $part[0] 60 } }
    }
    foreach ($entry in Get-DataEntries) {
        Invoke-Quietly { try { Move-Path $entry.FullName (Join-Path $failed "data\$($entry.Name)") } catch { Remove-Tree $entry.FullName } }
    }
    foreach ($entry in @(Get-ChildItem -LiteralPath (Join-Path $Slot "data") -Force)) {
        Invoke-Quietly { Move-Path $entry.FullName (Join-Path $DataDir $entry.Name) }
    }
    Invoke-Quietly { Restore-ExternalConfig $Slot }
    Invoke-Quietly { Remove-Tree $Slot }
    return $failed
}

function Restore-Snapshot {
    $failed = Restore-Slot $Snap
    Restart-Old
    $bytes = (Get-ChildItem -LiteralPath $failed -Recurse -Force -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
    Write-Warn ("The failed $Ver install was kept in $failed ({0:N1} MB) for troubleshooting" -f ([double]$bytes / 1MB))
    Write-Info "Your previous install and its data are back; it is safe to remove the copy with: cmd /c rd /s /q `"$failed`""
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
    $bytes = (Get-ChildItem -LiteralPath $kept -Recurse -Force -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
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
    # re-running the installer is always the recovery.
    foreach ($slot in @((Join-Path $DataDir "previous.new"), (Join-Path $DataDir ".repair"))) {
        if (-not (Test-Path -LiteralPath $slot)) { continue }
        if (Test-Path -LiteralPath (Join-Path $slot "COMPLETE")) {
            Write-Warn "An earlier install was interrupted; restoring the install it replaced"
            [void](Stop-Gateway)
            $wasRunning = (Read-Text (Join-Path $slot "GATEWAY_WAS_RUNNING")) -eq "true"
            $state = Join-Path $Staging "hook-runtime-state.json"
            if ((Test-Path -LiteralPath $state) -and -not (Test-Path -LiteralPath $SetupHookState)) { Move-Path $state $SetupHookState }
            $failed = Restore-Slot $slot
            if ($wasRunning) { [void](Start-Gateway) }
            Write-Warn "The interrupted install was kept in $failed"
        } else {
            # The snapshot never finished, so live data was only copied, not changed.
            Undo-Snapshot $slot
        }
    }
    $hold = Join-Path $DataDir ".rollback-hold"
    # A hold is deleted by renaming it first, so a half-deleted one is never read.
    Remove-Tree "$hold.done"
    $restart = (Read-Text (Join-Path $hold "GATEWAY_WAS_RUNNING")) -eq "true"
    if (Test-Path -LiteralPath (Join-Path $hold "ROLLED_BACK")) {
        # The rollback itself had finished; only renaming its hold was left.
        # START_AFTER is its own decision; previous\ may be half deleted.
        Write-Warn "An earlier rollback was interrupted; finishing it"
        $restart = $restart -or (Read-Text (Join-Path $hold "START_AFTER")) -eq "true"
        Remove-Tree $Previous
        Move-Path $hold $Previous
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
    if ($restart -and -not (Get-GatewayProcess) -and (Start-Gateway) -notin @(0, 3)) {
        Write-Warn "The gateway did not start; run 'defenseclaw-gateway start' and check its log"
    }
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
    Write-Info "Cleaning up the previous install's files (this can take a minute or two)"
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
    try { $choice = Read-Host "  Choice [default 1=codex]" } catch { $choice = "" }
    $number = 0
    $picked = "codex"
    if ([int]::TryParse($choice, [ref]$number) -and $number -ge 1 -and $number -le $ConnectorChoices.Count) {
        $picked = $ConnectorChoices[$number - 1]
    }
    Write-Ok "Connector: $picked"
    return $picked
}

function Invoke-FirstInstallExtras {
    if ($Connector -and $Connector -ne "none") {
        Set-Content -LiteralPath (Join-Path $DataDir "picked_connector") -Value $Connector -Encoding Ascii
    }
    if ($Quickstart) {
        if (-not $Connector -or $Connector -eq "none") {
            Write-Warn "Quickstart needs a connector; run 'defenseclaw init' when ready"
        } else {
            $quickstartArgs = @("quickstart", "--non-interactive", "--yes", "--connector", $Connector)
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
  -Help                 Show this help

Exit codes (run as a file):
  0  Installed        1  Not installed (a previous install is restored)
  3  Installed; a connector needs attention before it is guarded again
  4  Installed; the first-run quickstart failed (re-run it as shown)

Environment:
  DEFENSECLAW_HOME      Data directory (default: %USERPROFILE%\.defenseclaw)
"@ | Write-Host
}

# -- Main ---------------------------------------------------------------------

function Invoke-Rollback {
    $backTo = Read-Text (Join-Path $Previous "VERSION")
    if (-not (Test-Version $backTo)) { Write-Step "Rolling back"; Die "No previous install to roll back to ($Previous is missing)" }
    if (Test-Path -LiteralPath (Join-Path $Previous "legacy-setup")) {
        Die ("The previous install is DefenseClaw Setup $backTo, which cannot be restored automatically. To go back to it, " +
            "run 'defenseclaw uninstall', then download DefenseClawSetup-x64.exe from https://github.com/$Repo/releases/tag/$backTo " +
            "and run it in your desktop session. Its files and your data from before the upgrade are in $Previous; nothing was changed")
    }
    $current = Get-InstalledVersion
    $currentLabel = if ($current) { $current } else { "?" }
    # Run again after a rollback, this goes forward to the newer install (GAP-1497).
    if ($current -and (Test-Version $current) -and [version]$current -lt [version]$backTo) {
        Write-Step "Rolling forward to DefenseClaw $backTo"
        $question = "Replace DefenseClaw $current with DefenseClaw $backTo (the install you rolled back from)?"
    } else {
        Write-Step "Rolling back to DefenseClaw $backTo"
        $question = "Replace DefenseClaw $currentLabel with the previous install ($backTo)?"
    }
    if (-not (Confirm-Step $question)) {
        Die "Rollback cancelled; nothing was changed"
    }
    Wait-VenvFree
    $wasRunning = [bool](Get-GatewayProcess)
    $startAfter = $wasRunning -or (Read-Text (Join-Path $Previous "GATEWAY_WAS_RUNNING")) -eq "true"
    if (-not (Stop-Gateway)) { Die "The gateway did not stop; nothing was changed" }
    $swapped = @(Switch-WithPrevious $current $wasRunning $startAfter)[-1]
    if ($swapped -ne 0) {
        # 1: the swap undid itself, so this install is back and may run again.
        if ($swapped -eq 1 -and $wasRunning) { [void](Start-Gateway) }
        Die "Rollback failed part-way; see $($Run.Log)"
    }
    if ($startAfter -and (Start-Gateway) -notin @(0, 3)) {
        Write-Warn "The gateway did not start; run 'defenseclaw-gateway start' and check its log"
    }
    $forward = if ($current) { $current } else { "1.x" }
    if ([version]$backTo -lt [version]"1.0.0") {
        # 0.x has no `defenseclaw rollback`; the 1.x installer is parked in previous\.
        Write-Ok ("Now running DefenseClaw $backTo. To return to $forward, run: " +
            "powershell -ExecutionPolicy Bypass -File `"$Previous\installer\install.ps1`" -Rollback")
    } else {
        Write-Ok "Now running DefenseClaw $backTo. Run 'defenseclaw rollback' again to return to $forward."
    }
    return 0
}

function Invoke-Install {
    if ($Help) { Show-Usage; return 0 }
    foreach ($argument in $UnknownArguments) { Write-Warn "Ignoring unknown option: $argument" }
    $Connector = $Connector.Trim().ToLowerInvariant()
    if ($Connector -and $ConnectorChoices -notcontains $Connector) {
        Die "Invalid -Connector '$Connector'. Choices on Windows: $($ConnectorChoices -join ' ')"
    }
    if ($NoOpenclaw -and -not $Connector) { $Connector = "none" }
    if ($QuickstartMode -and $QuickstartMode -notin @("observe", "action")) { Die "invalid -QuickstartMode: $QuickstartMode" }
    if ($QuickstartMode) { $Quickstart = $true }
    $TargetVersion = $Version -replace '^v', ''
    if ($TargetVersion -and -not (Test-Version $TargetVersion)) { Die "-Version must look like 1.2.3, got '$Version'" }
    $LocalDir = ""
    if ($Local) {
        if (-not (Test-Path -LiteralPath $Local -PathType Container)) { Die "Directory not found: $Local" }
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
        Die "DefenseClaw $TargetVersion predates this installer; see https://github.com/$Repo/releases/tag/$TargetVersion"
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
    if ($TargetVersion -and $TargetVersion -ne $Ver -and -not $Rollback) {
        if ($LocalDir) { Die "-Local $LocalDir holds $Ver, not $TargetVersion" }
        return Invoke-ReleaseInstaller $TargetVersion $Forward
    }

    # Lock and log.
    New-Item -ItemType Directory -Path (Join-Path $DataDir "logs") -Force | Out-Null
    $acl = Get-Acl -LiteralPath $DataDir
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]) -ne $user) {
        # Created by an elevated installer of an older release.
        $acl.SetOwner($user)
        Set-Acl -LiteralPath $DataDir -AclObject $acl
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
    Resume-InterruptedRun

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

    # Never pick up uv settings (overrides, indexes) from a project in the cwd.
    $env:UV_NO_CONFIG = "1"
    # The download cache and the Python uv fetches for the venv stay in the
    # data dir, so `uninstall --all` leaves nothing of them in AppData.
    if (-not $env:UV_CACHE_DIR) { $env:UV_CACHE_DIR = Join-Path $DataDir ".uv\cache" }
    if (-not $env:UV_PYTHON_INSTALL_DIR) { $env:UV_PYTHON_INSTALL_DIR = Join-Path $DataDir ".uv\python" }
    $Uv = [string](Get-Command uv.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty Source)
    # A uv already in the bin folder belongs to the user (or an earlier run)
    # even when that folder is not on PATH yet: use it, never overwrite it.
    if (-not $Uv -and (Test-Path -LiteralPath (Join-Path $BinDir "uv.exe") -PathType Leaf)) { $Uv = Join-Path $BinDir "uv.exe" }
    if (-not $Uv) {
        Write-Info "Installing uv $UvVersion (Python package manager)"
        $Uv = Install-Uv
        if (-not $Uv) { Die "Could not install uv; install it from https://docs.astral.sh/uv/ and retry" }
    }

    New-InstallDirectory $Staging
    New-Item -ItemType Directory -Path (Join-Path $Staging "bin") | Out-Null
    $Archive = "defenseclaw-$Ver-windows-amd64.zip"
    $Wheel = "defenseclaw-$Ver-py3-none-any.whl"
    $Requirements = "defenseclaw-$Ver-requirements.txt"

    Write-Info "Downloading and verifying release assets"
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
    if (-not (Get-NativeOutput $stagedGateway @("--version")).Contains($Ver)) { Die "The downloaded gateway does not report version $Ver" }

    # A first install with an empty uv cache downloads Python and every
    # package, then compiles the bytecode: about 7 minutes on a busy Windows
    # host with nothing printed (GAP-1665), so say so up front.
    Write-Info "Building the Python environment (a first install can take several minutes)"
    if (-not (New-Venv (Join-Path $Staging "venv"))) { Die "Could not install the DefenseClaw $Ver Python package; nothing was changed" }
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
        if (-not (Confirm-Step "Upgrade DefenseClaw $PrevVersion -> ${Ver}?")) { Die "Cancelled; nothing was changed" }
    }
    if (-not $PrevVersion -and -not $Yes -and -not $Connector) { $Connector = Select-Connector }

    Wait-VenvFree
    if ($Setup) {
        Disable-SetupHooks
        if ($Setup.CodexHome -and -not $env:CODEX_HOME) { $env:CODEX_HOME = $Setup.CodexHome }
        if ($Setup.ClaudeConfigDir -and -not $env:CLAUDE_CONFIG_DIR) { $env:CLAUDE_CONFIG_DIR = $Setup.ClaudeConfigDir }
    }
    $WasRunning = [bool](Get-GatewayProcess)
    if ($WasRunning) {
        Write-Info "Stopping the gateway"
        if (-not (Stop-Gateway)) {
            if ($Setup) { Restore-SetupInstall }
            Die "The running gateway did not stop; nothing was changed"
        }
    }
    if ($Setup) { Stop-ProcessesUnder $Setup.Root }

    $Snap = if ($PrevVersion -and $PrevVersion -eq $Ver) { Join-Path $DataDir ".repair" } else { Join-Path $DataDir "previous.new" }
    # Ctrl+C now would leave a half-swapped install; it is ignored until the swap is done.
    try { [Console]::TreatControlCAsInput = $true } catch { }
    try { $saved = Save-Snapshot } catch { Write-Err $_.Exception.Message; $saved = $false }
    if (-not $saved) {
        Invoke-Quietly { Undo-Snapshot $Snap }
        Restart-Old
        Die "Could not save the current install; nothing was changed"
    }
    $previousLabel = if ($PrevVersion) { $PrevVersion } else { "the previous state" }
    try { $installed = Install-New } catch { Write-Err $_.Exception.Message; $installed = $false }
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
    $startNew = $WasRunning -or $sealOnly -or ($Setup -and (Test-ConnectorConfigured))
    if ($startNew -and -not (Test-Path -LiteralPath (Join-Path $DataDir "config.yaml")) -and -not $env:DEFENSECLAW_CONFIG) {
        # 0.x gateways ran on defaults without a config; 1.x needs one.
        $startNew = $false
        Write-Warn "The gateway was running without a configuration; run 'defenseclaw init' to set it up"
    }
    if ($startNew) {
        $startRc = Start-Gateway
        if ($sealOnly) {
            [void](Stop-Gateway)
            if ($startRc -ne 0 -and $startRc -ne 3) {
                Write-Warn "The $Ver gateway did not start (see above); fix what it reports, then run 'defenseclaw-gateway start'"
                $startRc = 0
            }
        } elseif ($startRc -ne 0 -and $startRc -ne 3) {
            Write-Err "The $Ver gateway did not become healthy; restoring $previousLabel"
            [void](Stop-Gateway)
            Restore-Snapshot
            Die "DefenseClaw $Ver was not installed. $(Get-RestoredNote) Log: $($Run.Log)"
        }
    }
    Complete-Swap
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
        Write-Host "  Upgraded from $PrevVersion. Undo with: defenseclaw rollback"
    }
    if ($PrevVersion -and $configured -and -not (Get-GatewayProcess)) {
        # GAP-1496: it was not running before the upgrade, so it was not started.
        Write-Warn "The gateway is not running, so agent hooks are not guarded until it is"
        Write-Host "  Start it with: defenseclaw-gateway start" -ForegroundColor Cyan
    }
    if ($PrevVersion -and -not $Setup -and -not $Quickstart -and -not $configured) {
        # An earlier install that was never initialized: say how to start, as a
        # fresh install does, with the connector picked back then.
        $nextConnector = $Connector
        $pickedPath = Join-Path $DataDir "picked_connector"
        if (-not $nextConnector -and (Test-Path -LiteralPath $pickedPath)) {
            $nextConnector = ([string](Get-Content -LiteralPath $pickedPath -TotalCount 1)) -replace '[^a-z0-9_-]', ''
        }
        if ($nextConnector -and $nextConnector -ne "none") {
            Write-Host "  DefenseClaw is not set up yet. Next: defenseclaw init --connector $nextConnector" -ForegroundColor Cyan
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
foreach ($name in @("UV_NO_CONFIG", "UV_CACHE_DIR", "UV_PYTHON_INSTALL_DIR", "UV_INSTALL_DIR", "UV_NO_MODIFY_PATH", "DEFENSECLAW_GATEWAY_BIN",
        "DEFENSECLAW_UPGRADE_FRESH_PROCESS", "CODEX_HOME", "CLAUDE_CONFIG_DIR")) {
    $savedEnv[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
}
$code = 1
try {
    $code = [int](@(Invoke-Install) | Select-Object -Last 1)
} catch {
    Write-Err $_.Exception.Message
    if ($_.FullyQualifiedErrorId -ne $_.Exception.Message) { Write-Host $_.InvocationInfo.PositionMessage -ForegroundColor DarkGray }
    $code = 1
} finally {
    try { [Console]::TreatControlCAsInput = $false } catch { }
    if ($Run.Transcript) { try { Stop-Transcript | Out-Null } catch { } }
    if ($Run.Lock) { Invoke-Quietly { Remove-Tree $LockDir } }
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
