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
    Native Windows release gate for the manifest-driven upgrade path.
.DESCRIPTION
    Builds an isolated release server from a sealed candidate and real
    published Windows releases.  For a hard-cut candidate it proves that an
    explicit published-source -> target request is side-effect free, injects a
    post-mutation bridge failure, kills bridge/recovery processes twice to prove
    journaled re-entry, and proves exact healthy source restoration. It then
    proves both the automatic source -> 0.8.4 -> target route and the direct
    0.8.4 -> target route plus phase-two rollback. The bridge is never
    synthesized from source.

    A 0.8.4 bridge candidate is handled as the release immediately before the
    hard cut: the gate proves the fresh-install guard and a real published-
    source -> candidate upgrade. Once 0.8.4 is published, a 0.8.5+ candidate
    takes the full hard-cut branch automatically from its signed manifest.
.PARAMETER ReleaseDir
    Flat sealed candidate directory (normally release-candidate/dist).
.PARAMETER TargetVersion
    Canonical candidate release version, X.Y.Z.
.PARAMETER SourceVersion
    Exact published pre-bridge baseline to exercise. The version must be listed
    in release/upgrade-baselines.json. If omitted, the newest published
    pre-bridge baseline is used for local compatibility; release CI should pass
    every pre-bridge baseline through a job matrix.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ReleaseDir,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$')]
    [string]$TargetVersion,

    [ValidatePattern('^$|^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$')]
    [string]$SourceVersion = "",

    [ValidateRange(1, 600)]
    [int]$HealthTimeout = 60,

    [switch]$KeepWorkDir
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$script:Repository = "cisco-ai-defense/defenseclaw"
$script:OldBaseline = ""
$script:BridgeVersion = "0.8.4"
$script:HardCutVersion = "0.8.5"
$script:PublishedPreBridgeBaselines = @()
$script:SourceVersionSpecified = $PSBoundParameters.ContainsKey("SourceVersion")
$script:WorkRoot = ""
$script:ReleaseRoot = ""
$script:ServerProcess = $null
$script:ServerBaseUrl = ""
$script:Cases = New-Object System.Collections.Generic.List[object]
$script:Sentinels = New-Object System.Collections.Generic.List[object]
$script:SavedEnvironment = @{}
$script:SavedUserPath = $null
$script:SavedUserPathCaptured = $false

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Write-Ok {
    param([string]$Message)
    Write-Host "OK: $Message" -ForegroundColor Green
}

function Fail {
    param([string]$Message)
    throw $Message
}

function Compare-Version {
    param([string]$Left, [string]$Right)
    return ([version]$Left).CompareTo([version]$Right)
}

function Get-Property {
    param([object]$Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    return $Object.PSObject.Properties[$Name]
}

function Read-UpgradeBaselinePolicy {
    $path = Join-Path (Join-Path $PSScriptRoot "..") "release\upgrade-baselines.json"
    try {
        $policy = Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json
    } catch {
        Fail "Could not read the release upgrade-baseline policy: $path"
    }
    $schema = Get-Property $policy "schema_version"
    $published = Get-Property $policy "published_baselines"
    if (-not $schema -or [int]$schema.Value -ne 1 -or -not $published) {
        Fail "Upgrade baseline policy must be a schema_version 1 object"
    }
    $values = @($published.Value)
    if ($values.Count -eq 0) { Fail "Upgrade baseline policy is empty" }
    foreach ($value in $values) {
        if ($value -isnot [string] -or $value -notmatch '^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$') {
            Fail "Upgrade baseline policy contains a non-canonical version"
        }
    }
    if (@($values | Sort-Object -Unique).Count -ne $values.Count) {
        Fail "Upgrade baseline policy contains duplicate versions"
    }
    $eligible = @(
        $values |
            Where-Object { (Compare-Version ([string]$_) $script:BridgeVersion) -lt 0 } |
            Sort-Object { [version]$_ } -Descending
    )
    if ($eligible.Count -eq 0) {
        Fail "Upgrade baseline policy has no published pre-bridge source"
    }
    $script:PublishedPreBridgeBaselines = @($eligible | ForEach-Object { [string]$_ })
    if ($script:SourceVersionSpecified -and -not $SourceVersion) {
        Fail "SourceVersion cannot be empty when explicitly supplied"
    }
    if ($SourceVersion) {
        if ($values -notcontains $SourceVersion) {
            Fail "SourceVersion $SourceVersion is not in the reviewed published-baseline policy"
        }
        if ((Compare-Version $SourceVersion $script:BridgeVersion) -ge 0) {
            Fail "SourceVersion must be a pre-bridge release older than $($script:BridgeVersion)"
        }
        $script:OldBaseline = $SourceVersion
    } else {
        $script:OldBaseline = [string]$eligible[0]
    }
}

function Get-CurrentSid {
    return [Security.Principal.WindowsIdentity]::GetCurrent().User
}

function Set-PrivatePathAcl {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [switch]$Directory
    )

    $owner = Get-CurrentSid
    $system = New-Object Security.Principal.SecurityIdentifier("S-1-5-18")
    $administrators = New-Object Security.Principal.SecurityIdentifier("S-1-5-32-544")
    if ($Directory) {
        $security = New-Object Security.AccessControl.DirectorySecurity
        $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor `
            [Security.AccessControl.InheritanceFlags]::ObjectInherit
    } else {
        $security = New-Object Security.AccessControl.FileSecurity
        $inheritance = [Security.AccessControl.InheritanceFlags]::None
    }
    $security.SetOwner($owner)
    $security.SetAccessRuleProtection($true, $false)
    foreach ($sid in @($owner, $system, $administrators)) {
        $rule = New-Object Security.AccessControl.FileSystemAccessRule(
            $sid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow
        )
        [void]$security.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $security
}

function Assert-PrivateDirectoryAcl {
    param([Parameter(Mandatory = $true)][string]$Path)

    $acl = Get-Acl -LiteralPath $Path
    $owner = (Get-CurrentSid).Value
    $actualOwner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if (-not $acl.AreAccessRulesProtected -or $actualOwner -ne $owner) {
        Fail "Directory is not owner-controlled with a protected DACL: $Path"
    }
    $allowed = @{}
    foreach ($sidValue in @($owner, "S-1-5-18", "S-1-5-32-544")) {
        $allowed[$sidValue] = $true
    }
    foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        $sid = $rule.IdentityReference.Value
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) {
            Fail "Private directory contains a non-allow ACE: $Path"
        }
        if (-not $allowed.ContainsKey($sid)) {
            Fail "Private directory grants access to an unexpected SID ($sid): $Path"
        }
    }
}
function Assert-PrivateFileAcl {
    param([Parameter(Mandatory = $true)][string]$Path)

    $item=Get-Item -LiteralPath $Path -Force
    if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){
        Fail "Private custody is not a real file: $Path"
    }
    $acl=Get-Acl -LiteralPath $Path
    $owner=(Get-CurrentSid).Value
    if(-not $acl.AreAccessRulesProtected -or $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $owner){
        Fail "File is not owner-controlled with a protected DACL: $Path"
    }
    $allowed=@{$owner=$true;"S-1-5-18"=$true;"S-1-5-32-544"=$true}
    foreach($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){
        if($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or -not $allowed.ContainsKey($rule.IdentityReference.Value)){
            Fail "Private file grants unexpected access: $Path"
        }
    }
}

function New-PrivateDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (Test-Path -LiteralPath $Path) {
        Fail "Refusing to reuse private test path: $Path"
    }
    New-Item -ItemType Directory -Path $Path | Out-Null
    try {
        Set-PrivatePathAcl -Path $Path -Directory
        Assert-PrivateDirectoryAcl -Path $Path
    } catch {
        Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue
        throw
    }
    return [IO.Path]::GetFullPath($Path)
}

function Assert-RequiredCommands {
    if ($env:OS -ne "Windows_NT") {
        Fail "This release gate must run on native Windows."
    }
    if (-not [Environment]::Is64BitOperatingSystem) {
        Fail "The native release gate currently requires a 64-bit Windows runner."
    }
    $architecture = if ($env:PROCESSOR_ARCHITEW6432) {
        $env:PROCESSOR_ARCHITEW6432
    } else {
        $env:PROCESSOR_ARCHITECTURE
    }
    if ([string]$architecture -ne "AMD64") {
        Fail "This gate verifies the required windows_amd64 release artifacts; runner architecture is $architecture"
    }
    foreach ($name in @("pwsh", "python", "uv", "cosign")) {
        $command = Get-Command $name -CommandType Application -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if (-not $command) { Fail "Required release-gate command is unavailable: $name" }
        Set-Variable -Scope Script -Name ("Command" + $name) -Value ([string]$command.Source)
    }
}

function Save-ProcessEnvironment {
    $names = @(
        "USERPROFILE", "HOME", "DEFENSECLAW_HOME", "DEFENSECLAW_CONFIG",
        "OPENCLAW_HOME", "APPDATA", "LOCALAPPDATA", "XDG_CONFIG_HOME",
        "PATH", "TEMP", "TMP", "PYTHONDONTWRITEBYTECODE",
        "PYTHONUTF8", "UV_NO_CONFIG", "NO_COLOR",
        "DEFENSECLAW_UPGRADE_TEST_MODE", "DEFENSECLAW_UPGRADE_TEST_RELEASE_BASE_URL",
        "DEFENSECLAW_STAGED_UPGRADE", "DEFENSECLAW_STAGED_BRIDGE_VERSION",
        "DEFENSECLAW_STAGED_BRIDGE_ARTIFACT_DIR", "DEFENSECLAW_STAGED_BRIDGE_BACKUP",
        "DEFENSECLAW_UPGRADE_FRESH_PROCESS", "DEFENSECLAW_TEST_TARGET_WHEEL",
        "DEFENSECLAW_TEST_WHEEL_CRASH_MARKER", "DEFENSECLAW_TEST_PACKAGE_DIR",
        "DEFENSECLAW_TEST_CLI_EXE", "DEFENSECLAW_TEST_WHEEL_RELEASE",
        "DEFENSECLAW_TEST_WHEEL_CONSUMED", "GITHUB_TOKEN", "GH_TOKEN"
    )
    foreach ($name in $names) {
        $script:SavedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
    }
    $script:SavedUserPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $script:SavedUserPathCaptured = $true
}

function Restore-ProcessEnvironment {
    foreach ($name in $script:SavedEnvironment.Keys) {
        [Environment]::SetEnvironmentVariable($name, $script:SavedEnvironment[$name], "Process")
    }
    if ($script:SavedUserPathCaptured) {
        $currentUserPath = [Environment]::GetEnvironmentVariable("Path", "User")
        if ($currentUserPath -ne $script:SavedUserPath) {
            [Environment]::SetEnvironmentVariable("Path", $script:SavedUserPath, "User")
        }
    }
}

function Clear-UpgradeTestEnvironment {
    foreach ($name in @(
        "DEFENSECLAW_UPGRADE_TEST_MODE", "DEFENSECLAW_UPGRADE_TEST_RELEASE_BASE_URL",
        "DEFENSECLAW_STAGED_UPGRADE", "DEFENSECLAW_STAGED_BRIDGE_VERSION",
        "DEFENSECLAW_STAGED_BRIDGE_ARTIFACT_DIR", "DEFENSECLAW_STAGED_BRIDGE_BACKUP",
        "DEFENSECLAW_UPGRADE_FRESH_PROCESS", "DEFENSECLAW_TEST_TARGET_WHEEL",
        "DEFENSECLAW_TEST_WHEEL_CRASH_MARKER", "DEFENSECLAW_TEST_PACKAGE_DIR",
        "DEFENSECLAW_TEST_CLI_EXE", "DEFENSECLAW_TEST_WHEEL_RELEASE",
        "DEFENSECLAW_TEST_WHEEL_CONSUMED", "GITHUB_TOKEN", "GH_TOKEN"
    )) {
        [Environment]::SetEnvironmentVariable($name, $null, "Process")
    }
}

function Set-CaseEnvironment {
    param([Parameter(Mandatory = $true)][object]$Case)

    $env:USERPROFILE = $Case.Home
    $env:HOME = $Case.Home
    $env:DEFENSECLAW_HOME = $Case.Data
    [Environment]::SetEnvironmentVariable("DEFENSECLAW_CONFIG", $null, "Process")
    $env:OPENCLAW_HOME = Join-Path $Case.Home ".openclaw"
    $env:APPDATA = $Case.AppData
    $env:LOCALAPPDATA = $Case.LocalAppData
    $env:XDG_CONFIG_HOME = $Case.XdgConfig
    $originalPath = [string]$script:SavedEnvironment["PATH"]
    $env:PATH = $Case.Bin + [IO.Path]::PathSeparator + $originalPath
    $env:TEMP = $Case.Temp
    $env:TMP = $Case.Temp
    $env:PYTHONDONTWRITEBYTECODE = "1"
    $env:PYTHONUTF8 = "1"
    $env:UV_NO_CONFIG = "1"
    $env:NO_COLOR = "1"
    Clear-UpgradeTestEnvironment
}

function Get-Checksums {
    param([Parameter(Mandatory = $true)][string]$Path)

    $checksums = @{}
    foreach ($raw in Get-Content -LiteralPath $Path -Encoding UTF8) {
        $line = $raw.Trim()
        if (-not $line -or $line.StartsWith("#")) { continue }
        if ($line -notmatch '^([0-9A-Fa-f]{64})\s+(.+)$') {
            Fail "Invalid checksums.txt line in $Path"
        }
        $name = $Matches[2].Trim()
        if ($name.StartsWith("./")) { $name = $name.Substring(2) }
        if (-not $name -or [IO.Path]::GetFileName($name) -ne $name -or $checksums.ContainsKey($name)) {
            Fail "Unsafe or duplicate checksum name in $Path"
        }
        $checksums[$name] = $Matches[1].ToLowerInvariant()
    }
    if ($checksums.Count -eq 0) { Fail "No checksums found in $Path" }
    return $checksums
}

function Assert-ArtifactHash {
    param(
        [Parameter(Mandatory = $true)][string]$Directory,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][hashtable]$Checksums
    )

    $path = Join-Path $Directory $Name
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { Fail "Release artifact missing: $path" }
    if (-not $Checksums.ContainsKey($Name)) { Fail "Signed checksums do not cover $Name" }
    $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $Checksums[$Name]) { Fail "Checksum mismatch for $Name" }
}

function Assert-ReleaseSet {
    param(
        [Parameter(Mandatory = $true)][string]$Directory,
        [Parameter(Mandatory = $true)][string]$Version
    )

    $names = @(
        "checksums.txt",
        "checksums.txt.sig",
        "checksums.txt.pem",
        "upgrade-manifest.json",
        "defenseclaw-$Version-py3-none-any.whl",
        "defenseclaw_${Version}_windows_amd64.zip"
    )
    foreach ($name in $names) {
        if (-not (Test-Path -LiteralPath (Join-Path $Directory $name) -PathType Leaf)) {
            Fail "Release $Version is missing $name"
        }
    }

    $identityArguments = if ((Compare-Version $Version $script:BridgeVersion) -ge 0) {
        @(
            "--certificate-identity",
            "https://github.com/$($script:Repository)/.github/workflows/release.yaml@refs/heads/main"
        )
    } else {
        # Historical pre-bridge releases were produced before main-only release
        # provenance became mandatory. They are seed inputs only; every modern
        # bridge and hard-cut release must match the exact protected workflow.
        @(
            "--certificate-identity-regexp",
            '^https://github\.com/cisco-ai-defense/defenseclaw/\.github/workflows/release\.yaml@refs/heads/(main|release/.+)$'
        )
    }
    & $script:Commandcosign verify-blob `
        --certificate (Join-Path $Directory "checksums.txt.pem") `
        --signature (Join-Path $Directory "checksums.txt.sig") `
        @identityArguments `
        --certificate-oidc-issuer "https://token.actions.githubusercontent.com" `
        (Join-Path $Directory "checksums.txt") *> $null
    if ($LASTEXITCODE -ne 0) { Fail "Sigstore verification failed for release $Version" }

    $checksums = Get-Checksums -Path (Join-Path $Directory "checksums.txt")
    foreach ($name in $names[3..5]) {
        Assert-ArtifactHash -Directory $Directory -Name $name -Checksums $checksums
    }
    try {
        $manifest = Get-Content -LiteralPath (Join-Path $Directory "upgrade-manifest.json") `
            -Raw -Encoding UTF8 | ConvertFrom-Json
    } catch {
        Fail "Release $Version has invalid upgrade-manifest.json"
    }
    $schema = Get-Property $manifest "schema_version"
    $release = Get-Property $manifest "release_version"
    if (-not $schema -or [int]$schema.Value -ne 1 -or -not $release -or [string]$release.Value -ne $Version) {
        Fail "Release $Version has a mismatched upgrade manifest"
    }
    return $manifest
}

function Copy-CandidateRelease {
    $resolved = (Resolve-Path -LiteralPath $ReleaseDir).Path
    $destination = New-PrivateDirectory -Path (Join-Path $script:ReleaseRoot $TargetVersion)
    foreach ($name in @(
        "checksums.txt",
        "checksums.txt.sig",
        "checksums.txt.pem",
        "upgrade-manifest.json",
        "defenseclaw-$TargetVersion-py3-none-any.whl",
        "defenseclaw_${TargetVersion}_windows_amd64.zip"
    )) {
        $source = Join-Path $resolved $name
        if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
            Fail "Sealed candidate is missing $name in $resolved"
        }
        Copy-Item -LiteralPath $source -Destination (Join-Path $destination $name)
    }
    return Assert-ReleaseSet -Directory $destination -Version $TargetVersion
}

function Get-PublishedAsset {
    param(
        [Parameter(Mandatory = $true)][string]$Version,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Destination
    )

    $url = "https://github.com/$($script:Repository)/releases/download/$Version/$Name"
    try {
        Invoke-WebRequest -Uri $url -OutFile $Destination -UseBasicParsing | Out-Null
    } catch {
        Fail "Published release asset is unavailable: $url"
    }
}

function Ensure-PublishedRelease {
    param([Parameter(Mandatory = $true)][string]$Version)

    $directory = Join-Path $script:ReleaseRoot $Version
    if (Test-Path -LiteralPath $directory -PathType Container) {
        [void](Assert-ReleaseSet -Directory $directory -Version $Version)
        return $directory
    }
    $directory = New-PrivateDirectory -Path $directory
    foreach ($name in @(
        "checksums.txt",
        "checksums.txt.sig",
        "checksums.txt.pem",
        "upgrade-manifest.json",
        "defenseclaw-$Version-py3-none-any.whl",
        "defenseclaw_${Version}_windows_amd64.zip"
    )) {
        Get-PublishedAsset -Version $Version -Name $name -Destination (Join-Path $directory $name)
    }
    [void](Assert-ReleaseSet -Directory $directory -Version $Version)
    Write-Ok "Authenticated published Windows release $Version"
    return $directory
}

function Get-FreeTcpPort {
    $listener = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback, 0)
    $listener.Start()
    try { return ([Net.IPEndPoint]$listener.LocalEndpoint).Port } finally { $listener.Stop() }
}

function Quote-ProcessArgument {
    param([Parameter(Mandatory = $true)][string]$Value)
    if ($Value.Contains('"')) { Fail "Process argument contains an unsupported quote" }
    return '"' + $Value + '"'
}

function Start-ReleaseServer {
    for ($attempt = 1; $attempt -le 5; $attempt++) {
        $port = Get-FreeTcpPort
        $stdout = Join-Path $script:WorkRoot "release-server.out.log"
        $stderr = Join-Path $script:WorkRoot "release-server.err.log"
        $process = Start-Process -FilePath $script:Commandpython `
            -ArgumentList @("-m", "http.server", [string]$port, "--bind", "127.0.0.1") `
            -WorkingDirectory $script:ReleaseRoot -NoNewWindow -PassThru `
            -RedirectStandardOutput $stdout -RedirectStandardError $stderr
        $ready = $false
        for ($probe = 0; $probe -lt 50; $probe++) {
            if ($process.HasExited) { break }
            try {
                Invoke-WebRequest -Uri "http://127.0.0.1:$port/$TargetVersion/checksums.txt" `
                    -Method Head -UseBasicParsing -TimeoutSec 2 | Out-Null
                $ready = $true
                break
            } catch {
                Start-Sleep -Milliseconds 200
            }
        }
        if ($ready) {
            $script:ServerProcess = $process
            $script:ServerBaseUrl = "http://127.0.0.1:$port"
            Write-Ok "Loopback release server is ready on port $port"
            return
        }
        if (-not $process.HasExited) { Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue }
    }
    Fail "Could not start the loopback release server"
}

function Invoke-ExternalLogged {
    param(
        [Parameter(Mandatory = $true)][string]$Command,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$LogPath
    )

    & $Command @Arguments *> $LogPath
    return $LASTEXITCODE
}

function Show-LogTail {
    param([string]$Path)
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        Write-Host "--- tail: $Path ---" -ForegroundColor Yellow
        Get-Content -LiteralPath $Path -Tail 100 | Write-Host
    }
}

function Assert-CommandVersion {
    param([string]$Command, [string]$Expected, [string]$Label)
    $output = (& $Command --version 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $output -notmatch [regex]::Escape($Expected)) {
        Fail "$Label did not report $Expected (output: $output)"
    }
}

function New-UpgradeCase {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$BaselineVersion
    )

    Write-Step "Seeding isolated $BaselineVersion Windows installation ($Name)"
    $root = New-PrivateDirectory -Path (Join-Path $script:WorkRoot $Name)
    $caseHome = New-PrivateDirectory -Path (Join-Path $root "profile")
    $data = New-PrivateDirectory -Path (Join-Path $caseHome ".defenseclaw")
    $local = New-PrivateDirectory -Path (Join-Path $caseHome ".local")
    $bin = New-PrivateDirectory -Path (Join-Path $local "bin")
    $appDataRoot = New-PrivateDirectory -Path (Join-Path $caseHome "AppData")
    $appData = New-PrivateDirectory -Path (Join-Path $appDataRoot "Roaming")
    $localAppData = New-PrivateDirectory -Path (Join-Path $appDataRoot "Local")
    $xdgConfig = New-PrivateDirectory -Path (Join-Path $caseHome ".config")
    $temp = New-PrivateDirectory -Path (Join-Path $root "temp")
    $port = Get-FreeTcpPort
    $case = [pscustomobject]@{
        Name = $Name
        Root = $root
        Home = $caseHome
        Data = $data
        Bin = $bin
        AppData = $appData
        LocalAppData = $localAppData
        XdgConfig = $xdgConfig
        Temp = $temp
        GatewayPort = $port
        Venv = Join-Path $data ".venv"
        Python = Join-Path (Join-Path (Join-Path $data ".venv") "Scripts") "python.exe"
        Cli = Join-Path (Join-Path (Join-Path $data ".venv") "Scripts") "defenseclaw.exe"
        Gateway = Join-Path $bin "defenseclaw-gateway.exe"
    }
    Set-CaseEnvironment -Case $case

    $venvLog = Join-Path $root "seed-venv.log"
    $status = Invoke-ExternalLogged -Command $script:Commanduv `
        -Arguments @("--no-config", "venv", $case.Venv, "--python", $script:Commandpython, "--quiet") `
        -LogPath $venvLog
    if ($status -ne 0) { Show-LogTail $venvLog; Fail "Could not create isolated venv for $Name" }

    # Install the target first to resolve the candidate dependency graph, then
    # replace only the DefenseClaw package with the real published baseline.
    # This is the same seed strategy used by the cross-platform release gate;
    # neither the controller nor gateway is synthesized from this checkout.
    $targetWheel = Join-Path (Join-Path $script:ReleaseRoot $TargetVersion) `
        "defenseclaw-$TargetVersion-py3-none-any.whl"
    $depsLog = Join-Path $root "seed-target-dependencies.log"
    $status = Invoke-ExternalLogged -Command $script:Commanduv `
        -Arguments @("--no-config", "pip", "install", "--python", $case.Python, "--quiet", $targetWheel) `
        -LogPath $depsLog
    if ($status -ne 0) { Show-LogTail $depsLog; Fail "Could not install candidate dependency graph" }

    $baselineDirectory = Join-Path $script:ReleaseRoot $BaselineVersion
    $baselineWheel = Join-Path $baselineDirectory "defenseclaw-$BaselineVersion-py3-none-any.whl"
    $baselineLog = Join-Path $root "seed-$BaselineVersion.log"
    $status = Invoke-ExternalLogged -Command $script:Commanduv `
        -Arguments @(
            "--no-config", "pip", "install", "--python", $case.Python,
            "--quiet", "--no-deps", "--reinstall", $baselineWheel
        ) -LogPath $baselineLog
    if ($status -ne 0) { Show-LogTail $baselineLog; Fail "Could not install published CLI $BaselineVersion" }

    $gatewayStage = New-PrivateDirectory -Path (Join-Path $root "gateway-stage")
    $gatewayArchive = Join-Path $baselineDirectory "defenseclaw_${BaselineVersion}_windows_amd64.zip"
    Expand-Archive -LiteralPath $gatewayArchive -DestinationPath $gatewayStage -Force
    $gatewayCandidates = @(
        Get-ChildItem -LiteralPath $gatewayStage -Filter "defenseclaw.exe" -File -Recurse
    )
    if ($gatewayCandidates.Count -ne 1) {
        Fail "Published gateway archive $BaselineVersion did not contain one defenseclaw.exe"
    }
    Copy-Item -LiteralPath $gatewayCandidates[0].FullName -Destination $case.Gateway
    Set-PrivatePathAcl -Path $case.Gateway

    $shim = Join-Path $bin "defenseclaw.cmd"
    [IO.File]::WriteAllText(
        $shim,
        "@echo off`r`n`"$($case.Cli)`" %*`r`n",
        [Text.Encoding]::ASCII
    )
    Set-PrivatePathAcl -Path $shim
    $openClawShim = Join-Path $bin "openclaw.cmd"
    [IO.File]::WriteAllText($openClawShim, "@echo off`r`nexit /b 127`r`n", [Text.Encoding]::ASCII)
    Set-PrivatePathAcl -Path $openClawShim
    Remove-Item -LiteralPath $gatewayStage -Recurse -Force

    $yamlData = $data.Replace("'", "''")
    $config = @"
config_version: 7
data_dir: '$yamlData'
gateway:
  api_bind: 127.0.0.1
  api_port: $port
guardrail:
  enabled: false
notifications:
  enabled: false
"@
    $configPath = Join-Path $data "config.yaml"
    [IO.File]::WriteAllText($configPath, $config.Replace("`r`n", "`n"), (New-Object Text.UTF8Encoding($false)))
    Set-PrivatePathAcl -Path $configPath
    $environmentPath = Join-Path $data ".env"
    [IO.File]::WriteAllText(
        $environmentPath,
        "WINDOWS_UPGRADE_SMOKE=preserved`n",
        (New-Object Text.UTF8Encoding($false))
    )
    Set-PrivatePathAcl -Path $environmentPath

    Assert-CommandVersion -Command $case.Cli -Expected $BaselineVersion -Label "published CLI"
    Assert-CommandVersion -Command $case.Gateway -Expected $BaselineVersion -Label "published gateway"
    [void]$script:Cases.Add($case)
    Write-Ok "Seeded real published $BaselineVersion wheel and Windows gateway"
    return $case
}

function Add-SnapshotPath {
    param(
        [Parameter(Mandatory = $true)][System.Collections.Generic.List[object]]$Rows,
        [Parameter(Mandatory = $true)][hashtable]$Seen,
        [Parameter(Mandatory = $true)][object]$Case,
        [Parameter(Mandatory = $true)][string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) { return }
    $full = [IO.Path]::GetFullPath($Path)
    if ($Seen.ContainsKey($full)) { return }
    $Seen[$full] = $true
    $item = Get-Item -LiteralPath $full -Force
    $acl = Get-Acl -LiteralPath $full
    $relative = [IO.Path]::GetRelativePath($Case.Root, $full).Replace('\', '/')
    $row = [ordered]@{
        path = $relative
        kind = if ($item.PSIsContainer) { "directory" } else { "file" }
        attributes = [string]$item.Attributes
        dacl_sddl = $acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access)
        owner_sid = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
        length = $null
        sha256 = $null
    }
    if (-not $item.PSIsContainer) {
        $row.length = $item.Length
        $row.sha256 = (Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    [void]$Rows.Add([pscustomobject]$row)
}

function Add-SnapshotTree {
    param(
        [Parameter(Mandatory = $true)][System.Collections.Generic.List[object]]$Rows,
        [Parameter(Mandatory = $true)][hashtable]$Seen,
        [Parameter(Mandatory = $true)][object]$Case,
        [Parameter(Mandatory = $true)][string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) { return }
    Add-SnapshotPath -Rows $Rows -Seen $Seen -Case $Case -Path $Path
    foreach ($item in Get-ChildItem -LiteralPath $Path -Force -Recurse) {
        Add-SnapshotPath -Rows $Rows -Seen $Seen -Case $Case -Path $item.FullName
    }
}

function Write-InstalledStateSnapshot {
    param(
        [Parameter(Mandatory = $true)][object]$Case,
        [Parameter(Mandatory = $true)][string]$Output
    )

    $rows = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    Add-SnapshotPath -Rows $rows -Seen $seen -Case $Case -Path $Case.Data
    foreach ($top in Get-ChildItem -LiteralPath $Case.Data -Force) {
        if ($top.Name -ne ".venv") {
            Add-SnapshotTree -Rows $rows -Seen $seen -Case $Case -Path $top.FullName
        }
    }
    Add-SnapshotTree -Rows $rows -Seen $seen -Case $Case -Path (Join-Path $Case.Home ".local")

    # Installed package/controller state is the part of the venv an upgrade
    # replaces.  Snapshot it in full without hashing unrelated dependency
    # caches, standard-library files, or the interpreter itself.
    $sitePackages = Join-Path (Join-Path $Case.Venv "Lib") "site-packages"
    Add-SnapshotTree -Rows $rows -Seen $seen -Case $Case -Path (Join-Path $sitePackages "defenseclaw")
    foreach ($distInfo in Get-ChildItem -LiteralPath $sitePackages -Directory -Filter "defenseclaw-*.dist-info") {
        Add-SnapshotTree -Rows $rows -Seen $seen -Case $Case -Path $distInfo.FullName
    }
    Add-SnapshotPath -Rows $rows -Seen $seen -Case $Case -Path $Case.Cli

    $ordered = @($rows | Sort-Object path)
    [IO.File]::WriteAllText(
        $Output,
        (($ordered | ConvertTo-Json -Depth 6 -Compress) + "`n"),
        (New-Object Text.UTF8Encoding($false))
    )
}

function Assert-SnapshotsEqual {
    param([string]$Before, [string]$After, [string]$Label)
    $beforeHash = (Get-FileHash -LiteralPath $Before -Algorithm SHA256).Hash
    $afterHash = (Get-FileHash -LiteralPath $After -Algorithm SHA256).Hash
    if ($beforeHash -ne $afterHash) {
        Fail "$Label changed installed bytes, ACLs, configuration, cursor, receipts, or artifacts"
    }
}

function Assert-NoSucceededReceipt {
    param([object]$Case)
    $root = Join-Path $Case.Data ".upgrade-receipts"
    if (-not (Test-Path -LiteralPath $root -PathType Container)) { return }
    foreach ($path in Get-ChildItem -LiteralPath $root -Filter "*.json" -File) {
        try { $receipt = Get-Content -LiteralPath $path.FullName -Raw -Encoding UTF8 | ConvertFrom-Json } catch { continue }
        if ([string]$receipt.status -in @("succeeded", "partial")) {
            Fail "A refused operation wrote a success receipt: $($path.FullName)"
        }
    }
}

function Write-TransactionalStateSnapshot {
    param(
        [Parameter(Mandatory = $true)][object]$Case,
        [Parameter(Mandatory = $true)][string]$Output
    )

    $records = @()
    foreach ($name in @("config.yaml", ".env", ".migration_state.json")) {
        $path = Join-Path $Case.Data $name
        if (-not (Test-Path -LiteralPath $path)) {
            $records += [pscustomobject][ordered]@{
                path = $name
                exists = $false
                length = $null
                sha256 = $null
                dacl_sddl = $null
                owner_sid = $null
            }
            continue
        }
        $item = Get-Item -LiteralPath $path -Force
        if ($item.PSIsContainer) { Fail "Transactional state path became a directory: $path" }
        $acl = Get-Acl -LiteralPath $path
        $records += [pscustomobject][ordered]@{
            path = $name
            exists = $true
            length = $item.Length
            sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
            dacl_sddl = $acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access)
            owner_sid = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
        }
    }
    [IO.File]::WriteAllText(
        $Output,
        (($records | ConvertTo-Json -Depth 4 -Compress) + "`n"),
        (New-Object Text.UTF8Encoding($false))
    )
}

function Test-InstallerExistingInstallRefusal {
    param([Parameter(Mandatory = $true)][object]$Case)

    Write-Step "Proving install.ps1 -Local cannot overwrite an existing installation"
    Set-CaseEnvironment -Case $Case
    $before = Join-Path $Case.Root "installer-refusal.before.json"
    $after = Join-Path $Case.Root "installer-refusal.after.json"
    $log = Join-Path $Case.Root "installer-refusal.log"
    $userPathBefore = [Environment]::GetEnvironmentVariable("Path", "User")
    Write-InstalledStateSnapshot -Case $Case -Output $before
    $arguments = @(
        "-NoProfile", "-NonInteractive", "-File", (Join-Path $PSScriptRoot "install.ps1"),
        "-Local", (Resolve-Path -LiteralPath $ReleaseDir).Path,
        "-Connector", "none", "-Yes"
    )
    $status = Invoke-ExternalLogged -Command $script:Commandpwsh -Arguments $arguments -LogPath $log
    if ($status -eq 0) { Show-LogTail $log; Fail "install.ps1 unexpectedly overwrote an existing installation" }
    Write-InstalledStateSnapshot -Case $Case -Output $after
    Assert-SnapshotsEqual -Before $before -After $after -Label "install.ps1 refusal"
    if ([Environment]::GetEnvironmentVariable("Path", "User") -ne $userPathBefore) {
        Fail "install.ps1 refusal changed the persistent user PATH"
    }
    $text = Get-Content -LiteralPath $log -Raw -Encoding UTF8
    if ($text -notmatch '(?i)existing DefenseClaw installation' -or $text -notmatch '(?i)No changes were made') {
        Show-LogTail $log
        Fail "install.ps1 refusal did not explain the fresh-install boundary"
    }
    Write-Ok "install.ps1 refused the existing installation without mutation"
}

function Start-RefusalSentinel {
    param([Parameter(Mandatory = $true)][object]$Case)

    $sentinel = Start-Process -FilePath $script:Commandpwsh `
        -ArgumentList @("-NoProfile", "-NonInteractive", "-Command", 'while ($true) { Start-Sleep -Seconds 30 }') `
        -WindowStyle Hidden -PassThru
    [void]$script:Sentinels.Add($sentinel)
    $pidPath = Join-Path $Case.Data "gateway.pid"
    [IO.File]::WriteAllText($pidPath, ([string]$sentinel.Id + "`n"), [Text.Encoding]::ASCII)
    Set-PrivatePathAcl -Path $pidPath
    return $sentinel
}

function Stop-RefusalSentinel {
    param([object]$Case, [object]$Sentinel)
    Remove-Item -LiteralPath (Join-Path $Case.Data "gateway.pid") -Force -ErrorAction SilentlyContinue
    if ($Sentinel -and -not $Sentinel.HasExited) {
        Stop-Process -Id $Sentinel.Id -Force -ErrorAction SilentlyContinue
        $Sentinel.WaitForExit(5000) | Out-Null
    }
}

function Test-HardCutExplicitRefusal {
    param([Parameter(Mandatory = $true)][object]$Case)

    Write-Step "Proving explicit $($Case.Name): $($script:OldBaseline) -> $TargetVersion refuses pre-mutation"
    Set-CaseEnvironment -Case $Case
    $sentinel = Start-RefusalSentinel -Case $Case
    $before = Join-Path $Case.Root "resolver-refusal.before.json"
    $after = Join-Path $Case.Root "resolver-refusal.after.json"
    $log = Join-Path $Case.Root "resolver-refusal.log"
    $userPathBefore = [Environment]::GetEnvironmentVariable("Path", "User")
    try {
        Write-InstalledStateSnapshot -Case $Case -Output $before
        $arguments = @(
            "-NoProfile", "-NonInteractive", "-File", (Join-Path $PSScriptRoot "upgrade.ps1"),
            "-Version", $TargetVersion, "-Yes", "-HealthTimeout", [string]$HealthTimeout,
            "-ReleaseBaseUrl", $script:ServerBaseUrl, "-TestMode"
        )
        $status = Invoke-ExternalLogged -Command $script:Commandpwsh -Arguments $arguments -LogPath $log
        if ($status -eq 0) { Show-LogTail $log; Fail "Explicit hard-cut request unexpectedly succeeded" }
        if ($sentinel.HasExited -or -not (Get-Process -Id $sentinel.Id -ErrorAction SilentlyContinue)) {
            Fail "Explicit hard-cut refusal crossed the service-stop boundary"
        }
        $pidText = (Get-Content -LiteralPath (Join-Path $Case.Data "gateway.pid") -Raw).Trim()
        if ($pidText -ne [string]$sentinel.Id) { Fail "Explicit refusal changed gateway.pid" }
        Write-InstalledStateSnapshot -Case $Case -Output $after
        Assert-SnapshotsEqual -Before $before -After $after -Label "explicit hard-cut refusal"
        if ([Environment]::GetEnvironmentVariable("Path", "User") -ne $userPathBefore) {
            Fail "Explicit hard-cut refusal changed the persistent user PATH"
        }
        Assert-NoSucceededReceipt -Case $Case
        Assert-CommandVersion -Command $Case.Cli -Expected $script:OldBaseline -Label "refused CLI"
        Assert-CommandVersion -Command $Case.Gateway -Expected $script:OldBaseline -Label "refused gateway"
        $text = Get-Content -LiteralPath $log -Raw -Encoding UTF8
        if ($text -notmatch '(?i)requires bridge' -or $text -notmatch '(?i)No installed state changed') {
            Show-LogTail $log
            Fail "Explicit refusal did not explain the signed bridge requirement"
        }
    } finally {
        Stop-RefusalSentinel -Case $Case -Sentinel $sentinel
    }
    Write-Ok "Explicit hard-cut request left PID, service, config, cursor, ACLs, CLI, and gateway unchanged"
}

function Invoke-ResolverUpgrade {
    param(
        [Parameter(Mandatory = $true)][object]$Case,
        [switch]$Latest,
        [switch]$Explicit
    )

    Set-CaseEnvironment -Case $Case
    $log = Join-Path $Case.Root "upgrade.log"
    $arguments = @(
        "-NoProfile", "-NonInteractive", "-File", (Join-Path $PSScriptRoot "upgrade.ps1"),
        "-Yes", "-HealthTimeout", [string]$HealthTimeout,
        "-ReleaseBaseUrl", $script:ServerBaseUrl, "-TestMode"
    )
    if ($Latest) { $arguments += @("-LatestVersionOverride", $TargetVersion) }
    if ($Explicit) { $arguments += @("-Version", $TargetVersion) }
    $status = Invoke-ExternalLogged -Command $script:Commandpwsh -Arguments $arguments -LogPath $log
    if ($status -ne 0) {
        Show-LogTail $log
        Fail "Production Windows resolver failed for case $($Case.Name)"
    }
}

function Test-PhaseOneRollback {
    param([Parameter(Mandatory = $true)][object]$Case)

    Write-Step "Injecting failure after bridge mutation and proving exact source rollback"
    Set-CaseEnvironment -Case $Case
    $before=Join-Path $Case.Root "phase-one-state.before.json"
    $after=Join-Path $Case.Root "phase-one-state.after.json"
    $log=Join-Path $Case.Root "phase-one-rollback.log"
    $userPathBefore=[Environment]::GetEnvironmentVariable("Path","User")
    Write-TransactionalStateSnapshot -Case $Case -Output $before
    $arguments=@(
        "-NoProfile","-NonInteractive","-File",(Join-Path $PSScriptRoot "upgrade.ps1"),
        "-Yes","-HealthTimeout",[string]$HealthTimeout,
        "-ReleaseBaseUrl",$script:ServerBaseUrl,"-TestMode",
        "-LatestVersionOverride",$TargetVersion,"-InjectPhaseOneFailureAfterMutation"
    )
    $status=Invoke-ExternalLogged -Command $script:Commandpwsh -Arguments $arguments -LogPath $log
    if($status -eq 0){Show-LogTail $log;Fail "Injected phase-one failure unexpectedly succeeded"}
    Write-TransactionalStateSnapshot -Case $Case -Output $after
    Assert-SnapshotsEqual -Before $before -After $after -Label "phase-one bridge rollback"
    Assert-CommandVersion -Command $Case.Cli -Expected $script:OldBaseline -Label "phase-one restored CLI"
    Assert-CommandVersion -Command $Case.Gateway -Expected $script:OldBaseline -Label "phase-one restored gateway"
    & $Case.Gateway status *> $null
    if($LASTEXITCODE -ne 0){Fail "Phase-one rollback did not restore a healthy source gateway"}
    $healthy=$false;$deadline=[DateTime]::UtcNow.AddSeconds([Math]::Min($HealthTimeout,30))
    while([DateTime]::UtcNow -lt $deadline){
        try{[void](Invoke-RestMethod -Uri "http://127.0.0.1:$($Case.GatewayPort)/health" -TimeoutSec 2);$healthy=$true;break}catch{Start-Sleep -Milliseconds 250}
    }
    if(-not $healthy){Fail "Phase-one rollback source health endpoint is unreachable"}
    if([Environment]::GetEnvironmentVariable("Path","User")-ne $userPathBefore){Fail "Phase-one rollback changed persistent user PATH"}
    foreach($receipt in @(Get-UpgradeReceipts -Case $Case)){
        if([string]$receipt.target_version -eq $TargetVersion -and [string]$receipt.status -in @("succeeded","partial")){Fail "Phase-one rollback left a successful hard-cut receipt"}
    }
    $text=Get-Content -LiteralPath $log -Raw -Encoding UTF8
    if($text -notmatch '(?i)restored healthy DefenseClaw'){Show-LogTail $log;Fail "Phase-one failure did not report healthy source restoration"}
    Write-Ok "Phase-one failure restored exact source state, owner/DACL, CLI, gateway, and health"
}

function Assert-PhaseOneJournalCustody {
    param([Parameter(Mandatory = $true)][object]$Case)

    $recoveryRoot=Join-Path $Case.Data ".upgrade-recovery"
    $journal=Join-Path $recoveryRoot "phase-one-active.json"
    Assert-PrivateDirectoryAcl -Path $recoveryRoot
    Assert-PrivateFileAcl -Path $journal
    try{$payload=Get-Content -LiteralPath $journal -Raw -Encoding UTF8|ConvertFrom-Json}catch{Fail "Phase-one active journal is not valid JSON"}
    if([int]$payload.schema_version -ne 1 -or [string]$payload.kind -ne "defenseclaw-phase-one-recovery" -or [string]$payload.plan_id -notmatch '^phase-one-[0-9a-f]{32}$'){
        Fail "Phase-one active journal contract is invalid"
    }
    $planRoot=Join-Path $recoveryRoot ([string]$payload.plan_id)
    Assert-PrivateDirectoryAcl -Path $planRoot
    foreach($path in @((Join-Path $planRoot "source.whl"),(Join-Path $planRoot "source-gateway.exe"))){Assert-PrivateFileAcl -Path $path}
    $stateRoot=Join-Path $planRoot "state";Assert-PrivateDirectoryAcl -Path $stateRoot
    foreach($record in @($payload.state)){
        if($record.existed){Assert-PrivateFileAcl -Path (Join-Path $stateRoot (([string]$record.name).TrimStart('.')+".source"))}
    }
    return [string]$payload.plan_id
}

function Test-PhaseOneCrashRecovery {
    param([Parameter(Mandatory = $true)][object]$Case)

    Write-Step "Killing phase one twice and proving journaled next-invocation recovery"
    Set-CaseEnvironment -Case $Case
    $before=Join-Path $Case.Root "phase-one-crash.before.json"
    $after=Join-Path $Case.Root "phase-one-crash.after.json"
    $firstLog=Join-Path $Case.Root "phase-one-crash-first.log"
    $secondLog=Join-Path $Case.Root "phase-one-crash-recovery.log"
    $finalLog=Join-Path $Case.Root "phase-one-crash-final.log"
    $userPathBefore=[Environment]::GetEnvironmentVariable("Path","User")
    Write-TransactionalStateSnapshot -Case $Case -Output $before
    $baseArguments=@(
        "-NoProfile","-NonInteractive","-File",(Join-Path $PSScriptRoot "upgrade.ps1"),
        "-Yes","-HealthTimeout",[string]$HealthTimeout,
        "-ReleaseBaseUrl",$script:ServerBaseUrl,"-TestMode"
    )
    $status=Invoke-ExternalLogged -Command $script:Commandpwsh -Arguments ($baseArguments+@("-LatestVersionOverride",$TargetVersion,"-InjectPhaseOneCrashAfterMutation")) -LogPath $firstLog
    if($status -eq 0){Show-LogTail $firstLog;Fail "First phase-one hard crash unexpectedly returned success"}
    $planId=Assert-PhaseOneJournalCustody -Case $Case

    $status=Invoke-ExternalLogged -Command $script:Commandpwsh -Arguments ($baseArguments+@("-LatestVersionOverride",$TargetVersion,"-InjectPhaseOneCrashDuringRecovery")) -LogPath $secondLog
    if($status -eq 0){Show-LogTail $secondLog;Fail "Repeated phase-one recovery crash unexpectedly returned success"}
    $reloadedPlanId=Assert-PhaseOneJournalCustody -Case $Case
    if($reloadedPlanId -ne $planId){Fail "Repeated crash replaced the active recovery custody"}

    $status=Invoke-ExternalLogged -Command $script:Commandpwsh -Arguments ($baseArguments+@("-Version",$TargetVersion)) -LogPath $finalLog
    if($status -eq 0){Show-LogTail $finalLog;Fail "Post-recovery explicit hard cut unexpectedly succeeded"}
    $journal=Join-Path (Join-Path $Case.Data ".upgrade-recovery") "phase-one-active.json"
    if(Test-Path -LiteralPath $journal){Fail "Successful next-invocation recovery left an active phase-one journal"}
    if(Test-Path -LiteralPath (Join-Path (Join-Path $Case.Data ".upgrade-recovery") $planId)){Fail "Successful next-invocation recovery left active phase-one custody"}
    Write-TransactionalStateSnapshot -Case $Case -Output $after
    Assert-SnapshotsEqual -Before $before -After $after -Label "repeat-crash phase-one recovery"
    Assert-CommandVersion -Command $Case.Cli -Expected $script:OldBaseline -Label "repeat-crash restored CLI"
    Assert-CommandVersion -Command $Case.Gateway -Expected $script:OldBaseline -Label "repeat-crash restored gateway"
    & $Case.Gateway status *> $null;if($LASTEXITCODE -ne 0){Fail "Repeat-crash recovery did not restore a healthy source gateway"}
    if([Environment]::GetEnvironmentVariable("Path","User")-ne $userPathBefore){Fail "Repeat-crash phase-one recovery changed persistent user PATH"}
    $text=Get-Content -LiteralPath $finalLog -Raw -Encoding UTF8
    if($text -notmatch '(?i)Recovered interrupted phase-one upgrade' -or $text -notmatch '(?i)requires bridge'){
        Show-LogTail $finalLog;Fail "Next resolver invocation did not recover before evaluating the explicit hard cut"
    }
    Write-Ok "Two abrupt phase-one deaths recovered from one durable private journal to exact healthy source state"
}

function Assert-PhaseTwoJournalCustody {
    param([Parameter(Mandatory = $true)][object]$Case)

    $recoveryRoot=Join-Path $Case.Data ".upgrade-recovery";$journal=Join-Path $recoveryRoot "phase-two-active.json"
    Assert-PrivateDirectoryAcl -Path $recoveryRoot;Assert-PrivateFileAcl -Path $journal
    Assert-PrivateFileAcl -Path (Join-Path $recoveryRoot "phase-two-mutator.lease")
    try{$payload=Get-Content -LiteralPath $journal -Raw -Encoding UTF8|ConvertFrom-Json}catch{Fail "Phase-two active journal is not valid JSON"}
    if([int]$payload.schema_version -ne 1 -or [string]$payload.source_version -ne $script:BridgeVersion -or [string]$payload.target_version -ne $TargetVersion -or [string]$payload.os_name -ne "windows"){
        Fail "Phase-two active journal identity is invalid"
    }
    $backupDir=[IO.Path]::GetFullPath([string]$payload.backup_dir);Assert-PrivateDirectoryAcl -Path $backupDir
    $rollbackRoot=Join-Path $backupDir "hard-cut-rollback";Assert-PrivateDirectoryAcl -Path $rollbackRoot
    foreach($custody in @(
        @([string]$payload.rollback_wheel_path,[string]$payload.rollback_wheel_sha256),
        @([string]$payload.rollback_gateway_path,[string]$payload.rollback_gateway_sha256)
    )){
        Assert-PrivateFileAcl -Path $custody[0]
        if((Get-FileHash -LiteralPath $custody[0] -Algorithm SHA256).Hash.ToLowerInvariant() -ne $custody[1]){Fail "Phase-two active custody digest changed"}
    }
    $receiptPath=[IO.Path]::GetFullPath([string]$payload.receipt_path)
    try{$receipt=Get-Content -LiteralPath $receiptPath -Raw -Encoding UTF8|ConvertFrom-Json}catch{Fail "Phase-two active receipt is invalid JSON"}
    if([string]$receipt.from_version -ne $script:BridgeVersion -or [string]$receipt.target_version -ne $TargetVersion -or [string]$receipt.status -ne "pending"){
        Fail "Phase-two active receipt is not the pending hard cut"
    }
    return $receiptPath
}

function Start-ResolverAndKillDuringTargetWheel {
    param([Parameter(Mandatory = $true)][object]$Case)

    Set-CaseEnvironment -Case $Case
    $uvShim=Join-Path $Case.Bin "uv.cmd";$marker=Join-Path $Case.Root "target-wheel-install.blocked"
    $release=Join-Path $Case.Root "target-wheel-install.release";$consumed=Join-Path $Case.Root "target-wheel-install.consumed"
    $stdout=Join-Path $Case.Root "target-wheel-crash.stdout.log";$stderr=Join-Path $Case.Root "target-wheel-crash.stderr.log"
    $log=Join-Path $Case.Root "target-wheel-crash.log"
    $env:DEFENSECLAW_TEST_TARGET_WHEEL="defenseclaw-$TargetVersion-py3-none-any.whl"
    $env:DEFENSECLAW_TEST_WHEEL_CRASH_MARKER=$marker
    $env:DEFENSECLAW_TEST_PACKAGE_DIR=Join-Path (Join-Path $Case.Venv "Lib\site-packages") "defenseclaw"
    $env:DEFENSECLAW_TEST_CLI_EXE=$Case.Cli
    $env:DEFENSECLAW_TEST_WHEEL_RELEASE=$release
    $env:DEFENSECLAW_TEST_WHEEL_CONSUMED=$consumed
    $batch=@"
@echo off
setlocal
echo(%*| findstr.exe /L /C:"%DEFENSECLAW_TEST_TARGET_WHEEL%" >nul
if errorlevel 1 goto delegate
if "%DEFENSECLAW_TEST_WHEEL_CRASH_MARKER%"=="" goto delegate
if exist "%DEFENSECLAW_TEST_WHEEL_CONSUMED%" goto delegate
if exist "%DEFENSECLAW_TEST_PACKAGE_DIR%" rmdir /s /q "%DEFENSECLAW_TEST_PACKAGE_DIR%"
if exist "%DEFENSECLAW_TEST_CLI_EXE%" del /f /q "%DEFENSECLAW_TEST_CLI_EXE%"
>"%DEFENSECLAW_TEST_WHEEL_CRASH_MARKER%" echo target wheel install made the CLI unimportable
:blocked
if exist "%DEFENSECLAW_TEST_WHEEL_RELEASE%" goto released
ping.exe -n 2 127.0.0.1 >nul
goto blocked
:released
>"%DEFENSECLAW_TEST_WHEEL_CONSUMED%" echo orphan mutator released
exit /b 86
:delegate
"$($script:Commanduv)" %*
exit /b %ERRORLEVEL%
"@
    [IO.File]::WriteAllText($uvShim,$batch.Replace("`n","`r`n"),[Text.Encoding]::ASCII);Set-PrivatePathAcl -Path $uvShim
    $arguments=@(
        "-NoProfile","-NonInteractive","-File",(Join-Path $PSScriptRoot "upgrade.ps1"),
        "-Yes","-HealthTimeout",[string]$HealthTimeout,"-ReleaseBaseUrl",$script:ServerBaseUrl,
        "-TestMode","-LatestVersionOverride",$TargetVersion
    )
    $quoted=@($arguments|ForEach-Object{Quote-ProcessArgument ([string]$_)})
    $process=Start-Process -FilePath $script:Commandpwsh -ArgumentList $quoted -NoNewWindow -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    [void]$script:Sentinels.Add($process)
    try{
        $deadline=[DateTime]::UtcNow.AddSeconds([Math]::Max($HealthTimeout*3,120))
        while([DateTime]::UtcNow -lt $deadline -and -not $process.HasExited -and -not(Test-Path -LiteralPath $marker)){Start-Sleep -Milliseconds 100}
        if(-not(Test-Path -LiteralPath $marker)){Fail "Target wheel install did not reach the unimportable-CLI crash barrier"}
        $controllers=@(Get-CimInstance Win32_Process -Filter "ParentProcessId = $($process.Id)"|Where-Object{$_.Name -ieq "python.exe" -and [string]$_.CommandLine -match 'defenseclaw\.main'})
        if($controllers.Count -ne 1){Fail "Could not identify exactly one live phase-two controller child"}
        Stop-Process -Id ([int]$controllers[0].ProcessId) -Force
        [void]$process.WaitForExit(30000)
        if(-not $process.HasExited){Fail "Resolver parent did not exit after its controller was killed"}
    }catch{
        if(-not $process.HasExited){& (Join-Path $env:SystemRoot "System32\taskkill.exe") /PID $process.Id /T /F *> $null;[void]$process.WaitForExit(10000)}
        if((Test-Path -LiteralPath $marker) -and -not(Test-Path -LiteralPath $release)){[IO.File]::WriteAllText($release,"release`n",[Text.Encoding]::ASCII)}
        Remove-Item -LiteralPath $uvShim -Force -ErrorAction SilentlyContinue
        foreach($name in @("DEFENSECLAW_TEST_TARGET_WHEEL","DEFENSECLAW_TEST_WHEEL_CRASH_MARKER","DEFENSECLAW_TEST_PACKAGE_DIR","DEFENSECLAW_TEST_CLI_EXE","DEFENSECLAW_TEST_WHEEL_RELEASE","DEFENSECLAW_TEST_WHEEL_CONSUMED")){[Environment]::SetEnvironmentVariable($name,$null,"Process")}
        throw
    }
    if(Test-Path -LiteralPath $Case.Cli){
        & $Case.Cli --version *> $null
        if($LASTEXITCODE -eq 0){Fail "Crash barrier did not make the canonical CLI unimportable"}
    }
    return [pscustomobject]@{Log=$log;Stdout=$stdout;Stderr=$stderr;UvShim=$uvShim;Release=$release;Consumed=$consumed}
}

function Test-PhaseTwoWheelInstallCrashRecovery {
    param([Parameter(Mandatory = $true)][object]$Case,[Parameter(Mandatory = $true)][object]$Manifest)

    Write-Step "Killing the hard cut during target wheel install with an unimportable CLI"
    $userPathBefore=[Environment]::GetEnvironmentVariable("Path","User")
    $crash=Start-ResolverAndKillDuringTargetWheel -Case $Case
    try{
    $receiptPath=Assert-PhaseTwoJournalCustody -Case $Case
    if(Test-Path -LiteralPath $Case.Cli){Fail "Target wheel crash left a callable canonical CLI instead of exercising bootstrap recovery"}
    $recoveryStdout=Join-Path $Case.Root "phase-two-lease-recovery.stdout.log";$recoveryStderr=Join-Path $Case.Root "phase-two-lease-recovery.stderr.log"
    $recoveryLog=Join-Path $Case.Root "upgrade.log"
    $arguments=@(
        "-NoProfile","-NonInteractive","-File",(Join-Path $PSScriptRoot "upgrade.ps1"),
        "-Yes","-HealthTimeout",[string]$HealthTimeout,"-ReleaseBaseUrl",$script:ServerBaseUrl,
        "-TestMode","-LatestVersionOverride",$TargetVersion
    )
    $quoted=@($arguments|ForEach-Object{Quote-ProcessArgument ([string]$_)})
    $recovery=Start-Process -FilePath $script:Commandpwsh -ArgumentList $quoted -NoNewWindow -PassThru -RedirectStandardOutput $recoveryStdout -RedirectStandardError $recoveryStderr
    [void]$script:Sentinels.Add($recovery)
    try{
        Start-Sleep -Seconds 2
        if($recovery.HasExited){Fail "Recovery resolver exited instead of waiting on the orphan mutator lease"}
        if(Test-Path -LiteralPath $Case.Cli){Fail "Recovery mutated the CLI before the orphan mutator lease was released"}
        [IO.File]::WriteAllText($crash.Release,"release`n",[Text.Encoding]::ASCII);Set-PrivatePathAcl -Path $crash.Release
        $releaseDeadline=[DateTime]::UtcNow.AddSeconds(30)
        while([DateTime]::UtcNow -lt $releaseDeadline -and -not(Test-Path -LiteralPath $crash.Consumed)){Start-Sleep -Milliseconds 100}
        if(-not(Test-Path -LiteralPath $crash.Consumed)){Fail "Orphan target-wheel mutator did not release its lease"}
        [void]$recovery.WaitForExit([Math]::Max($HealthTimeout*5000,300000))
        if(-not $recovery.HasExited -or $recovery.ExitCode -ne 0){Fail "Resolver re-entry failed after the orphan mutator lease released"}
    }finally{
        if(-not(Test-Path -LiteralPath $crash.Release)){[IO.File]::WriteAllText($crash.Release,"release`n",[Text.Encoding]::ASCII)}
        if(-not $recovery.HasExited){& (Join-Path $env:SystemRoot "System32\taskkill.exe") /PID $recovery.Id /T /F *> $null;[void]$recovery.WaitForExit(10000)}
        Start-Sleep -Milliseconds 250
        $crashOutput="";if(Test-Path -LiteralPath $crash.Stdout){$crashOutput+=(Get-Content -LiteralPath $crash.Stdout -Raw -Encoding UTF8)};if(Test-Path -LiteralPath $crash.Stderr){$crashOutput+=(Get-Content -LiteralPath $crash.Stderr -Raw -Encoding UTF8)}
        [IO.File]::WriteAllText($crash.Log,$crashOutput,(New-Object Text.UTF8Encoding($false)))
        $recoveryOutput="";if(Test-Path -LiteralPath $recoveryStdout){$recoveryOutput+=(Get-Content -LiteralPath $recoveryStdout -Raw -Encoding UTF8)};if(Test-Path -LiteralPath $recoveryStderr){$recoveryOutput+=(Get-Content -LiteralPath $recoveryStderr -Raw -Encoding UTF8)}
        [IO.File]::WriteAllText($recoveryLog,$recoveryOutput,(New-Object Text.UTF8Encoding($false)))
        Remove-Item -LiteralPath $crash.UvShim -Force -ErrorAction SilentlyContinue
        foreach($name in @("DEFENSECLAW_TEST_TARGET_WHEEL","DEFENSECLAW_TEST_WHEEL_CRASH_MARKER","DEFENSECLAW_TEST_PACKAGE_DIR","DEFENSECLAW_TEST_CLI_EXE","DEFENSECLAW_TEST_WHEEL_RELEASE","DEFENSECLAW_TEST_WHEEL_CONSUMED")){[Environment]::SetEnvironmentVariable($name,$null,"Process")}
    }
    $journal=Join-Path (Join-Path $Case.Data ".upgrade-recovery") "phase-two-active.json"
    if(Test-Path -LiteralPath $journal){Fail "Successful resolver re-entry left the phase-two journal active"}
    if(Test-Path -LiteralPath $receiptPath){
        $interrupted=Get-Content -LiteralPath $receiptPath -Raw -Encoding UTF8|ConvertFrom-Json
        if([string]$interrupted.status -ne "rolled_back" -or [string]$interrupted.failure_code -ne "interrupted"){
            Show-LogTail $crash.Log;Fail "Wheel-install crash receipt was not completed as rolled_back/interrupted"
        }
    }else{
        Assert-CanonicalUpgradeOutcome -Case $Case -From $script:BridgeVersion -Target $TargetVersion -Status "rolled_back" -FailureCode "interrupted"
    }
    $text=Get-Content -LiteralPath $recoveryLog -Raw -Encoding UTF8
    if($text -notmatch '(?i)Recovered interrupted phase-two hard cut'){Show-LogTail $recoveryLog;Fail "Resolver did not report phase-two bootstrap recovery before continuing"}
    if([Environment]::GetEnvironmentVariable("Path","User")-ne $userPathBefore){Fail "Phase-two bootstrap recovery changed persistent user PATH"}
    Assert-UpgradeSucceeded -Case $Case -Manifest $Manifest -RequireV8 -RequireRetainedBridge
    Write-Ok "Unimportable target-wheel crash bootstrapped the retained bridge, rolled back, and safely continued"
    }finally{
        if(-not(Test-Path -LiteralPath $crash.Release)){[IO.File]::WriteAllText($crash.Release,"release`n",[Text.Encoding]::ASCII)}
        Remove-Item -LiteralPath $crash.UvShim -Force -ErrorAction SilentlyContinue
        foreach($name in @("DEFENSECLAW_TEST_TARGET_WHEEL","DEFENSECLAW_TEST_WHEEL_CRASH_MARKER","DEFENSECLAW_TEST_PACKAGE_DIR","DEFENSECLAW_TEST_CLI_EXE","DEFENSECLAW_TEST_WHEEL_RELEASE","DEFENSECLAW_TEST_WHEEL_CONSUMED")){[Environment]::SetEnvironmentVariable($name,$null,"Process")}
    }
}

function Start-PostPublishPortBlocker {
    param([Parameter(Mandatory = $true)][object]$Case)

    $monitorPath = Join-Path $Case.Root "post-v8-port-blocker.py"
    $markerPath = Join-Path $Case.Root "post-v8-port-blocker.bound"
    $source = @'
import pathlib
import re
import socket
import struct
import sys
import time

config = pathlib.Path(sys.argv[1])
port = int(sys.argv[2])
marker = pathlib.Path(sys.argv[3])
deadline = time.monotonic() + 180
listener = None
saw_v8 = False
published = re.compile(rb"(?m)^\s*config_version:\s*8\s*$")
while time.monotonic() < deadline:
    if listener is None:
        candidate = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            candidate.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        try:
            candidate.bind(("127.0.0.1", port))
            candidate.listen(32)
            candidate.settimeout(0.01)
            listener = candidate
        except OSError:
            candidate.close()
    try:
        payload = config.read_bytes()
    except OSError:
        time.sleep(0.002)
        continue
    is_v8 = bool(published.search(payload))
    if listener is not None and is_v8 and not saw_v8:
        saw_v8 = True
        try:
            marker.write_text("bound-after-v8-publish\n", encoding="ascii")
        except OSError:
            listener.close()
            raise
    if listener is not None:
        if saw_v8 and not is_v8:
            listener.close()
            raise SystemExit(0)
        try:
            connection, _ = listener.accept()
        except (TimeoutError, socket.timeout):
            pass
        else:
            connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("hh", 1, 0))
            connection.close()
    time.sleep(0.002)
if listener is not None:
    listener.close()
raise SystemExit(2)
'@
    [IO.File]::WriteAllText($monitorPath, $source, (New-Object Text.UTF8Encoding($false)))
    Set-PrivatePathAcl -Path $monitorPath
    $stdout = Join-Path $Case.Root "post-v8-port-blocker.out.log"
    $stderr = Join-Path $Case.Root "post-v8-port-blocker.err.log"
    $process = Start-Process -FilePath $script:Commandpython `
        -ArgumentList @(
            (Quote-ProcessArgument $monitorPath),
            (Quote-ProcessArgument (Join-Path $Case.Data "config.yaml")),
            [string]$Case.GatewayPort,
            (Quote-ProcessArgument $markerPath)
        ) `
        -NoNewWindow -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    return [pscustomobject]@{ Process = $process; Marker = $markerPath; ErrorLog = $stderr }
}

function Assert-RolledBackReceipt {
    param([Parameter(Mandatory = $true)][object]$Case)
    $receiptMatches = @(
        (Get-UpgradeReceipts -Case $Case) | Where-Object {
            [string]$_.from_version -eq $script:BridgeVersion -and
            [string]$_.target_version -eq $TargetVersion -and
            [string]$_.status -eq "rolled_back" -and
            [string]$_.failure_code -eq "health_check_failed" -and
            $_.artifacts_verified -eq $true
        }
    )
    if ($receiptMatches.Count -eq 0) {
        # A healthy restored bridge may asynchronously admit the terminal
        # receipt before this assertion runs. In that case require the exact
        # canonical event rather than weakening the rollback outcome check.
        Assert-CanonicalUpgradeOutcome -Case $Case -From $script:BridgeVersion -Target $TargetVersion `
            -Status "rolled_back" -FailureCode "health_check_failed"
    }
}

function Test-PostPublishRollback {
    param([Parameter(Mandatory = $true)][object]$Case)

    Write-Step "Injecting target health failure after v8 publication and proving exact bridge rollback"
    Set-CaseEnvironment -Case $Case
    $before = Join-Path $Case.Root "phase-two-state.before.json"
    $after = Join-Path $Case.Root "phase-two-state.after.json"
    Write-TransactionalStateSnapshot -Case $Case -Output $before
    $blocker = Start-PostPublishPortBlocker -Case $Case
    $log = Join-Path $Case.Root "rollback-injection.log"
    $injectedTimeout = [Math]::Min($HealthTimeout, 15)
    $arguments = @(
        "-NoProfile", "-NonInteractive", "-File", (Join-Path $PSScriptRoot "upgrade.ps1"),
        "-Version", $TargetVersion, "-Yes", "-HealthTimeout", [string]$injectedTimeout,
        "-ReleaseBaseUrl", $script:ServerBaseUrl, "-TestMode"
    )
    try {
        $status = Invoke-ExternalLogged -Command $script:Commandpwsh -Arguments $arguments -LogPath $log
        if ($status -eq 0) {
            Show-LogTail $log
            Fail "Injected post-publish target health failure unexpectedly succeeded"
        }
        if (-not (Test-Path -LiteralPath $blocker.Marker -PathType Leaf)) {
            Show-LogTail $blocker.ErrorLog
            Show-LogTail $log
            Fail "Failure injector never observed v8 publication or could not reserve the gateway port"
        }
        if (-not $blocker.Process.HasExited) {
            $blocker.Process.WaitForExit(20000) | Out-Null
        }
        if (-not $blocker.Process.HasExited) {
            Fail "Post-publish port blocker did not observe rollback to the bridge configuration"
        }
        if ($blocker.Process.ExitCode -ne 0) {
            Show-LogTail $blocker.ErrorLog
            Fail "Post-publish port blocker exited without observing the v7 rollback"
        }
        Write-TransactionalStateSnapshot -Case $Case -Output $after
        Assert-SnapshotsEqual -Before $before -After $after -Label "hard-cut rollback transaction"
        Assert-CommandVersion -Command $Case.Cli -Expected $script:BridgeVersion -Label "rolled-back CLI"
        Assert-CommandVersion -Command $Case.Gateway -Expected $script:BridgeVersion -Label "rolled-back gateway"
        & $Case.Gateway status *> $null
        if ($LASTEXITCODE -ne 0) { Fail "Rolled-back bridge gateway is not healthy" }
        $healthy=$false;$deadline=[DateTime]::UtcNow.AddSeconds([Math]::Min($HealthTimeout,30))
        while([DateTime]::UtcNow -lt $deadline){
            try{[void](Invoke-RestMethod -Uri "http://127.0.0.1:$($Case.GatewayPort)/health" -TimeoutSec 2);$healthy=$true;break}catch{Start-Sleep -Milliseconds 250}
        }
        if(-not $healthy){Fail "Rolled-back bridge health endpoint is unreachable"}
        Assert-RolledBackReceipt -Case $Case
        Assert-RetainedBridgeArtifacts -Case $Case
        $text = Get-Content -LiteralPath $log -Raw -Encoding UTF8
        if ($text -notmatch '(?i)rolled back|rollback') {
            Show-LogTail $log
            Fail "Injected failure log did not report rollback"
        }
    } finally {
        if ($blocker -and -not $blocker.Process.HasExited) {
            Stop-Process -Id $blocker.Process.Id -Force -ErrorAction SilentlyContinue
        }
    }
    Write-Ok "Post-v8 failure restored exact config/.env/cursor bytes and owner/DACL, then recovered healthy 0.8.4"
}

function Get-UpgradeReceipts {
    param([Parameter(Mandatory = $true)][object]$Case)
    $root = Join-Path $Case.Data ".upgrade-receipts"
    if (-not (Test-Path -LiteralPath $root -PathType Container)) { return @() }
    $receipts = @()
    foreach ($path in Get-ChildItem -LiteralPath $root -Filter "*.json" -File) {
        try {
            $payload = Get-Content -LiteralPath $path.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
            $receipts += $payload
        } catch {
            if (-not (Test-Path -LiteralPath $path.FullName)) { continue }
            Fail "Malformed upgrade receipt: $($path.FullName)"
        }
    }
    return $receipts
}

function Assert-SucceededReceipt {
    param(
        [Parameter(Mandatory = $true)][object]$Case,
        [Parameter(Mandatory = $true)][object[]]$Receipts,
        [Parameter(Mandatory = $true)][string]$From,
        [Parameter(Mandatory = $true)][string]$Target
    )
    $receiptMatches = @(
        $Receipts | Where-Object {
            [string]$_.from_version -eq $From -and
            [string]$_.target_version -eq $Target -and
            [string]$_.status -eq "succeeded" -and
            $_.artifacts_verified -eq $true
        }
    )
    if ($receiptMatches.Count -eq 0) {
        # A healthy v8 gateway acknowledges terminal handoff files after
        # canonical audit persistence.  Accept that durable row if the queue
        # file was consumed after the production resolver verified it.
        Assert-CanonicalUpgradeOutcome -Case $Case -From $From -Target $Target `
            -Status "succeeded" -FailureCode ""
    }
}

function Assert-CanonicalUpgradeOutcome {
    param(
        [Parameter(Mandatory = $true)][object]$Case,
        [Parameter(Mandatory = $true)][string]$From,
        [Parameter(Mandatory = $true)][string]$Target,
        [Parameter(Mandatory = $true)][string]$Status,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$FailureCode
    )

    $database = Join-Path $Case.Data "audit.db"
    if (-not (Test-Path -LiteralPath $database -PathType Leaf)) {
        Fail "Canonical audit database is missing after the hard cut"
    }
    $probe = @'
import sqlite3
import sys
import time
from pathlib import Path

database, source, target, status, failure_code = sys.argv[1:]
if failure_code == "__DEFENSECLAW_EMPTY_FAILURE__":
    failure_code = ""
identity = f"status={status} from_version={source} target_version={target}"
failure = f"failure_code={failure_code}"
verified = "artifacts_verified=true"
deadline = time.monotonic() + 10
database_uri = Path(database).resolve().as_uri() + "?mode=ro"
while True:
    try:
        connection = sqlite3.connect(database_uri, uri=True, timeout=1)
        try:
            rows = connection.execute(
                "SELECT details FROM audit_events WHERE action = 'upgrade'"
            ).fetchall()
        finally:
            connection.close()
        if any(
            identity in str(row[0]) and failure in str(row[0]) and verified in str(row[0])
            for row in rows
        ):
            raise SystemExit(0)
    except sqlite3.Error:
        pass
    if time.monotonic() >= deadline:
        raise SystemExit(1)
    time.sleep(0.25)
'@
    $failureArgument = if ($FailureCode) { $FailureCode } else { "__DEFENSECLAW_EMPTY_FAILURE__" }
    $probe | & $Case.Python - $database $From $Target $Status $failureArgument
    if ($LASTEXITCODE -ne 0) {
        Fail "Canonical audit does not contain $Status event $From -> $Target with failure_code=$FailureCode"
    }
}

function Assert-CanonicalUpgradeEvent {
    param(
        [Parameter(Mandatory = $true)][object]$Case,
        [Parameter(Mandatory = $true)][string]$From,
        [Parameter(Mandatory = $true)][string]$Target
    )
    Assert-CanonicalUpgradeOutcome -Case $Case -From $From -Target $Target `
        -Status "succeeded" -FailureCode ""
}

function Assert-RetainedBridgeArtifacts {
    param([Parameter(Mandatory = $true)][object]$Case)

    $backupRoot = Join-Path $Case.Data "backups"
    $retained = @(
        Get-ChildItem -LiteralPath $backupRoot -Directory -Filter "staged-bridge-*" -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTimeUtc -Descending
    )
    if ($retained.Count -eq 0) { Fail "No retained bridge release was found" }
    $directory = $retained[0].FullName
    Assert-PrivateDirectoryAcl -Path $directory
    foreach ($name in @(
        "checksums.txt", "checksums.txt.sig", "checksums.txt.pem", "upgrade-manifest.json",
        "defenseclaw-$($script:BridgeVersion)-py3-none-any.whl",
        "defenseclaw_$($script:BridgeVersion)_windows_amd64.zip"
    )) {
        if (-not (Test-Path -LiteralPath (Join-Path $directory $name) -PathType Leaf)) {
            Fail "Retained bridge directory is incomplete: $name"
        }
    }
    [void](Assert-ReleaseSet -Directory $directory -Version $script:BridgeVersion)
    Write-Ok "Retained bridge artifacts are signed, complete, and protected by a private DACL"
}

function Assert-UpgradeSucceeded {
    param(
        [Parameter(Mandatory = $true)][object]$Case,
        [Parameter(Mandatory = $true)][object]$Manifest,
        [switch]$RequireV8,
        [switch]$RequireAutoBridge,
        [switch]$RequireRetainedBridge
    )

    Set-CaseEnvironment -Case $Case
    Assert-CommandVersion -Command $Case.Cli -Expected $TargetVersion -Label "upgraded CLI"
    Assert-CommandVersion -Command $Case.Gateway -Expected $TargetVersion -Label "upgraded gateway"
    & $Case.Gateway status *> $null
    if ($LASTEXITCODE -ne 0) { Fail "Target gateway status failed for $($Case.Name)" }
    $health = $null
    $deadline = [DateTime]::UtcNow.AddSeconds($HealthTimeout)
    while ([DateTime]::UtcNow -lt $deadline) {
        try {
            $health = Invoke-RestMethod -Uri "http://127.0.0.1:$($Case.GatewayPort)/health" -TimeoutSec 2
            break
        } catch {
            Start-Sleep -Milliseconds 250
        }
    }
    if ($null -eq $health) { Fail "Target gateway health endpoint is unreachable for $($Case.Name)" }

    $configPath = Join-Path $Case.Data "config.yaml"
    $config = Get-Content -LiteralPath $configPath -Raw -Encoding UTF8
    if ($RequireV8 -and $config -notmatch '(?m)^\s*config_version:\s*8\s*$') {
        Fail "Hard-cut upgrade did not publish config_version 8"
    }
    $cursorPath = Join-Path $Case.Data ".migration_state.json"
    if (-not (Test-Path -LiteralPath $cursorPath -PathType Leaf)) {
        Fail "Successful upgrade did not write a migration cursor"
    }
    $cursor = Get-Content -LiteralPath $cursorPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $required = Get-Property $Manifest "required_cli_migrations"
    if ($required) {
        foreach ($migration in @($required.Value)) {
            if (@($cursor.applied) -notcontains [string]$migration) {
                Fail "Migration cursor does not contain required migration $migration"
            }
        }
    }

    $receipts = @(Get-UpgradeReceipts -Case $Case)
    if ($RequireAutoBridge) {
        # Starting the hard-cut gateway admits and removes already-terminal
        # bridge queue files.  Their canonical v8 audit rows (rather than a
        # now-consumed handoff file) prove that both the legacy-controller
        # bridge install and the fresh-controller same-version repair ran.
        Assert-CanonicalUpgradeEvent -Case $Case -From $script:OldBaseline -Target $script:BridgeVersion
        Assert-CanonicalUpgradeEvent -Case $Case -From $script:BridgeVersion -Target $script:BridgeVersion
        Assert-SucceededReceipt -Case $Case -Receipts $receipts -From $script:BridgeVersion -Target $TargetVersion
    } elseif ($RequireV8) {
        Assert-SucceededReceipt -Case $Case -Receipts $receipts -From $script:BridgeVersion -Target $TargetVersion
    } else {
        Assert-SucceededReceipt -Case $Case -Receipts $receipts -From $script:OldBaseline -Target $TargetVersion
    }
    if ($RequireRetainedBridge) { Assert-RetainedBridgeArtifacts -Case $Case }
    Write-Ok "Healthy $TargetVersion CLI/gateway, required cursor, and succeeded receipts verified"
}

function Stop-CaseGateway {
    param([Parameter(Mandatory = $true)][object]$Case)
    try {
        Set-CaseEnvironment -Case $Case
        if (Test-Path -LiteralPath $Case.Gateway -PathType Leaf) {
            & $Case.Gateway stop *> $null
        }
    } catch {
        # Cleanup remains best-effort; the case root is isolated and is removed
        # after all child processes have been terminated.
    }
}

function Assert-CandidatePolicy {
    param([Parameter(Mandatory = $true)][object]$Manifest)

    $minProtocolProperty = Get-Property $Manifest "min_upgrade_protocol"
    $controllerProperty = Get-Property $Manifest "controller_upgrade_protocol"
    $minimumProperty = Get-Property $Manifest "minimum_source_version"
    $bridgeProperty = Get-Property $Manifest "required_bridge_version"
    $automaticProperty = Get-Property $Manifest "auto_bridge_from"
    $minProtocol = if ($minProtocolProperty) { [int]$minProtocolProperty.Value } else { 1 }
    $controllerProtocol = if ($controllerProperty) { [int]$controllerProperty.Value } else { $minProtocol }
    $hasBridge = $null -ne $minimumProperty -or $null -ne $bridgeProperty -or $null -ne $automaticProperty

    if ((Compare-Version $TargetVersion $script:HardCutVersion) -ge 0) {
        if (-not $minimumProperty -or -not $bridgeProperty -or -not $automaticProperty -or $minProtocol -lt 2) {
            Fail "Hard-cut candidate lacks its complete protocol-2 bridge contract"
        }
        if ([string]$minimumProperty.Value -ne $script:BridgeVersion -or
            [string]$bridgeProperty.Value -ne $script:BridgeVersion) {
            Fail "Hard-cut candidate must name published bridge $($script:BridgeVersion)"
        }
        $automatic = @($automaticProperty.Value)
        foreach ($value in $automatic) {
            if ($value -isnot [string] -or
                $value -notmatch '^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$') {
                Fail "Hard-cut auto_bridge_from contains a non-canonical version"
            }
        }
        if (@($automatic | Sort-Object -Unique).Count -ne $automatic.Count) {
            Fail "Hard-cut auto_bridge_from contains duplicate versions"
        }
        $missing = @(
            $script:PublishedPreBridgeBaselines |
                Where-Object { $automatic -notcontains ([string]$_) }
        )
        $unexpected = @(
            $automatic |
                Where-Object { $script:PublishedPreBridgeBaselines -notcontains ([string]$_) }
        )
        if ($missing.Count -gt 0 -or $unexpected.Count -gt 0) {
            Fail (
                "Hard-cut auto_bridge_from must exactly match the reviewed pre-bridge baseline policy " +
                "(missing=$($missing -join ','); unexpected=$($unexpected -join ','))"
            )
        }
        if ($automatic -notcontains $script:OldBaseline) {
            Fail "Hard-cut auto_bridge_from does not include tested baseline $($script:OldBaseline)"
        }
        $required = Get-Property $Manifest "required_cli_migrations"
        if (-not $required -or @($required.Value) -notcontains $script:HardCutVersion) {
            Fail "Hard-cut candidate does not require migration $($script:HardCutVersion)"
        }
        return $true
    }

    if ($hasBridge) { Fail "A pre-hard-cut candidate unexpectedly declares a partial bridge contract" }
    if ($TargetVersion -eq $script:BridgeVersion -and $controllerProtocol -lt 2) {
        Fail "Bridge candidate does not ship a protocol-2 controller"
    }
    return $false
}

function Cleanup {
    foreach ($case in $script:Cases) { Stop-CaseGateway -Case $case }
    foreach ($sentinel in $script:Sentinels) {
        try {
            if (-not $sentinel.HasExited) {
                Stop-Process -Id $sentinel.Id -Force -ErrorAction SilentlyContinue
                $sentinel.WaitForExit(5000) | Out-Null
            }
        } catch { }
    }
    if ($script:ServerProcess) {
        try {
            if (-not $script:ServerProcess.HasExited) {
                Stop-Process -Id $script:ServerProcess.Id -Force -ErrorAction SilentlyContinue
                $script:ServerProcess.WaitForExit(5000) | Out-Null
            }
        } catch { }
    }
    Restore-ProcessEnvironment
    if ($script:WorkRoot -and (Test-Path -LiteralPath $script:WorkRoot)) {
        if ($KeepWorkDir) {
            Write-Host "Kept Windows upgrade gate work directory: $($script:WorkRoot)" -ForegroundColor Yellow
        } else {
            Remove-Item -LiteralPath $script:WorkRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Main {
    Assert-RequiredCommands
    Save-ProcessEnvironment
    Read-UpgradeBaselinePolicy
    if ((Compare-Version $TargetVersion $script:OldBaseline) -le 0) {
        Fail "TargetVersion must be newer than published baseline $($script:OldBaseline)"
    }

    $script:WorkRoot = New-PrivateDirectory -Path (
        Join-Path ([IO.Path]::GetTempPath()) ("defenseclaw-windows-release-gate-" + [guid]::NewGuid().ToString("N"))
    )
    $script:ReleaseRoot = New-PrivateDirectory -Path (Join-Path $script:WorkRoot "releases")

    Write-Step "Authenticating sealed candidate $TargetVersion"
    $candidateManifest = Copy-CandidateRelease
    $hardCut = Assert-CandidatePolicy -Manifest $candidateManifest
    [void](Ensure-PublishedRelease -Version $script:OldBaseline)
    if ($hardCut) {
        [void](Ensure-PublishedRelease -Version $script:BridgeVersion)
    }
    Clear-UpgradeTestEnvironment
    Start-ReleaseServer

    if ($hardCut) {
        $refusal = New-UpgradeCase -Name "hard-cut-refusal" -BaselineVersion $script:OldBaseline
        Test-InstallerExistingInstallRefusal -Case $refusal
        Test-HardCutExplicitRefusal -Case $refusal

        $phaseOneRollback = New-UpgradeCase -Name "phase-one-rollback" -BaselineVersion $script:OldBaseline
        Test-PhaseOneRollback -Case $phaseOneRollback
        Stop-CaseGateway -Case $phaseOneRollback

        $phaseOneCrash = New-UpgradeCase -Name "phase-one-crash-recovery" -BaselineVersion $script:OldBaseline
        Test-PhaseOneCrashRecovery -Case $phaseOneCrash
        Stop-CaseGateway -Case $phaseOneCrash

        $phaseTwoWheelCrash = New-UpgradeCase -Name "phase-two-wheel-crash" -BaselineVersion $script:OldBaseline
        Test-PhaseTwoWheelInstallCrashRecovery -Case $phaseTwoWheelCrash -Manifest $candidateManifest
        Stop-CaseGateway -Case $phaseTwoWheelCrash

        $automatic = New-UpgradeCase -Name "automatic-bridge" -BaselineVersion $script:OldBaseline
        Write-Step "Running one-command latest path: $($script:OldBaseline) -> $($script:BridgeVersion) -> $TargetVersion"
        Invoke-ResolverUpgrade -Case $automatic -Latest
        Assert-UpgradeSucceeded -Case $automatic -Manifest $candidateManifest `
            -RequireV8 -RequireAutoBridge -RequireRetainedBridge
        Stop-CaseGateway -Case $automatic

        $direct = New-UpgradeCase -Name "direct-bridge" -BaselineVersion $script:BridgeVersion
        Write-Step "Running direct published bridge path: $($script:BridgeVersion) -> $TargetVersion"
        Invoke-ResolverUpgrade -Case $direct -Explicit
        Assert-UpgradeSucceeded -Case $direct -Manifest $candidateManifest `
            -RequireV8 -RequireRetainedBridge
        Stop-CaseGateway -Case $direct

        $rollback = New-UpgradeCase -Name "post-publish-rollback" -BaselineVersion $script:BridgeVersion
        Test-PostPublishRollback -Case $rollback
        Stop-CaseGateway -Case $rollback
        Write-Ok "Native hard-cut matrix passed: refusal, both phase rollbacks, automatic bridge, and direct bridge"
    } else {
        # This branch is the bridge release's own gate.  It cannot exercise a
        # not-yet-published hard cut, but it must prove the published 0.8.3
        # controller can install this candidate and that install.ps1 cannot be
        # abused as an unsigned existing-install updater.
        $bridgeCandidate = New-UpgradeCase -Name "bridge-candidate" -BaselineVersion $script:OldBaseline
        Test-InstallerExistingInstallRefusal -Case $bridgeCandidate
        Write-Step "Running published $($script:OldBaseline) -> candidate $TargetVersion upgrade"
        Invoke-ResolverUpgrade -Case $bridgeCandidate -Explicit
        Assert-UpgradeSucceeded -Case $bridgeCandidate -Manifest $candidateManifest
        Stop-CaseGateway -Case $bridgeCandidate
        Write-Ok "Native bridge-candidate matrix passed"
    }
}

$exitCode = 0
try {
    Main
} catch {
    $exitCode = 1
    Write-Host ""
    Write-Host "Windows upgrade release gate failed: $($_.Exception.Message)" -ForegroundColor Red
} finally {
    Cleanup
}
exit $exitCode
