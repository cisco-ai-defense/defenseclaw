# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
<#
.SYNOPSIS
    Intune Win32 app install command for the DefenseClaw standalone
    managed-enterprise deployment.

.DESCRIPTION
    Intune's management extension is a 32-bit process and runs install
    commands and scripts in Windows PowerShell 5.1. This launcher is
    therefore 5.1-compatible and does only what 5.1 can do safely: it
    re-checks the SHA-256 pins that New-DefenseClawIntunePackage.ps1 wrote
    into intune-package.json for the Setup executable and config.yaml that
    ship in the same .intunewin, then launches the native x64
    DefenseClawSetup-Enterprise-Standalone-x64.exe /ensure with absolute paths (Setup
    refuses relative or environment-expanded paths). Setup then launches the
    trusted PowerShell 7 engine itself.

    Exit codes are Setup's: 0 success or no-op, 1603 failure (rolled back),
    1618 another lifecycle run is active (Intune retries), 1639 invalid
    arguments. The lifecycle result is written to
    %WINDIR%\Logs\DefenseClaw\enterprise-lifecycle.log by the lifecycle and
    echoed on STDOUT here.

    Install command (Intune > App > Program):
      %SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\Install-DefenseClawIntune.ps1
#>
[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# region DefenseClaw MDM shared helpers
# Identical in every packaging/mdm Windows script (a test enforces it) so each
# script can be uploaded to an MDM on its own. Compatible with Windows
# PowerShell 5.1 (32- or 64-bit, as Intune runs detection and remediation
# scripts) and PowerShell 7. Never trusts environment variables for paths.

# Load only the engine's in-box modules. A parent process (for example a
# PowerShell 7 session launching Windows PowerShell 5.1) can pass a module
# path whose modules do not load in this engine.
$env:PSModulePath = Join-Path $PSHOME 'Modules'

$script:DefenseClawAdminSids = @(
    'S-1-5-18',     # LocalSystem
    'S-1-5-32-544', # BUILTIN\Administrators
    'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464' # TrustedInstaller
)
$script:DefenseClawMarkerKey = 'SOFTWARE\Cisco\DefenseClaw\Enterprise'

function Get-DefenseClawRegistryKey64 {
    # Opens an HKLM key in the 64-bit view even from a 32-bit PowerShell,
    # which WOW64 would otherwise redirect to SOFTWARE\WOW6432Node.
    param([Parameter(Mandatory = $true)][string]$SubKey)
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
        [Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
    try { return $base.OpenSubKey($SubKey, $false) } finally { $base.Dispose() }
}

function Get-DefenseClawProgramFiles64 {
    # The native Program Files directory from protected HKLM, never from
    # $env:ProgramFiles (which is "Program Files (x86)" in a 32-bit process).
    $key = Get-DefenseClawRegistryKey64 -SubKey 'SOFTWARE\Microsoft\Windows\CurrentVersion'
    if ($null -eq $key) { throw 'program_files_unresolved: HKLM CurrentVersion is unreadable' }
    try {
        $value = [string]$key.GetValue('ProgramFilesDir', $null,
            [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    } finally { $key.Dispose() }
    if (-not $value -or $value.Contains('%') -or $value -notmatch '^[A-Za-z]:\\[^/]*$') {
        throw "program_files_unresolved: unexpected ProgramFilesDir '$value'"
    }
    return $value.TrimEnd('\')
}

function Test-DefenseClawAdminOnlyItem {
    # True when the item is not a reparse point, is owned by SYSTEM,
    # Administrators or TrustedInstaller, and grants no other principal any
    # right that could change, replace or delete it.
    param([Parameter(Mandatory = $true)][string]$Path)
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { return $false }
    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    $owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
    if ($script:DefenseClawAdminSids -notcontains $owner) { return $false }
    # WriteData/CreateFiles, AppendData/CreateDirectories, WriteExtendedAttributes,
    # DeleteSubdirectoriesAndFiles, WriteAttributes, Delete, WriteDAC, WriteOwner,
    # GENERIC_ALL, GENERIC_WRITE.
    $dangerous = [int64](0x2 -bor 0x4 -bor 0x10 -bor 0x40 -bor 0x100 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor 0x10000000 -bor 0x40000000)
    foreach ($rule in $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }
        if (($rule.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) { continue }
        if ($script:DefenseClawAdminSids -contains $rule.IdentityReference.Value) { continue }
        if (([int64]$rule.FileSystemRights -band $dangerous) -ne 0) { return $false }
    }
    return $true
}

function Test-DefenseClawAdminOnlyPath {
    # Checks the item and every ancestor up to and including $StopAt.
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$StopAt
    )
    $current = [System.IO.Path]::GetFullPath($Path).TrimEnd('\')
    $stop = [System.IO.Path]::GetFullPath($StopAt).TrimEnd('\')
    if (-not $current.StartsWith($stop + '\', [System.StringComparison]::OrdinalIgnoreCase) -and
        -not [string]::Equals($current, $stop, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $false
    }
    while ($true) {
        if (-not (Test-DefenseClawAdminOnlyItem -Path $current)) { return $false }
        if ([string]::Equals($current, $stop, [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
        $current = [System.IO.Path]::GetDirectoryName($current)
        if (-not $current) { return $false }
    }
}

function Get-DefenseClawInstalledDeployment {
    # The installed standalone deployment from the HKLM marker, with its CLI
    # path checked against the protected Program Files root and ACLs.
    # Returns $null when nothing is installed; throws when an installation
    # is present but cannot be trusted.
    $key = Get-DefenseClawRegistryKey64 -SubKey $script:DefenseClawMarkerKey
    if ($null -eq $key) { return $null }
    try {
        $markerProfile = [string]$key.GetValue('Profile')
        $markerRoot = [string]$key.GetValue('InstallRoot')
        $markerVersion = [string]$key.GetValue('ProductVersion')
        $markerTrust = [string]$key.GetValue('TrustMode')
    } finally { $key.Dispose() }
    if ($markerProfile -ne 'standalone') {
        throw "profile_conflict: the enterprise marker names profile '$markerProfile', not standalone"
    }
    $programFiles = Get-DefenseClawProgramFiles64
    $expectedRoot = $programFiles + '\Cisco\DefenseClaw'
    if (-not [string]::Equals($markerRoot.TrimEnd('\'), $expectedRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "untrusted_install_root: the marker names '$markerRoot', expected '$expectedRoot'"
    }
    $cli = $expectedRoot + '\bin\defenseclaw.exe'
    if (-not (Test-Path -LiteralPath $cli -PathType Leaf)) {
        throw "installation_incomplete: $cli is missing although the enterprise marker exists"
    }
    if (-not (Test-DefenseClawAdminOnlyPath -Path $cli -StopAt $programFiles)) {
        throw "untrusted_install: $cli or one of its folders is writable by a non-administrator or is a reparse point"
    }
    if ($markerTrust -eq 'authenticode') {
        $signature = Get-AuthenticodeSignature -LiteralPath $cli
        if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
            throw "untrusted_install: $cli Authenticode status is $($signature.Status)"
        }
    }
    return New-Object -TypeName PSObject -Property @{
        Cli = $cli; InstallRoot = $expectedRoot; Version = $markerVersion; TrustMode = $markerTrust
    }
}

function ConvertTo-DefenseClawArgument {
    # Quotes one argument for CommandLineToArgvW (Windows PowerShell 5.1 has
    # no ProcessStartInfo.ArgumentList).
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value)
    if ($Value.Length -gt 0 -and $Value -notmatch '[\s"]') { return $Value }
    $builder = New-Object System.Text.StringBuilder
    [void]$builder.Append('"')
    $backslashes = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq '\') { $backslashes++; continue }
        if ($character -eq '"') {
            [void]$builder.Append([char]92, 2 * $backslashes + 1)
        } elseif ($backslashes -gt 0) {
            [void]$builder.Append([char]92, $backslashes)
        }
        $backslashes = 0
        [void]$builder.Append($character)
    }
    if ($backslashes -gt 0) { [void]$builder.Append([char]92, 2 * $backslashes) }
    [void]$builder.Append('"')
    return $builder.ToString()
}

function Invoke-DefenseClawNative {
    # Runs a native executable with a scrubbed .NET/PowerShell loader
    # environment, optional stdin, and captured output.
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [string[]]$ArgumentList = @(),
        [string]$StandardInputPath = '',
        [int]$TimeoutSeconds = 7200
    )
    $info = New-Object System.Diagnostics.ProcessStartInfo
    $info.FileName = $FilePath
    $info.Arguments = (($ArgumentList | ForEach-Object { ConvertTo-DefenseClawArgument -Value $_ }) -join ' ')
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.RedirectStandardInput = $true
    $info.WorkingDirectory = [System.IO.Path]::GetDirectoryName($FilePath)
    foreach ($name in @($info.EnvironmentVariables.Keys)) {
        if ($name -match '^(DOTNET_|COMPLUS_|CORECLR_|COR_ENABLE_PROFILING$|COR_PROFILER|PSMODULEPATH$|PSEXECUTIONPOLICYPREFERENCE$|__PSLOCKDOWNPOLICY$)') {
            $info.EnvironmentVariables.Remove($name)
        }
    }
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $info
    [void]$process.Start()
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    if ($StandardInputPath) {
        $bytes = [System.IO.File]::ReadAllBytes($StandardInputPath)
        $process.StandardInput.BaseStream.Write($bytes, 0, $bytes.Length)
        [System.Array]::Clear($bytes, 0, $bytes.Length)
    }
    $process.StandardInput.Close()
    if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
        try { $process.Kill() } catch { $null = $_ }
        throw "native_timeout: $FilePath did not finish within $TimeoutSeconds seconds"
    }
    $process.WaitForExit()
    return New-Object -TypeName PSObject -Property @{
        ExitCode = $process.ExitCode; StdOut = $stdout.Result; StdErr = $stderr.Result
    }
}

function ConvertTo-DefenseClawResultJson {
    # A lifecycle-result document (schema v2) for an outcome the script
    # decided itself. installed=false means "not evaluated" on failures.
    param(
        [Parameter(Mandatory = $true)][string]$Action,
        [Parameter(Mandatory = $true)][int]$ExitCode,
        [string]$Code = '',
        [string]$Message = '',
        [switch]$Noop,
        [string]$NoopReason = ''
    )
    $errors = @()
    if ($Code) { $errors = @(@{ code = $Code; message = $Message }) }
    $document = [ordered]@{
        schema_version = 2; ok = ($errors.Count -eq 0); action = $Action; noop = [bool]$Noop
    }
    if ($NoopReason) { $document.noop_reason = $NoopReason }
    $document.profile = 'standalone'; $document.platform = 'windows'; $document.product_version = ''
    $document.installed = $false; $document.transaction_pending = $false; $document.services = @()
    $document.readiness = [ordered]@{ gateway = $false; guardian = $false; enumerator = $false; sensor_helper = $false }
    $document.inspection = [ordered]@{ local = 'unknown'; ai_defense = 'unknown' }
    $document.machine_policy = @{}
    $document.enrollment = [ordered]@{ targets = 0; pending = 0; failed = 0; exempt = 0 }
    $document.coverage_complete = $false; $document.security_complete = $false
    $document.errors = $errors; $document.exit_code = $ExitCode
    $json = ConvertTo-Json -InputObject $document -Depth 6 -Compress
    # Windows PowerShell 5.1 renders a one-element array as an object.
    if ($errors.Count -eq 1 -and $json -match '"errors":\{') {
        $json = $json -replace '"errors":\{', '"errors":[{' -replace '\},"exit_code"', '}],"exit_code"'
    }
    return $json
}
# endregion DefenseClaw MDM shared helpers

function Exit-Launcher {
    param([int]$ExitCode, [string]$Code, [string]$Message)
    [Console]::Out.WriteLine((ConvertTo-DefenseClawResultJson -Action 'ensure' -ExitCode $ExitCode -Code $Code -Message $Message))
    exit $ExitCode
}

$root = $PSScriptRoot
if (-not $root) { Exit-Launcher 1639 'mdm_invalid_arguments' 'run this launcher with -File from the Win32 app content folder' }
$setup = Join-Path $root 'DefenseClawSetup-Enterprise-Standalone-x64.exe'
$config = Join-Path $root 'config.yaml'
$pinsPath = Join-Path $root 'intune-package.json'
foreach ($required in @($setup, $pinsPath)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        Exit-Launcher 1603 'mdm_package_incomplete' "the Win32 app content is missing $([System.IO.Path]::GetFileName($required)); rebuild it with New-DefenseClawIntunePackage.ps1"
    }
}
try {
    $pins = Get-Content -LiteralPath $pinsPath -Raw | ConvertFrom-Json
} catch {
    Exit-Launcher 1603 'mdm_package_incomplete' "intune-package.json is not valid JSON: $($_.Exception.Message)"
}
$actualSetup = (Get-FileHash -LiteralPath $setup -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualSetup -ne ([string]$pins.setup_sha256).ToLowerInvariant()) {
    Exit-Launcher 1603 'mdm_hash_mismatch' "Setup SHA-256 $actualSetup does not match the package pin"
}
$arguments = @('/ensure', 'JSON=1')
if ($pins.config_sha256) {
    if (-not (Test-Path -LiteralPath $config -PathType Leaf)) { Exit-Launcher 1603 'mdm_package_incomplete' 'the package pins a config.yaml that is missing' }
    $actualConfig = (Get-FileHash -LiteralPath $config -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualConfig -ne ([string]$pins.config_sha256).ToLowerInvariant()) {
        Exit-Launcher 1603 'mdm_hash_mismatch' "config.yaml SHA-256 $actualConfig does not match the package pin"
    }
    $arguments += ('CONFIG=' + [System.IO.Path]::GetFullPath($config))
}
if ($pins.trust_mode -eq 'authenticode') {
    $signature = Get-AuthenticodeSignature -LiteralPath $setup
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
        Exit-Launcher 1603 'mdm_signature_invalid' "Setup Authenticode status is $($signature.Status)"
    }
    $signers = @($pins.allowed_signers | ForEach-Object { ([string]$_).ToLowerInvariant() })
    $sha = New-Object System.Security.Cryptography.SHA256Managed
    try { $thumbprint = (($sha.ComputeHash($signature.SignerCertificate.RawData) | ForEach-Object { $_.ToString('x2') }) -join '') } finally { $sha.Dispose() }
    if ($signers -notcontains $thumbprint) { Exit-Launcher 1603 'mdm_signer_not_allowed' "Setup is signed by certificate $thumbprint, which the package does not allow" }
    $arguments += ('ALLOWEDSIGNERS=' + ($signers -join ','))
}
try {
    $run = Invoke-DefenseClawNative -FilePath $setup -ArgumentList $arguments
} catch {
    Exit-Launcher 1603 'mdm_lifecycle_launch_failed' $_.Exception.Message
}
$code = $run.ExitCode
if (@(0, 1603, 1618, 1639, 3010) -notcontains $code) { $code = 1603 }
$text = ([string]$run.StdOut).Trim()
$document = $null
if ($text) { try { $document = $text | ConvertFrom-Json } catch { $document = $null } }
if ($null -ne $document -and ($document.PSObject.Properties.Name -contains 'schema_version') -and $document.schema_version -eq 2) {
    [Console]::Out.WriteLine($text)
    exit $code
}
if ($code -eq 0) { $code = 1603 }
$detail = (($text + ' ' + [string]$run.StdErr).Trim())
if ($detail.Length -gt 2048) { $detail = $detail.Substring(0, 2048) }
Exit-Launcher $code 'mdm_lifecycle_no_result' "Setup printed no lifecycle result: $detail"
