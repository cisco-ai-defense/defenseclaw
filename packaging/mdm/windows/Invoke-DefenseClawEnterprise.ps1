# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
#Requires -Version 7.4
<#
.SYNOPSIS
    Generic MDM wrapper for the DefenseClaw standalone managed-enterprise
    deployment on Windows (PowerShell 7 only).

.DESCRIPTION
    One entry point for any MDM or configuration-management tool that runs
    PowerShell 7 as SYSTEM or an elevated administrator. It:

      1. refuses a 32-bit or emulated process, Constrained Language Mode, an
         untrusted PowerShell engine (not the Microsoft-signed pwsh.exe
         registered under HKLM in the protected Program Files root) and .NET
         loader-injection variables in its own environment;
      2. copies DefenseClawSetup-Enterprise-Standalone-x64.exe into a new SYSTEM- and
         Administrators-only staging folder and verifies the copy there:
         its SHA-256 against -Sha256 (hash-pinned trust, required) and/or its
         Authenticode signature against -AllowedSigners (SHA-256 thumbprints
         of the signer certificate; Cisco or your own re-signing certificate);
      3. takes the administrator config and the optional credential from an
         administrator-only file or standard input, never from the command
         line, and stages them in the same folder;
      4. runs Setup /ensure (install, upgrade, repair or a true no-op) or,
         without -SetupPath, the installed CLI, and prints the lifecycle
         result (packaging/mdm/contract/lifecycle-result.schema.json);
      5. appends the result to %WINDIR%\Logs\DefenseClaw\mdm-wrapper.log and
         exits with the MSI-compatible code: 0 success or no-op, 1603
         failure (already rolled back), 1618 busy (retry), 1639 invalid
         arguments, 3010 reserved.

    Intune note: Intune runs scripts in 32-bit Windows PowerShell 5.1. Use
    the native Setup command line or packaging/mdm/intune/windows instead of
    this script there.

.EXAMPLE
    pwsh -NoProfile -File Invoke-DefenseClawEnterprise.ps1 -SetupPath D:\stage\DefenseClawSetup-Enterprise-Standalone-x64.exe `
        -Sha256 3f0c...e1 -ConfigPath D:\stage\config.yaml

.EXAMPLE
    Get-Content key.txt | pwsh -NoProfile -File Invoke-DefenseClawEnterprise.ps1 -SetupPath ... -Sha256 ... `
        -ConfigPath ... -SecretName ai-defense-api-key -SecretFromStdin
#>
[CmdletBinding()]
param(
    [string]$Action = 'Ensure',
    [string]$SetupPath = '',
    [string]$Sha256 = '',
    [string]$TrustMode = 'HashPinned',
    [string[]]$AllowedSigners = @(),
    [string]$ConfigPath = '',
    [switch]$ConfigFromStdin,
    [string]$SecretName = '',
    [string]$SecretPath = '',
    [switch]$SecretFromStdin,
    [string]$ProductVersion = ''
)

Set-StrictMode -Version 3.0
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

$script:ExitFailure = 1603
$script:ExitBusy = 1618
$script:ExitInvalid = 1639
$script:MaxConfigBytes = 1MB
$script:MaxSecretBytes = 16KB
$script:Staging = $null
$script:LogPath = $null
$script:ResultAction = 'ensure'

function Write-WrapperLog {
    param([string]$Message)
    if (-not $script:LogPath) { return }
    try {
        $line = '{0} Invoke-DefenseClawEnterprise[{1}] {2}' -f [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'), $PID, $Message
        [System.IO.File]::AppendAllText($script:LogPath, $line + [Environment]::NewLine, [System.Text.UTF8Encoding]::new($false))
    } catch { $null = $_ }
}

function Exit-Wrapper {
    param([int]$ExitCode, [string]$Code, [string]$Message)
    $json = ConvertTo-DefenseClawResultJson -Action $script:ResultAction -ExitCode $ExitCode -Code $Code -Message $Message
    [Console]::Out.WriteLine($json)
    Write-WrapperLog -Message "result $json"
    Remove-WrapperStaging
    exit $ExitCode
}

function Remove-WrapperStaging {
    if ($script:Staging -and (Test-Path -LiteralPath $script:Staging)) {
        Get-ChildItem -LiteralPath $script:Staging -Force -File | ForEach-Object {
            # Overwrite credentials before deleting them.
            if ($_.Name -eq 'secret') { [System.IO.File]::WriteAllBytes($_.FullName, [byte[]]::new($_.Length)) }
        }
        Remove-Item -LiteralPath $script:Staging -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Initialize-WrapperLog {
    $windows = [Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)
    $directory = Join-Path $windows 'Logs\DefenseClaw'
    try {
        if (-not (Test-Path -LiteralPath $directory)) {
            # Same descriptor the lifecycle uses: SYSTEM and Administrators
            # write, users read.
            $security = [System.Security.AccessControl.DirectorySecurity]::new()
            $security.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)')
            [System.IO.FileSystemAclExtensions]::Create([System.IO.DirectoryInfo]::new($directory), $security)
        }
        if (Test-DefenseClawAdminOnlyItem -Path $directory) {
            $script:LogPath = Join-Path $directory 'mdm-wrapper.log'
        }
    } catch { $script:LogPath = $null }
}

function Assert-WrapperHost {
    if (-not [Environment]::Is64BitProcess -or
        [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne [System.Runtime.InteropServices.Architecture]::X64 -or
        [System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -ne [System.Runtime.InteropServices.Architecture]::X64) {
        Exit-Wrapper $script:ExitFailure 'unsupported_architecture' 'run the x64 PowerShell 7 on native Windows x64 (ARM64 and 32-bit are not supported)'
    }
    if ($ExecutionContext.SessionState.LanguageMode -ne [System.Management.Automation.PSLanguageMode]::FullLanguage) {
        Exit-Wrapper $script:ExitFailure 'powershell_constrained_language' "PowerShell runs in $($ExecutionContext.SessionState.LanguageMode); allow this script's signer in your application-control policy"
    }
    $variables = [Environment]::GetEnvironmentVariables()
    foreach ($name in @($variables.Keys)) {
        $upper = ([string]$name).ToUpperInvariant()
        if ($upper -in @('DOTNET_STARTUP_HOOKS', 'DOTNET_ADDITIONAL_DEPS', 'DOTNET_SHARED_STORE') -or
            $upper.StartsWith('CORECLR_PROFILER') -or $upper.StartsWith('COR_PROFILER') -or
            (($upper -in @('CORECLR_ENABLE_PROFILING', 'COR_ENABLE_PROFILING')) -and [string]$variables[$name] -ne '0')) {
            Exit-Wrapper $script:ExitFailure 'loader_environment_present' "the process environment sets $name, which loads code into PowerShell; remove it from the MDM agent's environment"
        }
    }
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $identity.IsSystem -and -not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Exit-Wrapper $script:ExitFailure 'mdm_not_elevated' 'run as SYSTEM or from an elevated administrator session'
    }
    Assert-WrapperEngine
}

function Assert-WrapperEngine {
    # The same engine trust the lifecycle applies before it launches pwsh.
    try {
        $programFiles = Get-DefenseClawProgramFiles64
        $engineHome = $PSHOME.TrimEnd('\')
        $pwsh = Join-Path $engineHome 'pwsh.exe'
        if (-not [string]::Equals([Environment]::ProcessPath, $pwsh, [StringComparison]::OrdinalIgnoreCase)) {
            throw "this script runs in '$([Environment]::ProcessPath)', not $pwsh"
        }
        if (-not $engineHome.StartsWith($programFiles + '\PowerShell\', [StringComparison]::OrdinalIgnoreCase)) {
            throw "PowerShell 7 at '$engineHome' is outside $programFiles\PowerShell"
        }
        $registered = $false
        $versions = Get-DefenseClawRegistryKey64 -SubKey 'SOFTWARE\Microsoft\PowerShellCore\InstalledVersions'
        if ($null -ne $versions) {
            try {
                foreach ($name in $versions.GetSubKeyNames()) {
                    $entry = $versions.OpenSubKey($name, $false)
                    try {
                        $location = [string]$entry.GetValue('InstallLocation')
                        if ($location -and [string]::Equals($location.TrimEnd('\'), $engineHome, [StringComparison]::OrdinalIgnoreCase)) { $registered = $true }
                    } finally { $entry.Dispose() }
                }
            } finally { $versions.Dispose() }
        }
        if (-not $registered) { throw "PowerShell 7 at '$engineHome' is not registered by the PowerShell MSI under HKLM" }
        if (-not (Test-DefenseClawAdminOnlyPath -Path $pwsh -StopAt $programFiles)) {
            throw "$pwsh or one of its folders is writable by a non-administrator"
        }
        $signature = Get-AuthenticodeSignature -LiteralPath $pwsh
        $signer = if ($signature.SignerCertificate) { $signature.SignerCertificate.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false) } else { '' }
        if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid -or $signer -cne 'Microsoft Corporation') {
            throw "$pwsh is not validly signed by Microsoft Corporation (status $($signature.Status), signer '$signer')"
        }
    } catch {
        Exit-Wrapper $script:ExitFailure 'powershell7_untrusted' $_.Exception.Message
    }
}

function New-WrapperStaging {
    $windows = [Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)
    $path = Join-Path $windows ('Temp\defenseclaw-mdm-' + [Guid]::NewGuid().ToString('N'))
    if (Test-Path -LiteralPath $path) { Exit-Wrapper $script:ExitFailure 'mdm_staging_untrusted' "staging folder $path already exists" }
    $security = [System.Security.AccessControl.DirectorySecurity]::new()
    $security.SetSecurityDescriptorSddlForm('O:BAG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
    [System.IO.FileSystemAclExtensions]::Create([System.IO.DirectoryInfo]::new($path), $security)
    $script:Staging = $path
    if (-not (Test-DefenseClawAdminOnlyItem -Path $path)) {
        Exit-Wrapper $script:ExitFailure 'mdm_staging_untrusted' "staging folder $path is not administrator-only"
    }
    return $path
}

function Test-WrapperAdminOnlyAncestors {
    # True when no folder above $Path can be renamed, deleted or
    # re-permissioned by a non-administrator, none lets one delete its
    # children, and none below the volume root is a reparse point. Then no
    # other account can swap the file between the ACL check and the copy
    # (the Unix wrapper's dc_trusted_path checks the same chain). Creating
    # new entries, which a volume root allows by default, cannot move an
    # existing folder and is accepted.
    param([Parameter(Mandatory = $true)][string]$Path)
    # DELETE, WRITE_DAC, WRITE_OWNER, GENERIC_ALL and DeleteSubdirectoriesAndFiles.
    $dangerous = [int64](0x10000 -bor 0x40000 -bor 0x80000 -bor 0x10000000 -bor 0x40)
    $current = [System.IO.Path]::GetDirectoryName([System.IO.Path]::GetFullPath($Path))
    while ($current) {
        $parent = [System.IO.Path]::GetDirectoryName($current)
        $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
        if ($parent -and ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { return $false }
        $acl = Get-Acl -LiteralPath $current -ErrorAction Stop
        $owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
        if ($script:DefenseClawAdminSids -notcontains $owner) { return $false }
        foreach ($rule in $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
            if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }
            if (($rule.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) { continue }
            if ($script:DefenseClawAdminSids -contains $rule.IdentityReference.Value) { continue }
            if (([int64]$rule.FileSystemRights -band $dangerous) -ne 0) { return $false }
        }
        $current = $parent
    }
    return $true
}

function Copy-WrapperInput {
    # Copies a bounded input into staging. Config and credentials must come
    # from an administrator-only location because nothing verifies them
    # after the copy; Setup is verified after the copy and may come from
    # anywhere the MDM staged it.
    param([string]$Source, [string]$Destination, [long]$Limit, [string]$Label, [switch]$RequireAdminOnly)
    if (-not [System.IO.Path]::IsPathFullyQualified($Source) -or $Source.StartsWith('\\')) {
        Exit-Wrapper $script:ExitInvalid 'mdm_invalid_arguments' "$Label must be an absolute local path"
    }
    $item = Get-Item -LiteralPath $Source -Force -ErrorAction SilentlyContinue
    if ($null -eq $item -or $item.PSIsContainer -or ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
        Exit-Wrapper $script:ExitInvalid 'mdm_invalid_arguments' "$Label is not a regular file: $Source"
    }
    if ($RequireAdminOnly -and -not (Test-DefenseClawAdminOnlyItem -Path $Source)) {
        Exit-Wrapper $script:ExitFailure 'mdm_untrusted_input' "$Label is writable by a non-administrator: $Source"
    }
    if ($RequireAdminOnly -and -not (Test-WrapperAdminOnlyAncestors -Path $Source)) {
        Exit-Wrapper $script:ExitFailure 'mdm_untrusted_input' "a folder above $Label can be renamed, deleted or re-permissioned by a non-administrator, or is a link: $Source; stage it in an administrator-only folder"
    }
    if ($item.Length -gt $Limit) { Exit-Wrapper $script:ExitInvalid 'mdm_input_too_large' "$Label exceeds $Limit bytes" }
    [System.IO.File]::Copy($Source, $Destination, $false)
    if ((Get-Item -LiteralPath $Destination).Length -gt $Limit) { Exit-Wrapper $script:ExitInvalid 'mdm_input_too_large' "$Label exceeds $Limit bytes" }
}

function Read-WrapperStdin {
    param([string]$Destination, [long]$Limit, [string]$Label)
    $stream = [Console]::OpenStandardInput()
    $buffer = [byte[]]::new($Limit + 1)
    $total = 0
    while ($total -le $Limit) {
        $read = $stream.Read($buffer, $total, $buffer.Length - $total)
        if ($read -le 0) { break }
        $total += $read
    }
    if ($total -gt $Limit) { Exit-Wrapper $script:ExitInvalid 'mdm_input_too_large' "$Label on standard input exceeds $Limit bytes" }
    $stream2 = [System.IO.File]::Open($Destination, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write)
    try { $stream2.Write($buffer, 0, $total) } finally { $stream2.Dispose(); [Array]::Clear($buffer, 0, $buffer.Length) }
    if ($total -eq 0) { Exit-Wrapper $script:ExitInvalid 'mdm_invalid_arguments' "$Label on standard input is empty" }
}

function Get-CertificateSha256 {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)
    return ([System.Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($Certificate.RawData))).ToLowerInvariant()
}

function Assert-WrapperSetup {
    param([string]$Staged)
    if ($script:PinnedSha256) {
        $actual = (Get-FileHash -LiteralPath $Staged -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actual -ne $script:PinnedSha256) {
            Exit-Wrapper $script:ExitFailure 'mdm_hash_mismatch' "Setup SHA-256 $actual does not match the pinned $($script:PinnedSha256)"
        }
    }
    if ($script:Mode -eq 'authenticode') {
        $signature = Get-AuthenticodeSignature -LiteralPath $Staged
        if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid -or $null -eq $signature.SignerCertificate) {
            Exit-Wrapper $script:ExitFailure 'mdm_signature_invalid' "Setup Authenticode status is $($signature.Status)"
        }
        $thumbprint = Get-CertificateSha256 -Certificate $signature.SignerCertificate
        if ($script:Signers -notcontains $thumbprint) {
            Exit-Wrapper $script:ExitFailure 'mdm_signer_not_allowed' "Setup is signed by certificate $thumbprint, which is not in -AllowedSigners"
        }
    }
}

function Write-LifecycleResult {
    # Passes a schema v2 result through; wraps anything else (Setup's own
    # argument errors, crashes) in one.
    param($Run, [string]$Label)
    $code = [int]$Run.ExitCode
    if (@(0, 1603, 1618, 1639, 3010) -notcontains $code) { $code = $script:ExitFailure }
    $text = ([string]$Run.StdOut).Trim()
    $document = $null
    if ($text) { try { $document = $text | ConvertFrom-Json -ErrorAction Stop } catch { $document = $null } }
    if ($null -ne $document -and $document.PSObject.Properties['schema_version'] -and $document.schema_version -eq 2) {
        [Console]::Out.WriteLine($text)
        Write-WrapperLog -Message ("result " + ($text -replace '\s+', ' '))
        return $code
    }
    if ($code -eq 0) { $code = $script:ExitFailure }
    $detail = if ($null -ne $document -and $document.PSObject.Properties['error']) { [string]$document.error } else { (($text + ' ' + [string]$Run.StdErr).Trim()) }
    if ($detail.Length -gt 2048) { $detail = $detail.Substring(0, 2048) }
    $json = ConvertTo-DefenseClawResultJson -Action $script:ResultAction -ExitCode $code -Code 'mdm_lifecycle_no_result' -Message "$Label printed no lifecycle result: $detail"
    [Console]::Out.WriteLine($json)
    Write-WrapperLog -Message "result $json"
    return $code
}

# --- main ------------------------------------------------------------------
Initialize-WrapperLog
$normalizedAction = $Action.Trim().ToLowerInvariant()
if (@('ensure', 'status', 'verify') -notcontains $normalizedAction) {
    Exit-Wrapper $script:ExitInvalid 'mdm_invalid_arguments' '-Action must be Ensure, Status or Verify (use uninstall.ps1 to remove)'
}
$script:ResultAction = $normalizedAction
Assert-WrapperHost

$script:Mode = switch ($TrustMode.Trim().ToLowerInvariant()) {
    'hashpinned' { 'hash_pinned' } 'hash_pinned' { 'hash_pinned' }
    'authenticode' { 'authenticode' }
    default { Exit-Wrapper $script:ExitInvalid 'mdm_invalid_arguments' '-TrustMode must be HashPinned or Authenticode' }
}
$script:PinnedSha256 = $Sha256.Trim().ToLowerInvariant()
if ($script:PinnedSha256 -and $script:PinnedSha256 -notmatch '^[0-9a-f]{64}$') {
    Exit-Wrapper $script:ExitInvalid 'mdm_invalid_arguments' '-Sha256 must be 64 hexadecimal characters'
}
$script:Signers = @($AllowedSigners | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object { $_ })
foreach ($signer in $script:Signers) {
    if ($signer -notmatch '^[0-9a-f]{64}$') { Exit-Wrapper $script:ExitInvalid 'mdm_invalid_arguments' "-AllowedSigners entry '$signer' is not a SHA-256 certificate thumbprint" }
}
if ($SetupPath) {
    if ($script:Mode -eq 'hash_pinned' -and -not $script:PinnedSha256) {
        Exit-Wrapper $script:ExitInvalid 'mdm_invalid_arguments' 'hash-pinned trust requires -Sha256 for -SetupPath'
    }
    if ($script:Mode -eq 'authenticode' -and $script:Signers.Count -eq 0) {
        Exit-Wrapper $script:ExitInvalid 'mdm_invalid_arguments' 'Authenticode trust requires -AllowedSigners'
    }
}
if ($ConfigFromStdin -and $SecretFromStdin) { Exit-Wrapper $script:ExitInvalid 'mdm_invalid_arguments' 'only one of -ConfigFromStdin and -SecretFromStdin can read standard input' }
if ($ConfigFromStdin -and $ConfigPath) { Exit-Wrapper $script:ExitInvalid 'mdm_invalid_arguments' '-ConfigPath and -ConfigFromStdin are exclusive' }
if ($SecretName) {
    if ($SecretName -cnotmatch '^[a-z0-9][a-z0-9-]{0,62}$') { Exit-Wrapper $script:ExitInvalid 'mdm_invalid_arguments' '-SecretName must be lowercase letters, digits and dashes' }
    if ([bool]$SecretPath -eq [bool]$SecretFromStdin) { Exit-Wrapper $script:ExitInvalid 'mdm_invalid_arguments' '-SecretName needs exactly one of -SecretPath and -SecretFromStdin' }
} elseif ($SecretPath -or $SecretFromStdin) {
    Exit-Wrapper $script:ExitInvalid 'mdm_invalid_arguments' 'a secret value needs -SecretName'
}
if ($normalizedAction -ne 'ensure' -and ($ConfigPath -or $ConfigFromStdin -or $SecretName)) {
    Exit-Wrapper $script:ExitInvalid 'mdm_invalid_arguments' "-Action $Action is read-only and takes no config or secret"
}
if ($ProductVersion -and $ProductVersion -notmatch '^v?[0-9]+\.[0-9]+\.[0-9]+([.+-][0-9A-Za-z.+-]+)?$') {
    Exit-Wrapper $script:ExitInvalid 'mdm_invalid_arguments' '-ProductVersion must be a release version such as 1.2.3'
}
if ($ProductVersion -and $SetupPath) {
    # Setup takes no version pin and carries its own payload version, so the
    # pin would be silently ignored; its SHA-256 pins an exact release.
    Exit-Wrapper $script:ExitInvalid 'mdm_invalid_arguments' '-ProductVersion applies only to the installed CLI (no -SetupPath); pin a staged Setup to one release with -Sha256'
}

$staging = New-WrapperStaging
Write-WrapperLog -Message "start action=$normalizedAction trust=$($script:Mode) setup=$([bool]$SetupPath)"
$config = ''
if ($ConfigFromStdin) {
    $config = Join-Path $staging 'config.yaml'
    Read-WrapperStdin -Destination $config -Limit $script:MaxConfigBytes -Label 'config'
} elseif ($ConfigPath) {
    $config = Join-Path $staging 'config.yaml'
    Copy-WrapperInput -Source $ConfigPath -Destination $config -Limit $script:MaxConfigBytes -Label 'config' -RequireAdminOnly
}
$secret = ''
if ($SecretName) {
    $secret = Join-Path $staging 'secret'
    if ($SecretFromStdin) {
        Read-WrapperStdin -Destination $secret -Limit $script:MaxSecretBytes -Label 'secret'
    } else {
        Copy-WrapperInput -Source $SecretPath -Destination $secret -Limit $script:MaxSecretBytes -Label 'secret' -RequireAdminOnly
    }
}

$exitCode = 0
try {
    if ($SetupPath) {
        $stagedSetup = Join-Path $staging 'DefenseClawSetup-Enterprise-Standalone-x64.exe'
        Copy-WrapperInput -Source $SetupPath -Destination $stagedSetup -Limit 1GB -Label 'Setup'
        Assert-WrapperSetup -Staged $stagedSetup
        Write-WrapperLog -Message "verified Setup (trust=$($script:Mode) sha256=$(if ($script:PinnedSha256) { $script:PinnedSha256 } else { 'unpinned' }))"
        $arguments = @('/' + $normalizedAction, 'JSON=1')
        if ($config) { $arguments += "CONFIG=$config" }
        if ($script:Signers.Count -gt 0) { $arguments += ('ALLOWEDSIGNERS=' + ($script:Signers -join ',')) }
        $run = Invoke-DefenseClawNative -FilePath $stagedSetup -ArgumentList $arguments
        $exitCode = Write-LifecycleResult -Run $run -Label 'Setup'
    } else {
        $deployment = Get-DefenseClawInstalledDeployment
        if ($null -eq $deployment) {
            Exit-Wrapper $script:ExitFailure 'mdm_not_installed' 'the deployment is not installed; pass -SetupPath to install it'
        }
        $arguments = @('enterprise', 'windows', $normalizedAction, '--profile', 'standalone', '--json')
        if ($config) { $arguments += @('--config', $config) }
        if ($ProductVersion) { $arguments += @('--product-version', $ProductVersion.TrimStart('v')) }
        $run = Invoke-DefenseClawNative -FilePath $deployment.Cli -ArgumentList $arguments
        $exitCode = Write-LifecycleResult -Run $run -Label 'defenseclaw.exe'
    }
} catch {
    Exit-Wrapper $script:ExitFailure 'mdm_lifecycle_launch_failed' $_.Exception.Message
}

if ($exitCode -eq 0 -and $secret) {
    try {
        $deployment = Get-DefenseClawInstalledDeployment
        if ($null -eq $deployment) { throw 'the deployment did not register its marker' }
        $run = Invoke-DefenseClawNative -FilePath $deployment.Cli -StandardInputPath $secret -ArgumentList @(
            'enterprise', 'secret', 'set', '--name', $SecretName, '--from-stdin', '--json')
    } catch {
        Exit-Wrapper $script:ExitFailure 'mdm_secret_failed' "storing credential '$SecretName' failed: $($_.Exception.Message)"
    }
    if ($run.ExitCode -ne 0) {
        $detail = ([string]$run.StdErr).Trim()
        if ($detail.Length -gt 1024) { $detail = $detail.Substring(0, 1024) }
        Exit-Wrapper $script:ExitFailure 'mdm_secret_failed' "storing credential '$SecretName' failed (exit $($run.ExitCode)): $detail"
    }
    Write-WrapperLog -Message "stored credential $SecretName"
}
Remove-WrapperStaging
exit $exitCode
