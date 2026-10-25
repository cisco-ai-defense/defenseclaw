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
         line, and stages them in the same folder; or, instead of a config,
         a signed policy bundle (-BundlePath) and its trust anchors
         (-TrustAnchorPath, administrator-only);
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
    pwsh -NoProfile -File Invoke-DefenseClawEnterprise.ps1 -SetupPath D:\stage\DefenseClawSetup-Enterprise-Standalone-x64.exe `
        -Sha256 3f0c...e1 -BundlePath D:\stage\policy-v7.dcbundle -TrustAnchorPath D:\stage\bundle-anchors.json

    Applies a signed policy bundle on an installed computer (Setup /ensure
    BUNDLE= TRUSTANCHORS=). The bundle carries the config, so -BundlePath is
    not combined with -ConfigPath. The bundle may come from any folder: the
    lifecycle verifies its own copy. The trust anchor file must be
    administrator-only, like a config.

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
    [string]$BundlePath = '',
    [string]$TrustAnchorPath = '',
	[switch]$RefuseCapabilityLoss,
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
    # Start the CLI in System32, never in the install's bin folder: a working
    # directory inside InstallRoot keeps an uninstall from retiring it (GAP-1684).
    $info.WorkingDirectory = [System.Environment]::SystemDirectory
    foreach ($name in @($info.EnvironmentVariables.Keys)) {
        if ($name -match '^(DOTNET_|COMPLUS_|CORECLR_|COR_ENABLE_PROFILING$|COR_PROFILER|PSMODULEPATH$|PSEXECUTIONPOLICYPREFERENCE$|__PSLOCKDOWNPOLICY$)') {
            $info.EnvironmentVariables.Remove($name)
        }
    }
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $info
    $elapsed = [System.Diagnostics.Stopwatch]::StartNew()
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
        # End the CLI and its PowerShell child before reporting the timeout.
        # Process.Kill() alone leaves the child holding the lifecycle lock.
        try {
            $killInfo = New-Object System.Diagnostics.ProcessStartInfo
            $killInfo.FileName = [System.IO.Path]::Combine([System.Environment]::SystemDirectory, 'taskkill.exe')
            $killInfo.Arguments = "/PID $($process.Id) /T /F"
            $killInfo.UseShellExecute = $false
            $killInfo.CreateNoWindow = $true
            $killInfo.RedirectStandardOutput = $true
            $killInfo.RedirectStandardError = $true
            $killer = [System.Diagnostics.Process]::Start($killInfo)
            if (-not $killer.WaitForExit(10000)) { $killer.Kill() }
            $killer.Dispose()
        } catch { $null = $_ }
        try { $process.Kill() } catch { $null = $_ }
        [void]$process.WaitForExit(5000)
        throw "native_timeout: $FilePath did not finish within $TimeoutSeconds seconds"
    }
    $remaining = [Math]::Max(0, $TimeoutSeconds * 1000 - [int]$elapsed.ElapsedMilliseconds)
    if (-not [System.Threading.Tasks.Task]::WaitAll(
            [System.Threading.Tasks.Task[]]@($stdout, $stderr), $remaining)) {
        throw "native_timeout: $FilePath output did not close within $TimeoutSeconds seconds"
    }
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
$script:MaxBundleBytes = 4MB
$script:MaxAnchorBytes = 256KB
$script:Staging = $null
$script:LogPath = $null
$script:ResultAction = 'ensure'
# The installed CLI while a credential this run rotated waits for its
# lifecycle to settle (credential rotation journal); every exit puts it back.
$script:RotationCli = ''
# This run's hold on the credential journal (rotation.lock): until it exits,
# no other wrapper run puts back or drops an entry this run still settles.
$script:RotationLock = $null
$script:RotationLockWaitSeconds = 60

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
    # The credential rotation and the bundle apply are one transaction: a run
    # that stops after the rotation and before its lifecycle settled puts the
    # old value back first. What is not put back stays journaled.
    if ($script:RotationCli) {
        $rotationCli = $script:RotationCli
        $script:RotationCli = ''
        try {
            Undo-WrapperSecretRotation -Cli $rotationCli
        } catch {
            Write-WrapperLog -Message "putting back credential '$SecretName' failed: $($_.Exception.Message); the next ensure tries again"
        }
    }
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
            # write, Administrators and Event Log Readers read. The results
            # name other accounts, so standard users may not read them.
            $security = [System.Security.AccessControl.DirectorySecurity]::new()
            $security.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;S-1-5-32-573)')
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

function New-WrapperAdminOnlyDirectory {
    # Creates a folder only SYSTEM and Administrators can open, owned by
    # Administrators, with no inherited entries.
    param([Parameter(Mandatory = $true)][string]$Path)
    $security = [System.Security.AccessControl.DirectorySecurity]::new()
    $security.SetSecurityDescriptorSddlForm('O:BAG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
    [System.IO.FileSystemAclExtensions]::Create([System.IO.DirectoryInfo]::new($Path), $security)
}

function New-WrapperStaging {
    $windows = [Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)
    $path = Join-Path $windows ('Temp\defenseclaw-mdm-' + [Guid]::NewGuid().ToString('N'))
    if (Test-Path -LiteralPath $path) { Exit-Wrapper $script:ExitFailure 'mdm_staging_untrusted' "staging folder $path already exists" }
    New-WrapperAdminOnlyDirectory -Path $path
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

function Get-WrapperUntrustedInputFix {
    # Names the accounts that own or can change an input the admin-only check
    # refused. The source folder may hold unrelated application data, so the
    # wrapper never recommends changing its ACLs (GAP-1175).
    param([Parameter(Mandatory = $true)][string]$Path)
    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    $sids = [System.Collections.Generic.List[string]]::new()
    $owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
    if ($script:DefenseClawAdminSids -notcontains $owner) {
        $sids.Add($owner)
    }
    # The rights Test-DefenseClawAdminOnlyItem refuses.
    $dangerous = [int64](0x2 -bor 0x4 -bor 0x10 -bor 0x40 -bor 0x100 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor 0x10000000 -bor 0x40000000)
    foreach ($rule in $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
        $sid = $rule.IdentityReference.Value
        if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }
        if (($rule.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) { continue }
        if ($script:DefenseClawAdminSids -contains $sid -or $sids.Contains($sid)) { continue }
        if (([int64]$rule.FileSystemRights -band $dangerous) -ne 0) { $sids.Add($sid) }
    }
    $accounts = foreach ($sid in $sids) {
        try {
            ([System.Security.Principal.SecurityIdentifier]::new($sid)).Translate([System.Security.Principal.NTAccount]).Value
        } catch {
            $sid
        }
    }
    return [pscustomobject]@{ Accounts = @($accounts) }
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
        $message = "$Label is writable by a non-administrator: $Source"
        $fix = try { Get-WrapperUntrustedInputFix -Path $Source } catch { $null }
        if ($null -ne $fix) {
            if ($fix.Accounts.Count -gt 0) { $message += ' (' + ($fix.Accounts -join ', ') + ' can change it)' }
        }
        $message += '. Nothing was changed. Stage a trusted copy in a new administrator-only folder dedicated to DefenseClaw, then run the wrapper again with that path'
        Exit-Wrapper $script:ExitFailure 'mdm_untrusted_input' $message
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

function ConvertTo-WrapperPublicText {
    # The config copy in the wrapper's staging folder is deleted when the
    # wrapper exits, so a result that names it (a next-step command such as
    # "/ensure CONFIG=<staging copy>") could not be run afterwards. Name the
    # administrator's own -ConfigPath instead, or <config.yaml> for a config
    # read from standard input. Both the raw and the JSON-escaped forms are
    # replaced; a replacement path with spaces is quoted in commands.
    param([string]$Text, [string]$Staged, [string]$Public)
    if (-not $Text -or -not $Staged) { return $Text }
    if (-not $Public) { $Public = '<config.yaml>' }
    $quoted = if ($Public -match '\s') { '"' + $Public + '"' } else { $Public }
    $escapedStaged = $Staged.Replace('\', '\\')
    $escapedPublic = $Public.Replace('\', '\\')
    $escapedQuoted = $quoted.Replace('\', '\\').Replace('"', '\"')
    $Text = $Text.Replace('CONFIG=' + $escapedStaged, 'CONFIG=' + $escapedQuoted)
    $Text = $Text.Replace('CONFIG=' + $Staged, 'CONFIG=' + $quoted)
    return $Text.Replace($escapedStaged, $escapedPublic).Replace($Staged, $Public)
}

function Write-LifecycleResult {
    # Passes a schema v2 result through; wraps anything else (Setup's own
    # argument errors, crashes) in one.
    param($Run, [string]$Label)
    $code = [int]$Run.ExitCode
    if (@(0, 1603, 1618, 1639, 3010) -notcontains $code) { $code = $script:ExitFailure }
    $text = ConvertTo-WrapperPublicText -Text ([string]$Run.StdOut).Trim() -Staged $script:StagedConfig -Public $ConfigPath
    $document = $null
    if ($text) { try { $document = $text | ConvertFrom-Json -ErrorAction Stop } catch { $document = $null } }
    if ($null -ne $document -and $document.PSObject.Properties['schema_version'] -and $document.schema_version -eq 2) {
        [Console]::Out.WriteLine($text)
        Write-WrapperLog -Message ("result " + ($text -replace '\s+', ' '))
        return $code
    }
    if ($code -eq 0) { $code = $script:ExitFailure }
    $stderr = ConvertTo-WrapperPublicText -Text ([string]$Run.StdErr) -Staged $script:StagedConfig -Public $ConfigPath
    $stderr = [regex]::Replace($stderr, '(?m)^DC_LIFECYCLE_PHASE: [^\r\n]*(?:\r?\n)?', '')
    $detail = if ($null -ne $document -and $document.PSObject.Properties['error']) { [string]$document.error } else { (($stderr + ' ' + $text).Trim()) }
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
if ($BundlePath -and ($ConfigPath -or $ConfigFromStdin)) {
    Exit-Wrapper $script:ExitInvalid 'mdm_invalid_arguments' '-BundlePath cannot be combined with -ConfigPath or -ConfigFromStdin: the signed bundle carries the config'
}
if ($RefuseCapabilityLoss -and -not $BundlePath) {
	Exit-Wrapper $script:ExitInvalid 'mdm_invalid_arguments' '-RefuseCapabilityLoss requires -BundlePath'
}
if ($normalizedAction -ne 'ensure' -and ($ConfigPath -or $ConfigFromStdin -or $SecretName -or $BundlePath -or $TrustAnchorPath)) {
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
$script:StagedConfig = $config
$bundle = ''
if ($BundlePath) {
    # Signed and hash-checked by the lifecycle on its own copy, so it may
    # come from any folder.
    $bundle = Join-Path $staging 'policy.dcbundle'
    Copy-WrapperInput -Source $BundlePath -Destination $bundle -Limit $script:MaxBundleBytes -Label 'bundle'
}
$anchors = ''
if ($TrustAnchorPath) {
    $anchors = Join-Path $staging 'bundle-anchors.json'
    Copy-WrapperInput -Source $TrustAnchorPath -Destination $anchors -Limit $script:MaxAnchorBytes -Label 'trust anchors' -RequireAdminOnly
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

function Get-WrapperSecretErrorCode {
    # errors[0].code of a failed `enterprise secret set|remove --json`, or ''.
    param($Run)
    try {
        $document = ([string]$Run.StdOut).Trim() | ConvertFrom-Json -ErrorAction Stop
        return [string]@($document.errors)[0].code
    } catch {
        return ''
    }
}

function Set-WrapperSecret {
    # Stores the staged credential with the installed CLI. Returns $null when
    # it is stored, else the failure (Code is the CLI's errors[0].code).
    param([string[]]$Extra = @())
    try {
        $deployment = Get-DefenseClawInstalledDeployment
        if ($null -eq $deployment) { throw 'the deployment did not register its marker' }
        $run = Invoke-DefenseClawNative -FilePath $deployment.Cli -StandardInputPath $secret -ArgumentList (@(
            'enterprise', 'secret', 'set', '--name', $SecretName, '--from-stdin', '--json') + $Extra)
    } catch {
        return [pscustomobject]@{ Code = ''; Message = "storing credential '$SecretName' failed: $($_.Exception.Message)" }
    }
    if ($run.ExitCode -ne 0) {
        $detail = ([string]$run.StdErr).Trim()
        if ($detail.Length -gt 1024) { $detail = $detail.Substring(0, 1024) }
        return [pscustomobject]@{ Code = (Get-WrapperSecretErrorCode -Run $run)
            Message = "storing credential '$SecretName' failed (exit $($run.ExitCode)): $detail" }
    }
    Write-WrapperLog -Message "stored credential $SecretName"
    return $null
}

# region credential rotation journal
#
# A credential delivered with a bundle to an installed 1.0.4 deployment is
# stored before the lifecycle applies that bundle (secret set --bundle, which
# restarts the gateway with it). Until the lifecycle confirms the bundle, the
# confirmed bundle signs only the value stored before. So that value (or
# that none was stored) is journaled first, in an administrator-only folder,
# and put back when the lifecycle fails, or at the start of the next ensure
# when this run stopped before it settled. Each entry also names the bundle
# confirmed before the rotation (bundle status), and the rotation runs only
# while that bundle is confirmed (--if-confirmed). The put-back passes it
# too (--undo-rotation): the CLI puts the value back, or removes a credential
# the rotation added, only while that bundle is still confirmed and does not
# sign the value stored now. An .absent entry also holds the SHA-256 of the
# config installed before the rotation (--undo-config): the CLI removes a
# credential the installed config references only while that very config is
# installed, so a config another ensure installed since keeps the value it
# may use (credential_in_use, the entry stays).
# Only its refusal rotation_confirmed proves the rotation committed (a
# bundle confirmed since uses the stored value), so only then does the new
# value stay. Any other refusal (credential_in_use, secret_ref_mismatch,
# secret_ref_unbound) proves nothing: the entry stays and is reported, and
# no other rotation runs while it does. A settled entry is first renamed
# .retired in one step, then overwritten and deleted, so an interrupted
# cleanup never leaves a bytes-gone entry a later run could put back. A
# bundle signed before 1.0.4 signs only the name (secret_ref_unbound): the
# CLI refuses a rotation from it that would replace a stored value. The journal is used
# only after its folders and entries pass the administrator-only check
# (Initialize-WrapperRotationJournal, Test-WrapperJournalEntry) and while
# this run holds rotation.lock (Enter-WrapperRotationLock), so a concurrent
# ensure never settles an entry a run still in flight wrote.

function Get-WrapperProgramData {
    $value = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
    if (-not $value -or $value -notmatch '^[A-Za-z]:\\') { throw "program_data_unresolved: unexpected ProgramData '$value'" }
    return $value.TrimEnd('\')
}

function Get-WrapperRotationJournal {
    return Join-Path (Get-WrapperProgramData) 'Cisco\DefenseClaw-MDM\rotation'
}

function Get-WrapperStoredSecretPath {
    # The deployment's credential file (managed.StandaloneLayout SecretsDir).
    param([Parameter(Mandatory = $true)][string]$Name)
    return Join-Path (Get-WrapperProgramData) ('Cisco\DefenseClaw\secrets\' + $Name)
}

function Initialize-WrapperRotationJournal {
    # The journal folder, once it and the folders above it are checked: its
    # two folders administrator-only (an administrator owns them, no link,
    # no other account can write), the folders above them not changeable by
    # another account. Every read, put-back and delete of an entry comes
    # after this check, so a folder another account created or can change is
    # refused and nothing in it is used or removed. With -Create the missing
    # folders are made administrator-only; without it a journal that does not
    # exist is $null.
    param([switch]$Create)
    $journal = Get-WrapperRotationJournal
    foreach ($directory in @((Split-Path -Parent $journal), $journal)) {
        if (-not (Test-Path -LiteralPath $directory)) {
            if (-not $Create) { return $null }
            New-WrapperAdminOnlyDirectory -Path $directory
        }
        if (-not (Test-Path -LiteralPath $directory -PathType Container) -or -not (Test-DefenseClawAdminOnlyItem -Path $directory)) {
            throw "the credential journal folder $directory is not administrator-only"
        }
    }
    if (-not (Test-WrapperAdminOnlyAncestors -Path (Join-Path $journal 'entry'))) {
        throw "a folder above the credential journal $journal can be changed by a non-administrator, or is a link"
    }
    return $journal
}

function Test-WrapperJournalEntry {
    # True for what this wrapper writes in the journal: a regular file, not
    # a link or a folder, that only administrators can change.
    param([Parameter(Mandatory = $true)]$Item)
    if ($Item.PSIsContainer -or ($Item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) { return $false }
    return [bool](Test-DefenseClawAdminOnlyItem -Path $Item.FullName)
}

function Enter-WrapperRotationLock {
    # Holds rotation.lock beside the journal until this run exits. Journaling
    # a credential, storing the new value, the lifecycle and its settle are
    # one transaction, so a concurrent ensure waits instead of putting back
    # or dropping an entry a run still in flight wrote. Still busy after
    # $script:RotationLockWaitSeconds: lifecycle_busy (1618, retry), with
    # nothing changed. With no journal and no -Create: $false.
    param([switch]$Create)
    if ($null -ne $script:RotationLock) { return $true }
    $journal = Initialize-WrapperRotationJournal -Create:$Create
    if (-not $journal) { return $false }
    $path = Join-Path (Split-Path -Parent $journal) 'rotation.lock'
    $deadline = [DateTime]::UtcNow.AddSeconds($script:RotationLockWaitSeconds)
    while ($true) {
        $item = Get-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        if ($null -ne $item -and -not (Test-WrapperJournalEntry -Item $item)) {
            throw "the credential journal lock $path is not a regular administrator-only file"
        }
        try {
            $script:RotationLock = [System.IO.FileStream]::new($path, [System.IO.FileMode]::OpenOrCreate,
                [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
            return $true
        } catch {
            # Only a sharing violation (another run holds it) is waited for.
            $failure = $_.Exception
            while ($failure -is [System.Management.Automation.MethodInvocationException] -and $null -ne $failure.InnerException) {
                $failure = $failure.InnerException
            }
            if ($failure -isnot [System.IO.IOException] -or $failure -is [System.IO.FileNotFoundException] -or
                $failure -is [System.IO.DirectoryNotFoundException]) { throw }
        }
        if ([DateTime]::UtcNow -ge $deadline) {
            Exit-Wrapper $script:ExitBusy 'lifecycle_busy' "another DefenseClaw MDM ensure holds the credential journal ($path) while it settles a credential rotation; nothing was changed, so run this ensure again after it finishes"
        }
        Start-Sleep -Milliseconds 500
    }
}

function Get-WrapperConfirmedBundle {
    # The manifest SHA-256 of the confirmed policy bundle (bundle status
    # --json), or 'none' when no bundle is confirmed: what a journal entry
    # records as the bundle confirmed before its rotation.
    param([Parameter(Mandatory = $true)][string]$Cli)
    $run = Invoke-DefenseClawNative -FilePath $Cli -ArgumentList @('enterprise', 'bundle', 'status', '--json')
    if ($run.ExitCode -ne 0) {
        throw "bundle status failed (exit $($run.ExitCode) $(Get-WrapperSecretErrorCode -Run $run)), so the confirmed bundle is unknown"
    }
    $document = ([string]$run.StdOut).Trim() | ConvertFrom-Json -ErrorAction Stop
    $current = $document.PSObject.Properties['current']
    if ($document.ok -ne $true -or $null -eq $current) { throw 'bundle status did not report the confirmed bundle' }
    if ($null -eq $current.Value) { return 'none' }
    $digest = $current.Value.PSObject.Properties['manifest_sha256']
    if ($null -eq $digest -or [string]$digest.Value -cnotmatch '^[0-9a-f]{64}$') {
        throw 'bundle status reported no valid manifest digest for the confirmed bundle'
    }
    return [string]$digest.Value
}

function Get-WrapperInstalledConfigIdentity {
    # The SHA-256 of the installed config (managed.StandaloneLayout
    # ConfigPath), or 'none' when no regular file is there: what an .absent
    # journal entry holds as the config installed before its rotation.
    $path = Join-Path (Get-WrapperProgramData) 'Cisco\DefenseClaw\etc\config.yaml'
    $item = Get-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
    if ($null -eq $item -or $item.PSIsContainer -or ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) { return 'none' }
    return (Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
}

function Get-WrapperRotatedValueDigest {
    # Match Go's bytes.TrimSpace in readWindowsSecretValue before naming the
    # journal entry. Work on bytes so even an invalid UTF-8 API key has the
    # same digest as the value the CLI stores.
    $bytes = [System.IO.File]::ReadAllBytes($secret)
    $hex = [System.BitConverter]::ToString($bytes).Replace('-', '').ToLowerInvariant()
    $space = '(?:09|0a|0b|0c|0d|20|c285|c2a0|e19a80|e2808[0-9a]|e280a[89]|e280af|e2819f|e38080)'
    while ($hex -cmatch ('^' + $space)) { $hex = $hex.Substring($Matches[0].Length) }
    while ($hex -cmatch ($space + '$')) { $hex = $hex.Substring(0, $hex.Length - $Matches[0].Length) }
    $normalized = [byte[]]::new($hex.Length / 2)
    for ($i = 0; $i -lt $normalized.Length; $i++) {
        $normalized[$i] = [Convert]::ToByte($hex.Substring($i * 2, 2), 16)
    }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return [System.BitConverter]::ToString($sha.ComputeHash($normalized)).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose(); [Array]::Clear($bytes, 0, $bytes.Length); [Array]::Clear($normalized, 0, $normalized.Length) }
}

function Get-WrapperJournalEntryName {
    # Current names hold the expected rotation value digest. Earlier rc
    # names (<name>[ @<confirmed> ][.absent]) have no digest and may only
    # settle when their before-state is already on disk.
    param([Parameter(Mandatory = $true)][string]$FileName)
    if ($FileName -cnotmatch '^(?<name>[a-z0-9][a-z0-9-]{0,62})(?:@(?<confirmed>[0-9a-f]{64}|none)(?:\+(?<stored>[0-9a-f]{64}))?)?(?<absent>\.absent)?$') { return $null }
    return [pscustomobject]@{ Name = $Matches.name; Confirmed = $(if ($Matches.ContainsKey('confirmed')) { $Matches.confirmed } else { 'none' })
        Stored = $(if ($Matches.ContainsKey('stored')) { $Matches.stored } else { '' })
        Absent = $Matches.ContainsKey('absent'); Legacy = -not $Matches.ContainsKey('stored') }
}

function Save-WrapperSecretJournal {
    # Journals credential $Name as it is stored now, with $Confirmed (the
    # bundle confirmed now), before a rotation replaces it; with nothing
    # stored, the .absent entry holds the SHA-256 of the installed config
    # (Get-WrapperInstalledConfigIdentity) instead. Refused while
    # the journal holds anything: an entry an earlier run could not settle
    # or one this wrapper did not write must be resolved first, so a second
    # rotation never runs over an entry it could not put back.
    param([Parameter(Mandatory = $true)][string]$Name, [Parameter(Mandatory = $true)][string]$Confirmed, [ref]$Preimage)
    if ($Confirmed -cnotmatch '^([0-9a-f]{64}|none)$') { throw "unexpected confirmed bundle '$Confirmed'" }
    $journal = Initialize-WrapperRotationJournal -Create
    $left = @(Get-ChildItem -LiteralPath $journal -Force)
    if ($left.Count -gt 0) {
        throw "an earlier credential rotation is not settled ($(@($left | ForEach-Object { $_.Name }) -join ', ') in $journal): each ensure tries to settle it first and logs why it could not; no credential is rotated until it is"
    }
    $entry = Join-Path $journal ($Name + '@' + $Confirmed + '+' + (Get-WrapperRotatedValueDigest))
    $stored = Get-WrapperStoredSecretPath -Name $Name
    $item = Get-Item -LiteralPath $stored -Force -ErrorAction SilentlyContinue
    $target = "$entry.absent"
    $before = 'none'
    # Nothing stored: the entry holds the config installed now instead.
    $bytes = [System.Text.Encoding]::ASCII.GetBytes((Get-WrapperInstalledConfigIdentity))
    if ($null -ne $item) {
        $folder = Get-Item -LiteralPath (Split-Path -Parent $stored) -Force
        if ($item.PSIsContainer -or ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -or
            ($folder.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
            throw "the stored credential $stored is not a regular file"
        }
        $target = $entry
        $bytes = [System.IO.File]::ReadAllBytes($stored)
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try { $before = [System.BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-', '').ToLowerInvariant() }
        finally { $sha.Dispose() }
    }
    $partial = "$entry.partial"
    try {
        $stream = [System.IO.FileStream]::new($partial, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::None, 4096, [System.IO.FileOptions]::WriteThrough)
        try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
    } finally { [Array]::Clear($bytes, 0, $bytes.Length) }
    [System.IO.File]::Move($partial, $target)
    if ($null -ne $Preimage) { $Preimage.Value = $before }
}

function Remove-WrapperJournalEntry {
    # Retires a settled entry: renamed .retired first (one step, so no later
    # run reads it as a recovery entry), then overwritten and deleted. A run
    # stopped in between leaves a .retired or .partial file, which the next
    # settle only deletes.
    param([Parameter(Mandatory = $true)][string]$Path)
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    if ($null -eq $item) { return }
    $length = $item.Length
    $retired = $Path
    if (-not ($Path.EndsWith('.retired') -or $Path.EndsWith('.partial'))) {
        $retired = "$Path.retired"
        $existing = Get-Item -LiteralPath $retired -Force -ErrorAction SilentlyContinue
        if ($null -ne $existing) {
            if (-not (Test-WrapperJournalEntry -Item $existing)) { throw "$retired is not a regular administrator-only file" }
            Remove-WrapperJournalEntry -Path $retired
        }
        [System.IO.File]::Move($Path, $retired)
    }
    # Overwrite a journaled credential before deleting it.
    if ($length -gt 0) { [System.IO.File]::WriteAllBytes($retired, [byte[]]::new($length)) }
    Remove-Item -LiteralPath $retired -Force
}

function Complete-WrapperSecretJournal {
    # Settles the journal: -Restore puts each journaled credential back with
    # $Cli (secret set|remove --undo-rotation <bundle confirmed before the
    # rotation>), and without it (the lifecycle confirmed the bundle) the
    # entries go. With no $Cli (nothing is installed any more) there is
    # nothing to put back. -Name limits it to one credential. Retired
    # entries and unfinished journal writes are only deleted. Returns what
    # could not be settled; those entries stay for the next ensure.
    param([string]$Cli = '', [string]$Name = '', [switch]$Restore)
    try {
        $journal = Initialize-WrapperRotationJournal
    } catch {
        return @("the credential journal was not used, and nothing in it was put back or removed: $($_.Exception.Message)")
    }
    if (-not $journal) { return @() }
    $problems = @()
    foreach ($file in @(Get-ChildItem -LiteralPath $journal -Force)) {
        if (-not (Test-WrapperJournalEntry -Item $file)) {
            # Not written by this wrapper: never read, put back or deleted.
            $problems += "the credential journal entry $($file.FullName) is not a regular administrator-only file, so it was not used and was left as it is"
            continue
        }
        if ($file.Name.EndsWith('.retired') -or $file.Name.EndsWith('.partial')) {
            # A settled entry whose cleanup stopped, or a journal write that
            # never finished (the rotation never ran): never put back.
            try { Remove-WrapperJournalEntry -Path $file.FullName } catch {
                $problems += "removing the settled credential journal entry $($file.FullName) failed: $($_.Exception.Message)"
            }
            continue
        }
        $entry = Get-WrapperJournalEntryName -FileName $file.Name
        if ($null -eq $entry) {
            $problems += "the credential journal entry $($file.FullName) is not one this wrapper writes, so it was not used and was left as it is; check the credential, then delete it"
            continue
        }
        if ($Name -and $entry.Name -ne $Name) { continue }
        if ($Restore -and $Cli) {
            $expectedStored = $entry.Stored
            if ($entry.Legacy) {
                # A digestless rc entry cannot identify B after rotation.
                # The only safe automatic settlement is a CLI no-op on its
                # exact before-state; otherwise --if-stored refuses the
                # change and keeps the entry for an administrator.
                try {
                    $expectedStored = if ($entry.Absent) { 'none' } else {
                        (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
                    }
                } catch {
                    $problems += "reading the earlier credential journal entry $($file.FullName) failed: $($_.Exception.Message); it was left as it is"
                    continue
                }
            }
            $arguments = @('enterprise', 'secret', 'set', '--name', $entry.Name, '--from-stdin', '--json', '--undo-rotation', $entry.Confirmed, '--if-stored', $expectedStored)
            $standardInput = $file.FullName
            if ($entry.Absent) {
                # The config installed before the rotation (Save-WrapperSecretJournal).
                $configBefore = if ($file.Length -le 64) { [System.IO.File]::ReadAllText($file.FullName) } else { '' }
                if (-not $entry.Legacy -and $configBefore -cnotmatch '^(?:[0-9a-f]{64}|none)\z') {
                    $problems += "the credential journal entry $($file.FullName) does not name the config installed before its rotation, so it was not used and was left as it is; check the credential, then delete it"
                    continue
                }
                if ($entry.Legacy -and $configBefore -cnotmatch '^(?:[0-9a-f]{64}|none)\z') { $configBefore = 'none' }
                $arguments = @('enterprise', 'secret', 'remove', '--name', $entry.Name, '--json', '--undo-rotation', $entry.Confirmed, '--undo-config', $configBefore, '--if-stored', $expectedStored)
                $standardInput = ''
            }
            try {
                $run = Invoke-DefenseClawNative -FilePath $Cli -StandardInputPath $standardInput -ArgumentList $arguments
            } catch {
                $problems += "putting back credential '$($entry.Name)' failed: $($_.Exception.Message); the next ensure tries again"
                continue
            }
            if ($run.ExitCode -eq 0) {
                Write-WrapperLog -Message "put back credential $($entry.Name): the lifecycle did not confirm the bundle that signs its new value"
            } else {
                $code = Get-WrapperSecretErrorCode -Run $run
                # Only rotation_confirmed proves the rotation committed (and
                # not_installed that nothing is left to put back); any other
                # refusal keeps the entry.
                if (@('rotation_confirmed', 'not_installed') -notcontains $code) {
                    $problems += "putting back credential '$($entry.Name)' failed (exit $($run.ExitCode) $code); the next ensure tries again"
                    continue
                }
                Write-WrapperLog -Message "kept credential $($entry.Name): $code"
            }
        }
        try { Remove-WrapperJournalEntry -Path $file.FullName } catch {
            $problems += "retiring the credential journal entry $($file.FullName) failed: $($_.Exception.Message); the next ensure settles it again"
        }
    }
    return @($problems)
}

function Undo-WrapperSecretRotation {
    # Puts back credential $SecretName after the lifecycle failed or did not
    # start. Anything not put back stays journaled for the next ensure.
    param([string]$Cli)
    foreach ($problem in @(Complete-WrapperSecretJournal -Cli $Cli -Name $SecretName -Restore)) {
        Write-WrapperLog -Message $problem
        [Console]::Error.WriteLine($problem)
    }
}
# endregion credential rotation journal

function Test-WrapperSecretSetBundle {
    # True when the installed CLI's secret set takes --bundle: --version-json
    # reports secret_set_bundle (from 1.0.4). An older CLI binds no
    # credential value and refuses the flag.
    param([Parameter(Mandatory = $true)][string]$Cli)
    try {
        $run = Invoke-DefenseClawNative -FilePath $Cli -ArgumentList @('--version-json') -TimeoutSeconds 120
        if ($run.ExitCode -ne 0) { return $false }
        $document = ([string]$run.StdOut).Trim() | ConvertFrom-Json -ErrorAction Stop
        return ($document.secret_set_bundle -eq $true)
    } catch {
        return $false
    }
}

function Resume-WrapperSecretJournal {
    # An earlier ensure that stopped between storing a credential and
    # settling its lifecycle left a journal entry: put that credential back
    # first. The journal is held first (Enter-WrapperRotationLock), so an
    # entry a concurrent run is still settling is waited for, never taken. A
    # journal that fails its check, or a deployment this run cannot trust,
    # keeps every entry for a later run and stops this ensure before it can
    # install a config that adopts the unsettled credential.
    $problems = @()
    try {
        $held = Enter-WrapperRotationLock
    } catch {
        $held = $false
        $problems += "the credential journal was not used, and nothing in it was put back or removed: $($_.Exception.Message)"
    }
    if ($held) {
        $cli = $null
        try {
            $deployment = Get-DefenseClawInstalledDeployment
            $cli = if ($null -ne $deployment) { $deployment.Cli } else { '' }
        } catch {
            $cli = $null
            $problems += "the installed deployment could not be inspected before credential journal replay: $($_.Exception.Message)"
        }
        if ($null -ne $cli) { $problems += @(Complete-WrapperSecretJournal -Cli $cli -Restore) }
    }
    foreach ($problem in $problems) {
        Write-WrapperLog -Message $problem
        [Console]::Error.WriteLine($problem)
    }
    if ($problems.Count -gt 0) {
        Exit-Wrapper $script:ExitFailure 'mdm_secret_failed' 'the credential journal is not settled; no lifecycle change was started; inspect the logged problem and retry after it is resolved'
    }
}

if ($normalizedAction -eq 'ensure') { Resume-WrapperSecretJournal }

# A credential delivered with a bundle to an installed deployment is stored
# first, with the bundle: the apply refuses a stored value the bundle does
# not sign, and a credential the confirmed bundle signs changes only to a
# value a newer signed bundle signs (secret set --bundle). The value it
# replaces is journaled first and put back unless the lifecycle succeeds
# (credential rotation journal). With -SetupPath, or an installed CLI before
# 1.0.4, which takes no --bundle, the credential is stored after the
# lifecycle as before.
$secretStored = $false
$installedDeployment = $null
if ($secret -and $bundle -and -not $SetupPath) { $installedDeployment = Get-DefenseClawInstalledDeployment }
if ($null -ne $installedDeployment -and (Test-WrapperSecretSetBundle -Cli $installedDeployment.Cli)) {
    try {
        [void](Enter-WrapperRotationLock -Create)
        $confirmedBundle = Get-WrapperConfirmedBundle -Cli $installedDeployment.Cli
        $preimage = ''
        Save-WrapperSecretJournal -Name $SecretName -Confirmed $confirmedBundle -Preimage ([ref]$preimage)
    } catch {
        Exit-Wrapper $script:ExitFailure 'mdm_secret_failed' "journaling credential '$SecretName' before its rotation failed, so nothing was changed: $($_.Exception.Message)"
    }
    $failure = Set-WrapperSecret -Extra @('--bundle', $bundle, '--if-confirmed', $confirmedBundle, '--if-stored', $preimage)
    if ($null -ne $failure) {
        # These refusals come before anything is written; after any other
        # failure the new value may be stored, so the old one goes back.
        if (@('secret_ref_mismatch', 'secret_ref_unbound', 'invalid_arguments', 'lifecycle_busy', 'confirmed_bundle_changed', 'credential_changed') -contains $failure.Code) {
            [void](Complete-WrapperSecretJournal -Name $SecretName)
        } else {
            Undo-WrapperSecretRotation -Cli $installedDeployment.Cli
        }
        Exit-Wrapper $script:ExitFailure 'mdm_secret_failed' $failure.Message
    }
    $secretStored = $true
    # From here until the lifecycle settles it, every exit puts it back.
    $script:RotationCli = $installedDeployment.Cli
}

$exitCode = 0
try {
    if ($SetupPath) {
        $stagedSetup = Join-Path $staging 'DefenseClawSetup-Enterprise-Standalone-x64.exe'
        Copy-WrapperInput -Source $SetupPath -Destination $stagedSetup -Limit 1GB -Label 'Setup'
        Assert-WrapperSetup -Staged $stagedSetup
        Write-WrapperLog -Message "verified Setup (trust=$($script:Mode) sha256=$(if ($script:PinnedSha256) { $script:PinnedSha256 } else { 'unpinned' }))"
        # Parenthesize the switch: the comma operator binds tighter than +, so
        # '/' + $normalizedAction, 'JSON=1' is one string "/ensure JSON=1".
        $arguments = @(('/' + $normalizedAction), 'JSON=1')
        if ($config) { $arguments += "CONFIG=$config" }
        if ($bundle) { $arguments += "BUNDLE=$bundle" }
        if ($anchors) { $arguments += "TRUSTANCHORS=$anchors" }
		if ($RefuseCapabilityLoss) { $arguments += 'REFUSECAPABILITYLOSS=1' }
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
        if ($bundle) { $arguments += @('--bundle', $bundle) }
        if ($anchors) { $arguments += @('--trust-anchors', $anchors) }
		if ($RefuseCapabilityLoss) { $arguments += '--refuse-capability-loss' }
        if ($ProductVersion) { $arguments += @('--product-version', $ProductVersion.TrimStart('v')) }
        $run = Invoke-DefenseClawNative -FilePath $deployment.Cli -ArgumentList $arguments
        $exitCode = Write-LifecycleResult -Run $run -Label 'defenseclaw.exe'
    }
} catch {
    # Exit-Wrapper puts a rotated credential back.
    Exit-Wrapper $script:ExitFailure 'mdm_lifecycle_launch_failed' $_.Exception.Message
}

if ($secretStored) {
    $script:RotationCli = ''
    # Success confirmed the bundle that signs the stored value.
    if ($exitCode -eq 0) {
        [void](Complete-WrapperSecretJournal -Name $SecretName)
    } else {
        Undo-WrapperSecretRotation -Cli $installedDeployment.Cli
    }
}
if ($exitCode -eq 0 -and $secret -and -not $secretStored) {
    $failure = Set-WrapperSecret
    if ($null -ne $failure) { Exit-Wrapper $script:ExitFailure 'mdm_secret_failed' $failure.Message }
}
Remove-WrapperStaging
exit $exitCode
