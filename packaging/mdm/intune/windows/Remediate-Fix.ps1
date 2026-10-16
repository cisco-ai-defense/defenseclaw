# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
<#
.SYNOPSIS
    Intune Remediations remediation script: converge the installed DefenseClaw
    standalone deployment.

.DESCRIPTION
    Runs the installed native CLI's `enterprise windows ensure --profile
    standalone --json`, which re-verifies and repairs from the installed
    payload (or is a no-op). 5.1-compatible for the same reason as
    Remediate-Detect.ps1: all lifecycle work happens in the native CLI and
    its trusted PowerShell 7 engine, never in the 32-bit Intune host.

    On a device that takes signed policy bundles, ensure re-applies the
    confirmed bundle from the bundle store when config.yaml was changed
    outside the lifecycle, and the script checks again that the gateway
    enforces it before it reports success.

    Exit 0 = repaired or already healthy; non-zero = still failing. Intune
    keeps at most 2,048 characters of output, so this prints a one-line
    summary; the full result is in %WINDIR%\Logs\DefenseClaw\enterprise-lifecycle.log.
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

function Test-DefenseClawLifecycleRunning {
    # True while a DefenseClaw lifecycle run (Setup, ensure, a bundle apply
    # or an uninstall) holds lifecycle.lock. The script then starts no
    # installed CLI: a CLI running from the install folder makes a running
    # uninstall refuse with uninstall_in_use (GAP-0126). A missing lock, or
    # one this account cannot open, is not a running lifecycle. The probe
    # holds the lock file for an instant; a lifecycle that opens it at that
    # moment waits (Setup) or reports a retryable lifecycle_busy. Identical
    # in detect.ps1, Remediate-Detect.ps1 and Remediate-Fix.ps1 (a test
    # enforces it).
    $key = Get-DefenseClawRegistryKey64 -SubKey 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders'
    if ($null -eq $key) { return $false }
    try {
        $programData = [string]$key.GetValue('Common AppData', $null,
            [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    } finally { $key.Dispose() }
    if (-not $programData -or $programData.Contains('%') -or $programData -notmatch '^[A-Za-z]:\\[^/]*$') { return $false }
    $lock = $programData.TrimEnd('\') + '\Cisco\DefenseClaw-Lifecycle\lifecycle.lock'
    try {
        $stream = [System.IO.File]::Open($lock, [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        $stream.Dispose()
        return $false
    } catch [System.IO.FileNotFoundException], [System.IO.DirectoryNotFoundException] {
        return $false
    } catch [System.IO.IOException] {
        return $true
    } catch {
        return $false
    }
}

function Get-DefenseClawBundleEnforcement {
    # A bundle-mode device is compliant only while the running gateway
    # enforces its confirmed signed policy bundle: `enterprise bundle status`
    # reports the marker's bundle as current with applied true (GAP-0114: a
    # config.yaml edited outside the lifecycle verified healthy while the
    # gateway enforced the edit). $null when the marker names no confirmed
    # bundle: without one the installed config is the policy and
    # verify covers it. Identical in Remediate-Detect.ps1 and
    # Remediate-Fix.ps1 (a test enforces it).
    param([Parameter(Mandatory = $true)][string]$Cli)
    $key = Get-DefenseClawRegistryKey64 -SubKey $script:DefenseClawMarkerKey
    if ($null -eq $key) { return $null }
    try {
        if ([string]$key.GetValue('BundleState') -ne 'confirmed') { return $null }
        $id = [string]$key.GetValue('BundleId')
        $version = [string]$key.GetValue('BundleVersion')
    } finally { $key.Dispose() }
    $label = "signed policy bundle $id version $version"
    $verdict = New-Object -TypeName PSObject -Property @{ Applied = $false; Line = '' }
    $field = {
        param($Object, [string]$Name)
        if ($null -eq $Object) { return $null }
        $property = $Object.PSObject.Properties[$Name]
        if ($null -eq $property) { return $null }
        return $property.Value
    }
    $short = {
        param([string]$Digest)
        if (-not $Digest) { return 'none' }
        if ($Digest.Length -gt 19) { return $Digest.Substring(0, 19) }
        return $Digest
    }
    try {
        $run = Invoke-DefenseClawNative -FilePath $Cli -TimeoutSeconds 300 -ArgumentList @(
            'enterprise', 'bundle', 'status', '--json')
        $status = $null
        if ([string]$run.StdOut) { $status = ([string]$run.StdOut) | ConvertFrom-Json }
    } catch {
        $verdict.Line = "$label is confirmed, but bundle status could not be read: $($_.Exception.Message)"
        return $verdict
    }
    if ($run.ExitCode -ne 0 -or $null -eq $status) {
        $verdict.Line = "$label is confirmed, but bundle status exited $($run.ExitCode)"
        return $verdict
    }
    $current = & $field $status 'current'
    if ($null -eq $current -or [string](& $field $current 'bundle_id') -ne $id) {
        $verdict.Line = "$label is confirmed in the enterprise marker but is not the current bundle in the bundle store"
        return $verdict
    }
    if (-not [bool](& $field $status 'applied')) {
        $detail = 'the running gateway policy could not be checked'
        if ([bool](& $field $status 'gateway_checked')) {
            $detail = 'the gateway enforces ' + (& $short ([string](& $field $status 'gateway_digest'))) +
                ', not ' + (& $short ([string](& $field $current 'effective_policy_digest')))
        }
        $verdict.Line = "$label is confirmed but not applied: $detail"
        return $verdict
    }
    $verdict.Applied = $true
    $verdict.Line = "$label is applied"
    return $verdict
}

function Get-DefenseClawStoppedSideServices {
    # From a failed verify result, the guardian and enumerator services that
    # are not running while the gateway and sensor helper run. Starting just
    # those repairs the drift; a full ensure re-applies the deployment and
    # stops every service, so every user's hooks failed closed for well over
    # a minute (GAP-0574). Any other failure returns nothing.
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Json)
    try { $document = $Json | ConvertFrom-Json } catch { return @() }
    $services = @($document.services)
    $down = @($services | Where-Object { $_.required -and [string]$_.state -ne 'running' })
    if ($down.Count -eq 0) { return @() }
    foreach ($service in $down) {
        if (@('guardian', 'enumerator') -notcontains [string]$service.kind -or
            [string]$service.name -notmatch '^DefenseClaw[A-Za-z]+$') { return @() }
    }
    foreach ($kind in @('gateway', 'sensor_helper')) {
        if (@($services | Where-Object { [string]$_.kind -eq $kind -and [string]$_.state -eq 'running' }).Count -eq 0) { return @() }
    }
    return @($down | ForEach-Object { [string]$_.name })
}

function Get-DefenseClawRemediationStartModes {
    $modes = [ordered]@{}
    foreach ($name in @('DefenseClawHookGuardian', 'DefenseClawGateway',
            'DefenseClawHookEnumerator', 'DefenseClawSensorHelper')) {
        $key = Get-DefenseClawRegistryKey64 -SubKey "SYSTEM\CurrentControlSet\Services\$name"
        if ($null -eq $key) { $modes[$name] = -1; continue }
        try {
            $mode = [int]$key.GetValue('Start', -1)
        } catch {
            $mode = -1
        } finally { $key.Dispose() }
        $modes[$name] = if ($mode -in @(2, 3)) { $mode } else { -1 }
    }
    return $modes
}

function Restore-DefenseClawRemediationStartModes {
    param([Parameter(Mandatory = $true)]$PriorModes)
    $sc = [System.IO.Path]::Combine([System.Environment]::SystemDirectory, 'sc.exe')
    $failures = New-Object System.Collections.Generic.List[string]
    foreach ($name in $PriorModes.Keys) {
        if ([int]$PriorModes[$name] -notin @(2, 3)) { continue }
        $key = Get-DefenseClawRegistryKey64 -SubKey "SYSTEM\CurrentControlSet\Services\$name"
        if ($null -eq $key) {
            $failures.Add("$name disappeared")
            continue
        }
        try { $current = [int]$key.GetValue('Start', -1) }
        catch { $failures.Add("$name`: cannot read current startup mode: $($_.Exception.Message)"); continue }
        finally { $key.Dispose() }
        # Only undo a quiesce. A later successful installer must own any
        # deliberate service-mode change, including Disabled.
        if ($current -ne 4) { continue }
        $mode = switch ([int]$PriorModes[$name]) {
            2 { 'auto' }
            3 { 'demand' }
        }
        try {
            $change = Invoke-DefenseClawNative -FilePath $sc -TimeoutSeconds 30 -ArgumentList @(
                'config', $name, 'start=', $mode)
            if ($change.ExitCode -ne 0) { throw "sc.exe exited $($change.ExitCode)" }
            $key = Get-DefenseClawRegistryKey64 -SubKey "SYSTEM\CurrentControlSet\Services\$name"
            if ($null -eq $key) { throw 'service disappeared after sc.exe config' }
            try { $restored = [int]$key.GetValue('Start', -1) } finally { $key.Dispose() }
            if ($restored -ne [int]$PriorModes[$name]) { throw "startup mode is still $restored" }
        } catch { $failures.Add("$name`: $($_.Exception.Message)") }
    }
    return ($failures -join '; ')
}

try {
    $deployment = Get-DefenseClawInstalledDeployment
} catch {
    [Console]::Out.WriteLine("DefenseClaw: not repaired: $($_.Exception.Message)")
    exit 1603
}
if ($null -eq $deployment) {
    [Console]::Out.WriteLine('DefenseClaw: not installed (the Win32 app installs it)')
    exit 0
}
if (Test-DefenseClawLifecycleRunning) {
    # As an ensure that met the lock would: 1618, nothing started (GAP-0126).
    [Console]::Out.WriteLine("DefenseClaw $($deployment.Version): not started: another DefenseClaw lifecycle run is in progress; the next scheduled run checks again")
    exit 1618
}
try {
    $check = Invoke-DefenseClawNative -FilePath $deployment.Cli -TimeoutSeconds 180 -ArgumentList @(
        'enterprise', 'windows', 'verify', '--profile', 'standalone', '--json')
    $stopped = @(Get-DefenseClawStoppedSideServices -Json ([string]$check.StdOut))
    if ($check.ExitCode -ne 0 -and $stopped.Count -gt 0) {
        $sc = [System.IO.Path]::Combine([System.Environment]::SystemDirectory, 'sc.exe')
        foreach ($name in $stopped) {
            [void](Invoke-DefenseClawNative -FilePath $sc -TimeoutSeconds 60 -ArgumentList @('config', $name, 'start=', 'auto'))
            [void](Invoke-DefenseClawNative -FilePath $sc -TimeoutSeconds 60 -ArgumentList @('start', $name))
        }
        Start-Sleep -Seconds 15
        $after = Invoke-DefenseClawNative -FilePath $deployment.Cli -TimeoutSeconds 180 -ArgumentList @(
            'enterprise', 'windows', 'verify', '--profile', 'standalone', '--json')
        $bundle = $null
        if ($after.ExitCode -eq 0) { $bundle = Get-DefenseClawBundleEnforcement -Cli $deployment.Cli }
        if ($after.ExitCode -eq 0 -and ($null -eq $bundle -or $bundle.Applied)) {
            [Console]::Out.WriteLine("DefenseClaw $($deployment.Version): repaired (started $($stopped -join ', '))")
            exit 0
        }
    }
} catch { $null = $_ }
try {
    $priorModes = Get-DefenseClawRemediationStartModes
} catch {
    [Console]::Out.WriteLine("DefenseClaw $($deployment.Version): ensure could not begin: $($_.Exception.Message)")
    exit 1603
}
$ensureFailure = ''
$run = $null
try {
    $run = Invoke-DefenseClawNative -FilePath $deployment.Cli -TimeoutSeconds 840 -ArgumentList @(
        'enterprise', 'windows', 'ensure', '--profile', 'standalone', '--json')
} catch {
    $ensureFailure = $_.Exception.Message
}
if ($null -eq $run -and -not $ensureFailure) { $ensureFailure = 'native ensure returned no result' }
$restoreFailure = ''
$committed = $false
if ($null -ne $run -and $run.ExitCode -notin @(3010, 1618)) {
    try {
        $ensureDocument = $run.StdOut | ConvertFrom-Json
        $committed = [bool]$ensureDocument.ok -and -not [bool]$ensureDocument.transaction_pending
    } catch { $null = $_ }
}
if (-not $committed -and ($ensureFailure -or
        ($null -ne $run -and $run.ExitCode -notin @(0, 3010, 1618)))) {
    try { $restoreFailure = [string](Restore-DefenseClawRemediationStartModes -PriorModes $priorModes) }
    catch { $restoreFailure = $_.Exception.Message }
}
if ($ensureFailure) {
    $summary = "ensure could not run: $ensureFailure"
    if ($restoreFailure) { $summary += "; startup-mode restore failed: $restoreFailure" }
    $line = "DefenseClaw $($deployment.Version): $summary"
    if ($line.Length -gt 2000) { $line = $line.Substring(0, 2000) }
    [Console]::Out.WriteLine($line)
    exit 1603
}
$code = $run.ExitCode
if (@(0, 1603, 1618, 1639, 3010) -notcontains $code) { $code = 1603 }
$summary = "exit $code"
try {
    $document = $run.StdOut | ConvertFrom-Json
    $ok = $false
    if ($document.PSObject.Properties['ok']) { $ok = [bool]$document.ok }
    $warnings = @(if ($document.PSObject.Properties['warnings']) { $document.warnings })
    # The installed CLI has no payload to install a missing scanner runtime
    # from: its ensure succeeds with a warning while verify keeps failing, so
    # this is not repaired, and only Setup /repair fixes it (GAP-0631).
    $runtime = @($warnings | Where-Object { $null -ne $_ -and $_.code -eq 'scanner_runtime_unavailable' } | Select-Object -First 1)
    if ($ok -and $runtime.Count -gt 0) { $code = 1603 }
    $errors = @(if ($document.PSObject.Properties['errors']) { $document.errors })
    $changes = @(if ($document.PSObject.Properties['changes']) { $document.changes })
    $noop = $false
    if ($document.PSObject.Properties['noop']) { $noop = [bool]$document.noop }
    $codes = (@($errors | ForEach-Object { [string]$_.code }) -join ',')
    # A rollback of an interrupted change (an upgrade cut off by a restart or
    # a power loss) is repaired, but the change itself did not finish: say
    # so and name the next step (GAP-0767).
    $recovered = @($warnings | Where-Object { $null -ne $_ -and $_.code -eq 'recovered_pending_transaction' } | Select-Object -First 1)
    # A config.yaml changed outside the lifecycle that ensure put back from
    # the confirmed policy bundle is a repair, even when nothing else was
    # left to do (GAP-0114).
    $restored = @($warnings | Where-Object { $null -ne $_ -and $_.code -eq 'bundle_config_restored' } | Select-Object -First 1)
    $specificErrors = @($errors | Where-Object {
        $null -ne $_ -and [string]$_.code -and [string]$_.code -ne 'lifecycle_error'
    } | Select-Object -First 1)
    # These Windows ensure warnings describe a repair; other warnings are
    # informational and must not be named as the repaired problem.
    $repairWarnings = @($warnings | Where-Object {
        $null -ne $_ -and @('config_reverted', 'ensure_config_applied') -contains [string]$_.code
    } | Select-Object -First 1)
    $specificProblem = $null
    if ($specificErrors.Count -gt 0) { $specificProblem = $specificErrors[0] }
    elseif ($repairWarnings.Count -gt 0) { $specificProblem = $repairWarnings[0] }
    $repairChanges = @($changes | Where-Object { [string]$_ })
    if ($ok -and $runtime.Count -gt 0) {
        $summary = "not repaired (scanner_runtime_unavailable): $($runtime[0].message)"
    }
    elseif ($ok -and $recovered.Count -gt 0) { $summary = "repaired (recovered_pending_transaction): $($recovered[0].message)" }
    elseif ($ok -and $restored.Count -gt 0) { $summary = "repaired (bundle_config_restored): $($restored[0].message)" }
    elseif ($ok -and $repairChanges.Count -gt 0) {
        $problemCode = if ($null -ne $specificProblem) { [string]$specificProblem.code } else { 'drift' }
        $summary = "repaired ($problemCode): $($repairChanges -join ', ')"
    }
    elseif ($ok -and $noop) { $summary = 'no repair needed after verify' }
    elseif ($ok) { $summary = 'ensure completed' }
    else {
        $problemCode = if ($null -ne $specificProblem) { [string]$specificProblem.code } else { $codes }
        $summary = "still failing ($problemCode)"
        $first = if ($null -ne $specificProblem) { $specificProblem } elseif ($errors.Count -gt 0) { $errors[0] } else { $null }
        if ($null -ne $first -and $first.message) { $summary += ": $($first.message)" }
        if ($repairChanges.Count -gt 0) { $summary += "; attempted repair: $($repairChanges -join ', ')" }
        $cliRestore = @($errors | Where-Object { $null -ne $_ -and $_.code -eq 'startup_mode_restore_failed' } | Select-Object -First 1)
        if ($cliRestore.Count -gt 0 -and $cliRestore[0].message) {
            $summary += "; startup-mode restore failed: $($cliRestore[0].message)"
        }
        # A DefenseClaw binary went missing (an antivirus quarantine): the
        # installed CLI has no payload to restore it from, so say what does
        # (GAP-0935).
        if ([string]$run.StdOut -match 'managed artifact is missing|managed path is missing' -and $summary -notmatch '/repair') {
            $summary += ' Next step: run the DefenseClaw Setup of this release with /repair JSON=1 as LocalSystem (for example a reinstall of the Win32 app); it restores the missing file from its payload.'
        }
    }
} catch { $summary = "exit $code, no lifecycle result" }
if ($code -eq 0) {
    # Detect again before reporting success: on a bundle-mode device the
    # remediation succeeded only when the gateway enforces the confirmed
    # bundle again. Otherwise Intune must show the failure (GAP-0114).
    try {
        $bundle = Get-DefenseClawBundleEnforcement -Cli $deployment.Cli
    } catch {
        $bundle = New-Object -TypeName PSObject -Property @{ Applied = $false; Line = "the signed policy bundle could not be checked: $($_.Exception.Message)" }
    }
    if ($null -ne $bundle -and -not $bundle.Applied) {
        $summary = "not repaired: $($bundle.Line)"
        $code = 1603
    } elseif ($null -ne $bundle) {
        $summary += "; $($bundle.Line)"
    }
}
if ($restoreFailure) {
    $summary += "; startup-mode restore failed: $restoreFailure"
    $code = 1603
}
$line = "DefenseClaw $($deployment.Version): $summary"
if ($line.Length -gt 2000) { $line = $line.Substring(0, 2000) }
[Console]::Out.WriteLine($line)
exit $code
