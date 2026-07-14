# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

<#
.SYNOPSIS
    Runs native Setup CI under a disposable real Windows standard user.

.DESCRIPTION
    GitHub-hosted Windows runners use an administrator account with UAC
    disabled, so they have no same-user limited token. This wrapper creates a
    short-lived local standard user, gives that SID narrowly scoped access to
    a private test sandbox and the current interactive desktop, and launches
    the complete Setup acceptance process with its own profile and HKCU hive.
    Credentials never enter argv, environment variables, files, or logs.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('setup-acceptance', 'wizard-smoke')]
    [string]$Mode,
    [Parameter(Mandatory)][string]$ArtifactRoot,
    [Parameter(Mandatory)][string]$StateRoot,
    [string]$DiagnosticsRoot = '',
    [ValidateRange(60, 7200)][int]$TimeoutSeconds = 4500,
    [switch]$Child,
    [switch]$CleanupOnly,
    [string]$ResultPath = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'windows-native-paths.ps1')

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Write-ChildResult([string]$Path, [bool]$Succeeded, [string]$Detail) {
    if ([string]::IsNullOrWhiteSpace($Path)) { return }
    $bounded = if ($Detail.Length -gt 32768) { $Detail.Substring(0, 32768) + "`n[truncated]" } else { $Detail }
    $payload = [ordered]@{
        succeeded = $Succeeded
        user_sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        elevated = Test-IsAdministrator
        detail = $bounded
    } | ConvertTo-Json -Depth 3
    [IO.File]::WriteAllText($Path, $payload, [Text.UTF8Encoding]::new($false))
}

function Invoke-ChildMode {
    $result = [IO.Path]::GetFullPath($ResultPath)
    $state = [IO.Path]::GetFullPath($StateRoot)
    $artifacts = [IO.Path]::GetFullPath($ArtifactRoot)
    if (Test-IsAdministrator) {
        throw 'disposable Setup acceptance child is an administrator'
    }

    $standardLauncher = Join-Path $PSScriptRoot 'windows-setup-standard-user-launcher.cs'
    Add-Type -Path $standardLauncher
    if ([DefenseClaw.SetupStandardUserLauncher]::IsCurrentProcessElevated()) {
        throw 'disposable Setup acceptance child token is elevated'
    }

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $accountName = ($identity.Name -split '\\')[-1]
    if ($accountName -notmatch '^dcacc[0-9a-f]{10}$') {
        throw 'child mode is restricted to a DefenseClaw disposable Setup CI account'
    }
    $localAccount = Get-LocalUser -Name $accountName -ErrorAction Stop
    if ($null -eq $identity.User -or
        -not $localAccount.SID.Equals($identity.User) -or
        $localAccount.Description -ne 'DefenseClaw disposable Setup CI account') {
        throw 'child mode could not verify the disposable Setup CI account identity'
    }

    $sandboxRoot = Split-Path -Parent $state
    $expectedScripts = Join-Path $sandboxRoot 'workspace\scripts'
    $expectedArtifacts = Join-Path $sandboxRoot 'artifacts'
    $allowedResults = @(
        (Join-Path $sandboxRoot 'result.json'),
        (Join-Path $sandboxRoot 'cleanup-result.json')
    )
    if (-not $PSScriptRoot.Equals(
            [IO.Path]::GetFullPath($expectedScripts),
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        -not $artifacts.Equals(
            [IO.Path]::GetFullPath($expectedArtifacts),
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        -not ($allowedResults | Where-Object {
            $result.Equals(
                [IO.Path]::GetFullPath($_),
                [StringComparison]::OrdinalIgnoreCase
            )
        } | Select-Object -First 1)) {
        throw 'child mode paths do not match the private disposable-user sandbox layout'
    }
    $interactive = [Security.Principal.SecurityIdentifier]::new('S-1-5-4')
    $groupSids = if ($null -eq $identity.Groups) { @() } else { @(
        $identity.Groups | ForEach-Object {
            $_.Translate([Security.Principal.SecurityIdentifier]).Value
        }
    ) }
    if ($null -eq $identity.User -or $interactive.Value -notin $groupSids) {
        throw 'disposable Setup acceptance child is not an interactive standard user'
    }

    $env:GITHUB_ACTIONS = 'true'
    $env:RUNNER_ENVIRONMENT = 'github-hosted'
    $env:CI = 'true'
    # The native harness requires StateRoot to be a strict child of an
    # approved temporary root. Keep that invariant intact for the disposable
    # profile instead of weakening its containment check or making the base
    # equal to the state directory.
    $env:RUNNER_TEMP = Split-Path -Parent $state
    Remove-Item Env:DC_WINDOWS_NATIVE_BASE_ROOT -ErrorAction SilentlyContinue
    $nativeHarness = Join-Path $PSScriptRoot 'windows-native-ci.ps1'
    if ($CleanupOnly) {
        & $nativeHarness -Operation cleanup -StateRoot $state
        Write-ChildResult $result $true 'disposable standard-user fallback cleanup passed'
        return
    }
    $failure = $null
    try {
        if ($Mode -eq 'setup-acceptance') {
            & $nativeHarness -Operation setup-acceptance `
                -WorkspaceRoot (Split-Path -Parent $PSScriptRoot) `
                -StateRoot $state -ArtifactRoot $artifacts `
                -AllowCurrentUserSetupAcceptance
        } else {
            $setup = Join-Path $artifacts 'DefenseClawSetup-x64.exe'
            & (Join-Path $PSScriptRoot 'test-windows-setup-wizard.ps1') `
                -SetupPath $setup -StateRoot (Join-Path $state 'wizard-smoke')
        }
    } catch {
        $failure = $_
        if (-not [string]::IsNullOrWhiteSpace($DiagnosticsRoot)) {
            try {
                & $nativeHarness -Operation capture -StateRoot $state `
                    -DiagnosticsRoot ([IO.Path]::GetFullPath($DiagnosticsRoot))
            } catch {
                $failure = [Management.Automation.ErrorRecord]::new(
                    [InvalidOperationException]::new(
                        "$($failure.Exception.Message); diagnostic capture failed: $($_.Exception.Message)",
                        $failure.Exception
                    ),
                    'DisposableUserDiagnosticCaptureFailed',
                    [Management.Automation.ErrorCategory]::OperationStopped,
                    $state
                )
            }
        }
    } finally {
        try {
            & $nativeHarness -Operation cleanup -StateRoot $state
        } catch {
            if ($null -eq $failure) {
                $failure = $_
            } else {
                $failure = [Management.Automation.ErrorRecord]::new(
                    [InvalidOperationException]::new(
                        "$($failure.Exception.Message); child cleanup failed: $($_.Exception.Message)",
                        $failure.Exception
                    ),
                    'DisposableUserCleanupFailed',
                    [Management.Automation.ErrorCategory]::OperationStopped,
                    $state
                )
            }
        }
    }

    if ($null -ne $failure) {
        Write-ChildResult $result $false ($failure | Out-String)
        throw $failure
    }
    Write-ChildResult $result $true "$Mode passed under a disposable standard user"
}

if ($Child) {
    try {
        Invoke-ChildMode
        exit 0
    } catch {
        try { Write-ChildResult ([IO.Path]::GetFullPath($ResultPath)) $false ($_ | Out-String) }
        catch { Write-Error "Could not write disposable-user result: $($_.Exception.Message)" }
        Write-Error $_
        exit 1
    }
}

function New-RandomSecurePassword {
    $password = [Security.SecureString]::new()
    foreach ($character in @('D', 'c', '7', '!')) { $password.AppendChar($character) }
    $alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%*-_'
    $random = [byte[]]::new(28)
    [Security.Cryptography.RandomNumberGenerator]::Fill($random)
    foreach ($value in $random) {
        $password.AppendChar($alphabet[$value % $alphabet.Length])
    }
    [Array]::Clear($random, 0, $random.Length)
    $password.MakeReadOnly()
    return $password
}

function Set-PrivateSandboxAcl([string]$Path, [Security.Principal.SecurityIdentifier]$ChildSid) {
    $directory = [IO.Directory]::CreateDirectory($Path)
    $parentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    if ($null -eq $parentSid) { throw 'runner identity has no user SID' }
    $systemSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $security = [Security.AccessControl.DirectorySecurity]::new()
    $security.SetOwner($parentSid)
    $security.SetAccessRuleProtection($true, $false)
    $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [Security.AccessControl.InheritanceFlags]::ObjectInherit
    foreach ($sid in @($parentSid, $systemSid, $ChildSid)) {
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $sid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow
        )
        [void]$security.AddAccessRule($rule)
    }
    [IO.FileSystemAclExtensions]::SetAccessControl($directory, $security)
}

function Set-ReadOnlyPayloadAcl([string]$Path, [Security.Principal.SecurityIdentifier]$ChildSid) {
    $directory = [IO.Directory]::CreateDirectory($Path)
    $parentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    if ($null -eq $parentSid) { throw 'runner identity has no user SID' }
    $systemSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $security = [Security.AccessControl.DirectorySecurity]::new()
    $security.SetOwner($parentSid)
    $security.SetAccessRuleProtection($true, $false)
    $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [Security.AccessControl.InheritanceFlags]::ObjectInherit
    foreach ($sid in @($parentSid, $systemSid)) {
        [void]$security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $sid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow
        ))
    }
    [void]$security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $ChildSid,
        [Security.AccessControl.FileSystemRights]::ReadAndExecute,
        $inheritance,
        [Security.AccessControl.PropagationFlags]::None,
        [Security.AccessControl.AccessControlType]::Allow
    ))
    [IO.FileSystemAclExtensions]::SetAccessControl($directory, $security)
}

function Remove-DisposableProfileAndAccount([string]$Name, [string]$Sid) {
    if (-not [string]::IsNullOrWhiteSpace($Name)) {
        $existing = Get-LocalUser -Name $Name -ErrorAction SilentlyContinue
        if ($null -ne $existing) { Remove-LocalUser -Name $Name -ErrorAction Stop }
    }
    if ([string]::IsNullOrWhiteSpace($Sid)) { return }

    $escapedSid = $Sid.Replace("'", "''")
    for ($attempt = 0; $attempt -lt 40; $attempt++) {
        $profiles = @(Get-CimInstance Win32_UserProfile -Filter "SID = '$escapedSid'" -ErrorAction Stop)
        if ($profiles.Count -eq 0) { return }
        $loaded = @($profiles | Where-Object { $_.Loaded })
        if ($loaded.Count -eq 0) {
            foreach ($profile in $profiles) { Remove-CimInstance -InputObject $profile -ErrorAction Stop }
        }
        Start-Sleep -Milliseconds 250
    }
    $remaining = @(Get-CimInstance Win32_UserProfile -Filter "SID = '$escapedSid'" -ErrorAction Stop)
    if ($remaining.Count -ne 0) {
        throw "disposable standard-user profile remained after cleanup: $Sid"
    }
}

if (-not $IsWindows) { throw 'disposable Setup acceptance requires native Windows' }
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
    throw 'disposable Setup acceptance is restricted to GitHub-hosted Windows CI'
}
if (-not (Test-IsAdministrator)) {
    throw 'disposable Setup acceptance account provisioning requires the hosted runner administrator'
}

$stateBase = [IO.Path]::GetFullPath($StateRoot).TrimEnd('\')
$artifactSource = [IO.Path]::GetFullPath($ArtifactRoot).TrimEnd('\')
$approvedStateBases = @(
    [Environment]::GetEnvironmentVariable('RUNNER_TEMP'),
    (Resolve-SafeWindowsNativeBase (
        [Environment]::GetEnvironmentVariable('DC_WINDOWS_NATIVE_BASE_ROOT')
    ))
) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
if (-not ($approvedStateBases | Where-Object {
    Test-PathWithin $stateBase ([IO.Path]::GetFullPath($_))
} | Select-Object -First 1)) {
    throw 'disposable Setup acceptance StateRoot must be below RUNNER_TEMP or DC_WINDOWS_NATIVE_BASE_ROOT'
}
$setupSource = Join-Path $artifactSource 'DefenseClawSetup-x64.exe'
if (-not (Test-Path -LiteralPath $setupSource -PathType Leaf)) {
    throw "native setup executable not found: $setupSource"
}
[IO.Directory]::CreateDirectory($stateBase) | Out-Null

$launcherSource = Join-Path $PSScriptRoot 'windows-disposable-standard-user-launcher.cs'
if (-not ('DefenseClaw.DisposableStandardUserLauncher' -as [type])) {
    Add-Type -Path $launcherSource
}

$accountName = 'dcacc' + ([guid]::NewGuid().ToString('N').Substring(0, 10))
$password = New-RandomSecurePassword
$accountSid = ''
$accountCreated = $false
$sandbox = ''
$desktopGrant = $null
$childProcess = $null
$workspace = ''
$scripts = ''
$childArtifacts = ''
$childState = ''
$primaryFailure = $null
$cleanupFailures = [Collections.Generic.List[string]]::new()
try {
    $account = New-LocalUser -Name $accountName -Password $password `
        -AccountNeverExpires -Description 'DefenseClaw disposable Setup CI account'
    $accountCreated = $true
    $accountSid = $account.SID.Value
    $sidObject = [Security.Principal.SecurityIdentifier]::new($accountSid)

    $administratorsSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $administratorMembers = @(Get-LocalGroupMember -SID $administratorsSid -ErrorAction Stop)
    if (@($administratorMembers | Where-Object { $_.SID -eq $sidObject }).Count -ne 0) {
        throw 'disposable Setup CI account unexpectedly belongs to Administrators'
    }
    $usersSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
    $userMembers = @(Get-LocalGroupMember -SID $usersSid -ErrorAction Stop)
    if (@($userMembers | Where-Object { $_.SID -eq $sidObject }).Count -eq 0) {
        Add-LocalGroupMember -SID $usersSid -Member $accountName -ErrorAction Stop
    }

    $sandbox = Join-Path $stateBase ('disposable-user-' + [guid]::NewGuid().ToString('N'))
    Set-PrivateSandboxAcl $sandbox $sidObject
    $workspace = Join-Path $sandbox 'workspace'
    $scripts = Join-Path $workspace 'scripts'
    $childArtifacts = Join-Path $sandbox 'artifacts'
    $childState = Join-Path $sandbox 'state'
    $childDiagnostics = Join-Path $sandbox 'diagnostics'
    foreach ($directory in @($scripts, $childArtifacts, $childState, $childDiagnostics)) {
        [IO.Directory]::CreateDirectory($directory) | Out-Null
    }
    # The product under test may write only to its isolated state/profile.
    # Keep both the exact Setup input and the harness that evaluates it
    # immutable to the disposable child, while retaining parent/SYSTEM cleanup
    # authority.
    Set-ReadOnlyPayloadAcl $childArtifacts $sidObject
    Set-ReadOnlyPayloadAcl $workspace $sidObject
    foreach ($file in @(
        'invoke-windows-setup-standard-user-ci.ps1',
        'windows-native-ci.ps1',
        'windows-native-paths.ps1',
        'windows-setup-standard-user-launcher.cs',
        'test-windows-setup-wizard.ps1'
    )) {
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot $file) `
            -Destination (Join-Path $scripts $file) -Force
    }
    Set-ReadOnlyPayloadAcl $scripts $sidObject
    $childSetup = Join-Path $childArtifacts 'DefenseClawSetup-x64.exe'
    Copy-Item -LiteralPath $setupSource -Destination $childSetup -Force
    if ((Get-FileHash -LiteralPath $childSetup -Algorithm SHA256).Hash -ne
        (Get-FileHash -LiteralPath $setupSource -Algorithm SHA256).Hash) {
        throw 'disposable-user Setup copy does not match the exact input artifact'
    }

    $result = Join-Path $sandbox 'result.json'
    $desktopGrant = [DefenseClaw.DisposableStandardUserLauncher]::GrantInteractiveDesktop($accountSid)
    $pwsh = Join-Path $PSHOME 'pwsh.exe'
    $arguments = @(
        '-NoLogo', '-NoProfile', '-File',
        (Join-Path $scripts 'invoke-windows-setup-standard-user-ci.ps1'),
        '-Child', '-Mode', $Mode,
        '-ArtifactRoot', $childArtifacts,
        '-StateRoot', $childState,
        '-DiagnosticsRoot', $childDiagnostics,
        '-ResultPath', $result
    )
    $childProcess = [DefenseClaw.DisposableStandardUserLauncher]::Start(
        $accountName,
        $env:COMPUTERNAME,
        $password,
        $pwsh,
        [string[]]$arguments,
        $workspace,
        $accountSid
    )
    if (-not $childProcess.WaitForExit($TimeoutSeconds * 1000)) {
        $childProcess.Terminate()
        throw "disposable standard-user $Mode timed out after $TimeoutSeconds seconds"
    }
    $exitCode = $childProcess.ExitCode
    if (-not (Test-Path -LiteralPath $result -PathType Leaf)) {
        throw "disposable standard-user $Mode did not emit its result (exit $exitCode)"
    }
    $observed = Get-Content -LiteralPath $result -Raw -Encoding UTF8 | ConvertFrom-Json
    if ([string]$observed.user_sid -ne $accountSid -or [bool]$observed.elevated) {
        throw 'disposable standard-user child result reported the wrong identity or elevation'
    }
    if ($exitCode -ne 0 -or -not [bool]$observed.succeeded) {
        throw "disposable standard-user $Mode failed (exit $exitCode): $($observed.detail)"
    }
    Write-Host ($observed | ConvertTo-Json -Compress -Depth 4)
} catch {
    $primaryFailure = $_
} finally {
    if (-not [string]::IsNullOrWhiteSpace($DiagnosticsRoot) -and
        -not [string]::IsNullOrWhiteSpace($sandbox)) {
        try {
            $sourceDiagnostics = Join-Path $sandbox 'diagnostics'
            if (Test-Path -LiteralPath $sourceDiagnostics -PathType Container) {
                [IO.Directory]::CreateDirectory([IO.Path]::GetFullPath($DiagnosticsRoot)) | Out-Null
                foreach ($entry in @(Get-ChildItem -LiteralPath $sourceDiagnostics -Force)) {
                    Copy-Item -LiteralPath $entry.FullName `
                        -Destination ([IO.Path]::GetFullPath($DiagnosticsRoot)) `
                        -Recurse -Force -ErrorAction Stop
                }
            }
        } catch { $cleanupFailures.Add("diagnostic handoff: $($_.Exception.Message)") }
    }
    if ($null -ne $childProcess) {
        try { $childProcess.Dispose() }
        catch { $cleanupFailures.Add("process job cleanup: $($_.Exception.Message)") }
    }
    if ($accountCreated -and $null -ne $desktopGrant -and
        -not [string]::IsNullOrWhiteSpace($childState) -and
        (Test-Path -LiteralPath $childState)) {
        $cleanupProcess = $null
        try {
            $cleanupResult = Join-Path $sandbox 'cleanup-result.json'
            $cleanupArguments = @(
                '-NoLogo', '-NoProfile', '-File',
                (Join-Path $scripts 'invoke-windows-setup-standard-user-ci.ps1'),
                '-Child', '-CleanupOnly', '-Mode', $Mode,
                '-ArtifactRoot', $childArtifacts,
                '-StateRoot', $childState,
                '-ResultPath', $cleanupResult
            )
            $cleanupProcess = [DefenseClaw.DisposableStandardUserLauncher]::Start(
                $accountName,
                $env:COMPUTERNAME,
                $password,
                (Join-Path $PSHOME 'pwsh.exe'),
                [string[]]$cleanupArguments,
                $workspace,
                $accountSid
            )
            if (-not $cleanupProcess.WaitForExit(120000) -or $cleanupProcess.ExitCode -ne 0) {
                throw 'disposable standard-user fallback cleanup process failed'
            }
        } catch { $cleanupFailures.Add("standard-user fallback cleanup: $($_.Exception.Message)") }
        finally {
            if ($null -ne $cleanupProcess) {
                try { $cleanupProcess.Dispose() }
                catch { $cleanupFailures.Add("fallback cleanup job disposal: $($_.Exception.Message)") }
            }
        }
    }
    if ($null -ne $desktopGrant) {
        try { $desktopGrant.Restore() }
        catch { $cleanupFailures.Add("interactive desktop ACL restore: $($_.Exception.Message)") }
    }
    if ($accountCreated) {
        try { Remove-DisposableProfileAndAccount $accountName $accountSid }
        catch { $cleanupFailures.Add("account/profile cleanup: $($_.Exception.Message)") }
    }
    $password.Dispose()
    if (-not [string]::IsNullOrWhiteSpace($sandbox) -and
        (Test-Path -LiteralPath $sandbox)) {
        try {
            $resolvedSandbox = [IO.Path]::GetFullPath($sandbox).TrimEnd('\')
            if (-not (Test-PathWithin $resolvedSandbox $stateBase) -or
                -not (Split-Path -Leaf $resolvedSandbox).StartsWith(
                    'disposable-user-', [StringComparison]::Ordinal
                )) {
                throw "refusing to remove unexpected disposable-user sandbox: $resolvedSandbox"
            }
            Remove-Item -LiteralPath $resolvedSandbox -Recurse -Force
        } catch { $cleanupFailures.Add("sandbox cleanup: $($_.Exception.Message)") }
    }
}

if ($null -ne $primaryFailure -or $cleanupFailures.Count -ne 0) {
    $parts = [Collections.Generic.List[string]]::new()
    if ($null -ne $primaryFailure) { $parts.Add($primaryFailure.Exception.Message) }
    foreach ($failure in $cleanupFailures) { $parts.Add($failure) }
    throw ($parts -join '; ')
}
