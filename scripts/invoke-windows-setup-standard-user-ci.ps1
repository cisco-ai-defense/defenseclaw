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
    [switch]$ExerciseWmiEscape,
    [string]$ExpectedSetupSha256 = '',
    [string]$ResultPath = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'windows-native-paths.ps1')
. (Join-Path $PSScriptRoot 'windows-disposable-user-safety.ps1')

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

function Test-ActualChildFilesystemBoundary {
    param(
        [string]$SandboxRoot,
        [string]$Workspace,
        [string]$Scripts,
        [string]$Artifacts,
        [string]$State,
        [string]$Results,
        [string]$ExpectedHash
    )

    if ($ExpectedHash -notmatch '^[0-9A-Fa-f]{64}$') {
        throw 'parent did not supply the exact expected Setup SHA-256'
    }
    foreach ($path in @($Workspace, $Scripts, $Artifacts, $State, $Results)) {
        if (-not (Test-PathWithin $path $SandboxRoot)) {
            throw "actual child probe path escaped the private sandbox: $path"
        }
    }
    $setup = Join-Path $Artifacts 'DefenseClawSetup-x64.exe'
    Assert-ChildOperationAccessDenied 'Setup overwrite probe' {
        $stream = [IO.File]::Open(
            $setup, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::None
        )
        $stream.Dispose()
    }
    Assert-ChildOperationAccessDenied 'Setup delete probe' {
        [IO.File]::Delete($setup)
    }

    foreach ($immutable in @($Workspace, $Scripts, $Artifacts)) {
        $leaf = Split-Path -Leaf $immutable
        Assert-ChildOperationAccessDenied "$leaf rename probe" {
            [IO.Directory]::Move($immutable, "$immutable.dc-immutability-moved")
        }
        Assert-ChildOperationAccessDenied "$leaf delete probe" {
            [IO.Directory]::Delete($immutable, $true)
        }
        Assert-ChildOperationAccessDenied "$leaf replacement probe" {
            [IO.File]::WriteAllText(
                (Join-Path $immutable 'dc-immutability-replacement.tmp'),
                'replace'
            )
        }
    }

    foreach ($writable in @($State, $Results)) {
        $probe = Join-Path $writable ('dc-writable-' + [guid]::NewGuid().ToString('N') + '.tmp')
        [IO.File]::WriteAllText($probe, 'writable')
        if ([IO.File]::ReadAllText($probe) -cne 'writable') {
            throw "actual child could not round-trip its writable root: $writable"
        }
        [IO.File]::Delete($probe)
    }

    foreach ($immutable in @($Workspace, $Scripts, $Artifacts)) {
        if (-not (Test-Path -LiteralPath $immutable -PathType Container) -or
            (Test-Path -LiteralPath "$immutable.dc-immutability-moved") -or
            (Test-Path -LiteralPath (
                Join-Path $immutable 'dc-immutability-replacement.tmp'
            ))) {
            throw "actual child immutability probe changed a protected path: $immutable"
        }
    }
    if (-not (Test-Path -LiteralPath (
            Join-Path $Scripts 'invoke-windows-setup-standard-user-ci.ps1'
        ) -PathType Leaf)) {
        throw 'actual child immutability probe removed the protected harness script'
    }
    $observedHash = [DefenseClaw.DisposableFileGuard]::ComputeSha256Hex(
        $setup,
        1073741824
    )
    if ($observedHash -cne $ExpectedHash.ToUpperInvariant()) {
        throw 'actual child immutability probe changed the exact Setup bytes'
    }
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
    $expectedDiagnostics = Join-Path $sandboxRoot 'diagnostics'
    $expectedResults = Join-Path $sandboxRoot 'results'
    $allowedResults = @((Join-Path $expectedResults 'result.json'))
    if (-not $PSScriptRoot.Equals(
            [IO.Path]::GetFullPath($expectedScripts),
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        -not $artifacts.Equals(
            [IO.Path]::GetFullPath($expectedArtifacts),
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        (-not [string]::IsNullOrWhiteSpace($DiagnosticsRoot) -and
            -not ([IO.Path]::GetFullPath($DiagnosticsRoot)).Equals(
                [IO.Path]::GetFullPath($expectedDiagnostics),
                [StringComparison]::OrdinalIgnoreCase
            )) -or
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

    $originalChildDirectory = [Environment]::CurrentDirectory
    try {
        [Environment]::CurrentDirectory = $state
        Test-ActualChildFilesystemBoundary $sandboxRoot `
            (Split-Path -Parent $PSScriptRoot) $PSScriptRoot $artifacts $state `
            $expectedResults $ExpectedSetupSha256
    } finally {
        [Environment]::CurrentDirectory = $originalChildDirectory
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
    if ($ExerciseWmiEscape) {
        # Win32_Process.Create is serviced outside the launcher's job object.
        # The harmless sleeper proves that the parent account-SID sweep catches
        # a process that intentionally escaped the kill-on-close job.
        $pwsh = Join-Path $PSHOME 'pwsh.exe'
        $commandLine = [DefenseClaw.SetupStandardUserLauncher]::QuoteWindowsArgument($pwsh) +
            ' -NoLogo -NoProfile -NonInteractive -Command ' +
            [DefenseClaw.SetupStandardUserLauncher]::QuoteWindowsArgument(
                'Start-Sleep -Seconds 14400'
            )
        $created = Invoke-CimMethod -ClassName Win32_Process -MethodName Create `
            -Arguments @{ CommandLine = $commandLine; CurrentDirectory = $expectedResults } `
            -ErrorAction Stop
        if ([uint32]$created.ReturnValue -ne 0 -or [uint32]$created.ProcessId -eq 0) {
            throw "WMI escape fixture creation failed: $($created.ReturnValue)"
        }
        [IO.File]::WriteAllText(
            (Join-Path $expectedResults 'wmi-escape-pid.txt'),
            ([string][uint32]$created.ProcessId),
            [Text.UTF8Encoding]::new($false)
        )
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

function Get-SameLiveProcess([object]$Process) {
    $current = @(Get-CimInstance Win32_Process `
        -Filter "ProcessId = $([int]$Process.ProcessId)" -ErrorAction Stop)
    if ($current.Count -ne 1) { return $null }
    if ((Get-DisposableProcessIdentityKey $current[0]) -cne
        (Get-DisposableProcessIdentityKey $Process)) {
        return $null
    }
    return $current[0]
}

function Get-UnverifiableProcessBaseline {
    $baseline = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal
    )
    foreach ($process in @(Get-CimInstance Win32_Process -ErrorAction Stop)) {
        $unverifiable = $false
        try {
            $owner = Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid `
                -ErrorAction Stop
            $unverifiable = [uint32]$owner.ReturnValue -ne 0
        } catch { $unverifiable = $true }
        if (-not $unverifiable) { continue }
        $live = Get-SameLiveProcess $process
        if ($null -ne $live) {
            [void]$baseline.Add((Get-DisposableProcessIdentityKey $live))
        }
    }
    return ,$baseline
}

function Get-DisposableSidProcesses(
    [string]$Sid,
    [Collections.Generic.HashSet[string]]$UnverifiableBaseline
) {
    if ([string]::IsNullOrWhiteSpace($Sid)) { return @() }
    $matches = [Collections.Generic.List[object]]::new()
    foreach ($process in @(Get-CimInstance Win32_Process -ErrorAction Stop)) {
        $owner = $null
        try {
            $owner = Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid `
                -ErrorAction Stop
        } catch {
            $live = Get-SameLiveProcess $process
            if ($null -ne $live) {
                Assert-UnverifiableProcessWasBaselined $live $UnverifiableBaseline
            }
            continue
        }
        if ([uint32]$owner.ReturnValue -ne 0) {
            $live = Get-SameLiveProcess $process
            if ($null -ne $live) {
                Assert-UnverifiableProcessWasBaselined $live $UnverifiableBaseline
            }
            continue
        }
        if ([string]$owner.Sid -ceq $Sid) {
            $matches.Add($process)
        }
    }
    return @($matches)
}

function Stop-AndVerifyDisposableSidProcesses(
    [string]$Sid,
    [Collections.Generic.HashSet[string]]$UnverifiableBaseline
) {
    $terminated = [Collections.Generic.HashSet[int]]::new()
    for ($attempt = 0; $attempt -lt 40; $attempt++) {
        $owned = @(Get-DisposableSidProcesses $Sid $UnverifiableBaseline)
        if ($owned.Count -eq 0) { return @($terminated) }
        foreach ($process in $owned) {
            $current = @(Get-CimInstance Win32_Process `
                -Filter "ProcessId = $([int]$process.ProcessId)" -ErrorAction Stop)
            if ($current.Count -ne 1 -or
                (Get-DisposableProcessIdentityKey $current[0]) -cne
                    (Get-DisposableProcessIdentityKey $process)) {
                continue
            }
            $owner = Invoke-CimMethod -InputObject $current[0] -MethodName GetOwnerSid `
                -ErrorAction Stop
            if ([uint32]$owner.ReturnValue -ne 0) {
                throw "owner SID became unverifiable for exact-SID process $($process.ProcessId)"
            }
            if ([string]$owner.Sid -cne $Sid) {
                throw "owner SID changed for exact-SID process $($process.ProcessId)"
            }
            $termination = Invoke-CimMethod -InputObject $current[0] -MethodName Terminate `
                -Arguments @{ Reason = [uint32]1603 } -ErrorAction Stop
            if ([uint32]$termination.ReturnValue -ne 0) {
                throw "could not terminate disposable-SID process $($process.ProcessId): $($termination.ReturnValue)"
            }
            [void]$terminated.Add([int]$process.ProcessId)
        }
        Start-Sleep -Milliseconds 250
    }
    $remaining = @(Get-DisposableSidProcesses $Sid $UnverifiableBaseline)
    if ($remaining.Count -ne 0) {
        throw "disposable account still owns live processes: $($remaining.ProcessId -join ', ')"
    }
    return @($terminated)
}

function Test-DisposableTaskPrincipal {
    param(
        [AllowNull()][string]$Principal,
        [string]$AccountName,
        [string]$Sid
    )
    if ([string]::IsNullOrWhiteSpace($Principal)) { return $false }
    $candidate = $Principal.Trim()
    if ($candidate.Equals($Sid, [StringComparison]::OrdinalIgnoreCase) -or
        $candidate.Equals($AccountName, [StringComparison]::OrdinalIgnoreCase) -or
        $candidate.Equals(".\$AccountName", [StringComparison]::OrdinalIgnoreCase) -or
        $candidate.Equals("$env:COMPUTERNAME\$AccountName", [StringComparison]::OrdinalIgnoreCase)) {
        return $true
    }
    try {
        $resolved = [Security.Principal.NTAccount]::new($candidate).Translate(
            [Security.Principal.SecurityIdentifier]
        )
        return $resolved.Value -ceq $Sid
    } catch { return $false }
}

function Remove-AndVerifyDisposableScheduledTasks([string]$AccountName, [string]$Sid) {
    $owned = @(Get-ScheduledTask -ErrorAction Stop | Where-Object {
        Test-DisposableTaskPrincipal ([string]$_.Principal.UserId) $AccountName $Sid
    })
    foreach ($task in $owned) {
        Unregister-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath `
            -Confirm:$false -ErrorAction Stop
    }
    $remaining = @(Get-ScheduledTask -ErrorAction Stop | Where-Object {
        Test-DisposableTaskPrincipal ([string]$_.Principal.UserId) $AccountName $Sid
    })
    if ($remaining.Count -ne 0) {
        throw "scheduled tasks remain for the disposable account: $($remaining.TaskPath + $remaining.TaskName -join ', ')"
    }
}

function Complete-DisposableExecutionBoundary {
    param(
        [AllowNull()][object]$Process,
        [string]$AccountName,
        [string]$Sid,
        [Collections.Generic.HashSet[string]]$UnverifiableBaseline
    )

    $failures = [Collections.Generic.List[string]]::new()
    $jobDrained = $null -eq $Process
    $initialJobFailure = ''
    if ($null -ne $Process) {
        try {
            $Process.TerminateAndDrain(30000)
            $jobDrained = [uint32]$Process.ActiveProcessCount -eq 0
            if (-not $jobDrained) {
                throw 'disposable process job did not drain to ActiveProcesses=0'
            }
        } catch { $initialJobFailure = $_.Exception.Message }
    }
    try {
        $account = Get-LocalUser -Name $AccountName -ErrorAction Stop
        if ($account.SID.Value -cne $Sid) {
            throw 'disposable account SID changed before shutdown'
        }
        Disable-LocalUser -Name $AccountName -ErrorAction Stop
    } catch { $failures.Add("account disable: $($_.Exception.Message)") }

    $terminated = @()
    try {
        $terminated = @(Stop-AndVerifyDisposableSidProcesses $Sid $UnverifiableBaseline)
    }
    catch { $failures.Add("exact-SID process termination: $($_.Exception.Message)") }
    try { Remove-AndVerifyDisposableScheduledTasks $AccountName $Sid }
    catch { $failures.Add("scheduled-task removal: $($_.Exception.Message)") }
    try {
        $late = @(Stop-AndVerifyDisposableSidProcesses $Sid $UnverifiableBaseline)
        foreach ($pidValue in $late) { $terminated += [int]$pidValue }
        if (@(Get-DisposableSidProcesses $Sid $UnverifiableBaseline).Count -ne 0) {
            throw 'disposable SID process verification was not stable after shutdown'
        }
    } catch { $failures.Add("late exact-SID verification: $($_.Exception.Message)") }

    if ($null -ne $Process -and -not $jobDrained) {
        try {
            $Process.TerminateAndDrain(30000)
            $jobDrained = [uint32]$Process.ActiveProcessCount -eq 0
            if (-not $jobDrained) {
                throw 'disposable process job still reports active processes after SID sweep'
            }
        } catch {
            $failures.Add(
                "job termination/drain failed twice: $initialJobFailure; $($_.Exception.Message)"
            )
        }
    }
    if ($null -ne $Process -and $jobDrained) {
        try { $Process.Dispose() }
        catch { $failures.Add("job handle disposal: $($_.Exception.Message)") }
    }
    if ($failures.Count -ne 0) {
        throw ($failures -join '; ')
    }
    return @($terminated | Sort-Object -Unique)
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
$stateBoundary = @($approvedStateBases | Where-Object {
    Test-PathWithin $stateBase ([IO.Path]::GetFullPath($_))
} | Select-Object -First 1)[0]
$null = Assert-DisposableNoReparseAncestors -Path $stateBase `
    -AllowedRoot ([IO.Path]::GetFullPath($stateBoundary))
$setupSource = Join-Path $artifactSource 'DefenseClawSetup-x64.exe'
if (-not (Test-Path -LiteralPath $setupSource -PathType Leaf)) {
    throw "native setup executable not found: $setupSource"
}
$null = Assert-DisposableNoReparseAncestors -Path $setupSource `
    -AllowedRoot $artifactSource -RequireExists
$setupSourceItem = Get-Item -LiteralPath $setupSource -Force -ErrorAction Stop
if ($setupSourceItem.Attributes -band [IO.FileAttributes]::ReparsePoint) {
    throw 'native setup input must be a regular file, not a reparse point'
}
$expectedSetupHash = [DefenseClaw.DisposableFileGuard]::ComputeSha256Hex(
    $setupSource,
    1073741824
)
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
$childDiagnostics = ''
$childResults = ''
$childSetup = ''
$result = ''
$wmiFixtureRecord = ''
$primaryFailure = $null
$cleanupFailures = [Collections.Generic.List[string]]::new()
$executionBoundaryComplete = $false
$terminatedSidProcessIds = @()
$unverifiableProcessBaseline = Get-UnverifiableProcessBaseline
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
    Set-DisposableProtectedDirectoryAcl $sandbox $sidObject `
        ([Security.AccessControl.FileSystemRights]::ReadAndExecute)
    $workspace = Join-Path $sandbox 'workspace'
    $scripts = Join-Path $workspace 'scripts'
    $childArtifacts = Join-Path $sandbox 'artifacts'
    $childState = Join-Path $sandbox 'state'
    $childDiagnostics = Join-Path $sandbox 'diagnostics'
    $childResults = Join-Path $sandbox 'results'
    foreach ($directory in @(
        $scripts, $childArtifacts, $childState, $childDiagnostics, $childResults
    )) {
        [IO.Directory]::CreateDirectory($directory) | Out-Null
    }
    # The product under test may write only to its isolated state/profile.
    # Keep both the exact Setup input and the harness that evaluates it
    # immutable to the disposable child, while retaining parent/SYSTEM cleanup
    # authority.
    foreach ($file in @(
        'invoke-windows-setup-standard-user-ci.ps1',
        'windows-native-ci.ps1',
        'windows-native-paths.ps1',
        'windows-disposable-file-guard.cs',
        'windows-disposable-user-safety.ps1',
        'windows-setup-standard-user-launcher.cs',
        'test-windows-setup-wizard.ps1'
    )) {
        $source = Join-Path $PSScriptRoot $file
        $destination = Join-Path $scripts $file
        $null = Assert-DisposableNoReparseAncestors -Path $source `
            -AllowedRoot $PSScriptRoot -RequireExists
        [IO.File]::Copy($source, $destination, $false)
    }
    $childSetup = Join-Path $childArtifacts 'DefenseClawSetup-x64.exe'
    [IO.File]::Copy($setupSource, $childSetup, $false)
    if ([DefenseClaw.DisposableFileGuard]::ComputeSha256Hex(
            $childSetup,
            1073741824
        ) -cne
        $expectedSetupHash) {
        throw 'disposable-user Setup copy does not match the exact input artifact'
    }

    Set-DisposableProtectedDirectoryAcl $workspace $sidObject `
        ([Security.AccessControl.FileSystemRights]::ReadAndExecute) -InheritChildRights
    Set-DisposableProtectedDirectoryAcl $scripts $sidObject `
        ([Security.AccessControl.FileSystemRights]::ReadAndExecute) -InheritChildRights
    Set-DisposableProtectedDirectoryAcl $childArtifacts $sidObject `
        ([Security.AccessControl.FileSystemRights]::ReadAndExecute) -InheritChildRights
    foreach ($directory in @($childState, $childDiagnostics, $childResults)) {
        Set-DisposableProtectedDirectoryAcl $directory $sidObject `
            ([Security.AccessControl.FileSystemRights]::Modify) -InheritChildRights
    }
    Assert-DisposableChildAcl $sandbox $sidObject `
        ([Security.AccessControl.FileSystemRights]::ReadAndExecute)
    foreach ($directory in @($workspace, $scripts, $childArtifacts)) {
        Assert-DisposableChildAcl $directory $sidObject `
            ([Security.AccessControl.FileSystemRights]::ReadAndExecute) -ExpectInheritance
    }
    foreach ($directory in @($childState, $childDiagnostics, $childResults)) {
        Assert-DisposableChildAcl $directory $sidObject `
            ([Security.AccessControl.FileSystemRights]::Modify) -ExpectInheritance
    }

    $result = Join-Path $childResults 'result.json'
    $wmiFixtureRecord = Join-Path $childResults 'wmi-escape-pid.txt'
    $desktopGrant = [DefenseClaw.DisposableStandardUserLauncher]::GrantInteractiveDesktop($accountSid)
    $pwsh = Join-Path $PSHOME 'pwsh.exe'
    $arguments = @(
        '-NoLogo', '-NoProfile', '-File',
        (Join-Path $scripts 'invoke-windows-setup-standard-user-ci.ps1'),
        '-Child', '-Mode', $Mode,
        '-ArtifactRoot', $childArtifacts,
        '-StateRoot', $childState,
        '-DiagnosticsRoot', $childDiagnostics,
        '-ResultPath', $result,
        '-ExerciseWmiEscape',
        '-ExpectedSetupSha256', $expectedSetupHash
    )
    # Refresh immediately before the untrusted logon. Only exact PID and
    # CreationDate pairs that are already unverifiable at this point may remain
    # unverifiable during teardown; PID reuse and every new unknown fail closed.
    $unverifiableProcessBaseline = Get-UnverifiableProcessBaseline
    $childProcess = [DefenseClaw.DisposableStandardUserLauncher]::Start(
        $accountName,
        $env:COMPUTERNAME,
        $password,
        $pwsh,
        [string[]]$arguments,
        $workspace,
        $accountSid
    )
    $timedOut = -not $childProcess.WaitForExit($TimeoutSeconds * 1000)
    $exitCode = if ($timedOut) { 124 } else { $childProcess.ExitCode }

    # No elevated file enumeration, hash, result read, diagnostics copy, or
    # profile cleanup is permitted until both containment layers are closed:
    # the job reports ActiveProcesses=0, then the disabled account has no
    # remaining process or scheduled-task identity anywhere on the host.
    $terminatedSidProcessIds = @(Complete-DisposableExecutionBoundary `
        $childProcess $accountName $accountSid $unverifiableProcessBaseline)
    $executionBoundaryComplete = $true
    if ($timedOut) {
        throw "disposable standard-user $Mode timed out after $TimeoutSeconds seconds"
    }

    $null = Assert-DisposableNoReparseAncestors -Path $setupSource `
        -AllowedRoot $artifactSource -RequireExists
    $null = Assert-DisposableNoReparseAncestors -Path $childSetup `
        -AllowedRoot $sandbox -RequireExists
    $sourceHashAfter = [DefenseClaw.DisposableFileGuard]::ComputeSha256Hex(
        $setupSource,
        1073741824
    )
    $childHashAfter = [DefenseClaw.DisposableFileGuard]::ComputeSha256Hex(
        $childSetup,
        1073741824
    )
    if ($sourceHashAfter -cne $expectedSetupHash -or
        $childHashAfter -cne $expectedSetupHash) {
        throw 'exact Setup artifact hash changed during disposable-user lifecycle acceptance'
    }
    $fixturePidText = Read-BoundedDisposableResult $wmiFixtureRecord $childResults 4096
    $fixturePid = 0
    if (-not [int]::TryParse($fixturePidText.Trim(), [ref]$fixturePid) -or
        $fixturePid -le 0 -or $fixturePid -notin $terminatedSidProcessIds) {
        throw 'WMI escape fixture was not terminated by the exact disposable-SID process sweep'
    }
    $observed = (Read-BoundedDisposableResult $result $childResults) | ConvertFrom-Json
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
    if ($accountCreated -and -not $executionBoundaryComplete) {
        try {
            $terminatedSidProcessIds = @(Complete-DisposableExecutionBoundary `
                $childProcess $accountName $accountSid $unverifiableProcessBaseline)
            $executionBoundaryComplete = $true
        } catch {
            $cleanupFailures.Add("disposable execution boundary: $($_.Exception.Message)")
        }
    }
    if ($null -ne $desktopGrant) {
        try { $desktopGrant.Restore() }
        catch { $cleanupFailures.Add("interactive desktop ACL restore: $($_.Exception.Message)") }
    }
    if ($executionBoundaryComplete -and
        -not [string]::IsNullOrWhiteSpace($DiagnosticsRoot) -and
        -not [string]::IsNullOrWhiteSpace($childDiagnostics) -and
        (Test-Path -LiteralPath $childDiagnostics)) {
        try {
            $diagnosticsDestination = [IO.Path]::GetFullPath($DiagnosticsRoot)
            $diagnosticsBoundary = @($approvedStateBases | Where-Object {
                Test-PathWithin $diagnosticsDestination ([IO.Path]::GetFullPath($_))
            } | Select-Object -First 1)[0]
            if ([string]::IsNullOrWhiteSpace([string]$diagnosticsBoundary)) {
                throw 'diagnostic handoff destination is outside approved hosted-runner temporary roots'
            }
            Copy-BoundedDisposableDiagnostics $childDiagnostics $diagnosticsDestination `
                $sandbox ([IO.Path]::GetFullPath($diagnosticsBoundary))
        } catch { $cleanupFailures.Add("diagnostic handoff: $($_.Exception.Message)") }
    }
    if ($accountCreated -and $executionBoundaryComplete) {
        try { Remove-DisposableProfileAndAccount $accountName $accountSid }
        catch { $cleanupFailures.Add("account/profile cleanup: $($_.Exception.Message)") }
    }
    $password.Dispose()
    if ($executionBoundaryComplete -and
        -not [string]::IsNullOrWhiteSpace($sandbox) -and
        (Test-Path -LiteralPath $sandbox)) {
        try {
            $resolvedSandbox = [IO.Path]::GetFullPath($sandbox).TrimEnd('\')
            if (-not (Test-PathWithin $resolvedSandbox $stateBase) -or
                -not (Split-Path -Leaf $resolvedSandbox).StartsWith(
                    'disposable-user-', [StringComparison]::Ordinal
                )) {
                throw "refusing to remove unexpected disposable-user sandbox: $resolvedSandbox"
            }
            Remove-DisposableTreeSafely $resolvedSandbox $stateBase
        } catch { $cleanupFailures.Add("sandbox cleanup: $($_.Exception.Message)") }
    }
}

if ($null -ne $primaryFailure -or $cleanupFailures.Count -ne 0) {
    $parts = [Collections.Generic.List[string]]::new()
    if ($null -ne $primaryFailure) { $parts.Add($primaryFailure.Exception.Message) }
    foreach ($failure in $cleanupFailures) { $parts.Add($failure) }
    throw ($parts -join '; ')
}
