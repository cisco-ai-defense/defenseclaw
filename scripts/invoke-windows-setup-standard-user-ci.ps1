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
    [ValidateSet('setup-acceptance', 'wizard-smoke', 'contract')]
    [string]$Mode,
    [ValidateSet('codex', 'claudecode')][string]$Connector = 'codex',
    [Parameter(Mandatory)][string]$ArtifactRoot,
    [Parameter(Mandatory)][string]$StateRoot,
    [string]$DiagnosticsRoot = '',
    [ValidateRange(60, 7200)][int]$TimeoutSeconds = 4500,
    [switch]$Child,
    [switch]$ExerciseWmiEscape,
    [string]$ExpectedSetupSha256 = '',
    [string]$ExpectedChildSid = '',
    [string]$ResultPath = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-ChildProgress([string]$Path, [string]$Phase) {
    try {
        [IO.File]::AppendAllText(
            $Path,
            (([DateTime]::UtcNow.ToString('o') + ' ' + $Phase) + [Environment]::NewLine),
            [Text.UTF8Encoding]::new($false)
        )
    } catch {
        # Progress is diagnostic only and must never change lifecycle behavior.
    }
}

$earlyProgress = ''
if ($Child) {
    $earlyIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $earlyAccountName = ($earlyIdentity.Name -split '\\')[-1]
    if ($earlyAccountName -notmatch '^dcacc[0-9a-f]{10}$') {
        throw 'child readiness is restricted to a DefenseClaw disposable Setup CI account'
    }
    $earlyReadinessName = 'Local\DefenseClaw-Disposable-' + $earlyAccountName
    $earlyReadiness = [Threading.EventWaitHandleAcl]::OpenExisting(
        $earlyReadinessName,
        [Security.AccessControl.EventWaitHandleRights]::Modify
    )
    try {
        if (-not $earlyReadiness.Set()) {
            throw 'disposable child readiness event could not be signaled'
        }
    } finally {
        $earlyReadiness.Dispose()
    }
    $earlyResult = [IO.Path]::GetFullPath($ResultPath)
    $earlyResultDirectory = [IO.Path]::GetDirectoryName($earlyResult)
    if ([string]::IsNullOrWhiteSpace($earlyResultDirectory)) {
        throw 'disposable child result path has no parent directory'
    }
    $earlyProgress = Join-Path $earlyResultDirectory 'progress.log'
    Write-ChildProgress $earlyProgress 'child-entry'
}
. (Join-Path $PSScriptRoot 'windows-native-paths.ps1')
if ($Child) { Write-ChildProgress $earlyProgress 'native-paths-loaded' }
if ($Child) { Write-ChildProgress $earlyProgress 'file-guard-load-start' }
. (Join-Path $PSScriptRoot 'windows-disposable-user-safety.ps1')
if ($Child) { Write-ChildProgress $earlyProgress 'file-guard-load-complete' }

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

    # Exercise PowerShell's filesystem provider through the leased ancestor
    # chain. Direct System.IO access alone does not cover provider path
    # normalization, which enumerates parent components on Windows.
    $providerProbe = Join-Path $State ('provider-probe-' + [guid]::NewGuid().ToString('N'))
    $providerNested = Join-Path $providerProbe 'nested'
    [IO.Directory]::CreateDirectory($providerNested) | Out-Null
    $providerFile = Join-Path $providerNested 'probe.txt'
    [IO.File]::WriteAllText($providerFile, 'provider writable')
    $listed = @(Get-ChildItem -LiteralPath $providerNested -Force -ErrorAction Stop)
    if (@($listed | Where-Object { $_.Name -ceq 'probe.txt' }).Count -ne 1) {
        throw 'PowerShell provider did not enumerate the writable child probe'
    }
    Remove-Item -LiteralPath $providerFile -Force -ErrorAction Stop
    if (Test-Path -LiteralPath $providerFile) {
        throw 'PowerShell provider did not delete the writable child probe'
    }
    Remove-Item -LiteralPath $providerProbe -Recurse -Force -ErrorAction Stop

    $parentOnlySibling = $SandboxRoot + '-parent-only'
    $expectedStateBase = Split-Path -Parent $SandboxRoot
    if (-not (Split-Path -Parent $parentOnlySibling).Equals(
            $expectedStateBase,
            [StringComparison]::OrdinalIgnoreCase
        ) -or (Test-PathWithinOrEqual $parentOnlySibling $SandboxRoot)) {
        throw 'parent-only sibling probe does not match the isolated state layout'
    }
    $siblingSentinel = Join-Path $parentOnlySibling 'sentinel.txt'
    Assert-ChildOperationAccessDenied 'parent-only sibling read probe' {
        $null = [IO.File]::ReadAllText($siblingSentinel)
    }
    Assert-ChildOperationAccessDenied 'parent-only sibling write probe' {
        $stream = [IO.File]::Open(
            $siblingSentinel,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Write,
            [IO.FileShare]::None
        )
        $stream.Dispose()
    }
    Assert-ChildOperationAccessDenied 'parent-only sibling enumeration probe' {
        Get-ChildItem -LiteralPath $parentOnlySibling -Force -ErrorAction Stop | Out-Null
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
    Write-ChildProgress $earlyProgress 'child-paths-resolved'
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if ([string]::IsNullOrWhiteSpace($ExpectedChildSid)) {
        throw 'parent did not supply the exact disposable child SID'
    }
    try {
        $expectedSid = [Security.Principal.SecurityIdentifier]::new($ExpectedChildSid)
    } catch {
        throw 'parent supplied an invalid disposable child SID'
    }
    if ($null -eq $identity.User -or -not $identity.User.Equals($expectedSid)) {
        throw 'disposable Setup acceptance child has an unexpected user SID'
    }
    $accountName = ($identity.Name -split '\\')[-1]
    if ($accountName -notmatch '^dcacc[0-9a-f]{10}$') {
        throw 'child mode is restricted to a DefenseClaw disposable Setup CI account'
    }
    Write-ChildProgress $earlyProgress 'child-user-validated'

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
    $progress = Join-Path $expectedResults 'progress.log'
    if (-not $earlyProgress.Equals(
            [IO.Path]::GetFullPath($progress),
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw 'early progress path does not match the private disposable-user result root'
    }
    Write-ChildProgress $progress 'layout-validated'
    $interactive = [Security.Principal.SecurityIdentifier]::new('S-1-5-4')
    $administrators = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $groupSids = if ($null -eq $identity.Groups) { @() } else { @(
        $identity.Groups | ForEach-Object {
            $_.Translate([Security.Principal.SecurityIdentifier]).Value
        }
    ) }
    if ($null -eq $identity.User -or $interactive.Value -notin $groupSids) {
        throw 'disposable Setup acceptance child is not an interactive standard user'
    }
    if ($administrators.Value -in $groupSids) {
        throw 'disposable Setup acceptance child is an administrator'
    }
    Write-ChildProgress $progress 'identity-validated'

    $originalChildDirectory = [Environment]::CurrentDirectory
    try {
        [Environment]::CurrentDirectory = $state
        Write-ChildProgress $progress 'filesystem-boundary-start'
        Test-ActualChildFilesystemBoundary $sandboxRoot `
            (Split-Path -Parent $PSScriptRoot) $PSScriptRoot $artifacts $state `
            $expectedResults $ExpectedSetupSha256
        Write-ChildProgress $progress 'filesystem-boundary-complete'
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
    Write-ChildProgress $progress 'environment-ready'
    if ($ExerciseWmiEscape) {
        # Win32_Process.Create is serviced outside the launcher's job object.
        # The harmless sleeper proves that the parent account-SID sweep catches
        # a process that intentionally escaped the kill-on-close job.
        $standardLauncher = Join-Path $PSScriptRoot 'windows-setup-standard-user-launcher.cs'
        Write-ChildProgress $progress 'wmi-launcher-load-start'
        Add-Type -Path $standardLauncher
        Write-ChildProgress $progress 'wmi-launcher-load-complete'
        $pwsh = Join-Path $PSHOME 'pwsh.exe'
        $commandLine = [DefenseClaw.SetupStandardUserLauncher]::QuoteWindowsArgument($pwsh) +
            ' -NoLogo -NoProfile -NonInteractive -Command ' +
            [DefenseClaw.SetupStandardUserLauncher]::QuoteWindowsArgument(
                'Start-Sleep -Seconds 14400'
            )
        $created = Invoke-CimMethod -ClassName Win32_Process -MethodName Create `
            -Arguments @{ CommandLine = $commandLine; CurrentDirectory = $expectedResults } `
            -OperationTimeoutSec 30 -ErrorAction Stop
        if ([uint32]$created.ReturnValue -ne 0 -or [uint32]$created.ProcessId -eq 0) {
            throw "WMI escape fixture creation failed: $($created.ReturnValue)"
        }
        [IO.File]::WriteAllText(
            (Join-Path $expectedResults 'wmi-escape-pid.txt'),
            ([string][uint32]$created.ProcessId),
            [Text.UTF8Encoding]::new($false)
        )
        Write-ChildProgress $progress 'wmi-fixture-ready'
    }
    $failure = $null
    try {
        Write-ChildProgress $progress "${Mode}-start"
        if ($Mode -eq 'setup-acceptance') {
            & $nativeHarness -Operation setup-acceptance `
                -WorkspaceRoot (Split-Path -Parent $PSScriptRoot) `
                -StateRoot $state -ArtifactRoot $artifacts `
                -AllowCurrentUserSetupAcceptance
        } elseif ($Mode -eq 'contract') {
            & $nativeHarness -Operation contract -Connector $Connector `
                -WorkspaceRoot (Split-Path -Parent $PSScriptRoot) `
                -StateRoot $state -ArtifactRoot $artifacts `
                -AllowCurrentUserSetupAcceptance
        } else {
            $setup = Join-Path $artifacts 'DefenseClawSetup-x64.exe'
            & (Join-Path $PSScriptRoot 'test-windows-setup-wizard.ps1') `
                -SetupPath $setup -StateRoot (Join-Path $state 'wizard-smoke')
        }
        Write-ChildProgress $progress "${Mode}-complete"
    } catch {
        Write-ChildProgress $progress "${Mode}-failed"
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
        Write-ChildProgress $progress 'child-cleanup-start'
        # Setup acceptance and the connector contract perform their product
        # teardown before returning. The elevated parent owns the stronger
        # harness cleanup boundary: job-object drain, exact-SID sweep, profile
        # removal, and sandbox deletion. A second child cleanup cannot add
        # coverage and would have to inspect parent-owned sandbox ancestors.
        Write-ChildProgress $progress 'child-cleanup-delegated-to-parent'
        Write-ChildProgress $progress 'child-cleanup-complete'
    }

    if ($null -ne $failure) {
        Write-ChildResult $result $false ($failure | Out-String)
        throw $failure
    }
    Write-ChildProgress $progress 'result-writing'
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
    $processId = [int]$Process.ProcessId
    if ($processId -le 0) { return $null }
    try {
        $current = @(Get-CimInstance Win32_Process `
            -Filter "ProcessId = $processId" -ErrorAction Stop)
    } catch {
        # A process can exit between the all-process snapshot and this exact-PID
        # lookup. Some Windows CIM providers report that normal race as "Not
        # found" instead of returning an empty set. Re-enumeration distinguishes
        # an exited or reused PID from a provider failure without weakening the
        # creation-time identity check below.
        $current = @(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object {
            [int]$_.ProcessId -eq $processId
        })
    }
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
            $current = Get-SameLiveProcess $process
            if ($null -eq $current) { continue }
            try {
                $owner = Invoke-CimMethod -InputObject $current -MethodName GetOwnerSid `
                    -ErrorAction Stop
            } catch {
                if ($null -eq (Get-SameLiveProcess $process)) { continue }
                throw
            }
            if ([uint32]$owner.ReturnValue -ne 0) {
                if ($null -eq (Get-SameLiveProcess $process)) { continue }
                throw "owner SID became unverifiable for exact-SID process $($process.ProcessId)"
            }
            if ([string]$owner.Sid -cne $Sid) {
                throw "owner SID changed for exact-SID process $($process.ProcessId)"
            }
            try {
                $termination = Invoke-CimMethod -InputObject $current -MethodName Terminate `
                    -Arguments @{ Reason = [uint32]1603 } -ErrorAction Stop
            } catch {
                if ($null -eq (Get-SameLiveProcess $process)) { continue }
                throw
            }
            if ([uint32]$termination.ReturnValue -ne 0) {
                if ($null -eq (Get-SameLiveProcess $process)) { continue }
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

function Publish-BoundedDisposableContractResults {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SourcePath,
        [Parameter(Mandatory)][string]$SourceRoot,
        [Parameter(Mandatory)][string]$DestinationPath,
        [Parameter(Mandatory)][string]$DestinationRoot,
        [Parameter(Mandatory)][ValidateSet('codex', 'claudecode')]
        [string]$ExpectedConnector
    )

    $contents = Read-BoundedDisposableResult $SourcePath $SourceRoot 1048576
    $lines = @($contents -split '\r?\n' | Where-Object {
        -not [string]::IsNullOrWhiteSpace($_)
    })
    if ($lines.Count -eq 0) {
        throw 'disposable connector contract produced an empty results.jsonl'
    }
    foreach ($line in $lines) {
        try { $record = $line | ConvertFrom-Json -ErrorAction Stop }
        catch { throw "disposable connector contract produced invalid JSONL: $($_.Exception.Message)" }
        if ([string]$record.connector -cne $ExpectedConnector -or
            [string]$record.os -cne 'windows') {
            throw 'disposable connector contract result identity does not match the requested Windows connector'
        }
    }

    $destination = Assert-DisposableNoReparseAncestors -Path $DestinationPath `
        -AllowedRoot $DestinationRoot
    if (Test-Path -LiteralPath $destination) {
        throw "refusing to overwrite an existing connector contract result: $destination"
    }
    [IO.File]::WriteAllText(
        $destination,
        $contents,
        [Text.UTF8Encoding]::new($false)
    )
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
$resourceVerifierInputs = @(
    'DefenseClawWindowsResourceVerifier-x64.exe',
    'DefenseClawWindowsResourceIcon.png',
    'DefenseClawWindowsResourceVersion.txt'
)
foreach ($resourceInputName in $resourceVerifierInputs) {
    $resourceInput = Join-Path $artifactSource $resourceInputName
    $null = Assert-DisposableNoReparseAncestors -Path $resourceInput `
        -AllowedRoot $artifactSource -RequireExists
    $resourceInputItem = Get-Item -LiteralPath $resourceInput -Force -ErrorAction Stop
    if (-not $resourceInputItem.PSIsContainer -and
        -not ($resourceInputItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        continue
    }
    throw "Windows resource verifier input must be a regular file: $resourceInput"
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
$ancestorReadLease = @()
$parentOnlySibling = ''
$desktopGrant = $null
$readinessEvent = $null
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
$progressRecord = ''
$wizardTraceRecord = ''
$contractResultsRecord = ''
$contractResultsDestination = ''
$contractResultsPublished = $false
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

    $readinessName = 'Local\DefenseClaw-Disposable-' + $accountName
    $readinessSecurity = [Security.AccessControl.EventWaitHandleSecurity]::new()
    $readinessSecurity.SetAccessRuleProtection($true, $false)
    $parentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $readinessSecurity.AddAccessRule(
        [Security.AccessControl.EventWaitHandleAccessRule]::new(
            $parentSid,
            [Security.AccessControl.EventWaitHandleRights]::FullControl,
            [Security.AccessControl.AccessControlType]::Allow
        )
    )
    $readinessSecurity.AddAccessRule(
        [Security.AccessControl.EventWaitHandleAccessRule]::new(
            $sidObject,
            [Security.AccessControl.EventWaitHandleRights]::Modify,
            [Security.AccessControl.AccessControlType]::Allow
        )
    )
    $createdReadiness = $false
    $readinessEvent = [Threading.EventWaitHandleAcl]::Create(
        $false,
        [Threading.EventResetMode]::ManualReset,
        $readinessName,
        [ref]$createdReadiness,
        $readinessSecurity
    )
    if (-not $createdReadiness) {
        throw 'disposable child readiness event name unexpectedly already exists'
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
    $harnessFiles = @(
        'invoke-windows-setup-standard-user-ci.ps1',
        'validate_packaged_v8_resources.py',
        'windows-native-ci.ps1',
        'windows-native-paths.ps1',
        'windows-disposable-file-guard.cs',
        'windows-disposable-user-safety.ps1',
        'windows-setup-standard-user-launcher.cs',
        'test-windows-setup-wizard.ps1'
    )
    if ($Mode -eq 'contract') {
        $harnessFiles += @(
            'assert-gateway-jsonl.py',
            'assert-observability-v8-jsonl.py',
            'live-connector-e2e\run-windows.ps1',
            'live-connector-e2e\assert-windows-evidence.py',
            'live-connector-e2e\testdata\windows-mock.ps1',
            "live-connector-e2e\golden\$Connector\pre_tool_allow.json",
            "live-connector-e2e\golden\$Connector\pre_tool_block.json",
            "live-connector-e2e\golden\$Connector\session_start.json"
        )
    }
    foreach ($file in $harnessFiles) {
        $source = Join-Path $PSScriptRoot $file
        $destination = Join-Path $scripts $file
        $null = Assert-DisposableNoReparseAncestors -Path $source `
            -AllowedRoot $PSScriptRoot -RequireExists
        $null = Assert-DisposableNoReparseAncestors -Path $destination `
            -AllowedRoot $scripts
        [IO.Directory]::CreateDirectory((Split-Path -Parent $destination)) | Out-Null
        [IO.File]::Copy($source, $destination, $false)
    }
    foreach ($resourceInputName in $resourceVerifierInputs) {
        $source = Join-Path $artifactSource $resourceInputName
        $destination = Join-Path $scripts $resourceInputName
        $null = Assert-DisposableNoReparseAncestors -Path $destination `
            -AllowedRoot $scripts
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
    # The native harness replaces its state-root DACL and owner immediately on
    # entry. Give this one writable root the WRITE_DAC/WRITE_OWNER rights needed
    # for that transition; immutable workspace and artifact roots stay read-only.
    Set-DisposableProtectedDirectoryAcl $childState $sidObject `
        ([Security.AccessControl.FileSystemRights]::FullControl) -InheritChildRights
    foreach ($directory in @($childDiagnostics, $childResults)) {
        Set-DisposableProtectedDirectoryAcl $directory $sidObject `
            ([Security.AccessControl.FileSystemRights]::Modify) -InheritChildRights
    }
    Assert-DisposableChildAcl $sandbox $sidObject `
        ([Security.AccessControl.FileSystemRights]::ReadAndExecute)
    foreach ($directory in @($workspace, $scripts, $childArtifacts)) {
        Assert-DisposableChildAcl $directory $sidObject `
            ([Security.AccessControl.FileSystemRights]::ReadAndExecute) -ExpectInheritance
    }
    Assert-DisposableChildAcl $childState $sidObject `
        ([Security.AccessControl.FileSystemRights]::FullControl) `
        -ExpectInheritance -AllowOwnershipBootstrap
    foreach ($directory in @($childDiagnostics, $childResults)) {
        Assert-DisposableChildAcl $directory $sidObject `
            ([Security.AccessControl.FileSystemRights]::Modify) -ExpectInheritance
    }

    # The temporary traversal lease must not grant access to adjacent state.
    # Protect a sibling before granting the non-inheriting ancestor ACEs so the
    # actual child can prove the boundary remains intact.
    $parentOnlySibling = $sandbox + '-parent-only'
    $parentOnlyDirectory = [IO.Directory]::CreateDirectory($parentOnlySibling)
    $parentOnlySecurity = [Security.AccessControl.DirectorySecurity]::new()
    $parentOnlySecurity.SetOwner($parentSid)
    $parentOnlySecurity.SetAccessRuleProtection($true, $false)
    $parentOnlyInheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [Security.AccessControl.InheritanceFlags]::ObjectInherit
    foreach ($trustedSid in @(
        $parentSid,
        [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    )) {
        [void]$parentOnlySecurity.AddAccessRule(
            [Security.AccessControl.FileSystemAccessRule]::new(
                $trustedSid,
                [Security.AccessControl.FileSystemRights]::FullControl,
                $parentOnlyInheritance,
                [Security.AccessControl.PropagationFlags]::None,
                [Security.AccessControl.AccessControlType]::Allow
            )
        )
    }
    [IO.FileSystemAclExtensions]::SetAccessControl(
        $parentOnlyDirectory,
        $parentOnlySecurity
    )
    [IO.File]::WriteAllText(
        (Join-Path $parentOnlySibling 'sentinel.txt'),
        'parent-only',
        [Text.UTF8Encoding]::new($false)
    )
    $ancestorReadLease = @(Grant-DisposableAncestorReadLease `
        $stateBoundary $stateBase $sidObject)

    $result = Join-Path $childResults 'result.json'
    $wmiFixtureRecord = Join-Path $childResults 'wmi-escape-pid.txt'
    $progressRecord = Join-Path $childResults 'progress.log'
    $wizardTraceRecord = Join-Path $childState 'wizard-smoke\wizard-driver.log'
    $contractResultsRecord = Join-Path $childState 'results.jsonl'
    $contractResultsDestination = Join-Path $stateBase 'results.jsonl'
    $desktopGrant = [DefenseClaw.DisposableStandardUserLauncher]::GrantInteractiveDesktop($accountSid)
    $pwsh = Join-Path $PSHOME 'pwsh.exe'
    $arguments = @(
        '-NoLogo', '-NoProfile', '-NonInteractive', '-File',
        (Join-Path $scripts 'invoke-windows-setup-standard-user-ci.ps1'),
        '-Child', '-Mode', $Mode,
        '-ArtifactRoot', $childArtifacts,
        '-StateRoot', $childState,
        '-DiagnosticsRoot', $childDiagnostics,
        '-ResultPath', $result,
        '-ExpectedChildSid', $accountSid
    )
    if ($Mode -eq 'contract') {
        $arguments += @('-Connector', $Connector)
    }
    if ($Mode -eq 'setup-acceptance') {
        $arguments += '-ExerciseWmiEscape'
    }
    $arguments += @('-ExpectedSetupSha256', $expectedSetupHash)
    # Refresh immediately before the untrusted logon. Only exact PID and
    # CreationDate pairs that are already unverifiable at this point may remain
    # unverifiable during teardown; PID reuse and every new unknown fail closed.
    $unverifiableProcessBaseline = Get-UnverifiableProcessBaseline
    $childProcess = [DefenseClaw.DisposableStandardUserLauncher]::Start(
        $accountName,
        '.',
        $password,
        $pwsh,
        [string[]]$arguments,
        $childState,
        $accountSid
    )
    $startupFailed = -not $readinessEvent.WaitOne(15000)
    $startupDiagnostic = if ($startupFailed) {
        $childProcess.GetStartupDiagnostics()
    } else {
        ''
    }
    $exitCode = 124
    $exited = $false
    if (-not $startupFailed) {
        $exited = $childProcess.WaitForExitAndGetExitCode(
            $TimeoutSeconds * 1000,
            [ref]$exitCode
        )
    }
    $timedOut = $startupFailed -or -not $exited

    # No elevated file enumeration, hash, result read, diagnostics copy, or
    # profile cleanup is permitted until both containment layers are closed:
    # the job reports ActiveProcesses=0, then the disabled account has no
    # remaining process or scheduled-task identity anywhere on the host.
    $terminatedSidProcessIds = @(Complete-DisposableExecutionBoundary `
        $childProcess $accountName $accountSid $unverifiableProcessBaseline)
    $executionBoundaryComplete = $true
    if ($Mode -eq 'contract' -and
        (Test-Path -LiteralPath $contractResultsRecord -PathType Leaf)) {
        Publish-BoundedDisposableContractResults `
            -SourcePath $contractResultsRecord `
            -SourceRoot $childState `
            -DestinationPath $contractResultsDestination `
            -DestinationRoot $stateBase `
            -ExpectedConnector $Connector
        $contractResultsPublished = $true
    }
    if ($startupFailed) {
        $progressDetail = if (Test-Path -LiteralPath $progressRecord -PathType Leaf) {
            Read-BoundedDisposableResult $progressRecord $childResults 32768
        } else {
            '[no child progress record]'
        }
        throw "disposable standard-user $Mode did not enter its child script within 15 seconds`nlauncher diagnostics: $startupDiagnostic`nchild progress:`n$progressDetail"
    }
    if ($timedOut) {
        $progressDetail = if (Test-Path -LiteralPath $progressRecord -PathType Leaf) {
            Read-BoundedDisposableResult $progressRecord $childResults 32768
        } else {
            '[no child progress record]'
        }
        $wizardTraceDetail = if (Test-Path -LiteralPath $wizardTraceRecord -PathType Leaf) {
            Read-BoundedDisposableResult $wizardTraceRecord $childState 65536
        } else {
            '[no wizard trace record]'
        }
        throw "disposable standard-user $Mode timed out after $TimeoutSeconds seconds`nchild progress:`n$progressDetail`nwizard trace:`n$wizardTraceDetail"
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
    if ($Mode -eq 'setup-acceptance') {
        $fixturePidText = Read-BoundedDisposableResult $wmiFixtureRecord $childResults 4096
        $fixturePid = 0
        if (-not [int]::TryParse($fixturePidText.Trim(), [ref]$fixturePid) -or
            $fixturePid -le 0 -or $fixturePid -notin $terminatedSidProcessIds) {
            throw 'WMI escape fixture was not terminated by the exact disposable-SID process sweep'
        }
    }
    $observed = (Read-BoundedDisposableResult $result $childResults) | ConvertFrom-Json
    if ([string]$observed.user_sid -ne $accountSid -or [bool]$observed.elevated) {
        throw 'disposable standard-user child result reported the wrong identity or elevation'
    }
    if ($exitCode -ne 0 -or -not [bool]$observed.succeeded) {
        throw "disposable standard-user $Mode failed (exit $exitCode): $($observed.detail)"
    }
    if ($Mode -eq 'contract' -and -not $contractResultsPublished) {
        throw 'disposable connector contract passed without producing bounded results.jsonl'
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
    if ($null -ne $readinessEvent) { $readinessEvent.Dispose() }
    if ($executionBoundaryComplete -and $ancestorReadLease.Count -ne 0) {
        try {
            Restore-DisposableAncestorReadLease $ancestorReadLease
            $ancestorReadLease = @()
        } catch {
            $cleanupFailures.Add("ancestor ACL lease restore: $($_.Exception.Message)")
        }
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
    if ($executionBoundaryComplete -and
        -not [string]::IsNullOrWhiteSpace($parentOnlySibling) -and
        (Test-Path -LiteralPath $parentOnlySibling)) {
        try {
            $resolvedSibling = [IO.Path]::GetFullPath($parentOnlySibling).TrimEnd('\')
            if (-not $resolvedSibling.Equals(
                    ([IO.Path]::GetFullPath($sandbox).TrimEnd('\') + '-parent-only'),
                    [StringComparison]::OrdinalIgnoreCase
                ) -or -not (Test-PathWithin $resolvedSibling $stateBase)) {
                throw "refusing to remove unexpected parent-only sibling: $resolvedSibling"
            }
            Remove-DisposableTreeSafely $resolvedSibling $stateBase
        } catch { $cleanupFailures.Add("parent-only sibling cleanup: $($_.Exception.Message)") }
    }
}

if ($null -ne $primaryFailure -or $cleanupFailures.Count -ne 0) {
    $parts = [Collections.Generic.List[string]]::new()
    if ($null -ne $primaryFailure) { $parts.Add($primaryFailure.Exception.Message) }
    foreach ($failure in $cleanupFailures) { $parts.Add($failure) }
    throw ($parts -join '; ')
}
