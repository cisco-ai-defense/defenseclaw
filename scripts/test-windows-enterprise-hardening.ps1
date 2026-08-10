# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 7.0

<#
.SYNOPSIS
Safely certifies the Windows managed-enterprise service and hook-guardian
security contract on a disposable endpoint.

.DESCRIPTION
The default invocation is read-only: it validates inputs and prints the exact
unique user, service, and path plan. Host mutation requires both -Execute and
-DisposableHost from an elevated 64-bit PowerShell process.

Execution uses the already-active WTS desktop user without requesting its
password, creates one uniquely named local non-admin denial user, creates
uniquely named SCM services through packaging/windows/install-enterprise.ps1,
and uses unique roots under the dedicated DefenseClaw-Cert subtrees in Program
Files and ProgramData. It never targets production service names or roots and
requires exact restoration of the active user's canonical managed trees.

The harness proves:
  * enterprise enforcement is administrator opt-in;
  * a standard user cannot stop/reconfigure/delete the services, write the
    binaries/config/manifest/ledger, read service-side credentials, forge
    authorization, or invoke administrator hook removal;
  * the guardian repairs deleted/modified target-owned DefenseClaw hook
    runtime files plus protected machine Codex requirements and enrollment
    state without reading or changing the active user's .codex tree;
  * target-owned sparse/oversized tokens, sidecars, contract state, and hook
    helpers are read with bounded memory, reported unhealthy, quarantined, and
    restored without restarting the guardian or recording secret bytes;
  * unsafe manifests, path escapes, foreign owners, unsafe DACLs, and reparse
    points fail closed;
  * Windows lifecycle/reconcile and guardian status/verify JSON and exit status
    do not claim success for partial or unhealthy state;
  * generic user-footprint mutation is performed only by the installed
    LocalSystem guardian while it impersonates the manifest's exact user SID;
  * failed servicing leaves the previously verified transaction intact.

Run this only on a disposable Windows validation endpoint with an independent
administrator recovery channel. The harness always attempts bounded cleanup in
finally; it never treats cleanup as proof that a failed test was safe.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$GatewayBinary,

    [Parameter(Mandatory)]
    [string]$HookBinary,

    [Parameter(Mandatory)]
    [string]$CLIBinary,

    [string]$NormalModeCLILauncher = '',

    [string]$NormalModeCLIWheel = '',

    [Parameter(Mandatory)]
    [string]$CodexBinary,

    [Parameter(Mandatory)]
    [string]$ClaudeBinary,

    [Parameter(Mandatory)]
    [string]$RejectedCodexBinary,

    [Parameter(Mandatory)]
    [string]$RejectedClaudeBinary,

    [string]$CodexTrustedHookLauncherBinary = '',

    [string]$InstallerPath = '',

    [string]$UpgradeGatewayBinary = '',

    [string]$UpgradeHookBinary = '',

    [string]$UpgradeCLIBinary = '',

    [ValidateRange(15, 600)]
    [int]$RepairTimeoutSeconds = 120,

    [ValidateRange(1, 30)]
    [int]$SettleSeconds = 3,

    [string]$EvidenceRoot = '',

    [string]$ProtectedUserSID = '',

    [switch]$AllowUnsigned,

    [switch]$AttestAgentApplicationControl,

    [switch]$AttestCodexTrustedHookLauncher,

    [switch]$ClaudeOnly,

    [switch]$Execute,

    [switch]$DisposableHost,

    [switch]$KeepWorkRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$script:HarnessSchemaVersion = 1
$script:Results = [Collections.Generic.List[object]]::new()
$script:CleanupErrors = [Collections.Generic.List[string]]::new()
$script:Phase = 'preflight'
$script:Installed = $false
$script:PrimaryUserCreated = $false
$script:HostileUserCreated = $false
$script:PrimaryCredential = $null
$script:HostileCredential = $null
$script:PrimarySID = ''
$script:HostileSID = ''
$script:PrimaryProfile = ''
$script:HostileProfile = ''
$script:PrimarySessionID = -1
$script:PrimaryDataDir = ''
$script:CertificationCodexHome = ''
$script:NormalModeSyntheticHome = ''
$script:CertificationCodexHomeInitialized = $false
$script:MachineCodexHomeBaseline = $null
$script:CoordinatorCodexHomeSnapshot = [pscustomobject]@{
    existed = Test-Path -LiteralPath 'Env:CODEX_HOME'
    value = [Environment]::GetEnvironmentVariable('CODEX_HOME', 'Process')
}
$script:CertificationCodexHomeValidation = $null
$script:CodexRuntimeRoot = ''
$script:CodexRuntimeBinary = ''
$script:CodexTrustedHookLauncherRuntimeBinary = ''
$script:CodexTrustedHookLauncherIdentity = $null
$script:ClaudeRuntimeBinary = ''
$script:RejectedCodexRuntimeBinary = ''
$script:RejectedClaudeRuntimeBinary = ''
$script:HostileShellProbeBinary = ''
$script:CodexLiveProcessProof = $null
$script:ClaudeLiveProcessProof = $null
$script:ClaudeEffectivePolicyAttested = $false
$script:CodexUserHookSentinel = ''
$script:CodexHostileShellMarker = ''
$script:CodexRejectedClientMarker = ''
$script:FirstGuardianPathProof = $null
$script:CertificationServiceCodexHomeAbsenceProof = @()
$script:PrimaryConfigPath = ''
$script:PrimaryConfigBaselineBytes = $null
$script:PrimaryConfigBaselineACL = $null
$script:PrimaryConfigBaselineSHA256 = ''
$script:ActiveUserHandoffRoot = ''
$script:ScheduledTasks = [Collections.Generic.List[string]]::new()
$script:UserTreeSnapshots = [Collections.Generic.List[object]]::new()
$script:SecretNeedles = [Collections.Generic.List[string]]::new()
$script:SourceDigests = [ordered]@{}
$script:CodexSharedOwnedByHarness = $false
$script:CodexSharedExpectedBeforeCleanup = $null
$script:APIPort = 0
$script:PlanOnly = -not $Execute
$script:RunStartedAt = [DateTimeOffset]::UtcNow
# Each hostile inode advertises 1 TiB but is marked sparse before either grow.
# The fixture fails above 1 MiB of NTFS allocation. A 256-MiB guardian
# working-set delta deliberately leaves ample room for Go/runtime and scanner
# jitter while remaining below 0.025% of the attacker-controlled logical size;
# a metadata-sized read must not scale with that logical length.
$script:SparseAttackLogicalBytes = [int64]1099511627776
$script:SparseAttackInitialGrowBytes = [int64]8388608
$script:SparseAttackMaxAllocatedBytes = [int64]1048576
$script:SparseAttackMaxGuardianWorkingSetGrowthBytes = [int64]268435456

function Protect-DisplayText([string]$Value) {
    if ($null -eq $Value) { return '' }
    $text = $Value -replace '[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '?'
    if ($text.Length -gt 4000) {
        return $text.Substring(0, 4000) + '…'
    }
    return $text
}

function Protect-SensitiveDisplayText([string]$Value) {
    $text = Protect-DisplayText $Value
    foreach ($secret in @($script:SecretNeedles.ToArray())) {
        if (-not [string]::IsNullOrWhiteSpace($secret)) {
            $text = $text.Replace($secret, '<redacted-secret>')
        }
    }
    return $text
}

function ConvertTo-CanonicalPath([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw 'path is empty'
    }
    return [IO.Path]::GetFullPath(
        [Environment]::ExpandEnvironmentVariables($Path)
    ).TrimEnd('\')
}

function Assert-PathBelow([string]$Path, [string]$Root, [string]$Label) {
    $full = ConvertTo-CanonicalPath $Path
    $base = (ConvertTo-CanonicalPath $Root).TrimEnd('\') + '\'
    if (-not $full.StartsWith($base, [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Label escapes its dedicated certification root: $full (root $base)"
    }
    return $full
}

function Assert-CertificationCodexHomePath([string]$Path, [switch]$RequireExisting) {
    if ([string]::IsNullOrWhiteSpace($script:PrimaryProfile) -or
        [string]::IsNullOrWhiteSpace($script:PrimarySID)) {
        throw 'certification CODEX_HOME requires a resolved active WTS profile and SID'
    }
    $profile = ConvertTo-CanonicalPath $script:PrimaryProfile
    $full = ConvertTo-CanonicalPath $Path
    $expectedName = ".codex-defenseclaw-cert-$($script:RunToken)"
    $expected = ConvertTo-CanonicalPath (Join-Path $profile $expectedName)
    $parent = ConvertTo-CanonicalPath ([IO.Path]::GetDirectoryName($full))
    if (-not $parent.Equals($profile, [StringComparison]::OrdinalIgnoreCase) -or
        -not $full.Equals($expected, [StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetFileName($full) -cne $expectedName) {
        throw "certification CODEX_HOME must be the exact allowlisted direct child $expected"
    }

    $current = $profile
    while (-not [string]::IsNullOrWhiteSpace($current)) {
        $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "active WTS profile traverses a reparse point: $current"
        }
        if ($current.Equals($profile, [StringComparison]::OrdinalIgnoreCase) -and
            -not $item.PSIsContainer) {
            throw "active WTS profile is not a real directory: $profile"
        }
        $parentPath = [IO.Path]::GetDirectoryName($current)
        if ([string]::IsNullOrWhiteSpace($parentPath) -or
            $parentPath.Equals($current, [StringComparison]::OrdinalIgnoreCase)) {
            break
        }
        $current = $parentPath
    }
    $volumeRoot = [IO.Path]::GetPathRoot($profile)
    if ([string]::IsNullOrWhiteSpace($volumeRoot)) {
        throw "active WTS profile has no local volume root: $profile"
    }
    $drive = [IO.DriveInfo]::new($volumeRoot)
    if (-not $drive.IsReady -or
        $drive.DriveType -ne [IO.DriveType]::Fixed -or
        -not [string]::Equals(
            $drive.DriveFormat,
            'NTFS',
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw (
            "certification CODEX_HOME requires a ready fixed NTFS profile volume; " +
            "root=$volumeRoot type=$($drive.DriveType) format=$($drive.DriveFormat)"
        )
    }

    if ($RequireExisting) {
        $item = Get-Item -LiteralPath $full -Force -ErrorAction Stop
        if (-not $item.PSIsContainer -or
            ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "certification CODEX_HOME is not a real directory: $full"
        }
        $owner = (Get-Acl -LiteralPath $full -ErrorAction Stop).Owner
        $ownerSID = ConvertTo-CertificationSID $owner
        if ($ownerSID -ne $script:PrimarySID) {
            throw "certification CODEX_HOME owner is $ownerSID, want $($script:PrimarySID)"
        }
    }
    $script:CertificationCodexHomeValidation = [pscustomobject]@{
        path = $full
        profile = $profile
        profile_sid = $script:PrimarySID
        direct_child = $true
        name = $expectedName
        volume_root = $volumeRoot
        drive_type = [string]$drive.DriveType
        file_system = [string]$drive.DriveFormat
        exists = [bool]$RequireExisting
        owner_sid = if ($RequireExisting) { $script:PrimarySID } else { '' }
        reparse = $false
        validated_at = [DateTimeOffset]::UtcNow.ToString('o')
    }
    return $full
}

function Get-MachineCodexHomeSnapshot {
    $keyPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
    $key = Get-Item -LiteralPath $keyPath -ErrorAction Stop
    $name = @(
        $key.GetValueNames() |
            Where-Object { $_.Equals('CODEX_HOME', [StringComparison]::OrdinalIgnoreCase) }
    )
    if ($name.Count -gt 1) {
        throw 'machine environment contains duplicate case-insensitive CODEX_HOME values'
    }
    if ($name.Count -eq 0) {
        return [pscustomobject]@{
            existed = $false
            name = 'CODEX_HOME'
            value = $null
            kind = ''
        }
    }
    $kind = $key.GetValueKind([string]$name[0])
    if ($kind -notin @(
        [Microsoft.Win32.RegistryValueKind]::String,
        [Microsoft.Win32.RegistryValueKind]::ExpandString
    )) {
        throw "refusing machine CODEX_HOME registry kind $kind"
    }
    return [pscustomobject]@{
        existed = $true
        name = [string]$name[0]
        value = $key.GetValue(
            [string]$name[0],
            $null,
            [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
        )
        kind = [string]$kind
    }
}

function Assert-CoordinatorCodexHomeUnchanged {
    $exists = Test-Path -LiteralPath 'Env:CODEX_HOME'
    $value = [Environment]::GetEnvironmentVariable('CODEX_HOME', 'Process')
    if ($exists -ne [bool]$script:CoordinatorCodexHomeSnapshot.existed -or
        -not [string]::Equals(
            [string]$value,
            [string]$script:CoordinatorCodexHomeSnapshot.value,
            [StringComparison]::Ordinal
        )) {
        throw 'certification changed the coordinator process CODEX_HOME'
    }
}

function Assert-MachineCodexHomeUnchanged {
    if ($null -eq $script:MachineCodexHomeBaseline) {
        throw 'machine CODEX_HOME baseline was not captured'
    }
    Assert-CoordinatorCodexHomeUnchanged
    $before = $script:MachineCodexHomeBaseline
    $after = Get-MachineCodexHomeSnapshot
    if ([bool]$after.existed -ne [bool]$before.existed -or
        ([bool]$before.existed -and (
            [string]$after.name -cne [string]$before.name -or
            [string]$after.kind -cne [string]$before.kind -or
            -not [string]::Equals(
                [string]$after.value,
                [string]$before.value,
                [StringComparison]::Ordinal
            )
        ))) {
        throw 'certification changed machine CODEX_HOME'
    }
    return $after
}

function Assert-CertificationServiceName([string]$Name, [string]$Role) {
    $expected = switch ($Role) {
        'gateway' { "DefenseClawCertGateway_$($script:RunToken)" }
        'guardian' { "DefenseClawCertGuardian_$($script:RunToken)" }
        default { throw "unknown certification service role: $Role" }
    }
    if ($Name -cne $expected) {
        throw "unsafe $Role service name: $Name (want exact $expected)"
    }
}

function Assert-CertificationUserName([string]$Name, [string]$Role) {
    if ($Name -notmatch '^DCE[PH][a-f0-9]{8}$' -or $Name.Length -gt 20) {
        throw "unsafe $Role local user name: $Name"
    }
}

function Assert-CertificationScope {
    Assert-CertificationServiceName $script:GatewayServiceName 'gateway'
    Assert-CertificationServiceName $script:GuardianServiceName 'guardian'
    $expectedInstall = ConvertTo-CanonicalPath (
        Join-Path $script:ProgramFilesCertificationRoot $script:RunToken
    )
    $expectedState = ConvertTo-CanonicalPath (
        Join-Path $script:ProgramDataCertificationRoot $script:RunToken
    )
    if (-not $script:InstallRoot.Equals(
        $expectedInstall,
        [StringComparison]::OrdinalIgnoreCase
    ) -or
        -not $script:StateRoot.Equals(
            $expectedState,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw (
            'certification roots must be the exact run-scoped allowlist: ' +
            "install=$expectedInstall state=$expectedState"
        )
    }
    if ($script:CertificationCodexHomeInitialized) {
        $null = Assert-CertificationCodexHomePath `
            $script:CertificationCodexHome `
            -RequireExisting
    }

    $productionInstall = ConvertTo-CanonicalPath (
        Join-Path $script:KnownProgramFiles 'Cisco\DefenseClaw'
    )
    $productionState = ConvertTo-CanonicalPath (
        Join-Path $script:KnownProgramData 'Cisco\DefenseClaw'
    )
    if ($script:GatewayServiceName -eq 'DefenseClawGateway' -or
        $script:GuardianServiceName -eq 'DefenseClawHookGuardian' -or
        $script:InstallRoot.Equals($productionInstall, [StringComparison]::OrdinalIgnoreCase) -or
        $script:StateRoot.Equals($productionState, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'refusing certification outside the unique non-production boundary'
    }
}

function Add-Result(
    [string]$Name,
    [string]$Status,
    [string]$Detail,
    [hashtable]$Data = @{}
) {
    $record = [ordered]@{
        name = $Name
        status = $Status
        phase = $script:Phase
        detail = Protect-SensitiveDisplayText $Detail
        observed_at = [DateTimeOffset]::UtcNow.ToString('o')
    }
    foreach ($entry in $Data.GetEnumerator()) {
        $record[$entry.Key] = $entry.Value
    }
    $script:Results.Add([pscustomobject]$record)
}

function Invoke-Check([string]$Name, [scriptblock]$Body) {
    try {
        $detail = & $Body
        if ($null -eq $detail) { $detail = 'passed' }
        Add-Result $Name 'passed' ([string]$detail)
    } catch {
        Add-Result $Name 'failed' $_.Exception.Message
        throw
    }
}

function Add-SkippedResult([string]$Name, [string]$Reason) {
    Add-Result $Name 'skipped' $Reason
}

function Get-PowerShellExecutable {
    $candidates = [Collections.Generic.List[string]]::new()
    $processPathProperty = [Environment].GetProperty(
        'ProcessPath',
        [Reflection.BindingFlags]::Public -bor
            [Reflection.BindingFlags]::Static
    )
    if ($null -ne $processPathProperty) {
        $processPath = [string]$processPathProperty.GetValue($null, $null)
        if (-not [string]::IsNullOrWhiteSpace($processPath)) {
            $candidates.Add($processPath)
        }
    }
    try {
        $currentProcessPath = [string](
            Get-Process -Id $PID -ErrorAction Stop
        ).Path
        if (-not [string]::IsNullOrWhiteSpace($currentProcessPath)) {
            $candidates.Add($currentProcessPath)
        }
    } catch {}
    foreach ($name in @('powershell.exe', 'pwsh.exe')) {
        $candidates.Add((Join-Path $PSHOME $name))
    }
    foreach ($candidate in @($candidates.ToArray())) {
        if (-not [string]::IsNullOrWhiteSpace($candidate) -and
            (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            return ConvertTo-CanonicalPath $candidate
        }
    }
    throw 'cannot resolve the current 64-bit PowerShell executable'
}

function Invoke-NativeProcess {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [string[]]$ArgumentList = @(),
        [int[]]$AllowedExitCodes = @(0),
        [Parameter(Mandatory)][string]$Label,
        [hashtable]$Environment = @{},
        [int]$TimeoutSeconds = 300,
        [scriptblock]$DuringExecution = $null,
        [ValidateRange(10, 1000)]
        [int]$ExecutionPollMilliseconds = 25,
        [switch]$StrictWindowsBootstrapEnvironment
    )

    $stdout = Join-Path $script:WorkRoot ($Label + '.stdout.log')
    $stderr = Join-Path $script:WorkRoot ($Label + '.stderr.log')
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = ConvertTo-CanonicalPath $FilePath
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    if ($StrictWindowsBootstrapEnvironment) {
        $start.Environment.Clear()
        $bootstrapEnvironment = [ordered]@{
            SystemRoot = $script:WindowsDirectory
            windir = $script:WindowsDirectory
            ProgramFiles = $script:KnownProgramFiles
            ProgramData = $script:KnownProgramData
            ComSpec = Join-Path $script:System32 'cmd.exe'
            PATH = @(
                $script:System32,
                $script:WindowsDirectory,
                (Join-Path $script:System32 'Wbem'),
                (Join-Path $script:System32 'WindowsPowerShell\v1.0')
            ) -join [IO.Path]::PathSeparator
            PSModulePath = Join-Path `
                $script:System32 `
                'WindowsPowerShell\v1.0\Modules'
            TEMP = $script:WorkRoot
            TMP = $script:WorkRoot
        }
        foreach ($entry in $bootstrapEnvironment.GetEnumerator()) {
            $start.Environment[[string]$entry.Key] = [string]$entry.Value
        }
    }
    foreach ($argument in $ArgumentList) {
        $start.ArgumentList.Add([string]$argument)
    }
    foreach ($entry in $Environment.GetEnumerator()) {
        if ($null -eq $entry.Value) {
            $null = $start.Environment.Remove([string]$entry.Key)
        } else {
            $start.Environment[[string]$entry.Key] = [string]$entry.Value
        }
    }

    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    if (-not $process.Start()) {
        throw "$Label failed to start"
    }
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    try {
        if ($null -eq $DuringExecution) {
            if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
                try { $process.Kill($true) } catch {}
                throw "$Label timed out after $TimeoutSeconds seconds"
            }
        } else {
            $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
            while (-not $process.HasExited -and
                [DateTimeOffset]::UtcNow -lt $deadline) {
                $null = & $DuringExecution $process
                Start-Sleep -Milliseconds $ExecutionPollMilliseconds
                $process.Refresh()
            }
            if (-not $process.HasExited) {
                try { $process.Kill($true) } catch {}
                throw "$Label timed out after $TimeoutSeconds seconds"
            }
            $process.WaitForExit()
        }
        $stdoutText = $stdoutTask.GetAwaiter().GetResult()
        $stderrText = $stderrTask.GetAwaiter().GetResult()
        $exitCode = $process.ExitCode
    } catch {
        try {
            if (-not $process.HasExited) {
                $process.Kill($true)
            }
        } catch {}
        throw
    } finally {
        $process.Dispose()
    }
    [IO.File]::WriteAllText($stdout, $stdoutText, [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText($stderr, $stderrText, [Text.UTF8Encoding]::new($false))
    if ($AllowedExitCodes -notcontains $exitCode) {
        throw "$Label exited $exitCode; expected $($AllowedExitCodes -join ', '). stderr: $(Protect-SensitiveDisplayText $stderrText)"
    }
    return [pscustomobject]@{
        ExitCode = $exitCode
        StdOut = $stdoutText
        StdErr = $stderrText
        StdOutPath = $stdout
        StdErrPath = $stderr
    }
}

function Set-ICaclsOwnerAndDacl {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Owner,
        [Parameter(Mandatory)][string[]]$Grants,
        [Parameter(Mandatory)][string]$Label,
        [string[]]$Options = @()
    )
    $icacls = Join-Path $script:System32 'icacls.exe'
    $null = Invoke-NativeProcess `
        -FilePath $icacls `
        -ArgumentList (@($Path, '/setowner', $Owner) + @($Options)) `
        -Label ($Label + '-owner')
    return Invoke-NativeProcess `
        -FilePath $icacls `
        -ArgumentList (
            @($Path, '/inheritance:r', '/grant:r') +
            @($Grants) +
            @($Options)
        ) `
        -Label $Label
}

function Invoke-UserPowerShell {
    param(
        [Parameter(Mandatory)][Management.Automation.PSCredential]$Credential,
        [Parameter(Mandatory)][string]$Script,
        [Parameter(Mandatory)][string]$Label,
        [int[]]$AllowedExitCodes = @(0),
        [int]$TimeoutSeconds = 120
    )

    $stdout = Join-Path $script:WorkRoot ($Label + '.stdout.log')
    $stderr = Join-Path $script:WorkRoot ($Label + '.stderr.log')
    $payload = Join-Path $script:WorkRoot (
        $Label + '-' + [Guid]::NewGuid().ToString('N') + '.user-script.ps1'
    )
    if (Test-Path -LiteralPath $payload) {
        throw "$Label user-script payload already exists"
    }
    [IO.File]::WriteAllText(
        $payload,
        $Script,
        [Text.UTF8Encoding]::new($false)
    )
    $targetSID = (
        [Security.Principal.NTAccount]::new($Credential.UserName)
    ).Translate([Security.Principal.SecurityIdentifier]).Value
    $null = Set-ICaclsOwnerAndDacl `
        -Path $payload `
        -Owner '*S-1-5-32-544' `
        -Grants @(
            '*S-1-5-18:F',
            '*S-1-5-32-544:F',
            ('*' + $targetSID + ':RX')
        ) `
        -Label ($Label + '-user-script-acl')
    $payloadSHA256 = Get-FileDigest $payload
    $arguments = (
        '-NoLogo -NoProfile -NonInteractive -File "' +
        $payload +
        '"'
    )
    if (($script:PowerShellExecutable.Length + $arguments.Length + 4) -ge 1024) {
        throw "$Label alternate-user command line exceeds the Windows limit"
    }
    $exitCode = $null
    try {
        $process = Start-Process `
            -FilePath $script:PowerShellExecutable `
            -ArgumentList $arguments `
            -WorkingDirectory $script:System32 `
            -Credential $Credential `
            -LoadUserProfile `
            -WindowStyle Hidden `
            -RedirectStandardOutput $stdout `
            -RedirectStandardError $stderr `
            -PassThru
        try {
            if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
                try { $process.Kill($true) } catch {}
                throw "$Label timed out after $TimeoutSeconds seconds"
            }
            $process.Refresh()
            $exitCode = $process.ExitCode
        } finally {
            $process.Dispose()
        }
    } finally {
        if (-not (Test-Path -LiteralPath $payload -PathType Leaf)) {
            throw "$Label user-script payload disappeared"
        }
        $payloadSHA256After = Get-FileDigest $payload
        Protect-AdministratorFile `
            $payload `
            ($Label + '-user-script-seal')
        if ($payloadSHA256After -cne $payloadSHA256) {
            throw "$Label user-script payload changed during execution"
        }
    }
    $stdoutText = if (Test-Path -LiteralPath $stdout) {
        [IO.File]::ReadAllText($stdout)
    } else { '' }
    $stderrText = if (Test-Path -LiteralPath $stderr) {
        [IO.File]::ReadAllText($stderr)
    } else { '' }
    if ($AllowedExitCodes -notcontains $exitCode) {
        throw "$Label exited $exitCode; expected $($AllowedExitCodes -join ', '). stderr: $(Protect-SensitiveDisplayText $stderrText)"
    }
    return [pscustomobject]@{
        ExitCode = $exitCode
        StdOut = $stdoutText
        StdErr = $stderrText
        StdOutPath = $stdout
        StdErrPath = $stderr
    }
}

function ConvertFrom-SingleJSONDocument([string]$Text, [string]$Label) {
    $trimmed = $Text.Trim()
    if ([string]::IsNullOrWhiteSpace($trimmed)) {
        throw "$Label emitted no JSON"
    }
    try {
        return $trimmed | ConvertFrom-Json -ErrorAction Stop
    } catch {
        throw "$Label emitted invalid JSON: $($_.Exception.Message); output: $(Protect-SensitiveDisplayText $trimmed)"
    }
}

function Wait-Until {
    param(
        [Parameter(Mandatory)][scriptblock]$Condition,
        [Parameter(Mandatory)][string]$Description,
        [int]$TimeoutSeconds = $RepairTimeoutSeconds,
        [int]$PollMilliseconds = 500
    )
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
    $last = ''
    do {
        try {
            $value = & $Condition
            if ($value) { return $value }
        } catch {
            $last = $_.Exception.Message
        }
        Start-Sleep -Milliseconds $PollMilliseconds
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    if (-not [string]::IsNullOrWhiteSpace($last)) {
        throw "timed out waiting for $Description; last error: $last"
    }
    throw "timed out waiting for $Description"
}

function Test-IsElevatedAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Initialize-WTSInterop {
    if ($null -ne ('DefenseClaw.Certification.WTSNative' -as [type])) {
        return
    }
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

namespace DefenseClaw.Certification {
    public enum WTSConnectState {
        Active = 0,
        Connected = 1,
        ConnectQuery = 2,
        Shadow = 3,
        Disconnected = 4,
        Idle = 5,
        Listen = 6,
        Reset = 7,
        Down = 8,
        Init = 9
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WTSSessionInfo {
        public int SessionId;
        public IntPtr WindowStationName;
        public WTSConnectState State;
    }

    public static class WTSNative {
        [DllImport("wtsapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool WTSEnumerateSessionsW(
            IntPtr server,
            int reserved,
            int version,
            out IntPtr sessions,
            out int count);

        [DllImport("wtsapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool WTSQuerySessionInformationW(
            IntPtr server,
            int sessionId,
            int infoClass,
            out IntPtr buffer,
            out int bytesReturned);

        [DllImport("wtsapi32.dll")]
        public static extern void WTSFreeMemory(IntPtr memory);
    }
}
'@
}

function Get-WTSSessionText([int]$SessionID, [int]$InformationClass) {
    $buffer = [IntPtr]::Zero
    $bytes = 0
    try {
        if (-not [DefenseClaw.Certification.WTSNative]::WTSQuerySessionInformationW(
            [IntPtr]::Zero,
            $SessionID,
            $InformationClass,
            [ref]$buffer,
            [ref]$bytes
        )) {
            return ''
        }
        if ($buffer -eq [IntPtr]::Zero -or $bytes -le 2) {
            return ''
        }
        return [Runtime.InteropServices.Marshal]::PtrToStringUni($buffer)
    } finally {
        if ($buffer -ne [IntPtr]::Zero) {
            [DefenseClaw.Certification.WTSNative]::WTSFreeMemory($buffer)
        }
    }
}

function Get-ActiveWTSSessions {
    Initialize-WTSInterop
    $buffer = [IntPtr]::Zero
    $count = 0
    if (-not [DefenseClaw.Certification.WTSNative]::WTSEnumerateSessionsW(
        [IntPtr]::Zero,
        0,
        1,
        [ref]$buffer,
        [ref]$count
    )) {
        $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw "WTSEnumerateSessionsW failed with Win32 error $errorCode"
    }
    try {
        $size = [Runtime.InteropServices.Marshal]::SizeOf(
            [type][DefenseClaw.Certification.WTSSessionInfo]
        )
        $sessions = [Collections.Generic.List[object]]::new()
        for ($index = 0; $index -lt $count; $index++) {
            $pointer = [IntPtr]::Add($buffer, $index * $size)
            $row = [Runtime.InteropServices.Marshal]::PtrToStructure(
                $pointer,
                [type][DefenseClaw.Certification.WTSSessionInfo]
            )
            if ($row.State -ne [DefenseClaw.Certification.WTSConnectState]::Active) {
                continue
            }
            # WTSUserName=5 and WTSDomainName=7.
            $user = Get-WTSSessionText $row.SessionId 5
            $domain = Get-WTSSessionText $row.SessionId 7
            if ([string]::IsNullOrWhiteSpace($user)) {
                continue
            }
            $account = if ([string]::IsNullOrWhiteSpace($domain)) {
                $user
            } else {
                "$domain\$user"
            }
            try {
                $sid = ([Security.Principal.NTAccount]$account).Translate(
                    [Security.Principal.SecurityIdentifier]
                ).Value
            } catch {
                continue
            }
            $sessions.Add([pscustomobject]@{
                session_id = [int]$row.SessionId
                account = $account
                sid = $sid
            })
        }
        return $sessions.ToArray()
    } finally {
        if ($buffer -ne [IntPtr]::Zero) {
            [DefenseClaw.Certification.WTSNative]::WTSFreeMemory($buffer)
        }
    }
}

function Resolve-ProtectedActiveUser([string]$ExplicitSID) {
    $sessions = @(Get-ActiveWTSSessions)
    $matches = if ([string]::IsNullOrWhiteSpace($ExplicitSID)) {
        $sessions
    } else {
        @($sessions | Where-Object { [string]$_.sid -eq $ExplicitSID.Trim() })
    }
    if ($matches.Count -ne 1) {
        $active = @($sessions | ForEach-Object {
            "$($_.account)[$($_.sid)]/session=$($_.session_id)"
        }) -join ', '
        throw "certification requires exactly one matching WTSActive user session; requested SID='$ExplicitSID'; observed: $active"
    }
    $sid = [string]$matches[0].sid
    $profileKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid"
    $profileValue = Get-ItemPropertyValue `
        -LiteralPath $profileKey `
        -Name ProfileImagePath `
        -ErrorAction Stop
    $profile = ConvertTo-CanonicalPath $profileValue
    if (-not (Test-Path -LiteralPath $profile -PathType Container)) {
        throw "active protected profile is missing: $profile"
    }
    return [pscustomobject]@{
        account = $matches[0].account
        sid = $sid
        profile = $profile
        session_id = [int]$matches[0].session_id
    }
}

function Initialize-ActiveUserHandoff {
    $script:ActiveUserHandoffRoot = Assert-PathBelow `
        (Join-Path $script:WorkRoot 'active-user-handoff') `
        $script:WorkRoot `
        'active-user handoff'
    [IO.Directory]::CreateDirectory($script:ActiveUserHandoffRoot) | Out-Null
    $null = Set-ICaclsOwnerAndDacl `
        -Path $script:ActiveUserHandoffRoot `
        -Owner '*S-1-5-32-544' `
        -Grants @(
            '*S-1-5-18:(OI)(CI)F',
            '*S-1-5-32-544:(OI)(CI)F',
            "*$($script:PrimarySID):(OI)(CI)M"
        ) `
        -Label 'protect-active-user-handoff'
}

function Initialize-ActiveUserCapturePipeNative {
    if ($null -ne (
        'DefenseClaw.Certification.ActiveUserCapturePipeNative' -as [type]
    )) {
        return
    }
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace DefenseClaw.Certification
{
    public static class ActiveUserCapturePipeNative
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetNamedPipeClientProcessId(
            SafePipeHandle pipe,
            out UInt32 clientProcessId);

        public static UInt32 ClientProcessId(SafePipeHandle pipe)
        {
            UInt32 processId;
            if (!GetNamedPipeClientProcessId(pipe, out processId))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "GetNamedPipeClientProcessId failed");
            }
            return processId;
        }
    }
}
'@
}

function New-ProtectedActiveUserCapturePipe([string]$Name) {
    Initialize-ActiveUserCapturePipeNative
    if ($Name -cnotmatch '^DefenseClawCert\.[a-f0-9]{10}\.[a-f0-9]{32}$') {
        throw "unsafe active-user capture pipe name: $Name"
    }
    $security = [IO.Pipes.PipeSecurity]::new()
    $security.SetAccessRuleProtection($true, $false)
    $administrators = [Security.Principal.SecurityIdentifier]::new(
        'S-1-5-32-544'
    )
    $system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $target = [Security.Principal.SecurityIdentifier]::new(
        $script:PrimarySID
    )
    $security.SetOwner($administrators)
    $security.SetGroup($administrators)
    foreach ($identity in @($system, $administrators)) {
        $security.AddAccessRule([IO.Pipes.PipeAccessRule]::new(
            $identity,
            [IO.Pipes.PipeAccessRights]::FullControl,
            [Security.AccessControl.AccessControlType]::Allow
        ))
    }
    $targetRights = (
        [IO.Pipes.PipeAccessRights]::ReadWrite -bor
        [IO.Pipes.PipeAccessRights]::Synchronize
    )
    $security.AddAccessRule([IO.Pipes.PipeAccessRule]::new(
        $target,
        $targetRights,
        [Security.AccessControl.AccessControlType]::Allow
    ))
    $arguments = @(
        $Name,
        [IO.Pipes.PipeDirection]::InOut,
        1,
        [IO.Pipes.PipeTransmissionMode]::Byte,
        [IO.Pipes.PipeOptions]::Asynchronous,
        65536,
        65536,
        $security,
        [IO.HandleInheritability]::None,
        [IO.Pipes.PipeAccessRights]0
    )
    $aclFactory = 'System.IO.Pipes.NamedPipeServerStreamAcl' -as [type]
    if ($null -ne $aclFactory) {
        $method = @(
            $aclFactory.GetMethods() |
                Where-Object {
                    $_.Name -eq 'Create' -and
                    $_.GetParameters().Count -eq 10
                }
        )
        if ($method.Count -ne 1) {
            throw 'cannot resolve the protected named-pipe ACL factory'
        }
        return $method[0].Invoke($null, $arguments)
    }
    return [IO.Pipes.NamedPipeServerStream]::new(
        [string]$arguments[0],
        [IO.Pipes.PipeDirection]$arguments[1],
        [int]$arguments[2],
        [IO.Pipes.PipeTransmissionMode]$arguments[3],
        [IO.Pipes.PipeOptions]$arguments[4],
        [int]$arguments[5],
        [int]$arguments[6],
        [IO.Pipes.PipeSecurity]$arguments[7],
        [IO.HandleInheritability]$arguments[8],
        [IO.Pipes.PipeAccessRights]$arguments[9]
    )
}

function Get-ScheduledTaskEngineProcessIDs([string]$TaskName) {
    $service = $null
    $folder = $null
    $task = $null
    $instances = @()
    try {
        $service = New-Object -ComObject 'Schedule.Service'
        $service.Connect()
        $folder = $service.GetFolder('\')
        $task = $folder.GetTask($TaskName)
        $instances = @($task.GetInstances(0))
        return @($instances | ForEach-Object { [uint32]$_.EnginePID })
    } finally {
        foreach ($instance in $instances) {
            try {
                [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject(
                    $instance
                )
            } catch {}
        }
        foreach ($value in @($task, $folder, $service)) {
            if ($null -ne $value) {
                try {
                    [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject(
                        $value
                    )
                } catch {}
            }
        }
    }
}

function Assert-CertificationScheduledTaskName([string]$TaskName) {
    if ($script:RunToken -cnotmatch '^[a-f0-9]{10}$') {
        throw "unsafe certification run token: $($script:RunToken)"
    }
    $pattern = (
        '^DefenseClawCert_' +
        [regex]::Escape($script:RunToken) +
        '_[A-Za-z0-9_.-]+_[a-f0-9]{8}$'
    )
    if ([string]::IsNullOrWhiteSpace($TaskName) -or
        $TaskName.Length -gt 238 -or
        $TaskName -cnotmatch $pattern) {
        throw "unsafe certification scheduled-task name: $TaskName"
    }
    return $TaskName
}

function New-ActiveUserScheduledTaskPrincipal {
    if ([string]::IsNullOrWhiteSpace($script:PrimarySID) -or
        $script:PrimarySessionID -le 0) {
        throw 'active-user scheduled-task identity is not initialized'
    }
    $principal = New-ScheduledTaskPrincipal `
        -UserId $script:PrimarySID `
        -LogonType Interactive `
        -RunLevel Limited
    try {
        $resolvedSID = (
            [Security.Principal.NTAccount]([string]$principal.UserId)
        ).Translate([Security.Principal.SecurityIdentifier]).Value
    } catch {
        throw (
            'Task Scheduler did not canonicalize the active-user SID to ' +
            "a resolvable account: $($_.Exception.Message)"
        )
    }
    if ($resolvedSID -cne $script:PrimarySID) {
        throw (
            'Task Scheduler canonicalized the active-user principal to ' +
            "unexpected SID $resolvedSID"
        )
    }
    return $principal
}

function Start-CertificationScheduledTaskInActiveSession(
    [string]$TaskName,
    [ValidateRange(5, 60)][int]$TimeoutSeconds = 30
) {
    $safeTaskName = Assert-CertificationScheduledTaskName $TaskName
    if (-not $script:ScheduledTasks.Contains($safeTaskName)) {
        throw (
            'refusing to start an untracked certification scheduled task: ' +
            $safeTaskName
        )
    }
    $active = @(
        Get-ActiveWTSSessions |
            Where-Object {
                [int]$_.session_id -eq $script:PrimarySessionID -and
                [string]$_.sid -ceq $script:PrimarySID
            }
    )
    if ($active.Count -ne 1) {
        throw (
            'the exact protected user is no longer active in WTS session ' +
            $script:PrimarySessionID
        )
    }
    $service = $folder = $task = $running = $process = $null
    $enginePID = [uint32]0
    try {
        $service = New-Object -ComObject 'Schedule.Service'
        $service.Connect()
        $folder = $service.GetFolder('\')
        $task = $folder.GetTask($safeTaskName)
        # TASK_RUN_USE_SESSION_ID | TASK_RUN_USER_SID. Never let an elevated
        # caller make Task Scheduler rediscover the target from a display name
        # or choose a different interactive session.
        $running = $task.RunEx(
            $null,
            [int]0x0C,
            [int]$script:PrimarySessionID,
            $script:PrimarySID
        )
        $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
        do {
            try {
                $enginePID = [uint32]$running.EnginePID
                if ($enginePID -gt 0) {
                    $process = Get-CimInstance `
                        Win32_Process `
                        -Filter "ProcessId=$enginePID" `
                        -ErrorAction Stop
                    break
                }
            } catch {}
            Start-Sleep -Milliseconds 50
        } while ([DateTimeOffset]::UtcNow -lt $deadline)
        if ($null -eq $process) {
            $taskInfo = Get-ScheduledTaskInfo `
                -TaskName $safeTaskName `
                -TaskPath '\' `
                -ErrorAction Stop
            $resultValue = [uint32](
                [int64]$taskInfo.LastTaskResult -band [int64]0xFFFFFFFFL
            )
            throw (
                "scheduled task $safeTaskName did not start; state=" +
                "$([string]$running.State); engine_pid=$enginePID; " +
                ('last_result=0x{0:X8}' -f $resultValue)
            )
        }
        if ([string]::IsNullOrWhiteSpace([string]$process.ExecutablePath) -or
            -not [string]::Equals(
                (ConvertTo-CanonicalPath ([string]$process.ExecutablePath)),
                (ConvertTo-CanonicalPath $script:PowerShellExecutable),
                [StringComparison]::OrdinalIgnoreCase
            ) -or
            [uint32]$process.SessionId -ne
                [uint32]$script:PrimarySessionID) {
            throw (
                "scheduled task $safeTaskName did not start the exact " +
                'PowerShell image in the protected WTS session'
            )
        }
        return [pscustomobject]@{
            EnginePID = $enginePID
            InstanceGuid = [string]$running.InstanceGuid
            SessionID = [int]$script:PrimarySessionID
            UserSID = $script:PrimarySID
        }
    } finally {
        foreach ($value in @($running, $task, $folder, $service)) {
            if ($null -ne $value) {
                try {
                    [void][Runtime.InteropServices.Marshal]::
                        FinalReleaseComObject($value)
                } catch {}
            }
        }
    }
}

function Remove-CertificationScheduledTask([string]$TaskName) {
    $safeTaskName = Assert-CertificationScheduledTaskName $TaskName
    if (-not $script:ScheduledTasks.Contains($safeTaskName)) {
        throw (
            'refusing to remove an untracked certification scheduled task: ' +
            $safeTaskName
        )
    }
    $enginePIDs = [uint32[]]@(
        Get-ScheduledTaskEngineProcessIDs $safeTaskName
    )
    try {
        Stop-ScheduledTask `
            -TaskName $safeTaskName `
            -TaskPath '\' `
            -ErrorAction Stop
    } catch {
        # Stopping is best-effort; unregistering and proving absence are not.
    }
    Unregister-ScheduledTask `
        -TaskName $safeTaskName `
        -TaskPath '\' `
        -Confirm:$false `
        -ErrorAction Stop
    $remaining = @(
        Get-ScheduledTask -ErrorAction Stop |
            Where-Object {
                [string]$_.TaskName -ceq $safeTaskName -and
                [string]$_.TaskPath -ceq '\'
            }
    )
    if ($remaining.Count -ne 0) {
        throw (
            'certification scheduled task remains after unregister: ' +
            $safeTaskName
        )
    }
    $engineDeadline = [DateTimeOffset]::UtcNow.AddSeconds(30)
    do {
        $remainingEnginePIDs = @(
            foreach ($enginePID in $enginePIDs) {
                try {
                    $engineProcess = [Diagnostics.Process]::GetProcessById(
                        [int]$enginePID
                    )
                    try {
                        if (-not $engineProcess.HasExited) {
                            $enginePID
                        }
                    } finally {
                        $engineProcess.Dispose()
                    }
                } catch [ArgumentException] {}
            }
        )
        if ($remainingEnginePIDs.Count -eq 0) {
            break
        }
        Start-Sleep -Milliseconds 100
    } while ([DateTimeOffset]::UtcNow -lt $engineDeadline)
    if ($remainingEnginePIDs.Count -ne 0) {
        throw (
            'certification scheduled-task engines remain after cleanup: ' +
            ($remainingEnginePIDs -join ',')
        )
    }
    if (-not $script:ScheduledTasks.Remove($safeTaskName)) {
        throw (
            'certification scheduled-task tracking removal failed: ' +
            $safeTaskName
        )
    }
}

function Assert-ProtectedActiveUserCaptureTaskSecurity([string]$TaskName) {
    $service = $null
    $folder = $null
    $task = $null
    try {
        $service = New-Object -ComObject 'Schedule.Service'
        $service.Connect()
        $folder = $service.GetFolder('\')
        $task = $folder.GetTask($TaskName)
        $sddl = [string]$task.GetSecurityDescriptor(7)
        $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new(
            $sddl
        )
        if ($null -eq $descriptor.Owner -or
            $descriptor.Owner.Value -cne 'S-1-5-32-544' -or
            $null -eq $descriptor.Group -or
            $descriptor.Group.Value -cne 'S-1-5-32-544' -or
            0 -eq (
                $descriptor.ControlFlags -band
                [Security.AccessControl.ControlFlags]::
                    DiscretionaryAclProtected
            )) {
            throw (
                'active-user capture task is not owned by Administrators ' +
                'with a protected DACL'
            )
        }
        $aces = @($descriptor.DiscretionaryAcl)
        if ($aces.Count -ne 3) {
            throw (
                'active-user capture task has an unexpected ACE count: ' +
                $aces.Count
            )
        }
        $expectedMasks = @{
            'S-1-5-18' = [uint32]0x001F01FF
            'S-1-5-32-544' = [uint32]0x001F01FF
            $script:PrimarySID = [uint32]0x001200A9
        }
        $seen = [Collections.Generic.HashSet[string]]::new(
            [StringComparer]::Ordinal
        )
        foreach ($ace in $aces) {
            if ($ace -isnot [Security.AccessControl.CommonAce] -or
                $ace.AceQualifier -ne
                    [Security.AccessControl.AceQualifier]::AccessAllowed -or
                $ace.AceFlags -ne
                    [Security.AccessControl.AceFlags]::None) {
                throw 'active-user capture task has a non-canonical ACE'
            }
            $sid = $ace.SecurityIdentifier.Value
            if (-not $expectedMasks.ContainsKey($sid) -or
                -not $seen.Add($sid)) {
                throw (
                    'active-user capture task grants an unexpected or ' +
                    "duplicate SID: $sid"
                )
            }
            $mask = [uint32](
                [int64]$ace.AccessMask -band [int64]0xFFFFFFFFL
            )
            if ($mask -ne [uint32]$expectedMasks[$sid]) {
                throw (
                    "active-user capture task grants SID $sid mask " +
                    ('0x{0:X8}' -f $mask) +
                    ' instead of the exact required mask'
                )
            }
        }
        if ($seen.Count -ne $expectedMasks.Count) {
            throw 'active-user capture task omitted a required SID'
        }
    } finally {
        foreach ($value in @($task, $folder, $service)) {
            if ($null -ne $value) {
                try {
                    [void][Runtime.InteropServices.Marshal]::
                        FinalReleaseComObject($value)
                } catch {}
            }
        }
    }
}

function Read-ExactActiveUserCapturePipe(
    [IO.Pipes.NamedPipeServerStream]$Pipe,
    [int]$Length,
    [DateTimeOffset]$Deadline,
    [string]$Label
) {
    if ($Length -lt 0) {
        throw "$Label requested a negative pipe read"
    }
    $buffer = [byte[]]::new($Length)
    $offset = 0
    while ($offset -lt $Length) {
        $remaining = [int][Math]::Ceiling(
            ($Deadline - [DateTimeOffset]::UtcNow).TotalMilliseconds
        )
        if ($remaining -le 0) {
            throw "$Label timed out reading the authenticated capture pipe"
        }
        $read = $Pipe.ReadAsync($buffer, $offset, $Length - $offset)
        if (-not $read.Wait($remaining)) {
            throw "$Label timed out reading the authenticated capture pipe"
        }
        $count = [int]$read.GetAwaiter().GetResult()
        if ($count -le 0) {
            throw "$Label authenticated capture pipe closed early"
        }
        $offset += $count
    }
    return $buffer
}

function Invoke-ActiveUserPowerShell {
    param(
        [Parameter(Mandatory)][string]$Script,
        [Parameter(Mandatory)][string]$Label,
        [int[]]$AllowedExitCodes = @(0),
        [int]$TimeoutSeconds = 120
    )
    if ([string]::IsNullOrWhiteSpace($script:ActiveUserHandoffRoot)) {
        throw 'active-user handoff is not initialized'
    }
    $safeLabel = ($Label -replace '[^A-Za-z0-9_.-]', '_')
    if ($safeLabel.Length -gt 48) {
        $safeLabel = $safeLabel.Substring(0, 48)
    }
    $nonce = [Guid]::NewGuid().ToString('N')
    $pipeName = "DefenseClawCert.$($script:RunToken).$nonce"
    $maximumCaptureBytes = 8 * 1024 * 1024
    $server = New-ProtectedActiveUserCapturePipe $pipeName
    $taskName = ''
    $transportRoot = ''
    try {
        $transportRoot = Assert-PathBelow `
            (Join-Path $script:WorkRoot "active-user-task-$nonce") `
            $script:WorkRoot `
            "$Label active-user task transport"
        if (Test-Path -LiteralPath $transportRoot) {
            throw "$Label active-user task transport already exists"
        }
        [IO.Directory]::CreateDirectory($transportRoot) | Out-Null
        $null = Set-ICaclsOwnerAndDacl `
            -Path $transportRoot `
            -Owner '*S-1-5-32-544' `
            -Grants @(
                '*S-1-5-18:(OI)(CI)F',
                '*S-1-5-32-544:(OI)(CI)F',
                "*$($script:PrimarySID):(OI)(CI)RX"
            ) `
            -Label (
                $safeLabel +
                '-' +
                $nonce.Substring(0, 8) +
                '-active-user-task-transport'
            )
        Assert-NoStandardUserAccess `
            -Path $transportRoot `
            -SID $script:PrimarySID `
            -DenyWrite
        $scriptPath = Join-Path $transportRoot 'payload.ps1'
        [IO.File]::WriteAllText(
            $scriptPath,
            $Script,
            [Text.UTF8Encoding]::new($false)
        )
        $scriptItem = Get-Item -LiteralPath $scriptPath -Force
        if ($scriptItem.PSIsContainer -or
            ($scriptItem.Attributes -band
                [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "$Label active-user script payload is unsafe"
        }
        Assert-NoStandardUserAccess `
            -Path $scriptPath `
            -SID $script:PrimarySID `
            -DenyWrite
        $scriptSHA256 = Get-FileDigest $scriptPath
        if ([string]::IsNullOrWhiteSpace($scriptSHA256)) {
            throw "$Label active-user script payload has no digest"
        }
        $payload = [ordered]@{
        executable = $script:PowerShellExecutable
        script_path = $scriptPath
        script_sha256 = $scriptSHA256
        script_length = $scriptItem.Length
        pipe_name = $pipeName
        nonce = $nonce
        timeout_seconds = $TimeoutSeconds
        maximum_capture_bytes = $maximumCaptureBytes
    }
    $payloadBase64 = [Convert]::ToBase64String(
        [Text.Encoding]::UTF8.GetBytes(($payload | ConvertTo-Json -Compress))
    )
    $wrapper = @'
$ErrorActionPreference = 'Stop'
$payload = [Text.Encoding]::UTF8.GetString(
    [Convert]::FromBase64String('__PAYLOAD__')
) | ConvertFrom-Json -ErrorAction Stop
$pipe = $null
$exitCode = 255
$errorText = ''
$stdoutText = ''
$stderrText = ''
try {
    $pipe = [IO.Pipes.NamedPipeClientStream]::new(
        '.',
        [string]$payload.pipe_name,
        [IO.Pipes.PipeDirection]::InOut,
        [IO.Pipes.PipeOptions]::None
    )
    $pipe.Connect(30000)
    if ($pipe.ReadByte() -ne 1) {
        throw 'elevated coordinator rejected the exact scheduled-task PID'
    }
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = [string]$payload.executable
    $scriptPath = [IO.Path]::GetFullPath([string]$payload.script_path)
    if ($scriptPath.IndexOf('"') -ge 0) {
        throw 'active-user script path contains an unsafe quote'
    }
    $scriptItem = Get-Item -LiteralPath $scriptPath -Force -ErrorAction Stop
    if ($scriptItem.PSIsContainer -or
        ($scriptItem.Attributes -band
            [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        [int64]$scriptItem.Length -ne [int64]$payload.script_length) {
        throw 'active-user script payload failed path/type/length validation'
    }
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $actualScriptSHA256 = (
            [BitConverter]::ToString(
                $sha.ComputeHash([IO.File]::ReadAllBytes($scriptPath))
            )
        ).Replace('-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
    if ($actualScriptSHA256 -cne
        ([string]$payload.script_sha256).ToLowerInvariant()) {
        throw 'active-user script payload failed digest validation'
    }
    $start.Arguments = (
        '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' +
        $scriptPath +
        '"'
    )
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.WindowStyle = [Diagnostics.ProcessWindowStyle]::Hidden
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    try {
        if (-not $process.Start()) {
            throw 'nested active-user probe did not start'
        }
        $stdoutBuilder = [Text.StringBuilder]::new()
        $stderrBuilder = [Text.StringBuilder]::new()
        $stdoutBuffer = [char[]]::new(4096)
        $stderrBuffer = [char[]]::new(4096)
        $stdoutRead = $process.StandardOutput.ReadAsync(
            $stdoutBuffer,
            0,
            $stdoutBuffer.Length
        )
        $stderrRead = $process.StandardError.ReadAsync(
            $stderrBuffer,
            0,
            $stderrBuffer.Length
        )
        $capturedBytes = 0
        $captureExceeded = $false
        $timedOut = $false
        $readError = ''
        $deadline = [DateTimeOffset]::UtcNow.AddSeconds(
            [int]$payload.timeout_seconds
        )
        while ($null -ne $stdoutRead -or $null -ne $stderrRead) {
            $pending = [Collections.Generic.List[Threading.Tasks.Task]]::new()
            $sources = [Collections.Generic.List[string]]::new()
            if ($null -ne $stdoutRead) {
                $pending.Add($stdoutRead)
                $sources.Add('stdout')
            }
            if ($null -ne $stderrRead) {
                $pending.Add($stderrRead)
                $sources.Add('stderr')
            }
            $remaining = [int][Math]::Ceiling(
                ($deadline - [DateTimeOffset]::UtcNow).TotalMilliseconds
            )
            if ($remaining -le 0) {
                $timedOut = $true
                break
            }
            $completedIndex = [Threading.Tasks.Task]::WaitAny(
                $pending.ToArray(),
                $remaining
            )
            if ($completedIndex -lt 0) {
                $timedOut = $true
                break
            }
            $source = $sources[$completedIndex]
            try {
                $count = [int]$pending[$completedIndex].
                    GetAwaiter().GetResult()
            } catch {
                $readError = $_.Exception.Message
                break
            }
            if ($count -eq 0) {
                if ($source -ceq 'stdout') {
                    $stdoutRead = $null
                } else {
                    $stderrRead = $null
                }
                continue
            }
            $buffer = if ($source -ceq 'stdout') {
                $stdoutBuffer
            } else {
                $stderrBuffer
            }
            $chunk = [string]::new($buffer, 0, $count)
            $capturedBytes += [Text.Encoding]::UTF8.GetByteCount($chunk)
            if ($capturedBytes -gt [int]$payload.maximum_capture_bytes) {
                $captureExceeded = $true
                break
            }
            if ($source -ceq 'stdout') {
                [void]$stdoutBuilder.Append($chunk)
                $stdoutRead = $process.StandardOutput.ReadAsync(
                    $stdoutBuffer,
                    0,
                    $stdoutBuffer.Length
                )
            } else {
                [void]$stderrBuilder.Append($chunk)
                $stderrRead = $process.StandardError.ReadAsync(
                    $stderrBuffer,
                    0,
                    $stderrBuffer.Length
                )
            }
        }
        if ($timedOut -or $captureExceeded -or
            -not [string]::IsNullOrWhiteSpace($readError)) {
            try { $process.Kill() } catch {}
            try { $process.WaitForExit(10000) | Out-Null } catch {}
            if ($captureExceeded) {
                $exitCode = 253
                $errorText = 'active-user capture exceeded its bounded payload'
            } elseif ($timedOut) {
                $exitCode = 254
                $errorText = 'nested active-user probe timed out'
            } else {
                $exitCode = 252
                $errorText = "nested active-user capture failed: $readError"
            }
        } else {
            $remaining = [int][Math]::Ceiling(
                ($deadline - [DateTimeOffset]::UtcNow).TotalMilliseconds
            )
            if ($remaining -le 0 -or -not $process.WaitForExit($remaining)) {
                try { $process.Kill() } catch {}
                try { $process.WaitForExit(10000) | Out-Null } catch {}
                $exitCode = 254
                $errorText = 'nested active-user probe timed out'
            } else {
                $process.Refresh()
                $exitCode = $process.ExitCode
            }
        }
        $stdoutText = $stdoutBuilder.ToString()
        $stderrText = $stderrBuilder.ToString()
    } finally {
        $process.Dispose()
    }
} catch {
    $errorText = $_.Exception.Message
} finally {
    if ($null -ne $pipe -and $pipe.IsConnected) {
        $result = [pscustomobject]@{
            schema_version = 1
            ok = [string]::IsNullOrWhiteSpace($errorText)
            sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
            pid = [Diagnostics.Process]::GetCurrentProcess().Id
            nonce = [string]$payload.nonce
            exit_code = $exitCode
            wrapper_error = $errorText
            stdout = $stdoutText
            stderr = $stderrText
        }
        $bytes = [Text.Encoding]::UTF8.GetBytes(
            ($result | ConvertTo-Json -Compress -Depth 5)
        )
        if ($bytes.Length -gt [int]$payload.maximum_capture_bytes) {
            $bytes = [Text.Encoding]::UTF8.GetBytes(
                ([pscustomobject]@{
                    schema_version = 1
                    ok = $false
                    sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
                    pid = [Diagnostics.Process]::GetCurrentProcess().Id
                    nonce = [string]$payload.nonce
                    exit_code = 253
                    wrapper_error = 'active-user capture exceeded its bounded payload'
                    stdout = ''
                    stderr = ''
                } | ConvertTo-Json -Compress)
            )
        }
        $writer = [IO.BinaryWriter]::new(
            $pipe,
            [Text.Encoding]::UTF8,
            $true
        )
        try {
            $writer.Write([int]$bytes.Length)
            $writer.Write($bytes)
            $writer.Flush()
        } finally {
            $writer.Dispose()
        }
    }
    if ($null -ne $pipe) {
        $pipe.Dispose()
    }
}
if (-not [string]::IsNullOrWhiteSpace($errorText)) { exit 251 }
'@.Replace('__PAYLOAD__', $payloadBase64)
    $wrapperPath = Join-Path $transportRoot 'capture-wrapper.ps1'
    [IO.File]::WriteAllText(
        $wrapperPath,
        $wrapper,
        [Text.UTF8Encoding]::new($false)
    )
    $wrapperItem = Get-Item -LiteralPath $wrapperPath -Force
    if ($wrapperItem.PSIsContainer -or
        ($wrapperItem.Attributes -band
            [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Label active-user capture wrapper is unsafe"
    }
    Assert-NoStandardUserAccess `
        -Path $wrapperPath `
        -SID $script:PrimarySID `
        -DenyWrite
    $taskArguments = (
        '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' +
        $wrapperPath +
        '"'
    )
    if (($script:PowerShellExecutable.Length +
            $taskArguments.Length +
            4) -ge 1024) {
        throw "$Label active-user task command line exceeds its bound"
    }
    $taskName = "DefenseClawCert_$($script:RunToken)_$($safeLabel)_$($nonce.Substring(0, 8))"
    if ($taskName -notmatch '^DefenseClawCert_[a-f0-9]{10}_[A-Za-z0-9_.-]+_[a-f0-9]{8}$') {
        throw "unsafe scheduled-task name: $taskName"
    }
    $action = New-ScheduledTaskAction `
        -Execute $script:PowerShellExecutable `
        -Argument $taskArguments
    $principal = New-ActiveUserScheduledTaskPrincipal
    $settings = New-ScheduledTaskSettingsSet `
        -ExecutionTimeLimit ([TimeSpan]::FromSeconds($TimeoutSeconds + 30)) `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries
    $task = New-ScheduledTask -Action $action -Principal $principal -Settings $settings
    $taskSecurityDescriptor = (
        'O:BAG:BAD:P' +
        '(A;;FA;;;SY)' +
        '(A;;FA;;;BA)' +
        "(A;;FRFX;;;$($script:PrimarySID))"
    )
    $taskXML = [string](Export-ScheduledTask -InputObject $task)
    $scheduler = $null
    $folder = $null
    $registeredTask = $null
    try {
        $scheduler = New-Object -ComObject 'Schedule.Service'
        $scheduler.Connect()
        $folder = $scheduler.GetFolder('\')
        $registeredTask = $folder.RegisterTask(
            $taskName,
            $taskXML,
            [int]0x12,
            [string]$principal.UserId,
            $null,
            [int]3,
            $taskSecurityDescriptor
        )
    } finally {
        foreach ($value in @($registeredTask, $folder, $scheduler)) {
            if ($null -ne $value) {
                try {
                    [void][Runtime.InteropServices.Marshal]::
                        FinalReleaseComObject($value)
                } catch {}
            }
        }
    }
    $script:ScheduledTasks.Add($taskName)
        Assert-ProtectedActiveUserCaptureTaskSecurity $taskName
        $connection = $server.WaitForConnectionAsync()
        $launch = Start-CertificationScheduledTaskInActiveSession $taskName
        if (-not $connection.Wait(30000)) {
            $taskInfo = Get-ScheduledTaskInfo `
                -TaskName $taskName `
                -TaskPath '\' `
                -ErrorAction Stop
            $resultValue = [uint32](
                [int64]$taskInfo.LastTaskResult -band [int64]0xFFFFFFFFL
            )
            throw (
                "$Label active-user task PID $($launch.EnginePID) did not " +
                'connect to its capture pipe; last_result=' +
                ('0x{0:X8}' -f $resultValue)
            )
        }
        $clientPID = [uint32](
            [DefenseClaw.Certification.ActiveUserCapturePipeNative]::
                ClientProcessId($server.SafePipeHandle)
        )
        $enginePIDs = [uint32[]]@(
            Get-ScheduledTaskEngineProcessIDs $taskName
        )
        if ($clientPID -eq 0 -or
            [uint32]$launch.EnginePID -ne $clientPID -or
            $enginePIDs.Count -ne 1 -or
            $enginePIDs[0] -ne $clientPID) {
            throw (
                "$Label capture client PID $clientPID is not the exact " +
                "RunEx PID $($launch.EnginePID) and scheduled-task " +
                "engine PID: $($enginePIDs -join ',')"
            )
        }
        $clientProcess = Get-CimInstance `
            Win32_Process `
            -Filter "ProcessId=$clientPID" `
            -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace(
                [string]$clientProcess.ExecutablePath
            ) -or
            -not [string]::Equals(
                (ConvertTo-CanonicalPath (
                    [string]$clientProcess.ExecutablePath
                )),
                (ConvertTo-CanonicalPath $script:PowerShellExecutable),
                [StringComparison]::OrdinalIgnoreCase
            ) -or
            [uint32]$clientProcess.SessionId -ne
                [uint32]$script:PrimarySessionID) {
            throw (
                "$Label capture client identity did not match the exact " +
                'approved PowerShell path and active session'
            )
        }
        $server.WriteByte(1)
        $server.Flush()
        $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds + 30)
        $lengthBytes = Read-ExactActiveUserCapturePipe `
            -Pipe $server `
            -Length 4 `
            -Deadline $deadline `
            -Label $Label
        $payloadLength = [BitConverter]::ToInt32($lengthBytes, 0)
        if ($payloadLength -le 0 -or
            $payloadLength -gt $maximumCaptureBytes) {
            throw (
                "$Label returned invalid authenticated capture length " +
                "$payloadLength"
            )
        }
        $resultBytes = Read-ExactActiveUserCapturePipe `
            -Pipe $server `
            -Length $payloadLength `
            -Deadline $deadline `
            -Label $Label
        $done = [Text.Encoding]::UTF8.GetString($resultBytes) |
            ConvertFrom-Json -ErrorAction Stop
        if ([int]$done.schema_version -ne 1 -or
            [string]$done.nonce -cne $nonce -or
            [string]$done.sid -ne $script:PrimarySID -or
            [uint32]$done.pid -ne $clientPID) {
            throw (
                "$Label authenticated capture receipt did not bind the " +
                'exact nonce, SID, and RunEx task PID'
            )
        }
        $stdoutText = [string]$done.stdout
        $stderrText = [string]$done.stderr
        if (-not [string]::IsNullOrWhiteSpace(
                [string]$done.wrapper_error
            )) {
            throw (
                "$Label active-user wrapper failed: " +
                (Protect-SensitiveDisplayText (
                    [string]$done.wrapper_error
                ))
            )
        }
        $exitCode = [int]$done.exit_code
        if ($AllowedExitCodes -notcontains $exitCode) {
            throw (
                "$Label exited $exitCode; expected " +
                "$($AllowedExitCodes -join ', '). stderr: " +
                (Protect-SensitiveDisplayText $stderrText)
            )
        }
        return [pscustomobject]@{
            ExitCode = $exitCode
            StdOut = $stdoutText
            StdErr = $stderrText
            StdOutPath = ''
            StdErrPath = ''
            CapturePipe = $pipeName
            CaptureClientPID = $clientPID
            CaptureTaskPIDBound = $true
            CaptureUserWritableFilesTrusted = $false
        }
    } finally {
        if ($null -ne $server) {
            $server.Dispose()
        }
        if (-not [string]::IsNullOrWhiteSpace($taskName) -and
            $script:ScheduledTasks.Contains($taskName)) {
            Remove-CertificationScheduledTask $taskName
        }
        if (-not [string]::IsNullOrWhiteSpace($transportRoot) -and
            (Test-Path -LiteralPath $transportRoot)) {
            $safeTransportRoot = Assert-PathBelow `
                $transportRoot `
                $script:WorkRoot `
                "$Label active-user task transport cleanup"
            $transportEntries = @(
                Get-ChildItem `
                    -LiteralPath $safeTransportRoot `
                    -Force `
                    -Recurse `
                    -ErrorAction Stop
            )
            $unsafeTransportEntries = @(
                $transportEntries |
                    Where-Object {
                        ($_.Attributes -band
                            [IO.FileAttributes]::ReparsePoint) -ne 0
                    }
            )
            if ($unsafeTransportEntries.Count -ne 0) {
                throw "$Label active-user task transport contains a reparse point"
            }
            Remove-Item `
                -LiteralPath $safeTransportRoot `
                -Recurse `
                -Force `
                -ErrorAction Stop
            if (Test-Path -LiteralPath $safeTransportRoot) {
                throw "$Label active-user task transport cleanup did not converge"
            }
        }
    }
}

function Start-ActiveUserFakeGatewayListener([string]$Label) {
    if ($script:APIPort -le 0) {
        throw 'gateway API port is not initialized'
    }
    $safeLabel = ($Label -replace '[^A-Za-z0-9_.-]', '_')
    $nonce = [Guid]::NewGuid().ToString('N')
    $ready = Join-Path $script:ActiveUserHandoffRoot "$safeLabel-$nonce.ready.json"
    $release = Join-Path $script:ActiveUserHandoffRoot "$safeLabel-$nonce.release"
    $evidence = Join-Path $script:ActiveUserHandoffRoot "$safeLabel-$nonce.listener.json"
    $stdout = Join-Path $script:ActiveUserHandoffRoot "$safeLabel-$nonce.stdout.log"
    $stderr = Join-Path $script:ActiveUserHandoffRoot "$safeLabel-$nonce.stderr.log"
    $inputObject = [ordered]@{
        expected_sid = $script:PrimarySID
        port = $script:APIPort
        ready = $ready
        release = $release
        evidence = $evidence
        timeout_seconds = 120
    }
    $inputBase64 = [Convert]::ToBase64String(
        [Text.Encoding]::UTF8.GetBytes(
            ($inputObject | ConvertTo-Json -Compress)
        )
    )
    $listenerScript = @'
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$inputObject = [Text.Encoding]::UTF8.GetString(
    [Convert]::FromBase64String('__INPUT__')
) | ConvertFrom-Json -ErrorAction Stop
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
if ($sid -ne [string]$inputObject.expected_sid) {
    throw "fake listener SID mismatch: $sid"
}
$listener = [Net.Sockets.TcpListener]::new(
    [Net.IPAddress]::Loopback,
    [int]$inputObject.port
)
$requestCount = 0
$authenticatedRequestCount = 0
$deadline = [DateTimeOffset]::UtcNow.AddSeconds(
    [int]$inputObject.timeout_seconds
)
function Write-ListenerEvidence([bool]$Final) {
    [IO.File]::WriteAllText(
        [string]$inputObject.evidence,
        ([pscustomobject]@{
            sid = $sid
            pid = [Diagnostics.Process]::GetCurrentProcess().Id
            port = [int]$inputObject.port
            request_count = $requestCount
            authenticated_request_count = $authenticatedRequestCount
            final = $Final
        } | ConvertTo-Json -Compress),
        [Text.UTF8Encoding]::new($false)
    )
}
try {
    $listener.Start()
    Write-ListenerEvidence $false
    [IO.File]::WriteAllText(
        [string]$inputObject.ready,
        ([pscustomobject]@{
            sid = $sid
            pid = [Diagnostics.Process]::GetCurrentProcess().Id
            port = [int]$inputObject.port
        } | ConvertTo-Json -Compress),
        [Text.UTF8Encoding]::new($false)
    )
    while (-not (Test-Path -LiteralPath ([string]$inputObject.release)) -and
        [DateTimeOffset]::UtcNow -lt $deadline) {
        if (-not $listener.Pending()) {
            Start-Sleep -Milliseconds 20
            continue
        }
        $client = $listener.AcceptTcpClient()
        try {
            $client.ReceiveTimeout = 2000
            $client.SendTimeout = 2000
            $stream = $client.GetStream()
            $reader = [IO.StreamReader]::new(
                $stream,
                [Text.Encoding]::ASCII,
                $false,
                4096,
                $true
            )
            $authenticated = $false
            while ($true) {
                $line = $reader.ReadLine()
                if ($null -eq $line -or $line.Length -eq 0) { break }
                if ($line -match '(?i)^Authorization:\s*Bearer\s+\S+') {
                    $authenticated = $true
                }
            }
            $requestCount++
            if ($authenticated) { $authenticatedRequestCount++ }
            $body = '{"action":"allow"}'
            $response = (
                "HTTP/1.1 200 OK`r`n" +
                "Content-Type: application/json`r`n" +
                "Content-Length: $([Text.Encoding]::UTF8.GetByteCount($body))`r`n" +
                "Connection: close`r`n`r`n" +
                $body
            )
            $bytes = [Text.Encoding]::UTF8.GetBytes($response)
            $stream.Write($bytes, 0, $bytes.Length)
            $stream.Flush()
            $reader.Dispose()
            Write-ListenerEvidence $false
        } finally {
            $client.Dispose()
        }
    }
} finally {
    $listener.Stop()
    Write-ListenerEvidence $true
}
'@.Replace('__INPUT__', $inputBase64)
    $encoded = [Convert]::ToBase64String(
        [Text.Encoding]::Unicode.GetBytes($listenerScript)
    )
    $taskName = "DefenseClawCert_$($script:RunToken)_$($safeLabel)_$($nonce.Substring(0, 8))"
    $action = New-ScheduledTaskAction `
        -Execute $script:PowerShellExecutable `
        -Argument "-NoLogo -NoProfile -NonInteractive -EncodedCommand $encoded"
    $principal = New-ActiveUserScheduledTaskPrincipal
    $settings = New-ScheduledTaskSettingsSet `
        -ExecutionTimeLimit ([TimeSpan]::FromSeconds(150)) `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries
    $task = New-ScheduledTask `
        -Action $action `
        -Principal $principal `
        -Settings $settings
    Register-ScheduledTask `
        -TaskName $taskName `
        -InputObject $task `
        -Force |
        Out-Null
    $script:ScheduledTasks.Add($taskName)
    $launch = Start-CertificationScheduledTaskInActiveSession $taskName
    $readyJSON = Wait-Until `
        -Description "$Label fake listener bind" `
        -TimeoutSeconds 30 `
        -Condition {
            if (-not (Test-Path -LiteralPath $ready -PathType Leaf)) {
                return $false
            }
            try {
                return Get-Content -LiteralPath $ready -Raw |
                    ConvertFrom-Json -ErrorAction Stop
            } catch {
                return $false
            }
        }
    if ([string]$readyJSON.sid -ne $script:PrimarySID -or
        [uint32]$readyJSON.pid -ne [uint32]$launch.EnginePID -or
        [int]$readyJSON.port -ne $script:APIPort) {
        throw 'fake gateway listener did not bind as the exact active target SID'
    }
    return [pscustomobject]@{
        TaskName = $taskName
        ReadyPath = $ready
        ReleasePath = $release
        EvidencePath = $evidence
        StdOutPath = $stdout
        StdErrPath = $stderr
        PID = [uint32]$readyJSON.pid
    }
}

function Stop-ActiveUserFakeGatewayListener([object]$Listener) {
    if ($null -eq $Listener) { return $null }
    [IO.File]::WriteAllText(
        [string]$Listener.ReleasePath,
        "release`r`n",
        [Text.UTF8Encoding]::new($false)
    )
    $evidence = Wait-Until `
        -Description 'fake gateway listener completion' `
        -TimeoutSeconds 30 `
        -Condition {
            try {
                $value = Get-Content `
                    -LiteralPath ([string]$Listener.EvidencePath) `
                    -Raw |
                    ConvertFrom-Json -ErrorAction Stop
                if ([bool]$value.final) { return $value }
            } catch {}
            return $false
        }
    Remove-CertificationScheduledTask ([string]$Listener.TaskName)
    return $evidence
}

function Start-ActiveUserMutexSquatter(
    [string]$MutexName,
    [ValidateSet('hostile_dacl', 'held_permissive')]
    [string]$Mode,
    [string]$Label
) {
    $safeLabel = ($Label -replace '[^A-Za-z0-9_.-]', '_')
    $nonce = [Guid]::NewGuid().ToString('N')
    $ready = Join-Path `
        $script:ActiveUserHandoffRoot `
        "$safeLabel-$nonce.mutex-ready.json"
    $release = Join-Path `
        $script:ActiveUserHandoffRoot `
        "$safeLabel-$nonce.mutex-release"
    $evidence = Join-Path `
        $script:ActiveUserHandoffRoot `
        "$safeLabel-$nonce.mutex-evidence.json"
    $inputObject = [ordered]@{
        expected_sid = $script:PrimarySID
        mutex_name = $MutexName
        mode = $Mode
        ready = $ready
        release = $release
        evidence = $evidence
        type_name = "MutexSquatter_$($script:RunToken)_$($nonce.Substring(0, 8))"
        timeout_seconds = 90
    }
    $inputBase64 = [Convert]::ToBase64String(
        [Text.Encoding]::UTF8.GetBytes(
            ($inputObject | ConvertTo-Json -Compress)
        )
    )
    $squatterScript = @'
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$inputObject = [Text.Encoding]::UTF8.GetString(
    [Convert]::FromBase64String('__INPUT__')
) | ConvertFrom-Json -ErrorAction Stop
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
if ($sid -ne [string]$inputObject.expected_sid) {
    throw "mutex squatter SID mismatch: $sid"
}
$typeName = [string]$inputObject.type_name
$source = @"
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

public static class $typeName
{
    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_ATTRIBUTES
    {
        public int nLength;
        public IntPtr lpSecurityDescriptor;
        [MarshalAs(UnmanagedType.Bool)]
        public bool bInheritHandle;
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(
        string descriptor, uint revision, out IntPtr securityDescriptor,
        out uint securityDescriptorSize);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr CreateMutex(
        ref SECURITY_ATTRIBUTES attributes,
        [MarshalAs(UnmanagedType.Bool)] bool initialOwner,
        string name);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool ReleaseMutex(IntPtr handle);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll")]
    public static extern IntPtr LocalFree(IntPtr memory);
}
"@
Add-Type -TypeDefinition $source -Language CSharp -ErrorAction Stop
$native = $typeName -as [type]
$sddl = if ([string]$inputObject.mode -eq 'hostile_dacl') {
    "D:P(A;;GA;;;$sid)"
} else {
    'D:P(A;;GA;;;WD)'
}
$securityDescriptor = [IntPtr]::Zero
$securityDescriptorSize = [uint32]0
if (-not $native::ConvertStringSecurityDescriptorToSecurityDescriptor(
    $sddl,
    1,
    [ref]$securityDescriptor,
    [ref]$securityDescriptorSize
)) {
    throw "convert mutex SDDL failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
}
$handle = [IntPtr]::Zero
$released = $false
try {
    $attributes = New-Object ($typeName + '+SECURITY_ATTRIBUTES')
    $attributes.nLength = [Runtime.InteropServices.Marshal]::SizeOf($attributes)
    $attributes.lpSecurityDescriptor = $securityDescriptor
    $attributes.bInheritHandle = $false
    $handle = $native::CreateMutex(
        [ref]$attributes,
        $true,
        [string]$inputObject.mutex_name
    )
    if ($handle -eq [IntPtr]::Zero) {
        throw "create squatted mutex failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    }
    $lastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    if ($lastError -eq 183) {
        throw 'predictable mutex already existed before the non-admin squatter'
    }
    $readyValue = [pscustomobject]@{
        sid = $sid
        pid = [Diagnostics.Process]::GetCurrentProcess().Id
        mutex_name = [string]$inputObject.mutex_name
        mode = [string]$inputObject.mode
        sddl = $sddl
        owns_mutex = $true
    }
    [IO.File]::WriteAllText(
        [string]$inputObject.ready,
        ($readyValue | ConvertTo-Json -Compress),
        [Text.UTF8Encoding]::new($false)
    )
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds(
        [int]$inputObject.timeout_seconds
    )
    while (-not (Test-Path -LiteralPath ([string]$inputObject.release)) -and
        [DateTimeOffset]::UtcNow -lt $deadline) {
        Start-Sleep -Milliseconds 50
    }
    $released = $native::ReleaseMutex($handle)
} finally {
    if ($handle -ne [IntPtr]::Zero) {
        [void]$native::CloseHandle($handle)
    }
    if ($securityDescriptor -ne [IntPtr]::Zero) {
        [void]$native::LocalFree($securityDescriptor)
    }
    [IO.File]::WriteAllText(
        [string]$inputObject.evidence,
        ([pscustomobject]@{
            sid = $sid
            mutex_name = [string]$inputObject.mutex_name
            mode = [string]$inputObject.mode
            released = $released
            final = $true
        } | ConvertTo-Json -Compress),
        [Text.UTF8Encoding]::new($false)
    )
}
'@.Replace('__INPUT__', $inputBase64)
    $encoded = [Convert]::ToBase64String(
        [Text.Encoding]::Unicode.GetBytes($squatterScript)
    )
    $taskName = (
        "DefenseClawCert_$($script:RunToken)_$($safeLabel)_" +
        $nonce.Substring(0, 8)
    )
    $action = New-ScheduledTaskAction `
        -Execute $script:PowerShellExecutable `
        -Argument "-NoLogo -NoProfile -NonInteractive -EncodedCommand $encoded"
    $principal = New-ActiveUserScheduledTaskPrincipal
    $settings = New-ScheduledTaskSettingsSet `
        -ExecutionTimeLimit ([TimeSpan]::FromSeconds(120)) `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries
    $task = New-ScheduledTask `
        -Action $action `
        -Principal $principal `
        -Settings $settings
    Register-ScheduledTask `
        -TaskName $taskName `
        -InputObject $task `
        -Force |
        Out-Null
    $script:ScheduledTasks.Add($taskName)
    $launch = Start-CertificationScheduledTaskInActiveSession $taskName
    $readyJSON = Wait-Until `
        -Description "$Label non-admin mutex squat" `
        -TimeoutSeconds 30 `
        -Condition {
            if (-not (Test-Path -LiteralPath $ready -PathType Leaf)) {
                return $false
            }
            try {
                return Get-Content -LiteralPath $ready -Raw |
                    ConvertFrom-Json -ErrorAction Stop
            } catch {
                return $false
            }
        }
    if ([string]$readyJSON.sid -ne $script:PrimarySID -or
        [uint32]$readyJSON.pid -ne [uint32]$launch.EnginePID -or
        [string]$readyJSON.mutex_name -cne $MutexName -or
        [string]$readyJSON.mode -cne $Mode -or
        -not [bool]$readyJSON.owns_mutex) {
        throw "$Label mutex squatter did not hold the exact object as target SID"
    }
    return [pscustomobject]@{
        TaskName = $taskName
        ReadyPath = $ready
        ReleasePath = $release
        EvidencePath = $evidence
        MutexName = $MutexName
        Mode = $Mode
        PID = [uint32]$readyJSON.pid
        SDDL = [string]$readyJSON.sddl
    }
}

function Stop-ActiveUserMutexSquatter([object]$Squatter) {
    if ($null -eq $Squatter) {
        return $null
    }
    [IO.File]::WriteAllText(
        [string]$Squatter.ReleasePath,
        "release`r`n",
        [Text.UTF8Encoding]::new($false)
    )
    $evidence = Wait-Until `
        -Description 'non-admin mutex squatter completion' `
        -TimeoutSeconds 30 `
        -Condition {
            try {
                $value = Get-Content `
                    -LiteralPath ([string]$Squatter.EvidencePath) `
                    -Raw |
                    ConvertFrom-Json -ErrorAction Stop
                if ([bool]$value.final) {
                    return $value
                }
            } catch {}
            return $false
        }
    Remove-CertificationScheduledTask ([string]$Squatter.TaskName)
    return $evidence
}

function Start-ActiveUserFileLockHolder(
    [string]$Path,
    [string]$Label,
    [ValidateRange(30, 600)]
    [int]$TimeoutSeconds = 90
) {
    $safeLabel = ($Label -replace '[^A-Za-z0-9_.-]', '_')
    $nonce = [Guid]::NewGuid().ToString('N')
    $ready = Join-Path `
        $script:ActiveUserHandoffRoot `
        "$safeLabel-$nonce.file-lock-ready.json"
    $release = Join-Path `
        $script:ActiveUserHandoffRoot `
        "$safeLabel-$nonce.file-lock-release"
    $evidence = Join-Path `
        $script:ActiveUserHandoffRoot `
        "$safeLabel-$nonce.file-lock-evidence.json"
    $inputObject = [ordered]@{
        expected_sid = $script:PrimarySID
        path = ConvertTo-CanonicalPath $Path
        ready = $ready
        release = $release
        evidence = $evidence
        type_name = "FileLockHolder_$($script:RunToken)_$($nonce.Substring(0, 8))"
        timeout_seconds = $TimeoutSeconds
    }
    $inputBase64 = [Convert]::ToBase64String(
        [Text.Encoding]::UTF8.GetBytes(
            ($inputObject | ConvertTo-Json -Compress)
        )
    )
    $holderScript = @'
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$inputObject = [Text.Encoding]::UTF8.GetString(
    [Convert]::FromBase64String('__INPUT__')
) | ConvertFrom-Json -ErrorAction Stop
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
if ($sid -ne [string]$inputObject.expected_sid) {
    throw "file-lock holder SID mismatch: $sid"
}
$path = [IO.Path]::GetFullPath([string]$inputObject.path)
if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
    throw "protected transaction lock is missing: $path"
}
$typeName = [string]$inputObject.type_name
$source = @"
using System;
using System.Runtime.InteropServices;

public static class $typeName
{
    public const UInt32 LOCKFILE_FAIL_IMMEDIATELY = 0x00000001;
    public const UInt32 LOCKFILE_EXCLUSIVE_LOCK = 0x00000002;

    [StructLayout(LayoutKind.Sequential)]
    public struct OVERLAPPED
    {
        public UIntPtr Internal;
        public UIntPtr InternalHigh;
        public UInt32 Offset;
        public UInt32 OffsetHigh;
        public IntPtr EventHandle;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool LockFileEx(
        IntPtr handle,
        UInt32 flags,
        UInt32 reserved,
        UInt32 bytesLow,
        UInt32 bytesHigh,
        ref OVERLAPPED overlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool UnlockFileEx(
        IntPtr handle,
        UInt32 reserved,
        UInt32 bytesLow,
        UInt32 bytesHigh,
        ref OVERLAPPED overlapped);
}
"@
Add-Type -TypeDefinition $source -Language CSharp -ErrorAction Stop
$native = $typeName -as [type]
$overlappedType = $native.GetNestedType('OVERLAPPED')
$overlapped = [Activator]::CreateInstance($overlappedType)
$stream = $null
$locked = $false
$unlocked = $false
try {
    $stream = [IO.File]::Open(
        $path,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::ReadWrite
    )
    $handle = $stream.SafeFileHandle.DangerousGetHandle()
    $flags = (
        $native::LOCKFILE_EXCLUSIVE_LOCK -bor
        $native::LOCKFILE_FAIL_IMMEDIATELY
    )
    $locked = $native::LockFileEx(
        $handle,
        $flags,
        0,
        1,
        0,
        [ref]$overlapped
    )
    if (-not $locked) {
        throw "lock protected transaction file failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    }
    [IO.File]::WriteAllText(
        [string]$inputObject.ready,
        ([pscustomobject]@{
            sid = $sid
            pid = [Diagnostics.Process]::GetCurrentProcess().Id
            path = $path
            locked = $true
            delete_sharing_enabled = $false
        } | ConvertTo-Json -Compress),
        [Text.UTF8Encoding]::new($false)
    )
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds(
        [int]$inputObject.timeout_seconds
    )
    while (-not (Test-Path -LiteralPath ([string]$inputObject.release)) -and
        [DateTimeOffset]::UtcNow -lt $deadline) {
        Start-Sleep -Milliseconds 50
    }
    $unlocked = $native::UnlockFileEx(
        $handle,
        0,
        1,
        0,
        [ref]$overlapped
    )
} finally {
    if ($null -ne $stream) {
        $stream.Dispose()
    }
    [IO.File]::WriteAllText(
        [string]$inputObject.evidence,
        ([pscustomobject]@{
            sid = $sid
            path = $path
            locked = $locked
            unlocked = $unlocked
            delete_sharing_enabled = $false
            final = $true
        } | ConvertTo-Json -Compress),
        [Text.UTF8Encoding]::new($false)
    )
}
'@.Replace('__INPUT__', $inputBase64)
    $encoded = [Convert]::ToBase64String(
        [Text.Encoding]::Unicode.GetBytes($holderScript)
    )
    $taskName = (
        "DefenseClawCert_$($script:RunToken)_$($safeLabel)_" +
        $nonce.Substring(0, 8)
    )
    $action = New-ScheduledTaskAction `
        -Execute $script:PowerShellExecutable `
        -Argument "-NoLogo -NoProfile -NonInteractive -EncodedCommand $encoded"
    $principal = New-ActiveUserScheduledTaskPrincipal
    $settings = New-ScheduledTaskSettingsSet `
        -ExecutionTimeLimit ([TimeSpan]::FromSeconds($TimeoutSeconds + 30)) `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries
    $task = New-ScheduledTask `
        -Action $action `
        -Principal $principal `
        -Settings $settings
    Register-ScheduledTask `
        -TaskName $taskName `
        -InputObject $task `
        -Force |
        Out-Null
    $script:ScheduledTasks.Add($taskName)
    $launch = Start-CertificationScheduledTaskInActiveSession $taskName
    $readyJSON = Wait-Until `
        -Description "$Label non-admin protected file lock" `
        -TimeoutSeconds 30 `
        -Condition {
            if (-not (Test-Path -LiteralPath $ready -PathType Leaf)) {
                return $false
            }
            try {
                return Get-Content -LiteralPath $ready -Raw |
                    ConvertFrom-Json -ErrorAction Stop
            } catch {
                return $false
            }
        }
    if ([string]$readyJSON.sid -ne $script:PrimarySID -or
        [uint32]$readyJSON.pid -ne [uint32]$launch.EnginePID -or
        -not [string]::Equals(
            [string]$readyJSON.path,
            (ConvertTo-CanonicalPath $Path),
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        -not [bool]$readyJSON.locked -or
        $null -eq $readyJSON.PSObject.Properties[
            'delete_sharing_enabled'
        ] -or
        [bool]$readyJSON.delete_sharing_enabled) {
        throw "$Label file-lock holder did not lock the exact path as target SID"
    }
    return [pscustomobject]@{
        TaskName = $taskName
        ReadyPath = $ready
        ReleasePath = $release
        EvidencePath = $evidence
        Path = ConvertTo-CanonicalPath $Path
        PID = [uint32]$readyJSON.pid
        DeleteSharingEnabled = $false
    }
}

function Stop-ActiveUserFileLockHolder([object]$Holder) {
    if ($null -eq $Holder) {
        return $null
    }
    [IO.File]::WriteAllText(
        [string]$Holder.ReleasePath,
        "release`r`n",
        [Text.UTF8Encoding]::new($false)
    )
    $evidence = Wait-Until `
        -Description 'non-admin protected file-lock holder completion' `
        -TimeoutSeconds 30 `
        -Condition {
            try {
                $value = Get-Content `
                    -LiteralPath ([string]$Holder.EvidencePath) `
                    -Raw |
                    ConvertFrom-Json -ErrorAction Stop
                if ([bool]$value.final) {
                    return $value
                }
            } catch {}
            return $false
        }
    if ([string]$evidence.sid -ne $script:PrimarySID -or
        -not [string]::Equals(
            [string]$evidence.path,
            [string]$Holder.Path,
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        -not [bool]$evidence.locked -or
        -not [bool]$evidence.unlocked -or
        $null -eq $evidence.PSObject.Properties[
            'delete_sharing_enabled'
        ] -or
        [bool]$evidence.delete_sharing_enabled) {
        throw (
            'non-admin protected file-lock holder did not prove exact ' +
            'LockFileEx acquisition and release'
        )
    }
    Remove-CertificationScheduledTask ([string]$Holder.TaskName)
    return $evidence
}

function Start-ActiveUserSparseArtifactAttack(
    [string]$Path,
    [string]$Label
) {
    if ([string]::IsNullOrWhiteSpace($script:ActiveUserHandoffRoot)) {
        throw 'active-user handoff is not initialized'
    }
    $canonical = ConvertTo-CanonicalPath $Path
    if (-not (Test-Path -LiteralPath $canonical -PathType Leaf)) {
        throw "$Label sparse target is missing: $canonical"
    }
    $safeLabel = ($Label -replace '[^A-Za-z0-9_.-]', '_')
    if ($safeLabel.Length -gt 44) {
        $safeLabel = $safeLabel.Substring(0, 44)
    }
    $nonce = [Guid]::NewGuid().ToString('N')
    $ready = Join-Path `
        $script:ActiveUserHandoffRoot `
        "$safeLabel-$nonce.sparse-ready.json"
    $release = Join-Path `
        $script:ActiveUserHandoffRoot `
        "$safeLabel-$nonce.sparse-release"
    $evidence = Join-Path `
        $script:ActiveUserHandoffRoot `
        "$safeLabel-$nonce.sparse-evidence.json"
    $renameMarker = Join-Path `
        $script:ActiveUserHandoffRoot `
        "$safeLabel-$nonce.sparse-rename.json"
    $typeName = (
        "DefenseClawSparseAttack_$($script:RunToken)_" +
        $nonce.Substring(0, 8)
    )
    $inputObject = [ordered]@{
        expected_sid = $script:PrimarySID
        path = $canonical
        ready = $ready
        release = $release
        evidence = $evidence
        rename_marker = $renameMarker
        quarantine_suffix = '.defenseclaw-quarantine'
        initial_grow_bytes = $script:SparseAttackInitialGrowBytes
        logical_bytes = $script:SparseAttackLogicalBytes
        max_allocated_bytes = $script:SparseAttackMaxAllocatedBytes
        timeout_seconds = 90
        type_name = $typeName
    }
    $inputBase64 = [Convert]::ToBase64String(
        [Text.Encoding]::UTF8.GetBytes(
            ($inputObject | ConvertTo-Json -Compress)
        )
    )
    $attackScript = @'
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$inputObject = [Text.Encoding]::UTF8.GetString(
    [Convert]::FromBase64String('__INPUT__')
) | ConvertFrom-Json -ErrorAction Stop
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
if ($sid -ne [string]$inputObject.expected_sid) {
    throw "sparse attack SID mismatch: $sid"
}
$path = [IO.Path]::GetFullPath([string]$inputObject.path)
if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
    throw "sparse attack target is missing: $path"
}
$typeName = [string]$inputObject.type_name
$source = @"
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

public static class $typeName
{
    private const UInt32 FSCTL_SET_SPARSE = 0x000900C4;

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DeviceIoControl(
        IntPtr device,
        UInt32 controlCode,
        IntPtr inBuffer,
        UInt32 inBufferSize,
        IntPtr outBuffer,
        UInt32 outBufferSize,
        out UInt32 bytesReturned,
        IntPtr overlapped);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern UInt32 GetCompressedFileSizeW(
        string fileName,
        out UInt32 fileSizeHigh);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern UInt32 GetFinalPathNameByHandleW(
        IntPtr file,
        StringBuilder path,
        UInt32 pathLength,
        UInt32 flags);

    public static void MarkSparse(IntPtr handle)
    {
        UInt32 returned;
        if (!DeviceIoControl(
            handle,
            FSCTL_SET_SPARSE,
            IntPtr.Zero,
            0,
            IntPtr.Zero,
            0,
            out returned,
            IntPtr.Zero))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "mark target-owned artifact sparse");
        }
    }

    public static UInt64 AllocatedBytes(string path)
    {
        UInt32 high;
        UInt32 low = GetCompressedFileSizeW(path, out high);
        if (low == UInt32.MaxValue)
        {
            Int32 error = Marshal.GetLastWin32Error();
            if (error != 0)
            {
                throw new Win32Exception(
                    error,
                    "inspect sparse artifact allocated bytes");
            }
        }
        return ((UInt64)high << 32) | low;
    }

    public static string FinalPath(IntPtr handle)
    {
        StringBuilder path = new StringBuilder(32768);
        UInt32 length = GetFinalPathNameByHandleW(
            handle,
            path,
            (UInt32)path.Capacity,
            0);
        if (length == 0 || length >= path.Capacity)
        {
            return String.Empty;
        }
        return path.ToString();
    }
}
"@
Add-Type -TypeDefinition $source -Language CSharp -ErrorAction Stop
$native = $typeName -as [type]
$stream = $null
$observer = $null
$watcher = $null
$subscription = $null
$failure = ''
$allocated = [uint64]0
$isSparse = $false
$renamedToQuarantine = $false
$canonicalRecreated = $false
$finalHandlePath = ''
$growOperations = 0
try {
    $watcher = [IO.FileSystemWatcher]::new(
        [IO.Path]::GetDirectoryName($path),
        [IO.Path]::GetFileName($path)
    )
    $watcher.NotifyFilter = [IO.NotifyFilters]::FileName
    $watcher.EnableRaisingEvents = $true
    $sourceIdentifier = "$typeName-Renamed"
    $subscription = Register-ObjectEvent `
        -InputObject $watcher `
        -EventName Renamed `
        -SourceIdentifier $sourceIdentifier `
        -MessageData ([string]$inputObject.rename_marker) `
        -Action {
            $args = $Event.SourceEventArgs
            [IO.File]::WriteAllText(
                [string]$Event.MessageData,
                ([pscustomobject]@{
                    old_name = [string]$args.OldName
                    new_name = [string]$args.Name
                } | ConvertTo-Json -Compress),
                [Text.UTF8Encoding]::new($false)
            )
        }

    # The first handle intentionally omits FILE_SHARE_DELETE. This keeps the
    # oversized inode at the canonical name long enough for status and verify
    # to observe the failure while still allowing bounded metadata reads.
    $stream = [IO.File]::Open(
        $path,
        [IO.FileMode]::Open,
        [IO.FileAccess]::ReadWrite,
        [IO.FileShare]::ReadWrite
    )
    $observerShare = (
        [IO.FileShare]::ReadWrite -bor
        [IO.FileShare]::Delete
    )
    $observer = [IO.File]::Open(
        $path,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        $observerShare
    )
    $native::MarkSparse($stream.SafeFileHandle.DangerousGetHandle())
    $stream.SetLength([int64]$inputObject.initial_grow_bytes)
    $growOperations++
    $stream.SetLength([int64]$inputObject.logical_bytes)
    $growOperations++
    $stream.Flush()
    $allocated = $native::AllocatedBytes($path)
    if ($allocated -gt [uint64]$inputObject.max_allocated_bytes) {
        throw (
            "sparse attack allocated $allocated bytes, exceeds safe " +
            "$($inputObject.max_allocated_bytes)-byte test ceiling"
        )
    }
    $sparseItem = Get-Item -LiteralPath $path -Force
    $logical = $sparseItem.Length
    $isSparse = (
        $sparseItem.Attributes -band [IO.FileAttributes]::SparseFile
    ) -ne 0
    if (-not $isSparse) {
        throw 'FSCTL_SET_SPARSE succeeded but NTFS did not mark the artifact sparse'
    }
    if ($logical -ne [int64]$inputObject.logical_bytes) {
        throw "sparse attack logical length is $logical"
    }
    [IO.File]::WriteAllText(
        [string]$inputObject.ready,
        ([pscustomobject]@{
            sid = $sid
            pid = [Diagnostics.Process]::GetCurrentProcess().Id
            path = $path
            sparse = $isSparse
            logical_bytes = $logical
            allocated_bytes = $allocated
            grow_operations = $growOperations
            delete_share_held = $false
        } | ConvertTo-Json -Compress),
        [Text.UTF8Encoding]::new($false)
    )
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds(
        [int]$inputObject.timeout_seconds
    )
    while (-not (Test-Path -LiteralPath ([string]$inputObject.release)) -and
        [DateTimeOffset]::UtcNow -lt $deadline) {
        Start-Sleep -Milliseconds 25
    }
    if (-not (Test-Path -LiteralPath ([string]$inputObject.release))) {
        throw 'sparse attack timed out waiting for bounded release'
    }

    # Dropping only the no-delete handle lets the guardian atomically rename
    # the bad inode into its bounded quarantine. The observer retains DELETE
    # sharing so it cannot obstruct repair and can witness the renamed handle.
    $stream.Dispose()
    $stream = $null
    $repairDeadline = [DateTimeOffset]::UtcNow.AddSeconds(30)
    do {
        try {
            $finalHandlePath = $native::FinalPath(
                $observer.SafeFileHandle.DangerousGetHandle()
            )
            if ($finalHandlePath.EndsWith(
                [string]$inputObject.quarantine_suffix,
                [StringComparison]::OrdinalIgnoreCase
            )) {
                $renamedToQuarantine = $true
            }
        } catch {}
        if (Test-Path -LiteralPath ([string]$inputObject.rename_marker) -PathType Leaf) {
            try {
                $rename = Get-Content `
                    -LiteralPath ([string]$inputObject.rename_marker) `
                    -Raw |
                    ConvertFrom-Json -ErrorAction Stop
                if ([string]$rename.new_name -eq (
                    [IO.Path]::GetFileName($path) +
                    [string]$inputObject.quarantine_suffix
                )) {
                    $renamedToQuarantine = $true
                }
            } catch {}
        }
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            try {
                $currentLength = (Get-Item -LiteralPath $path -Force).Length
                if ($currentLength -lt [int64]$inputObject.initial_grow_bytes) {
                    $canonicalRecreated = $true
                }
            } catch {}
        }
        if ($renamedToQuarantine -and $canonicalRecreated) {
            break
        }
        Start-Sleep -Milliseconds 25
    } while ([DateTimeOffset]::UtcNow -lt $repairDeadline)
} catch {
    $failure = $_.Exception.Message
} finally {
    if ($null -ne $stream) {
        $stream.Dispose()
    }
    if ($null -ne $observer) {
        $observer.Dispose()
    }
    if ($null -ne $subscription) {
        Unregister-Event `
            -SourceIdentifier $subscription.Name `
            -ErrorAction SilentlyContinue
        Remove-Job -Id $subscription.Id -Force -ErrorAction SilentlyContinue
    }
    if ($null -ne $watcher) {
        $watcher.Dispose()
    }
    [IO.File]::WriteAllText(
        [string]$inputObject.evidence,
        ([pscustomobject]@{
            ok = [string]::IsNullOrWhiteSpace($failure)
            sid = $sid
            path = $path
            sparse = $isSparse
            logical_bytes = [int64]$inputObject.logical_bytes
            allocated_bytes = $allocated
            grow_operations = $growOperations
            renamed_to_quarantine = $renamedToQuarantine
            canonical_recreated = $canonicalRecreated
            failure = $failure
            final = $true
        } | ConvertTo-Json -Compress),
        [Text.UTF8Encoding]::new($false)
    )
}
if (-not [string]::IsNullOrWhiteSpace($failure)) { exit 21 }
'@.Replace('__INPUT__', $inputBase64)
    $encoded = [Convert]::ToBase64String(
        [Text.Encoding]::Unicode.GetBytes($attackScript)
    )
    if ($encoded.Length -gt 30000) {
        throw (
            "$Label encoded sparse task exceeds the bounded Windows " +
            'Task Scheduler argument budget'
        )
    }
    $taskName = (
        "DefenseClawCert_$($script:RunToken)_$safeLabel" +
        "_$($nonce.Substring(0, 8))"
    )
    if ($taskName.Length -gt 238 -or
        $taskName -notmatch '^DefenseClawCert_[a-f0-9]{10}_[A-Za-z0-9_.-]+_[a-f0-9]{8}$') {
        throw "unsafe sparse-attack scheduled-task name: $taskName"
    }
    $action = New-ScheduledTaskAction `
        -Execute $script:PowerShellExecutable `
        -Argument "-NoLogo -NoProfile -NonInteractive -EncodedCommand $encoded"
    $principal = New-ActiveUserScheduledTaskPrincipal
    $settings = New-ScheduledTaskSettingsSet `
        -ExecutionTimeLimit ([TimeSpan]::FromSeconds(150)) `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries
    $task = New-ScheduledTask `
        -Action $action `
        -Principal $principal `
        -Settings $settings
    Register-ScheduledTask `
        -TaskName $taskName `
        -InputObject $task `
        -Force |
        Out-Null
    $script:ScheduledTasks.Add($taskName)
    $readyJSON = $null
    try {
        $launch = Start-CertificationScheduledTaskInActiveSession $taskName
        $started = Wait-Until `
            -Description "$Label sparse grow readiness" `
            -TimeoutSeconds 45 `
            -PollMilliseconds 100 `
            -Condition {
                if (Test-Path -LiteralPath $ready -PathType Leaf) {
                    try {
                        return [pscustomobject]@{
                            ready = Get-Content -LiteralPath $ready -Raw |
                                ConvertFrom-Json -ErrorAction Stop
                            failed = $null
                        }
                    } catch {}
                }
                if (Test-Path -LiteralPath $evidence -PathType Leaf) {
                    try {
                        return [pscustomobject]@{
                            ready = $null
                            failed = Get-Content -LiteralPath $evidence -Raw |
                                ConvertFrom-Json -ErrorAction Stop
                        }
                    } catch {}
                }
                return $false
            }
        if ($null -ne $started.failed) {
            throw (
                "$Label sparse grow failed before readiness: " +
                (Protect-SensitiveDisplayText ([string]$started.failed.failure))
            )
        }
        $readyJSON = $started.ready
        if ([string]$readyJSON.sid -ne $script:PrimarySID -or
            [uint32]$readyJSON.pid -ne [uint32]$launch.EnginePID -or
            -not [string]::Equals(
                [string]$readyJSON.path,
                $canonical,
                [StringComparison]::OrdinalIgnoreCase
            ) -or
            -not [bool]$readyJSON.sparse -or
            [int64]$readyJSON.logical_bytes -ne
                $script:SparseAttackLogicalBytes -or
            [int64]$readyJSON.allocated_bytes -gt
                $script:SparseAttackMaxAllocatedBytes -or
            [int]$readyJSON.grow_operations -lt 2 -or
            [bool]$readyJSON.delete_share_held) {
            throw "$Label did not establish the exact bounded non-admin sparse fixture"
        }
    } catch {
        try {
            [IO.File]::WriteAllText(
                $release,
                "release-after-start-failure`r`n",
                [Text.UTF8Encoding]::new($false)
            )
        } catch {}
        try {
            $null = Wait-Until `
                -Description "$Label sparse task release after start failure" `
                -TimeoutSeconds 10 `
                -PollMilliseconds 100 `
                -Condition {
                    return Test-Path -LiteralPath $evidence -PathType Leaf
                }
        } catch {}
        Remove-CertificationScheduledTask $taskName
        try {
            $null = Wait-Until `
                -Description "$Label sparse canonical repair after start failure" `
                -TimeoutSeconds ([Math]::Min($RepairTimeoutSeconds, 30)) `
                -PollMilliseconds 250 `
                -Condition {
                    if (-not (Test-Path -LiteralPath $canonical -PathType Leaf)) {
                        return $false
                    }
                    return (
                        (Get-Item -LiteralPath $canonical -Force).Length -lt
                            $script:SparseAttackInitialGrowBytes
                    )
                }
        } catch {}
        throw
    }
    return [pscustomobject]@{
        TaskName = $taskName
        ReadyPath = $ready
        ReleasePath = $release
        EvidencePath = $evidence
        RenameMarkerPath = $renameMarker
        Path = $canonical
        PID = [uint32]$readyJSON.pid
        LogicalBytes = [int64]$readyJSON.logical_bytes
        AllocatedBytes = [int64]$readyJSON.allocated_bytes
    }
}

function Stop-ActiveUserSparseArtifactAttack(
    [object]$Attack,
    [object]$GuardianBaseline
) {
    if ($null -eq $Attack) {
        return $null
    }
    [IO.File]::WriteAllText(
        [string]$Attack.ReleasePath,
        "release`r`n",
        [Text.UTF8Encoding]::new($false)
    )
    $evidence = $null
    $resourceState = [pscustomobject]@{
        peak_working_set_bytes = if ($null -ne $GuardianBaseline) {
            [int64]$GuardianBaseline.working_set_bytes
        } else {
            [int64]0
        }
        lifetime_peak_working_set_bytes = if ($null -ne $GuardianBaseline) {
            [int64]$GuardianBaseline.peak_working_set_bytes
        } else {
            [int64]0
        }
    }
    try {
        $evidence = Wait-Until `
            -Description 'non-admin sparse artifact attack completion' `
            -TimeoutSeconds 45 `
            -PollMilliseconds 100 `
            -Condition {
                if ($null -ne $GuardianBaseline) {
                    $resourceSample = Get-GuardianResourceObservation
                    Assert-SameLiveGuardianProcess `
                        $GuardianBaseline `
                        $resourceSample `
                        'sparse quarantine/recreate observation'
                    $resourceState.peak_working_set_bytes = [Math]::Max(
                        [int64]$resourceState.peak_working_set_bytes,
                        [int64]$resourceSample.working_set_bytes
                    )
                    $resourceState.lifetime_peak_working_set_bytes =
                        [Math]::Max(
                            [int64](
                                $resourceState.
                                    lifetime_peak_working_set_bytes
                            ),
                            [int64]$resourceSample.peak_working_set_bytes
                        )
                }
                try {
                    $value = Get-Content `
                        -LiteralPath ([string]$Attack.EvidencePath) `
                        -Raw |
                        ConvertFrom-Json -ErrorAction Stop
                    if ([bool]$value.final) {
                        return $value
                    }
                } catch {}
                return $false
            }
    } finally {
        Remove-CertificationScheduledTask ([string]$Attack.TaskName)
    }
    $evidence | Add-Member `
        -NotePropertyName guardian_release_peak_working_set_bytes `
        -NotePropertyValue ([int64]$resourceState.peak_working_set_bytes) `
        -Force
    $evidence | Add-Member `
        -NotePropertyName guardian_release_lifetime_peak_working_set_bytes `
        -NotePropertyValue (
            [int64]$resourceState.lifetime_peak_working_set_bytes
        ) `
        -Force
    if (-not [bool]$evidence.ok) {
        throw (
            'non-admin sparse artifact attack failed: ' +
            (Protect-SensitiveDisplayText ([string]$evidence.failure))
        )
    }
    if ([string]$evidence.sid -ne $script:PrimarySID -or
        -not [string]::Equals(
            [string]$evidence.path,
            [string]$Attack.Path,
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        -not [bool]$evidence.sparse -or
        [int64]$evidence.logical_bytes -ne
            $script:SparseAttackLogicalBytes -or
        [int64]$evidence.allocated_bytes -gt
            $script:SparseAttackMaxAllocatedBytes -or
        [int]$evidence.grow_operations -lt 2 -or
        -not [bool]$evidence.renamed_to_quarantine -or
        -not [bool]$evidence.canonical_recreated) {
        throw (
            'non-admin sparse artifact attack did not prove bounded grow, ' +
            'quarantine rename, and canonical recreation'
        )
    }
    return $evidence
}

function Get-EnterprisePowerShellTempSnapshot {
    $root = Assert-PathBelow `
        (Join-Path $script:WindowsDirectory 'Temp') `
        $script:WindowsDirectory `
        'Windows enterprise PowerShell temp parent'
    $rootItem = Get-Item -LiteralPath $root -Force -ErrorAction Stop
    if (-not $rootItem.PSIsContainer -or
        ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Windows enterprise PowerShell temp parent is unsafe: $root"
    }
    $sections = [Security.AccessControl.AccessControlSections]::All
    $entries = [Collections.Generic.List[object]]::new()
    foreach ($item in @(
        Get-ChildItem `
            -LiteralPath $root `
            -Force `
            -Directory `
            -Filter 'DefenseClaw-PowerShell-*' |
            Sort-Object Name
    )) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "enterprise PowerShell temp prefix contains a reparse point: $($item.FullName)"
        }
        $acl = Get-Acl -LiteralPath $item.FullName
        $entries.Add([pscustomobject]@{
            name = [string]$item.Name
            path = [string]$item.FullName
            owner_sid = ConvertTo-CertificationSID $acl.Owner
            access_rules_protected = [bool]$acl.AreAccessRulesProtected
            sddl = $acl.GetSecurityDescriptorSddlForm($sections)
            attributes = [int]$item.Attributes
        })
    }
    return [pscustomobject]@{
        root = $root
        prefix = 'DefenseClaw-PowerShell-'
        entries = @($entries.ToArray())
    }
}

function Update-EnterprisePowerShellTempObservation(
    [object]$Baseline,
    [object]$Observation
) {
    $baselineNames = @(
        $Baseline.entries |
            ForEach-Object { [string]$_.name }
    )
    $current = @(
        Get-ChildItem `
            -LiteralPath ([string]$Baseline.root) `
            -Force `
            -Directory `
            -Filter 'DefenseClaw-PowerShell-*' |
            Where-Object { [string]$_.Name -notin $baselineNames }
    )
    if ($current.Count -eq 0) {
        return
    }
    foreach ($item in $current) {
        if ([string]$item.Name -cnotmatch
            '^DefenseClaw-PowerShell-[a-f0-9]{32}$') {
            throw (
                'public lifecycle CLI created a non-capability temp child: ' +
                [string]$item.Name
            )
        }
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'public lifecycle CLI temp child is a reparse point'
        }
    }
    if ($current.Count -ne 1) {
        throw (
            'public lifecycle CLI exposed multiple new elevated temp children: ' +
            ($current.Name -join ',')
        )
    }
    $child = $current[0]
    if ([bool]$Observation.observed -and
        -not [string]::Equals(
            [string]$Observation.path,
            [string]$child.FullName,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw 'public lifecycle CLI changed elevated temp capability mid-call'
    }
    $acl = Get-Acl -LiteralPath $child.FullName -ErrorAction Stop
    $sddl = $acl.GetSecurityDescriptorSddlForm(
        [Security.AccessControl.AccessControlSections]::All
    )
    $expectedSDDL =
        'O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'
    if ((ConvertTo-CertificationSID $acl.Owner) -ne 'S-1-5-32-544' -or
        -not [bool]$acl.AreAccessRulesProtected -or
        $sddl -cne $expectedSDDL) {
        throw (
            'public lifecycle CLI elevated temp child owner/DACL mismatch: ' +
            (Protect-SensitiveDisplayText $sddl)
        )
    }
    $Observation.observed = $true
    $Observation.name = [string]$child.Name
    $Observation.path = [string]$child.FullName
    $Observation.owner_sid = 'S-1-5-32-544'
    $Observation.access_rules_protected = $true
    $Observation.sddl = $sddl
    $Observation.sample_count = [int]$Observation.sample_count + 1
}

function Start-ActiveUserEnterprisePowerShellTempProbe(
    [object]$Baseline,
    [string]$Label
) {
    if ([string]::IsNullOrWhiteSpace($script:ActiveUserHandoffRoot)) {
        throw 'active-user handoff is not initialized'
    }
    $safeLabel = ($Label -replace '[^A-Za-z0-9_.-]', '_')
    if ($safeLabel.Length -gt 44) {
        $safeLabel = $safeLabel.Substring(0, 44)
    }
    $nonce = [Guid]::NewGuid().ToString('N')
    $ready = Join-Path `
        $script:ActiveUserHandoffRoot `
        "$safeLabel-$nonce.temp-ready.json"
    $release = Join-Path `
        $script:ActiveUserHandoffRoot `
        "$safeLabel-$nonce.temp-release"
    $evidence = Join-Path `
        $script:ActiveUserHandoffRoot `
        "$safeLabel-$nonce.temp-evidence.json"
    $inputObject = [ordered]@{
        expected_sid = $script:PrimarySID
        root = [string]$Baseline.root
        excluded_names = @(
            $Baseline.entries |
                ForEach-Object { [string]$_.name }
        )
        ready = $ready
        release = $release
        evidence = $evidence
        icacls = Join-Path $script:System32 'icacls.exe'
        timeout_seconds = 120
    }
    $inputBase64 = [Convert]::ToBase64String(
        [Text.Encoding]::UTF8.GetBytes(
            ($inputObject | ConvertTo-Json -Compress -Depth 4)
        )
    )
    $probeScript = @'
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$inputObject = [Text.Encoding]::UTF8.GetString(
    [Convert]::FromBase64String('__INPUT__')
) | ConvertFrom-Json -ErrorAction Stop
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
if ($sid -ne [string]$inputObject.expected_sid) {
    throw "enterprise temp probe SID mismatch: $sid"
}
[IO.File]::WriteAllText(
    [string]$inputObject.ready,
    ([pscustomobject]@{
        sid = $sid
        pid = [Diagnostics.Process]::GetCurrentProcess().Id
        ready = $true
    } | ConvertTo-Json -Compress),
    [Text.UTF8Encoding]::new($false)
)
$excluded = @([string[]]$inputObject.excluded_names)
$deadline = [DateTimeOffset]::UtcNow.AddSeconds(
    [int]$inputObject.timeout_seconds
)
$result = $null
while ([DateTimeOffset]::UtcNow -lt $deadline -and
    -not (Test-Path -LiteralPath ([string]$inputObject.release))) {
    $children = @(
        Get-ChildItem `
            -LiteralPath ([string]$inputObject.root) `
            -Force `
            -Directory `
            -Filter 'DefenseClaw-PowerShell-*' `
            -ErrorAction SilentlyContinue |
            Where-Object { [string]$_.Name -notin $excluded }
    )
    if ($children.Count -eq 0) {
        Start-Sleep -Milliseconds 10
        continue
    }
    if ($children.Count -ne 1 -or
        [string]$children[0].Name -cnotmatch
            '^DefenseClaw-PowerShell-[a-f0-9]{32}$') {
        throw 'medium-user temp probe observed an invalid capability set'
    }
    $target = [string]$children[0].FullName
    $attempts = [Collections.Generic.List[object]]::new()
    try {
        $null = @([IO.Directory]::EnumerateFileSystemEntries($target))
        $attempts.Add([pscustomobject]@{
            operation = 'read'
            denied = $false
            error_type = ''
        })
    } catch {
        $attempts.Add([pscustomobject]@{
            operation = 'read'
            denied = $true
            error_type = $_.Exception.GetType().FullName
        })
    }
    $candidate = Join-Path $target '.defenseclaw-medium-create-probe'
    try {
        [IO.File]::WriteAllText(
            $candidate,
            'non-secret-probe',
            [Text.UTF8Encoding]::new($false)
        )
        $attempts.Add([pscustomobject]@{
            operation = 'create'
            denied = $false
            error_type = ''
        })
    } catch {
        $attempts.Add([pscustomobject]@{
            operation = 'create'
            denied = $true
            error_type = $_.Exception.GetType().FullName
        })
    }
    & ([string]$inputObject.icacls) `
        $target `
        '/grant' `
        ("*$sid" + ':(OI)(CI)F') `
        1>$null `
        2>$null
    $aclExit = $LASTEXITCODE
    $attempts.Add([pscustomobject]@{
        operation = 'change_dacl'
        denied = $aclExit -ne 0
        error_type = "icacls_exit_$aclExit"
    })
    try {
        [IO.Directory]::Delete($target, $false)
        $attempts.Add([pscustomobject]@{
            operation = 'delete'
            denied = $false
            error_type = ''
        })
    } catch {
        $attempts.Add([pscustomobject]@{
            operation = 'delete'
            denied = $true
            error_type = $_.Exception.GetType().FullName
        })
    }
    $result = [pscustomobject]@{
        sid = $sid
        observed = $true
        target_name = [string]$children[0].Name
        target_existed_before = $true
        target_existed_after = Test-Path -LiteralPath $target -PathType Container
        attempts = @($attempts.ToArray())
        secret_material_recorded = $false
    }
    break
}
if ($null -eq $result) {
    $result = [pscustomobject]@{
        sid = $sid
        observed = $false
        target_name = ''
        target_existed_before = $false
        target_existed_after = $false
        attempts = @()
        secret_material_recorded = $false
    }
}
[IO.File]::WriteAllText(
    [string]$inputObject.evidence,
    ($result | ConvertTo-Json -Compress -Depth 5),
    [Text.UTF8Encoding]::new($false)
)
'@.Replace('__INPUT__', $inputBase64)
    $encoded = [Convert]::ToBase64String(
        [Text.Encoding]::Unicode.GetBytes($probeScript)
    )
    if ($encoded.Length -gt 30000) {
        throw "$Label encoded temp-boundary task exceeds the safe argument budget"
    }
    $taskName = (
        "DefenseClawCert_$($script:RunToken)_$safeLabel" +
        "_$($nonce.Substring(0, 8))"
    )
    $action = New-ScheduledTaskAction `
        -Execute $script:PowerShellExecutable `
        -Argument "-NoLogo -NoProfile -NonInteractive -EncodedCommand $encoded"
    $principal = New-ActiveUserScheduledTaskPrincipal
    $settings = New-ScheduledTaskSettingsSet `
        -ExecutionTimeLimit ([TimeSpan]::FromSeconds(150)) `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries
    $task = New-ScheduledTask `
        -Action $action `
        -Principal $principal `
        -Settings $settings
    Register-ScheduledTask `
        -TaskName $taskName `
        -InputObject $task `
        -Force |
        Out-Null
    $script:ScheduledTasks.Add($taskName)
    try {
        $launch = Start-CertificationScheduledTaskInActiveSession $taskName
        $readyJSON = Wait-Until `
            -Description "$Label medium-user temp-probe readiness" `
            -TimeoutSeconds 30 `
            -PollMilliseconds 50 `
            -Condition {
                try {
                    return Get-Content -LiteralPath $ready -Raw |
                        ConvertFrom-Json -ErrorAction Stop
                } catch {
                    return $false
                }
            }
        if ([string]$readyJSON.sid -ne $script:PrimarySID -or
            [uint32]$readyJSON.pid -ne [uint32]$launch.EnginePID -or
            -not [bool]$readyJSON.ready) {
            throw "$Label medium-user temp probe used the wrong token"
        }
    } catch {
        Remove-CertificationScheduledTask $taskName
        throw
    }
    return [pscustomobject]@{
        TaskName = $taskName
        ReleasePath = $release
        EvidencePath = $evidence
        PID = [uint32]$readyJSON.pid
    }
}

function Stop-ActiveUserEnterprisePowerShellTempProbe([object]$Probe) {
    if ($null -eq $Probe) {
        return $null
    }
    [IO.File]::WriteAllText(
        [string]$Probe.ReleasePath,
        "release`r`n",
        [Text.UTF8Encoding]::new($false)
    )
    try {
        return Wait-Until `
            -Description 'medium-user enterprise PowerShell temp denial evidence' `
            -TimeoutSeconds 30 `
            -PollMilliseconds 50 `
            -Condition {
                try {
                    return Get-Content `
                        -LiteralPath ([string]$Probe.EvidencePath) `
                        -Raw |
                        ConvertFrom-Json -ErrorAction Stop
                } catch {
                    return $false
                }
            }
    } finally {
        Remove-CertificationScheduledTask ([string]$Probe.TaskName)
    }
}

function Initialize-CertificationCodexHome {
    $home = Assert-CertificationCodexHomePath $script:CertificationCodexHome
    if (Test-Path -LiteralPath $home) {
        throw "refusing pre-existing certification CODEX_HOME: $home"
    }
    $snapshot = New-ProtectedUserTreeSnapshot `
        -Path $home `
        -Name "codex-cert-$($script:RunToken)"
    if ([bool]$snapshot.inventory.existed) {
        throw "certification CODEX_HOME absent baseline unexpectedly existed: $home"
    }

    $script:CodexUserHookSentinel = Assert-PathBelow `
        (Join-Path $home 'forbidden-user-hook-fired.txt') `
        $home `
        'forbidden user-hook sentinel'
    $hostileHookScript = @"
[IO.File]::WriteAllText(
    '$($script:CodexUserHookSentinel.Replace("'", "''"))',
    'forbidden-user-hook-fired',
    [Text.UTF8Encoding]::new(`$false)
)
"@
    $hostileEncoded = [Convert]::ToBase64String(
        [Text.Encoding]::Unicode.GetBytes($hostileHookScript)
    )
    $hostileCommand = (
        '"' + $script:BootstrapPowerShellExecutable + '"' +
        ' -NoLogo -NoProfile -NonInteractive -EncodedCommand ' +
        $hostileEncoded
    )
    $inputObject = [ordered]@{
        path = $home
        profile = $script:PrimaryProfile
        sid = $script:PrimarySID
        expected_name = ".codex-defenseclaw-cert-$($script:RunToken)"
        hostile_command = $hostileCommand
        hostile_sentinel = $script:CodexUserHookSentinel
    }
    $inputBase64 = [Convert]::ToBase64String(
        [Text.Encoding]::UTF8.GetBytes(
            ($inputObject | ConvertTo-Json -Compress)
        )
    )
    $scriptText = @'
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$inputObject = [Text.Encoding]::UTF8.GetString(
    [Convert]::FromBase64String('__INPUT__')
) | ConvertFrom-Json -ErrorAction Stop
$actualSID = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
if ($actualSID -ne [string]$inputObject.sid) {
    throw "certification CODEX_HOME task SID mismatch: $actualSID"
}
$profile = [IO.Path]::GetFullPath([string]$inputObject.profile).TrimEnd('\')
$path = [IO.Path]::GetFullPath([string]$inputObject.path).TrimEnd('\')
$parent = [IO.Path]::GetFullPath([IO.Path]::GetDirectoryName($path)).TrimEnd('\')
if (-not $parent.Equals($profile, [StringComparison]::OrdinalIgnoreCase) -or
    [IO.Path]::GetFileName($path) -cne [string]$inputObject.expected_name) {
    throw "certification CODEX_HOME is not the exact allowlisted profile child: $path"
}
if (Test-Path -LiteralPath $path) {
    throw "certification CODEX_HOME unexpectedly exists: $path"
}
[IO.Directory]::CreateDirectory($path) | Out-Null
$item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
if (-not $item.PSIsContainer -or
    ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "created certification CODEX_HOME is not a real directory: $path"
}
$config = Join-Path $path 'config.toml'
[string]$hostileCommand = [string]$inputObject.hostile_command
if ($hostileCommand.Contains("'")) {
    throw 'hostile hook command cannot be encoded as a TOML literal string'
}
[IO.File]::WriteAllText(
    $config,
    @"
model = "defenseclaw-certification-offline"

[[hooks.SessionStart]]
matcher = "startup|resume|clear"

[[hooks.SessionStart.hooks]]
type = "command"
command = '$hostileCommand'
command_windows = '$hostileCommand'
timeout = 10
"@,
    [Text.UTF8Encoding]::new($false)
)
if (Test-Path -LiteralPath ([string]$inputObject.hostile_sentinel)) {
    throw 'hostile user-hook sentinel unexpectedly exists before Codex launch'
}
[pscustomobject]@{
    ok = $true
    sid = $actualSID
    codex_home = $path
    config = $config
    hostile_sentinel = [string]$inputObject.hostile_sentinel
} | ConvertTo-Json -Compress
'@.Replace('__INPUT__', $inputBase64)
    $result = Invoke-ActiveUserPowerShell `
        -Script $scriptText `
        -Label 'initialize-certification-codex-home' `
        -TimeoutSeconds 120
    $json = ConvertFrom-SingleJSONDocument `
        $result.StdOut `
        'initialize certification CODEX_HOME'
    if (-not [bool]$json.ok -or
        [string]$json.sid -ne $script:PrimarySID -or
        -not [string]::Equals(
            [string]$json.codex_home,
            $home,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw 'active-user certification CODEX_HOME initialization returned inconsistent identity/path evidence'
    }
    $script:CertificationCodexHomeInitialized = $true
    $script:PrimaryConfigPath = Assert-PathBelow `
        (Join-Path $home 'config.toml') `
        $home `
        'certification Codex config'
    $null = Assert-CertificationCodexHomePath $home -RequireExisting
    if (-not (Test-Path -LiteralPath $script:PrimaryConfigPath -PathType Leaf)) {
        throw "active user did not initialize certification Codex config: $($script:PrimaryConfigPath)"
    }
    $configOwnerSID = ConvertTo-CertificationSID (
        (Get-Acl -LiteralPath $script:PrimaryConfigPath -ErrorAction Stop).Owner
    )
    if ($configOwnerSID -ne $script:PrimarySID) {
        throw "certification Codex config owner is $configOwnerSID, want $($script:PrimarySID)"
    }
    $script:PrimaryConfigBaselineBytes = [IO.File]::ReadAllBytes($script:PrimaryConfigPath)
    $script:PrimaryConfigBaselineACL = Get-Acl -LiteralPath $script:PrimaryConfigPath
    $script:PrimaryConfigBaselineSHA256 = Get-FileDigest $script:PrimaryConfigPath
    return [pscustomobject]@{
        path = $home
        config = $script:PrimaryConfigPath
        sid = $script:PrimarySID
        owner_sid = $configOwnerSID
        initial_state = 'absent'
        validation = $script:CertificationCodexHomeValidation
    }
}

function New-RandomCredential([string]$UserName) {
    $random = [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(24))
    $passwordText = 'Dc!' + ($random -replace '[^A-Za-z0-9]', '7') + 'z9'
    $secure = ConvertTo-SecureString $passwordText -AsPlainText -Force
    $qualified = "$env:COMPUTERNAME\$UserName"
    return [pscredential]::new($qualified, $secure)
}

function New-CertificationLocalUser(
    [string]$UserName,
    [Management.Automation.PSCredential]$Credential
) {
    Assert-CertificationUserName $UserName 'certification'
    if (Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue) {
        throw "refusing pre-existing local user: $UserName"
    }
    New-LocalUser `
        -Name $UserName `
        -Password $Credential.Password `
        -AccountNeverExpires `
        -PasswordNeverExpires `
        -UserMayNotChangePassword `
        -Description 'DefenseClaw enterprise certification user' |
        Out-Null
    $user = Get-LocalUser -Name $UserName -ErrorAction Stop
    if ($user.Enabled -ne $true) {
        throw "temporary local user is disabled: $UserName"
    }
    $adminMembers = @(Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop)
    if ($adminMembers.SID.Value -contains $user.SID.Value) {
        throw "temporary user unexpectedly belongs to Administrators: $UserName"
    }
    return $user.SID.Value
}

function Initialize-CertificationProfile(
    [Management.Automation.PSCredential]$Credential,
    [string]$Label
) {
    $result = Invoke-UserPowerShell `
        -Credential $Credential `
        -Label $Label `
        -Script @'
$ErrorActionPreference = 'Stop'
$profilePath = [Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)
if ([string]::IsNullOrWhiteSpace($profilePath)) { throw 'profile path is empty' }
[IO.Directory]::CreateDirectory((Join-Path $profilePath '.codex')) | Out-Null
[IO.File]::WriteAllText(
    (Join-Path $profilePath '.codex\config.toml'),
    "model = `"gpt-5`"`r`n",
    [Text.UTF8Encoding]::new($false)
)
[pscustomobject]@{
    profile = [IO.Path]::GetFullPath($profilePath)
    sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
} | ConvertTo-Json -Compress
'@
    return ConvertFrom-SingleJSONDocument $result.StdOut $Label
}

function Protect-AdministratorTree([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        [IO.Directory]::CreateDirectory($Path) | Out-Null
    }
    $result = Set-ICaclsOwnerAndDacl `
        -Path $Path `
        -Owner '*S-1-5-32-544' `
        -Grants @(
            '*S-1-5-18:(OI)(CI)F',
            '*S-1-5-32-544:(OI)(CI)F'
        ) `
        -Label ('protect-' + [IO.Path]::GetFileName($Path))
    if ($result.ExitCode -ne 0) {
        throw "failed to protect administrator tree: $Path"
    }
}

function Protect-AdministratorFile([string]$Path, [string]$Label) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$Label protected file is missing: $Path"
    }
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Label is not a regular file: $Path"
    }
    $null = Set-ICaclsOwnerAndDacl `
        -Path $Path `
        -Owner '*S-1-5-32-544' `
        -Grants @(
            '*S-1-5-18:F',
            '*S-1-5-32-544:F'
        ) `
        -Label $Label
}

function Assert-SourcePathHasNoReparse([string]$Path, [string]$Label) {
    $full = ConvertTo-CanonicalPath $Path
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) {
        throw "$Label source is missing: $full"
    }
    $current = $full
    while (-not [string]::IsNullOrWhiteSpace($current)) {
        $item = Get-Item -LiteralPath $current -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "$Label source traverses a reparse point: $current"
        }
        $parent = [IO.Path]::GetDirectoryName($current)
        if ([string]::IsNullOrWhiteSpace($parent) -or
            $parent.Equals($current, [StringComparison]::OrdinalIgnoreCase)) {
            break
        }
        $current = $parent
    }
    return $full
}

function Copy-CertificationSourceToProtectedStaging(
    [string]$Source,
    [string]$RelativeDestination,
    [string]$Label
) {
    $sourcePath = Assert-SourcePathHasNoReparse $Source $Label
    $destination = Assert-PathBelow `
        (Join-Path $script:StagingRoot $RelativeDestination) `
        $script:StagingRoot `
        "$Label destination"
    if (Test-Path -LiteralPath $destination) {
        throw "$Label staging destination already exists: $destination"
    }
    $parent = Split-Path -Parent $destination
    [IO.Directory]::CreateDirectory($parent) | Out-Null
    Protect-AdministratorTree $parent
    $before = Get-FileDigest $sourcePath
    [IO.File]::Copy($sourcePath, $destination, $false)
    Protect-AdministratorFile $destination ("protect-" + $Label)
    $sourceAfter = Get-FileDigest $sourcePath
    $staged = Get-FileDigest $destination
    if ([string]::IsNullOrWhiteSpace($before) -or
        $sourceAfter -ne $before -or
        $staged -ne $before) {
        throw "$Label source changed while staging or staged bytes differ"
    }
    return $destination
}

function Initialize-ProtectedCertificationSources {
    $originalInstaller = $script:Installer
    $originalModule = $script:OriginalModuleSource
    if (-not (Test-Path -LiteralPath $originalModule -PathType Leaf)) {
        throw "enterprise installer module is missing: $originalModule"
    }
    $script:GatewaySource = Copy-CertificationSourceToProtectedStaging `
        $script:OriginalGatewaySource `
        'sources\defenseclaw-gateway.exe' `
        'stage-gateway'
    $script:HookSource = Copy-CertificationSourceToProtectedStaging `
        $script:OriginalHookSource `
        'sources\defenseclaw-hook.exe' `
        'stage-hook'
    $script:CLISource = Copy-CertificationSourceToProtectedStaging `
        $script:OriginalCLISource `
        'sources\defenseclaw.exe' `
        'stage-cli'
    $script:NormalModeCLILauncherSource =
        Copy-CertificationSourceToProtectedStaging `
            $script:OriginalNormalModeCLILauncher `
            'sources\normal-mode\defenseclaw.exe' `
            'stage-normal-mode-cli-launcher'
    $script:NormalModeCLIWheelSource =
        Copy-CertificationSourceToProtectedStaging `
            $script:OriginalNormalModeCLIWheel `
            'sources\normal-mode\defenseclaw.whl' `
            'stage-normal-mode-cli-wheel'
    if (-not $AllowUnsigned) {
        $signature = Get-AuthenticodeSignature -LiteralPath $script:GatewaySource
        if ($signature.Status -ne [Management.Automation.SignatureStatus]::Valid) {
            throw "candidate gateway Authenticode signature is not valid: $($signature.Status)"
        }
    }
    $script:Installer = Copy-CertificationSourceToProtectedStaging `
        $originalInstaller `
        'installer\install-enterprise.ps1' `
        'stage-enterprise-installer'
    $null = Copy-CertificationSourceToProtectedStaging `
        $originalModule `
        'installer\DefenseClawEnterprise.psm1' `
        'stage-enterprise-module'
    foreach ($entry in @(
        [pscustomobject]@{ name = 'gateway'; path = $script:GatewaySource },
        [pscustomobject]@{ name = 'hook'; path = $script:HookSource },
        [pscustomobject]@{ name = 'cli'; path = $script:CLISource },
        [pscustomobject]@{
            name = 'normal_mode_cli_launcher'
            path = $script:NormalModeCLILauncherSource
        },
        [pscustomobject]@{
            name = 'normal_mode_cli_wheel'
            path = $script:NormalModeCLIWheelSource
        },
        [pscustomobject]@{ name = 'installer'; path = $script:Installer },
        [pscustomobject]@{
            name = 'module'
            path = Join-Path (Split-Path -Parent $script:Installer) 'DefenseClawEnterprise.psm1'
        }
    )) {
        if ((Get-FileDigest $entry.path) -ne [string]$script:SourceDigests[$entry.name]) {
            throw "$($entry.name) source changed between preflight and protected staging"
        }
    }

    $script:UpgradeGatewaySource = ''
    $script:UpgradeHookSource = ''
    $script:UpgradeCLISource = ''
    if (-not [string]::IsNullOrWhiteSpace($UpgradeGatewayBinary) -or
        -not [string]::IsNullOrWhiteSpace($UpgradeHookBinary) -or
        -not [string]::IsNullOrWhiteSpace($UpgradeCLIBinary)) {
        if ([string]::IsNullOrWhiteSpace($UpgradeGatewayBinary) -or
            [string]::IsNullOrWhiteSpace($UpgradeHookBinary) -or
            [string]::IsNullOrWhiteSpace($UpgradeCLIBinary)) {
            throw 'upgrade certification requires all three upgrade binaries'
        }
        $script:UpgradeGatewaySource = Copy-CertificationSourceToProtectedStaging `
            $UpgradeGatewayBinary `
            'upgrade-sources\defenseclaw-gateway.exe' `
            'stage-upgrade-gateway'
        $script:UpgradeHookSource = Copy-CertificationSourceToProtectedStaging `
            $UpgradeHookBinary `
            'upgrade-sources\defenseclaw-hook.exe' `
            'stage-upgrade-hook'
        $script:UpgradeCLISource = Copy-CertificationSourceToProtectedStaging `
            $UpgradeCLIBinary `
            'upgrade-sources\defenseclaw.exe' `
            'stage-upgrade-cli'
        foreach ($entry in @(
            [pscustomobject]@{ name = 'upgrade_gateway'; path = $script:UpgradeGatewaySource },
            [pscustomobject]@{ name = 'upgrade_hook'; path = $script:UpgradeHookSource },
            [pscustomobject]@{ name = 'upgrade_cli'; path = $script:UpgradeCLISource }
        )) {
            if ((Get-FileDigest $entry.path) -ne [string]$script:SourceDigests[$entry.name]) {
                throw "$($entry.name) source changed between preflight and protected staging"
            }
        }
    }
    return 'installer, module, gateway, hook, lifecycle CLI, normal-mode Python CLI, and optional upgrade binaries are byte-stable in administrator-protected staging'
}

function Get-AgentBinaryTrustIdentity(
    [string]$Path,
    [ValidateSet('codex', 'claude')]
    [string]$Agent,
    [switch]$AllowMissingFileVersion
) {
    $resolved = Assert-SourcePathHasNoReparse $Path "$Agent application-control"
    $signature = Get-AuthenticodeSignature -LiteralPath $resolved
    $expectedSigner = if ($Agent -eq 'codex') {
        'OpenAI OpCo, LLC'
    } else {
        'Anthropic, PBC'
    }
    if ($signature.Status -ne
        [Management.Automation.SignatureStatus]::Valid -or
        $null -eq $signature.SignerCertificate -or
        -not ([string]$signature.SignerCertificate.Subject).Contains(
            $expectedSigner,
            [StringComparison]::Ordinal
        )) {
        throw (
            "$Agent application-control artifact requires a valid " +
            "$expectedSigner Authenticode signature; status=$($signature.Status)"
        )
    }
    $fileVersionText = [string](Get-Item -LiteralPath $resolved -Force).
        VersionInfo.FileVersion
    $match = [regex]::Match(
        $fileVersionText,
        '(?<!\d)(\d+\.\d+\.\d+(?:\.\d+)?)(?!\d)'
    )
    if (-not $match.Success -and
        -not (
            $Agent -eq 'codex' -and
            $AllowMissingFileVersion -and
            [string]::IsNullOrWhiteSpace($fileVersionText)
        )) {
        throw "$Agent application-control artifact has no parseable file version: $fileVersionText"
    }
    $version = $null
    $versionSource = 'protected_active_user_runtime_probe_required'
    if ($match.Success) {
        try {
            $version = [Version]$match.Groups[1].Value
            $versionSource = 'pe_version_info'
        } catch {
            throw "$Agent application-control artifact has invalid file version: $fileVersionText"
        }
    }
    return [pscustomobject]@{
        agent = $Agent
        path = $resolved
        sha256 = Get-FileDigest $resolved
        file_version = $fileVersionText
        version = $version
        version_source = $versionSource
        signer_subject = [string]$signature.SignerCertificate.Subject
        signature_status = [string]$signature.Status
    }
}

function Get-CodexTrustedHookLauncherIdentity([string]$Path) {
    $resolved = Assert-SourcePathHasNoReparse `
        $Path `
        'Codex trusted hook launcher'
    $signature = Get-AuthenticodeSignature -LiteralPath $resolved
    if ($signature.Status -ne
            [Management.Automation.SignatureStatus]::Valid -or
        $null -eq $signature.SignerCertificate) {
        throw (
            'Codex trusted hook launcher requires a valid Authenticode ' +
            "signature; status=$($signature.Status)"
        )
    }
    $digest = Get-FileDigest $resolved
    if ($digest -ceq [string]$script:SourceDigests['codex'] -or
        $digest -ceq [string]$script:SourceDigests['rejected_codex']) {
        throw (
            'Codex trusted hook launcher must have bytes distinct from both ' +
            'the stock and rejected Codex artifacts'
        )
    }
    return [pscustomobject]@{
        path = $resolved
        sha256 = $digest
        signer_subject = [string]$signature.SignerCertificate.Subject
        signer_thumbprint = [string]$signature.SignerCertificate.Thumbprint
        signature_status = [string]$signature.Status
    }
}

function Initialize-ProtectedCodexRuntime {
    $source = Assert-SourcePathHasNoReparse `
        $script:OriginalCodexSource `
        'Codex 0.144.3'
    $sourceDigest = Get-FileDigest $source
    if ($sourceDigest -cne [string]$script:SourceDigests['codex']) {
        throw 'Codex source changed between preflight and protected runtime staging'
    }
    $approvedCodexIdentity = Get-AgentBinaryTrustIdentity `
        $source `
        'codex' `
        -AllowMissingFileVersion
    $approvedClaudeIdentity = Get-AgentBinaryTrustIdentity `
        $script:OriginalClaudeSource `
        'claude'
    $rejectedCodexIdentity = Get-AgentBinaryTrustIdentity `
        $script:OriginalRejectedCodexSource `
        'codex'
    $rejectedClaudeIdentity = Get-AgentBinaryTrustIdentity `
        $script:OriginalRejectedClaudeSource `
        'claude'
    $trustedLauncherIdentity = if ($ClaudeOnly) {
        $null
    } else {
        Get-CodexTrustedHookLauncherIdentity `
            $script:OriginalCodexTrustedHookLauncherSource
    }
    foreach ($identityCheck in @(
        [pscustomobject]@{
            identity = $approvedClaudeIdentity
            digest = [string]$script:SourceDigests['claude']
        },
        [pscustomobject]@{
            identity = $rejectedCodexIdentity
            digest = [string]$script:SourceDigests['rejected_codex']
        },
        [pscustomobject]@{
            identity = $rejectedClaudeIdentity
            digest = [string]$script:SourceDigests['rejected_claude']
        }
    )) {
        if ([string]$identityCheck.identity.sha256 -cne
            [string]$identityCheck.digest) {
            throw "$($identityCheck.identity.agent) source changed between preflight and protected staging"
        }
    }
    if ($null -ne $approvedCodexIdentity.version -and
        $approvedCodexIdentity.version.ToString(3) -cne '0.144.3') {
        throw (
            'approved Codex certification artifact must be exact 0.144.3; ' +
            "got $($approvedCodexIdentity.file_version)"
        )
    }
    if ($approvedClaudeIdentity.version -lt [Version]'2.1.152') {
        throw (
            'approved Claude certification artifact is below 2.1.152; ' +
            "got $($approvedClaudeIdentity.file_version)"
        )
    }
    if ($rejectedCodexIdentity.version -ge [Version]'0.131.0') {
        throw (
            'rejected Codex artifact must be an official signed release below ' +
            "0.131.0; got $($rejectedCodexIdentity.file_version)"
        )
    }
    if ($rejectedClaudeIdentity.version -ge [Version]'2.1.152') {
        throw (
            'rejected Claude artifact must be an official signed release below ' +
            "2.1.152; got $($rejectedClaudeIdentity.file_version)"
        )
    }
    if ([string]$approvedCodexIdentity.sha256 -ceq
            [string]$rejectedCodexIdentity.sha256 -or
        [string]$approvedClaudeIdentity.sha256 -ceq
            [string]$rejectedClaudeIdentity.sha256) {
        throw 'approved and rejected application-control artifacts must have distinct bytes'
    }
    if ($null -ne $trustedLauncherIdentity -and
        [string]$trustedLauncherIdentity.sha256 -cne
            [string]$script:SourceDigests['codex_trusted_hook_launcher']) {
        throw (
            'Codex trusted hook launcher changed between preflight and ' +
            'protected runtime staging'
        )
    }

    $script:CodexRuntimeRoot = Assert-PathBelow `
        (Join-Path $script:WorkRoot 'codex-runtime') `
        $script:WorkRoot `
        'protected Codex runtime'
    if (Test-Path -LiteralPath $script:CodexRuntimeRoot) {
        throw "protected Codex runtime already exists: $($script:CodexRuntimeRoot)"
    }
    [IO.Directory]::CreateDirectory($script:CodexRuntimeRoot) | Out-Null
    $null = Set-ICaclsOwnerAndDacl `
        -Path $script:CodexRuntimeRoot `
        -Owner '*S-1-5-32-544' `
        -Grants @(
            '*S-1-5-18:(OI)(CI)F',
            '*S-1-5-32-544:(OI)(CI)F',
            "*$($script:PrimarySID):(OI)(CI)RX"
        ) `
        -Label 'protect-codex-runtime'
    $script:CodexRuntimeBinary = Assert-PathBelow `
        (Join-Path $script:CodexRuntimeRoot 'codex.exe') `
        $script:CodexRuntimeRoot `
        'protected Codex executable'
    [IO.File]::Copy($source, $script:CodexRuntimeBinary, $false)
    if ((Get-FileDigest $source) -cne $sourceDigest -or
        (Get-FileDigest $script:CodexRuntimeBinary) -cne $sourceDigest) {
        throw 'Codex source changed while staging or staged bytes differ'
    }
    $stagedSignature = Get-AuthenticodeSignature `
        -LiteralPath $script:CodexRuntimeBinary
    if ($stagedSignature.Status -ne
        [Management.Automation.SignatureStatus]::Valid -or
        $null -eq $stagedSignature.SignerCertificate -or
        -not ([string]$stagedSignature.SignerCertificate.Subject).Contains(
            'OpenAI OpCo, LLC',
            [StringComparison]::Ordinal
        )) {
        throw 'protected Codex runtime lost its valid OpenAI Authenticode signature'
    }
    if ($null -ne $trustedLauncherIdentity) {
        $script:CodexTrustedHookLauncherRuntimeBinary = Assert-PathBelow `
            (Join-Path $script:CodexRuntimeRoot 'codex-trusted-hook-launcher.exe') `
            $script:CodexRuntimeRoot `
            'protected Codex trusted hook launcher'
        [IO.File]::Copy(
            [string]$trustedLauncherIdentity.path,
            $script:CodexTrustedHookLauncherRuntimeBinary,
            $false
        )
        if ((Get-FileDigest $script:CodexTrustedHookLauncherRuntimeBinary) -cne
            [string]$trustedLauncherIdentity.sha256) {
            throw 'protected Codex trusted hook launcher staging changed bytes'
        }
        $stagedLauncherIdentity = Get-CodexTrustedHookLauncherIdentity `
            $script:CodexTrustedHookLauncherRuntimeBinary
        if ([string]$stagedLauncherIdentity.signer_thumbprint -cne
            [string]$trustedLauncherIdentity.signer_thumbprint) {
            throw 'protected Codex trusted hook launcher signer changed while staging'
        }
        $script:CodexTrustedHookLauncherIdentity = $stagedLauncherIdentity
    }
    $script:ClaudeRuntimeBinary = Assert-PathBelow `
        (Join-Path $script:CodexRuntimeRoot 'claude.exe') `
        $script:CodexRuntimeRoot `
        'protected Claude executable'
    $script:RejectedCodexRuntimeBinary = Assert-PathBelow `
        (Join-Path $script:CodexRuntimeRoot 'codex-rejected-old.exe') `
        $script:CodexRuntimeRoot `
        'protected rejected Codex executable'
    $script:RejectedClaudeRuntimeBinary = Assert-PathBelow `
        (Join-Path $script:CodexRuntimeRoot 'claude-rejected-old.exe') `
        $script:CodexRuntimeRoot `
        'protected rejected Claude executable'
    foreach ($copy in @(
        [pscustomobject]@{
            source = $script:OriginalClaudeSource
            destination = $script:ClaudeRuntimeBinary
            expected_sha256 = [string]$script:SourceDigests['claude']
            agent = 'claude'
        },
        [pscustomobject]@{
            source = $script:OriginalRejectedCodexSource
            destination = $script:RejectedCodexRuntimeBinary
            expected_sha256 = [string]$script:SourceDigests['rejected_codex']
            agent = 'codex'
        },
        [pscustomobject]@{
            source = $script:OriginalRejectedClaudeSource
            destination = $script:RejectedClaudeRuntimeBinary
            expected_sha256 = [string]$script:SourceDigests['rejected_claude']
            agent = 'claude'
        }
    )) {
        [IO.File]::Copy(
            (ConvertTo-CanonicalPath ([string]$copy.source)),
            [string]$copy.destination,
            $false
        )
        if ((Get-FileDigest ([string]$copy.destination)) -cne
            [string]$copy.expected_sha256) {
            throw "protected $($copy.agent) application-control staging changed bytes"
        }
        $null = Get-AgentBinaryTrustIdentity `
            ([string]$copy.destination) `
            ([string]$copy.agent)
    }
    $script:HostileShellProbeBinary = Assert-PathBelow `
        (Join-Path $script:CodexRuntimeRoot 'shell-probe.exe') `
        $script:CodexRuntimeRoot `
        'hostile shell probe executable'
    $probeClass = 'ShellProbe_' + $script:RunToken
    $probeSource = @"
using System;
using System.IO;
using System.Text;

public static class $probeClass
{
    public static int Main(string[] args)
    {
        string marker = Environment.GetEnvironmentVariable(
            "DEFENSECLAW_CERT_SHELL_PROBE_MARKER");
        if (!String.IsNullOrWhiteSpace(marker))
        {
            string[] argv = Environment.GetCommandLineArgs();
            File.AppendAllText(
                marker,
                String.Join(Environment.NewLine, argv) + Environment.NewLine,
                new UTF8Encoding(false));
        }
        return 0;
    }
}
"@
    $probeSourcePath = Assert-PathBelow `
        (Join-Path $script:CodexRuntimeRoot 'shell-probe.cs') `
        $script:CodexRuntimeRoot `
        'hostile shell probe source'
    [IO.File]::WriteAllText(
        $probeSourcePath,
        $probeSource,
        [Text.UTF8Encoding]::new($false)
    )
    $compiler = Assert-SourcePathHasNoReparse `
        (Join-Path `
            $script:WindowsDirectory `
            'Microsoft.NET\Framework64\v4.0.30319\csc.exe') `
        'fixed Windows C# compiler'
    try {
        $null = Invoke-NativeProcess `
            -FilePath $compiler `
            -ArgumentList @(
                '/nologo',
                '/target:exe',
                '/optimize+',
                ("/out:$($script:HostileShellProbeBinary)"),
                $probeSourcePath
            ) `
            -Label 'build-hostile-shell-probe' `
            -StrictWindowsBootstrapEnvironment
    } finally {
        if (Test-Path -LiteralPath $probeSourcePath -PathType Leaf) {
            Remove-Item -LiteralPath $probeSourcePath -Force
        }
    }
    if (-not (Test-Path -LiteralPath $script:HostileShellProbeBinary -PathType Leaf)) {
        throw 'failed to build the bounded hostile shell probe executable'
    }
    Assert-NoStandardUserAccess `
        -Path $script:CodexRuntimeRoot `
        -SID $script:PrimarySID `
        -DenyWrite

    $versionInput = [Convert]::ToBase64String(
        [Text.Encoding]::UTF8.GetBytes($script:CodexRuntimeBinary)
    )
    $versionProbe = Invoke-ActiveUserPowerShell `
        -Label 'codex-0.144.3-active-user-version' `
        -Script @"
`$ErrorActionPreference = 'Stop'
`$binary = [Text.Encoding]::UTF8.GetString(
    [Convert]::FromBase64String('$versionInput')
)
`$version = (& `$binary --version 2>&1 | Out-String).Trim()
if (`$LASTEXITCODE -ne 0) { exit `$LASTEXITCODE }
[pscustomobject]@{
    version = `$version
    sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
} | ConvertTo-Json -Compress
"@
    $version = ConvertFrom-SingleJSONDocument `
        $versionProbe.StdOut `
        'Codex active-user version'
    if ([string]$version.version -cne 'codex-cli 0.144.3' -or
        [string]$version.sid -ne $script:PrimarySID) {
        throw (
            'protected runtime is not exact Codex 0.144.3 under the target ' +
            "medium token: version=$($version.version) sid=$($version.sid)"
        )
    }
    $trustedLauncherVersion = $null
    if (-not $ClaudeOnly) {
        $launcherVersionInput = [Convert]::ToBase64String(
            [Text.Encoding]::UTF8.GetBytes(
                $script:CodexTrustedHookLauncherRuntimeBinary
            )
        )
        $launcherVersionProbe = Invoke-ActiveUserPowerShell `
            -Label 'codex-trusted-hook-launcher-active-user-version' `
            -Script @"
`$ErrorActionPreference = 'Stop'
`$binary = [Text.Encoding]::UTF8.GetString(
    [Convert]::FromBase64String('$launcherVersionInput')
)
`$version = (& `$binary --version 2>&1 | Out-String).Trim()
if (`$LASTEXITCODE -ne 0) { exit `$LASTEXITCODE }
[pscustomobject]@{
    version = `$version
    sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
} | ConvertTo-Json -Compress
"@
        $trustedLauncherVersion = ConvertFrom-SingleJSONDocument `
            $launcherVersionProbe.StdOut `
            'Codex trusted hook launcher active-user version'
        if ([string]$trustedLauncherVersion.version -cne 'codex-cli 0.144.3' -or
            [string]$trustedLauncherVersion.sid -ne $script:PrimarySID) {
            throw (
                'trusted hook launcher is not a drop-in Codex 0.144.3 CLI ' +
                "under the target medium token: version=" +
                "$($trustedLauncherVersion.version) sid=" +
                "$($trustedLauncherVersion.sid)"
            )
        }
    }
    $claudeVersionInput = [Convert]::ToBase64String(
        [Text.Encoding]::UTF8.GetBytes($script:ClaudeRuntimeBinary)
    )
    $claudeVersionProbe = Invoke-ActiveUserPowerShell `
        -Label 'claude-approved-active-user-version' `
        -Script @"
`$ErrorActionPreference = 'Stop'
`$binary = [Text.Encoding]::UTF8.GetString(
    [Convert]::FromBase64String('$claudeVersionInput')
)
`$version = (& `$binary --version 2>&1 | Out-String).Trim()
if (`$LASTEXITCODE -ne 0) { exit `$LASTEXITCODE }
[pscustomobject]@{
    version = `$version
    sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
} | ConvertTo-Json -Compress
"@
    $claudeVersion = ConvertFrom-SingleJSONDocument `
        $claudeVersionProbe.StdOut `
        'Claude active-user version'
    if ([string]$claudeVersion.version -notmatch
            '(?<!\d)2\.1\.(?:15[2-9]|1[6-9]\d|[2-9]\d{2,})(?!\d)' -or
        [string]$claudeVersion.sid -ne $script:PrimarySID) {
        throw (
            'protected runtime is not approved Claude >=2.1.152 under the ' +
            "target medium token: version=$($claudeVersion.version) " +
            "sid=$($claudeVersion.sid)"
        )
    }
    return [pscustomobject]@{
        codex_path = $script:CodexRuntimeBinary
        codex_sha256 = $sourceDigest
        codex_version = [string]$version.version
        codex_version_source = if ($null -eq $approvedCodexIdentity.version) {
            'protected_active_user_runtime_probe'
        } else {
            'pe_version_info_and_protected_active_user_runtime_probe'
        }
        codex_signer_subject = [string]$stagedSignature.SignerCertificate.Subject
        codex_trusted_hook_launcher_path =
            $script:CodexTrustedHookLauncherRuntimeBinary
        codex_trusted_hook_launcher_sha256 = if ($null -eq
            $script:CodexTrustedHookLauncherIdentity) {
            ''
        } else {
            [string]$script:CodexTrustedHookLauncherIdentity.sha256
        }
        codex_trusted_hook_launcher_signer_subject = if ($null -eq
            $script:CodexTrustedHookLauncherIdentity) {
            ''
        } else {
            [string]$script:CodexTrustedHookLauncherIdentity.signer_subject
        }
        codex_trusted_hook_launcher_version = if ($null -eq
            $trustedLauncherVersion) {
            ''
        } else {
            [string]$trustedLauncherVersion.version
        }
        claude_path = $script:ClaudeRuntimeBinary
        claude_sha256 = [string]$approvedClaudeIdentity.sha256
        claude_version = [string]$claudeVersion.version
        claude_signer_subject = [string]$approvedClaudeIdentity.signer_subject
        rejected_codex_path = $script:RejectedCodexRuntimeBinary
        rejected_codex_file_version = [string]$rejectedCodexIdentity.file_version
        rejected_claude_path = $script:RejectedClaudeRuntimeBinary
        rejected_claude_file_version = [string]$rejectedClaudeIdentity.file_version
        target_sid = [string]$version.sid
        target_write_denied = $true
    }
}

function Test-AgentApplicationControlBoundary {
    $home = Assert-CertificationCodexHomePath `
        $script:CertificationCodexHome `
        -RequireExisting
    $fixtureRoot = Assert-PathBelow `
        (Join-Path $home 'application-control') `
        $home `
        'user-writable application-control fixture'
    if (Test-Path -LiteralPath $fixtureRoot) {
        throw "application-control fixture already exists: $fixtureRoot"
    }
    $sourceMap = [ordered]@{
        approved_codex = $script:CodexRuntimeBinary
        approved_claude = $script:ClaudeRuntimeBinary
        rejected_codex = $script:RejectedCodexRuntimeBinary
        rejected_claude = $script:RejectedClaudeRuntimeBinary
        custom_codex = $script:HostileShellProbeBinary
        custom_claude = $script:HostileShellProbeBinary
        fake_pwsh = $script:HostileShellProbeBinary
        fake_powershell = $script:HostileShellProbeBinary
    }
    $leafMap = [ordered]@{
        approved_codex = 'codex.exe'
        approved_claude = 'claude.exe'
        rejected_codex = 'codex-old.exe'
        rejected_claude = 'claude-old.exe'
        custom_codex = 'codex-custom.exe'
        custom_claude = 'claude-custom.exe'
        fake_pwsh = 'pwsh.exe'
        fake_powershell = 'powershell.exe'
    }
    $copyInput = [ordered]@{
        root = $fixtureRoot
        expected_sid = $script:PrimarySID
        sources = $sourceMap
        leaves = $leafMap
    }
    $copyInputBase64 = [Convert]::ToBase64String(
        [Text.Encoding]::UTF8.GetBytes(
            ($copyInput | ConvertTo-Json -Compress -Depth 5)
        )
    )
    $copyResult = Invoke-ActiveUserPowerShell `
        -Label 'create-user-writable-application-control-fixture' `
        -TimeoutSeconds 120 `
        -Script @'
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$inputObject = [Text.Encoding]::UTF8.GetString(
    [Convert]::FromBase64String('__INPUT__')
) | ConvertFrom-Json -ErrorAction Stop
$actualSID = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
if ($actualSID -ne [string]$inputObject.expected_sid) {
    throw "application-control fixture SID mismatch: $actualSID"
}
$root = [IO.Path]::GetFullPath([string]$inputObject.root)
[IO.Directory]::CreateDirectory($root) | Out-Null
$files = [ordered]@{}
foreach ($property in $inputObject.sources.PSObject.Properties) {
    $name = [string]$property.Name
    $source = [IO.Path]::GetFullPath([string]$property.Value)
    $leaf = [string]$inputObject.leaves.$name
    $destination = [IO.Path]::GetFullPath((Join-Path $root $leaf))
    if (-not [string]::Equals(
        [IO.Path]::GetDirectoryName($destination),
        $root,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "application-control destination escaped fixture root: $destination"
    }
    [IO.File]::Copy($source, $destination, $false)
    # Prove the active standard user owns and can modify this portable copy.
    $stream = [IO.File]::Open(
        $destination,
        [IO.FileMode]::Open,
        [IO.FileAccess]::ReadWrite,
        [IO.FileShare]::Read
    )
    $stream.Dispose()
    $files[$name] = [pscustomobject]@{
        path = $destination
        sha256 = (Get-FileHash -LiteralPath $destination -Algorithm SHA256).
            Hash.ToLowerInvariant()
        owner = (Get-Acl -LiteralPath $destination).Owner
        target_read_write_open = $true
    }
}
[pscustomobject]@{
    sid = $actualSID
    root = $root
    files = $files
} | ConvertTo-Json -Compress -Depth 6
'@.Replace('__INPUT__', $copyInputBase64)
    $fixture = ConvertFrom-SingleJSONDocument `
        $copyResult.StdOut `
        'user-writable application-control fixture'
    if ([string]$fixture.sid -ne $script:PrimarySID -or
        -not [string]::Equals(
            (ConvertTo-CanonicalPath ([string]$fixture.root)),
            $fixtureRoot,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw 'application-control fixture was not created by the exact target SID'
    }
    foreach ($name in $sourceMap.Keys) {
        $row = $fixture.files.PSObject.Properties[[string]$name]
        if ($null -eq $row) {
            throw "application-control fixture omitted $name"
        }
        $path = Assert-PathBelow `
            ([string]$row.Value.path) `
            $fixtureRoot `
            "application-control $name"
        if ((Get-FileDigest $path) -cne
            (Get-FileDigest ([string]$sourceMap[$name])) -or
            -not [bool]$row.Value.target_read_write_open) {
            throw "user-writable application-control copy $name is not byte-exact and writable"
        }
    }

    $script:CodexRejectedClientMarker = Assert-PathBelow `
        (Join-Path $home ".defenseclaw-rejected-client-$($script:RunToken).txt") `
        $home `
        'rejected client marker'
    if (Test-Path -LiteralPath $script:CodexRejectedClientMarker) {
        throw "rejected-client marker already exists: $($script:CodexRejectedClientMarker)"
    }
    $probeInput = [ordered]@{
        expected_sid = $script:PrimarySID
        marker = $script:CodexRejectedClientMarker
        files = $fixture.files
    }
    $probeInputBase64 = [Convert]::ToBase64String(
        [Text.Encoding]::UTF8.GetBytes(
            ($probeInput | ConvertTo-Json -Compress -Depth 6)
        )
    )
    $probeResult = Invoke-ActiveUserPowerShell `
        -Label 'live-agent-application-control-boundary' `
        -TimeoutSeconds 180 `
        -Script @'
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$inputObject = [Text.Encoding]::UTF8.GetString(
    [Convert]::FromBase64String('__INPUT__')
) | ConvertFrom-Json -ErrorAction Stop
$actualSID = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
if ($actualSID -ne [string]$inputObject.expected_sid) {
    throw "application-control probe SID mismatch: $actualSID"
}
function Invoke-ProbeProcess([string]$Name, [string]$Path, [string[]]$Arguments) {
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $Path
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.Environment['DEFENSECLAW_CERT_SHELL_PROBE_MARKER'] =
        [string]$inputObject.marker
    foreach ($argument in $Arguments) {
        $start.ArgumentList.Add($argument)
    }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    try {
        $started = $process.Start()
        if (-not $started) {
            return [pscustomobject]@{
                name = $Name
                path = $Path
                process_started = $false
                native_error_code = 0
                diagnostic = 'Process.Start returned false'
            }
        }
        $stdout = $process.StandardOutput.ReadToEnd()
        $stderr = $process.StandardError.ReadToEnd()
        if (-not $process.WaitForExit(30000)) {
            $process.Kill()
            throw "$Name process exceeded 30 seconds"
        }
        return [pscustomobject]@{
            name = $Name
            path = $Path
            process_started = $true
            exit_code = [int]$process.ExitCode
            stdout = $stdout.Trim()
            stderr = $stderr.Trim()
            native_error_code = 0
        }
    } catch [ComponentModel.Win32Exception] {
        return [pscustomobject]@{
            name = $Name
            path = $Path
            process_started = $false
            native_error_code = [int]$_.Exception.NativeErrorCode
            diagnostic = $_.Exception.Message
        }
    } finally {
        $process.Dispose()
    }
}
$results = [Collections.Generic.List[object]]::new()
foreach ($case in @(
    [pscustomobject]@{ name = 'approved_codex'; args = @('--version') },
    [pscustomobject]@{ name = 'approved_claude'; args = @('--version') },
    [pscustomobject]@{ name = 'rejected_codex'; args = @('--version') },
    [pscustomobject]@{ name = 'rejected_claude'; args = @('--version') },
    [pscustomobject]@{ name = 'custom_codex'; args = @() },
    [pscustomobject]@{ name = 'custom_claude'; args = @() },
    [pscustomobject]@{ name = 'fake_pwsh'; args = @() },
    [pscustomobject]@{ name = 'fake_powershell'; args = @() }
)) {
    $path = [string]$inputObject.files.($case.name).path
    $results.Add((Invoke-ProbeProcess $case.name $path @($case.args)))
}
[pscustomobject]@{
    sid = $actualSID
    results = @($results.ToArray())
    marker_exists = Test-Path -LiteralPath ([string]$inputObject.marker)
} | ConvertTo-Json -Compress -Depth 7
'@.Replace('__INPUT__', $probeInputBase64)
    $probe = ConvertFrom-SingleJSONDocument `
        $probeResult.StdOut `
        'live agent application-control boundary'
    if ([string]$probe.sid -ne $script:PrimarySID) {
        throw 'application-control process probes did not run as the exact target SID'
    }
    $rows = @($probe.results)
    foreach ($approved in @('approved_codex', 'approved_claude')) {
        $row = @($rows | Where-Object { [string]$_.name -eq $approved })
        if ($row.Count -ne 1 -or
            -not [bool]$row[0].process_started -or
            [int]$row[0].exit_code -ne 0) {
            throw "application control blocked approved signed client $approved"
        }
    }
    $approvedCodex = @(
        $rows | Where-Object { [string]$_.name -eq 'approved_codex' }
    )[0]
    $approvedClaude = @(
        $rows | Where-Object { [string]$_.name -eq 'approved_claude' }
    )[0]
    if ([string]$approvedCodex.stdout -cne 'codex-cli 0.144.3' -or
        [string]$approvedClaude.stdout -notmatch
            '(?<!\d)2\.1\.(?:15[2-9]|1[6-9]\d|[2-9]\d{2,})(?!\d)') {
        throw 'approved portable clients did not report the certified versions'
    }
    foreach ($rejected in @(
        'rejected_codex',
        'rejected_claude',
        'custom_codex',
        'custom_claude',
        'fake_pwsh',
        'fake_powershell'
    )) {
        $row = @($rows | Where-Object { [string]$_.name -eq $rejected })
        if ($row.Count -ne 1 -or [bool]$row[0].process_started) {
            throw "application control allowed forbidden portable executable $rejected"
        }
        if ([int]$row[0].native_error_code -notin @(5, 577, 1260)) {
            throw (
                "forbidden $rejected was not rejected with an OS application-" +
                "control error; native=$($row[0].native_error_code) " +
                "diagnostic=$([string]$row[0].diagnostic)"
            )
        }
    }
    if ([bool]$probe.marker_exists -or (
        Test-Path -LiteralPath $script:CodexRejectedClientMarker
    )) {
        throw 'an unsigned custom client or fake shell executed and wrote its marker'
    }
    return [pscustomobject]@{
        approved_portable_clients = @('codex 0.144.3', 'claude >=2.1.152')
        rejected_portable_clients = @(
            'signed Codex <0.131.0',
            'signed Claude <2.1.152',
            'unsigned custom Codex',
            'unsigned custom Claude',
            'fake pwsh',
            'fake powershell'
        )
        fixture_root = $fixtureRoot
        target_sid = $script:PrimarySID
        target_writable = $true
        process_results = @($rows)
        unsigned_marker_absent = $true
    }
}

function Get-FreeLoopbackPort {
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    $listener.Start()
    try {
        return ([Net.IPEndPoint]$listener.LocalEndpoint).Port
    } finally {
        $listener.Stop()
    }
}

function Write-UTF8File([string]$Path, [string]$Content) {
    $parent = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        [IO.Directory]::CreateDirectory($parent) | Out-Null
    }
    [IO.File]::WriteAllText($Path, $Content, [Text.UTF8Encoding]::new($false))
}

function Get-FileDigest([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return '' }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-ProtectedUserTreeInventory([string]$Path, [string]$Label) {
    $root = ConvertTo-CanonicalPath $Path
    if (-not (Test-Path -LiteralPath $root)) {
        return [pscustomobject]@{
            root = $root
            existed = $false
            entries = @()
        }
    }
    $rootItem = Get-Item -LiteralPath $root -Force
    if (-not $rootItem.PSIsContainer -or
        ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Label root is not a real directory: $root"
    }
    $sections = (
        [Security.AccessControl.AccessControlSections]::Access -bor
        [Security.AccessControl.AccessControlSections]::Owner -bor
        [Security.AccessControl.AccessControlSections]::Group
    )
    $items = @($rootItem) + @(Get-ChildItem -LiteralPath $root -Force -Recurse)
    $entries = [Collections.Generic.List[object]]::new()
    foreach ($item in $items) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "$Label contains a reparse point that cannot be snapshotted safely: $($item.FullName)"
        }
        if (-not $item.PSIsContainer -and -not (Test-Path -LiteralPath $item.FullName -PathType Leaf)) {
            throw "$Label contains a non-regular filesystem object: $($item.FullName)"
        }
        $relative = if ($item.FullName.Equals(
            $root,
            [StringComparison]::OrdinalIgnoreCase
        )) {
            '.'
        } else {
            $item.FullName.Substring($root.Length).TrimStart('\')
        }
        $acl = Get-Acl -LiteralPath $item.FullName
        $entries.Add([pscustomobject]@{
            relative_path = $relative
            kind = if ($item.PSIsContainer) { 'directory' } else { 'file' }
            sha256 = if ($item.PSIsContainer) { '' } else { Get-FileDigest $item.FullName }
            length = if ($item.PSIsContainer) { 0 } else { [long]$item.Length }
            attributes = [int]$item.Attributes
            last_write_utc_ticks = [long]$item.LastWriteTimeUtc.Ticks
            sddl = $acl.GetSecurityDescriptorSddlForm($sections)
        })
    }
    return [pscustomobject]@{
        root = $root
        existed = $true
        entries = @($entries | Sort-Object relative_path)
    }
}

function Assert-SameUserTreeInventory([object]$Expected, [object]$Actual, [string]$Label) {
    if ([bool]$Expected.existed -ne [bool]$Actual.existed) {
        throw "$Label existence changed"
    }
    $expectedRows = @($Expected.entries)
    $actualRows = @($Actual.entries)
    if ($expectedRows.Count -ne $actualRows.Count) {
        throw "$Label entry count changed: $($expectedRows.Count) -> $($actualRows.Count)"
    }
    for ($index = 0; $index -lt $expectedRows.Count; $index++) {
        $before = $expectedRows[$index]
        $after = $actualRows[$index]
        foreach ($property in @(
            'relative_path',
            'kind',
            'sha256',
            'length',
            'attributes',
            'last_write_utc_ticks',
            'sddl'
        )) {
            if ([string]$before.$property -cne [string]$after.$property) {
                throw "$Label changed $($before.relative_path) property $property"
            }
        }
    }
}

function Assert-UserTreeBackupMatches([object]$Inventory, [string]$BackupPath, [string]$Label) {
    foreach ($row in @($Inventory.entries)) {
        $candidate = if ([string]$row.relative_path -eq '.') {
            $BackupPath
        } else {
            Join-Path $BackupPath ([string]$row.relative_path)
        }
        if ([string]$row.kind -eq 'directory') {
            if (-not (Test-Path -LiteralPath $candidate -PathType Container)) {
                throw "$Label backup omitted directory $($row.relative_path)"
            }
        } else {
            if (-not (Test-Path -LiteralPath $candidate -PathType Leaf) -or
                (Get-FileDigest $candidate) -ne [string]$row.sha256) {
                throw "$Label backup omitted or changed file $($row.relative_path)"
            }
        }
    }
}

function New-ProtectedUserTreeSnapshot(
    [string]$Path,
    [string]$Name,
    [switch]$Ephemeral
) {
    if ($Name -notmatch '^[a-z0-9-]+$') {
        throw "unsafe protected-user snapshot name: $Name"
    }
    $inventory = Get-ProtectedUserTreeInventory $Path $Name
    $backup = Assert-PathBelow `
        (Join-Path $script:StagingRoot "user-baseline\$Name") `
        $script:StagingRoot `
        "$Name backup"
    if ([bool]$inventory.existed) {
        [IO.Directory]::CreateDirectory($backup) | Out-Null
        Protect-AdministratorTree $backup
        $robocopy = Join-Path $script:System32 'robocopy.exe'
        $null = Invoke-NativeProcess `
            -FilePath $robocopy `
            -ArgumentList @(
                [string]$inventory.root,
                $backup,
                '/E',
                '/COPY:DAT',
                '/DCOPY:DAT',
                '/XJ',
                '/R:1',
                '/W:1',
                '/NFL',
                '/NDL',
                '/NJH',
                '/NJS',
                '/NP'
            ) `
            -AllowedExitCodes @(0, 1, 2, 3, 4, 5, 6, 7) `
            -TimeoutSeconds 300 `
            -Label "snapshot-$Name"
        Assert-UserTreeBackupMatches $inventory $backup $Name
        $after = Get-ProtectedUserTreeInventory $Path "$Name post-snapshot"
        Assert-SameUserTreeInventory $inventory $after "$Name snapshot stability"
    }
    $snapshot = [pscustomobject]@{
        name = $Name
        path = [string]$inventory.root
        backup = $backup
        inventory = $inventory
    }
    if (-not $Ephemeral) {
        $script:UserTreeSnapshots.Add($snapshot)
    }
    return $snapshot
}

function Remove-ExactCanonicalUserTreeReparse(
    [string]$Path,
    [string]$Label
) {
    $safe = Assert-PathBelow $Path $script:PrimaryProfile $Label
    $isCertificationCodexHome = (
        -not [string]::IsNullOrWhiteSpace($script:CertificationCodexHome) -and
        $safe.Equals(
            $script:CertificationCodexHome,
            [StringComparison]::OrdinalIgnoreCase
        )
    )
    if (-not $isCertificationCodexHome -and
        [IO.Path]::GetFileName($safe) -cne '.defenseclaw') {
        throw "$Label reparse root is unexpected: $safe"
    }
    if (-not (Test-Path -LiteralPath $safe)) {
        return
    }
    $item = Get-Item -LiteralPath $safe -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) {
        throw "$Label expected an exact root reparse point: $safe"
    }
    if (-not $item.PSIsContainer) {
        throw "$Label refuses a non-directory root reparse point: $safe"
    }
    [IO.Directory]::Delete($safe, $false)
    if (Test-Path -LiteralPath $safe) {
        throw "$Label did not remove the exact root reparse point: $safe"
    }
}

function Restore-ProtectedUserTreeSnapshot([object]$Snapshot) {
    $root = ConvertTo-CanonicalPath ([string]$Snapshot.path)
    $safe = Assert-PathBelow $root $script:PrimaryProfile "$($Snapshot.name) restore"
    $isCertificationCodexHome = (
        -not [string]::IsNullOrWhiteSpace($script:CertificationCodexHome) -and
        $safe.Equals(
            $script:CertificationCodexHome,
            [StringComparison]::OrdinalIgnoreCase
        )
    )
    if (-not $isCertificationCodexHome -and
        [IO.Path]::GetFileName($safe) -cne '.defenseclaw') {
        throw "protected-user restore root is unexpected: $safe"
    }
    if (Test-Path -LiteralPath $safe) {
        $item = Get-Item -LiteralPath $safe -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            Remove-ExactCanonicalUserTreeReparse `
                -Path $safe `
                -Label "$($Snapshot.name) restore"
        } else {
            Remove-Item -LiteralPath $safe -Recurse -Force -ErrorAction Stop
        }
    }
    if (-not [bool]$Snapshot.inventory.existed) {
        if (Test-Path -LiteralPath $safe) {
            throw "absent baseline remains after cleanup: $safe"
        }
        return
    }

    [IO.Directory]::CreateDirectory($safe) | Out-Null
    $robocopy = Join-Path $script:System32 'robocopy.exe'
    $null = Invoke-NativeProcess `
        -FilePath $robocopy `
        -ArgumentList @(
            [string]$Snapshot.backup,
            $safe,
            '/E',
            '/COPY:DAT',
            '/DCOPY:DAT',
            '/XJ',
            '/R:1',
            '/W:1',
            '/NFL',
            '/NDL',
            '/NJH',
            '/NJS',
            '/NP'
        ) `
        -AllowedExitCodes @(0, 1, 2, 3, 4, 5, 6, 7) `
        -TimeoutSeconds 300 `
        -Label "restore-$($Snapshot.name)"

    $sections = (
        [Security.AccessControl.AccessControlSections]::Access -bor
        [Security.AccessControl.AccessControlSections]::Owner -bor
        [Security.AccessControl.AccessControlSections]::Group
    )
    $rows = @($Snapshot.inventory.entries | Sort-Object {
        ([string]$_.relative_path).Length
    } -Descending)
    foreach ($row in $rows) {
        $target = if ([string]$row.relative_path -eq '.') {
            $safe
        } else {
            Join-Path $safe ([string]$row.relative_path)
        }
        $security = if ([string]$row.kind -eq 'directory') {
            [Security.AccessControl.DirectorySecurity]::new()
        } else {
            [Security.AccessControl.FileSecurity]::new()
        }
        $security.SetSecurityDescriptorSddlForm([string]$row.sddl, $sections)
        Set-Acl -LiteralPath $target -AclObject $security
        $lastWrite = [DateTime]::new(
            [long]$row.last_write_utc_ticks,
            [DateTimeKind]::Utc
        )
        if ([string]$row.kind -eq 'directory') {
            [IO.Directory]::SetLastWriteTimeUtc($target, $lastWrite)
        } else {
            [IO.File]::SetLastWriteTimeUtc($target, $lastWrite)
        }
        (Get-Item -LiteralPath $target -Force).Attributes = [IO.FileAttributes]([int]$row.attributes)
    }
    $restored = Get-ProtectedUserTreeInventory $safe "$($Snapshot.name) restored"
    Assert-SameUserTreeInventory $Snapshot.inventory $restored "$($Snapshot.name) restore"
}

function Get-DeploymentDigests {
    $paths = [ordered]@{
        gateway = Join-Path $script:InstallRoot 'bin\defenseclaw-gateway.exe'
        hook = Join-Path $script:InstallRoot 'bin\defenseclaw-hook.exe'
        cli = Join-Path $script:InstallRoot 'bin\defenseclaw.exe'
        config = Join-Path $script:StateRoot 'etc\config.yaml'
        manifest = Join-Path $script:StateRoot 'hook-guardian\targets.yaml'
        deployment = Join-Path $script:StateRoot 'install\deployment.json'
    }
    $out = [ordered]@{}
    foreach ($entry in $paths.GetEnumerator()) {
        $out[$entry.Key] = Get-FileDigest $entry.Value
    }
    return [pscustomobject]$out
}

function Assert-SameDigests([object]$Before, [object]$After, [string]$Context) {
    foreach ($property in $Before.PSObject.Properties) {
        $name = $property.Name
        $afterProperty = $After.PSObject.Properties[$name]
        if ($null -eq $afterProperty -or
            -not [string]::Equals(
                [string]$property.Value,
                [string]$afterProperty.Value,
                [StringComparison]::Ordinal
            )) {
            throw "$Context changed $name digest: $($property.Value) -> $($afterProperty.Value)"
        }
    }
}

function Get-MachineRootIdentitySnapshot([string[]]$Paths) {
    $sections = (
        [Security.AccessControl.AccessControlSections]::Access -bor
        [Security.AccessControl.AccessControlSections]::Owner -bor
        [Security.AccessControl.AccessControlSections]::Group
    )
    $rows = [Collections.Generic.List[object]]::new()
    foreach ($path in @($Paths | Sort-Object -Unique)) {
        $full = ConvertTo-CanonicalPath $path
        if (-not (Test-Path -LiteralPath $full)) {
            $rows.Add([pscustomobject]@{
                path = $full
                existed = $false
                kind = ''
                attributes = 0
                last_write_utc_ticks = 0
                sddl = ''
            })
            continue
        }
        $item = Get-Item -LiteralPath $full -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "managed machine-root probe refuses a reparse point: $full"
        }
        $acl = Get-Acl -LiteralPath $full
        $rows.Add([pscustomobject]@{
            path = $full
            existed = $true
            kind = if ($item.PSIsContainer) { 'directory' } else { 'file' }
            attributes = [int]$item.Attributes
            last_write_utc_ticks = [long]$item.LastWriteTimeUtc.Ticks
            sddl = $acl.GetSecurityDescriptorSddlForm($sections)
        })
    }
    return $rows.ToArray()
}

function Get-DefenseClawServiceInventory {
    return @(
        Get-CimInstance Win32_Service -ErrorAction Stop |
            Where-Object { [string]$_.Name -like 'DefenseClaw*' } |
            Sort-Object Name |
            ForEach-Object {
                [pscustomobject]@{
                    name = [string]$_.Name
                    state = [string]$_.State
                    start_mode = [string]$_.StartMode
                    start_name = [string]$_.StartName
                    path_name = [string]$_.PathName
                }
            }
    )
}

function Assert-SameObjectJSON([object]$Before, [object]$After, [string]$Label) {
    $beforeJSON = $Before | ConvertTo-Json -Compress -Depth 8
    $afterJSON = $After | ConvertTo-Json -Compress -Depth 8
    if (-not [string]::Equals(
        $beforeJSON,
        $afterJSON,
        [StringComparison]::Ordinal
    )) {
        throw "$Label changed: $beforeJSON -> $afterJSON"
    }
}

function Get-NormalModeEnterpriseMachineSnapshot {
    $paths = @(
        $script:InstallRoot,
        $script:StateRoot,
        (Join-Path $script:KnownProgramFiles 'Cisco\DefenseClaw'),
        (Join-Path $script:KnownProgramData 'Cisco\DefenseClaw'),
        $script:LifecycleLockDirectory,
        $script:LifecycleLockPath,
        (Join-Path $script:InstallRoot 'bin\defenseclaw-gateway.exe'),
        (Join-Path $script:InstallRoot 'bin\defenseclaw-hook.exe'),
        (Join-Path $script:InstallRoot 'bin\defenseclaw.exe'),
        (Join-Path $script:StateRoot 'etc\config.yaml'),
        (Join-Path $script:StateRoot 'hook-guardian\targets.yaml'),
        (Join-Path $script:StateRoot 'hook-guardian-state\protected_targets.json'),
        (Join-Path $script:StateRoot 'install\deployment.json'),
        $script:CodexVendorDirectory,
        $script:CodexMachinePolicyDirectory,
        $script:CodexRequirementsPath,
        $script:CodexMachineLockPath,
        $script:CodexManagedStatePath,
        $script:ClaudeManagedPolicyDirectory,
        $script:ClaudeManagedPolicyPath,
        $script:ClaudeManagedStatePath,
        $script:ClaudeManagedLockPath
    )
    $identity = @(Get-MachineRootIdentitySnapshot $paths)
    $fileDigests = @(
        $identity |
            Where-Object { [bool]$_.existed -and [string]$_.kind -eq 'file' } |
            ForEach-Object {
                [pscustomobject]@{
                    path = [string]$_.path
                    sha256 = Get-FileDigest ([string]$_.path)
                }
            }
    )
    return [pscustomobject]@{
        paths = $identity
        file_digests = $fileDigests
        services = @(Get-DefenseClawServiceInventory)
    }
}

function Test-NormalModePreinstallNoOp {
    $dataRoot = Assert-PathBelow `
        (Join-Path $script:FixtureRoot 'normal-mode-unmanaged-data') `
        $script:StagingRoot `
        'normal-mode data root'
    if (Test-Path -LiteralPath $dataRoot) {
        throw "normal-mode data-root fixture already exists: $dataRoot"
    }
    $configPath = Join-Path $script:FixtureRoot 'normal-mode-unmanaged-config.yaml'
    $dataYAML = $dataRoot.Replace("'", "''")
    $config = @"
config_version: 8
deployment_mode: unmanaged_byod
data_dir: '$dataYAML'
guardrail:
  enabled: true
  mode: observe
  scanner_mode: local
  hook_self_heal: true
application_protection:
  enabled: false
"@
    Write-ProtectedManifest $configPath $config 'normal-mode-noop-config'

    foreach ($snapshot in @($script:UserTreeSnapshots.ToArray())) {
        $current = Get-ProtectedUserTreeInventory `
            ([string]$snapshot.path) `
            "$($snapshot.name) before normal-mode no-op"
        Assert-SameUserTreeInventory `
            $snapshot.inventory `
            $current `
            "$($snapshot.name) before normal-mode no-op"
    }
    $machineRoots = @(
        $script:InstallRoot,
        $script:StateRoot,
        (Join-Path $script:KnownProgramFiles 'Cisco\DefenseClaw'),
        (Join-Path $script:KnownProgramData 'Cisco\DefenseClaw'),
        $script:CodexVendorDirectory,
        $script:CodexMachinePolicyDirectory
    )
    $rootBefore = Get-MachineRootIdentitySnapshot $machineRoots
    $servicesBefore = Get-DefenseClawServiceInventory
    $installerStatus = Invoke-EnterpriseInstallerJSON `
        -Action Status `
        -GatewaySource '' `
        -HookSource '' `
        -CLISource '' `
        -Label 'preinstall-installer-status-noop'
    if (-not [bool]$installerStatus.JSON.ok -or
        [bool]$installerStatus.JSON.installed) {
        throw 'pre-install installer Status did not report a healthy absent deployment'
    }
    $process = Invoke-NativeProcess `
        -FilePath $script:GatewaySource `
        -ArgumentList @('enterprise', 'hooks', 'status', '--json') `
        -Environment @{
            DEFENSECLAW_CONFIG = $configPath
            DEFENSECLAW_HOME = $dataRoot
            DEFENSECLAW_DEPLOYMENT_MODE = 'unmanaged_byod'
            DEFENSECLAW_HOOK_GUARDIAN_AUTH_DIR = $null
            CODEX_HOME = $null
        } `
        -Label 'preinstall-normal-mode-enterprise-status'
    $status = ConvertFrom-SingleJSONDocument `
        $process.StdOut `
        'preinstall normal-mode enterprise status'
    if ([bool]$status.enabled -or -not [bool]$status.ok) {
        throw 'unmanaged pre-install status did not report enabled=false and ok=true'
    }
    if (Test-Path -LiteralPath $dataRoot) {
        throw "unmanaged status created its explicit data root: $dataRoot"
    }
    $rootAfter = Get-MachineRootIdentitySnapshot $machineRoots
    Assert-SameObjectJSON $rootBefore $rootAfter 'unmanaged status machine roots'
    $servicesAfter = Get-DefenseClawServiceInventory
    Assert-SameObjectJSON $servicesBefore $servicesAfter 'unmanaged status services'
    foreach ($snapshot in @($script:UserTreeSnapshots.ToArray())) {
        $current = Get-ProtectedUserTreeInventory `
            ([string]$snapshot.path) `
            "$($snapshot.name) after normal-mode no-op"
        Assert-SameUserTreeInventory `
            $snapshot.inventory `
            $current `
            "$($snapshot.name) after normal-mode no-op"
    }
    return 'installer Status and candidate gateway reported an absent/disabled enterprise deployment; created no service/data/Codex-policy/machine root; canonical user-tree bytes and security metadata remained exact'
}

function Test-NormalModeLiveAutoHeal([switch]$RequireEnterpriseAbsent) {
    $machineBefore = Get-NormalModeEnterpriseMachineSnapshot
    if ($RequireEnterpriseAbsent) {
        $requiredAbsentPaths = @(
            $script:InstallRoot,
            $script:StateRoot,
            (Join-Path $script:KnownProgramFiles 'Cisco\DefenseClaw'),
            (Join-Path $script:KnownProgramData 'Cisco\DefenseClaw'),
            $script:LifecycleLockDirectory,
            $script:CodexVendorDirectory,
            $script:ClaudeManagedPolicyPath,
            $script:ClaudeManagedStatePath,
            $script:ClaudeManagedLockPath
        ) | ForEach-Object { ConvertTo-CanonicalPath $_ }
        $unexpectedPaths = @(
            $machineBefore.paths |
                Where-Object {
                    [bool]$_.existed -and
                    $requiredAbsentPaths -contains [string]$_.path
                } |
                ForEach-Object { [string]$_.path }
        )
        if ($unexpectedPaths.Count -ne 0 -or
            @($machineBefore.services).Count -ne 0) {
            throw (
                'normal-mode live auto-heal requires an absent enterprise ' +
                "machine baseline; paths=[$($unexpectedPaths -join ',')]; " +
                "services=[$(@($machineBefore.services.name) -join ',')]"
            )
        }
    }

    $syntheticHome = Assert-PathBelow `
        (Join-Path `
            $script:PrimaryProfile `
            ".defenseclaw-normal-$($script:RunToken)") `
        $script:PrimaryProfile `
        'normal-mode synthetic home'
    $script:NormalModeSyntheticHome = $syntheticHome
    if (-not (Split-Path -Parent $syntheticHome).Equals(
        $script:PrimaryProfile,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw 'normal-mode synthetic home is not an exact profile child'
    }
    if (Test-Path -LiteralPath $syntheticHome) {
        throw "normal-mode synthetic home already exists: $syntheticHome"
    }
    $before = Get-ProtectedUserTreeInventory `
        $syntheticHome `
        'normal synthetic home before'

    $dataRoot = Join-Path $syntheticHome '.defenseclaw'
    $codexHome = Join-Path $syntheticHome '.codex'
    $claudeHome = Join-Path $syntheticHome '.claude'
    $runtimeRoot = Join-Path $syntheticHome '.local\bin'
    $workRoot = Join-Path $syntheticHome 'work'
    $appData = Join-Path $syntheticHome 'AppData\Roaming'
    $localAppData = Join-Path $syntheticHome 'AppData\Local'
    $tempRoot = Join-Path $localAppData 'Temp'
    foreach ($path in @(
        $runtimeRoot,
        $workRoot,
        $appData,
        $localAppData,
        $tempRoot
    )) {
        [IO.Directory]::CreateDirectory($path) | Out-Null
    }

    $runtimeFiles = [ordered]@{
        cli = [pscustomobject]@{
            source = $script:NormalModeCLILauncherSource
            destination = Join-Path $runtimeRoot 'defenseclaw.exe'
        }
        wheel = [pscustomobject]@{
            source = $script:NormalModeCLIWheelSource
            destination = Join-Path $runtimeRoot 'defenseclaw.whl'
        }
        gateway = [pscustomobject]@{
            source = if ($RequireEnterpriseAbsent) {
                $script:GatewaySource
            } else {
                Join-Path $script:InstallRoot 'bin\defenseclaw-gateway.exe'
            }
            destination = Join-Path $runtimeRoot 'defenseclaw-gateway.exe'
        }
        hook = [pscustomobject]@{
            source = if ($RequireEnterpriseAbsent) {
                $script:HookSource
            } else {
                Join-Path $script:InstallRoot 'bin\defenseclaw-hook.exe'
            }
            destination = Join-Path $runtimeRoot 'defenseclaw-hook.exe'
        }
        codex = [pscustomobject]@{
            source = $script:CodexRuntimeBinary
            destination = Join-Path $runtimeRoot 'codex.exe'
        }
    }
    foreach ($entry in $runtimeFiles.GetEnumerator()) {
        if (-not (Test-Path -LiteralPath $entry.Value.source -PathType Leaf)) {
            throw "normal-mode $($entry.Key) source is missing: $($entry.Value.source)"
        }
        $sourceDigest = Get-FileDigest ([string]$entry.Value.source)
        [IO.File]::Copy(
            [string]$entry.Value.source,
            [string]$entry.Value.destination,
            $false
        )
        $destinationDigest = Get-FileDigest ([string]$entry.Value.destination)
        if ([string]::IsNullOrWhiteSpace($sourceDigest) -or
            $destinationDigest -cne $sourceDigest) {
            throw "normal-mode $($entry.Key) runtime copy is not byte-exact"
        }
        $entry.Value | Add-Member `
            -NotePropertyName sha256 `
            -NotePropertyValue $destinationDigest
    }
    $null = Set-ICaclsOwnerAndDacl `
        -Path $syntheticHome `
        -Owner "*$($script:PrimarySID)" `
        -Grants @(
            "*$($script:PrimarySID):(OI)(CI)F",
            '*S-1-5-18:(OI)(CI)F',
            '*S-1-5-32-544:(OI)(CI)F'
        ) `
        -Label 'normal-mode-synthetic-home-dacl'

    $inputObject = [ordered]@{
        expected_sid = $script:PrimarySID
        profile = $script:PrimaryProfile
        synthetic_home = $syntheticHome
        data_root = $dataRoot
        codex_home = $codexHome
        claude_home = $claudeHome
        runtime_root = $runtimeRoot
        work_root = $workRoot
        app_data = $appData
        local_app_data = $localAppData
        temp_root = $tempRoot
        source_cli = [string]$runtimeFiles.cli.destination
        source_wheel = [string]$runtimeFiles.wheel.destination
        source_gateway = [string]$runtimeFiles.gateway.destination
        source_hook = [string]$runtimeFiles.hook.destination
        source_codex = [string]$runtimeFiles.codex.destination
        cli_sha256 = [string]$runtimeFiles.cli.sha256
        wheel_sha256 = [string]$runtimeFiles.wheel.sha256
        gateway_sha256 = [string]$runtimeFiles.gateway.sha256
        hook_sha256 = [string]$runtimeFiles.hook.sha256
        codex_sha256 = [string]$runtimeFiles.codex.sha256
        api_port = Get-FreeLoopbackPort
    }
    $inputBase64 = [Convert]::ToBase64String(
        [Text.Encoding]::UTF8.GetBytes(
            ($inputObject | ConvertTo-Json -Compress -Depth 4)
        )
    )
    $scriptText = @'
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$inputObject = [Text.Encoding]::UTF8.GetString(
    [Convert]::FromBase64String('__INPUT__')
) | ConvertFrom-Json -ErrorAction Stop
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$sid = $identity.User.Value
if ($sid -ne [string]$inputObject.expected_sid) {
    throw "normal-mode auto-heal SID mismatch: $sid"
}
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
$windowsDirectory = [Environment]::GetFolderPath(
    [Environment+SpecialFolder]::Windows
)
$groupText = & (Join-Path $windowsDirectory 'System32\whoami.exe') `
    /groups /fo csv /nh 2>$null |
    Out-String
if ($principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    ) -or
    $groupText -notmatch 'S-1-16-8192') {
    throw 'normal-mode auto-heal did not run with an exact medium-integrity token'
}

function Read-SharedBytes([string]$Path) {
    for ($attempt = 0; $attempt -lt 80; $attempt++) {
        try {
            $stream = [IO.FileStream]::new(
                $Path,
                [IO.FileMode]::Open,
                [IO.FileAccess]::Read,
                [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete
            )
            try {
                $memory = [IO.MemoryStream]::new()
                try {
                    $stream.CopyTo($memory)
                    return $memory.ToArray()
                } finally {
                    $memory.Dispose()
                }
            } finally {
                $stream.Dispose()
            }
        } catch {
            if ($attempt -eq 79) { throw }
            Start-Sleep -Milliseconds 100
        }
    }
}

function Read-SharedText([string]$Path) {
    return [Text.Encoding]::UTF8.GetString((Read-SharedBytes $Path))
}

function Get-BytesSHA256([byte[]]$Bytes) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return (
            [BitConverter]::ToString($sha.ComputeHash($Bytes))
        ).Replace('-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

function Read-PID([string]$Path) {
    $raw = (Read-SharedText $Path).Trim()
    if ($raw -match '^\d+$') { return [int]$raw }
    $record = $raw | ConvertFrom-Json -ErrorAction Stop
    if ($null -eq $record.PSObject.Properties['pid'] -or
        [int]$record.pid -le 0) {
        throw "invalid PID record: $Path"
    }
    return [int]$record.pid
}

function Get-CodexHookFingerprint([string]$Text, [string]$ExpectedHook) {
    $hookTable = [regex]::Match(
        $Text,
        '(?ms)^\[hooks\]\s*\r?\n.*?(?=^\[(?!hooks(?:\.|\]))[^\]]+\]\s*$|\z)'
    )
    if (-not $hookTable.Success) {
        throw 'Codex registration has no owned [hooks] table'
    }
    $commandLiteral = [regex]::Match(
        $hookTable.Value,
        'command_windows\s*=\s*(?<literal>"(?:\\.|[^"\\])*"|''[^'']*'')'
    )
    if (-not $commandLiteral.Success) {
        throw 'Codex registration has no Windows hook command'
    }
    $literal = $commandLiteral.Groups['literal'].Value
    if ($literal.StartsWith("'", [StringComparison]::Ordinal)) {
        $command = $literal.Substring(1, $literal.Length - 2)
    } else {
        $command = $literal | ConvertFrom-Json -ErrorAction Stop
    }
    $encoded = [regex]::Match(
        $command,
        '(?i)(?:^|\s)-EncodedCommand\s+([A-Za-z0-9+/=]+)(?:\s|$)'
    )
    if (-not $encoded.Success) {
        throw 'Codex Windows hook command is not encoded'
    }
    $decoded = [Text.Encoding]::Unicode.GetString(
        [Convert]::FromBase64String($encoded.Groups[1].Value)
    )
    if ($decoded.IndexOf(
            $ExpectedHook,
            [StringComparison]::OrdinalIgnoreCase
        ) -lt 0 -or
        $decoded -notmatch '(?i)\bhook\s+--connector\s+codex\b') {
        throw 'Codex Windows hook command does not name the exact candidate hook'
    }
    $events = @(
        [regex]::Matches(
            $hookTable.Value,
            '(?m)^\[\[hooks\.(PreToolUse|PermissionRequest|PostToolUse|SubagentStart|SubagentStop|PreCompact|PostCompact|SessionStart|UserPromptSubmit|Stop)\]\]\s*$'
        ) |
            ForEach-Object { $_.Groups[1].Value } |
            Sort-Object -Unique
    )
    $hashes = @(
        [regex]::Matches(
            $hookTable.Value,
            '(?m)^\s*trusted_hash\s*=\s*[''"](?<hash>sha256:[0-9a-fA-F]{64})[''"]\s*$'
        ) |
            ForEach-Object { $_.Groups['hash'].Value.ToLowerInvariant() } |
            Sort-Object
    )
    if ($events.Count -ne 10 -or $hashes.Count -ne 10) {
        throw (
            'Codex owned registration is incomplete: ' +
            "events=$($events.Count) trusted_hashes=$($hashes.Count)"
        )
    }
    return [pscustomobject]@{
        events = $events
        trusted_hashes = $hashes
        decoded_command = $decoded
        table_index = $hookTable.Index
        table_length = $hookTable.Length
    }
}

function Get-ProcessExecutable([int]$PIDValue) {
    $process = Get-CimInstance `
        -ClassName Win32_Process `
        -Filter "ProcessId = $PIDValue" `
        -ErrorAction SilentlyContinue
    if ($null -eq $process) { return '' }
    return [IO.Path]::GetFullPath([string]$process.ExecutablePath)
}

function Remove-FixtureTree([string]$Path, [string]$ExpectedParent) {
    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    if (-not [string]::Equals(
        [IO.Path]::GetDirectoryName($full),
        $ExpectedParent,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "normal-mode cleanup target escaped its exact parent: $full"
    }
    for ($attempt = 0; $attempt -lt 100; $attempt++) {
        if (-not (Test-Path -LiteralPath $full)) { return }
        try {
            Remove-Item -LiteralPath $full -Recurse -Force -ErrorAction Stop
        } catch {
            if ($attempt -eq 99) { throw }
        }
        Start-Sleep -Milliseconds 100
    }
    throw "normal-mode cleanup did not remove $full"
}

$profile = [IO.Path]::GetFullPath([string]$inputObject.profile).TrimEnd('\')
$syntheticHome = [IO.Path]::GetFullPath(
    [string]$inputObject.synthetic_home
).TrimEnd('\')
if (-not [string]::Equals(
    [IO.Path]::GetDirectoryName($syntheticHome),
    $profile,
    [StringComparison]::OrdinalIgnoreCase
)) {
    throw 'normal-mode synthetic home escaped the active profile'
}
$dataRoot = [IO.Path]::GetFullPath([string]$inputObject.data_root).TrimEnd('\')
$codexHome = [IO.Path]::GetFullPath([string]$inputObject.codex_home).TrimEnd('\')
$claudeHome = [IO.Path]::GetFullPath([string]$inputObject.claude_home).TrimEnd('\')
$runtimeRoot = [IO.Path]::GetFullPath([string]$inputObject.runtime_root).TrimEnd('\')
$workRoot = [IO.Path]::GetFullPath([string]$inputObject.work_root).TrimEnd('\')
$cli = [IO.Path]::GetFullPath([string]$inputObject.source_cli)
$wheel = [IO.Path]::GetFullPath([string]$inputObject.source_wheel)
$gateway = [IO.Path]::GetFullPath([string]$inputObject.source_gateway)
$hook = [IO.Path]::GetFullPath([string]$inputObject.source_hook)
$codex = [IO.Path]::GetFullPath([string]$inputObject.source_codex)
$logs = [Collections.Generic.List[string]]::new()
$healed = $false
$fingerprintSHA256 = ''
$repairMilliseconds = 0
$gatewayPID = 0
$watchdogPID = 0
try {
    foreach ($entry in @(
    [pscustomobject]@{ role = 'cli'; path = $cli; sha256 = [string]$inputObject.cli_sha256 },
    [pscustomobject]@{ role = 'wheel'; path = $wheel; sha256 = [string]$inputObject.wheel_sha256 },
    [pscustomobject]@{ role = 'gateway'; path = $gateway; sha256 = [string]$inputObject.gateway_sha256 },
    [pscustomobject]@{ role = 'hook'; path = $hook; sha256 = [string]$inputObject.hook_sha256 },
    [pscustomobject]@{ role = 'codex'; path = $codex; sha256 = [string]$inputObject.codex_sha256 }
    )) {
        if (-not [string]::Equals(
            [IO.Path]::GetDirectoryName([string]$entry.path),
            $runtimeRoot,
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        -not (Test-Path -LiteralPath $entry.path -PathType Leaf) -or
        (Get-BytesSHA256 (Read-SharedBytes ([string]$entry.path))) -cne
            ([string]$entry.sha256).ToLowerInvariant()) {
            throw "normal-mode prepared $($entry.role) failed path/hash validation"
        }
    }

    foreach ($name in @(
        [Environment]::GetEnvironmentVariables('Process').Keys
    )) {
        if ([string]$name -like 'DEFENSECLAW_*') {
            [Environment]::SetEnvironmentVariable(
                [string]$name,
                $null,
                'Process'
            )
        }
    }
    $env:DEFENSECLAW_HOME = $dataRoot
    $env:DEFENSECLAW_CONFIG = Join-Path $dataRoot 'config.yaml'
    $env:DEFENSECLAW_DEPLOYMENT_MODE = 'unmanaged_byod'
    $env:CODEX_HOME = $codexHome
    $env:CLAUDE_CONFIG_DIR = $claudeHome
    $env:USERPROFILE = $syntheticHome
    $env:HOME = $syntheticHome
    $env:HOMEDRIVE = [IO.Path]::GetPathRoot($syntheticHome).TrimEnd('\')
    $env:HOMEPATH = $syntheticHome.Substring(
        [IO.Path]::GetPathRoot($syntheticHome).Length - 1
    )
    $env:APPDATA = [string]$inputObject.app_data
    $env:LOCALAPPDATA = [string]$inputObject.local_app_data
    $env:TEMP = [string]$inputObject.temp_root
    $env:TMP = [string]$inputObject.temp_root
    $env:PYTHONPATH = $wheel
    $env:PYTHONNOUSERSITE = '1'
    $env:PYTHONDONTWRITEBYTECODE = '1'
    $env:PATH = @(
        $runtimeRoot,
        [Environment]::SystemDirectory,
        (Split-Path -Parent (Get-Process -Id $PID).Path)
    ) -join [IO.Path]::PathSeparator
    Set-Location -LiteralPath $workRoot

    $initOutput = (
        & $cli init `
            --skip-install `
            --non-interactive `
            --yes `
            --connector codex `
            --profile observe `
            --no-start-gateway `
            --no-verify 2>&1 |
            Out-String
    )
    if ($LASTEXITCODE -ne 0) {
        throw "normal-mode init failed: $initOutput"
    }
    $logs.Add($initOutput.Trim())

    $configPath = Join-Path $dataRoot 'config.yaml'
    $config = [IO.File]::ReadAllText($configPath)
    $apiPortMatches = [regex]::Matches(
        $config,
        '(?m)^(?<indent>\s*)api_port:\s*\d+\s*$'
    )
    if ($apiPortMatches.Count -ne 1) {
        throw (
            'normal-mode fixture requires exactly one gateway api_port; ' +
            "observed $($apiPortMatches.Count)"
        )
    }
    $updated = [regex]::Replace(
        $config,
        '(?m)^(?<indent>\s*)api_port:\s*\d+\s*$',
        ('${indent}api_port: ' + [string]$inputObject.api_port),
        1
    )
    if ($updated -notmatch '(?m)^\s*hook_self_heal:\s*true\s*$') {
        $guardrailMatches = [regex]::Matches(
            $updated,
            '(?m)^guardrail:\s*$'
        )
        if ($guardrailMatches.Count -ne 1) {
            throw (
                'normal-mode fixture requires exactly one guardrail block; ' +
                "observed $($guardrailMatches.Count)"
            )
        }
        $updated = [regex]::Replace(
            $updated,
            '(?m)^guardrail:\s*$',
            "guardrail:`r`n  hook_self_heal: true",
            1
        )
    }
    if ($updated -notmatch '(?m)^\s*hook_self_heal:\s*true\s*$') {
        throw 'normal-mode fixture did not set explicit hook self-heal'
    }
    [IO.File]::WriteAllText(
        $configPath,
        $updated,
        [Text.UTF8Encoding]::new($false)
    )

    $setupOutput = (
        & $cli setup codex --yes --mode observe --restart 2>&1 |
            Out-String
    )
    if ($LASTEXITCODE -ne 0) {
        throw "normal-mode setup failed: $setupOutput"
    }
    $logs.Add($setupOutput.Trim())

    $nativeConfig = Join-Path $codexHome 'config.toml'
    $gatewayPIDPath = Join-Path $dataRoot 'gateway.pid'
    $watchdogPIDPath = Join-Path $dataRoot 'watchdog.pid'
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds(60)
    $baselineFingerprint = $null
    while ([DateTimeOffset]::UtcNow -lt $deadline) {
        try {
            $gatewayPID = Read-PID $gatewayPIDPath
            $watchdogPID = Read-PID $watchdogPIDPath
            $gatewayExecutable = Get-ProcessExecutable $gatewayPID
            $watchdogExecutable = Get-ProcessExecutable $watchdogPID
            $nativeText = Read-SharedText $nativeConfig
            $candidateFingerprint = Get-CodexHookFingerprint `
                $nativeText `
                $hook
            if ($gatewayExecutable.Equals(
                    $gateway,
                    [StringComparison]::OrdinalIgnoreCase
                ) -and
                $watchdogExecutable.Equals(
                    $gateway,
                    [StringComparison]::OrdinalIgnoreCase
                )) {
                $baselineFingerprint = $candidateFingerprint
                break
            }
        } catch {}
        Start-Sleep -Milliseconds 100
    }
    if ($null -eq $baselineFingerprint) {
        throw 'normal-mode gateway, watchdog, and Codex hook registration did not become ready'
    }

    Start-Sleep -Seconds 5
    $baselineText = Read-SharedText $nativeConfig
    $baselineFingerprint = Get-CodexHookFingerprint $baselineText $hook
    $fingerprintJSON = $baselineFingerprint |
        Select-Object events, trusted_hashes, decoded_command |
        ConvertTo-Json -Compress -Depth 4
    $fingerprintSHA256 = Get-BytesSHA256 (
        [Text.Encoding]::UTF8.GetBytes($fingerprintJSON)
    )
    $hookTable = [regex]::Match(
        $baselineText,
        '(?ms)^\[hooks\]\s*\r?\n.*?(?=^\[(?!hooks(?:\.|\]))[^\]]+\]\s*$|\z)'
    )
    if (-not $hookTable.Success) {
        throw 'normal-mode fixture could not isolate the owned Codex hook table'
    }
    $outsideBefore = $baselineText.Remove(
        $hookTable.Index,
        $hookTable.Length
    )
    [IO.File]::WriteAllText(
        $nativeConfig,
        $outsideBefore,
        [Text.UTF8Encoding]::new($false)
    )
    try {
        $null = Get-CodexHookFingerprint `
            (Read-SharedText $nativeConfig) `
            $hook
        throw 'normal-mode hook removal did not remove the owned registration'
    } catch {
        if ($_.Exception.Message -notlike
            'Codex registration has no owned*') {
            throw
        }
    }

    $repairStarted = [DateTimeOffset]::UtcNow
    $deadline = $repairStarted.AddSeconds(60)
    while ([DateTimeOffset]::UtcNow -lt $deadline) {
        try {
            $restoredText = Read-SharedText $nativeConfig
            $restoredFingerprint = Get-CodexHookFingerprint `
                $restoredText `
                $hook
            $restoredJSON = $restoredFingerprint |
                Select-Object events, trusted_hashes, decoded_command |
                ConvertTo-Json -Compress -Depth 4
            $restoredTable = [regex]::Match(
                $restoredText,
                '(?ms)^\[hooks\]\s*\r?\n.*?(?=^\[(?!hooks(?:\.|\]))[^\]]+\]\s*$|\z)'
            )
            $outsideAfter = $restoredText.Remove(
                $restoredTable.Index,
                $restoredTable.Length
            )
            if ($restoredJSON -ceq $fingerprintJSON -and
                $outsideAfter -ceq $outsideBefore) {
                $healed = $true
                break
            }
        } catch {}
        Start-Sleep -Milliseconds 100
    }
    $repairMilliseconds = [Math]::Round(
        ([DateTimeOffset]::UtcNow - $repairStarted).TotalMilliseconds,
        0
    )
    if (-not $healed) {
        throw (
            'normal-mode hook self-heal did not restore the exact owned ' +
            'Codex event/hash contract while preserving unrelated settings'
        )
    }
} finally {
    Set-Location -LiteralPath $profile
    try { & $gateway stop 1>$null 2>$null } catch {}
    try {
        & $gateway connector teardown `
            --connector codex `
            --data-dir $dataRoot 1>$null 2>$null
    } catch {}
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds(30)
    do {
        $alive = @(
            foreach ($candidatePID in @($gatewayPID, $watchdogPID)) {
                if ($candidatePID -gt 0 -and
                    $null -ne (
                        Get-Process `
                            -Id $candidatePID `
                            -ErrorAction SilentlyContinue
                    )) {
                    $candidatePID
                }
            }
        )
        if ($alive.Count -eq 0) { break }
        Start-Sleep -Milliseconds 100
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    if ($alive.Count -ne 0) {
        throw "normal-mode fixture processes did not stop: $($alive -join ',')"
    }
    Remove-FixtureTree $syntheticHome $profile
}
[pscustomobject]@{
    sid = $sid
    deployment_mode = 'unmanaged_byod'
    hook_self_heal = $healed
    owned_hook_fingerprint_sha256 = $fingerprintSHA256
    repair_milliseconds = $repairMilliseconds
    gateway_pid = $gatewayPID
    watchdog_pid = $watchdogPID
    gateway_port = [int]$inputObject.api_port
    log_count = $logs.Count
} | ConvertTo-Json -Compress
'@.Replace('__INPUT__', $inputBase64)
    $process = Invoke-ActiveUserPowerShell `
        -Script $scriptText `
        -Label 'normal-mode-live-hook-auto-heal' `
        -TimeoutSeconds 240
    $result = ConvertFrom-SingleJSONDocument `
        $process.StdOut `
        'normal-mode live hook auto-heal'
    if ([string]$result.sid -ne $script:PrimarySID -or
        [string]$result.deployment_mode -cne 'unmanaged_byod' -or
        -not [bool]$result.hook_self_heal -or
        [string]::IsNullOrWhiteSpace(
            [string]$result.owned_hook_fingerprint_sha256
        )) {
        throw 'normal-mode active user did not prove existing hook auto-heal'
    }
    $after = Get-ProtectedUserTreeInventory `
        $syntheticHome `
        'normal synthetic home after'
    Assert-SameUserTreeInventory `
        $before `
        $after `
        'normal-mode synthetic fixture cleanup'
    $script:NormalModeSyntheticHome = ''
    $machineAfter = Get-NormalModeEnterpriseMachineSnapshot
    Assert-SameObjectJSON `
        $machineBefore `
        $machineAfter `
        'normal-mode enterprise-protected machine state'
    return [pscustomobject]@{
        target_sid = $script:PrimarySID
        deployment_mode = 'unmanaged_byod'
        auto_heal_preserved = $true
        owned_hook_fingerprint_sha256 =
            [string]$result.owned_hook_fingerprint_sha256
        repair_milliseconds = [int]$result.repair_milliseconds
        gateway_pid = [int]$result.gateway_pid
        watchdog_pid = [int]$result.watchdog_pid
        enterprise_absent_before = [bool]$RequireEnterpriseAbsent
        protected_machine_state_unchanged = $true
        fixture_cleanup_exact = $true
        machine_before = $machineBefore
        machine_after = $machineAfter
    }
}

function Test-CandidateCodexHomeResolverContract {
    $certHome = Assert-CertificationCodexHomePath `
        $script:CertificationCodexHome `
        -RequireExisting
    $liveCodexHome = ConvertTo-CanonicalPath (
        Join-Path $script:PrimaryProfile '.codex'
    )
    if ($certHome.Equals($liveCodexHome, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'certification CODEX_HOME unexpectedly aliases the live .codex root'
    }

    $resolverRoot = Assert-PathBelow `
        (Join-Path $script:FixtureRoot 'codex-home-resolver-contract') `
        $script:StagingRoot `
        'Codex resolver contract root'
    $dataRoot = Assert-PathBelow `
        (Join-Path $resolverRoot 'data') `
        $script:StagingRoot `
        'Codex resolver contract data root'
    $configDecoyProfile = Assert-PathBelow `
        (Join-Path $resolverRoot 'config-decoy-profile') `
        $script:StagingRoot `
        'Codex config resolver decoy'
    $hooksDecoyProfile = Assert-PathBelow `
        (Join-Path $resolverRoot 'hooks-decoy-profile') `
        $script:StagingRoot `
        'Codex hooks resolver decoy'
    foreach ($profile in @($configDecoyProfile, $hooksDecoyProfile)) {
        [IO.Directory]::CreateDirectory((Join-Path $profile '.codex')) | Out-Null
    }
    $configDecoyHome = Join-Path $configDecoyProfile '.codex'
    $hooksDecoyHome = Join-Path $hooksDecoyProfile '.codex'
    Write-UTF8File `
        (Join-Path $configDecoyHome 'config.toml') `
        "not valid TOML = [`r`n"
    Write-UTF8File `
        (Join-Path $hooksDecoyHome 'config.toml') `
        "model = `"gpt-5`"`r`n"
    Write-UTF8File `
        (Join-Path $hooksDecoyHome 'hooks.json') `
        "{not-valid-json`r`n"

    $configPath = Join-Path $resolverRoot 'defenseclaw.yaml'
    $dataYAML = $dataRoot.Replace("'", "''")
    Write-ProtectedManifest `
        $configPath `
        @"
config_version: 8
deployment_mode: unmanaged_byod
data_dir: '$dataYAML'
guardrail:
  enabled: true
  mode: observe
  scanner_mode: local
  hook_self_heal: true
application_protection:
  enabled: false
"@ `
        'codex-resolver-contract-config'

    $before = @(
        Get-ProtectedUserTreeInventory $certHome 'candidate resolver cert CODEX_HOME before',
        Get-ProtectedUserTreeInventory $resolverRoot 'candidate resolver fixture before'
    )
    $run = {
        param([string]$CodexHome, [string]$UserProfile, [int[]]$ExitCodes, [string]$Label)
        $process = Invoke-NativeProcess `
            -FilePath $script:GatewaySource `
            -ArgumentList @(
                'connector',
                'verify',
                '--connector', 'codex',
                '--data-dir', $dataRoot,
                '--json'
            ) `
            -Environment @{
                DEFENSECLAW_CONFIG = $configPath
                DEFENSECLAW_HOME = $dataRoot
                DEFENSECLAW_DEPLOYMENT_MODE = 'unmanaged_byod'
                DEFENSECLAW_HOOK_GUARDIAN_AUTH_DIR = $null
                CODEX_HOME = $CodexHome
                USERPROFILE = $UserProfile
                HOME = $UserProfile
            } `
            -AllowedExitCodes $ExitCodes `
            -Label $Label
        return [pscustomobject]@{
            process = $process
            json = ConvertFrom-SingleJSONDocument $process.StdOut $Label
        }
    }

    $negativeConfig = & $run `
        $configDecoyHome `
        $configDecoyProfile `
        @(1) `
        'candidate-codex-resolver-negative-config'
    if ([bool]$negativeConfig.json.clean -or
        [string]$negativeConfig.json.residue -notmatch '(?i)parse codex config') {
        throw 'candidate binary did not observe the explicit invalid CODEX_HOME config decoy'
    }
    $positiveConfig = & $run `
        $certHome `
        $configDecoyProfile `
        @(0) `
        'candidate-codex-resolver-positive-config'
    if (-not [bool]$positiveConfig.json.clean) {
        throw 'candidate binary ignored CODEX_HOME in favor of the hostile USERPROFILE config decoy'
    }
    $negativeHooks = & $run `
        $hooksDecoyHome `
        $hooksDecoyProfile `
        @(1) `
        'candidate-codex-resolver-negative-hooks'
    if ([bool]$negativeHooks.json.clean -or
        [string]$negativeHooks.json.residue -notmatch '(?i)hooks\.json|json') {
        throw 'candidate binary did not observe the explicit invalid CODEX_HOME hooks.json decoy'
    }
    $positiveHooks = & $run `
        $certHome `
        $hooksDecoyProfile `
        @(0) `
        'candidate-codex-resolver-positive-hooks'
    if (-not [bool]$positiveHooks.json.clean) {
        throw 'candidate binary ignored CODEX_HOME in favor of the hostile USERPROFILE hooks decoy'
    }

    $after = @(
        Get-ProtectedUserTreeInventory $certHome 'candidate resolver cert CODEX_HOME after',
        Get-ProtectedUserTreeInventory $resolverRoot 'candidate resolver fixture after'
    )
    for ($index = 0; $index -lt $before.Count; $index++) {
        Assert-SameUserTreeInventory `
            $before[$index] `
            $after[$index] `
            "candidate resolver no-write inventory $index"
    }
    if (Test-Path -LiteralPath $dataRoot) {
        throw "read-only candidate resolver probe created its data root: $dataRoot"
    }

    $nativePaths = @(
        (Join-Path $certHome 'config.toml'),
        (Join-Path $certHome 'hooks.json'),
        (Join-Path $certHome 'config.toml.lock')
    )
    foreach ($path in $nativePaths) {
        $resolved = Assert-PathBelow $path $certHome 'candidate Codex native path'
        if ($resolved.Equals($liveCodexHome, [StringComparison]::OrdinalIgnoreCase) -or
            $resolved.StartsWith(
                $liveCodexHome.TrimEnd('\') + '\',
                [StringComparison]::OrdinalIgnoreCase
            )) {
            throw "candidate Codex native path enters the live .codex root: $resolved"
        }
    }
    $script:CertificationCodexResolverProof = [pscustomobject]@{
        binary = $script:GatewaySource
        binary_sha256 = $script:SourceDigests['gateway']
        codex_home = $certHome
        hostile_profiles = @($configDecoyProfile, $hooksDecoyProfile)
        native_paths = @($nativePaths)
        defenseclaw_data_root = $dataRoot
        negative_config_exit = [int]$negativeConfig.process.ExitCode
        positive_config_exit = [int]$positiveConfig.process.ExitCode
        negative_hooks_exit = [int]$negativeHooks.process.ExitCode
        positive_hooks_exit = [int]$positiveHooks.process.ExitCode
        no_write = $true
        live_codex_root = $liveCodexHome
        live_codex_enumerated = $false
        live_codex_snapshotted = $false
        live_codex_mutated = $false
        verified_at = [DateTimeOffset]::UtcNow.ToString('o')
    }
    return (
        'candidate binary selected explicit CODEX_HOME over hostile USERPROFILE ' +
        'config.toml/hooks.json decoys; before/after inventories were exact and ' +
        'the live .codex root was never enumerated, snapshotted, or mutated'
    )
}

function ConvertTo-CertificationSID([object]$Identity) {
    if ($Identity -is [Security.Principal.SecurityIdentifier]) {
        return $Identity.Value
    }
    return [Security.Principal.NTAccount]::new(
        [string]$Identity
    ).Translate([Security.Principal.SecurityIdentifier]).Value
}

function Assert-CodexMachinePolicyParentContract {
    foreach ($path in @(
        $script:CodexVendorDirectory,
        $script:CodexMachinePolicyDirectory
    )) {
        if (-not (Test-Path -LiteralPath $path -PathType Container)) {
            throw "Codex shared policy directory is missing: $path"
        }
        $item = Get-Item -LiteralPath $path -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Codex shared policy directory is a reparse point: $path"
        }
        $acl = Get-Acl -LiteralPath $path -ErrorAction Stop
        if (-not $acl.AreAccessRulesProtected) {
            throw "Codex shared policy directory inherits its DACL: $path"
        }
        $ownerSID = ConvertTo-CertificationSID $acl.Owner
        if ($ownerSID -ne 'S-1-5-32-544') {
            throw "Codex shared policy directory owner is $ownerSID, want BUILTIN\Administrators: $path"
        }
        $granted = @{}
        foreach ($rule in @($acl.Access)) {
            if ($rule.AccessControlType -ne
                [Security.AccessControl.AccessControlType]::Allow) {
                throw "Codex shared policy directory has a non-canonical deny ACE: $path"
            }
            if (($rule.PropagationFlags -band
                [Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) {
                continue
            }
            $sid = ConvertTo-CertificationSID $rule.IdentityReference
            if ($sid -notin @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-32-545')) {
                throw "Codex shared policy directory grants unexpected principal $sid`: $path"
            }
            $current = if ($granted.ContainsKey($sid)) {
                [Security.AccessControl.FileSystemRights]$granted[$sid]
            } else {
                [Security.AccessControl.FileSystemRights]0
            }
            $granted[$sid] = $current -bor $rule.FileSystemRights
        }
        foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
            $rights = if ($granted.ContainsKey($sid)) {
                [Security.AccessControl.FileSystemRights]$granted[$sid]
            } else {
                [Security.AccessControl.FileSystemRights]0
            }
            if (($rights -band [Security.AccessControl.FileSystemRights]::FullControl) -ne
                [Security.AccessControl.FileSystemRights]::FullControl) {
                throw "Codex shared policy directory does not grant $sid FullControl: $path"
            }
        }
        $usersRights = if ($granted.ContainsKey('S-1-5-32-545')) {
            [Security.AccessControl.FileSystemRights]$granted['S-1-5-32-545']
        } else {
            [Security.AccessControl.FileSystemRights]0
        }
        if (($usersRights -band [Security.AccessControl.FileSystemRights]::ReadAndExecute) -ne
            [Security.AccessControl.FileSystemRights]::ReadAndExecute) {
            throw "Codex shared policy directory does not grant BUILTIN\Users read/traverse: $path"
        }
        $writeLike = [Security.AccessControl.FileSystemRights](
            [Security.AccessControl.FileSystemRights]::WriteData -bor
            [Security.AccessControl.FileSystemRights]::AppendData -bor
            [Security.AccessControl.FileSystemRights]::CreateFiles -bor
            [Security.AccessControl.FileSystemRights]::CreateDirectories -bor
            [Security.AccessControl.FileSystemRights]::Delete -bor
            [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
            [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
            [Security.AccessControl.FileSystemRights]::TakeOwnership -bor
            [Security.AccessControl.FileSystemRights]::Modify
        )
        if (($usersRights -band $writeLike) -ne 0) {
            throw "Codex shared policy directory grants BUILTIN\Users write-like rights: $path"
        }
    }
    return 'OpenAI/Codex parents are real protected directories: Administrators/System full control and Users read/traverse only'
}

function Get-CodexMachinePolicySnapshot {
    $paths = [ordered]@{
        requirements = $script:CodexRequirementsPath
        transaction_lock = $script:CodexMachineLockPath
        managed_state = $script:CodexManagedStatePath
        ownership = $script:CodexRequirementsOwnershipPath
        acl_preimage = $script:CodexRequirementsAclBackupPath
        application_control_attestation =
            $script:AgentApplicationControlAttestationPath
    }
    $snapshot = [ordered]@{}
    foreach ($entry in $paths.GetEnumerator()) {
        if (-not (Test-Path -LiteralPath $entry.Value -PathType Leaf)) {
            throw "Codex machine-policy artifact is missing: $($entry.Value)"
        }
        $item = Get-Item -LiteralPath $entry.Value -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Codex machine-policy artifact is a reparse point: $($entry.Value)"
        }
        $security = Get-ManagedUserPathSecurityFingerprint $entry.Value
        if ([string]$security.owner_sid -ne 'S-1-5-32-544' -or
            -not [bool]$security.access_rules_protected) {
            throw (
                "Codex machine-policy artifact $($entry.Key) is not " +
                'Administrators-owned with a protected DACL'
            )
        }
        foreach ($sid in @($script:PrimarySID, $script:HostileSID)) {
            Assert-NoStandardUserAccess `
                -Path $entry.Value `
                -SID $sid `
                -DenyWrite
        }
        $snapshot[$entry.Key] = [pscustomobject]@{
            path = [string]$entry.Value
            sha256 = Get-FileDigest $entry.Value
            length = [int64]$item.Length
            owner_sid = [string]$security.owner_sid
            access_rules_protected = [bool]$security.access_rules_protected
            sddl = [string]$security.sddl
        }
    }
    return [pscustomobject]$snapshot
}

function Assert-CodexMachinePolicyContract([string]$Label) {
    $null = Assert-CodexMachinePolicyParentContract
    $snapshot = Get-CodexMachinePolicySnapshot
    $verify = Invoke-GatewayJSON `
        -Arguments @(
            'enterprise', 'windows', 'codex-requirements', 'verify'
        ) `
        -Label "$Label-codex-requirements-verify"
    $report = $verify.JSON
    $expectedClaudeAttestation =
        [bool]$script:ClaudeEffectivePolicyAttested
    if (-not [bool]$report.ok -or
        [bool]$report.changed -or
        [bool]$report.security_complete -ne
            $expectedClaudeAttestation) {
        throw (
            "$Label machine requirements report is not exact/security-complete: " +
            (Protect-SensitiveDisplayText (
                $report | ConvertTo-Json -Compress -Depth 7
            ))
        )
    }
    if ([string]$report.agent_application_control_prerequisite -cne
        'wdac_or_applocker_approved_agent_client_rules') {
        throw "$Label machine requirements reported the wrong application-control prerequisite"
    }
    if ([string]$report.codex_trusted_hook_launcher_prerequisite -cne
        'approved_fail_closed_fixed_hook_launcher') {
        throw "$Label machine requirements reported the wrong Codex launcher prerequisite"
    }
    foreach ($booleanName in @(
        'agent_application_control_enforced',
        'approved_client_enforced',
        'approved_agent_clients_enforced',
        'codex_trusted_hook_launcher_required',
        'codex_target_enabled',
        'codex_trusted_hook_launcher_verified'
    )) {
        $property = $report.PSObject.Properties[$booleanName]
        if ($null -eq $property -or -not [bool]$property.Value) {
            throw "$Label machine requirements did not attest $booleanName=true"
        }
    }
    if ([bool]$report.claude_effective_policy_verified -ne
        $expectedClaudeAttestation) {
        throw (
            "$Label machine requirements Claude effective-policy phase is " +
            "wrong: got=$($report.claude_effective_policy_verified) " +
            "expected=$expectedClaudeAttestation"
        )
    }
    $stockCodex = $report.PSObject.Properties['stock_codex_supported']
    if ($null -eq $stockCodex -or
        $stockCodex.Value -isnot [bool] -or
        [bool]$stockCodex.Value) {
        throw "$Label machine requirements must explicitly reject stock Codex"
    }
    $attestation = Get-Content `
        -LiteralPath $script:AgentApplicationControlAttestationPath `
        -Raw |
        ConvertFrom-Json -ErrorAction Stop
    if ([int]$attestation.schema_version -ne 2 -or
        [string]$attestation.prerequisite -cne
            'wdac_or_applocker_approved_agent_client_rules' -or
        -not [bool]$attestation.agent_application_control_enforced -or
        -not [bool]$attestation.approved_agent_clients_enforced -or
        [string]$attestation.minimum_claude_version -cne '2.1.152' -or
        [bool]$attestation.claude_effective_policy_verified -ne
            $expectedClaudeAttestation -or
        [string]$attestation.codex_trusted_hook_launcher_prerequisite -cne
            'approved_fail_closed_fixed_hook_launcher' -or
        -not [bool]$attestation.codex_trusted_hook_launcher_verified -or
        [bool]$attestation.stock_codex_supported -or
        -not [bool]$attestation.certification_required -or
        [string]$attestation.attested_by_sid -notmatch '^S-1-5-' -or
        [string]::IsNullOrWhiteSpace([string]$attestation.attested_at)) {
        throw "$Label protected agent application-control attestation is incomplete"
    }
    foreach ($field in @(
        [pscustomobject]@{
            name = 'requirements_path'
            expected = $script:CodexRequirementsPath
        },
        [pscustomobject]@{
            name = 'managed_state_path'
            expected = $script:CodexManagedStatePath
        },
        [pscustomobject]@{
            name = 'ownership_path'
            expected = $script:CodexRequirementsOwnershipPath
        },
        [pscustomobject]@{
            name = 'managed_dir'
            expected = (Join-Path $script:InstallRoot 'bin')
        },
        [pscustomobject]@{
            name = 'hook_binary'
            expected = (Join-Path $script:InstallRoot 'bin\defenseclaw-hook.exe')
        }
    )) {
        $property = $report.PSObject.Properties[[string]$field.name]
        if ($null -eq $property -or
            -not [string]::Equals(
                (ConvertTo-CanonicalPath ([string]$property.Value)),
                (ConvertTo-CanonicalPath ([string]$field.expected)),
                [StringComparison]::OrdinalIgnoreCase
            )) {
            throw "$Label machine requirements report has wrong $($field.name)"
        }
    }
    $expectedEvents = @(
        'PermissionRequest',
        'PostCompact',
        'PostToolUse',
        'PreCompact',
        'PreToolUse',
        'SessionStart',
        'Stop',
        'SubagentStart',
        'SubagentStop',
        'UserPromptSubmit'
    )
    $actualEvents = @(
        $report.managed_events |
            ForEach-Object { [string]$_ } |
            Sort-Object
    )
    if (($actualEvents -join "`n") -cne
        (($expectedEvents | Sort-Object) -join "`n")) {
        throw "$Label machine requirements report omitted the exact ten events"
    }

    $raw = [IO.File]::ReadAllText($script:CodexRequirementsPath)
    if ([regex]::Matches(
        $raw,
        '(?m)^allow_managed_hooks_only\s*=\s*true\s*$'
    ).Count -ne 1 -or
        [regex]::Matches(
            $raw,
            '(?ms)^\[features\]\s*\r?\n(?:[^\[]*\r?\n)*?hooks\s*=\s*true\s*$'
        ).Count -ne 1 -or
        $raw -match '(?m)^\s*state\s*=' -or
        $raw -match '(?m)^\s*\[hooks\.state\]') {
        throw "$Label requirements.toml lacks the managed-only/hooks=true contract"
    }
    foreach ($eventName in $expectedEvents) {
        $pattern = '(?m)^\[\[hooks\.' +
            [regex]::Escape($eventName) +
            '\]\]\s*$'
        if ([regex]::Matches($raw, $pattern).Count -ne 1) {
            throw "$Label requirements.toml lacks one exact $eventName group"
        }
    }
    if ([regex]::Matches($raw, '(?m)^command\s*=').Count -ne 10 -or
        [regex]::Matches($raw, '(?m)^command_windows\s*=').Count -ne 10 -or
        [regex]::Matches($raw, '(?m)^type\s*=\s*"command"\s*$').Count -ne 10 -or
        [regex]::Matches($raw, '(?m)^timeout\s*=').Count -ne 10) {
        throw "$Label requirements.toml does not have ten exact command handlers"
    }
    if ([regex]::Matches(
        $raw,
        '(?m)^windows_managed_dir\s*='
    ).Count -ne 1 -or
        $raw -notmatch '(?i)WindowsPowerShell.+powershell\.exe.+EncodedCommand') {
        throw "$Label requirements.toml does not pin the protected managed directory and fixed system shell command"
    }
    return [pscustomobject]@{
        report = $report
        snapshot = $snapshot
        event_count = $expectedEvents.Count
        command_count = 10
        user_codex_tree_consulted = $false
    }
}

function Assert-ClaudeOnlyWindowsSecurityContract([string]$Label) {
    $verify = Invoke-GatewayJSON `
        -Arguments @(
            'enterprise', 'windows', 'codex-requirements', 'verify'
        ) `
        -Label "$Label-claude-only-windows-security-verify"
    $report = $verify.JSON
    if (-not [bool]$report.ok -or
        [bool]$report.changed -or
        [bool]$report.security_complete -or
        [bool]$report.agent_application_control_enforced -or
        [bool]$report.approved_agent_clients_enforced -or
        -not [bool]$report.claude_target_enabled -or
        [bool]$report.claude_effective_policy_verified -or
        [bool]$report.codex_target_enabled -or
        [bool]$report.codex_trusted_hook_launcher_required -or
        [bool]$report.codex_trusted_hook_launcher_verified -or
        [bool]$report.stock_codex_supported) {
        throw (
            "$Label Claude-only Windows security report is not exact: " +
            (Protect-SensitiveDisplayText (
                $report | ConvertTo-Json -Compress -Depth 7
            ))
        )
    }
    foreach ($path in @(
        $script:CodexRequirementsPath,
        $script:CodexManagedStatePath,
        $script:CodexRequirementsOwnershipPath,
        $script:CodexRequirementsAclBackupPath
    )) {
        if (Test-Path -LiteralPath $path) {
            throw "$Label Claude-only deployment created a Codex artifact: $path"
        }
    }
    if (Test-Path -LiteralPath $script:AgentApplicationControlAttestationPath) {
        throw (
            "$Label Claude-only core run created a false external " +
            'application-control attestation'
        )
    }
    return $report
}

function Test-ClaudeManagedPolicyDeletionAutoHeal {
    $policy = $script:ClaudeManagedPolicyPath
    $beforePaths = [ordered]@{
        policy = $script:ClaudeManagedPolicyPath
        state = $script:ClaudeManagedStatePath
        transaction_lock = $script:ClaudeManagedLockPath
    }
    $before = Get-ArtifactSnapshots $beforePaths
    $policyBytes = [IO.File]::ReadAllBytes($policy)
    $policyACL = Get-Acl -LiteralPath $policy
    $applicationControlEvidence = if (
        Test-Path `
            -LiteralPath $script:AgentApplicationControlAttestationPath `
            -PathType Leaf
    ) {
        $attestation = Get-Content `
            -LiteralPath $script:AgentApplicationControlAttestationPath `
            -Raw |
            ConvertFrom-Json -ErrorAction Stop
        [pscustomobject]@{
            exists = $true
            sha256 = Get-FileDigest `
                $script:AgentApplicationControlAttestationPath
            agent_application_control_enforced =
                [bool]$attestation.agent_application_control_enforced
        }
    } else {
        [pscustomobject]@{
            exists = $false
            sha256 = ''
            agent_application_control_enforced = $false
        }
    }
    $guardianStarted = $true
    try {
        Stop-Service `
            -Name $script:GuardianServiceName `
            -Force `
            -ErrorAction Stop
        $guardianStarted = $false
        Wait-Until `
            -Description 'guardian stopped for Claude policy deletion' `
            -Condition {
                (Get-Service `
                    -Name $script:GuardianServiceName `
                    -ErrorAction Stop).Status -eq
                    [ServiceProcess.ServiceControllerStatus]::Stopped
            } | Out-Null
        Remove-Item -LiteralPath $policy -Force -ErrorAction Stop
        if (Test-Path -LiteralPath $policy) {
            throw 'administrator Claude managed-policy deletion did not take effect'
        }
        $installedManifest = Join-Path `
            $script:StateRoot `
            'hook-guardian\targets.yaml'
        $unhealthy = Invoke-GatewayJSON `
            -Arguments @(
                'enterprise', 'hooks', 'status',
                '--manifest', $installedManifest
            ) `
            -Label 'claude-policy-deleted-status' `
            -AllowedExitCodes @(1)
        if ([bool]$unhealthy.JSON.ok -or
            [bool]$unhealthy.JSON.claude_effective_policy_verified) {
            throw (
                'missing Claude managed policy was reported healthy/effective ' +
                'before guardian repair'
            )
        }
        if ([bool]$applicationControlEvidence.exists) {
            if (-not [bool](
                    $applicationControlEvidence.
                        agent_application_control_enforced
                ) -or
                (Get-FileDigest `
                    $script:AgentApplicationControlAttestationPath) -cne
                    [string]$applicationControlEvidence.sha256) {
                throw (
                    'application-control evidence changed while proving it ' +
                    'cannot substitute for Claude effective-policy verification'
                )
            }
        } elseif (Test-Path `
            -LiteralPath $script:AgentApplicationControlAttestationPath) {
            throw 'core mode created application-control evidence during policy drift'
        }
        Start-Service -Name $script:GuardianServiceName -ErrorAction Stop
        $guardianStarted = $true
        $repair = Wait-Until `
            -Description 'Claude managed policy exact auto-heal' `
            -TimeoutSeconds $RepairTimeoutSeconds `
            -Condition {
                if (-not (Test-Path -LiteralPath $policy -PathType Leaf)) {
                    return $false
                }
                if ((Get-FileDigest $policy) -cne
                    [string]$before.policy.sha256) {
                    return $false
                }
                try {
                    $status = Invoke-GatewayJSON `
                        -Arguments @(
                            'enterprise', 'hooks', 'status',
                            '--manifest', $installedManifest
                        ) `
                        -Label 'claude-policy-repair-poll'
                    if (-not [bool]$status.JSON.ok -or
                        [bool]$status.JSON.claude_effective_policy_verified -ne
                            [bool]$script:ClaudeEffectivePolicyAttested) {
                        return $false
                    }
                    return [pscustomobject]@{
                        status = $status.JSON
                        repaired_sha256 = Get-FileDigest $policy
                    }
                } catch {
                    return $false
                }
            }
        $after = Get-ArtifactSnapshots $beforePaths
        Assert-SameArtifactSnapshots `
            $before `
            $after `
            'Claude managed policy deletion auto-heal'
        return [pscustomobject]@{
            deleted_policy = $policy
            status_unhealthy_before_repair = $true
            effective_policy_false_before_repair = $true
            application_control_attested =
                [bool]$applicationControlEvidence.
                    agent_application_control_enforced
            application_control_evidence_unchanged =
                [bool]$applicationControlEvidence.exists
            application_control_did_not_promote_effective_policy = $true
            repaired_sha256 = [string]$repair.repaired_sha256
            exact_bytes_restored = $true
        }
    } finally {
        if (-not (Test-Path -LiteralPath $policy -PathType Leaf) -or
            (Get-FileDigest $policy) -cne [string]$before.policy.sha256) {
            if ($guardianStarted) {
                Stop-Service `
                    -Name $script:GuardianServiceName `
                    -Force `
                    -ErrorAction SilentlyContinue
                $guardianStarted = $false
            }
            [IO.File]::WriteAllBytes($policy, $policyBytes)
            Set-Acl -LiteralPath $policy -AclObject $policyACL
        }
        if (-not $guardianStarted) {
            Start-Service `
                -Name $script:GuardianServiceName `
                -ErrorAction SilentlyContinue
        }
        Wait-ForServicesRunning
    }
}

function Test-ProtectedLifecycleLockSquattingDenied {
    $path = $script:LifecycleLockPath
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "protected enterprise lifecycle lock is missing: $path"
    }
    $before = Get-ArtifactSnapshots ([ordered]@{ lifecycle_lock = $path })
    $beforeSecurity = Get-ManagedUserPathSecurityFingerprint $path
    $inputObject = [ordered]@{
        path = $path
        expected_sid = $script:PrimarySID
    }
    $inputBase64 = [Convert]::ToBase64String(
        [Text.Encoding]::UTF8.GetBytes(
            ($inputObject | ConvertTo-Json -Compress)
        )
    )
    $probe = Invoke-ActiveUserPowerShell `
        -Label 'nonadmin-lifecycle-lock-squatting' `
        -TimeoutSeconds 120 `
        -Script @'
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$inputObject = [Text.Encoding]::UTF8.GetString(
    [Convert]::FromBase64String('__INPUT__')
) | ConvertFrom-Json -ErrorAction Stop
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
if ($sid -ne [string]$inputObject.expected_sid) {
    throw "lifecycle lock probe SID mismatch: $sid"
}
$attempts = [Collections.Generic.List[object]]::new()
foreach ($mode in @('exclusive_open', 'overwrite', 'delete')) {
    $succeeded = $false
    $errorCode = 0
    try {
        switch ($mode) {
            'exclusive_open' {
                $stream = [IO.File]::Open(
                    [string]$inputObject.path,
                    [IO.FileMode]::OpenOrCreate,
                    [IO.FileAccess]::ReadWrite,
                    [IO.FileShare]::None
                )
                $stream.Dispose()
            }
            'overwrite' {
                [IO.File]::WriteAllText(
                    [string]$inputObject.path,
                    'squatted',
                    [Text.UTF8Encoding]::new($false)
                )
            }
            'delete' {
                Remove-Item `
                    -LiteralPath ([string]$inputObject.path) `
                    -Force `
                    -ErrorAction Stop
            }
        }
        $succeeded = $true
    } catch {
        $errorCode = [Runtime.InteropServices.Marshal]::GetHRForException(
            $_.Exception
        ) -band 0xffff
    }
    $attempts.Add([pscustomobject]@{
        mode = $mode
        succeeded = $succeeded
        error_code = $errorCode
    })
}
[pscustomobject]@{
    sid = $sid
    attempts = @($attempts)
} | ConvertTo-Json -Compress -Depth 5
'@.Replace('__INPUT__', $inputBase64)
    $result = ConvertFrom-SingleJSONDocument `
        $probe.StdOut `
        'non-admin lifecycle lock squatting'
    if ([string]$result.sid -ne $script:PrimarySID -or
        @($result.attempts | Where-Object {
            [bool]$_.succeeded -or [int]$_.error_code -notin @(5, 32)
        }).Count -ne 0) {
        throw (
            'standard user could capture/change the predictable lifecycle ' +
            "lock or received an unexpected result: " +
            (Protect-SensitiveDisplayText (
                $result | ConvertTo-Json -Compress -Depth 5
            ))
        )
    }
    $after = Get-ArtifactSnapshots ([ordered]@{ lifecycle_lock = $path })
    Assert-SameArtifactSnapshots `
        $before `
        $after `
        'non-admin lifecycle lock squatting'
    $afterSecurity = Get-ManagedUserPathSecurityFingerprint $path
    if ([string]$afterSecurity.sddl -cne [string]$beforeSecurity.sddl -or
        [string]$afterSecurity.owner_sid -cne
            [string]$beforeSecurity.owner_sid) {
        throw 'non-admin lifecycle lock probe changed owner/DACL'
    }
    $verify = Invoke-EnterpriseInstallerJSON `
        -Action Verify `
        -GatewaySource '' `
        -HookSource '' `
        -CLISource '' `
        -Label 'post-lifecycle-lock-squatting-installer-verify'
    if (-not [bool]$verify.JSON.ok) {
        throw 'installer was unhealthy after denied lifecycle lock squatting'
    }
    return [pscustomobject]@{
        path = $path
        attempts = @($result.attempts)
        bytes_unchanged = $true
        owner_dacl_unchanged = $true
        installer_responsive = $true
    }
}

function Test-CodexMachineLockSquattingBoundaries {
    if ($ClaudeOnly) {
        throw 'Codex machine lock squatting test requires an enabled Codex target'
    }
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $hashBytes = $sha.ComputeHash(
            [Text.Encoding]::UTF8.GetBytes(
                $script:CodexRequirementsPath.ToUpperInvariant()
            )
        )
    } finally {
        $sha.Dispose()
    }
    $mutexHash = ([BitConverter]::ToString($hashBytes)).Replace('-', '').
        ToLowerInvariant()
    $legacyMutexName = "Global\DefenseClaw-CodexRequirements-$mutexHash"
    $deploymentBefore = Get-DeploymentDigests
    $machineBefore = Get-CodexMachinePolicySnapshot
    $legacyCases = [Collections.Generic.List[object]]::new()
    foreach ($mode in @('hostile_dacl', 'held_permissive')) {
        $squatter = $null
        try {
            $squatter = Start-ActiveUserMutexSquatter `
                -MutexName $legacyMutexName `
                -Mode $mode `
                -Label "legacy-codex-machine-mutex-$mode"
            $stopwatch = [Diagnostics.Stopwatch]::StartNew()
            $verify = Invoke-GatewayJSON `
                -Arguments @(
                    'enterprise', 'windows',
                    'codex-requirements', 'verify'
                ) `
                -Label "legacy-codex-machine-mutex-$mode-verify"
            $stopwatch.Stop()
            if (-not [bool]$verify.JSON.ok -or
                $verify.Process.ExitCode -ne 0 -or
                [bool]$verify.JSON.security_complete -ne
                    [bool]$script:ClaudeEffectivePolicyAttested) {
                throw (
                    "$mode legacy Global mutex influenced protected file-lock " +
                    'verification'
                )
            }
            if ($stopwatch.Elapsed.TotalSeconds -gt 30) {
                throw (
                    "$mode legacy Global mutex delayed an implementation that " +
                    "must not open it: $($stopwatch.Elapsed.TotalSeconds)s"
                )
            }
            $deploymentAfter = Get-DeploymentDigests
            Assert-SameDigests `
                $deploymentBefore `
                $deploymentAfter `
                "$mode legacy Global mutex deployment"
            $machineAfter = Get-CodexMachinePolicySnapshot
            Assert-SameObjectJSON `
                $machineBefore `
                $machineAfter `
                "$mode legacy Global mutex machine policy"
            $legacyCases.Add([pscustomobject]@{
                mode = $mode
                mutex_name = $legacyMutexName
                squatter_sid = $script:PrimarySID
                squatter_pid = [uint32]$squatter.PID
                elapsed_ms = [int64]$stopwatch.ElapsedMilliseconds
                exit_code = [int]$verify.Process.ExitCode
                ignored_by_implementation = $true
                policy_unchanged = $true
                deployment_unchanged = $true
            })
        } finally {
            if ($null -ne $squatter) {
                $null = Stop-ActiveUserMutexSquatter $squatter
            }
        }
    }

    $fileLockHolder = $null
    $contention = $null
    try {
        $fileLockHolder = Start-ActiveUserFileLockHolder `
            -Path $script:CodexMachineLockPath `
            -Label 'codex-machine-protected-file-lock-contention'
        $stopwatch = [Diagnostics.Stopwatch]::StartNew()
        $verify = Invoke-GatewayJSON `
            -Arguments @(
                'enterprise', 'windows',
                'codex-requirements', 'verify'
            ) `
            -Label 'codex-machine-protected-file-lock-held-verify' `
            -AllowedExitCodes @(1)
        $stopwatch.Stop()
        if ([bool]$verify.JSON.ok -or
            $verify.Process.ExitCode -eq 0) {
            throw 'held protected Codex file lock did not fail closed'
        }
        $diagnostic = [string]$verify.JSON.error
        if ($diagnostic -notmatch
            '(?i)lock|timed out|sharing violation|used by another process') {
            throw (
                'held protected Codex file lock omitted a causal diagnostic: ' +
                (Protect-SensitiveDisplayText $diagnostic)
            )
        }
        if ($stopwatch.Elapsed.TotalSeconds -gt 30) {
            throw (
                'protected Codex file-lock contention exceeded the bounded ' +
                "30-second fail-closed window: " +
                "$($stopwatch.Elapsed.TotalSeconds)s"
            )
        }
        $deploymentAfter = Get-DeploymentDigests
        Assert-SameDigests `
            $deploymentBefore `
            $deploymentAfter `
            'held protected Codex file lock deployment'
        $machineAfter = Get-CodexMachinePolicySnapshot
        Assert-SameObjectJSON `
            $machineBefore `
            $machineAfter `
            'held protected Codex file lock machine policy'
        $contention = [pscustomobject]@{
            path = $script:CodexMachineLockPath
            holder_sid = $script:PrimarySID
            holder_pid = [uint32]$fileLockHolder.PID
            elapsed_ms = [int64]$stopwatch.ElapsedMilliseconds
            exit_code = [int]$verify.Process.ExitCode
            diagnostic = Protect-SensitiveDisplayText $diagnostic
            bounded_fail_closed = $true
            policy_unchanged = $true
            deployment_unchanged = $true
        }
    } finally {
        if ($null -ne $fileLockHolder) {
            $null = Stop-ActiveUserFileLockHolder $fileLockHolder
        }
    }
    $healthy = Invoke-GatewayJSON `
        -Arguments @(
            'enterprise', 'windows',
            'codex-requirements', 'verify'
        ) `
        -Label 'codex-machine-protected-file-lock-post-release'
    if (-not [bool]$healthy.JSON.ok -or
        [bool]$healthy.JSON.security_complete -ne
            [bool]$script:ClaudeEffectivePolicyAttested) {
        throw 'machine-policy verify did not recover after file-lock release'
    }
    return [pscustomobject]@{
        legacy_mutex_name = $legacyMutexName
        legacy_mutex_cases = @($legacyCases.ToArray())
        legacy_named_objects_ignored = $true
        protected_file_lock = $contention
        protected_file_lock_bounded_fail_closed = $true
        unauthorized_machine_policy_read_or_mutation = $false
    }
}

function Test-StandardUsersCannotTamperCodexMachinePolicy {
    $before = Get-CodexMachinePolicySnapshot
    $inputObject = [ordered]@{
        paths = @(
            $script:CodexRequirementsPath,
            $script:CodexMachineLockPath,
            $script:CodexManagedStatePath
        )
        icacls = Join-Path $script:System32 'icacls.exe'
    }
    $inputBase64 = [Convert]::ToBase64String(
        [Text.Encoding]::UTF8.GetBytes(
            ($inputObject | ConvertTo-Json -Compress -Depth 4)
        )
    )
    $probe = @'
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$inputObject = [Text.Encoding]::UTF8.GetString(
    [Convert]::FromBase64String('__INPUT__')
) | ConvertFrom-Json -ErrorAction Stop
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$results = [Collections.Generic.List[object]]::new()
foreach ($path in @($inputObject.paths)) {
    foreach ($operation in @('write', 'delete', 'change-dacl')) {
        $denied = $false
        $detail = ''
        try {
            switch ($operation) {
                'write' {
                    [IO.File]::WriteAllText(
                        [string]$path,
                        "FORBIDDEN-$sid`r`n",
                        [Text.UTF8Encoding]::new($false)
                    )
                }
                'delete' {
                    Remove-Item -LiteralPath ([string]$path) -Force -ErrorAction Stop
                }
                'change-dacl' {
                    $output = @(
                        & ([string]$inputObject.icacls) `
                            ([string]$path) `
                            '/grant' `
                            ("*" + $sid + ':F') 2>&1
                    )
                    if ($LASTEXITCODE -ne 0) {
                        $denied = $true
                        $detail = "icacls exit $LASTEXITCODE`: $($output -join ' ')"
                    }
                }
            }
        } catch [UnauthorizedAccessException] {
            $denied = $true
            $detail = $_.Exception.Message
        } catch [Security.SecurityException] {
            $denied = $true
            $detail = $_.Exception.Message
        } catch [IO.IOException] {
            $denied = (
                [uint32]$_.Exception.HResult -band 0xFFFF
            ) -in @(5, 32, 33)
            $detail = $_.Exception.Message
        } catch {
            $inner = $_.Exception.InnerException
            $native = if ($inner -is [ComponentModel.Win32Exception]) {
                [int]$inner.NativeErrorCode
            } else {
                [int]([uint32]$_.Exception.HResult -band 0xFFFF)
            }
            $denied = (
                $native -in @(5, 32, 33, 1314) -or
                $_.Exception.Message -match '(?i)access.*denied|unauthori'
            )
            if (-not $denied) { throw }
            $detail = $_.Exception.Message
        }
        $results.Add([pscustomobject]@{
            path = [string]$path
            operation = $operation
            denied = $denied
            detail = $detail
        })
    }
}
$failed = @($results | Where-Object { -not [bool]$_.denied })
[pscustomobject]@{
    sid = $sid
    ok = $failed.Count -eq 0
    results = @($results.ToArray())
    failed = @($failed)
} | ConvertTo-Json -Compress -Depth 6
if ($failed.Count -ne 0) { exit 22 }
'@.Replace('__INPUT__', $inputBase64)
    $observations = [Collections.Generic.List[object]]::new()
    $active = Invoke-ActiveUserPowerShell `
        -Script $probe `
        -Label 'active-user-codex-machine-policy-tamper' `
        -AllowedExitCodes @(0, 22) `
        -TimeoutSeconds 120
    $activeJSON = ConvertFrom-SingleJSONDocument `
        $active.StdOut `
        'active-user Codex machine-policy tamper'
    $observations.Add($activeJSON)
    $hostile = Invoke-UserPowerShell `
        -Credential $script:HostileCredential `
        -Script $probe `
        -Label 'unregistered-user-codex-machine-policy-tamper' `
        -AllowedExitCodes @(0, 22) `
        -TimeoutSeconds 120
    $hostileJSON = ConvertFrom-SingleJSONDocument `
        $hostile.StdOut `
        'unregistered-user Codex machine-policy tamper'
    $observations.Add($hostileJSON)
    foreach ($row in @($activeJSON, $hostileJSON)) {
        if (-not [bool]$row.ok) {
            throw "standard SID $($row.sid) crossed the Codex machine-policy boundary"
        }
    }
    $after = Get-CodexMachinePolicySnapshot
    Assert-SameObjectJSON `
        $before `
        $after `
        'standard-user Codex machine-policy tamper'
    return [pscustomobject]@{
        users = @($observations.ToArray())
        operations_per_user = 6
        bytes_and_security_unchanged = $true
    }
}

function Invoke-ExpectedCodexMachinePolicyFailure([string]$Label) {
    $machine = Invoke-GatewayJSON `
        -Arguments @(
            'enterprise', 'windows', 'codex-requirements', 'verify'
        ) `
        -Label "$Label-machine-verify" `
        -AllowedExitCodes @(1)
    if ($machine.Process.ExitCode -eq 0 -or [bool]$machine.JSON.ok) {
        throw "$Label machine requirements verify claimed healthy"
    }
    $guardian = Invoke-GatewayJSON `
        -Arguments @(
            'enterprise', 'hooks', 'verify',
            '--manifest',
            (Join-Path $script:StateRoot 'hook-guardian\targets.yaml')
        ) `
        -Label "$Label-guardian-verify" `
        -AllowedExitCodes @(1)
    if ($guardian.Process.ExitCode -eq 0 -or [bool]$guardian.JSON.ok) {
        throw "$Label guardian verify claimed healthy"
    }
    return [pscustomobject]@{
        machine_error = [string]$machine.JSON.error
        guardian_state = $guardian.JSON.state
    }
}

function Test-CodexMachinePolicyAutoHeal {
    $baseline = Get-CodexMachinePolicySnapshot
    $requirementsBytes = [IO.File]::ReadAllBytes($script:CodexRequirementsPath)
    $requirementsACL = Get-Acl -LiteralPath $script:CodexRequirementsPath
    $managedStateBytes = [IO.File]::ReadAllBytes($script:CodexManagedStatePath)
    $managedStateACL = Get-Acl -LiteralPath $script:CodexManagedStatePath
    $observations = [Collections.Generic.List[object]]::new()
    foreach ($case in @(
        'managed-hook-removal',
        'requirements-delete',
        'requirements-dacl-drift',
        'managed-enrollment-state-delete'
    )) {
        $guardianStopped = $false
        $pendingError = $null
        $failureEvidence = $null
        $started = [DateTimeOffset]::UtcNow
        try {
            Stop-Service `
                -Name $script:GuardianServiceName `
                -Force `
                -ErrorAction Stop
            Wait-Until -Description "$case guardian stop" -Condition {
                (Get-Service `
                    -Name $script:GuardianServiceName `
                    -ErrorAction Stop).Status -eq
                    [ServiceProcess.ServiceControllerStatus]::Stopped
            } | Out-Null
            $guardianStopped = $true
            switch ($case) {
                'managed-hook-removal' {
                    $raw = [Text.Encoding]::UTF8.GetString(
                        $requirementsBytes
                    )
                    $tampered = $raw.Replace(
                        '[[hooks.SessionStart]]',
                        '[[hooks.SessionStartRemoved]]'
                    )
                    if ($tampered -ceq $raw) {
                        throw 'could not locate the managed SessionStart group to remove'
                    }
                    [IO.File]::WriteAllText(
                        $script:CodexRequirementsPath,
                        $tampered,
                        [Text.UTF8Encoding]::new($false)
                    )
                }
                'requirements-delete' {
                    Remove-Item `
                        -LiteralPath $script:CodexRequirementsPath `
                        -Force `
                        -ErrorAction Stop
                }
                'requirements-dacl-drift' {
                    $null = Invoke-NativeProcess `
                        -FilePath (Join-Path $script:System32 'icacls.exe') `
                        -ArgumentList @(
                            $script:CodexRequirementsPath,
                            '/grant',
                            "*$($script:PrimarySID):F"
                        ) `
                        -Label 'drift-codex-requirements-dacl'
                }
                'managed-enrollment-state-delete' {
                    Remove-Item `
                        -LiteralPath $script:CodexManagedStatePath `
                        -Force `
                        -ErrorAction Stop
                }
            }
            $failureEvidence = Invoke-ExpectedCodexMachinePolicyFailure `
                "codex-policy-$case"
        } catch {
            $pendingError = $_
        } finally {
            $service = Get-Service `
                -Name $script:GuardianServiceName `
                -ErrorAction SilentlyContinue
            if ($null -ne $service -and
                $service.Status -eq
                    [ServiceProcess.ServiceControllerStatus]::Stopped) {
                try {
                    Start-Service `
                        -Name $script:GuardianServiceName `
                        -ErrorAction Stop
                } catch {
                    if ($null -eq $pendingError) { $pendingError = $_ }
                }
            }
        }
        try {
            Wait-Until `
                -Description "$case exact machine-policy auto-heal" `
                -Condition {
                    try {
                        $current = Get-CodexMachinePolicySnapshot
                        foreach ($property in $baseline.PSObject.Properties) {
                            $after = $current.PSObject.Properties[
                                $property.Name
                            ]
                            if ($null -eq $after -or
                                [string]$after.Value.sha256 -cne
                                    [string]$property.Value.sha256 -or
                                [string]$after.Value.sddl -cne
                                    [string]$property.Value.sddl) {
                                return $false
                            }
                        }
                        $healthy = Invoke-GatewayJSON `
                            -Arguments @(
                                'enterprise', 'windows',
                                'codex-requirements', 'verify'
                            ) `
                            -Label "poll-$case-machine-policy" `
                            -AllowedExitCodes @(0, 1)
                        return (
                            $healthy.Process.ExitCode -eq 0 -and
                            [bool]$healthy.JSON.ok -and
                            [bool]$healthy.JSON.security_complete -eq
                                [bool]$script:ClaudeEffectivePolicyAttested
                        )
                    } catch {
                        return $false
                    }
                } |
                Out-Null
        } catch {
            # Keep cleanup recoverable even when the guardian regression is
            # exactly the failure under test.
            [IO.File]::WriteAllBytes(
                $script:CodexRequirementsPath,
                $requirementsBytes
            )
            Set-Acl `
                -LiteralPath $script:CodexRequirementsPath `
                -AclObject $requirementsACL
            [IO.File]::WriteAllBytes(
                $script:CodexManagedStatePath,
                $managedStateBytes
            )
            Set-Acl `
                -LiteralPath $script:CodexManagedStatePath `
                -AclObject $managedStateACL
            throw
        }
        if ($null -ne $pendingError) {
            throw $pendingError
        }
        $current = Get-CodexMachinePolicySnapshot
        Assert-SameObjectJSON `
            $baseline `
            $current `
            "$case machine-policy repair"
        $observations.Add([pscustomobject]@{
            case = $case
            unhealthy_while_guardian_stopped = $true
            exact_auto_heal = $true
            recovery_milliseconds = [Math]::Round(
                ([DateTimeOffset]::UtcNow - $started).TotalMilliseconds,
                0
            )
            failure_evidence = $failureEvidence
        })
    }
    $null = Assert-CodexMachinePolicyContract 'post-auto-heal'
    return [pscustomobject]@{
        cases = @($observations.ToArray())
        requirements_exact = $true
        enrollment_state_exact = $true
        protected_dacl_exact = $true
    }
}

function Test-UnregisteredInteractiveSIDFailsClosed {
    $hook = ConvertTo-CanonicalPath (
        Join-Path $script:InstallRoot 'bin\defenseclaw-hook.exe'
    )
    $hostileData = ConvertTo-CanonicalPath (
        Join-Path $script:HostileProfile '.defenseclaw'
    )
    $before = Get-ProtectedUserTreeInventory `
        $hostileData `
        'unregistered SID DefenseClaw runtime before hook'
    $inputObject = [ordered]@{
        hook = $hook
        expected_sid = $script:HostileSID
        connector = if ($ClaudeOnly) { 'claudecode' } else { 'codex' }
    }
    $inputBase64 = [Convert]::ToBase64String(
        [Text.Encoding]::UTF8.GetBytes(
            ($inputObject | ConvertTo-Json -Compress)
        )
    )
    $scriptText = @'
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$inputObject = [Text.Encoding]::UTF8.GetString(
    [Convert]::FromBase64String('__INPUT__')
) | ConvertFrom-Json -ErrorAction Stop
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
if ($sid -ne [string]$inputObject.expected_sid) {
    throw "unregistered hook probe SID mismatch: $sid"
}
$output = @(
    '{"hook_event_name":"SessionStart","source":"startup"}' |
        & ([string]$inputObject.hook) `
            hook `
            --connector ([string]$inputObject.connector) `
            --enterprise-managed 2>&1
)
$hookExit = $LASTEXITCODE
[pscustomobject]@{
    sid = $sid
    hook_exit_code = $hookExit
    output = ($output | ForEach-Object { [string]$_ }) -join "`n"
} | ConvertTo-Json -Compress
'@.Replace('__INPUT__', $inputBase64)
    $process = Invoke-UserPowerShell `
        -Credential $script:HostileCredential `
        -Script $scriptText `
        -Label 'unregistered-interactive-sid-managed-hook' `
        -TimeoutSeconds 120
    $result = ConvertFrom-SingleJSONDocument `
        $process.StdOut `
        'unregistered interactive SID managed hook'
    if ([string]$result.sid -ne $script:HostileSID) {
        throw 'unregistered managed hook did not execute as the hostile SID'
    }
    if ([int]$result.hook_exit_code -eq 0) {
        throw 'unregistered interactive SID was silently allowed/no-op by the managed hook'
    }
    if ([string]$result.output -notmatch
        '(?i)enterprise_managed_sid_not_enrolled|not (?:enrolled|registered)|unauthori[sz]ed SID') {
        throw (
            'unregistered managed hook did not emit a causal enrollment ' +
            "diagnostic: $(Protect-SensitiveDisplayText ([string]$result.output))"
        )
    }
    $after = Get-ProtectedUserTreeInventory `
        $hostileData `
        'unregistered SID DefenseClaw runtime after hook'
    Assert-SameUserTreeInventory `
        $before `
        $after `
        'unregistered SID managed runtime'
    return [pscustomobject]@{
        sid = $script:HostileSID
        exit_code = [int]$result.hook_exit_code
        enrollment_diagnostic = Protect-SensitiveDisplayText (
            [string]$result.output
        )
        runtime_created = $false
        failed_closed = $true
    }
}

function Test-DisabledClaudeTargetDeenrollsExactly {
    $installedManifest = Join-Path `
        $script:StateRoot `
        'hook-guardian\targets.yaml'
    $baselineContent = [IO.File]::ReadAllText($installedManifest)
    $baselineACL = Get-Acl -LiteralPath $installedManifest
    $initialStatus = Invoke-GatewayJSON `
        -Arguments @(
            'enterprise', 'hooks', 'status',
            '--manifest', $installedManifest
        ) `
        -Label 'stale-sid-initial-status'
    $claudeArtifacts = Get-ManagedClaudeArtifactSet $initialStatus.JSON
    $runtimeBefore = Get-ArtifactSnapshots $claudeArtifacts.Paths
    $beforeAudit = @(Get-ClaudeHookAuditRows 'stale-sid-audit-before')
    $beforeAuditIDs = New-CodexHookAuditIDSet $beforeAudit
    $primaryHomeYAML = $script:PrimaryProfile.Replace("'", "''")
    $primaryDataYAML = $script:PrimaryDataDir.Replace("'", "''")
    $disabledManifest = if ($ClaudeOnly) {
        @"
version: 1
targets:
  - user_home: '$primaryHomeYAML'
    sid: '$($script:PrimarySID)'
    data_dir: '$primaryDataYAML'
    connector: claudecode
    agent_version: "2.1.207 (Claude Code)"
    enabled: false
"@
    } else {
        @"
version: 1
targets:
  - user_home: '$primaryHomeYAML'
    sid: '$($script:PrimarySID)'
    data_dir: '$primaryDataYAML'
    connector: codex
    agent_version: "codex-cli 0.144.3"
  - user_home: '$primaryHomeYAML'
    sid: '$($script:PrimarySID)'
    data_dir: '$primaryDataYAML'
    connector: claudecode
    agent_version: "2.1.207 (Claude Code)"
    enabled: false
"@
    }
    $disabledEvidence = $null
    try {
        Write-ProtectedManifest `
            $installedManifest `
            $disabledManifest `
            'disable-claude-target-for-exact-deenrollment'
        Set-Acl -LiteralPath $installedManifest -AclObject $baselineACL
        $reconcile = Invoke-GuardianServiceReconcile `
            -Label 'disabled-claude-target-reconcile'
        if (-not [bool]$reconcile.JSON.ok) {
            throw 'disabled Claude target reconciliation returned ok=false'
        }
        $status = Invoke-GatewayJSON `
            -Arguments @(
                'enterprise', 'hooks', 'status',
                '--manifest', $installedManifest
            ) `
            -Label 'disabled-claude-target-status'
        if (-not [bool]$status.JSON.ok) {
            throw 'disabled Claude target status is unhealthy'
        }
        $stateRows = @($status.JSON.state.results)
        $authorizationRows = @(
            $status.JSON.authorization.protected_targets
        )
        if (@($stateRows | Where-Object {
            [string]$_.connector -eq 'claudecode'
        }).Count -ne 0 -or
            @($authorizationRows | Where-Object {
                [string]$_.connector -eq 'claudecode' -and
                [string]$_.sid -eq $script:PrimarySID
            }).Count -ne 0) {
            throw (
                'disabled Claude SID survived in guardian state or protected ' +
                'authorization'
            )
        }
        $expectedRemaining = if ($ClaudeOnly) { 0 } else { 1 }
        if ($stateRows.Count -ne $expectedRemaining -or
            $authorizationRows.Count -ne $expectedRemaining) {
            throw (
                'disabled target reconciliation did not converge to the ' +
                "exact enabled set: state=$($stateRows.Count) " +
                "authorization=$($authorizationRows.Count) " +
                "expected=$expectedRemaining"
            )
        }
        foreach ($path in @(
            $script:ClaudeManagedPolicyPath,
            $script:ClaudeManagedStatePath
        )) {
            if (Test-Path -LiteralPath $path) {
                throw "disabled last Claude target left active policy enrollment: $path"
            }
        }
        $runtimeDisabled = Get-ArtifactSnapshots $claudeArtifacts.Paths
        Assert-SameArtifactSnapshots `
            $runtimeBefore `
            $runtimeDisabled `
            'disabled Claude target retained inert recovery runtime'

        $inputObject = [ordered]@{
            hook = ConvertTo-CanonicalPath (
                Join-Path $script:InstallRoot 'bin\defenseclaw-hook.exe'
            )
            expected_sid = $script:PrimarySID
        }
        $inputBase64 = [Convert]::ToBase64String(
            [Text.Encoding]::UTF8.GetBytes(
                ($inputObject | ConvertTo-Json -Compress)
            )
        )
        $managedHookProbeScript = @'
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$inputObject = [Text.Encoding]::UTF8.GetString(
    [Convert]::FromBase64String('__INPUT__')
) | ConvertFrom-Json -ErrorAction Stop
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
if ($sid -ne [string]$inputObject.expected_sid) {
    throw "disabled-target hook probe SID mismatch: $sid"
}
$output = @(
    '{"hook_event_name":"SessionStart","source":"startup"}' |
        & ([string]$inputObject.hook) `
            hook `
            --connector claudecode `
            --enterprise-managed 2>&1
)
[pscustomobject]@{
    sid = $sid
    exit_code = $LASTEXITCODE
    output = ($output | ForEach-Object { [string]$_ }) -join "`n"
} | ConvertTo-Json -Compress
'@.Replace('__INPUT__', $inputBase64)
        $probe = Invoke-ActiveUserPowerShell `
            -Label 'disabled-claude-target-managed-hook' `
            -TimeoutSeconds 120 `
            -Script $managedHookProbeScript
        $probeJSON = ConvertFrom-SingleJSONDocument `
            $probe.StdOut `
            'disabled Claude target managed hook'
        if ([int]$probeJSON.exit_code -eq 0 -or
            [string]$probeJSON.output -notmatch
                '(?i)enterprise_managed_sid_not_enrolled|not (?:enrolled|registered)|unauthori[sz]ed SID|disabled') {
            throw (
                'disabled Claude target managed invocation did not fail closed ' +
                "with a causal enrollment diagnostic: exit=" +
                "$($probeJSON.exit_code) output=" +
                (Protect-SensitiveDisplayText ([string]$probeJSON.output))
            )
        }
        Start-Sleep -Seconds 2
        $newAudit = @(
            Get-ClaudeHookAuditRows 'stale-sid-audit-after' |
                Where-Object {
                    -not $beforeAuditIDs.Contains([string]$_.id)
                }
        )
        if ($newAudit.Count -ne 0) {
            throw 'disabled Claude target produced authenticated managed-hook audit'
        }
        $runtimeAfterProbe = Get-ArtifactSnapshots $claudeArtifacts.Paths
        Assert-SameArtifactSnapshots `
            $runtimeBefore `
            $runtimeAfterProbe `
            'disabled Claude target inert runtime'

        $removedManifest = if ($ClaudeOnly) {
            @"
version: 1
targets: []
"@
        } else {
            @"
version: 1
targets:
  - user_home: '$primaryHomeYAML'
    sid: '$($script:PrimarySID)'
    data_dir: '$primaryDataYAML'
    connector: codex
    agent_version: "codex-cli 0.144.3"
"@
        }
        Write-ProtectedManifest `
            $installedManifest `
            $removedManifest `
            'remove-claude-target-for-exact-deenrollment'
        Set-Acl -LiteralPath $installedManifest -AclObject $baselineACL
        $removedReconcile = Invoke-GuardianServiceReconcile `
            -Label 'removed-claude-target-reconcile'
        if (-not [bool]$removedReconcile.JSON.ok) {
            throw 'removed Claude target reconciliation returned ok=false'
        }
        $removedStatus = Invoke-GatewayJSON `
            -Arguments @(
                'enterprise', 'hooks', 'status',
                '--manifest', $installedManifest
            ) `
            -Label 'removed-claude-target-status'
        if (-not [bool]$removedStatus.JSON.ok) {
            throw 'removed Claude target status is unhealthy'
        }
        $removedStateRows = @($removedStatus.JSON.state.results)
        $removedAuthorizationRows = @(
            $removedStatus.JSON.authorization.protected_targets
        )
        if (@($removedStateRows | Where-Object {
            [string]$_.connector -eq 'claudecode'
        }).Count -ne 0 -or
            @($removedAuthorizationRows | Where-Object {
                [string]$_.connector -eq 'claudecode' -and
                [string]$_.sid -eq $script:PrimarySID
            }).Count -ne 0 -or
            $removedStateRows.Count -ne $expectedRemaining -or
            $removedAuthorizationRows.Count -ne $expectedRemaining) {
            throw (
                'removed Claude target did not converge to exact enabled ' +
                'guardian state and protected authorization'
            )
        }
        foreach ($path in @(
            $script:ClaudeManagedPolicyPath,
            $script:ClaudeManagedStatePath
        )) {
            if (Test-Path -LiteralPath $path) {
                throw "removed last Claude target left active policy enrollment: $path"
            }
        }
        $removedProbe = Invoke-ActiveUserPowerShell `
            -Label 'removed-claude-target-managed-hook' `
            -TimeoutSeconds 120 `
            -Script $managedHookProbeScript
        $removedProbeJSON = ConvertFrom-SingleJSONDocument `
            $removedProbe.StdOut `
            'removed Claude target managed hook'
        if ([int]$removedProbeJSON.exit_code -eq 0 -or
            [string]$removedProbeJSON.output -notmatch
                '(?i)enterprise_managed_sid_not_enrolled|not (?:enrolled|registered)|unauthori[sz]ed SID|disabled') {
            throw (
                'removed Claude target managed invocation did not fail closed ' +
                "with a causal enrollment diagnostic: exit=" +
                "$($removedProbeJSON.exit_code) output=" +
                (Protect-SensitiveDisplayText (
                    [string]$removedProbeJSON.output
                ))
            )
        }
        Start-Sleep -Seconds 2
        $removedAudit = @(
            Get-ClaudeHookAuditRows 'removed-sid-audit-after' |
                Where-Object {
                    -not $beforeAuditIDs.Contains([string]$_.id)
                }
        )
        if ($removedAudit.Count -ne 0) {
            throw 'removed Claude target produced authenticated managed-hook audit'
        }
        $runtimeAfterRemoval = Get-ArtifactSnapshots $claudeArtifacts.Paths
        Assert-SameArtifactSnapshots `
            $runtimeBefore `
            $runtimeAfterRemoval `
            'removed Claude target inert runtime'
        $disabledEvidence = [pscustomobject]@{
            sid = $script:PrimarySID
            guardian_state_rows = $stateRows.Count
            authorization_rows = $authorizationRows.Count
            disabled_manifest_exact_deenrollment = $true
            removed_manifest_exact_deenrollment = $true
            removed_guardian_state_rows = $removedStateRows.Count
            removed_authorization_rows = $removedAuthorizationRows.Count
            claude_policy_removed = $true
            recovery_runtime_retained_exact = $true
            managed_hook_exit_code = [int]$probeJSON.exit_code
            managed_hook_diagnostic = Protect-SensitiveDisplayText (
                [string]$probeJSON.output
            )
            removed_managed_hook_exit_code =
                [int]$removedProbeJSON.exit_code
            removed_managed_hook_diagnostic = Protect-SensitiveDisplayText (
                [string]$removedProbeJSON.output
            )
            authenticated_audit_rows = 0
            runtime_inert = $true
        }
    } finally {
        Write-ProtectedManifest `
            $installedManifest `
            $baselineContent `
            'restore-claude-target-after-deenrollment'
        Set-Acl -LiteralPath $installedManifest -AclObject $baselineACL
        $restored = Invoke-GuardianServiceReconcile `
            -Label 'restore-claude-target-reconcile'
        if (-not [bool]$restored.JSON.ok) {
            throw 'Claude target restoration reconciliation returned ok=false'
        }
        Wait-ForServicesRunning
        $null = Assert-HealthyGuardianJSON 'restored-after-claude-deenrollment'
    }
    return $disabledEvidence
}

function Invoke-RegisteredCodexHookExpectFail([string]$Label) {
    $hook = ConvertTo-CanonicalPath (
        Join-Path $script:InstallRoot 'bin\defenseclaw-hook.exe'
    )
    $inputObject = [ordered]@{
        hook = $hook
        expected_sid = $script:PrimarySID
        connector = if ($ClaudeOnly) { 'claudecode' } else { 'codex' }
    }
    $inputBase64 = [Convert]::ToBase64String(
        [Text.Encoding]::UTF8.GetBytes(
            ($inputObject | ConvertTo-Json -Compress)
        )
    )
    $scriptText = @'
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$inputObject = [Text.Encoding]::UTF8.GetString(
    [Convert]::FromBase64String('__INPUT__')
) | ConvertFrom-Json -ErrorAction Stop
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
if ($sid -ne [string]$inputObject.expected_sid) {
    throw "registered hook probe SID mismatch: $sid"
}
$output = @(
    '{"hook_event_name":"SessionStart","source":"startup"}' |
        & ([string]$inputObject.hook) `
            hook `
            --connector ([string]$inputObject.connector) `
            --enterprise-managed 2>&1
)
$hookExit = $LASTEXITCODE
[pscustomobject]@{
    sid = $sid
    hook_exit_code = $hookExit
    output = ($output | ForEach-Object { [string]$_ }) -join "`n"
} | ConvertTo-Json -Compress
'@.Replace('__INPUT__', $inputBase64)
    $process = Invoke-ActiveUserPowerShell `
        -Script $scriptText `
        -Label $Label `
        -TimeoutSeconds 120
    $result = ConvertFrom-SingleJSONDocument $process.StdOut $Label
    if ([string]$result.sid -ne $script:PrimarySID -or
        [int]$result.hook_exit_code -eq 0) {
        throw "$Label did not fail closed under the exact registered target SID"
    }
    if ([string]$result.output -notmatch
        '(?i)gateway.*(?:PID|identity|listener)|foreign.*listener|peer.*PID|refus') {
        throw (
            "$Label omitted the causal gateway peer-identity diagnostic: " +
            (Protect-SensitiveDisplayText ([string]$result.output))
        )
    }
    return $result
}

function Get-FakeGatewayListenerEvidence([object]$Listener) {
    if (-not (Test-Path -LiteralPath $Listener.EvidencePath -PathType Leaf)) {
        throw 'fake gateway listener emitted no evidence'
    }
    return Get-Content -LiteralPath $Listener.EvidencePath -Raw |
        ConvertFrom-Json -ErrorAction Stop
}

function Test-GatewayPortHijackFailsClosed {
    $listener = $null
    $finalEvidence = $null
    $explicitStopHook = $null
    $restartRaceHook = $null
    $gatewayStartDiagnostic = ''
    try {
        Stop-Service `
            -Name $script:GatewayServiceName `
            -Force `
            -ErrorAction Stop
        Wait-Until -Description 'gateway explicit stop before port hijack' -Condition {
            (Get-Service `
                -Name $script:GatewayServiceName `
                -ErrorAction Stop).Status -eq
                [ServiceProcess.ServiceControllerStatus]::Stopped
        } | Out-Null
        $listener = Start-ActiveUserFakeGatewayListener `
            'fake-gateway-port-hijack'
        $owner = @(
            Get-NetTCPConnection `
                -LocalAddress '127.0.0.1' `
                -LocalPort $script:APIPort `
                -State Listen `
                -ErrorAction Stop
        )
        if ($owner.Count -ne 1 -or
            [uint32]$owner[0].OwningProcess -ne [uint32]$listener.PID) {
            throw 'fake listener does not exclusively own the configured API port'
        }

        $explicitStopHook = Invoke-RegisteredCodexHookExpectFail `
            'managed-hook-fake-listener-after-explicit-stop'
        $afterExplicitStop = Get-FakeGatewayListenerEvidence $listener
        if ([int]$afterExplicitStop.authenticated_request_count -ne 0) {
            throw 'managed hook disclosed its bearer token to the fake listener after explicit stop'
        }

        try {
            Start-Service `
                -Name $script:GatewayServiceName `
                -ErrorAction Stop
        } catch {
            $gatewayStartDiagnostic = Protect-SensitiveDisplayText (
                $_.Exception.Message
            )
        }
        Start-Sleep -Milliseconds 750
        $serviceDuringRace = Get-CimInstance `
            Win32_Service `
            -Filter "Name='$($script:GatewayServiceName)'" `
            -ErrorAction Stop
        $restartRaceHook = Invoke-RegisteredCodexHookExpectFail `
            'managed-hook-fake-listener-during-service-restart-race'
        $duringRace = Get-FakeGatewayListenerEvidence $listener
        if ([int]$duringRace.authenticated_request_count -ne 0) {
            throw 'managed hook disclosed its bearer token during the gateway restart/bind race'
        }
        if ([uint32]$listener.PID -eq [uint32]$serviceDuringRace.ProcessId -and
            [uint32]$serviceDuringRace.ProcessId -ne 0) {
            throw 'fake listener PID unexpectedly equals the SCM gateway PID'
        }
    } finally {
        if ($null -ne $listener) {
            try {
                $finalEvidence = Stop-ActiveUserFakeGatewayListener $listener
            } catch {
                if ($null -eq $finalEvidence) {
                    $gatewayStartDiagnostic +=
                        '; listener cleanup: ' +
                        (Protect-SensitiveDisplayText $_.Exception.Message)
                }
            }
        }
        $gateway = Get-Service `
            -Name $script:GatewayServiceName `
            -ErrorAction SilentlyContinue
        if ($null -ne $gateway) {
            if ($gateway.Status -ne
                [ServiceProcess.ServiceControllerStatus]::Stopped) {
                Stop-Service `
                    -Name $script:GatewayServiceName `
                    -Force `
                    -ErrorAction SilentlyContinue
                Wait-Until `
                    -Description 'gateway stop after fake-listener release' `
                    -Condition {
                        (Get-Service `
                            -Name $script:GatewayServiceName `
                            -ErrorAction Stop).Status -eq
                            [ServiceProcess.ServiceControllerStatus]::Stopped
                    } |
                    Out-Null
            }
            Start-Service `
                -Name $script:GatewayServiceName `
                -ErrorAction Stop
        }
    }
    Wait-ForServicesRunning
    $null = Assert-HealthyGuardianJSON 'gateway-port-hijack-restored'
    if ($null -eq $finalEvidence -or
        [int]$finalEvidence.authenticated_request_count -ne 0) {
        throw 'fake gateway listener observed an authenticated request'
    }
    return [pscustomobject]@{
        api_port = $script:APIPort
        fake_listener_pid = [uint32]$listener.PID
        explicit_stop_hook_exit = [int]$explicitStopHook.hook_exit_code
        restart_race_hook_exit = [int]$restartRaceHook.hook_exit_code
        fake_request_count = [int]$finalEvidence.request_count
        fake_authenticated_request_count =
            [int]$finalEvidence.authenticated_request_count
        gateway_start_diagnostic = $gatewayStartDiagnostic
        gateway_recovered = $true
    }
}

function New-NonLoopbackManagedConfigFixture([string]$Name) {
    if ($Name -notmatch '^[a-z0-9-]+$') {
        throw "unsafe invalid-config fixture name: $Name"
    }
    $path = Join-Path $script:StagingRoot "$Name.yaml"
    $configText = [IO.File]::ReadAllText($script:ConfigSource)
    $invalidText = $configText.Replace(
        'api_bind: 127.0.0.1',
        'api_bind: 0.0.0.0'
    )
    if ([string]::Equals($configText, $invalidText, [StringComparison]::Ordinal)) {
        throw "$Name could not replace the managed loopback bind"
    }
    Write-ProtectedManifest $path $invalidText "protect-$Name"
    return $path
}

function Assert-CodexLifecycleFailure([object]$Envelope, [string]$Label) {
    if ($Envelope.Process.ExitCode -eq 0 -or [bool]$Envelope.JSON.ok) {
        throw "$Label unexpectedly reported success"
    }
    $diagnostic = [string]$Envelope.JSON.error
    if ($diagnostic -notmatch '(?i)api_bind|loopback|owner|DACL|reparse|junction') {
        throw "$Label omitted the fail-closed diagnostic: $(Protect-SensitiveDisplayText $diagnostic)"
    }
}

function Test-CodexSharedDirectoryCreationRollback {
    foreach ($path in @(
        $script:CodexVendorDirectory,
        $script:CodexMachinePolicyDirectory
    )) {
        if (Test-Path -LiteralPath $path) {
            throw "clean creation rollback fixture requires absent path: $path"
        }
    }
    $badConfig = New-NonLoopbackManagedConfigFixture 'codex-parent-initial-rollback'
    $rootsBefore = Get-MachineRootIdentitySnapshot @(
        $script:CodexVendorDirectory,
        $script:CodexMachinePolicyDirectory
    )
    $servicesBefore = Get-DefenseClawServiceInventory
    $sentinel = Join-Path $script:FixtureRoot 'codex-parent-rollback-neighbor.txt'
    Write-UTF8File $sentinel "codex-parent-rollback-neighbor`r`n"
    Protect-AdministratorFile $sentinel 'protect-codex-parent-rollback-neighbor'
    $sentinelBefore = Get-ProtectedUserTreeInventory `
        $script:FixtureRoot `
        'Codex parent rollback protected staging neighbor'

    $failed = Invoke-EnterpriseInstallerJSON `
        -Action Install `
        -ConfigSource $badConfig `
        -AllowedExitCodes @(1) `
        -NoStart `
        -Label 'installer-initial-codex-parent-rollback'
    Assert-CodexLifecycleFailure `
        $failed `
        'initial Install after Codex parent creation'
    $rootsAfter = Get-MachineRootIdentitySnapshot @(
        $script:CodexVendorDirectory,
        $script:CodexMachinePolicyDirectory
    )
    Assert-SameObjectJSON `
        $rootsBefore `
        $rootsAfter `
        'post-snapshot Codex shared-directory rollback'
    $servicesAfter = Get-DefenseClawServiceInventory
    Assert-SameObjectJSON `
        $servicesBefore `
        $servicesAfter `
        'post-snapshot Codex shared-directory service rollback'
    $sentinelAfter = Get-ProtectedUserTreeInventory `
        $script:FixtureRoot `
        'Codex parent rollback protected staging neighbor after failure'
    Assert-SameUserTreeInventory `
        $sentinelBefore `
        $sentinelAfter `
        'Codex parent rollback protected staging neighbor'
    return 'failed initial activation removed only the transaction-created empty OpenAI/Codex directories; services and protected neighboring state stayed exact'
}

function Test-CodexSharedDirectoryProvisioning {
    $policy = Assert-CodexMachinePolicyContract 'post-install'
    $vendorChildren = @(
        Get-ChildItem -LiteralPath $script:CodexVendorDirectory -Force
    )
    if ($vendorChildren.Count -ne 1 -or
        -not [string]::Equals(
            [string]$vendorChildren[0].FullName,
            $script:CodexMachinePolicyDirectory,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw 'enterprise Install created unexpected content in the shared OpenAI directory'
    }
    if (@(
        Get-ChildItem -LiteralPath $script:CodexMachinePolicyDirectory -Force
    ).Count -ne 2) {
        throw 'enterprise Install did not publish exactly requirements.toml and managed enrollment state'
    }
    return (
        'OpenAI/Codex shared parents and the exact ten-event protected ' +
        "machine policy are healthy; events=$($policy.event_count)"
    )
}

function Get-CodexReparseFixtureSnapshot([string]$Outside) {
    $item = Get-Item -LiteralPath $script:CodexMachinePolicyDirectory -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) {
        throw 'Codex shared reparse fixture is not a reparse point'
    }
    $sections = (
        [Security.AccessControl.AccessControlSections]::Access -bor
        [Security.AccessControl.AccessControlSections]::Owner -bor
        [Security.AccessControl.AccessControlSections]::Group
    )
    return [pscustomobject]@{
        path = [string]$item.FullName
        attributes = [int]$item.Attributes
        target = @($item.Target | ForEach-Object { [string]$_ })
        link_type = [string]$item.LinkType
        sddl = (Get-Acl -LiteralPath $item.FullName).
            GetSecurityDescriptorSddlForm($sections)
        outside = Get-ProtectedUserTreeInventory `
            $Outside `
            'Codex shared reparse outside'
    }
}

function Test-CodexSharedDirectoriesSurviveFailedInstall {
    $before = Get-ProtectedUserTreeInventory `
        $script:CodexVendorDirectory `
        'preexisting legitimate Codex shared directories'
    $badConfig = New-NonLoopbackManagedConfigFixture 'codex-parent-preexisting-failure'
    $servicesBefore = Get-DefenseClawServiceInventory
    $failed = Invoke-EnterpriseInstallerJSON `
        -Action Install `
        -ConfigSource $badConfig `
        -AllowedExitCodes @(1) `
        -NoStart `
        -Label 'installer-preexisting-codex-parent-failure'
    Assert-CodexLifecycleFailure `
        $failed `
        'Install with preexisting legitimate Codex shared directories'
    $after = Get-ProtectedUserTreeInventory `
        $script:CodexVendorDirectory `
        'preexisting legitimate Codex shared directories after failed Install'
    Assert-SameUserTreeInventory `
        $before `
        $after `
        'failed Install preexisting Codex shared directories'
    Assert-SameObjectJSON `
        $servicesBefore `
        (Get-DefenseClawServiceInventory) `
        'failed Install with preexisting Codex shared directories'
    $null = Assert-CodexMachinePolicyParentContract
    return 'post-snapshot Install failure preserved preexisting legitimate OpenAI/Codex directories byte/security/timestamp-exactly'
}

function Test-UnsafeCodexSharedDirectoryFailsClosed {
    $legitimate = Get-ProtectedUserTreeInventory `
        $script:CodexVendorDirectory `
        'legitimate Codex shared directory before unsafe owner fixture'
    $originalACL = Get-Acl -LiteralPath $script:CodexMachinePolicyDirectory
    try {
        $null = Set-ICaclsOwnerAndDacl `
            -Path $script:CodexMachinePolicyDirectory `
            -Owner "*$($script:HostileSID)" `
            -Grants @(
                '*S-1-5-18:(OI)(CI)F',
                '*S-1-5-32-544:(OI)(CI)F',
                "*$($script:HostileSID):(OI)(CI)F"
            ) `
            -Label 'make-codex-parent-owner-dacl-unsafe'
        $unsafeBefore = Get-ProtectedUserTreeInventory `
            $script:CodexVendorDirectory `
            'unsafe Codex shared owner/DACL before refusal'
        $failed = Invoke-EnterpriseInstallerJSON `
            -Action Install `
            -AllowedExitCodes @(1) `
            -NoStart `
            -Label 'installer-unsafe-codex-parent-refusal'
        Assert-CodexLifecycleFailure `
            $failed `
            'Install with hostile Codex shared owner/DACL'
        $unsafeAfter = Get-ProtectedUserTreeInventory `
            $script:CodexVendorDirectory `
            'unsafe Codex shared owner/DACL after refusal'
        Assert-SameUserTreeInventory `
            $unsafeBefore `
            $unsafeAfter `
            'unsafe Codex shared owner/DACL refusal'
    } finally {
        Set-Acl `
            -LiteralPath $script:CodexMachinePolicyDirectory `
            -AclObject $originalACL
    }
    $restored = Get-ProtectedUserTreeInventory `
        $script:CodexVendorDirectory `
        'Codex shared owner/DACL after fixture restore'
    Assert-SameUserTreeInventory `
        $legitimate `
        $restored `
        'Codex shared owner/DACL fixture restoration'
    return 'hostile preexisting owner/write DACL failed without installer takeover or mutation; the legitimate directory restored exactly'
}

function Test-ReparseCodexSharedDirectoryFailsClosed {
    $legitimate = Get-ProtectedUserTreeInventory `
        $script:CodexVendorDirectory `
        'legitimate Codex shared directory before reparse fixture'
    $vendorTimestamp = (Get-Item -LiteralPath $script:CodexVendorDirectory).
        LastWriteTimeUtc
    $backup = Join-Path $script:StagingRoot 'codex-shared-real-backup'
    $outside = Join-Path $script:FixtureRoot 'codex-shared-reparse-outside'
    if (Test-Path -LiteralPath $backup) {
        throw "Codex shared reparse backup already exists: $backup"
    }
    [IO.Directory]::CreateDirectory($outside) | Out-Null
    Protect-AdministratorTree $outside
    $sentinel = Join-Path $outside 'must-not-change.txt'
    Write-UTF8File $sentinel "codex-shared-reparse-sentinel`r`n"
    Protect-AdministratorFile $sentinel 'protect-codex-shared-reparse-sentinel'
    $restored = $false
    try {
        Move-Item `
            -LiteralPath $script:CodexMachinePolicyDirectory `
            -Destination $backup
        $cmd = Join-Path $script:System32 'cmd.exe'
        $null = Invoke-NativeProcess `
            -FilePath $cmd `
            -ArgumentList @(
                '/d', '/c', 'mklink', '/J',
                $script:CodexMachinePolicyDirectory,
                $outside
            ) `
            -Label 'create-codex-shared-parent-junction'
        $linkBefore = Get-CodexReparseFixtureSnapshot $outside
        $failed = Invoke-EnterpriseInstallerJSON `
            -Action Install `
            -AllowedExitCodes @(1) `
            -NoStart `
            -Label 'installer-reparse-codex-parent-refusal'
        Assert-CodexLifecycleFailure `
            $failed `
            'Install through a Codex shared parent junction'
        $linkAfter = Get-CodexReparseFixtureSnapshot $outside
        Assert-SameObjectJSON `
            $linkBefore `
            $linkAfter `
            'Codex shared parent reparse refusal'
    } finally {
        if (Test-Path -LiteralPath $script:CodexMachinePolicyDirectory) {
            $current = Get-Item `
                -LiteralPath $script:CodexMachinePolicyDirectory `
                -Force
            if (($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) {
                throw 'Codex shared reparse fixture was replaced by a real directory'
            }
            Remove-Item `
                -LiteralPath $script:CodexMachinePolicyDirectory `
                -Force
        }
        if (-not (Test-Path -LiteralPath $backup -PathType Container)) {
            throw 'Codex shared reparse fixture lost its protected real-directory backup'
        }
        Move-Item `
            -LiteralPath $backup `
            -Destination $script:CodexMachinePolicyDirectory
        (Get-Item -LiteralPath $script:CodexVendorDirectory).
            LastWriteTimeUtc = $vendorTimestamp
        $restored = $true
    }
    if (-not $restored) {
        throw 'Codex shared reparse fixture did not restore its real directory'
    }
    $afterRestore = Get-ProtectedUserTreeInventory `
        $script:CodexVendorDirectory `
        'Codex shared directory after reparse fixture restore'
    Assert-SameUserTreeInventory `
        $legitimate `
        $afterRestore `
        'Codex shared reparse fixture restoration'
    return 'preexisting Codex junction failed closed without following, removing, or changing its protected target; the real directory restored exactly'
}

function Get-CertificationLifecycleScopeSHA256 {
    $canonical = @(
        [IO.Path]::GetFullPath($script:InstallRoot).TrimEnd('\'),
        [IO.Path]::GetFullPath($script:StateRoot).TrimEnd('\'),
        $script:GatewayServiceName,
        $script:GuardianServiceName
    ) |
        ForEach-Object { ([string]$_).ToLowerInvariant() }
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        $scope = [BitConverter]::ToString(
            $algorithm.ComputeHash(
                [Text.Encoding]::UTF8.GetBytes(
                    $canonical -join ([char]0)
                )
            )
        ).Replace('-', '').ToLowerInvariant()
    } finally {
        $algorithm.Dispose()
    }
    return $scope
}

function Get-CertificationLifecycleReceiptPaths {
    $scope = Get-CertificationLifecycleScopeSHA256
    $lifecycleRoot = Assert-PathBelow `
        (Join-Path $script:KnownProgramData 'Cisco\DefenseClaw-Lifecycle') `
        $script:KnownProgramData `
        'certification lifecycle receipt directory'
    return [pscustomobject]@{
        lifecycle_root = $lifecycleRoot
        scope_sha256 = $scope
        purge_intent = Assert-PathBelow `
            (Join-Path $lifecycleRoot "purge-$scope.json") `
            $lifecycleRoot `
            'certification authenticated purge intent'
        self_uninstall_receipt = Assert-PathBelow `
            (Join-Path $lifecycleRoot "self-uninstall-$scope.json") `
            $lifecycleRoot `
            'certification self-uninstall receipt'
        self_uninstall_helper = Assert-PathBelow `
            (Join-Path $lifecycleRoot "self-uninstall-$scope.ps1") `
            $lifecycleRoot `
            'certification self-uninstall finalizer'
        self_uninstall_environment = Assert-PathBelow `
            (Join-Path $lifecycleRoot "self-uninstall-$scope.environment") `
            $lifecycleRoot `
            'certification self-uninstall environment root'
    }
}

function Get-CertificationUninstallSiblingSnapshot(
    [string]$ManagedRoot,
    [string]$RequiredBase,
    [string]$Label
) {
    $safe = Assert-PathBelow $ManagedRoot $RequiredBase $Label
    $parent = Split-Path -Parent $safe
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        return [pscustomobject]@{
            parent = $parent
            entries = @()
        }
    }
    $rows = [Collections.Generic.List[object]]::new()
    foreach ($item in @(
        Get-ChildItem -LiteralPath $parent -Force |
            Where-Object {
                -not [string]::Equals(
                    [string]$_.FullName,
                    $safe,
                    [StringComparison]::OrdinalIgnoreCase
                )
            } |
            Sort-Object Name
    )) {
        $acl = Get-Acl -LiteralPath $item.FullName
        $rows.Add([pscustomobject]@{
            name = [string]$item.Name
            path = [string]$item.FullName
            kind = if ($item.PSIsContainer) { 'directory' } else { 'file' }
            attributes = [int]$item.Attributes
            owner_sid = ConvertTo-CertificationSID $acl.Owner
            access_rules_protected = [bool]$acl.AreAccessRulesProtected
            sddl = $acl.GetSecurityDescriptorSddlForm(
                [Security.AccessControl.AccessControlSections]::All
            )
        })
    }
    return [pscustomobject]@{
        parent = $parent
        entries = @($rows.ToArray())
    }
}

function Get-CertificationRetirementArtifactObservation(
    [string]$Path,
    [string]$Label
) {
    if (-not (Test-Path -LiteralPath $Path)) {
        return [pscustomobject]@{
            path = $Path
            observed = $false
            disappeared_during_observation = $false
            owner_sid = ''
            access_rules_protected = $false
            attributes = 0
            secret_material_recorded = $false
        }
    }
    try {
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "$Label is a reparse point: $Path"
        }
        $security = Get-ManagedUserPathSecurityFingerprint $Path
        if ([string]$security.owner_sid -ne 'S-1-5-32-544' -or
            -not [bool]$security.access_rules_protected) {
            throw (
                "$Label is not Administrators-owned with a protected DACL: " +
                $Path
            )
        }
        foreach ($sid in @($script:PrimarySID, $script:HostileSID)) {
            Assert-NoStandardUserAccess `
                -Path $Path `
                -SID $sid `
                -DenyRead `
                -DenyWrite
        }
        return [pscustomobject]@{
            path = $Path
            observed = $true
            disappeared_during_observation = $false
            owner_sid = [string]$security.owner_sid
            access_rules_protected =
                [bool]$security.access_rules_protected
            attributes = [int]$item.Attributes
            secret_material_recorded = $false
        }
    } catch {
        if (-not (Test-Path -LiteralPath $Path)) {
            return [pscustomobject]@{
                path = $Path
                observed = $false
                disappeared_during_observation = $true
                owner_sid = ''
                access_rules_protected = $false
                attributes = 0
                secret_material_recorded = $false
            }
        }
        throw
    }
}

function Get-CertificationSelfUninstallEnvironmentObservation(
    [string]$Path,
    [string]$Label
) {
    $root = Assert-PathBelow `
        $Path `
        $script:LifecycleLockDirectory `
        "$Label exact lifecycle child"
    $rootObservation = Get-CertificationRetirementArtifactObservation `
        -Path $root `
        -Label $Label
    if (-not [bool]$rootObservation.observed) {
        throw "$Label disappeared while the locked-hook finalizer was pending"
    }
    $trustedInstallerSID = ConvertTo-CertificationSID `
        'NT SERVICE\TrustedInstaller'
    $allowedSIDs = @(
        'S-1-5-18',
        'S-1-5-32-544',
        $trustedInstallerSID
    )
    $objects = @(
        Get-Item -LiteralPath $root -Force -ErrorAction Stop
    ) + @(
        Get-ChildItem `
            -LiteralPath $root `
            -Recurse `
            -Force `
            -ErrorAction Stop
    )
    foreach ($item in $objects) {
        $fullPath = [IO.Path]::GetFullPath(
            [string]$item.FullName
        ).TrimEnd('\')
        if (-not [string]::Equals(
                $fullPath,
                $root,
                [StringComparison]::OrdinalIgnoreCase
            ) -and
            -not $fullPath.StartsWith(
                $root + '\',
                [StringComparison]::OrdinalIgnoreCase
            )) {
            throw "$Label object escaped its exact lifecycle root: $fullPath"
        }
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "$Label contains a reparse point: $fullPath"
        }
        $acl = Get-Acl -LiteralPath $fullPath -ErrorAction Stop
        $ownerSID = ConvertTo-CertificationSID $acl.Owner
        if ($ownerSID -notin $allowedSIDs) {
            throw "$Label object has an untrusted owner $ownerSID`: $fullPath"
        }
        $granted = @{}
        foreach ($rule in @($acl.Access)) {
            if ($rule.AccessControlType -ne
                [Security.AccessControl.AccessControlType]::Allow) {
                throw "$Label object has a non-canonical deny ACE: $fullPath"
            }
            $sid = ConvertTo-CertificationSID $rule.IdentityReference
            if ($sid -notin $allowedSIDs) {
                throw "$Label object grants an unexpected principal $sid`: $fullPath"
            }
            if (($rule.PropagationFlags -band
                [Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) {
                continue
            }
            $current = if ($granted.ContainsKey($sid)) {
                [Security.AccessControl.FileSystemRights]$granted[$sid]
            } else {
                [Security.AccessControl.FileSystemRights]0
            }
            $granted[$sid] = $current -bor $rule.FileSystemRights
        }
        foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
            $rights = if ($granted.ContainsKey($sid)) {
                [Security.AccessControl.FileSystemRights]$granted[$sid]
            } else {
                [Security.AccessControl.FileSystemRights]0
            }
            if (($rights -band
                [Security.AccessControl.FileSystemRights]::FullControl) -ne
                [Security.AccessControl.FileSystemRights]::FullControl) {
                throw "$Label object does not grant $sid FullControl: $fullPath"
            }
        }
        foreach ($sid in @($script:PrimarySID, $script:HostileSID)) {
            Assert-NoStandardUserAccess `
                -Path $fullPath `
                -SID $sid `
                -DenyRead `
                -DenyWrite
        }
    }
    return [pscustomobject]@{
        path = $root
        observed = $true
        exact_lifecycle_child = $true
        object_count = @($objects).Count
        administrators_system_only = $true
        no_reparse_points = $true
        standard_users_denied_read_write = $true
        secret_material_recorded = $false
    }
}

function Get-SelfUninstallFinalizerProcessObservation(
    [string]$HelperPath,
    [string]$Label
) {
    $helper = Assert-PathBelow `
        $HelperPath `
        $script:LifecycleLockDirectory `
        "$Label helper"
    $powerShell = Assert-PathBelow `
        (Join-Path $script:System32 'WindowsPowerShell\v1.0\powershell.exe') `
        $script:System32 `
        "$Label fixed PowerShell"
    $expectedCommandLine = (
        '"' + $powerShell + '" ' +
        '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass ' +
        '-File "' + $helper + '"'
    )
    $matches = @(
        Get-CimInstance Win32_Process `
            -Filter "Name='powershell.exe'" `
            -ErrorAction Stop |
            Where-Object {
                [string]::Equals(
                    [string]$_.ExecutablePath,
                    $powerShell,
                    [StringComparison]::OrdinalIgnoreCase
                ) -and
                [string]::Equals(
                    [string]$_.CommandLine,
                    $expectedCommandLine,
                    [StringComparison]::OrdinalIgnoreCase
                )
            }
    )
    if ($matches.Count -ne 1 -or [uint32]$matches[0].ProcessId -eq 0) {
        throw (
            "$Label expected exactly one live fixed-engine finalizer after " +
            "captured CLI EOF, found $($matches.Count)"
        )
    }
    $process = Get-Process `
        -Id ([int][uint32]$matches[0].ProcessId) `
        -ErrorAction Stop
    try {
        if ($process.HasExited) {
            throw "$Label finalizer exited before live process observation"
        }
        return [pscustomobject]@{
            pid = [uint32]$matches[0].ProcessId
            creation_filetime = [int64](
                $process.StartTime.ToUniversalTime().ToFileTimeUtc()
            )
            executable_path = $powerShell
            exact_command_line = $true
            captured_cli_returned = $true
            helper_remained_alive_after_capture = $true
            no_inherited_capture_handles = $true
            secret_material_recorded = $false
        }
    } finally {
        $process.Dispose()
    }
}

function Assert-EnterpriseMachinePolicyAbsent([string]$Label) {
    $codexPaths = @(
        $script:CodexRequirementsPath,
        $script:CodexManagedStatePath,
        $script:CodexMachineLockPath
    )
    $claudePaths = @(
        $script:ClaudeManagedPolicyPath,
        $script:ClaudeManagedStatePath,
        $script:ClaudeManagedLockPath
    )
    foreach ($path in @($codexPaths + $claudePaths)) {
        if (Test-Path -LiteralPath $path) {
            throw "$Label left an enterprise machine-hook policy artifact: $path"
        }
    }
    return [pscustomobject]@{
        label = $Label
        codex_owned_policy_absent = $true
        claude_owned_policy_absent = $true
        checked_path_count = @($codexPaths + $claudePaths).Count
        observed_before_fresh_client_start = $true
        secret_material_recorded = $false
    }
}

function Test-FreshClientsHaveNoEnterpriseHookAfterUninstall {
    $home = Assert-CertificationCodexHomePath $script:CertificationCodexHome
    if (Test-Path -LiteralPath $home) {
        throw "fresh post-uninstall client home unexpectedly exists: $home"
    }
    $snapshot = @(
        $script:UserTreeSnapshots.ToArray() |
            Where-Object {
                [string]::Equals(
                    [string]$_.path,
                    $home,
                    [StringComparison]::OrdinalIgnoreCase
                )
            }
    )
    if ($snapshot.Count -ne 1 -or [bool]$snapshot[0].inventory.existed) {
        throw (
            'fresh post-uninstall clients require the exact protected ' +
            'absent-baseline certification CODEX_HOME snapshot'
        )
    }
    $policyBefore = Assert-EnterpriseMachinePolicyAbsent `
        'before fresh post-uninstall client processes'
    $inputObject = [ordered]@{
        path = $home
        profile = $script:PrimaryProfile
        sid = $script:PrimarySID
        expected_name = ".codex-defenseclaw-cert-$($script:RunToken)"
    }
    $inputBase64 = [Convert]::ToBase64String(
        [Text.Encoding]::UTF8.GetBytes(
            ($inputObject | ConvertTo-Json -Compress)
        )
    )
    $scriptText = @'
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$inputObject = [Text.Encoding]::UTF8.GetString(
    [Convert]::FromBase64String('__INPUT__')
) | ConvertFrom-Json -ErrorAction Stop
$actualSID = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
if ($actualSID -ne [string]$inputObject.sid) {
    throw "fresh post-uninstall client SID mismatch: $actualSID"
}
$profile = [IO.Path]::GetFullPath([string]$inputObject.profile).TrimEnd('\')
$path = [IO.Path]::GetFullPath([string]$inputObject.path).TrimEnd('\')
$parent = [IO.Path]::GetFullPath(
    [IO.Path]::GetDirectoryName($path)
).TrimEnd('\')
if (-not $parent.Equals(
        $profile,
        [StringComparison]::OrdinalIgnoreCase
    ) -or
    [IO.Path]::GetFileName($path) -cne
        [string]$inputObject.expected_name) {
    throw "fresh post-uninstall client root is outside its exact allowlist: $path"
}
if (Test-Path -LiteralPath $path) {
    throw "fresh post-uninstall client root already exists: $path"
}
[IO.Directory]::CreateDirectory($path) | Out-Null
$item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
if (-not $item.PSIsContainer -or
    ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
    @(Get-ChildItem -LiteralPath $path -Force).Count -ne 0) {
    throw "fresh post-uninstall client root is not a new empty real directory: $path"
}
[pscustomobject]@{
    ok = $true
    sid = $actualSID
    path = $path
    empty = $true
} | ConvertTo-Json -Compress
'@.Replace('__INPUT__', $inputBase64)
    $creation = Invoke-ActiveUserPowerShell `
        -Script $scriptText `
        -Label 'create-fresh-post-uninstall-client-root' `
        -TimeoutSeconds 120
    $created = ConvertFrom-SingleJSONDocument `
        $creation.StdOut `
        'create fresh post-uninstall client root'
    if (-not [bool]$created.ok -or
        -not [bool]$created.empty -or
        [string]$created.sid -ne $script:PrimarySID -or
        -not [string]::Equals(
            [string]$created.path,
            $home,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw 'fresh post-uninstall client root creation returned inconsistent evidence'
    }
    $null = Assert-CertificationCodexHomePath $home -RequireExisting

    $codex = $null
    $claude = $null
    try {
        $codex = Invoke-ActualCodexCertificationRun `
            -Label 'fresh-post-uninstall-codex-no-enterprise-hook' `
            -BinaryPath $script:CodexRuntimeBinary `
            -ExpectedSHA256 ([string]$script:SourceDigests['codex']) `
            -BinaryRole stock `
            -ExpectFreshUnmanagedClient
        $null = Assert-EnterpriseMachinePolicyAbsent `
            'between fresh post-uninstall client processes'
        $claude = Invoke-ActualClaudeCertificationRun `
            -Label 'fresh-post-uninstall-claude-no-enterprise-hook' `
            -ExpectFreshUnmanagedClient
        $policyAfter = Assert-EnterpriseMachinePolicyAbsent `
            'after fresh post-uninstall client processes'
    } finally {
        Restore-ProtectedUserTreeSnapshot $snapshot[0]
    }
    $restored = Get-ProtectedUserTreeInventory `
        $home `
        'fresh post-uninstall client root after cleanup'
    Assert-SameUserTreeInventory `
        $snapshot[0].inventory `
        $restored `
        'fresh post-uninstall client root restoration'
    foreach ($protectedSnapshot in @($script:UserTreeSnapshots.ToArray())) {
        $current = Get-ProtectedUserTreeInventory `
            ([string]$protectedSnapshot.path) `
            "after fresh clients $($protectedSnapshot.name)"
        Assert-SameUserTreeInventory `
            $protectedSnapshot.inventory `
            $current `
            "fresh post-uninstall clients $($protectedSnapshot.name) isolation"
    }
    return [pscustomobject]@{
        detail = (
            'new stock Codex and Claude processes used fresh target-owned ' +
            'configuration, reached their loopback providers with exit zero, ' +
            'and had no enterprise hook after machine policy removal'
        )
        process_fresh = $true
        configuration_fresh = $true
        machine_policy_absent_before_start = $true
        enterprise_hook_configured = $false
        cached_enterprise_command_noop_asserted = $false
        cached_process_semantics_tested = $false
        codex = $codex
        claude = $claude
        policy_before = $policyBefore
        policy_after = $policyAfter
        protected_user_trees_restored = $true
        secret_material_recorded = $false
    }
}

function Test-CodexSharedDirectoriesPersistThroughPurge {
    $sections = (
        [Security.AccessControl.AccessControlSections]::Access -bor
        [Security.AccessControl.AccessControlSections]::Owner -bor
        [Security.AccessControl.AccessControlSections]::Group
    )
    $claudeSentinel = Assert-PathBelow `
        (Join-Path `
            $script:ClaudeManagedPolicyDirectory `
            "defenseclaw-cert-unrelated-$($script:RunToken).json") `
        $script:ClaudeManagedPolicyRoot `
        'unrelated Claude administrator policy sentinel'
    if (Test-Path -LiteralPath $claudeSentinel) {
        throw "Claude unrelated policy sentinel already exists: $claudeSentinel"
    }
    [IO.File]::WriteAllText(
        $claudeSentinel,
        "{`"unrelated_admin_policy`":true}`r`n",
        [Text.UTF8Encoding]::new($false)
    )
    Protect-AdministratorFile `
        $claudeSentinel `
        'protect-unrelated-claude-policy-sentinel'
    $claudeSentinelSHA256 = Get-FileDigest $claudeSentinel
    $claudeSentinelSDDL = (Get-Acl -LiteralPath $claudeSentinel).
        GetSecurityDescriptorSddlForm($sections)
    $before = $null
    if (-not $ClaudeOnly) {
        $before = @(
            $script:CodexVendorDirectory,
            $script:CodexMachinePolicyDirectory |
                ForEach-Object {
                    $item = Get-Item -LiteralPath $_ -Force
                    [pscustomobject]@{
                        path = [string]$item.FullName
                        attributes = [int]$item.Attributes
                        sddl = (Get-Acl -LiteralPath $item.FullName).
                            GetSecurityDescriptorSddlForm($sections)
                    }
                }
        )
    }
    $installedCLI = Assert-SourcePathHasNoReparse `
        (Assert-PathBelow `
            (Join-Path $script:InstallRoot 'bin\defenseclaw.exe') `
            $script:InstallRoot `
            'installed self-uninstall CLI') `
        'installed self-uninstall CLI'
    $installedHook = Assert-SourcePathHasNoReparse `
        (Assert-PathBelow `
            (Join-Path $script:InstallRoot 'bin\defenseclaw-hook.exe') `
            $script:InstallRoot `
            'installed self-uninstall no-delete handle target') `
        'installed self-uninstall no-delete handle target'
    $installedInstaller = Assert-SourcePathHasNoReparse `
        (Assert-PathBelow `
            (Join-Path $script:InstallRoot 'libexec\install-enterprise.ps1') `
            $script:InstallRoot `
            'installed self-uninstall installer') `
        'installed self-uninstall installer'
    $installedModule = Assert-SourcePathHasNoReparse `
        (Assert-PathBelow `
            (Join-Path $script:InstallRoot 'libexec\DefenseClawEnterprise.psm1') `
            $script:InstallRoot `
            'installed self-uninstall module') `
        'installed self-uninstall module'
    $installedCLIHash = Get-FileDigest $installedCLI
    if ($installedCLIHash -cne
            [string]$script:SourceDigests['upgrade_cli'] -or
        (Get-FileDigest $installedHook) -cne
            [string]$script:SourceDigests['upgrade_hook'] -or
        (Get-FileDigest $installedInstaller) -cne
            [string]$script:SourceDigests['installer'] -or
        (Get-FileDigest $installedModule) -cne
            [string]$script:SourceDigests['module']) {
        throw (
            'installed public Uninstall CLI/entrypoint/module bytes differ ' +
            'from the exact protected upgraded/staged sources'
        )
    }
    $lifecycleReceipts = Get-CertificationLifecycleReceiptPaths
    foreach ($receipt in @(
        $lifecycleReceipts.purge_intent,
        $lifecycleReceipts.self_uninstall_receipt,
        $lifecycleReceipts.self_uninstall_helper,
        $lifecycleReceipts.self_uninstall_environment
    )) {
        if (Test-Path -LiteralPath $receipt) {
            throw "self-Uninstall lifecycle artifact existed before Uninstall: $receipt"
        }
    }
    $lifecycleSiblingsBefore =
        Get-CertificationUninstallSiblingSnapshot `
            $lifecycleReceipts.self_uninstall_environment `
            $lifecycleReceipts.lifecycle_root `
            'pre-uninstall lifecycle siblings'
    $installSiblingsBefore = Get-CertificationUninstallSiblingSnapshot `
        $script:InstallRoot `
        $script:KnownProgramFiles `
        'pre-uninstall InstallRoot siblings'
    $stateSiblingsBefore = Get-CertificationUninstallSiblingSnapshot `
        $script:StateRoot `
        $script:KnownProgramData `
        'pre-uninstall StateRoot siblings'
    $retirementLocker = $null
    $retirementLockerReleased = $false
    $retirementLockerEvidence = $null
    try {
        $retirementLocker = Start-ActiveUserFileLockHolder `
            -Path $installedHook `
            -Label 'self-uninstall-standard-user-no-delete-handle' `
            -TimeoutSeconds 600
        $arguments = @(
            'enterprise', 'windows', 'uninstall',
            '--installer', $installedInstaller,
            '--gateway-service-name', $script:GatewayServiceName,
            '--guardian-service-name', $script:GuardianServiceName,
            '--install-root', $script:InstallRoot,
            '--state-root', $script:StateRoot,
            '--purge',
            '--json'
        )
        $uninstallEnvelope = Invoke-EnterpriseLifecycleCLIJSON `
            -FilePath $installedCLI `
            -Arguments $arguments `
            -Label 'installed-public-self-uninstall-purge'
        $uninstalled = $uninstallEnvelope.JSON
        $finalizerProcessObservation =
            Get-SelfUninstallFinalizerProcessObservation `
                -HelperPath $lifecycleReceipts.self_uninstall_helper `
                -Label 'installed public self-Uninstall captured CLI'
        $purgedProperty = $uninstalled.PSObject.Properties['purged']
        if ([int]$uninstalled.schema_version -ne 1 -or
            [string]$uninstalled.action -cne 'uninstall' -or
            -not [bool]$uninstalled.ok -or
            [bool]$uninstalled.installed -or
            [bool]$uninstalled.transaction_pending -or
            [string]$uninstalled.gateway_service_state -cne 'absent' -or
            [string]$uninstalled.guardian_service_state -cne 'absent' -or
            [bool]$uninstalled.gateway_ready -or
            [bool]$uninstalled.guardian_ready -or
            [bool]$uninstalled.core_hardening_complete -or
            [bool]$uninstalled.external_security_prerequisites_satisfied -or
            [bool]$uninstalled.security_complete -or
            -not [string]::IsNullOrWhiteSpace(
                [string]$uninstalled.guardian_generation
            ) -or
            [string]$uninstalled.gateway_service -cne
                $script:GatewayServiceName -or
            [string]$uninstalled.guardian_service -cne
                $script:GuardianServiceName -or
            -not [string]::Equals(
                [string]$uninstalled.install_root,
                $script:InstallRoot,
                [StringComparison]::OrdinalIgnoreCase
            ) -or
            -not [string]::Equals(
                [string]$uninstalled.state_root,
                $script:StateRoot,
                [StringComparison]::OrdinalIgnoreCase
            ) -or
            $null -eq $purgedProperty -or
            -not [bool]$purgedProperty.Value -or
            @($uninstalled.errors).Count -ne 0) {
            throw (
                'installed public self-Uninstall -Purge did not report the ' +
                'exact healthy absent deployment: ' +
                (Protect-SensitiveDisplayText (
                    $uninstalled | ConvertTo-Json -Compress -Depth 7
                ))
            )
        }
        $script:Installed = $false
        foreach ($serviceName in @(
            $script:GatewayServiceName,
            $script:GuardianServiceName
        )) {
            if ($null -ne (
                Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            )) {
                throw "installed public self-Uninstall left service $serviceName"
            }
        }
        foreach ($removedRoot in @(
            $script:InstallRoot,
            $script:StateRoot
        )) {
            if (Test-Path -LiteralPath $removedRoot) {
                throw (
                    'installed public self-Uninstall -Purge left managed root: ' +
                    $removedRoot
                )
            }
        }
        $machinePolicyAbsentBeforeFinalizerWait =
            Assert-EnterpriseMachinePolicyAbsent `
                'immediately after installed public self-Uninstall returned'
        $retirementReceipt = [string]$uninstalled.self_uninstall_receipt_path
        $environmentRoot = [string]$uninstalled.self_uninstall_environment_root
        $retiredInstallRoot = [string]$uninstalled.retired_install_root
        if (-not [bool]$uninstalled.cached_enterprise_clients_require_reload -or
            -not [bool]$uninstalled.self_uninstall_cleanup_pending -or
            -not [bool]$uninstalled.canonical_install_root_absent -or
            -not [string]::Equals(
                $retirementReceipt,
                [string]$lifecycleReceipts.self_uninstall_receipt,
                [StringComparison]::OrdinalIgnoreCase
            ) -or
            -not [string]::Equals(
                $environmentRoot,
                [string]$lifecycleReceipts.self_uninstall_environment,
                [StringComparison]::OrdinalIgnoreCase
            ) -or
            [string]::IsNullOrWhiteSpace($retiredInstallRoot) -or
            [string]::Equals(
                $retiredInstallRoot,
                $script:InstallRoot,
                [StringComparison]::OrdinalIgnoreCase
            ) -or
            -not [string]::Equals(
                (Split-Path -Parent $retiredInstallRoot),
                (Split-Path -Parent $script:InstallRoot),
                [StringComparison]::OrdinalIgnoreCase
            ) -or
            [IO.Path]::GetFileName($retiredInstallRoot) -cnotmatch (
                '^' +
                [Text.RegularExpressions.Regex]::Escape(
                    [IO.Path]::GetFileName($script:InstallRoot)
                ) +
                '\.retired-[0-9a-f]{32}$'
            )) {
            throw (
                'installed public self-Uninstall did not publish the exact ' +
                'bounded finalizer contract: ' +
                (Protect-SensitiveDisplayText (
                    $uninstalled | ConvertTo-Json -Compress -Depth 7
                ))
            )
        }
        $retiredInstallRoot = Assert-PathBelow `
            $retiredInstallRoot `
            (Split-Path -Parent $script:InstallRoot) `
            'retired self-uninstall InstallRoot'
        $environmentObservation =
            Get-CertificationSelfUninstallEnvironmentObservation `
                -Path $environmentRoot `
                -Label 'protected self-uninstall environment root'
        $retirementArtifacts = @(
            (Get-CertificationRetirementArtifactObservation `
                -Path $lifecycleReceipts.self_uninstall_receipt `
                -Label 'authenticated self-uninstall receipt')
            (Get-CertificationRetirementArtifactObservation `
                -Path $lifecycleReceipts.self_uninstall_helper `
                -Label 'protected self-uninstall finalizer')
            $environmentObservation
            (Get-CertificationRetirementArtifactObservation `
                -Path $retiredInstallRoot `
                -Label 'protected retired InstallRoot')
        )
        $retirement = [pscustomobject]@{
            artifacts = @($retirementArtifacts)
            live_artifact_count = @(
                $retirementArtifacts |
                    Where-Object { [bool]$_.observed }
            ).Count
            polls = 0
        }
        if ([int]$retirement.live_artifact_count -ne 4) {
            throw (
                'standard-user no-delete handle did not keep the exact ' +
                'authenticated self-uninstall receipt, helper, protected ' +
                'environment root, and retired InstallRoot pending after ' +
                'the public CLI exited'
            )
        }
        $retiredLockedHook = Assert-SourcePathHasNoReparse `
            (Assert-PathBelow `
                (Join-Path $retiredInstallRoot 'bin\defenseclaw-hook.exe') `
                $retiredInstallRoot `
                'retired no-delete handle target') `
            'retired no-delete handle target'
        if ((Get-FileDigest $retiredLockedHook) -cne
            [string]$script:SourceDigests['hook']) {
            throw (
                'standard-user no-delete handle did not remain bound to the ' +
                'exact approved hook bytes after canonical tree retirement'
            )
        }
        $retirementLockerEvidence =
            Stop-ActiveUserFileLockHolder $retirementLocker
        $retirementLockerReleased = $true
        $null = Wait-Until `
            -Description 'installed public self-Uninstall finalizer retirement' `
            -TimeoutSeconds 60 `
            -PollMilliseconds 50 `
            -Condition {
                $retirement.polls = [int]$retirement.polls + 1
                return (
                    -not (Test-Path -LiteralPath $retiredInstallRoot) -and
                    -not (Test-Path -LiteralPath (
                        [string]$lifecycleReceipts.self_uninstall_receipt
                    )) -and
                    -not (Test-Path -LiteralPath (
                        [string]$lifecycleReceipts.self_uninstall_helper
                    )) -and
                    -not (Test-Path -LiteralPath (
                        [string]$lifecycleReceipts.self_uninstall_environment
                    ))
                )
            }
        $null = Wait-Until `
            -Description 'installed public self-Uninstall finalizer process exit' `
            -TimeoutSeconds 10 `
            -PollMilliseconds 25 `
            -Condition {
                $current = Get-Process `
                    -Id ([int]$finalizerProcessObservation.pid) `
                    -ErrorAction SilentlyContinue
                if ($null -eq $current) {
                    return $true
                }
                try {
                    if ($current.HasExited) {
                        return $true
                    }
                    $creationFileTime = [int64](
                        $current.StartTime.ToUniversalTime().ToFileTimeUtc()
                    )
                    return (
                        $creationFileTime -ne
                            [int64]$finalizerProcessObservation.creation_filetime
                    )
                } catch [InvalidOperationException] {
                    return $true
                } finally {
                    $current.Dispose()
                }
            }
        Start-Sleep -Milliseconds 750
        foreach ($receipt in @(
            $lifecycleReceipts.purge_intent,
            $lifecycleReceipts.self_uninstall_receipt,
            $lifecycleReceipts.self_uninstall_helper,
            $lifecycleReceipts.self_uninstall_environment,
            $retiredInstallRoot
        )) {
            if (Test-Path -LiteralPath $receipt) {
                throw (
                    'installed public self-Uninstall leaked a protected ' +
                    "retirement artifact: $receipt"
                )
            }
        }
        $lifecycleSiblingsAfter =
            Get-CertificationUninstallSiblingSnapshot `
                $lifecycleReceipts.self_uninstall_environment `
                $lifecycleReceipts.lifecycle_root `
                'post-uninstall lifecycle siblings'
        Assert-SameObjectJSON `
            $lifecycleSiblingsBefore `
            $lifecycleSiblingsAfter `
            'installed public self-Uninstall lifecycle sibling artifacts'
        $installSiblingsAfter = Get-CertificationUninstallSiblingSnapshot `
            $script:InstallRoot `
            $script:KnownProgramFiles `
            'post-uninstall InstallRoot siblings'
        $stateSiblingsAfter = Get-CertificationUninstallSiblingSnapshot `
            $script:StateRoot `
            $script:KnownProgramData `
            'post-uninstall StateRoot siblings'
        Assert-SameObjectJSON `
            $installSiblingsBefore `
            $installSiblingsAfter `
            'installed public self-Uninstall InstallRoot sibling tombstones'
        Assert-SameObjectJSON `
            $stateSiblingsBefore `
            $stateSiblingsAfter `
            'installed public self-Uninstall StateRoot sibling tombstones'
        foreach ($snapshot in @($script:UserTreeSnapshots.ToArray())) {
            $current = Get-ProtectedUserTreeInventory `
                ([string]$snapshot.path) `
                "post-uninstall $($snapshot.name)"
            Assert-SameUserTreeInventory `
                $snapshot.inventory `
                $current `
                "installed public self-Uninstall $($snapshot.name) restoration"
        }
        foreach ($owned in @(
            $script:ClaudeManagedPolicyPath,
            $script:ClaudeManagedStatePath
        )) {
            if (Test-Path -LiteralPath $owned) {
                throw "Uninstall -Purge left DefenseClaw-owned Claude policy: $owned"
            }
        }
        if (-not (Test-Path -LiteralPath $claudeSentinel -PathType Leaf) -or
            (Get-FileDigest $claudeSentinel) -cne $claudeSentinelSHA256 -or
            (Get-Acl -LiteralPath $claudeSentinel).
                GetSecurityDescriptorSddlForm($sections) -cne
                $claudeSentinelSDDL) {
            throw (
                'Uninstall -Purge removed or changed unrelated administrator ' +
                'Claude policy content/security'
            )
        }
        $freshClients = Test-FreshClientsHaveNoEnterpriseHookAfterUninstall
        if ($ClaudeOnly) {
            return [pscustomobject]@{
                detail = (
                    'installed public self-Uninstall -Purge removed only ' +
                    'DefenseClaw-owned Claude policy/state, restored both ' +
                    'target-user trees exactly, and preserved unrelated ' +
                    'administrator policy'
                )
                installed_cli_sha256 = $installedCLIHash
                purge_intent_retired = $true
                self_uninstall_finalizer_retired = $true
                self_uninstall_retirement = $retirement
                standard_user_no_delete_retirement_lock =
                    $retirementLockerEvidence
                retirement_pending_until_handle_release = $true
                finalizer_completed_after_handle_release = $true
                finalizer_process_after_captured_cli_return =
                    $finalizerProcessObservation
                no_inherited_finalizer_capture_handles = $true
                protected_finalizer_environment = $environmentObservation
                finalizer_environment_retired_without_recreation = $true
                finalizer_process_exited_before_recreation_recheck = $true
                lifecycle_sibling_artifacts_absent = $true
                install_and_state_roots_absent = $true
                sibling_tombstones_absent = $true
                protected_user_trees_restored = $true
                machine_policies_absent_before_finalizer_wait = $true
                machine_policy_removal =
                    $machinePolicyAbsentBeforeFinalizerWait
                fresh_clients_no_enterprise_hook = $freshClients
                cached_enterprise_clients_require_reload = $true
                cached_enterprise_command_noop_asserted = $false
                elevated_powershell_temp_boundary =
                    $uninstallEnvelope.TempBoundary
                result = $uninstalled
            }
        }
        foreach ($owned in @(
            $script:CodexRequirementsPath,
            $script:CodexManagedStatePath
        )) {
            if (Test-Path -LiteralPath $owned) {
                throw "Uninstall -Purge left DefenseClaw-owned Codex policy: $owned"
            }
        }
        $after = @(
            $script:CodexVendorDirectory,
            $script:CodexMachinePolicyDirectory |
                ForEach-Object {
                    $item = Get-Item -LiteralPath $_ -Force
                    [pscustomobject]@{
                        path = [string]$item.FullName
                        attributes = [int]$item.Attributes
                        sddl = (Get-Acl -LiteralPath $item.FullName).
                            GetSecurityDescriptorSddlForm($sections)
                    }
                }
        )
        Assert-SameUserTreeInventory `
            $before `
            $after `
            'enterprise purge shared Codex parent identity/security'
        $null = Assert-CodexMachinePolicyParentContract
        if (@(
            Get-ChildItem -LiteralPath $script:CodexMachinePolicyDirectory -Force
        ).Count -ne 0) {
            throw 'Uninstall -Purge left unexpected content in the shared Codex parent'
        }
        return [pscustomobject]@{
            detail = (
                'installed public self-Uninstall -Purge removed ' +
                'DefenseClaw-owned Codex and Claude policy/state, restored ' +
                'both target-user trees exactly, and preserved both shared ' +
                'parents plus unrelated policy'
            )
            installed_cli_sha256 = $installedCLIHash
            purge_intent_retired = $true
            self_uninstall_finalizer_retired = $true
            self_uninstall_retirement = $retirement
            standard_user_no_delete_retirement_lock =
                $retirementLockerEvidence
            retirement_pending_until_handle_release = $true
            finalizer_completed_after_handle_release = $true
            finalizer_process_after_captured_cli_return =
                $finalizerProcessObservation
            no_inherited_finalizer_capture_handles = $true
            protected_finalizer_environment = $environmentObservation
            finalizer_environment_retired_without_recreation = $true
            finalizer_process_exited_before_recreation_recheck = $true
            lifecycle_sibling_artifacts_absent = $true
            install_and_state_roots_absent = $true
            sibling_tombstones_absent = $true
            protected_user_trees_restored = $true
            machine_policies_absent_before_finalizer_wait = $true
            machine_policy_removal =
                $machinePolicyAbsentBeforeFinalizerWait
            fresh_clients_no_enterprise_hook = $freshClients
            cached_enterprise_clients_require_reload = $true
            cached_enterprise_command_noop_asserted = $false
            elevated_powershell_temp_boundary =
                $uninstallEnvelope.TempBoundary
            result = $uninstalled
        }
    } finally {
        if ($null -ne $retirementLocker -and
            -not $retirementLockerReleased) {
            $null = Stop-ActiveUserFileLockHolder $retirementLocker
            $retirementLockerReleased = $true
        }
        if (Test-Path -LiteralPath $claudeSentinel -PathType Leaf) {
            Remove-Item -LiteralPath $claudeSentinel -Force
        }
    }
}

function Restore-CodexSharedDirectoryFixture {
    if (-not $script:CodexSharedOwnedByHarness) {
        return
    }
    if (-not (Test-Path -LiteralPath $script:CodexVendorDirectory)) {
        if (Test-Path -LiteralPath $script:CodexMachinePolicyDirectory) {
            throw 'Codex shared cleanup found policy directory without its vendor parent'
        }
        $script:CodexSharedOwnedByHarness = $false
        return
    }
    $null = Assert-CodexMachinePolicyParentContract
    if ($null -ne $script:CodexSharedExpectedBeforeCleanup) {
        $current = Get-ProtectedUserTreeInventory `
            $script:CodexVendorDirectory `
            'Codex shared directory before final fixture cleanup'
        Assert-SameUserTreeInventory `
            $script:CodexSharedExpectedBeforeCleanup `
            $current `
            'Codex shared directory before final fixture cleanup'
    }
    $vendorChildren = @(
        Get-ChildItem -LiteralPath $script:CodexVendorDirectory -Force
    )
    if ($vendorChildren.Count -ne 1 -or
        -not [string]::Equals(
            [string]$vendorChildren[0].FullName,
            $script:CodexMachinePolicyDirectory,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw 'refusing shared-directory cleanup because OpenAI contains non-certification content'
    }
    if (@(
        Get-ChildItem -LiteralPath $script:CodexMachinePolicyDirectory -Force
    ).Count -ne 0) {
        throw 'refusing shared-directory cleanup because Codex is not empty'
    }
    Remove-Item -LiteralPath $script:CodexMachinePolicyDirectory -Force
    if (@(
        Get-ChildItem -LiteralPath $script:CodexVendorDirectory -Force
    ).Count -ne 0) {
        throw 'refusing shared-directory cleanup because OpenAI became non-empty'
    }
    Remove-Item -LiteralPath $script:CodexVendorDirectory -Force
    foreach ($path in @(
        $script:CodexVendorDirectory,
        $script:CodexMachinePolicyDirectory
    )) {
        if (Test-Path -LiteralPath $path) {
            throw "Codex shared fixture cleanup left path behind: $path"
        }
    }
    $script:CodexSharedOwnedByHarness = $false
}

function Get-CertificationLifecycleScopeArguments(
    [string]$Action,
    [bool]$UnsignedCertification,
    [bool]$CoreHardeningCertification
) {
    $arguments = [Collections.Generic.List[string]]::new()
    if ($Action -notin @('Install', 'Upgrade', 'Repair')) {
        return $arguments.ToArray()
    }
    if ($CoreHardeningCertification -and -not $UnsignedCertification) {
        throw (
            'internal certification scope error: core hardening requires ' +
            'unsigned certification'
        )
    }
    if (-not $UnsignedCertification) {
        return $arguments.ToArray()
    }
    if (-not $script:CertificationCodexHomeInitialized) {
        throw (
            'unsigned mutating lifecycle scope requires the exact initialized ' +
            'certification CODEX_HOME'
        )
    }
    Assert-CertificationScope
    $arguments.Add('-CertificationCodexHome')
    $arguments.Add($script:CertificationCodexHome)
    $arguments.Add('-AllowUnsigned')
    if ($CoreHardeningCertification) {
        $arguments.Add('-CoreHardeningCertification')
    }
    return $arguments.ToArray()
}

function Get-InstallerArguments(
    [string]$Action,
    [string]$GatewaySource,
    [string]$HookSource,
    [string]$CLISource,
    [string]$ConfigSource,
    [string]$ManifestSource,
    [switch]$NoStart,
    [switch]$Purge,
    [switch]$Json
) {
    $arguments = [Collections.Generic.List[string]]::new()
    foreach ($value in @(
        '-NoLogo',
        '-NoProfile',
        '-NonInteractive',
        '-File', $script:Installer,
        '-Action', $Action,
        '-GatewayServiceName', $script:GatewayServiceName,
        '-GuardianServiceName', $script:GuardianServiceName,
        '-InstallRoot', $script:InstallRoot,
        '-StateRoot', $script:StateRoot
    )) {
        $arguments.Add([string]$value)
    }
    if (-not [string]::IsNullOrWhiteSpace($GatewaySource)) {
        $arguments.Add('-GatewayBinary')
        $arguments.Add((ConvertTo-CanonicalPath $GatewaySource))
    }
    if (-not [string]::IsNullOrWhiteSpace($HookSource)) {
        $arguments.Add('-HookBinary')
        $arguments.Add((ConvertTo-CanonicalPath $HookSource))
    }
    if (-not [string]::IsNullOrWhiteSpace($CLISource)) {
        $arguments.Add('-CLIBinary')
        $arguments.Add((ConvertTo-CanonicalPath $CLISource))
    }
    if ($Action -in @('Install', 'Upgrade', 'Repair')) {
        $arguments.Add('-Config')
        $arguments.Add((ConvertTo-CanonicalPath $ConfigSource))
        $arguments.Add('-Manifest')
        $arguments.Add((ConvertTo-CanonicalPath $ManifestSource))
    }
    if ($NoStart) { $arguments.Add('-NoStart') }
    if ($Purge) { $arguments.Add('-Purge') }
    foreach ($scopeArgument in @(
        Get-CertificationLifecycleScopeArguments `
            -Action $Action `
            -UnsignedCertification ([bool]$AllowUnsigned) `
            -CoreHardeningCertification (
                [bool]($AllowUnsigned -and $ClaudeOnly)
            )
    )) {
        $arguments.Add([string]$scopeArgument)
    }
    if ($AttestAgentApplicationControl -and
        $Action -in @('Install', 'Upgrade', 'Repair')) {
        $arguments.Add('-AttestAgentApplicationControl')
    }
    if ($AttestCodexTrustedHookLauncher -and
        $Action -in @('Install', 'Upgrade', 'Repair')) {
        if ([string]::IsNullOrWhiteSpace(
                $script:CodexTrustedHookLauncherRuntimeBinary
            ) -or
            -not (Test-Path `
                -LiteralPath $script:CodexTrustedHookLauncherRuntimeBinary `
                -PathType Leaf)) {
            throw (
                'full Codex lifecycle attestation requires the protected ' +
                'staged trusted hook launcher artifact'
            )
        }
        $arguments.Add('-AttestCodexTrustedHookLauncher')
        $arguments.Add('-CodexTrustedHookLauncherBinary')
        $arguments.Add($script:CodexTrustedHookLauncherRuntimeBinary)
    }
    if ($script:ClaudeEffectivePolicyAttested -and
        $Action -eq 'Repair') {
        if ($ClaudeOnly) {
            throw (
                'Claude-only/core mode must never persist a production ' +
                'Claude effective-policy attestation'
            )
        }
        $arguments.Add('-AttestClaudeEffectivePolicy')
    }
    if ($Json) { $arguments.Add('-Json') }
    return $arguments.ToArray()
}

function Get-EnterpriseLifecycleCLIArguments(
    [ValidateSet(
        'Install',
        'Upgrade',
        'Repair',
        'Reconcile',
        'Status',
        'Verify',
        'Uninstall'
    )]
    [string]$Action,
    [string]$InstallerPath,
    [string]$GatewaySource = '',
    [string]$HookSource = '',
    [string]$CLISource = '',
    [string]$ConfigSource = '',
    [string]$ManifestSource = '',
    [switch]$NoStart,
    [switch]$Purge
) {
    $arguments = [Collections.Generic.List[string]]::new()
    foreach ($value in @(
        'enterprise',
        'windows',
        $Action.ToLowerInvariant(),
        '--installer',
        (ConvertTo-CanonicalPath $InstallerPath),
        '--gateway-service-name',
        $script:GatewayServiceName,
        '--guardian-service-name',
        $script:GuardianServiceName,
        '--install-root',
        $script:InstallRoot,
        '--state-root',
        $script:StateRoot
    )) {
        $arguments.Add([string]$value)
    }
    foreach ($source in @(
        @('--gateway-binary', $GatewaySource),
        @('--hook-binary', $HookSource),
        @('--cli-binary', $CLISource)
    )) {
        if (-not [string]::IsNullOrWhiteSpace([string]$source[1])) {
            $arguments.Add([string]$source[0])
            $arguments.Add((ConvertTo-CanonicalPath ([string]$source[1])))
        }
    }
    $mutation = $Action -in @('Install', 'Upgrade', 'Repair')
    if ($mutation) {
        foreach ($source in @(
            @('--config', $ConfigSource),
            @('--manifest', $ManifestSource)
        )) {
            if ([string]::IsNullOrWhiteSpace([string]$source[1])) {
                throw "public $Action requires $($source[0])"
            }
            $arguments.Add([string]$source[0])
            $arguments.Add((ConvertTo-CanonicalPath ([string]$source[1])))
        }
    }
    if ($NoStart) {
        $arguments.Add('--no-start')
    }
    if ($Purge) {
        $arguments.Add('--purge')
    }
    if ($AllowUnsigned -and $mutation) {
        Assert-CertificationScope
        if (-not $script:CertificationCodexHomeInitialized) {
            throw (
                "unsigned public $Action requires the exact initialized " +
                'certification CODEX_HOME scope'
            )
        }
        $arguments.Add('--certification-codex-home')
        $arguments.Add($script:CertificationCodexHome)
        $arguments.Add('--allow-unsigned')
        if ($ClaudeOnly) {
            $arguments.Add('--core-hardening-certification')
        }
    }
    if ($AttestAgentApplicationControl -and $mutation) {
        $arguments.Add('--attest-agent-application-control')
    }
    if ($AttestCodexTrustedHookLauncher -and $mutation) {
        if ([string]::IsNullOrWhiteSpace(
                $script:CodexTrustedHookLauncherRuntimeBinary
            )) {
            throw (
                "public $Action requires the protected trusted Codex " +
                'hook-launcher artifact'
            )
        }
        $arguments.Add('--attest-codex-trusted-hook-launcher')
        $arguments.Add('--codex-trusted-hook-launcher-binary')
        $arguments.Add($script:CodexTrustedHookLauncherRuntimeBinary)
    }
    if ($script:ClaudeEffectivePolicyAttested -and $Action -eq 'Repair') {
        if ($ClaudeOnly) {
            throw (
                'Claude-only/core mode cannot persist a production Claude ' +
                'effective-policy attestation'
            )
        }
        $arguments.Add('--attest-claude-effective-policy')
    }
    $arguments.Add('--json')
    return $arguments.ToArray()
}

function Test-AllowUnsignedHarnessContract {
    Assert-CertificationScope
    $installArguments = @(
        Get-InstallerArguments `
            -Action Install `
            -GatewaySource $script:GatewaySource `
            -HookSource $script:HookSource `
            -CLISource $script:CLISource `
            -ConfigSource $script:ConfigSource `
            -ManifestSource $script:ManifestSource
    )
    $verifyArguments = @(
        Get-InstallerArguments `
            -Action Verify `
            -GatewaySource '' `
            -HookSource '' `
            -CLISource '' `
            -ConfigSource '' `
            -ManifestSource ''
    )
    $installUnsignedCount = @(
        $installArguments | Where-Object { $_ -ceq '-AllowUnsigned' }
    ).Count
    $verifyUnsignedCount = @(
        $verifyArguments | Where-Object { $_ -ceq '-AllowUnsigned' }
    ).Count
    $installAttestationCount = @(
        $installArguments |
            Where-Object { $_ -ceq '-AttestAgentApplicationControl' }
    ).Count
    $verifyAttestationCount = @(
        $verifyArguments |
            Where-Object { $_ -ceq '-AttestAgentApplicationControl' }
    ).Count
    $installLauncherAttestationCount = @(
        $installArguments |
            Where-Object { $_ -ceq '-AttestCodexTrustedHookLauncher' }
    ).Count
    $verifyLauncherAttestationCount = @(
        $verifyArguments |
            Where-Object { $_ -ceq '-AttestCodexTrustedHookLauncher' }
    ).Count
    $installLauncherBinaryCount = @(
        $installArguments |
            Where-Object { $_ -ceq '-CodexTrustedHookLauncherBinary' }
    ).Count
    $verifyLauncherBinaryCount = @(
        $verifyArguments |
            Where-Object { $_ -ceq '-CodexTrustedHookLauncherBinary' }
    ).Count
    $installCertificationHomeCount = @(
        $installArguments |
            Where-Object { $_ -ceq '-CertificationCodexHome' }
    ).Count
    $verifyCertificationHomeCount = @(
        $verifyArguments |
            Where-Object { $_ -ceq '-CertificationCodexHome' }
    ).Count
    $installClaudeAttestationCount = @(
        $installArguments |
            Where-Object { $_ -ceq '-AttestClaudeEffectivePolicy' }
    ).Count
    $verifyClaudeAttestationCount = @(
        $verifyArguments |
            Where-Object { $_ -ceq '-AttestClaudeEffectivePolicy' }
    ).Count
    $installCoreCertificationCount = @(
        $installArguments |
            Where-Object { $_ -ceq '-CoreHardeningCertification' }
    ).Count
    $verifyCoreCertificationCount = @(
        $verifyArguments |
            Where-Object { $_ -ceq '-CoreHardeningCertification' }
    ).Count
    $expectedInstallUnsigned = if ($AllowUnsigned) { 1 } else { 0 }
    if ($installUnsignedCount -ne $expectedInstallUnsigned -or
        $verifyUnsignedCount -ne 0) {
        throw (
            'harness unsigned argument contract is unsafe: ' +
            "install=$installUnsignedCount verify=$verifyUnsignedCount " +
            "requested=$([bool]$AllowUnsigned)"
        )
    }
    $expectedInstallAttestation = if (
        $AttestAgentApplicationControl
    ) { 1 } else { 0 }
    if ($installAttestationCount -ne $expectedInstallAttestation -or
        $verifyAttestationCount -ne 0) {
        throw (
            'harness application-control attestation argument contract is unsafe: ' +
            "install=$installAttestationCount verify=$verifyAttestationCount " +
            "requested=$([bool]$AttestAgentApplicationControl)"
        )
    }
    $expectedLauncherAttestation = if (
        $AttestCodexTrustedHookLauncher
    ) { 1 } else { 0 }
    if ($installLauncherAttestationCount -ne
            $expectedLauncherAttestation -or
        $verifyLauncherAttestationCount -ne 0) {
        throw (
            'harness Codex trusted-hook-launcher attestation argument ' +
            "contract is unsafe: install=$installLauncherAttestationCount " +
            "verify=$verifyLauncherAttestationCount " +
            "requested=$([bool]$AttestCodexTrustedHookLauncher)"
        )
    }
    if ($installLauncherBinaryCount -ne
            $expectedLauncherAttestation -or
        $verifyLauncherBinaryCount -ne 0) {
        throw (
            'harness did not pair the protected Codex launcher artifact only ' +
            'with mutating full-certification actions: ' +
            "install=$installLauncherBinaryCount " +
            "verify=$verifyLauncherBinaryCount " +
            "requested=$([bool]$AttestCodexTrustedHookLauncher)"
        )
    }
    $expectedCertificationHomeCount = if ($AllowUnsigned) { 1 } else { 0 }
    if ($installCertificationHomeCount -ne
            $expectedCertificationHomeCount -or
        $verifyCertificationHomeCount -ne 0) {
        throw (
            'CertificationCodexHome must accompany only unsigned mutating ' +
            'certification transactions in full and Claude-only modes; signed ' +
            "production and read-only actions must omit it: install=$installCertificationHomeCount " +
            "verify=$verifyCertificationHomeCount " +
            "allow_unsigned=$([bool]$AllowUnsigned)"
        )
    }
    if ($installClaudeAttestationCount -ne 0 -or
        $verifyClaudeAttestationCount -ne 0) {
        throw (
            'initial Install/Verify must not emit ' +
            '-AttestClaudeEffectivePolicy before live hostile-precedence proof'
        )
    }
    $expectedCoreCertificationCount = if (
        $AllowUnsigned -and $ClaudeOnly
    ) { 1 } else { 0 }
    if ($installCoreCertificationCount -ne
            $expectedCoreCertificationCount -or
        $verifyCoreCertificationCount -ne 0) {
        throw (
            'CoreHardeningCertification must accompany only unsigned ' +
            'Claude-only mutating certification actions; full unsigned, ' +
            'signed production, and read-only actions must omit it: ' +
            "install=$installCoreCertificationCount " +
            "verify=$verifyCoreCertificationCount " +
            "allow_unsigned=$([bool]$AllowUnsigned) " +
            "claude_only=$([bool]$ClaudeOnly)"
        )
    }

    $scopeMatrix = [ordered]@{}
    foreach ($case in @(
        [pscustomobject]@{
            name = 'full_unsigned'
            action = 'Install'
            allow_unsigned = $true
            core_hardening = $false
            home_count = 1
            unsigned_count = 1
            core_count = 0
        },
        [pscustomobject]@{
            name = 'claude_only_unsigned'
            action = 'Install'
            allow_unsigned = $true
            core_hardening = $true
            home_count = 1
            unsigned_count = 1
            core_count = 1
        },
        [pscustomobject]@{
            name = 'signed_production'
            action = 'Install'
            allow_unsigned = $false
            core_hardening = $false
            home_count = 0
            unsigned_count = 0
            core_count = 0
        },
        [pscustomobject]@{
            name = 'read_only'
            action = 'Verify'
            allow_unsigned = $true
            core_hardening = $true
            home_count = 0
            unsigned_count = 0
            core_count = 0
        }
    )) {
        $caseArguments = @(
            Get-CertificationLifecycleScopeArguments `
                -Action ([string]$case.action) `
                -UnsignedCertification ([bool]$case.allow_unsigned) `
                -CoreHardeningCertification ([bool]$case.core_hardening)
        )
        $homeCount = @(
            $caseArguments |
                Where-Object { $_ -ceq '-CertificationCodexHome' }
        ).Count
        $unsignedCount = @(
            $caseArguments |
                Where-Object { $_ -ceq '-AllowUnsigned' }
        ).Count
        $coreCount = @(
            $caseArguments |
                Where-Object { $_ -ceq '-CoreHardeningCertification' }
        ).Count
        if ($homeCount -ne [int]$case.home_count -or
            $unsignedCount -ne [int]$case.unsigned_count -or
            $coreCount -ne [int]$case.core_count) {
            throw (
                "lifecycle scope matrix case $($case.name) failed: " +
                "home=$homeCount unsigned=$unsignedCount core=$coreCount"
            )
        }
        $scopeMatrix[[string]$case.name] = [pscustomobject]@{
            action = ([string]$case.action).ToLowerInvariant()
            certification_codex_home = $homeCount -eq 1
            allow_unsigned = $unsignedCount -eq 1
            core_hardening_certification = $coreCount -eq 1
        }
    }

    $saved = [ordered]@{
        gateway = $script:GatewayServiceName
        guardian = $script:GuardianServiceName
        install = $script:InstallRoot
        state = $script:StateRoot
        codex_home = $script:CertificationCodexHome
    }
    $otherLast = if ($script:RunToken.EndsWith('0')) { '1' } else { '0' }
    $otherToken = $script:RunToken.Substring(0, 9) + $otherLast
    $negativeCases = @(
        [pscustomobject]@{
            name = 'production-defaults'
            gateway = 'DefenseClawGateway'
            guardian = 'DefenseClawHookGuardian'
            install = Join-Path $script:KnownProgramFiles 'Cisco\DefenseClaw'
            state = Join-Path $script:KnownProgramData 'Cisco\DefenseClaw'
            codex_home = [string]$saved.codex_home
        },
        [pscustomobject]@{
            name = 'mismatched-service-run-id'
            gateway = [string]$saved.gateway
            guardian = "DefenseClawCertGuardian_$otherToken"
            install = [string]$saved.install
            state = [string]$saved.state
            codex_home = [string]$saved.codex_home
        },
        [pscustomobject]@{
            name = 'case-near-miss-service-name'
            gateway = "defenseClawCertGateway_$($script:RunToken)"
            guardian = [string]$saved.guardian
            install = [string]$saved.install
            state = [string]$saved.state
            codex_home = [string]$saved.codex_home
        },
        [pscustomobject]@{
            name = 'near-miss-install-root'
            gateway = [string]$saved.gateway
            guardian = [string]$saved.guardian
            install = Join-Path `
                $script:ProgramFilesCertificationRoot `
                ($script:RunToken + '-near')
            state = [string]$saved.state
            codex_home = [string]$saved.codex_home
        },
        [pscustomobject]@{
            name = 'nested-state-root'
            gateway = [string]$saved.gateway
            guardian = [string]$saved.guardian
            install = [string]$saved.install
            state = Join-Path ([string]$saved.state) 'nested'
            codex_home = [string]$saved.codex_home
        },
        [pscustomobject]@{
            name = 'mismatched-codex-home-run-id'
            gateway = [string]$saved.gateway
            guardian = [string]$saved.guardian
            install = [string]$saved.install
            state = [string]$saved.state
            codex_home = Join-Path `
                $script:PrimaryProfile `
                ".codex-defenseclaw-cert-$otherToken"
        }
    )
    $rejections = [Collections.Generic.List[object]]::new()
    try {
        foreach ($case in $negativeCases) {
            $script:GatewayServiceName = [string]$case.gateway
            $script:GuardianServiceName = [string]$case.guardian
            $script:InstallRoot = ConvertTo-CanonicalPath ([string]$case.install)
            $script:StateRoot = ConvertTo-CanonicalPath ([string]$case.state)
            $script:CertificationCodexHome = ConvertTo-CanonicalPath (
                [string]$case.codex_home
            )
            $rejected = $false
            $message = ''
            try {
                Assert-CertificationScope
            } catch {
                $rejected = $true
                $message = Protect-SensitiveDisplayText $_.Exception.Message
            }
            if (-not $rejected) {
                throw "certification scope accepted forbidden case: $($case.name)"
            }
            $rejections.Add([pscustomobject]@{
                case = [string]$case.name
                rejected = $true
                detail = $message
            })
        }
    } finally {
        $script:GatewayServiceName = [string]$saved.gateway
        $script:GuardianServiceName = [string]$saved.guardian
        $script:InstallRoot = [string]$saved.install
        $script:StateRoot = [string]$saved.state
        $script:CertificationCodexHome = [string]$saved.codex_home
        Assert-CertificationScope
    }
    return [pscustomobject]@{
        allow_unsigned_requested = [bool]$AllowUnsigned
        exact_positive_scope = $true
        install_allow_unsigned_count = $installUnsignedCount
        non_mutating_allow_unsigned_count = $verifyUnsignedCount
        application_control_attestation_requested = [bool]$AttestAgentApplicationControl
        install_application_control_attestation_count = $installAttestationCount
        non_mutating_application_control_attestation_count = $verifyAttestationCount
        codex_trusted_hook_launcher_attestation_requested =
            [bool]$AttestCodexTrustedHookLauncher
        install_codex_trusted_hook_launcher_attestation_count =
            $installLauncherAttestationCount
        non_mutating_codex_trusted_hook_launcher_attestation_count =
            $verifyLauncherAttestationCount
        install_codex_trusted_hook_launcher_binary_count =
            $installLauncherBinaryCount
        non_mutating_codex_trusted_hook_launcher_binary_count =
            $verifyLauncherBinaryCount
        install_certification_codex_home_count =
            $installCertificationHomeCount
        non_mutating_certification_codex_home_count =
            $verifyCertificationHomeCount
        install_core_hardening_certification_count =
            $installCoreCertificationCount
        non_mutating_core_hardening_certification_count =
            $verifyCoreCertificationCount
        lifecycle_scope_matrix = [pscustomobject]$scopeMatrix
        negative_rejections = @($rejections.ToArray())
    }
}

function Get-CertificationCodexEnvironment {
    # The lifecycle process is deliberately CODEX_HOME-independent. The
    # certification home is an unsigned-scope marker and is passed only to the
    # disposable actual Codex child process later in the run.
    return @{ CODEX_HOME = $null }
}

function Invoke-EnterpriseInstaller {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Install', 'Upgrade', 'Repair', 'Reconcile', 'Status', 'Verify', 'Uninstall')]
        [string]$Action,

        [string]$GatewaySource = $script:GatewaySource,
        [string]$HookSource = $script:HookSource,
        [string]$CLISource = $script:CLISource,
        [string]$ConfigSource = $script:ConfigSource,
        [string]$ManifestSource = $script:ManifestSource,
        [int[]]$AllowedExitCodes = @(0),
        [switch]$NoStart,
        [switch]$Purge,
        [switch]$Json,
        [scriptblock]$DuringExecution = $null,
        [ValidateRange(10, 1000)]
        [int]$ExecutionPollMilliseconds = 25,
        [string]$Label = ''
    )
    if ([string]::IsNullOrWhiteSpace($Label)) {
        $Label = 'installer-' + $Action.ToLowerInvariant()
    }
    $arguments = Get-InstallerArguments `
        -Action $Action `
        -GatewaySource $GatewaySource `
        -HookSource $HookSource `
        -CLISource $CLISource `
        -ConfigSource $ConfigSource `
        -ManifestSource $ManifestSource `
        -NoStart:$NoStart `
        -Purge:$Purge `
        -Json:$Json
    return Invoke-NativeProcess `
        -FilePath $script:BootstrapPowerShellExecutable `
        -ArgumentList $arguments `
        -AllowedExitCodes $AllowedExitCodes `
        -Environment (Get-CertificationCodexEnvironment) `
        -TimeoutSeconds 600 `
        -Label $Label `
        -DuringExecution $DuringExecution `
        -ExecutionPollMilliseconds $ExecutionPollMilliseconds `
        -StrictWindowsBootstrapEnvironment
}

function Invoke-EnterpriseInstallerJSON {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Install', 'Upgrade', 'Repair', 'Reconcile', 'Status', 'Verify', 'Uninstall')]
        [string]$Action,

        [string]$GatewaySource = $script:GatewaySource,
        [string]$HookSource = $script:HookSource,
        [string]$CLISource = $script:CLISource,
        [string]$ConfigSource = $script:ConfigSource,
        [string]$ManifestSource = $script:ManifestSource,
        [int[]]$AllowedExitCodes = @(0),
        [switch]$NoStart,
        [switch]$Purge,
        [scriptblock]$DuringExecution = $null,
        [ValidateRange(10, 1000)]
        [int]$ExecutionPollMilliseconds = 25,
        [string]$Label = ''
    )
    if ([string]::IsNullOrWhiteSpace($Label)) {
        $Label = 'installer-' + $Action.ToLowerInvariant() + '-json'
    }
    $process = Invoke-EnterpriseInstaller `
        -Action $Action `
        -GatewaySource $GatewaySource `
        -HookSource $HookSource `
        -CLISource $CLISource `
        -ConfigSource $ConfigSource `
        -ManifestSource $ManifestSource `
        -AllowedExitCodes $AllowedExitCodes `
        -NoStart:$NoStart `
        -Purge:$Purge `
        -Json `
        -DuringExecution $DuringExecution `
        -ExecutionPollMilliseconds $ExecutionPollMilliseconds `
        -Label $Label
    return [pscustomobject]@{
        Process = $process
        JSON = ConvertFrom-SingleJSONDocument $process.StdOut $Label
    }
}

function Get-ManagedCLIEnvironment {
    return @{
        DEFENSECLAW_CONFIG = Join-Path $script:StateRoot 'etc\config.yaml'
        DEFENSECLAW_HOME = $script:StateRoot
        DEFENSECLAW_DEPLOYMENT_MODE = 'managed_enterprise'
        DEFENSECLAW_HOOK_GUARDIAN_AUTH_DIR = Join-Path $script:StateRoot 'hook-guardian-state'
        CODEX_HOME = $null
    }
}

function Invoke-GatewayCommand {
    param(
        [Parameter(Mandatory)][string[]]$Arguments,
        [Parameter(Mandatory)][string]$Label,
        [int[]]$AllowedExitCodes = @(0),
        [int]$TimeoutSeconds = 300
    )
    $gateway = Join-Path $script:InstallRoot 'bin\defenseclaw-gateway.exe'
    if (-not (Test-Path -LiteralPath $gateway -PathType Leaf)) {
        throw "installed gateway is missing: $gateway"
    }
    return Invoke-NativeProcess `
        -FilePath $gateway `
        -ArgumentList $Arguments `
        -AllowedExitCodes $AllowedExitCodes `
        -Environment (Get-ManagedCLIEnvironment) `
        -TimeoutSeconds $TimeoutSeconds `
        -Label $Label
}

function Invoke-GatewayJSON {
    param(
        [Parameter(Mandatory)][string[]]$Arguments,
        [Parameter(Mandatory)][string]$Label,
        [int[]]$AllowedExitCodes = @(0),
        [int]$TimeoutSeconds = 300
    )
    $allArguments = @($Arguments)
    if ($allArguments -notcontains '--json') {
        $allArguments += '--json'
    }
    $result = Invoke-GatewayCommand `
        -Arguments $allArguments `
        -Label $Label `
        -AllowedExitCodes $AllowedExitCodes `
        -TimeoutSeconds $TimeoutSeconds
    $json = ConvertFrom-SingleJSONDocument $result.StdOut $Label
    return [pscustomobject]@{
        Process = $result
        JSON = $json
    }
}

function Get-CodexHookAuditRows([string]$Label) {
    $cli = Join-Path $script:InstallRoot 'bin\defenseclaw.exe'
    if (-not (Test-Path -LiteralPath $cli -PathType Leaf)) {
        throw "installed CLI is missing: $cli"
    }
    $result = Invoke-NativeProcess `
        -FilePath $cli `
        -ArgumentList @(
            'audit', 'export',
            '--output', '-',
            '--connector', 'codex'
        ) `
        -Environment (Get-ManagedCLIEnvironment) `
        -Label $Label
    $rows = [Collections.Generic.List[object]]::new()
    foreach ($line in @($result.StdOut -split "\r?\n")) {
        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }
        try {
            $row = $line | ConvertFrom-Json -ErrorAction Stop
        } catch {
            throw "$Label emitted invalid audit JSONL: $($_.Exception.Message)"
        }
        if ([string]$row.action -eq 'connector-hook' -and
            [string]$row.connector -eq 'codex') {
            $rows.Add($row)
        }
    }
    return $rows.ToArray()
}

function New-CodexHookAuditIDSet([object[]]$Rows) {
    $ids = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal
    )
    foreach ($row in @($Rows)) {
        if (-not [string]::IsNullOrWhiteSpace([string]$row.id)) {
            [void]$ids.Add([string]$row.id)
        }
    }
    return $ids
}

function Wait-ForNewCodexHookAudit(
    [Collections.Generic.HashSet[string]]$BeforeIDs,
    [string]$Label,
    [int]$TimeoutSeconds = $RepairTimeoutSeconds
) {
    return Wait-Until `
        -Description "$Label Codex managed hook audit" `
        -TimeoutSeconds $TimeoutSeconds `
        -Condition {
            $rows = @(
                Get-CodexHookAuditRows "$Label-audit-poll"
            ) | Where-Object {
                -not $BeforeIDs.Contains([string]$_.id)
            }
            $events = @(
                $rows |
                    ForEach-Object { [string]$_.target } |
                    Sort-Object -Unique
            )
            if ($events -contains 'SessionStart' -and
                $events -contains 'UserPromptSubmit') {
                return [pscustomobject]@{
                    rows = @($rows)
                    events = @($events)
                }
            }
            return $false
        }
}

function Invoke-ActualCodexCertificationRun {
    param(
        [Parameter(Mandatory)][string]$Label,
        [Parameter(Mandatory)][string]$BinaryPath,
        [Parameter(Mandatory)][string]$ExpectedSHA256,
        [Parameter(Mandatory)]
        [ValidateSet('stock', 'trusted_launcher')]
        [string]$BinaryRole,
        [switch]$DeleteUserConfig,
        [switch]$BypassHookTrust,
        [switch]$HostileShell,
        [switch]$ExpectFreshUnmanagedClient
    )
    if (-not $script:CertificationCodexHomeInitialized) {
        throw "$Label requires the disposable alternate CODEX_HOME"
    }
    if ($ExpectFreshUnmanagedClient -and (
        $BinaryRole -ne 'stock' -or
        $DeleteUserConfig -or
        $BypassHookTrust -or
        $HostileShell
    )) {
        throw (
            "$Label fresh post-uninstall Codex must use the stock runtime " +
            'without enterprise-test bypass, deletion, or hostile-shell flags'
        )
    }
    $resolvedBinary = ConvertTo-CanonicalPath $BinaryPath
    if (-not (Test-Path -LiteralPath $resolvedBinary -PathType Leaf) -or
        (-not $ExpectFreshUnmanagedClient -and
            -not (Test-Path -LiteralPath $script:HostileShellProbeBinary -PathType Leaf))) {
        throw "$Label requires the protected Codex and shell-probe executables"
    }
    if ((Get-FileDigest $resolvedBinary) -cne $ExpectedSHA256) {
        throw "$Label Codex executable does not match its preflight digest"
    }
    $expectedRuntime = if ($BinaryRole -eq 'stock') {
        $script:CodexRuntimeBinary
    } else {
        $script:CodexTrustedHookLauncherRuntimeBinary
    }
    if ([string]::IsNullOrWhiteSpace($expectedRuntime) -or
        -not $resolvedBinary.Equals(
            (ConvertTo-CanonicalPath $expectedRuntime),
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw "$Label did not select the protected $BinaryRole runtime"
    }
    $home = Assert-CertificationCodexHomePath `
        $script:CertificationCodexHome `
        -RequireExisting
    $port = Get-FreeLoopbackPort
    $shellDirectory = Assert-PathBelow `
        (Join-Path $home ".defenseclaw-hostile-shell-$($script:RunToken)") `
        $home `
        'hostile Codex shell directory'
    $script:CodexHostileShellMarker = Assert-PathBelow `
        (Join-Path $home ".defenseclaw-shell-probe-$($script:RunToken).txt") `
        $home `
        'hostile Codex shell marker'
    $inputObject = [ordered]@{
        binary = $resolvedBinary
        binary_sha256 = $ExpectedSHA256
        binary_role = $BinaryRole
        home = $home
        sid = $script:PrimarySID
        port = $port
        profile = 'defenseclaw-cert'
        base_config = $script:PrimaryConfigPath
        user_hook_sentinel = $script:CodexUserHookSentinel
        delete_user_config = [bool]$DeleteUserConfig
        bypass_hook_trust = [bool]$BypassHookTrust
        hostile_shell = [bool]$HostileShell
        expect_fresh_unmanaged_client = [bool]$ExpectFreshUnmanagedClient
        hostile_shell_source = $script:HostileShellProbeBinary
        hostile_shell_directory = $shellDirectory
        hostile_shell_marker = $script:CodexHostileShellMarker
        prompt = "DefenseClaw Windows certification $($script:RunToken): reply exactly OK and do not call tools."
    }
    $inputBase64 = [Convert]::ToBase64String(
        [Text.Encoding]::UTF8.GetBytes(
            ($inputObject | ConvertTo-Json -Compress)
        )
    )
    $scriptText = @'
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$inputObject = [Text.Encoding]::UTF8.GetString(
    [Convert]::FromBase64String('__INPUT__')
) | ConvertFrom-Json -ErrorAction Stop
$actualSID = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
if ($actualSID -ne [string]$inputObject.sid) {
    throw "actual Codex test SID mismatch: $actualSID"
}
$home = [IO.Path]::GetFullPath([string]$inputObject.home).TrimEnd('\')
$binary = [IO.Path]::GetFullPath([string]$inputObject.binary)
if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) {
    throw "protected Codex binary is missing: $binary"
}
$binarySHA256 = (
    Get-FileHash -LiteralPath $binary -Algorithm SHA256
).Hash.ToLowerInvariant()
if ($binarySHA256 -cne [string]$inputObject.binary_sha256) {
    throw "protected Codex binary changed before actual invocation"
}
$baseConfig = [IO.Path]::GetFullPath([string]$inputObject.base_config)
$homeWasEmpty = @(
    Get-ChildItem -LiteralPath $home -Force -ErrorAction Stop
).Count -eq 0
if ([bool]$inputObject.delete_user_config) {
    if (Test-Path -LiteralPath $baseConfig -PathType Leaf) {
        Remove-Item -LiteralPath $baseConfig -Force
    }
    if (Test-Path -LiteralPath $baseConfig) {
        throw "failed to delete alternate user config: $baseConfig"
    }
}
$profilePath = Join-Path $home (
    ([string]$inputObject.profile) + '.config.toml'
)
$provider = @"
model = "defenseclaw-certification-offline"
model_provider = "defenseclaw-certification"

[model_providers.defenseclaw-certification]
name = "DefenseClaw certification loopback"
base_url = "http://127.0.0.1:$([int]$inputObject.port)/v1"
env_key = "DEFENSECLAW_CERT_DUMMY_KEY"
wire_api = "responses"
"@
[IO.File]::WriteAllText(
    $profilePath,
    $provider,
    [Text.UTF8Encoding]::new($false)
)
$profileHasHookConfiguration = (
    [IO.File]::ReadAllText($profilePath) -match
        '(?im)^\s*(?:\[\[?hooks(?:\.|\])|(?:hooks|notify)\s*=)'
)

$shellMarker = [IO.Path]::GetFullPath(
    [string]$inputObject.hostile_shell_marker
)
if (Test-Path -LiteralPath $shellMarker) {
    Remove-Item -LiteralPath $shellMarker -Force
}
$hostileDirectory = [IO.Path]::GetFullPath(
    [string]$inputObject.hostile_shell_directory
).TrimEnd('\')
if ([bool]$inputObject.hostile_shell) {
    [IO.Directory]::CreateDirectory($hostileDirectory) | Out-Null
    foreach ($name in @('pwsh.exe', 'powershell.exe', 'cmd.exe')) {
        Copy-Item `
            -LiteralPath ([string]$inputObject.hostile_shell_source) `
            -Destination (Join-Path $hostileDirectory $name) `
            -Force
    }
}

$listener = [Net.Sockets.TcpListener]::new(
    [Net.IPAddress]::Loopback,
    [int]$inputObject.port
)
$listener.Start()
$process = $null
$client = $null
$requestLine = ''
$stdoutText = ''
$stderrText = ''
$exitCode = 255
$providerReached = $false
$processID = 0
$processStartTimeUTC = ''
try {
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $binary
    $start.WorkingDirectory = $home
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.Environment['CODEX_HOME'] = $home
    $start.Environment['DEFENSECLAW_CERT_DUMMY_KEY'] = 'local-certification-only'
    $start.Environment['NO_PROXY'] = '127.0.0.1,localhost'
    $start.Environment['no_proxy'] = '127.0.0.1,localhost'
    $start.Environment['DEFENSECLAW_CERT_SHELL_PROBE_MARKER'] = $shellMarker
    if ([bool]$inputObject.hostile_shell) {
        $start.Environment['PATH'] = (
            $hostileDirectory +
            [IO.Path]::PathSeparator +
            [string]$start.Environment['PATH']
        )
        $start.Environment['COMSPEC'] = Join-Path $hostileDirectory 'cmd.exe'
        $start.Environment['ComSpec'] = Join-Path $hostileDirectory 'cmd.exe'
    }
    foreach ($argument in @(
        'exec',
        '--skip-git-repo-check',
        '--ephemeral',
        '--json',
        '-p', [string]$inputObject.profile
    )) {
        $start.ArgumentList.Add([string]$argument)
    }
    if ([bool]$inputObject.bypass_hook_trust) {
        $start.ArgumentList.Add('--dangerously-bypass-hook-trust')
    }
    $start.ArgumentList.Add([string]$inputObject.prompt)

    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    if (-not $process.Start()) {
        throw 'failed to start actual Codex process'
    }
    $processID = $process.Id
    $processStartTimeUTC = $process.StartTime.ToUniversalTime().ToString('o')
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    $accept = $listener.AcceptTcpClientAsync()
    $providerDeadline = [DateTimeOffset]::UtcNow.AddSeconds(60)
    while (-not $accept.IsCompleted -and
        -not $process.HasExited -and
        [DateTimeOffset]::UtcNow -lt $providerDeadline) {
        Start-Sleep -Milliseconds 50
    }
    if ($accept.IsCompleted) {
        $providerReached = $true
    } elseif (-not $process.HasExited) {
        try { $process.Kill($true) } catch {}
        throw 'actual Codex process never reached the loopback provider'
    }
    if ($providerReached) {
        $client = $accept.GetAwaiter().GetResult()
        $stream = $client.GetStream()
        $stream.ReadTimeout = 15000
        $stream.WriteTimeout = 15000
        $reader = [IO.StreamReader]::new(
            $stream,
            [Text.UTF8Encoding]::new($false),
            $false,
            4096,
            $true
        )
        $requestLine = [string]$reader.ReadLine()
        $contentLength = 0
        while ($true) {
            $header = $reader.ReadLine()
            if ($null -eq $header -or $header.Length -eq 0) {
                break
            }
            if ($header.StartsWith('Content-Length:', [StringComparison]::OrdinalIgnoreCase)) {
                [void][int]::TryParse(
                    $header.Substring('Content-Length:'.Length).Trim(),
                    [ref]$contentLength
                )
            }
        }
        if ($contentLength -gt 0) {
            $bodyBuffer = [char[]]::new($contentLength)
            $read = 0
            while ($read -lt $contentLength) {
                $count = $reader.Read(
                    $bodyBuffer,
                    $read,
                    $contentLength - $read
                )
                if ($count -le 0) { break }
                $read += $count
            }
        }
        $responseID = 'resp_defenseclaw_cert'
        $itemID = 'msg_defenseclaw_cert'
        $events = @(
            "event: response.created`ndata: {`"type`":`"response.created`",`"response`":{`"id`":`"$responseID`",`"object`":`"response`",`"model`":`"defenseclaw-certification-offline`",`"status`":`"in_progress`",`"output`":[]}}`n",
            "event: response.output_item.added`ndata: {`"type`":`"response.output_item.added`",`"response_id`":`"$responseID`",`"output_index`":0,`"item`":{`"id`":`"$itemID`",`"type`":`"message`",`"role`":`"assistant`",`"status`":`"in_progress`",`"content`":[]}}`n",
            "event: response.content_part.added`ndata: {`"type`":`"response.content_part.added`",`"response_id`":`"$responseID`",`"item_id`":`"$itemID`",`"output_index`":0,`"content_index`":0,`"part`":{`"type`":`"output_text`",`"text`":`"`"}}`n",
            "event: response.output_text.delta`ndata: {`"type`":`"response.output_text.delta`",`"response_id`":`"$responseID`",`"item_id`":`"$itemID`",`"output_index`":0,`"content_index`":0,`"delta`":`"OK`"}`n",
            "event: response.output_text.done`ndata: {`"type`":`"response.output_text.done`",`"response_id`":`"$responseID`",`"item_id`":`"$itemID`",`"output_index`":0,`"content_index`":0,`"text`":`"OK`"}`n",
            "event: response.content_part.done`ndata: {`"type`":`"response.content_part.done`",`"response_id`":`"$responseID`",`"item_id`":`"$itemID`",`"output_index`":0,`"content_index`":0,`"part`":{`"type`":`"output_text`",`"text`":`"OK`",`"annotations`":[]}}`n",
            "event: response.output_item.done`ndata: {`"type`":`"response.output_item.done`",`"response_id`":`"$responseID`",`"output_index`":0,`"item`":{`"id`":`"$itemID`",`"type`":`"message`",`"role`":`"assistant`",`"status`":`"completed`",`"content`":[{`"type`":`"output_text`",`"text`":`"OK`",`"annotations`":[]}]}}`n",
            "event: response.completed`ndata: {`"type`":`"response.completed`",`"response`":{`"id`":`"$responseID`",`"object`":`"response`",`"model`":`"defenseclaw-certification-offline`",`"status`":`"completed`",`"output`":[{`"id`":`"$itemID`",`"type`":`"message`",`"role`":`"assistant`",`"status`":`"completed`",`"content`":[{`"type`":`"output_text`",`"text`":`"OK`",`"annotations`":[]}]}],`"usage`":{`"input_tokens`":1,`"output_tokens`":1,`"total_tokens`":2}}}`n"
        )
        $sse = ($events -join "`n") + "`n"
        $body = [Text.Encoding]::UTF8.GetBytes($sse)
        $headers = [Text.Encoding]::ASCII.GetBytes(
            "HTTP/1.1 200 OK`r`n" +
            "Content-Type: text/event-stream`r`n" +
            "Cache-Control: no-cache`r`n" +
            "Content-Length: $($body.Length)`r`n" +
            "Connection: close`r`n`r`n"
        )
        $stream.Write($headers, 0, $headers.Length)
        $stream.Write($body, 0, $body.Length)
        $stream.Flush()
        $client.Close()
        $client = $null
    }

    if (-not $process.WaitForExit(60000)) {
        try { $process.Kill($true) } catch {}
        throw 'actual Codex process did not exit after the loopback response'
    }
    $process.Refresh()
    $exitCode = $process.ExitCode
    $stdoutText = $stdoutTask.GetAwaiter().GetResult()
    $stderrText = $stderrTask.GetAwaiter().GetResult()
} finally {
    if ($null -ne $client) {
        try { $client.Close() } catch {}
    }
    try { $listener.Stop() } catch {}
    if ($null -ne $process) {
        $process.Dispose()
    }
}
[pscustomobject]@{
    sid = $actualSID
    binary_sha256 = $binarySHA256
    binary_role = [string]$inputObject.binary_role
    process_id = $processID
    process_start_time_utc = $processStartTimeUTC
    exit_code = $exitCode
    provider_reached = $providerReached
    request_line = $requestLine
    stdout = $stdoutText
    stderr = $stderrText
    home_was_empty = $homeWasEmpty
    profile_has_hook_configuration = $profileHasHookConfiguration
    base_config_exists = Test-Path -LiteralPath $baseConfig -PathType Leaf
    user_hook_sentinel_exists = Test-Path `
        -LiteralPath ([string]$inputObject.user_hook_sentinel)
    hostile_shell_marker_exists = Test-Path -LiteralPath $shellMarker -PathType Leaf
    hostile_shell_marker = if (Test-Path -LiteralPath $shellMarker -PathType Leaf) {
        [IO.File]::ReadAllText($shellMarker)
    } else {
        ''
    }
} | ConvertTo-Json -Compress -Depth 5
'@.Replace('__INPUT__', $inputBase64)
    $beforeIDs = if ($ExpectFreshUnmanagedClient) {
        $null
    } else {
        $beforeRows = @(Get-CodexHookAuditRows "$Label-audit-before")
        New-CodexHookAuditIDSet $beforeRows
    }
    $processResult = Invoke-ActiveUserPowerShell `
        -Script $scriptText `
        -Label $Label `
        -TimeoutSeconds 180
    $result = ConvertFrom-SingleJSONDocument `
        $processResult.StdOut `
        "$Label actual Codex"
    if ([string]$result.sid -ne $script:PrimarySID -or
        [string]$result.binary_sha256 -cne $ExpectedSHA256 -or
        [string]$result.binary_role -cne $BinaryRole) {
        throw (
            "$Label actual process identity is wrong: sid=$($result.sid) " +
            "role=$($result.binary_role) sha256=$($result.binary_sha256)"
        )
    }
    $audit = $null
    if (-not $ExpectFreshUnmanagedClient) {
        try {
            $audit = Wait-ForNewCodexHookAudit `
                -BeforeIDs $beforeIDs `
                -Label $Label `
                -TimeoutSeconds $(if ($BinaryRole -eq 'stock' -or
                    -not [bool]$result.provider_reached) {
                    20
                } else {
                    $RepairTimeoutSeconds
                })
        } catch {
            $audit = $null
        }
    }
    if ([bool]$result.user_hook_sentinel_exists) {
        throw "$Label executed a prohibited alternate-CODEX_HOME user hook"
    }
    if ($DeleteUserConfig -and [bool]$result.base_config_exists) {
        throw "$Label recreated the deleted alternate user config"
    }
    if ($BinaryRole -eq 'trusted_launcher' -and
        $HostileShell -and
        [bool]$result.hostile_shell_marker_exists) {
        throw (
            "$Label selected a user-controlled shell despite the mandatory " +
            'WDAC/AppLocker/trusted-launcher prerequisite; managed hook ' +
            "interception is bypassable. argv=$(Protect-SensitiveDisplayText " +
            "([string]$result.hostile_shell_marker))"
        )
    }
    $providerRequestValid = (
        [string]$result.request_line -match
            '^POST\s+/v1/responses(?:\?|\s)'
    )
    if ($ExpectFreshUnmanagedClient) {
        if (-not [bool]$result.home_was_empty -or
            [bool]$result.profile_has_hook_configuration -or
            [bool]$result.base_config_exists -or
            [int]$result.process_id -le 0 -or
            [string]::IsNullOrWhiteSpace(
                [string]$result.process_start_time_utc
            ) -or
            -not [bool]$result.provider_reached -or
            -not $providerRequestValid -or
            [int]$result.exit_code -ne 0) {
            throw (
                "$Label fresh Codex did not prove hook-free post-uninstall " +
                "startup: empty=$($result.home_was_empty) " +
                "hook_configured=$($result.profile_has_hook_configuration) " +
                "base_config=$($result.base_config_exists) " +
                "provider=$($result.provider_reached) " +
                "request=$providerRequestValid exit=$($result.exit_code) " +
                "stderr=$(Protect-SensitiveDisplayText ([string]$result.stderr))"
            )
        }
        return [pscustomobject]@{
            label = $Label
            client = 'codex'
            process_fresh = $true
            process_id = [int]$result.process_id
            process_start_time_utc =
                [string]$result.process_start_time_utc
            configuration_fresh = $true
            enterprise_hook_configured = $false
            cached_enterprise_command_noop_asserted = $false
            provider_reached = $true
            request_line = [string]$result.request_line
            exit_code = [int]$result.exit_code
            binary_sha256 = $ExpectedSHA256
            active_user_sid = [string]$result.sid
            secret_material_recorded = $false
        }
    }
    if ($BinaryRole -eq 'stock') {
        if (-not $HostileShell) {
            throw "$Label stock Codex negative must inject the blocked hostile shell"
        }
        $expectedHostileShellSelected = [bool]$ClaudeOnly
        if (-not [bool]$result.provider_reached -or
            -not $providerRequestValid -or
            [int]$result.exit_code -ne 0 -or
            $null -ne $audit -or
            [bool]$result.hostile_shell_marker_exists -ne
                $expectedHostileShellSelected) {
            throw (
                "$Label did not reproduce the mandatory stock Codex fail-open " +
                "negative: provider=$($result.provider_reached) " +
                "request=$providerRequestValid exit=$($result.exit_code) " +
                "managed_hook_contact=$($null -ne $audit) " +
                "fake_shell=$($result.hostile_shell_marker_exists) " +
                "expected_fake_shell=$expectedHostileShellSelected"
            )
        }
        return [pscustomobject]@{
            label = $Label
            binary_role = $BinaryRole
            codex_version = 'codex-cli 0.144.3'
            codex_sha256 = $ExpectedSHA256
            codex_exit_code = [int]$result.exit_code
            provider_reached = $true
            request_line = [string]$result.request_line
            hostile_shell_injected = $true
            hostile_shell_selected =
                [bool]$result.hostile_shell_marker_exists
            prohibited_user_hook_fired = $false
            managed_hook_contact = $false
            enforcement_outcome = if ($ClaudeOnly) {
                'rejected_stock_user_shell_bypass'
            } else {
                'rejected_stock_blocked_shell_fail_open'
            }
            upstream_fail_open_confirmed = $true
            accepted_for_enterprise = $false
        }
    }

    if ([bool]$result.provider_reached) {
        if (-not $providerRequestValid -or [int]$result.exit_code -ne 0) {
            throw (
                "$Label trusted launcher reached the provider but did not " +
                "preserve Codex exec semantics: exit=$($result.exit_code) " +
                "request=$(Protect-SensitiveDisplayText ([string]$result.request_line))"
            )
        }
        if ($null -eq $audit) {
            throw (
                "$Label trusted launcher allowed the operation without " +
                'SessionStart/UserPromptSubmit managed hook contact'
            )
        }
    } elseif ([int]$result.exit_code -eq 0) {
        throw (
            "$Label trusted launcher neither contacted managed hooks/the " +
            'provider nor blocked the operation'
        )
    }
    $enforcementOutcome = if ($null -ne $audit) {
        'managed_hook_contact'
    } else {
        'operation_blocked'
    }
    return [pscustomobject]@{
        label = $Label
        binary_role = $BinaryRole
        codex_version = 'codex-cli 0.144.3'
        codex_sha256 = $ExpectedSHA256
        codex_exit_code = [int]$result.exit_code
        provider_reached = [bool]$result.provider_reached
        request_line = [string]$result.request_line
        alternate_codex_home = $home
        user_config_deleted = [bool]$DeleteUserConfig
        bypass_hook_trust_requested = [bool]$BypassHookTrust
        hostile_shell_injected = [bool]$HostileShell
        hostile_shell_selected = [bool]$result.hostile_shell_marker_exists
        prohibited_user_hook_fired = [bool]$result.user_hook_sentinel_exists
        managed_hook_contact = $null -ne $audit
        enforcement_outcome = $enforcementOutcome
        accepted_for_enterprise = $true
        managed_hook_events = if ($null -eq $audit) { @() } else {
            @($audit.events)
        }
        managed_hook_rows = @($(if ($null -eq $audit) {
            @()
        } else {
            $audit.rows
        }) | ForEach-Object {
            [pscustomobject]@{
                id = [string]$_.id
                timestamp = [string]$_.timestamp
                event = [string]$_.target
                connector = [string]$_.connector
            }
        })
    }
}

function Get-ClaudeHookAuditRows([string]$Label) {
    $result = Invoke-GatewayProcess `
        -Arguments @(
            'audit', 'export',
            '--output', '-',
            '--connector', 'claudecode'
        ) `
        -Environment (Get-ManagedCLIEnvironment) `
        -Label $Label
    $rows = [Collections.Generic.List[object]]::new()
    foreach ($line in @($result.StdOut -split "\r?\n")) {
        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }
        try {
            $row = $line | ConvertFrom-Json -ErrorAction Stop
        } catch {
            throw "$Label emitted invalid Claude audit JSONL: $($_.Exception.Message)"
        }
        if ([string]$row.action -eq 'connector-hook' -and
            [string]$row.connector -eq 'claudecode') {
            $rows.Add($row)
        }
    }
    return $rows.ToArray()
}

function Wait-ForNewClaudeHookAudit(
    [Collections.Generic.HashSet[string]]$BeforeIDs,
    [string]$Label,
    [int]$TimeoutSeconds = $RepairTimeoutSeconds
) {
    return Wait-Until `
        -Description "$Label Claude managed hook audit" `
        -TimeoutSeconds $TimeoutSeconds `
        -Condition {
            $rows = @(
                Get-ClaudeHookAuditRows "$Label-audit-poll"
            ) | Where-Object {
                -not $BeforeIDs.Contains([string]$_.id)
            }
            $events = @(
                $rows |
                    ForEach-Object { [string]$_.target } |
                    Sort-Object -Unique
            )
            if ($events -contains 'SessionStart' -and
                $events -contains 'UserPromptSubmit') {
                return [pscustomobject]@{
                    rows = @($rows)
                    events = @($events)
                }
            }
            return $false
        }
}

function Invoke-ActualClaudeCertificationRun {
    param(
        [Parameter(Mandatory)][string]$Label,
        [switch]$ExpectFreshUnmanagedClient
    )
    if (-not $script:CertificationCodexHomeInitialized) {
        throw "$Label requires the disposable certification profile"
    }
    if (-not (Test-Path -LiteralPath $script:ClaudeRuntimeBinary -PathType Leaf) -or
        (-not $ExpectFreshUnmanagedClient -and
            -not (Test-Path -LiteralPath $script:HostileShellProbeBinary -PathType Leaf))) {
        throw "$Label requires protected Claude and hostile-hook probe binaries"
    }
    $home = Assert-CertificationCodexHomePath `
        $script:CertificationCodexHome `
        -RequireExisting
    $port = Get-FreeLoopbackPort
    $configDir = Assert-PathBelow `
        (Join-Path $home ".claude-config-$($script:RunToken)") `
        $home `
        'hostile Claude user settings directory'
    $workspace = Assert-PathBelow `
        (Join-Path $home "claude-workspace-$($script:RunToken)") `
        $home `
        'hostile Claude project directory'
    $hostileMarker = Assert-PathBelow `
        (Join-Path $home ".claude-hostile-hook-$($script:RunToken).txt") `
        $home `
        'hostile Claude hook marker'
    $dummyKey = "dc-claude-local-$($script:RunToken)"
    $script:SecretNeedles.Add($dummyKey)
    $inputObject = [ordered]@{
        binary = $script:ClaudeRuntimeBinary
        binary_sha256 = [string]$script:SourceDigests['claude']
        hostile_hook_binary = $script:HostileShellProbeBinary
        hostile_hook_marker = $hostileMarker
        home = $home
        config_dir = $configDir
        workspace = $workspace
        sid = $script:PrimarySID
        port = $port
        dummy_key = $dummyKey
        expect_fresh_unmanaged_client = [bool]$ExpectFreshUnmanagedClient
        prompt = "DefenseClaw Windows certification $($script:RunToken): reply exactly OK and do not call tools."
    }
    $inputBase64 = [Convert]::ToBase64String(
        [Text.Encoding]::UTF8.GetBytes(
            ($inputObject | ConvertTo-Json -Compress)
        )
    )
    $scriptText = @'
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$inputObject = [Text.Encoding]::UTF8.GetString(
    [Convert]::FromBase64String('__INPUT__')
) | ConvertFrom-Json -ErrorAction Stop
$actualSID = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
if ($actualSID -ne [string]$inputObject.sid) {
    throw "actual Claude test SID mismatch: $actualSID"
}
$binary = [IO.Path]::GetFullPath([string]$inputObject.binary)
if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) {
    throw "protected Claude binary is missing: $binary"
}
$binarySHA256 = (
    Get-FileHash -LiteralPath $binary -Algorithm SHA256
).Hash.ToLowerInvariant()
if ($binarySHA256 -cne [string]$inputObject.binary_sha256) {
    throw 'protected Claude binary changed before actual invocation'
}
$configDir = [IO.Path]::GetFullPath([string]$inputObject.config_dir)
$workspace = [IO.Path]::GetFullPath([string]$inputObject.workspace)
$projectSettingsDir = Join-Path $workspace '.claude'
$freshSurfacesAbsent = (
    -not (Test-Path -LiteralPath $configDir) -and
    -not (Test-Path -LiteralPath $workspace)
)
[IO.Directory]::CreateDirectory($configDir) | Out-Null
[IO.Directory]::CreateDirectory($projectSettingsDir) | Out-Null
$settingsObject = if ([bool]$inputObject.expect_fresh_unmanaged_client) {
    [ordered]@{}
} else {
    $hostileCommand = '"' + (
        [IO.Path]::GetFullPath([string]$inputObject.hostile_hook_binary)
    ) + '"'
    [ordered]@{
        disableAllHooks = $true
        hooks = [ordered]@{
            SessionStart = @(
                [ordered]@{
                    matcher = ''
                    hooks = @(
                        [ordered]@{
                            type = 'command'
                            command = $hostileCommand
                            timeout = 30
                        }
                    )
                }
            )
            UserPromptSubmit = @(
                [ordered]@{
                    matcher = ''
                    hooks = @(
                        [ordered]@{
                            type = 'command'
                            command = $hostileCommand
                            timeout = 30
                        }
                    )
                }
            )
        }
    }
}
$settingsJSON = $settingsObject | ConvertTo-Json -Compress -Depth 8
$userSettings = Join-Path $configDir 'settings.json'
$projectSettings = Join-Path $projectSettingsDir 'settings.json'
$localSettings = Join-Path $projectSettingsDir 'settings.local.json'
foreach ($path in @($userSettings, $projectSettings, $localSettings)) {
    [IO.File]::WriteAllText(
        $path,
        $settingsJSON,
        [Text.UTF8Encoding]::new($false)
    )
}
$settingsHaveHookConfiguration = $false
foreach ($path in @($userSettings, $projectSettings, $localSettings)) {
    $parsedSettings = [IO.File]::ReadAllText($path) |
        ConvertFrom-Json -ErrorAction Stop
    if ($null -ne $parsedSettings.PSObject.Properties['hooks']) {
        $settingsHaveHookConfiguration = $true
    }
}
$settingsHashesBefore = @{}
foreach ($path in @($userSettings, $projectSettings, $localSettings)) {
    $settingsHashesBefore[$path] = (
        Get-FileHash -LiteralPath $path -Algorithm SHA256
    ).Hash.ToLowerInvariant()
}
$hostileMarker = [IO.Path]::GetFullPath(
    [string]$inputObject.hostile_hook_marker
)
if (Test-Path -LiteralPath $hostileMarker) {
    Remove-Item -LiteralPath $hostileMarker -Force
}

$listener = [Net.Sockets.TcpListener]::new(
    [Net.IPAddress]::Loopback,
    [int]$inputObject.port
)
$listener.Start()
$process = $null
$client = $null
$requestLine = ''
$stdoutText = ''
$stderrText = ''
$exitCode = 255
$providerReached = $false
$processID = 0
$processStartTimeUTC = ''
try {
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $binary
    $start.WorkingDirectory = $workspace
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.Environment['CLAUDE_CONFIG_DIR'] = $configDir
    $start.Environment['ANTHROPIC_BASE_URL'] = (
        "http://127.0.0.1:$([int]$inputObject.port)"
    )
    $start.Environment['ANTHROPIC_API_KEY'] = [string]$inputObject.dummy_key
    $start.Environment['ANTHROPIC_AUTH_TOKEN'] = [string]$inputObject.dummy_key
    $start.Environment['NO_PROXY'] = '127.0.0.1,localhost'
    $start.Environment['no_proxy'] = '127.0.0.1,localhost'
    $start.Environment['CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC'] = '1'
    $start.Environment['DISABLE_TELEMETRY'] = '1'
    $start.Environment['DISABLE_ERROR_REPORTING'] = '1'
    $start.Environment['DISABLE_AUTOUPDATER'] = '1'
    $start.Environment['DEFENSECLAW_CERT_SHELL_PROBE_MARKER'] = $hostileMarker
    foreach ($argument in @(
        '--print',
        '--output-format', 'json',
        '--no-session-persistence',
        '--model', 'claude-sonnet-4-5-20250929',
        '--tools', '',
        '--setting-sources', 'user,project,local',
        [string]$inputObject.prompt
    )) {
        $start.ArgumentList.Add([string]$argument)
    }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    if (-not $process.Start()) {
        throw 'failed to start actual Claude process'
    }
    $processID = $process.Id
    $processStartTimeUTC = $process.StartTime.ToUniversalTime().ToString('o')
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    $accept = $listener.AcceptTcpClientAsync()
    $providerDeadline = [DateTimeOffset]::UtcNow.AddSeconds(75)
    while (-not $accept.IsCompleted -and
        -not $process.HasExited -and
        [DateTimeOffset]::UtcNow -lt $providerDeadline) {
        Start-Sleep -Milliseconds 50
    }
    if ($accept.IsCompleted) {
        $providerReached = $true
        $client = $accept.GetAwaiter().GetResult()
        $stream = $client.GetStream()
        $stream.ReadTimeout = 15000
        $stream.WriteTimeout = 15000
        $reader = [IO.StreamReader]::new(
            $stream,
            [Text.UTF8Encoding]::new($false),
            $false,
            4096,
            $true
        )
        $requestLine = [string]$reader.ReadLine()
        $contentLength = 0
        while ($true) {
            $header = $reader.ReadLine()
            if ($null -eq $header -or $header.Length -eq 0) {
                break
            }
            if ($header.StartsWith(
                'Content-Length:',
                [StringComparison]::OrdinalIgnoreCase
            )) {
                [void][int]::TryParse(
                    $header.Substring('Content-Length:'.Length).Trim(),
                    [ref]$contentLength
                )
            }
        }
        if ($contentLength -gt 0) {
            $bodyBuffer = [char[]]::new($contentLength)
            $read = 0
            while ($read -lt $contentLength) {
                $count = $reader.Read(
                    $bodyBuffer,
                    $read,
                    $contentLength - $read
                )
                if ($count -le 0) { break }
                $read += $count
            }
        }
        $messageID = 'msg_defenseclaw_claude_cert'
        $events = @(
            "event: message_start`ndata: {`"type`":`"message_start`",`"message`":{`"id`":`"$messageID`",`"type`":`"message`",`"role`":`"assistant`",`"content`":[],`"model`":`"claude-sonnet-4-5-20250929`",`"stop_reason`":null,`"stop_sequence`":null,`"usage`":{`"input_tokens`":1,`"output_tokens`":0}}}`n",
            "event: content_block_start`ndata: {`"type`":`"content_block_start`",`"index`":0,`"content_block`":{`"type`":`"text`",`"text`":`"`"}}`n",
            "event: content_block_delta`ndata: {`"type`":`"content_block_delta`",`"index`":0,`"delta`":{`"type`":`"text_delta`",`"text`":`"OK`"}}`n",
            "event: content_block_stop`ndata: {`"type`":`"content_block_stop`",`"index`":0}`n",
            "event: message_delta`ndata: {`"type`":`"message_delta`",`"delta`":{`"stop_reason`":`"end_turn`",`"stop_sequence`":null},`"usage`":{`"output_tokens`":1}}`n",
            "event: message_stop`ndata: {`"type`":`"message_stop`"}`n"
        )
        $sse = ($events -join "`n") + "`n"
        $body = [Text.Encoding]::UTF8.GetBytes($sse)
        $headers = [Text.Encoding]::ASCII.GetBytes(
            "HTTP/1.1 200 OK`r`n" +
            "Content-Type: text/event-stream`r`n" +
            "Cache-Control: no-cache`r`n" +
            "Content-Length: $($body.Length)`r`n" +
            "Connection: close`r`n`r`n"
        )
        $stream.Write($headers, 0, $headers.Length)
        $stream.Write($body, 0, $body.Length)
        $stream.Flush()
        $client.Close()
        $client = $null
    } elseif (-not $process.HasExited) {
        try { $process.Kill($true) } catch {}
        throw 'actual Claude process never reached the loopback provider or blocked'
    }
    if (-not $process.WaitForExit(60000)) {
        try { $process.Kill($true) } catch {}
        throw 'actual Claude process did not exit after the loopback response'
    }
    $process.Refresh()
    $exitCode = $process.ExitCode
    $stdoutText = $stdoutTask.GetAwaiter().GetResult()
    $stderrText = $stderrTask.GetAwaiter().GetResult()
} finally {
    if ($null -ne $client) {
        try { $client.Close() } catch {}
    }
    try { $listener.Stop() } catch {}
    if ($null -ne $process) {
        $process.Dispose()
    }
}
$settingsUnchanged = $true
foreach ($path in @($userSettings, $projectSettings, $localSettings)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf) -or
        (Get-FileHash -LiteralPath $path -Algorithm SHA256).
            Hash.ToLowerInvariant() -cne $settingsHashesBefore[$path]) {
        $settingsUnchanged = $false
    }
}
[pscustomobject]@{
    sid = $actualSID
    binary_sha256 = $binarySHA256
    process_id = $processID
    process_start_time_utc = $processStartTimeUTC
    exit_code = $exitCode
    provider_reached = $providerReached
    request_line = $requestLine
    stdout = $stdoutText
    stderr = $stderrText
    fresh_surfaces_absent = $freshSurfacesAbsent
    settings_have_hook_configuration = $settingsHaveHookConfiguration
    hostile_user_project_settings_unchanged = $settingsUnchanged
    hostile_hook_marker_exists = Test-Path `
        -LiteralPath $hostileMarker `
        -PathType Leaf
} | ConvertTo-Json -Compress -Depth 5
'@.Replace('__INPUT__', $inputBase64)
    $beforeIDs = if ($ExpectFreshUnmanagedClient) {
        $null
    } else {
        $beforeRows = @(Get-ClaudeHookAuditRows "$Label-audit-before")
        New-CodexHookAuditIDSet $beforeRows
    }
    $processResult = Invoke-ActiveUserPowerShell `
        -Script $scriptText `
        -Label $Label `
        -TimeoutSeconds 210
    $result = ConvertFrom-SingleJSONDocument `
        $processResult.StdOut `
        "$Label actual Claude"
    if ([string]$result.sid -ne $script:PrimarySID -or
        [string]$result.binary_sha256 -cne
            [string]$script:SourceDigests['claude']) {
        throw "$Label actual Claude process identity is wrong"
    }
    if (-not $ExpectFreshUnmanagedClient -and
        [bool]$result.hostile_hook_marker_exists) {
        throw "$Label executed a hostile user/project Claude hook"
    }
    if (-not [bool]$result.hostile_user_project_settings_unchanged) {
        throw "$Label modified hostile user/project Claude settings"
    }
    $audit = $null
    if (-not $ExpectFreshUnmanagedClient) {
        try {
            $audit = Wait-ForNewClaudeHookAudit `
                -BeforeIDs $beforeIDs `
                -Label $Label `
                -TimeoutSeconds $(if ([bool]$result.provider_reached) {
                    $RepairTimeoutSeconds
                } else {
                    20
                })
        } catch {
            $audit = $null
        }
    }
    $providerRequestValid = (
        [string]$result.request_line -match
            '^POST\s+/v1/messages(?:\?|\s)'
    )
    if ($ExpectFreshUnmanagedClient) {
        if (-not [bool]$result.fresh_surfaces_absent -or
            [bool]$result.settings_have_hook_configuration -or
            -not [bool]$result.hostile_user_project_settings_unchanged -or
            [int]$result.process_id -le 0 -or
            [string]::IsNullOrWhiteSpace(
                [string]$result.process_start_time_utc
            ) -or
            -not [bool]$result.provider_reached -or
            -not $providerRequestValid -or
            [int]$result.exit_code -ne 0) {
            throw (
                "$Label fresh Claude did not prove hook-free post-uninstall " +
                "startup: fresh=$($result.fresh_surfaces_absent) " +
                "hook_configured=$($result.settings_have_hook_configuration) " +
                "settings_unchanged=$($result.hostile_user_project_settings_unchanged) " +
                "provider=$($result.provider_reached) " +
                "request=$providerRequestValid exit=$($result.exit_code) " +
                "stderr=$(Protect-SensitiveDisplayText ([string]$result.stderr))"
            )
        }
        return [pscustomobject]@{
            label = $Label
            client = 'claude'
            process_fresh = $true
            process_id = [int]$result.process_id
            process_start_time_utc =
                [string]$result.process_start_time_utc
            configuration_fresh = $true
            enterprise_hook_configured = $false
            cached_enterprise_command_noop_asserted = $false
            provider_reached = $true
            request_line = [string]$result.request_line
            exit_code = [int]$result.exit_code
            binary_sha256 = [string]$script:SourceDigests['claude']
            active_user_sid = [string]$result.sid
            secret_material_recorded = $false
        }
    }
    if ([bool]$result.provider_reached) {
        if (-not $providerRequestValid -or
            [int]$result.exit_code -ne 0 -or
            $null -eq $audit) {
            throw (
                "$Label Claude reached the provider without a successful " +
                "managed-hook-enforced operation: request=$providerRequestValid " +
                "exit=$($result.exit_code) audit=$($null -ne $audit) " +
                "stderr=$(Protect-SensitiveDisplayText ([string]$result.stderr))"
            )
        }
    } elseif ([int]$result.exit_code -eq 0 -or
        [string]$result.stderr -notmatch
            '(?i)hook|managed|policy|DefenseClaw') {
        throw (
            "$Label Claude neither contacted managed hooks/the provider nor " +
            'failed closed with a causal enforcement diagnostic'
        )
    }
    return [pscustomobject]@{
        label = $Label
        claude_sha256 = [string]$script:SourceDigests['claude']
        claude_exit_code = [int]$result.exit_code
        provider_reached = [bool]$result.provider_reached
        request_line = [string]$result.request_line
        hostile_disable_all_hooks_user = $true
        hostile_disable_all_hooks_project = $true
        hostile_hook_fired = $false
        managed_hook_contact = $null -ne $audit
        enforcement_outcome = if ($null -ne $audit) {
            'managed_hook_contact'
        } else {
            'operation_blocked'
        }
        managed_hook_events = if ($null -eq $audit) { @() } else {
            @($audit.events)
        }
        managed_hook_rows = @($(if ($null -eq $audit) {
            @()
        } else {
            $audit.rows
        }) | ForEach-Object {
            [pscustomobject]@{
                id = [string]$_.id
                timestamp = [string]$_.timestamp
                event = [string]$_.target
                connector = [string]$_.connector
            }
        })
    }
}

function Assert-ServiceContract {
    $gateway = Get-CimInstance Win32_Service -Filter "Name='$($script:GatewayServiceName)'" -ErrorAction Stop
    $guardian = Get-CimInstance Win32_Service -Filter "Name='$($script:GuardianServiceName)'" -ErrorAction Stop
    if ($null -eq $gateway -or $null -eq $guardian) {
        throw 'one or both certification services are missing'
    }
    if ([string]$gateway.StartName -ne "NT SERVICE\$($script:GatewayServiceName)") {
        throw "gateway identity is $($gateway.StartName), want NT SERVICE\$($script:GatewayServiceName)"
    }
    if ([string]$guardian.StartName -notin @('LocalSystem', 'NT AUTHORITY\SYSTEM')) {
        throw "guardian identity is $($guardian.StartName), want LocalSystem"
    }
    foreach ($service in @($gateway, $guardian)) {
        if ([string]$service.StartMode -ne 'Auto') {
            throw "$($service.Name) start mode is $($service.StartMode), want Auto"
        }
        if ([string]$service.State -ne 'Running') {
            throw "$($service.Name) state is $($service.State), want Running"
        }
        if (-not ([string]$service.PathName).Contains(
            $script:InstallRoot,
            [StringComparison]::OrdinalIgnoreCase
        )) {
            throw "$($service.Name) image path escapes install root: $($service.PathName)"
        }
    }
    if (-not ([string]$guardian.PathName).Contains(
        'enterprise hooks watch',
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "guardian service does not host enterprise hooks watch: $($guardian.PathName)"
    }
    $null = Assert-CertificationServiceCodexHomeAbsent
    return "gateway=$($gateway.State)/$($gateway.StartName); guardian=$($guardian.State)/$($guardian.StartName)"
}

function Assert-CertificationServiceCodexHomeAbsent {
    $proof = [Collections.Generic.List[object]]::new()
    foreach ($service in @(
        [pscustomobject]@{
            name = $script:GatewayServiceName
            role = 'gateway'
        },
        [pscustomobject]@{
            name = $script:GuardianServiceName
            role = 'guardian'
        }
    )) {
        $serviceName = [string]$service.name
        Assert-CertificationServiceName $serviceName ([string]$service.role)
        $serviceKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"
        $values = @(
            Get-ItemPropertyValue `
                -LiteralPath $serviceKey `
                -Name Environment `
                -ErrorAction Stop
        )
        $entries = @(
            $values |
                Where-Object {
                    ([string]$_).StartsWith(
                        'CODEX_HOME=',
                        [StringComparison]::OrdinalIgnoreCase
                    )
                }
        )
        if ($entries.Count -ne 0) {
            throw (
                "$serviceName must be CODEX_HOME-independent; found service " +
                "environment entries [$($entries -join ',')]"
            )
        }
        $proof.Add([pscustomobject]@{
            service = $serviceName
            codex_home_entries = @()
            environment_count = $values.Count
            verified_at = [DateTimeOffset]::UtcNow.ToString('o')
        })
    }
    $script:CertificationServiceCodexHomeAbsenceProof = @($proof.ToArray())
    return $proof.ToArray()
}

function Assert-CertificationServicesStoppedAndIndependent {
    $proof = Assert-CertificationServiceCodexHomeAbsent
    foreach ($serviceName in @(
        $script:GatewayServiceName,
        $script:GuardianServiceName
    )) {
        $service = Get-CimInstance `
            Win32_Service `
            -Filter "Name='$serviceName'" `
            -ErrorAction Stop
        if ([string]$service.State -ne 'Stopped' -or
            [uint32]$service.ProcessId -ne 0 -or
            [string]$service.StartMode -ne 'Disabled') {
            throw (
                "$serviceName escaped disabled staging before the " +
                'CODEX_HOME-independent pre-activation proof: ' +
                "state=$($service.State) pid=$($service.ProcessId) " +
                "start_mode=$($service.StartMode)"
            )
        }
    }
    return $proof
}

function Invoke-EnterpriseLifecycleCLIJSON(
    [string]$FilePath,
    [string[]]$Arguments,
    [string]$Label,
    [int[]]$AllowedExitCodes = @(0)
) {
    $before = Get-EnterprisePowerShellTempSnapshot
    $observation = [pscustomobject]@{
        observed = $false
        name = ''
        path = ''
        owner_sid = ''
        access_rules_protected = $false
        sddl = ''
        sample_count = 0
    }
    $probe = Start-ActiveUserEnterprisePowerShellTempProbe `
        -Baseline $before `
        -Label "$Label-medium-temp-boundary"
    $process = $null
    $userEvidence = $null
    try {
        $process = Invoke-NativeProcess `
            -FilePath $FilePath `
            -ArgumentList $Arguments `
            -AllowedExitCodes $AllowedExitCodes `
            -Environment (Get-CertificationCodexEnvironment) `
            -TimeoutSeconds 600 `
            -Label $Label `
            -DuringExecution {
                param($RunningProcess)
                $null = $RunningProcess
                Update-EnterprisePowerShellTempObservation `
                    -Baseline $before `
                    -Observation $observation
            } `
            -ExecutionPollMilliseconds 25 `
            -StrictWindowsBootstrapEnvironment
    } finally {
        $userEvidence =
            Stop-ActiveUserEnterprisePowerShellTempProbe $probe
    }
    $after = Get-EnterprisePowerShellTempSnapshot
    Assert-SameObjectJSON `
        $before `
        $after `
        "$Label elevated PowerShell temp residual snapshot"
    if (-not [bool]$observation.observed -or
        [int]$observation.sample_count -lt 1) {
        throw "$Label did not expose its protected temp child to the admin monitor"
    }
    $attempts = @($userEvidence.attempts)
    $expectedOperations = @('change_dacl', 'create', 'delete', 'read')
    $actualOperations = @(
        $attempts |
            ForEach-Object { [string]$_.operation } |
            Sort-Object -Unique
    )
    if ([string]$userEvidence.sid -ne $script:PrimarySID -or
        -not [bool]$userEvidence.observed -or
        -not [bool]$userEvidence.target_existed_before -or
        -not [bool]$userEvidence.target_existed_after -or
        [bool]$userEvidence.secret_material_recorded -or
        [string]$userEvidence.target_name -cne [string]$observation.name -or
        $attempts.Count -ne 4 -or
        @($attempts | Where-Object { -not [bool]$_.denied }).Count -ne 0 -or
        ($actualOperations -join ',') -cne
            ($expectedOperations -join ',')) {
        throw (
            "$Label medium-user elevated-temp denial probe failed: " +
            (Protect-SensitiveDisplayText (
                $userEvidence | ConvertTo-Json -Compress -Depth 6
            ))
        )
    }
    return [pscustomobject]@{
        Process = $process
        JSON = ConvertFrom-SingleJSONDocument $process.StdOut $Label
        TempBoundary = [pscustomobject]@{
            root = [string]$before.root
            prefix = [string]$before.prefix
            before_entries = @($before.entries)
            after_entries = @($after.entries)
            exact_residual_snapshot_preserved = $true
            live_child_name = [string]$observation.name
            live_child_owner_sid = [string]$observation.owner_sid
            live_child_access_rules_protected =
                [bool]$observation.access_rules_protected
            live_child_sddl = [string]$observation.sddl
            live_child_admin_sample_count = [int]$observation.sample_count
            target_sid_verified = $true
            medium_user_attempts = @($attempts)
            medium_user_all_denied = $true
            secret_material_recorded = $false
        }
    }
}

function Invoke-PublicEnterpriseLifecycleCLIJSON(
    [ValidateSet(
        'Install',
        'Upgrade',
        'Repair',
        'Reconcile',
        'Status',
        'Verify',
        'Uninstall'
    )]
    [string]$Action,
    [string]$FilePath,
    [string]$InstallerPath,
    [string]$GatewaySource = '',
    [string]$HookSource = '',
    [string]$CLISource = '',
    [string]$ConfigSource = '',
    [string]$ManifestSource = '',
    [switch]$NoStart,
    [switch]$Purge,
    [int[]]$AllowedExitCodes = @(0),
    [string]$Label
) {
    $arguments = Get-EnterpriseLifecycleCLIArguments `
        -Action $Action `
        -InstallerPath $InstallerPath `
        -GatewaySource $GatewaySource `
        -HookSource $HookSource `
        -CLISource $CLISource `
        -ConfigSource $ConfigSource `
        -ManifestSource $ManifestSource `
        -NoStart:$NoStart `
        -Purge:$Purge
    return Invoke-EnterpriseLifecycleCLIJSON `
        -FilePath $FilePath `
        -Arguments $arguments `
        -AllowedExitCodes $AllowedExitCodes `
        -Label $Label
}

function Invoke-CertificationActivationRepairAfterIsolationProof {
    $null = Assert-MachineCodexHomeUnchanged
    $null = Assert-CertificationServicesStoppedAndIndependent

    $gatewayStartDiagnostic = ''
    $gatewayStartFailed = $false
    try {
        Start-Service -Name $script:GatewayServiceName -ErrorAction Stop
    } catch {
        $gatewayStartFailed = $true
        $gatewayStartDiagnostic = Protect-SensitiveDisplayText (
            $_.Exception.Message
        )
    }
    $gatewayAfterBlockedStart = Get-CimInstance `
        Win32_Service `
        -Filter "Name='$($script:GatewayServiceName)'" `
        -ErrorAction Stop
    $guardianAfterBlockedStart = Get-CimInstance `
        Win32_Service `
        -Filter "Name='$($script:GuardianServiceName)'" `
        -ErrorAction Stop
    if (-not $gatewayStartFailed -or
        [string]$gatewayAfterBlockedStart.State -ne 'Stopped' -or
        [uint32]$gatewayAfterBlockedStart.ProcessId -ne 0 -or
        [string]$gatewayAfterBlockedStart.StartMode -ne 'Disabled' -or
        [string]$guardianAfterBlockedStart.State -ne 'Stopped' -or
        [uint32]$guardianAfterBlockedStart.ProcessId -ne 0 -or
        [string]$guardianAfterBlockedStart.StartMode -ne 'Disabled') {
        throw (
            'gateway became startable before the public Repair guardian ' +
            'barrier: ' +
            "gateway=$($gatewayAfterBlockedStart.State)/" +
            "$($gatewayAfterBlockedStart.ProcessId)/" +
            "$($gatewayAfterBlockedStart.StartMode) " +
            "guardian=$($guardianAfterBlockedStart.State)/" +
            "$($guardianAfterBlockedStart.ProcessId)/" +
            "$($guardianAfterBlockedStart.StartMode)"
        )
    }

    $installedInstaller = Assert-PathBelow `
        (Join-Path $script:InstallRoot 'libexec\install-enterprise.ps1') `
        $script:InstallRoot `
        'installed activation installer'
    $installedModule = Assert-PathBelow `
        (Join-Path $script:InstallRoot 'libexec\DefenseClawEnterprise.psm1') `
        $script:InstallRoot `
        'installed activation module'
    $installedCLI = Assert-PathBelow `
        (Join-Path $script:InstallRoot 'bin\defenseclaw.exe') `
        $script:InstallRoot `
        'installed activation CLI'
    $installedInstaller = Assert-SourcePathHasNoReparse `
        $installedInstaller `
        'installed activation installer'
    $installedModule = Assert-SourcePathHasNoReparse `
        $installedModule `
        'installed activation module'
    $installedCLI = Assert-SourcePathHasNoReparse `
        $installedCLI `
        'installed activation CLI'
    if ((Get-FileDigest $installedInstaller) -cne
            [string]$script:SourceDigests['installer'] -or
        (Get-FileDigest $installedModule) -cne
            [string]$script:SourceDigests['module'] -or
        (Get-FileDigest $installedCLI) -cne
            [string]$script:SourceDigests['cli']) {
        throw (
            'installed public Repair CLI/entrypoint/module bytes differ from the ' +
            'protected staged sources'
        )
    }

    # Execute the installed public Go CLI. It validates the protected
    # entrypoint/module, creates an atomic 128-bit-capability TEMP/TMP child,
    # and the PowerShell entrypoint binds InstallerSource/ModuleSource to its
    # own protected libexec files. Deliberately omit every artifact replacement
    # and attestation refresh: Repair must activate the recorded deployment.
    $arguments = [Collections.Generic.List[string]]::new()
    foreach ($value in @(
        'enterprise', 'windows', 'repair',
        '--installer', $installedInstaller,
        '--gateway-service-name', $script:GatewayServiceName,
        '--guardian-service-name', $script:GuardianServiceName,
        '--install-root', $script:InstallRoot,
        '--state-root', $script:StateRoot
    )) {
        $arguments.Add([string]$value)
    }
    if ($AllowUnsigned) {
        Assert-CertificationScope
        if (-not $script:CertificationCodexHomeInitialized) {
            throw (
                'unsigned installed Repair requires the exact initialized ' +
                'certification CODEX_HOME scope'
            )
        }
        $arguments.Add('--certification-codex-home')
        $arguments.Add($script:CertificationCodexHome)
        $arguments.Add('--allow-unsigned')
        if ($ClaudeOnly) {
            $arguments.Add('--core-hardening-certification')
        }
    }
    $arguments.Add('--json')
    $repairEnvelope = Invoke-EnterpriseLifecycleCLIJSON `
        -FilePath $installedCLI `
        -Arguments $arguments.ToArray() `
        -Label 'installed-public-repair-first-activation'
    $repair = $repairEnvelope.JSON
    if ([int]$repair.schema_version -ne 1 -or
        [string]$repair.action -cne 'repair' -or
        -not [bool]$repair.ok -or
        -not [bool]$repair.installed -or
        [bool]$repair.transaction_pending -or
        [string]$repair.gateway_service_state -cne 'running' -or
        [string]$repair.guardian_service_state -cne 'running' -or
        -not [bool]$repair.gateway_ready -or
        -not [bool]$repair.guardian_ready -or
        -not [bool]$repair.core_hardening_complete -or
        [bool]$repair.core_hardening_certification -ne
            [bool]$ClaudeOnly -or
        [bool]$repair.agent_application_control_enforced -ne
            [bool]$AttestAgentApplicationControl -or
        [bool]$repair.codex_trusted_hook_launcher_verified -ne
            [bool]$AttestCodexTrustedHookLauncher -or
        [bool]$repair.codex_target_enabled -ne (-not [bool]$ClaudeOnly) -or
        -not [bool]$repair.claude_target_enabled -or
        [bool]$repair.claude_effective_policy_verified -or
        [bool]$repair.external_security_prerequisites_satisfied -or
        [bool]$repair.security_complete -or
        [string]::IsNullOrWhiteSpace([string]$repair.guardian_generation) -or
        [string]$repair.gateway_service -cne $script:GatewayServiceName -or
        [string]$repair.guardian_service -cne $script:GuardianServiceName -or
        -not [string]::Equals(
            [string]$repair.install_root,
            $script:InstallRoot,
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        -not [string]::Equals(
            [string]$repair.state_root,
            $script:StateRoot,
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        @($repair.errors).Count -ne 0) {
        throw (
            'installed public Repair did not establish the exact honest ' +
            'guardian-first live contract: ' +
            (Protect-SensitiveDisplayText (
                $repair | ConvertTo-Json -Compress -Depth 7
            ))
        )
    }
    Wait-ForServicesRunning
    $null = Assert-MachineCodexHomeUnchanged
    return [pscustomobject]@{
        gateway_start_blocked_while_disabled = $true
        gateway_start_diagnostic = $gatewayStartDiagnostic
        installed_cli_sha256 = Get-FileDigest $installedCLI
        installed_installer_sha256 = Get-FileDigest $installedInstaller
        installed_module_sha256 = Get-FileDigest $installedModule
        replacement_sources_supplied = @()
        elevated_powershell_temp_boundary = $repairEnvelope.TempBoundary
        repair = $repair
    }
}

function Get-ServiceControlSnapshot([string]$Label) {
    $sc = Join-Path $script:System32 'sc.exe'
    $snapshot = [ordered]@{}
    foreach ($serviceName in @($script:GatewayServiceName, $script:GuardianServiceName)) {
        $service = Get-CimInstance Win32_Service `
            -Filter "Name='$serviceName'" `
            -ErrorAction Stop
        $commands = [ordered]@{}
        foreach ($command in @('qc', 'qfailure', 'sdshow')) {
            $result = Invoke-NativeProcess `
                -FilePath $sc `
                -ArgumentList @($command, $serviceName) `
                -Label "$Label-$serviceName-$command"
            $commands[$command] = $result.StdOut.Trim()
        }
        $serviceKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"
        $environment = @(
            Get-ItemPropertyValue `
                -LiteralPath $serviceKey `
                -Name Environment `
                -ErrorAction Stop
        ) | Sort-Object
        $snapshot[$serviceName] = [pscustomobject]@{
            name = [string]$service.Name
            path_name = [string]$service.PathName
            start_name = [string]$service.StartName
            start_mode = [string]$service.StartMode
            qc = [string]$commands.qc
            qfailure = [string]$commands.qfailure
            sdshow = [string]$commands.sdshow
            environment = @($environment)
        }
    }
    return [pscustomobject]$snapshot
}

function Get-CertificationServiceProcessSnapshot {
    $rows = [Collections.Generic.List[object]]::new()
    foreach ($name in @($script:GatewayServiceName, $script:GuardianServiceName)) {
        $service = Get-CimInstance `
            Win32_Service `
            -Filter "Name='$name'" `
            -ErrorAction Stop
        if ([string]$service.State -ne 'Running' -or [uint32]$service.ProcessId -eq 0) {
            throw "service process snapshot found $name state=$($service.State) pid=$($service.ProcessId)"
        }
        $rows.Add([pscustomobject]@{
            name = $name
            process_id = [uint32]$service.ProcessId
            state = [string]$service.State
        })
    }
    return $rows.ToArray()
}

function Initialize-ServiceTokenProbeType {
    if ($null -ne ('DefenseClaw.Certification.ServiceTokenNative' -as [type])) {
        return
    }
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace DefenseClaw.Certification
{
    public sealed class TokenPrivilegeRecord
    {
        public string Name;
        public UInt32 Attributes;
        public bool Enabled;
        public bool EnabledByDefault;
        public bool Removed;
        public bool UsedForAccess;
    }

    public sealed class TokenGroupRecord
    {
        public string Sid;
        public string Name;
        public UInt32 Attributes;
        public bool Enabled;
        public bool EnabledByDefault;
        public bool DenyOnly;
        public bool Integrity;
        public bool LogonId;
        public bool Owner;
    }

    public sealed class ServiceProcessTokenRecord
    {
        public UInt32 ProcessId;
        public string UserSid;
        public string UserName;
        public string IntegritySid;
        public bool IsRestricted;
        public TokenPrivilegeRecord[] Privileges;
        public TokenGroupRecord[] Groups;
        public TokenGroupRecord[] RestrictedSids;
    }

    public static class ServiceTokenNative
    {
        private const UInt32 PROCESS_QUERY_LIMITED_INFORMATION = 0x00001000;
        private const UInt32 TOKEN_QUERY = 0x00000008;
        private const Int32 ERROR_INSUFFICIENT_BUFFER = 122;
        private const Int32 TokenUser = 1;
        private const Int32 TokenGroups = 2;
        private const Int32 TokenPrivileges = 3;
        private const Int32 TokenRestrictedSids = 11;
        private const Int32 TokenIntegrityLevel = 25;
        private const UInt32 SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001;
        private const UInt32 SE_PRIVILEGE_ENABLED = 0x00000002;
        private const UInt32 SE_PRIVILEGE_REMOVED = 0x00000004;
        private const UInt32 SE_PRIVILEGE_USED_FOR_ACCESS = 0x80000000;
        private const UInt32 SE_GROUP_ENABLED_BY_DEFAULT = 0x00000002;
        private const UInt32 SE_GROUP_ENABLED = 0x00000004;
        private const UInt32 SE_GROUP_OWNER = 0x00000008;
        private const UInt32 SE_GROUP_USE_FOR_DENY_ONLY = 0x00000010;
        private const UInt32 SE_GROUP_INTEGRITY = 0x00000020;
        private const UInt32 SE_GROUP_LOGON_ID = 0xC0000000;

        [StructLayout(LayoutKind.Sequential)]
        private struct SID_AND_ATTRIBUTES
        {
            public IntPtr Sid;
            public UInt32 Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct TOKEN_GROUPS_HEADER
        {
            public UInt32 GroupCount;
            public SID_AND_ATTRIBUTES FirstGroup;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct LUID
        {
            public UInt32 LowPart;
            public Int32 HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct LUID_AND_ATTRIBUTES
        {
            public LUID Luid;
            public UInt32 Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct TOKEN_PRIVILEGES_HEADER
        {
            public UInt32 PrivilegeCount;
            public LUID_AND_ATTRIBUTES FirstPrivilege;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(
            UInt32 desiredAccess,
            bool inheritHandle,
            UInt32 processId
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr handle);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool OpenProcessToken(
            IntPtr processHandle,
            UInt32 desiredAccess,
            out IntPtr tokenHandle
        );

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetTokenInformation(
            IntPtr tokenHandle,
            Int32 tokenInformationClass,
            IntPtr tokenInformation,
            Int32 tokenInformationLength,
            out Int32 returnLength
        );

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool IsTokenRestricted(IntPtr tokenHandle);

        [DllImport(
            "advapi32.dll",
            CharSet = CharSet.Unicode,
            SetLastError = true
        )]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool LookupPrivilegeNameW(
            string systemName,
            ref LUID luid,
            StringBuilder name,
            ref Int32 nameLength
        );

        private static IntPtr QueryTokenBuffer(
            IntPtr tokenHandle,
            Int32 informationClass
        )
        {
            Int32 required = 0;
            GetTokenInformation(
                tokenHandle,
                informationClass,
                IntPtr.Zero,
                0,
                out required
            );
            Int32 firstError = Marshal.GetLastWin32Error();
            if (required <= 0 || firstError != ERROR_INSUFFICIENT_BUFFER)
            {
                throw new Win32Exception(
                    firstError,
                    "GetTokenInformation size query failed for class " +
                    informationClass
                );
            }
            IntPtr buffer = Marshal.AllocHGlobal(required);
            try
            {
                if (!GetTokenInformation(
                    tokenHandle,
                    informationClass,
                    buffer,
                    required,
                    out required
                ))
                {
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "GetTokenInformation failed for class " +
                        informationClass
                    );
                }
                return buffer;
            }
            catch
            {
                Marshal.FreeHGlobal(buffer);
                throw;
            }
        }

        private static string SidString(IntPtr sid)
        {
            if (sid == IntPtr.Zero)
            {
                throw new InvalidOperationException(
                    "token information contained a null SID"
                );
            }
            return new SecurityIdentifier(sid).Value;
        }

        private static string SidName(string sid)
        {
            try
            {
                SecurityIdentifier identifier =
                    new SecurityIdentifier(sid);
                return identifier.Translate(typeof(NTAccount)).Value;
            }
            catch (IdentityNotMappedException)
            {
                return "";
            }
        }

        private static TokenGroupRecord GroupRecord(
            SID_AND_ATTRIBUTES source
        )
        {
            string sid = SidString(source.Sid);
            return new TokenGroupRecord
            {
                Sid = sid,
                Name = SidName(sid),
                Attributes = source.Attributes,
                Enabled =
                    (source.Attributes & SE_GROUP_ENABLED) != 0,
                EnabledByDefault =
                    (source.Attributes & SE_GROUP_ENABLED_BY_DEFAULT) != 0,
                DenyOnly =
                    (source.Attributes & SE_GROUP_USE_FOR_DENY_ONLY) != 0,
                Integrity =
                    (source.Attributes & SE_GROUP_INTEGRITY) != 0,
                LogonId =
                    (source.Attributes & SE_GROUP_LOGON_ID) ==
                    SE_GROUP_LOGON_ID,
                Owner =
                    (source.Attributes & SE_GROUP_OWNER) != 0
            };
        }

        private static TokenGroupRecord[] ReadGroups(
            IntPtr tokenHandle,
            Int32 informationClass
        )
        {
            IntPtr buffer = QueryTokenBuffer(
                tokenHandle,
                informationClass
            );
            try
            {
                UInt32 count = unchecked((UInt32)Marshal.ReadInt32(buffer));
                Int32 offset = Marshal.OffsetOf(
                    typeof(TOKEN_GROUPS_HEADER),
                    "FirstGroup"
                ).ToInt32();
                Int32 elementSize = Marshal.SizeOf(
                    typeof(SID_AND_ATTRIBUTES)
                );
                List<TokenGroupRecord> result =
                    new List<TokenGroupRecord>();
                for (UInt32 index = 0; index < count; index++)
                {
                    IntPtr current = IntPtr.Add(
                        buffer,
                        checked(offset + ((Int32)index * elementSize))
                    );
                    SID_AND_ATTRIBUTES value =
                        (SID_AND_ATTRIBUTES)Marshal.PtrToStructure(
                            current,
                            typeof(SID_AND_ATTRIBUTES)
                        );
                    result.Add(GroupRecord(value));
                }
                return result.ToArray();
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        private static string PrivilegeName(ref LUID luid)
        {
            Int32 length = 256;
            StringBuilder value = new StringBuilder(length);
            if (!LookupPrivilegeNameW(null, ref luid, value, ref length))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "LookupPrivilegeNameW failed"
                );
            }
            return value.ToString();
        }

        private static TokenPrivilegeRecord[] ReadPrivileges(
            IntPtr tokenHandle
        )
        {
            IntPtr buffer = QueryTokenBuffer(
                tokenHandle,
                TokenPrivileges
            );
            try
            {
                UInt32 count = unchecked((UInt32)Marshal.ReadInt32(buffer));
                Int32 offset = Marshal.OffsetOf(
                    typeof(TOKEN_PRIVILEGES_HEADER),
                    "FirstPrivilege"
                ).ToInt32();
                Int32 elementSize = Marshal.SizeOf(
                    typeof(LUID_AND_ATTRIBUTES)
                );
                List<TokenPrivilegeRecord> result =
                    new List<TokenPrivilegeRecord>();
                for (UInt32 index = 0; index < count; index++)
                {
                    IntPtr current = IntPtr.Add(
                        buffer,
                        checked(offset + ((Int32)index * elementSize))
                    );
                    LUID_AND_ATTRIBUTES value =
                        (LUID_AND_ATTRIBUTES)Marshal.PtrToStructure(
                            current,
                            typeof(LUID_AND_ATTRIBUTES)
                        );
                    result.Add(new TokenPrivilegeRecord
                    {
                        Name = PrivilegeName(ref value.Luid),
                        Attributes = value.Attributes,
                        Enabled =
                            (value.Attributes & SE_PRIVILEGE_ENABLED) != 0,
                        EnabledByDefault =
                            (value.Attributes &
                             SE_PRIVILEGE_ENABLED_BY_DEFAULT) != 0,
                        Removed =
                            (value.Attributes & SE_PRIVILEGE_REMOVED) != 0,
                        UsedForAccess =
                            (value.Attributes &
                             SE_PRIVILEGE_USED_FOR_ACCESS) != 0
                    });
                }
                return result.ToArray();
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        private static string ReadSingleSid(
            IntPtr tokenHandle,
            Int32 informationClass
        )
        {
            IntPtr buffer = QueryTokenBuffer(
                tokenHandle,
                informationClass
            );
            try
            {
                SID_AND_ATTRIBUTES value =
                    (SID_AND_ATTRIBUTES)Marshal.PtrToStructure(
                        buffer,
                        typeof(SID_AND_ATTRIBUTES)
                    );
                return SidString(value.Sid);
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        public static ServiceProcessTokenRecord Inspect(UInt32 processId)
        {
            IntPtr processHandle = OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION,
                false,
                processId
            );
            if (processHandle == IntPtr.Zero)
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION) failed"
                );
            }
            try
            {
                IntPtr tokenHandle;
                if (!OpenProcessToken(
                    processHandle,
                    TOKEN_QUERY,
                    out tokenHandle
                ))
                {
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "OpenProcessToken(TOKEN_QUERY) failed"
                    );
                }
                try
                {
                    string userSid = ReadSingleSid(
                        tokenHandle,
                        TokenUser
                    );
                    return new ServiceProcessTokenRecord
                    {
                        ProcessId = processId,
                        UserSid = userSid,
                        UserName = SidName(userSid),
                        IntegritySid = ReadSingleSid(
                            tokenHandle,
                            TokenIntegrityLevel
                        ),
                        IsRestricted = IsTokenRestricted(tokenHandle),
                        Privileges = ReadPrivileges(tokenHandle),
                        Groups = ReadGroups(tokenHandle, TokenGroups),
                        RestrictedSids = ReadGroups(
                            tokenHandle,
                            TokenRestrictedSids
                        )
                    };
                }
                finally
                {
                    CloseHandle(tokenHandle);
                }
            }
            finally
            {
                CloseHandle(processHandle);
            }
        }
    }
}
'@ -ErrorAction Stop
}

function Get-CertificationServiceTokenSnapshot {
    Initialize-ServiceTokenProbeType
    $processes = Get-CertificationServiceProcessSnapshot
    $dangerousPrivileges = @(
        'SeDebugPrivilege',
        'SeTakeOwnershipPrivilege',
        'SeAssignPrimaryTokenPrivilege',
        'SeCreateTokenPrivilege'
    )
    $records = [Collections.Generic.List[object]]::new()
    foreach ($process in $processes) {
        $serviceName = [string]$process.name
        $gateway = $serviceName -eq $script:GatewayServiceName
        $expectedUserSID = if ($gateway) {
            [Security.Principal.NTAccount]::new(
                "NT SERVICE\$serviceName"
            ).Translate([Security.Principal.SecurityIdentifier]).Value
        } else {
            'S-1-5-18'
        }
        $expectedPrivileges = if ($gateway) {
            @('SeChangeNotifyPrivilege')
        } else {
            @(
                'SeBackupPrivilege',
                'SeChangeNotifyPrivilege',
                'SeImpersonatePrivilege',
                'SeRestorePrivilege',
                'SeTcbPrivilege'
            )
        }
        $serviceSID = [Security.Principal.NTAccount]::new(
            "NT SERVICE\$serviceName"
        ).Translate([Security.Principal.SecurityIdentifier]).Value
        $token = [DefenseClaw.Certification.ServiceTokenNative]::Inspect(
            [uint32]$process.process_id
        )
        if ([string]$token.UserSid -ne $expectedUserSID) {
            throw "$serviceName PID $($process.process_id) TokenUser $($token.UserSid), want $expectedUserSID"
        }
        if ([string]$token.IntegritySid -ne 'S-1-16-16384') {
            throw "$serviceName PID $($process.process_id) integrity $($token.IntegritySid), want system S-1-16-16384"
        }
        $actualPrivileges = @(
            $token.Privileges |
                ForEach-Object { [string]$_.Name } |
                Sort-Object -Unique
        )
        $dangerous = @(
            $actualPrivileges |
                Where-Object { $_ -in $dangerousPrivileges }
        )
        if ($dangerous.Count -gt 0) {
            throw "$serviceName PID $($process.process_id) retains dangerous token privileges: $($dangerous -join ',')"
        }
        $wantedPrivileges = @($expectedPrivileges | Sort-Object -Unique)
        if (($actualPrivileges -join "`n") -cne ($wantedPrivileges -join "`n")) {
            throw (
                "$serviceName PID $($process.process_id) actual token privileges " +
                "[$($actualPrivileges -join ',')] differ from required set " +
                "[$($wantedPrivileges -join ',')]"
            )
        }
        if (-not $gateway) {
            foreach ($boundedPrivilege in @(
                'SeBackupPrivilege',
                'SeRestorePrivilege'
            )) {
                $entry = @(
                    $token.Privileges |
                        Where-Object { [string]$_.Name -eq $boundedPrivilege }
                )
                if ($entry.Count -ne 1) {
                    throw (
                        "$serviceName PID $($process.process_id) must retain " +
                        "$boundedPrivilege exactly once at idle; count=$($entry.Count)"
                    )
                }
                if ([bool]$entry[0].Enabled -or
                    [bool]$entry[0].EnabledByDefault -or
                    [bool]$entry[0].Removed) {
                    throw (
                        "$serviceName PID $($process.process_id) must retain " +
                        "$boundedPrivilege present-but-disabled at idle; " +
                        "count=$($entry.Count) enabled=$($entry[0].Enabled) " +
                        "default=$($entry[0].EnabledByDefault) removed=$($entry[0].Removed)"
                    )
                }
            }
        }
        $serviceGroups = @(
            $token.Groups |
                Where-Object { [string]$_.Sid -eq $serviceSID }
        )
        if ($serviceGroups.Count -ne 1 -or [bool]$serviceGroups[0].DenyOnly) {
            throw "$serviceName PID $($process.process_id) lacks its non-deny-only service SID group $serviceSID"
        }
        $restrictedSIDs = @(
            $token.RestrictedSids |
                ForEach-Object { [string]$_.Sid }
        )
        if ($gateway) {
            if (-not [bool]$token.IsRestricted) {
                throw "$serviceName PID $($process.process_id) is not a restricted token"
            }
            foreach ($requiredSID in @($serviceSID, 'S-1-1-0', 'S-1-5-33')) {
                if ($requiredSID -notin $restrictedSIDs) {
                    throw "$serviceName PID $($process.process_id) restricted SID list omits $requiredSID"
                }
            }
            if (@($restrictedSIDs | Where-Object { $_ -like 'S-1-5-5-*' }).Count -ne 1) {
                throw "$serviceName PID $($process.process_id) restricted SID list lacks one exact service-logon SID"
            }
        } else {
            if ([bool]$token.IsRestricted -or $restrictedSIDs.Count -ne 0) {
                throw "$serviceName PID $($process.process_id) unexpectedly has a restricted token"
            }
        }
        $records.Add([pscustomobject]@{
            service = $serviceName
            process_id = [uint32]$process.process_id
            token_user_sid = [string]$token.UserSid
            token_user_name = [string]$token.UserName
            integrity_sid = [string]$token.IntegritySid
            restricted = [bool]$token.IsRestricted
            required_privileges = @($wantedPrivileges)
            actual_privileges = @(
                $token.Privileges |
                    Sort-Object Name |
                    ForEach-Object {
                        [pscustomobject]@{
                            name = [string]$_.Name
                            attributes = [uint32]$_.Attributes
                            enabled = [bool]$_.Enabled
                            enabled_by_default = [bool]$_.EnabledByDefault
                            removed = [bool]$_.Removed
                            used_for_access = [bool]$_.UsedForAccess
                        }
                    }
            )
            groups = @(
                $token.Groups |
                    Sort-Object Sid |
                    ForEach-Object {
                        [pscustomobject]@{
                            sid = [string]$_.Sid
                            name = [string]$_.Name
                            attributes = [uint32]$_.Attributes
                            enabled = [bool]$_.Enabled
                            enabled_by_default = [bool]$_.EnabledByDefault
                            deny_only = [bool]$_.DenyOnly
                            integrity = [bool]$_.Integrity
                            logon_id = [bool]$_.LogonId
                            owner = [bool]$_.Owner
                        }
                    }
            )
            restricted_sids = @(
                $token.RestrictedSids |
                    Sort-Object Sid |
                    ForEach-Object {
                        [pscustomobject]@{
                            sid = [string]$_.Sid
                            name = [string]$_.Name
                            attributes = [uint32]$_.Attributes
                        }
                    }
            )
        })
    }
    return $records.ToArray()
}

function Get-CertificationFailureActionContract {
    $records = [Collections.Generic.List[object]]::new()
    foreach ($serviceName in @(
        $script:GatewayServiceName,
        $script:GuardianServiceName
    )) {
        $key = "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"
        $properties = Get-ItemProperty -LiteralPath $key -ErrorAction Stop
        $bytes = [byte[]]$properties.FailureActions
        $byteLength = if ($null -eq $bytes) { 0 } else { $bytes.Length }
        if ($byteLength -ne 44) {
            throw "$serviceName FailureActions length is $byteLength, want exact 44-byte restart contract"
        }
        $resetSeconds = [BitConverter]::ToUInt32($bytes, 0)
        $rebootMessageOffset = [BitConverter]::ToUInt32($bytes, 4)
        $commandOffset = [BitConverter]::ToUInt32($bytes, 8)
        $actionCount = [BitConverter]::ToUInt32($bytes, 12)
        $actionOffset = [BitConverter]::ToUInt32($bytes, 16)
        $actions = [Collections.Generic.List[object]]::new()
        for ($index = 0; $index -lt [int]$actionCount; $index++) {
            $offset = [int]$actionOffset + ($index * 8)
            if ($offset -lt 20 -or ($offset + 8) -gt $bytes.Length) {
                throw "$serviceName FailureActions action $index escapes its exact registry value"
            }
            $actions.Add([pscustomobject]@{
                ordinal = $index + 1
                type = [BitConverter]::ToUInt32($bytes, $offset)
                delay_ms = [BitConverter]::ToUInt32($bytes, $offset + 4)
            })
        }
        $actualTypes = @($actions | ForEach-Object { [uint32]$_.type })
        $actualDelays = @($actions | ForEach-Object { [uint32]$_.delay_ms })
        if ($resetSeconds -ne 86400 -or
            $rebootMessageOffset -ne 0 -or
            $commandOffset -ne 0 -or
            $actionCount -ne 3 -or
            $actionOffset -ne 20 -or
            ($actualTypes -join ',') -cne '1,1,1' -or
            ($actualDelays -join ',') -cne '5000,15000,60000') {
            throw (
                "$serviceName recovery is not exactly restart 5s/15s/60s " +
                "with final restart repeated by SCM; reset=$resetSeconds " +
                "count=$actionCount types=$($actualTypes -join ',') " +
                "delays=$($actualDelays -join ',')"
            )
        }
        if ([int]$properties.FailureActionsOnNonCrashFailures -ne 1) {
            throw "$serviceName does not apply recovery to non-crash failures"
        }
        $records.Add([pscustomobject]@{
            service = $serviceName
            reset_seconds = [uint32]$resetSeconds
            actions = $actions.ToArray()
            final_action_repeats = $true
            non_crash_failures = $true
        })
    }
    return $records.ToArray()
}

function Wait-ForEnterpriseServiceReadiness(
    [string]$Label,
    [int]$TimeoutSeconds = 120
) {
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $report = Wait-Until `
        -Description "$Label authenticated enterprise readiness" `
        -TimeoutSeconds $TimeoutSeconds `
        -PollMilliseconds 1000 `
        -Condition {
            $verified = Invoke-EnterpriseInstallerJSON `
                -Action Verify `
                -GatewaySource '' `
                -HookSource '' `
                -CLISource '' `
                -Label ($Label + '-installer-verify')
            if (-not [bool]$verified.JSON.ok -or
                -not [bool]$verified.JSON.gateway_ready -or
                -not [bool]$verified.JSON.guardian_ready) {
                throw (
                    "$Label Verify was not fully ready: " +
                    "ok=$($verified.JSON.ok) " +
                    "gateway_ready=$($verified.JSON.gateway_ready) " +
                    "guardian_ready=$($verified.JSON.guardian_ready)"
                )
            }
            return $verified.JSON
        }
    $watch.Stop()
    return [pscustomobject]@{
        elapsed_seconds = [Math]::Round($watch.Elapsed.TotalSeconds, 3)
        gateway_ready = [bool]$report.gateway_ready
        guardian_ready = [bool]$report.guardian_ready
    }
}

function Invoke-ControlledServiceFailure(
    [string]$ServiceName,
    [int]$Ordinal,
    [int]$ExpectedDelaySeconds
) {
    Assert-CertificationServiceName $ServiceName 'controlled-failure'
    $service = Get-CimInstance `
        Win32_Service `
        -Filter "Name='$ServiceName'" `
        -ErrorAction Stop
    if ([string]$service.State -ne 'Running' -or [uint32]$service.ProcessId -eq 0) {
        throw "$ServiceName failure $Ordinal started from state=$($service.State) pid=$($service.ProcessId)"
    }
    $oldPID = [uint32]$service.ProcessId
    $expectedExecutable = ConvertTo-CanonicalPath (
        Join-Path $script:InstallRoot 'bin\defenseclaw-gateway.exe'
    )
    $liveProcess = Get-CimInstance `
        Win32_Process `
        -Filter "ProcessId=$oldPID" `
        -ErrorAction Stop
    if ($null -eq $liveProcess -or
        [string]::IsNullOrWhiteSpace([string]$liveProcess.ExecutablePath) -or
        -not [string]::Equals(
            (ConvertTo-CanonicalPath ([string]$liveProcess.ExecutablePath)),
            $expectedExecutable,
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        ([string]$service.PathName).IndexOf(
            '"' + $expectedExecutable + '"',
            [StringComparison]::OrdinalIgnoreCase
        ) -lt 0) {
        throw (
            "$ServiceName controlled failure PID $oldPID does not point to " +
            "the exact protected executable $expectedExecutable; " +
            "PathName=$($service.PathName) ExecutablePath=$($liveProcess.ExecutablePath)"
        )
    }
    $watch = [Diagnostics.Stopwatch]::StartNew()
    Stop-Process -Id $oldPID -Force -ErrorAction Stop
    $newProcess = Wait-Until `
        -Description "$ServiceName restart after controlled failure $Ordinal" `
        -TimeoutSeconds ($ExpectedDelaySeconds + 75) `
        -PollMilliseconds 250 `
        -Condition {
            $current = Get-CimInstance `
                Win32_Service `
                -Filter "Name='$ServiceName'" `
                -ErrorAction Stop
            if ([string]$current.State -eq 'Running' -and
                [uint32]$current.ProcessId -ne 0 -and
                [uint32]$current.ProcessId -ne $oldPID) {
                return [pscustomobject]@{
                    process_id = [uint32]$current.ProcessId
                    state = [string]$current.State
                }
            }
            return $null
        }
    $watch.Stop()
    $elapsedSeconds = $watch.Elapsed.TotalSeconds
    if ($elapsedSeconds -lt ([Math]::Max(0, $ExpectedDelaySeconds - 2))) {
        throw (
            "$ServiceName failure $Ordinal restarted in " +
            "$([Math]::Round($elapsedSeconds, 3))s, earlier than its " +
            "${ExpectedDelaySeconds}s configured recovery action"
        )
    }
    $readiness = Wait-ForEnterpriseServiceReadiness `
        -Label "$ServiceName-failure-$Ordinal"
    return [pscustomobject]@{
        ordinal = $Ordinal
        expected_delay_seconds = $ExpectedDelaySeconds
        observed_restart_seconds = [Math]::Round($elapsedSeconds, 3)
        previous_process_id = $oldPID
        restarted_process_id = [uint32]$newProcess.process_id
        authenticated_readiness = $readiness
    }
}

function Assert-ExplicitServiceStopDoesNotRecover(
    [string]$ServiceName,
    [int]$ObservationSeconds = 70
) {
    Stop-Service -Name $ServiceName -ErrorAction Stop
    Wait-Until `
        -Description "$ServiceName explicit administrator stop" `
        -TimeoutSeconds 30 `
        -Condition {
            $current = Get-CimInstance `
                Win32_Service `
                -Filter "Name='$ServiceName'" `
                -ErrorAction Stop
            return (
                [string]$current.State -eq 'Stopped' -and
                [uint32]$current.ProcessId -eq 0
            )
        } | Out-Null
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($ObservationSeconds)
    do {
        $current = Get-CimInstance `
            Win32_Service `
            -Filter "Name='$ServiceName'" `
            -ErrorAction Stop
        if ([string]$current.State -ne 'Stopped' -or
            [uint32]$current.ProcessId -ne 0) {
            throw (
                "$ServiceName restarted after an explicit administrator Stop " +
                "state=$($current.State) pid=$($current.ProcessId)"
            )
        }
        Start-Sleep -Milliseconds 500
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    return [pscustomobject]@{
        service = $ServiceName
        observation_seconds = $ObservationSeconds
        remained_stopped = $true
    }
}

function Test-ServiceFailureRecovery {
    $contract = Get-CertificationFailureActionContract
    $controlBefore = Get-ServiceControlSnapshot 'before-recovery-sequence'
    $deploymentBefore = Get-DeploymentDigests
    $serviceRuns = [Collections.Generic.List[object]]::new()
    foreach ($serviceName in @(
        $script:GatewayServiceName,
        $script:GuardianServiceName
    )) {
        $failures = [Collections.Generic.List[object]]::new()
        $delays = @(5, 15, 60, 60)
        for ($index = 0; $index -lt $delays.Count; $index++) {
            $failures.Add(
                (Invoke-ControlledServiceFailure `
                    -ServiceName $serviceName `
                    -Ordinal ($index + 1) `
                    -ExpectedDelaySeconds ($delays[$index]))
            )
        }
        $explicitStop = Assert-ExplicitServiceStopDoesNotRecover `
            -ServiceName $serviceName `
            -ObservationSeconds 70
        Start-Service -Name $serviceName -ErrorAction Stop
        Wait-ForServicesRunning
        $postExplicitStartReadiness = Wait-ForEnterpriseServiceReadiness `
            -Label "$serviceName-post-explicit-start"
        $serviceRuns.Add([pscustomobject]@{
            service = $serviceName
            unexpected_failures = $failures.ToArray()
            explicit_stop = $explicitStop
            post_explicit_start_readiness = $postExplicitStartReadiness
        })
    }
    $null = Invoke-GuardianServiceReconcile `
        -Label 'post-recovery-sequence-localsystem-reconcile'
    Wait-ForServicesRunning
    $null = Assert-HealthyGuardianJSON 'service-recovery-sequence'
    $null = Get-CertificationServiceTokenSnapshot
    Assert-SameDigests `
        $deploymentBefore `
        (Get-DeploymentDigests) `
        'service recovery sequence'
    Assert-SameServiceControlSnapshot `
        $controlBefore `
        (Get-ServiceControlSnapshot 'after-recovery-sequence') `
        'service recovery sequence'
    return [pscustomobject]@{
        contract = $contract
        observations = $serviceRuns.ToArray()
    }
}

function Test-QueuedFailureRestartDuringServicing {
    $controlBefore = Get-ServiceControlSnapshot `
        'before-queued-restart-servicing'
    $deploymentBefore = Get-DeploymentDigests
    $gateway = Get-CimInstance `
        Win32_Service `
        -Filter "Name='$($script:GatewayServiceName)'" `
        -ErrorAction Stop
    if ([string]$gateway.State -ne 'Running' -or
        [uint32]$gateway.ProcessId -eq 0) {
        throw (
            'queued-restart servicing proof requires a running gateway; ' +
            "state=$($gateway.State) pid=$($gateway.ProcessId)"
        )
    }
    $failedPID = [uint32]$gateway.ProcessId
    $failedAt = [DateTimeOffset]::UtcNow
    Stop-Process -Id $failedPID -Force -ErrorAction Stop
    $null = Wait-Until `
        -Description 'gateway unexpected failure before servicing' `
        -TimeoutSeconds 10 `
        -PollMilliseconds 50 `
        -Condition {
            $current = Get-CimInstance `
                Win32_Service `
                -Filter "Name='$($script:GatewayServiceName)'" `
                -ErrorAction Stop
            return (
                [string]$current.State -eq 'Stopped' -and
                [uint32]$current.ProcessId -eq 0
            )
        }

    # Test-ServiceFailureRecovery has already exercised all four configured
    # actions. The next unexpected gateway failure therefore schedules the
    # final repeated SC_ACTION_RESTART after 60 seconds. Observe the whole
    # Repair -NoStart transaction and fail if either service becomes startable
    # or obtains a PID after the transaction first reaches disabled/stopped.
    $monitor = [pscustomobject]@{
        samples = 0
        quiesced_observed = $false
        quiesced_at = ''
        post_quiescence_samples = 0
        violations = [Collections.Generic.List[object]]::new()
    }
    $observeDisabledServicing = {
        param($RunningProcess)
        $null = $RunningProcess
        $rows = @(
            foreach ($name in @(
                $script:GatewayServiceName,
                $script:GuardianServiceName
            )) {
                $service = Get-CimInstance `
                    Win32_Service `
                    -Filter "Name='$name'" `
                    -ErrorAction Stop
                [pscustomobject]@{
                    name = $name
                    state = [string]$service.State
                    start_mode = [string]$service.StartMode
                    process_id = [uint32]$service.ProcessId
                }
            }
        )
        $monitor.samples = [int]$monitor.samples + 1
        $allQuiesced = @($rows | Where-Object {
            [string]$_.state -ne 'Stopped' -or
            [string]$_.start_mode -ne 'Disabled' -or
            [uint32]$_.process_id -ne 0
        }).Count -eq 0
        if ($allQuiesced) {
            if (-not [bool]$monitor.quiesced_observed) {
                $monitor.quiesced_observed = $true
                $monitor.quiesced_at =
                    [DateTimeOffset]::UtcNow.ToString('o')
            }
            $monitor.post_quiescence_samples =
                [int]$monitor.post_quiescence_samples + 1
        } elseif ([bool]$monitor.quiesced_observed) {
            $monitor.violations.Add([pscustomobject]@{
                observed_at = [DateTimeOffset]::UtcNow.ToString('o')
                services = $rows
            })
        }
    }

    $watch = [Diagnostics.Stopwatch]::StartNew()
    $staged = Invoke-EnterpriseInstallerJSON `
        -Action Repair `
        -NoStart `
        -DuringExecution $observeDisabledServicing `
        -ExecutionPollMilliseconds 100 `
        -Label 'repair-queued-restart-no-start'
    $watch.Stop()
    if (-not [bool]$staged.JSON.ok -or
        [bool]$staged.JSON.transaction_pending -or
        [string]$staged.JSON.gateway_service_state -cne 'stopped' -or
        [string]$staged.JSON.guardian_service_state -cne 'stopped' -or
        [bool]$staged.JSON.gateway_ready -or
        [bool]$staged.JSON.guardian_ready) {
        throw (
            'Repair -NoStart did not commit exact disabled/stopped state ' +
            'during a queued failure restart: ' +
            (Protect-SensitiveDisplayText (
                $staged.JSON | ConvertTo-Json -Compress -Depth 7
            ))
        )
    }
    if ($watch.Elapsed.TotalSeconds -lt 63) {
        throw (
            'Repair -NoStart did not hold a fresh 65-second failure-restart ' +
            "barrier; elapsed=$([Math]::Round($watch.Elapsed.TotalSeconds, 3))s"
        )
    }
    if (-not [bool]$monitor.quiesced_observed -or
        [int]$monitor.post_quiescence_samples -lt 100 -or
        $monitor.violations.Count -ne 0) {
        throw (
            'queued-restart servicing monitor did not observe a continuous ' +
            'disabled/stopped drain: ' +
            (Protect-SensitiveDisplayText (
                $monitor | ConvertTo-Json -Compress -Depth 7
            ))
        )
    }
    Start-Sleep -Seconds 2
    foreach ($name in @(
        $script:GatewayServiceName,
        $script:GuardianServiceName
    )) {
        $service = Get-CimInstance `
            Win32_Service `
            -Filter "Name='$name'" `
            -ErrorAction Stop
        if ([string]$service.State -ne 'Stopped' -or
            [string]$service.StartMode -ne 'Disabled' -or
            [uint32]$service.ProcessId -ne 0) {
            throw (
                "queued restart survived the drain for ${name}: " +
                "state=$($service.State) start=$($service.StartMode) " +
                "pid=$($service.ProcessId)"
            )
        }
    }

    $reactivated = Invoke-EnterpriseInstallerJSON `
        -Action Repair `
        -Label 'repair-after-queued-restart-drain'
    if (-not [bool]$reactivated.JSON.ok -or
        [bool]$reactivated.JSON.transaction_pending -or
        [string]$reactivated.JSON.gateway_service_state -cne 'running' -or
        [string]$reactivated.JSON.guardian_service_state -cne 'running' -or
        -not [bool]$reactivated.JSON.gateway_ready -or
        -not [bool]$reactivated.JSON.guardian_ready) {
        throw (
            'public Repair did not re-establish guardian-first readiness ' +
            'after queued-restart drain: ' +
            (Protect-SensitiveDisplayText (
                $reactivated.JSON | ConvertTo-Json -Compress -Depth 7
            ))
        )
    }
    Wait-ForServicesRunning
    $null = Assert-HealthyGuardianJSON 'queued-restart-servicing'
    Assert-SameDigests `
        $deploymentBefore `
        (Get-DeploymentDigests) `
        'queued-restart servicing'
    Assert-SameServiceControlSnapshot `
        $controlBefore `
        (Get-ServiceControlSnapshot 'after-queued-restart-servicing') `
        'queued-restart servicing'
    return [pscustomobject]@{
        failed_gateway_pid = $failedPID
        unexpected_failure_at = $failedAt.ToString('o')
        no_start_elapsed_seconds =
            [Math]::Round($watch.Elapsed.TotalSeconds, 3)
        quiesced_observed = [bool]$monitor.quiesced_observed
        quiesced_at = [string]$monitor.quiesced_at
        total_monitor_samples = [int]$monitor.samples
        post_quiescence_samples =
            [int]$monitor.post_quiescence_samples
        post_quiescence_violations = $monitor.violations.Count
        queued_restart_delay_seconds = 60
        fresh_drain_required_seconds = 65
        no_start_committed_disabled_stopped = $true
        guardian_first_reactivation_ready = $true
    }
}

function Assert-SameServiceControlSnapshot(
    [object]$Before,
    [object]$After,
    [string]$Label
) {
    foreach ($property in $Before.PSObject.Properties) {
        $name = $property.Name
        $beforeJSON = $property.Value | ConvertTo-Json -Compress -Depth 6
        $afterProperty = $After.PSObject.Properties[$name]
        if ($null -eq $afterProperty) {
            throw "$Label removed service $name"
        }
        $afterJSON = $afterProperty.Value | ConvertTo-Json -Compress -Depth 6
        if ($beforeJSON -cne $afterJSON) {
            throw "$Label changed service contract for $name"
        }
        $service = Get-Service -Name $name -ErrorAction Stop
        if ($service.Status -ne [ServiceProcess.ServiceControllerStatus]::Running) {
            throw "$Label left service $name in $($service.Status)"
        }
    }
}

function Wait-ForServicesRunning {
    Wait-Until -Description 'both certification services to be running' -Condition {
        $gateway = Get-Service -Name $script:GatewayServiceName -ErrorAction SilentlyContinue
        $guardian = Get-Service -Name $script:GuardianServiceName -ErrorAction SilentlyContinue
        return (
            $null -ne $gateway -and
            $null -ne $guardian -and
            $gateway.Status -eq [ServiceProcess.ServiceControllerStatus]::Running -and
            $guardian.Status -eq [ServiceProcess.ServiceControllerStatus]::Running
        )
    } | Out-Null
}

function Get-AccessRules([string]$Path) {
    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    return @($acl.Access)
}

function Assert-NoStandardUserAccess(
    [string]$Path,
    [string]$SID,
    [switch]$DenyRead,
    [switch]$DenyWrite
) {
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "protected path is missing: $Path"
    }
    $rules = Get-AccessRules $Path
    $dangerous = [Security.AccessControl.FileSystemRights](
        [Security.AccessControl.FileSystemRights]::WriteData -bor
        [Security.AccessControl.FileSystemRights]::AppendData -bor
        [Security.AccessControl.FileSystemRights]::CreateFiles -bor
        [Security.AccessControl.FileSystemRights]::CreateDirectories -bor
        [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership -bor
        [Security.AccessControl.FileSystemRights]::FullControl -bor
        [Security.AccessControl.FileSystemRights]::Modify
    )
    foreach ($rule in $rules) {
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) {
            continue
        }
        $identity = [string]$rule.IdentityReference
        $isTarget = $identity -eq $SID
        $isBroad = $identity -in @(
            'Everyone',
            'NT AUTHORITY\Authenticated Users',
            'BUILTIN\Users'
        )
        if (-not ($isTarget -or $isBroad)) { continue }
        if ($DenyWrite -and ($rule.FileSystemRights -band $dangerous) -ne 0) {
            throw "untrusted principal $identity can write $Path via $($rule.FileSystemRights)"
        }
        if ($DenyRead -and
            ($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::Read) -ne 0) {
            throw "untrusted principal $identity can read $Path via $($rule.FileSystemRights)"
        }
    }
}

function Invoke-StandardUserControlProbe {
    $processes = Get-CertificationServiceProcessSnapshot
    $inputObject = [ordered]@{
        gateway_service = $script:GatewayServiceName
        guardian_service = $script:GuardianServiceName
        gateway_binary = Join-Path $script:InstallRoot 'bin\defenseclaw-gateway.exe'
        hook_binary = Join-Path $script:InstallRoot 'bin\defenseclaw-hook.exe'
        config = Join-Path $script:StateRoot 'etc\config.yaml'
        manifest = Join-Path $script:StateRoot 'hook-guardian\targets.yaml'
        ledger = Join-Path $script:StateRoot 'hook-guardian-state\protected_targets.json'
        service_tokens = @(
            if (-not $ClaudeOnly) {
                [ordered]@{
                    name = 'codex'
                    path = Join-Path `
                        $script:StateRoot `
                        'runtime\hooks\.hook-codex.token'
                }
            }
            [ordered]@{
                name = 'claudecode'
                path = Join-Path `
                    $script:StateRoot `
                    'runtime\hooks\.hook-claudecode.token'
            }
        )
        claude_machine_paths = @(
            [ordered]@{
                name = 'policy'
                path = $script:ClaudeManagedPolicyPath
            },
            [ordered]@{
                name = 'state'
                path = $script:ClaudeManagedStatePath
            },
            [ordered]@{
                name = 'lock'
                path = $script:ClaudeManagedLockPath
            }
        )
        connector = if ($ClaudeOnly) { 'claudecode' } else { 'codex' }
        codex_target_enabled = -not [bool]$ClaudeOnly
        codex_vendor_directory = $script:CodexVendorDirectory
        codex_machine_policy_directory = $script:CodexMachinePolicyDirectory
        probe_nonce = $script:RunToken
        probe_sid = $script:HostileSID
        target_user = $script:PrimaryUserName
        target_home = $script:PrimaryProfile
        target_sid = $script:PrimarySID
        gateway_pid = [uint32]$processes[0].process_id
        guardian_pid = [uint32]$processes[1].process_id
    }
    $inputBase64 = [Convert]::ToBase64String(
        [Text.Encoding]::UTF8.GetBytes(($inputObject | ConvertTo-Json -Compress -Depth 5))
    )
    $probe = @'
$ErrorActionPreference = 'Stop'
$inputJSON = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__INPUT__'))
$input = $inputJSON | ConvertFrom-Json -ErrorAction Stop
$checks = [Collections.Generic.List[object]]::new()
function Add-Probe([string]$Name, [bool]$Denied, [string]$Detail) {
    $checks.Add([pscustomobject]@{ name = $Name; denied = $Denied; detail = $Detail })
}
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class DefenseClawHostileNative {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(
        UInt32 desiredAccess,
        bool inheritHandle,
        UInt32 processId
    );

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern IntPtr CreateFileW(
        string fileName,
        UInt32 desiredAccess,
        UInt32 shareMode,
        IntPtr securityAttributes,
        UInt32 creationDisposition,
        UInt32 flagsAndAttributes,
        IntPtr templateFile
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CloseHandle(IntPtr handle);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool OpenProcessToken(
        IntPtr processHandle,
        UInt32 desiredAccess,
        out IntPtr tokenHandle
    );
}
"@ -ErrorAction Stop
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
$adminEnabled = $principal.IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)
$windowsDirectory = [Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)
$system32 = Join-Path $windowsDirectory 'System32'
$groupText = & (Join-Path $system32 'whoami.exe') /groups /fo csv /nh 2>$null |
    Out-String
$mediumIntegrity = $groupText -match 'S-1-16-8192'
Add-Probe `
    'probe_exact_non_admin_identity' `
    ($identity.User.Value -eq [string]$input.probe_sid -and -not $adminEnabled -and $mediumIntegrity) `
    ("sid=" + $identity.User.Value + "; admin_enabled=" + $adminEnabled + "; medium=" + $mediumIntegrity)
function Test-WriteHandle([string]$Name, [string]$Path) {
    $invalid = [IntPtr]::new(-1)
    $handle = [DefenseClawHostileNative]::CreateFileW(
        $Path,
        0x40000000,
        0x00000007,
        [IntPtr]::Zero,
        3,
        0,
        [IntPtr]::Zero
    )
    if ($handle -eq $invalid) {
        $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Add-Probe `
            $Name `
            ($errorCode -eq 5) `
            ("CreateFileW GENERIC_WRITE error " + $errorCode +
                " (want ERROR_ACCESS_DENIED=5)")
        return
    }
    try {
        Add-Probe $Name $false 'GENERIC_WRITE handle was granted'
    } finally {
        [void][DefenseClawHostileNative]::CloseHandle($handle)
    }
}
function Test-DeleteHandle(
    [string]$Name,
    [string]$Path,
    [bool]$Directory = $false
) {
    $invalid = [IntPtr]::new(-1)
    $flags = if ($Directory) { 0x02000000 } else { 0 }
    $handle = [DefenseClawHostileNative]::CreateFileW(
        $Path,
        0x00010000,
        0x00000007,
        [IntPtr]::Zero,
        3,
        $flags,
        [IntPtr]::Zero
    )
    if ($handle -eq $invalid) {
        $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Add-Probe $Name ($errorCode -eq 5) ("CreateFileW DELETE error " + $errorCode)
        return
    }
    try {
        Add-Probe $Name $false 'DELETE handle was granted'
    } finally {
        [void][DefenseClawHostileNative]::CloseHandle($handle)
    }
}
function Test-ChangeACLDenied([string]$Name, [string]$Path) {
    try {
        $sections = [Security.AccessControl.AccessControlSections]::Access
        $beforeSDDL = (Get-Acl -LiteralPath $Path).
            GetSecurityDescriptorSddlForm($sections)
        $icacls = Join-Path $system32 'icacls.exe'
        & $icacls `
            $Path `
            /grant `
            ("*" + [string]$input.probe_sid + ':F') `
            1>$null `
            2>$null
        $code = $LASTEXITCODE
        $afterSDDL = (Get-Acl -LiteralPath $Path).
            GetSecurityDescriptorSddlForm($sections)
        Add-Probe `
            $Name `
            ($code -eq 5 -and $beforeSDDL -ceq $afterSDDL) `
            ("icacls.exe exit " + $code +
                " (want ERROR_ACCESS_DENIED=5); unchanged=" +
                ($beforeSDDL -ceq $afterSDDL))
    } catch [UnauthorizedAccessException] {
        Add-Probe $Name $true 'Get-Acl access denied before any change'
    } catch {
        Add-Probe $Name $false $_.Exception.Message
    }
}
function Test-CodexSharedDirectoryBoundary([string]$Name, [string]$Path) {
    try {
        $null = @(Get-ChildItem -LiteralPath $Path -Force)
        Add-Probe ('read_traverse_' + $Name) $true 'read/traverse succeeded'
    } catch {
        Add-Probe ('read_traverse_' + $Name) $false $_.Exception.Message
    }
    $candidate = Join-Path $Path (
        '.defenseclaw-standard-user-create-' + [string]$input.probe_nonce
    )
    try {
        $stream = [IO.File]::Open(
            $candidate,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write,
            [IO.FileShare]::None
        )
        $stream.Dispose()
        Add-Probe ('create_child_' + $Name) $false 'child creation succeeded'
    } catch [UnauthorizedAccessException] {
        Add-Probe ('create_child_' + $Name) $true 'access denied'
    } catch [IO.IOException] {
        Add-Probe `
            ('create_child_' + $Name) `
            $false `
            ('non-authorization I/O failure: ' + $_.Exception.Message)
    } finally {
        if (Test-Path -LiteralPath $candidate) {
            Remove-Item -LiteralPath $candidate -Force -ErrorAction SilentlyContinue
        }
    }
    Test-DeleteHandle ('delete_directory_handle_' + $Name) $Path $true
    try {
        $sections = [Security.AccessControl.AccessControlSections]::Access
        $beforeSDDL = (Get-Acl -LiteralPath $Path).
            GetSecurityDescriptorSddlForm($sections)
        $icacls = Join-Path $system32 'icacls.exe'
        & $icacls `
            $Path `
            /grant `
            ("*" + [string]$input.probe_sid + ':(OI)(CI)F') `
            1>$null `
            2>$null
        $afterSDDL = (Get-Acl -LiteralPath $Path).
            GetSecurityDescriptorSddlForm($sections)
        Add-Probe `
            ('change_acl_' + $Name) `
            ($LASTEXITCODE -ne 0 -and $beforeSDDL -ceq $afterSDDL) `
            ("icacls.exe exit " + $LASTEXITCODE + "; unchanged=" + ($beforeSDDL -ceq $afterSDDL))
    } catch [UnauthorizedAccessException] {
        Add-Probe ('change_acl_' + $Name) $true 'access denied'
    } catch {
        Add-Probe ('change_acl_' + $Name) $false $_.Exception.Message
    }
}
if ([bool]$input.codex_target_enabled) {
    Test-CodexSharedDirectoryBoundary `
        'codex_vendor_directory' `
        ([string]$input.codex_vendor_directory)
    Test-CodexSharedDirectoryBoundary `
        'codex_machine_policy_directory' `
        ([string]$input.codex_machine_policy_directory)
}
foreach ($entry in @(
    @('write_gateway_binary', [string]$input.gateway_binary),
    @('write_hook_binary', [string]$input.hook_binary),
    @('write_managed_config', [string]$input.config),
    @('write_guardian_manifest', [string]$input.manifest),
    @('forge_authorization_ledger', [string]$input.ledger)
)) {
    Test-WriteHandle $entry[0] $entry[1]
    Test-DeleteHandle ('delete_handle_' + $entry[0]) $entry[1]
}
foreach ($entry in @($input.claude_machine_paths)) {
    $name = [string]$entry.name
    $path = [string]$entry.path
    Test-WriteHandle ('write_claude_machine_' + $name) $path
    Test-DeleteHandle ('delete_claude_machine_' + $name) $path
    Test-ChangeACLDenied ('change_acl_claude_machine_' + $name) $path
}
foreach ($entry in @($input.service_tokens)) {
    $tokenName = [string]$entry.name
    $tokenPath = [string]$entry.path
    Test-WriteHandle ('write_service_token_' + $tokenName) $tokenPath
    Test-DeleteHandle ('delete_service_token_' + $tokenName) $tokenPath
    $credentialHandle = [DefenseClawHostileNative]::CreateFileW(
        $tokenPath,
        0x80000000,
        0x00000007,
        [IntPtr]::Zero,
        3,
        0,
        [IntPtr]::Zero
    )
    $invalid = [IntPtr]::new(-1)
    if ($credentialHandle -eq $invalid) {
        $credentialError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Add-Probe `
            ('read_service_scoped_credential_' + $tokenName) `
            ($credentialError -eq 5) `
            ("CreateFileW GENERIC_READ error " + $credentialError +
                " (want ERROR_ACCESS_DENIED=5)")
    } else {
        try {
            Add-Probe `
                ('read_service_scoped_credential_' + $tokenName) `
                $false `
                'GENERIC_READ handle was granted (content was not read)'
        } finally {
            [void][DefenseClawHostileNative]::CloseHandle($credentialHandle)
        }
    }
}
foreach ($process in @(
    [pscustomobject]@{
        service = [string]$input.gateway_service
        pid = [uint32]$input.gateway_pid
    },
    [pscustomobject]@{
        service = [string]$input.guardian_service
        pid = [uint32]$input.guardian_pid
    }
)) {
    foreach ($access in @(
        [pscustomobject]@{ name = 'terminate'; mask = [uint32]0x00000001 },
        [pscustomobject]@{ name = 'create_thread'; mask = [uint32]0x00000002 },
        [pscustomobject]@{ name = 'vm_operation'; mask = [uint32]0x00000008 },
        [pscustomobject]@{ name = 'vm_write'; mask = [uint32]0x00000020 },
        [pscustomobject]@{ name = 'dup_handle'; mask = [uint32]0x00000040 },
        [pscustomobject]@{ name = 'set_quota'; mask = [uint32]0x00000100 },
        [pscustomobject]@{ name = 'set_information'; mask = [uint32]0x00000200 },
        [pscustomobject]@{ name = 'suspend_resume'; mask = [uint32]0x00000800 },
        [pscustomobject]@{
            name = 'inject_thread_vm'
            mask = [uint32](0x00000002 -bor 0x00000008 -bor 0x00000020)
        },
        [pscustomobject]@{ name = 'write_dac'; mask = [uint32]0x00040000 },
        [pscustomobject]@{ name = 'write_owner'; mask = [uint32]0x00080000 },
        [pscustomobject]@{ name = 'all_access'; mask = [uint32]0x001F0FFF }
    )) {
        $handle = [DefenseClawHostileNative]::OpenProcess(
            [uint32]$access.mask,
            $false,
            [uint32]$process.pid
        )
        if ($handle -eq [IntPtr]::Zero) {
            $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Add-Probe `
                ('open_process_' + [string]$access.name + '_' + [string]$process.service) `
                ($errorCode -eq 5) `
                ("OpenProcess access 0x" + ([uint32]$access.mask).ToString('X8') + " error " + $errorCode)
        } else {
            try {
                Add-Probe `
                    ('open_process_' + [string]$access.name + '_' + [string]$process.service) `
                    $false `
                    ("OpenProcess granted access 0x" + ([uint32]$access.mask).ToString('X8'))
            } finally {
                [void][DefenseClawHostileNative]::CloseHandle($handle)
            }
        }
    }
    $queryHandle = [DefenseClawHostileNative]::OpenProcess(
        0x00001000,
        $false,
        [uint32]$process.pid
    )
    if ($queryHandle -eq [IntPtr]::Zero) {
        $queryError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Add-Probe `
            ('open_process_query_limited_' + [string]$process.service) `
            $false `
            ("OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION) error " + $queryError)
    } else {
        try {
            Add-Probe `
                ('open_process_query_limited_' + [string]$process.service) `
                $true `
                'query-limited handle granted as expected'
            foreach ($tokenAccess in @(
                [pscustomobject]@{ name = 'assign_primary'; mask = [uint32]0x00000001 },
                [pscustomobject]@{ name = 'duplicate'; mask = [uint32]0x00000002 },
                [pscustomobject]@{ name = 'impersonate'; mask = [uint32]0x00000004 },
                [pscustomobject]@{ name = 'adjust_privileges'; mask = [uint32]0x00000020 },
                [pscustomobject]@{ name = 'adjust_groups'; mask = [uint32]0x00000040 },
                [pscustomobject]@{ name = 'adjust_default'; mask = [uint32]0x00000080 },
                [pscustomobject]@{ name = 'write_dac'; mask = [uint32]0x00040000 },
                [pscustomobject]@{ name = 'write_owner'; mask = [uint32]0x00080000 },
                [pscustomobject]@{ name = 'all_mutation'; mask = [uint32]0x000C00E7 }
            )) {
                $tokenHandle = [IntPtr]::Zero
                $opened = [DefenseClawHostileNative]::OpenProcessToken(
                    $queryHandle,
                    [uint32]$tokenAccess.mask,
                    [ref]$tokenHandle
                )
                if (-not $opened) {
                    $tokenError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    Add-Probe `
                        ('open_process_token_' + [string]$tokenAccess.name + '_' + [string]$process.service) `
                        ($tokenError -eq 5) `
                        ("OpenProcessToken access 0x" + ([uint32]$tokenAccess.mask).ToString('X8') + " error " + $tokenError)
                } else {
                    try {
                        Add-Probe `
                            ('open_process_token_' + [string]$tokenAccess.name + '_' + [string]$process.service) `
                            $false `
                            ("OpenProcessToken granted access 0x" + ([uint32]$tokenAccess.mask).ToString('X8'))
                    } finally {
                        [void][DefenseClawHostileNative]::CloseHandle($tokenHandle)
                    }
                }
            }
        } finally {
            [void][DefenseClawHostileNative]::CloseHandle($queryHandle)
        }
    }
    $taskkill = Join-Path $system32 'taskkill.exe'
    & $taskkill /PID ([string]$process.pid) /F 1>$null 2>$null
    Add-Probe `
        ('taskkill_process_' + [string]$process.service) `
        ($LASTEXITCODE -ne 0) `
        ("taskkill.exe exit " + $LASTEXITCODE)
}
foreach ($service in @([string]$input.gateway_service, [string]$input.guardian_service)) {
    $sc = Join-Path $system32 'sc.exe'
    & $sc query $service 1>$null 2>$null
    Add-Probe ("query_service_" + $service) ($LASTEXITCODE -eq 0) ("sc.exe exit " + $LASTEXITCODE)
    foreach ($operation in @(
        [pscustomobject]@{ name = 'stop'; args = @('stop', $service) },
        [pscustomobject]@{ name = 'pause'; args = @('pause', $service) },
        [pscustomobject]@{ name = 'control128'; args = @('control', $service, '128') },
        [pscustomobject]@{ name = 'config'; args = @('config', $service, 'start=', 'disabled') },
        [pscustomobject]@{
            name = 'failure'
            args = @('failure', $service, 'reset=', '86400', 'actions=', 'restart/5000')
        },
        [pscustomobject]@{
            name = 'sdset'
            args = @(
                'sdset',
                $service,
                'D:(A;;CCLCSWLOCRRC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)'
            )
        },
        [pscustomobject]@{ name = 'delete'; args = @('delete', $service) }
    )) {
        $operationArguments = @($operation.args)
        & $sc @operationArguments 1>$null 2>$null
        $code = $LASTEXITCODE
        Add-Probe `
            ($operation.name + '_service_' + $service) `
            ($code -eq 5) `
            ("sc.exe exit " + $code + " (want ERROR_ACCESS_DENIED=5)")
    }
    try {
        $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
            "SYSTEM\CurrentControlSet\Services\$service",
            $true
        )
        if ($null -eq $key) {
            Add-Probe `
                ("write_service_registry_" + $service) `
                $false `
                'writable key returned null without an ACCESS_DENIED exception'
        } else {
            $key.Dispose()
            Add-Probe ("write_service_registry_" + $service) $false 'writable service key opened'
        }
    } catch [Security.SecurityException] {
        Add-Probe ("write_service_registry_" + $service) $true 'access denied'
    } catch [UnauthorizedAccessException] {
        Add-Probe ("write_service_registry_" + $service) $true 'access denied'
    }
}
$oldConfig = $env:DEFENSECLAW_CONFIG
$oldHome = $env:DEFENSECLAW_HOME
$oldMode = $env:DEFENSECLAW_DEPLOYMENT_MODE
try {
    $env:DEFENSECLAW_CONFIG = [string]$input.config
    $env:DEFENSECLAW_HOME = Split-Path -Parent (Split-Path -Parent ([string]$input.config))
    $env:DEFENSECLAW_DEPLOYMENT_MODE = 'managed_enterprise'
    $output = & ([string]$input.gateway_binary) enterprise hooks uninstall `
        --connector ([string]$input.connector) `
        --user-home ([string]$input.target_home) `
        --sid ([string]$input.target_sid) `
        --json 2>&1 | Out-String
    $exitCode = $LASTEXITCODE
    $causal = (
        $exitCode -ne 0 -and
        ([string]$output -match '(?i)LocalSystem|authoriz|elevat|privilege|access denied|guardian')
    )
    Add-Probe `
        'unregister_permanent_protection' `
        $causal `
        ("exit " + $exitCode + "; authorization_boundary=" + $causal + "; output=" + ([string]$output).Trim())
} finally {
    $env:DEFENSECLAW_CONFIG = $oldConfig
    $env:DEFENSECLAW_HOME = $oldHome
    $env:DEFENSECLAW_DEPLOYMENT_MODE = $oldMode
}
$failed = @($checks | Where-Object { -not $_.denied })
[pscustomobject]@{
    ok = $failed.Count -eq 0
    checks = $checks
    failed = @($failed.name)
} | ConvertTo-Json -Compress -Depth 6
if ($failed.Count -ne 0) { exit 17 }
'@.Replace('__INPUT__', $inputBase64)

    $result = Invoke-UserPowerShell `
        -Credential $script:HostileCredential `
        -Script $probe `
        -Label 'standard-user-control-probe' `
        -AllowedExitCodes @(0, 17) `
        -TimeoutSeconds 180
    $json = ConvertFrom-SingleJSONDocument $result.StdOut 'standard-user-control-probe'
    if (-not [bool]$json.ok -or $result.ExitCode -ne 0) {
        throw "standard user crossed protected boundary: $(@($json.failed) -join ', ')"
    }
    return "all $(@($json.checks).Count) protected operations were denied"
}

function Assert-ProtectedUserTamperToken {
    $result = Invoke-ActiveUserPowerShell `
        -Label 'protected-active-user-token' `
        -Script @'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
$windowsDirectory = [Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)
$groups = & (Join-Path $windowsDirectory 'System32\whoami.exe') /groups /fo csv /nh 2>$null |
    Out-String
[pscustomobject]@{
    sid = $identity.User.Value
    admin_enabled = $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
    medium_integrity = $groups -match 'S-1-16-8192'
    session_id = [Diagnostics.Process]::GetCurrentProcess().SessionId
} | ConvertTo-Json -Compress
'@
    $json = ConvertFrom-SingleJSONDocument $result.StdOut 'protected-active-user-token'
    if ([string]$json.sid -ne $script:PrimarySID) {
        throw "protected tamper token SID $($json.sid) does not match active target $($script:PrimarySID)"
    }
    if ([bool]$json.admin_enabled -or -not [bool]$json.medium_integrity) {
        throw "protected tamper token is not effective medium/non-admin: admin_enabled=$($json.admin_enabled), medium=$($json.medium_integrity)"
    }
    return "active target SID=$($json.sid), session=$($script:PrimarySessionID), tamper-process-session=$($json.session_id), medium/non-admin-effective"
}

function Get-PerUserArtifactSet([object]$GuardianJSON) {
    $rows = if ($null -ne $GuardianJSON.state) {
        @($GuardianJSON.state.results)
    } else {
        @($GuardianJSON.results)
    }
    $row = @($rows | Where-Object {
        [string]$_.connector -eq 'codex' -and [bool]$_.ok
    } | Select-Object -First 1)
    if ($row.Count -ne 1 -or $null -eq $row[0].result) {
        throw 'guardian JSON has no successful Codex result'
    }
    $result = $row[0].result
    $dataDir = ConvertTo-CanonicalPath ([string]$result.data_dir)
    if (-not $dataDir.Equals(
        $script:PrimaryDataDir,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "guardian emitted data_dir $dataDir, want exact $($script:PrimaryDataDir)"
    }
    $certHome = Assert-CertificationCodexHomePath `
        $script:CertificationCodexHome `
        -RequireExisting
    $liveCodexHome = ConvertTo-CanonicalPath (
        Join-Path $script:PrimaryProfile '.codex'
    )
    $nativeConfigPaths = [Collections.Generic.List[string]]::new()
    $runtimePaths = [Collections.Generic.List[string]]::new()
    $paths = [ordered]@{}
    $index = 0
    foreach ($path in @($result.hook_config_paths)) {
        if (-not [string]::IsNullOrWhiteSpace([string]$path)) {
            $resolved = Assert-PathBelow `
                ([string]$path) `
                $certHome `
                "Codex native hook config $index"
            if ($resolved.Equals(
                $liveCodexHome,
                [StringComparison]::OrdinalIgnoreCase
            ) -or $resolved.StartsWith(
                $liveCodexHome.TrimEnd('\') + '\',
                [StringComparison]::OrdinalIgnoreCase
            )) {
                throw "guardian emitted a native config path under live .codex: $resolved"
            }
            $paths["native_config_$index"] = $resolved
            $nativeConfigPaths.Add($resolved)
            $index++
        }
    }
    if ($nativeConfigPaths.Count -eq 0) {
        throw 'guardian emitted no Codex native hook config path'
    }
    $index = 0
    foreach ($path in @($result.hook_scripts)) {
        if (-not [string]::IsNullOrWhiteSpace([string]$path)) {
            $resolved = Assert-PathBelow `
                ([string]$path) `
                $dataDir `
                "DefenseClaw hook script $index"
            $paths["hook_script_$index"] = $resolved
            $runtimePaths.Add($resolved)
            $index++
        }
    }
    foreach ($propertyName in @('backup_files', 'created_dirs')) {
        $property = $result.PSObject.Properties[$propertyName]
        if ($null -eq $property) {
            continue
        }
        $index = 0
        foreach ($path in @($property.Value)) {
            if ([string]::IsNullOrWhiteSpace([string]$path)) {
                continue
            }
            $resolved = ConvertTo-CanonicalPath ([string]$path)
            if (-not $resolved.Equals(
                $dataDir,
                [StringComparison]::OrdinalIgnoreCase
            )) {
                $resolved = Assert-PathBelow `
                    $resolved `
                    $dataDir `
                    "DefenseClaw $propertyName path $index"
            }
            $runtimePaths.Add($resolved)
            $index++
        }
    }
    foreach ($candidate in @(
        [pscustomobject]@{ Name = 'native_config_lock'; Path = ($script:PrimaryConfigPath + '.lock'); Native = $true },
        [pscustomobject]@{ Name = 'hook_token'; Path = (Join-Path $dataDir 'hooks\.hook-codex.token'); Native = $false },
        [pscustomobject]@{ Name = 'otlp_token'; Path = (Join-Path $dataDir 'hooks\.otlp-codex.token'); Native = $false },
        [pscustomobject]@{ Name = 'notify_helper'; Path = (Join-Path $dataDir 'notify-bridge.sh'); Native = $false },
        [pscustomobject]@{ Name = 'contract_lock'; Path = (Join-Path $dataDir 'hook_contract_lock.json'); Native = $false }
    )) {
        if (Test-Path -LiteralPath $candidate.Path -PathType Leaf) {
            $resolved = Assert-PathBelow `
                $candidate.Path `
                $(if ([bool]$candidate.Native) { $certHome } else { $dataDir }) `
                "DefenseClaw $($candidate.Name)"
            $paths[$candidate.Name] = $resolved
            if ([bool]$candidate.Native) {
                $nativeConfigPaths.Add($resolved)
            } else {
                $runtimePaths.Add($resolved)
            }
        }
    }
    if ($paths.Count -lt 3) {
        throw "guardian exposed only $($paths.Count) managed artifacts; expected config, runtime, and contract evidence"
    }
    foreach ($entry in $paths.GetEnumerator()) {
        if (-not (Test-Path -LiteralPath $entry.Value -PathType Leaf)) {
            throw "expected per-user $($entry.Key) is missing: $($entry.Value)"
        }
    }
    $script:FirstGuardianPathProof = [pscustomobject]@{
        codex_home = $certHome
        native_config_paths = @($nativeConfigPaths.ToArray())
        defenseclaw_data_dir = $dataDir
        runtime_paths = @($runtimePaths.ToArray() | Sort-Object -Unique)
        live_codex_root = $liveCodexHome
        live_codex_path_rejected = $true
        verified_before_hostile_probe = $true
        verified_at = [DateTimeOffset]::UtcNow.ToString('o')
    }
    return [pscustomobject]@{
        DataDir = $dataDir
        Paths = $paths
    }
}

function Get-ManagedCodexArtifactSet([object]$GuardianJSON) {
    $rows = if ($null -ne $GuardianJSON.state) {
        @($GuardianJSON.state.results)
    } else {
        @($GuardianJSON.results)
    }
    $row = @($rows | Where-Object {
        [string]$_.connector -eq 'codex' -and
        [string]$_.sid -eq $script:PrimarySID -and
        [bool]$_.ok
    } | Select-Object -First 1)
    if ($row.Count -ne 1 -or $null -eq $row[0].result) {
        throw 'guardian JSON has no successful enrolled Codex result'
    }
    $result = $row[0].result
    if ([string]$result.agent_application_control_prerequisite -cne
        'wdac_or_applocker_approved_agent_client_rules') {
        throw 'guardian Codex result has the wrong application-control prerequisite'
    }
    if ([string]$result.codex_trusted_hook_launcher_prerequisite -cne
        'approved_fail_closed_fixed_hook_launcher') {
        throw 'guardian Codex result has the wrong trusted launcher prerequisite'
    }
    foreach ($field in @(
        'agent_application_control_enforced',
        'approved_client_enforced',
        'approved_agent_clients_enforced',
        'codex_trusted_hook_launcher_required',
        'codex_target_enabled',
        'codex_trusted_hook_launcher_verified'
    )) {
        $property = $result.PSObject.Properties[$field]
        if ($null -eq $property -or -not [bool]$property.Value) {
            throw "guardian Codex result does not prove $field=true"
        }
    }
    $expectedClaudeAttestation =
        [bool]$script:ClaudeEffectivePolicyAttested
    foreach ($field in @(
        'claude_effective_policy_verified',
        'security_complete'
    )) {
        $property = $result.PSObject.Properties[$field]
        if ($null -eq $property -or
            [bool]$property.Value -ne $expectedClaudeAttestation) {
            $observed = if ($null -eq $property) {
                '<missing>'
            } else {
                [string][bool]$property.Value
            }
            throw (
                "guardian Codex result has wrong $field phase: " +
                "got=$observed expected=$expectedClaudeAttestation"
            )
        }
    }
    $stockCodex = $result.PSObject.Properties['stock_codex_supported']
    if ($null -eq $stockCodex -or
        $stockCodex.Value -isnot [bool] -or
        [bool]$stockCodex.Value) {
        throw 'guardian Codex result did not explicitly reject stock Codex'
    }
    $dataDir = ConvertTo-CanonicalPath ([string]$result.data_dir)
    if (-not $dataDir.Equals(
        $script:PrimaryDataDir,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "guardian emitted data_dir $dataDir, want exact $($script:PrimaryDataDir)"
    }
    $requirements = $script:CodexRequirementsPath
    $managedState = $script:CodexManagedStatePath
    $ownership = $script:CodexRequirementsOwnershipPath
    $reportedConfigs = @(
        $result.hook_config_paths |
            Where-Object {
                -not [string]::IsNullOrWhiteSpace([string]$_)
            } |
            ForEach-Object { ConvertTo-CanonicalPath ([string]$_) }
    )
    if ($reportedConfigs.Count -ne 1 -or
        -not $reportedConfigs[0].Equals(
            $requirements,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw (
            'managed-enterprise Codex must report only the machine ' +
            "requirements.toml; got [$($reportedConfigs -join ',')]"
        )
    }
    $liveCodexHome = ConvertTo-CanonicalPath (
        Join-Path $script:PrimaryProfile '.codex'
    )
    foreach ($reported in $reportedConfigs) {
        if ($reported.Equals(
            $liveCodexHome,
            [StringComparison]::OrdinalIgnoreCase
        ) -or $reported.StartsWith(
            $liveCodexHome.TrimEnd('\') + '\',
            [StringComparison]::OrdinalIgnoreCase
        )) {
            throw "guardian reported forbidden active desktop Codex path: $reported"
        }
    }

    $paths = [ordered]@{
        hook_token = Join-Path $dataDir 'hooks\.hook-codex.token'
        hookcfg = Join-Path $dataDir 'hooks\.hookcfg'
        hookcfg_codex = Join-Path $dataDir 'hooks\.hookcfg.codex'
        hookcfg_lock = Join-Path $dataDir 'hooks\.hookcfg.lock'
        contract_lock = Join-Path $dataDir 'hook_contract_lock.json'
        contract_lock_lock = Join-Path $dataDir 'hook_contract_lock.json.lock'
        hook_helper = Join-Path $dataDir 'hooks\_hardening.sh'
    }
    foreach ($entry in $paths.GetEnumerator()) {
        $entry.Value = Assert-PathBelow `
            ([string]$entry.Value) `
            $dataDir `
            "managed Codex runtime $($entry.Key)"
        if (-not (Test-Path -LiteralPath $entry.Value -PathType Leaf)) {
            throw "managed Codex runtime leaf is missing: $($entry.Value)"
        }
        $security = Get-ManagedUserPathSecurityFingerprint $entry.Value
        if ([string]$security.owner_sid -ne $script:PrimarySID -or
            -not [bool]$security.access_rules_protected) {
            throw (
                "managed Codex runtime $($entry.Key) lacks target ownership " +
                'and a protected canonical DACL'
            )
        }
    }
    foreach ($machinePath in @($requirements, $managedState, $ownership)) {
        if (-not (Test-Path -LiteralPath $machinePath -PathType Leaf)) {
            throw "managed Codex machine artifact is missing: $machinePath"
        }
    }

    if ((Get-FileDigest $script:PrimaryConfigPath) -cne
        $script:PrimaryConfigBaselineSHA256) {
        throw 'guardian changed the disposable alternate user config'
    }
    $configACL = Get-Acl -LiteralPath $script:PrimaryConfigPath
    $sections = (
        [Security.AccessControl.AccessControlSections]::Access -bor
        [Security.AccessControl.AccessControlSections]::Owner -bor
        [Security.AccessControl.AccessControlSections]::Group
    )
    if ($configACL.GetSecurityDescriptorSddlForm($sections) -cne
        $script:PrimaryConfigBaselineACL.GetSecurityDescriptorSddlForm($sections)) {
        throw 'guardian changed the disposable alternate user config security'
    }
    if (Test-Path -LiteralPath $script:CodexUserHookSentinel) {
        throw 'alternate user hook ran before the actual Codex proof'
    }

    $script:FirstGuardianPathProof = [pscustomobject]@{
        codex_machine_policy = $requirements
        codex_machine_runtime_state = $managedState
        codex_private_ownership = $ownership
        defenseclaw_data_dir = $dataDir
        runtime_paths = @($paths.Values)
        alternate_codex_home = $script:CertificationCodexHome
        alternate_config_unchanged = $true
        live_codex_root = $liveCodexHome
        live_codex_enumerated = $false
        live_codex_snapshotted = $false
        live_codex_mutated = $false
        agent_application_control_prerequisite =
            'wdac_or_applocker_approved_agent_client_rules'
        codex_trusted_hook_launcher_prerequisite =
            'approved_fail_closed_fixed_hook_launcher'
        agent_application_control_enforced = $true
        codex_trusted_hook_launcher_required = $true
        codex_trusted_hook_launcher_verified = $true
        stock_codex_supported = $false
        approved_agent_clients_enforced = $true
        claude_effective_policy_verified =
            $expectedClaudeAttestation
        security_complete = $expectedClaudeAttestation
        verified_before_hostile_probe = $true
        verified_at = [DateTimeOffset]::UtcNow.ToString('o')
    }
    return [pscustomobject]@{
        DataDir = $dataDir
        Paths = $paths
        MachinePolicyPaths = [ordered]@{
            requirements = $requirements
            transaction_lock = $script:CodexMachineLockPath
            managed_state = $managedState
            ownership = $ownership
            acl_preimage = $script:CodexRequirementsAclBackupPath
            application_control_attestation =
                $script:AgentApplicationControlAttestationPath
        }
    }
}

function Get-ManagedClaudeArtifactSet([object]$GuardianJSON) {
    $rows = if ($null -ne $GuardianJSON.state) {
        @($GuardianJSON.state.results)
    } else {
        @($GuardianJSON.results)
    }
    $row = @($rows | Where-Object {
        [string]$_.connector -eq 'claudecode' -and
        [string]$_.sid -eq $script:PrimarySID -and
        [bool]$_.ok
    } | Select-Object -First 1)
    if ($row.Count -ne 1 -or $null -eq $row[0].result) {
        throw 'guardian JSON has no successful enrolled Claude result'
    }
    if ([bool]$GuardianJSON.claude_effective_policy_verified -ne
        [bool]$script:ClaudeEffectivePolicyAttested) {
        throw (
            'guardian status Claude effective-policy field does not match the ' +
            "persisted live-evidence phase: got=" +
            "$($GuardianJSON.claude_effective_policy_verified) expected=" +
            "$($script:ClaudeEffectivePolicyAttested)"
        )
    }
    $result = $row[0].result
    $dataDir = ConvertTo-CanonicalPath ([string]$result.data_dir)
    if (-not $dataDir.Equals(
        $script:PrimaryDataDir,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "guardian emitted Claude data_dir $dataDir, want $($script:PrimaryDataDir)"
    }
    $reportedConfigs = @(
        $result.hook_config_paths |
            Where-Object {
                -not [string]::IsNullOrWhiteSpace([string]$_)
            } |
            ForEach-Object { ConvertTo-CanonicalPath ([string]$_) }
    )
    if ($reportedConfigs.Count -ne 1 -or
        -not $reportedConfigs[0].Equals(
            $script:ClaudeManagedPolicyPath,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw (
            'managed-enterprise Claude must report only the administrator ' +
            "policy; got [$($reportedConfigs -join ',')]"
        )
    }

    $paths = [ordered]@{
        hook_token = Join-Path $dataDir 'hooks\.hook-claudecode.token'
        hookcfg = Join-Path $dataDir 'hooks\.hookcfg'
        hookcfg_claudecode = Join-Path $dataDir 'hooks\.hookcfg.claudecode'
        hookcfg_lock = Join-Path $dataDir 'hooks\.hookcfg.lock'
        contract_lock = Join-Path $dataDir 'hook_contract_lock.json'
        contract_lock_lock = Join-Path $dataDir 'hook_contract_lock.json.lock'
        hook_helper = Join-Path $dataDir 'hooks\_hardening.sh'
    }
    foreach ($entry in $paths.GetEnumerator()) {
        $entry.Value = Assert-PathBelow `
            ([string]$entry.Value) `
            $dataDir `
            "managed Claude runtime $($entry.Key)"
        if (-not (Test-Path -LiteralPath $entry.Value -PathType Leaf)) {
            throw "managed Claude runtime leaf is missing: $($entry.Value)"
        }
        $security = Get-ManagedUserPathSecurityFingerprint $entry.Value
        if ([string]$security.owner_sid -ne $script:PrimarySID -or
            -not [bool]$security.access_rules_protected) {
            throw (
                "managed Claude runtime $($entry.Key) lacks target ownership " +
                'and a protected canonical DACL'
            )
        }
    }
    foreach ($machinePath in @(
        $script:ClaudeManagedPolicyPath,
        $script:ClaudeManagedStatePath,
        $script:ClaudeManagedLockPath
    )) {
        if (-not (Test-Path -LiteralPath $machinePath -PathType Leaf)) {
            throw "managed Claude machine artifact is missing: $machinePath"
        }
        $security = Get-ManagedUserPathSecurityFingerprint $machinePath
        if ([string]$security.owner_sid -ne 'S-1-5-32-544' -or
            -not [bool]$security.access_rules_protected) {
            throw (
                "managed Claude machine artifact is not Administrators-owned " +
                "with a protected DACL: $machinePath"
            )
        }
    }
    return [pscustomobject]@{
        DataDir = $dataDir
        Paths = $paths
        MachinePolicyPaths = [ordered]@{
            policy = $script:ClaudeManagedPolicyPath
            state = $script:ClaudeManagedStatePath
            transaction_lock = $script:ClaudeManagedLockPath
        }
    }
}

function Get-ArtifactSnapshots([Collections.IDictionary]$Paths) {
    $out = [ordered]@{}
    foreach ($entry in $Paths.GetEnumerator()) {
        if (-not (Test-Path -LiteralPath $entry.Value -PathType Leaf)) {
            throw "cannot snapshot missing $($entry.Key): $($entry.Value)"
        }
        $item = Get-Item -LiteralPath $entry.Value -Force
        $out[$entry.Key] = [pscustomobject]@{
            path = $entry.Value
            sha256 = Get-FileDigest $entry.Value
            length = $item.Length
            last_write_utc = $item.LastWriteTimeUtc.ToString('o')
        }
    }
    return [pscustomobject]$out
}

function Assert-SameArtifactSnapshots([object]$Before, [object]$After, [string]$Label) {
    foreach ($property in $Before.PSObject.Properties) {
        $name = $property.Name
        $afterProperty = $After.PSObject.Properties[$name]
        if ($null -eq $afterProperty) {
            throw "$Label omitted artifact $name"
        }
        foreach ($field in @('path', 'sha256', 'length')) {
            if ([string]$property.Value.$field -cne [string]$afterProperty.Value.$field) {
                throw "$Label changed artifact $name field $field"
            }
        }
    }
}

function Invoke-UserArtifactTamper(
    [Collections.IDictionary]$Paths,
    [string]$Label
) {
    $inputBase64 = [Convert]::ToBase64String(
        [Text.Encoding]::UTF8.GetBytes(($Paths | ConvertTo-Json -Compress -Depth 4))
    )
    $scriptText = @'
$ErrorActionPreference = 'Stop'
$paths = [Text.Encoding]::UTF8.GetString(
    [Convert]::FromBase64String('__INPUT__')
) | ConvertFrom-Json -AsHashtable -ErrorAction Stop
$actions = [Collections.Generic.List[object]]::new()
$deletedHookToken = $false
$deletedConnectorSidecar = $false
$modifiedHookConfig = $false
$modifiedContract = $false
foreach ($entry in $paths.GetEnumerator()) {
    $path = [string]$entry.Value
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        $actions.Add([pscustomobject]@{
            artifact = $entry.Key
            action = 'missing-before-tamper'
            succeeded = $false
        })
        continue
    }
    try {
        $delete = [string]$entry.Key -in @(
            'hook_token',
            'hookcfg_codex',
            'hookcfg_claudecode'
        )
        if ($delete) {
            Remove-Item -LiteralPath $path -Force -ErrorAction Stop
            $action = 'deleted'
            if ([string]$entry.Key -eq 'hook_token') {
                $deletedHookToken = $true
            }
            if ([string]$entry.Key -in @(
                'hookcfg_codex',
                'hookcfg_claudecode'
            )) {
                $deletedConnectorSidecar = $true
            }
        } else {
            [IO.File]::WriteAllText(
                $path,
                "DEFENSECLAW-CERT-TAMPER-$($entry.Key)`r`n",
                [Text.UTF8Encoding]::new($false)
            )
            $action = 'modified'
            if ([string]$entry.Key -eq 'hookcfg') {
                $modifiedHookConfig = $true
            }
            if ([string]$entry.Key -eq 'contract_lock') {
                $modifiedContract = $true
            }
        }
        $actions.Add([pscustomobject]@{
            artifact = $entry.Key
            action = $action
            succeeded = $true
        })
    } catch {
        $actions.Add([pscustomobject]@{
            artifact = $entry.Key
            action = 'tamper-denied'
            succeeded = $false
            error = $_.Exception.Message
        })
    }
}
$coverageFailures = [Collections.Generic.List[string]]::new()
if (-not $deletedHookToken) { $coverageFailures.Add('delete_hook_token') }
if (-not $deletedConnectorSidecar) {
    $coverageFailures.Add('delete_connector_hookcfg')
}
if (-not $modifiedHookConfig) { $coverageFailures.Add('modify_hookcfg') }
if (-not $modifiedContract) { $coverageFailures.Add('modify_contract_lock') }
$failed = @($actions | Where-Object { -not $_.succeeded })
[pscustomobject]@{
    ok = $failed.Count -eq 0 -and $coverageFailures.Count -eq 0
    actions = $actions
    failed = @($failed.artifact) + @($coverageFailures)
    coverage = [pscustomobject]@{
        deleted_hook_token = $deletedHookToken
        deleted_connector_hookcfg = $deletedConnectorSidecar
        modified_hookcfg = $modifiedHookConfig
        modified_contract_lock = $modifiedContract
    }
} | ConvertTo-Json -Compress -Depth 6
if ($failed.Count -ne 0 -or $coverageFailures.Count -ne 0) { exit 18 }
'@.Replace('__INPUT__', $inputBase64)
    $result = Invoke-ActiveUserPowerShell `
        -Script $scriptText `
        -Label $Label `
        -AllowedExitCodes @(0, 18) `
        -TimeoutSeconds 120
    $json = ConvertFrom-SingleJSONDocument $result.StdOut $Label
    if (-not [bool]$json.ok) {
        throw "standard-user tamper fixture failed for: $(@($json.failed) -join ', ')"
    }
    return $json
}

function Invoke-ActiveUserCanonicalRootObstruction(
    [ValidateSet('delete', 'junction')]
    [string]$Mode,
    [string]$OutsidePath,
    [string]$Label
) {
    $inputObject = [ordered]@{
        mode = $Mode
        root = $script:PrimaryDataDir
        profile = $script:PrimaryProfile
        expected_sid = $script:PrimarySID
        outside = $OutsidePath
    }
    $inputBase64 = [Convert]::ToBase64String(
        [Text.Encoding]::UTF8.GetBytes(
            ($inputObject | ConvertTo-Json -Compress -Depth 4)
        )
    )
    $scriptText = @'
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$inputObject = [Text.Encoding]::UTF8.GetString(
    [Convert]::FromBase64String('__INPUT__')
) | ConvertFrom-Json -ErrorAction Stop
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$actualSID = $identity.User.Value
if ($actualSID -ne [string]$inputObject.expected_sid) {
    throw "obstruction task SID mismatch: $actualSID"
}
$profile = [IO.Path]::GetFullPath([string]$inputObject.profile).TrimEnd('\')
$root = [IO.Path]::GetFullPath([string]$inputObject.root).TrimEnd('\')
$expectedRoot = [IO.Path]::GetFullPath(
    (Join-Path $profile '.defenseclaw')
).TrimEnd('\')
if (-not $root.Equals($expectedRoot, [StringComparison]::OrdinalIgnoreCase)) {
    throw "obstruction root is not canonical: $root"
}
if (Test-Path -LiteralPath $root) {
    $item = Get-Item -LiteralPath $root -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "canonical root was already a reparse point: $root"
    }
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction Stop
}
if ([string]$inputObject.mode -eq 'junction') {
    $outside = [IO.Path]::GetFullPath([string]$inputObject.outside).TrimEnd('\')
    if ([string]::IsNullOrWhiteSpace($outside) -or
        $outside.StartsWith(
            $profile + '\',
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw "junction target is missing or inside the protected profile: $outside"
    }
    $windowsDirectory = [Environment]::GetFolderPath(
        [Environment+SpecialFolder]::Windows
    )
    $cmd = Join-Path $windowsDirectory 'System32\cmd.exe'
    $output = @(& $cmd /d /c mklink /J $root $outside 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "mklink /J failed with $LASTEXITCODE`: $($output -join ' ')"
    }
} elseif ([string]$inputObject.mode -ne 'delete') {
    throw "unsupported obstruction mode: $($inputObject.mode)"
}
[pscustomobject]@{
    ok = $true
    mode = [string]$inputObject.mode
    sid = $actualSID
    root = $root
} | ConvertTo-Json -Compress
'@.Replace('__INPUT__', $inputBase64)
    $result = Invoke-ActiveUserPowerShell `
        -Script $scriptText `
        -Label $Label `
        -TimeoutSeconds 120
    $json = ConvertFrom-SingleJSONDocument $result.StdOut $Label
    if (-not [bool]$json.ok -or [string]$json.sid -ne $script:PrimarySID) {
        throw "$Label did not run successfully under the exact protected SID"
    }
    return $json
}

function Wait-ForArtifactRepair(
    [object]$Baseline,
    [string]$ManifestPath,
    [string]$Label
) {
    $started = [DateTimeOffset]::UtcNow
    Wait-Until -Description "$Label artifact repair" -Condition {
        foreach ($property in $Baseline.PSObject.Properties) {
            $snapshot = $property.Value
            if (-not (Test-Path -LiteralPath $snapshot.path -PathType Leaf)) {
                return $false
            }
            if (-not [string]::Equals(
                (Get-FileDigest $snapshot.path),
                [string]$snapshot.sha256,
                [StringComparison]::Ordinal
            )) {
                return $false
            }
        }
        try {
            $verify = Invoke-GatewayJSON `
                -Arguments @('enterprise', 'hooks', 'verify', '--manifest', $ManifestPath) `
                -Label ($Label + '-verify-poll') `
                -AllowedExitCodes @(0, 1)
            return (
                $verify.Process.ExitCode -eq 0 -and
                [bool]$verify.JSON.ok
            )
        } catch {
            return $false
        }
    } | Out-Null
    return [Math]::Round(
        ([DateTimeOffset]::UtcNow - $started).TotalMilliseconds,
        0
    )
}

function Assert-ArtifactSetSettles([object]$Baseline) {
    $before = [ordered]@{}
    foreach ($property in $Baseline.PSObject.Properties) {
        $path = [string]$property.Value.path
        $item = Get-Item -LiteralPath $path -Force
        $before[$property.Name] = [pscustomobject]@{
            hash = Get-FileDigest $path
            mtime = $item.LastWriteTimeUtc.ToString('o')
        }
    }
    Start-Sleep -Seconds $SettleSeconds
    foreach ($entry in $before.GetEnumerator()) {
        $path = [string]$Baseline.PSObject.Properties[$entry.Key].Value.path
        $item = Get-Item -LiteralPath $path -Force
        if ((Get-FileDigest $path) -ne [string]$entry.Value.hash -or
            $item.LastWriteTimeUtc.ToString('o') -ne [string]$entry.Value.mtime) {
            throw "settled guardian churned unchanged artifact: $($entry.Key)"
        }
    }
    return "canonical artifacts stayed unchanged for $SettleSeconds seconds"
}

function Write-ProtectedManifest([string]$Path, [string]$Content, [string]$Label) {
    Write-UTF8File $Path $Content
    $null = Set-ICaclsOwnerAndDacl `
        -Path $Path `
        -Owner '*S-1-5-32-544' `
        -Grants @(
            '*S-1-5-18:F',
            '*S-1-5-32-544:F'
        ) `
        -Label $Label
}

function Invoke-GuardianServiceReconcile {
    param(
        [int[]]$AllowedExitCodes = @(0),
        [string]$Label = 'guardian-service-reconcile'
    )
    return Invoke-EnterpriseInstallerJSON `
        -Action Reconcile `
        -GatewaySource '' `
        -HookSource '' `
        -CLISource '' `
        -AllowedExitCodes $AllowedExitCodes `
        -Label $Label
}

function Restart-GuardianServiceForFixture(
    [string]$Label,
    [switch]$AllowStartFailure
) {
    Stop-Service -Name $script:GuardianServiceName -Force -ErrorAction Stop
    Wait-Until -Description "$Label guardian stop" -Condition {
        $service = Get-Service -Name $script:GuardianServiceName -ErrorAction Stop
        return $service.Status -eq [ServiceProcess.ServiceControllerStatus]::Stopped
    } | Out-Null
    try {
        Start-Service -Name $script:GuardianServiceName -ErrorAction Stop
    } catch {
        if (-not $AllowStartFailure) {
            throw
        }
        return "guardian start failed as expected: $($_.Exception.Message)"
    }
    if (-not $AllowStartFailure) {
        Wait-ForServicesRunning
    }
    return 'guardian service restart requested'
}

function Restore-BaselineGuardianManifest(
    [string]$Content,
    [object]$ACL,
    [string]$Label
) {
    $installed = Join-Path $script:StateRoot 'hook-guardian\targets.yaml'
    Write-ProtectedManifest $installed $Content ($Label + '-protect-manifest')
    if ($null -ne $ACL) {
        Set-Acl -LiteralPath $installed -AclObject $ACL
    }
    $restored = Invoke-GuardianServiceReconcile -Label ($Label + '-reconcile')
    if (-not [bool]$restored.JSON.ok) {
        throw "$Label LocalSystem guardian reconcile returned ok=false"
    }
    Wait-ForServicesRunning
    $null = Assert-HealthyGuardianJSON ($Label + '-healthy')
}

function Invoke-ExpectedReconcileFailure(
    [string]$ManifestPath,
    [string]$Label,
    [switch]$RequirePartialResult,
    [switch]$MakeInstalledManifestUserWritable
) {
    $installed = Join-Path $script:StateRoot 'hook-guardian\targets.yaml'
    $baselineContent = [IO.File]::ReadAllText($installed)
    $baselineACL = Get-Acl -LiteralPath $installed
    $result = $null
    try {
        Write-ProtectedManifest `
            $installed `
            ([IO.File]::ReadAllText((ConvertTo-CanonicalPath $ManifestPath))) `
            ($Label + '-install-manifest')
        Set-Acl -LiteralPath $installed -AclObject $baselineACL
        if ($MakeInstalledManifestUserWritable) {
            $icacls = Join-Path $script:System32 'icacls.exe'
            $null = Invoke-NativeProcess `
                -FilePath $icacls `
                -ArgumentList @($installed, '/grant', "*$($script:PrimarySID):W") `
                -Label ($Label + '-grant-user-write')
        }
        $null = Restart-GuardianServiceForFixture `
            -Label $Label `
            -AllowStartFailure:$MakeInstalledManifestUserWritable
        if ($MakeInstalledManifestUserWritable) {
            $verify = Invoke-GatewayCommand `
                -Arguments @(
                    'enterprise', 'hooks', 'verify',
                    '--manifest', $installed,
                    '--json'
                ) `
                -Label ($Label + '-verify-untrusted-manifest') `
                -AllowedExitCodes @(1)
            $diagnostic = $verify.StdOut + "`n" + $verify.StdErr
            if ($diagnostic -notmatch '(?i)trust|DACL|writ|unsafe') {
                throw "$Label did not report the unsafe manifest trust boundary: $(Protect-SensitiveDisplayText $diagnostic)"
            }
            $result = [pscustomobject]@{
                Process = $verify
                JSON = [pscustomobject]@{ ok = $false }
            }
        } elseif ($RequirePartialResult) {
            $null = Wait-Until -Description "$Label partial guardian state" -Condition {
                try {
                    $statePath = Join-Path $script:StateRoot 'runtime\hook_guardian_state.json'
                    $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json -ErrorAction Stop
                    return (
                        [int]$state.target_count -ge 2 -and
                        [int]$state.failure_count -ge 1
                    )
                } catch {
                    return $false
                }
            }
            $status = Invoke-GatewayJSON `
                -Arguments @('enterprise', 'hooks', 'status', '--manifest', $installed) `
                -Label ($Label + '-status') `
                -AllowedExitCodes @(1)
            if ([bool]$status.JSON.ok -or $status.Process.ExitCode -eq 0) {
                throw "$Label status claimed healthy after a partial reconcile"
            }
            $rows = @($status.JSON.state.results)
            if ($rows.Count -lt 2) {
                throw "$Label omitted partial target results"
            }
            if (@($rows | Where-Object { [bool]$_.ok }).Count -lt 1 -or
                @($rows | Where-Object { -not [bool]$_.ok }).Count -lt 1) {
                throw "$Label did not expose both success and failure rows"
            }
            $result = $status
        } else {
            throw "$Label fixture did not specify its expected failure mode"
        }
    } finally {
        Restore-BaselineGuardianManifest `
            $baselineContent `
            $baselineACL `
            ($Label + '-restore')
    }
    return $result
}

function Invoke-ExpectedCurrentTargetFailure(
    [string]$Label,
    [scriptblock]$RestoreTarget,
    [scriptblock]$AssertFailedTarget
) {
    $installed = Join-Path $script:StateRoot 'hook-guardian\targets.yaml'
    $result = $null
    try {
        $result = Invoke-GuardianServiceReconcile `
            -AllowedExitCodes @(1) `
            -Label ($Label + '-localsystem')
        if ([bool]$result.JSON.ok -or $result.Process.ExitCode -eq 0) {
            throw "$Label emitted successful lifecycle JSON for an unsafe live target"
        }
        $status = Invoke-GatewayJSON `
            -Arguments @('enterprise', 'hooks', 'status', '--manifest', $installed) `
            -Label ($Label + '-status') `
            -AllowedExitCodes @(1)
        if ([bool]$status.JSON.ok -or $status.Process.ExitCode -eq 0) {
            throw "$Label status claimed healthy for an unsafe live target"
        }
        $rows = @($status.JSON.state.results)
        $connectors = @(
            $rows |
                ForEach-Object { [string]$_.connector } |
                Sort-Object -Unique
        )
        $expectedRows = if ($ClaudeOnly) { 1 } else { 2 }
        $expectedConnectors = if ($ClaudeOnly) {
            'claudecode'
        } else {
            'claudecode,codex'
        }
        if ($rows.Count -ne $expectedRows -or
            @($rows | Where-Object { [bool]$_.ok }).Count -ne 0 -or
            ($connectors -join ',') -cne $expectedConnectors) {
            throw "$Label did not persist the exact failed target rows"
        }
        if ($null -ne $AssertFailedTarget) {
            & $AssertFailedTarget
        }
    } finally {
        if ($null -ne $RestoreTarget) {
            & $RestoreTarget
        }
        $restored = Invoke-GuardianServiceReconcile -Label ($Label + '-restore-reconcile')
        if (-not [bool]$restored.JSON.ok) {
            throw "$Label restoration reconcile returned ok=false"
        }
        Wait-ForServicesRunning
        $null = Assert-HealthyGuardianJSON ($Label + '-restored')
    }
    return $result
}

function Test-UnsafeManifestDACL {
    $path = Join-Path $script:FixtureRoot 'unsafe-manifest-dacl.yaml'
    Write-ProtectedManifest `
        $path `
        ([IO.File]::ReadAllText($script:ManifestSource)) `
        'unsafe-manifest-fixture'
    $null = Invoke-ExpectedReconcileFailure `
        -ManifestPath $path `
        -Label 'unsafe-manifest-dacl-reconcile' `
        -MakeInstalledManifestUserWritable
    return 'LocalSystem guardian rejected a user-writable installed manifest and recovered after trusted restoration'
}

function New-PartialManifest(
    [string]$Path,
    [string]$HostileDataDir,
    [string]$Label
) {
    $primaryHomeYAML = $script:PrimaryProfile.Replace("'", "''")
    $primaryDataYAML = $script:PrimaryDataDir.Replace("'", "''")
    $hostileHomeYAML = $script:PrimaryProfile.Replace("'", "''")
    $hostileDataYAML = $HostileDataDir.Replace("'", "''")
    $content = if ($ClaudeOnly) {
        @"
version: 1
targets:
  - user_home: '$primaryHomeYAML'
    sid: '$($script:PrimarySID)'
    data_dir: '$primaryDataYAML'
    connector: claudecode
    agent_version: "2.1.207 (Claude Code)"
  - user_home: '$hostileHomeYAML'
    sid: '$($script:PrimarySID)'
    data_dir: '$hostileDataYAML'
    connector: claudecode
    agent_version: "2.1.207 (Claude Code)"
"@
    } else {
        @"
version: 1
targets:
  - user_home: '$primaryHomeYAML'
    sid: '$($script:PrimarySID)'
    data_dir: '$primaryDataYAML'
    connector: codex
    agent_version: "codex-cli 0.144.3"
  - user_home: '$hostileHomeYAML'
    sid: '$($script:PrimarySID)'
    data_dir: '$hostileDataYAML'
    connector: codex
    agent_version: "codex-cli 0.144.3"
  - user_home: '$primaryHomeYAML'
    sid: '$($script:PrimarySID)'
    data_dir: '$primaryDataYAML'
    connector: claudecode
    agent_version: "2.1.207 (Claude Code)"
"@
    }
    Write-ProtectedManifest $Path $content $Label
}

function Test-PathEscapeFailsClosed {
    $outside = Join-Path $script:FixtureRoot 'path-escape-outside'
    [IO.Directory]::CreateDirectory($outside) | Out-Null
    $sentinel = Join-Path $outside 'must-not-change.txt'
    Write-UTF8File $sentinel "outside-sentinel`r`n"
    $before = Get-FileDigest $sentinel
    $manifest = Join-Path $script:FixtureRoot 'partial-path-escape.yaml'
    New-PartialManifest `
        -Path $manifest `
        -HostileDataDir $outside `
        -Label 'protect-partial-path-escape'
    $null = Invoke-ExpectedReconcileFailure `
        -ManifestPath $manifest `
        -Label 'partial-path-escape-reconcile' `
        -RequirePartialResult
    if ((Get-FileDigest $sentinel) -ne $before) {
        throw 'path-escape reconcile modified the outside sentinel'
    }
    return 'escaped data_dir failed while the valid target remained explicit'
}

function Test-ReparseDataDirFailsClosed {
    $outside = Join-Path $script:FixtureRoot 'reparse-outside'
    [IO.Directory]::CreateDirectory($outside) | Out-Null
    Protect-AdministratorTree $outside
    $sentinel = Join-Path $outside 'must-not-change.txt'
    Write-UTF8File $sentinel "reparse-sentinel`r`n"
    $outsideBefore = Get-ProtectedUserTreeInventory $outside 'reparse outside baseline'
    $junction = Assert-PathBelow `
        $script:PrimaryDataDir `
        $script:PrimaryProfile `
        'canonical reparse fixture'
    if ([IO.Path]::GetFileName($junction) -ne '.defenseclaw') {
        throw "canonical reparse fixture is not the exact .defenseclaw root: $junction"
    }
    $snapshot = New-ProtectedUserTreeSnapshot `
        -Path $junction `
        -Name "reparse-defenseclaw-$($script:RunToken)" `
        -Ephemeral
    $restoreState = [pscustomobject]@{ restored = $false }
    $restoreTarget = {
        $service = Get-Service -Name $script:GuardianServiceName -ErrorAction SilentlyContinue
        if ($null -ne $service -and
            $service.Status -ne [ServiceProcess.ServiceControllerStatus]::Stopped) {
            Stop-Service -Name $script:GuardianServiceName -Force -ErrorAction Stop
            Wait-Until -Description 'reparse fixture guardian stop for restore' -Condition {
                (Get-Service -Name $script:GuardianServiceName -ErrorAction Stop).Status -eq
                    [ServiceProcess.ServiceControllerStatus]::Stopped
            } | Out-Null
        }
        if (Test-Path -LiteralPath $junction) {
            $current = Get-Item -LiteralPath $junction -Force
            if (($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                Remove-ExactCanonicalUserTreeReparse `
                    -Path $junction `
                    -Label 'canonical reparse fixture cleanup'
            }
        }
        Restore-ProtectedUserTreeSnapshot $snapshot
        $restoreState.restored = $true
    }
    $cmd = Join-Path $script:System32 'cmd.exe'
    try {
        Stop-Service -Name $script:GuardianServiceName -Force -ErrorAction Stop
        Wait-Until -Description 'reparse fixture guardian stop' -Condition {
            (Get-Service -Name $script:GuardianServiceName -ErrorAction Stop).Status -eq
                [ServiceProcess.ServiceControllerStatus]::Stopped
        } | Out-Null
        $current = Get-Item -LiteralPath $junction -Force
        if (($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "canonical data root unexpectedly became a reparse point before the fixture: $junction"
        }
        Remove-Item -LiteralPath $junction -Recurse -Force -ErrorAction Stop
        $null = Invoke-NativeProcess `
            -FilePath $cmd `
            -ArgumentList @('/d', '/c', 'mklink', '/J', $junction, $outside) `
            -Label 'create-canonical-data-junction'
        $null = Set-ICaclsOwnerAndDacl `
            -Path $junction `
            -Owner '*S-1-5-32-544' `
            -Grants @(
                '*S-1-5-18:(OI)(CI)F',
                '*S-1-5-32-544:(OI)(CI)F'
            ) `
            -Options @('/L') `
            -Label 'protect-canonical-data-junction'
        $junctionItem = Get-Item -LiteralPath $junction -Force
        if (($junctionItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) {
            throw "canonical data fixture is not a reparse point: $junction"
        }
        $assertFailedTarget = {
            $failedItem = Get-Item -LiteralPath $junction -Force
            if (($failedItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) {
                throw 'LocalSystem guardian removed the foreign-owned canonical junction'
            }
            $outsideAfterRefusal = Get-ProtectedUserTreeInventory `
                $outside `
                'reparse outside during refusal'
            Assert-SameUserTreeInventory `
                $outsideBefore `
                $outsideAfterRefusal `
                'canonical reparse outside target during refusal'
        }
        $null = Invoke-ExpectedCurrentTargetFailure `
            -Label 'canonical-reparse-reconcile' `
            -RestoreTarget $restoreTarget `
            -AssertFailedTarget $assertFailedTarget
        $outsideAfter = Get-ProtectedUserTreeInventory $outside 'reparse outside after refusal'
        Assert-SameUserTreeInventory `
            $outsideBefore `
            $outsideAfter `
            'canonical reparse outside target'
        return 'foreign-owned canonical data-root reparse failed closed without following, removing, or changing its target'
    } finally {
        if (-not [bool]$restoreState.restored) {
            & $restoreTarget
        }
        $outsideAfterCleanup = Get-ProtectedUserTreeInventory `
            $outside `
            'reparse outside after cleanup'
        Assert-SameUserTreeInventory `
            $outsideBefore `
            $outsideAfterCleanup `
            'canonical reparse outside target after cleanup'
    }
}

function Set-TargetConfigACL(
    [string]$ConfigPath,
    [string]$OwnerSID,
    [string[]]$AdditionalGrants,
    [string]$Label
) {
    $grants = [Collections.Generic.List[string]]::new()
    foreach ($value in @(
        '*S-1-5-18:F',
        '*S-1-5-32-544:F'
    )) {
        $grants.Add([string]$value)
    }
    foreach ($grant in $AdditionalGrants) {
        $grants.Add([string]$grant)
    }
    $null = Set-ICaclsOwnerAndDacl `
        -Path $ConfigPath `
        -Owner "*$OwnerSID" `
        -Grants $grants.ToArray() `
        -Label $Label
}

function Test-ManagedEnterpriseIgnoresUserCodexConfig {
    $config = $script:PrimaryConfigPath
    $originalACL = Get-Acl -LiteralPath $config
    $before = Get-FileDigest $config
    $sections = (
        [Security.AccessControl.AccessControlSections]::Access -bor
        [Security.AccessControl.AccessControlSections]::Owner -bor
        [Security.AccessControl.AccessControlSections]::Group
    )
    $observations = [Collections.Generic.List[object]]::new()
    try {
        foreach ($case in @(
            [pscustomobject]@{
                name = 'broad-user-write'
                owner_sid = $script:PrimarySID
                grants = @("*$($script:PrimarySID):F", '*S-1-1-0:W')
            },
            [pscustomobject]@{
                name = 'administrator-owned'
                owner_sid = 'S-1-5-32-544'
                grants = @("*$($script:PrimarySID):R")
            }
        )) {
            Set-TargetConfigACL `
                -ConfigPath $config `
                -OwnerSID ([string]$case.owner_sid) `
                -AdditionalGrants @($case.grants) `
                -Label "isolate-user-codex-config-$($case.name)"
            $hostileACL = Get-Acl -LiteralPath $config
            $hostileSDDL = $hostileACL.GetSecurityDescriptorSddlForm($sections)
            $reconcile = Invoke-GuardianServiceReconcile `
                -Label "ignored-user-codex-config-$($case.name)"
            if (-not [bool]$reconcile.JSON.ok) {
                throw "managed reconcile consulted the isolated user config case $($case.name)"
            }
            $null = Assert-HealthyGuardianJSON "ignored-user-codex-config-$($case.name)"
            $afterACL = Get-Acl -LiteralPath $config
            if ((Get-FileDigest $config) -cne $before -or
                $afterACL.GetSecurityDescriptorSddlForm($sections) -cne
                    $hostileSDDL) {
                throw "managed enterprise read/write isolation changed user config case $($case.name)"
            }
            $observations.Add([pscustomobject]@{
                case = [string]$case.name
                digest_unchanged = $true
                security_unchanged = $true
                reconcile_healthy = $true
            })
        }
    } finally {
        Set-Acl -LiteralPath $config -AclObject $originalACL
    }
    if ((Get-FileDigest $config) -cne $before -or
        (Get-Acl -LiteralPath $config).
            GetSecurityDescriptorSddlForm($sections) -cne
            $originalACL.GetSecurityDescriptorSddlForm($sections)) {
        throw 'user Codex config isolation fixture did not restore exactly'
    }
    return [pscustomobject]@{
        active_user_codex_config_read = $false
        active_user_codex_config_written = $false
        active_user_codex_config_patched = $false
        cases = @($observations.ToArray())
    }
}

function Assert-HealthyGuardianJSON([string]$Label) {
    $manifest = Join-Path $script:StateRoot 'hook-guardian\targets.yaml'
    foreach ($command in @('status', 'verify')) {
        $result = Invoke-GatewayJSON `
            -Arguments @('enterprise', 'hooks', $command, '--manifest', $manifest) `
            -Label "$Label-$command"
        if (-not [bool]$result.JSON.ok) {
            throw "$command returned ok=false after $Label"
        }
        if (-not [string]::IsNullOrWhiteSpace([string]$result.JSON.manifest) -and
            -not [string]::Equals(
                (ConvertTo-CanonicalPath ([string]$result.JSON.manifest)),
                (ConvertTo-CanonicalPath $manifest),
                [StringComparison]::OrdinalIgnoreCase
            )) {
            throw "$command reported a different manifest: $($result.JSON.manifest)"
        }
    }
    return 'status and verify emitted healthy JSON with zero exit status'
}

function Test-FailedUpgradePreservesTransaction {
    $before = Get-DeploymentDigests
    $missing = Join-Path $script:FixtureRoot 'missing-hook.exe'
    if (Test-Path -LiteralPath $missing) {
        throw "unexpected invalid-upgrade fixture exists: $missing"
    }
    $result = Invoke-EnterpriseInstaller `
        -Action Upgrade `
        -GatewaySource $script:GatewaySource `
        -HookSource $missing `
        -CLISource $script:CLISource `
        -AllowedExitCodes @(1) `
        -Label 'installer-invalid-upgrade'
    if ($result.ExitCode -eq 0) {
        throw 'upgrade with a missing hook source reported success'
    }
    Wait-ForServicesRunning
    $after = Get-DeploymentDigests
    Assert-SameDigests $before $after 'failed upgrade'
    $null = Assert-HealthyGuardianJSON 'failed-upgrade'
    return 'invalid upgrade failed non-zero and preserved the verified transaction'
}

function Test-PostSnapshotActivationFailureRollsBack {
    $beforeDigests = Get-DeploymentDigests
    $beforeServices = Get-ServiceControlSnapshot 'before-post-snapshot-failure'
    $badConfig = Join-Path $script:StagingRoot 'invalid-activation-config.yaml'
    $configText = [IO.File]::ReadAllText($script:ConfigSource)
    $invalidText = $configText.Replace(
        'api_bind: 127.0.0.1',
        'api_bind: 0.0.0.0'
    )
    if ([string]::Equals($configText, $invalidText, [StringComparison]::Ordinal)) {
        throw 'post-snapshot fixture could not replace the managed loopback bind'
    }
    Write-ProtectedManifest `
        $badConfig `
        $invalidText `
        'protect-invalid-activation-config'

    $failed = Invoke-EnterpriseInstallerJSON `
        -Action Upgrade `
        -ConfigSource $badConfig `
        -AllowedExitCodes @(1) `
        -Label 'installer-post-snapshot-activation-failure'
    if ($failed.Process.ExitCode -eq 0 -or [bool]$failed.JSON.ok) {
        throw 'upgrade with a non-loopback managed bind reported success'
    }
    $diagnostic = [string]$failed.JSON.error
    if ($diagnostic -notmatch '(?i)api_bind|loopback|0\.0\.0\.0') {
        throw "post-snapshot failure did not reach managed config activation validation: $(Protect-SensitiveDisplayText $diagnostic)"
    }

    Wait-ForServicesRunning
    $afterDigests = Get-DeploymentDigests
    Assert-SameDigests `
        $beforeDigests `
        $afterDigests `
        'post-snapshot activation rollback'
    $afterServices = Get-ServiceControlSnapshot 'after-post-snapshot-failure'
    Assert-SameServiceControlSnapshot `
        $beforeServices `
        $afterServices `
        'post-snapshot activation rollback'
    $verified = Invoke-EnterpriseInstallerJSON `
        -Action Verify `
        -GatewaySource '' `
        -HookSource '' `
        -CLISource '' `
        -Label 'post-snapshot-rollback-installer-verify'
    if (-not [bool]$verified.JSON.ok) {
        throw 'installer Verify was unhealthy after post-snapshot rollback'
    }
    $null = Assert-HealthyGuardianJSON 'post-snapshot-activation-rollback'
    return 'non-loopback config failed after transaction snapshot; binaries, policy, metadata, full SCM contract, running state, and guardian readiness rolled back exactly'
}

function Test-PublicLifecycleInspectionAndReconcile {
    $installedCLI = Assert-SourcePathHasNoReparse `
        (Join-Path $script:InstallRoot 'bin\defenseclaw.exe') `
        'installed public lifecycle CLI'
    $installedInstaller = Assert-SourcePathHasNoReparse `
        (Join-Path $script:InstallRoot 'libexec\install-enterprise.ps1') `
        'installed public lifecycle installer'
    $evidence = [ordered]@{}
    foreach ($action in @('Status', 'Verify', 'Reconcile')) {
        $label = 'installed-public-' + $action.ToLowerInvariant()
        $envelope = Invoke-PublicEnterpriseLifecycleCLIJSON `
            -Action $action `
            -FilePath $installedCLI `
            -InstallerPath $installedInstaller `
            -Label $label
        $result = $envelope.JSON
        if ([int]$result.schema_version -ne 1 -or
            [string]$result.action -cne $action.ToLowerInvariant() -or
            -not [bool]$result.ok -or
            -not [bool]$result.installed -or
            [bool]$result.transaction_pending -or
            [string]$result.gateway_service_state -cne 'running' -or
            [string]$result.guardian_service_state -cne 'running' -or
            -not [bool]$result.gateway_ready -or
            -not [bool]$result.guardian_ready -or
            @($result.errors).Count -ne 0) {
            throw (
                "installed public $action did not report the exact healthy " +
                'deployment: ' +
                (Protect-SensitiveDisplayText (
                    $result | ConvertTo-Json -Compress -Depth 7
                ))
            )
        }
        $evidence[$action.ToLowerInvariant()] = [pscustomobject]@{
            exit_code = [int]$envelope.Process.ExitCode
            json = $result
            protected_temp = $envelope.TempBoundary
        }
    }
    Wait-ForServicesRunning
    $null = Assert-HealthyGuardianJSON 'public-lifecycle-reconcile'
    return [pscustomobject]$evidence
}

function Test-UpgradeTransaction {
    if ([string]::IsNullOrWhiteSpace($script:UpgradeGatewaySource) -or
        [string]::IsNullOrWhiteSpace($script:UpgradeHookSource) -or
        [string]::IsNullOrWhiteSpace($script:UpgradeCLISource)) {
        throw (
            'full execution requires all three -Upgrade*Binary inputs from ' +
            'a separately version-stamped build'
        )
    }
    $before = Get-DeploymentDigests
    $expected = [ordered]@{
        gateway = [string]$script:SourceDigests['upgrade_gateway']
        hook = [string]$script:SourceDigests['upgrade_hook']
        cli = [string]$script:SourceDigests['upgrade_cli']
    }
    $expectedConfigSHA256 = Get-FileDigest $script:ConfigSource
    $expectedManifestSHA256 = Get-FileDigest $script:ManifestSource
    foreach ($name in @('gateway', 'hook', 'cli')) {
        if ([string]::Equals(
            [string]$before.$name,
            [string]$expected[$name],
            [StringComparison]::OrdinalIgnoreCase
        )) {
            throw (
                "separately version-stamped upgrade $name bytes do not " +
                'differ from the installed preimage'
            )
        }
    }
    $installedInstaller = Assert-SourcePathHasNoReparse `
        (Join-Path $script:InstallRoot 'libexec\install-enterprise.ps1') `
        'installed public upgrade installer'
    $upgrade = Invoke-PublicEnterpriseLifecycleCLIJSON `
        -Action Upgrade `
        -FilePath $script:UpgradeCLISource `
        -InstallerPath $installedInstaller `
        -GatewaySource $script:UpgradeGatewaySource `
        -HookSource $script:UpgradeHookSource `
        -CLISource $script:UpgradeCLISource `
        -ConfigSource $script:ConfigSource `
        -ManifestSource $script:ManifestSource `
        -Label 'external-release-public-cli-versioned-upgrade'
    if ([int]$upgrade.JSON.schema_version -ne 1 -or
        [string]$upgrade.JSON.action -cne 'upgrade' -or
        -not [bool]$upgrade.JSON.ok -or
        -not [bool]$upgrade.JSON.installed -or
        [bool]$upgrade.JSON.transaction_pending -or
        [string]$upgrade.JSON.gateway_service_state -cne 'running' -or
        [string]$upgrade.JSON.guardian_service_state -cne 'running' -or
        -not [bool]$upgrade.JSON.gateway_ready -or
        -not [bool]$upgrade.JSON.guardian_ready -or
        @($upgrade.JSON.errors).Count -ne 0) {
        throw (
            'public Upgrade did not return exact successful JSON: ' +
            (Protect-SensitiveDisplayText (
                $upgrade.JSON | ConvertTo-Json -Compress -Depth 7
            ))
        )
    }
    $installedV2CLI = Assert-SourcePathHasNoReparse `
        (Join-Path $script:InstallRoot 'bin\defenseclaw.exe') `
        'installed v2 public Verify CLI'
    if ((Get-FileDigest $installedV2CLI) -cne [string]$expected.cli) {
        throw 'versioned public Upgrade did not install the v2 CLI before Verify'
    }
    $installedV2Installer = Assert-SourcePathHasNoReparse `
        (Join-Path $script:InstallRoot 'libexec\install-enterprise.ps1') `
        'installed v2 public Verify installer'
    $verify = Invoke-PublicEnterpriseLifecycleCLIJSON `
        -Action Verify `
        -FilePath $installedV2CLI `
        -InstallerPath $installedV2Installer `
        -Label 'installed-v2-public-verify-immediately-after-upgrade'
    if ([int]$verify.JSON.schema_version -ne 1 -or
        [string]$verify.JSON.action -cne 'verify' -or
        -not [bool]$verify.JSON.ok -or
        -not [bool]$verify.JSON.installed -or
        [bool]$verify.JSON.transaction_pending -or
        [string]$verify.JSON.gateway_service_state -cne 'running' -or
        [string]$verify.JSON.guardian_service_state -cne 'running' -or
        -not [bool]$verify.JSON.gateway_ready -or
        -not [bool]$verify.JSON.guardian_ready -or
        @($verify.JSON.errors).Count -ne 0) {
        throw (
            'installed v2 public Verify was not exactly healthy immediately ' +
            'after Upgrade: ' +
            (Protect-SensitiveDisplayText (
                $verify.JSON | ConvertTo-Json -Compress -Depth 7
            ))
        )
    }
    $serviceContract = Assert-ServiceContract
    $after = Get-DeploymentDigests
    foreach ($name in @('gateway', 'hook', 'cli')) {
        if (-not [string]::Equals(
            [string]$after.$name,
            [string]$expected[$name],
            [StringComparison]::OrdinalIgnoreCase
        )) {
            throw (
                "versioned public Upgrade installed the wrong $name bytes: " +
                "$($after.$name) != $($expected[$name])"
            )
        }
    }
    if (-not [string]::Equals(
            [string]$after.config,
            $expectedConfigSHA256,
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        -not [string]::Equals(
            [string]$after.manifest,
            $expectedManifestSHA256,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw (
            'versioned public Upgrade installed config/manifest bytes that ' +
            'do not exactly match the protected source hashes'
        )
    }
    $null = Assert-HealthyGuardianJSON 'versioned-upgrade'
    Add-Result `
        'upgrade-activation-and-rollback' `
        'passed' `
        'the protected external release CLI invoked public Upgrade; the installed v2 CLI immediately passed public Verify, the full service contract, exact staged binary/config/manifest SHA-256 checks, and guardian readiness' `
        @{
            cli_invocation = @{
                executable = $script:UpgradeCLISource
                exit_code = [int]$upgrade.Process.ExitCode
                protected_temp = $upgrade.TempBoundary
            }
            upgrade_json = $upgrade.JSON
            installed_v2_verify = @{
                executable = $installedV2CLI
                exit_code = [int]$verify.Process.ExitCode
                json = $verify.JSON
                protected_temp = $verify.TempBoundary
            }
            before = $before
            expected = [pscustomobject]$expected
            after = $after
            exact_gateway_sha256 = $true
            exact_hook_sha256 = $true
            exact_cli_sha256 = $true
            exact_config_source_sha256 = $true
            exact_manifest_source_sha256 = $true
            service_contract = $serviceContract
        }
}

function Stop-CertificationServicesForDefaultUninstallSnapshot {
    foreach ($name in @(
        $script:GuardianServiceName,
        $script:GatewayServiceName
    )) {
        $service = Get-Service -Name $name -ErrorAction Stop
        if ($service.Status -ne
            [ServiceProcess.ServiceControllerStatus]::Stopped) {
            Stop-Service -Name $name -ErrorAction Stop
        }
    }
    $snapshot = Wait-Until `
        -Description 'default-Uninstall services to quiesce for state snapshot' `
        -TimeoutSeconds 60 `
        -PollMilliseconds 100 `
        -Condition {
            $rows = @(
                foreach ($name in @(
                    $script:GatewayServiceName,
                    $script:GuardianServiceName
                )) {
                    Get-CimInstance `
                        Win32_Service `
                        -Filter "Name='$name'" `
                        -ErrorAction Stop
                }
            )
            if ($rows.Count -ne 2 -or
                @($rows | Where-Object {
                    [string]$_.State -ne 'Stopped' -or
                    [uint32]$_.ProcessId -ne 0
                }).Count -ne 0) {
                return $false
            }
            return $rows
        }
    return @(
        $snapshot |
            Sort-Object Name |
            ForEach-Object {
                [pscustomobject]@{
                    name = [string]$_.Name
                    state = [string]$_.State
                    process_id = [uint32]$_.ProcessId
                    start_mode = [string]$_.StartMode
                }
            }
    )
}

function Get-DefaultUninstallRetainedEvidenceSnapshot(
    [ValidateSet('installed', 'uninstalled')]
    [string]$ExpectedPhase
) {
    $specifications = [ordered]@{
        runtime_audit = Join-Path $script:StateRoot 'runtime\audit.db'
        gateway_log = Join-Path $script:StateRoot 'logs\gateway\gateway.log'
        guardian_log = Join-Path `
            $script:StateRoot `
            'logs\guardian\hook-guardian.log'
        guardian_runtime = Join-Path `
            $script:StateRoot `
            'runtime\hook_guardian_state.json'
        guardian_authorization = Join-Path `
            $script:StateRoot `
            'hook-guardian-state\protected_targets.json'
        deployment_diagnostics = Join-Path `
            $script:StateRoot `
            'install\deployment.json'
    }
    $rows = [Collections.Generic.List[object]]::new()
    foreach ($entry in $specifications.GetEnumerator()) {
        $path = Assert-PathBelow `
            ([string]$entry.Value) `
            $script:StateRoot `
            "default-Uninstall retained $($entry.Key)"
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw (
                "default-Uninstall $ExpectedPhase snapshot is missing real " +
                "$($entry.Key) evidence: $path"
            )
        }
        $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "default-Uninstall retained evidence is a reparse point: $path"
        }
        $security = Get-ManagedUserPathSecurityFingerprint $path
        $rows.Add([pscustomobject]@{
            role = [string]$entry.Key
            path = $path
            length = [int64]$item.Length
            sha256 = Get-FileDigest $path
            owner_sid = [string]$security.owner_sid
            access_rules_protected =
                [bool]$security.access_rules_protected
            sddl = [string]$security.sddl
        })
    }

    $deploymentPath = [string]$specifications.deployment_diagnostics
    try {
        $deployment = [IO.File]::ReadAllText($deploymentPath) |
            ConvertFrom-Json -ErrorAction Stop
    } catch {
        throw (
            "default-Uninstall $ExpectedPhase deployment diagnostics are " +
            "invalid JSON: $($_.Exception.Message)"
        )
    }
    $wantInstalled = $ExpectedPhase -eq 'installed'
    if ([int]$deployment.schema_version -ne 1 -or
        [string]$deployment.deployment_mode -cne 'managed_enterprise' -or
        [bool]$deployment.installed -ne $wantInstalled -or
        [string]$deployment.gateway_service -cne
            $script:GatewayServiceName -or
        [string]$deployment.guardian_service -cne
            $script:GuardianServiceName -or
        -not [string]::Equals(
            [string]$deployment.install_root,
            $script:InstallRoot,
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        -not [string]::Equals(
            [string]$deployment.state_root,
            $script:StateRoot,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw (
            "default-Uninstall $ExpectedPhase deployment diagnostics do not " +
            'match the exact certification deployment'
        )
    }
    $hashCount = @($deployment.hashes.PSObject.Properties).Count
    if ($wantInstalled) {
        if ($hashCount -lt 3 -or
            -not [string]::IsNullOrWhiteSpace(
                [string]$deployment.uninstalled_at
            )) {
            throw 'pre-uninstall deployment diagnostics are not installed metadata'
        }
    } elseif (
        $hashCount -ne 0 -or
        [string]::IsNullOrWhiteSpace([string]$deployment.uninstalled_at) -or
        [bool]$deployment.codex_target_enabled -or
        [bool]$deployment.claude_target_enabled -or
        [bool]$deployment.codex_machine_policy_managed -or
        [bool]$deployment.agent_application_control_enforced
    ) {
        throw (
            'default Uninstall deployment diagnostics are not a complete ' +
            'inactive tombstone'
        )
    }
    return [pscustomobject]@{
        phase = $ExpectedPhase
        state_root = $script:StateRoot
        files = @($rows.ToArray())
        deployment = [pscustomobject]@{
            path = $deploymentPath
            installed = [bool]$deployment.installed
            hash_count = $hashCount
            uninstalled_at_present = -not [string]::IsNullOrWhiteSpace(
                [string]$deployment.uninstalled_at
            )
            codex_target_enabled = [bool]$deployment.codex_target_enabled
            claude_target_enabled = [bool]$deployment.claude_target_enabled
            machine_policy_managed =
                [bool]$deployment.codex_machine_policy_managed
            application_control_enforced =
                [bool]$deployment.agent_application_control_enforced
        }
        secret_material_recorded = $false
    }
}

function Assert-DefaultUninstallRetainedEvidenceContent(
    [object]$Before,
    [object]$After,
    [string]$Label
) {
    $contentRoles = @(
        'runtime_audit',
        'gateway_log',
        'guardian_log',
        'guardian_runtime',
        'guardian_authorization'
    )
    foreach ($role in $contentRoles) {
        $beforeRows = @($Before.files | Where-Object {
            [string]$_.role -ceq $role
        })
        $afterRows = @($After.files | Where-Object {
            [string]$_.role -ceq $role
        })
        if ($beforeRows.Count -ne 1 -or $afterRows.Count -ne 1 -or
            -not [string]::Equals(
                [string]$beforeRows[0].path,
                [string]$afterRows[0].path,
                [StringComparison]::OrdinalIgnoreCase
            ) -or
            [int64]$beforeRows[0].length -ne
                [int64]$afterRows[0].length -or
            [string]$beforeRows[0].sha256 -cne
                [string]$afterRows[0].sha256) {
            throw "$Label did not preserve exact real $role content"
        }
    }
}

function Get-DefaultUninstallRetainedDirectorySecuritySnapshot(
    [switch]$RequireAdministratorOnly
) {
    $paths = @(
        $script:StateRoot,
        (Join-Path $script:StateRoot 'runtime'),
        (Join-Path $script:StateRoot 'logs'),
        (Join-Path $script:StateRoot 'logs\gateway'),
        (Join-Path $script:StateRoot 'logs\guardian'),
        (Join-Path $script:StateRoot 'hook-guardian'),
        (Join-Path $script:StateRoot 'hook-guardian-state'),
        (Join-Path $script:StateRoot 'install')
    )
    $rows = [Collections.Generic.List[object]]::new()
    foreach ($path in $paths) {
        $safe = Assert-PathBelow `
            $path `
            $script:ProgramDataCertificationRoot `
            'default-Uninstall retained directory'
        if (-not (Test-Path -LiteralPath $safe -PathType Container)) {
            throw "default-Uninstall retained directory is missing: $safe"
        }
        $item = Get-Item -LiteralPath $safe -Force -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "default-Uninstall retained directory is a reparse point: $safe"
        }
        $security = Get-ManagedUserPathSecurityFingerprint $safe
        if ([string]$security.owner_sid -ne 'S-1-5-32-544' -or
            -not [bool]$security.access_rules_protected) {
            throw (
                'default-Uninstall retained directory is not ' +
                "Administrators-owned with a protected DACL: $safe"
            )
        }
        if ($RequireAdministratorOnly) {
            foreach ($sid in @($script:PrimarySID, $script:HostileSID)) {
                Assert-NoStandardUserAccess `
                    -Path $safe `
                    -SID $sid `
                    -DenyRead `
                    -DenyWrite
            }
        }
        $rows.Add([pscustomobject]@{
            path = $safe
            owner_sid = [string]$security.owner_sid
            access_rules_protected =
                [bool]$security.access_rules_protected
            sddl = [string]$security.sddl
        })
    }
    return @($rows.ToArray())
}

function Assert-DefaultUninstallRetainedDirectoryTransition(
    [object[]]$Before,
    [object[]]$After,
    [string]$GatewayServiceSID
) {
    if ($Before.Count -ne $After.Count -or $After.Count -lt 2) {
        throw 'default-Uninstall retained directory snapshot count changed'
    }
    if ($GatewayServiceSID -cnotmatch '^S-1-5-80-(?:\d+-){4}\d+$') {
        throw 'default-Uninstall gateway service SID evidence is invalid'
    }
    $serviceScopedBefore = 0
    foreach ($beforeRow in $Before) {
        $matches = @($After | Where-Object {
            [string]::Equals(
                [string]$_.path,
                [string]$beforeRow.path,
                [StringComparison]::OrdinalIgnoreCase
            )
        })
        if ($matches.Count -ne 1 -or
            [string]$beforeRow.owner_sid -cne
                [string]$matches[0].owner_sid -or
            -not [bool]$beforeRow.access_rules_protected -or
            -not [bool]$matches[0].access_rules_protected) {
            throw (
                'default-Uninstall changed a retained directory owner or ' +
                "lost DACL protection: $($beforeRow.path)"
            )
        }
        if ([string]$beforeRow.sddl -match
            [regex]::Escape($GatewayServiceSID)) {
            $serviceScopedBefore++
        }
        if ([string]$matches[0].sddl -match
            [regex]::Escape($GatewayServiceSID)) {
            throw (
                'default-Uninstall retained an obsolete gateway service SID ' +
                "in a preserved-state DACL: $($beforeRow.path)"
            )
        }
    }
    if ($serviceScopedBefore -lt 1) {
        throw (
            'pre-uninstall retained directory snapshot did not contain the ' +
            'live gateway service SID expected by the managed DACL contract'
        )
    }
}

function Test-DefaultUninstallRetainedStateMediumUserDenial(
    [object[]]$DirectorySecurity,
    [object]$Evidence,
    [string]$SentinelPath
) {
    $filePaths = @(
        @($Evidence.files | ForEach-Object { [string]$_.path }) +
        @($SentinelPath)
    ) | Sort-Object -Unique
    $inputObject = [ordered]@{
        expected_sid = $script:PrimarySID
        gateway_service = $script:GatewayServiceName
        guardian_service = $script:GuardianServiceName
        whoami = Join-Path $script:System32 'whoami.exe'
        nonce = $script:RunToken
        directories = @(
            $DirectorySecurity |
                ForEach-Object { [string]$_.path }
        )
        files = @($filePaths)
    }
    $inputBase64 = [Convert]::ToBase64String(
        [Text.Encoding]::UTF8.GetBytes(
            ($inputObject | ConvertTo-Json -Compress -Depth 4)
        )
    )
    $probe = @'
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$inputObject = [Text.Encoding]::UTF8.GetString(
    [Convert]::FromBase64String('__INPUT__')
) | ConvertFrom-Json -ErrorAction Stop
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

namespace DefenseClaw.Certification
{
    public static class RetainedStateNative
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr CreateFileW(
            string fileName,
            UInt32 desiredAccess,
            UInt32 shareMode,
            IntPtr securityAttributes,
            UInt32 creationDisposition,
            UInt32 flagsAndAttributes,
            IntPtr templateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr handle);
    }
}
"@ -ErrorAction Stop

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
$groups = & ([string]$inputObject.whoami) `
    /groups /fo csv /nh 2>$null |
    Out-String
$adminEnabled = $principal.IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)
$mediumIntegrity = $groups -match 'S-1-16-8192'
$gateway = Get-Service `
    -Name ([string]$inputObject.gateway_service) `
    -ErrorAction SilentlyContinue
$guardian = Get-Service `
    -Name ([string]$inputObject.guardian_service) `
    -ErrorAction SilentlyContinue
$checks = [Collections.Generic.List[object]]::new()
function Add-DenialCheck(
    [string]$Kind,
    [string]$Path,
    [string]$Operation,
    [bool]$Denied,
    [int]$ErrorCode
) {
    $checks.Add([pscustomobject]@{
        kind = $Kind
        path = $Path
        operation = $Operation
        denied = $Denied
        error_code = $ErrorCode
    })
}
function Test-DeleteHandle(
    [string]$Kind,
    [string]$Path,
    [bool]$Directory
) {
    $flags = if ($Directory) { [uint32]0x02000000 } else { [uint32]0 }
    $handle = [DefenseClaw.Certification.RetainedStateNative]::CreateFileW(
        $Path,
        [uint32]0x00010000,
        [uint32]0x00000007,
        [IntPtr]::Zero,
        [uint32]3,
        $flags,
        [IntPtr]::Zero
    )
    $invalid = [IntPtr]::new(-1)
    if ($handle -eq $invalid) {
        $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Add-DenialCheck $Kind $Path 'delete_handle' ($errorCode -eq 5) $errorCode
        return
    }
    try {
        Add-DenialCheck $Kind $Path 'delete_handle' $false 0
    } finally {
        [void][DefenseClaw.Certification.RetainedStateNative]::CloseHandle(
            $handle
        )
    }
}
function Test-WriteHandle([string]$Path) {
    $handle = [DefenseClaw.Certification.RetainedStateNative]::CreateFileW(
        $Path,
        [uint32]0x40000000,
        [uint32]0x00000007,
        [IntPtr]::Zero,
        [uint32]3,
        [uint32]0,
        [IntPtr]::Zero
    )
    $invalid = [IntPtr]::new(-1)
    if ($handle -eq $invalid) {
        $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Add-DenialCheck 'file' $Path 'write_handle' ($errorCode -eq 5) $errorCode
        return
    }
    try {
        Add-DenialCheck 'file' $Path 'write_handle' $false 0
    } finally {
        [void][DefenseClaw.Certification.RetainedStateNative]::CloseHandle(
            $handle
        )
    }
}
foreach ($directory in @($inputObject.directories)) {
    $path = [string]$directory
    $candidate = Join-Path `
        $path `
        ('.defenseclaw-forbidden-retained-' + [string]$inputObject.nonce)
    $denied = $false
    $errorCode = 0
    try {
        [IO.File]::WriteAllText(
            $candidate,
            'non-secret-denial-probe',
            [Text.UTF8Encoding]::new($false)
        )
    } catch {
        $errorCode = [int]([uint32]$_.Exception.HResult -band 0xFFFF)
        $denied = $errorCode -eq 5
    } finally {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            Remove-Item -LiteralPath $candidate -Force -ErrorAction SilentlyContinue
        }
    }
    Add-DenialCheck 'directory' $path 'create_child' $denied $errorCode
    Test-DeleteHandle 'directory' $path $true
}
foreach ($file in @($inputObject.files)) {
    $path = [string]$file
    Test-WriteHandle $path
    Test-DeleteHandle 'file' $path $false
}
$failed = @($checks | Where-Object {
    -not [bool]$_.denied -or [int]$_.error_code -ne 5
})
[pscustomobject]@{
    schema_version = 1
    ok = (
        $identity.User.Value -eq [string]$inputObject.expected_sid -and
        -not $adminEnabled -and
        $mediumIntegrity -and
        $null -eq $gateway -and
        $null -eq $guardian -and
        $failed.Count -eq 0
    )
    sid = $identity.User.Value
    admin_enabled = $adminEnabled
    medium_integrity = $mediumIntegrity
    services_absent = $null -eq $gateway -and $null -eq $guardian
    checks = @($checks.ToArray())
    failed_count = $failed.Count
    secret_material_recorded = $false
} | ConvertTo-Json -Compress -Depth 6
'@.Replace('__INPUT__', $inputBase64)

    $result = Invoke-ActiveUserPowerShell `
        -Script $probe `
        -Label 'default-uninstall-retained-state-medium-user-denial' `
        -TimeoutSeconds 180
    $json = ConvertFrom-SingleJSONDocument `
        $result.StdOut `
        'default-Uninstall retained-state medium-user denial'
    $expectedCheckCount = (
        @($inputObject.directories).Count * 2 +
        @($inputObject.files).Count * 2
    )
    if ([int]$json.schema_version -ne 1 -or
        -not [bool]$json.ok -or
        [string]$json.sid -ne $script:PrimarySID -or
        [bool]$json.admin_enabled -or
        -not [bool]$json.medium_integrity -or
        -not [bool]$json.services_absent -or
        [int]$json.failed_count -ne 0 -or
        [bool]$json.secret_material_recorded -or
        @($json.checks).Count -ne $expectedCheckCount -or
        @($json.checks | Where-Object {
            -not [bool]$_.denied -or [int]$_.error_code -ne 5
        }).Count -ne 0) {
        throw (
            'default-Uninstall retained-state medium-user probe did not ' +
            'observe exact ACCESS_DENIED write/delete boundaries while both ' +
            'services were absent: ' +
            (Protect-SensitiveDisplayText (
                $json | ConvertTo-Json -Compress -Depth 7
            ))
        )
    }
    return $json
}

function Test-PublicDefaultUninstallAndReinstall {
    $releaseCLI = Assert-SourcePathHasNoReparse `
        $script:UpgradeCLISource `
        'external release CLI for default Uninstall and Install'
    $installedInstaller = Assert-SourcePathHasNoReparse `
        (Join-Path $script:InstallRoot 'libexec\install-enterprise.ps1') `
        'installed public default-Uninstall installer'
    $sentinel = Assert-PathBelow `
        (Join-Path `
            $script:StateRoot `
            "runtime\retained-public-uninstall-$($script:RunToken).txt") `
        $script:StateRoot `
        'default-Uninstall retained-state sentinel'
    $sentinelParent = Split-Path -Parent $sentinel
    [IO.Directory]::CreateDirectory($sentinelParent) | Out-Null
    [IO.File]::WriteAllText(
        $sentinel,
        "DefenseClaw retained state $($script:RunToken)`r`n",
        [Text.UTF8Encoding]::new($false)
    )
    Protect-AdministratorFile `
        $sentinel `
        'protect-default-uninstall-retained-state'
    $sentinelDigest = Get-FileDigest $sentinel
    $sentinelSDDL = (Get-Acl -LiteralPath $sentinel).
        GetSecurityDescriptorSddlForm(
            (
                [Security.AccessControl.AccessControlSections]::Access -bor
                [Security.AccessControl.AccessControlSections]::Owner -bor
                [Security.AccessControl.AccessControlSections]::Group
            )
        )
    $quiescedServices =
        Stop-CertificationServicesForDefaultUninstallSnapshot
    $retainedSecurityBeforeUninstall =
        Get-DefaultUninstallRetainedDirectorySecuritySnapshot
    $gatewayServiceSID = (
        [Security.Principal.NTAccount]::new(
            "NT SERVICE\$($script:GatewayServiceName)"
        )
    ).Translate([Security.Principal.SecurityIdentifier]).Value
    $retainedEvidenceBefore =
        Get-DefaultUninstallRetainedEvidenceSnapshot `
            -ExpectedPhase installed

    $uninstall = Invoke-PublicEnterpriseLifecycleCLIJSON `
        -Action Uninstall `
        -FilePath $releaseCLI `
        -InstallerPath $installedInstaller `
        -Label 'external-release-public-default-uninstall'
    $purgedProperty = $uninstall.JSON.PSObject.Properties['purged']
    if ([int]$uninstall.JSON.schema_version -ne 1 -or
        [string]$uninstall.JSON.action -cne 'uninstall' -or
        -not [bool]$uninstall.JSON.ok -or
        [bool]$uninstall.JSON.installed -or
        [bool]$uninstall.JSON.transaction_pending -or
        [string]$uninstall.JSON.gateway_service_state -cne 'absent' -or
        [string]$uninstall.JSON.guardian_service_state -cne 'absent' -or
        $null -eq $purgedProperty -or
        [bool]$purgedProperty.Value -or
        @($uninstall.JSON.errors).Count -ne 0) {
        throw (
            'public default Uninstall did not report exact preserved-state ' +
            'success: ' +
            (Protect-SensitiveDisplayText (
                $uninstall.JSON | ConvertTo-Json -Compress -Depth 7
            ))
        )
    }
    $script:Installed = $false
    if (Test-Path -LiteralPath $script:InstallRoot) {
        throw 'public default Uninstall left the canonical InstallRoot'
    }
    if (-not (Test-Path -LiteralPath $script:StateRoot -PathType Container) -or
        -not (Test-Path -LiteralPath $sentinel -PathType Leaf) -or
        (Get-FileDigest $sentinel) -cne $sentinelDigest -or
        (Get-Acl -LiteralPath $sentinel).
            GetSecurityDescriptorSddlForm(
                (
                    [Security.AccessControl.AccessControlSections]::Access -bor
                    [Security.AccessControl.AccessControlSections]::Owner -bor
                    [Security.AccessControl.AccessControlSections]::Group
                )
            ) -cne $sentinelSDDL) {
        throw (
            'public default Uninstall did not preserve the exact protected ' +
            'managed-state sentinel'
        )
    }
    foreach ($name in @(
        $script:GatewayServiceName,
        $script:GuardianServiceName
    )) {
        if ($null -ne (Get-Service -Name $name -ErrorAction SilentlyContinue)) {
            throw "public default Uninstall left service $name"
        }
    }
    $retainedEvidenceAfterUninstall =
        Get-DefaultUninstallRetainedEvidenceSnapshot `
            -ExpectedPhase uninstalled
    Assert-DefaultUninstallRetainedEvidenceContent `
        $retainedEvidenceBefore `
        $retainedEvidenceAfterUninstall `
        'public default Uninstall'
    $retainedSecurityAfterUninstall =
        Get-DefaultUninstallRetainedDirectorySecuritySnapshot `
            -RequireAdministratorOnly
    Assert-DefaultUninstallRetainedDirectoryTransition `
        $retainedSecurityBeforeUninstall `
        $retainedSecurityAfterUninstall `
        $gatewayServiceSID
    $mediumUserDenial =
        Test-DefaultUninstallRetainedStateMediumUserDenial `
            -DirectorySecurity $retainedSecurityAfterUninstall `
            -Evidence $retainedEvidenceAfterUninstall `
            -SentinelPath $sentinel
    $retainedSecurityAfterMediumProbe =
        Get-DefaultUninstallRetainedDirectorySecuritySnapshot `
            -RequireAdministratorOnly
    Assert-SameObjectJSON `
        $retainedSecurityAfterUninstall `
        $retainedSecurityAfterMediumProbe `
        'default-Uninstall retained owner/DACL after medium-user denial'
    $policyAbsentBeforeFreshClients = Assert-EnterpriseMachinePolicyAbsent `
        'after public default Uninstall and before fresh client processes'
    $freshClients = Test-FreshClientsHaveNoEnterpriseHookAfterUninstall
    $policyAbsentAfterFreshClients = Assert-EnterpriseMachinePolicyAbsent `
        'after public default Uninstall fresh client processes'
    $retainedSecurityAfterFreshClients =
        Get-DefaultUninstallRetainedDirectorySecuritySnapshot `
            -RequireAdministratorOnly
    Assert-SameObjectJSON `
        $retainedSecurityAfterUninstall `
        $retainedSecurityAfterFreshClients `
        'default-Uninstall retained owner/DACL after fresh clients'
    $retainedEvidenceAfterFreshClients =
        Get-DefaultUninstallRetainedEvidenceSnapshot `
            -ExpectedPhase uninstalled
    Assert-SameObjectJSON `
        $retainedEvidenceAfterUninstall `
        $retainedEvidenceAfterFreshClients `
        'default-Uninstall retained evidence after fresh clients'

    $install = Invoke-PublicEnterpriseLifecycleCLIJSON `
        -Action Install `
        -FilePath $releaseCLI `
        -InstallerPath $script:Installer `
        -GatewaySource $script:UpgradeGatewaySource `
        -HookSource $script:UpgradeHookSource `
        -CLISource $script:UpgradeCLISource `
        -ConfigSource $script:ConfigSource `
        -ManifestSource $script:ManifestSource `
        -Label 'external-release-public-reinstall-preserved-state'
    if ([int]$install.JSON.schema_version -ne 1 -or
        [string]$install.JSON.action -cne 'install' -or
        -not [bool]$install.JSON.ok -or
        -not [bool]$install.JSON.installed -or
        [bool]$install.JSON.transaction_pending -or
        [string]$install.JSON.gateway_service_state -cne 'running' -or
        [string]$install.JSON.guardian_service_state -cne 'running' -or
        -not [bool]$install.JSON.gateway_ready -or
        -not [bool]$install.JSON.guardian_ready -or
        @($install.JSON.errors).Count -ne 0) {
        throw (
            'public Install did not reactivate the preserved deployment: ' +
            (Protect-SensitiveDisplayText (
                $install.JSON | ConvertTo-Json -Compress -Depth 7
            ))
        )
    }
    $script:Installed = $true
    $after = Get-DeploymentDigests
    foreach ($name in @('gateway', 'hook', 'cli')) {
        $expected = [string]$script:SourceDigests["upgrade_$name"]
        if (-not [string]::Equals(
            [string]$after.$name,
            $expected,
            [StringComparison]::OrdinalIgnoreCase
        )) {
            throw "public reinstall activated the wrong $name digest"
        }
    }
    if ((Get-FileDigest $sentinel) -cne $sentinelDigest -or
        (Get-Acl -LiteralPath $sentinel).
            GetSecurityDescriptorSddlForm(
                (
                    [Security.AccessControl.AccessControlSections]::Access -bor
                    [Security.AccessControl.AccessControlSections]::Owner -bor
                    [Security.AccessControl.AccessControlSections]::Group
                )
            ) -cne $sentinelSDDL) {
        throw 'public reinstall changed the retained state sentinel'
    }
    Wait-ForServicesRunning
    $null = Assert-ServiceContract
    $null = Assert-HealthyGuardianJSON 'public-reinstall-preserved-state'
    return [pscustomobject]@{
        external_release_cli = $releaseCLI
        uninstall_exit_code = [int]$uninstall.Process.ExitCode
        uninstall_json = $uninstall.JSON
        uninstall_temp_boundary = $uninstall.TempBoundary
        quiesced_services = @($quiescedServices)
        state_sentinel_path = $sentinel
        state_sentinel_sha256 = $sentinelDigest
        exact_state_preserved = $true
        retained_evidence_before = $retainedEvidenceBefore
        retained_evidence_after_uninstall =
            $retainedEvidenceAfterUninstall
        retained_directory_security_before =
            @($retainedSecurityBeforeUninstall)
        retained_directory_security_after_uninstall =
            @($retainedSecurityAfterUninstall)
        retired_gateway_service_sid = $gatewayServiceSID
        retained_directory_security_unchanged_by_medium_user = $true
        retained_directory_security_unchanged_by_fresh_clients = $true
        medium_user_write_delete_denial = $mediumUserDenial
        machine_policy_absent_before_fresh_clients =
            $policyAbsentBeforeFreshClients
        machine_policy_absent_after_fresh_clients =
            $policyAbsentAfterFreshClients
        fresh_clients_without_enterprise_hook = $freshClients
        install_exit_code = [int]$install.Process.ExitCode
        install_json = $install.JSON
        install_temp_boundary = $install.TempBoundary
        installed_digests = $after
    }
}

function Get-ManagedUserPathSecurityFingerprint([string]$Path) {
    $sections = (
        [Security.AccessControl.AccessControlSections]::Access -bor
        [Security.AccessControl.AccessControlSections]::Owner -bor
        [Security.AccessControl.AccessControlSections]::Group
    )
    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    return [pscustomobject]@{
        owner_sid = ConvertTo-CertificationSID $acl.Owner
        access_rules_protected = [bool]$acl.AreAccessRulesProtected
        sddl = $acl.GetSecurityDescriptorSddlForm($sections)
    }
}

function Initialize-ManagedFileIdentityProbeType {
    if ($null -ne ('DefenseClaw.Certification.ManagedFileNative' -as [type])) {
        return
    }
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace DefenseClaw.Certification
{
    public sealed class ManagedFileIdentityRecord
    {
        public UInt32 NumberOfLinks;
        public UInt32 VolumeSerialNumber;
        public UInt32 FileIndexHigh;
        public UInt32 FileIndexLow;
        public string Identity;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ManagedByHandleFileInformation
    {
        public UInt32 FileAttributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
        public UInt32 VolumeSerialNumber;
        public UInt32 FileSizeHigh;
        public UInt32 FileSizeLow;
        public UInt32 NumberOfLinks;
        public UInt32 FileIndexHigh;
        public UInt32 FileIndexLow;
    }

    public static class ManagedFileNative
    {
        private const UInt32 FILE_READ_ATTRIBUTES = 0x00000080;
        private const UInt32 FILE_SHARE_ALL = 0x00000007;
        private const UInt32 OPEN_EXISTING = 3;
        private const UInt32 FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFileW(
            string fileName,
            UInt32 desiredAccess,
            UInt32 shareMode,
            IntPtr securityAttributes,
            UInt32 creationDisposition,
            UInt32 flagsAndAttributes,
            IntPtr templateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetFileInformationByHandle(
            SafeFileHandle handle,
            out ManagedByHandleFileInformation information);

        public static ManagedFileIdentityRecord Inspect(string path)
        {
            using (SafeFileHandle handle = CreateFileW(
                path,
                FILE_READ_ATTRIBUTES,
                FILE_SHARE_ALL,
                IntPtr.Zero,
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT,
                IntPtr.Zero))
            {
                if (handle == null || handle.IsInvalid)
                {
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "open managed regular file without following");
                }
                ManagedByHandleFileInformation information;
                if (!GetFileInformationByHandle(handle, out information))
                {
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "inspect managed regular file identity");
                }
                return new ManagedFileIdentityRecord
                {
                    NumberOfLinks = information.NumberOfLinks,
                    VolumeSerialNumber = information.VolumeSerialNumber,
                    FileIndexHigh = information.FileIndexHigh,
                    FileIndexLow = information.FileIndexLow,
                    Identity = String.Format(
                        "{0:X8}:{1:X8}{2:X8}",
                        information.VolumeSerialNumber,
                        information.FileIndexHigh,
                        information.FileIndexLow)
                };
            }
        }
    }
}
'@ -ErrorAction Stop
}

function Get-ManagedRegularFileIdentity([string]$Path) {
    $canonical = ConvertTo-CanonicalPath $Path
    $item = Get-Item -LiteralPath $canonical -Force -ErrorAction Stop
    if ($item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "managed identity probe requires a non-reparse regular file: $canonical"
    }
    Initialize-ManagedFileIdentityProbeType
    return [DefenseClaw.Certification.ManagedFileNative]::Inspect($canonical)
}

function Invoke-ActiveUserHardLink(
    [string]$ExistingPath,
    [string]$LinkPath,
    [string]$Label
) {
    $inputObject = [ordered]@{
        existing = ConvertTo-CanonicalPath $ExistingPath
        link = ConvertTo-CanonicalPath $LinkPath
        expected_sid = $script:PrimarySID
    }
    $inputBase64 = [Convert]::ToBase64String(
        [Text.Encoding]::UTF8.GetBytes(
            ($inputObject | ConvertTo-Json -Compress)
        )
    )
    $scriptText = @'
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$inputObject = [Text.Encoding]::UTF8.GetString(
    [Convert]::FromBase64String('__INPUT__')
) | ConvertFrom-Json -ErrorAction Stop
$actualSID = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
if ($actualSID -ne [string]$inputObject.expected_sid) {
    throw "hard-link task SID mismatch: $actualSID"
}
$existing = [IO.Path]::GetFullPath([string]$inputObject.existing)
$link = [IO.Path]::GetFullPath([string]$inputObject.link)
if (-not (Test-Path -LiteralPath $existing -PathType Leaf)) {
    throw "hard-link source is not a regular file: $existing"
}
if (Test-Path -LiteralPath $link) {
    throw "hard-link destination already exists: $link"
}
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class DefenseClawCertificationHardLinkNative {
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CreateHardLinkW(
        string newFileName,
        string existingFileName,
        IntPtr securityAttributes);
}
"@ -ErrorAction Stop
if (-not [DefenseClawCertificationHardLinkNative]::CreateHardLinkW(
    $link,
    $existing,
    [IntPtr]::Zero
)) {
    $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    throw "CreateHardLinkW failed with Win32 error $errorCode"
}
$created = Get-Item -LiteralPath $link -Force -ErrorAction Stop
if ($created.PSIsContainer -or
    ($created.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "created hard-link name is not a non-reparse regular file: $link"
}
[pscustomobject]@{
    ok = $true
    sid = $actualSID
    existing = $existing
    link = $link
} | ConvertTo-Json -Compress
'@.Replace('__INPUT__', $inputBase64)
    $result = Invoke-ActiveUserPowerShell `
        -Script $scriptText `
        -Label $Label `
        -TimeoutSeconds 120
    $json = ConvertFrom-SingleJSONDocument $result.StdOut $Label
    if (-not [bool]$json.ok -or [string]$json.sid -ne $script:PrimarySID) {
        throw "$Label did not create the hard link under the exact protected SID"
    }
    return $json
}

function Test-ActiveUserCannotInstallSelfDeny(
    [Collections.IDictionary]$ArtifactPaths
) {
    $managedLeaf = [string]$ArtifactPaths['hook_token']
    if ([string]::IsNullOrWhiteSpace($managedLeaf)) {
        throw 'self-deny prevention requires the managed Codex hook token'
    }
    $baseline = Get-ManagedUserPathSecurityFingerprint $managedLeaf
    $baselineDigest = Get-FileDigest $managedLeaf
    $icacls = Join-Path $script:System32 'icacls.exe'
    $attempts = [Collections.Generic.List[object]]::new()
    foreach ($denySID in @(
        $script:PrimarySID,
        'S-1-5-18',
        'S-1-5-32-544',
        'S-1-3-4'
    )) {
        $inputObject = [ordered]@{
            path = $managedLeaf
            expected_sid = $script:PrimarySID
            deny_sid = $denySID
            icacls = $icacls
        }
        $inputBase64 = [Convert]::ToBase64String(
            [Text.Encoding]::UTF8.GetBytes(
                ($inputObject | ConvertTo-Json -Compress)
            )
        )
        $scriptText = @'
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$inputObject = [Text.Encoding]::UTF8.GetString(
    [Convert]::FromBase64String('__INPUT__')
) | ConvertFrom-Json -ErrorAction Stop
$actualSID = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
if ($actualSID -ne [string]$inputObject.expected_sid) {
    throw "self-deny probe SID mismatch: $actualSID"
}
$output = @(
    & ([string]$inputObject.icacls) `
        ([string]$inputObject.path) `
        '/deny' `
        ("*" + [string]$inputObject.deny_sid + ':F') 2>&1
)
$exitCode = $LASTEXITCODE
[pscustomobject]@{
    sid = $actualSID
    deny_sid = [string]$inputObject.deny_sid
    denied = $exitCode -ne 0
    exit_code = $exitCode
    output = @($output | ForEach-Object { [string]$_ })
} | ConvertTo-Json -Compress -Depth 4
if ($exitCode -eq 0) { exit 19 }
'@.Replace('__INPUT__', $inputBase64)
        $result = Invoke-ActiveUserPowerShell `
            -Script $scriptText `
            -Label ("active-user-self-deny-" + ($denySID -replace '[^A-Za-z0-9]', '_')) `
            -AllowedExitCodes @(0, 19) `
            -TimeoutSeconds 120
        $json = ConvertFrom-SingleJSONDocument `
            $result.StdOut `
            "active-user self-deny $denySID"
        if ($result.ExitCode -eq 19 -or -not [bool]$json.denied) {
            # Keep cleanup bounded even if a regression permits the DACL
            # mutation: the running guardian should restore the exact baseline.
            Wait-Until `
                -Description "unexpected active-user $denySID self-deny repair" `
                -Condition {
                    try {
                        $current = Get-ManagedUserPathSecurityFingerprint $managedLeaf
                        return [string]$current.sddl -ceq [string]$baseline.sddl
                    } catch {
                        return $false
                    }
                } |
                Out-Null
            throw "active medium target installed forbidden deny ACE for $denySID"
        }
        $attempts.Add([pscustomobject]@{
            deny_sid = $denySID
            exit_code = [int]$json.exit_code
            denied = [bool]$json.denied
        })
        $current = Get-ManagedUserPathSecurityFingerprint $managedLeaf
        if ([string]$current.sddl -cne [string]$baseline.sddl -or
            (Get-FileDigest $managedLeaf) -cne $baselineDigest) {
            throw "denied active-user $denySID DACL attempt changed managed runtime bytes/security"
        }
    }
    return $attempts.ToArray()
}

function Add-AdministratorDenyACE(
    [string]$Path,
    [string]$DenySID,
    [string]$Label
) {
    $icacls = Join-Path $script:System32 'icacls.exe'
    $result = Invoke-NativeProcess `
        -FilePath $icacls `
        -ArgumentList @(
            $Path,
            '/deny',
            "*$($DenySID):F"
        ) `
        -Label $Label
}

function Test-GuardianRepairsPreexistingSelfDenyDACL(
    [Collections.IDictionary]$ArtifactPaths
) {
    $cases = @(
        [pscustomobject]@{
            name = 'target'
            deny_sid = $script:PrimarySID
            path = [string]$ArtifactPaths['hook_token']
        },
        [pscustomobject]@{
            name = 'owner-rights'
            deny_sid = 'S-1-3-4'
            path = [string]$ArtifactPaths['hookcfg_lock']
        },
        [pscustomobject]@{
            name = 'system'
            deny_sid = 'S-1-5-18'
            path = [string]$ArtifactPaths['hookcfg_codex']
        },
        [pscustomobject]@{
            name = 'administrators'
            deny_sid = 'S-1-5-32-544'
            path = [string]$ArtifactPaths['contract_lock']
        }
    )
    foreach ($case in $cases) {
        if ([string]::IsNullOrWhiteSpace([string]$case.path) -or
            -not (Test-Path -LiteralPath ([string]$case.path) -PathType Leaf)) {
            throw "self-deny recovery case $($case.name) has no managed leaf"
        }
    }

    $manifest = Join-Path $script:StateRoot 'hook-guardian\targets.yaml'
    $observations = [Collections.Generic.List[object]]::new()
    foreach ($case in $cases) {
        $path = ConvertTo-CanonicalPath ([string]$case.path)
        $securityBefore = Get-ManagedUserPathSecurityFingerprint $path
        if ([string]$securityBefore.owner_sid -ne $script:PrimarySID -or
            -not [bool]$securityBefore.access_rules_protected) {
            throw "self-deny case $($case.name) lacks canonical target ownership/protected DACL"
        }
        $digestBefore = Get-FileDigest $path
        $baselinePaths = [ordered]@{ managed_leaf = $path }
        $baseline = Get-ArtifactSnapshots $baselinePaths
        $pendingError = $null
        $guardianStopped = $false
        try {
            Stop-Service -Name $script:GuardianServiceName -Force -ErrorAction Stop
            Wait-Until `
                -Description "$($case.name) self-deny guardian stop" `
                -Condition {
                    (Get-Service `
                        -Name $script:GuardianServiceName `
                        -ErrorAction Stop).Status -eq
                        [ServiceProcess.ServiceControllerStatus]::Stopped
                } |
                Out-Null
            $guardianStopped = $true
            Add-AdministratorDenyACE `
                -Path $path `
                -DenySID ([string]$case.deny_sid) `
                -Label "inject-self-deny-$($case.name)"

            foreach ($command in @('status', 'verify')) {
                $unhealthy = Invoke-GatewayJSON `
                    -Arguments @(
                        'enterprise', 'hooks', $command,
                        '--manifest', $manifest
                    ) `
                    -Label "self-deny-$($case.name)-$command" `
                    -AllowedExitCodes @(1)
                if ($unhealthy.Process.ExitCode -eq 0 -or
                    [bool]$unhealthy.JSON.ok) {
                    throw "$command claimed healthy with $($case.name) deny ACE installed"
                }
            }
        } catch {
            $pendingError = $_
        } finally {
            if ($guardianStopped -or
                (Get-Service `
                    -Name $script:GuardianServiceName `
                    -ErrorAction SilentlyContinue).Status -eq
                    [ServiceProcess.ServiceControllerStatus]::Stopped) {
                Start-Service -Name $script:GuardianServiceName -ErrorAction Stop
            }
        }

        $repairMilliseconds = Wait-ForArtifactRepair `
            -Baseline $baseline `
            -ManifestPath $manifest `
            -Label "self-deny-$($case.name)-repair"
        $securityAfter = Get-ManagedUserPathSecurityFingerprint $path
        if ([string]$securityAfter.sddl -cne [string]$securityBefore.sddl -or
            [string]$securityAfter.owner_sid -ne $script:PrimarySID -or
            -not [bool]$securityAfter.access_rules_protected -or
            (Get-FileDigest $path) -cne $digestBefore) {
            throw (
                "$($case.name) self-deny repair did not restore exact " +
                'bytes/owner/protected canonical DACL'
            )
        }
        if ($null -ne $pendingError) {
            throw $pendingError
        }
        $observations.Add([pscustomobject]@{
            case = [string]$case.name
            deny_sid = [string]$case.deny_sid
            path = $path
            recovery_milliseconds = $repairMilliseconds
            bytes_preserved = $true
            owner_preserved = $true
            canonical_dacl_restored = $true
        })
    }
    # A recovery cycle must not leave the process token's bounded file-repair
    # privileges enabled after the dedicated helper thread exits.
    $idleTokens = Get-CertificationServiceTokenSnapshot
    return [pscustomobject]@{
        cases = @($observations.ToArray())
        idle_service_tokens = @($idleTokens)
    }
}

function Test-GuardianRepairsManagedHardLink(
    [Collections.IDictionary]$ArtifactPaths
) {
    $managedLeaf = ConvertTo-CanonicalPath (
        [string]$ArtifactPaths['hook_token']
    )
    $expectedManagedLeaf = ConvertTo-CanonicalPath (
        Join-Path `
            $script:PrimaryDataDir `
            $(if ($ClaudeOnly) {
                'hooks\.hook-claudecode.token'
            } else {
                'hooks\.hook-codex.token'
            })
    )
    if (-not $managedLeaf.Equals(
        $expectedManagedLeaf,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "hard-link recovery requires exact managed hook token $expectedManagedLeaf; got $managedLeaf"
    }
    $outside = ConvertTo-CanonicalPath (
        Join-Path `
            $script:PrimaryDataDir `
            ".defenseclaw-hardlink-outside-$($script:RunToken).token"
    )
    if (-not [string]::Equals(
        (Split-Path -Parent $outside),
        $script:PrimaryDataDir,
        [StringComparison]::OrdinalIgnoreCase
    ) -or
        (Split-Path -Leaf $outside) -notmatch
            '^\.defenseclaw-hardlink-outside-[a-f0-9]{10}\.token$') {
        throw "hard-link outside name escaped its exact target data-dir allowlist: $outside"
    }
    if (Test-Path -LiteralPath $outside) {
        throw "hard-link outside name already exists: $outside"
    }
    $quarantine = $managedLeaf + '.defenseclaw-quarantine'
    if (Test-Path -LiteralPath $quarantine) {
        throw "hard-link quarantine slot was occupied before the test: $quarantine"
    }

    $configDigestBefore = Get-FileDigest $managedLeaf
    $configSecurityBefore = Get-ManagedUserPathSecurityFingerprint $managedLeaf
    $configIdentityBefore = Get-ManagedRegularFileIdentity $managedLeaf
    if ([uint32]$configIdentityBefore.NumberOfLinks -ne 1) {
        throw "managed runtime leaf began hard-link test with $($configIdentityBefore.NumberOfLinks) links"
    }
    $baseline = Get-ArtifactSnapshots ([ordered]@{ managed_leaf = $managedLeaf })
    $manifest = Join-Path $script:StateRoot 'hook-guardian\targets.yaml'
    $linkCreated = $false
    $guardianStopped = $false
    $pendingError = $null
    $startError = $null
    $linkedConfigIdentity = $null
    $outsideIdentityBefore = $null
    $outsideDigestBefore = ''
    $outsideSecurityBefore = $null

    try {
        Stop-Service -Name $script:GuardianServiceName -Force -ErrorAction Stop
        Wait-Until -Description 'hard-link guardian stop' -Condition {
            (Get-Service `
                -Name $script:GuardianServiceName `
                -ErrorAction Stop).Status -eq
                [ServiceProcess.ServiceControllerStatus]::Stopped
        } | Out-Null
        $guardianStopped = $true
        $null = Invoke-ActiveUserHardLink `
            -ExistingPath $managedLeaf `
            -LinkPath $outside `
            -Label 'active-user-managed-hook-token-hardlink'
        $linkCreated = $true

        $linkedConfigIdentity = Get-ManagedRegularFileIdentity $managedLeaf
        $outsideIdentityBefore = Get-ManagedRegularFileIdentity $outside
        if ([string]$linkedConfigIdentity.Identity -cne
                [string]$configIdentityBefore.Identity -or
            [string]$outsideIdentityBefore.Identity -cne
                [string]$configIdentityBefore.Identity -or
            [uint32]$linkedConfigIdentity.NumberOfLinks -ne 2 -or
            [uint32]$outsideIdentityBefore.NumberOfLinks -ne 2) {
            throw 'active target did not create exactly two names for the original managed file identity'
        }
        $outsideDigestBefore = Get-FileDigest $outside
        $outsideSecurityBefore = Get-ManagedUserPathSecurityFingerprint $outside
        if ($outsideDigestBefore -cne $configDigestBefore -or
            [string]$outsideSecurityBefore.sddl -cne
                [string]$configSecurityBefore.sddl) {
            throw 'new outside hard-link name did not expose the original bytes and security descriptor'
        }

        foreach ($command in @('status', 'verify')) {
            $unhealthy = Invoke-GatewayJSON `
                -Arguments @(
                    'enterprise', 'hooks', $command,
                    '--manifest', $manifest
                ) `
                -Label "hard-linked-managed-runtime-$command" `
                -AllowedExitCodes @(1)
            if ($unhealthy.Process.ExitCode -eq 0 -or
                [bool]$unhealthy.JSON.ok) {
                throw "$command claimed healthy for a two-link managed runtime leaf"
            }
        }
    } catch {
        $pendingError = $_
    } finally {
        $service = Get-Service `
            -Name $script:GuardianServiceName `
            -ErrorAction SilentlyContinue
        if ($null -ne $service -and
            $service.Status -eq
                [ServiceProcess.ServiceControllerStatus]::Stopped) {
            try {
                Start-Service -Name $script:GuardianServiceName -ErrorAction Stop
            } catch {
                $startError = $_
            }
        }
    }

    if ($null -ne $startError) {
        if (Test-Path -LiteralPath $outside -PathType Leaf) {
            Remove-Item -LiteralPath $outside -Force -ErrorAction SilentlyContinue
        }
        throw "guardian could not restart after hard-link fixture: $($startError.Exception.Message)"
    }
    if (-not $linkCreated) {
        if ($null -ne $pendingError) {
            throw $pendingError
        }
        throw 'hard-link fixture did not create its outside name'
    }

    $recoveryError = $null
    $repairMilliseconds = 0
    $configIdentityAfter = $null
    $outsideIdentityAfter = $null
    $idleTokens = @()
    try {
        Wait-ForServicesRunning
        $repairMilliseconds = Wait-ForArtifactRepair `
            -Baseline $baseline `
            -ManifestPath $manifest `
            -Label 'managed-hardlink-repair'
        $configIdentityAfter = Get-ManagedRegularFileIdentity $managedLeaf
        $outsideIdentityAfter = Get-ManagedRegularFileIdentity $outside
        $configSecurityAfter = Get-ManagedUserPathSecurityFingerprint $managedLeaf
        $outsideSecurityAfter = Get-ManagedUserPathSecurityFingerprint $outside
        if ([uint32]$configIdentityAfter.NumberOfLinks -ne 1 -or
            [uint32]$outsideIdentityAfter.NumberOfLinks -ne 1) {
            throw (
                'hard-link recovery did not leave both managed and outside ' +
                'file identities with one name'
            )
        }
        if ([string]$configIdentityAfter.Identity -ceq
                [string]$configIdentityBefore.Identity -or
            [string]$outsideIdentityAfter.Identity -cne
                [string]$configIdentityBefore.Identity) {
            throw 'hard-link recovery did not recreate the managed leaf as a distinct file identity'
        }
        if ((Get-FileDigest $managedLeaf) -cne $configDigestBefore -or
            [string]$configSecurityAfter.sddl -cne
                [string]$configSecurityBefore.sddl -or
            [string]$configSecurityAfter.owner_sid -ne $script:PrimarySID -or
            -not [bool]$configSecurityAfter.access_rules_protected) {
            throw 'recreated managed runtime leaf did not restore exact bytes/owner/canonical protected DACL'
        }
        if ((Get-FileDigest $outside) -cne $outsideDigestBefore -or
            [string]$outsideSecurityAfter.sddl -cne
                [string]$outsideSecurityBefore.sddl -or
            [string]$outsideSecurityAfter.owner_sid -cne
                [string]$outsideSecurityBefore.owner_sid -or
            [bool]$outsideSecurityAfter.access_rules_protected -ne
                [bool]$outsideSecurityBefore.access_rules_protected) {
            throw 'guardian hard-link recovery changed outside bytes, owner, or DACL'
        }
        if (Test-Path -LiteralPath $quarantine) {
            throw "guardian left its bounded hard-link quarantine behind: $quarantine"
        }
        $null = Assert-HealthyGuardianJSON 'managed-hardlink-repaired'
        $idleTokens = @(Get-CertificationServiceTokenSnapshot)
    } catch {
        $recoveryError = $_
    } finally {
        if (Test-Path -LiteralPath $outside -PathType Leaf) {
            Remove-Item -LiteralPath $outside -Force -ErrorAction Stop
        }
    }
    if (Test-Path -LiteralPath $outside) {
        throw "hard-link outside fixture survived exact cleanup: $outside"
    }
    if ($null -ne $pendingError) {
        throw $pendingError
    }
    if ($null -ne $recoveryError) {
        throw $recoveryError
    }
    return [pscustomobject]@{
        path = $managedLeaf
        outside_path = $outside
        original_file_identity = [string]$configIdentityBefore.Identity
        recreated_file_identity = [string]$configIdentityAfter.Identity
        outside_file_identity = [string]$outsideIdentityAfter.Identity
        recovery_milliseconds = $repairMilliseconds
        managed_link_count = [uint32]$configIdentityAfter.NumberOfLinks
        outside_link_count = [uint32]$outsideIdentityAfter.NumberOfLinks
        outside_bytes_preserved = $true
        outside_owner_preserved = $true
        outside_dacl_preserved = $true
        bounded_quarantine_removed = $true
        idle_service_tokens = @($idleTokens)
    }
}

function Get-GuardianResourceObservation {
    $service = Get-CimInstance `
        Win32_Service `
        -Filter "Name='$($script:GuardianServiceName)'" `
        -ErrorAction Stop
    if ([string]$service.State -ne 'Running' -or
        [uint32]$service.ProcessId -eq 0) {
        throw (
            "guardian resource probe found state=$($service.State) " +
            "pid=$($service.ProcessId)"
        )
    }
    $process = Get-Process `
        -Id ([uint32]$service.ProcessId) `
        -ErrorAction Stop
    $process.Refresh()
    return [pscustomobject]@{
        process_id = [uint32]$process.Id
        working_set_bytes = [int64]$process.WorkingSet64
        peak_working_set_bytes = [int64]$process.PeakWorkingSet64
        private_memory_bytes = [int64]$process.PrivateMemorySize64
        sampled_at = [DateTimeOffset]::UtcNow.ToString('o')
    }
}

function Assert-SameLiveGuardianProcess(
    [object]$Baseline,
    [object]$Observed,
    [string]$Label
) {
    if ([uint32]$Observed.process_id -ne [uint32]$Baseline.process_id) {
        throw (
            "$Label guardian PID changed: $($Baseline.process_id) -> " +
            "$($Observed.process_id)"
        )
    }
    $growth = [Math]::Max(
        [int64]0,
        [int64]$Observed.working_set_bytes -
            [int64]$Baseline.working_set_bytes
    )
    if ($growth -gt
        $script:SparseAttackMaxGuardianWorkingSetGrowthBytes) {
        throw (
            "$Label guardian working-set growth $growth exceeded the " +
            "$($script:SparseAttackMaxGuardianWorkingSetGrowthBytes)-byte " +
            'bounded sparse-file ceiling'
        )
    }
    $lifetimePeakGrowth = [Math]::Max(
        [int64]0,
        [int64]$Observed.peak_working_set_bytes -
            [int64]$Baseline.peak_working_set_bytes
    )
    if ($lifetimePeakGrowth -gt
        $script:SparseAttackMaxGuardianWorkingSetGrowthBytes) {
        throw (
            "$Label guardian lifetime peak working-set growth " +
            "$lifetimePeakGrowth exceeded the " +
            "$($script:SparseAttackMaxGuardianWorkingSetGrowthBytes)-byte " +
            'bounded sparse-file ceiling'
        )
    }
}

function Test-ManagedSparseOversizedArtifactRecovery(
    [Collections.IDictionary]$ArtifactPaths
) {
    $flatSidecar = if ($ClaudeOnly) {
        'hookcfg_claudecode'
    } else {
        'hookcfg_codex'
    }
    $cases = @(
        [pscustomobject]@{
            name = 'managed_token'
            key = 'hook_token'
        },
        [pscustomobject]@{
            name = 'hookcfg_json'
            key = 'hookcfg'
        },
        [pscustomobject]@{
            name = 'flat_sidecar'
            key = $flatSidecar
        },
        [pscustomobject]@{
            name = 'hook_contract_lock'
            key = 'contract_lock'
        },
        [pscustomobject]@{
            name = 'hook_helper_script'
            key = 'hook_helper'
        }
    )
    $manifest = Join-Path $script:StateRoot 'hook-guardian\targets.yaml'
    $observations = [Collections.Generic.List[object]]::new()
    foreach ($case in $cases) {
        $path = [string]$ArtifactPaths[[string]$case.key]
        if ([string]::IsNullOrWhiteSpace($path) -or
            -not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw (
                "sparse-file certification is missing managed artifact " +
                "$($case.key)"
            )
        }
        $quarantine = $path + '.defenseclaw-quarantine'
        if (Test-Path -LiteralPath $quarantine) {
            throw (
                "sparse-file quarantine slot was occupied before $($case.name)"
            )
        }
        $onePath = [ordered]@{}
        $onePath[[string]$case.name] = $path
        $baseline = Get-ArtifactSnapshots $onePath
        $baselineSecurity = Get-ManagedUserPathSecurityFingerprint $path
        $baselineIdentity = Get-ManagedRegularFileIdentity $path
        if ([uint32]$baselineIdentity.NumberOfLinks -ne 1) {
            throw "$($case.name) baseline is not a single-link managed file"
        }
        $guardianBefore = Get-GuardianResourceObservation
        $workingSetPeak = [int64]$guardianBefore.working_set_bytes
        $lifetimeWorkingSetPeak =
            [int64]$guardianBefore.peak_working_set_bytes
        $attack = $null
        $attackEvidence = $null
        $status = $null
        $verify = $null
        try {
            $attack = Start-ActiveUserSparseArtifactAttack `
                -Path $path `
                -Label "sparse-$($case.name)"
            foreach ($sampleIndex in 1..4) {
                $sample = Get-GuardianResourceObservation
                Assert-SameLiveGuardianProcess `
                    $guardianBefore `
                    $sample `
                    "$($case.name) held sparse attack sample $sampleIndex"
                $workingSetPeak = [Math]::Max(
                    $workingSetPeak,
                    [int64]$sample.working_set_bytes
                )
                $lifetimeWorkingSetPeak = [Math]::Max(
                    $lifetimeWorkingSetPeak,
                    [int64]$sample.peak_working_set_bytes
                )
                Start-Sleep -Milliseconds 100
            }
            $status = Invoke-GatewayJSON `
                -Arguments @(
                    'enterprise', 'hooks', 'status',
                    '--manifest', $manifest
                ) `
                -Label "sparse-$($case.name)-status" `
                -AllowedExitCodes @(1)
            if ($status.Process.ExitCode -eq 0 -or
                [bool]$status.JSON.ok) {
                throw (
                    "$($case.name) status claimed healthy while a 1-TiB " +
                    'sparse managed artifact was held at the canonical name'
                )
            }
            $verify = Invoke-GatewayJSON `
                -Arguments @(
                    'enterprise', 'hooks', 'verify',
                    '--manifest', $manifest
                ) `
                -Label "sparse-$($case.name)-verify" `
                -AllowedExitCodes @(1)
            if ($verify.Process.ExitCode -eq 0 -or
                [bool]$verify.JSON.ok) {
                throw (
                    "$($case.name) verify claimed healthy while a 1-TiB " +
                    'sparse managed artifact was held at the canonical name'
                )
            }
            foreach ($sampleIndex in 5..12) {
                $sample = Get-GuardianResourceObservation
                Assert-SameLiveGuardianProcess `
                    $guardianBefore `
                    $sample `
                    "$($case.name) unhealthy sparse attack sample $sampleIndex"
                $workingSetPeak = [Math]::Max(
                    $workingSetPeak,
                    [int64]$sample.working_set_bytes
                )
                $lifetimeWorkingSetPeak = [Math]::Max(
                    $lifetimeWorkingSetPeak,
                    [int64]$sample.peak_working_set_bytes
                )
                Start-Sleep -Milliseconds 100
            }
        } finally {
            if ($null -ne $attack) {
                $attackEvidence = Stop-ActiveUserSparseArtifactAttack `
                    $attack `
                    $guardianBefore
            }
        }
        if ($null -eq $attackEvidence) {
            throw "$($case.name) sparse attack emitted no completion evidence"
        }
        $repairMilliseconds = Wait-ForArtifactRepair `
            -Baseline $baseline `
            -ManifestPath $manifest `
            -Label "sparse-$($case.name)-repair"
        $after = Get-ArtifactSnapshots $onePath
        Assert-SameArtifactSnapshots `
            $baseline `
            $after `
            "$($case.name) sparse recovery"
        $afterSecurity = Get-ManagedUserPathSecurityFingerprint $path
        Assert-SameObjectJSON `
            $baselineSecurity `
            $afterSecurity `
            "$($case.name) sparse recovery security"
        $afterIdentity = Get-ManagedRegularFileIdentity $path
        if ([uint32]$afterIdentity.NumberOfLinks -ne 1 -or
            [string]$afterIdentity.Identity -eq
                [string]$baselineIdentity.Identity) {
            throw (
                "$($case.name) sparse recovery did not replace the " +
                'quarantined inode with a new single-link canonical file'
            )
        }
        if (Test-Path -LiteralPath $quarantine) {
            throw (
                "$($case.name) sparse recovery left its bounded " +
                'quarantine slot behind'
            )
        }
        $guardianAfter = Get-GuardianResourceObservation
        Assert-SameLiveGuardianProcess `
            $guardianBefore `
            $guardianAfter `
            "$($case.name) completed sparse recovery"
        $workingSetPeak = [Math]::Max(
            $workingSetPeak,
            [int64](
                $attackEvidence.guardian_release_peak_working_set_bytes
            )
        )
        $lifetimeWorkingSetPeak = [Math]::Max(
            $lifetimeWorkingSetPeak,
            [int64](
                $attackEvidence.
                    guardian_release_lifetime_peak_working_set_bytes
            )
        )
        $workingSetPeak = [Math]::Max(
            $workingSetPeak,
            [int64]$guardianAfter.working_set_bytes
        )
        $lifetimeWorkingSetPeak = [Math]::Max(
            $lifetimeWorkingSetPeak,
            [int64]$guardianAfter.peak_working_set_bytes
        )
        $workingSetGrowth = [Math]::Max(
            [int64]0,
            $workingSetPeak - [int64]$guardianBefore.working_set_bytes
        )
        $lifetimeWorkingSetGrowth = [Math]::Max(
            [int64]0,
            $lifetimeWorkingSetPeak -
                [int64]$guardianBefore.peak_working_set_bytes
        )
        if ($workingSetGrowth -gt
            $script:SparseAttackMaxGuardianWorkingSetGrowthBytes) {
            throw (
                "$($case.name) guardian peak working-set growth " +
                "$workingSetGrowth exceeded the bounded threshold"
            )
        }
        if ($lifetimeWorkingSetGrowth -gt
            $script:SparseAttackMaxGuardianWorkingSetGrowthBytes) {
            throw (
                "$($case.name) guardian lifetime peak working-set growth " +
                "$lifetimeWorkingSetGrowth exceeded the bounded threshold"
            )
        }
        $observations.Add([pscustomobject]@{
            artifact = [string]$case.name
            target_sid_verified = $true
            sparse_logical_bytes = [int64]$attackEvidence.logical_bytes
            sparse_allocated_bytes = [int64]$attackEvidence.allocated_bytes
            grow_operations = [int]$attackEvidence.grow_operations
            status_unhealthy_during_attack = $true
            verify_unhealthy_during_attack = $true
            guardian_pid = [uint32]$guardianBefore.process_id
            guardian_pid_unchanged = $true
            guardian_working_set_before_bytes =
                [int64]$guardianBefore.working_set_bytes
            guardian_working_set_peak_bytes = $workingSetPeak
            guardian_working_set_growth_bytes = $workingSetGrowth
            guardian_working_set_growth_limit_bytes =
                $script:SparseAttackMaxGuardianWorkingSetGrowthBytes
            guardian_lifetime_peak_working_set_before_bytes =
                [int64]$guardianBefore.peak_working_set_bytes
            guardian_lifetime_peak_working_set_after_bytes =
                $lifetimeWorkingSetPeak
            guardian_lifetime_peak_working_set_growth_bytes =
                $lifetimeWorkingSetGrowth
            guardian_lifetime_peak_working_set_growth_limit_bytes =
                $script:SparseAttackMaxGuardianWorkingSetGrowthBytes
            quarantine_rename_observed =
                [bool]$attackEvidence.renamed_to_quarantine
            quarantine_slot_removed = $true
            file_identity_replaced = $true
            exact_bytes_restored = $true
            exact_owner_and_dacl_restored = $true
            repair_milliseconds = $repairMilliseconds
            secret_material_recorded = $false
        })
    }
    $null = Assert-HealthyGuardianJSON 'after-sparse-oversized-artifact-attacks'
    return [pscustomobject]@{
        logical_attack_bytes = $script:SparseAttackLogicalBytes
        maximum_allocated_fixture_bytes =
            $script:SparseAttackMaxAllocatedBytes
        maximum_guardian_working_set_growth_bytes =
            $script:SparseAttackMaxGuardianWorkingSetGrowthBytes
        cases = $observations.ToArray()
        case_count = $observations.Count
        guardian_stayed_alive = $true
        exact_bytes_restored = $true
        bounded_quarantines_removed = $true
        evidence_contains_secret_material = $false
    }
}

function Test-TruthfulUnhealthyJSON([Collections.IDictionary]$ArtifactPaths) {
    Stop-Service -Name $script:GuardianServiceName -Force -ErrorAction Stop
    Wait-Until -Description 'guardian service to stop' -Condition {
        $service = Get-Service -Name $script:GuardianServiceName -ErrorAction Stop
        return $service.Status -eq [ServiceProcess.ServiceControllerStatus]::Stopped
    } | Out-Null

    $baseline = Get-ArtifactSnapshots $ArtifactPaths
    $null = Invoke-UserArtifactTamper `
        -Paths $ArtifactPaths `
        -Label 'standard-user-artifact-tamper'

    foreach ($command in @('status', 'verify')) {
        $result = Invoke-GatewayJSON `
            -Arguments @(
                'enterprise', 'hooks', $command,
                '--manifest', (Join-Path $script:StateRoot 'hook-guardian\targets.yaml')
            ) `
            -Label "tampered-$command" `
            -AllowedExitCodes @(1)
        if ([bool]$result.JSON.ok -or $result.Process.ExitCode -eq 0) {
            throw "$command claimed healthy success while the guardian was stopped and artifacts were tampered"
        }

        $installedCLI = Join-Path `
            $script:InstallRoot `
            'bin\defenseclaw.exe'
        $installedInstaller = Join-Path `
            $script:InstallRoot `
            'libexec\install-enterprise.ps1'
        $public = Invoke-PublicEnterpriseLifecycleCLIJSON `
            -Action (
                $command.Substring(0, 1).ToUpperInvariant() +
                $command.Substring(1)
            ) `
            -FilePath $installedCLI `
            -InstallerPath $installedInstaller `
            -AllowedExitCodes @(1) `
            -Label "tampered-public-windows-$command"
        if ([bool]$public.JSON.ok -or
            [int]$public.Process.ExitCode -ne 1 -or
            [string]$public.JSON.action -cne $command) {
            throw (
                "public Windows $command did not emit truthful JSON and " +
                'exit 1 while the guardian was stopped and artifacts were ' +
                'tampered'
            )
        }
    }

    Start-Service -Name $script:GuardianServiceName -ErrorAction Stop
    Wait-ForServicesRunning
    $repairMilliseconds = Wait-ForArtifactRepair `
        -Baseline $baseline `
        -ManifestPath (Join-Path $script:StateRoot 'hook-guardian\targets.yaml') `
        -Label 'guardian-repair'
    $settled = Assert-ArtifactSetSettles $baseline
    return [pscustomobject]@{
        Baseline = $baseline
        RepairMilliseconds = $repairMilliseconds
        Settled = $settled
    }
}

function Test-PreviouslyAuthorizedRootObstructionRepair(
    [Collections.IDictionary]$ArtifactPaths
) {
    $outside = Join-Path $script:FixtureRoot 'authorized-obstruction-outside'
    [IO.Directory]::CreateDirectory($outside) | Out-Null
    Protect-AdministratorTree $outside
    $sentinel = Join-Path $outside 'must-not-change.txt'
    Write-UTF8File $sentinel "authorized-obstruction-sentinel`r`n"
    $outsideBefore = Get-ProtectedUserTreeInventory `
        $outside `
        'authorized obstruction outside baseline'
    $baseline = Get-ArtifactSnapshots $ArtifactPaths
    $emergencySnapshot = New-ProtectedUserTreeSnapshot `
        -Path $script:PrimaryDataDir `
        -Name "authorized-obstruction-$($script:RunToken)" `
        -Ephemeral
    $completed = $false
    $recoveries = [ordered]@{}
    try {
        foreach ($mode in @('delete', 'junction')) {
            Stop-Service -Name $script:GuardianServiceName -Force -ErrorAction Stop
            Wait-Until -Description "$mode obstruction guardian stop" -Condition {
                (Get-Service -Name $script:GuardianServiceName -ErrorAction Stop).Status -eq
                    [ServiceProcess.ServiceControllerStatus]::Stopped
            } | Out-Null
            $outsidePath = if ($mode -eq 'junction') { $outside } else { '' }
            $null = Invoke-ActiveUserCanonicalRootObstruction `
                -Mode $mode `
                -OutsidePath $outsidePath `
                -Label "active-user-canonical-root-$mode"
            if ($mode -eq 'delete') {
                if (Test-Path -LiteralPath $script:PrimaryDataDir) {
                    throw 'active protected user did not delete the canonical data root'
                }
            } else {
                $item = Get-Item -LiteralPath $script:PrimaryDataDir -Force
                if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) {
                    throw 'active protected user did not create the canonical root junction'
                }
            }
            $outsideAfterObstruction = Get-ProtectedUserTreeInventory `
                $outside `
                "$mode obstruction outside before repair"
            Assert-SameUserTreeInventory `
                $outsideBefore `
                $outsideAfterObstruction `
                "$mode obstruction outside before repair"

            Start-Service -Name $script:GuardianServiceName -ErrorAction Stop
            Wait-ForServicesRunning
            $recoveries[$mode] = Wait-ForArtifactRepair `
                -Baseline $baseline `
                -ManifestPath (Join-Path $script:StateRoot 'hook-guardian\targets.yaml') `
                -Label "authorized-$mode-obstruction-repair"
            $repairedRoot = Get-Item -LiteralPath $script:PrimaryDataDir -Force
            if (-not $repairedRoot.PSIsContainer -or
                ($repairedRoot.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "$mode obstruction repair did not restore a canonical real directory"
            }
            $outsideAfterRepair = Get-ProtectedUserTreeInventory `
                $outside `
                "$mode obstruction outside after repair"
            Assert-SameUserTreeInventory `
                $outsideBefore `
                $outsideAfterRepair `
                "$mode obstruction outside after repair"
            $null = Assert-HealthyGuardianJSON "authorized-$mode-obstruction"
        }
        $completed = $true
    } finally {
        if (-not $completed) {
            $service = Get-Service -Name $script:GuardianServiceName -ErrorAction SilentlyContinue
            if ($null -ne $service -and
                $service.Status -ne [ServiceProcess.ServiceControllerStatus]::Stopped) {
                Stop-Service -Name $script:GuardianServiceName -Force -ErrorAction Stop
                Wait-Until -Description 'authorized obstruction guardian stop for restore' -Condition {
                    (Get-Service -Name $script:GuardianServiceName -ErrorAction Stop).Status -eq
                        [ServiceProcess.ServiceControllerStatus]::Stopped
                } | Out-Null
            }
            Restore-ProtectedUserTreeSnapshot $emergencySnapshot
        }
        $outsideAfterCleanup = Get-ProtectedUserTreeInventory `
            $outside `
            'authorized obstruction outside after cleanup'
        Assert-SameUserTreeInventory `
            $outsideBefore `
            $outsideAfterCleanup `
            'authorized obstruction outside after cleanup'
    }
    return [pscustomobject]@{
        DeletedRootRepairMilliseconds = $recoveries['delete']
        JunctionRootRepairMilliseconds = $recoveries['junction']
    }
}

function Test-AdministratorGenericMutationDenied {
    $manifest = Join-Path $script:StateRoot 'hook-guardian\targets.yaml'
    $result = Invoke-GatewayCommand `
        -Arguments @(
            'enterprise', 'hooks', 'reconcile',
            '--manifest', $manifest,
            '--json'
        ) `
        -Label 'administrator-direct-generic-reconcile-denied' `
        -AllowedExitCodes @(1)
    if ($result.ExitCode -eq 0) {
        throw 'elevated administrator directly executed generic user-footprint reconcile'
    }
    $diagnostic = ($result.StdOut + "`n" + $result.StdErr)
    if ($diagnostic -notmatch '(?i)LocalSystem|guardian') {
        throw "administrator mutation denial omitted the LocalSystem guardian boundary: $(Protect-SensitiveDisplayText $diagnostic)"
    }
    $null = Assert-HealthyGuardianJSON 'administrator-direct-mutation-denial'
    return 'elevated administrator direct generic reconcile was denied; LocalSystem service-mediated reconcile remains healthy'
}

function Remove-CertificationProfile([string]$SID, [string]$Label) {
    if ([string]::IsNullOrWhiteSpace($SID)) { return }
    $profiles = @(Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue | Where-Object {
        [string]$_.SID -eq $SID
    })
    if ($profiles.Count -gt 1) {
        throw "$Label SID has multiple user profiles"
    }
    $expectedPath = if ($Label -ceq 'hostile') {
        $script:HostileProfile
    } elseif ($Label -ceq 'primary') {
        $script:PrimaryProfile
    } else {
        throw "unknown certification profile label: $Label"
    }
    foreach ($profile in $profiles) {
        $localPath = ConvertTo-CanonicalPath ([string]$profile.LocalPath)
        if ([bool]$profile.Loaded -or [bool]$profile.Special -or
            $localPath -cne $expectedPath) {
            throw "$Label profile is unsafe to delete: $localPath"
        }
        $item = Get-Item -LiteralPath $localPath -Force -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "$Label profile is a reparse point: $localPath"
        }
        Remove-CimInstance `
            -InputObject $profile `
            -Confirm:$false `
            -ErrorAction Stop
    }
    $remaining = @(Get-CimInstance Win32_UserProfile -ErrorAction Stop | Where-Object {
        [string]$_.SID -eq $SID
    })
    if ($remaining.Count -ne 0 -or
        (-not [string]::IsNullOrWhiteSpace($expectedPath) -and
            (Test-Path -LiteralPath $expectedPath))) {
        throw "$Label profile state remains after deletion"
    }
}

function Remove-CertificationRoot(
    [string]$Path,
    [string]$ExpectedParent,
    [string]$Label
) {
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) {
        return
    }
    $safe = Assert-PathBelow $Path $ExpectedParent $Label
    Remove-Item -LiteralPath $safe -Recurse -Force -ErrorAction Stop
}

function Register-CertificationSecretFile([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return
    }
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $item.Length -gt 16384) {
        return
    }
    $value = [IO.File]::ReadAllText($item.FullName).Trim()
    if ($value.Length -lt 8) {
        return
    }
    if (-not $script:SecretNeedles.Contains($value)) {
        $script:SecretNeedles.Add($value)
    }
}

function Register-CurrentCertificationSecrets {
    foreach ($root in @(
        (Join-Path $script:StateRoot 'runtime'),
        $script:PrimaryDataDir
    )) {
        if ([string]::IsNullOrWhiteSpace($root) -or
            -not (Test-Path -LiteralPath $root -PathType Container)) {
            continue
        }
        $rootItem = Get-Item -LiteralPath $root -Force
        if (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            continue
        }
        foreach ($file in Get-ChildItem -LiteralPath $root -Filter '*.token' -File -Recurse -Force) {
            Register-CertificationSecretFile $file.FullName
        }
    }
}

function Protect-TreeFromRegisteredSecretLeak([string]$Root, [string]$Label) {
    if (-not (Test-Path -LiteralPath $Root -PathType Container) -or
        $script:SecretNeedles.Count -eq 0) {
        return
    }
    $leaked = [Collections.Generic.List[string]]::new()
    foreach ($file in Get-ChildItem -LiteralPath $Root -File -Recurse -Force) {
        if (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "$Label contains an unsafe reparse file: $($file.FullName)"
        }
        $text = [IO.File]::ReadAllText($file.FullName)
        $redacted = $text
        foreach ($secret in @($script:SecretNeedles.ToArray())) {
            if (-not [string]::IsNullOrWhiteSpace($secret)) {
                $redacted = $redacted.Replace($secret, '<redacted-secret>')
            }
        }
        if (-not [string]::Equals($text, $redacted, [StringComparison]::Ordinal)) {
            [IO.File]::WriteAllText(
                $file.FullName,
                $redacted,
                [Text.UTF8Encoding]::new($false)
            )
            $leaked.Add($file.FullName)
        }
    }
    if ($leaked.Count -ne 0) {
        throw "$Label contained registered secret material in $($leaked.Count) file(s); raw material was redacted and certification is failed"
    }
}

function Copy-WorkEvidence {
    if (-not (Test-Path -LiteralPath $script:WorkRoot -PathType Container)) {
        return
    }
    Register-CurrentCertificationSecrets
    Protect-TreeFromRegisteredSecretLeak $script:WorkRoot 'work logs'
    $logRoot = Join-Path $script:EvidenceDirectory 'logs'
    [IO.Directory]::CreateDirectory($logRoot) | Out-Null
    foreach ($entry in Get-ChildItem -LiteralPath $script:WorkRoot -Force) {
        Copy-Item -LiteralPath $entry.FullName -Destination $logRoot -Recurse -Force
    }
    Protect-TreeFromRegisteredSecretLeak $logRoot 'copied evidence logs'
}

function Restore-ProtectedUserFixture {
    if (-not [string]::IsNullOrWhiteSpace(
            $script:NormalModeSyntheticHome
        ) -and
        (Test-Path -LiteralPath $script:NormalModeSyntheticHome)) {
        $safeNormalHome = Assert-PathBelow `
            $script:NormalModeSyntheticHome `
            $script:PrimaryProfile `
            'normal-mode synthetic-home cleanup'
        if (-not (Split-Path -Parent $safeNormalHome).Equals(
                $script:PrimaryProfile,
                [StringComparison]::OrdinalIgnoreCase
            ) -or
            [IO.Path]::GetFileName($safeNormalHome) -cne
                ".defenseclaw-normal-$($script:RunToken)") {
            throw (
                'normal-mode cleanup target is not the exact registered ' +
                "synthetic home: $safeNormalHome"
            )
        }
        $item = Get-Item -LiteralPath $safeNormalHome -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            [IO.Directory]::Delete($safeNormalHome, $false)
        } else {
            $nestedReparse = @(
                Get-ChildItem `
                    -LiteralPath $safeNormalHome `
                    -Force `
                    -Recurse |
                    Where-Object {
                        ($_.Attributes -band
                            [IO.FileAttributes]::ReparsePoint) -ne 0
                    }
            )
            if ($nestedReparse.Count -ne 0) {
                throw (
                    'normal-mode synthetic home contains an unexpected ' +
                    "reparse point: $($nestedReparse[0].FullName)"
                )
            }
            Remove-Item `
                -LiteralPath $safeNormalHome `
                -Recurse `
                -Force `
                -ErrorAction Stop
        }
    }
    $script:NormalModeSyntheticHome = ''
    foreach ($snapshot in @($script:UserTreeSnapshots.ToArray())) {
        Restore-ProtectedUserTreeSnapshot $snapshot
    }
    if ($script:CertificationCodexHomeInitialized -and
        (Test-Path -LiteralPath $script:CertificationCodexHome)) {
        throw (
            'absent-baseline certification CODEX_HOME remains after cleanup: ' +
            $script:CertificationCodexHome
        )
    }
}

function Invoke-BoundedCleanup {
    $script:Phase = 'cleanup'
    foreach ($taskName in @($script:ScheduledTasks.ToArray())) {
        try {
            Remove-CertificationScheduledTask $taskName
        } catch {
            $script:CleanupErrors.Add(
                "scheduled task $taskName`: " + (Protect-SensitiveDisplayText $_.Exception.Message)
            )
        }
    }
    try {
        if ($script:RunToken -cnotmatch '^[a-f0-9]{10}$') {
            throw "unsafe certification run token: $($script:RunToken)"
        }
        $certificationTaskPrefix = "DefenseClawCert_$($script:RunToken)_"
        $remainingCertificationTasks = @(
            Get-ScheduledTask -ErrorAction Stop |
                Where-Object {
                    ([string]$_.TaskName).StartsWith(
                        $certificationTaskPrefix,
                        [StringComparison]::Ordinal
                    )
                }
        )
        if ($remainingCertificationTasks.Count -ne 0) {
            $identities = @(
                $remainingCertificationTasks |
                    ForEach-Object {
                        ([string]$_.TaskPath) + ([string]$_.TaskName)
                    } |
                    Sort-Object
            )
            throw (
                'certification scheduled tasks remain after cleanup: ' +
                ($identities -join ', ')
            )
        }
        if ($script:ScheduledTasks.Count -ne 0) {
            throw (
                'certification scheduled-task tracking remains after cleanup: ' +
                ($script:ScheduledTasks.ToArray() -join ', ')
            )
        }
    } catch {
        $script:CleanupErrors.Add(
            'scheduled-task final sweep: ' +
            (Protect-SensitiveDisplayText $_.Exception.Message)
        )
    }
    if ($script:Installed -or
        $null -ne (Get-Service -Name $script:GatewayServiceName -ErrorAction SilentlyContinue) -or
        $null -ne (Get-Service -Name $script:GuardianServiceName -ErrorAction SilentlyContinue)) {
        try {
            $null = Invoke-EnterpriseInstaller `
                -Action Uninstall `
                -Purge `
                -AllowedExitCodes @(0) `
                -Label 'cleanup-installer-uninstall'
            $script:Installed = $false
        } catch {
            $script:CleanupErrors.Add(
                'enterprise uninstall: ' + (Protect-SensitiveDisplayText $_.Exception.Message)
            )
        }
    }
    foreach ($serviceName in @($script:GuardianServiceName, $script:GatewayServiceName)) {
        if ($null -ne (Get-Service -Name $serviceName -ErrorAction SilentlyContinue)) {
            try {
                $serviceRole = if ($serviceName -ceq $script:GuardianServiceName) {
                    'guardian'
                } elseif ($serviceName -ceq $script:GatewayServiceName) {
                    'gateway'
                } else {
                    throw "unsafe cleanup service name: $serviceName"
                }
                Assert-CertificationServiceName $serviceName $serviceRole
                $sc = Join-Path $script:System32 'sc.exe'
                $null = Invoke-NativeProcess `
                    -FilePath $sc `
                    -ArgumentList @('stop', $serviceName) `
                    -AllowedExitCodes @(0, 1060, 1062) `
                    -Label "cleanup-stop-$serviceName"
                $null = Invoke-NativeProcess `
                    -FilePath $sc `
                    -ArgumentList @('delete', $serviceName) `
                    -AllowedExitCodes @(0, 1060, 1072) `
                    -Label "cleanup-delete-$serviceName"
            } catch {
                $script:CleanupErrors.Add(
                    "service $serviceName`: " + (Protect-SensitiveDisplayText $_.Exception.Message)
                )
            }
        }
    }
    try {
        $null = Assert-MachineCodexHomeUnchanged
    } catch {
        $script:CleanupErrors.Add(
            'machine/coordinator CODEX_HOME changed despite no-mutation contract: ' +
            (Protect-SensitiveDisplayText $_.Exception.Message)
        )
    }
    try {
        foreach ($serviceName in @(
            $script:GuardianServiceName,
            $script:GatewayServiceName
        )) {
            if ($null -ne (
                Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            )) {
                throw "refusing Codex shared cleanup while service still exists: $serviceName"
            }
        }
        Restore-CodexSharedDirectoryFixture
    } catch {
        $script:CleanupErrors.Add(
            'Codex shared policy fixture: ' +
            (Protect-SensitiveDisplayText $_.Exception.Message)
        )
    }

    try {
        foreach ($serviceName in @(
            $script:GuardianServiceName,
            $script:GatewayServiceName
        )) {
            if ($null -ne (
                Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            )) {
                throw "refusing user fixture cleanup while service still exists: $serviceName"
            }
        }
        Restore-ProtectedUserFixture
    } catch {
        $script:CleanupErrors.Add(
            'protected user fixture: ' + (Protect-SensitiveDisplayText $_.Exception.Message)
        )
    }

    foreach ($user in @(
        [pscustomobject]@{
            Name = $script:HostileUserName
            SID = $script:HostileSID
            Created = $script:HostileUserCreated
            Label = 'hostile'
        },
        [pscustomobject]@{
            Name = $script:PrimaryUserName
            SID = $script:PrimarySID
            Created = $script:PrimaryUserCreated
            Label = 'primary'
        }
    )) {
        if (-not [bool]$user.Created) { continue }
        try {
            Remove-CertificationProfile $user.SID $user.Label
        } catch {
            $script:CleanupErrors.Add(
                "$($user.Label) profile: " + (Protect-SensitiveDisplayText $_.Exception.Message)
            )
        }
        try {
            Assert-CertificationUserName $user.Name 'cleanup'
            if (Get-LocalUser -Name $user.Name -ErrorAction SilentlyContinue) {
                Remove-LocalUser -Name $user.Name -ErrorAction Stop
            }
        } catch {
            $script:CleanupErrors.Add(
                "$($user.Label) user: " + (Protect-SensitiveDisplayText $_.Exception.Message)
            )
        }
    }

    try {
        Copy-WorkEvidence
    } catch {
        $script:CleanupErrors.Add(
            'evidence copy: ' + (Protect-SensitiveDisplayText $_.Exception.Message)
        )
    }

    foreach ($item in @(
        [pscustomobject]@{
            Path = $script:InstallRoot
            Parent = $script:ProgramFilesCertificationRoot
            Label = 'install root'
        },
        [pscustomobject]@{
            Path = $script:StateRoot
            Parent = $script:ProgramDataCertificationRoot
            Label = 'state root'
        },
        [pscustomobject]@{
            Path = $script:StagingRoot
            Parent = $script:ProgramDataStagingRoot
            Label = 'staging root'
        }
    )) {
        try {
            Remove-CertificationRoot $item.Path $item.Parent $item.Label
        } catch {
            $script:CleanupErrors.Add(
                "$($item.Label): " + (Protect-SensitiveDisplayText $_.Exception.Message)
            )
        }
    }
    if (-not $KeepWorkRoot) {
        try {
            Remove-CertificationRoot $script:WorkRoot $script:ProgramDataWorkRoot 'work root'
        } catch {
            $script:CleanupErrors.Add(
                'work root: ' + (Protect-SensitiveDisplayText $_.Exception.Message)
            )
        }
    }
}

function Write-FinalEvidence([string]$Status, [string]$Failure) {
    if (-not (Test-Path -LiteralPath $script:EvidenceDirectory -PathType Container)) {
        [IO.Directory]::CreateDirectory($script:EvidenceDirectory) | Out-Null
    }
    # Cleanup is part of the certification boundary. A run that exercised the
    # controls but failed exact restoration is retained as diagnostic evidence,
    # never as a completed core or production certificate.
    $passed = $Status -eq 'passed'
    $coreHardeningComplete = (
        $passed -and
        $null -ne $script:ClaudeLiveProcessProof
    )
    $productionCertified = (
        $passed -and
        -not [bool]$ClaudeOnly -and
        [bool]$AttestAgentApplicationControl -and
        [bool]$AttestCodexTrustedHookLauncher -and
        [bool]$script:ClaudeEffectivePolicyAttested -and
        $null -ne $script:ClaudeLiveProcessProof -and
        $null -ne $script:CodexLiveProcessProof -and
        $null -ne $script:CodexTrustedHookLauncherIdentity
    )
    $payload = [ordered]@{
        schema_version = $script:HarnessSchemaVersion
        status = $Status
        run_id = $script:RunToken
        started_at = $script:RunStartedAt.ToString('o')
        completed_at = [DateTimeOffset]::UtcNow.ToString('o')
        source = [ordered]@{
            gateway_sha256 = [string]$script:SourceDigests['gateway']
            hook_sha256 = [string]$script:SourceDigests['hook']
            cli_sha256 = [string]$script:SourceDigests['cli']
            normal_mode_cli_launcher_sha256 =
                [string]$script:SourceDigests['normal_mode_cli_launcher']
            normal_mode_cli_wheel_sha256 =
                [string]$script:SourceDigests['normal_mode_cli_wheel']
            installer_sha256 = [string]$script:SourceDigests['installer']
            module_sha256 = [string]$script:SourceDigests['module']
            codex_sha256 = [string]$script:SourceDigests['codex']
            claude_sha256 = [string]$script:SourceDigests['claude']
            codex_trusted_hook_launcher_sha256 =
                [string]$script:SourceDigests['codex_trusted_hook_launcher']
            rejected_codex_sha256 = [string]$script:SourceDigests['rejected_codex']
            rejected_claude_sha256 = [string]$script:SourceDigests['rejected_claude']
            upgrade_gateway_sha256 = [string]$script:SourceDigests['upgrade_gateway']
            upgrade_hook_sha256 = [string]$script:SourceDigests['upgrade_hook']
            upgrade_cli_sha256 = [string]$script:SourceDigests['upgrade_cli']
        }
        fixture = [ordered]@{
            gateway_service = $script:GatewayServiceName
            guardian_service = $script:GuardianServiceName
            protected_active_user = $script:PrimaryUserName
            protected_active_sid = $script:PrimarySID
            protected_active_session_id = $script:PrimarySessionID
            protected_fixture_data_dir = $script:PrimaryDataDir
            certification_codex_home = $script:CertificationCodexHome
            certification_codex_home_initial_state = 'absent'
            protected_config_baseline_sha256 = $script:PrimaryConfigBaselineSHA256
            denial_user = $script:HostileUserName
            denial_user_sid = $script:HostileSID
            install_root = $script:InstallRoot
            state_root = $script:StateRoot
        }
        certification = [ordered]@{
            profile = if ($ClaudeOnly) {
                'claude-only-core'
            } else {
                'codex-and-claude-production'
            }
            core_hardening_complete = $coreHardeningComplete
            external_agent_application_control_attested =
                [bool]$AttestAgentApplicationControl
            codex_trusted_hook_launcher_attested =
                [bool]$AttestCodexTrustedHookLauncher
            claude_live_hostile_precedence_proof =
                $script:ClaudeLiveProcessProof
            claude_effective_policy_persisted =
                [bool]$script:ClaudeEffectivePolicyAttested
            codex_target_enabled = -not [bool]$ClaudeOnly
            stock_codex_supported = $false
            stock_codex_mandatory_negative_and_trusted_launcher_positive =
                $script:CodexLiveProcessProof
            trusted_codex_launcher_identity =
                $script:CodexTrustedHookLauncherIdentity
            security_complete = $productionCertified
            production_certified = $productionCertified
        }
        codex_home_isolation = [ordered]@{
            validation = $script:CertificationCodexHomeValidation
            actual_codex_process = $script:CodexLiveProcessProof
            protected_codex_binary = $script:CodexRuntimeBinary
            service_codex_home_absent = $true
            service_environment_proof = @(
                $script:CertificationServiceCodexHomeAbsenceProof
            )
            first_guardian_paths = $script:FirstGuardianPathProof
            machine_before = $script:MachineCodexHomeBaseline
            machine_mutation_attempted = $false
            machine_after = if ($null -ne $script:MachineCodexHomeBaseline) {
                Get-MachineCodexHomeSnapshot
            } else {
                $null
            }
            existing_process_environment_writes_attempted = $false
            coordinator_process_environment_unchanged = $true
            coordinator_process_before = $script:CoordinatorCodexHomeSnapshot
            live_codex_root = if ([string]::IsNullOrWhiteSpace($script:PrimaryProfile)) {
                ''
            } else {
                ConvertTo-CanonicalPath (Join-Path $script:PrimaryProfile '.codex')
            }
            live_codex_enumerated = $false
            live_codex_snapshotted = $false
            live_codex_mutated = $false
        }
        failure = Protect-SensitiveDisplayText $Failure
        results = $script:Results
        cleanup_ok = $script:CleanupErrors.Count -eq 0
        cleanup_errors = $script:CleanupErrors
    }
    $path = Join-Path $script:EvidenceDirectory 'windows-enterprise-certification.json'
    $evidenceJSON = $payload | ConvertTo-Json -Depth 12
    foreach ($secret in @($script:SecretNeedles.ToArray())) {
        if (-not [string]::IsNullOrWhiteSpace($secret) -and
            $evidenceJSON.Contains($secret)) {
            throw 'final evidence payload contains registered secret material'
        }
    }
    [IO.File]::WriteAllText(
        $path,
        $evidenceJSON,
        [Text.UTF8Encoding]::new($false)
    )
    return $path
}

if ($env:OS -ne 'Windows_NT') {
    throw 'Windows enterprise certification requires native Windows'
}
if (-not [Environment]::Is64BitProcess) {
    throw 'Windows enterprise certification requires 64-bit PowerShell'
}

$script:RepositoryRoot = ConvertTo-CanonicalPath (Split-Path -Parent $PSScriptRoot)
$resolvedInstallerPath = if ([string]::IsNullOrWhiteSpace($InstallerPath)) {
    Join-Path `
        $script:RepositoryRoot `
        'packaging\windows\install-enterprise.ps1'
} else {
    $InstallerPath
}
$script:Installer = ConvertTo-CanonicalPath $resolvedInstallerPath
$script:OriginalGatewaySource = ConvertTo-CanonicalPath $GatewayBinary
$script:OriginalHookSource = ConvertTo-CanonicalPath $HookBinary
$script:OriginalCLISource = ConvertTo-CanonicalPath $CLIBinary
$script:OriginalNormalModeCLILauncher = if (
    [string]::IsNullOrWhiteSpace($NormalModeCLILauncher)
) {
    ''
} else {
    ConvertTo-CanonicalPath $NormalModeCLILauncher
}
$script:OriginalNormalModeCLIWheel = if (
    [string]::IsNullOrWhiteSpace($NormalModeCLIWheel)
) {
    ''
} else {
    ConvertTo-CanonicalPath $NormalModeCLIWheel
}
$script:OriginalCodexSource = ConvertTo-CanonicalPath $CodexBinary
$script:OriginalClaudeSource = ConvertTo-CanonicalPath $ClaudeBinary
$script:OriginalRejectedCodexSource = ConvertTo-CanonicalPath $RejectedCodexBinary
$script:OriginalRejectedClaudeSource = ConvertTo-CanonicalPath $RejectedClaudeBinary
$script:OriginalCodexTrustedHookLauncherSource = if (
    [string]::IsNullOrWhiteSpace($CodexTrustedHookLauncherBinary)
) {
    ''
} else {
    ConvertTo-CanonicalPath $CodexTrustedHookLauncherBinary
}
if ($ClaudeOnly) {
    if ($AttestAgentApplicationControl -or
        $AttestCodexTrustedHookLauncher -or
        -not [string]::IsNullOrWhiteSpace(
            $script:OriginalCodexTrustedHookLauncherSource
        )) {
        throw (
            '-ClaudeOnly is a truthful core-hardening run and must not claim ' +
            'external application control or a Codex launcher; omit both ' +
            'attestation switches and -CodexTrustedHookLauncherBinary'
        )
    }
    if (-not $AllowUnsigned) {
        throw (
            '-ClaudeOnly requires -AllowUnsigned so the installer can ' +
            'authenticate the exact disposable certification scope; this ' +
            'never enables an unattested production install'
        )
    }
} elseif ([string]::IsNullOrWhiteSpace(
    $script:OriginalCodexTrustedHookLauncherSource
)) {
    throw (
        'Codex certification requires -CodexTrustedHookLauncherBinary with ' +
        'a separately signed fail-closed drop-in launcher; an attestation ' +
        'switch without the artifact is never sufficient'
    )
}
$script:OriginalModuleSource = ConvertTo-CanonicalPath (
    Join-Path (Split-Path -Parent $script:Installer) 'DefenseClawEnterprise.psm1'
)
$script:GatewaySource = $script:OriginalGatewaySource
$script:HookSource = $script:OriginalHookSource
$script:CLISource = $script:OriginalCLISource
$script:NormalModeCLILauncherSource =
    $script:OriginalNormalModeCLILauncher
$script:NormalModeCLIWheelSource = $script:OriginalNormalModeCLIWheel
$script:UpgradeGatewaySource = ''
$script:UpgradeHookSource = ''
$script:UpgradeCLISource = ''
$script:PowerShellExecutable = Get-PowerShellExecutable
foreach ($required in @(
    [pscustomobject]@{ Path = $script:Installer; Label = 'enterprise installer' },
    [pscustomobject]@{ Path = $script:OriginalModuleSource; Label = 'enterprise installer module' },
    [pscustomobject]@{ Path = $script:GatewaySource; Label = 'gateway binary' },
    [pscustomobject]@{ Path = $script:HookSource; Label = 'hook binary' },
    [pscustomobject]@{ Path = $script:CLISource; Label = 'CLI binary' },
    [pscustomobject]@{ Path = $script:OriginalCodexSource; Label = 'approved Codex binary' },
    [pscustomobject]@{ Path = $script:OriginalClaudeSource; Label = 'approved Claude binary' },
    [pscustomobject]@{ Path = $script:OriginalRejectedCodexSource; Label = 'rejected old Codex binary' },
    [pscustomobject]@{ Path = $script:OriginalRejectedClaudeSource; Label = 'rejected old Claude binary' }
)) {
    if (-not (Test-Path -LiteralPath $required.Path -PathType Leaf)) {
        throw "$($required.Label) is missing: $($required.Path)"
    }
}
foreach ($required in @(
    [pscustomobject]@{
        Path = $script:OriginalNormalModeCLILauncher
        Label = 'normal-mode Python CLI launcher'
    },
    [pscustomobject]@{
        Path = $script:OriginalNormalModeCLIWheel
        Label = 'normal-mode committed Python CLI wheel'
    }
)) {
    if (-not [string]::IsNullOrWhiteSpace($required.Path) -and
        -not (Test-Path -LiteralPath $required.Path -PathType Leaf)) {
        throw "$($required.Label) is missing: $($required.Path)"
    }
}
if (-not $ClaudeOnly -and
    -not (Test-Path -LiteralPath $script:OriginalCodexTrustedHookLauncherSource -PathType Leaf)) {
    throw (
        'Codex trusted hook launcher is missing: ' +
        $script:OriginalCodexTrustedHookLauncherSource
    )
}
$script:SourceDigests = [ordered]@{
    gateway = Get-FileDigest $script:OriginalGatewaySource
    hook = Get-FileDigest $script:OriginalHookSource
    cli = Get-FileDigest $script:OriginalCLISource
    normal_mode_cli_launcher = if (
        [string]::IsNullOrWhiteSpace(
            $script:OriginalNormalModeCLILauncher
        )
    ) {
        ''
    } else {
        Get-FileDigest $script:OriginalNormalModeCLILauncher
    }
    normal_mode_cli_wheel = if (
        [string]::IsNullOrWhiteSpace($script:OriginalNormalModeCLIWheel)
    ) {
        ''
    } else {
        Get-FileDigest $script:OriginalNormalModeCLIWheel
    }
    installer = Get-FileDigest $script:Installer
    module = Get-FileDigest $script:OriginalModuleSource
    codex = Get-FileDigest $script:OriginalCodexSource
    claude = Get-FileDigest $script:OriginalClaudeSource
    rejected_codex = Get-FileDigest $script:OriginalRejectedCodexSource
    rejected_claude = Get-FileDigest $script:OriginalRejectedClaudeSource
    codex_trusted_hook_launcher = if ($ClaudeOnly) {
        ''
    } else {
        Get-FileDigest $script:OriginalCodexTrustedHookLauncherSource
    }
    upgrade_gateway = if ([string]::IsNullOrWhiteSpace($UpgradeGatewayBinary)) {
        ''
    } else {
        Get-FileDigest (ConvertTo-CanonicalPath $UpgradeGatewayBinary)
    }
    upgrade_hook = if ([string]::IsNullOrWhiteSpace($UpgradeHookBinary)) {
        ''
    } else {
        Get-FileDigest (ConvertTo-CanonicalPath $UpgradeHookBinary)
    }
    upgrade_cli = if ([string]::IsNullOrWhiteSpace($UpgradeCLIBinary)) {
        ''
    } else {
        Get-FileDigest (ConvertTo-CanonicalPath $UpgradeCLIBinary)
    }
}

$script:RunToken = ([Guid]::NewGuid().ToString('N')).Substring(0, 10)
$script:GatewayServiceName = "DefenseClawCertGateway_$($script:RunToken)"
$script:GuardianServiceName = "DefenseClawCertGuardian_$($script:RunToken)"
$script:PrimaryUserName = '<active-wts-user>'
$script:HostileUserName = 'DCEH' + $script:RunToken.Substring(0, 8)
Assert-CertificationServiceName $script:GatewayServiceName 'gateway'
Assert-CertificationServiceName $script:GuardianServiceName 'guardian'
Assert-CertificationUserName $script:HostileUserName 'hostile'

$script:KnownProgramFiles = ConvertTo-CanonicalPath (
    [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
)
$script:KnownProgramData = ConvertTo-CanonicalPath (
    [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
)
$script:CodexVendorDirectory = ConvertTo-CanonicalPath (
    Join-Path $script:KnownProgramData 'OpenAI'
)
$script:LifecycleLockDirectory = ConvertTo-CanonicalPath (
    Join-Path $script:KnownProgramData 'Cisco\DefenseClaw-Lifecycle'
)
$script:LifecycleLockPath = Assert-PathBelow `
    (Join-Path $script:LifecycleLockDirectory 'lifecycle.lock') `
    $script:KnownProgramData `
    'enterprise lifecycle lock'
$script:CodexMachinePolicyDirectory = Assert-PathBelow `
    (Join-Path $script:CodexVendorDirectory 'Codex') `
    $script:KnownProgramData `
    'Codex machine-policy parent'
$script:ClaudeManagedPolicyRoot = ConvertTo-CanonicalPath (
    Join-Path $script:KnownProgramFiles 'ClaudeCode'
)
$script:ClaudeManagedPolicyDirectory = Assert-PathBelow `
    (Join-Path $script:ClaudeManagedPolicyRoot 'managed-settings.d') `
    $script:KnownProgramFiles `
    'Claude managed-policy directory'
$script:ClaudeManagedPolicyPath = Assert-PathBelow `
    (Join-Path $script:ClaudeManagedPolicyDirectory '90-defenseclaw.json') `
    $script:ClaudeManagedPolicyRoot `
    'Claude DefenseClaw managed policy'
$script:ClaudeManagedStatePath = Assert-PathBelow `
    (Join-Path `
        $script:ClaudeManagedPolicyDirectory `
        '.defenseclaw-managed-hooks.state') `
    $script:ClaudeManagedPolicyRoot `
    'Claude managed-policy state'
$script:ClaudeManagedLockPath = Assert-PathBelow `
    (Join-Path `
        $script:ClaudeManagedPolicyDirectory `
        '.defenseclaw-managed-hooks.lock') `
    $script:ClaudeManagedPolicyRoot `
    'Claude managed-policy transaction lock'
$script:WindowsDirectory = ConvertTo-CanonicalPath (
    [Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)
)
$script:System32 = Assert-PathBelow `
    (Join-Path $script:WindowsDirectory 'System32') `
    $script:WindowsDirectory `
    'Windows System32'
$script:BootstrapPowerShellExecutable = Assert-PathBelow `
    (Join-Path $script:System32 'WindowsPowerShell\v1.0\powershell.exe') `
    $script:System32 `
    'fixed Windows PowerShell bootstrap'
if (-not (Test-Path -LiteralPath $script:BootstrapPowerShellExecutable -PathType Leaf)) {
    throw "fixed Windows PowerShell bootstrap is missing: $($script:BootstrapPowerShellExecutable)"
}
$script:ProgramFilesCertificationRoot = ConvertTo-CanonicalPath (
    Join-Path $script:KnownProgramFiles 'Cisco\DefenseClaw-Cert'
)
$script:ProgramDataCertificationRoot = ConvertTo-CanonicalPath (
    Join-Path $script:KnownProgramData 'Cisco\DefenseClaw-Cert'
)
$script:ProgramDataStagingRoot = ConvertTo-CanonicalPath (
    Join-Path $script:KnownProgramData 'Cisco\DefenseClaw-Cert-Staging'
)
$script:ProgramDataWorkRoot = ConvertTo-CanonicalPath (
    Join-Path $script:KnownProgramData 'Cisco\DefenseClaw-Cert-Work'
)
$script:InstallRoot = Assert-PathBelow `
    (Join-Path $script:ProgramFilesCertificationRoot $script:RunToken) `
    $script:ProgramFilesCertificationRoot `
    'install root'
$script:StateRoot = Assert-PathBelow `
    (Join-Path $script:ProgramDataCertificationRoot $script:RunToken) `
    $script:ProgramDataCertificationRoot `
    'state root'
$script:CodexRequirementsPath = ConvertTo-CanonicalPath (
    Join-Path $script:CodexMachinePolicyDirectory 'requirements.toml'
)
$script:CodexMachineLockPath = ConvertTo-CanonicalPath (
    Join-Path `
        $script:CodexMachinePolicyDirectory `
        '.defenseclaw-managed-hooks.lock'
)
$script:CodexManagedStatePath = ConvertTo-CanonicalPath (
    Join-Path `
        $script:CodexMachinePolicyDirectory `
        '.defenseclaw-managed-hooks.state'
)
$script:CodexRequirementsOwnershipPath = Assert-PathBelow `
    (Join-Path $script:StateRoot 'install\codex-requirements-ownership.json') `
    $script:StateRoot `
    'Codex requirements ownership record'
$script:CodexRequirementsAclBackupPath = Assert-PathBelow `
    (Join-Path $script:StateRoot 'install\codex-requirements-acl-backup.json') `
    $script:StateRoot `
    'Codex requirements ACL preimage'
$script:AgentApplicationControlAttestationPath = Assert-PathBelow `
    (Join-Path $script:StateRoot 'install\agent-application-control-attestation.json') `
    $script:StateRoot `
    'agent application-control attestation'
$script:StagingRoot = Assert-PathBelow `
    (Join-Path $script:ProgramDataStagingRoot $script:RunToken) `
    $script:ProgramDataStagingRoot `
    'staging root'
$script:WorkRoot = Assert-PathBelow `
    (Join-Path $script:ProgramDataWorkRoot $script:RunToken) `
    $script:ProgramDataWorkRoot `
    'work root'
$script:FixtureRoot = Join-Path $script:StagingRoot 'fixtures'
$script:ConfigSource = Join-Path $script:StagingRoot 'config.yaml'
$script:ManifestSource = Join-Path $script:StagingRoot 'targets.yaml'
Assert-CertificationScope
$script:MachineCodexHomeBaseline = Get-MachineCodexHomeSnapshot

if ([string]::IsNullOrWhiteSpace($EvidenceRoot)) {
    $EvidenceRoot = Join-Path $script:RepositoryRoot 'artifacts\windows-enterprise-certification'
}
$script:EvidenceRootPath = ConvertTo-CanonicalPath $EvidenceRoot
$script:EvidenceDirectory = Join-Path $script:EvidenceRootPath $script:RunToken

$plan = [ordered]@{
    schema_version = $script:HarnessSchemaVersion
    mode = if ($script:PlanOnly) { 'plan' } else { 'execute' }
    run_id = $script:RunToken
    installer = $script:Installer
    installer_bootstrap = $script:BootstrapPowerShellExecutable
    gateway_source = $script:GatewaySource
    hook_source = $script:HookSource
    cli_source = $script:CLISource
    normal_mode_cli_launcher_source = $script:NormalModeCLILauncherSource
    normal_mode_cli_wheel_source = $script:NormalModeCLIWheelSource
    codex_source = $script:OriginalCodexSource
    codex_trusted_hook_launcher_source =
        $script:OriginalCodexTrustedHookLauncherSource
    claude_source = $script:OriginalClaudeSource
    rejected_codex_source = $script:OriginalRejectedCodexSource
    rejected_claude_source = $script:OriginalRejectedClaudeSource
    gateway_service = $script:GatewayServiceName
    guardian_service = $script:GuardianServiceName
    protected_active_user = $script:PrimaryUserName
    protected_active_sid_filter = $ProtectedUserSID
    generated_denial_user = $script:HostileUserName
    certification_codex_home = '<active-WTS-profile>\.codex-defenseclaw-cert-<run_id>'
    certification_codex_home_process_scope_only = $true
    machine_codex_home_mutation = $false
    service_codex_home_entries = 0
    live_codex_enumerated = $false
    live_codex_snapshotted = $false
    live_codex_mutated = $false
    install_root = $script:InstallRoot
    state_root = $script:StateRoot
    codex_vendor_directory = $script:CodexVendorDirectory
    codex_machine_policy_directory = $script:CodexMachinePolicyDirectory
    claude_managed_policy_path = $script:ClaudeManagedPolicyPath
    claude_managed_state_path = $script:ClaudeManagedStatePath
    staging_root = $script:StagingRoot
    work_root = $script:WorkRoot
    evidence_directory = $script:EvidenceDirectory
    allow_unsigned_fixture_binaries = [bool]$AllowUnsigned
    agent_application_control_attested = [bool]$AttestAgentApplicationControl
    codex_trusted_hook_launcher_attested =
        [bool]$AttestCodexTrustedHookLauncher
    codex_target_enabled = -not [bool]$ClaudeOnly
    claude_target_enabled = $true
    claude_effective_policy_initially_attested = $false
    claude_effective_policy_attestation_after_live_proof =
        -not [bool]$ClaudeOnly
    initial_security_complete = $false
    core_mode_security_complete = $false
    lifecycle_scope_matrix = [ordered]@{
        full_unsigned = [ordered]@{
            action = 'install|upgrade|repair'
            certification_codex_home = $true
            allow_unsigned = $true
            core_hardening_certification = $false
        }
        claude_only_unsigned = [ordered]@{
            action = 'install|upgrade|repair'
            certification_codex_home = $true
            allow_unsigned = $true
            core_hardening_certification = $true
        }
        signed_production = [ordered]@{
            action = 'install|upgrade|repair'
            certification_codex_home = $false
            allow_unsigned = $false
            core_hardening_certification = $false
        }
        read_only = [ordered]@{
            action = 'status|verify|reconcile|uninstall'
            certification_codex_home = $false
            allow_unsigned = $false
            core_hardening_certification = $false
        }
    }
    certification_profile = if ($ClaudeOnly) {
        'claude-only-core'
    } else {
        'codex-and-claude'
    }
    host_mutation = -not $script:PlanOnly
}

if ($script:PlanOnly) {
    $plan | ConvertTo-Json -Depth 5
    exit 0
}
if ([string]::IsNullOrWhiteSpace($script:OriginalNormalModeCLILauncher) -or
    [string]::IsNullOrWhiteSpace($script:OriginalNormalModeCLIWheel)) {
    throw (
        'full execution requires -NormalModeCLILauncher and ' +
        '-NormalModeCLIWheel from the clean committed Python CLI build'
    )
}
if (-not $DisposableHost) {
    throw 'host mutation requires both -Execute and -DisposableHost'
}
if ([string]::IsNullOrWhiteSpace($UpgradeGatewayBinary) -or
    [string]::IsNullOrWhiteSpace($UpgradeHookBinary) -or
    [string]::IsNullOrWhiteSpace($UpgradeCLIBinary)) {
    throw (
        'full execution requires -UpgradeGatewayBinary, ' +
        '-UpgradeHookBinary, and -UpgradeCLIBinary from a separately ' +
        'version-stamped build'
    )
}
if (-not $ClaudeOnly -and -not $AttestAgentApplicationControl) {
    throw (
        'Windows managed enterprise requires explicit ' +
        '-AttestAgentApplicationControl after WDAC/AppLocker policy blocks ' +
        'unapproved and old agent clients'
    )
}
if (-not $ClaudeOnly -and -not $AttestCodexTrustedHookLauncher) {
    throw (
        'this certification enables Codex and therefore requires explicit ' +
        '-AttestCodexTrustedHookLauncher after a separately verified, ' +
        'fail-closed fixed hook launcher is deployed; stock Codex 0.144.3 ' +
        'is not sufficient because hook-launch failures are non-blocking'
    )
}
if (-not (Test-IsElevatedAdministrator)) {
    throw 'execution requires an elevated administrator token'
}
foreach ($name in @($script:GatewayServiceName, $script:GuardianServiceName)) {
    if ($null -ne (Get-Service -Name $name -ErrorAction SilentlyContinue)) {
        throw "refusing pre-existing certification service: $name"
    }
}
foreach ($path in @($script:InstallRoot, $script:StateRoot, $script:StagingRoot, $script:WorkRoot)) {
    if (Test-Path -LiteralPath $path) {
        throw "refusing pre-existing certification path: $path"
    }
}
foreach ($path in @(
    $script:CodexVendorDirectory,
    $script:CodexMachinePolicyDirectory
)) {
    if (Test-Path -LiteralPath $path) {
        throw (
            'full shared-directory certification requires a clean disposable ' +
            "host with this path initially absent: $path"
        )
    }
}
foreach ($path in @(
    $script:ClaudeManagedPolicyPath,
    $script:ClaudeManagedStatePath,
    $script:ClaudeManagedLockPath
)) {
    if (Test-Path -LiteralPath $path) {
        throw (
            'full Claude policy certification requires the exact DefenseClaw ' +
            "artifact initially absent: $path"
        )
    }
}

$failure = ''
$completed = $false
try {
    $script:Phase = 'fixture'
    foreach ($root in @(
        $script:WorkRoot,
        $script:StagingRoot,
        $script:FixtureRoot
    )) {
        [IO.Directory]::CreateDirectory($root) | Out-Null
    }
    Protect-AdministratorTree $script:StagingRoot
    Protect-AdministratorTree $script:WorkRoot

    Invoke-Check 'active-protected-user-and-temporary-denial-user' {
        $primary = Resolve-ProtectedActiveUser $ProtectedUserSID
        $script:PrimaryUserName = [string]$primary.account
        $script:PrimarySID = [string]$primary.sid
        $script:PrimaryProfile = ConvertTo-CanonicalPath ([string]$primary.profile)
        $script:PrimarySessionID = [int]$primary.session_id
        $script:PrimaryDataDir = Assert-PathBelow `
            (Join-Path $script:PrimaryProfile '.defenseclaw') `
            $script:PrimaryProfile `
            'canonical protected user data dir'
        $script:CertificationCodexHome = Assert-CertificationCodexHomePath (
            Join-Path `
                $script:PrimaryProfile `
                ".codex-defenseclaw-cert-$($script:RunToken)"
        )
        if (Test-Path -LiteralPath $script:CertificationCodexHome) {
            throw (
                'refusing pre-existing certification CODEX_HOME; the live ' +
                "profile is left untouched: $($script:CertificationCodexHome)"
            )
        }
        $null = New-ProtectedUserTreeSnapshot `
            $script:PrimaryDataDir `
            'defenseclaw'
        Initialize-ActiveUserHandoff

        $script:HostileCredential = New-RandomCredential $script:HostileUserName
        $script:HostileSID = New-CertificationLocalUser `
            $script:HostileUserName `
            $script:HostileCredential
        $script:HostileUserCreated = $true
        $hostile = Initialize-CertificationProfile `
            $script:HostileCredential `
            'initialize-hostile-profile'
        if ([string]$hostile.sid -ne $script:HostileSID) {
            throw "hostile profile SID mismatch: $($hostile.sid) != $($script:HostileSID)"
        }
        $script:HostileProfile = ConvertTo-CanonicalPath ([string]$hostile.profile)
        $token = Assert-ProtectedUserTamperToken
        return "active target $($script:PrimaryUserName) session=$($script:PrimarySessionID); created exact non-admin denial user $($script:HostileUserName); $token"
    }
    Invoke-Check 'protected-source-staging' {
        Initialize-ProtectedCertificationSources
    }
    Invoke-Check 'protected-approved-agent-runtimes' {
        $runtime = Initialize-ProtectedCodexRuntime
        $launcherDetail = if ($ClaudeOnly) {
            'Codex launcher intentionally omitted for Claude-only/core mode'
        } else {
            (
                'separately signed stock-distinct launcher ' +
                "$($runtime.codex_trusted_hook_launcher_sha256)"
            )
        }
        return (
            "staged OpenAI-signed $($runtime.codex_version) " +
            "($($runtime.codex_version_source)), " +
            "Anthropic-signed $($runtime.claude_version), and $launcherDetail; " +
            'the enrolled standard user can execute approved clients but ' +
            'cannot modify them'
        )
    }

    $script:Phase = 'normal-mode-noop'
    try {
        $normalPreinstall = Test-NormalModeLiveAutoHeal `
            -RequireEnterpriseAbsent
        Add-Result `
            'preinstall-normal-mode-live-hook-auto-heal-is-no-op' `
            'passed' `
            'the real unmanaged init/setup path repaired an exact tampered per-user Codex registration while every enterprise machine path, file digest, and service remained at its absent baseline' `
            @{ evidence = $normalPreinstall }
    } catch {
        Add-Result `
            'preinstall-normal-mode-live-hook-auto-heal-is-no-op' `
            'failed' `
            $_.Exception.Message
        throw
    }
    Invoke-Check 'preinstall-normal-mode-is-no-op' {
        Test-NormalModePreinstallNoOp
    }
    $script:Phase = 'certification-isolation'
    Invoke-Check 'certification-codex-home-fixture' {
        $fixture = Initialize-CertificationCodexHome
        return (
            "created absent-baseline target-owned CODEX_HOME $($fixture.path) " +
            'as an exact same-profile direct child on fixed NTFS'
        )
    }
    Invoke-Check 'machine-and-coordinator-codex-home-untouched-before-install' {
        $null = Assert-MachineCodexHomeUnchanged
        return 'machine and coordinator process CODEX_HOME stayed byte/type/existence exact'
    }

    $apiPort = Get-FreeLoopbackPort
    $script:APIPort = $apiPort
    $proxyPort = Get-FreeLoopbackPort
    $stateYAML = $script:StateRoot.Replace("'", "''")
    $config = @"
config_version: 8
deployment_mode: managed_enterprise
data_dir: '$stateYAML\runtime'
observability:
  local:
    path: '$stateYAML\runtime\audit.db'
    judge_bodies_path: '$stateYAML\runtime\judge_bodies.db'
  defaults:
    redaction_profile: sensitive
plugin_dir: '$stateYAML\runtime\plugins'
policy_dir: '$stateYAML\runtime\policies'
gateway:
  device_key_file: '$stateYAML\runtime\device.key'
  api_bind: 127.0.0.1
  api_port: $apiPort
  config_reload:
    mode: restart
guardrail:
  enabled: true
  mode: observe
  scanner_mode: local
  host: 127.0.0.1
  port: $proxyPort
  hook_self_heal: true
application_protection:
  enabled: false
"@
    $primaryHomeYAML = $script:PrimaryProfile.Replace("'", "''")
    $primaryDataYAML = $script:PrimaryDataDir.Replace("'", "''")
    $manifest = if ($ClaudeOnly) {
        @"
version: 1
targets:
  - user_home: '$primaryHomeYAML'
    sid: '$($script:PrimarySID)'
    data_dir: '$primaryDataYAML'
    connector: claudecode
    agent_version: "2.1.207 (Claude Code)"
"@
    } else {
        @"
version: 1
targets:
  - user_home: '$primaryHomeYAML'
    sid: '$($script:PrimarySID)'
    data_dir: '$primaryDataYAML'
    connector: codex
    agent_version: "codex-cli 0.144.3"
  - user_home: '$primaryHomeYAML'
    sid: '$($script:PrimarySID)'
    data_dir: '$primaryDataYAML'
    connector: claudecode
    agent_version: "2.1.207 (Claude Code)"
"@
    }
    Write-ProtectedManifest $script:ConfigSource $config 'protect-config-source'
    Write-ProtectedManifest $script:ManifestSource $manifest 'protect-manifest-source'
    try {
        $unsignedScopeProof = Test-AllowUnsignedHarnessContract
        Add-Result `
            'allow-unsigned-certification-scope' `
            'passed' `
            'unsigned import is emitted only for mutating install/upgrade/repair inside the exact run-scoped service/root/CODEX_HOME grammar; production defaults and every near miss were rejected' `
            @{
                contract = $unsignedScopeProof
            }
    } catch {
        Add-Result `
            'allow-unsigned-certification-scope' `
            'failed' `
            $_.Exception.Message
        throw
    }

    $script:Phase = 'install'
    $script:CodexSharedOwnedByHarness = -not [bool]$ClaudeOnly
    if (-not $ClaudeOnly) {
        Invoke-Check 'codex-shared-parent-creation-rollback' {
            Test-CodexSharedDirectoryCreationRollback
        }
    }
    Invoke-Check 'enterprise-installer-install' {
        $installed = Invoke-PublicEnterpriseLifecycleCLIJSON `
            -Action Install `
            -FilePath $script:CLISource `
            -InstallerPath $script:Installer `
            -GatewaySource $script:GatewaySource `
            -HookSource $script:HookSource `
            -CLISource $script:CLISource `
            -ConfigSource $script:ConfigSource `
            -ManifestSource $script:ManifestSource `
            -NoStart `
            -Label 'external-release-public-initial-install-no-start'
        if (-not [bool]$installed.JSON.ok) {
            throw 'staged base public CLI Install returned zero with ok=false'
        }
        if ([int]$installed.JSON.schema_version -ne 1 -or
            [string]$installed.JSON.action -cne 'install' -or
            -not [bool]$installed.JSON.installed -or
            [bool]$installed.JSON.transaction_pending -or
            [string]$installed.JSON.gateway_service_state -cne 'stopped' -or
            [string]$installed.JSON.guardian_service_state -cne 'stopped' -or
            [bool]$installed.JSON.gateway_ready -or
            [bool]$installed.JSON.guardian_ready -or
            -not [string]::IsNullOrWhiteSpace(
                [string]$installed.JSON.guardian_generation
            ) -or
            [bool]$installed.JSON.claude_effective_policy_verified -or
            [bool]$installed.JSON.security_complete -or
            [bool]$installed.JSON.external_security_prerequisites_satisfied -or
            [bool]$installed.JSON.core_hardening_complete -or
            [bool]$installed.JSON.core_hardening_certification -ne
                [bool]$ClaudeOnly -or
            @($installed.JSON.errors).Count -ne 0) {
            throw (
                'initial Install -NoStart escaped disabled/incomplete staging ' +
                'or overclaimed pre-live Claude/security evidence: ' +
                (Protect-SensitiveDisplayText (
                    $installed.JSON | ConvertTo-Json -Compress -Depth 7
                ))
            )
        }
        $script:Installed = $true
        $null = Assert-CertificationServicesStoppedAndIndependent
        $activation =
            Invoke-CertificationActivationRepairAfterIsolationProof
        return (
            'the staged base public CLI Install -NoStart left both services ' +
            'disabled with PID zero and ' +
            'core_hardening_complete=false; direct gateway start failed, then ' +
            'the protected installed public Repair supplied no replacement ' +
            'sources and established fresh guardian-first readiness while ' +
            'pre-live Claude/security_complete remained honestly false; ' +
            "blocked-start diagnostic=$($activation.gateway_start_diagnostic)"
        )
    }
    if (-not $ClaudeOnly) {
        Invoke-Check 'codex-shared-parent-provisioning' {
            Test-CodexSharedDirectoryProvisioning
        }
    }
    Invoke-Check 'windows-service-contract' {
        Assert-ServiceContract
    }
    try {
        $serviceTokenSnapshot = Get-CertificationServiceTokenSnapshot
        Add-Result `
            'live-service-token-least-privilege' `
            'passed' `
            'live gateway/guardian TokenUser, system integrity, privileges, service SID groups, and restricted-token semantics match the hardened contract' `
            @{ service_tokens = @($serviceTokenSnapshot) }
    } catch {
        Add-Result `
            'live-service-token-least-privilege' `
            'failed' `
            $_.Exception.Message
        throw
    }
    Invoke-Check 'installer-status-and-verify' {
        foreach ($action in @('Status', 'Verify')) {
            $result = Invoke-EnterpriseInstallerJSON `
                -Action $action `
                -GatewaySource '' `
                -HookSource '' `
                -CLISource '' `
                -Label ("installer-" + $action.ToLowerInvariant() + '-json')
            if (-not [bool]$result.JSON.ok) {
                throw "installer $action returned zero with ok=false"
            }
            if ([bool]$result.JSON.claude_effective_policy_verified -or
                [bool]$result.JSON.security_complete -or
                [bool]$result.JSON.external_security_prerequisites_satisfied -or
                -not [bool]$result.JSON.core_hardening_complete) {
                throw (
                    "initial installer $action overclaimed Claude/security " +
                    'evidence or failed structural core hardening'
                )
            }
        }
        return 'installer Status and Verify emitted structural ok=true while Claude effective-policy and aggregate security remained false before live proof'
    }

    $script:Phase = 'cli'
    $installedManifest = Join-Path $script:StateRoot 'hook-guardian\targets.yaml'
    $guardianStatusEnvelope = $null
    Invoke-Check 'windows-service-mediated-reconcile-json' {
        $reconcile = Invoke-GuardianServiceReconcile -Label 'initial-localsystem-reconcile-json'
        if (-not [bool]$reconcile.JSON.ok) {
            throw 'service-mediated reconcile returned zero with ok=false'
        }
        Wait-ForServicesRunning
        $script:guardianStatusEnvelope = Invoke-GatewayJSON `
            -Arguments @('enterprise', 'hooks', 'status', '--manifest', $installedManifest) `
            -Label 'initial-guardian-status-json'
        $rows = @($script:guardianStatusEnvelope.JSON.state.results)
        $expectedRowCount = if ($ClaudeOnly) { 1 } else { 2 }
        if ($rows.Count -ne $expectedRowCount -or
            @($rows | Where-Object {
                -not [bool]$_.ok -or [string]$_.sid -ne $script:PrimarySID
            }).Count -ne 0) {
            throw 'LocalSystem guardian status omitted a successful enrolled target'
        }
        $connectors = @(
            $rows |
                ForEach-Object { [string]$_.connector } |
                Sort-Object -Unique
        )
        $expectedConnectors = if ($ClaudeOnly) {
            'claudecode'
        } else {
            'claudecode,codex'
        }
        if (($connectors -join ',') -cne $expectedConnectors) {
            throw "LocalSystem guardian covered wrong connectors: $($connectors -join ',')"
        }
        return (
            "LocalSystem guardian reconciled $expectedConnectors for exact " +
            "active SID $($script:PrimarySID) and lifecycle emitted ok=true"
        )
    }
    Invoke-Check 'cli-status-and-verify-json' {
        Assert-HealthyGuardianJSON 'initial'
    }
    try {
        $publicLifecycle =
            Test-PublicLifecycleInspectionAndReconcile
        Add-Result `
            'public-windows-status-verify-reconcile' `
            'passed' `
            'the installed public CLI executed Status, Verify, and Reconcile through the protected installer boundary; each emitted one truthful healthy JSON document with zero exit status and Reconcile restored guardian-first readiness' `
            @{ lifecycle = $publicLifecycle }
    } catch {
        Add-Result `
            'public-windows-status-verify-reconcile' `
            'failed' `
            $_.Exception.Message
        throw
    }
    if ($ClaudeOnly) {
        $null = Assert-ClaudeOnlyWindowsSecurityContract 'initial'
        $artifactSet = Get-ManagedClaudeArtifactSet `
            $script:guardianStatusEnvelope.JSON
    } else {
        $artifactSet = Get-ManagedCodexArtifactSet `
            $script:guardianStatusEnvelope.JSON
    }
    Register-CurrentCertificationSecrets
    $controlArtifactBaseline = Get-ArtifactSnapshots $artifactSet.Paths
    $controlDeploymentBaseline = Get-DeploymentDigests
    $controlLedgerPath = Join-Path $script:StateRoot 'hook-guardian-state\protected_targets.json'
    $controlLedgerDigest = Get-FileDigest $controlLedgerPath
    $controlMachinePolicyRoot = if ($ClaudeOnly) {
        $script:ClaudeManagedPolicyDirectory
    } else {
        $script:CodexVendorDirectory
    }
    $controlCodexSharedBaseline = Get-ProtectedUserTreeInventory `
        $controlMachinePolicyRoot `
        'managed machine policy directories before hostile probe'
    $serviceControlBaseline = Get-ServiceControlSnapshot 'before-hostile-control'
    $serviceProcessBaseline = Get-CertificationServiceProcessSnapshot

    $script:Phase = 'protected-boundary'
    Invoke-Check 'certification-scope-and-work-root-dacls' {
        Assert-CertificationScope
        foreach ($path in @($script:StagingRoot, $script:WorkRoot)) {
            foreach ($sid in @($script:PrimarySID, $script:HostileSID)) {
                Assert-NoStandardUserAccess -Path $path -SID $sid -DenyWrite
            }
        }
        return "staging/work roots are protected local ProgramData descendants; allow_unsigned=$([bool]$AllowUnsigned)"
    }
    Invoke-Check 'protected-path-dacls' {
        $protectedPaths = [Collections.Generic.List[string]]::new()
        foreach ($path in @(
            (Join-Path $script:InstallRoot 'bin\defenseclaw-gateway.exe'),
            (Join-Path $script:InstallRoot 'bin\defenseclaw-hook.exe'),
            (Join-Path $script:StateRoot 'etc\config.yaml'),
            (Join-Path $script:StateRoot 'hook-guardian\targets.yaml'),
            (Join-Path $script:StateRoot 'hook-guardian-state\protected_targets.json'),
            $script:LifecycleLockDirectory,
            $script:LifecycleLockPath,
            $script:ClaudeManagedPolicyDirectory,
            $script:ClaudeManagedPolicyPath,
            $script:ClaudeManagedStatePath,
            $script:ClaudeManagedLockPath
        )) {
            $protectedPaths.Add($path)
        }
        if (-not $ClaudeOnly) {
            foreach ($path in @(
                $script:CodexVendorDirectory,
                $script:CodexMachinePolicyDirectory,
                $script:CodexRequirementsPath,
                $script:CodexMachineLockPath,
                $script:CodexManagedStatePath,
                $script:CodexRequirementsOwnershipPath,
                $script:CodexRequirementsAclBackupPath,
                $script:AgentApplicationControlAttestationPath
            )) {
                $protectedPaths.Add($path)
            }
        }
        foreach ($path in $protectedPaths) {
            foreach ($sid in @($script:PrimarySID, $script:HostileSID)) {
                Assert-NoStandardUserAccess `
                    -Path $path `
                    -SID $sid `
                    -DenyWrite
            }
        }
        $secretPaths = [Collections.Generic.List[string]]::new()
        $secretPaths.Add((
            Join-Path `
                $script:StateRoot `
                $(if ($ClaudeOnly) {
                    'runtime\hooks\.hook-claudecode.token'
                } else {
                    'runtime\hooks\.hook-codex.token'
                })
        ))
        if (-not $ClaudeOnly) {
            foreach ($path in @(
                $script:CodexRequirementsOwnershipPath,
                $script:CodexRequirementsAclBackupPath,
                $script:AgentApplicationControlAttestationPath
            )) {
                $secretPaths.Add($path)
            }
        }
        foreach ($path in $secretPaths) {
            foreach ($sid in @($script:PrimarySID, $script:HostileSID)) {
                Assert-NoStandardUserAccess `
                    -Path $path `
                    -SID $sid `
                    -DenyRead `
                    -DenyWrite
            }
        }
        return 'binaries, policy, ledger, managed machine parents, and service credentials enforce the expected standard-user boundary'
    }
    Invoke-Check 'standard-user-control-denials' {
        Invoke-StandardUserControlProbe
    }
    try {
        $lifecycleLockEvidence = Test-ProtectedLifecycleLockSquattingDenied
        Add-Result `
            'predictable-lifecycle-lock-squatting-denied' `
            'passed' `
            'the active non-admin could not exclusively open/create, overwrite, or delete the predictable enterprise lifecycle lock; bytes, owner, DACL, and installer responsiveness remained exact' `
            @{ evidence = $lifecycleLockEvidence }
    } catch {
        Add-Result `
            'predictable-lifecycle-lock-squatting-denied' `
            'failed' `
            $_.Exception.Message
        throw
    }
    if ($ClaudeOnly) {
        Add-Result `
            'codex-machine-lock-squatting-boundary' `
            'not_applicable' `
            'Claude-only/core mode has no Codex machine requirements or protected Codex transaction lock; the protected lifecycle-file squatting boundary was still exercised' `
            @{ codex_target_enabled = $false }
    } else {
        try {
            $lockSquatting = Test-CodexMachineLockSquattingBoundaries
            Add-Result `
                'codex-machine-lock-squatting-boundary' `
                'passed' `
                'hostile and permissive objects at the retired predictable Global mutex name had zero influence; contention on the protected no-reparse/single-link Codex file lock failed closed within 30 seconds without changing policy/deployment, then recovered after release' `
                @{ evidence = $lockSquatting }
        } catch {
            Add-Result `
                'codex-machine-lock-squatting-boundary' `
                'failed' `
                $_.Exception.Message
            throw
        }
    }
    if (-not $ClaudeOnly) {
        Invoke-Check 'standard-users-cannot-tamper-codex-machine-policy' {
            Test-StandardUsersCannotTamperCodexMachinePolicy
        }
    }
    Invoke-Check 'unregistered-interactive-sid-fails-closed' {
        Test-UnregisteredInteractiveSIDFailsClosed
    }
    try {
        $deenrollment = Test-DisabledClaudeTargetDeenrollsExactly
        Add-Result `
            'disabled-target-exact-deenrollment-and-inert-runtime' `
            'passed' `
            'both disabling and then removing the last Claude target removed its SID from protected authorization and active machine policy, retained the exact per-user recovery runtime, and made direct managed invocation fail closed without authenticated audit' `
            @{ evidence = $deenrollment }
    } catch {
        Add-Result `
            'disabled-target-exact-deenrollment-and-inert-runtime' `
            'failed' `
            $_.Exception.Message
        throw
    }
    $postDeenrollmentStatus = Invoke-GatewayJSON `
        -Arguments @(
            'enterprise', 'hooks', 'status',
            '--manifest', $installedManifest
        ) `
        -Label 'post-deenrollment-restored-status'
    if ($ClaudeOnly) {
        $artifactSet = Get-ManagedClaudeArtifactSet `
            $postDeenrollmentStatus.JSON
    }
    $controlArtifactBaseline = Get-ArtifactSnapshots $artifactSet.Paths
    $controlLedgerDigest = Get-FileDigest $controlLedgerPath
    $controlCodexSharedBaseline = Get-ProtectedUserTreeInventory `
        $controlMachinePolicyRoot `
        'managed machine policy directories after de-enrollment restore'
    Invoke-Check 'normal-mode-live-hook-auto-heal-preserved' {
        Test-NormalModeLiveAutoHeal
    }
    Invoke-Check 'administrator-direct-generic-mutation-denied' {
        Test-AdministratorGenericMutationDenied
    }
    Invoke-Check 'service-survives-denied-control' {
        Wait-ForServicesRunning
        $afterProbe = Get-DeploymentDigests
        Assert-SameDigests `
            $controlDeploymentBaseline `
            $afterProbe `
            'hostile control probe'
        $afterArtifacts = Get-ArtifactSnapshots $artifactSet.Paths
        Assert-SameArtifactSnapshots `
            $controlArtifactBaseline `
            $afterArtifacts `
            'hostile unregister probe'
        $afterCodexShared = Get-ProtectedUserTreeInventory `
            $controlMachinePolicyRoot `
            'managed machine policy directories after hostile probe'
        Assert-SameUserTreeInventory `
            $controlCodexSharedBaseline `
            $afterCodexShared `
            'hostile managed machine-policy directory probe'
        if ([string]::IsNullOrWhiteSpace($controlLedgerDigest) -or
            (Get-FileDigest $controlLedgerPath) -ne $controlLedgerDigest) {
            throw 'hostile unregister probe changed the protected authorization ledger'
        }
        $afterServiceControl = Get-ServiceControlSnapshot 'after-hostile-control'
        Assert-SameServiceControlSnapshot `
            $serviceControlBaseline `
            $afterServiceControl `
            'hostile SCM probe'
        $afterServiceProcesses = Get-CertificationServiceProcessSnapshot
        Assert-SameObjectJSON `
            $serviceProcessBaseline `
            $afterServiceProcesses `
            'hostile process-termination probe'
        $responsive = Invoke-EnterpriseInstallerJSON `
            -Action Verify `
            -GatewaySource '' `
            -HookSource '' `
            -CLISource '' `
            -Label 'post-hostile-process-token-probe-installer-verify'
        if (-not [bool]$responsive.JSON.ok) {
            throw 'installer Verify found a service unresponsive after hostile process/token handle probes'
        }
        Assert-HealthyGuardianJSON 'standard-user-probe'
        return 'services/PIDs remained running/responsive; process and token mutation handles, SCM mutation, and file/ACL tamper were denied; SCM contract, ledger, deployment bytes, machine policy parent, and protected hook remained unchanged'
    }

    $script:Phase = 'repair'
    try {
        $claudePolicyRepair = Test-ClaudeManagedPolicyDeletionAutoHeal
        Add-Result `
            'claude-managed-policy-deletion-auto-heal' `
            'passed' `
            'with the guardian stopped, deleting the DefenseClaw-owned Claude machine policy made live status/effective-policy verification fail; the restarted guardian restored exact bytes and health' `
            @{ repair = $claudePolicyRepair }
        Add-Result `
            'application-control-is-not-claude-effective-policy' `
            'passed' `
            $(if ([bool]$claudePolicyRepair.application_control_attested) {
                'while protected application-control evidence remained present and byte-exact, deleting the Claude machine policy made live claude_effective_policy_verified=false; the two gates are independently recorded'
            } else {
                'core mode contained no application-control evidence, and deleting the Claude machine policy independently made live claude_effective_policy_verified=false; no field was inferred from the other'
            }) `
            @{ evidence = $claudePolicyRepair }
    } catch {
        Add-Result `
            'claude-managed-policy-deletion-auto-heal' `
            'failed' `
            $_.Exception.Message
        throw
    }
    if (-not $ClaudeOnly) {
        Invoke-Check 'codex-machine-policy-drift-auto-heal' {
            Test-CodexMachinePolicyAutoHeal
        }
    }
    Invoke-Check 'previously-authorized-root-obstruction-repair' {
        $obstruction = Test-PreviouslyAuthorizedRootObstructionRepair $artifactSet.Paths
        return (
            'target-token deletion and junction obstruction repaired without ' +
            "touching the outside target; delete=$($obstruction.DeletedRootRepairMilliseconds)ms; " +
            "junction=$($obstruction.JunctionRootRepairMilliseconds)ms"
        )
    }
    try {
        $deniedSelfDACLAttempts = Test-ActiveUserCannotInstallSelfDeny `
            $artifactSet.Paths
        Add-Result `
            'standard-user-self-deny-dacl-blocked' `
            'passed' `
            'the exact active medium target could not add target/SYSTEM/Administrators/OWNER RIGHTS deny ACEs; bytes and canonical DACL stayed exact' `
            @{ attempts = @($deniedSelfDACLAttempts) }
    } catch {
        Add-Result `
            'standard-user-self-deny-dacl-blocked' `
            'failed' `
            $_.Exception.Message
        throw
    }
    try {
        $selfDenyRecovery = Test-GuardianRepairsPreexistingSelfDenyDACL `
            $artifactSet.Paths
        Add-Result `
            'guardian-preexisting-self-deny-dacl-auto-heal' `
            'passed' `
            'with the guardian stopped, target/SYSTEM/Administrators/OWNER RIGHTS deny ACEs made status and verify unhealthy; the restarted guardian restored exact bytes, target owner, and canonical protected DACL while Backup/Restore returned to disabled idle state' `
            @{
                recoveries = @($selfDenyRecovery.cases)
                idle_service_tokens = @($selfDenyRecovery.idle_service_tokens)
            }
    } catch {
        Add-Result `
            'guardian-preexisting-self-deny-dacl-auto-heal' `
            'failed' `
            $_.Exception.Message
        throw
    }
    try {
        $sparseRecovery = Test-ManagedSparseOversizedArtifactRecovery `
            $artifactSet.Paths
        Add-Result `
            'guardian-sparse-oversized-runtime-auto-heal' `
            'passed' `
            'the exact registered medium user grew the managed token, JSON and flat sidecars, contract lock, and hook helper to 1-TiB sparse files; status/verify stayed unhealthy without restarting the guardian, then bounded quarantine replacement restored exact bytes/owner/DACL with bounded working-set growth and no secret evidence' `
            @{
                recovery = $sparseRecovery
            }
    } catch {
        Add-Result `
            'guardian-sparse-oversized-runtime-auto-heal' `
            'failed' `
            $_.Exception.Message
        throw
    }
    try {
        $hardLinkRecovery = Test-GuardianRepairsManagedHardLink `
            $artifactSet.Paths
        Add-Result `
            'guardian-managed-hardlink-auto-heal' `
            'passed' `
            'a target-created second name made status/verify unhealthy; the guardian quarantined and recreated the managed leaf with a new one-link file identity, removed its bounded quarantine, and preserved the outside bytes/owner/DACL exactly' `
            @{
                recovery = $hardLinkRecovery
            }
    } catch {
        Add-Result `
            'guardian-managed-hardlink-auto-heal' `
            'failed' `
            $_.Exception.Message
        throw
    }
    Invoke-Check 'truthful-unhealthy-and-auto-repair' {
        $repair = Test-TruthfulUnhealthyJSON $artifactSet.Paths
        return "tamper was unhealthy until guardian repair; recovery=$($repair.RepairMilliseconds)ms; $($repair.Settled)"
    }

    $script:Phase = 'service-recovery'
    try {
        $recoveryEvidence = Test-ServiceFailureRecovery
        Add-Result `
            'scm-repeated-restart-and-explicit-stop' `
            'passed' `
            'both services restarted after controlled failures 1-4 using 5s/15s/60s/final-repeat recovery, while explicit administrator Stop remained stopped beyond the final delay' `
            @{
                failure_action_contract = @($recoveryEvidence.contract)
                recovery_observations = @($recoveryEvidence.observations)
            }
    } catch {
        Add-Result `
            'scm-repeated-restart-and-explicit-stop' `
            'failed' `
            $_.Exception.Message
        throw
    }
    try {
        $queuedRestart = Test-QueuedFailureRestartDuringServicing
        Add-Result `
            'queued-scm-restart-during-servicing' `
            'passed' `
            'after the repeated 60-second SCM recovery action was armed by a real gateway crash, Repair -NoStart continuously held both services disabled/stopped through a fresh 65-second drain; the queued restart never obtained a PID, and a second public Repair restored guardian-first readiness' `
            @{ evidence = $queuedRestart }
    } catch {
        Add-Result `
            'queued-scm-restart-during-servicing' `
            'failed' `
            $_.Exception.Message
        throw
    }
    Invoke-Check 'gateway-port-hijack-and-restart-race-fail-closed' {
        Test-GatewayPortHijackFailsClosed
    }

    $script:Phase = 'fail-closed'
    Invoke-Check 'unsafe-manifest-dacl' {
        Test-UnsafeManifestDACL
    }
    Invoke-Check 'target-data-path-escape' {
        Test-PathEscapeFailsClosed
    }
    Invoke-Check 'target-data-reparse-point' {
        Test-ReparseDataDirFailsClosed
    }
    if (-not $ClaudeOnly) {
        Invoke-Check 'managed-enterprise-does-not-consult-user-codex-config' {
            Test-ManagedEnterpriseIgnoresUserCodexConfig
        }
    }
    Invoke-Check 'partial-failure-remains-truthful' {
        Assert-HealthyGuardianJSON 'after-partial-fixtures'
    }

    $script:Phase = 'servicing'
    Invoke-Check 'failed-upgrade-preserves-transaction' {
        Test-FailedUpgradePreservesTransaction
    }
    Invoke-Check 'post-snapshot-activation-failure-rolls-back' {
        Test-PostSnapshotActivationFailureRollsBack
    }
    Test-UpgradeTransaction
    try {
        $publicReinstall = Test-PublicDefaultUninstallAndReinstall
        Add-Result `
            'public-windows-default-uninstall-and-install' `
            'passed' `
            'the protected external release CLI executed default Uninstall without --purge, preserved exact real audit/log/guardian evidence plus its sentinel, converted every retained StateRoot DACL to administrator-only, denied medium-user write/delete access while both services were absent, removed machine wiring before fresh clients, then restored the exact upgraded binaries, service contract, and guardian readiness' `
            @{ lifecycle = $publicReinstall }
    } catch {
        Add-Result `
            'public-windows-default-uninstall-and-install' `
            'failed' `
            $_.Exception.Message
        throw
    }

    $script:Phase = 'final-verify'
    Invoke-Check 'final-installer-and-guardian-verify' {
        $null = Invoke-EnterpriseInstaller -Action Verify -Label 'final-installer-verify'
        Assert-ServiceContract | Out-Null
        Assert-HealthyGuardianJSON 'final'
    }
    if ($ClaudeOnly) {
        Add-Result `
            'live-approved-and-rejected-agent-application-control' `
            'external_gate_not_run' `
            'Claude-only/core mode deliberately supplied no WDAC/AppLocker attestation; application-control enforcement and aggregate security_complete remain false' `
            @{
                attested = $false
                security_complete = $false
                production_certified = $false
            }
    } else {
        Invoke-Check 'live-approved-and-rejected-agent-application-control' {
            Test-AgentApplicationControlBoundary
        }
    }
    try {
        $claudeRun = Invoke-ActualClaudeCertificationRun `
            -Label 'actual-claude-managed-policy-hostile-user-project-settings'
        Add-Result `
            'actual-claude-effective-managed-policy' `
            'passed' `
            'the protected Anthropic-signed Claude client ran against a local no-auth Messages stub with hostile user/project disableAllHooks and custom hook settings; the hostile hooks did not run, and the operation contacted both managed hooks or failed closed' `
            @{ run = $claudeRun }
        $script:ClaudeLiveProcessProof = $claudeRun
    } catch {
        Add-Result `
            'actual-claude-effective-managed-policy' `
            'failed' `
            $_.Exception.Message
        throw
    }
    if ($ClaudeOnly) {
        $script:ClaudeEffectivePolicyAttested = $false
        $coreReport = Assert-ClaudeOnlyWindowsSecurityContract `
            'post-live-claude-core'
        Add-Result `
            'claude-effective-policy-evidence-persistence' `
            'core_evidence_only' `
            'the live hostile-precedence proof was recorded in certification evidence only; core mode did not emit -AttestClaudeEffectivePolicy, persisted no production attestation, and kept security_complete=false' `
            @{
                live_proof = $claudeRun
                persisted_production_attestation = $false
                claude_effective_policy_verified =
                    [bool]$coreReport.claude_effective_policy_verified
                security_complete = [bool]$coreReport.security_complete
            }
    } else {
        try {
            $script:ClaudeEffectivePolicyAttested = $true
            $attestedRepair = Invoke-EnterpriseInstallerJSON `
                -Action Repair `
                -Label 'repair-attest-live-claude-effective-policy'
            if (-not [bool]$attestedRepair.JSON.ok -or
                -not [bool](
                    $attestedRepair.JSON.claude_effective_policy_verified
                ) -or
                -not [bool]$attestedRepair.JSON.security_complete -or
                -not [bool](
                    $attestedRepair.JSON.
                        external_security_prerequisites_satisfied
                )) {
                throw (
                    'post-live Repair did not persist independent Claude ' +
                    'effective-policy evidence or complete aggregate security'
                )
            }
            $phaseContract = Assert-CodexMachinePolicyContract `
                'post-live-claude-attestation'
            $attestedStatus = Invoke-GatewayJSON `
                -Arguments @(
                    'enterprise', 'hooks', 'status',
                    '--manifest', $installedManifest
                ) `
                -Label 'post-live-claude-attested-status'
            if (-not [bool]$attestedStatus.JSON.ok -or
                -not [bool](
                    $attestedStatus.JSON.
                        claude_effective_policy_verified
                )) {
                throw 'guardian status did not surface the persisted live Claude proof'
            }
            Add-Result `
                'claude-effective-policy-evidence-persistence' `
                'passed' `
                'initial Install remained incomplete; only after the real hostile-precedence Claude proof did Repair receive -AttestClaudeEffectivePolicy, bind it to the protected manifest, and make aggregate security_complete=true' `
                @{
                    live_proof = $claudeRun
                    repair = $attestedRepair.JSON
                    machine_policy = $phaseContract.report
                }
        } catch {
            Add-Result `
                'claude-effective-policy-evidence-persistence' `
                'failed' `
                $_.Exception.Message
            throw
        }
    }
    try {
        $stockNegative = Invoke-ActualCodexCertificationRun `
            -Label 'stock-codex-0.144.3-blocked-shell-fail-open-negative' `
            -BinaryPath $script:CodexRuntimeBinary `
            -ExpectedSHA256 ([string]$script:SourceDigests['codex']) `
            -BinaryRole stock `
            -DeleteUserConfig `
            -HostileShell
        Add-Result `
            'stock-codex-0.144.3-rejected-for-enterprise' `
            'passed' `
            $(if ($ClaudeOnly) {
                'mandatory negative reproduced without external app control: stock signed Codex selected the user-writable fake shell, then reached the provider and exited zero with no managed hook contact; stock_codex_supported remains false'
            } else {
                'mandatory negative reproduced: stock signed Codex reached the provider and exited zero after its hook shell was OS-blocked, with no managed hook contact; stock_codex_supported remains false'
            }) `
            @{ run = $stockNegative }
    } catch {
        Add-Result `
            'stock-codex-0.144.3-rejected-for-enterprise' `
            'failed' `
            $_.Exception.Message
        throw
    }
    if ($ClaudeOnly) {
        Add-Result `
            'codex-trusted-hook-launcher-certification' `
            'not_applicable' `
            'Claude-only/core certification intentionally omitted the Codex target and launcher attestation; stock Codex remains explicitly uncertified' `
            @{
                codex_target_enabled = $false
                codex_trusted_hook_launcher_verified = $false
                stock_codex_supported = $false
            }
    } else {
        try {
            $codexRuns = [Collections.Generic.List[object]]::new()
            foreach ($run in @(
                [pscustomobject]@{
                    label = 'actual-trusted-codex-launcher-hostile-user-config'
                    delete = $false
                    bypass = $true
                    hostile_shell = $false
                },
                [pscustomobject]@{
                    label = 'actual-trusted-codex-launcher-deleted-user-config'
                    delete = $true
                    bypass = $false
                    hostile_shell = $false
                },
                [pscustomobject]@{
                    label = 'actual-trusted-codex-launcher-hostile-shell-path'
                    delete = $true
                    bypass = $false
                    hostile_shell = $true
                }
            )) {
                $arguments = @{
                    Label = [string]$run.label
                    BinaryPath =
                        $script:CodexTrustedHookLauncherRuntimeBinary
                    ExpectedSHA256 = [string](
                        $script:CodexTrustedHookLauncherIdentity.sha256
                    )
                    BinaryRole = 'trusted_launcher'
                    DeleteUserConfig = [bool]$run.delete
                    BypassHookTrust = [bool]$run.bypass
                    HostileShell = [bool]$run.hostile_shell
                }
                $codexRuns.Add((
                    Invoke-ActualCodexCertificationRun @arguments
                ))
            }
            if (@($codexRuns | Where-Object {
                [string]$_.enforcement_outcome -eq 'managed_hook_contact'
            }).Count -lt 1 -or
                @($codexRuns | Where-Object {
                    -not [bool]$_.accepted_for_enterprise
                }).Count -ne 0) {
                throw (
                    'trusted Codex launcher never completed a real managed-hook ' +
                    'contact or returned a non-accepted run'
                )
            }
            $script:CodexLiveProcessProof = @($codexRuns.ToArray())
            Add-Result `
                'actual-codex-trusted-hook-launcher-enforcement' `
                'passed' `
                'the separately signed, stock-distinct launcher was actually invoked with drop-in Codex exec argv; every hostile case either contacted both managed hooks or blocked the operation, and at least one completed through the loopback Responses provider' `
                @{
                    launcher = $script:CodexTrustedHookLauncherIdentity
                    runs = @($codexRuns.ToArray())
                }
        } catch {
            Add-Result `
                'actual-codex-trusted-hook-launcher-enforcement' `
                'failed' `
                $_.Exception.Message
            throw
        }
    }
    $script:Phase = 'removal-boundary'
    Invoke-Check 'surgical-machine-policy-purge-preserves-unrelated-content' {
        Test-CodexSharedDirectoriesPersistThroughPurge
    }
    if (-not $ClaudeOnly) {
        Invoke-Check 'preexisting-codex-parent-persists-through-failed-install' {
            Test-CodexSharedDirectoriesSurviveFailedInstall
        }
        Invoke-Check 'unsafe-codex-parent-owner-dacl-fails-closed' {
            Test-UnsafeCodexSharedDirectoryFailsClosed
        }
        Invoke-Check 'reparse-codex-parent-fails-closed' {
            Test-ReparseCodexSharedDirectoryFailsClosed
        }
        $script:CodexSharedExpectedBeforeCleanup =
            Get-ProtectedUserTreeInventory `
                $script:CodexVendorDirectory `
                'Codex shared directories before final fixture cleanup'
    }
    $script:Phase = 'final-verify'
    Invoke-Check 'evidence-secret-hygiene' {
        Register-CurrentCertificationSecrets
        Protect-TreeFromRegisteredSecretLeak $script:WorkRoot 'certification work logs'
        return "registered $($script:SecretNeedles.Count) secret value(s); no raw value appears in retained logs or result details"
    }
    $completed = $true
} catch {
    $failure = $_.Exception.Message
    Add-Result 'harness-failure' 'failed' $failure
} finally {
    try {
        if (-not (Test-Path -LiteralPath $script:EvidenceDirectory -PathType Container)) {
            [IO.Directory]::CreateDirectory($script:EvidenceDirectory) | Out-Null
        }
    } catch {
        $script:CleanupErrors.Add(
            'create evidence directory: ' + (Protect-SensitiveDisplayText $_.Exception.Message)
        )
    }
    Invoke-BoundedCleanup
    $status = if ($completed -and $script:CleanupErrors.Count -eq 0) {
        'passed'
    } elseif ($completed) {
        'passed_with_cleanup_errors'
    } else {
        'failed'
    }
    try {
        $evidencePath = Write-FinalEvidence $status $failure
        Write-Host "Windows enterprise certification evidence: $evidencePath"
    } catch {
        Write-Error "failed to write certification evidence: $($_.Exception.Message)"
        $completed = $false
    }
}

if (-not $completed) {
    throw "Windows enterprise certification failed: $failure"
}
if ($script:CleanupErrors.Count -ne 0) {
    throw "Windows enterprise certification passed but cleanup failed: $($script:CleanupErrors -join '; ')"
}

Write-Host 'Windows enterprise certification passed.'
