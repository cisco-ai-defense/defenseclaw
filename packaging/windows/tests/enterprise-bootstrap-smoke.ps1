# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 5.1

# How to run: from an elevated PowerShell 5.1 or 7 session (including elevated
# SSH or an interactive UAC-consent admin session), or as a standard user.
# The raw DOS-device checks need an effective medium-integrity non-admin token.
# A standard user already has one. An elevated caller starts its worker with the
# UAC-linked limited token when the launcher can duplicate it (CI). When it
# cannot (no UAC split, as in elevated SSH or with UAC off, or a UAC-consent
# session whose linked token is identification-level only), it creates a
# throwaway local standard user and a one-shot scheduled task, runs the
# worker there from a staging folder only that user and administrators can
# write, accepts only a result that user wrote with this run's nonce, and
# removes the task, the user, the folder and the profile. A profile Windows
# still holds is removed by the next run. The worker refuses to run under any
# other token. The script writes the route it used and every cleanup warning to
# stderr and fails with a message naming how to run it when neither is
# available.

[CmdletBinding()]
param(
    [string]$BasicUserResultPath = '',
    [string]$BasicUserResultNonce = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$installerSource = [IO.Path]::GetFullPath(
    (Join-Path $PSScriptRoot '..\install-enterprise.ps1')
)
$moduleSource = [IO.Path]::GetFullPath(
    (Join-Path $PSScriptRoot '..\DefenseClawEnterprise.psm1')
)
$engine = if ($PSVersionTable.PSEdition -eq 'Core') {
    Join-Path $PSHOME 'pwsh.exe'
}
else {
    Join-Path $PSHOME 'powershell.exe'
}

function Test-EffectiveMediumNonAdminUser {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    $whoamiPath = Join-Path $env:SystemRoot 'System32\whoami.exe'
    $groupText = & $whoamiPath /groups /fo csv /nh 2>$null | Out-String
    return (-not $principal.IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator
        ) -and $groupText -match 'S-1-16-8192')
}

function Write-BasicUserResult {
    param([Parameter(Mandatory = $true)][string]$Json)
    $resultPath = [IO.Path]::GetFullPath($BasicUserResultPath)
    $tempPath = "$resultPath.$PID.tmp"
    [IO.File]::WriteAllText($tempPath, "$BasicUserResultNonce`n$Json")
    [IO.File]::Move($tempPath, $resultPath)
}

trap {
    $detail = ($_ | Out-String).Trim()
    if (-not [string]::IsNullOrWhiteSpace($BasicUserResultPath)) {
        Write-BasicUserResult -Json (
            [pscustomobject]@{ ok = $false; error = $detail } |
                ConvertTo-Json -Compress
        )
    }
    [Console]::Error.WriteLine($detail)
    exit 1
}

function Write-SmokeWarning {
    param([Parameter(Mandatory = $true)][string]$Message)
    # Windows PowerShell 5.1 sends Write-Warning to stdout when stdout is
    # redirected, which breaks callers that parse the JSON report.
    [Console]::Error.WriteLine("WARNING: $Message")
}

function New-RandomHex {
    param([Parameter(Mandatory = $true)][int]$ByteCount)
    $bytes = New-Object byte[] $ByteCount
    $generator = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $generator.GetBytes($bytes) } finally { $generator.Dispose() }
    return (($bytes | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Read-BasicUserResult {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Nonce
    )
    # The worker writes this run's nonce on the first line. A result without
    # it was not written by this run's worker.
    $parts = [IO.File]::ReadAllText($Path).Split([char[]]"`n", 2)
    if ($parts.Count -ne 2 -or $parts[0] -cne $Nonce) {
        throw "Basic User bootstrap result $Path was not written by this run's worker"
    }
    return $parts[1]
}

$smokeUserNamePattern = '^dcsmoke[0-9a-f]{8}$'

function Test-NotMappedIdentity {
    param([Parameter(Mandatory = $true)]$ErrorRecord)
    return (
        $ErrorRecord.Exception.GetBaseException() -is
        [Security.Principal.IdentityNotMappedException]
    )
}

function Test-LocalAccountExists {
    param([Parameter(Mandatory = $true)][string]$Name)
    try {
        $null = (
            [Security.Principal.NTAccount]"$env:COMPUTERNAME\$Name"
        ).Translate([Security.Principal.SecurityIdentifier])
        return $true
    }
    catch {
        if (Test-NotMappedIdentity -ErrorRecord $_) { return $false }
        throw
    }
}

function Test-SidResolves {
    param([Parameter(Mandatory = $true)][string]$Sid)
    try {
        $null = (
            [Security.Principal.SecurityIdentifier]$Sid
        ).Translate([Security.Principal.NTAccount])
        return $true
    }
    catch {
        if (Test-NotMappedIdentity -ErrorRecord $_) { return $false }
        throw
    }
}

function Remove-OrphanedSmokeProfiles {
    # The task's batch logon session can keep a throwaway user's profile hive
    # loaded long after the task and the user are gone, so a run can leave its
    # profile behind. Remove earlier runs' leftovers: only a profile whose
    # folder is exactly dcsmoke + 8 hex, whose SID no longer maps to an account
    # (its run deleted the user) and that is not loaded. A concurrent run's
    # profile still has its account, so it is never touched.
    foreach ($userProfile in @(Get-CimInstance -ClassName Win32_UserProfile)) {
        $localPath = [string]$userProfile.LocalPath
        if ([string]::IsNullOrEmpty($localPath) -or
            [IO.Path]::GetFileName($localPath) -cnotmatch $smokeUserNamePattern -or
            [bool]$userProfile.Special -or [bool]$userProfile.Loaded) {
            continue
        }
        try {
            if (Test-SidResolves -Sid ([string]$userProfile.SID)) { continue }
            $userProfile | Remove-CimInstance -ErrorAction Stop
            [Console]::Error.WriteLine(
                'enterprise-bootstrap-smoke: removed orphaned throwaway profile ' +
                "$localPath (SID $($userProfile.SID))"
            )
        }
        catch {
            Write-SmokeWarning (
                "could not remove orphaned throwaway profile ${localPath}: " +
                $_.Exception.Message
            )
        }
    }
}

function New-SmokeStandardUser {
    param([Parameter(Mandatory = $true)]$User)
    $name = 'dcsmoke' + (New-RandomHex -ByteCount 4)
    if (Test-LocalAccountExists -Name $name) {
        throw "throwaway user name $name is already taken"
    }
    # The password lives only in a SecureString built from random bytes, and
    # reaches Windows only through method calls (ADSI and the Task Scheduler
    # COM API). It is never a literal, a cmdlet parameter (module logging
    # records those) or written anywhere.
    $bytes = New-Object byte[] 24
    $generator = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $generator.GetBytes($bytes) } finally { $generator.Dispose() }
    $password = New-Object Security.SecureString
    foreach ($byte in $bytes) {
        $password.AppendChar('0123456789abcdef'[$byte -shr 4])
        $password.AppendChar('0123456789abcdef'[$byte -band 15])
    }
    [Array]::Clear($bytes, 0, $bytes.Length)
    foreach ($character in 'aA1!'.ToCharArray()) { $password.AppendChar($character) }
    $password.MakeReadOnly()
    $User.Password = $password
    $computer = [ADSI]"WinNT://$env:COMPUTERNAME,computer"
    $account = $computer.Create('user', $name)
    $passwordPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($password)
    try {
        $null = $account.SetPassword(
            [Runtime.InteropServices.Marshal]::PtrToStringBSTR($passwordPointer)
        )
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($passwordPointer)
    }
    $null = $account.Put(
        'Description', 'DefenseClaw bootstrap smoke throwaway standard user'
    )
    # Record the name before the account exists, so the caller's cleanup also
    # runs when an error or Ctrl-C lands right after SetInfo. The name was free
    # a moment ago, so cleanup never deletes someone else's account.
    $User.Name = $name
    $null = $account.SetInfo()
    $User.Sid = (
        [Security.Principal.NTAccount]"$env:COMPUTERNAME\$name"
    ).Translate([Security.Principal.SecurityIdentifier]).Value
    # Users is the standard-user group. Performance Log Users carries the
    # "log on as a batch job" right a scheduled task needs and grants no
    # administrative access.
    foreach ($groupSid in 'S-1-5-32-545', 'S-1-5-32-559') {
        $groupName = (
            [Security.Principal.SecurityIdentifier]$groupSid
        ).Translate([Security.Principal.NTAccount]).Value.Split('\')[-1]
        $group = [ADSI]"WinNT://$env:COMPUTERNAME/$groupName,group"
        $null = $group.Add("WinNT://$env:COMPUTERNAME/$name")
    }
}

function Remove-SmokeStandardUserAccount {
    param([Parameter(Mandatory = $true)]$User)
    try {
        $computer = [ADSI]"WinNT://$env:COMPUTERNAME,computer"
        $null = $computer.Delete('user', $User.Name)
    }
    catch {
        # An account that never got created, or is already gone, is removed.
        if (Test-LocalAccountExists -Name $User.Name) { throw }
    }
}

function Remove-SmokeStandardUserProfile {
    param([Parameter(Mandatory = $true)]$User)
    # Removing the Win32_UserProfile instance deletes the profile folder and
    # hive. Give Windows a few seconds to unload the hive. A hive that stays
    # loaded is removed by the orphan sweep of a later run.
    for ($attempt = 1; ; $attempt++) {
        $userProfile = Get-CimInstance -ClassName Win32_UserProfile `
            -Filter "SID='$($User.Sid)'"
        if ($null -eq $userProfile) { return }
        try {
            $userProfile | Remove-CimInstance -ErrorAction Stop
            return
        }
        catch {
            if ($attempt -ge 5) { throw }
            Start-Sleep -Seconds 2
        }
    }
}

function New-ProtectedSmokeRelay {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$UserSid
    )
    # A new ProgramData folder inherits a rule that lets any local user create
    # files in it, so another user could plant a passing result.json. Create
    # the folder with inheritance broken and only SYSTEM, Administrators and
    # the throwaway user on it, then check that Windows applied exactly that.
    $allowed = @{
        'S-1-5-18' = 'FullControl'
        'S-1-5-32-544' = 'FullControl'
        $UserSid = 'Modify'
    }
    $security = [Security.AccessControl.DirectorySecurity]::new()
    $security.SetAccessRuleProtection($true, $false)
    foreach ($sid in $allowed.Keys) {
        $security.AddAccessRule(
            [Security.AccessControl.FileSystemAccessRule]::new(
                [Security.Principal.SecurityIdentifier]$sid,
                [Security.AccessControl.FileSystemRights]$allowed[$sid],
                'ContainerInherit,ObjectInherit',
                'None',
                'Allow'
            )
        )
    }
    if ([IO.Directory]::Exists($Path)) {
        throw "staging folder $Path already exists"
    }
    # .NET Framework (Windows PowerShell 5.1) creates a directory with an ACL
    # through Directory.CreateDirectory; .NET (PowerShell 7) moved that to
    # FileSystemAclExtensions.CreateDirectory.
    $aclExtensions = 'System.IO.FileSystemAclExtensions' -as [type]
    if ($null -ne $aclExtensions -and $null -ne $aclExtensions.GetMethod(
            'CreateDirectory',
            [type[]]@([Security.AccessControl.DirectorySecurity], [string])
        )) {
        [void]$aclExtensions::CreateDirectory($security, $Path)
    }
    else {
        [void][IO.Directory]::CreateDirectory($Path, $security)
    }
    $applied = Get-Acl -LiteralPath $Path
    $rules = @(
        $applied.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])
    )
    $unexpected = @(
        $rules | Where-Object {
            $_.IsInherited -or -not $allowed.ContainsKey($_.IdentityReference.Value)
        }
    )
    if (-not $applied.AreAccessRulesProtected -or $rules.Count -eq 0 -or
        $unexpected.Count -gt 0) {
        throw "staging folder $Path did not get its protected access list"
    }
}

function Start-StandardUserTask {
    param(
        [Parameter(Mandatory = $true)][string]$TaskName,
        [Parameter(Mandatory = $true)][string]$Engine,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [Parameter(Mandatory = $true)]$User
    )
    $argumentText = (
        $Arguments | ForEach-Object {
            [DefenseClaw.SetupStandardUserLauncher]::QuoteWindowsArgument([string]$_)
        }
    ) -join ' '
    # Register through the Task Scheduler COM API rather than
    # Register-ScheduledTask -Password: module logging records cmdlet
    # parameters, and the password must not reach an event log. An S4U task
    # needs no password, but Windows refuses to register one from elevated SSH.
    $service = New-Object -ComObject Schedule.Service
    $service.Connect()
    $definition = $service.NewTask(0)
    $definition.Settings.DisallowStartIfOnBatteries = $false
    $definition.Settings.StopIfGoingOnBatteries = $false
    $definition.Settings.ExecutionTimeLimit = 'PT10M'
    $definition.Principal.LogonType = 1 # TASK_LOGON_PASSWORD
    $definition.Principal.RunLevel = 0 # TASK_RUNLEVEL_LUA
    $action = $definition.Actions.Create(0) # TASK_ACTION_EXEC
    $action.Path = $Engine
    $action.Arguments = $argumentText
    $action.WorkingDirectory = $WorkingDirectory
    $passwordPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR(
        $User.Password
    )
    try {
        $registered = $service.GetFolder('\').RegisterTaskDefinition(
            $TaskName,
            $definition,
            2, # TASK_CREATE
            "$env:COMPUTERNAME\$($User.Name)",
            [Runtime.InteropServices.Marshal]::PtrToStringBSTR($passwordPointer),
            1 # TASK_LOGON_PASSWORD
        )
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($passwordPointer)
    }
    $null = $registered.Run($null)
}

function Wait-StandardUserTask {
    param(
        [Parameter(Mandatory = $true)][string]$TaskName,
        [Parameter(Mandatory = $true)][string]$ResultPath,
        [Parameter(Mandatory = $true)][DateTime]$Deadline
    )
    # Stop at the result, at the worker's exit, or when the task has not
    # started within a minute, instead of always waiting for the deadline.
    # 267009 is SCHED_S_TASK_RUNNING and 267011 SCHED_S_TASK_HAS_NOT_RUN.
    $startDeadline = [DateTime]::UtcNow.AddMinutes(1)
    $seenRunning = $false
    while (-not [IO.File]::Exists($ResultPath)) {
        if ([DateTime]::UtcNow -ge $Deadline) { return 'timed out' }
        if ([string](Get-ScheduledTask -TaskName $TaskName).State -eq 'Running') {
            $seenRunning = $true
        }
        else {
            $lastResult = [int64](Get-ScheduledTaskInfo -TaskName $TaskName).LastTaskResult
            if ($seenRunning -or ($lastResult -ne 267009 -and $lastResult -ne 267011)) {
                return 'worker exited'
            }
            if ([DateTime]::UtcNow -ge $startDeadline) { return 'task never started' }
        }
        Start-Sleep -Milliseconds 250
    }
    return 'result written'
}

function Remove-StandardUserTask {
    param([Parameter(Mandatory = $true)][string]$TaskName)
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($null -eq $task) { return }
    if ($task.State -eq 'Running') {
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    }
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}

function Invoke-ThrowawayUserWorker {
    param(
        [Parameter(Mandatory = $true)][string]$RelayRoot,
        [Parameter(Mandatory = $true)][string]$Nonce,
        [Parameter(Mandatory = $true)][string]$StrictFailure,
        [Parameter(Mandatory = $true)][DateTime]$Deadline
    )
    try { Remove-OrphanedSmokeProfiles }
    catch {
        Write-SmokeWarning (
            "could not sweep earlier throwaway profiles: $($_.Exception.Message)"
        )
    }
    $smokeUser = [pscustomobject]@{ Name = $null; Sid = $null; Password = $null }
    $sharedRelay = $null
    $taskName = $null
    try {
        New-SmokeStandardUser -User $smokeUser
        $sharedRelay = Join-Path (
            [Environment]::GetFolderPath(
                [Environment+SpecialFolder]::CommonApplicationData
            )
        ) "DefenseClaw-BootstrapRelay-$(New-RandomHex -ByteCount 16)"
        New-ProtectedSmokeRelay -Path $sharedRelay -UserSid $smokeUser.Sid
        Copy-Item -Path (Join-Path $RelayRoot '*') -Destination $sharedRelay -Recurse
        $sharedTests = Join-Path $sharedRelay 'packaging\windows\tests'
        $sharedScript = Join-Path $sharedTests 'enterprise-bootstrap-smoke.ps1'
        $sharedResult = Join-Path $sharedRelay 'result.json'
        $sharedCommand = (
            "& '" + $sharedScript.Replace("'", "''") +
            "' -BasicUserResultPath '" + $sharedResult.Replace("'", "''") +
            "' -BasicUserResultNonce '$Nonce'"
        )
        $taskArguments = [string[]]@(
            '-NoLogo', '-NoProfile', '-NonInteractive',
            '-ExecutionPolicy', 'Bypass', '-EncodedCommand',
            [Convert]::ToBase64String(
                [Text.Encoding]::Unicode.GetBytes($sharedCommand)
            )
        )
        $taskName = "DefenseClawBootstrapSmoke-$(New-RandomHex -ByteCount 16)"
        Start-StandardUserTask -TaskName $taskName -Engine $engine `
            -Arguments $taskArguments -WorkingDirectory $sharedTests `
            -User $smokeUser
        $waitOutcome = Wait-StandardUserTask -TaskName $taskName `
            -ResultPath $sharedResult -Deadline $Deadline
        $taskDeadline = [DateTime]::UtcNow.AddSeconds(30)
        while ((Get-ScheduledTask -TaskName $taskName).State -eq 'Running' -and
            [DateTime]::UtcNow -lt $taskDeadline) {
            Start-Sleep -Milliseconds 250
        }
        if (-not [IO.File]::Exists($sharedResult)) {
            $taskInfo = Get-ScheduledTaskInfo -TaskName $taskName
            throw (
                'Basic User bootstrap smoke could not get a medium-integrity ' +
                'non-admin token (' + $StrictFailure + ') and the throwaway ' +
                "standard-user scheduled task produced no result ($waitOutcome, " +
                "last task result $($taskInfo.LastTaskResult)). Run the smoke as a " +
                'standard (non-admin) user, or from an elevated session that ' +
                'may create a local user and a scheduled task, or from a ' +
                'UAC-linked elevated session where the launcher can duplicate ' +
                'the linked limited token (CI).'
            )
        }
        $resultOwner = (Get-Acl -LiteralPath $sharedResult).GetOwner(
            [Security.Principal.SecurityIdentifier]
        ).Value
        if ($resultOwner -cne $smokeUser.Sid) {
            throw (
                "Basic User bootstrap result $sharedResult is owned by " +
                "$resultOwner, not by the throwaway user $($smokeUser.Sid), so " +
                "this run's worker did not write it"
            )
        }
        return (Read-BasicUserResult -Path $sharedResult -Nonce $Nonce)
    }
    finally {
        # Each step runs on its own, so one failure cannot skip the others.
        if ($null -ne $taskName) {
            try { Remove-StandardUserTask -TaskName $taskName }
            catch {
                Write-SmokeWarning (
                    "could not remove scheduled task ${taskName}: " +
                    "$($_.Exception.Message); remove it with: " +
                    "Unregister-ScheduledTask -TaskName '$taskName' -Confirm:`$false"
                )
            }
        }
        if ($null -ne $smokeUser.Name) {
            try { Remove-SmokeStandardUserAccount -User $smokeUser }
            catch {
                Write-SmokeWarning (
                    "could not delete throwaway user $($smokeUser.Name): " +
                    "$($_.Exception.Message); delete it with: " +
                    "net user $($smokeUser.Name) /delete"
                )
            }
        }
        if ($null -ne $sharedRelay) {
            try {
                if ([IO.Directory]::Exists($sharedRelay)) {
                    [IO.Directory]::Delete($sharedRelay, $true)
                }
            }
            catch {
                Write-SmokeWarning (
                    "could not remove staging folder ${sharedRelay}: " +
                    "$($_.Exception.Message); remove it with: " +
                    "Remove-Item -LiteralPath '$sharedRelay' -Recurse -Force"
                )
            }
        }
        if ($null -ne $smokeUser.Sid) {
            try { Remove-SmokeStandardUserProfile -User $smokeUser }
            catch {
                Write-SmokeWarning (
                    "Windows still holds the throwaway user's profile (SID " +
                    "$($smokeUser.Sid)), so it was not removed. The next run of " +
                    'this smoke removes it once Windows unloads it, or remove it ' +
                    'then with: Get-CimInstance Win32_UserProfile -Filter ' +
                    """SID='$($smokeUser.Sid)'"" | Remove-CimInstance (" +
                    $_.Exception.Message.Trim() + ')'
                )
            }
        }
    }
}

function Get-Win32ErrorCode {
    param([Parameter(Mandatory = $true)][Exception]$Exception)
    for ($inner = $Exception; $null -ne $inner; $inner = $inner.InnerException) {
        if ($inner -is [ComponentModel.Win32Exception]) { return $inner.NativeErrorCode }
    }
    return $null
}

function Get-StandardUserFallbackReason {
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        $ErrorCode
    )
    # Two elevated shapes cannot hand a primary limited token to the worker:
    # no UAC split at all (elevated SSH as the built-in Administrator, UAC
    # off), and a UAC-consent session whose linked token is
    # identification-level only, so DuplicateTokenEx fails with 1346
    # (ERROR_BAD_IMPERSONATION_LEVEL) without SeTcbPrivilege (GAP-0661). A
    # restricted LUA token is no substitute: it cannot initialise from SSH or
    # a batch session, and a SYSTEM-derived one makes the untrusted fixtures
    # look trusted. A real standard user is what the launcher asks for, so
    # these two run the worker as a throwaway one. Any other launcher error,
    # including another DuplicateTokenEx code, returns $null and fails.
    if ($Message -match 'restricted LUA default-token fallback is disabled') {
        return 'no UAC-linked token'
    }
    if ($Message -match 'DuplicateTokenEx failed for linked limited Setup' -and
        $ErrorCode -eq 1346) {
        return 'linked token is identification-level, DuplicateTokenEx error 1346'
    }
    return $null
}

function Invoke-BasicUserBootstrapSmoke {
    $relayRoot = Join-Path (
        [IO.Path]::GetTempPath()
    ) "DefenseClaw-BootstrapRelay-$([Guid]::NewGuid().ToString('N'))"
    [void][IO.Directory]::CreateDirectory($relayRoot)
    $process = $null
    try {
        # Hosted runners may grant the elevated token workspace access only
        # through its Administrators SID. The filtered LUA child must not rely
        # on that SID, so stage the exact three-file bootstrap surface beneath
        # its user-accessible relay while preserving the production layout.
        $stagedWindowsRoot = Join-Path $relayRoot 'packaging\windows'
        $stagedTestsRoot = Join-Path $stagedWindowsRoot 'tests'
        [void][IO.Directory]::CreateDirectory($stagedTestsRoot)
        $stagedScriptPath = Join-Path $stagedTestsRoot 'enterprise-bootstrap-smoke.ps1'
        [IO.File]::WriteAllBytes(
            $stagedScriptPath,
            [IO.File]::ReadAllBytes($PSCommandPath)
        )
        [IO.File]::WriteAllBytes(
            (Join-Path $stagedWindowsRoot 'install-enterprise.ps1'),
            [IO.File]::ReadAllBytes($installerSource)
        )
        [IO.File]::WriteAllBytes(
            (Join-Path $stagedWindowsRoot 'DefenseClawEnterprise.psm1'),
            [IO.File]::ReadAllBytes($moduleSource)
        )
        $resultPath = Join-Path $relayRoot 'result.json'
        $resultNonce = New-RandomHex -ByteCount 16
        $scriptLiteral = $stagedScriptPath.Replace("'", "''")
        $resultLiteral = $resultPath.Replace("'", "''")
        $workerCommand = (
            "& '$scriptLiteral' -BasicUserResultPath '$resultLiteral' " +
            "-BasicUserResultNonce '$resultNonce'"
        )
        $encodedCommand = [Convert]::ToBase64String(
            [Text.Encoding]::Unicode.GetBytes($workerCommand)
        )
        $repoRoot = [IO.Path]::GetFullPath(
            (Join-Path $PSScriptRoot '..\..\..')
        )
        $launcherSource = Join-Path `
            $repoRoot 'scripts\windows-setup-standard-user-launcher.cs'
        if (-not ('DefenseClaw.SetupStandardUserLauncher' -as [type])) {
            Add-Type -Path $launcherSource -ErrorAction Stop
        }
        $environment = @(
            [Environment]::GetEnvironmentVariables('Process').GetEnumerator() |
                ForEach-Object {
                    '{0}={1}' -f [string]$_.Key, [string]$_.Value
                }
        )
        $arguments = [string[]]@(
            '-NoLogo', '-NoProfile', '-NonInteractive',
            '-ExecutionPolicy', 'Bypass', '-EncodedCommand', $encodedCommand
        )
        $workerDirectory = [IO.Path]::GetFullPath($stagedTestsRoot)
        $launchContext = 'uac-linked-limited-token'
        $standardUserRun = $false
        $strictFailure = $null
        try {
            $process = [DefenseClaw.SetupStandardUserLauncher]::StartRestrictedWithCapture(
                $engine, $arguments, $workerDirectory, [string[]]$environment, $false
            )
        }
        catch {
            $strictFailure = $_.Exception.Message
            if ($null -ne $_.Exception.InnerException) {
                $strictFailure += ' ' + $_.Exception.InnerException.Message
            }
            $strictErrorCode = Get-Win32ErrorCode -Exception $_.Exception
            $fallbackReason = Get-StandardUserFallbackReason `
                -Message $strictFailure -ErrorCode $strictErrorCode
            if ($null -eq $fallbackReason) {
                if ($null -ne $strictErrorCode) {
                    [Console]::Error.WriteLine(
                        'enterprise-bootstrap-smoke: strict launch failed with ' +
                        "Win32 error $strictErrorCode"
                    )
                }
                throw
            }
            $standardUserRun = $true
            $launchContext = "throwaway-local-standard-user ($fallbackReason)"
        }
        $deadline = [DateTime]::UtcNow.AddMinutes(5)
        if ($standardUserRun) {
            $reportJson = Invoke-ThrowawayUserWorker -RelayRoot $relayRoot `
                -Nonce $resultNonce -StrictFailure $strictFailure -Deadline $deadline
            $outputHealthy = $true
            $launchOutput = ''
        }
        else {
            while (-not [IO.File]::Exists($resultPath) -and
                -not $process.HasExited -and
                [DateTime]::UtcNow -lt $deadline) {
                Start-Sleep -Milliseconds 100
            }
            $timedOut = -not [IO.File]::Exists($resultPath) -and
                -not $process.HasExited
            if ($timedOut) {
                $process.Kill($true)
            }
            if (-not $process.WaitForExit(30000)) {
                throw 'Basic User bootstrap smoke child did not exit after completion'
            }
            $outputHealthy = $process.CompleteOutput(5000)
            $launchOutput = @(
                [string]$process.StdOut,
                [string]$process.StdErr,
                [string]$process.OutputCaptureError
            ) -join [Environment]::NewLine
            if (-not [IO.File]::Exists($resultPath)) {
                throw (
                    $(if ($timedOut) {
                        'Basic User bootstrap smoke timed out; '
                    } else {
                        "Basic User bootstrap smoke exited $($process.ExitCode); "
                    }) +
                    "launch output=$($launchOutput.Trim())"
                )
            }
            $reportJson = Read-BasicUserResult -Path $resultPath -Nonce $resultNonce
        }
        [Console]::Error.WriteLine(
            "enterprise-bootstrap-smoke: Basic User worker token = $launchContext"
        )
        $report = $reportJson | ConvertFrom-Json
        if (-not [bool]$report.ok) {
            throw (
                "Basic User bootstrap smoke failed: $($report.error); " +
                "output capture healthy=$outputHealthy; " +
                "launch output=$($launchOutput.Trim())"
            )
        }
        if (-not $outputHealthy) {
            Write-SmokeWarning (
                'Basic User bootstrap output capture failed despite a ' +
                "successful result: $launchOutput"
            )
        }
        Write-Output $reportJson
    }
    finally {
        if ($null -ne $process) {
            try {
                if (-not $process.HasExited) {
                    $process.Kill($true)
                    if (-not $process.WaitForExit(30000)) {
                        throw (
                            'Basic User bootstrap smoke process tree did not ' +
                            'exit during cleanup'
                        )
                    }
                }
            }
            finally {
                $process.Dispose()
            }
        }
        if ([IO.Directory]::Exists($relayRoot)) {
            [IO.Directory]::Delete($relayRoot, $true)
        }
    }
}

$effectiveMediumNonAdmin = Test-EffectiveMediumNonAdminUser
if (-not $effectiveMediumNonAdmin) {
    if (-not [string]::IsNullOrWhiteSpace($BasicUserResultPath)) {
        throw (
            'raw DOS-device bootstrap regression requires the executable ' +
            'test process to be an effective medium-integrity non-admin user'
        )
    }
    Invoke-BasicUserBootstrapSmoke
    exit 0
}
$testRoot = Join-Path (
    [IO.Path]::GetTempPath()
) "DefenseClaw-BootstrapSmoke-$([Guid]::NewGuid().ToString('N'))"
$scopeToken = ([Guid]::NewGuid().ToString('N')).Substring(0, 10)
$scopeGatewayService = "DefenseClawCertGateway_$scopeToken"
$scopeGuardianService = "DefenseClawCertGuardian_$scopeToken"
$scopeInstallRoot = [IO.Path]::Combine(
    [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles),
    'Cisco',
    'Cisco Secure Client',
    'DefenseClaw-Cert',
    $scopeToken
)
$scopeStateRoot = [IO.Path]::Combine(
    [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData),
    'Cisco',
    'Cisco Secure Client',
    'DefenseClaw-Cert',
    $scopeToken
)
$productionInstallRoot = [IO.Path]::Combine(
    [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles),
    'Cisco',
    'Cisco Secure Client',
    'DefenseClaw'
)
$productionStateRoot = [IO.Path]::Combine(
    [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData),
    'Cisco',
    'Cisco Secure Client',
    'DefenseClaw'
)
$scopeCertificationCodexHome = Join-Path (
    [IO.Path]::GetTempPath()
) ".codex-defenseclaw-cert-$scopeToken"
$markerPath = Join-Path $testRoot 'module-executed.marker'
$maliciousModule = @'
$marker = [Environment]::GetEnvironmentVariable('DEFENSECLAW_BOOTSTRAP_TEST_MARKER', 'Process')
if (-not [string]::IsNullOrWhiteSpace($marker)) {
    [IO.File]::WriteAllText($marker, 'module executed')
}
function Invoke-DefenseClawEnterpriseLifecycle {
    [pscustomobject]@{ ok = $true }
}
Export-ModuleMember -Function Invoke-DefenseClawEnterpriseLifecycle
'@

function Initialize-RawDosDeviceInterop {
    if ($null -ne (
        'DefenseClaw.Windows.Tests.RawDosDeviceNative' -as [type]
    )) {
        return
    }
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

namespace DefenseClaw.Windows.Tests
{
    public static class RawDosDeviceNative
    {
        private const uint DDD_RAW_TARGET_PATH = 0x00000001;
        private const uint DDD_REMOVE_DEFINITION = 0x00000002;
        private const uint DDD_EXACT_MATCH_ON_REMOVE = 0x00000004;
        private const uint DDD_NO_BROADCAST_SYSTEM = 0x00000008;
        private const int ERROR_FILE_NOT_FOUND = 2;

        [DllImport(
            "kernel32.dll",
            CharSet = CharSet.Unicode,
            SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DefineDosDeviceW(
            uint flags,
            string deviceName,
            string targetPath);

        [DllImport(
            "kernel32.dll",
            CharSet = CharSet.Unicode,
            SetLastError = true)]
        private static extern uint QueryDosDeviceW(
            string deviceName,
            StringBuilder targetPath,
            int maximumLength);

        public static string TryQuery(string deviceName)
        {
            StringBuilder target = new StringBuilder(32768);
            uint length = QueryDosDeviceW(
                deviceName,
                target,
                target.Capacity);
            if (length != 0)
                return target.ToString();
            int error = Marshal.GetLastWin32Error();
            if (error == ERROR_FILE_NOT_FOUND)
                return null;
            throw new Win32Exception(
                error,
                "QueryDosDeviceW failed for " + deviceName);
        }

        public static void DefineRaw(string deviceName, string targetPath)
        {
            if (!DefineDosDeviceW(
                DDD_RAW_TARGET_PATH | DDD_NO_BROADCAST_SYSTEM,
                deviceName,
                targetPath))
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "DefineDosDeviceW raw alias creation failed");
        }

        public static void RemoveRaw(string deviceName, string targetPath)
        {
            if (!DefineDosDeviceW(
                DDD_RAW_TARGET_PATH |
                    DDD_REMOVE_DEFINITION |
                    DDD_EXACT_MATCH_ON_REMOVE |
                    DDD_NO_BROADCAST_SYSTEM,
                deviceName,
                targetPath))
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "DefineDosDeviceW raw alias removal failed");
        }

        public static void RemoveAny(string deviceName)
        {
            if (!DefineDosDeviceW(
                DDD_REMOVE_DEFINITION | DDD_NO_BROADCAST_SYSTEM,
                deviceName,
                null))
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "DefineDosDeviceW alias fallback removal failed");
        }
    }
}
'@ -Language CSharp -ErrorAction Stop
}

function Remove-RawDosDeviceFixtureAlias(
    [string]$Drive,
    [string]$Target
) {
    try {
        [DefenseClaw.Windows.Tests.RawDosDeviceNative]::RemoveRaw(
            $Drive,
            $Target
        )
    }
    catch {
        [DefenseClaw.Windows.Tests.RawDosDeviceNative]::RemoveAny($Drive)
    }
    $surviving =
        [DefenseClaw.Windows.Tests.RawDosDeviceNative]::TryQuery($Drive)
    if (-not [string]::IsNullOrWhiteSpace($surviving)) {
        throw "raw DOS-device alias survived cleanup: $Drive -> $surviving"
    }
    return $true
}

function Get-RawAliasFixtureInventory([string]$Root) {
    $fullRoot = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    $rows = [Collections.Generic.List[object]]::new()
    foreach ($item in @(
        Get-ChildItem `
            -LiteralPath $fullRoot `
            -Recurse `
            -Force |
            Sort-Object FullName
    )) {
        $fullPath = [IO.Path]::GetFullPath(
            [string]$item.FullName
        ).TrimEnd('\')
        if (-not $fullPath.StartsWith(
                $fullRoot + '\',
                [StringComparison]::OrdinalIgnoreCase
            )) {
            throw "raw DOS-device fixture inventory escaped its root: $fullPath"
        }
        $rows.Add([pscustomobject]@{
            relative_path = $fullPath.Substring($fullRoot.Length + 1)
            kind = if ($item.PSIsContainer) { 'directory' } else { 'file' }
            attributes = [int]$item.Attributes
            length = if ($item.PSIsContainer) {
                [int64]0
            } else {
                [int64]$item.Length
            }
            sha256 = if ($item.PSIsContainer) {
                ''
            } else {
                $stream = [IO.File]::Open(
                    $fullPath,
                    [IO.FileMode]::Open,
                    [IO.FileAccess]::Read,
                    (
                        [IO.FileShare]::Read -bor
                        [IO.FileShare]::Write -bor
                        [IO.FileShare]::Delete
                    )
                )
                $algorithm = [Security.Cryptography.SHA256]::Create()
                try {
                    [BitConverter]::ToString(
                        $algorithm.ComputeHash($stream)
                    ).Replace('-', '').ToLowerInvariant()
                }
                finally {
                    $algorithm.Dispose()
                    $stream.Dispose()
                }
            }
        })
    }
    return @($rows.ToArray())
}

function Get-ProductionBootstrapNativePathType {
    $tokens = $null
    $parseErrors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile(
        $installerSource,
        [ref]$tokens,
        [ref]$parseErrors
    )
    if (@($parseErrors).Count -ne 0) {
        throw 'could not parse the production enterprise bootstrap probe'
    }
    $definitions = @(
        $ast.FindAll(
            {
                param($node)
                return (
                    $node -is
                        [Management.Automation.Language.FunctionDefinitionAst] -and
                    [string]$node.Name -ceq
                        'Initialize-DefenseClawBootstrapNativePath'
                )
            },
            $true
        )
    )
    if ($definitions.Count -ne 1) {
        throw (
            'expected exactly one production bootstrap native-path ' +
            "initializer, found $($definitions.Count)"
        )
    }
    $script:DefenseClawBootstrapPathProbe = $null
    . ([scriptblock]::Create([string]$definitions[0].Extent.Text))
    $nativeType = Initialize-DefenseClawBootstrapNativePath
    if ($nativeType -isnot [type]) {
        throw 'production bootstrap native-path initializer did not return a CLR type'
    }
    return $nativeType
}

function Invoke-ProductionModuleLogicalDiskAliasProbe(
    [string]$NormalDrive,
    [string[]]$AliasDrives
) {
    $tokens = $null
    $parseErrors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile(
        $moduleSource,
        [ref]$tokens,
        [ref]$parseErrors
    )
    if (@($parseErrors).Count -ne 0) {
        throw 'could not parse the production enterprise module drive probe'
    }
    $requiredNames = @(
        'Initialize-DefenseClawNativeSecurity',
        'Get-DefenseClawLogicalDisk'
    )
    $definitions = @(
        $ast.FindAll(
            {
                param($node)
                return (
                    $node -is
                        [Management.Automation.Language.FunctionDefinitionAst] -and
                    [string]$node.Name -in $requiredNames
                )
            },
            $true
        )
    )
    if ($definitions.Count -ne $requiredNames.Count) {
        throw (
            'could not isolate both exact production module drive-probe ' +
            "functions; found $($definitions.Count)"
        )
    }
    $script:WindowsDirectory =
        [Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)
    $script:System32 = [IO.Path]::Combine(
        $script:WindowsDirectory,
        'System32'
    )
    $script:DefenseClawNativeSecurityType = $null
    foreach ($name in $requiredNames) {
        $definition = @(
            $definitions | Where-Object {
                [string]$_.Name -ceq $name
            }
        )
        if ($definition.Count -ne 1) {
            throw "production module drive probe has an ambiguous $name definition"
        }
        . ([scriptblock]::Create([string]$definition[0].Extent.Text))
    }
    $normal = Get-DefenseClawLogicalDisk -DriveID $NormalDrive
    if ([int]$normal.DriveType -ne 3 -or
        -not [string]::Equals(
            [string]$normal.FileSystem,
            'NTFS',
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        [string]::IsNullOrWhiteSpace([string]$normal.Target)) {
        throw 'production module drive probe rejected the canonical system drive'
    }
    $rejected = [Collections.Generic.List[string]]::new()
    foreach ($aliasDrive in $AliasDrives) {
        try {
            $null = Get-DefenseClawLogicalDisk -DriveID $aliasDrive
            throw "production module drive probe accepted raw alias $aliasDrive"
        }
        catch {
            if ($_.Exception.Message -notmatch (
                    'GetVolumeNameForVolumeMountPoint|' +
                    'QueryDosDevice failed for Global|authoritative volume|' +
                    'Mount Manager|canonical DOS drive root'
                )) {
                throw
            }
            $rejected.Add($aliasDrive)
        }
    }
    return [pscustomobject]@{
        canonical_system_drive_accepted = $true
        rejected_aliases = @($rejected.ToArray())
    }
}

function Invoke-RejectedBootstrap {
    param(
        [Parameter(Mandatory)][string]$InstallerPath,
        [Parameter(Mandatory)][string]$ExpectedError,
        [string[]]$InstallerArguments,
        [switch]$PreloadFixedHelperSpoof
    )
    if ($null -eq $InstallerArguments -or $InstallerArguments.Count -eq 0) {
        $InstallerArguments = @(
            '-Action', 'Install',
            '-GatewayServiceName', $scopeGatewayService,
            '-GuardianServiceName', $scopeGuardianService,
            '-InstallRoot', $scopeInstallRoot,
            '-StateRoot', $scopeStateRoot,
            '-CertificationCodexHome', $scopeCertificationCodexHome,
            '-AllowUnsigned',
            '-Json'
        )
    }
    if (Test-Path -LiteralPath $markerPath) {
        Remove-Item -LiteralPath $markerPath -Force
    }
    [Environment]::SetEnvironmentVariable(
        'DEFENSECLAW_BOOTSTRAP_TEST_MARKER',
        $markerPath,
        'Process'
    )
    $previousErrorAction = $ErrorActionPreference
    try {
        # Windows PowerShell 5.1 wraps native stderr as NativeCommandError when
        # the caller uses Stop. The non-zero child exit is the assertion here,
        # so capture it without converting expected stderr into a test abort.
        $ErrorActionPreference = 'Continue'
        if ($PreloadFixedHelperSpoof) {
            $quotedInstallerPath = $InstallerPath.Replace("'", "''")
            $quotedGatewayService = $scopeGatewayService.Replace("'", "''")
            $quotedGuardianService = $scopeGuardianService.Replace("'", "''")
            $quotedInstallRoot = $scopeInstallRoot.Replace("'", "''")
            $quotedStateRoot = $scopeStateRoot.Replace("'", "''")
            $quotedCertificationHome = $scopeCertificationCodexHome.Replace("'", "''")
            $preloadPath = Join-Path $testRoot 'preloaded-helper-spoof.ps1'
            Set-Content -LiteralPath $preloadPath -Encoding UTF8 -Value @"
`$ErrorActionPreference = 'Stop'
[void](Microsoft.PowerShell.Utility\Add-Type -TypeDefinition @'
using System;
namespace DefenseClaw.Windows
{
    public static class EnterpriseBootstrapPath
    {
        public static uint GetDriveType(string root)
        {
            throw new InvalidOperationException("fixed bootstrap helper spoof was used");
        }
        public static string GetFileSystem(string root)
        {
            throw new InvalidOperationException("fixed bootstrap helper spoof was used");
        }
        public static string QueryDriveTarget(string drive)
        {
            throw new InvalidOperationException("fixed bootstrap helper spoof was used");
        }
    }
}
'@ -Language CSharp -ErrorAction Stop)
& '$quotedInstallerPath' `
    -Action Install `
    -GatewayServiceName '$quotedGatewayService' `
    -GuardianServiceName '$quotedGuardianService' `
    -InstallRoot '$quotedInstallRoot' `
    -StateRoot '$quotedStateRoot' `
    -CertificationCodexHome '$quotedCertificationHome' `
    -AllowUnsigned `
    -Json
"@
            $output = & $engine `
                -NoLogo `
                -NoProfile `
                -NonInteractive `
                -ExecutionPolicy Bypass `
                -File $preloadPath 2>&1
        }
        else {
            $output = & $engine `
                -NoLogo `
                -NoProfile `
                -NonInteractive `
                -ExecutionPolicy Bypass `
                -File $InstallerPath `
                @InstallerArguments 2>&1
        }
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousErrorAction
        [Environment]::SetEnvironmentVariable(
            'DEFENSECLAW_BOOTSTRAP_TEST_MARKER',
            $null,
            'Process'
        )
    }
    if ($exitCode -eq 0) {
        throw (
            "untrusted bootstrap fixture unexpectedly succeeded: $InstallerPath; " +
            "output=$(($output | Out-String).Trim())"
        )
    }
    if (Test-Path -LiteralPath $markerPath) {
        throw "rejected bootstrap imported and executed its malicious adjacent module: $InstallerPath"
    }
    $detail = ($output | Out-String).Trim()
    if ($detail -notmatch $ExpectedError) {
        throw "bootstrap rejection did not report '$ExpectedError': $detail"
    }
}

$junctionExecuted = $false
$rawAliasDefined = $false
$rawAliasCleanupVerified = $false
$rawAliasDrive = ''
$rawAliasTarget = ''
$wholeVolumeAliasDefined = $false
$wholeVolumeAliasCleanupVerified = $false
$wholeVolumeAliasDrive = ''
$wholeVolumeAliasTarget = ''
$rawAliasCases = [Collections.Generic.List[object]]::new()
$canonicalSystemDriveAccepted = $false
$rawAliasNativeProbeRejected = $false
$wholeVolumeAliasNativeProbeRejected = $false
$moduleLogicalDiskProbe = $null
try {
    [void](New-Item -ItemType Directory -Path $testRoot)
    [void](New-Item -ItemType Directory -Path $scopeCertificationCodexHome)

    $untrustedRoot = Join-Path $testRoot 'untrusted'
    [void](New-Item -ItemType Directory -Path $untrustedRoot)
    Copy-Item `
        -LiteralPath $installerSource `
        -Destination (Join-Path $untrustedRoot 'install-enterprise.ps1')
    Set-Content `
        -LiteralPath (Join-Path $untrustedRoot 'DefenseClawEnterprise.psm1') `
        -Value $maliciousModule `
        -Encoding UTF8
    Invoke-RejectedBootstrap `
        -InstallerPath (Join-Path $untrustedRoot 'install-enterprise.ps1') `
        -ExpectedError 'untrusted owner|replacement access|write-like access'
    Invoke-RejectedBootstrap `
        -InstallerPath (Join-Path $untrustedRoot 'install-enterprise.ps1') `
        -ExpectedError 'untrusted owner|replacement access|write-like access' `
        -InstallerArguments @(
            '-Action', 'Status',
            '-GatewayServiceName', $scopeGatewayService,
            '-GuardianServiceName', $scopeGuardianService,
            '-InstallRoot', $scopeInstallRoot,
            '-StateRoot', $scopeStateRoot,
            '-CertificationCodexHome', $scopeCertificationCodexHome,
            '-AllowUnsigned',
            '-Json'
        )
    Invoke-RejectedBootstrap `
        -InstallerPath (Join-Path $untrustedRoot 'install-enterprise.ps1') `
        -ExpectedError 'untrusted owner|replacement access|write-like access' `
        -PreloadFixedHelperSpoof
    Invoke-RejectedBootstrap `
        -InstallerPath (Join-Path $untrustedRoot 'install-enterprise.ps1') `
        -ExpectedError 'untrusted owner|replacement access|write-like access' `
        -InstallerArguments @(
            '-Action', 'Install',
            '-GatewayServiceName', $scopeGatewayService,
            '-GuardianServiceName', $scopeGuardianService,
            '-InstallRoot', $scopeInstallRoot,
            '-StateRoot', $scopeStateRoot,
            '-CertificationCodexHome', $scopeCertificationCodexHome,
            '-AllowUnsigned',
            '-AttestAgentApplicationControl',
            '-AttestClaudeEffectivePolicy',
            '-Json'
        )
    Invoke-RejectedBootstrap `
        -InstallerPath (Join-Path $untrustedRoot 'install-enterprise.ps1') `
        -ExpectedError 'untrusted owner|replacement access|write-like access' `
        -InstallerArguments @(
            '-Action', 'Install',
            '-GatewayServiceName', $scopeGatewayService,
            '-GuardianServiceName', $scopeGuardianService,
            '-InstallRoot', $scopeInstallRoot,
            '-StateRoot', $scopeStateRoot,
            '-CertificationCodexHome', $scopeCertificationCodexHome,
            '-AllowUnsigned',
            '-CoreHardeningCertification',
            '-Json'
        )
    Invoke-RejectedBootstrap `
        -InstallerPath (Join-Path $untrustedRoot 'install-enterprise.ps1') `
        -ExpectedError 'CoreHardeningCertification requires -AllowUnsigned and -CertificationCodexHome' `
        -InstallerArguments @(
            '-Action', 'Install',
            '-CoreHardeningCertification',
            '-Json'
        )
    Invoke-RejectedBootstrap `
        -InstallerPath (Join-Path $untrustedRoot 'install-enterprise.ps1') `
        -ExpectedError 'CoreHardeningCertification cannot be combined with production' `
        -InstallerArguments @(
            '-Action', 'Install',
            '-GatewayServiceName', $scopeGatewayService,
            '-GuardianServiceName', $scopeGuardianService,
            '-InstallRoot', $scopeInstallRoot,
            '-StateRoot', $scopeStateRoot,
            '-CertificationCodexHome', $scopeCertificationCodexHome,
            '-AllowUnsigned',
            '-CoreHardeningCertification',
            '-AttestAgentApplicationControl',
            '-Json'
        )
    Invoke-RejectedBootstrap `
        -InstallerPath (Join-Path $untrustedRoot 'install-enterprise.ps1') `
        -ExpectedError 'CoreHardeningCertification is valid only with Install, Upgrade, Repair, or Recover' `
        -InstallerArguments @(
            '-Action', 'Status',
            '-CoreHardeningCertification',
            '-Json'
        )
    Invoke-RejectedBootstrap `
        -InstallerPath (Join-Path $untrustedRoot 'install-enterprise.ps1') `
        -ExpectedError 'requires exact production roots' `
        -InstallerArguments @(
            '-Action', 'Status',
            '-GatewayServiceName', 'DefenseClawGateway',
            '-GuardianServiceName', 'DefenseClawHookGuardian',
            '-InstallRoot', $scopeInstallRoot,
            '-StateRoot', $productionStateRoot,
            '-Json'
        )
    Invoke-RejectedBootstrap `
        -InstallerPath (Join-Path $untrustedRoot 'install-enterprise.ps1') `
        -ExpectedError 'requires exact production service names' `
        -InstallerArguments @(
            '-Action', 'Status',
            '-GatewayServiceName', "DefenseClawGatewaySmoke_$scopeToken",
            '-GuardianServiceName', "DefenseClawGuardianSmoke_$scopeToken",
            '-InstallRoot', $productionInstallRoot,
            '-StateRoot', $productionStateRoot,
            '-Json'
        )
    Invoke-RejectedBootstrap `
        -InstallerPath (Join-Path $untrustedRoot 'install-enterprise.ps1') `
        -ExpectedError 'certification-scoped Install, Upgrade, or Repair requires -AllowUnsigned' `
        -InstallerArguments @(
            '-Action', 'Install',
            '-GatewayServiceName', $scopeGatewayService,
            '-GuardianServiceName', $scopeGuardianService,
            '-InstallRoot', $scopeInstallRoot,
            '-StateRoot', $scopeStateRoot,
            '-CertificationCodexHome', $scopeCertificationCodexHome,
            '-Json'
        )
    Invoke-RejectedBootstrap `
        -InstallerPath (Join-Path $untrustedRoot 'install-enterprise.ps1') `
        -ExpectedError '-AllowUnsigned is restricted to exact disposable' `
        -InstallerArguments @(
            '-Action', 'Install',
            '-AllowUnsigned',
            '-Json'
        )
    Invoke-RejectedBootstrap `
        -InstallerPath (Join-Path $untrustedRoot 'install-enterprise.ps1') `
        -ExpectedError 'certification services require exact run-scoped' `
        -InstallerArguments @(
            '-Action', 'Install',
            '-GatewayServiceName', $scopeGatewayService,
            '-GuardianServiceName', $scopeGuardianService,
            '-InstallRoot', "$scopeInstallRoot-near",
            '-StateRoot', $scopeStateRoot,
            '-CertificationCodexHome', $scopeCertificationCodexHome,
            '-AllowUnsigned',
            '-Json'
        )
    Invoke-RejectedBootstrap `
        -InstallerPath (Join-Path $untrustedRoot 'install-enterprise.ps1') `
        -ExpectedError 'certification services require exact run-scoped' `
        -InstallerArguments @(
            '-Action', 'Install',
            '-GatewayServiceName', $scopeGatewayService,
            '-GuardianServiceName', $scopeGuardianService,
            '-InstallRoot', $scopeInstallRoot,
            '-StateRoot', "$scopeStateRoot-near",
            '-CertificationCodexHome', $scopeCertificationCodexHome,
            '-AllowUnsigned',
            '-Json'
        )

    # A medium user can create a raw per-logon DOS-device alias without
    # SeCreateSymbolicLinkPrivilege. DriveInfo reports that alias as fixed
    # NTFS, and subst.exe does not enumerate it. Exercise the public bootstrap
    # in a child of this same logon so only authoritative mount-manager volume
    # identity can reject the redirected root.
    if (-not $effectiveMediumNonAdmin) {
        throw (
            'raw DOS-device bootstrap regression requires the executable ' +
            'test process to be an effective medium-integrity non-admin user'
        )
    }
    Initialize-RawDosDeviceInterop
    foreach ($candidate in @('Y:', 'X:', 'W:', 'V:', 'U:', 'T:', 'S:', 'R:')) {
        if ([string]::IsNullOrWhiteSpace(
                [DefenseClaw.Windows.Tests.RawDosDeviceNative]::TryQuery(
                    $candidate
                )
            ) -and
            -not (Test-Path -LiteralPath ($candidate + '\'))) {
            $rawAliasDrive = $candidate
            break
        }
    }
    if ([string]::IsNullOrWhiteSpace($rawAliasDrive)) {
        throw 'raw DOS-device bootstrap regression found no unused drive alias'
    }
    $rawAliasTargetDirectory = Join-Path $testRoot 'raw-dos-device-target'
    [void](New-Item -ItemType Directory -Path $rawAliasTargetDirectory)
    $sourceRoot = [IO.Path]::GetPathRoot(
        $rawAliasTargetDirectory
    )
    $sourceDrive = $sourceRoot.TrimEnd('\')
    $sourceDevice = [DefenseClaw.Windows.Tests.RawDosDeviceNative]::TryQuery(
        $sourceDrive
    )
    if ([string]::IsNullOrWhiteSpace($sourceDevice) -or
        $sourceDevice.StartsWith('\??\')) {
        throw 'raw DOS-device bootstrap fixture could not resolve its local source volume'
    }
    $sourceRelative = $rawAliasTargetDirectory.Substring(
        $sourceRoot.Length
    ).TrimStart('\')
    $rawAliasTarget = $sourceDevice.TrimEnd('\') + '\' + $sourceRelative
    [DefenseClaw.Windows.Tests.RawDosDeviceNative]::DefineRaw(
        $rawAliasDrive,
        $rawAliasTarget
    )
    $rawAliasDefined = $true
    $observedAliasTarget =
        [DefenseClaw.Windows.Tests.RawDosDeviceNative]::TryQuery(
            $rawAliasDrive
        )
    if (-not [string]::Equals(
            $observedAliasTarget,
            $rawAliasTarget,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw (
            'raw DOS-device bootstrap fixture did not create the exact ' +
            'per-logon alias'
        )
    }
    $rawAliasRoot = $rawAliasDrive + '\'
    $aliasDriveInfo = [IO.DriveInfo]::new($rawAliasRoot)
    if ($aliasDriveInfo.DriveType -ne [IO.DriveType]::Fixed -or
        -not [string]::Equals(
            $aliasDriveInfo.DriveFormat,
            'NTFS',
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw 'raw DOS-device alias did not reproduce the fixed-NTFS bypass precondition'
    }
    $productionNativePathType = Get-ProductionBootstrapNativePathType
    $productionNativePathType::AssertCanonicalDriveRoot(
        $sourceRoot,
        $sourceDrive
    )
    $canonicalSystemDriveAccepted = $true
    try {
        $productionNativePathType::AssertCanonicalDriveRoot(
            $rawAliasRoot,
            $rawAliasDrive
        )
        throw 'production bootstrap native probe accepted a raw DOS-device alias'
    }
    catch {
        if ($_.Exception.Message -notmatch (
                'GetVolumeNameForVolumeMountPoint|authoritative volume|' +
                'Mount Manager|canonical DOS drive root'
            )) {
            throw
        }
        $rawAliasNativeProbeRejected = $true
    }
    foreach ($candidate in @('X:', 'W:', 'V:', 'U:', 'T:', 'S:', 'R:', 'Q:')) {
        if (-not [string]::Equals(
                $candidate,
                $rawAliasDrive,
                [StringComparison]::OrdinalIgnoreCase
            ) -and
            [string]::IsNullOrWhiteSpace(
                [DefenseClaw.Windows.Tests.RawDosDeviceNative]::TryQuery(
                    $candidate
                )
            ) -and
            -not (Test-Path -LiteralPath ($candidate + '\'))) {
            $wholeVolumeAliasDrive = $candidate
            break
        }
    }
    if ([string]::IsNullOrWhiteSpace($wholeVolumeAliasDrive)) {
        throw 'whole-volume DOS-device regression found no second unused drive alias'
    }
    $wholeVolumeAliasTarget = $sourceDevice
    [DefenseClaw.Windows.Tests.RawDosDeviceNative]::DefineRaw(
        $wholeVolumeAliasDrive,
        $wholeVolumeAliasTarget
    )
    $wholeVolumeAliasDefined = $true
    $observedWholeVolumeTarget =
        [DefenseClaw.Windows.Tests.RawDosDeviceNative]::TryQuery(
            $wholeVolumeAliasDrive
        )
    if (-not [string]::Equals(
            $observedWholeVolumeTarget,
            $wholeVolumeAliasTarget,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw 'whole-volume DOS-device fixture did not create the exact alias'
    }
    $wholeVolumeAliasRoot = $wholeVolumeAliasDrive + '\'
    $wholeVolumeDriveInfo = [IO.DriveInfo]::new($wholeVolumeAliasRoot)
    if ($wholeVolumeDriveInfo.DriveType -ne [IO.DriveType]::Fixed -or
        -not [string]::Equals(
            $wholeVolumeDriveInfo.DriveFormat,
            'NTFS',
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw 'whole-volume DOS-device alias did not appear as fixed NTFS'
    }
    try {
        $productionNativePathType::AssertCanonicalDriveRoot(
            $wholeVolumeAliasRoot,
            $wholeVolumeAliasDrive
        )
        throw 'production bootstrap native probe accepted a whole-volume alias'
    }
    catch {
        if ($_.Exception.Message -notmatch (
                'QueryDosDevice failed for Global|authoritative volume|' +
                'Mount Manager|canonical DOS drive root'
            )) {
            throw
        }
        $wholeVolumeAliasNativeProbeRejected = $true
    }
    $moduleLogicalDiskProbe =
        Invoke-ProductionModuleLogicalDiskAliasProbe `
            -NormalDrive $sourceDrive `
            -AliasDrives @($rawAliasDrive, $wholeVolumeAliasDrive)
    if (-not [bool]$moduleLogicalDiskProbe.canonical_system_drive_accepted -or
        @($moduleLogicalDiskProbe.rejected_aliases).Count -ne 2 -or
        [string]$moduleLogicalDiskProbe.rejected_aliases[0] -cne
            $rawAliasDrive -or
        [string]$moduleLogicalDiskProbe.rejected_aliases[1] -cne
            $wholeVolumeAliasDrive) {
        throw 'production module logical-disk raw-alias evidence is incomplete'
    }
    $aliasBootstrapDirectory = Join-Path $rawAliasRoot 'bootstrap'
    $aliasBootstrapPhysicalDirectory = Join-Path `
        $rawAliasTargetDirectory `
        'bootstrap'
    [void](New-Item -ItemType Directory -Path $aliasBootstrapDirectory)
    Copy-Item `
        -LiteralPath $installerSource `
        -Destination (
            Join-Path $aliasBootstrapDirectory 'install-enterprise.ps1'
        )
    Set-Content `
        -LiteralPath (
            Join-Path $aliasBootstrapDirectory 'DefenseClawEnterprise.psm1'
        ) `
        -Value $maliciousModule `
        -Encoding UTF8
    $wholeVolumeAliasBootstrapDirectory = Join-Path `
        $wholeVolumeAliasRoot `
        $aliasBootstrapPhysicalDirectory.Substring($sourceRoot.Length)
    $wholeVolumeAliasInstaller = Join-Path `
        $wholeVolumeAliasBootstrapDirectory `
        'install-enterprise.ps1'
    $aliasCertificationHome = Join-Path `
        $rawAliasRoot `
        ".codex-defenseclaw-cert-$scopeToken"
    [void](New-Item -ItemType Directory -Path $aliasCertificationHome)
    $rawAliasInventoryBefore = @(
        Get-RawAliasFixtureInventory $rawAliasRoot
    )
    foreach ($case in @(
        [pscustomobject]@{
            name = 'installer_module_path'
            installer_path = Join-Path `
                $aliasBootstrapDirectory `
                'install-enterprise.ps1'
            install_root = $scopeInstallRoot
            state_root = $scopeStateRoot
            certification_home = $scopeCertificationCodexHome
            expected_error = (
                'GetVolumeNameForVolumeMountPoint|authoritative volume|' +
                'Mount Manager|canonical DOS drive root'
            )
        },
        [pscustomobject]@{
            name = 'whole_volume_installer_module_path'
            installer_path = $wholeVolumeAliasInstaller
            install_root = $scopeInstallRoot
            state_root = $scopeStateRoot
            certification_home = $scopeCertificationCodexHome
            expected_error = (
                'QueryDosDevice failed for Global|authoritative volume|' +
                'Mount Manager|canonical DOS drive root'
            )
        },
        [pscustomobject]@{
            name = 'install_root'
            installer_path = $installerSource
            install_root = Join-Path $rawAliasRoot 'install'
            state_root = $scopeStateRoot
            certification_home = $aliasCertificationHome
            expected_error = 'certification services require exact run-scoped'
        },
        [pscustomobject]@{
            name = 'state_root'
            installer_path = $installerSource
            install_root = $scopeInstallRoot
            state_root = Join-Path $rawAliasRoot 'state'
            certification_home = $aliasCertificationHome
            expected_error = 'certification services require exact run-scoped'
        },
        [pscustomobject]@{
            name = 'certification_home'
            installer_path = $installerSource
            install_root = $scopeInstallRoot
            state_root = $scopeStateRoot
            certification_home = $aliasCertificationHome
            expected_error = (
                'GetVolumeNameForVolumeMountPoint|canonical|mount-manager|' +
                'DOS.device|volume root|redirection'
            )
        }
    )) {
        Invoke-RejectedBootstrap `
            -InstallerPath ([string]$case.installer_path) `
            -ExpectedError ([string]$case.expected_error) `
            -InstallerArguments @(
                '-Action', 'Install',
                '-GatewayServiceName', $scopeGatewayService,
                '-GuardianServiceName', $scopeGuardianService,
                '-InstallRoot', ([string]$case.install_root),
                '-StateRoot', ([string]$case.state_root),
                '-CertificationCodexHome', ([string]$case.certification_home),
                '-AllowUnsigned',
                '-Json'
            )
        foreach ($unexpectedRoot in @(
            $scopeInstallRoot,
            $scopeStateRoot,
            (Join-Path $rawAliasRoot 'install'),
            (Join-Path $rawAliasRoot 'state')
        )) {
            if (Test-Path -LiteralPath $unexpectedRoot) {
                throw (
                    "raw DOS-device $($case.name) rejection created a " +
                    "managed root: $unexpectedRoot"
                )
            }
        }
        $rawAliasCases.Add([pscustomobject]@{
            name = [string]$case.name
            rejected_before_module_import = $true
            managed_roots_absent = $true
        })
    }
    $rawAliasInventoryAfter = @(
        Get-RawAliasFixtureInventory $rawAliasRoot
    )
    if (($rawAliasInventoryBefore | ConvertTo-Json -Compress -Depth 5) -cne
        ($rawAliasInventoryAfter | ConvertTo-Json -Compress -Depth 5)) {
        throw (
            'raw DOS-device bootstrap rejection changed its medium-user ' +
            'fixture or left temporary content'
        )
    }

    # Directory junctions do not require SeCreateSymbolicLinkPrivilege. Running
    # the copied installer through one proves an ancestor reparse is rejected
    # before the adjacent module can execute.
    $junctionTarget = Join-Path $testRoot 'junction-target'
    $junctionPath = Join-Path $testRoot 'junction'
    [void](New-Item -ItemType Directory -Path $junctionTarget)
    Copy-Item `
        -LiteralPath $installerSource `
        -Destination (Join-Path $junctionTarget 'install-enterprise.ps1')
    Set-Content `
        -LiteralPath (Join-Path $junctionTarget 'DefenseClawEnterprise.psm1') `
        -Value $maliciousModule `
        -Encoding UTF8
    try {
        [void](New-Item -ItemType Junction -Path $junctionPath -Target $junctionTarget)
        Invoke-RejectedBootstrap `
            -InstallerPath (Join-Path $junctionPath 'install-enterprise.ps1') `
            -ExpectedError 'reparse point'
        $junctionExecuted = $true
    }
    catch {
        # A runner that cannot create a junction (missing SeCreateSymbolic-
        # LinkPrivilege, filesystem that does not support reparse points)
        # should not fail the whole smoke. Record the capability gap on the
        # report field so the reason is visible and treat this branch as a
        # skip. Any other error still fails the smoke.
        if ($_.Exception.Message -match 'privilege|not supported|cannot find|reparse') {
            $junctionCapabilityUnavailable = $true
            $junctionCapabilityReason = $_.Exception.Message
        }
        else {
            throw
        }
    }
}
finally {
    $rawAliasCleanupErrors = [Collections.Generic.List[string]]::new()
    if ($wholeVolumeAliasDefined) {
        try {
            $wholeVolumeAliasCleanupVerified =
                Remove-RawDosDeviceFixtureAlias `
                    -Drive $wholeVolumeAliasDrive `
                    -Target $wholeVolumeAliasTarget
            $wholeVolumeAliasDefined = $false
        }
        catch {
            $rawAliasCleanupErrors.Add(
                'whole-volume alias cleanup failed: ' +
                $_.Exception.Message
            )
        }
    }
    if ($rawAliasDefined) {
        try {
            $rawAliasCleanupVerified =
                Remove-RawDosDeviceFixtureAlias `
                    -Drive $rawAliasDrive `
                    -Target $rawAliasTarget
            $rawAliasDefined = $false
        }
        catch {
            $rawAliasCleanupErrors.Add(
                'subdirectory alias cleanup failed: ' +
                $_.Exception.Message
            )
        }
    }
    $fullTestRoot = [IO.Path]::GetFullPath($testRoot).TrimEnd('\')
    $fullTempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
    if (-not $fullTestRoot.StartsWith(
        $fullTempRoot + '\',
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "refusing to clean bootstrap fixture outside the temporary root: $fullTestRoot"
    }
    if (Test-Path -LiteralPath $fullTestRoot) {
        Remove-Item -LiteralPath $fullTestRoot -Recurse -Force
    }
    $fullCertificationHome = [IO.Path]::GetFullPath(
        $scopeCertificationCodexHome
    ).TrimEnd('\')
    if (-not [string]::Equals(
        [IO.Path]::GetDirectoryName($fullCertificationHome).TrimEnd('\'),
        $fullTempRoot,
        [StringComparison]::OrdinalIgnoreCase
    ) -or
        [IO.Path]::GetFileName($fullCertificationHome) -cne
            ".codex-defenseclaw-cert-$scopeToken") {
        throw "refusing to clean unexpected certification CODEX_HOME fixture: $fullCertificationHome"
    }
    if (Test-Path -LiteralPath $fullCertificationHome) {
        Remove-Item -LiteralPath $fullCertificationHome -Recurse -Force
    }
    if ($rawAliasCleanupErrors.Count -ne 0) {
        throw ($rawAliasCleanupErrors -join '; ')
    }
}

$reportJson = [pscustomobject]@{
    schema_version = 1
    ok = $true
    engine = $PSVersionTable.PSVersion.ToString()
    untrusted_module_rejected_before_import = $true
    fixed_helper_spoof_ignored = $true
    reparse_ancestor_rejected_before_import = $junctionExecuted
    exact_unsigned_scope_reached_bootstrap_trust = $true
    production_unsigned_scope_rejected_before_import = $true
    near_miss_unsigned_roots_rejected_before_import = $true
    signed_custom_roots_rejected_before_import = $true
    signed_custom_service_names_rejected_before_import = $true
    certification_mutation_requires_unsigned_before_import = $true
    raw_dos_device_medium_user = $true
    raw_dos_device_cases = @($rawAliasCases.ToArray())
    raw_dos_device_rejected_before_import = (
        $rawAliasCases.Count -eq 5
    )
    canonical_system_drive_accepted = $canonicalSystemDriveAccepted
    raw_dos_device_native_probe_rejected = $rawAliasNativeProbeRejected
    whole_volume_alias_native_probe_rejected =
        $wholeVolumeAliasNativeProbeRejected
    whole_volume_alias_cleanup_verified =
        $wholeVolumeAliasCleanupVerified
    module_canonical_system_drive_accepted =
        [bool]$moduleLogicalDiskProbe.canonical_system_drive_accepted
    module_raw_subdirectory_alias_rejected = (
        [string]$moduleLogicalDiskProbe.rejected_aliases[0] -cne ''
    )
    module_raw_whole_volume_alias_rejected = (
        [string]$moduleLogicalDiskProbe.rejected_aliases[1] -cne ''
    )
    raw_dos_device_no_roots_or_temp = $true
    raw_dos_device_cleanup_verified = $rawAliasCleanupVerified
} | ConvertTo-Json -Compress
if (-not [string]::IsNullOrWhiteSpace($BasicUserResultPath)) {
    Write-BasicUserResult -Json $reportJson
    exit 0
}
Write-Output $reportJson
