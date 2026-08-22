# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$harness = Join-Path $PSScriptRoot 'run-windows.ps1'
$workflowRunPathHelper = Join-Path $PSScriptRoot 'workflow-run-path.ps1'
$openCodeAssertion = Join-Path $PSScriptRoot 'assert-opencode-plugin.mjs'
$auditProjector = Join-Path $PSScriptRoot 'project-audit-events.py'
$nativeHarness = Join-Path $root 'scripts\windows-native-ci.ps1'
$wizardHarness = Join-Path $root 'scripts\test-windows-setup-wizard.ps1'
$standardUserCI = Join-Path $root 'scripts\invoke-windows-setup-standard-user-ci.ps1'
$standardUserLauncher = Join-Path $root 'scripts\windows-disposable-standard-user-launcher.cs'
$standardUserFileGuard = Join-Path $root 'scripts\windows-disposable-file-guard.cs'
$standardUserSafety = Join-Path $root 'scripts\windows-disposable-user-safety.ps1'
$standardUserSafetyTest = Join-Path $root 'scripts\test-windows-disposable-user-safety.ps1'
$setupStandardUserLauncher = Join-Path $root 'scripts\windows-setup-standard-user-launcher.cs'
$nativePathHelpers = Join-Path $root 'scripts\windows-native-paths.ps1'
$nativePathInitializer = Join-Path $root 'scripts\initialize-windows-native-ci-paths.ps1'
$nativeWorkflow = Join-Path $root '.github\workflows\windows-native.yml'
$releaseWorkflow = Join-Path $root '.github\workflows\release.yaml'
$liveWorkflow = Join-Path $root '.github\workflows\connector-live-e2e.yml'
$ciWorkflow = Join-Path $root '.github\workflows\ci.yml'
$installer = Join-Path $root 'scripts\install.ps1'
$ampHookTest = Join-Path $root 'internal\gateway\amp_hook_test.go'
$setupMainSource = Join-Path $root 'cmd\defenseclaw-setup\main.go'
$setupMainTests = Join-Path $root 'cmd\defenseclaw-setup\main_test.go'
$setupWizardSource = Join-Path $root 'cmd\defenseclaw-setup\wizard_windows.go'
$devinAdmissionSource = Join-Path $root 'cmd\defenseclaw-setup\devin_admission_windows.go'
$devinAdmissionTests = Join-Path $root 'cmd\defenseclaw-setup\devin_admission_windows_test.go'
$mock = Join-Path $PSScriptRoot 'testdata\windows-mock.ps1'
$ampGoldenRoot = Join-Path $PSScriptRoot 'golden\amp'
$tempCandidates = [Collections.Generic.List[string]]::new()
if (-not [string]::IsNullOrWhiteSpace($env:RUNNER_TEMP)) {
    $tempCandidates.Add($env:RUNNER_TEMP)
}
$tempCandidates.Add([IO.Path]::GetTempPath())
$tempParent = $null
foreach ($candidate in $tempCandidates) {
    try {
        $fullCandidate = [IO.Path]::GetFullPath($candidate)
        if ($fullCandidate.Length -gt
            [IO.Path]::GetPathRoot($fullCandidate).Length) {
            $fullCandidate = $fullCandidate.TrimEnd('\')
        }
        $item = Get-Item -LiteralPath $fullCandidate -Force -ErrorAction Stop
        $regularChain = $item.PSIsContainer
        $cursor = $item
        while ($regularChain -and $null -ne $cursor) {
            $cursor.Refresh()
            if (-not $cursor.Exists -or
                ($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                $regularChain = $false
                break
            }
            $cursor = $cursor.Parent
        }
        if ($regularChain) {
            $tempParent = $fullCandidate
            break
        }
    } catch {
        # Fall through to the next existing temp root.
    }
}
if ([string]::IsNullOrWhiteSpace($tempParent)) {
    throw 'Windows harness tests require an existing, non-reparse temporary directory'
}
$temp = Join-Path $tempParent ("dc-windows-harness-test-" + [guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($temp) | Out-Null
$script:LogRoot = Join-Path $temp 'logs'
[IO.Directory]::CreateDirectory($script:LogRoot) | Out-Null
$script:CommandIndex = 0

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw "assertion failed: $Message" }
}

function Invoke-PackageLiveCleanupRegressionFixture {
    $paths = [pscustomobject]@{
        StatePath = 'C:\fixture\install\installer\install-state.json'
        InstallRoot = 'C:\fixture\install'
        DataRoot = 'C:\fixture\data'
        CacheRoot = 'C:\fixture\cache'
        CommandDir = 'C:\fixture\install\bin'
    }
    $fixture = [pscustomobject]@{
        Paths = $paths
        Setup = 'C:\fixture\package\DefenseClawSetup-x64.exe'
        Exists = [Collections.Generic.Dictionary[string, bool]]::new(
            [StringComparer]::OrdinalIgnoreCase
        )
        AuthorityCalls = 0
        IdentityCalls = 0
        UninstallCalls = 0
        DeferredCalls = 0
        ResultRows = [Collections.Generic.List[object]]::new()
        RejectDeferred = $false
    }
    $fixture.Exists[$paths.StatePath] = $true
    $fixture.Exists[$paths.InstallRoot] = $true

    $mockedFunctions = @(
        'Initialize-PackageLiveEvidenceAuthority',
        'Get-PackageLiveEvidencePaths',
        'Assert-PackageLiveInstalledIdentity',
        'Invoke-NativeProcess',
        'Assert-PackageDeferredCleanupPending',
        'Write-Result'
    )
    $savedFunctions = @{}
    foreach ($name in $mockedFunctions) {
        $savedFunctions[$name] = (
            Get-Command $name -CommandType Function -ErrorAction Stop
        ).ScriptBlock
    }
    $existingTestPath = Get-Command Test-Path -CommandType Function `
        -ErrorAction SilentlyContinue
    $savedTestPath = if ($null -eq $existingTestPath) {
        $null
    } else {
        $existingTestPath.ScriptBlock
    }
    $savedSetup = $script:PackageLiveSetupExecutable
    $savedOriginalPath = $script:PackageLiveOriginalPath
    $script:PackageLiveCleanupFixture = $fixture
    try {
        Set-Item Function:script:Initialize-PackageLiveEvidenceAuthority {
            $script:PackageLiveCleanupFixture.AuthorityCalls++
            $script:PackageLiveSetupExecutable =
                $script:PackageLiveCleanupFixture.Setup
        }
        Set-Item Function:script:Get-PackageLiveEvidencePaths {
            return $script:PackageLiveCleanupFixture.Paths
        }
        Set-Item Function:script:Assert-PackageLiveInstalledIdentity {
            param([pscustomobject]$Paths)
            if ($Paths -ne $script:PackageLiveCleanupFixture.Paths) {
                throw 'fixture received the wrong installed paths'
            }
            $script:PackageLiveCleanupFixture.IdentityCalls++
        }
        Set-Item Function:script:Invoke-NativeProcess {
            param(
                [string]$FilePath,
                [string[]]$ArgumentList,
                [int[]]$AllowedExitCodes,
                [int]$TimeoutSeconds
            )
            $state = $script:PackageLiveCleanupFixture
            if ($FilePath -cne $state.Setup -or
                ($ArgumentList -join ' ') -cne
                    '/uninstall /quiet /norestart DELETEUSERDATA=1' -or
                ($AllowedExitCodes -join ',') -cne '0,3010' -or
                $TimeoutSeconds -ne 900) {
                throw 'fixture observed a broadened or malformed Setup uninstall contract'
            }
            $state.UninstallCalls++
            $state.Exists.Remove($state.Paths.StatePath) | Out-Null
            $state.Exists.Remove($state.Paths.InstallRoot) | Out-Null
            $state.Exists.Remove($state.Paths.DataRoot) | Out-Null
            $state.Exists[$state.Paths.CacheRoot] = $true
            return [pscustomobject]@{ ExitCode = 3010 }
        }
        Set-Item Function:script:Assert-PackageDeferredCleanupPending {
            param([pscustomobject]$Paths, [string]$ExactSetupExecutable)
            $state = $script:PackageLiveCleanupFixture
            if ($Paths -ne $state.Paths -or $ExactSetupExecutable -cne $state.Setup) {
                throw 'fixture received the wrong deferred cleanup authority'
            }
            $state.DeferredCalls++
            if ($state.RejectDeferred) {
                throw 'protected package deferred cleanup retained an unexpected same-boot path'
            }
            return [pscustomobject]@{ status = 'pending-reboot' }
        }
        Set-Item Function:script:Write-Result {
            param([string]$EventName, [string]$Status, [string]$Detail)
            $script:PackageLiveCleanupFixture.ResultRows.Add(
                [pscustomobject]@{
                    Event = $EventName
                    Status = $Status
                    Detail = $Detail
                }
            )
        }
        Set-Item Function:script:Test-Path {
            param([string]$LiteralPath, [object]$PathType)
            $exists = $script:PackageLiveCleanupFixture.Exists
            return $exists.ContainsKey($LiteralPath) -and $exists[$LiteralPath]
        }

        Invoke-PackageLiveEvidenceCleanup
        Invoke-PackageLiveEvidenceCleanup
        Assert-True ($fixture.AuthorityCalls -eq 2 -and
            $fixture.IdentityCalls -eq 1 -and
            $fixture.UninstallCalls -eq 1 -and
            $fixture.DeferredCalls -eq 2) `
            '3010 cleanup authenticates the installed package once and exact deferred residue again on safety-net re-entry'
        Assert-True ($fixture.ResultRows.Count -eq 1 -and
            $fixture.ResultRows[0].Event -ceq 'package:cleanup' -and
            $fixture.ResultRows[0].Status -ceq 'pass' -and
            $fixture.ResultRows[0].Detail -match '3010.*pending reboot') `
            '3010 cleanup reports successful uninstall with truthful pending-reboot status'

        $deferredCalls = $fixture.DeferredCalls
        $fixture.Exists[$paths.InstallRoot] = $true
        $foreignRejected = $false
        try { Invoke-PackageLiveEvidenceCleanup } catch {
            $foreignRejected = $_.Exception.Message -match
                'product state without exact installed provenance'
        }
        Assert-True ($foreignRejected -and
            $fixture.DeferredCalls -eq $deferredCalls) `
            'cleanup rejects partial install state before treating cache residue as deferred authority'

        $fixture.Exists.Remove($paths.InstallRoot) | Out-Null
        $fixture.RejectDeferred = $true
        $extraResidueRejected = $false
        try { Invoke-PackageLiveEvidenceCleanup } catch {
            $extraResidueRejected = $_.Exception.Message -match
                'unexpected same-boot path'
        }
        Assert-True $extraResidueRejected `
            'cleanup propagates exact deferred-residue validation failures'

        $primaryFailure = [InvalidOperationException]::new('primary live failure')
        $cleanupFailure = [InvalidOperationException]::new('secondary cleanup failure')
        $secondaryReport = @(& {
            Complete-PackageLiveFinalization $primaryFailure $cleanupFailure
        } 3>&1) -join "`n"
        Assert-True ($secondaryReport -match
            'finalization also failed after the primary harness failure.*secondary cleanup failure') `
            'a secondary cleanup failure is reported without replacing the primary live failure'
        $standaloneCleanupSurfaced = $false
        try { Complete-PackageLiveFinalization $null $cleanupFailure } catch {
            $standaloneCleanupSurfaced = $_.Exception.Message -match
                'secondary cleanup failure'
        }
        Assert-True $standaloneCleanupSurfaced `
            'cleanup failure remains fatal when no primary live failure exists'
    } finally {
        foreach ($name in $mockedFunctions) {
            Set-Item "Function:script:$name" $savedFunctions[$name]
        }
        if ($null -eq $savedTestPath) {
            Remove-Item Function:\Test-Path -ErrorAction SilentlyContinue
        } else {
            Set-Item Function:script:Test-Path $savedTestPath
        }
        $script:PackageLiveSetupExecutable = $savedSetup
        $script:PackageLiveOriginalPath = $savedOriginalPath
        Remove-Variable -Name PackageLiveCleanupFixture -Scope Script `
            -ErrorAction SilentlyContinue
    }
}

function New-SyntheticProcessIdentity(
    [int]$ProcessId,
    [string]$Created,
    [string]$Exited = ''
) {
    return [pscustomobject]@{
        ProcessId = $ProcessId
        ParentProcessId = 0
        CreationDate = $Created
        ExitDate = $Exited
        ExecutablePath = ''
    }
}

function New-SyntheticProcessRow([int]$ProcessId, [int]$ParentId, [string]$Created) {
    return [pscustomobject]@{
        ProcessId = $ProcessId
        ParentProcessId = $ParentId
        CreationDate = [DateTime]$Created
        ExecutablePath = "C:\process-$ProcessId.exe"
    }
}

function Assert-SyntheticProcessTree(
    [object[]]$Roots,
    [object[]]$Processes,
    [int[]]$ExpectedIds,
    [string]$Message
) {
    $expected = @($ExpectedIds | Sort-Object) -join ','
    $liveIds = @(Get-ProcessTreeSnapshot -RootProcesses $Roots -ProcessSnapshot $Processes |
        ForEach-Object ProcessId | Sort-Object) -join ','
    $nativeIds = @(Get-WindowsNativeProcessTreeSnapshot `
        -RootProcesses $Roots -ProcessSnapshot $Processes |
        ForEach-Object ProcessId | Sort-Object) -join ','
    Assert-True ($liveIds -ceq $expected) "$Message (live helper returned: $liveIds)"
    Assert-True ($nativeIds -ceq $expected) "$Message (native helper returned: $nativeIds)"
}

function Invoke-PackagedRotationDiagnosticRegressionFixture([string]$Root) {
    [IO.Directory]::CreateDirectory($Root) | Out-Null
    $rawCredential = 'raw-rotation-credential-must-not-persist'
    $reason = Get-PackagedRotationFailureReason `
        -StdOut $rawCredential `
        -StdErr (@(
            'Error: Gateway start failed during the token-rotation transaction.',
            "untrusted child output credential=$rawCredential"
        ) -join [Environment]::NewLine)
    Assert-True ($reason -ceq 'gateway-start-failed') `
        'rotation failure classifier did not recognize the exact outer CLI message'
    $nearMatchReason = Get-PackagedRotationFailureReason `
        -StdOut '' `
        -StdErr "Error: Gateway start failed during the token-rotation transaction. $rawCredential"
    Assert-True ($nearMatchReason -ceq 'unclassified-cli-exit') `
        'rotation failure classifier accepted a non-exact or credential-bearing message'

    $diagnosticPath = Join-Path $Root 'rotation-failure.json'
    Write-PackagedRotationFailureDiagnostic `
        -Path $diagnosticPath -ExitCode 1 -Reason $reason
    $diagnosticText = [IO.File]::ReadAllText($diagnosticPath)
    $diagnostic = $diagnosticText | ConvertFrom-Json -ErrorAction Stop
    Assert-True (
        (@($diagnostic.PSObject.Properties.Name) -join ',') -ceq 'schema,exit,reason' -and
        [int]$diagnostic.schema -eq 1 -and
        [int]$diagnostic.exit -eq 1 -and
        [string]$diagnostic.reason -ceq 'gateway-start-failed' -and
        [Text.Encoding]::UTF8.GetByteCount($diagnosticText) -le 4096 -and
        -not $diagnosticText.Contains($rawCredential)
    ) 'rotation failure diagnostic was not bounded, fixed-schema, or secret-free'

    $priorityNames = @(
        'rotation-failure.json',
        'rotation-setup-codex.log',
        'rotation-success.log',
        'gateway.log',
        'watchdog.log'
    )
    foreach ($name in $priorityNames | Where-Object { $_ -cne 'rotation-failure.json' }) {
        Write-BoundedText -Path (Join-Path $Root $name) -Text 'safe diagnostic fixture'
    }
    Write-BoundedText -Path (Join-Path $Root 'rotation-failure-extra.json') `
        -Text 'must-not-capture'
    foreach ($index in 0..39) {
        Write-BoundedText -Path (Join-Path $Root ("00-rotation-decoy-{0:D2}.log" -f $index)) `
            -Text 'decoy'
    }
    $selected = @(Get-WindowsNativeCaptureFiles $Root)
    Assert-True ($selected.Count -eq 30) `
        'rotation diagnostic capture did not retain its existing 30-file cap'
    foreach ($name in $priorityNames) {
        Assert-True (@($selected | Where-Object { $_.Name -ceq $name }).Count -eq 1) `
            "rotation diagnostic capture did not prioritize $name over more than 30 decoys"
    }
    Assert-True (@($selected | Where-Object {
        $_.Name -ceq 'rotation-failure-extra.json'
    }).Count -eq 0) 'rotation diagnostic capture accepted a near-match JSON file'
}

try {
    foreach ($scriptPath in @(
        $harness,
        $workflowRunPathHelper,
        $nativeHarness,
        $wizardHarness,
        $standardUserCI,
        $standardUserSafety,
        $standardUserSafetyTest,
        $nativePathHelpers,
        $nativePathInitializer,
        $installer
    )) {
        $tokens = $null; $errors = $null
        [Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$errors) | Out-Null
        Assert-True (@($errors).Count -eq 0) "PowerShell parser errors in ${scriptPath}: $($errors -join '; ')"
    }
    $ampFixtureEvents = [ordered]@{
        'session_start.json' = 'session.start'
        'agent_start.json' = 'agent.start'
        'pre_tool_allow.json' = 'tool.call'
        'tool_result.json' = 'tool.result'
        'subagent_tool_call.json' = 'tool.call'
        'pre_tool_block.json' = 'tool.call'
        'agent_end.json' = 'agent.end'
    }
    foreach ($entry in $ampFixtureEvents.GetEnumerator()) {
        $payload = [IO.File]::ReadAllText((Join-Path $ampGoldenRoot $entry.Key)) |
            ConvertFrom-Json -ErrorAction Stop
        Assert-True ([string]$payload.hook_event_name -ceq [string]$entry.Value -and
            [string]$payload.agent_name -ceq 'amp' -and
            [string]$payload.agent_type -ceq 'amp' -and
            [string]$payload.session_id -ceq [string]$payload.thread_id -and
            -not [string]::IsNullOrWhiteSpace([string]$payload.source_event_id) -and
            -not [string]::IsNullOrWhiteSpace([string]$payload.source_sequence) -and
            $null -eq $payload.PSObject.Properties['agent_id']) `
            "Amp native fixture has an invalid identity or event shape: $($entry.Key)"
    }
    $subagentFixture = [IO.File]::ReadAllText(
        (Join-Path $ampGoldenRoot 'subagent_tool_call.json')
    ) | ConvertFrom-Json -ErrorAction Stop
    Assert-True ([string]$subagentFixture.tool_name -ceq 'Task' -and
        [bool]$subagentFixture.delegation_boundary) `
        'Amp subagent fixture marks the native Task tool as a delegation boundary'
    $heldStateFixtureRoot = Join-Path $temp (
        'dc-antigravity-held-state-fixture-' + [Guid]::NewGuid().ToString('N')
    )
    $fixturePowerShell = (Get-Command 'pwsh.exe' -CommandType Application -ErrorAction Stop |
        Select-Object -First 1).Source
    $heldStateFixtureOutput = @(& $fixturePowerShell -NoLogo -NoProfile -NonInteractive `
        -File $harness -HeldStateFixture -StateRoot $heldStateFixtureRoot 2>&1)
    Assert-True ($LASTEXITCODE -eq 0) (
        'authenticated Antigravity held-state dynamic fixture failed: ' +
        ($heldStateFixtureOutput -join [Environment]::NewLine)
    )
    Assert-True ($heldStateFixtureOutput -contains `
        'authenticated Antigravity held-state dynamic fixture: PASS') `
        'authenticated Antigravity held-state dynamic fixture did not report PASS'
    Assert-True (-not (Test-Path -LiteralPath $heldStateFixtureRoot)) `
        'authenticated Antigravity held-state dynamic fixture left its task root behind'
    $localAuthorityFixtureRoot = Join-Path $temp (
        'dc-antigravity-local-authority-fixture-' + [Guid]::NewGuid().ToString('N')
    )
    $localAuthorityFixtureOutput = @(& $fixturePowerShell `
        -NoLogo -NoProfile -NonInteractive -File $harness `
        -LocalAuthorityFixture -StateRoot $localAuthorityFixtureRoot 2>&1)
    Assert-True ($LASTEXITCODE -eq 0) (
        'authenticated Antigravity local-authority dynamic fixture failed: ' +
        ($localAuthorityFixtureOutput -join [Environment]::NewLine)
    )
    Assert-True ($localAuthorityFixtureOutput -contains `
        'authenticated Antigravity local-authority dynamic fixture: PASS') `
        'authenticated Antigravity local-authority fixture did not report PASS'
    Assert-True (-not (Test-Path -LiteralPath $localAuthorityFixtureRoot)) `
        'authenticated Antigravity local-authority fixture left its task root behind'
    & $standardUserSafetyTest
    if (-not ('DefenseClaw.DisposableStandardUserLauncher' -as [type])) {
        Add-Type -Path $standardUserLauncher
    }
    if (-not ('DefenseClaw.SetupStandardUserLauncher' -as [type])) {
        Add-Type -Path $setupStandardUserLauncher
    }
    $launcherType = [DefenseClaw.DisposableStandardUserLauncher]
    $privateStatic = [Reflection.BindingFlags]'NonPublic,Static'
    $createEmptyJob = $launcherType.GetMethod('CreateKillOnCloseJob', $privateStatic)
    $readActiveCount = $launcherType.GetMethod('GetActiveJobProcessCount', $privateStatic)
    $closeJob = $launcherType.GetMethod('CloseHandle', $privateStatic)
    Assert-True ($null -ne $createEmptyJob -and $null -ne $readActiveCount -and
        $null -ne $closeJob) 'disposable-user launcher exposes its compiled job accounting implementation'
    $emptyJob = [IntPtr]$createEmptyJob.Invoke($null, @())
    try {
        Assert-True ([uint32]$readActiveCount.Invoke($null, @($emptyJob)) -eq 0) `
            'new disposable-user job reports ActiveProcesses=0'
    } finally {
        [void]$closeJob.Invoke($null, @($emptyJob))
    }
    . $harness -NoRun
    . $workflowRunPathHelper
    . $nativeHarness -WorkspaceRoot $root -StateRoot (Join-Path $temp 'synthetic-native') -NoRun
    $missingOptionalCleanupFields = '{"status":"pending-reboot"}' |
        ConvertFrom-Json -ErrorAction Stop
    foreach ($propertyName in @(
        'cleanup_boot_identifier', 'data_root', 'gateway_path', 'gateway_sha256'
    )) {
        Assert-True (
            (Get-OptionalJsonStringValue `
                -InputObject $missingOptionalCleanupFields `
                -PropertyName $propertyName) -ceq ''
        ) "missing optional deferred-cleanup field is treated as its exact empty Go value: $propertyName"
    }
    $presentOptionalCleanupField = '{"cleanup_boot_identifier":"foreign-boot"}' |
        ConvertFrom-Json -ErrorAction Stop
    Assert-True (
        (Get-OptionalJsonStringValue `
            -InputObject $presentOptionalCleanupField `
            -PropertyName 'cleanup_boot_identifier') -ceq 'foreign-boot'
    ) 'present deferred-cleanup fields are not erased by optional-property access'
    Invoke-PackageLiveCleanupRegressionFixture
    Invoke-PackagedRotationDiagnosticRegressionFixture `
        (Join-Path $temp 'packaged-rotation-diagnostic')

    $validClaudeInstaller = @'
param([string]$Target = "latest")
$null = $Target
'@
    $claudeImmediateState = [pscustomobject]@{ Attempts = 0; Delays = 0 }
    $claudeImmediate = Get-OfficialClaudeInstallerScriptBlock `
        -MaxAttempts 3 -PerAttemptTimeoutSeconds 1 `
        -OverallTimeoutSeconds 5 -RequestInvoker {
            param([Uri]$Uri, [int]$TimeoutSeconds)
            $claudeImmediateState.Attempts++
            return $validClaudeInstaller
        } -DelayInvoker {
            param([int]$DelaySeconds)
            $claudeImmediateState.Delays++
        }
    Assert-True ($claudeImmediate -is [scriptblock] -and
        $claudeImmediateState.Attempts -eq 1 -and
        $claudeImmediateState.Delays -eq 0) `
        'Claude installer fetch returns immediately after one valid response'

    $claudeRetryState = [pscustomobject]@{ Attempts = 0; Delays = @() }
    $claudeRetrySecret = 'dc-claude-retry-secret-value'
    $originalAnthropicKey = $env:ANTHROPIC_API_KEY
    $env:ANTHROPIC_API_KEY = $claudeRetrySecret
    $claudeRetryWarnings = @()
    try {
        $claudeInstaller = Get-OfficialClaudeInstallerScriptBlock `
            -MaxAttempts 3 -PerAttemptTimeoutSeconds 1 `
            -OverallTimeoutSeconds 5 -RequestInvoker {
                param([Uri]$Uri, [int]$TimeoutSeconds)
                $claudeRetryState.Attempts++
                if ($claudeRetryState.Attempts -lt 3) {
                    $transientSocket = [Net.Sockets.SocketException]::new(
                        [int][Net.Sockets.SocketError]::ConnectionReset
                    )
                    throw [Net.Http.HttpRequestException]::new(
                        "The SSL connection could not be established: $claudeRetrySecret",
                        $transientSocket
                    )
                }
                return $validClaudeInstaller
            } -DelayInvoker {
                param([int]$DelaySeconds)
                $claudeRetryState.Delays += $DelaySeconds
            } -WarningVariable +claudeRetryWarnings
    } finally {
        $env:ANTHROPIC_API_KEY = $originalAnthropicKey
    }
    Assert-True ($claudeInstaller -is [scriptblock] -and
        $claudeRetryState.Attempts -eq 3 -and
        ($claudeRetryState.Delays -join ',') -ceq '2,4') `
        'Claude installer fetch retries only the bounded transient transport attempts'
    Assert-True ((@($claudeRetryWarnings) -join "`n").Contains('***REDACTED***') -and
        -not (@($claudeRetryWarnings) -join "`n").Contains($claudeRetrySecret)) `
        'Claude installer transient retry warnings redact configured secrets'

    foreach ($wrappedTransient in @(
        [pscustomobject]@{
            Name = 'authentication-wrapped EOF'
            Inner = [IO.IOException]::new(
                'Received an unexpected EOF or 0 bytes from the transport stream.'
            )
        },
        [pscustomobject]@{
            Name = 'authentication-wrapped connection reset'
            Inner = [Net.Sockets.SocketException]::new(
                [int][Net.Sockets.SocketError]::ConnectionReset
            )
        }
    )) {
        $wrappedState = [pscustomobject]@{ Attempts = 0; Delays = @() }
        $wrappedResult = Get-OfficialClaudeInstallerScriptBlock `
            -MaxAttempts 3 -PerAttemptTimeoutSeconds 1 `
            -OverallTimeoutSeconds 5 -RequestInvoker {
                param([Uri]$Uri, [int]$TimeoutSeconds)
                $wrappedState.Attempts++
                if ($wrappedState.Attempts -lt 3) {
                    throw [Net.Http.HttpRequestException]::new(
                        'The SSL connection could not be established, see inner exception.',
                        [Security.Authentication.AuthenticationException]::new(
                            'Authentication failed, see inner exception.',
                            $wrappedTransient.Inner
                        )
                    )
                }
                return $validClaudeInstaller
            } -DelayInvoker {
                param([int]$DelaySeconds)
                $wrappedState.Delays += $DelaySeconds
            } -WarningAction SilentlyContinue
        Assert-True ($wrappedResult -is [scriptblock] -and
            $wrappedState.Attempts -eq 3 -and
            ($wrappedState.Delays -join ',') -ceq '2,4') `
            "Claude installer retries $($wrappedTransient.Name) only through its concrete transient inner cause"
    }

    $claudeExhaustionState = [pscustomobject]@{ Attempts = 0; Delays = @() }
    $claudeExhaustionRejected = $false
    $env:ANTHROPIC_API_KEY = $claudeRetrySecret
    try {
        Get-OfficialClaudeInstallerScriptBlock -MaxAttempts 3 `
            -PerAttemptTimeoutSeconds 1 -OverallTimeoutSeconds 5 `
            -RequestInvoker {
                param([Uri]$Uri, [int]$TimeoutSeconds)
                $claudeExhaustionState.Attempts++
                $transientSocket = [Net.Sockets.SocketException]::new(
                    [int][Net.Sockets.SocketError]::ConnectionReset
                )
                throw [Net.Http.HttpRequestException]::new(
                    "The SSL connection could not be established: $claudeRetrySecret",
                    $transientSocket
                )
            } -DelayInvoker {
                param([int]$DelaySeconds)
                $claudeExhaustionState.Delays += $DelaySeconds
            } -WarningAction SilentlyContinue | Out-Null
    } catch {
        $serializedFailure = $_.Exception.ToString()
        $claudeExhaustionRejected = (
            $_.Exception.Message -match 'failed on attempt 3/3' -and
            $null -eq $_.Exception.InnerException -and
            $serializedFailure.Contains('***REDACTED***') -and
            -not $serializedFailure.Contains($claudeRetrySecret)
        )
    } finally {
        $env:ANTHROPIC_API_KEY = $originalAnthropicKey
    }
    Assert-True ($claudeExhaustionRejected -and
        $claudeExhaustionState.Attempts -eq 3 -and
        ($claudeExhaustionState.Delays -join ',') -ceq '2,4') `
        'Claude installer fetch stops after three bounded transient attempts without retaining secret-bearing exceptions'

    foreach ($terminalClaudeFailure in @(
        [pscustomobject]@{
            Name = 'HTTP status'
            Exception = [Net.Http.HttpRequestException]::new(
                'service unavailable', $null, [Net.HttpStatusCode]::ServiceUnavailable
            )
        },
        [pscustomobject]@{
            Name = 'ambiguous secure connection'
            Exception = [Net.Http.HttpRequestException]::new(
                'The SSL connection could not be established'
            )
        },
        [pscustomobject]@{
            Name = 'ambiguous authentication'
            Exception = [Net.Http.HttpRequestException]::new(
                'The SSL connection could not be established',
                [Security.Authentication.AuthenticationException]::new(
                    'Authentication failed'
                )
            )
        },
        [pscustomobject]@{
            Name = 'untrusted certificate root'
            Exception = [Net.Http.HttpRequestException]::new(
                'The SSL connection could not be established',
                [Security.Authentication.AuthenticationException]::new(
                    'The remote certificate is invalid because of errors in the certificate chain: UntrustedRoot'
                )
            )
        },
        [pscustomobject]@{
            Name = 'certificate hostname mismatch'
            Exception = [Net.Http.HttpRequestException]::new(
                'The SSL connection could not be established',
                [Security.Authentication.AuthenticationException]::new(
                    'RemoteCertificateNameMismatch'
                )
            )
        },
        [pscustomobject]@{
            Name = 'certificate evidence overrides transient-looking inner failure'
            Exception = [Net.Http.HttpRequestException]::new(
                'The SSL connection could not be established',
                [Security.Authentication.AuthenticationException]::new(
                    'The remote certificate is invalid: UntrustedRoot',
                    [IO.IOException]::new(
                        'Received an unexpected EOF or 0 bytes from the transport stream.'
                    )
                )
            )
        }
    )) {
        $terminalState = [pscustomobject]@{ Attempts = 0 }
        $terminalRejected = $false
        try {
            Get-OfficialClaudeInstallerScriptBlock -MaxAttempts 3 `
                -PerAttemptTimeoutSeconds 1 -OverallTimeoutSeconds 5 `
                -RequestInvoker {
                    param([Uri]$Uri, [int]$TimeoutSeconds)
                    $terminalState.Attempts++
                    throw $terminalClaudeFailure.Exception
                } -DelayInvoker { param([int]$DelaySeconds) } | Out-Null
        } catch {
            $terminalRejected = $_.Exception.Message -match
                'failed on attempt 1/3'
        }
        Assert-True ($terminalRejected -and $terminalState.Attempts -eq 1) `
            "Claude installer fetch does not retry $($terminalClaudeFailure.Name) failures"
    }

    $invalidClaudeState = [pscustomobject]@{ Attempts = 0 }
    $invalidClaudeRejected = $false
    try {
        Get-OfficialClaudeInstallerScriptBlock -MaxAttempts 3 `
            -PerAttemptTimeoutSeconds 1 -OverallTimeoutSeconds 5 `
            -RequestInvoker {
                param([Uri]$Uri, [int]$TimeoutSeconds)
                $invalidClaudeState.Attempts++
                return 'param('
            } -DelayInvoker { param([int]$DelaySeconds) } | Out-Null
    } catch {
        $invalidClaudeRejected = $_.Exception.Message -match
            'failed on attempt 1/3'
    }
    Assert-True ($invalidClaudeRejected -and $invalidClaudeState.Attempts -eq 1) `
        'Claude installer fetch rejects invalid content once without an integrity retry'

    $noncanonicalClaudeRejected = $false
    try {
        Assert-OfficialClaudeClientIdentity `
            -Path (Join-Path $temp 'foreign-claude.exe') `
            -ExpectedVersion '2.1.238' `
            -ExpectedSHA256 ('a' * 64) | Out-Null
    } catch {
        $noncanonicalClaudeRejected = $_.Exception.Message -match
            'not the canonical native launcher'
    }
    Assert-True $noncanonicalClaudeRejected `
        'executed Claude identity validation rejects a noncanonical parent handoff before client execution'

    $originalClaudeIdentityFunction =
        (Get-Command Assert-OfficialClaudeClientIdentity -CommandType Function).ScriptBlock
    $originalClaudeInstallerFunction =
        (Get-Command Get-OfficialClaudeInstallerScriptBlock -CommandType Function).ScriptBlock
    $unsetClaudeFixtureVariables = [Collections.Generic.List[string]]::new()
    foreach ($variableName in @('ResultsPath', 'ToolRoot', 'AgentVersion')) {
        if ($null -eq (Get-Variable -Name $variableName -Scope Script `
                    -ErrorAction SilentlyContinue)) {
            Set-Variable -Name $variableName -Scope Script -Value ''
            $unsetClaudeFixtureVariables.Add($variableName)
        }
    }
    $savedClaudeFixture = [ordered]@{
        Connector = $Connector
        PackageLiveEvidence = $PackageLiveEvidence
        ReleaseCertification = $ReleaseCertification
        ProtectedCopilotRunner = $ProtectedCopilotRunner
        AgentPath = $AgentPath
        ExpectedAgentVersion = $ExpectedAgentVersion
        ExpectedAgentSHA256 = $ExpectedAgentSHA256
        ResultsPath = $script:ResultsPath
        ToolRoot = $script:ToolRoot
        AgentVersion = $script:AgentVersion
        ClaudeVersion = $env:CLAUDE_VERSION
        DisableAutoUpdater = $env:DISABLE_AUTOUPDATER
    }
    $script:ClaudePackageIdentityCalls = 0
    $script:ClaudePackageNetworkCalls = 0
    try {
        Set-Item -LiteralPath Function:Assert-OfficialClaudeClientIdentity -Value {
            param(
                [string]$Path,
                [string]$ExpectedVersion = '',
                [string]$ExpectedSHA256 = ''
            )
            if ($Path -cne 'C:\Users\runneradmin\.local\bin\claude.exe' -or
                $ExpectedVersion -cne '2.1.238' -or
                $ExpectedSHA256 -cne ('a' * 64)) {
                throw 'package-live Claude identity fixture received the wrong parent handoff'
            }
            $script:ClaudePackageIdentityCalls++
            return [pscustomobject]@{
                Path = $Path
                Version = $ExpectedVersion
                VersionOutput = '2.1.238 (Claude Code)'
                SHA256 = $ExpectedSHA256
                Signer = 'Anthropic, PBC'
                SignerThumbprint = '0123456789ABCDEF0123456789ABCDEF01234567'
                OwnerSID = 'S-1-5-21-1-2-3-1001'
            }
        }
        Set-Item -LiteralPath Function:Get-OfficialClaudeInstallerScriptBlock -Value {
            $script:ClaudePackageNetworkCalls++
            throw 'restricted package-live Claude attempted a forbidden network bootstrap'
        }
        $script:Connector = 'claudecode'
        $script:PackageLiveEvidence = $true
        $script:ReleaseCertification = $false
        $script:ProtectedCopilotRunner = $false
        $script:AgentPath = 'C:\Users\runneradmin\.local\bin\claude.exe'
        $script:ExpectedAgentVersion = '2.1.238'
        $script:ExpectedAgentSHA256 = 'a' * 64
        $script:ResultsPath = Join-Path $temp 'claude-package-live-results.jsonl'
        $script:ToolRoot = Join-Path $temp 'claude-package-live-tools'
        $script:AgentVersion = 'unversioned'
        $env:CLAUDE_VERSION = 'latest'
        Install-Agent
        $claudePackageResult = Get-Content -LiteralPath $script:ResultsPath -Raw |
            ConvertFrom-Json -ErrorAction Stop
        Assert-True ($script:ClaudePackageIdentityCalls -eq 1 -and
            $script:ClaudePackageNetworkCalls -eq 0 -and
            [string]$script:AgentVersion -ceq '2.1.238 (Claude Code)' -and
            [string]$claudePackageResult.event -ceq 'install' -and
            [string]$claudePackageResult.status -ceq 'pass' -and
            [string]$claudePackageResult.detail -match
                'preinstalled=parent exact=2\.1\.238 sha256=a{64} signer=Anthropic, PBC') `
            'executed package-live Claude install revalidates the exact parent identity and performs no child bootstrap'
    } finally {
        Set-Item -LiteralPath Function:Assert-OfficialClaudeClientIdentity `
            -Value $originalClaudeIdentityFunction
        Set-Item -LiteralPath Function:Get-OfficialClaudeInstallerScriptBlock `
            -Value $originalClaudeInstallerFunction
        $script:Connector = $savedClaudeFixture.Connector
        $script:PackageLiveEvidence = $savedClaudeFixture.PackageLiveEvidence
        $script:ReleaseCertification = $savedClaudeFixture.ReleaseCertification
        $script:ProtectedCopilotRunner = $savedClaudeFixture.ProtectedCopilotRunner
        $script:AgentPath = $savedClaudeFixture.AgentPath
        $script:ExpectedAgentVersion = $savedClaudeFixture.ExpectedAgentVersion
        $script:ExpectedAgentSHA256 = $savedClaudeFixture.ExpectedAgentSHA256
        $script:ResultsPath = $savedClaudeFixture.ResultsPath
        $script:ToolRoot = $savedClaudeFixture.ToolRoot
        $script:AgentVersion = $savedClaudeFixture.AgentVersion
        $env:CLAUDE_VERSION = $savedClaudeFixture.ClaudeVersion
        $env:DISABLE_AUTOUPDATER = $savedClaudeFixture.DisableAutoUpdater
        foreach ($variableName in $unsetClaudeFixtureVariables) {
            Remove-Variable -Name $variableName -Scope Script -ErrorAction SilentlyContinue
        }
    }

    # GitHub-hosted Windows disables UAC and starts Actions with an elevated
    # default token whose default owner can be BUILTIN\Administrators. The
    # shared live lane deliberately uses the reviewed restricted-LUA fallback,
    # so exercise the exact owner normalization and suspended-child validation
    # used by that workflow whenever this host exposes the same token shape.
    if ([DefenseClaw.SetupStandardUserLauncher]::IsCurrentProcessElevated() -and
        -not [DefenseClaw.SetupStandardUserLauncher]::CurrentElevatedTokenHasLinkedLimitedToken()) {
        Set-CurrentUserAsDefaultOwner
        $restrictedOwnerRoot = Join-Path $temp (
            'restricted-owner-probe-' + [Guid]::NewGuid().ToString('N')
        )
        New-ProductPrivateTestDirectory $restrictedOwnerRoot
        $restrictedOwnerScript = Join-Path $restrictedOwnerRoot 'probe.ps1'
        $restrictedOwnerOutput = Join-Path $restrictedOwnerRoot 'result.json'
        $restrictedOwnerBody = @'
param(
    [Parameter(Mandatory)][string]$OutputPath,
    [Parameter(Mandatory)][string]$LauncherSource
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Add-Type -Path $LauncherSource
$output = [IO.Path]::GetFullPath($OutputPath)
$stream = [IO.FileStream]::new(
    $output,
    [IO.FileMode]::CreateNew,
    [IO.FileAccess]::Write,
    [IO.FileShare]::None
)
try {
    $bytes = [Text.Encoding]::ASCII.GetBytes('{}')
    $stream.Write($bytes, 0, $bytes.Length)
    $stream.Flush($true)
} finally {
    $stream.Dispose()
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$security = [IO.FileSystemAclExtensions]::GetAccessControl(
    [IO.FileInfo]::new($output),
    [Security.AccessControl.AccessControlSections]::Owner
)
$owner = $security.GetOwner([Security.Principal.SecurityIdentifier])
$payload = [ordered]@{
    user_sid = $identity.User.Value
    owner_sid = $owner.Value
    elevated = [DefenseClaw.SetupStandardUserLauncher]::IsCurrentProcessElevated()
    restricted_or_limited = [DefenseClaw.SetupStandardUserLauncher]::IsCurrentProcessRestrictedOrLimited()
}
[IO.File]::WriteAllText(
    $output,
    ($payload | ConvertTo-Json -Compress),
    [Text.UTF8Encoding]::new($false)
)
'@
        [IO.File]::WriteAllText(
            $restrictedOwnerScript,
            $restrictedOwnerBody,
            [Text.UTF8Encoding]::new($false)
        )
        $probePowerShell = Join-Path $PSHOME 'pwsh.exe'
        $restrictedLaunch = Invoke-WindowsSetupStandardUserProcess -FilePath $probePowerShell `
            -ArgumentList @(
                '-NoLogo', '-NoProfile', '-NonInteractive', '-File',
                $restrictedOwnerScript, '-OutputPath', $restrictedOwnerOutput,
                '-LauncherSource', $setupStandardUserLauncher
            ) -TimeoutSeconds 30 -WorkingDirectory $restrictedOwnerRoot `
            -AllowRestrictedLuaFallback -SuppressOutput
        $restrictedOwner = [IO.File]::ReadAllText(
            $restrictedOwnerOutput,
            [Text.Encoding]::UTF8
        ) | ConvertFrom-Json -ErrorAction Stop
        $restrictedOwnerSecurity = [IO.FileSystemAclExtensions]::GetAccessControl(
            [IO.FileInfo]::new($restrictedOwnerOutput),
            [Security.AccessControl.AccessControlSections]::Owner
        )
        $restrictedOwnerSID = $restrictedOwnerSecurity.GetOwner(
            [Security.Principal.SecurityIdentifier]
        ).Value
        Assert-True ([string]$restrictedLaunch.LaunchContext -ceq
                'verified-restricted-lua-default-token-noncertification' -and
            $null -ne $restrictedLaunch.ExitCode -and
            [int]$restrictedLaunch.ExitCode -eq 0 -and
            -not [bool]$restrictedOwner.elevated -and
            [bool]$restrictedOwner.restricted_or_limited -and
            [string]$restrictedOwner.user_sid -ceq
                [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -and
            [string]$restrictedOwner.owner_sid -ceq [string]$restrictedOwner.user_sid -and
            $restrictedOwnerSID -ceq [string]$restrictedOwner.user_sid) `
            'hosted restricted-LUA child is non-elevated, token-validated, and creates current-user-owned files'
    }

    foreach ($acceptedWorkflowRunPath in @(
        '.github/workflows/windows-native.yml',
        '.github/workflows/windows-native.yml@main',
        '.github/workflows/windows-native.yml@refs/heads/main',
        '.github/workflows/windows-native.yml@feature/windows-package',
        '.github/workflows/windows-native.yml@refs/heads/feature@beta',
        '.github/workflows/windows-native.yml@main@other',
        '.github/workflows/windows-native.yml@@main'
    )) {
        Assert-True (Test-CanonicalWindowsWorkflowRunPath $acceptedWorkflowRunPath) `
            "canonical Windows workflow run path was rejected: $acceptedWorkflowRunPath"
    }
    foreach ($rejectedWorkflowRunPath in @(
        '',
        '@main',
        '.github/workflows/windows-native.yml@',
        '.github/workflows/windows-native.yml@@',
        '.github/workflows/windows-native.yml@refs/heads/feature@{beta',
        '.github/workflows/windows-native.yml.backup@main',
        'prefix/.github/workflows/windows-native.yml@main',
        '.github/workflows/windows.yml@main',
        '.github/workflows/windows-native.yml@refs/heads//main',
        '.github/workflows/windows-native.yml@refs/heads/../main',
        '.github/workflows/windows-native.yml@refs/heads/.hidden',
        '.github/workflows/windows-native.yml@refs/heads/main.lock',
        '.github/workflows/windows-native.yml@refs/heads/main?query',
        ".github/workflows/windows-native.yml@refs/heads/main`nother",
        ('.github/workflows/windows-native.yml@refs/heads/' + ('a' * 256)),
        ('.github/workflows/windows-native.yml@' + ('a' * 4097))
    )) {
        Assert-True (-not (Test-CanonicalWindowsWorkflowRunPath $rejectedWorkflowRunPath)) `
            "malformed or ambiguous Windows workflow run path was accepted: $rejectedWorkflowRunPath"
    }

    $cursorCompatibilityHome = Join-Path $temp 'cursor-compatibility\.codex'
    Assert-CursorCompatibilitySkillHomes @($cursorCompatibilityHome)
    [IO.Directory]::CreateDirectory((Join-Path $cursorCompatibilityHome 'skills')) | Out-Null
    Assert-CursorCompatibilitySkillHomes @($cursorCompatibilityHome)
    [IO.File]::WriteAllText((Join-Path $cursorCompatibilityHome 'config.toml'), 'forbidden')
    $cursorCompatibilityConfigRejected = $false
    try {
        Assert-CursorCompatibilitySkillHomes @($cursorCompatibilityHome)
    } catch {
        $cursorCompatibilityConfigRejected = $_.Exception.Message -match
            'outside its empty documented compatibility skill root'
    }
    Assert-True $cursorCompatibilityConfigRejected `
        'Cursor compatibility skill-home allowance rejects a default Codex config'
    Remove-Item -LiteralPath (Join-Path $cursorCompatibilityHome 'config.toml') -Force
    [IO.File]::WriteAllText((Join-Path $cursorCompatibilityHome 'skills\SKILL.md'), 'forbidden')
    $cursorCompatibilityContentRejected = $false
    try {
        Assert-CursorCompatibilitySkillHomes @($cursorCompatibilityHome)
    } catch {
        $cursorCompatibilityContentRejected = $_.Exception.Message -match
            'outside its empty documented compatibility skill root'
    }
    Assert-True $cursorCompatibilityContentRejected `
        'Cursor compatibility skill-home allowance accepts only the watcher-created empty skills root'

    $copilotEvents = @(
        'sessionStart', 'sessionEnd', 'userPromptSubmitted',
        'userPromptTransformed', 'preToolUse', 'postToolUse',
        'postToolUseFailure', 'permissionRequest', 'agentStop', 'subagentStart',
        'subagentStop', 'errorOccurred', 'preCompact', 'notification'
    )
    $copilotHooks = [ordered]@{}
    foreach ($event in $copilotEvents) {
        $powershell = "`$ErrorActionPreference='Stop'; " +
            "`$env:NoDefaultCurrentDirectoryInExePath='1'; " +
            "`$hookProcess=Microsoft.PowerShell.Management\Start-Process " +
            "-FilePath 'C:\Program Files\DefenseClaw\bin\defenseclaw-hook.exe' " +
            "-ArgumentList @('hook','--connector','copilot','--event','$event') " +
            "-NoNewWindow -Wait -PassThru; exit `$hookProcess.ExitCode"
        $copilotHooks[$event] = @([ordered]@{
            type = 'command'
            powershell = $powershell
            timeoutSec = 30
        })
    }
    $copilotFixture = [ordered]@{ version = 1; hooks = $copilotHooks } |
        ConvertTo-Json -Depth 8
    Assert-CopilotSynchronousWindowsHookConfig $copilotFixture 'synthetic Copilot registration'

    $copilotWrongEvent = $copilotFixture | ConvertFrom-Json
    $copilotWrongEvent.hooks.preToolUse[0].powershell =
        ([string]$copilotWrongEvent.hooks.preToolUse[0].powershell).Replace(
            ",'preToolUse')",
            ",'postToolUse')"
        )
    $wrongEventRejected = $false
    try {
        Assert-CopilotSynchronousWindowsHookConfig (
            $copilotWrongEvent | ConvertTo-Json -Depth 8
        ) 'mismatched synthetic Copilot registration'
    } catch {
        $wrongEventRejected = $true
    }
    Assert-True $wrongEventRejected 'Copilot live harness rejects a mismatched --event binding'

    $copilotMissingEvent = $copilotFixture | ConvertFrom-Json
    [void]$copilotMissingEvent.hooks.PSObject.Properties.Remove('userPromptTransformed')
    $missingEventRejected = $false
    try {
        Assert-CopilotSynchronousWindowsHookConfig (
            $copilotMissingEvent | ConvertTo-Json -Depth 8
        ) '13-event synthetic Copilot registration'
    } catch {
        $missingEventRejected = $true
    }
    Assert-True $missingEventRejected 'Copilot live harness requires userPromptTransformed'

    $copilotExtraEvent = $copilotFixture | ConvertFrom-Json
    Add-Member -InputObject $copilotExtraEvent.hooks -MemberType NoteProperty `
        -Name futureEvent -Value $copilotExtraEvent.hooks.preToolUse
    $extraEventRejected = $false
    try {
        Assert-CopilotSynchronousWindowsHookConfig (
            $copilotExtraEvent | ConvertTo-Json -Depth 8
        ) 'extra-event synthetic Copilot registration'
    } catch {
        $extraEventRejected = $true
    }
    Assert-True $extraEventRejected 'Copilot live harness rejects unreviewed extra events'
    $ampBlockFixturePath = Join-Path $ampGoldenRoot 'pre_tool_block.json'
    $ampBlockFixtureText = [IO.File]::ReadAllText($ampBlockFixturePath)
    $ampBlockFixture = $ampBlockFixtureText | ConvertFrom-Json -ErrorAction Stop
    $ampActionPayloadPath = New-AmpHookPayloadOccurrence `
        -Payload $ampBlockFixturePath -IdentitySuffix 'action-block' `
        -OutputRoot (Join-Path $temp 'amp-hook-occurrences')
    $ampActionPayload = [IO.File]::ReadAllText($ampActionPayloadPath) |
        ConvertFrom-Json -ErrorAction Stop
    Assert-True ([string]$ampActionPayload.source_event_id -ceq
        "$([string]$ampBlockFixture.source_event_id):action-block" -and
        [string]$ampActionPayload.tool_call_id -ceq
        "$([string]$ampBlockFixture.tool_call_id)-action-block" -and
        [long]$ampActionPayload.source_sequence -eq
        ([long]$ampBlockFixture.source_sequence + 1000000) -and
        [string]$ampActionPayload.session_id -ceq [string]$ampBlockFixture.session_id -and
        [IO.File]::ReadAllText($ampBlockFixturePath) -ceq $ampBlockFixtureText) `
        'Amp action payload has a unique replay identity without mutating the golden fixture'
    $invalidAmpIdentityRejected = $false
    try {
        New-AmpHookPayloadOccurrence `
            -Payload $ampBlockFixturePath -IdentitySuffix '..\unsafe' `
            -OutputRoot (Join-Path $temp 'amp-hook-occurrences') | Out-Null
    } catch {
        $invalidAmpIdentityRejected = $_.Exception.Message -match 'invalid Amp hook identity suffix'
    }
    Assert-True $invalidAmpIdentityRejected 'Amp occurrence payload rejects unsafe identity suffixes'

    $safeRegistrationLocations = @(Get-DefenseClawRegistrationLocations @'
notify = ["C:\synthetic-private-path\DefenseClaw\bin\launcher.exe", "notify"]

[otel.exporter.otlp-http.headers]
x-defenseclaw-client = "synthetic-sensitive-value"

[mcp_servers.private-customer-name]
private-secret-name = "DefenseClaw must remain redacted"
'@)
    Assert-True (($safeRegistrationLocations -join '|') -ceq
        'line 1: notify|line 4: otel.exporter.otlp-http.headers.x-defenseclaw-client|line 7: other-table.other-field') `
        "connector residue diagnostics return only exact structural locations: $($safeRegistrationLocations -join '|')"
    Assert-True (($safeRegistrationLocations -join '|') -notmatch
        '(?i)synthetic-private-path|synthetic-sensitive-value|launcher\.exe|private-customer-name|private-secret-name') `
        'connector residue diagnostics do not disclose matched config values or private schema names'

    $savedDefenseClawHome = $env:DEFENSECLAW_HOME
    $savedResultsPath = $script:ResultsPath
    $savedAgentVersion = Get-Variable -Name AgentVersion -Scope Script -ErrorAction SilentlyContinue
    try {
        $script:ResultsPath = Join-Path $temp 'gateway-port-results.jsonl'
        $script:AgentVersion = 'harness-test'
        $gatewayPortCases = @(
            [pscustomobject]@{
                Name = 'fresh v8 config omits default gateway block'
                Body = "config_version: 8`nobservability: {}`n"
            },
            [pscustomobject]@{
                Name = 'existing gateway block omits default api port'
                Body = "config_version: 8`r`ngateway:`r`n  host: 127.0.0.1`r`nobservability: {}`r`n"
            },
            [pscustomobject]@{
                Name = 'legacy explicit gateway api port is replaced'
                Body = "config_version: 8`ngateway:`n  api_port: 18970`nobservability: {}`n"
            }
        )
        foreach ($case in $gatewayPortCases) {
            $caseRoot = Join-Path $temp ('gateway-port-' + ($case.Name -replace '[^A-Za-z0-9]+', '-'))
            Protect-TestDirectory $caseRoot
            $env:DEFENSECLAW_HOME = $caseRoot
            $casePath = Join-Path $caseRoot 'config.yaml'
            [IO.File]::WriteAllText($casePath, $case.Body, [Text.UTF8Encoding]::new($false))
            Set-IsolatedGatewayPort
            $updated = [IO.File]::ReadAllText($casePath)
            $ports = [regex]::Matches($updated, '(?m)^[ \t]*api_port:[ \t]*(\d+)[ \t]*(?=\r?$)')
            Assert-True ($ports.Count -eq 1) "$($case.Name) writes exactly one gateway api_port"
            $isolatedPort = [int]$ports[0].Groups[1].Value
            Assert-True ($isolatedPort -ge 1 -and $isolatedPort -le 65535) `
                "$($case.Name) writes a valid isolated port"
            Assert-True ([regex]::Matches($updated, '(?m)^gateway:[ \t]*(?=\r?$)').Count -eq 1) `
                "$($case.Name) preserves exactly one gateway block"
            $inspection = Invoke-NativeProcess `
                -FilePath $env:DEFENSECLAW_GATEWAY_BIN `
                -ArgumentList @(
                    'config-v8', 'effective',
                    '--config', $casePath,
                    '--data-dir', $caseRoot
                ) `
                -TimeoutSeconds 30 `
                -AllowedExitCodes @(0) `
                -LogPath (Join-Path $script:LogRoot (
                    'gateway-port-effective-' + ($case.Name -replace '[^A-Za-z0-9]+', '-') + '.log'
                ))
            $effective = $inspection.StdOut | ConvertFrom-Json -Depth 100
            Assert-True ($effective.gateway_api_port -eq $isolatedPort) `
                "$($case.Name) canonical effective config retains the isolated gateway port"
            $contractDestinations = @(
                $effective.effective.destinations |
                    Where-Object { $_.name -ceq 'windows-contract-jsonl' }
            )
            Assert-True ($contractDestinations.Count -eq 1) `
                "$($case.Name) writes exactly one explicit contract JSONL destination"
            Assert-True ($contractDestinations[0].kind -ceq 'jsonl') `
                "$($case.Name) writes a local JSONL destination"
            Assert-True ($contractDestinations[0].transport.path -ceq (
                Join-Path $caseRoot 'gateway.jsonl'
            )) "$($case.Name) roots JSONL evidence in the isolated profile"
        }
    } finally {
        $env:DEFENSECLAW_HOME = $savedDefenseClawHome
        $script:ResultsPath = $savedResultsPath
        if ($null -ne $savedAgentVersion) {
            $script:AgentVersion = $savedAgentVersion.Value
        } else {
            Remove-Variable -Name AgentVersion -Scope Script -ErrorAction SilentlyContinue
        }
    }

    $liveRoot = New-SyntheticProcessIdentity 100 '2026-07-15T00:10:00Z'
    Assert-SyntheticProcessTree @($liveRoot) @(
        (New-SyntheticProcessRow 100 1 '2026-07-15T00:10:00Z'),
        (New-SyntheticProcessRow 200 100 '2026-07-15T00:11:00Z'),
        (New-SyntheticProcessRow 201 200 '2026-07-15T00:12:00Z')
    ) @(200, 201) 'exact live parent identities preserve valid ancestry'

    $reusedParent = New-SyntheticProcessIdentity 200 '2026-07-15T00:11:00Z'
    Assert-SyntheticProcessTree @($reusedParent) @(
        (New-SyntheticProcessRow 200 999 '2026-07-15T00:20:00Z'),
        (New-SyntheticProcessRow 201 200 '2026-07-15T00:21:00Z')
    ) @() 'a reused parent PID cannot authorize a newer child'

    $exitedRoot = New-SyntheticProcessIdentity `
        100 '2026-07-15T00:10:00Z' '2026-07-15T00:15:00Z'
    Assert-SyntheticProcessTree @($exitedRoot) @(
        (New-SyntheticProcessRow 200 100 '2026-07-15T00:12:00Z'),
        (New-SyntheticProcessRow 201 200 '2026-07-15T00:13:00Z'),
        (New-SyntheticProcessRow 300 100 '2026-07-15T00:16:00Z')
    ) @(200, 201) 'an exited root expands only within its recorded lifetime'

    Assert-True ((Get-CodexVersionNumber 'codex-cli 0.124.0') -eq [Version]'0.124.0') `
        'Codex version parser accepts the pinned minimum client format'
    Assert-True (@(Get-CodexExpectedHookEvents ([Version]'0.124.0')).Count -eq 6) `
        'Codex 0.124.x contract exposes exactly six events'
    Assert-True (@(Get-CodexExpectedHookEvents ([Version]'0.129.0')).Count -eq 8) `
        'Codex 0.129.x contract exposes exactly eight events'
    Assert-True (@(Get-CodexExpectedHookEvents ([Version]'0.133.0')).Count -eq 10) `
        'Codex 0.133+ contract exposes the complete ten-event matrix'
    $codexSpecs = @(Get-CodexExpectedHookSpecs ([Version]'0.133.0'))
    $preToolSpec = @($codexSpecs | Where-Object Event -ceq 'preToolUse')
    $stopSpec = @($codexSpecs | Where-Object Event -ceq 'stop')
    Assert-True ($preToolSpec.Count -eq 1 -and $preToolSpec[0].Matcher -ceq '*' -and
        $preToolSpec[0].TimeoutSec -eq 30) 'Codex PreToolUse metadata requires broad matching and a 30s budget'
    Assert-True ($stopSpec.Count -eq 1 -and $null -eq $stopSpec[0].Matcher -and
        $stopSpec[0].TimeoutSec -eq 90) 'Codex Stop metadata requires no matcher and a 90s budget'
    $metadataConfig = [IO.Path]::GetFullPath((Join-Path $temp 'codex-metadata-managed_config.toml'))
    $metadataCommand = 'managed-codex-hook-command'
    $healthyMetadata = [pscustomobject]@{
        eventName = 'preToolUse'
        sourcePath = $metadataConfig
        handlerType = 'command'
        enabled = $true
        isManaged = $true
        source = 'legacyManagedConfigFile'
        command = $metadataCommand
        matcher = '*'
        timeoutSec = 30
        statusMessage = $null
        key = $metadataConfig + ':pre_tool_use:0:0'
        trustStatus = 'managed'
        currentHash = 'sha256:' + ('a' * 64)
    }
    Assert-CodexHookMetadata $healthyMetadata $preToolSpec[0] $metadataCommand $metadataConfig 'fixture' `
        ([Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal))
    foreach ($mutation in @(
        [pscustomobject]@{ Name = 'unmanaged hook'; Property = 'isManaged'; Value = $false },
        [pscustomobject]@{ Name = 'user source'; Property = 'source'; Value = 'user' },
        [pscustomobject]@{ Name = 'private trust state'; Property = 'trustStatus'; Value = 'trusted' },
        [pscustomobject]@{ Name = 'narrow matcher'; Property = 'matcher'; Value = 'Bash' },
        [pscustomobject]@{ Name = 'short timeout'; Property = 'timeoutSec'; Value = 1 },
        [pscustomobject]@{ Name = 'status override'; Property = 'statusMessage'; Value = 'tampered' }
    )) {
        $candidate = $healthyMetadata.PSObject.Copy()
        $candidate.($mutation.Property) = $mutation.Value
        $rejected = $false
        try {
            Assert-CodexHookMetadata $candidate $preToolSpec[0] $metadataCommand $metadataConfig 'fixture' `
                ([Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal))
        } catch {
            $rejected = $true
        }
        Assert-True $rejected "Codex metadata validator rejects $($mutation.Name)"
    }

    $originalUserProfile = [Environment]::GetEnvironmentVariable('USERPROFILE')
    $originalCodexHome = [Environment]::GetEnvironmentVariable('CODEX_HOME')
    $originalClaudeHome = [Environment]::GetEnvironmentVariable('CLAUDE_CONFIG_DIR')
    $originalCopilotHome = [Environment]::GetEnvironmentVariable('COPILOT_HOME')
    $originalCursorHome = [Environment]::GetEnvironmentVariable('DEFENSECLAW_CURSOR_CONFIG_HOME')
    $originalHermesHome = [Environment]::GetEnvironmentVariable('HERMES_HOME')
    $originalOpenCodeHome = [Environment]::GetEnvironmentVariable('OPENCODE_CONFIG_DIR')
    try {
        $resolverRoot = Join-Path $temp 'resolver-root'
        $resolverProfile = Join-Path $resolverRoot 'profile'
        $resolverCodexHome = Join-Path $resolverRoot 'codex-home'
        $resolverClaudeHome = Join-Path $resolverRoot 'claude-home'
        $resolverAmpHome = Join-Path $resolverProfile '.config\amp'
        $resolverCopilotHome = Join-Path $resolverRoot 'copilot-home'
        $resolverCursorHome = Join-Path $resolverProfile '.cursor'
        $resolverHermesHome = Join-Path $resolverRoot 'hermes-home'
        $resolverOpenCodeHome = Join-Path $resolverRoot 'opencode-home'
        foreach ($path in @(
            $resolverProfile,
            $resolverCodexHome,
            $resolverClaudeHome,
            $resolverAmpHome,
            $resolverCopilotHome,
            $resolverCursorHome,
            $resolverHermesHome,
            $resolverOpenCodeHome
        )) {
            [IO.Directory]::CreateDirectory($path) | Out-Null
        }
        $env:USERPROFILE = $resolverProfile
        $env:CODEX_HOME = $resolverCodexHome
        $env:CLAUDE_CONFIG_DIR = $resolverClaudeHome
        $env:COPILOT_HOME = $resolverCopilotHome
        $env:DEFENSECLAW_CURSOR_CONFIG_HOME = $resolverCursorHome
        $env:HERMES_HOME = $resolverHermesHome
        $env:OPENCODE_CONFIG_DIR = $resolverOpenCodeHome
        Assert-True ((Resolve-EffectiveConnectorHome codex).Equals(
            [IO.Path]::GetFullPath($resolverCodexHome),
            [StringComparison]::OrdinalIgnoreCase
        )) 'Codex effective home honors CODEX_HOME'
        Assert-True ((Resolve-EffectiveConnectorHome claudecode).Equals(
            [IO.Path]::GetFullPath($resolverClaudeHome),
            [StringComparison]::OrdinalIgnoreCase
        )) 'Claude effective home honors CLAUDE_CONFIG_DIR'
        Assert-True ((Resolve-EffectiveConnectorHome amp).Equals(
            [IO.Path]::GetFullPath($resolverAmpHome),
            [StringComparison]::OrdinalIgnoreCase
        )) 'Amp effective home uses the official Windows system-plugin directory'
        Assert-True ((Get-EffectiveConnectorConfigPath amp).Equals(
            [IO.Path]::GetFullPath((Join-Path $resolverAmpHome 'plugins\defenseclaw.ts')),
            [StringComparison]::OrdinalIgnoreCase
        )) 'Amp effective registration targets its native system plugin'
        Assert-PackagedConnectorHomes $resolverRoot $resolverProfile
        Assert-True ($env:CODEX_HOME -eq [IO.Path]::GetFullPath($resolverCodexHome) -and
            $env:CLAUDE_CONFIG_DIR -eq [IO.Path]::GetFullPath($resolverClaudeHome)) `
            'packaged connector home guard preserves exact installer-recorded homes'
        $env:DEFENSECLAW_CURSOR_CONFIG_HOME = Join-Path $resolverRoot 'spoofed-cursor-home'
        [IO.Directory]::CreateDirectory($env:DEFENSECLAW_CURSOR_CONFIG_HOME) | Out-Null
        $spoofedCursorHomeRejected = $false
        try { Assert-PackagedConnectorHomes $resolverRoot $resolverProfile }
        catch {
            $spoofedCursorHomeRejected = $_.Exception.Message.Contains(
                'documented USERPROFILE\.cursor path'
            )
        }
        Assert-True $spoofedCursorHomeRejected `
            'packaged connector home guard rejects a non-vendor Cursor home override'
        $env:DEFENSECLAW_CURSOR_CONFIG_HOME = $resolverCursorHome
        $env:CODEX_HOME = Join-Path $temp 'operator-codex-home'
        [IO.Directory]::CreateDirectory($env:CODEX_HOME) | Out-Null
        $escapedHomeRejected = $false
        try { Assert-PackagedConnectorHomes $resolverRoot $resolverProfile }
        catch { $escapedHomeRejected = $_.Exception.Message -match 'strict children of StateRoot' }
        Assert-True $escapedHomeRejected 'packaged connector home guard rejects an operator path outside StateRoot'
        Remove-Item Env:CODEX_HOME -ErrorAction SilentlyContinue
        Remove-Item Env:CLAUDE_CONFIG_DIR -ErrorAction SilentlyContinue
        Assert-True ((Resolve-EffectiveConnectorHome codex).Equals(
            [IO.Path]::GetFullPath((Join-Path $resolverProfile '.codex')),
            [StringComparison]::OrdinalIgnoreCase
        )) 'Codex effective home falls back to the isolated OS profile'
        Assert-True ((Resolve-EffectiveConnectorHome claudecode).Equals(
            [IO.Path]::GetFullPath((Join-Path $resolverProfile '.claude')),
            [StringComparison]::OrdinalIgnoreCase
        )) 'Claude effective home falls back to the isolated OS profile'
        Assert-True ((Resolve-EffectiveConnectorHome amp).Equals(
            [IO.Path]::GetFullPath($resolverAmpHome),
            [StringComparison]::OrdinalIgnoreCase
        )) 'Amp effective home remains bound to the isolated OS profile'
    } finally {
        [Environment]::SetEnvironmentVariable('USERPROFILE', $originalUserProfile)
        [Environment]::SetEnvironmentVariable('CODEX_HOME', $originalCodexHome)
        [Environment]::SetEnvironmentVariable('CLAUDE_CONFIG_DIR', $originalClaudeHome)
        [Environment]::SetEnvironmentVariable('COPILOT_HOME', $originalCopilotHome)
        [Environment]::SetEnvironmentVariable(
            'DEFENSECLAW_CURSOR_CONFIG_HOME', $originalCursorHome
        )
        [Environment]::SetEnvironmentVariable('HERMES_HOME', $originalHermesHome)
        [Environment]::SetEnvironmentVariable('OPENCODE_CONFIG_DIR', $originalOpenCodeHome)
    }
    . $nativePathHelpers
    $disjointRoots = @(Assert-WindowsNativePathsDisjoint @(
        (Join-Path $temp 'disjoint-profile'),
        (Join-Path $temp 'disjoint-codex'),
        (Join-Path $temp 'disjoint-claude')
    ))
    Assert-True ($disjointRoots.Count -eq 3) 'pairwise-disjoint root validation returns every normalized root'
    $equalRootsError = $null
    try {
        $null = Assert-WindowsNativePathsDisjoint @(
            (Join-Path $temp 'same'),
            (Join-Path $temp 'same')
        )
    } catch { $equalRootsError = $_.Exception.Message }
    Assert-True ($equalRootsError -match '^Windows-native roots must be pairwise non-equal and non-nested:') `
        'pairwise-disjoint root validation rejects equal roots with the expected diagnostic'
    $nestedRootsError = $null
    try {
        $null = Assert-WindowsNativePathsDisjoint @(
            (Join-Path $temp 'parent'),
            (Join-Path $temp 'parent\child')
        )
    } catch { $nestedRootsError = $_.Exception.Message }
    Assert-True ($nestedRootsError -match '^Windows-native roots must be pairwise non-equal and non-nested:') `
        'pairwise-disjoint root validation rejects nested roots with the expected diagnostic'

    $privateRoot = Join-Path $temp 'private-state'
    Protect-TestDirectory $privateRoot
    $private = Join-Path $privateRoot 'connector_backups\codex'
    Protect-TestDirectory $private
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $security = [IO.FileSystemAclExtensions]::GetAccessControl([IO.DirectoryInfo]::new($private))
    $owner = $security.GetOwner([Security.Principal.SecurityIdentifier])
    Assert-True ($owner.Equals($identity.User)) 'private fixture owner is the current user'
    Assert-True $security.AreAccessRulesProtected 'private fixture does not inherit the workspace ACL'
    $system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $administrators = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $rules = $security.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])
    $seenUser = $false
    $seenSystem = $false
    $seenAdministrators = $false
    foreach ($rule in $rules) {
        Assert-True ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow) "private fixture contains non-allow ACE for $($rule.IdentityReference)"
        $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier])
        Assert-True ($sid.Equals($identity.User) -or $sid.Equals($system) -or
            $sid.Equals($administrators)) "private fixture trusts unexpected principal $sid"
        if ($sid.Equals($identity.User)) { $seenUser = $true }
        if ($sid.Equals($system)) { $seenSystem = $true }
        if ($sid.Equals($administrators)) { $seenAdministrators = $true }
    }
    Assert-True ($seenUser -and $seenSystem -and $seenAdministrators) `
        'private fixture must grant only the current user, SYSTEM, and Administrators'

    $savedLayer = $Layer
    $savedConnector = $Connector
    $savedStateRoot = $StateRoot
    $savedPath = $env:PATH
    $savedContractHookTool = Get-Variable -Name ContractHookTool -Scope Script -ErrorAction SilentlyContinue
    try {
        $fakeBin = Join-Path $temp 'contract-hook-source'
        [IO.Directory]::CreateDirectory($fakeBin) | Out-Null
        $fakeHook = Join-Path $fakeBin 'defenseclaw-hook.exe'
        [IO.File]::WriteAllBytes($fakeHook, [byte[]](0..255))
        $env:PATH = $fakeBin + [IO.Path]::PathSeparator + $env:PATH
        $Layer = 'contract'
        $Connector = 'amp'
        $StateRoot = Join-Path $temp 'contract-hook-state'
        Protect-TestDirectory $StateRoot
        $script:ContractHookTool = ''

        $contractHook = Resolve-ContractHookTool

        Assert-True ([IO.Path]::GetFileName($contractHook) -ceq
            'defenseclaw-hook-contract.exe') `
            'Amp source-build contract stages a deliberately non-canonical hook launcher'
        Assert-True ((Get-FileHash -LiteralPath $contractHook -Algorithm SHA256).Hash -ceq
            (Get-FileHash -LiteralPath $fakeHook -Algorithm SHA256).Hash) `
            'Amp source-build contract launcher preserves the exact selected hook bytes'
        $contractInfo = Get-Item -LiteralPath $contractHook -Force
        Assert-True (-not ($contractInfo.Attributes -band [IO.FileAttributes]::ReparsePoint)) `
            'Amp source-build contract launcher is not a reparse point'

        $dangerousPayloadRoot = Join-Path $StateRoot 'dangerous-payload-identity'
        [IO.Directory]::CreateDirectory($dangerousPayloadRoot) | Out-Null
        $observePayload = [IO.File]::ReadAllText((
            New-DangerousCommandPayload 'fixture' 'synthetic command' $dangerousPayloadRoot observe
        )) | ConvertFrom-Json
        $actionPayload = [IO.File]::ReadAllText((
            New-DangerousCommandPayload 'fixture' 'synthetic command' $dangerousPayloadRoot action
        )) | ConvertFrom-Json
        foreach ($identityField in @(
            'turn_id',
            'message_id',
            'source_event_id',
            'source_sequence',
            'tool_call_id'
        )) {
            Assert-True (
                [string]$observePayload.$identityField -cne
                    [string]$actionPayload.$identityField
            ) "observe/action dangerous fixtures have distinct $identityField values"
        }

        $Connector = 'codex'
        $codexObservePayload = [IO.File]::ReadAllText((
            New-DangerousCommandPayload 'fixture' 'synthetic command' $dangerousPayloadRoot observe
        )) | ConvertFrom-Json
        $codexActionPayload = [IO.File]::ReadAllText((
            New-DangerousCommandPayload 'fixture' 'synthetic command' $dangerousPayloadRoot action
        )) | ConvertFrom-Json
        Assert-True ([string]$codexObservePayload.tool_call_id -ceq
            [string]$codexObservePayload.tool_use_id) `
            'Codex dangerous fixture aliases identify one observe invocation'
        Assert-True ([string]$codexActionPayload.tool_call_id -ceq
            [string]$codexActionPayload.tool_use_id) `
            'Codex dangerous fixture aliases identify one action invocation'
        Assert-True ([string]$codexObservePayload.tool_use_id -cne
            [string]$codexActionPayload.tool_use_id) `
            'Codex observe/action dangerous fixtures retain distinct tool identities'
    } finally {
        $Layer = $savedLayer
        $Connector = $savedConnector
        $StateRoot = $savedStateRoot
        $env:PATH = $savedPath
        if ($null -eq $savedContractHookTool) {
            Remove-Variable -Name ContractHookTool -Scope Script -ErrorAction SilentlyContinue
        } else {
            $script:ContractHookTool = $savedContractHookTool.Value
        }
    }

    $pwsh = (Get-Process -Id $PID).Path
    $originalNativeBase = [Environment]::GetEnvironmentVariable('DC_WINDOWS_NATIVE_BASE_ROOT')
    try {
        # The native self-test validates and rebinds its own base after it
        # creates an isolated USERPROFILE. Do not leak the workflow's real-
        # profile base into that child; restore it before the outer path-gate
        # tests below exercise the workflow contract.
        Remove-Item Env:DC_WINDOWS_NATIVE_BASE_ROOT -ErrorAction SilentlyContinue
        $profileTest = Invoke-NativeProcess -FilePath $pwsh -ArgumentList @(
            '-NoProfile', '-File', $nativeHarness, '-Operation', 'self-test',
            '-StateRoot', (Join-Path $temp 'isolated-profile')
        ) -TimeoutSeconds 90
    } finally {
        [Environment]::SetEnvironmentVariable(
            'DC_WINDOWS_NATIVE_BASE_ROOT',
            $originalNativeBase
        )
    }
    Assert-True ($profileTest.ExitCode -eq 0 -and $profileTest.StdOut -match 'self-test passed') 'disposable Windows profile and PATH isolation'

    $originalGithubActions = [Environment]::GetEnvironmentVariable('GITHUB_ACTIONS')
    $originalRunnerEnvironment = [Environment]::GetEnvironmentVariable('RUNNER_ENVIRONMENT')
    $originalRunnerTemp = [Environment]::GetEnvironmentVariable('RUNNER_TEMP')
    $wizardApprovedRoot = $null
    try {
        $broadNativeBase = [Environment]::GetFolderPath(
            [Environment+SpecialFolder]::UserProfile
        )
        $approvedNativeBase = Join-Path $broadNativeBase '.dc-ci'
        $shortNativeRoot = Join-Path $approvedNativeBase 'ct-claudecode'
        Assert-True ($shortNativeRoot.Length -le 48) `
            'worst-case native connector root preserves the linker path budget'
        $env:DC_WINDOWS_NATIVE_BASE_ROOT = $approvedNativeBase
        $approvedBaseResult = Invoke-NativeProcess -FilePath $pwsh -ArgumentList @(
            '-NoProfile', '-File', $nativeHarness, '-Operation', 'cleanup',
            '-StateRoot', $shortNativeRoot
        ) -TimeoutSeconds 15
        Assert-True ($approvedBaseResult.ExitCode -eq 0) `
            'native cleanup accepts a short state root below its explicit user-profile base'

        $env:GITHUB_ACTIONS = 'true'
        $env:RUNNER_ENVIRONMENT = 'github-hosted'
        $env:RUNNER_TEMP = Join-Path $temp 'runner-temp'
        [IO.Directory]::CreateDirectory($env:RUNNER_TEMP) | Out-Null
        $wizardApprovedRoot = Join-Path $approvedNativeBase (
            'wizard-root-gate-' + [guid]::NewGuid().ToString('N')
        )
        $approvedWizardResult = Invoke-NativeProcess -FilePath $pwsh -ArgumentList @(
            '-NoProfile', '-File', $wizardHarness,
            '-SetupPath', $pwsh,
            '-StateRoot', $wizardApprovedRoot,
            '-ActivateInstall',
            '-InteropSelfTestOnly'
        ) -TimeoutSeconds 15
        Assert-True ($approvedWizardResult.ExitCode -eq 0 -and
            ($approvedWizardResult.StdOut | ConvertFrom-Json).unicode_window_text -eq 'pass') `
            'install-driving wizard accepts state below the explicit user-profile base'

        $equalBaseWizardResult = Invoke-NativeProcess -FilePath $pwsh -ArgumentList @(
            '-NoProfile', '-File', $wizardHarness,
            '-SetupPath', $pwsh,
            '-StateRoot', $approvedNativeBase,
            '-ActivateInstall',
            '-InteropSelfTestOnly'
        ) -TimeoutSeconds 15 -AllowedExitCodes @(1)
        Assert-True ($equalBaseWizardResult.StdErr -match
            'must be a child of RUNNER_TEMP or DC_WINDOWS_NATIVE_BASE_ROOT') `
            'install-driving wizard rejects equality with its multi-job approved base'

        $outsideApprovedRoots = Join-Path $temp 'wizard-outside-approved-roots'
        $outsideWizardResult = Invoke-NativeProcess -FilePath $pwsh -ArgumentList @(
            '-NoProfile', '-File', $wizardHarness,
            '-SetupPath', $pwsh,
            '-StateRoot', $outsideApprovedRoots,
            '-ActivateInstall',
            '-InteropSelfTestOnly'
        ) -TimeoutSeconds 15 -AllowedExitCodes @(1)
        Assert-True ($outsideWizardResult.StdErr -match
            'must be a child of RUNNER_TEMP or DC_WINDOWS_NATIVE_BASE_ROOT') `
            'install-driving wizard rejects state outside both approved roots'

        $env:DC_WINDOWS_NATIVE_BASE_ROOT = $broadNativeBase
        $broadBaseResult = Invoke-NativeProcess -FilePath $pwsh -ArgumentList @(
            '-NoProfile', '-File', $nativeHarness, '-Operation', 'cleanup',
            '-StateRoot', (Join-Path $temp 'broad-base-rejection')
        ) -TimeoutSeconds 15 -AllowedExitCodes @(1)
        Assert-True ($broadBaseResult.StdErr -match
            'DC_WINDOWS_NATIVE_BASE_ROOT must be a strict child of the current user''s profile') `
            'native cleanup rejects an explicit base as broad as the user profile'

        $broadWizardResult = Invoke-NativeProcess -FilePath $pwsh -ArgumentList @(
            '-NoProfile', '-File', $wizardHarness,
            '-SetupPath', $pwsh,
            '-StateRoot', (Join-Path $temp 'broad-wizard-base-rejection'),
            '-ActivateInstall',
            '-InteropSelfTestOnly'
        ) -TimeoutSeconds 15 -AllowedExitCodes @(1)
        Assert-True ($broadWizardResult.StdErr -match
            'DC_WINDOWS_NATIVE_BASE_ROOT must be a strict child of the current user''s profile') `
            'install-driving wizard rejects an explicit base as broad as the user profile'
    } finally {
        if (-not [string]::IsNullOrWhiteSpace($wizardApprovedRoot)) {
            Remove-Item -LiteralPath $wizardApprovedRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
        [Environment]::SetEnvironmentVariable(
            'DC_WINDOWS_NATIVE_BASE_ROOT',
            $originalNativeBase
        )
        [Environment]::SetEnvironmentVariable('GITHUB_ACTIONS', $originalGithubActions)
        [Environment]::SetEnvironmentVariable('RUNNER_ENVIRONMENT', $originalRunnerEnvironment)
        [Environment]::SetEnvironmentVariable('RUNNER_TEMP', $originalRunnerTemp)
    }

    $unicodeInterop = Invoke-NativeProcess -FilePath $pwsh -ArgumentList @(
        '-NoProfile', '-File', $wizardHarness,
        '-SetupPath', $pwsh,
        '-StateRoot', (Join-Path $temp 'wizard-unicode-interop'),
        '-InteropSelfTestOnly'
    ) -TimeoutSeconds 15
    $unicodeInteropResult = $unicodeInterop.StdOut | ConvertFrom-Json
    Assert-True ($unicodeInterop.ExitCode -eq 0 -and
        $unicodeInteropResult.unicode_window_text -eq 'pass') `
        'bounded wizard interop round-trips Unicode window text'

    $allow = Invoke-NativeProcess -FilePath $pwsh -ArgumentList @('-NoProfile', '-File', $mock, '-Action', 'allow') -TimeoutSeconds 5
    Assert-True ($allow.ExitCode -eq 0 -and $allow.StdOut -match 'allow') 'mock allow decision'

    $block = Invoke-NativeProcess -FilePath $pwsh -ArgumentList @('-NoProfile', '-File', $mock, '-Action', 'block') -TimeoutSeconds 5 -AllowedExitCodes @(2)
    Assert-True ($block.ExitCode -eq 2 -and $block.StdOut -match 'block') 'mock block decision'

    $healthyOutput = [Threading.Tasks.TaskCompletionSource[string]]::new()
    $healthyOutput.SetResult('complete')
    $faultedOutput = [Threading.Tasks.TaskCompletionSource[string]]::new()
    $faultedOutput.SetException([IO.IOException]::new('injected output read failure'))
    Assert-True (Test-RedirectedOutputTasksHealthy $healthyOutput.Task $healthyOutput.Task) `
        'completed redirected output tasks are healthy'
    Assert-True (-not (Test-RedirectedOutputTasksHealthy $faultedOutput.Task $healthyOutput.Task)) `
        'faulted redirected output is classified as a harness failure'

    $missingInputRoot = Join-Path $temp 'missing-input-preflight'
    [IO.Directory]::CreateDirectory($missingInputRoot) | Out-Null
    $missingInputRejected = $false
    try {
        Invoke-NativeProcess -FilePath $pwsh -ArgumentList @(
            '-NoProfile', '-File', $mock, '-Action', 'child', '-StateRoot', $missingInputRoot
        ) -InputPath (Join-Path $missingInputRoot 'missing.json') -TimeoutSeconds 2 | Out-Null
    } catch {
        $missingInputRejected = $_.Exception.Message -match 'Cannot find path'
    }
    Assert-True $missingInputRejected 'missing stdin payload is rejected before process start'

    $oversizedInput = Join-Path $temp 'oversized-input.bin'
    [IO.File]::WriteAllBytes($oversizedInput, [byte[]]::new(1048577))
    $oversizedInputRejected = $false
    try {
        Invoke-NativeProcess -FilePath $pwsh -ArgumentList @(
            '-NoProfile', '-File', $mock, '-Action', 'child', '-StateRoot', $missingInputRoot
        ) -InputPath $oversizedInput -TimeoutSeconds 2 | Out-Null
    } catch {
        $oversizedInputRejected = $_.Exception.Message -match 'exceeds the 1 MiB limit'
    }
    Assert-True $oversizedInputRejected 'oversized stdin payload is rejected before process start'

    $blockedInputRoot = Join-Path $temp 'blocked-stdin'
    [IO.Directory]::CreateDirectory($blockedInputRoot) | Out-Null
    $blockedInput = Join-Path $blockedInputRoot 'payload.bin'
    [IO.File]::WriteAllBytes($blockedInput, [byte[]]::new(1048576))
    $blockedInputTimedOut = $false
    $blockedInputStopwatch = [Diagnostics.Stopwatch]::StartNew()
    try {
        Invoke-NativeProcess -FilePath $pwsh -ArgumentList @(
            '-NoProfile', '-File', $mock, '-Action', 'child', '-StateRoot', $blockedInputRoot
        ) -InputPath $blockedInput -TimeoutSeconds 2 | Out-Null
    } catch {
        $blockedInputTimedOut = $_.Exception.Message -match 'timed out after 2s'
    } finally {
        $blockedInputStopwatch.Stop()
    }
    Assert-True $blockedInputTimedOut 'non-reading child cannot block stdin beyond the process deadline'
    Assert-True ($blockedInputStopwatch.Elapsed -lt [TimeSpan]::FromSeconds(10)) `
        'stdin timeout cleanup is bounded'
    $blockedInputLeaks = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
        $_.CommandLine -and
        $_.CommandLine.IndexOf($mock, [StringComparison]::OrdinalIgnoreCase) -ge 0 -and
        $_.CommandLine.IndexOf($blockedInputRoot, [StringComparison]::OrdinalIgnoreCase) -ge 0
    })
    Assert-True ($blockedInputLeaks.Count -eq 0) 'stdin timeout left no matching process alive'

    $payloadPath = Join-Path $temp 'hook-payload.json'
    $payload = '{"hook":"stdin-sentinel"}'
    [IO.File]::WriteAllText($payloadPath, $payload)
    $stdin = Invoke-Tool 'pwsh' @('-NoProfile', '-File', $mock, '-Action', 'stdin') @(0) -InputPath $payloadPath
    Assert-True ($stdin.StdOut.Trim() -eq $payload) 'Invoke-Tool forwards the payload file to native stdin'

    $whileRunningMarker = Join-Path $temp 'while-running.marker'
    $whileRunning = {
        param([Diagnostics.Process]$ChildProcess)
        if ($ChildProcess.HasExited) { throw 'callback did not observe the running child' }
        $observations = 0
        while (-not $ChildProcess.HasExited) {
            $observations++
            Start-Sleep -Milliseconds 25
        }
        [IO.File]::WriteAllText($whileRunningMarker, [string]$observations)
    }
    Invoke-NativeProcess -FilePath $pwsh -ArgumentList @(
        '-NoProfile', '-Command', 'Start-Sleep -Milliseconds 250'
    ) -TimeoutSeconds 10 -WhileRunning $whileRunning | Out-Null
    Assert-True ([int][IO.File]::ReadAllText($whileRunningMarker) -gt 1) `
        'native process keeps its bounded concurrent readiness callback attached until the child exits'

    [Environment]::SetEnvironmentVariable('DC_E2E_TEST_SECRET', ('unit-test-' + 'sensitive-value'))
    $secret = Invoke-NativeProcess -FilePath $pwsh -ArgumentList @('-NoProfile', '-File', $mock, '-Action', 'secret') -TimeoutSeconds 5
    Assert-True ($secret.StdOut -notmatch 'unit-test-sensitive-value' -and $secret.StdOut -match 'REDACTED') 'secret redaction'
    Remove-Item Env:DC_E2E_TEST_SECRET

    $timedOut = $false
    try {
        Invoke-NativeProcess -FilePath $pwsh -ArgumentList @('-NoProfile', '-File', $mock, '-Action', 'timeout', '-StateRoot', $temp) -TimeoutSeconds 8 | Out-Null
    } catch { $timedOut = $_.Exception.Message -match 'timed out' }
    Assert-True $timedOut 'bounded timeout returns failure'
    Start-Sleep -Milliseconds 500
    $childPidPath = Join-Path $temp 'child.pid'
    Assert-True (Test-Path -LiteralPath $childPidPath) 'mock timeout child started'
    $childPid = [int][IO.File]::ReadAllText($childPidPath)
    Assert-True ($null -eq (Get-Process -Id $childPid -ErrorAction SilentlyContinue)) 'timeout killed the process tree'

    $unrelatedRoot = Join-Path $temp 'unrelated-process'
    $drainRoot = Join-Path $temp 'drain-timeout'
    [IO.Directory]::CreateDirectory($unrelatedRoot) | Out-Null
    [IO.Directory]::CreateDirectory($drainRoot) | Out-Null
    $unrelated = Start-Process -FilePath $pwsh -ArgumentList @(
        '-NoProfile', '-File', $mock, '-Action', 'child', '-StateRoot', $unrelatedRoot
    ) -PassThru -WindowStyle Hidden
    try {
        $unrelatedStarted = $unrelated.StartTime.ToUniversalTime()
        $drainTimedOut = $false
        $drainStopwatch = [Diagnostics.Stopwatch]::StartNew()
        try {
            Invoke-NativeProcess -FilePath $pwsh -ArgumentList @(
                '-NoProfile', '-File', $mock, '-Action', 'drain-timeout', '-StateRoot', $drainRoot
            ) -TimeoutSeconds 2 | Out-Null
        } catch {
            $drainTimedOut = $_.Exception.Message -match 'timed out after 2s'
        } finally {
            $drainStopwatch.Stop()
        }
        Assert-True $drainTimedOut 'inherited redirected handles consume the same bounded timeout'
        Assert-True ($drainStopwatch.Elapsed -lt [TimeSpan]::FromSeconds(10)) `
            'inherited-handle timeout and exact tree cleanup are bounded'
        $drainChildPidPath = Join-Path $drainRoot 'drain-child.pid'
        Assert-True (Test-Path -LiteralPath $drainChildPidPath -PathType Leaf) `
            'inherited-handle timeout child started'
        $drainChildPid = [int][IO.File]::ReadAllText($drainChildPidPath)
        Assert-True ($null -eq (Get-Process -Id $drainChildPid -ErrorAction SilentlyContinue)) `
            'inherited-handle timeout killed its exact descendant'
        $unrelatedLive = Get-Process -Id $unrelated.Id -ErrorAction SilentlyContinue
        Assert-True ($null -ne $unrelatedLive -and
            [Math]::Abs(($unrelatedLive.StartTime.ToUniversalTime() - $unrelatedStarted).TotalMilliseconds) -lt 1) `
            'timeout tree cleanup preserved an unrelated same-image process'
    } finally {
        Stop-Process -Id $unrelated.Id -Force -ErrorAction SilentlyContinue
        $unrelated.Dispose()
    }

    $unrelatedDescendant = Start-Process -FilePath $pwsh -ArgumentList @(
        '-NoProfile', '-Command', 'Start-Sleep -Seconds 30'
    ) -PassThru -WindowStyle Hidden
    $originalStateRoot = $StateRoot
    $cleanupFixtureStateRoot = Join-Path $temp 'cleanup-fixture'
    $StateRoot = $cleanupFixtureStateRoot
    $ownedRoot = Join-Path $StateRoot 'cleanup-owned-process'
    [IO.Directory]::CreateDirectory($ownedRoot) | Out-Null
    $argvOwnedDescendant = Start-Process -FilePath $pwsh -ArgumentList @(
        '-NoProfile', '-File', $mock, '-Action', 'child', '-StateRoot', $ownedRoot
    ) -PassThru -WindowStyle Hidden
    $productExecutable = (Get-Command ping.exe -CommandType Application -ErrorAction Stop).Source
    $productDescendant = Start-Process -FilePath $productExecutable -ArgumentList @(
        '-t', '127.0.0.1'
    ) -WorkingDirectory $ownedRoot -Environment @{
        DEFENSECLAW_HOME = $ownedRoot
    } -PassThru -WindowStyle Hidden
    try {
        $argvOwnedReady = $false
        $argvOwnedStopwatch = [Diagnostics.Stopwatch]::StartNew()
        try {
            do {
                $argvOwnedRows = @(Get-CimInstance Win32_Process `
                    -Filter "ProcessId = $($argvOwnedDescendant.Id)" `
                    -ErrorAction SilentlyContinue)
                $argvOwnedCommandLine = if ($argvOwnedRows.Count -eq 1) {
                    [string]$argvOwnedRows[0].CommandLine
                } else {
                    ''
                }
                $argvOwnedReady =
                    -not [string]::IsNullOrWhiteSpace($argvOwnedCommandLine) -and
                    $argvOwnedCommandLine.IndexOf(
                        [IO.Path]::GetFullPath($StateRoot),
                        [StringComparison]::OrdinalIgnoreCase
                    ) -ge 0
                if ($argvOwnedReady) { break }
                Start-Sleep -Milliseconds 100
            } while ($argvOwnedStopwatch.Elapsed -lt [TimeSpan]::FromSeconds(5))
        } finally {
            $argvOwnedStopwatch.Stop()
        }
        if (-not $argvOwnedReady) {
            throw 'isolated cleanup fixture setup failed: exact argv-owned process and StateRoot were not queryable within 5 seconds'
        }

        $expectedProductExecutable = Get-NormalizedExecutablePath $productExecutable
        $productStartIdentity = ''
        $productLiveExecutable = ''
        $productIdentityReady = $false
        $productIdentityStopwatch = [Diagnostics.Stopwatch]::StartNew()
        try {
            do {
                $productProbe = $null
                try {
                    $productProbe = [Diagnostics.Process]::GetProcessById($productDescendant.Id)
                    $productLiveExecutable = Get-NormalizedExecutablePath `
                        ([string]$productProbe.MainModule.FileName)
                    $productStartIdentity = Get-NativeProcessStartIdentity $productProbe
                } catch {
                    $productLiveExecutable = ''
                    $productStartIdentity = ''
                } finally {
                    if ($null -ne $productProbe) { $productProbe.Dispose() }
                }
                $productIdentityReady =
                    -not [string]::IsNullOrWhiteSpace($productStartIdentity) -and
                    [string]::Equals(
                        $productLiveExecutable,
                        $expectedProductExecutable,
                        [StringComparison]::OrdinalIgnoreCase
                    )
                if ($productIdentityReady) { break }
                Start-Sleep -Milliseconds 100
            } while ($productIdentityStopwatch.Elapsed -lt [TimeSpan]::FromSeconds(5))
        } finally {
            $productIdentityStopwatch.Stop()
        }
        if (-not $productIdentityReady) {
            throw 'managed cleanup fixture setup failed: matching executable and nonempty start identity were not queryable within 5 seconds'
        }
        $productPID = @{
            pid = $productDescendant.Id
            executable = $productExecutable
            start_identity = $productStartIdentity
        } | ConvertTo-Json -Compress
        [IO.File]::WriteAllText((Join-Path $ownedRoot 'gateway.pid'), $productPID)
        Stop-IsolatedProcessTree -ProductExecutablePaths @($productExecutable) `
            -ProductDataRoot $ownedRoot -Confirm:$false
        Assert-True ($argvOwnedDescendant.WaitForExit(5000)) `
            'isolated cleanup killed a process with StateRoot on argv'
        Assert-True ($productDescendant.WaitForExit(5000)) `
            'isolated cleanup killed the exact managed product process without StateRoot on argv'
        Assert-True (-not $unrelatedDescendant.HasExited) `
            'isolated cleanup preserved a descendant without StateRoot in its command line'
    } finally {
        Stop-Process -Id $unrelatedDescendant.Id -Force -ErrorAction SilentlyContinue
        Stop-Process -Id $argvOwnedDescendant.Id -Force -ErrorAction SilentlyContinue
        Stop-Process -Id $productDescendant.Id -Force -ErrorAction SilentlyContinue
        $unrelatedDescendant.Dispose()
        $argvOwnedDescendant.Dispose()
        $productDescendant.Dispose()
        $StateRoot = $originalStateRoot
        if (Test-Path -LiteralPath $cleanupFixtureStateRoot) {
            Remove-Item -LiteralPath $cleanupFixtureStateRoot -Recurse -Force
        }
    }

    $jsonl = Join-Path $temp 'gateway.jsonl'
    $database = Join-Path $temp 'audit.db'
    $requestId = [guid]::NewGuid().ToString()
    $sessionId = 'windows-contract-session'
    $hookEvent = 'PreToolUse'
    $toolInvocationId = 'windows-contract-tool'
    $observedAt = [DateTime]::UtcNow.ToString('o')
    $provenance = [ordered]@{
        producer = 'defenseclaw'
        binary_version = '0.8.6-test'
        registry_schema_version = 1
        config_generation = 1
    }
    $fixtureEvents = @(
        [ordered]@{
            schema_version = 1; bucket_catalog_version = 1; timestamp = $observedAt
            record_id = 'windows-contract-verdict'; bucket = 'asset.scan'; signal = 'logs'
            event_name = 'scan.completed'; source = 'scanner'; connector = 'codex'
            correlation = @{
                request_id = $requestId; session_id = $sessionId
                tool_invocation_id = $toolInvocationId
            }; provenance = $provenance; field_classes = @{}
            mandatory = $false
            body = @{
                'defenseclaw.scan.verdict' = 'block'
            }
        },
        [ordered]@{
            schema_version = 1; bucket_catalog_version = 1; timestamp = $observedAt
            record_id = 'windows-contract-hook-decision'; bucket = 'guardrail.evaluation'; signal = 'logs'
            event_name = 'hook_decision'; source = 'connector'; connector = 'codex'
            correlation = @{
                request_id = $requestId; session_id = $sessionId
                tool_invocation_id = $toolInvocationId
            }; provenance = $provenance; field_classes = @{}
            mandatory = $false
            body = @{
                'defenseclaw.guardrail.effective_action' = 'allow'
                'defenseclaw.guardrail.raw_action' = 'block'
                'defenseclaw.guardrail.mode' = 'observe'
                'defenseclaw.guardrail.would_block' = $true
                'defenseclaw.guardrail.enforced' = $false
                'defenseclaw.guardrail.rule_ids' = @('CMD-WIN-REMOVE-ITEM-RF')
                'defenseclaw.hook.event' = $hookEvent
            }
        },
        [ordered]@{
            schema_version = 1; bucket_catalog_version = 1; timestamp = $observedAt
            record_id = 'windows-contract-tool'; bucket = 'tool.activity'; signal = 'logs'
            event_name = 'tool.invocation.requested'; source = 'connector'; connector = 'codex'
            correlation = @{
                request_id = $requestId; session_id = $sessionId
                tool_invocation_id = $toolInvocationId
            }; provenance = $provenance; field_classes = @{}
            mandatory = $false; body = @{}
        },
        [ordered]@{
            schema_version = 1; bucket_catalog_version = 1; timestamp = $observedAt
            record_id = 'windows-contract-decoy'; bucket = 'diagnostic'; signal = 'logs'
            event_name = 'event'; source = 'gateway'; connector = 'cursor'
            correlation = @{}; provenance = $provenance; field_classes = @{}
            mandatory = $false; body = @{ note = 'claudecode' }
        },
        [ordered]@{
            schema_version = 1; bucket_catalog_version = 1; timestamp = $observedAt
            record_id = 'windows-contract-invalid-scan-verdict'; bucket = 'asset.scan'; signal = 'logs'
            event_name = 'scan.completed'; source = 'scanner'; connector = 'codex'
            correlation = @{ request_id = $requestId }; provenance = $provenance; field_classes = @{}
            mandatory = $false; body = @{ 'defenseclaw.scan.verdict' = 'deny' }
        }
    ) | ForEach-Object { $_ | ConvertTo-Json -Depth 8 -Compress }
    [IO.File]::WriteAllText($jsonl, ($fixtureEvents -join [Environment]::NewLine) + [Environment]::NewLine)
    $liveWriter = [IO.File]::Open($jsonl, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::ReadWrite)
    try {
        $sharedText = Read-SharedText $jsonl
        Assert-True ($sharedText -match 'hook_decision') 'diagnostics can read a live writer-owned JSONL'
        Assert-True (@(Get-EventLines $jsonl).Count -eq 5) 'gateway JSONL remains readable while the gateway writer is open'
    } finally {
        $liveWriter.Dispose()
    }
    $pythonCode = @'
import hashlib
import json
import sqlite3
import sys

database, source = sys.argv[1:]
connection = sqlite3.connect(database)
connection.execute("PRAGMA journal_mode=WAL")
connection.execute(
    """CREATE TABLE audit_events (
           id TEXT, bucket TEXT, event_name TEXT, source TEXT, signal TEXT,
           connector TEXT, request_id TEXT, session_id TEXT, turn_id TEXT,
           record_schema_version INTEGER, payload_json TEXT,
           projected_record_json TEXT, projection_hash TEXT
       )"""
)
with open(source, encoding="utf-8") as stream:
    for raw in stream:
        if not raw.strip():
            continue
        event = json.loads(raw)
        correlation = event.get("correlation") or {}
        connection.execute(
            """INSERT INTO audit_events
                   (id, bucket, event_name, source, signal, connector,
                    request_id, session_id, turn_id, record_schema_version,
                    payload_json, projected_record_json, projection_hash)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)""",
            (
                event["record_id"],
                event["bucket"],
                event["event_name"],
                event["source"],
                event["signal"],
                event.get("connector"),
                correlation.get("request_id"),
                correlation.get("session_id"),
                correlation.get("turn_id"),
                json.dumps(event.get("body") or {}, separators=(",", ":")),
                raw.strip(),
                "sha256:" + hashlib.sha256(raw.strip().encode("utf-8")).hexdigest(),
            ),
        )
connection.commit()
connection.close()
'@
    & python.exe -c $pythonCode $database $jsonl
    if ($LASTEXITCODE -ne 0) { throw 'failed to create disposable audit fixture' }
    $savedAuditDb = $script:AuditDb
    $savedStateRoot = $StateRoot
    $projectionStateRoot = Join-Path $temp 'canonical-event-projection-state'
    Protect-TestDirectory $projectionStateRoot
    $walWriter = $null
    try {
        $StateRoot = $projectionStateRoot
        $script:AuditDb = $database
        $canonicalLines = @(Get-EventLines $script:AuditDb)
        Assert-True ($canonicalLines.Count -eq 5) `
            'Windows live evidence reads every canonical SQLite projection in rowid order'
        Assert-True ($canonicalLines[0] -ceq $fixtureEvents[0] -and
            $canonicalLines[4] -ceq $fixtureEvents[4]) `
            'canonical SQLite projection preserves exact stored JSON records and order'
        $projectionFiles = @(Get-ChildItem -LiteralPath (
            Join-Path $projectionStateRoot '.canonical-event-projection'
        ) -Filter '*.jsonl' -File -ErrorAction SilentlyContinue)
        Assert-True ($projectionFiles.Count -eq 0) `
            'private canonical projection snapshots are deleted immediately after each read'

        $delayedSessionId = 'windows-contract-delayed-session'
        $delayedRequestId = [guid]::NewGuid().ToString()
        $delayedToolInvocationId = 'windows-contract-delayed-tool'
        $delayedDecision = $fixtureEvents[1] | ConvertFrom-Json -ErrorAction Stop
        $delayedDecision.record_id = 'windows-contract-delayed-hook-decision'
        $delayedDecision.correlation.request_id = $delayedRequestId
        $delayedDecision.correlation.session_id = $delayedSessionId
        $delayedDecision.correlation.tool_invocation_id = $delayedToolInvocationId
        $delayedDecision.body.'defenseclaw.guardrail.effective_action' = 'allow'
        $delayedDecision.body.'defenseclaw.guardrail.raw_action' = 'allow'
        $delayedDecision.body.'defenseclaw.guardrail.mode' = 'enforce'
        $delayedDecision.body.'defenseclaw.guardrail.would_block' = $false
        $delayedDecision.body.'defenseclaw.guardrail.enforced' = $false
        $delayedDecision.body.'defenseclaw.guardrail.rule_ids' = @()
        $delayedRaw = $delayedDecision | ConvertTo-Json -Depth 8 -Compress
        $uncommittedReady = Join-Path $projectionStateRoot 'uncommitted.ready'
        $commitReady = Join-Path $projectionStateRoot 'commit.ready'
        $committedReady = Join-Path $projectionStateRoot 'committed.ready'
        $walPython = @'
import hashlib
import json
import sqlite3
import sys
import time
from pathlib import Path

database, raw, uncommitted_ready, commit_ready, committed_ready = sys.argv[1:]
event = json.loads(raw)
correlation = event["correlation"]
connection = sqlite3.connect(database, timeout=5)
connection.execute("BEGIN IMMEDIATE")
connection.execute(
    """INSERT INTO audit_events
           (id, bucket, event_name, source, signal, connector,
            request_id, session_id, turn_id, record_schema_version,
            payload_json, projected_record_json, projection_hash)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)""",
    (
        event["record_id"], event["bucket"], event["event_name"],
        event["source"], event["signal"], event["connector"],
        correlation["request_id"], correlation["session_id"],
        correlation.get("turn_id"),
        json.dumps(event.get("body") or {}, separators=(",", ":")),
        raw,
        "sha256:" + hashlib.sha256(raw.encode("utf-8")).hexdigest(),
    ),
)
Path(uncommitted_ready).write_text("ready", encoding="utf-8")
deadline = time.monotonic() + 10
while not Path(commit_ready).is_file():
    if time.monotonic() >= deadline:
        raise TimeoutError("commit authorization was not published")
    time.sleep(0.05)
connection.commit()
connection.close()
Path(committed_ready).write_text("committed", encoding="utf-8")
'@
        $pythonApplication = (Get-Command 'python.exe' -CommandType Application `
            -ErrorAction Stop | Select-Object -First 1).Source
        $walWriter = Start-Job -ArgumentList @(
            $pythonApplication, $walPython, $database, $delayedRaw,
            $uncommittedReady, $commitReady, $committedReady
        ) -ScriptBlock {
            param($Python, $Code, $Database, $Raw, $Uncommitted, $Commit, $Committed)
            & $Python -c $Code $Database $Raw $Uncommitted $Commit $Committed
            if ($LASTEXITCODE -ne 0) { throw "SQLite WAL fixture exited $LASTEXITCODE" }
        }
        $uncommittedDeadline = [DateTime]::UtcNow.AddSeconds(10)
        while (-not (Test-Path -LiteralPath $uncommittedReady -PathType Leaf)) {
            if ($walWriter.State -eq 'Failed') {
                Receive-Job $walWriter -ErrorAction Stop | Out-Null
            }
            if ([DateTime]::UtcNow -ge $uncommittedDeadline) {
                throw 'SQLite WAL fixture did not publish its uncommitted row'
            }
            Start-Sleep -Milliseconds 50
        }
        Assert-True (@(Get-EventLines $script:AuditDb).Count -eq 5) `
            'canonical live-WAL reader does not expose an uncommitted event'
        Assert-True ($null -eq (Get-LatestHookDecision `
            $script:AuditDb codex 5 $delayedSessionId $hookEvent `
            $delayedToolInvocationId)) `
            'readiness cannot accept an uncommitted hook decision'
        $forgedGatewayJsonl = Join-Path $projectionStateRoot 'gateway.jsonl'
        [IO.File]::WriteAllText(
            $forgedGatewayJsonl,
            $delayedRaw + [Environment]::NewLine
        )
        $forgedDecision = Wait-HookDecisionAfter `
            -Since 5 -Deadline ([DateTime]::UtcNow.AddMilliseconds(500)) `
            -SessionID $delayedSessionId -HookEvent $hookEvent
        Assert-True ($null -eq $forgedDecision) `
            'a forged retired gateway.jsonl cannot satisfy canonical SQLite readiness'

        [IO.File]::WriteAllText($commitReady, 'commit')
        $delayedObserved = Wait-HookDecisionAfter `
            -Since 5 -Deadline ([DateTime]::UtcNow.AddSeconds(10)) `
            -SessionID $delayedSessionId -HookEvent $hookEvent
        Assert-True ($null -ne $delayedObserved -and
            [string]$delayedObserved.request_id -ceq $delayedRequestId -and
            [string]$delayedObserved.tool_invocation_id -ceq $delayedToolInvocationId -and
            [string]$delayedObserved.action -ceq 'allow' -and
            [string]$delayedObserved.raw_action -ceq 'allow' -and
            -not [bool]$delayedObserved.would_block -and
            -not [bool]$delayedObserved.enforced) `
            'session-bound readiness observes the exact canonical decision after WAL commit'
        Wait-Job -Job $walWriter -Timeout 10 | Out-Null
        Assert-True ($walWriter.State -eq 'Completed' -and
            (Test-Path -LiteralPath $committedReady -PathType Leaf)) `
            'SQLite WAL writer committed and closed within the bounded fixture'
        Receive-Job $walWriter -ErrorAction Stop | Out-Null

        $validatorSnapshot = New-CanonicalAuditProjectionSnapshot
        try {
            & python.exe (Join-Path $root 'scripts\assert-observability-v8-jsonl.py') `
                $validatorSnapshot --min-records 6 --require-event-name hook_decision
            Assert-True ($LASTEXITCODE -eq 0) `
                'canonical SQLite projection passes the observability-v8 validator'
            & python.exe (Join-Path $PSScriptRoot 'assert-windows-evidence.py') `
                --jsonl $validatorSnapshot --audit-db $database --connector codex
            Assert-True ($LASTEXITCODE -eq 0) `
                'canonical SQLite projection passes indexed audit correlation validation'
        } finally {
            Remove-Item -LiteralPath $validatorSnapshot -Force -ErrorAction SilentlyContinue
        }

        $wrongSchemaRecord = $fixtureEvents[0] | ConvertFrom-Json -ErrorAction Stop
        $wrongSchemaRecord.schema_version = 2
        $wrongBooleanRecord = $fixtureEvents[1] | ConvertFrom-Json -ErrorAction Stop
        $wrongBooleanRecord.body.'defenseclaw.guardrail.would_block' = 'false'
        $projectionFailureCases = @(
            [pscustomobject]@{
                Name = 'blank'; RecordID = 'windows-contract-verdict'
                Value = ''; Original = $fixtureEvents[0]
            },
            [pscustomobject]@{
                Name = 'malformed'; RecordID = 'windows-contract-verdict'
                Value = '{'; Original = $fixtureEvents[0]
            },
            [pscustomobject]@{
                Name = 'wrong-schema'; RecordID = 'windows-contract-verdict'
                Value = ($wrongSchemaRecord | ConvertTo-Json -Depth 8 -Compress)
                Original = $fixtureEvents[0]
            },
            [pscustomobject]@{
                Name = 'non-boolean-hook-verdict'
                RecordID = 'windows-contract-hook-decision'
                Value = ($wrongBooleanRecord | ConvertTo-Json -Depth 8 -Compress)
                Original = $fixtureEvents[1]
            }
        )
        $updateProjection = @'
import hashlib
import json
import sqlite3
import sys

database, record_id, value = sys.argv[1:]
try:
    event = json.loads(value)
    body = event.get("body") or {}
except json.JSONDecodeError:
    body = {}
connection = sqlite3.connect(database)
connection.execute(
    """UPDATE audit_events
          SET payload_json = ?, projected_record_json = ?, projection_hash = ?
        WHERE id = ?""",
    (
        json.dumps(body, separators=(",", ":")),
        value,
        "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest(),
        record_id,
    ),
)
connection.commit()
connection.close()
'@
        foreach ($failureCase in $projectionFailureCases) {
            & $pythonApplication -c $updateProjection $database `
                $failureCase.RecordID $failureCase.Value
            if ($LASTEXITCODE -ne 0) {
                throw "failed to install $($failureCase.Name) projection fixture"
            }
            $projectionRejected = $false
            try {
                $null = @(Get-EventLines $script:AuditDb)
            } catch {
                $projectionRejected = $true
            } finally {
                & $pythonApplication -c $updateProjection $database `
                    $failureCase.RecordID $failureCase.Original
                if ($LASTEXITCODE -ne 0) {
                    throw "failed to restore $($failureCase.Name) projection fixture"
                }
            }
            Assert-True $projectionRejected `
                "canonical SQLite reader rejects a $($failureCase.Name) projection without cursor collapse"
        }

        $mismatchProjection = @'
import sqlite3
import sys

database, connector, record_id = sys.argv[1:]
connection = sqlite3.connect(database)
connection.execute(
    "UPDATE audit_events SET connector = ? WHERE id = ?",
    (connector, record_id),
)
connection.commit()
connection.close()
'@
        & $pythonApplication -c $mismatchProjection $database cursor `
            'windows-contract-verdict'
        if ($LASTEXITCODE -ne 0) { throw 'failed to install indexed projection mismatch' }
        $mismatchRejected = $false
        try {
            $null = @(Get-EventLines $script:AuditDb)
        } catch {
            $mismatchRejected = $true
        } finally {
            & $pythonApplication -c $mismatchProjection $database codex `
                'windows-contract-verdict'
            if ($LASTEXITCODE -ne 0) { throw 'failed to restore indexed projection mismatch' }
        }
        Assert-True $mismatchRejected `
            'canonical SQLite reader rejects disagreement between indexed and projected identity'

        $updateIndexedField = @'
import sqlite3
import sys

database, field, value, record_id = sys.argv[1:]
if field not in {"payload_json", "projection_hash"}:
    raise ValueError("unsupported fixture field")
connection = sqlite3.connect(database)
connection.execute(
    f"UPDATE audit_events SET {field} = ? WHERE id = ?",
    (value, record_id),
)
connection.commit()
connection.close()
'@
        foreach ($corruption in @(
            [pscustomobject]@{
                Name = 'payload/body mismatch'; Field = 'payload_json'; Value = '{}'
            },
            [pscustomobject]@{
                Name = 'projection hash mismatch'; Field = 'projection_hash'
                Value = 'sha256:' + (('0' * 64) -join '')
            }
        )) {
            & $pythonApplication -c $updateIndexedField $database $corruption.Field `
                $corruption.Value 'windows-contract-verdict'
            if ($LASTEXITCODE -ne 0) {
                throw "failed to install $($corruption.Name) fixture"
            }
            $corruptionRejected = $false
            try {
                $null = @(Get-EventLines $script:AuditDb)
            } catch {
                $corruptionRejected = $true
            } finally {
                & $pythonApplication -c $updateProjection $database `
                    'windows-contract-verdict' $fixtureEvents[0]
                if ($LASTEXITCODE -ne 0) {
                    throw "failed to restore $($corruption.Name) fixture"
                }
            }
            Assert-True $corruptionRejected `
                "canonical SQLite reader rejects a $($corruption.Name)"
        }
    } finally {
        if ($null -ne $walWriter) {
            Stop-Job $walWriter -ErrorAction SilentlyContinue
            Remove-Job $walWriter -Force -ErrorAction SilentlyContinue
        }
        $script:AuditDb = $savedAuditDb
        $StateRoot = $savedStateRoot
    }
    & python.exe (Join-Path $root 'scripts\assert-observability-v8-jsonl.py') $jsonl `
        --min-records 5 --require-event-name hook_decision
    Assert-True ($LASTEXITCODE -eq 0) 'mock canonical observability-v8 schema'
    & python.exe (Join-Path $PSScriptRoot 'assert-windows-evidence.py') --jsonl $jsonl --audit-db $database --connector codex
    Assert-True ($LASTEXITCODE -eq 0) 'mock audit correlation'
    Assert-True (Test-ConnectorEvent $jsonl 'codex' 0) 'connector event seam'
    Assert-True (-not (Test-ConnectorEvent $jsonl 'claudecode' 0)) 'connector event seam ignores body-text false positives'
    Assert-True (Test-ConnectorEvent `
        -Path $jsonl -Name 'codex' -Since 0 -SessionID $sessionId -HookEvent $hookEvent `
        -ToolInvocationID $toolInvocationId) `
        'connector event seam accepts the matching hook identity'
    Assert-True (-not (Test-ConnectorEvent `
        -Path $jsonl -Name 'codex' -Since 0 -SessionID 'unrelated-session' -HookEvent $hookEvent)) `
        'connector event seam rejects an unrelated hook identity'
    Assert-True (-not (Test-ConnectorEvent `
        -Path $jsonl -Name 'codex' -Since 0 -SessionID $sessionId -HookEvent $hookEvent `
        -RequestID 'unrelated-request')) `
        'connector event seam rejects an unrelated request identity'
    Assert-True (-not (Test-ConnectorEvent `
        -Path $jsonl -Name 'codex' -Since 0 -SessionID $sessionId -HookEvent $hookEvent `
        -ToolInvocationID 'unrelated-tool')) `
        'connector event seam rejects an unrelated tool invocation identity'
    Assert-True (Test-BlockVerdict $jsonl 0) 'block verdict seam'
    Assert-True (-not (Test-BlockVerdict $jsonl 1)) 'block verdict seam rejects hook decisions and non-canonical scan deny values'
    Assert-True (Test-BlockVerdict `
        -Path $jsonl -Since 0 -Name 'codex' -RequestID $requestId `
        -SessionID $sessionId -ToolInvocationID $toolInvocationId) `
        'block verdict seam accepts the matching request identity'
    Assert-True (-not (Test-BlockVerdict `
        -Path $jsonl -Since 0 -Name 'codex' -RequestID 'unrelated-request')) `
        'block verdict seam rejects an unrelated request identity'
    Assert-True (-not (Test-BlockVerdict `
        -Path $jsonl -Since 0 -Name 'codex' -RequestID $requestId `
        -SessionID $sessionId -ToolInvocationID 'unrelated-tool')) `
        'block verdict seam rejects an unrelated tool invocation identity'
    $delayedJsonl = Join-Path $temp 'delayed-gateway-evidence.jsonl'
    [IO.File]::WriteAllText($delayedJsonl, '')
    $unrelatedDecision = $fixtureEvents[1] | ConvertFrom-Json -ErrorAction Stop
    $unrelatedDecision.record_id = 'windows-contract-unrelated-hook-decision'
    $unrelatedDecision.correlation.request_id = 'unrelated-request'
    $unrelatedDecision.correlation.session_id = $sessionId
    $unrelatedDecision.correlation.tool_invocation_id = 'unrelated-tool'
    $unrelatedVerdict = $fixtureEvents[0] | ConvertFrom-Json -ErrorAction Stop
    $unrelatedVerdict.record_id = 'windows-contract-unrelated-verdict'
    $unrelatedVerdict.correlation.request_id = 'unrelated-request'
    $unrelatedVerdict.correlation.session_id = $sessionId
    $unrelatedVerdict.correlation.tool_invocation_id = 'unrelated-tool'
    $delayedWriter = Start-Job -ArgumentList @(
        $delayedJsonl,
        ($unrelatedDecision | ConvertTo-Json -Depth 8 -Compress),
        ($unrelatedVerdict | ConvertTo-Json -Depth 8 -Compress),
        $fixtureEvents[1],
        $fixtureEvents[0]
    ) -ScriptBlock {
        param($Path, $UnrelatedDecision, $UnrelatedVerdict, $CurrentDecision, $CurrentVerdict)
        Start-Sleep -Milliseconds 100
        [IO.File]::AppendAllText($Path, $UnrelatedDecision + [Environment]::NewLine)
        [IO.File]::AppendAllText($Path, $UnrelatedVerdict + [Environment]::NewLine)
        Start-Sleep -Milliseconds 1000
        [IO.File]::AppendAllText($Path, $CurrentDecision + [Environment]::NewLine)
        Start-Sleep -Milliseconds 100
        [IO.File]::AppendAllText($Path, $CurrentVerdict + [Environment]::NewLine)
    }
    try {
        $delayedEvidence = Wait-GatewayEvidenceAfter `
            -Path $delayedJsonl -Name 'codex' -Since 0 -RequireBlock $true `
            -TimeoutMilliseconds 5000 -SessionID $sessionId -HookEvent $hookEvent `
            -ToolInvocationID $toolInvocationId
        Wait-Job -Job $delayedWriter -Timeout 10 | Out-Null
        Assert-True ($delayedWriter.State -eq 'Completed') `
            'delayed gateway evidence writer completed within the bounded wait'
        Receive-Job $delayedWriter -ErrorAction Stop | Out-Null
        Assert-True ($delayedEvidence.ConnectorEvent -and $delayedEvidence.BlockVerdict -and
            [string]$delayedEvidence.RequestID -ceq $requestId -and
            [string]$delayedEvidence.ToolInvocationID -ceq $toolInvocationId) `
            'gateway evidence polling ignores delayed unrelated records and waits for the matching hook request'
    } finally {
        Stop-Job $delayedWriter -ErrorAction SilentlyContinue
        Remove-Job $delayedWriter -Force -ErrorAction SilentlyContinue
    }
    $hookDecision = Get-LatestHookDecision $jsonl 'codex' 0
    Assert-True ($null -ne $hookDecision -and $hookDecision.action -eq 'allow' -and
        $hookDecision.raw_action -eq 'block' -and $hookDecision.mode -eq 'observe' -and
        $hookDecision.would_block -and -not $hookDecision.enforced -and
        @($hookDecision.rule_ids) -contains 'CMD-WIN-REMOVE-ITEM-RF') `
        'hook decision reads canonical dotted guardrail fields'
    Assert-True (Test-GatewayConnectorTelemetry $jsonl 'codex' 0) 'gateway-generated connector telemetry evidence seam'

    $ampProviderJsonl = Join-Path $temp 'amp-five-event-provider.jsonl'
    $ampProviderResults = Join-Path $temp 'amp-five-event-provider-results.jsonl'
    $ampHookEvents = @(
        'session.start',
        'agent.start',
        'tool.call',
        'tool.result',
        'agent.end'
    )
    $ampLifecycleEvents = @(
        [pscustomobject]@{ Event = 'session_start'; Bucket = 'agent.lifecycle' },
        [pscustomobject]@{ Event = 'turn_start'; Bucket = 'agent.lifecycle' },
        [pscustomobject]@{ Event = 'tool_start'; Bucket = 'tool.activity' },
        [pscustomobject]@{ Event = 'tool_end'; Bucket = 'tool.activity' },
        [pscustomobject]@{ Event = 'turn_end'; Bucket = 'agent.lifecycle' }
    )
    $ampProviderRows = [Collections.Generic.List[string]]::new()
    for ($index = 0; $index -lt $ampHookEvents.Count; $index++) {
        $decision = [ordered]@{
            schema_version = 1; bucket_catalog_version = 1; timestamp = $observedAt
            record_id = "amp-provider-decision-$index"
            bucket = 'guardrail.evaluation'; signal = 'logs'
            event_name = 'hook_decision'; source = 'connector'; connector = 'amp'
            correlation = @{ request_id = "amp-provider-request-$index" }
            provenance = $provenance; field_classes = @{}; mandatory = $false
            body = @{
                'defenseclaw.hook.event' = $ampHookEvents[$index]
            }
        }
        $lifecycle = [ordered]@{
            schema_version = 1; bucket_catalog_version = 1; timestamp = $observedAt
            record_id = "amp-provider-lifecycle-$index"
            bucket = $ampLifecycleEvents[$index].Bucket; signal = 'logs'
            event_name = $ampLifecycleEvents[$index].Event
            source = 'connector'; connector = 'amp'
            correlation = @{ request_id = "amp-provider-request-$index" }
            provenance = $provenance; field_classes = @{}; mandatory = $false
            body = @{ 'defenseclaw.connector.source' = 'amp' }
        }
        $ampProviderRows.Add(($decision | ConvertTo-Json -Depth 8 -Compress))
        $ampProviderRows.Add(($lifecycle | ConvertTo-Json -Depth 8 -Compress))
    }
    [IO.File]::WriteAllText(
        $ampProviderJsonl,
        ($ampProviderRows -join [Environment]::NewLine) + [Environment]::NewLine,
        [Text.UTF8Encoding]::new($false)
    )
    $savedProviderConnector = $Connector
    $savedProviderResultsPath = $script:ResultsPath
    $savedProviderAgentVersion = Get-Variable `
        -Name AgentVersion -Scope Script -ErrorAction SilentlyContinue
    try {
        $Connector = 'amp'
        $script:ResultsPath = $ampProviderResults
        $script:AgentVersion = 'provider-fixture'
        Assert-AmpFiveEventProviderProvenance $ampProviderJsonl 0
        Assert-True (
            [IO.File]::ReadAllText($ampProviderResults) -match
                '"event":"amp:five-event-provider".*"status":"pass"'
        ) 'Amp five-event provider fixture emits a passing contract result'

        $poisonedLines = @([IO.File]::ReadAllLines($ampProviderJsonl))
        $poisoned = $poisonedLines[1] | ConvertFrom-Json -ErrorAction Stop
        $poisoned.body | Add-Member -NotePropertyName 'gen_ai.provider.name' `
            -NotePropertyValue 'fabricated'
        $poisonedLines[1] = $poisoned | ConvertTo-Json -Depth 8 -Compress
        $poisonedPath = Join-Path $temp 'amp-five-event-provider-poisoned.jsonl'
        [IO.File]::WriteAllLines(
            $poisonedPath,
            [string[]]$poisonedLines,
            [Text.UTF8Encoding]::new($false)
        )
        $fabricatedProviderRejected = $false
        try { Assert-AmpFiveEventProviderProvenance $poisonedPath 0 }
        catch {
            $fabricatedProviderRejected =
                $_.Exception.Message -match 'fabricated gen_ai\.provider\.name'
        }
        Assert-True $fabricatedProviderRejected `
            'Amp five-event provider proof rejects a fabricated provider field'
    } finally {
        $Connector = $savedProviderConnector
        $script:ResultsPath = $savedProviderResultsPath
        if ($null -ne $savedProviderAgentVersion) {
            $script:AgentVersion = $savedProviderAgentVersion.Value
        } else {
            Remove-Variable -Name AgentVersion -Scope Script -ErrorAction SilentlyContinue
        }
    }

    $nativeWorkflowText = [IO.File]::ReadAllText($nativeWorkflow)
    $releaseWorkflowText = [IO.File]::ReadAllText($releaseWorkflow)
    $liveWorkflowText = [IO.File]::ReadAllText($liveWorkflow)
    $ciWorkflowText = [IO.File]::ReadAllText($ciWorkflow)
    $harnessText = [IO.File]::ReadAllText($harness)
    $auditProjectorText = [IO.File]::ReadAllText($auditProjector)
    $openCodeAssertionText = [IO.File]::ReadAllText($openCodeAssertion)
    $nativeHarnessText = [IO.File]::ReadAllText($nativeHarness)
    $wizardHarnessText = [IO.File]::ReadAllText($wizardHarness)
    $standardUserCIText = [IO.File]::ReadAllText($standardUserCI)
    $standardUserLauncherText = [IO.File]::ReadAllText($standardUserLauncher)
    $setupStandardUserLauncherText = [IO.File]::ReadAllText($setupStandardUserLauncher)
    $nativePathHelpersText = [IO.File]::ReadAllText($nativePathHelpers)
    $nativePathInitializerText = [IO.File]::ReadAllText($nativePathInitializer)
    $installerText = [IO.File]::ReadAllText($installer)
    $ampHookTestText = [IO.File]::ReadAllText($ampHookTest)
    $setupMainSourceText = [IO.File]::ReadAllText($setupMainSource)
    $setupMainTestsText = [IO.File]::ReadAllText($setupMainTests)
    $setupWizardSourceText = [IO.File]::ReadAllText($setupWizardSource)
    $devinAdmissionSourceText = [IO.File]::ReadAllText($devinAdmissionSource)
    $devinAdmissionTestsText = [IO.File]::ReadAllText($devinAdmissionTests)
    $packageLiveAuthority = [regex]::Match(
        $harnessText,
        '(?s)function Initialize-PackageLiveEvidenceAuthority\b.*?(?=\r?\nfunction )'
    ).Value
    $packageLiveCleanup = [regex]::Match(
        $harnessText,
        '(?s)function Invoke-PackageLiveEvidenceCleanup\b.*?(?=\r?\nfunction )'
    ).Value
    $optionalJsonStringValue = [regex]::Match(
        $harnessText,
        '(?s)function Get-OptionalJsonStringValue\b.*?(?=\r?\nfunction )'
    ).Value
    $packageDeferredCleanup = [regex]::Match(
        $harnessText,
        '(?s)function Assert-PackageDeferredCleanupPending\b.*?(?=\r?\nfunction )'
    ).Value
    $antigravitySourceAuthority = [regex]::Match(
        $harnessText,
        '(?s)function Assert-AuthenticatedAntigravitySourceCheckout\b.*?(?=\r?\nfunction )'
    ).Value
    $copilotSourceAuthority = [regex]::Match(
        $harnessText,
        '(?s)function Assert-ProtectedCopilotSourceCheckout\b.*?(?=\r?\nfunction )'
    ).Value
    $singleGitAuthorityPattern =
        "(?s)\`$gitApplication = Get-Command 'git\.exe' -CommandType Application -ErrorAction Stop\s*\|\s*Select-Object -First 1\s*\`$git = \[string\]\`$gitApplication\.Source.*?Invoke-NativeProcess -FilePath \`$git"
    Assert-True ($packageLiveAuthority -match $singleGitAuthorityPattern -and
        $antigravitySourceAuthority -match $singleGitAuthorityPattern -and
        $copilotSourceAuthority -match $singleGitAuthorityPattern -and
        $packageLiveCleanup -match
            '(?s)^function Invoke-PackageLiveEvidenceCleanup.*?Initialize-PackageLiveEvidenceAuthority') `
        'live Git authority checks select one PATH application before package, Antigravity, Copilot, and cleanup validation'
    Assert-True (
        $packageLiveCleanup -match
            '(?s)\$uninstall = Invoke-NativeProcess.*?''/uninstall''.*?-AllowedExitCodes @\(0, 3010\).*?if \(\$uninstall\.ExitCode -eq 3010\)' -and
        ([regex]::Matches(
            $packageLiveCleanup,
            'Assert-PackageDeferredCleanupPending'
        )).Count -eq 2 -and
        $packageLiveCleanup -match
            '(?s)elseif \(\(Test-Path -LiteralPath \$paths\.InstallRoot\).*?\$paths\.DataRoot\)\) \{\s*throw ''package live cleanup found product state without exact installed provenance''\s*\} elseif \(Test-Path -LiteralPath \$paths\.CacheRoot\) \{\s*\$null = Assert-PackageDeferredCleanupPending' -and
        $optionalJsonStringValue -match
            '\$InputObject\.PSObject\.Properties\[\$PropertyName\]' -and
        $packageDeferredCleanup -match
            '(?s)Get-OptionalJsonStringValue.*?cleanup_boot_identifier.*?Get-OptionalJsonStringValue.*?data_root.*?Get-OptionalJsonStringValue.*?gateway_path.*?Get-OptionalJsonStringValue.*?gateway_sha256' -and
        $packageDeferredCleanup -notmatch
            '\$(?:record\.cleanup_boot_identifier|hookState\.(?:data_root|gateway_path|gateway_sha256))' -and
        $packageDeferredCleanup -match "\[string\]\`$record\.status -cne 'pending-reboot'" -and
        $packageDeferredCleanup -match
            'Get-FileHash -LiteralPath \$ExactSetupExecutable' -and
        $packageDeferredCleanup -match
            'deferred cleanup retained an unexpected same-boot path' -and
        $packageDeferredCleanup -match
            'Run value differs from authenticated authority'
    ) 'package live cleanup accepts exact 0/3010 uninstall success, authenticates deferred residue on re-entry, and rejects partial or foreign state'
    $nativeProcessFunction = [regex]::Match(
        $nativeHarnessText,
        '(?s)function Invoke-WindowsNativeProcess\b.*?(?=\r?\nfunction )'
    ).Value
    $diagnosticTailFunction = [regex]::Match(
        $nativeHarnessText,
        '(?s)function Add-WindowsNativeDiagnosticTail\b.*?(?=\r?\nfunction )'
    ).Value
    $nativeSelfTestFunction = [regex]::Match(
        $nativeHarnessText,
        '(?s)function Invoke-SelfTest\b.*?(?=\r?\nif \(-not \$NoRun\))'
    ).Value
    $connectorContractJob = [regex]::Match(
        $nativeWorkflowText,
        '(?ms)^  connector-contract:.*?(?=^  [a-z0-9][a-z0-9-]*:|\z)'
    ).Value
    $connectorMatrix = [regex]::Match(
        $connectorContractJob,
        '(?m)^\s+connector: \[([^\]]+)\]\s*$'
    )
    $requiredContractConnectors = @(
        'amp', 'antigravity', 'claudecode', 'codex', 'copilot',
        'cursor', 'devin', 'hermes', 'omnigent', 'opencode'
    )
    $excludedContractConnectors = @(
        'geminicli', 'openhands', 'openclaw', 'windsurf', 'zeptoclaw'
    )
    $genericContractConnectors = if ($connectorMatrix.Success) {
        @($connectorMatrix.Groups[1].Value -split '\s*,\s*')
    } else {
        @()
    }
    $omniGentJob = [regex]::Match(
        $nativeWorkflowText,
        '(?ms)^  omnigent-native-degraded:.*?(?=^  [a-z0-9][a-z0-9-]*:|\z)'
    ).Value
    $actualContractConnectors = @($genericContractConnectors)
    if (-not [string]::IsNullOrWhiteSpace($omniGentJob)) {
        $actualContractConnectors += 'omnigent'
    }
    Assert-True (
        $actualContractConnectors.Count -eq $requiredContractConnectors.Count -and
        ($actualContractConnectors | Sort-Object) -join ',' -ceq
            ($requiredContractConnectors | Sort-Object) -join ','
    ) 'required Windows contract coverage is exactly the ten deterministic packaged connector lanes'
    Assert-True (@($excludedContractConnectors | Where-Object {
        $actualContractConnectors -ccontains $_
    }).Count -eq 0) 'packaged coverage excludes deprecated or unsupported connectors'
    Assert-True ($devinAdmissionSourceText -match 'const devinPinnedCLIVersion = "3000\.4\.25"' -and
        $devinAdmissionSourceText -match 'rejectReparseAncestors\(executable\)' -and
        $devinAdmissionSourceText -match 'verifyEmbeddedAuthenticodeTrust\(executable\)' -and
        $devinAdmissionSourceText -match 'SignerCommonName == "Exafunction, Inc\."' -and
        $devinAdmissionSourceText -match 'context\.WithTimeout\(context\.Background\(\), 5\*time\.Second\)' -and
        $devinAdmissionSourceText -match 'exec\.CommandContext\(ctx, executable, "--version"\)' -and
        $devinAdmissionTestsText -match 'TestValidateDevinExecutableIdentityRequiresExactFixedPath' -and
        $devinAdmissionTestsText -match 'TestValidateDevinSignerRequiresExactExafunctionIdentity' -and
        $devinAdmissionTestsText -match 'TestValidateDevinVersionOutputPins3000425') `
        'Devin packaged readiness retains fixed-path, signed-publisher, and exact-version admission checks without claiming authenticated or live-client evidence'
    Assert-True ($connectorContractJob -match 'https://static\.devin\.ai/cli/3000\.4\.25/devin-3000\.4\.25-x86_64-pc-windows\.zip' -and
        $connectorContractJob -match '926EF4C2139D593BE564B93382D5A80F8AF0EE8AD7201CD35D50EEC9CD289808' -and
        $standardUserCIText -match 'disposable-user Devin archive copy does not match the pinned input' -and
        $nativeHarnessText -match 'pinned Devin executable does not have the required valid Exafunction signature' -and
        $nativeHarnessText -match 'devin 3000\.4\.25 \(7e8e528a\)') `
        'Devin contract uses one digest-pinned official archive and revalidates signer, version, and immutable child handoff'
    $requiredFanInJob = [regex]::Match(
        $nativeWorkflowText,
        '(?ms)^  windows-native-required:.*?(?=^  [a-z0-9][a-z0-9-]*:|\z)'
    ).Value
    Assert-True ($requiredFanInJob -match '(?m)^\s{6}- connector-contract\s*$' -and
        $requiredFanInJob -match '(?m)^\s{6}- omnigent-native-degraded\s*$') `
        'required Windows aggregate depends on every deterministic packaged connector contract'
    $invokeHookFunction = [regex]::Match(
        $harnessText,
        '(?s)function Invoke-Hook\b.*?(?=\r?\nfunction )'
    ).Value
    Assert-True ($invokeHookFunction -match 'Wait-GatewayEvidenceAfter' -and
        $invokeHookFunction -match '-SessionID \$sessionID' -and
        $invokeHookFunction -match '-HookEvent \$hookEvent' -and
        $invokeHookFunction -match 'Get-JsonPropertyValue \$payloadObject ''tool_call_id''' -and
        $invokeHookFunction -match '-ToolInvocationID \$toolInvocationID' -and
        $invokeHookFunction -match 'New-AmpHookPayloadOccurrence' -and
        $invokeHookFunction -notmatch 'Start-Sleep -Milliseconds 800') `
        'hook evidence uses session, event, and tool-scoped bounded polling instead of a fixed 800ms delay'
    Assert-True ($nativeWorkflowText -match '(?m)^\s+name: Windows Native Required\s*$') 'stable aggregate check name exists'
    foreach ($job in @('windows-go', 'windows-python', 'powershell-static', 'package-artifact', 'packaged-acceptance', 'connector-contract', 'omnigent-native-degraded')) {
        Assert-True ($nativeWorkflowText -match "(?m)^\s{6}- $([regex]::Escape($job))\s*$") "aggregate depends on $job"
        $requiredJob = [regex]::Match(
            $nativeWorkflowText,
            "(?ms)^  $([regex]::Escape($job)):.*?(?=^  [a-z0-9][a-z0-9-]*:|\z)"
        ).Value
        Assert-True ($requiredJob -notmatch 'continue-on-error') "required Windows job $job is not advisory"
    }
    Assert-True ($nativeWorkflowText -match '(?s)windows-native-required:.*?if: \$\{\{ always\(\) \}\}.*?result -ne ''success''') 'aggregate fails skipped or failed dependencies'
    Assert-True ($omniGentJob -notmatch '(?m)^\s{4}if:' -and
        $omniGentJob -notmatch '(?m)^\s{4}continue-on-error:') `
        'OmniGent native-degraded contract is unconditional and non-advisory'
    Assert-True ($nativeWorkflowText -notmatch 'shell:\s*bash') 'dedicated Windows workflow never selects Bash'
    Assert-True ($nativeWorkflowText -notmatch 'secrets\.') 'dedicated deterministic workflow consumes no secrets'
    Assert-True ([regex]::Matches(
        $nativeWorkflowText,
        '(?m)^\s*run: \./scripts/initialize-windows-native-ci-paths\.ps1 '
    ).Count -eq 8) 'every native Windows job uses the shared isolated-path initializer'
    foreach ($leafContract in @(
        '-Leaf go -DiagnosticsLeaf windows-native-diagnostics-go',
        "-Leaf ('py-' + `$env:PYTHON_SHARD) -DiagnosticsLeaf ('windows-native-diagnostics-python-' + `$env:PYTHON_SHARD)",
        '-Leaf ps -DiagnosticsLeaf windows-native-diagnostics-powershell',
        '-Leaf pkg -DiagnosticsLeaf windows-native-diagnostics-package -ArtifactLeaf windows-native-dist',
        '-Leaf acc -DiagnosticsLeaf windows-native-diagnostics-acceptance -ArtifactLeaf windows-native-dist',
        '-Leaf bootstrap -DiagnosticsLeaf windows-native-diagnostics-bootstrap -ArtifactLeaf windows-bootstrap-fixture',
        "-Leaf ('ct-' + `$env:CONNECTOR) -DiagnosticsLeaf ('windows-native-diagnostics-' + `$env:CONNECTOR) -ArtifactLeaf windows-native-dist",
        '-Leaf omnigent -DiagnosticsLeaf windows-native-diagnostics-omnigent -ArtifactLeaf windows-native-dist'
    )) {
        Assert-True ($nativeWorkflowText.Contains($leafContract)) `
            "native Windows workflow preserves isolated path contract: $leafContract"
    }
    Assert-True ($nativePathInitializerText -match
        "Resolve-SafeWindowsNativeBase \(Join-Path \`$env:USERPROFILE '\.dc-ci'\)" -and
        $nativePathInitializerText -match 'Test-PathWithin \$stateRoot \$stateBase' -and
        $nativePathInitializerText -match 'if \(\$stateRoot\.Length -gt 48\)' -and
        $nativePathInitializerText -match 'DC_WINDOWS_NATIVE_BASE_ROOT=\$stateBase' -and
        $nativePathInitializerText -match 'DC_STATE_ROOT=\$stateRoot') `
        'shared initializer roots short mutable state below the trusted user profile'
    $initializeProfileIndex = $nativeSelfTestFunction.IndexOf(
        '$profile = Initialize-IsolatedProfile $root',
        [StringComparison]::Ordinal
    )
    $rebindNativeBaseIndex = $nativeSelfTestFunction.IndexOf(
        '$env:DC_WINDOWS_NATIVE_BASE_ROOT = Resolve-SafeWindowsNativeBase $selfTestNativeBase',
        [StringComparison]::Ordinal
    )
    Assert-True ($initializeProfileIndex -ge 0 -and
        $rebindNativeBaseIndex -gt $initializeProfileIndex -and
        $nativeSelfTestFunction -match
            "\`$selfTestNativeBase = Join-Path \`$nativeBaseProfile '\.dc-ci\\self-test'" -and
        $nativeSelfTestFunction -notmatch
            '\$env:DC_WINDOWS_NATIVE_BASE_ROOT\s*=\s*\$root') `
        'native self-test rebinds child-only authority below the Profile Known Folder without weakening the shared guard'
    Assert-True ($nativePathInitializerText -match 'Join-Path \$env:RUNNER_TEMP \$DiagnosticsLeaf' -and
        $nativePathInitializerText -match 'Join-Path \$env:RUNNER_TEMP \$ArtifactLeaf' -and
        [regex]::Matches($nativeWorkflowText, '-ArtifactLeaf windows-native-dist').Count -eq 4) `
        'shared initializer keeps diagnostics and artifacts under RUNNER_TEMP'
    Assert-True ($nativeHarnessText -match '\$approvedStateBase' -and
        $nativeHarnessText -match 'interactive setup acceptance requires StateRoot below RUNNER_TEMP or DC_WINDOWS_NATIVE_BASE_ROOT') `
        'interactive setup cleanup accepts only the pre-validated runner temp or explicit state base'
    Assert-True ($nativePathHelpersText -match 'function Test-PathWithin\b' -and
        $nativePathHelpersText -match 'function Resolve-SafeWindowsNativeBase\b' -and
        $nativeHarnessText -notmatch 'function Test-PathWithin\b' -and
        $wizardHarnessText -notmatch 'function Test-PathWithin\b' -and
        $nativeHarnessText -match "\. \(Join-Path \`$PSScriptRoot 'windows-native-paths\.ps1'\)" -and
        $wizardHarnessText -match "\. \(Join-Path \`$PSScriptRoot 'windows-native-paths\.ps1'\)") `
        'native cleanup and wizard gates dot-source one authoritative path helper'
    Assert-True ($nativeHarnessText -notmatch 'Test-PathWithinOrEquals' -and
        $wizardHarnessText -notmatch 'Test-PathWithinOrEqual' -and
        $nativePathHelpersText -notmatch 'Test-PathWithinOrEquals' -and
        [regex]::Matches($nativeHarnessText, 'Test-PathWithinOrEqual \$full \$explicitBase').Count -eq 1 -and
        [regex]::Matches($nativeHarnessText, 'Test-PathWithin \$root \$approvedStateBase').Count -eq 1 -and
        [regex]::Matches($wizardHarnessText, 'Test-PathWithin \$state \$_').Count -eq 1) `
        'setup cleanup and wizard gates require strict descendants while general state validation can recheck its exact approved root'
    Assert-True ($nativeWorkflowText -match 'Run native Windows Go DACL regressions explicitly') 'native Windows workflow has a required Go DACL regression step'
    foreach ($testName in @(
        'TestWriteWindowsRemovesInheritedUnauthorizedWriter',
        'TestWriteWindowsPreservesStricterExistingDACL',
        'TestWindowsWriteLikeAccess',
        'TestWindowsTrustedOwner',
        'TestRejectUntrustedWindowsWriteACEs',
        'TestHookAPITokenWindowsRejectsUntrustedDirectoryACL',
        'TestHookAPITokenWindowsAllowsReadOnlyUnsupportedAllowACE',
        'TestHookAPITokenWindowsAllowsInheritOnlyCreatorOwnerTemplate',
        'TestHookAPITokenWindowsAllowsOwnerRightsACE',
        'TestHookAPITokenWindowsRejectsDirectCreatorOwnerACE',
        'TestHookAPITokenWindowsAllowsCreateChildOnSharedAncestor',
        'TestHookAPITokenWindowsRejectsOrdinaryWriteOnSharedAncestor',
        'TestHookAPITokenWindowsRejectsWritableAncestorThroughPublicOperations',
        'TestHookAPITokenWindowsAllowsInheritOnlyTemplateOnSharedAncestor',
        'TestHookAPITokenWindowsRejectsDeleteChildOnSharedAncestor',
        'TestLoadOTLPPathTokenWindowsRejectsWritableAncestor',
        'TestLoadOTLPPathTokenWindowsAllowsCreateChildOnSharedAncestor'
    )) {
        Assert-True ($nativeWorkflowText -match [regex]::Escape($testName)) "native Windows Go DACL step reaches $testName"
    }
    Assert-True ($nativeWorkflowText -match '''test'', ''-vet=off'', ''-v'', ''-count=1'', ''-run'', \$daclTestPattern, ''\./internal/safefile'', ''\./internal/managed'', ''\./internal/gateway/connector''') 'Go DACL regressions execute in every owning package without cache reuse'
    Assert-True ($nativeWorkflowText -match
        '''test'', ''-vet=off'', ''-list'', ''\^\(Test\|Fuzz\|Example\)'', ''\./internal/gateway''' -and
        $nativeWorkflowText -match '''-run'', \$gatewayShardPattern, ''\./internal/gateway''' -and
        $nativeWorkflowText -match
        '''test'', ''-vet=off'', ''-list'', ''\^\(Test\|Fuzz\|Example\)'', ''\./internal/gateway/connector''' -and
        $nativeWorkflowText -match '''-run'', \$connectorShardPattern, ''\./internal/gateway/connector''' -and
        [regex]::Matches($nativeWorkflowText, '\(\$index % 4\) -eq \$shard').Count -eq 2 -and
        $nativeWorkflowText -match '\$_ -ne ''github\.com/defenseclaw/defenseclaw/internal/gateway'' -and\s+\$_ -ne ''github\.com/defenseclaw/defenseclaw/internal/gateway/connector''' -and
        $nativeWorkflowText -match '\$remainingArguments = @\(') `
        'full native Go suite shards gateway and connector processes and separately selects every remaining package'
    Assert-True ($nativeWorkflowText -match '(?s)''-p=1''.*?''-skip''.*?\$windowsInapplicable') 'native Go suite serializes packages and excludes only declared Windows-inapplicable tests'
    Assert-True ([regex]::Matches($nativeWorkflowText, '''test'', ''-vet=off''').Count -eq
        [regex]::Matches($nativeWorkflowText, '''test''').Count -and
        $nativeWorkflowText -match 'Invoke-WindowsNativeProcess \$go @\(''vet'', ''\./\.\.\.''\)') `
        'native Go test processes disable duplicate implicit vet while retaining the explicit full vet gate'
    Assert-True ($nativeWorkflowText -match '''test'', ''-vet=off'', ''-json'', ''-count=1''' -and
        $nativeWorkflowText -match '-GoTestFailureSummaryPath \$goFailureSummary' -and
        $nativeWorkflowText -match 'go-test-failure-summary\.log') `
        'full Go suite retains a bounded structured failure summary'
    Assert-True ($nativeProcessFunction -match
        '(?s)\$exitCode = if \(\$timedOut\).*?if \(\$GoTestFailureSummaryPath -and.*?\$exitCode -notin \$AllowedExitCodes.*?Get-GoTestFailureSummary' -and
        $nativeProcessFunction -match
        '(?s)\$failureOutput = if \(\$goTestFailureSummary\).*?throw "\$FilePath \$reason`n\$failureOutput"' -and
        $diagnosticTailFunction -match
        '(?s)function Add-WindowsNativeDiagnosticTail.*?\$boundedText = Limit-WindowsNativeText.*?\$retainedBytes -gt \$MaxBytes') `
        'native process harness parses Go JSON only on failure, bounds collection, and reports the focused summary instead of the full JSON stream'
    Assert-True ($nativeWorkflowText -match 'Validate registered Windows Codex and Claude hook commands') 'native Windows workflow has a required Doctor hook-command step'
    Assert-True ($nativeWorkflowText -match "'pytest', 'cli/tests/test_cmd_doctor_windows_hooks\.py', '-q'") 'Doctor validates registered Windows hook commands explicitly'
    Assert-True ($nativeWorkflowText -match "Get-ChildItem cli/tests -Recurse -File -Filter 'test_\*\.py'") 'Windows Python suite discovers every test file before applying its documented TUI mode'
    Assert-True ($nativeWorkflowText -match 'shard: \[1, 2, 3, 4, 5, 6, 7, 8\]' -and
        $nativeWorkflowText -match "WINDOWS_TUI_MODE: \$\{\{ github\.event_name == 'pull_request' && 'smoke' \|\| 'full' \}\}" -and
        $nativeWorkflowText -match '\$fullTUI = \$env:WINDOWS_TUI_MODE -eq ''full''' -and
        $nativeWorkflowText -match 'Join-Path \$env:GITHUB_WORKSPACE ''cli\\tests\\tui''' -and
        $nativeWorkflowText -match 'return \$fullTUI -or -not \$isTUI' -and
        $nativeWorkflowText -match "\.Name -eq 'test_app_shell\.py'" -and
        $nativeWorkflowText -match "'--collect-only', '-q', '--color=no'" -and
        $nativeWorkflowText -match "Collected no test_app_shell\.py nodes" -and
        $nativeWorkflowText -match '\$appShellNodes\[\$index\]' -and
        $nativeWorkflowText -match '\(\$index % 8\) -eq \$shardIndex' -and
        $nativeWorkflowText -match 'elseif \(\$shardIndex -eq 0\)' -and
        $nativeWorkflowText -match 'test_textual_shell_starts_on_overview' -and
        $nativeWorkflowText -match 'test_digit_shortcut_switches_panel_placeholder' -and
        $nativeWorkflowText -match 'test_executor_gateway_windows\.py' -and
        $nativeWorkflowText -match 'test_windows_clipboard\.py' -and
        $nativeWorkflowText -match '\$tuiPytestArgs.*?\$tuiTargets' -and
        $nativeWorkflowText -match '\$ordinaryPytestArgs.*?\$shardFiles' -and
        $nativeWorkflowText -match 'pytest-shard-\{0\}-tui\.log' -and
        $nativeWorkflowText -match 'pytest-shard-\{0\}-ordinary\.log') `
        'Windows Python suite keeps full TUI coverage on main/manual runs and a bounded native smoke set on pull requests'
    foreach ($node in @(
        'test_existing_openclaw_integration_requires_pin',
        'test_f0162_refuses_swapped_symlink',
        'test_f0421_rechecks_pinned_home_before_chown'
    )) {
        Assert-True ($nativeWorkflowText -match "--deselect=.*$node") `
            "native Windows suite excludes the POSIX-only sandbox assertion $node"
    }
    Assert-True ($nativeWorkflowText -match 'Run native Windows Local Splunk certification regressions') 'native Windows workflow has a required Local Splunk regression step'
    Assert-True ($nativeHarnessText -match "'pip', 'check'" -and $nativeHarnessText -match "'uv.exe'") 'managed environment runs explicit uv pip check'
    Assert-True ($nativeHarnessText -match 'function Initialize-WindowsNativeTestEnvironment' -and
        $nativeHarnessText -match '\$env:TEMP = \$temp') `
        'native test harness provides a private current-user-owned temp root'
    Assert-True ([regex]::Matches(
        $nativeWorkflowText,
        'Initialize-WindowsNativeTestEnvironment \$env:DC_STATE_ROOT'
    ).Count -ge 5) 'Go and Python test steps initialize the private temp root'
    Assert-True ($nativeHarnessText -match 'doctor'', ''--json-output' -and $nativeHarnessText -match 'skill'', ''scan' -and $nativeHarnessText -match 'mcp'', ''scan') 'installed artifact smoke covers doctor and scanners'
    Assert-True ($wizardHarnessText.Contains('[switch]$ActivateInstall') -and
        $wizardHarnessText -match "GITHUB_ACTIONS -ne 'true'" -and
        $wizardHarnessText -match "RUNNER_ENVIRONMENT -ne 'github-hosted'" -and
        $wizardHarnessText -match 'Resolve-SafeWindowsNativeBase' -and
        $wizardHarnessText -match 'RUNNER_TEMP or DC_WINDOWS_NATIVE_BASE_ROOT') `
        'install-driving wizard automation is restricted to disposable GitHub-hosted runner state'
    Assert-True ($wizardHarnessText -match 'EntryPoint = "SendMessageTimeoutW"' -and
        $wizardHarnessText -match 'CharSet = CharSet\.Unicode' -and
        $wizardHarnessText -match 'InstallTimeoutSeconds' -and
        $wizardHarnessText -match 'Get-BoundedWindowText') `
        'wizard automation uses bounded Unicode Win32 calls and install timeout'
    Assert-True ($wizardHarnessText -match 'function Assert-UnicodeWindowTextInterop' -and
        $wizardHarnessText -match 'DefenseClaw → installed' -and
        $wizardHarnessText -match "Write-WizardTrace 'unicode-interop-passed'") `
        'wizard automation round-trips Unicode window text before driving setup'
    Assert-True ($wizardHarnessText -match "wizard-driver\.log" -and
        $wizardHarnessText -match "Write-WizardTrace 'install-progress'" -and
        $wizardHarnessText -match "Write-WizardTrace 'install-timeout'" -and
        $wizardHarnessText -notmatch 'if \(-not \$ActivateInstall\) \{ return \}' -and
        $nativeHarnessText -match "Name -eq 'wizard-driver\.log'") `
        'wizard automation records and prioritizes bounded install and cancel diagnostics'
    foreach ($controlID in @(1001, 1002, 1003, 1009, 1011)) {
        Assert-True ($wizardHarnessText -match "Get-WizardControl \`$window $controlID") `
            "wizard automation reaches required real control id $controlID"
    }
    Assert-True ($wizardHarnessText -match "Get-WizardControl \`$window 1 'primary action'" -and
        $wizardHarnessText -match "Send-WizardCommand \`$window 2 'Cancel'") `
        'wizard automation uses standard Win32 IDOK and IDCANCEL semantics'
    Assert-True ($wizardHarnessText -match 'foreach \(\$index in 0\.\.\(\$connectorIndices\.Count - 1\)\)' -and
        $wizardHarnessText -match 'foreach \(\$index in 0\.\.1\)' -and
        $wizardHarnessText -match 'connectorIndices\s*=\s*@\{[^}]*amp\s*=\s*3' -and
        $wizardHarnessText -match 'Set-AndAssertCheckState \$startControl \$false' -and
        $wizardHarnessText -match 'Set-AndAssertCheckState \$startControl \$true') `
        'wizard automation deterministically exercises every connector, mode, and start choice'
    Assert-True ($wizardHarnessText -match "Send-WizardCommand \`$window 1 'Install'" -and
        $wizardHarnessText -match "heading -ne 'DefenseClaw is installed'" -and
        $wizardHarnessText -match "Send-WizardCommand \`$window 1 'Finish'") `
        'wizard automation activates Install and verifies the completion page before Finish'
    Assert-True ($nativeHarnessText -match "Invoke-WizardConfigureLaterAcceptance" -and
        $nativeHarnessText -match "(?s)Invoke-WizardConnectorAcceptance.*?'codex' 'observe'.*?Invoke-WizardConnectorAcceptance.*?'claudecode' 'action'.*?Invoke-WizardConnectorAcceptance.*?'amp' 'action'" -and
        $nativeHarnessText -match "foreach \(\`$wizardConnector in @\('copilot', 'cursor'\)\)") `
        'setup acceptance performs Configure Later, reference mode installs, and the established additive connector wizard lifecycle samples'
    $antigravitySupportedAvailability = [regex]::Match(
        $nativeHarnessText,
        '(?s)function Assert-PackagedAntigravitySupportedAvailability\b.*?(?=\r?\nfunction )'
    ).Value
    Assert-True ($antigravitySupportedAvailability -match
        '(?s)Invoke-Installed \$Launcher @\(.*?\)\s*\x60\s*@\(0\)\s+300\s+\$LogPath' -and
        $antigravitySupportedAvailability -match
        'connector was not detected locally; refusing action-mode hook setup' -and
        $antigravitySupportedAvailability -match 'unexpectedly wrote hooks') `
        'supported Antigravity absent-client setup succeeds after a truthful observe downgrade without writing hooks'
    foreach ($wizardChoice in @(
        'none = 0',
        'codex = 1',
        'claudecode = 2',
        'amp = 3',
        'antigravity = 4',
        'copilot = 5',
        'cursor = 6',
        'hermes = 7',
        'devin = 8',
        'omnigent = 9',
        'opencode = 10'
    )) {
        Assert-True ($wizardHarnessText.Contains($wizardChoice)) `
            "wizard driver preserves the integrated selection contract: $wizardChoice"
    }
    $wizardChoiceSource = [regex]::Match(
        $setupWizardSourceText,
        '(?s)wizardConnectorChoices = \[\]wizardChoice\{(.*?)\n\s*\}'
    ).Groups[1].Value
    $wizardChoiceValues = @([regex]::Matches($wizardChoiceSource, 'Value: "([^"]+)"') |
        ForEach-Object { $_.Groups[1].Value })
    $wizardChoiceLabels = @([regex]::Matches($wizardChoiceSource, 'Label: "([^"]+)"') |
        ForEach-Object { $_.Groups[1].Value })
    $wizardIndexSource = [regex]::Match(
        $wizardHarnessText,
        '(?s)\$connectorIndices = @\{(.*?)\r?\n\}'
    ).Groups[1].Value
    $wizardIndexValues = @([regex]::Matches(
        $wizardIndexSource,
        '(?m)^\s*([a-z]+)\s*=\s*(\d+)\s*$'
    ) | Sort-Object { [int]$_.Groups[2].Value } | ForEach-Object { $_.Groups[1].Value })
    $wizardValidateSource = [regex]::Match(
        $wizardHarnessText,
        '(?s)\[ValidateSet\((.*?)\)\]\s*\[string\]\$Connector'
    ).Groups[1].Value
    $wizardValidateValues = @([regex]::Matches($wizardValidateSource, "'([^']+)'") |
        ForEach-Object { $_.Groups[1].Value })
    $wizardLabelSource = [regex]::Match(
        $wizardHarnessText,
        '(?s)\$connectorLabels = @\((.*?)\r?\n\)'
    ).Groups[1].Value
    $wizardDriverLabels = @([regex]::Matches($wizardLabelSource, "'([^']+)'") |
        ForEach-Object { $_.Groups[1].Value })
    Assert-True (($wizardChoiceValues -join ',') -ceq ($wizardIndexValues -join ',') -and
        ($wizardChoiceValues -join ',') -ceq ($wizardValidateValues -join ',')) `
        'wizard Go choices, driver indices, and accepted connector values have exact ordered parity'
    Assert-True (($wizardChoiceLabels -join ',') -ceq ($wizardDriverLabels -join ',') -and
        $wizardChoiceLabels[8] -ceq 'Devin CLI' -and
        $wizardHarnessText -match 'Get-BoundedComboItemText \$connectorControl \$index') `
        'wizard driver verifies every rendered label and identifies canonical Devin without index drift'
    $wizardInstall = [regex]::Match(
        $nativeHarnessText,
        '(?s)function Invoke-WizardInstall\b.*?(?=\r?\nfunction )'
    ).Value
    Assert-True ($wizardInstall -match 'InstallTimeoutSeconds = 600') `
        'each interactive wizard install has a ten-minute diagnostic timeout'
    $wizardAcceptance = [regex]::Match(
        $nativeHarnessText,
        '(?s)function Invoke-WizardConnectorAcceptance\b.*?(?=\r?\nfunction )'
    ).Value
    Assert-True ($wizardAcceptance -and
        $wizardAcceptance -match 'Assert-WizardConnectorState' -and
        $wizardAcceptance -match 'Assert-WizardHookRegistration' -and
        $wizardAcceptance -match 'Assert-WizardConnectorHealth' -and
        $wizardAcceptance -match 'setup repair changed the selected' -and
        $wizardAcceptance -notmatch 'DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT') `
        'wizard connector acceptance validates canonical state, hooks, health, and repair without a contract override'
    $wizardHealth = [regex]::Match(
        $nativeHarnessText,
        '(?s)function Assert-WizardConnectorHealth\b.*?(?=\r?\nfunction )'
    ).Value
    Assert-True ($wizardHealth -match "(?s)Connector -eq 'amp'.*?Specification\.ConfigPath") `
        'Amp wizard Doctor validation requires the native plugin path rather than the hook runtime executable'
    $wizardHookValidation = [regex]::Match(
        $nativeHarnessText,
        '(?s)function Assert-WizardHookRegistration\b.*?(?=\r?\nfunction )'
    ).Value
    Assert-True ($wizardHookValidation -match
        "\.PSObject\.Properties\['disableAllHooks'\]" -and
        $wizardHookValidation -match
        '\$null -ne \$disableAllHooks -and \[bool\]\$disableAllHooks\.Value' -and
        $wizardHookValidation -notmatch '\$hookDocument\.disableAllHooks') `
        'Copilot wizard validation treats omitted disableAllHooks as enabled while rejecting explicit true'
    Assert-True ($wizardAcceptance -match 'Get-WatchdogIdentity' -and
        $wizardAcceptance -match "@\('watchdog', 'status'\)" -and
        $wizardAcceptance -match 'wizard-started watchdog' -and
        $wizardAcceptance -match 'Assert-OnlyInstalledGatewayProcesses' -and
        $wizardAcceptance -notmatch "@\('watchdog', 'start'\)") `
        'wizard lifecycle requires STARTGATEWAY to auto-start an owned gateway and watchdog'
    $legacyLauncherAcceptance = [regex]::Match(
        $nativeHarnessText,
        '(?s)function Assert-WizardCodexLegacyLauncherNeedsRepair\b.*?(?=\r?\nfunction )'
    ).Value
    $legacyLauncherFixture = [regex]::Match(
        $nativeHarnessText,
        '(?s)function Set-WizardCodexLegacyNonWaitingHook\b.*?(?=\r?\nfunction )'
    ).Value
    Assert-True ($legacyLauncherFixture -match '--event' -and
        $legacyLauncherFixture -match '--hook-contract' -and
        $legacyLauncherFixture -match '\$argumentLiterals\.Value -join '' ''') `
        'legacy Codex launcher fixture preserves current event and hook-contract bindings'
    $legacyWatchdogStop = $legacyLauncherAcceptance.IndexOf("@('watchdog', 'stop')", [StringComparison]::Ordinal)
    $legacyGatewayStop = $legacyLauncherAcceptance.IndexOf("@('stop')", [StringComparison]::Ordinal)
    $legacyFixture = $legacyLauncherAcceptance.IndexOf('Set-WizardCodexLegacyNonWaitingHook', [StringComparison]::Ordinal)
    $legacyDoctor = $legacyLauncherAcceptance.IndexOf("@('doctor', '--json-output')", [StringComparison]::Ordinal)
    Assert-True ($legacyWatchdogStop -ge 0 -and $legacyGatewayStop -gt $legacyWatchdogStop -and
        $legacyFixture -gt $legacyGatewayStop -and $legacyDoctor -gt $legacyFixture) `
        'wizard legacy-launcher validation pauses watchdog and gateway self-heal before staging the fixture'
    $autoStartAssertion = [regex]::Match(
        $nativeHarnessText,
        '(?s)function Assert-GatewayAutoStart\b.*?(?=\r?\nfunction )'
    ).Value
    Assert-True ($autoStartAssertion -match 'defenseclaw-startup\.exe' -and
        $autoStartAssertion -notmatch '\$Gateway \+ ''" start') `
        'setup acceptance binds logon startup to the no-console startup sibling without gateway CLI arguments'
    Assert-True ($nativeHarnessText -match 'installed-runtime lock fixture' -and
        $nativeHarnessText -match 'import time; time\.sleep\(300\)' -and
        $nativeHarnessText -match 'setup killed the foreground installed-runtime process' -and
        $nativeHarnessText -match 'stateHashBeforeLockedRepair' -and
        $nativeHarnessText -match 'transactionTreesAfterLockedRepair') `
        'setup locked-process acceptance preserves the foreground process and committed install tree'
    $contractFunction = [regex]::Match(
        $nativeHarnessText,
        '(?s)function Invoke-Contract\b.*?(?=\r?\nfunction Get-StateProcesses)'
    ).Value
    Assert-True ($contractFunction -match 'DefenseClawSetup-x64\.exe' -and
        $contractFunction -match "'CONNECTOR=none'" -and
        $contractFunction -match 'Assert-ManagedDistributionIntegrity' -and
        $contractFunction -match "@\('/uninstall', '/quiet', 'DELETEUSERDATA=1'\)" -and
        $contractFunction -notmatch 'Install-PackagedArtifacts' -and
        $contractFunction -notmatch 'scripts\\install\.ps1') `
        'connector contract installs, validates, and removes the exact native Setup artifact'
    $knownFolderResolver = [regex]::Match(
        $nativeHarnessText,
        '(?s)function Get-WindowsNativeCurrentUserKnownFolderPath\b.*?(?=\r?\nfunction )'
    ).Value
    $contractPathPreamble = [regex]::Match(
        $contractFunction,
        '(?s)^.*?(?=\r?\n    \$installRoot = )'
    ).Value
    Assert-True ($knownFolderResolver -match 'OpenProcessToken' -and
        $knownFolderResolver -match 'TOKEN_QUERY \| TOKEN_IMPERSONATE' -and
        $knownFolderResolver -match 'SHGetKnownFolderPath\(ref folderID, flags, token, out value\)' -and
        $contractPathPreamble -match "F1B32785-6FBA-4FCF-9D55-7B8E7F157091" -and
        $contractPathPreamble -match "3EB685DB-65F9-4CF6-A03A-E3EF65729F3D" -and
        $contractPathPreamble -match "5E6C858F-0E22-4760-9AFE-EA3317B67173" -and
        $contractPathPreamble -notmatch 'Environment\+SpecialFolder' -and
        $contractFunction.IndexOf('$env:APPDATA =', [StringComparison]::Ordinal) -gt
            $contractFunction.IndexOf("3EB685DB-65F9-4CF6-A03A-E3EF65729F3D", [StringComparison]::Ordinal)) `
        'connector contract binds Profile, LocalAppData, and RoamingAppData to the current process token before hostile environment isolation'
    Assert-True ($connectorContractJob -match '(?s)Required setup, allow/block, audit, telemetry, timeout, and teardown contract.*?matrix\.connector != ''devin''.*?invoke-windows-setup-standard-user-ci\.ps1.*?-Mode contract.*?-Connector \$env:CONNECTOR.*?-DiagnosticsRoot \$env:DC_DIAGNOSTICS' -and
        $connectorContractJob -match '(?s)Required Devin contract with one bounded infrastructure retry.*?matrix\.connector == ''devin''.*?Invoke-DevinContractAttempt' -and
        $connectorContractJob -match "timeout-minutes: \$\{\{ matrix\.connector == 'devin' && 50 \|\| 35 \}\}" -and
        $nativeWorkflowText -notmatch '\./scripts/windows-native-ci\.ps1 -Operation contract') `
        'hosted connector contracts run as disposable real standard users and preserve the matrix connector'
    $devinRetryStep = [regex]::Match(
        $connectorContractJob,
        '(?ms)^      - name: Required Devin contract with one bounded infrastructure retry.*?(?=^      - name:)'
    ).Value
    $retryCaptureIndex = $devinRetryStep.IndexOf("'-Operation', 'capture'", [StringComparison]::Ordinal)
    $retryCleanupIndex = $devinRetryStep.IndexOf("'-Operation', 'cleanup'", [StringComparison]::Ordinal)
    $retrySecondAttemptIndex = $devinRetryStep.IndexOf(
        '$second = Invoke-DevinContractAttempt 2', [StringComparison]::Ordinal
    )
    $retryCleanupFailurePrefixes = @(
        'disposable execution boundary:',
        'interactive desktop ACL restore:',
        'ancestor ACL lease restore:',
        'diagnostic handoff:',
        'account/profile cleanup:',
        'sandbox cleanup:',
        'parent-only sibling cleanup:'
    )
    Assert-True ($devinRetryStep -match '\. \$nativeHarness -NoRun' -and
        $devinRetryStep -match '\$first = Invoke-DevinContractAttempt 1' -and
        $devinRetryStep -match '\$retrySignal = ''event_history=sqlite_write_failed''' -and
        $devinRetryStep -notmatch 'rollback was incomplete' -and
        @($retryCleanupFailurePrefixes | Where-Object {
            -not $devinRetryStep.Contains("'$_'", [StringComparison]::Ordinal)
        }).Count -eq 0 -and
        $devinRetryStep -match '\$firstOutput\.Contains\(\$_, \[StringComparison\]::Ordinal\)' -and
        $devinRetryStep -match '\$cleanupFailure\.Count -ne 0' -and
        $devinRetryStep -match '-AllowedExitCodes @\(0, 1\)' -and
        $retryCaptureIndex -ge 0 -and $retryCleanupIndex -gt $retryCaptureIndex -and
        $retrySecondAttemptIndex -gt $retryCleanupIndex -and
        $devinRetryStep -match 'Test-Path -LiteralPath \$contractStateRoot' -and
        $devinRetryStep -match 'Get-StateProcesses \$contractStateRoot' -and
        $devinRetryStep -match 'attempt-\$Attempt-child' -and
        $devinRetryStep -match 'Write-BoundedText.*?devin-event-history-retry\.txt' -and
        $connectorContractJob -match 'steps\.devin_contract\.outputs\.retried == ''true''') `
        'Devin retries only the exact SQLite telemetry transient after bounded capture and complete isolated cleanup'
    Assert-True ($omniGentJob -match '(?s)invoke-windows-setup-standard-user-ci\.ps1.*?-Mode omnigent-native-degraded.*?-DiagnosticsRoot \$env:DC_DIAGNOSTICS' -and
        $standardUserCIText -match "'omnigent-native-degraded'" -and
        $standardUserCIText -match 'test-omnigent-windows-native\.ps1' -and
        $standardUserCIText -match 'SpecialFolder\]::LocalApplicationData' -and
        $standardUserCIText -match 'Join-Path \$localAppData ''DefenseClaw-CI\\uv-input''' -and
        $standardUserCIText -match 'Join-Path \$localAppData ''DefenseClaw-CI\\omnigent-native-degraded''' -and
        $standardUserCIText -match 'Set-DisposableProtectedDirectoryAcl \$state \$identity\.User' -and
        $standardUserCIText -match '(?s)Set-DisposableProtectedDirectoryAcl \$state \$identity\.User.*?-UseAdministratorsForCleanup' -and
        $standardUserCIText -match '(?s)Set-DisposableProtectedDirectoryAcl \$uvRoot \$identity\.User.*?-UseAdministratorsForCleanup' -and
        $standardUserCIText -match 'Assert-DisposableChildAcl \$uvRoot \$identity\.User' -and
        $standardUserCIText -match '(?s)Set-DisposableProtectedDirectoryAcl \$omnigentState \$identity\.User.*?-UseAdministratorsForCleanup' -and
        $standardUserCIText -match 'Assert-DisposableChildAcl \$omnigentState \$identity\.User' -and
        $standardUserCIText -match 'standard-user OmniGent uv copy does not match its authenticated input' -and
        $standardUserCIText -match '(?s)-StateRoot \$omnigentState -ArtifactRoot \$artifacts.*?-UvPath \$uvPath') `
        'hosted OmniGent packaged lifecycle runs as a disposable real standard user'
    Assert-True ($nativeWorkflowText -notmatch '-Operation acceptance\b' -and
        $nativeHarnessText -notmatch "'acceptance' \{ Invoke-Acceptance \}" -and
        $nativeWorkflowText -match 'invoke-windows-setup-standard-user-ci\.ps1' -and
        $nativeWorkflowText -match '-Mode setup-acceptance') `
        'required lifecycle certification no longer routes through the legacy wheel materializer'
    $standardUserSafetyText = Get-Content -LiteralPath $standardUserSafety -Raw
    $standardUserFileGuardText = Get-Content -LiteralPath $standardUserFileGuard -Raw
    $standardUserChildPreamble = [regex]::Match(
        $standardUserCIText,
        '(?s)function Invoke-ChildMode\b.*?(?=\r?\n    \$sandboxRoot = )'
    ).Value
    $standardUserLauncherStart = [regex]::Match(
        $standardUserLauncherText,
        '(?s)public static DisposableStandardUserProcess Start\b.*?(?=\r?\n        private static IntPtr OpenToken)'
    ).Value
    $sameLiveProcessFunction = [regex]::Match(
        $standardUserCIText,
        '(?s)function Get-SameLiveProcess\b.*?(?=\r?\nfunction )'
    ).Value
    $contractHarnessFiles = [regex]::Match(
        $standardUserCIText,
        '(?s)if \(\$Mode -eq ''contract''\) \{\s*\$harnessFiles \+= @\(.*?\)\s*\}'
    ).Value
    Assert-True ($contractHarnessFiles -match '''prepare-windows-contract-v8\.py''' -and
        $contractHarnessFiles -match '''live-connector-e2e\\project-audit-events\.py''') `
        'disposable standard-user contracts carry the canonical v8 configuration and audit projection helpers'
    Assert-True ($standardUserCIText -match 'New-LocalUser' -and
        $standardUserCIText -match 'Remove-DisposableProfileAndAccount' -and
        $standardUserCIText -match 'DefenseClaw disposable Setup CI account' -and
        $standardUserCIText -match '\^dcacc\[0-9a-f\]\{10\}\$' -and
        $standardUserCIText -match 'private disposable-user sandbox layout' -and
        $standardUserCIText -match 'Set-DisposableProtectedDirectoryAcl \$sandbox' -and
        $standardUserCIText -match 'Set-DisposableProtectedDirectoryAcl \$workspace' -and
        $standardUserCIText -match 'Set-DisposableProtectedDirectoryAcl \$childArtifacts' -and
        $standardUserCIText -match 'Set-DisposableProtectedDirectoryAcl \$childState \$sidObject' -and
        $standardUserCIText -match '\[Security\.AccessControl\.FileSystemRights\]::FullControl\) -InheritChildRights' -and
        $standardUserCIText -match 'AllowOwnershipBootstrap' -and
        $standardUserCIText -match 'Set-DisposableProtectedDirectoryAcl \$directory \$sidObject' -and
        $standardUserCIText -match 'Assert-DisposableChildAcl \$sandbox' -and
        $standardUserCIText -match '\$childResults = Join-Path \$sandbox ''results''' -and
        $standardUserCIText -match '\$result = Join-Path \$childResults ''result\.json''' -and
        $standardUserCIText -match 'GrantInteractiveDesktop' -and
        $standardUserCIText -match 'Get-LocalGroupMember -SID \$administratorsSid' -and
        $standardUserCIText -match '-Operation setup-acceptance' -and
        $standardUserCIText -match '-Operation contract -Connector \$Connector' -and
        $standardUserCIText -match '\$arguments \+= @\(''-Connector'', \$Connector\)' -and
        $standardUserCIText -match 'live-connector-e2e\\run-windows\.ps1' -and
        $standardUserCIText -match "ValidateSet\('codex', 'claudecode', 'amp', 'copilot', 'cursor', 'devin', 'hermes', 'antigravity', 'opencode'\)" -and
        $standardUserCIText.Contains('live-connector-e2e\golden\$Connector\pre_tool_allow.json') -and
        $standardUserCIText.Contains('live-connector-e2e\golden\$Connector\pre_tool_block.json') -and
        $standardUserCIText.Contains('live-connector-e2e\golden\$Connector\session_start.json') -and
        $standardUserCIText.Contains('live-connector-e2e\golden\amp\agent_start.json') -and
        $standardUserCIText.Contains('live-connector-e2e\golden\amp\tool_result.json') -and
        $standardUserCIText.Contains('live-connector-e2e\golden\amp\subagent_tool_call.json') -and
        $standardUserCIText.Contains('live-connector-e2e\golden\amp\agent_end.json') -and
        $standardUserCIText -match '\$env:RUNNER_TEMP = Split-Path -Parent \$state' -and
        $standardUserCIText -match 'Remove-Item Env:DC_WINDOWS_NATIVE_BASE_ROOT' -and
        $standardUserCIText -notmatch '\$env:DC_WINDOWS_NATIVE_BASE_ROOT = \$state' -and
        $standardUserCIText -notmatch '(?i)password\s*=\s*["''][^"'']+["'']') `
        'hosted Setup lifecycle uses a verified disposable standard user without weakening state containment or persisting a credential'
    Assert-True ($nativeHarnessText -match 'DefenseClawWindowsResourceVerifier-x64\.exe' -and
        $nativeHarnessText -match "'build', '-trimpath', '-buildvcs=false'" -and
        $nativeHarnessText -match '\./internal/tools/windowsresources' -and
        $nativeHarnessText -match 'DefenseClawWindowsResourceIcon\.png' -and
        $nativeHarnessText -match 'DefenseClawWindowsResourceVersion\.txt' -and
        $standardUserCIText -match
            '(?s)\$resourceVerifierInputs = if \(\$Mode -eq ''bootstrap-acceptance''\) \{\s*@\(\)\s*\} else \{\s*@\(' -and
        $standardUserCIText -match '\[IO\.File\]::Copy\(\$source, \$destination, \$false\)') `
        'packaged lifecycle carries an offline immutable Windows resource verifier into the disposable child'
    Assert-True ($standardUserCIText -match 'Publish-BoundedDisposableContractResults' -and
        $standardUserCIText -match 'Read-BoundedDisposableResult \$SourcePath \$SourceRoot 1048576' -and
        $standardUserCIText -match '\[string\]\$record\.os -cne ''windows''' -and
        $standardUserCIText -match '(?s)Complete-DisposableExecutionBoundary.*?\$executionBoundaryComplete = \$true.*?Publish-BoundedDisposableContractResults' -and
        $standardUserCIText -match "contract passed without producing bounded results\.jsonl") `
        'contract results are identity-checked, bounded, and handed to the parent only after job and SID drain'
    Assert-True ($standardUserCIText -match '(?s)child-entry.*?windows-native-paths\.ps1.*?file-guard-load-start.*?windows-disposable-user-safety\.ps1.*?file-guard-load-complete' -and
        $standardUserCIText -match "'-NoLogo', '-NoProfile', '-NonInteractive', '-File'" -and
        $standardUserCIText -match '''-ExpectedChildSid'', \$accountSid' -and
        $standardUserCIText -match '\[string\]\$ExpectedChildSid' -and
        $standardUserChildPreamble -match '\$identity\.User\.Equals\(\$expectedSid\)' -and
        $standardUserChildPreamble -notmatch 'Get-LocalUser|Add-Type|IsCurrentProcessElevated|Test-IsAdministrator') `
        'disposable child records startup before helper loading and validates the parent-bound SID without provider-dependent identity work'
    Assert-True ($standardUserLauncherText -match 'CreateProcessWithLogonW' -and
        $standardUserLauncherText -match 'LOGON_WITH_PROFILE' -and
        $standardUserLauncherText -match 'SecureString password' -and
        $standardUserLauncherText -match 'JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE' -and
        $standardUserLauncherText -match 'QueryInformationJobObject' -and
        $standardUserLauncherText -match 'TerminateAndDrain' -and
        $standardUserLauncherText -match 'ActiveProcesses' -and
        $standardUserLauncherText -match 'InteractiveDesktopGrant' -and
        $standardUserLauncherText -match 'S-1-5-32-544' -and
        $standardUserLauncherText -notmatch 'WindowsPrincipal' -and
        $standardUserLauncherText -match 'TokenIsElevated != 0') `
        'disposable-user launcher validates identity/elevation and bounds the complete process tree'
    Assert-True ($standardUserLauncherStart -match 'CREATE_SUSPENDED\s*\|\s*CREATE_NEW_CONSOLE\s*\|\s*CREATE_UNICODE_ENVIRONMENT' -and
        $standardUserLauncherStart -match 'startupInfo\.dwFlags\s*=\s*STARTF_USESHOWWINDOW' -and
        $standardUserLauncherStart -match 'startupInfo\.wShowWindow\s*=\s*SW_HIDE' -and
        $standardUserLauncherStart -notmatch 'CREATE_NO_WINDOW' -and
        $standardUserLauncherStart -notmatch 'startupInfo\.lpDesktop\s*=') `
        'disposable PowerShell starts with hidden console-backed stdio on the exact inherited desktop'
    Assert-True ($standardUserLauncherText -match 'WaitForExitAndGetExitCode\s*\(' -and
        $standardUserLauncherText -match 'WaitForSingleObject\s*\(' -and
        $standardUserLauncherText -match 'GetExitCodeProcess\s*\(' -and
        $standardUserLauncherText -match 'processInfo\.hProcess\s*=\s*IntPtr\.Zero' -and
        $standardUserLauncherText -notmatch 'process\.WaitForExit\s*\(' -and
        $standardUserCIText -match '\.WaitForExitAndGetExitCode\s*\(' -and
        $standardUserCIText -match '\[ref\]\$exitCode') `
        'disposable-user wrapper retains the authoritative native handle and captures the root exit code'
    Assert-True ($standardUserCIText -match 'Disable-LocalUser' -and
        $standardUserCIText -match 'GetOwnerSid' -and
        $standardUserCIText -match 'Stop-AndVerifyDisposableSidProcesses' -and
        $standardUserCIText -match 'Remove-AndVerifyDisposableScheduledTasks' -and
        $standardUserCIText -match 'WMI escape fixture' -and
        $standardUserCIText -match '-OperationTimeoutSec 30' -and
        $standardUserCIText -match "(?s)if \(\`$Mode -eq 'setup-acceptance'\) \{\s*\`$arguments \+= '-ExerciseWmiEscape'" -and
        $standardUserCIText -match 'wmi-escape-pid\.txt' -and
        $standardUserCIText -match 'progress\.log' -and
        $standardUserCIText -match 'child-cleanup-delegated-to-parent' -and
        $standardUserCIText -match 'wizard trace:' -and
        $standardUserCIText -match 'Complete-DisposableExecutionBoundary' -and
        $standardUserCIText -notmatch 'Copy-Item[^\r\n]*-Recurse') `
        'privileged handoff drains the job, disables the account, sweeps exact-SID escapes, and avoids recursive copies'
    Assert-True ($standardUserCIText -match 'Get-UnverifiableProcessBaseline' -and
        [regex]::Matches(
            $standardUserCIText,
            '\$unverifiableProcessBaseline = Get-UnverifiableProcessBaseline'
        ).Count -ge 2 -and
        $standardUserCIText -match 'Get-DisposableProcessIdentityKey' -and
        $sameLiveProcessFunction -match '\$processId = \[int\]\$Process\.ProcessId' -and
        $sameLiveProcessFunction -match 'if \(\$processId -le 0\) \{ return \$null \}' -and
        $sameLiveProcessFunction -match '(?s)catch \{.*?Get-CimInstance Win32_Process -ErrorAction Stop.*?Where-Object' -and
        $standardUserCIText -match '(?s)Stop-AndVerifyDisposableSidProcesses.*?Get-SameLiveProcess \$process' -and
        $standardUserSafetyText -match 'Assert-UnverifiableProcessWasBaselined' -and
        $standardUserCIText -match 'owner SID became unverifiable for exact-SID process') `
        'process teardown baselines exact PID/CreationDate unknowns before launch and fails closed on reuse or second-check errors'
    Assert-True ($standardUserSafetyText -match 'Copy-BoundedDisposableDiagnostics' -and
        $standardUserSafetyText -match 'MaximumFileBytes' -and
        $standardUserSafetyText -match 'MaximumTotalBytes' -and
        $standardUserSafetyText -match 'ReparsePoint' -and
        $standardUserSafetyText -match 'Remove-DisposableTreeSafely' -and
        $standardUserSafetyText -match 'CopyBoundedRegularFile' -and
        $standardUserSafetyText -match 'ReadBoundedUtf8' -and
        $standardUserFileGuardText -match 'FILE_FLAG_OPEN_REPARSE_POINT' -and
        $standardUserFileGuardText -match 'GetFileInformationByHandle' -and
        $standardUserFileGuardText -match 'NumberOfLinks != 1' -and
        $standardUserFileGuardText -match 'FileMode\.CreateNew') `
        'diagnostic/result handoff validates and consumes one no-follow, single-link regular-file handle'
    $captureSelectionFunction = [regex]::Match(
        $nativeHarnessText,
        '(?s)function Get-WindowsNativeCaptureFiles\b.*?(?=\r?\nfunction )'
    ).Value
    $rotationReasonFunction = [regex]::Match(
        $nativeHarnessText,
        '(?s)function Get-PackagedRotationFailureReason\b.*?(?=\r?\nfunction )'
    ).Value
    $rotationDiagnosticFunction = [regex]::Match(
        $nativeHarnessText,
        '(?s)function Write-PackagedRotationFailureDiagnostic\b.*?(?=\r?\nfunction )'
    ).Value
    $packagedRotationFunction = [regex]::Match(
        $nativeHarnessText,
        '(?s)function Assert-PackagedClaudeTokenRotation\b.*?(?=\r?\nfunction )'
    ).Value
    $captureFunction = [regex]::Match(
        $nativeHarnessText,
        '(?s)function Invoke-Capture\b.*?(?=\r?\nfunction )'
    ).Value
    Assert-True ($captureSelectionFunction -match 'SortedDictionary\[string, IO\.FileInfo\]' -and
        $captureSelectionFunction -match '\$selectionLimit = 30' -and
        $captureSelectionFunction -match "Name -ceq 'rotation-failure\.json'\) \{ -4 \}" -and
        $captureSelectionFunction -match "Name -match '\^rotation-\.\*\\\.log\$'\) \{ -3 \}" -and
        $captureSelectionFunction -match "Name -match '\^\(\?:gateway\|watchdog\)\.\*.*?\) \{ -2 \}" -and
        $captureSelectionFunction -match "Name -ceq 'setup-seeded-health\.jsonl'\) \{ -1 \}" -and
        $captureSelectionFunction -notmatch '\$matches\b' -and
        $captureSelectionFunction -notmatch '\$visited\b' -and
        $rotationReasonFunction -match 'switch -CaseSensitive' -and
        $rotationReasonFunction -match "return 'unclassified-cli-exit'" -and
        $rotationDiagnosticFunction -match '(?s)schema = 1.*?exit = \$ExitCode.*?reason = \$Reason' -and
        $rotationDiagnosticFunction -match 'Write-BoundedText.*?-MaxBytes 4096' -and
        $rotationDiagnosticFunction -notmatch '\$(?:StdOut|StdErr)' -and
        $packagedRotationFunction -match '(?s)setup'', ''rotate-token'', ''--yes''.*?-AllowedExitCodes @\(0, 1\) -TimeoutSeconds 1200' -and
        $packagedRotationFunction -match 'Join-Path \$Logs ''rotation-failure\.json''' -and
        $captureFunction -match 'DisposableFileGuard\]::OpenRootedReader\(\$root\)' -and
        $captureFunction -match 'ReadBoundedUtf8\(\$file\.FullName, 1048576\)' -and
        $captureFunction -notmatch 'ReadAllText\(\$file\.FullName\)' -and
        $standardUserFileGuardText -match 'sealed class RootedReader' -and
        $standardUserFileGuardText -match 'GetFinalPathNameByHandleW' -and
        $standardUserFileGuardText -match 'guarded file resolved outside its retained root' -and
        $nativeHarnessText -match 'leaf replaced by a reparse point after enumeration' -and
        $nativeHarnessText -match 'replaced ancestor outside its retained root') `
        'native capture exhaustively selects priority logs and reads only retained-root no-follow handles'
    Assert-True ($standardUserSafetyText -match 'function Grant-DisposableAncestorReadLease' -and
        $standardUserSafetyText -match 'function Restore-DisposableAncestorReadLease' -and
        $standardUserSafetyText -match '(?s)Grant-DisposableAncestorReadLease.*?FileSystemRights\]::ReadAndExecute.*?InheritanceFlags\]::None.*?PropagationFlags\]::None' -and
        $standardUserSafetyText -match 'GetSecurityDescriptorBinaryForm' -and
        $standardUserSafetyText -match 'SetSecurityDescriptorBinaryForm' -and
        $standardUserCIText -match '(?s)Grant-DisposableAncestorReadLease.*?\$stateBoundary \$stateBase \$sidObject' -and
        $standardUserCIText -match '(?s)if \(\$executionBoundaryComplete -and \$ancestorReadLease\.Count -ne 0\).*?Restore-DisposableAncestorReadLease') `
        'disposable-user provider traversal uses an exact non-inheriting ACL lease restored only after process drain'
    Assert-True ($standardUserCIText -match 'Test-ActualChildFilesystemBoundary' -and
        $standardUserSafetyText -match 'function Assert-ChildOperationAccessDenied' -and
        $standardUserCIText -match 'Setup overwrite probe' -and
        $standardUserCIText -match 'Setup delete probe' -and
        $standardUserCIText -match 'rename probe' -and
        $standardUserCIText -match 'delete probe' -and
        $standardUserCIText -match 'replacement probe' -and
        $standardUserCIText -match 'Get-ChildItem -LiteralPath \$providerNested' -and
        $standardUserCIText -match 'Remove-Item -LiteralPath \$providerFile' -and
        $standardUserCIText -match 'parent-only sibling read probe' -and
        $standardUserCIText -match 'parent-only sibling write probe' -and
        $standardUserCIText -match 'actual child immutability probe changed the exact Setup bytes') `
        'the real disposable child proves protected payload denial, provider deletion, and sibling isolation before Setup'
    Assert-True ($setupStandardUserLauncherText -match 'TokenLinkedToken' -and
        $setupStandardUserLauncherText -match 'TokenElevationTypeLimited' -and
        $setupStandardUserLauncherText -match 'ValidateStandardUserPrimaryToken' -and
        $setupStandardUserLauncherText -match 'CurrentElevatedTokenHasLinkedLimitedToken' -and
        $setupStandardUserLauncherText -match 'allowRestrictedLuaFallback' -and
        $setupStandardUserLauncherText -notmatch 'TryGetLinkedToken' -and
        $nativeHarnessText -match 'restricted LUA fallback is prohibited' -and
        $nativeHarnessText -match 'verified-linked-limited-token' -and
        $nativeHarnessText -match 'requires-disposable-standard-user') `
        'Setup launcher fails linked-token query errors and prohibits restricted-LUA fallback in certification'
    $restrictedLuaTokenFunction = [regex]::Match(
        $setupStandardUserLauncherText,
        '(?sm)private static IntPtr CreateRestrictedLuaToken\b.*?^        \}'
    ).Value
    $restrictedDefaultDaclFunction = [regex]::Match(
        $setupStandardUserLauncherText,
        '(?sm)private static void SetRestrictedTokenDefaultDacl\b.*?^        \}'
    ).Value
    Assert-True ($restrictedLuaTokenFunction -match
            'WindowsIdentity\(sourceToken\)' -and
        $restrictedLuaTokenFunction -match 'GetTokenLogonSid\(sourceToken\)' -and
        $restrictedLuaTokenFunction -match 'WellKnownSidType\.WorldSid' -and
        $restrictedLuaTokenFunction -match 'restrictingSids\[index\]\.GetBinaryForm' -and
        $restrictedLuaTokenFunction -match 'Attributes = 0' -and
        $restrictedLuaTokenFunction -match
            'DISABLE_MAX_PRIVILEGE \| LUA_TOKEN \| WRITE_RESTRICTED' -and
        $restrictedLuaTokenFunction -match
            '(?s)IntPtr\.Zero,\s*\(uint\)restrictingSids\.Length,\s*restrictingSidBuffer,\s*out restrictedToken' -and
        $restrictedLuaTokenFunction -match
            '(?s)SetRestrictedTokenDefaultDacl\(\s*restrictedToken,\s*restrictingSids\[1\]\)' -and
        $setupStandardUserLauncherText -match 'SE_GROUP_LOGON_ID' -and
        $setupStandardUserLauncherText -match 'TOKEN_ADJUST_DEFAULT' -and
        $setupStandardUserLauncherText -match
            'SetTokenInformation\(TokenDefaultDacl\) failed for restricted LUA token' -and
        $setupStandardUserLauncherText -match 'GetTokenInformationBuffer' -and
        $setupStandardUserLauncherText -match
            'restricted LUA source token has an invalid logon SID set' -and
        $setupStandardUserLauncherText -match
            'launchToken = CreateRestrictedLuaToken\(sourceToken\)' -and
        $setupStandardUserLauncherText -match
            'if \(!IsTokenRestricted\(token\)\)') `
        'restricted-LUA fallback uses exact account, logon, and World write-restriction SIDs with fail-closed validation'
    Assert-True ($restrictedDefaultDaclFunction -match
            '(?s)allowedSids = new SecurityIdentifier\[\].*?\{\s*logonSid\s*\}' -and
        $restrictedDefaultDaclFunction -match
            'AccessPermissions = GENERIC_ALL' -and
        $restrictedDefaultDaclFunction -match 'AccessMode = GRANT_ACCESS' -and
        $restrictedDefaultDaclFunction -match 'TrusteeForm = TRUSTEE_IS_SID' -and
        $restrictedDefaultDaclFunction -match 'TrusteeType = TRUSTEE_IS_GROUP' -and
        $restrictedDefaultDaclFunction -match
            '(?s)SetEntriesInAcl\(\s*\(uint\)allowedSids\.Length,\s*entryBuffer,\s*IntPtr\.Zero,\s*out newAcl\)' -and
        $restrictedDefaultDaclFunction -match
            'SetTokenInformationDefaultDacl' -and
        $restrictedDefaultDaclFunction -notmatch 'WorldSid|LocalSystemSid|userSid|AdministratorsSid') `
        'restricted-LUA fallback replaces inherited administrator defaults with exact logon-session IPC access'
    Assert-True ($setupStandardUserLauncherText -match
            '(?s)process = Process\.GetProcessById\(.*?process\.Handle == IntPtr\.Zero.*?ResumeThread\(processInfo\.hThread\)') `
        'restricted Setup retains the exact suspended child handle before it can exit'
    Assert-True ([regex]::Matches(
            $standardUserCIText,
            'DisposableFileGuard\]::ComputeSha256Hex'
        ).Count -ge 4 -and
        $standardUserCIText -match 'exact Setup artifact hash changed during') `
        'disposable acceptance revalidates the exact single-link Setup handle before and after the lifecycle'
    Assert-True ($releaseWorkflowText -match 'invoke-windows-setup-standard-user-ci\.ps1' -and
        $releaseWorkflowText -match '-Mode setup-acceptance' -and
        $releaseWorkflowText -notmatch '(?s)Validate the exact installer lifecycle.*?-AllowCurrentUserSetupAcceptance') `
        'Setup acceptance uses the same real standard-user boundary'
    Assert-True ($nativeWorkflowText -match 'Always clean isolated processes, listeners, and temp state') 'required jobs have cleanup safety nets'
    $pathSnapshotFunction = [regex]::Match(
        $nativeHarnessText,
        '(?s)function Get-UserPathRegistrySnapshot\b.*?(?=\r?\nfunction )'
    ).Value
    Assert-True ($pathSnapshotFunction -match 'GetValueNames' -and
        $pathSnapshotFunction -match 'GetValueKind' -and
        $pathSnapshotFunction -match 'DoNotExpandEnvironmentNames') `
        'PATH lifecycle snapshots distinguish a missing value from an empty value and preserve registry type/raw text'
    Assert-True ($contractFunction -match 'Get-UserPathRegistrySnapshot' -and
        $contractFunction -match 'Assert-UserPathRegistrySnapshot' -and
        $contractFunction -match 'restore the original user PATH exactly') `
        'native Setup connector contract proves uninstall restores exact PATH registry existence, type, and value'
    $setupAcceptanceFunction = [regex]::Match(
        $nativeHarnessText,
        '(?s)function Invoke-SetupAcceptance\b.*?(?=\r?\nfunction Invoke-Contract)'
    ).Value
    $defaultOwnerFunction = [regex]::Match(
        $nativeHarnessText,
        '(?s)function Set-CurrentUserAsDefaultOwner\b.*?(?=\r?\nfunction )'
    ).Value
    Assert-True ($nativeHarnessText -match 'function Test-WindowsNativeProcessElevated\b' -and
        $nativeHarnessText -match 'WindowsBuiltInRole\]::Administrator' -and
        $defaultOwnerFunction -match 'if \(-not \(Test-WindowsNativeProcessElevated\)\) \{ return \}' -and
        $defaultOwnerFunction.IndexOf('Test-WindowsNativeProcessElevated') -lt
            $defaultOwnerFunction.IndexOf('Add-Type')) `
        'hosted owner normalization runs only in an actually elevated process'
    Assert-True ($setupAcceptanceFunction -notmatch '\$env:DC_WINDOWS_NATIVE_BASE_ROOT\s*=' -and
        $contractFunction -notmatch '\$env:DC_WINDOWS_NATIVE_BASE_ROOT\s*=' -and
        $standardUserCIText -match '\$env:RUNNER_TEMP = Split-Path -Parent \$state' -and
        $standardUserCIText -match 'Remove-Item Env:DC_WINDOWS_NATIVE_BASE_ROOT') `
        'non-elevated hosted children keep parent-owned state under RUNNER_TEMP without publishing an out-of-profile native base'
    $agentFixtureFunction = [regex]::Match(
        $nativeHarnessText,
        '(?s)function New-WizardAgentFixtures\b.*?(?=\r?\nfunction Remove-WizardAgentFixtures)'
    ).Value
    $agentFixtureCleanupFunction = [regex]::Match(
        $nativeHarnessText,
        '(?s)function Remove-WizardAgentFixtures\b.*?(?=\r?\nfunction )'
    ).Value
    Assert-True ($agentFixtureFunction -match "'OpenAI\\Codex\\bin'" -and
        $agentFixtureFunction -match "'\.local\\bin'" -and
        $agentFixtureFunction -match 'app-server' -and
        $agentFixtureFunction -match 'configRequirements/read' -and
        $agentFixtureFunction -match 'allowManagedHooksOnly.*false' -and
        $agentFixtureFunction -match 'SearchPath = \$claudeBin' -and
        $agentFixtureFunction -match 'AmpVersionFixture' -and
        $agentFixtureFunction -match 'amp 0\.0\.1785334225-g9abe75' -and
        $agentFixtureFunction -match 'AmpPath = \$ampPath' -and
        $agentFixtureFunction -notmatch 'SearchPath = @\(\$codexBin' -and
        $agentFixtureFunction -notmatch 'DEFENSECLAW_TRUSTED_BIN_PREFIXES') `
        'Windows fixtures exercise native Codex, Claude Code, and Amp discovery without env-only trust'
    Assert-True ($agentFixtureFunction -match
        '\$hermesBin = Join-Path \$localAppData ''hermes\\hermes-agent\\venv\\Scripts''' -and
        $agentFixtureFunction -match 'HermesVersionFixture' -and
        $agentFixtureFunction -match 'Hermes Agent v0\.20\.0 \(2026\.8\.3\)' -and
        $agentFixtureFunction -match 'HermesPath = \$hermesPath' -and
        $agentFixtureFunction -match
        '\$openCodeBin = Join-Path \$localAppData ''Microsoft\\WinGet\\Packages\\SST\.opencode_Microsoft\.Winget\.Source_8wekyb3d8bbwe''' -and
        '\$openCodePath = Join-Path \$openCodeBin ''opencode\.exe''' -and
        $agentFixtureFunction -match 'OpenCodeVersionFixture' -and
        $agentFixtureFunction -match 'opencode 1\.18\.11' -and
        $agentFixtureFunction -match "(?s)foreach \(\`$attempt in 1\.\.3\).*?\`$openCodePath @\('--version'\) -TimeoutSeconds 2" -and
        $agentFixtureFunction -match 'OpenCodePath = \$openCodePath' -and
        $agentFixtureCleanupFunction -match 'Fixtures\.HermesPath' -and
        $agentFixtureCleanupFunction -match 'Fixtures\.HermesBin' -and
        $agentFixtureCleanupFunction -match 'Fixtures\.OpenCodePath' -and
        $agentFixtureCleanupFunction -match 'Fixtures\.OpenCodeBin') `
        'Windows fixtures provision and clean supported Hermes and OpenCode executables only in built-in trusted prefixes'
    Assert-True ($setupAcceptanceFunction -match 'New-WizardAgentFixtures' -and
        $setupAcceptanceFunction -match 'Remove-WizardAgentFixtures' -and
        $setupAcceptanceFunction -notmatch 'DEFENSECLAW_TRUSTED_BIN_PREFIXES') `
        'interactive Setup acceptance owns and cleans built-in-root fixtures without environment trust authority'
    Assert-True ($setupAcceptanceFunction -match "(?s)'setup', 'claude-code', '--yes', '--no-restart'.*?'setup', 'amp', '--yes', '--no-restart'.*?'setup', 'cursor', '--yes', '--no-restart'" -and
        $setupAcceptanceFunction -match 'foreach \(\$expectedConnector in @\(''codex'', ''claudecode'', ''amp'', ''cursor''\)\)' -and
        $setupAcceptanceFunction -match '(?s)connectors:\r?\n\s+amp: \{\}\r?\n\s+codex: \{\}\r?\n\s+claudecode: \{\}\r?\n\s+cursor: \{\}' -and
        $setupAcceptanceFunction -match '\{"amp", "codex", "claudecode", "cursor"\}' -and
        $setupAcceptanceFunction -match '\$expectedRosterBeforeRepair = @\(''amp'', ''claudecode'', ''codex'', ''cursor''\)' -and
        $setupAcceptanceFunction -match '(?s)if \(\(@\(\$rosterBeforeRepair \| Sort-Object\) -join "`0"\) -cne\s+\(@\(\$expectedRosterBeforeRepair \| Sort-Object\) -join "`0"\)\)' -and
        $setupAcceptanceFunction -match '(?s)\$configHashBeforeRepair = \(Get-FileHash -LiteralPath \$configPath -Algorithm SHA256\)\.Hash.*?\$configHashAfterRepair = \(Get-FileHash -LiteralPath \$configPath -Algorithm SHA256\)\.Hash' -and
        $setupAcceptanceFunction.Contains('if ($configHashAfterRepair -cne $configHashBeforeRepair)') -and
        $setupAcceptanceFunction -match '(?s)if \(\(@\(\$repairedRoster \| Sort-Object\) -join "`0"\) -cne\s+\(@\(\$rosterBeforeRepair \| Sort-Object\) -join "`0"\)\)' -and
        $setupAcceptanceFunction -notmatch '\(@\(\$roster \| Sort-Object\) -join "`0"\)\) \{' -and
        $setupAcceptanceFunction -match 'Assert-NativeConnectorCleanupAuthorityPresent \$dataRoot \$repairedRoster' -and
        $setupAcceptanceFunction -match 'Assert-NativeConnectorBackupMarkersConsumed \$dataRoot' -and
        $setupAcceptanceFunction -match 'foreach \(\$configuredConnector in @\(''codex'', ''claudecode'', ''amp'', ''copilot'', ''cursor'', ''antigravity''\)\)' -and
        $setupAcceptanceFunction -match "Get-NativeConnectorBackupMarkers \`$dataRoot 'windsurf'") `
        'packaged Setup preserves and migrates the exact staged connector roster with complete supported cleanup custody'
    Assert-True ($setupAcceptanceFunction -match '\$cachedSetup' -and
        $setupAcceptanceFunction -match 'Join-Path \$cacheRoot ''DefenseClawSetup-x64\.exe''' -and
        $setupAcceptanceFunction -match '-AllowedExitCodes @\(3010\)' -and
        $setupAcceptanceFunction -match 'uninstall-cleanup\.json' -and
        $setupAcceptanceFunction -match '''pending-reboot''' -and
        $setupAcceptanceFunction -match '''converged''') `
        'native Setup acceptance proves exact 3010 and authenticated same-boot pending cleanup custody'
    Assert-True ($setupAcceptanceFunction -match
        '\(\$terminalProperties -join '',''\) -cne ''phase,schema_version''' -and
        $setupAcceptanceFunction -notmatch '\$legacyJournal\.transaction') `
        'native Setup acceptance treats the completed journal only as the frozen terminal tombstone'
    Assert-True ($contractFunction -match
        '(?s)/uninstall.*?-AllowedExitCodes @\(3010\).*?setup-contract-uninstall\.log') `
        'packaged connector contract accepts only restart-required full-uninstall success'
    Assert-True ($nativeHarnessText -match '-StateRoot \$contractProfileRoot -HomeRoot \$contractHome -NativeDataRoot \$dataRoot' -and
        $nativeHarnessText -match '-AllowNativeDataRoot' -and
        $harnessText -match 'NativeDataRoot is restricted to an explicitly authorized packaged contract run' -and
        $harnessText -match 'NativeDataRoot must be the current Windows user Known-Folder data root') `
        'packaged connector contract binds Doctor and hooks to the installed native data root'
    Assert-True ($contractFunction -match 'New-WizardAgentFixtures' -and
        $contractFunction -match 'Remove-WizardAgentFixtures') `
        'packaged connector contracts use and clean deterministic production-shaped native agent fixtures'
    $cleanupFunction = [regex]::Match($nativeHarnessText, '(?s)function Invoke-Cleanup \{.*?\n\}').Value
    $stateProcessesFunction = [regex]::Match(
        $nativeHarnessText,
        '(?s)function Get-StateProcesses\(.*?\n\}'
    ).Value
    Assert-True ($stateProcessesFunction -match 'ParentProcessId' -and
        $stateProcessesFunction -match 'ExecutablePath' -and
        $stateProcessesFunction -match '-StateRoot') `
        'cleanup excludes caller ancestry and requires rooted process evidence'
    Assert-True ($cleanupFunction -notmatch "@\('stop'\)" -and
        $cleanupFunction -match 'Stop-StateProcesses' -and
        $cleanupFunction -match 'Remove-SafeDisposableTree') `
        'fresh-step cleanup is process-scoped and removes without reparse traversal'

    Assert-True ($liveWorkflowText -match '(?s)windows-live:.*?connector: \[codex, claudecode, amp, cursor, opencode\].*?report:') 'manual Windows live matrix contains Codex, Claude, Amp, Cursor, and OpenCode'
    $installAgentContract = [regex]::Match(
        $harnessText,
        '(?s)function Install-Agent\b.*?(?=\r?\nfunction )'
    ).Value
    $claudeInstallerFetchContract = [regex]::Match(
        $harnessText,
        '(?s)function Get-OfficialClaudeInstallerScriptBlock\b.*?(?=\r?\nfunction )'
    ).Value
    $claudeInstallerBodyContract = [regex]::Match(
        $harnessText,
        '(?s)function ConvertTo-OfficialClaudeInstallerScriptBlock\b.*?(?=\r?\nfunction )'
    ).Value
    $claudeClientPathContract = [regex]::Match(
        $harnessText,
        '(?s)function Get-OfficialClaudeClientPath\b.*?(?=\r?\nfunction )'
    ).Value
    $claudeClientIdentityContract = [regex]::Match(
        $harnessText,
        '(?s)function Assert-OfficialClaudeClientIdentity\b.*?(?=\r?\nfunction )'
    ).Value
    $claudeParentPreinstallContract = [regex]::Match(
        $harnessText,
        '(?s)function Install-OfficialClaudePackageLiveParentClient\b.*?(?=\r?\nfunction )'
    ).Value
    $invokeAgentContract = [regex]::Match(
        $harnessText,
        '(?s)function Invoke-Agent\b.*?(?=\r?\nfunction )'
    ).Value
    Assert-True ($installAgentContract -match
            '\$installer = Get-OfficialClaudeInstallerScriptBlock' -and
        $installAgentContract -notmatch
            "Invoke-RestMethod -Uri 'https://claude\.ai/install\.ps1'" -and
        $claudeInstallerFetchContract -match
            '\[ValidateRange\(1, 3\)\]\[int\]\$MaxAttempts = 3' -and
        $claudeInstallerFetchContract -match
            '\[ValidateRange\(1, 30\)\]\[int\]\$PerAttemptTimeoutSeconds = 30' -and
        $claudeInstallerFetchContract -match
            '\[ValidateRange\(1, 90\)\]\[int\]\$OverallTimeoutSeconds = 75' -and
        $claudeInstallerFetchContract -match
            '\$deadline = \[DateTimeOffset\]::UtcNow\.AddSeconds' -and
        $claudeInstallerFetchContract -match
            '(?s)Invoke-RestMethod -Method Get.*?-MaximumRedirection 3.*?-TimeoutSec \$TimeoutSeconds' -and
        $claudeInstallerFetchContract -notmatch
            'SkipCertificateCheck|MaximumRetryCount' -and
        $claudeInstallerFetchContract -match
            'Test-ClaudeInstallerTransientTransportFailure' -and
        $harnessText -match
            'Get-ClaudeInstallerFailureFingerprint' -and
        $harnessText -match
            'RemoteCertificate\(\?:NameMismatch\|ChainErrors\|NotAvailable\)' -and
        $harnessText -notmatch
            'failure -is \[Security\.Authentication\.AuthenticationException\].*?return \$false' -and
        $claudeInstallerFetchContract -match 'Protect-LogText' -and
        $claudeInstallerBodyContract -match
            'byteCount -gt 65536' -and
        $claudeInstallerBodyContract -match
            '\[scriptblock\]::Create\(\$text\)') `
        'Claude installer fetch is TLS-validating, deadline/attempt bounded, transient-only, redacted, and validates bounded PowerShell before execution'
    Assert-True ($claudeClientPathContract -match
            '5E6C858F-0E22-4760-9AFE-EA3317B67173' -and
        $claudeClientPathContract -match "'\.local\\bin\\claude\.exe'" -and
        $claudeClientPathContract -match
            'USERPROFILE to match the current-user Known Folder profile' -and
        $claudeClientIdentityContract -match
            '(?s)Assert-DisposableNoReparseAncestors.*?-RequireExists' -and
        $claudeClientIdentityContract -match
            '(?s)\$item -isnot \[IO\.FileInfo\].*?ReparsePoint' -and
        $claudeClientIdentityContract -match
            '(?s)GetAccessControl.*?AccessControlSections\]::Owner' -and
        $claudeClientIdentityContract -match
            'WindowsIdentity\]::GetCurrent\(\)\.User' -and
        $claudeClientIdentityContract -match 'Get-AuthenticodeSignature' -and
        $claudeClientIdentityContract -match
            "(?s)Status -cne 'Valid'.*?SignatureType -cne 'Authenticode'.*?X509NameType\]::SimpleName.*?Anthropic, PBC" -and
        $claudeClientIdentityContract -match
            'Get-FileHash.*?-Algorithm SHA256' -and
        $claudeClientIdentityContract -match
            '(?s)ExpectedSHA256.*?parent-installed client' -and
        $claudeClientIdentityContract -match
            "Invoke-NativeProcess.*?'--version'" -and
        $claudeClientIdentityContract -match
            "Get-Command 'claude\.exe' -CommandType Application" -and
        $claudeClientIdentityContract -match
            '(?s)postProbeSHA256.*?changed while its signature, version, and PATH identity were probed' -and
        $claudeClientIdentityContract -match
            'SHA256 = \$postProbeSHA256') `
        'Claude native identity requires canonical non-reparse current-user custody, valid Anthropic signing, exact hash/version, and PATH resolution'
    Assert-True ($claudeParentPreinstallContract -match
            'PackageLiveNonCertification' -and
        $claudeParentPreinstallContract -match
            "(?s)GITHUB_ACTIONS -cne 'true'.*?RUNNER_ENVIRONMENT -cne 'github-hosted'.*?GITHUB_EVENT_NAME -cne 'workflow_dispatch'" -and
        $claudeParentPreinstallContract -match
            "(?s)'ANTHROPIC_API_KEY'.*?'AWS_BEARER_TOKEN_BEDROCK'.*?'AWS_ACCESS_KEY_ID'.*?'AWS_SECRET_ACCESS_KEY'.*?'AWS_SESSION_TOKEN'" -and
        $claudeParentPreinstallContract -match
            'refuses an ambient canonical client' -and
        $claudeParentPreinstallContract -match
            "Get-Command 'claude' -All" -and
        $claudeParentPreinstallContract -match
            "DISABLE_AUTOUPDATER = '1'" -and
        $claudeParentPreinstallContract -match
            'Get-OfficialClaudeInstallerScriptBlock' -and
        $claudeParentPreinstallContract -match
            'Assert-OfficialClaudeClientIdentity') `
        'Claude parent preinstall is secret-free, fresh-client-only, and restricted to hosted manual noncertification evidence'
    Assert-True ($harnessText -match
            '\[string\]\$ExpectedAgentSHA256' -and
        $installAgentContract -match
            '(?s)\$PackageLiveEvidence.*?ExpectedAgentSHA256.*?Assert-OfficialClaudeClientIdentity.*?preinstalled=parent.*?return.*?\$installer = Get-OfficialClaudeInstallerScriptBlock') `
        'package-live Claude requires parent path/version/hash identity and returns before any restricted-child network bootstrap'
    Assert-True ($installAgentContract -match '@ampcode/cli@' -and
        $installAgentContract -match 'AMP_VERSION' -and
        $installAgentContract -match "'amp\.cmd'" -and
        $invokeAgentContract -match "'amp'\s*\{" -and
        $invokeAgentContract -match '@\(''-x'', \$Prompt, ''--plugin-ready-timeout'', ''30''\)' -and
        $harnessText -match 'AMP_API_KEY') `
        'Windows live harness installs, redacts, and invokes official Amp execute mode with bounded plugin readiness'
    Assert-True ($liveWorkflowText -match '(?s)windows-antigravity-live:.*?runs-on: \[self-hosted, Windows, X64, antigravity-authenticated\].*?AuthenticatedAntigravityRunner') 'manual Antigravity live job requires a dedicated authenticated native Windows runner'
    $antigravityLiveJob = [regex]::Match(
        $liveWorkflowText,
        '(?ms)^  windows-antigravity-live:.*?(?=^  # -+\r?$\n  # Report)'
    ).Value
    Assert-True ($antigravityLiveJob -match 'permissions:\s*\r?\n\s+actions: read\s*\r?\n\s+contents: read' -and
        $antigravityLiveJob -match 'actions/download-artifact@' -and
        $antigravityLiveJob -match 'name: windows-native-package' -and
        $antigravityLiveJob -match 'run-id: \$\{\{ inputs\.windows_package_run_id \}\}' -and
        $antigravityLiveJob -match '-PackagedSetupPath' -and
        $antigravityLiveJob -match "-ExpectedPackageSourceCommit '\$\{\{ github\.sha \}\}'" -and
        $antigravityLiveJob -match "-ExpectedHarnessSourceCommit '\$\{\{ github\.sha \}\}'") `
        'authenticated Antigravity lane consumes an explicit exact-head Windows package artifact'
    Assert-True ($antigravityLiveJob -match 'GH_TOKEN: \$\{\{ github\.token \}\}' -and
        $antigravityLiveJob -match 'actions/workflows/windows-native\.yml' -and
        $antigravityLiveJob -match '\$run\.workflow_id.*?\$workflow\.id' -and
        $antigravityLiveJob -match 'Test-CanonicalWindowsWorkflowRunPath \(\[string\]\$run\.path\)' -and
        $antigravityLiveJob -match '\$run\.repository\.full_name.*?GITHUB_REPOSITORY' -and
        $antigravityLiveJob -match '\$run\.conclusion.*?success' -and
        $antigravityLiveJob -match '\$run\.head_sha.*?EXPECTED_HEAD_SHA' -and
        $antigravityLiveJob -match 'actions/runs/\$env:PACKAGE_RUN_ID/artifacts\?per_page=100' -and
        $antigravityLiveJob -match '\$packageArtifacts\.Count -ne 1' -and
        $antigravityLiveJob -match '\$packageArtifacts\[0\]\.expired' -and
        $antigravityLiveJob -match '\$packageArtifacts\[0\]\.size_in_bytes') `
        'package authorization binds run, canonical workflow, repository, exact head, success, and unexpired artifact before download'
    $antigravitySafetyNet = [regex]::Match(
        $antigravityLiveJob,
        '(?s)- name: Antigravity teardown safety net.*?-StateRoot \$env:DC_WINDOWS_STATE'
    ).Value
    Assert-True ($antigravitySafetyNet -match '-Operation cleanup' -and
        $antigravitySafetyNet -match '-AuthenticatedAntigravityRunner' -and
        $antigravitySafetyNet -match '-PackagedSetupPath' -and
        $antigravitySafetyNet -match "-ExpectedPackageSourceCommit '\$\{\{ github\.sha \}\}'" -and
        $antigravitySafetyNet -match "-ExpectedHarnessSourceCommit '\$\{\{ github\.sha \}\}'") `
        'Antigravity safety net receives the same exact package identity as the live run'
    Assert-True ($antigravityLiveJob -notmatch 'go build|uv sync|CONNECTOR=antigravity|native-setup-antigravity') `
        'authenticated Antigravity lane cannot substitute raw builds or a public Setup bootstrap'
    Assert-True ($antigravityLiveJob -match 'Protect exact package destination' -and
        $antigravityLiveJob -match 'SetAccessRuleProtection\(\$true, \$false\)' -and
        $antigravityLiveJob -match "S-1-5-18" -and
        $antigravityLiveJob -match "S-1-5-32-544" -and
        $antigravityLiveJob -match 'FullControl') `
        'workflow protects the exact package destination before artifact download'
    $windowsLiveJob = [regex]::Match(
        $liveWorkflowText,
        '(?ms)^  windows-live:.*?(?=^  [A-Za-z0-9_-]+:\r?$|\z)'
    ).Value
    $claudeParentPreinstallStep = [regex]::Match(
        $windowsLiveJob,
        '(?ms)^      - name: Preinstall official native Claude client without provider credentials.*?(?=^      - name: Native Windows live harness)'
    ).Value
    Assert-True (-not [string]::IsNullOrWhiteSpace($claudeParentPreinstallStep) -and
        $claudeParentPreinstallStep -match
            "steps\.select\.outputs\.run == 'true' && matrix\.connector == 'claudecode'" -and
        $claudeParentPreinstallStep -notmatch 'secrets\.' -and
        $claudeParentPreinstallStep -match 'Set-CurrentUserAsDefaultOwner' -and
        $claudeParentPreinstallStep -match
            'Install-OfficialClaudePackageLiveParentClient' -and
        $claudeParentPreinstallStep -match '-PackageLiveNonCertification' -and
        $claudeParentPreinstallStep -match
            '(?s)agent_path=.*?agent_version=.*?agent_sha256=' -and
        $windowsLiveJob.IndexOf($claudeParentPreinstallStep) -lt
            $windowsLiveJob.IndexOf('- name: Native Windows live harness') -and
        $windowsLiveJob -match
            "'-AgentPath', '\$\{\{ steps\.claude_client\.outputs\.agent_path \}\}'" -and
        $windowsLiveJob -match
            "'-ExpectedAgentVersion', '\$\{\{ steps\.claude_client\.outputs\.agent_version \}\}'" -and
        $windowsLiveJob -match
            "'-ExpectedAgentSHA256', '\$\{\{ steps\.claude_client\.outputs\.agent_sha256 \}\}'" -and
        [regex]::Matches(
            $windowsLiveJob,
            'secrets\.ANTHROPIC_API_KEY'
        ).Count -eq 1) `
        'Claude is installed in a selected-only secret-free parent step and its exact identity is handed to the sole credential-bearing restricted harness step'
    Assert-True ($windowsLiveJob -notmatch 'continue-on-error') 'Windows live jobs are not advisory'
    Assert-True ($windowsLiveJob -notmatch 'shell:\s*bash') 'Windows live jobs never select Bash'
    Assert-True ($windowsLiveJob -match "github.event_name == 'workflow_dispatch'") `
        'Connector Live Windows radar remains manual-only'
    Assert-True (
        [regex]::Matches(
            $windowsLiveJob,
            '(?m)^\s+\. ./scripts/windows-native-ci\.ps1 -NoRun\s*$'
        ).Count -eq 4 -and
        [regex]::Matches(
            $windowsLiveJob,
            '(?m)^\s+Set-CurrentUserAsDefaultOwner\s*$'
        ).Count -eq 4 -and
        [regex]::Matches(
            $windowsLiveJob,
            'Invoke-WindowsSetupStandardUserProcess -FilePath \$pwsh'
        ).Count -eq 3 -and
        [regex]::Matches(
            $windowsLiveJob,
            '-AllowRestrictedLuaFallback \| Out-Null'
        ).Count -eq 3 -and
        $windowsLiveJob -match "'-Operation', 'capture'" -and
        $windowsLiveJob -match "'-Operation', 'cleanup'" -and
        $windowsLiveJob -notmatch
            'DC_E2E_RESULTS:.*?github\.workspace|defenseclaw-live-e2e-logs' -and
        $windowsLiveJob -match
            'DC_E2E_RESULTS: D:\\DefenseClaw-Connector-Live-.*?\\results\.jsonl' -and
        $windowsLiveJob -match 'GIT_OPTIONAL_LOCKS: "0"' -and
        [regex]::Matches(
            $windowsLiveJob,
            "'-ArtifactPath', \(Join-Path \`$env:DC_WINDOWS_STATE 'artifacts'\)"
        ).Count -eq 2 -and
        $windowsLiveJob -match
            'path: \$\{\{ env\.DC_WINDOWS_STATE \}\}/artifacts/\*\*'
    ) 'hosted Windows parent preinstall plus live run, capture, and cleanup normalize ownership while restricted operations use the validated standard-user launcher'
    Assert-True ($releaseWorkflowText -notmatch '(?m)^  windows-real-client-certification:' -and
        $releaseWorkflowText -notmatch 'secrets\.OPENAI_API_KEY' -and
        $releaseWorkflowText -notmatch 'secrets\.ANTHROPIC_API_KEY' -and
        $releaseWorkflowText -notmatch '-Operation release-certification') `
        'production release does not depend on provider-backed Windows live radar'
    $releaseAssemblyJob = [regex]::Match(
        $releaseWorkflowText,
        '(?ms)^  assemble-release-candidate:.*?(?=^  [a-z0-9][a-z0-9-]*:|\z)'
    ).Value
    Assert-True ($releaseAssemblyJob -match 'needs:\s*\[release-preflight,\s*build-runtime-candidate,\s*macos-app,\s*windows-installer\]' -and
        $releaseAssemblyJob -match 'artifact-ids:\s*\$\{\{ needs\.windows-installer\.outputs\.artifact_id \}\}' -and
        $releaseAssemblyJob -match '--windows-dir candidate-input/windows') `
        'immutable release assembly consumes the tested Windows artifact bundle directly'
    Assert-True ($liveWorkflowText -match 'shell:\s*bash') 'Unix Bash harness remains present'
    Assert-True ($liveWorkflowText -notmatch '(?m)^  windows-(harness-static|contract):') 'deterministic Windows jobs moved out of live radar'
    Assert-True ($ciWorkflowText -notmatch '(?m)^  windows-(hook-path|installer-smoke):') 'legacy partial Windows jobs were removed'
    Assert-True ($harnessText -notmatch '(?i)\bwsl(?:\.exe)?\b|git bash|/bin/|Get-Command\s+(?:jq|tail|curl)|Invoke-Tool\s+''(?:jq|tail|curl)''') 'native harness has no WSL, Git Bash, or Unix utility dependency'
    $packagedConnectorHomes = [regex]::Match(
        $harnessText,
        '(?s)function Assert-PackagedConnectorHomes\b.*?(?=\nfunction Get-StableHookRuntimeExecutable\b)'
    ).Value
    Assert-True ($packagedConnectorHomes -notmatch '(?i)windsurf|cascade|geminicli|gemini cli') `
        'packaged connector-home setup exposes no retired Windsurf/Cascade or Gemini CLI binding'
    $setupOtlpFixture = [regex]::Match(
        $nativeHarnessText,
        '(?s)function Start-SetupAcceptanceOtlpCollector\b.*?(?=\nfunction Stop-SetupAcceptanceOtlpCollector\b)'
    ).Value
    $setupOtlpCleanup = [regex]::Match(
        $nativeHarnessText,
        '(?s)function Stop-SetupAcceptanceOtlpCollector\b.*?\n\}'
    ).Value
    $setupHealthSampler = [regex]::Match(
        $nativeHarnessText,
        '(?s)function Start-SetupAcceptanceHealthSampler\b.*?(?=\nfunction Stop-SetupAcceptanceHealthSampler\b)'
    ).Value
    $setupHealthSamplerContract = [regex]::Match(
        $nativeHarnessText,
        '(?s)function Test-SetupAcceptanceHealthSamplerContract\b.*?(?=\nfunction Write-SetupAcceptanceConvergenceDiagnostics\b)'
    ).Value
    $setupAcceptance = [regex]::Match(
        $nativeHarnessText,
        '(?s)function Invoke-SetupAcceptance\b.*?\n\}'
    ).Value
    Assert-True ($setupOtlpFixture -match '\[Net\.Sockets\.TcpListener\]::new\(\[Net\.IPAddress\]::Loopback, 0\)' -and
        $setupOtlpFixture -match 'if \(\$length -gt 16MB\)' -and
        $setupOtlpFixture -match 'HTTP/1\.1 200 OK' -and
        $setupOtlpFixture -match 'CreateRunspacePool\(1, 8\)' -and
        $setupOtlpFixture -match 'if \(\$workers\.Count -ge 8\)' -and
        $setupOtlpFixture -match '\$worker\.BeginInvoke\(\)' -and
        $setupOtlpFixture -match 'A reset, timeout, or malformed request is isolated to its client' -and
        $setupOtlpFixture -match "ArgumentList\.Add\('-CommandWithArgs'\)" -and
        $setupOtlpFixture -notmatch "ArgumentList\.Add\('-Command'\)" -and
        $setupOtlpFixture -match "Get-NetTCPConnection -State Listen -LocalAddress '127\.0\.0\.1'" -and
        $setupOtlpFixture -match 'OwningProcess.*?process\.Id') `
        'seeded Setup upgrade uses an exact-PID-owned dynamic loopback OTLP sink'
    Assert-True ($setupAcceptance -match 'Start-SetupAcceptanceOtlpCollector \(Join-Path \$PSHOME ''pwsh\.exe''\)' -and
        $setupAcceptance -notmatch 'Start-SetupAcceptanceOtlpCollector \$python' -and
        $setupAcceptance -match 'endpoint: http://127\.0\.0\.1:\$setupOtlpPort' -and
        ([regex]::Matches($setupAcceptance, '(?m)^    endpoint: http://127\.0\.0\.1:\$setupOtlpPort\s*$')).Count -eq 3 -and
        ([regex]::Matches($setupAcceptance, '(?m)^    protocol: http\s*$')).Count -eq 3 -and
        $setupAcceptance -match 'expected_endpoint = f"http://127\.0\.0\.1:\{int\(sys\.argv\[2\]\)\}"' -and
        $setupAcceptance -match 'assert not otlp\.get\("signal_overrides"\)' -and
        $setupAcceptance -match '\$configPath, \$setupOtlpPort' -and
        $setupAcceptance -match 'Stop-SetupAcceptanceOtlpCollector \$setupOtlpCollector') `
        'Setup acceptance pins every migrated signal to its external bounded OTLP fixture and cleans it'
    $setupOtlpMetricInterval = [regex]::Match(
        $setupAcceptance,
        '(?m)^\s*export_interval_s:\s*(?<seconds>[0-9]+)\s*$'
    )
    Assert-True ($setupOtlpMetricInterval.Success -and
        [int]$setupOtlpMetricInterval.Groups['seconds'].Value -gt 0 -and
        [int]$setupOtlpMetricInterval.Groups['seconds'].Value -lt 60) `
        'Setup acceptance metric export interval is positive and strictly inside the 60-second readiness deadline'
    Assert-True ($setupOtlpCleanup -match '\$process\.Kill\(\$true\)' -and
        $setupOtlpCleanup -match 'WaitForExit\(5000\)' -and
        $setupOtlpCleanup -match 'Remove-Item -LiteralPath \$ready') `
        'Setup OTLP fixture cleanup terminates only its captured process tree and removes readiness state'
    Assert-True ($setupHealthSampler -match '\$healthConfigGeneration = \[int\]\$health\.telemetry\.details\.generation' -and
        $setupHealthSampler -notmatch '\$health\.provenance\.generation|provenance_generation' -and
        $setupHealthSampler -match "kind = 'sample_error'" -and
        $setupHealthSampler -match "'event_correlation', 'projection', 'record'" -and
        $setupHealthSampler -notmatch '\$_\.Exception') `
        'Setup health sampler uses the real health generation and bounded nonsecret failure categories'
    $hasHealthSamplerPrewarm = {
        param([string]$Source)
        $prewarm = $Source.IndexOf(
            "`$prewarmListeners = @(Get-NetTCPConnection -State Listen -LocalAddress '127.0.0.1' -LocalPort `$ApiPort -ErrorAction Stop)",
            [StringComparison]::Ordinal
        )
        $readiness = $Source.IndexOf(
            "`$stream = [IO.FileStream]::new(`$OutcomePath, 'CreateNew', 'Write', 'Read')",
            [StringComparison]::Ordinal
        )
        return $prewarm -ge 0 -and $readiness -gt $prewarm
    }
    Assert-True (& $hasHealthSamplerPrewarm $setupHealthSampler) `
        'Setup health sampler initializes its listener provider before publishing readiness'
    Assert-True ($setupHealthSampler -match '\$prewarmDeadline = \[DateTime\]::UtcNow\.AddSeconds\(20\)' -and
        $setupHealthSampler -match '(?s)do \{.*?Get-NetTCPConnection.*?\$prewarmListeners\.Count -gt 0.*?Start-Sleep -Milliseconds 100.*?\} while \(\$true\)' -and
        $setupHealthSampler -match '\$deadline = \[DateTime\]::UtcNow\.AddSeconds\(30\)' -and
        $setupHealthSampler -match "Setup health sampler readiness cleanup timed out") `
        'Setup health sampler cold-provider retry, readiness polling, and cleanup remain bounded'
    Assert-True (-not (& $hasHealthSamplerPrewarm $setupHealthSampler.Replace(
                "`$prewarmListeners = @(Get-NetTCPConnection -State Listen -LocalAddress '127.0.0.1' -LocalPort `$ApiPort -ErrorAction Stop)", ''
            ))) `
        'Setup health sampler prewarm predicate rejects a missing listener-provider initialization'
    $reorderedHealthSampler = $setupHealthSampler.Replace(
        "`$prewarmListeners = @(Get-NetTCPConnection -State Listen -LocalAddress '127.0.0.1' -LocalPort `$ApiPort -ErrorAction Stop)", ''
    ).Replace(
        "`$stream = [IO.FileStream]::new(`$OutcomePath, 'CreateNew', 'Write', 'Read')",
        "`$stream = [IO.FileStream]::new(`$OutcomePath, 'CreateNew', 'Write', 'Read')`n`$prewarmListeners = @(Get-NetTCPConnection -State Listen -LocalAddress '127.0.0.1' -LocalPort `$ApiPort -ErrorAction Stop)"
    )
    Assert-True (-not (& $hasHealthSamplerPrewarm $reorderedHealthSampler)) `
        'Setup health sampler prewarm predicate rejects readiness published before preload'
    Assert-True ($setupHealthSamplerContract -match '\$listener = \[Net\.Sockets\.TcpListener\]::new\(\[Net\.IPAddress\]::Loopback, 0\)' -and
        $setupHealthSamplerContract -match 'started_at = \$startedAt' -and
        $setupHealthSamplerContract -match 'uptime_ms = 1' -and
        $setupHealthSamplerContract -match 'application_protection = \$running' -and
        $setupHealthSamplerContract -match 'telemetry = \[ordered\]@\{' -and
        $setupHealthSamplerContract -match 'generation = 7' -and
        $setupHealthSamplerContract -match 'A reset, timeout, or malformed request is isolated to its client' -and
        $setupHealthSamplerContract -match '\$resetClient\.Client\.LingerState = \[Net\.Sockets\.LingerOption\]::new\(\$true, 0\)' -and
        $setupHealthSamplerContract -match 'synthetic Setup health server did not isolate a reset client' -and
        $setupHealthSamplerContract -match '\$null -ne \$sample\.PSObject\.Properties\[''provenance_generation''\]' -and
        $setupHealthSamplerContract -match 'did not emit its bounded stage diagnostic' -and
        $setupHealthSamplerContract -match 'did not emit a correlated health sample') `
        'hosted-equivalent Setup health sampler fixture covers schema drift diagnostics and exact correlation'
    $sampleSamplerStart = $setupHealthSamplerContract.IndexOf(
        '$sampler = Start-SetupAcceptanceHealthSampler $pwsh $sampleOutcomePath',
        [StringComparison]::Ordinal
    )
    $sampleDeadlineStart = $setupHealthSamplerContract.IndexOf(
        '$sampleDeadline = [DateTime]::UtcNow.AddSeconds(15)',
        [StringComparison]::Ordinal
    )
    Assert-True ($sampleSamplerStart -ge 0 -and
        $sampleDeadlineStart -gt $sampleSamplerStart -and
        ([regex]::Matches(
            $setupHealthSamplerContract.Substring($sampleSamplerStart),
            'Start-SetupAcceptanceHealthSampler'
        )).Count -eq 1 -and
        $setupHealthSamplerContract -notmatch 'foreach \(\$attempt in 1\.\.2\)') `
        'hosted-equivalent Setup health sampler uses one persistent sampler with a fresh post-readiness deadline'
    Assert-True ($harnessText -match 'CLAUDE_CODE_USE_POWERSHELL_TOOL = ''1''' -and
        $harnessText -match 'https://claude\.ai/install\.ps1' -and
        $harnessText -match '\.local\\bin\\claude\.exe' -and
        $harnessText -match "Get-Command 'claude\.exe' -CommandType Application" -and
        $harnessText -notmatch '@anthropic-ai/claude-code@' -and
        $harnessText -match '--allowedTools'', ''PowerShell''' -and
        $harnessText -match 'Assert-ClaudeNativePowerShellExecution' -and
        $harnessText -match 'CapturedProcesses' -and
        $harnessText -match 'powershell\|pwsh' -and
        $harnessText -match 'bash\|sh\|dash\|git-bash\|mintty\|msys' -and
        $harnessText -match 'cygwin') `
        'Claude live lane forces and captures native PowerShell tool/process execution without a compatibility shell'
    $isolatedHomeBinding = [regex]::Match(
        $harnessText,
        '(?s)if \(\[string\]::IsNullOrWhiteSpace\(\$NativeDataRoot\)\) \{.*?\} else \{\s*Assert-PackagedConnectorHomes \$StateRoot \$HomeRoot\s*\}'
    ).Value
    Assert-True ($harnessText.Contains('$env:DEFENSECLAW_CONFIG = Join-Path $env:DEFENSECLAW_HOME ''config.yaml''') -and
        $isolatedHomeBinding -match '\$env:CODEX_HOME = Join-Path \$env:USERPROFILE ''\.codex''' -and
        $isolatedHomeBinding -match '\$env:CLAUDE_CONFIG_DIR = Join-Path \$env:USERPROFILE ''\.claude''' -and
        $isolatedHomeBinding -match '\$env:COPILOT_HOME = Join-Path \$env:USERPROFILE ''\.copilot''' -and
        $isolatedHomeBinding -match '\$env:DEFENSECLAW_CURSOR_CONFIG_HOME = Join-Path \$env:USERPROFILE ''\.cursor''' -and
        $isolatedHomeBinding -match '\$env:HERMES_HOME = Join-Path \$env:USERPROFILE ''AppData\\Local\\hermes''' -and
        $isolatedHomeBinding -match '\$env:OPENCODE_CONFIG_DIR = Join-Path \$env:USERPROFILE ''\.config\\opencode''') `
        'native harness preserves packaged connector homes and otherwise binds disposable defaults'
    $packagedHomeGuard = [regex]::Match($harnessText, '(?s)function Assert-PackagedConnectorHomes\b.*?\n\}').Value
    Assert-True ($packagedHomeGuard -match 'Assert-WindowsNativePathsDisjoint' -and
        $packagedHomeGuard -match '\$officialCursorHome' -and
        $packagedHomeGuard -match 'documented USERPROFILE\\\.cursor path' -and
        $packagedHomeGuard -match 'Test-PathWithin' -and
        $packagedHomeGuard -match 'Assert-DisposableNoReparseAncestors' -and
        $packagedHomeGuard -match '-RequireExists' -and
        $packagedHomeGuard -match '\.config\\amp' -and
        $packagedHomeGuard -match 'packaged Amp home must be a strict child' -and
        $packagedHomeGuard -match '\$env:HERMES_HOME = \$homes\[5\]') `
        'packaged connector homes are authentic, contained, existing, and non-reparse'
    Assert-True ($nativeWorkflowText -notmatch '(?i)geminicli|gemini cli' -and
        $wizardHarnessText -notmatch '(?i)geminicli|gemini cli' -and
        $standardUserCIText -notmatch "ValidateSet\([^)]*geminicli") `
        'Gemini CLI is absent from active Windows workflow and setup-selection surfaces'
    Assert-True ($harnessText -match 'timeout-handling' -and $harnessText -match 'telemetry pass') 'contract records timeout and telemetry evidence'
    foreach ($rule in @(
        'CMD-WIN-REMOVE-ITEM-RF', 'CMD-WIN-RMDIR-SQ', 'CMD-PIPE-CURL', 'CMD-WIN-REG-PERSIST',
        'PATH-WIN-AWS-CREDS', 'PATH-WIN-GIT-CREDS', 'PATH-WIN-CREDENTIAL-MANAGER'
    )) {
        Assert-True ($harnessText.Contains($rule)) "required Windows dangerous-command corpus contains $rule"
    }
    Assert-True ($harnessText -match "Invoke-DangerousCommandCorpus observe" -and $harnessText -match "Invoke-DangerousCommandCorpus action") 'connector contract executes dangerous-command corpus in observe and action modes'
    Assert-True ($harnessText -match 'raw_action' -and $harnessText -match 'would_block' -and $harnessText -match 'enforced') 'dangerous-command contract asserts raw and enforced decisions'
    $dangerousPayloadContract = [regex]::Match(
        $harnessText,
        '(?s)function New-DangerousCommandPayload\b.*?(?=\nfunction Invoke-DangerousHook\b)'
    ).Value
    Assert-True ($dangerousPayloadContract -match "ValidateSet\('observe', 'action'\).*?\`$Mode" -and
        $dangerousPayloadContract -match '\$probeID = "\$Name-\$Mode"' -and
        $dangerousPayloadContract -match 'conversationId = "dc-windows-contract-\$Connector-\$probeID"' -and
        $dangerousPayloadContract -match 'session_id = "dc-windows-contract-\$Connector-\$Mode"' -and
        $dangerousPayloadContract -match 'turn_id = "dc-windows-contract-\$Connector-\$probeID"' -and
        $dangerousPayloadContract -match '(?s)\$Connector -eq ''codex''.*?event_id = "dc-windows-contract-\$Connector-\$probeID-event".*?tool_use_id = \$payload\.tool_call_id' -and
        $dangerousPayloadContract -match '\$path = Join-Path \$Root "\$probeID\.json"' -and
        $harnessText -match 'New-DangerousCommandPayload \$case\.Name \$command \$payloadRoot \$Mode') `
        'observe/action dangerous-command fixtures use distinct exact correlation and file identities'
    $dangerousHookContract = [regex]::Match(
        $harnessText,
        '(?s)function Invoke-DangerousHook\b.*?(?=\nfunction Invoke-DangerousCommandCorpus\b)'
    ).Value
    Assert-True ($dangerousHookContract -match "\`$telemetryMode = if \(\`$Mode -eq 'action'\)" -and
        $dangerousHookContract -match "\`$effectiveObserve = \`$Mode -eq 'observe'" -and
        $dangerousHookContract -match 'Invoke-RegisteredNativeHook' -and
        $dangerousHookContract -match "\`$decision\.raw_action -ne 'block'" -and
        $dangerousHookContract -match 'Test-BlockVerdict' -and
        $dangerousHookContract -match '\$decision\.rule_ids') `
        'dangerous-command checks require mode-matched action enforcement or observe telemetry with exact block evidence'
    $hookContract = [regex]::Match($harnessText, '(?s)function Invoke-Hook\b.*?(?=\nfunction New-DangerousCommandPayload\b)').Value
    Assert-True ($hookContract -match '\$RequireGatewayBlock' -and
        $hookContract -match '\$decision\.raw_action -ne ''block''' -and
        $hookContract -match '\$decision\.mode -ne ''observe''' -and
        $hookContract -match '\$decision\.action -ne ''allow''' -and
        $hookContract -match '-not \[bool\]\$decision\.would_block' -and
        $hookContract -match '\[bool\]\$decision\.enforced') `
        'advisory block hook assertions require exact raw block, observe, would-block, and non-enforcement telemetry'
    Assert-True ($harnessText -match 'enterprise-hooks:install:elevation-required' -and
        $harnessText -match 'require an elevated administrator or LocalSystem token') `
        'native enterprise hooks require elevation in the standard-user connector contract'
    Assert-True ($harnessText -match 'Get-TreeFingerprint' -and $harnessText -match 'AllowedExitCodes @\(1\)') 'enterprise hooks elevation rejection is bounded, exit 1, and checks an unchanged tree'
    Assert-True ($harnessText -match 'Assert-DoctorWindowsHookRegistration' -and $harnessText -match 'healthy Windows-native executable registration') 'connector contract runs Doctor against the registered Windows hook executable'
    $contractRun = [regex]::Match($harnessText, '(?s)function Invoke-ContractRun\b.*?\n\}').Value
    $ampFiveEventContract = [regex]::Match(
        $harnessText,
        '(?s)function Invoke-AmpFiveEventProviderContract\b.*?(?=\r?\nfunction )'
    ).Value
    Assert-True ($contractRun -match 'Invoke-AmpFiveEventProviderContract \$golden' -and
        $ampFiveEventContract -match "'session\.start'.*?'session_start\.json'" -and
        $ampFiveEventContract -match "'agent\.start'.*?'agent_start\.json'" -and
        $ampFiveEventContract -match "'tool\.call'.*?'pre_tool_allow\.json'" -and
        $ampFiveEventContract -match "'tool\.result'.*?'tool_result\.json'" -and
        $ampFiveEventContract -match "'agent\.end'.*?'agent_end\.json'" -and
        $contractRun -match "'tool\.call'.*?'subagent_tool_call\.json'" -and
        $ampFiveEventContract -match 'Invoke-Hook \$spec\.Event \$payloadPath allow') `
        'Amp Windows contract exercises all five native callbacks plus the subagent delegation boundary'
    Assert-True ($contractRun -match "\`$actionBlockExpectation = 'block'" -and
        $contractRun -match "\`$requireAdvisoryBlock = \`$false" -and
        $contractRun -match "(?s)Invoke-DangerousCommandCorpus action.*?Invoke-Hook 'PreTool-block'.*?\`$actionBlockExpectation \`$requireAdvisoryBlock") `
        'all final action-profile probes, including Cursor, require enforced blocking'
    $antigravityPackageInitialization = [regex]::Match(
        $harnessText,
        '(?s)function Initialize-AuthenticatedAntigravityPackage\b.*?(?=\r?\nfunction )'
    ).Value
    $antigravitySupportedAvailability = [regex]::Match(
        $harnessText,
        '(?s)function Assert-AuthenticatedAntigravityPublicCLIAvailable\b.*?(?=\r?\nfunction )'
    ).Value
    Assert-True ($antigravityPackageInitialization -match
        "(?s)Invoke-AuthenticatedAntigravitySetup @\(.*?'CONNECTOR=antigravity'.*?'MODE=action'.*?'STARTGATEWAY=1'.*?\) @\(0\).*?Assert-AuthenticatedAntigravityPublicCLIAvailable \`$paths" -and
        $antigravitySupportedAvailability -match
        "(?s)\`$result = Invoke-Tool 'defenseclaw' @\(.*?'init', '--skip-install', '--non-interactive', '--yes'.*?'--connector', 'antigravity', '--profile', 'action'.*?'--no-start-gateway', '--no-verify'.*?\) @\(0\)" -and
        $antigravitySupportedAvailability -match
        "(?s)if \(\(\`$result\.StdOut \+ .*?\`$result\.StdErr\) -match '\(\?i\)not_certified\|preview'\) \{\s+throw 'ordinary Antigravity init emitted a stale platform gate or preview warning'" -and
        $antigravitySupportedAvailability -match
        '(?s)if \(\(Get-FileHash -LiteralPath \$Paths\.StatePath -Algorithm SHA256\)\.Hash -cne \$stateBefore -or\s+\(Get-FileHash -LiteralPath \$configPath -Algorithm SHA256\)\.Hash -cne \$configBefore -or\s+\$backupAfter -cne \$backupBefore\) \{\s+throw ''ordinary idempotent Antigravity init changed package state, config, or connector custody''' -and
        $antigravitySupportedAvailability -match
        'Write-Result ''public-init:supported'' pass `\r?\n\s+''ordinary CLI exit=0; idempotent install/config/hook/custody state unchanged; evidence fields remain empty and live=false''' -and
        $harnessText -notmatch 'native-setup-antigravity') `
        'packaged Antigravity contract proves ordinary supported availability without a preview warning or public bootstrap flag'
    $connectorSetup = [regex]::Match($harnessText, '(?s)function Invoke-Setup\b.*?\n\}').Value
    Assert-True ($connectorSetup -notmatch 'native-setup-antigravity') `
        'generic connector setup does not invent an Antigravity bootstrap flag'
    $packagePaths = [regex]::Match(
        $harnessText,
        '(?s)function Get-AuthenticatedAntigravityPackagePaths\b.*?(?=\nfunction Assert-ExactPath\b)'
    ).Value
    $packageIdentity = [regex]::Match(
        $harnessText,
        '(?s)function Assert-ExactPackagedSetup\b.*?(?=\nfunction Invoke-AuthenticatedAntigravitySetup\b)'
    ).Value
    $packageBootstrap = [regex]::Match(
        $harnessText,
        '(?s)function Initialize-AuthenticatedAntigravityPackage\b.*?(?=\nfunction Repair-AuthenticatedAntigravityPackage\b)'
    ).Value
    $packageRepair = [regex]::Match(
        $harnessText,
        '(?s)function Repair-AuthenticatedAntigravityPackage\b.*?(?=\nfunction Get-AntigravityHookConfigFingerprint\b)'
    ).Value
    $hookFingerprint = [regex]::Match(
        $harnessText,
        '(?s)function Get-AntigravityHookConfigFingerprint\b.*?(?=\nfunction Save-AntigravityOriginalConfig\b)'
    ).Value
    $existingVendorCustody = [regex]::Match(
        $harnessText,
        '(?s)function Get-AuthenticatedAntigravityCustodyTreeFingerprint\b.*?(?=\nfunction Save-AntigravityOriginalConfig\b)'
    ).Value
    $existingHookCustody = [regex]::Match(
        $harnessText,
        '(?s)function Get-AuthenticatedAntigravityHookBackupPath\b.*?(?=\nfunction Restore-AntigravityConfigParents\b)'
    ).Value
    $existingProfileBootstrap = [regex]::Match(
        $harnessText,
        '(?s)function Assert-NoPreexistingDefenseClawRuntime\b.*?(?=\nfunction Initialize-AuthenticatedAntigravityPackage\b)'
    ).Value
    $packageManifest = [regex]::Match(
        $harnessText,
        '(?s)function New-AuthenticatedAntigravityCleanupManifestDocument\b.*?(?=\nfunction Read-AuthenticatedAntigravityCleanupManifest\b)'
    ).Value
    $packageManifestValidation = [regex]::Match(
        $harnessText,
        '(?s)function Assert-AuthenticatedAntigravityCleanupManifest\b.*?(?=\nfunction Invoke-AuthenticatedAntigravityCleanup\b)'
    ).Value
    $packageRecovery = [regex]::Match(
        $harnessText,
        '(?s)function Invoke-AuthenticatedAntigravityCleanup\b.*?(?=\nfunction Assert-AuthenticatedAntigravityFreshRunPreflight\b)'
    ).Value
    $existingProfileCleanup = [regex]::Match(
        $harnessText,
        '(?s)function Invoke-AuthenticatedAntigravityExistingProfileCleanup\b.*?(?=\nfunction Invoke-AuthenticatedAntigravityCleanup\b)'
    ).Value
    $packageFreshPreflight = [regex]::Match(
        $harnessText,
        '(?s)function Assert-AuthenticatedAntigravityFreshRunPreflight\b.*?(?=\nfunction Uninstall-AuthenticatedAntigravityPackage\b)'
    ).Value
    $packageCleanup = [regex]::Match(
        $harnessText,
        '(?s)function Uninstall-AuthenticatedAntigravityPackage\b.*?(?=\nfunction Get-ProcessTreeSnapshot\b)'
    ).Value
    Assert-True ($packagePaths -match "5E6C858F-0E22-4760-9AFE-EA3317B67173" -and
        $packagePaths -match "F1B32785-6FBA-4FCF-9D55-7B8E7F157091" -and
        $packagePaths -match "5CD7AEE2-2219-4A67-B85D-6C9CE15660CB" -and
        $packagePaths -match 'Join-Path \$profile ''\.gemini\\config''' -and
        $packagePaths -match 'Join-Path \$profile ''\.defenseclaw''') `
        'authenticated Antigravity package lane binds data and config to exact Windows Known Folders'
    Assert-True ($packageIdentity -match 'artifact_sha256' -and
        $packageIdentity -match 'source_commit' -and
        $packageIdentity -match 'Get-FileHash.*?SHA256' -and
        $harnessText -match 'Assert-ProtectedPackageArtifactRoot' -and
        $harnessText -match 'AreAccessRulesProtected' -and
        $packageIdentity -match 'Assert-DisposableNoReparseAncestors' -and
        $packageIdentity -match 'ReparsePoint') `
        'authenticated Antigravity package lane pins provenance, bytes, protected DACL, and non-reparse custody'
    Assert-True ($packageBootstrap -match "'CONNECTOR=antigravity'" -and
        $packageBootstrap -match "'MODE=action'" -and
        $packageBootstrap -match "'STARTGATEWAY=1'" -and
        $packageBootstrap -match "(?s)'CONNECTOR=antigravity'.*?\) @\(0\) 'public-antigravity-install'" -and
        ([regex]::Matches($packageBootstrap, "'CONNECTOR=antigravity'")).Count -eq 1 -and
        $packageBootstrap -match 'Assert-AuthenticatedAntigravityInstallState' -and
        $packageBootstrap -match 'Assert-AuthenticatedAntigravityPublicCLIAvailable' -and
        $packageBootstrap -notmatch "'CONNECTOR=none'|public-antigravity-rejection|fresh-none-install" -and
        $harnessText -match "\[string\]\`$State\.connector -cne 'antigravity'" -and
        $harnessText -match "\[string\]\`$State\.mode -cne 'action'") `
        'fresh exact Setup installs only connector=antigravity/action through the ordinary supported path'
    Assert-True (([regex]::Matches($packageBootstrap, "Write-Result 'package-setup:identity' pass")).Count -eq 1 -and
        $packageBootstrap -match 'Get-FileHash -LiteralPath \$script:PackagedSetupExecutable' -and
        $packageBootstrap -match '\.Hash\.ToLowerInvariant\(\)' -and
        $packageBootstrap -match 'package_source_commit=\$ExpectedPackageSourceCommit harness_source_commit=\$ExpectedHarnessSourceCommit installer_sha256=\$packagedSetupHash') `
        'authenticated results separately bind exact package and harness/workflow source commits plus recomputed lowercase installer SHA-256 once'
    Assert-True ($packageBootstrap -match '(?s)Save-AntigravityOriginalConfig\s+Write-AuthenticatedAntigravityCleanupManifest \$paths.*?public-antigravity-install.*?Assert-AuthenticatedAntigravityInstallState.*?Assert-PackagedAntigravityTrustedDiscovery.*?Assert-AuthenticatedAntigravityPublicCLIAvailable' -and
        $packageBootstrap -notmatch 'public-antigravity-rejection|fresh-none-install|Assert-AntigravityOriginalConfigRestored' -and
        $antigravitySupportedAvailability -match '\$stateBefore = \(Get-FileHash' -and
        $antigravitySupportedAvailability -match '\$configBefore = \(Get-FileHash' -and
        $antigravitySupportedAvailability -match '\$backupAfter -cne \$backupBefore' -and
        $hookFingerprint -match 'Assert-DisposableNoReparseAncestors' -and
        $hookFingerprint -match '-AllowedRoot \$Paths\.Profile' -and
        $hookFingerprint -match '(?s)Assert-DisposableNoReparseAncestors.*?\$exists = Test-Path' -and
        $hookFingerprint -match 'non-directory ancestor' -and
        $hookFingerprint -match 'path exists but is not a file' -and
        $hookFingerprint -match 'ReparsePoint' -and
        $hookFingerprint -match 'GetOwner\(\[Security\.Principal\.SecurityIdentifier\]\)' -and
        $hookFingerprint -match 'GetGroup\(\[Security\.Principal\.SecurityIdentifier\]\)' -and
        $hookFingerprint -match 'GetSecurityDescriptorSddlForm' -and
        $hookFingerprint -match 'SecuritySHA256') `
        'real Antigravity hook custody is captured before supported Setup and idempotent public init rejects state, config, or backup mutation'
    Assert-True ($packageBootstrap -notmatch 'preflight-uninstall' -and
        $packageBootstrap -match 'Invoke-AuthenticatedAntigravityCleanup -PreserveRunInputs' -and
        $packageBootstrap -match 'refuses preexisting install/data without its matching protected cleanup manifest' -and
        $packageFreshPreflight -match 'Assert-ExactPackagedSetup' -and
        $packageFreshPreflight -match 'Read-AuthenticatedAntigravityCleanupManifest' -and
        $packageFreshPreflight -match 'Assert-AuthenticatedAntigravityCleanupManifest' -and
        $packageFreshPreflight -match 'refuses install/data before protected cleanup-manifest authentication' -and
        $harnessText -match '(?s)Assert-AuthenticatedAntigravityFreshRunPreflight.*?\$script:ResultsPath') `
        'fresh-run preflight leaves residual state untouched unless a matching protected manifest authenticates recovery first'
    Assert-True ($connectorSetup -match "\`$Connector -eq 'antigravity' -and \`$AuthenticatedAntigravityRunner" -and
        $connectorSetup -match "'connector', 'reconcile', '--connector', 'antigravity'" -and
        $connectorSetup -match "'--data-dir', \`$env:DEFENSECLAW_HOME" -and
        $connectorSetup -match "'--config-home', \`$configHome" -and
        $connectorSetup -match 'Repair-AuthenticatedAntigravityPackage' -and
        $packageRepair -match "@\('/repair', '/quiet', '/norestart'\)" -and
        $packageRepair -match "@\('/upgrade', '/quiet', '/norestart'\)" -and
        $packageRepair -match 'upgraded package state' -and
        $packageRepair -notmatch "'CONNECTOR=") `
        'dedicated lane alone performs installer-shaped reconcile followed by no-override Setup repair and upgrade'
    Assert-True ($packageCleanup -match "@\('/uninstall', '/quiet', '/norestart', 'DELETEUSERDATA=1'\)" -and
        $harnessText -match 'Assert-AntigravityOriginalConfigRestored' -and
        $harnessText -match 'SHA-256 restored exactly; credentials untouched') `
        'authenticated teardown proves exact Antigravity hook restoration before package uninstall'
    Assert-True ($packageManifest -match 'Assert-ProtectedPackageArtifactRoot \$StateRoot' -and
        $packageManifest -match 'antigravity-package-cleanup\..*?\.tmp' -and
        $packageManifest -match '\[IO\.File\]::Move\(\$temporaryPath, \$manifestPath\)' -and
        $packageManifest -match 'setup_path' -and
        $packageManifest -match 'package_source_commit' -and
        $packageManifest -match 'harness_source_commit' -and
        $packageManifest -match 'install_root' -and
        $packageManifest -match 'config_home' -and
        $packageManifest -match 'original_hook_sha256' -and
        $packageManifest -match 'original_hook_owner_sid' -and
        $packageManifest -match 'original_hook_group_sid' -and
        $packageManifest -match 'original_hook_security_sha256' -and
        $packageManifest -notmatch 'original_hook_(?:content|bytes|base64)') `
        'protected durable cleanup manifest contains only exact non-secret identities and hook custody fingerprints'
    Assert-True ($packageManifestValidation -match 'expectedProperties' -and
        $packageManifestValidation -match 'Assert-ExactPath' -and
        $packageManifestValidation -match 'ExpectedPackageSourceCommit' -and
        $packageManifestValidation -match 'ExpectedHarnessSourceCommit' -and
        $packageManifestValidation -match 'original_hook_reparse' -and
        $packageManifestValidation -match 'original_hook_security_sha256' -and
        $packageRecovery -match 'Assert-ExactPackagedSetup' -and
        $packageRecovery -match 'Read-AuthenticatedAntigravityInstallState' -and
        $packageRecovery -match 'Assert-AuthenticatedAntigravityInstallState' -and
        $packageRecovery -match 'Set-AuthenticatedAntigravityInstalledPath' -and
        $packageRecovery -match 'Invoke-Teardown' -and
        $packageRecovery -match 'Assert-AntigravityOriginalConfigRestored' -and
        $packageRecovery -match 'Uninstall-AuthenticatedAntigravityPackage' -and
        $packageRecovery -match 'Stop-IsolatedProcessTree' -and
        ([regex]::Matches($packageRecovery, 'Remove-DisposableTreeSafely')).Count -ge 4 -and
        $packageRecovery -match '\[IO\.File\]::Delete\(\$manifestPath\)' -and
        $packageRecovery -match '\$PreserveRunInputs' -and
        $packageRecovery -match 'refuses install/data state without its protected manifest' -and
        $harnessText -match '(?s)if \(\$Operation -eq ''cleanup''\).*?AuthenticatedAntigravityRunner.*?Invoke-AuthenticatedAntigravityCleanup' -and
        $harnessText -match '(?s)try \{ Stop-IsolatedProcessTree \} finally \{\s*Invoke-AuthenticatedAntigravityCleanup') `
        'fresh cleanup authenticates custody and exact package state, independently drains teardown/uninstall/process phases, and removes only exact roots'
    Assert-True ($harnessText -match "ValidateSet\('full-hilt', 'enforcement-only'\)" -and
        $harnessText -match "ValidateSet\('fresh', 'existing'\)" -and
        $existingProfileBootstrap -match 'Assert-NoPreexistingDefenseClawRuntime' -and
        $existingProfileBootstrap -match 'maintenance Setup is not byte-identical' -and
        $existingProfileBootstrap -match 'Write-AuthenticatedAntigravityExistingHookBackup' -and
        $existingProfileBootstrap -match 'package-setup:repair-scope.*?unclaimed' -and
        $connectorSetup -match 'package-setup:repair-persistence.*?unclaimed' -and
        $connectorSetup -match 'no isolated Setup data-root primitive exists') `
        'existing-profile mode is an explicit protected input and never misrepresents Known-Folder-bound local repair as isolated evidence'
    Assert-True ($packagePaths -match 'LaneDataRoot' -and
        $existingVendorCustody -match 'bounded 64-entry custody inventory' -and
        $existingVendorCustody -match 'GetSecurityDescriptorSddlForm' -and
        $existingVendorCustody -match 'Get-FileHash.*?SHA256' -and
        $existingVendorCustody -match 'Assert-AuthenticatedAntigravityVendorFingerprint' -and
        $existingHookCustody -match 'original-hooks\.json' -and
        $existingHookCustody -match 'hook security changed before restoration' -and
        $existingHookCustody -match '\[IO\.FileMode\]::Open' -and
        $existingHookCustody -match '\$destination\.Flush\(\$true\)' -and
        $existingHookCustody -match 'FileSystemAclExtensions.*?SetAccessControl' -and
        $existingHookCustody -match 'SetAttributes' -and
        $existingHookCustody -match 'Assert-AntigravityOriginalConfigRestored' -and
        $existingProfileCleanup -match 'Restore-AuthenticatedAntigravityHookFromCustody' -and
        $existingProfileCleanup -match 'Assert-AuthenticatedAntigravityExistingPackageFingerprint' -and
        $existingProfileCleanup -match 'credentials untouched') `
        'existing-profile custody snapshots and restores hook bytes/security while authenticating unchanged package and vendor trees without touching credentials'
    Assert-True ($packageManifest -match 'certification_scope' -and
        $packageManifest -match 'profile_custody_mode' -and
        $packageManifest -match 'lane_data_root' -and
        $packageManifest -match 'original_hook_backup_path' -and
        $packageManifest -match 'existing_vendor_sha256' -and
        $packageManifest -match 'existing_install_state_sha256' -and
        $packageManifestValidation -match 'existing-profile hook SDDL does not match' -and
        $packageManifestValidation -match 'existing-profile exact-package custody drifted') `
        'protected continuation binds scope, task-specific data, hook recovery, official vendor custody, and exact installed package identity'
    $clientCleanupDiagnostic = [regex]::Match(
        $packageRecovery,
        '(?s)if \(\[bool\]\$manifest\.vendor_mutation_started\).*?(?=\n\s*if \(Test-Path -LiteralPath \$paths\.InstallRoot\))'
    ).Value
    Assert-True (-not [string]::IsNullOrWhiteSpace($clientCleanupDiagnostic) -and
        $clientCleanupDiagnostic -match '(?s)try \{\s*Assert-OfficialAntigravityClient \$paths\s*\} catch \{' -and
        $clientCleanupDiagnostic -match '\$cleanupFailure = \$_\.Exception' -and
        $clientCleanupDiagnostic -notmatch '\$cleanupIncomplete' -and
        $packageRecovery -match '(?s)try \{\s*Stop-AuthenticatedAntigravityHeldTUIProcess.*?catch \{.*?\$cleanupIncomplete = \$true' -and
        $packageRecovery -match '(?s)Remove-DisposableTreeSafely -Path \$StateRoot.*?Remove-DisposableTreeSafely -Path \$packageRoot.*?if \(\$null -ne \$cleanupFailure\) \{ throw \$cleanupFailure \}') `
        'client drift is retained as the primary diagnostic while exact authenticated teardown/restoration/removal continues; foreign or reused live TUI identity keeps cleanup incomplete'
    Assert-True ($harnessText -match 'public-init:supported' -and
        $harnessText -match 'ordinary CLI exit=0; idempotent install/config/hook/custody state unchanged; evidence fields remain empty and live=false' -and
        $harnessText -match 'authentication, HITL, and live evidence remain unverified and unclaimed') `
        'authenticated lane reports supported public availability without fabricating certification evidence'
    $officialInstallerContract = [regex]::Match(
        $harnessText,
        '(?s)function Assert-OfficialAntigravityInstaller\b.*?(?=\nfunction Read-OfficialAntigravityReleaseManifest\b)'
    ).Value
    $officialManifestContract = [regex]::Match(
        $harnessText,
        '(?s)function Read-OfficialAntigravityReleaseManifest\b.*?(?=\nfunction Assert-FreshAntigravityVendorBaseline\b)'
    ).Value
    $officialClientIdentityContract = [regex]::Match(
        $harnessText,
        '(?s)function Assert-OfficialAntigravityClientIdentity\b.*?(?=\nfunction Assert-OfficialAntigravityClient\b)'
    ).Value
    $officialClientContract = [regex]::Match(
        $harnessText,
        '(?s)function Assert-OfficialAntigravityClient\b.*?(?=\nfunction Assert-PackagedAntigravityTrustedDiscovery\b)'
    ).Value
    $officialClientInstallContract = [regex]::Match(
        $harnessText,
        '(?s)function Install-OfficialAntigravityClient\b.*?(?=\nfunction Invoke-AuthenticatedAntigravitySetup\b)'
    ).Value
    $trustedDiscoveryContract = [regex]::Match(
        $harnessText,
        '(?s)function Assert-PackagedAntigravityTrustedDiscovery\b.*?(?=\nfunction Install-OfficialAntigravityClient\b)'
    ).Value
    $heldStateContract = [regex]::Match(
        $harnessText,
        '(?s)function Get-AuthenticatedAntigravityHeldStatePath\b.*?(?=\nfunction Invoke-AuthenticatedAntigravityCleanup\b)'
    ).Value
    $interactivePrepare = [regex]::Match(
        $harnessText,
        '(?s)function Invoke-AuthenticatedAntigravityInteractivePrepare\b.*?(?=\nfunction Initialize-AuthenticatedAntigravityHeldOperation\b)'
    ).Value
    $hiltConfig = [regex]::Match(
        $harnessText,
        '(?s)function Initialize-AuthenticatedAntigravityHILTConfig\b.*?(?=\nfunction Assert-AuthenticatedAntigravityConfiguredPosture\b)'
    ).Value
    $configuredPosture = [regex]::Match(
        $harnessText,
        '(?s)function Assert-AuthenticatedAntigravityConfiguredPosture\b.*?(?=\nfunction Repair-AuthenticatedAntigravityPackage\b)'
    ).Value
    $interactiveHold = [regex]::Match(
        $harnessText,
        '(?s)function Invoke-AuthenticatedAntigravityInteractiveHold\b.*?(?=\nfunction Get-AuthenticatedAntigravityInteractiveRecords\b)'
    ).Value
    $interactiveEvidence = [regex]::Match(
        $harnessText,
        '(?s)function Assert-AuthenticatedAntigravityInteractiveRecordSet\b.*?(?=\nfunction Invoke-AuthenticatedAntigravityInteractiveResume\b)'
    ).Value
    $interactiveResume = [regex]::Match(
        $harnessText,
        '(?s)function Invoke-AuthenticatedAntigravityInteractiveResume\b.*?(?=\nfunction Get-NormalizedExecutablePath\b)'
    ).Value
    Assert-True ($harnessText -match "F1B32785-6FBA-4FCF-9D55-7B8E7F157091" -and
        $harnessText -match "5E6C858F-0E22-4760-9AFE-EA3317B67173" -and
        $packagePaths -match "AntigravityExecutable = Join-Path \`$localAppData 'agy\\bin\\agy\.exe'" -and
        $packagePaths -match "AntigravityProfileRoot = Join-Path \`$profile '\.gemini'") `
        'interactive Antigravity lifecycle uses token-bound LocalAppData/Profile Known Folders for canonical vendor and config roots'
    Assert-True ($harnessText -match [regex]::Escape('https://antigravity.google/cli/install.ps1') -and
        $harnessText -match '51c2cb4fada22ce0228da71b9506370383d6544bfebcec85fe7616a52b805344' -and
        $officialInstallerContract -match 'Assert-ProtectedPackageArtifactRoot' -and
        $officialInstallerContract -match 'Assert-DisposableNoReparseAncestors' -and
        $officialInstallerContract -match 'reviewed option contract' -and
        $officialInstallerContract -match 'Invoke-Expression' -and
        $officialManifestContract -match 'MaximumRedirection 0' -and
        $harnessText -match [regex]::Escape('https://storage.googleapis.com/antigravity-public/antigravity-cli/1.1.10-6423386432339968/windows-x64/cli_windows_x64.exe') -and
        $officialManifestContract -match 'official Antigravity release manifest drifted') `
        'official installer and update provenance reject hash, option-contract, redirect, host, URL, version, and release-digest drift'
    $officialClientContractPredicate = {
        param(
            [string]$IdentityContract,
            [string]$ClientContract,
            [string]$InstallContract,
            [string]$Source
        )
        $identityCall = $ClientContract.IndexOf(
            'Assert-OfficialAntigravityClientIdentity $Paths',
            [StringComparison]::Ordinal
        )
        $versionProbe = $ClientContract.IndexOf(
            'Invoke-NativeProcess',
            [StringComparison]::Ordinal
        )
        $manifestRead = $InstallContract.IndexOf(
            'Read-OfficialAntigravityReleaseManifest',
            [StringComparison]::Ordinal
        )
        $installerRun = $InstallContract.IndexOf(
            'Invoke-NativeProcess',
            [StringComparison]::Ordinal
        )
        $clientValidation = $InstallContract.IndexOf(
            'Assert-OfficialAntigravityClient $Paths',
            [StringComparison]::Ordinal
        )
        return (
            -not [string]::IsNullOrWhiteSpace($IdentityContract) -and
            -not [string]::IsNullOrWhiteSpace($ClientContract) -and
            -not [string]::IsNullOrWhiteSpace($InstallContract) -and
            $IdentityContract -match "Join-Path \`$Paths.LocalAppData 'agy\\bin\\agy\.exe'" -and
            $IdentityContract -match '(?s)Assert-DisposableNoReparseAncestors.*?-AllowedRoot \$Paths\.LocalAppData -RequireExists' -and
            $IdentityContract -match '(?s)PSIsContainer.*?ReparsePoint' -and
            $IdentityContract -match '(?s)Get-FileHash.*?-Algorithm SHA512.*?\$hash -cne \$script:AntigravityOfficialBinarySHA512' -and
            $IdentityContract -match '(?s)Get-AuthenticodeSignature.*?Status.*?SignerCertificate\.Subject -cne \$script:AntigravityOfficialSignerSubject.*?SignerCertificate\.Thumbprint -cne \$script:AntigravityOfficialSignerThumbprint' -and
            $Source.Contains('$script:AntigravityOfficialVersion = ''1.1.10''') -and
            $Source.Contains('$script:AntigravityOfficialBinarySHA512 = ''b2fee3202b1083308621715e3332c4b8280a0dfb0e13a6de0d4140db09a64d9c877b3274f3dc1dbaee86c0c67b4f665ef1c260fe5d4ec761a8cd48feaf19d8ea''') -and
            $Source.Contains('$script:AntigravityOfficialSignerSubject = ''CN=Google LLC, O=Google LLC, L=Mountain View, S=California, C=US, SERIALNUMBER=3582691, OID.2.5.4.15=Private Organization, OID.1.3.6.1.4.1.311.60.2.1.2=Delaware, OID.1.3.6.1.4.1.311.60.2.1.3=US''') -and
            $Source.Contains('$script:AntigravityOfficialSignerThumbprint = ''607A3EDAA64933E94422FC8F0C80388E0590986C''') -and
            $identityCall -ge 0 -and $versionProbe -gt $identityCall -and
            $ClientContract -match '(?s)''--version''.*?1\\\.1\\\.10.*?\$versions\.Count -ne 1' -and
            $InstallContract -match "'--skip-aliases', '--skip-path'" -and
            $InstallContract -notmatch '(?i)--dir' -and
            $manifestRead -ge 0 -and $installerRun -gt $manifestRead -and
            $clientValidation -gt $installerRun
        )
    }
    Assert-True (& $officialClientContractPredicate $officialClientIdentityContract `
        $officialClientContract $officialClientInstallContract $harnessText) `
        'canonical client install pins exact LocalAppData path, official bytes/version/signature, and documented no-alias/no-PATH flags'
    $officialClientContractMutations = @(
        [pscustomobject]@{ Name = 'noncanonical executable path'; Identity = $officialClientIdentityContract.Replace('agy\bin\agy.exe', 'agy\bin\other.exe'); Client = $officialClientContract; Install = $officialClientInstallContract; Source = $harnessText },
        [pscustomobject]@{ Name = 'missing non-reparse custody'; Identity = $officialClientIdentityContract.Replace('Assert-DisposableNoReparseAncestors', 'Skip-DisposableNoReparseAncestors'); Client = $officialClientContract; Install = $officialClientInstallContract; Source = $harnessText },
        [pscustomobject]@{ Name = 'weakened binary digest'; Identity = $officialClientIdentityContract.Replace('-Algorithm SHA512', '-Algorithm SHA256'); Client = $officialClientContract; Install = $officialClientInstallContract; Source = $harnessText },
        [pscustomobject]@{ Name = 'missing Authenticode verification'; Identity = $officialClientIdentityContract.Replace('Get-AuthenticodeSignature', 'Skip-AuthenticodeSignature'); Client = $officialClientContract; Install = $officialClientInstallContract; Source = $harnessText },
        [pscustomobject]@{ Name = 'unreviewed binary digest'; Identity = $officialClientIdentityContract; Client = $officialClientContract; Install = $officialClientInstallContract; Source = $harnessText.Replace('b2fee3202b1083308621715e3332c4b8280a0dfb0e13a6de0d4140db09a64d9c877b3274f3dc1dbaee86c0c67b4f665ef1c260fe5d4ec761a8cd48feaf19d8ea', ('0' * 128)) },
        [pscustomobject]@{ Name = 'unreviewed signer subject'; Identity = $officialClientIdentityContract; Client = $officialClientContract; Install = $officialClientInstallContract; Source = $harnessText.Replace('SERIALNUMBER=3582691', 'SERIALNUMBER=0000000') },
        [pscustomobject]@{ Name = 'unreviewed signer thumbprint'; Identity = $officialClientIdentityContract; Client = $officialClientContract; Install = $officialClientInstallContract; Source = $harnessText.Replace('607A3EDAA64933E94422FC8F0C80388E0590986C', ('0' * 40)) },
        [pscustomobject]@{ Name = 'version before identity'; Identity = $officialClientIdentityContract; Client = $officialClientContract.Replace('Assert-OfficialAntigravityClientIdentity $Paths', "Invoke-NativeProcess`n    Assert-OfficialAntigravityClientIdentity `$Paths"); Install = $officialClientInstallContract; Source = $harnessText },
        [pscustomobject]@{ Name = 'unreviewed client version'; Identity = $officialClientIdentityContract; Client = $officialClientContract.Replace('1\.1\.10', '1\.1\.11'); Install = $officialClientInstallContract; Source = $harnessText },
        [pscustomobject]@{ Name = 'missing no-PATH installer flag'; Identity = $officialClientIdentityContract; Client = $officialClientContract; Install = $officialClientInstallContract.Replace("'--skip-aliases', '--skip-path'", "'--skip-aliases'"); Source = $harnessText },
        [pscustomobject]@{ Name = 'installer directory override'; Identity = $officialClientIdentityContract; Client = $officialClientContract; Install = $officialClientInstallContract.Replace("'--skip-aliases', '--skip-path'", "'--skip-aliases', '--skip-path', '--dir'"); Source = $harnessText },
        [pscustomobject]@{ Name = 'client validation before install'; Identity = $officialClientIdentityContract; Client = $officialClientContract; Install = $officialClientInstallContract.Replace('Assert-FreshAntigravityVendorBaseline $Paths', "Assert-OfficialAntigravityClient `$Paths`n    Assert-FreshAntigravityVendorBaseline `$Paths"); Source = $harnessText }
    )
    foreach ($mutation in $officialClientContractMutations) {
        Assert-True (-not (& $officialClientContractPredicate $mutation.Identity `
            $mutation.Client $mutation.Install $mutation.Source)) `
            "canonical Antigravity client contract rejects $($mutation.Name)"
    }
    Assert-True ($packageBootstrap -match 'Assert-PackagedAntigravityTrustedDiscovery' -and
        $trustedDiscoveryContract -match "'agent', 'discover', '--refresh', '--no-cache', '--json', '--no-emit-otel'" -and
        $trustedDiscoveryContract -match 'packaged trusted-discovery ACL/reparse gate' -and
        $trustedDiscoveryContract -match 'Assert-ExactPath' -and
        $trustedDiscoveryContract -match '1\\\.1\\\.10') `
        'canonical client eligibility is accepted only through packaged trusted discovery with exact path and version'
    Assert-True ($heldStateContract -match "phase = 'armed'" -and
        $heldStateContract -match "ValidateSet\('held', 'interactive', 'awaiting_resume'\)" -and
        $heldStateContract -match "(?s)'workflow_repository'.*?'prepare_run_id'.*?'prepare_run_attempt'.*?'package_run_id'" -and
        $heldStateContract -match "(?s)'package_artifact_id'.*?'package_artifact_digest'.*?'package_source_commit'.*?'harness_source_commit'" -and
        $heldStateContract -match "(?s)'setup_sha256'.*?'setup_provenance_sha256'" -and
        $heldStateContract -match "(?s)'official_installer_sha256'.*?'official_binary_sha512'" -and
        $heldStateContract -match "(?s)'active_hook_length'.*?'active_hook_security_sha256'.*?'tui_process_state'.*?'tui_process_exit_code'" -and
        $heldStateContract -match 'RandomNumberGenerator' -and
        $heldStateContract -match '\$RequireHoldID' -and
        $heldStateContract -match 'prepare_run_id -cne \$AntigravityPrepareRunID' -and
        $heldStateContract -match 'prepare_run_attempt -cne \$AntigravityPrepareRunAttempt' -and
        $heldStateContract -match 'Assert-ExactPath' -and
        $heldStateContract -match 'setup package bytes drifted|held-state package bytes drifted' -and
        $heldStateContract -match 'Assert-AuthenticatedAntigravityCleanupManifestCustody' -and
        $heldStateContract -match 'Assert-AuthenticatedAntigravityTUIProcessIdentity' -and
        $heldStateContract -match 'PID/start identity is foreign or reused' -and
        $heldStateContract -match "held-state TUI process image") `
        'held-state schema authenticates stale/wrong phase, hold, run/attempt, SHA, artifact, manifest, profile, path, DACL/reparse, and exact TUI PID/start/image identity'
    Assert-True ($packageBootstrap -match '(?s)Save-AntigravityOriginalConfig\s+Write-AuthenticatedAntigravityCleanupManifest \$paths.*?New-AuthenticatedAntigravityHeldState.*?Install-OfficialAntigravityClient' -and
        $packageRecovery -match 'AntigravityVendorRoot' -and
        $packageRecovery -match 'AntigravityStagingRoot' -and
        $packageRecovery -match 'Assert-AntigravityOriginalConfigRestored' -and
        $packageRecovery -match 'never calls /logout or accesses' -and
        $packageRecovery -match 'Remove-DisposableTreeSafely') `
        'cleanup and held-state manifests are durable before vendor/product/config mutation and recovery removes only manifest-created exact roots without credentials access'
    Assert-True ($interactivePrepare -match 'Initialize-AuthenticatedAntigravityHILTConfig' -and
        $hiltConfig -match "'--connector', 'none', '--profile', 'action', '--human-approval'" -and
        $hiltConfig -match "'--hilt-min-severity', 'HIGH'" -and
        $connectorSetup -match "(?s)Assert-AuthenticatedAntigravityConfiguredPosture\s+.*?'reconcile'" -and
        $connectorSetup -match "(?s)Assert-AuthenticatedAntigravityConfiguredPosture\s+.*?'ready' -RequireGatewayRunning" -and
        $packageRepair -match "(?s)Assert-AuthenticatedAntigravityConfiguredPosture\s+.*?'repair'" -and
        $packageRepair -match "(?s)Assert-AuthenticatedAntigravityConfiguredPosture\s+.*?'upgrade'" -and
        $configuredPosture -match "'status', '--json'" -and
        $configuredPosture -match "source -cne 'manual'" -and
        $configuredPosture -match "mode -cne 'action'" -and
        $configuredPosture -match 'guardrail\\\.hilt\\\.min_severity' -and
        $configuredPosture -match 'install_state_connector=\$stateConnector' -and
        $configuredPosture -match 'Assert-AuthenticatedAntigravityExistingInstallState' -and
        $interactivePrepare -match 'Assert-AuthenticatedAntigravityInstallState' -and
        $interactivePrepare -match 'Assert-OfficialAntigravityClient' -and
        $interactivePrepare -match 'Assert-AntigravityWindowsHookCommands' -and
        $interactivePrepare -match 'Assert-DoctorWindowsHookRegistration' -and
        $interactivePrepare -match "defenseclaw-gateway' @\('status'\)" -and
        $interactivePrepare -match 'Read-AuthenticatedAntigravityCleanupManifest' -and
        $interactivePrepare -match 'Set-AuthenticatedAntigravityHeldStatePhase \$heldState held') `
        'prepare reaches held only after exact package/client, five events, readiness, Doctor/status, custody, and both manifests validate'
    Assert-True ($interactiveHold -match 'Assert-DoctorWindowsHookRegistration' -and
        $interactiveHold -match "defenseclaw-gateway' @\('status'\)" -and
        $interactiveHold -match "(?s)Assert-AuthenticatedAntigravityConfiguredPosture\s+.*?'interactive-hold' -RequireGatewayRunning" -and
        $interactiveHold -match 'Start-Process -FilePath \$context\.Paths\.AntigravityExecutable' -and
        $interactiveHold -match '-NoNewWindow -PassThru' -and
        $interactiveHold -notmatch 'dangerously-skip-permissions|--print|-ArgumentList' -and
        $interactiveHold -match 'Set-AuthenticatedAntigravityHeldStateTUIProcess' -and
        $interactiveHold -match 'Set-AuthenticatedAntigravityHeldStateTUIExited' -and
        $interactiveHold -match 'Set-AuthenticatedAntigravityHeldStatePhase \$context\.State interactive' -and
        $interactiveHold -match 'Set-AuthenticatedAntigravityHeldStatePhase \$current awaiting_resume' -and
        $interactiveHold -match 'ASK/APPROVE' -and
        $interactiveHold -match 'ASK/DECLINE' -and
        $interactiveHold -match 'Do not use /logout' -and
        $interactiveResume -match "defenseclaw-gateway' @\('status'\)" -and
        $interactiveResume -match "(?s)Assert-AuthenticatedAntigravityConfiguredPosture\s+.*?'interactive-resume' -RequireGatewayRunning" -and
        $interactiveResume -match 'Get-AuthenticatedAntigravityHeldStateActiveHook') `
        'hold/resume revalidate exact ready posture and HILT immediately around a no-argument native TUI whose PID/start/image identity is durable'
    foreach ($eventName in @('PreInvocation', 'PreToolUse', 'PostToolUse', 'PostInvocation', 'Stop')) {
        Assert-True ($interactiveEvidence -match [regex]::Escape("'$eventName'")) `
            "interactive evidence schema requires authentic $eventName delivery"
    }
    Assert-True ($interactiveEvidence -match "\`$allow\.Count -ne 1" -and
        $interactiveEvidence -match "\`$deny\.Count -ne 1" -and
        $interactiveEvidence -match '\$expectedAskCount = if \(\$AntigravityCertificationScope' -and
        $interactiveEvidence -match "'enforcement-only'" -and
        $harnessText -match "Get-JsonPropertyValue \`$correlation 'tool_invocation_id'" -and
        $interactiveEvidence -match 'lacks canonical record/request/tool identities' -and
        $interactiveEvidence -match 'reused a tool-invocation identity' -and
        $interactiveEvidence -match 'lacks an authentic record identity' -and
        $interactiveEvidence -match 'CMD-SOCAT-EXEC' -and
        $interactiveEvidence -match 'CMD-ENV-DUMP' -and
        $interactiveEvidence -match "native_decision = 'ask'" -and
        $interactiveEvidence -match "native_interaction = 'approved'" -and
        $interactiveEvidence -match "native_interaction = 'declined'" -and
        $interactiveEvidence -notmatch '(?s)PostToolUse.*?step_idx\s+-ceq' -and
        $interactiveEvidence -match '\$allowPost.Count -lt 1' -and
        $interactiveEvidence -match '\$denyPost.Count -ne 0' -and
        $interactiveEvidence -match '\$approvedPost.Count -lt 1' -and
        $interactiveEvidence -match '\$declinedPost.Count -ne 0' -and
        $interactiveEvidence -match 'ask_approve' -and
        $interactiveEvidence -match 'ask_decline' -and
        $interactiveEvidence -match 'HITL ask/approve/decline is excluded, unverified, unclaimed' -and
        $interactiveEvidence -match 'raw protected-lane test output; not certification') `
        'correlation-bound evidence keeps the full-HITL lane and explicitly unclaims HITL for enforcement-only scope'
    $heldStateFixtureContract = [regex]::Match(
        $harnessText,
        '(?s)function Invoke-AuthenticatedAntigravityHeldStateFixture\b.*?(?=\nif \(\$HeldStateFixture\))'
    ).Value
    $fixtureRootContract = [regex]::Match(
        $harnessText,
        '(?s)function Resolve-AuthenticatedAntigravityFixtureRoot\b.*?(?=\r?\nfunction )'
    ).Value
    $protectTestDirectoryContract = [regex]::Match(
        $harnessText,
        '(?s)function Protect-TestDirectory\b.*?(?=\r?\nfunction )'
    ).Value
    $protectedArtifactRootContract = [regex]::Match(
        $harnessText,
        '(?s)function New-ProtectedPackageArtifactRoot\b.*?(?=\r?\nfunction )'
    ).Value
    Assert-True ($heldStateFixtureContract -match
            "Resolve-AuthenticatedAntigravityFixtureRoot 'held-state'" -and
        $fixtureRootContract -match '\[IO\.Path\]::GetFileName\(\$fixtureRoot\)' -and
        $fixtureRootContract -match "'\^dc-antigravity-'" -and
        $fixtureRootContract -match '\$parent\.Exists' -and
        $fixtureRootContract -match 'FileAttributes\]::ReparsePoint' -and
        $fixtureRootContract -match 'Assert-DisposableNoReparseAncestors' -and
        $protectTestDirectoryContract -match 'test directory path has no existing ancestor' -and
        $protectTestDirectoryContract -match 'test directory path is not a regular directory' -and
        $protectedArtifactRootContract.Contains(
            "if ([IO.Path]::GetPathRoot(`$root) -cne 'D:\')"
        ) -and
        $heldStateFixtureContract -match 'New-AuthenticatedAntigravityHeldStateDocument' -and
        $heldStateFixtureContract -match 'Assert-AuthenticatedAntigravityCleanupManifest' -and
        $heldStateFixtureContract -match 'Assert-AuthenticatedAntigravityRecoveryCompanion' -and
        $heldStateFixtureContract -match 'package source SHA' -and
        $heldStateFixtureContract -match 'harness source SHA' -and
        $heldStateFixtureContract -match 'Assert-AuthenticatedAntigravityTUIProcessIdentity' -and
        $heldStateFixtureContract -match 'foreign TUI PID identity' -and
        $heldStateFixtureContract -match 'reused TUI PID start identity' -and
        $heldStateFixtureContract -match 'foreign TUI image identity' -and
        $heldStateFixtureContract -match 'Assert-AuthenticatedAntigravityInteractiveRecordSet' -and
        $heldStateFixtureContract -match 'PostToolUse step-only correlation' -and
        $heldStateFixtureContract -match 'Assert-AuthenticatedAntigravitySecurityDescriptor' -and
        $heldStateFixtureContract -match 'Assert-AuthenticatedAntigravityPlainAttributes' -and
        $heldStateFixtureContract -match 'Assert-DisposableNoReparseAncestors' -and
        $heldStateFixtureContract -match 'Assert-AuthenticatedAntigravityTerminalMarkerDocument' -and
        $heldStateFixtureContract -match 'Remove-DisposableTreeSafely' -and
        $heldStateFixtureContract -match "'interactive', 'cancelled'" -and
        $heldStateFixtureContract -match 'dynamic fixture: PASS') `
        'task-temp dynamic fixture retains GUID containment, ancestor/reparse gates, the production D: contract, and held-state security coverage'
    $heldWorkflowJob = [regex]::Match(
        $liveWorkflowText,
        '(?ms)^  windows-antigravity-held-state:.*?(?=^  # -+\r?$\n  # Report)'
    ).Value
    Assert-True ($heldWorkflowJob -match 'D:\\DefenseClaw-PR655-Antigravity-Held-State' -and
        $liveWorkflowText -match 'antigravity_certification_scope:' -and
        $liveWorkflowText -match 'antigravity_profile_custody:' -and
        $heldWorkflowJob -match 'DC_ANTIGRAVITY_CERTIFICATION_SCOPE' -and
        $heldWorkflowJob -match 'DC_ANTIGRAVITY_PROFILE_CUSTODY' -and
        $heldWorkflowJob -match 'Existing-profile Antigravity custody is restricted to explicit enforcement-only scope' -and
        $heldWorkflowJob -match 'campaign path has a foreign owner' -and
        $heldWorkflowJob -notmatch '\$security\.SetOwner' -and
        $heldWorkflowJob -match 'AntigravityCertificationScope = \$env:DC_ANTIGRAVITY_CERTIFICATION_SCOPE' -and
        $heldWorkflowJob -match 'AntigravityProfileCustodyMode = \$env:DC_ANTIGRAVITY_PROFILE_CUSTODY' -and
        $liveWorkflowText -match "format\('connector-live-e2e-antigravity-held-state-\{0\}', github\.repository_id\)" -and
        $liveWorkflowText -match "cancel-in-progress:.*?antigravity_phase != 'automated'" -and
        $heldWorkflowJob -notmatch '\$\{\{ github\.workspace \}\}.*?DC_WINDOWS_STATE|RUNNER_TEMP.*?DC_WINDOWS_STATE' -and
        $heldWorkflowJob -match 'inputs\.antigravity_phase == ''prepare''' -and
        $heldWorkflowJob -match "inputs\.antigravity_phase != 'prepare'" -and
        $heldWorkflowJob -match 'RequestMessage\.RequestUri\.AbsoluteUri' -and
        $heldWorkflowJob -match 'MaximumRedirection 0' -and
        $heldWorkflowJob -match '-Operation hold' -and
        $heldWorkflowJob -match 'DC_ANTIGRAVITY_DEDICATED_RUNNER' -and
        $heldWorkflowJob -match 'GitHub Actions cannot supply the native TUI' -and
        $heldWorkflowJob -match 'hard cancellation cannot guarantee an Actions safety step executes' -and
        $heldWorkflowJob -match 'Protected Antigravity failure cleanup safety net' -and
        $heldWorkflowJob -match '-Operation cleanup') `
        'workflow serializes and exempts fixed-D prepare/resume/recovery from cancellation while truthfully requiring the local interactive TUI and durable cancel recovery'
    Assert-True ($liveWorkflowText -match 'windows_package_source_commit:' -and
        $heldWorkflowJob -match 'INPUT_PACKAGE_SOURCE_COMMIT' -and
        $heldWorkflowJob -match '\$run\.head_sha -cne \$requiredPackageSource' -and
        $heldWorkflowJob -match 'RECOVERY_HARNESS_SOURCE_COMMIT -cne \$env:EXPECTED_HARNESS_SHA' -and
        $heldWorkflowJob -match 'package_source_commit=\$requiredPackageSource' -and
        $heldWorkflowJob -match 'ExpectedPackageSourceCommit = ''\$\{\{ steps\.package\.outputs\.package_source_commit \}\}''' -and
        $heldWorkflowJob -match 'ExpectedHarnessSourceCommit = ''\$\{\{ inputs\.antigravity_phase == ''prepare'' && github\.sha \|\| steps\.recovery\.outputs\.harness_source_commit \}\}''' -and
        $heldWorkflowJob -match '-ExpectedPackageSourceCommit ''\$\(\$state\.package_source_commit\)''' -and
        $heldWorkflowJob -match '-ExpectedHarnessSourceCommit ''\$\(\$state\.harness_source_commit\)''') `
        'protected lifecycle separately authenticates immutable product package source/run/artifact identity and the exact harness/workflow commit used for prepare/hold/resume'
    $wizardConnectorChoices = [regex]::Match(
        $setupWizardSourceText,
        '(?s)wizardConnectorChoices = \[\]wizardChoice\{.*?\n\s*\}'
    ).Value
    Assert-True ($wizardConnectorChoices -match 'Google Antigravity.*?antigravity' -and
        $setupMainSourceText -match 'CONNECTOR=amp\|antigravity\|codex\|claudecode\|copilot\|cursor\|devin\|hermes\|omnigent\|opencode\|none' -and
        $setupMainSourceText -notmatch 'Antigravity is not_certified and cannot be selected by public Setup' -and
        $setupMainTestsText -match 'TestParseArgsAllowsPublicAntigravitySetupSelection' -and
        $setupMainTestsText -match 'TestParseArgsAllowsRecordedAntigravityMaintenanceWithoutOverride' -and
        $setupMainTestsText -match 'TestPrintUsageAdvertisesPublicAntigravitySelection' -and
        $setupMainSourceText -match 'internalSetupParentEnv') `
        'exact-head source/unit linkage exposes supported Antigravity while preserving internal Setup parent binding'
    Assert-True ($contractRun -match "(?s)try\s*\{.*?DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT = '1'.*?Invoke-Setup action.*?\}\s*finally\s*\{.*?Remove-Item Env:DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT") `
        'unversioned fixture override is removed before Doctor tamper validation'
    $liveRun = [regex]::Match($harnessText, '(?s)function Invoke-LiveRun\b.*?\n\}').Value
    Assert-True ($contractRun -notmatch 'Assert-CodexPinnedTrustMatrix' -and
        $liveRun -match 'Assert-CodexPinnedTrustMatrix') `
        'official npm trust probes stay in manual live-client certification, not mandatory deterministic CI'
    $nativeProcessContract = [regex]::Match(
        $harnessText,
        '(?s)function Invoke-NativeProcess\b.*?(?=\r?\nfunction )'
    ).Value
    $ampResultGateContract = [regex]::Match(
        $harnessText,
        '(?s)function Assert-AmpAuthenticatedToolResultGate\b.*?(?=\r?\nfunction )'
    ).Value
    $ampProviderContract = [regex]::Match(
        $harnessText,
        '(?s)function Assert-AmpFiveEventProviderProvenance\b.*?(?=\r?\nfunction )'
    ).Value
    Assert-True ($nativeProcessContract -match '\$start\.UseShellExecute = \$false' -and
        $nativeProcessContract -match
            'foreach \(\$argument in \$ArgumentList\) \{ \[void\]\$start\.ArgumentList\.Add\(\$argument\) \}' -and
        $invokeAgentContract -match
            'Invoke-NativeProcess .*?-ArgumentList \$agentArgs') `
        'authenticated prompts use opaque ProcessStartInfo arguments without cmd.exe transport'
    Assert-True ($ampResultGateContract -match
            '\$syntheticAWSAccessKey = ''AKIA'' \+ ''DEFENSECLAW12345''' -and
        $ampResultGateContract -match 'Get-Content -Raw -LiteralPath' -and
        $ampResultGateContract -match 'RESULT_WITHHELD' -and
        $ampResultGateContract -match '''tool\.call''' -and
        $ampResultGateContract -match '''tool\.result''' -and
        $ampResultGateContract -match '''SEC-AWS-KEY''' -and
        $ampResultGateContract -match '\$toolCall\.action -cne ''allow''' -and
        $ampResultGateContract -match '\$toolResult\.action -cne ''block''' -and
        $liveRun -match 'Assert-AmpAuthenticatedToolResultGate \$sentinelRoot' -and
        $contractRun -notmatch 'Assert-AmpAuthenticatedToolResultGate') `
        'authenticated Amp live coverage proves post-tool output withholding without adding secrets to deterministic CI'
    Assert-True ($ampProviderContract -match
            '(?s)''session\.start''.*?''agent\.start''.*?''tool\.call''.*?''tool\.result''.*?''agent\.end''' -and
        $ampProviderContract -match
            '(?s)''session_start''.*?''turn_start''.*?''tool_start''.*?''tool_end''.*?''turn_end''' -and
        $ampProviderContract -match
            'PSObject\.Properties\[''gen_ai\.provider\.name''\]' -and
        $ampProviderContract -match
            'PSObject\.Properties\[''gen_ai\.request\.model''\]' -and
        $contractRun -match 'Invoke-AmpFiveEventProviderContract \$golden') `
        'deterministic Amp coverage requires exact five-event connector identity and absent unreported provider/model fields'
    Assert-True (
        $ampHookTestText.Contains(
            'func TestAMPFiveEventCanonicalObservability'
        ) -and
        $ampHookTestText.Contains(
            'if got := attributes["gen_ai.provider.name"]; got != ""'
        ) -and
        $ampHookTestText.Contains(
            'if got, present := wire.Body["gen_ai.provider.name"]; present'
        ) -and
        $ampHookTestText.Contains(
            'point.attributes["gen_ai.provider.name"]; got != "unknown"'
        ) -and
        $ampHookTestText.Contains(
            'attributes["defenseclaw.connector.source"] != "amp"'
        )
    ) 'native Amp capture test proves span/log provider absence and required metric unknown fallback'
    Assert-True ($harnessText -match "@\('0\.129\.0', '0\.133\.0', '0\.144\.3'\)" -and
        $harnessText -match "method = 'hooks/list'" -and
        $harnessText -match "trustStatus -cne 'managed'" -and
        $harnessText -match "source -cne 'legacyManagedConfigFile'" -and
        $harnessText -match "managed_config\.toml" -and
        $harnessText -match '\$hook\.command -cne \$expectedCommand' -and
        $harnessText -match "Properties\['matcher'\]" -and
        $harnessText -match "Properties\['timeoutSec'\]" -and
        $harnessText -match "Properties\['statusMessage'\]" -and
        $harnessText -match '\^sha256:\[0-9a-f\]\{64\}\$') `
        'Codex trust matrix pins transition/current clients and validates exact managed app-server command/shape/trust evidence'
    Assert-True ($harnessText -notmatch '(?i)dangerously-bypass-hook-trust|bypass-hook-trust') `
        'Codex certification never bypasses hook trust'
    $doctorContract = [regex]::Match($harnessText, '(?s)function Assert-DoctorWindowsHookRegistration\b.*?\n\}').Value
    $doctorSetupContract = [regex]::Match($harnessText, '(?s)function Assert-DoctorHookRegistration\b.*?\n\}').Value
    $ampScopedTokenContract = [regex]::Match(
        $harnessText,
        '(?s)function Assert-AmpScopedTokenPluginContract\b.*?(?=\r?\nfunction )'
    ).Value
    $wizardHookContract = [regex]::Match(
        $nativeHarnessText,
        '(?s)function Assert-WizardHookRegistration\b.*?(?=\r?\nfunction )'
    ).Value
    foreach ($marker in @(
        'amp.on("session.start"',
        'amp.on("agent.start"',
        'amp.on("tool.call"',
        'amp.on("tool.result"',
        'amp.on("agent.end"',
        'ctx.ui.confirm',
        'amp.activeThread.current',
        'isPluginUINotAvailableError',
        'action: "reject-and-continue"'
    )) {
        Assert-True ($doctorSetupContract.Contains($marker) -and
            $wizardHookContract.Contains($marker)) `
            "Windows setup and wizard contracts require the Amp plugin marker: $marker"
    }
    Assert-True ($doctorSetupContract -match '\$expectedAmpFailMode\s*=\s*if\s*\(\$script:LastSetupMode\s*-eq\s*''action''\)\s*\{\s*''closed''\s*\}\s*else\s*\{\s*''open''\s*\}' -and
        $doctorSetupContract -match 'const DC_FAIL_MODE: string = .*expectedAmpFailMode') `
        'Amp setup validator binds the generated plugin fail mode to the requested setup posture'
    Assert-True ($doctorSetupContract -match "\`$Connector -eq 'devin'" -and
        $doctorSetupContract -match 'Get-DevinWindowsHookCommand \$devinCommand ''setup-created Devin PreToolUse''') `
        'Devin setup validation decodes and verifies its POSIX-quoted EncodedCommand launcher'
    foreach ($marker in @(
        'const DC_TOKEN_FILE = "',
        '.hook-amp.token',
        'const DC_TOKEN_PATTERN = /^[0-9a-f]{64}$/',
        'const DC_MAX_TOKEN_FILE_BYTES = 4096',
        'runtime.file(DC_TOKEN_FILE).slice(0, DC_MAX_TOKEN_FILE_BYTES + 1).text()',
        'if (!DC_TOKEN_PATTERN.test(token))',
        'headers.Authorization = `Bearer ${token}`',
        'ToBase64String',
        'const DC_API_TOKEN =',
        'ConvertFrom-Json',
        'GetFullPath',
        'OrdinalIgnoreCase'
    )) {
        Assert-True ($ampScopedTokenContract.Contains($marker) -and
            $wizardHookContract.Contains($marker)) `
            "Windows setup and wizard contracts validate the Amp scoped-token boundary: $marker"
    }
    Assert-True ($wizardHookContract.Contains(
        '$tokenPath = Join-Path $hookDir ''.hook-amp.token'''
    ) -and $wizardHookContract -notmatch '\$env:DEFENSECLAW_HOME') `
        'wizard Amp scoped-token validation derives its sidecar from the selected data root'
    Assert-True ($doctorSetupContract.Contains('Assert-AmpScopedTokenPluginContract') -and
        $doctorContract.Contains('Assert-AmpScopedTokenPluginContract')) `
        'both Windows doctor contracts invoke the Amp scoped-token boundary validator'
    foreach ($marker in @(
        'const DC_FAIL_MODE: string = "closed"',
        'const DC_TIMEOUT_MS = 10000',
        'new AbortController()'
    )) {
        Assert-True ($doctorContract.Contains($marker) -and
            $wizardHookValidation.Contains($marker)) `
            "Windows contracts require the Amp fail-safe marker: $marker"
    }
    $ampNativeHookPattern = 'defenseclaw-hook(?:\.exe|\.cmd)'
    $ampCompatibilityPattern = '\bwsl\b|\bbash\b|\bchmod\b'
    $hasAmpShellRejectionContract = {
        param([string]$SetupContract, [string]$WizardContract)
        return $SetupContract.Contains($ampNativeHookPattern) -and
            $SetupContract.Contains($ampCompatibilityPattern) -and
            $WizardContract.Contains($ampNativeHookPattern) -and
            $WizardContract.Contains($ampCompatibilityPattern)
    }
    Assert-True (& $hasAmpShellRejectionContract $doctorSetupContract $wizardHookValidation) `
        'Amp Windows setup and wizard contracts reject shell-hook compatibility layers'
    Assert-True (-not (& $hasAmpShellRejectionContract `
                $doctorSetupContract.Replace($ampNativeHookPattern, '') `
                $wizardHookValidation)) `
        'Amp shell rejection predicate rejects a setup validator missing the native-hook pattern'
    Assert-True (-not (& $hasAmpShellRejectionContract `
                $doctorSetupContract.Replace($ampCompatibilityPattern, '') `
                $wizardHookValidation)) `
        'Amp shell rejection predicate rejects a setup validator missing the compatibility pattern'
    Assert-True (-not (& $hasAmpShellRejectionContract `
                $doctorSetupContract `
                $wizardHookValidation.Replace($ampNativeHookPattern, ''))) `
        'Amp shell rejection predicate rejects a wizard validator missing the native-hook pattern'
    Assert-True (-not (& $hasAmpShellRejectionContract `
                $doctorSetupContract `
                $wizardHookValidation.Replace($ampCompatibilityPattern, ''))) `
        'Amp shell rejection predicate rejects a wizard validator missing the compatibility pattern'
    $ampACLContract = [regex]::Match(
        $harnessText,
        '(?s)function Assert-AmpPluginPrivateACL\b.*?(?=\r?\nfunction )'
    ).Value
    $ampSelfHealContract = [regex]::Match(
        $harnessText,
        '(?s)function Assert-AmpPluginSelfHeal\b.*?(?=\r?\nfunction )'
    ).Value
    Assert-True ($ampACLContract -match 'ReparsePoint' -and
        $ampACLContract -match 'WindowsIdentity\]::GetCurrent' -and
        $ampACLContract -match 'AreAccessRulesProtected' -and
        $ampACLContract -match "systemSID = 'S-1-5-18'" -and
        $ampACLContract -match 'grants access to an untrusted Windows principal' -and
        $ampACLContract -match 'FileSystemRights\]::FullControl' -and
        $ampACLContract -match 'connector_backups\\amp\\config\.json') `
        'Amp Windows contract requires a protected owner-and-SYSTEM-only, non-reparse plugin and durable backup authority'
    Assert-True ($ampSelfHealContract -match 'Remove-Item -LiteralPath \$PluginPath' -and
        $ampSelfHealContract -match '\$attempt -lt 80' -and
        $ampSelfHealContract -match 'Start-Sleep -Milliseconds 250' -and
        $ampSelfHealContract -match 'ToBase64String\(\$ExpectedBytes\)' -and
        $ampSelfHealContract -match 'Assert-AmpPluginPrivateACL \$PluginPath') `
        'Amp Windows contract deletes and verifies byte-exact, ACL-safe self-healing within 20 seconds'
    Assert-True ($doctorSetupContract -match "expectedStatus = if \(\`$Connector -eq 'hermes'\) \{ 'fail' \}" -and
        $doctorSetupContract -match 'hook_entries=23' -and
        $doctorSetupContract -match 'allowlist_entries=23' -and
        $doctorSetupContract -match 'must be reloaded or restarted' -and
        $doctorSetupContract -match 'live=false') `
        'Hermes setup Doctor contract preserves truthful failed readiness with direct-native pending-reload evidence'
    $hermesSetupContract = [regex]::Match(
        $harnessText,
        '(?s)function Assert-HermesWindowsHookConfig\b.*?(?=\nfunction Assert-DoctorHookRegistration\b)'
    ).Value
    Assert-True ($hermesSetupContract -match 'if "hooks_auto_accept" in document:' -and
        $hermesSetupContract -match 'Setup introduced operator-owned hooks_auto_accept' -and
        $hermesSetupContract -match 'shell-hooks-allowlist\.json' -and
        $hermesSetupContract -match 'defenseclaw_managed' -and
        $hermesSetupContract -match 'allowlist_entries' -and
        $hermesSetupContract -notmatch 'hooks_auto_accept is not true') `
        'Hermes packaged contract preserves operator consent and requires exactly 23 scoped owned approvals'
    Assert-True ($doctorContract.Contains("Assert-CursorSynchronousWindowsHookCommand `$config (`$script:LastSetupMode -eq 'action') 'Cursor setup'") -and
        $doctorContract.Contains("`$expectedMode = if (`$script:LastSetupMode -eq 'action') { 'action' } else { 'observe' }") -and
        $doctorContract.Contains("`$expectedFailClosed = if (`$expectedMode -eq 'action') { 'true' } else { 'false' }") -and
        $doctorContract.Contains("`$expectedFailure = if (`$expectedMode -eq 'action') { 'fail-closed' } else { 'fail-open' }") -and
        $doctorContract.Contains("`$check.detail -notmatch 'higher-priority conflict detection=unavailable \(none inferred\)'") -and
        $doctorContract.Contains("`$check.detail -notmatch 'human-approval=unsupported'")) `
        'Cursor contract requires mode-matched action/fail-closed or observe/fail-open posture without unsupported claims'
    Assert-True ($doctorContract -match "'cursor' \{ 'configured file has no DefenseClaw Cursor command entries' \}") `
        'Cursor tamper contract expects exact zero-managed-entry rejection after lock-bound ownership filtering'
    Assert-True ([IO.File]::ReadAllText($openCodeAssertion) -match 'await hooks\.config') `
        'OpenCode contract runs the official config hook before tool hooks'
    Assert-True ($openCodeAssertionText -match '\["allow", "block", "lifecycle", "load"\]' -and
        $openCodeAssertionText -match '(?s)await hooks\.config.*?if \(expected === "load"\).*?else if \(expected === "lifecycle"\)') `
        'OpenCode setup load probe stops after the authenticated config hook'
    $synchronousCodexHookContract = [regex]::Match(
        $harnessText,
        '(?s)function Assert-CodexSynchronousWindowsHookCommand\b.*?\n\}'
    ).Value
    Assert-True ($doctorContract -match 'Assert-CodexSynchronousWindowsHookCommand' -and
        $doctorSetupContract -match 'Assert-CodexSynchronousWindowsHookCommand' -and
        $synchronousCodexHookContract -match 'Start-Process' -and
        $synchronousCodexHookContract -match '-NoNewWindow\\s\+\-Wait\\s\+\-PassThru' -and
        $synchronousCodexHookContract -match '\$hookProcess\\\.ExitCode' -and
        $synchronousCodexHookContract -match '\$LASTEXITCODE') `
        'Codex Doctor contracts require the synchronous native launcher and reject stale LASTEXITCODE handling'
    $doctorRegistration = $doctorContract.IndexOf("Write-Result 'doctor:windows-hook-registration'", [StringComparison]::Ordinal)
    $doctorAmpSelfHeal = $doctorContract.IndexOf('Assert-AmpPluginSelfHeal $configPath $originalConfig', [StringComparison]::Ordinal)
    $doctorStop = $doctorContract.IndexOf("Invoke-Tool 'defenseclaw-gateway' @('stop')", [StringComparison]::Ordinal)
    $doctorTamper = $doctorContract.IndexOf('$tamperedConfig =', [StringComparison]::Ordinal)
    $doctorRecovery = $doctorContract.IndexOf("Write-Result 'doctor:windows-hook-recovery'", [StringComparison]::Ordinal)
    $doctorStart = $doctorContract.IndexOf("Invoke-Tool 'defenseclaw-gateway' @('start')", [StringComparison]::Ordinal)
    $doctorWait = $doctorContract.LastIndexOf('Wait-Gateway', [StringComparison]::Ordinal)
    Assert-True ($doctorRegistration -ge 0 -and $doctorAmpSelfHeal -gt $doctorRegistration -and
        $doctorStop -gt $doctorAmpSelfHeal -and
        $doctorTamper -gt $doctorStop -and $doctorStart -gt $doctorTamper -and
        $doctorWait -gt $doctorStart -and $doctorRecovery -gt $doctorWait) `
        'Doctor tamper validation pauses self-heal, restores the gateway, then validates live recovery'
    Assert-True ($doctorContract -match "(?s)DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT = '1'.*?defenseclaw-gateway' @\('start'\).*?\}\s*finally\s*\{.*?Remove-Item Env:DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT.*?\}.*?Wait-Gateway.*?Write-Result 'doctor:windows-hook-recovery'") `
        'unversioned fixture override is scoped to the pre-recovery gateway restart'
    $openCodeDoctorContract = [regex]::Match($harnessText, '(?s)function Assert-OpenCodePluginContract\b.*?\n\}').Value
    Assert-True ($openCodeDoctorContract -match "recoveredChecks\[0\]\.status -ne 'warn'" -and
        $openCodeDoctorContract -match 'managed plugin digest current' -and
        $openCodeDoctorContract -match '\$expectedStoppedRuntime' -and
        $openCodeDoctorContract -match 'sidecar /health is unavailable' -and
        $openCodeDoctorContract -match 'managed gateway PID file is missing') `
        'OpenCode recovery distinguishes a restored digest from runtime readiness while the isolated gateway is stopped'
    Assert-True ($harnessText -match 'obsolete shell-hook guidance for native Windows') 'Doctor connector contract rejects obsolete shell guidance'
    $gatewayWait = [regex]::Match($harnessText, '(?s)function Wait-Gateway\b.*?\n\}').Value
    $gatewayHookReadiness = [regex]::Match(
        $harnessText,
        '(?s)function Wait-GatewayHookReady\b.*?\n\}'
    ).Value
    Assert-True ($gatewayWait -match "Invoke-Tool 'defenseclaw-gateway' @\('status'\)" -and
        $gatewayWait -match '\$probeTimeout = \[Math\]::Min\(15, \$remaining\)' -and
        $gatewayWait -match 'if \(\$Connector -ne ''amp''\)' -and
        $gatewayWait -match 'Wait-GatewayHookReady -Timeout \$remaining') `
        'gateway readiness requires bounded status and native hook API probes'
    $readinessTool = $gatewayHookReadiness.IndexOf(
        '-ArgumentList (Get-NativeHookArguments $toolEvent)',
        [StringComparison]::Ordinal
    )
    $readinessToolDecision = $gatewayHookReadiness.IndexOf(
        '$beforeTool $decisionDeadline $probeID $toolEvent',
        [StringComparison]::Ordinal
    )
    Assert-True ($gatewayHookReadiness -match 'Get-StableHookRuntimeExecutable' -and
        $gatewayHookReadiness -match "'copilot' \{ 'preToolUse' \}" -and
        $gatewayHookReadiness -match "'cursor' \{ 'preToolUse' \}" -and
        $gatewayHookReadiness -match 'Invoke-OpenCodePluginProbe allow' -and
        $readinessTool -ge 0 -and
        $readinessToolDecision -gt $readinessTool) `
        'gateway restart readiness exercises each connector-specific native pre-tool path'
    $nativeProcessContract = [regex]::Match(
        $harnessText,
        '(?s)function Invoke-NativeProcess\b.*?(?=\r?\nfunction Read-EventJsonLines)'
    ).Value
    $setupContract = [regex]::Match(
        $harnessText,
        '(?s)function Invoke-Setup\b.*?(?=\r?\nfunction Get-ConnectorHookLabel)'
    ).Value
    Assert-True ($nativeProcessContract -match '\[scriptblock\]\$WhileRunning' -and
        $nativeProcessContract -match '(?s)& \$WhileRunning \$process.*?\$process\.Kill\(\$true\)' -and
        $setupContract -match 'Invoke-OpenCodePluginProbe load' -and
        $setupContract -match 'setup-readiness-\$attempt' -and
        $setupContract -match '-TimeoutSeconds 3' -and
        $setupContract -match '-not \$SetupProcess\.HasExited' -and
        $setupContract -match '-WhileRunning \$setupRuntimeProbe') `
        'OpenCode setup loads the managed plugin while convergence is waiting and cleans up a failed setup child'
    Assert-True ($gatewayHookReadiness -match "'--connector', 'hermes', '--event', 'pre_tool_call'" -and
        $gatewayHookReadiness -match '\$probeID ''pre_tool_call''' -and
        $gatewayHookReadiness -match 'canonical fail-open allow decision') `
        'Hermes readiness uses its official event name and forced fail-open effective posture'
    Assert-True ($gatewayHookReadiness -match '\$toolDecision\.action -cne ''allow''' -and
        $gatewayHookReadiness -match '\$toolDecision\.raw_action -cne ''allow''' -and
        $gatewayHookReadiness -match '\$toolDecision\.would_block') `
        'gateway restart readiness requires canonical non-blocking allow decisions'
    $copilotPayloadContract = [regex]::Match(
        $harnessText,
        '(?s)function ConvertTo-CopilotOfficialToolPayload\b.*?\n\}'
    ).Value
    Assert-True ($copilotPayloadContract -match 'sessionId\s*=' -and
        $copilotPayloadContract -match 'timestamp\s*=' -and
        $copilotPayloadContract -match 'cwd\s*=' -and
        $copilotPayloadContract -match 'toolName\s*=\s*''powershell''' -and
        $copilotPayloadContract -match 'toolArgs\s*=' -and
        $copilotPayloadContract -notmatch 'hook_event_name\s*=' -and
        [regex]::Matches(
            $harnessText,
            'ConvertTo-CopilotOfficialToolPayload\s+\$'
        ).Count -eq 3) `
        'Copilot readiness and policy probes preserve the exact event-free official tool body'
    $latestHookDecision = [regex]::Match(
        $harnessText,
        '(?s)function Get-LatestHookDecision\b.*?\n\}'
    ).Value
    $hookDecisionWait = [regex]::Match(
        $harnessText,
        '(?s)function Wait-HookDecisionAfter\b.*?\n\}'
    ).Value
    Assert-True ($latestHookDecision -match 'Get-JsonPropertyValue \$correlation ''session_id''' -and
        $latestHookDecision -match 'Get-JsonPropertyValue \$body ''defenseclaw\.hook\.event''' -and
        $latestHookDecision -match 'Get-JsonPropertyValue \$correlation ''tool_invocation_id''' -and
        $hookDecisionWait -match '\$script:AuditDb \$Connector \$Since \$SessionID \$HookEvent') `
        'gateway hook readiness accepts only the current probe session and event decision'
    $canonicalEventReader = [regex]::Match(
        $harnessText,
        '(?s)function New-CanonicalAuditProjectionSnapshot\b.*?(?=\r?\nfunction Get-EventLines)'
    ).Value
    $eventLineRouter = [regex]::Match(
        $harnessText,
        '(?s)function Get-EventLines\b.*?(?=\r?\nfunction )'
    ).Value
    Assert-True ($canonicalEventReader -match 'project-audit-events\.py' -and
        $canonicalEventReader -match '\.canonical-event-projection' -and
        $canonicalEventReader -match '\[guid\]::NewGuid' -and
        $eventLineRouter -match 'New-CanonicalAuditProjectionSnapshot' -and
        $eventLineRouter -match 'Remove-Item -LiteralPath \$snapshot' -and
        $harnessText -notmatch '\$script:GatewayJsonl') `
        'Windows live readiness exclusively reads a private transient canonical SQLite projection'
    Assert-True ($auditProjectorText -match 'mode=ro' -and
        $auditProjectorText -match 'PRAGMA query_only=ON' -and
        $auditProjectorText -match 'ORDER BY rowid' -and
        $auditProjectorText -match 'record_schema_version != 1' -and
        $auditProjectorText -match 'os\.replace\(temporary, output\)' -and
        $auditProjectorText -match 'output must differ from the audit database') `
        'canonical SQLite projection is read-only, ordered, schema-bound, and atomically published'
    Assert-True ($openCodeAssertionText.Contains('const probeID = basename(scratchPath, ".mjs");') -and
        [regex]::Matches(
            $openCodeAssertionText,
            'defenseclaw-windows-contract-\$\{probeID\}'
        ).Count -ge 4 -and
        $harnessText.Contains('$probeID = [IO.Path]::GetFileNameWithoutExtension($scratch)') -and
        $harnessText.Contains('$probeSessionID = "defenseclaw-windows-contract-$probeID"') -and
        $harnessText.Contains('$beforeTool $decisionDeadline $probe.SessionID ''tool.execute.before''')) `
        'OpenCode contract probes use and await a fresh correlation identity for every helper invocation'
    Assert-True ($harnessText -match '(?s)\$blockIdentitySuffix = if \(\$Connector -eq ''amp''\).*?Invoke-Hook.*?-IdentitySuffix \$blockIdentitySuffix') `
        'Amp action block uses a fresh fixture identity so strict hook-decision correlation remains required'
    $isolatedCleanup = [regex]::Match($harnessText, '(?s)function Stop-IsolatedProcessTree\b.*?\n\}').Value
    Assert-True ($isolatedCleanup -match 'HashSet\[int\]' -and
        $isolatedCleanup -match '\$ancestor\[0\]\.ParentProcessId' -and
        $isolatedCleanup -match '-not \$ancestorIds\.Contains\(\$processId\)') `
        'isolated process cleanup excludes the complete ancestor wrapper chain'
    Assert-True ($isolatedCleanup -match '\$matchesRoot -and' -and
        $isolatedCleanup -notmatch 'descendantIds') `
        'isolated process cleanup only terminates state-root-owned processes'
    Assert-True ($isolatedCleanup -match 'gateway\.pid' -and
        $isolatedCleanup -match 'watchdog\.pid' -and
        $isolatedCleanup -match '\$livePath, \$recordedPath, \[StringComparison\]::OrdinalIgnoreCase') `
        'isolated process cleanup strongly identifies detached product processes'
    Assert-True ($harnessText -match 'doctor:windows-hook-tamper' -and
        $harnessText -match 'cannot be resolved' -and
        $harnessText -match 'does not use the native hook runtime' -and
        $harnessText.Contains("'copilot' {") -and
        $harnessText.Contains('"registered hook target cannot be resolved with PATHEXT: $missingGatewayLauncher"') -and
        $harnessText.Contains("Invoke-Tool 'defenseclaw' @('doctor', '--json-output') @(1)")) `
        'Doctor connector contract rejects connector-specific tampered hook commands with exit 1'
    Assert-True ($doctorContract -match "(?s)'devin'\s*\{.*?registered hook uses the obsolete gateway launcher.*?registered hook target cannot be resolved with PATHEXT: \`$missingGatewayLauncher") `
        'Devin tamper validation accepts only exact fail-closed diagnoses for present or absent obsolete launchers'
    Assert-True ($doctorContract.Contains('"setup $repairSubcommand --mode $($script:CopilotConfiguredMode) --yes --restart"') -and
        $doctorContract.Contains('[regex]::Escape($repairGuidance)')) `
        'Copilot Doctor tamper validation requires the exact configured-mode native Setup repair command'
    Assert-True ($harnessText -match 'WriteAllBytes\(\$configPath, \$originalConfig\)' -and $harnessText -match 'doctor:windows-hook-recovery') 'Doctor connector contract restores the registration byte-for-byte and validates recovery'
    Assert-True ($nativeHarnessText -match '-StateRoot \$contractProfileRoot -HomeRoot \$contractHome' -and
        $harnessText -match 'HomeRoot must be contained by StateRoot') `
        'connector contract keeps alternate agent homes inside the current-user-owned profile root'
    $contractProfileProvisioning = [regex]::Match(
        $contractFunction,
        '(?s)foreach \(\$path in @\((?<paths>.*?)\)\) \{\s*\[IO\.Directory\]::CreateDirectory\(\$path\)'
    )
    $productPrivateProvisioning = [regex]::Match(
        $contractFunction,
        '(?s)foreach \(\$path in @\(\$ampPluginDir, \$openCodePluginDir\)\) \{\s*New-ProductPrivateTestDirectory \$path'
    )
    $productPrivateDirectoryFunction = [regex]::Match(
        $nativeHarnessText,
        '(?s)function New-ProductPrivateTestDirectory\b.*?\n\}'
    ).Value
    Assert-True ($contractProfileProvisioning.Success -and
        $contractProfileProvisioning.Groups['paths'].Value -match '\$ampHome' -and
        $contractProfileProvisioning.Groups['paths'].Value -match '\$openCodeHome' -and
        $contractProfileProvisioning.Groups['paths'].Value -match '\$cursorHome' -and
        $contractProfileProvisioning.Groups['paths'].Value -notmatch '\$ampPluginDir|\$openCodePluginDir' -and
        $productPrivateProvisioning.Success) `
        'connector contract isolates Amp/OpenCode plugin leaves from general test-directory provisioning'
    Assert-True ($productPrivateDirectoryFunction -match 'Assert-NoReparseAncestors' -and
        $productPrivateDirectoryFunction -match 'not owned by the current Windows identity' -and
        $productPrivateDirectoryFunction -match 'SetAccessRuleProtection\(\$true, \$false\)' -and
        $productPrivateDirectoryFunction -match 'foreach \(\$sid in @\(\$identity\.User, \$system\)\)' -and
        $productPrivateDirectoryFunction -match 'FileSystemAclExtensions\]::Create\(\$directory, \$security\)' -and
        $productPrivateDirectoryFunction -notmatch 'S-1-5-32-544') `
        'product-private connector leaves are atomically created with only current-user/SYSTEM writers and custody/reparse checks'
    $contractInstall = $contractFunction.IndexOf(
        'Invoke-WindowsSetupStandardUserProcess $setup',
        [StringComparison]::Ordinal
    )
    $contractOwnerPin = $contractFunction.IndexOf(
        'Set-CurrentUserAsDefaultOwner',
        [StringComparison]::Ordinal
    )
    $productPrivateCreate = $contractFunction.IndexOf(
        'New-ProductPrivateTestDirectory $path',
        [StringComparison]::Ordinal
    )
    Assert-True ($contractOwnerPin -ge 0 -and
        $contractOwnerPin -lt $productPrivateCreate -and
        $productPrivateCreate -lt $contractInstall) `
        'connector contract pins disposable hosted ownership before product-private leaves and native Setup'
    Assert-True ($nativeHarnessText -match 'Join-Path \$realProfile ''\.defenseclaw-ci-contract''' -and
        $nativeHarnessText -match 'Join-Path \$contractProfileRoot ''codex-home''' -and
        $nativeHarnessText -match 'Join-Path \$contractProfileRoot ''claude-home''' -and
        $nativeHarnessText -match 'Join-Path \$contractProfileRoot ''copilot-home''' -and
        $nativeHarnessText -match 'Join-Path \$contractHome ''\.config\\amp''' -and
        $nativeHarnessText -match '\$ampPluginDir = Join-Path \$ampHome ''plugins''' -and
        $nativeHarnessText -match 'Join-Path \$contractHome ''\.cursor''' -and
        $nativeHarnessText -match 'Join-Path \$contractProfileRoot ''hermes-home''' -and
        $nativeHarnessText -match 'Join-Path \$contractProfileRoot ''opencode-home''' -and
        $nativeHarnessText -match '\$openCodePluginDir = Join-Path \$openCodeHome ''plugins''' -and
        $nativeHarnessText -match '(?s)Assert-WindowsNativePathsDisjoint @\(\s*\$contractHome, \$codexHome, \$claudeHome, \$copilotHome, \$hermesHome,\s*\$openCodeHome, \$geminiCLIHome\s*\)' -and
        $nativeHarnessText -notmatch '\$officialWindsurfConfig' -and
        $contractInstall -ge 0) `
        'connector contract keeps active connector homes and legacy Gemini cleanup custody disjoint without a Windsurf target'
    foreach ($homeAssignment in @(
        '$env:CODEX_HOME = $codexHome',
        '$env:CLAUDE_CONFIG_DIR = $claudeHome',
        '$env:COPILOT_HOME = $copilotHome',
        '$env:DEFENSECLAW_CURSOR_CONFIG_HOME = $cursorHome',
        '$env:HERMES_HOME = $hermesHome',
        '$env:OPENCODE_CONFIG_DIR = $openCodeHome'
    )) {
        $homeCapture = $contractFunction.IndexOf($homeAssignment, [StringComparison]::Ordinal)
        Assert-True ($homeCapture -ge 0 -and $homeCapture -lt $contractInstall) `
            "connector contract captures recorded home before native Setup: $homeAssignment"
    }
    Assert-True ($contractFunction -match 'fresh native Setup install state retained deprecated connector custody' -and
        $contractFunction -match "'gemini_cli_home', 'gemini_config_dir'" -and
        $contractFunction -match "'windsurf_user_home', 'windsurf_hooks_path'" -and
        $contractFunction -notmatch '\$contractInstallState\.(gemini_cli_home|gemini_config_dir|windsurf_user_home|windsurf_hooks_path)') `
        'connector contract rejects fresh retired Gemini/Windsurf custody without dereferencing absent state properties'
    $contractCleanupTry = $contractFunction.IndexOf('    try {', [StringComparison]::Ordinal)
    $contractProfileCreate = $contractFunction.IndexOf(
        '[IO.Directory]::CreateDirectory($path)',
        [StringComparison]::Ordinal
    )
    $contractProfileCleanup = $contractFunction.LastIndexOf(
        'Remove-SafeDisposableTree $contractProfileRoot',
        [StringComparison]::Ordinal
    )
    Assert-True ($contractCleanupTry -ge 0 -and
        $contractCleanupTry -lt $contractProfileCreate -and
        $contractProfileCleanup -gt $contractProfileCreate) `
        'connector contract profile creation is covered by its cleanup finally block'
    Assert-True ($nativeHarnessText -match '\$originalEnvironment = @\{\}' -and
        $nativeHarnessText -match 'GetEnvironmentVariables\(''Process''\)' -and
        $nativeHarnessText -match 'SetEnvironmentVariable\(\s*\[string\]\$name,\s*\[string\]\$originalEnvironment\[\$name\],\s*''Process''') `
        'connector contract restores the complete process environment in finally'
    Assert-True ($nativeHarnessText -match 'connector contract wrote to the default agent home' -and
        $nativeHarnessText -match 'connector contract wrote to the unrelated agent home' -and
        $nativeHarnessText -match 'function Assert-CursorCompatibilitySkillHomes\b' -and
        $nativeHarnessText -match 'Cursor contract wrote to a default compatibility agent config' -and
        $harnessText -match 'function Resolve-EffectiveConnectorHome\b' -and
        $harnessText -match '\$fileName = switch \(\$ConnectorName\)' -and
        $harnessText -match '''codex'' \{ ''managed_config\.toml'' \}' -and
        $harnessText -match '''claudecode'' \{ ''settings\.json'' \}' -and
        $harnessText -match '''hermes'' \{ ''config\.yaml'' \}' -and
        $harnessText -match '''opencode'' \{ ''plugins\\defenseclaw\.js'' \}' -and
        [regex]::Matches($harnessText, 'Get-EffectiveConnectorConfigPath \$Connector').Count -eq 3 -and
        $harnessText -notmatch 'Join-Path \$env:USERPROFILE ''\.codex\\config\.toml''' -and
        $harnessText -notmatch 'Join-Path \$env:USERPROFILE ''\.claude\\settings\.json''') `
        'contract setup, Doctor, and teardown share effective homes and never fall back behind explicit overrides'
    $releaseCertificationFunction = [regex]::Match(
        $nativeHarnessText,
        '(?s)function Invoke-WindowsReleaseCertification\b.*?(?=\r?\nfunction )'
    ).Value
    $releaseCleanUninstallFunction = [regex]::Match(
        $nativeHarnessText,
        '(?s)function Assert-WindowsReleaseCleanUninstall\b.*?(?=\r?\nfunction )'
    ).Value
    $hasAmpReleaseCustodyContract = {
        param([string]$ReleaseContract, [string]$CleanUninstallContract)
        $refusal = [regex]::Match(
            $ReleaseContract,
            '(?s)\$connectorConfigs = @\(.*?\$ampPluginPath,.*?\).*?foreach \(\$path in @\(.*?\$ampOperatorPluginPath,\s*\$ampSettingsPath\s*\) \+ \$connectorConfigs\) \{.*?release certification refuses pre-existing product or connector state: \$path'
        )
        $fixtureWrite = $ReleaseContract.IndexOf(
            '[IO.File]::WriteAllBytes($ampOperatorPluginPath, $unrelatedAmpPlugin)',
            [StringComparison]::Ordinal
        )
        $settingsWrite = $ReleaseContract.IndexOf(
            '[IO.File]::WriteAllBytes($ampSettingsPath, $unrelatedAmpSettings)',
            [StringComparison]::Ordinal
        )
        if (-not $refusal.Success -or $fixtureWrite -lt 0 -or $settingsWrite -lt 0 -or
            $refusal.Index -gt $fixtureWrite -or $refusal.Index -gt $settingsWrite) {
            return $false
        }
        foreach ($phasePattern in @(
            '(?s)release-reconfigure-amp\.log.*?Assert-WindowsReleaseAmpPlugin \$ampPluginPath ''Amp reconfiguration''.*?Assert-WindowsReleasePreservedFile\s+`?\s*\$ampOperatorPluginPath \$unrelatedAmpPlugin ''Amp plugin''.*?Assert-WindowsReleasePreservedFile\s+`?\s*\$ampSettingsPath \$unrelatedAmpSettings ''Amp settings''',
            '(?s)release-setup-repair\.log.*?Assert-WindowsReleaseAmpPlugin \$ampPluginPath ''exact-installer repair''.*?Assert-WindowsReleasePreservedFile\s+`?\s*\$ampOperatorPluginPath \$unrelatedAmpPlugin ''Amp plugin''.*?Assert-WindowsReleasePreservedFile\s+`?\s*\$ampSettingsPath \$unrelatedAmpSettings ''Amp settings''',
            '(?s)release-setup-upgrade\.log.*?Assert-WindowsReleaseAmpPlugin \$ampPluginPath ''exact-installer upgrade''.*?Assert-WindowsReleasePreservedFile\s+`?\s*\$ampOperatorPluginPath \$unrelatedAmpPlugin ''Amp plugin''.*?Assert-WindowsReleasePreservedFile\s+`?\s*\$ampSettingsPath \$unrelatedAmpSettings ''Amp settings'''
        )) {
            if ($ReleaseContract -notmatch $phasePattern) { return $false }
        }
        return $ReleaseContract -match
                '(?s)release-setup-uninstall\.log.*?Assert-WindowsReleaseCleanUninstall.*?\$ampOperatorPluginPath \$unrelatedAmpPlugin\s+`?\s*\$ampSettingsPath \$unrelatedAmpSettings' -and
            $CleanUninstallContract -match 'Assert-NoDefenseClawRegistration \$ConnectorConfigs' -and
            $CleanUninstallContract -match
                '(?s)Assert-WindowsReleasePreservedFile\s+`?\s*\$PreservedAmpPluginPath \$ExpectedAmpPlugin ''Amp plugin''.*?Assert-WindowsReleasePreservedFile\s+`?\s*\$PreservedAmpSettingsPath \$ExpectedAmpSettings ''Amp settings'''
    }
    Assert-True (& $hasAmpReleaseCustodyContract `
            $releaseCertificationFunction $releaseCleanUninstallFunction) `
        'release Amp lifecycle refuses a pre-existing managed target and preserves unrelated plugin/settings bytes through reconfigure, repair, upgrade, and uninstall'
    Assert-True (-not (& $hasAmpReleaseCustodyContract `
                $releaseCertificationFunction.Replace('$ampPluginPath,', '$unownedAmpPluginPath,') `
                $releaseCleanUninstallFunction)) `
        'Amp release custody predicate rejects a lifecycle that no longer refuses the managed target'
    Assert-True (-not (& $hasAmpReleaseCustodyContract `
                $releaseCertificationFunction.Replace(
                    '$ampOperatorPluginPath $unrelatedAmpPlugin ''Amp plugin''',
                    '$ampOperatorPluginPath $unrelatedAmpPlugin ''unchecked plugin'''
                ) `
                $releaseCleanUninstallFunction)) `
        'Amp release custody predicate rejects missing unrelated-plugin preservation checks'
    Assert-True ($harnessText -match 'Assert-DoctorHookRegistration' -and $harnessText -match 'doctor-hooks pass') 'contract validates setup-created hooks with Doctor'
    Assert-True ($nativeHarnessText -match '\.codex\\managed_config\.toml' -and
        $nativeHarnessText -match 'unrelated Codex managed config byte-for-byte') `
        'release certification inventories and exactly preserves unrelated Codex managed config'
    $protectedCopilotClient = [regex]::Match(
        $harnessText,
        '(?s)function Assert-ProtectedCopilotClient\b.*?(?=\nfunction Get-ProtectedCopilotCleanupManifestPath\b)'
    ).Value
    Assert-True ($protectedCopilotClient -match "CopilotOfficialVersion = '1\.0\.77'" -or
        ($harnessText -match "CopilotOfficialVersion = '1\.0\.77'" -and
         $protectedCopilotClient -match 'CopilotOfficialPackageIntegrity' -and
         $protectedCopilotClient -match 'CopilotOfficialPlatformIntegrity')) `
        'protected Copilot client is pinned to exact official npm package and Windows platform integrities'
    Assert-True ($protectedCopilotClient -match 'package-lock\.json' -and
        $protectedCopilotClient -match 'npm-loader\.js' -and
        $protectedCopilotClient -match 'copilot-win32-x64' -and
        $protectedCopilotClient -match 'Get-AuthenticodeSignature' -and
        $protectedCopilotClient -match 'CopilotOfficialSignerSubject' -and
        $protectedCopilotClient -match 'CopilotOfficialSignerThumbprint') `
        'protected Copilot client proves canonical shim/loader/package-lock and GitHub-signed native binary custody'
    $protectedCopilotBootstrap = [regex]::Match(
        $harnessText,
        '(?s)function Initialize-ProtectedCopilotPackage\b.*?(?=\nfunction Assert-ProtectedCopilotConfiguredPosture\b)'
    ).Value
    $protectedCopilotInstallState = [regex]::Match(
        $harnessText,
        '(?s)function Assert-ProtectedCopilotInstallState\b.*?(?=\nfunction Set-ProtectedCopilotInstalledPath\b)'
    ).Value
    $protectedCopilotConfiguredPosture = [regex]::Match(
        $harnessText,
        '(?s)function Assert-ProtectedCopilotConfiguredPosture\b.*?(?=\nfunction Repair-ProtectedCopilotPackage\b)'
    ).Value
    Assert-True ($protectedCopilotBootstrap -match
        "(?s)Save-ProtectedCopilotOriginalHook.*?Write-ProtectedCopilotCleanupManifest.*?Write-Result 'copilot:provenance' pass.*?Invoke-ProtectedCopilotSetup @\(.*?'CONNECTOR=copilot'.*?'MODE=action'.*?'STARTGATEWAY=0'.*?\) @\(0\) 'fresh-copilot-install'.*?Read-ProtectedCopilotInstallState.*?Assert-ProtectedCopilotInstallState .*? 'copilot' 'fresh protected Copilot package state'.*?Assert-CopilotSynchronousWindowsHookConfig.*?Set-ProtectedCopilotCleanupPhase 'configured'.*?Write-Result 'package-setup:copilot' pass.*?Write-Result 'copilot:hitl' skip" -and
        $protectedCopilotInstallState -match
        "(?s)\[int\]\`$State\.schema_version -lt 1.*?\[string\]\`$State\.install_kind -cne 'native-windows-exe'.*?\[string\]\`$State\.install_scope -cne 'user'.*?\[string\]\`$State\.distribution_flavor -cne 'oss'.*?\[string\]\`$State\.source_commit -cne \`$ExpectedPackageSourceCommit.*?\[string\]\`$State\.connector -cne \`$ExpectedConnector.*?\[string\]\`$State\.mode -cne 'action'" -and
        $protectedCopilotInstallState -match 'install_root' -and
        $protectedCopilotInstallState -match 'command_dir' -and
        $protectedCopilotInstallState -match 'data_root' -and
        $protectedCopilotInstallState -match 'runtime' -and
        $protectedCopilotInstallState -match 'maintenance_path' -and
        $protectedCopilotInstallState -match 'copilot_home' -and
        $protectedCopilotConfiguredPosture -match
        "(?s)\`$rows\.Count -ne 1.*?\`$copilot\.Count -ne 1.*?source -cne 'manual'.*?mode -cne 'action'.*?enabled.*?Assert-ProtectedCopilotInstallState .*? 'copilot'.*?Assert-ProtectedCopilotFingerprintEqual" -and
        $protectedCopilotBootstrap -notmatch
        'CONNECTOR=none|Assert-ProtectedCopilotPublicGate|public-copilot-rejection|not_certified|preview|native-setup-copilot') `
        'protected Copilot package lane proves ordinary supported action Setup after custody, exact state and hook posture, no retired rejection/preview/bootstrap-bypass path, and leaves HITL unclaimed'
    Assert-True ($protectedCopilotBootstrap -match "Get-Process -Name 'defenseclaw-gateway', 'defenseclaw-watchdog'" -and
        $protectedCopilotBootstrap -match 'requires an absent DefenseClaw product baseline' -and
        $protectedCopilotBootstrap -match 'Save-ProtectedCopilotOriginalHook' -and
        $protectedCopilotBootstrap -match 'Write-ProtectedCopilotCleanupManifest') `
        'protected Copilot mutation is preceded by clean product/process and durable authenticated hook-custody gates'
    $protectedCopilotMaintenance = [regex]::Match(
        $harnessText,
        '(?s)function Repair-ProtectedCopilotPackage\b.*?(?=\nfunction Invoke-ProtectedCopilotCleanup\b)'
    ).Value
    Assert-True ($protectedCopilotMaintenance -match "@\('/repair', '/quiet', '/norestart'\)" -and
        $protectedCopilotMaintenance -match "@\('/upgrade', '/quiet', '/norestart'\)" -and
        [regex]::Matches($protectedCopilotMaintenance, 'Assert-ProtectedCopilotConfiguredPosture').Count -eq 4 -and
        [regex]::Matches($protectedCopilotMaintenance, '-ExpectedHookFingerprint \$fingerprint').Count -eq 4 -and
        $protectedCopilotMaintenance -match 'no-override repair preserved exact source, Copilot home, action roster, and 14-event hook bytes' -and
        $protectedCopilotMaintenance -match 'same-package no-override upgrade preserved exact source, Copilot home, action roster, and hook bytes' -and
        $protectedCopilotMaintenance -match 'copilot:restart-persistence') `
        'protected Copilot lane proves idempotent no-override repair and upgrade plus status, restart, and exact hook persistence'
    $protectedCopilotCleanup = [regex]::Match(
        $harnessText,
        '(?s)function Invoke-ProtectedCopilotCleanup\b.*?(?=\nfunction Install-Agent\b)'
    ).Value
    Assert-True ($protectedCopilotCleanup -match 'Assert-ProtectedCopilotCleanupManifest' -and
        $protectedCopilotCleanup -match "'connector', 'teardown', '--connector', 'copilot'" -and
        $protectedCopilotCleanup -match "'connector', 'verify', '--connector', 'copilot'" -and
        $protectedCopilotCleanup -match 'Assert-ProtectedCopilotOriginalHookRestored' -and
        $protectedCopilotCleanup -match 'Remove-DisposableTreeSafely') `
        'protected Copilot cleanup authenticates provenance, tears down and verifies the connector, restores the hook, and removes only exact task roots'
    $copilotLiveJob = [regex]::Match(
        $liveWorkflowText,
        '(?s)  windows-copilot-live:.*?(?=\n  windows-antigravity-live:)'
    ).Value
    Assert-True ($copilotLiveJob -match 'runs-on: \[self-hosted, Windows, X64, copilot-authenticated\]' -and
        $copilotLiveJob -match 'DC_WINDOWS_STATE: D:\\DefenseClaw-PR655-Copilot-Delta-State' -and
        $copilotLiveJob -match 'DC_COPILOT_PACKAGE_ROOT: D:\\DefenseClaw-PR655-Copilot-Delta-Package' -and
        $copilotLiveJob -match 'run\.head_sha -cne \$env:EXPECTED_HEAD_SHA' -and
        $copilotLiveJob -match "name -ceq 'windows-native-package'" -and
        $copilotLiveJob -match 'digest -cnotmatch') `
        'Copilot workflow job is dedicated, D:-custodied, and accepts only the successful exact-head canonical package artifact'
    Assert-True ($copilotLiveJob -match '"@github/copilot@\$env:DC_COPILOT_VERSION"' -and
        $copilotLiveJob -match 'DC_COPILOT_VERSION: "1\.0\.77"' -and
        $copilotLiveJob -match '--ignore-scripts' -and
        $copilotLiveJob -match '--registry https://registry\.npmjs\.org/' -and
        $copilotLiveJob -match '-ProtectedCopilotRunner' -and
        $copilotLiveJob -match '-ExpectedPackageSourceCommit' -and
        $copilotLiveJob -match '-ExpectedHarnessSourceCommit' -and
        $copilotLiveJob -match '-ExpectedPackageArtifactDigest' -and
        $copilotLiveJob -match '-ExpectedWorkflowRepository' -and
        $copilotLiveJob -match '-ExpectedAgentVersion' -and
        [regex]::Matches($copilotLiveJob, '-Operation cleanup').Count -eq 1) `
        'Copilot workflow installs the exact task-local client and binds run/package/source/artifact/workflow/client identities into one cleanup-protected invocation'
    Assert-True ($liveWorkflowText -match 'connector: \[codex, claudecode, amp, cursor, opencode\]' -and
        $liveWorkflowText -match 'needs: \[contract-matrix, live-matrix, windows-live, windows-copilot-live,') `
        'Copilot is excluded from the generic Windows matrix and included only through the protected report dependency'
    $workflowText = $nativeWorkflowText + "`n" + $liveWorkflowText
    Assert-True ([regex]::Matches($workflowText, 'failure\(\) \|\| cancelled\(\)').Count -ge 2) 'failure and cancellation diagnostics are uploaded'
    $checkoutCount = [regex]::Matches($workflowText, 'uses:\s*actions/checkout@').Count
    $nonPersistentCheckoutCount = [regex]::Matches($workflowText, 'persist-credentials:\s*false').Count
    Assert-True ($checkoutCount -eq $nonPersistentCheckoutCount) 'every checkout disables credential persistence'
    $unpinned = [regex]::Matches($workflowText, '(?m)^\s*-?\s*uses:\s*[^@\s]+@(?![0-9a-f]{40}\b)')
    $unpinnedText = @($unpinned | ForEach-Object { $_.Value }) -join ', '
    Assert-True ($unpinned.Count -eq 0) "external actions must be SHA-pinned: $unpinnedText"

    Write-Host 'Windows connector harness tests passed.'
} finally {
    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
        $_.CommandLine -and $_.CommandLine.Contains($temp)
    } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
}
