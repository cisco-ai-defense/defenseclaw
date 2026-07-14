# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$harness = Join-Path $PSScriptRoot 'run-windows.ps1'
$nativeHarness = Join-Path $root 'scripts\windows-native-ci.ps1'
$wizardHarness = Join-Path $root 'scripts\test-windows-setup-wizard.ps1'
$nativePathHelpers = Join-Path $root 'scripts\windows-native-paths.ps1'
$nativePathInitializer = Join-Path $root 'scripts\initialize-windows-native-ci-paths.ps1'
$nativeWorkflow = Join-Path $root '.github\workflows\windows-native.yml'
$liveWorkflow = Join-Path $root '.github\workflows\connector-live-e2e.yml'
$ciWorkflow = Join-Path $root '.github\workflows\ci.yml'
$installer = Join-Path $root 'scripts\install.ps1'
$mock = Join-Path $PSScriptRoot 'testdata\windows-mock.ps1'
$temp = Join-Path ([IO.Path]::GetTempPath()) ("dc-windows-harness-test-" + [guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($temp) | Out-Null

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw "assertion failed: $Message" }
}

try {
    foreach ($scriptPath in @(
        $harness,
        $nativeHarness,
        $wizardHarness,
        $nativePathHelpers,
        $nativePathInitializer,
        $installer
    )) {
        $tokens = $null; $errors = $null
        [Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$errors) | Out-Null
        Assert-True (@($errors).Count -eq 0) "PowerShell parser errors in ${scriptPath}: $($errors -join '; ')"
    }
    . $harness -NoRun

    $originalUserProfile = [Environment]::GetEnvironmentVariable('USERPROFILE')
    $originalCodexHome = [Environment]::GetEnvironmentVariable('CODEX_HOME')
    $originalClaudeHome = [Environment]::GetEnvironmentVariable('CLAUDE_CONFIG_DIR')
    try {
        $resolverProfile = Join-Path $temp 'resolver-profile'
        $resolverCodexHome = Join-Path $temp 'resolver-codex-home'
        $resolverClaudeHome = Join-Path $temp 'resolver-claude-home'
        $env:USERPROFILE = $resolverProfile
        $env:CODEX_HOME = $resolverCodexHome
        $env:CLAUDE_CONFIG_DIR = $resolverClaudeHome
        Assert-True ((Resolve-EffectiveConnectorHome codex).Equals(
            [IO.Path]::GetFullPath($resolverCodexHome),
            [StringComparison]::OrdinalIgnoreCase
        )) 'Codex effective home honors CODEX_HOME'
        Assert-True ((Resolve-EffectiveConnectorHome claudecode).Equals(
            [IO.Path]::GetFullPath($resolverClaudeHome),
            [StringComparison]::OrdinalIgnoreCase
        )) 'Claude effective home honors CLAUDE_CONFIG_DIR'
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
    } finally {
        [Environment]::SetEnvironmentVariable('USERPROFILE', $originalUserProfile)
        [Environment]::SetEnvironmentVariable('CODEX_HOME', $originalCodexHome)
        [Environment]::SetEnvironmentVariable('CLAUDE_CONFIG_DIR', $originalClaudeHome)
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
    $rules = $security.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])
    $seenUser = $false
    $seenSystem = $false
    foreach ($rule in $rules) {
        Assert-True ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow) "private fixture contains non-allow ACE for $($rule.IdentityReference)"
        $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier])
        Assert-True ($sid.Equals($identity.User) -or $sid.Equals($system)) "private fixture trusts unexpected principal $sid"
        if ($sid.Equals($identity.User)) { $seenUser = $true }
        if ($sid.Equals($system)) { $seenSystem = $true }
    }
    Assert-True ($seenUser -and $seenSystem) 'private fixture must grant only the current user and SYSTEM'

    $pwsh = (Get-Process -Id $PID).Path
    $profileTest = Invoke-NativeProcess -FilePath $pwsh -ArgumentList @(
        '-NoProfile', '-File', $nativeHarness, '-Operation', 'self-test',
        '-StateRoot', (Join-Path $temp 'isolated-profile')
    ) -TimeoutSeconds 30
    Assert-True ($profileTest.ExitCode -eq 0 -and $profileTest.StdOut -match 'self-test passed') 'disposable Windows profile and PATH isolation'

    $originalNativeBase = [Environment]::GetEnvironmentVariable('DC_WINDOWS_NATIVE_BASE_ROOT')
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

    $payloadPath = Join-Path $temp 'hook-payload.json'
    $payload = '{"hook":"stdin-sentinel"}'
    [IO.File]::WriteAllText($payloadPath, $payload)
    $script:LogRoot = Join-Path $temp 'logs'
    $script:CommandIndex = 0
    $stdin = Invoke-Tool 'pwsh' @('-NoProfile', '-File', $mock, '-Action', 'stdin') @(0) -InputPath $payloadPath
    Assert-True ($stdin.StdOut.Trim() -eq $payload) 'Invoke-Tool forwards the payload file to native stdin'

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

    $descendant = Start-Process -FilePath $pwsh -ArgumentList @('-NoProfile', '-Command', 'Start-Sleep -Seconds 30') -PassThru -WindowStyle Hidden
    try {
        Start-Sleep -Milliseconds 250
        Stop-IsolatedProcessTree -Confirm:$false
        Assert-True ($descendant.WaitForExit(5000)) 'isolated cleanup killed a descendant without StateRoot in its command line'
    } finally {
        Stop-Process -Id $descendant.Id -Force -ErrorAction SilentlyContinue
    }

    $jsonl = Join-Path $temp 'gateway.jsonl'
    $database = Join-Path $temp 'audit.db'
    $requestId = [guid]::NewGuid().ToString()
    $fixtureEvents = @(
        @{ connector = 'codex'; request_id = $requestId; event_type = 'verdict'; verdict = @{ action = 'block' } },
        @{ connector = 'codex'; request_id = $requestId; event_type = 'hook_decision'; hook_decision = @{ connector = 'codex'; action = 'allow'; raw_action = 'block'; mode = 'observe'; would_block = $true; enforced = $false; rule_ids = @('CMD-WIN-REMOVE-ITEM-RF') } },
        @{ connector = 'codex'; request_id = $requestId; event_type = 'tool_invocation' }
    ) | ForEach-Object { $_ | ConvertTo-Json -Compress }
    [IO.File]::WriteAllText($jsonl, ($fixtureEvents -join [Environment]::NewLine) + [Environment]::NewLine)
    $liveWriter = [IO.File]::Open($jsonl, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::ReadWrite)
    try {
        $sharedText = Read-SharedText $jsonl
        Assert-True ($sharedText -match 'hook_decision') 'diagnostics can read a live writer-owned JSONL'
        Assert-True (@(Get-EventLines $jsonl).Count -eq 3) 'gateway JSONL remains readable while the gateway writer is open'
    } finally {
        $liveWriter.Dispose()
    }
    $pythonCode = 'import sqlite3,sys;c=sqlite3.connect(sys.argv[1]);c.execute("create table audit_events(request_id text)");c.execute("insert into audit_events(request_id) values (?)",(sys.argv[2],));c.commit();c.close()'
    & python.exe -c $pythonCode $database $requestId
    if ($LASTEXITCODE -ne 0) { throw 'failed to create disposable audit fixture' }
    & python.exe (Join-Path $PSScriptRoot 'assert-windows-evidence.py') --jsonl $jsonl --audit-db $database --connector codex
    Assert-True ($LASTEXITCODE -eq 0) 'mock audit correlation'
    Assert-True (Test-ConnectorEvent $jsonl 'codex' 0) 'connector event seam'
    Assert-True (Test-BlockVerdict $jsonl 0) 'block verdict seam'
    $hookDecision = Get-LatestHookDecision $jsonl 'codex' 0
    Assert-True ($null -ne $hookDecision -and $hookDecision.raw_action -eq 'block' -and $hookDecision.would_block) 'hook decision raw block and would-block seam'
    Assert-True (Test-OtlpEvent $jsonl 'codex' 0) 'OTLP evidence seam'

    $nativeWorkflowText = [IO.File]::ReadAllText($nativeWorkflow)
    $liveWorkflowText = [IO.File]::ReadAllText($liveWorkflow)
    $ciWorkflowText = [IO.File]::ReadAllText($ciWorkflow)
    $harnessText = [IO.File]::ReadAllText($harness)
    $nativeHarnessText = [IO.File]::ReadAllText($nativeHarness)
    $wizardHarnessText = [IO.File]::ReadAllText($wizardHarness)
    $nativePathHelpersText = [IO.File]::ReadAllText($nativePathHelpers)
    $nativePathInitializerText = [IO.File]::ReadAllText($nativePathInitializer)
    $installerText = [IO.File]::ReadAllText($installer)
    Assert-True ($nativeWorkflowText -match '(?s)connector-contract:.*?connector: \[codex, claudecode\].*?windows-native-required:') 'required Windows contract matrix contains Codex and Claude'
    Assert-True ($nativeWorkflowText -match '(?m)^\s+name: Windows Native Required\s*$') 'stable aggregate check name exists'
    foreach ($job in @('windows-go', 'windows-python', 'powershell-static', 'package-artifact', 'packaged-acceptance', 'connector-contract')) {
        Assert-True ($nativeWorkflowText -match "(?m)^\s{6}- $([regex]::Escape($job))\s*$") "aggregate depends on $job"
    }
    Assert-True ($nativeWorkflowText -match '(?s)windows-native-required:.*?if: \$\{\{ always\(\) \}\}.*?result -ne ''success''') 'aggregate fails skipped or failed dependencies'
    Assert-True ($nativeWorkflowText -notmatch 'continue-on-error') 'required Windows jobs are not advisory'
    Assert-True ($nativeWorkflowText -notmatch 'shell:\s*bash') 'dedicated Windows workflow never selects Bash'
    Assert-True ($nativeWorkflowText -notmatch 'secrets\.') 'dedicated deterministic workflow consumes no secrets'
    Assert-True ([regex]::Matches(
        $nativeWorkflowText,
        '(?m)^\s*run: \./scripts/initialize-windows-native-ci-paths\.ps1 '
    ).Count -eq 6) 'every native Windows job uses the shared isolated-path initializer'
    foreach ($leafContract in @(
        '-Leaf go -DiagnosticsLeaf windows-native-diagnostics-go',
        "-Leaf ('py-' + `$env:PYTHON_SHARD) -DiagnosticsLeaf ('windows-native-diagnostics-python-' + `$env:PYTHON_SHARD)",
        '-Leaf ps -DiagnosticsLeaf windows-native-diagnostics-powershell',
        '-Leaf pkg -DiagnosticsLeaf windows-native-diagnostics-package -ArtifactLeaf windows-native-dist',
        '-Leaf acc -DiagnosticsLeaf windows-native-diagnostics-acceptance -ArtifactLeaf windows-native-dist',
        "-Leaf ('ct-' + `$env:CONNECTOR) -DiagnosticsLeaf ('windows-native-diagnostics-' + `$env:CONNECTOR) -ArtifactLeaf windows-native-dist"
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
    Assert-True ($nativePathInitializerText -match 'Join-Path \$env:RUNNER_TEMP \$DiagnosticsLeaf' -and
        $nativePathInitializerText -match 'Join-Path \$env:RUNNER_TEMP \$ArtifactLeaf' -and
        [regex]::Matches($nativeWorkflowText, '-ArtifactLeaf windows-native-dist').Count -eq 3) `
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
    Assert-True ($nativeWorkflowText -match '''test'', ''-v'', ''-count=1'', ''-run'', \$daclTestPattern, ''\./internal/safefile'', ''\./internal/managed'', ''\./internal/gateway/connector''') 'Go DACL regressions execute in every owning package without cache reuse'
    Assert-True ($nativeWorkflowText -match "'test'.*'\./\.\.\.'") 'full Go suite is required'
    Assert-True ($nativeWorkflowText -match '''-p=1''.*''-skip''.*\$windowsInapplicable') 'full Go suite serializes packages and excludes only declared Windows-inapplicable tests'
    Assert-True ($nativeWorkflowText -match 'Validate registered Windows Codex and Claude hook commands') 'native Windows workflow has a required Doctor hook-command step'
    Assert-True ($nativeWorkflowText -match "'pytest', 'cli/tests/test_cmd_doctor_windows_hooks\.py', '-q'") 'Doctor validates registered Windows hook commands explicitly'
    Assert-True ($nativeWorkflowText -match "Get-ChildItem cli/tests -Recurse -File -Filter 'test_\*\.py'") 'complete Python suite discovers every test file'
    Assert-True ($nativeWorkflowText -match 'shard: \[1, 2, 3, 4\]' -and
        $nativeWorkflowText -match '\(\$index % 4\) -eq \$shardIndex') `
        'complete Python suite assigns every test file to one of four deterministic shards'
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
        $nativeHarnessText -match "Name -eq 'wizard-driver\.log'") `
        'wizard automation records and prioritizes bounded install-transition diagnostics'
    foreach ($controlID in @(1001, 1002, 1003, 1005, 1009, 1011)) {
        Assert-True ($wizardHarnessText -match "Get-WizardControl \`$window $controlID") `
            "wizard automation reaches required real control id $controlID"
    }
    Assert-True ($wizardHarnessText -match 'foreach \(\$index in 0\.\.2\)' -and
        $wizardHarnessText -match 'foreach \(\$index in 0\.\.1\)' -and
        $wizardHarnessText -match 'Set-AndAssertCheckState \$startControl \$false' -and
        $wizardHarnessText -match 'Set-AndAssertCheckState \$startControl \$true') `
        'wizard automation deterministically exercises every connector, mode, and start choice'
    Assert-True ($wizardHarnessText -match "Send-WizardCommand \`$window 1005 'Install'" -and
        $wizardHarnessText -match "heading -ne 'DefenseClaw is installed'" -and
        $wizardHarnessText -match "Send-WizardCommand \`$window 1005 'Finish'") `
        'wizard automation activates Install and verifies the completion page before Finish'
    Assert-True ($nativeHarnessText -match "Invoke-WizardConfigureLaterAcceptance" -and
        $nativeHarnessText -match "(?s)Invoke-WizardConnectorAcceptance.*?'codex' 'observe'.*?Invoke-WizardConnectorAcceptance.*?'claudecode' 'action'") `
        'setup acceptance performs Configure Later, Codex Observe, and Claude Code Action wizard installs'
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
    Assert-True ($wizardAcceptance -match 'Get-WatchdogIdentity' -and
        $wizardAcceptance -match "@\('watchdog', 'status'\)" -and
        $wizardAcceptance -match 'wizard-started watchdog' -and
        $wizardAcceptance -match 'Assert-OnlyInstalledGatewayProcesses' -and
        $wizardAcceptance -notmatch "@\('watchdog', 'start'\)") `
        'wizard lifecycle requires STARTGATEWAY to auto-start an owned gateway and watchdog'
    Assert-True ($nativeHarnessText -match '\[IO\.FileShare\]::None' -and
        $nativeHarnessText -notmatch 'import time; time\.sleep\(60\)') `
        'setup locked-file acceptance uses a deterministic non-shareable handle'
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
    Assert-True ($nativeWorkflowText -notmatch '-Operation acceptance\b' -and
        $nativeHarnessText -notmatch "'acceptance' \{ Invoke-Acceptance \}" -and
        $nativeWorkflowText -match '-Operation setup-acceptance') `
        'required lifecycle certification no longer routes through the legacy wheel materializer'
    Assert-True ($nativeWorkflowText -match 'Always clean isolated processes, listeners, and temp state') 'required jobs have cleanup safety nets'
    Assert-True ($contractFunction -match "GetEnvironmentVariable\('Path', 'User'\)" -and
        $contractFunction -match 'restore the original user PATH exactly') `
        'native Setup connector contract proves uninstall restores the runner user PATH'
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

    Assert-True ($liveWorkflowText -match '(?s)windows-live:.*?connector: \[codex, claudecode\].*?report:') 'manual Windows live matrix contains Codex and Claude'
    $windowsLiveJob = [regex]::Match($liveWorkflowText, '(?s)  windows-live:.*?(?=\r?\n  # -+\r?\n  # Report)').Value
    Assert-True ($windowsLiveJob -notmatch 'continue-on-error') 'Windows live jobs are not advisory'
    Assert-True ($windowsLiveJob -notmatch 'shell:\s*bash') 'Windows live jobs never select Bash'
    Assert-True ($windowsLiveJob -match "github.event_name == 'workflow_dispatch'") 'provider-secret Windows tests are manual-only'
    Assert-True ($liveWorkflowText -match 'shell:\s*bash') 'Unix Bash harness remains present'
    Assert-True ($liveWorkflowText -notmatch '(?m)^  windows-(harness-static|contract):') 'deterministic Windows jobs moved out of live radar'
    Assert-True ($ciWorkflowText -notmatch '(?m)^  windows-(hook-path|installer-smoke):') 'legacy partial Windows jobs were removed'
    Assert-True ($harnessText -notmatch '(?i)\bwsl(?:\.exe)?\b|git bash|/bin/|Get-Command\s+(?:jq|tail|curl)|Invoke-Tool\s+''(?:jq|tail|curl)''') 'native harness has no WSL, Git Bash, or Unix utility dependency'
    Assert-True ($harnessText -match 'timeout-handling' -and $harnessText -match 'telemetry pass') 'contract records timeout and telemetry evidence'
    foreach ($rule in @(
        'CMD-WIN-REMOVE-ITEM-RF', 'CMD-WIN-RMDIR-SQ', 'CMD-WIN-IWR-IEX', 'CMD-WIN-REG-PERSIST',
        'PATH-WIN-AWS-CREDS', 'PATH-WIN-GIT-CREDS', 'PATH-WIN-CREDENTIAL-MANAGER'
    )) {
        Assert-True ($harnessText.Contains($rule)) "required Windows dangerous-command corpus contains $rule"
    }
    Assert-True ($harnessText -match "Invoke-DangerousCommandCorpus observe" -and $harnessText -match "Invoke-DangerousCommandCorpus action") 'connector contract executes dangerous-command corpus in observe and action modes'
    Assert-True ($harnessText -match 'raw_action' -and $harnessText -match 'would_block' -and $harnessText -match 'enforced') 'dangerous-command contract asserts raw and enforced decisions'
    foreach ($enterpriseOperation in @('install', 'reconcile', 'watch')) {
        Assert-True ($harnessText -match 'enterprise-hooks:\$\(\$command\.Name\):native-rejection' -and $harnessText.Contains("Name = '$enterpriseOperation'")) "built enterprise hooks $enterpriseOperation rejection is required"
    }
    Assert-True ($harnessText -match 'Get-TreeFingerprint' -and $harnessText -match 'AllowedExitCodes @\(1\)') 'enterprise hooks rejection is bounded, exit 1, and checks an unchanged tree'
    Assert-True ($harnessText -match 'Assert-DoctorWindowsHookRegistration' -and $harnessText -match 'healthy Windows-native executable registration') 'connector contract runs Doctor against the registered Windows hook executable'
    $contractRun = [regex]::Match($harnessText, '(?s)function Invoke-ContractRun\b.*?\n\}').Value
    Assert-True ($contractRun -match "(?s)try\s*\{.*?DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT = '1'.*?Invoke-Setup action.*?\}\s*finally\s*\{.*?Remove-Item Env:DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT") `
        'unversioned fixture override is removed before Doctor tamper validation'
    $doctorContract = [regex]::Match($harnessText, '(?s)function Assert-DoctorWindowsHookRegistration\b.*?\n\}').Value
    $doctorRegistration = $doctorContract.IndexOf("Write-Result 'doctor:windows-hook-registration'", [StringComparison]::Ordinal)
    $doctorStop = $doctorContract.IndexOf("Invoke-Tool 'defenseclaw-gateway' @('stop')", [StringComparison]::Ordinal)
    $doctorTamper = $doctorContract.IndexOf('$tamperedConfig =', [StringComparison]::Ordinal)
    $doctorRecovery = $doctorContract.IndexOf("Write-Result 'doctor:windows-hook-recovery'", [StringComparison]::Ordinal)
    $doctorStart = $doctorContract.IndexOf("Invoke-Tool 'defenseclaw-gateway' @('start')", [StringComparison]::Ordinal)
    $doctorWait = $doctorContract.LastIndexOf('Wait-Gateway', [StringComparison]::Ordinal)
    Assert-True ($doctorRegistration -ge 0 -and $doctorStop -gt $doctorRegistration -and
        $doctorTamper -gt $doctorStop -and $doctorRecovery -gt $doctorTamper -and
        $doctorStart -gt $doctorRecovery -and $doctorWait -gt $doctorStart) `
        'Doctor tamper validation pauses isolated self-heal and restores the gateway afterward'
    Assert-True ($doctorContract -match "(?s)Write-Result 'doctor:windows-hook-recovery'.*?try\s*\{.*?DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT = '1'.*?defenseclaw-gateway' @\('start'\).*?\}\s*finally\s*\{.*?Remove-Item Env:DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT.*?\}.*?Wait-Gateway") `
        'unversioned fixture override is scoped to the post-Doctor gateway restart'
    Assert-True ($harnessText -match 'obsolete shell-hook guidance for native Windows') 'Doctor connector contract rejects obsolete shell guidance'
    Assert-True ($harnessText -match 'function Wait-Gateway\(\[int\]\$Timeout = 90\)' -and $harnessText -match '\$probeTimeout = \[Math\]::Min\(15, \$remaining\)') 'gateway readiness uses bounded Windows-native status probes'
    Assert-True ($harnessText -match 'doctor:windows-hook-tamper' -and $harnessText -match 'obsolete gateway launcher' -and $harnessText.Contains("Invoke-Tool 'defenseclaw' @('doctor', '--json-output') @(1)")) 'Doctor connector contract rejects a tampered registered hook command with exit 1'
    Assert-True ($harnessText -match 'WriteAllBytes\(\$configPath, \$originalConfig\)' -and $harnessText -match 'doctor:windows-hook-recovery') 'Doctor connector contract restores the registration byte-for-byte and validates recovery'
    Assert-True ($nativeHarnessText -match '-StateRoot \$contractRoot -HomeRoot \$contractHome' -and
        $harnessText -match 'HomeRoot must be contained by StateRoot') `
        'connector contract keeps the installed runtime and agent homes in one disposable ownership root'
    Assert-True ($nativeHarnessText -match 'Join-Path \$contractRoot ''codex-home''' -and
        $nativeHarnessText -match 'Join-Path \$contractRoot ''claude-home''' -and
        $nativeHarnessText -match 'Assert-WindowsNativePathsDisjoint @\(\$contractHome, \$codexHome, \$claudeHome\)' -and
        $nativeHarnessText -match '\$env:CODEX_HOME = \$codexHome' -and
        $nativeHarnessText -match '\$env:CLAUDE_CONFIG_DIR = \$claudeHome') `
        'connector contract uses pairwise disjoint OS, Codex, and Claude homes'
    Assert-True ($nativeHarnessText -match '\$originalEnvironment = @\{\}' -and
        $nativeHarnessText -match 'GetEnvironmentVariables\(''Process''\)' -and
        $nativeHarnessText -match 'SetEnvironmentVariable\(\s*\[string\]\$name,\s*\[string\]\$originalEnvironment\[\$name\],\s*''Process''') `
        'connector contract restores the complete process environment in finally'
    Assert-True ($nativeHarnessText -match 'connector contract wrote to the default agent home' -and
        $nativeHarnessText -match 'connector contract wrote to the unrelated agent home' -and
        $harnessText -match 'function Resolve-EffectiveConnectorHome\b' -and
        [regex]::Matches($harnessText, 'Get-EffectiveConnectorConfigPath \$Connector').Count -eq 3 -and
        $harnessText -notmatch 'Join-Path \$env:USERPROFILE ''\.codex\\config\.toml''' -and
        $harnessText -notmatch 'Join-Path \$env:USERPROFILE ''\.claude\\settings\.json''') `
        'contract setup, Doctor, and teardown share effective homes and never fall back behind explicit overrides'
    Assert-True ($harnessText -match 'Assert-DoctorHookRegistration' -and $harnessText -match 'doctor-hooks pass') 'contract validates setup-created hooks with Doctor'
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
