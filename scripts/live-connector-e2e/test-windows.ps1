# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$harness = Join-Path $PSScriptRoot 'run-windows.ps1'
$nativeHarness = Join-Path $root 'scripts\windows-native-ci.ps1'
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
    foreach ($scriptPath in @($harness, $nativeHarness, $installer)) {
        $tokens = $null; $errors = $null
        [Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$errors) | Out-Null
        Assert-True (@($errors).Count -eq 0) "PowerShell parser errors in ${scriptPath}: $($errors -join '; ')"
    }
    . $harness -NoRun

    $pwsh = (Get-Process -Id $PID).Path
    $profileTest = Invoke-NativeProcess -FilePath $pwsh -ArgumentList @(
        '-NoProfile', '-File', $nativeHarness, '-Operation', 'self-test',
        '-StateRoot', (Join-Path $temp 'isolated-profile')
    ) -TimeoutSeconds 30
    Assert-True ($profileTest.ExitCode -eq 0 -and $profileTest.StdOut -match 'self-test passed') 'disposable Windows profile and PATH isolation'

    $allow = Invoke-NativeProcess -FilePath $pwsh -ArgumentList @('-NoProfile', '-File', $mock, '-Action', 'allow') -TimeoutSeconds 5
    Assert-True ($allow.ExitCode -eq 0 -and $allow.StdOut -match 'allow') 'mock allow decision'

    $block = Invoke-NativeProcess -FilePath $pwsh -ArgumentList @('-NoProfile', '-File', $mock, '-Action', 'block') -TimeoutSeconds 5 -AllowedExitCodes @(2)
    Assert-True ($block.ExitCode -eq 2 -and $block.StdOut -match 'block') 'mock block decision'

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

    $jsonl = Join-Path $temp 'gateway.jsonl'
    $database = Join-Path $temp 'audit.db'
    $requestId = [guid]::NewGuid().ToString()
    $fixtureEvents = @(
        @{ connector = 'codex'; request_id = $requestId; event_type = 'verdict'; verdict = @{ action = 'block' } },
        @{ connector = 'codex'; request_id = $requestId; event_type = 'hook_decision'; hook_decision = @{ connector = 'codex'; action = 'allow'; raw_action = 'block'; mode = 'observe'; would_block = $true; enforced = $false; rule_ids = @('CMD-WIN-REMOVE-ITEM-RF') } },
        @{ connector = 'codex'; request_id = $requestId; event_type = 'tool_invocation' }
    ) | ForEach-Object { $_ | ConvertTo-Json -Compress }
    [IO.File]::WriteAllText($jsonl, ($fixtureEvents -join [Environment]::NewLine) + [Environment]::NewLine)
    $liveWriter = [IO.File]::Open($jsonl, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::Read)
    try {
        $sharedText = Read-SharedText $jsonl
        Assert-True ($sharedText -match 'hook_decision') 'diagnostics can read a live writer-owned JSONL'
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
        'TestHookAPITokenWindowsAllowsGenericWriteOnSharedAncestor',
        'TestHookAPITokenWindowsAllowsInheritOnlyTemplateOnSharedAncestor',
        'TestHookAPITokenWindowsRejectsDeleteChildOnSharedAncestor'
    )) {
        Assert-True ($nativeWorkflowText -match [regex]::Escape($testName)) "native Windows Go DACL step reaches $testName"
    }
    Assert-True ($nativeWorkflowText -match '''test'', ''-v'', ''-count=1'', ''-run'', \$daclTestPattern, ''\./internal/safefile'', ''\./internal/managed'', ''\./internal/gateway/connector''') 'Go DACL regressions execute in every owning package without cache reuse'
    Assert-True ($nativeWorkflowText -match 'go'', ''test'', ''\.\/\.\.\.''' -or $nativeWorkflowText -match "'test', './\.\.\.'") 'full Go suite is required'
    Assert-True ($nativeWorkflowText -match 'Validate registered Windows Codex and Claude hook commands') 'native Windows workflow has a required Doctor hook-command step'
    Assert-True ($nativeWorkflowText -match "'pytest', 'cli/tests/test_cmd_doctor_windows_hooks\.py', '-q'") 'Doctor validates registered Windows hook commands explicitly'
    Assert-True ($nativeWorkflowText -match "'pytest', 'cli/tests', '-q'") 'complete Python suite is required'
    Assert-True ($nativeWorkflowText -match 'Run native Windows Local Splunk certification regressions') 'native Windows workflow has a required Local Splunk regression step'
    Assert-True ($nativeHarnessText -match "'pip', 'check'" -and $nativeHarnessText -match "'uv.exe'") 'managed environment runs explicit uv pip check'
    Assert-True ($nativeHarnessText -match 'doctor'', ''--json-output' -and $nativeHarnessText -match 'skill'', ''scan' -and $nativeHarnessText -match 'mcp'', ''scan') 'installed artifact smoke covers doctor and scanners'
    $acceptance = [regex]::Match(
        $nativeHarnessText,
        '(?s)function Invoke-Acceptance\b.*?\n\}'
    ).Value
    foreach ($phase in @('Invoke-InstallerAcceptance', 'Invoke-GatewayLifecycleAcceptance')) {
        Assert-True ($acceptance -match "\b$([regex]::Escape($phase))\b") `
            "packaged acceptance reaches $phase"
    }
    $installerAcceptance = [regex]::Match(
        $nativeHarnessText,
        '(?s)function Invoke-InstallerAcceptance\b.*?\n\}'
    ).Value
    foreach ($acceptanceHelper in @(
        'Assert-PackagedDoctorSmoke',
        'Assert-PackagedDaclAcceptance',
        'Assert-PackagedRepairAcceptance',
        'Assert-ResetAcceptance',
        'Invoke-FullUninstallCycle'
    )) {
        $definition = [regex]::Match(
            $nativeHarnessText,
            "(?s)function $([regex]::Escape($acceptanceHelper))\b.*?\n\}"
        ).Value
        Assert-True ($definition -and $installerAcceptance -match "\b$([regex]::Escape($acceptanceHelper))\b") `
            "packaged installer acceptance reaches $acceptanceHelper"
    }
    $gatewayAcceptance = [regex]::Match(
        $nativeHarnessText,
        '(?s)function Invoke-GatewayLifecycleAcceptance\b.*?\n\}'
    ).Value
    foreach ($acceptanceHelper in @(
        'Assert-RunningReinstallAcceptance',
        'Assert-TransactionalRollbackAcceptance'
    )) {
        $definition = [regex]::Match(
            $nativeHarnessText,
            "(?s)function $([regex]::Escape($acceptanceHelper))\b.*?\n\}"
        ).Value
        Assert-True ($definition -and $gatewayAcceptance -match "\b$([regex]::Escape($acceptanceHelper))\b") `
            "packaged gateway acceptance reaches $acceptanceHelper"
    }
    Assert-True ($gatewayAcceptance -match "@\('start'\) -Timeout 90" -and
        $gatewayAcceptance -match "@\('restart'\) -Timeout 90") `
        'packaged gateway lifecycle lets the native 60-second readiness deadline report and clean up'
    Assert-True ($nativeWorkflowText -match 'Always clean isolated processes, listeners, and temp state') 'required jobs have cleanup safety nets'
    Assert-True ($installerText -match '\[switch\]\$NoPersistPath' -and $nativeHarnessText -match '-NoPersistPath') 'CI install opts out of persistent user PATH changes'
    Assert-True ($nativeHarnessText -match "GetEnvironmentVariable\('Path', 'User'\)" -and $nativeHarnessText -match 'runner user PATH despite -NoPersistPath') 'packaged install verifies the runner user PATH was unchanged'
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
    Assert-True ($nativeHarnessText -match '-StateRoot \$contractRoot -HomeRoot \$contractHome' -and $harnessText -match 'HomeRoot must be contained by StateRoot') 'connector contract keeps the installed runtime and agent home in one disposable ownership root'
    Assert-True ($harnessText -match 'Assert-DoctorHookRegistration' -and $harnessText -match 'doctor-hooks pass') 'contract validates setup-created hooks with Doctor'
    $unpinned = [regex]::Matches($nativeWorkflowText, '(?m)^\s*-?\s*uses:\s*[^@\s]+@(?![0-9a-f]{40}\b)')
    $unpinnedText = @($unpinned | ForEach-Object { $_.Value }) -join ', '
    Assert-True ($unpinned.Count -eq 0) "external actions must be SHA-pinned: $unpinnedText"

    Write-Host 'Windows connector harness tests passed.'
} finally {
    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
        $_.CommandLine -and $_.CommandLine.Contains($temp)
    } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
}
