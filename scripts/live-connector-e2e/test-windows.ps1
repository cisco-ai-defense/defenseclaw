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
$mock = Join-Path $PSScriptRoot 'testdata\windows-mock.ps1'
$temp = Join-Path ([IO.Path]::GetTempPath()) ("dc-windows-harness-test-" + [guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($temp) | Out-Null

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw "assertion failed: $Message" }
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

try {
    foreach ($scriptPath in @(
        $harness,
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
    . $nativeHarness -WorkspaceRoot $root -StateRoot (Join-Path $temp 'synthetic-native') -NoRun

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
            [IO.Directory]::CreateDirectory($caseRoot) | Out-Null
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
            Assert-True ([regex]::Matches(
                $updated,
                '(?m)^[ \t]*-[ \t]+name:[ \t]+windows-contract-jsonl[ \t]*(?=\r?$)'
            ).Count -eq 1) "$($case.Name) writes exactly one explicit contract JSONL destination"
            Assert-True ([regex]::Matches(
                $updated,
                '(?m)^[ \t]+kind:[ \t]+jsonl[ \t]*(?=\r?$)'
            ).Count -eq 1) "$($case.Name) writes a local JSONL destination"
            $jsonlPath = [regex]::Match(
                $updated,
                '(?m)^[ \t]+path:[ \t]+(?<literal>"(?:\\.|[^"\\])*")[ \t]*(?=\r?$)'
            )
            Assert-True $jsonlPath.Success "$($case.Name) writes a JSON-quoted JSONL path"
            Assert-True (($jsonlPath.Groups['literal'].Value | ConvertFrom-Json) -ceq (
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
    try {
        $resolverRoot = Join-Path $temp 'resolver-root'
        $resolverProfile = Join-Path $resolverRoot 'profile'
        $resolverCodexHome = Join-Path $resolverRoot 'codex-home'
        $resolverClaudeHome = Join-Path $resolverRoot 'claude-home'
        foreach ($path in @($resolverProfile, $resolverCodexHome, $resolverClaudeHome)) {
            [IO.Directory]::CreateDirectory($path) | Out-Null
        }
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
        Assert-PackagedConnectorHomes $resolverRoot $resolverProfile
        Assert-True ($env:CODEX_HOME -eq [IO.Path]::GetFullPath($resolverCodexHome) -and
            $env:CLAUDE_CONFIG_DIR -eq [IO.Path]::GetFullPath($resolverClaudeHome)) `
            'packaged connector home guard preserves exact installer-recorded homes'
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
            correlation = @{ request_id = $requestId }; provenance = $provenance; field_classes = @{}
            mandatory = $false
            body = @{
                'defenseclaw.scan.verdict' = 'block'
            }
        },
        [ordered]@{
            schema_version = 1; bucket_catalog_version = 1; timestamp = $observedAt
            record_id = 'windows-contract-hook-decision'; bucket = 'guardrail.evaluation'; signal = 'logs'
            event_name = 'hook_decision'; source = 'connector'; connector = 'codex'
            correlation = @{ request_id = $requestId }; provenance = $provenance; field_classes = @{}
            mandatory = $false
            body = @{
                'defenseclaw.guardrail.effective_action' = 'allow'
                'defenseclaw.guardrail.raw_action' = 'block'
                'defenseclaw.guardrail.mode' = 'observe'
                'defenseclaw.guardrail.would_block' = $true
                'defenseclaw.guardrail.enforced' = $false
                'defenseclaw.guardrail.rule_ids' = @('CMD-WIN-REMOVE-ITEM-RF')
            }
        },
        [ordered]@{
            schema_version = 1; bucket_catalog_version = 1; timestamp = $observedAt
            record_id = 'windows-contract-tool'; bucket = 'tool.activity'; signal = 'logs'
            event_name = 'tool.invocation.requested'; source = 'connector'; connector = 'codex'
            correlation = @{ request_id = $requestId }; provenance = $provenance; field_classes = @{}
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
    $pythonCode = 'import sqlite3,sys;c=sqlite3.connect(sys.argv[1]);c.execute("create table audit_events(request_id text)");c.execute("insert into audit_events(request_id) values (?)",(sys.argv[2],));c.commit();c.close()'
    & python.exe -c $pythonCode $database $requestId
    if ($LASTEXITCODE -ne 0) { throw 'failed to create disposable audit fixture' }
    & python.exe (Join-Path $root 'scripts\assert-observability-v8-jsonl.py') $jsonl `
        --min-records 5 --require-event-name hook_decision
    Assert-True ($LASTEXITCODE -eq 0) 'mock canonical observability-v8 schema'
    & python.exe (Join-Path $PSScriptRoot 'assert-windows-evidence.py') --jsonl $jsonl --audit-db $database --connector codex
    Assert-True ($LASTEXITCODE -eq 0) 'mock audit correlation'
    Assert-True (Test-ConnectorEvent $jsonl 'codex' 0) 'connector event seam'
    Assert-True (-not (Test-ConnectorEvent $jsonl 'claudecode' 0)) 'connector event seam ignores body-text false positives'
    Assert-True (Test-BlockVerdict $jsonl 0) 'block verdict seam'
    Assert-True (-not (Test-BlockVerdict $jsonl 1)) 'block verdict seam rejects hook decisions and non-canonical scan deny values'
    $hookDecision = Get-LatestHookDecision $jsonl 'codex' 0
    Assert-True ($null -ne $hookDecision -and $hookDecision.action -eq 'allow' -and
        $hookDecision.raw_action -eq 'block' -and $hookDecision.mode -eq 'observe' -and
        $hookDecision.would_block -and -not $hookDecision.enforced -and
        @($hookDecision.rule_ids) -contains 'CMD-WIN-REMOVE-ITEM-RF') `
        'hook decision reads canonical dotted guardrail fields'
    Assert-True (Test-OtlpEvent $jsonl 'codex' 0) 'OTLP evidence seam'

    $nativeWorkflowText = [IO.File]::ReadAllText($nativeWorkflow)
    $releaseWorkflowText = [IO.File]::ReadAllText($releaseWorkflow)
    $liveWorkflowText = [IO.File]::ReadAllText($liveWorkflow)
    $ciWorkflowText = [IO.File]::ReadAllText($ciWorkflow)
    $harnessText = [IO.File]::ReadAllText($harness)
    $nativeHarnessText = [IO.File]::ReadAllText($nativeHarness)
    $wizardHarnessText = [IO.File]::ReadAllText($wizardHarness)
    $standardUserCIText = [IO.File]::ReadAllText($standardUserCI)
    $standardUserLauncherText = [IO.File]::ReadAllText($standardUserLauncher)
    $setupStandardUserLauncherText = [IO.File]::ReadAllText($setupStandardUserLauncher)
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
    Assert-True ($wizardHarnessText -match 'foreach \(\$index in 0\.\.2\)' -and
        $wizardHarnessText -match 'foreach \(\$index in 0\.\.1\)' -and
        $wizardHarnessText -match 'Set-AndAssertCheckState \$startControl \$false' -and
        $wizardHarnessText -match 'Set-AndAssertCheckState \$startControl \$true') `
        'wizard automation deterministically exercises every connector, mode, and start choice'
    Assert-True ($wizardHarnessText -match "Send-WizardCommand \`$window 1 'Install'" -and
        $wizardHarnessText -match "heading -ne 'DefenseClaw is installed'" -and
        $wizardHarnessText -match "Send-WizardCommand \`$window 1 'Finish'") `
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
    $legacyLauncherAcceptance = [regex]::Match(
        $nativeHarnessText,
        '(?s)function Assert-WizardCodexLegacyLauncherNeedsRepair\b.*?(?=\r?\nfunction )'
    ).Value
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
    Assert-True ($nativeWorkflowText -match '(?s)Required setup, allow/block, audit, telemetry, timeout, and teardown contract.*?invoke-windows-setup-standard-user-ci\.ps1.*?-Mode contract.*?-Connector \$env:CONNECTOR.*?-DiagnosticsRoot \$env:DC_DIAGNOSTICS' -and
        $nativeWorkflowText -notmatch '\./scripts/windows-native-ci\.ps1 -Operation contract') `
        'hosted connector contracts run as disposable real standard users and preserve the matrix connector'
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
        $standardUserCIText -match '\$resourceVerifierInputs = @\(' -and
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
    Assert-True ($agentFixtureFunction -match "'OpenAI\\Codex\\bin'" -and
        $agentFixtureFunction -match "'\.local\\bin'" -and
        $agentFixtureFunction -match 'app-server' -and
        $agentFixtureFunction -match 'configRequirements/read' -and
        $agentFixtureFunction -match 'allowManagedHooksOnly.*false' -and
        $agentFixtureFunction -match 'SearchPath = \$claudeBin' -and
        $agentFixtureFunction -notmatch 'SearchPath = @\(\$codexBin' -and
        $agentFixtureFunction -notmatch 'DEFENSECLAW_TRUSTED_BIN_PREFIXES') `
        'Windows fixtures exercise Known-Folder Codex discovery and implement the policy RPC without PATH or env-only trust'
    Assert-True ($setupAcceptanceFunction -match 'New-WizardAgentFixtures' -and
        $setupAcceptanceFunction -match 'Remove-WizardAgentFixtures' -and
        $setupAcceptanceFunction -notmatch 'DEFENSECLAW_TRUSTED_BIN_PREFIXES') `
        'interactive Setup acceptance owns and cleans built-in-root fixtures without environment trust authority'
    Assert-True ($setupAcceptanceFunction -match '\$cachedSetup' -and
        $setupAcceptanceFunction -match 'Join-Path \$cacheRoot ''DefenseClawSetup-x64\.exe''' -and
        $setupAcceptanceFunction -match 'cached setup self-uninstall left installer cache behind') `
        'native Setup acceptance executes the cached Apps & Features binary and proves deferred self-delete removes InstallerCache'
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

    Assert-True ($liveWorkflowText -match '(?s)windows-live:.*?connector: \[codex, claudecode\].*?report:') 'manual Windows live matrix contains Codex and Claude'
    $windowsLiveJob = [regex]::Match($liveWorkflowText, '(?s)  windows-live:.*?(?=\r?\n  # -+\r?\n  # Report)').Value
    Assert-True ($windowsLiveJob -notmatch 'continue-on-error') 'Windows live jobs are not advisory'
    Assert-True ($windowsLiveJob -notmatch 'shell:\s*bash') 'Windows live jobs never select Bash'
    Assert-True ($windowsLiveJob -match "github.event_name == 'workflow_dispatch'") `
        'Connector Live Windows radar remains manual-only'
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
    Assert-True ($harnessText.Contains('$env:DEFENSECLAW_CONFIG = Join-Path $env:DEFENSECLAW_HOME ''config.yaml''') -and
        $harnessText -match '(?s)if \(\[string\]::IsNullOrWhiteSpace\(\$NativeDataRoot\)\) \{\s*\$env:CODEX_HOME = Join-Path \$env:USERPROFILE ''\.codex''\s*\$env:CLAUDE_CONFIG_DIR = Join-Path \$env:USERPROFILE ''\.claude''\s*\} else \{\s*Assert-PackagedConnectorHomes \$StateRoot \$HomeRoot\s*\}') `
        'native harness preserves packaged connector homes and otherwise binds disposable defaults'
    $packagedHomeGuard = [regex]::Match($harnessText, '(?s)function Assert-PackagedConnectorHomes\b.*?\n\}').Value
    Assert-True ($packagedHomeGuard -match 'Assert-WindowsNativePathsDisjoint' -and
        $packagedHomeGuard -match 'Test-PathWithin' -and
        $packagedHomeGuard -match 'Assert-DisposableNoReparseAncestors' -and
        $packagedHomeGuard -match '-RequireExists') `
        'packaged connector homes are disjoint, contained, existing, and non-reparse'
    Assert-True ($harnessText -match 'timeout-handling' -and $harnessText -match 'telemetry pass') 'contract records timeout and telemetry evidence'
    foreach ($rule in @(
        'CMD-WIN-REMOVE-ITEM-RF', 'CMD-WIN-RMDIR-SQ', 'CMD-WIN-IWR-IEX', 'CMD-WIN-REG-PERSIST',
        'PATH-WIN-AWS-CREDS', 'PATH-WIN-GIT-CREDS', 'PATH-WIN-CREDENTIAL-MANAGER'
    )) {
        Assert-True ($harnessText.Contains($rule)) "required Windows dangerous-command corpus contains $rule"
    }
    Assert-True ($harnessText -match "Invoke-DangerousCommandCorpus observe" -and $harnessText -match "Invoke-DangerousCommandCorpus action") 'connector contract executes dangerous-command corpus in observe and action modes'
    Assert-True ($harnessText -match 'raw_action' -and $harnessText -match 'would_block' -and $harnessText -match 'enforced') 'dangerous-command contract asserts raw and enforced decisions'
    Assert-True ($harnessText -match 'enterprise-hooks:install:elevation-required' -and
        $harnessText -match 'require an elevated administrator or LocalSystem token') `
        'native enterprise hooks require elevation in the standard-user connector contract'
    Assert-True ($harnessText -match 'Get-TreeFingerprint' -and $harnessText -match 'AllowedExitCodes @\(1\)') 'enterprise hooks elevation rejection is bounded, exit 1, and checks an unchanged tree'
    Assert-True ($harnessText -match 'Assert-DoctorWindowsHookRegistration' -and $harnessText -match 'healthy Windows-native executable registration') 'connector contract runs Doctor against the registered Windows hook executable'
    $contractRun = [regex]::Match($harnessText, '(?s)function Invoke-ContractRun\b.*?\n\}').Value
    Assert-True ($contractRun -match "(?s)try\s*\{.*?DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT = '1'.*?Invoke-Setup action.*?\}\s*finally\s*\{.*?Remove-Item Env:DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT") `
        'unversioned fixture override is removed before Doctor tamper validation'
    $liveRun = [regex]::Match($harnessText, '(?s)function Invoke-LiveRun\b.*?\n\}').Value
    Assert-True ($contractRun -notmatch 'Assert-CodexPinnedTrustMatrix' -and
        $liveRun -match 'Assert-CodexPinnedTrustMatrix') `
        'official npm trust probes stay in manual live-client certification, not mandatory deterministic CI'
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
        $harnessText.Contains("Invoke-Tool 'defenseclaw' @('doctor', '--json-output') @(1)")) `
        'Doctor connector contract rejects connector-specific tampered hook commands with exit 1'
    Assert-True ($harnessText -match 'WriteAllBytes\(\$configPath, \$originalConfig\)' -and $harnessText -match 'doctor:windows-hook-recovery') 'Doctor connector contract restores the registration byte-for-byte and validates recovery'
    Assert-True ($nativeHarnessText -match '-StateRoot \$contractProfileRoot -HomeRoot \$contractHome' -and
        $harnessText -match 'HomeRoot must be contained by StateRoot') `
        'connector contract keeps alternate agent homes inside the current-user-owned profile root'
    $contractInstall = $contractFunction.IndexOf(
        'Invoke-WindowsSetupStandardUserProcess $setup',
        [StringComparison]::Ordinal
    )
    $codexHomeCapture = $contractFunction.IndexOf(
        '$env:CODEX_HOME = $codexHome',
        [StringComparison]::Ordinal
    )
    $claudeHomeCapture = $contractFunction.IndexOf(
        '$env:CLAUDE_CONFIG_DIR = $claudeHome',
        [StringComparison]::Ordinal
    )
    Assert-True ($nativeHarnessText -match 'Join-Path \$realProfile ''\.defenseclaw-ci-contract''' -and
        $nativeHarnessText -match 'Join-Path \$contractProfileRoot ''codex-home''' -and
        $nativeHarnessText -match 'Join-Path \$contractProfileRoot ''claude-home''' -and
        $nativeHarnessText -match 'Assert-WindowsNativePathsDisjoint @\(\$contractHome, \$codexHome, \$claudeHome\)' -and
        $contractInstall -ge 0 -and
        $codexHomeCapture -ge 0 -and $codexHomeCapture -lt $contractInstall -and
        $claudeHomeCapture -ge 0 -and $claudeHomeCapture -lt $contractInstall) `
        'connector contract captures pairwise disjoint Codex and Claude homes during native Setup'
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
        $harnessText -match 'function Resolve-EffectiveConnectorHome\b' -and
        $harnessText -match '\$fileName = if \(\$ConnectorName -eq ''codex''\) \{ ''managed_config\.toml'' \}' -and
        [regex]::Matches($harnessText, 'Get-EffectiveConnectorConfigPath \$Connector').Count -eq 3 -and
        $harnessText -notmatch 'Join-Path \$env:USERPROFILE ''\.codex\\config\.toml''' -and
        $harnessText -notmatch 'Join-Path \$env:USERPROFILE ''\.claude\\settings\.json''') `
        'contract setup, Doctor, and teardown share effective homes and never fall back behind explicit overrides'
    Assert-True ($harnessText -match 'Assert-DoctorHookRegistration' -and $harnessText -match 'doctor-hooks pass') 'contract validates setup-created hooks with Doctor'
    Assert-True ($nativeHarnessText -match '\.codex\\managed_config\.toml' -and
        $nativeHarnessText -match 'unrelated Codex managed config byte-for-byte') `
        'release certification inventories and exactly preserves unrelated Codex managed config'
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
