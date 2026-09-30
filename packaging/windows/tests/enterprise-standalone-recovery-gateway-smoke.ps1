# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 7.0

# Function-level regression test. Recovering a pending transaction
# runs the managed-hook lifecycle restore and retire with the transaction's
# staged gateway. When that gateway fails (a release whose retire refuses
# state it cannot repair), no newer Setup could finish the recovery. A
# standalone recovery now reruns the failed step with the running Setup's own
# gateway, but only after that gateway passed the payload trust check an
# Install applies, only as LocalSystem and only when it is not an older
# release than the staged gateway, and records which binary ran (with its own
# release) and why. Everything else keeps the staged gateway's error. The
# gateway command, the LocalSystem test, the protected-location check (owned
# by the exact-ACL and bootstrap smokes) and the version-resource read are
# stubbed; the standalone hash-pinned trust policy, the source descriptor, the
# release ordering and the atomic install are the production functions, run in
# a disposable scratch directory. The last case drives the real
# Restore-DefenseClawTransaction through a fallback with service control
# stubbed, to show the later cleanup runs with the verified gateway and the
# file rollback puts <InstallRoot>\bin back to its preimage. The standalone
# lifecycle runs only on PowerShell 7.

[CmdletBinding()]
param(
    [string]$ScratchRoot = [IO.Path]::GetTempPath()
)

Microsoft.PowerShell.Core\Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modulePath = [IO.Path]::GetFullPath(
    (Microsoft.PowerShell.Management\Join-Path `
        $PSScriptRoot `
        '..\DefenseClawEnterprise.psm1')
)
$installerPath = [IO.Path]::GetFullPath(
    (Microsoft.PowerShell.Management\Join-Path `
        $PSScriptRoot `
        '..\install-enterprise.ps1')
)
$module = Microsoft.PowerShell.Core\Import-Module `
    -Name $modulePath `
    -Force `
    -PassThru `
    -ErrorAction Stop

$failures = & $module {
    param([string]$ModulePath, [string]$InstallerPath, [string]$ScratchRoot)

    $failures = [Collections.Generic.List[string]]::new()
    $script:TestCalls = [Collections.Generic.List[string]]::new()
    $script:TestFailing = @{}
    $script:TestLocalSystem = $true
    $script:TestUntrustedSource = ''
    $script:TestVersions = @{}
    $relaxedHooks = 'managed Windows DACL on C:\Users\alice\.defenseclaw\hooks has 2 ACEs, expected 7'

    function Assert-DefenseClawAdministrator {
    }
    function Test-DefenseClawLocalSystemToken {
        return [bool]$script:TestLocalSystem
    }
    function Assert-DefenseClawTrustedSource {
        param([string]$Path, [string]$Label)
        $full = [IO.Path]::GetFullPath($Path)
        if ([string]::Equals($full, $script:TestUntrustedSource, [StringComparison]::OrdinalIgnoreCase)) {
            throw "untrusted principal S-1-5-32-545 has write-like access to $Label source: $full"
        }
        return $full
    }
    # The release a gateway's version resource carries, keyed by its bytes.
    function Get-DefenseClawRecoveryGatewayVersion {
        param([string]$Path)
        if ([string]::IsNullOrWhiteSpace($Path) -or -not [IO.File]::Exists($Path)) {
            return ''
        }
        $content = [IO.File]::ReadAllText($Path).Trim()
        if ($script:TestVersions.ContainsKey($content)) {
            return [string]$script:TestVersions[$content]
        }
        return ''
    }
    # The hidden command, keyed by which gateway bytes sit at GatewayPath.
    function Invoke-DefenseClawGatewayCommand {
        param(
            [hashtable]$Layout,
            [string]$GatewayServiceName,
            [string[]]$Arguments,
            [switch]$Capture,
            [switch]$AllowFailure
        )
        $gateway = [IO.File]::ReadAllText([string]$Layout.GatewayPath).Trim()
        $action = [string]$Arguments[3]
        $script:TestCalls.Add("${gateway}:$action")
        $phase = switch ($action) {
            'restore' { 'restored' }
            'retire' { 'retired' }
        }
        $report = [ordered]@{
            schema_version = 4
            action = $action
            ok = $true
            journal_path = [string]$Layout.ManagedHooksLifecycleJournalPath
            phase = $phase
        }
        $exitCode = 0
        if ($script:TestFailing.ContainsKey("${gateway}:$action")) {
            $report.ok = $false
            $report.phase = ''
            $report['error'] = "retire amp managed runtime generations for SID S-1-5-21-1-2-3-1017: $relaxedHooks"
            $exitCode = 1
        }
        return [ordered]@{
            exit_code = $exitCode
            output = @(($report | Microsoft.PowerShell.Utility\ConvertTo-Json -Compress))
        }
    }

    function Get-TestSHA256([string]$Path) {
        return (Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    }

    $root = [IO.Path]::Combine(
        [IO.Path]::GetFullPath($ScratchRoot),
        ('dc-recovery-gw-' + [Guid]::NewGuid().ToString('N').Substring(0, 12))
    )
    $utf8 = [Text.UTF8Encoding]::new($false)
    $originalProfile = Get-DefenseClawEnterpriseProfile
    try {
        $installRoot = [IO.Path]::Combine($root, 'install')
        $setupRoot = [IO.Path]::Combine($root, 'setup')
        $emptySetupRoot = [IO.Path]::Combine($root, 'setup-without-payload')
        foreach ($directory in @(
            [IO.Path]::Combine($installRoot, 'bin'),
            [IO.Path]::Combine($installRoot, 'libexec'),
            $setupRoot,
            $emptySetupRoot,
            [IO.Path]::Combine($root, 'state', 'install')
        )) {
            [void][IO.Directory]::CreateDirectory($directory)
        }
        $layout = @{
            InstallRoot = $installRoot
            GatewayPath = [IO.Path]::Combine($installRoot, 'bin', 'defenseclaw-gateway.exe')
            ManagedHooksLifecycleJournalPath = [IO.Path]::Combine($root, 'state', 'install', 'managed-hooks-lifecycle.json')
            PendingPath = [IO.Path]::Combine($root, 'state', 'install', 'pending.json')
            # An ensure-driven repair records the staged gateway's release,
            # not the running Setup's.
            ProductVersion = '1.0.40'
        }
        $setupInstaller = [IO.Path]::Combine($setupRoot, 'install-enterprise.ps1')
        $setupGateway = [IO.Path]::Combine($setupRoot, 'defenseclaw-gateway.exe')
        $payloadManifest = [IO.Path]::Combine($root, 'payload-trust.json')
        [IO.File]::WriteAllText($setupInstaller, '# Setup installer', $utf8)
        [IO.File]::WriteAllText(
            [IO.Path]::Combine($emptySetupRoot, 'install-enterprise.ps1'),
            '# installer without a payload',
            $utf8
        )

        function Reset-TestHost {
            param(
                [string]$SetupContent = 'setup-gateway',
                [string]$PinnedSHA256 = '',
                [string[]]$Failing = @('staged-gateway:retire'),
                [string]$StagedVersion = '1.0.40',
                [string]$SetupVersion = '1.0.43'
            )
            $script:TestVersions = @{
                'staged-gateway' = $StagedVersion
                'setup-gateway' = $SetupVersion
            }
            [IO.File]::WriteAllText($layout.GatewayPath, 'staged-gateway', $utf8)
            [IO.File]::WriteAllText($setupGateway, $SetupContent, $utf8)
            if ([string]::IsNullOrEmpty($PinnedSHA256)) {
                $PinnedSHA256 = Get-TestSHA256 $setupGateway
            }
            [IO.File]::WriteAllText(
                $payloadManifest,
                (@{ schema_version = 1; files = @{ 'defenseclaw-gateway.exe' = $PinnedSHA256 } } |
                    Microsoft.PowerShell.Utility\ConvertTo-Json -Depth 4),
                $utf8
            )
            Initialize-DefenseClawStandalonePayloadTrust `
                -TrustMode HashPinned `
                -PayloadManifest $payloadManifest
            $script:TestFailing = @{}
            foreach ($entry in $Failing) {
                $script:TestFailing[$entry] = $true
            }
            $script:TestCalls.Clear()
            $script:TestLocalSystem = $true
            $script:TestUntrustedSource = ''
            Set-DefenseClawRecoveryGatewayCandidate -InstallerSource $setupInstaller
        }

        function Invoke-TestRecovery {
            $outcome = [ordered]@{ reports = @(); error = '' }
            try {
                foreach ($action in @('restore', 'retire')) {
                    $outcome.reports += @(Invoke-DefenseClawManagedHooksLifecycleRecoveryStep `
                        -Layout $layout `
                        -GatewayServiceName 'DefenseClawGateway' `
                        -Action $action)
                }
            }
            catch {
                $outcome.error = $_.Exception.Message
            }
            return $outcome
        }

        function Assert-TestRefused {
            param([string]$Label, [string]$Code)
            $outcome = Invoke-TestRecovery
            $gateway = [IO.File]::ReadAllText($layout.GatewayPath).Trim()
            $refusal = $script:DefenseClawRecoveryGatewayRefusal
            if (-not $outcome.error.Contains($relaxedHooks) -or
                $outcome.error.Contains('verified Setup gateway')) {
                $failures.Add("${Label}: the staged gateway's error did not stand: $($outcome.error)")
            }
            if ($null -eq $refusal -or [string]$refusal.code -cne $Code -or [string]$refusal.action -cne 'retire') {
                $failures.Add("${Label}: refusal $(if ($null -eq $refusal) { 'none' } else { [string]$refusal.code }), want $Code")
            }
            if (@($script:DefenseClawRecoveryGatewayRuns).Count -ne 0 -or $gateway -cne 'staged-gateway') {
                $failures.Add("${Label}: a refused fallback still replaced the staged gateway ($gateway)")
            }
            if ((@($script:TestCalls) -join '|') -cne 'staged-gateway:restore|staged-gateway:retire') {
                $failures.Add("${Label}: calls $(@($script:TestCalls) -join ', ')")
            }
        }

        Set-DefenseClawEnterpriseProfile -EnterpriseProfile Standalone

        # 1. Verified fallback: the staged gateway restores but cannot retire;
        # the hash-pinned Setup gateway replaces it and retires.
        Reset-TestHost
        $stagedSHA256 = Get-TestSHA256 $layout.GatewayPath
        $setupSHA256 = Get-TestSHA256 $setupGateway
        $outcome = Invoke-TestRecovery
        $runs = @(Get-DefenseClawRecoveryGatewayRunRecords)
        if (-not [string]::IsNullOrEmpty($outcome.error) -or @($outcome.reports).Count -ne 2 -or
            [string]$outcome.reports[1].phase -cne 'retired') {
            $failures.Add("verified fallback failed: $($outcome.error)")
        }
        if ((@($script:TestCalls) -join '|') -cne 'staged-gateway:restore|staged-gateway:retire|setup-gateway:retire') {
            $failures.Add("verified fallback calls: $(@($script:TestCalls) -join ', ')")
        }
        if ([IO.File]::ReadAllText($layout.GatewayPath).Trim() -cne 'setup-gateway') {
            $failures.Add('the verified Setup gateway was not staged at <InstallRoot>\bin')
        }
        if ($runs.Count -ne 1) {
            $failures.Add("verified fallback recorded $($runs.Count) runs")
        }
        else {
            $run = $runs[0]
            foreach ($check in @(
                @('action', 'retire'),
                @('binary', $layout.GatewayPath),
                @('source', $setupGateway),
                @('sha256', $setupSHA256),
                @('trust', 'hash_pinned'),
                @('identity', 'NT AUTHORITY\SYSTEM'),
                # The release of the gateway that ran, not the version the
                # lifecycle records for the deployment.
                @('product_version', '1.0.43'),
                @('replaced_sha256', $stagedSHA256),
                @('staged_version', '1.0.40'),
                @('reason', 'staged_gateway_failed'),
                @('outcome', 'succeeded')
            )) {
                if ([string]$run.($check[0]) -cne [string]$check[1]) {
                    $failures.Add("run $($check[0]) = '$($run.($check[0]))', want '$($check[1])'")
                }
            }
            if (-not ([string]$run.staged_error).Contains($relaxedHooks)) {
                $failures.Add("run staged_error = '$($run.staged_error)'")
            }
        }
        if ($null -ne $script:DefenseClawRecoveryGatewayRefusal) {
            $failures.Add('a taken fallback recorded a refusal')
        }

        # The failure document of a lifecycle that fails after the fallback
        # carries the pending state and the binary recovery ran.
        $tokens = $null
        $parseErrors = $null
        $installerAst = [Management.Automation.Language.Parser]::ParseFile(
            $InstallerPath,
            [ref]$tokens,
            [ref]$parseErrors
        )
        $evidenceFunction = $installerAst.Find({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -ceq 'Add-DefenseClawLifecycleFailureEvidence'
        }, $true)
        . ([scriptblock]::Create([string]$evidenceFunction.Extent.Text))
        [IO.File]::WriteAllText($layout.PendingPath, '{}', $utf8)
        $record = [Management.Automation.ErrorRecord]::new(
            [Management.Automation.RuntimeException]::new('Repair failed'),
            'LifecycleFailed',
            [Management.Automation.ErrorCategory]::NotSpecified,
            $null
        )
        Add-DefenseClawRecoveryEvidenceToError -ErrorRecord $record -Layout $layout
        $document = [pscustomobject]@{ schema_version = 1; ok = $false; action = 'repair'; error = 'Repair failed'; errors = @('Repair failed') }
        Add-DefenseClawLifecycleFailureEvidence -Document $document -Evidence $record.Exception.Data
        $parsed = ($document | Microsoft.PowerShell.Utility\ConvertTo-Json -Depth 6 -Compress) |
            Microsoft.PowerShell.Utility\ConvertFrom-Json
        if (-not [bool]$parsed.transaction_pending -or
            @($parsed.recovery_gateway_runs).Count -ne 1 -or
            [string]@($parsed.recovery_gateway_runs)[0].binary -cne $layout.GatewayPath -or
            [string]@($parsed.recovery_gateway_runs)[0].sha256 -cne $setupSHA256) {
            $failures.Add("failure document: $($document | Microsoft.PowerShell.Utility\ConvertTo-Json -Depth 6 -Compress)")
        }
        [IO.File]::Delete($layout.PendingPath)
        $plain = [pscustomobject]@{ schema_version = 1; ok = $false }
        Add-DefenseClawLifecycleFailureEvidence -Document $plain -Evidence ([Collections.Hashtable]::new())
        Add-DefenseClawLifecycleFailureEvidence -Document $plain -Evidence $null
        if (@($plain.PSObject.Properties).Count -ne 2) {
            $failures.Add('a failure without recovery evidence changed its document')
        }

        # 2. A staged gateway that fails restore: the Setup gateway restores,
        # then retires as the newly staged gateway.
        Reset-TestHost -Failing @('staged-gateway:restore', 'staged-gateway:retire')
        $outcome = Invoke-TestRecovery
        if (-not [string]::IsNullOrEmpty($outcome.error) -or
            (@($script:TestCalls) -join '|') -cne 'staged-gateway:restore|setup-gateway:restore|setup-gateway:retire' -or
            @($script:DefenseClawRecoveryGatewayRuns).Count -ne 1) {
            $failures.Add("restore fallback: $($outcome.error) calls $(@($script:TestCalls) -join ', ')")
        }

        # 3. Refusals keep the staged gateway and its error.
        Reset-TestHost -PinnedSHA256 ('0' * 64)
        Assert-TestRefused 'payload failing the hash pin' 'untrusted'

        Reset-TestHost
        $script:TestUntrustedSource = $setupGateway
        Assert-TestRefused 'payload a standard user could replace' 'untrusted'

        Reset-TestHost
        $script:TestLocalSystem = $false
        Assert-TestRefused 'elevated administrator, not LocalSystem' 'not_local_system'

        Reset-TestHost -SetupContent 'staged-gateway'
        Assert-TestRefused 'the Setup gateway is the staged one' 'same_binary'

        Reset-TestHost
        Set-DefenseClawRecoveryGatewayCandidate -InstallerSource $setupInstaller -AllowUnsigned
        Assert-TestRefused 'unsigned certification scope' 'unsigned_scope'

        Reset-TestHost
        Set-DefenseClawRecoveryGatewayCandidate -InstallerSource ([IO.Path]::Combine($emptySetupRoot, 'install-enterprise.ps1'))
        Assert-TestRefused 'installer without a payload (the installed CLI)' 'no_payload'

        Reset-TestHost
        $insideGateway = [IO.Path]::Combine($installRoot, 'libexec', 'defenseclaw-gateway.exe')
        [IO.File]::WriteAllText($insideGateway, 'setup-gateway', $utf8)
        Set-DefenseClawRecoveryGatewayCandidate -GatewayBinary $insideGateway
        Assert-TestRefused 'a gateway inside InstallRoot' 'inside_install_root'

        # 3b. Version floor: never an older release than the staged gateway,
        # and never a gateway whose release cannot be read.
        Reset-TestHost -SetupVersion '1.0.39'
        Assert-TestRefused 'an older Setup release' 'older_release'
        $refusal = $script:DefenseClawRecoveryGatewayRefusal
        if ($null -eq $refusal -or
            -not ([string]$refusal.message).Contains('release 1.0.39, older than the staged gateway''s release 1.0.40')) {
            $failures.Add("older release refusal message: $(if ($null -eq $refusal) { 'none' } else { [string]$refusal.message })")
        }

        Reset-TestHost -StagedVersion '1.0.40' -SetupVersion '1.0.40-rc.1'
        Assert-TestRefused 'a prerelease of the staged release' 'older_release'

        Reset-TestHost -SetupVersion ''
        Assert-TestRefused 'a Setup gateway without a version resource' 'version_unknown'

        Reset-TestHost -StagedVersion 'dev'
        Assert-TestRefused 'a staged gateway without a release version' 'version_unknown'

        foreach ($pair in @(
            @('1.0.40', '1.0.40'),
            @('1.0.40-rc.1', '1.0.40'),
            @('1.0.40', 'v1.0.41+abc'),
            @('1.0.9', '1.0.10')
        )) {
            Reset-TestHost -StagedVersion $pair[0] -SetupVersion $pair[1]
            $outcome = Invoke-TestRecovery
            if (-not [string]::IsNullOrEmpty($outcome.error) -or
                @($script:DefenseClawRecoveryGatewayRuns).Count -ne 1 -or
                [string]@(Get-DefenseClawRecoveryGatewayRunRecords)[0].product_version -cne $pair[1]) {
                $failures.Add("Setup release $($pair[1]) over staged $($pair[0]) was not admitted: $($outcome.error)")
            }
        }

        foreach ($case in @(
            @('1.0.43', '1.0.43', 0),
            @('1.0.43', '1.0.42', 1),
            @('1.0.9', '1.0.10', -1),
            @('1.0', '1.0.0', 0),
            @('V1.0.43+build.7', '1.0.43', 0),
            @('1.0.43-rc.1', '1.0.43', -1),
            @('1.0.43-rc.2', '1.0.43-rc.10', 1),
            @('1.0.43.1', '1.0.43', 1)
        )) {
            $left = ConvertTo-DefenseClawRecoveryGatewayRelease -Value $case[0]
            $right = ConvertTo-DefenseClawRecoveryGatewayRelease -Value $case[1]
            $order = if ($null -eq $left -or $null -eq $right) {
                'unparsed'
            }
            else {
                Compare-DefenseClawRecoveryGatewayRelease -Left $left -Right $right
            }
            if ([string]$order -cne [string]$case[2]) {
                $failures.Add("release order $($case[0]) vs $($case[1]) = $order, want $($case[2])")
            }
        }
        foreach ($value in @('', 'dev', '1..2', '1.2.3.4.5', '7.4.6 SHA: 0123abc', '1.0.x', '-1.0')) {
            if ($null -ne (ConvertTo-DefenseClawRecoveryGatewayRelease -Value $value)) {
                $failures.Add("'$value' parsed as a release")
            }
        }

        # 4. The Setup gateway fails the step too: the run is recorded as
        # failed and both failures are reported.
        Reset-TestHost -Failing @('staged-gateway:retire', 'setup-gateway:retire')
        $outcome = Invoke-TestRecovery
        $runs = @(Get-DefenseClawRecoveryGatewayRunRecords)
        if (-not $outcome.error.Contains('failed with the staged gateway and again with the verified Setup gateway') -or
            $runs.Count -ne 1 -or [string]$runs[0].outcome -cne 'failed' -or
            -not ([string]$runs[0].error).Contains($relaxedHooks)) {
            $failures.Add("failed fallback: $($outcome.error)")
        }

        # 5. Secure Client recovers only with the staged gateway.
        Set-DefenseClawEnterpriseProfile -EnterpriseProfile SecureClient
        Reset-TestHost
        if ($null -ne $script:DefenseClawRecoveryGatewayCandidate) {
            $failures.Add('Secure Client named a recovery gateway')
        }
        $outcome = Invoke-TestRecovery
        if (-not $outcome.error.Contains($relaxedHooks) -or
            $null -ne $script:DefenseClawRecoveryGatewayRefusal -or
            @($script:DefenseClawRecoveryGatewayRuns).Count -ne 0 -or
            (@($script:TestCalls) -join '|') -cne 'staged-gateway:restore|staged-gateway:retire' -or
            [IO.File]::ReadAllText($layout.GatewayPath).Trim() -cne 'staged-gateway') {
            $failures.Add("Secure Client recovery changed: $($outcome.error) calls $(@($script:TestCalls) -join ', ')")
        }
        $record = [Management.Automation.ErrorRecord]::new(
            [Management.Automation.RuntimeException]::new('Repair failed'),
            'LifecycleFailed',
            [Management.Automation.ErrorCategory]::NotSpecified,
            $null
        )
        Add-DefenseClawRecoveryEvidenceToError -ErrorRecord $record -Layout $layout
        if ($record.Exception.Data.Count -ne 0) {
            $failures.Add('Secure Client attached recovery evidence to a lifecycle error')
        }

        # 6. Wiring: recovery restore and retire go through the fallback step,
        # the entry point names the candidate for every run and attaches the
        # evidence to a failure, and a status document reports the runs.
        $moduleAst = [Management.Automation.Language.Parser]::ParseFile(
            $ModulePath,
            [ref]$tokens,
            [ref]$parseErrors
        )
        $body = {
            param([string]$Name)
            $moduleAst.Find({
                param($node)
                $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
                    $node.Name -ceq $Name
            }, $true).Body.Extent.Text
        }
        $restore = & $body 'Restore-DefenseClawTransaction'
        foreach ($action in @('restore', 'retire')) {
            $step = [Text.RegularExpressions.Regex]::Matches(
                $restore,
                'Invoke-DefenseClawManagedHooksLifecycleRecoveryStep\s+`\s+-Layout \$Layout\s+`\s+-GatewayServiceName \(\[string\]\$snapshot\.gateway_service\)\s+`\s+-Action ' + $action + '\)'
            ).Count
            $direct = [Text.RegularExpressions.Regex]::Matches(
                $restore,
                'Invoke-DefenseClawManagedHooksLifecycleSnapshotCommand\s+`\s+-Layout \$Layout\s+`\s+-GatewayServiceName \(\[string\]\$snapshot\.gateway_service\)\s+`\s+-Action ' + $action + '\)'
            ).Count
            if ($step -ne 1 -or $direct -ne 0) {
                $failures.Add("Restore-DefenseClawTransaction $action runs through the recovery step $step time(s), directly $direct time(s)")
            }
        }
        $entry = & $body 'Invoke-DefenseClawEnterpriseLifecycle'
        $candidate = $entry.IndexOf('Set-DefenseClawRecoveryGatewayCandidate `')
        $lock = $entry.IndexOf('$lifecycleLock = Enter-DefenseClawLifecycleLock -Layout $layout')
        $evidence = $entry.IndexOf('Add-DefenseClawRecoveryEvidenceToError -ErrorRecord $_ -Layout $layout')
        $finally = $entry.LastIndexOf('Exit-DefenseClawLifecycleLock -Lock $lifecycleLock')
        if ($candidate -lt 0 -or $lock -lt $candidate -or $evidence -lt $lock -or $finally -lt $evidence) {
            $failures.Add('the lifecycle entry point does not name the recovery candidate before the lock and attach evidence to failures')
        }
        $status = & $body 'Get-DefenseClawLifecycleStatus'
        if (-not $status.Contains("`$status['recovery_gateway_runs'] = `$recoveryRuns") -or
            -not $status.Contains("`$status['recovery_gateway_refusal']")) {
            $failures.Add('the standalone status document does not report the recovery gateway')
        }

        # 7. End to end through Restore-DefenseClawTransaction. After the
        # fallback retires with the verified gateway, the per-user runtime
        # cleanup runs with that gateway, and the generic file rollback puts
        # <InstallRoot>\bin back to its preimage: the prior release's gateway
        # after a failed upgrade, no gateway after a failed first install.
        # The Secure Client profile still stops at the staged gateway's
        # failure. Service control, the recovery binding and the ACL steps
        # are stubbed.
        function Assert-DefenseClawOwnedServiceOrAbsent {
        }
        function Test-DefenseClawServiceExists {
            param([string]$Name)
            return $false
        }
        function Set-DefenseClawServiceStartMode {
        }
        function Stop-DefenseClawService {
        }
        function Set-DefenseClawServiceActivationPhase {
        }
        function Resolve-DefenseClawManagedHooksLifecycleRecoveryBinding {
            return $null
        }
        function Assert-DefenseClawUnboundLegacyLifecycleRecoveryPreimage {
            return $null
        }
        function Invoke-DefenseClawTargetRuntimeRollbackCleanup {
            param(
                [string]$SnapshotPath,
                [hashtable]$Layout,
                [string]$GatewayServiceName,
                [string]$GuardianServiceName
            )
            $script:TestCalls.Add('cleanup:' + [IO.File]::ReadAllText([string]$Layout.GatewayPath).Trim())
            return (Microsoft.PowerShell.Management\Get-Content -LiteralPath $SnapshotPath -Raw |
                Microsoft.PowerShell.Utility\ConvertFrom-Json)
        }
        function Restore-DefenseClawRedactionKeySecuritySnapshot {
        }
        function Revoke-DefenseClawManagedIPCServiceAccess {
        }
        function Remove-DefenseClawService {
        }
        function Remove-DefenseClawTransactionCreatedSharedDirectories {
        }
        function Restore-DefenseClawRetainedStateAclsFromTransaction {
        }
        function Assert-DefenseClawRestoredTransactionReadyForActivation {
            return $false
        }

        Set-DefenseClawEnterpriseProfile -EnterpriseProfile Standalone
        $stateRoot = [IO.Path]::Combine($root, 'state')
        $layout.StateRoot = $stateRoot
        $layout.ManifestPath = [IO.Path]::Combine($stateRoot, 'targets.yaml')
        $layout.CertificationCodexHome = ''
        $layout.CoreHardeningCertification = $false
        $layout.ProviderLibraryPath = ''
        $layout.BrokerServiceName = ''
        $layout.CodexMachinePolicyDirectory = [IO.Path]::Combine($root, 'codex-policy')
        $layout.CodexMachinePolicyPath = [IO.Path]::Combine($root, 'codex-policy', 'requirements.toml')
        $layout.CodexManagedHooksStatePath = [IO.Path]::Combine($stateRoot, 'codex-managed-hooks.json')
        $layout.AgentApplicationControlAttestationPath = [IO.Path]::Combine($stateRoot, 'agent-application-control.json')
        $layout.StateRootAncestors = @()
        $priorGateway = [IO.Path]::Combine($stateRoot, 'install', 'backup', 'defenseclaw-gateway.exe')
        [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($priorGateway))
        [IO.File]::WriteAllText($priorGateway, 'prior-gateway', $utf8)
        $snapshotPath = [IO.Path]::Combine($stateRoot, 'install', 'transaction.json')
        foreach ($case in @(
            @{ Profile = 'Standalone'; Existed = $true; Label = 'rollback of a failed upgrade' },
            @{ Profile = 'Standalone'; Existed = $false; Label = 'rollback of a failed first install' },
            @{ Profile = 'SecureClient'; Existed = $true; Label = 'Secure Client rollback' }
        )) {
            $existed = [bool]$case.Existed
            $label = [string]$case.Label
            Set-DefenseClawEnterpriseProfile -EnterpriseProfile $case.Profile
            Reset-TestHost
            [IO.File]::WriteAllText($layout.ManagedHooksLifecycleJournalPath, '{}', $utf8)
            $snapshot = [ordered]@{
                gateway_service = 'DefenseClawGateway'
                guardian_service = 'DefenseClawHookGuardian'
                core_hardening_certification = $false
                agent_application_control_attested = $false
                claude_effective_policy_verified = $false
                services = @(
                    [ordered]@{ name = 'DefenseClawGateway'; existed = $false },
                    [ordered]@{ name = 'DefenseClawHookGuardian'; existed = $false }
                )
                files = @(
                    [ordered]@{
                        path = $layout.GatewayPath
                        existed = $existed
                        backup = $(if ($existed) { $priorGateway } else { '' })
                    }
                )
            }
            [IO.File]::WriteAllText(
                $snapshotPath,
                ($snapshot | Microsoft.PowerShell.Utility\ConvertTo-Json -Depth 6),
                $utf8
            )
            $restoreError = ''
            try {
                $null = Restore-DefenseClawTransaction -SnapshotPath $snapshotPath -Layout $layout
            }
            catch {
                $restoreError = $_.Exception.Message
            }
            $calls = @($script:TestCalls) -join '|'
            if ($case.Profile -ceq 'SecureClient') {
                # Secure Client keeps the staged gateway: its failure ends
                # the recovery before any file is restored.
                if (-not $restoreError.Contains($relaxedHooks) -or
                    $calls -cne 'staged-gateway:restore|staged-gateway:retire' -or
                    @($script:DefenseClawRecoveryGatewayRuns).Count -ne 0 -or
                    $null -ne $script:DefenseClawRecoveryGatewayRefusal -or
                    [IO.File]::ReadAllText($layout.GatewayPath).Trim() -cne 'staged-gateway') {
                    $failures.Add("${label}: '$restoreError', calls $calls")
                }
                continue
            }
            if (-not [string]::IsNullOrEmpty($restoreError) -or
                $calls -cne 'staged-gateway:restore|staged-gateway:retire|setup-gateway:retire|cleanup:setup-gateway') {
                $failures.Add("${label}: '$restoreError', calls $calls")
            }
            $runs = @(Get-DefenseClawRecoveryGatewayRunRecords)
            if ($runs.Count -ne 1 -or [string]$runs[0].outcome -cne 'succeeded') {
                $failures.Add("${label}: recorded $($runs.Count) recovery gateway runs")
            }
            $present = [IO.File]::Exists($layout.GatewayPath)
            if ($existed -and
                (-not $present -or [IO.File]::ReadAllText($layout.GatewayPath).Trim() -cne 'prior-gateway')) {
                $failures.Add("${label}: <InstallRoot>\bin does not hold the prior release's gateway again")
            }
            if (-not $existed -and $present) {
                $failures.Add("${label}: the recovery gateway was left at <InstallRoot>\bin")
            }
        }
    }
    finally {
        Set-DefenseClawEnterpriseProfile -EnterpriseProfile $originalProfile
        Microsoft.PowerShell.Management\Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
    }
    return , $failures
} $modulePath $installerPath $ScratchRoot

if (@($failures).Count -gt 0) {
    foreach ($failure in $failures) {
        Microsoft.PowerShell.Utility\Write-Output "FAIL: $failure"
    }
    exit 1
}
Microsoft.PowerShell.Utility\Write-Output 'enterprise-standalone-recovery-gateway-smoke: OK'
