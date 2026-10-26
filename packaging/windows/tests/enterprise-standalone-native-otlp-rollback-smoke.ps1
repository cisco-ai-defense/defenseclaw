# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

# Regression for a managed Windows upgrade that reaches the guardian, removes
# a previous per-user native exporter, then rolls back. The transaction must
# restore the user files' bytes and ACLs and remove its new CAS state.

[CmdletBinding()]
param(
    [string]$ModulePath = '',
    [string]$ScratchRoot = [IO.Path]::GetTempPath(),
    [ValidateSet('All', 'Baseline', 'ExistingCas', 'Linked', 'Junction', 'Interrupted', 'Order')]
    [string]$Case = 'All'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $ModulePath) {
    $ModulePath = [IO.Path]::GetFullPath(
        (Join-Path $PSScriptRoot '..\DefenseClawEnterprise.psm1'))
}
$module = Import-Module -Name $ModulePath -Force -PassThru
$scratch = Join-Path $ScratchRoot ('native-otlp-rollback-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $scratch | Out-Null
try {
    & $module {
        param([string]$Scratch, [string]$SelectedCase, [string]$ModulePath)
        Set-DefenseClawEnterpriseProfile -EnterpriseProfile Standalone
        if ($SelectedCase -in @('All', 'Baseline')) {
        $userProfile = Join-Path $Scratch 'user'
        $otherProfile = Join-Path $Scratch 'user-owned'
        $stateRoot = Join-Path $Scratch 'state'
        $transaction = Join-Path $stateRoot 'transactions\test'
        New-Item -ItemType Directory -Force -Path $transaction | Out-Null
        $layout = @{ StateRoot = $stateRoot }
        $plan = [pscustomobject]@{
            manifest_sha256 = ('a' * 64)
            roots = @(
                [pscustomobject]@{
                    user_home = $userProfile
                    data_dir = (Join-Path $userProfile '.defenseclaw')
                    sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
                },
                [pscustomobject]@{
                    user_home = $otherProfile
                    data_dir = (Join-Path $otherProfile '.defenseclaw')
                    sid = 'S-1-5-21-1-2-3-1001'
                }
            )
        }
        $snapshotPath = Join-Path $transaction 'snapshot.json'
        [IO.File]::WriteAllText(
            $snapshotPath,
            # Upgrade validates its target plan without adding it to the
            # machine-root journal; the user-file preimage must stand alone.
            (@{ schema_version = 1 } | ConvertTo-Json -Depth 6),
            [Text.UTF8Encoding]::new($false))
        $paths = @(Get-DefenseClawUserNativeOTLPTransactionPaths `
                -UserHome $userProfile)
        $contents = @(
            "[otel.exporter.otlp-http]`nendpoint = 'http://127.0.0.1:19010/v1/logs'`n",
            '{"env":{"OTEL_EXPORTER_OTLP_ENDPOINT":"http://127.0.0.1:19010"}}',
            'fixture token contents'
        )
        $before = @()
        for ($index = 0; $index -lt 3; $index++) {
            New-Item -ItemType Directory -Force `
                -Path ([IO.Path]::GetDirectoryName($paths[$index])) | Out-Null
            [IO.File]::WriteAllText($paths[$index], $contents[$index])
            $item = Get-Item -LiteralPath $paths[$index]
            $item.CreationTimeUtc = [DateTime]::UtcNow.AddDays(-3)
            $item.LastWriteTimeUtc = [DateTime]::UtcNow.AddDays(-2)
            if ($index -eq 1) {
                $acl = Get-Acl -LiteralPath $paths[$index]
                $acl.SetAccessRuleProtection($true, $true)
                Set-Acl -LiteralPath $paths[$index] -AclObject $acl
            }
            $item = Get-Item -LiteralPath $paths[$index]
            $before += [pscustomobject]@{
                sha256 = (Get-FileHash -LiteralPath $paths[$index] `
                    -Algorithm SHA256).Hash.ToLowerInvariant()
                sddl = (Get-Acl -LiteralPath $paths[$index]).Sddl
                creation = $item.CreationTimeUtc
                modified = $item.LastWriteTimeUtc
            }
        }
        $otherPaths = @(Get-DefenseClawUserNativeOTLPTransactionPaths `
                -UserHome $otherProfile)
        foreach ($path in @($otherPaths[0], $otherPaths[1])) {
            New-Item -ItemType Directory -Force `
                -Path ([IO.Path]::GetDirectoryName($path)) | Out-Null
            [IO.File]::WriteAllText($path, 'user-owned setting before upgrade')
        }
        New-Item -ItemType Directory -Force `
            -Path ([IO.Path]::GetDirectoryName($otherPaths[2])) | Out-Null
        [IO.File]::WriteAllText($otherPaths[2], 'orphaned predecessor token')
        [IO.File]::WriteAllText($otherPaths[3], 'operator credential before upgrade')
        $orphanedTokenHash = (Get-FileHash -LiteralPath $otherPaths[2] `
            -Algorithm SHA256).Hash.ToLowerInvariant()
        $orphanedTokenAcl = (Get-Acl -LiteralPath $otherPaths[2]).Sddl
        Add-DefenseClawUserNativeOTLPTransactionSnapshot `
            -SnapshotPath $snapshotPath -Layout $layout -Plan $plan
        Remove-Item -LiteralPath $paths[0]
        [IO.File]::WriteAllText($paths[0], 'candidate Codex edit')
        [IO.File]::WriteAllText($paths[1], 'candidate Claude edit')
        Remove-Item -LiteralPath $paths[2]
        $codexAcl = Get-Acl -LiteralPath $paths[0]
        $codexAcl.SetAccessRuleProtection($true, $true)
        Set-Acl -LiteralPath $paths[0] -AclObject $codexAcl
        $claudeAcl = Get-Acl -LiteralPath $paths[1]
        $claudeAcl.SetAccessRuleProtection($false, $true)
        Set-Acl -LiteralPath $paths[1] -AclObject $claudeAcl
        foreach ($agent in @('.codex', '.claude')) {
            $cas = Join-Path (Join-Path $userProfile $agent) `
                '.defenseclaw-cas-state'
            New-Item -ItemType Directory -Path $cas | Out-Null
            [IO.File]::WriteAllBytes(
                (Join-Path $cas '.defenseclaw-v2-protocol.lock'),
                [byte[]]::new(0))
        }
        foreach ($path in @($otherPaths[0], $otherPaths[1])) {
            [IO.File]::WriteAllText($path, 'user-owned setting edited during upgrade')
        }
        Remove-Item -LiteralPath $otherPaths[2]
        [IO.File]::WriteAllText($otherPaths[3], 'operator credential edited during upgrade')
        Set-DefenseClawUserNativeOTLPTransactionPostimages `
            -SnapshotPath $snapshotPath -Layout $layout
        $snapshot = Get-Content -LiteralPath $snapshotPath -Raw |
            ConvertFrom-Json
        Restore-DefenseClawUserNativeOTLPTransactionSnapshot `
            -Snapshot $snapshot -SnapshotPath $snapshotPath -Layout $layout
        for ($index = 0; $index -lt 3; $index++) {
            $hash = (Get-FileHash -LiteralPath $paths[$index] `
                -Algorithm SHA256).Hash.ToLowerInvariant()
            $sddl = (Get-Acl -LiteralPath $paths[$index]).Sddl
            # The entries and every control flag but AutoInherited (AI),
            # which putting back an inheriting DACL sets (D: becomes D:AI).
            $aclRestored = Test-DefenseClawRestoredUserFileSDDL `
                -Actual $sddl -Expected $before[$index].sddl
            $item = Get-Item -LiteralPath $paths[$index]
            if ($hash -cne $before[$index].sha256 -or
                -not $aclRestored -or
                $item.CreationTimeUtc -ne $before[$index].creation -or
                $item.LastWriteTimeUtc -ne $before[$index].modified) {
                throw "rollback did not restore user file $index exactly (hash=$($hash -ceq $before[$index].sha256), acl=$aclRestored, sddl=$sddl, recorded=$($before[$index].sddl), created=$($item.CreationTimeUtc -eq $before[$index].creation), modified=$($item.LastWriteTimeUtc -eq $before[$index].modified))"
            }
        }
        if (Test-Path -LiteralPath $paths[3]) {
            throw 'rollback created an absent token'
        }
        foreach ($path in @($otherPaths[0], $otherPaths[1])) {
            if ([IO.File]::ReadAllText($path) -cne
                'user-owned setting edited during upgrade') {
                throw 'rollback overwrote a user-owned edit Guardian never changed'
            }
        }
        if (-not (Test-Path -LiteralPath $otherPaths[2] -PathType Leaf) -or
            (Get-FileHash -LiteralPath $otherPaths[2] -Algorithm SHA256).Hash.ToLowerInvariant() -cne $orphanedTokenHash -or
            -not (Test-DefenseClawRestoredUserFileSDDL `
                -Actual (Get-Acl -LiteralPath $otherPaths[2]).Sddl `
                -Expected $orphanedTokenAcl)) {
            throw 'rollback did not restore a revoked token without a CAS witness'
        }
        if ([IO.File]::ReadAllText($otherPaths[3]) -cne
            'operator credential edited during upgrade') {
            throw 'rollback overwrote an operator credential that Guardian did not revoke'
        }
        foreach ($agent in @('.codex', '.claude')) {
            if (Test-Path -LiteralPath (Join-Path `
                        (Join-Path $userProfile $agent) `
                        '.defenseclaw-cas-state')) {
                throw "rollback kept $agent CAS state"
            }
        }
        }
        function New-NativeOTLPFixture {
            param([string]$Name)
            $base = Join-Path $Scratch $Name
            $profile = Join-Path $base 'user'
            $state = Join-Path $base 'state'
            $transaction = Join-Path $state 'transactions\test'
            New-Item -ItemType Directory -Force -Path $transaction | Out-Null
            New-Item -ItemType Directory -Force -Path $profile | Out-Null
            $snapshot = Join-Path $transaction 'snapshot.json'
            [IO.File]::WriteAllText($snapshot,
                (@{ schema_version = 1 } | ConvertTo-Json -Depth 6),
                [Text.UTF8Encoding]::new($false))
            return @{
                profile = $profile
                snapshot = $snapshot
                layout = @{ StateRoot = $state }
                plan = [pscustomobject]@{
                    manifest_sha256 = ('b' * 64)
                    roots = @([pscustomobject]@{
                        user_home = $profile
                        data_dir = (Join-Path $profile '.defenseclaw')
                        sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
                    })
                }
            }
        }
        if ($SelectedCase -in @('All', 'ExistingCas')) {
            $fixture = New-NativeOTLPFixture -Name 'existing-cas'
            $codex = Join-Path $fixture.profile '.codex'
            $cas = Join-Path $codex '.defenseclaw-cas-state'
            New-Item -ItemType Directory -Force -Path $cas | Out-Null
            $config = Join-Path $codex 'config.toml'
            [IO.File]::WriteAllText($config, 'operator original')
            Add-DefenseClawUserNativeOTLPTransactionSnapshot `
                -SnapshotPath $fixture.snapshot -Layout $fixture.layout `
                -Plan $fixture.plan
            [IO.File]::WriteAllText($config, 'operator edited while upgrade is open')
            Set-DefenseClawUserNativeOTLPTransactionPostimages `
                -SnapshotPath $fixture.snapshot -Layout $fixture.layout
            $saved = Get-Content -LiteralPath $fixture.snapshot -Raw |
                ConvertFrom-Json
            Restore-DefenseClawUserNativeOTLPTransactionSnapshot `
                -Snapshot $saved -SnapshotPath $fixture.snapshot `
                -Layout $fixture.layout
            if ([IO.File]::ReadAllText($config) -cne
                'operator edited while upgrade is open') {
                throw 'pre-existing CAS state caused rollback to overwrite operator edit'
            }
            $changed = New-NativeOTLPFixture -Name 'existing-cas-changed'
            $changedCodex = Join-Path $changed.profile '.codex'
            $changedCas = Join-Path $changedCodex '.defenseclaw-cas-state'
            New-Item -ItemType Directory -Force -Path $changedCas | Out-Null
            $changedConfig = Join-Path $changedCodex 'config.toml'
            [IO.File]::WriteAllText($changedConfig, 'prior product exporter')
            Add-DefenseClawUserNativeOTLPTransactionSnapshot `
                -SnapshotPath $changed.snapshot -Layout $changed.layout `
                -Plan $changed.plan
            [IO.File]::WriteAllText($changedConfig, 'guardian cleanup postimage')
            [IO.File]::WriteAllText((Join-Path $changedCas 'transaction-witness'),
                'existing CAS directory changed by Guardian')
            Set-DefenseClawUserNativeOTLPTransactionPostimages `
                -SnapshotPath $changed.snapshot -Layout $changed.layout
            $changedSaved = Get-Content -LiteralPath $changed.snapshot -Raw |
                ConvertFrom-Json
            if ([string]$changedSaved.user_native_otlp_preimages.files[0].postimage_sha256 -cnotmatch
                '^[0-9a-f]{64}$') {
                throw 'Guardian postimage was not recorded for an existing CAS directory'
            }
            [IO.File]::WriteAllText($changedConfig, 'operator edit after Guardian')
            Restore-DefenseClawUserNativeOTLPTransactionSnapshot `
                -Snapshot $changedSaved -SnapshotPath $changed.snapshot `
                -Layout $changed.layout
            if ([IO.File]::ReadAllText($changedConfig) -cne
                'operator edit after Guardian') {
                throw 'rollback overwrote a user edit after the transaction postimage'
            }
            $nativeSecurity = Initialize-DefenseClawNativeSecurity
            $backup = Join-Path (Join-Path $changed.layout.StateRoot `
                'transactions\test') 'native-otlp-000.bak'
            $staleRestoreRefused = $false
            try {
                [void]$nativeSecurity::RestoreUserFileNoFollow(
                    $changedConfig,
                    [IO.File]::ReadAllBytes($backup),
                    [string]$changedSaved.user_native_otlp_preimages.files[0].security_descriptor,
                    [IO.File]::GetCreationTimeUtc($backup),
                    [IO.File]::GetLastWriteTimeUtc($backup),
                    [string]$changedSaved.user_native_otlp_preimages.files[0].postimage_sha256)
            }
            catch { $staleRestoreRefused = $true }
            if (-not $staleRestoreRefused -or
                [IO.File]::ReadAllText($changedConfig) -cne
                    'operator edit after Guardian') {
                throw 'handle-bound rollback overwrote a changed postimage'
            }
            $missing = Join-Path $changedCodex 'missing-config.toml'
            $missingRestoreRefused = $false
            try {
                [void]$nativeSecurity::RestoreUserFileNoFollow(
                    $missing,
                    [IO.File]::ReadAllBytes($backup),
                    [string]$changedSaved.user_native_otlp_preimages.files[0].security_descriptor,
                    [IO.File]::GetCreationTimeUtc($backup),
                    [IO.File]::GetLastWriteTimeUtc($backup),
                    [string]$changedSaved.user_native_otlp_preimages.files[0].postimage_sha256)
            }
            catch { $missingRestoreRefused = $true }
            if (-not $missingRestoreRefused -or
                (Test-Path -LiteralPath $missing)) {
                throw 'rollback created a file after a captured postimage disappeared'
            }
            $positive = New-NativeOTLPFixture -Name 'existing-cas-product'
            $positiveCodex = Join-Path $positive.profile '.codex'
            $positiveCas = Join-Path $positiveCodex '.defenseclaw-cas-state'
            New-Item -ItemType Directory -Force -Path $positiveCas | Out-Null
            $positiveConfig = Join-Path $positiveCodex 'config.toml'
            [IO.File]::WriteAllText($positiveConfig, 'prior native exporter')
            Add-DefenseClawUserNativeOTLPTransactionSnapshot `
                -SnapshotPath $positive.snapshot -Layout $positive.layout `
                -Plan $positive.plan
            [IO.File]::WriteAllText($positiveConfig, 'guardian removed exporter')
            [IO.File]::WriteAllText((Join-Path $positiveCas 'transaction-witness'),
                'Guardian changed the existing CAS directory')
            Set-DefenseClawUserNativeOTLPTransactionPostimages `
                -SnapshotPath $positive.snapshot -Layout $positive.layout
            $positiveSaved = Get-Content -LiteralPath $positive.snapshot -Raw |
                ConvertFrom-Json
            Restore-DefenseClawUserNativeOTLPTransactionSnapshot `
                -Snapshot $positiveSaved -SnapshotPath $positive.snapshot `
                -Layout $positive.layout
            if ([IO.File]::ReadAllText($positiveConfig) -cne
                'prior native exporter') {
                throw 'rollback did not restore a proven transaction postimage'
            }
        }
        if ($SelectedCase -in @('All', 'Linked')) {
            $fixture = New-NativeOTLPFixture -Name 'linked'
            $outside = Join-Path $Scratch 'linked-outside'
            New-Item -ItemType Directory -Force -Path $outside | Out-Null
            [IO.File]::WriteAllText((Join-Path $outside 'config.toml'),
                'outside Codex stays unchanged')
            [IO.File]::WriteAllText((Join-Path $outside 'settings.json'),
                'outside settings stay unchanged')
            $codex = Join-Path $fixture.profile '.codex'
            New-Item -ItemType Directory -Path $codex | Out-Null
            New-Item -ItemType SymbolicLink -Path (Join-Path $codex 'config.toml') `
                -Target (Join-Path $outside 'config.toml') | Out-Null
            New-Item -ItemType Junction -Path (Join-Path $fixture.profile '.claude') `
                -Target $outside | Out-Null
            Add-DefenseClawUserNativeOTLPTransactionSnapshot `
                -SnapshotPath $fixture.snapshot -Layout $fixture.layout `
                -Plan $fixture.plan
            $saved = Get-Content -LiteralPath $fixture.snapshot -Raw |
                ConvertFrom-Json
            if ($saved.user_native_otlp_preimages.files[0].captured -ne $false -or
                $saved.user_native_otlp_preimages.files[1].captured -ne $false -or
                $saved.user_native_otlp_preimages.files[2].captured -ne $true -or
                $saved.user_native_otlp_preimages.files[2].existed -ne $false) {
                throw 'linked and absent user paths were not captured distinctly'
            }
            $skipped = Get-Variable `
                -Name DefenseClawUserNativeOTLPCaptureSkipped `
                -Scope Script -ErrorAction SilentlyContinue
            if ($null -eq $skipped -or @($skipped.Value).Count -ne 2) {
                throw 'linked user files were not reported to Setup'
            }
            Restore-DefenseClawUserNativeOTLPTransactionSnapshot `
                -Snapshot $saved -SnapshotPath $fixture.snapshot `
                -Layout $fixture.layout
            if (@($script:DefenseClawRollbackLeftovers | Where-Object {
                $_ -match '^native OTLP user rollback: ' -and
                $_ -match 'preimage could not be captured'
            }).Count -lt 2) {
                throw 'uncaptured linked user files were not tagged on rollback'
            }
            if ([IO.File]::ReadAllText((Join-Path $outside 'config.toml')) -cne
                    'outside Codex stays unchanged' -or
                [IO.File]::ReadAllText((Join-Path $outside 'settings.json')) -cne
                'outside settings stay unchanged') {
                throw 'linked agent target changed during capture or rollback'
            }
        }
        if ($SelectedCase -in @('All', 'Junction')) {
            $fixture = New-NativeOTLPFixture -Name 'junction'
            $codex = Join-Path $fixture.profile '.codex'
            $claude = Join-Path $fixture.profile '.claude'
            New-Item -ItemType Directory -Force -Path $codex, $claude | Out-Null
            [IO.File]::WriteAllText((Join-Path $codex 'config.toml'), 'prior Codex')
            [IO.File]::WriteAllText((Join-Path $claude 'settings.json'), 'prior Claude')
            $oldCas = Join-Path $codex '.defenseclaw-cas-state'
            New-Item -ItemType Directory -Path $oldCas | Out-Null
            Add-DefenseClawUserNativeOTLPTransactionSnapshot `
                -SnapshotPath $fixture.snapshot -Layout $fixture.layout `
                -Plan $fixture.plan
            $outside = Join-Path $Scratch 'junction-outside'
            New-Item -ItemType Directory -Force -Path $outside | Out-Null
            $outsideFile = Join-Path $outside 'config.toml'
            [IO.File]::WriteAllText($outsideFile, 'outside Codex stays unchanged')
            $outsideAcl = (Get-Acl -LiteralPath $outsideFile).Sddl
            Move-Item -LiteralPath $codex -Destination ($codex + '-saved')
            New-Item -ItemType Junction -Path $codex -Target $outside | Out-Null
            [IO.File]::WriteAllText((Join-Path $claude 'settings.json'),
                'candidate Claude')
            $newCas = Join-Path $claude '.defenseclaw-cas-state'
            New-Item -ItemType Directory -Path $newCas | Out-Null
            [IO.File]::WriteAllBytes(
                (Join-Path $newCas '.defenseclaw-v2-protocol.lock'),
                [byte[]]::new(0))
            Set-DefenseClawUserNativeOTLPTransactionPostimages `
                -SnapshotPath $fixture.snapshot -Layout $fixture.layout
            $saved = Get-Content -LiteralPath $fixture.snapshot -Raw |
                ConvertFrom-Json
            Restore-DefenseClawUserNativeOTLPTransactionSnapshot `
                -Snapshot $saved -SnapshotPath $fixture.snapshot `
                -Layout $fixture.layout
            $nativeSecurity = Initialize-DefenseClawNativeSecurity
            $backup = Join-Path (Join-Path $fixture.layout.StateRoot `
                'transactions\test') 'native-otlp-000.bak'
            $refused = $false
            try {
                [void]$nativeSecurity::RestoreUserFileNoFollow(
                    (Join-Path $codex 'config.toml'),
                    [Text.Encoding]::UTF8.GetBytes('must not reach outside'),
                    [string]$saved.user_native_otlp_preimages.files[0].security_descriptor,
                    [IO.File]::GetCreationTimeUtc($backup),
                    [IO.File]::GetLastWriteTimeUtc($backup),
                    $null)
            }
            catch {
                $refused = $true
            }
            if (-not $refused) {
                throw 'native user-file restore followed a junction'
            }
            if ([IO.File]::ReadAllText($outsideFile) -cne
                    'outside Codex stays unchanged' -or
                (Get-Acl -LiteralPath $outsideFile).Sddl -cne $outsideAcl -or
                [IO.File]::ReadAllText((Join-Path $claude 'settings.json')) -cne
                    'prior Claude' -or
                @($script:DefenseClawRollbackLeftovers | Where-Object {
                    $_ -match '\.codex'
                }).Count -eq 0) {
                throw 'junction rollback changed outside profile or stopped early'
            }
        }
        if ($SelectedCase -in @('All', 'Interrupted')) {
            $fixture = New-NativeOTLPFixture -Name 'interrupted'
            $codex = Join-Path $fixture.profile '.codex'
            New-Item -ItemType Directory -Force -Path $codex | Out-Null
            $config = Join-Path $codex 'config.toml'
            [IO.File]::WriteAllText($config, 'prior config')
            Add-DefenseClawUserNativeOTLPTransactionSnapshot `
                -SnapshotPath $fixture.snapshot -Layout $fixture.layout `
                -Plan $fixture.plan
            [IO.File]::WriteAllText($config, 'candidate edit')
            $cas = Join-Path $codex '.defenseclaw-cas-state'
            New-Item -ItemType Directory -Path $cas | Out-Null
            [IO.File]::WriteAllBytes(
                (Join-Path $cas '.defenseclaw-v2-protocol.lock'),
                [byte[]]::new(0))
            [IO.File]::WriteAllText((Join-Path $cas '.intent'),
                'interrupted compare-and-swap receipt')
            Set-DefenseClawUserNativeOTLPTransactionPostimages `
                -SnapshotPath $fixture.snapshot -Layout $fixture.layout
            $saved = Get-Content -LiteralPath $fixture.snapshot -Raw |
                ConvertFrom-Json
            Restore-DefenseClawUserNativeOTLPTransactionSnapshot `
                -Snapshot $saved -SnapshotPath $fixture.snapshot `
                -Layout $fixture.layout
            if ([IO.File]::ReadAllText($config) -cne 'prior config' -or
                -not (Test-Path -LiteralPath (Join-Path $cas '.intent')) -or
                @($script:DefenseClawRollbackLeftovers | Where-Object {
                    $_ -match '\.intent|compare-and-swap state'
                }).Count -eq 0) {
                throw 'interrupted CAS stopped rollback or lost its leftover'
            }
        }
        if ($SelectedCase -in @('All', 'Order')) {
            # A malformed per-user receipt must be handled only after the
            # machine files and the previous services have been restored.
            # Both the direct and managed-hooks deferred restart paths matter.
            $tokens = $null
            $errors = $null
            $ast = [Management.Automation.Language.Parser]::ParseFile(
                $ModulePath, [ref]$tokens, [ref]$errors)
            foreach ($name in @(
                    'Restore-DefenseClawTransaction',
                    'Restore-DefenseClawTransactionWithManagedHooksRollback')) {
                $body = $ast.Find({
                    param($node)
                    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
                        $node.Name -ceq $name
                }, $true).Body.Extent.Text
                $machine = $body.LastIndexOf('Start-DefenseClawTransactionServices')
                $user = $body.LastIndexOf('Invoke-DefenseClawUserNativeOTLPRestoreBestEffort')
                if ($machine -lt 0 -or $user -le $machine -or
                    $body.Contains('Restore-DefenseClawUserNativeOTLPTransactionSnapshot')) {
                    throw "$name restores user files before the machine services"
                }
            }
            $bad = [pscustomobject]@{
                user_native_otlp_preimages = [pscustomobject]@{
                    schema_version = -1
                }
            }
            $script:DefenseClawRollbackLeftovers = @()
            Invoke-DefenseClawUserNativeOTLPRestoreBestEffort `
                -Snapshot $bad -SnapshotPath (Join-Path $Scratch 'bad.json') `
                -Layout @{ StateRoot = $Scratch }
            if (@($script:DefenseClawRollbackLeftovers).Count -ne 1 -or
                $script:DefenseClawRollbackLeftovers[0] -notmatch
                    'invalid user native OTLP rollback preimages') {
                throw 'unsettled user rollback was not reported'
            }
        }
    } $scratch $Case $ModulePath
    'PASS: native OTLP user preimages restored'
}
finally {
    Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue
}
'enterprise-standalone-native-otlp-rollback-smoke: OK'
