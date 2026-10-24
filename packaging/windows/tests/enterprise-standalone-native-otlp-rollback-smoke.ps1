# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

# Regression for a managed Windows upgrade that reaches the guardian, removes
# a previous per-user native exporter, then rolls back. The transaction must
# restore the user files' bytes and ACLs and remove its new CAS state.

[CmdletBinding()]
param(
    [string]$ModulePath = [IO.Path]::GetFullPath(
        (Join-Path $PSScriptRoot '..\DefenseClawEnterprise.psm1')),
    [string]$ScratchRoot = [IO.Path]::GetTempPath(),
    [ValidateSet('All', 'Baseline', 'Linked', 'Junction', 'Interrupted')]
    [string]$Case = 'All'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$module = Import-Module -Name $ModulePath -Force -PassThru
$scratch = Join-Path $ScratchRoot ('native-otlp-rollback-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $scratch | Out-Null
try {
    & $module {
        param([string]$Scratch, [string]$SelectedCase)
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
        $snapshot = Get-Content -LiteralPath $snapshotPath -Raw |
            ConvertFrom-Json
        Restore-DefenseClawUserNativeOTLPTransactionSnapshot `
            -Snapshot $snapshot -SnapshotPath $snapshotPath -Layout $layout
        for ($index = 0; $index -lt 3; $index++) {
            $hash = (Get-FileHash -LiteralPath $paths[$index] `
                -Algorithm SHA256).Hash.ToLowerInvariant()
            $sddl = (Get-Acl -LiteralPath $paths[$index]).Sddl
            $item = Get-Item -LiteralPath $paths[$index]
            if ($hash -cne $before[$index].sha256 -or
                $sddl -cne $before[$index].sddl -or
                $item.CreationTimeUtc -ne $before[$index].creation -or
                $item.LastWriteTimeUtc -ne $before[$index].modified) {
                throw "rollback did not restore user file $index exactly (hash=$($hash -ceq $before[$index].sha256), acl=$($sddl -ceq $before[$index].sddl), created=$($item.CreationTimeUtc -eq $before[$index].creation), modified=$($item.LastWriteTimeUtc -eq $before[$index].modified))"
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
            (Get-Acl -LiteralPath $otherPaths[2]).Sddl -cne $orphanedTokenAcl) {
            throw 'rollback did not restore a revoked token without a CAS witness'
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
            Restore-DefenseClawUserNativeOTLPTransactionSnapshot `
                -Snapshot $saved -SnapshotPath $fixture.snapshot `
                -Layout $fixture.layout
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
                    [IO.File]::GetLastWriteTimeUtc($backup))
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
    } $scratch $Case
    'PASS: native OTLP user preimages restored'
}
finally {
    Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue
}
'enterprise-standalone-native-otlp-rollback-smoke: OK'
