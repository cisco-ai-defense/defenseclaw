# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

# Regression for a managed Windows upgrade that reaches the guardian, removes
# a previous per-user native exporter, then rolls back. The transaction must
# restore the user files' bytes and ACLs and remove its new CAS state.

[CmdletBinding()]
param(
    [string]$ModulePath = [IO.Path]::GetFullPath(
        (Join-Path $PSScriptRoot '..\DefenseClawEnterprise.psm1')),
    [string]$ScratchRoot = [IO.Path]::GetTempPath()
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$module = Import-Module -Name $ModulePath -Force -PassThru
$scratch = Join-Path $ScratchRoot ('native-otlp-rollback-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $scratch | Out-Null
try {
    & $module {
        param([string]$Scratch)
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
                throw "rollback did not restore user file $index exactly"
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
    } $scratch
    'PASS: native OTLP user preimages restored'
}
finally {
    Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue
}
