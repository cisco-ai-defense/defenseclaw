# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 5.1

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$WarningPreference = 'SilentlyContinue'

$modulePath = [IO.Path]::GetFullPath(
    (Microsoft.PowerShell.Management\Join-Path $PSScriptRoot '..\DefenseClawEnterprise.psm1')
)
Microsoft.PowerShell.Core\Import-Module -Name $modulePath -Force
$module = Microsoft.PowerShell.Core\Get-Module DefenseClawEnterprise
if ($null -eq $module) {
    throw 'DefenseClaw enterprise module was not imported'
}

$result = & $module {
    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'
    $script:NativeCleanupCalls = [Collections.Generic.List[object]]::new()

    function script:Assert-DefenseClawSourceDescriptorCurrent {
        param([Parameter(Mandatory)][hashtable]$Source)
        if ([string]::IsNullOrWhiteSpace([string]$Source.path)) {
            throw 'native cleanup test source is empty'
        }
        return $Source
    }
    function script:Invoke-DefenseClawNamespaceRootCleanup {
        param(
            [Parameter(Mandatory)][hashtable]$Source,
            [Parameter(Mandatory)][Collections.IDictionary]$Request,
            [Parameter(Mandatory)][string]$RequestPath,
            [Parameter(Mandatory)][string]$ReportPath,
            [Parameter(Mandatory)][string]$ExchangeDirectory,
            [Parameter(Mandatory)][bool]$ExpectedRootPresent,
            [switch]$AllowAbsentRoot,
            [switch]$ExpectSealOnly
        )
        $script:NativeCleanupCalls.Add([pscustomobject]@{
            source = [string]$Source.path
            request = $Request
            expect_seal_only = [bool]$ExpectSealOnly
            allow_absent_root = [bool]$AllowAbsentRoot
        })
        $removed = [string]$Request.operation -ceq 'delete'
        $report = [pscustomobject]@{
            schema_version = 1
            ok = $true
            root = [string]$Request.root
            expected_identity = [string]$Request.expected_identity
            removed = $removed
            entries_removed = $(if ($removed) { 1 } else { 0 })
            error = ''
        }
        [void](Assert-DefenseClawNamespaceRootCleanupReport `
            -Report $report `
            -ExpectedRoot ([string]$Request.root) `
            -ExpectedIdentity ([string]$Request.expected_identity) `
            -ValidateOnly:$false `
            -ExpectedRootPresent $ExpectedRootPresent `
            -AllowAbsentRoot:$AllowAbsentRoot `
            -ExpectSealOnly:$ExpectSealOnly)
        return $report
    }

    $layout = @{
        InstallRoot = 'C:\Program Files\Cisco\Cisco Secure Client\DefenseClaw'
        LifecycleLockDirectory = Microsoft.PowerShell.Management\Join-Path `
            ([IO.Path]::GetTempPath()) `
            ('dcut-native-contract-' + [Guid]::NewGuid().ToString('N'))
        PurgeScopeSHA256 = ('0' * 64)
    }
    $source = @{
        path = 'C:\Program Files\Cisco\Cisco Secure Client\AVC\defenseclaw\DefenseClawSetup-Enterprise-x64.exe'
    }
    $identity = '00000001:0000000000000001'
    $sid = 'S-1-5-80-1-2-3-4-5'

    [void](Invoke-DefenseClawUninstallInstallRootNativeCleanup `
        -Layout $layout `
        -Source $source `
        -ExpectedIdentity $identity `
        -GatewayServiceSID $sid `
        -Operation seal_only)
    [void](Invoke-DefenseClawUninstallInstallRootNativeCleanup `
        -Layout $layout `
        -Source $source `
        -ExpectedIdentity $identity `
        -GatewayServiceSID $sid `
        -Operation delete)
    if ($script:NativeCleanupCalls.Count -ne 2) {
        throw 'native install cleanup did not invoke both lifecycle phases'
    }
    $seal = $script:NativeCleanupCalls[0]
    $delete = $script:NativeCleanupCalls[1]
    if ([string]$seal.request.mode -cne 'uninstall_install_purge' -or
        [string]$seal.request.operation -cne 'seal_only' -or
        [string]$seal.request.expected_identity -cne $identity -or
        [string]$seal.request.gateway_service_sid -cne $sid -or
        -not [bool]$seal.expect_seal_only -or
        [bool]$seal.allow_absent_root -or
        [string]$delete.request.operation -cne 'delete' -or
        [bool]$delete.expect_seal_only -or
        -not [bool]$delete.allow_absent_root) {
        throw 'native install cleanup request or report contract drifted'
    }

    $insideRejected = $false
    try {
        [void](Invoke-DefenseClawUninstallInstallRootNativeCleanup `
            -Layout $layout `
            -Source @{path = ($layout.InstallRoot + '\bin\defenseclaw.exe')} `
            -ExpectedIdentity $identity `
            -GatewayServiceSID $sid `
            -Operation delete)
    }
    catch {
        $insideRejected = $_.Exception.Message -like '*external executable*'
    }
    if (-not $insideRejected -or $script:NativeCleanupCalls.Count -ne 2) {
        throw 'native install cleanup accepted a helper inside its deletion root'
    }

    $idempotent = [pscustomobject]@{
        schema_version = 1
        ok = $true
        root = $layout.InstallRoot
        expected_identity = $identity
        removed = $false
        entries_removed = 0
        error = ''
    }
    [void](Assert-DefenseClawNamespaceRootCleanupReport `
        -Report $idempotent `
        -ExpectedRoot $layout.InstallRoot `
        -ExpectedIdentity $identity `
        -ValidateOnly:$false `
        -ExpectedRootPresent $true `
        -AllowAbsentRoot)

    # A fresh uninstall tombstone carries the precommit StateRoot inode. A
    # postcommit ACL denial must not force an ordinary root security open just
    # to publish the authenticated purge intent.
    function script:Get-DefenseClawManagedServiceNames {
        param([string]$GatewayServiceName, [string]$GuardianServiceName)
        return @()
    }
    function script:Test-DefenseClawServiceExists {
        param([string]$Name)
        return $false
    }
    function script:Get-DefenseClawDeploymentMetadata {
        param([hashtable]$Layout, [switch]$Required)
        return [pscustomobject]@{
            installed = $false
            state_root_identity = $identity
        }
    }
    function script:Assert-DefenseClawMetadataIdentity {
        param($Metadata, [string]$GatewayServiceName, [string]$GuardianServiceName)
    }
    function script:Test-DefenseClawMetadataInstalled {
        param($Metadata)
        return $false
    }
    function script:Get-DefenseClawManagedHookContractCleanupReceipt {
        param(
            [hashtable]$Layout,
            [string]$GatewayServiceName,
            [string]$GuardianServiceName,
            $Metadata
        )
        return [pscustomobject]@{
            phase = 'finalized'
            identity_sha256 = ('1' * 64)
        }
    }
    function script:Get-DefenseClawStatePurgeIntent {
        param(
            [hashtable]$Layout,
            [string]$GatewayServiceName,
            [string]$GuardianServiceName,
            [switch]$Required
        )
        return $script:NativeContractPurgeIntent
    }
    function script:Write-DefenseClawStatePurgeIntentAtomic {
        param([string]$Value, [hashtable]$Layout)
        $script:NativeContractPurgeIntent = $Value |
            Microsoft.PowerShell.Utility\ConvertFrom-Json
    }
    function script:Initialize-DefenseClawNativeSecurity {
        throw 'unexpected ordinary StateRoot security snapshot'
    }
    $intentDirectory = [IO.Path]::GetFullPath(
        (Microsoft.PowerShell.Management\Join-Path `
            ([IO.Path]::GetTempPath()) `
            ('dcut-native-intent-' + [Guid]::NewGuid().ToString('N')))
    )
    $tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
    if (-not $intentDirectory.StartsWith(
            $tempRoot + '\',
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw 'native intent fixture escaped the temporary directory'
    }
    [void](Microsoft.PowerShell.Management\New-Item `
        -ItemType Directory `
        -Path $intentDirectory)
    try {
        $metadataPath = Microsoft.PowerShell.Management\Join-Path `
            $intentDirectory 'deployment.json'
        [IO.File]::WriteAllText($metadataPath, '{"fixture":true}')
        $intentLayout = @{
            InstallRoot = (Microsoft.PowerShell.Management\Join-Path `
                $intentDirectory 'InstallRoot')
            StateRoot = (Microsoft.PowerShell.Management\Join-Path `
                $intentDirectory 'StateRoot')
            PendingPath = (Microsoft.PowerShell.Management\Join-Path `
                $intentDirectory 'pending.json')
            ManagedHooksTeardownJournalPath =
                (Microsoft.PowerShell.Management\Join-Path `
                    $intentDirectory 'teardown.json')
            MetadataPath = $metadataPath
            PurgeScopeSHA256 = ('0' * 64)
            CertificationCodexHome = ''
            CoreHardeningCertification = $false
        }
        $script:NativeContractPurgeIntent = $null
        $intent = Publish-DefenseClawStatePurgeIntent `
            -Layout $intentLayout `
            -GatewayServiceName DefenseClawGateway `
            -GuardianServiceName DefenseClawHookGuardian
        if ([string]$intent.state_root_identity -cne $identity) {
            throw 'purge intent did not use the recorded StateRoot identity'
        }
    }
    finally {
        Microsoft.PowerShell.Management\Remove-Item `
            -LiteralPath $intentDirectory `
            -Recurse `
            -Force `
            -ErrorAction Stop
    }

    return [pscustomobject]@{
        schema_version = 1
        ok = $true
        seal_and_delete_bound = $true
        internal_helper_rejected = $insideRejected
        absent_delete_idempotent = $true
        recorded_state_identity_used = $true
    }
}

$result | Microsoft.PowerShell.Utility\ConvertTo-Json -Compress
