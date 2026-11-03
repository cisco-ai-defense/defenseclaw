# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 7.0

[CmdletBinding()]
param([string]$ModulePath = ([IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\DefenseClawEnterprise.psm1'))))
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$tokens = $null
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($ModulePath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -ne 0) { throw "module parse failed: $($parseErrors[0].Message)" }

# Execute the production registry snapshot/restore functions against one
# temporary current-user key. The only substitutions are the registry root
# and path: no system or Claude policy is changed by this smoke test.
$testKey = 'SOFTWARE\DefenseClaw-Cowork-Smoke-' + [Guid]::NewGuid().ToString('N')
foreach ($name in @('Get-DefenseClawCoworkRegistrySnapshot', 'Restore-DefenseClawCoworkRegistrySnapshot')) {
    $definition = $ast.Find({param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name
    }, $true)
    if ($null -eq $definition) { throw "missing Cowork lifecycle function $name" }
    $source = $definition.Extent.Text.Replace(
        '[Microsoft.Win32.RegistryHive]::LocalMachine', '[Microsoft.Win32.RegistryHive]::CurrentUser'
    ).Replace('SOFTWARE\Policies\Claude', $testKey)
    . ([ScriptBlock]::Create($source))
}
$base = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
    [Microsoft.Win32.RegistryHive]::CurrentUser, [Microsoft.Win32.RegistryView]::Registry64)
try {
    $key = $base.CreateSubKey($testKey, $true)
    try {
        $key.SetValue('unrelatedPolicy', 'keep', [Microsoft.Win32.RegistryValueKind]::String)
        foreach ($kind in @('String', 'ExpandString', 'DWord', 'QWord', 'Binary', 'MultiString', 'None')) {
            $value = switch ($kind) {
                'String' { 'C:\Program Files\Claude\edr-integration\defenseclaw-cowork-amd64.tar.gz' }
                'ExpandString' { '%ProgramFiles%\existing' }
                'DWord' { [int]37 }
                'QWord' { [long]4294967300 }
                'Binary' { ,([byte[]]@(1, 2, 3)) }
                'MultiString' { ,([string[]]@('first', 'second')) }
                'None' { ,([byte[]]@(4, 5)) }
            }
            $registryKind = [Enum]::Parse([Microsoft.Win32.RegistryValueKind], $kind)
            $key.SetValue('coworkEDRIntegration', $value, $registryKind)
            $key.DeleteValue('coworkEDRIntegrationVendor', $false)
            $snapshot = @(Get-DefenseClawCoworkRegistrySnapshot)
            if ($snapshot.Count -ne 2 -or $snapshot[0] -is [array] -or $snapshot[1] -is [array]) {
                throw 'Cowork snapshot is not exactly two flat registry entries'
            }
            $json = ConvertTo-Json -InputObject $snapshot -Depth 8 -Compress
            $roundtrip = ConvertFrom-Json -InputObject $json -NoEnumerate
            $key.SetValue('coworkEDRIntegration', 'changed', [Microsoft.Win32.RegistryValueKind]::String)
            $key.SetValue('coworkEDRIntegrationVendor', 'cisco', [Microsoft.Win32.RegistryValueKind]::String)
            Restore-DefenseClawCoworkRegistrySnapshot -Entries $roundtrip
            if ($key.GetValueKind('coworkEDRIntegration') -ne $registryKind) { throw "registry type $kind was not restored" }
            $restored = $key.GetValue('coworkEDRIntegration', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            if ((ConvertTo-Json -InputObject $restored -Compress) -cne (ConvertTo-Json -InputObject $value -Compress)) {
                throw "registry value $kind was not restored"
            }
            if (@($key.GetValueNames()) -contains 'coworkEDRIntegrationVendor') { throw 'absent registry preimage was not restored' }
            if ($key.GetValue('unrelatedPolicy') -cne 'keep') { throw 'unrelated registry policy was changed' }
        }
    }
    finally { $key.Dispose() }
}
finally { $base.DeleteSubKeyTree($testKey, $false); $base.Dispose() }

# The production custody check keeps writer/owner validation for a missing
# Users read ACE, but lets the transaction snapshot an owned file before
# repair restores that read ACE. Unowned files still require it.
$definition = $ast.Find({param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Assert-DefenseClawCoworkPublicPath'
}, $true)
. ([ScriptBlock]::Create($definition.Extent.Text))
$script:SystemSID = 'S-1-5-18'
$script:AdministratorsSID = 'S-1-5-32-544'
$script:TrustedInstallerSID = 'S-1-5-80-1-2-3-4-5'
$script:UsersSID = 'S-1-5-32-545'
function Assert-DefenseClawNoReparsePath { param([string]$Path) }
function Assert-DefenseClawTrustedAncestor { param([string]$Path, [switch]$Strict)
    if (-not $Strict) { throw 'Cowork ancestor trust must remain strict' }
}
$script:requireUsersRead = $true
function Assert-DefenseClawPathAcl {
    param([string]$Path, [string[]]$AllowedWriterSIDs, [string[]]$AllowedReaderSIDs,
        [hashtable]$RequiredRights, [switch]$AllowUsersRead, [switch]$AllowInheritance, [switch]$RejectUntrustedRead)
    if (($AllowedWriterSIDs -contains $script:UsersSID) -or -not $RejectUntrustedRead) { throw 'reader repair loosened custody checks' }
    if ($RequiredRights.ContainsKey($script:UsersSID) -ne $script:requireUsersRead) { throw 'reader repair did not distinguish owned from unowned files' }
}
$scratch = [IO.Path]::GetTempFileName()
try {
    Assert-DefenseClawCoworkPublicPath -Path $scratch
    $script:requireUsersRead = $false
    Assert-DefenseClawCoworkPublicPath -Path $scratch -AllowReaderRepair
}
finally { [IO.File]::Delete($scratch) }
'Cowork registry snapshot roundtrip and owned reader repair checks passed'

# Forced uninstall must capture trusted ownership before it renames StateRoot,
# and retire external Cowork artifacts only after that rename succeeds.
$definition = $ast.Find({param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Invoke-DefenseClawForcedUninstallPreparation'
}, $true)
. ([ScriptBlock]::Create($definition.Extent.Text))
function Test-DefenseClawStandaloneProfile { return $true }
function Get-DefenseClawEnumeratorServiceName { param([string]$GuardianServiceName) return 'test-enumerator' }
function Assert-DefenseClawOwnedServiceOrAbsent {
    param([switch]$Strict, [string]$Name, [string]$ExpectedGatewayPath, [string]$ExpectedManifestPath,
        [switch]$Guardian, [switch]$Enumerator, [string]$ExpectedSensorHelperImage, [switch]$SensorHelper)
}
function Get-DefenseClawSensorHelperImage { param([hashtable]$Layout, [string]$GatewayServiceName) return 'test-helper' }
function Test-DefenseClawServiceExists { param([string]$Name) return $false }
function Exit-DefenseClawPurgeBundleLock { }
function Get-DefenseClawCoworkOwnership {
    param([hashtable]$Layout)
    if (-not [IO.Directory]::Exists($Layout.StateRoot)) { throw 'ownership was read after StateRoot moved' }
    return @{schema_version=1; marker='authenticated-before-move'}
}
$script:forcedCoworkCalls = 0
function Invoke-DefenseClawCoworkDelivery {
    param([hashtable]$Layout, [string]$GatewayServiceName, [AllowEmptyString()][string]$SnapshotPath,
        [switch]$Remove, [Collections.IDictionary]$OwnershipRecord, [switch]$PreservePrivateState)
    if (-not $Remove -or -not $PreservePrivateState -or $SnapshotPath -cne '' -or
        $OwnershipRecord.marker -cne 'authenticated-before-move' -or [IO.Directory]::Exists($Layout.StateRoot)) {
        throw 'forced Cowork removal lost provenance or ran before a successful state rename'
    }
    $script:forcedCoworkCalls++
}
$forceScratch = [IO.Path]::Combine([IO.Path]::GetTempPath(), 'dc-cowork-force-' + [Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($forceScratch)
$layout = @{StateRoot=$forceScratch; GatewayPath='test-gateway'; ManifestPath='test-manifest'; SensorHelperPath='test-helper'; SensorHelperServiceName='test-helper-service'}
try {
    $prepared = Invoke-DefenseClawForcedUninstallPreparation -Layout $layout -GatewayServiceName 'test-gateway' -GuardianServiceName 'test-guardian'
    if ($script:forcedCoworkCalls -ne 1 -or -not [IO.Directory]::Exists($prepared.moved_state_root)) {
        throw 'forced uninstall did not retire Cowork after authenticating and moving private state'
    }
    [IO.Directory]::Delete($prepared.moved_state_root)
}
finally { if ([IO.Directory]::Exists($forceScratch)) { [IO.Directory]::Delete($forceScratch) } }
'Cowork forced removal provenance and ordering checks passed'
