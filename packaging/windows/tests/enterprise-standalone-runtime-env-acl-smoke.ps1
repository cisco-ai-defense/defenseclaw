# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

param([string]$ModulePath)

$ErrorActionPreference = 'Stop'
if (-not $ModulePath) {
    $ModulePath = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\DefenseClawEnterprise.psm1'))
}
$source = [IO.File]::ReadAllText($ModulePath)
$begin = $source.IndexOf('function Set-DefenseClawManagedAcls {', [StringComparison]::Ordinal)
$end = $source.IndexOf('function Set-DefenseClawRetainedRuntimeAcls {', $begin, [StringComparison]::Ordinal)
if ($begin -lt 0 -or $end -le $begin) { throw 'managed ACL function was not found' }
Invoke-Expression $source.Substring($begin, $end - $begin)

function Get-DefenseClawServiceSID { 'S-1-5-80-1-2-3-4-5' }
function Set-DefenseClawPathAcl {
    param([string]$Path, [string]$Kind, [string]$GatewayServiceSID)
    $script:Calls += [pscustomobject]@{ Path = $Path; Kind = $Kind; SID = $GatewayServiceSID }
}
function Set-DefenseClawSharedPathAcl { }
function Set-DefenseClawSecureClientInstallMarker { }
function Get-DefenseClawOptionalLayoutValue { '' }
function Grant-DefenseClawStateAncestorTraverse { }
function Invoke-DefenseClawBundleAclContract { }
function Test-DefenseClawLayoutBrokerEnabled { $false }
function Test-DefenseClawStandaloneProfile { $script:Standalone }

$root = [IO.Path]::Combine([IO.Path]::GetTempPath(), 'dc-env-acl-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($root)
try {
    $runtime = [IO.Path]::Combine($root, 'runtime')
    [void][IO.Directory]::CreateDirectory($runtime)
    $envPath = [IO.Path]::Combine($runtime, '.env')
    [IO.File]::WriteAllText($envPath, "DC_TEST_TOKEN=fixture`n")
    $missing = [IO.Path]::Combine($root, 'missing')
    $layout = @{
        RuntimeDirectory = $runtime
        StateRootAncestors = @()
        StateRoot = $missing
        InstallRoot = $missing
        BinDirectory = $missing
        LibexecDirectory = $missing
        GatewayPath = $missing
        CLIPath = $missing
        ConfigDirectory = $missing
        GuardianDirectory = $missing
        InstallStateDirectory = $missing
        ConfigPath = $missing
        ManifestPath = $missing
        AuthorizationDirectory = $missing
        AuthorizationLedgerPath = $missing
        LogDirectory = $missing
        GatewayLogDirectory = $missing
        GuardianLogDirectory = $missing
        GatewayLogPath = $missing
        GuardianLogPath = $missing
        MetadataPath = $missing
        CodexRequirementsOwnershipPath = $missing
        CodexRequirementsAclBackupPath = $missing
        AgentApplicationControlAttestationPath = $missing
        ManagedHooksTeardownJournalPath = $missing
        ManagedIPCDirectory = $missing
    }
    $script:Standalone = $true
    $script:Calls = @()
    Set-DefenseClawManagedAcls -Layout $layout -GatewayServiceName 'DefenseClawGateway'
    $envCalls = @($script:Calls | Where-Object { $_.Path -ceq $envPath })
    if ($envCalls.Count -ne 1 -or $envCalls[0].Kind -cne 'RuntimeFile' -or
        $envCalls[0].SID -cne 'S-1-5-80-1-2-3-4-5') {
        throw "existing runtime .env was not repaired for the gateway service: $($envCalls | ConvertTo-Json -Compress)"
    }
    [IO.File]::Delete($envPath)
    $script:Calls = @()
    Set-DefenseClawManagedAcls -Layout $layout -GatewayServiceName 'DefenseClawGateway'
    if (@($script:Calls | Where-Object { $_.Path -ceq $envPath }).Count -ne 0) {
        throw 'repair tried to create an absent runtime .env'
    }
    [IO.File]::WriteAllText($envPath, "DC_TEST_TOKEN=fixture`n")
    $script:Standalone = $false
    $script:Calls = @()
    Set-DefenseClawManagedAcls -Layout $layout -GatewayServiceName 'DefenseClawGateway'
    if (@($script:Calls | Where-Object { $_.Path -ceq $envPath }).Count -ne 0) {
        throw 'Secure Client runtime .env was changed by standalone repair'
    }
    Write-Output 'enterprise-standalone-runtime-env-acl-smoke: OK'
}
finally {
    [IO.Directory]::Delete($root, $true)
}
