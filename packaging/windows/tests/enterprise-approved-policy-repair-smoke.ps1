# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

# Exercise the approved policy copy and source-less Repair decisions without
# requiring a managed Windows service on the test runner.
param([string]$ModulePath = '')
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($ModulePath)) {
    $ModulePath = [IO.Path]::GetFullPath([IO.Path]::Combine(
        $PSScriptRoot, '..', 'DefenseClawEnterprise.psm1'))
}
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    $ModulePath, [ref]$null, [ref]$parseErrors)
if (@($parseErrors).Count -ne 0) { throw "module parse failed: $($parseErrors[0])" }
foreach ($name in @(
    'Get-DefenseClawApprovedPolicyPath',
    'Get-DefenseClawApprovedPolicyHash',
    'Get-DefenseClawStandaloneBundleRepairCommand',
    'Get-DefenseClawApprovedPolicySource',
    'Get-DefenseClawRecordedConfigGenerationHash',
    'Get-DefenseClawRepairRollbackApprovedConfigSource',
    'Invoke-DefenseClawRepairApprovedPolicyRecovery',
    'Publish-DefenseClawApprovedPolicySources',
    'Install-DefenseClawSourceDescriptor',
    'Assert-DefenseClawInstalledConfig',
    'Assert-DefenseClawRepairRollbackConfig'
)) {
    $definition = $ast.Find({ param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
    }, $true)
    if ($null -eq $definition) {
        if ($name -in @(
            'Get-DefenseClawStandaloneBundleRepairCommand',
            'Get-DefenseClawRecordedConfigGenerationHash',
            'Get-DefenseClawRepairRollbackApprovedConfigSource'
        )) { continue }
        throw "module does not define $name"
    }
    . ([scriptblock]::Create($definition.Extent.Text))
}
$lifecycle = $ast.Find({ param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
    $node.Name -eq 'Invoke-DefenseClawEnterpriseLifecycle'
}, $true)
if ($null -eq $lifecycle) { throw 'enterprise lifecycle is missing' }
$preflightCall = $lifecycle.Extent.Text.IndexOf('Assert-DefenseClawRepairRollbackConfig `',
    [StringComparison]::Ordinal)
$installCall = $lifecycle.Extent.Text.IndexOf('Invoke-DefenseClawInstallLikeLifecycle `',
    [StringComparison]::Ordinal)
if ($preflightCall -lt 0 -or $installCall -le $preflightCall) {
    throw 'Repair does not validate rollback before the install-like lifecycle'
}

$script:SystemSID = 'S-1-5-18'
$script:AdministratorsSID = 'S-1-5-32-544'
$script:TrustedInstallerSID = 'S-1-5-80-1'
$script:DriftConfig = $false
$script:DriftManifest = $false
$script:Copies = 0
$script:AclWrites = 0
$script:ValidatedConfigPaths = [Collections.Generic.List[string]]::new()
function Get-DefenseClawArtifactPath {
    param($Layout, $Name)
    if ($Name -ceq 'config') { return $Layout.ConfigPath }
    if ($Name -ceq 'manifest') { return $Layout.ManifestPath }
    throw "unknown artifact $Name"
}
function Assert-DefenseClawPathAcl {
    param($Path, $AllowedWriterSIDs, $AllowedReaderSIDs,
        [switch]$RejectUntrustedRead, [switch]$AllowInheritance,
        [switch]$IgnoreCreatorTemplates)
    if (($Path -ceq $script:Layout.ConfigPath -and $script:DriftConfig) -or
        ($Path -ceq $script:Layout.ManifestPath -and $script:DriftManifest)) {
        throw 'installed policy descriptor changed'
    }
}
function Assert-DefenseClawNoReparsePath { param($Path) }
function Get-DefenseClawSourceDescriptor {
    param($Path, $Label)
    return @{ path = $Path; label = $Label; authenticode = $false;
        allow_unsigned = $false; sha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
}
function Assert-DefenseClawSourceDescriptorCurrent { param($Source) return $Source }
function Install-DefenseClawFileAtomic {
    param($Source, $Destination, $ExpectedSHA256, [switch]$SkipIfContentMatches)
    if ($ExpectedSHA256 -and
        (Get-FileHash -LiteralPath $Source -Algorithm SHA256).Hash -ne $ExpectedSHA256) {
        throw 'source digest changed'
    }
    Copy-Item -LiteralPath $Source -Destination $Destination -Force
    $script:Copies++
    if ($Destination -ceq $script:Layout.ConfigPath) { $script:DriftConfig = $false }
    if ($Destination -ceq $script:Layout.ManifestPath) { $script:DriftManifest = $false }
}
function Set-DefenseClawPathAcl {
    param($Path, $Kind, $GatewayServiceSID)
    $script:AclWrites++
}
function Get-DefenseClawServiceSID { param($ServiceName) return $script:SystemSID }
function Get-DefenseClawStandaloneManifestAdoption {
    param($Layout, $GatewayServiceName, $Activation, $InstalledManifestSHA256)
    return @{ ok = $false }
}
function Get-DefenseClawServiceChecked {
    param($Name)
    return [pscustomobject]@{ Status = 'Running' }
}
function Get-DefenseClawDeploymentMetadata {
    param($Layout)
    return $script:MetadataForPreflight
}
function Invoke-DefenseClawGatewayCommand {
    param($Layout, $GatewayServiceName, $Arguments, $GatewayPath)
    $path = [string]$Arguments[[array]::IndexOf([string[]]$Arguments, '--config') + 1]
    $script:ValidatedConfigPaths.Add($path)
    if ([IO.File]::ReadAllText($path) -match 'invalid: true') {
        throw 'invalid config setting'
    }
}

$root = [IO.Path]::Combine([IO.Path]::GetTempPath(),
    'dc-approved-policy-' + [Guid]::NewGuid().ToString('N'))
try {
    $state = [IO.Path]::Combine($root, 'state')
    $etc = [IO.Path]::Combine($state, 'etc')
    $guardian = [IO.Path]::Combine($state, 'hook-guardian')
    $install = [IO.Path]::Combine($state, 'install')
    foreach ($path in @($etc, $guardian, $install)) {
        [void][IO.Directory]::CreateDirectory($path)
    }
    $script:Layout = @{
        StateRoot = $state
        ConfigDirectory = $etc
        GuardianDirectory = $guardian
        InstallStateDirectory = $install
        PendingPath = [IO.Path]::Combine($install, 'pending.json')
        RuntimeDirectory = [IO.Path]::Combine($state, 'runtime')
        GatewayPath = [IO.Path]::Combine($state, 'gateway.exe')
        CLIPath = [IO.Path]::Combine($state, 'bin', 'defenseclaw.exe')
        ConfigPath = [IO.Path]::Combine($etc, 'config.yaml')
        ManifestPath = [IO.Path]::Combine($guardian, 'targets.yaml')
    }
    $approvedConfig = [Text.UTF8Encoding]::new($false).GetBytes("config_version: 9`n")
    $approvedManifest = [Text.UTF8Encoding]::new($false).GetBytes("targets: []`n")
    [IO.File]::WriteAllBytes($script:Layout.ConfigPath, $approvedConfig)
    [IO.File]::WriteAllBytes($script:Layout.ManifestPath, $approvedManifest)
    $record = Publish-DefenseClawApprovedPolicySources -Layout $script:Layout `
        -Sources @{config = @{path = 'approved'}; manifest = @{path = 'approved'}}
    if ($record.Count -ne 2 -or $script:Copies -ne 2) {
        throw 'the approved sources were not recorded in protected copies'
    }
    $metadata = (@{ approved_policy_sources = $record;
        managed_hooks_activation = @{ manifest_sha256 = $record.manifest; state = 'activated' }
    } | ConvertTo-Json -Depth 4 | ConvertFrom-Json)
    [IO.File]::WriteAllText([IO.Path]::Combine($etc, 'config.generation.json'),
        ('{"config_sha256":"' + $record.config + '"}'))
    [IO.File]::WriteAllText($script:Layout.ConfigPath, "config_version: 9`nchanged: true`n")
    [IO.File]::WriteAllText($script:Layout.ManifestPath, "targets: [changed]`n")
    $script:DriftConfig = $true
    $script:DriftManifest = $true
    Invoke-DefenseClawRepairApprovedPolicyRecovery -Layout $script:Layout `
        -Sources @{} -Metadata $metadata -GatewayServiceName 'gateway'
    if (-not [Linq.Enumerable]::SequenceEqual([byte[]][IO.File]::ReadAllBytes($script:Layout.ConfigPath), $approvedConfig) -or
        -not [Linq.Enumerable]::SequenceEqual([byte[]][IO.File]::ReadAllBytes($script:Layout.ManifestPath), $approvedManifest) -or
        $script:Copies -ne 4 -or $script:AclWrites -ne 4) {
        throw 'Repair did not rewrite both files from the recorded approved bytes'
    }
    $priorCopies = $script:Copies
    Invoke-DefenseClawRepairApprovedPolicyRecovery -Layout $script:Layout `
        -Sources @{} -Metadata $metadata -GatewayServiceName 'gateway'
    if ($script:Copies -ne $priorCopies) {
        throw 'Repair rewrote an undrifted policy file'
    }
    [IO.File]::WriteAllText($script:Layout.ConfigPath, "config_version: 9`nchanged: true`n")
    $script:DriftConfig = $true
    $noRecord = (@{ managed_hooks_activation = @{ manifest_sha256 = $record.manifest;
        state = 'activated' } } | ConvertTo-Json -Depth 3 | ConvertFrom-Json)
    $refusal = ''
    try {
        Invoke-DefenseClawRepairApprovedPolicyRecovery -Layout $script:Layout `
            -Sources @{} -Metadata $noRecord -GatewayServiceName 'gateway'
    }
    catch { $refusal = $_.Exception.Message }
    if ($refusal -notmatch 'Setup /ensure' -or $script:Copies -ne $priorCopies) {
        throw 'source-less Repair did not refuse with a working command'
    }
    [IO.File]::WriteAllBytes($script:Layout.ConfigPath, $approvedConfig)
    $script:DriftConfig = $false
    [IO.File]::WriteAllText($script:Layout.ManifestPath, "targets: [changed]`n")
    $script:DriftManifest = $true
    $refusal = ''
    try {
        Invoke-DefenseClawRepairApprovedPolicyRecovery -Layout $script:Layout `
            -Sources @{} -Metadata $noRecord -GatewayServiceName 'gateway'
    }
    catch { $refusal = $_.Exception.Message }
    if ($refusal -notmatch 'Setup /ensure' -or $script:Copies -ne $priorCopies) {
        throw 'source-less Repair accepted a changed manifest without an approved source'
    }
    $script:DriftManifest = $false
    [IO.File]::WriteAllBytes($script:Layout.ManifestPath, $approvedManifest)
    [IO.File]::WriteAllText($script:Layout.ConfigPath, "config_version: 9`nchanged: true`n")
    $script:DriftConfig = $true
    [IO.File]::WriteAllText([IO.Path]::Combine($etc, 'config.generation.json'),
        ('{"config_sha256":"' + ('0' * 64) + '"}'))
    $refusal = ''
    try {
        Invoke-DefenseClawRepairApprovedPolicyRecovery -Layout $script:Layout `
            -Sources @{} -Metadata $metadata -GatewayServiceName 'gateway'
    }
    catch { $refusal = $_.Exception.Message }
    if ($refusal -notmatch 'cannot prove' -or $script:Copies -ne $priorCopies) {
        throw 'Repair accepted an approved copy from a prior config generation'
    }
    # The running-gateway preflight must validate the recorded bytes before
    # the install-like recovery rewrites an invalid installed config.
    [IO.File]::WriteAllText([IO.Path]::Combine($etc, 'config.generation.json'),
        ('{"config_sha256":"' + $record.config + '"}'))
    [IO.File]::WriteAllText($script:Layout.ConfigPath, "invalid: true`n")
    $script:MetadataForPreflight = $metadata
    $script:ValidatedConfigPaths.Clear()
    Assert-DefenseClawRepairRollbackConfig -Layout $script:Layout `
        -Sources @{} -GatewayServiceName 'gateway'
    if ($script:ValidatedConfigPaths.Count -ne 2 -or
        $script:ValidatedConfigPaths[0] -cne $script:Layout.ConfigPath -or
        $script:ValidatedConfigPaths[1] -ceq $script:Layout.ConfigPath -or
        [IO.File]::ReadAllText($script:Layout.ConfigPath) -cne "invalid: true`n" -or
        [IO.File]::Exists($script:ValidatedConfigPaths[1])) {
        throw 'Repair preflight did not validate a temporary approved candidate without changing the installed file'
    }
    Invoke-DefenseClawRepairApprovedPolicyRecovery -Layout $script:Layout `
        -Sources @{} -Metadata $metadata -GatewayServiceName 'gateway'
    if (-not [Linq.Enumerable]::SequenceEqual([byte[]][IO.File]::ReadAllBytes($script:Layout.ConfigPath), $approvedConfig)) {
        throw 'Repair did not rewrite the invalid installed config after preflight'
    }
    $script:DriftConfig = $false
    $script:ValidatedConfigPaths.Clear()
    Assert-DefenseClawRepairRollbackConfig -Layout $script:Layout `
        -Sources @{} -GatewayServiceName 'gateway'
    if ($script:ValidatedConfigPaths.Count -ne 1 -or
        $script:ValidatedConfigPaths[0] -cne $script:Layout.ConfigPath) {
        throw 'an undrifted config did not use the installed preflight path'
    }

    # A later signed bundle makes Setup's old approved copy stale. Its
    # source-less refusal must name the installed CLI's bundle repair path.
    [IO.File]::WriteAllText($script:Layout.ConfigPath, "invalid: true`n")
    [IO.File]::WriteAllText([IO.Path]::Combine($etc, 'config.generation.json'),
        ('{"config_sha256":"' + ('a' * 64) + '"}'))
    $copiesBeforeRefusal = $script:Copies
    $refusal = ''
    try {
        Assert-DefenseClawRepairRollbackConfig -Layout $script:Layout `
            -Sources @{} -GatewayServiceName 'gateway'
    }
    catch { $refusal = $_.Exception.Message }
    $bundleCommand = Get-DefenseClawStandaloneBundleRepairCommand -Layout $script:Layout
    if (-not $refusal.Contains($bundleCommand) -or
        $script:Copies -ne $copiesBeforeRefusal -or
        [IO.File]::ReadAllText($script:Layout.ConfigPath) -cne "invalid: true`n") {
        throw 'stale approved copy lacked a working bundle-mode recovery command'
    }
    'approved policy Repair smoke passed'
}
finally {
    if ([IO.Directory]::Exists($root)) {
        Remove-Item -LiteralPath $root -Recurse -Force
    }
}
