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
    'Test-DefenseClawStandaloneProfile',
    'Format-DefenseClawSetupAction',
    'Format-DefenseClawRepairAction',
    'Get-DefenseClawApprovedPolicySource',
    'Get-DefenseClawRecordedConfigGenerationHash',
    'Get-DefenseClawRepairRollbackApprovedConfigSource',
    'Get-DefenseClawRecordedConfigGeneration',
    'ConvertTo-DefenseClawConfigGenerationNumber',
    'Test-DefenseClawSignedBundleStoreHoldsVersions',
    'Get-DefenseClawHandEditApprovedConfigSource',
    'Assert-DefenseClawApprovedConfigProven',
    'Restore-DefenseClawApprovedConfigOverHandEdit',
    'ConvertTo-DefenseClawBoundedDiagnostic',
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

$script:DefenseClawEnterpriseProfile = 'Standalone'
$script:SystemSID = 'S-1-5-18'
$script:AdministratorsSID = 'S-1-5-32-544'
$script:TrustedInstallerSID = 'S-1-5-80-1'
$script:DriftConfig = $false
$script:DriftManifest = $false
$script:Copies = 0
$script:AclWrites = 0
$script:ValidatedConfigPaths = [Collections.Generic.List[string]]::new()
$script:ResilienceReasons = [Collections.Generic.List[string]]::new()
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
        allow_unsigned = $false; sha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash }
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
function Write-DefenseClawResilienceEvent {
    param($Marker, $Fields)
    $script:ResilienceReasons.Add([string]$Fields.reason)
}
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
    if ($refusal -notmatch [regex]::Escape("DefenseClawSetup-Enterprise-Standalone-x64.exe' /ensure") -or
        $refusal -notmatch 'Setup is not installed on this computer' -or $script:Copies -ne $priorCopies) {
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
    if ($refusal -notmatch [regex]::Escape("DefenseClawSetup-Enterprise-Standalone-x64.exe' /ensure") -or
        $refusal -notmatch 'Setup is not installed on this computer' -or $script:Copies -ne $priorCopies) {
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
    # GAP-0743: a hand edit is recorded in config.generation.json for exactly
    # the bytes now installed. Repair and its rollback must still put the
    # recorded approved bytes back before the gateway is started, whether the
    # edit is a comment or a content change, and must record them afterwards.
    $generationFile = [IO.Path]::Combine($etc, 'config.generation.json')
    # The hand edit is generation 7. A lifecycle run of this release proved the
    # approved copy at generation 6 (approved-config.current.json), so by
    # default the edit directly follows the proven generation (GAP-0779).
    $proofFile = [IO.Path]::Combine($install, 'approved-config.current.json')
    function Set-ApprovedProof {
        param([string]$Json)
        [IO.File]::WriteAllText($proofFile, $Json)
    }
    function Set-HandEditRecord {
        param([string]$Text, [string]$Actor = 'hand-edit:unattributed', [string]$Proof = 'default', [string]$Previous = 'default')
        [IO.File]::WriteAllText($script:Layout.ConfigPath, $Text)
        $hash = (Get-FileHash -LiteralPath $script:Layout.ConfigPath -Algorithm SHA256).Hash.ToLowerInvariant()
        # A record names the digest of the config it replaced (the approved
        # config unless a case says otherwise; 'none' leaves the field out).
        $link = if ($Previous -ceq 'none') { '' }
        else { ',"previous_config_sha256":"' + $(if ($Previous -ceq 'default') { $record.config } else { $Previous }) + '"' }
        [IO.File]::WriteAllText($generationFile,
            ('{"generation":7,"config_sha256":"' + $hash + '","actor":"' + $Actor + '"' + $link + '}'))
        if ($Proof -ceq 'default') {
            Set-ApprovedProof ('{"config_sha256":"' + $record.config + '","generation":6}')
        }
        $script:DriftConfig = $true
    }
    function Assert-ConfigIsApproved {
        param([string]$Message)
        if (-not [Linq.Enumerable]::SequenceEqual(
                [byte[]][IO.File]::ReadAllBytes($script:Layout.ConfigPath), $approvedConfig)) {
            throw $Message
        }
    }
    foreach ($edit in @(
        @{ name = 'comment-only'; text = "config_version: 9`n# edited by hand`n" },
        @{ name = 'content'; text = "config_version: 9`nguardrail:`n  mode: bogus`n" }
    )) {
        Set-HandEditRecord -Text $edit.text
        $copiesBefore = $script:Copies
        $recovered = @{}
        Invoke-DefenseClawRepairApprovedPolicyRecovery -Layout $script:Layout `
            -Sources @{} -Metadata $metadata -GatewayServiceName 'gateway' -ApprovedConfig $recovered
        Assert-ConfigIsApproved "Repair left a $($edit.name) hand edit installed"
        if ($script:Copies -ne $copiesBefore + 1 -or $recovered['config'] -cne $record.config) {
            throw "Repair did not report the approved config it restored over a $($edit.name) hand edit"
        }
        # Rollback puts the same preimage back; it must not leave the edit.
        Set-HandEditRecord -Text $edit.text
        $script:MetadataForPreflight = $metadata
        Restore-DefenseClawApprovedConfigOverHandEdit -Layout $script:Layout -GatewayServiceName 'gateway'
        Assert-ConfigIsApproved "rollback restored a $($edit.name) hand edit managed startup refuses"
    }
    # Drift from a lifecycle-recorded config (no hand-edit record) reports the
    # approved bytes it restored too: the guardian may record them as a hand
    # edit before the config step runs.
    [IO.File]::WriteAllText($script:Layout.ConfigPath, "config_version: 9`nchanged: true`n")
    $script:DriftConfig = $true
    [IO.File]::WriteAllText($generationFile,
        ('{"config_sha256":"' + $record.config + '","actor":"lifecycle"}'))
    $recovered = @{}
    Invoke-DefenseClawRepairApprovedPolicyRecovery -Layout $script:Layout `
        -Sources @{} -Metadata $metadata -GatewayServiceName 'gateway' -ApprovedConfig $recovered
    Assert-ConfigIsApproved 'Repair left a drifted lifecycle config installed'
    if ($recovered['config'] -cne $record.config) {
        throw 'Repair did not report the approved config it restored over drift'
    }
    # A reverted edit: the bytes are approved again but the record is still a
    # hand edit. Nothing is copied, and the approved hash is still reported so
    # the config step records the lifecycle generation.
    Set-HandEditRecord -Text ([Text.Encoding]::UTF8.GetString($approvedConfig))
    $script:DriftConfig = $false
    $copiesBefore = $script:Copies
    $recovered = @{}
    Invoke-DefenseClawRepairApprovedPolicyRecovery -Layout $script:Layout `
        -Sources @{} -Metadata $metadata -GatewayServiceName 'gateway' -ApprovedConfig $recovered
    if ($script:Copies -ne $copiesBefore -or $recovered['config'] -cne $record.config) {
        throw 'Repair did not adopt a reverted hand edit through the approved hash'
    }
    # Preflight: a running gateway whose installed config is an invalid hand
    # edit validates the approved copy, not the edit, and changes nothing.
    Set-HandEditRecord -Text "invalid: true`n"
    $script:MetadataForPreflight = $metadata
    $script:ValidatedConfigPaths.Clear()
    Assert-DefenseClawRepairRollbackConfig -Layout $script:Layout `
        -Sources @{} -GatewayServiceName 'gateway'
    if ($script:ValidatedConfigPaths.Count -ne 2 -or
        [IO.File]::ReadAllText($script:Layout.ConfigPath) -cne "invalid: true`n") {
        throw 'preflight did not validate the approved copy in place of an invalid hand edit'
    }
    # Benign twin: an ordinary lifecycle record of the installed bytes is not
    # a hand edit; nothing is rewritten and nothing is reported.
    [IO.File]::WriteAllBytes($script:Layout.ConfigPath, $approvedConfig)
    $script:DriftConfig = $false
    [IO.File]::WriteAllText($generationFile,
        ('{"config_sha256":"' + $record.config + '","actor":"lifecycle"}'))
    $copiesBefore = $script:Copies
    $recovered = @{}
    Invoke-DefenseClawRepairApprovedPolicyRecovery -Layout $script:Layout `
        -Sources @{} -Metadata $metadata -GatewayServiceName 'gateway' -ApprovedConfig $recovered
    Restore-DefenseClawApprovedConfigOverHandEdit -Layout $script:Layout -GatewayServiceName 'gateway'
    if ($script:Copies -ne $copiesBefore -or $recovered.Count -ne 0) {
        throw 'a lifecycle-recorded config was rewritten or reported as a hand-edit recovery'
    }
    # A deployment that stored a signed bundle cannot prove the approved copy
    # is current: Repair refuses with the CLI's bundle command, rollback keeps
    # the restored bytes, and neither changes the installed file.
    Set-HandEditRecord -Text "config_version: 9`n# edited by hand`n"
    [void][IO.Directory]::CreateDirectory([IO.Path]::Combine($etc, 'bundles', 'v0001'))
    $copiesBefore = $script:Copies
    $refusal = ''
    try {
        Invoke-DefenseClawRepairApprovedPolicyRecovery -Layout $script:Layout `
            -Sources @{} -Metadata $metadata -GatewayServiceName 'gateway' -ApprovedConfig @{}
    }
    catch { $refusal = $_.Exception.Message }
    if (-not $refusal.Contains((Get-DefenseClawStandaloneBundleRepairCommand -Layout $script:Layout)) -or
        $script:Copies -ne $copiesBefore) {
        throw 'a bundle-managed hand edit was not refused with the bundle repair command'
    }
    Restore-DefenseClawApprovedConfigOverHandEdit -Layout $script:Layout -GatewayServiceName 'gateway'
    if ($script:Copies -ne $copiesBefore -or
        [IO.File]::ReadAllText($script:Layout.ConfigPath) -cne "config_version: 9`n# edited by hand`n") {
        throw 'rollback replaced a hand edit of a bundle-managed deployment'
    }
    [IO.Directory]::Delete([IO.Path]::Combine($etc, 'bundles'), $true)
    # GAP-0779: the copy is restored over a hand edit only when a lifecycle run
    # of this release proved it current. No proof, a proof of another copy, a
    # proof an older build left without a generation, and a proof of an older
    # generation (a config was applied after it, so the hand edit no longer
    # directly follows it) all stop Repair and the rollback before anything is
    # changed, and name the ensure that proves the next copy.
    $brokenProofs = [ordered]@{
        'no proof'                       = $null
        'a proof of another copy'        = ('{"config_sha256":"' + ('0' * 64) + '","generation":6}')
        'a proof without generation'     = ('{"config_sha256":"' + $record.config + '"}')
        'a proof of an older generation' = ('{"config_sha256":"' + $record.config + '","generation":5}')
        'a proof of a later generation'  = ('{"config_sha256":"' + $record.config + '","generation":7}')
        'a proof that is not JSON'       = 'not json'
    }
    foreach ($name in $brokenProofs.Keys) {
        Set-HandEditRecord -Text "config_version: 9`n# edited by hand`n" -Proof 'none'
        if ($null -eq $brokenProofs[$name]) {
            if ([IO.File]::Exists($proofFile)) { [IO.File]::Delete($proofFile) }
        }
        else { Set-ApprovedProof $brokenProofs[$name] }
        $copiesBefore = $script:Copies
        $refusal = ''
        try {
            Invoke-DefenseClawRepairApprovedPolicyRecovery -Layout $script:Layout `
                -Sources @{} -Metadata $metadata -GatewayServiceName 'gateway' -ApprovedConfig @{}
        }
        catch { $refusal = $_.Exception.Message }
        if ($refusal -notlike ("*" + (Format-DefenseClawSetupAction -Action '/ensure CONFIG=<approved absolute config path>') + "*") -or
            $script:Copies -ne $copiesBefore -or
            [IO.File]::ReadAllText($script:Layout.ConfigPath) -cne "config_version: 9`n# edited by hand`n") {
            throw "Repair restored the approved copy over a hand edit with $name"
        }
        Restore-DefenseClawApprovedConfigOverHandEdit -Layout $script:Layout -GatewayServiceName 'gateway'
        if ($script:Copies -ne $copiesBefore -or
            [IO.File]::ReadAllText($script:Layout.ConfigPath) -cne "config_version: 9`n# edited by hand`n") {
            throw "rollback restored the approved copy over a hand edit with $name"
        }
    }
    # A generation record that restarted after the proof (it was lost, and a
    # build that knows nothing of the proof applied another config) numbers the
    # hand edit as directly after the proof, but the edit replaced another
    # config, or no readable record: Repair and the rollback stop the same way.
    $brokenLinks = [ordered]@{
        'a hand edit that replaced another config' = ('0' * 64)
        'a hand edit with no recorded predecessor' = 'none'
        'a predecessor that is not a digest'      = 'not-a-digest'
    }
    foreach ($name in $brokenLinks.Keys) {
        Set-HandEditRecord -Text "config_version: 9`n# edited by hand`n" -Previous $brokenLinks[$name]
        $copiesBefore = $script:Copies
        $refusal = ''
        try {
            Invoke-DefenseClawRepairApprovedPolicyRecovery -Layout $script:Layout `
                -Sources @{} -Metadata $metadata -GatewayServiceName 'gateway' -ApprovedConfig @{}
        }
        catch { $refusal = $_.Exception.Message }
        if ($refusal -notlike ("*" + (Format-DefenseClawSetupAction -Action '/ensure CONFIG=<approved absolute config path>') + "*") -or
            $script:Copies -ne $copiesBefore -or
            [IO.File]::ReadAllText($script:Layout.ConfigPath) -cne "config_version: 9`n# edited by hand`n") {
            throw "Repair restored the approved copy over $name"
        }
        Restore-DefenseClawApprovedConfigOverHandEdit -Layout $script:Layout -GatewayServiceName 'gateway'
        if ($script:Copies -ne $copiesBefore -or
            [IO.File]::ReadAllText($script:Layout.ConfigPath) -cne "config_version: 9`n# edited by hand`n") {
            throw "rollback restored the approved copy over $name"
        }
    }
    # Benign twin: the proof of the generation directly before the hand edit
    # restores the copy.
    Set-HandEditRecord -Text "config_version: 9`n# edited by hand`n"
    $copiesBefore = $script:Copies
    $recovered = @{}
    Invoke-DefenseClawRepairApprovedPolicyRecovery -Layout $script:Layout `
        -Sources @{} -Metadata $metadata -GatewayServiceName 'gateway' -ApprovedConfig $recovered
    Assert-ConfigIsApproved 'Repair did not restore the approved copy over a proven hand edit'
    if ($script:Copies -ne $copiesBefore + 1) { throw 'a proven restore copied more than once' }
    Set-HandEditRecord -Text "config_version: 9`n# edited by hand`n"
    $copiesBefore = $script:Copies
    # No recorded approved source: Repair refuses before changing anything and
    # rollback keeps the restored bytes, with the reason on the event log.
    $script:ResilienceReasons.Clear()
    $refusal = ''
    try {
        Invoke-DefenseClawRepairApprovedPolicyRecovery -Layout $script:Layout `
            -Sources @{} -Metadata $noRecord -GatewayServiceName 'gateway' -ApprovedConfig @{}
    }
    catch { $refusal = $_.Exception.Message }
    $script:MetadataForPreflight = $noRecord
    Restore-DefenseClawApprovedConfigOverHandEdit -Layout $script:Layout -GatewayServiceName 'gateway'
    if ($refusal -notlike ("*" + (Format-DefenseClawSetupAction -Action '/ensure CONFIG=<approved absolute path>') + "*") -or $script:Copies -ne $copiesBefore -or
        $script:ResilienceReasons.Count -ne 1 -or
        $script:ResilienceReasons[0] -notmatch 'kept the restored config') {
        throw 'a hand edit without a recorded approved source was not left as it was'
    }
    'approved policy Repair smoke passed'
}
finally {
    if ([IO.Directory]::Exists($root)) {
        Remove-Item -LiteralPath $root -Recurse -Force
    }
}
