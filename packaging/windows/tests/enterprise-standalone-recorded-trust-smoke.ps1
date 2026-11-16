# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 7.0

# A hash-pinned standalone deployment keeps no payload manifest after install,
# so the installed CLI reaches the bootstrap with no pin. The bootstrap admits
# the installed module by the digest the protected deployment metadata
# recorded, and only when the running installer is the recorded one. This
# exercises the production Get-DefenseClawBootstrapRecordedModulePin in a
# disposable scratch directory. The administrator-owned path chain check is
# stubbed here (the bootstrap and exact-ACL smokes own it); a stubbed refusal
# stands in for an untrusted record. The standalone bootstrap runs only on
# PowerShell 7.

[CmdletBinding()]
param(
    [string]$ScratchRoot = [IO.Path]::GetTempPath()
)

Microsoft.PowerShell.Core\Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$installerSource = [IO.Path]::GetFullPath(
    (Microsoft.PowerShell.Management\Join-Path `
        $PSScriptRoot `
        '..\install-enterprise.ps1')
)
$tokens = $null
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    $installerSource,
    [ref]$tokens,
    [ref]$parseErrors
)
if (@($parseErrors).Count -ne 0) {
    throw 'could not parse install-enterprise.ps1'
}
$definitions = @(
    $ast.FindAll(
        {
            param($node)
            return (
                $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
                [string]$node.Name -ceq 'Get-DefenseClawBootstrapRecordedModulePin'
            )
        },
        $true
    )
)
if ($definitions.Count -ne 1) {
    throw "expected one Get-DefenseClawBootstrapRecordedModulePin, found $($definitions.Count)"
}
. ([scriptblock]::Create([string]$definitions[0].Extent.Text))

$script:UntrustedMetadata = ''
function Assert-DefenseClawBootstrapModuleTrust {
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$AllowUnsignedModule,
        [string]$PinnedSHA256,
        [string[]]$AllowedSignerSHA256 = @()
    )
    if (-not $AllowUnsignedModule) {
        throw 'the recorded-pin lookup must check the metadata as an unsigned trust anchor'
    }
    if ([string]::Equals($Path, $script:UntrustedMetadata, [StringComparison]::OrdinalIgnoreCase)) {
        throw "untrusted principal S-1-5-32-545 has write-like access to DefenseClaw enterprise installer module path: $Path"
    }
    return [IO.Path]::GetFullPath($Path)
}

function Get-TestSHA256([string]$Path) {
    return (Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

$root = [IO.Path]::Combine(
    [IO.Path]::GetFullPath($ScratchRoot),
    ('dc-standalone-recorded-trust-' + [Guid]::NewGuid().ToString('N'))
)
[void][IO.Directory]::CreateDirectory($root)
$failures = [Collections.Generic.List[string]]::new()
try {
    $utf8 = [Text.UTF8Encoding]::new($false)
    $installer = [IO.Path]::Combine($root, 'install-enterprise.ps1')
    $module = [IO.Path]::Combine($root, 'DefenseClawEnterprise.psm1')
    $otherInstaller = [IO.Path]::Combine($root, 'other-install-enterprise.ps1')
    [IO.File]::WriteAllText($installer, '# installed installer', $utf8)
    [IO.File]::WriteAllText($module, '# installed module', $utf8)
    [IO.File]::WriteAllText($otherInstaller, '# a different installer', $utf8)
    $moduleHash = Get-TestSHA256 $module
    $installerHash = Get-TestSHA256 $installer
    $metadata = [IO.Path]::Combine($root, 'deployment.json')
    function Write-TestMetadata([hashtable]$Document) {
        [IO.File]::WriteAllText($metadata, ($Document | Microsoft.PowerShell.Utility\ConvertTo-Json -Depth 4), $utf8)
    }
    # $Unreadable is the text the damaged-record note must hold ('' for no
    # note): a record that does not parse is named by the caller instead of
    # the module signature (GAP-0164); any other outcome leaves no note.
    function Test-Pin([string]$Label, [string]$Want, [string]$Installer = $installer, [string]$Unreadable = '') {
        $script:DefenseClawBootstrapUnreadableRecord = 'stale note from an earlier call'
        $got = Get-DefenseClawBootstrapRecordedModulePin -MetadataPath $metadata -InstallerPath $Installer
        if ($got -cne $Want) {
            $failures.Add("${Label}: pin '$got', want '$Want'")
        }
        $note = [string]$script:DefenseClawBootstrapUnreadableRecord
        if ([string]::IsNullOrEmpty($Unreadable)) {
            if ($note -ne '') {
                $failures.Add("${Label}: damaged-record note '$note', want none")
            }
        }
        elseif (-not $note.StartsWith($metadata, [StringComparison]::OrdinalIgnoreCase) -or -not $note.Contains($Unreadable)) {
            $failures.Add("${Label}: damaged-record note '$note', want $metadata and '$Unreadable'")
        }
    }
    $recorded = @{
        schema_version = 1
        installed = $true
        profile = 'standalone'
        trust_mode = 'hash_pinned'
        hashes = @{ module = $moduleHash; installer = $installerHash; gateway = ('0' * 64) }
    }

    Test-Pin 'no metadata' ''

    Write-TestMetadata $recorded
    Test-Pin 'hash-pinned standalone deployment' $moduleHash

    $recorded.installed = $false
    Write-TestMetadata $recorded
    Test-Pin 'hash-pinned tombstone' $moduleHash
    $recorded.installed = $true

    Test-Pin 'a different running installer' '' $otherInstaller

    $script:UntrustedMetadata = $metadata
    Test-Pin 'metadata a standard user could write' ''
    $script:UntrustedMetadata = ''

    $authenticode = $recorded.Clone()
    $authenticode.trust_mode = 'authenticode'
    Write-TestMetadata $authenticode
    Test-Pin 'authenticode deployment' ''

    $secureClient = $recorded.Clone()
    $secureClient.Remove('profile')
    Write-TestMetadata $secureClient
    Test-Pin 'metadata without the standalone profile' ''

    $noModule = $recorded.Clone()
    $noModule.hashes = @{ installer = $installerHash }
    Write-TestMetadata $noModule
    Test-Pin 'metadata without a module digest' ''

    $badDigest = $recorded.Clone()
    $badDigest.hashes = @{ module = $moduleHash.ToUpperInvariant(); installer = $installerHash }
    Write-TestMetadata $badDigest
    Test-Pin 'non-canonical module digest' ''

    [IO.File]::WriteAllText($metadata, 'not json', $utf8)
    Test-Pin 'unparseable metadata' '' $installer 'Conversion from JSON failed'

    [IO.File]::WriteAllText($metadata, '[1, 2]', $utf8)
    Test-Pin 'metadata that is not a JSON object' '' $installer 'it is not a JSON object'

    [IO.File]::WriteAllText($metadata, '', $utf8)
    Test-Pin 'empty metadata' '' $installer ' ('

    [IO.File]::WriteAllText($metadata, ('{"trust_mode":"hash_pinned","pad":"' + ('x' * 1048576) + '"}'), $utf8)
    Test-Pin 'oversized metadata' '' $installer 'larger than 1 MiB'

    # An untrusted record is not named: only a protected record is evidence.
    [IO.File]::WriteAllText($metadata, 'not json', $utf8)
    $script:UntrustedMetadata = $metadata
    Test-Pin 'unparseable metadata a standard user could write' ''
    $script:UntrustedMetadata = ''
}
finally {
    Microsoft.PowerShell.Management\Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}

# While a transaction is pending, the bootstrap also admits the installer and
# module pair the transaction pinned in its protected directory, and only for
# the running installer it names (rel-1-0-6 GAP-0649: an upgrade cut off after
# it copied its own installer and module). The module stages that pair first.
$transactionPins = @(
    $ast.FindAll(
        {
            param($node)
            return (
                $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
                [string]$node.Name -ceq 'Get-DefenseClawBootstrapTransactionModulePin'
            )
        },
        $true
    )
)
if ($transactionPins.Count -ne 1) {
    $failures.Add("expected one Get-DefenseClawBootstrapTransactionModulePin, found $($transactionPins.Count)")
}
else {
    . ([scriptblock]::Create([string]$transactionPins[0].Extent.Text))
    $stateRoot = [IO.Path]::Combine(
        [IO.Path]::GetFullPath($ScratchRoot),
        ('dc-standalone-transaction-pins-' + [Guid]::NewGuid().ToString('N'))
    )
    try {
        $utf8 = [Text.UTF8Encoding]::new($false)
        $transaction = [IO.Path]::Combine($stateRoot, 'install', 'transactions', ('a' * 32))
        [void][IO.Directory]::CreateDirectory($transaction)
        $installer = [IO.Path]::Combine($stateRoot, 'install-enterprise.ps1')
        $otherInstaller = [IO.Path]::Combine($stateRoot, 'other-install-enterprise.ps1')
        [IO.File]::WriteAllText($installer, '# the installer the transaction installed', $utf8)
        [IO.File]::WriteAllText($otherInstaller, '# the replaced installer', $utf8)
        $installerHash = Get-TestSHA256 $installer
        $moduleHash = 'b' * 64
        $pending = [IO.Path]::Combine($stateRoot, 'install', 'pending.json')
        $pins = [IO.Path]::Combine($transaction, 'lifecycle-pins.json')
        function Write-TestJson([string]$Path, $Document) {
            [IO.File]::WriteAllText($Path, ($Document | Microsoft.PowerShell.Utility\ConvertTo-Json -Depth 4), $utf8)
        }
        function Test-TransactionPin([string]$Label, [string]$Want, [string]$Installer = $installer) {
            $got = Get-DefenseClawBootstrapTransactionModulePin -StateRoot $stateRoot -InstallerPath $Installer
            if ($got -cne $Want) {
                $failures.Add("${Label}: transaction pin '$got', want '$Want'")
            }
        }
        $pinned = [ordered]@{ schema_version = 1; installer = $installerHash; module = $moduleHash }

        Test-TransactionPin 'no pending transaction' ''

        Write-TestJson $pending @{ snapshot = [IO.Path]::Combine($transaction, 'snapshot.json') }
        Test-TransactionPin 'pending transaction without pins' ''

        Write-TestJson $pins $pinned
        Test-TransactionPin 'pending transaction pins the running installer' $moduleHash
        Test-TransactionPin 'pins name another installer' '' $otherInstaller

        $script:UntrustedMetadata = $pins
        Test-TransactionPin 'pins a standard user could write' ''
        $script:UntrustedMetadata = $pending
        Test-TransactionPin 'pending record a standard user could write' ''
        $script:UntrustedMetadata = ''

        Write-TestJson $pending @{ snapshot = [IO.Path]::Combine($stateRoot, 'elsewhere', 'snapshot.json') }
        Test-TransactionPin 'snapshot outside the transactions directory' ''
        Write-TestJson $pending @{ phase = 'quiescing' }
        Test-TransactionPin 'quiescing record without a snapshot' ''
        Write-TestJson $pending @{ snapshot = [IO.Path]::Combine($transaction, 'snapshot.json') }

        $badPins = [ordered]@{ schema_version = 1; installer = $installerHash; module = $moduleHash.ToUpperInvariant() }
        Write-TestJson $pins $badPins
        Test-TransactionPin 'non-canonical module digest' ''
        $badPins = [ordered]@{ schema_version = 2; installer = $installerHash; module = $moduleHash }
        Write-TestJson $pins $badPins
        Test-TransactionPin 'unknown pin schema' ''
        [IO.File]::WriteAllText($pins, 'not json', $utf8)
        Test-TransactionPin 'unparseable pins' ''
    }
    finally {
        Microsoft.PowerShell.Management\Remove-Item -LiteralPath $stateRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# The module's own deployment.json reader refuses every record that is not a
# JSON object with the marker the CLI maps to ensure_refused, an empty one
# too ($null -isnot [pscustomobject] is false; GAP-0164).
$moduleSource = [IO.Path]::GetFullPath(
    (Microsoft.PowerShell.Management\Join-Path $PSScriptRoot '..\DefenseClawEnterprise.psm1')
)
$moduleAst = [Management.Automation.Language.Parser]::ParseFile($moduleSource, [ref]$tokens, [ref]$parseErrors)
$readers = @($moduleAst.FindAll({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            [string]$node.Name -ceq 'ConvertFrom-DefenseClawDeploymentMetadataText'
        }, $true))
if ($readers.Count -ne 1) {
    $failures.Add("expected one ConvertFrom-DefenseClawDeploymentMetadataText, found $($readers.Count)")
}
else {
    . ([scriptblock]::Create([string]$readers[0].Extent.Text))
    foreach ($hintName in @('Test-DefenseClawStandaloneProfile', 'Format-DefenseClawSetupAction')) {
        $hint = @($moduleAst.FindAll({
                    param($node)
                    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and [string]$node.Name -ceq $hintName
                }, $true))
        if ($hint.Count -ne 1) { $failures.Add("expected one $hintName, found $($hint.Count)"); continue }
        . ([scriptblock]::Create([string]$hint[0].Extent.Text))
    }
    $script:UnreadableMetadataMessage = 'could not read the installed deployment metadata'
    # GAP-0095: a standalone computer has no Setup installed, so the hint runs
    # it from its folder and says where it comes from; another profile keeps
    # "Setup /repair" as it was.
    foreach ($profileCase in @(
            @('Standalone', "run & '.\DefenseClawSetup-Enterprise-Standalone-x64.exe' /repair (Setup is not installed on this computer: use the copy in your MDM package or the release download) to rebuild it"),
            @('SecureClient', 'run Setup /repair to rebuild it'))) {
        $script:DefenseClawEnterpriseProfile = $profileCase[0]
        foreach ($case in @(@('empty', ''), @('garbage', 'e-not-a-record'), @('array', '[1]'), @('number', '5'))) {
            try {
                [void](ConvertFrom-DefenseClawDeploymentMetadataText -Path 'C:\x\deployment.json' -Text $case[1])
                $failures.Add("module reader accepted the $($case[0]) record")
            }
            catch {
                if (-not ([string]$_.Exception.Message).StartsWith($script:UnreadableMetadataMessage) -or
                    -not ([string]$_.Exception.Message).EndsWith($profileCase[1])) {
                    $failures.Add("module reader $($case[0]) record under $($profileCase[0]): $($_.Exception.Message)")
                }
            }
        }
    }
    if ($null -eq (ConvertFrom-DefenseClawDeploymentMetadataText -Path 'C:\x\deployment.json' -Text '{"installed":true}')) {
        $failures.Add('module reader refused a JSON object')
    }
}

$stagingOrders = @($moduleAst.FindAll({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            [string]$node.Name -ceq 'Get-DefenseClawStagingOrder'
        }, $true))
if ($stagingOrders.Count -ne 1) {
    $failures.Add("expected one Get-DefenseClawStagingOrder, found $($stagingOrders.Count)")
}
else {
    . ([scriptblock]::Create([string]$stagingOrders[0].Extent.Text))
    $script:StandaloneProfile = $true
    function Test-DefenseClawStandaloneProfile { return $script:StandaloneProfile }
    $names = @('gateway', 'module', 'hook', 'cli', 'config', 'installer', 'acp')
    $order = (@(Get-DefenseClawStagingOrder -Names $names) -join ',')
    if ($order -cne 'installer,module,cli,acp,config,gateway,hook') {
        $failures.Add("standalone staging order '$order'")
    }
    $script:StandaloneProfile = $false
    $order = (@(Get-DefenseClawStagingOrder -Names $names) -join ',')
    if ($order -cne ($names -join ',')) {
        $failures.Add("Secure Client staging order '$order', want the caller's")
    }
}

# The installed CLI's bootstrap chooses between the recorded pin and the
# pending transaction's pin, and uses the transaction's only for a trusted
# hash-pinned standalone record (rel-1-0-6 GAP-0649; g649 review F1, F2).
$selections = @($ast.FindAll({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            [string]$node.Name -ceq 'Get-DefenseClawBootstrapInstalledModulePin'
        }, $true))
if ($selections.Count -ne 1 -or $transactionPins.Count -ne 1) {
    $failures.Add("expected one Get-DefenseClawBootstrapInstalledModulePin, found $($selections.Count)")
}
else {
    . ([scriptblock]::Create([string]$selections[0].Extent.Text))
    $stateRoot = [IO.Path]::Combine(
        [IO.Path]::GetFullPath($ScratchRoot),
        ('dc-standalone-pin-selection-' + [Guid]::NewGuid().ToString('N'))
    )
    try {
        $utf8 = [Text.UTF8Encoding]::new($false)
        $installState = [IO.Path]::Combine($stateRoot, 'install')
        $transaction = [IO.Path]::Combine($installState, 'transactions', ('c' * 32))
        [void][IO.Directory]::CreateDirectory($transaction)
        $newInstaller = [IO.Path]::Combine($stateRoot, 'install-enterprise.ps1')
        $oldInstaller = [IO.Path]::Combine($stateRoot, 'old-install-enterprise.ps1')
        $modulePath = [IO.Path]::Combine($stateRoot, 'DefenseClawEnterprise.psm1')
        [IO.File]::WriteAllText($newInstaller, '# the installer the transaction installed', $utf8)
        [IO.File]::WriteAllText($oldInstaller, '# the installer the deployment recorded', $utf8)
        $newInstallerHash = Get-TestSHA256 $newInstaller
        $oldInstallerHash = Get-TestSHA256 $oldInstaller
        $oldModuleText = '# the module the deployment recorded'
        $newModuleText = '# the module the transaction installed'
        [IO.File]::WriteAllText($modulePath, $newModuleText, $utf8)
        $newModuleHash = Get-TestSHA256 $modulePath
        [IO.File]::WriteAllText($modulePath, $oldModuleText, $utf8)
        $oldModuleHash = Get-TestSHA256 $modulePath
        $deployment = [IO.Path]::Combine($installState, 'deployment.json')
        $pendingRecord = [IO.Path]::Combine($installState, 'pending.json')
        $pinsRecord = [IO.Path]::Combine($transaction, 'lifecycle-pins.json')
        function Write-SelectionJson([string]$Path, $Document) {
            [IO.File]::WriteAllText($Path, ($Document | Microsoft.PowerShell.Utility\ConvertTo-Json -Depth 4), $utf8)
        }
        function Test-Selection([string]$Label, [string]$Want, [string]$Installer, [string]$ModuleText) {
            [IO.File]::WriteAllText($modulePath, $ModuleText, $utf8)
            $got = Get-DefenseClawBootstrapInstalledModulePin -StateRoot $stateRoot -InstallerPath $Installer -ModulePath $modulePath
            if ($got -cne $Want) {
                $failures.Add("${Label}: selected pin '$got', want '$Want'")
            }
        }
        $record = @{
            schema_version = 1
            installed = $true
            profile = 'standalone'
            trust_mode = 'hash_pinned'
            hashes = @{ module = $oldModuleHash; installer = $newInstallerHash }
        }
        Write-SelectionJson $deployment $record
        Write-SelectionJson $pendingRecord @{ snapshot = [IO.Path]::Combine($transaction, 'snapshot.json') }
        Write-SelectionJson $pinsRecord ([ordered]@{ schema_version = 1; installer = $newInstallerHash; module = $newModuleHash })

        Test-Selection 'recorded pair on disk keeps the recorded pin' $oldModuleHash $newInstaller $oldModuleText
        Test-Selection 'transaction module on disk takes the transaction pin' $newModuleHash $newInstaller $newModuleText

        $record.hashes = @{ module = $oldModuleHash; installer = $oldInstallerHash }
        Write-SelectionJson $deployment $record
        Test-Selection 'recorded pair of another installer takes the transaction pin' $newModuleHash $newInstaller $oldModuleText

        Remove-Item -LiteralPath $pendingRecord -Force
        Test-Selection 'no pending transaction keeps the recorded pin' '' $newInstaller $newModuleText
        $record.hashes = @{ module = $oldModuleHash; installer = $newInstallerHash }
        Write-SelectionJson $deployment $record
        Test-Selection 'no pending transaction, recorded installer' $oldModuleHash $newInstaller $oldModuleText
        Write-SelectionJson $pendingRecord @{ snapshot = [IO.Path]::Combine($transaction, 'snapshot.json') }

        # F1: an Authenticode deployment never admits a module by the hash a
        # pending transaction pinned, an unsigned one included.
        $authenticodeRecord = $record.Clone()
        $authenticodeRecord.trust_mode = 'authenticode'
        Write-SelectionJson $deployment $authenticodeRecord
        Test-Selection 'Authenticode deployment with a pending transaction' '' $newInstaller $newModuleText
        $script:UntrustedMetadata = $deployment
        Write-SelectionJson $deployment $record
        Test-Selection 'untrusted deployment record with a pending transaction' '' $newInstaller $newModuleText
        $script:UntrustedMetadata = ''
        Remove-Item -LiteralPath $deployment -Force
        Test-Selection 'no deployment record with a pending transaction' '' $newInstaller $newModuleText
        $scRecord = $record.Clone()
        $scRecord.Remove('profile')
        Write-SelectionJson $deployment $scRecord
        Test-Selection 'record without the standalone profile' '' $newInstaller $newModuleText
    }
    finally {
        Microsoft.PowerShell.Management\Remove-Item -LiteralPath $stateRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# The module side: the pending transaction's pins reader, the re-admission
# of the pair it pinned, the pins write and the Repair stop after a recovery
# that restored another release (rel-1-0-6 GAP-0649; g649 review F2). The
# path and ACL checks are stubbed; a stubbed refusal stands in for an ACE.
$moduleFunctions = @{}
foreach ($name in @(
        'Get-DefenseClawPendingTransactionLifecyclePins',
        'Initialize-DefenseClawRecordedPayloadTrust',
        'Write-DefenseClawTransactionLifecyclePins',
        'Test-DefenseClawRecoveryRestoredOtherRelease'
    )) {
    $found = @($moduleAst.FindAll({
                param($node)
                $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
                [string]$node.Name -ceq $name
            }.GetNewClosure(), $true))
    $moduleFunctions[$name] = $found.Count
    if ($found.Count -eq 1) {
        . ([scriptblock]::Create([string]$found[0].Extent.Text))
    }
}
if (@($moduleFunctions.Values | Where-Object { $_ -ne 1 }).Count -ne 0) {
    $failures.Add("expected one of each module transaction-pin function: $(($moduleFunctions.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ', ')")
}
else {
    $script:SystemSID = 'S-1-5-18'
    $script:AdministratorsSID = 'S-1-5-32-544'
    $script:TrustedInstallerSID = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
    $script:UntrustedWriteAce = ''
    $script:UntrustedReadAce = ''
    $script:AclStamps = [Collections.Generic.List[string]]::new()
    function Assert-DefenseClawNoReparsePath { param([string]$Path) }
    function New-DefenseClawRequiredRights { param([string]$Kind) return $Kind }
    function Assert-DefenseClawPathAcl {
        param(
            [string]$Path,
            [string[]]$AllowedWriterSIDs,
            [string[]]$AllowedReaderSIDs,
            $RequiredRights,
            [switch]$RejectUntrustedRead
        )
        $admins = @($script:SystemSID, $script:AdministratorsSID, $script:TrustedInstallerSID)
        if (@($AllowedWriterSIDs | Where-Object { $_ -notin $admins }).Count -ne 0 -or
            @($AllowedReaderSIDs | Where-Object { $_ -notin $admins }).Count -ne 0) {
            throw "pins ACL check admits a non-administrator: $Path"
        }
        if ([string]::Equals($Path, $script:UntrustedWriteAce, [StringComparison]::OrdinalIgnoreCase)) {
            throw "untrusted principal S-1-5-32-545 has write-like access: $Path"
        }
        if ($RejectUntrustedRead -and
            [string]::Equals($Path, $script:UntrustedReadAce, [StringComparison]::OrdinalIgnoreCase)) {
            throw "untrusted principal S-1-5-32-545 can read: $Path"
        }
    }
    function Get-DefenseClawArtifactPath {
        param([hashtable]$Layout, [string]$Name)
        switch ($Name) {
            'installer' { return $Layout.InstallerPath }
            'module' { return $Layout.ModulePath }
            'gateway' { return $Layout.GatewayPath }
            'cli' { return $Layout.CLIPath }
            default { throw "unknown managed artifact: $Name" }
        }
    }
    function Write-DefenseClawJsonAtomic {
        param($Value, [string]$Path, [string]$Kind)
        [IO.File]::WriteAllText($Path, ($Value | Microsoft.PowerShell.Utility\ConvertTo-Json -Depth 4), [Text.UTF8Encoding]::new($false))
        if ($Kind) { $script:AclStamps.Add("$Kind $Path") }
    }
    function Set-DefenseClawPathAcl {
        param([string]$Path, [string]$Kind, [string]$GatewayServiceSID)
        $script:AclStamps.Add("$Kind $Path")
    }
    $script:StandaloneProfile = $true
    function Test-DefenseClawStandaloneProfile { return $script:StandaloneProfile }

    $root = [IO.Path]::Combine(
        [IO.Path]::GetFullPath($ScratchRoot),
        ('dc-standalone-module-pins-' + [Guid]::NewGuid().ToString('N'))
    )
    try {
        $utf8 = [Text.UTF8Encoding]::new($false)
        $installState = [IO.Path]::Combine($root, 'state', 'install')
        $transactionsDir = [IO.Path]::Combine($installState, 'transactions')
        $transaction = [IO.Path]::Combine($transactionsDir, ('d' * 32))
        $libexec = [IO.Path]::Combine($root, 'libexec')
        [void][IO.Directory]::CreateDirectory($transaction)
        [void][IO.Directory]::CreateDirectory($libexec)
        $layout = @{
            PendingPath = [IO.Path]::Combine($installState, 'pending.json')
            TransactionsDirectory = $transactionsDir
            InstallerPath = [IO.Path]::Combine($libexec, 'install-enterprise.ps1')
            ModulePath = [IO.Path]::Combine($libexec, 'DefenseClawEnterprise.psm1')
            GatewayPath = [IO.Path]::Combine($root, 'defenseclaw-gateway.exe')
            CLIPath = [IO.Path]::Combine($root, 'defenseclaw.exe')
        }
        $pinsPath = [IO.Path]::Combine($transaction, 'lifecycle-pins.json')
        function Set-TestText([string]$Path, [string]$Text) { [IO.File]::WriteAllText($Path, $Text, $utf8) }
        function Get-TextSHA256([string]$Text) {
            $probe = [IO.Path]::Combine($root, 'probe.txt')
            Set-TestText $probe $Text
            $digest = Get-TestSHA256 $probe
            Remove-Item -LiteralPath $probe -Force
            return $digest
        }
        $oldInstaller = '# 1.0.8 installer'; $newInstaller = '# 1.0.9 installer'
        $oldModule = '# 1.0.8 module'; $newModule = '# 1.0.9 module'
        $oldInstallerHash = Get-TextSHA256 $oldInstaller; $newInstallerHash = Get-TextSHA256 $newInstaller
        $oldModuleHash = Get-TextSHA256 $oldModule; $newModuleHash = Get-TextSHA256 $newModule
        $gatewayHash = 'e' * 64
        $oldCli = '# 1.0.8 cli'; $newCli = '# 1.0.9 cli'
        $oldCliHash = Get-TextSHA256 $oldCli; $newCliHash = Get-TextSHA256 $newCli
        function Write-ModuleJson([string]$Path, $Document) {
            [IO.File]::WriteAllText($Path, ($Document | Microsoft.PowerShell.Utility\ConvertTo-Json -Depth 4), $utf8)
        }
        Write-ModuleJson $pinsPath ([ordered]@{ schema_version = 1; installer = $newInstallerHash; module = $newModuleHash; cli = $newCliHash })

        # Reader.
        if ($null -ne (Get-DefenseClawPendingTransactionLifecyclePins -Layout $layout)) {
            $failures.Add('module pins reader: no pending transaction returned pins')
        }
        Write-ModuleJson $layout.PendingPath @{ snapshot = [IO.Path]::Combine($transaction, 'snapshot.json') }
        $read = Get-DefenseClawPendingTransactionLifecyclePins -Layout $layout
        if ($null -eq $read -or $read.installer -cne $newInstallerHash -or $read.module -cne $newModuleHash -or $read.cli -cne $newCliHash) {
            $failures.Add('module pins reader: trusted pins of the pending transaction were not returned')
        }
        Write-ModuleJson $pinsPath ([ordered]@{ schema_version = 1; installer = $newInstallerHash; module = $newModuleHash; cli = 'not-a-digest' })
        if ($null -ne (Get-DefenseClawPendingTransactionLifecyclePins -Layout $layout)) {
            $failures.Add('module pins reader: pins with a malformed cli digest were returned')
        }
        Write-ModuleJson $pinsPath ([ordered]@{ schema_version = 1; installer = $newInstallerHash; module = $newModuleHash; cli = $newCliHash })
        $script:UntrustedWriteAce = $pinsPath
        if ($null -ne (Get-DefenseClawPendingTransactionLifecyclePins -Layout $layout)) {
            $failures.Add('module pins reader: pins with a Users write ACE were returned')
        }
        $script:UntrustedWriteAce = ''
        $script:UntrustedReadAce = $pinsPath
        if ($null -ne (Get-DefenseClawPendingTransactionLifecyclePins -Layout $layout)) {
            $failures.Add('module pins reader: pins with a Users read ACE were returned')
        }
        $script:UntrustedReadAce = ''
        Write-ModuleJson $layout.PendingPath @{ snapshot = [IO.Path]::Combine($root, 'elsewhere', 'snapshot.json') }
        if ($null -ne (Get-DefenseClawPendingTransactionLifecyclePins -Layout $layout)) {
            $failures.Add('module pins reader: a snapshot outside transactions returned pins')
        }
        Write-ModuleJson $layout.PendingPath @{ snapshot = [IO.Path]::Combine($transactionsDir, ('d' * 32), '..', ('f' * 32), 'snapshot.json') }
        if ($null -ne (Get-DefenseClawPendingTransactionLifecyclePins -Layout $layout)) {
            $failures.Add('module pins reader: a snapshot that leaves its transaction directory returned pins')
        }
        Write-ModuleJson $layout.PendingPath @{ snapshot = [IO.Path]::Combine($transaction, 'snapshot.json') }

        # Re-admission (swap).
        $metadata = [pscustomobject]@{
            trust_mode = 'hash_pinned'
            hashes = [pscustomobject]@{ installer = $oldInstallerHash; module = $oldModuleHash; gateway = $gatewayHash; cli = $oldCliHash }
        }
        Set-TestText $layout.CLIPath $oldCli
        function Test-Swap([string]$Label, [string]$InstallerText, [string]$ModuleText, [string]$WantInstaller, [string]$WantModule, $Metadata = $metadata, [hashtable]$Preset = @{}) {
            Set-TestText $layout.InstallerPath $InstallerText
            Set-TestText $layout.ModulePath $ModuleText
            $script:DefenseClawTrustMode = 'Authenticode'
            $script:DefenseClawPinnedPayloadSHA256 = @{}
            foreach ($key in $Preset.Keys) { $script:DefenseClawPinnedPayloadSHA256[$key] = $Preset[$key] }
            Initialize-DefenseClawRecordedPayloadTrust -Metadata $Metadata -Layout $layout
            $gotInstaller = [string]$script:DefenseClawPinnedPayloadSHA256['install-enterprise.ps1']
            $gotModule = [string]$script:DefenseClawPinnedPayloadSHA256['defenseclawenterprise.psm1']
            if ($gotInstaller -cne $WantInstaller -or $gotModule -cne $WantModule) {
                $failures.Add("${Label}: installer pin '$gotInstaller' module pin '$gotModule', want '$WantInstaller' '$WantModule'")
            }
            return $script:DefenseClawPinnedPayloadSHA256
        }
        $map = Test-Swap 'swap: both files are the pinned pair' $newInstaller $newModule $newInstallerHash $newModuleHash
        if ([string]$map['defenseclaw-gateway.exe'] -cne $gatewayHash -or $script:DefenseClawTrustMode -cne 'HashPinned') {
            $failures.Add('swap: the pinned pair replaced more than the installer and module leaves')
        }
        [void](Test-Swap 'swap: installer is the pin, module is not' $newInstaller $oldModule $oldInstallerHash $oldModuleHash)
        [void](Test-Swap 'swap: module is the pin, installer is not' $oldInstaller $newModule $oldInstallerHash $oldModuleHash)
        $manifestModule = 'a' * 64
        [void](Test-Swap 'swap: a payload manifest pin is kept' $newInstaller $newModule $newInstallerHash $manifestModule `
            $metadata @{ 'defenseclawenterprise.psm1' = $manifestModule })
        $authenticodeMetadata = [pscustomobject]@{ trust_mode = 'authenticode'; hashes = $metadata.hashes }
        Set-TestText $layout.CLIPath $newCli
        $map = Test-Swap 'swap: an Authenticode deployment admits nothing by hash' $newInstaller $newModule '' '' $authenticodeMetadata
        if ([string]$map['defenseclaw.exe'] -cne '') {
            $failures.Add("swap: an Authenticode deployment pinned the CLI ('$([string]$map['defenseclaw.exe'])')")
        }
        # The CLI follows the pair, only while the file on disk is its pin (g649 review F4).
        Set-TestText $layout.CLIPath $newCli
        $map = Test-Swap 'swap: the pair and the pinned CLI' $newInstaller $newModule $newInstallerHash $newModuleHash
        if ([string]$map['defenseclaw.exe'] -cne $newCliHash) {
            $failures.Add("swap: the pinned CLI on disk was not admitted ('$([string]$map['defenseclaw.exe'])')")
        }
        $manifestCli = 'b' * 64
        $map = Test-Swap 'swap: a payload manifest CLI pin is kept' $newInstaller $newModule $newInstallerHash $newModuleHash `
            $metadata @{ 'defenseclaw.exe' = $manifestCli }
        if ([string]$map['defenseclaw.exe'] -cne $manifestCli) {
            $failures.Add("swap: a payload manifest CLI pin was replaced ('$([string]$map['defenseclaw.exe'])')")
        }
        $map = Test-Swap 'swap: the pinned CLI without the pair' $newInstaller $oldModule $oldInstallerHash $oldModuleHash
        if ([string]$map['defenseclaw.exe'] -cne $oldCliHash) {
            $failures.Add('swap: the pinned CLI was admitted without the pinned pair')
        }
        Set-TestText $layout.CLIPath $oldCli
        $map = Test-Swap 'swap: the pair with the recorded CLI' $newInstaller $newModule $newInstallerHash $newModuleHash
        if ([string]$map['defenseclaw.exe'] -cne $oldCliHash) {
            $failures.Add('swap: a CLI that is not the pinned one replaced the recorded pin')
        }
        Remove-Item -LiteralPath $layout.PendingPath -Force
        [void](Test-Swap 'swap: no pending transaction keeps the recorded pair' $newInstaller $newModule $oldInstallerHash $oldModuleHash)

        # Pins write.
        $snapshotPath = [IO.Path]::Combine($transaction, 'snapshot.json')
        Remove-Item -LiteralPath $pinsPath -Force
        $sources = @{
            installer = @{ sha256 = $newInstallerHash.ToUpperInvariant() }
            module = @{ sha256 = $newModuleHash }
            cli = @{ sha256 = $newCliHash }
            gateway = @{ sha256 = $gatewayHash }
        }
        $script:AclStamps.Clear()
        Write-DefenseClawTransactionLifecyclePins -SnapshotPath $snapshotPath -Sources $sources
        $written = Get-Content -LiteralPath $pinsPath -Raw | ConvertFrom-Json
        if ([string]$written.schema_version -cne '1' -or $written.installer -cne $newInstallerHash -or $written.module -cne $newModuleHash -or $written.cli -cne $newCliHash) {
            $failures.Add("pins write: wrote '$(Get-Content -LiteralPath $pinsPath -Raw)'")
        }
        if ($script:AclStamps.Count -ne 1 -or $script:AclStamps[0] -cne "AdminFile $pinsPath") {
            $failures.Add("pins write: ACL stamps '$($script:AclStamps -join ';')', want one AdminFile stamp")
        }
        Remove-Item -LiteralPath $pinsPath -Force
        Write-DefenseClawTransactionLifecyclePins -SnapshotPath $snapshotPath -Sources @{ gateway = @{ sha256 = $gatewayHash } }
        if (Test-Path -LiteralPath $pinsPath) {
            $failures.Add('pins write: a transaction without an installer and module wrote pins')
        }
        $script:StandaloneProfile = $false
        Write-DefenseClawTransactionLifecyclePins -SnapshotPath $snapshotPath -Sources $sources
        if (Test-Path -LiteralPath $pinsPath) {
            $failures.Add('pins write: Secure Client wrote pins')
        }
        $script:StandaloneProfile = $true
        try {
            Write-DefenseClawTransactionLifecyclePins -SnapshotPath $snapshotPath -Sources @{
                installer = @{ sha256 = 'not-a-digest' }; module = @{ sha256 = $newModuleHash }
            }
            $failures.Add('pins write: a malformed source digest was accepted')
        }
        catch {
            if (Test-Path -LiteralPath $pinsPath) {
                $failures.Add('pins write: a malformed source digest left a pins file')
            }
        }
        try {
            Write-DefenseClawTransactionLifecyclePins -SnapshotPath $snapshotPath -Sources @{
                installer = @{ sha256 = $newInstallerHash }; module = @{ sha256 = $newModuleHash }; cli = @{ sha256 = '' }
            }
            $failures.Add('pins write: a malformed cli digest was accepted')
        }
        catch {
            if (Test-Path -LiteralPath $pinsPath) {
                $failures.Add('pins write: a malformed cli digest left a pins file')
            }
        }

        # Repair stop after a recovery that restored another release.
        Set-TestText $layout.ModulePath $oldModule
        $script:DefenseClawRunningModuleSHA256 = $newModuleHash
        $recovered = [pscustomobject]@{ recovered = $true; fresh_install_rollback = $false }
        function Test-Stop([string]$Label, [bool]$Want, [string]$Action = 'Repair', $Recovery = $recovered, [hashtable]$Sources = @{}) {
            $got = [bool](Test-DefenseClawRecoveryRestoredOtherRelease -Layout $layout -Recovery $Recovery -Action $Action -Sources $Sources)
            if ($got -ne $Want) {
                $failures.Add("${Label}: stop after recovery $got, want $Want")
            }
        }
        Test-Stop 'Repair that restored another module' $true
        Test-Stop 'Upgrade' $false 'Upgrade'
        Test-Stop 'installed-CLI Uninstall that restored another module' $true 'Uninstall'
        Test-Stop 'Setup Uninstall that brings its own gateway' $false 'Uninstall' $recovered @{ gateway = @{ sha256 = $gatewayHash } }
        Test-Stop 'Install' $false 'Install'
        Test-Stop 'fresh install rollback' $false 'Repair' ([pscustomobject]@{ recovered = $true; fresh_install_rollback = $true })
        Test-Stop 'nothing recovered' $false 'Repair' ([pscustomobject]@{ recovered = $false; fresh_install_rollback = $false })
        Test-Stop 'Repair that brings its own gateway' $false 'Repair' $recovered @{ gateway = @{ sha256 = $gatewayHash } }
        $script:StandaloneProfile = $false
        Test-Stop 'Secure Client' $false
        $script:StandaloneProfile = $true
        $script:DefenseClawRunningModuleSHA256 = $oldModuleHash
        Test-Stop 'Repair that restored the running module' $false
    }
    finally {
        $script:StandaloneProfile = $true
        Microsoft.PowerShell.Management\Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
    }
}

if ($failures.Count -gt 0) {
    foreach ($failure in $failures) {
        Microsoft.PowerShell.Utility\Write-Output "FAIL: $failure"
    }
    exit 1
}
Microsoft.PowerShell.Utility\Write-Output 'enterprise-standalone-recorded-trust-smoke: OK'
