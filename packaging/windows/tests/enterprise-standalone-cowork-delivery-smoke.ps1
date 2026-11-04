# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 7.0

[CmdletBinding()]
param([string]$ModulePath = ([IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\DefenseClawEnterprise.psm1'))))
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$marker = 'enterprise-standalone-cowork-delivery-smoke'
$tokens = $null
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($ModulePath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -ne 0) { throw "module parse failed: $($parseErrors[0].Message)" }

# Execute the production registry snapshot/restore functions against one
# temporary current-user key. The module's two Cowork policy-key variables
# are the only substitution: no system or Claude policy is changed here.
$testKey = 'SOFTWARE\DefenseClaw-Cowork-Smoke-' + [Guid]::NewGuid().ToString('N')
$script:CoworkPolicyHive = [Microsoft.Win32.RegistryHive]::CurrentUser
$script:CoworkPolicyKey = $testKey
foreach ($name in @('Get-DefenseClawCoworkRegistrySnapshot', 'Restore-DefenseClawCoworkRegistrySnapshot')) {
    $definition = $ast.Find({param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name
    }, $true)
    if ($null -eq $definition) { throw "missing Cowork lifecycle function $name" }
    if ($definition.Extent.Text.Contains('LocalMachine') -or $definition.Extent.Text.Contains('Policies\Claude')) {
        throw "$name must reach the Claude policy key only through the module's Cowork policy-key variables"
    }
    . ([ScriptBlock]::Create($definition.Extent.Text))
}
# Delivery writes the same two values: it may reach the key only through
# the variables too (it is run for real below, not dot-sourced here).
$definition = $ast.Find({param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Invoke-DefenseClawCoworkDelivery'
}, $true)
if ($null -eq $definition -or $definition.Extent.Text.Contains('LocalMachine') -or $definition.Extent.Text.Contains('Policies\Claude')) {
    throw "Invoke-DefenseClawCoworkDelivery must reach the Claude policy key only through the module's Cowork policy-key variables"
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

# Run the production Invoke-DefenseClawCoworkDelivery against temporary
# Program Files and ProgramData roots and a temporary HKCU policy key:
# ensure on, uninstall, ensure again, disable with administrator changes,
# and a refused ensure rolled back. Only the ACL setters and trust checks
# (which need real machine roots), the gateway's plan probe and the profile
# switch are stubbed; files, ownership record and registry writes are real.
$osRoot = [IO.Path]::GetPathRoot([Environment]::SystemDirectory)
$deliveryRoot = [IO.Path]::Combine($osRoot, 'dc-cowork-' + [Guid]::NewGuid().ToString('N').Substring(0, 12))
try { [void][IO.Directory]::CreateDirectory($deliveryRoot) }
catch {
    # CI runners are elevated: there an unwritable OS drive root is a failure.
    if (-not [string]::IsNullOrEmpty($env:CI)) {
        throw "the Windows OS drive root is not writable for the temporary Program Files root: $($_.Exception.Message)"
    }
    "${marker}: SKIP the Windows OS drive root is not writable for the temporary Program Files root: $($_.Exception.Message)"
    exit 0
}
$deliveryKey = 'SOFTWARE\DefenseClaw-Cowork-Delivery-' + [Guid]::NewGuid().ToString('N')
$module = Microsoft.PowerShell.Core\Import-Module -Name $ModulePath -Force -PassThru -ErrorAction Stop
try {
    & $module {
        param($Root, $Key)
        Set-StrictMode -Version Latest
        $ErrorActionPreference = 'Stop'
        $script:ProgramFiles = [IO.Path]::Combine($Root, 'Program Files')
        $script:CoworkPolicyHive = [Microsoft.Win32.RegistryHive]::CurrentUser
        $script:CoworkPolicyKey = $Key
        [void][IO.Directory]::CreateDirectory($script:ProgramFiles)
        $state = [IO.Path]::Combine($Root, 'ProgramData', 'Cisco', 'DefenseClaw', 'install')
        [void][IO.Directory]::CreateDirectory($state)
        $layout = @{ InstallStateDirectory = $state }
        $paths = Get-DefenseClawCoworkPaths -Layout $layout

        function Test-DefenseClawStandaloneProfile { return $true }
        function Assert-DefenseClawTrustedAncestor { param([string]$Path, [switch]$Strict) }
        function Assert-DefenseClawPathAcl {
            param([string]$Path, [string[]]$AllowedWriterSIDs, [string[]]$AllowedReaderSIDs, $RequiredRights,
                [switch]$AllowUsersRead, [switch]$AllowInheritance, [switch]$RejectUntrustedRead)
        }
        function Assert-DefenseClawCoworkPublicPath {
            param([string]$Path, [switch]$Directory, [switch]$AllowReaderRepair)
            $item = Microsoft.PowerShell.Management\Get-Item -LiteralPath $Path -Force
            if ([bool]$item.PSIsContainer -ne [bool]$Directory) { throw "Cowork path has the wrong type: $Path" }
        }
        $script:smokeAcl = [Collections.Generic.List[string]]::new()
        function Set-DefenseClawPathAcl {
            param([string]$Path, [string]$Kind, [string]$GatewayServiceSID)
            $script:smokeAcl.Add("$Kind $Path")
        }
        function New-DefenseClawProtectedDirectory {
            param([string]$Path, [switch]$AllowUsersRead)
            if ([IO.Directory]::Exists($Path)) { return $false }
            [void][IO.Directory]::CreateDirectory($Path)
            return $true
        }
        $script:smokePlan = $null
        function Get-DefenseClawCoworkPlan {
            param($Layout, $GatewayServiceName, $GatewaySource, $ConfigPath, $CoworkPackagePath, $CoworkSignaturePath)
            return $script:smokePlan
        }
        function Get-Sha256 { param([string]$Path)
            (Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
        }
        function New-Snapshot {
            $path = [IO.Path]::Combine($state, 'snapshot-' + [Guid]::NewGuid().ToString('N') + '.json')
            Write-DefenseClawJsonAtomic -Path $path -Value @{
                cowork_registry = @(Get-DefenseClawCoworkRegistrySnapshot)
                cowork_directories = @(Get-DefenseClawCoworkDirectorySnapshot -Layout $layout)
                cowork_created_directories = @()
                cowork_cache_created = $false
            }
            return $path
        }
        function Get-PolicyValue { param([string]$Name)
            $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey($script:CoworkPolicyHive, [Microsoft.Win32.RegistryView]::Registry64)
            try {
                $k = $base.OpenSubKey($script:CoworkPolicyKey, $false)
                if ($null -eq $k -or @($k.GetValueNames()) -notcontains $Name) { if ($null -ne $k) { $k.Dispose() }; return $null }
                try { return [pscustomobject]@{ kind = [string]$k.GetValueKind($Name); value = $k.GetValue($Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) } }
                finally { $k.Dispose() }
            }
            finally { $base.Dispose() }
        }
        function Set-PolicyValue { param([string]$Name, $Value)
            $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey($script:CoworkPolicyHive, [Microsoft.Win32.RegistryView]::Registry64)
            try { $k = $base.CreateSubKey($script:CoworkPolicyKey, $true); try { $k.SetValue($Name, $Value, [Microsoft.Win32.RegistryValueKind]::String) } finally { $k.Dispose() } }
            finally { $base.Dispose() }
        }
        function Remove-PolicyValue { param([string]$Name)
            $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey($script:CoworkPolicyHive, [Microsoft.Win32.RegistryView]::Registry64)
            try { $k = $base.OpenSubKey($script:CoworkPolicyKey, $true); if ($null -ne $k) { try { $k.DeleteValue($Name, $false) } finally { $k.Dispose() } } }
            finally { $base.Dispose() }
        }

        $source = [IO.Path]::Combine($Root, 'source')
        [void][IO.Directory]::CreateDirectory($source)
        $archive = [IO.Path]::Combine($source, 'defenseclaw-cowork-amd64.tar.gz')
        [IO.File]::WriteAllBytes($archive, [byte[]](1..200))
        [IO.File]::WriteAllText("$archive.sig", 'detached test signature', [Text.ASCIIEncoding]::new())
        $package = [IO.Path]::Combine($paths.Directory, 'defenseclaw-cowork-amd64.tar.gz')
        $arguments = 'tenant=tenant_1,device=6f1c2a9e-3b7d-4e1f-9a2b-0c8d7e6f5a4b,collector=edr.example.test:443'
        $enabled = [pscustomobject]@{
            enabled = $true; cache_directory = ''; package_path = $package; arguments_path = $paths.Arguments
            source_archive = $archive; source_signature = "$archive.sig"
            package_sha256 = (Get-Sha256 $archive); signature_sha256 = (Get-Sha256 "$archive.sig")
            arguments = $arguments; vendor = 'testvendor'; registry_refusal = ''
        }
        $disabled = [pscustomobject]@{ enabled = $false }
        $owned = @($package, "$package.sig", $paths.Arguments)
        Set-PolicyValue -Name 'unrelatedPolicy' -Value 'keep'
        # The administrator already set the vendor value to the same REG_SZ.
        Set-PolicyValue -Name 'coworkEDRIntegrationVendor' -Value 'testvendor'

        function Assert-Delivered {
            foreach ($file in $owned) { if (-not [IO.File]::Exists($file)) { throw "ensure did not deliver $file" } }
            if ((Get-Sha256 $package) -cne $enabled.package_sha256) { throw 'delivered package differs from its pin' }
            $bytes = [IO.File]::ReadAllBytes($paths.Arguments)
            if ($bytes.Length -ne $arguments.Length -or @($bytes | Where-Object { $_ -gt 0x7e -or $_ -lt 0x21 }).Count -ne 0 -or
                [Text.Encoding]::ASCII.GetString($bytes) -cne $arguments) {
                throw 'install.args is not the exact ASCII arguments without BOM, newline or spaces'
            }
            $value = Get-PolicyValue 'coworkEDRIntegration'
            if ($null -eq $value -or $value.kind -cne 'String' -or [string]$value.value -cne $package) { throw 'coworkEDRIntegration is not the REG_SZ package path' }
            $vendor = Get-PolicyValue 'coworkEDRIntegrationVendor'
            if ($null -eq $vendor -or $vendor.kind -cne 'String' -or [string]$vendor.value -cne 'testvendor') { throw 'coworkEDRIntegrationVendor is not the REG_SZ vendor' }
            if ([string](Get-PolicyValue 'unrelatedPolicy').value -cne 'keep') { throw 'an unrelated Claude policy value changed' }
        }

        # 1. Ensure on, from nothing: both directories are created and owned.
        $script:smokePlan = $enabled
        $snapshot = New-Snapshot
        Invoke-DefenseClawCoworkDelivery -Layout $layout -GatewayServiceName 'DefenseClawGateway' -SnapshotPath $snapshot
        Assert-Delivered
        $record = Get-DefenseClawCoworkOwnership -Layout $layout
        if ($record.files.Count -ne 3 -or @($record.values).Count -ne 1 -or [string]@($record.values)[0].name -cne 'coworkEDRIntegration' -or
            @($record.directories).Count -ne 2) {
            throw "ownership record after ensure: $($record | ConvertTo-Json -Depth 6 -Compress)"
        }
        $created = @((Microsoft.PowerShell.Management\Get-Content -LiteralPath $snapshot -Raw | ConvertFrom-Json).cowork_created_directories)
        if ($created.Count -ne 2) { throw 'created directories were not recorded in the lifecycle snapshot' }
        if (-not @($script:smokeAcl | Where-Object { $_ -ceq "InstallFile $($paths.Arguments)" }).Count) { throw 'install.args did not get the public file ACL' }

        # 2. A repeated ensure changes nothing.
        $before = @($record.files.Keys | Sort-Object | ForEach-Object { "$_=$($record.files[$_])" }) -join ';'
        Invoke-DefenseClawCoworkDelivery -Layout $layout -GatewayServiceName 'DefenseClawGateway' -SnapshotPath (New-Snapshot)
        Assert-Delivered
        $again = Get-DefenseClawCoworkOwnership -Layout $layout
        $after = @($again.files.Keys | Sort-Object | ForEach-Object { "$_=$($again.files[$_])" }) -join ';'
        if ($after -cne $before -or @($again.values).Count -ne 1 -or @($again.directories).Count -ne 2) {
            throw 'a repeated ensure changed the ownership record'
        }

        # 3. Uninstall removes only what DefenseClaw owns.
        Invoke-DefenseClawCoworkDelivery -Layout $layout -GatewayServiceName 'DefenseClawGateway' -SnapshotPath '' -Remove
        foreach ($file in $owned) { if ([IO.File]::Exists($file)) { throw "uninstall left $file" } }
        if ([IO.Directory]::Exists($paths.Directory) -or [IO.Directory]::Exists($paths.Parent)) { throw 'uninstall left the directories it created' }
        if ($null -ne (Get-PolicyValue 'coworkEDRIntegration')) { throw 'uninstall left the owned registry value' }
        if ([string](Get-PolicyValue 'coworkEDRIntegrationVendor').value -cne 'testvendor') { throw 'uninstall removed the administrator vendor value' }
        if ([IO.File]::Exists($paths.Record)) { throw 'uninstall left the ownership record' }

        # 4. Disable keeps administrator replacements and additions.
        Invoke-DefenseClawCoworkDelivery -Layout $layout -GatewayServiceName 'DefenseClawGateway' -SnapshotPath (New-Snapshot)
        Assert-Delivered
        [IO.File]::WriteAllText("$package.sig", 'administrator signature')
        $notes = [IO.Path]::Combine($paths.Directory, 'administrator-notes.txt')
        [IO.File]::WriteAllText($notes, 'keep')
        $script:smokePlan = $disabled
        $kept = @(Invoke-DefenseClawCoworkDelivery -Layout $layout -GatewayServiceName 'DefenseClawGateway' -SnapshotPath (New-Snapshot) 3>&1)
        if ([IO.File]::Exists($package) -or [IO.File]::Exists($paths.Arguments)) { throw 'disable left an unchanged owned file' }
        if ([IO.File]::ReadAllText("$package.sig") -cne 'administrator signature' -or -not [IO.File]::Exists($notes)) { throw 'disable removed administrator files' }
        if (-not @($kept | Where-Object { $_ -is [Management.Automation.WarningRecord] -and $_.Message -like '*changed after DefenseClaw wrote it*' }).Count) {
            throw 'disable did not warn about the kept replacement'
        }
        if ($null -ne (Get-PolicyValue 'coworkEDRIntegration') -or [string](Get-PolicyValue 'coworkEDRIntegrationVendor').value -cne 'testvendor') {
            throw 'disable did not remove only the owned registry value'
        }
        if (-not [IO.Directory]::Exists($paths.Directory) -or [IO.File]::Exists($paths.Record)) { throw 'disable removed a non-empty directory or kept the record' }
        [IO.File]::Delete("$package.sig"); [IO.File]::Delete($notes)
        [IO.Directory]::Delete($paths.Directory); [IO.Directory]::Delete($paths.Parent)

        # 5. A refused ensure rolls back: an administrator vendor value that
        # differs stops delivery after the files and the package value were
        # written; the transaction restores the registry preimage, removes
        # the files it created (absent preimages) and the created directories.
        Set-PolicyValue -Name 'coworkEDRIntegrationVendor' -Value 'othervendor'
        $script:smokePlan = $enabled
        $snapshot = New-Snapshot
        $refused = $false
        try { Invoke-DefenseClawCoworkDelivery -Layout $layout -GatewayServiceName 'DefenseClawGateway' -SnapshotPath $snapshot }
        catch { $refused = $_.Exception.Message -like '*refuses to replace administrator registry value coworkEDRIntegrationVendor*' }
        if (-not $refused) { throw 'delivery replaced a differing administrator registry value' }
        if ($null -eq (Get-PolicyValue 'coworkEDRIntegration')) { throw 'the refusal case did not reach the registry step' }
        $saved = Microsoft.PowerShell.Management\Get-Content -LiteralPath $snapshot -Raw | ConvertFrom-Json
        Restore-DefenseClawCoworkRegistrySnapshot -Entries $saved.cowork_registry
        # The shared transaction restores the Cowork file preimages (absent
        # here) with every other recorded file before these two run
        # (DefenseClawEnterprise.psm1, the cowork_registry restore); this
        # smoke stands in for that file step by removing the new files.
        foreach ($file in $owned) { if ([IO.File]::Exists($file)) { [IO.File]::Delete($file) } }
        Restore-DefenseClawCoworkCreatedDirectories -Layout $layout -Snapshot $saved
        if ($null -ne (Get-PolicyValue 'coworkEDRIntegration') -or [string](Get-PolicyValue 'coworkEDRIntegrationVendor').value -cne 'othervendor' -or
            [string](Get-PolicyValue 'unrelatedPolicy').value -cne 'keep') {
            throw 'rollback did not restore the registry preimage'
        }
        if ([IO.Directory]::Exists($paths.Directory) -or [IO.Directory]::Exists($paths.Parent) -or [IO.File]::Exists($paths.Record)) {
            throw 'rollback left created directories or an ownership record'
        }

        # 6. Explicit inputs fill the lifecycle cache. Turning delivery off
        # removes the cache files and the cache folder DefenseClaw created,
        # once empty; a cache folder the administrator created stays
        # (GAP-0035).
        Set-PolicyValue -Name 'coworkEDRIntegrationVendor' -Value 'testvendor'
        $cached = $enabled.PSObject.Copy()
        $cached.cache_directory = $paths.Cache
        foreach ($adminCache in @($false, $true)) {
            if ($adminCache) { [void][IO.Directory]::CreateDirectory($paths.Cache) }
            $script:smokePlan = $cached
            Invoke-DefenseClawCoworkDelivery -Layout $layout -GatewayServiceName 'DefenseClawGateway' -SnapshotPath (New-Snapshot)
            Assert-Delivered
            $record = Get-DefenseClawCoworkOwnership -Layout $layout
            if ([bool]$record.cache_directory_owned -eq $adminCache -or $record.cache_files.Count -ne 2) {
                throw "cache ownership after ensure (administrator folder: $adminCache): $($record | ConvertTo-Json -Depth 6 -Compress)"
            }
            $script:smokePlan = $disabled
            Invoke-DefenseClawCoworkDelivery -Layout $layout -GatewayServiceName 'DefenseClawGateway' -SnapshotPath (New-Snapshot)
            if ([IO.Directory]::Exists($paths.Cache) -and @(Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $paths.Cache -Force).Count -ne 0) {
                throw 'disable left the cache files'
            }
            if ([IO.Directory]::Exists($paths.Cache) -ne $adminCache) {
                throw "disable did not remove only the cache folder DefenseClaw created (administrator folder: $adminCache)"
            }
            if ([IO.Directory]::Exists($paths.Directory) -or [IO.Directory]::Exists($paths.Parent) -or [IO.File]::Exists($paths.Record)) {
                throw 'disable left the Cowork folders or the ownership record'
            }
        }
        [IO.Directory]::Delete($paths.Cache)
    } $deliveryRoot $deliveryKey
}
finally {
    Microsoft.PowerShell.Core\Remove-Module -ModuleInfo $module -Force -ErrorAction SilentlyContinue
    $cleanupBase = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
        [Microsoft.Win32.RegistryHive]::CurrentUser, [Microsoft.Win32.RegistryView]::Registry64)
    try { $cleanupBase.DeleteSubKeyTree($deliveryKey, $false) } finally { $cleanupBase.Dispose() }
    if ([IO.Directory]::Exists($deliveryRoot)) { [IO.Directory]::Delete($deliveryRoot, $true) }
}
'Cowork delivery ensure, uninstall, disable, rollback and cache checks passed'
'enterprise-standalone-cowork-delivery-smoke: OK'
