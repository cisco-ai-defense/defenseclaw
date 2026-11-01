# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 5.1

# Permission drift is judged by effective write authority, not by exact
# descriptor equality, and every repair, acceptance and recovery is logged with
# a stable marker followed by key="value" fields in key order (the same line
# the Go components write). The helpers are loaded from the module by AST, so
# the string and rights checks also run under pwsh off Windows; descriptor
# checks run only where the ACL APIs exist.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modulePath = [IO.Path]::GetFullPath(
    [IO.Path]::Combine($PSScriptRoot, '..', 'DefenseClawEnterprise.psm1')
)
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($modulePath, [ref]$null, [ref]$parseErrors)
if (@($parseErrors).Count -ne 0) {
    throw "module does not parse: $(@($parseErrors)[0])"
}
foreach ($name in @(
        'ConvertTo-DefenseClawResilienceFieldValue',
        'Format-DefenseClawResilienceEvent',
        'Write-DefenseClawResilienceEvent',
        'Get-DefenseClawResilienceEvents',
        'Sync-DefenseClawNativeResilienceEvents',
        'Get-DefenseClawAddTypeFailure',
        'Get-DefenseClawPolicyBlockEvent',
        'Get-DefenseClawMissingFilePrivileges',
        'Get-DefenseClawMissingPrivilegeFromError',
        'Test-DefenseClawWriteLikeRights',
        'ConvertTo-DefenseClawMappedFileRights',
        'Test-DefenseClawCreateChildOnlyRights',
        'ConvertTo-DefenseClawMappedRegistryRights',
        'Get-DefenseClawServiceDaclUntrustedWriter',
        'Get-DefenseClawRawDescriptorFindings',
        'Test-DefenseClawTrustStrictAncestors'
    )) {
    $definition = $ast.Find({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
        }, $true)
    if ($null -eq $definition) {
        throw "module does not define $name"
    }
    . ([scriptblock]::Create($definition.Extent.Text))
}

$script:ResilienceMarkers = @(
    'defenseclaw_repair', 'defenseclaw_accept', 'defenseclaw_skip',
    'defenseclaw_boundary', 'defenseclaw_prereq', 'defenseclaw_recover',
    'defenseclaw_degraded'
)
$script:ResilienceEvents = [Collections.Generic.List[string]]::new()
$script:DefenseClawNativeSecurityType = $null
$script:SystemSID = 'S-1-5-18'
$script:AdministratorsSID = 'S-1-5-32-544'
$script:TrustedInstallerSID = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
$script:OwnerRightsSID = 'S-1-3-4'
$script:TrustStrictAncestorsEnv = 'DEFENSECLAW_MANAGED_TRUST_STRICT_ANCESTORS'

# Log line contract: marker, then sorted keys, values quoted like Go's
# strconv.Quote.
$line = Format-DefenseClawResilienceEvent -Marker defenseclaw_repair -Fields @{
    reason = 'said "hi"'
    path   = 'C:\ProgramData\Cisco\x'
}
$expected = 'defenseclaw_repair path="C:\\ProgramData\\Cisco\\x" reason="said \"hi\""'
if ($line -cne $expected) {
    throw "resilience line is not in the shared format: $line"
}
if ((Format-DefenseClawResilienceEvent -Marker defenseclaw_skip -Fields @{ b = "x`ny"; a = '' }) -cne
    'defenseclaw_skip a="" b="x\ny"') {
    throw 'resilience fields are not sorted or control characters are not escaped'
}
$rejected = $false
try {
    [void](Format-DefenseClawResilienceEvent -Marker 'defenseclaw_unknown')
}
catch {
    $rejected = $true
}
if (-not $rejected) {
    throw 'an unknown resilience marker was accepted'
}
Write-DefenseClawResilienceEvent -Marker defenseclaw_accept -Fields @{ path = 'p' } 3>$null
$kept = @(Get-DefenseClawResilienceEvents)
if ($kept.Count -ne 1 -or $kept[0] -cne 'defenseclaw_accept path="p"') {
    throw 'a written resilience event was not kept for the action result'
}

# Generic rights are judged exactly like the specific rights they map to.
$genericAll = [Enum]::ToObject([Security.AccessControl.FileSystemRights], 0x10000000)
$mapped = ConvertTo-DefenseClawMappedFileRights -Rights $genericAll
if (([int]$mapped -band 0x1f01ff) -ne 0x1f01ff) {
    throw 'GENERIC_ALL does not map to full file access'
}
$genericRead = [Enum]::ToObject([Security.AccessControl.FileSystemRights], [int]-2147483648)
if (Test-DefenseClawWriteLikeRights -Rights (ConvertTo-DefenseClawMappedFileRights -Rights $genericRead)) {
    throw 'GENERIC_READ was judged write-like'
}
if (([int](ConvertTo-DefenseClawMappedRegistryRights -Rights ([Enum]::ToObject([Security.AccessControl.RegistryRights], 0x10000000))) -band 0xf003f) -ne 0xf003f) {
    throw 'GENERIC_ALL does not map to full registry access'
}

# ProgramData's inherited Users entry lets users add children but never
# delete, rename or re-ACL what is already there.
if (-not (Test-DefenseClawCreateChildOnlyRights -Rights ([Security.AccessControl.FileSystemRights]0x116))) {
    throw 'the ProgramData Users create-child entry was judged as more than create-child'
}
foreach ($rights in @(
        [Security.AccessControl.FileSystemRights]::Modify,
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles,
        [Security.AccessControl.FileSystemRights]::ChangePermissions
    )) {
    if (Test-DefenseClawCreateChildOnlyRights -Rights $rights) {
        throw "rights $rights were judged create-child only"
    }
}

$aclApis = $true
try {
    [void][Security.AccessControl.RawSecurityDescriptor]::new('O:BAG:BAD:P(A;;FA;;;SY)')
}
catch {
    $aclApis = $false
}
if ($aclApis) {
    $canonical = [Security.AccessControl.RawSecurityDescriptor]::new(
        'O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)'
    )
    foreach ($case in @(
            @{ label = 'extra read entry'; sddl = 'O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)'; untrusted = $false },
            @{ label = 'inherited entries'; sddl = 'O:BAG:SYD:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;0x1200a9;;;BU)'; untrusted = $false },
            @{ label = 'inherit-only CREATOR OWNER'; sddl = 'O:BAG:BAD:(A;;FA;;;SY)(A;;FA;;;BA)(A;OICIIO;GA;;;CO)'; untrusted = $false },
            @{ label = 'TrustedInstaller owner'; sddl = 'O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464G:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)'; untrusted = $false },
            @{ label = 'reordered and generic'; sddl = 'O:BAG:BAD:P(A;;GA;;;BA)(A;;FA;;;SY)'; untrusted = $false },
            @{ label = 'deny for an unrelated principal'; sddl = 'O:BAG:BAD:P(D;;FA;;;BG)(A;;FA;;;SY)(A;;FA;;;BA)'; untrusted = $false },
            @{ label = 'extra write entry'; sddl = 'O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x116;;;BU)'; untrusted = $true },
            @{ label = 'user owner'; sddl = 'O:S-1-5-21-1-2-3-1001G:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)'; untrusted = $true }
        )) {
        $findings = @(Get-DefenseClawRawDescriptorFindings `
            -Path $case.label `
            -Actual ([Security.AccessControl.RawSecurityDescriptor]::new($case.sddl)) `
            -Expected $canonical)
        $hasUntrusted = @($findings | Where-Object { $_.Severity -eq 'Untrusted' }).Count -gt 0
        if ($hasUntrusted -ne [bool]$case.untrusted) {
            throw "descriptor drift '$($case.label)' was judged untrusted=$hasUntrusted"
        }
    }
    if (-not [string]::IsNullOrEmpty(
            (Get-DefenseClawServiceDaclUntrustedWriter -Dacl 'D:(A;;CCLCSWLORC;;;BU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLORC;;;AU)'))) {
        throw 'a query-only service entry was judged able to reconfigure the service'
    }
    if ((Get-DefenseClawServiceDaclUntrustedWriter -Dacl 'D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BU)') -cne 'S-1-5-32-545') {
        throw 'a Users service entry with change-config was not reported'
    }
}

# Add-Type failures are named from numeric codes and error IDs only.
function New-SmokeErrorRecord {
    param([Parameter(Mandatory)][Exception]$Exception, [string]$Id = 'AddTypeFailure')
    return [Management.Automation.ErrorRecord]::new(
        $Exception,
        $Id,
        [Management.Automation.ErrorCategory]::NotSpecified,
        $null
    )
}
$wrappedAppLocker = [Management.Automation.MethodInvocationException]::new(
    'outer',
    [ComponentModel.Win32Exception]::new(1260)
)
foreach ($case in @(
        @{ record = (New-SmokeErrorRecord -Exception $wrappedAppLocker); policy = 'applocker_or_srp'; win32 = '1260' },
        @{ record = (New-SmokeErrorRecord -Exception ([ComponentModel.Win32Exception]::new(4551))); policy = 'wdac_or_smart_app_control'; win32 = '4551' },
        @{ record = (New-SmokeErrorRecord -Exception ([Runtime.InteropServices.COMException]::new('x', [int]-2147020345))); policy = 'wdac_or_smart_app_control'; win32 = '4551' },
        @{ record = (New-SmokeErrorRecord -Exception ([ComponentModel.Win32Exception]::new(225))); policy = 'defender_or_asr'; win32 = '225' },
        @{ record = (New-SmokeErrorRecord -Exception ([ComponentModel.Win32Exception]::new(112))); policy = 'compiler_temp_unusable'; win32 = '112' },
        @{ record = (New-SmokeErrorRecord -Exception ([IO.IOException]::new('locked'))); policy = 'compiler_temp_unusable'; win32 = '' },
        @{ record = (New-SmokeErrorRecord -Exception ([Management.Automation.RuntimeException]::new('blocked')) -Id 'ScriptContainedMaliciousContent,Microsoft.PowerShell.Commands.AddTypeCommand'); policy = 'amsi'; win32 = '' }
    )) {
    $line = Get-DefenseClawAddTypeFailure -ErrorRecord $case.record
    if ($line -notlike 'defenseclaw_prereq check="powershell_add_type" *' -or
        $line -notlike "* policy=`"$($case.policy)`"*" -or
        $line -notlike "* win32=`"$($case.win32)`"*" -or
        $line -notmatch ' path="[^"]*csc\.exe"') {
        throw "Add-Type failure was not classified as $($case.policy): $line"
    }
}
$unclassified = Get-DefenseClawAddTypeFailure -ErrorRecord (
    New-SmokeErrorRecord -Exception ([InvalidOperationException]::new('CS1002: ; expected'))
)
if ($null -ne $unclassified) {
    throw "a compile error was classified as a policy block: $unclassified"
}
$importBlock = Get-DefenseClawAddTypeFailure `
    -ErrorRecord (New-SmokeErrorRecord -Exception ([Management.Automation.RuntimeException]::new('x')) -Id 'ScriptContainedMaliciousContent') `
    -Check 'powershell_module_import' `
    -Path 'C:\m.psm1'
if ($importBlock -cne 'defenseclaw_prereq check="powershell_module_import" path="C:\\m.psm1" policy="amsi" win32=""') {
    throw "module import block was not reported in the shared format: $importBlock"
}

# Missing file privileges are named; a 1300 failure names its privilege.
$missing = @(Get-DefenseClawMissingFilePrivileges -Held @('SeBackupPrivilege', 'SeChangeNotifyPrivilege'))
if (($missing -join ',') -cne 'SeRestorePrivilege,SeTakeOwnershipPrivilege') {
    throw "missing file privileges were not reported: $($missing -join ',')"
}
$lacks = [ComponentModel.Win32Exception]::new(1300, 'installer token lacks SeRestorePrivilege for uninstall ACL recovery')
if ((Get-DefenseClawMissingPrivilegeFromError -Exception ([Management.Automation.MethodInvocationException]::new('outer', $lacks))) -cne 'SeRestorePrivilege') {
    throw 'a Win32 1300 failure did not name its privilege'
}
if ((Get-DefenseClawMissingPrivilegeFromError -Exception ([ComponentModel.Win32Exception]::new(5))) -ne '') {
    throw 'an access denial was reported as a missing privilege'
}

# The installer's bootstrap helpers run before the module exists and keep the
# same line format; drift they accept travels in the JSON verdict.
$installerPath = [IO.Path]::GetFullPath(
    [IO.Path]::Combine($PSScriptRoot, '..', 'install-enterprise.ps1')
)
$installerAst = [Management.Automation.Language.Parser]::ParseFile($installerPath, [ref]$null, [ref]$parseErrors)
if (@($parseErrors).Count -ne 0) {
    throw "installer does not parse: $(@($parseErrors)[0])"
}
foreach ($name in @(
        'Format-DefenseClawBootstrapResilienceEvent',
        'Add-DefenseClawBootstrapResilienceEvent',
        'Get-DefenseClawBootstrapAddTypeFailure',
        'Get-DefenseClawBootstrapPolicyBlockEvent',
        'Test-DefenseClawBootstrapAdminEquivalentSID',
        'Get-DefenseClawBootstrapOneShotRootDrift',
        'Test-DefenseClawBootstrapWriteLikeRights'
    )) {
    $definition = $installerAst.Find({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
        }, $true)
    if ($null -eq $definition) {
        throw "installer does not define $name"
    }
    . ([scriptblock]::Create($definition.Extent.Text))
}
$script:DefenseClawBootstrapResilienceEvents = [Collections.Generic.List[string]]::new()
$bootstrapLine = Format-DefenseClawBootstrapResilienceEvent -Marker defenseclaw_accept -Fields @{
    reason = 'said "hi"'
    path   = 'C:\ProgramData\Cisco\x'
}
if ($bootstrapLine -cne 'defenseclaw_accept path="C:\\ProgramData\\Cisco\\x" reason="said \"hi\""') {
    throw "bootstrap resilience line is not in the shared format: $bootstrapLine"
}
Add-DefenseClawBootstrapResilienceEvent -Marker defenseclaw_accept -Fields @{ path = 'p' }
Add-DefenseClawBootstrapResilienceEvent -Marker defenseclaw_accept -Fields @{ path = 'p' }
if ($script:DefenseClawBootstrapResilienceEvents.Count -ne 1) {
    throw 'a repeated bootstrap event was logged twice'
}
$bootstrapAddType = Get-DefenseClawBootstrapAddTypeFailure -ErrorRecord (
    New-SmokeErrorRecord -Exception $wrappedAppLocker
)
if ($bootstrapAddType -notlike 'defenseclaw_prereq check="powershell_add_type" path="*csc.exe" policy="applocker_or_srp" win32="1260"*') {
    throw "bootstrap Add-Type failure was not classified: $bootstrapAddType"
}
$script:DefenseClawBootstrapAdminEquivalentMembers = [string[]]@('S-1-5-21-7-8-9-1104')
foreach ($case in @(
        @{ sid = 'S-1-5-21-1-2-3-500'; admin = $true },
        @{ sid = 'S-1-5-21-1-2-3-512'; admin = $true },
        @{ sid = 'S-1-5-21-1-2-3-519'; admin = $true },
        @{ sid = 'S-1-5-21-7-8-9-1104'; admin = $true },
        @{ sid = 'S-1-5-21-1-2-3-1001'; admin = $false },
        @{ sid = 'S-1-5-32-545'; admin = $false },
        @{ sid = ''; admin = $false }
    )) {
    if ((Test-DefenseClawBootstrapAdminEquivalentSID -SID $case.sid) -ne $case.admin) {
        throw "bootstrap admin-equivalent owner rule misjudged '$($case.sid)'"
    }
}

# The one-shot bootstrap directory is judged by meaning: extra read or deny
# entries are accepted, a foreign writer or an unprotected DACL is re-stamped
# once, and a foreign owner is fatal. Runs where the ACL APIs exist.
$directoryAclApis = $true
try {
    [void][Security.AccessControl.DirectorySecurity]::new()
}
catch {
    $directoryAclApis = $false
}
if ($directoryAclApis) {
    $expectedRoot = [Security.AccessControl.DirectorySecurity]::new()
    $expectedRoot.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
    foreach ($case in @(
            @{ label = 'exact'; sddl = 'O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'; boundary = $false; repair = $false; accept = 0 },
            @{ label = 'extra read'; sddl = 'O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)'; boundary = $false; repair = $false; accept = 1 },
            @{ label = 'extra deny'; sddl = 'O:BAG:BAD:P(D;OICI;FA;;;BG)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'; boundary = $false; repair = $false; accept = 1 },
            @{ label = 'SYSTEM owner'; sddl = 'O:SYG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'; boundary = $false; repair = $false; accept = 1 },
            @{ label = 'foreign writer'; sddl = 'O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x116;;;BU)'; boundary = $false; repair = $true; accept = 0 },
            @{ label = 'unprotected'; sddl = 'O:BAG:BAD:(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'; boundary = $false; repair = $true; accept = 0 },
            @{ label = 'missing Administrators'; sddl = 'O:BAG:BAD:P(A;OICI;FA;;;SY)'; boundary = $false; repair = $true; accept = 0 },
            @{ label = 'foreign owner'; sddl = 'O:S-1-5-21-1-2-3-1001G:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'; boundary = $true; repair = $false; accept = 0 }
        )) {
        $actualRoot = [Security.AccessControl.DirectorySecurity]::new()
        $actualRoot.SetSecurityDescriptorSddlForm($case.sddl)
        $drift = Get-DefenseClawBootstrapOneShotRootDrift -Actual $actualRoot -Expected $expectedRoot
        if ((-not [string]::IsNullOrEmpty($drift.Boundary)) -ne $case.boundary -or
            ($drift.Repair.Count -gt 0) -ne $case.repair -or
            $drift.Accept.Count -ne $case.accept) {
            throw "bootstrap directory drift '$($case.label)' was misjudged: boundary=$($drift.Boundary) repair=$($drift.Repair -join ';') accept=$($drift.Accept -join ';')"
        }
    }
}

# The constrained-language guards answer before any .NET call: the installer
# with its standard JSON failure, the module with a message the installer's
# catch puts into that JSON.
$constrained = [powershell]::Create()
try {
    $constrained.Runspace.SessionStateProxy.LanguageMode = 'ConstrainedLanguage'
    [void]$constrained.AddCommand($installerPath).AddParameter('Json').AddParameter('Action', 'Status')
    $verdictText = (@($constrained.Invoke()) -join '')
}
finally {
    $constrained.Dispose()
}
$verdict = $verdictText | ConvertFrom-Json
if ($verdict.schema_version -ne 1 -or $verdict.ok -ne $false -or $verdict.action -cne 'status' -or
    [string]$verdict.error -notlike 'defenseclaw_prereq check="powershell_language_mode" language_mode="ConstrainedLanguage" policy="*"*' -or
    @($verdict.errors).Count -ne 1) {
    throw "installer constrained-language verdict is not the standard failure JSON: $verdictText"
}
$constrainedModule = [powershell]::Create()
$moduleRefusal = ''
try {
    $constrainedModule.Runspace.SessionStateProxy.LanguageMode = 'ConstrainedLanguage'
    [void]$constrainedModule.AddCommand('Microsoft.PowerShell.Core\Import-Module').AddParameter('Name', $modulePath)
    try {
        [void]$constrainedModule.Invoke()
    }
    catch {
        $moduleRefusal = [string]$_.Exception.InnerException.Message
    }
    if ([string]::IsNullOrEmpty($moduleRefusal) -and $constrainedModule.Streams.Error.Count -gt 0) {
        $moduleRefusal = [string]$constrainedModule.Streams.Error[0]
    }
}
finally {
    $constrainedModule.Dispose()
}
if ($moduleRefusal -notlike 'defenseclaw_prereq check="powershell_language_mode" language_mode="ConstrainedLanguage" policy="*"*') {
    throw "module constrained-language refusal did not name the prerequisite: $moduleRefusal"
}

'resilience helpers smoke passed'
