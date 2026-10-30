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

'resilience helpers smoke passed'
