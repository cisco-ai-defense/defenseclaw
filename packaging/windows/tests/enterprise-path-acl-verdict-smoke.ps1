# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 5.1

# Table test for the permission verdicts of Assert-DefenseClawPathAcl and the
# canonical-descriptor checks it relies on. A verdict for drift a standard user
# could have created (a write-like grant, a foreign owner, an unreadable
# descriptor) stays fatal after the canonical re-stamp on the standalone
# profile, with and without DEFENSECLAW_MANAGED_TRUST_STRICT_ANCESTORS; only
# drift that needs an administrator (a read grant, a lost protected flag) may
# continue with a warning, and the strict pin restores those refusals too
# (GAP-0010). Secure Client keeps its earlier rules and is not covered here
# (Secure Client is out of scope for this fix).
# The verdict reader and the re-stamp are replaced inside the module, so the
# test touches no ACL on the machine.

[CmdletBinding()]
param()

Microsoft.PowerShell.Core\Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modulePath = [IO.Path]::GetFullPath((
    Microsoft.PowerShell.Management\Join-Path `
        $PSScriptRoot '..\DefenseClawEnterprise.psm1'
))
$module = Microsoft.PowerShell.Core\Import-Module `
    -Name $modulePath -Force -PassThru -DisableNameChecking -ErrorAction Stop `
    -WarningAction SilentlyContinue

$strictEnv = 'DEFENSECLAW_MANAGED_TRUST_STRICT_ANCESTORS'
$savedStrict = [Environment]::GetEnvironmentVariable($strictEnv, 'Process')
$fixture = [IO.Path]::Combine(
    [IO.Path]::GetTempPath(),
    'dc-path-acl-verdict-' + [Guid]::NewGuid().ToString('N') + '.bin'
)
[IO.File]::WriteAllBytes($fixture, [byte[]]@(0))

$write = @{ Kind = 'Access'; Severity = 'Write'; Reason = 'untrusted principal S-1-5-21-1-2-3-1001 has write-like access to managed path: x' }
$read = @{ Kind = 'Access'; Severity = 'Read'; Reason = 'untrusted principal S-1-5-21-1-2-3-1001 can read protected managed path: x' }
$inherit = @{ Kind = 'Access'; Severity = 'Inheritance'; Reason = 'managed DACL inherits from an ancestor: x' }
$owner = @{ Kind = 'Contract'; Reason = 'untrusted owner S-1-5-21-1-2-3-1001 on managed path: x' }
$rights = @{ Kind = 'Rights'; Reason = 'managed path is missing required rights for S-1-5-18: x' }

# before = first reading, after = reading after the re-stamp, stamp = what the
# re-stamp does, heal = -SelfHealKind given, advisory = -AdvisoryUntrustedAccess.
$cases = @(
    @{ name = 'write survives a re-stamp that does nothing'; before = @($write); after = @($write); stamp = 'noop'; strict = ''; expect = $write.Reason }
    @{ name = 'write survives a re-stamp that fails'; before = @($write); after = @($write); stamp = 'throw'; strict = ''; expect = $write.Reason }
    @{ name = 'write survives, strict pin'; before = @($write); after = @($write); stamp = 'noop'; strict = '1'; expect = $write.Reason }
    @{ name = 'write cleared by the re-stamp'; before = @($write); after = @(); stamp = 'noop'; strict = ''; expect = '' }
    @{ name = 'write behind a read keeps the write message'; before = @($read, $write); after = @($read, $write); stamp = 'noop'; strict = ''; expect = $write.Reason }
    @{ name = 'write without a self-heal'; before = @($write); after = $null; heal = $false; strict = ''; expect = $write.Reason }
    @{ name = 'read survives'; before = @($read); after = @($read); stamp = 'noop'; strict = ''; expect = '' }
    @{ name = 'read survives, strict pin'; before = @($read); after = @($read); stamp = 'noop'; strict = '1'; expect = $read.Reason }
    @{ name = 'lost protected flag survives the re-stamp'; before = @($inherit); after = @($inherit); stamp = 'throw'; strict = ''; expect = '' }
    @{ name = 'lost protected flag survives, strict pin'; before = @($inherit); after = @($inherit); stamp = 'noop'; strict = '1'; expect = $inherit.Reason }
    @{ name = 'lost protected flag without a self-heal'; before = @($inherit); after = $null; heal = $false; strict = ''; expect = $inherit.Reason }
    @{ name = 'foreign owner survives'; before = @($owner); after = @($owner); stamp = 'noop'; strict = ''; expect = $owner.Reason }
    @{ name = 'missing rights survive'; before = @($rights); after = @($rights); stamp = 'noop'; strict = ''; expect = $rights.Reason }
    @{ name = 'standalone state root has no advisory'; before = @($write); after = @($write); stamp = 'noop'; strict = ''; advisory = $true; expect = $write.Reason }
)

$failures = [Collections.Generic.List[string]]::new()
try {
    # Canonical-descriptor check of a DACL that lost SE_DACL_PROTECTED: the lost
    # flag may continue outside the strict pin, the owner and every ACE are
    # still judged. The path does not exist, so the icacls repair attempt and
    # its native re-read fail and the descriptor under test is what is judged.
    $user = 'S-1-5-21-1-2-3-1001'
    $rawCases = @(
        @{ name = 'protected canonical'; protected = $true; owner = ''; ace = $null; strict = ''; expect = '' }
        @{ name = 'protected with an extra explicit ACE'; protected = $true; owner = ''; ace = @{ flags = 'None'; mask = 0x1200A9; sid = $user }; strict = ''; expect = 'managed path does not have the exact canonical DACL' }
        @{ name = 'lost protected flag only'; protected = $false; owner = ''; ace = $null; strict = ''; expect = '' }
        @{ name = 'lost protected flag, strict pin'; protected = $false; owner = ''; ace = $null; strict = '1'; expect = 'managed DACL is not protected after exact ACL replacement' }
        @{ name = 'lost protected flag and a user owner'; protected = $false; owner = $user; ace = $null; strict = ''; expect = 'managed path owner/group do not match the exact canonical descriptor after ACL replacement' }
        @{ name = 'lost protected flag and an explicit user write ACE'; protected = $false; owner = ''; ace = @{ flags = 'None'; mask = 0x116; sid = $user }; strict = ''; expect = 'managed path does not have the exact canonical DACL' }
        @{ name = 'lost protected flag and an inherited Users write ACE'; protected = $false; owner = ''; ace = @{ flags = 'Inherited'; mask = 0x116; sid = 'S-1-5-32-545' }; strict = ''; expect = 'untrusted principal S-1-5-32-545 has inherited write-like access to managed path' }
        @{ name = 'lost protected flag and an inherited GENERIC_WRITE ACE'; protected = $false; owner = ''; ace = @{ flags = 'Inherited'; mask = 0x40000000; sid = $user }; strict = ''; expect = "untrusted principal $user has inherited write-like access to managed path" }
        @{ name = 'lost protected flag and an inherited Users read ACE'; protected = $false; owner = ''; ace = @{ flags = 'Inherited'; mask = 0x1200A9; sid = 'S-1-5-32-545' }; strict = ''; expect = '' }
        @{ name = 'lost protected flag and an inherited SYSTEM ACE'; protected = $false; owner = ''; ace = @{ flags = 'Inherited'; mask = 0x1F01FF; sid = 'S-1-5-18' }; strict = ''; expect = '' }
        @{ name = 'lost protected flag and an inherited CREATOR OWNER template'; protected = $false; owner = ''; ace = @{ flags = 'Inherited, InheritOnly, ObjectInherit'; mask = 0x10000000; sid = 'S-1-3-0' }; strict = ''; expect = '' }
    )
    foreach ($case in $rawCases) {
        [Environment]::SetEnvironmentVariable($strictEnv, [string]$case['strict'], 'Process')
        $observed = & $module {
            param($Case, $Missing)
            $script:DefenseClawEnterpriseProfile = 'Standalone'
            $expected = New-DefenseClawCanonicalPathAcl -IsDirectory:$false -Kind AdminFile -GatewayServiceSID $script:AdministratorsSID
            $raw = [Security.AccessControl.RawSecurityDescriptor]::new($expected.GetSecurityDescriptorBinaryForm(), 0)
            if (-not [bool]$Case['protected']) {
                $raw.SetFlags([Security.AccessControl.ControlFlags](
                    [int]$raw.ControlFlags -band (-bnot [int][Security.AccessControl.ControlFlags]::DiscretionaryAclProtected)
                ))
            }
            if (-not [string]::IsNullOrEmpty([string]$Case['owner'])) {
                $raw.Owner = [Security.Principal.SecurityIdentifier]::new([string]$Case['owner'])
            }
            $ace = $Case['ace']
            if ($null -ne $ace) {
                $raw.DiscretionaryAcl.InsertAce($raw.DiscretionaryAcl.Count, [Security.AccessControl.CommonAce]::new(
                    [Security.AccessControl.AceFlags]([string]$ace['flags']),
                    [Security.AccessControl.AceQualifier]::AccessAllowed,
                    [int]$ace['mask'],
                    [Security.Principal.SecurityIdentifier]::new([string]$ace['sid']),
                    $false,
                    $null
                ))
            }
            try {
                Assert-DefenseClawCanonicalRawPathAcl -Path $Missing -Actual $raw -Expected $expected -WarningAction SilentlyContinue
                return ''
            }
            catch {
                return [string]$_.Exception.Message
            }
        } $case ($fixture + '.missing')
        $want = [string]$case['expect']
        if (($want -eq '' -and $observed -ne '') -or
            ($want -ne '' -and -not ([string]$observed).StartsWith($want, [StringComparison]::Ordinal))) {
            $failures.Add("raw: $($case['name']): want '$want', got '$observed'")
        }
    }

    # A descriptor that cannot be read is not "no drift observed": only a path
    # that is gone may continue, and only outside the strict pin.
    if (-not ('DcPathAclSmokeNativeSecurity' -as [type])) {
        Microsoft.PowerShell.Utility\Add-Type -TypeDefinition @'
public static class DcPathAclSmokeNativeSecurity
{
    public static int Code;
    public static byte[] GetFileSecurityDescriptor(string path)
    {
        throw new System.ComponentModel.Win32Exception(Code, "open file for raw security query failed: " + path);
    }
}
'@
    }
    $readCases = @(
        @{ name = 'access denied'; code = 5; strict = ''; expect = 'refuse' }
        @{ name = 'path gone'; code = 2; strict = ''; expect = '' }
        @{ name = 'folder gone'; code = 3; strict = ''; expect = '' }
        @{ name = 'path gone, strict pin'; code = 2; strict = '1'; expect = 'refuse' }
    )
    foreach ($case in $readCases) {
        [Environment]::SetEnvironmentVariable($strictEnv, [string]$case['strict'], 'Process')
        [DcPathAclSmokeNativeSecurity]::Code = [int]$case['code']
        $observed = & $module {
            param($Fixture)
            $script:DefenseClawEnterpriseProfile = 'Standalone'
            function script:Initialize-DefenseClawNativeSecurity { return [DcPathAclSmokeNativeSecurity] }
            $expected = New-DefenseClawCanonicalPathAcl -IsDirectory:$false -Kind AdminFile -GatewayServiceSID $script:AdministratorsSID
            try {
                Assert-DefenseClawCanonicalPathAcl -Path $Fixture -Expected $expected -WarningAction SilentlyContinue
                return ''
            }
            catch {
                return 'refuse'
            }
            finally {
                Microsoft.PowerShell.Management\Remove-Item -LiteralPath Function:\Initialize-DefenseClawNativeSecurity -ErrorAction SilentlyContinue
            }
        } $fixture
        if ([string]$observed -cne [string]$case['expect']) {
            $failures.Add("read: $($case['name']): want '$($case['expect'])', got '$observed'")
        }
    }

    foreach ($case in $cases) {
        [Environment]::SetEnvironmentVariable($strictEnv, [string]$case.strict, 'Process')
        $heal = -not $case.ContainsKey('heal') -or [bool]$case.heal
        $advisory = $case.ContainsKey('advisory') -and [bool]$case.advisory
        $observed = & $module {
            param($Case, $Fixture, $Heal, $Advisory)
            $script:DefenseClawEnterpriseProfile = 'Standalone'
            $script:VerdictReadings = [Collections.Generic.List[object]]::new()
            foreach ($reading in @($Case['before'], $Case['after'])) {
                $script:VerdictReadings.Add([object[]]@(
                    $reading | Microsoft.PowerShell.Core\ForEach-Object { [pscustomobject]$_ }
                ))
            }
            $script:VerdictReads = 0
            $script:StampMode = [string]$Case['stamp']
            function script:Get-DefenseClawPathAclVerdicts {
                $reading = $script:VerdictReadings[[Math]::Min($script:VerdictReads, 1)]
                $script:VerdictReads++
                return $reading
            }
            function script:Set-DefenseClawPathAcl {
                if ($script:StampMode -ceq 'throw') { throw 'simulated: the canonical stamp lost a race' }
            }
            $arguments = @{
                Path              = $Fixture
                AllowedWriterSIDs = @($script:SystemSID, $script:AdministratorsSID)
                AllowUsersRead    = $true
            }
            if ($Heal) {
                $arguments['SelfHealKind'] = 'ServiceInstallFile'
                $arguments['SelfHealGatewayServiceSID'] = 'S-1-5-80-1'
            }
            if ($Advisory) {
                $arguments['AdvisoryUntrustedAccess'] = $true
            }
            try {
                Assert-DefenseClawPathAcl @arguments -WarningAction SilentlyContinue
                return ''
            }
            catch {
                return [string]$_.Exception.Message
            }
        } $case $fixture $heal $advisory
        if ([string]$observed -cne [string]$case.expect) {
            $want = if ($case.expect) { "refusal '$($case.expect)'" } else { 'pass' }
            $failures.Add("$($case.name): want $want, got '$observed'")
        }
    }
}
finally {
    [Environment]::SetEnvironmentVariable($strictEnv, $savedStrict, 'Process')
    Microsoft.PowerShell.Management\Remove-Item -LiteralPath $fixture -Force -ErrorAction SilentlyContinue
    Microsoft.PowerShell.Core\Remove-Module -ModuleInfo $module -Force -ErrorAction SilentlyContinue
}
if ($failures.Count -gt 0) {
    throw ("enterprise-path-acl-verdict-smoke: FAIL`n" + ($failures -join "`n"))
}
Microsoft.PowerShell.Utility\Write-Host "enterprise-path-acl-verdict-smoke: PASS ($($cases.Count + $rawCases.Count + $readCases.Count) cases)"
