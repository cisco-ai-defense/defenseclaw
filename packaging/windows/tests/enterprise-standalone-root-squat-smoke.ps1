# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 7.0

# Standalone roots a standard user created first. Under the default
# ProgramData ACL a standard user can create C:\ProgramData\Cisco (or a
# DefenseClaw root beneath it) before the first install and own it. The
# lifecycle never adopts such a tree: Install moves it aside, every other
# action reports root_squatted, a tree holding administrator-owned content is
# never moved, and the shared vendor directory moves only with content its own
# user owner created. Runs elevated inside a disposable ProgramData stand-in;
# ownership by a non-administrator is simulated with SeRestorePrivilege. No
# service or real machine root is touched.

[CmdletBinding()]
param(
    [string]$ScratchRoot = [IO.Path]::GetTempPath()
)

Microsoft.PowerShell.Core\Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Microsoft.PowerShell.Utility\Write-Output 'enterprise-standalone-root-squat-smoke: SKIP (requires an elevated token)'
    exit 0
}

$privilegeType = Microsoft.PowerShell.Utility\Add-Type -PassThru -Namespace ('DefenseClawSmoke' + [Guid]::NewGuid().ToString('N')) -Name RestorePrivilege -MemberDefinition @'
[StructLayout(LayoutKind.Sequential)] public struct LUID { public uint Low; public int High; }
[StructLayout(LayoutKind.Sequential)] public struct TOKEN_PRIVILEGES { public uint Count; public LUID Luid; public uint Attributes; }
[DllImport("advapi32.dll", SetLastError = true)] static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
[DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern bool LookupPrivilegeValueW(string system, string name, out LUID luid);
[DllImport("advapi32.dll", SetLastError = true)] static extern bool AdjustTokenPrivileges(IntPtr token, bool disableAll, ref TOKEN_PRIVILEGES state, uint length, IntPtr previous, IntPtr returnLength);
[DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
[DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
public static void Enable() {
    IntPtr token;
    if (!OpenProcessToken(GetCurrentProcess(), 0x28, out token)) throw new System.ComponentModel.Win32Exception();
    try {
        TOKEN_PRIVILEGES state = new TOKEN_PRIVILEGES();
        state.Count = 1;
        state.Attributes = 2;
        if (!LookupPrivilegeValueW(null, "SeRestorePrivilege", out state.Luid)) throw new System.ComponentModel.Win32Exception();
        if (!AdjustTokenPrivileges(token, false, ref state, 0, IntPtr.Zero, IntPtr.Zero) || Marshal.GetLastWin32Error() != 0)
            throw new System.ComponentModel.Win32Exception();
    } finally { CloseHandle(token); }
}
'@
$privilegeType = @($privilegeType | Microsoft.PowerShell.Core\Where-Object { $_.Name -ceq 'RestorePrivilege' })[0]
$privilegeType::Enable()

$modulePath = [IO.Path]::GetFullPath(
    (Microsoft.PowerShell.Management\Join-Path `
        $PSScriptRoot `
        '..\DefenseClawEnterprise.psm1')
)
$module = Microsoft.PowerShell.Core\Import-Module `
    -Name $modulePath `
    -Force `
    -PassThru `
    -ErrorAction Stop

$root = [IO.Path]::Combine(
    [IO.Path]::GetFullPath($ScratchRoot),
    ('dc-standalone-root-squat-' + [Guid]::NewGuid().ToString('N'))
)
[void][IO.Directory]::CreateDirectory($root)
try {
    $failures = & $module {
        param([string]$Root)
        $failures = [Collections.Generic.List[string]]::new()
        $originalProgramData = $script:ProgramData
        $originalProfile = Get-DefenseClawEnterpriseProfile
        # A disposable stand-in: the owner is set explicitly, the DACL lets
        # the elevated smoke clean up whatever it creates.
        function Set-TestOwner([string]$Path, [string]$Owner) {
            $isDirectory = [IO.Directory]::Exists($Path)
            $security = if ($isDirectory) { [Security.AccessControl.DirectorySecurity]::new() } else { [Security.AccessControl.FileSecurity]::new() }
            $inherit = if ($isDirectory) { 'OICI' } else { '' }
            $security.SetSecurityDescriptorSddlForm(
                "O:${Owner}G:BAD:P(A;$inherit;FA;;;SY)(A;$inherit;FA;;;BA)(A;$inherit;FA;;;BU)",
                [Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Access
            )
            Microsoft.PowerShell.Security\Set-Acl -LiteralPath $Path -AclObject $security
        }
        function New-TestDirectory([string]$Path, [string]$Owner) {
            [void][IO.Directory]::CreateDirectory($Path)
            Set-TestOwner $Path $Owner
        }
        function Reset-TestRoots {
            foreach ($entry in @(Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $Root -Force)) {
                if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                    [IO.Directory]::Delete($entry.FullName)
                }
                else {
                    Microsoft.PowerShell.Management\Remove-Item -LiteralPath $entry.FullName -Recurse -Force
                }
            }
            $script:DefenseClawQuarantinedRoots = @()
        }
        function Get-TestSquatPaths {
            return @(Get-DefenseClawStandaloneSquattedRoots | Microsoft.PowerShell.Core\ForEach-Object {
                    ([string]$_.path).Substring($Root.Length + 1)
                })
        }
        function Assert-TestPaths([string]$Label, [string[]]$Actual, [string[]]$Expected) {
            if ((@($Actual) -join '|') -cne (@($Expected) -join '|')) {
                $failures.Add("${Label}: got [$(@($Actual) -join ', ')], want [$(@($Expected) -join ', ')]")
            }
        }
        $protected = 'O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'
        $rootSecurity = [Security.AccessControl.DirectorySecurity]::new()
        $rootSecurity.SetSecurityDescriptorSddlForm($protected, [Security.AccessControl.AccessControlSections]::All)
        Microsoft.PowerShell.Security\Set-Acl -LiteralPath $Root -AclObject $rootSecurity
        $script:ProgramData = $Root
        Set-DefenseClawEnterpriseProfile -EnterpriseProfile Standalone
        try {
            $vendor = [IO.Path]::Combine($Root, 'Cisco')
            $state = [IO.Path]::Combine($vendor, 'DefenseClaw')
            $lock = [IO.Path]::Combine($vendor, 'DefenseClaw-Lifecycle')

            Assert-TestPaths 'clean host' (Get-TestSquatPaths) @()

            New-TestDirectory $vendor 'BA'
            New-TestDirectory $state 'SY'
            Assert-TestPaths 'administrator roots' (Get-TestSquatPaths) @()

            # A lock directory a standard user created first is moved aside.
            New-TestDirectory $lock 'BU'
            [IO.File]::WriteAllText([IO.Path]::Combine($lock, 'lifecycle.lock'), 'x')
            Set-TestOwner ([IO.Path]::Combine($lock, 'lifecycle.lock')) 'BU'
            Assert-TestPaths 'user lock directory' (Get-TestSquatPaths) @('Cisco\DefenseClaw-Lifecycle')
            Move-DefenseClawStandaloneSquattedRoots -Squatted @(Get-DefenseClawStandaloneSquattedRoots)
            $moved = @(Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $vendor -Directory -Filter 'DefenseClaw-Lifecycle.untrusted-*')
            if ([IO.Directory]::Exists($lock) -or $moved.Count -ne 1 -or
                -not [IO.File]::Exists([IO.Path]::Combine($moved[0].FullName, 'lifecycle.lock')) -or
                @($script:DefenseClawQuarantinedRoots).Count -ne 1 -or
                [string]$script:DefenseClawQuarantinedRoots[0] -cne $moved[0].FullName) {
                $failures.Add('user lock directory was not moved aside intact and reported')
            }
            Assert-TestPaths 'after the move' (Get-TestSquatPaths) @()
            Reset-TestRoots

            # A user-owned vendor directory is moved with everything in it.
            New-TestDirectory $vendor 'BU'
            New-TestDirectory $state 'BU'
            Assert-TestPaths 'user vendor directory' (Get-TestSquatPaths) @('Cisco')
            Move-DefenseClawStandaloneSquattedRoots -Squatted @(Get-DefenseClawStandaloneSquattedRoots)
            $moved = @(Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $Root -Directory -Filter 'Cisco.untrusted-*')
            if ([IO.Directory]::Exists($vendor) -or $moved.Count -ne 1 -or
                -not [IO.Directory]::Exists([IO.Path]::Combine($moved[0].FullName, 'DefenseClaw'))) {
                $failures.Add('user vendor directory was not moved aside with its content')
            }
            Reset-TestRoots

            # A folder the vendor directory's own user owner created in it
            # moves with it: one `mkdir C:\ProgramData\Cisco\x` must not
            # block every install.
            $squatter = 'S-1-5-21-1000000001-1000000002-1000000003-1001'
            New-TestDirectory $vendor $squatter
            New-TestDirectory ([IO.Path]::Combine($vendor, 'x')) $squatter
            Assert-TestPaths 'user vendor directory with user content' (Get-TestSquatPaths) @('Cisco')
            Move-DefenseClawStandaloneSquattedRoots -Squatted @(Get-DefenseClawStandaloneSquattedRoots)
            $moved = @(Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $Root -Directory -Filter 'Cisco.untrusted-*')
            if ([IO.Directory]::Exists($vendor) -or $moved.Count -ne 1 -or
                -not [IO.Directory]::Exists([IO.Path]::Combine($moved[0].FullName, 'x'))) {
                $failures.Add("a user vendor directory holding only that user's content was not moved aside with it")
            }
            Reset-TestRoots

            # Anything in the shared vendor directory that another principal
            # owns (another product's service account, an administrator), and
            # a vendor directory a service identity owns, is never moved.
            foreach ($case in @(
                    @{ Label = 'service-account content'; Vendor = $squatter; Child = 'NS'; Pattern = 'content other than DefenseClaw' },
                    @{ Label = 'another user''s content'; Vendor = $squatter; Child = 'S-1-5-21-1000000001-1000000002-1000000003-1002'; Pattern = 'content other than DefenseClaw' },
                    @{ Label = 'administrator content'; Vendor = $squatter; Child = 'SY'; Pattern = 'administrator-owned content' },
                    @{ Label = 'a service-owned vendor directory'; Vendor = 'NS'; Child = 'NS'; Pattern = 'content other than DefenseClaw' },
                    @{ Label = 'a group-owned vendor directory'; Vendor = 'BU'; Child = 'BU'; Pattern = 'content other than DefenseClaw' }
                )) {
                New-TestDirectory $vendor $case.Vendor
                New-TestDirectory ([IO.Path]::Combine($vendor, 'Other Product')) $case.Child
                try {
                    Move-DefenseClawStandaloneSquattedRoots -Squatted @(Get-DefenseClawStandaloneSquattedRoots)
                    $failures.Add("a user vendor directory holding $($case.Label) was moved")
                }
                catch {
                    if ($_.Exception.Message -notmatch ('^root_squatted: .*' + $case.Pattern)) {
                        $failures.Add("$($case.Label) refusal lacks root_squatted: $($_.Exception.Message)")
                    }
                }
                if (-not [IO.Directory]::Exists([IO.Path]::Combine($vendor, 'Other Product'))) {
                    $failures.Add("$($case.Label) was disturbed")
                }
                Reset-TestRoots
            }

            # Administrator-owned data inside a DefenseClaw root is never moved.
            New-TestDirectory $vendor 'BA'
            New-TestDirectory $state 'BU'
            New-TestDirectory ([IO.Path]::Combine($state, 'install')) 'SY'
            try {
                Move-DefenseClawStandaloneSquattedRoots -Squatted @(Get-DefenseClawStandaloneSquattedRoots)
                $failures.Add('a user state root holding administrator content was moved')
            }
            catch {
                if ($_.Exception.Message -notmatch '^root_squatted: .*administrator-owned content') {
                    $failures.Add("administrator content refusal lacks root_squatted: $($_.Exception.Message)")
                }
            }
            if (-not [IO.Directory]::Exists([IO.Path]::Combine($state, 'install'))) {
                $failures.Add('administrator content was disturbed')
            }
            Reset-TestRoots

            # A junction is renamed as a link; its target is never followed.
            $target = [IO.Path]::Combine($Root, 'junction-target')
            New-TestDirectory $target 'BA'
            [IO.File]::WriteAllText([IO.Path]::Combine($target, 'keep.txt'), 'keep')
            New-TestDirectory $vendor 'BA'
            [void](Microsoft.PowerShell.Management\New-Item -ItemType Junction -Path $lock -Target $target)
            Assert-TestPaths 'junction lock directory' (Get-TestSquatPaths) @('Cisco\DefenseClaw-Lifecycle')
            Move-DefenseClawStandaloneSquattedRoots -Squatted @(Get-DefenseClawStandaloneSquattedRoots)
            if ([IO.Directory]::Exists($lock) -or
                -not [IO.File]::Exists([IO.Path]::Combine($target, 'keep.txt'))) {
                $failures.Add('junction was not renamed as a link, or its target changed')
            }
            Reset-TestRoots

            # Upgrade, Repair and Uninstall prepare an existing state root
            # without rewriting its protected DACL, so the live gateway entry
            # survives an action that fails before its transaction.
            $vendorSecurity = [Security.AccessControl.DirectorySecurity]::new()
            $vendorSecurity.SetSecurityDescriptorSddlForm($protected, [Security.AccessControl.AccessControlSections]::All)
            [void][IO.Directory]::CreateDirectory($vendor)
            Microsoft.PowerShell.Security\Set-Acl -LiteralPath $vendor -AclObject $vendorSecurity
            [void][IO.Directory]::CreateDirectory($state)
            $gatewayStandIn = 'S-1-5-19'
            Set-DefenseClawPathAcl -Path $state -Kind StateDirectory -GatewayServiceSID $gatewayStandIn
            Initialize-DefenseClawManagedRoot -Path $state -Label 'StateRoot' -RequiredBase $Root -KeepProtectedAcl
            $kept = @((Microsoft.PowerShell.Security\Get-Acl -LiteralPath $state).GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) |
                    Microsoft.PowerShell.Core\Where-Object { $_.IdentityReference.Value -ceq $gatewayStandIn })
            if ($kept.Count -ne 1) {
                $failures.Add('preparing an existing state root removed the gateway entry')
            }
            Reset-TestRoots

            # The vendor directory standalone Setup creates lets standard users
            # read it (that directory only), as their hooks check every
            # ancestor of the machine policy summary. An existing vendor
            # directory, and one the Secure Client profile creates, is never
            # given that entry.
            function Get-TestUsersRules([string]$Path) {
                return @((Microsoft.PowerShell.Security\Get-Acl -LiteralPath $Path).GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) |
                        Microsoft.PowerShell.Core\Where-Object { $_.IdentityReference.Value -ceq $script:UsersSID })
            }
            Initialize-DefenseClawManagedRoot -Path $lock -Label 'lifecycle lock directory' -RequiredBase $Root
            $usersRules = @(Get-TestUsersRules $vendor)
            if ($usersRules.Count -ne 1 -or $usersRules[0].IsInherited -or
                $usersRules[0].AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
                $usersRules[0].InheritanceFlags -ne [Security.AccessControl.InheritanceFlags]::None -or
                [int]$usersRules[0].FileSystemRights -ne 0x1200a9 -or
                @(Get-TestUsersRules $lock).Count -ne 0) {
                $failures.Add('a vendor directory Setup created lacks the this-folder-only Users read entry, or it reached the lock directory')
            }
            Reset-TestRoots
            [void][IO.Directory]::CreateDirectory($vendor)
            Microsoft.PowerShell.Security\Set-Acl -LiteralPath $vendor -AclObject $vendorSecurity
            $before = (Microsoft.PowerShell.Security\Get-Acl -LiteralPath $vendor).Sddl
            Initialize-DefenseClawManagedRoot -Path $lock -Label 'lifecycle lock directory' -RequiredBase $Root
            if ((Microsoft.PowerShell.Security\Get-Acl -LiteralPath $vendor).Sddl -cne $before) {
                $failures.Add('preparing a root changed the DACL of an existing vendor directory')
            }
            # GAP-0577: install, upgrade and repair then give an existing
            # administrator-owned vendor directory the same entry, once.
            Grant-DefenseClawStandaloneVendorDirectoryUsersRead
            Grant-DefenseClawStandaloneVendorDirectoryUsersRead
            $usersRules = @(Get-TestUsersRules $vendor)
            if ($usersRules.Count -ne 1 -or $usersRules[0].IsInherited -or
                $usersRules[0].InheritanceFlags -ne [Security.AccessControl.InheritanceFlags]::None -or
                [int]$usersRules[0].FileSystemRights -ne 0x1200a9) {
                $failures.Add("an existing vendor directory did not get one this-folder-only Users read entry: $($usersRules.Count)")
            }
            Reset-TestRoots
            Set-DefenseClawEnterpriseProfile -EnterpriseProfile SecureClient
            try {
                Initialize-DefenseClawManagedRoot -Path ([IO.Path]::Combine($vendor, 'Cisco Secure Client', 'DefenseClaw-Lifecycle')) -Label 'lifecycle lock directory' -RequiredBase $Root
            }
            finally {
                Set-DefenseClawEnterpriseProfile -EnterpriseProfile Standalone
            }
            Set-DefenseClawEnterpriseProfile -EnterpriseProfile SecureClient
            try {
                Grant-DefenseClawStandaloneVendorDirectoryUsersRead
            }
            finally {
                Set-DefenseClawEnterpriseProfile -EnterpriseProfile Standalone
            }
            if (@(Get-TestUsersRules $vendor).Count -ne 0) {
                $failures.Add('the Secure Client profile gave its vendor directory a Users entry')
            }
            Reset-TestRoots

            # Actions other than Install name the squatted root with a stable code.
            New-TestDirectory $vendor 'BU'
            try {
                [void](Invoke-DefenseClawEnterpriseLifecycle -Action Status -EnterpriseProfile Standalone)
                $failures.Add('Status accepted a user-owned vendor directory')
            }
            catch {
                if ($_.Exception.Message -notmatch '^root_squatted: ') {
                    $failures.Add("Status refusal lacks root_squatted: $($_.Exception.Message)")
                }
            }
            if (-not [IO.Directory]::Exists($vendor)) {
                $failures.Add('Status moved a squatted root')
            }
            Reset-TestRoots
        }
        finally {
            $script:ProgramData = $originalProgramData
            $script:DefenseClawQuarantinedRoots = @()
            Set-DefenseClawEnterpriseProfile -EnterpriseProfile $originalProfile
        }
        return , $failures
    } $root
}
finally {
    Microsoft.PowerShell.Management\Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}

if ($failures.Count -gt 0) {
    foreach ($failure in $failures) {
        Microsoft.PowerShell.Utility\Write-Output "FAIL: $failure"
    }
    exit 1
}
Microsoft.PowerShell.Utility\Write-Output 'enterprise-standalone-root-squat-smoke: OK'
