# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 5.1

# GAP-0763: on the standalone profile an in-place re-stamp of a recorded
# regular file holds the file first. A program that holds it open with write
# or delete access, or without sharing read access, stops the stamp before
# anything is written, and the refusal names the file; the access list is
# byte for byte what it was. Readers that share read (an antivirus scan, the
# gateway) do not stop it. Secure Client stamps as it always did. Same
# account, one process, no second account.

[CmdletBinding()]
param([string]$ScratchRoot = [IO.Path]::GetTempPath())

Microsoft.PowerShell.Core\Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$module = Microsoft.PowerShell.Core\Import-Module `
    -Name ([IO.Path]::GetFullPath((Microsoft.PowerShell.Management\Join-Path $PSScriptRoot '..\DefenseClawEnterprise.psm1'))) `
    -Force -PassThru -ErrorAction Stop
$scratch = [IO.Path]::Combine($ScratchRoot, ('dc-held-restamp-' + [Guid]::NewGuid().ToString('N')))
[void][IO.Directory]::CreateDirectory($scratch)

$holderType = Microsoft.PowerShell.Utility\Add-Type -PassThru `
    -Namespace ('DcHeld' + [Guid]::NewGuid().ToString('N')) -Name Holder `
    -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
public static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr attributes, uint disposition, uint flags, IntPtr template);
[DllImport("kernel32.dll", SetLastError = true)]
public static extern bool CloseHandle(IntPtr handle);
[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
public static extern bool CreateHardLinkW(string link, string existing, IntPtr attributes);
'@

try {
    & $module {
        param($Scratch, $Holder)
        $admins = $script:AdministratorsSID
        $drifted = 'O:BAG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)'
        $usersRead = '(A;;0x1200a9;;;BU)'

        function Get-Sddl([string]$Path) {
            (Microsoft.PowerShell.Security\Get-Acl -LiteralPath $Path).Sddl
        }
        function New-DriftedFile([string]$Name) {
            $path = [IO.Path]::Combine($Scratch, $Name)
            [IO.File]::WriteAllText($path, 'x')
            Set-DefenseClawPathAcl -Path $path -Kind MachinePolicyFile -GatewayServiceSID $admins
            # Trusted-only drift: the Users read entry is gone.
            $security = [Security.AccessControl.FileSecurity]::new()
            $security.SetSecurityDescriptorSddlForm($drifted, [Security.AccessControl.AccessControlSections]::All)
            Microsoft.PowerShell.Security\Set-Acl -LiteralPath $path -AclObject $security
            if ((Get-Sddl $path).Contains(';;;BU)')) { throw 'could not make trusted-only drift' }
            return $path
        }
        # access / share masks of the holders.
        $DELETE = [uint32]0x00010000; $READ_ATTR = [uint32]0x80; $READ_DATA = [uint32]1; $WRITE_DATA = [uint32]2
        $SHARE_R = [uint32]1; $SHARE_W = [uint32]2; $SHARE_D = [uint32]4
        function Open-Holder([string]$Path, [uint32]$Access, [uint32]$Share) {
            $handle = $Holder::CreateFileW($Path, $Access, $Share, [IntPtr]::Zero, 3, 0, [IntPtr]::Zero)
            if ($handle -eq [IntPtr](-1)) { throw "holder open failed ($([Runtime.InteropServices.Marshal]::GetLastWin32Error())): $Path" }
            return $handle
        }
        function Close-Holder([IntPtr]$Handle) { [void]$Holder::CloseHandle($Handle) }

        function Assert-Refused([scriptblock]$Action, [string]$Path, [string]$Label) {
            $before = Get-Sddl $Path
            $message = ''
            try { & $Action } catch { $message = $_.Exception.Message }
            if (-not $message.StartsWith('refusing to re-stamp a managed') -or -not $message.Contains($Path)) {
                throw "${Label}: not refused by name: '$message'"
            }
            if ((Get-Sddl $Path) -ne $before) {
                throw "${Label}: the refused re-stamp changed the access list"
            }
        }
        function Assert-Healed([scriptblock]$Action, [string]$Path, [string]$Label) {
            & $Action
            if (-not (Get-Sddl $Path).Contains(';;;BU)')) { throw "${Label}: the Users read entry was not put back" }
        }

        $heal = {
            param($Path)
            $required = New-DefenseClawRequiredRights -Kind MachinePolicy
            Assert-DefenseClawPathAcl `
                -Path $Path `
                -AllowedWriterSIDs @($script:SystemSID, $script:AdministratorsSID, $script:TrustedInstallerSID) `
                -AllowedReaderSIDs @($script:SystemSID, $script:AdministratorsSID, $script:TrustedInstallerSID, $script:UsersSID) `
                -RequiredRights $required -AllowUsersRead -RejectUntrustedRead `
                -SelfHealKind MachinePolicyFile -SelfHealGatewayServiceSID $admins -HealOnlyUntrusted
        }

        Set-DefenseClawEnterpriseProfile -EnterpriseProfile Standalone
        try {
            $holders = @(
                @{ Name = 'a DELETE handle without delete sharing'; Access = ($DELETE -bor $READ_ATTR); Share = ($SHARE_R -bor $SHARE_W) },
                @{ Name = 'a write handle'; Access = ($WRITE_DATA -bor $READ_ATTR); Share = ($SHARE_R -bor $SHARE_W -bor $SHARE_D) },
                @{ Name = 'a read handle that does not share read'; Access = $READ_DATA; Share = ($SHARE_W -bor $SHARE_D) }
            )
            foreach ($entry in $holders) {
                # The stamp itself.
                $path = New-DriftedFile ('stamp-' + [Guid]::NewGuid().ToString('N') + '.toml')
                $handle = Open-Holder $path $entry.Access $entry.Share
                try {
                    Assert-Refused { Set-DefenseClawPathAcl -Path $path -Kind MachinePolicyFile -GatewayServiceSID $admins } $path "stamp with $($entry.Name)"
                }
                finally { Close-Holder $handle }
                Assert-Healed { Set-DefenseClawPathAcl -Path $path -Kind MachinePolicyFile -GatewayServiceSID $admins } $path "stamp after $($entry.Name) let go"

                # The self-heal of the Codex requirements checks.
                $path = New-DriftedFile ('heal-' + [Guid]::NewGuid().ToString('N') + '.toml')
                $handle = Open-Holder $path $entry.Access $entry.Share
                try { Assert-Refused { & $heal $path } $path "self-heal with $($entry.Name)" }
                finally { Close-Holder $handle }
                Assert-Healed { & $heal $path } $path "self-heal after $($entry.Name) let go"

                # The identity-pinned native branch (AdminFile, RuntimeSecretFile).
                $path = [IO.Path]::Combine($Scratch, 'admin-' + [Guid]::NewGuid().ToString('N') + '.json')
                [IO.File]::WriteAllText($path, '{}')
                Set-DefenseClawPathAcl -Path $path -Kind AdminFile -GatewayServiceSID $admins
                $security = [Security.AccessControl.FileSecurity]::new()
                $security.SetSecurityDescriptorSddlForm('O:BAG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)', [Security.AccessControl.AccessControlSections]::All)
                Microsoft.PowerShell.Security\Set-Acl -LiteralPath $path -AclObject $security
                $handle = Open-Holder $path $entry.Access $entry.Share
                try {
                    Assert-Refused { Set-DefenseClawPathAcl -Path $path -Kind AdminFile -GatewayServiceSID $admins } $path "admin file stamp with $($entry.Name)"
                }
                finally { Close-Holder $handle }
                Set-DefenseClawPathAcl -Path $path -Kind AdminFile -GatewayServiceSID $admins
                if ((Get-Sddl $path).Contains(';;;BU)')) { throw "admin file stamp after $($entry.Name) let go left the Users entry" }
            }

            # g582 round 11c, M1. A file that already carries the canonical
            # access list is not probed: no holder is in the way of a write
            # that is not needed, and nothing is written.
            foreach ($entry in $holders) {
                $path = New-DriftedFile ('canonical-' + [Guid]::NewGuid().ToString('N') + '.toml')
                Set-DefenseClawPathAcl -Path $path -Kind MachinePolicyFile -GatewayServiceSID $admins
                $handle = Open-Holder $path $entry.Access $entry.Share
                try {
                    $before = Get-Sddl $path
                    Set-DefenseClawPathAcl -Path $path -Kind MachinePolicyFile -GatewayServiceSID $admins
                    if ((Get-Sddl $path) -ne $before) { throw "canonical file with $($entry.Name): the access list changed" }
                }
                finally { Close-Holder $handle }
            }

            # A hook copy of the Codex state (.state.<n>) that a user holds is
            # neither re-stamped in place nor refused, whatever the holder;
            # once released it is stamped as any other file.
            foreach ($entry in $holders) {
                $path = New-DriftedFile ('.defenseclaw-managed-hooks.state.' + (Get-Random -Minimum 10 -Maximum 99999) )
                $handle = Open-Holder $path $entry.Access $entry.Share
                try {
                    $before = Get-Sddl $path
                    Set-DefenseClawPathAcl -Path $path -Kind MachinePolicyFile -GatewayServiceSID $admins
                    if ((Get-Sddl $path) -ne $before) { throw "state copy held by $($entry.Name): stamped in place" }
                }
                finally { Close-Holder $handle }
                Assert-Healed { Set-DefenseClawPathAcl -Path $path -Kind MachinePolicyFile -GatewayServiceSID $admins } $path "state copy after $($entry.Name) let go"
            }

            # An antivirus scan or a backup agent reads with delete sharing: it does not stop the heal.
            $path = New-DriftedFile ('reader-' + [Guid]::NewGuid().ToString('N') + '.toml')
            $handle = Open-Holder $path ($READ_DATA -bor $READ_ATTR) ($SHARE_R -bor $SHARE_W -bor $SHARE_D)
            try { Assert-Healed { Set-DefenseClawPathAcl -Path $path -Kind MachinePolicyFile -GatewayServiceSID $admins } $path 'stamp with a reader that shares everything' }
            finally { Close-Holder $handle }

            # A second hard link is refused on the same hold, access list unchanged.
            $path = New-DriftedFile ('link-' + [Guid]::NewGuid().ToString('N') + '.toml')
            if (-not $Holder::CreateHardLinkW($path + '.sibling', $path, [IntPtr]::Zero)) { throw 'could not create a hard link' }
            Assert-Refused { Set-DefenseClawPathAcl -Path $path -Kind MachinePolicyFile -GatewayServiceSID $admins } $path 'stamp of a linked file'

            # Program files are not held: no standard account ever held a grant on them.
            $path = [IO.Path]::Combine($Scratch, 'program.exe')
            [IO.File]::WriteAllText($path, 'x')
            $handle = Open-Holder $path ($WRITE_DATA -bor $READ_ATTR) ($SHARE_R -bor $SHARE_W -bor $SHARE_D)
            try { Set-DefenseClawPathAcl -Path $path -Kind InstallFile -GatewayServiceSID $admins }
            finally { Close-Holder $handle }
        }
        finally {
            Set-DefenseClawEnterpriseProfile -EnterpriseProfile SecureClient
        }

        # Secure Client stamps as it always did, holder or not.
        foreach ($entry in $holders) {
            $path = New-DriftedFile ('sc-' + [Guid]::NewGuid().ToString('N') + '.toml')
            $handle = Open-Holder $path $entry.Access $entry.Share
            try { Assert-Healed { Set-DefenseClawPathAcl -Path $path -Kind MachinePolicyFile -GatewayServiceSID $admins } $path "Secure Client with $($entry.Name)" }
            finally { Close-Holder $handle }
        }
    } $scratch $holderType
    'enterprise-standalone-held-file-restamp-smoke: OK'
}
finally {
    Microsoft.PowerShell.Management\Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue
}
