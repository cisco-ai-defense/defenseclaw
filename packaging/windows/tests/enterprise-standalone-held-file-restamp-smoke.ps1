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

        # g582 round 11c. The delete probe the Codex file gate uses: a holder
        # that denies delete sharing is seen, one that shares everything is not.
        $probePath = [IO.Path]::Combine($Scratch, 'delete-probe.toml')
        [IO.File]::WriteAllText($probePath, 'x')
        if (Test-DefenseClawFileDeleteBlocked -Path $probePath) { throw 'delete probe: a file nobody holds reads as blocked' }
        foreach ($case in @(
                @{ Name = 'read sharing only'; Share = ($SHARE_R); Blocked = $true },
                @{ Name = 'read and write sharing'; Share = ($SHARE_R -bor $SHARE_W); Blocked = $true },
                @{ Name = 'write and delete sharing'; Share = ($SHARE_W -bor $SHARE_D); Blocked = $false },
                @{ Name = 'everything shared'; Share = ($SHARE_R -bor $SHARE_W -bor $SHARE_D); Blocked = $false })) {
            $handle = Open-Holder $probePath $READ_DATA $case.Share
            try {
                $got = [bool](Test-DefenseClawFileDeleteBlocked -Path $probePath)
                if ($got -ne $case.Blocked) { throw "delete probe with a holder of $($case.Name): blocked=$got, want $($case.Blocked)" }
            }
            finally { Close-Holder $handle }
        }

        # g582 round 11c twin. Secure Client keeps its stamp of a Codex state
        # copy, held or not (no tolerance, no refusal), and the recovery
        # helper that puts the requirements read back before the guardian
        # starts does nothing there; the standalone profile heals the file.
        foreach ($entry in $holders) {
            $path = New-DriftedFile ('.defenseclaw-managed-hooks.state.' + (Get-Random -Minimum 100000 -Maximum 999999))
            $handle = Open-Holder $path $entry.Access $entry.Share
            try { Assert-Healed { Set-DefenseClawPathAcl -Path $path -Kind MachinePolicyFile -GatewayServiceSID $admins } $path "Secure Client, state copy held by $($entry.Name)" }
            finally { Close-Holder $handle }
        }
        $requirements = New-DriftedFile 'requirements.toml'
        $ownership = [IO.Path]::Combine($Scratch, 'codex-requirements-ownership.json')
        [IO.File]::WriteAllText($ownership, '{}')
        $recoveryLayout = @{ CodexMachinePolicyPath = $requirements; CodexRequirementsOwnershipPath = $ownership }
        $before = Get-Sddl $requirements
        Repair-DefenseClawCodexRequirementsAccessBeforeGuardian -Layout $recoveryLayout -GatewayServiceName 'DefenseClawGateway'
        if ((Get-Sddl $requirements) -ne $before) { throw 'Secure Client: the recovery helper changed the requirements access list' }
        Set-DefenseClawEnterpriseProfile -EnterpriseProfile Standalone
        try {
            Repair-DefenseClawCodexRequirementsAccessBeforeGuardian -Layout $recoveryLayout -GatewayServiceName 'DefenseClawGateway'
        }
        finally { Set-DefenseClawEnterpriseProfile -EnterpriseProfile SecureClient }
        if (-not (Get-Sddl $requirements).Contains(';;;BU)')) { throw 'standalone: the recovery helper did not put the Users read entry back' }
        # g582 round 11e, GAP-0803. A Codex file a program holds open without
        # delete sharing, arrived after the gate, ends the rollback with the
        # retryable held code naming the file, within the bound.
        $codexDir = [IO.Path]::Combine($Scratch, 'codex-held'); [void][IO.Directory]::CreateDirectory($codexDir)
        $heldRequirements = [IO.Path]::Combine($codexDir, 'requirements.toml'); [IO.File]::WriteAllText($heldRequirements, 'x')
        $heldState = [IO.Path]::Combine($codexDir, '.defenseclaw-managed-hooks.state'); [IO.File]::WriteAllText($heldState, 'x')
        $heldLayout = @{ CodexMachinePolicyPath = $heldRequirements; InstallRoot = $Scratch }
        Set-DefenseClawEnterpriseProfile -EnterpriseProfile Standalone
        try {
            foreach ($case in @(
                    @{ Path = $heldRequirements; Code = 'codex_requirements_held' },
                    @{ Path = $heldState; Code = 'codex_state_held' })) {
                foreach ($entry in $holders) {
                    $handle = Open-Holder $case.Path $entry.Access $entry.Share
                    try {
                        $clock = [Diagnostics.Stopwatch]::StartNew()
                        $message = ''
                        try { [void](Open-DefenseClawCodexRollbackHold -Layout $heldLayout -Path $case.Path -TimeoutSeconds 1) } catch { $message = $_.Exception.Message }
                        if (-not $message.StartsWith($case.Code + ': ') -or -not $message.Contains($case.Path) -or -not $message.Contains('still pending')) {
                            throw "rollback hold, $($entry.Name) on $($case.Code): not refused by name: '$message'"
                        }
                        if ($clock.Elapsed.TotalSeconds -gt 20) { throw "rollback hold, $($entry.Name): waited $($clock.Elapsed.TotalSeconds) s" }
                    }
                    finally { Close-Holder $handle }
                }
                $released = Open-DefenseClawCodexRollbackHold -Layout $heldLayout -Path $case.Path -TimeoutSeconds 1
                Close-DefenseClawRestampHold -Handle $released
            }
        }
        finally { Set-DefenseClawEnterpriseProfile -EnterpriseProfile SecureClient }

        # g582 round 11e, GAP-0802. The recorded preimage is used only when the
        # record names this file and its stored bytes match the recorded hash.
        $recDir = [IO.Path]::Combine($Scratch, 'codex-recover'); [void][IO.Directory]::CreateDirectory($recDir)
        $recRequirements = [IO.Path]::Combine($recDir, 'requirements.toml')
        $recOwnership = [IO.Path]::Combine($recDir, 'ownership.json')
        $recInstallState = [IO.Path]::Combine($recDir, 'install-state'); [void][IO.Directory]::CreateDirectory($recInstallState)
        $recLayout = @{ CodexMachinePolicyPath = $recRequirements; CodexRequirementsOwnershipPath = $recOwnership; InstallStateDirectory = $recInstallState; InstallRoot = $Scratch; CodexManagedHooksStatePath = [IO.Path]::Combine($recDir, '.defenseclaw-managed-hooks.state') }
        $preimage = [Text.Encoding]::UTF8.GetBytes("[features]`nfoo = true`n")
        $sha = [Security.Cryptography.SHA256]::Create(); $preimageHash = ([BitConverter]::ToString($sha.ComputeHash($preimage)) -replace '-', '').ToLowerInvariant(); $sha.Dispose()
        function Write-Record([string]$RequirementsPath, [string]$Hash, [bool]$Existed) {
            $record = [ordered]@{ schema_version = 2; requirements_path = $RequirementsPath; preimage_existed = $Existed; preimage = [Convert]::ToBase64String($preimage); preimage_sha256 = $Hash }
            [IO.File]::WriteAllText($recOwnership, ($record | ConvertTo-Json))
        }
        Write-Record $recRequirements $preimageHash $true
        if ([Convert]::ToBase64String((Get-DefenseClawRecordedCodexRequirementsPreimage -Layout $recLayout)) -ne [Convert]::ToBase64String($preimage)) { throw 'recorded preimage: a matching record was not used' }
        Write-Record $recRequirements ('0' * 64) $true
        if ((Get-DefenseClawRecordedCodexRequirementsPreimage -Layout $recLayout).Length -ne 0) { throw 'recorded preimage: a record whose hash does not match was used' }
        Write-Record ([IO.Path]::Combine($recDir, 'other.toml')) $preimageHash $true
        if ((Get-DefenseClawRecordedCodexRequirementsPreimage -Layout $recLayout).Length -ne 0) { throw 'recorded preimage: a record of another file was used' }
        Write-Record $recRequirements $preimageHash $false
        if ((Get-DefenseClawRecordedCodexRequirementsPreimage -Layout $recLayout).Length -ne 0) { throw 'recorded preimage: a record without a preimage was used' }
        [IO.File]::WriteAllText($recOwnership, '{ not json')
        if ((Get-DefenseClawRecordedCodexRequirementsPreimage -Layout $recLayout).Length -ne 0) { throw 'recorded preimage: an unparseable record was used' }

        # The recovery step, with the Codex command and the protected
        # directory stubbed: merge, rebuild from the preimage, held, nothing
        # to do, and Secure Client untouched.
        $script:RecoverCalls = [Collections.Generic.List[string]]::new()
        $script:RecoverPlan = @()
        function script:Invoke-DefenseClawCodexRequirementsCommand {
            param($Layout, $GatewayServiceName, $Action, $BaseFile = '')
            $step = $script:RecoverPlan[$script:RecoverCalls.Count]
            if ($BaseFile -ne '') {
                # GAP-1001: the managed policy is rendered into this document; the file on disk is not the base.
                $script:RecoverCalls.Add($Action + ':base:' + [Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($BaseFile)))
            }
            else {
                $live = if (Test-Path -LiteralPath $Layout.CodexMachinePolicyPath) { [Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($Layout.CodexMachinePolicyPath)) } else { '' }
                $script:RecoverCalls.Add($Action + ':' + $live)
            }
            if ($step.StartsWith('codex_state_unsettled: ')) { throw $step }
            if ($step -ne 'ok') { throw "Codex requirements $Action failed: $step" }
            if ($Action -eq 'reconcile') { [IO.File]::WriteAllText($Layout.CodexMachinePolicyPath, 'canonical') }
        }
        $script:BaseFileSupported = $true
        function script:Test-DefenseClawManagedHooksCommittedTeardownSupported { param($Layout, $GatewayServiceName, $Capability) [bool]$script:BaseFileSupported }
        function script:New-DefenseClawProtectedDirectory { param($Path) [void][IO.Directory]::CreateDirectory($Path); return $true }
        function Reset-Recovery([string[]]$Plan, [string]$Content) {
            $script:RecoverCalls.Clear(); $script:RecoverPlan = $Plan
            [IO.File]::WriteAllText($recRequirements, $Content)
            foreach ($f in @(Get-ChildItem -LiteralPath $recInstallState -Recurse -File -ErrorAction SilentlyContinue)) { Remove-Item -LiteralPath $f.FullName -Force }
        }
        function Get-Backups { @(Get-ChildItem -LiteralPath $recInstallState -Recurse -File -Filter 'requirements.toml.hand-edited.*' -ErrorAction SilentlyContinue) }
        Set-DefenseClawEnterpriseProfile -EnterpriseProfile Standalone
        try {
            # Nothing to do: verify passes, no backup, no reconcile.
            Reset-Recovery @('ok') 'fine'
            Repair-DefenseClawRecoveredCodexRequirements -Layout $recLayout -GatewayServiceName 'DefenseClawGateway'
            if ($script:RecoverCalls.Count -ne 1 -or @(Get-Backups).Count -ne 0 -or [IO.File]::ReadAllText($recRequirements) -ne 'fine') { throw 'recovery: a file that verifies was touched' }
            # Merge: the hand edit is saved byte for byte, the managed policy is published.
            Reset-Recovery @('hooks.SessionStart has 0 exact DefenseClaw managed groups, want 1', 'ok') 'hand edit'
            Repair-DefenseClawRecoveredCodexRequirements -Layout $recLayout -GatewayServiceName 'DefenseClawGateway'
            $backups = @(Get-Backups)
            if ($backups.Count -ne 1 -or [IO.File]::ReadAllText($backups[0].FullName) -ne 'hand edit') { throw 'recovery: the hand-edited bytes were not kept' }
            if ([IO.File]::ReadAllText($recRequirements) -ne 'canonical' -or -not ($script:RecoverCalls -join '|').Contains('reconcile:hand edit')) { throw 'recovery: the managed policy was not merged into the file' }
            if (-not (@(Get-DefenseClawResilienceEvents) -join "`n").Contains($backups[0].Name)) { throw 'recovery: the event does not name the backup' }
            # Rebuild: a hand edit the merge refuses is replaced from the recorded preimage.
            Write-Record $recRequirements $preimageHash $true
            Reset-Recovery @('is not pinned true', 'allow_managed_hooks_only=false conflicts', 'ok') 'allow = false'
            Repair-DefenseClawRecoveredCodexRequirements -Layout $recLayout -GatewayServiceName 'DefenseClawGateway'
            if (($script:RecoverCalls -join '|') -notmatch 'reconcile:allow = false\|reconcile:base:\[features\]') { throw "recovery: the file was not rebuilt from the recorded preimage: $($script:RecoverCalls -join '|')" }
            if (@(Get-Backups).Count -ne 1 -or [IO.File]::ReadAllText((Get-Backups)[0].FullName) -ne 'allow = false') { throw 'recovery: the refused hand edit was not kept' }
            # Both fail: named, and the hand edit is still kept.
            Reset-Recovery @('bad', 'bad merge', 'bad rebuild') 'edit'
            $message = ''
            try { Repair-DefenseClawRecoveredCodexRequirements -Layout $recLayout -GatewayServiceName 'DefenseClawGateway' } catch { $message = $_.Exception.Message }
            if (-not $message.Contains('could not republish the managed policy') -or @(Get-Backups).Count -ne 1) { throw "recovery: failure not named or edit not kept: '$message'" }
            if ([IO.File]::ReadAllText($recRequirements) -ne 'edit' -or -not $message.Contains('the file was left as it was')) { throw "recovery: a failed republish left the file changed: '$([IO.File]::ReadAllText($recRequirements))' / '$message'" }
            # GAP-1001: a gateway that cannot render beside the file is not asked to swap anything: the file stays and the way out is named.
            $script:BaseFileSupported = $false
            Reset-Recovery @('bad', 'bad merge') 'edit'
            $message = ''
            try { Repair-DefenseClawRecoveredCodexRequirements -Layout $recLayout -GatewayServiceName 'DefenseClawGateway' } catch { $message = $_.Exception.Message }
            $script:BaseFileSupported = $true
            if (-not $message.Contains('cannot render the managed policy beside the file') -or [IO.File]::ReadAllText($recRequirements) -ne 'edit' -or $script:RecoverCalls.Count -ne 2 -or -not $message.Contains('/repair')) { throw "recovery: an older gateway was asked to swap, or the file changed: '$message'" }
            # GAP-1001: the original file did not exist and the rebuild fails: no file is left behind.
            Reset-Recovery @('bad', 'bad merge', 'bad rebuild') 'edit'
            Remove-Item -LiteralPath $recRequirements -Force
            $message = ''
            try { Repair-DefenseClawRecoveredCodexRequirements -Layout $recLayout -GatewayServiceName 'DefenseClawGateway' } catch { $message = $_.Exception.Message }
            if ($message -eq '' -or (Test-Path -LiteralPath $recRequirements)) { throw "recovery: a failed rebuild of a missing file left a file behind: '$message'" }
            # GAP-1001: with no recorded preimage the managed policy is rendered into an empty document; nothing is swapped over the path first.
            Write-Record $recRequirements $preimageHash $false
            Reset-Recovery @('bad', 'bad merge', 'ok') 'allow = false'
            Repair-DefenseClawRecoveredCodexRequirements -Layout $recLayout -GatewayServiceName 'DefenseClawGateway'
            if ($script:RecoverCalls.Count -ne 3 -or $script:RecoverCalls[2] -ne 'reconcile:base:') { throw "recovery: a rebuild with no preimage did not render into an empty base: $($script:RecoverCalls -join '|')" }
            Write-Record $recRequirements $preimageHash $true
            foreach ($bad in @(@{ Bytes = [byte[]]@(); Why = 'empty' }, @{ Bytes = [byte[]](0x20, 0x0d, 0x0a); Why = 'white space' }, @{ Bytes = [byte[]](0x61, 0x00, 0x62); Why = 'NUL' }, @{ Bytes = [byte[]](0xc3, 0x28); Why = 'invalid UTF-8' }, @{ Bytes = [byte[]](0xef, 0xbb, 0xbf); Why = 'BOM only' })) {
                $refused = ''
                try { Assert-DefenseClawCodexRequirementsPublishable -Bytes $bad.Bytes } catch { $refused = $_.Exception.Message }
                if (-not $refused.StartsWith('refusing to publish')) { throw "publishable check: $($bad.Why) bytes were not refused: '$refused'" }
            }
            Assert-DefenseClawCodexRequirementsPublishable -Bytes ([Text.Encoding]::UTF8.GetBytes("[features]`nfoo = true`n"))
            # GAP-1001: the rollback's second look finds the document that guards nothing.
            $guardRows = @(
                @{ Text = ''; Guarded = $false },
                @{ Text = "[features]`nfoo = true`n"; Guarded = $false },
                @{ Text = "# comment only`n"; Guarded = $false },
                @{ Text = "[[hooks.PreToolUse]]`n[[hooks.PreToolUse.hooks]]`ncommand = 'C:\\other\\tool.exe'`n"; Guarded = $false },
                @{ Text = "[[hooks.SessionStart]]`n[[hooks.SessionStart.hooks]]`ncommand = 'C:\\Program Files\\Cisco\\DefenseClaw\\bin\\defenseclaw-hook.exe hook --connector codex'`n"; Guarded = $true }
            )
            foreach ($row in $guardRows) {
                $reason = Get-DefenseClawCodexRequirementsGuardProblem -Bytes ([Text.Encoding]::UTF8.GetBytes([string]$row.Text))
                if (([string]::IsNullOrEmpty($reason)) -ne [bool]$row.Guarded) { throw "guard problem: wrong answer '$reason' for '$($row.Text)'" }
            }
            # GAP-1001: a Codex writer that holds the lock is never read as a hand edit: the file is not judged, not backed up, not rebuilt.
            Reset-Recovery @('codex_state_unsettled: a Codex writer holds the writer lock') 'edit'
            $message = ''
            try { Repair-DefenseClawRecoveredCodexRequirements -Layout $recLayout -GatewayServiceName 'DefenseClawGateway' } catch { $message = $_.Exception.Message }
            if (-not $message.StartsWith('codex_state_unsettled: ') -or [IO.File]::ReadAllText($recRequirements) -ne 'edit' -or @(Get-Backups).Count -ne 0 -or $script:RecoverCalls.Count -ne 1) { throw "recovery: a busy writer was read as a hand edit: '$message' calls=$($script:RecoverCalls.Count)" }
            Reset-Recovery @('bad', 'codex_state_unsettled: a Codex writer holds the writer lock') 'edit'
            $message = ''
            try { Repair-DefenseClawRecoveredCodexRequirements -Layout $recLayout -GatewayServiceName 'DefenseClawGateway' } catch { $message = $_.Exception.Message }
            if (-not $message.StartsWith('codex_state_unsettled: ') -or [IO.File]::ReadAllText($recRequirements) -ne 'edit' -or $script:RecoverCalls.Count -ne 2) { throw "recovery: a writer that got busy during the merge led to a rebuild: '$message' calls=$($script:RecoverCalls.Count)" }
            # Held: the retryable code, nothing saved, no reconcile.
            Reset-Recovery @('bad') 'edit'
            $handle = Open-Holder $recRequirements $READ_DATA ($SHARE_R -bor $SHARE_W)
            try {
                $message = ''
                try { Repair-DefenseClawRecoveredCodexRequirements -Layout $recLayout -GatewayServiceName 'DefenseClawGateway' } catch { $message = $_.Exception.Message }
            }
            finally { Close-Holder $handle }
            if (-not $message.StartsWith('codex_requirements_held: ') -or @(Get-Backups).Count -ne 0 -or $script:RecoverCalls.Count -ne 1) { throw "recovery: a held file was not refused by name: '$message'" }
        }
        finally { Set-DefenseClawEnterpriseProfile -EnterpriseProfile SecureClient }
        # Secure Client: the recovery step does nothing.
        Reset-Recovery @('bad') 'edit'
        Repair-DefenseClawRecoveredCodexRequirements -Layout $recLayout -GatewayServiceName 'DefenseClawGateway'
        if ($script:RecoverCalls.Count -ne 0 -or @(Get-Backups).Count -ne 0 -or [IO.File]::ReadAllText($recRequirements) -ne 'edit') { throw 'Secure Client: the recovery step acted' }

        # GAP-0947. A rollback that meets a late holder leaves the file, names
        # the holder, points at /repair (never the forced uninstall), and ends
        # with the retryable code only after everything else was put back.
        Clear-DefenseClawRollbackDeferredHolds
        Set-DefenseClawEnterpriseProfile -EnterpriseProfile Standalone
        try {
            $handle = Open-Holder $heldRequirements $READ_DATA $SHARE_R
            try {
                $deferredMessage = New-DefenseClawCodexFileHeldMessage -Layout $heldLayout -Path $heldRequirements -Why 'open without delete sharing, so the rollback could not put it back'
            }
            finally { Close-Holder $handle }
            if (-not $deferredMessage.StartsWith('codex_requirements_held: ') -or -not $deferredMessage.Contains('/repair') -or $deferredMessage -match 'FORCE|uninstall') {
                throw "deferred rollback hold: not retryable, or not pointing at /repair: '$deferredMessage'"
            }
            # This process is the holder, and the query leaves it out (it is Setup itself): the message says what it can.
            if (-not $deferredMessage.Contains('no process id is available')) { throw "deferred rollback hold: no hint for a holder Windows did not name: '$deferredMessage'" }
            # The recovery step defers instead of stopping the rollback: the
            # held code is recorded, the hold list ends the run.
            Add-DefenseClawRollbackDeferredHold -Message $deferredMessage
            Add-DefenseClawRollbackDeferredHold -Message $deferredMessage
            if ($script:DefenseClawRollbackDeferredHolds.Count -ne 1) { throw 'deferred holds: the same message was listed twice' }
            $clock = [Diagnostics.Stopwatch]::StartNew()
            $second = ''
            $handle = Open-Holder $heldState $holders[0].Access $holders[0].Share
            try { try { [void](Open-DefenseClawCodexRollbackHold -Layout $heldLayout -Path $heldState) } catch { $second = $_.Exception.Message } }
            finally { Close-Holder $handle }
            if (-not $second.StartsWith('codex_state_held: ') -or $clock.Elapsed.TotalSeconds -gt 15) { throw "deferred holds: a second holder waited $([int]$clock.Elapsed.TotalSeconds) s or was not named: '$second'" }
            $ended = ''
            try { Assert-DefenseClawRollbackHoldsResolved } catch { $ended = $_.Exception.Message }
            if ($ended -ne $deferredMessage -or $script:DefenseClawRollbackDeferredHolds.Count -ne 0) { throw "deferred holds: the run did not end with the held message: '$ended'" }
            Assert-DefenseClawRollbackHoldsResolved
            if (-not (Test-DefenseClawRollbackHeldMessage -Message $deferredMessage) -or (Test-DefenseClawRollbackHeldMessage -Message 'Codex requirements reconcile failed: boom')) { throw 'held message test: wrong' }

            # The previous hook, put back after the restored release runs: a
            # holder without delete sharing defers it; a free hook goes back.
            $hookStateRoot = [IO.Path]::Combine($Scratch, 'hook-state'); [void][IO.Directory]::CreateDirectory($hookStateRoot)
            $hookPath = [IO.Path]::Combine($Scratch, 'defenseclaw-hook.exe'); [IO.File]::WriteAllText($hookPath, 'replacement')
            $hookBackup = [IO.Path]::Combine($hookStateRoot, 'file-00.bak'); [IO.File]::WriteAllText($hookBackup, 'previous')
            $hookSha = (Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $hookBackup -Algorithm SHA256).Hash.ToLowerInvariant()
            $hookLayout = @{ HookPath = $hookPath; StateRoot = $hookStateRoot; InstallRoot = $Scratch }
            $hookSnapshot = [pscustomobject]@{
                early_hook_guard_copy = 'guard'
                early_hook_preimage_sha256 = $hookSha
                files = @([pscustomobject]@{ path = $hookPath; existed = $true; backup = $hookBackup })
            }
            $handle = Open-Holder $hookPath $READ_DATA $SHARE_R
            try { Restore-DefenseClawSnapshotHookAfterActivation -Snapshot $hookSnapshot -Layout $hookLayout }
            finally { Close-Holder $handle }
            $hookHeld = $ended = ''
            try { Assert-DefenseClawRollbackHoldsResolved } catch { $hookHeld = $_.Exception.Message }
            if (-not $hookHeld.StartsWith('hook_in_use: ') -or -not $hookHeld.Contains($hookPath) -or -not $hookHeld.Contains('/repair') -or $hookHeld -match 'FORCE') { throw "hook put-back: a held hook was not deferred by name: '$hookHeld'" }
            if ([IO.File]::ReadAllText($hookPath) -ne 'replacement') { throw 'hook put-back: the held replacement hook changed' }
            Restore-DefenseClawSnapshotHookAfterActivation -Snapshot $hookSnapshot -Layout $hookLayout
            if ([IO.File]::ReadAllText($hookPath) -ne 'previous' -or $script:DefenseClawRollbackDeferredHolds.Count -ne 0) { throw 'hook put-back: a free hook was not put back' }
        }
        finally { Set-DefenseClawEnterpriseProfile -EnterpriseProfile SecureClient }
        # Secure Client pin: nothing is deferred or tolerated; the recovery
        # step and the hook put-back act as they did (the hook holder is the
        # error it always was).
        Clear-DefenseClawRollbackDeferredHolds
        Reset-Recovery @('bad') 'edit'
        Repair-DefenseClawRecoveredCodexRequirements -Layout $recLayout -GatewayServiceName 'DefenseClawGateway'
        if ($script:DefenseClawRollbackDeferredHolds.Count -ne 0) { throw 'Secure Client: the recovery step deferred a hold' }
        [IO.File]::WriteAllText($hookPath, 'replacement')
        $handle = Open-Holder $hookPath $READ_DATA $SHARE_R
        $scMessage = ''
        try { try { Restore-DefenseClawSnapshotHookAfterActivation -Snapshot $hookSnapshot -Layout $hookLayout } catch { $scMessage = $_.Exception.Message } }
        finally { Close-Holder $handle }
        if ($scMessage -eq '' -or $scMessage.StartsWith('hook_in_use: ') -or $script:DefenseClawRollbackDeferredHolds.Count -ne 0) { throw "Secure Client: a held hook was deferred instead of failing: '$scMessage'" }

        # Review S1: the early-hook put-back of a recovery (services already
        # running) names a held hook instead of failing with the generic error.
        Set-DefenseClawEnterpriseProfile -EnterpriseProfile Standalone
        try {
            Clear-DefenseClawRollbackDeferredHolds
            $earlyDirectory = [IO.Path]::Combine($Scratch, 'early-hook'); [void][IO.Directory]::CreateDirectory($earlyDirectory)
            $earlyBackup = [IO.Path]::Combine($earlyDirectory, 'early-hook.bak'); [IO.File]::WriteAllText($earlyBackup, 'previous')
            $earlySha = (Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $earlyBackup -Algorithm SHA256).Hash.ToLowerInvariant()
            $earlyIntent = @{ early_hook_preimage = $earlyBackup; early_hook_preimage_sha256 = $earlySha }
            [IO.File]::WriteAllText($hookPath, 'replacement')
            $handle = Open-Holder $hookPath $READ_DATA $SHARE_R
            try { Restore-DefenseClawEarlyHook -Layout $hookLayout -Intent $earlyIntent -TransactionDirectory $earlyDirectory }
            finally { Close-Holder $handle }
            $earlyHeld = ''
            try { Assert-DefenseClawRollbackHoldsResolved } catch { $earlyHeld = $_.Exception.Message }
            if (-not $earlyHeld.StartsWith('hook_in_use: ') -or -not $earlyHeld.Contains($hookPath) -or -not $earlyHeld.Contains('/repair') -or $earlyHeld -match 'FORCE') { throw "early hook put-back: a held hook was not deferred by name: '$earlyHeld'" }
            if ([IO.File]::ReadAllText($hookPath) -ne 'replacement') { throw 'early hook put-back: the held replacement hook changed' }
            Restore-DefenseClawEarlyHook -Layout $hookLayout -Intent $earlyIntent -TransactionDirectory $earlyDirectory
            if ([IO.File]::ReadAllText($hookPath) -ne 'previous' -or $script:DefenseClawRollbackDeferredHolds.Count -ne 0) { throw 'early hook put-back: a free hook was not put back' }

            # Review S2 and S6: the guardian is said not to be proven when the
            # coverage proof was deferred; one file is named once.
            Clear-DefenseClawRollbackDeferredHolds
            Add-DefenseClawRollbackDeferredHold -Message $deferredMessage
            Add-DefenseClawRollbackDeferredHold -Message ($deferredMessage -replace '^codex_requirements_held: [^h]*', 'codex_requirements_held: other.exe (process id 9) ')
            if ($script:DefenseClawRollbackDeferredHolds.Count -ne 1) { throw 'deferred holds: the same file was listed twice' }
            $script:DefenseClawRollbackCoverageDeferred = $true
            $notProven = ''
            try { Assert-DefenseClawRollbackHoldsResolved } catch { $notProven = $_.Exception.Message }
            if (-not $notProven.Contains("The guardian's coverage was not proven by this rollback")) { throw "deferred holds: the result does not say the guardian was not proven: '$notProven'" }
            Add-DefenseClawRollbackDeferredHold -Message $deferredMessage
            $proven = ''
            try { Assert-DefenseClawRollbackHoldsResolved } catch { $proven = $_.Exception.Message }
            if ($proven.Contains('not proven')) { throw 'deferred holds: the guardian note is there without a deferred coverage proof' }

            # Review S5, GAP-0955: the forward reconcile. A hand-edited file the
            # recovery replaces lets the run go on; a failure the recovery does
            # not explain, and a held file, stay failures.
            Reset-Recovery @('allow_managed_hooks_only=false conflicts with required isolation', 'allow_managed_hooks_only is not pinned true', 'ok') 'allow = false'
            Invoke-DefenseClawCodexRequirementsReconcileOrRecover -Layout $recLayout -GatewayServiceName 'DefenseClawGateway'
            $forwardBackups = @(Get-Backups)
            if ($forwardBackups.Count -ne 1 -or [IO.File]::ReadAllText($forwardBackups[0].FullName) -ne 'allow = false' -or [IO.File]::ReadAllText($recRequirements) -ne 'canonical') { throw 'forward reconcile: the hand-edited file was not kept and replaced' }
            Reset-Recovery @('boom', 'ok') 'fine'
            $unexplained = ''
            try { Invoke-DefenseClawCodexRequirementsReconcileOrRecover -Layout $recLayout -GatewayServiceName 'DefenseClawGateway' } catch { $unexplained = $_.Exception.Message }
            if (-not $unexplained.Contains('boom') -or @(Get-Backups).Count -ne 0 -or [IO.File]::ReadAllText($recRequirements) -ne 'fine') { throw "forward reconcile: a failure the recovery does not explain was swallowed: '$unexplained'" }
            Reset-Recovery @('boom', 'bad') 'edit'
            $handle = Open-Holder $recRequirements $READ_DATA ($SHARE_R -bor $SHARE_W)
            $forwardHeld = ''
            try { try { Invoke-DefenseClawCodexRequirementsReconcileOrRecover -Layout $recLayout -GatewayServiceName 'DefenseClawGateway' } catch { $forwardHeld = $_.Exception.Message } }
            finally { Close-Holder $handle }
            if (-not $forwardHeld.StartsWith('codex_requirements_held: ')) { throw "forward reconcile: a held file was not the retryable held error: '$forwardHeld'" }
        }
        finally { Set-DefenseClawEnterpriseProfile -EnterpriseProfile SecureClient }
        Reset-Recovery @('boom') 'edit'
        $scForward = ''
        try { Invoke-DefenseClawCodexRequirementsReconcileOrRecover -Layout $recLayout -GatewayServiceName 'DefenseClawGateway' } catch { $scForward = $_.Exception.Message }
        if (-not $scForward.Contains('boom') -or $script:RecoverCalls.Count -ne 1 -or @(Get-Backups).Count -ne 0) { throw "Secure Client: the forward reconcile recovered instead of failing: '$scForward'" }
    } $scratch $holderType
    'enterprise-standalone-held-file-restamp-smoke: OK'
}
finally {
    Microsoft.PowerShell.Management\Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue
}
