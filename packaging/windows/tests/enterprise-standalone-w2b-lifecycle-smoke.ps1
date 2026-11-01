# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

# Standalone lifecycle regressions of the 1.0.4 Windows fix wave: an
# uninstall refuses a link in its state folder before it changes anything
# (GAP-0145), the InstallRoot retirement rename waits out a short-lived
# holder (GAP-0149), a reinstall accepts the retained redaction key the
# deleted gateway service still held (GAP-0152), a run that starts while a
# purge removes the lifecycle lock gets a new protected one (GAP-1076), and
# the vendor directory check and grant handle an administrator's own entry,
# INTERACTIVE-only grants and group denies (GAP-0867, GAP-1439, GAP-1142).
# Review fixes: a full standalone purge keeps a selector shared with another
# deployment and works under the selector lock, and a deny for an account
# that is not enrolled or no longer exists does not block the vendor check.
# Loop round 1: a deny for a domain SID the lookup cannot map still counts
# (only this computer's own SAM proves a SID retired), and a program that
# holds a file in InstallRoot after the commit defers the retirement to the
# finalizer instead of failing the committed uninstall.
# Loop round 2: no InstallRoot rename runs where another account could
# create an entry in its parent folder (and the pre-commit rename probe is
# gone), a recovery takes the finalizer of a run that stopped before it
# recorded the finalizer's hash, and an uninstall gives back only the vendor
# directory rights Setup recorded adding.
# W2B-G-win loop round 2: a self-uninstall that defers a held InstallRoot to
# the finalizer fails with the retryable uninstall_in_use, never ok.
# Runs elevated in a disposable directory; no service or machine root is
# touched.

[CmdletBinding()]
param(
    [string]$ScratchRoot = [IO.Path]::GetTempPath()
)

Microsoft.PowerShell.Core\Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modulePath = [IO.Path]::GetFullPath(
    (Microsoft.PowerShell.Management\Join-Path $PSScriptRoot '..\DefenseClawEnterprise.psm1')
)
$module = Microsoft.PowerShell.Core\Import-Module -Name $modulePath -Force -PassThru -ErrorAction Stop

$root = [IO.Path]::Combine([IO.Path]::GetFullPath($ScratchRoot), ('dc-w2b-win-' + [Guid]::NewGuid().ToString('N').Substring(0, 8)))
[void][IO.Directory]::CreateDirectory($root)
try {
    $failures = & $module {
        param([string]$Root, [string]$ModulePath)
        $failures = [Collections.Generic.List[string]]::new()
        $savedProgramData = $script:ProgramData
        $savedProfile = Get-DefenseClawEnterpriseProfile
        $savedRetry = $script:InstallRootRetirementRetryMilliseconds
        $savedSelectorTimeout = $script:RuntimeSelectorLockTimeoutSeconds
        $engine = [IO.Path]::Combine($PSHOME, $(if ($PSVersionTable.PSVersion.Major -ge 6) { 'pwsh.exe' } else { 'powershell.exe' }))
        function Start-TestHolder([string]$Path, [string]$Mode, [int]$HoldMilliseconds) {
            # A child process that opens Path (Read: shared read; DeleteOnClose:
            # exclusive with delete-on-close, as a purge does) and holds it.
            $ready = [IO.Path]::Combine($Root, 'ready-' + [Guid]::NewGuid().ToString('N'))
            $script = [IO.Path]::Combine($Root, 'holder-' + [Guid]::NewGuid().ToString('N') + '.ps1')
            [IO.File]::WriteAllText($script, @'
param([string]$Path, [string]$Mode, [string]$Ready, [int]$HoldMilliseconds)
if ($Mode -eq 'DeleteOnClose') {
    $stream = [IO.FileStream]::new($Path, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None, 1, [IO.FileOptions]::DeleteOnClose)
}
else {
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
}
[IO.File]::WriteAllText($Ready, 'ready')
Start-Sleep -Milliseconds $HoldMilliseconds
$stream.Dispose()
'@)
            $arguments = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -Path "{1}" -Mode {2} -Ready "{3}" -HoldMilliseconds {4}' -f $script, $Path, $Mode, $ready, $HoldMilliseconds
            $process = Microsoft.PowerShell.Management\Start-Process -FilePath $engine -ArgumentList $arguments -WindowStyle Hidden -PassThru
            $clock = [Diagnostics.Stopwatch]::StartNew()
            while (-not [IO.File]::Exists($ready)) {
                if ($process.HasExited -or $clock.ElapsedMilliseconds -gt 60000) {
                    throw "test holder of $Path did not open it"
                }
                Microsoft.PowerShell.Utility\Start-Sleep -Milliseconds 50
            }
            return $process
        }
        $protected = 'O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'
        $rootSecurity = [Security.AccessControl.DirectorySecurity]::new()
        $rootSecurity.SetSecurityDescriptorSddlForm($protected, [Security.AccessControl.AccessControlSections]::All)
        Microsoft.PowerShell.Security\Set-Acl -LiteralPath $Root -AclObject $rootSecurity
        $script:ProgramData = $Root
        Set-DefenseClawEnterpriseProfile -EnterpriseProfile Standalone
        try {
            # GAP-0145, mgmt-agent-api GAP-1317: a junction or symbolic link
            # below StateRoot is removed as a link before the uninstall changes
            # the state tree; what it points to keeps every file. A link at
            # StateRoot itself is refused before anything changes, naming how
            # to remove only the link.
            $state = [IO.Path]::Combine($Root, 'state')
            $target = [IO.Path]::Combine($Root, 'junction-target')
            [void][IO.Directory]::CreateDirectory($state)
            [void][IO.Directory]::CreateDirectory($target)
            $targetFile = [IO.Path]::Combine($target, 'kept.txt')
            [IO.File]::WriteAllText($targetFile, 'kept')
            $targetHash = (Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $targetFile).Hash
            $junction = [IO.Path]::Combine($state, 'secrets')
            [void](Microsoft.PowerShell.Management\New-Item -ItemType Junction -Path $junction -Target $target)
            $nested = [IO.Path]::Combine($state, 'logs', 'deeper')
            [void][IO.Directory]::CreateDirectory($nested)
            $nestedJunction = [IO.Path]::Combine($nested, 'link')
            [void](Microsoft.PowerShell.Management\New-Item -ItemType Junction -Path $nestedJunction -Target $target)
            $fileLink = [IO.Path]::Combine($state, 'file-link.txt')
            [void](Microsoft.PowerShell.Management\New-Item -ItemType SymbolicLink -Path $fileLink -Target $targetFile)
            try {
                $warnings = @(Remove-DefenseClawUninstallStateTreeLinks -Layout @{ StateRoot = $state } 3>&1)
            }
            catch {
                $warnings = @()
                $failures.Add("the StateRoot link removal refused: $($_.Exception.Message)")
            }
            foreach ($link in @($junction, $nestedJunction, $fileLink)) {
                if ($null -ne (Microsoft.PowerShell.Management\Get-Item -LiteralPath $link -Force -ErrorAction SilentlyContinue)) {
                    $failures.Add("the uninstall kept the link below StateRoot: $link")
                }
            }
            if ([IO.File]::Exists($fileLink)) {
                [IO.File]::Delete($fileLink)
            }
            if ($warnings.Count -ne 3) {
                $failures.Add("the StateRoot link removal reported $($warnings.Count) links, not 3")
            }
            if (-not [IO.File]::Exists($targetFile) -or
                (Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $targetFile).Hash -ne $targetHash -or
                @(Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $target -Force).Count -ne 1) {
                $failures.Add('removing the StateRoot links changed what they pointed to')
            }
            if (-not [IO.Directory]::Exists($nested)) {
                $failures.Add('removing the StateRoot links removed a real folder')
            }
            $linkedState = [IO.Path]::Combine($Root, 'linked-state')
            [void](Microsoft.PowerShell.Management\New-Item -ItemType Junction -Path $linkedState -Target $target)
            try {
                Remove-DefenseClawUninstallStateTreeLinks -Layout @{ StateRoot = $linkedState }
                $failures.Add('a StateRoot that is a junction passed the uninstall preflight')
            }
            catch {
                if ($_.Exception.Message -notlike 'state_invalid: managed state contains a reparse point:*' -or
                    $_.Exception.Message -notlike '*still installed*' -or
                    $_.Exception.Message -notlike '*rmdir*') {
                    $failures.Add("StateRoot junction refusal: $($_.Exception.Message)")
                }
            }
            if (-not [IO.File]::Exists($targetFile)) {
                $failures.Add('the StateRoot junction refusal changed its target')
            }
            [IO.Directory]::Delete($linkedState)
            Remove-DefenseClawUninstallStateTreeLinks -Layout @{ StateRoot = $state }
            # The link removal runs before the uninstall transaction.
            $tokens = $null
            $errors = $null
            $ast = [Management.Automation.Language.Parser]::ParseFile($ModulePath, [ref]$tokens, [ref]$errors)
            $uninstall = $ast.Find({
                    param($node)
                    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Invoke-DefenseClawUninstallLifecycle'
                }, $true)
            $calls = @($uninstall.FindAll({ param($node) $node -is [Management.Automation.Language.CommandAst] }, $true))
            $preflight = @($calls | Microsoft.PowerShell.Core\Where-Object { $_.GetCommandName() -ceq 'Remove-DefenseClawUninstallStateTreeLinks' })
            $transaction = @($calls | Microsoft.PowerShell.Core\Where-Object { $_.GetCommandName() -ceq 'New-DefenseClawTransaction' })
            if ($preflight.Count -ne 1 -or $transaction.Count -lt 1 -or
                $preflight[0].Extent.StartOffset -ge $transaction[0].Extent.StartOffset) {
                $failures.Add('the StateRoot link removal does not run before the uninstall transaction')
            }

            # GAP-0149: the retirement rename waits for a program that holds a
            # file in InstallRoot for a moment; another failure is immediate.
            $install = [IO.Path]::Combine($Root, 'install')
            $binary = [IO.Path]::Combine($install, 'bin', 'defenseclaw-hook.exe')
            [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($binary))
            [IO.File]::WriteAllText($binary, 'stand-in')
            $script:InstallRootRetirementRetryMilliseconds = 30000
            $holder = Start-TestHolder -Path $binary -Mode Read -HoldMilliseconds 2000
            $retired = [IO.Path]::Combine($Root, 'install-retired')
            try {
                Move-DefenseClawInstallRootForRetirement -Source $install -Destination $retired
                if (-not [IO.Directory]::Exists($retired) -or [IO.Directory]::Exists($install)) {
                    $failures.Add('the retirement rename did not complete after the holder exited')
                }
            }
            catch {
                $failures.Add("the retirement rename failed while a holder was briefly open: $($_.Exception.Message)")
            }
            finally {
                [void]$holder.WaitForExit(30000)
            }
            $clock = [Diagnostics.Stopwatch]::StartNew()
            try {
                Move-DefenseClawInstallRootForRetirement -Source ([IO.Path]::Combine($Root, 'absent')) -Destination ([IO.Path]::Combine($Root, 'absent-retired'))
                $failures.Add('renaming a missing InstallRoot succeeded')
            }
            catch {
                if ($clock.ElapsedMilliseconds -gt 10000) {
                    $failures.Add('a missing InstallRoot was retried as if it were in use')
                }
            }

            # Loop round 2: renaming InstallRoot aside frees its name, so no
            # rename runs where another account could create an entry in the
            # parent folder (a junction or a folder at that name, or a file):
            # nothing could put InstallRoot back, and a recovery would find
            # both trees. Each such parent is refused with InstallRoot in
            # place and nothing retired; an administrator-only parent, one
            # whose create rights are inherit-only or CREATOR OWNER, and one
            # with read for Users are renamed.
            function Set-TestFolderSddl([string]$Path, [string]$Sddl) {
                [void][IO.Directory]::CreateDirectory($Path)
                $security = [Security.AccessControl.DirectorySecurity]::new()
                $security.SetSecurityDescriptorSddlForm($Sddl, [Security.AccessControl.AccessControlSections]::All)
                Microsoft.PowerShell.Security\Set-Acl -LiteralPath $Path -AclObject $security
            }
            $adminOnly = 'O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'
            $openParent = [IO.Path]::Combine($Root, 'open-parent')
            $openInstall = [IO.Path]::Combine($openParent, 'DefenseClaw')
            $openRetired = [IO.Path]::Combine($openParent, 'DefenseClaw.retired')
            $openBinary = [IO.Path]::Combine($openInstall, 'bin', 'defenseclaw-hook.exe')
            $currentSID = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
            $refused = [ordered]@{
                'Users create folders' = '(A;;0x100004;;;BU)'
                'Users create files' = '(A;;0x100002;;;BU)'
                'Authenticated Users generic write' = '(A;;GW;;;AU)'
                'Everyone change permissions' = '(A;;0x140000;;;WD)'
                'Users delete children' = '(A;;0x100040;;;BU)'
                'an unmapped domain group create folders' = '(A;;0x100004;;;S-1-5-21-1000-2000-3000-1234)'
            }
            if ($currentSID -notin @($script:SystemSID, $script:AdministratorsSID, $script:TrustedInstallerSID)) {
                $refused['current account creates folders without elevation'] = ('(A;;0x100004;;;{0})' -f $currentSID)
            }
            foreach ($case in $refused.GetEnumerator()) {
                Set-TestFolderSddl $openParent ($adminOnly + $case.Value)
                [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($openBinary))
                [IO.File]::WriteAllText($openBinary, 'stand-in')
                foreach ($step in @('rename', 'committed')) {
                    try {
                        if ($step -ceq 'rename') {
                            Move-DefenseClawInstallRootForRetirement -Source $openInstall -Destination $openRetired
                        }
                        else {
                            [void](Invoke-DefenseClawCommittedInstallRootRetirement -Source $openInstall -Destination $openRetired)
                        }
                        $failures.Add("the $step retirement renamed InstallRoot while $($case.Key) in its parent")
                    }
                    catch {
                        if ($_.Exception.Message -notlike '*not renamed aside*' -or -not [IO.File]::Exists($openBinary) -or
                            [IO.Directory]::Exists($openRetired)) {
                            $failures.Add("the $step retirement with $($case.Key) in the parent: $($_.Exception.Message)")
                        }
                    }
                }
                if ([IO.Directory]::Exists($openRetired)) {
                    [IO.Directory]::Move($openRetired, $openInstall)
                }
            }
            $accepted = [ordered]@{
                'administrators only' = ''
                'inherit-only Users create' = '(A;OICIIO;0x100006;;;BU)'
                'CREATOR OWNER full' = '(A;OICIIO;GA;;;CO)'
                'Users read and traverse' = '(A;;0x1200a9;;;BU)'
            }
            foreach ($case in $accepted.GetEnumerator()) {
                Set-TestFolderSddl $openParent ($adminOnly + $case.Value)
                try {
                    Move-DefenseClawInstallRootForRetirement -Source $openInstall -Destination $openRetired
                    if ([IO.Directory]::Exists($openInstall) -or -not [IO.Directory]::Exists($openRetired)) {
                        $failures.Add("InstallRoot was not retired with a parent of $($case.Key)")
                    }
                    [IO.Directory]::Move($openRetired, $openInstall)
                }
                catch {
                    $failures.Add("a parent of $($case.Key) refused the retirement: $($_.Exception.Message)")
                }
            }
            # Ownership lets this same account rewrite the DACL without its
            # elevated token, even if no explicit create ACE names it.
            if ($currentSID -notin @($script:SystemSID, $script:AdministratorsSID, $script:TrustedInstallerSID)) {
                Set-TestFolderSddl $openParent ($adminOnly.Replace('O:BA', ('O:' + $currentSID)))
                try {
                    Move-DefenseClawInstallRootForRetirement -Source $openInstall -Destination $openRetired
                    $failures.Add('the retirement trusted the current account as the parent owner')
                }
                catch {
                    if ($_.Exception.Message -notlike '*not renamed aside*' -or -not [IO.File]::Exists($openBinary) -or
                        [IO.Directory]::Exists($openRetired)) {
                        $failures.Add("the current-account ownership refusal: $($_.Exception.Message)")
                    }
                }
                Set-TestFolderSddl $openParent $adminOnly
            }
            # Every retirement rename checks the parent first: the bounded
            # rename, the committed one (through it) and the deferred
            # finalizer's; the uninstall checks it before its transaction, so
            # a self-uninstall stops before it removes anything. The
            # pre-commit rename probe (aside and back) is gone.
            $functions = @{}
            foreach ($node in @($ast.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] }, $true))) {
                $functions[$node.Name] = $node
            }
            if ($functions.ContainsKey('Assert-DefenseClawInstallRootRetirable')) {
                $failures.Add('the pre-commit InstallRoot rename probe is still defined')
            }
            function Get-TestCallOffsets([string]$Function, [string]$Command) {
                return @(@($functions[$Function].FindAll({ param($node) $node -is [Management.Automation.Language.CommandAst] }, $true)) |
                        Microsoft.PowerShell.Core\Where-Object { $_.GetCommandName() -ceq $Command } |
                        Microsoft.PowerShell.Core\ForEach-Object { $_.Extent.StartOffset })
            }
            $moveCheck = @(Get-TestCallOffsets 'Move-DefenseClawInstallRootForRetirement' 'Assert-DefenseClawInstallRootNameReserved')
            $deferredCheck = @(Get-TestCallOffsets 'Complete-DefenseClawDeferredSelfUninstallRetirement' 'Assert-DefenseClawInstallRootNameReserved')
            $deferredMove = @($functions['Complete-DefenseClawDeferredSelfUninstallRetirement'].FindAll({
                        param($node)
                        $node -is [Management.Automation.Language.InvokeMemberExpressionAst] -and [string]$node.Member -ceq 'Move'
                    }, $true) | Microsoft.PowerShell.Core\ForEach-Object { $_.Extent.StartOffset })
            $uninstallCheck = @($calls | Microsoft.PowerShell.Core\Where-Object { $_.GetCommandName() -ceq 'Assert-DefenseClawInstallRootNameReserved' })
            if ($moveCheck.Count -ne 1 -or $deferredCheck.Count -ne 1 -or $deferredMove.Count -ne 1 -or
                $deferredCheck[0] -ge $deferredMove[0] -or $uninstallCheck.Count -ne 1 -or
                $uninstallCheck[0].Extent.StartOffset -ge $transaction[0].Extent.StartOffset) {
                $failures.Add('an InstallRoot retirement rename runs without the parent check, or the uninstall checks it after its transaction started')
            }
            if (@($ast.FindAll({
                            param($node)
                            $node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -ceq 'Assert-DefenseClawInstallRootRetirable'
                        }, $true)).Count -ne 0) {
                $failures.Add('the module still calls the removed rename probe')
            }
            $commit = @($calls | Microsoft.PowerShell.Core\Where-Object { $_.GetCommandName() -ceq 'Complete-DefenseClawTransaction' })

            # Loop round 1: a program that opens a file in InstallRoot and
            # holds it past the retry window no longer fails the committed
            # retirement: it is deferred, with InstallRoot in place. A free
            # InstallRoot is retired, and a missing one is still an error.
            $late = [IO.Path]::Combine($Root, 'late-install')
            $lateRetired = [IO.Path]::Combine($Root, 'late-install-retired')
            $lateBinary = [IO.Path]::Combine($late, 'bin', 'defenseclaw-hook.exe')
            [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($lateBinary))
            [IO.File]::WriteAllText($lateBinary, 'stand-in')
            $script:InstallRootRetirementRetryMilliseconds = 1000
            $holder = Start-TestHolder -Path $lateBinary -Mode Read -HoldMilliseconds 8000
            try {
                $deferred = Invoke-DefenseClawCommittedInstallRootRetirement -Source $late -Destination $lateRetired
                if ([string]::IsNullOrEmpty($deferred) -or -not [IO.File]::Exists($lateBinary) -or [IO.Directory]::Exists($lateRetired)) {
                    $failures.Add("a holder of a file in InstallRoot was not deferred: '$deferred'")
                }
            }
            catch {
                $failures.Add("a holder of a file in InstallRoot failed the committed retirement: $($_.Exception.Message)")
            }
            finally {
                [void]$holder.WaitForExit(30000)
            }
            try {
                $deferred = Invoke-DefenseClawCommittedInstallRootRetirement -Source $late -Destination $lateRetired
                if (-not [string]::IsNullOrEmpty($deferred) -or [IO.Directory]::Exists($late) -or -not [IO.Directory]::Exists($lateRetired)) {
                    $failures.Add("a free InstallRoot was not retired after the commit: '$deferred'")
                }
            }
            catch {
                $failures.Add("a free InstallRoot failed the committed retirement: $($_.Exception.Message)")
            }
            # W4 review, loop round 1: access denied with no program holding a
            # file in InstallRoot is an access list (here a deny of creating
            # or deleting folders in the parent), which no program exit ends:
            # the committed retirement fails with InstallRoot in place
            # instead of deferring to a finalizer that could never finish.
            $deniedParent = [IO.Path]::Combine($Root, 'denied-parent')
            $denied = [IO.Path]::Combine($deniedParent, 'DefenseClaw')
            $deniedRetired = [IO.Path]::Combine($deniedParent, 'DefenseClaw.retired')
            [void][IO.Directory]::CreateDirectory([IO.Path]::Combine($denied, 'bin'))
            [IO.File]::WriteAllText([IO.Path]::Combine($denied, 'bin', 'defenseclaw-hook.exe'), 'stand-in')
            # Loop round 2: the same deny while a program also holds a file
            # in InstallRoot fails too; the holder exiting would not end it.
            Set-TestFolderSddl $deniedParent 'O:BAG:BAD:P(D;;0x44;;;WD)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'
            # GAP-2263: an elevated OpenSSH or similar session starts with
            # SeBackupPrivilege and SeRestorePrivilege enabled, and a rename
            # with those enabled is not checked against the deny, so these
            # rows passed or failed by how the shell was started. Setup runs
            # them as LocalSystem, whose token has both disabled; the rows
            # run the same way here and give back what was enabled.
            $privilegeType = Microsoft.PowerShell.Utility\Add-Type -PassThru -Namespace ('DefenseClawSmoke' + [Guid]::NewGuid().ToString('N')) -Name BackupRestorePrivileges -MemberDefinition @'
[StructLayout(LayoutKind.Sequential)] public struct LUID { public uint Low; public int High; }
[StructLayout(LayoutKind.Sequential)] public struct TOKEN_PRIVILEGES { public uint Count; public LUID Luid; public uint Attributes; }
[DllImport("advapi32.dll", SetLastError = true)] static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
[DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern bool LookupPrivilegeValueW(string system, string name, out LUID luid);
[DllImport("advapi32.dll", SetLastError = true)] static extern bool AdjustTokenPrivileges(IntPtr token, bool disableAll, ref TOKEN_PRIVILEGES state, uint length, ref TOKEN_PRIVILEGES previous, out uint returnLength);
[DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
[DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
// Sets one privilege of this process (enabled or disabled) and returns
// whether it was enabled before; a privilege the token lacks is a no-op.
public static bool Set(string name, bool enable) {
    IntPtr token;
    if (!OpenProcessToken(GetCurrentProcess(), 0x28, out token)) throw new System.ComponentModel.Win32Exception();
    try {
        TOKEN_PRIVILEGES state = new TOKEN_PRIVILEGES();
        state.Count = 1;
        state.Attributes = enable ? 2u : 0u;
        if (!LookupPrivilegeValueW(null, name, out state.Luid)) throw new System.ComponentModel.Win32Exception();
        TOKEN_PRIVILEGES previous = new TOKEN_PRIVILEGES();
        uint length;
        if (!AdjustTokenPrivileges(token, false, ref state, (uint)Marshal.SizeOf(typeof(TOKEN_PRIVILEGES)), ref previous, out length))
            throw new System.ComponentModel.Win32Exception();
        if (Marshal.GetLastWin32Error() == 1300) return false;
        return previous.Count == 0 ? enable : (previous.Attributes & 2u) != 0;
    } finally { CloseHandle(token); }
}
'@
            $privilegeType = @($privilegeType | Microsoft.PowerShell.Core\Where-Object { $_.Name -ceq 'BackupRestorePrivileges' })[0]
            $enabledBefore = @(foreach ($name in @('SeBackupPrivilege', 'SeRestorePrivilege')) {
                    if ($privilegeType::Set($name, $false)) { $name }
                })
            try {
                foreach ($withHolder in @($false, $true)) {
                    $holder = $null
                    if ($withHolder) {
                        $holder = Start-TestHolder -Path ([IO.Path]::Combine($denied, 'bin', 'defenseclaw-hook.exe')) -Mode Read -HoldMilliseconds 8000
                    }
                    try {
                        $deferred = Invoke-DefenseClawCommittedInstallRootRetirement -Source $denied -Destination $deniedRetired
                        $failures.Add("an access-list refusal of the InstallRoot rename (holder: $withHolder) was deferred: '$deferred'")
                    }
                    catch {
                        if ($_.Exception.Message -notlike '*may not create a folder in*does not end when a program exits*' -or
                            -not [IO.Directory]::Exists($denied) -or [IO.Directory]::Exists($deniedRetired)) {
                            $failures.Add("an access-list refusal of the InstallRoot rename (holder: $withHolder): $($_.Exception.Message)")
                        }
                    }
                    finally {
                        if ($null -ne $holder) { [void]$holder.WaitForExit(30000) }
                    }
                }
            }
            finally {
                foreach ($name in $enabledBefore) { [void]$privilegeType::Set($name, $true) }
                Set-TestFolderSddl $deniedParent $adminOnly
            }
            try {
                [void](Invoke-DefenseClawCommittedInstallRootRetirement -Source ([IO.Path]::Combine($Root, 'absent')) -Destination ([IO.Path]::Combine($Root, 'absent-retired')))
                $failures.Add('a missing InstallRoot was deferred instead of failing')
            }
            catch {
                Microsoft.PowerShell.Utility\Write-Verbose "missing InstallRoot refused: $($_.Exception.Message)"
            }
            # The uninstall runs that retirement after its commit, never the
            # bare rename, and hands a deferred one to the finalizer before it
            # retires the teardown journal.
            $committedRetirement = @($calls | Microsoft.PowerShell.Core\Where-Object { $_.GetCommandName() -ceq 'Invoke-DefenseClawCommittedInstallRootRetirement' })
            $bareRename = @($calls | Microsoft.PowerShell.Core\Where-Object { $_.GetCommandName() -ceq 'Move-DefenseClawInstallRootForRetirement' })
            $deferStart = @($calls | Microsoft.PowerShell.Core\Where-Object { $_.GetCommandName() -ceq 'Start-DefenseClawDeferredSelfUninstallRetirement' })
            $journalRetire = @($calls | Microsoft.PowerShell.Core\Where-Object { $_.GetCommandName() -ceq 'Remove-DefenseClawCommittedManagedHooksTeardownJournal' })
            if ($committedRetirement.Count -ne 1 -or $bareRename.Count -ne 0 -or $deferStart.Count -ne 1 -or $journalRetire.Count -lt 1 -or
                $committedRetirement[0].Extent.StartOffset -le $commit[0].Extent.StartOffset -or
                $deferStart[0].Extent.StartOffset -le $committedRetirement[0].Extent.StartOffset -or
                $deferStart[0].Extent.StartOffset -ge $journalRetire[0].Extent.StartOffset) {
                $failures.Add('the committed uninstall does not defer a held InstallRoot to the finalizer before the journal retirement')
            }
            # The finalizer of a deferred retirement runs the module from
            # InstallRoot while the retired one is not there; the usual
            # finalizer content is unchanged (the retired module only).
            $helperLayout = @{ SelfUninstallReceiptPath = 'C:\ProgramData\Cisco\DefenseClaw-Lifecycle\self-uninstall-0.json' }
            $helperReceipt = [pscustomobject]@{
                install_root = 'C:\Program Files\Cisco\DefenseClaw'
                retired_install_root = 'C:\Program Files\Cisco\DefenseClaw.retired-0'
                retired_module_sha256 = ('0' * 64)
            }
            $usual = Get-DefenseClawSelfUninstallHelperContent -Layout $helperLayout -Receipt $helperReceipt
            $deferredContent = Get-DefenseClawSelfUninstallHelperContent -Layout $helperLayout -Receipt $helperReceipt -DeferredRetirement
            $canonicalModule = "'C:\Program Files\Cisco\DefenseClaw\libexec\DefenseClawEnterprise.psm1'"
            foreach ($content in @($usual, $deferredContent)) {
                $parseErrors = $null
                [void][Management.Automation.Language.Parser]::ParseInput($content, [ref]$null, [ref]$parseErrors)
                if (@($parseErrors).Count -gt 0) {
                    $failures.Add("a self-uninstall finalizer does not parse: $($parseErrors -join '; ')")
                }
            }
            if ($usual.Contains($canonicalModule) -or -not $deferredContent.Contains($canonicalModule) -or
                $usual.Replace("`r", '') -cne $deferredContent.Replace("`r", '').Replace(
                    "; if (-not [IO.File]::Exists(`$modulePath)) { `$modulePath = $canonicalModule }", '')) {
                $failures.Add('the deferred finalizer is not the usual one plus the InstallRoot module')
            }

            # GAP-1076: a run waiting for the lock while a purge holds it
            # with delete-on-close gets a new protected lock afterwards.
            $lockDirectory = [IO.Path]::Combine($Root, 'Cisco', 'DefenseClaw-Lifecycle')
            $lockLayout = @{
                LifecycleLockDirectory = $lockDirectory
                LifecycleLockPath = [IO.Path]::Combine($lockDirectory, 'lifecycle.lock')
            }
            Initialize-DefenseClawManagedRoot -Path $lockDirectory -Label 'lifecycle lock directory' -RequiredBase $Root
            Exit-DefenseClawLifecycleLock -Lock (Enter-DefenseClawLifecycleLock -Layout $lockLayout -TimeoutSeconds 10)
            $purge = Start-TestHolder -Path $lockLayout.LifecycleLockPath -Mode DeleteOnClose -HoldMilliseconds 1500
            try {
                $lock = Enter-DefenseClawLifecycleLock -Layout $lockLayout -TimeoutSeconds 20
                Exit-DefenseClawLifecycleLock -Lock $lock
                if (-not [IO.File]::Exists($lockLayout.LifecycleLockPath)) {
                    $failures.Add('the new lifecycle lock is missing')
                }
            }
            catch {
                $failures.Add("a run that started while a purge removed the lock did not get one: $($_.Exception.Message)")
            }
            finally {
                [void]$purge.WaitForExit(30000)
            }

            # Loop round 1: the finalizer of a deferred retirement renames
            # InstallRoot once per pass under the lifecycle lock, waits for a
            # holder outside it, then commits; a holder that outlasts its
            # deadline leaves InstallRoot and the receipt for the next
            # Uninstall, and a receipt another run finished is left alone.
            $deferInstall = [IO.Path]::Combine($Root, 'defer-install')
            $deferRetired = [IO.Path]::Combine($Root, 'defer-install-retired')
            $deferBinary = [IO.Path]::Combine($deferInstall, 'bin', 'defenseclaw-hook.exe')
            $deferLayout = @{
                InstallRoot = $deferInstall
                LifecycleLockDirectory = $lockLayout.LifecycleLockDirectory
                LifecycleLockPath = $lockLayout.LifecycleLockPath
            }
            $stubbed = @(
                'Get-DefenseClawSelfUninstallReceipt',
                'Test-DefenseClawSelfUninstallCallerRunning',
                'Assert-DefenseClawDeferredRetirementState',
                'Complete-DefenseClawCommittedManagedHooksFinalization',
                'Complete-DefenseClawRetiredSelfUninstallCommit'
            )
            $savedFunctions = @{}
            foreach ($name in $stubbed) {
                $savedFunctions[$name] = (Microsoft.PowerShell.Management\Get-Item -LiteralPath "function:$name").ScriptBlock
            }
            $script:TestDeferredCommits = 0
            $script:TestDeferredReceipt = $null
            try {
                function script:Get-DefenseClawSelfUninstallReceipt { param($Layout, $GatewayServiceName, $GuardianServiceName, [switch]$Required) return $script:TestDeferredReceipt }
                function script:Test-DefenseClawSelfUninstallCallerRunning { param($Layout, $Receipt) return $false }
                function script:Assert-DefenseClawDeferredRetirementState { param($Layout, $Receipt) }
                function script:Complete-DefenseClawCommittedManagedHooksFinalization { param($Layout, $GatewayServiceName, $GuardianServiceName, [switch]$Purge, [switch]$NativeSealed) }
                function script:Complete-DefenseClawRetiredSelfUninstallCommit {
                    param($Layout, $Receipt)
                    $script:TestDeferredCommits++
                    $script:TestDeferredReceipt.phase = 'committed_install_retirement'
                }
                function New-TestDeferredRoot {
                    if ([IO.Directory]::Exists($deferRetired)) {
                        [IO.Directory]::Delete($deferRetired, $true)
                    }
                    [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($deferBinary))
                    [IO.File]::WriteAllText($deferBinary, 'stand-in')
                    $script:TestDeferredCommits = 0
                    $script:TestDeferredReceipt = [pscustomobject]@{
                        phase = 'prepared_install_retirement'
                        retired_install_root = $deferRetired
                        gateway_service = 'DefenseClawW2BSmokeAbsent'
                        guardian_service = 'DefenseClawW2BSmokeGuardianAbsent'
                        purge_requested = $false
                    }
                }
                New-TestDeferredRoot
                $holder = Start-TestHolder -Path $deferBinary -Mode Read -HoldMilliseconds 3000
                $clock = [Diagnostics.Stopwatch]::StartNew()
                try {
                    $outcome = Complete-DefenseClawDeferredSelfUninstallRetirement -Layout $deferLayout -Receipt $script:TestDeferredReceipt -Deadline ([DateTime]::UtcNow.AddSeconds(60)) -RetryIntervalMilliseconds 200
                    if ($outcome -cne 'retired' -or [IO.Directory]::Exists($deferInstall) -or -not [IO.Directory]::Exists($deferRetired) -or
                        $script:TestDeferredCommits -ne 1 -or $clock.ElapsedMilliseconds -lt 1000) {
                        $failures.Add("the deferred retirement did not wait out the holder and commit once: $outcome, commits $($script:TestDeferredCommits), $($clock.ElapsedMilliseconds) ms")
                    }
                }
                catch {
                    $failures.Add("the deferred retirement failed while a holder was briefly open: $($_.Exception.Message)")
                }
                finally {
                    [void]$holder.WaitForExit(30000)
                }
                New-TestDeferredRoot
                $holder = Start-TestHolder -Path $deferBinary -Mode Read -HoldMilliseconds 8000
                try {
                    [void](Complete-DefenseClawDeferredSelfUninstallRetirement -Layout $deferLayout -Receipt $script:TestDeferredReceipt -Deadline ([DateTime]::UtcNow.AddSeconds(1)) -RetryIntervalMilliseconds 200)
                    $failures.Add('the deferred retirement passed while a holder outlasted its deadline')
                }
                catch {
                    if ($_.Exception.Message -notlike '*next Uninstall finishes it*' -or -not [IO.File]::Exists($deferBinary) -or
                        [IO.Directory]::Exists($deferRetired) -or $script:TestDeferredCommits -ne 0 -or
                        [string]$script:TestDeferredReceipt.phase -cne 'prepared_install_retirement') {
                        $failures.Add("a holder past the deadline: $($_.Exception.Message)")
                    }
                }
                finally {
                    [void]$holder.WaitForExit(30000)
                }
                # Loop round 2: the finalizer does not rename InstallRoot in a
                # parent another account can create entries in.
                $openDeferLayout = @{
                    InstallRoot = $openInstall
                    LifecycleLockDirectory = $lockLayout.LifecycleLockDirectory
                    LifecycleLockPath = $lockLayout.LifecycleLockPath
                }
                Set-TestFolderSddl $openParent ($adminOnly + '(A;;0x100004;;;BU)')
                New-TestDeferredRoot
                $script:TestDeferredReceipt.retired_install_root = $openRetired
                try {
                    [void](Complete-DefenseClawDeferredSelfUninstallRetirement -Layout $openDeferLayout -Receipt $script:TestDeferredReceipt -Deadline ([DateTime]::UtcNow.AddSeconds(5)) -RetryIntervalMilliseconds 200)
                    $failures.Add('the deferred retirement renamed InstallRoot in a parent Users can create folders in')
                }
                catch {
                    if ($_.Exception.Message -notlike '*not renamed aside*' -or -not [IO.File]::Exists($openBinary) -or
                        [IO.Directory]::Exists($openRetired) -or $script:TestDeferredCommits -ne 0) {
                        $failures.Add("the deferred retirement with an open parent: $($_.Exception.Message)")
                    }
                }
                Set-TestFolderSddl $openParent $adminOnly
                $script:TestDeferredReceipt.retired_install_root = $deferRetired
                $script:TestDeferredReceipt.phase = 'committed_install_retirement'
                if ((Complete-DefenseClawDeferredSelfUninstallRetirement -Layout $deferLayout -Receipt $script:TestDeferredReceipt -Deadline ([DateTime]::UtcNow.AddSeconds(5))) -cne 'not_deferred' -or
                    -not [IO.File]::Exists($deferBinary)) {
                    $failures.Add('the finalizer renamed InstallRoot for a receipt another run committed')
                }
                $script:TestDeferredReceipt = $null
                if ((Complete-DefenseClawDeferredSelfUninstallRetirement -Layout $deferLayout -Receipt ([pscustomobject]@{ gateway_service = 'a'; guardian_service = 'b' }) -Deadline ([DateTime]::UtcNow.AddSeconds(5))) -cne 'finished' -or
                    -not [IO.File]::Exists($deferBinary)) {
                    $failures.Add('the finalizer acted on a receipt another run finished')
                }
            }
            finally {
                foreach ($name in $stubbed) {
                    Microsoft.PowerShell.Management\Set-Item -Path "function:script:$name" -Value $savedFunctions[$name]
                }
            }

            # W2B-G-win review, loop round 2: a committed self-uninstall that
            # hands a held InstallRoot to the finalizer is not finished when
            # the CLI exits (InstallRoot, and with purge the purge, are still
            # there, and nothing confirms the finalizer finishes them), so its
            # result is a retryable uninstall_in_use failure, never ok, with
            # or without purge; the finalizer still starts once, and the
            # status's own errors stay.
            $strandedInstall = [IO.Path]::Combine($Root, 'stranded-install')
            [void][IO.Directory]::CreateDirectory($strandedInstall)
            $strandedLayout = @{
                InstallRoot = $strandedInstall
                SelfUninstallReceiptPath = [IO.Path]::Combine($Root, 'stranded-receipt.json')
                SelfUninstallHelperPath = [IO.Path]::Combine($Root, 'stranded-finalizer.ps1')
                SelfUninstallEnvironmentRoot = [IO.Path]::Combine($Root, 'stranded-environment')
            }
            $strandedStubs = @(
                'Set-DefenseClawSelfUninstallReceiptHelper',
                'Start-DefenseClawSelfUninstallHelper',
                'Get-DefenseClawLifecycleStatus',
                'Add-DefenseClawUserRegistrationCleanupResult'
            )
            $savedStranded = @{}
            foreach ($name in $strandedStubs) {
                $savedStranded[$name] = (Microsoft.PowerShell.Management\Get-Item -LiteralPath "function:$name").ScriptBlock
            }
            $script:TestStrandedPurge = $false
            $script:TestStrandedStarts = 0
            $script:TestStrandedStatusErrors = @()
            try {
                function script:Set-DefenseClawSelfUninstallReceiptHelper {
                    param($Layout, $GatewayServiceName, $GuardianServiceName)
                    return [pscustomobject]@{
                        phase = 'prepared_install_retirement'
                        retired_install_root = [IO.Path]::Combine($Root, 'stranded-install-retired')
                        purge_requested = $script:TestStrandedPurge
                    }
                }
                function script:Start-DefenseClawSelfUninstallHelper { param($Layout, $Receipt) $script:TestStrandedStarts++ }
                function script:Get-DefenseClawLifecycleStatus {
                    param($Action, $Layout, $GatewayServiceName, $GuardianServiceName)
                    return [pscustomobject]@{
                        schema_version = 1
                        ok = $true
                        action = 'uninstall'
                        installed = $false
                        transaction_pending = $false
                        errors = @($script:TestStrandedStatusErrors)
                    }
                }
                function script:Add-DefenseClawUserRegistrationCleanupResult { param($Result, $Layout, $Finalization) return $Result }
                foreach ($case in @(
                        @{ purge = $true; statusErrors = @(); rerun = 'run the uninstall with PURGE=1 again'; finish = 'the uninstall cleanup and the purge' },
                        @{ purge = $false; statusErrors = @(); rerun = 'run the uninstall again'; finish = 'the uninstall cleanup once' },
                        @{ purge = $true; statusErrors = @('a status error'); rerun = 'run the uninstall with PURGE=1 again'; finish = 'the uninstall cleanup and the purge' }
                    )) {
                    $script:TestStrandedPurge = [bool]$case.purge
                    $script:TestStrandedStarts = 0
                    $script:TestStrandedStatusErrors = @($case.statusErrors)
                    $label = "purge=$($case.purge) status errors=$(@($case.statusErrors).Count)"
                    try {
                        $stranded = Start-DefenseClawDeferredSelfUninstallRetirement `
                            -Layout $strandedLayout `
                            -GatewayServiceName 'DefenseClawW2BSmokeAbsent' `
                            -GuardianServiceName 'DefenseClawW2BSmokeGuardianAbsent' `
                            -Finalization $null `
                            -Reason 'The process cannot access the file because it is being used by another process.'
                        $errors = @($stranded.errors)
                        $inUse = @($errors | Microsoft.PowerShell.Core\Where-Object { ([string]$_).StartsWith('uninstall_in_use: ', [StringComparison]::Ordinal) })
                        $json = $stranded | Microsoft.PowerShell.Utility\ConvertTo-Json -Depth 6 -Compress | Microsoft.PowerShell.Utility\ConvertFrom-Json
                        if ([bool]$stranded.ok -or [bool]$json.ok -or $inUse.Count -ne 1 -or $errors.Count -ne (@($case.statusErrors).Count + 1) -or
                            ($errors.Count -gt 1 -and [string]$errors[0] -cne 'a status error') -or
                            -not ([string]$inUse[0]).Contains($strandedInstall) -or
                            -not ([string]$inUse[0]).Contains('being used by another process') -or
                            -not ([string]$inUse[0]).Contains([string]$case.rerun) -or
                            -not ([string]$inUse[0]).Contains([string]$case.finish) -or
                            (-not $case.purge -and ([string]$inUse[0]).Contains('PURGE=1')) -or
                            -not [bool]$stranded.self_uninstall_cleanup_pending -or
                            [bool]$stranded.canonical_install_root_absent -or
                            [string]::IsNullOrWhiteSpace([string]$stranded.install_root_retirement_deferred) -or
                            [bool]$stranded.installed -or $script:TestStrandedStarts -ne 1) {
                            $failures.Add("a self-uninstall with a held InstallRoot ($label) did not fail with uninstall_in_use: ok=$($stranded.ok) errors=$($errors -join ' | ') starts=$($script:TestStrandedStarts) canonical_absent=$($stranded.canonical_install_root_absent)")
                        }
                    }
                    catch {
                        $failures.Add("a self-uninstall with a held InstallRoot ($label) threw: $($_.Exception.Message)")
                    }
                }
            }
            finally {
                foreach ($name in $strandedStubs) {
                    Microsoft.PowerShell.Management\Set-Item -Path "function:script:$name" -Value $savedStranded[$name]
                }
            }

            # Loop round 2: a run that stopped after it wrote the finalizer
            # of a deferred retirement and before it recorded its hash leaves
            # a prepared receipt with no hash. The next Uninstall's recovery
            # (the usual finalizer variant) takes that finalizer, as one of
            # the receipt's two exact variants, and records its hash; a
            # finalizer of other content, or one that does not match a
            # recorded hash, is still refused.
            $crashLayout = @{
                LifecycleLockDirectory = $lockLayout.LifecycleLockDirectory
                SelfUninstallReceiptPath = [IO.Path]::Combine($lockLayout.LifecycleLockDirectory, 'self-uninstall-' + ('0' * 64) + '.json')
                SelfUninstallHelperPath = [IO.Path]::Combine($lockLayout.LifecycleLockDirectory, 'self-uninstall-finalizer-w2b.ps1')
                SelfUninstallEnvironmentRoot = [IO.Path]::Combine($lockLayout.LifecycleLockDirectory, 'self-uninstall-environment-w2b')
            }
            function New-TestCrashReceipt([string]$HelperHash = '') {
                return [pscustomobject]@{
                    phase = 'prepared_install_retirement'
                    install_root = 'C:\Program Files\Cisco\DefenseClaw'
                    retired_install_root = 'C:\Program Files\Cisco\DefenseClaw.retired-0'
                    retired_module_sha256 = ('0' * 64)
                    helper_sha256 = $HelperHash
                }
            }
            $crashStubbed = @('Get-DefenseClawSelfUninstallReceipt', 'Write-DefenseClawJsonAtomic')
            $savedCrashFunctions = @{}
            foreach ($name in $crashStubbed) {
                $savedCrashFunctions[$name] = (Microsoft.PowerShell.Management\Get-Item -LiteralPath "function:$name").ScriptBlock
            }
            $script:TestCrashReceipt = New-TestCrashReceipt
            try {
                function script:Get-DefenseClawSelfUninstallReceipt { param($Layout, $GatewayServiceName, $GuardianServiceName, [switch]$Required) return $script:TestCrashReceipt }
                function script:Write-DefenseClawJsonAtomic { param($Value, $Path) throw 'w2b test: the run stops before it writes the receipt' }
                try {
                    [void](Set-DefenseClawSelfUninstallReceiptHelper -Layout $crashLayout -GatewayServiceName 'a' -GuardianServiceName 'b')
                    $failures.Add('the crash stand-in did not stop the receipt write')
                }
                catch {
                    if ($_.Exception.Message -notlike '*stops before it writes the receipt*') {
                        $failures.Add("the deferred finalizer write failed: $($_.Exception.Message)")
                    }
                }
            }
            finally {
                foreach ($name in $crashStubbed) {
                    Microsoft.PowerShell.Management\Set-Item -Path "function:script:$name" -Value $savedCrashFunctions[$name]
                }
            }
            $usualHash = Get-DefenseClawTextSHA256 -Value (Get-DefenseClawSelfUninstallHelperContent -Layout $crashLayout -Receipt (New-TestCrashReceipt))
            $deferredHash = Get-DefenseClawTextSHA256 -Value (Get-DefenseClawSelfUninstallHelperContent -Layout $crashLayout -Receipt (New-TestCrashReceipt) -DeferredRetirement)
            if (-not [IO.File]::Exists($crashLayout.SelfUninstallHelperPath) -or
                (Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $crashLayout.SelfUninstallHelperPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $deferredHash) {
                $failures.Add('the crash stand-in did not leave the deferred finalizer')
            }
            foreach ($variant in @('usual', 'deferred')) {
                $recovered = New-TestCrashReceipt
                try {
                    [void](Ensure-DefenseClawSelfUninstallHelper -Layout $crashLayout -Receipt $recovered -DeferredRetirement:($variant -ceq 'deferred'))
                    if ([string]$recovered.helper_sha256 -cne $deferredHash) {
                        $failures.Add("the $variant recovery recorded '$($recovered.helper_sha256)', not the existing deferred finalizer's hash")
                    }
                }
                catch {
                    $failures.Add("the $variant recovery refused the deferred finalizer of a receipt with no hash: $($_.Exception.Message)")
                }
            }
            try {
                [void](Ensure-DefenseClawSelfUninstallHelper -Layout $crashLayout -Receipt (New-TestCrashReceipt -HelperHash $usualHash))
                $failures.Add('a deferred finalizer passed for a receipt that recorded the usual one')
            }
            catch {
                if ($_.Exception.Message -notlike '*hash does not match its receipt*') {
                    $failures.Add("a finalizer that does not match its recorded hash: $($_.Exception.Message)")
                }
            }
            [IO.File]::WriteAllText($crashLayout.SelfUninstallHelperPath, '# another finalizer')
            try {
                [void](Ensure-DefenseClawSelfUninstallHelper -Layout $crashLayout -Receipt (New-TestCrashReceipt))
                $failures.Add('a finalizer of other content passed for a receipt with no hash')
            }
            catch {
                if ($_.Exception.Message -notlike '*different protected receipt content*') {
                    $failures.Add("a finalizer of other content: $($_.Exception.Message)")
                }
            }
            [IO.File]::Delete($crashLayout.SelfUninstallHelperPath)
            $recovered = New-TestCrashReceipt
            [void](Ensure-DefenseClawSelfUninstallHelper -Layout $crashLayout -Receipt $recovered)
            if ([string]$recovered.helper_sha256 -cne $usualHash) {
                $failures.Add('a receipt with no hash and no finalizer did not get the usual finalizer')
            }
            [IO.File]::Delete($crashLayout.SelfUninstallHelperPath)

            # GAP-0867: an administrator's identical Users entry survives
            # install and uninstall.
            function Set-TestDirectorySddl([string]$Path, [string]$Sddl) {
                [void][IO.Directory]::CreateDirectory($Path)
                $security = [Security.AccessControl.DirectorySecurity]::new()
                $security.SetSecurityDescriptorSddlForm($Sddl, [Security.AccessControl.AccessControlSections]::All)
                Microsoft.PowerShell.Security\Set-Acl -LiteralPath $Path -AclObject $security
            }
            $vendor = [IO.Path]::Combine($Root, 'vendor')
            # The StateRoot of the deployment scope each grant is for.
            $productionScope = [IO.Path]::Combine($Root, 'scope-production')
            [void][IO.Directory]::CreateDirectory($productionScope)
            Set-TestDirectorySddl $vendor 'O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x1200a0;;;BU)'
            $before = (Microsoft.PowerShell.Security\Get-Acl -LiteralPath $vendor).Sddl
            Grant-DefenseClawStandaloneVendorUsersRead -Path $vendor -Scope $productionScope
            Revoke-DefenseClawStandaloneVendorUsersRead -Path $vendor -Scope $productionScope
            if ((Microsoft.PowerShell.Security\Get-Acl -LiteralPath $vendor).Sddl -cne $before) {
                $failures.Add("uninstall removed the administrator's own Users entry from the vendor directory")
            }
            # Review loop round 2: Setup records which rights it added, and
            # an uninstall gives back only those. An administrator's entry
            # with any rights (the 0x1200a8 one included) stays exactly;
            # one Setup completed keeps the administrator's rights; one Setup
            # created goes, with its record. A record for another folder, or
            # an unreadable one, takes nothing away.
            $grantRecord = Get-DefenseClawVendorUsersReadGrantPath
            Remove-DefenseClawVendorUsersReadGrant
            foreach ($existing in @('(A;;0x1200a8;;;BU)', '(A;;0x1200a9;;;BU)', '(A;;FA;;;BU)')) {
                Set-TestDirectorySddl $vendor ('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)' + $existing)
                $before = (Microsoft.PowerShell.Security\Get-Acl -LiteralPath $vendor).Sddl
                Grant-DefenseClawStandaloneVendorUsersRead -Path $vendor -Scope $productionScope
                Revoke-DefenseClawStandaloneVendorUsersRead -Path $vendor -Scope $productionScope
                if ((Microsoft.PowerShell.Security\Get-Acl -LiteralPath $vendor).Sddl -cne $before -or [IO.File]::Exists($grantRecord)) {
                    $failures.Add("uninstall changed an administrator's Users entry $existing on the vendor directory")
                }
            }
            Set-TestDirectorySddl $vendor 'O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x120080;;;BU)'
            $before = (Microsoft.PowerShell.Security\Get-Acl -LiteralPath $vendor).Sddl
            Grant-DefenseClawStandaloneVendorUsersRead -Path $vendor -Scope $productionScope
            if (-not (Test-DefenseClawStandaloneVendorUsersRead -Path $vendor) -or
                (Get-DefenseClawVendorUsersReadGrant -Path $vendor) -ne 0x20) {
                $failures.Add("Setup did not complete an administrator's partial Users entry, or did not record only what it added")
            }
            # Get-Acl projects same-SID allow rules. Inspect the on-disk
            # descriptor so this catches a widened foreign ACE, not a
            # FileSystemSecurity projection of two separate raw ACEs.
            $native = Initialize-DefenseClawNativeSecurity
            $partialSnapshot = $native::GetDirectorySecuritySnapshotNoFollow($vendor)
            $partialRaw = [Security.AccessControl.RawSecurityDescriptor]::new(
                [byte[]]$partialSnapshot.SecurityDescriptor, 0)
            $originalUsers = @($partialRaw.DiscretionaryAcl | Microsoft.PowerShell.Core\Where-Object {
                    $_ -is [Security.AccessControl.KnownAce] -and
                    $_.SecurityIdentifier.Value -ceq $script:UsersSID -and
                    $_.AccessMask -eq 0x120080
                })
            $addedUsers = @($partialRaw.DiscretionaryAcl | Microsoft.PowerShell.Core\Where-Object {
                    $_ -is [Security.AccessControl.KnownAce] -and
                    $_.SecurityIdentifier.Value -ceq $script:UsersSID -and
                    $_.AccessMask -eq 0x20
                })
            if ($originalUsers.Count -ne 1 -or $addedUsers.Count -ne 1) {
                $failures.Add("Setup widened the administrator's partial Users ACE instead of adding its own")
            }
            Revoke-DefenseClawStandaloneVendorUsersRead -Path $vendor -Scope $productionScope
            if ((Microsoft.PowerShell.Security\Get-Acl -LiteralPath $vendor).Sddl -cne $before -or [IO.File]::Exists($grantRecord)) {
                $failures.Add("uninstall took the administrator's own rights with Setup's: $((Microsoft.PowerShell.Security\Get-Acl -LiteralPath $vendor).Sddl)")
            }
            Set-TestDirectorySddl $vendor 'O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'
            $before = (Microsoft.PowerShell.Security\Get-Acl -LiteralPath $vendor).Sddl
            Grant-DefenseClawStandaloneVendorUsersRead -Path $vendor -Scope $productionScope
            Grant-DefenseClawStandaloneVendorUsersRead -Path $vendor -Scope $productionScope
            if (-not (Test-DefenseClawStandaloneVendorUsersRead -Path $vendor) -or
                (Get-DefenseClawVendorUsersReadGrant -Path $vendor) -ne 0x1200a0) {
                $failures.Add('Setup did not record the Users entry it created')
            }
            Set-DefenseClawVendorUsersReadGrant -Path ([IO.Path]::Combine($Root, 'other-vendor')) -AddedRights 0x1200a0 -Scopes @($productionScope)
            Revoke-DefenseClawStandaloneVendorUsersRead -Path $vendor -Scope $productionScope
            if (-not (Test-DefenseClawStandaloneVendorUsersRead -Path $vendor) -or [IO.File]::Exists($grantRecord)) {
                $failures.Add('a grant record for another folder took the vendor entry away, or stayed')
            }
            Set-DefenseClawVendorUsersReadGrant -Path $vendor -AddedRights 0x1200a0 -Scopes @($productionScope)
            [IO.File]::WriteAllText($grantRecord, '{ not json')
            Revoke-DefenseClawStandaloneVendorUsersRead -Path $vendor -Scope $productionScope 3>$null
            if (-not (Test-DefenseClawStandaloneVendorUsersRead -Path $vendor) -or [IO.File]::Exists($grantRecord)) {
                $failures.Add('an unreadable grant record took the vendor entry away, or stayed')
            }
            Set-DefenseClawVendorUsersReadGrant -Path $vendor -AddedRights 0x1200a0 -Scopes @($productionScope)
            Revoke-DefenseClawStandaloneVendorUsersRead -Path $vendor -Scope $productionScope
            if ((Microsoft.PowerShell.Security\Get-Acl -LiteralPath $vendor).Sddl -cne $before -or [IO.File]::Exists($grantRecord)) {
                $failures.Add('uninstall did not give back the Users entry Setup created')
            }
            # A second installer or GPO can replace the vendor DACL after
            # Setup. Repair must restore its grant, and uninstall must leave
            # that replacement DACL exactly as it found it.
            Grant-DefenseClawStandaloneVendorUsersRead -Path $vendor -Scope $productionScope
            Set-TestDirectorySddl $vendor 'O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'
            $reset = (Microsoft.PowerShell.Security\Get-Acl -LiteralPath $vendor).Sddl
            Grant-DefenseClawStandaloneVendorUsersRead -Path $vendor -Scope $productionScope
            Grant-DefenseClawStandaloneVendorUsersRead -Path $vendor -Scope $productionScope
            if (-not (Test-DefenseClawStandaloneVendorUsersRead -Path $vendor) -or
                (Get-DefenseClawVendorUsersReadGrant -Path $vendor) -ne 0x1200a0) {
                $failures.Add('repair did not restore the recorded vendor Users grant')
            }
            Revoke-DefenseClawStandaloneVendorUsersRead -Path $vendor -Scope $productionScope
            if ((Microsoft.PowerShell.Security\Get-Acl -LiteralPath $vendor).Sddl -cne $reset -or [IO.File]::Exists($grantRecord)) {
                $failures.Add('uninstall did not preserve the externally reset vendor DACL')
            }
            Grant-DefenseClawStandaloneVendorUsersRead -Path $vendor -Scope $productionScope
            Set-TestDirectorySddl $vendor 'O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x120080;;;BU)'
            $partialReset = (Microsoft.PowerShell.Security\Get-Acl -LiteralPath $vendor).Sddl
            Grant-DefenseClawStandaloneVendorUsersRead -Path $vendor -Scope $productionScope
            $partialSnapshot = $native::GetDirectorySecuritySnapshotNoFollow($vendor)
            $partialRepaired = [Security.AccessControl.RawSecurityDescriptor]::new(
                [byte[]]$partialSnapshot.SecurityDescriptor, 0)
            $foreignPartial = @($partialRepaired.DiscretionaryAcl | Microsoft.PowerShell.Core\Where-Object {
                    $_ -is [Security.AccessControl.KnownAce] -and
                    $_.SecurityIdentifier.Value -ceq $script:UsersSID -and $_.AccessMask -eq 0x120080
                })
            if ($foreignPartial.Count -ne 1 -or
                (Get-DefenseClawVendorUsersReadGrant -Path $vendor) -ne 0x20 -or
                -not (Test-DefenseClawStandaloneVendorUsersRead -Path $vendor)) {
                $failures.Add('repair widened a foreign partial Users ACE or recorded the wrong rights')
            }
            Revoke-DefenseClawStandaloneVendorUsersRead -Path $vendor -Scope $productionScope
            if ((Microsoft.PowerShell.Security\Get-Acl -LiteralPath $vendor).Sddl -cne $partialReset -or [IO.File]::Exists($grantRecord)) {
                $failures.Add('uninstall changed the foreign partial Users ACE after repair')
            }
            # Review loop round 3: production and certification scopes share
            # the vendor directory and its grant record. A certification
            # rollback or uninstall keeps the rights production Setup added,
            # whether or not the certification install recorded that it
            # relies on them; a production uninstall keeps them for a
            # certification scope that is still installed; the last scope
            # to go gives them back; and a scope whose StateRoot is gone
            # (removed without an uninstall) no longer holds them.
            $certificationScope = [IO.Path]::Combine($Root, 'scope-certification')
            [void][IO.Directory]::CreateDirectory($certificationScope)
            function Test-TestGrantScopes([string[]]$Want) {
                $got = @(Get-DefenseClawVendorUsersReadGrantScopes -Path $vendor)
                return ($got.Count -eq $Want.Count -and
                    @($Want | Microsoft.PowerShell.Core\Where-Object { $got -contains [IO.Path]::GetFullPath($_).TrimEnd('\') }).Count -eq $Want.Count)
            }
            Set-TestDirectorySddl $vendor 'O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'
            $before = (Microsoft.PowerShell.Security\Get-Acl -LiteralPath $vendor).Sddl
            Grant-DefenseClawStandaloneVendorUsersRead -Path $vendor -Scope $productionScope
            $granted = (Microsoft.PowerShell.Security\Get-Acl -LiteralPath $vendor).Sddl
            # The rollback of a certification install that found the rights.
            Revoke-DefenseClawStandaloneVendorUsersRead -Path $vendor -Scope $certificationScope
            if ((Microsoft.PowerShell.Security\Get-Acl -LiteralPath $vendor).Sddl -cne $granted -or
                -not (Test-DefenseClawStandaloneVendorUsersRead -Path $vendor) -or -not (Test-TestGrantScopes @($productionScope))) {
                $failures.Add('a certification rollback took away the vendor rights production Setup added')
            }
            Grant-DefenseClawStandaloneVendorUsersRead -Path $vendor -Scope $certificationScope
            if ((Microsoft.PowerShell.Security\Get-Acl -LiteralPath $vendor).Sddl -cne $granted -or
                -not (Test-TestGrantScopes @($productionScope, $certificationScope))) {
                $failures.Add('a certification install over production changed the vendor entry or did not record that it relies on it')
            }
            Revoke-DefenseClawStandaloneVendorUsersRead -Path $vendor -Scope $certificationScope
            if ((Microsoft.PowerShell.Security\Get-Acl -LiteralPath $vendor).Sddl -cne $granted -or
                -not (Test-DefenseClawStandaloneVendorUsersRead -Path $vendor) -or -not (Test-TestGrantScopes @($productionScope))) {
                $failures.Add('a certification uninstall took away the vendor rights production Setup added')
            }
            Revoke-DefenseClawStandaloneVendorUsersRead -Path $vendor -Scope $productionScope
            if ((Microsoft.PowerShell.Security\Get-Acl -LiteralPath $vendor).Sddl -cne $before -or [IO.File]::Exists($grantRecord)) {
                $failures.Add('the uninstall of the last scope did not give back the vendor entry and its record')
            }
            Grant-DefenseClawStandaloneVendorUsersRead -Path $vendor -Scope $certificationScope
            Grant-DefenseClawStandaloneVendorUsersRead -Path $vendor -Scope $productionScope
            Revoke-DefenseClawStandaloneVendorUsersRead -Path $vendor -Scope $productionScope
            if ((Microsoft.PowerShell.Security\Get-Acl -LiteralPath $vendor).Sddl -cne $granted -or
                -not (Test-TestGrantScopes @($certificationScope))) {
                $failures.Add('a production uninstall took away the vendor rights an installed certification scope relies on')
            }
            Revoke-DefenseClawStandaloneVendorUsersRead -Path $vendor -Scope $certificationScope
            if ((Microsoft.PowerShell.Security\Get-Acl -LiteralPath $vendor).Sddl -cne $before -or [IO.File]::Exists($grantRecord)) {
                $failures.Add('the certification uninstall, the last scope, did not give back the vendor entry')
            }
            Grant-DefenseClawStandaloneVendorUsersRead -Path $vendor -Scope $certificationScope
            Grant-DefenseClawStandaloneVendorUsersRead -Path $vendor -Scope $productionScope
            [IO.Directory]::Delete($certificationScope)
            Revoke-DefenseClawStandaloneVendorUsersRead -Path $vendor -Scope $productionScope
            if ((Microsoft.PowerShell.Security\Get-Acl -LiteralPath $vendor).Sddl -cne $before -or [IO.File]::Exists($grantRecord)) {
                $failures.Add('a scope whose StateRoot is gone kept the vendor entry')
            }
            # GAP-1439: INTERACTIVE alone is not every enrolled token.
            Set-TestDirectorySddl $vendor 'O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x1200a0;;;IU)'
            if (Test-DefenseClawStandaloneVendorUsersRead -Path $vendor) {
                $failures.Add('an INTERACTIVE-only entry counted as access for every enrolled user')
            }
            # GAP-1142: a deny for a domain group removes access; one for a
            # service SID does not.
            Set-TestDirectorySddl $vendor 'O:BAG:BAD:P(D;;0x1200a0;;;S-1-5-21-1000-2000-3000-513)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x1200a0;;;BU)'
            if (Test-DefenseClawStandaloneVendorUsersRead -Path $vendor) {
                $failures.Add('a group deny entry was not detected')
            }
            Set-TestDirectorySddl $vendor 'O:BAG:BAD:P(D;;0x1200a0;;;S-1-5-80-1-2-3-4-5)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x1200a0;;;BU)'
            if (-not (Test-DefenseClawStandaloneVendorUsersRead -Path $vendor)) {
                $failures.Add('a service SID deny entry blocked the users check')
            }
            # Review of GAP-1142: a deny for an account of this computer that
            # no one has (a retired local user) beside a valid Users entry
            # does not block, so Grant converges; a deny for a built-in group
            # or for an enrolled user (this account, which has a profile here)
            # still does. Loop round 1: a domain SID the lookup does not map
            # (a custom domain group above RID 999, while the domain
            # controller does not answer) counts, since an enrolled user's
            # token can hold it.
            $nativeSecurity = Initialize-DefenseClawNativeSecurity
            function Get-TestSidUse([string]$Sid) {
                $identifier = [Security.Principal.SecurityIdentifier]::new($Sid)
                $bytes = [byte[]]::new($identifier.BinaryLength)
                $identifier.GetBinaryForm($bytes, 0)
                return $nativeSecurity::LookupSidUse($bytes)
            }
            $unmappedDomainGroup = 'S-1-5-21-1000-2000-3000-1234'
            $unmappedUse = Get-TestSidUse $unmappedDomainGroup
            if ($unmappedUse -ne 0) {
                $failures.Add("the lookup of an unknown domain SID returned $unmappedUse, not none-mapped")
            }
            if (-not (Test-DefenseClawUserTokenDenySID -SID $unmappedDomainGroup)) {
                $failures.Add('a deny for an unmapped domain group above RID 999 was treated as a retired account')
            }
            Set-TestDirectorySddl $vendor ('O:BAG:BAD:P(D;;0x1200a0;;;' + $unmappedDomainGroup + ')(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x1200a0;;;BU)')
            if (Test-DefenseClawStandaloneVendorUsersRead -Path $vendor) {
                $failures.Add('a deny entry for an unmapped domain group did not block the users check')
            }
            $accountDomain = Get-DefenseClawAccountDomainSID
            if ($accountDomain -cnotmatch '^S-1-5-21-\d+-\d+-\d+$') {
                $failures.Add("this computer's account domain SID was not read: '$accountDomain'")
            }
            $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
            if ($currentUser.Name -like "$env:COMPUTERNAME\*" -and $null -ne $currentUser.User.AccountDomainSid -and
                $currentUser.User.AccountDomainSid.Value -cne $accountDomain) {
                $failures.Add("the account domain SID $accountDomain is not the local account's $($currentUser.User.AccountDomainSid.Value)")
            }
            $retiredLocal = $accountDomain + '-2147483000'
            if ((Get-TestSidUse $retiredLocal) -ne 0) {
                $failures.Add("the retired local SID $retiredLocal is mapped")
            }
            $retiredDeny = '(D;;0x1200a0;;;' + $retiredLocal + ')'
            Set-TestDirectorySddl $vendor ('O:BAG:BAD:P' + $retiredDeny + '(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x1200a0;;;BU)')
            if (-not (Test-DefenseClawStandaloneVendorUsersRead -Path $vendor)) {
                $failures.Add('a deny entry for a retired account blocked the users check')
            }
            Set-TestDirectorySddl $vendor ('O:BAG:BAD:P' + $retiredDeny + '(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
            Grant-DefenseClawStandaloneVendorUsersRead -Path $vendor -Scope $productionScope
            if (-not (Test-DefenseClawStandaloneVendorUsersRead -Path $vendor)) {
                $failures.Add('the vendor grant did not converge beside a deny for a retired account')
            }
            Set-TestDirectorySddl $vendor 'O:BAG:BAD:P(D;;0x1200a0;;;S-1-5-32-555)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x1200a0;;;BU)'
            if (Test-DefenseClawStandaloneVendorUsersRead -Path $vendor) {
                $failures.Add('a deny entry for a built-in group was not detected')
            }
            $self = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
            if (@(Get-DefenseClawManagedUserRuntimeHomes | Microsoft.PowerShell.Core\Where-Object { $_.sid -ceq $self }).Count -eq 1) {
                Set-TestDirectorySddl $vendor ('O:BAG:BAD:P(D;;0x1200a0;;;{0})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x1200a0;;;BU)' -f $self)
                if (Test-DefenseClawStandaloneVendorUsersRead -Path $vendor) {
                    $failures.Add('a deny entry for an enrolled user was not detected')
                }
            }
            # That deny names this account: drop it, so the scratch tree can
            # be listed and removed.
            Set-TestDirectorySddl $vendor 'O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'

            # Review of GAP-1158: the full standalone purge (the committed
            # cleanup's selector step, then the orphaned-state step) keeps a
            # selector that holds targets of this deployment and another,
            # with its lock and bytes. A selector with only this deployment's
            # targets goes, with or without a lock file, and neither step
            # touches a selector while a hook holds its lock.
            $ownHook = 'C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe'
            $otherHook = 'D:\Other\DefenseClaw\bin\defenseclaw-hook.exe'
            $selectorPF = [IO.Path]::Combine($Root, 'selector-pf')
            $selectorPD = [IO.Path]::Combine($Root, 'selector-pd')
            $claudeDir = [IO.Path]::Combine($selectorPF, 'ClaudeCode', 'managed-settings.d')
            $codexDir = [IO.Path]::Combine($selectorPD, 'OpenAI', 'Codex')
            $cursorDir = [IO.Path]::Combine($selectorPD, 'Cursor')
            $stateLeaf = '.defenseclaw-managed-runtime-selector.state'
            $lockLeaf = '.defenseclaw-managed-runtime-selector.lock'
            function New-TestSelector([string]$Directory, [string[]]$Hooks) {
                [void][IO.Directory]::CreateDirectory($Directory)
                $targets = @(for ($i = 0; $i -lt $Hooks.Count; $i++) {
                        @{ connector = 'codex'; sid = "S-1-5-21-1-2-3-$(1001 + $i)"; hook_executable = $Hooks[$i] }
                    })
                $document = @{ schema_version = 1; connector = 'codex'; targets = $targets } |
                    Microsoft.PowerShell.Utility\ConvertTo-Json -Depth 4
                [IO.File]::WriteAllText([IO.Path]::Combine($Directory, $stateLeaf), $document)
                [IO.File]::WriteAllText([IO.Path]::Combine($Directory, $lockLeaf), '')
                # Setup writes these as an administrator. A runner account
                # whose token makes itself the owner of new files (the
                # built-in Administrator) would make them untrusted.
                foreach ($tree in @($selectorPF, $selectorPD)) {
                    if (-not [IO.Directory]::Exists($tree)) {
                        continue
                    }
                    foreach ($item in @(@(Microsoft.PowerShell.Management\Get-Item -LiteralPath $tree -Force) +
                            @(Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $tree -Recurse -Force))) {
                        $security = Microsoft.PowerShell.Security\Get-Acl -LiteralPath $item.FullName
                        $security.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
                        Microsoft.PowerShell.Security\Set-Acl -LiteralPath $item.FullName -AclObject $security
                    }
                }
            }
            function Invoke-TestSelectorPurge {
                @(Remove-DefenseClawRuntimeSelectorState -HookPath $ownHook -Directories @($claudeDir, $codexDir, $cursorDir)) +
                @(Remove-DefenseClawStandaloneOrphanedHookMachineState `
                        -Layout @{ HookPath = $ownHook; CodexMachinePolicyDirectory = $codexDir } `
                        -ProgramFiles $selectorPF `
                        -ProgramData $selectorPD)
            }
            $codexState = [IO.Path]::Combine($codexDir, $stateLeaf)
            $codexLock = [IO.Path]::Combine($codexDir, $lockLeaf)
            $cursorState = [IO.Path]::Combine($cursorDir, $stateLeaf)
            $cursorLock = [IO.Path]::Combine($cursorDir, $lockLeaf)
            New-TestSelector $codexDir @($ownHook, $otherHook)
            $mixed = [IO.File]::ReadAllText($codexState)
            New-TestSelector $cursorDir @($ownHook)
            $left = @(Invoke-TestSelectorPurge)
            if (-not [IO.File]::Exists($codexState) -or -not [IO.File]::Exists($codexLock) -or
                [IO.File]::ReadAllText($codexState) -cne $mixed -or
                @($left | Microsoft.PowerShell.Core\Where-Object { $_ -like "*Codex*another DefenseClaw deployment*" }).Count -lt 1) {
                $failures.Add("the full purge removed or changed a selector shared with another deployment: $($left -join '; ')")
            }
            if ([IO.File]::Exists($cursorState) -or [IO.File]::Exists($cursorLock)) {
                $failures.Add("the full purge kept a selector with only this deployment's targets: $($left -join '; ')")
            }
            New-TestSelector $cursorDir @($ownHook)
            [IO.File]::Delete($cursorLock)
            $left = @(Invoke-TestSelectorPurge)
            if ([IO.File]::Exists($cursorState) -or [IO.File]::Exists($cursorLock)) {
                $failures.Add("a selector without a lock file stayed, or left a lock: $($left -join '; ')")
            }
            New-TestSelector $cursorDir @($ownHook)
            $script:RuntimeSelectorLockTimeoutSeconds = 1
            $hook = Start-TestHolder -Path $cursorLock -Mode Read -HoldMilliseconds 8000
            try {
                $left = @(Invoke-TestSelectorPurge)
                if (-not [IO.File]::Exists($cursorState) -or
                    @($left | Microsoft.PowerShell.Core\Where-Object { $_ -like "*Cursor*lock could not be taken*" }).Count -lt 1) {
                    $failures.Add("a selector was removed while a hook held its lock: $($left -join '; ')")
                }
            }
            finally {
                [void]$hook.WaitForExit(30000)
                $script:RuntimeSelectorLockTimeoutSeconds = $savedSelectorTimeout
            }
            $left = @(Invoke-TestSelectorPurge)
            if ([IO.File]::Exists($cursorState) -or [IO.File]::Exists($cursorLock)) {
                $failures.Add("the selector stayed after the hook released its lock: $($left -join '; ')")
            }

            # GAP-0152: the retained key held by the deleted gateway's
            # per-service SID becomes administrator-only with its bytes kept;
            # a key another account can read stays refused.
            $serviceName = 'DefenseClawW2BSmokeAbsent'
            $serviceSID = Get-DefenseClawDeterministicServiceSID -ServiceName $serviceName
            $runtime = [IO.Path]::Combine($Root, 'runtime')
            [void][IO.Directory]::CreateDirectory($runtime)
            $keyLayout = @{ RuntimeDirectory = $runtime; RedactionCorrelationKeyPath = [IO.Path]::Combine($runtime, 'redaction-correlation.key') }
            [IO.File]::WriteAllBytes($keyLayout.RedactionCorrelationKeyPath, [byte[]](1..32))
            $keyHash = (Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $keyLayout.RedactionCorrelationKeyPath).Hash
            function Set-TestKeySddl([string]$Sddl) {
                $security = [Security.AccessControl.FileSecurity]::new()
                $security.SetSecurityDescriptorSddlForm($Sddl, [Security.AccessControl.AccessControlSections]::All)
                Microsoft.PowerShell.Security\Set-Acl -LiteralPath $keyLayout.RedactionCorrelationKeyPath -AclObject $security
            }
            Set-TestKeySddl ('O:BAG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;{0})' -f $serviceSID)
            Repair-DefenseClawRetainedRedactionKeyAcl -Layout $keyLayout -GatewayServiceName $serviceName
            try {
                $snapshot = Get-DefenseClawRedactionKeySecuritySnapshot -Layout $keyLayout -GatewayServiceSID ''
                if ([string]$snapshot.preimage_class -cne 'inactive_admin' -or
                    (Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $keyLayout.RedactionCorrelationKeyPath).Hash -cne $keyHash) {
                    $failures.Add("the retained key was not normalized with its bytes kept: $($snapshot.preimage_class)")
                }
            }
            catch {
                $failures.Add("the retained service-held key is still refused: $($_.Exception.Message)")
            }
            Set-TestKeySddl ('O:BAG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;{0})(A;;FR;;;BU)' -f $serviceSID)
            Repair-DefenseClawRetainedRedactionKeyAcl -Layout $keyLayout -GatewayServiceName $serviceName
            try {
                [void](Get-DefenseClawRedactionKeySecuritySnapshot -Layout $keyLayout -GatewayServiceSID '')
                $failures.Add('a key that Users can read was accepted')
            }
            catch {
                if ($_.Exception.Message -notlike '*Set-Acl*') {
                    $failures.Add("the refusal does not give the Set-Acl recovery: $($_.Exception.Message)")
                }
            }
        }
        finally {
            $script:ProgramData = $savedProgramData
            $script:InstallRootRetirementRetryMilliseconds = $savedRetry
            $script:RuntimeSelectorLockTimeoutSeconds = $savedSelectorTimeout
            Set-DefenseClawEnterpriseProfile -EnterpriseProfile $savedProfile
        }
        return , $failures
    } $root $modulePath
}
finally {
    foreach ($entry in @(Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue |
            Microsoft.PowerShell.Core\Where-Object { ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 })) {
        [IO.Directory]::Delete($entry.FullName)
    }
    Microsoft.PowerShell.Management\Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}

if ($failures.Count -gt 0) {
    foreach ($failure in $failures) {
        Microsoft.PowerShell.Utility\Write-Output "FAIL: $failure"
    }
    exit 1
}
Microsoft.PowerShell.Utility\Write-Output 'enterprise-standalone-w2b-lifecycle-smoke: OK'
