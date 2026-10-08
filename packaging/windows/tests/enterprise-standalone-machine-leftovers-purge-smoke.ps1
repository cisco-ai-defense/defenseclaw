# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 5.1

# What a standalone purge removes outside StateRoot, and what it reports.
# GAP-0100: the Claude Code managed-settings.d and ClaudeCode folders Setup
# created go once dropping the serialization lock leaves them empty, and stay
# while they hold anything else. GAP-1734: stale protected
# DefenseClaw-PowerShell-<32 hex> temp folders go, except the one this run
# uses and the launching CLI's own (GAP-1853: install-enterprise.ps1 moves
# TEMP into its bootstrap folder, and the CLI still removes its folder after
# PowerShell exits); one it cannot remove is reported. GAP-2057: stale
# DefenseClaw-Installer-<32 hex> staging folders in ProgramData and
# DefenseClaw-Bootstrap-<32 hex> folders in Windows\Temp go the same way,
# except the bootstrap folder this run's TEMP points into. GAP-0525: stale
# DefenseClaw-Enterprise-Setup-<32 hex> staging folders go too, except young
# or busy ones, which are reported. GAP-0262: the
# hooks' runtime selector state and lock go, so the Claude Code folders they
# kept go too. GAP-0575, GAP-0562: without a deployment record, the hook
# machine state that names this scope's hook executable and the public
# policy summary go. GAP-0938: a standalone uninstall drops the Codex ACL
# preimage of a requirements.toml the managed-hook teardown already removed.
# Runs in a disposable scratch directory; no service or machine root is
# touched.

[CmdletBinding()]
param()

Microsoft.PowerShell.Core\Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

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

$scratch = Microsoft.PowerShell.Management\Join-Path `
    ([IO.Path]::GetTempPath()) `
    ('dc-machine-leftovers-' + [guid]::NewGuid().ToString('N'))
$failures = & $module {
    param([string]$Scratch)
    Microsoft.PowerShell.Core\Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'
    $failures = [Collections.Generic.List[string]]::new()
    $savedTemp = $env:TEMP
    try {
        # GAP-0100
        $empty = Microsoft.PowerShell.Management\Join-Path $Scratch 'empty'
        [void][IO.Directory]::CreateDirectory([IO.Path]::Combine($empty, 'ClaudeCode', 'managed-settings.d'))
        $out = @(Remove-DefenseClawEmptyClaudeManagedSettingsFolders -ProgramFiles $empty)
        if ($out.Count -ne 0 -or (Microsoft.PowerShell.Management\Test-Path -LiteralPath ([IO.Path]::Combine($empty, 'ClaudeCode')))) {
            $failures.Add("empty ClaudeCode\managed-settings.d was not removed cleanly: $($out -join '; ')")
        }
        $kept = Microsoft.PowerShell.Management\Join-Path $Scratch 'kept'
        $dropIns = [IO.Path]::Combine($kept, 'ClaudeCode', 'managed-settings.d')
        [void][IO.Directory]::CreateDirectory($dropIns)
        [IO.File]::WriteAllText([IO.Path]::Combine($dropIns, '50-other-vendor.json'), '{}')
        [void]@(Remove-DefenseClawEmptyClaudeManagedSettingsFolders -ProgramFiles $kept)
        if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath ([IO.Path]::Combine($dropIns, '50-other-vendor.json')))) {
            $failures.Add('a managed-settings.d holding another file was removed')
        }
        $other = Microsoft.PowerShell.Management\Join-Path $Scratch 'other'
        [void][IO.Directory]::CreateDirectory([IO.Path]::Combine($other, 'ClaudeCode', 'managed-settings.d'))
        [IO.File]::WriteAllText([IO.Path]::Combine($other, 'ClaudeCode', 'managed-settings.json'), '{}')
        [void]@(Remove-DefenseClawEmptyClaudeManagedSettingsFolders -ProgramFiles $other)
        if ((Microsoft.PowerShell.Management\Test-Path -LiteralPath ([IO.Path]::Combine($other, 'ClaudeCode', 'managed-settings.d'))) -or
            -not (Microsoft.PowerShell.Management\Test-Path -LiteralPath ([IO.Path]::Combine($other, 'ClaudeCode', 'managed-settings.json')))) {
            $failures.Add('a ClaudeCode folder holding another file lost it, or kept its empty managed-settings.d')
        }
        if (@(Remove-DefenseClawEmptyClaudeManagedSettingsFolders -ProgramFiles (Microsoft.PowerShell.Management\Join-Path $Scratch 'absent')).Count -ne 0) {
            $failures.Add('an absent ClaudeCode folder was reported')
        }

        # GAP-1734. The ACL check and the guarded tree removal need a real
        # machine root, so they are replaced here; the selection is under test.
        function Assert-DefenseClawPathAcl {
            param([string]$Path, [string[]]$AllowedWriterSIDs)
            if ($Path.EndsWith('b' * 32)) {
                throw "untrusted owner S-1-5-21-1 on managed path: $Path"
            }
        }
        function Remove-DefenseClawManagedTree {
            param([string]$Path, [string]$RequiredBase, [string]$Label)
            Microsoft.PowerShell.Management\Remove-Item -LiteralPath $Path -Recurse -Force
        }
        $programData = Microsoft.PowerShell.Management\Join-Path $Scratch 'ProgramData'
        $stale = [IO.Path]::Combine($programData, 'DefenseClaw-PowerShell-' + ('a' * 32))
        $foreign = [IO.Path]::Combine($programData, 'DefenseClaw-PowerShell-' + ('b' * 32))
        $own = [IO.Path]::Combine($programData, 'DefenseClaw-PowerShell-' + ('c' * 32))
        $launcher = [IO.Path]::Combine($programData, 'DefenseClaw-PowerShell-' + ('d' * 32))
        $unrelated = [IO.Path]::Combine($programData, 'DefenseClaw-PowerShell-notours')
        $staleInstaller = [IO.Path]::Combine($programData, 'DefenseClaw-Installer-' + ('e' * 32))
        $windowsTemp = Microsoft.PowerShell.Management\Join-Path $Scratch 'WindowsTemp'
        $staleBootstrap = [IO.Path]::Combine($windowsTemp, 'DefenseClaw-Bootstrap-' + ('f' * 32))
        $ownBootstrap = [IO.Path]::Combine($windowsTemp, 'DefenseClaw-Bootstrap-' + ('1' * 32))
        $retiredBootstrap = [IO.Path]::Combine($windowsTemp, 'DefenseClaw-Bootstrap-Retired-' + ('2' * 32))
        [IO.Directory]::CreateDirectory($staleInstaller) | Microsoft.PowerShell.Core\Out-Null
        [IO.File]::WriteAllText([IO.Path]::Combine($staleInstaller, 'install-enterprise.ps1'), '#')
        [IO.Directory]::CreateDirectory([IO.Path]::Combine($staleBootstrap, 'compiler')) | Microsoft.PowerShell.Core\Out-Null
        [void][IO.Directory]::CreateDirectory($retiredBootstrap)
        [void][IO.Directory]::CreateDirectory([IO.Path]::Combine($stale, 'AppData', 'Local', 'Microsoft', 'PowerShell'))
        foreach ($path in @($foreign, $own, $unrelated)) {
            [void][IO.Directory]::CreateDirectory($path)
        }
        [void][IO.Directory]::CreateDirectory([IO.Path]::Combine($launcher, 'AppData', 'Local', 'Microsoft', 'PowerShell'))
        $env:TEMP = $own
        $script:DefenseClawLauncherTemp = $launcher + '\'
        $left = @(Remove-DefenseClawStaleRunDirectories -ProgramData $programData -WindowsTemp $windowsTemp)
        if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $stale) {
            $failures.Add('a stale DefenseClaw-PowerShell temp folder was not removed')
        }
        foreach ($path in @($staleInstaller, $staleBootstrap)) {
            if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $path) {
                $failures.Add("a stale run folder was not removed: $path")
            }
        }
        if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $retiredBootstrap)) {
            $failures.Add("removed a folder it must keep: $retiredBootstrap")
        }
        foreach ($path in @($foreign, $own, $launcher, $unrelated)) {
            if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $path)) {
                $failures.Add("removed a folder it must keep: $path")
            }
        }
        if ($left.Count -ne 1 -or -not ([string]$left[0]).StartsWith("${foreign}: untrusted owner")) {
            $failures.Add("kept-folder report was '$($left -join '; ')'")
        }
        # This run's TEMP is inside its bootstrap folder (GAP-1853).
        [void][IO.Directory]::CreateDirectory($ownBootstrap)
        $env:TEMP = $ownBootstrap
        [void]@(Remove-DefenseClawStaleRunDirectories -ProgramData $programData -WindowsTemp $windowsTemp)
        if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $ownBootstrap)) {
            $failures.Add("removed this run's bootstrap folder: $ownBootstrap")
        }

        # GAP-0525: the staging folder an interrupted Setup left goes once it
        # is 30 minutes old; a younger one, and one a running Setup holds as
        # its working directory, stay and are reported.
        $setupStale = [IO.Path]::Combine($programData, 'DefenseClaw-Enterprise-Setup-' + ('3' * 32))
        $setupYoung = [IO.Path]::Combine($programData, 'DefenseClaw-Enterprise-Setup-' + ('4' * 32))
        $setupBusy = [IO.Path]::Combine($programData, 'DefenseClaw-Enterprise-Setup-' + ('5' * 32))
        foreach ($path in @($setupStale, $setupYoung, $setupBusy)) {
            [void][IO.Directory]::CreateDirectory([IO.Path]::Combine($path, 'scratch'))
        }
        foreach ($path in @($setupStale, $setupBusy)) {
            [IO.Directory]::SetCreationTimeUtc($path, [DateTime]::UtcNow.AddHours(-2))
        }
        $savedDirectory = [Environment]::CurrentDirectory
        [Environment]::CurrentDirectory = $setupBusy
        try {
            $left = @(Remove-DefenseClawStaleRunDirectories -ProgramData $programData -WindowsTemp $windowsTemp)
        }
        finally {
            [Environment]::CurrentDirectory = $savedDirectory
        }
        $setupLeft = @(Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $programData -Directory -Filter 'DefenseClaw-Enterprise-Setup-*' |
                Microsoft.PowerShell.Core\ForEach-Object { $_.FullName } | Microsoft.PowerShell.Utility\Sort-Object)
        if (($setupLeft -join ';') -cne (@($setupYoung, $setupBusy) -join ';')) {
            $failures.Add("Setup staging folders left: $($setupLeft -join '; ')")
        }
        foreach ($expected in @("${setupYoung}: created less than 30 minutes ago", "${setupBusy}: in use by a running Setup")) {
            if (@($left | Microsoft.PowerShell.Core\Where-Object { ([string]$_).StartsWith($expected) }).Count -ne 1) {
                $failures.Add("Setup staging report lacks '$expected': $($left -join '; ')")
            }
        }

        # GAP-0526: once a CLI uninstall's finalizer removed the install
        # root, the empty C:\Program Files\Cisco it sat in goes; a Cisco
        # folder that holds anything else stays.
        $savedProfile = Get-DefenseClawEnterpriseProfile
        $savedProgramFiles = $script:ProgramFiles
        Set-DefenseClawEnterpriseProfile -EnterpriseProfile Standalone
        try {
            $script:ProgramFiles = Microsoft.PowerShell.Management\Join-Path $Scratch 'PF'
            $vendor = [IO.Path]::Combine($script:ProgramFiles, 'Cisco')
            [void][IO.Directory]::CreateDirectory($vendor)
            Remove-DefenseClawEmptyStandaloneInstallParent -Layout @{ InstallRoot = [IO.Path]::Combine($vendor, 'DefenseClaw') }
            if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $vendor) {
                $failures.Add('an empty Program Files\Cisco was kept after the install root went')
            }
            [void][IO.Directory]::CreateDirectory([IO.Path]::Combine($vendor, 'Other'))
            Remove-DefenseClawEmptyStandaloneInstallParent -Layout @{ InstallRoot = [IO.Path]::Combine($vendor, 'DefenseClaw') }
            if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath ([IO.Path]::Combine($vendor, 'Other')))) {
                $failures.Add('a Program Files\Cisco holding another folder was removed')
            }
        }
        finally {
            $script:ProgramFiles = $savedProgramFiles
            Set-DefenseClawEnterpriseProfile -EnterpriseProfile $savedProfile
        }

        # GAP-0533: an uninstall that finds no recorded state still removes
        # DefenseClaw's machine-wide hook files: the drop-ins that name this
        # scope's hook, and the hook runtime folder with its connector
        # folders (the ACL check and the tree removal are still replaced, as
        # above).
        $savedProgramFiles = $script:ProgramFiles
        $savedProgramData = $script:ProgramData
        $savedProfile = Get-DefenseClawEnterpriseProfile
        Set-DefenseClawEnterpriseProfile -EnterpriseProfile Standalone
        try {
            $script:ProgramFiles = Microsoft.PowerShell.Management\Join-Path $Scratch 'PF533'
            $script:ProgramData = Microsoft.PowerShell.Management\Join-Path $Scratch 'PD533'
            $hook533 = 'C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe'
            $named533 = '{"hook_executable":"' + $hook533.Replace('\', '\\') + '"}'
            $claudeDropIns = [IO.Path]::Combine($script:ProgramFiles, 'ClaudeCode', 'managed-settings.d')
            [void][IO.Directory]::CreateDirectory($claudeDropIns)
            foreach ($leaf in @('90-defenseclaw.json', '.defenseclaw-managed-hooks.state', '.defenseclaw-managed-runtime-selector.state')) {
                [IO.File]::WriteAllText([IO.Path]::Combine($claudeDropIns, $leaf), $named533)
            }
            [IO.File]::WriteAllText([IO.Path]::Combine($claudeDropIns, '00-defenseclaw-version-floor.json'), '{}')
            $hookRuntime = [IO.Path]::Combine($script:ProgramData, 'Cisco', 'DefenseClaw-HookRuntime')
            [void][IO.Directory]::CreateDirectory([IO.Path]::Combine($hookRuntime, 'opencode'))
            [IO.File]::WriteAllText([IO.Path]::Combine($hookRuntime, 'machine-policy.json'), '{}')
            $layout533 = @{
                StateRoot = [IO.Path]::Combine($script:ProgramData, 'Cisco', 'DefenseClaw')
                HookPath = $hook533
                CodexMachinePolicyDirectory = ''
            }
            $left = @(
                @(Remove-DefenseClawUnattributedStandaloneHookRuntime -Layout $layout533) +
                @(Remove-DefenseClawStandaloneOrphanedHookMachineState -Layout $layout533)
            )
            if ($left.Count -ne 0 -or
                (Microsoft.PowerShell.Management\Test-Path -LiteralPath ([IO.Path]::Combine($script:ProgramFiles, 'ClaudeCode'))) -or
                (Microsoft.PowerShell.Management\Test-Path -LiteralPath $hookRuntime)) {
                $failures.Add("a state-absent uninstall left DefenseClaw's machine-wide hook files: $($left -join '; ')")
            }
        }
        finally {
            $script:ProgramFiles = $savedProgramFiles
            $script:ProgramData = $savedProgramData
            Set-DefenseClawEnterpriseProfile -EnterpriseProfile $savedProfile
        }

        # GAP-0262 (the ACL check is still replaced, as above).
        $selector = Microsoft.PowerShell.Management\Join-Path $Scratch 'selector'
        $selectorDropIns = [IO.Path]::Combine($selector, 'ClaudeCode', 'managed-settings.d')
        [void][IO.Directory]::CreateDirectory($selectorDropIns)
        foreach ($leaf in @('.defenseclaw-managed-runtime-selector.state', '.defenseclaw-managed-runtime-selector.lock')) {
            $file = [IO.Path]::Combine($selectorDropIns, $leaf)
            [IO.File]::WriteAllText($file, '{}')
            [IO.File]::SetAttributes($file, [IO.FileAttributes]::Hidden)
        }
        $left = @(
            @(Remove-DefenseClawRuntimeSelectorState -Directories @($selectorDropIns, '', [IO.Path]::Combine($selector, 'absent'))) +
            @(Remove-DefenseClawEmptyClaudeManagedSettingsFolders -ProgramFiles $selector)
        )
        if ($left.Count -ne 0 -or (Microsoft.PowerShell.Management\Test-Path -LiteralPath ([IO.Path]::Combine($selector, 'ClaudeCode')))) {
            $failures.Add("the runtime selector state kept ClaudeCode\managed-settings.d: $($left -join '; ')")
        }

        # GAP-0575, GAP-0562: with no deployment record, the hook machine
        # state that names this scope's hook executable goes (the Claude Code
        # policy, its state, lock and floor, and the runtime selectors), one
        # that names another hook stays and is named, and the public policy
        # summary goes with its empty HookRuntime folder.
        $savedProfile = Get-DefenseClawEnterpriseProfile
        Set-DefenseClawEnterpriseProfile -EnterpriseProfile Standalone
        try {
            $orphanFiles = Microsoft.PowerShell.Management\Join-Path $Scratch 'orphan-pf'
            $orphanData = Microsoft.PowerShell.Management\Join-Path $Scratch 'orphan-pd'
            $hook = 'C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe'
            $named = '"' + $hook.Replace('\', '\\') + '"'
            $claudeDropIns = [IO.Path]::Combine($orphanFiles, 'ClaudeCode', 'managed-settings.d')
            $codexPolicy = [IO.Path]::Combine($orphanData, 'OpenAI', 'Codex')
            foreach ($directory in @($claudeDropIns, $codexPolicy)) {
                [void][IO.Directory]::CreateDirectory($directory)
            }
            foreach ($entry in @(
                    @('90-defenseclaw.json', ('{"hooks":{"Stop":[{"hooks":[{"command":' + $named + '}]}]}}')),
                    @('.defenseclaw-managed-hooks.state', ('{"hook_executable":' + $named + '}')),
                    @('.defenseclaw-managed-hooks.lock', ''),
                    @('00-defenseclaw-version-floor.json', '{}'),
                    @('.defenseclaw-managed-runtime-selector.state', ('{"targets":[{"hook_executable":' + $named + '}]}')),
                    @('.defenseclaw-managed-runtime-selector.lock', ''))) {
                [IO.File]::WriteAllText([IO.Path]::Combine($claudeDropIns, $entry[0]), $entry[1])
            }
            $otherSelector = [IO.Path]::Combine($codexPolicy, '.defenseclaw-managed-runtime-selector.state')
            [IO.File]::WriteAllText($otherSelector, '{"targets":[{"hook_executable":"C:\\Other\\defenseclaw-hook.exe"}]}')
            $orphanLayout = @{ HookPath = $hook; CodexMachinePolicyDirectory = $codexPolicy }
            $left = @(Remove-DefenseClawStandaloneOrphanedHookMachineState -Layout $orphanLayout -ProgramFiles $orphanFiles -ProgramData $orphanData)
            if (Microsoft.PowerShell.Management\Test-Path -LiteralPath ([IO.Path]::Combine($orphanFiles, 'ClaudeCode'))) {
                $failures.Add('the orphaned Claude Code hook machine state was not removed')
            }
            if (-not [IO.File]::Exists($otherSelector) -or $left.Count -ne 1 -or
                -not ([string]$left[0]).StartsWith("${otherSelector}: kept")) {
                $failures.Add("another hook's selector was not kept and named: $($left -join '; ')")
            }
            $hookRuntime = [IO.Path]::Combine($orphanData, 'Cisco', 'DefenseClaw-HookRuntime')
            [void][IO.Directory]::CreateDirectory($hookRuntime)
            [IO.File]::WriteAllText([IO.Path]::Combine($hookRuntime, 'machine-policy.json'), '{}')
            $left = @(Remove-DefenseClawStandaloneHookRuntimeLeftovers -Directory $hookRuntime)
            if ($left.Count -ne 0 -or [IO.Directory]::Exists($hookRuntime)) {
                $failures.Add("the HookRuntime folder and its machine-policy.json stayed: $($left -join '; ')")
            }
        }
        finally {
            Set-DefenseClawEnterpriseProfile -EnterpriseProfile $savedProfile
        }

        # GAP-0938: a fresh ensure adopted the requirements.toml a purge
        # without the state root left, so its ACL preimage records a file
        # that existed before the deployment. The managed-hook teardown then
        # deletes that file and its ownership record, and the removal after
        # it finds nothing. A standalone uninstall drops the preimage of the
        # missing file; Secure Client keeps the refusal.
        $codexState = Microsoft.PowerShell.Management\Join-Path $Scratch 'codex-acl'
        [void][IO.Directory]::CreateDirectory($codexState)
        $codexLayout = @{
            CodexMachinePolicyPath = [IO.Path]::Combine($codexState, 'requirements.toml')
            CodexRequirementsOwnershipPath = [IO.Path]::Combine($codexState, 'codex-requirements-ownership.json')
            CodexManagedHooksStatePath = [IO.Path]::Combine($codexState, '.defenseclaw-managed-hooks.state')
            CodexRequirementsAclBackupPath = [IO.Path]::Combine($codexState, 'codex-requirements-acl-backup.json')
        }
        $absentRemoval = [pscustomobject]@{
            disposition = 'ownership_absent'
            safe_to_remove_binary = $true
            managed_state_existed = $false
            managed_state_removed = $false
            managed_state_removed_or_absent = $true
            surviving_owned_path_references = 0
        }
        $savedProfile = Get-DefenseClawEnterpriseProfile
        try {
            foreach ($case in @(@('Standalone', $false), @('SecureClient', $true))) {
                Set-DefenseClawEnterpriseProfile -EnterpriseProfile $case[0]
                [IO.File]::WriteAllText($codexLayout.CodexRequirementsAclBackupPath, (([ordered]@{
                                schema_version = 1
                                path = $codexLayout.CodexMachinePolicyPath
                                existed = $true
                                sha256 = ('a' * 64)
                                security_descriptor = 'O:BAG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)'
                            }) | Microsoft.PowerShell.Utility\ConvertTo-Json))
                $refused = $false
                try {
                    Complete-DefenseClawCodexRequirementsRemoval `
                        -Layout $codexLayout `
                        -GatewayServiceName 'DefenseClawGateway' `
                        -Report $absentRemoval
                }
                catch {
                    $refused = ([string]$_.Exception.Message).StartsWith('verified-absent Codex removal retains an ACL preimage')
                    if (-not $refused) {
                        $failures.Add("$($case[0]): unexpected Codex removal error: $($_.Exception.Message)")
                    }
                }
                if ($refused -ne $case[1] -or [IO.File]::Exists($codexLayout.CodexRequirementsAclBackupPath) -ne $case[1]) {
                    $failures.Add("$($case[0]): the preimage of a missing requirements.toml was refused=$refused, kept=$([IO.File]::Exists($codexLayout.CodexRequirementsAclBackupPath))")
                }
            }
        }
        finally {
            Set-DefenseClawEnterpriseProfile -EnterpriseProfile $savedProfile
        }
    }
    finally {
        $env:TEMP = $savedTemp
        $script:DefenseClawLauncherTemp = ''
        if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $Scratch) {
            Microsoft.PowerShell.Management\Remove-Item -LiteralPath $Scratch -Recurse -Force
        }
    }
    return , $failures
} $scratch

if (@($failures).Count -gt 0) {
    foreach ($failure in @($failures)) {
        Microsoft.PowerShell.Utility\Write-Output "FAIL: $failure"
    }
    exit 1
}
Microsoft.PowerShell.Utility\Write-Output 'enterprise-standalone-machine-leftovers-purge-smoke: OK'
