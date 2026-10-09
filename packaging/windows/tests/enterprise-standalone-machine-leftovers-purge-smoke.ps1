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
# except the bootstrap folder this run's TEMP points into. GAP-0262: the
# hooks' runtime selector state and lock go, so the Claude Code folders they
# kept go too. GAP-0575, GAP-0562: without a deployment record, the hook
# machine state that names this scope's hook executable and the public
# policy summary go. Runs in a disposable scratch directory; no service or
# machine root is touched.

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
