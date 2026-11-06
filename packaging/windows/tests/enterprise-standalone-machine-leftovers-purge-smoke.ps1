# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 5.1

# What a standalone purge removes outside StateRoot, and what it reports.
# GAP-0091: the vendor folders DefenseClaw recorded creating (C:\ProgramData\Cisco,
# Cursor, OpenAI\Codex, C:\Program Files\Cisco and ClaudeCode) go once they are
# empty, deepest first; a folder that existed before, or that holds another
# program's file, stays, and the walk up stops at the first folder
# DefenseClaw did not create. This replaces the GAP-0100 and GAP-0526
# removals, which deleted those folders whenever they were empty. GAP-1734: stale protected
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
# GAP-1145: a purge removes, and re-permissions, a tree that holds names
# Win32 path normalization changes (a skill quarantined as 'tdot.').
# GAP-0029: with StateRoot gone, a purge removes the managed-hook contract
# cleanup receipt a forced uninstall left in the lifecycle folder.
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
        # GAP-1145 (standalone runs PowerShell 7)
        if ($PSVersionTable.PSVersion.Major -ge 7) {
            $exactTree = Microsoft.PowerShell.Management\Join-Path $Scratch 'exact-names'
            foreach ($name in @('tdot.', 'tsp ')) {
                $leaf = [IO.Path]::Combine($exactTree, 'quarantine', $name)
                [void][IO.Directory]::CreateDirectory('\\?\' + $leaf)
                [IO.File]::WriteAllText('\\?\' + [IO.Path]::Combine($leaf, 'SKILL.md'), 'x')
            }
            $dotted = [IO.Path]::Combine($exactTree, 'quarantine', 'tdot.')
            if ((Get-DefenseClawExactItemPath -Path $dotted) -cne ('\\?\' + $dotted) -or
                (Get-DefenseClawExactItemPath -Path $exactTree) -cne $exactTree) {
                $failures.Add('the exact path of a trailing-dot name is not its extended-length form')
            }
            foreach ($item in @(Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $exactTree -Recurse -Force)) {
                $kind = if ($item.PSIsContainer) { 'AdminDirectory' } else { 'AdminFile' }
                try {
                    Set-DefenseClawPathAcl `
                        -Path (Get-DefenseClawExactItemPath -Path $item.FullName) `
                        -Kind $kind `
                        -GatewayServiceSID $script:AdministratorsSID
                }
                catch {
                    $failures.Add("preserved-state ACL rewrite failed on $($item.FullName): $($_.Exception.Message)")
                }
            }
            $originalSafeRoot = ${function:script:Assert-DefenseClawSafeRoot}
            try {
                ${function:script:Assert-DefenseClawSafeRoot} = {
                    param([string]$Path, [string]$Label, [string]$RequiredBase)
                    return [IO.Path]::GetFullPath($Path)
                }
                Remove-DefenseClawManagedTree -Path $exactTree -RequiredBase $Scratch -Label 'exact-name tree'
            }
            catch {
                $failures.Add("a tree with exact names was not removed: $($_.Exception.Message)")
            }
            finally {
                ${function:script:Assert-DefenseClawSafeRoot} = $originalSafeRoot
            }
            if ([IO.Directory]::Exists('\\?\' + $exactTree)) {
                $failures.Add('a tree with exact names survived its removal')
                Microsoft.PowerShell.Management\Remove-Item -LiteralPath ('\\?\' + $exactTree) -Recurse -Force
            }
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

        # GAP-0091: the created-folder record. The protected-directory and
        # ACL writers need a real machine root, so they are replaced in this
        # block; the record, its consumer and the removal rule are under test.
        $savedProfile = Get-DefenseClawEnterpriseProfile
        Set-DefenseClawEnterpriseProfile -EnterpriseProfile Standalone
        try {
            & {
                function New-DefenseClawProtectedDirectory {
                    param([string]$Path, [switch]$AllowUsersRead)
                    [void][IO.Directory]::CreateDirectory($Path)
                    return $true
                }
                function Set-DefenseClawPathAcl {
                    param([string]$Path, [string]$Kind, [string]$GatewayServiceSID)
                }
                $root = Microsoft.PowerShell.Management\Join-Path $Scratch 'gap0091'
                $pd = [IO.Path]::Combine($root, 'ProgramData')
                $pf = [IO.Path]::Combine($root, 'Program Files')
                $roots = @($pd, $pf)
                $vendor = [IO.Path]::Combine($pd, 'Cisco')
                $life = [IO.Path]::Combine($vendor, 'DefenseClaw-Lifecycle')
                $records = [IO.Path]::Combine($life, 'created-folders')
                $cursor = [IO.Path]::Combine($pd, 'Cursor')
                $openai = [IO.Path]::Combine($pd, 'OpenAI')
                $codex = [IO.Path]::Combine($openai, 'Codex')
                $before = [IO.Path]::Combine($pd, 'Preexisting')
                $claude = [IO.Path]::Combine($pf, 'ClaudeCode')
                $dropIns = [IO.Path]::Combine($claude, 'managed-settings.d')
                $foreignFile = [IO.Path]::Combine($dropIns, '50-other-vendor.json')
                $shared = [IO.Path]::Combine($pd, 'Shared')
                $sharedSub = [IO.Path]::Combine($shared, 'Sub')
                $layout = @{ SelfUninstallReceiptPath = [IO.Path]::Combine($life, ('self-uninstall-' + ('0' * 64) + '.json')) }
                foreach ($folder in @($life, $cursor, $codex, $before, $dropIns, $sharedSub)) {
                    [void][IO.Directory]::CreateDirectory($folder)
                }
                [IO.File]::WriteAllText($foreignFile, '{}')
                [IO.File]::WriteAllText([IO.Path]::Combine($life, 'lifecycle.lock'), '')
                # Recorded: what DefenseClaw created. Not recorded: Preexisting
                # and Shared, which existed before.
                Add-DefenseClawStandaloneCreatedFolderRecord -Path @($vendor, $cursor, $openai, $codex, $claude, $dropIns, $sharedSub) -RecordDirectory $records -Roots $roots
                Add-DefenseClawStandaloneCreatedFolderRecord -Path @($cursor, ($cursor + '\'), [IO.Path]::Combine($root, 'Elsewhere'), $pd) -RecordDirectory $records -Roots $roots
                $files = @(Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $records -Force)
                if ($files.Count -ne 7) {
                    $failures.Add("GAP-0091: want 7 write-once records (no duplicate, nothing outside or at a root), got $($files.Count)")
                }
                $cursorRecord = [IO.Path]::Combine($records, (Get-DefenseClawCreatedFolderRecordName -Path $cursor))
                $document = [IO.File]::ReadAllText($cursorRecord) | Microsoft.PowerShell.Utility\ConvertFrom-Json
                if ([int]$document.schema_version -ne 1 -or [string]$document.path -cne $cursor) {
                    $failures.Add("GAP-0091: the Cursor record is not schema 1 naming its path: $([IO.File]::ReadAllText($cursorRecord))")
                }
                # The Go writer names a record the same way (sha256 of the
                # lower-case path).
                $sha = [Security.Cryptography.SHA256]::Create()
                $want = -join @($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($cursor.ToLowerInvariant())) | Microsoft.PowerShell.Core\ForEach-Object { $_.ToString('x2') })
                $sha.Dispose()
                if ((Get-DefenseClawCreatedFolderRecordName -Path $cursor.ToUpperInvariant()) -cne ($want + '.json')) {
                    $failures.Add('GAP-0091: the record name is not the sha256 of the lower-case path')
                }

                # Not consumed while a self-uninstall finalizer is pending, or
                # while the lifecycle folder holds another scope's state.
                [IO.File]::WriteAllText($layout.SelfUninstallReceiptPath, '{}')
                if (@(Pop-DefenseClawStandaloneCreatedFolderRecords -Layout $layout -RecordDirectory $records -SkipDeploymentCheck).Count -ne 0 -or
                    @(Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $records -Force).Count -ne 7) {
                    $failures.Add('GAP-0091: the record was consumed while a self-uninstall finalizer was pending')
                }
                [IO.File]::Delete($layout.SelfUninstallReceiptPath)
                $rollback = [IO.Path]::Combine($life, ('install-rollback-' + ('1' * 64) + '.json'))
                [IO.File]::WriteAllText($rollback, '{}')
                if (@(Pop-DefenseClawStandaloneCreatedFolderRecords -Layout $layout -RecordDirectory $records -SkipDeploymentCheck).Count -ne 0) {
                    $failures.Add('GAP-0091: the record was consumed while the lifecycle folder held another receipt')
                }
                [IO.File]::Delete($rollback)
                # A record whose name is not its path's is not used, and stays.
                $planted = [IO.Path]::Combine($records, ('f' * 64) + '.json')
                [IO.File]::WriteAllText($planted, ('{"schema_version":1,"path":"' + $before.Replace('\', '\\') + '"}'))

                $popped = @(Pop-DefenseClawStandaloneCreatedFolderRecords -Layout $layout -RecordDirectory $records -SkipDeploymentCheck)
                if ($popped.Count -ne 7 -or $popped -contains $before) {
                    $failures.Add("GAP-0091: want the 7 recorded folders, got: $($popped -join '; ')")
                }
                if (-not [IO.File]::Exists($planted) -or @(Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $records -Force).Count -ne 1) {
                    $failures.Add('GAP-0091: the consumed records were not deleted, or the planted record was')
                }
                [IO.File]::Delete($planted)
                [IO.Directory]::Delete($records)
                # The lock and its folder go first (Remove-DefenseClawStandaloneLifecycleLockLeftover).
                [IO.File]::Delete([IO.Path]::Combine($life, 'lifecycle.lock'))
                [IO.Directory]::Delete($life)

                Remove-DefenseClawStandaloneCreatedFolders -Path $popped -Roots $roots
                foreach ($case in @(
                        @('a created empty folder', $cursor, $false),
                        @('a created empty vendor folder above the lifecycle folder', $vendor, $false),
                        @('a created folder and the created parent above it', $openai, $false),
                        @('a folder that existed before', $before, $true),
                        @('a created folder holding another program''s file', $foreignFile, $true),
                        @('the created parent of a folder holding another program''s file', $claude, $true),
                        @('a created folder below one that existed before', $sharedSub, $false),
                        @('a folder that existed before, above a created one', $shared, $true))) {
                    if ((Microsoft.PowerShell.Management\Test-Path -LiteralPath $case[1]) -ne $case[2]) {
                        $failures.Add("GAP-0091: $($case[0]) ($($case[1])) present=$(-not $case[2]), want present=$($case[2])")
                    }
                }
                # Never a path outside the roots, even when handed one.
                $outside = [IO.Path]::Combine($root, 'Outside')
                [void][IO.Directory]::CreateDirectory($outside)
                Remove-DefenseClawStandaloneCreatedFolders -Path @($outside) -Roots $roots
                if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $outside)) {
                    $failures.Add('GAP-0091: a folder outside ProgramData and Program Files was removed')
                }

                # Secure Client keeps no record and removes nothing.
                Set-DefenseClawEnterpriseProfile -EnterpriseProfile SecureClient
                $scLife = [IO.Path]::Combine($root, 'sc', 'Lifecycle')
                $scFolder = [IO.Path]::Combine($pd, 'SecureClientVendor')
                [void][IO.Directory]::CreateDirectory($scLife)
                [void][IO.Directory]::CreateDirectory($scFolder)
                Add-DefenseClawStandaloneCreatedFolderRecord -Path @($scFolder) -RecordDirectory ([IO.Path]::Combine($scLife, 'created-folders')) -Roots $roots
                Remove-DefenseClawStandaloneCreatedFolders -Path @($scFolder) -Roots $roots
                if ((Microsoft.PowerShell.Management\Test-Path -LiteralPath ([IO.Path]::Combine($scLife, 'created-folders'))) -or
                    -not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $scFolder)) {
                    $failures.Add('GAP-0091: the Secure Client profile recorded or removed a folder')
                }
            }
        }
        finally {
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
            # The emptied folders stay for the created-folder step (GAP-0091).
            if ($left.Count -ne 0 -or
                @(Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $claudeDropIns -Force).Count -ne 0 -or
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
        $ownHook = 'C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe'
        $left = @(Remove-DefenseClawRuntimeSelectorState -HookPath $ownHook -Directories @($selectorDropIns, '', [IO.Path]::Combine($selector, 'absent')))
        if ($left.Count -ne 0 -or @(Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $selectorDropIns -Force).Count -ne 0) {
            $failures.Add("the runtime selector state stayed in ClaudeCode\managed-settings.d: $($left -join '; ')")
        }

        # GAP-1158: a selector that also holds another deployment's target
        # stays with its lock, and is named; one with only this deployment's
        # targets goes.
        $shared = Microsoft.PowerShell.Management\Join-Path $Scratch 'selector-shared'
        [void][IO.Directory]::CreateDirectory($shared)
        $sharedState = [IO.Path]::Combine($shared, '.defenseclaw-managed-runtime-selector.state')
        $sharedLock = [IO.Path]::Combine($shared, '.defenseclaw-managed-runtime-selector.lock')
        $sharedDocument = @{ schema_version = 1; connector = 'codex'; targets = @(
                @{ connector = 'codex'; sid = 'S-1-5-21-1-2-3-1001'; hook_executable = $ownHook },
                @{ connector = 'codex'; sid = 'S-1-5-21-1-2-3-1002'; hook_executable = 'D:\Other\DefenseClaw\bin\defenseclaw-hook.exe' }
            ) } | Microsoft.PowerShell.Utility\ConvertTo-Json -Depth 4
        [IO.File]::WriteAllText($sharedState, $sharedDocument)
        [IO.File]::WriteAllText($sharedLock, '')
        $kept = @(Remove-DefenseClawRuntimeSelectorState -HookPath $ownHook -Directories @($shared))
        if ($kept.Count -ne 1 -or $kept[0] -notlike '*another DefenseClaw deployment*' -or
            -not [IO.File]::Exists($sharedState) -or -not [IO.File]::Exists($sharedLock)) {
            $failures.Add("a selector shared with another deployment was removed: $($kept -join '; ')")
        }
        $onlyOurs = @{ schema_version = 1; connector = 'codex'; targets = @(
                @{ connector = 'codex'; sid = 'S-1-5-21-1-2-3-1001'; hook_executable = $ownHook }
            ) } | Microsoft.PowerShell.Utility\ConvertTo-Json -Depth 4
        [IO.File]::WriteAllText($sharedState, $onlyOurs)
        $gone = @(Remove-DefenseClawRuntimeSelectorState -HookPath $ownHook -Directories @($shared))
        if ($gone.Count -ne 0 -or [IO.File]::Exists($sharedState) -or [IO.File]::Exists($sharedLock)) {
            $failures.Add("a selector with only this deployment's targets stayed: $($gone -join '; ')")
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
            if (@(Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $claudeDropIns -Force).Count -ne 0) {
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

        # GAP-0029: Setup /uninstall FORCE=1 left a prepared managed-hook
        # contract cleanup receipt in the lifecycle folder, and every later
        # uninstall of a new deployment failed on it. With StateRoot gone and
        # no state-purge intent pending, a purge removes the receipt and its
        # report; otherwise both stay, and a folder in their place is named.
        # A rollback retires, without binding it, only a prepared receipt of
        # another deployment generation than the metadata records.
        $lifecycle = Microsoft.PowerShell.Management\Join-Path $Scratch 'lifecycle'
        [void][IO.Directory]::CreateDirectory($lifecycle)
        $receiptLayout = @{
            StateRoot = [IO.Path]::Combine($Scratch, 'receipt-state')
            PurgeIntentPath = [IO.Path]::Combine($lifecycle, 'state-purge-intent.json')
            LifecycleLockDirectory = $lifecycle
            ManagedHookContractCleanupReceiptPath = [IO.Path]::Combine($lifecycle, 'managed-hook-contract-cleanup-receipt.json')
            ManagedHookContractCleanupReportPath = [IO.Path]::Combine($lifecycle, 'managed-hook-contract-cleanup-receipt.report.json')
        }
        foreach ($case in @(
                @('StateRoot gone and no intent', '', $false),
                @('StateRoot present', 'state', $true),
                @('state-purge intent pending', 'intent', $true))) {
            if ([IO.Directory]::Exists($receiptLayout.StateRoot)) { [IO.Directory]::Delete($receiptLayout.StateRoot) }
            if ([IO.File]::Exists($receiptLayout.PurgeIntentPath)) { [IO.File]::Delete($receiptLayout.PurgeIntentPath) }
            [IO.File]::WriteAllText($receiptLayout.ManagedHookContractCleanupReceiptPath, '{"phase":"prepared"}')
            [IO.File]::WriteAllText($receiptLayout.ManagedHookContractCleanupReportPath, '{}')
            if ($case[1] -ceq 'state') { [void][IO.Directory]::CreateDirectory($receiptLayout.StateRoot) }
            if ($case[1] -ceq 'intent') { [IO.File]::WriteAllText($receiptLayout.PurgeIntentPath, '{}') }
            $left = @(Remove-DefenseClawStandaloneOrphanedContractCleanupReceipt -Layout $receiptLayout)
            $receiptKept = [IO.File]::Exists($receiptLayout.ManagedHookContractCleanupReceiptPath)
            $reportKept = [IO.File]::Exists($receiptLayout.ManagedHookContractCleanupReportPath)
            if ($left.Count -ne 0 -or $receiptKept -ne $case[2] -or $reportKept -ne $case[2]) {
                $failures.Add("$($case[0]): receipt kept=$receiptKept, report kept=$reportKept, named: $($left -join '; ')")
            }
        }
        foreach ($leaf in @($receiptLayout.PurgeIntentPath, $receiptLayout.ManagedHookContractCleanupReceiptPath, $receiptLayout.ManagedHookContractCleanupReportPath)) {
            if ([IO.File]::Exists($leaf)) { [IO.File]::Delete($leaf) }
        }
        [void][IO.Directory]::CreateDirectory($receiptLayout.ManagedHookContractCleanupReceiptPath)
        $left = @(Remove-DefenseClawStandaloneOrphanedContractCleanupReceipt -Layout $receiptLayout)
        if (-not [IO.Directory]::Exists($receiptLayout.ManagedHookContractCleanupReceiptPath) -or $left.Count -ne 1 -or
            -not ([string]$left[0]).StartsWith($receiptLayout.ManagedHookContractCleanupReceiptPath + ': ')) {
            $failures.Add("a folder at the receipt path was not kept and named: $($left -join '; ')")
        }
        [IO.Directory]::Delete($receiptLayout.ManagedHookContractCleanupReceiptPath)
        $activation = [pscustomobject]@{
            schema_version = 1
            deployment_generation_id = ('a' * 32)
            state = 'activated'
            manifest_sha256 = ('b' * 64)
            target_count = 2
        }
        foreach ($case in @(
                @('prepared, another generation', 'prepared', ('c' * 32), $true, $true),
                @('prepared, this generation', 'prepared', ('a' * 32), $true, $false),
                @('finalized, another generation', 'finalized', ('c' * 32), $true, $false),
                @('metadata without activation', 'prepared', ('c' * 32), $false, $false))) {
            $receipt = [pscustomobject]@{ phase = $case[1]; deployment_generation_id = $case[2] }
            $metadata = if ($case[3]) { [pscustomobject]@{ managed_hooks_activation = $activation } } else { [pscustomobject]@{ product_version = '9.9.9' } }
            $orphan = Test-DefenseClawContractCleanupReceiptOfRemovedDeployment -Receipt $receipt -Metadata $metadata
            if ([bool]$orphan -ne $case[4]) {
                $failures.Add("$($case[0]): removed deployment=$orphan, want $($case[4])")
            }
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
