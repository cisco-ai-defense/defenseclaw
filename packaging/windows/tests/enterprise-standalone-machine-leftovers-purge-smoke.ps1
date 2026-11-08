# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 5.1

# What a standalone purge removes outside StateRoot, and what it reports.
# GAP-0091: the vendor folders DefenseClaw recorded creating (C:\ProgramData\Cisco,
# Cursor, OpenAI\Codex, C:\Program Files\Cisco and ClaudeCode) go once they are
# empty, deepest first; a folder that existed before, or that holds another
# program's file, stays, and the walk up stops at the first folder
# DefenseClaw did not create. A record goes only once its folder is gone, a
# rollback that removes a folder takes its record, and a recorded folder is
# never removed through a junction at it or above it, nor when someone else
# owns or can write it or its parent (review M1). On a computer installed
# before 1.0.9 the two Cisco folders are recorded only when they carry
# Setup's exact descriptor and hold only DefenseClaw folders. This replaces the GAP-0100 and GAP-0526
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

        # GAP-0091: the created-folder record, its consumer and the removal
        # rule, on a scratch ProgramData and Program Files with the real
        # protected-directory, ACL and reparse checks (they need an elevated
        # run: Administrator or SYSTEM).
        $savedProfile = Get-DefenseClawEnterpriseProfile
        Set-DefenseClawEnterpriseProfile -EnterpriseProfile Standalone
        $junctions = [Collections.Generic.List[string]]::new()
        try {
            & {
                # The GAP-1734 rows above replace the ACL check; this block
                # needs the module's own. A local wrapper, so the stub the
                # rows below rely on stays as it is.
                $modulePathAcl = ${function:script:Assert-DefenseClawPathAcl}
                function Assert-DefenseClawPathAcl { & $modulePathAcl @args }
                # The lifecycle log lines a purge writes for folders that stay
                # are collected here, not written to this computer's log.
                $logged = [Collections.Generic.List[string]]::new()
                function Write-DefenseClawLifecycleLogDiagnostic { param([string]$Message) $logged.Add($Message) }
                # As in the self-uninstall finalizer, which writes them (in a
                # lifecycle run the result carries them, review 2 L3).
                $script:DefenseClawCreatedFolderLogToLifecycleLog = $true
                $adminOnly = 'O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'
                $native = Initialize-DefenseClawNativeSecurity
                # A fixture folder a purge may remove is owned by
                # BUILTIN\Administrators, as the folders Setup and the hooks
                # create are. A folder an elevated administrator creates is
                # owned by that account itself where "Default owner for objects
                # created by members of the Administrators group" is "Object
                # creator" (the GitHub runner's runneradmin), and the purge's
                # owner check rightly refuses it; SYSTEM and hosts set to
                # "Administrators group" get BUILTIN\Administrators anyway.
                # The negative rows keep what makes them negative (a junction,
                # a Users write entry).
                function Set-G091AdministratorsOwner {
                    param([string[]]$Path)
                    foreach ($folder in $Path) {
                        $out = & "$env:SystemRoot\System32\icacls.exe" $folder /setowner '*S-1-5-32-544' /Q 2>&1
                        if ($LASTEXITCODE -ne 0) {
                            throw "set the owner of $folder to BUILTIN\Administrators: $out"
                        }
                    }
                }
                [void][IO.Directory]::CreateDirectory($Scratch)
                $root = Microsoft.PowerShell.Management\Join-Path $Scratch 'gap0091'
                [void]$native::CreateDirectorySecure($root, $adminOnly)
                $pd = [IO.Path]::Combine($root, 'ProgramData')
                $pf = [IO.Path]::Combine($root, 'Program Files')
                $outsideRoot = [IO.Path]::Combine($root, 'Outside')
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
                $gone = [IO.Path]::Combine($pd, 'Gone')
                # Review M1 and S2: a junction at the recorded folder, a
                # junction at its parent (a standard user re-creating
                # C:\ProgramData\OpenAI as a junction after a stale record),
                # a folder made again by someone else, and a parent someone
                # else can write.
                $leafLink = [IO.Path]::Combine($pd, 'LeafLink')
                $leafTarget = [IO.Path]::Combine($outsideRoot, 'leaf-target')
                $parentLink = [IO.Path]::Combine($pd, 'ParentLink')
                $parentTarget = [IO.Path]::Combine($outsideRoot, 'parent-target')
                $throughParent = [IO.Path]::Combine($parentLink, 'Codex')
                $recreated = [IO.Path]::Combine($pd, 'Recreated')
                $userParent = [IO.Path]::Combine($pd, 'UserParent')
                $userParentChild = [IO.Path]::Combine($userParent, 'Child')
                $openRecordFolder = [IO.Path]::Combine($pd, 'OpenRecord')
                $layout = @{ SelfUninstallReceiptPath = [IO.Path]::Combine($life, ('self-uninstall-' + ('0' * 64) + '.json')) }
                foreach ($folder in @($pd, $pf, $outsideRoot, $vendor)) {
                    [void][IO.Directory]::CreateDirectory($folder)
                }
                [void]$native::CreateDirectorySecure($life, $adminOnly)
                foreach ($folder in @($cursor, $codex, $before, $dropIns, $sharedSub, $leafTarget,
                        ([IO.Path]::Combine($parentTarget, 'Codex')), $recreated, $userParentChild, $openRecordFolder)) {
                    [void][IO.Directory]::CreateDirectory($folder)
                }
                Set-G091AdministratorsOwner -Path @($pd, $pf, $outsideRoot, $vendor, $cursor, $openai, $codex, $before,
                    $claude, $dropIns, $shared, $sharedSub, $leafTarget, $parentTarget, ([IO.Path]::Combine($parentTarget, 'Codex')),
                    $recreated, $userParent, $userParentChild, $openRecordFolder)
                [IO.File]::WriteAllText($foreignFile, '{}')
                [IO.File]::WriteAllText([IO.Path]::Combine($life, 'lifecycle.lock'), '')
                foreach ($link in @(@($leafLink, $leafTarget), @($parentLink, $parentTarget))) {
                    [void](Microsoft.PowerShell.Management\New-Item -ItemType Junction -Path $link[0] -Target $link[1])
                    $junctions.Add($link[0])
                }
                # Someone else can write Recreated, and UserParent above an
                # administrator-only Child.
                foreach ($open in @($recreated, $userParent)) {
                    $acl = Microsoft.PowerShell.Security\Get-Acl -LiteralPath $open
                    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                        [Security.Principal.SecurityIdentifier]::new($script:UsersSID),
                        [Security.AccessControl.FileSystemRights]::Modify,
                        [Security.AccessControl.InheritanceFlags]::None,
                        [Security.AccessControl.PropagationFlags]::None,
                        [Security.AccessControl.AccessControlType]::Allow))
                    Microsoft.PowerShell.Security\Set-Acl -LiteralPath $open -AclObject $acl
                }
                $childAcl = Microsoft.PowerShell.Security\Get-Acl -LiteralPath $userParentChild
                $childAcl.SetAccessRuleProtection($true, $false)
                $childAcl.SetSecurityDescriptorSddlForm('D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)', [Security.AccessControl.AccessControlSections]::Access)
                Microsoft.PowerShell.Security\Set-Acl -LiteralPath $userParentChild -AclObject $childAcl

                # Recorded: what DefenseClaw created (and the M1 cases). Not
                # recorded: Preexisting and Shared, which existed before.
                $recorded = @($vendor, $cursor, $openai, $codex, $claude, $dropIns, $sharedSub, $gone,
                    $leafLink, $throughParent, $recreated, $userParentChild, $openRecordFolder)
                $null = Add-DefenseClawStandaloneCreatedFolderRecord -Path $recorded -RecordDirectory $records -Roots $roots
                $null = Add-DefenseClawStandaloneCreatedFolderRecord -Path @($cursor, ($cursor + '\'), [IO.Path]::Combine($root, 'Elsewhere'), $pd) -RecordDirectory $records -Roots $roots
                $files = @(Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $records -Force)
                if ($files.Count -ne $recorded.Count) {
                    $failures.Add("GAP-0091: want $($recorded.Count) write-once records (no duplicate, nothing outside or at a root), got $($files.Count)")
                }
                $cursorRecord = [IO.Path]::Combine($records, (Get-DefenseClawCreatedFolderRecordName -Path $cursor))
                $document = [IO.File]::ReadAllText($cursorRecord) | Microsoft.PowerShell.Utility\ConvertFrom-Json
                if ([int]$document.schema_version -ne 1 -or [string]$document.path -cne $cursor) {
                    $failures.Add("GAP-0091: the Cursor record is not schema 1 naming its path: $([IO.File]::ReadAllText($cursorRecord))")
                }
                # Review L3: the name folds only A-Z, as the Go writer does
                # (TestStandaloneCreatedFolderRecordNameFoldsOnlyASCIILetters
                # pins the same name for the same path).
                $nonAscii = 'C:\ProgramData\' + [char]0xDC + 'n' + [char]0xEF + 'code ' + [char]0x130 + '\Codex'
                if ((Get-DefenseClawCreatedFolderRecordName -Path $nonAscii) -cne 'cb0ed1e34f5e1961147f1101c3b7a237146fc893cc261ebfaaadb52ada704767.json' -or
                    (Get-DefenseClawCreatedFolderRecordName -Path $nonAscii.Replace('ProgramData', 'PROGRAMDATA')) -cne 'cb0ed1e34f5e1961147f1101c3b7a237146fc893cc261ebfaaadb52ada704767.json') {
                    $failures.Add('GAP-0091: the record name is not the sha256 of the path with only A-Z folded')
                }

                # Not consumed while a self-uninstall finalizer is pending, or
                # while the lifecycle folder holds another scope's state.
                [IO.File]::WriteAllText($layout.SelfUninstallReceiptPath, '{}')
                if (@(Invoke-DefenseClawStandaloneCreatedFolderRemoval -Layout $layout -RecordDirectory $records -Roots $roots -SkipDeploymentCheck).Count -ne 0 -or
                    @(Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $records -Force).Count -ne $recorded.Count -or
                    -not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $cursor)) {
                    $failures.Add('GAP-0091: the record was consumed while a self-uninstall finalizer was pending')
                }
                [IO.File]::Delete($layout.SelfUninstallReceiptPath)
                $rollback = [IO.Path]::Combine($life, ('install-rollback-' + ('1' * 64) + '.json'))
                [IO.File]::WriteAllText($rollback, '{}')
                if (@(Invoke-DefenseClawStandaloneCreatedFolderRemoval -Layout $layout -RecordDirectory $records -Roots $roots -SkipDeploymentCheck).Count -ne 0 -or
                    -not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $cursor)) {
                    $failures.Add('GAP-0091: the record was consumed while the lifecycle folder held another receipt')
                }
                [IO.File]::Delete($rollback)
                # A record whose name is not its path's is not used, and
                # stays; so does a well-named record someone else can write
                # (review S2), and its folder.
                $planted = [IO.Path]::Combine($records, ('f' * 64) + '.json')
                [IO.File]::WriteAllText($planted, ('{"schema_version":1,"path":"' + $before.Replace('\', '\\') + '"}'))
                $openRecord = [IO.Path]::Combine($records, (Get-DefenseClawCreatedFolderRecordName -Path $openRecordFolder))
                $recordAcl = Microsoft.PowerShell.Security\Get-Acl -LiteralPath $openRecord
                $recordAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                    [Security.Principal.SecurityIdentifier]::new($script:UsersSID),
                    [Security.AccessControl.FileSystemRights]::Write,
                    [Security.AccessControl.AccessControlType]::Allow))
                Microsoft.PowerShell.Security\Set-Acl -LiteralPath $openRecord -AclObject $recordAcl

                # First purge: every folder that may go goes, with its
                # record; every other one stays with its record, and so does
                # the vendor folder above the lifecycle folder (review L1).
                $deferred = @(Invoke-DefenseClawStandaloneCreatedFolderRemoval -Layout $layout -RecordDirectory $records -Roots $roots -SkipDeploymentCheck)
                if ($deferred.Count -ne 0) {
                    $failures.Add("GAP-0091: the vendor folder was handed on while other recorded folders stayed: $($deferred -join '; ')")
                }
                foreach ($case in @(
                        @('a created empty folder', $cursor, $false),
                        @('a created folder and the created parent above it', $openai, $false),
                        @('a created folder below one that existed before', $sharedSub, $false),
                        @('a folder that existed before', $before, $true),
                        @('a folder that existed before, above a created one', $shared, $true),
                        @('a created folder holding another program''s file', $foreignFile, $true),
                        @('the created parent of a folder holding another program''s file', $claude, $true),
                        @('M1: a junction at the recorded folder', $leafLink, $true),
                        @('M1: the junction target of the recorded folder', $leafTarget, $true),
                        @('M1: a recorded folder reached through a junction at its parent', ([IO.Path]::Combine($parentTarget, 'Codex')), $true),
                        @('M1: a recorded folder someone else can write (made again by them)', $recreated, $true),
                        @('M1: a recorded folder whose parent someone else can write', $userParentChild, $true),
                        @('S2: the folder of a record someone else can write', $openRecordFolder, $true),
                        @('the vendor folder above the lifecycle folder', $vendor, $true))) {
                    if ((Microsoft.PowerShell.Management\Test-Path -LiteralPath $case[1]) -ne $case[2]) {
                        $failures.Add("GAP-0091: $($case[0]) ($($case[1])) present=$(-not $case[2]), want present=$($case[2])")
                    }
                }
                foreach ($case in @(
                        @('a removed folder', $cursor, $false),
                        @('an absent folder (a stale record)', $gone, $false),
                        @('a folder that stayed', $dropIns, $true),
                        @('M1: a junction at the folder', $leafLink, $true),
                        @('M1: a junction at the parent', $throughParent, $true),
                        @('M1: a folder made again by someone else', $recreated, $true),
                        @('M1: a parent someone else can write', $userParentChild, $true),
                        @('S2: a record someone else can write', $openRecordFolder, $true),
                        @('the vendor folder above the lifecycle folder', $vendor, $true))) {
                    $recordFile = [IO.Path]::Combine($records, (Get-DefenseClawCreatedFolderRecordName -Path $case[1]))
                    if ([IO.File]::Exists($recordFile) -ne $case[2]) {
                        $failures.Add("GAP-0091: the record of $($case[0]) ($($case[1])) present=$(-not $case[2]), want present=$($case[2])")
                    }
                }
                if (-not [IO.File]::Exists($planted)) {
                    $failures.Add('GAP-0091: the planted record was deleted')
                }
                foreach ($stayed in @($dropIns, $claude, $leafLink, $throughParent, $recreated, $userParentChild, $vendor)) {
                    if (@($logged | Microsoft.PowerShell.Core\Where-Object { $_.StartsWith("defenseclaw_skip path=${stayed}: a folder DefenseClaw created stays") }).Count -ne 1) {
                        $failures.Add("GAP-0091: the lifecycle log does not name the folder that stayed once: $stayed")
                    }
                }

                # The folders that stayed are cleared; the next purge takes
                # the rest, hands on the vendor folder and removes the record
                # folder.
                [IO.File]::Delete($foreignFile)
                foreach ($link in $junctions) {
                    [IO.Directory]::Delete($link, $false)
                }
                $junctions.Clear()
                foreach ($folder in @($recreated, $userParentChild, $userParent, $openRecordFolder)) {
                    [IO.Directory]::Delete($folder, $false)
                }
                [IO.File]::Delete($planted)
                [IO.File]::Delete($openRecord)
                $deferred = @(Invoke-DefenseClawStandaloneCreatedFolderRemoval -Layout $layout -RecordDirectory $records -Roots $roots -SkipDeploymentCheck)
                if ($deferred.Count -ne 1 -or $deferred[0] -cne $vendor) {
                    $failures.Add("GAP-0091: want the vendor folder handed on, got: $($deferred -join '; ')")
                }
                foreach ($case in @(@('emptied managed-settings.d', $dropIns), @('its created parent', $claude), @('the record folder', $records))) {
                    if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $case[1]) {
                        $failures.Add("GAP-0091: $($case[0]) ($($case[1])) stayed on the second purge")
                    }
                }
                # The lock and its folder go first (Remove-DefenseClawStandaloneLifecycleLockLeftover).
                [IO.File]::Delete([IO.Path]::Combine($life, 'lifecycle.lock'))
                [IO.Directory]::Delete($life)
                Remove-DefenseClawStandaloneCreatedFolders -Path $deferred -Roots $roots
                if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $vendor) {
                    $failures.Add('GAP-0091: the created empty vendor folder above the lifecycle folder stayed')
                }
                # Never a path outside the roots, even when handed one.
                Remove-DefenseClawStandaloneCreatedFolders -Path @($leafTarget) -Roots $roots
                if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $leafTarget)) {
                    $failures.Add('GAP-0091: a folder outside ProgramData and Program Files was removed')
                }

                # A rollback that removes the Codex folders it created takes
                # their records too (review M1), and so does one that finds
                # them gone.
                [void][IO.Directory]::CreateDirectory($vendor)
                [void]$native::CreateDirectorySecure($life, $adminOnly)
                $rollbackVendor = [IO.Path]::Combine($pd, 'OpenAI')
                $rollbackCodex = [IO.Path]::Combine($rollbackVendor, 'Codex')
                [void][IO.Directory]::CreateDirectory($rollbackCodex)
                Set-G091AdministratorsOwner -Path @($vendor, $rollbackVendor, $rollbackCodex)
                $null = Add-DefenseClawStandaloneCreatedFolderRecord -Path @($rollbackVendor, $rollbackCodex) -RecordDirectory $records -Roots $roots
                & {
                    function Get-DefenseClawStandaloneCreatedFolderRecordDirectory { return $records }
                    function Assert-DefenseClawCodexMachinePolicyDirectory { param([string]$Path) }
                    function Remove-DefenseClawCodexPolicySerializationLock { param([string]$Directory, [hashtable]$Layout) }
                    function Test-DefenseClawTrustStrictAncestors { return $false }
                    $codexLayout = @{ CodexVendorDirectory = $rollbackVendor; CodexMachinePolicyDirectory = $rollbackCodex }
                    $snapshot = [pscustomobject]@{ created_shared_directories = @($rollbackVendor, $rollbackCodex) }
                    Remove-DefenseClawTransactionCreatedSharedDirectories -Snapshot $snapshot -Layout $codexLayout
                    if ((Microsoft.PowerShell.Management\Test-Path -LiteralPath $rollbackVendor) -or
                        @(Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $records -Force).Count -ne 0) {
                        $failures.Add('GAP-0091: a rollback left the Codex folders it created, or their records')
                    }
                    $null = Add-DefenseClawStandaloneCreatedFolderRecord -Path @($rollbackVendor) -RecordDirectory $records -Roots $roots
                    $snapshot = [pscustomobject]@{ created_shared_directories = @($rollbackVendor) }
                    Remove-DefenseClawTransactionCreatedSharedDirectories -Snapshot $snapshot -Layout $codexLayout
                    if (@(Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $records -Force).Count -ne 0) {
                        $failures.Add('GAP-0091: a rollback that found its Codex folder gone kept the record')
                    }
                }

                # The upgrade back-fill (GAP-0526 on a computer installed
                # before 1.0.9): the two Cisco folders are recorded only with
                # Setup's exact descriptor and nothing but DefenseClaw folders.
                $vendorThisFolder = $adminOnly + '(A;;0x1200a9;;;BU)'
                $vendorInherited = $adminOnly + '(A;OICI;0x1200a9;;;BU)'
                $backfill = [IO.Path]::Combine($root, 'backfill')
                [void][IO.Directory]::CreateDirectory($backfill)
                $serviceSid = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
                $index = 0
                foreach ($case in @(
                        @('Setup''s ProgramData vendor folder with the gateway traverse grant', $vendorThisFolder, $false, @('DefenseClaw', 'DefenseClaw-Lifecycle', 'DefenseClaw-HookRuntime'), $true, $true),
                        @('Setup''s Program Files vendor folder', $vendorInherited, $true, @('DefenseClaw'), $false, $true),
                        @('an empty folder an earlier purge left', $vendorThisFolder, $false, @(), $false, $true),
                        @('an inherited folder (an MSI or an administrator made it)', '', $false, @('DefenseClaw'), $false, $false),
                        @('Setup''s descriptor holding another product''s folder', $vendorThisFolder, $false, @('DefenseClaw', 'Cisco Secure Client'), $false, $false),
                        @('the Program Files descriptor on the ProgramData folder', $vendorInherited, $false, @('DefenseClaw'), $false, $false),
                        @('Setup''s descriptor with one more entry', ($vendorThisFolder + '(A;;0x1301bf;;;BU)'), $false, @('DefenseClaw'), $false, $false),
                        @('SYSTEM and Administrators only (another Cisco product)', $adminOnly, $false, @('DefenseClaw'), $false, $false),
                        # Review 2 L4: 1.0.2 and 1.0.3 added this Users entry to
                        # a folder they found, and kept no record of it.
                        @('the 1.0.2/1.0.3 Users grant (0x1200a0) with no grant record', ($adminOnly + '(A;;0x1200a0;;;BU)'), $false, @('DefenseClaw'), $false, $false),
                        @('Setup''s exact descriptor with a Users-read grant record', $vendorThisFolder, $false, @('DefenseClaw'), $false, $false, $true))) {
                    $index++
                    $caseRoot = [IO.Path]::Combine($backfill, "c$index")
                    $casePd = [IO.Path]::Combine($caseRoot, 'ProgramData')
                    $casePf = [IO.Path]::Combine($caseRoot, 'Program Files')
                    foreach ($folder in @($casePd, $casePf)) {
                        [void][IO.Directory]::CreateDirectory($folder)
                    }
                    $caseVendor = [IO.Path]::Combine($(if ($case[2]) { $casePf } else { $casePd }), 'Cisco')
                    if ([string]::IsNullOrEmpty($case[1])) {
                        [void][IO.Directory]::CreateDirectory($caseVendor)
                    }
                    else {
                        [void]$native::CreateDirectorySecure($caseVendor, $case[1])
                    }
                    foreach ($child in $case[3]) {
                        [void][IO.Directory]::CreateDirectory([IO.Path]::Combine($caseVendor, $child))
                    }
                    if ($case[4]) {
                        [void](Set-DefenseClawSharedDirectoryRawAce -Path $caseVendor -SID $serviceSid -Action Add -AccessMask 0x1200a9)
                    }
                    $caseLife = [IO.Path]::Combine($caseRoot, 'Lifecycle')
                    [void]$native::CreateDirectorySecure($caseLife, $adminOnly)
                    $caseRecords = [IO.Path]::Combine($caseLife, 'created-folders')
                    $grantFile = [IO.Path]::Combine($caseLife, 'vendor-users-read-grant.json')
                    if ($case.Count -gt 6 -and $case[6]) {
                        # The record GAP-0578 writes when Setup adds Users read
                        # to a folder it found.
                        [IO.File]::WriteAllText($grantFile, (@{ sid = $script:UsersSID; path = $caseVendor; added_rights = 0x1200a9; scopes = @($caseVendor) } |
                            Microsoft.PowerShell.Utility\ConvertTo-Json -Compress))
                    }
                    $backfillArgs = @{ RecordDirectory = $caseRecords; Roots = @($casePd, $casePf) }
                    if ($case[2]) {
                        $backfillArgs.ProgramFilesVendorFolder = $caseVendor
                        $backfillArgs.ProgramDataVendorFolder = [IO.Path]::Combine($casePd, 'Cisco')
                    }
                    else {
                        $backfillArgs.ProgramDataVendorFolder = $caseVendor
                        $backfillArgs.ProgramFilesVendorFolder = [IO.Path]::Combine($casePf, 'Cisco')
                    }
                    & {
                        function Get-DefenseClawVendorUsersReadGrantPath { return $grantFile }
                        Add-DefenseClawStandaloneUpgradeVendorFolderRecords @backfillArgs
                    }
                    $recordedNow = [IO.File]::Exists([IO.Path]::Combine($caseRecords, (Get-DefenseClawCreatedFolderRecordName -Path $caseVendor)))
                    if ($recordedNow -ne $case[5]) {
                        $failures.Add("GAP-0091 back-fill: $($case[0]) recorded=$recordedNow, want $($case[5]): $(Get-DefenseClawVendorFolderBackfillRefusal -Path $caseVendor -UsersInherit:([bool]$case[2]))")
                    }
                }

                # Review 2 L1: the record of the folder above the lifecycle
                # folder goes only when that folder holds nothing but the
                # lifecycle folder; with anything else (here a kept MDM
                # journal) the folder stays, and its record with it. L2: a
                # recorded folder two levels down is kept when a folder above
                # its parent is open to someone else. L3: every kept folder is
                # in the list the result carries.
                $r3 = [IO.Path]::Combine($root, 'r3')
                $r3pd = [IO.Path]::Combine($r3, 'ProgramData')
                $r3pf = [IO.Path]::Combine($r3, 'Program Files')
                $r3roots = @($r3pd, $r3pf)
                $r3vendor = [IO.Path]::Combine($r3pd, 'Cisco')
                $r3life = [IO.Path]::Combine($r3vendor, 'DefenseClaw-Lifecycle')
                $r3records = [IO.Path]::Combine($r3life, 'created-folders')
                $r3journal = [IO.Path]::Combine($r3vendor, 'DefenseClaw-MDM', 'rotation')
                $r3open = [IO.Path]::Combine($r3pd, 'Open2')
                $r3deep = [IO.Path]::Combine($r3open, 'Mid', 'Leaf')
                foreach ($folder in @($r3pd, $r3pf, $r3vendor, $r3journal)) {
                    [void][IO.Directory]::CreateDirectory($folder)
                }
                [void]$native::CreateDirectorySecure($r3life, $adminOnly)
                [IO.File]::WriteAllText([IO.Path]::Combine($r3life, 'lifecycle.lock'), '')
                [void][IO.Directory]::CreateDirectory($r3open)
                Set-G091AdministratorsOwner -Path @($r3pd, $r3pf, $r3vendor, ([IO.Path]::GetDirectoryName($r3journal)), $r3journal, $r3open)
                foreach ($folder in @(([IO.Path]::Combine($r3open, 'Mid')), $r3deep)) {
                    [void]$native::CreateDirectorySecure($folder, $adminOnly)
                }
                $openAcl = Microsoft.PowerShell.Security\Get-Acl -LiteralPath $r3open
                $openAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                    [Security.Principal.SecurityIdentifier]::new($script:UsersSID),
                    [Security.AccessControl.FileSystemRights]::Modify,
                    [Security.AccessControl.InheritanceFlags]::None,
                    [Security.AccessControl.PropagationFlags]::None,
                    [Security.AccessControl.AccessControlType]::Allow))
                Microsoft.PowerShell.Security\Set-Acl -LiteralPath $r3open -AclObject $openAcl
                $null = Add-DefenseClawStandaloneCreatedFolderRecord -Path @($r3vendor, $r3deep) -RecordDirectory $r3records -Roots $r3roots
                $logged.Clear()
                $script:DefenseClawCreatedFoldersKept.Clear()
                $r3layout = @{ SelfUninstallReceiptPath = [IO.Path]::Combine($r3life, ('self-uninstall-' + ('2' * 64) + '.json')) }
                $r3deferred = @(Invoke-DefenseClawStandaloneCreatedFolderRemoval -Layout $r3layout -RecordDirectory $r3records -Roots $r3roots -SkipDeploymentCheck)
                if ($r3deferred.Count -ne 0 -or
                    -not [IO.File]::Exists([IO.Path]::Combine($r3records, (Get-DefenseClawCreatedFolderRecordName -Path $r3deep)))) {
                    $failures.Add("review 2 L2: a recorded folder under an open grandparent was handed on or lost its record: $($r3deferred -join '; ')")
                }
                if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $r3deep)) {
                    $failures.Add('review 2 L2: a recorded folder under a grandparent someone else can write was removed')
                }
                # The open grandparent goes; the journal still holds the vendor folder.
                [IO.Directory]::Delete($r3deep, $false)
                [IO.Directory]::Delete([IO.Path]::Combine($r3open, 'Mid'), $false)
                [IO.Directory]::Delete($r3open, $false)
                $logged.Clear()
                $script:DefenseClawCreatedFoldersKept.Clear()
                $r3deferred = @(Invoke-DefenseClawStandaloneCreatedFolderRemoval -Layout $r3layout -RecordDirectory $r3records -Roots $r3roots -SkipDeploymentCheck)
                $r3vendorRecord = [IO.Path]::Combine($r3records, (Get-DefenseClawCreatedFolderRecordName -Path $r3vendor))
                if ($r3deferred.Count -ne 0 -or -not [IO.File]::Exists($r3vendorRecord)) {
                    $failures.Add("review 2 L1: the record of a vendor folder that still holds a kept journal went: handed on '$($r3deferred -join '; ')', record=$([IO.File]::Exists($r3vendorRecord))")
                }
                if (@($logged | Microsoft.PowerShell.Core\Where-Object { $_.StartsWith("defenseclaw_skip path=${r3vendor}: a folder DefenseClaw created stays, and so does its record: it holds") }).Count -ne 1) {
                    $failures.Add("review 2 L1: the lifecycle log does not say once why the vendor folder and its record stay: $($logged -join ' | ')")
                }
                $kept = @(Get-DefenseClawCreatedFoldersKept)
                if ($kept.Count -ne 1 -or -not ([string]$kept[0]).StartsWith("${r3vendor}: a folder DefenseClaw created stays, and so does its record: it holds")) {
                    $failures.Add("review 2 L3: the result's kept list is not the vendor folder once: $($kept -join ' | ')")
                }
                # The journal goes: the record goes, the folder is handed on and
                # removed last.
                [IO.Directory]::Delete($r3journal, $false)
                [IO.Directory]::Delete([IO.Path]::GetDirectoryName($r3journal), $false)
                $script:DefenseClawCreatedFoldersKept.Clear()
                $r3deferred = @(Invoke-DefenseClawStandaloneCreatedFolderRemoval -Layout $r3layout -RecordDirectory $r3records -Roots $r3roots -SkipDeploymentCheck)
                if ($r3deferred.Count -ne 1 -or $r3deferred[0] -cne $r3vendor -or [IO.File]::Exists($r3vendorRecord)) {
                    $failures.Add("review 2 L1: an emptied vendor folder was not handed on with its record gone: $($r3deferred -join '; ')")
                }
                # A folder handed on that cannot go any more (an install made
                # something in it meanwhile) is reported without a record.
                [IO.File]::Delete([IO.Path]::Combine($r3life, 'lifecycle.lock'))
                [IO.Directory]::Delete($r3life)
                [void][IO.Directory]::CreateDirectory([IO.Path]::Combine($r3vendor, 'DefenseClaw'))
                $logged.Clear()
                Remove-DefenseClawStandaloneCreatedFolders -Path $r3deferred -Roots $r3roots
                if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $r3vendor) -or
                    @($logged | Microsoft.PowerShell.Core\Where-Object { $_.StartsWith("defenseclaw_skip path=${r3vendor}: a folder DefenseClaw created stays; its record went with the lifecycle folder in it") }).Count -ne 1) {
                    $failures.Add("review 2 L1: a handed-on folder that stays is not reported as record-less: $($logged -join ' | ')")
                }
                [IO.Directory]::Delete([IO.Path]::Combine($r3vendor, 'DefenseClaw'), $false)
                Remove-DefenseClawStandaloneCreatedFolders -Path $r3deferred -Roots $r3roots
                if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $r3vendor) {
                    $failures.Add('review 2 L1: the emptied vendor folder stayed')
                }

                # Batch red (rel/1.0.9 Windows install and upgrade lanes): the
                # Go scanner step removes DefenseClaw-ScannerRuntime only after
                # this script returned, so a Setup /uninstall found the Cisco
                # folder holding it, reported the folder as kept and left it.
                # The purge now retires the runtime (a sibling of the
                # lifecycle folder) first: under its lock, never through a
                # junction, only when administrator-only.
                $sr = [IO.Path]::Combine($root, 'scanner')
                $srpd = [IO.Path]::Combine($sr, 'ProgramData')
                $srpf = [IO.Path]::Combine($sr, 'Program Files')
                $srroots = @($srpd, $srpf)
                $srvendor = [IO.Path]::Combine($srpd, 'Cisco')
                $srlife = [IO.Path]::Combine($srvendor, 'DefenseClaw-Lifecycle')
                $srrecords = [IO.Path]::Combine($srlife, 'created-folders')
                $srruntime = [IO.Path]::Combine($srvendor, 'DefenseClaw-ScannerRuntime')
                $srsite = [IO.Path]::Combine($srruntime, 'cpython', 'Lib')
                $srtarget = [IO.Path]::Combine($sr, 'link-target')
                foreach ($folder in @($srpd, $srpf, $srvendor, $srtarget)) {
                    [void][IO.Directory]::CreateDirectory($folder)
                }
                Set-G091AdministratorsOwner -Path @($srpd, $srpf, $srvendor)
                [void]$native::CreateDirectorySecure($srlife, $adminOnly)
                [IO.File]::WriteAllText([IO.Path]::Combine($srlife, 'lifecycle.lock'), '')
                [void]$native::CreateDirectorySecure($srruntime, $adminOnly)
                [void]$native::CreateDirectorySecure([IO.Path]::Combine($srruntime, 'cpython'), $adminOnly)
                [void]$native::CreateDirectorySecure($srsite, $adminOnly)
                [IO.File]::WriteAllText([IO.Path]::Combine($srruntime, 'defenseclaw-scanners.exe'), 'x')
                [IO.File]::WriteAllText([IO.Path]::Combine($srsite, 'site.py'), 'x')
                [IO.File]::SetAttributes([IO.Path]::Combine($srsite, 'site.py'), [IO.FileAttributes]::ReadOnly)
                [IO.File]::WriteAllText([IO.Path]::Combine($srtarget, 'keep.txt'), 'keep')
                [void](Microsoft.PowerShell.Management\New-Item -ItemType Junction -Path ([IO.Path]::Combine($srsite, 'out')) -Target $srtarget)
                $junctions.Add([IO.Path]::Combine($srsite, 'out'))
                $null = Add-DefenseClawStandaloneCreatedFolderRecord -Path @($srvendor) -RecordDirectory $srrecords -Roots $srroots
                $srlayout = @{ SelfUninstallReceiptPath = [IO.Path]::Combine($srlife, ('self-uninstall-' + ('4' * 64) + '.json')) }
                # A run that holds the scanner runtime lock keeps the runtime,
                # and with it the Cisco folder, which is named as kept.
                $held = [IO.FileStream]::new([IO.Path]::Combine($srruntime, 'scanner-runtime.lock'),
                    [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
                try {
                    $script:DefenseClawCreatedFoldersKept.Clear()
                    $srdeferred = @(Invoke-DefenseClawStandaloneCreatedFolderRemoval -Layout $srlayout -RecordDirectory $srrecords -Roots $srroots -SkipDeploymentCheck)
                }
                finally {
                    $held.Dispose()
                }
                $srkept = @(Get-DefenseClawCreatedFoldersKept)
                if ($srdeferred.Count -ne 0 -or -not [IO.File]::Exists([IO.Path]::Combine($srsite, 'site.py')) -or
                    $srkept.Count -ne 1 -or -not ([string]$srkept[0]).Contains('DefenseClaw-ScannerRuntime')) {
                    $failures.Add("scanner runtime: a runtime whose lock another run holds was removed or the Cisco folder not named as kept: handed on '$($srdeferred -join '; ')', kept=$($srkept -join ' | ')")
                }
                # A scanner-runtime.lock that is a link is refused before it is
                # opened, as the Go step opens it without following links:
                # following it would delete the link's target when the stream
                # closes. The runtime is left whole for the Go step. A file
                # symbolic link and a junction are both tried; only the file
                # link is followed (and its target deleted) without the check.
                $srlockPath = [IO.Path]::Combine($srruntime, 'scanner-runtime.lock')
                $srlockfile = [IO.Path]::Combine($srtarget, 'lock-target.txt')
                [IO.File]::WriteAllText($srlockfile, 'lock-target')
                foreach ($kind in @('SymbolicLink', 'Junction')) {
                    $srlinkTarget = $srlockfile
                    if ($kind -eq 'Junction') {
                        $srlinkTarget = $srtarget
                    }
                    [IO.File]::Delete($srlockPath)
                    if ([IO.Directory]::Exists($srlockPath)) {
                        [IO.Directory]::Delete($srlockPath, $false)
                    }
                    [void](Microsoft.PowerShell.Management\New-Item -ItemType $kind -Path $srlockPath -Target $srlinkTarget)
                    try {
                        $script:DefenseClawCreatedFoldersKept.Clear()
                        $srdeferred = @(Invoke-DefenseClawStandaloneCreatedFolderRemoval -Layout $srlayout -RecordDirectory $srrecords -Roots $srroots -SkipDeploymentCheck)
                        $srkept = @(Get-DefenseClawCreatedFoldersKept)
                        $srattr = [IO.File]::GetAttributes($srlockPath)
                        if (-not [IO.File]::Exists($srlockfile) -or [IO.File]::ReadAllText($srlockfile) -cne 'lock-target') {
                            $failures.Add("scanner runtime: a lock file that is a $kind was followed and its target changed or deleted")
                        }
                        if (($srattr -band [IO.FileAttributes]::ReparsePoint) -eq 0) {
                            $failures.Add("scanner runtime: a lock file that is a $kind was replaced or removed")
                        }
                        if (-not [IO.File]::Exists([IO.Path]::Combine($srsite, 'site.py')) -or
                            -not [IO.File]::Exists([IO.Path]::Combine($srtarget, 'keep.txt'))) {
                            $failures.Add("scanner runtime: a lock file that is a $kind did not leave the runtime whole")
                        }
                        if ($srdeferred.Count -ne 0 -or $srkept.Count -ne 1 -or -not ([string]$srkept[0]).Contains('DefenseClaw-ScannerRuntime')) {
                            $failures.Add("scanner runtime: a lock file that is a $kind did not keep the Cisco folder as kept: handed on '$($srdeferred -join '; ')', kept=$($srkept -join ' | ')")
                        }
                    }
                    finally {
                        if ([IO.Directory]::Exists($srlockPath)) {
                            [IO.Directory]::Delete($srlockPath, $false)
                        }
                        elseif ([IO.File]::Exists($srlockPath) -or (Test-DefenseClawPathPresentNoFollow -Path $srlockPath)) {
                            [IO.File]::Delete($srlockPath)
                        }
                    }
                }
                [IO.File]::Delete($srlockfile)
                # With the lock free, a junction inside the runtime is left
                # as found (its target is untouched) and keeps the runtime,
                # which the Go step then removes as a link.
                $script:DefenseClawCreatedFoldersKept.Clear()
                $srdeferred = @(Invoke-DefenseClawStandaloneCreatedFolderRemoval -Layout $srlayout -RecordDirectory $srrecords -Roots $srroots -SkipDeploymentCheck)
                if (-not [IO.File]::Exists([IO.Path]::Combine($srtarget, 'keep.txt'))) {
                    $failures.Add('scanner runtime: a junction inside the runtime was followed')
                }
                if ($srdeferred.Count -ne 0 -or @(Get-DefenseClawCreatedFoldersKept).Count -ne 1) {
                    $failures.Add("scanner runtime: a runtime holding a junction did not keep the Cisco folder as kept: handed on '$($srdeferred -join '; ')'")
                }
                # Without the junction it goes, and the Cisco folder is handed
                # on with its record gone, to be removed last.
                [IO.Directory]::Delete([IO.Path]::Combine($srsite, 'out'), $false)
                $script:DefenseClawCreatedFoldersKept.Clear()
                $srdeferred = @(Invoke-DefenseClawStandaloneCreatedFolderRemoval -Layout $srlayout -RecordDirectory $srrecords -Roots $srroots -SkipDeploymentCheck)
                if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $srruntime) {
                    $failures.Add('scanner runtime: the DefenseClaw-ScannerRuntime folder stayed with no deployment left')
                }
                if ($srdeferred.Count -ne 1 -or $srdeferred[0] -cne $srvendor -or @(Get-DefenseClawCreatedFoldersKept).Count -ne 0) {
                    $failures.Add("scanner runtime: the Cisco folder was not handed on without a kept note once the runtime was gone: handed on '$($srdeferred -join '; ')', kept=$(@(Get-DefenseClawCreatedFoldersKept) -join ' | ')")
                }
                [IO.File]::Delete([IO.Path]::Combine($srlife, 'lifecycle.lock'))
                [IO.Directory]::Delete($srlife)
                Remove-DefenseClawStandaloneCreatedFolders -Path $srdeferred -Roots $srroots
                if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $srvendor) {
                    $failures.Add('scanner runtime: the Cisco folder stayed after the runtime and the lifecycle folder were gone')
                }

                # Review 2 L3: with a self-uninstall finalizer pending, the
                # result names what the finalizer will keep: a recorded folder
                # holding another program's file; not a Cisco folder holding
                # only DefenseClaw's folders and the retired install root.
                $pv = [IO.Path]::Combine($root, 'preview')
                $pvpd = [IO.Path]::Combine($pv, 'ProgramData')
                $pvpf = [IO.Path]::Combine($pv, 'Program Files')
                $pvvendor = [IO.Path]::Combine($pvpd, 'Cisco')
                $pvlife = [IO.Path]::Combine($pvvendor, 'DefenseClaw-Lifecycle')
                $pvrecords = [IO.Path]::Combine($pvlife, 'created-folders')
                $pvpfvendor = [IO.Path]::Combine($pvpf, 'Cisco')
                $pvcursor = [IO.Path]::Combine($pvpd, 'Cursor')
                foreach ($folder in @($pvpd, $pvpf, $pvvendor, $pvcursor, ([IO.Path]::Combine($pvpfvendor, ('DefenseClaw.retired-' + ('a' * 32)))))) {
                    [void][IO.Directory]::CreateDirectory($folder)
                }
                Set-G091AdministratorsOwner -Path @($pvpd, $pvpf, $pvvendor, $pvcursor, $pvpfvendor, ([IO.Path]::Combine($pvpfvendor, ('DefenseClaw.retired-' + ('a' * 32)))))
                [void]$native::CreateDirectorySecure($pvlife, $adminOnly)
                [IO.File]::WriteAllText([IO.Path]::Combine($pvcursor, 'cursor-own.json'), '{}')
                $null = Add-DefenseClawStandaloneCreatedFolderRecord -Path @($pvvendor, $pvpfvendor, $pvcursor) -RecordDirectory $pvrecords -Roots @($pvpd, $pvpf)
                $pvlayout = @{ SelfUninstallReceiptPath = [IO.Path]::Combine($pvlife, ('self-uninstall-' + ('3' * 64) + '.json')) }
                if (@(Get-DefenseClawStandaloneCreatedFolderPreview -Layout $pvlayout -RecordDirectory $pvrecords -Roots @($pvpd, $pvpf)).Count -ne 0) {
                    $failures.Add('review 2 L3: the preview ran with no self-uninstall finalizer pending')
                }
                [IO.File]::WriteAllText($pvlayout.SelfUninstallReceiptPath, '{}')
                $preview = @(Get-DefenseClawStandaloneCreatedFolderPreview -Layout $pvlayout -RecordDirectory $pvrecords -Roots @($pvpd, $pvpf))
                if ($preview.Count -ne 1 -or $preview[0].Folder -cne $pvcursor -or
                    -not ([string]$preview[0].Note).Contains('it holds cursor-own.json')) {
                    $failures.Add("review 2 L3: the preview is not the Cursor folder alone: $(@($preview | Microsoft.PowerShell.Core\ForEach-Object { "$($_.Folder): $($_.Note)" }) -join ' | ')")
                }

                # GAP-0704: on a computer installed before 1.0.9 the agent
                # folders are back-filled ("origin":"upgrade") only when all
                # three proofs hold: (a) created no earlier than StateRoot,
                # (b) exactly the permissions DefenseClaw creates them with,
                # (c) only DefenseClaw's own files; a parent only when its
                # only child is recorded. Anything else stays and the purge
                # names it once (rule i). A Cisco folder that holds anything
                # shaped like Secure Client is never back-filled or removed
                # (rule ii).
                $agentSddl = 'O:BAG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)'
                $ag = [IO.Path]::Combine($root, 'g0704')
                $agPd = [IO.Path]::Combine($ag, 'ProgramData')
                $agPf = [IO.Path]::Combine($ag, 'Program Files')
                $agRoots = @($agPd, $agPf)
                $agVendor = [IO.Path]::Combine($agPd, 'Cisco')
                $agState = [IO.Path]::Combine($agVendor, 'DefenseClaw')
                $agLife = [IO.Path]::Combine($agVendor, 'DefenseClaw-Lifecycle')
                $agRecords = [IO.Path]::Combine($agLife, 'created-folders')
                $agClaude = [IO.Path]::Combine($agPf, 'ClaudeCode')
                $agDropIns = [IO.Path]::Combine($agClaude, 'managed-settings.d')
                $agCursor = [IO.Path]::Combine($agPd, 'Cursor')
                $agOpenAI = [IO.Path]::Combine($agPd, 'OpenAI')
                $agCodex = [IO.Path]::Combine($agOpenAI, 'Codex')
                $agArgs = @{ RecordDirectory = $agRecords; Roots = $agRoots; StateRoot = $agState; ProgramData = $agPd; ProgramFiles = $agPf
                    ProgramDataVendorFolder = $agVendor; ProgramFilesVendorFolder = [IO.Path]::Combine($agPf, 'Cisco') }
                $agNew = {
                    param([string[]]$Folders)
                    foreach ($folder in $Folders) {
                        [void]$native::CreateDirectorySecure($folder, $agentSddl)
                    }
                }
                $agRecord = { param([string]$Folder) [IO.Path]::Combine($agRecords, (Get-DefenseClawCreatedFolderRecordName -Path $Folder)) }
                foreach ($folder in @($agPd, $agPf, $agVendor, $agState)) {
                    [void][IO.Directory]::CreateDirectory($folder)
                }
                Set-G091AdministratorsOwner -Path @($agPd, $agPf, $agVendor, $agState)
                [void]$native::CreateDirectorySecure($agLife, $adminOnly)
                [IO.File]::WriteAllText([IO.Path]::Combine($agLife, 'lifecycle.lock'), '')
                $stateBorn = [IO.Directory]::GetCreationTimeUtc($agState)
                & $agNew @($agClaude, $agDropIns, $agCursor, $agOpenAI, $agCodex)
                foreach ($own in @(
                        @($agDropIns, '90-defenseclaw.json'), @($agDropIns, '00-defenseclaw-version-floor.json'),
                        @($agDropIns, '.defenseclaw-managed-hooks.lock'), @($agDropIns, '.defenseclaw-managed-runtime-selector.lock'),
                        @($agCursor, '.defenseclaw-managed-runtime-selector.lock'),
                        @($agCodex, '.defenseclaw-managed-hooks.lock'), @($agCodex, '.defenseclaw-managed-runtime-selector.lock'))) {
                    [IO.File]::WriteAllText([IO.Path]::Combine($own[0], $own[1]), '{}')
                }
                # requirements.toml counts only when the state binds its hash
                # and the ownership record says DefenseClaw published it where
                # none was.
                $toml = [IO.Path]::Combine($agCodex, 'requirements.toml')
                [IO.File]::WriteAllText($toml, "[hooks]`n")
                $tomlHash = Get-DefenseClawPlainFileSha256 -Path $toml
                [IO.File]::WriteAllText([IO.Path]::Combine($agCodex, '.defenseclaw-managed-hooks.state'), (@{ requirements_sha256 = $tomlHash } | Microsoft.PowerShell.Utility\ConvertTo-Json -Compress))
                $ownershipPath = [IO.Path]::Combine($agState, 'install', 'codex-requirements-ownership.json')
                [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($ownershipPath))
                [IO.File]::WriteAllText($ownershipPath, (@{ preimage_existed = $true; postimage_sha256 = $tomlHash } | Microsoft.PowerShell.Utility\ConvertTo-Json -Compress))
                if (-not ([string](Get-DefenseClawAgentFolderBackfillRefusal -Path $agCodex -Kind Codex -StateRoot $agState -RecordDirectory $agRecords -CodexOwnershipPath $ownershipPath)).Contains('requirements.toml')) {
                    $failures.Add('GAP-0704 (c): a requirements.toml that was there before DefenseClaw counted as its own')
                }
                [IO.File]::WriteAllText($ownershipPath, (@{ preimage_existed = $false; postimage_sha256 = $tomlHash } | Microsoft.PowerShell.Utility\ConvertTo-Json -Compress))
                # (a) a folder that existed before StateRoot; (b) other
                # permissions; (c) a foreign file. Each its own folder.
                $agBefore = [IO.Path]::Combine($agPd, 'OpenAI-before')
                $agBeforeCodex = [IO.Path]::Combine($agBefore, 'Codex')
                & $agNew @($agBefore, $agBeforeCodex)
                [IO.Directory]::SetCreationTimeUtc($agBeforeCodex, $stateBorn.AddMinutes(-5))
                $agInherited = [IO.Path]::Combine($agPd, 'Inherited')
                [void][IO.Directory]::CreateDirectory($agInherited)
                $agExtra = [IO.Path]::Combine($agPd, 'Extra')
                [void]$native::CreateDirectorySecure($agExtra, $agentSddl + '(A;OICI;0x1301bf;;;BU)')
                $agForeign = [IO.Path]::Combine($agPd, 'Foreign')
                & $agNew @($agForeign)
                [IO.File]::WriteAllText([IO.Path]::Combine($agForeign, '.defenseclaw-managed-runtime-selector.lock'), '')
                [IO.File]::WriteAllText([IO.Path]::Combine($agForeign, 'settings.json'), '{}')
                foreach ($case in @(
                        @('(a) a folder created before StateRoot', $agBeforeCodex, 'Codex', 'before DefenseClaw''s StateRoot'),
                        @('(b) an inherited descriptor', $agInherited, 'Cursor', ''),
                        @('(b) DefenseClaw''s descriptor with one more entry', $agExtra, 'Cursor', 'DefenseClaw gives a folder it creates'),
                        @('(c) a foreign file', $agForeign, 'Cursor', 'settings.json'))) {
                    $why = [string](Get-DefenseClawAgentFolderBackfillRefusal -Path $case[1] -Kind $case[2] -StateRoot $agState -RecordDirectory $agRecords -CodexOwnershipPath $ownershipPath)
                    if ([string]::IsNullOrEmpty($why) -or ($case[3] -ne '' -and -not $why.Contains($case[3]))) {
                        $failures.Add("GAP-0704 $($case[0]) was not refused as expected: '$why'")
                    }
                }
                # A foreign file in managed-settings.d keeps it and ClaudeCode
                # unrecorded; once it goes, both are back-filled.
                $agForeignDropIn = [IO.Path]::Combine($agDropIns, '50-other-vendor.json')
                [IO.File]::WriteAllText($agForeignDropIn, '{}')
                Add-DefenseClawStandaloneUpgradeVendorFolderRecords @agArgs
                $agMarker = [IO.Path]::Combine($agRecords, 'agent-folder-backfill.done')
                if (-not [IO.File]::Exists($agMarker)) {
                    $failures.Add('GAP-0704 review 3 S2: the first agent-folder back-fill left no one-shot marker')
                }
                foreach ($case in @(@('Cursor', $agCursor, $true), @('OpenAI\Codex', $agCodex, $true), @('OpenAI (its only child recorded)', $agOpenAI, $true),
                        @('managed-settings.d holding a foreign file', $agDropIns, $false), @('ClaudeCode above an unrecorded child', $agClaude, $false),
                        @('the Cisco folder with an inherited descriptor', $agVendor, $false))) {
                    if ([IO.File]::Exists((& $agRecord $case[1])) -ne $case[2]) {
                        $failures.Add("GAP-0704 back-fill: $($case[0]) recorded=$(-not $case[2]), want $($case[2])")
                    }
                }
                # Review 3 L4: only the folders DefenseClaw touched (a
                # DefenseClaw file, or a DefenseClaw folder, in them), taken
                # before the uninstall removes its files.
                $touched = @(Get-DefenseClawTouchedUnrecordedVendorFolders -RecordDirectory $agRecords -ProgramData $agPd -ProgramFiles $agPf)
                $unproven = @(Get-DefenseClawUnprovenVendorFolders -Touched $touched -RecordDirectory $agRecords)
                foreach ($want in @($agDropIns, $agClaude, $agVendor)) {
                    if (@($unproven | Microsoft.PowerShell.Core\Where-Object { $_ -ceq $want }).Count -ne 1) {
                        $failures.Add("GAP-0704 rule (i): $want is not listed once as not provably created: $($unproven -join '; ')")
                    }
                }
                if ($unproven.Count -ne 3) {
                    $failures.Add("GAP-0704 rule (i): want exactly the three unproven folders, got: $($unproven -join '; ')")
                }
                [IO.File]::Delete($agForeignDropIn)
                # Review 3 S2: the back-fill is one-shot. The foreign file is
                # gone, but a later install, upgrade or repair does not
                # record the two folders.
                Add-DefenseClawStandaloneUpgradeVendorFolderRecords @agArgs
                foreach ($folder in @($agDropIns, $agClaude)) {
                    if ([IO.File]::Exists((& $agRecord $folder))) {
                        $failures.Add("GAP-0704 review 3 S2: a second back-fill recorded $folder")
                    }
                }
                # A first run that did not reach its marker back-fills again.
                [IO.File]::Delete($agMarker)
                Add-DefenseClawStandaloneUpgradeVendorFolderRecords @agArgs
                foreach ($folder in @($agDropIns, $agClaude, $agCursor, $agCodex, $agOpenAI)) {
                    $recordFile = & $agRecord $folder
                    if (-not [IO.File]::Exists($recordFile)) {
                        $failures.Add("GAP-0704 back-fill: $folder was not recorded once its foreign file went")
                        continue
                    }
                    $document = [IO.File]::ReadAllText($recordFile) | Microsoft.PowerShell.Utility\ConvertFrom-Json
                    if ([string]$document.origin -cne 'upgrade' -or [int]$document.schema_version -ne 1 -or [string]$document.path -cne $folder) {
                        $failures.Add("GAP-0704: the record of $folder is not schema 1 with origin upgrade: $([IO.File]::ReadAllText($recordFile))")
                    }
                }
                foreach ($folder in @($agBeforeCodex, $agBefore, $agInherited, $agExtra, $agForeign)) {
                    if ([IO.File]::Exists((& $agRecord $folder))) {
                        $failures.Add("GAP-0704: $folder was recorded")
                    }
                }
                # The purge (after the teardown removed DefenseClaw's files)
                # removes the back-filled folders and their records.
                foreach ($folder in @($agDropIns, $agCursor, $agCodex)) {
                    foreach ($file in @(Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $folder -Force -File)) {
                        [IO.File]::Delete($file.FullName)
                    }
                }
                $agLayout = @{ SelfUninstallReceiptPath = [IO.Path]::Combine($agLife, ('self-uninstall-' + ('4' * 64) + '.json')) }
                [void](Invoke-DefenseClawStandaloneCreatedFolderRemoval -Layout $agLayout -RecordDirectory $agRecords -Roots $agRoots -SkipDeploymentCheck)
                foreach ($folder in @($agDropIns, $agClaude, $agCursor, $agCodex, $agOpenAI)) {
                    if ((Microsoft.PowerShell.Management\Test-Path -LiteralPath $folder) -or [IO.File]::Exists((& $agRecord $folder))) {
                        $failures.Add("GAP-0704: the purge left the back-filled empty folder $folder or its record")
                    }
                }
                foreach ($folder in @($agBeforeCodex, $agInherited, $agExtra, $agForeign)) {
                    if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $folder)) {
                        $failures.Add("GAP-0704: the purge removed $folder, which nothing proves DefenseClaw created")
                    }
                }
                if ([IO.File]::Exists($agMarker) -or [IO.Directory]::Exists($agRecords)) {
                    $failures.Add('GAP-0704 review 3 S2: the purge left the one-shot marker or the record folder')
                }

                # Review 3: a fixture for each new row, with its own roots,
                # StateRoot and lifecycle folder.
                $r4Root = [IO.Path]::Combine($root, 'g0704r4')
                $r4New = {
                    param([string]$Name)
                    $c = @{}
                    $base = [IO.Path]::Combine($r4Root, $Name)
                    $c.Pd = [IO.Path]::Combine($base, 'ProgramData')
                    $c.Pf = [IO.Path]::Combine($base, 'Program Files')
                    $c.Vendor = [IO.Path]::Combine($c.Pd, 'Cisco')
                    $c.State = [IO.Path]::Combine($c.Vendor, 'DefenseClaw')
                    $c.Life = [IO.Path]::Combine($c.Vendor, 'DefenseClaw-Lifecycle')
                    $c.Records = [IO.Path]::Combine($c.Life, 'created-folders')
                    foreach ($folder in @($c.Pd, $c.Pf, $c.Vendor, $c.State)) {
                        [void][IO.Directory]::CreateDirectory($folder)
                    }
                    Set-G091AdministratorsOwner -Path @($c.Pd, $c.Pf, $c.Vendor, $c.State)
                    [void]$native::CreateDirectorySecure($c.Life, $adminOnly)
                    [IO.File]::WriteAllText([IO.Path]::Combine($c.Life, 'lifecycle.lock'), '')
                    $c.Roots = @($c.Pd, $c.Pf)
                    $c.Args = @{ RecordDirectory = $c.Records; Roots = $c.Roots; StateRoot = $c.State; ProgramData = $c.Pd; ProgramFiles = $c.Pf
                        ProgramDataVendorFolder = $c.Vendor; ProgramFilesVendorFolder = [IO.Path]::Combine($c.Pf, 'Cisco') }
                    $c.OpenAI = [IO.Path]::Combine($c.Pd, 'OpenAI')
                    $c.Codex = [IO.Path]::Combine($c.OpenAI, 'Codex')
                    $c.Ownership = [IO.Path]::Combine($c.State, 'install', 'codex-requirements-ownership.json')
                    $c
                }
                $r4Fill = { param($c) $fillArgs = $c.Args; Add-DefenseClawStandaloneUpgradeVendorFolderRecords @fillArgs }
                $r4Has = { param($c, [string]$Folder) [IO.File]::Exists([IO.Path]::Combine($c.Records, (Get-DefenseClawCreatedFolderRecordName -Path $Folder))) }
                # A Codex folder as the machine-policy writer of this release
                # leaves it: the writer lock (its size is the counter), the
                # writer copy and the hook copy of the state.
                $r4Codex = {
                    param($c, [switch]$Committed, [string]$HookCopy = '4', [string]$LockBytes = 'abc')
                    & $agNew @($c.OpenAI, $c.Codex)
                    $toml = [IO.Path]::Combine($c.Codex, 'requirements.toml')
                    [IO.File]::WriteAllText($toml, "[hooks]`n")
                    $hash = Get-DefenseClawPlainFileSha256 -Path $toml
                    $state = (@{ requirements_sha256 = $hash } | Microsoft.PowerShell.Utility\ConvertTo-Json -Compress)
                    [IO.File]::WriteAllText([IO.Path]::Combine($c.Codex, '.defenseclaw-managed-hooks.writer.lock'), $LockBytes)
                    if ($Committed) {
                        [IO.File]::WriteAllText([IO.Path]::Combine($c.Codex, '.defenseclaw-managed-hooks.state.committed'), $state)
                    }
                    if ($HookCopy) {
                        [IO.File]::WriteAllText([IO.Path]::Combine($c.Codex, ('.defenseclaw-managed-hooks.state.' + $HookCopy)), $state)
                    }
                    [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($c.Ownership))
                    [IO.File]::WriteAllText($c.Ownership, (@{ preimage_existed = $false; postimage_sha256 = $hash } | Microsoft.PowerShell.Utility\ConvertTo-Json -Compress))
                }

                # Review 3 S1: the files the Codex machine-policy writer adds
                # (.defenseclaw-managed-hooks.writer.lock, .state.committed,
                # .state.<n>) are DefenseClaw's own, and the state copy the
                # lock names binds requirements.toml, so a back-fill after
                # that writer has published still recognises the folder.
                foreach ($case in @(
                        @('s1a', 'writer lock, writer copy and hook copy', @{ Committed = $true }, $true),
                        @('s1b', 'hook copy named by the lock only', @{}, $true),
                        @('s1c', 'a hook copy the lock does not name', @{ HookCopy = '6' }, $false),
                        @('s1d', 'a state copy name DefenseClaw does not write', @{ HookCopy = '04' }, $false))) {
                    $c = & $r4New $case[0]
                    $codexArgs = $case[2]
                    & $r4Codex $c @codexArgs
                    & $r4Fill $c
                    $got = [bool](& $r4Has $c $c.Codex)
                    if ($got -ne $case[3]) {
                        $failures.Add("GAP-0704 review 3 S1: Codex folder with $($case[1]) recorded=$got, want $($case[3]): $(Get-DefenseClawAgentFolderBackfillRefusal -Path $c.Codex -Kind Codex -StateRoot $c.State -RecordDirectory $c.Records -CodexOwnershipPath $c.Ownership)")
                    }
                    if ($case[3] -and $got) {
                        if (-not (& $r4Has $c $c.OpenAI)) {
                            $failures.Add("GAP-0704 review 3 S1: OpenAI above the $($case[1]) folder was not recorded")
                        }
                        $document = [IO.File]::ReadAllText([IO.Path]::Combine($c.Records, (Get-DefenseClawCreatedFolderRecordName -Path $c.Codex))) | Microsoft.PowerShell.Utility\ConvertFrom-Json
                        if ([string]$document.origin -cne 'upgrade') {
                            $failures.Add('GAP-0704 review 3 S1: the Codex record is not origin upgrade')
                        }
                    }
                }
                # The names belong to Codex only.
                $c = & $r4New 's1e'
                $cursorHere = [IO.Path]::Combine($c.Pd, 'Cursor')
                & $agNew @($cursorHere)
                [IO.File]::WriteAllText([IO.Path]::Combine($cursorHere, '.defenseclaw-managed-hooks.writer.lock'), 'abc')
                if (([string](Get-DefenseClawAgentFolderBackfillRefusal -Path $cursorHere -Kind Cursor -StateRoot $c.State -RecordDirectory $c.Records)) -notlike '*writer.lock*') {
                    $failures.Add('GAP-0704 review 3 S1: a Cursor folder holding the Codex writer lock was not refused')
                }

                # Review 3 S2: an empty folder an administrator made after the
                # first run, adopted by Setup (g582 case b: re-stamped with
                # DefenseClaw's descriptor, then holding DefenseClaw's lock),
                # is not recorded by a later repair, and a purge keeps it.
                $c = & $r4New 's2'
                & $r4Fill $c
                if (-not [IO.File]::Exists([IO.Path]::Combine($c.Records, 'agent-folder-backfill.done'))) {
                    $failures.Add('GAP-0704 review 3 S2: the first run on an empty deployment left no marker')
                }
                & $r4Codex $c -Committed
                & $r4Fill $c
                if ((& $r4Has $c $c.Codex) -or (& $r4Has $c $c.OpenAI)) {
                    $failures.Add('GAP-0704 review 3 S2: a repair after the adoption recorded the adopted folder')
                }
                $adoptedTouched = @(Get-DefenseClawTouchedUnrecordedVendorFolders -RecordDirectory $c.Records -ProgramData $c.Pd -ProgramFiles $c.Pf)
                if (@($adoptedTouched | Microsoft.PowerShell.Core\Where-Object { $_ -ceq $c.Codex }).Count -ne 1) {
                    $failures.Add("GAP-0704 review 3 S2: the adopted folder is not named as touched: $($adoptedTouched -join '; ')")
                }
                foreach ($file in @(Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $c.Codex -Force -File)) {
                    [IO.File]::Delete($file.FullName)
                }
                [void](Invoke-DefenseClawStandaloneCreatedFolderRemoval -Layout @{ SelfUninstallReceiptPath = [IO.Path]::Combine($c.Life, ('self-uninstall-' + ('5' * 64) + '.json')) } -RecordDirectory $c.Records -Roots $c.Roots -SkipDeploymentCheck)
                if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $c.Codex) -or -not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $c.OpenAI)) {
                    $failures.Add('GAP-0704 review 3 S2: the purge removed the folder Setup adopted')
                }
                if ([IO.Directory]::Exists($c.Records)) {
                    $failures.Add('GAP-0704 review 3 S2: the purge left the record folder (the marker) behind')
                }

                # Review 3 L4: only the folders DefenseClaw touched are named.
                $c = & $r4New 'l4'
                $mdmCursor = [IO.Path]::Combine($c.Pd, 'Cursor')
                [void][IO.Directory]::CreateDirectory($mdmCursor)
                [IO.File]::WriteAllText([IO.Path]::Combine($mdmCursor, 'mdm-made.json'), '{}')
                [void][IO.Directory]::CreateDirectory([IO.Path]::Combine($c.Pf, 'Cisco', 'Cisco Secure Client'))
                $touched = @(Get-DefenseClawTouchedUnrecordedVendorFolders -RecordDirectory $c.Records -ProgramData $c.Pd -ProgramFiles $c.Pf)
                if (@($touched | Microsoft.PowerShell.Core\Where-Object { $_ -ceq $mdmCursor -or $_ -ceq [IO.Path]::Combine($c.Pf, 'Cisco') }).Count -ne 0 -or
                    @($touched | Microsoft.PowerShell.Core\Where-Object { $_ -ceq $c.Vendor }).Count -ne 1) {
                    $failures.Add("GAP-0704 review 3 L4: touched = '$($touched -join '; ')', want the ProgramData Cisco folder only (not a Cursor folder with another product's file, not a Cisco folder with Secure Client)")
                }
                [IO.File]::WriteAllText([IO.Path]::Combine($mdmCursor, '.defenseclaw-managed-runtime-selector.lock'), '')
                $touched = @(Get-DefenseClawTouchedUnrecordedVendorFolders -RecordDirectory $c.Records -ProgramData $c.Pd -ProgramFiles $c.Pf)
                if (@($touched | Microsoft.PowerShell.Core\Where-Object { $_ -ceq $mdmCursor }).Count -ne 1) {
                    $failures.Add('GAP-0704 review 3 L4: a Cursor folder holding a DefenseClaw file is not touched')
                }
                $unproven = @(Get-DefenseClawUnprovenVendorFolders -Touched $touched -RecordDirectory $c.Records)
                if ($unproven.Count -ne $touched.Count) {
                    $failures.Add("GAP-0704 review 3 L4: unproven = '$($unproven -join '; ')', want the touched folders: '$($touched -join '; ')'")
                }
                $null = Add-DefenseClawStandaloneCreatedFolderRecord -Path @($mdmCursor) -RecordDirectory $c.Records -Roots $c.Roots
                if (@(Get-DefenseClawUnprovenVendorFolders -Touched $touched -RecordDirectory $c.Records | Microsoft.PowerShell.Core\Where-Object { $_ -ceq $mdmCursor }).Count -ne 0) {
                    $failures.Add('GAP-0704 review 3 L4: a recorded folder is still named as not provably created')
                }

                # Review 3 L1: an error while reporting what an uninstall left
                # must not escape the lifecycle `finally`, and one folder's
                # failure loses no other.
                $reported = [Collections.Generic.List[string]]::new()
                $warnLog = [Collections.Generic.List[string]]::new()
                $reportThrew = ''
                & {
                    function Get-DefenseClawStandaloneCreatedFolderPreview { param($Layout, $RecordDirectory, $Roots) throw 'the record folder cannot be listed' }
                    function Get-DefenseClawUnprovenVendorFolders { param($Touched, $RecordDirectory) 'C:\one'; 'C:\two' }
                    function Add-DefenseClawCreatedFolderKept {
                        param($Folder, $Note)
                        if ($Folder -ceq 'C:\one') { throw 'the event could not be written' }
                        $reported.Add($Folder)
                    }
                    try {
                        Write-DefenseClawUninstallCreatedFolderReport -Layout @{ Marker = 1 } -Touched @('C:\one', 'C:\two') -LeftNothing $true -WarningVariable warned -WarningAction SilentlyContinue
                    }
                    catch {
                        $reportThrew = [string]$_.Exception.Message
                    }
                    foreach ($warning in @($warned)) {
                        $warnLog.Add([string]$warning)
                    }
                }
                # Review 4 L4: each failed step leaves a warning, not silence.
                if ($warnLog.Count -ne 2 -or -not $warnLog[0].Contains('preview not reported') -or -not $warnLog[1].Contains('unproven-folder note not written')) {
                    $failures.Add("GAP-0704 review 4 L4: want a warning for the preview and one for the first folder, got: $($warnLog -join ' | ')")
                }
                $warnLog.Clear()
                if ($reportThrew -ne '' -or $reported.Count -ne 1 -or $reported[0] -cne 'C:\two') {
                    $failures.Add("GAP-0704 review 3 L1: the uninstall report threw '$reportThrew' or lost the second folder: $($reported -join '; ')")
                }
                $reportThrew = ''
                & {
                    function Get-DefenseClawUnprovenVendorFolders { param($Touched, $RecordDirectory) throw 'the record folder cannot be listed' }
                    try {
                        Write-DefenseClawUninstallCreatedFolderReport -Layout @{ Marker = 1 } -Touched @('C:\one') -LeftNothing $true -WarningVariable warned -WarningAction SilentlyContinue
                    }
                    catch {
                        $reportThrew = [string]$_.Exception.Message
                    }
                    foreach ($warning in @($warned)) {
                        $warnLog.Add([string]$warning)
                    }
                }
                if ($reportThrew -ne '') {
                    $failures.Add("GAP-0704 review 3 L1: an unlistable record folder escaped the uninstall report: $reportThrew")
                }
                if ($warnLog.Count -ne 1 -or -not $warnLog[0].Contains('unproven vendor folders not reported')) {
                    $failures.Add("GAP-0704 review 4 L4: want one warning for the unlistable record folder, got: $($warnLog -join ' | ')")
                }

                # Review 4 S1: the one-shot marker is written only after a
                # back-fill that succeeded: every candidate recorded, or refused
                # by proof (a), (b) or (c), which is final. A record that could
                # not be written is retried by the next run. A rollback keeps the
                # marker (review 5 M1).
                $r5Marker = { param($c) [IO.File]::Exists([IO.Path]::Combine($c.Records, 'agent-folder-backfill.done')) }
                $r5Cursor = {
                    param($c)
                    $folder = [IO.Path]::Combine($c.Pd, 'Cursor')
                    & $agNew @($folder)
                    [IO.File]::WriteAllText([IO.Path]::Combine($folder, '.defenseclaw-managed-runtime-selector.lock'), '')
                    $folder
                }
                $r5Real = ${function:Write-DefenseClawCreatedFolderRecordFile}
                # A refusal for (a), (b) or (c) is final: the marker is written.
                foreach ($case in @(@('r5a', '(a) created before StateRoot'), @('r5b', '(b) another descriptor'), @('r5c', '(c) a foreign file'))) {
                    $c = & $r4New $case[0]
                    $cursorFolder = [IO.Path]::Combine($c.Pd, 'Cursor')
                    if ($case[0] -ceq 'r5a') {
                        & $agNew @($cursorFolder)
                        [IO.Directory]::SetCreationTimeUtc($cursorFolder, [IO.Directory]::GetCreationTimeUtc($c.State).AddMinutes(-5))
                    }
                    elseif ($case[0] -ceq 'r5b') {
                        [void][IO.Directory]::CreateDirectory($cursorFolder)
                    }
                    else {
                        & $agNew @($cursorFolder)
                        [IO.File]::WriteAllText([IO.Path]::Combine($cursorFolder, 'settings.json'), '{}')
                    }
                    & $r4Fill $c
                    if (-not (& $r5Marker $c)) {
                        $failures.Add("GAP-0704 review 4 S1: a folder refused by proof $($case[1]) is final, but the back-fill left no marker")
                    }
                    if (& $r4Has $c $cursorFolder) {
                        $failures.Add("GAP-0704 review 4 S1: the folder refused by proof $($case[1]) was recorded")
                    }
                }
                # A record that could not be written is not done: no marker,
                # the folders that were written stay recorded, and the next
                # run records the rest and writes the marker.
                $c = & $r4New 'r5d'
                $cursorFolder = & $r5Cursor $c
                & $r4Codex $c -Committed
                $failName = Get-DefenseClawCreatedFolderRecordName -Path $c.Codex
                & {
                    function Write-DefenseClawCreatedFolderRecordFile {
                        param([string]$Path, [byte[]]$Body)
                        if ($Path.EndsWith($failName, [StringComparison]::OrdinalIgnoreCase)) {
                            throw 'the disk is full'
                        }
                        & $r5Real -Path $Path -Body $Body
                    }
                    $fillArgs = $c.Args
                    Add-DefenseClawStandaloneUpgradeVendorFolderRecords @fillArgs
                }
                if (& $r5Marker $c) {
                    $failures.Add('GAP-0704 review 4 S1: a record write failed, but the back-fill wrote its marker')
                }
                if (-not (& $r4Has $c $cursorFolder) -or (& $r4Has $c $c.Codex)) {
                    $failures.Add('GAP-0704 review 4 S1: want the Cursor record written and the Codex record not, after one write failed')
                }
                & $r4Fill $c
                if (-not (& $r5Marker $c) -or -not (& $r4Has $c $c.Codex) -or -not (& $r4Has $c $c.OpenAI)) {
                    $failures.Add('GAP-0704 review 4 S1: the next run did not record the rest and write the marker')
                }
                # No record folder (the lifecycle folder is gone): nothing is
                # recorded, no marker, no error, and nothing is created.
                $c = & $r4New 'r5e'
                $null = & $r5Cursor $c
                [IO.File]::Delete([IO.Path]::Combine($c.Life, 'lifecycle.lock'))
                [IO.Directory]::Delete($c.Life, $false)
                $fillThrew = ''
                try {
                    & $r4Fill $c
                }
                catch {
                    $fillThrew = [string]$_.Exception.Message
                }
                if ($fillThrew -ne '' -or (& $r5Marker $c) -or [IO.Directory]::Exists($c.Life)) {
                    $failures.Add("GAP-0704 review 4 S1: with no lifecycle folder the back-fill threw '$fillThrew', wrote a marker or created the folder")
                }
                # The writer's result: success or failure.
                $c = & $r4New 'r5f'
                $cursorFolder = & $r5Cursor $c
                $other = [IO.Path]::Combine($c.Pd, 'OtherVendor')
                & $agNew @($other)
                $outside = [IO.Path]::Combine($r4Root, 'r5f-outside')
                [void][IO.Directory]::CreateDirectory($outside)
                $r5Want = {
                    param([string]$Name, $Got, [bool]$Want)
                    $list = @($Got)
                    if ($list.Count -ne 1 -or $list[0] -isnot [bool] -or [bool]$list[0] -ne $Want) {
                        $failures.Add("GAP-0704 review 4 S1: the record writer returned '$($list -join ',')' for $Name, want $Want")
                    }
                }
                & $r5Want 'a folder it recorded' (Add-DefenseClawStandaloneCreatedFolderRecord -Path @($cursorFolder) -RecordDirectory $c.Records -Roots $c.Roots -Origin upgrade) $true
                & $r5Want 'a folder already recorded' (Add-DefenseClawStandaloneCreatedFolderRecord -Path @($cursorFolder) -RecordDirectory $c.Records -Roots $c.Roots -Origin upgrade) $true
                & $r5Want 'no folder' (Add-DefenseClawStandaloneCreatedFolderRecord -Path @() -RecordDirectory $c.Records -Roots $c.Roots) $true
                & $r5Want 'a folder outside the roots' (Add-DefenseClawStandaloneCreatedFolderRecord -Path @($outside) -RecordDirectory $c.Records -Roots $c.Roots) $false
                & $r5Want 'a missing lifecycle folder' (Add-DefenseClawStandaloneCreatedFolderRecord -Path @($other) -RecordDirectory ([IO.Path]::Combine($c.Pd, 'no-lifecycle', 'created-folders')) -Roots $c.Roots) $false
                $failedWrite = & {
                    function Write-DefenseClawCreatedFolderRecordFile { param([string]$Path, [byte[]]$Body) throw 'the disk is full' }
                    Add-DefenseClawStandaloneCreatedFolderRecord -Path @($other) -RecordDirectory $c.Records -Roots $c.Roots
                }
                & $r5Want 'a failed write' $failedWrite $false
                if (& $r4Has $c $other) {
                    $failures.Add('GAP-0704 review 4 S1: a folder whose write failed has a record')
                }
                # A rollback keeps the marker (review 5 M1): it does not undo an
                # adoption, so a folder an administrator made and a later run
                # adopted (Setup stamps it with the same descriptor) must not be
                # recorded by a later back-fill.
                $c = & $r4New 'r5g'
                $cursorFolder = & $r5Cursor $c
                & $r4Fill $c
                if (-not (& $r5Marker $c) -or -not (& $r4Has $c $cursorFolder)) {
                    $failures.Add('GAP-0704 review 5 M1: the first run did not record Cursor and write the marker')
                }
                # The adopted folder: it passes (a), (b) and (c).
                & $r4Codex $c -Committed
                & $r4Fill $c
                if (-not (& $r5Marker $c) -or -not (& $r4Has $c $cursorFolder)) {
                    $failures.Add('GAP-0704 review 5 M1: a later back-fill removed the marker or a record')
                }
                if ((& $r4Has $c $c.Codex) -or (& $r4Has $c $c.OpenAI)) {
                    $failures.Add('GAP-0704 review 5 M1: a later back-fill recorded a folder adopted after the first one')
                }
                $gone = (-not (Get-Command Remove-DefenseClawAgentFolderBackfillMarker -ErrorAction SilentlyContinue))
                if (-not $gone) {
                    $failures.Add('GAP-0704 review 5 M1: Remove-DefenseClawAgentFolderBackfillMarker still exists')
                }

                # GAP-0758 review S2: the runtime selector purge neither tests,
                # opens, creates nor reads behind a link at its folder, and names
                # the folder.
                $s2 = [IO.Path]::Combine($ag, 'g0758s2')
                $s2Target = [IO.Path]::Combine($s2, 'target')
                $s2Link = [IO.Path]::Combine($s2, 'link')
                [void][IO.Directory]::CreateDirectory($s2Target)
                Set-G091AdministratorsOwner -Path @($s2, $s2Target)
                foreach ($name in @('.defenseclaw-managed-runtime-selector.state', '.defenseclaw-managed-hooks.state', '90-defenseclaw.json')) {
                    [IO.File]::WriteAllText([IO.Path]::Combine($s2Target, $name), "decoy $name")
                }
                $s2Listing = {
                    (@(Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $s2Target -Force | Microsoft.PowerShell.Utility\Sort-Object Name |
                        Microsoft.PowerShell.Core\ForEach-Object { $_.Name + '=' + [IO.File]::ReadAllText($_.FullName) })) -join '|'
                }
                $s2Before = & $s2Listing
                [void](Microsoft.PowerShell.Management\New-Item -ItemType Junction -Path $s2Link -Target $s2Target)
                $junctions.Add($s2Link)
                $s2Out = @(Remove-DefenseClawOwnRuntimeSelector -Directory $s2Link -OwnHook 'C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe')
                if (@($s2Out | Microsoft.PowerShell.Core\Where-Object { ([string]$_).StartsWith("${s2Link}: kept: a link sits here") }).Count -ne 1) {
                    $failures.Add("GAP-0758 review S2: the selector purge did not name the linked folder once: $($s2Out -join ' | ')")
                }
                if ((& $s2Listing) -cne $s2Before) {
                    $failures.Add("GAP-0758 review S2: the selector purge changed the folder behind the link: $(& $s2Listing)")
                }
                # A failure of the link check that is not a link keeps its own message
                # (GAP-0758 review L1): it is not labelled as a link, and a purge goes on.
                $l1Drive = @('Q', 'R', 'S', 'T', 'U') | Microsoft.PowerShell.Core\Where-Object { -not [IO.Directory]::Exists("${_}:\") } | Microsoft.PowerShell.Utility\Select-Object -First 1
                if ($null -ne $l1Drive) {
                    $l1Directory = "${l1Drive}:\no\such\folder"
                    $l1Out = @(Remove-DefenseClawOwnRuntimeSelector -Directory $l1Directory -OwnHook 'C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe')
                    if ($l1Out.Count -ne 1 -or -not ([string]$l1Out[0]).StartsWith("${l1Directory}: cannot resolve existing ancestor") -or ([string]$l1Out[0]) -match 'a link sits') {
                        $failures.Add("GAP-0758 review L1: the selector purge labelled a failure that is not a link: $($l1Out -join ' | ')")
                    }
                    $l1Threw = $false
                    try {
                        Remove-DefenseClawCommittedManagedHooksSerializationLocks -Layout @{ ClaudeManagedHooksLockPath = [IO.Path]::Combine($l1Directory, '.defenseclaw-managed-hooks.lock') }
                    }
                    catch {
                        $l1Threw = ([string]$_.Exception.Message) -match 'cannot resolve existing ancestor'
                    }
                    if (-not $l1Threw -or @(Get-DefenseClawCreatedFoldersKept).Count -ne 0) {
                        $failures.Add('GAP-0758 review L1: the committed lock removal kept a failure that is not a link as a kept link')
                    }
                    $script:DefenseClawCreatedFoldersKept.Clear()
                }
                # The committed-uninstall lock removal meets the same link: it
                # neither throws (a 1603 over a link) nor touches the lock behind it.
                $s2Lock = [IO.Path]::Combine($s2Target, '.defenseclaw-managed-hooks.lock')
                [IO.File]::WriteAllText($s2Lock, 'decoy lock')
                $s2LockBefore = & $s2Listing
                $script:DefenseClawCreatedFoldersKept.Clear()
                try {
                    Remove-DefenseClawCommittedManagedHooksSerializationLocks -Layout @{ ClaudeManagedHooksLockPath = [IO.Path]::Combine($s2Link, '.defenseclaw-managed-hooks.lock') }
                }
                catch {
                    $failures.Add("GAP-0758 review S2: the committed lock removal threw over a link: $($_.Exception.Message)")
                }
                if ((& $s2Listing) -cne $s2LockBefore) {
                    $failures.Add("GAP-0758 review S2: the committed lock removal changed the folder behind the link: $(& $s2Listing)")
                }
                if (@(Get-DefenseClawCreatedFoldersKept | Microsoft.PowerShell.Core\Where-Object { ([string]$_).StartsWith("${s2Link}: kept: a link sits on its path") }).Count -ne 1) {
                    $failures.Add("GAP-0758 review S2: the committed lock removal did not name the linked folder once: $((Get-DefenseClawCreatedFoldersKept) -join ' | ')")
                }
                $script:DefenseClawCreatedFoldersKept.Clear()

                # GAP-0773: a link at the Codex machine-policy folder. A purge step
                # that meets it writes a kept entry at the link, not "path: could not
                # remove" for a file behind it; the Codex folder link is found without
                # following it (standalone only); and the Codex removal report that
                # says the link was kept is accepted, not refused as unexplained.
                $g773 = [IO.Path]::Combine($ag, 'g0773')
                $g773Target = [IO.Path]::Combine($g773, 'target')
                $g773Link = [IO.Path]::Combine($g773, 'Codex')
                $g773Plain = [IO.Path]::Combine($g773, 'plain')
                [void][IO.Directory]::CreateDirectory($g773Target)
                [void][IO.Directory]::CreateDirectory($g773Plain)
                Set-G091AdministratorsOwner -Path @($g773, $g773Target, $g773Plain)
                foreach ($name in @('requirements.toml', '.defenseclaw-managed-hooks.state', '.defenseclaw-managed-hooks.writer.lock')) {
                    [IO.File]::WriteAllText([IO.Path]::Combine($g773Target, $name), "decoy $name")
                }
                $g773Listing = {
                    (@(Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $g773Target -Force | Microsoft.PowerShell.Utility\Sort-Object Name |
                        Microsoft.PowerShell.Core\ForEach-Object { $_.Name + '=' + [IO.File]::ReadAllText($_.FullName) })) -join '|'
                }
                $g773Before = & $g773Listing
                [void](Microsoft.PowerShell.Management\New-Item -ItemType Junction -Path $g773Link -Target $g773Target)
                $junctions.Add($g773Link)
                $keptEntry = "${g773Link}: kept: a link sits here; DefenseClaw does not follow, change or remove it"
                $g773Entry = Get-DefenseClawMachineStateFailureEntry -Path ([IO.Path]::Combine($g773Link, 'requirements.toml')) `
                    -Message "reparse points are not allowed in managed path: $g773Link"
                if ($g773Entry -cne $keptEntry) {
                    $failures.Add("GAP-0773: a link failure was not turned into a kept entry at the link: $g773Entry")
                }
                $g773Plain1 = Get-DefenseClawMachineStateFailureEntry -Path 'C:\x\y' -Message 'access denied'
                if ($g773Plain1 -cne 'C:\x\y: access denied') {
                    $failures.Add("GAP-0773: a plain failure lost its path and reason: $g773Plain1")
                }
                if ((Get-DefenseClawVendorMachineFolderLink -Directory $g773Link) -ne $g773Link) {
                    $failures.Add('GAP-0773: the Codex folder link was not found')
                }
                if ((Get-DefenseClawVendorMachineFolderLink -Directory ([IO.Path]::Combine($g773Link, 'sub'))) -ne $g773Link) {
                    $failures.Add('GAP-0773: a folder below the Codex link was not reported as behind the link')
                }
                if ((Get-DefenseClawVendorMachineFolderLink -Directory $g773Plain) -ne '' -or
                    (Get-DefenseClawVendorMachineFolderLink -Directory ([IO.Path]::Combine($g773Plain, 'absent'))) -ne '') {
                    $failures.Add('GAP-0773: a plain or absent Codex folder was reported as a link')
                }
                $g773SecureClient = 'unset'
                Set-DefenseClawEnterpriseProfile -EnterpriseProfile SecureClient
                try {
                    $g773SecureClient = Get-DefenseClawVendorMachineFolderLink -Directory $g773Link
                }
                finally {
                    Set-DefenseClawEnterpriseProfile -EnterpriseProfile Standalone
                }
                if ($g773SecureClient -cne '') {
                    $failures.Add("GAP-0773: Secure Client kept a Codex link: '$g773SecureClient'")
                }
                # The uninstall's removal reports a kept link as kept and not
                # verified (no safe_to_remove_binary), and only the uninstall
                # (-Teardown) accepts that report.
                $g773Report = [pscustomobject]@{
                    safe_to_remove_binary = $false; managed_state_existed = $false; managed_state_removed = $false
                    managed_state_removed_or_absent = $false; surviving_owned_path_references = 0; disposition = 'link_kept'
                    link_kept = $g773Link
                }
                try {
                    Complete-DefenseClawCodexRequirementsRemoval -Layout @{} -GatewayServiceName 'DefenseClawGateway' -Report $g773Report -Teardown
                }
                catch {
                    $failures.Add("GAP-0773: the uninstall's Codex removal that kept a link was refused: $($_.Exception.Message)")
                }
                $g773Refused = $false
                try { Complete-DefenseClawCodexRequirementsRemoval -Layout @{} -GatewayServiceName 'DefenseClawGateway' -Report $g773Report } catch { $g773Refused = $true }
                if (-not $g773Refused) {
                    $failures.Add('GAP-0773: a Codex removal that is not the uninstall''s accepted a kept link')
                }
                $g773Report.link_kept = ''
                $g773Refused = $false
                try { Complete-DefenseClawCodexRequirementsRemoval -Layout @{} -GatewayServiceName 'DefenseClawGateway' -Report $g773Report -Teardown } catch { $g773Refused = $true }
                if (-not $g773Refused) {
                    $failures.Add('GAP-0773: link_kept without a named link was accepted')
                }
                $g773Report.link_kept = $g773Link
                $g773Report.safe_to_remove_binary = $true
                $g773Report.managed_state_removed_or_absent = $true
                $g773Report.disposition = 'bogus'
                $g773Refused = $false
                try { Complete-DefenseClawCodexRequirementsRemoval -Layout @{} -GatewayServiceName 'DefenseClawGateway' -Report $g773Report -Teardown } catch { $g773Refused = $true }
                if (-not $g773Refused) {
                    $failures.Add('GAP-0773: an unexplained Codex removal disposition was accepted')
                }
                if ((& $g773Listing) -cne $g773Before) {
                    $failures.Add("GAP-0773: a step changed the folder behind the Codex link: $(& $g773Listing)")
                }

                # GAP-0773, review M1: the uninstall asks the installed gateway before it
                # passes --uninstall to "codex-requirements remove". A gateway older than
                # this build (1.0.3 has no capabilities command; 1.0.8 has one without the
                # field) defines only --json, answers "unknown flag" to --uninstall with no
                # JSON line, and gets the plain removal; a gateway that reports the field
                # gets --uninstall. Any other call to the gateway fails the row.
                & {
                    $m1Layout = @{
                        CodexMachinePolicyPath = 'C:\m1\requirements.toml'
                        CodexRequirementsOwnershipPath = 'C:\m1\ownership.json'
                        CodexManagedHooksStatePath = 'C:\m1\state'
                        CodexManagedHooksDirectory = 'C:\m1\managed'
                        HookPath = 'C:\m1\hook.exe'
                    }
                    function Assert-DefenseClawAdministrator { }
                    function Invoke-DefenseClawGatewayCommand {
                        param($Layout, $GatewayServiceName, [string[]]$Arguments, [switch]$Capture,
                            [switch]$AllowFailure, [int]$TimeoutSeconds)
                        $verb = ($Arguments -join ' ')
                        $script:M1Calls.Add($verb)
                        if ($verb -ceq 'enterprise windows teardown-managed-hooks capabilities --json') {
                            return [pscustomobject]@{ exit_code = $script:M1CapabilityCode; output = $script:M1CapabilityOutput }
                        }
                        $accepts = $verb -ceq 'enterprise windows codex-requirements remove --json --uninstall' -and $script:M1Gateway -ceq 'new'
                        if ($verb -ceq 'enterprise windows codex-requirements remove --json' -or $accepts) {
                            $report = [ordered]@{
                                schema_version = 2; action = 'remove'; ok = $true; disposition = 'ownership_absent'
                                requirements_path = $m1Layout.CodexMachinePolicyPath
                                ownership_path = $m1Layout.CodexRequirementsOwnershipPath
                                managed_state_path = $m1Layout.CodexManagedHooksStatePath
                                managed_dir = $m1Layout.CodexManagedHooksDirectory
                                hook_binary = $m1Layout.HookPath
                            }
                            return [pscustomobject]@{ exit_code = 0; output = @(($report | Microsoft.PowerShell.Utility\ConvertTo-Json -Compress)) }
                        }
                        return [pscustomobject]@{ exit_code = 1; output = @('Error: unknown flag: --uninstall') }
                    }
                    $script:M1Calls = [Collections.Generic.List[string]]::new()
                    $goodOld = '{"schema_version":4,"action":"capabilities","ok":true,"committed_standalone_prepare":true,"precommit_check":true}'
                    $goodNew = '{"schema_version":4,"action":"capabilities","ok":true,"committed_standalone_prepare":true,"precommit_check":true,"codex_requirements_uninstall":true}'
                    foreach ($case in @(
                        @{ name = '1.0.3: no capabilities command'; gateway = 'old'; code = 1; output = @('Error: unknown command "capabilities"'); flag = $false },
                        @{ name = '1.0.8: report without the field'; gateway = 'old'; code = 0; output = @($goodOld); flag = $false },
                        @{ name = 'field false'; gateway = 'old'; code = 0; output = @($goodNew.Replace('"codex_requirements_uninstall":true', '"codex_requirements_uninstall":false')); flag = $false },
                        @{ name = 'this build'; gateway = 'new'; code = 0; output = @($goodNew); flag = $true }
                    )) {
                        $script:M1Gateway = $case.gateway
                        $script:M1CapabilityCode = $case.code
                        $script:M1CapabilityOutput = $case.output
                        $script:M1Calls.Clear()
                        try {
                            [void](Invoke-DefenseClawCodexRequirementsCommand -Layout $m1Layout -GatewayServiceName DefenseClawGateway -Action remove -Teardown)
                        }
                        catch {
                            $failures.Add("GAP-0773 M1, $($case.name): the uninstall removal failed: $($_.Exception.Message)")
                            continue
                        }
                        $sent = @($script:M1Calls | Microsoft.PowerShell.Core\Where-Object { $_ -match 'codex-requirements' })
                        if ($sent.Count -ne 1 -or (($sent[0] -match '--uninstall') -ne $case.flag)) {
                            $failures.Add("GAP-0773 M1, $($case.name): --uninstall sent = $(($sent[0] -match '--uninstall')), want $($case.flag): $($sent -join ' | ')")
                        }
                    }
                    # A removal that is not the uninstall never sends the flag and does not ask the gateway.
                    $script:M1Gateway = 'new'; $script:M1CapabilityCode = 0; $script:M1CapabilityOutput = @($goodNew)
                    $script:M1Calls.Clear()
                    [void](Invoke-DefenseClawCodexRequirementsCommand -Layout $m1Layout -GatewayServiceName DefenseClawGateway -Action remove)
                    if (($script:M1Calls -join ' | ') -cne 'enterprise windows codex-requirements remove --json') {
                        $failures.Add("GAP-0773 M1: a removal that is not the uninstall called the gateway as: $($script:M1Calls -join ' | ')")
                    }
                }

                # GAP-0767: C:\ProgramData\ampcode. The 1.0.2 policy writer
                # created it empty, with the descriptor above and no marker; a
                # 1.0.9 upgrade back-fills it (origin upgrade) under the same three
                # proofs, in the same one-shot, and a purge then removes it. A
                # folder that fails a proof, or holds a foreign file, stays and is
                # named once.
                $am = [IO.Path]::Combine($ag, 'g0767')
                $amPd = [IO.Path]::Combine($am, 'ProgramData')
                $amPf = [IO.Path]::Combine($am, 'Program Files')
                $amVendor = [IO.Path]::Combine($amPd, 'Cisco')
                $amState = [IO.Path]::Combine($amVendor, 'DefenseClaw')
                $amLife = [IO.Path]::Combine($amVendor, 'DefenseClaw-Lifecycle')
                $amRecords = [IO.Path]::Combine($amLife, 'created-folders')
                $amDir = [IO.Path]::Combine($amPd, 'ampcode')
                $amArgs = @{ RecordDirectory = $amRecords; Roots = @($amPd, $amPf); StateRoot = $amState; ProgramData = $amPd; ProgramFiles = $amPf
                    ProgramDataVendorFolder = $amVendor; ProgramFilesVendorFolder = [IO.Path]::Combine($amPf, 'Cisco') }
                foreach ($folder in @($am, $amPd, $amPf, $amVendor, $amState)) {
                    [void][IO.Directory]::CreateDirectory($folder)
                }
                Set-G091AdministratorsOwner -Path @($am, $amPd, $amPf, $amVendor, $amState)
                [void]$native::CreateDirectorySecure($amLife, $adminOnly)
                [IO.File]::WriteAllText([IO.Path]::Combine($amLife, 'lifecycle.lock'), '')
                $amStateBorn = [IO.Directory]::GetCreationTimeUtc($amState)
                $amRecordFile = [IO.Path]::Combine($amRecords, (Get-DefenseClawCreatedFolderRecordName -Path $amDir))
                $amMarker = [IO.Path]::Combine($amRecords, 'agent-folder-backfill.done')
                $amFresh = {
                    # A computer that has not run the back-fill: no record, no marker.
                    foreach ($leftover in @($amRecordFile, $amMarker)) {
                        if ([IO.File]::Exists($leftover)) {
                            [IO.File]::Delete($leftover)
                        }
                    }
                    if ([IO.Directory]::Exists($amDir)) {
                        foreach ($entry in @(Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $amDir -Force)) {
                            [IO.File]::Delete($entry.FullName)
                        }
                        [IO.Directory]::Delete($amDir, $false)
                    }
                }
                # An empty folder in the 1.0.2 descriptor, born after StateRoot.
                & $amFresh
                [void]$native::CreateDirectorySecure($amDir, $agentSddl)
                Add-DefenseClawStandaloneUpgradeVendorFolderRecords @amArgs
                if (-not [IO.File]::Exists($amRecordFile)) {
                    $failures.Add('GAP-0767: an empty ampcode in the 1.0.2 descriptor, created after StateRoot, was not back-filled')
                }
                elseif (([IO.File]::ReadAllText($amRecordFile) | Microsoft.PowerShell.Utility\ConvertFrom-Json).origin -cne 'upgrade') {
                    $failures.Add('GAP-0767: the ampcode record is not origin:upgrade')
                }
                if (-not [IO.File]::Exists($amMarker)) {
                    $failures.Add('GAP-0767: the back-fill that judged ampcode left no one-shot marker')
                }
                # The purge removes it, and its record.
                if (-not [string]::IsNullOrEmpty((Remove-DefenseClawStandaloneCreatedFolder -Path $amDir -Roots @($amPd, $amPf))) -or [IO.Directory]::Exists($amDir)) {
                    $failures.Add('GAP-0767: a purge did not remove the back-filled empty ampcode')
                }
                # The one-shot: the marker is there, so a folder that appears
                # later is not judged.
                [void]$native::CreateDirectorySecure($amDir, $agentSddl)
                [IO.File]::Delete($amRecordFile)
                Add-DefenseClawStandaloneUpgradeVendorFolderRecords @amArgs
                if ([IO.File]::Exists($amRecordFile)) {
                    $failures.Add('GAP-0767: a second back-fill recorded ampcode')
                }
                # (a) born before StateRoot, (b) another descriptor, (c) a foreign file.
                & $amFresh
                [void]$native::CreateDirectorySecure($amDir, $agentSddl)
                [IO.Directory]::SetCreationTimeUtc($amDir, $amStateBorn.AddMinutes(-5))
                $amWhy = [string](Get-DefenseClawAgentFolderBackfillRefusal -Path $amDir -Kind Amp -StateRoot $amState -RecordDirectory $amRecords)
                if (-not $amWhy.Contains('before DefenseClaw')) {
                    $failures.Add("GAP-0767 (a): an ampcode born before StateRoot was not refused for it: '$amWhy'")
                }
                & $amFresh
                [void][IO.Directory]::CreateDirectory($amDir)
                $amWhy = [string](Get-DefenseClawAgentFolderBackfillRefusal -Path $amDir -Kind Amp -StateRoot $amState -RecordDirectory $amRecords)
                if ([string]::IsNullOrEmpty($amWhy)) {
                    $failures.Add('GAP-0767 (b): an ampcode with an inherited descriptor was not refused')
                }
                $amTouched = @(Get-DefenseClawTouchedUnrecordedVendorFolders -RecordDirectory $amRecords -ProgramData $amPd -ProgramFiles $amPf)
                if (@($amTouched | Microsoft.PowerShell.Core\Where-Object { $_ -ceq $amDir }).Count -ne 0) {
                    $failures.Add('GAP-0767: an ampcode without DefenseClaw descriptor was named as touched')
                }
                & $amFresh
                [void]$native::CreateDirectorySecure($amDir, $agentSddl)
                [IO.File]::WriteAllText([IO.Path]::Combine($amDir, 'managed-settings.json'), '{}')
                Add-DefenseClawStandaloneUpgradeVendorFolderRecords @amArgs
                if ([IO.File]::Exists($amRecordFile)) {
                    $failures.Add('GAP-0767 (c): an ampcode holding a foreign file was back-filled')
                }
                if (-not [IO.File]::Exists($amMarker)) {
                    $failures.Add('GAP-0767 (c): a refusal by a proof is final, so the back-fill is done and leaves the marker')
                }
                $amTouched = @(Get-DefenseClawTouchedUnrecordedVendorFolders -RecordDirectory $amRecords -ProgramData $amPd -ProgramFiles $amPf)
                $amUnproven = @(Get-DefenseClawUnprovenVendorFolders -Touched $amTouched -RecordDirectory $amRecords)
                if (@($amUnproven | Microsoft.PowerShell.Core\Where-Object { $_ -ceq $amDir }).Count -ne 1) {
                    $failures.Add("GAP-0767 (c): an ampcode holding a foreign file is not listed once as not provably created: $($amUnproven -join '; ')")
                }
                if (-not [string]::IsNullOrEmpty((Remove-DefenseClawStandaloneCreatedFolder -Path $amDir -Roots @($amPd, $amPf))) -eq $false) {
                    $failures.Add('GAP-0767 (c): removal of a folder holding a foreign file reported it gone')
                }
                if (-not [IO.File]::Exists([IO.Path]::Combine($amDir, 'managed-settings.json'))) {
                    $failures.Add('GAP-0767 (c): the foreign file in ampcode is gone')
                }
                & $amFresh

                # Rule (ii): Secure Client.
                $scCisco = [IO.Path]::Combine($ag, 'sc', 'ProgramData', 'Cisco')
                [void][IO.Directory]::CreateDirectory([IO.Path]::Combine($ag, 'sc', 'Program Files'))
                [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($scCisco))
                Set-G091AdministratorsOwner -Path @(([IO.Path]::Combine($ag, 'sc')), ([IO.Path]::GetDirectoryName($scCisco)), ([IO.Path]::Combine($ag, 'sc', 'Program Files')))
                [void]$native::CreateDirectorySecure($scCisco, $vendorThisFolder)
                [void][IO.Directory]::CreateDirectory([IO.Path]::Combine($scCisco, 'Cisco Secure Client'))
                [void][IO.Directory]::CreateDirectory([IO.Path]::Combine($scCisco, 'DefenseClaw'))
                $scWhy = [string](Get-DefenseClawVendorFolderBackfillRefusal -Path $scCisco)
                if (-not $scWhy.Contains('looks like Secure Client')) {
                    $failures.Add("GAP-0704 rule (ii): a Cisco folder holding Cisco Secure Client was not refused as Secure Client: '$scWhy'")
                }
                [IO.Directory]::Delete([IO.Path]::Combine($scCisco, 'DefenseClaw'), $false)
                $scRoots = @(([IO.Path]::Combine($ag, 'sc', 'ProgramData')), ([IO.Path]::Combine($ag, 'sc', 'Program Files')))
                if ([string]::IsNullOrEmpty((Remove-DefenseClawStandaloneCreatedFolder -Path $scCisco -Roots $scRoots)) -or
                    -not (Microsoft.PowerShell.Management\Test-Path -LiteralPath ([IO.Path]::Combine($scCisco, 'Cisco Secure Client')))) {
                    $failures.Add('GAP-0704 rule (ii): a recorded Cisco folder holding Cisco Secure Client was removed')
                }

                # Secure Client keeps no record and removes nothing.
                Set-DefenseClawEnterpriseProfile -EnterpriseProfile SecureClient
                $scLife = [IO.Path]::Combine($root, 'sc', 'Lifecycle')
                $scFolder = [IO.Path]::Combine($pd, 'SecureClientVendor')
                [void][IO.Directory]::CreateDirectory($scLife)
                [void][IO.Directory]::CreateDirectory($scFolder)
                $null = Add-DefenseClawStandaloneCreatedFolderRecord -Path @($scFolder) -RecordDirectory ([IO.Path]::Combine($scLife, 'created-folders')) -Roots $roots
                Remove-DefenseClawStandaloneCreatedFolders -Path @($scFolder) -Roots $roots
                Add-DefenseClawStandaloneUpgradeVendorFolderRecords -ProgramDataVendorFolder $scFolder -ProgramFilesVendorFolder $scFolder -RecordDirectory ([IO.Path]::Combine($scLife, 'created-folders')) -Roots $roots
                if ((Microsoft.PowerShell.Management\Test-Path -LiteralPath ([IO.Path]::Combine($scLife, 'created-folders'))) -or
                    -not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $scFolder)) {
                    $failures.Add('GAP-0091: the Secure Client profile recorded or removed a folder')
                }
            }
        }
        finally {
            foreach ($link in $junctions) {
                if ([IO.Directory]::Exists($link)) {
                    [IO.Directory]::Delete($link, $false)
                }
            }
            $script:DefenseClawCreatedFolderLogToLifecycleLog = $false
            $script:DefenseClawCreatedFoldersKept.Clear()
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

        # GAP-0900: Install, Upgrade and Repair refuse a link on the path of the
        # Codex, Cursor or Claude Code machine folder before they change anything,
        # with the one link check the uninstall uses, and name each link with the
        # command that removes it. Secure Client keeps its behaviour.
        $savedProgramFiles = $script:ProgramFiles
        $savedProgramData = $script:ProgramData
        $savedProfile = Get-DefenseClawEnterpriseProfile
        $g900Links = [Collections.Generic.List[string]]::new()
        Set-DefenseClawEnterpriseProfile -EnterpriseProfile Standalone
        try {
            $script:ProgramFiles = Microsoft.PowerShell.Management\Join-Path $Scratch 'PF900'
            $script:ProgramData = Microsoft.PowerShell.Management\Join-Path $Scratch 'PD900'
            $g900Target = [IO.Path]::Combine($script:ProgramData, 'decoys')
            [void][IO.Directory]::CreateDirectory($g900Target)
            [IO.File]::WriteAllText([IO.Path]::Combine($g900Target, 'decoy.txt'), 'decoy behind a link')
            $g900Layout = @{ CodexMachinePolicyDirectory = [IO.Path]::Combine($script:ProgramData, 'OpenAI', 'Codex') }
            $g900Cursor = [IO.Path]::Combine($script:ProgramData, 'Cursor')
            $g900Openai = [IO.Path]::Combine($script:ProgramData, 'OpenAI')
            $g900Claude = [IO.Path]::Combine($script:ProgramFiles, 'ClaudeCode')
            $g900Refuses = {
                param([string]$Action)
                try {
                    Assert-DefenseClawVendorMachineFoldersNotLinked -Layout $g900Layout -Action $Action
                    return ''
                }
                catch {
                    return [string]$_.Exception.Message
                }
            }
            # No folder at all, and plain folders, are not refused.
            if (& $g900Refuses 'Repair') {
                $failures.Add('GAP-0900: absent machine folders were refused')
            }
            foreach ($plain in @([IO.Path]::Combine($g900Layout.CodexMachinePolicyDirectory), $g900Cursor, [IO.Path]::Combine($g900Claude, 'managed-settings.d'))) {
                [void][IO.Directory]::CreateDirectory($plain)
            }
            if (& $g900Refuses 'Repair') {
                $failures.Add('GAP-0900: plain machine folders were refused')
            }
            foreach ($case in @(
                    @('Cursor folder', $g900Cursor, 'Cursor'),
                    @('Claude Code folder above managed-settings.d', $g900Claude, 'Claude Code'),
                    @('OpenAI folder above Codex', $g900Openai, 'Codex'))) {
                $link = [string]$case[1]
                [IO.Directory]::Delete($link, $true)
                [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($link))
                [void](Microsoft.PowerShell.Management\New-Item -ItemType Junction -Path $link -Target $g900Target)
                $g900Links.Add($link)
                foreach ($action in @('Install', 'Upgrade', 'Repair')) {
                    $message = & $g900Refuses $action
                    $fix = 'cmd /c rmdir "' + $link + '"'
                    if (-not $message.StartsWith("$action stopped before it changed anything") -or
                        -not $message.Contains($case[2] + ': ' + $link) -or
                        -not $message.Contains($fix)) {
                    $failures.Add("GAP-0900: $action over a link at the $($case[0]) was not refused with the link and its fix: '$message'")
                    }
                }
                if ([IO.File]::ReadAllText([IO.Path]::Combine($g900Target, 'decoy.txt')) -cne 'decoy behind a link' -or
                    @(Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $g900Target -Force).Count -ne 1) {
                    $failures.Add("GAP-0900: the folder behind the $($case[0]) link was changed")
                }
                # Secure Client keeps its behaviour: nothing is refused here.
                Set-DefenseClawEnterpriseProfile -EnterpriseProfile SecureClient
                try {
                    if (& $g900Refuses 'Repair') {
                        $failures.Add("GAP-0900: Secure Client refused a link at the $($case[0])")
                    }
                    if ((Get-DefenseClawVendorMachineFolderLink -Directory $link) -cne '') {
                        $failures.Add("GAP-0900: Secure Client found a link at the $($case[0])")
                    }
                }
                finally {
                    Set-DefenseClawEnterpriseProfile -EnterpriseProfile Standalone
                }
                [IO.Directory]::Delete($link, $false)
                $g900Links.Remove($link) | Out-Null
                [void][IO.Directory]::CreateDirectory($link)
                if (& $g900Refuses 'Repair') {
                    $failures.Add("GAP-0900: the $($case[0]) was still refused after its link was removed")
                }
            }
            # Two links at once are both named, so one run of the fix removes both.
            foreach ($link in @($g900Cursor, $g900Claude)) {
                [IO.Directory]::Delete($link, $true)
                [void](Microsoft.PowerShell.Management\New-Item -ItemType Junction -Path $link -Target $g900Target)
                $g900Links.Add($link)
            }
            $both = & $g900Refuses 'Repair'
            if (-not $both.Contains('Cursor: ' + $g900Cursor) -or -not $both.Contains('Claude Code: ' + $g900Claude)) {
                $failures.Add("GAP-0900: two links were not both named: '$both'")
            }
        }
        finally {
            foreach ($link in $g900Links) {
                if ([IO.Directory]::Exists($link)) {
                    [IO.Directory]::Delete($link, $false)
                }
            }
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
