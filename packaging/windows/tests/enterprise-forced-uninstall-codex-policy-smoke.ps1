# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 5.1

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$WarningPreference = 'SilentlyContinue'

# The standalone forced uninstall (Setup /uninstall FORCE=1) puts the
# administrator's Codex requirements.toml back from the ownership record in
# the StateRoot it moved aside before that folder goes, and keeps the folder
# when it cannot (GAP-0028). It removes DefenseClaw's Codex state and lock
# with Remove-DefenseClawNuclearPath, which never follows a link or junction
# at the path or in any folder above it. The functions run from the real
# module against throwaway ProgramFiles and ProgramData folders; native
# helpers are stand-ins, so the run needs neither elevation nor a DefenseClaw
# install. Junctions need Windows.
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    Microsoft.PowerShell.Utility\Write-Output 'SKIP enterprise-forced-uninstall-codex-policy-smoke: junctions need Windows'
    return
}

$modulePath = [IO.Path]::GetFullPath((
    Microsoft.PowerShell.Management\Join-Path `
        $PSScriptRoot '..\DefenseClawEnterprise.psm1'
))
$tokens = $null
$parseErrors = $null
$moduleAst = [Management.Automation.Language.Parser]::ParseFile(
    $modulePath,
    [ref]$tokens,
    [ref]$parseErrors
)
if ($parseErrors.Count -ne 0) {
    throw "module parser errors: $($parseErrors.Message -join '; ')"
}
foreach ($name in @(
    'Test-DefenseClawPathPresentNoFollow',
    'Remove-DefenseClawNoFollowTree',
    'Assert-DefenseClawNuclearPathNoLink',
    'Reset-DefenseClawNuclearEntryAccess',
    'Remove-DefenseClawNuclearPath',
    'Test-DefenseClawNuclearPathWithin',
    'Get-DefenseClawNuclearSHA256',
    'Read-DefenseClawNuclearFileBytes',
    'Read-DefenseClawNuclearRecord',
    'Get-DefenseClawNuclearRecordField',
    'Write-DefenseClawNuclearFileContent',
    'Get-DefenseClawNuclearConnectorOwner',
    'Invoke-DefenseClawNuclearCodexRequirements',
    'Restore-DefenseClawForcedUninstallCodexPolicy',
    'Complete-DefenseClawForcedUninstall'
)) {
    $functionAst = @($moduleAst.FindAll(
        {
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq $name
        },
        $true
    ))
    if ($functionAst.Count -ne 1) {
        throw "expected exactly one $name in the module"
    }
    . ([scriptblock]::Create($functionAst[0].Extent.Text))
}

# The native folder pin opens without following and refuses a link; this
# stand-in refuses the same way so the walk runs unelevated.
if (-not ('DefenseClawForcedUninstallSmokePin' -as [type])) {
    Microsoft.PowerShell.Utility\Add-Type -TypeDefinition @"
public static class DefenseClawForcedUninstallSmokePin {
    public static System.IntPtr OpenDirectoryPinNoFollow(string path) {
        var attributes = System.IO.File.GetAttributes(path);
        if ((attributes & System.IO.FileAttributes.ReparsePoint) != 0 ||
            (attributes & System.IO.FileAttributes.Directory) == 0)
            throw new System.InvalidOperationException("refusing a link, junction or non-folder: " + path);
        return new System.IntPtr(1);
    }
    public static void CloseDirectoryPin(System.IntPtr handle) {}
}
"@
}
function Initialize-DefenseClawNativeSecurity { return [DefenseClawForcedUninstallSmokePin] }
$script:execCalls = [Collections.Generic.List[string]]::new()
function Invoke-DefenseClawNuclearSilentExec {
    param([string]$File, [string[]]$Arguments = @())
    $script:execCalls.Add(([IO.Path]::GetFileName($File) + ' ' + ($Arguments -join ' ')))
}
function Test-DefenseClawNuclearTrustedOwner {
    param([string]$Path)
    return $true
}
function Assert-DefenseClawNuclearRecordTrusted {
    param([string]$Path)
}
$script:removedTrees = [Collections.Generic.List[string]]::new()
function Remove-DefenseClawManagedTree {
    param([string]$Path, [string]$RequiredBase, [string]$Label)
    $script:removedTrees.Add($Path)
    Microsoft.PowerShell.Management\Remove-Item -LiteralPath $Path -Recurse -Force
}
function ConvertTo-DefenseClawBoundedDiagnostic {
    param($Value, [int]$MaxLength = 512)
    return (@($Value) -join ' ')
}

$script:tmp = [IO.Path]::GetFullPath((
    Microsoft.PowerShell.Management\Join-Path `
        ([IO.Path]::GetTempPath()) `
        ('dc-forced-uninstall-smoke-' + [Guid]::NewGuid().ToString('N'))
))
$script:ProgramFiles = [IO.Path]::Combine($script:tmp, 'PF')
$script:ProgramData = [IO.Path]::Combine($script:tmp, 'PD')
$script:System32 = [IO.Path]::Combine($env:windir, 'System32')
$script:IcaclsExe = [IO.Path]::Combine($script:System32, 'icacls.exe')
$script:DefenseClawEnterpriseProfile = 'Standalone'
$script:junctions = [Collections.Generic.List[string]]::new()

function New-SmokeFile {
    param([string]$Path, [string]$Text = 'x')
    [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($Path))
    [IO.File]::WriteAllText($Path, $Text)
}
function New-SmokeJunction {
    param([string]$Path, [string]$Target)
    [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($Path))
    [void][IO.Directory]::CreateDirectory($Target)
    [void](Microsoft.PowerShell.Management\New-Item -ItemType Junction -Path $Path -Target $Target)
    $script:junctions.Add($Path)
}
function Reset-SmokeTree {
    # Links go first, as links only, so the cleanup never reaches through one.
    foreach ($junction in @($script:junctions)) {
        if ([IO.Directory]::Exists($junction) -or
            (Test-DefenseClawPathPresentNoFollow -Path $junction)) {
            [IO.Directory]::Delete($junction, $false)
        }
    }
    $script:junctions.Clear()
    if ([IO.Directory]::Exists($script:tmp)) {
        Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $script:tmp -Recurse -Force |
            Microsoft.PowerShell.Core\ForEach-Object { $_.Attributes = [IO.FileAttributes]::Normal }
        Microsoft.PowerShell.Management\Remove-Item -LiteralPath $script:tmp -Recurse -Force
    }
    [void][IO.Directory]::CreateDirectory($script:tmp)
    $script:execCalls.Clear()
}
function Write-SmokeJson {
    param([string]$Path, $Value)
    New-SmokeFile -Path $Path -Text ($Value | Microsoft.PowerShell.Utility\ConvertTo-Json -Depth 6 -Compress)
}
function Get-SmokeBytes {
    param([string]$Path)
    return ,[IO.File]::ReadAllBytes($Path)
}
function Test-SmokeSameBytes {
    param([string]$Path, [byte[]]$Expected)
    if (-not [IO.File]::Exists($Path)) {
        return $false
    }
    return (Get-DefenseClawNuclearSHA256 -Bytes (Get-SmokeBytes -Path $Path)) -ceq (Get-DefenseClawNuclearSHA256 -Bytes $Expected)
}
function Assert-Smoke {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) {
        throw "forced uninstall smoke: $Message"
    }
}

try {
    # Path checks, read without following any component.
    Reset-SmokeTree
    $real = [IO.Path]::Combine($script:tmp, 'real', 'child')
    [void][IO.Directory]::CreateDirectory($real)
    $linkParent = [IO.Path]::Combine($script:tmp, 'linked')
    New-SmokeJunction -Path $linkParent -Target ([IO.Path]::Combine($script:tmp, 'real'))
    $dangling = [IO.Path]::Combine($script:tmp, 'dangling')
    New-SmokeJunction -Path $dangling -Target ([IO.Path]::Combine($script:tmp, 'gone'))
    [IO.Directory]::Delete([IO.Path]::Combine($script:tmp, 'gone'), $false)
    foreach ($case in @(
        @{ Path = $real; Refused = $false },
        @{ Path = [IO.Path]::Combine($script:tmp, 'missing', 'leaf'); Refused = $false },
        @{ Path = [IO.Path]::Combine($linkParent, 'child'); Refused = $true },
        @{ Path = $linkParent; Refused = $true },
        @{ Path = $dangling; Refused = $true },
        @{ Path = [IO.Path]::Combine($dangling, 'below'); Refused = $true }
    )) {
        $refused = $false
        try {
            Assert-DefenseClawNuclearPathNoLink -Path $case.Path
        }
        catch {
            $refused = $true
        }
        Assert-Smoke ($refused -eq $case.Refused) "path check for $($case.Path): refused=$refused, want $($case.Refused)"
    }

    # GAP-0028: a standalone forced uninstall. The managed-hook teardown did
    # not run, so requirements.toml is still DefenseClaw's postimage for the
    # standalone hook, and the administrator's original is only in the
    # ownership record in the StateRoot the preparation moved aside.
    $codexDir = [IO.Path]::Combine($script:ProgramData, 'OpenAI', 'Codex')
    $codexPolicy = [IO.Path]::Combine($codexDir, 'requirements.toml')
    $codexState = [IO.Path]::Combine($codexDir, '.defenseclaw-managed-hooks.state')
    $codexLockPath = [IO.Path]::Combine($codexDir, '.defenseclaw-managed-hooks.lock')
    $adminCodex = [Text.Encoding]::UTF8.GetBytes("approval_policy = `"never`"`n")
    $postimage = [Text.Encoding]::UTF8.GetBytes("approval_policy = `"never`"`n[hooks]`nmanaged = true`n")
    $standaloneRoot = [IO.Path]::Combine($script:ProgramFiles, 'Cisco', 'DefenseClaw')
    $standaloneHook = [IO.Path]::Combine($standaloneRoot, 'bin', 'defenseclaw-hook.exe')
    $otherHook = [IO.Path]::Combine($script:ProgramFiles, 'Other', 'bin', 'defenseclaw-hook.exe')
    $standaloneState = [IO.Path]::Combine($script:ProgramData, 'Cisco', 'DefenseClaw')
    $forcedLayout = @{ InstallRoot = $standaloneRoot; StateRoot = $standaloneState }
    $moved = $standaloneState + '.forced-uninstall-20261019T000000Z'
    $movedOwnership = [IO.Path]::Combine($moved, 'install', 'codex-requirements-ownership.json')
    $forcedOwnership = [ordered]@{
        schema_version = 1
        requirements_path = $codexPolicy
        hook_binary = $standaloneHook
        preimage_existed = $true
        preimage = [Convert]::ToBase64String($adminCodex)
        preimage_sha256 = (Get-DefenseClawNuclearSHA256 -Bytes $adminCodex)
        postimage_sha256 = (Get-DefenseClawNuclearSHA256 -Bytes $postimage)
    }
    $newForcedCase = {
        param([byte[]]$Policy)
        Reset-SmokeTree
        $script:removedTrees.Clear()
        New-SmokeFile -Path $codexPolicy -Text ([Text.Encoding]::UTF8.GetString($Policy))
        Write-SmokeJson -Path $codexState -Value @{ schema_version = 1; hook_executable = $standaloneHook }
        New-SmokeFile -Path $codexLockPath -Text ''
        Write-SmokeJson -Path $movedOwnership -Value $forcedOwnership
    }
    & $newForcedCase $postimage
    $result = Complete-DefenseClawForcedUninstall -Result ([pscustomobject]@{ ok = $true }) `
        -MovedStateRoot $moved -MovedInstallReceipt '' -Layout $forcedLayout
    Assert-Smoke (Test-SmokeSameBytes -Path $codexPolicy -Expected $adminCodex) 'the forced uninstall did not put the administrator''s Codex requirements.toml back'
    Assert-Smoke (-not [IO.File]::Exists($codexState) -and -not [IO.File]::Exists($codexLockPath)) 'the forced uninstall left DefenseClaw''s Codex state beside the restored policy'
    Assert-Smoke ($script:removedTrees -contains $moved -and $null -eq $result.PSObject.Properties['forced_state_root_kept']) 'the forced uninstall kept a StateRoot nothing needs'
    Assert-Smoke ([bool]$result.forced) 'the forced uninstall result is not marked forced'

    # The file changed after DefenseClaw wrote it: it stays as found, and so
    # does the moved StateRoot with the only copy of the original.
    $edited = [Text.Encoding]::UTF8.GetBytes("approval_policy = `"on-request`"`n[hooks]`nmanaged = true`n")
    & $newForcedCase $edited
    $result = Complete-DefenseClawForcedUninstall -Result ([pscustomobject]@{ ok = $true }) `
        -MovedStateRoot $moved -MovedInstallReceipt '' -Layout $forcedLayout
    Assert-Smoke (Test-SmokeSameBytes -Path $codexPolicy -Expected $edited) 'the forced uninstall changed a Codex policy edited after install'
    Assert-Smoke ([IO.File]::Exists($movedOwnership) -and $script:removedTrees.Count -eq 0) 'the forced uninstall deleted the only copy of the administrator''s Codex original'
    Assert-Smoke ([string]$result.forced_state_root_kept -like "$moved*codex-requirements-ownership.json*") "the kept StateRoot is not named: $($result.forced_state_root_kept)"

    # A Codex state for another hook: not this deployment's to restore.
    & $newForcedCase $postimage
    Write-SmokeJson -Path $codexState -Value @{ schema_version = 1; hook_executable = $otherHook }
    $result = Complete-DefenseClawForcedUninstall -Result ([pscustomobject]@{ ok = $true }) `
        -MovedStateRoot $moved -MovedInstallReceipt '' -Layout $forcedLayout
    Assert-Smoke ((Test-SmokeSameBytes -Path $codexPolicy -Expected $postimage) -and [IO.File]::Exists($movedOwnership)) 'the forced uninstall restored a Codex policy another deployment owns'

    # A junction above the Codex policy folder: the state behind it stays.
    & $newForcedCase $postimage
    $elsewhere = [IO.Path]::Combine($script:tmp, 'agent-elsewhere')
    New-SmokeFile -Path ([IO.Path]::Combine($elsewhere, 'Codex', '.defenseclaw-managed-hooks.lock')) -Text ''
    $remaining = [Collections.Generic.List[string]]::new()
    $linkedLock = [IO.Path]::Combine($script:ProgramData, 'Linked', 'Codex', '.defenseclaw-managed-hooks.lock')
    New-SmokeJunction -Path ([IO.Path]::Combine($script:ProgramData, 'Linked')) -Target $elsewhere
    Assert-Smoke (-not (Remove-DefenseClawNuclearPath -Path $linkedLock -Remaining $remaining)) 'a path below a junction was reported removed'
    Assert-Smoke ([IO.File]::Exists([IO.Path]::Combine($elsewhere, 'Codex', '.defenseclaw-managed-hooks.lock'))) 'a junction above the Codex folder redirected the removal'
    Assert-Smoke (@($remaining | Microsoft.PowerShell.Core\Where-Object { $_ -like '*reparse points are not allowed*' }).Count -eq 1) "the refused link is not named: $($remaining -join ' | ')"

    # No Codex record: the moved StateRoot goes as before.
    Reset-SmokeTree
    $script:removedTrees.Clear()
    New-SmokeFile -Path ([IO.Path]::Combine($moved, 'audit.db')) -Text 'x'
    $result = Complete-DefenseClawForcedUninstall -Result ([pscustomobject]@{ ok = $true }) `
        -MovedStateRoot $moved -MovedInstallReceipt '' -Layout $forcedLayout
    Assert-Smoke ($script:removedTrees -contains $moved -and -not [IO.Directory]::Exists($moved)) 'the forced uninstall kept a StateRoot without a Codex record'

    Microsoft.PowerShell.Utility\Write-Output 'PASS enterprise-forced-uninstall-codex-policy-smoke'
}
finally {
    foreach ($junction in @($script:junctions)) {
        try { [IO.Directory]::Delete($junction, $false) } catch { }
    }
    if ([IO.Directory]::Exists($script:tmp)) {
        Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $script:tmp -Recurse -Force -ErrorAction SilentlyContinue |
            Microsoft.PowerShell.Core\ForEach-Object { $_.Attributes = [IO.FileAttributes]::Normal }
        Microsoft.PowerShell.Management\Remove-Item -LiteralPath $script:tmp -Recurse -Force -ErrorAction SilentlyContinue
    }
}
