# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 5.1

# The nuclear purge lists every enrolled user's DefenseClaw data folder before
# it tears anything down. Users come from the target manifest's data_dir rows
# (in the exact form the Go enumerator's YAML marshaller writes) and, because
# those rows are optional and the manifest can be gone, also from registered
# interactive profiles whose .defenseclaw holds managed-runtime evidence. An
# unmanaged per-user .defenseclaw, a reparse point (also when a manifest row
# names it), a non-interactive profile
# and a folder outside every registered profile are never listed. The helpers
# are loaded from the module by AST and the profile list is replaced, so the
# smoke also runs under pwsh off Windows.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modulePath = [IO.Path]::GetFullPath(
    [IO.Path]::Combine($PSScriptRoot, '..', 'DefenseClawEnterprise.psm1')
)
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($modulePath, [ref]$null, [ref]$parseErrors)
if (@($parseErrors).Count -ne 0) {
    throw "module does not parse: $(@($parseErrors)[0])"
}
foreach ($name in @(
        'Test-DefenseClawNuclearRealDirectoryPath',
        'Test-DefenseClawNuclearManagedUserDataFolder',
        'Get-DefenseClawNuclearUserDataPaths'
    )) {
    $definition = $ast.Find({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
        }, $true)
    if ($null -eq $definition) {
        throw "module does not define $name"
    }
    . ([scriptblock]::Create($definition.Extent.Text))
}
if ($null -eq $ast.Find({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -eq 'Get-DefenseClawNuclearRegisteredProfiles'
        }, $true)) {
    throw 'module does not define Get-DefenseClawNuclearRegisteredProfiles'
}

# The purge refuses a path with a linked ancestor, and macOS keeps the temp
# folder under /var (a link to /private/var), so build the fixture on the
# real path. Windows PowerShell has no link resolver and needs none here.
function Resolve-SmokeRealDirectory([string]$Path) {
    $current = [IO.Path]::GetFullPath($Path)
    for ($round = 0; $round -lt 16; $round++) {
        $linked = $null
        $probe = $current
        while (-not [string]::IsNullOrEmpty($probe)) {
            if (([IO.File]::GetAttributes($probe) -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                $linked = $probe
                break
            }
            $probe = [IO.Path]::GetDirectoryName($probe)
        }
        if ($null -eq $linked) {
            return $current
        }
        $target = [IO.Directory]::ResolveLinkTarget($linked, $true)
        $current = [IO.Path]::GetFullPath([IO.Path]::Combine(
            $target.FullName,
            [IO.Path]::GetRelativePath($linked, $current)
        ))
    }
    return $current
}

$root = [IO.Path]::Combine((Resolve-SmokeRealDirectory ([IO.Path]::GetTempPath())), "dc-nuclear-users-smoke-$([Guid]::NewGuid().ToString('N'))")
$users = [IO.Path]::Combine($root, 'Users')
$stateRoot = [IO.Path]::Combine($root, 'DefenseClaw')
$manifestDirectory = [IO.Path]::Combine($stateRoot, 'hook-guardian')
$manifestPath = [IO.Path]::Combine($manifestDirectory, 'targets.yaml')
[void][IO.Directory]::CreateDirectory($manifestDirectory)

function New-SmokeHome([string]$Name) {
    $userHome = [IO.Path]::Combine($script:users, $Name)
    [void][IO.Directory]::CreateDirectory($userHome)
    return $userHome
}
function New-SmokeDataDir([string]$UserHome) {
    $dataDir = [IO.Path]::Combine($UserHome, '.defenseclaw')
    [void][IO.Directory]::CreateDirectory([IO.Path]::Combine($dataDir, 'hooks'))
    return $dataDir
}

$generation = 'a' * 64
# alice: listed by the manifest only; nothing in her folder proves management.
$alice = New-SmokeHome 'alice'
$aliceData = New-SmokeDataDir $alice
# bob: absent from the manifest; holds an immutable managed runtime generation
# and a Setup staging folder.
$bob = New-SmokeHome 'bob'
$bobData = New-SmokeDataDir $bob
[IO.File]::WriteAllText([IO.Path]::Combine($bobData, 'hooks', ".managed-runtime-cursor-$generation.json"), '{}')
$bobStaging = [IO.Path]::Combine($bob, ".defenseclaw.setup-$('b' * 32)")
[void][IO.Directory]::CreateDirectory($bobStaging)
[void][IO.Directory]::CreateDirectory([IO.Path]::Combine($bob, '.defenseclaw.setup-not-ours'))
# carol: absent from the manifest; holds a hook contract bound to a managed
# gateway service.
$carol = New-SmokeHome 'carol'
$carolData = New-SmokeDataDir $carol
[IO.File]::WriteAllText(
    [IO.Path]::Combine($carolData, 'hook_contract_lock.json'),
    '{"connectors":{"codex":{"connector":"codex","managed_gateway_service_name":"DefenseClawGateway","updated_at":"2026-10-01T00:00:00Z"}}}'
)
# dave: an unmanaged per-user DefenseClaw install. Its runtime looks alike but
# carries no managed evidence, so the managed purge leaves it alone.
$dave = New-SmokeHome 'dave'
$daveData = New-SmokeDataDir $dave
[IO.File]::WriteAllText([IO.Path]::Combine($daveData, 'hooks', '.token'), 'token')
[IO.File]::WriteAllText([IO.Path]::Combine($daveData, 'hooks', '.managed-runtime-unknown.json'), '{}')
[IO.File]::WriteAllText(
    [IO.Path]::Combine($daveData, 'hook_contract_lock.json'),
    '{"connectors":{"codex":{"connector":"codex","updated_at":"2026-10-01T00:00:00Z"}}}'
)
# svc: a non-interactive profile with managed evidence is never swept.
$svc = New-SmokeHome 'svc'
$svcData = New-SmokeDataDir $svc
[IO.File]::WriteAllText([IO.Path]::Combine($svcData, 'hooks', ".managed-runtime-codex-$generation.json"), '{}')
# erin: her .defenseclaw is a link to bob's managed folder.
$erin = New-SmokeHome 'erin'
$erinData = [IO.Path]::Combine($erin, '.defenseclaw')
$erinLinked = $false
try {
    [void](Microsoft.PowerShell.Management\New-Item -ItemType SymbolicLink -Path $erinData -Target $bobData -ErrorAction Stop)
    $erinLinked = $true
}
catch {
    Microsoft.PowerShell.Utility\Write-Host "symbolic link creation is unavailable; the reparse case is skipped: $($_.Exception.Message)"
}
# outsider: a manifest row whose home is not a registered profile.
$outsider = [IO.Path]::Combine($root, 'Elsewhere', 'outsider')
$outsiderData = New-SmokeDataDir $outsider

$script:registeredProfiles = @(
    [pscustomobject]@{ sid = 'S-1-5-21-1000-2000-3000-1001'; home = $alice }
    [pscustomobject]@{ sid = 'S-1-5-21-1000-2000-3000-1002'; home = $bob }
    [pscustomobject]@{ sid = 'S-1-12-1-1111111111-2222222222-3333333333-4000000000'; home = $carol }
    [pscustomobject]@{ sid = 'S-1-5-21-1000-2000-3000-1004'; home = $dave }
    [pscustomobject]@{ sid = 'S-1-5-18'; home = $svc }
    [pscustomobject]@{ sid = 'S-1-5-21-1000-2000-3000-1005'; home = $erin }
)
function Get-DefenseClawNuclearRegisteredProfiles {
    return $script:registeredProfiles
}

function Assert-Paths([string]$Label, [string[]]$Expected) {
    $actual = @(Get-DefenseClawNuclearUserDataPaths -StateRoot $script:stateRoot)
    $missing = @($Expected | Microsoft.PowerShell.Core\Where-Object { $actual -notcontains $_ })
    $extra = @($actual | Microsoft.PowerShell.Core\Where-Object { $Expected -notcontains $_ })
    if ($missing.Count -ne 0 -or $extra.Count -ne 0 -or $actual.Count -ne $Expected.Count) {
        throw "${Label}: missing [$($missing -join ', ')] extra [$($extra -join ', ')]"
    }
}

try {
    # The plain-scalar form the Go enumerator's yaml.v3 marshaller writes.
    $goYaml = @"
version: 1
targets:
    - user: alice
      user_home: $alice
      sid: S-1-5-21-1000-2000-3000-1001
      connector: cursor
      data_dir: $aliceData
      agent_version: 3.17.8
      enabled: true
    - user: outsider
      user_home: $outsider
      sid: S-1-5-21-1000-2000-3000-1009
      connector: codex
      data_dir: $outsiderData
      enabled: true
"@
    [IO.File]::WriteAllText($manifestPath, $goYaml)
    Assert-Paths 'enumerator manifest' @($aliceData, $bobData, $bobStaging, $carolData)

    # The installer-rendered manifest has no data_dir rows at all.
    [IO.File]::WriteAllText($manifestPath, @"
version: 1
targets:
  - user: "alice"
    user_home: "$($alice.Replace('\', '\\'))"
    sid: "S-1-5-21-1000-2000-3000-1001"
    connector: "cursor"
    agent_version: "1.7.0"
    enabled: true
"@)
    Assert-Paths 'rendered manifest without data_dir' @($bobData, $bobStaging, $carolData)

    # A double-quoted data_dir with escaped separators still counts.
    [IO.File]::WriteAllText($manifestPath, "version: 1`ntargets:`n  - data_dir: `"$($aliceData.Replace('\', '\\'))`"`n    connector: codex`n")
    Assert-Paths 'double-quoted data_dir' @($aliceData, $bobData, $bobStaging, $carolData)

    # A manifest row and managed evidence for the same folder list it once.
    [IO.File]::WriteAllText($manifestPath, "version: 1`ntargets:`n  - data_dir: $bobData`n")
    Assert-Paths 'manifest and evidence agree' @($bobData, $bobStaging, $carolData)

    # A manifest row naming a linked .defenseclaw is not taken either.
    if ($erinLinked) {
        [IO.File]::WriteAllText($manifestPath, "version: 1`ntargets:`n  - data_dir: $erinData`n    connector: codex`n")
        Assert-Paths 'manifest row through a reparse point' @($bobData, $bobStaging, $carolData)
    }

    # No manifest at all: the managed folders are still found.
    [IO.File]::Delete($manifestPath)
    Assert-Paths 'missing manifest' @($bobData, $bobStaging, $carolData)

    # An unreadable profile list keeps the purge away from every home.
    $script:registeredProfiles = @()
    [IO.File]::WriteAllText($manifestPath, $goYaml)
    Assert-Paths 'no registered profiles' @()

    if ($erinLinked -and (Test-DefenseClawNuclearManagedUserDataFolder -Path $erinData)) {
        throw 'a .defenseclaw reparse point was treated as a managed user data folder'
    }
    if (-not (Test-DefenseClawNuclearManagedUserDataFolder -Path $bobData) -or
        (Test-DefenseClawNuclearManagedUserDataFolder -Path $daveData) -or
        (Test-DefenseClawNuclearManagedUserDataFolder -Path ([IO.Path]::Combine($root, 'absent', '.defenseclaw')))) {
        throw 'managed user data evidence was misjudged'
    }
}
finally {
    if ($erinLinked) {
        [IO.Directory]::Delete($erinData)
    }
    [IO.Directory]::Delete($root, $true)
}

Microsoft.PowerShell.Utility\Write-Output 'nuclear user data paths smoke passed'
