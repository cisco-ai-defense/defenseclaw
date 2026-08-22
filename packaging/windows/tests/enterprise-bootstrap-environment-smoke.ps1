# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 5.1

[CmdletBinding()]
param(
    [switch]$Worker,
    [string]$ResultPath,
    [int]$HoldMilliseconds = 0
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$installerPath = [IO.Path]::GetFullPath(
    (Join-Path $PSScriptRoot '..\install-enterprise.ps1')
)

function Get-ProductionBootstrapDefinitions {
    $source = [IO.File]::ReadAllText($installerPath)
    $executionMarker = '$bootstrapEnvironment = $null'
    $markerIndex = $source.IndexOf(
        $executionMarker,
        [StringComparison]::Ordinal
    )
    if ($markerIndex -le 0 -or
        $source.IndexOf(
            $executionMarker,
            $markerIndex + $executionMarker.Length,
            [StringComparison]::Ordinal
        ) -ge 0) {
        throw 'could not isolate the exact production bootstrap definition region'
    }
    return [scriptblock]::Create($source.Substring(0, $markerIndex))
}

function Invoke-ProtectedEnvironmentProbe {
    param([int]$Hold = 0)

    $probeToken = [Guid]::NewGuid().ToString('N')
    $originalEnvironment = @{}
    foreach ($name in $script:DefenseClawBootstrapEnvironmentNames) {
        $originalEnvironment[$name] = [Environment]::GetEnvironmentVariable(
            $name,
            'Process'
        )
    }
    $hostileRoot = $null
    $probeResult = $null
    try {
        $hostileRoot = [IO.Path]::GetFullPath(
            [IO.Path]::Combine(
                [IO.Path]::GetTempPath(),
                "DefenseClaw-BootstrapHostile-$probeToken"
            )
        )
        [void][IO.Directory]::CreateDirectory($hostileRoot)
        $hostileVolume = [IO.Path]::GetPathRoot($hostileRoot).TrimEnd('\')
        $hostile = @{}
        foreach ($name in $script:DefenseClawBootstrapEnvironmentNames) {
            $hostile[$name] = switch ($name) {
                'HOMEDRIVE' { $hostileVolume; break }
                'HOMEPATH' {
                    $hostileRoot.Substring($hostileVolume.Length)
                    break
                }
                default { [IO.Path]::Combine($hostileRoot, $name) }
            }
            [Environment]::SetEnvironmentVariable(
                $name,
                $hostile[$name],
                'Process'
            )
        }
        $context = $null
        $root = $null
        $cleanupFailure = $null
        try {
            $context = New-DefenseClawBootstrapEnvironment
            $root = [string]$context.Path
            $windowsTemp = [IO.Path]::GetFullPath(
                [IO.Path]::Combine(
                    [Environment]::GetFolderPath(
                        [Environment+SpecialFolder]::Windows
                    ),
                    'Temp'
                )
            ).TrimEnd('\')
            if (-not [string]::Equals(
                    [IO.Path]::GetDirectoryName($root),
                    $windowsTemp,
                    [StringComparison]::OrdinalIgnoreCase
                ) -or
                [IO.Path]::GetFileName($root) -cnotmatch
                    '^DefenseClaw-Bootstrap-[a-f0-9]{32}$') {
                throw "protected bootstrap root is outside exact capability scope: $root"
            }
            [void](Assert-DefenseClawBootstrapOneShotRoot `
                -Path $root `
                -ExpectedSecurity $context.Security `
                -RequireEmpty)

            foreach ($name in @(
                'TEMP',
                'TMP',
                'TMPDIR',
                'LOCALAPPDATA',
                'APPDATA',
                'USERPROFILE',
                'HOME',
                'XDG_CACHE_HOME',
                'XDG_CONFIG_HOME',
                'XDG_DATA_HOME',
                'DOTNET_CLI_HOME',
                'NUGET_PACKAGES'
            )) {
                $actual = [Environment]::GetEnvironmentVariable(
                    $name,
                    'Process'
                )
                if (-not [string]::Equals(
                        $actual,
                        $root,
                        [StringComparison]::Ordinal
                    )) {
                    throw "$name was not pinned to the protected bootstrap root"
                }
            }
            $volume = [IO.Path]::GetPathRoot($root).TrimEnd('\')
            if ([Environment]::GetEnvironmentVariable(
                    'HOMEDRIVE',
                    'Process'
                ) -cne $volume -or
                [Environment]::GetEnvironmentVariable(
                    'HOMEPATH',
                    'Process'
                ) -cne $root.Substring($volume.Length) -or
                [Environment]::GetEnvironmentVariable(
                    'PSModuleAnalysisCachePath',
                    'Process'
                ) -cne 'NUL') {
                throw 'home drive/path or PowerShell module-analysis cache was not pinned'
            }

            $sections = [Security.AccessControl.AccessControlSections]::Owner `
                -bor [Security.AccessControl.AccessControlSections]::Group `
                -bor [Security.AccessControl.AccessControlSections]::Access
            $actualSecurity = Get-DefenseClawBootstrapDirectorySecurity `
                -Directory ([IO.DirectoryInfo]::new($root)) `
                -Sections $sections
            $rules = $actualSecurity.GetAccessRules(
                $true,
                $true,
                [Security.Principal.SecurityIdentifier]
            )
            $actualSIDs = @(
                $rules |
                    Where-Object {
                        $_.AccessControlType -eq
                            [Security.AccessControl.AccessControlType]::Allow
                    } |
                    ForEach-Object {
                        (
                            [Security.Principal.SecurityIdentifier](
                                $_.IdentityReference
                            )
                        ).Value
                    } |
                    Sort-Object -Unique
            )
            $expectedSIDs = @('S-1-5-18', 'S-1-5-32-544')
            $expectedOwner = 'S-1-5-32-544'
            if (-not [bool]$context.Elevated) {
                $expectedSIDs += [string]$context.CurrentSID
                $expectedOwner = [string]$context.CurrentSID
            }
            $expectedSIDs = @($expectedSIDs | Sort-Object -Unique)
            if (($actualSIDs -join ',') -cne ($expectedSIDs -join ',')) {
                throw (
                    'protected bootstrap DACL principal set mismatch: got ' +
                    "$($actualSIDs -join ','); expected $($expectedSIDs -join ',')"
                )
            }
            $ownerSID = $actualSecurity.GetOwner(
                [Security.Principal.SecurityIdentifier]
            ).Value
            if ($ownerSID -cne $expectedOwner -or
                -not $actualSecurity.AreAccessRulesProtected) {
                throw (
                    'protected bootstrap owner/protection mismatch: got ' +
                    "$ownerSID protected=$($actualSecurity.AreAccessRulesProtected)"
                )
            }

            $nested = [IO.Directory]::CreateDirectory(
                [IO.Path]::Combine($root, 'compiler-output')
            )
            [IO.File]::WriteAllText(
                [IO.Path]::Combine($nested.FullName, 'generated.dll'),
                'test compiler output'
            )
            if ($Hold -gt 0) {
                [Threading.Thread]::Sleep($Hold)
            }
        }
        finally {
            if ($null -ne $context) {
                try {
                    Remove-DefenseClawBootstrapEnvironment -Context $context
                }
                catch {
                    $cleanupFailure = $_.Exception.Message
                }
                finally {
                    Restore-DefenseClawBootstrapEnvironment -Context $context
                }
            }
        }
        if ($null -ne $cleanupFailure) {
            throw "protected bootstrap probe cleanup failed: $cleanupFailure"
        }
        if ([string]::IsNullOrWhiteSpace($root) -or
            (Test-DefenseClawBootstrapPathExists -Path $root)) {
            throw "protected bootstrap root survived exact cleanup: $root"
        }
        foreach ($name in $script:DefenseClawBootstrapEnvironmentNames) {
            $actual = [Environment]::GetEnvironmentVariable($name, 'Process')
            if ($actual -cne $hostile[$name]) {
                throw "bootstrap cleanup did not restore $name exactly"
            }
        }
        $probeResult = [pscustomobject]@{
            root = $root
            elevated = [bool]$context.Elevated
            exact_acl = $true
            all_environment_paths_pinned = $true
            module_analysis_cache_disabled = $true
            nested_cleanup_verified = $true
            environment_restore_verified = $true
            hostile_fixture_cleanup_verified = $true
        }
    }
    finally {
        foreach ($name in $script:DefenseClawBootstrapEnvironmentNames) {
            [Environment]::SetEnvironmentVariable(
                $name,
                $originalEnvironment[$name],
                'Process'
            )
        }
        if (-not [string]::IsNullOrWhiteSpace($hostileRoot) -and
            [IO.Directory]::Exists($hostileRoot)) {
            [IO.Directory]::Delete($hostileRoot, $true)
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($hostileRoot) -and
        [IO.Directory]::Exists($hostileRoot)) {
        throw "hostile bootstrap fixture root survived cleanup: $hostileRoot"
    }
    return $probeResult
}

function Invoke-CollisionNoSeizeProbe {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    $elevated = $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
    $expected = New-DefenseClawBootstrapDirectorySecurity `
        -CurrentSID $identity.User `
        -Elevated $elevated
    $foreign = [Security.AccessControl.DirectorySecurity]::new()
    $foreign.SetSecurityDescriptorSddlForm(
        (Get-DefenseClawBootstrapSecuritySDDL -Security $expected)
    )
    $usersSID =
        [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
    $foreign.AddAccessRule(
        [Security.AccessControl.FileSystemAccessRule]::new(
            $usersSID,
            [Security.AccessControl.FileSystemRights]::ReadAndExecute,
            (
                [Security.AccessControl.InheritanceFlags]::ContainerInherit `
                    -bor
                [Security.AccessControl.InheritanceFlags]::ObjectInherit
            ),
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow
        )
    )
    $windowsTemp = [IO.Path]::Combine(
        [Environment]::GetFolderPath([Environment+SpecialFolder]::Windows),
        'Temp'
    )
    $collisionPath = [IO.Path]::Combine(
        $windowsTemp,
        "DefenseClaw-Bootstrap-$([Guid]::NewGuid().ToString('N'))"
    )
    $directory = [IO.DirectoryInfo]::new($collisionPath)
    try {
        if ($PSVersionTable.PSEdition -eq 'Core') {
            [IO.FileSystemAclExtensions]::Create($directory, $foreign)
            [IO.FileSystemAclExtensions]::Create($directory, $expected)
        }
        else {
            $directory.Create($foreign)
            $directory.Create($expected)
        }
        $rejected = $false
        try {
            [void](Assert-DefenseClawBootstrapOneShotRoot `
                -Path $collisionPath `
                -ExpectedSecurity $expected `
                -RequireEmpty)
        }
        catch {
            if ($_.Exception.Message -notmatch
                'security descriptor mismatch') {
                throw
            }
            $rejected = $true
        }
        if (-not $rejected) {
            throw 'ACL-aware create seized an existing collision directory'
        }
    }
    finally {
        if ([IO.Directory]::Exists($collisionPath)) {
            [IO.Directory]::Delete($collisionPath, $false)
        }
    }
    return $true
}

function Invoke-RenderedEnterpriseTargetsVersionProbe {
    $fixtureRoot = [IO.Path]::Combine(
        [IO.Path]::GetTempPath(),
        "DefenseClaw-TargetMetadata-$([Guid]::NewGuid().ToString('N'))"
    )
    [void][IO.Directory]::CreateDirectory($fixtureRoot)
    try {
        $fixtures = @(
            [pscustomobject]@{
                RelativePath = 'AppData\Roaming\npm\node_modules\@openai\codex\package.json'
                Body = '{"name":"@openai/codex","version":"0.144.3"}'
            },
            [pscustomobject]@{
                RelativePath = 'AppData\Local\Programs\cursor\resources\app\package.json'
                Body = '{"name":"cursor","version":"1.7.54"}'
            },
            [pscustomobject]@{
                RelativePath = '.cursor\extensions\anthropic.claude-code-2.1.208-win32-x64\package.json'
                Body = '{"name":"claude-code","version":"2.1.208"}'
            },
            [pscustomobject]@{
                RelativePath = 'AppData\Roaming\npm\node_modules\@ampcode\cli\package.json'
                Body = '{"name":"@attacker/not-amp","version":"9.9.9"}'
            }
        )
        foreach ($fixture in $fixtures) {
            $path = [IO.Path]::Combine($fixtureRoot, $fixture.RelativePath)
            [void][IO.Directory]::CreateDirectory(
                [IO.Path]::GetDirectoryName($path)
            )
            [IO.File]::WriteAllText(
                $path,
                [string]$fixture.Body,
                [Text.UTF8Encoding]::new($false)
            )
        }

        $rendered = Get-DefenseClawRenderedEnterpriseTargets `
            -Connectors @('codex', 'cursor', 'claudecode', 'amp') `
            -Profiles @([pscustomobject]@{
                SID = 'S-1-5-21-1000-1000-1000-1001'
                UserName = 'fixture-user'
                UserHome = $fixtureRoot
            })
        $blocks = @(
            [regex]::Split($rendered, '(?m)(?=^  - user: )') |
                Where-Object { $_.StartsWith('  - user: ') }
        )
        if ($blocks.Count -ne 4) {
            throw "target renderer emitted $($blocks.Count) rows instead of four"
        }
        foreach ($block in $blocks) {
            $enabled = $block -match '(?m)^    enabled: true\r?$'
            $hasVersion =
                $block -match '(?m)^    agent_version: "[^"]+"\r?$'
            if ($enabled -ne $hasVersion) {
                throw 'target renderer emitted an enabled/version contract mismatch'
            }
        }
        foreach ($expectedVersion in @('0.144.3', '1.7.54', '2.1.208')) {
            if ($rendered -notmatch (
                    '(?m)^    agent_version: "' +
                    [regex]::Escape($expectedVersion) +
                    '"\r?$'
                )) {
                throw "target renderer omitted discovered version $expectedVersion"
            }
        }
        $ampBlock = @(
            $blocks |
                Where-Object { $_ -match '(?m)^    connector: "amp"\r?$' }
        )
        if ($ampBlock.Count -ne 1 -or
            $ampBlock[0] -notmatch '(?m)^    enabled: false\r?$' -or
            $ampBlock[0] -match '(?m)^    agent_version:' -or
            $rendered.Contains('9.9.9')) {
            throw 'target renderer enabled Amp from mismatched package metadata'
        }
        $hostileVersion = "9.9.9`n    enabled: true"
        if (-not [string]::IsNullOrEmpty(
                (ConvertTo-DefenseClawConnectorMetadataVersion `
                    -Value $hostileVersion)
            )) {
            throw 'target renderer accepted a YAML-shaping metadata version'
        }
    }
    finally {
        if ([IO.Directory]::Exists($fixtureRoot)) {
            [IO.Directory]::Delete($fixtureRoot, $true)
        }
    }
    return $true
}

function Invoke-ClaudeWinGetMetadataVersionProbe {
    $fixtureRoot = [IO.Path]::Combine(
        [IO.Path]::GetTempPath(),
        "DefenseClaw-ClaudeWinGet-$([Guid]::NewGuid().ToString('N'))"
    )
    [void][IO.Directory]::CreateDirectory($fixtureRoot)
    $junctionPath = $null
    try {
        $validIdentity = Test-DefenseClawClaudeWinGetIdentity `
            -SignatureStatus 'Valid' `
            -SignerSimpleName 'Anthropic PBC' `
            -ProductName 'Claude Code' `
            -OriginalFilename 'claude.exe' `
            -FileVersion '2.1.229.0'
        if ($validIdentity -cne '2.1.229') {
            throw "WinGet Claude version normalization returned '$validIdentity'"
        }
        foreach ($invalidIdentity in @(
            [pscustomobject]@{
                Status = 'NotSigned'; Signer = 'Anthropic PBC'
                Product = 'Claude Code'; Original = 'claude.exe'
                Version = '2.1.229.0'
            },
            [pscustomobject]@{
                Status = 'Valid'; Signer = 'Attacker LLC'
                Product = 'Claude Code'; Original = 'claude.exe'
                Version = '2.1.229.0'
            },
            [pscustomobject]@{
                Status = 'Valid'; Signer = 'Anthropic PBC'
                Product = 'Claude Desktop'; Original = 'claude.exe'
                Version = '2.1.229.0'
            },
            [pscustomobject]@{
                Status = 'Valid'; Signer = 'Anthropic PBC'
                Product = 'Claude Code'; Original = 'other.exe'
                Version = '2.1.229.0'
            },
            [pscustomobject]@{
                Status = 'Valid'; Signer = 'Anthropic PBC'
                Product = 'Claude Code'; Original = 'claude.exe'
                Version = ''
            },
            [pscustomobject]@{
                Status = 'Valid'; Signer = 'Anthropic PBC'
                Product = 'Claude Code'; Original = 'claude.exe'
                Version = 'not-a-version'
            },
            [pscustomobject]@{
                Status = 'Valid'; Signer = 'Anthropic PBC'
                Product = 'Claude Code'; Original = 'claude.exe'
                Version = '2.1.229.1'
            }
        )) {
            $rejected = Test-DefenseClawClaudeWinGetIdentity `
                -SignatureStatus $invalidIdentity.Status `
                -SignerSimpleName $invalidIdentity.Signer `
                -ProductName $invalidIdentity.Product `
                -OriginalFilename $invalidIdentity.Original `
                -FileVersion $invalidIdentity.Version
            if (-not [string]::IsNullOrEmpty($rejected)) {
                throw "WinGet Claude identity validation accepted '$rejected'"
            }
        }

        $officialLeaf =
            'Anthropic.ClaudeCode_Microsoft.Winget.Source_8wekyb3d8bbwe'
        $validUserHome = [IO.Path]::Combine($fixtureRoot, 'valid-user')
        $validPackageRoot = [IO.Path]::Combine(
            $validUserHome,
            'AppData\Local\Microsoft\WinGet\Packages'
        )
        $validPackage = [IO.Path]::Combine(
            $validPackageRoot,
            $officialLeaf
        )
        [void][IO.Directory]::CreateDirectory($validPackage)
        $validExecutable = [IO.Path]::Combine($validPackage, 'claude.exe')
        [IO.File]::WriteAllBytes($validExecutable, [byte[]]@(0x4d, 0x5a))
        $validReaderState = @{ Calls = 0 }
        $validReader = {
            param([string]$Root, [string]$Path)
            $validReaderState.Calls++
            if (-not [string]::Equals(
                    [IO.Path]::GetFullPath($Root),
                    [IO.Path]::GetFullPath($validPackageRoot),
                    [StringComparison]::OrdinalIgnoreCase
                ) -or
                -not [string]::Equals(
                    [IO.Path]::GetFullPath($Path),
                    [IO.Path]::GetFullPath($validExecutable),
                    [StringComparison]::OrdinalIgnoreCase
                )) {
                return ''
            }
            return '2.1.229'
        }.GetNewClosure()
        $discovered = Get-DefenseClawClaudeWinGetMetadataVersion `
            -UserHome $validUserHome `
            -ExecutableVersionReader $validReader
        if ($discovered -cne '2.1.229' -or
            [int]$validReaderState.Calls -ne 1) {
            throw 'official WinGet Claude package was not discovered exactly once'
        }

        $missingUserHome = [IO.Path]::Combine($fixtureRoot, 'missing-user')
        [void][IO.Directory]::CreateDirectory([IO.Path]::Combine(
            $missingUserHome,
            'AppData\Local\Microsoft\WinGet\Packages',
            $officialLeaf
        ))
        $missingReaderState = @{ Calls = 0 }
        $missingReader = {
            param([string]$Root, [string]$Path)
            $missingReaderState.Calls++
            return '9.9.9'
        }.GetNewClosure()
        if (-not [string]::IsNullOrEmpty(
                (Get-DefenseClawClaudeWinGetMetadataVersion `
                    -UserHome $missingUserHome `
                    -ExecutableVersionReader $missingReader)
            ) -or
            [int]$missingReaderState.Calls -ne 0) {
            throw 'WinGet Claude discovery accepted a missing executable'
        }

        $hostileUserHome = [IO.Path]::Combine($fixtureRoot, 'hostile-user')
        $hostilePackage = [IO.Path]::Combine(
            $hostileUserHome,
            'AppData\Local\Microsoft\WinGet\Packages',
            "${officialLeaf}_hostile"
        )
        [void][IO.Directory]::CreateDirectory($hostilePackage)
        [IO.File]::WriteAllBytes(
            [IO.Path]::Combine($hostilePackage, 'claude.exe'),
            [byte[]]@(0x4d, 0x5a)
        )
        $hostileReaderState = @{ Calls = 0 }
        $hostileReader = {
            param([string]$Root, [string]$Path)
            $hostileReaderState.Calls++
            return '9.9.9'
        }.GetNewClosure()
        if (-not [string]::IsNullOrEmpty(
                (Get-DefenseClawClaudeWinGetMetadataVersion `
                    -UserHome $hostileUserHome `
                    -ExecutableVersionReader $hostileReader)
            ) -or
            [int]$hostileReaderState.Calls -ne 0) {
            throw 'WinGet Claude discovery accepted a similarly named package'
        }

        $multipleUserHome = [IO.Path]::Combine($fixtureRoot, 'multiple-user')
        $multiplePackageRoot = [IO.Path]::Combine(
            $multipleUserHome,
            'AppData\Local\Microsoft\WinGet\Packages'
        )
        $multipleVersions = @{}
        foreach ($candidate in @(
            [pscustomobject]@{ Suffix = '8wekyb3d8bbwe'; Version = '2.1.228' },
            [pscustomobject]@{ Suffix = 'SecondSource1'; Version = '2.1.229' }
        )) {
            $package = [IO.Path]::Combine(
                $multiplePackageRoot,
                "Anthropic.ClaudeCode_Microsoft.Winget.Source_$($candidate.Suffix)"
            )
            [void][IO.Directory]::CreateDirectory($package)
            $executable = [IO.Path]::Combine($package, 'claude.exe')
            [IO.File]::WriteAllBytes($executable, [byte[]]@(0x4d, 0x5a))
            $multipleVersions[[IO.Path]::GetFullPath($executable)] =
                [string]$candidate.Version
        }
        $multipleReader = {
            param([string]$Root, [string]$Path)
            return [string]$multipleVersions[[IO.Path]::GetFullPath($Path)]
        }.GetNewClosure()
        $highest = Get-DefenseClawClaudeWinGetMetadataVersion `
            -UserHome $multipleUserHome `
            -ExecutableVersionReader $multipleReader
        if ($highest -cne '2.1.229') {
            throw "multiple WinGet Claude packages selected '$highest'"
        }

        $escapeUserHome = [IO.Path]::Combine($fixtureRoot, 'escape-user')
        $escapePackageRoot = [IO.Path]::Combine(
            $escapeUserHome,
            'AppData\Local\Microsoft\WinGet\Packages'
        )
        [void][IO.Directory]::CreateDirectory($escapePackageRoot)
        $escapeTarget = [IO.Path]::Combine($fixtureRoot, 'escape-target')
        [void][IO.Directory]::CreateDirectory($escapeTarget)
        [IO.File]::WriteAllBytes(
            [IO.Path]::Combine($escapeTarget, 'claude.exe'),
            [byte[]]@(0x4d, 0x5a)
        )
        $junctionPath = [IO.Path]::Combine(
            $escapePackageRoot,
            'Anthropic.ClaudeCode_Microsoft.Winget.Source_EscapeSource1'
        )
        [void](New-Item `
            -ItemType Junction `
            -Path $junctionPath `
            -Target $escapeTarget `
            -ErrorAction Stop)
        $escapeReaderState = @{ Calls = 0 }
        $escapeReader = {
            param([string]$Root, [string]$Path)
            $escapeReaderState.Calls++
            return '9.9.9'
        }.GetNewClosure()
        if (-not [string]::IsNullOrEmpty(
                (Get-DefenseClawClaudeWinGetMetadataVersion `
                    -UserHome $escapeUserHome `
                    -ExecutableVersionReader $escapeReader)
            ) -or
            [int]$escapeReaderState.Calls -ne 0) {
            throw 'WinGet Claude discovery followed a package reparse point'
        }
        [IO.Directory]::Delete($junctionPath, $false)
        $junctionPath = $null

        $precedenceUserHome = [IO.Path]::Combine(
            $fixtureRoot,
            'precedence-user'
        )
        $npmMetadata = [IO.Path]::Combine(
            $precedenceUserHome,
            'AppData\Roaming\npm\node_modules\@anthropic-ai\claude-code\package.json'
        )
        [void][IO.Directory]::CreateDirectory(
            [IO.Path]::GetDirectoryName($npmMetadata)
        )
        [IO.File]::WriteAllText(
            $npmMetadata,
            '{"name":"@anthropic-ai/claude-code","version":"2.1.230"}',
            [Text.UTF8Encoding]::new($false)
        )
        $precedencePackage = [IO.Path]::Combine(
            $precedenceUserHome,
            'AppData\Local\Microsoft\WinGet\Packages',
            $officialLeaf
        )
        [void][IO.Directory]::CreateDirectory($precedencePackage)
        [IO.File]::WriteAllBytes(
            [IO.Path]::Combine($precedencePackage, 'claude.exe'),
            [byte[]]@(0x4d, 0x5a)
        )
        $precedence = Get-DefenseClawConnectorMetadataVersion `
            -Connector 'claudecode' `
            -UserHome $precedenceUserHome
        if ($precedence -cne '2.1.230') {
            throw "npm/WinGet precedence returned '$precedence'"
        }

        $rendered = Get-DefenseClawRenderedEnterpriseTargets `
            -Connectors @('claudecode') `
            -Profiles @([pscustomobject]@{
                SID = 'S-1-5-21-2000-2000-2000-2001'
                UserName = 'eligible-user'
                UserHome = $precedenceUserHome
            })
        if ([regex]::Matches(
                $rendered,
                '(?m)^  - user: "eligible-user"\r?$'
            ).Count -ne 1 -or
            [regex]::Matches(
                $rendered,
                '(?m)^    connector: "claudecode"\r?$'
            ).Count -ne 1 -or
            [regex]::Matches(
                $rendered,
                '(?m)^    agent_version: "2\.1\.230"\r?$'
            ).Count -ne 1 -or
            [regex]::Matches(
                $rendered,
                '(?m)^    enabled: true\r?$'
            ).Count -ne 1) {
            throw 'eligible Claude user did not receive exactly one enabled target'
        }
    }
    finally {
        if ($null -ne $junctionPath -and
            [IO.Directory]::Exists($junctionPath)) {
            [IO.Directory]::Delete($junctionPath, $false)
        }
        if ([IO.Directory]::Exists($fixtureRoot)) {
            [IO.Directory]::Delete($fixtureRoot, $true)
        }
    }
    return $true
}

function Invoke-RenderedEnterpriseConfigRulePackProbe {
    $rendered = Get-DefenseClawRenderedEnterpriseConfig `
        -Mode 'action' `
        -Connectors @('claudecode')
    $guardrailStart = $rendered.IndexOf(
        "guardrail:$([Environment]::NewLine)",
        [StringComparison]::Ordinal
    )
    $nextSection = $rendered.IndexOf(
        "ai_discovery:$([Environment]::NewLine)",
        [StringComparison]::Ordinal
    )
    if ($guardrailStart -lt 0 -or $nextSection -le $guardrailStart) {
        throw 'shorthand config did not emit a bounded guardrail section'
    }
    $guardrailBlock = $rendered.Substring(
        $guardrailStart,
        $nextSection - $guardrailStart
    )
    if ([regex]::Matches(
            $guardrailBlock,
            '(?m)^  rule_pack_dir: ""\r?$'
        ).Count -ne 1) {
        throw 'shorthand config did not explicitly select embedded rule-pack defaults'
    }
    return $true
}

$expectedWindows = [IO.Path]::GetFullPath(
    [IO.Path]::GetDirectoryName([Environment]::SystemDirectory)
).TrimEnd('\')
$registry = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
    [Microsoft.Win32.RegistryHive]::LocalMachine,
    [Microsoft.Win32.RegistryView]::Registry64
)
$currentVersion = $null
$shellFolders = $null
try {
    $currentVersion = $registry.OpenSubKey(
        'SOFTWARE\Microsoft\Windows\CurrentVersion',
        $false
    )
    $shellFolders = $registry.OpenSubKey(
        'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders',
        $false
    )
    if ($null -eq $currentVersion -or $null -eq $shellFolders) {
        throw 'machine known-folder registration is unavailable to the smoke'
    }
    $expectedProgramFiles = [IO.Path]::GetFullPath(
        [string]$currentVersion.GetValue(
            'ProgramFilesDir',
            $null,
            [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
        )
    ).TrimEnd('\')
    $expectedProgramData = [IO.Path]::GetFullPath(
        [string]$shellFolders.GetValue(
            'Common AppData',
            $null,
            [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
        )
    ).TrimEnd('\')
} finally {
    # Guard each Dispose independently. If OpenSubKey succeeded for one key
    # but the other returned $null (or threw), the inner try/finally could
    # leak the opened one. Moving the opens into this outer try and
    # nil-checking each dispose keeps both handles paired to this scope.
    if ($null -ne $currentVersion) { $currentVersion.Dispose() }
    if ($null -ne $shellFolders) { $shellFolders.Dispose() }
    $registry.Dispose()
}
foreach ($name in @(
    'ProgramData',
    'ProgramFiles',
    'ProgramFiles(x86)',
    'SystemRoot',
    'windir',
    'HOME',
    'USERPROFILE',
    'HOMEDRIVE',
    'HOMEPATH',
    'APPDATA',
    'LOCALAPPDATA'
)) {
    [Environment]::SetEnvironmentVariable($name, $null, 'Process')
}

$productionDefinitions = Get-ProductionBootstrapDefinitions
. $productionDefinitions
if (-not [string]::Equals(
        $trustedWindows,
        $expectedWindows,
        [StringComparison]::OrdinalIgnoreCase
    ) -or
    -not [string]::Equals(
        $trustedProgramFiles,
        $expectedProgramFiles,
        [StringComparison]::OrdinalIgnoreCase
    ) -or
    -not [string]::Equals(
        $trustedProgramData,
        $expectedProgramData,
        [StringComparison]::OrdinalIgnoreCase
    ) -or
    -not [IO.Path]::IsPathRooted($InstallRoot) -or
    -not [IO.Path]::IsPathRooted($StateRoot)) {
    throw 'production bootstrap did not recover exact machine roots from an empty environment'
}
$certificationRunID = [Guid]::NewGuid().ToString('N').Substring(0, 10)
$certificationInstallRoot = [IO.Path]::Combine(
    $expectedProgramFiles,
    'Cisco',
    'Cisco Secure Client',
    'DefenseClaw-Cert',
    $certificationRunID
)
$certificationStateRoot = [IO.Path]::Combine(
    $expectedProgramData,
    'Cisco',
    'Cisco Secure Client',
    'DefenseClaw-Cert',
    $certificationRunID
)
Assert-DefenseClawBootstrapLifecycleScope `
    -LifecycleAction 'Status' `
    -RequestedInstallRoot $certificationInstallRoot `
    -RequestedStateRoot $certificationStateRoot `
    -RequestedGatewayServiceName "DefenseClawCertGateway_$certificationRunID" `
    -RequestedGuardianServiceName "DefenseClawCertGuardian_$certificationRunID" `
    -AllowUnsignedLifecycle $false
foreach ($name in @(
    'New-DefenseClawBootstrapEnvironment',
    'Remove-DefenseClawBootstrapEnvironment',
    'Restore-DefenseClawBootstrapEnvironment',
    'Assert-DefenseClawBootstrapOneShotRoot'
)) {
    if ($null -eq (Get-Command -Name $name -CommandType Function)) {
        throw "production bootstrap definition is unavailable: $name"
    }
}

if ($Worker) {
    if ([string]::IsNullOrWhiteSpace($ResultPath)) {
        throw 'bootstrap environment worker requires -ResultPath'
    }
    try {
        $workerResult = Invoke-ProtectedEnvironmentProbe `
            -Hold $HoldMilliseconds
        [IO.File]::WriteAllText(
            [IO.Path]::GetFullPath($ResultPath),
            ($workerResult | ConvertTo-Json -Compress)
        )
        exit 0
    }
    catch {
        [IO.File]::WriteAllText(
            [IO.Path]::GetFullPath($ResultPath),
            ([pscustomobject]@{
                ok = $false
                error = $_.Exception.Message
            } | ConvertTo-Json -Compress)
        )
        exit 1
    }
}

$certificationCodexHome = [IO.Path]::Combine(
    $PSScriptRoot,
    ".codex-defenseclaw-cert-$certificationRunID"
)
$managedRootsExistedBeforeStatus = @{
    install = [IO.Directory]::Exists($certificationInstallRoot)
    state = [IO.Directory]::Exists($certificationStateRoot)
    codex = [IO.Directory]::Exists($certificationCodexHome)
}
if ($managedRootsExistedBeforeStatus.install -or
    $managedRootsExistedBeforeStatus.state -or
    $managedRootsExistedBeforeStatus.codex) {
    throw 'restricted-environment Status fixture collided with an existing root'
}
$enterpriseModule = $null
try {
    $enterpriseModule = Microsoft.PowerShell.Core\Import-Module `
        -Name ([IO.Path]::GetFullPath(
            (Join-Path $PSScriptRoot '..\DefenseClawEnterprise.psm1')
        )) `
        -Force `
        -PassThru `
        -ErrorAction Stop
    $status = Invoke-DefenseClawEnterpriseLifecycle `
        -Action Status `
        -InstallRoot $certificationInstallRoot `
        -StateRoot $certificationStateRoot `
        -GatewayServiceName "DefenseClawCertGateway_$certificationRunID" `
        -GuardianServiceName "DefenseClawCertGuardian_$certificationRunID" `
        -CertificationCodexHome $certificationCodexHome `
        -AllowUnsigned
}
finally {
    if ($null -ne $enterpriseModule) {
        Microsoft.PowerShell.Core\Remove-Module `
            -ModuleInfo $enterpriseModule `
            -Force `
            -ErrorAction Stop
    }
}
if (-not [bool]$status.ok -or [bool]$status.installed -or
    -not [string]::Equals(
        [string]$status.install_root,
        $certificationInstallRoot,
        [StringComparison]::OrdinalIgnoreCase
    ) -or
    -not [string]::Equals(
        [string]$status.state_root,
        $certificationStateRoot,
        [StringComparison]::OrdinalIgnoreCase
    ) -or
    [IO.Directory]::Exists($certificationInstallRoot) -or
    [IO.Directory]::Exists($certificationStateRoot) -or
    [IO.Directory]::Exists($certificationCodexHome)) {
    throw 'module Status did not remain a read-only absent deployment under the restricted environment'
}

$single = Invoke-ProtectedEnvironmentProbe
$collisionRejected = Invoke-CollisionNoSeizeProbe
$renderedTargetsVersionContract = Invoke-RenderedEnterpriseTargetsVersionProbe
$claudeWinGetMetadataContract = Invoke-ClaudeWinGetMetadataVersionProbe
$renderedConfigEmbeddedRulePack = Invoke-RenderedEnterpriseConfigRulePackProbe
$raceRoot = [IO.Path]::Combine(
    [IO.Path]::GetTempPath(),
    "DefenseClaw-BootstrapEnvironmentRace-$([Guid]::NewGuid().ToString('N'))"
)
[void][IO.Directory]::CreateDirectory($raceRoot)
$processes = [Collections.Generic.List[Diagnostics.Process]]::new()
$resultPaths = [Collections.Generic.List[string]]::new()
try {
    $engine = if ($PSVersionTable.PSEdition -eq 'Core') {
        [IO.Path]::Combine($PSHOME, 'pwsh.exe')
    }
    else {
        [IO.Path]::Combine($PSHOME, 'powershell.exe')
    }
    for ($index = 0; $index -lt 6; $index++) {
        $workerResultPath = [IO.Path]::Combine(
            $raceRoot,
            "worker-$index.json"
        )
        $resultPaths.Add($workerResultPath)
        $arguments = @(
            '-NoLogo',
            '-NoProfile',
            '-NonInteractive',
            '-ExecutionPolicy',
            'Bypass',
            '-File',
            ('"{0}"' -f $PSCommandPath.Replace('"', '\"')),
            '-Worker',
            '-ResultPath',
            ('"{0}"' -f $workerResultPath.Replace('"', '\"')),
            '-HoldMilliseconds',
            '750'
        ) -join ' '
        $start = [Diagnostics.ProcessStartInfo]::new()
        $start.FileName = $engine
        $start.Arguments = $arguments
        $start.UseShellExecute = $false
        $start.CreateNoWindow = $true
        $process = [Diagnostics.Process]::Start($start)
        if ($null -eq $process) {
            throw "could not start bootstrap race worker $index"
        }
        $processes.Add($process)
    }
    foreach ($process in $processes) {
        # Hosted Windows runners can spend well over 30 seconds starting six
        # concurrent PowerShell workers while Defender scans Add-Type output.
        if (-not $process.WaitForExit(120000)) {
            try {
                $process.Kill()
            }
            catch {
                # Best-effort termination after a bounded test timeout.
            }
            throw "bootstrap race worker $($process.Id) timed out"
        }
        if ($process.ExitCode -ne 0) {
            throw "bootstrap race worker $($process.Id) exited $($process.ExitCode)"
        }
    }
    $raceResults = @(
        foreach ($path in $resultPaths) {
            if (-not [IO.File]::Exists($path)) {
                throw "bootstrap race worker did not publish its result: $path"
            }
            [IO.File]::ReadAllText($path) | ConvertFrom-Json
        }
    )
    $uniqueRoots = @(
        $raceResults |
            ForEach-Object { [string]$_.root } |
            Sort-Object -Unique
    )
    if ($uniqueRoots.Count -ne $raceResults.Count) {
        throw 'concurrent bootstrap workers reused a capability root'
    }
    foreach ($root in $uniqueRoots) {
        if (Test-DefenseClawBootstrapPathExists -Path $root) {
            throw "concurrent bootstrap worker left its root behind: $root"
        }
    }
}
finally {
    foreach ($process in $processes) {
        $process.Dispose()
    }
    if ([IO.Directory]::Exists($raceRoot)) {
        [IO.Directory]::Delete($raceRoot, $true)
    }
}

$legacyRelativeEnvironmentResidue = @(
    foreach ($name in $script:DefenseClawBootstrapEnvironmentNames) {
        [IO.Directory]::EnumerateDirectories(
            (Get-Location).Path,
            "hostile-*-$name",
            [IO.SearchOption]::TopDirectoryOnly
        )
    }
)
if ($legacyRelativeEnvironmentResidue.Count -ne 0) {
    throw (
        'bootstrap environment smoke left legacy relative environment residue: ' +
        ($legacyRelativeEnvironmentResidue -join ', ')
    )
}

[pscustomobject]@{
    schema_version = 1
    ok = $true
    engine = $PSVersionTable.PSVersion.ToString()
    elevated = [bool]$single.elevated
    exact_acl = [bool]$single.exact_acl
    empty_environment_known_folders_recovered = $true
    restricted_environment_certification_status_scope = $true
    restricted_environment_module_status = $true
    all_environment_paths_pinned =
        [bool]$single.all_environment_paths_pinned
    module_analysis_cache_disabled =
        [bool]$single.module_analysis_cache_disabled
    nested_cleanup_verified = [bool]$single.nested_cleanup_verified
    environment_restore_verified =
        [bool]$single.environment_restore_verified
    hostile_fixture_cleanup_verified =
        [bool]$single.hostile_fixture_cleanup_verified
    existing_collision_rejected_without_acl_seizure =
        [bool]$collisionRejected
    rendered_targets_version_contract =
        [bool]$renderedTargetsVersionContract
    claude_winget_metadata_contract =
        [bool]$claudeWinGetMetadataContract
    rendered_config_embedded_rule_pack =
        [bool]$renderedConfigEmbeddedRulePack
    concurrent_workers = 6
    concurrent_roots_unique = $true
    concurrent_cleanup_verified = $true
} | ConvertTo-Json -Compress
