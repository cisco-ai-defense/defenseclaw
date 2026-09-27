# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 5.1

# Function-level regression for the Claude bootstrap placeholder that the
# installer's -Mode/-Connector renderer writes for a user with no Claude client
# yet (#895 review). The machine-wide DefenseClaw Claude policy is rendered from
# the hook contract of each enrolled row, so placeholder rows on an older
# contract than the detected clients rewrote it and changed its digest. Only
# fixture profiles under a disposable scratch directory are read or written.

[CmdletBinding()]
param(
    [string]$ScratchRoot = [IO.Path]::GetTempPath()
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$installerPath = [IO.Path]::GetFullPath(
    (Join-Path $PSScriptRoot '..\install-enterprise.ps1')
)
$source = [IO.File]::ReadAllText($installerPath)
$executionMarker = '$bootstrapEnvironment = $null'
$markerIndex = $source.IndexOf($executionMarker, [StringComparison]::Ordinal)
if ($markerIndex -le 0 -or
    $source.IndexOf(
        $executionMarker,
        $markerIndex + $executionMarker.Length,
        [StringComparison]::Ordinal
    ) -ge 0) {
    throw 'could not isolate the exact production bootstrap definition region'
}
. ([scriptblock]::Create($source.Substring(0, $markerIndex)))

$root = [IO.Path]::Combine(
    [IO.Path]::GetFullPath($ScratchRoot),
    ('dc-claude-placeholder-' + [Guid]::NewGuid().ToString('N'))
)
[void][IO.Directory]::CreateDirectory($root)
$failures = [Collections.Generic.List[string]]::new()
try {
    function New-FixtureProfile {
        param([string]$Name, [string]$ClaudeVersion, [int]$Rid)
        $userHome = [IO.Path]::Combine($root, $Name)
        [void][IO.Directory]::CreateDirectory($userHome)
        if (-not [string]::IsNullOrEmpty($ClaudeVersion)) {
            $package = [IO.Path]::Combine(
                $userHome,
                ".cursor\extensions\anthropic.claude-code-$ClaudeVersion-win32-x64\package.json"
            )
            [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($package))
            [IO.File]::WriteAllText(
                $package,
                ('{"name":"claude-code","version":"' + $ClaudeVersion + '"}'),
                [Text.UTF8Encoding]::new($false)
            )
        }
        return [pscustomobject]@{
            SID = "S-1-5-21-1000-1000-1000-$Rid"
            UserName = $Name
            UserHome = $userHome
        }
    }
    function Get-RenderedVersions {
        param([object[]]$Profiles, [string[]]$Connectors)
        $rendered = Get-DefenseClawRenderedEnterpriseTargets `
            -Connectors $Connectors `
            -Profiles $Profiles
        $versions = [ordered]@{}
        foreach ($block in @(
            [regex]::Split($rendered, '(?m)(?=^  - user: )') |
                Where-Object { $_.StartsWith('  - user: ') }
        )) {
            $user = [regex]::Match($block, '(?m)^  - user: "([^"]+)"').Groups[1].Value
            $connector = [regex]::Match($block, '(?m)^    connector: "([^"]+)"').Groups[1].Value
            $version = [regex]::Match($block, '(?m)^    agent_version: "([^"]+)"').Groups[1].Value
            $versions["$user/$connector"] = $version
        }
        return $versions
    }
    function Assert-Versions {
        param([string]$Label, [Collections.IDictionary]$Actual, [hashtable]$Expected)
        foreach ($key in $Expected.Keys) {
            if (-not $Actual.Contains($key)) {
                $failures.Add("${Label}: no row for $key")
            }
            elseif ([string]$Actual[$key] -cne [string]$Expected[$key]) {
                $failures.Add("${Label}: $key agent_version $($Actual[$key]), want $($Expected[$key])")
            }
        }
    }

    $bob = New-FixtureProfile -Name 'bob' -ClaudeVersion '2.1.250' -Rid 1001
    $carol = New-FixtureProfile -Name 'carol' -ClaudeVersion '2.1.200' -Rid 1002
    $dave = New-FixtureProfile -Name 'dave' -ClaudeVersion '2.1.250-beta.1' -Rid 1003
    $alice = New-FixtureProfile -Name 'alice' -ClaudeVersion '' -Rid 1004

    # A user without a client shares the contract of the detected client
    # (claudecode-hooks-v2 starts at 2.1.219) instead of the lowest one.
    Assert-Versions 'modern client beside a user without one' `
        (Get-RenderedVersions -Profiles @($bob, $alice) -Connectors @('claudecode')) `
        @{ 'bob/claudecode' = '2.1.250'; 'alice/claudecode' = '2.1.219' }
    Assert-Versions 'older contract client beside a user without one' `
        (Get-RenderedVersions -Profiles @($carol, $alice) -Connectors @('claudecode')) `
        @{ 'carol/claudecode' = '2.1.200'; 'alice/claudecode' = '2.1.154' }
    Assert-Versions 'newest detected contract wins' `
        (Get-RenderedVersions -Profiles @($carol, $alice, $bob) -Connectors @('claudecode')) `
        @{ 'carol/claudecode' = '2.1.200'; 'alice/claudecode' = '2.1.219'; 'bob/claudecode' = '2.1.250' }
    # No detected client, or only a pre-release build: the bootstrap default.
    Assert-Versions 'no detected client' `
        (Get-RenderedVersions -Profiles @($alice) -Connectors @('claudecode', 'codex')) `
        @{ 'alice/claudecode' = '2.1.154'; 'alice/codex' = '0.131.0' }
    Assert-Versions 'pre-release client only' `
        (Get-RenderedVersions -Profiles @($dave, $alice) -Connectors @('claudecode')) `
        @{ 'dave/claudecode' = '2.1.250-beta.1'; 'alice/claudecode' = '2.1.154' }
    # Other connectors keep their fixed placeholders.
    Assert-Versions 'codex placeholder unchanged' `
        (Get-RenderedVersions -Profiles @($bob, $alice) -Connectors @('codex', 'claudecode')) `
        @{ 'alice/codex' = '0.131.0'; 'alice/claudecode' = '2.1.219' }

    foreach ($case in @(
        @(@(), '2.1.154'),
        @(@('2.1.100'), '2.1.154'),
        @(@('2.1.218'), '2.1.154'),
        @(@('2.1.219'), '2.1.219'),
        @(@('2.1.200', '3.0.0'), '2.1.219'),
        @(@('not-a-version', '2.1.300+build.5'), '2.1.154')
    )) {
        $got = Get-DefenseClawClaudeBootstrapPlaceholder `
            -DetectedVersions ([string[]]$case[0]) `
            -Default '2.1.154'
        if ([string]$got -cne [string]$case[1]) {
            $failures.Add("placeholder for [$($case[0] -join ',')] = $got, want $($case[1])")
        }
    }
}
finally {
    if ([IO.Directory]::Exists($root)) {
        [IO.Directory]::Delete($root, $true)
    }
}

if ($failures.Count -ne 0) {
    throw ("Claude placeholder smoke failed:`n" + ($failures -join "`n"))
}
Write-Output 'Claude placeholder smoke passed'
