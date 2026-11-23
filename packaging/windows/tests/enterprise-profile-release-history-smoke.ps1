# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 5.1

# rel-1-0-10:GAP-1537, GAP-0644: the guardian honours the release a signed-out
# target's hook-contract lock names only when the administrator-only machine
# release history (<StateRoot>\install\release_history.json) names it, because
# the account owns and can write its lock. Setup adds the release its prior
# deployment record names before it writes the new record, so the first
# upgrade from 1.0.10 or older (and one from 1.0.3, whose signed-out Hermes
# accounts still wait) seeds it with the release it replaces. A first install
# adds nothing, a known release is not written again, and a history with a
# drifted access list is not carried forward. Runs in a disposable scratch
# directory; the protected writer and the access-list check are replaced.

[CmdletBinding()]
param(
    [string]$ScratchRoot = [IO.Path]::GetTempPath()
)

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

$root = [IO.Path]::Combine(
    [IO.Path]::GetFullPath($ScratchRoot),
    ('dc-release-history-' + [Guid]::NewGuid().ToString('N'))
)
[void][IO.Directory]::CreateDirectory($root)
try {
    $failures = & $module {
        param([string]$Root)
        $failures = [Collections.Generic.List[string]]::new()
        $install = [IO.Path]::Combine($Root, 'install')
        [void][IO.Directory]::CreateDirectory($install)
        $layout = @{ MetadataPath = [IO.Path]::Combine($install, 'deployment.json') }
        $path = [IO.Path]::Combine($install, 'release_history.json')
        $script:SmokeWrites = 0
        $script:SmokeAclDrift = $false
        function script:Write-DefenseClawJsonAtomic {
            param($Value, [string]$Path, [string]$Kind)
            if ($Kind -cne 'AdminFile') { throw "unexpected kind $Kind" }
            $script:SmokeWrites++
            [IO.File]::WriteAllText($Path, ($Value | Microsoft.PowerShell.Utility\ConvertTo-Json -Depth 4), [Text.UTF8Encoding]::new($false))
        }
        function script:Assert-DefenseClawCanonicalPathAcl {
            param([string]$Path, $Expected)
            if ($script:SmokeAclDrift) { throw "access list of $Path is not canonical" }
        }
        function script:New-DefenseClawCanonicalPathAcl {
            param([switch]$IsDirectory, [string]$Kind, [string]$GatewayServiceSID)
            if ($Kind -cne 'AdminFile') { throw "unexpected kind $Kind" }
            return [Security.AccessControl.FileSecurity]::new()
        }
        function Get-SmokeReleases {
            if (-not [IO.File]::Exists($path)) { return '<none>' }
            $record = [IO.File]::ReadAllText($path) | Microsoft.PowerShell.Utility\ConvertFrom-Json
            if ([string]$record.schema_version -cne '1') { return "<schema $($record.schema_version)>" }
            return (@($record.releases) -join ',')
        }
        function Assert-Smoke([string]$Label, [string]$Want, [int]$Writes) {
            $got = Get-SmokeReleases
            if ($got -cne $Want -or $script:SmokeWrites -ne $Writes) {
                $failures.Add("${Label}: releases '$got' after $($script:SmokeWrites) writes; want '$Want' after $Writes")
            }
        }
        function New-SmokeMetadata([string]$Version) {
            return [pscustomobject]@{ installed = $true; product_version = $Version }
        }

        Update-DefenseClawReleaseHistory -Layout $layout -PriorMetadata $null
        Assert-Smoke 'first install' '<none>' 0
        Update-DefenseClawReleaseHistory -Layout $layout -PriorMetadata ([pscustomobject]@{ installed = $true })
        Assert-Smoke 'a prior record without product_version' '<none>' 0
        Update-DefenseClawReleaseHistory -Layout $layout -PriorMetadata (New-SmokeMetadata '1.0.3')
        Assert-Smoke 'upgrade from 1.0.3 seeds it' '1.0.3' 1
        Update-DefenseClawReleaseHistory -Layout $layout -PriorMetadata (New-SmokeMetadata '1.0.3')
        Assert-Smoke 'a known release is not written again' '1.0.3' 1
        Update-DefenseClawReleaseHistory -Layout $layout -PriorMetadata (New-SmokeMetadata '1.0.10')
        Assert-Smoke 'the next upgrade adds its prior release' '1.0.3,1.0.10' 2
        Update-DefenseClawReleaseHistory -Layout $layout -PriorMetadata ([pscustomobject]@{ installed = $false; product_version = '1.0.11' })
        Assert-Smoke 'an uninstall tombstone release counts' '1.0.3,1.0.10,1.0.11' 3
        Update-DefenseClawReleaseHistory -Layout $layout -PriorMetadata (New-SmokeMetadata '1.0.12"; "x')
        Assert-Smoke 'a malformed release is not recorded' '1.0.3,1.0.10,1.0.11' 3

        [IO.File]::WriteAllText($path, '{"schema_version":1,"releases":["1.0.3","bad value","1.0.9"]}', [Text.UTF8Encoding]::new($false))
        Update-DefenseClawReleaseHistory -Layout $layout -PriorMetadata (New-SmokeMetadata '1.0.11')
        Assert-Smoke 'a malformed entry is dropped' '1.0.3,1.0.9,1.0.11' 4

        $script:SmokeAclDrift = $true
        Update-DefenseClawReleaseHistory -Layout $layout -PriorMetadata (New-SmokeMetadata '1.0.11')
        Assert-Smoke 'a history with a drifted access list is not carried forward' '1.0.11' 5
        $script:SmokeAclDrift = $false

        [IO.File]::WriteAllText($path, 'not json', [Text.UTF8Encoding]::new($false))
        Update-DefenseClawReleaseHistory -Layout $layout -PriorMetadata (New-SmokeMetadata '1.0.10')
        Assert-Smoke 'a history that does not parse is not carried forward' '1.0.10' 6

        # The install-like lifecycle records the prior release before it
        # writes the new deployment record.
        $body = (Get-Command Invoke-DefenseClawInstallLikeLifecycle -CommandType Function).Definition
        $update = $body.IndexOf('Update-DefenseClawReleaseHistory -Layout $Layout -PriorMetadata $metadata')
        $write = $body.IndexOf('Write-DefenseClawJsonAtomic -Value $newMetadata -Path $Layout.MetadataPath')
        if ($update -lt 0 -or $write -lt 0 -or $update -gt $write) {
            $failures.Add("the install-like lifecycle does not record the prior release before the new deployment record (update=$update write=$write)")
        }
        return , $failures
    } $root
}
finally {
    Microsoft.PowerShell.Management\Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}

if (@($failures).Count -gt 0) {
    foreach ($failure in $failures) {
        Microsoft.PowerShell.Utility\Write-Output "FAIL: $failure"
    }
    Microsoft.PowerShell.Utility\Write-Output 'enterprise-profile-release-history-smoke: FAIL'
    exit 1
}
Microsoft.PowerShell.Utility\Write-Output 'enterprise-profile-release-history-smoke: OK'
