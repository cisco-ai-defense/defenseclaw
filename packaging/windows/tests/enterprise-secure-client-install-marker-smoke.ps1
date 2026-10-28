# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 5.1

# The Secure Client install marker (InstallRoot\secure-client.install) is
# what the strict Secure Client host classifier requires. A Secure Client
# layout carries no BrokerEnabled key (an absent key is its broker
# deployment), so a marker gate that required the key never wrote it, and
# every Secure Client install ran its hooks as if it were not one. Only a
# standalone layout, which sets BrokerEnabled to false, gets no marker. The
# marker's ACL write is stubbed: it needs real service SIDs and is covered by
# the exact ACL smoke.

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

$scratch = [IO.Path]::Combine(
    $ScratchRoot,
    'dc-sc-marker-' + [guid]::NewGuid().ToString('N')
)
[void](Microsoft.PowerShell.Management\New-Item -ItemType Directory -Path $scratch)
try {
    $result = & $module {
        param([string]$Scratch)
        $script:MarkerAclWrites = 0
        Microsoft.PowerShell.Management\Set-Item -Path function:script:Set-DefenseClawPathAcl -Value {
            param($Path, $Kind, $GatewayServiceSID)
            if ($Kind -cne 'SecureClientMarkerDirectory') {
                throw "unexpected ACL kind $Kind"
            }
            $script:MarkerAclWrites++
        }
        $secureClient = @{ InstallRoot = [IO.Path]::Combine($Scratch, 'secure-client') }
        $standalone = @{
            InstallRoot = [IO.Path]::Combine($Scratch, 'standalone')
            Profile = 'Standalone'
            BrokerEnabled = $false
        }
        foreach ($layout in @($secureClient, $standalone)) {
            [void](Microsoft.PowerShell.Management\New-Item -ItemType Directory -Path $layout.InstallRoot)
            Set-DefenseClawSecureClientInstallMarker -Layout $layout -GatewayServiceSID 'S-1-5-80-0'
        }
        [pscustomobject]@{
            SecureClient = Microsoft.PowerShell.Management\Test-Path `
                -LiteralPath ([IO.Path]::Combine($secureClient.InstallRoot, 'secure-client.install')) `
                -PathType Container
            Standalone = Microsoft.PowerShell.Management\Test-Path `
                -LiteralPath ([IO.Path]::Combine($standalone.InstallRoot, 'secure-client.install'))
            AclWrites = $script:MarkerAclWrites
        }
    } $scratch
    if (-not $result.SecureClient) {
        throw 'a Secure Client layout (no BrokerEnabled key) got no install marker'
    }
    if ($result.Standalone) {
        throw 'a standalone layout got the Secure Client install marker'
    }
    if ($result.AclWrites -ne 1) {
        throw "marker ACL writes = $($result.AclWrites), want 1"
    }
    Microsoft.PowerShell.Utility\Write-Output 'enterprise-secure-client-install-marker-smoke: PASS'
}
finally {
    Microsoft.PowerShell.Management\Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue
}
