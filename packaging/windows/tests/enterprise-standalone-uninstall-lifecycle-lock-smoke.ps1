# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

# GAP-1897: a standalone uninstall that leaves no StateRoot and no
# InstallRoot drops the lifecycle lock and its empty folder whatever path
# removed the deployment (a PURGE=1 over a 1.0.2 tombstone set no flag);
# an uninstall that keeps either root, and every other action, keep it.

#Requires -Version 5.1

[CmdletBinding()]
param()

Microsoft.PowerShell.Core\Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modulePath = [IO.Path]::GetFullPath(
    (Microsoft.PowerShell.Management\Join-Path $PSScriptRoot '..\DefenseClawEnterprise.psm1')
)
$module = Microsoft.PowerShell.Core\Import-Module -Name $modulePath -Force -PassThru -ErrorAction Stop
$root = Microsoft.PowerShell.Management\Join-Path ([IO.Path]::GetTempPath()) ("dc-lock-" + [guid]::NewGuid().ToString('N'))
[void](Microsoft.PowerShell.Management\New-Item -ItemType Directory -Path $root)
try {
    $failures = & $module {
        param($root)
        $failures = [Collections.Generic.List[string]]::new()
        $script:DefenseClawEnterpriseProfile = 'Standalone'
        $layout = @{
            StateRoot = (Microsoft.PowerShell.Management\Join-Path $root 'state')
            InstallRoot = (Microsoft.PowerShell.Management\Join-Path $root 'install')
        }
        if (-not (Test-DefenseClawStandaloneUninstallLeftNothing -Action 'Uninstall' -Layout $layout)) {
            $failures.Add('an uninstall that left no roots keeps the lifecycle lock')
        }
        if (Test-DefenseClawStandaloneUninstallLeftNothing -Action 'Repair' -Layout $layout) {
            $failures.Add('a repair drops the lifecycle lock')
        }
        [void](Microsoft.PowerShell.Management\New-Item -ItemType Directory -Path $layout.StateRoot)
        if (Test-DefenseClawStandaloneUninstallLeftNothing -Action 'Uninstall' -Layout $layout) {
            $failures.Add('an uninstall that kept StateRoot drops the lifecycle lock')
        }
        $script:DefenseClawEnterpriseProfile = 'SecureClient'
        Microsoft.PowerShell.Management\Remove-Item -LiteralPath $layout.StateRoot -Force
        if (Test-DefenseClawStandaloneUninstallLeftNothing -Action 'Uninstall' -Layout $layout) {
            $failures.Add('a Secure Client uninstall drops the standalone lifecycle lock')
        }
        return , $failures
    } $root
}
finally {
    Microsoft.PowerShell.Management\Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}

if ($failures.Count -gt 0) {
    foreach ($failure in $failures) {
        Microsoft.PowerShell.Utility\Write-Output "FAIL: $failure"
    }
    exit 1
}
Microsoft.PowerShell.Utility\Write-Output 'enterprise-standalone-uninstall-lifecycle-lock-smoke: OK'
