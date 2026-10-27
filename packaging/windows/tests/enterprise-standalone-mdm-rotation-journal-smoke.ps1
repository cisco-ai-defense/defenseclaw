# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

# GAP-1615 class on Windows: once an uninstall removed the deployment and its
# credentials, the MDM kit's credential rotation journal goes whichever route
# ran the uninstall. Each entry (it can hold a plaintext copy of an earlier
# credential) is overwritten with zeros and deleted, with the folder and
# rotation.lock; a journal holding a folder is left as it is; -Purge removes
# the empty kit state folder.

#Requires -Version 5.1

[CmdletBinding()]
param()

Microsoft.PowerShell.Core\Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modulePath = [IO.Path]::GetFullPath(
    (Microsoft.PowerShell.Management\Join-Path $PSScriptRoot '..\DefenseClawEnterprise.psm1')
)
$module = Microsoft.PowerShell.Core\Import-Module -Name $modulePath -Force -PassThru -ErrorAction Stop
$root = Microsoft.PowerShell.Management\Join-Path ([IO.Path]::GetTempPath()) ("dc-mdm-" + [guid]::NewGuid().ToString('N'))
try {
    $failures = & $module {
        param($root)
        $failures = [Collections.Generic.List[string]]::new()
        function Assert-DefenseClawPathAcl { param($Path, $AllowedWriterSIDs) }
        $journal = [IO.Path]::Combine($root, 'rotation')
        [void][IO.Directory]::CreateDirectory($journal)
        [IO.File]::WriteAllText([IO.Path]::Combine($journal, 'ai-defense-api-key.value'), 'old-secret')
        [IO.File]::WriteAllText([IO.Path]::Combine($root, 'rotation.lock'), '')
        Remove-DefenseClawMdmRotationJournal -StateDirectory $root -WarningAction SilentlyContinue
        if ([IO.Directory]::Exists($journal) -or [IO.File]::Exists([IO.Path]::Combine($root, 'rotation.lock'))) {
            $failures.Add('the rotation journal or its lock survived the uninstall')
        }
        if (-not [IO.Directory]::Exists($root)) {
            $failures.Add('an uninstall without purge removed the kit state folder')
        }
        [void][IO.Directory]::CreateDirectory([IO.Path]::Combine($journal, 'foreign'))
        Remove-DefenseClawMdmRotationJournal -StateDirectory $root -WarningAction SilentlyContinue
        if (-not [IO.Directory]::Exists([IO.Path]::Combine($journal, 'foreign'))) {
            $failures.Add('a journal holding a folder was not left as it is')
        }
        [IO.Directory]::Delete($journal, $true)
        Remove-DefenseClawMdmRotationJournal -StateDirectory $root -Purge -WarningAction SilentlyContinue
        if ([IO.Directory]::Exists($root)) {
            $failures.Add('a purge left the empty kit state folder')
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
Microsoft.PowerShell.Utility\Write-Output 'enterprise-standalone-mdm-rotation-journal-smoke: OK'
