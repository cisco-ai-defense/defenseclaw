# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 5.1

# GAP-1061: /verify over a targets.yaml whose bytes the guardian did not
# activate leads with the untrusted account when one can write the file, and
# never tells the administrator to wait for the guardian then.

[CmdletBinding()]
param([string]$ScratchRoot = [IO.Path]::GetTempPath())

Microsoft.PowerShell.Core\Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$module = Microsoft.PowerShell.Core\Import-Module `
    -Name ([IO.Path]::GetFullPath((Microsoft.PowerShell.Management\Join-Path $PSScriptRoot '..\DefenseClawEnterprise.psm1'))) `
    -Force -PassThru -ErrorAction Stop
$state = [IO.Path]::Combine($ScratchRoot, ('dc-verify-order-' + [Guid]::NewGuid().ToString('N')))
[void][IO.Directory]::CreateDirectory($state)

try {
    & $module {
        param($State)
        $manifest = [IO.Path]::Combine($State, 'targets.yaml')
        [IO.File]::WriteAllText($manifest, "version: 1`ntargets: []`n")
        Set-DefenseClawPathAcl -Path $State -Kind StateDirectory -GatewayServiceSID $script:AdministratorsSID
        Set-DefenseClawPathAcl -Path $manifest -Kind AdminFile -GatewayServiceSID $script:AdministratorsSID
        $layout = @{ ManifestPath = $manifest }

        # Secure Client: never judged here.
        function Test-DefenseClawStandaloneProfile { return $false }
        Add-Content -LiteralPath $manifest -Value '# changed'
        $acl = Microsoft.PowerShell.Security\Get-Acl -LiteralPath $manifest
        [void]$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($script:UsersSID),
            [Security.AccessControl.FileSystemRights]::Modify,
            [Security.AccessControl.AccessControlType]::Allow))
        Microsoft.PowerShell.Security\Set-Acl -LiteralPath $manifest -AclObject $acl
        Assert-DefenseClawManifestNotUntrustedBeforeBinding -Layout $layout

        function Test-DefenseClawStandaloneProfile { return $true }
        $message = ''
        try { Assert-DefenseClawManifestNotUntrustedBeforeBinding -Layout $layout } catch { $message = $_.Exception.Message }
        $lead = 'untrusted principal ' + $script:UsersSID + ' has write-like access to managed path: ' + $manifest
        if (-not $message.StartsWith($lead) -or $message -match 'guardian') {
            throw "the untrusted manifest is not named first, or the message waits for the guardian: '$message'"
        }

        # Nothing untrusted: the check is silent, so the wait for the guardian stays the answer.
        Set-DefenseClawPathAcl -Path $manifest -Kind AdminFile -GatewayServiceSID $script:AdministratorsSID
        Assert-DefenseClawManifestNotUntrustedBeforeBinding -Layout $layout
    } $state
}
finally {
    Microsoft.PowerShell.Management\Remove-Item -LiteralPath $state -Recurse -Force -ErrorAction SilentlyContinue
}
Microsoft.PowerShell.Utility\Write-Output 'enterprise-policy-verify-order-smoke: OK'
