# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 5.1

[CmdletBinding()]
param([string]$ScratchRoot = [IO.Path]::GetTempPath())

Microsoft.PowerShell.Core\Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$module = Microsoft.PowerShell.Core\Import-Module `
    -Name ([IO.Path]::GetFullPath((Microsoft.PowerShell.Management\Join-Path $PSScriptRoot '..\DefenseClawEnterprise.psm1'))) `
    -Force -PassThru -ErrorAction Stop
$state = [IO.Path]::Combine($ScratchRoot, ('dc-config-acl-' + [Guid]::NewGuid().ToString('N')))
$configDirectory = [IO.Path]::Combine($state, 'config')
$config = [IO.Path]::Combine($configDirectory, 'config.yaml')
[void][IO.Directory]::CreateDirectory($configDirectory)
[IO.File]::WriteAllText($config, "guardrail:\n  mode: observe\n")

try {
    & $module {
        param($State, $ConfigDirectory, $Config)
        $sid = 'S-1-5-80-1-2-3-4-5'
        $layout = @{
            StateRoot = $State
            ConfigDirectory = $ConfigDirectory
            ConfigPath = $Config
            RuntimeDirectory = [IO.Path]::Combine($State, 'runtime')
        }
        Set-DefenseClawPathAcl -Path $State -Kind StateDirectory -GatewayServiceSID $sid
        Set-DefenseClawPathAcl -Path $ConfigDirectory -Kind ConfigDirectory -GatewayServiceSID $sid
        Set-DefenseClawPathAcl -Path $Config -Kind ConfigFile -GatewayServiceSID $sid

        # A standard user can now edit the config before repair runs.
        $acl = Microsoft.PowerShell.Security\Get-Acl -LiteralPath $Config
        $users = [Security.Principal.SecurityIdentifier]::new($script:UsersSID)
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $users,
            [Security.AccessControl.FileSystemRights]::Write,
            [Security.AccessControl.AccessControlType]::Allow
        )
        [void]$acl.AddAccessRule($rule)
        Microsoft.PowerShell.Security\Set-Acl -LiteralPath $Config -AclObject $acl
        $script:repairCalls = 0
        function Get-DefenseClawServiceSID { return $sid }
        function Set-DefenseClawRetainedRuntimeAcls { $script:repairCalls++ }
        function Set-DefenseClawManagedCoreAcls { $script:repairCalls++ }

        $refused = $false
        try {
            [void](Repair-DefenseClawDeploymentAclDrift `
                -Layout $layout -GatewayServiceName 'DefenseClawGateway' `
                -RedactionKeyClass trusted_drift)
        }
        catch {
            $refused = $_.Exception.Message -match 'untrusted managed config path'
        }
        if (-not $refused -or $script:repairCalls -ne 0) {
            throw 'ACL repair accepted a user-writable config or changed ACLs before refusing it'
        }
        $after = Microsoft.PowerShell.Security\Get-Acl -LiteralPath $Config
        if (-not @($after.Access | Microsoft.PowerShell.Core\Where-Object {
            (ConvertTo-DefenseClawSID -Identity $_.IdentityReference) -eq $script:UsersSID -and
            (Test-DefenseClawWriteLikeRights -Rights $_.FileSystemRights)
        }).Count) {
            throw 'refused repair changed the config ACL'
        }

        # Trusted inherited ACL drift still permits the existing recovery path.
        Set-DefenseClawPathAcl -Path $Config -Kind ConfigFile -GatewayServiceSID $sid
        $trusted = Microsoft.PowerShell.Security\Get-Acl -LiteralPath $Config
        $trusted.SetAccessRuleProtection($false, $false)
        Microsoft.PowerShell.Security\Set-Acl -LiteralPath $Config -AclObject $trusted
        if (-not (Repair-DefenseClawDeploymentAclDrift `
            -Layout $layout -GatewayServiceName 'DefenseClawGateway' `
            -RedactionKeyClass trusted_drift) -or $script:repairCalls -ne 2) {
            throw 'trusted ACL drift was not repaired'
        }
    } $state $configDirectory $config
}
finally {
    Microsoft.PowerShell.Management\Remove-Item -LiteralPath $state -Recurse -Force -ErrorAction SilentlyContinue
}
Microsoft.PowerShell.Utility\Write-Output 'enterprise-standalone-config-acl-repair-smoke: OK'
