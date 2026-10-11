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

        # Recovering a quiescing intent must refuse the same config: putting
        # the canonical ACL back and restarting would trust the user's edits.
        $id = [Guid]::NewGuid().ToString('N')
        $layout.InstallRoot = [IO.Path]::Combine($State, 'install')
        $layout.TransactionsDirectory = [IO.Path]::Combine($State, 'transactions')
        $layout.PendingPath = [IO.Path]::Combine($State, 'pending.json')
        $layout.GatewayPath = [IO.Path]::Combine($State, 'install', 'defenseclaw-gateway.exe')
        $layout.ManifestPath = [IO.Path]::Combine($State, 'targets.yaml')
        $layout.CertificationCodexHome = ''
        $layout.CoreHardeningCertification = $false
        $layout.BrokerEnabled = $false
        $intent = [pscustomobject]@{
            schema_version = 1
            phase = 'quiescing'
            id = $id
            install_root = $layout.InstallRoot
            state_root = $State
            gateway_service = 'DefenseClawGateway'
            guardian_service = 'DefenseClawHookGuardian'
            certification_codex_home = ''
            core_hardening_certification = $false
            prior_deployment_active = $true
            directory = [IO.Path]::Combine($layout.TransactionsDirectory, $id)
            services = @(
                [pscustomobject]@{ name = 'DefenseClawGateway'; existed = $true; running = $true },
                [pscustomobject]@{ name = 'DefenseClawHookGuardian'; existed = $true; running = $true }
            )
        }
        [IO.File]::WriteAllText($layout.PendingPath, '{}')
        $script:started = 0
        function Assert-DefenseClawOwnedServiceOrAbsent { }
        function Test-DefenseClawServiceExists { return $true }
        function Set-DefenseClawServiceStartMode { }
        function Stop-DefenseClawService { }
        function Set-DefenseClawServiceActivationPhase { }
        function Test-DefenseClawStandaloneProfile { return $true }
        function Start-DefenseClawTransactionServices { $script:started++ }
        $recoveryError = ''
        try {
            Recover-DefenseClawQuiescingIntent `
                -Intent $intent -Layout $layout `
                -GatewayServiceName 'DefenseClawGateway' `
                -GuardianServiceName 'DefenseClawHookGuardian'
        }
        catch {
            $recoveryError = $_.Exception.Message
        }
        if ($recoveryError -notmatch 'refusing to recover the pending lifecycle transaction' -or
            $script:repairCalls -ne 0 -or $script:started -ne 0 -or
            -not [IO.File]::Exists($layout.PendingPath)) {
            throw "quiescing recovery trusted a user-writable config: '$recoveryError', ACL calls $($script:repairCalls), starts $($script:started)"
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
