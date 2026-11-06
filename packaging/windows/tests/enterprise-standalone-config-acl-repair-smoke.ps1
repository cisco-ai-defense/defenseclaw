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
            $refused = $_.Exception.Message -match 'untrusted managed config path' -and
                $_.Exception.Message -match 'Setup /ensure CONFIG='
        }
        if (-not $refused -or $script:repairCalls -ne 0) {
            throw 'ACL repair accepted a user-writable config, changed ACLs before refusing it, or named no recovery'
        }

        # GAP-0590: the transaction asks the same question read-only before
        # it stops any service; the answer is the same refusal, with nothing
        # changed.
        $checkRefused = $false
        try {
            [void](Repair-DefenseClawDeploymentAclDrift `
                -Layout $layout -GatewayServiceName 'DefenseClawGateway' `
                -RedactionKeyClass trusted_drift -CheckOnly)
        }
        catch {
            $checkRefused = $_.Exception.Message -match 'untrusted managed config path'
        }
        if (-not $checkRefused -or $script:repairCalls -ne 0) {
            throw 'the read-only drift check did not refuse a user-writable config, or changed ACLs'
        }

        # GAP-0590: the content gate an install-like lifecycle runs before any
        # service stops refuses every managed content path another account can
        # change, names it and its recovery, and changes nothing. It runs only
        # on the standalone profile, whose verdicts it uses.
        function Test-DefenseClawStandaloneProfile { return $true }
        $manifest = [IO.Path]::Combine($State, 'targets.yaml')
        $metadata = [IO.Path]::Combine($State, 'deployment.json')
        foreach ($file in @($manifest, $metadata)) {
            [IO.File]::WriteAllText($file, '{}')
            Set-DefenseClawPathAcl -Path $file -Kind AdminFile -GatewayServiceSID $script:AdministratorsSID
        }
        $gateLayout = @{
            StateRoot = $State
            ConfigDirectory = $ConfigDirectory
            ConfigPath = $Config
            ManifestPath = $manifest
            MetadataPath = $metadata
            CodexTargetEnabled = $false
        }
        function Assert-GateRefuses([string]$Path, [string]$Recovery) {
            $message = ''
            try {
                Assert-DefenseClawStandaloneContentTrusted -Layout $gateLayout
            }
            catch {
                $message = $_.Exception.Message
            }
            if (-not $message.Contains($Path) -or -not $message.Contains($Recovery) -or
                -not $message.StartsWith('refusing to change the deployment, and nothing was changed')) {
                throw "content gate on ${Path}: '$message'"
            }
        }
        function Add-UsersWrite([string]$Path, [string]$Rights = 'Write') {
            $acl = Microsoft.PowerShell.Security\Get-Acl -LiteralPath $Path
            [void]$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                [Security.Principal.SecurityIdentifier]::new($script:UsersSID),
                [Security.AccessControl.FileSystemRights]$Rights,
                [Security.AccessControl.AccessControlType]::Allow))
            Microsoft.PowerShell.Security\Set-Acl -LiteralPath $Path -AclObject $acl
        }
        Assert-GateRefuses -Path $Config -Recovery 'Setup /ensure CONFIG=<the approved administrator-only config>'
        if (-not @((Microsoft.PowerShell.Security\Get-Acl -LiteralPath $Config).Access | Microsoft.PowerShell.Core\Where-Object {
            (ConvertTo-DefenseClawSID -Identity $_.IdentityReference) -eq $script:UsersSID
        }).Count) {
            throw 'the content gate changed the config ACL'
        }
        Set-DefenseClawPathAcl -Path $Config -Kind ConfigFile -GatewayServiceSID $sid
        Assert-DefenseClawStandaloneContentTrusted -Layout $gateLayout
        Add-UsersWrite -Path $manifest
        Assert-GateRefuses -Path $manifest -Recovery 'Setup writes a new targets.yaml enumerated from it'
        Set-DefenseClawPathAcl -Path $manifest -Kind AdminFile -GatewayServiceSID $script:AdministratorsSID
        Add-UsersWrite -Path $metadata
        Assert-GateRefuses -Path $metadata -Recovery 'remove that entry, or give the file back to Administrators'
        Set-DefenseClawPathAcl -Path $metadata -Kind AdminFile -GatewayServiceSID $script:AdministratorsSID
        # Modify, as icacls /grant (M) plants it, and an entry that only adds
        # children, which could plant a file the lifecycle reads.
        foreach ($rights in 'Modify', 'Write') {
            Add-UsersWrite -Path $ConfigDirectory -Rights $rights
            Assert-GateRefuses -Path $ConfigDirectory -Recovery 'remove that entry, or give the folder back to Administrators'
            Set-DefenseClawPathAcl -Path $ConfigDirectory -Kind ConfigDirectory -GatewayServiceSID $sid
        }
        Assert-DefenseClawStandaloneContentTrusted -Layout $gateLayout
        if ($script:repairCalls -ne 0) {
            throw 'the content gate repaired ACLs'
        }

        # GAP-0603: every Setup-owned record kind and both content files,
        # each with an untrusted owner and a canonical ACL, an untrusted entry
        # and an administrator owner, and both: refused before the stop and
        # named, nothing changed. The standalone self-heal leaves an
        # untrusted owner and a missing DACL as they are; Secure Client still
        # repairs, and Setup's own account as owner is still repaired.
        $users = $script:UsersSID
        function Get-OwnerSID([string]$Path) {
            return Get-DefenseClawAclOwnerSID -Acl (Microsoft.PowerShell.Security\Get-Acl -LiteralPath $Path)
        }
        function Set-TestOwner([string]$Path, [string]$SID) {
            $out = & icacls.exe $Path /setowner "*$SID" 2>&1
            if ($LASTEXITCODE -ne 0) { throw "icacls /setowner $SID ${Path}: $out" }
        }
        foreach ($name in @(
            'deployment.json', 'agent-application-control-attestation.json', 'codex-requirements-ownership.json',
            'codex-requirements-acl-backup.json', 'managed-hooks-lifecycle.json', 'managed-hooks-teardown.json'
        )) {
            $file = [IO.Path]::Combine($State, $name)
            [IO.File]::WriteAllText($file, '{}')
            Set-DefenseClawPathAcl -Path $file -Kind AdminFile -GatewayServiceSID $script:AdministratorsSID
        }
        $kinds = [ordered]@{
            MetadataPath = 'deployment.json'
            AgentApplicationControlAttestationPath = 'agent-application-control-attestation.json'
            CodexRequirementsOwnershipPath = 'codex-requirements-ownership.json'
            CodexRequirementsAclBackupPath = 'codex-requirements-acl-backup.json'
            ManagedHooksLifecycleJournalPath = 'managed-hooks-lifecycle.json'
            ManagedHooksTeardownJournalPath = 'managed-hooks-teardown.json'
        }
        foreach ($key in $kinds.Keys) {
            $gateLayout[$key] = [IO.Path]::Combine($State, $kinds[$key])
        }
        $variants = @(
            @{ Name = 'owner'; Owner = $true; Entry = $false },
            @{ Name = 'entry'; Owner = $false; Entry = $true },
            @{ Name = 'both'; Owner = $true; Entry = $true }
        )
        foreach ($key in @($kinds.Keys) + @('ConfigPath', 'ManifestPath')) {
            $path = [string]$gateLayout[$key]
            $kind = if ($key -eq 'ConfigPath') { 'ConfigFile' } else { 'AdminFile' }
            $gatewaySID = if ($key -eq 'ConfigPath') { $sid } else { $script:AdministratorsSID }
            $recovery = switch ($key) {
                'ConfigPath' { 'Setup /ensure CONFIG=<the approved administrator-only config>' }
                'ManifestPath' { 'Setup writes a new targets.yaml enumerated from it' }
                default { 'remove that entry, or give the file back to Administrators' }
            }
            foreach ($variant in $variants) {
                if ($variant.Owner) { Set-TestOwner -Path $path -SID $users }
                if ($variant.Entry) { Add-UsersWrite -Path $path -Rights Modify }
                $before = (Microsoft.PowerShell.Security\Get-Acl -LiteralPath $path).Sddl
                Assert-GateRefuses -Path $path -Recovery $recovery
                if ((Microsoft.PowerShell.Security\Get-Acl -LiteralPath $path).Sddl -cne $before) {
                    throw "the content gate changed $key ($($variant.Name))"
                }
                Set-TestOwner -Path $path -SID $script:AdministratorsSID
                Set-DefenseClawPathAcl -Path $path -Kind $kind -GatewayServiceSID $gatewaySID
            }
        }
        Assert-DefenseClawStandaloneContentTrusted -Layout $gateLayout

        # The self-heal path itself (Verify, the attestation, the journals and
        # the Codex records read through it).
        $healed = [IO.Path]::Combine($State, 'self-heal.json')
        [IO.File]::WriteAllText($healed, '{}')
        Set-DefenseClawPathAcl -Path $healed -Kind AdminFile -GatewayServiceSID $script:AdministratorsSID
        $writers = @($script:SystemSID, $script:AdministratorsSID, $script:TrustedInstallerSID)
        Set-TestOwner -Path $healed -SID $users
        $healError = ''
        try {
            Assert-DefenseClawPathAcl -Path $healed -AllowedWriterSIDs $writers `
                -SelfHealKind AdminFile -SelfHealGatewayServiceSID $script:AdministratorsSID
        }
        catch {
            $healError = $_.Exception.Message
        }
        if ($healError -notmatch [regex]::Escape("untrusted owner $users on managed path: $healed") -or
            (Get-OwnerSID -Path $healed) -ne $users) {
            throw "standalone self-heal re-stamped an untrusted owner in place: '$healError', owner $(Get-OwnerSID -Path $healed)"
        }
        Add-UsersWrite -Path $healed -Rights Modify
        $healError = ''
        try {
            Assert-DefenseClawPathAcl -Path $healed -AllowedWriterSIDs $writers `
                -SelfHealKind AdminFile -SelfHealGatewayServiceSID $script:AdministratorsSID
        }
        catch {
            $healError = $_.Exception.Message
        }
        if (-not $healError -or (Get-OwnerSID -Path $healed) -ne $users) {
            throw "standalone self-heal re-stamped an untrusted owner and entry in place: '$healError'"
        }
        # Secure Client keeps repairing a foreign owner (unchanged there).
        function Test-DefenseClawStandaloneProfile { return $false }
        Assert-DefenseClawPathAcl -Path $healed -AllowedWriterSIDs $writers `
            -SelfHealKind AdminFile -SelfHealGatewayServiceSID $script:AdministratorsSID
        if ((Get-OwnerSID -Path $healed) -ne $script:AdministratorsSID) {
            throw 'Secure Client self-heal no longer repairs a foreign owner'
        }
        function Test-DefenseClawStandaloneProfile { return $true }
        # Setup's own account as owner is still repaired on standalone.
        $self = Get-DefenseClawCurrentProcessUserSID
        if ($self -notin $writers) {
            Set-TestOwner -Path $healed -SID $self
            Assert-DefenseClawPathAcl -Path $healed -AllowedWriterSIDs $writers `
                -SelfHealKind AdminFile -SelfHealGatewayServiceSID $script:AdministratorsSID
            if ((Get-OwnerSID -Path $healed) -ne $script:AdministratorsSID) {
                throw "standalone self-heal refused Setup's own account as owner"
            }
        }
        # GAP-0603 review M1: an untrusted owner or writer beside a verdict
        # the re-stamp may repair (a deny entry the owner's WRITE_DAC planted,
        # SYSTEM's or the gateway's rights removed) is refused, with the owner
        # and the access list as they were. Before, the re-stamp healed both
        # and the second reading accepted the file.
        $required = New-DefenseClawRequiredRights -Kind Config -GatewayServiceSID $sid
        function Remove-TestEntry([string]$Path, [string]$SID) {
            $acl = Microsoft.PowerShell.Security\Get-Acl -LiteralPath $Path
            foreach ($rule in @($acl.Access)) {
                if ((ConvertTo-DefenseClawSID -Identity $rule.IdentityReference) -eq $SID) {
                    [void]$acl.RemoveAccessRuleSpecific($rule)
                }
            }
            Microsoft.PowerShell.Security\Set-Acl -LiteralPath $Path -AclObject $acl
        }
        function Add-TestDeny([string]$Path) {
            $acl = Microsoft.PowerShell.Security\Get-Acl -LiteralPath $Path
            [void]$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                [Security.Principal.SecurityIdentifier]::new($script:UsersSID),
                [Security.AccessControl.FileSystemRights]::Write,
                [Security.AccessControl.AccessControlType]::Deny))
            Microsoft.PowerShell.Security\Set-Acl -LiteralPath $Path -AclObject $acl
        }
        function Invoke-TestHeal {
            Assert-DefenseClawPathAcl -Path $healed -AllowedWriterSIDs $writers -RequiredRights $required `
                -SelfHealKind ConfigFile -SelfHealGatewayServiceSID $sid
        }
        $mixed = [ordered]@{
            'an untrusted owner and a deny entry' = { Set-TestOwner -Path $healed -SID $users; Add-TestDeny -Path $healed }
            "an untrusted owner without SYSTEM's rights" = {
                Set-TestOwner -Path $healed -SID $users; Remove-TestEntry -Path $healed -SID $script:SystemSID
            }
            "an untrusted owner without the gateway's rights" = {
                Set-TestOwner -Path $healed -SID $users; Remove-TestEntry -Path $healed -SID $sid
            }
            'an untrusted writer and a missing right' = {
                Add-UsersWrite -Path $healed -Rights Modify; Remove-TestEntry -Path $healed -SID $sid
            }
        }
        foreach ($name in @($mixed.Keys)) {
            Set-DefenseClawPathAcl -Path $healed -Kind ConfigFile -GatewayServiceSID $sid
            & $mixed[$name]
            $before = (Microsoft.PowerShell.Security\Get-Acl -LiteralPath $healed).Sddl
            $healError = ''
            try { Invoke-TestHeal } catch { $healError = $_.Exception.Message }
            if (-not $healError.StartsWith('refusing to re-stamp a managed path in place') -or
                -not $healError.Contains($healed) -or
                (Microsoft.PowerShell.Security\Get-Acl -LiteralPath $healed).Sddl -cne $before) {
                throw "standalone self-heal re-stamped $name in place: '$healError'"
            }
        }
        # Twins: a trusted owner with a deny entry is still repaired, and so
        # is Setup's own account as owner; Secure Client still repairs the
        # untrusted owner with a deny entry.
        $twins = @(@($script:AdministratorsSID, $true))
        if ($self -notin $writers) { $twins += , @($self, $true) }
        $twins += , @($users, $false)
        foreach ($twin in $twins) {
            Set-DefenseClawPathAcl -Path $healed -Kind ConfigFile -GatewayServiceSID $sid
            Set-TestOwner -Path $healed -SID $twin[0]
            Add-TestDeny -Path $healed
            if (-not $twin[1]) { function Test-DefenseClawStandaloneProfile { return $false } }
            Invoke-TestHeal
            function Test-DefenseClawStandaloneProfile { return $true }
            if ((Get-OwnerSID -Path $healed) -ne $script:AdministratorsSID -or
                @((Microsoft.PowerShell.Security\Get-Acl -LiteralPath $healed).Access | Microsoft.PowerShell.Core\Where-Object {
                    $_.AccessControlType -eq [Security.AccessControl.AccessControlType]::Deny
                }).Count) {
                throw "self-heal did not repair a deny entry with owner $($twin[0]) (standalone $($twin[1]))"
            }
        }
        Add-UsersWrite -Path $Config
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
        # Trusted-only drift passes the content gate for the repair to put back.
        Assert-DefenseClawStandaloneContentTrusted -Layout $gateLayout
        if (-not (Repair-DefenseClawDeploymentAclDrift `
            -Layout $layout -GatewayServiceName 'DefenseClawGateway' `
            -RedactionKeyClass trusted_drift -CheckOnly) -or $script:repairCalls -ne 0) {
            throw 'the read-only drift check refused trusted ACL drift or repaired it'
        }
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
