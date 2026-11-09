# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 5.1

# GAP-0602, GAP-0603: a Setup-owned record (the deployment record, the
# application-control attestation) that another account owns or can write is
# never trusted in place. Setup keeps it aside, administrators only, and
# writes the record again; a folder another account can change is refused; the
# refusal names the exact commands. Fixtures: the untrusted owner and writer
# are planted directly with icacls (Administrators or SYSTEM runs this; no
# second account is used).

[CmdletBinding()]
param([string]$ScratchRoot = [IO.Path]::GetTempPath())

Microsoft.PowerShell.Core\Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$module = Microsoft.PowerShell.Core\Import-Module `
    -Name ([IO.Path]::GetFullPath((Microsoft.PowerShell.Management\Join-Path $PSScriptRoot '..\DefenseClawEnterprise.psm1'))) `
    -Force -PassThru -ErrorAction Stop
$state = [IO.Path]::Combine($ScratchRoot, ('dc-record-recovery-' + [Guid]::NewGuid().ToString('N')))
[void][IO.Directory]::CreateDirectory($state)

try {
    & $module {
        param($State)
        function Test-DefenseClawStandaloneProfile { return $true }
        $script:rebuilds = [Collections.Generic.List[string]]::new()
        $script:rebuildFails = $false
        $script:approvedCarried = $null
        $script:serviceRegistered = $true
        $script:failKeptStamp = $false
        function Repair-DefenseClawUnreadableDeploymentMetadata {
            param($Layout, $Sources, $GatewayServiceName, $GuardianServiceName, [string]$RebuildBecause = '', $ApprovedPolicySources = $null)
            if ($script:rebuildFails) { throw 'the rebuild write failed (fixture)' }
            $script:rebuilds.Add($RebuildBecause)
            $script:approvedCarried = $ApprovedPolicySources
            [IO.File]::WriteAllText($Layout.MetadataPath, '{"installed":true,"rebuilt":true}')
            return $true
        }
        function Test-DefenseClawServiceExists { param([string]$Name) return $script:serviceRegistered }
        function Assert-DefenseClawOwnedServiceOrAbsent { param($Name, $ExpectedGatewayPath) }
        $originalStamp = Get-Command -Name Set-DefenseClawPathAcl -CommandType Function
        function Set-DefenseClawPathAcl {
            param([string]$Path, [string]$Kind, [string]$GatewayServiceSID)
            if ($script:failKeptStamp -and $Path -like '*.rejected-*') { throw 'a program holds the file open (fixture)' }
            & $originalStamp -Path $Path -Kind $Kind -GatewayServiceSID $GatewayServiceSID
        }
        $full = @{}
        foreach ($artifact in @('gateway', 'acp', 'hook', 'sensor_helper', 'installer', 'module')) { $full[$artifact] = @{ sha256 = ('a' * 64) } }
        $sid = 'S-1-5-80-1-2-3-4-5'
        $install = [IO.Path]::Combine($State, 'install')
        [void][IO.Directory]::CreateDirectory($install)
        Set-DefenseClawPathAcl -Path $State -Kind StateDirectory -GatewayServiceSID $sid
        Set-DefenseClawPathAcl -Path $install -Kind AdminDirectory -GatewayServiceSID $script:AdministratorsSID
        $metadata = [IO.Path]::Combine($install, 'deployment.json')
        $attestation = [IO.Path]::Combine($install, 'agent-application-control-attestation.json')
        $layout = @{
            MetadataPath = $metadata
            AgentApplicationControlAttestationPath = $attestation
            PendingPath = [IO.Path]::Combine($install, 'pending.json')
            CLIPath = [IO.Path]::Combine($State, 'absent-cli.exe')
            GatewayPath = [IO.Path]::Combine($State, 'gateway.exe')
        }
        function New-Record([string]$Path, [string]$Text) {
            [IO.File]::WriteAllText($Path, $Text)
            Set-DefenseClawPathAcl -Path $Path -Kind AdminFile -GatewayServiceSID $script:AdministratorsSID
        }
        function Reset-Records {
            foreach ($path in @($metadata, $attestation)) {
                foreach ($leftover in @(Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $install -Force -Filter ((Split-Path $path -Leaf) + '*'))) {
                    Microsoft.PowerShell.Management\Remove-Item -LiteralPath $leftover.FullName -Force
                }
            }
            $script:rebuilds.Clear()
            New-Record $metadata '{"installed":true}'
            New-Record $attestation '{"agent_application_control_enforced":false}'
        }
        function Plant-Writer([string]$Path) { & icacls.exe $Path /grant '*S-1-5-32-545:(M)' | Out-Null }
        function Plant-Owner([string]$Path) { & icacls.exe $Path /setowner '*S-1-5-32-545' | Out-Null }
        function Kept([string]$Leaf) {
            return @(Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $install -Force -Filter ($Leaf + '.rejected-*'))
        }

        # No tamper: a healthy host moves nothing aside and rebuilds nothing.
        Reset-Records
        if ((Get-DefenseClawStandaloneRecordUntrustedReason -Path $metadata) -ne '') { throw 'a trusted record was judged untrusted' }
        if ((Get-DefenseClawStandaloneRecordUntrustedReason -Path ([IO.Path]::Combine($install, 'absent.json'))) -ne '') { throw 'a missing record was judged untrusted' }
        for ($pass = 0; $pass -lt 2; $pass++) {
            $kept = @(Invoke-DefenseClawStandaloneRecordRecovery -Layout $layout -Sources $full -GatewayServiceName 'G' -GuardianServiceName 'H')
            if ($kept.Count -ne 0 -or $script:rebuilds.Count -ne 0 -or @(Kept 'deployment.json').Count -ne 0 -or @(Kept 'agent-application-control-attestation.json').Count -ne 0) {
                throw 'a healthy host had a record moved aside or rebuilt'
            }
        }

        # The judgement: an entry, an owner, both. Each names the account.
        Plant-Writer $metadata
        $reason = Get-DefenseClawStandaloneRecordUntrustedReason -Path $metadata
        if ($reason -notmatch 'untrusted principal S-1-5-32-545 has write-like access') { throw "writer not judged: $reason" }
        $refusal = Format-DefenseClawUntrustedRecordRefusal -Path $metadata -Reason $reason
        if ($refusal -notmatch '^untrusted_record: ' -or
            $refusal -notmatch [regex]::Escape("icacls `"$metadata`" /remove:g *S-1-5-32-545") -or
            $refusal -notmatch '/repair') {
            throw "the refusal does not carry the code and the exact commands: $refusal"
        }
        Reset-Records
        Plant-Owner $metadata
        $reason = Get-DefenseClawStandaloneRecordUntrustedReason -Path $metadata
        if ($reason -notmatch 'untrusted owner S-1-5-32-545') { throw "owner not judged: $reason" }
        $refusal = Format-DefenseClawUntrustedRecordRefusal -Path $metadata -Reason $reason
        if ($refusal -notmatch [regex]::Escape("icacls `"$metadata`" /setowner *S-1-5-32-544")) { throw "owner fix not exact: $refusal" }

        # Recovery: the changed record is kept aside (same bytes, administrators
        # only, a new object path), the live path is free for the new record,
        # and the deployment record is rebuilt.
        Reset-Records
        $before = (Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $metadata -Algorithm SHA256).Hash
        Plant-Writer $metadata
        $kept = @(Invoke-DefenseClawStandaloneRecordRecovery -Layout $layout -Sources $full -GatewayServiceName 'G' -GuardianServiceName 'H')
        # The rebuild (a fixture here) writes the new record at the live path.
        if ($kept.Count -ne 1 -or -not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $metadata) -or
            (Microsoft.PowerShell.Management\Get-Content -LiteralPath $metadata -Raw) -notmatch 'rebuilt') { throw 'the changed deployment record was not moved aside and written again' }
        if ((Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $kept[0] -Algorithm SHA256).Hash -ne $before) { throw 'the kept record lost its bytes' }
        if ((Get-DefenseClawStandaloneRecordUntrustedReason -Path $kept[0]) -ne '') { throw "the kept record still carries the other account's access: $(Get-DefenseClawStandaloneRecordUntrustedReason -Path $kept[0])" }
        if ($script:rebuilds.Count -ne 1 -or $script:rebuilds[0] -notmatch 'deployment record could be changed by another account') { throw 'the deployment record was not rebuilt' }
        if (@(Kept 'deployment.json').Count -ne 1) { throw 'the kept record is not named <name>.rejected-<time>-<hash>' }

        # An attestation owner: kept aside, and the deployment record is rebuilt
        # with it so the two agree.
        Reset-Records
        Plant-Owner $attestation
        $kept = @(Invoke-DefenseClawStandaloneRecordRecovery -Layout $layout -Sources $full -GatewayServiceName 'G' -GuardianServiceName 'H')
        if ($kept.Count -ne 1 -or (Microsoft.PowerShell.Management\Test-Path -LiteralPath $attestation) -or
            -not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $metadata) -or $script:rebuilds.Count -ne 1) {
            throw 'an untrusted attestation was not kept aside with the deployment record rebuilt'
        }

        # A pending transaction restores its own preimages: nothing moves.
        Reset-Records
        Plant-Writer $metadata
        [IO.File]::WriteAllText($layout.PendingPath, '{}')
        $kept = @(Invoke-DefenseClawStandaloneRecordRecovery -Layout $layout -Sources $full -GatewayServiceName 'G' -GuardianServiceName 'H')
        if ($kept.Count -ne 0 -or -not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $metadata)) { throw 'a pending transaction had a record moved aside' }
        Microsoft.PowerShell.Management\Remove-Item -LiteralPath $layout.PendingPath -Force

        # A folder another account can change is refused by name; nothing moves.
        Reset-Records
        Plant-Writer $metadata
        & icacls.exe $install /grant '*S-1-5-32-545:(OI)(CI)(M)' | Out-Null
        $folderRefused = $false
        try { [void](Invoke-DefenseClawStandaloneRecordRecovery -Layout $layout -Sources $full -GatewayServiceName 'G' -GuardianServiceName 'H') }
        catch { $folderRefused = $_.Exception.Message -match '^untrusted_record: ' -and $_.Exception.Message -match [regex]::Escape($install) }
        if (-not $folderRefused -or -not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $metadata)) { throw 'a record in a folder another account can change was moved or not refused by name' }
        & icacls.exe $install /remove:g '*S-1-5-32-545' | Out-Null

        # Review M1: a rebuild that cannot succeed moves nothing. Each row leaves
        # the changed record where it is, with the access it had, and names it.
        foreach ($case in @(
                @{ Name = 'a payload that lacks an artifact'; Prepare = { $script:missingSources = $true } },
                @{ Name = 'a gateway service that is not registered'; Prepare = { $script:serviceRegistered = $false } })) {
            Reset-Records
            Plant-Writer $metadata
            $script:serviceRegistered = $true
            $sources = $full
            if ($case.Name -like 'a payload*') { $sources = @{ gateway = @{ sha256 = ('a' * 64) } } }
            else { $script:serviceRegistered = $false }
            $refused = ''
            try { [void](Invoke-DefenseClawStandaloneRecordRecovery -Layout $layout -Sources $sources -GatewayServiceName 'G' -GuardianServiceName 'H') }
            catch { $refused = $_.Exception.Message }
            $script:serviceRegistered = $true
            if ($refused -notmatch '^untrusted_record: ' -or $refused -notmatch 'nothing was moved' -or $refused -notmatch '/repair|/uninstall PURGE=1') { throw "$($case.Name): not refused by name: $refused" }
            if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $metadata) -or @(Kept 'deployment.json').Count -ne 0 -or
                (Get-DefenseClawStandaloneRecordUntrustedReason -Path $metadata) -eq '' -or $script:rebuilds.Count -ne 0) {
                throw "$($case.Name): the record was moved, re-stamped or rebuilt"
            }
        }

        # A rebuild that fails after the move puts the record back exactly as it
        # was, with the access it had, and says so.
        Reset-Records
        Plant-Writer $metadata
        $beforeSddl = (Microsoft.PowerShell.Security\Get-Acl -LiteralPath $metadata).Sddl
        $script:rebuildFails = $true
        $refused = ''
        try { [void](Invoke-DefenseClawStandaloneRecordRecovery -Layout $layout -Sources $full -GatewayServiceName 'G' -GuardianServiceName 'H') }
        catch { $refused = $_.Exception.Message }
        $script:rebuildFails = $false
        if ($refused -notmatch '^untrusted_record: ' -or $refused -notmatch 'back where it was') { throw "a failed rebuild was not refused by name: $refused" }
        if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $metadata) -or @(Kept 'deployment.json').Count -ne 0 -or
            (Microsoft.PowerShell.Security\Get-Acl -LiteralPath $metadata).Sddl -ne $beforeSddl) {
            throw 'a failed rebuild did not put the record back with its access'
        }

        # Review S1: a kept file that cannot be given administrator-only access
        # is a named refusal, after the record was written again.
        Reset-Records
        Plant-Owner $metadata
        $script:failKeptStamp = $true
        $refused = ''
        try { [void](Invoke-DefenseClawStandaloneRecordRecovery -Layout $layout -Sources $full -GatewayServiceName 'G' -GuardianServiceName 'H') }
        catch { $refused = $_.Exception.Message }
        $script:failKeptStamp = $false
        if ($refused -notmatch 'could not be given administrator-only access' -or $refused -notmatch 'icacls' -or
            -not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $metadata) -or @(Kept 'deployment.json').Count -ne 1) {
            throw "a kept file that could not be stamped was not named: $refused"
        }

        # Review S2: an attestation-only change keeps the approved config and
        # manifest digests a trusted deployment record held.
        Reset-Records
        $digestConfig = ('b' * 64); $digestManifest = ('c' * 64)
        [IO.File]::WriteAllText($metadata, ('{"installed":true,"approved_policy_sources":{"config":"' + $digestConfig + '","manifest":"' + $digestManifest + '"}}'))
        Plant-Owner $attestation
        $script:approvedCarried = $null
        [void](Invoke-DefenseClawStandaloneRecordRecovery -Layout $layout -Sources $full -GatewayServiceName 'G' -GuardianServiceName 'H')
        if ($null -eq $script:approvedCarried -or $script:approvedCarried['config'] -ne $digestConfig -or $script:approvedCarried['manifest'] -ne $digestManifest) {
            throw 'an attestation-only change lost the approved policy digests'
        }

        # Review S5: the refusal names every account (owner and writer), each
        # command exact, the inherited-entry step and the open-handle caveat.
        Reset-Records
        Plant-Owner $metadata
        Plant-Writer $metadata
        $reason = Get-DefenseClawStandaloneRecordUntrustedReason -Path $metadata
        $text = Format-DefenseClawUntrustedRecordRefusal -Path $metadata -Reason $reason
        foreach ($want in @("icacls `"$metadata`" /remove:g *S-1-5-32-545", "icacls `"$metadata`" /setowner *S-1-5-32-544", '/inheritance:d', 'handle')) {
            if ($text -notmatch [regex]::Escape($want)) { throw "the refusal lacks '$want': $text" }
        }
        if ($text -match '<[A-Za-z ]+>') { throw "the refusal holds a template: $text" }

        # Secure Client: nothing changes.
        function Test-DefenseClawStandaloneProfile { return $false }
        Reset-Records
        Plant-Writer $metadata
        $kept = @(Invoke-DefenseClawStandaloneRecordRecovery -Layout $layout -Sources $full -GatewayServiceName 'G' -GuardianServiceName 'H')
        if ($kept.Count -ne 0 -or $script:rebuilds.Count -ne 0 -or (Get-DefenseClawStandaloneRecordUntrustedReason -Path $metadata) -ne '') {
            throw 'Secure Client had a record judged or moved aside'
        }
    } $state
    'enterprise-standalone-record-recovery-smoke: OK'
}
finally {
    if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $state) {
        & icacls.exe $state /reset /T /C /Q | Out-Null
        Microsoft.PowerShell.Management\Remove-Item -LiteralPath $state -Recurse -Force -ErrorAction SilentlyContinue
    }
}
