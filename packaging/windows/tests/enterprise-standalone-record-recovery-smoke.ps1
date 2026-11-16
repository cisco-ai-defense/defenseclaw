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
        $script:omitHash = @()
        function New-DefenseClawRebuiltDeploymentRecord {
            param($Layout, $Sources, $GatewayServiceName, $GuardianServiceName, $ApprovedPolicySources = $null)
            if ($script:rebuildFails) { throw 'the rebuild failed (fixture)' }
            $script:rebuilds.Add('built')
            $script:approvedCarried = $ApprovedPolicySources
            $hashes = [ordered]@{ gateway = ('a' * 64); hook = ('a' * 64); sensor_helper = ('a' * 64) }
            foreach ($left in @($script:omitHash)) { if ($left) { $hashes.Remove($left) } }
            return [ordered]@{ installed = $true; rebuilt = $true; hashes = $hashes }
        }
        # Review D1: the one-step swap is wrapped so a run can be "killed" at
        # the Nth swap, and every call checks that a live record is in place
        # before and after it and that the sibling it publishes was
        # administrator-only before it had the live name.
        $script:swapCalls = 0
        $script:failSwapOn = 0
        $script:liveGaps = [Collections.Generic.List[string]]::new()
        $script:siblingOpen = [Collections.Generic.List[string]]::new()
        $realSwap = Get-Command -Name Invoke-DefenseClawLaunchableFileSwap -CommandType Function
        function Invoke-DefenseClawLaunchableFileSwap {
            param($Temporary, $Destination, $Backup, [switch]$KeepReplacementAccess)
            $script:swapCalls++
            if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $Destination -PathType Leaf)) { $script:liveGaps.Add("before swap $($script:swapCalls): $Destination") }
            if ((Get-DefenseClawStandaloneRecordUntrustedReason -Path $Temporary) -ne '') { $script:siblingOpen.Add($Temporary) }
            if ($script:failSwapOn -eq $script:swapCalls) { throw 'the process was killed here (fixture)' }
            $result = & $realSwap -Temporary $Temporary -Destination $Destination -Backup $Backup -KeepReplacementAccess:$KeepReplacementAccess
            if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $Destination -PathType Leaf)) { $script:liveGaps.Add("after swap $($script:swapCalls): $Destination") }
            return $result
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
        if ($script:rebuilds.Count -ne 1) { throw 'the deployment record was not rebuilt' }
        if ($script:liveGaps.Count -ne 0 -or $script:siblingOpen.Count -ne 0) { throw "a record was absent or a sibling was open during the swap: $($script:liveGaps -join '; ') $($script:siblingOpen -join '; ')" }
        if (@(Kept 'deployment.json').Count -ne 1) { throw 'the kept record is not named <name>.rejected-<time>-<hash>' }

        # An attestation owner: the old one is kept, a not-attested one takes
        # its place with no moment without a record, and the deployment record
        # is rebuilt with it so the two agree.
        Reset-Records
        $attestationBytes = (Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $attestation -Algorithm SHA256).Hash
        Plant-Owner $attestation
        $script:swapCalls = 0; $script:liveGaps.Clear(); $script:siblingOpen.Clear()
        $kept = @(Invoke-DefenseClawStandaloneRecordRecovery -Layout $layout -Sources $full -GatewayServiceName 'G' -GuardianServiceName 'H')
        if ($kept.Count -ne 1 -or -not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $attestation) -or
            -not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $metadata) -or $script:rebuilds.Count -ne 1) {
            throw 'an untrusted attestation was not replaced with the deployment record rebuilt'
        }
        if ((Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $kept[0] -Algorithm SHA256).Hash -ne $attestationBytes) { throw 'the kept attestation lost its bytes' }
        $replacement = Microsoft.PowerShell.Management\Get-Content -LiteralPath $attestation -Raw | Microsoft.PowerShell.Utility\ConvertFrom-Json
        if ($replacement.agent_application_control_enforced -ne $false -or [string]::IsNullOrEmpty([string]$replacement.attested_at)) { throw 'the replacement attestation is not a not-attested record' }
        if ((Get-DefenseClawStandaloneRecordUntrustedReason -Path $attestation) -ne '' -or (Get-DefenseClawStandaloneRecordUntrustedReason -Path $kept[0]) -ne '') { throw 'the attestation or its kept copy carries the other account access' }
        if ($script:swapCalls -ne 1 -or $script:liveGaps.Count -ne 0 -or $script:siblingOpen.Count -ne 0) { throw "attestation swap: calls $($script:swapCalls), gaps $($script:liveGaps -join '; '), open siblings $($script:siblingOpen -join '; ')" }

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
        $folderRefused = $false; $folderMessage = ''
        try { [void](Invoke-DefenseClawStandaloneRecordRecovery -Layout $layout -Sources $full -GatewayServiceName 'G' -GuardianServiceName 'H') }
        catch { $folderMessage = $_.Exception.Message; $folderRefused = $folderMessage -match '^untrusted_record: ' -and $folderMessage -match [regex]::Escape($install) }
        if (-not $folderRefused -or -not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $metadata)) { throw "a record in a folder another account can change was moved or not refused by name: $folderMessage" }
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
            if ($refused -notmatch '^untrusted_record: ' -or $refused -notmatch 'nothing was changed' -or $refused -notmatch '/repair|/uninstall PURGE=1') { throw "$($case.Name): not refused by name: $refused" }
            if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $metadata) -or @(Kept 'deployment.json').Count -ne 0 -or
                (Get-DefenseClawStandaloneRecordUntrustedReason -Path $metadata) -eq '' -or $script:rebuilds.Count -ne 0) {
                throw "$($case.Name): the record was moved, re-stamped or rebuilt"
            }
        }

        # Review D1: a kill at any step leaves a live record at each name. The
        # run is "killed" (an injected throw) before anything is published,
        # at the first swap, and at the second swap; after each, both records
        # exist, the one not yet replaced is byte for byte as it was, and a
        # later run finishes the job.
        foreach ($case in @(
                @{ Name = 'the rebuild fails before any swap'; Rebuild = $true; Swap = 0; Both = $true },
                @{ Name = 'killed at the first swap'; Rebuild = $false; Swap = 1; Both = $true },
                @{ Name = 'killed at the second swap'; Rebuild = $false; Swap = 2; Both = $true })) {
            Reset-Records
            Plant-Writer $metadata
            Plant-Owner $attestation
            $metadataSha = (Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $metadata -Algorithm SHA256).Hash
            $attestationSha = (Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $attestation -Algorithm SHA256).Hash
            $script:swapCalls = 0; $script:liveGaps.Clear(); $script:siblingOpen.Clear()
            $script:rebuildFails = [bool]$case.Rebuild
            $script:failSwapOn = [int]$case.Swap
            $refused = ''
            try { [void](Invoke-DefenseClawStandaloneRecordRecovery -Layout $layout -Sources $full -GatewayServiceName 'G' -GuardianServiceName 'H') }
            catch { $refused = $_.Exception.Message }
            $script:rebuildFails = $false; $script:failSwapOn = 0
            if ($refused -notmatch '^untrusted_record: ' -or $refused -notmatch 'run the same command again|/repair') { throw "$($case.Name): not refused by name: $refused" }
            foreach ($live in @($metadata, $attestation)) {
                if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $live -PathType Leaf)) { throw "$($case.Name): no live record at $live" }
            }
            if ($script:liveGaps.Count -ne 0 -or $script:siblingOpen.Count -ne 0) { throw "$($case.Name): gaps $($script:liveGaps -join '; '), open siblings $($script:siblingOpen -join '; ')" }
            # Whatever was not replaced is as it was found, access included.
            if ($case.Swap -le 1 -and (Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $metadata -Algorithm SHA256).Hash -ne $metadataSha) { throw "$($case.Name): the deployment record changed" }
            if ($case.Swap -ge 1 -and (Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $attestation -Algorithm SHA256).Hash -ne $attestationSha) { throw "$($case.Name): the attestation changed before its swap" }
            if ($case.Swap -eq 0 -and (@(Kept 'deployment.json').Count -ne 0 -or @(Kept 'agent-application-control-attestation.json').Count -ne 0)) { throw "$($case.Name): a record was moved" }
            if ($case.Swap -eq 2 -and (Microsoft.PowerShell.Management\Get-Content -LiteralPath $metadata -Raw) -notmatch 'rebuilt') { throw "$($case.Name): the first record was not replaced" }
            if (@(Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $install -Force -Filter '*.new.*').Count -ne 0) { throw "$($case.Name): a sibling was left behind" }
            # The next run finishes it: both records trusted, the kept copies
            # stamped, no further copy kept for a record it already replaced.
            $script:swapCalls = 0
            [void](Invoke-DefenseClawStandaloneRecordRecovery -Layout $layout -Sources $full -GatewayServiceName 'G' -GuardianServiceName 'H')
            foreach ($live in @($metadata, $attestation)) {
                if ((Get-DefenseClawStandaloneRecordUntrustedReason -Path $live) -ne '') { throw "$($case.Name): the rerun left $live untrusted" }
            }
            foreach ($keptFile in (@(Kept 'deployment.json') + @(Kept 'agent-application-control-attestation.json'))) {
                if ((Get-DefenseClawStandaloneRecordUntrustedReason -Path $keptFile.FullName) -ne '') { throw "$($case.Name): the rerun left $($keptFile.Name) unstamped" }
            }
            if ($script:liveGaps.Count -ne 0) { throw "$($case.Name): the rerun had a gap: $($script:liveGaps -join '; ')" }
        }

        # Review S1/D2: a kept file that cannot be given administrator-only
        # access (a program holds it open) is a named warning, not a stop: the
        # records are written and the run goes on to the repair transaction,
        # which a legacy-shaped rebuilt record needs (a native run that stopped
        # here left the next /ensure failing with the services stopped). The
        # next run stamps it.
        Reset-Records
        Plant-Owner $metadata
        $script:failKeptStamp = $true
        $quiet = @(Invoke-DefenseClawStandaloneRecordRecovery -Layout $layout -Sources $full -GatewayServiceName 'G' -GuardianServiceName 'H' 3>&1)
        $script:failKeptStamp = $false
        $warned = (@($quiet | Microsoft.PowerShell.Core\Where-Object { $_ -is [Management.Automation.WarningRecord] }) | Microsoft.PowerShell.Core\ForEach-Object { $_.Message }) -join ' '
        if ($warned -notmatch 'could not be given administrator-only access' -or $warned -notmatch 'icacls' -or $warned -notmatch '/repair' -or $warned -notmatch 'only the stamp is left' -or
            -not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $metadata) -or @(Kept 'deployment.json').Count -ne 1) {
            throw "a kept file that could not be stamped was not named: $warned"
        }
        $heldKept = (Kept 'deployment.json')[0].FullName
        if ((Get-DefenseClawStandaloneRecordUntrustedReason -Path $heldKept) -eq '') { throw 'the kept copy was stamped although the stamp failed' }
        # Still held on the next run: it warns again and goes on.
        $script:failKeptStamp = $true
        $quiet = @(Invoke-DefenseClawStandaloneRecordRecovery -Layout $layout -Sources $full -GatewayServiceName 'G' -GuardianServiceName 'H' 3>&1)
        $script:failKeptStamp = $false
        if ((Get-DefenseClawStandaloneRecordUntrustedReason -Path $heldKept) -eq '') { throw 'a rerun with the copy still held stamped it' }
        # Released: the next run finishes the stamp and keeps no further copy.
        [void](Invoke-DefenseClawStandaloneRecordRecovery -Layout $layout -Sources $full -GatewayServiceName 'G' -GuardianServiceName 'H')
        if ((Get-DefenseClawStandaloneRecordUntrustedReason -Path $heldKept) -ne '' -or @(Kept 'deployment.json').Count -ne 1) { throw 'the rerun did not finish the stamp of the kept copy' }

        # Review D1: a deployment record that is missing while a copy kept aside
        # is next to it (an earlier build stopped between the two) is named,
        # and a repair writes it again from the machine and stamps the copy.
        Reset-Records
        if ((Get-DefenseClawOrphanedKeptRecordRefusal -Layout $layout -GatewayServiceName 'G' -GuardianServiceName 'H') -ne '') { throw 'a healthy host was reported as having an orphaned kept copy' }
        Plant-Writer $metadata
        $orphanKept = Join-Path $install 'deployment.json.rejected-20261101T000000000Z-0123456789ab'
        Microsoft.PowerShell.Management\Move-Item -LiteralPath $metadata -Destination $orphanKept
        $orphan = Get-DefenseClawOrphanedKeptRecordRefusal -Layout $layout -GatewayServiceName 'G' -GuardianServiceName 'H'
        if ($orphan -notmatch '^untrusted_record: ' -or $orphan -notmatch [regex]::Escape($orphanKept) -or $orphan -notmatch '/repair' -or $orphan -match 'PURGE=1') { throw "the orphaned kept copy is not named with the way out: $orphan" }
        if ((Get-DefenseClawStandaloneRecordUntrustedReason -Path $orphanKept) -eq '') { throw 'the planted orphan is not untrusted' }
        $script:rebuilds.Clear()
        $kept = @(Invoke-DefenseClawStandaloneRecordRecovery -Layout $layout -Sources $full -GatewayServiceName 'G' -GuardianServiceName 'H')
        if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $metadata -PathType Leaf) -or $script:rebuilds.Count -ne 1 -or @(Kept 'deployment.json').Count -ne 1 -or
            (Get-DefenseClawStandaloneRecordUntrustedReason -Path $orphanKept) -ne '' -or (Get-DefenseClawOrphanedKeptRecordRefusal -Layout $layout -GatewayServiceName 'G' -GuardianServiceName 'H') -ne '') {
            throw 'a repair did not write the record again and stamp the orphaned copy'
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

        # Delta-4 F3: a rebuilt record that cannot name the gateway, the hook and
        # the sensor helper (an empty hashes table, or one artifact missing)
        # is refused before anything is swapped: the record, the attestation and
        # the services are as they were, and the text names the artifact and the way out.
        foreach ($omit in @(@('gateway', 'hook', 'sensor_helper'), @('hook'), @('sensor_helper'))) {
            Reset-Records
            Plant-Writer $metadata
            $before = [IO.File]::ReadAllText($metadata)
            $script:omitHash = $omit
            $script:rebuilds.Clear()
            $refusal = ''
            try { [void](Invoke-DefenseClawStandaloneRecordRecovery -Layout $layout -Sources $full -GatewayServiceName 'G' -GuardianServiceName 'H') } catch { $refusal = $_.Exception.Message }
            $script:omitHash = @()
            if ($refusal -notmatch 'Nothing was changed and every service is as it was' -or $refusal -notmatch [regex]::Escape($omit[0]) -or $refusal -notmatch '/repair') {
                throw "a rebuilt record without $($omit -join ',') was not refused by name before the swap: $refusal"
            }
            if ([IO.File]::ReadAllText($metadata) -cne $before -or @(Kept 'deployment.json').Count -ne 0 -or (Get-DefenseClawStandaloneRecordUntrustedReason -Path $metadata) -eq '') {
                throw 'a refused rebuild changed the record'
            }
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

        # Orphan reinstall: with no DefenseClaw service registered, a kept copy
        # left by an uninstall is no refusal, and an install removes it (only a
        # regular file with the name Setup gave it); with a live record, or with
        # a service registered, nothing is removed.
        Reset-Records
        Plant-Writer $metadata
        $leftover = Join-Path $install 'deployment.json.rejected-20261101T000000000Z-0123456789ab'
        $decoy = Join-Path $install 'deployment.json.rejected-notes.txt'
        Microsoft.PowerShell.Management\Move-Item -LiteralPath $metadata -Destination $leftover
        [IO.File]::WriteAllText($decoy, 'mine')
        $script:serviceRegistered = $true
        Remove-DefenseClawLeftoverKeptRecords -Layout $layout -GatewayServiceName 'G' -GuardianServiceName 'H' 3>&1 | Out-Null
        if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $leftover)) { throw 'a kept copy was removed while a service is registered' }
        $script:serviceRegistered = $false
        if ((Get-DefenseClawOrphanedKeptRecordRefusal -Layout $layout -GatewayServiceName 'G' -GuardianServiceName 'H') -ne '') { throw 'a leftover kept copy with no service registered blocks the reinstall' }
        New-Record $metadata '{"installed":true}'
        Remove-DefenseClawLeftoverKeptRecords -Layout $layout -GatewayServiceName 'G' -GuardianServiceName 'H' 3>&1 | Out-Null
        if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $leftover)) { throw 'a kept copy was removed next to a live record' }
        Microsoft.PowerShell.Management\Remove-Item -LiteralPath $metadata -Force
        $removed = @(Remove-DefenseClawLeftoverKeptRecords -Layout $layout -GatewayServiceName 'G' -GuardianServiceName 'H' 3>&1)
        if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $leftover) { throw 'the leftover kept copy was not removed by the install step' }
        if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $decoy)) { throw 'a file that Setup did not name was removed' }
        if ((@($removed | Microsoft.PowerShell.Core\Where-Object { $_ -is [Management.Automation.WarningRecord] -and $_.Message -match '^kept_record_removed: ' })).Count -ne 1) { throw 'the removal was not named' }
        $script:serviceRegistered = $true

        # Secure Client: nothing changes.
        function Test-DefenseClawStandaloneProfile { return $false }
        Reset-Records
        Plant-Writer $metadata
        $kept = @(Invoke-DefenseClawStandaloneRecordRecovery -Layout $layout -Sources $full -GatewayServiceName 'G' -GuardianServiceName 'H')
        if ($kept.Count -ne 0 -or $script:rebuilds.Count -ne 0 -or (Get-DefenseClawStandaloneRecordUntrustedReason -Path $metadata) -ne '') {
            throw 'Secure Client had a record judged or moved aside'
        }
    } $state

    # GAP-0994: a rebuilt deployment record carries a marker, a rollback to it
    # is judged by the artifacts it names (not by the evidence it cannot
    # carry), and a repair over a record with no activation evidence has the
    # Guardian publish its records again before the transaction opens when
    # they are from different publications. Its own scope: the stubs below are
    # gone after it.
    & $module {
        param($State)
        function Test-DefenseClawStandaloneProfile { return $true }
        function Write-DefenseClawLifecyclePhase { param([string]$Stage) $script:phases.Add($Stage) }
        $script:phases = [Collections.Generic.List[string]]::new()

        # The real builder marks its record; the marker survives JSON.
        $built = New-DefenseClawRebuiltDeploymentRecord -Layout @{ InstallRoot = 'C:\x'; StateRoot = 'C:\y' } -Sources @{} -GatewayServiceName 'G' -GuardianServiceName 'H'
        if ($built['record_rebuilt_by_setup'] -ne $true) { throw 'the rebuilt record carries no marker' }
        $roundTrip = ($built | ConvertTo-Json -Depth 5) | ConvertFrom-Json
        if (-not (Test-DefenseClawRebuiltDeploymentRecord -Metadata $roundTrip)) { throw 'the marker does not survive JSON' }
        $withEvidence = ($built | ConvertTo-Json -Depth 5) | ConvertFrom-Json
        $withEvidence | Add-Member -NotePropertyName managed_hooks_activation -NotePropertyValue ([pscustomobject]@{ state = 'activated' })
        if (Test-DefenseClawRebuiltDeploymentRecord -Metadata $withEvidence) { throw 'a record with activation evidence was called rebuilt' }
        if (Test-DefenseClawRebuiltDeploymentRecord -Metadata ([pscustomobject]@{ installed = $true })) { throw 'a record with no marker was called rebuilt' }
        if (Test-DefenseClawRebuiltDeploymentRecord -Metadata ([pscustomobject]@{ record_rebuilt_by_setup = 'yes' })) { throw 'a marker that is not a Boolean was accepted' }

        # The artifact check of the rollback: the gateway, the hook and the sensor
        # helper must be named with the digest of their installed file (delta-4 F3);
        # an empty table or a missing one is refused by name, never passed.
        $files = @{}
        foreach ($pair in @(@('gateway', 'GatewayPath'), @('hook', 'HookPath'), @('sensor_helper', 'SensorHelperPath'))) {
            $f = [IO.Path]::Combine($State, "$($pair[0]).exe")
            [IO.File]::WriteAllText($f, "$($pair[0]) bytes")
            $files[$pair[0]] = $f
        }
        $layout = @{ GatewayPath = $files.gateway; HookPath = $files.hook; SensorHelperPath = $files.sensor_helper }
        function New-Hashes { $h = [ordered]@{}; foreach ($k in $files.Keys) { $h[$k] = (Get-FileHash -LiteralPath $files[$k] -Algorithm SHA256).Hash.ToLowerInvariant() }; [pscustomobject]$h }
        $meta = [pscustomobject]@{ hashes = (New-Hashes) }
        Assert-DefenseClawRebuiltRecordArtifacts -Layout $layout -Metadata $meta
        function Expect-Refusal([string]$Why, $Metadata, [string]$Pattern) {
            $threw = $false
            try { Assert-DefenseClawRebuiltRecordArtifacts -Layout $layout -Metadata $Metadata } catch { $threw = $_.Exception.Message -match $Pattern }
            if (-not $threw) { throw "$Why was accepted by the rollback check" }
        }
        Expect-Refusal 'a record with an empty hashes table' ([pscustomobject]@{ hashes = [pscustomobject]@{} }) 'names no digest'
        Expect-Refusal 'a record with no hashes at all' ([pscustomobject]@{ installed = $true }) 'names no digest'
        foreach ($drop in @('gateway', 'hook', 'sensor_helper')) {
            $partial = New-Hashes; $partial.PSObject.Properties.Remove($drop)
            Expect-Refusal "a record without the $drop digest" ([pscustomobject]@{ hashes = $partial }) ("for it|" + $drop)
        }
        [IO.File]::WriteAllText($files.hook, 'another file')
        Expect-Refusal 'a changed hook' $meta 'another digest'
        Remove-Item -LiteralPath $files.hook -Force
        Expect-Refusal 'a missing hook' $meta 'missing'

        # The full assertion: a rollback to a rebuilt record returns after the
        # identity and artifact checks; every other caller still fails.
        $script:record = $roundTrip
        function Get-DefenseClawDeploymentMetadata { param($Layout, [switch]$Required) return $script:record }
        function Assert-DefenseClawMetadataIdentity { param($Metadata, $GatewayServiceName, $GuardianServiceName) }
        function Get-DefenseClawAcceptedGatewayServiceAccounts { param($GatewayServiceName) return @('NT SERVICE\G') }
        function Test-DefenseClawMetadataInstalled { param($Metadata) return $true }
        function Get-DefenseClawRedactionKeySecuritySnapshot { param($Layout, $GatewayServiceSID) throw 'the full assertion ran (fixture)' }
        function Get-DefenseClawServiceSID { param($ServiceName) return 'S-1-5-80-1-2-3-4-5' }
        [IO.File]::WriteAllText($files.hook, 'hook bytes')
        $script:record = [pscustomobject]@{ installed = $true; record_rebuilt_by_setup = $true; hashes = (New-Hashes) }
        $script:layoutForRollback = $layout
        $script:phases.Clear()
        Assert-DefenseClawEnterpriseDeployment -Layout $script:layoutForRollback -GatewayServiceName 'G' -GuardianServiceName 'H' -ServicingTransaction -RollbackRestore
        if (@($script:phases | Where-Object { $_ -match 'rebuilt deployment record' }).Count -ne 1) { throw 'the rollback to a rebuilt record did not return early' }
        $threw = $false
        try { Assert-DefenseClawEnterpriseDeployment -Layout @{} -GatewayServiceName 'G' -GuardianServiceName 'H' -ServicingTransaction } catch { $threw = $_.Exception.Message -match 'full assertion ran' }
        if (-not $threw) { throw 'a forward assertion accepted a rebuilt record' }
        $script:record = [pscustomobject]@{ installed = $true; hashes = [pscustomobject]@{} }
        $threw = $false
        try { Assert-DefenseClawEnterpriseDeployment -Layout @{} -GatewayServiceName 'G' -GuardianServiceName 'H' -ServicingTransaction -RollbackRestore } catch { $threw = $_.Exception.Message -match 'full assertion ran' }
        if (-not $threw) { throw 'a rollback to a record that is not rebuilt skipped the full assertion' }

        # The Guardian's three records before the transaction opens: one
        # publication is left alone; records from different publications get the
        # running Guardian restarted once (its first pass publishes all three);
        # a Guardian that does not publish them again ends the run with nothing
        # opened; a Guardian that is not running, and no record at all, are left
        # to the classification.
        $gdir = [IO.Path]::Combine($State, 'guardian-records')
        $auth = [IO.Path]::Combine($gdir, 'hook-guardian-state')
        $run = [IO.Path]::Combine($gdir, 'runtime')
        [void][IO.Directory]::CreateDirectory($auth); [void][IO.Directory]::CreateDirectory($run)
        $glayout = @{ AuthorizationDirectory = $auth; AuthorizationLedgerPath = [IO.Path]::Combine($auth, 'protected_targets.json'); RuntimeDirectory = $run }
        function Write-Publication([string]$Activation, [string]$Authorization, [string]$StateStamp) {
            [IO.File]::WriteAllText([IO.Path]::Combine($auth, 'activation.json'), ('{"version": 1, "updated_at": "' + $Activation + '"}'))
            [IO.File]::WriteAllText($glayout.AuthorizationLedgerPath, ('{' + "`n" + '  "updated_at": "' + $Authorization + '"' + "`n" + '}'))
            [IO.File]::WriteAllText([IO.Path]::Combine($run, 'hook_guardian_state.json'), ('{"version": 1, "updated_at": "' + $StateStamp + '"}'))
        }
        Add-Type -AssemblyName System.ServiceProcess
        $script:GuardianRepublishWaitSeconds = 3
        $script:GuardianRepublishPollSeconds = 1
        $script:GuardianRepublishRecheckSeconds = 1
        $script:guardianStatus = [ServiceProcess.ServiceControllerStatus]::Running
        $script:restarts = 0
        $script:republishes = $true
        $script:startFailures = 0
        $script:startCalls = 0
        $script:startModeSet = @()
        function Get-DefenseClawServiceStartMode { param([string]$Name) return 2 }
        function Set-DefenseClawServiceStartMode { param([string]$Name, [int]$StartMode) $script:startModeSet += $StartMode }
        function Get-DefenseClawServiceChecked { param([string]$Name) return [pscustomobject]@{ Status = $script:guardianStatus } }
        function Stop-DefenseClawService { param([string]$Name) $script:restarts++ }
        function Start-DefenseClawService {
            param([string]$Name, [string]$FailureLogPath)
            $script:startCalls++
            if ($script:startFailures -gt 0) { $script:startFailures--; throw 'SCM start request exited 1056 (fixture)' }
            if ($script:republishes) { Write-Publication '2026-11-09T22:00:00.5Z' '2026-11-09T22:00:00.5Z' '2026-11-09T22:00:00.5Z' }
            if ($script:republishIncomplete) { Write-ActivationOutcome '2026-11-09T22:00:00.5Z' 'false' 0 }
        }
        $script:republishIncomplete = $false
        function Write-ActivationOutcome([string]$Stamp, [string]$Ok, [int]$Failures) {
            [IO.File]::WriteAllText([IO.Path]::Combine($auth, 'activation.json'), ('{"version": 2, "updated_at": "' + $Stamp + '", "ok": ' + $Ok + ', "failure_count": ' + $Failures + '}'))
        }
        Write-Publication '2026-11-09T21:00:00.1Z' '2026-11-09T21:00:00.1Z' '2026-11-09T21:00:00.1Z'
        Resolve-DefenseClawGuardianPublicationBeforeTransaction -Layout $glayout -GuardianServiceName 'H'
        if ($script:restarts -ne 0) { throw 'a Guardian that published once was restarted' }
        Write-Publication '2026-11-09T00:00:00Z' '2026-11-09T21:00:00.1Z' '2026-11-09T21:00:00.1Z'
        Resolve-DefenseClawGuardianPublicationBeforeTransaction -Layout $glayout -GuardianServiceName 'H'
        if ($script:restarts -ne 1 -or -not (Test-DefenseClawGuardianPublicationWhole -Layout $glayout)) { throw 'records from different publications were not published again by one restart' }
        # Delta-4 F2: a look taken between the Guardian's three writes is not a
        # fault. The records agree about a second later: no restart. They still
        # disagree: one restart.
        $realStamps = Get-Command -Name Get-DefenseClawGuardianPublicationStamps -CommandType Function
        $script:stampQueue = [Collections.Generic.Queue[object]]::new()
        function Get-DefenseClawGuardianPublicationStamps {
            param($Layout)
            if ($script:stampQueue.Count -gt 0) { return $script:stampQueue.Dequeue() }
            return & $realStamps -Layout $Layout
        }
        $mid = [ordered]@{ activation = 'T0'; authorization = 'T1'; state = 'T1' }
        $whole = [ordered]@{ activation = 'T1'; authorization = 'T1'; state = 'T1' }
        $script:restarts = 0
        foreach ($look in @($mid, $mid, $whole)) { $script:stampQueue.Enqueue($look) }
        Resolve-DefenseClawGuardianPublicationBeforeTransaction -Layout $glayout -GuardianServiceName 'H'
        if ($script:restarts -ne 0 -or $script:stampQueue.Count -ne 0) { throw 'a read between the Guardian writes restarted a healthy Guardian' }
        Write-Publication '2026-11-09T00:00:00Z' '2026-11-09T21:00:00.1Z' '2026-11-09T21:00:00.1Z'
        Remove-Item Function:\Get-DefenseClawGuardianPublicationStamps
        function Get-DefenseClawGuardianPublicationStamps { param($Layout) return & $realStamps -Layout $Layout }
        $script:restarts = 0
        Resolve-DefenseClawGuardianPublicationBeforeTransaction -Layout $glayout -GuardianServiceName 'H'
        if ($script:restarts -ne 1) { throw 'records that still disagree after the second look were not restarted once' }

        # Delta-4 F1: a start that fails after the stop is tried once more with the
        # start mode put back; a Guardian that still does not start ends the run
        # naming both failures and the exact command, with nothing else changed.
        Write-Publication '2026-11-09T00:00:00Z' '2026-11-09T21:00:00.1Z' '2026-11-09T21:00:00.1Z'
        $script:restarts = 0; $script:startCalls = 0; $script:startFailures = 1; $script:startModeSet = @()
        Resolve-DefenseClawGuardianPublicationBeforeTransaction -Layout $glayout -GuardianServiceName 'H'
        if ($script:startCalls -ne 2 -or @($script:startModeSet).Count -ne 1 -or $script:startModeSet[0] -ne 2 -or -not (Test-DefenseClawGuardianPublicationWhole -Layout $glayout)) { throw 'a failed first start was not retried once with the start mode put back' }
        Write-Publication '2026-11-09T00:00:00Z' '2026-11-09T21:00:00.1Z' '2026-11-09T21:00:00.1Z'
        $script:startCalls = 0; $script:startFailures = 5; $script:startModeSet = @()
        $threw = ''
        try { Resolve-DefenseClawGuardianPublicationBeforeTransaction -Layout $glayout -GuardianServiceName 'H' } catch { $threw = $_.Exception.Message }
        $script:startFailures = 0
        if ($script:startCalls -ne 2 -or $threw -notmatch 'could not be started' -or $threw -notmatch 'sc\.exe start H' -or $threw -notmatch 'No transaction was opened' -or $threw -notmatch '1056') { throw "a Guardian that does not start was not named: $threw" }
        $script:republishes = $false; $script:restarts = 0
        Write-Publication '2026-11-09T21:00:00.1Z' '2026-11-09T21:00:00.1Z' '2026-11-09T00:00:00Z'
        $threw = $false
        try { Resolve-DefenseClawGuardianPublicationBeforeTransaction -Layout $glayout -GuardianServiceName 'H' } catch { $threw = $_.Exception.Message -match 'No transaction was opened and nothing was changed' }
        if (-not $threw -or $script:restarts -ne 1) { throw 'a Guardian that does not publish again did not end the run before the transaction' }
        $script:restarts = 0; $script:guardianStatus = [ServiceProcess.ServiceControllerStatus]::Stopped
        Resolve-DefenseClawGuardianPublicationBeforeTransaction -Layout $glayout -GuardianServiceName 'H'
        if ($script:restarts -ne 0) { throw 'a stopped Guardian was restarted' }
        $script:guardianStatus = [ServiceProcess.ServiceControllerStatus]::Running
        Microsoft.PowerShell.Management\Remove-Item -LiteralPath $gdir -Recurse -Force
        [void][IO.Directory]::CreateDirectory($auth); [void][IO.Directory]::CreateDirectory($run)
        Resolve-DefenseClawGuardianPublicationBeforeTransaction -Layout $glayout -GuardianServiceName 'H'
        if ($script:restarts -ne 0) { throw 'a deployment with no Guardian record at all was restarted' }

        # fc36 EW-02 (GAP-0602, GAP-0974, GAP-0994): one whole publication of a
        # pass that failed with no failed target, which the Guardian publishes
        # while it cannot read the deployment record, gets one restart and the
        # new publication is used. A pass with a failed target and a healthy
        # pass are left alone. A new publication that is still such a pass
        # ends the run before the transaction.
        $script:republishes = $true; $script:restarts = 0
        Write-Publication '2026-11-09T21:00:00.1Z' '2026-11-09T21:00:00.1Z' '2026-11-09T21:00:00.1Z'
        Write-ActivationOutcome '2026-11-09T21:00:00.1Z' 'false' 0
        Resolve-DefenseClawGuardianPublicationBeforeTransaction -Layout $glayout -GuardianServiceName 'H'
        if ($script:restarts -ne 1 -or -not (Test-DefenseClawGuardianPublicationCurrent -Layout $glayout)) { throw 'a whole pass that failed with no failed target was not published again by one restart' }
        $script:restarts = 0
        Write-Publication '2026-11-09T21:00:00.1Z' '2026-11-09T21:00:00.1Z' '2026-11-09T21:00:00.1Z'
        Write-ActivationOutcome '2026-11-09T21:00:00.1Z' 'false' 1
        Resolve-DefenseClawGuardianPublicationBeforeTransaction -Layout $glayout -GuardianServiceName 'H'
        Write-ActivationOutcome '2026-11-09T21:00:00.1Z' 'true' 0
        Resolve-DefenseClawGuardianPublicationBeforeTransaction -Layout $glayout -GuardianServiceName 'H'
        if ($script:restarts -ne 0) { throw 'a pass with a failed target, or a healthy pass, was restarted' }
        $script:republishIncomplete = $true
        Write-ActivationOutcome '2026-11-09T21:00:00.1Z' 'false' 0
        $threw = ''
        try { Resolve-DefenseClawGuardianPublicationBeforeTransaction -Layout $glayout -GuardianServiceName 'H' } catch { $threw = $_.Exception.Message }
        $script:republishIncomplete = $false
        if ($script:restarts -ne 1 -or $threw -notmatch 'still did not publish the protected enrollment set' -or $threw -notmatch 'No transaction was opened') { throw "a restarted Guardian whose pass still failed with no failed target did not end the run before the transaction: $threw" }

        # Delta-5 F4: the non-JSON rebuild (Repair-DefenseClawUnreadableDeploymentMetadata)
        # refuses a rebuilt record that cannot name the gateway, hook and sensor
        # helper before it writes: the garbage record stays, and the text says
        # nothing was changed and every service is as it was. With the digests
        # it writes the record.
        $rpath = [IO.Path]::Combine($State, 'unreadable-deployment.json')
        $rlayout = @{ MetadataPath = $rpath; PendingPath = [IO.Path]::Combine($State, 'no-pending.json') }
        $script:rwrites = 0
        $script:romit = ''
        function Test-DefenseClawDeploymentMetadataPresent { param([string]$Path) return $true }
        function Get-DefenseClawDeploymentMetadata { param($Layout, [switch]$Required) throw "$($script:UnreadableMetadataMessage) $($Layout.MetadataPath)" }
        function Assert-DefenseClawMetadataRebuildReady { param($Layout, $Sources, $GatewayServiceName, $Reason) }
        function New-DefenseClawRebuiltDeploymentRecord {
            param($Layout, $Sources, $GatewayServiceName, $GuardianServiceName, $ApprovedPolicySources = $null)
            $h = [ordered]@{ gateway = ('a' * 64); hook = ('a' * 64); sensor_helper = ('a' * 64) }
            if ($script:romit) { $h.Remove($script:romit) }
            return [ordered]@{ installed = $true; hashes = $h; record_rebuilt_by_setup = $true }
        }
        function Write-DefenseClawJsonAtomic { param($Path, $Value, $Kind) $script:rwrites++; [IO.File]::WriteAllText($Path, 'rebuilt') }
        [IO.File]::WriteAllText($rpath, 'this is not json')
        foreach ($stale in @('gateway', 'hook', 'sensor_helper')) {
            $script:romit = $stale; $refusal = ''
            try { [void](Repair-DefenseClawUnreadableDeploymentMetadata -Layout $rlayout -Sources @{} -GatewayServiceName 'G' -GuardianServiceName 'H' -WarningAction SilentlyContinue) } catch { $refusal = $_.Exception.Message }
            if ($refusal -notmatch 'Nothing was changed and every service is as it was' -or $refusal -notmatch [regex]::Escape($stale) -or $script:rwrites -ne 0 -or [IO.File]::ReadAllText($rpath) -cne 'this is not json') {
                throw "a non-JSON rebuild with a stale $stale was not refused before the write: $refusal"
            }
        }
        $script:romit = ''
        if (-not (Repair-DefenseClawUnreadableDeploymentMetadata -Layout $rlayout -Sources @{} -GatewayServiceName 'G' -GuardianServiceName 'H' -WarningAction SilentlyContinue) -or $script:rwrites -ne 1) {
            throw 'a non-JSON rebuild that names all three digests was not written'
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
