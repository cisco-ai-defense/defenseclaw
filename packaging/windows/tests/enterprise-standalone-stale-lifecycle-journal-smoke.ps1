# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 5.1

# A committed lifecycle can leave its managed-hook lifecycle journal behind
# when the installed gateway refuses to collect an old runtime generation (a
# release before GAP-1322 refuses the contractless Kiro bundles 1.0.1 wrote).
# Every later Setup upgrade, ensure and uninstall then failed retiring it
# with that same installed gateway. A standalone lifecycle now removes that
# exact journal, records why, and goes on; any other retire failure, a
# pending transaction or the Secure Client profile keeps the error. The
# gateway command is stubbed; runs in a disposable scratch directory.

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
    ('dc-stale-lifecycle-journal-' + [Guid]::NewGuid().ToString('N'))
)
[void][IO.Directory]::CreateDirectory($root)
try {
    $failures = & $module {
        param([string]$Root)
        $failures = [Collections.Generic.List[string]]::new()
        $originalProfile = Get-DefenseClawEnterpriseProfile
        $layout = @{
            ManagedHooksLifecycleJournalPath = [IO.Path]::Combine($Root, 'managed-hooks-lifecycle-journal.json')
            PendingPath = [IO.Path]::Combine($Root, 'pending.json')
        }
        $gcRefusal = 'managed-hook lifecycle snapshot retire failed: retire kiro managed runtime generations for SID S-1-5-21-1-2-3-1017: enterprise hooks: refusing to collect an invalid managed runtime bundle'
        $script:TestRetireError = ''
        function Invoke-DefenseClawManagedHooksLifecycleSnapshotCommand {
            param([hashtable]$Layout, [string]$GatewayServiceName, [string]$Action)
            if ($Action -cne 'retire') {
                throw "unexpected action $Action"
            }
            if ($script:TestRetireError) {
                throw $script:TestRetireError
            }
            [IO.File]::Delete($Layout.ManagedHooksLifecycleJournalPath)
            return [pscustomobject]@{ ok = $true }
        }
        $run = {
            param([string]$Name, [string]$EnterpriseProfile, [string]$RetireError, [bool]$Pending, [bool]$WantThrow, [bool]$WantRemoved)
            Set-DefenseClawEnterpriseProfile -EnterpriseProfile $EnterpriseProfile
            [IO.File]::WriteAllText($layout.ManagedHooksLifecycleJournalPath, '{"schema_version":4,"phase":"captured"}')
            if ($Pending) {
                [IO.File]::WriteAllText($layout.PendingPath, '{}')
            }
            $script:TestRetireError = $RetireError
            $script:DefenseClawStaleLifecycleJournalRemoved = ''
            $threw = $false
            try {
                Invoke-DefenseClawCommittedManagedHooksLifecycleRetire `
                    -Layout $layout `
                    -GatewayServiceName 'DefenseClawGateway'
            }
            catch {
                $threw = $true
                if ([string]$_.Exception.Message -cne $RetireError) {
                    $failures.Add("${Name}: error changed to '$($_.Exception.Message)'")
                }
            }
            $removed = -not [IO.File]::Exists($layout.ManagedHooksLifecycleJournalPath)
            if ($threw -ne $WantThrow) {
                $failures.Add("${Name}: threw=$threw, want $WantThrow")
            }
            if ($removed -ne $WantRemoved) {
                $failures.Add("${Name}: journal removed=$removed, want $WantRemoved")
            }
            $recorded = -not [string]::IsNullOrEmpty($script:DefenseClawStaleLifecycleJournalRemoved)
            $wantRecorded = $WantRemoved -and -not [string]::IsNullOrEmpty($RetireError)
            if ($recorded -ne $wantRecorded) {
                $failures.Add("${Name}: removal recorded=$recorded, want $wantRecorded")
            }
            [IO.File]::Delete($layout.ManagedHooksLifecycleJournalPath)
            [IO.File]::Delete($layout.PendingPath)
        }
        try {
            & $run 'retired' 'Standalone' '' $false $false $true
            & $run 'legacy bundle refused' 'Standalone' $gcRefusal $false $false $true
            & $run 'other retire failure' 'Standalone' 'managed-hook lifecycle snapshot retire failed: deployment managed-hook activation binding is invalid' $false $true $false
            & $run 'pending transaction' 'Standalone' $gcRefusal $true $true $false
            & $run 'Secure Client' 'SecureClient' $gcRefusal $false $true $false
        }
        finally {
            Set-DefenseClawEnterpriseProfile -EnterpriseProfile $originalProfile
            $script:DefenseClawStaleLifecycleJournalRemoved = ''
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
Microsoft.PowerShell.Utility\Write-Output 'enterprise-standalone-stale-lifecycle-journal-smoke: OK'
