# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 5.1

# Standalone credential store permissions across a non-purge uninstall. The
# uninstall resets every retained item to administrator-only ACLs, which
# removes the gateway's entries from <StateRoot>\secrets; install, upgrade and
# reconcile must give them back with the exact descriptors
# `enterprise secret set` writes. Runs elevated in a disposable directory with
# a stand-in service SID; no service or real machine root is touched.

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
    ('dcsec-' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
)
[void][IO.Directory]::CreateDirectory($root)
try {
    $failures = & $module {
        param([string]$Root)
        $failures = [Collections.Generic.List[string]]::new()
        $originalProfile = Get-DefenseClawEnterpriseProfile
        $sid = 'S-1-5-80-1-2-3-4-5'
        $directorySddl = "O:BAG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x1200a0;;;$sid)"
        # 0x1200a0 is FILE_GENERIC_EXECUTE, which Windows renders as FX.
        $directoryOnDisk = "O:BAG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;FX;;;$sid)"
        $fileSddl = "O:BAG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;$sid)"
        $adminDirectorySddl = 'O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'
        $adminFileSddl = 'O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)'
        try {
            function Get-TestSddl([string]$Path) {
                # NTFS may add the benign AutoInherited flag to a protected DACL.
                return ((Microsoft.PowerShell.Security\Get-Acl -LiteralPath $Path).Sddl -replace 'D:PAI\(', 'D:P(')
            }
            function Assert-TestSddl([string]$Label, [string]$Path, [string]$Want) {
                $got = Get-TestSddl $Path
                if ($got -cne $Want) {
                    $failures.Add("${Label}: $got, want $Want")
                }
            }
            function Test-Refused([string]$Label, [scriptblock]$Action, [string]$Pattern) {
                try {
                    & $Action
                    $failures.Add("${Label}: expected a refusal")
                }
                catch {
                    if ($_.Exception.Message -notmatch $Pattern) {
                        $failures.Add("${Label}: unexpected refusal: $($_.Exception.Message)")
                    }
                }
            }
            function New-TestStore([string]$Name) {
                $state = [IO.Path]::Combine($Root, $Name)
                $secrets = [IO.Path]::Combine($state, 'secrets')
                [void][IO.Directory]::CreateDirectory($secrets)
                return @{ StateRoot = $state; Secrets = $secrets }
            }

            # The module helpers produce the descriptors the Go writer uses.
            if ((Get-DefenseClawStandaloneSecretsDirectorySddl -GatewayServiceSID $sid) -cne $directorySddl) {
                $failures.Add('directory descriptor differs from enterprise_secret_windows.go')
            }
            if ((Get-DefenseClawStandaloneSecretFileSddl -GatewayServiceSID $sid) -cne $fileSddl) {
                $failures.Add('credential descriptor differs from enterprise_secret_windows.go')
            }

            Set-DefenseClawEnterpriseProfile -EnterpriseProfile Standalone
            $store = New-TestStore 'reinstall'
            $credential = [IO.Path]::Combine($store.Secrets, 'ai-defense-api-key')
            $second = [IO.Path]::Combine($store.Secrets, 'judge-key')
            $temporary = [IO.Path]::Combine($store.Secrets, '.ai-defense-api-key.tmp-0011223344556677')
            $nested = [IO.Path]::Combine($store.Secrets, 'nested')
            foreach ($path in @($credential, $second, $temporary)) {
                [IO.File]::WriteAllText($path, 'stand-in value')
            }
            [void][IO.Directory]::CreateDirectory($nested)

            # A non-purge uninstall leaves the store administrator-only.
            Set-DefenseClawPreservedStateAcls -Layout @{ StateRoot = $store.StateRoot } -GatewayServiceSID $sid
            Assert-TestSddl 'store after uninstall' $store.Secrets $adminDirectorySddl
            Assert-TestSddl 'credential after uninstall' $credential $adminFileSddl

            # Reinstall gives the gateway its entries back.
            Set-DefenseClawStandaloneSecretsAcls -Layout @{ StateRoot = $store.StateRoot } -GatewayServiceSID $sid
            Assert-TestSddl 'store after reinstall' $store.Secrets $directoryOnDisk
            Assert-TestSddl 'credential after reinstall' $credential $fileSddl
            Assert-TestSddl 'second credential after reinstall' $second $fileSddl
            Assert-TestSddl 'temporary file' $temporary $adminFileSddl
            Assert-TestSddl 'nested directory' $nested $adminDirectorySddl
            if ([IO.File]::ReadAllText($credential) -cne 'stand-in value') {
                $failures.Add('credential content changed')
            }
            # Idempotent.
            Set-DefenseClawStandaloneSecretsAcls -Layout @{ StateRoot = $store.StateRoot } -GatewayServiceSID $sid
            Assert-TestSddl 'store after a second pass' $store.Secrets $directoryOnDisk
            Assert-TestSddl 'credential after a second pass' $credential $fileSddl

            # No store: nothing to do.
            $empty = [IO.Path]::Combine($Root, 'empty')
            [void][IO.Directory]::CreateDirectory($empty)
            Set-DefenseClawStandaloneSecretsAcls -Layout @{ StateRoot = $empty } -GatewayServiceSID $sid
            if ([IO.Directory]::Exists([IO.Path]::Combine($empty, 'secrets'))) {
                $failures.Add('the repair created a credential store')
            }

            # A file where the store belongs is refused.
            $occupied = [IO.Path]::Combine($Root, 'occupied')
            [void][IO.Directory]::CreateDirectory($occupied)
            [IO.File]::WriteAllText([IO.Path]::Combine($occupied, 'secrets'), 'x')
            Test-Refused 'non-directory store' { Set-DefenseClawStandaloneSecretsAcls -Layout @{ StateRoot = $occupied } -GatewayServiceSID $sid } 'non-directory'

            # A link named like a credential is refused before any change.
            $linked = New-TestStore 'linked'
            Set-DefenseClawPreservedStateAcls -Layout @{ StateRoot = $linked.StateRoot } -GatewayServiceSID $sid
            $outside = [IO.Path]::Combine($Root, 'outside.txt')
            [IO.File]::WriteAllText($outside, 'keep')
            $before = Get-TestSddl $outside
            [void](Microsoft.PowerShell.Management\New-Item -ItemType SymbolicLink -Path ([IO.Path]::Combine($linked.Secrets, 'ai-defense-api-key')) -Target $outside)
            Test-Refused 'link named like a credential' { Set-DefenseClawStandaloneSecretsAcls -Layout @{ StateRoot = $linked.StateRoot } -GatewayServiceSID $sid } 'reparse point'
            if ((Get-TestSddl $outside) -cne $before) {
                $failures.Add('the link target outside the store changed')
            }
            Assert-TestSddl 'store with a refused link' $linked.Secrets $adminDirectorySddl

            # The Secure Client profile has no standalone credential store.
            Set-DefenseClawEnterpriseProfile -EnterpriseProfile SecureClient
            $secureClient = New-TestStore 'secure-client'
            Set-DefenseClawPreservedStateAcls -Layout @{ StateRoot = $secureClient.StateRoot } -GatewayServiceSID $sid
            Set-DefenseClawStandaloneSecretsAcls -Layout @{ StateRoot = $secureClient.StateRoot } -GatewayServiceSID $sid
            Assert-TestSddl 'Secure Client store' $secureClient.Secrets $adminDirectorySddl
        }
        finally {
            Set-DefenseClawEnterpriseProfile -EnterpriseProfile $originalProfile
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
Microsoft.PowerShell.Utility\Write-Output 'enterprise-standalone-secrets-acl-smoke: OK'
