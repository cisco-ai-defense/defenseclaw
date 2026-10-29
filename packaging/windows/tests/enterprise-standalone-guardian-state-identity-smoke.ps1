# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

# GAP-1849: the fresh-reconcile wait polls hook_guardian_state.json while the
# guardian that writes it restarts. A state file that disappears between the
# existence check and the identity read means "no identity yet" ($null), not
# an ItemNotFound that fails the whole upgrade transaction. Any other read
# failure of a file that is still there keeps throwing.

#Requires -Version 5.1

[CmdletBinding()]
param()

Microsoft.PowerShell.Core\Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modulePath = [IO.Path]::GetFullPath(
    (Microsoft.PowerShell.Management\Join-Path $PSScriptRoot '..\DefenseClawEnterprise.psm1')
)
$module = Microsoft.PowerShell.Core\Import-Module -Name $modulePath -Force -PassThru -ErrorAction Stop
$root = Microsoft.PowerShell.Management\Join-Path ([IO.Path]::GetTempPath()) ("dc-gsi-" + [guid]::NewGuid().ToString('N'))
[void](Microsoft.PowerShell.Management\New-Item -ItemType Directory -Path $root)
try {
    $failures = & $module {
        param($root)
        $failures = [Collections.Generic.List[string]]::new()
        $layout = @{ RuntimeDirectory = $root }
        $state = Microsoft.PowerShell.Management\Join-Path $root 'hook_guardian_state.json'
        $script:TestStatePath = $state
        $script:TestMode = 'vanish'
        function Get-DefenseClawFileIdentity {
            param([string]$Path)
            if ($script:TestMode -eq 'vanish') {
                Microsoft.PowerShell.Management\Remove-Item -LiteralPath $script:TestStatePath -Force
                throw [Management.Automation.ItemNotFoundException]::new("Cannot find path '$Path' because it does not exist.")
            }
            if ($script:TestMode -eq 'denied') {
                throw [UnauthorizedAccessException]::new("Access to the path '$Path' is denied.")
            }
            return 'identity'
        }
        foreach ($case in @(
                @{ mode = 'vanish'; wantThrow = $false; want = $null },
                @{ mode = 'denied'; wantThrow = $true },
                @{ mode = 'present'; wantThrow = $false; want = 'identity' }
            )) {
            Microsoft.PowerShell.Management\Set-Content -LiteralPath $state -Value '{}' -NoNewline
            $script:TestMode = $case.mode
            $threw = $false
            $got = $null
            try {
                $got = Get-DefenseClawGuardianStateIdentity -Layout $layout
            }
            catch {
                $threw = $true
            }
            if ($threw -ne $case.wantThrow) {
                $failures.Add("$($case.mode): threw=$threw, want $($case.wantThrow)")
            }
            elseif (-not $threw -and $got -ne $case.want) {
                $failures.Add("$($case.mode): identity '$got', want '$($case.want)'")
            }
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
Microsoft.PowerShell.Utility\Write-Output 'enterprise-standalone-guardian-state-identity-smoke: OK'
