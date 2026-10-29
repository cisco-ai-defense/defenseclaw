# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

# GAP-1849: the fresh-reconcile wait polls hook_guardian_state.json while the
# guardian that writes it restarts. A state file that disappears between the
# existence check and the identity read means "no identity yet" ($null), not
# an ItemNotFound that fails the whole upgrade transaction. The guardian
# publishes the file with ReplaceFile, so the name can be missing for the
# read and back before the next check (GAP-2501): a failed read is read
# again; one that keeps failing as not found means no identity yet. Any
# other read failure that persists on a file that is still there throws.

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
        $script:TestCalls = 0
        function Get-DefenseClawFileIdentity {
            param([string]$Path)
            $script:TestCalls++
            if ($script:TestMode -eq 'flicker' -and $script:TestCalls -eq 1) {
                throw [Management.Automation.ItemNotFoundException]::new("Cannot find path '$Path' because it does not exist.")
            }
            if ($script:TestMode -eq 'flicker-always') {
                throw [Management.Automation.ItemNotFoundException]::new("Cannot find path '$Path' because it does not exist.")
            }
            if ($script:TestMode -eq 'io-flicker') {
                throw [IO.IOException]::new("Could not find item $Path.")
            }
            if ($script:TestMode -eq 'denied-once' -and $script:TestCalls -eq 1) {
                throw [UnauthorizedAccessException]::new("Access to the path '$Path' is denied.")
            }
            if ($script:TestMode -eq 'wrapped') {
                throw [Management.Automation.MethodInvocationException]::new(
                    "Exception calling GetFileIdentity",
                    [IO.FileNotFoundException]::new("Could not find file '$Path'."))
            }
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
                @{ mode = 'flicker'; wantThrow = $false; want = 'identity' },
                @{ mode = 'flicker-always'; wantThrow = $false; want = $null },
                @{ mode = 'wrapped'; wantThrow = $false; want = $null },
                @{ mode = 'io-flicker'; wantThrow = $false; want = $null },
                @{ mode = 'denied-once'; wantThrow = $false; want = 'identity' },
                @{ mode = 'denied'; wantThrow = $true },
                @{ mode = 'present'; wantThrow = $false; want = 'identity' }
            )) {
            Microsoft.PowerShell.Management\Set-Content -LiteralPath $state -Value '{}' -NoNewline
            $script:TestMode = $case.mode
            $script:TestCalls = 0
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
