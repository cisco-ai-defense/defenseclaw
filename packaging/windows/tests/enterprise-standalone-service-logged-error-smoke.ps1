# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 5.1

# A standalone gateway that stops at startup writes its reason to the
# gateway log, and a failed first install rolls that log back with the data
# folder. The lifecycle error therefore carries the last "Error: " line the
# service wrote after this start, never one from an earlier run, and Secure
# Client errors are unchanged. Runs in a disposable scratch directory.

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
    ('dc-service-logged-error-' + [Guid]::NewGuid().ToString('N'))
)
[void][IO.Directory]::CreateDirectory($root)
try {
    $failures = & $module {
        param([string]$Root)
        $failures = [Collections.Generic.List[string]]::new()
        $originalProfile = Get-DefenseClawEnterpriseProfile
        $log = [IO.Path]::Combine($Root, 'gateway.log')
        try {
            Set-DefenseClawEnterpriseProfile -EnterpriseProfile 'Standalone'
            [IO.File]::WriteAllText($log, "Error: an earlier run`r`n")
            $script:DefenseClawServiceLogOffsets[$log] = Get-DefenseClawLogLength -LogPath $log
            $got = Get-DefenseClawStandaloneServiceLoggedError -LogPath $log
            if ($got -ne '') {
                $failures.Add("an earlier run's error was reported: '$got'")
            }
            $reason = 'guardrail: rule-pack directory cannot be inspected (access denied)'
            [IO.File]::AppendAllText($log, "starting gateway`r`nError: $reason`r`n")
            $got = Get-DefenseClawStandaloneServiceLoggedError -LogPath $log
            if ($got -ne $reason) {
                $failures.Add("this start's error was '$got', want '$reason'")
            }

            Set-DefenseClawEnterpriseProfile -EnterpriseProfile 'SecureClient'
            $got = Get-DefenseClawStandaloneServiceLoggedError -LogPath $log
            if ($got -ne '') {
                $failures.Add("Secure Client error changed: '$got'")
            }

            # GAP-0946: a standalone stop that the service process does not
            # answer ends that process after the stop budget and continues;
            # Secure Client keeps the plain Stop-Service failure.
            # Windows PowerShell 5.1 loads System.ServiceProcess on first use.
            [void](Microsoft.PowerShell.Management\Get-Service -Name 'EventLog' -ErrorAction SilentlyContinue)
            $script:ServiceStopTimeoutSeconds = 1
            $script:SmokeService = [pscustomobject]@{
                Status = [ServiceProcess.ServiceControllerStatus]::Running
                DependentServices = @()
            }
            $script:SmokeService | Microsoft.PowerShell.Utility\Add-Member -MemberType ScriptMethod -Name Refresh -Value { }
            $script:SmokeService | Microsoft.PowerShell.Utility\Add-Member -MemberType ScriptMethod -Name WaitForStatus -Value {
                param($Status, $Timeout)
                throw [System.ServiceProcess.TimeoutException]::new('smoke: the service did not stop')
            }
            $script:SmokeEnded = @()
            function script:Get-DefenseClawServiceChecked { param([string]$Name) return $script:SmokeService }
            function script:Stop-DefenseClawUnresponsiveServiceProcess {
                param([string]$Name)
                $script:SmokeEnded += $Name
                $script:SmokeService.Status = [ServiceProcess.ServiceControllerStatus]::Stopped
            }
            $hung = 'DefenseClawSmokeHung' + [Guid]::NewGuid().ToString('N').Substring(0, 8)
            Set-DefenseClawEnterpriseProfile -EnterpriseProfile 'Standalone'
            try {
                Stop-DefenseClawService -Name $hung
            }
            catch {
                $failures.Add("a standalone stop of a hung service failed: $($_.Exception.Message)")
            }
            if ((@($script:SmokeEnded) -join ',') -ne $hung) {
                $failures.Add("the hung service's process was not ended once: '$(@($script:SmokeEnded) -join ',')'")
            }
            $script:SmokeService.Status = [ServiceProcess.ServiceControllerStatus]::Running
            $script:SmokeEnded = @()
            Set-DefenseClawEnterpriseProfile -EnterpriseProfile 'SecureClient'
            $secureClientFailed = $false
            try {
                Stop-DefenseClawService -Name $hung
            }
            catch {
                $secureClientFailed = $true
            }
            if (-not $secureClientFailed -or @($script:SmokeEnded).Count -ne 0) {
                $failures.Add('Secure Client stop behaviour changed')
            }
        }
        finally {
            $script:DefenseClawServiceLogOffsets.Remove($log)
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
Microsoft.PowerShell.Utility\Write-Output 'enterprise-standalone-service-logged-error-smoke: OK'
