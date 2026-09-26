# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 5.1

# Function-level regression for the Status view of an outranking HKLM Claude
# policy (#899). Only a disposable scratch directory is written; the machine
# registry is read, never written.

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
    ('dc-claude-hklm-' + [Guid]::NewGuid().ToString('N'))
)
[void][IO.Directory]::CreateDirectory($root)
try {
    $failures = & $module {
        param([string]$Root)
        $failures = [Collections.Generic.List[string]]::new()
        $policyPath = [IO.Path]::Combine($Root, '90-defenseclaw.json')
        $layout = @{ ClaudeManagedPolicyPath = $policyPath }
        $installed = @'
{
  "hooks": {
    "PreToolUse": [
      {
        "hooks": [
          {
            "args": ["hook", "--connector", "claudecode", "--enterprise-managed"],
            "command": "C:\\Program Files\\Cisco\\Cisco Secure Client\\DefenseClaw\\bin\\defenseclaw-hook.exe",
            "timeout": 30,
            "type": "command"
          }
        ],
        "matcher": "*"
      }
    ],
    "Stop": [
      {
        "hooks": [
          {
            "args": ["hook", "--connector", "claudecode", "--enterprise-managed"],
            "command": "C:\\Program Files\\Cisco\\Cisco Secure Client\\DefenseClaw\\bin\\defenseclaw-hook.exe",
            "timeout": 30,
            "type": "command"
          }
        ]
      }
    ]
  }
}
'@
        [IO.File]::WriteAllText($policyPath, $installed, [Text.UTF8Encoding]::new($false))
        $hook = 'C:\\Program Files\\Cisco\\Cisco Secure Client\\DefenseClaw\\bin\\defenseclaw-hook.exe'
        $cases = [ordered]@{
            # Reordered keys, compact form, and an extra administrator hook.
            'carries the installed matrix' = @{
                want = $true
                json = '{"model":"x","hooks":{"Stop":[{"hooks":[{"type":"command","timeout":30,"command":"' + $hook + '","args":["hook","--connector","claudecode","--enterprise-managed"]}]}],"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"C:\\audit.exe"}]},{"matcher":"*","hooks":[{"timeout":30,"type":"command","command":"' + $hook + '","args":["hook","--connector","claudecode","--enterprise-managed"]}]}]}}'
            }
            'misses an event' = @{
                want = $false
                json = '{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"args":["hook","--connector","claudecode","--enterprise-managed"],"command":"' + $hook + '","timeout":30,"type":"command"}]}]}}'
            }
            'changes a timeout' = @{
                want = $false
                json = '{"hooks":{"Stop":[{"hooks":[{"args":["hook","--connector","claudecode","--enterprise-managed"],"command":"' + $hook + '","timeout":5,"type":"command"}]}],"PreToolUse":[{"matcher":"*","hooks":[{"args":["hook","--connector","claudecode","--enterprise-managed"],"command":"' + $hook + '","timeout":30,"type":"command"}]}]}}'
            }
            'drops the enterprise flag' = @{
                want = $false
                json = '{"hooks":{"Stop":[{"hooks":[{"args":["hook","--connector","claudecode"],"command":"' + $hook + '","timeout":30,"type":"command"}]}],"PreToolUse":[{"matcher":"*","hooks":[{"args":["hook","--connector","claudecode"],"command":"' + $hook + '","timeout":30,"type":"command"}]}]}}'
            }
            'has no hooks' = @{ want = $false; json = '{"model":"x"}' }
            'has non-object hooks' = @{ want = $false; json = '{"hooks":"none"}' }
        }
        foreach ($name in $cases.Keys) {
            $case = $cases[$name]
            try {
                $settings = $case.json | Microsoft.PowerShell.Utility\ConvertFrom-Json
                $got = Test-DefenseClawClaudeHKLMCarriesInstalledHooks -Settings $settings -Layout $layout
                if ([bool]$got -ne [bool]$case.want) {
                    $failures.Add("${name}: carries=$got, want $($case.want)")
                }
            }
            catch {
                $failures.Add("${name}: threw $($_.Exception.Message)")
            }
        }
        Microsoft.PowerShell.Management\Remove-Item -LiteralPath $policyPath -Force
        $settings = $cases['carries the installed matrix'].json | Microsoft.PowerShell.Utility\ConvertFrom-Json
        if (Test-DefenseClawClaudeHKLMCarriesInstalledHooks -Settings $settings -Layout $layout) {
            $failures.Add('without an installed DefenseClaw policy nothing can be carried')
        }
        foreach ($pair in @(
            @('{"b":1,"a":[true,null,"x"]}', '{"a":[true,null,"x"],"b":1}'),
            @('{"a":{"d":2,"c":1}}', '{"a":{"c":1,"d":2}}')
        )) {
            $left = ConvertTo-DefenseClawCanonicalJsonText -Value ($pair[0] | Microsoft.PowerShell.Utility\ConvertFrom-Json)
            $right = ConvertTo-DefenseClawCanonicalJsonText -Value ($pair[1] | Microsoft.PowerShell.Utility\ConvertFrom-Json)
            if ($left -cne $right) {
                $failures.Add("canonical JSON differs by key order: $left vs $right")
            }
        }
        # The Status view reads the live registry and must never throw.
        try {
            $state = Get-DefenseClawClaudeHKLMPolicyState -Layout $layout
            foreach ($field in @('shadowed', 'managed_sources_merge', 'merge_client_floor_required', 'detail')) {
                if ($null -eq $state.PSObject.Properties[$field]) {
                    $failures.Add("HKLM policy state is missing $field")
                }
            }
        }
        catch {
            $failures.Add("HKLM policy state threw: $($_.Exception.Message)")
        }
        # #899 review: under an HKLM merge policy the recorded client version
        # neither admits nor refuses a target; Status lists the targets whose
        # recorded version is below the merge floor.
        foreach ($case in @(
            @("2.1.242", "2.1.242", $true),
            @("2.1.250", "2.1.242", $true),
            @("2.1.241", "2.1.242", $false),
            @("", "2.1.242", $false),
            @("not-a-version", "2.1.242", $false)
        )) {
            $got = Test-DefenseClawClaudeVersionAtLeast -Value $case[0] -Minimum $case[1]
            if ([bool]$got -ne [bool]$case[2]) {
                $failures.Add("version $($case[0]) at least $($case[1]) = $got")
            }
        }
        foreach ($floor in @("2.1.154", "2.1.242", "2.1.152")) {
            if (-not (Test-DefenseClawClaudeMinimumClientVersion -Value $floor)) {
                $failures.Add("attested Claude floor $floor was not accepted")
            }
        }
        if (Test-DefenseClawClaudeMinimumClientVersion -Value "2.1.200") {
            $failures.Add("an arbitrary Claude floor was accepted")
        }
        $report = [pscustomobject]@{
            verification = @(
                [pscustomobject]@{ connector = "claudecode"; sid = "S-1-5-21-1-1001"; result = [pscustomobject]@{ agent_version = "2.1.154" } },
                [pscustomobject]@{ connector = "claudecode"; sid = "S-1-12-1-2-3-4-5"; result = [pscustomobject]@{ agent_version = "2.1.250" } },
                [pscustomobject]@{ connector = "claudecode"; sid = "S-1-5-21-1-1002"; result = [pscustomobject]@{ agent_version = "" } },
                [pscustomobject]@{ connector = "codex"; sid = "S-1-5-21-1-1003"; result = [pscustomobject]@{ agent_version = "0.131.0" } }
            )
        }
        $pending = @(Get-DefenseClawClaudeMergePendingTargets -Report $report)
        $want = @("claudecode@S-1-5-21-1-1001 (recorded 2.1.154)", "claudecode@S-1-5-21-1-1002 (recorded unknown)")
        if (($pending -join "|") -cne ($want -join "|")) {
            $failures.Add("merge pending targets = $($pending -join "|")")
        }
        if (@(Get-DefenseClawClaudeMergePendingTargets -Report $null).Count -ne 0) {
            $failures.Add("a missing guardian report listed merge pending targets")
        }
        return @($failures)
    } $root
}
finally {
    if ([IO.Directory]::Exists($root)) {
        Microsoft.PowerShell.Management\Remove-Item -LiteralPath $root -Recurse -Force
    }
}

$failures = @($failures | Microsoft.PowerShell.Core\Where-Object { $null -ne $_ })
if ($failures.Count -ne 0) {
    throw ("Claude HKLM policy smoke failed:`n" + ($failures -join "`n"))
}
Microsoft.PowerShell.Utility\Write-Output 'Claude HKLM policy smoke passed'
