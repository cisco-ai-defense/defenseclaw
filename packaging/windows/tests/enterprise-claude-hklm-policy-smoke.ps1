# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 5.1

# Function-level regression for the Status view of an outranking HKLM Claude
# policy (#899). Only a disposable scratch directory is written; the machine
# registry is read, never written.

[CmdletBinding()]
param(
    [string]$ScratchRoot = [IO.Path]::GetTempPath(),
    [string]$VectorsPath = ''
)

Microsoft.PowerShell.Core\Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modulePath = [IO.Path]::GetFullPath(
    (Microsoft.PowerShell.Management\Join-Path `
        $PSScriptRoot `
        '..\DefenseClawEnterprise.psm1')
)
if ([string]::IsNullOrWhiteSpace($VectorsPath)) {
    $VectorsPath = [IO.Path]::GetFullPath(
        (Microsoft.PowerShell.Management\Join-Path `
            $PSScriptRoot `
            '..\..\..\internal\gateway\connector\testdata\claude_hklm_admission_vectors.json')
    )
}
$vectorsText = [IO.File]::ReadAllText($VectorsPath)
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
        param([string]$Root, [string]$VectorsText)
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
            # A second DefenseClaw PreToolUse copy: Claude Code runs one copy
            # of a repeated hook, whatever its timeout.
            'repeats the PreToolUse entry' = @{
                want = $false
                json = '{"hooks":{"Stop":[{"hooks":[{"args":["hook","--connector","claudecode","--enterprise-managed"],"command":"' + $hook + '","timeout":30,"type":"command"}]}],"PreToolUse":[{"matcher":"*","hooks":[{"args":["hook","--connector","claudecode","--enterprise-managed"],"command":"' + $hook + '","timeout":30,"type":"command"}]},{"matcher":"*","hooks":[{"args":["hook","--connector","claudecode","--enterprise-managed"],"command":"' + $hook + '","timeout":30,"type":"command"}]}]}}'
            }
            'adds a shorter PreToolUse copy' = @{
                want = $false
                json = '{"hooks":{"Stop":[{"hooks":[{"args":["hook","--connector","claudecode","--enterprise-managed"],"command":"' + $hook + '","timeout":30,"type":"command"}]}],"PreToolUse":[{"matcher":"*","hooks":[{"args":["hook","--connector","claudecode","--enterprise-managed"],"command":"' + $hook + '","timeout":30,"type":"command"}]},{"matcher":"Bash","hooks":[{"args":["hook","--connector","claudecode","--enterprise-managed"],"command":"' + $hook + '","timeout":1,"type":"command"}]}]}}'
            }
            'has no hooks' = @{ want = $false; json = '{"model":"x"}' }
            'has non-object hooks' = @{ want = $false; json = '{"hooks":"none"}' }
        }
        foreach ($name in $cases.Keys) {
            $case = $cases[$name]
            try {
                $settings = ConvertFrom-DefenseClawStrictJson -Text $case.json
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
        $settings = ConvertFrom-DefenseClawStrictJson -Text $cases['carries the installed matrix'].json
        if (Test-DefenseClawClaudeHKLMCarriesInstalledHooks -Settings $settings -Layout $layout) {
            $failures.Add('without an installed DefenseClaw policy nothing can be carried')
        }
        foreach ($pair in @(
            @('{"b":1,"a":[true,null,"x"]}', '{"a":[true,null,"x"],"b":1}'),
            @('{"a":{"d":2,"c":1}}', '{"a":{"c":1,"d":2}}')
        )) {
            $left = ConvertTo-DefenseClawCanonicalJsonText -Value (ConvertFrom-DefenseClawStrictJson -Text $pair[0])
            $right = ConvertTo-DefenseClawCanonicalJsonText -Value (ConvertFrom-DefenseClawStrictJson -Text $pair[1])
            if ($left -cne $right) {
                $failures.Add("canonical JSON differs by key order: $left vs $right")
            }
        }
        # #899 review: the Status verdict parses the HKLM value as strict JSON
        # with case-sensitive keys, as Claude Code and the gateway do.
        foreach ($pair in @(
            @('[1,[2,[]],{},true,false,null,-0.5e1,"x"]', '[1,[2,[]],{},true,false,null,-5,"x"]'),
            @('{"a":1,"A":2}', '{"A":2,"a":1}'),
            @('{"a":1,"a":{"b":2}}', '{"a":{"b":2}}'),
            @('{"":{"":[]}}', '{"" : {"" : [ ]}}'),
            @('["\u0041\n\"\\\/\t"]', '["A\n\"\\/\t"]'),
            @(" `r`n`t{} ", '{}')
        )) {
            try {
                $got = ConvertTo-DefenseClawCanonicalJsonText -Value (ConvertFrom-DefenseClawStrictJson -Text $pair[0])
                $want = ConvertTo-DefenseClawCanonicalJsonText -Value (ConvertFrom-DefenseClawStrictJson -Text $pair[1])
                if ($got -cne $want) {
                    $failures.Add("strict JSON $($pair[0]) = $got, want $want")
                }
            }
            catch {
                $failures.Add("strict JSON $($pair[0]) threw $($_.Exception.Message)")
            }
        }
        $cased = ConvertFrom-DefenseClawStrictJson -Text '{"hooks":1,"Hooks":2}'
        if ($cased.Count -ne 2 -or [double](Get-DefenseClawJsonMember -Object $cased -Name 'Hooks').Value -ne 2 -or
            $null -ne (Get-DefenseClawJsonMember -Object $cased -Name 'HOOKS')) {
            $failures.Add('strict JSON did not keep keys that differ only in case')
        }
        foreach ($bad in @(
            '', ' ', '{', '}', '{"a":1,}', '[1,]', '[,1]', '{,}', "{'a':1}", '{"a":1/*c*/}', '{"a":1}//c',
            '[01]', '[1.]', '[.5]', '[+1]', '[-]', '[NaN]', '[Infinity]', "[`"a`tb`"]", '["\x"]', '["\u12"]',
            '{"a" 1}', '{"a":}', '{a:1}', '[1 2]', '{"a":1} x', '{"a":1}{}', 'tru', 'nul', "`v{}", "{}`v",
            ([string][char]0xFEFF + '{}')
        )) {
            try {
                $null = ConvertFrom-DefenseClawStrictJson -Text $bad
                $failures.Add("strict JSON accepted $bad")
            }
            catch {
                # Refused, as Claude Code and the gateway refuse it.
            }
        }
        # Windows PowerShell 5.1 ConvertFrom-Json stops at 100 levels; the
        # gateway reads up to 10000.
        $node = ConvertFrom-DefenseClawStrictJson -Text (('[' * 300) + (']' * 300))
        $depth = 0
        while ($node -is [Collections.IList]) {
            $depth++
            if ($node.Count -eq 0) {
                break
            }
            $node = $node[0]
        }
        if ($depth -ne 300) {
            $failures.Add("strict JSON kept $depth of 300 nested lists")
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
        # #899 review: the Status verdict reads an HKLM policy the way the
        # gateway admission gate does. TestClaudeHKLMAdmissionVectorsOnWindows
        # runs the same documents through connector
        # ClaudeCodeOSAdminPolicyAdmitsManagedHooks and checks that the
        # installed drop-in below is the one the gateway renders.
        $vectors = $VectorsText | Microsoft.PowerShell.Utility\ConvertFrom-Json
        $expand = {
            param([string]$Text)
            foreach ($token in @($vectors.tokens)) {
                $Text = $Text.Replace([string]$token[0], [string]$token[1])
            }
            return $Text
        }
        $vectorCount = 0
        foreach ($case in @($vectors.cases)) {
            $vectorCount++
            $optOut = [bool]($null -ne $case.PSObject.Properties['opt_out'] -and [bool]$case.opt_out)
            $installedText = if ($optOut) { [string]$vectors.installed_opt_out } else { [string]$vectors.installed }
            [IO.File]::WriteAllText($policyPath, (& $expand $installedText), [Text.UTF8Encoding]::new($false))
            $want = [string]$case.want
            $wantShadowed = $want -ceq 'refuse'
            $wantFloor = $want -ceq 'merge'
            $wantMerge = [bool](
                $want -ceq 'merge' -or
                ($want -ceq 'carry' -and $null -ne $case.PSObject.Properties['managed_sources_merge'] -and
                    [bool]$case.managed_sources_merge)
            )
            try {
                $verdict = Get-DefenseClawClaudeHKLMPolicyVerdict -Raw (& $expand ([string]$case.settings)) -Layout $layout
                if ([bool]$verdict.shadowed -ne $wantShadowed -or
                    (-not $wantShadowed -and
                        ([bool]$verdict.merge_client_floor_required -ne $wantFloor -or
                            [bool]$verdict.managed_sources_merge -ne $wantMerge))) {
                    $failures.Add("vector $($case.name): shadowed=$($verdict.shadowed) merge=$($verdict.managed_sources_merge) floor=$($verdict.merge_client_floor_required), want $want ($($verdict.detail))")
                }
                if ($wantShadowed -and [string]::IsNullOrWhiteSpace([string]$verdict.detail)) {
                    $failures.Add("vector $($case.name): refused without a detail")
                }
            }
            catch {
                $failures.Add("vector $($case.name): threw $($_.Exception.Message)")
            }
        }
        if ($vectorCount -lt 40) {
            $failures.Add("only $vectorCount HKLM admission vectors were read")
        }
        # Without an installed drop-in nothing can be carried, while a merge
        # policy still only raises the client floor.
        Microsoft.PowerShell.Management\Remove-Item -LiteralPath $policyPath -Force
        $carried = Get-DefenseClawClaudeHKLMPolicyVerdict -Raw (& $expand '{"allowManagedHooksOnly":true,"hooks":{@MATRIX@}}') -Layout $layout
        if (-not [bool]$carried.shadowed) {
            $failures.Add('a carried matrix was admitted without an installed drop-in')
        }
        $merged = Get-DefenseClawClaudeHKLMPolicyVerdict -Raw '{"managedSourcesBehavior":"merge"}' -Layout $layout
        if ([bool]$merged.shadowed -or -not [bool]$merged.merge_client_floor_required) {
            $failures.Add("merge without an installed drop-in = shadowed=$($merged.shadowed) floor=$($merged.merge_client_floor_required)")
        }
        $none = Get-DefenseClawClaudeHKLMPolicyVerdict -Raw $null -Layout $layout
        if ([bool]$none.shadowed) {
            $failures.Add('a missing Settings value was reported as shadowing')
        }
        return @($failures)
    } $root $vectorsText
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
