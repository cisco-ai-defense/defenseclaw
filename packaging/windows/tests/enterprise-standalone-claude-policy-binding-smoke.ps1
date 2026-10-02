# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 5.1

# Function-level regression for standalone Claude effective-policy evidence.
# Standalone evidence (schema 3) binds the Claude policy identity the live
# proof exercised (the machine policy fragment plus the hook binary), not
# targets.yaml, which the enumerator rewrites on every enrollment change.
# Everything runs inside a disposable scratch directory; the protected-DACL
# assertion is stubbed because the exact-ACL smoke owns it.

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
    ('dc-standalone-claude-binding-' + [Guid]::NewGuid().ToString('N'))
)
[void][IO.Directory]::CreateDirectory($root)
try {
    $failures = & $module {
        param([string]$Root)

        function Assert-DefenseClawPathAcl {
            [CmdletBinding()]
            param(
                $Path,
                $AllowedWriterSIDs,
                $AllowedReaderSIDs,
                $RequiredRights,
                [switch]$AllowInheritance,
                [switch]$RejectUntrustedRead
            )
        }
        function New-DefenseClawDirectory {
            param([string]$Path)
        }

        $originalProgramFiles = $script:ProgramFiles
        $originalProfile = Get-DefenseClawEnterpriseProfile
        $script:ProgramFiles = $Root
        Set-DefenseClawEnterpriseProfile -EnterpriseProfile Standalone
        $failures = [Collections.Generic.List[string]]::new()
        try {
            $installState = [IO.Path]::Combine($Root, 'install')
            $bin = [IO.Path]::Combine($Root, 'bin')
            $guardian = [IO.Path]::Combine($Root, 'hook-guardian')
            $paths = Get-DefenseClawClaudeManagedPolicyPaths
            foreach ($directory in @(
                $installState,
                $bin,
                $guardian,
                [IO.Path]::GetDirectoryName([string]$paths.Policy)
            )) {
                [void][IO.Directory]::CreateDirectory($directory)
            }
            $layout = @{
                InstallStateDirectory = $installState
                AgentApplicationControlAttestationPath = [IO.Path]::Combine(
                    $installState,
                    'agent-application-control-attestation.json'
                )
                ManifestPath = [IO.Path]::Combine($guardian, 'targets.yaml')
                HookPath = [IO.Path]::Combine($bin, 'defenseclaw-hook.exe')
                CoreHardeningCertification = $false
                AgentApplicationControlAttested = $false
                ClaudeEffectivePolicyVerified = $false
            }
            $utf8 = [Text.UTF8Encoding]::new($false)

            function Get-TestSha256([string]$Path) {
                return (
                    Microsoft.PowerShell.Utility\Get-FileHash `
                        -LiteralPath $Path `
                        -Algorithm SHA256
                ).Hash.ToLowerInvariant()
            }
            function Set-TestClaudePolicy([string]$Body, [string[]]$TargetSIDs) {
                [IO.File]::WriteAllText([string]$paths.Policy, $Body, $utf8)
                $state = [ordered]@{
                    schema_version = 2
                    policy_sha256 = 'sha256:' + (Get-TestSha256 ([string]$paths.Policy))
                    hook_executable = $layout.HookPath
                    gateway_addr = '127.0.0.1:18970'
                    gateway_service_name = 'DefenseClawGateway'
                    target_sids = @($TargetSIDs)
                }
                [IO.File]::WriteAllText(
                    [string]$paths.State,
                    ($state | Microsoft.PowerShell.Utility\ConvertTo-Json -Depth 4),
                    $utf8
                )
            }
            function Set-TestAttestation([Collections.IDictionary]$Fields) {
                $value = [ordered]@{
                    schema_version = 3
                    agent_application_control_enforced = $false
                    prerequisite = 'wdac_or_applocker_approved_agent_client_rules'
                    approved_agent_clients_enforced = $false
                    minimum_claude_version = (Get-DefenseClawClaudeMinimumClientVersion)
                    claude_effective_policy_verified = $false
                    claude_effective_policy_managed_policy_sha256 = ''
                    claude_effective_policy_hook_sha256 = ''
                    attested_by_sid = 'S-1-5-32-544'
                    attested_at = '2026-09-01T00:00:00.0000000Z'
                    certification_required = $true
                }
                foreach ($key in @($Fields.Keys)) {
                    if ($null -eq $Fields[$key]) {
                        $value.Remove($key)
                    }
                    else {
                        $value[$key] = $Fields[$key]
                    }
                }
                [IO.File]::WriteAllText(
                    $layout.AgentApplicationControlAttestationPath,
                    ($value | Microsoft.PowerShell.Utility\ConvertTo-Json -Depth 4),
                    $utf8
                )
            }
            function Get-TestStaleReason {
                return [string](
                    (Get-DefenseClawAgentApplicationControlAttestation -Layout $layout).claude_effective_policy_stale_reason
                )
            }
            function Assert-TestFresh([string]$Label) {
                try {
                    $reason = Get-TestStaleReason
                    if (-not [string]::IsNullOrEmpty($reason)) {
                        $failures.Add("${Label}: expected current evidence, got stale reason: $reason")
                    }
                }
                catch {
                    $failures.Add("${Label}: expected current evidence, got throw: $($_.Exception.Message)")
                }
            }
            function Assert-TestStale([string]$Label) {
                try {
                    if ([string]::IsNullOrEmpty((Get-TestStaleReason))) {
                        $failures.Add("${Label}: expected a stale reason")
                    }
                }
                catch {
                    $failures.Add("${Label}: stale evidence must not throw, got: $($_.Exception.Message)")
                }
            }
            function Assert-TestThrows([string]$Label, [scriptblock]$Action) {
                try {
                    & $Action
                    $failures.Add("${Label}: expected a throw")
                }
                catch {
                }
            }

            [IO.File]::WriteAllText($layout.HookPath, 'hook-v1', $utf8)
            [IO.File]::WriteAllText($layout.ManifestPath, "version: 1`ntargets: []`n", $utf8)
            Set-TestClaudePolicy -Body '{"hooks":{"v":1}}' -TargetSIDs @('S-1-5-21-1-2-3-1001')

            # The writer binds a verified result to the current policy identity.
            $layout.ClaudeEffectivePolicyVerified = $true
            Write-DefenseClawAgentApplicationControlAttestation -Layout $layout
            $written = Microsoft.PowerShell.Management\Get-Content `
                -LiteralPath $layout.AgentApplicationControlAttestationPath `
                -Raw | Microsoft.PowerShell.Utility\ConvertFrom-Json
            if ([int]$written.schema_version -ne 3 -or
                [string]$written.claude_effective_policy_managed_policy_sha256 -cne (Get-TestSha256 ([string]$paths.Policy)) -or
                [string]$written.claude_effective_policy_hook_sha256 -cne (Get-TestSha256 $layout.HookPath) -or
                $null -ne $written.PSObject.Properties['claude_effective_policy_manifest_sha256']) {
                $failures.Add('writer: standalone evidence must be schema 3 bound to the policy and hook digests only')
            }
            Assert-TestFresh 'freshly written'

            # An enumerator-style targets.yaml rewrite and a new enrolled SID do
            # not change the policy Claude loads.
            [IO.File]::WriteAllText($layout.ManifestPath, "version: 1`ntargets:`n- sid: S-1-12-1-1-2-3-4`n", $utf8)
            Set-TestClaudePolicy -Body '{"hooks":{"v":1}}' -TargetSIDs @('S-1-5-21-1-2-3-1001', 'S-1-12-1-1-2-3-4')
            Assert-TestFresh 'after enrollment change'

            # A different policy or hook binary makes the evidence stale, not fatal.
            Set-TestClaudePolicy -Body '{"hooks":{"v":2}}' -TargetSIDs @('S-1-5-21-1-2-3-1001')
            Assert-TestStale 'after policy change'
            Set-TestClaudePolicy -Body '{"hooks":{"v":1}}' -TargetSIDs @('S-1-5-21-1-2-3-1001')
            [IO.File]::WriteAllText($layout.HookPath, 'hook-v2', $utf8)
            Assert-TestStale 'after hook binary change'

            # Stale evidence is never re-published as verified.
            $layout['ClaudeEffectivePolicyStaleReason'] = 'recorded for another policy'
            Assert-TestThrows 'writer refuses stale' {
                Write-DefenseClawAgentApplicationControlAttestation -Layout $layout
            }
            $layout['ClaudeEffectivePolicyStaleReason'] = ''

            # Malformed standalone evidence still fails closed.
            Set-TestAttestation @{ claude_effective_policy_verified = $true }
            Assert-TestThrows 'verified without a policy binding' { Get-TestStaleReason }

            # The Secure Client profile keeps its schema and manifest binding.
            Set-DefenseClawEnterpriseProfile -EnterpriseProfile SecureClient
            Set-TestAttestation @{ minimum_claude_version = '2.1.152' }
            Assert-TestThrows 'Secure Client rejects schema 3' { Get-TestStaleReason }
            if ((Get-DefenseClawAgentApplicationControlAttestationSchemaVersion) -ne 2 -or
                (Get-DefenseClawClaudeMinimumClientVersion) -cne '2.1.152') {
                $failures.Add('Secure Client schema or Claude floor changed')
            }
        }
        finally {
            $script:ProgramFiles = $originalProgramFiles
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
Microsoft.PowerShell.Utility\Write-Output 'enterprise-standalone-claude-policy-binding-smoke: OK'
