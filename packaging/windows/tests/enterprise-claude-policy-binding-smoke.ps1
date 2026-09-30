# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 5.1

# Function-level regression for Claude effective-policy evidence (#895).
# Everything runs inside a disposable scratch directory: no service, user,
# ProgramData/Program Files tree, or machine policy is created or read. The
# protected-DACL assertion is stubbed because the exact-ACL smoke owns it;
# this smoke owns only the binding semantics.

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
    ('dc-claude-binding-' + [Guid]::NewGuid().ToString('N'))
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

        $installState = [IO.Path]::Combine($Root, 'install')
        $bin = [IO.Path]::Combine($Root, 'bin')
        $guardian = [IO.Path]::Combine($Root, 'hook-guardian')
        $claudeDirectory = [IO.Path]::Combine($Root, 'ClaudeCode\managed-settings.d')
        foreach ($directory in @($installState, $bin, $guardian, $claudeDirectory)) {
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
            ClaudeManagedPolicyPath = [IO.Path]::Combine($claudeDirectory, '90-defenseclaw.json')
            ClaudeManagedPolicyStatePath = [IO.Path]::Combine(
                $claudeDirectory,
                '.defenseclaw-managed-hooks.state'
            )
            CoreHardeningCertification = $false
            AgentApplicationControlAttested = $false
            ClaudeEffectivePolicyVerified = $false
            ClaudeEffectivePolicyStaleReason = ''
        }
        $utf8 = [Text.UTF8Encoding]::new($false)
        $failures = [Collections.Generic.List[string]]::new()

        function Get-TestSha256([string]$Path) {
            return (
                Microsoft.PowerShell.Utility\Get-FileHash `
                    -LiteralPath $Path `
                    -Algorithm SHA256
            ).Hash.ToLowerInvariant()
        }
        function Set-TestClaudePolicy([string]$Body, [string[]]$TargetSIDs) {
            [IO.File]::WriteAllText($layout.ClaudeManagedPolicyPath, $Body, $utf8)
            $state = [ordered]@{
                schema_version = 2
                policy_sha256 = 'sha256:' + (Get-TestSha256 $layout.ClaudeManagedPolicyPath)
                hook_executable = $layout.HookPath
                gateway_addr = '127.0.0.1:18970'
                gateway_service_name = 'DefenseClawGateway'
                target_sids = @($TargetSIDs)
            }
            [IO.File]::WriteAllText(
                $layout.ClaudeManagedPolicyStatePath,
                ($state | Microsoft.PowerShell.Utility\ConvertTo-Json -Depth 4),
                $utf8
            )
        }
        function Set-TestManifest([string]$Body) {
            [IO.File]::WriteAllText($layout.ManifestPath, $Body, $utf8)
        }
        function Set-TestAttestation([Collections.IDictionary]$Fields) {
            $value = [ordered]@{
                schema_version = 3
                agent_application_control_enforced = $false
                prerequisite = 'wdac_or_applocker_approved_agent_client_rules'
                approved_agent_clients_enforced = $false
                minimum_claude_version = '2.1.152'
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
                $attestation = Get-DefenseClawAgentApplicationControlAttestation -Layout $layout
                if (-not [bool]$attestation.claude_effective_policy_verified) {
                    $failures.Add("${Label}: recorded claim must stay true for metadata consistency")
                }
                if ([string]::IsNullOrEmpty([string]$attestation.claude_effective_policy_stale_reason)) {
                    $failures.Add("${Label}: expected a stale reason, evidence was reported current")
                }
            }
            catch {
                $failures.Add("${Label}: stale evidence must degrade, got throw: $($_.Exception.Message)")
            }
        }
        function Assert-TestThrows([string]$Label, [scriptblock]$Action, [string]$Pattern) {
            try {
                & $Action
                $failures.Add("${Label}: expected a throw matching '$Pattern'")
            }
            catch {
                if ($_.Exception.Message -notmatch $Pattern) {
                    $failures.Add("${Label}: unexpected throw: $($_.Exception.Message)")
                }
            }
        }

        $policyV1 = "{`n  `"hooks`": {`n    `"PreToolUse`": []`n  }`n}`n"
        $policyV2 = "{`n  `"hooks`": {`n    `"DirectoryAdded`": [],`n    `"PreToolUse`": []`n  }`n}`n"
        [IO.File]::WriteAllBytes($layout.HookPath, [byte[]](1, 2, 3, 4))
        Set-TestClaudePolicy -Body $policyV1 -TargetSIDs @('S-1-5-21-1-2-3-1001')
        Set-TestManifest -Body "schema_version: 1`ntargets: [alice]`n"

        # Attest through the production writer.
        $layout.ClaudeEffectivePolicyVerified = $true
        Write-DefenseClawAgentApplicationControlAttestation -Layout $layout
        $written = [IO.File]::ReadAllText($layout.AgentApplicationControlAttestationPath) |
            Microsoft.PowerShell.Utility\ConvertFrom-Json
        if ([int]$written.schema_version -ne 3 -or
            -not [bool]$written.claude_effective_policy_verified -or
            [string]$written.claude_effective_policy_managed_policy_sha256 -cne
                (Get-TestSha256 $layout.ClaudeManagedPolicyPath) -or
            [string]$written.claude_effective_policy_hook_sha256 -cne
                (Get-TestSha256 $layout.HookPath) -or
            $null -ne $written.PSObject.Properties['claude_effective_policy_manifest_sha256']) {
            $failures.Add('writer: schema-3 evidence is not bound to the Claude policy and hook digests')
        }
        Assert-TestFresh 'freshly attested'

        # #895: the enumerator rewrites targets.yaml and the sidecar SID list
        # when another user enrolls. That is not a different Claude policy.
        Set-TestManifest -Body "schema_version: 1`ntargets: [alice, bob]`n"
        Set-TestClaudePolicy -Body $policyV1 -TargetSIDs @(
            'S-1-5-21-1-2-3-1001',
            'S-1-5-21-1-2-3-1002'
        )
        Assert-TestFresh 'enumerator rewrote targets.yaml and target SIDs'

        # A different policy fragment (for example another hook contract) is
        # a different Claude policy: the evidence cannot be reused.
        Set-TestClaudePolicy -Body $policyV2 -TargetSIDs @('S-1-5-21-1-2-3-1001')
        Assert-TestStale 'Claude policy fragment changed'
        Set-TestClaudePolicy -Body $policyV1 -TargetSIDs @('S-1-5-21-1-2-3-1001')
        Assert-TestFresh 'Claude policy fragment restored'

        # A replaced hook binary was never exercised by the live proof.
        [IO.File]::WriteAllBytes($layout.HookPath, [byte[]](9, 9, 9, 9))
        Assert-TestStale 'hook binary replaced'
        [IO.File]::WriteAllBytes($layout.HookPath, [byte[]](1, 2, 3, 4))
        Assert-TestFresh 'hook binary restored'

        # Policy bytes that the DefenseClaw sidecar does not own.
        [IO.File]::WriteAllText($layout.ClaudeManagedPolicyPath, $policyV1 + ' ', $utf8)
        Assert-TestStale 'policy does not match its ownership record'
        Set-TestClaudePolicy -Body $policyV1 -TargetSIDs @('S-1-5-21-1-2-3-1001')

        # Removed policy (no Claude target left): degrade, never throw.
        Microsoft.PowerShell.Management\Remove-Item `
            -LiteralPath $layout.ClaudeManagedPolicyPath `
            -Force
        Assert-TestStale 'Claude policy removed'

        # The writer refuses to attest without the installed Claude policy
        # and refuses to re-publish carried-over stale evidence.
        Assert-TestThrows 'writer without Claude policy' {
            $layout.ClaudeEffectivePolicyVerified = $true
            $layout.ClaudeEffectivePolicyStaleReason = ''
            Write-DefenseClawAgentApplicationControlAttestation -Layout $layout
        } 'cannot attest Claude effective policy without the installed DefenseClaw Claude policy'
        Set-TestClaudePolicy -Body $policyV1 -TargetSIDs @('S-1-5-21-1-2-3-1001')
        Assert-TestThrows 'writer with carried-over stale evidence' {
            $layout.ClaudeEffectivePolicyVerified = $true
            $layout.ClaudeEffectivePolicyStaleReason = 'recorded for another policy'
            Write-DefenseClawAgentApplicationControlAttestation -Layout $layout
        } 'refusing to re-publish stale Claude effective-policy evidence'
        $layout.ClaudeEffectivePolicyStaleReason = ''

        # Unverified evidence carries no binding and is never stale.
        $layout.ClaudeEffectivePolicyVerified = $false
        Write-DefenseClawAgentApplicationControlAttestation -Layout $layout
        Assert-TestFresh 'unverified evidence'

        # Legacy schema-2 evidence bound to a since-rewritten targets.yaml:
        # previously a throw on every lifecycle action.
        Set-TestAttestation @{
            schema_version = 2
            claude_effective_policy_verified = $true
            claude_effective_policy_managed_policy_sha256 = $null
            claude_effective_policy_hook_sha256 = $null
            claude_effective_policy_manifest_sha256 = ('0' * 64)
        }
        Assert-TestStale 'legacy schema-2 manifest-bound evidence'
        Set-TestAttestation @{
            schema_version = 2
            claude_effective_policy_managed_policy_sha256 = $null
            claude_effective_policy_hook_sha256 = $null
            claude_effective_policy_manifest_sha256 = ''
        }
        Assert-TestFresh 'legacy schema-2 unverified evidence'

        # Review of #895: Repair -AttestClaudeEffectivePolicy that first
        # recovers a pending transaction. Restore-DefenseClawTransaction puts
        # the interrupted transaction's recorded claim and the restored
        # evidence's stale reason back into the layout, which made the
        # explicit re-attest throw. Re-applying the requested attestations
        # after recovery rebinds the evidence to the current identity.
        Set-TestAttestation @{
            schema_version = 2
            claude_effective_policy_verified = $true
            claude_effective_policy_managed_policy_sha256 = $null
            claude_effective_policy_hook_sha256 = $null
            claude_effective_policy_manifest_sha256 = ('0' * 64)
        }
        $restored = Get-DefenseClawAgentApplicationControlAttestation -Layout $layout
        $layout.AgentApplicationControlAttested = [bool]$restored.agent_application_control_enforced
        $layout.ClaudeEffectivePolicyVerified = [bool]$restored.claude_effective_policy_verified
        $layout.ClaudeEffectivePolicyStaleReason = [string]$restored.claude_effective_policy_stale_reason
        Assert-TestThrows 'recovered stale evidence without the requested attestation' {
            Write-DefenseClawAgentApplicationControlAttestation -Layout $layout
        } 'refusing to re-publish stale Claude effective-policy evidence'
        Set-DefenseClawRequestedAttestations -Layout $layout -AttestClaudeEffectivePolicy
        try {
            Write-DefenseClawAgentApplicationControlAttestation -Layout $layout
            $rebound = [IO.File]::ReadAllText($layout.AgentApplicationControlAttestationPath) |
                Microsoft.PowerShell.Utility\ConvertFrom-Json
            if ([int]$rebound.schema_version -ne 3 -or
                -not [bool]$rebound.claude_effective_policy_verified -or
                [string]$rebound.claude_effective_policy_managed_policy_sha256 -cne
                    (Get-TestSha256 $layout.ClaudeManagedPolicyPath)) {
                $failures.Add('re-attest after recovery: evidence was not rebound to the current Claude policy')
            }
            Assert-TestFresh 're-attest after recovery'
        }
        catch {
            $failures.Add("re-attest after recovery: unexpected throw: $($_.Exception.Message)")
        }
        # A snapshot that recorded no application control must not swallow
        # this transaction's -AttestAgentApplicationControl either.
        $layout.AgentApplicationControlAttested = $false
        Set-DefenseClawRequestedAttestations -Layout $layout -AttestAgentApplicationControl
        if (-not [bool]$layout.AgentApplicationControlAttested) {
            $failures.Add('requested application-control attestation was not re-applied')
        }
        $layout.CoreHardeningCertification = $true
        Assert-TestThrows 'requested attestation in core-hardening mode' {
            Set-DefenseClawRequestedAttestations -Layout $layout -AttestClaudeEffectivePolicy
        } 'forbidden in core-hardening certification mode'
        $layout.CoreHardeningCertification = $false
        $layout.AgentApplicationControlAttested = $false
        $layout.ClaudeEffectivePolicyVerified = $false
        $layout.ClaudeEffectivePolicyStaleReason = ''

        # A fresh Install has no DefenseClaw Claude policy for a live proof to
        # have exercised, so the flag is refused before any lifecycle work
        # (it used to fail late and roll the Install back).
        foreach ($lifecycleAction in @('Install', 'Verify')) {
            Assert-TestThrows "-AttestClaudeEffectivePolicy with $lifecycleAction" {
                Invoke-DefenseClawEnterpriseLifecycle `
                    -Action $lifecycleAction `
                    -AttestClaudeEffectivePolicy
            } '-AttestClaudeEffectivePolicy is valid only with Upgrade or Repair'
        }

        # Malformed evidence still fails closed.
        Set-TestAttestation @{
            claude_effective_policy_verified = $true
        }
        Assert-TestThrows 'verified evidence without a binding' {
            [void](Get-DefenseClawAgentApplicationControlAttestation -Layout $layout)
        } 'not bound to a Claude policy identity'
        Set-TestAttestation @{
            claude_effective_policy_hook_sha256 = ('a' * 64)
        }
        Assert-TestThrows 'unverified evidence with a binding' {
            [void](Get-DefenseClawAgentApplicationControlAttestation -Layout $layout)
        } 'unexpectedly records a Claude policy binding'
        Set-TestAttestation @{
            claude_effective_policy_manifest_sha256 = ''
        }
        Assert-TestThrows 'schema-3 evidence with a legacy manifest binding' {
            [void](Get-DefenseClawAgentApplicationControlAttestation -Layout $layout)
        } 'legacy manifest binding'
        Set-TestAttestation @{ schema_version = 4 }
        Assert-TestThrows 'unknown schema' {
            [void](Get-DefenseClawAgentApplicationControlAttestation -Layout $layout)
        } 'unsupported agent application-control attestation schema'

        return @($failures)
    } $root
}
finally {
    if ([IO.Directory]::Exists($root)) {
        Microsoft.PowerShell.Management\Remove-Item `
            -LiteralPath $root `
            -Recurse `
            -Force
    }
}

$failures = @($failures | Microsoft.PowerShell.Core\Where-Object { $null -ne $_ })
if ($failures.Count -ne 0) {
    throw ("Claude effective-policy binding smoke failed:`n" + ($failures -join "`n"))
}
Microsoft.PowerShell.Utility\Write-Output 'Claude effective-policy binding smoke passed'
