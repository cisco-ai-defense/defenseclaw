# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 5.1

# Idempotent-Install regression guard. AVC's Windows installer runs
# `-Action Install` unconditionally after its own preinstall has removed
# the machine-wide state; refusing on a still-present active deployment
# aborted a legitimate reinstall on hosts where metadata survived (see
# the AVC 5.1.21.3862 DART for the macOS twin). This test pins the psm1
# body so a future refactor that reintroduces the throw is caught in CI
# before it ships in another AVC drop.
#
# The test is static: it parses the psm1 rather than importing it. That
# keeps the coverage independent of test-mock scaffolding for
# Read-DefenseClawInstallMetadata, which does not yet exist for this
# code path.

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modulePath = [IO.Path]::GetFullPath(
    (Microsoft.PowerShell.Management\Join-Path $PSScriptRoot '..\DefenseClawEnterprise.psm1')
)

$parseErrors = $null
$parseTokens = $null
[void][Management.Automation.Language.Parser]::ParseFile(
    $modulePath,
    [ref]$parseTokens,
    [ref]$parseErrors
)
if ($parseErrors.Count -ne 0) {
    throw "module parser errors: $($parseErrors.Message -join '; ')"
}

$body = Microsoft.PowerShell.Management\Get-Content -LiteralPath $modulePath -Raw

# ---- must NOT contain: the pre-reinstall refusal ------------------------

$forbidden = @(
    @{
        needle = "'DefenseClaw enterprise mode is already installed; use Upgrade or Repair'"
        why    = 'idempotent-Install regression: throw text reintroduced'
    },
    @{
        needle = 'throw ''DefenseClaw enterprise mode is already installed'
        why    = 'idempotent-Install regression: any throw of the already-installed text'
    }
)
foreach ($entry in $forbidden) {
    if ($body.Contains($entry.needle)) {
        throw "enterprise-install-reconcile-smoke: $($entry.why): ``$($entry.needle)`` reappeared in the psm1"
    }
}

# ---- must contain: the reconcile-in-place branch ------------------------

$required = @(
    @{
        needle = 'reconciling existing installation'
        why    = 'reconcile-Install warning wording'
    },
    @{
        needle = '$reconcileInstall = $false'
        why    = 'reconcile-Install selector declared before the Install/Upgrade dispatch'
    },
    @{
        needle = '$reconcileInstall = $true'
        why    = 'reconcile-Install selector flipped when metadata is installed'
    },
    @{
        needle = '-not $reconcileInstall'
        why    = 'inactive-metadata tombstone adoption is gated on reconcile-Install'
    }
)
foreach ($entry in $required) {
    if (-not $body.Contains($entry.needle)) {
        throw "enterprise-install-reconcile-smoke: expected marker missing ($($entry.why)): ``$($entry.needle)``"
    }
}

# ---- structural: the reconcile-Install branch and the tombstone-lane
# branch must NOT both fire in the same run. In practice this is the
# `if/elseif` split around the `Test-DefenseClawMetadataInstalled` check
# — grep for both members of the pair in close proximity so an
# accidental flatten to two independent `if` blocks is caught.

$reconcileFirst = $body.IndexOf('reconciling existing installation')
$tombstoneLater = $body.IndexOf(
    'Remove-DefenseClawCommittedManagedHooksTeardownJournal',
    $reconcileFirst
)
if ($reconcileFirst -lt 0 -or $tombstoneLater -lt 0 -or $reconcileFirst -ge $tombstoneLater) {
    throw 'enterprise-install-reconcile-smoke: reconcile warning must precede the tombstone-teardown branch'
}
$elseifBetween = $body.Substring(
    $reconcileFirst,
    [Math]::Min(2000, $tombstoneLater - $reconcileFirst)
)
if (-not $elseifBetween.Contains('elseif ($null -ne $metadata)')) {
    throw 'enterprise-install-reconcile-smoke: tombstone-teardown must be the elseif of the reconcile branch, not a separate if'
}

'enterprise-install-reconcile-smoke OK'
