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
$moduleAst = [Management.Automation.Language.Parser]::ParseFile(
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
    },
    @{
        needle = 'refusing -DeferredConfig against an active DefenseClaw'
        why    = '-DeferredConfig must be refused inside reconcile-Install to avoid stopping services with a placeholder policy in place'
    }
)
foreach ($entry in $required) {
    if (-not $body.Contains($entry.needle)) {
        throw "enterprise-install-reconcile-smoke: expected marker missing ($($entry.why)): ``$($entry.needle)``"
    }
}

# ---- structural: verify branch ownership via the parsed IfStatementAst
# rather than a substring near-miss. The psm1 must contain an IfStatementAst
# whose clauses look like:
#   if     ($null -ne $metadata -and (Test-DefenseClawMetadataInstalled ...))
#          { ... $reconcileInstall = $true; reconcile warning; DeferredConfig refusal }
#   elseif ($null -ne $metadata)
#          { ... Remove-DefenseClawCommittedManagedHooksTeardownJournal ... }
#
# Substring proximity would accept an unrelated elseif elsewhere in the
# 22 000-line module. `IfStatementAst.Clauses` binds the assertion to the
# actual clause structure.

function Test-BranchClause {
    param(
        [Parameter(Mandatory)][string]$Text,
        [Parameter(Mandatory)][string[]]$MustContain,
        [Parameter(Mandatory)][string]$Label
    )
    foreach ($needle in $MustContain) {
        if (-not $Text.Contains($needle)) {
            throw "enterprise-install-reconcile-smoke: ${Label} clause missing required text: ``$needle``"
        }
    }
}

# Locate the `if ($Action -eq 'Install')` dispatch that carries the reconcile
# branch. There are several `if ($Action -eq 'Install')` sites across the
# module; the reconcile one is uniquely identified by its body containing
# Test-DefenseClawMetadataInstalled. Anchoring the search here means a future
# refactor can't move the reconcile branch under a different action (Upgrade,
# Repair, Reconcile) without failing this test.
$installDispatch = $null
foreach ($ifNode in $moduleAst.FindAll(
    { param($node) $node -is [Management.Automation.Language.IfStatementAst] },
    $true
)) {
    if ($ifNode.Clauses.Count -lt 1) { continue }
    $cond = $ifNode.Clauses[0].Item1.Extent.Text
    if ($cond -notmatch '^\s*\$Action\s+-eq\s+''Install''\s*$') { continue }
    $bodyText = $ifNode.Clauses[0].Item2.Extent.Text
    if ($bodyText -notmatch 'Test-DefenseClawMetadataInstalled') { continue }
    $installDispatch = $ifNode
    break
}
if ($null -eq $installDispatch) {
    throw 'enterprise-install-reconcile-smoke: could not locate the `if ($Action -eq ''Install'')` dispatch whose body gates on Test-DefenseClawMetadataInstalled'
}

# Only look for the reconcile if/elseif INSIDE that dispatch block so the
# assertion cannot pass on a hypothetical Upgrade/Repair reconcile branch.
$installBodyAst = $installDispatch.Clauses[0].Item2
$ifCandidates = $installBodyAst.FindAll(
    {
        param($node)
        if ($node -isnot [Management.Automation.Language.IfStatementAst]) { return $false }
        if ($node.Clauses.Count -lt 2) { return $false }
        $firstCond = $node.Clauses[0].Item1.Extent.Text
        return ($firstCond -match 'Test-DefenseClawMetadataInstalled' -and
                $firstCond -match '\$metadata')
    },
    $true
)

$reconcileIf = $null
foreach ($candidate in $ifCandidates) {
    $firstBody = $candidate.Clauses[0].Item2.Extent.Text
    if ($firstBody -notmatch [regex]::Escape('$reconcileInstall = $true')) {
        continue
    }
    if ($firstBody -notmatch [regex]::Escape('reconciling existing installation')) {
        continue
    }
    $reconcileIf = $candidate
    break
}
if ($null -eq $reconcileIf) {
    throw 'enterprise-install-reconcile-smoke: could not locate an if/elseif rooted at (Test-DefenseClawMetadataInstalled) WITHIN the `if ($Action -eq ''Install'')` dispatch whose reconcile clause sets $reconcileInstall = $true and emits the reconcile warning'
}

$reconcileClauseCond = $reconcileIf.Clauses[0].Item1.Extent.Text
$reconcileClauseBody = $reconcileIf.Clauses[0].Item2.Extent.Text
$tombstoneClauseCond = $reconcileIf.Clauses[1].Item1.Extent.Text
$tombstoneClauseBody = $reconcileIf.Clauses[1].Item2.Extent.Text

if ($reconcileClauseCond -notmatch '\$null\s+-ne\s+\$metadata\s+-and' -or
    $reconcileClauseCond -notmatch 'Test-DefenseClawMetadataInstalled') {
    throw "enterprise-install-reconcile-smoke: reconcile clause condition must gate on active metadata; got: $reconcileClauseCond"
}
if ($tombstoneClauseCond -notmatch '^\s*\$null\s+-ne\s+\$metadata\s*$') {
    throw "enterprise-install-reconcile-smoke: tombstone clause condition must be exactly `$null -ne `$metadata (elseif for the inactive-metadata tombstone lane); got: $tombstoneClauseCond"
}

Test-BranchClause -Text $reconcileClauseBody -Label 'reconcile' -MustContain @(
    '$reconcileInstall = $true',
    'reconciling existing installation',
    'refusing -DeferredConfig against an active DefenseClaw'
)
Test-BranchClause -Text $tombstoneClauseBody -Label 'tombstone' -MustContain @(
    'Remove-DefenseClawCommittedManagedHooksTeardownJournal'
)
if ($tombstoneClauseBody.Contains('$reconcileInstall = $true')) {
    throw 'enterprise-install-reconcile-smoke: tombstone clause must not flip $reconcileInstall (that flag is reconcile-only)'
}
if ($tombstoneClauseBody.Contains('reconciling existing installation')) {
    throw 'enterprise-install-reconcile-smoke: reconcile warning must not appear in the tombstone clause'
}

'enterprise-install-reconcile-smoke OK'
