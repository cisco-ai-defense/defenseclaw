# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$harness = Join-Path $PSScriptRoot 'run-windows.ps1'
$workflow = Join-Path $root '.github\workflows\connector-live-e2e.yml'

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw "assertion failed: $Message" }
}

foreach ($scriptPath in @($harness, $PSCommandPath)) {
    $tokens = $null
    $errors = $null
    [void][Management.Automation.Language.Parser]::ParseFile(
        $scriptPath, [ref]$tokens, [ref]$errors
    )
    Assert-True (@($errors).Count -eq 0) `
        "PowerShell parser errors in ${scriptPath}: $($errors -join '; ')"
}

$pwsh = (Get-Command 'pwsh.exe' -CommandType Application -ErrorAction Stop |
    Select-Object -First 1).Source
foreach ($fixture in @(
    [pscustomobject]@{
        Switch = '-LocalAuthorityFixture'
        Root = 'D:\dc-antigravity-local-authority-fixture-' + [Guid]::NewGuid().ToString('N')
        Pass = 'authenticated Antigravity local-authority dynamic fixture: PASS'
    },
    [pscustomobject]@{
        Switch = '-HeldStateFixture'
        Root = 'D:\dc-antigravity-held-state-fixture-' + [Guid]::NewGuid().ToString('N')
        Pass = 'authenticated Antigravity held-state dynamic fixture: PASS'
    }
)) {
    $output = @(& $pwsh -NoLogo -NoProfile -NonInteractive -File $harness `
        $fixture.Switch -StateRoot $fixture.Root 2>&1)
    Assert-True ($LASTEXITCODE -eq 0) `
        "fixture failed: $($output -join [Environment]::NewLine)"
    Assert-True ($output -contains $fixture.Pass) "fixture did not report PASS: $($fixture.Switch)"
    Assert-True (-not (Test-Path -LiteralPath $fixture.Root)) `
        "fixture left its isolated D: root behind: $($fixture.Root)"
}

$harnessText = [IO.File]::ReadAllText($harness)
$workflowText = [IO.File]::ReadAllText($workflow)
$authority = [regex]::Match(
    $harnessText,
    '(?s)function Get-AuthenticatedAntigravityLocalAuthorityPath\b.*?(?=\nfunction New-AuthenticatedAntigravityCleanupManifestDocument\b)'
).Value
$localFixture = [regex]::Match(
    $harnessText,
    '(?s)function Invoke-AuthenticatedAntigravityLocalAuthorityFixture\b.*?(?=\nfunction Invoke-AuthenticatedAntigravityHeldStateFixture\b)'
).Value

Assert-True (-not [string]::IsNullOrWhiteSpace($authority)) `
    'local authority lifecycle contract is present'
foreach ($required in @(
    "kind = 'antigravity-local-protected-authority'",
    "package_authority = 'local-protected'",
    "certification_scope = 'enforcement-only'",
    "profile_custody_mode = 'existing'",
    "hitl_status = 'unverified-unclaimed'",
    "local_repair_status = 'unverified-unclaimed'",
    'current_user_sid',
    'Assert-ProtectedPackageArtifactRoot',
    'Assert-DisposableNoReparseAncestors',
    'Assert-OfficialAntigravityClientIdentity',
    'Assert-NoPreexistingDefenseClawRuntime',
    'Assert-AuthenticatedAntigravitySourceCheckout',
    'no fabricated run/artifact/campaign identity'
)) {
    Assert-True ($authority.Contains($required, [StringComparison]::Ordinal)) `
        "local authority contract is missing: $required"
}
Assert-True ($authority -notmatch '(?i)credential|token|WCM|PasswordVault') `
    'local authority code does not read credentials, tokens, or WCM'
foreach ($required in @(
    '[switch]$ProtectedAntigravityLocal',
    '[string]$ExpectedAntigravityLocalAuthoritySHA256',
    "ValidateSet('run', 'authorize', 'prepare'",
    'authorize is restricted to the protected local Antigravity lane',
    "Operation -notin @('authorize', 'prepare', 'hold', 'resume', 'cleanup')",
    'protected local Antigravity lifecycle rejects fabricated GitHub run/artifact identities',
    'local Antigravity authorization StateRoot',
    'protected local Antigravity lifecycle requires an existing authenticated authority manifest',
    'Invoke-AuthenticatedAntigravityLocalAuthorize',
    'Import-AuthenticatedAntigravityLocalAuthority',
    'authority manifest hash does not match the explicit lifecycle input',
    "'remote', 'get-url', 'origin'",
    '--untracked-files=all',
    'local_authority_manifest_sha256',
    'local_campaign_id'
)) {
    Assert-True ($harnessText.Contains($required, [StringComparison]::Ordinal)) `
        "protected local entry point is missing: $required"
}
foreach ($required in @(
    'current-user SID', 'package digest', 'HITL status',
    'local authority manifest hash mismatch',
    'local authority extra schema field', 'local authority foreign ACL entry',
    'dynamic fixture: PASS'
)) {
    Assert-True ($localFixture.Contains($required, [StringComparison]::Ordinal)) `
        "local authority fixture contract is missing: $required"
}
Assert-True ($workflowText -notmatch `
    'ProtectedAntigravityLocal|LocalAuthorityFixture|antigravity-local-protected-authority') `
    'existing Actions workflow remains independent of local authority mode'
Assert-True ($workflowText -match `
    'runs-on: \[self-hosted, Windows, X64, antigravity-authenticated\]') `
    'existing optional authenticated Actions lane remains present'

Write-Output 'authenticated Antigravity local-authority focused tests: PASS'
