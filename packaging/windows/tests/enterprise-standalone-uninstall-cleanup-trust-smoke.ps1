# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

#Requires -Version 5.1

# A hash-pinned standalone deployment (the unsigned standalone Setup) admits
# its installed payload by the SHA-256 pins its protected deployment metadata
# recorded. "defenseclaw.exe enterprise windows uninstall" passes the running,
# unsigned installed CLI as the native exact-scope cleanup executable. A
# production uninstall authenticates that metadata only under the lifecycle
# lock, so the executable is admitted there, after the recorded pins are
# loaded, and never by Authenticode alone at entry (GAP-0023). The trusted
# source-path check is stubbed (the exact-ACL smokes own it); the signature
# check is real, so the scratch "defenseclaw.exe" is NotSigned.

[CmdletBinding()]
param()

Microsoft.PowerShell.Core\Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modulePath = [IO.Path]::GetFullPath((
    Microsoft.PowerShell.Management\Join-Path `
        $PSScriptRoot '..\DefenseClawEnterprise.psm1'
))
$module = Microsoft.PowerShell.Core\Import-Module `
    -Name $modulePath -Force -PassThru -DisableNameChecking -ErrorAction Stop `
    -WarningAction SilentlyContinue

$root = [IO.Path]::Combine(
    [IO.Path]::GetTempPath(),
    'dc-uninstall-cleanup-trust-' + [Guid]::NewGuid().ToString('N')
)
[void][IO.Directory]::CreateDirectory($root)
$cli = [IO.Path]::Combine($root, 'defenseclaw.exe')
[IO.File]::WriteAllBytes($cli, [Text.Encoding]::ASCII.GetBytes('unsigned test CLI ' + [Guid]::NewGuid()))
# Hashed in .NET: Windows PowerShell 5.1 does not resolve the module-qualified
# Get-FileHash here.
$sha256 = [Security.Cryptography.SHA256]::Create()
try {
    $cliHash = ([BitConverter]::ToString($sha256.ComputeHash([IO.File]::ReadAllBytes($cli)))).Replace('-', '').ToLowerInvariant()
}
finally {
    $sha256.Dispose()
}
$otherHash = ('0' * 64)

$cases = @(
    @{ name = 'trusted hash-pinned metadata admits the installed CLI'; profile = 'Standalone'; trust = 'hash_pinned'; hash = $cliHash; trusted = $true; expect = 'admit' }
    @{ name = 'untrusted metadata loads no pins'; profile = 'Standalone'; trust = 'hash_pinned'; hash = $cliHash; trusted = $false; expect = 'refuse' }
    @{ name = 'absent metadata loads no pins'; profile = 'Standalone'; trust = ''; hash = ''; trusted = $true; expect = 'refuse' }
    @{ name = 'authenticode metadata loads no pins'; profile = 'Standalone'; trust = 'authenticode'; hash = $cliHash; trusted = $true; expect = 'refuse' }
    @{ name = 'a recorded pin for other bytes'; profile = 'Standalone'; trust = 'hash_pinned'; hash = $otherHash; trusted = $true; expect = 'refuse' }
    # Secure Client admits the executable at entry, as on main (Secure Client is
    # out of scope for GAP-0023), so the deferred admission adds nothing there.
    @{ name = 'Secure Client is not admitted under the lock'; profile = 'SecureClient'; trust = 'hash_pinned'; hash = $cliHash; trusted = $true; expect = 'no native_cleanup source' }
    @{ name = 'entry admission by Authenticode alone refuses (why it is deferred)'; profile = 'Standalone'; trust = 'entry'; hash = ''; trusted = $true; expect = 'refuse' }
)

$failures = [Collections.Generic.List[string]]::new()
try {
    foreach ($case in $cases) {
        $observed = & $module {
            param($Case, $Root, $CLI)
            $script:DefenseClawEnterpriseProfile = [string]$Case['profile']
            if ($script:DefenseClawEnterpriseProfile -ceq 'Standalone') {
                Initialize-DefenseClawStandalonePayloadTrust -TrustMode Authenticode
            }
            function script:Assert-DefenseClawTrustedSource {
                param([string]$Path, [string]$Label)
                return $Path
            }
            $layout = @{ CLIPath = $CLI }
            $metadata = $null
            if ([string]$Case['trust'] -cnotin @('', 'entry')) {
                $metadata = [pscustomobject]@{
                    trust_mode = [string]$Case['trust']
                    hashes = [pscustomobject]@{ cli = [string]$Case['hash'] }
                }
            }
            $sources = @{}
            try {
                if ([string]$Case['trust'] -ceq 'entry') {
                    $sources = Get-DefenseClawLifecycleSources -Action Uninstall -NativeCleanupBinary $CLI
                }
                else {
                    Add-DefenseClawProductionUninstallNativeCleanupSource `
                        -Sources $sources `
                        -Layout $layout `
                        -Metadata $metadata `
                        -MetadataTrusted:([bool]$Case['trusted']) `
                        -NativeCleanupBinary $CLI
                }
            }
            catch {
                return 'refuse: ' + $_.Exception.Message
            }
            finally {
                Microsoft.PowerShell.Management\Remove-Item -LiteralPath Function:\Assert-DefenseClawTrustedSource -ErrorAction SilentlyContinue
                $script:DefenseClawEnterpriseProfile = 'SecureClient'
            }
            if (-not $sources.ContainsKey('native_cleanup') -or
                -not [string]::Equals([string]$sources['native_cleanup'].path, $CLI, [StringComparison]::OrdinalIgnoreCase)) {
                return 'no native_cleanup source'
            }
            return 'admit'
        } $case $root $cli
        $verdict = ([string]$observed -split ':', 2)[0]
        if ($verdict -cne [string]$case['expect']) {
            $failures.Add("$($case['name']): want $($case['expect']), got '$observed'")
        }
        elseif ($verdict -ceq 'refuse' -and [string]$observed -notmatch 'native exact-scope cleanup executable') {
            $failures.Add("$($case['name']): refused for another reason: '$observed'")
        }
    }
}
finally {
    Microsoft.PowerShell.Management\Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
    Microsoft.PowerShell.Core\Remove-Module -ModuleInfo $module -Force -ErrorAction SilentlyContinue
}
if ($failures.Count -gt 0) {
    throw ("enterprise-standalone-uninstall-cleanup-trust-smoke: FAIL`n" + ($failures -join "`n"))
}
Microsoft.PowerShell.Utility\Write-Output "enterprise-standalone-uninstall-cleanup-trust-smoke: OK ($($cases.Count) cases)"
