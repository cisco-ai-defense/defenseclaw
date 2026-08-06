#Requires -Version 7.4
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function Assert-Rejects([scriptblock]$Action, [string]$Message) {
    try {
        & $Action
    } catch {
        return
    }
    throw "expected rejection: $Message"
}

function Copy-Document([object]$Document) {
    return ($Document | ConvertTo-Json -Depth 12) |
        ConvertFrom-Json -ErrorAction Stop
}

$workspace = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$authorizerPath = Join-Path $PSScriptRoot 'run-copilot-local.ps1'
$innerPath = Join-Path $PSScriptRoot 'run-windows.ps1'
$fixtureRoot = Join-Path 'D:\' ("dc-copilot-local-unit-$PID")
$baselineRoot = Join-Path $fixtureRoot 'baseline'
$filesRoot = Join-Path $baselineRoot 'files'
$liveRoot = Join-Path $fixtureRoot 'live'
$stateRoot = Join-Path $fixtureRoot 'state'
$packageRoot = Join-Path $fixtureRoot 'package'
$setupPath = Join-Path $packageRoot 'DefenseClawSetup-x64.exe'
$agentPath = Join-Path $stateRoot 'tools\node_modules\.bin\copilot.cmd'
$resultsPath = Join-Path $stateRoot 'results.jsonl'
$artifactPath = Join-Path $stateRoot 'artifacts'
$manifestPath = Join-Path $baselineRoot 'manifest.json'
$transactionPath = Join-Path $baselineRoot 'transaction.json'
$sourceCommit = '337232942b3e054cd0650124da965d9ae5426f00'
$harnessCommit = '1111111111111111111111111111111111111111'
$artifactDigest = 'sha256:' + ('2' * 64)
$authorizerHash = (Get-FileHash -LiteralPath $authorizerPath `
    -Algorithm SHA256).Hash.ToLowerInvariant()

try {
    foreach ($path in @($filesRoot, $liveRoot, (Split-Path -Parent $agentPath),
        $packageRoot, $artifactPath)) {
        [IO.Directory]::CreateDirectory($path) | Out-Null
    }
    [IO.File]::WriteAllText($setupPath, 'synthetic setup')
    [IO.File]::WriteAllText($agentPath, 'synthetic agent')
    $syntheticSetupHash = (Get-FileHash -LiteralPath $setupPath `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    [IO.File]::WriteAllText("$setupPath.provenance.json", ([ordered]@{
        schema_version = 1
        artifact = 'DefenseClawSetup-x64.exe'
        artifact_sha256 = $syntheticSetupHash
        source_commit = $sourceCommit
        distribution_flavor = 'oss'
    } | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
    $syntheticProvenanceHash = (Get-FileHash `
        -LiteralPath "$setupPath.provenance.json" -Algorithm SHA256).Hash.ToLowerInvariant()

    . $authorizerPath -Operation run -WorkspaceRoot $workspace `
        -StateRoot $stateRoot -ResultsPath $resultsPath `
        -ArtifactPath $artifactPath -PackagedSetupPath $setupPath `
        -ExpectedPackagedSetupSHA256 $syntheticSetupHash `
        -ExpectedPackagedSetupProvenanceSHA256 $syntheticProvenanceHash `
        -ExpectedPackageSourceCommit $sourceCommit `
        -ExpectedHarnessSourceCommit $harnessCommit `
        -ExpectedPackageRunID '30860124789' `
        -ExpectedPackageArtifactID '8874215347' `
        -ExpectedPackageArtifactDigest $artifactDigest `
        -ExpectedWorkflowRepository 'cisco-ai-defense/defenseclaw' `
        -AgentPath $agentPath -ExpectedAgentVersion '1.0.77' `
        -BaselineManifestPath $manifestPath `
        -ExpectedBaselineManifestSHA256 ('0' * 64) `
        -ExpectedLocalProtectedCopilotAuthorizerSHA256 $authorizerHash -NoRun

    $fingerprints = [ordered]@{}
    $copies = [ordered]@{}
    foreach ($name in $script:LocalExpectedFingerprintNames) {
        if ($name -ceq 'codex_hooks') {
            $fingerprints[$name] = [ordered]@{
                path = Join-Path $liveRoot "$name.bin"; exists = $false
            }
            $copies[$name] = [ordered]@{ exists = $false }
            continue
        }
        $bytes = [Text.Encoding]::UTF8.GetBytes("copy-$name")
        $copyPath = Join-Path $filesRoot "$name.bin"
        [IO.File]::WriteAllBytes($copyPath, $bytes)
        $hash = (Get-FileHash -LiteralPath $copyPath `
            -Algorithm SHA256).Hash.ToLowerInvariant()
        $fingerprints[$name] = [ordered]@{
            path = Join-Path $liveRoot "$name.bin"
            exists = $true
            length = [long]$bytes.Length
            attributes = 32
            sha256 = $hash
            owner = 'fixture-user'
            sddl = 'O:SYG:SYD:P(A;;FA;;;SY)'
        }
        $copies[$name] = [ordered]@{
            exists = $true
            path = $copyPath
            length = [long]$bytes.Length
            sha256 = $hash
        }
    }
    # Give the custody-mapping helper the same canonical path shape as the
    # authenticated manifest while keeping every dynamic test D:-local.
    $fingerprints.install_state.path = Join-Path $liveRoot `
        'Programs\DefenseClaw\installer\install-state.json'
    $fingerprints.config.path = Join-Path $liveRoot '.defenseclaw\config.yaml'
    $fingerprints.maintenance_setup.path = Join-Path $liveRoot `
        'LocalAppData\DefenseClaw\InstallerCache\DefenseClawSetup-x64.exe'
    $fingerprints.copilot_hook.path = Join-Path $liveRoot `
        '.copilot\hooks\defenseclaw.json'

    $manifest = [ordered]@{
        schema_version = 1
        kind = 'copilot-four-connector-sealed-current'
        package_source_commit = $sourceCommit
        hitl_claimed = $false
        roster = @($script:LocalExpectedRoster)
        opencode_active = $false
        doctor = [ordered]@{ pass = 70; fail = 0; warn = 3; skip = 13 }
        processes = @(
            [ordered]@{ name = 'defenseclaw-gateway.exe'; pid = 1 },
            [ordered]@{ name = 'defenseclaw-gateway.exe'; pid = 2 }
        )
        fingerprints = $fingerprints
        copies = $copies
    }
    [IO.File]::WriteAllText($manifestPath,
        ($manifest | ConvertTo-Json -Depth 12), [Text.UTF8Encoding]::new($false))
    $manifestHash = (Get-FileHash -LiteralPath $manifestPath `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    $manifest = Read-LocalJson $manifestPath 'synthetic sealed baseline manifest'

    $null = Assert-LocalBaselineManifestDocument $manifest $manifestPath `
        $manifestHash -VerifyCopies
    Write-Output 'valid sealed baseline manifest and protected copies: PASS'

    Assert-Rejects {
        $null = Assert-LocalBaselineManifestDocument $manifest $manifestPath `
            ('f' * 64) -VerifyCopies
    } 'wrong baseline manifest SHA-256'
    $missing = Copy-Document $manifest
    $missing.PSObject.Properties.Remove('doctor')
    Assert-Rejects {
        $null = Assert-LocalBaselineManifestDocument $missing $manifestPath `
            $manifestHash
    } 'missing required baseline field'
    $escaped = Copy-Document $manifest
    $escaped.copies.config.path = 'D:\outside-baseline.bin'
    Assert-Rejects {
        $null = Assert-LocalBaselineManifestDocument $escaped $manifestPath `
            $manifestHash
    } 'baseline copy path escape'
    $driftPath = [string]$manifest.copies.config.path
    $originalDriftBytes = [IO.File]::ReadAllBytes($driftPath)
    try {
        [IO.File]::WriteAllText($driftPath, 'drift')
        Assert-Rejects {
            $null = Assert-LocalBaselineManifestDocument $manifest $manifestPath `
                $manifestHash -VerifyCopies
        } 'baseline copy byte drift'
    } finally {
        [IO.File]::WriteAllBytes($driftPath, $originalDriftBytes)
    }
    Write-Output 'baseline manifest fail-closed negatives: PASS'

    $derivedLivePath = Join-Path $liveRoot 'derived-active.json'
    $derivedCopyPath = Join-Path $filesRoot 'derived-active.bin'
    [IO.File]::WriteAllText($derivedLivePath, 'sealed-derived')
    [IO.File]::WriteAllText($derivedCopyPath, 'sealed-derived')
    $derivedActual = Get-LocalFileFingerprint $derivedLivePath
    $derivedExpected = [pscustomobject]@{
        path = $derivedActual.Path; exists = $true; length = $derivedActual.Length
        attributes = $derivedActual.Attributes; sha256 = $derivedActual.SHA256
        owner = $derivedActual.Owner; sddl = $derivedActual.SDDL
    }
    $derivedBaseline = [pscustomobject]@{
        fingerprints = [pscustomobject]@{ active_connector = $derivedExpected }
        copies = [pscustomobject]@{ active_connector = [pscustomobject]@{
            exists = $true; path = $derivedCopyPath; length = $derivedActual.Length
            sha256 = $derivedActual.SHA256
        } }
    }
    [IO.File]::WriteAllText($derivedLivePath, 'runtime-regenerated')
    Restore-LocalDerivedFingerprint $derivedBaseline 'active_connector'
    Assert-LocalFileFingerprint $derivedExpected 'focused derived recovery'
    Write-Output 'runtime-derived sealed byte/security recovery: PASS'

    $mappingSource = Join-Path $fixtureRoot 'mapping-source'
    $mappingDestination = Join-Path $fixtureRoot 'mapping-destination'
    [IO.Directory]::CreateDirectory($mappingSource) | Out-Null
    $validMapping = @([pscustomobject]@{
        Name = 'fixture'; Source = $mappingSource; Destination = $mappingDestination
    })
    Assert-LocalCustodyMappings $validMapping
    $crossVolume = @([pscustomobject]@{
        Name = 'fixture'; Source = $mappingSource
        Destination = 'C:\dc-copilot-local-cross-volume-fixture'
    })
    Assert-Rejects { Assert-LocalCustodyMappings $crossVolume } `
        'cross-volume custody mapping'
    [IO.Directory]::CreateDirectory($mappingDestination) | Out-Null
    Assert-Rejects { Assert-LocalCustodyMappings $validMapping } `
        'occupied custody destination'
    Assert-Rejects {
        Assert-LocalProtectedRootsOutsideCustody @($mappingSource) $validMapping
    } 'protected root overlap with live custody'
    $junctionTarget = Join-Path $fixtureRoot 'junction-target'
    $junctionPath = Join-Path $fixtureRoot 'junction-path'
    [IO.Directory]::CreateDirectory($junctionTarget) | Out-Null
    New-Item -ItemType Junction -Path $junctionPath -Target $junctionTarget | Out-Null
    try {
        Assert-Rejects {
            Assert-LocalPlainPath $junctionPath 'D:\' -Directory
        } 'D:-spelled junction traversal'
        $junctionAliasMapping = @([pscustomobject]@{
            Name = 'junction-alias-fixture'; Source = $junctionTarget
            Destination = Join-Path $fixtureRoot 'junction-alias-destination'
        })
        Assert-Rejects {
            Assert-LocalProtectedRootsOutsideCustody @($junctionPath) `
                $junctionAliasMapping
        } 'handle-resolved directory alias overlap with live custody'
    } finally {
        [IO.Directory]::Delete($junctionPath, $false)
    }
    $aliasLongRoot = Join-Path $fixtureRoot 'alias overlap protected root'
    [IO.Directory]::CreateDirectory($aliasLongRoot) | Out-Null
    $aliasPath = Get-LocalShortPathAlias $aliasLongRoot
    if ([string]::Equals($aliasPath, $aliasLongRoot,
            [StringComparison]::OrdinalIgnoreCase) -and
        (Test-Path -LiteralPath $env:ProgramFiles -PathType Container)) {
        $systemAlias = Get-LocalShortPathAlias $env:ProgramFiles
        if (-not [string]::Equals($systemAlias, $env:ProgramFiles,
                [StringComparison]::OrdinalIgnoreCase)) {
            $aliasLongRoot = [IO.Path]::GetFullPath($env:ProgramFiles)
            $aliasPath = $systemAlias
        }
    }
    $aliasCoverage = 'handle-resolved-alias-overlap-rejected'
    if (-not [string]::Equals($aliasPath, $aliasLongRoot,
            [StringComparison]::OrdinalIgnoreCase)) {
        $aliasMapping = @([pscustomobject]@{
            Name = 'alias-fixture'; Source = $aliasLongRoot
            Destination = Join-Path $fixtureRoot 'alias-overlap-destination'
        })
        Assert-Rejects {
            Assert-LocalProtectedRootsOutsideCustody @($aliasPath) $aliasMapping
        } 'DOS short-name alias overlap with live custody'
        $aliasCoverage = 'dos-short-name-overlap-rejected'
    } else {
        Assert-True ((Get-LocalCanonicalPath $aliasPath) -ceq
            (Get-LocalCanonicalPath $aliasLongRoot)) `
            'canonical path resolution changed an alias-disabled directory identity'
    }
    Write-Output "custody mapping fail-closed negatives ($aliasCoverage): PASS"

    $script:CopilotClientSHA256 = '3' * 64
    $script:WindowsLiveHarnessPath = $innerPath
    $script:CopilotHarnessSHA256 = (Get-FileHash -LiteralPath $innerPath `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    $script:ExpectedBaselineManifestSHA256 = $manifestHash
    $script:LocalPackageProvenance = Assert-LocalPackageProvenance $setupPath
    $mappings = @(Get-LocalCustodyMappings $manifest $manifestHash)
    New-LocalCapability
    Assert-True (-not (Test-Path Env:DC_COPILOT_LOCAL_CAPABILITY)) `
        'run capability escaped script scope before the inner launch'
    $script:LocalRestoreCapabilityRecord = New-LocalRestoreCapabilityFile `
        $baselineRoot 'focused-transaction'
    $transaction = Copy-Document `
        (New-LocalTransactionDocument $manifest $mappings $transactionPath)
    Assert-LocalTransactionDocument $transaction $transactionPath $manifest
    $script:LocalTransactionPath = $transactionPath
    Use-LocalRestoreCapability $transaction
    Assert-True ($script:LocalCapabilitySHA256 -ceq
        [string]$transaction.restore_capability_sha256) `
        'DPAPI restore capability did not round-trip under the current SID'
    Assert-True (-not (Test-Path Env:DC_COPILOT_LOCAL_CAPABILITY)) `
        'restore capability escaped script scope before the inner launch'
    $ciphertextDrift = Copy-Document $transaction
    $ciphertextDrift.restore_capability_ciphertext_sha256 = '5' * 64
    Assert-Rejects {
        Assert-LocalTransactionDocument $ciphertextDrift $transactionPath $manifest
    } 'restore capability ciphertext drift'
    $awaiting = Copy-Document $transaction
    $awaiting.inner_capability_sha256 = [string]$awaiting.restore_capability_sha256
    $awaiting.deferred_cleanup_transaction_id = '6' * 32
    $awaiting.uninstall_boot_identifier = '77777777-7777-7777-7777-777777777777'
    $awaiting.deferred_cleanup_run_command_sha256 = '8' * 64
    $awaiting.phase = 'awaiting-reboot'
    Assert-LocalTransactionDocument $awaiting $transactionPath $manifest
    $missingCleanupAuthority = Copy-Document $awaiting
    $missingCleanupAuthority.deferred_cleanup_transaction_id = ''
    Assert-Rejects {
        Assert-LocalTransactionDocument $missingCleanupAuthority $transactionPath $manifest
    } 'awaiting-reboot transaction without exact Setup cleanup authority'
    $wrongTransaction = Copy-Document $transaction
    $wrongTransaction.authorizer_sha256 = '4' * 64
    Assert-Rejects {
        Assert-LocalTransactionDocument $wrongTransaction $transactionPath $manifest
    } 'wrong transaction authorizer binding'
    $expandedTransaction = Copy-Document $transaction
    $expandedTransaction.custody = @($expandedTransaction.custody) +
        [pscustomobject]@{ name = 'extra'; source = 'D:\extra'; destination = 'D:\extra2'; moved = $false }
    Assert-Rejects {
        Assert-LocalTransactionDocument $expandedTransaction $transactionPath $manifest
    } 'expanded transaction custody inventory'
    $currentBoot = Get-LocalWindowsBootIdentifier
    $currentBootAgain = Get-LocalWindowsBootIdentifier
    $knownComposite = New-LocalWindowsBootIdentifier `
        '00112233-4455-6677-8899-aabbccddeeff' 0x11223344
    Assert-True ($knownComposite -ceq '124a2a11-3686-92c6-3006-2e91636ef5fa') `
        'PowerShell boot identity differs from exact Setup composition'
    Assert-True ($currentBoot -ceq $currentBootAgain -and
        $currentBoot -cmatch
            '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') `
        'Setup-compatible Windows boot identity is invalid or unstable'
    Assert-Rejects {
        Assert-LocalBootTransition $currentBoot $currentBoot
    } 'same-boot or hibernate-resume restoration'
    Assert-LocalBootTransition $currentBoot '00000000-0000-0000-0000-000000000000'
    Write-Output 'transaction identity/custody authentication negatives: PASS'

    $innerText = [IO.File]::ReadAllText($innerPath)
    $authorizerText = [IO.File]::ReadAllText($authorizerPath)
    [Environment]::SetEnvironmentVariable('GH_TOKEN', 'synthetic ambient value')
    [Environment]::SetEnvironmentVariable('GITHUB_TOKEN', 'synthetic ambient value')
    [Environment]::SetEnvironmentVariable('COPILOT_GITHUB_TOKEN', 'synthetic ambient value')
    $clearOutput = @(Clear-LocalAmbientCredentials)
    Assert-True ($clearOutput.Count -eq 0 -and
        -not (Test-Path Env:GH_TOKEN) -and
        -not (Test-Path Env:GITHUB_TOKEN) -and
        -not (Test-Path Env:COPILOT_GITHUB_TOKEN)) `
        'ambient GitHub token variables were read, emitted, or retained'
    $invokeStart = $authorizerText.IndexOf(
        'function Invoke-LocalProtectedCopilot', [StringComparison]::Ordinal)
    $invokeBody = $authorizerText.Substring($invokeStart)
    Assert-True ($invokeStart -ge 0 -and
        $invokeBody.IndexOf('Clear-LocalAmbientCredentials', [StringComparison]::Ordinal) -lt
            $invokeBody.IndexOf('Assert-ProtectedCopilotSourceCheckout', [StringComparison]::Ordinal)) `
        'ambient credential removal does not precede source/package native processes'
    Assert-True ($innerText.Contains('[switch]$LocalProtectedCopilotRunner') -and
        $innerText.Contains('$script:WindowsLiveHarnessPath = [IO.Path]::GetFullPath($PSCommandPath)') -and
        $innerText.Contains('$script:CopilotAuthorizationMode = ''local-powershell''') -and
        $innerText.Contains('Remove-Item Env:DC_COPILOT_LOCAL_CAPABILITY') -and
        $innerText.Contains('Assert-ProtectedCopilotDeferredCleanupPending') -and
        $innerText.Contains("'/cleanup', '/quiet'") -and
        $innerText.Contains("@(3010) 'same-boot-cleanup-gate'") -and
        $innerText.Contains("'ls-files', '--error-unmatch'") -and
        $innerText.Contains('"--path=$authorizerRelativePath"')) `
        'inner harness does not bind the local authorizer and exact harness identity'
    Assert-True ($authorizerText.Contains("@('stop')") -and
        $authorizerText.IndexOf('Wait-LocalProcessAbsence', [StringComparison]::Ordinal) -lt
            $authorizerText.LastIndexOf('Move-Item -LiteralPath $mappings', [StringComparison]::Ordinal) -and
        $authorizerText.Contains('Assert-LocalAuditExclusive') -and
        $authorizerText.Contains('Invoke-LocalInnerHarness run') -and
        $authorizerText.Contains('Get-LocalWindowsBootIdentifier') -and
        $authorizerText.Contains('Assert-LocalDeferredCleanupCompleted') -and
        $authorizerText.Contains('COPILOT_PHASE1_COMPLETE_AWAITING_AUTHORIZED_WINDOWS_RESTART')) `
        'local authorizer does not keep quiesce, custody, and harness launch in one invocation'
    Assert-True ($authorizerText.Contains("'-LocalProtectedCopilotTransactionPath'") -and
        $authorizerText.Contains("'-ExpectedLocalProtectedCopilotTransactionSHA256'") -and
        $authorizerText.Contains("'-ExpectedLocalProtectedCopilotCapabilitySHA256'") -and
        $authorizerText.Contains("'-PreserveProtectedCopilotRunInputs'")) `
        'inner/outer transaction, capability, or authenticated cleanup binding is incomplete'
    Assert-True (-not $authorizerText.Contains('GITHUB_ACTIONS') -and
        -not $authorizerText.Contains('DC_COPILOT_DEDICATED_RUNNER') -and
        -not $authorizerText.Contains('Get-Credential') -and
        -not $authorizerText.Contains('hitl_claimed = $true')) `
        'local authorizer depends on hosted runner state, credential input, or an HITL claim'
    Write-Output 'runner-independent parser and custody source contract: PASS'
} finally {
    Clear-LocalCapability
    if (Test-Path -LiteralPath $fixtureRoot) {
        $resolved = [IO.Path]::GetFullPath($fixtureRoot)
        if ([IO.Path]::GetPathRoot($resolved) -cne 'D:\' -or
            [IO.Path]::GetFileName($resolved) -cnotmatch '^dc-copilot-local-unit-[0-9]+$') {
            throw 'refusing to remove an unexpected focused-test fixture root'
        }
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
