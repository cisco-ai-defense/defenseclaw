# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

<#
.SYNOPSIS
    Exercises the public Windows bootstrap against one exact sealed candidate.

.DESCRIPTION
    Native Setup derives its per-user layout from token-bound Windows Known
    Folders. Environment-variable profile spoofing is intentionally unsupported.
    The parent mode therefore delegates to the repository's disposable
    standard-user launcher. Child mode runs with a real isolated profile and
    HKCU hive, installs through the exact sealed install.ps1 release asset,
    repeats the authenticated handoff, verifies the installed version, and
    proves immediate uninstall plus the exact authenticated cleanup state that
    must remain until Windows restarts.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ReleaseDir,
    [Parameter(Mandatory = $true)][string]$TargetVersion,
    [Parameter(Mandatory = $true)]
    [ValidateSet("immediate", "deferred")]
    [string]$UninstallContract,
    [Parameter(DontShow = $true)][switch]$Child,
    [Parameter(DontShow = $true)][string]$StateRoot = "",
    [Parameter(DontShow = $true)][string]$DiagnosticsRoot = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ($TargetVersion -notmatch '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$') {
    throw "TargetVersion must be canonical X.Y.Z"
}

function Resolve-RegularReleaseDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)

    $full = [IO.Path]::GetFullPath($Path)
    $item = [IO.DirectoryInfo]::new($full)
    $item.Refresh()
    if (-not $item.Exists -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "Bootstrap acceptance release input must be a regular directory: $full"
    }
    return $full
}

function Assert-RegularReleaseFile {
    param([Parameter(Mandatory = $true)][string]$Path)

    $full = [IO.Path]::GetFullPath($Path)
    $item = [IO.FileInfo]::new($full)
    $item.Refresh()
    if (-not $item.Exists -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "Bootstrap acceptance release input must be a regular file: $full"
    }
}

$ReleaseDir = Resolve-RegularReleaseDirectory -Path $ReleaseDir
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

function Invoke-CapturedProcess {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$ArgumentList
    )

    $previousErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        $output = (& $FilePath @ArgumentList 2>&1 | Out-String -Width 32768)
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    return [pscustomobject]@{
        ExitCode = [int]$exitCode
        Output = [string]$output
    }
}

function Assert-ExactVersion {
    param(
        [Parameter(Mandatory = $true)][string]$Executable,
        [Parameter(Mandatory = $true)][string]$ExpectedVersion
    )

    $probe = Invoke-CapturedProcess -FilePath $Executable -ArgumentList @("--version")
    if ($probe.ExitCode -ne 0) {
        throw "Version probe failed for ${Executable}:`n$($probe.Output)"
    }
    $versions = @(
        [regex]::Matches(
            $probe.Output,
            '(?<![0-9.])([0-9]+\.[0-9]+\.[0-9]+)(?![0-9.])'
        ) | ForEach-Object { $_.Groups[1].Value }
    )
    if ($versions.Count -ne 1 -or $versions[0] -cne $ExpectedVersion) {
        throw "${Executable} did not report exact version ${ExpectedVersion}: $($probe.Output)"
    }
}

function Assert-BootstrapSucceeded {
    param(
        [Parameter(Mandatory = $true)][object]$Result,
        [Parameter(Mandatory = $true)][string]$ExpectedVersion,
        [Parameter(Mandatory = $true)][string]$Phase
    )

    foreach ($expected in @(
        "Release checksum signature verified (Sigstore)",
        "Authenticated DefenseClawSetup-x64.exe for DefenseClaw $ExpectedVersion",
        "Starting authenticated native Setup",
        "Native DefenseClaw Setup completed successfully"
    )) {
        if ($Result.Output -notmatch [regex]::Escape($expected)) {
            throw "${Phase} did not report '$expected':`n$($Result.Output)"
        }
    }
    if ($Result.Output -notmatch (
            "Setup Authenticode signature verified" +
            "|Setup is explicitly unverified by Authenticode"
        )) {
        throw "${Phase} did not report an explicit Setup signing state:`n$($Result.Output)"
    }
    if ($Result.ExitCode -ne 0) {
        throw "${Phase} failed ($($Result.ExitCode)):`n$($Result.Output)"
    }
}

function Get-UserPathEntryCount {
    param(
        [AllowNull()][string]$Value,
        [Parameter(Mandatory = $true)][string]$ExpectedEntry
    )

    if ([string]::IsNullOrWhiteSpace($Value)) { return 0 }
    return @(
        $Value.Split(
            [char[]]@(";"),
            [StringSplitOptions]::RemoveEmptyEntries
        ) | Where-Object {
            ([IO.Path]::GetFullPath($_.Trim())).TrimEnd('\').Equals(
                ([IO.Path]::GetFullPath($ExpectedEntry)).TrimEnd('\'),
                [StringComparison]::OrdinalIgnoreCase
            )
        }
    ).Count
}

function Assert-NoReparsePathChain {
    param([Parameter(Mandatory = $true)][string]$Path)

    $current = [IO.Path]::GetFullPath($Path)
    while ($true) {
        try {
            $attributes = [IO.File]::GetAttributes($current)
            if ($attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw "Deferred uninstall authority crosses a reparse point: $current"
            }
        } catch [IO.FileNotFoundException] {
            # Missing transaction artifacts are expected after convergence.
        } catch [IO.DirectoryNotFoundException] {
            # Continue with the first existing ancestor.
        }
        $parent = [IO.Directory]::GetParent($current)
        if ($null -eq $parent) {
            break
        }
        $current = $parent.FullName
    }
}

function Assert-CanonicalPathBinding {
    param(
        [Parameter(Mandatory = $true)][string]$Actual,
        [Parameter(Mandatory = $true)][string]$Expected,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if (-not [IO.Path]::IsPathFullyQualified($Actual)) {
        throw "$Label is not an absolute filesystem path"
    }
    $normalizedActual = [IO.Path]::GetFullPath($Actual)
    $normalizedExpected = [IO.Path]::GetFullPath($Expected)
    if (-not $Actual.Equals($normalizedActual, [StringComparison]::OrdinalIgnoreCase) -or
        -not $normalizedActual.Equals(
            $normalizedExpected,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw "$Label is not bound to the exact canonical path"
    }
}

function Assert-PrivatePathCustody {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [switch]$Directory
    )

    Assert-NoReparsePathChain -Path $Path
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ([bool]$item.PSIsContainer -ne [bool]$Directory -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "Deferred uninstall authority is not the required regular path: $Path"
    }

    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    $owner = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $actualOwner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if (-not $acl.AreAccessRulesProtected -or $actualOwner -cne $owner) {
        throw "Deferred uninstall authority is not owner-controlled with a protected DACL: $Path"
    }
    $systemSid = "S-1-5-18"
    $creatorOwnerSid = "S-1-3-0"
    $ownerRightsSid = "S-1-3-4"
    $foundOwner = $false
    $foundSystem = $false
    foreach ($rule in $acl.GetAccessRules(
            $true,
            $true,
            [Security.Principal.SecurityIdentifier]
        )) {
        $sid = $rule.IdentityReference.Value
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) {
            throw (
                "Deferred uninstall authority contains a non-allow ACE " +
                "($sid): $Path"
            )
        }
        if ([int64]$rule.FileSystemRights -eq 0) {
            continue
        }
        $inheritOnly = (
            $rule.PropagationFlags -band
            [Security.AccessControl.PropagationFlags]::InheritOnly
        ) -ne [Security.AccessControl.PropagationFlags]::None
        # CREATOR OWNER is only a template for inherited child ACEs and
        # provides no access to this directory. Permit that template without
        # treating it as the effective owner grant required below.
        if ($sid -ceq $creatorOwnerSid) {
            if (-not $Directory -or -not $inheritOnly) {
                throw "Deferred uninstall authority grants access to an unexpected SID ($sid): $Path"
            }
            continue
        }
        # OWNER RIGHTS is owner-relative, so it is safe only after the
        # concrete current-user owner and protected DACL checks above.
        if ($sid -ceq $owner -or $sid -ceq $ownerRightsSid) {
            if (-not $inheritOnly) {
                $foundOwner = $true
            }
            continue
        }
        if ($sid -ceq $systemSid) {
            if (-not $inheritOnly) {
                $foundSystem = $true
            }
            continue
        }
        throw "Deferred uninstall authority grants access to an unexpected SID ($sid): $Path"
    }
    if (-not $foundOwner -or -not $foundSystem) {
        throw "Deferred uninstall authority lacks required owner and SYSTEM access: $Path"
    }
}

function Assert-WindowsAMD64Executable {
    param([Parameter(Mandatory = $true)][string]$Path)

    $stream = [IO.File]::Open(
        $Path,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read
    )
    $reader = [IO.BinaryReader]::new($stream)
    try {
        if ($stream.Length -lt 70 -or $reader.ReadUInt16() -ne 0x5A4D) {
            throw "Deferred HookRuntime launcher is not a valid PE executable"
        }
        $stream.Position = 0x3C
        $peOffset = [int64]$reader.ReadUInt32()
        if ($peOffset -lt 64 -or $peOffset -gt ($stream.Length - 6)) {
            throw "Deferred HookRuntime launcher has an invalid PE header offset"
        }
        $stream.Position = $peOffset
        if ($reader.ReadUInt32() -ne 0x00004550 -or $reader.ReadUInt16() -ne 0x8664) {
            throw "Deferred HookRuntime launcher is not a Windows AMD64 executable"
        }
    } finally {
        $reader.Dispose()
        $stream.Dispose()
    }
}

function Wait-ForPathRemoval {
    param([Parameter(Mandatory = $true)][string]$Path)

    # Historical installers use a transaction-bound post-exit helper that may
    # wait up to two minutes for its parent to exit. The current deferred
    # cleanup contract returns 3010 and must never enter this compatibility
    # wait.
    for ($attempt = 0; $attempt -lt 520 -and (Test-Path -LiteralPath $Path); $attempt++) {
        Start-Sleep -Milliseconds 250
    }
}

function Get-OptionalJsonPropertyValue {
    param(
        [Parameter(Mandatory = $true)]$InputObject,
        [Parameter(Mandatory = $true)][string]$PropertyName
    )

    $property = $InputObject.PSObject.Properties[$PropertyName]
    if ($null -eq $property) {
        return
    }
    return $property.Value
}

function Get-OptionalJsonStringValue {
    param(
        [Parameter(Mandatory = $true)]$InputObject,
        [Parameter(Mandatory = $true)][string]$PropertyName
    )

    $value = Get-OptionalJsonPropertyValue `
        -InputObject $InputObject `
        -PropertyName $PropertyName
    if ($null -eq $value) {
        return ""
    }
    return [string]$value
}

function Get-OptionalJsonStringArrayValue {
    param(
        [Parameter(Mandatory = $true)]$InputObject,
        [Parameter(Mandatory = $true)][string]$PropertyName
    )

    $value = Get-OptionalJsonPropertyValue `
        -InputObject $InputObject `
        -PropertyName $PropertyName
    foreach ($item in @($value)) {
        if ($null -ne $item) {
            [string]$item
        }
    }
}

function Assert-ExactDeferredUninstallState {
    param(
        [Parameter(Mandatory = $true)][string]$LocalAppData,
        [Parameter(Mandatory = $true)][string]$CacheRoot,
        [Parameter(Mandatory = $true)][string]$ExpectedSetup,
        [Parameter(Mandatory = $true)][string]$ExpectedProvenance
    )

    $productRoot = Join-Path $LocalAppData "DefenseClaw"
    $hookRuntimeRoot = Join-Path $productRoot "HookRuntime"
    $installerStateRoot = Join-Path $productRoot "InstallerState"
    $cachedSetup = Join-Path $CacheRoot "DefenseClawSetup-x64.exe"
    $hookLauncher = Join-Path $hookRuntimeRoot "defenseclaw-hook.exe"
    $hookStatePath = Join-Path $hookRuntimeRoot "hook-runtime-state.json"
    $cleanupRecordPath = Join-Path $installerStateRoot "uninstall-cleanup.json"
    $transactionJournalPath = Join-Path $installerStateRoot "setup-transaction.json"
    $cacheAckPath = Join-Path $CacheRoot "uninstall-cleanup-ack.json"
    $installRoot = Join-Path $LocalAppData "Programs\DefenseClaw"
    $dataRoot = Join-Path (
        [Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)
    ) ".defenseclaw"
    $expectedHookPath = Join-Path $installRoot "bin\defenseclaw-hook.exe"

    foreach ($authorityRoot in @($hookRuntimeRoot, $CacheRoot, $installerStateRoot)) {
        Assert-PrivatePathCustody -Path $authorityRoot -Directory
    }
    foreach ($requiredResidue in @(
        $cachedSetup,
        $hookLauncher,
        $hookStatePath,
        $cleanupRecordPath,
        $transactionJournalPath
    )) {
        if (-not (Test-Path -LiteralPath $requiredResidue -PathType Leaf)) {
            throw "Same-boot uninstall did not retain authenticated cleanup authority: $requiredResidue"
        }
        Assert-PrivatePathCustody -Path $requiredResidue
    }

    $cleanupRecord = Get-Content -LiteralPath $cleanupRecordPath -Raw -Encoding UTF8 |
        ConvertFrom-Json
    $transactionJournal = Get-Content -LiteralPath $transactionJournalPath -Raw -Encoding UTF8 |
        ConvertFrom-Json
    $hookState = Get-Content -LiteralPath $hookStatePath -Raw -Encoding UTF8 |
        ConvertFrom-Json
    $provenance = Get-Content -LiteralPath $ExpectedProvenance -Raw -Encoding UTF8 |
        ConvertFrom-Json
    $releaseUnsigned = [bool]$provenance.unsigned
    $productExecutablesSigned = [bool]$provenance.inputs.product_executables_authenticode_signed
    if ($releaseUnsigned -eq $productExecutablesSigned) {
        throw "Release provenance has an inconsistent Windows signing posture"
    }

    $cleanupBootIdentifier = Get-OptionalJsonStringValue `
        -InputObject $cleanupRecord `
        -PropertyName "cleanup_boot_identifier"
    if ([int]$cleanupRecord.schema_version -ne 1) {
        throw "Same-boot uninstall retained an unsupported cleanup record schema"
    }
    if ([string]$cleanupRecord.status -cne "pending-reboot") {
        throw "Same-boot uninstall cleanup record is not pending reboot"
    }
    if ([string]$cleanupRecord.transaction_id -cnotmatch "^[0-9a-f]{32}$") {
        throw "Same-boot uninstall cleanup record has an invalid transaction identity"
    }
    if ($cleanupBootIdentifier -cne "") {
        throw "Same-boot uninstall cleanup record prematurely names a cleanup boot"
    }
    if ([string]$cleanupRecord.uninstall_boot_identifier -cnotmatch (
            "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-" +
            "[0-9a-f]{4}-[0-9a-f]{12}$"
        )) {
        throw "Same-boot uninstall cleanup record has an invalid uninstall boot identity"
    }
    $transactionID = [string]$cleanupRecord.transaction_id
    foreach ($pathBinding in @(
        @([string]$cleanupRecord.runtime_root, $hookRuntimeRoot, "cleanup runtime root"),
        @([string]$cleanupRecord.launcher_path, $hookLauncher, "cleanup launcher"),
        @([string]$cleanupRecord.state_path, $hookStatePath, "cleanup state"),
        @(
            [string]$cleanupRecord.retired_launcher_path,
            "$hookLauncher.retired.$transactionID",
            "retired cleanup launcher"
        ),
        @(
            [string]$cleanupRecord.retired_state_path,
            "$hookStatePath.retired.$transactionID",
            "retired cleanup state"
        ),
        @([string]$cleanupRecord.hook_path, $expectedHookPath, "cleanup hook target"),
        @([string]$cleanupRecord.maintenance_path, $cachedSetup, "cleanup maintenance executable"),
        @([string]$cleanupRecord.installer_state_root, $installerStateRoot, "installer-state root"),
        @([string]$cleanupRecord.journal_path, $transactionJournalPath, "cleanup journal"),
        @([string]$cleanupRecord.record_path, $cleanupRecordPath, "cleanup record"),
        @([string]$cleanupRecord.cache_ack_path, $cacheAckPath, "cleanup cache acknowledgement"),
        @([string]$hookState.runtime_root, $hookRuntimeRoot, "HookRuntime state root"),
        @([string]$hookState.launcher_path, $hookLauncher, "HookRuntime state launcher"),
        @([string]$hookState.hook_path, $expectedHookPath, "HookRuntime state hook target")
    )) {
        Assert-CanonicalPathBinding `
            -Actual ([string]$pathBinding[0]) `
            -Expected ([string]$pathBinding[1]) `
            -Label ([string]$pathBinding[2])
    }
    if ([string]$cleanupRecord.run_value_name -cne "DefenseClawDeferredUninstallCleanup") {
        throw "Same-boot uninstall cleanup record does not bind the canonical cached Setup authority"
    }
    $expectedSetupDigest = (Get-FileHash -LiteralPath $ExpectedSetup -Algorithm SHA256).Hash.ToLowerInvariant()
    $cachedSetupDigest = (Get-FileHash -LiteralPath $cachedSetup -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($cachedSetupDigest -cne $expectedSetupDigest -or
        [string]$cleanupRecord.maintenance_sha256 -cne $cachedSetupDigest) {
        throw "Same-boot uninstall cleanup record does not bind the exact release Setup digest"
    }
    $transaction = $transactionJournal.transaction
    $transactionMaintenanceSHA256 = Get-OptionalJsonStringValue `
        -InputObject $transaction `
        -PropertyName "maintenance_sha256"
    if ([int]$transactionJournal.schema_version -ne 2 -or
        [string]$transactionJournal.phase -cne "converged" -or
        [int]$transaction.schema_version -ne 1 -or
        [string]$transaction.action -cne "uninstall" -or
        [string]$transaction.id -cne $transactionID -or
        [bool]$transaction.maintenance_existed -ne $true -or
        [string]$transaction.previous_maintenance_sha256 -cne $cachedSetupDigest -or
        [string]$transaction.previous_maintenance_sha256 -cne (
            [string]$cleanupRecord.maintenance_sha256
        ) -or
        $transactionMaintenanceSHA256 -cne "" -or
        [bool]$transaction.had_install -ne $true -or
        $null -eq $transaction.previous_state -or
        [bool]$transaction.delete_user_data -ne $true -or
        [string]$transaction.target_connector -cne "none" -or
        [bool]$transaction.target_services.gateway -ne $false -or
        [bool]$transaction.target_services.watchdog -ne $false) {
        throw "Same-boot uninstall did not retain the exact converged uninstall journal"
    }
    $previousState = $transaction.previous_state
    if ([int]$previousState.schema_version -ne 1 -or
        [string]$previousState.install_kind -cne "native-windows-exe" -or
        [string]$previousState.install_scope -cne "user" -or
        [string]$previousState.connector -cne "none" -or
        [bool]$previousState.unsigned_local_artifact -ne $releaseUnsigned -or
        [bool]$previousState.release_signing_required -ne $true) {
        throw "Converged uninstall journal does not bind the authenticated native installation"
    }
    foreach ($previousStateBinding in @(
        @([string]$previousState.install_root, $installRoot, "previous install root"),
        @([string]$previousState.data_root, $dataRoot, "previous install data root"),
        @([string]$previousState.maintenance_path, $cachedSetup, "previous maintenance executable")
    )) {
        Assert-CanonicalPathBinding `
            -Actual ([string]$previousStateBinding[0]) `
            -Expected ([string]$previousStateBinding[1]) `
            -Label ([string]$previousStateBinding[2])
    }
    foreach ($transactionPathBinding in @(
        @([string]$transaction.install_root, $installRoot, "transaction install root"),
        @([string]$transaction.data_root, $dataRoot, "transaction data root"),
        @([string]$transaction.maintenance_path, $cachedSetup, "transaction maintenance executable"),
        @([string]$transaction.staging_path, "$installRoot.staging.$transactionID", "transaction staging"),
        @([string]$transaction.backup_path, "$installRoot.backup.$transactionID", "transaction backup"),
        @([string]$transaction.trash_path, "$installRoot.uninstall.$transactionID", "transaction trash"),
        @(
            [string]$transaction.maintenance_new,
            "$cachedSetup.new.$transactionID",
            "transaction maintenance staging"
        ),
        @(
            [string]$transaction.maintenance_backup,
            "$cachedSetup.backup.$transactionID",
            "transaction maintenance backup"
        )
    )) {
        Assert-CanonicalPathBinding `
            -Actual ([string]$transactionPathBinding[0]) `
            -Expected ([string]$transactionPathBinding[1]) `
            -Label ([string]$transactionPathBinding[2])
        Assert-NoReparsePathChain -Path ([string]$transactionPathBinding[0])
    }
    foreach ($transactionArtifact in @(
        [string]$transaction.install_root,
        [string]$transaction.staging_path,
        [string]$transaction.backup_path,
        [string]$transaction.trash_path,
        [string]$transaction.maintenance_new,
        [string]$transaction.maintenance_backup
    )) {
        if (Test-Path -LiteralPath $transactionArtifact) {
            throw "Converged uninstall retained a transaction artifact: $transactionArtifact"
        }
    }
    $journalConnectors = @(
        Get-OptionalJsonStringArrayValue `
            -InputObject $transaction `
            -PropertyName "previous_connectors"
    )
    $recordConnectors = @(
        Get-OptionalJsonStringArrayValue `
            -InputObject $cleanupRecord `
            -PropertyName "verified_connectors"
    )
    if ($recordConnectors.Count -ne 0 -or $journalConnectors.Count -ne 0) {
        throw "Connector-none release uninstall retained connector cleanup authority"
    }
    $hookDataRoot = Get-OptionalJsonStringValue `
        -InputObject $hookState `
        -PropertyName "data_root"
    $hookGatewayPath = Get-OptionalJsonStringValue `
        -InputObject $hookState `
        -PropertyName "gateway_path"
    $hookGatewaySHA256 = Get-OptionalJsonStringValue `
        -InputObject $hookState `
        -PropertyName "gateway_sha256"
    if ([int]$hookState.schema_version -ne 2 -or
        [string]$hookState.status -cne "disabled" -or
        [string]$hookState.transaction_id -cne $transactionID -or
        $hookDataRoot -cne "" -or
        $hookGatewayPath -cne "" -or
        $hookGatewaySHA256 -cne "") {
        throw "Same-boot uninstall did not retain the exact disabled HookRuntime state"
    }
    $expectedHookLauncherDigest = [string]$provenance.inputs.hook_launcher_sha256
    $actualHookLauncherDigest = (
        Get-FileHash -LiteralPath $hookLauncher -Algorithm SHA256
    ).Hash.ToLowerInvariant()
    $hookLauncherItem = Get-Item -LiteralPath $hookLauncher -Force
    if ($expectedHookLauncherDigest -cnotmatch "^[0-9a-f]{64}$" -or
        $actualHookLauncherDigest -cne $expectedHookLauncherDigest -or
        [string]$cleanupRecord.launcher_sha256 -cne $expectedHookLauncherDigest -or
        [string]$hookState.launcher_sha256 -cne $expectedHookLauncherDigest -or
        [int64]$cleanupRecord.launcher_size -ne [int64]$hookLauncherItem.Length -or
        [string]$cleanupRecord.launcher_kind -cne "trampoline" -or
        [string]$hookState.launcher_kind -cne "trampoline" -or
        [string]$cleanupRecord.hook_sha256 -cnotmatch "^[0-9a-f]{64}$" -or
        [string]$cleanupRecord.hook_sha256 -cne [string]$hookState.hook_sha256) {
        throw "Same-boot uninstall did not cross-bind the exact sealed HookRuntime launcher"
    }
    Assert-WindowsAMD64Executable -Path $hookLauncher
    $hookSignature = Get-AuthenticodeSignature -FilePath $hookLauncher
    $hookPublisher = if ($null -eq $hookSignature.SignerCertificate) {
        ""
    } else {
        $hookSignature.SignerCertificate.GetNameInfo(
            [Security.Cryptography.X509Certificates.X509NameType]::SimpleName,
            $false
        )
    }
    $signerThumbprintSHA256 = Get-OptionalJsonStringValue `
        -InputObject $cleanupRecord `
        -PropertyName "signer_thumbprint_sha256"
    if ($releaseUnsigned) {
        if ($hookSignature.Status -ne [System.Management.Automation.SignatureStatus]::NotSigned -or
            $null -ne $hookSignature.SignerCertificate -or
            [bool]$cleanupRecord.launcher_signed -ne $false -or
            [bool]$cleanupRecord.unsigned_local_artifact -ne $true -or
            $signerThumbprintSHA256 -cne "") {
            throw "Explicitly unverified release retained inconsistent unsigned-local HookRuntime authority"
        }
    } else {
        if ($hookSignature.Status -ne [System.Management.Automation.SignatureStatus]::Valid -or
            $null -eq $hookSignature.SignerCertificate -or
            $hookPublisher -cne "Cisco Systems, Inc." -or
            [bool]$cleanupRecord.launcher_signed -ne $true -or
            [bool]$cleanupRecord.unsigned_local_artifact -ne $false) {
            throw "Signed release retained a HookRuntime launcher without valid Cisco Authenticode"
        }
        $actualSignerDigest = [Convert]::ToHexString(
            [Security.Cryptography.SHA256]::HashData(
                $hookSignature.SignerCertificate.RawData
            )
        ).ToLowerInvariant()
        if ($signerThumbprintSHA256 -cne $actualSignerDigest) {
            throw "Same-boot uninstall HookRuntime signer differs from the authenticated cleanup record"
        }
    }

    $hookRuntimeNames = @(
        Get-ChildItem -LiteralPath $hookRuntimeRoot -Force |
            ForEach-Object Name |
            Sort-Object
    )
    $expectedHookRuntimeNames = @("defenseclaw-hook.exe", "hook-runtime-state.json")
    if (($hookRuntimeNames -join "`0") -cne ($expectedHookRuntimeNames -join "`0")) {
        throw "Same-boot uninstall retained unexpected HookRuntime residue: $($hookRuntimeNames -join ', ')"
    }

    $installerStateNames = @(
        Get-ChildItem -LiteralPath $installerStateRoot -Force |
            ForEach-Object Name |
            Sort-Object
    )
    $unexpectedInstallerState = @(
        $installerStateNames |
            Where-Object {
                $_ -notin @(
                    "setup-transaction.json",
                    "setup.log",
                    "uninstall-cleanup.json"
                )
            }
    )
    if ($unexpectedInstallerState.Count -ne 0) {
        throw "Same-boot uninstall retained unrelated InstallerState: $($unexpectedInstallerState -join ', ')"
    }
    foreach ($installerStateName in $installerStateNames) {
        Assert-PrivatePathCustody -Path (Join-Path $installerStateRoot $installerStateName)
    }

    $cacheNames = @(
        Get-ChildItem -LiteralPath $CacheRoot -Force |
            ForEach-Object Name |
            Sort-Object
    )
    if (($cacheNames -join "`0") -cne "DefenseClawSetup-x64.exe") {
        throw "Same-boot uninstall retained unexpected installer-cache residue: $($cacheNames -join ', ')"
    }

    $productRootNames = @(
        Get-ChildItem -LiteralPath $productRoot -Force |
            ForEach-Object Name |
            Sort-Object
    )
    $expectedProductRootNames = @("HookRuntime", "InstallerCache", "InstallerState")
    if (($productRootNames -join "`0") -cne ($expectedProductRootNames -join "`0")) {
        throw "Same-boot uninstall retained unrelated managed residue: $($productRootNames -join ', ')"
    }

    $runKey = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey(
        "Software\Microsoft\Windows\CurrentVersion\Run",
        $false
    )
    if ($null -eq $runKey) {
        throw "Same-boot uninstall did not retain the cleanup Run key"
    }
    try {
        $runCommand = $runKey.GetValue(
            "DefenseClawDeferredUninstallCleanup",
            $null,
            [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
        )
        $runValueKind = if ($null -eq $runCommand) {
            $null
        } else {
            $runKey.GetValueKind("DefenseClawDeferredUninstallCleanup")
        }
    } finally {
        $runKey.Dispose()
    }
    if ($runValueKind -ne [Microsoft.Win32.RegistryValueKind]::String -or
        [string]$runCommand -cne [string]$cleanupRecord.run_command) {
        throw "Same-boot uninstall Run value differs from the authenticated cleanup record"
    }
    $runCommandMatch = [regex]::Match(
        [string]$runCommand,
        '^"(?<path>[^"]+)" (?<tail>/cleanup /quiet CLEANUPTRANSACTION=[0-9a-f]{32})$'
    )
    $expectedTail = "/cleanup /quiet CLEANUPTRANSACTION=" +
        [string]$cleanupRecord.transaction_id
    $rawRunPath = [string]$runCommandMatch.Groups["path"].Value
    $normalizedRunPath = if ($runCommandMatch.Success) {
        [IO.Path]::GetFullPath($rawRunPath)
    } else {
        ""
    }
    if (-not $runCommandMatch.Success -or
        [string]$runCommandMatch.Groups["tail"].Value -cne $expectedTail -or
        -not $rawRunPath.Equals(
            $normalizedRunPath,
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        -not $normalizedRunPath.Equals(
                [IO.Path]::GetFullPath($cachedSetup),
                [StringComparison]::OrdinalIgnoreCase
            )) {
        throw "Same-boot uninstall Run value is not the exact absolute cached Setup command"
    }
}

if (-not $Child) {
    if (-not $IsWindows) {
        throw "Fresh Windows release smoke requires native Windows"
    }
    if ($env:GITHUB_ACTIONS -ne "true" -or $env:RUNNER_ENVIRONMENT -ne "github-hosted") {
        throw "Fresh Windows release smoke is restricted to GitHub-hosted Windows CI"
    }
    if ([string]::IsNullOrWhiteSpace($env:RUNNER_TEMP)) {
        throw "RUNNER_TEMP is required for disposable Windows release smoke"
    }

    $helper = Join-Path $Root "scripts\invoke-windows-setup-standard-user-ci.ps1"
    $stateBase = if ([string]::IsNullOrWhiteSpace($StateRoot)) {
        Join-Path $env:RUNNER_TEMP (
            "defenseclaw-bootstrap-acceptance-" + [guid]::NewGuid().ToString("N")
        )
    } else {
        [IO.Path]::GetFullPath($StateRoot)
    }
    $helperCompleted = $false
    try {
        & $helper `
            -Mode bootstrap-acceptance `
            -ArtifactRoot $ReleaseDir `
            -StateRoot $stateBase `
            -TargetVersion $TargetVersion `
            -BootstrapUninstallContract $UninstallContract `
            -DiagnosticsRoot $DiagnosticsRoot `
            -TimeoutSeconds 1800
        $helperCompleted = $true
    } finally {
        $resolvedState = [IO.Path]::GetFullPath($stateBase).TrimEnd('\')
        $approvedStateBases = @(
            $env:RUNNER_TEMP,
            $env:DC_WINDOWS_NATIVE_BASE_ROOT
        ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            ForEach-Object { [IO.Path]::GetFullPath($_).TrimEnd('\') }
        $approvedBoundary = $approvedStateBases | Where-Object {
            $resolvedState.StartsWith(
                $_ + [IO.Path]::DirectorySeparatorChar,
                [StringComparison]::OrdinalIgnoreCase
            )
        } | Select-Object -First 1
        if ([string]::IsNullOrWhiteSpace([string]$approvedBoundary) -or
            -not ([IO.Path]::GetFileName($resolvedState)).StartsWith(
                "defenseclaw-bootstrap-acceptance-",
                [StringComparison]::Ordinal
            )) {
            throw "Refusing to clean unexpected bootstrap acceptance state: $resolvedState"
        }
        if (Test-Path -LiteralPath $resolvedState) {
            if ($helperCompleted) {
                Remove-Item -LiteralPath $resolvedState -Recurse -Force -ErrorAction Stop
            } else {
                Write-Warning (
                    "Disposable bootstrap state was preserved after failure: $resolvedState"
                )
            }
        }
    }
    return
}

if (-not $IsWindows) {
    throw "Disposable bootstrap acceptance child requires native Windows"
}
if ([string]::IsNullOrWhiteSpace($StateRoot)) {
    throw "Disposable bootstrap acceptance child requires StateRoot"
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$accountName = ($identity.Name -split '\\')[-1]
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if ($accountName -notmatch '^dcacc[0-9a-f]{10}$' -or
    $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Bootstrap acceptance child must be a disposable real Windows standard user"
}

$userProfile = [Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)
$localAppData = [Environment]::GetFolderPath(
    [Environment+SpecialFolder]::LocalApplicationData
)
if ([string]::IsNullOrWhiteSpace($userProfile) -or
    [string]::IsNullOrWhiteSpace($localAppData) -or
    [string]::IsNullOrWhiteSpace($env:USERPROFILE) -or
    -not ([IO.Path]::GetFullPath($env:USERPROFILE)).TrimEnd('\').Equals(
        ([IO.Path]::GetFullPath($userProfile)).TrimEnd('\'),
        [StringComparison]::OrdinalIgnoreCase
    )) {
    throw "Disposable bootstrap child does not have a token-bound real user profile"
}

$installer = Join-Path $ReleaseDir "install.ps1"
$powerShell = Join-Path $PSHOME "pwsh.exe"
$cosign = Join-Path $ReleaseDir "cosign-windows-amd64.exe"
$setup = Join-Path $ReleaseDir "DefenseClawSetup-x64.exe"
$setupProvenance = Join-Path $ReleaseDir "DefenseClawSetup-x64.exe.provenance.json"
$installRoot = Join-Path $localAppData "Programs\DefenseClaw"
$dataRoot = Join-Path $userProfile ".defenseclaw"
$cacheRoot = Join-Path $localAppData "DefenseClaw\InstallerCache"
$arpKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\DefenseClaw"
$launcher = Join-Path $installRoot "bin\defenseclaw.exe"
$gateway = Join-Path $installRoot "bin\defenseclaw-gateway.exe"
$installed = $false
$userPathBefore = [Environment]::GetEnvironmentVariable("Path", "User")

foreach ($path in @(
    $installRoot,
    $dataRoot,
    $cacheRoot,
    $arpKey
)) {
    if (Test-Path -LiteralPath $path) {
        throw "Bootstrap acceptance refuses pre-existing product state: $path"
    }
}
if (-not (Test-Path -LiteralPath $powerShell -PathType Leaf)) {
    throw "Bootstrap acceptance input is missing: $powerShell"
}
foreach ($path in @($installer, $cosign, $setup, $setupProvenance)) {
    Assert-RegularReleaseFile -Path $path
}

# The supported public path has no custom home override. Setup and the
# compatibility bootstrap must agree on the account's real Known Folder.
Remove-Item Env:DEFENSECLAW_HOME -ErrorAction SilentlyContinue

$bootstrapArguments = @(
    "-NoLogo",
    "-NoProfile",
    "-NonInteractive",
    "-File",
    $installer,
    "-Local",
    $ReleaseDir,
    "-CosignPath",
    $cosign,
    "-Version",
    $TargetVersion,
    "-Connector",
    "none",
    "-Yes"
)

try {
    $first = Invoke-CapturedProcess `
        -FilePath $powerShell `
        -ArgumentList $bootstrapArguments
    Assert-BootstrapSucceeded `
        -Result $first `
        -ExpectedVersion $TargetVersion `
        -Phase "First public bootstrap"
    $installed = $true

    foreach ($path in @($launcher, $gateway)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Public bootstrap did not install native executable: $path"
        }
    }
    if (-not (Test-Path -LiteralPath $arpKey)) {
        throw "Public bootstrap did not publish the per-user Installed Apps registration"
    }
    Assert-ExactVersion -Executable $launcher -ExpectedVersion $TargetVersion
    Assert-ExactVersion -Executable $gateway -ExpectedVersion $TargetVersion
    if ((Get-UserPathEntryCount `
            -Value ([Environment]::GetEnvironmentVariable("Path", "User")) `
            -ExpectedEntry (Join-Path $installRoot "bin")) -ne 1) {
        throw "Public bootstrap did not publish exactly one native user PATH entry"
    }

    $firstHashes = @(
        (Get-FileHash -LiteralPath $launcher -Algorithm SHA256).Hash,
        (Get-FileHash -LiteralPath $gateway -Algorithm SHA256).Hash
    )
    $second = Invoke-CapturedProcess `
        -FilePath $powerShell `
        -ArgumentList $bootstrapArguments
    Assert-BootstrapSucceeded `
        -Result $second `
        -ExpectedVersion $TargetVersion `
        -Phase "Repeated public bootstrap"
    Assert-ExactVersion -Executable $launcher -ExpectedVersion $TargetVersion
    Assert-ExactVersion -Executable $gateway -ExpectedVersion $TargetVersion
    if ((Get-UserPathEntryCount `
            -Value ([Environment]::GetEnvironmentVariable("Path", "User")) `
            -ExpectedEntry (Join-Path $installRoot "bin")) -ne 1) {
        throw "Repeated public bootstrap changed the native user PATH entry count"
    }
    $secondHashes = @(
        (Get-FileHash -LiteralPath $launcher -Algorithm SHA256).Hash,
        (Get-FileHash -LiteralPath $gateway -Algorithm SHA256).Hash
    )
    if (($firstHashes -join ":") -cne ($secondHashes -join ":")) {
        throw "Repeated public bootstrap changed the exact installed candidate bytes"
    }

    $uninstall = Invoke-CapturedProcess `
        -FilePath $setup `
        -ArgumentList @("/uninstall", "/quiet", "DELETEUSERDATA=1")
    $expectedUninstallExitCode = if ($UninstallContract -ceq "deferred") {
        3010
    } else {
        0
    }
    if ($uninstall.ExitCode -ne $expectedUninstallExitCode) {
        throw (
            "Native uninstall did not return the required $UninstallContract " +
            "result $expectedUninstallExitCode ($($uninstall.ExitCode)):`n$($uninstall.Output)"
        )
    }
    $installed = $false
    foreach ($path in @($installRoot, $dataRoot, $arpKey)) {
        if (Test-Path -LiteralPath $path) {
            throw "Public bootstrap uninstall left active managed state behind: $path"
        }
    }
    if (-not [string]::Equals(
            $userPathBefore,
            [Environment]::GetEnvironmentVariable("Path", "User"),
            [StringComparison]::Ordinal
        )) {
        throw "Public bootstrap uninstall did not restore the original user PATH exactly"
    }
    if ($UninstallContract -ceq "deferred") {
        Assert-ExactDeferredUninstallState `
            -LocalAppData $localAppData `
            -CacheRoot $cacheRoot `
            -ExpectedSetup $setup `
            -ExpectedProvenance $setupProvenance
    } else {
        Wait-ForPathRemoval -Path $cacheRoot
        if (Test-Path -LiteralPath $cacheRoot) {
            throw "Historical immediate uninstall left installer-cache state behind: $cacheRoot"
        }
    }
    Write-Host "Fresh Windows public bootstrap passed: $TargetVersion" -ForegroundColor Green
} finally {
    if ($installed -or (Test-Path -LiteralPath $installRoot)) {
        try {
            $cleanup = Invoke-CapturedProcess `
                -FilePath $setup `
                -ArgumentList @("/uninstall", "/quiet", "DELETEUSERDATA=1")
            if ($cleanup.ExitCode -notin @(0, 3010)) {
                Write-Warning "Emergency native uninstall failed ($($cleanup.ExitCode))"
            }
        } catch {
            Write-Warning "Emergency native uninstall failed: $($_.Exception.Message)"
        }
    }
}
