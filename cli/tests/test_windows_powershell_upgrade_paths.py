# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

ROOT = Path(__file__).resolve().parents[2]
INSTALLER = ROOT / "scripts" / "install.ps1"
RESOLVER = ROOT / "scripts" / "upgrade.ps1"
RELEASE_HARNESS = ROOT / "scripts" / "test-upgrade-release-windows.ps1"


def _main_body(source: str) -> str:
    marker = "function Main {"
    assert marker in source
    return source[source.index(marker) :]


def test_windows_installer_refuses_existing_install_before_any_dependency_or_artifact_work() -> None:
    source = INSTALLER.read_text(encoding="utf-8")
    main = _main_body(source)

    assert "function Assert-FreshInstall" in source
    assert "function Test-InstallMarker" in source
    assert "Get-ChildItem -LiteralPath $parent -Force" in source
    assert "$DefenseClawHome," in source
    assert 'Join-Path $Venv "Scripts\\defenseclaw.exe"' in source
    assert 'Join-Path $InstallDir "defenseclaw.cmd"' in source
    assert 'Join-Path $InstallDir "defenseclaw-gateway.exe"' in source
    assert "$markers | Where-Object { Test-InstallMarker -Path $_ }" in source
    assert "Get-Command defenseclaw -CommandType Application, ExternalScript" in source
    assert "Get-Command defenseclaw-gateway -CommandType Application, ExternalScript" in source
    assert "$existing += [string]$installedGateway.Source" in source
    assert "No changes were made" in source
    assert "upgrade.ps1" in source
    guard = main.index("\n    Assert-FreshInstall\n")
    assert guard < main.index("$arch = Get-Arch", guard)
    assert guard < main.index("Install-Uv", guard)
    assert guard < main.index("Ensure-Python", guard)
    assert guard < main.index("$script:ReleaseVersion = Resolve-Version", guard)
    assert guard < main.index("Install-Gateway -Arch $arch", guard)
    assert guard < main.index("Install-Cli", guard)
    assert "$headerRead=0" in source
    assert "while($headerRead -lt $magic.Length)" in source
    assert "$sourceStream.Read($observed,$headerRead,$magic.Length-$headerRead)" in source
    assert "if($count -eq 0){break}" in source


def test_windows_fresh_installer_never_delegates_persistent_path_or_python_registration() -> None:
    source = INSTALLER.read_text(encoding="utf-8")
    install_uv = source[source.index("function Install-Uv {") : source.index("function Ensure-Python {")]
    ensure_python = source[source.index("function Ensure-Python {") : source.index("function Resolve-Version {")]

    assert '"UV_NO_MODIFY_PATH"' in install_uv
    assert '"1"' in install_uv
    assert "[EnvironmentVariableTarget]::Process" in install_uv
    assert "$previousUvNoModifyPath" in install_uv
    assert "finally" in install_uv
    assert 'SetEnvironmentVariable("Path"' not in install_uv
    assert "uv python install 3.12 --no-bin --no-registry --quiet" in ensure_python
    assert "$pythonInstallExitCode -ne 0" in ensure_python
    assert "Select-Object -Last 20" in ensure_python
    assert "A current uv release" in ensure_python
    assert "uv output:" in ensure_python
    assert "and adds that bin dir to the user PATH" not in source
    assert "Persistent PATH was not modified" in install_uv


def test_windows_fresh_installer_rolls_back_exact_attempt_owned_payloads() -> None:
    source = INSTALLER.read_text(encoding="utf-8")
    main = _main_body(source)

    # Windows PowerShell 5.1 treats a BOM-less script as the active ANSI code
    # page. Keep this release entrypoint ASCII so its mandatory 5.1 execution
    # does not rely on comment-only UTF-8 bytes being decoded benignly.
    assert INSTALLER.read_bytes().isascii()

    for contract in (
        "FreshPathClaim",
        "NtCreateFile",
        "FILE_CREATE",
        "FILE_DIRECTORY_FILE",
        "CreatePrivateDirectory",
        "OpenIfExists",
        "GetFileInformationByHandle",
        "SetFileInformationByHandle",
        "FILE_FLAG_OPEN_REPARSE_POINT",
        "FILE_SHARE_READ | FILE_SHARE_WRITE",
        "TransitionOpenedFileCustody",
        "DeleteOpenedFileExact",
        "MoveDirectoryNoReplace",
        "MOVEFILE_WRITE_THROUGH",
        "DeleteFileExact",
        "DeleteTreeExact",
        "ConfigureTestMoveOutAfterSnapshot",
        "ClearTestMoveOutAfterSnapshot",
        "DeleteEmptyDirectoryExact",
        "MAX_TREE_DEPTH",
        "MAX_TREE_NODES",
        "MAX_TREE_BYTES",
        "Add-FreshInstallStreamClaim",
        "Initialize-FreshInstallAttempt",
        "Undo-FreshInstallAttempt",
        "Add-PrivateDirectoryRollbackResidue",
        "Complete-FreshInstallAttempt",
        "Close-ReleasePolicyCustody",
        "PolicyCleanupWarning",
        "Private release-policy cleanup was incomplete",
        "Fresh-install payload rollback completed; retry is safe",
        "changed or nonempty attempt path was preserved",
    ):
        assert contract in source

    open_handle_start = source.index("private static SafeFileHandle OpenHandle")
    open_handle_end = source.index("private static SafeFileHandle OpenParentHandle")
    assert open_handle_start < open_handle_end
    assert "FILE_SHARE_DELETE" not in source[open_handle_start:open_handle_end]
    parent_handle = source[
        source.index("private static SafeFileHandle OpenParentHandle") : source.index(
            "private static BY_HANDLE_FILE_INFORMATION Information"
        )
    ]
    assert "FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE" in parent_handle
    factory = source[
        source.index("public static FreshPathClaim CreatePrivateDirectory") : source.index(
            "public static FreshPathClaim TransitionOpenedFileCustody"
        )
    ]
    assert "if (!parentIsDirectory || parentIsReparse)" in factory
    assert "private directory parent must be a real directory" in factory
    assert "SYNCHRONIZE | FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES" in factory
    assert "DELETE | SYNCHRONIZE" not in factory
    assert "FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE" in factory
    tree_delete = source[source.index("public bool DeleteTreeExact()") : source.index("public void Dispose()")]
    missing_child = tree_delete[
        tree_delete.index("if (current == null)") : tree_delete.index(
            "try {", tree_delete.index("if (current == null)")
        )
    ]
    assert "return false" in missing_child
    assert "continue" not in missing_child
    assert "InvokeTestMoveOutAfterSnapshot()" in tree_delete
    assert "FreshInstallDestination" in source
    assert "$sourceStream" in source
    assert "$checksumDigests" in source
    assert "$input" not in source
    assert "$matches" not in source
    assert '".$leaf.fresh-install-"' in source
    assert source.count("-FreshInstallDestination") == 2
    assert "Add-FreshInstallStreamClaim -Stream $shimStream -Path $shim" in source
    assert "Add-FreshInstallStreamClaim -Stream $stream -Path $marker" in source
    assert main.index("Initialize-FreshInstallAttempt") < main.index("Install-Gateway -Arch $arch")
    assert main.index("Install-Cli") < main.index("Complete-FreshInstallAttempt")
    assert main.index("Close-ReleasePolicyCustody") < main.index("Complete-FreshInstallAttempt")
    failure_handler = main[main.index("} catch {") : main.index("Write-Success")]
    assert "$installFailure$cleanupDiagnostic" in failure_handler
    cleanup = source[source.index("function Close-ReleasePolicyCustody {") : source.index("function Get-OwnerDaclSddl")]
    assert "$attemptCount = if ($InjectPolicyCleanupFailure) { 1 } else { 3 }" in cleanup
    assert "Start-Sleep -Milliseconds (50 * $attempt)" in cleanup
    assert "Write-Warn2 $script:PolicyCleanupWarning" in cleanup
    assert main.index("Undo-FreshInstallAttempt") < main.index(
        "Fresh-install payload rollback completed; retry is safe"
    )
    assert "Fresh-install fault injection requires -TestMode" in main
    assert "[Parameter(DontShow = $true)][switch]$TestMode" in source
    assert "[Parameter(DontShow = $true)][switch]$InjectFailureBeforeShim" in source
    assert "[Parameter(DontShow = $true)][switch]$InjectConcurrentShimBeforePublish" in source
    assert "[Parameter(DontShow = $true)][switch]$InjectPolicyCleanupFailure" in source
    assert "[Parameter(DontShow = $true)][switch]$InjectPolicyCustodyMoveBeforeCleanup" in source
    assert "[Parameter(DontShow = $true)][switch]$InjectFailureAfterFreshDirectoryMove" in source
    assert '[Parameter(DontShow = $true)][string]$NativePrivateDirectorySelfTestRoot = ""' in source

    harness = (ROOT / "scripts/test-fresh-install-release-windows.ps1").read_text(encoding="utf-8")
    assert "-InjectFailureBeforeShim" in harness
    assert "Invoke-FreshInstaller -InjectConcurrentShimBeforePublish" in harness
    assert "InjectPolicyCleanupFailure" in harness
    assert "InjectPolicyCustodyMoveBeforeCleanup" in harness
    assert "Invoke-FreshInstaller -InjectFailureAfterFreshDirectoryMove" in harness
    assert "Post-move fresh-directory cleanup was not exact" in harness
    assert "Persistent User PATH was not modified" in harness
    assert "Modern fresh install mutated the persistent user PATH" in harness
    assert 'defenseclaw.cmd`" init' in harness
    assert 'Join-Path $HomeRoot ".local\\bin"' in harness
    assert 'Join-Path $HomeRoot ".local/bin"' not in harness
    assert "Remove-MovedPolicyCustodyResidue" in harness
    assert "Creation-bound policy custody was not preserved" in harness
    assert "Remove-InjectedPolicyResidue" in harness
    assert "Fresh Windows install did not survive policy cleanup failure" in harness
    assert "Policy cleanup failure or residual retirement changed installed bytes" in harness
    assert "powershell.exe" in harness
    assert "Get-Command powershell.exe -CommandType Application -ErrorAction Stop" in harness
    assert "WindowsPowerShellCommand" not in harness
    assert "Windows PowerShell 5.1 could not parse/compile install.ps1" in harness
    assert "-NativePrivateDirectorySelfTestRoot $legacyNativeRoot" in harness
    assert "Windows PowerShell 5.1 native private lifecycle failed" in harness
    assert "Native private directory lifecycle passed" in source
    assert "Native snapshotted-child move-out refusal passed" in source
    assert "Native fresh directory fault boundaries passed" in source
    assert "Native private-directory self-test accepted a file as its parent" in source
    assert "Fresh-install payload rollback completed; retry is safe" in harness
    assert "Concurrent unclaimed shim disappeared during rollback" in harness
    assert "Failed fresh install left installer-created binary directories behind" in harness


def test_windows_private_custody_cleanup_is_creation_bound_and_identity_exact() -> None:
    source = INSTALLER.read_text(encoding="utf-8")

    create = source[
        source.index("function New-PrivateDirectory {") : source.index("function Get-PrivateDirectoryClaimKeys")
    ]
    cleanup = source[
        source.index("function Get-PrivateDirectoryClaimKeys") : source.index("function Close-ReleasePolicyCustody")
    ]
    materialize = source[
        source.index("function Copy-AuthenticatedPrivateArtifact") : source.index(
            "# Keep in sync with cli/defenseclaw/connector_paths.py"
        )
    ]

    assert "CreatePrivateDirectory" in create
    assert "$script:PrivateDirectoryClaims[$full] = [pscustomobject]@{" in create
    assert "Identity = $claim.Identity" in create
    assert "Native = $claim" in create
    assert "$claim = $null" in create
    assert "Remove-PrivateDirectory -Path $full -RequireEmpty" in create
    assert "Private install directory cleanup was incomplete; creation-bound custody" in create
    assert "private-directory-registration" in create
    assert "Update-RollbackSafetyBoundary" in create
    assert "Remove-Item" not in create
    assert "$script:PrivateDirectoryClaims.ContainsKey($full)" in cleanup
    assert "Sort-Object -Property Length -Descending" in cleanup
    assert "OpenIfExists" in cleanup
    assert "$cleanupClaim.Identity -cne $entry.Identity" in cleanup
    assert "$cleanupClaim.DeleteTreeExact()" in cleanup
    assert "canonical binding was lost" in cleanup
    assert "current location is unknown" in cleanup
    assert "canonical path now names a different object" in cleanup
    assert "private-directory-cleanup" in cleanup
    assert "Complete-RollbackSafetyBoundary" in cleanup
    assert "$entry.Native.Dispose()" in cleanup
    missing_path = cleanup[
        cleanup.index("if (-not $cleanupClaim)") : cleanup.index("if ($cleanupClaim.Identity -cne $entry.Identity)")
    ]
    assert "PrivateDirectoryClaims.Remove" not in missing_path
    assert ".Native.Dispose" not in missing_path
    deletion = cleanup.index("$cleanupClaim.DeleteTreeExact()")
    release = cleanup.index("$entry.Native.Dispose()", deletion)
    forget = cleanup.index("$script:PrivateDirectoryClaims.Remove($claimKeyFull)", release)
    assert deletion < release < forget
    assert "Remove-Item" not in cleanup
    assert "$output.Position = 0" in materialize
    assert "ComputeHash($output)" in materialize
    assert "DeleteOpenedFileExact" in materialize
    assert "Remove-Item" not in materialize

    path_claim = source[
        source.index("function Add-FreshInstallClaim") : source.index("function Add-FreshInstallStreamClaim")
    ]
    stream_claim = source[
        source.index("function Add-FreshInstallStreamClaim") : source.index("function Ensure-FreshInstallDirectory")
    ]
    assert "DeleteFileExact" not in path_claim
    assert "DeleteFileExact" in stream_claim

    fresh_directory = source[
        source.index("function New-FreshInstallOwnedDirectory") : source.index(
            "function Initialize-FreshInstallAttempt"
        )
    ]
    assert "Move-PrivateDirectoryClaimRegistration -Source $stage -Destination $full" in fresh_directory
    assert "Release-PrivateDirectoryClaim -Path $full" in fresh_directory
    assert "$InjectFailureAfterFreshDirectoryMove" in fresh_directory
    assert "Injected fresh-install directory failure after publishing" in fresh_directory
    assert "Remove-PrivateDirectoryClaimAt" in fresh_directory
    assert "-CandidatePath $candidatePath" in fresh_directory
    assert "Fresh-install directory publication cleanup was incomplete" in fresh_directory
    assert "Add-PrivateDirectoryRollbackResidue" in fresh_directory
    assert "process-local identity" in fresh_directory
    assert "fresh-directory-publication" in fresh_directory
    for boundary in (
        "pre-rekey",
        "open-failure",
        "lost-binding",
        "identity-mismatch",
        "list-add",
        "release",
    ):
        assert boundary in fresh_directory

    undo = source[
        source.index("function Undo-FreshInstallAttempt") : source.index("function Complete-FreshInstallAttempt")
    ]
    assert undo.count("Add-PrivateDirectoryRollbackResidue -Residue $residue") == 2
    assert "RollbackSafetyLedger" in source
    assert "rollback safety boundary did not complete" in source
    assert (
        "[StringComparison]::OrdinalIgnoreCase"
        in source[
            source.index("function Start-RollbackSafetyBoundary") : source.index(
                "function Update-RollbackSafetyBoundary"
            )
        ]
    )
    assert "canonical binding and current location are unverified" in source
    assert "claim will close when the installer exits" in source

    path_publish = source[source.index("function Add-ToPath") : source.index("# -- Success")]
    assert "Persistent User PATH is shared registry state" in path_publish
    assert "Persistent User PATH was not modified" in path_publish
    assert "Edit environment variables for your account" in path_publish
    assert "Add this exact directory" in path_publish
    assert '& `"$shim`" <command>' in path_publish
    assert "FreshInstallPublishedProcessPath" in path_publish
    assert "SetEnvironmentVariable" not in path_publish
    assert "FreshInstallOriginalUserPath" not in source
    assert "FreshInstallPublishedUserPath" not in source
    assert "Invoke-WithUserPathLock" not in source
    assert "InjectConcurrentUserPathBeforePublish" not in source
    assert 'SetEnvironmentVariable("Path"' not in source
    assert "FreshInstallPublishedProcessPath" in undo

    no_stage_identity = fresh_directory[
        fresh_directory.index("if (-not $stageIdentity)") : fresh_directory.index('$cleanupFailure = ""')
    ]
    assert "throw $publicationFailure" in no_stage_identity
    assert "missingClaimFailure" not in no_stage_identity
    assert "Die" not in no_stage_identity

    success = source[source.index("function Write-Success") : source.index("function Main {")]
    assert 'Join-Path $InstallDir "defenseclaw.cmd"' in success
    assert '& `"$shim`" init' in success
    assert "    defenseclaw init" not in success

    policy_cleanup = source[
        source.index("function Close-ReleasePolicyCustody") : source.index("function Get-OwnerDaclSddl")
    ]
    assert "$InjectPolicyCustodyMoveBeforeCleanup" in policy_cleanup
    assert "FreshPathClaim]::MoveDirectoryNoReplace" in policy_cleanup
    assert "its canonical binding is" in policy_cleanup
    assert "current location of installer-owned custody may be unknown" in policy_cleanup
    assert "Retained creation identity:" in policy_cleanup
    assert "installer-owned custody remains at" not in policy_cleanup

    legacy_gateway = source[source.index("function Install-Gateway") : source.index("function Install-Cli")]
    assert "Remove-PrivateDirectory -Path $tmp" in legacy_gateway


def test_windows_resolver_has_fail_closed_bridge_and_fresh_controller_contract() -> None:
    source = RESOLVER.read_text(encoding="utf-8")
    main = _main_body(source)

    assert "$versionMatches" in source
    assert "$gatewayProcesses" in source
    assert "$matches" not in source

    for required in (
        "minimum_source_version",
        "required_bridge_version",
        "auto_bridge_from",
        "tested_source_versions",
        "platform_tested_source_versions",
        "controller_upgrade_protocol",
        "migration_failure_policy",
        "required_cli_migrations",
        "DEFENSECLAW_STAGED_UPGRADE",
        "DEFENSECLAW_STAGED_BRIDGE_VERSION",
        "DEFENSECLAW_STAGED_BRIDGE_ARTIFACT_DIR",
        "_prepare_hard_cut_rollback_plan",
        "_execute_hard_cut_rollback",
        "No installed state changed",
    ):
        assert required in source
    assert "Invoke-FreshHardCut" in source
    assert ".dcwheel" in source
    assert ".dcgateway" in source
    assert "DEFENSECLAW-PROTECTED-ARTIFACT-V1" in source
    assert "-bxor 0xA5" in source
    assert "New-AuthenticatedMaterializedFile" in source
    assert "ExpectedOuterSha256" in source
    assert "changed after checksum authentication" in source
    assert "$outerHash.TransformBlock" in source
    assert "Authenticated protected $Label envelope has invalid magic" in source
    assert "Assert-CanonicalRefusalEnvelope" in source
    assert "[IO.FileMode]::CreateNew" in source
    assert "$destinationStream.Flush($true)" in source
    assert 'New-PrivateDirectory (Join-Path $directory "materialized")' in source
    assert '$expectedSchema = if ((Compare-Version $ReleaseVersion "0.8.4") -ge 0) { 2 } else { 1 }' in source
    assert "outside the tested Windows source matrix" in source
    assert "No tested in-place path exists from this version; remain on it and contact support" in source
    assert "Do not force $($final.Manifest.RequiredBridge)" in source
    assert "contact DefenseClaw support for a validated state-aware recovery path" in source
    assert "Bridge $bridgeVersion does not declare $installed in its tested Windows source matrix" in source
    assert "-I -m defenseclaw.main upgrade" in source

    release_gate = (ROOT / "scripts/test-upgrade-release-windows.ps1").read_text(encoding="utf-8")
    assert "defenseclaw-$TargetVersion-2-py3-none-any.whl" in release_gate
    assert "defenseclaw-$BaselineVersion-2-py3-none-any.whl" in release_gate
    assert "seed-target-dependencies.whl" not in release_gate
    assert "seed-baseline.whl" not in release_gate
    assert "Set-PrivateDirectoryAcl" in source
    assert "AreAccessRulesProtected" in source
    assert "ReparsePoint" in source
    assert 'Fail "cosign is required' in source
    assert "--certificate-identity" in source
    assert "/.github/workflows/release.yaml@refs/heads/main" in source
    assert "[IO.FileSystemAclExtensions]::Create" in source
    assert "Invoke-BridgeTransaction" in source
    assert "Restore-PhaseOneSource" in source
    assert "InjectPhaseOneFailureAfterMutation" in source
    assert "InjectPhaseOneCrashAfterMutation" in source
    assert "InjectPhaseOneCrashDuringRecovery" in source
    assert "phase-one-active.json" in source
    assert "Register-PhaseOneJournal" in source
    assert "Recover-InterruptedPhaseOne" in source
    assert "New-PhaseOneStateSnapshot" in source
    assert "Read-PhaseOneStateSnapshot" in source
    assert "Restore-PhaseOneStateSnapshot" in source
    assert "state_manifest_sha256" in source
    assert "state_snapshot_ready" in source
    assert "source_was_running" in source
    assert "Seal-PhaseOneStateSnapshot" in source
    assert "Stop-PhaseOneSourceForSnapshot" in source
    assert "Get-PhaseOneSourceRunningState" in source
    assert "Assert-PhaseOneGatewayStopped" in source
    assert "Get-PhaseOneGatewayProcesses" in source
    assert "Gateway stop command failed before phase-one state capture" in source
    assert "Gateway remains live after phase-one stop" in source
    assert 'schema_version=4;kind="defenseclaw-phase-one-recovery"' in source
    assert "active_snapshot_ready" in source
    assert "active_manifest_sha256" in source
    assert "Seal-PhaseOneActiveStateSnapshot" in source
    assert "Assert-PhaseOneStateRollbackCas" in source
    assert "Move-PhaseOnePathNoReplace" in source
    assert "Phase-one state diverged after migration; preserved without overwrite" in source
    assert "Install-PhaseOneBridgeArtifacts" in source
    assert "Invoke-FreshBridgeActivation" in source
    assert "resolver-owned bridge venv" in source
    assert ".defenseclaw-phase-one-owner.json" in source
    assert "Restore-PhaseOneSourceVenv" in source
    assert "bridge_wheel_sha256" in source
    assert "bridge_gateway_sha256" in source
    assert "venv_sddl" in source
    assert "base_python" in source
    assert "phase-one-mutator.lease" in source
    assert "Initialize-PhaseOneMutatorLease" in source
    assert "Enter-PhaseOneMutatorLease" in source
    assert "Invoke-PhaseOneLeasedCommand" in source
    assert "Sync-PhaseOneBridgeVenv" in source
    assert "A phase-one mutation child is still active" in source
    assert "Refusing to execute or overwrite an unrecognized phase-one gateway activation" in source
    for runtime_field in (
        "controller_home",
        "data_dir",
        "config_path",
        "path_identities",
        "openclaw_home_existed",
        "ControllerHome",
        "DataDir",
        "ConfigPath",
    ):
        assert runtime_field in source
    assert "Resolve-InstalledRuntimePaths" in source
    assert "Get-ControllerHome" in source
    assert "Get-PhaseOneDirectoryIdentity" in source
    assert "Ambient DEFENSECLAW_HOME differs" in source
    assert "Ambient DEFENSECLAW_CONFIG differs" in source
    assert "Get-PhaseOneOpenClawIdentity" in source
    assert "AllowCreatedOpenClaw" in source
    assert "Remove-PhaseOneOwnedMutationTemporaries" in source
    assert "DEFENSECLAW_UPGRADE_MUTATION_TOKEN" in source
    assert "InjectPhaseOneOwnedMutationTemporaries" in source
    assert "InjectPhaseOneFailureAfterFreshMutation" in source
    assert "New-TestPhaseOneOwnedMutationTemporaries" in source
    assert '$config+".pre-observability-migration.bak"' in source
    assert '$config+".lock"' in source
    assert '$config+".tmp-f3395"' in source
    assert "$env:DEFENSECLAW_HOME=$Plan.DataDir" in source
    assert "$env:DEFENSECLAW_CONFIG=$Plan.ConfigPath" in source
    fresh_activation = source[
        source.index("function Invoke-FreshBridgeActivation") : source.index(
            "function Write-PhaseOneBridgeSuccessReceipt"
        )
    ]
    assert fresh_activation.index("Seal-PhaseOneActiveStateSnapshot $Plan") < fresh_activation.index(
        'Invoke-PhaseOneLeasedCommand -Plan $Plan -Command @((Get-Gateway),"start")'
    )
    assert fresh_activation.index("Remove-PhaseOneOwnedMutationTemporaries $Plan") < fresh_activation.index(
        "Seal-PhaseOneActiveStateSnapshot $Plan"
    )
    restore_source = source[
        source.index("function Restore-PhaseOneSource {") : source.index("function Recover-InterruptedPhaseOne")
    ]
    assert restore_source.index("Assert-PhaseOneStateRollbackCas") < restore_source.index(
        "if(Test-Path -LiteralPath $Plan.GatewaySnapshot.Active"
    )
    assert restore_source.index("Assert-PhaseOneStateRollbackCas") < restore_source.index(
        "Restore-PhaseOneSourceVenv $Plan"
    )
    bridge_transaction = source[source.index("function Invoke-BridgeTransaction") : source.index("function Main")]
    assert "Invoke-Controller $Bridge.Version" not in bridge_transaction
    assert "Install-PhaseOneBridgeArtifacts $plan" in bridge_transaction
    assert "Invoke-FreshBridgeActivation -Plan $plan -Manifest $Bridge.Manifest" in bridge_transaction
    assert bridge_transaction.index("Remove-PhaseOneOwnedMutationTemporaries $plan") < bridge_transaction.index(
        "Sync-PhaseOneBridgeVenv $plan"
    )
    assert "Sync-PhaseOneBridgeVenv $plan" in bridge_transaction
    assert bridge_transaction.index("Complete-PhaseOneJournal $plan") < bridge_transaction.index(
        "Write-PhaseOneBridgeSuccessReceipt"
    )
    assert "if($committed)" in bridge_transaction
    assert "release contract; installed version $installed is already current" in main
    assert main.index("if($target -eq $installed)") < main.index("Confirm-Plan")
    for managed in (
        "guardrail_runtime.json",
        "active_connector.json",
        "connector_backups",
        '"hooks"',
        "observability-stack",
        "openclaw.json.pre-0.3.0-migration",
    ):
        assert managed in source
    assert 'kind -in @("symboliclink","junction")' in source
    assert "Remove-PhaseOneManagedPath" in source
    assert "Recover-InterruptedPhaseTwo" in source
    assert "phase-two-active.json" in source
    assert "phase-two-mutator.lease" in source
    assert "Enter-PhaseTwoMutatorLease" in source
    assert "_recover_interrupted_hard_cut" in source
    assert "$stateFiles.Count -ne 7" in source
    assert "$configPath=[IO.Path]::GetFullPath($configRaw)" in source
    assert "$env:DEFENSECLAW_HOME=$script:RuntimePaths.ControllerHome" in source
    assert "$env:DEFENSECLAW_CONFIG=$script:RuntimePaths.ConfigPath" in source
    assert "Test-VersionBoundGatewayHealth" in source
    assert "Assert-PhaseTwoGatewayStopped -DataDir $plan.DataDir -ConfigPath $plan.ConfigPath" in source
    assert "pip install --python (Get-Python) --quiet --offline --no-deps --reinstall" in source
    assert "--force-reinstall" not in source
    assert main.index("[void](Recover-InterruptedPhaseOne)") < main.index("[void](Recover-InterruptedPhaseTwo)")
    assert main.index("[void](Recover-InterruptedPhaseTwo)") < main.index("Resolve-InstalledRuntimePaths")
    assert main.index("[void](Recover-InterruptedPhaseTwo)") < main.index("$installed=Get-InstalledVersion")
    assert "$displaced=Join-Path $parent" in source
    assert "$createdQuarantine=Join-Path $createdParent" in source
    assert "$sourceStream=[IO.File]::OpenRead($Source)" in source
    assert "[IO.Directory]::CreateDirectory($Path, $acl)" in source


def test_windows_success_health_is_bounded_running_and_version_bound() -> None:
    source = RESOLVER.read_text(encoding="utf-8")
    helper = source[
        source.index("function Test-VersionBoundGatewayHealth") : source.index("function Assert-PhaseTwoGatewayStopped")
    ]

    for required in (
        "time.monotonic() + timeout_seconds",
        "http.client.HTTPConnection",
        'connection.request("GET", "/health", headers=headers)',
        "response.read((1 << 20) + 1)",
        'gateway.get("state") == "running"',
        'provenance.get("binary_version") == expected_version',
        "cfg.gateway.resolved_token() if loopback else",
        "-I -c $probe",
    ):
        assert required in helper
    assert "(Get-Gateway) status" not in helper

    source_probe = source[
        source.index("function Get-PhaseOneSourceRunningState") : source.index("function Assert-PhaseOneGatewayStopped")
    ]
    assert "-ExpectedVersion $ExpectedVersion" in source_probe

    fresh = source[
        source.index("function Invoke-FreshBridgeActivation") : source.index(
            "function Write-PhaseOneBridgeSuccessReceipt"
        )
    ]
    assert "-ExpectedVersion $Plan.BridgeVersion" in fresh
    assert "(Get-Gateway) status" not in fresh

    restore = source[
        source.index("function Restore-PhaseOneSource") : source.index("function Recover-InterruptedPhaseOne")
    ]
    assert "-ExpectedVersion $Plan.SourceVersion" in restore
    assert "(Get-Gateway) status" not in restore

    recovery = source[source.index("function Recover-InterruptedPhaseTwo") : source.index("function Confirm-Plan")]
    assert "-ExpectedVersion $expected" in recovery
    assert "-ExpectedVersion $plan.SourceVersion" in recovery

    final_health = source[source.index("function Assert-Healthy") : source.index("function Assert-RunningComponents")]
    assert "-ExpectedVersion $Expected" in final_health
    assert "(Get-Gateway) status" not in final_health


def test_windows_version_bound_health_probe_rejects_false_green_and_polls() -> None:
    source = RESOLVER.read_text(encoding="utf-8")
    helper = source[
        source.index("function Test-VersionBoundGatewayHealth") : source.index("function Assert-PhaseTwoGatewayStopped")
    ]
    marker = "$probe=@'\n"
    probe = helper[helper.index(marker) + len(marker) : helper.index("\n'@")]

    def run_probe(payloads: list[dict[str, object]]) -> subprocess.CompletedProcess[str]:
        class Handler(BaseHTTPRequestHandler):
            request_index = 0

            def do_GET(self) -> None:  # noqa: N802 - stdlib handler contract
                index = min(type(self).request_index, len(payloads) - 1)
                type(self).request_index += 1
                body = json.dumps(payloads[index]).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, _format: str, *_args: object) -> None:
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with TemporaryDirectory() as root:
                root_path = Path(root)
                (root_path / "config.yaml").write_text(
                    f"config_version: 7\ngateway:\n  api_bind: 127.0.0.1\n  api_port: {server.server_port}\n",
                    encoding="utf-8",
                )
                env = os.environ.copy()
                env["DEFENSECLAW_HOME"] = root
                env["DEFENSECLAW_CONFIG"] = str(root_path / "config.yaml")
                return subprocess.run(
                    [sys.executable, "-I", "-c", probe, root, "1", "0.8.4"],
                    cwd=ROOT,
                    env=env,
                    text=True,
                    capture_output=True,
                    timeout=5,
                    check=False,
                )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    unhealthy = {"gateway": {"state": "error"}, "provenance": {"binary_version": "0.8.4"}}
    wrong_version = {
        "gateway": {"state": "running"},
        "provenance": {"binary_version": "0.8.3"},
    }
    expected = {
        "gateway": {"state": "running"},
        "provenance": {"binary_version": "0.8.4"},
    }

    assert run_probe([unhealthy]).returncode != 0
    assert run_probe([wrong_version]).returncode != 0
    delayed = run_probe([unhealthy, wrong_version, expected])
    assert delayed.returncode == 0, delayed.stdout + delayed.stderr


def test_native_windows_release_harness_proves_refusal_bridge_and_exact_rollback() -> None:
    source = RELEASE_HARNESS.read_text(encoding="utf-8")

    assert "exact schema-4 contract" in source
    assert "[int]$payload.schema_version -ne 4" in source
    for journal_field in (
        "bridge_version",
        "bridge_wheel_sha256",
        "bridge_gateway_sha256",
        "venv_sddl",
        "venv_identity_sha256",
        "base_python",
    ):
        assert journal_field in source
    assert 'Join-Path $planRoot "source-venv"' in source
    assert 'Join-Path $Case.Venv ".defenseclaw-phase-one-owner.json"' in source
    assert "Phase-one bridge venv ownership marker does not bind the active plan" in source
    assert "--force-reinstall" not in source
    assert "[Parameter(Mandatory = $true)]\n    [ValidateNotNullOrEmpty()]\n    [string]$ReleaseDir" in source
    assert "[ValidatePattern('^(0|[1-9]\\d*)" in source
    assert "[string]$TargetVersion" in source
    assert "[string]$SourceVersion" in source
    assert "release\\upgrade-baselines.json" in source
    assert "platform_published_baselines" in source
    assert "$script:PublishedWindowsBaselines" in source
    assert "$windowsValues -notcontains $SourceVersion" in source
    assert "SourceVersion must be a pre-bridge release" in source
    assert '$PSBoundParameters.ContainsKey("SourceVersion")' in source
    assert "SourceVersion cannot be empty when explicitly supplied" in source
    assert "$script:PublishedPreBridgeBaselines" in source
    assert "auto_bridge_from must exactly match the reviewed pre-bridge baseline policy" in source
    assert "Candidate tested_source_versions does not match the reviewed global matrix" in source
    assert "Candidate platform_tested_source_versions.windows does not match" in source
    assert 'Join-Path $PSScriptRoot "upgrade.ps1"' in source
    assert 'Join-Path $PSScriptRoot "install.ps1"' in source
    assert "Explicit hard-cut refusal" in source
    assert "-LatestVersionOverride" in source
    assert "post-v8-port-blocker.bound" in source
    assert "Test-PhaseOneRollback" in source
    assert "Test-PhaseOneCrashRecovery" in source
    assert "Test-PhaseOneParentDeathLeaseRecovery" in source
    assert "phase-one-mutator.lease" in source
    assert "orphan phase-one mutator lease" in source
    assert "InjectPhaseOneCrashAfterJournalClose" in source
    assert "New-PrivateDecodedArtifact" in source
    assert "DEFENSECLAW-PROTECTED-ARTIFACT-V1" in source
    assert "Protected .dcwheel remained directly installable" in source
    assert "Protected .dcgateway remained directly consumable" in source
    assert "Test-ProtectedMaterializationCollision" in source
    assert "InjectProtectedMaterializationCollision" in source
    assert "Create-new refusal overwrote" in source
    assert "split-data-default-config" in source
    assert "split-data-external-config" in source
    assert "no-openclaw-install" in source
    assert "-NoOpenClaw" in source
    assert "Preflight refusal created an absent OpenClaw home" in source
    assert "-SplitDataDir" in source
    assert "-ExternalConfig" in source
    assert "Test-PhaseOneCrashRecovery -Case $splitDefault" in source
    assert "Test-PhaseOneRollback -Case $externalConfig" in source
    assert "Test-PhaseTwoWheelInstallCrashRecovery -Case $externalConfig" in source
    assert "Test-PhaseOneOwnedTemporaryRollback" in source
    assert "New-ForeignPhaseOneMutationTemporaries" in source
    assert "Current-attempt phase-one mutation temporary survived cleanup" in source
    assert "Foreign-token phase-one temporary was changed or removed" in source
    assert '"config/pre-observability-migration-backup","config/lock","config/fixed-temp"' in source
    assert "InjectPhaseOneFailureAfterMutation" in source
    assert "InjectPhaseOneCrashAfterMutation" in source
    assert "InjectPhaseOneCrashDuringRecovery" in source
    assert "InjectPhaseOneConcurrentEditAfterActiveSeal" in source
    assert "InjectPhaseOneConcurrentFileAfterActiveSeal" in source
    assert "Test-PhaseOneConcurrentDivergence" in source
    assert "Concurrent edit and new managed-tree file survived" in source
    assert "Test-PhaseOneStopFailures" in source
    assert "InjectPhaseOneStopFailure" in source
    assert "InjectPhaseOneNonQuiescentStop" in source
    assert "Assert-CaseGatewayStopped" in source
    assert "phase-one-active.json" in source
    assert "state_manifest_sha256" in source
    assert "complete managed set" in source
    assert 'ContainsKey("junction")' in source
    assert 'ContainsKey("symboliclink")' in source
    assert "Assert-ExternalPolicyTargetPreserved" in source
    assert "removed its external target" in source
    assert "Write-TransactionalStateSnapshot" in source
    assert "Test-PhaseTwoWheelInstallCrashRecovery" in source
    assert "target-wheel-install.blocked" in source
    assert "phase-two-active.json" in source
    assert "exact schema-3 contract" in source
    assert '"receipt_path","recovery_home"' in source
    assert "different controller recovery home" in source
    assert "exact seven-state inventory" in source
    assert '$Case.Controller ".upgrade-recovery"' in source
    assert 'failure_code -ne "interrupted"' in source
    assert 'status -eq "rolled_back"' in source
    assert 'failure_code -eq "health_check_failed"' in source
    assert "dacl_sddl" in source
    assert "owner_sid" in source
    assert "Assert-SnapshotsEqual" in source
    assert "Assert-RetainedBridgeArtifacts" in source
    assert 'Join-Path $PSScriptRoot "historical_release_auth.py"' in source
    assert "historical-artifact-digests.json" in source
    assert '"--asset", $name' in source
    assert "Signed release authentication failed" in source
    assert "--certificate-identity-regexp" not in source
    assert 'Get-Command "curl.exe"' in source
    assert '"--proto", "=https"' in source
    assert '"--proto-redir", "=https"' in source
    assert '"--max-filesize", [string]$maximumBytes' in source


@pytest.mark.skipif(
    not (shutil.which("pwsh") or shutil.which("powershell.exe") or shutil.which("powershell")),
    reason="PowerShell parser is unavailable on this host",
)
@pytest.mark.parametrize("path", [INSTALLER, RESOLVER, RELEASE_HARNESS])
def test_windows_powershell_scripts_parse_without_errors(path: Path) -> None:
    executable = shutil.which("pwsh") or shutil.which("powershell.exe") or shutil.which("powershell")
    assert executable is not None
    command = (
        "$tokens=$null; $errors=$null; "
        "[System.Management.Automation.Language.Parser]::ParseFile($env:PS_PARSE_FILE,[ref]$tokens,[ref]$errors) | Out-Null; "
        "if($errors.Count){$errors | ForEach-Object {$_.ToString()}; exit 1}"
    )
    completed = subprocess.run(
        [executable, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
        env={
            **os.environ,
            "POWERSHELL_TELEMETRY_OPTOUT": "1",
            "PS_PARSE_FILE": str(path),
        },
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
