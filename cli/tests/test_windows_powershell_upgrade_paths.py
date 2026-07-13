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


def _powershell_python_here_string(source: str, variable: str) -> str:
    marker = f"${variable}=@'\n"
    start = source.index(marker) + len(marker)
    return source[start : source.index("\n'@", start)]


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
        "RetirementState",
        "NamespaceObservation",
        "RetirementStateValue",
        "MutationStarted",
        "ObserveNamespace",
        "WaitForNamespaceRetirement",
        "NAMESPACE_RETIRE_TIMEOUT_MS",
        "ConfigureTestNamespaceRetirementDelay",
        "ClearTestNamespaceRetirementDelay",
        "ConfigureTestDeleteBindingDelay",
        "ClearTestDeleteBindingDelay",
        "OpenSnapshotObservationHandle",
        "OpenRetirementHandle",
        "ConfigureTestMoveOutAfterSnapshot",
        "ClearTestMoveOutAfterSnapshot",
        "ConfigureTestEmptyDirectoryDeleteFailures",
        "ClearTestEmptyDirectoryDeleteFailures",
        "ConsumeTestEmptyDirectoryDeleteFailure",
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

    rollback_residue = source[
        source.index("function Add-PrivateDirectoryRollbackResidue") : source.index(
            "function Initialize-FreshInstallAttempt"
        )
    ]
    assert "[AllowEmptyCollection()]" in rollback_residue

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
    assert "TREE_ROOT_DELETE_ATTEMPTS" not in source
    assert "WaitForNamespaceRetirement(" in tree_delete
    assert tree_delete.index("current.Dispose()") < tree_delete.index("WaitForNamespaceRetirement(")
    assert "return RetireRootNamespaceExact(" in tree_delete
    assert "never resnapshot or acquire fresh delete authority" in tree_delete
    assert tree_delete.count("SnapshotDirectory(path, 1, entries, ref bytes, deadline)") == 1
    assert "StartTestDeleteBindingDelay()" in tree_delete
    snapshot = source[
        source.index("private void SnapshotDirectory") : source.index(
            "public bool DeleteTreeExact()"
        )
    ]
    assert "OpenSnapshotObservationHandle(child, deadline)" in snapshot
    assert "OpenRetirementHandle" not in snapshot
    retirement_open = source[
        source.index("private static SafeFileHandle OpenRetirementHandle") : source.index(
            "private static SafeFileHandle OpenParentHandle"
        )
    ]
    assert "FILE_SHARE_READ | FILE_SHARE_WRITE" in retirement_open
    assert "FILE_SHARE_DELETE" not in retirement_open
    assert "ERROR_ACCESS_DENIED" in retirement_open
    assert "ERROR_SHARING_VIOLATION" in retirement_open
    assert "ERROR_DELETE_PENDING" in retirement_open
    assert "timed out binding exact fresh-install path for retirement" in retirement_open
    observer = source[
        source.index("private static NamespaceObservation ObserveNamespace") : source.index(
            "private static long NewNamespaceRetirementDeadline"
        )
    ]
    assert "FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE" in source[
        source.index("private static SafeFileHandle OpenNamespaceObservationHandle") : source.index(
            "private static TestRetainer TakeTestNamespaceRetainer"
        )
    ]
    assert "ERROR_FILE_NOT_FOUND" in observer
    assert "ERROR_PATH_NOT_FOUND" in observer
    assert "ERROR_ACCESS_DENIED" in observer
    assert "ERROR_SHARING_VIOLATION" in observer
    assert "ERROR_DELETE_PENDING" in observer
    assert "NamespaceObservation.Different" in observer
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
    self_test_branch = main.index("if ($NativePrivateDirectorySelfTestRoot)")
    assert self_test_branch < main.index(
        "Invoke-NativePrivateDirectorySelfTest -Root $NativePrivateDirectorySelfTestRoot",
        self_test_branch,
    ) < main.index("return", self_test_branch) < main.index("Assert-FreshInstall")
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
    assert "-NativePrivateDirectorySelfTestRoot $modernNativeRoot" in harness
    assert "PowerShell 7 native private lifecycle failed" in harness
    assert "Native private directory lifecycle passed" in source
    assert "Native snapshotted-child move-out refusal passed" in source
    assert "Native fresh directory fault boundaries passed" in source
    assert "Native empty directory rollback retry passed" in source
    assert "Native delayed tree-root namespace retirement passed" in source
    assert "Native delayed child namespace retirement passed" in source
    assert "Native delayed exact DELETE binding passed" in source
    assert "Native namespace retirement wait passed" in source
    assert "Native post-move rollback topology passed" in source
    assert "Native private-directory self-test accepted a file as its parent" in source
    assert "Fresh-install payload rollback completed; retry is safe" in harness
    assert "Concurrent unclaimed shim disappeared during rollback" in harness
    assert "Failed fresh install left installer-created binary directories behind" in harness
    assert '-Phase "post-directory-publication injection" -Context $postMove.Output' in harness
    assert '-Phase "post-venv policy-cleanup injection"' in harness
    assert '-Phase "moved policy-custody injection"' in harness
    assert '-Phase "concurrent shim collision"' in harness
    assert "--- post-move installer output ---" in harness
    assert "bounded residual path inventory (names and kinds only)" in harness


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
    assert "$cleanupClaim.DeleteTreeExact($entry.Native)" in cleanup
    assert "$cleanupClaim.DeleteEmptyDirectoryExact($entry.Native)" in cleanup
    assert "$cleanupClaim.DeleteEmptyDirectoryExact($claim)" in create
    assert "CleanupTerminal = $false" in create
    assert "$entry.CleanupTerminal = $true" in cleanup
    assert "refusing a second traversal" in cleanup
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
    deletion = cleanup.index("$cleanupClaim.DeleteTreeExact($entry.Native)")
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
    assert '$entry.Native.RetirementStateValue -cne "Bound"' in undo
    assert "$entry.Native.MutationStarted" in undo
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
    assert '$maximumAttempts = if ($entry.Kind -ceq "EmptyDirectory") { 20 } else { 1 }' in undo
    assert "$removed = Remove-FreshInstallClaim -Entry $entry" in undo
    assert "Start-Sleep -Milliseconds (50 * $attempt)" in undo
    retry = undo[
        undo.index("$maximumAttempts = if") : undo.index("if (-not $removed)")
    ]
    assert retry.index("Remove-FreshInstallClaim") < retry.index("Start-Sleep")
    assert undo.index("if (-not $removed)") < undo.index("$entry.Native.Dispose()")

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


def test_windows_phase_one_custody_keeps_pep427_wheel_names() -> None:
    resolver = RESOLVER.read_text(encoding="utf-8")
    harness = RELEASE_HARNESS.read_text(encoding="utf-8")

    assert 'Join-Path $root "source.whl"' not in resolver
    assert 'Join-Path $root "bridge.whl"' not in resolver
    assert '"defenseclaw-$sourceVersion-py3-none-any.whl"' in resolver
    assert '"defenseclaw-$bridgeVersion-py3-none-any.whl"' in resolver
    assert '"defenseclaw-$([string]$payload.source_version)-py3-none-any.whl"' in harness
    assert '"defenseclaw-$([string]$payload.bridge_version)-py3-none-any.whl"' in harness


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


def test_windows_resolver_binds_hard_cut_provenance_before_mutation() -> None:
    source = RESOLVER.read_text(encoding="utf-8")
    main = _main_body(source)

    assert "function Validate-ReleaseProvenance" in source
    assert 'Download $ReleaseVersion "release-provenance.json"' in source
    assert 'Assert-Hash $provenancePath "release-provenance.json" $checksums' in source
    assert "$item.Length -gt 16384" in source
    assert "Hard-cut release provenance" in source
    assert "source_install_compatibility_epoch" in source
    assert "BridgeVersion=[string]$raw.bridge.version" in source
    assert "BridgeChecksumsSha256=[string]$raw.bridge.checksums_sha256" in source
    assert "function Assert-BridgeReleaseProvenance" in source
    assert "Authenticated 0.8.4 checksums do not match release-provenance.json" in source
    assert main.index("Assert-BridgeReleaseProvenance -Final $final -Bridge $bridge") < main.index(
        'Confirm-Plan "$installed -> $bridgeVersion -> fresh controller -> $target"'
    )
    assert main.index("Assert-BridgeReleaseProvenance -Final $final -Bridge $sourceRelease") < main.index(
        'Step "Fresh-controller handoff"'
    )
    assert "$raw.schema_version -ne 4" in source
    assert "receipt_provenance_binding_sha256" in source
    assert "Phase-two receipt provenance binding changed" in source
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
    runtime_paths = source[
        source.index("function Resolve-InstalledRuntimePaths") : source.index("function Get-OpenClawHome")
    ]
    assert 'if "data_dir" in loader_parameters:' in runtime_paths
    assert "cfg = config_module.load(data_dir=controller_home)" in runtime_paths
    assert "config_module.CONFIG_FILE_NAME = config_path" in runtime_paths
    assert "cfg = config_module.load()" in runtime_paths
    assert "config_module.CONFIG_FILE_NAME = legacy_config_name" in runtime_paths
    assert "installed source config loader has an unsupported signature" in runtime_paths
    assert "except TypeError" not in runtime_paths
    assert runtime_paths.index("$env:DEFENSECLAW_HOME=$controllerHome") < runtime_paths.index(
        "(Get-Python) -I -c $resolver"
    )
    assert runtime_paths.index("$env:DEFENSECLAW_CONFIG=$configPath") < runtime_paths.index(
        "(Get-Python) -I -c $resolver"
    )
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


@pytest.mark.parametrize(
    ("legacy_loader", "configured_data_dir"),
    [(True, True), (True, False), (False, True), (False, False)],
)
def test_windows_runtime_path_resolver_supports_published_and_scoped_loaders(
    legacy_loader: bool,
    configured_data_dir: bool,
) -> None:
    source = RESOLVER.read_text(encoding="utf-8")
    runtime_paths = source[
        source.index("function Resolve-InstalledRuntimePaths") : source.index("function Get-OpenClawHome")
    ]
    resolver = _powershell_python_here_string(runtime_paths, "resolver")

    if legacy_loader:
        loader = (
            "def load():\n"
            "    active = os.path.join(os.environ['DEFENSECLAW_HOME'], module.CONFIG_FILE_NAME)\n"
            "    return make_config(active)\n"
        )
    else:
        loader = (
            "def load(*, data_dir=None):\n"
            "    assert os.path.abspath(data_dir) == os.path.abspath(os.environ['DEFENSECLAW_HOME'])\n"
            "    return make_config(os.environ['DEFENSECLAW_CONFIG'])\n"
        )

    module_prelude = (
        "import json, os, sys, types\n"
        "module = types.ModuleType('defenseclaw.config')\n"
        "module.CONFIG_FILE_NAME = 'config.yaml'\n"
        "class Config:\n"
        "    def __init__(self, raw):\n"
        "        self.raw = raw\n"
        "        self.claw = types.SimpleNamespace(home_dir=raw.get('claw', {}).get('home_dir', '~/.openclaw'))\n"
        "    @property\n"
        "    def data_dir(self):\n"
        "        assert module.CONFIG_FILE_NAME == 'config.yaml'\n"
        "        return self.raw.get('data_dir', os.environ['DEFENSECLAW_HOME'])\n"
        "def make_config(active):\n"
        "    with open(active, encoding='utf-8') as stream:\n"
        "        raw = json.load(stream)\n"
        "    return Config(raw)\n"
        + loader
        + "module.load = load\n"
        "package = types.ModuleType('defenseclaw')\n"
        "package.__path__ = []\n"
        "package.config = module\n"
        "sys.modules['defenseclaw'] = package\n"
        "sys.modules['defenseclaw.config'] = module\n"
    )

    with TemporaryDirectory() as root:
        root_path = Path(root)
        controller = root_path / "controller"
        data_dir = root_path / "runtime-data"
        external = root_path / "external" / "defenseclaw.yaml"
        openclaw = root_path / "openclaw"
        controller.mkdir()
        data_dir.mkdir()
        external.parent.mkdir()
        raw: dict[str, object] = {"claw": {"home_dir": str(openclaw)}}
        if configured_data_dir:
            raw["data_dir"] = str(data_dir)
        external.write_text(json.dumps(raw), encoding="utf-8")
        env = os.environ.copy()
        env["DEFENSECLAW_HOME"] = str(controller)
        env["DEFENSECLAW_CONFIG"] = str(external)
        result = subprocess.run(
            [
                sys.executable,
                "-I",
                "-c",
                module_prelude + resolver,
                str(controller),
                str(external),
                "0",
                "__DEFENSECLAW_UNSET__",
            ],
            cwd=ROOT,
            env=env,
            text=True,
            capture_output=True,
            timeout=5,
            check=False,
        )

    assert result.returncode == 0, result.stdout + result.stderr
    contract = json.loads(result.stdout)
    assert Path(contract["data_dir"]) == (data_dir if configured_data_dir else controller)
    assert Path(contract["config_path"]) == external
    assert Path(contract["openclaw_home"]) == openclaw


def test_windows_runtime_path_resolver_rejects_unknown_loader_signature() -> None:
    source = RESOLVER.read_text(encoding="utf-8")
    runtime_paths = source[
        source.index("function Resolve-InstalledRuntimePaths") : source.index("function Get-OpenClawHome")
    ]
    resolver = _powershell_python_here_string(runtime_paths, "resolver")
    module_prelude = (
        "import sys, types\n"
        "module = types.ModuleType('defenseclaw.config')\n"
        "module.CONFIG_FILE_NAME = 'config.yaml'\n"
        "def load(path):\n"
        "    raise AssertionError('unsupported loader must not be called')\n"
        "module.load = load\n"
        "package = types.ModuleType('defenseclaw')\n"
        "package.__path__ = []\n"
        "package.config = module\n"
        "sys.modules['defenseclaw'] = package\n"
        "sys.modules['defenseclaw.config'] = module\n"
    )
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            module_prelude + resolver,
            str(ROOT),
            str(RESOLVER),
            "0",
            "__DEFENSECLAW_UNSET__",
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        timeout=5,
        check=False,
    )

    assert result.returncode != 0
    assert "installed source config loader has an unsupported signature" in result.stderr
    assert "unsupported loader must not be called" not in result.stderr


def test_windows_success_health_is_bounded_healthy_and_version_bound() -> None:
    source = RESOLVER.read_text(encoding="utf-8")
    helper = source[
        source.index("function Test-VersionBoundGatewayHealth") : source.index("function Assert-PhaseTwoGatewayStopped")
    ]

    for required in (
        "time.monotonic() + timeout_seconds",
        "http.client.HTTPConnection",
        'connection.request("GET", "/health", headers=headers)',
        "response.read((1 << 20) + 1)",
        'gateway.get("state") in {"running", "disabled"}',
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
    disabled_wrong_version = {
        "gateway": {"state": "disabled"},
        "provenance": {"binary_version": "0.8.3"},
    }
    disabled_expected = {
        "gateway": {"state": "disabled"},
        "provenance": {"binary_version": "0.8.4"},
    }
    expected = {
        "gateway": {"state": "running"},
        "provenance": {"binary_version": "0.8.4"},
    }

    assert run_probe([unhealthy]).returncode != 0
    assert run_probe([wrong_version]).returncode != 0
    assert run_probe([disabled_wrong_version]).returncode != 0
    assert run_probe([disabled_expected]).returncode == 0
    delayed = run_probe([unhealthy, wrong_version, expected])
    assert delayed.returncode == 0, delayed.stdout + delayed.stderr


def test_windows_release_authentication_output_cannot_pollute_manifest_return() -> None:
    source = (ROOT / "scripts" / "test-upgrade-release-windows.ps1").read_text(encoding="utf-8")
    release_set = source[
        source.index("function Assert-ReleaseSet") : source.index("function Assert-SealedCandidateResolver")
    ]

    capture = "$authenticationOutput = @(& $script:Commandpython @authenticationArguments 2>&1)"
    status = "$authenticationStatus = $LASTEXITCODE"
    host = "foreach ($line in $authenticationOutput) { Write-Host ([string]$line) }"
    gate = "if ($authenticationStatus -ne 0)"
    assert capture in release_set
    assert release_set.index(capture) < release_set.index(status) < release_set.index(host)
    assert release_set.index(host) < release_set.index(gate)
    assert "[void](Add-Type -AssemblyName System.IO.Compression.FileSystem)" in release_set
    assert "[void](Expand-Archive -LiteralPath $protectedGateway" in release_set
    assert "[void](Assert-ReleaseSet -Directory $destination -Version $TargetVersion)" in source
    assert "[void](Copy-CandidateRelease)" in source
    assert "$candidateManifestPath = Join-Path (Join-Path $script:ReleaseRoot $TargetVersion)" in source
    assert "Get-Content -LiteralPath $candidateManifestPath" in source
    assert "$candidateManifest -isnot [pscustomobject]" in source
    assert source.index("[void](Copy-CandidateRelease)") < source.index(
        "$hardCut = Assert-CandidatePolicy -Manifest $candidateManifest"
    )
    assert "$candidateReleaseOutput" not in source


def test_windows_release_snapshot_accumulators_accept_their_initial_empty_list() -> None:
    source = RELEASE_HARNESS.read_text(encoding="utf-8")
    snapshot_path = source[
        source.index("function Add-SnapshotPath") : source.index("function Add-SnapshotTree")
    ]
    snapshot_tree = source[
        source.index("function Add-SnapshotTree") : source.index("function Write-InstalledStateSnapshot")
    ]

    for helper in (snapshot_path, snapshot_tree):
        rows_type = helper.index("[System.Collections.Generic.List[object]]$Rows")
        rows_parameter = helper[:rows_type]
        assert "[Parameter(Mandatory = $true)]" in rows_parameter
        assert "[AllowEmptyCollection()]" in rows_parameter

    assert "$rows = New-Object System.Collections.Generic.List[object]" in source
    assert "Add-SnapshotPath -Rows $rows" in source
    assert "Add-SnapshotTree -Rows $rows" in source


@pytest.mark.skipif(
    not (shutil.which("pwsh") or shutil.which("powershell.exe") or shutil.which("powershell")),
    reason="PowerShell is unavailable on this host",
)
def test_powershell_release_snapshot_helpers_bind_an_empty_accumulator() -> None:
    executable = shutil.which("pwsh") or shutil.which("powershell.exe") or shutil.which("powershell")
    assert executable is not None
    source = RELEASE_HARNESS.read_text(encoding="utf-8")
    helpers = source[
        source.index("function Add-SnapshotPath") : source.index("function Write-InstalledStateSnapshot")
    ]
    command = (
        "$ErrorActionPreference='Stop'\n"
        + helpers
        + "\n$rows=New-Object System.Collections.Generic.List[object]\n"
        + "$seen=@{}\n"
        + "$case=[pscustomobject]@{Root=[IO.Path]::GetTempPath()}\n"
        + "$missing=Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString('N'))\n"
        + "Add-SnapshotPath -Rows $rows -Seen $seen -Case $case -Path $missing\n"
        + "Add-SnapshotTree -Rows $rows -Seen $seen -Case $case -Path $missing\n"
        + "if($rows.Count -ne 0){exit 9}\n"
    )
    completed = subprocess.run(
        [executable, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
        env={**os.environ, "POWERSHELL_TELEMETRY_OPTOUT": "1"},
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr


@pytest.mark.skipif(
    not (shutil.which("pwsh") or shutil.which("powershell.exe") or shutil.which("powershell")),
    reason="PowerShell is unavailable on this host",
)
def test_powershell_archive_refusal_preserves_scalar_manifest_output() -> None:
    executable = shutil.which("pwsh") or shutil.which("powershell.exe") or shutil.which("powershell")
    assert executable is not None
    command = (
        "$archive=[IO.Path]::GetTempFileName(); "
        "$destination=$archive + '-out'; "
        "function Get-Manifest([string]$path,[string]$destination) { "
        "try{[void](Expand-Archive -LiteralPath $path -DestinationPath $destination -ErrorAction Stop)}catch{}; "
        "return [pscustomobject]@{schema_version=2} }; "
        "try{$result=@(Get-Manifest $archive $destination); "
        "if($result.Count -ne 1 -or $result[0].schema_version -ne 2){exit 1}} "
        "finally{Remove-Item -LiteralPath $archive -Force -ErrorAction SilentlyContinue; "
        "Remove-Item -LiteralPath $destination -Recurse -Force -ErrorAction SilentlyContinue}"
    )
    completed = subprocess.run(
        [executable, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
        env={**os.environ, "POWERSHELL_TELEMETRY_OPTOUT": "1"},
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr


def test_windows_release_harness_accepts_both_reviewed_config_map_topologies() -> None:
    policy = json.loads((ROOT / "release/upgrade-baselines.json").read_text(encoding="utf-8"))

    def assert_reviewed_topology(candidate: dict[str, object]) -> None:
        assert candidate["schema_version"] == 2
        published = candidate["published_baselines"]
        config_versions = candidate["published_baseline_config_versions"]
        assert isinstance(published, list)
        assert isinstance(config_versions, dict)
        assert set(config_versions) == set(published)
        for version in published:
            major, minor, patch = (int(component) for component in version.split("."))
            expected = 7 if (major, minor, patch) >= (0, 8, 3) else 6 if (
                major,
                minor,
                patch,
            ) >= (0, 7, 1) else 5
            assert config_versions[version] == expected
        if "0.8.4" in config_versions:
            assert config_versions["0.8.4"] == 7

    with_bridge = json.loads(json.dumps(policy))
    if "0.8.4" not in with_bridge["published_baselines"]:
        with_bridge["published_baselines"].insert(0, "0.8.4")
        with_bridge["published_baseline_config_versions"]["0.8.4"] = 7
        with_bridge["platform_published_baselines"]["windows"].insert(0, "0.8.4")
    assert_reviewed_topology(with_bridge)

    without_bridge = json.loads(json.dumps(policy))
    without_bridge["published_baselines"] = [
        version for version in without_bridge["published_baselines"] if version != "0.8.4"
    ]
    without_bridge["published_baseline_config_versions"].pop("0.8.4", None)
    without_bridge["platform_published_baselines"]["windows"] = [
        version
        for version in without_bridge["platform_published_baselines"]["windows"]
        if version != "0.8.4"
    ]
    assert_reviewed_topology(without_bridge)


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
    assert "published_baseline_config_versions" in source
    assert "Upgrade baseline policy must be a schema_version 2 object" in source
    assert "Published baseline config-version keys must exactly match published_baselines" in source
    assert "Published baseline $value must seed historical config version $expectedConfigVersion" in source
    assert "$script:BaselineConfigVersions.ContainsKey($script:BridgeVersion) -and" in source
    assert "if ([int]$script:BaselineConfigVersions[$script:BridgeVersion]" not in source
    assert "Get-PublishedBaselineConfigVersion" in source
    assert "SourceConfigVersion = $sourceConfigVersion" in source
    assert "Assert-CaseConfigVersion -Case $case -Expected $sourceConfigVersion" in source
    assert "$versions.Count -ne 1" in source
    assert "[string]$versions[0] -cne $Expected" in source
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
    assert "Get-CandidateResolverPath" in source
    assert '"defenseclaw-upgrade.ps1"' in source
    assert "Assert-SealedCandidateResolver" in source
    assert "Sealed checksums.txt must bind defenseclaw-upgrade.ps1 exactly once" in source
    assert "# DefenseClaw upgrade resolver complete v1" in source
    assert 'Join-Path $PSScriptRoot "upgrade.ps1"' not in source
    assert 'Join-Path $PSScriptRoot "install.ps1"' in source
    assert "Explicit hard-cut refusal" in source
    assert "-LatestVersionOverride" in source
    assert "post-v8-port-blocker.bound" in source
    assert "if is_v8 and listener is None:" in source
    assert 'New-UpgradeCase -Name "post-publish-staged-rollback" -BaselineVersion $script:OldBaseline' in source
    assert "Assert-BridgeRollbackState" in source
    assert 'Join-Path $stateDirectory "config.yaml"' in source
    assert 'Join-Path $stateDirectory "environment"' in source
    assert 'Join-Path $stateDirectory "migration-state.json"' in source
    assert "Rolled-back bridge cursor retained target-only migration" in source
    assert "Bridge phase retained duplicate succeeded evidence" in source
    assert "Assert-CanonicalUpgradeEvent -Case $Case -From $transition[0] -Target $transition[1]" in source
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
    assert "exact schema-4 contract" in source
    assert '"receipt_path","receipt_provenance_binding_sha256"' in source
    assert '"release_provenance","release_provenance_sha256"' in source
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
