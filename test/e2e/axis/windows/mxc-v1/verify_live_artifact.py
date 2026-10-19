#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Verify the reviewed Windows PSEC contributor artifact. Never executes it."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import struct
import subprocess
import zipfile
from pathlib import Path, PurePosixPath

REPOSITORY = "cisco-ai-defense/defenseclaw"
WORKFLOW = ".github/workflows/axis-mxc-v1-windows-build.yml"
AXIS_COMMIT = "fb5fd5f0f9377c2ccb30d7e027a36373de0d037c"
MXC_COMMIT = "fda29ac63bc306b7f97f3b86b4b63d44f7f40cf2"
# Independently reviewed by the root agent before the first locked rebuild.
COMBINED_LOCK_SHA256 = "3b29ecb06dd2a81266c84712f8d6e088605290f386e87498bb7a7472a005af69"
BINARY = "bin/defenseclaw-axis-windows-psec-probe.exe"
LOADER_BINARY = "bin/defenseclaw-axis-windows-psec-loader-child.exe"
VARIANT = "separate_std_loader_diagnostic"
SCOPE = "fixed_windows_native_psec_loader_diagnostic"
SOURCE_PREFIX = "test/e2e/axis/windows/mxc-v1/"
SOURCE_FILES = {
    "Cargo.toml",
    "Cargo.lock",
    "prepare_build.py",
    "test_prepare_build.py",
    "README.md",
    "src/main.rs",
    "src/probe.rs",
    "src/loader_child.rs",
    "patches/mxc-strict-windows-psec.patch",
}
PATCHED_PATHS = {
    "src/mxc-sdk/src/lib.rs",
    "src/mxc-sdk/src/core/mxc_engine/mod.rs",
    "src/mxc-sdk/src/core/mxc_engine/dispatch.rs",
    "src/mxc-sdk/src/backends/process_container/common/base_container_runner.rs",
}
FILES = {"source/" + name for name in SOURCE_FILES} | {
    BINARY,
    LOADER_BINARY,
    "TOOLCHAIN.txt",
    "upstream/axis-Cargo.lock",
    "upstream/mxc-Cargo.lock",
    "upstream/axis-LICENSE",
    "upstream/mxc-LICENSE",
}
ALL_FILES = FILES | {"PROVENANCE.json", "WORKFLOW.json"}
BOUNDARY_BINARY = "bin/defenseclaw-axis-windows-psec-boundary-child.exe"
BOUNDARY_VARIANT = "standalone_std_boundary_native_identity_environment"
BOUNDARY_SCOPE = "fixed_windows_native_psec_boundary_native_identity_environment"
DLL_BINARY = "bin/defenseclaw-axis-windows-psec-dll-child.exe"
DLL_VARIANT = "standalone_std_fixed_dll_startup_diagnostic"
DLL_SCOPE = "fixed_windows_native_psec_dll_startup_diagnostic"
CLAUDE_VARIANT = "standalone_std_fixed_signed_claude_version"
CLAUDE_SCOPE = "fixed_windows_native_psec_signed_claude_version"
CONTROL_VARIANT = "standalone_std_fixed_signed_claude_create_control"
CONTROL_SCOPE = "fixed_windows_uncontained_claude_create_control"
CONTROL_OVERLAY_SHA256 = "1c68169aeac3a777b9fb553e7697a61af8ef38381442d45f293bd6ab35cd76f2"
CONTROL_SDK_TEST = (
    "backend_modules::process_container::common::base_container_runner::strict_windows_argv_tests::"
    "fixed_control_compares_exact_buffers_flags_stdio_and_refuses_other_payloads"
)
CONTROL_PATH = "src/mxc-sdk/src/backends/process_container/common/secenv.rs"
IDENTITY_OVERLAY_SHA256 = "d2d3819325c3027f159d75d577dd02306d497234f99293df3c825fbeebddeeab"
BOUNDARY_OVERLAY_SHA256 = "1a9c94cb33501091a504d5c4ff55281b183a9d41472709edf7f35541c25f45af"
LITERAL_OVERLAY_SHA256 = "7117afc3c7ae28345757c364518b7b9120a7dd8e6b844403b06fe05403e4a76d"
SDK_LOCK_SHA256 = "2d145ff3861cd19d1f50969083f8ac59e4d4fd50b030bef12f365a5fcc87afa0"
SDK_TEST_GROUPS = {
    "core_modules::mxc_common::sandbox_process::runner_tests": [
        "native_query_process_handle_defaults_to_unsupported_without_os_calls",
    ],
    "core_modules::mxc_engine::strict_psec_tests": [
        "strict_psec_refuses_fallback_dry_run_and_other_backends_before_spawn",
        "contributor_psec_admission_only_accepts_fixed_offline_posture",
    ],
    "v1::strict_windows_psec_argv_tests": [
        "preparation_preserves_literal_arguments_and_closed_native_options",
        "preparation_rejects_legacy_ambiguity_other_backend_and_missing_filesystem",
        "preparation_refuses_network_allow_before_any_native_creation",
        "preparation_refuses_normalization_that_drops_a_covering_grant",
    ],
    "backend_modules::process_container::common::base_container_runner::strict_windows_argv_tests": [
        "explicit_application_and_native_quoting_preserve_literal_values",
        "native_limit_and_invalid_application_fail_before_resource_creation",
        "native_failure_diagnostics_are_numeric_bounded_and_ordered",
    ],
    "backend_modules::process_container::common::base_container_runner::strict_windows_path_tests": [
        "local_lexical_admission_accepts_only_unambiguous_drive_paths",
        "native_local_file_custody_holds_image_against_write_without_spawning",
        "literal_image_mapping_requires_exact_success_before_resume",
        "native_process_image_mapping_matches_current_image_and_refuses_wrong_file",
    ],
}
SDK_TESTS = [group + "::" + name for group, names in SDK_TEST_GROUPS.items() for name in names]
NATIVE_DIRECTORY_CUSTODY_TESTS = {
    "defenseclaw-axis-windows-psec-probe": [
        "probe::native_identity::tests::directory_custody_blocks_rename_until_handles_close_without_spawning",
    ],
}


def native_directory_custody_tests(mode: str) -> dict[str, list[str]]:
    tests = {binary: list(names) for binary, names in NATIVE_DIRECTORY_CUSTODY_TESTS.items()}
    if mode == "standalone-boundary":
        tests["defenseclaw-axis-windows-psec-probe"].extend(
            [
                "probe::native_identity::private_native_record::tests::private_record_create_is_exclusive_nonfollowing_and_owner_system_only",
                "probe::native_identity::private_native_record::tests::private_environment_subtree_is_exclusive_nonfollowing_private_and_pinned",
            ]
        )
    return tests


PURE_ENVIRONMENT_TESTS = {
    "defenseclaw-axis-windows-psec-boundary-child": [
        "tests::private_environment_only_accepts_exact_local_disk_prefix_difference",
        "native_environment::tests::native_folder_requires_exact_private_branch_and_one_profile_component",
        "native_environment::tests::ordinary_native_profile_component_confines_literal_windows_names",
        "native_environment::tests::native_environment_utf16_frame_roundtrips_and_refuses_tampering",
    ],
    "defenseclaw-axis-windows-psec-probe": [
        "probe::native_environment::tests::native_folder_requires_exact_private_branch_and_one_profile_component",
        "probe::native_environment::tests::ordinary_native_profile_component_confines_literal_windows_names",
        "probe::native_environment::tests::native_environment_utf16_frame_roundtrips_and_refuses_tampering",
        "probe::native_identity::tests::returned_sid_pointer_and_body_must_fit_the_fixed_native_result",
        "probe::native_identity::tests::profile_directory_query_requires_bounded_complete_native_result",
    ],
}

PURE_STARTUP_ENVIRONMENT_TESTS = {
    "defenseclaw-axis-windows-psec-probe": [
        "probe::native_identity::tests::directory_open_refusal_contains_only_closed_gate_index_and_numeric_status",
        "probe::native_environment::tests::startup_environment_requires_exact_eight_private_values",
        "probe::native_environment::tests::startup_environment_snapshot_refuses_drift_and_canary_misuse",
        "probe::native_environment::tests::native_profile_refusal_classifier_reports_bounded_relationships",
        "probe::native_identity::private_native_record::tests::fixed_private_record_is_lossless_bounded_complete_and_not_authority",
    ],
}


def pure_environment_tests(mode: str) -> dict[str, list[str]]:
    tests = {binary: list(names) for binary, names in PURE_ENVIRONMENT_TESTS.items()}
    if mode == "standalone-boundary":
        for binary, names in PURE_STARTUP_ENVIRONMENT_TESTS.items():
            tests[binary].extend(names)
    return tests


PURE_DLL_TESTS = {
    "defenseclaw-axis-windows-psec-dll-child": [
        "dll_startup_protocol::tests::fixed_dll_selectors_never_accept_an_arbitrary_module_or_path",
        "dll_startup_protocol::tests::exact_dll_markers_distinguish_returned_error_from_success",
    ],
    "defenseclaw-axis-windows-psec-probe": [
        "probe::dll_startup_protocol::tests::fixed_dll_selectors_never_accept_an_arbitrary_module_or_path",
        "probe::dll_startup_protocol::tests::exact_dll_markers_distinguish_returned_error_from_success",
    ],
}
BOUNDARY_MODIFIED_PATHS = PATCHED_PATHS | {
    "src/mxc-sdk/src/sandbox.rs",
    "src/mxc-sdk/src/backends/bubblewrap/common/bwrap_command.rs",
    "src/mxc-sdk/src/backends/bubblewrap/common/bwrap_runner.rs",
    "src/mxc-sdk/src/backends/seatbelt/common/seatbelt_runner.rs",
    "src/mxc-sdk/src/core/mxc_common/mod.rs",
    "src/mxc-sdk/src/core/mxc_common/sandbox_process.rs",
    "src/mxc-sdk/src/core/mxc_common/validator.rs",
    "src/mxc-sdk/src/policy.rs",
    "src/mxc-sdk/src/policy/exact/mod.rs",
}
BOUNDARY_ADDED_PATHS = {
    "src/mxc-sdk/src/core/mxc_common/literal_argv.rs",
    "src/mxc-sdk/src/core/mxc_engine/literal_argv.rs",
    "src/mxc-sdk/src/literal_argv.rs",
}


# Exact fda source with the four contributor overlays. This source registry
# remains subject to independent review before a new artifact/live admission.
BOUNDARY_OVERLAY_FILES = {
    "src/mxc-sdk/src/sandbox.rs": "530bb8fbbaf97715fdc6efbdfe28706b333e3140cca4456641759fdb30ca62b1",
    "src/mxc-sdk/src/backends/bubblewrap/common/bwrap_command.rs": (
        "a13934345597bd3fcaa66353b37ed5a9f54e643d234a620257970035b6212abc"
    ),
    "src/mxc-sdk/src/backends/bubblewrap/common/bwrap_runner.rs": (
        "5b23635df276e0743f9f9986f1ee4b63d9b0c71685b8e14bfa7b099023cfa210"
    ),
    "src/mxc-sdk/src/backends/process_container/common/base_container_runner.rs": (
        "68add915437007786ddef0d4fbf4100a5b3f034b2c910f283991c8730d77e95c"
    ),
    "src/mxc-sdk/src/backends/seatbelt/common/seatbelt_runner.rs": (
        "110534317bd4311b6ce1253126a7f6d507b7e98f381ad7945a63792e3297a13e"
    ),
    "src/mxc-sdk/src/core/mxc_common/literal_argv.rs": (
        "9a75fbca0fe9152abe4349ed37dd0a5db0d272e10ba89ecfbeb1f54bbd07d89d"
    ),
    "src/mxc-sdk/src/core/mxc_common/mod.rs": ("42bb9328a9beb5f5217a55f11f5a4341fc36f8dbda9cf72729aeb767f7d92289"),
    "src/mxc-sdk/src/core/mxc_common/sandbox_process.rs": (
        "4ad92632273e3f26ad902c7611edd13146bc96911a69c915954b84b398ae1508"
    ),
    "src/mxc-sdk/src/core/mxc_common/validator.rs": (
        "a7487090a1693fb237acedd81f4e1c66b64d907c77e46824cc81a9f571c92191"
    ),
    "src/mxc-sdk/src/core/mxc_engine/dispatch.rs": ("e1fd28a30b19f04d6be4c6694f33ee6cbad005e02aad334a1085d2438808df49"),
    "src/mxc-sdk/src/core/mxc_engine/literal_argv.rs": (
        "c35bb7f302e84fbca74c62d4d8d12bb142002a6f69f12476f386c7a858b5f719"
    ),
    "src/mxc-sdk/src/core/mxc_engine/mod.rs": ("1561b879ebe6bfee5d4db6d84e112aa0b97f8395e1cbf4bc3be41c3cfd9a60fe"),
    "src/mxc-sdk/src/lib.rs": ("4f9c1e49c52ffad33864fee9e83a22dfa30b26034386024fdf930534e46556b4"),
    "src/mxc-sdk/src/literal_argv.rs": ("3e5884c316403be2ad82052492f1d3fd9dbd7ea2500ccbb7c716a64a29602cd5"),
    "src/mxc-sdk/src/policy.rs": ("43680b63e9e7d4c9351cee1936e791be1b4b877cfcee368b07429e22c355de9c"),
    "src/mxc-sdk/src/policy/exact/mod.rs": ("da9ad3bd8cf1be1af225aa95c887718d67ce7efbb8270d2e7d578bab9dc87bb7"),
}


CONTROL_OVERLAY_FILES = dict(BOUNDARY_OVERLAY_FILES)
CONTROL_OVERLAY_FILES.update(
    {
        "src/mxc-sdk/src/backends/process_container/common/base_container_runner.rs": (
            "1c50a9b3f32d6eb68e3519f1dd4bc128a2c7b2e33a583f37b97e9aacc41af0b8"
        ),
        CONTROL_PATH: "3f6bb0972c5ddaa46eab77e8e28aea94f9310ecf168c13791ed9100cf4b551eb",
    }
)


def artifact_contract(mode: str = "loader-only") -> dict:
    if mode not in {
        "loader-only",
        "standalone-boundary",
        "dll-startup-only",
        "claude-version-only",
        "claude-create-control-only",
    }:
        raise ValueError("unknown fixed artifact mode")
    boundary = mode != "loader-only"
    dll = mode == "dll-startup-only"
    control = mode == "claude-create-control-only"
    claude = mode in {"claude-version-only", "claude-create-control-only"}
    sources = {name: SOURCE_PREFIX + name for name in SOURCE_FILES}
    binaries = (BINARY, LOADER_BINARY)
    files = set(FILES)
    extra = {"PROVENANCE.json", "WORKFLOW.json"}
    if boundary:
        for name in (
            "src/boundary_child.rs",
            "src/native_environment.rs",
            "src/native_identity.rs",
            "src/private_native_record.rs",
            "src/dll_startup_child.rs",
            "src/dll_startup_protocol.rs",
            "patches/mxc-windows-literal-argv.patch",
            "patches/mxc-windows-process-identity.patch",
        ):
            sources[name] = SOURCE_PREFIX + name
        sources["patches/mxc-literal-argv.patch"] = "test/e2e/axis/patches/mxc-literal-argv.patch"
        binaries += (BOUNDARY_BINARY,)
        files |= {"source/" + name for name in sources} | {BOUNDARY_BINARY}
        extra.add("SDK-ADMISSION-TESTS.json")
    if dll or claude:
        for name in ("src/dll_startup_child.rs", "src/dll_startup_protocol.rs"):
            sources[name] = SOURCE_PREFIX + name
        binaries += (DLL_BINARY,)
        files |= {"source/" + name for name in sources} | {DLL_BINARY}
    if control:
        name = "patches/mxc-fixed-claude-create-control.patch"
        sources[name] = SOURCE_PREFIX + name
        files.add("source/" + name)
    return {
        "variant": CONTROL_VARIANT
        if control
        else CLAUDE_VARIANT
        if claude
        else DLL_VARIANT
        if dll
        else BOUNDARY_VARIANT
        if boundary
        else VARIANT,
        "scope": CONTROL_SCOPE
        if control
        else CLAUDE_SCOPE
        if claude
        else DLL_SCOPE
        if dll
        else BOUNDARY_SCOPE
        if boundary
        else SCOPE,
        "sources": sources,
        "binaries": binaries,
        "files": files,
        "all_files": files | extra,
        "modified": (BOUNDARY_MODIFIED_PATHS | {CONTROL_PATH})
        if control
        else BOUNDARY_MODIFIED_PATHS
        if boundary
        else PATCHED_PATHS,
    }


MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_ARCHIVE_BYTES = 96 * 1024 * 1024


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest_argument(value: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{64}", value):
        raise argparse.ArgumentTypeError("expected a lowercase SHA256 digest")
    return value


def commit_argument(value: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{40}", value):
        raise argparse.ArgumentTypeError("expected an exact lowercase Git commit")
    return value


def ordinary_file(path: Path, bound: int = MAX_FILE_BYTES) -> bytes:
    for component in [path, *path.parents]:
        metadata = component.lstat()
        require(not stat.S_ISLNK(metadata.st_mode), "symlink path refused")
        require(not getattr(metadata, "st_file_attributes", 0) & 0x400, "reparse-point path refused")
    metadata = path.stat()
    require(stat.S_ISREG(metadata.st_mode) and metadata.st_size <= bound, "file type or size differs")
    with path.open("rb") as source:
        data = source.read(bound + 1)
    require(len(data) <= bound, "file grew beyond its read bound")
    return data


def payload_file(root: Path, name: str, allowed: set[str] = ALL_FILES) -> bytes:
    require(name in allowed, "path outside the exact artifact inventory")
    return ordinary_file(root.joinpath(*PurePosixPath(name).parts))


def exact_inventory(root: Path, allowed: set[str] = ALL_FILES) -> set[str]:
    directories = {str(parent) for name in allowed for parent in PurePosixPath(name).parents if str(parent) != "."}
    pending = [root]
    files = set()
    entries = 0
    while pending:
        for path in pending.pop().iterdir():
            entries += 1
            require(entries <= 64, "too many extracted artifact entries")
            metadata = path.lstat()
            require(
                not stat.S_ISLNK(metadata.st_mode) and not getattr(metadata, "st_file_attributes", 0) & 0x400,
                "artifact reparse point refused",
            )
            name = path.relative_to(root).as_posix()
            if stat.S_ISDIR(metadata.st_mode):
                require(name in directories, "unreviewed artifact directory")
                pending.append(path)
            else:
                require(name in allowed and stat.S_ISREG(metadata.st_mode), "unreviewed artifact entry")
                files.add(name)
    return files


def git_blob(checkout: Path, commit: str, relative: str) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(checkout), "show", commit + ":" + relative],
        check=True,
        shell=False,
        capture_output=True,
        timeout=20,
    )
    require(len(result.stdout) <= MAX_FILE_BYTES, "reviewed Git object exceeds its bound")
    return result.stdout


def github_json(endpoint: str) -> dict:
    result = subprocess.run(
        ["gh", "api", "repos/" + REPOSITORY + "/actions/" + endpoint],
        check=True,
        shell=False,
        capture_output=True,
        timeout=30,
    )
    require(len(result.stdout) <= 2 * 1024 * 1024, "GitHub response exceeds its bound")
    value = json.loads(result.stdout)
    require(isinstance(value, dict), "GitHub metadata must be an object")
    return value


def verify_github(
    artifact_id: int, run_id: int, build_commit: str, archive_sha256: str, mode: str = "loader-only"
) -> None:
    artifact = github_json(f"artifacts/{artifact_id}")
    run = github_json(f"runs/{run_id}")
    require(
        artifact.get("id") == artifact_id
        and artifact.get("name") == "axis-mxc-v1-windows-contributor-" + build_commit
        and artifact.get("expired") is False
        and artifact.get("digest") == "sha256:" + archive_sha256
        and artifact.get("workflow_run", {}).get("id") == run_id
        and artifact.get("workflow_run", {}).get("head_sha") == build_commit,
        "GitHub artifact identity, source or digest differs",
    )
    require(
        run.get("id") == run_id
        and run.get("head_sha") == build_commit
        and run.get("path") == WORKFLOW
        and (
            run.get("head_branch") == "codex/axis-sandbox-feasibility"
            or (
                mode in {"standalone-boundary", "dll-startup-only", "claude-version-only", "claude-create-control-only"}
                and run.get("event") == "workflow_dispatch"
                and run.get("head_branch") in {"codex/axis-native-build", "codex/axis-peer-experiments"}
            )
        )
        and run.get("repository", {}).get("full_name") == REPOSITORY
        and run.get("head_repository", {}).get("full_name") == REPOSITORY
        and run.get("event") in {"push", "workflow_dispatch"}
        and run.get("status") == "completed"
        and run.get("conclusion") == "success",
        "the exact native Windows build workflow did not succeed",
    )


def verify_archive(archive: Path, artifact: Path, archive_sha256: str, allowed: set[str] = ALL_FILES) -> None:
    require(sha256(ordinary_file(archive, MAX_ARCHIVE_BYTES)) == archive_sha256, "outer archive digest differs")
    expected = {"build-artifact/" + name for name in allowed} | {"Cargo.lock"}
    with zipfile.ZipFile(archive) as bundle:
        members = bundle.infolist()
        require(len(members) <= 64, "too many ZIP entries")
        names = set()
        folded = set()
        total = 0
        for member in members:
            name = member.filename
            require(name not in names and name.casefold() not in folded, "duplicate ZIP path")
            names.add(name)
            folded.add(name.casefold())
            require(not member.is_dir() and name in expected, "unreviewed ZIP entry")
            require((member.external_attr >> 16) & 0o170000 != 0o120000, "ZIP symlink refused")
            require(member.file_size <= MAX_FILE_BYTES, "oversized ZIP entry")
            total += member.file_size
            require(total <= MAX_ARCHIVE_BYTES, "oversized ZIP payload")
            relative = name.removeprefix("build-artifact/") if name != "Cargo.lock" else "source/Cargo.lock"
            require(
                bundle.read(member) == payload_file(artifact, relative, allowed), "ZIP and extracted artifact differ"
            )
        require(names == expected, "ZIP inventory differs")


def verify(
    artifact: Path,
    archive: Path,
    checkout: Path,
    axis: Path,
    mxc: Path,
    archive_sha256: str,
    provenance_sha256: str,
    build_commit: str,
    run_id: int,
    artifact_id: int,
    mode: str = "loader-only",
) -> dict:
    contract = artifact_contract(mode)

    def read(name: str) -> bytes:
        return payload_file(artifact, name, contract["all_files"])

    require(artifact.is_absolute() and artifact.is_dir(), "absolute extracted artifact directory required")
    provenance_raw = read("PROVENANCE.json")
    require(sha256(provenance_raw) == provenance_sha256, "external provenance pin differs")
    provenance = json.loads(provenance_raw)
    require(isinstance(provenance, dict), "provenance must be an object")
    required = {
        "schema": "defenseclaw-contributor-axis-windows-psec-v1",
        "variant": contract["variant"],
        "axis_commit": AXIS_COMMIT,
        "mxc_commit": MXC_COMMIT,
        "combined_lock_sha256": COMBINED_LOCK_SHA256,
        "build_mode": "build-locked",
        "probe_executed": False,
        "human_lock_review_required_before_live_execution": True,
        "locked_rebuild": True,
        "scope": contract["scope"],
        "production_certification": False,
        "mxc_patched_paths": sorted(contract["modified"]),
    }
    for key, expected in required.items():
        require(
            type(provenance.get(key)) is type(expected) and provenance[key] == expected,
            "build contract differs: " + key,
        )
    inventory = provenance.get("files")
    require(isinstance(inventory, dict) and set(inventory) == contract["files"], "provenance inventory differs")
    actual = exact_inventory(artifact, contract["all_files"])
    require(actual == contract["all_files"], "extracted artifact has missing or additional files")
    for name, expected in inventory.items():
        require(
            isinstance(expected, str) and re.fullmatch(r"[0-9a-f]{64}", expected) is not None, "invalid file digest"
        )
        require(sha256(read(name)) == expected, "artifact file changed: " + name)
    for name, source_path in contract["sources"].items():
        require(
            read("source/" + name) == git_blob(checkout, build_commit, source_path),
            "source Git blob differs: " + name,
        )
    require(sha256(read("source/Cargo.lock")) == COMBINED_LOCK_SHA256, "reviewed combined lock differs")
    upstream_hashes = {}
    for name, source, commit, lock, license_name in [
        ("axis", axis, AXIS_COMMIT, "Cargo.lock", "LICENSE"),
        ("mxc", mxc, MXC_COMMIT, "src/Cargo.lock", "LICENSE.md"),
    ]:
        for packaged, git_path in [(f"upstream/{name}-Cargo.lock", lock), (f"upstream/{name}-LICENSE", license_name)]:
            raw = read(packaged)
            git_bytes = git_blob(source, commit, git_path)
            require(
                raw == git_bytes or raw.replace(b"\r\n", b"\n") == git_bytes, "upstream Git bytes differ: " + packaged
            )
            if git_path == lock:
                upstream_hashes[name] = sha256(raw)
    require(provenance.get("upstream_lock_sha256") == upstream_hashes, "raw upstream lock digests differ")
    require(
        sha256(read("source/patches/mxc-strict-windows-psec.patch")) == provenance.get("mxc_patch_sha256"),
        "reviewed SDK overlay differs",
    )
    if mode in {"standalone-boundary", "dll-startup-only", "claude-version-only", "claude-create-control-only"}:
        require(
            provenance.get("pure_native_environment_tests_passed") is True
            and provenance.get("pure_native_environment_tests") == pure_environment_tests(mode),
            "fixed pure native environment test evidence differs",
        )
        require(upstream_hashes["mxc"] == SDK_LOCK_SHA256, "SDK admission upstream lock differs")
        require(provenance.get("mxc_added_paths") == sorted(BOUNDARY_ADDED_PATHS), "added SDK paths differ")
        require(
            provenance.get("native_directory_custody_tests_passed") is True
            and provenance.get("native_directory_custody_tests") == native_directory_custody_tests(mode),
            "native directory custody test evidence differs",
        )
        fingerprints = provenance.get("mxc_overlay_file_sha256")
        require(
            isinstance(fingerprints, dict) and set(fingerprints) == contract["modified"] | BOUNDARY_ADDED_PATHS,
            "SDK source fingerprint inventory differs",
        )
        require(
            fingerprints == (CONTROL_OVERLAY_FILES if mode == "claude-create-control-only" else BOUNDARY_OVERLAY_FILES),
            "SDK source fingerprint digest differs",
        )
        require(
            sha256(read("source/patches/mxc-literal-argv.patch"))
            == LITERAL_OVERLAY_SHA256
            == provenance.get("mxc_literal_argv_patch_sha256"),
            "shared literal overlay differs",
        )
        require(
            provenance.get("mxc_literal_argv_patch_source") == "test/e2e/axis/patches/mxc-literal-argv.patch",
            "shared overlay source differs",
        )
        require(
            sha256(read("source/patches/mxc-windows-literal-argv.patch"))
            == BOUNDARY_OVERLAY_SHA256
            == provenance.get("mxc_windows_argv_patch_sha256"),
            "Windows literal overlay differs",
        )
        require(
            sha256(read("source/patches/mxc-windows-process-identity.patch"))
            == IDENTITY_OVERLAY_SHA256
            == provenance.get("mxc_windows_process_identity_patch_sha256"),
            "Windows native identity overlay differs",
        )
        admission = json.loads(read("SDK-ADMISSION-TESTS.json"))
        require(
            isinstance(admission, dict)
            and type(admission.get("passed")) is int
            and type(admission.get("native_file_fixture_tests")) is int
            and type(admission.get("native_image_mapping_query_tests")) is int
            and admission.get("sandbox_or_payload_execution") is False
            and admission
            == {
                "tests": SDK_TESTS + ([CONTROL_SDK_TEST] if mode == "claude-create-control-only" else []),
                "passed": len(SDK_TESTS) + int(mode == "claude-create-control-only"),
                "sandbox_or_payload_execution": False,
                "native_file_fixture_tests": 2,
                "native_image_mapping_query_tests": 1,
                "upstream_lock_sha256": SDK_LOCK_SHA256,
            },
            "exact SDK admission test evidence differs",
        )
    if mode in {"standalone-boundary", "claude-version-only", "claude-create-control-only"}:
        require(provenance.get("probe_slice") == mode, "fixed Claude build slice differs")
    if mode in {"standalone-boundary", "dll-startup-only", "claude-version-only", "claude-create-control-only"}:
        require(
            provenance.get("pure_dll_startup_tests_passed") is True
            and provenance.get("pure_dll_startup_tests") == PURE_DLL_TESTS,
            "fixed pure DLL startup test evidence differs",
        )
    if mode == "claude-create-control-only":
        require(
            sha256(read("source/patches/mxc-fixed-claude-create-control.patch"))
            == CONTROL_OVERLAY_SHA256
            == provenance.get("mxc_fixed_create_control_patch_sha256")
            and provenance.get("psec_attribute_attached_to_payload") is False
            and provenance.get("control_reference_plan_executed") is False
            and provenance.get("probe_cargo_features") == ["fixed-claude-create-control"],
            "separate fixed uncontained control overlay evidence differs",
        )
    else:
        require(
            "mxc_fixed_create_control_patch_sha256" not in provenance,
            "ordinary PSEC artifact cannot contain the uncontained control overlay",
        )
    toolchain = read("TOOLCHAIN.txt")
    require(
        toolchain.startswith(b"rustc 1.95.0 ")
        and b"host: x86_64-pc-windows-msvc" in toolchain
        and b"cargo 1.95.0 " in toolchain,
        "compiler identity differs",
    )
    binaries = []
    for relative in contract["binaries"]:
        binary = read(relative)
        require(len(binary) >= 64 and binary[:2] == b"MZ", "native PE image required")
        pe = struct.unpack_from("<I", binary, 60)[0]
        require(
            pe + 26 <= len(binary)
            and binary[pe : pe + 4] == b"PE\0\0"
            and struct.unpack_from("<H", binary, pe + 4)[0] == 0x8664
            and struct.unpack_from("<H", binary, pe + 24)[0] == 0x20B,
            "native x64 PE image required",
        )
        binaries.append({"path": relative, "sha256": inventory[relative], "size": len(binary)})
    workflow = json.loads(read("WORKFLOW.json"))
    require(
        isinstance(workflow, dict)
        and workflow.get("repository") == REPOSITORY
        and workflow.get("workflow_commit") == build_commit
        and workflow.get("run_id") == str(run_id)
        and workflow.get("execution_performed") is False,
        "workflow attribution differs",
    )
    verify_archive(archive, artifact, archive_sha256, contract["all_files"])
    verify_github(artifact_id, run_id, build_commit, archive_sha256, mode)
    return {
        **({"probe_cargo_features": ["fixed-claude-create-control"]} if mode == "claude-create-control-only" else {}),
        "verified": True,
        "execution_performed": False,
        "scope": required["scope"],
        "variant": contract["variant"],
        "axis_commit": AXIS_COMMIT,
        "mxc_commit": MXC_COMMIT,
        "build_commit": build_commit,
        "build_run": run_id,
        "artifact_id": artifact_id,
        "archive_sha256": archive_sha256,
        "provenance_sha256": provenance_sha256,
        "combined_lock_sha256": COMBINED_LOCK_SHA256,
        "artifact": str(artifact),
        "binary": BINARY,
        "binary_sha256": inventory[BINARY],
        "binary_size": binaries[0]["size"],
        "binaries": binaries,
        "production_certification": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("artifact", "archive", "source-checkout", "axis-source", "mxc-source", "receipt"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("archive-sha256", "provenance-sha256"):
        parser.add_argument("--" + name, type=digest_argument, required=True)
    parser.add_argument("--build-commit", type=commit_argument, required=True)
    parser.add_argument("--build-run", type=int, required=True)
    parser.add_argument("--artifact-id", type=int, required=True)
    parser.add_argument(
        "--variant",
        choices=(
            "loader-only",
            "standalone-boundary",
            "dll-startup-only",
            "claude-version-only",
            "claude-create-control-only",
        ),
        default="loader-only",
    )
    args = parser.parse_args()
    require(args.build_run > 0 and args.artifact_id > 0, "positive exact GitHub IDs required")
    result = verify(
        args.artifact,
        args.archive,
        args.source_checkout,
        args.axis_source,
        args.mxc_source,
        args.archive_sha256,
        args.provenance_sha256,
        args.build_commit,
        args.build_run,
        args.artifact_id,
        args.variant,
    )
    with args.receipt.open("x", encoding="utf-8") as output:
        output.write(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))


if __name__ == "__main__":
    main()
