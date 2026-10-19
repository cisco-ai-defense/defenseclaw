#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Build-only contributor artifact preparation. Never runs the probe binary."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import stat
import subprocess
import sys
from pathlib import Path

AXIS_COMMIT = "fb5fd5f0f9377c2ccb30d7e027a36373de0d037c"
MXC_COMMIT = "fda29ac63bc306b7f97f3b86b4b63d44f7f40cf2"
TOOLCHAIN = "1.95.0"
BINARY = "defenseclaw-axis-windows-psec-probe.exe"
LOADER_BINARY = "defenseclaw-axis-windows-psec-loader-child.exe"
BOUNDARY_BINARY = "defenseclaw-axis-windows-psec-boundary-child.exe"
DLL_BINARY = "defenseclaw-axis-windows-psec-dll-child.exe"
PROBE_SLICE_CONTRACTS = {
    "standalone-boundary": (
        "standalone_std_boundary_native_identity_environment",
        "fixed_windows_native_psec_boundary_native_identity_environment",
    ),
    "claude-create-control-only": (
        "standalone_std_fixed_signed_claude_create_control",
        "fixed_windows_uncontained_claude_create_control",
    ),
    "dll-startup-only": (
        "standalone_std_fixed_dll_startup_diagnostic",
        "fixed_windows_native_psec_dll_startup_diagnostic",
    ),
    "claude-version-only": (
        "standalone_std_fixed_signed_claude_version",
        "fixed_windows_native_psec_signed_claude_version",
    ),
}
ROOT = Path(__file__).resolve().parent
PATCH = ROOT / "patches" / "mxc-strict-windows-psec.patch"
LITERAL_PATCH = ROOT / "patches" / "mxc-literal-argv.patch"
WINDOWS_ARGV_PATCH = ROOT / "patches" / "mxc-windows-literal-argv.patch"
IDENTITY_PATCH = ROOT / "patches" / "mxc-windows-process-identity.patch"
CONTROL_PATCH = ROOT / "patches" / "mxc-fixed-claude-create-control.patch"
CONTROL_PATCH_SHA256 = "1c68169aeac3a777b9fb553e7697a61af8ef38381442d45f293bd6ab35cd76f2"
CONTROL_PATH = "src/mxc-sdk/src/backends/process_container/common/secenv.rs"
CONTROL_PATCH_PATHS = {CONTROL_PATH, "src/mxc-sdk/src/backends/process_container/common/base_container_runner.rs"}
LITERAL_PATCH_SOURCE = "test/e2e/axis/patches/mxc-literal-argv.patch"
LITERAL_PATCH_SHA256 = "7117afc3c7ae28345757c364518b7b9120a7dd8e6b844403b06fe05403e4a76d"
WINDOWS_ARGV_PATCH_PATHS = {
    "src/mxc-sdk/src/lib.rs",
    "src/mxc-sdk/src/core/mxc_engine/mod.rs",
    "src/mxc-sdk/src/core/mxc_engine/dispatch.rs",
    "src/mxc-sdk/src/backends/process_container/common/base_container_runner.rs",
}
IDENTITY_PATCH_PATHS = {
    "src/mxc-sdk/src/sandbox.rs",
    "src/mxc-sdk/src/core/mxc_common/sandbox_process.rs",
    "src/mxc-sdk/src/core/mxc_engine/mod.rs",
    "src/mxc-sdk/src/backends/process_container/common/base_container_runner.rs",
}
PATCHED_PATHS = {
    "src/mxc-sdk/src/lib.rs",
    "src/mxc-sdk/src/core/mxc_engine/mod.rs",
    "src/mxc-sdk/src/core/mxc_engine/dispatch.rs",
    "src/mxc-sdk/src/backends/process_container/common/base_container_runner.rs",
    "src/mxc-sdk/src/backends/bubblewrap/common/bwrap_command.rs",
    "src/mxc-sdk/src/backends/bubblewrap/common/bwrap_runner.rs",
    "src/mxc-sdk/src/backends/seatbelt/common/seatbelt_runner.rs",
    "src/mxc-sdk/src/core/mxc_common/mod.rs",
    "src/mxc-sdk/src/core/mxc_common/sandbox_process.rs",
    "src/mxc-sdk/src/core/mxc_common/validator.rs",
    "src/mxc-sdk/src/policy.rs",
    "src/mxc-sdk/src/policy/exact/mod.rs",
    "src/mxc-sdk/src/sandbox.rs",
}
ADDED_PATHS = {
    "src/mxc-sdk/src/core/mxc_common/literal_argv.rs",
    "src/mxc-sdk/src/core/mxc_engine/literal_argv.rs",
    "src/mxc-sdk/src/literal_argv.rs",
}


NATIVE_DIRECTORY_CUSTODY_TESTS = {
    "defenseclaw-axis-windows-psec-probe": [
        "probe::native_identity::tests::directory_custody_blocks_rename_until_handles_close_without_spawning",
    ],
}


def native_directory_custody_tests(probe_slice: str) -> dict[str, list[str]]:
    if probe_slice not in PROBE_SLICE_CONTRACTS:
        raise ValueError("unknown fixed contributor slice")
    tests = {binary: list(names) for binary, names in NATIVE_DIRECTORY_CUSTODY_TESTS.items()}
    if probe_slice == "standalone-boundary":
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

PURE_STARTUP_ENVIRONMENT_TESTS = {
    "defenseclaw-axis-windows-psec-probe": [
        "probe::native_identity::tests::directory_open_refusal_contains_only_closed_gate_index_and_numeric_status",
        "probe::native_environment::tests::startup_environment_requires_exact_eight_private_values",
        "probe::native_environment::tests::startup_environment_snapshot_refuses_drift_and_canary_misuse",
        "probe::native_environment::tests::native_profile_refusal_classifier_reports_bounded_relationships",
        "probe::native_identity::private_native_record::tests::fixed_private_record_is_lossless_bounded_complete_and_not_authority",
    ],
}


def pure_environment_tests(probe_slice: str) -> dict[str, list[str]]:
    if probe_slice not in PROBE_SLICE_CONTRACTS:
        raise ValueError("unknown fixed contributor slice")
    tests = {binary: list(names) for binary, names in PURE_ENVIRONMENT_TESTS.items()}
    if probe_slice == "standalone-boundary":
        for binary, names in PURE_STARTUP_ENVIRONMENT_TESTS.items():
            tests[binary].extend(names)
    return tests


def artifact_binaries(probe_slice: str) -> tuple[str, ...]:
    if probe_slice not in PROBE_SLICE_CONTRACTS:
        raise ValueError("unknown fixed contributor slice")
    binaries = (BINARY, LOADER_BINARY, BOUNDARY_BINARY)
    return binaries if probe_slice == "standalone-boundary" else binaries + (DLL_BINARY,)


def command(argv: list[str], *, cwd: Path = ROOT, capture: bool = False) -> str:
    # Build tooling is already provisioned by the disposable CI job. Do not
    # forward tokens, loader overrides or caller Rust flags to build scripts.
    environment = {
        key: os.environ[key]
        for key in (
            "PATH",
            "HOME",
            "USERPROFILE",
            "SYSTEMROOT",
            "SystemRoot",
            "WINDIR",
            "TEMP",
            "TMP",
            "APPDATA",
            "LOCALAPPDATA",
            "CARGO_HOME",
            "RUSTUP_HOME",
            "SSL_CERT_FILE",
            "CARGO_HTTP_CAINFO",
            "INCLUDE",
            "LIB",
            "LIBPATH",
            "VCINSTALLDIR",
            "VCToolsInstallDir",
            "WindowsSdkDir",
            "WindowsSDKVersion",
        )
        if key in os.environ
    }
    environment.update(CARGO_TERM_COLOR="never", CARGO_INCREMENTAL="0", CARGO_BUILD_JOBS="2")
    result = subprocess.run(
        argv,
        cwd=cwd,
        env=environment,
        check=True,
        shell=False,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        timeout=2400,
    )
    return result.stdout.strip() if capture else ""


def verify_source(directory: str, expected: str) -> Path:
    source = ROOT / directory
    if source.is_symlink() or not source.is_dir():
        raise RuntimeError(f"provision a fresh exact-commit checkout at {directory}")
    if command(["git", "rev-parse", "HEAD"], cwd=source, capture=True) != expected:
        raise RuntimeError(f"{directory} is not at the reviewed commit")
    if command(["git", "status", "--porcelain", "--untracked-files=all"], cwd=source, capture=True):
        raise RuntimeError(f"{directory} must be clean before the reviewed overlay is applied")
    return source


def verify_build_sources(axis: Path, mxc: Path, *, control: bool = False) -> None:
    """Reject source drift, index writes and new files around the build."""
    for source, expected in ((axis, AXIS_COMMIT), (mxc, MXC_COMMIT)):
        if command(["git", "rev-parse", "HEAD"], cwd=source, capture=True) != expected:
            raise RuntimeError("an upstream source commit changed during the build")
        status = command(["git", "status", "--porcelain", "--untracked-files=all"], cwd=source, capture=True)
        # command() strips surrounding whitespace; strip each expected status
        # line too, without accepting staged, added or untracked content.
        actual = {line.strip() for line in status.splitlines()}
        expected_status = (
            {f"M {path}" for path in (PATCHED_PATHS | ({CONTROL_PATH} if control else set()))}
            | {f"?? {path}" for path in ADDED_PATHS}
            if source == mxc
            else set()
        )
        if actual != expected_status:
            raise RuntimeError("upstream source changes differ from the reviewed MXC overlay paths")
        staged = command(["git", "diff", "--cached", "--name-only"], cwd=source, capture=True)
        if staged:
            raise RuntimeError("upstream source staging is not permitted")


def digest(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            result.update(chunk)
    return result.hexdigest()


def overlay_fingerprints(mxc: Path, *, control: bool = False) -> dict[str, str]:
    """Include newly added files: Git's unstaged diff does not contain them."""
    result = {}
    for relative in sorted(PATCHED_PATHS | ADDED_PATHS | ({CONTROL_PATH} if control else set())):
        path = mxc / relative
        metadata = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or getattr(metadata, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
            or metadata.st_size > 2 * 1024 * 1024
        ):
            raise RuntimeError("reviewed MXC overlay target must be a bounded regular file")
        result[relative] = digest(path)
    return result


def verify_windows_patch_paths(mxc: Path) -> None:
    rows = command(["git", "apply", "--numstat", str(WINDOWS_ARGV_PATCH)], cwd=mxc, capture=True).splitlines()
    fields = [row.split("\t") for row in rows]
    if (
        len(fields) != len(WINDOWS_ARGV_PATCH_PATHS)
        or any(len(row) != 3 or not row[0].isdigit() or not row[1].isdigit() for row in fields)
        or {row[2] for row in fields} != WINDOWS_ARGV_PATCH_PATHS
    ):
        raise RuntimeError("Windows argv overlay must touch exactly its four reviewed source paths")


def verify_identity_patch_paths(mxc: Path) -> None:
    rows = command(["git", "apply", "--numstat", str(IDENTITY_PATCH)], cwd=mxc, capture=True).splitlines()
    fields = [row.split("\t") for row in rows]
    if (
        len(fields) != len(IDENTITY_PATCH_PATHS)
        or any(len(row) != 3 or not row[0].isdigit() or not row[1].isdigit() for row in fields)
        or {row[2] for row in fields} != IDENTITY_PATCH_PATHS
    ):
        raise RuntimeError("Windows identity overlay must touch exactly its four reviewed source paths")


def verify_control_patch_paths(mxc: Path) -> None:
    if digest(CONTROL_PATCH) != CONTROL_PATCH_SHA256:
        raise RuntimeError("fixed uncontained control overlay differs")
    rows = command(["git", "apply", "--numstat", str(CONTROL_PATCH)], cwd=mxc, capture=True).splitlines()
    fields = [row.split("\t") for row in rows]
    if (
        len(fields) != 2
        or any(len(row) != 3 or not row[0].isdigit() or not row[1].isdigit() for row in fields)
        or {row[2] for row in fields} != CONTROL_PATCH_PATHS
    ):
        raise RuntimeError("fixed control overlay must touch exactly its two reviewed source paths")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("generate-lock", "build-locked"))
    parser.add_argument("--probe-slice", choices=tuple(PROBE_SLICE_CONTRACTS), default="dll-startup-only")
    args = parser.parse_args()
    variant, scope = PROBE_SLICE_CONTRACTS[args.probe_slice]
    control = args.probe_slice == "claude-create-control-only"
    feature_args = ["--features", "fixed-claude-create-control"] if control else []
    if sys.platform != "win32" or platform.machine().lower() not in {"amd64", "x86_64"}:
        raise RuntimeError("build this contributor artifact on native Windows x86_64")
    artifact = ROOT / "build-artifact"
    if artifact.exists() or artifact.is_symlink():
        raise RuntimeError("build-artifact already exists; use a fresh contributor staging directory")
    lock = ROOT / "Cargo.lock"
    if args.mode == "generate-lock" and (lock.exists() or lock.is_symlink()):
        raise RuntimeError("generate-lock requires a fresh staging directory without Cargo.lock")
    if args.mode == "build-locked" and (lock.is_symlink() or not lock.is_file()):
        raise RuntimeError("build-locked requires the reviewed combined Cargo.lock")
    axis = verify_source("axis-source", AXIS_COMMIT)
    mxc = verify_source("mxc-source", MXC_COMMIT)
    toolchain = command(["rustc", f"+{TOOLCHAIN}", "-Vv"], capture=True)
    cargo_version = command(["cargo", f"+{TOOLCHAIN}", "--version"], capture=True)
    if not toolchain.startswith(f"rustc {TOOLCHAIN} "):
        raise RuntimeError("the already-installed Rust toolchain differs from the reviewed version")
    upstream_locks = {"axis": digest(axis / "Cargo.lock"), "mxc": digest(mxc / "src" / "Cargo.lock")}
    if not LITERAL_PATCH.is_file() or digest(LITERAL_PATCH) != LITERAL_PATCH_SHA256:
        raise RuntimeError("stage the exact reviewed shared literal-argv patch from Git before building")
    verify_windows_patch_paths(mxc)
    verify_identity_patch_paths(mxc)
    for patch in (PATCH, LITERAL_PATCH, WINDOWS_ARGV_PATCH, IDENTITY_PATCH):
        command(["git", "apply", "--check", str(patch)], cwd=mxc)
        command(["git", "apply", str(patch)], cwd=mxc)
    if control:
        verify_control_patch_paths(mxc)
        command(["git", "apply", "--check", str(CONTROL_PATCH)], cwd=mxc)
        command(["git", "apply", str(CONTROL_PATCH)], cwd=mxc)
    verify_build_sources(axis, mxc, control=control)
    overlay_before = overlay_fingerprints(mxc, control=control)
    if args.mode == "generate-lock":
        command(["cargo", f"+{TOOLCHAIN}", "generate-lockfile"])
    lock_before = digest(lock)
    command(["cargo", f"+{TOOLCHAIN}", "build", "--locked", "--release", *feature_args])
    # Compile the probe's test target without executing any newly built code.
    command(["cargo", f"+{TOOLCHAIN}", "test", "--locked", "--release", *feature_args, "--no-run"])
    # Run only these exact pure parser/spelling/buffer tests. They perform no
    # filesystem query, environment lookup, process creation or PSEC operation.
    pure_tests = pure_environment_tests(args.probe_slice)
    for binary, names in [*pure_tests.items(), *PURE_DLL_TESTS.items()]:
        for name in names:
            output = command(
                [
                    "cargo",
                    f"+{TOOLCHAIN}",
                    "test",
                    "--locked",
                    "--release",
                    *feature_args,
                    "--bin",
                    binary,
                    name,
                    "--",
                    "--exact",
                ],
                capture=True,
            )
            print(output)
            if (
                output.splitlines().count(f"test {name} ... ok") != 1
                or "test result: ok. 1 passed; 0 failed; 0 ignored;" not in output
            ):
                raise RuntimeError("fixed pure contributor test did not pass exactly once")
    # Separate synthetic filesystem gates create no child/profile/PSEC. The
    # boundary-only private-file gate reads current TokenUser for its new DACL.
    native_tests = native_directory_custody_tests(args.probe_slice)
    for binary, names in native_tests.items():
        for name in names:
            output = command(
                [
                    "cargo",
                    f"+{TOOLCHAIN}",
                    "test",
                    "--locked",
                    "--release",
                    *feature_args,
                    "--bin",
                    binary,
                    name,
                    "--",
                    "--exact",
                ],
                capture=True,
            )
            print(output)
            if (
                output.splitlines().count(f"test {name} ... ok") != 1
                or "test result: ok. 1 passed; 0 failed; 0 ignored;" not in output
            ):
                raise RuntimeError("fixed native directory custody test did not pass exactly once")
    if digest(lock) != lock_before:
        raise RuntimeError("the combined dependency lock changed during the locked build")
    if upstream_locks != {"axis": digest(axis / "Cargo.lock"), "mxc": digest(mxc / "src" / "Cargo.lock")}:
        raise RuntimeError("an upstream lock changed during the build")
    verify_build_sources(axis, mxc, control=control)
    if overlay_fingerprints(mxc, control=control) != overlay_before:
        raise RuntimeError("reviewed MXC overlay bytes changed during the build")

    (artifact / "bin").mkdir(parents=True)
    files = [
        Path("Cargo.toml"),
        Path("Cargo.lock"),
        Path("prepare_build.py"),
        Path("test_prepare_build.py"),
        Path("README.md"),
        Path("src/main.rs"),
        Path("src/probe.rs"),
        Path("src/loader_child.rs"),
        Path("src/boundary_child.rs"),
        Path("src/native_environment.rs"),
        Path("src/native_identity.rs"),
        Path("src/private_native_record.rs"),
        Path("src/dll_startup_child.rs"),
        Path("src/dll_startup_protocol.rs"),
        Path("patches/mxc-strict-windows-psec.patch"),
        Path("patches/mxc-literal-argv.patch"),
        Path("patches/mxc-windows-literal-argv.patch"),
        Path("patches/mxc-windows-process-identity.patch"),
    ]
    if control:
        files.append(Path("patches/mxc-fixed-claude-create-control.patch"))
    for relative in files:
        target = artifact / "source" / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, target)
    for binary in artifact_binaries(args.probe_slice):
        shutil.copyfile(ROOT / "target" / "release" / binary, artifact / "bin" / binary)
        (artifact / "bin" / binary).chmod(0o755)
    (artifact / "upstream").mkdir()
    for name, source, lock_path, license_name in [
        ("axis", axis, axis / "Cargo.lock", "LICENSE"),
        ("mxc", mxc, mxc / "src" / "Cargo.lock", "LICENSE.md"),
    ]:
        shutil.copyfile(lock_path, artifact / "upstream" / f"{name}-Cargo.lock")
        shutil.copyfile(source / license_name, artifact / "upstream" / f"{name}-LICENSE")
    (artifact / "TOOLCHAIN.txt").write_text(toolchain + "\n" + cargo_version + "\n", encoding="utf-8")
    provenance = {
        "schema": "defenseclaw-contributor-axis-windows-psec-v1",
        "variant": variant,
        "probe_slice": args.probe_slice,
        "axis_commit": AXIS_COMMIT,
        "mxc_commit": MXC_COMMIT,
        "mxc_patch_sha256": digest(PATCH),
        "mxc_literal_argv_patch_sha256": digest(LITERAL_PATCH),
        "mxc_literal_argv_patch_source": LITERAL_PATCH_SOURCE,
        "mxc_windows_argv_patch_sha256": digest(WINDOWS_ARGV_PATCH),
        "mxc_windows_process_identity_patch_sha256": digest(IDENTITY_PATCH),
        "mxc_patched_paths": sorted(PATCHED_PATHS | ({CONTROL_PATH} if control else set())),
        "mxc_added_paths": sorted(ADDED_PATHS),
        "mxc_overlay_file_sha256": overlay_before,
        "combined_lock_sha256": lock_before,
        "upstream_lock_sha256": upstream_locks,
        "build_mode": args.mode,
        "probe_executed": False,
        "pure_private_environment_spelling_test_passed": True,
        "pure_native_environment_tests": pure_tests,
        "pure_native_environment_tests_passed": True,
        "pure_dll_startup_tests": PURE_DLL_TESTS,
        "pure_dll_startup_tests_passed": True,
        "native_directory_custody_tests": native_tests,
        "native_directory_custody_tests_passed": True,
        "human_lock_review_required_before_live_execution": True,
        "locked_rebuild": args.mode == "build-locked",
        "scope": scope,
        "production_certification": False,
        "files": {
            path.relative_to(artifact).as_posix(): digest(path)
            for path in sorted(artifact.rglob("*"))
            if path.is_file()
        },
    }
    if control:
        provenance["mxc_fixed_create_control_patch_sha256"] = digest(CONTROL_PATCH)
        provenance["psec_attribute_attached_to_payload"] = False
        provenance["control_reference_plan_executed"] = False
        provenance["probe_cargo_features"] = ["fixed-claude-create-control"]
    (artifact / "PROVENANCE.json").write_text(json.dumps(provenance, indent=2) + "\n", encoding="utf-8")
    print("Contributor build complete; probe was not executed.")
    if args.mode == "generate-lock":
        print(
            "Review and commit source/Cargo.lock, then rebuild from fresh sources "
            "in build-locked mode before any live execution."
        )


if __name__ == "__main__":
    main()
