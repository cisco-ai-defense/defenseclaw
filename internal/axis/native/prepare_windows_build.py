# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Build the Windows peer and run only reviewed inert unit tests."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import stat
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
AXIS = "fb5fd5f0f9377c2ccb30d7e027a36373de0d037c"
MXC = "fda29ac63bc306b7f97f3b86b4b63d44f7f40cf2"
TOOLCHAIN = "1.95.0"
PATCHES = {
    "windows-patches/mxc-strict-windows-psec.patch": "2afaa15f4387f8104c1dfe01f6f7c98a7ba6cd248d611139d2dbd04c2f39c6b2",
    "windows-patches/mxc-literal-argv.patch": "7117afc3c7ae28345757c364518b7b9120a7dd8e6b844403b06fe05403e4a76d",
    "windows-patches/mxc-windows-literal-argv.patch": (
        "1a9c94cb33501091a504d5c4ff55281b183a9d41472709edf7f35541c25f45af"
    ),
    "windows-patches/mxc-windows-process-identity.patch": (
        "d2d3819325c3027f159d75d577dd02306d497234f99293df3c825fbeebddeeab"
    ),
}
# Reviewed owned-input adapter; never includes the uncontained control overlay.
OWNED_PATCH = {
    "path": "patches/mxc-owned-windows-psec.patch",
    "sha256": "a0232b93b5131905dcfc4c7c47f85faa9113f85ca03be413b8f453b774ca25d2",
}
SDK_OVERLAY_FILES = {
    "src/mxc-sdk/src/backends/bubblewrap/common/bwrap_command.rs": (
        "a13934345597bd3fcaa66353b37ed5a9f54e643d234a620257970035b6212abc"
    ),
    "src/mxc-sdk/src/backends/bubblewrap/common/bwrap_runner.rs": (
        "5b23635df276e0743f9f9986f1ee4b63d9b0c71685b8e14bfa7b099023cfa210"
    ),
    "src/mxc-sdk/src/backends/process_container/common/base_container_runner.rs": (
        "e01e8885fbea92083c308a5ff47c683e77567e6b0f930ca9b002bf8e7bf38323"
    ),
    "src/mxc-sdk/src/backends/seatbelt/common/seatbelt_runner.rs": (
        "110534317bd4311b6ce1253126a7f6d507b7e98f381ad7945a63792e3297a13e"
    ),
    "src/mxc-sdk/src/core/mxc_common/literal_argv.rs": (
        "9a75fbca0fe9152abe4349ed37dd0a5db0d272e10ba89ecfbeb1f54bbd07d89d"
    ),
    "src/mxc-sdk/src/core/mxc_common/mod.rs": "42bb9328a9beb5f5217a55f11f5a4341fc36f8dbda9cf72729aeb767f7d92289",
    "src/mxc-sdk/src/core/mxc_common/sandbox_process.rs": (
        "4ad92632273e3f26ad902c7611edd13146bc96911a69c915954b84b398ae1508"
    ),
    "src/mxc-sdk/src/core/mxc_common/validator.rs": "a7487090a1693fb237acedd81f4e1c66b64d907c77e46824cc81a9f571c92191",
    "src/mxc-sdk/src/core/mxc_engine/dispatch.rs": "e1fd28a30b19f04d6be4c6694f33ee6cbad005e02aad334a1085d2438808df49",
    "src/mxc-sdk/src/core/mxc_engine/literal_argv.rs": (
        "c35bb7f302e84fbca74c62d4d8d12bb142002a6f69f12476f386c7a858b5f719"
    ),
    "src/mxc-sdk/src/core/mxc_engine/mod.rs": "1561b879ebe6bfee5d4db6d84e112aa0b97f8395e1cbf4bc3be41c3cfd9a60fe",
    "src/mxc-sdk/src/lib.rs": "4de6da448d6f68da8142efe39fe8abf56c843ebab397d63e2d0cd3a38e2fa7b1",
    "src/mxc-sdk/src/literal_argv.rs": "3e5884c316403be2ad82052492f1d3fd9dbd7ea2500ccbb7c716a64a29602cd5",
    "src/mxc-sdk/src/owned_windows_psec.rs": "f52eec99f1feb5e125b3e923377b02b9f68a4cecfc1d4ee937252f01c1db4218",
    "src/mxc-sdk/src/owned_windows_root_security.rs": (
        "e219d0a4c07a4e435e8ce3b4f319606bf23065b42337b277496552cc04915c04"
    ),
    "src/mxc-sdk/src/policy.rs": "43680b63e9e7d4c9351cee1936e791be1b4b877cfcee368b07429e22c355de9c",
    "src/mxc-sdk/src/policy/exact/mod.rs": "da9ad3bd8cf1be1af225aa95c887718d67ce7efbb8270d2e7d578bab9dc87bb7",
    "src/mxc-sdk/src/sandbox.rs": "530bb8fbbaf97715fdc6efbdfe28706b333e3140cca4456641759fdb30ca62b1",
}
INERT_TESTS = (
    "conversation::tests::prepared_handle_cannot_admit_duplicate_launch",
    "conversation::tests::late_controls_do_not_reopen_exited_session_and_destroy_is_separate",
    "wire::tests::independent_go_hash_vector_and_no_read_ahead",
    "wire::tests::ambiguous_json_and_null_poison_the_decoder",
    "windows_bootstrap::tests::prefix_only_pure_roundtrip_and_all_boundaries",
    "windows_io::tests::completion_never_treats_cancel_request_as_terminal_proof",
    "windows_io::tests::overlapped_event_suppresses_foreign_iocp_without_changing_owned_handle",
    "windows_io::tests::wait_set_is_bounded_unique_and_contains_no_pseudo_handle",
    "windows_io::tests::read_buffer_storage_stays_stable_and_observation_follows_completion",
    "windows_io::workload_tests::native_owned_workload_pair_transfers_and_cancels_without_a_child",
    "windows_io::workload_tests::native_sync_workload_end_is_never_adopted_as_overlapped",
    "windows::tests::native_sdk_owned_stdio_accepts_only_the_fixed_sync_child_endpoints",
)
SDK_INERT_TESTS = (
    "owned_windows_psec::tests::owned_access_requires_exact_role_rights_without_host_mutation_rights",
    "owned_windows_psec::stdio_tests::stdio_requires_synchronous_mode_and_direction_before_native_launch",
    "owned_windows_psec::native_access_tests::native_current_image_read_handle_cannot_be_promoted_to_execute_or_write",
    "owned_windows_psec::native_access_tests::native_relative_grant_pin_requires_the_exact_held_file_object",
)


def require(value, message):
    if not value:
        raise ValueError(message)


def ordinary(path, bound=2 << 20):
    info = path.lstat()
    require(
        stat.S_ISREG(info.st_mode) and not path.is_symlink() and 0 < info.st_size <= bound,
        "ordinary bounded build input required",
    )
    raw = path.read_bytes()
    require(len(raw) == info.st_size, "build input changed")
    return raw


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def command(argv, cwd=ROOT):
    # Preserve installed MSVC/SDK discovery; strip tokens and caller compiler,
    # linker, loader, Cargo and Rust command overrides.
    names = (
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
    environment = {key: os.environ[key] for key in names if key in os.environ}
    environment.update(CARGO_TERM_COLOR="never", CARGO_INCREMENTAL="0", CARGO_BUILD_JOBS="2")
    result = subprocess.run(
        argv, cwd=cwd, env=environment, check=True, shell=False, stdout=subprocess.PIPE, timeout=1800
    )
    require(len(result.stdout) <= 8 << 20, "build-reader output bound")
    return result.stdout


def source(name, commit):
    root = ROOT / name
    require(root.is_dir() and not root.is_symlink(), "fresh upstream checkout required")
    require(command(["git", "rev-parse", "HEAD"], root).decode().strip() == commit, "upstream commit differs")
    require(
        not command(["git", "status", "--porcelain", "--untracked-files=all"], root).strip(),
        "upstream checkout must be clean",
    )
    return root


def pe(raw):
    require(256 <= len(raw) <= 64 << 20 and raw[:2] == b"MZ", "bounded PE required")
    offset = struct.unpack_from("<I", raw, 60)[0]
    require(64 <= offset <= len(raw) - 264 and raw[offset : offset + 4] == b"PE\0\0", "PE header differs")
    require(
        struct.unpack_from("<H", raw, offset + 4)[0] == 0x8664
        and struct.unpack_from("<H", raw, offset + 24)[0] == 0x20B,
        "amd64 PE32+ required",
    )


def main():
    require(
        isinstance(OWNED_PATCH, dict)
        and set(OWNED_PATCH) == {"path", "sha256"}
        and isinstance(INERT_TESTS, tuple)
        and len(INERT_TESTS) > 0
        and len(set(INERT_TESTS)) == len(INERT_TESTS)
        and isinstance(SDK_INERT_TESTS, tuple)
        and len(SDK_INERT_TESTS) == len(set(SDK_INERT_TESTS)) == 4,
        "Windows source/test admission is closed",
    )
    require(
        sys.argv[1:] == [] and sys.platform == "win32" and platform.machine().lower() in {"amd64", "x86_64"},
        "fixed Windows build only",
    )
    staging = json.loads(ordinary(ROOT / "STAGING.json"))
    inputs = staging["files"]
    require(isinstance(inputs, dict) and 1 <= len(inputs) <= 256, "fixed staging inventory required")
    for name, expected in inputs.items():
        path = Path(name)
        require(not path.is_absolute() and ".." not in path.parts and "\\" not in name, "staged path shape differs")
        raw = ordinary(ROOT / path)
        require(expected == {"sha256": sha(raw), "size": len(raw)}, "Git-staged bytes differ")
    axis, mxc = source("axis-source", AXIS), source("mxc-source", MXC)
    locks = {
        "peer": ordinary(ROOT / "Cargo.lock"),
        "axis": ordinary(axis / "Cargo.lock"),
        "mxc": ordinary(mxc / "src/Cargo.lock"),
    }
    artifact = ROOT / "windows-build-artifact"
    artifact.mkdir()
    toolchain = command(["rustc", "+" + TOOLCHAIN, "-Vv"])
    require(toolchain.startswith(("rustc " + TOOLCHAIN + " ").encode()), "installed Rust differs")
    patches = dict(PATCHES)
    require(OWNED_PATCH["path"] not in patches, "duplicate owned overlay")
    patches[OWNED_PATCH["path"]] = OWNED_PATCH["sha256"]
    for name, expected in patches.items():
        raw = ordinary(ROOT / name)
        require(sha(raw) == expected, "reviewed overlay differs")
        command(["git", "apply", "--check", str(ROOT / name)], mxc)
        command(["git", "apply", str(ROOT / name)], mxc)
    changed = command(["git", "diff", "--name-only"], mxc).decode().splitlines()
    added = command(["git", "ls-files", "--others", "--exclude-standard"], mxc).decode().splitlines()
    overlay = {}
    for name in sorted(set(changed + added)):
        require(name.startswith("src/mxc-sdk/") and ".." not in Path(name).parts, "overlay escaped SDK source")
        overlay[name] = ordinary(mxc / name)
    require(
        {name: sha(value.replace(b"\r\n", b"\n")) for name, value in overlay.items()} == SDK_OVERLAY_FILES,
        "reviewed final SDK overlay inventory differs",
    )
    cargo = ["cargo", "+" + TOOLCHAIN]
    command(cargo + ["build", "--locked", "--release", "--bins"])
    listing = command(cargo + ["test", "--locked", "--release", "--lib", "--", "--list"])
    listed = [line[:-6] for line in listing.decode().splitlines() if line.endswith(": test")]
    require(sorted(listed) == sorted(INERT_TESTS), "exact inert test inventory differs")
    output = command(cargo + ["test", "--locked", "--release", "--lib", "--", "--test-threads=1"])
    passed = re.findall(r"(?m)^test (\S+) \.\.\. ok\r?$", output.decode())
    require(
        sorted(passed) == sorted(INERT_TESTS) and not re.search(rb"(?m)^test .*\.\.\. (?:FAILED|ignored)\r?$", output),
        "exact inert tests did not pass",
    )
    sdk_outputs = {}
    for name in SDK_INERT_TESTS:
        sdk_output = command(
            cargo
            + [
                "test",
                "--locked",
                "--release",
                "--target-dir",
                str(ROOT / "target-sdk-tests"),
                "-p",
                "mxc-sdk",
                "--lib",
                "--no-default-features",
                name,
                "--",
                "--exact",
                "--test-threads=1",
            ],
            mxc / "src",
        )
        sdk_text = sdk_output.decode()
        require(
            sdk_text.splitlines().count("test " + name + " ... ok") == 1
            and "test result: ok. 1 passed; 0 failed; 0 ignored;" in sdk_text,
            "exact SDK inert test did not pass once",
        )
        sdk_outputs[name] = sdk_output
    require(
        ordinary(ROOT / "Cargo.lock") == locks["peer"]
        and ordinary(axis / "Cargo.lock") == locks["axis"]
        and ordinary(mxc / "src/Cargo.lock") == locks["mxc"],
        "admitted lock changed",
    )
    require(all(ordinary(mxc / name) == raw for name, raw in overlay.items()), "overlay changed during build")
    require(
        command(["git", "rev-parse", "HEAD"], mxc).decode().strip() == MXC
        and command(["git", "diff", "--name-only"], mxc).decode().splitlines() == changed
        and command(["git", "ls-files", "--others", "--exclude-standard"], mxc).decode().splitlines() == added
        and not command(["git", "diff", "--cached", "--name-only"], mxc).strip(),
        "SDK source inventory changed during build",
    )
    source("axis-source", AXIS)
    for name, expected in inputs.items():
        raw = ordinary(ROOT / name)
        require(expected == {"sha256": sha(raw), "size": len(raw)}, "staged source changed during build")
    image = ordinary(ROOT / "target/release/defenseclaw-axis-peer.exe", 64 << 20)
    pe(image)
    retained = {
        "bin/defenseclaw-axis-peer.exe": image,
        "INERT-TESTS.txt": output,
        "INERT-TESTS-LIST.txt": listing,
        "TOOLCHAIN.txt": toolchain,
        "STAGING.json": ordinary(ROOT / "STAGING.json"),
    }
    retained.update({"source/" + name: ordinary(ROOT / name) for name in inputs})
    retained.update({"mxc-overlay/" + name: raw for name, raw in overlay.items()})
    for index, (name, log) in enumerate(sdk_outputs.items(), start=1):
        retained[f"SDK-INERT-{index}.txt"] = log
    for label, directory, license_name in (("axis", axis, "LICENSE"), ("mxc", mxc, "LICENSE.md")):
        retained["upstream/" + label + "-Cargo.lock"] = locks[label]
        retained["upstream/" + label + "-LICENSE"] = ordinary(directory / license_name)
    files = {}
    for name, raw in retained.items():
        target = artifact / name
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as stream:
            stream.write(raw)
        files[name] = {"sha256": sha(raw), "size": len(raw)}
    provenance = dict(
        scope="fixed_windows_native_peer_build_and_inert_tests_only",
        axis_commit=AXIS,
        mxc_commit=MXC,
        toolchain=TOOLCHAIN,
        staging=staging,
        patches=patches,
        inert_tests=sorted(passed),
        sdk_inert_tests=list(sdk_outputs),
        files=files,
        peer_or_payload_or_psec_execution=False,
        production_certification=False,
        limits="Registry archive bytes/compiler closure and reproducibility are not established by this build.",
    )
    (artifact / "PROVENANCE.json").write_text(json.dumps(provenance, indent=2) + "\n", encoding="utf-8")
    print("Windows peer build complete; peer and PSEC workloads were not executed.")


if __name__ == "__main__":
    main()
