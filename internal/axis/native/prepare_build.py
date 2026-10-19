#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Build-only private peer evidence. Never launches a peer or contained child."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import tomllib

ROOT = Path(__file__).resolve().parent
AXIS = "fb5fd5f0f9377c2ccb30d7e027a36373de0d037c"
MXC = "fda29ac63bc306b7f97f3b86b4b63d44f7f40cf2"
BWRAP = "8e51677abd7e3338e4952370bf7d902e37d8cbb6"
TOOLCHAIN = "1.95.0"
NATIVE_TEST_COUNT = 19
C_TESTS = (
    "topology_refuses_nested_bind_mounts_and_malformed_inventory",
    "locator_refuses_deleted_traversal_and_unrepresentable_names",
    "cloned_view_uses_reopened_mount_id_and_still_refuses_nested_aliases",
    "immutable_copy_preserves_seals_size_and_every_byte",
    "readonly_root_is_nonrecursive_and_source_noexec_is_preserved",
)
C_TEST_SUMMARY = "PASS 5 inert owned-FD tests; no namespace, mount or workload execution"
SEED_SHA256 = "d6556677c6decd2d5d786ca082ac2bcdb37fc92130d45b7002a7e8bffe2154db"
PATCHES = {
    "patches/axis-offline-bpf.patch": "914b75d4ad1da26f4f9850886093fb3560ade14d9870dd604de20a33d2f179f2",
    "patches/mxc-owned-bubblewrap.patch": "422aff2de2719878e6fe10a6c097153c58dc3f58d3fa53ee97b2b1d1ea43d5e8",
    "patches/bwrap-owned-fds.patch": "1563032b5bfbd74b56214119f1287de3a7e63c9054898b58c6cd9603948dd621",
    "mxc-literal-argv.patch": "7117afc3c7ae28345757c364518b7b9120a7dd8e6b844403b06fe05403e4a76d",
}
# Windows-only inputs remain source evidence; Linux neither applies this
# overlay nor derives compiled unit roots from these explicitly listed files.
WINDOWS_SOURCE = {
    "WINDOWS.md",
    "prepare_windows_build.py",
    "src/windows.rs",
    "src/windows_bootstrap.rs",
    "src/windows_io.rs",
    "src/windows_transport.rs",
    "patches/mxc-owned-windows-psec.patch",
}
SOURCE = {
    "Cargo.toml",
    "README.md",
    "prepare_build.py",
    "test_prepare_build.py",
    "src/lib.rs",
    "src/main.rs",
    "src/namespace.rs",
    "src/conversation.rs",
    "src/custody.rs",
    "src/linux.rs",
    "src/owner.rs",
    "src/transport.rs",
    "src/wire.rs",
    "patches/README.md",
    "patches/bwrap-COPYING",
    "patches/bwrap-owned-fd-tests.c",
    "static/README.md",
    "static/sources.json",
    "static/build_static.py",
    "static/test_build_static.py",
    "static/musl-LICENSE",
    "static/libcap-LICENSE",
} | (set(PATCHES) - {"mxc-literal-argv.patch"}) | WINDOWS_SOURCE
PATH_PACKAGES = {
    ("axis-core", "0.3.5"),
    ("axis-sandbox", "0.3.5"),
    ("mxc-sdk", "1.0.1"),
    ("defenseclaw-axis-native", "0.0.0"),
}


def ordinary(path: Path, bound: int = 2 << 20, *, allow_empty: bool = False) -> bytes:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or getattr(metadata, "st_file_attributes", 0) & 0x400:
        raise RuntimeError("source must be an ordinary non-reparse regular file")
    with path.open("rb") as stream:
        raw = stream.read(bound + 1)
    if (not raw and not allow_empty) or len(raw) > bound:
        raise RuntimeError("source exceeds its byte bound")
    return raw


def sha(path: Path) -> str:
    return hashlib.sha256(ordinary(path, 512 << 20, allow_empty=True)).hexdigest()


def admit_c_test_output(output: str) -> None:
    if output.splitlines() != [*C_TESTS, C_TEST_SUMMARY]:
        raise RuntimeError("inert C unit-test inventory/pass output differs")


def native_test_inventory() -> set[str]:
    expected = set()
    for name in sorted(SOURCE - WINDOWS_SOURCE):
        if name.startswith("src/") and name.endswith(".rs"):
            expected |= {
                f"{Path(name).stem}::tests::{test}"
                for test in re.findall(r"#\[test\]\s+fn ([A-Za-z_][A-Za-z_0-9]*)\(", ordinary(ROOT / name).decode())
            }
    return expected


DEPENDENCY_TESTS = {
    "axis": {
        "workspace": "axis-source",
        "package": "axis-sandbox",
        "prefix": "linux::seccomp::tests::private_offline_export_",
        "tests": {
            "linux::seccomp::tests::private_offline_export_denies_every_socket_without_installing_filter",
            "linux::seccomp::tests::private_offline_export_keeps_explicit_blocked_syscalls_and_refuses_unknown",
        },
    },
    "mxc": {
        "workspace": "mxc-source/src",
        "package": "mxc-sdk",
        "prefix": "owned_bubblewrap::tests::",
        "tests": {
            "owned_bubblewrap::tests::static_structure_refuses_interpreter_dynamic_and_mutable_images",
            "owned_bubblewrap::tests::filter_copy_starts_at_zero_and_ignores_caller_offset_changes",
            "owned_bubblewrap::tests::guest_destinations_refuse_alias_components_and_synthetic_roots",
            "owned_bubblewrap::tests::fixed_image_uses_verified_copy_route_without_path_or_legacy_data_options",
        },
    },
}


def dependency_unit_gates(artifact: Path) -> None:
    evidence = {}
    for name, spec in DEPENDENCY_TESTS.items():
        workspace = ROOT / spec["workspace"]
        lock = ordinary(workspace / "Cargo.lock")
        base = [
            "cargo",
            f"+{TOOLCHAIN}",
            "test",
            "--locked",
            "--release",
            "-p",
            spec["package"],
            "--no-default-features",
            "--lib",
            spec["prefix"],
            "--",
        ]
        listing = command([*base, "--list"], cwd=workspace, capture=True)
        listed = {line.removesuffix(": test") for line in listing.splitlines() if line.endswith(": test")}
        if listed != spec["tests"]:
            raise RuntimeError("pure dependency unit-test inventory differs")
        output = command([*base, "--test-threads=1"], cwd=workspace, capture=True)
        passed = set(re.findall(r"^test (\S+) \.\.\. ok$", output, re.MULTILINE))
        if passed != listed or f"test result: ok. {len(listed)} passed; 0 failed; 0 ignored;" not in output:
            raise RuntimeError("pure dependency unit-test pass inventory differs")
        if ordinary(workspace / "Cargo.lock") != lock:
            raise RuntimeError("dependency unit tests changed pinned upstream workspace lock")
        (artifact / f"{name.upper()}-PURE-UNIT-TESTS.txt").write_text(output, encoding="utf-8")
        evidence[name] = {
            "tests": sorted(passed),
            "passed": len(passed),
            "workspace_lock_sha256": hashlib.sha256(lock).hexdigest(),
            "scope": "BPF_export_or_inert_memfd_path_validation_only",
            "sandbox_or_peer_execution": False,
        }
    (artifact / "DEPENDENCY-PURE-UNIT-TESTS.json").write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")


def command(argv: list[str], *, cwd: Path = ROOT, capture: bool = False) -> str:
    # Disposable build tools only. Tokens and loader/Cargo/Rust overrides are
    # excluded; no request/workload/provider credential environment exists here.
    environment = {
        key: os.environ[key]
        for key in ("PATH", "HOME", "CARGO_HOME", "RUSTUP_HOME", "SSL_CERT_FILE", "CARGO_HTTP_CAINFO")
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
        timeout=1800,
    )
    return result.stdout if capture else ""


def source(name: str, commit: str) -> Path:
    directory = ROOT / name
    if directory.is_symlink() or not directory.is_dir():
        raise RuntimeError("provision a fresh exact-commit source checkout")
    if command(["git", "rev-parse", "HEAD"], cwd=directory, capture=True).strip() != commit:
        raise RuntimeError("upstream checkout commit differs")
    if command(["git", "status", "--porcelain", "--untracked-files=all"], cwd=directory, capture=True):
        raise RuntimeError("upstream checkout must be clean before overlays")
    return directory


def patch_paths(raw: bytes) -> set[str]:
    paths = set()
    for value in re.findall(rb"^\+\+\+ b/(.+)$", raw, re.MULTILINE):
        path = value.decode("ascii")
        if path.startswith("/") or any(part in ("", ".", "..") for part in path.split("/")):
            raise RuntimeError("overlay contains an invalid path")
        paths.add(path)
    if not paths:
        raise RuntimeError("overlay contains no admitted source paths")
    return paths


def apply(directory: Path, names: list[str]) -> dict[str, str]:
    expected = set()
    for name in names:
        patch = ROOT / name
        raw = ordinary(patch)
        if hashlib.sha256(raw).hexdigest() != PATCHES[name]:
            raise RuntimeError("overlay differs from the reviewed bytes")
        expected |= patch_paths(raw)
        command(["git", "apply", "--check", "--whitespace=error-all", str(patch)], cwd=directory)
        command(["git", "apply", "--whitespace=error-all", str(patch)], cwd=directory)
    modified = set(command(["git", "diff", "--name-only"], cwd=directory, capture=True).splitlines())
    added = set(
        command(["git", "ls-files", "--others", "--exclude-standard"], cwd=directory, capture=True).splitlines()
    )
    if modified | added != expected:
        raise RuntimeError("overlay changed an unexpected source inventory")
    return {name: sha(directory / name) for name in sorted(expected)}


def registry(raw: bytes) -> tuple[dict[tuple[str, str, str], str], set[tuple[str, str]]]:
    packages = tomllib.loads(raw.decode("utf-8"))["package"]
    entries = {}
    local = set()
    for package in packages:
        if "source" not in package:
            local.add((package["name"], package["version"]))
            continue
        if package["source"] != "registry+https://github.com/rust-lang/crates.io-index":
            raise RuntimeError("only the reviewed crates.io registry is admitted")
        key = package["name"], package["version"], package["source"]
        checksum = package.get("checksum", "")
        if not re.fullmatch(r"[0-9a-f]{64}", checksum) or key in entries:
            raise RuntimeError("missing or duplicate registry checksum")
        entries[key] = checksum
    return entries, local


def admit_lock(seed: bytes, candidate: bytes) -> dict[str, object]:
    reviewed, _ = registry(seed)
    proposed, paths = registry(candidate)
    if paths != PATH_PACKAGES:
        raise RuntimeError("combined lock has an unexpected local package identity")
    unknown = [list(key[:2]) for key, checksum in proposed.items() if reviewed.get(key) != checksum]
    if unknown:
        raise RuntimeError("unreviewed registry package/version/checksum; retain discovery lock for review")
    return {
        "registry_packages": len(proposed),
        "new_registry_versions": [],
        "seed_sha256": hashlib.sha256(seed).hexdigest(),
        "candidate_sha256": hashlib.sha256(candidate).hexdigest(),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("discover", "locked"))
    parser.add_argument("--static-musl", action="store_true", help="build two unexecuted static C closure candidates")
    parser.add_argument(
        "--dependency-unit-gates", action="store_true", help="run selected nonspawning dependency tests"
    )
    options = parser.parse_args()
    mode = options.mode
    if sys.platform != "linux" or os.uname().machine != "x86_64":
        raise RuntimeError("build the private peer on disposable Linux x86_64")
    artifact = ROOT / "build-artifact"
    if artifact.exists() or artifact.is_symlink():
        raise RuntimeError("use fresh build staging; build-artifact exists")
    for name in SOURCE:
        ordinary(ROOT / name)
    axis = source("axis-source", AXIS)
    mxc = source("mxc-source", MXC)
    bwrap = source("bwrap-source", BWRAP)
    upstream = {
        "axis-Cargo.lock": ordinary(axis / "Cargo.lock"),
        "mxc-Cargo.lock": ordinary(mxc / "src/Cargo.lock"),
        "axis-LICENSE": ordinary(axis / "LICENSE"),
        "mxc-LICENSE": ordinary(mxc / "LICENSE.md"),
        "bwrap-COPYING": ordinary(bwrap / "COPYING"),
    }
    if upstream["bwrap-COPYING"] != ordinary(ROOT / "patches/bwrap-COPYING"):
        raise RuntimeError("pinned Bubblewrap license differs")
    overlays = {
        "axis": apply(axis, ["patches/axis-offline-bpf.patch"]),
        "mxc": apply(mxc, ["mxc-literal-argv.patch", "patches/mxc-owned-bubblewrap.patch"]),
        "bwrap": apply(bwrap, ["patches/bwrap-owned-fds.patch"]),
    }
    seed = ordinary(ROOT / "reviewed-linux-seed.lock")
    if hashlib.sha256(seed).hexdigest() != SEED_SHA256:
        raise RuntimeError("reviewed Linux dependency seed differs")
    lock = ROOT / "Cargo.lock"
    if mode == "discover":
        if lock.exists() or lock.is_symlink():
            raise RuntimeError("discovery starts without a contributor lock")
        lock.write_bytes(seed)
        # Cargo preserves the seeded reviewed registry versions while replacing
        # the contributor root package. Nothing is compiled before lock admission.
        command(["cargo", f"+{TOOLCHAIN}", "metadata", "--format-version", "1"], capture=True)
    else:
        ordinary(lock)
    lock_bytes = ordinary(lock)
    admission = admit_lock(seed, lock_bytes)
    artifact.mkdir()
    (artifact / "LOCK-ADMISSION.json").write_text(json.dumps(admission, indent=2) + "\n", encoding="utf-8")
    # Retain the exact inputs even if a later Rust/C/static build refuses.
    for name, raw in upstream.items():
        target = artifact / "upstream" / name
        target.parent.mkdir(exist_ok=True)
        target.write_bytes(raw)
    for name in sorted(SOURCE | {"mxc-literal-argv.patch", "Cargo.lock", "reviewed-linux-seed.lock"}):
        target = artifact / "source" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(ordinary(ROOT / name))
    (artifact / "BUILD-INPUTS.json").write_text(
        json.dumps(
            {
                "source_commits": {"axis": AXIS, "mxc": MXC, "bwrap": BWRAP},
                "patch_sha256": PATCHES,
                "overlay_files": overlays,
                "mode": mode,
                "static_build_requested": options.static_musl,
                "dependency_pure_unit_gates_requested": options.dependency_unit_gates,
                "peer_or_sandbox_execution": False,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    toolchain = command(["rustc", f"+{TOOLCHAIN}", "-Vv"], capture=True)
    if not toolchain.startswith("rustc 1.95.0 ") or "host: x86_64-unknown-linux-gnu" not in toolchain:
        raise RuntimeError("unexpected Rust toolchain identity")
    (artifact / "TOOLCHAIN.txt").write_text(toolchain, encoding="utf-8")
    command(["cargo", f"+{TOOLCHAIN}", "build", "--locked", "--release", "--bins"])
    expected_tests = native_test_inventory()
    listing = command(
        ["cargo", f"+{TOOLCHAIN}", "test", "--locked", "--release", "--lib", "--", "--list"], capture=True
    )
    listed = {line.removesuffix(": test") for line in listing.splitlines() if line.endswith(": test")}
    if len(expected_tests) != NATIVE_TEST_COUNT or listed != expected_tests:
        raise RuntimeError("Rust unit-test inventory differs from reviewed native source")
    output = command(
        ["cargo", f"+{TOOLCHAIN}", "test", "--locked", "--release", "--lib", "--", "--test-threads=1"], capture=True
    )
    passed = set(re.findall(r"^test (\S+) \.\.\. ok$", output, re.MULTILINE))
    if passed != expected_tests or f"test result: ok. {len(expected_tests)} passed; 0 failed; 0 ignored;" not in output:
        raise RuntimeError("Rust pure unit-test pass inventory differs")
    (artifact / "RUST-UNIT-TESTS.json").write_text(
        json.dumps(
            {
                "tests": sorted(expected_tests),
                "passed": len(passed),
                "peer_execution_performed": False,
                "contained_payload_execution": False,
                "scope": "protocol_fake_processes_and_owned_inert_fds_only",
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    (artifact / "RUST-UNIT-TESTS.txt").write_text(output, encoding="utf-8")
    if options.dependency_unit_gates:
        dependency_unit_gates(artifact)
    if (
        ordinary(lock) != lock_bytes
        or ordinary(axis / "Cargo.lock") != upstream["axis-Cargo.lock"]
        or ordinary(mxc / "src/Cargo.lock") != upstream["mxc-Cargo.lock"]
    ):
        raise RuntimeError("build changed an admitted lock")
    # Compile the bwrap C seam as ordinary dynamic Linux source only. Never run
    # it, install it or present it as the required reviewed static-musl image.
    command(
        [
            "meson",
            "setup",
            "compile-check",
            "-Dselinux=disabled",
            "-Dman=disabled",
            "-Dtests=false",
            "-Dbash_completion=disabled",
            "-Dzsh_completion=disabled",
            "--werror",
        ],
        cwd=bwrap,
    )
    command(["ninja", "-C", "compile-check", "bwrap"], cwd=bwrap)
    # A separate host unit executable includes the C source with main renamed
    # and uncalled. Only fixed parsers, flag predicates and owned inert byte-copy
    # fixtures run; neither bwrap, namespace setup nor a payload is launched.
    unit = bwrap / "compile-check/owned-fd-inert-unit"
    command(
        [
            "/usr/bin/x86_64-linux-gnu-gcc-13",
            "-D_GNU_SOURCE",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            f"-I{bwrap}",
            f"-I{bwrap / 'compile-check'}",
            str(ROOT / "patches/bwrap-owned-fd-tests.c"),
            *[str(bwrap / f"compile-check/bwrap.p/{name}.c.o") for name in ("bind-mount", "network", "utils")],
            "-lcap",
            "-o",
            str(unit),
        ]
    )
    c_output = command([str(unit)], capture=True)
    admit_c_test_output(c_output)
    (artifact / "BWRAP-INERT-UNIT-TESTS.json").write_text(
        json.dumps(
            {
                "tests": C_TESTS,
                "passed": len(C_TESTS),
                "scope": "parsers_flags_and_owned_inert_copy_only",
                "unit_execution_performed": True,
                "bubblewrap_main_called": False,
                "namespace_or_mount_or_workload_execution": False,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    (artifact / "BWRAP-INERT-UNIT-TESTS.txt").write_text(c_output, encoding="utf-8")
    c_binary = bwrap / "compile-check/bwrap"
    (artifact / "BWRAP-COMPILE-ONLY.json").write_text(
        json.dumps(
            {
                "source_commit": BWRAP,
                "binary_sha256": sha(c_binary),
                "execution_performed": False,
                "runtime_image_admission": False,
                "static_musl_closure_qualified": False,
                "elf_program_headers": command(["readelf", "--program-headers", str(c_binary)], capture=True),
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    static_candidate = {"candidate_supplied": False, "runtime_admission": False}
    if options.static_musl:
        from static.build_static import build

        static_candidate = build(ROOT, bwrap, artifact)
    (artifact / "bin").mkdir()
    shutil.copyfile(ROOT / "target/release/defenseclaw-axis-peer", artifact / "bin/defenseclaw-axis-peer")
    inventory = {
        path.relative_to(artifact).as_posix(): {"sha256": sha(path), "size": path.stat().st_size}
        for path in sorted(artifact.rglob("*"))
        if path.is_file()
    }
    provenance = {
        "variant": "private_linux_owned_fd_peer_build_only",
        "source_commits": {"axis": AXIS, "mxc": MXC, "bwrap": BWRAP},
        "toolchain": TOOLCHAIN,
        "mode": mode,
        "locked_build": mode == "locked",
        "lock_review_requires_external_receipt": True,
        "peer_execution_performed": False,
        "contained_payload_execution": False,
        "customer_activation": False,
        "static_bwrap_runtime_supplied": False,
        "static_bwrap_build_candidate": static_candidate,
        "unit_scope": "protocol_fake_processes_and_owned_inert_fds_only",
        "c_unit_scope": "separate_parsers_flags_and_owned_inert_copy_executable_only",
        "overlay_files": overlays,
        "patch_sha256": PATCHES,
        "files": inventory,
    }
    (artifact / "PROVENANCE.json").write_text(json.dumps(provenance, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
