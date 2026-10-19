#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Prepare the macOS contributor artifact. This helper never executes it."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

AXIS_COMMIT = "fb5fd5f0f9377c2ccb30d7e027a36373de0d037c"
MXC_COMMIT = "fda29ac63bc306b7f97f3b86b4b63d44f7f40cf2"
TOOLCHAIN = "1.95.0"
BINARY = "defenseclaw-axis-mxc-macos-probe"
ROOT = Path(__file__).resolve().parent
LITERAL_PATCH = ROOT / "mxc-literal-argv.patch"
LITERAL_PATCH_SHA256 = "7117afc3c7ae28345757c364518b7b9120a7dd8e6b844403b06fe05403e4a76d"


def command(argv: list[str], *, cwd: Path = ROOT, capture: bool = False) -> str:
    # CI provisions tools first. Do not forward credentials, loader overrides,
    # caller Rust flags, or the caller's proxy configuration to build scripts.
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
        raise RuntimeError(f"{directory} must be clean")
    return source


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_literal_patch() -> None:
    if LITERAL_PATCH.is_symlink() or not LITERAL_PATCH.is_file():
        raise RuntimeError("the reviewed MXC literal-argv patch is missing or linked")
    if digest(LITERAL_PATCH) != LITERAL_PATCH_SHA256:
        raise RuntimeError("the MXC literal-argv patch differs from the reviewed bytes")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("generate-lock", "build-locked"))
    args = parser.parse_args()
    if sys.platform != "darwin" or os.uname().machine not in ("arm64", "x86_64"):
        raise RuntimeError("build this contributor artifact on macOS arm64 or x86_64")
    artifact = ROOT / "build-artifact"
    if artifact.exists() or artifact.is_symlink():
        raise RuntimeError("build-artifact already exists; use a fresh staging directory")
    lock = ROOT / "Cargo.lock"
    if args.mode == "generate-lock" and lock.exists():
        raise RuntimeError("generate-lock requires a fresh staging directory without Cargo.lock")
    if args.mode == "build-locked" and (lock.is_symlink() or not lock.is_file()):
        raise RuntimeError("build-locked requires the reviewed combined Cargo.lock")
    verify_literal_patch()
    axis = verify_source("axis-source", AXIS_COMMIT)
    mxc = verify_source("mxc-source", MXC_COMMIT)
    toolchain = command(["rustc", f"+{TOOLCHAIN}", "-Vv"], capture=True)
    cargo_version = command(["cargo", f"+{TOOLCHAIN}", "--version"], capture=True)
    if not toolchain.startswith(f"rustc {TOOLCHAIN} "):
        raise RuntimeError("the already-installed Rust toolchain differs from the reviewed version")
    upstream_locks = {"axis": digest(axis / "Cargo.lock"), "mxc": digest(mxc / "src" / "Cargo.lock")}
    command(["git", "apply", "--check", "--whitespace=error-all", str(LITERAL_PATCH)], cwd=mxc)
    command(["git", "apply", "--whitespace=error-all", str(LITERAL_PATCH)], cwd=mxc)
    if args.mode == "generate-lock":
        command(["cargo", f"+{TOOLCHAIN}", "generate-lockfile"])
    lock_before = digest(lock)
    command(["cargo", f"+{TOOLCHAIN}", "build", "--locked", "--release"])
    command(["cargo", f"+{TOOLCHAIN}", "test", "--locked", "--release", "--no-run"])
    if digest(lock) != lock_before:
        raise RuntimeError("the combined dependency lock changed during the locked build")
    if upstream_locks != {"axis": digest(axis / "Cargo.lock"), "mxc": digest(mxc / "src" / "Cargo.lock")}:
        raise RuntimeError("an upstream lock changed during the build")
    verify_literal_patch()

    (artifact / "bin").mkdir(parents=True)
    for relative in (
        Path("Cargo.toml"),
        Path("Cargo.lock"),
        Path("prepare_build.py"),
        Path("README.md"),
        Path("src/main.rs"),
        Path("src/probe.rs"),
        Path("src/strict_profile.rs"),
        Path("mxc-literal-argv.patch"),
    ):
        target = artifact / "source" / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, target)
    shutil.copyfile(ROOT / "target" / "release" / BINARY, artifact / "bin" / BINARY)
    (artifact / "bin" / BINARY).chmod(0o755)
    (artifact / "upstream").mkdir()
    for name, source, lock_path, license_path in (
        ("axis", axis, axis / "Cargo.lock", axis / "LICENSE"),
        ("mxc", mxc, mxc / "src" / "Cargo.lock", mxc / "LICENSE.md"),
    ):
        shutil.copyfile(lock_path, artifact / "upstream" / f"{name}-Cargo.lock")
        shutil.copyfile(license_path, artifact / "upstream" / f"{name}-LICENSE{license_path.suffix}")
    (artifact / "TOOLCHAIN.txt").write_text(toolchain + "\n" + cargo_version + "\n", encoding="utf-8")
    provenance = {
        "schema": "defenseclaw-contributor-axis-mxc-macos-probe-v1",
        "axis_commit": AXIS_COMMIT,
        "mxc_commit": MXC_COMMIT,
        "mxc_literal_patch_sha256": digest(LITERAL_PATCH),
        "combined_lock_sha256": lock_before,
        "upstream_lock_sha256": upstream_locks,
        "build_mode": args.mode,
        "probe_executed": False,
        "human_lock_review_required_before_live_execution": True,
        "files": {
            path.relative_to(artifact).as_posix(): digest(path)
            for path in sorted(artifact.rglob("*"))
            if path.is_file()
        },
    }
    (artifact / "PROVENANCE.json").write_text(json.dumps(provenance, indent=2) + "\n", encoding="utf-8")
    print("Contributor build complete; probe was not executed.")
    if args.mode == "generate-lock":
        print(
            "Review and commit source/Cargo.lock; rebuild from fresh sources "
            "in build-locked mode before live execution."
        )


if __name__ == "__main__":
    main()
