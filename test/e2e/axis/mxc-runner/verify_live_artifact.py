#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Verify a reviewed locked contributor artifact. This never executes it."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import subprocess
from pathlib import Path

AXIS_COMMIT = "fb5fd5f0f9377c2ccb30d7e027a36373de0d037c"
MXC_COMMIT = "fda29ac63bc306b7f97f3b86b4b63d44f7f40cf2"
LITERAL_PATCH_SHA256 = "7117afc3c7ae28345757c364518b7b9120a7dd8e6b844403b06fe05403e4a76d"
COMBINED_LOCK_SHA256 = "d6556677c6decd2d5d786ca082ac2bcdb37fc92130d45b7002a7e8bffe2154db"
UPSTREAM_LOCK_SHA256 = {
    "axis": "788c5b5ea12b19176969d495f53d2c97a8e056d035832ec529ffc042fd97f3b2",
    "mxc": "2d145ff3861cd19d1f50969083f8ac59e4d4fd50b030bef12f365a5fcc87afa0",
}
SOURCE_FILES = {
    "mxc-literal-argv.patch",
    "Cargo.toml",
    "Cargo.lock",
    "prepare_build.py",
    "test_prepare_build.py",
    "README.md",
    "src/main.rs",
    "src/probe.rs",
    "patches/axis-offline-mxc-child.patch",
}
BINARY = "bin/defenseclaw-axis-mxc-probe"
FILES = {f"source/{name}" for name in SOURCE_FILES} | {
    BINARY,
    "TOOLCHAIN.txt",
    "upstream/axis-Cargo.lock",
    "upstream/mxc-Cargo.lock",
    "upstream/axis-LICENSE",
    "upstream/mxc-LICENSE",
}
MAX_FILE_BYTES = 128 * 1024 * 1024


def file_bytes(root: Path, relative: str) -> bytes:
    """Read only exact regular inventory entries, through no symlink parents."""
    if relative not in FILES | {"PROVENANCE.json", "WORKFLOW.json"}:
        raise ValueError("artifact path is outside the fixed inventory")
    path = root
    for component in Path(relative).parts:
        path = path / component
        if path.is_symlink():
            raise ValueError("artifact contains a symlink")
    metadata = path.stat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o6000:
        raise ValueError("artifact entry is not an ordinary unprivileged file")
    if metadata.st_size > MAX_FILE_BYTES:
        raise ValueError("artifact file exceeds the size bound")
    return path.read_bytes()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_argument(value: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{64}", value):
        raise argparse.ArgumentTypeError("expected a lowercase SHA-256 digest")
    return value


def commit_argument(value: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{40}", value):
        raise argparse.ArgumentTypeError("expected an exact lowercase Git commit")
    return value


def git_identity(checkout: Path, expected: str) -> None:
    for arguments, wanted in [(["rev-parse", "HEAD"], expected), (["status", "--porcelain"], "")]:
        result = subprocess.run(
            ["git", "-C", str(checkout), *arguments],
            check=True,
            shell=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
        if result.stdout.strip() != wanted:
            raise ValueError("source checkout identity or clean status differs")


def verify(
    artifact: Path,
    checkout: Path,
    provenance_sha256: str,
    build_commit: str,
    build_run: str,
) -> dict[str, object]:
    if artifact.is_symlink() or not artifact.is_dir():
        raise ValueError("artifact root must be an ordinary directory")
    artifact = artifact.resolve(strict=True)
    git_identity(checkout, build_commit)
    provenance_bytes = file_bytes(artifact, "PROVENANCE.json")
    if sha256(provenance_bytes) != provenance_sha256:
        raise ValueError("provenance does not match the independently reviewed digest")
    provenance = json.loads(provenance_bytes)
    if not isinstance(provenance, dict):
        raise ValueError("provenance must be an object")
    required = {
        "schema": "defenseclaw-contributor-axis-mxc-probe-v1",
        "axis_commit": AXIS_COMMIT,
        "mxc_commit": MXC_COMMIT,
        "mxc_literal_patch_sha256": LITERAL_PATCH_SHA256,
        "combined_lock_sha256": COMBINED_LOCK_SHA256,
        "upstream_lock_sha256": UPSTREAM_LOCK_SHA256,
        "build_mode": "build-locked",
        "probe_executed": False,
        "human_lock_review_required_before_live_execution": True,
        "locked_rebuild": True,
    }
    for name, value in required.items():
        if provenance.get(name) != value or type(provenance.get(name)) is not type(value):
            raise ValueError(f"locked build provenance differs for {name}")
    files = provenance.get("files")
    if not isinstance(files, dict) or set(files) != FILES:
        raise ValueError("artifact provenance inventory differs")
    actual = {
        path.relative_to(artifact).as_posix() for path in artifact.rglob("*") if path.is_file() or path.is_symlink()
    }
    if actual != FILES | {"PROVENANCE.json", "WORKFLOW.json"}:
        raise ValueError("artifact has missing or unreviewed files")
    for relative, expected_hash in files.items():
        if not isinstance(expected_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_hash):
            raise ValueError("invalid per-file digest")
        if sha256(file_bytes(artifact, relative)) != expected_hash:
            raise ValueError(f"artifact content differs for {relative}")
    for name in SOURCE_FILES:
        source_root = checkout / "test" / "e2e" / "axis"
        source = source_root / ("patches" if name == "mxc-literal-argv.patch" else "mxc-runner") / name
        if source.is_symlink() or source.read_bytes() != file_bytes(artifact, "source/" + name):
            raise ValueError(f"packaged source differs from the reviewed commit for {name}")
    if sha256(file_bytes(artifact, "source/mxc-literal-argv.patch")) != LITERAL_PATCH_SHA256:
        raise ValueError("MXC literal-argv patch content differs")
    if sha256(file_bytes(artifact, "source/Cargo.lock")) != COMBINED_LOCK_SHA256:
        raise ValueError("combined lock content differs")
    for name, expected_hash in UPSTREAM_LOCK_SHA256.items():
        if sha256(file_bytes(artifact, f"upstream/{name}-Cargo.lock")) != expected_hash:
            raise ValueError("upstream lock content differs")
    if sha256(file_bytes(artifact, "source/patches/axis-offline-mxc-child.patch")) != provenance.get(
        "axis_patch_sha256"
    ):
        raise ValueError("AXIS export patch identity differs")
    if not file_bytes(artifact, "TOOLCHAIN.txt").startswith(b"rustc 1.95.0 "):
        raise ValueError("artifact toolchain differs")
    workflow = json.loads(file_bytes(artifact, "WORKFLOW.json"))
    if not isinstance(workflow, dict) or any(
        workflow.get(name) != value
        for name, value in {
            "repository": "cisco-ai-defense/defenseclaw",
            "workflow_commit": build_commit,
            "run_id": build_run,
            "execution_performed": False,
        }.items()
    ):
        raise ValueError("build workflow attribution differs")
    if workflow.get("execution_performed") is not False:
        raise ValueError("build workflow unexpectedly executed the probe")
    return {
        "verified": True,
        "provenance_sha256": provenance_sha256,
        "build_commit": build_commit,
        "build_run": build_run,
        "binary": BINARY,
        "binary_sha256": files[BINARY],
        "combined_lock_sha256": COMBINED_LOCK_SHA256,
        "verified_file_count": len(FILES),
        "execution_performed": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--source-checkout", type=Path, required=True)
    parser.add_argument("--provenance-sha256", type=sha256_argument, required=True)
    parser.add_argument("--build-commit", type=commit_argument, required=True)
    parser.add_argument("--build-run", required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[1-9][0-9]*", args.build_run):
        parser.error("--build-run must be an exact numeric Actions run ID")
    receipt = verify(args.artifact, args.source_checkout, args.provenance_sha256, args.build_commit, args.build_run)
    with args.receipt.open("x", encoding="utf-8") as output:
        output.write(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt))


if __name__ == "__main__":
    main()
