#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Run only the verified fixed strict Seatbelt contributor experiment on macOS."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import stat
import subprocess
import time
from pathlib import Path

from verify_live_artifact import BINARY, COMBINED_LOCK_SHA256, commit_argument, sha256_argument

CHECKS = {
    "explicit_footprint_admission",
    "private_home_and_cwd",
    "denied_read_write_metadata",
    "readonly_write_denied",
    "ungranted_read_denied",
    "loopback_network_denied_with_host_positive_control",
    "pipe_echo_exit_23",
    "pty_echo_resize_exit_23",
    "typed_timeout",
    "descendant_marker_absent",
    "literal_argv_preserved_without_shell",
    "owned_fixture_removed",
}
OUTPUT_LIMIT = 128 * 1024
MAX_BINARY_BYTES = 128 * 1024 * 1024
FIXTURE_PREFIX = "dc-axis-mxc-macos-"


def _names_exact_artifact(command: str, binary: Path) -> bool:
    """Match a complete argv/shell token; a path prefix does not count."""
    literal = re.escape(str(binary))
    return bool(re.search(rf"(?:^|[\s'\"])({literal})(?=$|[\s'\"])", command))


def owned_processes(binary: Path) -> list[dict[str, object]]:
    """Inspect only our UID's commands naming this exact artifact path."""
    result = subprocess.run(
        ["/bin/ps", "-ww", "-U", str(os.geteuid()), "-o", "pid=,uid=,command="],
        check=True,
        shell=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    matches = []
    for line in result.stdout.splitlines():
        fields = line.split(maxsplit=2)
        if len(fields) != 3:
            continue
        pid_text, uid_text, command = fields
        if not pid_text.isdigit() or not uid_text.isdigit():
            continue
        pid = int(pid_text)
        if pid == os.getpid() or int(uid_text) != os.geteuid():
            continue
        if _names_exact_artifact(command, binary):
            matches.append({"pid": pid, "match": "exact_artifact_path_argument"})
    return matches


def owned_fixtures() -> set[str]:
    """Snapshot only this user's fixed private fixture prefix."""
    paths = set()
    for path in Path("/private/tmp").glob(f"{FIXTURE_PREFIX}*"):
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == os.geteuid():
            paths.add(str(path))
    return paths


def hash_binary(binary: Path) -> str:
    if binary.is_symlink() or binary.parent.is_symlink():
        raise ValueError("fixed binary path contains a symlink")
    metadata = binary.stat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o6000 or metadata.st_size > MAX_BINARY_BYTES:
        raise ValueError("fixed binary is not an ordinary bounded unprivileged file")
    digest = hashlib.sha256()
    with binary.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def limit_output() -> None:
    import resource

    resource.setrlimit(resource.RLIMIT_FSIZE, (OUTPUT_LIMIT, OUTPUT_LIMIT))


def read_bounded(path: Path) -> bytes:
    with path.open("rb") as stream:
        return stream.read(OUTPUT_LIMIT + 1)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--gtimeout", type=Path, required=True)
    parser.add_argument("--provenance-sha256", type=sha256_argument, required=True)
    parser.add_argument("--build-commit", type=commit_argument, required=True)
    parser.add_argument("--build-run", required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[1-9][0-9]*", args.build_run):
        parser.error("--build-run must be an exact numeric Actions run ID")
    if args.evidence.is_symlink() or not args.evidence.is_dir():
        raise ValueError("a precreated ordinary evidence directory is required")
    evidence = args.evidence.resolve(strict=True)
    started = time.monotonic()
    errors: list[str] = []
    exit_code = None
    output = diagnostic = b""
    remaining: list[dict[str, object]] | None = None
    new_fixtures: list[str] | None = None
    before: set[str] | None = None
    binary: Path | None = None
    command: list[str] | None = None
    attempted = False
    try:
        if platform.system() != "Darwin" or platform.machine() not in {"arm64", "x86_64"} or os.geteuid() == 0:
            raise ValueError("live experiment requires native unprivileged macOS")
        artifact = args.artifact.resolve(strict=True)
        if args.artifact.is_symlink() or not artifact.is_dir():
            raise ValueError("artifact root is not an ordinary directory")
        receipt = json.loads(args.receipt.read_text(encoding="utf-8"))
        required = {
            "verified": True,
            "execution_performed": False,
            "binary": BINARY,
            "combined_lock_sha256": COMBINED_LOCK_SHA256,
            "provenance_sha256": args.provenance_sha256,
            "build_commit": args.build_commit,
            "build_run": args.build_run,
        }
        if not isinstance(receipt, dict) or any(
            receipt.get(name) != value or type(receipt.get(name)) is not type(value) for name, value in required.items()
        ):
            raise ValueError("verification receipt does not identify the reviewed fixed artifact")
        binary = artifact / BINARY
        if hash_binary(binary) != receipt.get("binary_sha256"):
            raise ValueError("verified binary content changed")
        timeout_bin = args.gtimeout.resolve(strict=True)
        if args.gtimeout.name != "gtimeout" or not timeout_bin.is_file():
            raise ValueError("an explicit GNU gtimeout executable is required")
        version = subprocess.run(
            [str(timeout_bin), "--version"],
            check=True,
            shell=False,
            capture_output=True,
            timeout=5,
        )
        if not version.stdout.startswith(b"timeout (GNU coreutils) "):
            raise ValueError("outer watchdog is not GNU coreutils timeout")
        private = evidence / "private"
        private.mkdir(mode=0o700)
        (private / "home").mkdir(mode=0o700)
        (private / "tmp").mkdir(mode=0o700)
        environment = {
            "PATH": "/usr/bin:/bin",
            "LANG": "C",
            "TERM": "xterm-256color",
            "HOME": str(private / "home"),
            "TMPDIR": str(private / "tmp"),
        }
        before = owned_fixtures()
        if owned_processes(binary):
            raise ValueError("reviewed artifact already has a matching process")
        binary.chmod(0o700)
        command = [str(timeout_bin), "--signal=TERM", "--kill-after=5s", "60s", str(binary), "--strict-fixed"]
        with (evidence / "probe-stdout.txt").open("xb") as stdout, (evidence / "probe-stderr.txt").open("xb") as stderr:
            attempted = True
            result = subprocess.run(
                command,
                cwd=private,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                timeout=75,
                check=False,
                preexec_fn=limit_output,
            )
            exit_code = result.returncode
    except Exception as error:
        errors.append(type(error).__name__)
    finally:
        for name in ("probe-stdout.txt", "probe-stderr.txt"):
            try:
                data = read_bounded(evidence / name)
                if name == "probe-stdout.txt":
                    output = data
                else:
                    diagnostic = data
            except FileNotFoundError:
                if attempted:
                    errors.append(f"{name}: missing")
            except OSError as error:
                errors.append(f"{name}: {type(error).__name__}")
        if before is not None and binary is not None:
            try:
                remaining = owned_processes(binary)
                new_fixtures = sorted(owned_fixtures() - before)
            except Exception as error:
                errors.append(f"post-run inspection: {type(error).__name__}")
    payload = None
    try:
        payload = json.loads(output)
    except (ValueError, UnicodeDecodeError):
        pass
    passed = (
        attempted
        and not errors
        and exit_code == 0
        and len(output) < OUTPUT_LIMIT
        and len(diagnostic) < OUTPUT_LIMIT
        and isinstance(payload, dict)
        and payload.get("axis_commit") == "fb5fd5f0f9377c2ccb30d7e027a36373de0d037c"
        and payload.get("mxc_commit") == "fda29ac63bc306b7f97f3b86b4b63d44f7f40cf2"
        and payload.get("containment") == "mxc_sdk_v1_seatbelt"
        and payload.get("bridge") == "axis_policy_and_old_wire_admission_to_typed_mxc_v1"
        and payload.get("seatbelt_profile") == "reviewed_fixed_strict_override"
        and isinstance(payload.get("checks"), list)
        and all(isinstance(value, str) for value in payload["checks"])
        and len(payload["checks"]) == len(CHECKS)
        and set(payload["checks"]) == CHECKS
        and payload.get("scope") == "fixed_benign_composite_contributor_experiment"
        and payload.get("production_or_defenseclaw_provider_qualification") is False
        and payload.get("exact_system_read_or_general_metadata_parity") is False
        and payload.get("strict_host_canary_open_denied") is True
        and not remaining
        and not new_fixtures
    )
    record = {
        "passed": passed,
        "attempted": attempted,
        "command": command,
        "exit_code": exit_code,
        "errors": errors,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "stdout_bytes": len(output),
        "stderr_bytes": len(diagnostic),
        "stderr_excerpt": diagnostic[:1200].decode("utf-8", errors="replace") if not passed else None,
        "result": payload if isinstance(payload, dict) and len(output) < 16 * 1024 else None,
        "remaining_matching_processes": remaining,
        "new_owned_fixtures": new_fixtures,
        "cleanup_scope": "own-UID commands naming exact artifact path and newly owned fixed-prefix fixtures",
        "scope": "fixed offline strict Seatbelt contributor experiment; no general descendant/helper claim",
    }
    with (evidence / "live-result.json").open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(record, indent=2) + "\n")
    print(json.dumps(record, indent=2))
    if not passed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
