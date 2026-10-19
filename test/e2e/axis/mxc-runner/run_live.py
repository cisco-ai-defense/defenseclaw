#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Run only the independently verified, fixed Linux contributor experiment."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import time
from pathlib import Path

CHECKS = {
    "private_home_and_environment",
    "allowed_writes",
    "outer_mxc_canary_visible_before_guards",
    "ungranted_read_and_write_eacces",
    "readonly_write_denied",
    "ipv4_ipv6_tcp_udp_socket_eperm",
    "exit_23",
    "pty_isatty_and_foreground",
    "pty_input_ack_and_resize",
    "pty_sigint_ack_and_continued_input",
    "typed_timeout",
    "direct_child_pidfd_exited",
    "handle_kill_after_wait_idempotent",
    "literal_argv_preserved_without_shell",
    "owned_fixture_removed",
}
OUTPUT_LIMIT = 128 * 1024


def positive_pty_groups(value: object) -> bool:
    if not isinstance(value, list) or len(value) != 3:
        return False
    for observation, phase in zip(value, ("initial", "resized", "continued"), strict=True):
        if not isinstance(observation, dict):
            return False
        foreground = observation.get("foreground_pgrp")
        group = observation.get("process_pgrp")
        if (
            observation.get("phase") != phase
            or type(observation.get("isatty")) is not int
            or observation["isatty"] != 1
            or type(foreground) is not int
            or type(group) is not int
            or foreground <= 0
            or group <= 0
            or foreground != group
        ):
            return False
    return True


def owned_processes(binary: Path) -> list[dict[str, object]]:
    """Report only exact executable matches or commands naming this artifact."""
    identity = binary.stat()
    matches = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit() or int(entry.name) == os.getpid():
            continue
        try:
            executable = (entry / "exe").stat()
            command = (entry / "cmdline").read_bytes().split(b"\0")
            same_binary = (executable.st_dev, executable.st_ino) == (identity.st_dev, identity.st_ino)
            names_binary = any(os.fsencode(binary) in argument for argument in command)
            if same_binary or names_binary:
                matches.append(
                    {
                        "pid": int(entry.name),
                        "exact_binary": same_binary,
                        "command": [os.fsdecode(value) for value in command if value],
                    }
                )
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue  # Other users' processes are outside this fixed probe's scope.
    return matches


def limit_output() -> None:
    import resource

    # The fixed program writes only bounded diagnostics. Also bound files if a
    # regression writes indefinitely; GNU timeout still owns the process group.
    resource.setrlimit(resource.RLIMIT_FSIZE, (OUTPUT_LIMIT, OUTPUT_LIMIT))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    if platform.system() != "Linux" or platform.machine() != "x86_64" or os.geteuid() == 0:
        raise RuntimeError("the live experiment requires native unprivileged Linux x86_64")
    artifact = args.artifact.resolve(strict=True)
    receipt = json.loads(args.receipt.read_text())
    if receipt.get("verified") is not True or receipt.get("execution_performed") is not False:
        raise ValueError("a verification-only receipt is required")
    if receipt.get("binary") != "bin/defenseclaw-axis-mxc-probe":
        raise ValueError("only the fixed contributor binary may be run")
    binary = artifact / receipt["binary"]
    if binary.is_symlink() or not binary.is_file():
        raise ValueError("the fixed binary must be an ordinary file")
    if hashlib.sha256(binary.read_bytes()).hexdigest() != receipt.get("binary_sha256"):
        raise ValueError("the verified binary has changed")
    evidence = args.evidence.resolve(strict=True)
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
    # The compiled fixed probe explicitly allocates /tmp/dc-axis-mxc-* fixtures.
    before = {str(path) for path in Path("/tmp").glob("dc-axis-mxc-*")}
    existing = owned_processes(binary)
    if existing:
        raise RuntimeError("the exact artifact already has a matching live process")
    binary.chmod(0o700)
    command = ["/usr/bin/timeout", "--signal=TERM", "--kill-after=5s", "60s", str(binary)]
    started = time.monotonic()
    errors = []
    exit_code = None
    output = diagnostic = b""
    remaining = new_fixtures = None
    try:
        with (evidence / "probe-stdout.txt").open("xb") as stdout, (evidence / "probe-stderr.txt").open("xb") as stderr:
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
    except (OSError, subprocess.SubprocessError) as error:
        errors.append(type(error).__name__)
    finally:
        for name in ("probe-stdout.txt", "probe-stderr.txt"):
            try:
                with (evidence / name).open("rb") as stream:
                    data = stream.read(OUTPUT_LIMIT + 1)
                if name == "probe-stdout.txt":
                    output = data
                else:
                    diagnostic = data
            except OSError as error:
                errors.append(f"{name}: {type(error).__name__}")
        try:
            remaining = owned_processes(binary)
            new_fixtures = sorted({str(path) for path in Path("/tmp").glob("dc-axis-mxc-*")} - before)
        except OSError as error:
            errors.append(f"post-run inspection: {type(error).__name__}")
    payload = None
    try:
        payload = json.loads(output)
    except (ValueError, UnicodeDecodeError):
        pass
    passed = (
        not errors
        and exit_code == 0
        and len(output) < OUTPUT_LIMIT
        and len(diagnostic) < OUTPUT_LIMIT
        and isinstance(payload, dict)
        and payload.get("containment") == "mxc_sdk_v1_bubblewrap"
        and payload.get("axis_child_guards") == "landlock_and_offline_seccomp"
        and payload.get("filesystem") == "hard_requirement"
        and payload.get("network") == "block"
        and isinstance(payload.get("checks"), list)
        and all(isinstance(value, str) for value in payload["checks"])
        and len(payload["checks"]) == len(CHECKS)
        and set(payload["checks"]) == CHECKS
        and type(payload.get("landlock_abi")) is int
        and payload["landlock_abi"] >= 3
        and positive_pty_groups(payload.get("pty_groups"))
        and payload.get("production_or_claude_qualification") is False
        and payload.get("proxy_or_descendant_cleanup_qualification") is False
        and not remaining
        and not new_fixtures
    )
    record = {
        "passed": passed,
        "command": command,
        "exit_code": exit_code,
        "errors": errors,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "result": payload,
        "remaining_matching_processes": remaining,
        "new_owned_fixtures": new_fixtures,
        "cleanup_scope": "exact artifact executable and commands naming it; no general descendant/helper claim",
        "scope": "fixed offline contributor experiment; no real agent or credentials",
    }
    (evidence / "live-result.json").write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps(record, indent=2))
    if not passed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
