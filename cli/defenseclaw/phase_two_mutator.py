# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Private child wrapper for phase-two upgrade mutations.

The controller passes an already-locked lease descriptor to this process.
Both this wrapper and the real mutator inherit that descriptor, so abruptly
terminating only the controller cannot release the lease while the mutation is
still running.  A later recovery blocks on the same lease before restoring any
state.
"""

from __future__ import annotations

import os
import stat
import subprocess
import sys

_MARKER = "--defenseclaw-phase-two-mutator"


def _fail(message: str) -> int:
    print(f"phase-two mutator wrapper: {message}", file=sys.stderr)
    return 125


def main(argv: list[str] | None = None) -> int:
    values = list(sys.argv[1:] if argv is None else argv)
    if len(values) < 5 or values[0] != _MARKER or values[3] != "--":
        return _fail("invalid invocation")
    lease_path = os.path.abspath(values[1])
    try:
        lease_fd = int(values[2])
    except ValueError:
        return _fail("invalid lease descriptor")
    command = values[4:]
    if lease_fd < 3 or not command or any("\x00" in item for item in command):
        return _fail("invalid command")

    try:
        path_info = os.lstat(lease_path)
        fd_info = os.fstat(lease_fd)
    except OSError:
        return _fail("lease is unavailable")
    if (
        stat.S_ISLNK(path_info.st_mode)
        or not stat.S_ISREG(path_info.st_mode)
        or not stat.S_ISREG(fd_info.st_mode)
        or not os.path.samestat(path_info, fd_info)
    ):
        return _fail("lease identity is invalid")
    if os.name == "posix" and (
        path_info.st_uid != os.getuid() or stat.S_IMODE(path_info.st_mode) != 0o600
    ):
        return _fail("lease is not owner-only")

    child_env = os.environ.copy()
    child_env["DEFENSECLAW_PHASE_TWO_MUTATOR_CHILD"] = "1"
    try:
        completed = subprocess.run(
            command,
            env=child_env,
            check=False,
            pass_fds=(lease_fd,) if os.name == "posix" else (),
        )
    except OSError:
        return _fail("could not launch command")
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
