# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Private supervisor for phase-two upgrade mutations.

The controller passes an already-locked lease descriptor to this process.  The
supervisor retains that descriptor while it synchronously waits for the real
mutator, so abruptly terminating only the controller cannot release the lease
while the mutation is still running.  The descriptor is deliberately closed
across the mutator exec: commands such as ``defenseclaw-gateway start``
daemonize, and allowing their gateway/watchdog descendants to inherit the lease
would prevent every later recovery or upgrade from acquiring it.
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
    # Keep the lease in this synchronous supervisor, never in the mutation
    # command.  ``pass_fds`` clears FD_CLOEXEC, so passing the descriptor would
    # let a daemonizing command leak it into long-lived descendants after both
    # the controller and this supervisor have completed.  Setting the flag
    # explicitly and closing all non-stdio descriptors at the exec boundary
    # makes that invariant independent of the descriptor state we inherited.
    if os.name == "posix":
        try:
            os.set_inheritable(lease_fd, False)
        except OSError:
            return _fail("lease could not be isolated from the child exec")
    try:
        completed = subprocess.run(
            command,
            env=child_env,
            check=False,
            close_fds=True,
            pass_fds=(),
        )
    except OSError:
        return _fail("could not launch command")
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
