# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""Launch a custody-checked executable as the file object that was checked.

Callers resolve an executable to one concrete path and verify who can write
it before running it. Running it by that path afterwards leaves a window in
which the path can come to name a different file. Each platform closes that
window with the primitive it has:

* Linux executes the open descriptor (``/proc/<pid>/fd/N``), so the kernel
  runs the verified inode whatever the path names by then.
* Windows holds the file open without write or delete sharing until the
  process exists. NTFS then refuses to rewrite, rename or replace the file or
  any directory above it.
* macOS has no descriptor exec. Just before the launch the path must still
  name the held file, and the identity and change times of the file and of
  every directory above it are recorded; once the process exists they must be
  unchanged, or the process is stopped and the launch fails. Callers already
  require that nobody but root or this account can write the path, so only
  they can cause that.
"""

from __future__ import annotations

import contextlib
import os
import stat
import subprocess
import sys
from collections.abc import Iterator, Sequence
from typing import Any

from defenseclaw.file_permissions import (
    UNSAFE_PATH_CHANGED,
    UNSAFE_PATH_INSPECTION_FAILED,
    UNSAFE_PATH_UNTRUSTED_CUSTODY,
    UnsafePathError,
    open_regular_file_no_follow,
)

_PathSnapshot = tuple[tuple[str, int, int, int, int, int, int], ...]


def _path_snapshot(path: str) -> _PathSnapshot:
    """Identity and change times of ``path`` and every directory above it."""
    entries = []
    current = path
    while True:
        info = os.lstat(current)
        entries.append(
            (
                current,
                info.st_dev,
                info.st_ino,
                info.st_mode,
                info.st_uid,
                info.st_mtime_ns,
                info.st_ctime_ns,
            )
        )
        parent = os.path.dirname(current)
        if parent == current:
            return tuple(entries)
        current = parent


class PinnedExecutable:
    """One verified executable, held open until its process exists."""

    def __init__(self, path: str, fd: int) -> None:
        self.path = path
        self._fd = fd
        self._linux = sys.platform.startswith("linux")
        self._script = False
        if self._linux:
            if not os.path.exists(f"/proc/{os.getpid()}/fd/{fd}"):
                raise UnsafePathError(
                    "descriptor-bound launch needs /proc",
                    code=UNSAFE_PATH_INSPECTION_FAILED,
                )
            self._script = os.pread(fd, 2, 0) == b"#!"
        self._require_same_file()

    def _require_same_file(self, snapshot: _PathSnapshot | None = None) -> _PathSnapshot | None:
        """Fail unless the path still names the pinned file; return a path snapshot on macOS."""
        try:
            current = os.stat(self.path) if os.name == "nt" else os.lstat(self.path)
            unchanged = os.path.samestat(os.fstat(self._fd), current)
            observed = None if os.name == "nt" or self._linux else _path_snapshot(self.path)
        except OSError as exc:
            raise UnsafePathError(
                f"verified executable could not be re-inspected: {self.path}",
                code=UNSAFE_PATH_CHANGED,
            ) from exc
        if not unchanged or (snapshot is not None and observed != snapshot):
            raise UnsafePathError(
                f"verified executable path changed around its launch: {self.path}",
                code=UNSAFE_PATH_CHANGED,
            )
        return observed

    def popen(self, argv: Sequence[str], **kwargs: Any) -> subprocess.Popen:
        """Start ``argv``, whose first item is this path, from the pinned file."""
        if not argv or argv[0] != self.path:
            raise ValueError("argv[0] must be the pinned executable path")
        snapshot = None
        if self._linux:
            if self._script:
                # The interpreter reopens the script path after exec, so the
                # child keeps its own copy of the descriptor.
                kwargs["executable"] = f"/proc/self/fd/{self._fd}"
                kwargs["pass_fds"] = (self._fd,)
            else:
                # This process holds the descriptor until the exec is done;
                # the child inherits none of it.
                kwargs["executable"] = f"/proc/{os.getpid()}/fd/{self._fd}"
        else:
            snapshot = self._require_same_file()
        process = subprocess.Popen(list(argv), **kwargs)
        if snapshot is not None:
            try:
                self._require_same_file(snapshot)
            except BaseException:
                with contextlib.suppress(OSError):
                    process.kill()
                with contextlib.suppress(OSError, subprocess.TimeoutExpired):
                    process.communicate(timeout=5)
                raise
        return process


@contextlib.contextmanager
def pinned_executable(path: str) -> Iterator[PinnedExecutable]:
    """Hold the custody-checked executable ``path`` open for one launch."""
    fd = open_regular_file_no_follow(path, _deny_write_sharing=True, _deny_delete_sharing=True)
    try:
        if os.name != "nt":
            info = os.fstat(fd)
            if (
                info.st_uid not in {0, os.geteuid()}
                or stat.S_IMODE(info.st_mode) & 0o022
                or not stat.S_IMODE(info.st_mode) & 0o111
            ):
                raise UnsafePathError(
                    f"verified executable is not an executable held only by root or this account: {path}",
                    code=UNSAFE_PATH_UNTRUSTED_CUSTODY,
                )
        yield PinnedExecutable(path, fd)
    finally:
        os.close(fd)


def run_pinned_executable(
    argv: Sequence[str],
    *,
    timeout: float | None = None,
    check: bool = False,
    capture_output: bool = False,
    **kwargs: Any,
) -> subprocess.CompletedProcess:
    """``subprocess.run`` for a custody-checked ``argv[0]``, bound to that file."""
    if capture_output:
        kwargs["stdout"] = subprocess.PIPE
        kwargs["stderr"] = subprocess.PIPE
    with pinned_executable(argv[0]) as pinned:
        process = pinned.popen(argv, **kwargs)
    with process:
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            process.kill()
            if os.name == "nt":
                exc.stdout, exc.stderr = process.communicate()
            else:
                process.wait()
            raise
        except BaseException:
            process.kill()
            raise
        returncode = process.poll()
    if check and returncode:
        raise subprocess.CalledProcessError(returncode, process.args, output=stdout, stderr=stderr)
    return subprocess.CompletedProcess(process.args, returncode, stdout, stderr)
