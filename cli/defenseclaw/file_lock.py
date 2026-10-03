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

"""Cross-platform advisory locks for atomic file update transactions.

This module intentionally has no imports from the rest of ``defenseclaw``.
An older CLI can replace its wheel while the upgrade command is still running,
leaving old modules cached beside newly installed migration code.  Keeping the
lock primitive dependency-free lets that migration code load safely in the
mixed old/new process as well as in the clean target interpreter.
"""

from __future__ import annotations

import errno
import os
import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import IO


class FileLockTimeoutError(TimeoutError):
    """A sibling update lock did not become available within its budget."""


def _lock_deadline(timeout_seconds: float | None) -> float | None:
    if timeout_seconds is None:
        return None
    if isinstance(timeout_seconds, bool) or timeout_seconds < 0:
        raise ValueError("file-lock timeout must be a non-negative number or None")
    return time.monotonic() + timeout_seconds


def _lock_retry_delay(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise FileLockTimeoutError("file update lock is busy")
    return min(0.05, remaining)


if os.name == "nt":
    import msvcrt

    def _lock_file_exclusive(
        file_obj: IO[str],
        *,
        timeout_seconds: float | None,
    ) -> None:
        """Lock the sentinel byte, optionally within a monotonic budget."""

        deadline = _lock_deadline(timeout_seconds)
        while True:
            file_obj.seek(0)
            try:
                operation = msvcrt.LK_LOCK if deadline is None else msvcrt.LK_NBLCK
                msvcrt.locking(file_obj.fileno(), operation, 1)
                return
            except OSError:
                # LK_LOCK itself waits for a bounded period before raising;
                # retry indefinitely only for the legacy blocking contract.
                if deadline is None:
                    time.sleep(0.05)
                else:
                    time.sleep(_lock_retry_delay(deadline))

    def _unlock_file(file_obj: IO[str]) -> None:
        file_obj.seek(0)
        try:
            msvcrt.locking(file_obj.fileno(), msvcrt.LK_UNLCK, 1)
        except OSError:
            # Teardown is idempotent if the handle already released its lock.
            pass

else:
    import fcntl

    def _lock_file_exclusive(
        file_obj: IO[str],
        *,
        timeout_seconds: float | None,
    ) -> None:
        deadline = _lock_deadline(timeout_seconds)
        if deadline is None:
            fcntl.flock(file_obj.fileno(), fcntl.LOCK_EX)
            return
        while True:
            try:
                fcntl.flock(file_obj.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                return
            except OSError as exc:
                if exc.errno not in {errno.EACCES, errno.EAGAIN}:
                    raise
                time.sleep(_lock_retry_delay(deadline))

    def _unlock_file(file_obj: IO[str]) -> None:
        fcntl.flock(file_obj.fileno(), fcntl.LOCK_UN)


def probe_file_lock_available(
    file_obj: IO[str],
    *,
    timeout_seconds: float,
) -> None:
    """Acquire and immediately release one already-open sentinel lock."""

    _lock_file_exclusive(file_obj, timeout_seconds=timeout_seconds)
    _unlock_file(file_obj)


@contextmanager
def locked_file_update(
    path: str,
    *,
    timeout_seconds: float | None = None,
) -> Iterator[None]:
    """Hold a sibling sentinel lock for one read/modify/write transaction."""
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    lock_path = path + ".lock"
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(lock_path, flags, 0o600)
    try:
        # The sentinel is never written. ``r+`` keeps the Windows byte-range
        # cursor at offset zero; append mode would silently lock another byte.
        lock = os.fdopen(fd, "r+")
    except BaseException:
        os.close(fd)
        raise
    try:
        _lock_file_exclusive(lock, timeout_seconds=timeout_seconds)
        try:
            yield
        finally:
            _unlock_file(lock)
    finally:
        lock.close()


# Held by an open ``defenseclaw tui`` for its lifetime, so ``uninstall --all``
# can ask the user to quit it before removing the data directory (GAP-2576).
TUI_LOCK_FILENAME = "tui.lock"


def hold_tui_lock(data_dir: str) -> IO[str] | None:
    """Take the TUI lock in an existing ``data_dir``; the handle keeps it.

    Returns None (and the TUI runs without it) when the folder is missing,
    the file cannot be opened, or another TUI already holds the lock.
    """
    if not os.path.isdir(data_dir):
        return None
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(os.path.join(data_dir, TUI_LOCK_FILENAME), flags, 0o600)
    except OSError:
        return None
    lock = os.fdopen(fd, "r+")
    try:
        _lock_file_exclusive(lock, timeout_seconds=0)
    except OSError:
        lock.close()
        return None
    return lock


def release_tui_lock(lock: IO[str] | None, data_dir: str) -> None:
    """Release the TUI lock and remove its file."""
    if lock is None:
        return
    lock.close()
    try:
        os.unlink(os.path.join(data_dir, TUI_LOCK_FILENAME))
    except OSError:
        pass


def tui_lock_held(data_dir: str) -> bool:
    """Whether an open ``defenseclaw tui`` holds the lock in ``data_dir``."""
    flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(os.path.join(data_dir, TUI_LOCK_FILENAME), flags)
    except OSError:
        return False
    with os.fdopen(fd, "r+") as lock:
        try:
            probe_file_lock_available(lock, timeout_seconds=0)
        except FileLockTimeoutError:
            return True
        except OSError:
            return False
    return False
