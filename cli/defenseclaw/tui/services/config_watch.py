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

"""Lightweight, cross-platform config generation detection for the TUI.

The watcher deliberately does not parse YAML.  A one-second background poll
compares a stable file signature and asks the app shell to reload only when a
new generation is present.  The content digest is the fallback for filesystems
whose timestamp granularity can hide rapid, same-size in-place writes.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from time import monotonic

CONFIG_POLL_INTERVAL_SECONDS = 1.0
_MAX_CONFIG_BYTES = 16 * 1024 * 1024
_READ_CHUNK_BYTES = 64 * 1024


@dataclass(frozen=True)
class ConfigGeneration:
    """Stable identity + metadata + content signature for one config write."""

    device: int
    inode: int
    modified_ns: int
    changed_ns: int
    size: int
    digest: str

    @property
    def identity(self) -> tuple[int, int]:
        return self.device, self.inode


def _nanoseconds(stat_result: os.stat_result, name: str, fallback: str) -> int:
    value = getattr(stat_result, name, None)
    if value is not None:
        return int(value)
    return int(float(getattr(stat_result, fallback, 0.0)) * 1_000_000_000)


def probe_config_generation(path: str | Path) -> ConfigGeneration | None:
    """Return a stable config signature, or ``None`` for transient states.

    Missing, locked, oversized, or concurrently-changing files are treated as
    unavailable.  Callers retain their last valid config and try again on a
    later poll.  Stat-before/read/stat-after catches atomic replacement and
    ordinary in-place writes on Windows, macOS, and Linux; SHA-256 catches a
    same-size update even when all observable timestamps are unchanged.
    """

    config_path = Path(path)
    try:
        before = config_path.stat()
        if before.st_size < 0 or before.st_size > _MAX_CONFIG_BYTES:
            return None
        digest = hashlib.sha256()
        total = 0
        with config_path.open("rb") as stream:
            while chunk := stream.read(_READ_CHUNK_BYTES):
                total += len(chunk)
                if total > _MAX_CONFIG_BYTES:
                    return None
                digest.update(chunk)
        after = config_path.stat()
    except OSError:
        return None

    before_key = (
        int(before.st_dev),
        int(before.st_ino),
        _nanoseconds(before, "st_mtime_ns", "st_mtime"),
        _nanoseconds(before, "st_ctime_ns", "st_ctime"),
        int(before.st_size),
    )
    after_key = (
        int(after.st_dev),
        int(after.st_ino),
        _nanoseconds(after, "st_mtime_ns", "st_mtime"),
        _nanoseconds(after, "st_ctime_ns", "st_ctime"),
        int(after.st_size),
    )
    if before_key != after_key or total != after.st_size:
        return None
    return ConfigGeneration(*after_key, digest.hexdigest())


class ConfigChangeWatcher:
    """Bounded-poll state machine that emits each valid generation once.

    Atomic replacements have a new file identity and can be reloaded on the
    first observing poll.  Same-identity changes are required to remain stable
    across two polls, which avoids applying the middle of an in-place rewrite.
    Failed parses retry on the next poll, then back off up to four seconds so a
    permanently malformed file does not trigger an expensive parse every tick.
    Any new generation bypasses that backoff immediately.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        poll_interval: float = CONFIG_POLL_INTERVAL_SECONDS,
    ) -> None:
        self.path = Path(path)
        self.poll_interval = max(float(poll_interval), 0.01)
        self.applied = probe_config_generation(self.path)
        self._candidate: ConfigGeneration | None = None
        self._failed: ConfigGeneration | None = None
        self._failed_attempts = 0
        self._retry_at = 0.0
        self._last_poll_at: float | None = None

    def poll(self, *, now: float | None = None) -> ConfigGeneration | None:
        """Return a changed stable generation when the poll interval is due."""

        current_time = monotonic() if now is None else float(now)
        if (
            self._last_poll_at is not None
            and current_time - self._last_poll_at < self.poll_interval
        ):
            return None
        self._last_poll_at = current_time
        generation = probe_config_generation(self.path)
        if generation is None:
            return None
        if generation == self.applied:
            self._candidate = None
            self._failed = None
            self._failed_attempts = 0
            self._retry_at = 0.0
            return None
        if generation == self._failed and current_time < self._retry_at:
            return None
        if self.applied is not None and generation.identity != self.applied.identity:
            self._candidate = generation
            return generation
        if self._candidate == generation:
            return generation
        self._candidate = generation
        return None

    def accept(self, generation: ConfigGeneration) -> None:
        """Mark ``generation`` applied so it is never emitted twice."""

        self.applied = generation
        self._candidate = None
        self._failed = None
        self._failed_attempts = 0
        self._retry_at = 0.0

    def reject(self, generation: ConfigGeneration, *, now: float | None = None) -> bool:
        """Keep a failed generation pending and schedule a bounded retry.

        Returns ``True`` on the first failure for this generation so callers
        can report one visible warning without flooding the Activity panel.
        """

        current_time = monotonic() if now is None else float(now)
        first_failure = generation != self._failed
        if first_failure:
            self._failed = generation
            self._failed_attempts = 1
        else:
            self._failed_attempts += 1
        delay = min(self.poll_interval * (2 ** max(self._failed_attempts - 1, 0)), 4.0)
        self._retry_at = current_time + delay
        self._candidate = generation
        return first_failure

    def sync_to_disk(self) -> bool:
        """Accept the current stable generation after an in-TUI config write."""

        generation = probe_config_generation(self.path)
        if generation is None:
            return False
        self.accept(generation)
        return True
