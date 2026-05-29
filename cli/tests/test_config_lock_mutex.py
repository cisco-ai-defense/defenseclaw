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

"""Mutual-exclusion contract for ``locked_config_yaml``.

This runs on every OS in CI. On Windows it exercises the ``msvcrt.locking``
path; on POSIX it exercises ``fcntl.flock``. It is the regression guard for
the bug where the Windows lock grabbed a different byte offset on each
acquisition (append-mode write + post-write file position) and therefore let
concurrent holders into the critical section simultaneously.
"""

from __future__ import annotations

import threading
import time

from defenseclaw.config import locked_config_yaml


def test_locked_config_yaml_serializes_concurrent_holders(tmp_path) -> None:
    cfg = tmp_path / "config.yaml"
    cfg.write_text("a: 1\n")

    events: list[str] = []
    events_guard = threading.Lock()  # protects the list mutation only

    def worker() -> None:
        with locked_config_yaml(str(cfg)):
            with events_guard:
                events.append("enter")
            # Hold the lock long enough that a broken (non-exclusive) lock
            # would let another worker append "enter" before this one exits.
            time.sleep(0.02)
            with events_guard:
                events.append("exit")

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    assert all(not t.is_alive() for t in threads), "a holder deadlocked"
    assert len(events) == 16

    # With true mutual exclusion each holder completes enter->exit before the
    # next acquires the lock, so the sequence is strictly paired. Any
    # enter-enter adjacency means two holders were inside at once.
    for i in range(0, len(events), 2):
        assert events[i] == "enter", f"overlap at {i}: {events}"
        assert events[i + 1] == "exit", f"overlap at {i}: {events}"
