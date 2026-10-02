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

"""Plain-words notice when the disk holding the audit database is full."""

from __future__ import annotations

import os
import shutil

# Below this SQLite cannot grow the audit database (doctor's capacity check).
AUDIT_DISK_FULL_BYTES = 16 * 1024 * 1024


def audit_disk_full_notice(db_path: str) -> str:
    """Return a notice when audit events cannot be recorded for lack of space, else ""."""
    if not db_path:
        return ""
    directory = os.path.dirname(os.path.abspath(db_path)) or os.curdir
    try:
        free_bytes = shutil.disk_usage(directory).free
    except OSError:
        return ""
    if free_bytes >= AUDIT_DISK_FULL_BYTES:
        return ""
    return (
        f"the disk holding {directory} is full ({free_bytes // (1024 * 1024)} MiB free): "
        "new alerts and audit events are not being recorded; free space on that disk "
        "(the gateway resumes writing once there is room)"
    )
