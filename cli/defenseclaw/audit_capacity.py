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

# Free space at which a disk the gateway reported full counts as freed. Well
# above the full mark: a full APFS volume still reports about 32 MiB free.
AUDIT_DISK_FREED_BYTES = 256 * 1024 * 1024


def audit_disk_freed(db_path: str) -> bool:
    """True when the disk holding *db_path* has clear room again (GAP-2016)."""
    if not db_path:
        return False
    try:
        free_bytes = shutil.disk_usage(os.path.dirname(os.path.abspath(db_path)) or os.curdir).free
    except OSError:
        return False
    return free_bytes >= AUDIT_DISK_FREED_BYTES


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


def audit_open_failure_notice(db_path: str, exc: BaseException) -> str:
    directory = os.path.dirname(os.path.abspath(db_path)) or os.curdir
    cause = str(exc)
    if "unable to open database file" in cause.lower() or isinstance(exc, OSError):
        try:
            free_bytes = shutil.disk_usage(directory).free
        except OSError:
            free_bytes = None
        if free_bytes is not None and free_bytes < 256 * 1024 * 1024:
            return (
                f"the disk holding {directory} has too little usable space "
                f"({free_bytes // (1024 * 1024)} MiB reported free); free space, "
                "then retry opening the audit store"
            )
    return f"cannot open audit store {db_path}: {cause}"


# Plain words for the gateway's event_history_last_sqlite_class tokens.
AUDIT_WRITE_FAILURE_CAUSES = {
    "full": "the disk holding the audit database is full",
    "busy_locked": "another process keeps the audit database locked",
    "deadline": "audit database writes time out",
    "io": "the disk returned an I/O error",
    "readonly_cantopen": "the audit database is read-only or cannot be opened",
    "constraint_corrupt": "the audit database is damaged",
}


# The gateway cannot write its local-write loss journal (GAP-1129).
AUDIT_LOSS_JOURNAL_FAILING = (
    "the gateway cannot write its audit loss journal (local-write-losses.journal in its data directory), "
    "so a restart before audit writes recover loses the count of audit events missing from the local history"
)


def audit_loss_journal_failing(details: object) -> bool:
    """True when the gateway reports its local-write loss journal failing (GAP-1129)."""
    return isinstance(details, dict) and details.get("local_write_loss_journal") == "failing"


def audit_write_failure_reason(details: object, audit_db: str = "") -> str:
    """Plain words for a gateway telemetry snapshot whose audit writes fail, else "".

    *details* is the gateway's ``telemetry.details`` map (GAP-1308). Shared by
    doctor, status and the TUI Overview so they say the same thing (GAP-2215).
    """
    if not isinstance(details, dict):
        return ""
    journal = AUDIT_LOSS_JOURNAL_FAILING if audit_loss_journal_failing(details) else ""
    if details.get("event_history_failure") != "sqlite_write_failed":
        return journal
    sqlite_class = str(details.get("event_history_last_sqlite_class") or "")
    if sqlite_class == "full" and audit_disk_freed(audit_db):
        reason = (
            "audit events could not be written while the disk holding the audit database was full; "
            "it has room again, and this clears with the next audit event"
        )
    else:
        cause = AUDIT_WRITE_FAILURE_CAUSES.get(sqlite_class, "the audit database rejects writes")
        reason = f"audit events cannot be written: {cause}"
    return f"{reason}; {journal}" if journal else reason
