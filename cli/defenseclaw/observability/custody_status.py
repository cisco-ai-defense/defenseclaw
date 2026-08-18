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

"""Read-only, content-free connector export-custody diagnostics.

The correlation ledger is the authority for per-instance custody.  This
module never infers custody from configuration files and never edits a
connector-owned exporter.  Managed-file backups are consulted only to prove
that a configuration DefenseClaw previously wrote still has the exact
post-setup digest; their pristine payload is neither decoded nor rendered.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import sqlite3
import stat
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from defenseclaw.db import Store

_CUSTODY_VALUES = frozenset(("defenseclaw", "external", "hook_only"))
_CONNECTOR_TOKEN = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SIGNALS = frozenset(("logs", "traces", "metrics"))
_EVENT_NAMES = (
    "telemetry.authentication.failed",
    "telemetry.batch.normalized",
    "telemetry.records.dropped",
)
_WINDOW = timedelta(hours=24)
_MAX_EVENT_ROWS = 4096
_MAX_INSTANCES = 256
_MAX_BACKUPS = 32
_MAX_BACKUP_BYTES = 2 * 1024 * 1024
_MAX_MANAGED_TARGET_BYTES = 32 * 1024 * 1024


@dataclass(frozen=True)
class ConnectorCustodyStatus:
    """One bounded, secret-free connector-instance custody snapshot."""

    connector_instance_id: str
    connector: str
    custody: str
    profile_version: str
    default: bool
    managed_config_state: str = "not_applicable"
    managed_config_files: int = 0
    normalized_batches: int = 0
    drop_only_batches: int = 0
    authentication_failures: int = 0
    credential_state: str = "no_recent_failure"
    last_native_activity: str = ""
    last_authentication_failure: str = ""

    def as_json(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ConnectorCustodyReport:
    """Bounded report shared by plan and doctor renderers."""

    state: str
    reason: str
    observation_window_hours: int
    instances: tuple[ConnectorCustodyStatus, ...] = ()
    unattributed_authentication_failures: int = 0
    last_unattributed_authentication_failure: str = ""
    event_rows_truncated: bool = False

    def as_json(self) -> dict[str, Any]:
        return {
            "state": self.state,
            "reason": self.reason,
            "observation_window_hours": self.observation_window_hours,
            "instances": [item.as_json() for item in self.instances],
            "unattributed_authentication_failures": self.unattributed_authentication_failures,
            "last_unattributed_authentication_failure": self.last_unattributed_authentication_failure,
            "event_rows_truncated": self.event_rows_truncated,
        }


@dataclass
class _Evidence:
    normalized: dict[tuple[str, str, str], int]
    dropped: dict[tuple[str, str, str], int]
    last_native: dict[str, datetime]
    auth_count: dict[str, int]
    last_auth: dict[str, datetime]
    unattributed_auth_count: int = 0
    last_unattributed_auth: datetime | None = None
    truncated: bool = False


def inspect_connector_custody(
    audit_db: str | os.PathLike[str],
    data_dir: str | os.PathLike[str],
    *,
    now: datetime | None = None,
) -> ConnectorCustodyReport:
    """Read custody and recent ingest evidence without initializing SQLite.

    Absence is a bounded status, not an exception: ``observability plan`` must
    remain usable before the gateway has created its database, and doctor
    already owns the separate audit-database readiness check.
    """

    window_hours = int(_WINDOW.total_seconds() // 3600)
    path = Path(audit_db)
    try:
        info = path.lstat()
    except FileNotFoundError:
        return ConnectorCustodyReport("unavailable", "database_missing", window_hours)
    except OSError:
        return ConnectorCustodyReport("unavailable", "database_unreadable", window_hours)
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        return ConnectorCustodyReport("unavailable", "database_path_untrusted", window_hours)

    store: Store | None = None
    try:
        store = Store.open_read_only(str(path), timeout=0.1)
        if not _table_exists(store.db, "correlation_connector_instances"):
            return ConnectorCustodyReport("unavailable", "ledger_unavailable", window_hours)
        rows = store.db.execute(
            """SELECT connector_instance_id, connector, export_custody,
                      profile_version, is_default
                 FROM correlation_connector_instances
                ORDER BY connector, connector_instance_id
                LIMIT ?""",
            (_MAX_INSTANCES + 1,),
        ).fetchall()
        if len(rows) > _MAX_INSTANCES:
            return ConnectorCustodyReport("unavailable", "instance_limit_exceeded", window_hours)

        current = _utc(now or datetime.now(timezone.utc))
        evidence = _load_recent_evidence(store.db, current)
        instances: list[ConnectorCustodyStatus] = []
        for raw in rows:
            item = _normalize_instance(raw)
            if item is None:
                # The reduced v8 contract has exactly three custody states.
                # Do not silently hide a fourth/invalid state or malformed
                # instance row from operator diagnostics.
                return ConnectorCustodyReport("unavailable", "invalid_ledger", window_hours)
            connector_id, connector, custody, profile_version, is_default = item
            managed_state, managed_files = _managed_config_state(
                Path(data_dir), connector, custody, is_default
            )
            # The current inbound endpoint resolves one implicit/default
            # instance per authenticated connector source. Never smear that
            # evidence across explicit additional instances merely because
            # they share a connector name.
            evidence_connector = connector if is_default else ""
            normalized, drop_only = _batch_counts(evidence, evidence_connector)
            last_native = evidence.last_native.get(evidence_connector)
            last_auth = evidence.last_auth.get(evidence_connector)
            instances.append(
                ConnectorCustodyStatus(
                    connector_instance_id=connector_id,
                    connector=connector,
                    custody=custody,
                    profile_version=profile_version,
                    default=is_default,
                    managed_config_state=managed_state,
                    managed_config_files=managed_files,
                    normalized_batches=normalized,
                    drop_only_batches=drop_only,
                    authentication_failures=evidence.auth_count.get(evidence_connector, 0),
                    credential_state=_credential_state(last_auth, last_native),
                    last_native_activity=_format_time(last_native),
                    last_authentication_failure=_format_time(last_auth),
                )
            )
        return ConnectorCustodyReport(
            state="available",
            reason="",
            observation_window_hours=window_hours,
            instances=tuple(instances),
            unattributed_authentication_failures=evidence.unattributed_auth_count,
            last_unattributed_authentication_failure=_format_time(
                evidence.last_unattributed_auth
            ),
            event_rows_truncated=evidence.truncated,
        )
    except sqlite3.Error as exc:
        reason = "database_busy" if "locked" in str(exc).lower() else "database_unreadable"
        return ConnectorCustodyReport("unavailable", reason, window_hours)
    except (OSError, ValueError, TypeError):
        return ConnectorCustodyReport("unavailable", "invalid_ledger", window_hours)
    finally:
        if store is not None:
            store.close()


def _table_exists(db: sqlite3.Connection, table: str) -> bool:
    row = db.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
    ).fetchone()
    return row is not None


def _columns(db: sqlite3.Connection, table: str) -> frozenset[str]:
    return frozenset(str(row[1]) for row in db.execute(f"PRAGMA table_info({table})"))


def _normalize_instance(raw: tuple[Any, ...]) -> tuple[str, str, str, str, bool] | None:
    if len(raw) != 5:
        return None
    connector_id, connector, custody, profile_version, is_default = raw
    if not all(isinstance(value, str) for value in raw[:4]):
        return None
    if len(connector_id) != 36 or not _CONNECTOR_TOKEN.fullmatch(connector):
        return None
    if custody not in _CUSTODY_VALUES or not (1 <= len(profile_version) <= 128):
        return None
    if is_default not in (0, 1):
        return None
    return connector_id, connector, custody, profile_version, bool(is_default)


def _load_recent_evidence(db: sqlite3.Connection, now: datetime) -> _Evidence:
    evidence = _Evidence({}, {}, {}, {}, {})
    if not _table_exists(db, "audit_events"):
        return evidence
    required = {
        "id",
        "timestamp",
        "event_name",
        "connector",
        "request_id",
        "projected_record_json",
    }
    if not required.issubset(_columns(db, "audit_events")):
        return evidence
    cutoff = _format_time(now - _WINDOW)
    rows = db.execute(
        """SELECT id, timestamp, event_name, connector, request_id,
                  projected_record_json
             FROM audit_events
            WHERE event_name IN (?, ?, ?) AND timestamp >= ?
            ORDER BY timestamp DESC, id DESC
            LIMIT ?""",
        (*_EVENT_NAMES, cutoff, _MAX_EVENT_ROWS + 1),
    ).fetchall()
    if len(rows) > _MAX_EVENT_ROWS:
        evidence.truncated = True
        rows = rows[:_MAX_EVENT_ROWS]
    for record_id, timestamp, event_name, connector_raw, request_id, projected in rows:
        when = _parse_time(timestamp)
        if when is None or not isinstance(event_name, str):
            continue
        connector = (
            connector_raw
            if isinstance(connector_raw, str) and _CONNECTOR_TOKEN.fullmatch(connector_raw)
            else ""
        )
        if event_name == "telemetry.authentication.failed":
            if connector and connector != "unknown":
                evidence.auth_count[connector] = evidence.auth_count.get(connector, 0) + 1
                evidence.last_auth[connector] = max(when, evidence.last_auth.get(connector, when))
            else:
                evidence.unattributed_auth_count += 1
                if evidence.last_unattributed_auth is None or when > evidence.last_unattributed_auth:
                    evidence.last_unattributed_auth = when
            continue
        facts = _telemetry_facts(projected)
        signal = facts.get("signal", "")
        count = facts.get("record_count", 0)
        if not connector or signal not in _SIGNALS or not isinstance(count, int) or count <= 0:
            continue
        request = request_id if isinstance(request_id, str) and request_id else str(record_id)
        key = (connector, request, signal)
        if event_name == "telemetry.batch.normalized":
            evidence.normalized[key] = max(count, evidence.normalized.get(key, 0))
            evidence.last_native[connector] = max(when, evidence.last_native.get(connector, when))
        elif event_name == "telemetry.records.dropped":
            evidence.dropped[key] = evidence.dropped.get(key, 0) + count
    return evidence


def _telemetry_facts(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, str) or not raw or len(raw) > _MAX_BACKUP_BYTES:
        return {}
    try:
        record = json.loads(raw)
    except (json.JSONDecodeError, ValueError, TypeError):
        return {}
    if not isinstance(record, dict):
        return {}
    attributes = record.get("body")
    if not isinstance(attributes, dict):
        return {}
    count = attributes.get("defenseclaw.telemetry.record_count")
    signal = attributes.get("defenseclaw.telemetry.signal")
    if (
        isinstance(count, bool)
        or not isinstance(count, (int, float))
        or not math.isfinite(count)
    ):
        count = 0
    elif int(count) != count or count < 0:
        count = 0
    else:
        count = int(count)
    return {"record_count": count, "signal": signal if isinstance(signal, str) else ""}


def _batch_counts(evidence: _Evidence, connector: str) -> tuple[int, int]:
    batches = 0
    drop_only = 0
    for key, count in evidence.normalized.items():
        if key[0] != connector:
            continue
        batches += 1
        if count > 0 and evidence.dropped.get(key, 0) >= count:
            drop_only += 1
    return batches, drop_only


def _credential_state(last_auth: datetime | None, last_native: datetime | None) -> str:
    if last_auth is None:
        return "no_recent_failure"
    if last_native is not None and last_native > last_auth:
        return "recovered"
    return "invalid"


def _managed_config_state(
    data_dir: Path, connector: str, custody: str, is_default: bool
) -> tuple[str, int]:
    if custody != "defenseclaw" or not is_default:
        return "not_applicable", 0
    directory = data_dir / "connector_backups" / connector
    try:
        info = directory.lstat()
    except FileNotFoundError:
        return "untracked", 0
    except OSError:
        return "unverifiable", 0
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        return "unverifiable", 0
    try:
        candidates = sorted(directory.iterdir(), key=lambda item: item.name)
    except OSError:
        return "unverifiable", 0
    backups = [item for item in candidates if item.suffix == ".json"]
    if not backups:
        return "untracked", 0
    if len(backups) > _MAX_BACKUPS:
        return "unverifiable", len(backups)
    verified = 0
    for backup in backups:
        state = _verify_managed_backup(backup, connector)
        if state == "drifted":
            return "drifted", len(backups)
        if state != "verified":
            return "unverifiable", len(backups)
        verified += 1
    return "verified", verified


def _verify_managed_backup(path: Path, connector: str) -> str:
    try:
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            return "unverifiable"
        if info.st_size <= 0 or info.st_size > _MAX_BACKUP_BYTES:
            return "unverifiable"
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError, TypeError):
        return "unverifiable"
    if not isinstance(payload, dict) or payload.get("version") != 1:
        return "unverifiable"
    if payload.get("connector") != connector:
        return "unverifiable"
    target_raw = payload.get("path")
    expected = payload.get("post_sha256")
    if not isinstance(target_raw, str) or not target_raw or not isinstance(expected, str):
        return "unverifiable"
    if expected != "missing" and not _SHA256.fullmatch(expected):
        return "unverifiable"
    target = Path(target_raw)
    if not target.is_absolute():
        return "unverifiable"
    try:
        target_info = target.lstat()
    except FileNotFoundError:
        actual = "missing"
    except OSError:
        return "unverifiable"
    else:
        if stat.S_ISLNK(target_info.st_mode) or not stat.S_ISREG(target_info.st_mode):
            return "drifted"
        if target_info.st_size > _MAX_MANAGED_TARGET_BYTES:
            return "unverifiable"
        actual = _sha256_file(target)
        if not actual:
            return "unverifiable"
    return "verified" if actual == expected else "drifted"


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(128 * 1024), b""):
                digest.update(chunk)
    except OSError:
        return ""
    return digest.hexdigest()


def _parse_time(raw: Any) -> datetime | None:
    if not isinstance(raw, str) or not raw or len(raw) > 64:
        return None
    value = raw[:-1] + "+00:00" if raw.endswith("Z") else raw
    try:
        return _utc(datetime.fromisoformat(value))
    except (ValueError, OverflowError):
        return None


def _format_time(value: datetime | None) -> str:
    if value is None:
        return ""
    return _utc(value).isoformat(timespec="seconds").replace("+00:00", "Z")


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


__all__ = [
    "ConnectorCustodyReport",
    "ConnectorCustodyStatus",
    "inspect_connector_custody",
]
