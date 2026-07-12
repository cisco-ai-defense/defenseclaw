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

"""Single-threaded, generation-aware SQLite reads for the Textual TUI.

The gateway is the audit database writer.  Textual only needs immutable display
snapshots, so this repository owns one read-only connection in one worker
thread, checks ``PRAGMA data_version``, and performs no history work when the
writer has not committed anything new.  A failed refresh retains the previous
snapshot instead of flashing every panel empty.
"""

from __future__ import annotations

import asyncio
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, replace
from datetime import datetime
from pathlib import Path
from time import monotonic

from defenseclaw.db import Store
from defenseclaw.models import ActionEntry, Counts, Event
from defenseclaw.tui.panels.activity import (
    activity_mutations_from_v8_history,
)
from defenseclaw.tui.panels.alerts import AlertEvent, alerts_from_v8_history
from defenseclaw.tui.services.event_models import ActivityMutation, EgressEvent
from defenseclaw.tui.services.gateway_log_views import (
    GatewayLogViews,
    project_v8_log_views,
)
from defenseclaw.tui.services.v8_event_history import (
    V8EventHistoryReader,
    V8EventHistoryRow,
    project_v8_egress_events,
)

_HISTORY_LIMIT = 1000
_PANEL_LIMIT = 500
_SLOW_COMPONENT_TTL_SECONDS = 15.0
_MAX_RETRY_SECONDS = 60.0


@dataclass(frozen=True)
class ConnectorHookStat:
    connector: str
    calls: int = 0
    blocks: int = 0
    alerts: int = 0
    newest: object | None = None


@dataclass(frozen=True)
class TUIReadSnapshot:
    """Immutable payload swapped into panel models on Textual's main loop."""

    revision: int
    data_version: int
    history: tuple[V8EventHistoryRow, ...] = ()
    alert_events: tuple[AlertEvent, ...] = ()
    log_views: GatewayLogViews = GatewayLogViews()
    egress_events: tuple[EgressEvent, ...] = ()
    mutations: tuple[ActivityMutation, ...] = ()
    audit_events: tuple[Event, ...] = ()
    tool_actions: tuple[ActionEntry, ...] = ()
    enforcement_counts: Counts = field(default_factory=Counts)
    session_scan_count: int = 0
    session_scan_since: datetime | None = None
    connector_hook_events: tuple[Event, ...] = ()
    connector_hook_stats: tuple[ConnectorHookStat, ...] = ()


@dataclass(frozen=True)
class TUIReadResult:
    snapshot: TUIReadSnapshot | None
    changed: bool
    error: str = ""


class TUIReadRepository:
    """Own a read connection and serialize all work onto one thread."""

    def __init__(self, db_path: str | Path, *, timeout: float = 0.25) -> None:
        self.db_path = str(db_path)
        self.timeout = timeout
        self._executor = ThreadPoolExecutor(
            max_workers=1,
            thread_name_prefix="defenseclaw-tui-read",
        )
        self._store: Store | None = None
        self._history_reader: V8EventHistoryReader | None = None
        self._snapshot: TUIReadSnapshot | None = None
        self._successful_data_version: int | None = None
        self._revision = 0
        self._closed = False
        self._retry_seconds = 1.0
        self._next_retry_at = 0.0
        self._last_error = ""
        self._hook_stats: tuple[ConnectorHookStat, ...] = ()
        self._slow_components_loaded_at = 0.0

    async def refresh(
        self,
        *,
        force: bool = False,
        scan_since: datetime | None = None,
    ) -> TUIReadResult:
        """Return a new snapshot only when the writer generation changed."""

        if self._closed:
            return TUIReadResult(self._snapshot, False, "TUI read repository is closed")
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            self._executor,
            self._refresh_sync,
            force,
            scan_since,
        )

    def close(self) -> None:
        """Close the connection on its owner thread without blocking teardown."""

        if self._closed:
            return
        self._closed = True
        try:
            self._executor.submit(self._close_sync)
        except RuntimeError:
            pass
        self._executor.shutdown(wait=False, cancel_futures=False)

    def _ensure_open(self) -> Store:
        if self._store is None:
            # sqlite3 keeps its default same-thread guard.  This method only
            # runs inside the repository's single-worker executor.
            self._store = Store.open_read_only(self.db_path, timeout=self.timeout)
            self._history_reader = V8EventHistoryReader(self._store)
        return self._store

    def _refresh_sync(
        self,
        force: bool,
        scan_since: datetime | None,
    ) -> TUIReadResult:
        now = monotonic()
        if not force and self._last_error and now < self._next_retry_at:
            return TUIReadResult(self._snapshot, False, self._last_error)
        try:
            store = self._ensure_open()
            data_version = int(store.db.execute("PRAGMA data_version").fetchone()[0])
        except (OSError, sqlite3.Error, ValueError) as exc:
            return self._failed_result("database", exc)

        slow_components_due = (
            force
            or self._snapshot is None
            or now - self._slow_components_loaded_at >= _SLOW_COMPONENT_TTL_SECONDS
        )
        if (
            not force
            and self._snapshot is not None
            and self._successful_data_version == data_version
            and self._snapshot.session_scan_since == scan_since
            and not slow_components_due
        ):
            return TUIReadResult(self._snapshot, False)

        previous = self._snapshot
        errors: list[str] = []

        history = self._component(
            "history",
            lambda: self._history_reader.load(_HISTORY_LIMIT) if self._history_reader else (),
            previous.history if previous else (),
            errors,
        )
        if errors and previous is not None and history is previous.history:
            alert_events = previous.alert_events
            log_views = previous.log_views
            egress_events = previous.egress_events
            mutations = previous.mutations
        else:
            panel_history = history[:_PANEL_LIMIT]
            alert_events = alerts_from_v8_history(panel_history)
            log_views = project_v8_log_views(history)
            egress_events = project_v8_egress_events(panel_history)
            mutations = activity_mutations_from_v8_history(panel_history)

        audit_events = self._component(
            "audit",
            lambda: tuple(store.list_event_summaries(_PANEL_LIMIT)),
            previous.audit_events if previous else (),
            errors,
        )
        if slow_components_due:
            slow_error_count = len(errors)
            tool_actions = self._component(
                "tools",
                lambda: tuple(store.list_actions_by_type("tool")),
                previous.tool_actions if previous else (),
                errors,
            )
            enforcement_counts = self._component(
                "counts",
                store.get_enforcement_counts,
                previous.enforcement_counts if previous else Counts(),
                errors,
            )
            if len(errors) == slow_error_count:
                self._slow_components_loaded_at = now
        else:
            tool_actions = previous.tool_actions if previous else ()
            enforcement_counts = previous.enforcement_counts if previous else Counts()
        if scan_since is None:
            session_scan_count = enforcement_counts.total_scans
        elif (
            slow_components_due
            or previous is None
            or previous.session_scan_since != scan_since
        ):
            prior_session_scan_count = (
                previous.session_scan_count
                if previous is not None and previous.session_scan_since == scan_since
                else enforcement_counts.total_scans
            )
            session_scan_count = self._component(
                "session scans",
                lambda: store.count_scan_results_since(scan_since),
                prior_session_scan_count,
                errors,
            )
        else:
            session_scan_count = previous.session_scan_count
        connector_hook_events = self._component(
            "connector hooks",
            lambda: tuple(store.list_connector_hook_event_summaries(_PANEL_LIMIT)),
            previous.connector_hook_events if previous else (),
            errors,
        )
        connector_hook_stats = self._load_hook_stats(store, previous, errors)

        candidate = TUIReadSnapshot(
            revision=previous.revision if previous else 0,
            data_version=data_version,
            history=history,
            alert_events=alert_events,
            log_views=log_views,
            egress_events=egress_events,
            mutations=mutations,
            audit_events=audit_events,
            tool_actions=tool_actions,
            enforcement_counts=enforcement_counts,
            session_scan_count=session_scan_count,
            session_scan_since=scan_since,
            connector_hook_events=connector_hook_events,
            connector_hook_stats=connector_hook_stats,
        )
        changed = candidate != previous
        if changed:
            self._revision += 1
            candidate = replace(candidate, revision=self._revision)
            self._snapshot = candidate

        if errors:
            error = "; ".join(errors)
            self._record_failure(error)
            return TUIReadResult(self._snapshot, changed, error)

        self._successful_data_version = data_version
        self._last_error = ""
        self._next_retry_at = 0.0
        self._retry_seconds = 1.0
        return TUIReadResult(self._snapshot, changed)

    def _load_hook_stats(
        self,
        store: Store,
        previous: TUIReadSnapshot | None,
        errors: list[str],
    ) -> tuple[ConnectorHookStat, ...]:
        fallback = previous.connector_hook_stats if previous else self._hook_stats

        def load() -> tuple[ConnectorHookStat, ...]:
            raw = store.connector_hook_event_stats()
            return tuple(
                ConnectorHookStat(
                    connector=str(connector or "").strip().lower(),
                    calls=int(values.get("calls") or 0),
                    blocks=int(values.get("blocks") or 0),
                    alerts=int(values.get("alerts") or 0),
                    newest=values.get("newest"),
                )
                for connector, values in sorted(raw.items())
                if str(connector or "").strip()
            )

        loaded = self._component("connector stats", load, fallback, errors)
        if loaded is not fallback or not errors:
            self._hook_stats = loaded
        return loaded

    @staticmethod
    def _component(name: str, loader, fallback, errors: list[str]):  # type: ignore[no-untyped-def]
        try:
            return loader()
        except (OSError, sqlite3.Error, ValueError, TypeError) as exc:
            errors.append(f"{name}: {type(exc).__name__}: {str(exc)[:160]}")
            return fallback

    def _failed_result(self, name: str, exc: BaseException) -> TUIReadResult:
        error = f"{name}: {type(exc).__name__}: {str(exc)[:160]}"
        self._record_failure(error)
        return TUIReadResult(self._snapshot, False, error)

    def _record_failure(self, error: str) -> None:
        self._last_error = error
        self._next_retry_at = monotonic() + self._retry_seconds
        self._retry_seconds = min(self._retry_seconds * 2.0, _MAX_RETRY_SECONDS)

    def _close_sync(self) -> None:
        if self._store is not None:
            self._store.close()
            self._store = None
            self._history_reader = None


__all__ = [
    "ConnectorHookStat",
    "TUIReadRepository",
    "TUIReadResult",
    "TUIReadSnapshot",
]
