# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Deterministic query-count regression coverage for TUI refreshes."""

from __future__ import annotations

import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from defenseclaw.tui.services.read_repository import TUIReadRepository

from scripts.benchmark_tui_refresh import (
    SQLTrace,
    append_synthetic_v8_event,
    create_synthetic_v8_database,
    run_refresh_benchmark,
    trace_repository_connections,
)


async def test_shared_snapshot_reads_history_once_per_sqlite_generation(tmp_path) -> None:
    result = await run_refresh_benchmark(tmp_path / "audit.db", row_count=32)

    assert result.first_history_selects == 1
    assert result.unchanged_history_selects == 0
    assert result.external_commit_history_selects == 1
    assert result.total_history_selects == 2
    assert result.first_changed is True
    assert result.unchanged_changed is False
    assert result.external_commit_changed is True
    assert result.initial_rows == 32
    assert result.final_rows == 33
    assert result.derived_counts == {
        "history": 33,
        "alert_events": 25,
        "egress_events": 9,
        "mutations": 16,
        "log_verdict_rows": 16,
        "log_otel_rows": 33,
    }
    assert result.errors == ("", "", "")


async def test_connector_stats_refresh_with_each_sqlite_generation(tmp_path) -> None:
    path = tmp_path / "audit.db"
    create_synthetic_v8_database(path, 1)

    def insert_hook(event_id: str, timestamp: str) -> None:
        with sqlite3.connect(path) as connection:
            connection.execute(
                """INSERT INTO audit_events
                       (id, timestamp, action, actor, details, connector)
                   VALUES (?, ?, 'connector-hook', 'codex',
                           ' action=block severity=HIGH ', 'codex')""",
                (event_id, timestamp),
            )
            connection.commit()

    insert_hook("hook-1", "2026-07-10T00:00:00Z")
    repository = TUIReadRepository(path)
    try:
        first = await repository.refresh()
        assert first.snapshot is not None
        assert first.snapshot.connector_hook_stats[0].calls == 1

        insert_hook("hook-2", "2026-07-10T00:00:01Z")
        second = await repository.refresh()
        assert second.snapshot is not None
        assert second.snapshot.connector_hook_stats[0].calls == 2
    finally:
        repository.close()


async def test_repository_open_failures_honor_retry_backoff(tmp_path) -> None:
    repository = TUIReadRepository(tmp_path / "not-created-yet.db")
    try:
        first = await repository.refresh()
        retry_after_first_failure = repository._retry_seconds  # noqa: SLF001
        second = await repository.refresh()

        assert first.error.startswith("database:")
        assert second.error == first.error
        assert repository._retry_seconds == retry_after_first_failure  # noqa: SLF001
    finally:
        repository.close()


async def test_snapshot_carries_session_scoped_scan_count(tmp_path) -> None:
    path = tmp_path / "audit.db"
    create_synthetic_v8_database(path, 1)
    with sqlite3.connect(path) as connection:
        connection.executemany(
            "INSERT INTO scan_results (id, timestamp) VALUES (?, ?)",
            [
                ("old", "2026-07-09T23:59:59Z"),
                ("current", "2026-07-10T00:00:01Z"),
            ],
        )
        connection.commit()
    since = datetime(2026, 7, 10, tzinfo=timezone.utc)
    repository = TUIReadRepository(path)
    try:
        result = await repository.refresh(scan_since=since)
        assert result.snapshot is not None
        assert result.snapshot.session_scan_since == since
        assert result.snapshot.session_scan_count == 1
        assert result.snapshot.enforcement_counts.total_scans == 2
    finally:
        repository.close()


async def test_audit_only_generation_reuses_slow_tool_and_count_components(tmp_path) -> None:
    from defenseclaw.tui.services import read_repository

    path = tmp_path / "audit.db"
    create_synthetic_v8_database(path, 8)
    trace = SQLTrace()
    with trace_repository_connections(read_repository, trace):
        repository = TUIReadRepository(path)
        try:
            await repository.refresh()
            append_synthetic_v8_event(path, 8)
            before_incremental = len(trace.statements)
            incremental = await repository.refresh()
            incremental_sql = trace.statements[before_incremental:]

            before_forced = len(trace.statements)
            await repository.refresh(force=True)
            forced_sql = trace.statements[before_forced:]
        finally:
            repository.close()

    assert incremental.changed is True
    assert not any("FROM actions" in statement for statement in incremental_sql)
    assert not any("FROM scan_results" in statement for statement in incremental_sql)
    assert not any("FROM network_egress_events" in statement for statement in incremental_sql)
    assert any("FROM actions" in statement for statement in forced_sql)
    assert any("FROM scan_results" in statement for statement in forced_sql)
