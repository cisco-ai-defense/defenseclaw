#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Exercise the TUI's generation-aware SQLite refresh path.

This is deliberately a query-count benchmark, not a wall-clock gate.  Local
machine load makes latency thresholds noisy in CI, while the invariant that
matters here is stable: one canonical history SELECT for each observed SQLite
generation and no history SELECT for an unchanged generation.

Run from the repository root::

    python scripts/benchmark_tui_refresh.py --rows 1000
"""

from __future__ import annotations

import argparse
import asyncio
import inspect
import json
import re
import sqlite3
import sys
import tempfile
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from time import perf_counter
from typing import Any

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
CLI_ROOT = REPOSITORY_ROOT / "cli"
if str(CLI_ROOT) not in sys.path:
    sys.path.insert(0, str(CLI_ROOT))


_AUDIT_SCHEMA = """
CREATE TABLE audit_events (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT,
    actor TEXT NOT NULL DEFAULT 'defenseclaw',
    details TEXT,
    structured_json TEXT,
    severity TEXT,
    run_id TEXT,
    connector TEXT,
    step_idx INTEGER,
    enforced INTEGER,
    rule_pack_dir TEXT,
    bucket TEXT,
    event_name TEXT,
    source TEXT,
    signal TEXT,
    payload_json TEXT,
    projected_record_json TEXT,
    redaction_profile TEXT,
    trace_id TEXT,
    request_id TEXT,
    session_id TEXT,
    turn_id TEXT,
    scan_id TEXT,
    finding_id TEXT
);
CREATE INDEX idx_audit_timestamp ON audit_events(timestamp);
CREATE INDEX idx_audit_signal_timestamp ON audit_events(signal, timestamp DESC);
CREATE INDEX idx_audit_bucket_timestamp ON audit_events(bucket, timestamp DESC);

CREATE TABLE actions (
    id TEXT PRIMARY KEY,
    target_type TEXT NOT NULL,
    target_name TEXT NOT NULL,
    source_path TEXT,
    actions_json TEXT NOT NULL DEFAULT '{}',
    reason TEXT,
    updated_at TEXT NOT NULL,
    connector TEXT NOT NULL DEFAULT ''
);
CREATE TABLE scan_results (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL
);
CREATE TABLE network_egress_events (
    id TEXT PRIMARY KEY,
    blocked INTEGER NOT NULL DEFAULT 0
);
"""

_INSERT_EVENT = """
INSERT INTO audit_events (
    id, timestamp, action, target, actor, details, structured_json, severity,
    run_id, connector, step_idx, enforced, rule_pack_dir, bucket, event_name,
    source, signal, payload_json, projected_record_json, redaction_profile,
    trace_id, request_id, session_id, turn_id, scan_id, finding_id
) VALUES (
    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
)
"""

_HISTORY_SELECT_RE = re.compile(
    r"\bFROM\s+[\"`\[]?audit_events(?:[\"`\]]|\b)",
    re.IGNORECASE,
)
_RAW_SQLITE_CONNECT = sqlite3.connect


@dataclass
class SQLTrace:
    """Statements observed on repository-owned SQLite connections."""

    statements: list[str] = field(default_factory=list)

    def __call__(self, statement: str) -> None:
        self.statements.append(statement)

    @property
    def canonical_history_selects(self) -> tuple[str, ...]:
        return tuple(
            statement
            for statement in self.statements
            if statement.lstrip().upper().startswith("SELECT")
            and _HISTORY_SELECT_RE.search(statement)
            and "projected_record_json" in statement.lower()
            and "payload_json" in statement.lower()
        )

    @property
    def select_statements(self) -> tuple[str, ...]:
        return tuple(
            statement
            for statement in self.statements
            if statement.lstrip().upper().startswith("SELECT")
        )

    @property
    def data_version_reads(self) -> tuple[str, ...]:
        return tuple(
            statement
            for statement in self.statements
            if statement.lstrip().upper().startswith("PRAGMA DATA_VERSION")
        )


@dataclass(frozen=True)
class RefreshBenchmarkResult:
    """Deterministic outcome plus observational latency from one scenario."""

    initial_rows: int
    final_rows: int
    first_changed: bool
    unchanged_changed: bool
    external_commit_changed: bool
    first_history_selects: int
    unchanged_history_selects: int
    external_commit_history_selects: int
    total_history_selects: int
    total_selects: int
    total_sql_statements: int
    data_version_reads: int
    first_data_version: int
    unchanged_data_version: int
    external_commit_data_version: int
    appended_event_visible: bool
    errors: tuple[str, str, str]
    derived_counts: dict[str, int]
    elapsed_ms: tuple[float, float, float]

    def verify(self) -> None:
        """Raise when generation-aware refresh regresses."""

        assert self.first_changed is True
        assert self.unchanged_changed is False
        assert self.external_commit_changed is True
        assert self.first_history_selects == 1
        assert self.unchanged_history_selects == 0
        assert self.external_commit_history_selects == 1
        assert self.total_history_selects == 2
        assert self.initial_rows > 0
        assert self.final_rows in {self.initial_rows, self.initial_rows + 1}
        assert self.appended_event_visible is True
        assert self.first_data_version == self.unchanged_data_version
        assert self.external_commit_data_version != self.unchanged_data_version
        assert self.errors == ("", "", "")

    def as_dict(self) -> dict[str, Any]:
        return {
            "rows": {"initial": self.initial_rows, "final": self.final_rows},
            "changed": {
                "initial": self.first_changed,
                "unchanged": self.unchanged_changed,
                "external_commit": self.external_commit_changed,
            },
            "history_selects": {
                "initial": self.first_history_selects,
                "unchanged": self.unchanged_history_selects,
                "external_commit": self.external_commit_history_selects,
                "total": self.total_history_selects,
            },
            "sql_trace": {
                "selects": self.total_selects,
                "statements": self.total_sql_statements,
            },
            "data_version_reads": self.data_version_reads,
            "data_versions": {
                "initial": self.first_data_version,
                "unchanged": self.unchanged_data_version,
                "external_commit": self.external_commit_data_version,
            },
            "appended_event_visible": self.appended_event_visible,
            "errors": self.errors,
            "derived_counts": self.derived_counts,
            "elapsed_ms_observational": {
                "initial": round(self.elapsed_ms[0], 3),
                "unchanged": round(self.elapsed_ms[1], 3),
                "external_commit": round(self.elapsed_ms[2], 3),
            },
        }


def _event_values(index: int) -> tuple[Any, ...]:
    """Return one varied but bounded canonical v8 audit row."""

    timestamp = datetime(2026, 7, 10, tzinfo=timezone.utc) + timedelta(milliseconds=index)
    kind = index % 4
    event_id = f"event-{index:06d}"
    common = {
        "defenseclaw.agent.id": f"agent-{index % 7}",
        "defenseclaw.connector": "codex",
    }
    if kind == 0:
        bucket = "network.egress"
        event_name = "egress.allowed"
        action = "allow"
        severity = "INFO"
        details = "LLM-shaped request allowed through shape branch"
        payload = {
            **common,
            "defenseclaw.network.target_ref": f"api-{index % 11}.example.test",
            "defenseclaw.network.target_path": "/v1/chat/completions",
            "defenseclaw.network.body_shape": "chat.completions",
            "defenseclaw.network.looks_like_llm": True,
            "defenseclaw.network.branch": "shape",
            "defenseclaw.network.decision": "allow",
            "defenseclaw.network.reason": "synthetic benchmark row",
        }
    elif kind == 1:
        bucket = "security.finding"
        event_name = "finding.observed"
        action = "finding.observed"
        severity = "HIGH"
        details = "unsafe synthetic capability"
        payload = {
            **common,
            "defenseclaw.finding.rule_id": f"BENCH-{index % 13:03d}",
            "defenseclaw.finding.target_ref": f"skill:synthetic-{index % 17}",
            "defenseclaw.finding.description": details,
            "defenseclaw.security.severity": severity,
        }
    elif kind == 2:
        bucket = "compliance.activity"
        event_name = "config.change.applied"
        action = "config.change"
        severity = "INFO"
        details = "synthetic config generation applied"
        payload = {
            **common,
            "defenseclaw.operator.id": "operator:benchmark",
            "defenseclaw.config.path": f"connectors.synthetic_{index % 5}",
            "defenseclaw.config.generation.previous": index,
            "defenseclaw.config.generation": index + 1,
        }
    else:
        bucket = "enforcement.action"
        event_name = "enforcement.blocked"
        action = "block"
        severity = "CRITICAL"
        details = "synthetic policy block"
        payload = {
            **common,
            "defenseclaw.enforcement.id": f"enforcement-{index:06d}",
            "defenseclaw.enforcement.target_ref": f"tool:synthetic-{index % 19}",
            "defenseclaw.enforcement.effective_action": "block",
            "defenseclaw.guardrail.reason": details,
        }

    trace_id = f"{index:032x}"[-32:]
    projection = {
        "outcome": "blocked" if action == "block" else "allowed",
        "correlation": {"trace_id": trace_id, "span_id": f"{index:016x}"[-16:]},
    }
    scan_id = f"scan-{index // 4:06d}" if bucket == "security.finding" else ""
    finding_id = event_id if bucket == "security.finding" else ""
    return (
        event_id,
        timestamp.isoformat().replace("+00:00", "Z"),
        action,
        f"synthetic:{index}",
        "operator:benchmark",
        details,
        json.dumps({"benchmark": True, "index": index}, separators=(",", ":")),
        severity,
        f"run-{index // 100:04d}",
        "codex",
        index,
        int(action == "block"),
        "",
        bucket,
        event_name,
        "benchmark",
        "logs",
        json.dumps(payload, separators=(",", ":"), sort_keys=True),
        json.dumps(projection, separators=(",", ":"), sort_keys=True),
        "strict",
        trace_id,
        f"request-{index:06d}",
        f"session-{index % 9}",
        f"turn-{index:06d}",
        scan_id,
        finding_id,
    )


def create_synthetic_v8_database(path: Path, row_count: int) -> None:
    """Create a canonical-history-only database for refresh regression tests."""

    if row_count < 1:
        raise ValueError("row_count must be positive")
    connection = _RAW_SQLITE_CONNECT(path)
    try:
        connection.executescript(_AUDIT_SCHEMA)
        connection.executemany(_INSERT_EVENT, (_event_values(index) for index in range(row_count)))
        connection.commit()
    finally:
        connection.close()


def append_synthetic_v8_event(path: Path, index: int) -> None:
    """Commit a row through a second connection so ``data_version`` changes."""

    connection = _RAW_SQLITE_CONNECT(path)
    try:
        connection.execute(_INSERT_EVENT, _event_values(index))
        connection.commit()
    finally:
        connection.close()


@contextmanager
def trace_repository_connections(repository_module: Any, trace: SQLTrace) -> Iterator[None]:
    """Attach a trace callback to connections opened by ``read_repository``."""

    sqlite_module = getattr(repository_module, "sqlite3", sqlite3)
    original_connect: Callable[..., sqlite3.Connection] = sqlite_module.connect

    def traced_connect(*args: Any, **kwargs: Any) -> sqlite3.Connection:
        connection = original_connect(*args, **kwargs)
        connection.set_trace_callback(trace)
        return connection

    sqlite_module.connect = traced_connect
    try:
        yield
    finally:
        sqlite_module.connect = original_connect


def _derived_counts(snapshot: Any) -> dict[str, int]:
    """Report whichever public shared projections the snapshot exposes."""

    counts: dict[str, int] = {"history": len(snapshot.history)}
    for name in ("alert_events", "egress_events", "mutations"):
        value = getattr(snapshot, name, None)
        if value is not None:
            counts[name] = len(value)
    log_views = getattr(snapshot, "log_views", None)
    if log_views is not None:
        counts["log_verdict_rows"] = len(log_views.verdict_rows)
        counts["log_otel_rows"] = len(log_views.otel_rows)
    return counts


async def _close_repository(repository: Any) -> None:
    closed = repository.close()
    if inspect.isawaitable(closed):
        await closed


async def run_refresh_benchmark(path: Path, row_count: int = 1000) -> RefreshBenchmarkResult:
    """Run initial, unchanged, and externally changed repository refreshes."""

    from defenseclaw.tui.services import read_repository

    create_synthetic_v8_database(path, row_count)
    trace = SQLTrace()
    repository = None
    with trace_repository_connections(read_repository, trace):
        repository = read_repository.TUIReadRepository(path, timeout=0.25)
        try:
            started = perf_counter()
            first = await repository.refresh()
            first_ms = (perf_counter() - started) * 1000
            first_selects = len(trace.canonical_history_selects)

            started = perf_counter()
            unchanged = await repository.refresh()
            unchanged_ms = (perf_counter() - started) * 1000
            unchanged_selects = len(trace.canonical_history_selects) - first_selects

            append_synthetic_v8_event(path, row_count)
            before_changed = len(trace.canonical_history_selects)
            started = perf_counter()
            external_commit = await repository.refresh()
            external_ms = (perf_counter() - started) * 1000
            external_selects = len(trace.canonical_history_selects) - before_changed
        finally:
            if repository is not None:
                await _close_repository(repository)

    first_snapshot = first.snapshot
    unchanged_snapshot = unchanged.snapshot
    external_snapshot = external_commit.snapshot
    result = RefreshBenchmarkResult(
        initial_rows=len(first_snapshot.history),
        final_rows=len(external_snapshot.history),
        first_changed=first.changed,
        unchanged_changed=unchanged.changed,
        external_commit_changed=external_commit.changed,
        first_history_selects=first_selects,
        unchanged_history_selects=unchanged_selects,
        external_commit_history_selects=external_selects,
        total_history_selects=len(trace.canonical_history_selects),
        total_selects=len(trace.select_statements),
        total_sql_statements=len(trace.statements),
        data_version_reads=len(trace.data_version_reads),
        first_data_version=first_snapshot.data_version,
        unchanged_data_version=unchanged_snapshot.data_version,
        external_commit_data_version=external_snapshot.data_version,
        appended_event_visible=any(row.id == f"event-{row_count:06d}" for row in external_snapshot.history),
        errors=(first.error, unchanged.error, external_commit.error),
        derived_counts=_derived_counts(external_snapshot),
        elapsed_ms=(first_ms, unchanged_ms, external_ms),
    )
    result.verify()
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rows", type=int, default=500, help="synthetic rows before the external commit")
    parser.add_argument("--db", type=Path, help="database path (default: temporary directory)")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.db:
        args.db.parent.mkdir(parents=True, exist_ok=True)
        if args.db.exists():
            args.db.unlink()
        result = asyncio.run(run_refresh_benchmark(args.db, args.rows))
    else:
        with tempfile.TemporaryDirectory(prefix="defenseclaw-tui-refresh-") as directory:
            result = asyncio.run(run_refresh_benchmark(Path(directory) / "audit.db", args.rows))

    payload = result.as_dict()
    if args.json:
        print(json.dumps(payload, sort_keys=True))
    else:
        print(json.dumps(payload, indent=2, sort_keys=True))
        print("PASS: one canonical history SELECT per changed SQLite generation")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
