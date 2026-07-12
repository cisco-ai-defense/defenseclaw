# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import sqlite3
from pathlib import Path

from defenseclaw import config as config_module
from defenseclaw.tui.services.judge_history import (
    read_judge_response_history,
    resolve_judge_history_paths,
)


def _create_history_db(path: Path, *, raw_column: str = "raw_response") -> None:
    with sqlite3.connect(path) as db:
        db.execute(
            f"""
            CREATE TABLE judge_responses (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                kind TEXT,
                direction TEXT,
                action TEXT,
                severity TEXT,
                latency_ms INTEGER,
                inspected_model TEXT,
                model TEXT,
                request_id TEXT,
                trace_id TEXT,
                run_id TEXT,
                input_hash TEXT,
                confidence REAL,
                fail_closed_applied INTEGER,
                prompt_template_id TEXT,
                parse_error TEXT,
                {raw_column} TEXT
            )
            """
        )


def _insert_history_row(
    path: Path,
    *,
    stable_id: str,
    timestamp: str,
    request_id: str,
    raw: str,
    raw_column: str = "raw_response",
) -> None:
    with sqlite3.connect(path) as db:
        db.execute(
            f"""
            INSERT INTO judge_responses (
                id, timestamp, kind, direction, action, severity, latency_ms,
                inspected_model, model, request_id, trace_id, run_id,
                input_hash, confidence, fail_closed_applied,
                prompt_template_id, parse_error, {raw_column}
            ) VALUES (?, ?, 'pii', 'prompt', 'block', 'HIGH', 17,
                      'gpt-inspected', 'judge-model', ?, 'trace-1', 'run-1',
                      'sha256:input', 0.91, 1, 'template-1', '', ?)
            """,
            (stable_id, timestamp, request_id, raw),
        )


def test_reads_v8_authoritative_rows_from_active_config_yaml(
    tmp_path: Path,
    monkeypatch,
) -> None:
    judge_db = tmp_path / "forensics" / "judge-bodies.sqlite"
    judge_db.parent.mkdir()
    audit_db = tmp_path / "audit.sqlite"
    _create_history_db(judge_db)
    _create_history_db(audit_db)
    _insert_history_row(
        judge_db,
        stable_id="judge-new",
        timestamp="2026-07-03T12:00:00Z",
        request_id="req-authoritative",
        raw='{"source":"judge_bodies"}',
    )

    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "\n".join(
            (
                "config_version: 8",
                f"data_dir: {tmp_path}",
                "observability:",
                "  local:",
                f"    path: {audit_db}",
                f"    judge_bodies_path: {judge_db}",
                "",
            )
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("DEFENSECLAW_CONFIG", str(config_path))
    loaded = config_module.load()

    paths = resolve_judge_history_paths(loaded)
    rows, error = read_judge_response_history(loaded)

    assert paths.authoritative == judge_db
    assert paths.legacy == audit_db
    assert error == ""
    assert len(rows) == 1
    assert rows[0]["id"] == "judge-new"
    assert rows[0]["request_id"] == "req-authoritative"
    assert rows[0]["raw"] == '{"source":"judge_bodies"}'


def test_falls_back_to_v7_audit_rows_and_legacy_raw_column(tmp_path: Path) -> None:
    audit_db = tmp_path / "audit.db"
    _create_history_db(audit_db, raw_column="raw")
    _insert_history_row(
        audit_db,
        stable_id="legacy-only",
        timestamp="2026-07-03T11:00:00Z",
        request_id="req-legacy",
        raw='{"source":"audit"}',
        raw_column="raw",
    )

    rows, error = read_judge_response_history({"audit_db": str(audit_db)})

    assert error == ""
    assert [row["id"] for row in rows] == ["legacy-only"]
    assert rows[0]["raw"] == '{"source":"audit"}'


def test_authoritative_ids_win_and_merged_rows_have_stable_order(tmp_path: Path) -> None:
    judge_db = tmp_path / "judge_bodies.db"
    audit_db = tmp_path / "audit.db"
    _create_history_db(judge_db)
    _create_history_db(audit_db)
    _insert_history_row(
        judge_db,
        stable_id="same-id",
        timestamp="2026-07-03T10:00:00Z",
        request_id="req-authoritative-copy",
        raw='{"copy":"authoritative"}',
    )
    _insert_history_row(
        judge_db,
        stable_id="tie-b",
        timestamp="2026-07-03T12:00:00Z",
        request_id="req-tie-b",
        raw='{"id":"b"}',
    )
    _insert_history_row(
        audit_db,
        stable_id="same-id",
        timestamp="2026-07-03T13:00:00Z",
        request_id="req-stale-legacy-copy",
        raw='{"copy":"legacy"}',
    )
    _insert_history_row(
        audit_db,
        stable_id="tie-a",
        timestamp="2026-07-03T12:00:00Z",
        request_id="req-tie-a",
        raw='{"id":"a"}',
    )
    config = {
        "data_dir": str(tmp_path),
        "observability": {
            "local": {
                "path": str(audit_db),
                "judge_bodies_path": str(judge_db),
            }
        },
    }

    rows, error = read_judge_response_history(config)

    assert error == ""
    assert [row["id"] for row in rows] == ["tie-b", "tie-a", "same-id"]
    duplicate = next(row for row in rows if row["id"] == "same-id")
    assert duplicate["request_id"] == "req-authoritative-copy"
    assert duplicate["raw"] == '{"copy":"authoritative"}'


def test_retention_purge_order_does_not_hide_or_resurrect_rows(tmp_path: Path) -> None:
    judge_db = tmp_path / "judge_bodies.db"
    audit_db = tmp_path / "audit.db"
    _create_history_db(judge_db)
    _create_history_db(audit_db)
    for path in (judge_db, audit_db):
        _insert_history_row(
            path,
            stable_id="retained-id",
            timestamp="2026-07-03T12:00:00Z",
            request_id="req-retained",
            raw=f'{{"database":"{path.name}"}}',
        )
    config = {
        "data_dir": str(tmp_path),
        "observability": {
            "local": {
                "path": str(audit_db),
                "judge_bodies_path": str(judge_db),
            }
        },
    }

    # Retention removes a migrated legacy copy first.  The authoritative row
    # must remain visible throughout that first phase.
    with sqlite3.connect(audit_db) as db:
        db.execute("DELETE FROM judge_responses WHERE id = ?", ("retained-id",))
    rows, error = read_judge_response_history(config)
    assert error == ""
    assert [row["id"] for row in rows] == ["retained-id"]
    assert rows[0]["raw"] == '{"database":"judge_bodies.db"}'

    # Once the authoritative copy is also outside retention, no stale legacy
    # copy remains to make the expired evidence reappear in the TUI.
    with sqlite3.connect(judge_db) as db:
        db.execute("DELETE FROM judge_responses WHERE id = ?", ("retained-id",))
    rows, error = read_judge_response_history(config)
    assert error == ""
    assert rows == ()


def test_limit_is_applied_after_instant_ordering_across_offsets(tmp_path: Path) -> None:
    judge_db = tmp_path / "judge_bodies.db"
    _create_history_db(judge_db)
    for stable_id, timestamp in (
        ("newest", "2026-01-01T09:30:00-03:00"),
        ("middle", "2026-01-01T12:00:00Z"),
        ("oldest", "2026-01-01T13:00:00+02:00"),
    ):
        _insert_history_row(
            judge_db,
            stable_id=stable_id,
            timestamp=timestamp,
            request_id=f"req-{stable_id}",
            raw=f'{{"id":"{stable_id}"}}',
        )

    rows, error = read_judge_response_history(
        {"judge_bodies_db": str(judge_db)},
        limit=2,
    )

    assert error == ""
    assert [row["id"] for row in rows] == ["newest", "middle"]
