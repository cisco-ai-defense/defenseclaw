from __future__ import annotations

import hashlib
import importlib.util
import json
import sqlite3
from pathlib import Path
from types import ModuleType

import pytest


def _load_projector() -> ModuleType:
    path = (
        Path(__file__).parents[2]
        / "scripts"
        / "live-connector-e2e"
        / "project-audit-events.py"
    )
    spec = importlib.util.spec_from_file_location("project_audit_events", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PROJECTOR = _load_projector()


def _record(*, schema_version: object = 1, would_block: object = False) -> dict[str, object]:
    return {
        "schema_version": schema_version,
        "record_id": "record-1",
        "bucket": "guardrail.evaluation",
        "event_name": "hook_decision",
        "source": "connector",
        "signal": "logs",
        "connector": "claudecode",
        "correlation": {
            "request_id": "request-1",
            "session_id": "session-1",
            "turn_id": "turn-1",
        },
        "body": {
            "defenseclaw.guardrail.would_block": would_block,
            "defenseclaw.guardrail.enforced": False,
        },
    }


def _database(
    path: Path,
    *,
    record: dict[str, object] | None = None,
    projected_raw: str | None = None,
    payload_raw: str | None = None,
    projection_hash: str | None = None,
    indexed_connector: str | None = "claudecode",
) -> str:
    record = record or _record()
    raw = projected_raw if projected_raw is not None else json.dumps(record, separators=(",", ":"))
    body = record.get("body")
    payload = payload_raw if payload_raw is not None else json.dumps(body, separators=(",", ":"))
    digest = projection_hash or "sha256:" + hashlib.sha256(raw.encode()).hexdigest()
    correlation = record["correlation"]
    assert isinstance(correlation, dict)
    connection = sqlite3.connect(path)
    connection.execute(
        """CREATE TABLE audit_events (
               id TEXT, bucket TEXT, event_name TEXT, source TEXT, signal TEXT,
               connector TEXT, request_id TEXT, session_id TEXT, turn_id TEXT,
               record_schema_version INTEGER, payload_json TEXT,
               projected_record_json TEXT, projection_hash TEXT
           )"""
    )
    connection.execute(
        "INSERT INTO audit_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)",
        (
            record.get("record_id"),
            record.get("bucket"),
            record.get("event_name"),
            record.get("source"),
            record.get("signal"),
            indexed_connector,
            correlation.get("request_id"),
            correlation.get("session_id"),
            correlation.get("turn_id"),
            payload,
            raw,
            digest,
        ),
    )
    connection.commit()
    connection.close()
    return raw


def test_projects_exact_stored_record(tmp_path: Path) -> None:
    database = tmp_path / "audit.db"
    expected = _database(database)

    assert PROJECTOR._read_projected_records(database) == [expected]

    output = tmp_path / "projection.jsonl"
    PROJECTOR._replace_jsonl(output, [expected])
    assert output.read_text(encoding="utf-8") == expected + "\n"


def test_retries_busy_and_locked_before_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = tmp_path / "audit.db"
    expected = _database(database)
    real_connect = PROJECTOR.sqlite3.connect
    attempts = 0
    delays: list[float] = []

    def flaky_connect(*args: object, **kwargs: object) -> sqlite3.Connection:
        nonlocal attempts
        attempts += 1
        if attempts <= 2:
            error = sqlite3.OperationalError("database is locked")
            error.sqlite_errorcode = (
                sqlite3.SQLITE_BUSY if attempts == 1 else sqlite3.SQLITE_LOCKED
            )
            raise error
        return real_connect(*args, **kwargs)

    monkeypatch.setattr(PROJECTOR.sqlite3, "connect", flaky_connect)
    monkeypatch.setattr(PROJECTOR.time, "sleep", delays.append)

    assert PROJECTOR._read_projected_records(database) == [expected]
    assert attempts == 3
    assert delays == [0.05, 0.1]


def test_permanent_busy_is_fatal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    database = tmp_path / "audit.db"
    database.touch()
    attempts = 0

    def busy_connect(*_args: object, **_kwargs: object) -> sqlite3.Connection:
        nonlocal attempts
        attempts += 1
        error = sqlite3.OperationalError("database is busy")
        error.sqlite_errorcode = sqlite3.SQLITE_BUSY
        raise error

    monkeypatch.setattr(PROJECTOR.sqlite3, "connect", busy_connect)
    monkeypatch.setattr(PROJECTOR.time, "sleep", lambda _delay: None)

    with pytest.raises(sqlite3.OperationalError, match="database is busy"):
        PROJECTOR._read_projected_records(database)
    assert attempts == 3


@pytest.mark.parametrize(
    ("record", "projected_raw", "payload_raw", "projection_hash", "connector"),
    [
        (_record(), "", None, None, "claudecode"),
        (_record(), "{", None, None, "claudecode"),
        (_record(schema_version=2), None, None, None, "claudecode"),
        (_record(schema_version=True), None, None, None, "claudecode"),
        (_record(would_block="false"), None, None, None, "claudecode"),
        (_record(), None, "{}", None, "claudecode"),
        (
            _record(),
            None,
            '{"defenseclaw.guardrail.would_block":0,'
            '"defenseclaw.guardrail.enforced":false}',
            None,
            "claudecode",
        ),
        (_record(), None, None, "sha256:" + "0" * 64, "claudecode"),
        (_record(), None, None, None, "cursor"),
        ({**_record(), "connector": ""}, None, None, None, None),
    ],
)
def test_corrupt_projection_fails_closed(
    tmp_path: Path,
    record: dict[str, object],
    projected_raw: str | None,
    payload_raw: str | None,
    projection_hash: str | None,
    connector: str | None,
) -> None:
    database = tmp_path / "audit.db"
    _database(
        database,
        record=record,
        projected_raw=projected_raw,
        payload_raw=payload_raw,
        projection_hash=projection_hash,
        indexed_connector=connector,
    )

    with pytest.raises(ValueError):
        PROJECTOR._read_projected_records(database)
