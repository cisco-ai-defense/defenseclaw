from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import sqlite3
import subprocess
import sys
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


def _request(database: Path, output: Path) -> str:
    return json.dumps({"audit_db": str(database), "out": str(output)}) + "\n"


def test_serve_answers_every_request_and_survives_rejections(tmp_path: Path) -> None:
    database = tmp_path / "audit.db"
    expected = _database(database)
    first = tmp_path / "first.jsonl"
    second = tmp_path / "second.jsonl"
    requests = io.StringIO(
        _request(database, first)
        + _request(tmp_path / "missing.db", second)
        + "not json\n"
        + json.dumps({"out": str(second)}) + "\n"
        + _request(database, database)
        + _request(database, second)
    )
    responses = io.StringIO()

    assert PROJECTOR.serve(requests, responses) == 0

    answers = [json.loads(line) for line in responses.getvalue().splitlines()]
    assert answers[0] == {"ready": True, "protocol": 1}
    assert answers[1] == {"ok": True}
    assert [answer["ok"] for answer in answers[2:6]] == [False] * 4
    assert "missing" in answers[2]["error"]
    assert "must differ from the audit database" in answers[5]["error"]
    assert answers[6] == {"ok": True}
    assert len(answers) == 7
    assert first.read_text(encoding="utf-8") == expected + "\n"
    assert second.read_text(encoding="utf-8") == expected + "\n"
    assert not second.with_name("missing.db").exists()


def test_serve_streams_records_without_a_snapshot_file(tmp_path: Path) -> None:
    database = tmp_path / "audit.db"
    expected = _database(database)
    stream = json.dumps({"audit_db": str(database)}) + "\n"
    requests = io.StringIO(stream + _request(tmp_path / "missing.db", tmp_path / "x") + stream)
    responses = io.StringIO()

    assert PROJECTOR.serve(requests, responses) == 0

    lines = responses.getvalue().splitlines()
    assert lines[0] == '{"ready":true,"protocol":1}'
    assert lines[1:3] == ['{"ok":true,"records":1}', expected]
    assert json.loads(lines[3])["ok"] is False
    assert lines[4:] == ['{"ok":true,"records":1}', expected]
    assert sorted(p.name for p in tmp_path.iterdir()) == ["audit.db"]


def test_validation_cache_revalidates_changed_rows(tmp_path: Path) -> None:
    database = tmp_path / "audit.db"
    expected = _database(database)
    validated: dict[object, tuple[object, ...]] = {}
    assert PROJECTOR._read_projected_records(database, validated) == [expected]
    assert list(validated) == [1]

    connection = sqlite3.connect(database)
    connection.execute("UPDATE audit_events SET connector = 'codex' WHERE rowid = 1")
    connection.commit()
    connection.close()

    with pytest.raises(ValueError, match="disagrees with indexed connector"):
        PROJECTOR._read_projected_records(database, validated)
    # A rejected read keeps the last accepted rows, so the bad row stays
    # rejected on every later poll instead of being trusted from the cache.
    with pytest.raises(ValueError, match="disagrees with indexed connector"):
        PROJECTOR._read_projected_records(database, validated)


def test_validation_cache_skips_only_identical_rows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = tmp_path / "audit.db"
    expected = _database(database)
    validated: dict[object, tuple[object, ...]] = {}
    checked: list[object] = []
    original = PROJECTOR._validated_record

    def counting(row: tuple[object, ...]) -> str:
        checked.append(row[0])
        return original(row)

    monkeypatch.setattr(PROJECTOR, "_validated_record", counting)
    assert PROJECTOR._read_projected_records(database, validated) == [expected]
    assert PROJECTOR._read_projected_records(database, validated) == [expected]
    assert checked == [1]

    connection = sqlite3.connect(database)
    connection.execute("INSERT INTO audit_events SELECT * FROM audit_events")
    connection.commit()
    connection.close()
    assert PROJECTOR._read_projected_records(database, validated) == [expected, expected]
    assert checked == [1, 2]


def test_serve_process_exits_cleanly_at_end_of_input(tmp_path: Path) -> None:
    database = tmp_path / "audit.db"
    expected = _database(database)
    output = tmp_path / "projection.jsonl"
    script = Path(PROJECTOR.__file__)

    completed = subprocess.run(
        [sys.executable, str(script), "--serve"],
        input=_request(database, output),
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=60,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.splitlines() == ['{"ready":true,"protocol":1}', '{"ok":true}']
    assert output.read_text(encoding="utf-8") == expected + "\n"


def test_serve_rejects_one_shot_paths(tmp_path: Path) -> None:
    completed = subprocess.run(
        [sys.executable, str(Path(PROJECTOR.__file__)), "--serve", "--audit-db", str(tmp_path / "a")],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert completed.returncode == 2
    assert "--serve takes the audit database and output from each request" in completed.stderr
