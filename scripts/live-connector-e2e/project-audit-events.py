#!/usr/bin/env python3
"""Materialize canonical observability-v8 records from SQLite as JSONL.

One-shot mode (``--audit-db``/``--out``) writes a single snapshot. Serve mode
(``--serve``) keeps one interpreter alive and answers one JSON request per
standard-input line, so a harness that polls the audit history many times per
run pays interpreter start-up once instead of once per poll.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import sys
import tempfile
import time
from pathlib import Path
from typing import TextIO

_MAX_RECORD_BYTES = 4 * 1024 * 1024 + 4 * 1024
_MAX_PROJECTION_BYTES = 64 * 1024 * 1024


def _same_json_type_and_value(left: object, right: object) -> bool:
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(
            _same_json_type_and_value(left[key], right[key]) for key in left
        )
    if isinstance(left, list):
        return len(left) == len(right) and all(
            _same_json_type_and_value(left_item, right_item)
            for left_item, right_item in zip(left, right, strict=True)
        )
    return left == right


def _require_indexed_text_match(
    projected: object,
    indexed: object,
    *,
    rowid: int,
    field: str,
    required: bool,
) -> None:
    if indexed is None:
        if projected is not None:
            raise ValueError(
                f"audit row {rowid} canonical projection disagrees with indexed {field}"
            )
        if required:
            raise ValueError(f"audit row {rowid} canonical {field} is empty")
        return
    if not isinstance(indexed, str):
        raise ValueError(f"audit row {rowid} indexed {field} is not text")
    if not isinstance(projected, str):
        raise ValueError(f"audit row {rowid} projected {field} is not text")
    if required and (not indexed or not projected):
        raise ValueError(f"audit row {rowid} canonical {field} is empty")
    if projected != indexed:
        raise ValueError(
            f"audit row {rowid} canonical projection disagrees with indexed {field}"
        )


def _query_rows(database: Path) -> list[tuple[object, ...]]:
    if not database.is_file():
        raise ValueError(f"canonical audit database is missing: {database}")

    uri = database.resolve().as_uri() + "?mode=ro"
    rows: list[tuple[object, ...]] | None = None
    for attempt in range(3):
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(uri, uri=True, timeout=2)
            connection.execute("PRAGMA query_only=ON")
            cursor = connection.execute(
                """SELECT rowid, id, bucket, event_name, source, signal, connector,
                          request_id, session_id, turn_id, record_schema_version,
                          payload_json, projected_record_json, projection_hash
                     FROM audit_events ORDER BY rowid"""
            )
            candidate_rows: list[tuple[object, ...]] = []
            candidate_bytes = 0
            for candidate in cursor:
                raw = candidate[-2]
                if isinstance(raw, str):
                    record_bytes = len(raw.encode("utf-8"))
                    if record_bytes > _MAX_RECORD_BYTES:
                        raise ValueError(
                            f"audit row {candidate[0]} canonical projection exceeds the size bound"
                        )
                    candidate_bytes += record_bytes + 1
                    if candidate_bytes > _MAX_PROJECTION_BYTES:
                        raise ValueError("canonical audit projection exceeds the total size bound")
                candidate_rows.append(candidate)
            rows = candidate_rows
            break
        except sqlite3.OperationalError as exc:
            primary_code = int(getattr(exc, "sqlite_errorcode", 0) or 0) & 0xFF
            if primary_code not in (sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED) or attempt == 2:
                raise
            time.sleep(0.05 * (attempt + 1))
        finally:
            if connection is not None:
                connection.close()
    if rows is None:
        raise RuntimeError("canonical audit projection query did not complete")

    return rows


def _validated_record(row: tuple[object, ...]) -> str:
    """Return the exact stored record after checking it against its row."""
    (
        rowid,
        record_id,
        bucket,
        event_name,
        source,
        signal,
        connector,
        request_id,
        session_id,
        turn_id,
        record_schema_version,
        payload_raw,
        raw,
        projection_hash,
    ) = row
    if not isinstance(raw, str) or not raw.strip():
        raise ValueError(f"audit row {rowid} has no canonical projected record")
    if raw != raw.strip() or "\r" in raw or "\n" in raw:
        raise ValueError(f"audit row {rowid} canonical projection is not one JSONL record")
    try:
        record = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"audit row {rowid} has an invalid canonical projection") from exc
    if not isinstance(record, dict):
        raise ValueError(f"audit row {rowid} canonical projection is not an object")
    if type(record_schema_version) is not int or record_schema_version != 1:
        raise ValueError(f"audit row {rowid} has an invalid indexed schema version")
    if type(record.get("schema_version")) is not int:
        raise ValueError(f"audit row {rowid} has an invalid canonical schema version type")
    if record.get("schema_version") != 1:
        raise ValueError(f"audit row {rowid} is not a canonical schema-v1 record")
    correlation = record.get("correlation")
    if not isinstance(correlation, dict):
        raise ValueError(f"audit row {rowid} canonical correlation is not an object")
    body = record.get("body")
    if not isinstance(body, dict):
        raise ValueError(f"audit row {rowid} canonical body is not an object")
    if not isinstance(payload_raw, str):
        raise ValueError(f"audit row {rowid} indexed payload_json is not text")
    try:
        payload = json.loads(payload_raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"audit row {rowid} indexed payload_json is invalid") from exc
    if not isinstance(payload, dict) or not _same_json_type_and_value(payload, body):
        raise ValueError(f"audit row {rowid} indexed payload disagrees with canonical body")
    comparisons = (
        ("record_id", record.get("record_id"), record_id),
        ("bucket", record.get("bucket"), bucket),
        ("event_name", record.get("event_name"), event_name),
        ("source", record.get("source"), source),
        ("signal", record.get("signal"), signal),
        ("connector", record.get("connector"), connector),
        ("request_id", correlation.get("request_id"), request_id),
        ("session_id", correlation.get("session_id"), session_id),
        ("turn_id", correlation.get("turn_id"), turn_id),
    )
    for field, projected, indexed in comparisons:
        _require_indexed_text_match(
            projected,
            indexed,
            rowid=rowid,
            field=field,
            required=field in ("record_id", "bucket", "event_name", "source", "signal"),
        )
    expected_hash = "sha256:" + hashlib.sha256(raw.encode("utf-8")).hexdigest()
    if not isinstance(projection_hash, str) or projection_hash != expected_hash:
        raise ValueError(f"audit row {rowid} canonical projection hash is invalid")
    if record.get("event_name") == "hook_decision":
        for field in (
            "defenseclaw.guardrail.would_block",
            "defenseclaw.guardrail.enforced",
        ):
            if type(body.get(field)) is not bool:
                raise ValueError(f"audit row {rowid} hook decision {field} is not boolean")
    return raw


def _read_projected_records(
    database: Path,
    validated: dict[object, tuple[object, ...]] | None = None,
) -> list[str]:
    """Read every canonical record in rowid order.

    ``validated`` maps a rowid to the exact row last accepted for it. A row
    that is byte-for-byte unchanged is not re-validated, because validation
    is a pure function of the row; any new, changed, or reordered row is
    validated in full. The map is replaced only after every row passes.
    """
    records: list[str] = []
    accepted: dict[object, tuple[object, ...]] = {}
    for row in _query_rows(database):
        rowid = row[0]
        if validated is None or validated.get(rowid) != row:
            _validated_record(row)
        accepted[rowid] = row
        records.append(row[-2])  # type: ignore[arg-type]
    if validated is not None:
        validated.clear()
        validated.update(accepted)
    return records


def _replace_jsonl(output: Path, records: list[str]) -> None:
    if not output.parent.is_dir():
        raise ValueError(f"canonical projection output parent is missing: {output.parent}")
    descriptor, temporary_name = tempfile.mkstemp(
        dir=output.parent,
        prefix=f".{output.name}.",
        suffix=".tmp",
        text=True,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            for record in records:
                stream.write(record)
                stream.write("\n")
            # The snapshot is a private, transient file that the harness
            # reads and deletes immediately, so it has no durability need
            # and is not forced to the device. os.replace below still makes
            # publication atomic.
            stream.flush()
        os.replace(temporary, output)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def project(audit_db: Path, output: Path) -> None:
    if audit_db.resolve() == output.resolve():
        raise ValueError("canonical projection output must differ from the audit database")
    _replace_jsonl(output, _read_projected_records(audit_db))


SERVE_PROTOCOL = 1


def _write_line(responses: TextIO, response: dict[str, object]) -> None:
    responses.write(json.dumps(response, separators=(",", ":")))
    responses.write("\n")


class _Server:
    def __init__(self) -> None:
        self._validated: dict[Path, dict[object, tuple[object, ...]]] = {}

    def answer(self, line: str, responses: TextIO) -> None:
        try:
            request = json.loads(line)
            if not isinstance(request, dict) or not (
                set(request) == {"audit_db"} or set(request) == {"audit_db", "out"}
            ):
                raise ValueError("projection request must name audit_db and optionally out")
            audit_db = request["audit_db"]
            output = request.get("out")
            if not isinstance(audit_db, str) or not audit_db:
                raise ValueError("projection request audit_db must be non-empty text")
            if output is not None and (not isinstance(output, str) or not output):
                raise ValueError("projection request out must be non-empty text")
            database = Path(audit_db)
            if output is not None and database.resolve() == Path(output).resolve():
                raise ValueError("canonical projection output must differ from the audit database")
            validated = self._validated.setdefault(database.resolve(), {})
            records = _read_projected_records(database, validated)
            if output is not None:
                _replace_jsonl(Path(output), records)
        except (OSError, ValueError, sqlite3.Error) as exc:
            _write_line(responses, {"ok": False, "error": f"canonical audit projection failed: {exc}"})
            return
        if output is not None:
            _write_line(responses, {"ok": True})
            return
        # Every record is validated to be exactly one line, so the records
        # follow the header one per line.
        _write_line(responses, {"ok": True, "records": len(records)})
        for record in records:
            responses.write(record)
            responses.write("\n")


def serve(requests: TextIO, responses: TextIO) -> int:
    """Answer one projection request per line until end of input.

    ``{"audit_db": ...}`` answers ``{"ok": true, "records": N}`` followed by
    the N canonical records, one per line. ``{"audit_db": ..., "out": ...}``
    atomically publishes a JSONL snapshot and answers ``{"ok": true}``. A
    rejected projection answers ``{"ok": false, "error": ...}`` and leaves the
    server ready for the next request. End of input (the harness closing its
    pipe or exiting) is the only shutdown request.
    """
    server = _Server()
    _write_line(responses, {"ready": True, "protocol": SERVE_PROTOCOL})
    responses.flush()
    while True:
        line = requests.readline()
        if not line:
            return 0
        server.answer(line, responses)
        responses.flush()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serve", action="store_true")
    parser.add_argument("--audit-db", type=Path)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()

    if args.serve:
        if args.audit_db is not None or args.out is not None:
            parser.error("--serve takes the audit database and output from each request")
        sys.stdin.reconfigure(encoding="utf-8")
        sys.stdout.reconfigure(encoding="utf-8", newline="\n")
        return serve(sys.stdin, sys.stdout)
    if args.audit_db is None or args.out is None:
        parser.error("--audit-db and --out are required without --serve")
    project(args.audit_db, args.out)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, sqlite3.Error) as exc:
        print(f"canonical audit projection failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
