#!/usr/bin/env python3
"""Validate Windows live-E2E JSONL schema and SQLite audit correlation."""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--jsonl", required=True, type=Path)
    parser.add_argument("--audit-db", required=True, type=Path)
    parser.add_argument("--connector", required=True)
    parser.add_argument("--since", type=int, default=0)
    args = parser.parse_args()

    events: list[dict[str, object]] = []
    with args.jsonl.open(encoding="utf-8") as stream:
        for line_number, raw in enumerate(stream, start=1):
            if line_number <= args.since or not raw.strip():
                continue
            value = json.loads(raw)
            if not isinstance(value, dict):
                raise ValueError(f"JSONL line {line_number} is not an object")
            events.append(value)

    connector = args.connector.lower()
    matching = [event for event in events if connector in json.dumps(event).lower()]
    if not matching:
        raise ValueError(f"no events correlated with connector {args.connector}")

    request_ids = {
        value
        for event in matching
        if isinstance((value := event.get("request_id")), str) and value
    }
    if not request_ids:
        raise ValueError("connector events contain no request_id for audit correlation")
    if not args.audit_db.is_file():
        raise ValueError(f"audit database is missing: {args.audit_db}")

    connection = sqlite3.connect(f"file:{args.audit_db.as_posix()}?mode=ro", uri=True)
    try:
        correlated = any(
            connection.execute(
                "SELECT 1 FROM audit_events WHERE request_id = ? LIMIT 1", (request_id,)
            ).fetchone()
            for request_id in request_ids
        )
        if not correlated:
            raise ValueError("no audit row matches a gateway request_id")
    finally:
        connection.close()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError, sqlite3.Error) as exc:
        print(f"windows evidence assertion failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
