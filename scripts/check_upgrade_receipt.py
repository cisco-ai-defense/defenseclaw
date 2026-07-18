#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Verify that one successful upgrade receipt reached canonical v8 audit storage."""

from __future__ import annotations

import argparse
import json
import math
import sqlite3
import stat
import time
from pathlib import Path
from typing import Any

import yaml

MAX_RECEIPT_BYTES = 16 * 1024
MAX_RECEIPTS = 64
POLL_SECONDS = 0.1


class ReceiptCheckError(RuntimeError):
    """The terminal upgrade receipt was missing, ambiguous, or invalid."""


def _audit_database(data_dir: Path) -> Path:
    config_path = data_dir / "config.yaml"
    try:
        config = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise ReceiptCheckError("upgraded config is unavailable for receipt verification") from exc
    local = (config.get("observability") or {}).get("local") or {}
    configured = local.get("path")
    if configured is None:
        return data_dir / "audit.db"
    if not isinstance(configured, str) or not configured.strip():
        raise ReceiptCheckError("configured audit database path is invalid")
    path = Path(configured).expanduser()
    return path if path.is_absolute() else data_dir / path


def _queued_receipts(data_dir: Path) -> list[dict[str, Any]]:
    root = data_dir / ".upgrade-receipts"
    try:
        entries = sorted(root.iterdir())
    except FileNotFoundError:
        return []
    except OSError as exc:
        raise ReceiptCheckError("upgrade receipt queue is unavailable") from exc
    receipts: list[dict[str, Any]] = []
    for path in entries:
        if len(receipts) >= MAX_RECEIPTS:
            raise ReceiptCheckError("upgrade receipt queue exceeds its bounded capacity")
        try:
            info = path.lstat()
        except FileNotFoundError:
            # The gateway acknowledges receipts by unlinking them after the
            # canonical SQLite commit. Disappearance is the expected success
            # race; every other filesystem error remains fail-closed.
            continue
        except OSError as exc:
            raise ReceiptCheckError("upgrade receipt queue changed during verification") from exc
        if not stat.S_ISREG(info.st_mode) or info.st_size <= 0 or info.st_size > MAX_RECEIPT_BYTES:
            raise ReceiptCheckError("upgrade receipt queue contains an invalid entry")
        try:
            receipt = json.loads(path.read_bytes())
        except FileNotFoundError:
            continue
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ReceiptCheckError("upgrade receipt queue contains invalid JSON") from exc
        if not isinstance(receipt, dict):
            raise ReceiptCheckError("upgrade receipt queue contains an invalid document")
        receipts.append(receipt)
    return receipts


def _canonical_receipts(database: Path, source: str, target: str) -> list[tuple[Any, ...]]:
    if not database.is_file():
        return []
    connection = sqlite3.connect(database.resolve().as_uri() + "?mode=ro", uri=True, timeout=1)
    try:
        rows = connection.execute(
            """SELECT id, bucket, signal, event_name, source, mandatory,
                      structured_json, projected_record_json
               FROM audit_events
               WHERE action = 'upgrade'
                 AND bucket = 'compliance.activity'
                 AND signal = 'logs'
                 AND event_name = 'legacy.audit.upgrade'"""
        ).fetchall()
    finally:
        connection.close()
    matches: list[tuple[Any, ...]] = []
    for row in rows:
        try:
            structured = json.loads(row[6])
        except (TypeError, json.JSONDecodeError) as exc:
            raise ReceiptCheckError("canonical upgrade receipt has invalid structured facts") from exc
        if (
            isinstance(structured, dict)
            and structured.get("from_version") == source
            and structured.get("target_version") == target
        ):
            matches.append((*row[:6], structured, row[7]))
    return matches


def _validate_facts(facts: dict[str, Any], source: str, target: str) -> None:
    if facts.get("from_version") != source or facts.get("target_version") != target:
        raise ReceiptCheckError("terminal target receipt has the wrong upgrade path")
    if (
        facts.get("status") != "succeeded"
        or facts.get("migration_status") != "completed"
        or facts.get("artifacts_verified") is not True
        or facts.get("failure_code")
    ):
        raise ReceiptCheckError("terminal target receipt is not fully successful")


def _validate_attempt(row: tuple[Any, ...], source: str, target: str) -> str:
    receipt_id, _, _, _, event_source, mandatory, facts, projected_raw = row
    if facts.get("from_version") != source or facts.get("target_version") != target:
        raise ReceiptCheckError("terminal target receipt has the wrong upgrade path")
    if facts.get("receipt_id") != receipt_id or event_source != "cli" or mandatory != 1:
        raise ReceiptCheckError("canonical target receipt has an invalid compliance identity")
    if facts.get("artifacts_verified") is not True:
        raise ReceiptCheckError("terminal target receipt lacks verified artifacts")
    try:
        projected = json.loads(projected_raw)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ReceiptCheckError("canonical target receipt has an invalid projection") from exc
    if not isinstance(projected, dict):
        raise ReceiptCheckError("canonical target receipt has an invalid projection")

    status = facts.get("status")
    if status == "succeeded":
        _validate_facts(facts, source, target)
        expected_outcome = "applied"
    elif status == "failed":
        expected_outcome = "failed"
    elif status == "rolled_back":
        expected_outcome = "revoked"
    else:
        raise ReceiptCheckError("canonical target receipt is not terminal")
    if status != "succeeded" and not facts.get("failure_code"):
        raise ReceiptCheckError("prior target attempt lacks its failure code")
    if projected.get("outcome") != expected_outcome:
        raise ReceiptCheckError("canonical target receipt has an inconsistent outcome")
    return status


def check_upgrade_receipt(
    data_dir: Path,
    *,
    source: str,
    target: str,
    timeout_seconds: float,
) -> None:
    if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
        raise ReceiptCheckError("receipt verification timeout must be finite and positive")
    database = _audit_database(data_dir)
    deadline = time.monotonic() + timeout_seconds
    last_canonical_count = 0
    last_queued_count = 0
    while True:
        queued = _queued_receipts(data_dir)
        if any(item.get("status") in {"pending", "partial"} for item in queued):
            raise ReceiptCheckError("successful upgrade left a pending or partial receipt")
        queued_target = [item for item in queued if item.get("target_version") == target]
        queued_success = [item for item in queued_target if item.get("status") == "succeeded"]
        if len(queued_success) > 1:
            raise ReceiptCheckError("successful upgrade left duplicate successful target receipts")
        for attempt in queued_target:
            status = attempt.get("status")
            if status == "succeeded":
                _validate_facts(attempt, source, target)
            elif status not in {"failed", "rolled_back"}:
                raise ReceiptCheckError("target receipt queue contains a nonterminal attempt")
            elif (
                attempt.get("from_version") != source
                or attempt.get("artifacts_verified") is not True
                or not attempt.get("failure_code")
            ):
                raise ReceiptCheckError("prior queued target attempt is invalid")

        try:
            canonical = _canonical_receipts(database, source, target)
        except sqlite3.Error:
            canonical = []
        last_canonical_count = len(canonical)
        last_queued_count = len(queued_target)
        canonical_success = [row for row in canonical if _validate_attempt(row, source, target) == "succeeded"]
        if len(canonical_success) > 1:
            raise ReceiptCheckError("canonical audit contains duplicate successful target receipts")
        if canonical_success:
            receipt_id = canonical_success[0][0]
            if queued_success and queued_success[0].get("receipt_id") != receipt_id:
                raise ReceiptCheckError("queued and canonical successful target receipts disagree")
            if not queued_target:
                return

        if time.monotonic() >= deadline:
            raise ReceiptCheckError(
                "expected one admitted and acknowledged target receipt; "
                f"canonical={last_canonical_count} queued={last_queued_count}"
            )
        time.sleep(POLL_SECONDS)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", required=True, type=Path)
    parser.add_argument("--from-version", required=True)
    parser.add_argument("--target-version", required=True)
    parser.add_argument("--timeout-seconds", type=float, default=10.0)
    args = parser.parse_args()
    if not math.isfinite(args.timeout_seconds) or args.timeout_seconds <= 0:
        parser.error("--timeout-seconds must be finite and positive")
    try:
        check_upgrade_receipt(
            args.data_dir,
            source=args.from_version,
            target=args.target_version,
            timeout_seconds=args.timeout_seconds,
        )
    except ReceiptCheckError as exc:
        parser.error(str(exc))
    print(f"upgrade_receipt=admitted_and_acknowledged {args.from_version}->{args.target_version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
