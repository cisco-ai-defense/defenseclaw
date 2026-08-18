# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Read retained judge history across the v8 forensic-store cutover.

The gateway writes new judge bodies to ``observability.local.judge_bodies_path``
while upgraded installations can still contain older rows in the local audit
database.  The TUI is a read-only compatibility consumer: authoritative rows
win by stable ID, legacy-only rows remain visible, and the result is ordered
the same way as the Go cutover reader.
"""

from __future__ import annotations

import calendar
import os
import re
import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

_HISTORY_COLUMNS = (
    "id",
    "timestamp",
    "kind",
    "direction",
    "action",
    "severity",
    "latency_ms",
    "inspected_model",
    "model",
    "request_id",
    "trace_id",
    "run_id",
    "input_hash",
    "confidence",
    "fail_closed_applied",
    "prompt_template_id",
    "parse_error",
    "raw",
)

_GO_TIMESTAMP_RE = re.compile(
    r"^(?P<base>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"
    r"(?:\.(?P<fraction>\d{1,9}))? (?P<offset>[+-]\d{4}) [A-Za-z]+$"
)
_FRACTION_RE = re.compile(r"[.,](?P<fraction>\d{1,9})(?=Z|[+-]\d{2}:?\d{2}|$)")
_INVALID_UNIX_NANO = -(1 << 63)


@dataclass(frozen=True)
class JudgeHistoryPaths:
    """Effective v8 and legacy SQLite locations used by the history view."""

    authoritative: Path | None
    legacy: Path | None


def resolve_judge_history_paths(
    config: object | None,
    *,
    data_dir: str | Path | None = None,
) -> JudgeHistoryPaths:
    """Resolve the real v8 paths without adding another Python config shape.

    Python's current :class:`defenseclaw.config.Config` models only the legacy
    connector portion of ``observability``.  When that concrete class is
    supplied by the TUI launcher, read the active YAML to recover the v8 local
    paths.  Mapping and duck-typed configs are resolved directly so tests and
    existing embedded callers do not unexpectedly consult a user's config.
    """

    raw = _config_mapping(config)
    effective_data_dir = _first_path_value(
        data_dir,
        raw.get("data_dir"),
        _object_value(config, "data_dir"),
    )
    local = _mapping_value(raw.get("observability"), "local")

    authoritative_value = _first_path_value(
        local.get("judge_bodies_path"),
        raw.get("judge_bodies_db"),
        _nested_object_value(config, "observability", "local", "judge_bodies_path"),
        _object_value(config, "judge_bodies_db"),
    )
    if authoritative_value is None and effective_data_dir is not None:
        authoritative_value = effective_data_dir / "judge_bodies.db"

    legacy_value = _first_path_value(
        local.get("path"),
        raw.get("audit_db"),
        _nested_object_value(config, "observability", "local", "path"),
        _object_value(config, "audit_db"),
    )
    if legacy_value is None and effective_data_dir is not None:
        legacy_value = effective_data_dir / "audit.db"

    return JudgeHistoryPaths(
        authoritative=_normalize_path(authoritative_value),
        legacy=_normalize_path(legacy_value),
    )


def read_judge_response_history(
    config: object | None,
    *,
    data_dir: str | Path | None = None,
    limit: int = 20,
) -> tuple[tuple[dict[str, object], ...], str]:
    """Return merged judge rows plus a user-facing error, if any.

    Both databases are opened read-only.  A missing database or table is an
    empty source during the upgrade window; a present database that cannot be
    read is surfaced instead of silently hiding a forensic-store failure.
    """

    if limit <= 0:
        limit = 20
    paths = resolve_judge_history_paths(config, data_dir=data_dir)
    existing_sources: list[tuple[str, Path]] = []
    if paths.authoritative is not None and paths.authoritative.is_file():
        existing_sources.append(("authoritative", paths.authoritative))
    if (
        paths.legacy is not None
        and paths.legacy.is_file()
        and not _same_path(paths.legacy, paths.authoritative)
    ):
        existing_sources.append(("legacy", paths.legacy))

    if not existing_sources:
        return (), (
            "Judge history is unavailable; configure "
            "observability.local.judge_bodies_path or audit_db."
        )

    rows_by_source: list[tuple[str, tuple[dict[str, object], ...]]] = []
    initialized = False
    try:
        for source, path in existing_sources:
            rows, has_table = _read_history_source(path, limit)
            initialized = initialized or has_table
            rows_by_source.append((source, rows))
    except (OSError, sqlite3.Error) as exc:
        return (), str(exc)

    combined: list[tuple[dict[str, object], int, int]] = []
    seen_ids: set[str] = set()
    sequence = 0
    for source, rows in rows_by_source:
        source_priority = 1 if source == "authoritative" else 0
        for row in rows:
            stable_id = str(row.get("id") or "").strip()
            if stable_id:
                if stable_id in seen_ids:
                    continue
                seen_ids.add(stable_id)
            combined.append((row, source_priority, sequence))
            sequence += 1

    combined.sort(key=_history_sort_key, reverse=True)
    result = tuple(row for row, _source_priority, _sequence in combined[:limit])
    if result or initialized:
        return result, ""
    return (), "judge_responses table is not initialized yet."


def _read_history_source(
    path: Path,
    limit: int,
) -> tuple[tuple[dict[str, object], ...], bool]:
    uri = path.resolve(strict=False).as_uri() + "?mode=ro"
    with sqlite3.connect(uri, uri=True) as db:
        db.create_function(
            "defenseclaw_unix_nano",
            1,
            _timestamp_unix_nano,
            deterministic=True,
        )
        columns = {
            str(row[1])
            for row in db.execute("PRAGMA table_info(judge_responses)").fetchall()
        }
        if not columns:
            return (), False

        expressions: list[str] = []
        selected: list[str] = []
        for canonical in _HISTORY_COLUMNS:
            actual = canonical
            if canonical == "raw" and "raw" not in columns and "raw_response" in columns:
                actual = "raw_response"
            if actual not in columns:
                continue
            expressions.append(f'"{actual}" AS "{canonical}"')
            selected.append(canonical)
        if not selected:
            return (), True

        if "timestamp_unix_nano" in columns and "timestamp" in columns:
            order = (
                'COALESCE("timestamp_unix_nano", '
                'defenseclaw_unix_nano("timestamp")) DESC'
            )
        elif "timestamp" in columns:
            order = 'defenseclaw_unix_nano("timestamp") DESC'
        else:
            order = "rowid DESC"
        if "id" in columns:
            order += ', "id" DESC'
        cursor = db.execute(
            f"SELECT {', '.join(expressions)} FROM judge_responses "
            f"ORDER BY {order} LIMIT ?",
            (limit,),
        )
        return (
            tuple(dict(zip(selected, row, strict=True)) for row in cursor.fetchall()),
            True,
        )


def _history_sort_key(
    item: tuple[dict[str, object], int, int],
) -> tuple[int, str, int, int]:
    row, source_priority, sequence = item
    timestamp = _timestamp_unix_nano(row.get("timestamp"))
    stable_id = str(row.get("id") or "")
    # Source priority makes an authoritative no-ID row deterministic on ties;
    # sequence is inverted so the source query's existing order is preserved.
    return timestamp, stable_id, source_priority, -sequence


def _timestamp_unix_nano(value: object) -> int:
    encoded = str(value).strip()
    match = _GO_TIMESTAMP_RE.match(encoded)
    try:
        if match is not None:
            parsed = datetime.strptime(
                f"{match.group('base')} {match.group('offset')}",
                "%Y-%m-%d %H:%M:%S %z",
            )
            fraction = match.group("fraction") or ""
        else:
            fraction_match = _FRACTION_RE.search(encoded)
            fraction = fraction_match.group("fraction") if fraction_match else ""
            parsed = datetime.fromisoformat(encoded.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return _INVALID_UNIX_NANO
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    parsed = parsed.astimezone(timezone.utc)
    seconds = calendar.timegm(parsed.utctimetuple())
    nanos = int(fraction.ljust(9, "0")) if fraction else parsed.microsecond * 1000
    return seconds * 1_000_000_000 + nanos


def _parse_timestamp(value: object) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return datetime.min.replace(tzinfo=timezone.utc)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _config_mapping(config: object | None) -> dict[str, Any]:
    if isinstance(config, Mapping):
        return dict(config)

    # Only the concrete Config loaded by the CLI is allowed to consult the
    # process-wide active YAML.  Duck-typed configs used by embedders retain
    # the historical attribute-only behavior and cannot leak another install's
    # paths into their TUI.
    try:
        from defenseclaw import config as config_module

        if isinstance(config, config_module.Config):
            path = config_module.config_path()
            with path.open(encoding="utf-8") as stream:
                raw = yaml.safe_load(stream) or {}
            if isinstance(raw, dict):
                return raw
    except (OSError, TypeError, ValueError, yaml.YAMLError):
        pass
    return {}


def _mapping_value(value: object, key: str) -> dict[str, Any]:
    if isinstance(value, Mapping):
        nested = value.get(key)
        if isinstance(nested, Mapping):
            return dict(nested)
    return {}


def _nested_object_value(config: object | None, *names: str) -> object | None:
    value = config
    for name in names:
        if isinstance(value, Mapping):
            value = value.get(name)
        else:
            value = getattr(value, name, None)
        if value is None:
            return None
    return value


def _object_value(config: object | None, name: str) -> object | None:
    if isinstance(config, Mapping):
        return config.get(name)
    return getattr(config, name, None)


def _first_path_value(*values: object) -> Path | None:
    for value in values:
        if isinstance(value, Path):
            return value
        if value is not None and str(value).strip():
            return Path(str(value).strip())
    return None


def _normalize_path(value: Path | None) -> Path | None:
    if value is None:
        return None
    return Path(os.path.abspath(os.path.expanduser(str(value))))


def _same_path(left: Path, right: Path | None) -> bool:
    if right is None:
        return False
    try:
        return left.samefile(right)
    except OSError:
        return os.path.normcase(str(left)) == os.path.normcase(str(right))
