# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Registry index cache reader for the Textual TUI.

The registry sync pipeline writes ``index.json`` under
``<data_dir>/registries/<source-id>/``. This module deliberately reads
that JSON directly instead of importing the mutable CLI cache helpers:
the TUI needs a non-creating, read-only loader with the same defensive
source-id validation as the Go Bubble Tea panel.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class RegistryCacheError(Exception):
    """Raised when a registry cache file exists but cannot be parsed."""


class UnsafeSourceIDError(ValueError):
    """Raised before any filesystem access for unsafe registry source IDs."""


@dataclass(frozen=True)
class RegistryEntryRow:
    """One verdict row read from a registry ``index.json`` file."""

    source_id: str
    type: str
    name: str
    status: str = ""
    severity: str = ""
    findings: int = 0
    approved: bool = False
    rejected: bool = False
    transport: str = ""
    command: str = ""
    args: tuple[str, ...] = ()
    url: str = ""
    source_url: str = ""

    @property
    def approval_marker(self) -> str:
        if self.approved:
            return "A-"
        if self.rejected:
            return "-R"
        return "--"

    @property
    def location(self) -> str:
        return self.url or self.command or self.source_url


@dataclass(frozen=True)
class SourceIndex:
    """Read-only projection of a cached registry source index."""

    source_id: str
    schema_version: int = 1
    fetched_at: str = ""
    publisher: str = ""
    entry_count: int = 0
    clean_count: int = 0
    warning_count: int = 0
    blocked_count: int = 0
    error_count: int = 0
    verdicts: tuple[RegistryEntryRow, ...] = ()


def validate_source_id(source_id: str) -> None:
    """Reject source IDs that could alter the cache path.

    Go parity requires rejecting any ``/``, ``\\``, or ``.`` before
    opening ``<data_dir>/registries/<id>/index.json``.
    """

    if not source_id or any(ch in source_id for ch in "/\\."):
        raise UnsafeSourceIDError(f"unsafe registry source id: {source_id!r}")


def registry_index_path(data_dir: str | Path, source_id: str) -> Path:
    """Return the read-only cache path for a validated registry source."""

    if not data_dir:
        raise RegistryCacheError("missing registry data_dir")
    validate_source_id(source_id)
    return Path(data_dir) / "registries" / source_id / "index.json"


def load_registry_index(data_dir: str | Path, source_id: str) -> SourceIndex:
    """Load one registry source index from ``data_dir``.

    Missing files are surfaced as :class:`FileNotFoundError`; corrupt or
    malformed JSON is surfaced as :class:`RegistryCacheError`. The panel
    treats both as non-fatal empty/error states, while tests can assert
    the exact safety contract of this loader.
    """

    path = registry_index_path(data_dir, source_id)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise
    except json.JSONDecodeError as exc:
        raise RegistryCacheError(f"invalid registry index JSON for {source_id!r}: {exc}") from exc
    except OSError as exc:
        raise RegistryCacheError(f"unable to read registry index for {source_id!r}: {exc}") from exc

    if not isinstance(payload, dict):
        raise RegistryCacheError(f"registry index for {source_id!r} must be a JSON object")

    verdicts = tuple(_entry_from_raw(source_id, raw) for raw in _dict_items(payload.get("verdicts")))
    return SourceIndex(
        source_id=_str(payload.get("source_id")) or source_id,
        schema_version=_int(payload.get("schema_version"), 1),
        fetched_at=_str(payload.get("fetched_at")),
        publisher=_str(payload.get("publisher")),
        entry_count=_int(payload.get("entry_count"), len(verdicts)),
        clean_count=_int(payload.get("clean_count"), _count_status(verdicts, "clean")),
        warning_count=_int(payload.get("warning_count"), _count_status(verdicts, "warning")),
        blocked_count=_int(payload.get("blocked_count"), _count_status(verdicts, "blocked")),
        error_count=_int(payload.get("error_count"), _count_status(verdicts, "error")),
        verdicts=verdicts,
    )


def _entry_from_raw(source_id: str, raw: dict[str, Any]) -> RegistryEntryRow:
    args = raw.get("args")
    return RegistryEntryRow(
        source_id=source_id,
        type=_str(raw.get("type")),
        name=_str(raw.get("name")),
        status=_str(raw.get("status")),
        severity=_str(raw.get("severity")),
        findings=_int(raw.get("findings"), 0),
        approved=_bool(raw.get("approved")),
        rejected=_bool(raw.get("rejected")),
        transport=_str(raw.get("transport")),
        command=_str(raw.get("command")),
        args=tuple(_str(arg) for arg in args) if isinstance(args, list) else (),
        url=_str(raw.get("url")),
        source_url=_str(raw.get("source_url")),
    )


def _dict_items(value: object) -> tuple[dict[str, Any], ...]:
    if not isinstance(value, list):
        return ()
    return tuple(item for item in value if isinstance(item, dict))


def _count_status(verdicts: tuple[RegistryEntryRow, ...], status: str) -> int:
    return sum(1 for verdict in verdicts if verdict.status == status)


def _str(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return str(value)


def _int(value: object, default: int) -> int:
    if value is None:
        return default
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return default
    return default


def _bool(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes"}
    return False
