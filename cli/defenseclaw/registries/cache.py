# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""On-disk cache of fetched manifests + per-entry scan verdicts.

Layout::

    ~/.defenseclaw/registries/<source-id>/index.json
    ~/.defenseclaw/registries/<source-id>/manifest.yaml   # last raw fetch

``index.json`` is the structured artefact the TUI and ``registry
entries`` consume. ``manifest.yaml`` is kept verbatim alongside it for
forensic inspection — operators occasionally need to diff what the
publisher served vs what made it through the validator.

All files are written via :func:`_atomic_write` (tempfile + rename) at
mode 0o600. ``manifest.yaml`` may legitimately contain ingest tokens
embedded in URLs and we don't want a half-written read leaking through
a concurrent ``registry list``.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from defenseclaw.registries.manifest import Manifest, ManifestEntry, parse_manifest


@dataclass
class EntryVerdict:
    """Per-entry scan outcome cached for fast TUI rendering."""

    name: str
    type: str
    status: str = "pending"   # pending | clean | warning | blocked | error
    severity: str = ""
    findings: int = 0
    scan_id: str = ""
    target: str = ""
    error: str = ""
    last_scanned_at: str = ""
    approved: bool = False
    rejected: bool = False
    source_url: str = ""
    transport: str = ""
    command: str = ""
    args: list[str] = field(default_factory=list)
    url: str = ""

    def to_dict(self) -> dict[str, Any]:
        out = {
            "name": self.name,
            "type": self.type,
            "status": self.status,
            "approved": self.approved,
            "rejected": self.rejected,
        }
        for key in (
            "severity", "scan_id", "target", "error", "last_scanned_at",
            "source_url", "transport", "command", "url",
        ):
            value = getattr(self, key)
            if value:
                out[key] = value
        if self.findings:
            out["findings"] = self.findings
        if self.args:
            out["args"] = list(self.args)
        return out


@dataclass
class SourceIndex:
    """Cached state for one registry source."""

    source_id: str = ""
    schema_version: int = 1
    fetched_at: str = ""
    publisher: str = ""
    entry_count: int = 0
    clean_count: int = 0
    warning_count: int = 0
    blocked_count: int = 0
    error_count: int = 0
    verdicts: list[EntryVerdict] = field(default_factory=list)

    def recount(self) -> None:
        self.entry_count = len(self.verdicts)
        self.clean_count = sum(1 for v in self.verdicts if v.status == "clean")
        self.warning_count = sum(1 for v in self.verdicts if v.status == "warning")
        self.blocked_count = sum(1 for v in self.verdicts if v.status == "blocked")
        self.error_count = sum(1 for v in self.verdicts if v.status == "error")

    def find(self, type_: str, name: str) -> EntryVerdict | None:
        for v in self.verdicts:
            if v.type == type_ and v.name == name:
                return v
        return None

    def to_dict(self) -> dict[str, Any]:
        out = asdict(self)
        out["verdicts"] = [v.to_dict() for v in self.verdicts]
        return out


def cache_root(data_dir: str) -> Path:
    """Return ``~/.defenseclaw/registries`` (creating it lazily)."""
    base = Path(data_dir) / "registries"
    base.mkdir(mode=0o700, exist_ok=True, parents=True)
    return base


def source_dir(data_dir: str, source_id: str) -> Path:
    """Per-source directory under :func:`cache_root`."""
    if not source_id or "/" in source_id or ".." in source_id:
        raise ValueError(f"invalid source id: {source_id!r}")
    d = cache_root(data_dir) / source_id
    d.mkdir(mode=0o700, exist_ok=True)
    return d


def index_path(data_dir: str, source_id: str) -> Path:
    return source_dir(data_dir, source_id) / "index.json"


def manifest_path(data_dir: str, source_id: str) -> Path:
    return source_dir(data_dir, source_id) / "manifest.yaml"


# ---------------------------------------------------------------------------
# Index read / write
# ---------------------------------------------------------------------------

def load_index(data_dir: str, source_id: str) -> SourceIndex:
    """Load the cached :class:`SourceIndex` for *source_id*.

    Missing / corrupt files return a fresh, zero-valued
    :class:`SourceIndex` so the caller can build it up on first sync
    without a guard pyramid.
    """
    path = index_path(data_dir, source_id)
    if not path.exists():
        return SourceIndex(source_id=source_id)
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return SourceIndex(source_id=source_id)
    if not isinstance(data, dict):
        return SourceIndex(source_id=source_id)
    verdicts: list[EntryVerdict] = []
    for raw in data.get("verdicts") or []:
        if not isinstance(raw, dict):
            continue
        verdicts.append(EntryVerdict(
            name=str(raw.get("name", "")),
            type=str(raw.get("type", "")),
            status=str(raw.get("status", "pending")),
            severity=str(raw.get("severity", "")),
            findings=int(raw.get("findings", 0) or 0),
            scan_id=str(raw.get("scan_id", "")),
            target=str(raw.get("target", "")),
            error=str(raw.get("error", "")),
            last_scanned_at=str(raw.get("last_scanned_at", "")),
            approved=bool(raw.get("approved", False)),
            rejected=bool(raw.get("rejected", False)),
            source_url=str(raw.get("source_url", "")),
            transport=str(raw.get("transport", "")),
            command=str(raw.get("command", "")),
            args=[str(a) for a in (raw.get("args") or [])],
            url=str(raw.get("url", "")),
        ))
    idx = SourceIndex(
        source_id=str(data.get("source_id", source_id)),
        schema_version=int(data.get("schema_version", 1) or 1),
        fetched_at=str(data.get("fetched_at", "")),
        publisher=str(data.get("publisher", "")),
        verdicts=verdicts,
    )
    idx.recount()
    return idx


def save_index(data_dir: str, source_id: str, idx: SourceIndex) -> None:
    """Write *idx* atomically to ``index.json`` (mode 0o600)."""
    idx.recount()
    path = index_path(data_dir, source_id)
    payload = json.dumps(idx.to_dict(), indent=2, sort_keys=True) + "\n"
    _atomic_write(path, payload.encode("utf-8"))


def save_manifest(data_dir: str, source_id: str, raw: bytes | str) -> None:
    """Persist the raw fetched manifest bytes for forensic inspection."""
    if isinstance(raw, str):
        raw = raw.encode("utf-8")
    _atomic_write(manifest_path(data_dir, source_id), raw)


def remove_source(data_dir: str, source_id: str) -> None:
    """Delete the cache directory for *source_id*.

    Best-effort: missing directories are ignored so this is safe to
    call from ``registry remove`` regardless of prior sync state.

    Uses :func:`shutil.rmtree` so the cache layout can grow nested
    directories (e.g. a future ``manifests/`` history folder) without
    leaving orphaned files when the operator removes the source. The
    earlier per-file unlink loop would silently succeed and then
    refuse to delete the parent directory, leaving stale state behind.
    """
    try:
        d = source_dir(data_dir, source_id)
    except ValueError:
        return
    if not d.exists():
        return
    shutil.rmtree(d, ignore_errors=True)


def index_from_manifest(source_id: str, manifest: Manifest) -> SourceIndex:
    """Project a fresh manifest into a :class:`SourceIndex` skeleton.

    Used at the start of a sync — every entry starts at
    ``status="pending"`` and gets updated as the scanner returns.
    """
    verdicts: list[EntryVerdict] = []
    for entry in manifest.entries:
        verdicts.append(_verdict_from_entry(entry))
    idx = SourceIndex(
        source_id=source_id,
        schema_version=manifest.schema_version,
        publisher=manifest.publisher,
        verdicts=verdicts,
    )
    idx.recount()
    return idx


def merge_manifest_into_index(
    idx: SourceIndex, manifest: Manifest,
) -> SourceIndex:
    """Apply a freshly-fetched manifest to an existing index.

    Preserves prior verdicts where the (type, name) tuple still
    appears; drops verdicts for entries that have been removed; adds
    new placeholders for new entries. Approved / rejected flags are
    preserved across syncs so an operator's manual override survives a
    publisher refresh.
    """
    keep: dict[tuple[str, str], EntryVerdict] = {
        (v.type, v.name): v for v in idx.verdicts
    }
    new_verdicts: list[EntryVerdict] = []
    for entry in manifest.entries:
        key = (entry.type, entry.name)
        prior = keep.get(key)
        fresh = _verdict_from_entry(entry)
        if prior is not None:
            # Preserve operator overrides + last successful scan.
            fresh.approved = prior.approved
            fresh.rejected = prior.rejected
            if prior.status in {"clean", "warning", "blocked"}:
                fresh.status = prior.status
                fresh.severity = prior.severity
                fresh.findings = prior.findings
                fresh.scan_id = prior.scan_id
                fresh.target = prior.target
                fresh.last_scanned_at = prior.last_scanned_at
        new_verdicts.append(fresh)
    idx.verdicts = new_verdicts
    idx.publisher = manifest.publisher
    idx.schema_version = manifest.schema_version
    idx.recount()
    return idx


def _verdict_from_entry(entry: ManifestEntry) -> EntryVerdict:
    return EntryVerdict(
        name=entry.name,
        type=entry.type,
        status="pending",
        source_url=entry.source_url,
        transport=entry.transport,
        command=entry.command,
        args=list(entry.args),
        url=entry.url,
    )


# ---------------------------------------------------------------------------
# Manifest reload helper — useful for the TUI to re-read an existing
# cached manifest without a fresh fetch.
# ---------------------------------------------------------------------------

def load_cached_manifest(data_dir: str, source_id: str) -> Manifest | None:
    path = manifest_path(data_dir, source_id)
    if not path.exists():
        return None
    try:
        raw = path.read_bytes()
    except OSError:
        return None
    try:
        return parse_manifest(raw)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Atomic write — same pattern as connector_paths._atomic_write_json.
# ---------------------------------------------------------------------------

def _atomic_write(path: Path, data: bytes) -> None:
    parent = path.parent
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".dc-reg-", dir=str(parent))
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.chmod(tmp, 0o600)
        os.replace(tmp, str(path))
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
