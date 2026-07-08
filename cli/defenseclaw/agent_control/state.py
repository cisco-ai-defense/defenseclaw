"""Persistent, redacted synchronizer state."""

from __future__ import annotations

import json
import os
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass
class SyncState:
    schema_version: int = 1
    status: str = "not_initialized"
    sdk_version: str = "unknown"
    agent_name: str = "defenseclaw-policy-sync"
    target_type: str = "defenseclaw.installation"
    target_id_hash: str = ""
    snapshot_state: str = "none"
    snapshot_freshness: str = "not_exposed_by_sdk"
    opa_source_digest: str | None = None
    opa_published_digest: str | None = None
    opa_active_digest: str | None = None
    rule_pack_source_digest: str | None = None
    rule_pack_published_digest: str | None = None
    rule_pack_active_digest: str | None = None
    rule_pack_pending_restart: bool = False
    matching_controls: int = 0
    ignored_controls: int = 0
    last_observed_at: str | None = None
    last_published_at: str | None = None
    last_activated_at: str | None = None
    last_error: str | None = None

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> SyncState:
        allowed = cls.__dataclass_fields__
        return cls(**{key: val for key, val in value.items() if key in allowed})


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def load_state(path: Path) -> SyncState:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, ValueError, TypeError):
        return SyncState()
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        return SyncState()
    return SyncState.from_dict(value)


def save_state(path: Path, state: SyncState) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        existing = path.lstat()
    except FileNotFoundError:
        existing = None
    if existing is not None:
        if path.is_symlink() or not path.is_file() or existing.st_nlink != 1:
            raise OSError(f"refusing unsafe Agent Control state file: {path}")
        geteuid = getattr(os, "geteuid", None)
        if geteuid is not None and existing.st_uid != geteuid():
            raise OSError(f"Agent Control state file has unexpected owner: {path}")
    payload = (json.dumps(asdict(state), ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
    tmp = path.parent / f".{path.name}.{os.getpid()}.{time.monotonic_ns()}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(tmp, flags, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=True) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
        try:
            dir_fd = os.open(path.parent, os.O_RDONLY)
        except OSError:
            # Opening directories for fsync is unsupported on Windows.
            dir_fd = None
        if dir_fd is not None:
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
    finally:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass
