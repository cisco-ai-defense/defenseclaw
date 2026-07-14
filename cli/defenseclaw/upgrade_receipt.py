# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Durable, secret-free handoff from ``upgrade`` to the v8 sidecar.

The process performing an upgrade can be an older Python CLI and must not
construct the target release's logger.  It records bounded facts in a private
queue instead.  A successfully bootstrapped v8 sidecar owns canonical
compliance persistence and removes terminal receipts only after admission.
"""

from __future__ import annotations

import json
import os
import re
import stat
import tempfile
import uuid
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Final

UPGRADE_RECEIPT_DIRECTORY: Final[str] = ".upgrade-receipts"
UPGRADE_RECEIPT_SCHEMA_VERSION: Final[int] = 1
MAX_UPGRADE_RECEIPTS: Final[int] = 64
MAX_UPGRADE_RECEIPT_BYTES: Final[int] = 16 * 1024

_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")
_STATUSES = frozenset({"pending", "succeeded", "partial", "failed", "rolled_back"})
_TERMINAL_STATUSES = _STATUSES - {"pending"}
_MIGRATION_STATUSES = frozenset({"pending", "completed", "degraded"})
_FAILURE_CODES = frozenset(
    {
        "",
        "install_failed",
        "migration_failed",
        "required_migration_failed",
        "local_observability_failed",
        "startup_failed",
        "health_check_failed",
        "interrupted",
        "rollback_detected",
    }
)


@dataclass(frozen=True)
class UpgradeReceipt:
    schema_version: int
    receipt_id: str
    created_at: str
    completed_at: str | None
    from_version: str
    target_version: str
    status: str
    migration_status: str
    migration_count: int | None
    artifacts_verified: bool
    failure_code: str

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "receipt_id": self.receipt_id,
            "created_at": self.created_at,
            "completed_at": self.completed_at,
            "from_version": self.from_version,
            "target_version": self.target_version,
            "status": self.status,
            "migration_status": self.migration_status,
            "migration_count": self.migration_count,
            "artifacts_verified": self.artifacts_verified,
            "failure_code": self.failure_code,
        }


def begin_upgrade_receipt(
    data_dir: str,
    *,
    from_version: str,
    target_version: str,
    artifacts_verified: bool,
) -> Path:
    """Create one durable pending receipt before installed state is mutated."""

    receipt_dir = _secure_receipt_directory(data_dir)
    _ensure_queue_capacity(receipt_dir)
    now = _utc_now()
    receipt = UpgradeReceipt(
        schema_version=UPGRADE_RECEIPT_SCHEMA_VERSION,
        receipt_id=str(uuid.uuid4()),
        created_at=now,
        completed_at=None,
        from_version=from_version,
        target_version=target_version,
        status="pending",
        migration_status="pending",
        migration_count=None,
        artifacts_verified=bool(artifacts_verified),
        failure_code="",
    )
    _validate(receipt)
    path = receipt_dir / f"{receipt.receipt_id}.json"
    _atomic_write(path, receipt)
    return path


def record_upgrade_migrations(
    path: Path,
    *,
    migration_count: int,
    degraded: bool,
) -> UpgradeReceipt:
    """Persist migration progress without making the upgrade terminal."""

    receipt = load_upgrade_receipt(path)
    if receipt.status != "pending":
        raise ValueError("terminal upgrade receipt cannot be changed")
    updated = replace(
        receipt,
        migration_status="degraded" if degraded else "completed",
        migration_count=migration_count,
    )
    _validate(updated)
    _atomic_write(path, updated)
    return updated


def complete_upgrade_receipt(
    path: Path,
    *,
    status: str,
    failure_code: str = "",
) -> UpgradeReceipt:
    """Atomically make one receipt terminal; terminal states are immutable."""

    receipt = load_upgrade_receipt(path)
    if receipt.status in _TERMINAL_STATUSES:
        if receipt.status == status and receipt.failure_code == failure_code:
            return receipt
        raise ValueError("terminal upgrade receipt cannot be changed")
    updated = replace(
        receipt,
        status=status,
        completed_at=_utc_now(),
        failure_code=failure_code,
    )
    _validate(updated)
    _atomic_write(path, updated)
    return updated


def finalize_interrupted_upgrade_receipts(data_dir: str, *, current_version: str) -> int:
    """Close receipts abandoned by a crashed updater before a new attempt.

    Version equality alone is not proof that every mutable component was
    restored and health-checked.  Journaled hard-cut transactions finalize a
    ``rolled_back`` receipt only after exact state restoration and a fresh
    bridge health check; an orphaned receipt without that proof is always an
    interrupted failure.
    """

    receipt_dir = _secure_receipt_directory(data_dir)
    changed = 0
    for path in sorted(receipt_dir.glob("*.json"))[:MAX_UPGRADE_RECEIPTS]:
        if path.is_symlink() or not path.is_file():
            continue
        try:
            receipt = load_upgrade_receipt(path)
        except (OSError, ValueError, json.JSONDecodeError):
            continue
        if receipt.status != "pending":
            continue
        complete_upgrade_receipt(
            path,
            status="failed",
            failure_code="interrupted",
        )
        changed += 1
    return changed


def load_upgrade_receipt(path: Path) -> UpgradeReceipt:
    """Read one bounded regular receipt without following a symlink."""

    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise ValueError("upgrade receipt must be a regular file")
    if info.st_size <= 0 or info.st_size > MAX_UPGRADE_RECEIPT_BYTES:
        raise ValueError("upgrade receipt has invalid size")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ValueError("upgrade receipt could not be opened safely") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_size <= 0
            or opened.st_size > MAX_UPGRADE_RECEIPT_BYTES
            or not os.path.samestat(info, opened)
        ):
            raise ValueError("upgrade receipt changed while opening")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read(MAX_UPGRADE_RECEIPT_BYTES + 1)
    finally:
        os.close(descriptor)
    if not raw or len(raw) > MAX_UPGRADE_RECEIPT_BYTES:
        raise ValueError("upgrade receipt has invalid size")
    payload = json.loads(raw)
    if not isinstance(payload, dict) or set(payload) != set(UpgradeReceipt.__dataclass_fields__):
        raise ValueError("upgrade receipt has invalid fields")
    receipt = UpgradeReceipt(**payload)
    _validate(receipt)
    if path.name != f"{receipt.receipt_id}.json":
        raise ValueError("upgrade receipt identity mismatch")
    return receipt


def _secure_receipt_directory(data_dir: str) -> Path:
    root = Path(os.path.abspath(os.path.expanduser(data_dir)))
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = root / UPGRADE_RECEIPT_DIRECTORY
    try:
        info = path.lstat()
    except FileNotFoundError:
        path.mkdir(mode=0o700)
    else:
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise OSError("upgrade receipt location is not a private directory")
    if os.name == "posix":
        os.chmod(path, 0o700)
    return path


def _ensure_queue_capacity(receipt_dir: Path) -> None:
    count = sum(1 for entry in receipt_dir.iterdir() if entry.name.endswith(".json"))
    if count >= MAX_UPGRADE_RECEIPTS:
        raise OSError("upgrade receipt queue is full")


def _atomic_write(path: Path, receipt: UpgradeReceipt) -> None:
    encoded = json.dumps(receipt.to_dict(), sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(encoded) > MAX_UPGRADE_RECEIPT_BYTES:
        raise ValueError("upgrade receipt exceeds its size bound")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".receipt-", suffix=".tmp", dir=path.parent)
    try:
        if os.name == "posix":
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        if os.name == "posix":
            os.chmod(path, 0o600)
            directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def _validate(receipt: UpgradeReceipt) -> None:
    if receipt.schema_version != UPGRADE_RECEIPT_SCHEMA_VERSION:
        raise ValueError("unsupported upgrade receipt schema")
    try:
        parsed_id = uuid.UUID(receipt.receipt_id)
    except (ValueError, TypeError, AttributeError) as exc:
        raise ValueError("invalid upgrade receipt id") from exc
    if str(parsed_id) != receipt.receipt_id:
        raise ValueError("upgrade receipt id is not canonical")
    if (
        len(receipt.from_version) > 32
        or len(receipt.target_version) > 32
        or not _VERSION_RE.fullmatch(receipt.from_version)
        or not _VERSION_RE.fullmatch(receipt.target_version)
    ):
        raise ValueError("invalid upgrade receipt version")
    if receipt.status not in _STATUSES or receipt.migration_status not in _MIGRATION_STATUSES:
        raise ValueError("invalid upgrade receipt state")
    if receipt.failure_code not in _FAILURE_CODES:
        raise ValueError("invalid upgrade receipt failure code")
    if receipt.migration_count is not None and (
        not isinstance(receipt.migration_count, int)
        or isinstance(receipt.migration_count, bool)
        or not 0 <= receipt.migration_count <= 10_000
    ):
        raise ValueError("invalid upgrade receipt migration count")
    if not isinstance(receipt.artifacts_verified, bool):
        raise ValueError("invalid upgrade receipt verification state")
    created_at = _parse_time(receipt.created_at)
    if receipt.status == "pending":
        if receipt.completed_at is not None or receipt.failure_code:
            raise ValueError("pending upgrade receipt has terminal facts")
    else:
        if receipt.completed_at is None:
            raise ValueError("terminal upgrade receipt is missing its timestamp")
        if _parse_time(receipt.completed_at) < created_at:
            raise ValueError("upgrade receipt completes before it was created")
    if receipt.status in {"succeeded", "partial"} and receipt.failure_code:
        raise ValueError("successful upgrade receipt has failure code")
    if receipt.status in {"failed", "rolled_back"} and not receipt.failure_code:
        raise ValueError("failed upgrade receipt is missing failure code")
    if receipt.status == "succeeded" and receipt.migration_status == "degraded":
        raise ValueError("degraded migration cannot report full success")


def _parse_time(value: str) -> datetime:
    if not isinstance(value, str) or not value or len(value) > 64:
        raise ValueError("invalid upgrade receipt timestamp")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("upgrade receipt timestamp must include a timezone")
    return parsed


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


__all__ = [
    "MAX_UPGRADE_RECEIPT_BYTES",
    "MAX_UPGRADE_RECEIPTS",
    "UPGRADE_RECEIPT_DIRECTORY",
    "UpgradeReceipt",
    "begin_upgrade_receipt",
    "complete_upgrade_receipt",
    "finalize_interrupted_upgrade_receipts",
    "load_upgrade_receipt",
    "record_upgrade_migrations",
]
