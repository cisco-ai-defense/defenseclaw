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
MAX_LOCAL_BUNDLE_INTENT_BYTES: Final[int] = 1024
MAX_UPGRADE_SUPERSESSION_BYTES: Final[int] = 1024
_LOCAL_BUNDLE_INTENT_SCHEMA_VERSION: Final[int] = 1
_LOCAL_BUNDLE_INTENT_SUFFIX: Final[str] = ".local-bundle-intent"
_UPGRADE_SUPERSESSION_SCHEMA_VERSION: Final[int] = 1
_UPGRADE_SUPERSESSION_SUFFIX: Final[str] = ".superseded-by"

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
_RECOVERABLE_TARGET_FAILURE_CODES = frozenset(
    {
        "migration_failed",
        "required_migration_failed",
        "local_observability_failed",
        "startup_failed",
        "health_check_failed",
        "interrupted",
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


@dataclass(frozen=True)
class UpgradeReceiptSupersession:
    receipt_id: str
    target_version: str
    superseded_by_receipt_id: str
    health_proven: bool


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
    remove_bundle_intent = status == "rolled_back"
    if status in {"succeeded", "partial"}:
        try:
            remove_bundle_intent = load_local_bundle_restart_intent(path) is False
        except (OSError, ValueError, json.JSONDecodeError):
            remove_bundle_intent = False
    if remove_bundle_intent:
        try:
            _local_bundle_intent_path(path, updated).unlink()
        except OSError:
            pass
    return updated


def record_local_bundle_restart_intent(path: Path, *, restart_required: bool) -> bool:
    """Durably bind a monotonic bundle restart requirement to one attempt."""

    if not isinstance(restart_required, bool):
        raise ValueError("local bundle restart intent must be boolean")
    receipt = load_upgrade_receipt(path)
    if receipt.status != "pending" or not receipt.artifacts_verified:
        raise ValueError("local bundle restart intent requires a verified pending receipt")
    existing = load_local_bundle_restart_intent(path)
    durable = restart_required or existing is True
    payload = {
        "schema_version": _LOCAL_BUNDLE_INTENT_SCHEMA_VERSION,
        "receipt_id": receipt.receipt_id,
        "target_version": receipt.target_version,
        "restart_required": durable,
    }
    _atomic_write_private_json(
        _local_bundle_intent_path(path, receipt),
        payload,
        maximum=MAX_LOCAL_BUNDLE_INTENT_BYTES,
    )
    return durable


def load_local_bundle_restart_intent(path: Path) -> bool | None:
    """Read one receipt-bound restart requirement without following links."""

    receipt = load_upgrade_receipt(path)
    intent_path = _local_bundle_intent_path(path, receipt)
    payload = _load_private_json(
        intent_path,
        maximum=MAX_LOCAL_BUNDLE_INTENT_BYTES,
        kind="local bundle restart intent",
    )
    if payload is None:
        return None
    if (
        not isinstance(payload, dict)
        or set(payload) != {"schema_version", "receipt_id", "target_version", "restart_required"}
        or payload["schema_version"] != _LOCAL_BUNDLE_INTENT_SCHEMA_VERSION
        or payload["receipt_id"] != receipt.receipt_id
        or payload["target_version"] != receipt.target_version
        or not isinstance(payload["restart_required"], bool)
    ):
        raise ValueError("local bundle restart intent is invalid")
    return payload["restart_required"]


def record_upgrade_receipt_supersession(
    path: Path,
    *,
    replacement_path: Path,
    health_proven: bool,
) -> str:
    """Durably transfer retry authority from one terminal receipt to a pending one."""

    receipt = load_upgrade_receipt(path)
    replacement = load_upgrade_receipt(replacement_path)
    if (
        receipt.status not in _TERMINAL_STATUSES
        or not receipt.artifacts_verified
        or replacement.status != "pending"
        or not replacement.artifacts_verified
        or receipt.target_version != replacement.target_version
        or path.parent != replacement_path.parent
        or path == replacement_path
    ):
        raise ValueError("upgrade receipt supersession requires one verified target retry")
    if not isinstance(health_proven, bool):
        raise ValueError("upgrade receipt supersession phase must be boolean")
    existing = load_upgrade_receipt_supersession(path)
    if existing is not None and existing.health_proven:
        return existing.superseded_by_receipt_id
    payload = {
        "schema_version": _UPGRADE_SUPERSESSION_SCHEMA_VERSION,
        "receipt_id": receipt.receipt_id,
        "target_version": receipt.target_version,
        "superseded_by_receipt_id": replacement.receipt_id,
        "health_proven": health_proven,
    }
    _atomic_write_private_json(
        _upgrade_supersession_path(path, receipt),
        payload,
        maximum=MAX_UPGRADE_SUPERSESSION_BYTES,
    )
    return replacement.receipt_id


def load_upgrade_receipt_supersession(path: Path) -> UpgradeReceiptSupersession | None:
    """Return the receipt ID that durably owns a superseded attempt."""

    receipt = load_upgrade_receipt(path)
    payload = _load_private_json(
        _upgrade_supersession_path(path, receipt),
        maximum=MAX_UPGRADE_SUPERSESSION_BYTES,
        kind="upgrade receipt supersession",
    )
    if payload is None:
        return None
    if (
        not isinstance(payload, dict)
        or set(payload)
        != {
            "schema_version",
            "receipt_id",
            "target_version",
            "superseded_by_receipt_id",
            "health_proven",
        }
        or payload["schema_version"] != _UPGRADE_SUPERSESSION_SCHEMA_VERSION
        or payload["receipt_id"] != receipt.receipt_id
        or payload["target_version"] != receipt.target_version
        or not isinstance(payload["health_proven"], bool)
    ):
        raise ValueError("upgrade receipt supersession is invalid")
    replacement_id = payload["superseded_by_receipt_id"]
    try:
        parsed_id = uuid.UUID(replacement_id)
    except (ValueError, TypeError, AttributeError) as exc:
        raise ValueError("upgrade receipt supersession is invalid") from exc
    if str(parsed_id) != replacement_id or replacement_id == receipt.receipt_id:
        raise ValueError("upgrade receipt supersession is invalid")
    return UpgradeReceiptSupersession(
        receipt_id=receipt.receipt_id,
        target_version=receipt.target_version,
        superseded_by_receipt_id=replacement_id,
        health_proven=payload["health_proven"],
    )


def clear_local_bundle_restart_intent(path: Path) -> None:
    """Clear restart custody after readiness or a newer receipt supersedes it."""

    receipt = load_upgrade_receipt(path)
    if not receipt.artifacts_verified:
        raise ValueError("local bundle restart intent requires a verified receipt")
    if load_local_bundle_restart_intent(path) is None:
        return
    intent_path = _local_bundle_intent_path(path, receipt)
    try:
        intent_path.unlink()
    except FileNotFoundError:
        # Another recovery process may clear the same receipt-bound intent
        # after the validated read above. The desired durable state is already
        # present, while every other unlink failure must remain actionable.
        return
    if os.name == "posix":
        directory_fd = os.open(intent_path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)


def _verified_pending_target_queue(
    receipt_path: Path,
) -> tuple[UpgradeReceipt, list[tuple[Path, UpgradeReceipt]]]:
    """Validate one pending retry and return its bounded receipt queue."""

    current = load_upgrade_receipt(receipt_path)
    if current.status != "pending" or not current.artifacts_verified:
        raise ValueError("bundle restart recovery requires a verified pending receipt")
    if receipt_path.parent.name != UPGRADE_RECEIPT_DIRECTORY:
        raise ValueError("bundle restart recovery receipt is outside its private queue")
    queue = _read_verified_receipt_queue(str(receipt_path.parent.parent))
    pending = [
        receipt.receipt_id
        for _, receipt in queue
        if receipt.target_version == current.target_version and receipt.status == "pending"
    ]
    if pending != [current.receipt_id]:
        raise ValueError("bundle restart recovery requires one pending target receipt")
    return current, queue


def delegate_prior_upgrade_receipts(receipt_path: Path) -> int:
    """Delegate prior retry authority to a newly verified pending attempt."""

    current, queue = _verified_pending_target_queue(receipt_path)
    delegated = 0
    for path, receipt in queue:
        if (
            path == receipt_path
            or receipt.target_version != current.target_version
            or not receipt.artifacts_verified
            or receipt.status == "pending"
        ):
            continue
        existing = load_upgrade_receipt_supersession(path)
        if existing is not None and existing.health_proven:
            continue
        restart_intent = load_local_bundle_restart_intent(path)
        if not _is_recoverable_target(receipt, restart_intent):
            continue
        record_upgrade_receipt_supersession(
            path,
            replacement_path=receipt_path,
            health_proven=False,
        )
        delegated += 1
    return delegated


def supersede_prior_upgrade_receipts(receipt_path: Path) -> int:
    """Promote prior target delegations after the pending retry proves health."""

    current, queue = _verified_pending_target_queue(receipt_path)
    superseded = 0
    for path, receipt in queue:
        if (
            path == receipt_path
            or receipt.target_version != current.target_version
            or not receipt.artifacts_verified
            or receipt.status == "pending"
        ):
            continue
        restart_intent = load_local_bundle_restart_intent(path)
        if not _is_recoverable_target(receipt, restart_intent):
            continue
        marker = load_upgrade_receipt_supersession(path)
        if marker is not None and marker.health_proven:
            continue
        record_upgrade_receipt_supersession(
            path,
            replacement_path=receipt_path,
            health_proven=True,
        )
        superseded += 1
    return superseded


def _local_bundle_intent_path(path: Path, receipt: UpgradeReceipt) -> Path:
    if path.name != f"{receipt.receipt_id}.json":
        raise ValueError("upgrade receipt identity mismatch")
    return path.with_name(f"{receipt.receipt_id}{_LOCAL_BUNDLE_INTENT_SUFFIX}")


def _upgrade_supersession_path(path: Path, receipt: UpgradeReceipt) -> Path:
    if path.name != f"{receipt.receipt_id}.json":
        raise ValueError("upgrade receipt identity mismatch")
    return path.with_name(f"{receipt.receipt_id}{_UPGRADE_SUPERSESSION_SUFFIX}")


def _is_recoverable_target(
    receipt: UpgradeReceipt,
    restart_intent: bool | None = None,
) -> bool:
    """Return whether a receipt retains authenticated target recovery custody."""

    if not receipt.artifacts_verified:
        return False
    if receipt.status == "failed":
        return receipt.failure_code in _RECOVERABLE_TARGET_FAILURE_CODES
    return receipt.status in {"succeeded", "partial"} and restart_intent is True


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


def find_resumable_upgrade_receipt(data_dir: str, *, target_version: str) -> Path | None:
    """Return durable recovery authority for an installed target.

    This lookup is deliberately read-only when the queue does not exist. The
    sole pending receipt remains the retry authority until fresh target health
    checks complete. A bounded delegation marker makes one pending retry the
    sole authority; only its health-proven promotion can suppress the older
    authority after the retry receipt itself has been acknowledged.
    """

    if _VERSION_RE.fullmatch(target_version) is None:
        raise ValueError("invalid resumable upgrade target version")
    queue = _read_verified_receipt_queue(data_dir)
    matches: list[tuple[Path, UpgradeReceipt]] = []
    for path, receipt in queue:
        if receipt.target_version != target_version:
            continue
        if receipt.status == "pending" and not receipt.artifacts_verified:
            raise ValueError("pending upgrade receipt did not authenticate target artifacts")
        matches.append((path, receipt))
    pending = [(path, receipt) for path, receipt in matches if receipt.status == "pending"]
    if len(pending) > 1:
        raise ValueError("multiple pending upgrade receipts target the installed version")
    by_id = {receipt.receipt_id: receipt for _, receipt in queue}
    superseded: set[Path] = set()
    for path, receipt in matches:
        if receipt.status == "pending":
            continue
        marker = load_upgrade_receipt_supersession(path)
        if marker is None:
            continue
        replacement = by_id.get(marker.superseded_by_receipt_id)
        if marker.health_proven:
            superseded.add(path)
        elif replacement is not None:
            if not replacement.artifacts_verified or replacement.target_version != target_version:
                raise ValueError("upgrade receipt delegation points to an invalid target retry")
            superseded.add(path)
    if pending:
        return pending[0][0]
    authorities: list[Path] = []
    for path, receipt in matches:
        if receipt.status == "pending":
            continue
        if path in superseded:
            continue
        restart_intent = None
        if receipt.status in {"succeeded", "partial"}:
            restart_intent = load_local_bundle_restart_intent(path)
        if _is_recoverable_target(receipt, restart_intent):
            authorities.append(path)
    if len(authorities) > 1:
        raise ValueError("multiple terminal receipts claim target recovery authority")
    return authorities[0] if authorities else None


def find_verified_installed_upgrade_receipt(
    data_dir: str,
    *,
    target_version: str,
) -> Path | None:
    """Return the latest verified receipt proving target installation.

    This is narrower than resumable recovery authority: a terminal success or
    partial receipt cannot itself be mutated, but it can authenticate the
    already-installed target before a fresh receipt reconciles target-owned
    bundle state. Hosts without that durable evidence fail closed instead of
    trusting a version string alone.
    """

    if _VERSION_RE.fullmatch(target_version) is None:
        raise ValueError("invalid installed upgrade target version")
    matches = [
        (path, receipt)
        for path, receipt in _read_verified_receipt_queue(data_dir)
        if receipt.target_version == target_version
        and receipt.artifacts_verified
        and receipt.status in {"succeeded", "partial"}
    ]
    if not matches:
        return None
    return max(
        matches,
        key=lambda item: (item[1].created_at, item[1].status == "succeeded"),
    )[0]


def _read_verified_receipt_queue(data_dir: str) -> list[tuple[Path, UpgradeReceipt]]:
    """Read the bounded private receipt queue or fail closed.

    Receipts are local durable authority, so silently skipping a malformed or
    replaceable entry could turn an interrupted same-version transaction into
    a false no-op. POSIX queues and records must remain owned by the current
    account and inaccessible to group/other users.
    """

    root = Path(os.path.abspath(os.path.expanduser(data_dir)))
    try:
        root_info = root.lstat()
    except FileNotFoundError:
        return []
    if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
        raise OSError("upgrade receipt root is not a directory")
    receipt_dir = root / UPGRADE_RECEIPT_DIRECTORY
    try:
        receipt_info = receipt_dir.lstat()
    except FileNotFoundError:
        return []
    if stat.S_ISLNK(receipt_info.st_mode) or not stat.S_ISDIR(receipt_info.st_mode):
        raise OSError("upgrade receipt location is not a private directory")
    _require_private_posix_receipt_path(receipt_info, kind="directory")

    entries = sorted(receipt_dir.glob("*.json"))
    if len(entries) > MAX_UPGRADE_RECEIPTS:
        raise OSError("upgrade receipt queue exceeds its bound")
    receipts: list[tuple[Path, UpgradeReceipt]] = []
    for path in entries:
        try:
            info = path.lstat()
        except OSError as exc:
            raise ValueError("upgrade receipt queue changed while reading") from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise ValueError("upgrade receipt queue contains an unsafe entry")
        _require_private_posix_receipt_path(info, kind="record")
        try:
            receipt = load_upgrade_receipt(path)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            raise ValueError("upgrade receipt queue contains an invalid entry") from exc
        receipts.append((path, receipt))
    return receipts


def _require_private_posix_receipt_path(info: os.stat_result, *, kind: str) -> None:
    if os.name != "posix":
        return
    geteuid = getattr(os, "geteuid", None)
    if geteuid is not None and info.st_uid != geteuid():
        raise OSError(f"upgrade receipt {kind} is not owned by the current account")
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise OSError(f"upgrade receipt {kind} is accessible to other accounts")


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
        stream = os.fdopen(fd, "wb")
        fd = -1
        with stream:
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
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def _atomic_write_private_json(path: Path, payload: dict[str, object], *, maximum: int) -> None:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if not encoded or len(encoded) > maximum:
        raise ValueError("private receipt metadata exceeds its size bound")
    fd, temporary = tempfile.mkstemp(prefix=".receipt-metadata-", suffix=".tmp", dir=path.parent)
    try:
        if os.name == "posix":
            os.fchmod(fd, 0o600)
        stream = os.fdopen(fd, "wb")
        fd = -1
        with stream:
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
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def _load_private_json(path: Path, *, maximum: int, kind: str) -> object | None:
    """Read bounded private receipt metadata without following replacements."""

    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise ValueError(f"{kind} must be a regular file")
    _require_private_posix_receipt_path(info, kind=kind)
    if info.st_size <= 0 or info.st_size > maximum:
        raise ValueError(f"{kind} has invalid size")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ValueError(f"{kind} could not be opened safely") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_size <= 0
            or opened.st_size > maximum
            or not os.path.samestat(info, opened)
        ):
            raise ValueError(f"{kind} changed while opening")
        raw = os.read(descriptor, maximum + 1)
    finally:
        os.close(descriptor)
    try:
        return json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{kind} is invalid") from exc


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
    "MAX_UPGRADE_SUPERSESSION_BYTES",
    "UPGRADE_RECEIPT_DIRECTORY",
    "UpgradeReceipt",
    "UpgradeReceiptSupersession",
    "begin_upgrade_receipt",
    "clear_local_bundle_restart_intent",
    "complete_upgrade_receipt",
    "delegate_prior_upgrade_receipts",
    "find_resumable_upgrade_receipt",
    "find_verified_installed_upgrade_receipt",
    "finalize_interrupted_upgrade_receipts",
    "load_local_bundle_restart_intent",
    "load_upgrade_receipt",
    "load_upgrade_receipt_supersession",
    "record_local_bundle_restart_intent",
    "record_upgrade_receipt_supersession",
    "record_upgrade_migrations",
    "supersede_prior_upgrade_receipts",
]
