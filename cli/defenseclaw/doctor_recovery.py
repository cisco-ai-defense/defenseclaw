# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""Custody-bound recovery plans for narrowly missing local state.

Planning is read-only.  Application is explicit, revalidates the controlled
directory identity chain, and publishes with no-overwrite semantics.  These
helpers intentionally do not provide a generic ``apply(plan)`` function:
identity-key recovery and audit-database recovery have different continuity
and unattended-use policies.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import ntpath
import os
import sqlite3
import stat
import tempfile
import urllib.parse
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

_DEVICE_PROVENANCE_PREFIX = b"defenseclaw-device-provenance-v1:"
_DEVICE_PROVENANCE_SECRET = "device.provenance.secret"
_AUDIT_REQUIRED_TABLES = frozenset({"audit_events", "scan_results", "findings"})


class RecoveryKind(str, Enum):
    AUDIT_DB = "audit-db"
    DEVICE_KEY = "device-key"


class RecoveryDisposition(str, Enum):
    READY = "ready"
    NOT_NEEDED = "not-needed"
    BLOCKED = "blocked"


class RecoveryApplyStatus(str, Enum):
    CREATED = "created"
    FAILED = "failed"


class DeviceKeyHealthStatus(str, Enum):
    VALID = "valid"
    LEGACY_UNPROVENANCED = "legacy-unprovenanced"
    MISSING = "missing"
    INVALID = "invalid"


class AuditDBHealthStatus(str, Enum):
    VALID = "valid"
    MISSING = "missing"
    INVALID = "invalid"


@dataclass(frozen=True)
class AuditDBHealth:
    status: AuditDBHealthStatus
    reason_code: str


@dataclass(frozen=True)
class DeviceKeyHealth:
    status: DeviceKeyHealthStatus
    reason_code: str


@dataclass(frozen=True)
class DirectoryIdentity:
    path: str
    device: int
    inode: int
    mode: int
    owner: int


@dataclass(frozen=True)
class WindowsDirectoryIdentity:
    path: str
    device: int
    inode: int
    security: object = field(repr=False)


@dataclass(frozen=True)
class CustodySnapshot:
    platform: str
    directories: tuple[DirectoryIdentity, ...] = ()
    windows_directories: tuple[WindowsDirectoryIdentity, ...] = ()


@dataclass(frozen=True)
class RecoveryPlan:
    kind: RecoveryKind
    target: str
    data_dir: str
    disposition: RecoveryDisposition
    reason_code: str
    summary: str
    custody: CustodySnapshot | None = None
    continuity_paths: tuple[str, ...] = ()
    unattended_allowed: bool = False


@dataclass(frozen=True)
class RecoveryApplyResult:
    kind: RecoveryKind
    status: RecoveryApplyStatus
    reason_code: str
    created_artifacts: tuple[str, ...] = ()


class RecoveryRefusedError(RuntimeError):
    """A safe, bounded refusal from a recovery authorization or recheck."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class RecoveryPublicationError(OSError):
    """A bounded publication failure that records whether a name was created."""

    def __init__(self, code: str, *, created: bool) -> None:
        self.code = code
        self.created = created
        super().__init__(code)


def inspect_audit_db(
    target: str | os.PathLike[str],
    *,
    data_dir: str | os.PathLike[str],
) -> AuditDBHealth:
    """Inspect an existing audit database without creating or replacing it."""

    plan = plan_missing_audit_db(target, data_dir=data_dir)
    if plan.disposition is RecoveryDisposition.READY:
        return AuditDBHealth(AuditDBHealthStatus.MISSING, "audit-db-missing")
    if plan.disposition is RecoveryDisposition.BLOCKED:
        return AuditDBHealth(AuditDBHealthStatus.INVALID, plan.reason_code)
    if plan.custody is None:
        return AuditDBHealth(AuditDBHealthStatus.INVALID, "audit-db-custody-unavailable")
    if not _private_file_postconditions(
        plan.target,
        platform=plan.custody.platform,
        confidential=True,
    ):
        return AuditDBHealth(AuditDBHealthStatus.INVALID, "audit-db-custody-invalid")

    try:
        inspected = os.lstat(plan.target)
        uri = Path(os.path.abspath(plan.target)).as_uri() + "?" + urllib.parse.urlencode(
            {"mode": "ro"}
        )
        connection = sqlite3.connect(uri, uri=True, timeout=0.1)
        try:
            connection.execute("PRAGMA query_only=ON")
            quick_check = connection.execute("PRAGMA quick_check(1)").fetchone()
            tables = {
                str(row[0])
                for row in connection.execute(
                    "SELECT name FROM sqlite_master "
                    "WHERE type='table' AND name IN ('audit_events', 'scan_results', 'findings')"
                )
            }
        finally:
            connection.close()
        if not os.path.samestat(inspected, os.lstat(plan.target)):
            return AuditDBHealth(AuditDBHealthStatus.INVALID, "audit-db-changed-during-inspection")
    except (OSError, sqlite3.Error, ValueError):
        return AuditDBHealth(AuditDBHealthStatus.INVALID, "audit-db-integrity-unavailable")

    if quick_check != ("ok",):
        return AuditDBHealth(AuditDBHealthStatus.INVALID, "audit-db-corrupt")
    if tables != _AUDIT_REQUIRED_TABLES:
        return AuditDBHealth(AuditDBHealthStatus.INVALID, "audit-db-schema-incomplete")
    return AuditDBHealth(AuditDBHealthStatus.VALID, "audit-db-valid")


def inspect_device_key(
    target: str | os.PathLike[str],
    *,
    data_dir: str | os.PathLike[str],
) -> DeviceKeyHealth:
    """Inspect an existing identity without trusting path or payload text."""

    plan = plan_missing_device_key(target, data_dir=data_dir)
    if plan.disposition is RecoveryDisposition.READY:
        return DeviceKeyHealth(DeviceKeyHealthStatus.MISSING, "device-key-missing")
    if plan.disposition is RecoveryDisposition.BLOCKED:
        return DeviceKeyHealth(DeviceKeyHealthStatus.INVALID, plan.reason_code)
    if plan.custody is None:
        return DeviceKeyHealth(DeviceKeyHealthStatus.INVALID, "device-key-custody-unavailable")

    platform = plan.custody.platform
    if not _private_file_postconditions(plan.target, platform=platform, confidential=True):
        return DeviceKeyHealth(DeviceKeyHealthStatus.INVALID, "device-key-custody-invalid")
    try:
        key_data = _read_private_regular_file(plan.target, max_bytes=4096, platform=platform)
    except OSError:
        return DeviceKeyHealth(DeviceKeyHealthStatus.INVALID, "device-key-read-failed")
    if not _valid_device_key_bytes(key_data):
        return DeviceKeyHealth(DeviceKeyHealthStatus.INVALID, "device-key-payload-invalid")

    secret_path = os.path.join(plan.data_dir, _DEVICE_PROVENANCE_SECRET)
    provenance_path = plan.target + ".provenance"
    secret_exists = os.path.lexists(secret_path)
    provenance_exists = os.path.lexists(provenance_path)
    if secret_exists and provenance_exists:
        if _device_key_postconditions(
            plan.target,
            secret_path,
            provenance_path,
            platform=platform,
        ):
            return DeviceKeyHealth(DeviceKeyHealthStatus.VALID, "device-key-provenance-valid")
        return DeviceKeyHealth(DeviceKeyHealthStatus.INVALID, "device-key-provenance-invalid")
    if secret_exists:
        return DeviceKeyHealth(DeviceKeyHealthStatus.INVALID, "device-key-provenance-incomplete")
    if provenance_exists:
        try:
            legacy = _read_private_regular_file(
                provenance_path,
                max_bytes=4096,
                platform=platform,
            )
        except OSError:
            return DeviceKeyHealth(DeviceKeyHealthStatus.INVALID, "device-key-provenance-invalid")
        if legacy.startswith(b"# DefenseClaw device.key provenance sentinel\n"):
            return DeviceKeyHealth(
                DeviceKeyHealthStatus.LEGACY_UNPROVENANCED,
                "device-key-legacy-provenance",
            )
        return DeviceKeyHealth(DeviceKeyHealthStatus.INVALID, "device-key-provenance-incomplete")
    return DeviceKeyHealth(
        DeviceKeyHealthStatus.LEGACY_UNPROVENANCED,
        "device-key-provenance-absent",
    )


def plan_missing_audit_db(
    target: str | os.PathLike[str],
    *,
    data_dir: str | os.PathLike[str],
    continuity_paths: tuple[str | os.PathLike[str], ...] = (),
) -> RecoveryPlan:
    """Read-only plan for a genuinely absent audit database.

    Orphaned SQLite journal/WAL files are continuity evidence and fail closed;
    creating an empty database beside them could conceal lost audit history.
    """

    normalized_target = _normalize_disk_path(target)
    normalized_data = _normalize_disk_path(data_dir)
    if normalized_target and normalized_data:
        markers = (
            normalized_target + "-wal",
            normalized_target + "-shm",
            normalized_target + "-journal",
            *continuity_paths,
        )
    else:
        markers = continuity_paths
    return _plan_missing_target(
        RecoveryKind.AUDIT_DB,
        normalized_target,
        normalized_data,
        markers,
        unattended_allowed=True,
    )


def plan_missing_device_key(
    target: str | os.PathLike[str],
    *,
    data_dir: str | os.PathLike[str],
    continuity_paths: tuple[str | os.PathLike[str], ...] = (),
) -> RecoveryPlan:
    """Read-only plan for an absent device identity.

    A provenance sentinel or provenance secret with no key means identity
    continuity is ambiguous.  Automatic regeneration is refused rather than
    silently changing the device ID, telemetry HMAC root, and derived proxy
    credentials.
    """

    normalized_target = _normalize_disk_path(target)
    normalized_data = _normalize_disk_path(data_dir)
    if normalized_target and normalized_data:
        alias_reason = _device_identity_artifact_alias_reason(
            normalized_target,
            normalized_data,
        )
        if alias_reason is not None:
            return _blocked_plan(
                RecoveryKind.DEVICE_KEY,
                normalized_target,
                normalized_data,
                alias_reason,
            )
        markers = (
            normalized_target + ".provenance",
            os.path.join(normalized_data, _DEVICE_PROVENANCE_SECRET),
            *continuity_paths,
        )
    else:
        markers = continuity_paths
    return _plan_missing_target(
        RecoveryKind.DEVICE_KEY,
        normalized_target,
        normalized_data,
        markers,
        unattended_allowed=False,
    )


def _device_identity_artifact_alias_reason(target: str, data_dir: str) -> str | None:
    """Reject device identity layouts whose publications can alias each other."""

    if os.name == "nt" and any(
        _windows_path_has_alternate_data_stream(path) for path in (target, data_dir)
    ):
        return "windows-alternate-data-stream-path"
    secret_target = os.path.join(data_dir, _DEVICE_PROVENANCE_SECRET)
    provenance_target = target + ".provenance"
    normalized = tuple(
        _normalize_device_identity_path(candidate)
        for candidate in (target, secret_target, provenance_target)
    )
    if len(set(normalized)) != len(normalized):
        return "identity-artifact-alias"
    folded_target = _normalize_device_identity_path(target)
    folded_secret = _normalize_device_identity_path(secret_target)
    if folded_target.startswith(folded_secret + os.sep):
        return "reserved-provenance-secret-path"
    return None


def _windows_path_has_alternate_data_stream(path: str | os.PathLike[str]) -> bool:
    _volume, remainder = ntpath.splitdrive(os.fspath(path))
    return ":" in remainder


def _normalize_device_identity_path(path: str | os.PathLike[str]) -> str:
    """Return the conservative comparison spelling for identity artifacts."""

    return os.path.normpath(os.fspath(path)).casefold()


def _device_identity_paths_equal(
    left: str | os.PathLike[str],
    right: str | os.PathLike[str],
) -> bool:
    return _normalize_device_identity_path(left) == _normalize_device_identity_path(
        right
    )


def apply_audit_db_recovery(
    plan: RecoveryPlan,
    *,
    approved: bool,
    unattended: bool = False,
) -> RecoveryApplyResult:
    """Create and verify a new audit database from an exact approved plan."""

    _authorize_plan(plan, RecoveryKind.AUDIT_DB, approved=approved, unattended=unattended)
    _revalidate_plan(plan)
    parent = os.path.dirname(plan.target)
    temporary = ""
    published = False
    try:
        temporary = _stage_private_bytes(parent, ".doctor-audit-db.", b"")

        from defenseclaw.db import Store

        store = Store(temporary)
        try:
            store.init()
            # Recovery publishes one exact database file.  Force every schema
            # page out of WAL before publication so neither the POSIX hard
            # link nor the Windows CREATE_NEW payload can omit sidecar-only
            # state.
            store.db.commit()
            store.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            journal_mode = store.db.execute("PRAGMA journal_mode=DELETE").fetchone()
            if not journal_mode or str(journal_mode[0]).lower() != "delete":
                raise sqlite3.OperationalError("audit staging journal did not converge")
            store.db.commit()
        finally:
            store.close()
        if not _audit_db_is_valid(temporary):
            return RecoveryApplyResult(
                kind=RecoveryKind.AUDIT_DB,
                status=RecoveryApplyStatus.FAILED,
                reason_code="audit-db-staging-validation-failed",
            )

        _revalidate_plan(plan)
        if plan.custody.platform == "windows":
            payload = _read_private_regular_file(temporary, max_bytes=64 * 1024 * 1024, platform="windows")
            try:
                _windows_write_new_private_file(
                    plan.target,
                    payload,
                    plan.custody,
                    confidential=True,
                )
            except RecoveryPublicationError as exc:
                published = exc.created
                raise
            published = True
        else:
            _publish_no_replace(temporary, plan.target)
            published = True
            _fsync_directory(parent)
        if not _private_file_postconditions(
            plan.target,
            platform=plan.custody.platform,
            confidential=True,
        ) or not _audit_db_is_valid(plan.target):
            return RecoveryApplyResult(
                kind=RecoveryKind.AUDIT_DB,
                status=RecoveryApplyStatus.FAILED,
                reason_code="audit-db-postcondition-failed",
                created_artifacts=("audit-db",),
            )
        return RecoveryApplyResult(
            kind=RecoveryKind.AUDIT_DB,
            status=RecoveryApplyStatus.CREATED,
            reason_code="audit-db-created",
            created_artifacts=("audit-db",),
        )
    except RecoveryRefusedError:
        raise
    except (ImportError, OSError, RuntimeError, sqlite3.Error, ValueError):
        return RecoveryApplyResult(
            kind=RecoveryKind.AUDIT_DB,
            status=RecoveryApplyStatus.FAILED,
            reason_code="audit-db-create-failed",
            created_artifacts=("audit-db",) if published else (),
        )
    finally:
        _remove_staging_files(temporary)


def apply_device_key_recovery(
    plan: RecoveryPlan,
    *,
    approved: bool,
    unattended: bool = False,
) -> RecoveryApplyResult:
    """Create a new Ed25519 identity and HMAC-bound provenance artifacts.

    Device identity recovery is always attended.  Publication order places the
    provenance secret and HMAC sentinel before the key, so a crash can leave
    ambiguous continuity (which the next plan blocks) but never exposes a
    usable new identity before its provenance is durable.
    """

    _authorize_plan(plan, RecoveryKind.DEVICE_KEY, approved=approved, unattended=unattended)
    _revalidate_plan(plan)

    target_parent = os.path.dirname(plan.target)
    provenance_target = plan.target + ".provenance"
    secret_target = os.path.join(plan.data_dir, _DEVICE_PROVENANCE_SECRET)
    key_data = _new_device_key_pem()
    secret = os.urandom(32)
    digest = hmac.new(secret, key_data, hashlib.sha256).hexdigest().encode("ascii")
    provenance_data = _DEVICE_PROVENANCE_PREFIX + digest + b"\n"

    staged: list[str] = []
    published: list[str] = []
    try:
        secret_stage = _stage_private_bytes(plan.data_dir, ".doctor-device-provenance-secret.", secret)
        staged.append(secret_stage)
        key_stage = _stage_private_bytes(target_parent, ".doctor-device-key.", key_data)
        staged.append(key_stage)
        provenance_stage = _stage_private_bytes(
            target_parent,
            ".doctor-device-provenance.",
            provenance_data,
        )
        staged.append(provenance_stage)

        _revalidate_plan(plan)
        for source, destination, label in (
            (secret_stage, secret_target, "device-provenance-secret"),
            (provenance_stage, provenance_target, "device-provenance"),
            (key_stage, plan.target, "device-key"),
        ):
            # The data root is owner-private before staging, but a same-user
            # concurrent actor can still replace a nested component. Re-bind
            # the entire captured directory chain before every publication;
            # Windows additionally holds the destination chain lease inside
            # its CREATE_NEW adapter.
            _revalidate_directory_custody(plan)
            if plan.custody.platform == "windows":
                payload = _read_private_regular_file(source, max_bytes=4096, platform="windows")
                try:
                    _windows_write_new_private_file(
                        destination,
                        payload,
                        plan.custody,
                        confidential=True,
                    )
                except RecoveryPublicationError as exc:
                    if exc.created:
                        published.append(label)
                    raise
                published.append(label)
            else:
                _publish_no_replace(source, destination)
                published.append(label)
                _fsync_directory(os.path.dirname(destination))

        if not _device_key_postconditions(
            plan.target,
            secret_target,
            provenance_target,
            platform=plan.custody.platform,
        ):
            return RecoveryApplyResult(
                kind=RecoveryKind.DEVICE_KEY,
                status=RecoveryApplyStatus.FAILED,
                reason_code="device-key-postcondition-failed",
                created_artifacts=tuple(published),
            )
        return RecoveryApplyResult(
            kind=RecoveryKind.DEVICE_KEY,
            status=RecoveryApplyStatus.CREATED,
            reason_code="device-key-created",
            created_artifacts=tuple(published),
        )
    except RecoveryRefusedError:
        raise
    except (ImportError, OSError, RuntimeError, ValueError):
        return RecoveryApplyResult(
            kind=RecoveryKind.DEVICE_KEY,
            status=RecoveryApplyStatus.FAILED,
            reason_code=("device-key-recovery-incomplete" if published else "device-key-create-failed"),
            created_artifacts=tuple(published),
        )
    finally:
        for path in staged:
            _remove_staging_files(path)


def _plan_missing_target(
    kind: RecoveryKind,
    target: str,
    data_dir: str,
    continuity_paths: tuple[str | os.PathLike[str], ...],
    *,
    unattended_allowed: bool,
) -> RecoveryPlan:
    if not target or not data_dir:
        return _blocked_plan(kind, target, data_dir, "invalid-recovery-path")
    if _path_is_filesystem_root(data_dir):
        return _blocked_plan(kind, target, data_dir, "data-dir-too-broad")

    try:
        common = os.path.commonpath((target, data_dir))
        if not _device_identity_paths_equal(
            common, data_dir
        ) or _device_identity_paths_equal(target, data_dir):
            return _blocked_plan(kind, target, data_dir, "target-outside-data-dir")
    except ValueError:
        return _blocked_plan(kind, target, data_dir, "target-outside-data-dir")

    parent = os.path.dirname(target)
    try:
        custody = _custody_snapshot(data_dir, parent)
    except RecoveryRefusedError as exc:
        return _blocked_plan(kind, target, data_dir, exc.code)

    try:
        target_stat = os.lstat(target)
    except FileNotFoundError:
        target_stat = None
    except OSError:
        return _blocked_plan(kind, target, data_dir, "target-custody-unavailable")
    if target_stat is not None:
        target_attributes = int(getattr(target_stat, "st_file_attributes", 0))
        if (
            stat.S_ISREG(target_stat.st_mode)
            and not stat.S_ISLNK(target_stat.st_mode)
            and not target_attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        ):
            return RecoveryPlan(
                kind=kind,
                target=target,
                data_dir=data_dir,
                disposition=RecoveryDisposition.NOT_NEEDED,
                reason_code="target-already-exists",
                summary=f"{kind.value} recovery is not needed",
                custody=custody,
                unattended_allowed=unattended_allowed,
            )
        return _blocked_plan(kind, target, data_dir, "target-is-not-regular-file")

    normalized_markers: list[str] = []
    for raw_marker in continuity_paths:
        marker = _normalize_disk_path(raw_marker)
        if not marker:
            return _blocked_plan(kind, target, data_dir, "invalid-continuity-path")
        if marker not in normalized_markers:
            normalized_markers.append(marker)
    for marker in normalized_markers:
        try:
            os.lstat(marker)
        except FileNotFoundError:
            continue
        except OSError:
            return _blocked_plan(kind, target, data_dir, "continuity-custody-unavailable")
        return RecoveryPlan(
            kind=kind,
            target=target,
            data_dir=data_dir,
            disposition=RecoveryDisposition.BLOCKED,
            reason_code="continuity-evidence-present",
            summary=f"{kind.value} continuity evidence requires operator review",
            custody=custody,
            continuity_paths=tuple(normalized_markers),
            unattended_allowed=unattended_allowed,
        )

    return RecoveryPlan(
        kind=kind,
        target=target,
        data_dir=data_dir,
        disposition=RecoveryDisposition.READY,
        reason_code="missing-target-safe-to-create",
        summary=f"{kind.value} is absent and custody checks permit creation",
        custody=custody,
        continuity_paths=tuple(normalized_markers),
        unattended_allowed=unattended_allowed,
    )


def _path_is_filesystem_root(path: str, *, path_module=None) -> bool:
    """Recognize POSIX, drive, and UNC roots using native path semantics."""

    module = path_module or os.path
    normalized = module.normpath(path)
    return bool(normalized) and module.dirname(normalized) == normalized


def _blocked_plan(
    kind: RecoveryKind,
    target: str,
    data_dir: str,
    code: str,
) -> RecoveryPlan:
    return RecoveryPlan(
        kind=kind,
        target=target,
        data_dir=data_dir,
        disposition=RecoveryDisposition.BLOCKED,
        reason_code=code,
        summary=f"{kind.value} recovery is blocked by custody policy",
    )


def _normalize_disk_path(value: str | os.PathLike[str]) -> str:
    try:
        raw = os.fspath(value)
    except TypeError:
        return ""
    if not isinstance(raw, str) or not raw or "\x00" in raw:
        return ""
    if raw == ":memory:" or raw.startswith("file:"):
        return ""
    expanded = os.path.expanduser(raw)
    if not os.path.isabs(expanded):
        return ""
    return os.path.normpath(os.path.abspath(expanded))


def _platform_name() -> str:
    return "windows" if os.name == "nt" else "posix"


def _custody_snapshot(data_dir: str, parent: str) -> CustodySnapshot:
    if _platform_name() == "windows":
        return CustodySnapshot(
            platform="windows",
            windows_directories=_windows_directory_custody(data_dir, parent),
        )
    return CustodySnapshot(
        platform="posix",
        directories=_directory_identity_chain(data_dir, parent),
    )


def _directory_identity_chain(data_dir: str, parent: str) -> tuple[DirectoryIdentity, ...]:
    if os.path.realpath(data_dir) != data_dir:
        raise RecoveryRefusedError("data-dir-path-is-indirect")
    paths = _controlled_directory_paths(data_dir, parent)

    from defenseclaw.file_permissions import (
        darwin_acl_confidentiality_error,
        darwin_acl_write_error,
    )

    identities: list[DirectoryIdentity] = []
    running_uid = os.geteuid()
    for path in paths:
        try:
            info = os.lstat(path)
        except FileNotFoundError as exc:
            raise RecoveryRefusedError("target-parent-missing") from exc
        except OSError as exc:
            raise RecoveryRefusedError("directory-custody-unavailable") from exc
        if not stat.S_ISDIR(info.st_mode):
            raise RecoveryRefusedError("directory-chain-is-not-regular")
        if info.st_uid != running_uid:
            raise RecoveryRefusedError("directory-owner-mismatch")
        mode = stat.S_IMODE(info.st_mode)
        if mode & 0o022:
            raise RecoveryRefusedError("directory-chain-is-writable-by-others")
        if darwin_acl_write_error(path) is not None:
            raise RecoveryRefusedError("directory-chain-has-untrusted-writer")
        if darwin_acl_confidentiality_error(path) is not None:
            raise RecoveryRefusedError("directory-chain-has-untrusted-reader")
        if os.path.realpath(path) != path:
            raise RecoveryRefusedError("directory-chain-is-indirect")
        identities.append(
            DirectoryIdentity(
                path=path,
                device=int(info.st_dev),
                inode=int(info.st_ino),
                mode=mode,
                owner=int(info.st_uid),
            )
        )
    return tuple(identities)


def _controlled_directory_paths(data_dir: str, parent: str) -> tuple[str, ...]:
    try:
        relative = os.path.relpath(parent, data_dir)
    except ValueError as exc:
        raise RecoveryRefusedError("target-parent-outside-data-dir") from exc
    if relative == os.pardir or relative.startswith(os.pardir + os.sep):
        raise RecoveryRefusedError("target-parent-outside-data-dir")

    paths = [data_dir]
    if relative != os.curdir:
        current = data_dir
        for part in relative.split(os.sep):
            current = os.path.join(current, part)
            paths.append(current)
    return tuple(paths)


def _windows_directory_custody(
    data_dir: str,
    parent: str,
) -> tuple[WindowsDirectoryIdentity, ...]:
    """Capture exact private Windows directory descriptors under name leases."""

    from defenseclaw.file_permissions import (
        reject_reparse_path,
        windows_acl_custody_write_error,
    )
    from defenseclaw.windows_acl import (
        WindowsAclError,
        assert_not_broadly_writable,
        assert_trusted_owner,
        capture_path,
        hold_directory_chain,
    )

    paths = _controlled_directory_paths(data_dir, parent)
    identities: list[WindowsDirectoryIdentity] = []
    try:
        with hold_directory_chain(parent):
            for path in paths:
                reject_reparse_path(path)
                info = os.lstat(path)
                attributes = int(getattr(info, "st_file_attributes", 0))
                if (
                    stat.S_ISLNK(info.st_mode)
                    or attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
                    or not stat.S_ISDIR(info.st_mode)
                ):
                    raise RecoveryRefusedError("directory-chain-is-not-regular")
                if windows_acl_custody_write_error(
                    path,
                    allow_current_user=True,
                    require_current_user_owner=True,
                ):
                    raise RecoveryRefusedError("directory-chain-has-untrusted-writer")
                security = capture_path(path, directory=True)
                assert_trusted_owner(security)
                assert_not_broadly_writable(security)
                identities.append(
                    WindowsDirectoryIdentity(
                        path=path,
                        device=int(info.st_dev),
                        inode=int(info.st_ino),
                        security=security,
                    )
                )
    except RecoveryRefusedError:
        raise
    except (OSError, WindowsAclError) as exc:
        raise RecoveryRefusedError("directory-custody-unavailable") from exc
    return tuple(identities)


def _authorize_plan(
    plan: RecoveryPlan,
    expected_kind: RecoveryKind,
    *,
    approved: bool,
    unattended: bool,
) -> None:
    if plan.kind is not expected_kind:
        raise RecoveryRefusedError("recovery-kind-mismatch")
    if plan.disposition is not RecoveryDisposition.READY or plan.custody is None:
        raise RecoveryRefusedError("recovery-plan-not-ready")
    if not approved:
        raise RecoveryRefusedError("recovery-approval-required")
    if unattended and not plan.unattended_allowed:
        raise RecoveryRefusedError("unattended-recovery-refused")


def _revalidate_plan(plan: RecoveryPlan) -> None:
    if plan.kind is RecoveryKind.AUDIT_DB:
        fresh = plan_missing_audit_db(
            plan.target,
            data_dir=plan.data_dir,
            continuity_paths=plan.continuity_paths,
        )
    else:
        fresh = plan_missing_device_key(
            plan.target,
            data_dir=plan.data_dir,
            continuity_paths=plan.continuity_paths,
        )
    if (
        fresh.disposition is not RecoveryDisposition.READY
        or fresh.target != plan.target
        or fresh.data_dir != plan.data_dir
        or fresh.custody != plan.custody
    ):
        raise RecoveryRefusedError("recovery-plan-stale")


def _revalidate_directory_custody(plan: RecoveryPlan) -> None:
    if plan.custody is None:
        raise RecoveryRefusedError("recovery-plan-stale")
    try:
        current = _custody_snapshot(plan.data_dir, os.path.dirname(plan.target))
    except RecoveryRefusedError as exc:
        raise RecoveryRefusedError("recovery-plan-stale") from exc
    if current != plan.custody:
        raise RecoveryRefusedError("recovery-plan-stale")


def _stage_private_bytes(parent: str, prefix: str, data: bytes) -> str:
    fd, path = tempfile.mkstemp(prefix=prefix, suffix=".tmp", dir=parent)
    try:
        from defenseclaw.file_permissions import set_file_mode

        set_file_mode(fd, path, 0o600, set_owner=True)
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("short staging write")
            view = view[written:]
        os.fsync(fd)
    except Exception:
        os.close(fd)
        _remove_staging_files(path)
        raise
    os.close(fd)
    return path


def _publish_no_replace(source: str, target: str) -> None:
    """Atomically publish one staged regular file without replacing a name."""

    try:
        os.link(source, target, follow_symlinks=False)
    except FileExistsError as exc:
        raise RecoveryRefusedError("recovery-target-changed") from exc


def _windows_planned_directory(
    custody: CustodySnapshot,
    path: str,
) -> WindowsDirectoryIdentity:
    normalized = os.path.normcase(os.path.abspath(path))
    for identity in custody.windows_directories:
        if os.path.normcase(os.path.abspath(identity.path)) == normalized:
            return identity
    raise RecoveryRefusedError("windows-directory-custody-missing")


def _windows_write_new_private_file(
    path: str,
    payload: bytes,
    custody: CustodySnapshot,
    *,
    confidential: bool,
) -> None:
    """Native CREATE_NEW publication under an exact Windows directory lease."""

    from defenseclaw.file_permissions import windows_acl_custody_write_error
    from defenseclaw.windows_acl import (
        WindowsAclError,
        assert_not_broadly_readable,
        assert_not_broadly_writable,
        assert_trusted_owner,
        capture_path,
        hold_directory_chain,
        private_security_for_directory,
        write_new_file,
    )

    parent = os.path.dirname(os.path.abspath(path))
    expected = _windows_planned_directory(custody, parent)
    created = False
    try:
        with hold_directory_chain(parent):
            from defenseclaw.file_permissions import reject_reparse_path

            reject_reparse_path(parent)
            parent_info = os.lstat(parent)
            if (
                not stat.S_ISDIR(parent_info.st_mode)
                or int(parent_info.st_dev) != expected.device
                or int(parent_info.st_ino) != expected.inode
            ):
                raise RecoveryRefusedError("recovery-plan-stale")
            current = capture_path(parent, directory=True)
            if current != expected.security:
                raise RecoveryRefusedError("recovery-plan-stale")
            if windows_acl_custody_write_error(
                parent,
                allow_current_user=True,
                require_current_user_owner=True,
            ):
                raise RecoveryRefusedError("windows-directory-custody-changed")
            assert_trusted_owner(current)
            assert_not_broadly_writable(current)

            requested = private_security_for_directory(parent)
            try:
                written = write_new_file(path, payload, requested)
            except WindowsAclError as exc:
                error = getattr(exc, "winerror", None) or getattr(exc, "errno", None)
                if error in {80, 183}:  # ERROR_FILE_EXISTS / ERROR_ALREADY_EXISTS
                    raise RecoveryRefusedError("recovery-target-changed") from exc
                # CREATE_NEW may already have published an empty or partial
                # candidate before a later security/write/flush check failed.
                # Conservatively report the name as created; a pathname probe
                # after the native handle closes could inspect a racer's
                # replacement and must not be used as identity evidence.
                created = True
                raise RecoveryPublicationError(
                    "windows-create-new-failed",
                    created=created,
                ) from exc
            created = True
            actual = capture_path(path)
            if actual != written:
                raise RecoveryPublicationError(
                    "windows-postpublication-security-changed",
                    created=True,
                )
            assert_trusted_owner(actual)
            assert_not_broadly_writable(actual)
            if confidential:
                assert_not_broadly_readable(actual)
    except (RecoveryPublicationError, RecoveryRefusedError):
        raise
    except WindowsAclError as exc:
        raise RecoveryPublicationError(
            "windows-publication-postcondition-failed",
            created=created,
        ) from exc


def _private_file_postconditions(
    path: str,
    *,
    platform: str,
    confidential: bool,
) -> bool:
    if platform == "windows":
        return _windows_private_file_postconditions(path, confidential=confidential)

    try:
        info = os.lstat(path)
    except OSError:
        return False
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or stat.S_IMODE(info.st_mode) & 0o077
        or info.st_uid != os.geteuid()
    ):
        return False
    try:
        from defenseclaw.file_permissions import (
            darwin_acl_confidentiality_error,
            darwin_acl_write_error,
        )

        if darwin_acl_write_error(path) is not None:
            return False
        if confidential and darwin_acl_confidentiality_error(path) is not None:
            return False
    except OSError:
        return False
    return True


def _windows_private_file_postconditions(path: str, *, confidential: bool) -> bool:
    try:
        from defenseclaw.file_permissions import reject_reparse_path
        from defenseclaw.windows_acl import (
            assert_not_broadly_readable,
            assert_not_broadly_writable,
            assert_trusted_owner,
            capture_path,
        )

        reject_reparse_path(path)
        info = os.lstat(path)
        if (
            not stat.S_ISREG(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or int(getattr(info, "st_file_attributes", 0)) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        ):
            return False
        security = capture_path(path)
        assert_trusted_owner(security)
        assert_not_broadly_writable(security)
        if confidential:
            assert_not_broadly_readable(security)
        return True
    except OSError:
        return False


def _read_private_regular_file(
    path: str,
    *,
    max_bytes: int,
    platform: str,
) -> bytes:
    if not _private_file_postconditions(path, platform=platform, confidential=True):
        raise OSError("private staging file postcondition failed")
    from defenseclaw.file_permissions import read_regular_file_no_follow

    return read_regular_file_no_follow(path, max_bytes=max_bytes)


def _audit_db_is_valid(path: str) -> bool:
    try:
        uri = Path(path).resolve().as_uri() + "?mode=ro"
        connection = sqlite3.connect(uri, uri=True, timeout=0.1)
        try:
            connection.execute("PRAGMA query_only=ON")
            quick_check = connection.execute("PRAGMA quick_check").fetchone()
            tables = {
                str(row[0])
                for row in connection.execute(
                    "SELECT name FROM sqlite_master "
                    "WHERE type='table' AND name IN ('audit_events', 'scan_results', 'findings')"
                )
            }
            return quick_check == ("ok",) and tables == _AUDIT_REQUIRED_TABLES
        finally:
            connection.close()
    except (OSError, sqlite3.Error, ValueError):
        return False


def _new_device_key_pem() -> bytes:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private_key = Ed25519PrivateKey.generate()
    seed = private_key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    encoded = base64.b64encode(seed)
    return b"-----BEGIN ED25519 PRIVATE KEY-----\n" + encoded + b"\n-----END ED25519 PRIVATE KEY-----\n"


def _device_key_postconditions(
    key_path: str,
    secret_path: str,
    provenance_path: str,
    *,
    platform: str,
) -> bool:
    try:
        for path in (key_path, secret_path, provenance_path):
            if not _private_file_postconditions(
                path,
                platform=platform,
                confidential=True,
            ):
                return False
        key_data = _read_private_regular_file(key_path, max_bytes=4096, platform=platform)
        secret = _read_private_regular_file(secret_path, max_bytes=64, platform=platform)
        provenance = _read_private_regular_file(
            provenance_path,
            max_bytes=256,
            platform=platform,
        ).strip()
    except OSError:
        return False
    if len(secret) != 32 or not provenance.startswith(_DEVICE_PROVENANCE_PREFIX):
        return False
    claimed = provenance[len(_DEVICE_PROVENANCE_PREFIX) :]
    expected = hmac.new(secret, key_data, hashlib.sha256).hexdigest().encode("ascii")
    if not hmac.compare_digest(claimed, expected):
        return False
    return _valid_device_key_bytes(key_data)


def _valid_device_key_bytes(key_data: bytes) -> bool:
    lines = key_data.strip().splitlines()
    if len(lines) != 3 or lines[0] != b"-----BEGIN ED25519 PRIVATE KEY-----":
        return False
    if lines[2] != b"-----END ED25519 PRIVATE KEY-----":
        return False
    try:
        seed = base64.b64decode(lines[1], validate=True)
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        Ed25519PrivateKey.from_private_bytes(seed)
    except (TypeError, ValueError):
        return False
    return True


def _fsync_directory(path: str) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _remove_staging_files(path: str) -> None:
    if not path:
        return
    for candidate in (path, path + "-wal", path + "-shm", path + "-journal"):
        try:
            os.unlink(candidate)
        except FileNotFoundError:
            pass
        except OSError:
            # Cleanup is best effort.  The randomized, non-authoritative
            # staging name is never consumed by a later recovery plan.
            pass
