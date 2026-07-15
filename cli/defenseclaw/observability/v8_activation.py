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

"""Transactional activation for a prepared observability-v8 migration.

The converter in :mod:`defenseclaw.observability.v8_migration` is deliberately
pure.  This module is the narrow filesystem boundary that can activate its
result during ``defenseclaw upgrade``.  It is not another migration engine: it
does not select versions, mutate the migration cursor, restart services, or
construct v8 policy.

The transaction holds the ordinary config lock, validates the exact source
digest, snapshots config and ``.env``, invokes the caller's target-Go validator,
creates one private recovery backup, then atomically publishes ``.env`` before
``config.yaml``.  Any failure after publication starts restores both original
files, including the absence of a pre-upgrade ``.env``.

The sibling locks serialize participating Python writers.  On Linux and macOS,
existing-file publication also exchanges the staged and live names atomically,
then verifies the displaced inode before committing.  A stale uncooperative
writer in the final check-to-publish window is therefore restored rather than
silently overwritten.

Secret values exist only in the converter's repr-protected ``EnvironmentEdit``
objects, short-lived byte buffers, the private environment backup, and the
protected mapping passed to the validator.  They are never included in result
representations, manifests, or error text.
"""

from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import uuid
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Final

import yaml

from defenseclaw import windows_acl
from defenseclaw.file_lock import locked_file_update
from defenseclaw.observability.v8_migration import (
    EnvironmentDependency,
    EnvironmentEdit,
    EnvironmentReference,
    V8MigrationResult,
)

_CONFIG_ENV: Final = "DEFENSECLAW_CONFIG"
_HOME_ENV: Final = "DEFENSECLAW_HOME"
_DEFAULT_HOME: Final = ".defenseclaw"
_CONFIG_NAME: Final = "config.yaml"
_ENV_NAME: Final = ".env"
_DEPLOYMENT_MODE_ENV: Final = "DEFENSECLAW_DEPLOYMENT_MODE"
_BACKUP_SCHEMA: Final = 1
_MAX_SNAPSHOT_BYTES: Final = 64 * 1024 * 1024
_MIN_SECRET_LEAK_SCAN_BYTES: Final = 8
_ENV_NAME_RE: Final = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_ENV_LINE_RE: Final = re.compile(
    rb"^[ \t]*(?P<export>export[ \t]+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
    rb"[ \t]*=[ \t]*(?P<value>.*?)[ \t]*$"
)

CandidateValidator = Callable[[bytes, Mapping[str, str]], None]
FaultInjector = Callable[[str], None]
PrivateFileTransform = Callable[[bytes], bytes | None]


class V8ActivationError(RuntimeError):
    """A value-safe activation failure.

    The originating exception is intentionally not chained or rendered.  A
    validator, filesystem adapter, or test fault may carry a secret in its
    exception message; the upgrade boundary must never repeat that payload.
    """

    def __init__(
        self,
        code: str,
        stage: str,
        *,
        target_path: str | None = None,
        backup_directory: str | None = None,
        recovery_paths: tuple[str, ...] = (),
    ) -> None:
        self.code = code
        self.stage = stage
        self.target_path = target_path
        self.backup_directory = backup_directory
        self.recovery_paths = tuple(
            dict.fromkeys(path for path in ((backup_directory,) if backup_directory else ()) + recovery_paths if path)
        )
        message = f"observability v8 activation failed ({code}) at {stage}"
        if target_path:
            message += f"; target={target_path}"
        if backup_directory:
            message += f"; recovery backup={backup_directory}"
        additional_recovery = tuple(path for path in self.recovery_paths if path != backup_directory)
        if additional_recovery:
            message += f"; recovery paths={','.join(additional_recovery)}"
        super().__init__(message)


class V8ActivationRollbackError(V8ActivationError):
    """Activation failed and at least one original could not be restored."""


@dataclass(frozen=True)
class V8ActivationResult:
    """Secret-free result returned to the upgrade orchestrator."""

    activated: bool
    already_v8: bool
    config_path: str
    environment_path: str
    backup_directory: str | None
    source_sha256: str
    candidate_sha256: str
    environment_before_sha256: str | None
    environment_after_sha256: str | None


@dataclass(frozen=True)
class _FileSnapshot:
    path: str
    existed: bool
    payload: bytes = field(repr=False)
    sha256: str | None
    mode: int | None
    uid: int | None
    gid: int | None
    device: int | None
    inode: int | None
    parent_device: int | None
    parent_inode: int | None
    xattrs: tuple[tuple[str, bytes], ...] = field(default=(), repr=False)
    windows_security: windows_acl.WindowsFileSecurity | None = field(default=None, repr=False)
    flags: int | None = None
    darwin_acl: bytes | None = field(default=None, repr=False)


@dataclass(frozen=True)
class _ExpectedFileState:
    existed: bool
    sha256: str | None
    mode: int | None
    uid: int | None
    gid: int | None
    xattrs: tuple[tuple[str, bytes], ...] = field(default=(), repr=False)
    allow_platform_xattrs: bool = False
    windows_security: windows_acl.WindowsFileSecurity | None = field(default=None, repr=False)
    flags: int | None = None
    darwin_acl: bytes | None = field(default=None, repr=False)


class _ProtectedEnvironment(Mapping[str, str]):
    """Read-only validator environment whose repr never contains values."""

    def __init__(self, values: Mapping[str, str]) -> None:
        self._values = dict(values)

    def __getitem__(self, key: str) -> str:
        return self._values[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._values)

    def __len__(self) -> int:
        return len(self._values)

    def __repr__(self) -> str:
        return f"<protected environment: {len(self._values)} entries>"


def resolve_active_config_path(
    *,
    data_dir: str | os.PathLike[str] | None = None,
    environment: Mapping[str, str] | None = None,
) -> str:
    """Resolve the same active source selected by the CLI.

    ``DEFENSECLAW_CONFIG`` wins over ``data_dir``.  When neither is supplied,
    ``DEFENSECLAW_HOME`` and then ``~/.defenseclaw`` provide the data root.
    ``abspath`` is intentional: resolving symlinks here would hide a forbidden
    final-component symlink before the secure open checks can reject it.
    """

    env = os.environ if environment is None else environment
    override = str(env.get(_CONFIG_ENV, "") or "").strip()
    if override:
        return _absolute_path(override)
    root = _resolve_data_dir(data_dir=data_dir, environment=env)
    return os.path.join(root, _CONFIG_NAME)


def activate_v8_migration(
    migration: V8MigrationResult,
    *,
    validator: CandidateValidator,
    data_dir: str | os.PathLike[str] | None = None,
    config_path: str | os.PathLike[str] | None = None,
    environment_path: str | os.PathLike[str] | None = None,
    backup_root: str | os.PathLike[str] | None = None,
    tighten_legacy_backup_root: bool = False,
    environment: Mapping[str, str] | None = None,
    fault_injector: FaultInjector | None = None,
) -> V8ActivationResult:
    """Validate, back up, and atomically activate one prepared migration.

    The validator must compile ``candidate`` using the target gateway's
    canonical v8 compiler.  Its second argument contains only protected values
    that must override the child process environment for that validation.  A
    validator exception is converted to a value-safe :class:`V8ActivationError`.

    ``fault_injector`` exists for deterministic boundary testing.  Production
    callers omit it.
    """

    if not callable(validator):
        raise TypeError("validator must be callable")
    env = os.environ if environment is None else environment
    if migration.effective_data_dir is None:
        if migration.changed:
            raise V8ActivationError("effective_data_dir_invalid", "resolve_paths")
        resolved_data_dir = _resolve_data_dir(data_dir=data_dir, environment=env)
    elif not os.path.isabs(migration.effective_data_dir):
        raise V8ActivationError("effective_data_dir_invalid", "resolve_paths")
    else:
        resolved_data_dir = _absolute_path(migration.effective_data_dir)
    if (
        migration.effective_data_dir is not None
        and data_dir is not None
        and not _same_path(_absolute_path(os.fspath(data_dir)), resolved_data_dir)
    ):
        raise V8ActivationError(
            "effective_data_dir_mismatch",
            "resolve_paths",
            target_path=resolved_data_dir,
        )
    active_config = _absolute_path(
        os.fspath(config_path)
        if config_path is not None
        else resolve_active_config_path(data_dir=data_dir, environment=environment)
    )
    expected_environment = _absolute_path(os.path.join(resolved_data_dir, _ENV_NAME))
    active_environment = (
        _absolute_path(os.fspath(environment_path)) if environment_path is not None else expected_environment
    )
    if environment_path is not None and not _same_path(active_environment, expected_environment):
        raise V8ActivationError(
            "environment_path_mismatch",
            "resolve_paths",
            target_path=active_environment,
        )
    if os.path.normcase(active_config) == os.path.normcase(active_environment):
        raise V8ActivationError(
            "path_alias",
            "resolve_paths",
            target_path=active_config,
        )
    backups = _absolute_path(
        os.fspath(backup_root) if backup_root is not None else os.path.join(resolved_data_dir, "backups")
    )
    if migration.changed and (_same_path(backups, active_config) or _same_path(backups, active_environment)):
        raise V8ActivationError(
            "path_alias",
            "resolve_paths",
            target_path=backups,
        )

    trusted_owners = _trusted_owner_pairs(env)
    trusted_uids = _trusted_owner_ids(active_config, resolved_data_dir, env)
    _assert_secure_parent_chain(active_config, trusted_uids)
    _assert_secure_parent_chain(active_environment, trusted_uids)
    if migration.changed:
        _assert_secure_parent_chain(backups, trusted_uids, target_may_be_directory=True)
        if tighten_legacy_backup_root and os.path.lexists(backups):
            try:
                _tighten_existing_backup_root(backups, trusted_owners)
            except OSError:
                raise V8ActivationError(
                    "backup_failed",
                    "prepare_backup_root",
                    target_path=backups,
                ) from None
    _assert_no_inheritable_read_acl(os.path.dirname(active_environment) or ".")
    if migration.changed:
        backup_acl_parent = backups if os.path.isdir(backups) else os.path.dirname(backups) or "."
        _assert_no_inheritable_read_acl(backup_acl_parent)

    with locked_file_update(active_config), locked_file_update(active_environment):
        config_snapshot = _snapshot_regular_file(active_config, required=True)
        _assert_leaf_owner(config_snapshot, trusted_owners)
        _validate_migration_result(migration, config_snapshot)
        _assert_all_environment_dependencies(env, migration.environment_dependencies)
        _assert_all_ambient_environments_compatible(env, migration.environment_edits)
        environment_snapshot = _snapshot_regular_file(active_environment, required=False)
        _assert_leaf_owner(environment_snapshot, trusted_owners)
        environment_write_metadata = (
            environment_snapshot
            if environment_snapshot.existed
            else _new_environment_metadata(environment_snapshot, resolved_data_dir, env)
        )
        environment_candidate = _build_environment_candidate(
            environment_snapshot.payload,
            migration.environment_edits,
        )
        if _is_windows() and migration.environment_edits and environment_snapshot.existed:
            try:
                if environment_snapshot.windows_security is None:
                    raise windows_acl.WindowsAclError("environment DACL is unavailable")
                windows_acl.assert_not_broadly_readable(environment_snapshot.windows_security)
            except windows_acl.WindowsAclError:
                raise V8ActivationError(
                    "environment_permissions_unsafe",
                    "validate_environment_permissions",
                    target_path=active_environment,
                ) from None
        if (
            not _is_windows()
            and migration.environment_edits
            and environment_snapshot.mode is not None
            and environment_snapshot.mode & 0o077
        ):
            raise V8ActivationError(
                "environment_permissions_unsafe",
                "validate_environment_permissions",
                target_path=active_environment,
            )
        environment_will_exist = environment_snapshot.existed or bool(environment_candidate)
        environment_candidate_sha256 = _sha256(environment_candidate) if environment_will_exist else None
        validator_environment = _ProtectedEnvironment({edit.name: edit.value for edit in migration.environment_edits})

        _inject_fault(fault_injector, "before_validator")
        try:
            validator(migration.candidate, validator_environment)
        except Exception:
            raise V8ActivationError(
                "candidate_validation_failed",
                "target_go_validation",
                target_path=active_config,
            ) from None
        _inject_fault(fault_injector, "after_validator")

        if migration.changed:
            try:
                _assert_config_write_allowed(active_config, env)
            except Exception:
                raise V8ActivationError(
                    "config_write_forbidden",
                    "managed_write_policy",
                    target_path=active_config,
                ) from None

        # The validator is caller-provided and may take long enough for an
        # uncooperative writer to change the source despite our advisory lock.
        _assert_snapshot_current(config_snapshot, "post_validation_cas")
        _assert_snapshot_current(environment_snapshot, "post_validation_environment_cas")
        _assert_all_environment_dependencies(env, migration.environment_dependencies)

        if not migration.changed:
            return V8ActivationResult(
                activated=False,
                already_v8=migration.already_v8,
                config_path=active_config,
                environment_path=active_environment,
                backup_directory=None,
                source_sha256=migration.source_sha256,
                candidate_sha256=migration.candidate_sha256,
                environment_before_sha256=environment_snapshot.sha256,
                environment_after_sha256=environment_snapshot.sha256,
            )

        # Prove both same-directory temp/metadata/rename prerequisites before
        # publishing either live file.  A read-only config parent must not be
        # discovered only after a newly-created secret environment has landed.
        try:
            _preflight_atomic_replace(config_snapshot, default_mode=0o600)
            if environment_candidate != environment_snapshot.payload:
                _preflight_atomic_replace(
                    environment_snapshot,
                    default_mode=0o600,
                    metadata=environment_write_metadata,
                )
        except Exception:
            raise V8ActivationError(
                "permission_preflight_failed",
                "atomic_replace_preflight",
                target_path=active_config,
            ) from None

        _assert_snapshot_current(config_snapshot, "post_preflight_config_cas")
        _assert_snapshot_current(environment_snapshot, "post_preflight_environment_cas")
        _inject_fault(fault_injector, "after_preflight")

        backup_directory: str | None = None
        try:
            backup_directory = _create_recovery_backup(
                backups,
                config_snapshot,
                environment_snapshot,
                migration,
                environment_candidate_sha256,
            )
        except Exception:
            raise V8ActivationError(
                "backup_failed",
                "create_recovery_backup",
                target_path=backups,
                backup_directory=backup_directory,
            ) from None
        _inject_fault(fault_injector, "after_backup", backup_directory=backup_directory)

        mutation_started = False
        stage = "before_environment_write"
        activated_config_state = _activated_file_state(
            config_snapshot,
            existed=True,
            sha256=migration.candidate_sha256,
            default_mode=0o600,
        )
        activated_environment_state = _activated_file_state(
            environment_snapshot,
            existed=environment_will_exist,
            sha256=environment_candidate_sha256,
            default_mode=0o600,
            metadata=environment_write_metadata,
        )
        try:
            _assert_snapshot_current(config_snapshot, "pre_activation_config_cas")
            _assert_snapshot_current(environment_snapshot, "pre_activation_environment_cas")
            _assert_all_environment_dependencies(env, migration.environment_dependencies)
            _assert_all_ambient_environments_compatible(env, migration.environment_edits)
            _inject_fault(fault_injector, "before_environment_write")

            if environment_candidate != environment_snapshot.payload:
                mutation_started = True
                stage = "environment_write"
                _atomic_replace(
                    environment_snapshot,
                    environment_candidate,
                    default_mode=0o600,
                    metadata=environment_write_metadata,
                )
            _inject_fault(fault_injector, "after_environment_write")
            _assert_all_environment_dependencies(env, migration.environment_dependencies)

            # Config is the commit marker.  Recheck it after the ancillary
            # write so a concurrent edit causes .env rollback, not overwrite.
            stage = "pre_config_cas"
            _assert_snapshot_current(config_snapshot, "pre_config_write_cas")
            _inject_fault(fault_injector, "before_config_write")
            mutation_started = True
            stage = "config_write"
            _atomic_replace(config_snapshot, migration.candidate, default_mode=0o600)
            _inject_fault(fault_injector, "after_config_write")

            stage = "activation_verification"
            _assert_expected_file_state(active_config, activated_config_state)
            _assert_expected_file_state(active_environment, activated_environment_state)
            _assert_all_environment_dependencies(env, migration.environment_dependencies)
            _assert_all_ambient_environments_compatible(env, migration.environment_edits)
            _inject_fault(fault_injector, "after_activation")
        except BaseException as exc:
            if isinstance(exc, V8ActivationRollbackError):
                # The atomic publisher retained recovery evidence because it
                # could not prove that another rollback would preserve a
                # concurrent writer. Do not run the generic reconstruction
                # path over that authoritative state.
                raise
            if mutation_started:
                rollback_errors = _rollback(
                    config_snapshot,
                    environment_snapshot,
                    activated_config=activated_config_state,
                    activated_environment=activated_environment_state,
                )
                if rollback_errors:
                    raise V8ActivationRollbackError(
                        "rollback_incomplete",
                        stage,
                        target_path=active_config,
                        backup_directory=backup_directory,
                    ) from None
            if not isinstance(exc, Exception):
                raise
            if isinstance(exc, V8ActivationError):
                raise V8ActivationError(
                    exc.code,
                    exc.stage,
                    target_path=exc.target_path or active_config,
                    backup_directory=backup_directory,
                ) from None
            raise V8ActivationError(
                "activation_failed",
                stage,
                target_path=active_config,
                backup_directory=backup_directory,
            ) from None

        return V8ActivationResult(
            activated=True,
            already_v8=False,
            config_path=active_config,
            environment_path=active_environment,
            backup_directory=backup_directory,
            source_sha256=migration.source_sha256,
            candidate_sha256=migration.candidate_sha256,
            environment_before_sha256=environment_snapshot.sha256,
            environment_after_sha256=environment_candidate_sha256,
        )


def _resolve_data_dir(
    *,
    data_dir: str | os.PathLike[str] | None,
    environment: Mapping[str, str],
) -> str:
    if data_dir is not None:
        return _absolute_path(os.fspath(data_dir))
    configured = str(environment.get(_HOME_ENV, "") or "").strip()
    if configured:
        return _absolute_path(configured)
    sudo_user = str(environment.get("SUDO_USER", "") or "").strip()
    getuid = getattr(os, "getuid", None)
    if sudo_user and getuid is not None and getuid() == 0:
        try:
            import pwd

            candidate = Path(pwd.getpwnam(sudo_user).pw_dir) / _DEFAULT_HOME
            if (candidate / _CONFIG_NAME).is_file():
                return _absolute_path(os.fspath(candidate))
        except (ImportError, KeyError):
            pass
    return _absolute_path(os.path.join(str(Path.home()), _DEFAULT_HOME))


def _absolute_path(value: str) -> str:
    return os.path.abspath(os.path.expanduser(value))


def _is_admin_process() -> bool:
    if hasattr(os, "geteuid"):
        return os.geteuid() == 0
    if os.name == "nt":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return False


def _managed_enterprise_source(path: str) -> bool:
    """Read only the deployment-mode discriminator needed for write policy."""

    try:
        source = yaml.safe_load(Path(path).read_bytes()) or {}
    except (OSError, yaml.YAMLError):
        return False
    if not isinstance(source, dict):
        return False
    mode = str(source.get("deployment_mode", "") or "").strip()
    return mode in {"managed", "managed_enterprise"}


def _assert_config_write_allowed(path: str, environment: Mapping[str, str]) -> None:
    """Enforce managed-config ownership without importing cached CLI config.

    The migration can execute inside a pre-v8 upgrader after its wheel has been
    replaced. That process may retain an older ``defenseclaw.config`` module,
    so this low-level activation boundary must own its small write-policy check
    instead of importing target-only private helpers from the cached module.
    """

    modes = {str(environment.get(_DEPLOYMENT_MODE_ENV, "") or "").strip()}
    if environment is not os.environ:
        modes.add(str(os.environ.get(_DEPLOYMENT_MODE_ENV, "") or "").strip())
    managed = bool(modes.intersection({"managed", "managed_enterprise"})) or _managed_enterprise_source(path)
    if managed and not _is_admin_process():
        raise PermissionError(
            "managed_enterprise config changes require operating-system "
            "administrator privileges; use the enterprise managed config path "
            "or rerun this command with admin elevation"
        )


def _macos_write_acl_problem(path: str) -> str | None:
    """Return a fail-closed diagnostic for write-capable macOS ACL entries."""

    if sys.platform != "darwin":
        return None
    try:
        completed = subprocess.run(
            ["/bin/ls", "-lde", "--", path],
            check=False,
            capture_output=True,
            text=True,
            env={"LANG": "C", "LC_ALL": "C"},
        )
    except OSError:
        return "macOS ACL is unreadable"
    if completed.returncode != 0:
        return "macOS ACL is unreadable"
    write_permissions = {
        "write",
        "add_file",
        "append",
        "add_subdirectory",
        "delete",
        "delete_child",
        "writeattr",
        "writeextattr",
        "writesecurity",
        "chown",
    }
    for line in completed.stdout.splitlines():
        normalized = line.strip().lower()
        prefix, separator, _rest = normalized.partition(":")
        if not separator or not prefix.isdigit() or " allow " not in normalized:
            continue
        permissions = normalized.split(" allow ", 1)[1].split(None, 1)
        if not permissions:
            return "macOS ACL is unparseable"
        if write_permissions.intersection(permissions[0].split(",")):
            return "write-capable macOS ACL entry is not trusted"
    return None


def _same_path(left: str, right: str) -> bool:
    return os.path.normcase(os.path.normpath(left)) == os.path.normcase(os.path.normpath(right))


def _is_windows() -> bool:
    return os.name == "nt"


def _trusted_owner_ids(
    config_path: str,
    data_dir: str,
    environment: Mapping[str, str],
) -> frozenset[int]:
    trusted = {uid for uid, _gid in _trusted_owner_pairs(environment)}
    for path in (config_path, data_dir):
        try:
            info = os.lstat(path)
        except OSError:
            continue
        if stat.S_ISLNK(info.st_mode):
            raise V8ActivationError("symlink_forbidden", "validate_parent_chain", target_path=path)
    invoking = _validated_invoking_owner(environment)
    if invoking is not None:
        trusted.add(invoking[0])
    return frozenset(trusted)


def _trusted_owner_pairs(environment: Mapping[str, str]) -> frozenset[tuple[int, int]]:
    geteuid = getattr(os, "geteuid", None)
    getegid = getattr(os, "getegid", None)
    getuid = getattr(os, "getuid", None)
    getgid = getattr(os, "getgid", None)
    current = (
        geteuid() if geteuid is not None else (getuid() if getuid is not None else 0),
        getegid() if getegid is not None else (getgid() if getgid is not None else 0),
    )
    trusted = {(0, 0), current}
    invoking = _validated_invoking_owner(environment)
    if invoking is not None:
        trusted.add(invoking)
    return frozenset(trusted)


def _trusted_private_owner(
    uid: int | None,
    gid: int | None,
    mode: int,
    trusted: frozenset[tuple[int, int]],
) -> bool:
    """Accept a trusted UID with an inherited group only for private objects.

    macOS inherits a new path's group from its parent directory. A caller-owned
    custom data directory under ``/private/tmp`` can therefore be ``uid:wheel``
    even when the process's primary group is ``staff``. The owner UID still has
    exclusive authority when all group/other mode bits are clear. Preserve the
    stricter exact-pair rule for every non-private object so a changed group can
    never gain read, traverse, or write access through this compatibility path.
    """

    if uid is None or gid is None:
        return False
    if (uid, gid) in trusted:
        return True
    trusted_uids = {owner_uid for owner_uid, _owner_gid in trusted}
    return uid in trusted_uids and stat.S_IMODE(mode) & 0o077 == 0


def _assert_leaf_owner(snapshot: _FileSnapshot, trusted: frozenset[tuple[int, int]]) -> None:
    if not snapshot.existed:
        return
    if snapshot.flags:
        raise V8ActivationError("file_flags_unsupported", "snapshot", target_path=snapshot.path)
    if snapshot.darwin_acl is not None:
        raise V8ActivationError("acl_preservation_unsupported", "snapshot", target_path=snapshot.path)
    if _is_windows():
        if snapshot.windows_security is None:
            raise V8ActivationError("acl_unreadable", "validate_leaf_owner", target_path=snapshot.path)
        try:
            windows_acl.assert_trusted_owner(snapshot.windows_security)
            windows_acl.assert_not_broadly_writable(snapshot.windows_security)
        except windows_acl.WindowsAclError:
            raise V8ActivationError("leaf_acl_unsafe", "validate_leaf_owner", target_path=snapshot.path) from None
        return
    if snapshot.mode is None or not _trusted_private_owner(
        snapshot.uid,
        snapshot.gid,
        snapshot.mode,
        trusted,
    ):
        raise V8ActivationError("leaf_owner_untrusted", "validate_leaf_owner", target_path=snapshot.path)
    if snapshot.mode & 0o022:
        raise V8ActivationError(
            "leaf_permissions_unsafe",
            "validate_leaf_owner",
            target_path=snapshot.path,
        )


def _validated_invoking_owner(environment: Mapping[str, str]) -> tuple[int, int] | None:
    sudo_uid = str(environment.get("SUDO_UID", "") or "").strip()
    sudo_gid = str(environment.get("SUDO_GID", "") or "").strip()
    sudo_user = str(environment.get("SUDO_USER", "") or "").strip()
    if not (sudo_uid.isdigit() and sudo_gid.isdigit() and sudo_user):
        return None
    try:
        import pwd

        account = pwd.getpwnam(sudo_user)
    except (ImportError, KeyError):
        return None
    if account.pw_uid != int(sudo_uid) or account.pw_gid != int(sudo_gid):
        return None
    return account.pw_uid, account.pw_gid


def _assert_secure_parent_chain(
    target: str,
    trusted_uids: frozenset[int],
    *,
    target_may_be_directory: bool = False,
) -> None:
    """Reject replaceable/writable parent components before opening transaction files."""

    current = target if target_may_be_directory and os.path.lexists(target) else os.path.dirname(target) or "."
    current = _absolute_path(current)
    direct_parent = current
    while True:
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            parent = os.path.dirname(current)
            if parent == current:
                raise V8ActivationError("parent_missing", "validate_parent_chain", target_path=target) from None
            current = parent
            continue
        except OSError:
            raise V8ActivationError("parent_unreadable", "validate_parent_chain", target_path=target) from None
        if stat.S_ISLNK(info.st_mode):
            raise V8ActivationError("parent_symlink_forbidden", "validate_parent_chain", target_path=target)
        if _is_windows() and getattr(info, "st_file_attributes", 0) & 0x00000400:
            raise V8ActivationError("parent_reparse_forbidden", "validate_parent_chain", target_path=target)
        if not stat.S_ISDIR(info.st_mode):
            raise V8ActivationError("parent_directory_required", "validate_parent_chain", target_path=target)
        if _is_windows():
            try:
                security = windows_acl.capture_path(current, directory=True)
                windows_acl.assert_trusted_owner(security)
                if _same_path(current, direct_parent):
                    windows_acl.assert_not_broadly_writable(security)
            except windows_acl.WindowsAclError:
                raise V8ActivationError(
                    "parent_acl_unsafe",
                    "validate_parent_chain",
                    target_path=target,
                ) from None
            parent = os.path.dirname(current)
            if parent == current:
                return
            current = parent
            continue
        uid = getattr(info, "st_uid", None)
        if uid is not None and uid not in trusted_uids:
            raise V8ActivationError("parent_owner_untrusted", "validate_parent_chain", target_path=target)
        mode = stat.S_IMODE(info.st_mode)
        if mode & 0o022 and not (uid == 0 and mode & stat.S_ISVTX):
            raise V8ActivationError("parent_permissions_unsafe", "validate_parent_chain", target_path=target)
        if _macos_write_acl_problem(current) is not None:
            raise V8ActivationError("parent_acl_unsafe", "validate_parent_chain", target_path=target)
        parent = os.path.dirname(current)
        if parent == current:
            return
        current = parent


def _assert_no_inheritable_read_acl(path: str) -> None:
    """Reject macOS directory ACLs that can expose newly-created secret files."""

    if _is_windows():
        # New secret files receive a protected explicit DACL before their
        # first byte is written. Existing .env files are checked directly
        # before migrated secret values are appended.
        return
    if sys.platform != "darwin":
        return
    try:
        completed = subprocess.run(
            ["/bin/ls", "-lde", "--", path],
            check=False,
            capture_output=True,
            text=True,
            env={"LANG": "C", "LC_ALL": "C"},
        )
    except OSError:
        raise V8ActivationError("acl_unreadable", "validate_secret_parent_acl", target_path=path) from None
    if completed.returncode != 0:
        raise V8ActivationError("acl_unreadable", "validate_secret_parent_acl", target_path=path)
    read_permissions = {"read", "list", "search", "readattr", "readextattr", "readsecurity"}
    inheritance = {"file_inherit", "directory_inherit", "limit_inherit", "only_inherit"}
    for line in completed.stdout.splitlines()[1:]:
        normalized = line.strip().lower()
        prefix, separator, _rest = normalized.partition(":")
        if not separator or not prefix.isdigit() or " allow " not in normalized:
            continue
        tokens = set(re.split(r"[\s,]+", normalized.split(" allow ", 1)[1]))
        if tokens.intersection(read_permissions) and tokens.intersection(inheritance):
            raise V8ActivationError("inheritable_read_acl_unsafe", "validate_secret_parent_acl", target_path=path)


def _new_environment_metadata(
    snapshot: _FileSnapshot,
    data_dir: str,
    environment: Mapping[str, str],
) -> _FileSnapshot:
    """Use the already-validated data-directory owner for a new secret file."""

    if _is_windows():
        try:
            security = windows_acl.private_security_for_directory(data_dir)
        except windows_acl.WindowsAclError:
            raise V8ActivationError(
                "environment_permissions_unsafe",
                "new_environment_owner",
                target_path=snapshot.path,
            ) from None
        return _FileSnapshot(
            path=snapshot.path,
            existed=False,
            payload=b"",
            sha256=None,
            mode=None,
            uid=None,
            gid=None,
            device=None,
            inode=None,
            parent_device=snapshot.parent_device,
            parent_inode=snapshot.parent_inode,
            xattrs=(),
            windows_security=security,
        )
    allowed = set(_trusted_owner_pairs(environment))
    data_info = os.lstat(data_dir)
    data_owner = (getattr(data_info, "st_uid", None), getattr(data_info, "st_gid", None))
    if not _trusted_private_owner(
        getattr(data_info, "st_uid", None),
        getattr(data_info, "st_gid", None),
        stat.S_IMODE(data_info.st_mode),
        frozenset(allowed),
    ):
        raise V8ActivationError("leaf_owner_untrusted", "new_environment_owner", target_path=snapshot.path)
    owner = (int(data_owner[0]), int(data_owner[1]))
    return _FileSnapshot(
        path=snapshot.path,
        existed=False,
        payload=b"",
        sha256=None,
        mode=0o600,
        uid=owner[0],
        gid=owner[1],
        device=None,
        inode=None,
        parent_device=snapshot.parent_device,
        parent_inode=snapshot.parent_inode,
        xattrs=(),
    )


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _snapshot_regular_file(path: str, *, required: bool) -> _FileSnapshot:
    parent_device, parent_inode = _parent_identity(path)
    try:
        link_stat = os.lstat(path)
    except FileNotFoundError:
        if required:
            raise V8ActivationError("source_missing", "snapshot", target_path=path) from None
        return _FileSnapshot(
            path=path,
            existed=False,
            payload=b"",
            sha256=None,
            mode=None,
            uid=None,
            gid=None,
            device=None,
            inode=None,
            parent_device=parent_device,
            parent_inode=parent_inode,
        )
    except OSError:
        raise V8ActivationError("source_unreadable", "snapshot", target_path=path) from None

    if stat.S_ISLNK(link_stat.st_mode):
        raise V8ActivationError("symlink_forbidden", "snapshot", target_path=path)
    if _is_windows() and getattr(link_stat, "st_file_attributes", 0) & 0x00000400:
        raise V8ActivationError("reparse_forbidden", "snapshot", target_path=path)
    if not stat.S_ISREG(link_stat.st_mode):
        raise V8ActivationError("regular_file_required", "snapshot", target_path=path)
    if link_stat.st_size > _MAX_SNAPSHOT_BYTES:
        raise V8ActivationError("source_too_large", "snapshot", target_path=path)

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        raise V8ActivationError("source_unreadable", "snapshot", target_path=path) from None
    try:
        opened_stat = os.fstat(descriptor)
        if not stat.S_ISREG(opened_stat.st_mode):
            raise V8ActivationError("regular_file_required", "snapshot", target_path=path)
        if (opened_stat.st_dev, opened_stat.st_ino) != (link_stat.st_dev, link_stat.st_ino):
            raise V8ActivationError("source_changed", "snapshot", target_path=path)
        chunks: list[bytes] = []
        size = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > _MAX_SNAPSHOT_BYTES:
                raise V8ActivationError("source_too_large", "snapshot", target_path=path)
            chunks.append(chunk)
        payload = b"".join(chunks)
        xattrs = _read_xattrs(descriptor, path)
        windows_security = windows_acl.capture_fd(descriptor) if _is_windows() else None
        darwin_acl = _read_darwin_acl(descriptor, path)
        _assert_parent_identity(path, parent_device, parent_inode)
    except windows_acl.WindowsAclError:
        raise V8ActivationError("acl_unreadable", "snapshot", target_path=path) from None
    finally:
        os.close(descriptor)

    return _FileSnapshot(
        path=path,
        existed=True,
        payload=payload,
        sha256=_sha256(payload),
        mode=stat.S_IMODE(opened_stat.st_mode),
        uid=getattr(opened_stat, "st_uid", None),
        gid=getattr(opened_stat, "st_gid", None),
        device=opened_stat.st_dev,
        inode=opened_stat.st_ino,
        parent_device=parent_device,
        parent_inode=parent_inode,
        xattrs=xattrs,
        windows_security=windows_security,
        flags=int(getattr(opened_stat, "st_flags", 0)),
        darwin_acl=darwin_acl,
    )


def _snapshot_claimed_windows_file(path: str, descriptor: int) -> _FileSnapshot:
    """Snapshot the exact file held by a write/delete-denying Windows claim."""

    parent_device, parent_inode = _parent_identity(path)
    try:
        link_stat = os.lstat(path)
    except OSError:
        raise V8ActivationError("source_unreadable", "snapshot", target_path=path) from None
    if stat.S_ISLNK(link_stat.st_mode) or getattr(link_stat, "st_file_attributes", 0) & 0x00000400:
        raise V8ActivationError("reparse_forbidden", "snapshot", target_path=path)
    if not stat.S_ISREG(link_stat.st_mode):
        raise V8ActivationError("regular_file_required", "snapshot", target_path=path)

    opened_stat = os.fstat(descriptor)
    if not stat.S_ISREG(opened_stat.st_mode):
        raise V8ActivationError("regular_file_required", "snapshot", target_path=path)
    if getattr(opened_stat, "st_file_attributes", 0) & 0x00000400:
        raise V8ActivationError("reparse_forbidden", "snapshot", target_path=path)
    if (opened_stat.st_dev, opened_stat.st_ino) != (link_stat.st_dev, link_stat.st_ino):
        raise V8ActivationError("source_changed", "snapshot", target_path=path)
    if opened_stat.st_size > _MAX_SNAPSHOT_BYTES:
        raise V8ActivationError("source_too_large", "snapshot", target_path=path)

    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    size = 0
    while chunk := os.read(descriptor, 1024 * 1024):
        size += len(chunk)
        if size > _MAX_SNAPSHOT_BYTES:
            raise V8ActivationError("source_too_large", "snapshot", target_path=path)
        chunks.append(chunk)
    payload = b"".join(chunks)
    try:
        security = windows_acl.capture_fd(descriptor)
    except windows_acl.WindowsAclError:
        raise V8ActivationError("acl_unreadable", "snapshot", target_path=path) from None
    _assert_parent_identity(path, parent_device, parent_inode)
    return _FileSnapshot(
        path=path,
        existed=True,
        payload=payload,
        sha256=_sha256(payload),
        mode=stat.S_IMODE(opened_stat.st_mode),
        uid=getattr(opened_stat, "st_uid", None),
        gid=getattr(opened_stat, "st_gid", None),
        device=opened_stat.st_dev,
        inode=opened_stat.st_ino,
        parent_device=parent_device,
        parent_inode=parent_inode,
        xattrs=(),
        windows_security=security,
        flags=0,
        darwin_acl=None,
    )


def _parent_identity(path: str) -> tuple[int, int]:
    parent = os.path.dirname(path) or "."
    if _is_windows():
        try:
            info = os.lstat(parent)
        except OSError:
            raise V8ActivationError("parent_unreadable", "snapshot", target_path=path) from None
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x00000400:
            raise V8ActivationError("parent_reparse_forbidden", "snapshot", target_path=path)
        if not stat.S_ISDIR(info.st_mode):
            raise V8ActivationError("parent_directory_required", "snapshot", target_path=path)
        return info.st_dev, info.st_ino
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(parent, flags)
    except OSError:
        raise V8ActivationError("parent_unreadable", "snapshot", target_path=path) from None
    try:
        info = os.fstat(descriptor)
        return info.st_dev, info.st_ino
    finally:
        os.close(descriptor)


def _assert_parent_identity(path: str, device: int, inode: int) -> None:
    current_device, current_inode = _parent_identity(path)
    if (current_device, current_inode) != (device, inode):
        raise V8ActivationError("parent_changed", "snapshot", target_path=path)


def _read_xattrs(descriptor: int, path: str) -> tuple[tuple[str, bytes], ...]:
    listxattr = getattr(os, "listxattr", None)
    getxattr = getattr(os, "getxattr", None)
    if listxattr is None or getxattr is None:
        if sys.platform == "darwin":
            return _read_darwin_xattrs(descriptor, path)
        if os.name == "posix":
            raise V8ActivationError("metadata_unreadable", "snapshot", target_path=path)
        return ()
    try:
        names = listxattr(descriptor)
        return tuple(sorted((name, getxattr(descriptor, name)) for name in names))
    except OSError:
        raise V8ActivationError("metadata_unreadable", "snapshot", target_path=path) from None


def _read_darwin_xattrs(descriptor: int, path: str) -> tuple[tuple[str, bytes], ...]:
    libc = ctypes.CDLL(None, use_errno=True)
    flistxattr = libc.flistxattr
    flistxattr.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
    flistxattr.restype = ctypes.c_ssize_t
    size = flistxattr(descriptor, None, 0, 0)
    if size < 0:
        raise V8ActivationError("metadata_unreadable", "snapshot", target_path=path)
    if size == 0:
        return ()
    names_buffer = ctypes.create_string_buffer(size)
    if flistxattr(descriptor, names_buffer, size, 0) != size:
        raise V8ActivationError("metadata_unreadable", "snapshot", target_path=path)
    fgetxattr = libc.fgetxattr
    fgetxattr.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_uint32,
        ctypes.c_int,
    ]
    fgetxattr.restype = ctypes.c_ssize_t
    result: list[tuple[str, bytes]] = []
    for raw_name in names_buffer.raw[:size].split(b"\0"):
        if not raw_name:
            continue
        value_size = fgetxattr(descriptor, raw_name, None, 0, 0, 0)
        if value_size < 0:
            raise V8ActivationError("metadata_unreadable", "snapshot", target_path=path)
        value_buffer = ctypes.create_string_buffer(value_size)
        if value_size and fgetxattr(descriptor, raw_name, value_buffer, value_size, 0, 0) != value_size:
            raise V8ActivationError("metadata_unreadable", "snapshot", target_path=path)
        result.append((os.fsdecode(raw_name), value_buffer.raw[:value_size]))
    return tuple(sorted(result))


def _read_darwin_acl(descriptor: int, target: str) -> bytes | None:
    """Capture the exact extended ACL attached to one already-open inode."""

    if sys.platform != "darwin":
        return None
    libc = ctypes.CDLL(None, use_errno=True)
    acl_get_fd_np = libc.acl_get_fd_np
    acl_get_fd_np.argtypes = [ctypes.c_int, ctypes.c_int]
    acl_get_fd_np.restype = ctypes.c_void_p
    acl_to_text = libc.acl_to_text
    acl_to_text.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ssize_t)]
    acl_to_text.restype = ctypes.c_void_p
    acl_free = libc.acl_free
    acl_free.argtypes = [ctypes.c_void_p]
    acl_free.restype = ctypes.c_int

    ctypes.set_errno(0)
    acl = acl_get_fd_np(descriptor, 0x00000100)  # ACL_TYPE_EXTENDED
    if not acl:
        error = ctypes.get_errno()
        no_acl_errors = {errno.ENOENT, getattr(errno, "ENOATTR", errno.ENOENT)}
        if error in no_acl_errors:
            return None
        raise V8ActivationError("acl_unreadable", "snapshot", target_path=target)
    try:
        length = ctypes.c_ssize_t()
        text = acl_to_text(acl, ctypes.byref(length))
        if not text:
            raise V8ActivationError("acl_unreadable", "snapshot", target_path=target)
        try:
            return ctypes.string_at(text, length.value)
        finally:
            acl_free(text)
    finally:
        acl_free(acl)


def _assert_descriptor_acl_representable(descriptor: int, target: str) -> None:
    if _read_darwin_acl(descriptor, target) is not None:
        raise V8ActivationError("acl_preservation_unsupported", "staged_acl", target_path=target)


def _validate_migration_result(
    migration: V8MigrationResult,
    source: _FileSnapshot,
) -> None:
    if not source.existed or source.sha256 != migration.source_sha256:
        raise V8ActivationError("source_digest_mismatch", "validate_result", target_path=source.path)
    if _sha256(migration.candidate) != migration.candidate_sha256:
        raise V8ActivationError("candidate_digest_mismatch", "validate_result")
    if migration.already_v8 == migration.changed:
        raise V8ActivationError("invalid_result_state", "validate_result")
    if not migration.changed and migration.candidate != source.payload:
        raise V8ActivationError("invalid_result_state", "validate_result")
    if not migration.changed and migration.environment_edits:
        raise V8ActivationError("invalid_result_state", "validate_result")

    dependency_names: set[str] = set()
    for dependency in migration.environment_dependencies:
        if (
            dependency.name in dependency_names
            or not _ENV_NAME_RE.fullmatch(dependency.name)
            or not re.fullmatch(r"[0-9a-f]{64}", dependency.value_sha256)
        ):
            raise V8ActivationError("invalid_environment_dependency", "validate_result")
        dependency_names.add(dependency.name)

    candidate_scalars, candidate_document = _candidate_projection(migration.candidate)
    seen: set[str] = set()
    for edit in migration.environment_edits:
        if edit.name in seen or not _ENV_NAME_RE.fullmatch(edit.name):
            raise V8ActivationError("invalid_environment_edit", "validate_result")
        seen.add(edit.name)
        if not edit.references:
            raise V8ActivationError("unsupported_environment_reference", "validate_result")
        for reference in edit.references:
            if not _candidate_reference_matches(candidate_document, reference.destination, reference.path, edit.name):
                raise V8ActivationError("environment_reference_missing", "validate_result")
        if set(edit.references) != _candidate_environment_references(candidate_document, edit.name):
            raise V8ActivationError("environment_reference_provenance_mismatch", "validate_result")
        if edit.operation != "set_if_absent" or not edit.backup_required or not edit.rollback_with_config:
            raise V8ActivationError("unsupported_environment_edit", "validate_result")
        try:
            encoded = edit.value.encode("utf-8")
        except UnicodeEncodeError:
            raise V8ActivationError(
                "environment_value_invalid",
                "validate_result",
            ) from None
        if _sha256(encoded) != edit.value_sha256:
            raise V8ActivationError("environment_edit_digest_mismatch", "validate_result")
        # Parse scalar values for exact low-entropy leaks (so a secret "8"
        # does not collide with the integer config_version) and retain a raw
        # scan for longer values that could survive in comments.
        if edit.value in candidate_scalars or (
            len(encoded) >= _MIN_SECRET_LEAK_SCAN_BYTES and encoded in migration.candidate
        ):
            raise V8ActivationError("secret_in_candidate", "validate_result")


def _candidate_projection(candidate: bytes) -> tuple[frozenset[str], object]:
    try:
        document = yaml.safe_load(candidate)
    except (yaml.YAMLError, UnicodeDecodeError, RecursionError):
        # The mandatory target validator owns malformed candidates.  Do not
        # render its source or a parser cause at this secret boundary.
        return frozenset(), None
    pending = [document]
    seen_containers: set[int] = set()
    strings: set[str] = set()
    while pending:
        value = pending.pop()
        if isinstance(value, str):
            strings.add(value)
            continue
        if isinstance(value, dict):
            if id(value) in seen_containers:
                continue
            seen_containers.add(id(value))
            pending.extend(value.keys())
            pending.extend(value.values())
        elif isinstance(value, (list, tuple, set)):
            if id(value) in seen_containers:
                continue
            seen_containers.add(id(value))
            pending.extend(value)
    return frozenset(strings), document


def _candidate_reference_matches(
    document: object,
    destination_name: str,
    path: tuple[str, ...],
    environment_name: str,
) -> bool:
    if not destination_name or not path or not isinstance(document, dict):
        return False
    observability = document.get("observability")
    if not isinstance(observability, dict):
        return False
    destinations = observability.get("destinations")
    if not isinstance(destinations, list):
        return False
    matching = [
        destination
        for destination in destinations
        if isinstance(destination, dict) and destination.get("name") == destination_name
    ]
    if len(matching) != 1:
        return False
    value: object = matching[0]
    for component in path:
        if not isinstance(component, str) or not component or not isinstance(value, dict) or component not in value:
            return False
        value = value[component]
    return value == environment_name


def _candidate_environment_references(document: object, environment_name: str) -> set[EnvironmentReference]:
    references: set[EnvironmentReference] = set()
    if not isinstance(document, dict):
        return references
    observability = document.get("observability")
    destinations = observability.get("destinations") if isinstance(observability, dict) else None
    if not isinstance(destinations, list):
        return references
    for destination in destinations:
        if not isinstance(destination, dict) or not isinstance(destination.get("name"), str):
            continue
        destination_name = destination["name"]
        for field_name in ("token_env", "bearer_env"):
            if destination.get(field_name) == environment_name:
                references.add(EnvironmentReference(destination_name, (field_name,)))
        headers = destination.get("headers")
        if not isinstance(headers, dict):
            continue
        for header_name, value in headers.items():
            if isinstance(header_name, str) and isinstance(value, dict) and value.get("env") == environment_name:
                references.add(EnvironmentReference(destination_name, ("headers", header_name, "env")))
    return references


def _build_environment_candidate(source: bytes, edits: tuple[EnvironmentEdit, ...]) -> bytes:
    if not edits:
        return source
    occurrences: dict[str, list[tuple[bytes, bool]]] = {edit.name: [] for edit in edits}
    for raw_line in source.splitlines():
        match = _ENV_LINE_RE.fullmatch(raw_line.rstrip(b"\r"))
        if match is None:
            continue
        try:
            name = match.group("name").decode("ascii")
        except UnicodeDecodeError:
            continue
        if name in occurrences:
            occurrences[name].append((match.group("value"), bool(match.group("export"))))

    pending: list[EnvironmentEdit] = []
    for edit in sorted(edits, key=lambda item: item.name):
        matches = occurrences[edit.name]
        if len(matches) > 1 or (matches and matches[0][1]):
            raise V8ActivationError("environment_entry_ambiguous", "build_environment")
        if matches:
            existing = _decode_environment_value(matches[0][0])
            if existing != edit.value:
                raise V8ActivationError("environment_entry_conflict", "build_environment")
            continue
        pending.append(edit)

    if not pending:
        return source
    newline = b"\r\n" if b"\r\n" in source and b"\n" in source else b"\n"
    candidate = bytearray(source)
    if candidate and not candidate.endswith((b"\n", b"\r")):
        candidate.extend(newline)
    for edit in pending:
        candidate.extend(edit.name.encode("ascii"))
        candidate.extend(b"=")
        candidate.extend(_encode_environment_value(edit.value))
        candidate.extend(newline)
    return bytes(candidate)


def _assert_ambient_environment_compatible(
    environment: Mapping[str, str],
    edits: tuple[EnvironmentEdit, ...],
) -> None:
    for edit in edits:
        if edit.name in environment and environment[edit.name] != edit.value:
            raise V8ActivationError(
                "ambient_environment_conflict",
                "validate_environment_precedence",
            )


def _assert_all_ambient_environments_compatible(
    supplied: Mapping[str, str],
    edits: tuple[EnvironmentEdit, ...],
) -> None:
    _assert_ambient_environment_compatible(supplied, edits)
    if supplied is not os.environ:
        _assert_ambient_environment_compatible(os.environ, edits)


def _assert_environment_dependencies(
    environment: Mapping[str, str],
    dependencies: tuple[EnvironmentDependency, ...],
) -> None:
    for dependency in dependencies:
        present = dependency.name in environment
        value = environment.get(dependency.name, "")
        if present != dependency.present or _sha256(value.encode("utf-8")) != dependency.value_sha256:
            raise V8ActivationError("environment_dependency_changed", "environment_cas")


def _assert_all_environment_dependencies(
    supplied: Mapping[str, str],
    dependencies: tuple[EnvironmentDependency, ...],
) -> None:
    _assert_environment_dependencies(supplied, dependencies)
    if supplied is os.environ:
        return
    for dependency in dependencies:
        if dependency.name not in os.environ:
            continue
        value = os.environ.get(dependency.name, "")
        if not dependency.present or _sha256(value.encode("utf-8")) != dependency.value_sha256:
            raise V8ActivationError("environment_dependency_changed", "environment_cas")


def _decode_environment_value(raw: bytes) -> str:
    value = raw.strip()
    if len(value) >= 2 and value[:1] == value[-1:] and value[:1] in {b"'", b'"'}:
        value = value[1:-1]
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError:
        raise V8ActivationError("environment_entry_invalid_utf8", "build_environment") from None


def _encode_environment_value(value: str) -> bytes:
    if any(character in value for character in ("\n", "\r", "\x00")):
        raise V8ActivationError("environment_value_invalid", "build_environment")
    # Both gateway and CLI dotenv readers remove one matching outer quote
    # pair.  Quoting every promoted value therefore preserves leading/trailing
    # whitespace and comment characters without an escaping language.
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        raise V8ActivationError(
            "environment_value_invalid",
            "build_environment",
        ) from None
    return b"'" + encoded + b"'"


def _assert_snapshot_current(snapshot: _FileSnapshot, stage: str) -> None:
    current = _snapshot_regular_file(snapshot.path, required=snapshot.existed)
    if snapshot.existed != current.existed:
        raise V8ActivationError("source_changed", stage, target_path=snapshot.path)
    if not snapshot.existed:
        return
    if (
        snapshot.sha256 != current.sha256
        or snapshot.mode != current.mode
        or snapshot.uid != current.uid
        or snapshot.gid != current.gid
        or snapshot.device != current.device
        or snapshot.inode != current.inode
        or snapshot.parent_device != current.parent_device
        or snapshot.parent_inode != current.parent_inode
        or snapshot.xattrs != current.xattrs
        or snapshot.windows_security != current.windows_security
        or snapshot.flags != current.flags
        or snapshot.darwin_acl != current.darwin_acl
    ):
        raise V8ActivationError("source_changed", stage, target_path=snapshot.path)


def _assert_expected_file_state(path: str, expected: _ExpectedFileState) -> None:
    current = _snapshot_regular_file(path, required=expected.existed)
    if not _matches_expected_state(current, expected):
        raise V8ActivationError(
            "activation_state_mismatch",
            "activation_verification",
            target_path=path,
        )


def _create_recovery_backup(
    backup_root: str,
    config: _FileSnapshot,
    environment: _FileSnapshot,
    migration: V8MigrationResult,
    environment_candidate_sha256: str | None,
) -> str:
    if _is_windows():
        return _create_recovery_backup_windows(
            backup_root,
            config,
            environment,
            migration,
            environment_candidate_sha256,
        )
    backup_parent = os.path.dirname(backup_root) or "."
    root_name = os.path.basename(backup_root)
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    parent_descriptor = os.open(backup_parent, flags)
    root_descriptor = -1
    directory_descriptor = -1
    directory_name = ""
    try:
        try:
            os.mkdir(root_name, 0o700, dir_fd=parent_descriptor)
            os.fsync(parent_descriptor)
        except FileExistsError:
            pass
        root_descriptor = os.open(root_name, flags, dir_fd=parent_descriptor)
        backup_info = os.fstat(root_descriptor)
        if not stat.S_ISDIR(backup_info.st_mode):
            raise OSError(errno.ENOTDIR, "backup root is not a directory")
        if stat.S_IMODE(backup_info.st_mode) & 0o077:
            raise OSError(errno.EPERM, "backup root permissions are not private")
        for _ in range(128):
            directory_name = f"observability-v8-{uuid.uuid4().hex}"
            try:
                os.mkdir(directory_name, 0o700, dir_fd=root_descriptor)
                break
            except FileExistsError:
                continue
        else:
            raise OSError(errno.EEXIST, "unable to allocate recovery directory")
        directory_descriptor = os.open(directory_name, flags, dir_fd=root_descriptor)
        _assert_descriptor_acl_representable(directory_descriptor, backup_root)
        _write_backup_snapshot_at(directory_descriptor, "config.source", config)
        if environment.existed:
            _write_backup_snapshot_at(directory_descriptor, "environment.source", environment)

        manifest = {
            "schema_version": _BACKUP_SCHEMA,
            "kind": "observability-v8-activation",
            "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "source_sha256": migration.source_sha256,
            "candidate_sha256": migration.candidate_sha256,
            "environment_candidate_sha256": environment_candidate_sha256,
            "files": [
                _manifest_file("config", config),
                _manifest_file("environment", environment),
            ],
        }
        payload = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
        _write_new_file_at(directory_descriptor, "manifest.json", payload, 0o600)
        os.fsync(directory_descriptor)
        os.fsync(root_descriptor)
        root_public = os.lstat(backup_root)
        if stat.S_ISLNK(root_public.st_mode) or (root_public.st_dev, root_public.st_ino) != (
            backup_info.st_dev,
            backup_info.st_ino,
        ):
            raise OSError(errno.EBUSY, "backup root changed during transaction")
        directory = os.path.join(backup_root, directory_name)
        directory_public = os.lstat(directory)
        directory_pinned = os.fstat(directory_descriptor)
        if stat.S_ISLNK(directory_public.st_mode) or (directory_public.st_dev, directory_public.st_ino) != (
            directory_pinned.st_dev,
            directory_pinned.st_ino,
        ):
            raise OSError(errno.EBUSY, "backup directory changed during transaction")
        return directory
    except BaseException:
        if directory_descriptor >= 0:
            for name in ("config.source", "environment.source", "manifest.json"):
                try:
                    os.unlink(name, dir_fd=directory_descriptor)
                except OSError:
                    pass
        if root_descriptor >= 0 and directory_name:
            try:
                os.rmdir(directory_name, dir_fd=root_descriptor)
            except OSError:
                pass
        raise
    finally:
        if directory_descriptor >= 0:
            os.close(directory_descriptor)
        if root_descriptor >= 0:
            os.close(root_descriptor)
        os.close(parent_descriptor)


def _create_recovery_backup_windows(
    backup_root: str,
    config: _FileSnapshot,
    environment: _FileSnapshot,
    migration: V8MigrationResult,
    environment_candidate_sha256: str | None,
) -> str:
    backup_parent = os.path.dirname(backup_root) or "."
    try:
        private_security = windows_acl.private_security_for_directory(backup_parent)
        if os.path.lexists(backup_root):
            info = os.lstat(backup_root)
            if (
                stat.S_ISLNK(info.st_mode)
                or getattr(info, "st_file_attributes", 0) & 0x00000400
                or not stat.S_ISDIR(info.st_mode)
            ):
                raise windows_acl.WindowsAclError("backup root is not a real directory")
            root_security = windows_acl.capture_path(backup_root, directory=True)
            windows_acl.assert_trusted_owner(root_security)
            windows_acl.assert_not_broadly_writable(root_security)
            windows_acl.assert_not_broadly_readable(root_security)
        else:
            os.mkdir(backup_root)
            windows_acl.apply_path(backup_root, private_security, directory=True)
    except (OSError, windows_acl.WindowsAclError):
        raise V8ActivationError("backup_failed", "prepare_backup_root", target_path=backup_root) from None

    directory = os.path.join(backup_root, f"observability-v8-{uuid.uuid4().hex}")
    created = False
    try:
        os.mkdir(directory)
        created = True
        windows_acl.apply_path(directory, private_security, directory=True)
        windows_acl.write_new_file(os.path.join(directory, "config.source"), config.payload, private_security)
        if environment.existed:
            windows_acl.write_new_file(
                os.path.join(directory, "environment.source"),
                environment.payload,
                private_security,
            )
        manifest = {
            "schema_version": _BACKUP_SCHEMA,
            "kind": "observability-v8-activation",
            "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "source_sha256": migration.source_sha256,
            "candidate_sha256": migration.candidate_sha256,
            "environment_candidate_sha256": environment_candidate_sha256,
            "files": [
                _manifest_file("config", config),
                _manifest_file("environment", environment),
            ],
        }
        payload = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
        windows_acl.write_new_file(os.path.join(directory, "manifest.json"), payload, private_security)
        root_info = os.lstat(backup_root)
        directory_info = os.lstat(directory)
        if (
            getattr(root_info, "st_file_attributes", 0) & 0x00000400
            or getattr(directory_info, "st_file_attributes", 0) & 0x00000400
        ):
            raise OSError(errno.EBUSY, "backup directory became a reparse point")
        return directory
    except BaseException:
        if created:
            for name in ("config.source", "environment.source", "manifest.json"):
                try:
                    os.unlink(os.path.join(directory, name))
                except OSError:
                    pass
            try:
                os.rmdir(directory)
            except OSError:
                pass
        raise


def _tighten_existing_backup_root(
    backup_root: str,
    trusted_owners: frozenset[tuple[int, int]],
) -> None:
    """Narrow a trusted legacy upgrader root before writing v8 recovery data.

    Released pre-v8 upgrade commands create ``backups`` before installing and
    invoking the target migration.  Those commands inherited the process umask,
    commonly leaving an owner-controlled 0755 root.  The target migration may
    narrow that exact real directory to 0700, but it never repairs a symlink,
    non-directory, untrusted owner, or group/other-writable parent chain.
    """

    backup_parent = os.path.dirname(backup_root) or "."
    if _is_windows():
        info = os.lstat(backup_root)
        if (
            stat.S_ISLNK(info.st_mode)
            or getattr(info, "st_file_attributes", 0) & 0x00000400
            or not stat.S_ISDIR(info.st_mode)
        ):
            raise OSError(errno.ENOTDIR, "backup root is not a real directory")
        security = windows_acl.private_security_for_directory(backup_parent)
        windows_acl.apply_path(backup_root, security, directory=True)
        return
    root_name = os.path.basename(backup_root)
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    parent_descriptor = os.open(backup_parent, flags)
    root_descriptor = -1
    try:
        root_descriptor = os.open(root_name, flags, dir_fd=parent_descriptor)
        root_info = os.fstat(root_descriptor)
        if not stat.S_ISDIR(root_info.st_mode):
            raise OSError(errno.ENOTDIR, "backup root is not a directory")
        if not _trusted_private_owner(
            getattr(root_info, "st_uid", None),
            getattr(root_info, "st_gid", None),
            stat.S_IMODE(root_info.st_mode),
            trusted_owners,
        ):
            raise OSError(errno.EPERM, "backup root owner is not trusted")
        # _assert_secure_parent_chain has already rejected group/other write
        # access. Narrowing the remaining read/execute bits is monotonic.
        if stat.S_IMODE(root_info.st_mode) != 0o700:
            os.fchmod(root_descriptor, 0o700)
            os.fsync(root_descriptor)
        narrowed = os.fstat(root_descriptor)
        public = os.lstat(backup_root)
        if (
            stat.S_ISLNK(public.st_mode)
            or (public.st_dev, public.st_ino) != (narrowed.st_dev, narrowed.st_ino)
            or stat.S_IMODE(narrowed.st_mode) != 0o700
        ):
            raise OSError(errno.EBUSY, "backup root changed while permissions were narrowed")
    finally:
        if root_descriptor >= 0:
            os.close(root_descriptor)
        os.close(parent_descriptor)


def _manifest_file(role: str, snapshot: _FileSnapshot) -> dict[str, object]:
    return {
        "role": role,
        "target_path": snapshot.path,
        "existed": snapshot.existed,
        "sha256": snapshot.sha256,
        "size": len(snapshot.payload) if snapshot.existed else 0,
        "mode": f"{snapshot.mode:04o}" if snapshot.mode is not None else None,
        "uid": snapshot.uid,
        "gid": snapshot.gid,
    }


def _write_backup_snapshot_at(directory_descriptor: int, name: str, snapshot: _FileSnapshot) -> None:
    mode = snapshot.mode if snapshot.mode is not None else 0o600
    _write_new_file_at(
        directory_descriptor,
        name,
        snapshot.payload,
        mode,
        uid=snapshot.uid,
        gid=snapshot.gid,
        xattrs=snapshot.xattrs,
    )


def _write_new_file_at(
    directory_descriptor: int,
    name: str,
    payload: bytes,
    mode: int,
    *,
    uid: int | None = None,
    gid: int | None = None,
    xattrs: tuple[tuple[str, bytes], ...] = (),
) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(name, flags, mode, dir_fd=directory_descriptor)
    try:
        _assert_descriptor_acl_representable(descriptor, name)
        _apply_descriptor_metadata(descriptor, mode, uid, gid, xattrs=xattrs)
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
            _remove_unexpected_xattrs(handle.fileno(), frozenset(name for name, _value in xattrs))
            os.fsync(handle.fileno())
    finally:
        os.close(descriptor)


def _open_pinned_parent(snapshot: _FileSnapshot) -> int:
    parent = os.path.dirname(snapshot.path) or "."
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(parent, flags)
    info = os.fstat(descriptor)
    if (info.st_dev, info.st_ino) != (snapshot.parent_device, snapshot.parent_inode):
        os.close(descriptor)
        raise V8ActivationError("parent_changed", "locked_publish_check", target_path=snapshot.path)
    return descriptor


def _assert_pinned_parent_public(snapshot: _FileSnapshot, descriptor: int) -> None:
    parent = os.path.dirname(snapshot.path) or "."
    try:
        public = os.lstat(parent)
    except OSError:
        raise V8ActivationError("parent_changed", "locked_publish_check", target_path=snapshot.path) from None
    pinned = os.fstat(descriptor)
    if stat.S_ISLNK(public.st_mode) or (public.st_dev, public.st_ino) != (pinned.st_dev, pinned.st_ino):
        raise V8ActivationError("parent_changed", "locked_publish_check", target_path=snapshot.path)


def _create_staged_file(parent_descriptor: int, basename: str, purpose: str) -> tuple[int, str]:
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    for _ in range(128):
        name = f".{basename}.observability-v8-{purpose}-{uuid.uuid4().hex}.tmp"
        try:
            return os.open(name, flags, 0o600, dir_fd=parent_descriptor), name
        except FileExistsError:
            continue
    raise OSError(errno.EEXIST, "unable to allocate a private staged file")


def _snapshot_regular_file_at(
    parent_descriptor: int,
    parent_path: str,
    name: str,
    *,
    required: bool,
) -> _FileSnapshot:
    display_path = os.path.join(parent_path, name)
    try:
        link_stat = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        if required:
            raise V8ActivationError("source_missing", "snapshot", target_path=display_path) from None
        parent = os.fstat(parent_descriptor)
        return _FileSnapshot(
            path=display_path,
            existed=False,
            payload=b"",
            sha256=None,
            mode=None,
            uid=None,
            gid=None,
            device=None,
            inode=None,
            parent_device=parent.st_dev,
            parent_inode=parent.st_ino,
        )
    if stat.S_ISLNK(link_stat.st_mode):
        raise V8ActivationError("symlink_forbidden", "snapshot", target_path=display_path)
    if not stat.S_ISREG(link_stat.st_mode):
        raise V8ActivationError("regular_file_required", "snapshot", target_path=display_path)
    if link_stat.st_size > _MAX_SNAPSHOT_BYTES:
        raise V8ActivationError("source_too_large", "snapshot", target_path=display_path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(name, flags, dir_fd=parent_descriptor)
    try:
        opened_stat = os.fstat(descriptor)
        if (opened_stat.st_dev, opened_stat.st_ino) != (link_stat.st_dev, link_stat.st_ino):
            raise V8ActivationError("source_changed", "snapshot", target_path=display_path)
        chunks: list[bytes] = []
        size = 0
        while chunk := os.read(descriptor, 1024 * 1024):
            size += len(chunk)
            if size > _MAX_SNAPSHOT_BYTES:
                raise V8ActivationError("source_too_large", "snapshot", target_path=display_path)
            chunks.append(chunk)
        payload = b"".join(chunks)
        xattrs = _read_xattrs(descriptor, display_path)
        darwin_acl = _read_darwin_acl(descriptor, display_path)
    finally:
        os.close(descriptor)
    parent = os.fstat(parent_descriptor)
    return _FileSnapshot(
        path=display_path,
        existed=True,
        payload=payload,
        sha256=_sha256(payload),
        mode=stat.S_IMODE(opened_stat.st_mode),
        uid=getattr(opened_stat, "st_uid", None),
        gid=getattr(opened_stat, "st_gid", None),
        device=opened_stat.st_dev,
        inode=opened_stat.st_ino,
        parent_device=parent.st_dev,
        parent_inode=parent.st_ino,
        xattrs=xattrs,
        flags=int(getattr(opened_stat, "st_flags", 0)),
        darwin_acl=darwin_acl,
    )


def _atomic_replace(
    snapshot: _FileSnapshot,
    payload: bytes,
    *,
    default_mode: int,
    metadata: _FileSnapshot | None = None,
) -> None:
    if _is_windows():
        _atomic_replace_windows(snapshot, payload, metadata=metadata)
        return
    parent = os.path.dirname(snapshot.path) or "."
    parent_descriptor = _open_pinned_parent(snapshot)
    descriptor, temporary_name = _create_staged_file(
        parent_descriptor,
        os.path.basename(snapshot.path),
        "candidate",
    )
    try:
        _assert_descriptor_acl_representable(descriptor, snapshot.path)
        metadata_source = snapshot if metadata is None else metadata
        mode = metadata_source.mode if metadata_source.mode is not None else default_mode
        _apply_descriptor_metadata(
            descriptor,
            mode,
            metadata_source.uid,
            metadata_source.gid,
            xattrs=metadata_source.xattrs,
        )
        handle = os.fdopen(descriptor, "wb")
        descriptor = -1
        with handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
            _remove_unexpected_xattrs(
                handle.fileno(),
                frozenset(name for name, _value in metadata_source.xattrs),
            )
            os.fsync(handle.fileno())
        candidate = _snapshot_regular_file_at(
            parent_descriptor,
            parent,
            temporary_name,
            required=True,
        )
        _assert_staged_metadata(candidate, metadata_source, mode)
        try:
            _publish_checked_under_lock(
                snapshot,
                candidate,
                parent_descriptor=parent_descriptor,
                candidate_name=temporary_name,
            )
        except V8ActivationRollbackError:
            # The path may now retain the authoritative inode displaced by an
            # uncooperative writer. Its recovery path is carried by the error;
            # generic cleanup must never unlink it.
            temporary_name = ""
            raise
        temporary_name = ""
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary_name:
            try:
                os.unlink(temporary_name, dir_fd=parent_descriptor)
            except FileNotFoundError:
                pass
        os.close(parent_descriptor)


def _atomic_replace_windows(
    snapshot: _FileSnapshot,
    payload: bytes,
    *,
    metadata: _FileSnapshot | None,
) -> None:
    """Publish with native ACL-preserving replace and verified recovery.

    ``ReplaceFileW`` is called without either ACL-error suppression flag.  Its
    transient backup retains the original file object until the new bytes,
    owner, raw DACL, mandatory label, and protection bits have all been re-read.
    """

    metadata_source = snapshot if metadata is None else metadata
    security = metadata_source.windows_security
    if security is None:
        raise OSError(errno.ENOTSUP, "Windows security metadata is unavailable")
    parent = os.path.dirname(snapshot.path) or "."
    basename = os.path.basename(snapshot.path)
    temporary_path = os.path.join(parent, f".{basename}.observability-v8-candidate-{uuid.uuid4().hex}.tmp")
    backup_path = os.path.join(parent, f".{basename}.observability-v8-replaced-{uuid.uuid4().hex}.tmp")
    discard_path = os.path.join(parent, f".{basename}.observability-v8-discard-{uuid.uuid4().hex}.tmp")
    preserve_transients = False
    try:
        windows_acl.write_new_file(temporary_path, payload, security)
        staged = _snapshot_regular_file(temporary_path, required=True)
        _assert_windows_staged_snapshot(staged, payload, security)
        _assert_snapshot_current(snapshot, "locked_publish_check")

        if snapshot.existed:
            preserve_transients = True
            try:
                windows_acl.replace_file(snapshot.path, temporary_path, backup_path)
            except windows_acl.WindowsAclError:
                try:
                    _restore_windows_original(
                        snapshot,
                        candidate_path=temporary_path,
                        backup_path=backup_path,
                        discard_path=discard_path,
                    )
                except BaseException:
                    raise _windows_rollback_incomplete(
                        "windows_replace_failure",
                        snapshot.path,
                        backup_path,
                        discard_path,
                        temporary_path,
                        snapshot.path,
                    ) from None
                preserve_transients = False
                raise
        else:
            preserve_transients = True
            try:
                windows_acl.move_file_no_replace(temporary_path, snapshot.path)
            except windows_acl.WindowsAclError:
                _restore_absent_windows_target(snapshot, payload, security)
                preserve_transients = False
                raise

        if snapshot.existed:
            displaced = _snapshot_regular_file(backup_path, required=True)
            if not _same_snapshot_identity(displaced, snapshot):
                displaced_at_target = replace(displaced, path=snapshot.path)
                try:
                    _restore_windows_original(
                        displaced_at_target,
                        candidate_path=temporary_path,
                        backup_path=backup_path,
                        discard_path=discard_path,
                    )
                except BaseException:
                    raise _windows_rollback_incomplete(
                        "locked_publish_check",
                        snapshot.path,
                        backup_path,
                        discard_path,
                        temporary_path,
                        snapshot.path,
                    ) from None
                preserve_transients = False
                raise V8ActivationError(
                    "source_changed",
                    "locked_publish_check",
                    target_path=snapshot.path,
                )

        expected_security = security if snapshot.existed else security.staging_copy()
        expected = _ExpectedFileState(
            existed=True,
            sha256=_sha256(payload),
            mode=None,
            uid=None,
            gid=None,
            xattrs=(),
            allow_platform_xattrs=not snapshot.existed,
            windows_security=expected_security,
        )
        try:
            _assert_expected_file_state(snapshot.path, expected)
            windows_acl.flush_path(snapshot.path)
        except BaseException:
            try:
                published = _snapshot_regular_file(snapshot.path, required=False)
            except BaseException:
                raise _windows_rollback_incomplete(
                    "windows_publish_verification",
                    snapshot.path,
                    backup_path if snapshot.existed else snapshot.path,
                ) from None
            if not _matches_expected_state(published, expected):
                # An external writer replaced or mutated the live file after
                # ReplaceFileW. Keep it authoritative and retain our recovery
                # evidence instead of moving/deleting its inode.
                raise _windows_rollback_incomplete(
                    "windows_publish_verification",
                    snapshot.path,
                    snapshot.path,
                    backup_path if snapshot.existed else "",
                ) from None
            try:
                if snapshot.existed:
                    _restore_windows_original(
                        snapshot,
                        candidate_path=temporary_path,
                        backup_path=backup_path,
                        discard_path=discard_path,
                    )
                else:
                    _restore_absent_windows_target(snapshot, payload, security)
            except BaseException:
                raise _windows_rollback_incomplete(
                    "windows_publish_verification",
                    snapshot.path,
                    backup_path,
                    discard_path,
                    temporary_path,
                    snapshot.path,
                ) from None
            preserve_transients = False
            raise

        if os.path.lexists(backup_path):
            os.unlink(backup_path)
        preserve_transients = False
        _fsync_directory(parent)
    finally:
        if not preserve_transients:
            for path in (temporary_path, backup_path, discard_path):
                if os.path.lexists(path):
                    # A leftover original/secret-bearing transient is a
                    # transaction failure, not harmless cleanup noise.
                    os.unlink(path)


def _assert_windows_staged_snapshot(
    snapshot: _FileSnapshot,
    payload: bytes,
    security: windows_acl.WindowsFileSecurity,
) -> None:
    if snapshot.sha256 != _sha256(payload) or snapshot.windows_security != security.staging_copy():
        raise OSError(errno.EPERM, "staged Windows file does not match the security contract")


def _restore_windows_original(
    original: _FileSnapshot,
    *,
    candidate_path: str,
    backup_path: str,
    discard_path: str,
) -> None:
    """Recover an existing original after success or partial ReplaceFileW failure."""

    current_descriptor = _claim_windows_file(original.path, missing_ok=True)
    source_descriptor = -1
    try:
        current = (
            _snapshot_claimed_windows_file(original.path, current_descriptor)
            if current_descriptor >= 0
            else replace(original, existed=False, payload=b"", sha256=None)
        )
        if _same_restorable_state(current, original):
            return

        for path in (backup_path, candidate_path):
            candidate_descriptor = _claim_windows_file(path, missing_ok=True)
            if candidate_descriptor < 0:
                continue
            try:
                candidate = _snapshot_claimed_windows_file(path, candidate_descriptor)
            except BaseException:
                os.close(candidate_descriptor)
                raise
            if _same_restorable_state(candidate, original):
                source_descriptor = candidate_descriptor
                break
            os.close(candidate_descriptor)
        if source_descriptor < 0:
            raise OSError(errno.EIO, "ReplaceFileW did not retain a restorable original")

        current_in_discard = False
        if current_descriptor >= 0:
            windows_acl.move_regular_fd_no_replace(current_descriptor, discard_path)
            current_in_discard = True
        try:
            windows_acl.move_regular_fd_no_replace(source_descriptor, original.path)
        except BaseException:
            if current_descriptor >= 0:
                try:
                    windows_acl.move_regular_fd_no_replace(current_descriptor, original.path)
                    current_in_discard = False
                except BaseException:
                    pass
            raise
        restored = _snapshot_claimed_windows_file(original.path, source_descriptor)
        if not _same_restorable_state(restored, original):
            raise OSError(errno.EIO, "Windows original owner/DACL/label was not restored")
        if current_in_discard:
            windows_acl.delete_regular_fd(current_descriptor)
    finally:
        if source_descriptor >= 0:
            os.close(source_descriptor)
        if current_descriptor >= 0:
            os.close(current_descriptor)


def _restore_absent_windows_target(
    original: _FileSnapshot,
    payload: bytes,
    security: windows_acl.WindowsFileSecurity,
) -> None:
    expected = _ExpectedFileState(
        existed=True,
        sha256=_sha256(payload),
        mode=None,
        uid=None,
        gid=None,
        xattrs=(),
        allow_platform_xattrs=True,
        windows_security=security.staging_copy(),
    )
    _delete_expected_windows_file(original.path, expected)


def _claim_windows_file(path: str, *, missing_ok: bool) -> int:
    try:
        return windows_acl.open_regular_mutation_fd(path)
    except OSError as exc:
        code = getattr(exc, "winerror", None) or getattr(exc, "errno", None)
        if missing_ok and code in {2, 3}:
            return -1
        raise


def _delete_expected_windows_file(path: str, expected: _ExpectedFileState) -> None:
    descriptor = _claim_windows_file(path, missing_ok=True)
    if descriptor < 0:
        return
    try:
        current = _snapshot_claimed_windows_file(path, descriptor)
        if not _matches_expected_state(current, expected):
            raise OSError(errno.EBUSY, "Windows rollback target changed outside the transaction")
        windows_acl.delete_regular_fd(descriptor)
    finally:
        os.close(descriptor)


def _windows_rollback_incomplete(
    stage: str,
    target_path: str,
    *possible_recovery_paths: str,
) -> V8ActivationRollbackError:
    retained = tuple(dict.fromkeys(path for path in possible_recovery_paths if path and os.path.lexists(path)))
    backup = next((path for path in retained if not _same_path(path, target_path)), None)
    return V8ActivationRollbackError(
        "rollback_incomplete",
        stage,
        target_path=target_path,
        backup_directory=backup,
        recovery_paths=retained,
    )


def _publish_checked_under_lock(
    expected: _FileSnapshot,
    candidate: _FileSnapshot,
    *,
    parent_descriptor: int,
    candidate_name: str,
) -> None:
    """Publish under the shared lock with an exchange-backed final CAS.

    Existing files are exchanged atomically with the staged candidate.  The
    displaced name is then compared with the exact pre-update snapshot before
    the exchange is committed.  If an uncooperative writer won the final
    check-to-exchange race, its inode is exchanged back into place and the
    candidate is rejected.
    """

    parent = os.path.dirname(expected.path) or "."
    target_name = os.path.basename(expected.path)
    retained_path = os.path.join(parent, candidate_name)
    if not expected.existed:
        try:
            os.link(
                candidate_name,
                target_name,
                src_dir_fd=parent_descriptor,
                dst_dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except OSError:
            raise V8ActivationError("source_changed", "locked_publish_check", target_path=expected.path) from None
        try:
            _assert_pinned_parent_public(expected, parent_descriptor)
            os.fsync(parent_descriptor)
        except BaseException:
            # The target and candidate names still reference the same staged
            # inode. Keep the candidate name as exact recovery evidence when
            # publication durability cannot be established.
            raise V8ActivationRollbackError(
                "rollback_incomplete",
                "publication_commit",
                target_path=expected.path,
                backup_directory=retained_path,
            ) from None
        _cleanup_committed_displaced_entry(
            parent_descriptor,
            candidate_name,
            target_path=expected.path,
            retained_path=retained_path,
        )
        return
    current = _snapshot_regular_file_at(
        parent_descriptor,
        parent,
        target_name,
        required=True,
    )
    if not _same_snapshot_identity(current, expected):
        raise V8ActivationError("source_changed", "locked_publish_check", target_path=expected.path)

    _exchange_entries(parent_descriptor, candidate_name, target_name, expected.path)
    try:
        displaced = _snapshot_regular_file_at(
            parent_descriptor,
            parent,
            candidate_name,
            required=True,
        )
        published = _snapshot_regular_file_at(
            parent_descriptor,
            parent,
            target_name,
            required=True,
        )
    except BaseException:
        # Exchange has already happened. Any failure to characterize both
        # names must retain the displaced entry instead of letting the generic
        # temporary-file cleanup unlink the only exact recovery object.
        raise V8ActivationRollbackError(
            "rollback_incomplete",
            "locked_publish_check",
            target_path=expected.path,
            backup_directory=retained_path,
        ) from None
    if not _same_snapshot_identity(displaced, expected) or not _same_snapshot_identity(published, candidate):
        try:
            restored = _restore_displaced_exchange(
                parent_descriptor,
                parent,
                candidate_name,
                target_name,
                candidate,
                displaced,
                expected.path,
            )
        except BaseException:
            restored = False
        if not restored:
            raise V8ActivationRollbackError(
                "rollback_incomplete",
                "locked_publish_check",
                target_path=expected.path,
                backup_directory=retained_path,
            )
        raise V8ActivationError("source_changed", "locked_publish_check", target_path=expected.path)

    try:
        _assert_pinned_parent_public(expected, parent_descriptor)
    except BaseException:
        try:
            restored = _restore_displaced_exchange(
                parent_descriptor,
                parent,
                candidate_name,
                target_name,
                candidate,
                displaced,
                expected.path,
            )
        except BaseException:
            restored = False
        if not restored:
            raise V8ActivationRollbackError(
                "rollback_incomplete",
                "locked_publish_check",
                target_path=expected.path,
                backup_directory=retained_path,
            ) from None
        raise

    try:
        # This is the publication commit point. Before it succeeds the exact
        # displaced inode must remain named; after it succeeds target already
        # contains the durably committed replacement and cleanup must never
        # trigger reconstructive rollback.
        os.fsync(parent_descriptor)
    except BaseException:
        raise V8ActivationRollbackError(
            "rollback_incomplete",
            "publication_commit",
            target_path=expected.path,
            backup_directory=retained_path,
        ) from None
    _cleanup_committed_displaced_entry(
        parent_descriptor,
        candidate_name,
        target_path=expected.path,
        retained_path=retained_path,
    )


def _cleanup_committed_displaced_entry(
    parent_descriptor: int,
    candidate_name: str,
    *,
    target_path: str,
    retained_path: str,
) -> None:
    """Remove post-commit recovery evidence without invoking reconstruction."""

    try:
        os.unlink(candidate_name, dir_fd=parent_descriptor)
    except FileNotFoundError:
        # Another same-owner process already retired the private transient.
        return
    except BaseException:
        raise V8ActivationRollbackError(
            "rollback_incomplete",
            "post_commit_cleanup",
            target_path=target_path,
            backup_directory=retained_path,
        ) from None
    try:
        os.fsync(parent_descriptor)
    except BaseException:
        # Publication was committed by the preceding directory fsync. Do not
        # reconstruct the old target after cleanup durability becomes unknown;
        # the exact transient name identifies what may reappear after recovery.
        raise V8ActivationRollbackError(
            "rollback_incomplete",
            "post_commit_cleanup",
            target_path=target_path,
            backup_directory=retained_path,
        ) from None


def _exchange_entries(parent_descriptor: int, first: str, second: str, target_path: str) -> None:
    """Use the repository's native Linux/macOS exchange primitive."""

    _native_exchange_entries(parent_descriptor, first, second, target_path)


def _exchange_probe_entries(parent_descriptor: int, first: str, second: str, target_path: str) -> None:
    """Exercise the same native exchange primitive without touching a live name."""

    _native_exchange_entries(parent_descriptor, first, second, target_path)


def _native_exchange_entries(parent_descriptor: int, first: str, second: str, target_path: str) -> None:
    """Invoke the platform exchange primitive with value-safe errors."""

    from defenseclaw.install_publish import PublishError, _exchange

    try:
        _exchange(parent_descriptor, first, second)
    except PublishError:
        raise V8ActivationError(
            "atomic_exchange_failed",
            "locked_publish_check",
            target_path=target_path,
        ) from None


def _rename_entry_no_replace(
    parent_descriptor: int,
    source: str,
    destination: str,
    target_path: str,
) -> None:
    """Atomically move one sibling entry without replacing another writer."""

    from defenseclaw.install_publish import PublishError, _rename_no_replace_between

    try:
        _rename_no_replace_between(
            parent_descriptor,
            source,
            parent_descriptor,
            destination,
        )
    except (FileExistsError, FileNotFoundError):
        raise
    except PublishError:
        raise V8ActivationError(
            "atomic_rename_failed",
            "rollback_delete_cas",
            target_path=target_path,
        ) from None


def _restore_displaced_exchange(
    parent_descriptor: int,
    parent: str,
    candidate_name: str,
    target_name: str,
    candidate: _FileSnapshot,
    displaced: _FileSnapshot,
    target_path: str,
) -> bool:
    """Exchange a stale displaced inode back without clobbering a later writer."""

    try:
        current = _snapshot_regular_file_at(
            parent_descriptor,
            parent,
            target_name,
            required=True,
        )
        retained = _snapshot_regular_file_at(
            parent_descriptor,
            parent,
            candidate_name,
            required=True,
        )
        if not _same_snapshot_identity(current, candidate) or not _same_snapshot_identity(retained, displaced):
            return False
        _exchange_entries(parent_descriptor, candidate_name, target_name, target_path)
        os.fsync(parent_descriptor)
        restored = _snapshot_regular_file_at(
            parent_descriptor,
            parent,
            target_name,
            required=True,
        )
        rejected = _snapshot_regular_file_at(
            parent_descriptor,
            parent,
            candidate_name,
            required=True,
        )
        return _same_snapshot_identity(restored, displaced) and _same_snapshot_identity(rejected, candidate)
    except (OSError, V8ActivationError):
        return False


def _same_snapshot_identity(left: _FileSnapshot, right: _FileSnapshot) -> bool:
    return (
        left.existed == right.existed
        and left.sha256 == right.sha256
        and left.mode == right.mode
        and left.uid == right.uid
        and left.gid == right.gid
        and left.device == right.device
        and left.inode == right.inode
        and left.parent_device == right.parent_device
        and left.parent_inode == right.parent_inode
        and left.xattrs == right.xattrs
        and left.windows_security == right.windows_security
        and left.flags == right.flags
        and left.darwin_acl == right.darwin_acl
    )


def _preflight_atomic_replace(
    snapshot: _FileSnapshot,
    *,
    default_mode: int,
    metadata: _FileSnapshot | None = None,
) -> None:
    """Prove that a same-directory metadata-preserving replacement is possible."""

    if _is_windows():
        _preflight_atomic_replace_windows(snapshot, metadata=metadata)
        return
    parent = os.path.dirname(snapshot.path) or "."
    parent_descriptor = _open_pinned_parent(snapshot)
    descriptor, temporary_name = _create_staged_file(
        parent_descriptor,
        os.path.basename(snapshot.path),
        "preflight",
    )
    exchange_probe_name = ""
    try:
        _assert_descriptor_acl_representable(descriptor, snapshot.path)
        metadata_source = snapshot if metadata is None else metadata
        mode = metadata_source.mode if metadata_source.mode is not None else default_mode
        _apply_descriptor_metadata(
            descriptor,
            mode,
            metadata_source.uid,
            metadata_source.gid,
            xattrs=metadata_source.xattrs,
        )
        os.write(descriptor, b"preflight")
        os.fsync(descriptor)
        _remove_unexpected_xattrs(
            descriptor,
            frozenset(name for name, _value in metadata_source.xattrs),
        )
        os.fsync(descriptor)
        staged = _snapshot_regular_file_at(
            parent_descriptor,
            parent,
            temporary_name,
            required=True,
        )
        _assert_staged_metadata(staged, metadata_source, mode)
        probe_descriptor, exchange_probe_name = _create_staged_file(
            parent_descriptor,
            os.path.basename(snapshot.path),
            "exchange",
        )
        try:
            os.write(probe_descriptor, b"exchange")
            os.fsync(probe_descriptor)
        finally:
            os.close(probe_descriptor)
        # Exercise the exact native primitive required by existing-file
        # publication and absent-file rollback before any secret-bearing
        # candidate is staged. A round trip keeps both probes private and
        # restores their cleanup identities.
        _exchange_probe_entries(
            parent_descriptor,
            temporary_name,
            exchange_probe_name,
            snapshot.path,
        )
        _exchange_probe_entries(
            parent_descriptor,
            temporary_name,
            exchange_probe_name,
            snapshot.path,
        )
        _assert_pinned_parent_public(snapshot, parent_descriptor)
    finally:
        os.close(descriptor)
        for name in (temporary_name, exchange_probe_name):
            if name:
                try:
                    os.unlink(name, dir_fd=parent_descriptor)
                except FileNotFoundError:
                    pass
        os.fsync(parent_descriptor)
        os.close(parent_descriptor)


def _preflight_atomic_replace_windows(
    snapshot: _FileSnapshot,
    *,
    metadata: _FileSnapshot | None,
) -> None:
    metadata_source = snapshot if metadata is None else metadata
    security = metadata_source.windows_security
    if security is None:
        raise OSError(errno.ENOTSUP, "Windows security metadata is unavailable")
    parent = os.path.dirname(snapshot.path) or "."
    basename = os.path.basename(snapshot.path)
    target = os.path.join(parent, f".{basename}.observability-v8-preflight-target-{uuid.uuid4().hex}.tmp")
    replacement = os.path.join(parent, f".{basename}.observability-v8-preflight-new-{uuid.uuid4().hex}.tmp")
    backup = os.path.join(parent, f".{basename}.observability-v8-preflight-old-{uuid.uuid4().hex}.tmp")
    try:
        windows_acl.write_new_file(target, b"preflight-target", security)
        windows_acl.write_new_file(replacement, b"preflight-replacement", security)
        windows_acl.replace_file(target, replacement, backup)
        published = _snapshot_regular_file(target, required=True)
        _assert_windows_staged_snapshot(published, b"preflight-replacement", security)
        retained = _snapshot_regular_file(backup, required=True)
        _assert_windows_staged_snapshot(retained, b"preflight-target", security)
        _assert_parent_identity(snapshot.path, snapshot.parent_device, snapshot.parent_inode)
    finally:
        for path in (target, replacement, backup):
            if os.path.lexists(path):
                os.unlink(path)
        _fsync_directory(parent)


def _assert_staged_metadata(candidate: _FileSnapshot, metadata: _FileSnapshot, mode: int) -> None:
    if (
        candidate.mode != mode
        or (metadata.uid is not None and candidate.uid != metadata.uid)
        or (metadata.gid is not None and candidate.gid != metadata.gid)
        or not _xattrs_match(metadata.xattrs, candidate.xattrs, not metadata.existed)
        or candidate.flags != 0
        or candidate.darwin_acl is not None
    ):
        raise OSError(errno.EPERM, "staged file metadata does not match the transaction contract")


def _apply_descriptor_metadata(
    descriptor: int,
    mode: int,
    uid: int | None,
    gid: int | None,
    *,
    xattrs: tuple[tuple[str, bytes], ...] = (),
) -> None:
    fchown = getattr(os, "fchown", None)
    if fchown is not None and uid is not None and gid is not None:
        current = os.fstat(descriptor)
        if (getattr(current, "st_uid", None), getattr(current, "st_gid", None)) != (uid, gid):
            fchown(descriptor, uid, gid)
    fchmod = getattr(os, "fchmod", None)
    if fchmod is not None:
        fchmod(descriptor, mode)
    setxattr = getattr(os, "setxattr", None)
    if xattrs and setxattr is None:
        if sys.platform != "darwin":
            raise OSError(errno.ENOTSUP, "extended attributes cannot be preserved")
        _set_darwin_xattrs(descriptor, xattrs)
    elif setxattr is not None:
        for name, value in xattrs:
            setxattr(descriptor, name, value)
    _remove_unexpected_xattrs(descriptor, frozenset(name for name, _value in xattrs))


def _remove_unexpected_xattrs(descriptor: int, expected: frozenset[str]) -> None:
    current = _read_xattrs(descriptor, "staged replacement")
    remove = getattr(os, "removexattr", None)
    for name, _value in current:
        if name in expected:
            continue
        if remove is not None:
            remove(descriptor, name)
        elif sys.platform == "darwin":
            _remove_darwin_xattr(descriptor, name)
        else:
            raise OSError(errno.ENOTSUP, "unexpected extended attributes cannot be removed")


def _remove_darwin_xattr(descriptor: int, name: str) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    fremovexattr = libc.fremovexattr
    fremovexattr.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int]
    fremovexattr.restype = ctypes.c_int
    if fremovexattr(descriptor, os.fsencode(name), 0) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def _set_darwin_xattrs(descriptor: int, xattrs: tuple[tuple[str, bytes], ...]) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    fsetxattr = libc.fsetxattr
    fsetxattr.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_uint32,
        ctypes.c_int,
    ]
    fsetxattr.restype = ctypes.c_int
    for name, value in xattrs:
        buffer = ctypes.create_string_buffer(value)
        if fsetxattr(descriptor, os.fsencode(name), buffer, len(value), 0, 0) != 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))


def _rollback(
    config: _FileSnapshot,
    environment: _FileSnapshot,
    *,
    activated_config: _ExpectedFileState,
    activated_environment: _ExpectedFileState,
) -> list[str]:
    errors: list[str] = []
    expected = (
        (config, activated_config),
        (environment, activated_environment),
    )
    for snapshot, activated in expected:
        try:
            _restore_snapshot(
                snapshot,
                activated=activated,
            )
        except BaseException:
            errors.append(snapshot.path)
    return errors


def _restore_snapshot(
    snapshot: _FileSnapshot,
    *,
    activated: _ExpectedFileState,
) -> None:
    current = _snapshot_regular_file(snapshot.path, required=False)
    if _same_restorable_state(current, snapshot):
        return
    if not _matches_expected_state(current, activated):
        raise OSError(errno.EBUSY, "rollback target changed outside the transaction")

    if snapshot.existed:
        original_mode = snapshot.mode if snapshot.mode is not None else 0o600
        _atomic_replace(
            current,
            snapshot.payload,
            default_mode=original_mode,
            metadata=snapshot,
        )
        return

    if not current.existed:
        return
    if _is_windows():
        _delete_expected_windows_file(snapshot.path, activated)
        _assert_parent_identity(snapshot.path, snapshot.parent_device, snapshot.parent_inode)
        return
    parent = os.path.dirname(snapshot.path) or "."
    parent_descriptor = _open_pinned_parent(current)
    try:
        _restore_absent_posix_target(
            current,
            parent_descriptor=parent_descriptor,
            parent=parent,
        )
    finally:
        os.close(parent_descriptor)


def _restore_absent_posix_target(
    expected: _FileSnapshot,
    *,
    parent_descriptor: int,
    parent: str,
) -> None:
    """Remove our newly-created inode without ever unlinking a raced writer."""

    target_name = os.path.basename(expected.path)
    recovery_name = _move_entry_to_recovery(
        parent_descriptor,
        target_name,
        target_path=expected.path,
    )
    if recovery_name is None:
        # An external writer removed the target before the atomic move. Its
        # chosen absent state already satisfies rollback; do not recreate it.
        _assert_pinned_parent_public(expected, parent_descriptor)
        return

    recovery_path = os.path.join(parent, recovery_name)
    try:
        retained_identity = _entry_identity_at(parent_descriptor, recovery_name)
    except BaseException:
        raise V8ActivationRollbackError(
            "rollback_incomplete",
            "rollback_delete_cas",
            target_path=expected.path,
            backup_directory=recovery_path,
        ) from None

    try:
        retained = _snapshot_regular_file_at(
            parent_descriptor,
            parent,
            recovery_name,
            required=True,
        )
    except BaseException:
        _restore_retained_external_entry(
            parent_descriptor,
            recovery_name,
            target_name,
            expected.path,
            retained_identity,
            recovery_path,
        )
        raise OSError(errno.EBUSY, "rollback target changed outside the transaction") from None

    if not _same_snapshot_identity(retained, expected):
        _restore_retained_external_entry(
            parent_descriptor,
            recovery_name,
            target_name,
            expected.path,
            retained_identity,
            recovery_path,
        )
        raise OSError(errno.EBUSY, "rollback target changed outside the transaction")

    try:
        _assert_pinned_parent_public(expected, parent_descriptor)
        # Commit target absence while the exact candidate remains recoverable
        # under its private sibling name. Cleanup after this point must never
        # reconstruct or touch a newly-created target.
        os.fsync(parent_descriptor)
    except BaseException:
        raise V8ActivationRollbackError(
            "rollback_incomplete",
            "rollback_delete_commit",
            target_path=expected.path,
            backup_directory=recovery_path,
        ) from None

    try:
        if _entry_identity_at(parent_descriptor, recovery_name) != retained_identity:
            raise OSError(errno.EBUSY, "rollback recovery entry changed outside the transaction")
        os.unlink(recovery_name, dir_fd=parent_descriptor)
    except FileNotFoundError:
        return
    except BaseException:
        raise V8ActivationRollbackError(
            "rollback_incomplete",
            "rollback_delete_cleanup",
            target_path=expected.path,
            backup_directory=recovery_path,
        ) from None
    # Target absence was durably committed while this exact recovery entry
    # still existed. Once unlink succeeds there is no recovery path to report;
    # a crash may at worst resurrect that private sibling, never the target.


def _move_entry_to_recovery(
    parent_descriptor: int,
    source_name: str,
    *,
    target_path: str,
) -> str | None:
    for _ in range(128):
        recovery_name = f".{source_name}.observability-v8-rollback-{uuid.uuid4().hex}.tmp"
        try:
            _rename_entry_no_replace(
                parent_descriptor,
                source_name,
                recovery_name,
                target_path,
            )
        except FileExistsError:
            continue
        except FileNotFoundError:
            return None
        return recovery_name
    raise OSError(errno.EEXIST, "unable to allocate a private rollback recovery name")


def _entry_identity_at(parent_descriptor: int, name: str) -> tuple[int, int, int]:
    info = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    return info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode)


def _restore_retained_external_entry(
    parent_descriptor: int,
    recovery_name: str,
    target_name: str,
    target_path: str,
    retained_identity: tuple[int, int, int],
    recovery_path: str,
) -> None:
    """Restore a raced entry or retain its exact recovery name on ambiguity."""

    try:
        _rename_entry_no_replace(
            parent_descriptor,
            recovery_name,
            target_name,
            target_path,
        )
    except BaseException:
        raise V8ActivationRollbackError(
            "rollback_incomplete",
            "rollback_external_restore",
            target_path=target_path,
            backup_directory=recovery_path,
        ) from None
    try:
        os.fsync(parent_descriptor)
        if _entry_identity_at(parent_descriptor, target_name) != retained_identity:
            raise OSError(errno.EBUSY, "restored external entry changed outside the transaction")
    except BaseException:
        raise V8ActivationRollbackError(
            "rollback_incomplete",
            "rollback_external_restore",
            target_path=target_path,
            backup_directory=target_path,
        ) from None


def _same_restorable_state(current: _FileSnapshot, original: _FileSnapshot) -> bool:
    if current.existed != original.existed:
        return False
    if not current.existed:
        return True
    return (
        current.sha256 == original.sha256
        and current.mode == original.mode
        and current.uid == original.uid
        and current.gid == original.gid
        and current.parent_device == original.parent_device
        and current.parent_inode == original.parent_inode
        and current.xattrs == original.xattrs
        and current.windows_security == original.windows_security
        and current.flags == original.flags
        and current.darwin_acl == original.darwin_acl
    )


def _activated_file_state(
    original: _FileSnapshot,
    *,
    existed: bool,
    sha256: str | None,
    default_mode: int,
    metadata: _FileSnapshot | None = None,
) -> _ExpectedFileState:
    if not existed:
        return _ExpectedFileState(False, None, None, None, None, (), False, None)
    metadata_source = original if metadata is None else metadata
    uid = metadata_source.uid
    gid = metadata_source.gid
    if not original.existed and metadata is None:
        getuid = getattr(os, "getuid", None)
        getgid = getattr(os, "getgid", None)
        uid = getuid() if getuid is not None else None
        gid = getgid() if getgid is not None else None
    windows_security = metadata_source.windows_security
    if _is_windows() and not original.existed and windows_security is not None:
        windows_security = windows_security.staging_copy()
    return _ExpectedFileState(
        existed=True,
        sha256=sha256,
        mode=None if _is_windows() else (metadata_source.mode if metadata_source.mode is not None else default_mode),
        uid=uid,
        gid=gid,
        xattrs=metadata_source.xattrs,
        allow_platform_xattrs=not metadata_source.existed,
        windows_security=windows_security,
        flags=None if _is_windows() else 0,
        darwin_acl=None,
    )


def _matches_expected_state(current: _FileSnapshot, expected: _ExpectedFileState) -> bool:
    return (
        current.existed == expected.existed
        and current.sha256 == expected.sha256
        and (expected.mode is None or current.mode == expected.mode)
        and (expected.uid is None or current.uid == expected.uid)
        and (expected.gid is None or current.gid == expected.gid)
        and _xattrs_match(expected.xattrs, current.xattrs, expected.allow_platform_xattrs)
        and current.windows_security == expected.windows_security
        and (expected.flags is None or current.flags == expected.flags)
        and current.darwin_acl == expected.darwin_acl
    )


def _xattrs_match(
    expected: tuple[tuple[str, bytes], ...],
    actual: tuple[tuple[str, bytes], ...],
    allow_platform_xattrs: bool,
) -> bool:
    if actual == expected:
        return True
    if not allow_platform_xattrs or sys.platform != "darwin":
        return False
    expected_map = dict(expected)
    actual_map = dict(actual)
    return all(
        name in {"com.apple.provenance"} or expected_map.get(name) == value for name, value in actual_map.items()
    ) and all(actual_map.get(name) == value for name, value in expected_map.items())


def _assert_private_file_parent_trust(target: str, owner_root: str, trusted_uids: frozenset[int]) -> None:
    _assert_secure_parent_chain(target, trusted_uids)
    _assert_no_inheritable_read_acl(owner_root)


def update_private_file(
    path: str | os.PathLike[str],
    *,
    owner_directory: str | os.PathLike[str],
    transform: PrivateFileTransform,
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Safely read, transform, flush, and atomically publish one private file.

    The transform runs under the sibling lock against the exact snapshotted
    bytes. Returning ``None`` performs a validated read without publication.
    Existing owner and authorization metadata are retained while POSIX mode is
    tightened to ``0600``. New files inherit the validated data-directory owner
    and a private native Windows DACL before their first payload byte is written.
    Windows flushes the staged and published file objects and requests native
    write-through moves, but does not claim unsupported directory-entry fsync.
    """

    target = _absolute_path(os.fspath(path))
    owner_root = _absolute_path(os.fspath(owner_directory))
    # macOS exposes /var through one stable root-owned system alias. Normalize
    # only that exact alias; arbitrary data-dir and intermediate symlinks must
    # remain visible to the strict parent-chain lstat checks below.
    owner_root = _resolve_darwin_var_alias(owner_root)
    target = os.path.join(
        _resolve_darwin_var_alias(os.path.dirname(target) or "."),
        os.path.basename(target),
    )
    if not _same_path(os.path.dirname(target) or ".", owner_root):
        raise V8ActivationError("path_mismatch", "private_file_update", target_path=target)

    env = os.environ if environment is None else environment
    trusted_owners = _trusted_owner_pairs(env)
    trusted_uids = _trusted_owner_ids(target, owner_root, env)
    _assert_private_file_parent_trust(target, owner_root, trusted_uids)

    with locked_file_update(target):
        snapshot = _snapshot_regular_file(target, required=False)
        _assert_private_file_parent_trust(target, owner_root, trusted_uids)
        _assert_leaf_owner(snapshot, trusted_owners)
        if _is_windows() and snapshot.existed:
            try:
                if snapshot.windows_security is None:
                    raise windows_acl.WindowsAclError("private file DACL is unavailable")
                windows_acl.assert_not_broadly_readable(snapshot.windows_security)
            except windows_acl.WindowsAclError:
                raise V8ActivationError(
                    "environment_permissions_unsafe",
                    "private_file_update",
                    target_path=target,
                ) from None

        candidate = transform(snapshot.payload)
        if candidate is None:
            if not _is_windows() and snapshot.existed and snapshot.mode is not None and snapshot.mode & 0o044:
                raise V8ActivationError(
                    "environment_permissions_unsafe",
                    "private_file_update",
                    target_path=target,
                )
            _assert_private_file_parent_trust(target, owner_root, trusted_uids)
            return False
        if not isinstance(candidate, bytes):
            raise TypeError("private-file transform must return bytes or None")

        if snapshot.existed:
            metadata = snapshot if _is_windows() else replace(snapshot, mode=0o600)
        else:
            metadata = _new_environment_metadata(snapshot, owner_root, env)

        _preflight_atomic_replace(snapshot, default_mode=0o600, metadata=metadata)
        _assert_private_file_parent_trust(target, owner_root, trusted_uids)
        expected = _activated_file_state(
            snapshot,
            existed=True,
            sha256=_sha256(candidate),
            default_mode=0o600,
            metadata=metadata,
        )
        try:
            _atomic_replace(snapshot, candidate, default_mode=0o600, metadata=metadata)
            _assert_expected_file_state(target, expected)
            _assert_private_file_parent_trust(target, owner_root, trusted_uids)
        except V8ActivationRollbackError:
            # A rollback-incomplete error carries the retained recovery path.
            # Reconstructing the old snapshot here could clobber the external
            # writer whose inode was deliberately preserved there.
            raise
        except BaseException:
            try:
                _restore_private_file_update(snapshot, expected)
            except V8ActivationRollbackError:
                raise
            except BaseException:
                if _is_windows():
                    raise _windows_rollback_incomplete(
                        "private_file_update",
                        target,
                        target,
                    ) from None
                raise V8ActivationRollbackError(
                    "rollback_incomplete",
                    "private_file_update",
                    target_path=target,
                ) from None
            raise
        return True


def _resolve_darwin_var_alias(path: str) -> str:
    if sys.platform != "darwin":
        return path
    normalized = os.path.normpath(path)
    if normalized != "/var" and not normalized.startswith("/var/"):
        return path
    try:
        alias = os.lstat("/var")
    except OSError:
        return path
    if (
        not stat.S_ISLNK(alias.st_mode)
        or getattr(alias, "st_uid", None) != 0
        or os.path.realpath("/var") != "/private/var"
    ):
        return path
    return "/private/var" + normalized[len("/var") :]


def _restore_private_file_update(original: _FileSnapshot, expected: _ExpectedFileState) -> None:
    """Restore our published candidate, but never clobber an external writer."""

    current = _snapshot_regular_file(original.path, required=False)
    if _same_restorable_state(current, original):
        return
    if not _matches_expected_state(current, expected):
        return
    _restore_snapshot(original, activated=expected)
    restored = _snapshot_regular_file(original.path, required=False)
    if not _same_restorable_state(restored, original):
        raise OSError(errno.EIO, "private-file rollback did not restore the original state")


def _fsync_directory(path: str) -> None:
    if os.name == "nt":
        return
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _inject_fault(
    injector: FaultInjector | None,
    stage: str,
    *,
    backup_directory: str | None = None,
) -> None:
    if injector is None:
        return
    try:
        injector(stage)
    except Exception:
        raise V8ActivationError(
            "injected_failure",
            stage,
            backup_directory=backup_directory,
        ) from None


__all__ = [
    "CandidateValidator",
    "PrivateFileTransform",
    "V8ActivationError",
    "V8ActivationResult",
    "V8ActivationRollbackError",
    "activate_v8_migration",
    "resolve_active_config_path",
    "update_private_file",
]
