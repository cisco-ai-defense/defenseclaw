# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Files a removed managed (enterprise) DefenseClaw left in a per-user data folder.

On Windows the managed install runs as LocalSystem and writes its per-user
runtime into each enrolled account's ``%USERPROFILE%\\.defenseclaw`` with
the managed access list (LocalSystem and Administrators full control, the
account Modify, a read-only OWNER RIGHTS entry). An uninstall from before
1.0.8 kept those files, and a later per-user install of the same account
failed its first run: the hook contract lock was "not protected", so no
rollback point could be taken (cowork-1-0-8 GAP-0045).

The first run of a per-user install with no configuration yet moves those
files, and only those, to a dated folder beside the data folder before it
takes its rollback point. It never reads them, so nothing in them is trusted
or restored. Nothing moves while a managed deployment is installed, once a
per-user configuration exists, for an entry another account could have
written, or for one with only the profile's own access list.
"""

from __future__ import annotations

import os
import stat
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone

# What the managed runtime and its hooks write into an account's folder
# (windowsManagedUserRuntimeEntries in
# internal/enterprisehooks/managed_user_runtime_windows.go), plus the hooks
# the foreign-hook policy moved aside and the connector backup records. The
# per-user installer writes logs\ too, so only the hook's failure log moves
# from there.
MANAGED_ENTRIES = (
    "hook_contract_lock.json",
    "hook_contract_lock.json.lock",
    "hooks",
    "foreign-hook-env.json",
    "foreign-hook-sessions",
    "foreign-hooks-backup",
    "connector_backups",
    "agent_selection.json",
    "agent_selection.json.lock",
    ".hook-api-token-publish.lock",
    ".hermes-lifecycle.lock",
    "kiro-created-dirs.json",
    "inventory.db",
    "inventory.db-journal",
    "inventory.db-shm",
    "inventory.db-wal",
    "model_usage",
    os.path.join("logs", "hook-failures.jsonl"),
)

# A per-user install that ran its first run keeps one of these; then the
# folder is that install's, and nothing moves.
PER_USER_STATE = ("config.yaml", ".env", "audit.db")

BACKUP_PREFIX = ".defenseclaw-managed-leftovers-"


@dataclass(frozen=True)
class SetAside:
    """Where the managed leftovers went, and which entries moved."""

    backup_dir: str
    entries: tuple[str, ...]

    def detail(self, data_dir: str) -> str:
        return (
            f"moved {', '.join(self.entries)} out of {data_dir} to {self.backup_dir}: "
            "a managed (enterprise) DefenseClaw that was removed from this computer left them. "
            "They are not used; delete that folder when you no longer need it."
        )


def _is_windows() -> bool:
    return os.name == "nt"


def _managed_deployment() -> str | None:
    from defenseclaw.upgrade_shim import managed_deployment

    return managed_deployment()


# The field lock the managed runtime puts on what it writes into an
# account's folder (windowsUserPathCanonicalACEs in
# internal/enterprisehooks/install_windows.go): LocalSystem and
# Administrators full control, the account Modify (never the right to change
# the access list or take ownership), and a read-only OWNER RIGHTS entry. A
# file the runtime created in such a folder carries the same grants without
# the OWNER RIGHTS entry (foreign-hook-env.json, logs\hook-failures.jsonl).
# A profile's own access list grants the account full control, so an entry
# that only inherited it is never the managed install's.
_ADMINISTRATORS = "S-1-5-32-544"
_OWNER_RIGHTS = "S-1-3-4"
_FILE_ALL_ACCESS = 0x001F01FF
_GENERIC_ALL = 0x10000000
_WRITE_RIGHTS = _GENERIC_ALL | 0x40000000 | 0x000D0156  # GENERIC_WRITE, WRITE_DAC/OWNER, DELETE, data
_CHANGE_ACCESS = _GENERIC_ALL | 0x00040000 | 0x00080000  # WRITE_DAC, WRITE_OWNER
_INHERIT_ONLY_ACE = 0x08


def field_locked(entries: list[tuple[int, int, int, str]], account_sid: str) -> bool:
    """Whether a DACL (``_windows_acl_snapshot`` entries) is the managed field lock.

    Administrators hold full control; the account may write but not change
    the access list or take ownership; an OWNER RIGHTS entry, if any, is
    read-only. Inherit-only entries do not apply to the object itself.
    """
    admins_full = account_writes = False
    for mask, access_mode, flags, sid in entries:
        if access_mode != 1 or flags & _INHERIT_ONLY_ACE:
            continue
        if sid == _ADMINISTRATORS and (mask & _GENERIC_ALL or mask & _FILE_ALL_ACCESS == _FILE_ALL_ACCESS):
            admins_full = True
        if sid == account_sid:
            if mask & _CHANGE_ACCESS:
                return False
            account_writes = account_writes or bool(mask & _WRITE_RIGHTS)
        if sid == _OWNER_RIGHTS and mask & _WRITE_RIGHTS:
            return False
    return admins_full and account_writes


def managed_custody(path: str) -> bool:
    """Whether *path* is held the way the managed install leaves it.

    Only this account, LocalSystem, Administrators or TrustedInstaller can
    write it, and its access list is the managed field lock
    (:func:`field_locked`). An entry another account could write, or one
    with the profile's plain access list, is not DefenseClaw's managed
    custody and is left alone (cowork-1-0-8 GAP-0069).
    """
    from defenseclaw.file_permissions import (
        _windows_acl_snapshot,
        _windows_current_user_sid,
        windows_acl_custody_write_error,
    )

    if windows_acl_custody_write_error(path, allow_current_user=True) is not None:
        return False
    try:
        # A null DACL has no entries, so it is never the field lock.
        _owner, _null_dacl, entries = _windows_acl_snapshot(os.fspath(path))
        account_sid = _windows_current_user_sid()
    except OSError:
        return False
    return bool(account_sid) and field_locked(entries, account_sid)


def _plain_entry(path: str) -> bool:
    try:
        info = os.lstat(path)
    except OSError:
        return False
    if stat.S_ISLNK(info.st_mode):
        return False
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    if getattr(info, "st_file_attributes", 0) & reparse:
        return False
    return stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)


def find_managed_leftovers(
    data_dir: str,
    *,
    custody: Callable[[str], bool] | None = None,
) -> list[str]:
    """Name the managed leftovers in *data_dir* a first run may move, or []."""
    if not _is_windows():
        return []
    data_dir = os.path.abspath(os.fspath(data_dir))
    if not _plain_entry(data_dir) or not os.path.isdir(data_dir):
        return []
    if any(os.path.lexists(os.path.join(data_dir, name)) for name in PER_USER_STATE):
        return []
    if _managed_deployment():
        return []
    custody = custody or managed_custody
    found = []
    for name in MANAGED_ENTRIES:
        path = os.path.join(data_dir, name)
        if _plain_entry(path) and custody(path):
            found.append(name)
    return found


def set_aside_managed_leftovers(
    data_dir: str,
    *,
    custody: Callable[[str], bool] | None = None,
    now: datetime | None = None,
) -> SetAside | None:
    """Move the managed leftovers out of *data_dir*, or return None.

    Raises OSError naming the exact remediation when an entry cannot move.
    """
    names = find_managed_leftovers(data_dir, custody=custody)
    if not names:
        return None
    data_dir = os.path.abspath(os.fspath(data_dir))
    stamp = (now or datetime.now(timezone.utc)).strftime("%Y%m%dT%H%M%SZ")
    base = os.path.join(os.path.dirname(data_dir), BACKUP_PREFIX + stamp)
    backup_dir = base
    for suffix in range(1, 100):
        try:
            os.mkdir(backup_dir, 0o700)
            break
        except FileExistsError:
            backup_dir = f"{base}-{suffix}"
    else:
        raise OSError(f"could not create a folder beside {data_dir} for the files a removed managed DefenseClaw left")
    moved: list[str] = []
    for name in names:
        source = os.path.join(data_dir, name)
        target = os.path.join(backup_dir, name)
        try:
            os.makedirs(os.path.dirname(target), exist_ok=True)
            os.rename(source, target)
        except OSError as exc:
            raise OSError(
                f"{source} was left by a managed (enterprise) DefenseClaw that was removed, and it could not be moved "
                f"aside ({exc.strerror or exc}). Move it out of {data_dir} (for example to {backup_dir}), "
                "or ask an administrator to delete it, then run: defenseclaw init"
            ) from None
        moved.append(name)
    return SetAside(backup_dir=backup_dir, entries=tuple(moved))
