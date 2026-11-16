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

"""Cross-platform file-permission helpers for secret-bearing writes."""

from __future__ import annotations

import contextlib
import errno
import os
import shlex
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from collections.abc import Callable, Iterable
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import TYPE_CHECKING, TextIO

if TYPE_CHECKING:
    from defenseclaw.windows_acl import WindowsFileSecurity

# Stable UnsafePathError.code values. Add a constant rather than a new bare
# string so every consumer's match stays exhaustive and greppable.
UNSAFE_PATH_UNKNOWN = "unsafe-path-unknown"
UNSAFE_PATH_NOT_REGULAR_FILE = "unsafe-path-not-regular-file"
UNSAFE_PATH_SYMLINK_OR_REPARSE = "unsafe-path-symlink-or-reparse"
UNSAFE_PATH_EXCEEDS_LIMIT = "unsafe-path-exceeds-limit"
UNSAFE_PATH_CHANGED = "unsafe-path-changed"
UNSAFE_PATH_UNTRUSTED_CUSTODY = "unsafe-path-untrusted-custody"
UNSAFE_PATH_NOT_ABSOLUTE = "unsafe-path-not-absolute"
UNSAFE_PATH_INSPECTION_FAILED = "unsafe-path-inspection-failed"
# The owner is hidden by the user namespace this process runs in (an agent's
# sandbox): it is not known to be another account, it cannot be checked here.
UNSAFE_PATH_NAMESPACE_VIEW = "unsafe-path-namespace-view"

_tracked_host_stat_lock = threading.Lock()

# The local account records are checked alongside NSS before a group is
# considered private. Tests replace these paths with isolated account data.
_PASSWD_FILE = "/etc/passwd"
_GROUP_FILE = "/etc/group"


def _account_records(path: str) -> list[list[str]] | None:
    try:
        with open(path, encoding="utf-8", errors="strict") as handle:
            lines = handle.read().splitlines()
    except (OSError, UnicodeDecodeError):
        return None
    records = []
    for line in lines:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line.startswith(("+", "-")):
            return None
        records.append(line.split(":"))
    return records


def _has_access_acl(path: str) -> bool:
    """Treat an unreadable ACL as present; group mode bits can be its mask."""
    getxattr = getattr(os, "getxattr", None)
    if getxattr is None:
        return True
    for attribute in ("system.posix_acl_access", "system.nfs4_acl", "system.nfs4acl"):
        try:
            getxattr(path, attribute, follow_symlinks=False)
        except OSError as exc:
            if exc.errno in (errno.ENODATA, errno.ENOTSUP, getattr(errno, "ENOATTR", errno.ENODATA)):
                continue
            return True
        return True
    return False


def owner_private_group(path: str, info: os.stat_result) -> bool:
    """Whether a Linux path is owned by this account and its private group."""
    if not sys.platform.startswith("linux") or os.name == "nt":
        return False
    uid, gid = os.geteuid(), info.st_gid
    try:
        target = os.path.realpath(path)
        resolved = os.stat(target)
    except OSError:
        return False
    if (resolved.st_dev, resolved.st_ino) != (info.st_dev, info.st_ino):
        return False
    if info.st_uid != uid or _has_access_acl(target):
        return False
    passwd = _account_records(_PASSWD_FILE)
    groups = _account_records(_GROUP_FILE)
    if passwd is None or groups is None:
        return False
    try:
        owners = [rec for rec in passwd if len(rec) >= 4 and int(rec[2]) == uid]
        if len(owners) != 1:
            return False
        name = owners[0][0]
        if not name:
            return False
        for rec in passwd:
            if len(rec) < 4:
                return False
            record_uid, record_gid = int(rec[2]), int(rec[3])
            if record_gid == gid and record_uid != uid:
                return False
            if rec[0] == name and (record_uid != uid or record_gid != gid):
                return False
        matches = [rec for rec in groups if len(rec) >= 4 and int(rec[2]) == gid]
    except ValueError:
        return False
    if not matches:
        return False
    for rec in matches:
        members = {member.strip() for member in rec[3].split(",") if member.strip()}
        if rec[0] != name or not members <= {name}:
            return False
    try:
        import grp
        import pwd

        account = pwd.getpwuid(uid)
        group = grp.getgrgid(gid)
    except (ImportError, KeyError, OSError):
        return False
    return account.pw_name == name and account.pw_gid == gid and group.gr_name == name and set(group.gr_mem) <= {name}


_ACL_USER_OBJ, _ACL_USER, _ACL_GROUP_OBJ, _ACL_GROUP, _ACL_MASK, _ACL_OTHER = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20
_ACL_WRITE = 0x02


def _plugin_trusted_owner(uid: int) -> bool:
    """The gateway's trusted owners for a plugin folder: root, this account, the service account."""
    if trusted_runtime_owner(uid):
        return True
    try:
        import pwd
    except ImportError:
        return False
    for name in ("defenseclaw", "_defenseclaw") if sys.platform == "darwin" else ("defenseclaw",):
        try:
            if pwd.getpwnam(name).pw_uid == uid:
                return True
        except (KeyError, OSError):
            continue
    return False


def plugin_owner_untrusted(info: os.stat_result) -> bool:
    """True when the owner is not one the gateway accepts for a plugin folder or file."""
    return not _plugin_trusted_owner(info.st_uid)


def _plugin_darwin_acl_refused(path: str) -> bool:
    """The gateway's macOS ACL rule for a plugin folder or file (hook_api_acl_darwin.go).

    The standalone managed profile refuses any allow entry with a write-class
    right. Every other scope (a per-user install, Secure Client) refuses only
    an effective allow entry with a write-class right for a principal other
    than root, wheel and admin, and leaves read, deny, inherit-only and those
    trusted entries alone. An ACL that cannot be read, or an entry that cannot
    be parsed, is a refusal in both: the gateway strict parser refuses the same
    entry. Asking the stricter rule everywhere would warn about, and make setup
    refuse, a folder the gateway accepts.
    """
    mode_field, acl_text = _darwin_acl_output(
        path, timeout=_PLUGIN_ACL_INSPECTION_TIMEOUT, attempts=_PLUGIN_ACL_INSPECTION_ATTEMPTS
    )
    if not mode_field:
        return True
    if not acl_text:
        return "+" in mode_field
    standalone = _plugin_standalone_scope()
    for raw_line in acl_text.splitlines():
        index, colon, entry = raw_line.strip().lower().partition(":")
        if not colon or not index.isdigit():
            continue
        fields = entry.split()
        verb = next((i for i, field in enumerate(fields) if field in ("allow", "deny")), -1)
        if verb < 1 or verb + 1 >= len(fields):
            return True
        if fields[verb] != "allow":
            continue
        rights = set(fields[verb + 1].split(","))
        if standalone:
            if rights & _DARWIN_ACL_WRITE_PERMISSIONS:
                return True
        elif (
            fields[0] not in _DARWIN_ACL_TRUSTED_PRINCIPALS
            and rights & _DARWIN_ACL_WRITE_PERMISSIONS
            and "only_inherit" not in rights
        ):
            return True
    return False


def _plugin_standalone_scope() -> bool:
    """Whether the gateway on this host judges by the standalone managed profile."""
    try:
        from defenseclaw.envvars import managed_standalone

        return managed_standalone()
    except (ImportError, OSError, ValueError, RuntimeError):
        return False


def plugin_acl_refused(path: str) -> bool:
    """True when the gateway's ACL rule would refuse *path* (hook_api_acl_{linux,darwin}.go).

    macOS: the rule of the gateway's trust scope (see
    :func:`_plugin_darwin_acl_refused`). Linux: an NFSv4 ACL, an
    unreadable or incomplete POSIX ACL, or a POSIX ACL whose effective write
    belongs to a group, to other, or to a named user that is not trusted.
    """
    if sys.platform == "darwin":
        return _plugin_darwin_acl_refused(path)
    getxattr = getattr(os, "getxattr", None)
    if getxattr is None:
        return False
    absent = (errno.ENODATA, errno.ENOTSUP, getattr(errno, "ENOATTR", errno.ENODATA))
    for attribute in ("system.nfs4_acl", "system.nfs4acl"):
        try:
            getxattr(path, attribute)
        except OSError as exc:
            if exc.errno in absent:
                continue
        return True
    try:
        data = getxattr(path, "system.posix_acl_access")
    except OSError as exc:
        return exc.errno not in absent
    if len(data) < 4 or struct.unpack_from("<I", data)[0] != 2 or (len(data) - 4) % 8:
        return True
    entries = [struct.unpack_from("<HHI", data, offset) for offset in range(4, len(data), 8)]
    tags = [tag for tag, _, _ in entries]
    named = any(tag in (_ACL_USER, _ACL_GROUP) for tag in tags)
    if (
        tags.count(_ACL_USER_OBJ) != 1
        or tags.count(_ACL_GROUP_OBJ) != 1
        or tags.count(_ACL_OTHER) != 1
        or tags.count(_ACL_MASK) > 1
        or (named and tags.count(_ACL_MASK) != 1)
    ):
        return True
    mask = next((perm for tag, perm, _ in entries if tag == _ACL_MASK), 0x7)
    for tag, perm, uid in entries:
        if tag in (_ACL_USER, _ACL_GROUP_OBJ, _ACL_GROUP):
            perm &= mask
        elif tag not in (_ACL_USER_OBJ, _ACL_OTHER, _ACL_MASK):
            return True
        if not perm & _ACL_WRITE:
            continue
        if tag == _ACL_USER and not _plugin_trusted_owner(uid):
            return True
        if tag in (_ACL_GROUP_OBJ, _ACL_GROUP, _ACL_OTHER):
            return True
    return False


def plugin_link_refused(path: str, info: os.stat_result, *, leaf: bool) -> bool:
    """True when the gateway's folder walk refuses the link *path*.

    The plugin folder itself is never a link; an ancestor may be one only when
    it is a root-owned system link (a macOS root alias, or a link inside a
    root-owned private parent) that leads to a folder.
    """
    if not leaf:
        alias = sys.platform == "darwin" and os.path.normpath(path) in ("/etc", "/tmp", "/var")
        if not alias and info.st_uid == 0:
            try:
                parent = os.lstat(os.path.dirname(path))
            except OSError:
                parent = None
            alias = (
                parent is not None
                and stat.S_ISDIR(parent.st_mode)
                and not parent.st_mode & 0o022
                and parent.st_uid == 0
            )
        if alias:
            return not os.path.isdir(path)
    return True


def other_accounts_can_write(path: str, info: os.stat_result) -> bool:
    """Check other-write and group-write after proving a private group."""
    mode = stat.S_IMODE(info.st_mode)
    if mode & 0o002:
        return True
    return bool(mode & 0o020) and not owner_private_group(path, info)


def tracked_host_owner_uid(path: str | os.PathLike[str], info: os.stat_result) -> int:
    """Recover a file's host UID inside a tracked scanner's user namespace.

    An unmapped owner appears as 65534 there. The scanner launcher, which is
    outside that namespace, checks the same inode and reports its actual UID.
    Missing or mismatched evidence is refused even when the scanner itself
    uses the overflow UID. This channel is present only in the PID-1 scanner.
    """
    owner = info.st_uid
    if sys.platform != "linux" or owner != 65534:
        return owner
    # The overflow UID can also equal the scanner's own UID. Without host
    # evidence, accepting it would trust an unmapped file owner.
    if os.getpid() != 1:
        return -1
    raw = os.fsencode(path)
    if not raw or len(raw) > 4096:
        return -1
    nonce = os.urandom(8)
    request = struct.pack("!QQ", info.st_dev, info.st_ino) + nonce + struct.pack("!H", len(raw)) + raw
    channel = tracked_host_stat_channel()
    if channel is None:
        return -1
    try:
        with _tracked_host_stat_lock, channel:
            channel.settimeout(2.0)
            channel.sendall(request)
            response = channel.recv(12)
        if len(response) != 12 or response[:8] != nonce:
            return -1
        reported = struct.unpack("!I", response[8:])[0]
        return -1 if reported == 0xFFFFFFFF else reported
    except OSError:
        return -1


def namespace_hides_owner(info: os.stat_result) -> bool:
    """True when *info*'s owner is only the overflow UID of this user namespace.

    Inside an unprivileged user namespace (the workspace sandbox an agent such
    as Codex runs its tools in) every host account outside the namespace's UID
    map, root included, shows as the kernel's overflow UID. Such an owner is
    unknown, not another account (GAP-1395).
    """
    if not in_child_user_namespace():
        return False
    try:
        with open("/proc/sys/kernel/overflowuid", encoding="ascii") as handle:
            overflow = int(handle.read().strip())
    except (OSError, ValueError):
        return False
    return info.st_uid == overflow


def in_child_user_namespace() -> bool:
    """True when this process runs in a user namespace other than the host's.

    That is the workspace sandbox an agent such as Codex runs its tools in: it
    hides host accounts, and usually the host's processes and network too.
    """
    if sys.platform != "linux":
        return False
    try:
        with open("/proc/self/uid_map", encoding="ascii") as handle:
            uid_map = handle.read().split()
    except OSError:
        return False
    # The initial namespace maps every UID onto itself in one range.
    return bool(uid_map) and uid_map != ["0", "0", "4294967295"]


def _namespace_view_error(path: Path | str, resolved: str) -> UnsafePathError:
    what = f"the gateway executable {resolved}"
    if str(path) != resolved:
        what = f"{path}, which holds {what},"
    return UnsafePathError(
        f"the owner of {what} cannot be checked here: "
        "this command runs inside a sandbox (a user namespace) that hides it, so DefenseClaw did not "
        "run the gateway's checks. Nothing needs changing; run the command outside the sandbox to check",
        code=UNSAFE_PATH_NAMESPACE_VIEW,
    )


def tracked_host_stat_channel() -> socket.socket | None:
    """The scanner launcher's host-owner channel on fd 5, or None.

    The environment variable only names the descriptor; the process and the
    socket must prove it. The process runs in a PID namespace other than the
    host's, and fd 5 is a connected AF_UNIX SOCK_SEQPACKET socket whose peer
    runs as this user outside that namespace, so the kernel reports the peer's
    PID as 0. Every other socket on fd 5 (TCP, UDP, a stream or a socketpair of
    this process) is refused before a request is sent.
    """
    if sys.platform != "linux" or os.environ.get("DEFENSECLAW_TRACKED_HOST_STAT_FD") != "5":
        return None
    if not _in_child_pid_namespace():
        return None
    try:
        channel = socket.socket(fileno=os.dup(5))
    except OSError:
        return None
    try:
        if channel.family != socket.AF_UNIX or channel.type != socket.SOCK_SEQPACKET:
            raise OSError("not the launcher's socket")
        credentials = channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("iII"))
        pid, uid, gid = struct.unpack("iII", credentials)
        if pid != 0 or uid != os.geteuid() or gid != os.getegid():
            raise OSError("not the launcher's socket")
    except OSError:
        channel.close()
        return None
    return channel


def _in_child_pid_namespace() -> bool:
    """True when this process has a PID in more than one PID namespace."""
    try:
        with open("/proc/self/status", encoding="ascii", errors="replace") as status:
            for line in status:
                if line.startswith("NSpid:"):
                    return len(line.split()) > 2
    except OSError:
        return False
    return False


class UnsafePathError(OSError):
    """Raised when a sensitive path fails a custody or stability check.

    ``code`` is the stable, machine-readable reason. Callers that must map a
    refusal onto their own vocabulary (Doctor turns these into PID-record
    evidence statuses, and the distinction between "malformed" and
    "unavailable" changes which repairs are allowed to run) branch on it
    instead of matching the human-readable message, so rewording a message
    cannot silently reclassify a security refusal.
    """

    def __init__(self, message: str, *, code: str = UNSAFE_PATH_UNKNOWN) -> None:
        super().__init__(message)
        self.code = code


def unsafe_gateway_remedy(exc: UnsafePathError) -> str:
    """The refusal plus a fix, without repeating one it already names."""
    if "chmod go-w" in str(exc) or getattr(exc, "code", "") == UNSAFE_PATH_NAMESPACE_VIEW:
        return str(exc)
    return f"{exc}; fix its owner and mode (chmod go-w) or reinstall DefenseClaw"


MAX_DOTENV_BYTES = 1024 * 1024


def trusted_runtime_owner(st_uid: int, *, current_uid: int | None = None) -> bool:
    """True when *st_uid* may hold a self-managed ~/.defenseclaw runtime file.

    Root may access root-owned files and files owned by the validated sudo
    invoker. Merely running as root never makes an arbitrary UID trusted.
    Group/other-writable bits are a separate check.
    """

    if current_uid is None:
        geteuid = getattr(os, "geteuid", None)
        current_uid = geteuid() if callable(geteuid) else st_uid
    if st_uid in {0, current_uid}:
        return True
    if current_uid != 0:
        return False
    getuid = getattr(os, "getuid", None)
    real_uid = getuid() if callable(getuid) else 0
    if real_uid > 0 and st_uid == real_uid:
        return True
    sudo_uid = _validated_sudo_uid()
    return sudo_uid is not None and st_uid == sudo_uid


def _validated_sudo_uid() -> int | None:
    """Return the sudo invoker UID only when account identity agrees."""

    if os.name != "posix" or not hasattr(os, "geteuid") or os.geteuid() != 0:
        return None
    raw_uid = os.environ.get("SUDO_UID", "")
    raw_gid = os.environ.get("SUDO_GID", "")
    sudo_user = os.environ.get("SUDO_USER", "")
    if not raw_uid.isdecimal() or not raw_gid.isdecimal() or not sudo_user:
        return None
    uid = int(raw_uid)
    gid = int(raw_gid)
    if str(uid) != raw_uid or str(gid) != raw_gid or uid == 0:
        return None
    try:
        import pwd

        account = pwd.getpwnam(sudo_user)
    except (ImportError, KeyError, OSError):
        return None
    if account.pw_uid != uid or account.pw_gid != gid:
        return None
    return uid


def root_owned_private_regular_file(path: str | os.PathLike[str]) -> bool:
    """True when *path* is a private regular file owned by root.

    ``lstat`` works without read access, so first-run and Doctor can name a
    sudo leftover instead of calling the file unavailable.
    """

    if os.name == "nt" or not hasattr(os, "geteuid"):
        return False
    try:
        current_uid = os.geteuid()
        info = os.lstat(path)
    except OSError:
        return False
    if current_uid == 0 or info.st_uid != 0:
        return False
    return bool(stat.S_ISREG(info.st_mode) and not (stat.S_IMODE(info.st_mode) & 0o077))


# Files a sudo-started self-managed gateway writes into ~/.defenseclaw.
# Doctor and first-run name these leftovers instead of calling them unavailable.
SUDO_RUNTIME_LEFTOVER_NAMES: tuple[str, ...] = (
    "gateway.pid",
    "watchdog.pid",
    "hook_contract_lock.json",
    "active_connector.json",
    "ai_discovery_state.json",
    "application_protection_state.json",
    "redaction-correlation.key",
    "device.key",
    "device.key.provenance",
)


# The data directory itself, named in the start blockers below when root owns
# it and this account cannot use it (a moved store left root-owned 0700).
STORE_DIR_ENTRY = "./"


def _root_owned_runtime_files(
    data_dir: str | os.PathLike[str],
    names: tuple[str, ...],
    *,
    private_only: bool,
    hooks: bool = True,
) -> list[tuple[str, bool]]:
    """``(relative path, group/other bits set)`` of root-owned files under *data_dir*.

    ``lstat`` needs no read access. With *private_only* a file that grants
    group or others anything is left out (the Sudo leftovers row of Doctor); without
    it the file is named and flagged, because the gateway refuses such a file
    too and a change of owner alone does not repair it. Without *hooks* the
    hooks folder and its tokens are not scanned.
    """

    if os.name == "nt" or not hasattr(os, "geteuid") or os.geteuid() == 0:
        return []
    root = os.fspath(data_dir)
    found: list[tuple[str, bool]] = []

    def add(rel: str) -> None:
        try:
            info = os.lstat(os.path.join(root, rel))
        except OSError:
            return
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0:
            return
        loose = bool(stat.S_IMODE(info.st_mode) & 0o077)
        if loose and private_only:
            return
        found.append((rel, loose))

    for name in names:
        add(name)

    if not hooks:
        return found
    hooks_dir = os.path.join(root, "hooks")
    try:
        info = os.lstat(hooks_dir)
    except OSError:
        return found
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        return found
    if info.st_uid == 0 and not (stat.S_IMODE(info.st_mode) & 0o022):
        found.append(("hooks/", False))
    try:
        hook_names = os.listdir(hooks_dir)
    except OSError:
        return found
    for name in sorted(hook_names):
        if name.startswith(".hook-") and name.endswith(".token"):
            add(f"hooks/{name}")
    return found


def sudo_runtime_leftover_relpaths(data_dir: str | os.PathLike[str]) -> list[str]:
    """Return relative paths of private root-owned leftovers under *data_dir*."""

    return [rel for rel, _ in _root_owned_runtime_files(data_dir, SUDO_RUNTIME_LEFTOVER_NAMES, private_only=True)]


# The PID records the gateway start and restart validate before anything else.
GATEWAY_PID_RECORD_NAMES: tuple[str, ...] = ("gateway.pid", "watchdog.pid")


def root_owned_start_blockers(
    data_dir: str | os.PathLike[str],
    *,
    ai_discovery_enabled: bool,
    pid_dir: str | os.PathLike[str] | None = None,
) -> tuple[list[str], list[str]]:
    """Root-owned state that stops the gateway start of this account (GAP-0788).

    Returns ``(blockers, loose)``: the paths to name, and the ones of those
    whose group/other bits the gateway also refuses, which the repair must
    take away after the owner is returned. Unlike the Sudo leftovers row this
    names a root-owned file of any mode. Each file list is scoped to the
    folder the start reads it from: *data_dir* is the store, with the runtime
    files and the hooks folder with its tokens (its PID records only when
    *pid_dir* is the same folder); *pid_dir* is the install home, where start
    validates the PID records, and when it is another folder only those are
    scanned there. The store itself is named (``STORE_DIR_ENTRY``) when root
    owns it and this account cannot write there, as with a root-owned 0700
    moved store: its files are invisible, so *loose* then also holds the store
    with a trailing separator, for the repair to take group and other access
    away from the runtime files it finds there once the owner is returned. The
    AI discovery state is named only when discovery is enabled: the gateway
    reads it then and not otherwise.
    """

    if os.name == "nt" or not hasattr(os, "geteuid") or os.geteuid() == 0:
        return [], []
    pids_elsewhere = pid_dir is not None and os.path.abspath(os.fspath(pid_dir)) != os.path.abspath(
        os.fspath(data_dir)
    )
    names = tuple(
        n
        for n in SUDO_RUNTIME_LEFTOVER_NAMES
        if (ai_discovery_enabled or n != "ai_discovery_state.json")
        and not (pids_elsewhere and n in GATEWAY_PID_RECORD_NAMES)
    )
    blockers: list[str] = []
    loose: list[str] = []
    try:
        info = os.lstat(data_dir)
    except OSError:
        info = None
    if (
        info is not None
        and stat.S_ISDIR(info.st_mode)
        and info.st_uid == 0
        and not os.access(data_dir, os.W_OK | os.X_OK)
    ):
        blockers.append(STORE_DIR_ENTRY)
        loose.append(os.path.join(os.path.normpath(os.fspath(data_dir)), ""))
    for rel, is_loose in _root_owned_runtime_files(data_dir, names, private_only=False):
        blockers.append(rel)
        if is_loose:
            loose.append(os.path.join(os.fspath(data_dir), rel))
    if pids_elsewhere:
        for rel, is_loose in _root_owned_runtime_files(
            pid_dir, GATEWAY_PID_RECORD_NAMES, private_only=False, hooks=False
        ):
            path = os.path.join(os.fspath(pid_dir), rel)
            blockers.append(path)
            if is_loose:
                loose.append(path)
    return blockers, loose


# The one Windows owner trust set, besides the account itself, for folders and
# files DefenseClaw validates but did not create: a profile folder is owned by
# BUILTIN\Administrators when a member of that group created it, elevated or
# not (cowork-1-0-8 GAP-0085). Matched by well-known SID only. Go's
# internal/winowner.SystemOwnerSIDs holds the same list; a test pins the two.
_WINDOWS_TRUSTED_SYSTEM_CONTROLLER_SIDS = frozenset(
    {
        "S-1-5-18",  # LocalSystem
        "S-1-5-32-544",  # BUILTIN\Administrators
        # NT SERVICE\TrustedInstaller
        "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
    }
)


# Every right that lets a principal change a folder's entries or a file's
# content, DACL or owner: GENERIC_ALL, GENERIC_WRITE, DELETE, WRITE_DAC,
# WRITE_OWNER, FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY, FILE_WRITE_EA,
# FILE_DELETE_CHILD and FILE_WRITE_ATTRIBUTES. Go's
# internal/winowner.CustodyWriteMask holds the same value (the Cowork guard
# applies it to the removal marker's folder); a test pins the two.
_WINDOWS_CUSTODY_WRITE_MASK = 0x10000000 | 0x40000000 | 0x000D0156


def windows_owner_problem(owner_sid: str, current_sid: str) -> str | None:
    """Return why *owner_sid* is outside the Windows owner trust set, or ``None``.

    The set is *current_sid* (when known) and
    ``_WINDOWS_TRUSTED_SYSTEM_CONTROLLER_SIDS``. Users, Authenticated Users,
    Everyone and every other account are refused; the message names the owner.
    """
    if owner_sid and (
        (current_sid and owner_sid == current_sid) or owner_sid in _WINDOWS_TRUSTED_SYSTEM_CONTROLLER_SIDS
    ):
        return None
    trusted = "SYSTEM, BUILTIN Administrators or TrustedInstaller"
    if current_sid:
        trusted = "this account, " + trusted
    return f"owner SID {owner_sid or '<unknown>'} is not {trusted}"


_DOTENV_PROCESS_CONTROL_NAMES = frozenset(
    {
        "ALL_PROXY",
        "BASH_ENV",
        "CLAUDE_CONFIG_DIR",
        "CODEX_HOME",
        "COMSPEC",
        "CURL_CA_BUNDLE",
        "DEFENSECLAW_CONFIG",
        "DEFENSECLAW_CODEX_LOOPBACK_TRUST",
        "DEFENSECLAW_DATA_DIR",
        "DEFENSECLAW_DAEMON",
        "DEFENSECLAW_DEV",
        "DEFENSECLAW_DISABLE_AWS_HTTP1_SHIM",
        "DEFENSE" + "CLAW_DISABLE_REDACTION",
        "DEFENSECLAW_DUMP_RAW_SECRETS",
        # The managed deployment mode and profile pins come only from the
        # service definition.
        "DEFENSECLAW_DEPLOYMENT_MODE",
        "DEFENSECLAW_ENTERPRISE_PROFILE",
        "DEFENSECLAW_FAIL_MODE",
        "DEFENSECLAW_FORCE_AWS_HTTP1_SHIM",
        "DEFENSECLAW_GATEWAY_BIN",
        "DEFENSECLAW_HOME",
        "DEFENSECLAW_JSONL_DISABLE",
        "DEFENSECLAW_OTEL_TLS_INSECURE",
        "DEFENSECLAW_POLICY_VALIDATE_ALLOW_NO_OPA",
        "DEFENSECLAW_REVEAL_PII",
        # Set only by DefenseClaw inside a sandbox; a planted value would make
        # the shell wrapper believe it already runs sandboxed.
        "DEFENSECLAW_SANDBOX_ID",
        "DEFENSECLAW_SANDBOX_NAME",
        "DEFENSECLAW_SANDBOX_TOKEN",
        "DEFENSECLAW_STRICT_AVAILABILITY",
        "DEFENSECLAW_TEST",
        "DEFENSECLAW_TRACKED_HOST_STAT_FD",
        "DEFENSECLAW_TOOL_INSPECT_FAIL_OPEN",
        "DEFENSECLAW_TRUSTED_PROXY_CIDRS",
        "DEFENSECLAW_UNGUARDED_CHATGPT_CODEX_RESPONSES",
        "DEFENSECLAW_UPGRADE_ALLOW_UNVERIFIED",
        "DEFENSECLAW_WEBHOOK_ALLOW_LOCALHOST",
        "ENV",
        "GIT_SSL_NO_VERIFY",
        "HOME",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "LOCPATH",
        "NO_PROXY",
        "NODE_EXTRA_CA_CERTS",
        "NODE_OPTIONS",
        "PATH",
        "PATHEXT",
        "PYTHONHOME",
        "PYTHONPATH",
        "PYTHONSTARTUP",
        "REQUESTS_CA_BUNDLE",
        "SSL_CERT_DIR",
        "SSL_CERT_FILE",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "TMPDIR",
        "USERPROFILE",
        "WINDIR",
        "XDG_CACHE_HOME",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_RUNTIME_DIR",
        "XDG_STATE_HOME",
    }
)
_DOTENV_PROCESS_CONTROL_PREFIXES = ("DYLD_", "LD_")
_DOTENV_PROCESS_CONTROL_DEFENSECLAW_PREFIXES = ("DEFENSE" + "CLAW_ALLOW_",)


def dotenv_key_is_valid(key: str) -> bool:
    """Return whether *key* is one portable ASCII environment name."""
    return bool(
        key
        and key.isascii()
        and (key[0].isalpha() or key[0] == "_")
        and all(character.isalnum() or character == "_" for character in key)
    )


def dotenv_line_ending(existing: bytes | None) -> bytes:
    """The line ending DefenseClaw writes into a ``.env`` that now holds *existing*.

    One per file, on every OS: CRLF only when the file is entirely CRLF,
    otherwise LF (also for a new or empty file). The readers accept both.
    """
    body = existing or b""
    lf = body.count(b"\n")
    return b"\r\n" if lf and lf == body.count(b"\r\n") else b"\n"


def serialize_dotenv(lines: Iterable[bytes], existing: bytes | None) -> bytes:
    """The one serializer every DefenseClaw ``.env`` writer ends with.

    Each of *lines* is written without whatever line ending it carried and
    with the single ending :func:`dotenv_line_ending` picks from *existing*, the
    bytes being replaced. A file an older writer left half CRLF and half LF
    therefore leaves the first write with one ending. Byte-exact rollback
    restores do not use it: they put the earlier bytes back as they were.
    """
    newline = dotenv_line_ending(existing)
    out: list[bytes] = []
    for line in lines:
        for terminator in (b"\r\n", b"\n", b"\r"):
            if line.endswith(terminator):
                line = line[: -len(terminator)]
                break
        out.append(line + newline)
    return b"".join(out)


def dotenv_key_is_process_control(key: str) -> bool:
    """Return whether a dotenv key can redirect or inject a child process."""
    normalized = key.strip().upper()
    return normalized in _DOTENV_PROCESS_CONTROL_NAMES or normalized.startswith(
        _DOTENV_PROCESS_CONTROL_PREFIXES + _DOTENV_PROCESS_CONTROL_DEFENSECLAW_PREFIXES
    )


def windows_extended_path(path: str | os.PathLike[str]) -> str:
    """Return an absolute Win32 path that is not limited by ``MAX_PATH``."""

    value = os.path.abspath(os.fspath(path))
    if value.startswith(("\\\\?\\", "\\\\.\\")):
        return value
    if value.startswith("\\\\"):
        return "\\\\?\\UNC\\" + value[2:]
    return "\\\\?\\" + value


def _sync_directory(path: str | os.PathLike[str]) -> None:
    """Persist a directory-entry mutation where the platform supports it."""

    if os.name == "nt":
        # Windows replacements use MOVEFILE_WRITE_THROUGH below. Opening a
        # directory for FlushFileBuffers is filesystem/privilege dependent and
        # adds no stronger guarantee than that documented primitive.
        return
    fd = os.open(os.fspath(path), os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def replace_file_durable(source: str | os.PathLike[str], target: str | os.PathLike[str]) -> None:
    """Atomically replace *target* and durably commit the directory entry.

    ``os.replace`` provides name atomicity but does not request write-through
    on Windows. Installer migrations use the resulting file as a recovery
    boundary, so native Windows uses ``MoveFileExW`` with both
    ``MOVEFILE_REPLACE_EXISTING`` and ``MOVEFILE_WRITE_THROUGH``. POSIX uses a
    sibling rename followed by an fsync of the containing directory.
    """

    source_path = os.path.abspath(os.fspath(source))
    target_path = os.path.abspath(os.fspath(target))
    if os.path.normcase(os.path.dirname(source_path)) != os.path.normcase(os.path.dirname(target_path)):
        raise OSError("durable atomic replacement requires sibling paths")
    if os.name != "nt":
        os.replace(source_path, target_path)
        _sync_directory(os.path.dirname(target_path) or os.curdir)
        return

    import ctypes
    from ctypes import wintypes

    movefile_replace_existing = 0x00000001
    movefile_write_through = 0x00000008
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    move_file_ex = kernel32.MoveFileExW
    move_file_ex.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
    move_file_ex.restype = wintypes.BOOL
    code = _move_retrying_sharing_errors(
        lambda: bool(
            move_file_ex(
                windows_extended_path(source_path),
                windows_extended_path(target_path),
                movefile_replace_existing | movefile_write_through,
            )
        ),
        ctypes.get_last_error,
    )
    if code:
        # ctypes.WinError carries no file name; callers name the file they
        # could not save from filename2, as os.replace sets it on POSIX.
        error = ctypes.WinError(code)
        raise OSError(error.errno, error.strerror, source_path, error.winerror, target_path)


# ERROR_ACCESS_DENIED and ERROR_SHARING_VIOLATION: a reader that opened the
# target without FILE_SHARE_DELETE (another DefenseClaw process, an indexer,
# antivirus) makes MoveFileExW fail for a moment.
_TRANSIENT_MOVE_ERRORS = frozenset({5, 32})


def _move_retrying_sharing_errors(
    move: Callable[[], bool], last_error: Callable[[], int], sleep: Callable[[float], None] = time.sleep
) -> int:
    """Run *move* until it succeeds (0) or fails with a non-transient error
    or eight times (that error code), backing off as the Go writer does."""
    delay = 0.01
    for attempt in range(1, 9):
        if move():
            return 0
        code = last_error()
        if code not in _TRANSIENT_MOVE_ERRORS or attempt == 8:
            return code
        sleep(delay)
        delay = min(delay * 2, 0.08)
    return 0


def delete_file_durable(path: str | os.PathLike[str]) -> None:
    """Durably remove one file without exposing a partially deleted name.

    On Windows, first write-through rename the file to a unique sibling. A
    crash can therefore leave only an inert tombstone, never the live legacy
    filename that a downgraded process would consume again. The tombstone is
    then unlinked immediately. We deliberately do not glob-delete tombstones
    on a later run: without a durable ownership record, a matching filename is
    not sufficient proof that DefenseClaw owns an artifact. POSIX unlinks and
    fsyncs the parent directory.
    """

    target = os.path.abspath(os.fspath(path))
    parent = os.path.dirname(target) or os.curdir
    if os.name != "nt":
        os.unlink(target)
        _sync_directory(parent)
        return
    tombstone = os.path.join(parent, f".{os.path.basename(target)}.deleted.{uuid.uuid4().hex}")
    replace_file_durable(target, tombstone)
    try:
        os.unlink(tombstone)
    except OSError as exc:
        raise OSError(f"removed live path but could not delete durable tombstone {tombstone}: {exc}") from exc


def reject_reparse_path(path: str | os.PathLike[str]) -> None:
    """Reject a leaf or Windows ancestor that redirects filesystem access."""
    target = os.path.abspath(os.fspath(path))
    _reject_reparse_chain(os.path.dirname(target) or os.curdir)
    _reject_reparse_path(target, allow_missing=True)


def make_private_directory(path: str | os.PathLike[str]) -> None:
    """Create or tighten one operator-private directory cross-platform."""
    target = os.path.abspath(os.fspath(path))
    _reject_reparse_chain(os.path.dirname(target) or os.curdir)
    _make_private_directories(target)
    _reject_reparse_path(target, allow_missing=False)
    _protect_private_directory(target)


def protect_private_file(path: str | os.PathLike[str]) -> None:
    """Tighten an existing regular file to POSIX 0600 or a private DACL."""
    target = os.path.abspath(os.fspath(path))
    fd = open_regular_file_no_follow(target)
    try:
        set_file_mode(fd, target, 0o600)
    finally:
        os.close(fd)


def open_regular_file_no_follow(
    path: str | os.PathLike[str],
    *,
    expected_stat: os.stat_result | None = None,
    _deny_write_sharing: bool = False,
    _deny_delete_sharing: bool = False,
) -> int:
    """Open one regular file without following a swapped symlink/reparse point.

    ``expected_stat`` lets a caller bind this open to an identity it inspected
    before entering the shared reader. This closes an A→B→A pathname swap in
    callers that perform custody checks before reading the file.

    On Windows ``_deny_delete_sharing`` also withholds delete sharing, so while
    the descriptor is open NTFS refuses to rename or replace the file or any
    directory above it.
    """
    target = os.path.abspath(os.fspath(path))
    _reject_reparse_chain(os.path.dirname(target) or os.curdir)
    expected = _reject_reparse_path(target, allow_missing=False)
    assert expected is not None
    if expected_stat is not None and not os.path.samestat(expected_stat, expected):
        raise UnsafePathError(
            f"sensitive file changed before opening: {target}",
            code=UNSAFE_PATH_CHANGED,
        )
    if not stat.S_ISREG(expected.st_mode):
        raise UnsafePathError(
            f"refusing sensitive access to non-file: {target}",
            code=UNSAFE_PATH_NOT_REGULAR_FILE,
        )
    # Windows CRT text mode translates CRLF while ``fstat().st_size`` reports
    # the exact bytes on disk. Callers that bind security evidence to the
    # opened file size must therefore always receive a binary descriptor.
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    if os.name == "nt" and (_deny_write_sharing or _deny_delete_sharing):
        fd = _open_windows_stable_read_fd(target, share_delete=not _deny_delete_sharing)
    else:
        fd = os.open(target, flags)
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            raise UnsafePathError(
                f"refusing sensitive access to non-file: {target}",
                code=UNSAFE_PATH_NOT_REGULAR_FILE,
            )
        if not os.path.samestat(expected, opened):
            raise UnsafePathError(
                f"sensitive file changed while opening: {target}",
                code=UNSAFE_PATH_CHANGED,
            )
    except Exception:
        os.close(fd)
        raise
    return fd


def _open_windows_stable_read_fd(path: str, *, share_delete: bool = True) -> int:
    """Open a binary CRT reader backed by an NT handle that denies writers."""
    import ctypes
    import msvcrt
    from ctypes import wintypes

    generic_read = 0x80000000
    file_share_read = 0x00000001
    file_share_delete = 0x00000004
    open_existing = 3
    file_flag_open_reparse_point = 0x00200000
    invalid_handle = ctypes.c_void_p(-1).value

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create_file.restype = wintypes.HANDLE
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL

    handle = create_file(
        windows_extended_path(path),
        generic_read,
        file_share_read | (file_share_delete if share_delete else 0),
        None,
        open_existing,
        file_flag_open_reparse_point,
        None,
    )
    if handle == invalid_handle:
        raise ctypes.WinError(ctypes.get_last_error())
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0)
    try:
        return msvcrt.open_osfhandle(handle, flags)
    except BaseException:
        close_handle(handle)
        raise


def _windows_file_stability_times(fd: int) -> tuple[int, int]:
    """Return handle-bound NT last-write and change times."""
    import ctypes
    import msvcrt
    from ctypes import wintypes

    class _FileBasicInfo(ctypes.Structure):
        _fields_ = [
            ("creation_time", ctypes.c_longlong),
            ("last_access_time", ctypes.c_longlong),
            ("last_write_time", ctypes.c_longlong),
            ("change_time", ctypes.c_longlong),
            ("file_attributes", wintypes.DWORD),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_file_information = kernel32.GetFileInformationByHandleEx
    get_file_information.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    get_file_information.restype = wintypes.BOOL
    basic = _FileBasicInfo()
    file_basic_info = 0
    if not get_file_information(
        msvcrt.get_osfhandle(fd),
        file_basic_info,
        ctypes.byref(basic),
        ctypes.sizeof(basic),
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    return basic.last_write_time, basic.change_time


def _file_stability_snapshot(fd: int) -> tuple[int, int, int, int, int]:
    """Capture metadata that changes when an open file is mutated in place."""
    opened = os.fstat(fd)
    native_modified = 0
    native_changed = 0
    if os.name == "nt":
        native_modified, native_changed = _windows_file_stability_times(fd)
    return (
        opened.st_size,
        opened.st_mtime_ns,
        opened.st_ctime_ns,
        native_modified,
        native_changed,
    )


def read_regular_file_no_follow(
    path: str | os.PathLike[str],
    *,
    max_bytes: int,
    expected_stat: os.stat_result | None = None,
) -> bytes:
    """Read one stable bounded file without following links or blocking on FIFOs."""
    if max_bytes <= 0:
        raise ValueError("max_bytes must be positive")
    target = os.path.abspath(os.fspath(path))
    fd = open_regular_file_no_follow(
        target,
        expected_stat=expected_stat,
        _deny_write_sharing=True,
    )
    try:
        opened = os.fstat(fd)
        before = _file_stability_snapshot(fd)
        if before[0] > max_bytes:
            raise UnsafePathError(
                f"sensitive file exceeds {max_bytes}-byte read limit",
                code=UNSAFE_PATH_EXCEEDS_LIMIT,
            )
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining:
            chunk = os.read(fd, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        body = b"".join(chunks)
        after = _file_stability_snapshot(fd)
    finally:
        os.close(fd)
    if len(body) > max_bytes:
        raise UnsafePathError(
            f"sensitive file exceeds {max_bytes}-byte read limit",
            code=UNSAFE_PATH_EXCEEDS_LIMIT,
        )
    if before != after or len(body) != before[0]:
        raise UnsafePathError(
            f"sensitive file changed while reading: {target}",
            code=UNSAFE_PATH_CHANGED,
        )
    _reject_reparse_chain(os.path.dirname(target) or os.curdir)
    current = _reject_reparse_path(target, allow_missing=False)
    assert current is not None
    if not os.path.samestat(opened, current):
        raise UnsafePathError(
            f"sensitive file changed while reading: {target}",
            code=UNSAFE_PATH_CHANGED,
        )
    return body


def trusted_system_subprocess_env() -> dict[str, str]:
    """Return a minimal environment for fixed-path OS evidence commands."""
    allowed = (
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "TZ",
        "SystemRoot",
        "WINDIR",
        "TEMP",
        "TMP",
    )
    return {name: os.environ[name] for name in allowed if name in os.environ}


def trusted_posix_executable_path(path: str | os.PathLike[str]) -> str:
    """Resolve an executable held only by root/current-user, non-writable paths."""
    if os.name == "nt":
        raise OSError("POSIX executable custody is unavailable on Windows")
    raw_path = os.fspath(path)
    if not os.path.isabs(raw_path):
        raise UnsafePathError(
            "gateway executable path is not absolute",
            code=UNSAFE_PATH_NOT_ABSOLUTE,
        )
    candidate = os.path.abspath(raw_path)
    resolved = os.path.realpath(candidate)
    try:
        info = os.lstat(resolved)
    except OSError as exc:
        raise UnsafePathError(
            "gateway executable could not be inspected",
            code=UNSAFE_PATH_INSPECTION_FAILED,
        ) from exc
    if not stat.S_ISREG(info.st_mode) or not os.access(resolved, os.X_OK):
        raise UnsafePathError(
            "gateway executable is not an executable regular file",
            code=UNSAFE_PATH_NOT_REGULAR_FILE,
        )
    geteuid = getattr(os, "geteuid", None)
    current_uid = geteuid() if callable(geteuid) else info.st_uid
    owner = tracked_host_owner_uid(resolved, info)
    if owner == -1 and namespace_hides_owner(info):
        raise _namespace_view_error(resolved, resolved)
    if owner not in {0, current_uid} or stat.S_IMODE(info.st_mode) & 0o022:
        raise UnsafePathError(
            f"gateway executable {resolved} can be changed by another account; "
            f"make this account or root its owner and run: chmod go-w {shlex.quote(str(resolved))}",
            code=UNSAFE_PATH_UNTRUSTED_CUSTODY,
        )
    if sys.platform == "darwin" and darwin_acl_write_error(resolved):
        raise UnsafePathError(
            "gateway executable has a write-capable extended ACL",
            code=UNSAFE_PATH_UNTRUSTED_CUSTODY,
        )

    current = Path(resolved).parent
    while True:
        parent_info = os.lstat(current)
        if not stat.S_ISDIR(parent_info.st_mode):
            raise UnsafePathError(
                "gateway executable ancestor is not a directory",
                code=UNSAFE_PATH_NOT_REGULAR_FILE,
            )
        # A root-owned sticky directory such as /tmp is writable by everyone,
        # but only an entry's owner can rename or remove it, so nobody else
        # can replace this account's folder inside it (the gateway's own
        # directory check allows it too). Without this, every config check
        # failed for a home under /tmp.
        parent_uid = tracked_host_owner_uid(current, parent_info)
        if parent_uid == -1 and namespace_hides_owner(parent_info):
            raise _namespace_view_error(f"folder {current}", resolved)
        root_sticky = parent_uid == 0 and parent_info.st_mode & stat.S_ISVTX
        if parent_uid not in {0, current_uid} or (
            stat.S_IMODE(parent_info.st_mode) & 0o022 and not root_sticky
        ):
            # Name the folder: a chmod on the (possibly symlinked) command
            # path changes the file, not the folder other accounts can write.
            raise UnsafePathError(
                f"folder {current} holding the gateway executable {resolved} can be changed by "
                f"another account; make this account or root its owner and run: "
                f"chmod go-w {shlex.quote(str(current))}",
                code=UNSAFE_PATH_UNTRUSTED_CUSTODY,
            )
        if sys.platform == "darwin" and darwin_acl_write_error(current):
            raise UnsafePathError(
                "gateway executable ancestor has a write-capable extended ACL",
                code=UNSAFE_PATH_UNTRUSTED_CUSTODY,
            )
        if current.parent == current:
            break
        current = current.parent
    return resolved


#: The gateway inspection bound (hookAPIACLInspectionTimeout) and its retry: a
#: slow ls under a process scanner is inspected once more, and a second timeout
#: is the verdict. Only the plugin-folder check (_plugin_darwin_acl_refused) asks
#: for this; every other caller keeps the single 2-second inspection, so a
#: timeout there stays a refusal on the first try.
_PLUGIN_ACL_INSPECTION_TIMEOUT = 5.0
_PLUGIN_ACL_INSPECTION_ATTEMPTS = 2


def _darwin_acl_output(path: str | os.PathLike[str], *, timeout: float = 2.0, attempts: int = 1) -> tuple[str, str]:
    """Return ``(mode, ACL text)`` from a fixed-path Darwin inspection."""
    if sys.platform != "darwin":
        return "", ""
    result = None
    for _attempt in range(attempts):
        try:
            result = subprocess.run(
                ["/bin/ls", "-lde", os.path.abspath(os.fspath(path))],
                capture_output=True,
                text=True,
                shell=False,
                stdin=subprocess.DEVNULL,
                env=trusted_system_subprocess_env(),
                timeout=timeout,
                check=False,
            )
            break
        except subprocess.TimeoutExpired:
            continue
        except (FileNotFoundError, OSError):
            return "", ""
    if result is None:
        return "", ""
    if result.returncode != 0:
        return "", ""
    lines = result.stdout.splitlines()
    first_line = lines[0] if lines else ""
    mode_field = first_line.split(maxsplit=1)[0] if first_line else ""
    return mode_field, "\n".join(lines[1:])


_DARWIN_ACL_WRITE_PERMISSIONS = frozenset(
    {
        "add_file",
        "add_subdirectory",
        "append",
        "chown",
        "delete",
        "delete_child",
        "write",
        "writeattr",
        "writeextattr",
        "writesecurity",
    }
)
#: Principals whose allow entries the gateway ignores outside the standalone
#: profile: they hold administrator authority on macOS already.
_DARWIN_ACL_TRUSTED_PRINCIPALS = frozenset({"user:root", "group:wheel", "group:admin"})


def _darwin_acl_allows(acl_text: str, permissions: frozenset[str]) -> bool:
    for raw_line in acl_text.splitlines():
        line = raw_line.strip().lower()
        if " allow " not in f" {line} ":
            continue
        granted = line.rsplit(" allow ", 1)[-1]
        words = {word.strip() for word in granted.replace(":", ",").split(",")}
        if words & permissions:
            return True
    return False


def darwin_acl_confidentiality_error(path: str | os.PathLike[str]) -> str | None:
    """Return whether a Darwin ACL grants file-content read access."""
    if sys.platform != "darwin":
        return None
    mode_field, acl_text = _darwin_acl_output(path)
    if not mode_field:
        return "extended ACL could not be inspected"
    if not acl_text:
        return "extended ACL could not be interpreted" if "+" in mode_field else None
    read_permissions = frozenset({"read", "readattr", "readextattr"})
    return "extended ACL grants additional read access" if _darwin_acl_allows(acl_text, read_permissions) else None


def darwin_acl_write_error(path: str | os.PathLike[str]) -> str | None:
    """Return whether a Darwin ACL grants file-integrity-changing access."""
    if sys.platform != "darwin":
        return None
    mode_field, acl_text = _darwin_acl_output(path)
    if not mode_field:
        return "extended ACL could not be inspected"
    if not acl_text:
        return "extended ACL could not be interpreted" if "+" in mode_field else None
    if _darwin_acl_allows(acl_text, _DARWIN_ACL_WRITE_PERMISSIONS):
        return "extended ACL grants additional write access"
    return None


def _clear_darwin_extended_acl(fd: int, path: str) -> None:
    """Remove a Darwin extended ACL and prove the path still names *fd*."""
    expected = os.fstat(fd)
    try:
        result = subprocess.run(
            ["/bin/chmod", "-N", f"/dev/fd/{fd}"],
            capture_output=True,
            text=True,
            shell=False,
            stdin=subprocess.DEVNULL,
            env=trusted_system_subprocess_env(),
            pass_fds=(fd,),
            timeout=2.0,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        raise OSError("could not clear the private file's extended ACL") from exc
    if result.returncode != 0:
        raise OSError("could not clear the private file's extended ACL")
    current = os.lstat(path)
    if not os.path.samestat(expected, current):
        raise UnsafePathError(
            "sensitive file changed while clearing its extended ACL",
            code=UNSAFE_PATH_CHANGED,
        )


def set_file_mode(fd: int, path: str, mode: int, *, set_owner: bool = False) -> None:
    """Apply *mode* to the open file described by *fd* and *path*.

    POSIX uses the descriptor so the permission change cannot be redirected
    through a path race. Windows has no :func:`os.fchmod`, and its
    :func:`os.chmod` only toggles the read-only attribute; for owner-only
    modes, install a protected owner/SYSTEM DACL before secret bytes are
    written instead.

    The caller must keep *fd* open for the duration of this call. Windows CRT
    descriptors deny delete sharing, which keeps *path* bound to that file
    while ``SetFileSecurityW`` applies the DACL. ``set_owner`` is reserved for
    a DefenseClaw-managed path opened for creation or an authorized rewrite;
    operator-selected existing paths must leave it disabled.
    """
    if os.name == "nt":
        if mode & 0o077 == 0:
            _set_windows_owner_only_acl(path, set_owner=set_owner)
        else:
            os.chmod(path, mode)
        return

    fchmod = getattr(os, "fchmod", None)
    if fchmod is not None:
        fchmod(fd, mode)
    else:
        os.chmod(path, mode)
    if sys.platform == "darwin" and mode & 0o077 == 0:
        _clear_darwin_extended_acl(fd, path)
        if fchmod is not None:
            fchmod(fd, mode)


def atomic_write_text_secure(
    path: str,
    write: Callable[[TextIO], None],
    *,
    prefix: str,
) -> None:
    """Atomically replace a secret-bearing text file without widening access.

    A new parent directory is owner-only on POSIX, while an existing directory
    is never chmodded. The staging file is protected before ``write`` receives
    its stream, and every failure path closes and removes the staging file.
    """
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, mode=0o700, exist_ok=True)

    target_mode = 0o600
    if os.name != "nt":
        try:
            existing_mode = stat.S_IMODE(os.stat(path).st_mode)
        except OSError:
            existing_mode = None
        if existing_mode is not None and existing_mode != 0o600:
            target_mode = existing_mode & 0o600
            if target_mode == 0o600 and existing_mode & 0o077 == 0o040:
                target_mode = 0o640
            elif target_mode == 0:
                target_mode = 0o600

    fd = -1
    tmp = ""
    try:
        fd, tmp = tempfile.mkstemp(prefix=prefix, suffix=".tmp", dir=directory)
        set_file_mode(fd, tmp, target_mode, set_owner=True)
        stream = os.fdopen(fd, "w")
        fd = -1
        with stream:
            write(stream)
            stream.flush()
            os.fsync(stream.fileno())
        replace_file_durable(tmp, path)
        tmp = ""
    finally:
        if fd != -1:
            with contextlib.suppress(OSError):
                os.close(fd)
        if tmp:
            with contextlib.suppress(OSError):
                os.unlink(tmp)


def copy_windows_dacl(source: str, destination: str) -> None:
    """Copy the Windows DACL from *source* to *destination*.

    Atomic replacement creates a new file, so Windows ACLs do not follow the
    old path automatically. This preserves an operator-hardened DACL (and also
    avoids tightening a deliberately shared non-secret file) across rewrite.
    """
    if os.name != "nt":
        raise OSError("Windows DACL copying is only available on Windows")

    import ctypes
    from ctypes import wintypes

    dacl_security_information = 0x00000004
    protected_dacl_security_information = 0x80000000
    error_insufficient_buffer = 122

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    get_file_security = advapi32.GetFileSecurityW
    get_file_security.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    get_file_security.restype = wintypes.BOOL

    get_descriptor_dacl = advapi32.GetSecurityDescriptorDacl
    get_descriptor_dacl.argtypes = [
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.BOOL),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.BOOL),
    ]
    get_descriptor_dacl.restype = wintypes.BOOL

    set_named_security_info = advapi32.SetNamedSecurityInfoW
    set_named_security_info.argtypes = [
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.LPVOID,
    ]
    set_named_security_info.restype = wintypes.DWORD

    needed = wintypes.DWORD()
    ctypes.set_last_error(0)
    found = get_file_security(
        source,
        dacl_security_information,
        None,
        0,
        ctypes.byref(needed),
    )
    error = ctypes.get_last_error()
    if not found and error != error_insufficient_buffer:
        raise ctypes.WinError(error)

    descriptor = ctypes.create_string_buffer(needed.value)
    if not get_file_security(
        source,
        dacl_security_information,
        descriptor,
        needed,
        ctypes.byref(needed),
    ):
        raise ctypes.WinError(ctypes.get_last_error())

    dacl_present = wintypes.BOOL()
    dacl = wintypes.LPVOID()
    dacl_defaulted = wintypes.BOOL()
    if not get_descriptor_dacl(
        descriptor,
        ctypes.byref(dacl_present),
        ctypes.byref(dacl),
        ctypes.byref(dacl_defaulted),
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    if not dacl_present.value or not dacl.value:
        raise OSError(f"refusing to copy a missing or NULL Windows DACL: {source}")

    result = set_named_security_info(
        destination,
        1,  # SE_FILE_OBJECT
        dacl_security_information | protected_dacl_security_information,
        None,
        None,
        dacl,
        None,
    )
    if result:
        raise OSError(result, ctypes.FormatError(result), destination)
    if not _windows_dacl_is_protected(destination):
        raise OSError(f"copied Windows DACL remains inheritable: {destination}")


def _windows_dacl_is_protected(path: str | os.PathLike[str]) -> bool:
    """Return whether *path* has the ``SE_DACL_PROTECTED`` control bit."""

    if os.name != "nt":
        raise OSError("Windows DACL inspection is only available on Windows")

    import ctypes
    from ctypes import wintypes

    dacl_security_information = 0x00000004
    error_insufficient_buffer = 122
    se_dacl_protected = 0x1000

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    get_file_security = advapi32.GetFileSecurityW
    get_file_security.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    get_file_security.restype = wintypes.BOOL
    get_descriptor_control = advapi32.GetSecurityDescriptorControl
    get_descriptor_control.argtypes = [
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.WORD),
        ctypes.POINTER(wintypes.DWORD),
    ]
    get_descriptor_control.restype = wintypes.BOOL

    needed = wintypes.DWORD()
    ctypes.set_last_error(0)
    found = get_file_security(
        os.fspath(path),
        dacl_security_information,
        None,
        0,
        ctypes.byref(needed),
    )
    error = ctypes.get_last_error()
    if not found and error != error_insufficient_buffer:
        raise ctypes.WinError(error)

    descriptor = ctypes.create_string_buffer(needed.value)
    if not get_file_security(
        os.fspath(path),
        dacl_security_information,
        descriptor,
        needed,
        ctypes.byref(needed),
    ):
        raise ctypes.WinError(ctypes.get_last_error())

    control = wintypes.WORD()
    revision = wintypes.DWORD()
    if not get_descriptor_control(
        descriptor,
        ctypes.byref(control),
        ctypes.byref(revision),
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    return bool(control.value & se_dacl_protected)


def _windows_private_target_problem(path: str) -> str | None:
    try:
        problem = windows_acl_confidentiality_error(path)
    except OSError as exc:
        return f"ACL inspection failed: {exc}"
    if problem is not None:
        return problem
    try:
        required_access = _windows_acl_has_required_access(path)
    except OSError as exc:
        return f"ACL access verification failed: {exc}"
    if not required_access:
        return "owner/SYSTEM access missing"
    return None


def _verify_or_repair_windows_private_target(path: str) -> None:
    """Repair or remove a replaced private file whose DACL cannot be verified."""

    problem = _windows_private_target_problem(path)
    if problem is None:
        return

    repair_error: OSError | None = None
    try:
        _set_windows_owner_only_acl(path)
    except OSError as exc:
        repair_error = exc
    else:
        problem = _windows_private_target_problem(path)
        if problem is None:
            return

    cleanup_error: OSError | None = None
    try:
        os.unlink(path)
    except OSError as exc:
        cleanup_error = exc

    detail = problem
    if repair_error is not None:
        detail += f"; repair failed: {repair_error}"
    if cleanup_error is not None:
        detail += f"; cleanup failed: {cleanup_error}"
    raise OSError(f"private Windows DACL verification failed: {detail}")


def _safe_os_error_label(exc: OSError) -> str:
    """Return an error label that cannot replay sensitive exception text."""

    code = getattr(exc, "winerror", None) or exc.errno
    if code is None:
        return type(exc).__name__
    return f"{type(exc).__name__} code {code}"


def _managed_windows_publication_name_stat(
    path: str,
    claimed_stat: os.stat_result,
) -> os.stat_result:
    """Prove that *path* still names the exclusively claimed publication."""

    try:
        named_stat = os.stat(path, follow_symlinks=False)
    except OSError as exc:
        code = getattr(exc, "winerror", None) or exc.errno
        if code in {2, 3}:
            raise OSError("managed Windows publication disappeared during validation") from None
        raise OSError(f"managed Windows publication name inspection failed ({_safe_os_error_label(exc)})") from None
    if not os.path.samestat(named_stat, claimed_stat):
        raise OSError("managed Windows publication was concurrently replaced; the replacement was preserved") from None
    return named_stat


def _managed_windows_publication_security_problem(
    path: str,
    descriptor: int,
    claimed_stat: os.stat_result,
    expected_security: WindowsFileSecurity | None,
) -> str | None:
    """Return a value-safe custody failure for one identity-bound file."""

    from defenseclaw import windows_acl

    try:
        actual_security = windows_acl.capture_fd(descriptor)
    except OSError as exc:
        return f"managed Windows security inspection failed ({_safe_os_error_label(exc)})"
    if actual_security != expected_security:
        return "managed Windows security changed during atomic publication"
    inspection_problem: str | None = None
    try:
        problem = windows_acl_custody_confidentiality_error(path)
    except OSError as exc:
        problem = None
        inspection_problem = f"managed Windows custody inspection failed ({_safe_os_error_label(exc)})"
    _managed_windows_publication_name_stat(path, claimed_stat)
    if inspection_problem is not None:
        return inspection_problem
    if problem is not None:
        return f"published managed-custody target is unsafe: {problem}"
    return None


def _repair_managed_windows_publication(
    path: str,
    descriptor: int,
    claimed_stat: os.stat_result,
    expected_security: WindowsFileSecurity | None,
) -> str | None:
    """Repair and revalidate one claimed publication, returning safe failure detail."""

    from defenseclaw import windows_acl

    if expected_security is None:
        return "expected managed Windows security is unavailable"
    try:
        windows_acl.apply_fd(descriptor, expected_security)
        _managed_windows_publication_name_stat(path, claimed_stat)
        repaired_security = windows_acl.capture_fd(descriptor)
    except OSError as exc:
        return _safe_os_error_label(exc)
    if repaired_security != expected_security:
        return "managed Windows security remained changed after repair"
    inspection_problem: str | None = None
    try:
        problem = windows_acl_custody_confidentiality_error(path)
    except OSError as exc:
        problem = None
        inspection_problem = f"managed Windows custody inspection failed ({_safe_os_error_label(exc)})"
    _managed_windows_publication_name_stat(path, claimed_stat)
    if inspection_problem is not None:
        return inspection_problem
    if problem is not None:
        return f"managed Windows custody remained unsafe after repair: {problem}"
    return None


def _verify_managed_windows_private_target(
    path: str,
    staged_stat: os.stat_result,
    expected_security: WindowsFileSecurity | None,
) -> None:
    """Repair or delete only the exact managed file published from staging."""

    from defenseclaw import windows_acl

    try:
        descriptor = windows_acl.open_regular_security_mutation_fd(path)
    except OSError as exc:
        code = getattr(exc, "winerror", None) or exc.errno
        if code in {2, 3}:
            raise OSError("managed Windows publication disappeared before validation") from None
        raise OSError(f"managed Windows publication claim failed ({_safe_os_error_label(exc)})") from None

    claimed_stat: os.stat_result | None = None
    problem: str | None = None
    repair_problem: str | None = None
    cleanup_problem: str | None = None
    delete_requested = False
    close_problem: str | None = None
    try:
        try:
            claimed_stat = os.fstat(descriptor)
        except OSError as exc:
            raise OSError(
                f"managed Windows publication identity inspection failed ({_safe_os_error_label(exc)})"
            ) from None
        if not os.path.samestat(claimed_stat, staged_stat):
            raise OSError(
                "managed Windows publication was concurrently replaced before validation; the replacement was preserved"
            ) from None
        _managed_windows_publication_name_stat(path, claimed_stat)
        problem = _managed_windows_publication_security_problem(
            path,
            descriptor,
            claimed_stat,
            expected_security,
        )
        if problem is not None:
            repair_problem = _repair_managed_windows_publication(
                path,
                descriptor,
                claimed_stat,
                expected_security,
            )
            if repair_problem is not None:
                _managed_windows_publication_name_stat(path, claimed_stat)
                try:
                    windows_acl.delete_regular_fd(descriptor)
                except OSError as exc:
                    cleanup_problem = _safe_os_error_label(exc)
                else:
                    delete_requested = True
    finally:
        try:
            os.close(descriptor)
        except OSError as exc:
            close_problem = _safe_os_error_label(exc)

    if problem is None or repair_problem is None:
        if close_problem is not None:
            raise OSError(f"managed Windows publication handle close failed: {close_problem}") from None
        return

    concurrent_replacement = False
    if delete_requested and close_problem is None:
        try:
            named_after = os.stat(path, follow_symlinks=False)
        except OSError as exc:
            code = getattr(exc, "winerror", None) or exc.errno
            if code not in {2, 3}:
                cleanup_problem = f"post-delete name inspection failed ({_safe_os_error_label(exc)})"
        else:
            if claimed_stat is None:
                cleanup_problem = "claimed managed publication identity was unavailable"
            elif os.path.samestat(named_after, claimed_stat):
                cleanup_problem = "exact managed publication remained after bound deletion"
            else:
                concurrent_replacement = True

    detail = problem
    if repair_problem is not None:
        detail += f"; repair failed: {repair_problem}"
    if cleanup_problem is not None:
        detail += f"; cleanup failed: {cleanup_problem}"
    if close_problem is not None:
        detail += f"; handle close failed: {close_problem}"
    if concurrent_replacement:
        detail += "; concurrent replacement appeared after exact cleanup and was preserved"
    raise OSError(detail) from None


def atomic_write_private(
    path: str | os.PathLike[str],
    write: Callable[[int], None],
    *,
    protect_parent: bool = True,
    windows_managed_custody: bool = False,
    windows_managed_security: WindowsFileSecurity | None = None,
) -> None:
    """Atomically materialize a sensitive file with native protections.

    The random same-directory staging file is protected before ``write`` is
    called.  Existing safe Windows DACLs are copied to the replacement so an
    operator-hardened target is never widened. Unsafe inherited read or write
    grants are replaced by the canonical owner/SYSTEM policy instead.

    ``windows_managed_custody`` is reserved for connector hook credentials
    whose Go writer admits Windows system controllers. It preserves an existing
    custody-safe DACL and validates, without narrowing, the containing hooks
    directory. Generic user-secret writes retain the stricter default policy.
    A new managed target receives the Go-compatible owner/SYSTEM/Administrators
    descriptor rather than inheriting the parent or using a generic secret DACL.
    A rollback may provide its previously captured ``windows_managed_security``
    so the exact accepted descriptor, rather than generation B's descriptor,
    is applied to the staged replacement before publication.

    ``protect_parent=False`` preserves an operator-selected or account folder
    as it is and validates it with :func:`_validate_unmodified_parent`. The
    staged and published file keeps the stricter owner/SYSTEM-only policy.
    """
    if windows_managed_security is not None and not windows_managed_custody:
        raise ValueError("managed Windows security requires managed-custody mode")
    target = os.path.abspath(os.fspath(path))
    parent = os.path.dirname(target) or os.curdir
    _reject_reparse_chain(parent)
    _make_private_directories(parent)
    with _hold_windows_directory(parent):
        _reject_reparse_chain(parent)
        if windows_managed_custody and os.name == "nt":
            problem = windows_acl_custody_write_error(
                parent,
                allow_current_user=True,
                require_current_user_owner=True,
            )
            if problem is not None:
                raise OSError(f"unsafe managed-custody parent {parent}: {problem}")
        elif protect_parent:
            _protect_private_directory(parent)
        else:
            _validate_unmodified_parent(parent)
        _reject_reparse_path(target, allow_missing=True)

        managed_security = windows_managed_security
        if windows_managed_custody and os.name == "nt" and os.path.exists(target) and managed_security is None:
            problem = windows_acl_custody_confidentiality_error(target)
            if problem is not None:
                raise OSError(f"unsafe managed-custody target {target}: {problem}")
            from defenseclaw import windows_acl

            managed_security = windows_acl.capture_path(target)

        fd = -1
        tmp = ""
        staged_stat: os.stat_result | None = None
        try:
            fd, tmp = tempfile.mkstemp(
                prefix=f".{os.path.basename(target)}.",
                suffix=".tmp",
                dir=parent,
            )
            set_file_mode(fd, tmp, 0o600, set_owner=True)
            write(fd)
            os.fsync(fd)
            if windows_managed_custody and os.name == "nt":
                staged_stat = os.fstat(fd)
            os.close(fd)
            fd = -1

            _reject_reparse_chain(parent)
            _reject_reparse_path(target, allow_missing=True)
            if windows_managed_custody and os.name == "nt":
                from defenseclaw import windows_acl

                if managed_security is not None:
                    windows_acl.apply_path(tmp, managed_security)
                else:
                    managed_security = windows_acl.private_security_for_directory(parent)
                    windows_acl.apply_path(tmp, managed_security)
                problem = windows_acl_custody_confidentiality_error(tmp)
                if problem is not None:
                    raise OSError(f"staged managed-custody target is unsafe: {problem}")
            elif os.name == "nt" and os.path.exists(target):
                # Preserve an existing DACL only when it grants no untrusted
                # read or write access. A readable inherited DACL must not be
                # copied onto the new secret-bearing staging file.
                if windows_acl_confidentiality_error(target) is None and _windows_acl_has_required_access(target):
                    copy_windows_dacl(target, tmp)
            replace_file_durable(tmp, target)
            tmp = ""
            if os.name == "nt":
                if windows_managed_custody:
                    if staged_stat is None:
                        raise OSError("managed Windows staging identity is unavailable")
                    _verify_managed_windows_private_target(
                        target,
                        staged_stat,
                        managed_security,
                    )
                else:
                    _verify_or_repair_windows_private_target(target)
        finally:
            if fd != -1:
                with suppress(OSError):
                    os.close(fd)
            if tmp:
                with suppress(OSError):
                    os.unlink(tmp)


def atomic_write_private_bytes(
    path: str | os.PathLike[str],
    data: bytes,
    *,
    protect_parent: bool = True,
    windows_managed_custody: bool = False,
    windows_managed_security: WindowsFileSecurity | None = None,
) -> None:
    """Convenience wrapper for a complete in-memory payload."""

    def _write(fd: int) -> None:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("short write while materializing private file")
            view = view[written:]

    atomic_write_private(
        path,
        _write,
        protect_parent=protect_parent,
        windows_managed_custody=windows_managed_custody,
        windows_managed_security=windows_managed_security,
    )


_WINDOWS_UNTRUSTED_WRITER = "ACL grants write access to untrusted SID "


def windows_untrusted_writer_problem(sid: str) -> str:
    """The custody problem text for an untrusted SID that can write a path."""
    return f"{_WINDOWS_UNTRUSTED_WRITER}{sid or '<unknown>'}"


def windows_untrusted_writer_sid(problem: str | None) -> str | None:
    """The SID in a :func:`windows_untrusted_writer_problem` text, or ``None`` for any other problem."""
    if not problem or not problem.startswith(_WINDOWS_UNTRUSTED_WRITER):
        return None
    sid = problem[len(_WINDOWS_UNTRUSTED_WRITER) :]
    if sid.startswith("S-1-") and all(char in "0123456789-" for char in sid[4:]) and len(sid) > 4:
        return sid
    return None


def windows_acl_write_error(
    path: str | os.PathLike[str],
    *,
    trust_administrators: bool = False,
) -> str | None:
    """Return why an untrusted SID can write *path*, or ``None`` when safe.

    Only the current user (who must own *path*), OWNER RIGHTS and LocalSystem
    may hold write rights. ``trust_administrators`` is for a folder or file
    DefenseClaw did not create, such as ``~\\.local\\bin``: it applies the
    one Windows owner trust set of :func:`windows_acl_custody_write_error`,
    whose owners and writers also include BUILTIN Administrators and
    TrustedInstaller (cowork-1-0-8 GAP-0085).
    """
    if trust_administrators:
        return windows_acl_custody_write_error(path, allow_current_user=True)
    if os.name != "nt":
        return None
    try:
        owner_sid, null_dacl, entries = _windows_acl_snapshot(os.fspath(path))
    except OSError as exc:
        return f"cannot read Windows ACL ({exc})"
    if null_dacl:
        return "ACL grants write access to Everyone (null DACL)"

    try:
        current_sid = _windows_current_user_sid()
    except OSError:
        return "current user SID could not be resolved"
    if not current_sid:
        return "current user SID could not be resolved"
    if owner_sid != current_sid:
        return f"owner SID {owner_sid or '<unknown>'} is not the current user"

    trusted = {"S-1-3-4", "S-1-5-18", current_sid}  # OWNER RIGHTS, LocalSystem, current user
    write_mask = 0x10000000 | 0x40000000 | 0x000D0156
    for permissions, access_mode, inheritance, sid in entries:
        if access_mode not in (1, 2) or not permissions & write_mask:
            continue
        if sid in trusted:
            continue
        if sid == "S-1-3-0" and inheritance & 0x08:
            continue
        return windows_untrusted_writer_problem(sid)
    return None


def windows_acl_custody_write_error(
    path: str | os.PathLike[str],
    *,
    allow_current_user: bool,
    require_current_user_owner: bool = False,
    ancestor_replace_only: bool = False,
) -> str | None:
    """Return why a path is outside trusted Windows write custody.

    Private credential files use :func:`windows_acl_write_error`, which
    deliberately requires current-user ownership. Executable and ancestor
    custody must also admit objects owned by Windows itself. This validator
    accepts only LocalSystem, BUILTIN\\Administrators, TrustedInstaller, and
    optionally the current user as owners or write-capable trustees. Runtime
    state can additionally require current-user ownership while still
    admitting Windows system controllers as write-capable trustees.
    """
    if os.name != "nt":
        return None
    try:
        owner_sid, null_dacl, entries = _windows_acl_snapshot(os.fspath(path))
    except OSError as exc:
        return f"cannot read Windows ACL ({exc})"
    if null_dacl:
        return "ACL grants write access to Everyone (null DACL)"

    current_sid = ""
    trust_current_user = allow_current_user or require_current_user_owner
    if trust_current_user:
        try:
            current_sid = _windows_current_user_sid()
        except OSError:
            return "current user SID could not be resolved"
        if not current_sid:
            return "current user SID could not be resolved"
    system_controllers = set(_WINDOWS_TRUSTED_SYSTEM_CONTROLLER_SIDS)
    if require_current_user_owner and owner_sid != current_sid:
        return f"owner SID {owner_sid or '<unknown>'} is not the current user"
    if not require_current_user_owner and (problem := windows_owner_problem(owner_sid, current_sid)):
        return problem

    trusted_writers = system_controllers | {
        "S-1-3-4",  # OWNER RIGHTS, constrained by the owner check above
        owner_sid,
    }
    if trust_current_user:
        trusted_writers.add(current_sid)
    write_mask = _WINDOWS_CUSTODY_WRITE_MASK
    ancestor_replace_mask = 0x10000000 | 0x40000000 | 0x00010000 | 0x00040000 | 0x00080000 | 0x40
    for permissions, access_mode, inheritance, sid in entries:
        if access_mode not in (1, 2):
            continue
        effective_write_mask = write_mask
        if ancestor_replace_only and inheritance & 0x08:
            continue  # INHERIT_ONLY_ACE does not apply to this directory.
        if ancestor_replace_only and sid != "S-1-1-0":
            effective_write_mask = ancestor_replace_mask
        if not permissions & effective_write_mask:
            continue
        if sid in trusted_writers:
            continue
        if sid == "S-1-3-0" and inheritance & 0x08:
            continue
        return windows_untrusted_writer_problem(sid)
    return None


def windows_acl_confidentiality_error(path: str | os.PathLike[str]) -> str | None:
    """Return why *path* does not have a private Windows DACL.

    ``windows_acl_write_error`` protects integrity, but a secret-bearing file
    can still be unsafe when another principal has read-only access.  This
    stricter validator accepts effective read/write grants only for the current
    owner, Owner Rights, and LocalSystem.  Inherit-only ACEs do not apply to the
    file itself and are therefore ignored.

    Non-Windows callers receive ``None`` so cross-platform permission checks can
    use this helper without importing Win32 APIs.
    """
    if os.name != "nt":
        return None
    try:
        owner_sid, null_dacl, entries = _windows_acl_snapshot(os.fspath(path))
    except OSError as exc:
        return f"cannot read Windows ACL ({exc})"
    if null_dacl:
        return "ACL grants read/write access to Everyone (null DACL)"

    try:
        current_sid = _windows_current_user_sid()
    except OSError:
        return "current user SID could not be resolved"
    if not current_sid:
        return "current user SID could not be resolved"
    if owner_sid != current_sid:
        return f"owner SID {owner_sid or '<unknown>'} is not the current user"

    trusted = {"S-1-3-4", "S-1-5-18", current_sid}  # OWNER RIGHTS, LocalSystem, current user
    # Content confidentiality depends on GENERIC_READ/GENERIC_ALL or
    # FILE_READ_DATA. Metadata-only rights such as READ_CONTROL and
    # FILE_READ_ATTRIBUTES do not reveal secret bytes.
    read_mask = 0x80000000 | 0x10000000 | 0x00000001
    write_mask = 0x10000000 | 0x40000000 | 0x000D0156
    inherit_only_ace = 0x08
    for permissions, access_mode, inheritance, sid in entries:
        if access_mode not in (1, 2) or inheritance & inherit_only_ace:
            continue
        if sid in trusted:
            continue
        if permissions & read_mask:
            return f"ACL grants read access to untrusted SID {sid or '<unknown>'}"
        if permissions & write_mask:
            return f"ACL grants write access to untrusted SID {sid or '<unknown>'}"
    if not _windows_acl_has_required_access(path):
        return "owner/SYSTEM effective access is missing"
    return None


def guard_private_dacl_error(
    owner_sid: str,
    null_dacl: bool,
    entries: list[tuple[int, int, int, str]],
    current_sid: str,
) -> str | None:
    """Apply the Go guard's private-file DACL rule to one ACL snapshot.

    This is ``privateSecurityDescriptorIsSafeForSubject`` in
    internal/safefile/protect_windows.go for a non-impersonated caller: the
    current user owns the object; no allow entry with a non-empty mask names
    anyone but the current user, OWNER RIGHTS or LocalSystem (read-only and
    inherit-only grants included); no deny entry with a non-empty mask names
    one of those three; and both the owner and LocalSystem hold a grant.
    *entries* are ``(mask, access_mode, ace_flags, sid)`` as returned by
    ``_windows_acl_snapshot`` (access mode 1 allows, 3 denies).
    """
    system, owner_rights = "S-1-5-18", "S-1-3-4"
    if not current_sid:
        return "current user SID could not be resolved"
    if null_dacl:
        return "ACL is a null DACL"
    if owner_sid != current_sid:
        return f"owner SID {owner_sid or '<unknown>'} is not the current user"
    found_owner, found_system = False, current_sid == system
    for mask, access_mode, _flags, sid in entries:
        if not mask:
            continue
        if access_mode == 3:
            if sid in {current_sid, system, owner_rights}:
                return f"ACL denies access to {sid}"
            continue
        if access_mode not in (1, 2):
            return f"ACL has an entry the guard cannot read for {sid or '<unknown>'}"
        if sid in {current_sid, owner_rights}:
            found_owner = True
        elif sid == system:
            found_system = True
        else:
            return f"ACL grants access to untrusted SID {sid or '<unknown>'}"
    if not (found_owner and found_system):
        return "owner/SYSTEM access missing"
    return None


def windows_guard_private_file_error(path: str | os.PathLike[str]) -> str | None:
    """Return why the Go guard would refuse *path* as a private file, or ``None``.

    Mirrors ``safefile.ValidatePrivateFile`` on Windows: no reparse point on
    the path or any ancestor, a regular file, owned by the current user, and
    a DACL that passes :func:`guard_private_dacl_error`. Non-Windows callers
    get ``None``; POSIX callers check the mode bits themselves.
    """
    if os.name != "nt":
        return None
    target = os.path.abspath(os.fspath(path))
    try:
        reject_reparse_path(target)
        info = os.lstat(target)
    except OSError as exc:
        return f"cannot inspect {target} ({exc})"
    if not stat.S_ISREG(info.st_mode):
        return "not a regular file"
    try:
        owner_sid, null_dacl, entries = _windows_acl_snapshot(target)
        current_sid = _windows_current_user_sid()
    except OSError as exc:
        return f"cannot read Windows ACL ({exc})"
    return guard_private_dacl_error(owner_sid, null_dacl, entries, current_sid)


def windows_acl_custody_confidentiality_error(
    path: str | os.PathLike[str], *, allow_inheritable: bool = False
) -> str | None:
    """Validate a current-user secret managed by Windows system controllers.

    The gateway's connector-token trust model admits the current user,
    LocalSystem, BUILTIN\\Administrators, and TrustedInstaller so the same
    managed credential survives user and service lifecycle transitions.
    Generic user-secret validation remains stricter; this predicate is for
    that managed-token boundary only. Every other effective read or write ACE,
    a foreign owner, an inheritable or null DACL, or missing owner/SYSTEM access
    still fails. ``allow_inheritable`` skips only the inheritance check, to
    tell a file that just needs its DACL sealed from one that is exposed.
    """

    if os.name != "nt":
        return None
    try:
        owner_sid, null_dacl, entries = _windows_acl_snapshot(os.fspath(path))
    except OSError as exc:
        return f"cannot read Windows ACL ({exc})"
    if null_dacl:
        return "ACL grants read/write access to Everyone (null DACL)"

    try:
        current_sid = _windows_current_user_sid()
    except OSError:
        return "current user SID could not be resolved"
    if not current_sid:
        return "current user SID could not be resolved"
    if owner_sid != current_sid:
        return f"owner SID {owner_sid or '<unknown>'} is not the current user"
    try:
        dacl_protected = allow_inheritable or _windows_dacl_is_protected(path)
    except OSError as exc:
        return f"cannot inspect Windows DACL protection ({exc})"
    if not dacl_protected:
        return "Windows DACL is inheritable"

    trusted = set(_WINDOWS_TRUSTED_SYSTEM_CONTROLLER_SIDS) | {
        "S-1-3-4",  # OWNER RIGHTS, constrained by the owner check above
        current_sid,
    }
    # Keep exact parity with the gateway's otlpWindowsRejectUntrustedReadACEs:
    # GENERIC_{READ,ALL,EXECUTE}, FILE_READ_{DATA,EA,ATTRIBUTES}, FILE_EXECUTE.
    read_mask = 0x80000000 | 0x10000000 | 0x20000000 | 0x00000001 | 0x00000008 | 0x00000080 | 0x00000020
    write_mask = 0x10000000 | 0x40000000 | 0x000D0156
    inherit_only_ace = 0x08
    for permissions, access_mode, inheritance, sid in entries:
        if access_mode not in (1, 2) or inheritance & inherit_only_ace or sid in trusted:
            continue
        if permissions & read_mask:
            return f"ACL grants read access to untrusted SID {sid or '<unknown>'}"
        if permissions & write_mask:
            return f"ACL grants write access to untrusted SID {sid or '<unknown>'}"
    if not _windows_acl_has_required_access(path):
        return "owner/SYSTEM effective access is missing"
    return None


def _protect_private_directory(path: str) -> None:
    if os.name != "nt":
        if os.stat(path).st_mode & 0o077:
            os.chmod(path, 0o700)
        return
    owner_sid, _null_dacl, _entries = _windows_acl_snapshot(path)
    if owner_sid != _windows_current_user_sid():
        raise OSError(f"refusing to protect foreign-owned directory: {path}")
    problem = windows_acl_write_error(path)
    if problem is not None or not _windows_acl_has_required_access(path):
        try:
            _set_windows_owner_only_acl(path)
        except PermissionError as exc:
            # A managed install's DACL (read-only OWNER RIGHTS) denies the
            # owner WRITE_DAC. When that DACL still admits only this account
            # and Windows itself, the folder is already private: use it as it
            # is instead of locking DefenseClaw out of a folder it set up
            # (GAP-1243). Anything else names the folder and the way out.
            if windows_acl_custody_confidentiality_error(path) is None:
                return
            raise PermissionError(
                exc.errno,
                f"cannot protect private directory {path}: its access control list does not let this "
                "account change it (a managed DefenseClaw install can leave it that way); have an "
                f'administrator reset its access (icacls "{path}" /reset /t), then run the command again',
            ) from exc
        problem = windows_acl_write_error(path)
        if problem is not None:
            raise OSError(f"cannot protect private directory {path}: {problem}")
    else:
        # Freeze an already-safe inherited DACL without changing its ACEs.
        copy_windows_dacl(path, path)


def _validate_unmodified_parent(path: str) -> None:
    """Fail closed when an operator-selected parent is replaceable by others.

    On Windows the parent is a folder DefenseClaw did not create, such as the
    profile folder that holds the Cowork removal marker, so it gets the one
    Windows owner trust set: owned by this account, SYSTEM, BUILTIN
    Administrators or TrustedInstaller, and writable by no one else
    (cowork-1-0-8 GAP-0085).
    """
    if os.name == "nt":
        problem = windows_acl_custody_write_error(path, allow_current_user=True)
        if problem is not None:
            raise OSError(f"unsafe export parent {path}: {problem}")
        return
    info = os.stat(path)
    # The parent is a folder the operator or an agent made under its umask (an
    # export target, OpenCode's ~/.config/opencode): group write by the owner's
    # own private group is the owner's (GAP-0053).
    writable_by_others = other_accounts_can_write(path, info)
    sticky = info.st_mode & 0o1000
    if writable_by_others and not sticky:
        raise OSError(f"unsafe group/world-writable export parent: {path}")


def _make_private_directories(path: str) -> None:
    """Create missing Windows directories with the policy DACL at creation."""
    if os.name != "nt":
        os.makedirs(path, mode=0o700, exist_ok=True)
        return
    import ctypes
    from ctypes import wintypes

    missing: list[str] = []
    current = os.path.abspath(path)
    while not os.path.lexists(current):
        missing.append(current)
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
    if not missing:
        return

    class _SecurityAttributes(ctypes.Structure):
        _fields_ = [
            ("nLength", wintypes.DWORD),
            ("lpSecurityDescriptor", wintypes.LPVOID),
            ("bInheritHandle", wintypes.BOOL),
        ]

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    convert = advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW
    convert.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.DWORD),
    ]
    convert.restype = wintypes.BOOL
    create_directory = kernel32.CreateDirectoryW
    create_directory.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(_SecurityAttributes)]
    create_directory.restype = wintypes.BOOL
    local_free = kernel32.LocalFree
    local_free.argtypes = [wintypes.HLOCAL]
    local_free.restype = wintypes.HLOCAL

    descriptor = wintypes.LPVOID()
    sddl = _windows_private_directory_sddl()
    if not convert(sddl, 1, ctypes.byref(descriptor), None):
        raise ctypes.WinError(ctypes.get_last_error())
    attributes = _SecurityAttributes(ctypes.sizeof(_SecurityAttributes), descriptor, False)
    try:
        for directory in reversed(missing):
            if not create_directory(directory, ctypes.byref(attributes)):
                error = ctypes.get_last_error()
                if error != 183:  # ERROR_ALREADY_EXISTS: validate the racing object below.
                    raise ctypes.WinError(error)
            _reject_reparse_path(directory, allow_missing=False)
            _protect_private_directory(directory)
    finally:
        local_free(descriptor)


def _windows_private_directory_sddl() -> str:
    """Build the creation descriptor for a current-user-owned directory."""
    owner_sid = _windows_current_user_sid()
    return f"O:{owner_sid}D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;OW)"


@contextmanager
def _hold_windows_directory(path: str):
    """Hold the parent without delete sharing so it cannot be swapped mid-write."""
    if os.name != "nt":
        yield
        return
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create_file.restype = wintypes.HANDLE
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL
    handle = create_file(
        path,
        0x00000001 | 0x00000080,  # FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES
        0x00000001 | 0x00000002,  # FILE_SHARE_READ | FILE_SHARE_WRITE; deliberately no DELETE
        None,
        3,  # OPEN_EXISTING
        0x02000000 | 0x00200000,  # BACKUP_SEMANTICS | OPEN_REPARSE_POINT
        None,
    )
    if handle == wintypes.HANDLE(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        yield
    finally:
        close_handle(handle)


def _windows_acl_has_required_access(path: str | os.PathLike[str]) -> bool:
    owner_sid, null_dacl, entries = _windows_acl_snapshot(os.fspath(path))
    try:
        current_sid = _windows_current_user_sid()
    except OSError:
        return False
    if not current_sid or null_dacl or owner_sid != current_sid:
        return False

    file_read_data = 0x00000001
    file_write_data = 0x00000002
    required_content = file_read_data | file_write_data
    generic_all = 0x10000000
    generic_read = 0x80000000
    generic_write = 0x40000000
    inherit_only_ace = 0x08

    def _content_mask(permissions: int) -> int:
        concrete = permissions & required_content
        if permissions & generic_all:
            concrete |= required_content
        if permissions & generic_read:
            concrete |= file_read_data
        if permissions & generic_write:
            concrete |= file_write_data
        return concrete

    # Without complete token-group expansion for both the interactive owner
    # and LocalSystem, an applicable group deny cannot be proven irrelevant.
    # Reject it conservatively instead of preserving an unusable secret DACL.
    for permissions, access_mode, inheritance, _sid in entries:
        if access_mode == 3 and not inheritance & inherit_only_ace and _content_mask(permissions):
            return False

    def _has_content_access(principal_sids: set[str]) -> bool:
        allowed_content = 0
        for permissions, access_mode, inheritance, sid in entries:
            if inheritance & inherit_only_ace or sid not in principal_sids:
                continue
            if access_mode in (1, 2):
                allowed_content |= _content_mask(permissions)
        return allowed_content == required_content

    required_owner_sids = {current_sid, "S-1-3-4"}
    return _has_content_access({"S-1-5-18"}) and _has_content_access(required_owner_sids)


def _windows_current_user_sid() -> str:
    """Return the current process token user's SID string."""
    if os.name != "nt":
        raise OSError("Windows access tokens are unavailable on this platform")
    import ctypes
    from ctypes import wintypes

    token_query = 0x0008
    token_user_class = 1
    error_insufficient_buffer = 122
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_current_process = kernel32.GetCurrentProcess
    get_current_process.argtypes = []
    get_current_process.restype = wintypes.HANDLE
    open_process_token = advapi32.OpenProcessToken
    open_process_token.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    open_process_token.restype = wintypes.BOOL
    get_token_information = advapi32.GetTokenInformation
    get_token_information.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    get_token_information.restype = wintypes.BOOL
    sid_to_string = advapi32.ConvertSidToStringSidW
    sid_to_string.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    sid_to_string.restype = wintypes.BOOL
    local_free = kernel32.LocalFree
    local_free.argtypes = [wintypes.HLOCAL]
    local_free.restype = wintypes.HLOCAL
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL
    token = wintypes.HANDLE()
    if not open_process_token(get_current_process(), token_query, ctypes.byref(token)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        needed = wintypes.DWORD()
        ctypes.set_last_error(0)
        get_token_information(token, token_user_class, None, 0, ctypes.byref(needed))
        if ctypes.get_last_error() != error_insufficient_buffer:
            raise ctypes.WinError(ctypes.get_last_error())
        buffer = ctypes.create_string_buffer(needed.value)
        if not get_token_information(token, token_user_class, buffer, needed, ctypes.byref(needed)):
            raise ctypes.WinError(ctypes.get_last_error())
        sid_pointer = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p)).contents.value
        value = wintypes.LPWSTR()
        if not sid_to_string(sid_pointer, ctypes.byref(value)):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            return value.value or ""
        finally:
            local_free(value)
    finally:
        close_handle(token)


def _reject_reparse_chain(path: str) -> None:
    if os.name != "nt":
        # POSIX systems intentionally ship symlinked system ancestors (for
        # example macOS /tmp -> /private/tmp). The caller-owned leaf must not
        # itself be a symlink, while Windows requires checking every ancestor
        # because a junction is transparent to ordinary path operations.
        _reject_reparse_path(os.path.abspath(path), allow_missing=True)
        return
    current = Path(os.path.abspath(path))
    while True:
        _reject_reparse_path(os.fspath(current), allow_missing=True)
        if current.parent == current:
            break
        current = current.parent


def _reject_reparse_path(path: str, *, allow_missing: bool) -> os.stat_result | None:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        if allow_missing:
            return None
        raise
    if os.path.islink(path):
        raise UnsafePathError(
            f"refusing sensitive write through symlink: {path}",
            code=UNSAFE_PATH_SYMLINK_OR_REPARSE,
        )
    attributes = getattr(info, "st_file_attributes", 0)
    if attributes & 0x400:  # FILE_ATTRIBUTE_REPARSE_POINT
        raise UnsafePathError(
            f"refusing sensitive write through reparse point: {path}",
            code=UNSAFE_PATH_SYMLINK_OR_REPARSE,
        )
    return info


def _windows_acl_snapshot(path: str) -> tuple[str, bool, list[tuple[int, int, int, str]]]:
    """Read the owner SID and every DACL ACE using native Win32 APIs."""
    if os.name != "nt":
        raise OSError("Windows ACLs are unavailable on this platform")
    import ctypes
    from ctypes import wintypes

    class _Acl(ctypes.Structure):
        _fields_ = [
            ("AclRevision", wintypes.BYTE),
            ("Sbz1", wintypes.BYTE),
            ("AclSize", wintypes.WORD),
            ("AceCount", wintypes.WORD),
            ("Sbz2", wintypes.WORD),
        ]

    class _AceHeader(ctypes.Structure):
        _fields_ = [
            ("AceType", wintypes.BYTE),
            ("AceFlags", wintypes.BYTE),
            ("AceSize", wintypes.WORD),
        ]

    class _AccessAce(ctypes.Structure):
        _fields_ = [
            ("Header", _AceHeader),
            ("Mask", wintypes.DWORD),
            ("SidStart", wintypes.DWORD),
        ]

    access_allowed_ace_type = 0
    access_denied_ace_type = 1
    access_modes = {
        access_allowed_ace_type: 1,  # GRANT_ACCESS
        access_denied_ace_type: 3,  # DENY_ACCESS
    }

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_security = advapi32.GetNamedSecurityInfoW
    get_security.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    get_security.restype = wintypes.DWORD
    # GetExplicitEntriesFromAclW omits inherited ACEs. Setup deliberately
    # publishes its executable tree with inherited read/execute access, so
    # custody checks must enumerate the exact DACL instead.
    get_ace = advapi32.GetAce
    get_ace.argtypes = [
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    get_ace.restype = wintypes.BOOL
    sid_to_string = advapi32.ConvertSidToStringSidW
    sid_to_string.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    sid_to_string.restype = wintypes.BOOL
    local_free = kernel32.LocalFree
    local_free.argtypes = [ctypes.c_void_p]
    local_free.restype = ctypes.c_void_p

    def _sid_string(sid: int | None) -> str:
        if not sid:
            return ""
        value = wintypes.LPWSTR()
        if not sid_to_string(ctypes.c_void_p(sid), ctypes.byref(value)):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            return value.value or ""
        finally:
            local_free(ctypes.cast(value, ctypes.c_void_p))

    owner = ctypes.c_void_p()
    dacl = ctypes.c_void_p()
    descriptor = ctypes.c_void_p()
    result = get_security(
        path,
        1,
        0x00000001 | 0x00000004,
        ctypes.byref(owner),
        None,
        ctypes.byref(dacl),
        None,
        ctypes.byref(descriptor),
    )
    if result:
        raise OSError(result, ctypes.FormatError(result), path)
    try:
        owner_sid = _sid_string(owner.value)
        if not dacl.value:
            return owner_sid, True, []
        acl = ctypes.cast(dacl, ctypes.POINTER(_Acl)).contents
        entries = []
        for index in range(acl.AceCount):
            ace_pointer = ctypes.c_void_p()
            if not get_ace(dacl, index, ctypes.byref(ace_pointer)):
                raise ctypes.WinError(ctypes.get_last_error())
            ace = ctypes.cast(ace_pointer, ctypes.POINTER(_AccessAce)).contents
            if ace.Header.AceSize < ctypes.sizeof(_AccessAce):
                raise OSError(f"invalid Windows DACL ACE size at index {index}: {path}")
            access_mode = access_modes.get(ace.Header.AceType)
            if access_mode is None:
                raise OSError(f"unsupported Windows DACL ACE type {ace.Header.AceType}: {path}")
            sid_pointer = ace_pointer.value + _AccessAce.SidStart.offset
            entries.append(
                (
                    int(ace.Mask),
                    access_mode,
                    int(ace.Header.AceFlags),
                    _sid_string(sid_pointer),
                )
            )
        return owner_sid, False, entries
    finally:
        if descriptor.value:
            local_free(descriptor)


def _set_windows_owner_only_acl(path: str, *, set_owner: bool = False) -> None:
    """Replace inherited access with the protected owner/SYSTEM policy DACL."""
    import ctypes
    from ctypes import wintypes

    sddl_revision_1 = 1
    dacl_security_information = 0x00000004
    # D:P protects the DACL from inheritance. OW is the Windows Owner Rights
    # SID; SY retains LocalSystem access required by the product policy.
    # Private directories must propagate the same policy to existing and new
    # descendants. Without OI/CI, Windows recalculates an existing child's
    # inherited ACL against a parent with no inheritable ACEs and can leave the
    # child with an empty DACL (the managed venv became inaccessible after init).
    inheritance = "OICI" if os.path.isdir(path) else ""
    owner_only_sddl = f"D:P(A;{inheritance};FA;;;SY)(A;{inheritance};FA;;;OW)"

    if set_owner:
        _set_windows_current_user_owner(path)

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    convert = advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW
    convert.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.DWORD),
    ]
    convert.restype = wintypes.BOOL

    set_file_security = advapi32.SetFileSecurityW
    set_file_security.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.LPVOID,
    ]
    set_file_security.restype = wintypes.BOOL

    local_free = kernel32.LocalFree
    local_free.argtypes = [wintypes.HLOCAL]
    local_free.restype = wintypes.HLOCAL

    descriptor = wintypes.LPVOID()
    if not convert(
        owner_only_sddl,
        sddl_revision_1,
        ctypes.byref(descriptor),
        None,
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        if not set_file_security(path, dacl_security_information, descriptor):
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        local_free(descriptor)


def _set_windows_current_user_owner(path: str) -> None:
    """Assign a DefenseClaw-managed path to the current token user.

    A path the user already owns is left alone: setting the owner needs
    WRITE_OWNER even when it does not change, and a folder that grants the
    user Modify, such as a per-session TEMP folder on a Windows server, does
    not grant it.
    """
    try:
        already_owned = _windows_acl_snapshot(path)[0] == _windows_current_user_sid()
    except OSError:
        already_owned = False
    if already_owned:
        return
    import ctypes
    from ctypes import wintypes

    se_file_object = 1
    owner_security_information = 0x00000001
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    convert = advapi32.ConvertStringSidToSidW
    convert.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(wintypes.LPVOID)]
    convert.restype = wintypes.BOOL
    set_security = advapi32.SetNamedSecurityInfoW
    set_security.argtypes = [
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.LPVOID,
    ]
    set_security.restype = wintypes.DWORD
    local_free = ctypes.WinDLL("kernel32", use_last_error=True).LocalFree
    local_free.argtypes = [wintypes.HLOCAL]
    local_free.restype = wintypes.HLOCAL

    owner = wintypes.LPVOID()
    if not convert(_windows_current_user_sid(), ctypes.byref(owner)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        result = set_security(
            path,
            se_file_object,
            owner_security_information,
            owner,
            None,
            None,
            None,
        )
        if result:
            raise ctypes.WinError(result)
    finally:
        local_free(owner)
