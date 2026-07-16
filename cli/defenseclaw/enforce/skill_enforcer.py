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

"""SkillEnforcer — filesystem quarantine for skills.

Mirrors internal/enforce/skill_enforcer.go.
"""

from __future__ import annotations

import contextlib
import ctypes
import errno
import hashlib
import json
import ntpath
import os
import posixpath
import shutil
import stat
import sys
import uuid
from dataclasses import dataclass
from typing import Any, BinaryIO

from defenseclaw import file_permissions
from defenseclaw.file_permissions import make_private_directory

_RUNTIME_ISOLATION_PURPOSE = "runtime-isolation"
_RUNTIME_ISOLATION_DIRECTORY = "runtime-isolation"
_LEGACY_QUARANTINE_PURPOSES = {"operator", "watcher-enforcement"}


@dataclass(frozen=True)
class _PathIdentity:
    """Stable root identity that an atomic rename must preserve."""

    device: int
    inode: int
    file_type: int


class SkillEnforcer:
    def __init__(self, quarantine_dir: str) -> None:
        self.quarantine_dir = os.path.abspath(os.path.join(quarantine_dir, "skills"))
        if os.name != "nt":
            # Standard macOS temporary paths may contain an ancestor alias
            # such as /var -> /private/var. Canonicalize before the no-follow
            # checks so the held-dirfd boundary uses the physical path.
            self.quarantine_dir = os.path.realpath(self.quarantine_dir)
        make_private_directory(self.quarantine_dir)

    @staticmethod
    def _is_link_or_reparse(path: str) -> bool:
        try:
            info = os.lstat(path)
        except OSError:
            return False
        reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        attributes = getattr(info, "st_file_attributes", 0)
        return stat.S_ISLNK(info.st_mode) or bool(attributes & reparse_flag)

    @staticmethod
    def _safe_segment(value: str) -> str | None:
        if not isinstance(value, str):
            return None
        safe = value.strip()
        if (
            not safe
            or safe != value
            or safe in (".", "..")
            or any(char in safe for char in ("/", "\\", "\x00"))
            or ntpath.isabs(safe)
            or posixpath.isabs(safe)
        ):
            return None
        return safe

    @staticmethod
    def _contained(path: str, root: str, *, allow_equal: bool = False) -> bool:
        try:
            path_abs = os.path.abspath(path)
            root_abs = os.path.abspath(root)
            common = os.path.commonpath((path_abs, root_abs))
        except (OSError, ValueError):
            return False
        if os.path.normcase(common) != os.path.normcase(root_abs):
            return False
        return allow_equal or os.path.normcase(path_abs) != os.path.normcase(root_abs)

    @classmethod
    def _existing_path_is_safe(cls, path: str, stop_at: str | None = None) -> bool:
        current = os.path.abspath(path)
        stop = os.path.abspath(stop_at) if stop_at else os.path.splitdrive(current)[0] + os.sep
        while True:
            if os.path.lexists(current) and cls._is_link_or_reparse(current):
                return False
            if os.path.normcase(current) == os.path.normcase(stop):
                return True
            parent = os.path.dirname(current)
            if parent == current:
                return stop_at is None
            current = parent

    @classmethod
    def _validate_tree(cls, root: str) -> bool:
        if not os.path.lexists(root) or cls._is_link_or_reparse(root):
            return False
        try:
            root_info = os.lstat(root)
            if stat.S_ISREG(root_info.st_mode):
                return True
            if not stat.S_ISDIR(root_info.st_mode):
                return False
            for current, dirs, files in os.walk(root, topdown=True, followlinks=False):
                if cls._is_link_or_reparse(current):
                    return False
                for name in (*dirs, *files):
                    candidate = os.path.join(current, name)
                    info = os.lstat(candidate)
                    if cls._is_link_or_reparse(candidate):
                        return False
                    if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                        return False
        except OSError:
            return False
        return True

    @staticmethod
    def _hash_file(handle: BinaryIO, digest: Any) -> None:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                return
            digest.update(chunk)

    @classmethod
    def content_hash(cls, path: str) -> str | None:
        """Return a deterministic SHA-256 tree identity for a safe asset."""
        if not cls._validate_tree(path):
            return None
        root = os.path.abspath(path)
        digest = hashlib.sha256()
        try:
            root_info = os.lstat(root)
            if stat.S_ISREG(root_info.st_mode):
                digest.update(b"F\0.\0")
                digest.update(f"{stat.S_IMODE(root_info.st_mode):04o}\0".encode("ascii"))
                with open(root, "rb") as handle:
                    cls._hash_file(handle, digest)
                return digest.hexdigest()

            for current, dirs, files in os.walk(root, topdown=True, followlinks=False):
                dirs.sort()
                files.sort()
                rel_dir = os.path.relpath(current, root).replace(os.sep, "/")
                info = os.lstat(current)
                digest.update(b"D\0")
                digest.update(rel_dir.encode("utf-8", errors="surrogateescape"))
                digest.update(b"\0")
                digest.update(f"{stat.S_IMODE(info.st_mode):04o}\0".encode("ascii"))
                for name in files:
                    candidate = os.path.join(current, name)
                    info = os.lstat(candidate)
                    rel = os.path.relpath(candidate, root).replace(os.sep, "/")
                    digest.update(b"F\0")
                    digest.update(rel.encode("utf-8", errors="surrogateescape"))
                    digest.update(b"\0")
                    digest.update(f"{stat.S_IMODE(info.st_mode):04o}\0".encode("ascii"))
                    with open(candidate, "rb") as handle:
                        cls._hash_file(handle, digest)
        except OSError:
            return None
        return digest.hexdigest()

    @classmethod
    def ownership_marker(cls, path: str) -> str:
        """Capture non-secret ownership/mode markers needed for recovery audit."""
        try:
            info = os.lstat(path)
        except OSError:
            return "{}"
        marker = {
            "mode": stat.S_IMODE(info.st_mode),
            "uid": getattr(info, "st_uid", None),
            "gid": getattr(info, "st_gid", None),
            "device": int(info.st_dev),
            "inode": int(info.st_ino),
            "type": stat.S_IFMT(info.st_mode),
        }
        if os.name == "nt":
            acl_fingerprint = cls._windows_acl_fingerprint(path)
            if acl_fingerprint is None:
                return "{}"
            marker["windows_acl_sha256"] = acl_fingerprint
        return json.dumps(marker, sort_keys=True, separators=(",", ":"))

    @classmethod
    def _windows_acl_fingerprint(cls, path: str) -> str | None:
        """Hash owner/DACL state for every non-reparse entry in a skill tree."""
        if os.name != "nt":
            return None
        candidates = [path]
        try:
            if os.path.isdir(path):
                for current, directories, filenames in os.walk(
                    path, topdown=True, followlinks=False,
                ):
                    directories.sort()
                    filenames.sort()
                    candidates.extend(
                        os.path.join(current, name)
                        for name in [*directories, *filenames]
                    )
            digest = hashlib.sha256()
            for candidate in candidates:
                if cls._is_link_or_reparse(candidate):
                    return None
                owner, null_dacl, entries = file_permissions._windows_acl_snapshot(  # noqa: SLF001
                    candidate,
                )
                relative = os.path.relpath(candidate, path).replace(os.sep, "/")
                encoded = json.dumps(
                    [relative, owner, null_dacl, entries],
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
                digest.update(encoded)
                digest.update(b"\0")
        except OSError:
            return None
        return digest.hexdigest()

    @classmethod
    def _windows_tree_acl_is_safe(cls, path: str) -> bool:
        if os.name != "nt":
            return True
        candidates = [path]
        try:
            if os.path.isdir(path):
                for current, directories, filenames in os.walk(
                    path, topdown=True, followlinks=False,
                ):
                    directories.sort()
                    filenames.sort()
                    candidates.extend(
                        os.path.join(current, name)
                        for name in [*directories, *filenames]
                    )
            current_sid = file_permissions._windows_current_user_sid()  # noqa: SLF001
            trusted = {
                current_sid,
                "S-1-3-4",  # Owner Rights
                "S-1-5-18",  # LocalSystem
                "S-1-5-32-544",  # local Administrators
            }
            write_mask = 0x10000000 | 0x40000000 | 0x000D0156
            for candidate in candidates:
                if cls._is_link_or_reparse(candidate):
                    return False
                owner, null_dacl, entries = file_permissions._windows_acl_snapshot(  # noqa: SLF001
                    candidate,
                )
                if null_dacl or owner != current_sid:
                    return False
                for permissions, access_mode, _inheritance, sid in entries:
                    if (
                        access_mode in (1, 2)
                        and permissions & write_mask
                        and sid not in trusted
                    ):
                        return False
            return True
        except OSError:
            return False

    @classmethod
    def matches_ownership_marker(cls, path: str, marker_json: str) -> bool:
        """Match a durable marker to the same filesystem object identity."""
        try:
            marker = json.loads(marker_json or "{}")
        except (TypeError, ValueError):
            return False
        current_json = cls.ownership_marker(path)
        if current_json == "{}":
            return False
        try:
            current = json.loads(current_json)
            return marker == current
        except (TypeError, ValueError):
            return False

    @classmethod
    def runtime_ownership_marker(
        cls, original_marker_json: str, isolated_path: str,
    ) -> str | None:
        """Bind original and isolated ownership/ACL states after a safe move."""
        try:
            original = json.loads(original_marker_json or "{}")
            isolated = json.loads(cls.ownership_marker(isolated_path))
        except (TypeError, ValueError):
            return None
        if (
            not original
            or not isolated
            or not cls._runtime_acl_transition_is_safe(
                isolated_path, original_marker_json,
            )
        ):
            return None
        return json.dumps(
            {"original": original, "isolated": isolated},
            sort_keys=True,
            separators=(",", ":"),
        )

    @classmethod
    def matches_runtime_ownership_marker(
        cls, path: str, marker_json: str, *, isolated: bool,
    ) -> bool:
        """Match the exact recorded side of a runtime-isolation transition."""
        try:
            marker = json.loads(marker_json or "{}")
        except (TypeError, ValueError):
            return False
        component = marker.get("isolated" if isolated else "original")
        if not isinstance(component, dict):
            # A pending pre-move journal contains only the original marker.
            if isolated:
                return False
            component = marker
        current_json = cls.ownership_marker(path)
        if current_json == "{}":
            return False
        try:
            return component == json.loads(current_json)
        except (TypeError, ValueError):
            return False

    @classmethod
    def _runtime_acl_transition_is_safe(
        cls, isolated_path: str, original_marker_json: str,
    ) -> bool:
        """Allow only Windows' safe inherited-DACL transition on isolation."""
        if os.name != "nt":
            return cls.matches_ownership_marker(
                isolated_path, original_marker_json,
            )
        try:
            original = json.loads(original_marker_json or "{}")
            current = json.loads(cls.ownership_marker(isolated_path))
        except (TypeError, ValueError):
            return False
        if not original or not current:
            return False
        original_without_acl = dict(original)
        current_without_acl = dict(current)
        if not original_without_acl.pop("windows_acl_sha256", ""):
            return False
        if not current_without_acl.pop("windows_acl_sha256", ""):
            return False
        return (
            original_without_acl == current_without_acl
            and cls._windows_tree_acl_is_safe(isolated_path)
        )

    @classmethod
    def _path_identity(
        cls, path: str, *, require_safe_type: bool = True,
    ) -> _PathIdentity | None:
        """Return the non-content identity bound to one directory entry."""
        try:
            info = os.lstat(path)
        except OSError:
            return None
        file_type = stat.S_IFMT(info.st_mode)
        if require_safe_type:
            reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            attributes = getattr(info, "st_file_attributes", 0)
            if (
                stat.S_ISLNK(info.st_mode)
                or bool(attributes & reparse_flag)
                or file_type not in {stat.S_IFREG, stat.S_IFDIR}
            ):
                return None
        return _PathIdentity(
            device=int(info.st_dev),
            inode=int(info.st_ino),
            file_type=file_type,
        )

    @classmethod
    def _identity_matches(cls, path: str, expected: _PathIdentity) -> bool:
        return cls._path_identity(path) == expected

    @classmethod
    def _verified_hash_identity(
        cls, path: str,
    ) -> tuple[str, _PathIdentity] | None:
        """Hash a safe tree while proving its root entry was not replaced."""
        path_abs = os.path.abspath(path)
        if not cls._existing_path_is_safe(path_abs):
            return None
        before = cls._path_identity(path_abs)
        if before is None:
            return None
        content_hash = cls.content_hash(path_abs)
        if content_hash is None or not cls._identity_matches(path_abs, before):
            return None
        return content_hash, before

    @classmethod
    def verified_snapshot(
        cls, path: str,
    ) -> tuple[str, _PathIdentity, str] | None:
        """Capture hash, root identity, and ownership as one verified snapshot."""
        verified = cls._verified_hash_identity(path)
        if verified is None:
            return None
        content_hash, identity = verified
        ownership = cls.ownership_marker(path)
        if ownership == "{}" or not cls._identity_matches(path, identity):
            return None
        return content_hash, identity, ownership

    @staticmethod
    def _same_filesystem(
        source: _PathIdentity, destination_parent: _PathIdentity,
    ) -> bool:
        return source.device == destination_parent.device

    @classmethod
    def _allowed_roots(cls, roots: list[str] | None) -> list[str] | None:
        if not roots:
            return None
        resolved: list[str] = []
        for root in roots:
            root_abs = os.path.abspath(root)
            if os.name != "nt":
                root_abs = os.path.realpath(root_abs)
            if (
                not os.path.isdir(root_abs)
                or not cls._existing_path_is_safe(root_abs)
                or cls._is_link_or_reparse(root_abs)
            ):
                return None
            resolved.append(os.path.realpath(root_abs))
        return resolved

    @classmethod
    def _inside_one_root(cls, path: str, roots: list[str]) -> bool:
        real_path = os.path.realpath(os.path.abspath(path))
        return any(cls._contained(real_path, root) for root in roots)

    @classmethod
    def _outside_all_roots(cls, path: str, roots: list[str]) -> bool:
        real_path = os.path.realpath(os.path.abspath(path))
        return all(
            not cls._contained(real_path, root, allow_equal=True)
            for root in roots
        )

    @classmethod
    def _contains_any_root(cls, path: str, roots: list[str]) -> bool:
        """Reject moving a directory that owns a discovery-root subtree."""
        real_path = os.path.realpath(os.path.abspath(path))
        return any(
            cls._contained(root, real_path, allow_equal=True)
            for root in roots
        )

    def _runtime_isolation_parent(self, connector: str) -> str | None:
        safe_connector = self._safe_segment(connector or "_global")
        if safe_connector is None:
            return None
        parent = os.path.abspath(os.path.join(
            self.quarantine_dir,
            _RUNTIME_ISOLATION_DIRECTORY,
            safe_connector,
        ))
        if not self._contained(parent, self.quarantine_dir):
            return None
        return parent

    def _runtime_destination_valid(
        self, path: str, connector: str, *, require_parent: bool,
    ) -> bool:
        parent = self._runtime_isolation_parent(connector)
        if parent is None:
            return False
        candidate = os.path.abspath(path)
        leaf = os.path.basename(candidate)
        if (
            os.path.normcase(os.path.dirname(candidate))
            != os.path.normcase(parent)
            or len(leaf) != 32
            or any(character not in "0123456789abcdef" for character in leaf)
            or not self._contained(candidate, self.quarantine_dir)
        ):
            return False
        return not require_parent or (
            os.path.isdir(parent)
            and self._existing_path_is_safe(parent, self.quarantine_dir)
        )

    def path_identity(self, path: str) -> _PathIdentity | None:
        """Return the immutable filesystem identity used by atomic moves."""
        return self._path_identity(path)

    def is_runtime_isolation_path(
        self,
        path: str,
        connector: str = "",
        *,
        allowed_roots: list[str] | None,
    ) -> bool:
        """Validate a recorded runtime-isolation path and its root boundary."""
        roots = self._allowed_roots(allowed_roots)
        return bool(
            roots is not None
            and self._runtime_destination_valid(
                path, connector, require_parent=True,
            )
            and self._outside_all_roots(path, roots)
        )

    def runtime_isolation_path(
        self,
        skill_name: str,
        connector: str = "",
        *,
        allowed_roots: list[str] | None,
    ) -> str | None:
        """Allocate a private random destination outside every discovery root."""
        if self._safe_segment(skill_name) is None:
            return None
        roots = self._allowed_roots(allowed_roots)
        parent = self._runtime_isolation_parent(connector)
        if roots is None or parent is None:
            return None
        try:
            if not self._outside_all_roots(parent, roots):
                return None
            make_private_directory(parent)
        except OSError:
            return None
        if (
            not self._existing_path_is_safe(self.quarantine_dir)
            or not self._existing_path_is_safe(parent, self.quarantine_dir)
        ):
            return None
        destination = os.path.join(parent, uuid.uuid4().hex)
        if (
            not self._runtime_destination_valid(
                destination, connector, require_parent=True,
            )
            or os.path.lexists(destination)
        ):
            return None
        return destination

    @staticmethod
    @contextlib.contextmanager
    def _hold_parent_directories(source_parent: str, destination_parent: str):
        """Hold parent identities across the rename when the OS permits it."""
        if os.name == "nt":
            with contextlib.ExitStack() as stack:
                stack.enter_context(
                    file_permissions._hold_windows_directory(source_parent),  # noqa: SLF001
                )
                if os.path.normcase(source_parent) != os.path.normcase(
                    destination_parent,
                ):
                    stack.enter_context(
                        file_permissions._hold_windows_directory(  # noqa: SLF001
                            destination_parent,
                        ),
                    )
                yield None, None
            return

        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        source_fd = os.open(source_parent, flags)
        destination_fd = -1
        try:
            destination_fd = os.open(destination_parent, flags)
            yield source_fd, destination_fd
        finally:
            if destination_fd != -1:
                os.close(destination_fd)
            os.close(source_fd)

    @staticmethod
    def _rename_no_replace(
        source: str,
        destination: str,
        source_dir_fd: int | None,
        destination_dir_fd: int | None,
    ) -> None:
        """Atomically rename without copying or replacing an existing name."""
        if os.path.lexists(destination):
            raise FileExistsError(errno.EEXIST, os.strerror(errno.EEXIST), destination)
        if os.name == "nt":
            # Windows rename is same-volume and refuses an existing target.
            os.rename(source, destination)
            return
        if source_dir_fd is None or destination_dir_fd is None:
            raise OSError(errno.EBADF, "parent directory handles are required")
        libc = ctypes.CDLL(None, use_errno=True)
        if sys.platform == "darwin":
            try:
                rename_exclusive = libc.renameatx_np
            except AttributeError as exc:
                raise OSError(
                    errno.ENOTSUP,
                    "renameatx_np is required for atomic no-replace isolation",
                    destination,
                ) from exc
            rename_exclusive.argtypes = [
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_uint,
            ]
            rename_exclusive.restype = ctypes.c_int
            result = rename_exclusive(
                source_dir_fd,
                os.fsencode(os.path.basename(source)),
                destination_dir_fd,
                os.fsencode(os.path.basename(destination)),
                0x00000004,  # RENAME_EXCL
            )
            if result != 0:
                error = ctypes.get_errno()
                raise OSError(error, os.strerror(error), destination)
            return
        if not sys.platform.startswith("linux"):
            raise OSError(
                errno.ENOTSUP,
                "atomic no-replace rename is unavailable on this platform",
                destination,
            )
        try:
            renameat2 = libc.renameat2
        except AttributeError as exc:
            raise OSError(
                errno.ENOTSUP,
                "renameat2 is required for atomic no-replace isolation",
                destination,
            ) from exc
        renameat2.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        renameat2.restype = ctypes.c_int
        result = renameat2(
            source_dir_fd,
            os.fsencode(os.path.basename(source)),
            destination_dir_fd,
            os.fsencode(os.path.basename(destination)),
            1,  # RENAME_NOREPLACE
        )
        if result != 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error), destination)

    @classmethod
    def _rollback_atomic_move(
        cls,
        moved_path: str,
        original_path: str,
        moved_identity: _PathIdentity | None,
        moved_parent_fd: int | None,
        original_parent_fd: int | None,
    ) -> bool:
        """Rollback only the exact entry moved by this operation."""
        if (
            moved_identity is None
            or os.path.lexists(original_path)
            or cls._path_identity(
                moved_path, require_safe_type=False,
            ) != moved_identity
        ):
            return False
        try:
            cls._rename_no_replace(
                moved_path,
                original_path,
                moved_parent_fd,
                original_parent_fd,
            )
        except OSError:
            return False
        return (
            not os.path.lexists(moved_path)
            and cls._path_identity(
                original_path, require_safe_type=False,
            ) == moved_identity
        )

    def _atomic_runtime_move(
        self,
        source: str,
        destination: str,
        *,
        expected_hash: str,
        expected_ownership_json: str,
        allowed_roots: list[str] | None,
        isolation_roots: list[str] | None,
        source_must_be_discoverable: bool,
    ) -> bool:
        roots = self._allowed_roots(allowed_roots)
        boundary_roots = self._allowed_roots(isolation_roots)
        source_abs = os.path.abspath(source)
        destination_abs = os.path.abspath(destination)
        if os.name != "nt":
            source_abs = os.path.realpath(source_abs)
            destination_abs = os.path.realpath(destination_abs)
        if roots is None or boundary_roots is None:
            return False
        source_inside = self._inside_one_root(source_abs, roots)
        destination_inside = self._inside_one_root(destination_abs, roots)
        source_inside_boundary = self._inside_one_root(
            source_abs, boundary_roots,
        )
        destination_inside_boundary = self._inside_one_root(
            destination_abs, boundary_roots,
        )
        if source_must_be_discoverable:
            if (
                not source_inside
                or destination_inside_boundary
                or self._contains_any_root(source_abs, boundary_roots)
            ):
                return False
        elif (
            source_inside_boundary
            or not destination_inside
            or self._contains_any_root(destination_abs, boundary_roots)
        ):
            return False
        if (
            not self._existing_path_is_safe(source_abs)
            or not self._existing_path_is_safe(os.path.dirname(destination_abs))
            or os.path.lexists(destination_abs)
        ):
            return False
        verified = self._verified_hash_identity(source_abs)
        if verified is None:
            return False
        source_hash, source_identity = verified
        if (
            not expected_hash
            or source_hash != expected_hash
            or not expected_ownership_json
            or not self.matches_runtime_ownership_marker(
                source_abs,
                expected_ownership_json,
                isolated=not source_must_be_discoverable,
            )
        ):
            return False

        source_parent = os.path.dirname(source_abs)
        destination_parent = os.path.dirname(destination_abs)
        source_parent_identity = self._path_identity(source_parent)
        destination_parent_identity = self._path_identity(destination_parent)
        if (
            source_parent_identity is None
            or source_parent_identity.file_type != stat.S_IFDIR
            or destination_parent_identity is None
            or destination_parent_identity.file_type != stat.S_IFDIR
            or not self._same_filesystem(source_identity, destination_parent_identity)
        ):
            return False

        moved = False
        moved_identity: _PathIdentity | None = None
        try:
            with self._hold_parent_directories(
                source_parent, destination_parent,
            ) as (source_fd, destination_fd):
                if (
                    not self._identity_matches(
                        source_parent, source_parent_identity,
                    )
                    or not self._identity_matches(
                        destination_parent, destination_parent_identity,
                    )
                    or not self._identity_matches(source_abs, source_identity)
                    or os.path.lexists(destination_abs)
                ):
                    return False
                try:
                    self._rename_no_replace(
                        source_abs,
                        destination_abs,
                        source_fd,
                        destination_fd,
                    )
                    moved = True
                except OSError:
                    moved_identity = self._path_identity(
                        destination_abs, require_safe_type=False,
                    )
                    moved = (
                        not os.path.lexists(source_abs)
                        and moved_identity == source_identity
                    )
                    if not moved:
                        return False

                moved_identity = self._path_identity(
                    destination_abs, require_safe_type=False,
                )
                post_move = self._verified_hash_identity(destination_abs)
                valid = (
                    not os.path.lexists(source_abs)
                    and moved_identity == source_identity
                    and self._identity_matches(
                        source_parent, source_parent_identity,
                    )
                    and self._identity_matches(
                        destination_parent, destination_parent_identity,
                    )
                    and post_move == (expected_hash, source_identity)
                    and (
                        self._runtime_acl_transition_is_safe(
                            destination_abs, expected_ownership_json,
                        )
                        if source_must_be_discoverable
                        else self.matches_runtime_ownership_marker(
                            destination_abs,
                            expected_ownership_json,
                            isolated=False,
                        )
                    )
                )
                if valid:
                    return True
                self._rollback_atomic_move(
                    destination_abs,
                    source_abs,
                    source_identity,
                    destination_fd,
                    source_fd,
                )
                return False
        except OSError:
            if moved:
                # Parent handles are no longer available here. Retaining the
                # random quarantine target is safer than a path-based rollback.
                return False
            return False

    def runtime_isolate(
        self,
        skill_name: str,
        source_path: str,
        connector: str = "",
        *,
        quarantine_path: str,
        expected_hash: str,
        expected_ownership_json: str,
        allowed_roots: list[str] | None,
        isolation_roots: list[str] | None,
    ) -> bool:
        """Atomically move a skill outside discovery for runtime isolation."""
        if (
            self._safe_segment(skill_name) is None
            or not self._runtime_destination_valid(
                quarantine_path, connector, require_parent=True,
            )
        ):
            return False
        return self._atomic_runtime_move(
            source_path,
            quarantine_path,
            expected_hash=expected_hash,
            expected_ownership_json=expected_ownership_json,
            allowed_roots=allowed_roots,
            isolation_roots=isolation_roots,
            source_must_be_discoverable=True,
        )

    def restore_runtime_isolation(
        self,
        skill_name: str,
        restore_path: str,
        *,
        quarantine_path: str,
        expected_hash: str,
        expected_ownership_json: str,
        allowed_roots: list[str] | None,
        isolation_roots: list[str] | None,
        connector: str = "",
    ) -> bool:
        """Atomically restore the exact recorded runtime-isolation entry."""
        if (
            self._safe_segment(skill_name) is None
            or not quarantine_path
            or not self._runtime_destination_valid(
                quarantine_path, connector, require_parent=True,
            )
        ):
            return False
        return self._atomic_runtime_move(
            quarantine_path,
            restore_path,
            expected_hash=expected_hash,
            expected_ownership_json=expected_ownership_json,
            allowed_roots=allowed_roots,
            isolation_roots=isolation_roots,
            source_must_be_discoverable=False,
        )

    @classmethod
    def _copy_path(cls, source: str, destination: str) -> None:
        if cls._is_link_or_reparse(source):
            raise OSError("refusing linked or reparse-point quarantine content")
        info = os.lstat(source)
        if stat.S_ISREG(info.st_mode):
            with open(source, "rb") as src, open(destination, "xb") as dst:
                shutil.copyfileobj(src, dst, length=1024 * 1024)
            shutil.copystat(source, destination, follow_symlinks=False)
            return
        if not stat.S_ISDIR(info.st_mode):
            raise OSError("refusing non-regular quarantine content")
        os.mkdir(destination, mode=0o700)
        with os.scandir(source) as entries:
            for entry in sorted(entries, key=lambda item: item.name):
                child_source = os.path.join(source, entry.name)
                child_destination = os.path.join(destination, entry.name)
                cls._copy_path(child_source, child_destination)
        shutil.copystat(source, destination, follow_symlinks=False)

    @staticmethod
    def _remove_path(path: str) -> None:
        info = os.lstat(path)
        if stat.S_ISDIR(info.st_mode):
            shutil.rmtree(path)
        else:
            os.remove(path)

    def _quarantine_path(self, skill_name: str, connector: str = "") -> str | None:
        safe_name = self._safe_segment(skill_name)
        if safe_name is None:
            return None
        if connector:
            safe_connector = self._safe_segment(connector)
            if safe_connector is None:
                return None
            dest = os.path.join(self.quarantine_dir, safe_connector, safe_name)
        else:
            dest = os.path.join(self.quarantine_dir, safe_name)
        dest = os.path.abspath(dest)
        if not self._contained(dest, self.quarantine_dir):
            return None
        return dest

    def quarantine_path(
        self,
        skill_name: str,
        connector: str = "",
        *,
        purpose: str = "operator",
        allowed_roots: list[str] | None = None,
    ) -> str | None:
        """Return the validated physical quarantine location for an identity."""
        if purpose == _RUNTIME_ISOLATION_PURPOSE:
            return self.runtime_isolation_path(
                skill_name,
                connector,
                allowed_roots=allowed_roots,
            )
        if purpose not in _LEGACY_QUARANTINE_PURPOSES:
            return None
        return self._quarantine_path(skill_name, connector)

    def quarantine(
        self,
        skill_name: str,
        source_path: str,
        connector: str = "",
        *,
        expected_hash: str = "",
        expected_ownership_json: str = "",
        purpose: str = "operator",
        quarantine_path: str = "",
        allowed_roots: list[str] | None = None,
        isolation_roots: list[str] | None = None,
    ) -> str | None:
        """Copy, verify, then remove a skill from its original location."""
        if purpose == _RUNTIME_ISOLATION_PURPOSE:
            destination = os.path.abspath(quarantine_path) if quarantine_path else ""
            if not destination:
                return None
            if self.runtime_isolate(
                skill_name,
                source_path,
                connector,
                quarantine_path=destination,
                expected_hash=expected_hash,
                expected_ownership_json=expected_ownership_json,
                allowed_roots=allowed_roots,
                isolation_roots=isolation_roots,
            ):
                return destination
            return None
        if purpose not in _LEGACY_QUARANTINE_PURPOSES:
            return None
        if not self._existing_path_is_safe(self.quarantine_dir):
            return None
        source = os.path.abspath(source_path)
        if not self._validate_tree(source):
            return None
        source_hash = self.content_hash(source)
        if source_hash is None or (expected_hash and source_hash != expected_hash):
            return None
        dest = self._quarantine_path(skill_name, connector)
        if dest is None:
            return None
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        if os.path.lexists(dest):
            return None
        stage = dest + f".pending-{uuid.uuid4().hex}"
        try:
            self._copy_path(source, stage)
            if self.content_hash(stage) != source_hash:
                raise OSError("quarantine copy hash mismatch")
            os.rename(stage, dest)
            if self.content_hash(dest) != source_hash:
                raise OSError("quarantine destination hash mismatch")
            if self.content_hash(source) != source_hash:
                raise OSError("skill changed during quarantine")
            self._remove_path(source)
        except OSError:
            if os.path.lexists(stage):
                try:
                    self._remove_path(stage)
                except OSError:
                    pass
            # A verified destination is intentionally retained if source
            # removal failed; the pending provenance journal can recover it.
            return None
        return dest

    def restore(
        self, skill_name: str, restore_path: str,
        allowed_roots: list[str] | None = None,
        connector: str = "",
        *,
        expected_hash: str = "",
        expected_ownership_json: str = "",
        quarantine_path: str = "",
        purpose: str = "operator",
        isolation_roots: list[str] | None = None,
    ) -> bool:
        """Restore via a verified staging copy while retaining quarantine."""
        if purpose == _RUNTIME_ISOLATION_PURPOSE:
            return self.restore_runtime_isolation(
                skill_name,
                restore_path,
                quarantine_path=quarantine_path,
                expected_hash=expected_hash,
                expected_ownership_json=expected_ownership_json,
                allowed_roots=allowed_roots,
                isolation_roots=isolation_roots,
                connector=connector,
            )
        if purpose not in _LEGACY_QUARANTINE_PURPOSES:
            return False
        src = os.path.abspath(quarantine_path) if quarantine_path else self._quarantine_path(
            skill_name, connector,
        )
        if src is None:
            return False
        safe_name = self._safe_segment(skill_name)
        if (
            safe_name is None
            or os.path.basename(src) != safe_name
            or not self._contained(src, self.quarantine_dir)
            or not self._validate_tree(src)
        ):
            return False
        source_hash = self.content_hash(src)
        if source_hash is None or (expected_hash and source_hash != expected_hash):
            return False
        destination = os.path.abspath(restore_path)
        real_dest = os.path.realpath(destination)
        if allowed_roots:
            matched_root = next(
                (
                    os.path.abspath(root)
                    for root in allowed_roots
                    if self._contained(real_dest, os.path.realpath(root))
                ),
                None,
            )
            if matched_root is None:
                return False
            if not self._existing_path_is_safe(os.path.dirname(destination), matched_root):
                return False
        if os.path.lexists(destination):
            return False
        parent = os.path.dirname(destination)
        stage = os.path.join(parent, f".defenseclaw-restore-{uuid.uuid4().hex}")
        try:
            os.makedirs(parent, exist_ok=True)
            if allowed_roots and not self._existing_path_is_safe(parent, matched_root):
                return False
            self._copy_path(src, stage)
            if self.content_hash(stage) != source_hash:
                raise OSError("restore staging hash mismatch")
            os.rename(stage, destination)
            if self.content_hash(destination) != source_hash:
                raise OSError("restore destination hash mismatch")
            if self.content_hash(src) != source_hash:
                raise OSError("quarantine content changed during restore")
            self._remove_path(src)
        except OSError:
            for candidate in (stage, destination):
                if os.path.lexists(candidate):
                    try:
                        self._remove_path(candidate)
                    except OSError:
                        pass
            return False
        return True

    def is_quarantined(self, skill_name: str, connector: str = "") -> bool:
        path = self._quarantine_path(skill_name, connector)
        return bool(path and os.path.exists(path))
