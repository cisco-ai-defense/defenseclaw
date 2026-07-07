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

import hashlib
import json
import ntpath
import os
import posixpath
import shutil
import stat
import uuid
from typing import Any, BinaryIO

from defenseclaw.file_permissions import make_private_directory


class SkillEnforcer:
    def __init__(self, quarantine_dir: str) -> None:
        self.quarantine_dir = os.path.abspath(os.path.join(quarantine_dir, "skills"))
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
        }
        return json.dumps(marker, sort_keys=True, separators=(",", ":"))

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

    def quarantine_path(self, skill_name: str, connector: str = "") -> str | None:
        """Return the validated physical quarantine location for an identity."""
        return self._quarantine_path(skill_name, connector)

    def quarantine(
        self,
        skill_name: str,
        source_path: str,
        connector: str = "",
        *,
        expected_hash: str = "",
    ) -> str | None:
        """Copy, verify, then remove a skill from its original location."""
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
        quarantine_path: str = "",
    ) -> bool:
        """Restore via a verified staging copy while retaining quarantine."""
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
