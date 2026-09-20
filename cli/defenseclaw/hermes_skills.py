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

"""Hermes installer-managed skill provenance.

Hermes copies its bundled skill library into ``HERMES_HOME/skills`` alongside
hub-installed and operator-authored skills.  The adjacent
``.bundled_manifest`` maps each bundled skill's frontmatter name to the MD5
tree hash that Hermes recorded when it last synchronized that copy. A skill is
vendor-bundled only when the manifest, installed user copy, and matching source
under the exact ``hermes-agent/skills`` checkout all agree. Modified,
untracked, and manifest-only copies remain ordinary scanable assets.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat

from defenseclaw.file_permissions import open_regular_file_no_follow

HERMES_BUNDLED_MANIFEST = ".bundled_manifest"
_MANIFEST_MAX_BYTES = 2 * 1024 * 1024
_SKILL_MARKER_MAX_BYTES = 64 * 1024
_SKILL_FILE_MAX_BYTES = 64 * 1024 * 1024
_SKILL_TREE_MAX_BYTES = 256 * 1024 * 1024
_MANIFEST_HASH_RE = re.compile(r"^[0-9a-fA-F]{32}$")


def _filesystem_identity(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _is_real_directory(info: os.stat_result) -> bool:
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return (
        stat.S_ISDIR(info.st_mode)
        and not stat.S_ISLNK(info.st_mode)
        and not bool(getattr(info, "st_file_attributes", 0) & reparse_flag)
    )


def _is_regular_file(info: os.stat_result) -> bool:
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return (
        stat.S_ISREG(info.st_mode)
        and not stat.S_ISLNK(info.st_mode)
        and not bool(getattr(info, "st_file_attributes", 0) & reparse_flag)
    )


def _read_regular_file(path: str, *, max_bytes: int) -> bytes | None:
    """Return one bounded, stable, non-link file snapshot."""

    try:
        fd = open_regular_file_no_follow(path)
    except OSError:
        return None
    try:
        before = os.fstat(fd)
        if not _is_regular_file(before) or before.st_size > max_bytes:
            return None
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining:
            chunk = os.read(fd, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after = os.fstat(fd)
        named = os.stat(path, follow_symlinks=False)
        if (
            len(payload) > max_bytes
            or _filesystem_identity(before) != _filesystem_identity(after)
            or not os.path.samestat(after, named)
        ):
            return None
        return payload
    except OSError:
        return None
    finally:
        os.close(fd)


def _manifest_for_root(skill_root: str) -> dict[str, str]:
    payload = _read_regular_file(
        os.path.join(skill_root, HERMES_BUNDLED_MANIFEST),
        max_bytes=_MANIFEST_MAX_BYTES,
    )
    if payload is None:
        return {}
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        return {}
    entries: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or ":" not in line:
            continue
        name, digest = (part.strip() for part in line.split(":", 1))
        if name and _MANIFEST_HASH_RE.fullmatch(digest):
            entries[name] = digest.lower()
    return entries


def skill_name(skill_dir: str) -> str:
    """Return Hermes's manifest identity from ``SKILL.md`` frontmatter."""

    payload = _read_regular_file(
        os.path.join(skill_dir, "SKILL.md"),
        max_bytes=_SKILL_MARKER_MAX_BYTES,
    )
    fallback = os.path.basename(os.path.normpath(skill_dir))
    if payload is None:
        return fallback
    text = payload.decode("utf-8", errors="replace")
    in_frontmatter = False
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line == "---":
            if in_frontmatter:
                break
            in_frontmatter = True
            continue
        if in_frontmatter and line.startswith("name:"):
            value = line.split(":", 1)[1].strip().strip("\"'")
            if value:
                return value
    return fallback


def _tree_md5(skill_dir: str) -> str | None:
    """Compute the exact tree hash used by Hermes's ``skills_sync.py``."""

    root = os.path.abspath(skill_dir)
    try:
        root_before = os.stat(root, follow_symlinks=False)
    except OSError:
        return None
    if not _is_real_directory(root_before):
        return None

    files: list[tuple[str, str, int]] = []
    tree_bytes = 0
    try:
        for current, dirs, names in os.walk(root, topdown=True, followlinks=False):
            current_info = os.stat(current, follow_symlinks=False)
            if not _is_real_directory(current_info):
                return None
            safe_dirs: list[str] = []
            for name in dirs:
                child = os.path.join(current, name)
                if _is_real_directory(os.stat(child, follow_symlinks=False)):
                    safe_dirs.append(name)
                else:
                    return None
            dirs[:] = safe_dirs
            for name in names:
                full = os.path.join(current, name)
                info = os.stat(full, follow_symlinks=False)
                if not _is_regular_file(info):
                    return None
                if info.st_size > _SKILL_FILE_MAX_BYTES:
                    return None
                tree_bytes += info.st_size
                if tree_bytes > _SKILL_TREE_MAX_BYTES:
                    return None
                files.append((os.path.relpath(full, root), full, info.st_size))
    except OSError:
        return None

    digest = hashlib.md5()  # noqa: S324 -- compatibility with Hermes manifest.
    # ``pathlib.WindowsPath`` sorts case-insensitively; Hermes hashes files in
    # ``sorted(directory.rglob("*"))`` order, so mirror the host path flavour.
    for relative, full, size in sorted(
        files,
        key=lambda item: os.path.normcase(item[0]),
    ):
        payload = _read_regular_file(full, max_bytes=size)
        if payload is None:
            return None
        digest.update(relative.encode("utf-8"))
        digest.update(payload)
    try:
        root_after = os.stat(root, follow_symlinks=False)
    except OSError:
        return None
    if _filesystem_identity(root_before) != _filesystem_identity(root_after):
        return None
    return digest.hexdigest()


def _hermes_skill_root() -> str:
    try:
        from defenseclaw.connector_paths import hermes_home

        home = hermes_home()
    except (OSError, ValueError):
        return ""
    return os.path.abspath(os.path.join(home, "skills")) if home else ""


def is_hermes_skill_root(path: str) -> bool:
    root = _hermes_skill_root()
    if not root or not path:
        return False
    return os.path.normcase(os.path.abspath(path)) == os.path.normcase(root)


def is_bundled_skill_dir(
    skill_dir: str,
    *,
    name: str | None = None,
    skill_root: str | None = None,
    manifest: dict[str, str] | None = None,
) -> bool:
    """Return True only for an unchanged source-bound Hermes skill."""

    root = os.path.abspath(skill_root or _hermes_skill_root())
    candidate = os.path.abspath(skill_dir)
    if not root or not is_hermes_skill_root(root):
        return False
    try:
        if (
            os.path.normcase(os.path.commonpath((candidate, root)))
            != os.path.normcase(root)
            or os.path.normcase(candidate) == os.path.normcase(root)
        ):
            return False
    except ValueError:
        return False
    identity = name or skill_name(candidate)
    entries = manifest if manifest is not None else _manifest_for_root(root)
    origin_hash = entries.get(identity, "").lower()
    if not origin_hash or _tree_md5(candidate) != origin_hash:
        return False

    # The manifest is user-writable and is therefore not a sufficient trust
    # boundary by itself. Bind the origin hash to the matching skill shipped in
    # the exact Hermes installation checkout. If that source is unavailable,
    # moved, linked, modified, or mismatched, fail open to scanning.
    try:
        relative = os.path.relpath(candidate, root)
        source_root = os.path.join(os.path.dirname(root), "hermes-agent", "skills")
        source = os.path.abspath(os.path.join(source_root, relative))
        source_root = os.path.abspath(source_root)
        if os.path.normcase(os.path.commonpath((source, source_root))) != os.path.normcase(
            source_root
        ):
            return False
    except ValueError:
        return False
    return skill_name(source) == identity and _tree_md5(source) == origin_hash


def is_bundled_skill_path(path: str) -> bool:
    """Classify a Hermes skill directory or any descendant path."""

    if not path or not path.strip():
        return False
    root = _hermes_skill_root()
    if not root:
        return False
    candidate = os.path.abspath(os.path.normpath(path.strip()))
    if os.path.isfile(candidate):
        candidate = os.path.dirname(candidate)
    try:
        if (
            os.path.normcase(os.path.commonpath((candidate, root)))
            != os.path.normcase(root)
            or os.path.normcase(candidate) == os.path.normcase(root)
        ):
            return False
    except ValueError:
        return False

    manifest = _manifest_for_root(root)
    current = candidate
    while os.path.normcase(current) != os.path.normcase(root):
        if os.path.isfile(os.path.join(current, "SKILL.md")):
            return is_bundled_skill_dir(
                current,
                skill_root=root,
                manifest=manifest,
            )
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
    return False


def manifest_for_root(skill_root: str) -> dict[str, str]:
    """Expose a snapshot for one bounded discovery pass."""

    if not is_hermes_skill_root(skill_root):
        return {}
    return _manifest_for_root(os.path.abspath(skill_root))


def directory_md5(skill_dir: str) -> str | None:
    """Testable compatibility wrapper for Hermes's manifest hash."""

    return _tree_md5(skill_dir)
