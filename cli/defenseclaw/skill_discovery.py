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

"""Shared filesystem rules for connector skill discovery."""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass

from defenseclaw.file_permissions import (
    open_regular_file_no_follow,
    reject_reparse_path,
)
from defenseclaw.safety import is_symlink

_SKILL_MARKERS = ("SKILL.md", "skill.json", "README.md")


@dataclass(frozen=True)
class SkillDirectory:
    """One discoverable skill directory beneath a connector skill root."""

    name: str
    path: str
    source: str
    bundled: bool = False


def _filesystem_identity(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _directory_identity(info: os.stat_result) -> tuple[int, int]:
    return info.st_dev, info.st_ino


def _is_real_directory(info: os.stat_result) -> bool:
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return (
        stat.S_ISDIR(info.st_mode)
        and not stat.S_ISLNK(info.st_mode)
        and not bool(getattr(info, "st_file_attributes", 0) & reparse_flag)
    )


def _directory_entry_matches(
    enumerated: os.stat_result,
    named: os.stat_result,
) -> bool:
    """Compare a DirEntry snapshot without assuming Windows exposes file IDs."""
    if enumerated.st_dev or enumerated.st_ino:
        return (enumerated.st_dev, enumerated.st_ino) == (
            named.st_dev,
            named.st_ino,
        )
    return True


def _canonically_contained(
    path: str,
    root: str,
    *,
    allow_root: bool = False,
) -> bool:
    path_abs = os.path.abspath(path)
    root_abs = os.path.abspath(root)
    try:
        lexical_common = os.path.commonpath((path_abs, root_abs))
    except ValueError:
        return False
    if os.path.normcase(lexical_common) != os.path.normcase(root_abs):
        return False
    if not allow_root and os.path.normcase(path_abs) == os.path.normcase(root_abs):
        return False

    path_real = os.path.realpath(path_abs)
    root_real = os.path.realpath(root_abs)
    try:
        canonical_common = os.path.commonpath((path_real, root_real))
    except ValueError:
        return False
    if os.path.normcase(canonical_common) != os.path.normcase(root_real):
        return False
    return allow_root or os.path.normcase(path_real) != os.path.normcase(root_real)


def _stable_directory_info(
    path: str,
    *,
    containment_root: str | None = None,
) -> os.stat_result:
    if containment_root is not None and not _canonically_contained(
        path,
        containment_root,
    ):
        raise OSError(f"skill directory escapes its declared root: {path}")
    reject_reparse_path(path)
    before = os.stat(path, follow_symlinks=False)
    if not _is_real_directory(before):
        raise OSError(f"skill directory is a symlink or reparse point: {path}")
    reject_reparse_path(path)
    after = os.stat(path, follow_symlinks=False)
    if _directory_identity(before) != _directory_identity(after):
        raise OSError(f"skill directory changed while it was being inventoried: {path}")
    if containment_root is not None and not _canonically_contained(
        path,
        containment_root,
    ):
        raise OSError(f"skill directory escaped its declared root: {path}")
    return after


def _directory_unchanged(path: str, expected: os.stat_result) -> bool:
    try:
        current = _stable_directory_info(path)
    except OSError:
        return False
    return _directory_identity(current) == _directory_identity(expected)


def _stable_child_directories(
    root: str,
) -> list[tuple[str, str, os.stat_result]]:
    before = _stable_directory_info(root)
    with os.scandir(root) as iterator:
        entries = sorted(iterator, key=lambda entry: entry.name.casefold())
    after = _stable_directory_info(root)
    if _directory_identity(before) != _directory_identity(after):
        raise OSError(f"skill root changed while it was being inventoried: {root}")

    children: list[tuple[str, str, os.stat_result]] = []
    for entry in entries:
        try:
            entry_info = entry.stat(follow_symlinks=False)
            if entry.is_symlink() or not _is_real_directory(entry_info):
                continue
            named = _stable_directory_info(
                entry.path,
                containment_root=root,
            )
        except OSError:
            continue
        if not _directory_entry_matches(entry_info, named):
            continue
        children.append((entry.name, entry.path, named))
    if not _directory_unchanged(root, before):
        raise OSError(f"skill root changed while it was being inventoried: {root}")
    return children


def _open_stable_skill_marker(
    skill_path: str,
    marker: str,
) -> tuple[int, os.stat_result, os.stat_result] | None:
    if marker not in _SKILL_MARKERS:
        return None
    try:
        skill_identity = _stable_directory_info(skill_path)
        marker_path = os.path.join(skill_path, marker)
        if not _canonically_contained(marker_path, skill_path):
            return None
        fd = open_regular_file_no_follow(marker_path)
    except OSError:
        return None
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            raise OSError(f"skill marker is not a regular file: {marker_path}")
        reject_reparse_path(marker_path)
        named = os.stat(marker_path, follow_symlinks=False)
        if not os.path.samestat(opened, named):
            raise OSError(f"skill marker changed while it was being inventoried: {marker_path}")
        if not _canonically_contained(marker_path, skill_path):
            raise OSError(f"skill marker escaped its declared root: {marker_path}")
        return fd, opened, skill_identity
    except OSError:
        os.close(fd)
        return None


def skill_dir_is_eligible(path: str) -> bool:
    """Return whether *path* contains a recognized skill marker."""
    for marker in _SKILL_MARKERS:
        opened = _open_stable_skill_marker(path, marker)
        if opened is None:
            continue
        fd, _marker_identity, skill_identity = opened
        os.close(fd)
        if _directory_unchanged(path, skill_identity):
            return True
    return False


def read_skill_marker_text(
    skill_path: str,
    marker: str,
    *,
    max_bytes: int,
) -> str | None:
    """Read a bounded marker prefix without following any linked ancestry."""
    if max_bytes < 0:
        raise ValueError("max_bytes must be non-negative")
    opened = _open_stable_skill_marker(skill_path, marker)
    if opened is None:
        return None
    fd, before, skill_identity = opened
    try:
        chunks: list[bytes] = []
        remaining = max_bytes
        while remaining:
            chunk = os.read(fd, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(fd)
        marker_path = os.path.join(skill_path, marker)
        reject_reparse_path(marker_path)
        named = os.stat(marker_path, follow_symlinks=False)
        if (
            _filesystem_identity(before) != _filesystem_identity(after)
            or not os.path.samestat(before, named)
            or not _directory_unchanged(skill_path, skill_identity)
            or not _canonically_contained(marker_path, skill_path)
        ):
            return None
        return b"".join(chunks).decode("utf-8", errors="replace")
    except OSError:
        return None
    finally:
        os.close(fd)


def _discover_claude_skill_directories(
    skill_root: str,
    *,
    commands: bool,
) -> list[SkillDirectory]:
    """Preserve Claude's documented Markdown-command and symlink skill forms."""

    try:
        entries = sorted(os.listdir(skill_root), key=str.casefold)
    except OSError:
        return []

    regular: list[SkillDirectory] = []
    targets: set[str] = set()
    for entry in entries:
        full = os.path.join(skill_root, entry)
        if (
            commands
            and entry.casefold().endswith(".md")
            and not is_symlink(full)
            and os.path.isfile(full)
        ):
            regular.append(
                SkillDirectory(
                    os.path.splitext(entry)[0],
                    full,
                    skill_root,
                )
            )
            continue
        if not os.path.isdir(full):
            continue
        resolved = os.path.realpath(full)
        target_key = os.path.normcase(resolved)
        if target_key in targets:
            continue
        targets.add(target_key)
        if os.path.isfile(
            os.path.join(resolved, ".claude-plugin", "plugin.json")
        ):
            # Anthropic assigns this exact child to the @skills-dir plugin
            # namespace. It must not also appear as a plain skill.
            continue
        regular.append(SkillDirectory(entry, resolved, skill_root))
    return regular


def discover_skill_directories(
    skill_root: str,
    *,
    connector: str,
) -> list[SkillDirectory]:
    """Return immediate skills, expanding connector-owned containers.

    Codex reserves ``.system`` as a container for bundled skills. Treating the
    container itself as a skill produces a false "missing SKILL.md" result, so
    enumerate only its marked child skill directories. Ordinary top-level
    skills are returned first so an operator-installed skill with the same
    name takes precedence over a bundled child.
    """
    normalized_connector = (connector or "").strip().lower().replace("-", "")
    system_containers = {".system"} if normalized_connector == "codex" else set()
    claude_skills = normalized_connector in {"claude", "claudecode"}
    claude_commands = claude_skills and os.path.basename(
        os.path.normpath(skill_root)
    ).casefold() == "commands"
    if claude_skills:
        return _discover_claude_skill_directories(
            skill_root,
            commands=claude_commands,
        )

    try:
        root_identity = _stable_directory_info(skill_root)
        if system_containers:
            system_path = os.path.join(skill_root, ".system")
            if os.path.lexists(system_path):
                _stable_directory_info(
                    system_path,
                    containment_root=skill_root,
                )
        entries = _stable_child_directories(skill_root)
    except OSError:
        return []

    regular: list[SkillDirectory] = []
    bundled: list[SkillDirectory] = []
    selected_identities: list[tuple[str, os.stat_result]] = []
    for entry, full, entry_identity in entries:
        if entry not in system_containers:
            regular.append(SkillDirectory(entry, full, skill_root))
            selected_identities.append((full, entry_identity))
            continue

        try:
            children = _stable_child_directories(full)
        except OSError:
            continue
        for child, child_path, child_identity in children:
            if not skill_dir_is_eligible(child_path):
                continue
            bundled.append(
                SkillDirectory(child, child_path, full, bundled=True)
            )
            selected_identities.append((child_path, child_identity))
        if not _directory_unchanged(full, entry_identity):
            return []
    if not _directory_unchanged(skill_root, root_identity):
        return []
    if any(
        not _directory_unchanged(path, identity)
        for path, identity in selected_identities
    ):
        return []
    return regular + bundled
