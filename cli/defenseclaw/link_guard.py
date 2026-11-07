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

"""A link on the way to a Windows folder that uninstall is about to read or remove.

A junction or symbolic link at a per-user folder, or at any folder above it,
sends a read or a removal somewhere else. Uninstall does not follow one:
every component from the drive down is looked at with ``lstat`` (never
followed), the folder stays, and the link is named with the step that is safe
(remove only the link, or ask an administrator). Every uninstall and teardown
removal of a per-user Windows path asks this module before it touches the path.
"""

from __future__ import annotations

import contextlib
import os
import stat
from pathlib import Path

# The reparse tags of a junction (mount point) and of a symbolic link.
_IO_REPARSE_TAG_MOUNT_POINT = 0xA0000003
_IO_REPARSE_TAG_SYMLINK = 0xA000000C


class Problem(str):
    """What could not be done (or why a folder stays), with the next step for that reason."""

    step: str

    def __new__(cls, text: str, step: str = "") -> Problem:
        obj = super().__new__(cls, text)
        obj.step = step
        return obj


def is_reparse(path: str | os.PathLike[str]) -> bool:
    """Whether *path* itself is a symbolic link, a junction or another reparse point (never followed)."""
    if os.path.islink(path):
        return True
    isjunction = getattr(os.path, "isjunction", None)
    if isjunction and isjunction(path):
        return True
    with contextlib.suppress(OSError):
        attributes = getattr(os.lstat(path), "st_file_attributes", 0)
        return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return False


def link_kind(info: os.stat_result) -> str:
    """The kind of link an lstat result describes: junction, symlink, or link (another reparse point)."""
    tag = getattr(info, "st_reparse_tag", 0)
    if tag == _IO_REPARSE_TAG_MOUNT_POINT:
        return "junction"
    if tag == _IO_REPARSE_TAG_SYMLINK or stat.S_ISLNK(info.st_mode):
        return "symlink"
    return "link"


def links_on_path(path: str, *, include_self: bool = True) -> list[tuple[str, str]]:
    """The links on the way to *path*, outermost first, as (link path, kind).

    Every component is looked at with lstat, so a link is seen as a link and
    never followed. *include_self* False leaves *path* itself out.
    """
    full = Path(os.path.abspath(path))
    chain = [*reversed(full.parents), full]
    if not include_self:
        chain.pop()
    found: list[tuple[str, str]] = []
    for part in chain:
        if part == Path(part.anchor):
            continue
        try:
            info = os.lstat(part)
        except OSError:
            continue
        if is_reparse(str(part)):
            found.append((str(part), link_kind(info)))
    return found


def link_problem(path: str, *, include_self: bool = True, setup: bool = False) -> Problem | None:
    """Why *path* is not reached: a link at or above it, named, with the safe step (None when there is none).

    The link nearest the folder is the one to deal with first; one outside it
    is named in the reason and comes up on the next run. *setup* ends the step
    with the way out for a DefenseClaw Setup 0.8.x install.
    """
    links = links_on_path(path, include_self=include_self)
    if not links:
        return None
    link, kind = links[-1]
    text = f"{link} is a {kind}, and DefenseClaw does not read or remove a folder through a link"
    if len(links) > 1:
        text += "; also a link above it: " + ", ".join(f"{outer} ({outer_kind})" for outer, outer_kind in links[:-1])
    leave = (
        f"uninstall DefenseClaw Setup from Apps & Features, or ask an administrator to check {link}."
        if setup
        else f"ask an administrator to check {link}."
    )
    step = (
        f"{link} is a {kind}. DefenseClaw does not remove anything through a link. If it is a stray link, "
        f'remove only the link with `cmd /c rmdir "{link}"` (this removes only the link, not what it points '
        f"to), or ask an administrator to, then run the command again. If it is part of how this profile is "
        f"set up, leave it: {leave}"
    )
    return Problem(text, step)


def dangling_link_problem(path: str) -> Problem | None:
    """Why *path* cannot be reached: a link at or above it whose target is missing (None when there is none).

    Nothing is behind such a link, so removing only the link is safe. A link
    whose target cannot be read for another reason (access denied, an offline
    file) is not reported as missing.
    """
    for link, kind in links_on_path(path):
        try:
            os.stat(link)
        except (FileNotFoundError, NotADirectoryError):
            text = f"{link} is a {kind} whose target is missing"
            step = (
                f"{link} is a {kind} whose target is missing, so nothing is behind it. Remove only the link "
                f'with `cmd /c rmdir "{link}"` (this removes only the link), or ask an administrator to, '
                "then run the command again."
            )
            return Problem(text, step)
        except OSError:
            continue
    return None
