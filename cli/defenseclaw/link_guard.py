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
    with contextlib.suppress(OSError, ValueError):
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
    never followed. The path is read as written: a ".." is not folded into
    the component before it, because the system follows a link before it
    reads the ".." that comes after (link/../state is the folder above where
    link points, not the folder beside it). *include_self* False leaves *path*
    itself out.
    """
    written = os.fspath(path)
    full = Path(written if os.path.isabs(written) else os.path.abspath(written))
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


def _windows() -> bool:
    return os.name == "nt"


def _long_name(path: str) -> str:
    """*path* with its 8.3 short names written out (as given when Windows cannot say)."""
    if not _windows():
        return path
    with contextlib.suppress(Exception):
        import ctypes

        size = ctypes.windll.kernel32.GetLongPathNameW(path, None, 0)  # type: ignore[attr-defined]
        if size:
            buffer = ctypes.create_unicode_buffer(size)
            if ctypes.windll.kernel32.GetLongPathNameW(path, buffer, size):  # type: ignore[attr-defined]
                return buffer.value
    return path


def _drive_kind(drive: str) -> tuple[str, str]:
    """What a drive letter such as ``Z:`` is: ("local", ""), ("network", its UNC root) or ("subst", "").

    ``QueryDosDevice`` tells them apart: a subst drive maps to ``\\??\\C:\\...``, a mapped network drive to
    ``\\Device\\LanmanRedirector\\...`` or ``\\Device\\Mup\\...`` (the UNC root then comes from
    ``WNetGetConnection``). Anything unknown is "local", so it is compared as written.
    """
    if not _windows():
        return ("local", "")
    with contextlib.suppress(Exception):
        import ctypes

        buffer = ctypes.create_unicode_buffer(1024)
        if not ctypes.windll.kernel32.QueryDosDeviceW(drive, buffer, len(buffer)):  # type: ignore[attr-defined]
            return ("local", "")
        target = buffer.value.lower()
        if target.startswith(("\\device\\lanmanredirector", "\\device\\mup", "\\??\\unc\\")):
            remote = ctypes.create_unicode_buffer(1024)
            size = ctypes.c_ulong(len(remote))
            if ctypes.windll.mpr.WNetGetConnectionW(drive, remote, ctypes.byref(size)) == 0:  # type: ignore[attr-defined]
                return ("network", remote.value)
            if target.startswith("\\??\\"):
                # A raw \??\UNC\ target that the network provider does not know is a DefineDosDevice
                # substitution, not a mapped drive.
                return ("subst", "")
            return ("network", "")
        if target.startswith("\\??\\"):
            return ("subst", "")
    return ("local", "")


def _key(path: str) -> str:
    return os.path.normcase(path).rstrip("\\/")


_UNKNOWN = "its real location cannot be determined"


def _exists(path: str) -> bool:
    """Whether *path* itself is there (never followed). A folder that cannot be read is still there."""
    try:
        os.lstat(path)
    except PermissionError:
        return True
    except (OSError, ValueError):
        return False
    return True


def _resolution(path: str, *, include_self: bool = True) -> tuple[str, str]:
    """(real path, what the path goes through) when *path* is not where it is written; ("", "") otherwise.

    Only the longest part that exists is compared: Windows cannot expand the
    short name of a part that does not exist, while ``realpath`` expands the
    existing part, so the missing tail (the same on both sides) is left out.
    A drive mapped to a share is the same place as its UNC root; a subst drive is not.
    When the real path cannot be determined at all (an error from the system), the
    answer is "refuse": the path as written and ``its real location cannot be
    determined (<error class>)``.
    """
    if not _windows():
        return ("", "")
    try:
        return _resolve(path, include_self)
    except Exception as exc:  # noqa: BLE001 - fail closed: a path that cannot be placed is not safe to remove
        return (path, f"{_UNKNOWN} ({type(exc).__name__})")


def _resolve(path: str, include_self: bool) -> tuple[str, str]:
    written = os.path.abspath(path)
    if not include_self:
        written = os.path.dirname(written)
    existing, tail = written, ""
    while not _exists(existing):
        parent, name = os.path.split(existing)
        if parent == existing or not name:
            break
        existing, tail = parent, (os.path.join(name, tail) if tail else name)
    real = os.path.realpath(existing)
    whole = os.path.join(real, tail) if tail else real
    drive = os.path.splitdrive(existing)[0]
    kind, remote = _drive_kind(drive) if len(drive) == 2 and drive[1] == ":" else ("local", "")
    if kind == "subst":
        return (whole, "a substituted drive (subst)")
    shown = _long_name(existing)
    accepted = {_key(shown)}
    if kind == "network":
        rest = shown[len(drive):]
        if remote:
            accepted.add(_key(remote + rest))
        accepted.add(_key(os.path.realpath(drive + "\\").rstrip("\\/") + rest))
    if _key(real) in accepted:
        return ("", "")
    return (whole, "a link")


def resolves_elsewhere(path: str, *, include_self: bool = True) -> str:
    """Where *path* really is, when that is not where it is written (Windows only; empty otherwise).

    The last look before a removal: the real path (every link followed) must
    equal the path written, upper and lower case and short names aside, and a
    drive mapped to a network share counts as its share. It catches a link made
    since the component-by-component look, and a substituted drive. *include_self*
    False compares the folder above *path*, as *path* itself may be a link that
    goes as a link.
    """
    return _resolution(path, include_self=include_self)[0]


def _step(link: str, kind: str, *, leave: str) -> str:
    """The step for a link of *kind*: remove only the link when it is a plain junction or symlink."""
    if kind not in ("junction", "symlink"):
        # Another kind of reparse point (an online-only OneDrive folder, a mount point, a dedup or WSL point)
        # is not for DefenseClaw to take apart, and rmdir may not remove it.
        return (
            f"{link} is a {kind} (a reparse point that is neither a junction nor a symbolic link). DefenseClaw "
            f"does not remove anything through it. Ask an administrator to check {link}, then run the command again."
        )
    return (
        f"{link} is a {kind}. DefenseClaw does not remove anything through a link. If it is a stray link, "
        f"remove only the link with `cmd /c rmdir \"{link}\"` (this removes only the link, not what it points "
        f"to), or ask an administrator to, then run the command again. If it is part of how this profile is "
        f"set up, leave it: {leave}"
    )


def link_problem(path: str, *, include_self: bool = True, setup: bool = False) -> Problem | None:
    """Why *path* is not reached: a link at or above it, named, with the safe step (None when there is none).

    The link nearest the folder is the one to deal with first; one outside it
    is named in the reason and comes up on the next run. *setup* ends the step
    with the way out for a DefenseClaw Setup 0.8.x install. On Windows a last
    check that the real path is the path written refuses what the component look
    cannot name (see resolves_elsewhere).
    """
    try:
        links = links_on_path(path, include_self=include_self)
    except (OSError, ValueError) as exc:
        links, real, what = [], path, f"{_UNKNOWN} ({type(exc).__name__})"
    else:
        real, what = _resolution(path, include_self=include_self) if not links else ("", "")
    if not links:
        if not real:
            return None
        if what.startswith(_UNKNOWN):
            return Problem(
                f"{path} cannot be checked: {what}",
                f"DefenseClaw does not remove anything it cannot place. Ask an administrator to check {path}, "
                "then run the command again.",
            )
        if what.endswith("(subst)"):
            drive = os.path.splitdrive(os.path.abspath(path))[0]
            return Problem(
                f"{path} is reached through {what} (it resolves to {real})",
                f"DefenseClaw does not remove anything through a substituted drive. If {drive} is a stray "
                f"substitution, remove it with `subst {drive} /d`, or ask an administrator to, then run the "
                "command again.",
            )
        return Problem(
            f"{path} is reached through {what} (it resolves to {real})",
            f"DefenseClaw does not remove anything through a link. Ask an administrator to check {path}, "
            "then run the command again.",
        )
    link, kind = links[-1]
    text = f"{link} is a {kind}, and DefenseClaw does not read or remove a folder through a link"
    if len(links) > 1:
        text += "; also a link above it: " + ", ".join(f"{outer} ({outer_kind})" for outer, outer_kind in links[:-1])
    leave = (
        f"uninstall DefenseClaw Setup from Apps & Features, or ask an administrator to check {link}."
        if setup
        else f"ask an administrator to check {link}."
    )
    return Problem(text, _step(link, kind, leave=leave))


def dangling_link_problem(path: str, *, above: bool = True) -> Problem | None:
    """Why *path* cannot be reached: a link at or above it whose target cannot be found (None when there is none).

    The target may be a deleted folder, or a drive or share that is not
    connected, so the text does not say that nothing is behind it. A link whose
    target cannot be read for another reason (access denied, an offline file) is
    not reported. *above* False looks at *path* itself only.
    """
    try:
        here = os.path.normcase(os.path.abspath(path))
        links = links_on_path(path)
    except (OSError, ValueError):
        return None  # link_problem is the gate: it names a path that cannot be placed
    for link, kind in links:
        if not above and os.path.normcase(os.path.abspath(link)) != here:
            continue
        try:
            os.stat(link)
        except (FileNotFoundError, NotADirectoryError):
            lost = (
                f"{link} is a {kind} whose target cannot be found "
                "(a deleted folder, or a drive or share that is not connected)"
            )
            if kind in ("junction", "symlink"):
                step = (
                    f"{lost}. If it is a stray link, remove only the link with `cmd /c rmdir \"{link}\"` "
                    "(this removes only the link), or ask an administrator to, then run the command again. "
                    "If the drive or share should be there, connect it and run the command again."
                )
            else:
                step = f"{lost}. Ask an administrator to check {link}, then run the command again."
            return Problem(f"{link} is a {kind} whose target cannot be found", step)
        except (OSError, ValueError):
            continue
    return None
