"""Windows long-path-safe file copies for the packaged-data seeds.

A per-user install keeps the packaged data under
``<profile>\\.defenseclaw\\.venv\\Lib\\site-packages\\defenseclaw\\_data``. On a
profile folder of about 100 characters the longest packaged file (a Splunk app
view) is 266 characters, past the 260-character ``MAX_PATH`` that the Python
file calls hit unless the machine enables long paths. Every seed that copies
packaged data into the data directory goes through these helpers, so the
result does not depend on the profile length or on that machine setting.
"""

from __future__ import annotations

import errno
import os
import shutil
import uuid

from defenseclaw.file_permissions import windows_extended_path


def extended(path: str | os.PathLike[str]) -> str:
    """Return *path* unlimited by ``MAX_PATH`` on Windows, unchanged elsewhere."""

    if os.name != "nt":
        return os.fspath(path)
    return windows_extended_path(path)


def display(text: str) -> str:
    """Return *text* with the Win32 extended-path prefix removed, for messages."""

    return text.replace("\\\\?\\UNC\\", "\\\\").replace("\\\\?\\", "")


def copytree(src: str | os.PathLike[str], dst: str | os.PathLike[str]) -> str:
    """``shutil.copytree`` that is not limited by ``MAX_PATH`` on Windows.

    *dst* must not exist, as for ``shutil.copytree``; a destination that exists,
    or that appears while this call copies, raises ``FileExistsError`` and is
    never changed, replaced or reported as a seed.

    The copy is made in a hidden folder this call created next to *dst* (a name
    already in use is never reused) and is moved to *dst* only when it is
    complete, so *dst* is never a partial copy. On POSIX, where renaming a folder
    over an empty folder replaces it, this call first creates *dst* itself with
    ``mkdir`` (which cannot succeed over anything that exists) and renames onto
    that empty folder it owns; Windows refuses a rename onto an existing folder.
    A failure removes only the folders this call created. A raised error names
    the paths without the extended-path prefix.
    """

    final = extended(dst)
    if os.path.lexists(final):
        raise FileExistsError(errno.EEXIST, "File exists", display(final))
    parent = os.path.dirname(final) or os.curdir
    staging = ""
    claimed = False
    try:
        os.makedirs(parent, exist_ok=True)
        staging = _new_staging(parent, os.path.basename(final))
        shutil.copytree(extended(src), staging, dirs_exist_ok=True)
        if os.name != "nt":
            os.mkdir(final)
            claimed = True
        os.rename(staging, final)
    except (OSError, shutil.Error) as exc:
        left = _remove(staging) if staging else False
        if claimed:
            try:
                os.rmdir(final)
            except OSError:
                pass
        message = display(str(exc))
        if left:
            message += f" (the partial copy {display(staging)} could not be removed)"
        if os.name == "nt" or left:
            raise OSError(message) from exc
        raise
    return os.fspath(dst)


def _new_staging(parent: str, leaf: str) -> str:
    """Create and return an empty hidden folder in *parent* that nothing else owns."""

    for _ in range(8):
        path = os.path.join(parent, f".{leaf}.seed-{uuid.uuid4().hex[:8]}")
        try:
            os.mkdir(path)
        except FileExistsError:
            continue
        return path
    raise FileExistsError(errno.EEXIST, "no unused staging folder name", display(parent))


def rmtree(path: str | os.PathLike[str]) -> None:
    """Remove *path* and what is below it, ignoring errors, on any path length."""

    shutil.rmtree(extended(path), ignore_errors=True)


def _remove(path: str) -> bool:
    """Remove *path*; return True when something of it is still there."""

    if os.path.lexists(path):
        shutil.rmtree(path, ignore_errors=True)
    return os.path.lexists(path)
