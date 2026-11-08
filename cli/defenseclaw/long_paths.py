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


def _windows() -> bool:
    return os.name == "nt"


def extended(path: str | os.PathLike[str]) -> str:
    """Return *path* unlimited by ``MAX_PATH`` on Windows, unchanged elsewhere."""

    if not _windows():
        return os.fspath(path)
    return windows_extended_path(path)


def display(text: str) -> str:
    """Return *text* with the Win32 extended-path prefix removed, for messages."""

    return text.replace("\\\\?\\UNC\\", "\\\\").replace("\\\\?\\", "")


def copytree(src: str | os.PathLike[str], dst: str | os.PathLike[str]) -> str:
    """``shutil.copytree`` that is not limited by ``MAX_PATH`` on Windows.

    *dst* must not exist, as for ``shutil.copytree``; a destination that exists,
    or that appears while this call copies, raises ``FileExistsError`` and is
    never reported as a seed.

    The copy is made in a hidden folder this call created next to *dst* (a name
    already in use is never reused) and is moved to *dst* with one rename only
    when it is complete. Until that rename *dst* does not exist, so another init
    never sees an empty or partial *dst* and takes it for a finished seed. The
    system refuses a rename onto a folder that holds anything, and *dst* is
    checked once more just before it; the only folder the rename can replace is
    an empty one that another run created in the instant between that check and
    the rename, which holds no data. A failure removes only the folder this call
    created. A raised error keeps the class of the failure and names the paths
    without the extended-path prefix.
    """

    final = extended(dst)
    if os.path.lexists(final):
        raise FileExistsError(errno.EEXIST, "File exists", display(final))
    parent = os.path.dirname(final) or os.curdir
    staging = ""
    try:
        os.makedirs(parent, exist_ok=True)
        staging = _new_staging(parent, os.path.basename(final))
        shutil.copytree(extended(src), staging, dirs_exist_ok=True)
        if os.path.lexists(final):
            raise FileExistsError(errno.EEXIST, "File exists", display(final))
        try:
            os.rename(staging, final)
        except OSError as exc:
            if exc.errno in (errno.EEXIST, errno.ENOTEMPTY) and os.path.lexists(final):
                raise FileExistsError(errno.EEXIST, "File exists", display(final)) from exc
            raise
    except (OSError, shutil.Error) as exc:
        left = _remove(staging) if staging else False
        message = display(str(exc))
        if left:
            message += f" (the partial copy {display(staging)} could not be removed)"
        if _windows() or left:
            raise _same_kind(exc, message) from exc
        raise
    return os.fspath(dst)


def _same_kind(exc: OSError, message: str) -> OSError:
    """Return an error of the same class and errno as exc that carries message.

    Callers and tests tell a refused destination (FileExistsError) from any
    other failure by class, so rewording the message must not change it.
    """

    try:
        clean = type(exc)(message)
    except Exception:  # a subclass with a non-standard constructor
        clean = OSError(message)
    clean.errno = exc.errno
    return clean


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
