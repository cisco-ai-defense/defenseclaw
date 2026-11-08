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

    The copy is made in a hidden folder this call creates next to *dst* and is
    moved to *dst* only when it is complete. A failure removes that folder and
    nothing else, so *dst* is never a partial copy and a destination another
    run created (or created while this one copied) is never touched. When
    another run published *dst* first, that copy is kept and returned. A raised
    error names the paths without the extended-path prefix.
    """

    final = extended(dst)
    if os.path.lexists(final):
        raise FileExistsError(errno.EEXIST, "File exists", display(final))
    staging = os.path.join(os.path.dirname(final), f".{os.path.basename(final)}.seed-{uuid.uuid4().hex[:8]}")
    try:
        os.makedirs(os.path.dirname(final), exist_ok=True)
        os.mkdir(staging)
        shutil.copytree(extended(src), staging, dirs_exist_ok=True)
        os.rename(staging, final)
    except (OSError, shutil.Error) as exc:
        left = _remove(staging)
        if os.path.isdir(final) and not os.path.islink(final) and not left:
            # Another run published a complete copy while this one copied.
            return os.fspath(dst)
        message = display(str(exc))
        if left:
            message += f" (the partial copy {display(staging)} could not be removed)"
        if os.name == "nt" or left:
            raise OSError(message) from exc
        raise
    return os.fspath(dst)


def rmtree(path: str | os.PathLike[str]) -> None:
    """Remove *path* and what is below it, ignoring errors, on any path length."""

    shutil.rmtree(extended(path), ignore_errors=True)


def _remove(path: str) -> bool:
    """Remove *path*; return True when something of it is still there."""

    if os.path.lexists(path):
        shutil.rmtree(path, ignore_errors=True)
    return os.path.lexists(path)
