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

import os
import shutil
from typing import Any

from defenseclaw.file_permissions import windows_extended_path


def extended(path: str | os.PathLike[str]) -> str:
    """Return *path* unlimited by ``MAX_PATH`` on Windows, unchanged elsewhere."""

    if os.name != "nt":
        return os.fspath(path)
    return windows_extended_path(path)


def display(text: str) -> str:
    """Return *text* with the Win32 extended-path prefix removed, for messages."""

    return text.replace("\\\\?\\UNC\\", "\\\\").replace("\\\\?\\", "")


def copytree(src: str | os.PathLike[str], dst: str | os.PathLike[str], **kwargs: Any) -> str:
    """``shutil.copytree`` that is not limited by ``MAX_PATH`` on Windows.

    A copy that fails part way removes the folder it started, so a later run
    does not take the partial copy for a seeded one. A raised error names the
    paths without the extended-path prefix.
    """

    started = not os.path.lexists(dst)
    try:
        shutil.copytree(extended(src), extended(dst), **kwargs)
    except (OSError, shutil.Error) as exc:
        if started and os.path.isdir(extended(dst)) and not os.path.islink(extended(dst)):
            rmtree(dst)
        if os.name == "nt":
            raise OSError(display(str(exc))) from exc
        raise
    return os.fspath(dst)


def rmtree(path: str | os.PathLike[str]) -> None:
    """Remove *path* and what is below it, ignoring errors, on any path length."""

    shutil.rmtree(extended(path), ignore_errors=True)
