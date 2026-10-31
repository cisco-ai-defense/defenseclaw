# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""The result the Windows deferred uninstall cleanup leaves behind.

`defenseclaw uninstall` on Windows ends by scheduling a helper that removes
the data folder and the binaries once the CLI has exited. When another
window of the same account still holds a file (an unfinished setup, a TUI),
that removal fails and DefenseClaw stays; the reason was only in the
helper's result file in TEMP (p0-round GAP-1095). Every later `defenseclaw`
command of that install names it.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

RESULT_PREFIX = "defenseclaw-uninstall-result-"
_MAX_RESULT_BYTES = 64 << 10


def _install_time() -> float:
    """When the running CLI was installed, 0 if unknown.

    The venv's pyvenv.cfg is written by the install; a package file can keep
    the time uv's cache unpacked it.
    """
    times = []
    for path in (Path(sys.prefix) / "pyvenv.cfg", Path(__file__)):
        try:
            times.append(path.stat().st_mtime)
        except OSError:
            continue
    return max(times, default=0.0)


def failed_deferred_uninstall(folder: str | None = None, since: float | None = None) -> tuple[str, str] | None:
    """Return (detail, path) of the newest uninstall result when it says failed.

    Only a result written after this install counts: a reinstall after the
    failed run is not reported. None when there is nothing to report.
    """
    folder = folder or tempfile.gettempdir()
    since = _install_time() if since is None else since
    newest: tuple[float, str] | None = None
    try:
        with os.scandir(folder) as entries:
            for entry in entries:
                if not (entry.name.startswith(RESULT_PREFIX) and entry.name.endswith(".json")):
                    continue
                try:
                    if not entry.is_file(follow_symlinks=False):
                        continue
                    mtime = entry.stat(follow_symlinks=False).st_mtime
                except OSError:
                    continue
                if newest is None or mtime > newest[0]:
                    newest = (mtime, entry.path)
    except OSError:
        return None
    if newest is None or newest[0] <= since:
        return None
    try:
        with open(newest[1], encoding="utf-8") as stream:
            result = json.loads(stream.read(_MAX_RESULT_BYTES))
    except (OSError, ValueError):
        return None
    if not isinstance(result, dict) or result.get("status") != "failed":
        return None
    detail = str(result.get("detail") or "the removal did not finish").strip()
    return detail, newest[1]


def failed_deferred_uninstall_message(found: tuple[str, str]) -> str:
    detail, path = found
    return (
        f"The last `defenseclaw uninstall` did not finish, so DefenseClaw is still installed: {detail.rstrip('.')}. "
        "Close every other window that runs DefenseClaw (a setup waiting at its prompt, the TUI), "
        f"then run the same `defenseclaw uninstall` command again. Details: {path}"
    )
