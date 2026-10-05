#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Remove the retired binaries pre-1.0 installers left behind, after `make all`.

0.x installers parked the binaries they replaced in
<temp>/.defenseclaw-install-custody-<uid>-<hash> and in
~/.defenseclaw-install-custody (about 250 MB per account). install.sh and
install.ps1 remove them once a 1.0 install is live, and `defenseclaw uninstall
--binaries` removes them too, but a source install ran neither, so they stayed
(GAP-0053). This does the same sweep for `make all`.

It never touches the custody folder beside the installed launchers
(<install dir>/.defenseclaw-install-custody): a running gateway may still be
executing a binary retired there. Only folders owned by this account are
removed. Optional arguments name the temp folders to search (default: the
temp folder and /tmp). Always exits 0: a leftover is not worth failing over.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
from pathlib import Path

PREFIX = ".defenseclaw-install-custody"


def _owned(path: Path) -> bool:
    try:
        info = path.lstat()
    except OSError:
        return False
    if path.is_symlink():
        return False
    return not hasattr(os, "getuid") or info.st_uid == os.getuid()


def candidates(temp_dirs: list[str]) -> list[Path]:
    home = Path.home()
    data_dir = Path(os.environ.get("DEFENSECLAW_HOME") or home / ".defenseclaw").expanduser()
    paths = {home / PREFIX, data_dir.absolute().parent / PREFIX}
    for parent in temp_dirs:
        try:
            names = os.listdir(parent)
        except OSError:
            continue
        paths.update(Path(parent) / name for name in names if name.startswith(PREFIX + "-"))
    return sorted(paths)


def main(argv: list[str]) -> int:
    temp_dirs = argv or sorted({tempfile.gettempdir(), *([] if os.name == "nt" else ["/tmp"])})
    removed = 0
    for path in candidates(temp_dirs):
        if not path.is_dir() or not _owned(path):
            continue
        try:
            shutil.rmtree(path)
            removed += 1
        except OSError as exc:
            print(f"  could not remove {path}: {exc}", file=sys.stderr)
    if removed:
        print(f"  Removed {removed} folder(s) of retired binaries left by pre-1.0 installers.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
