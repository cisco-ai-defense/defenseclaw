"""Cross-platform environment fixtures shared by unittest-style tests."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest


def isolated_home_env(home: str | os.PathLike[str]) -> dict[str, str]:
    """Return a complete disposable user identity rooted at *home*."""
    root = Path(home)
    drive, tail = os.path.splitdrive(os.fspath(root))
    return {
        "HOME": os.fspath(root),
        "USERPROFILE": os.fspath(root),
        "HOMEDRIVE": drive,
        "HOMEPATH": tail or os.sep,
        "APPDATA": os.fspath(root / "AppData" / "Roaming"),
        "LOCALAPPDATA": os.fspath(root / "AppData" / "Local"),
        "XDG_CONFIG_HOME": os.fspath(root / ".config"),
        "XDG_CACHE_HOME": os.fspath(root / ".cache"),
        "XDG_DATA_HOME": os.fspath(root / ".local" / "share"),
        "NPM_CONFIG_PREFIX": os.fspath(root / ".npm-global"),
        "DEFENSECLAW_HOME": os.fspath(root / ".defenseclaw"),
        "CODEX_HOME": os.fspath(root / ".codex"),
        "CLAUDE_CONFIG_DIR": os.fspath(root / ".claude"),
        "HERMES_HOME": os.fspath(root / "AppData" / "Local" / "hermes"),
    }


def _can_create_symlink() -> bool:
    if not hasattr(os, "symlink"):
        return False
    with tempfile.TemporaryDirectory(prefix="dc-symlink-capability-") as tmp:
        target = Path(tmp) / "target"
        link = Path(tmp) / "link"
        target.write_text("capability", encoding="utf-8")
        try:
            link.symlink_to(target)
        except OSError:
            return False
        return link.is_symlink()


requires_symlink_privilege = pytest.mark.skipif(
    not _can_create_symlink(),
    reason=(
        "symlink-only assertion requires Windows SeCreateSymbolicLinkPrivilege; "
        "reparse containment has separate coverage"
    ),
)
