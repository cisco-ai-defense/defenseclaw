"""Host-state snapshot and restore.

Each snapshot bundles paths from ``Settings.snapshot_paths`` into a single
tarball under ``runs/<run-id>/snapshots/<label>.tgz``. Restore reverses
the operation. This is intended to be invoked between lifecycle cells
(install / uninstall / upgrade) so that destructive runs are reversible.

This is a safety/repro helper, NOT automation. The agent invokes it from
lifecycle case prompts; the harness itself never makes pass/fail calls
based on snapshot diffs.
"""

from __future__ import annotations

import shutil
import tarfile
from pathlib import Path

from dctest import utc_now
from dctest.config import get_settings
from dctest.exceptions import SnapshotError
from dctest.services import run_store


def _expand(path_str: str) -> Path:
    return Path(path_str).expanduser().resolve()


# Patterns the snapshot intentionally never archives. These files are
# either large, transient, or recreated by DefenseClaw at process start,
# so capturing them only inflates the snapshot size and slows down
# `tar`. Tuple of (substring, glob_segment) checked case-insensitively
# against each path's last-segment / suffix.
_SNAPSHOT_EXCLUDE_GLOBS = (
    "*.sqlite-wal",
    "*.sqlite-shm",
    "*.sqlite-journal",
    "*.log",
    "*.lock",
    "*.tmp",
    "*.swp",
)

_SNAPSHOT_EXCLUDE_DIRS = (
    "logs",
    ".tmp",
    "__pycache__",
    "node_modules",
)


def _tar_filter(tarinfo: tarfile.TarInfo) -> tarfile.TarInfo | None:
    """Drop transient files from the snapshot to keep tarballs lean."""
    import fnmatch

    name = Path(tarinfo.name).name
    parts = Path(tarinfo.name).parts

    for pat in _SNAPSHOT_EXCLUDE_GLOBS:
        if fnmatch.fnmatchcase(name, pat):
            return None
    for d in _SNAPSHOT_EXCLUDE_DIRS:
        if d in parts:
            return None
    return tarinfo


def _collect_existing(paths: list[str]) -> list[Path]:
    out: list[Path] = []
    for p in paths:
        expanded = _expand(p)
        if expanded.exists():
            out.append(expanded)
    return out


def create_snapshot(run_id: str, label: str, extra_paths: list[str] | None = None) -> Path:
    """Create a tarball snapshot for the given run and label.

    Returns the absolute path of the resulting tarball.
    """
    settings = get_settings()
    snapshots = run_store.snapshots_dir(settings.runs_root, run_id)
    snapshots.mkdir(parents=True, exist_ok=True)
    ts = utc_now().strftime("%Y%m%dT%H%M%SZ")
    safe_label = label.replace("/", "_").replace(" ", "_")
    out_path = snapshots / f"{ts}__{safe_label}.tgz"

    paths = list(settings.snapshot_paths)
    if extra_paths:
        paths.extend(extra_paths)
    existing = _collect_existing(paths)
    if not existing:
        # Still produce an empty archive so the agent has a sentinel to point to.
        with tarfile.open(out_path, "w:gz") as tar:
            placeholder = snapshots / f"{safe_label}.empty"
            placeholder.write_text(
                "No matching paths existed at snapshot time.\n", encoding="utf-8"
            )
            tar.add(placeholder, arcname=placeholder.name)
            placeholder.unlink(missing_ok=True)
        return out_path

    home = Path.home()
    with tarfile.open(out_path, "w:gz") as tar:
        for p in existing:
            arcname = _arcname_for(p, home)
            tar.add(p, arcname=arcname, recursive=True, filter=_tar_filter)
    return out_path


def _arcname_for(path: Path, home: Path) -> str:
    try:
        rel = path.relative_to(home)
        return f"HOME/{rel.as_posix()}"
    except ValueError:
        return path.as_posix().lstrip("/")


def list_snapshots(run_id: str) -> list[Path]:
    settings = get_settings()
    snapshots = run_store.snapshots_dir(settings.runs_root, run_id)
    if not snapshots.exists():
        return []
    return sorted(p for p in snapshots.iterdir() if p.suffix == ".tgz")


def restore_snapshot(run_id: str, label_or_path: str, *, dry_run: bool = False) -> list[Path]:
    """Extract a snapshot back to its original paths.

    ``label_or_path`` may be a substring of a snapshot filename or a full
    absolute path. Returns the list of paths written.

    Restore is a destructive operation; pass ``dry_run=True`` to merely
    report which paths would be written.
    """
    settings = get_settings()
    target = _resolve_snapshot(run_id, label_or_path)
    home = Path.home()
    written: list[Path] = []
    with tarfile.open(target, "r:gz") as tar:
        for member in tar.getmembers():
            if member.name.startswith("HOME/"):
                dest = home / member.name[len("HOME/") :]
            else:
                dest = Path("/" + member.name)
            if dry_run:
                written.append(dest)
                continue
            if not _is_safe_restore(dest):
                raise SnapshotError(f"Refusing to restore outside allowlist: {dest}")
            if member.isdir():
                dest.mkdir(parents=True, exist_ok=True)
            else:
                dest.parent.mkdir(parents=True, exist_ok=True)
                extracted = tar.extractfile(member)
                if extracted is None:
                    continue
                tmp = dest.with_suffix(dest.suffix + ".dctest-restore-tmp")
                with tmp.open("wb") as fh:
                    shutil.copyfileobj(extracted, fh)
                tmp.replace(dest)
            written.append(dest)
    _ = settings  # quiet linter; kept for future settings-driven overrides
    return written


def _resolve_snapshot(run_id: str, label_or_path: str) -> Path:
    if Path(label_or_path).is_absolute():
        p = Path(label_or_path)
        if not p.exists():
            raise SnapshotError(f"Snapshot does not exist: {p}")
        return p
    candidates = list_snapshots(run_id)
    matches = [c for c in candidates if label_or_path in c.name]
    if not matches:
        raise SnapshotError(
            f"No snapshot in run {run_id!r} matches {label_or_path!r}; "
            f"available: {[c.name for c in candidates]}"
        )
    return matches[-1]


_ALLOWLIST_PREFIXES = (
    str(Path.home()),
    "/tmp/",
    "/private/tmp/",
)


def _is_safe_restore(dest: Path) -> bool:
    """Allow restore only into the user's home or a tmp directory."""
    try:
        resolved = dest.expanduser().resolve()
    except (OSError, RuntimeError):
        return False
    text = str(resolved)
    return any(text.startswith(prefix) for prefix in _ALLOWLIST_PREFIXES)
