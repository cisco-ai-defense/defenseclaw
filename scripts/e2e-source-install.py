#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Own one isolated DefenseClaw source-install home for persistent E2E."""

from __future__ import annotations

import argparse
import os
import re
import secrets
import shutil
import stat
import sys
import tempfile
from pathlib import Path
from typing import NoReturn

_ROOT_RE = re.compile(r"defenseclaw-e2e-slot-(?:core|full-live)")
_OWNER_MARKER = ".defenseclaw-e2e-owner"
_STAGING_SUFFIX = ".staging"
_TOMBSTONE_SUFFIX = ".tombstone"
_BUILD_TOOL_NAMES = ("go", "node", "npm", "uv")
_BUILD_TOOL_SHIM_DIR = ".e2e-build-tools"


def _fail(message: str) -> NoReturn:
    """Exit without changing an untrusted install root."""

    raise SystemExit(f"e2e source install refused: {message}")


def _runner_workspace() -> Path:
    """Return the real, persistent GitHub runner workspace directory."""

    value = os.environ.get("RUNNER_WORKSPACE", "")
    if not value:
        _fail("RUNNER_WORKSPACE is required")
    candidate = Path(value)
    if not candidate.is_absolute():
        _fail("RUNNER_WORKSPACE must be absolute")
    try:
        info = candidate.lstat()
    except FileNotFoundError:
        _fail("RUNNER_WORKSPACE does not exist")
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        _fail("RUNNER_WORKSPACE must be a real directory")
    return candidate.resolve(strict=True)


def _root(value: str) -> Path:
    """Validate one canonical stable-slot child of the persistent workspace."""

    candidate = Path(value)
    if not candidate.is_absolute() or not _ROOT_RE.fullmatch(candidate.name):
        _fail("install home must be an absolute, slot-named E2E path")
    base = _runner_workspace()
    if candidate.parent.resolve(strict=True) != base:
        _fail("install home must be a direct child of RUNNER_WORKSPACE")
    return base / candidate.name


def _entry_exists(path: Path) -> bool:
    """Return whether a path entry exists without following a dangling link."""

    try:
        path.lstat()
    except FileNotFoundError:
        return False
    return True


def _validate_owned(root: Path, *, slot_name: str | None = None) -> None:
    """Prove that an existing root was created for this exact E2E job."""

    try:
        info = root.lstat()
    except FileNotFoundError:
        _fail("install home disappeared during validation")
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        _fail("install home is not a real directory")
    if hasattr(os, "getuid") and info.st_uid != os.getuid():
        _fail("install home is not owned by the current user")

    marker = root / _OWNER_MARKER
    try:
        marker_info = marker.lstat()
    except FileNotFoundError:
        _fail("install home has no E2E ownership marker")
    if not stat.S_ISREG(marker_info.st_mode) or stat.S_ISLNK(marker_info.st_mode):
        _fail("E2E ownership marker is not a regular file")
    if hasattr(os, "getuid") and marker_info.st_uid != os.getuid():
        _fail("E2E ownership marker is not owned by the current user")
    expected_name = root.name if slot_name is None else slot_name
    if marker.read_text(encoding="utf-8") != f"{expected_name}\n":
        _fail("E2E ownership marker does not match this job")


def _transaction_paths(root: Path) -> tuple[Path, Path]:
    """Return the exact crash-recovery siblings for one stable slot."""

    return (
        root.parent / f".{root.name}{_STAGING_SUFFIX}",
        root.parent / f".{root.name}{_TOMBSTONE_SUFFIX}",
    )


def _write_owner_marker(directory: Path, slot_name: str) -> None:
    """Durably mark a newly created private directory before publication."""

    marker = directory / _OWNER_MARKER
    descriptor = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(f"{slot_name}\n")
        handle.flush()
        os.fsync(handle.fileno())


def _validate_staging(staging: Path, root: Path) -> None:
    """Accept only the marker-only tree produced before slot publication."""

    _validate_owned(staging, slot_name=root.name)
    if {entry.name for entry in staging.iterdir()} != {_OWNER_MARKER}:
        _fail("E2E staging home contains unexpected state")


def _remove_owned_tree(path: Path, root: Path) -> None:
    """Drain a transaction tree without ever unmarking its exact path."""

    _validate_owned(path, slot_name=root.name)
    try:
        for child in path.iterdir():
            if child.name == _OWNER_MARKER:
                continue
            info = child.lstat()
            if stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode):
                shutil.rmtree(child)
            else:
                child.unlink()
    except OSError:
        _fail("could not remove owned E2E transaction contents")

    _validate_owned(path, slot_name=root.name)
    if {entry.name for entry in path.iterdir()} != {_OWNER_MARKER}:
        _fail("E2E transaction home changed during cleanup")

    # Move the empty, still-marked tree away from the exact recovery name
    # before the final marker unlink/rmdir pair. A hard abort can therefore
    # leave only a random inert entry, never an unmarked canonical blocker.
    garbage = path.parent / f".{root.name}.gc-{secrets.token_hex(12)}"
    os.rename(path, garbage)
    (garbage / _OWNER_MARKER).unlink()
    garbage.rmdir()


def _build_staging(root: Path, staging: Path) -> None:
    """Build a marked tree privately, then publish the exact staging path."""

    temporary = Path(tempfile.mkdtemp(prefix=f".{root.name}.build-", dir=root.parent))
    try:
        temporary.chmod(0o700)
        _write_owner_marker(temporary, root.name)
        _validate_staging(temporary, root)
        if _entry_exists(staging):
            _fail("E2E staging home appeared during preparation")
        os.rename(temporary, staging)
    finally:
        if _entry_exists(temporary):
            shutil.rmtree(temporary)


def _retire(root: Path, tombstone: Path) -> None:
    """Atomically retire an owned canonical slot before recursive removal."""

    _validate_owned(root)
    if _entry_exists(tombstone):
        _fail("canonical and retired install homes both exist")
    os.rename(root, tombstone)
    _remove_owned_tree(tombstone, root)


def prepare(root_value: str) -> None:
    """Transactionally publish a fresh home, replacing only an owned retry."""

    root = _root(root_value)
    staging, tombstone = _transaction_paths(root)

    if _entry_exists(root):
        _validate_owned(root)
    if _entry_exists(staging):
        _validate_staging(staging, root)
    if _entry_exists(tombstone):
        _validate_owned(tombstone, slot_name=root.name)
    if _entry_exists(root) and _entry_exists(tombstone):
        _fail("canonical and retired install homes both exist")
    if _entry_exists(tombstone):
        _fail("retired install home must be authorized and repaired before preparation")

    if not _entry_exists(staging):
        _build_staging(root, staging)
    if _entry_exists(root):
        _retire(root, tombstone)

    if _entry_exists(root):
        _fail("install home appeared during publication")
    os.rename(staging, root)
    _validate_owned(root)


def cleanup(root_value: str) -> None:
    """Transactionally retire marked E2E state; preserve every unknown path."""

    root = _root(root_value)
    staging, tombstone = _transaction_paths(root)

    if _entry_exists(staging):
        _validate_staging(staging, root)
    if _entry_exists(tombstone):
        _validate_owned(tombstone, slot_name=root.name)
    if _entry_exists(root):
        _validate_owned(root)
    if _entry_exists(root) and _entry_exists(tombstone):
        _fail("canonical and retired install homes both exist")
    if _entry_exists(tombstone):
        _fail("retired install home must be authorized and repaired before cleanup")

    if _entry_exists(staging):
        _remove_owned_tree(staging, root)
    if _entry_exists(root):
        _retire(root, tombstone)


def verify(root_value: str) -> None:
    """Validate ownership without changing the selected install home."""

    _validate_owned(_root(root_value))


def authorize_cleanup(root_value: str) -> None:
    """Allow cleanup only when the selected root is absent or already owned."""

    root = _root(root_value)
    staging, tombstone = _transaction_paths(root)
    if _entry_exists(root):
        _validate_owned(root)
    if _entry_exists(staging):
        _validate_staging(staging, root)
    if _entry_exists(tombstone):
        _validate_owned(tombstone, slot_name=root.name)
    if _entry_exists(root) and _entry_exists(tombstone):
        _fail("canonical and retired install homes both exist")
    if _entry_exists(tombstone):
        # A killed recursive retirement can leave root-owned descendants.
        # Restore the still-marked tree to the canonical slot so the workflow's
        # next runner-cleanup invocation repairs it before prepare/cleanup.
        os.rename(tombstone, root)
        _validate_owned(root)


def _preserve_persistent_build_tools(root: Path, persistent_bin: Path) -> Path | None:
    """Expose only required build tools that resolve from the filtered account bin."""

    preserved: dict[str, Path] = {}
    for name in _BUILD_TOOL_NAMES:
        resolved = shutil.which(name)
        if not resolved:
            continue
        candidate = Path(resolved)
        if candidate.parent.resolve(strict=False) != persistent_bin:
            continue
        try:
            target = candidate.resolve(strict=True)
            info = target.stat()
        except OSError:
            _fail(f"persistent build tool {name} is not a stable executable")
        if not stat.S_ISREG(info.st_mode) or not os.access(target, os.X_OK):
            _fail(f"persistent build tool {name} is not a stable executable")
        preserved[name] = target

    if not preserved:
        return None

    shim_dir = root / _BUILD_TOOL_SHIM_DIR
    if _entry_exists(shim_dir):
        info = shim_dir.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            _fail("isolated build-tool directory is not a real directory")
        if hasattr(os, "getuid") and info.st_uid != os.getuid():
            _fail("isolated build-tool directory is not owned by the current user")
        unexpected = {entry.name for entry in shim_dir.iterdir()} - set(_BUILD_TOOL_NAMES)
        if unexpected:
            _fail("isolated build-tool directory contains unexpected entries")
        for entry in shim_dir.iterdir():
            if not stat.S_ISLNK(entry.lstat().st_mode):
                _fail(f"isolated build-tool shim {entry.name} is not a symbolic link")
            entry.unlink()
    else:
        shim_dir.mkdir(mode=0o700)

    for name, target in preserved.items():
        shim = shim_dir / name
        shim.symlink_to(target)
        if shim.resolve(strict=True) != target:
            _fail(f"isolated build-tool shim {name} does not match its executable")
    return shim_dir


def isolated_path(root_value: str) -> str:
    """Prepend isolated bins without exposing unrelated account executables."""

    root = _root(root_value)
    _validate_owned(root)
    persistent_bin = (Path.home() / ".local" / "bin").resolve(strict=False)
    isolated_bin = root / ".local" / "bin"
    components: list[str] = []
    for component in os.environ.get("PATH", "").split(os.pathsep):
        if not component:
            continue
        if Path(component).resolve(strict=False) in (persistent_bin, isolated_bin):
            continue
        components.append(component)
    build_tools = _preserve_persistent_build_tools(root, persistent_bin)
    prefix = [os.fspath(isolated_bin)]
    if build_tools is not None:
        prefix.append(os.fspath(build_tools))
    return os.pathsep.join((*prefix, *components))


def parse_args(argv: list[str]) -> argparse.Namespace:
    """Parse the small workflow-only command surface."""

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "command",
        choices=("prepare", "verify", "authorize-cleanup", "cleanup", "path"),
    )
    parser.add_argument("root")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Run one isolated-home operation."""

    args = parse_args(sys.argv[1:] if argv is None else argv)
    if args.command == "prepare":
        prepare(args.root)
    elif args.command == "verify":
        verify(args.root)
    elif args.command == "authorize-cleanup":
        authorize_cleanup(args.root)
    elif args.command == "cleanup":
        cleanup(args.root)
    else:
        print(isolated_path(args.root))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
