# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Exact published OpenClaw provider identities for plugin admission."""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
from datetime import datetime, timedelta, timezone
from itertools import islice
from pathlib import Path

from defenseclaw.hermes_skills import (
    _filesystem_identity,
    _is_real_directory,
    _read_regular_file,
    _tree_sha256,
)

# SHA-256 of sorted relative paths and file bytes, using the same bounded,
# non-link tree reader as the Hermes vendor library. These are the published
# npm package trees, including their bundled dependencies.
VENDOR_DIGESTS = {
    ("@openclaw/amazon-bedrock-provider", "2026.10.9"):
        "88d9c6715528c0ddfb47adf43a35ccbfec3bb4b8fe75f233e8be431b9ddce3cb",
    ("@openclaw/amazon-bedrock-provider", "2026.10.10"):
        "48b7d1fb0862b9914c722b514a3214202ce7a1efe7b2a6d8a50fe31456ae431a",
}

_PRIVATE_INSTALL_COMPONENTS = frozenset({
    ".ssh", ".aws", ".gnupg", ".kube", ".azure", ".docker", ".defenseclaw",
})


def inspect_official_provider_tree(plugin_dir: str, *, data_dir: str = "") -> str | None:
    """Identify published bytes plus validated installer-created peer links."""

    manifest = _read_regular_file(
        os.path.join(plugin_dir, "package.json"), max_bytes=64 * 1024,
    )
    if manifest is None:
        return None
    try:
        package = json.loads(manifest)
    except (UnicodeDecodeError, ValueError):
        return None
    if not isinstance(package, dict):
        return None
    name, version = package.get("name"), package.get("version")
    if not isinstance(name, str) or not isinstance(version, str):
        return None
    want = VENDOR_DIGESTS.get((name, version))
    if not want:
        return None

    peers = package.get("peerDependencies", {})
    if not isinstance(peers, dict):
        return None
    root = os.path.abspath(plugin_dir)
    tolerated: set[str] = set()
    links: dict[str, tuple[str, tuple]] = {}
    for peer in peers:
        if not isinstance(peer, str) or not re.fullmatch(
            r"(?:@[a-z0-9._-]+/)?[a-z0-9._-]+", peer,
        ) or any(part in (".", "..") for part in peer.split("/")):
            return None
        relative = "node_modules/" + peer
        link = os.path.join(plugin_dir, *relative.split("/"))
        tolerated.add(relative)
        try:
            links[peer] = (link, _validated_peer_link(link, root, peer, data_dir))
        except (OSError, ValueError, TypeError, AttributeError):
            return None

    before_tree = _tree_entry_state(root)
    if before_tree is None:
        return None
    # A same-size edit can retain its mtime, and Windows ctime is creation
    # time. Recheck the published bytes and links before admitting.
    for _ in range(2):
        if _tree_sha256(plugin_dir, tolerated_links=frozenset(tolerated)) != want:
            return None
        for peer, (link, before) in links.items():
            try:
                if before != _validated_peer_link(link, root, peer, data_dir):
                    return None
            except (OSError, ValueError, TypeError, AttributeError):
                return None
        if before_tree != _tree_entry_state(root):
            return None
    return name


def _tree_entry_state(root: str) -> tuple | None:
    """Record every in-root entry so the digest describes the final tree."""

    try:
        root_info = os.stat(root, follow_symlinks=False)
        if not _is_real_directory(root_info):
            return None
        entries = [(".", root_info.st_mode, _filesystem_identity(root_info), None)]
        pending = [(root, "")]
        while pending:
            current, parent = pending.pop()
            with os.scandir(current) as children:
                for child in children:
                    info = child.stat(follow_symlinks=False)
                    relative = os.path.join(parent, child.name).replace("\\", "/")
                    target = os.readlink(child.path) if stat.S_ISLNK(info.st_mode) else None
                    entries.append((relative, info.st_mode, _filesystem_identity(info), target))
                    if _is_real_directory(info):
                        pending.append((child.path, relative))
        return tuple(sorted(entries))
    except (OSError, ValueError):
        return None


def _validated_peer_link(link: str, root: str, peer: str, data_dir: str) -> tuple:
    """Record the complete in-root path to an optional installer peer link."""

    relative = os.path.relpath(link, root)
    parts = relative.split(os.sep)
    ancestors = []
    current = root
    for part in ("", *parts[:-1]):
        if part:
            current = os.path.join(current, part)
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            ancestors.append(None)
            return tuple(ancestors), None
        if not _is_real_directory(info):
            raise ValueError("peer path contains a non-directory entry")
        ancestors.append(_filesystem_identity(info))

    try:
        info = os.lstat(link)
    except FileNotFoundError:
        return tuple(ancestors), None
    if not stat.S_ISLNK(info.st_mode):
        raise ValueError("peer entry is not a link")
    destination = os.path.realpath(link)
    if os.path.commonpath((os.path.realpath(root), destination)) == os.path.realpath(root):
        raise ValueError("peer link points inside the package")
    if any(part.casefold() in _PRIVATE_INSTALL_COMPONENTS for part in Path(destination).parts):
        raise ValueError("peer link points into private state")
    active_root = _active_openclaw_root(data_dir=data_dir) if peer == "openclaw" else None
    if active_root is None or not os.path.samefile(destination, active_root):
        raise ValueError("peer link points outside the active installation")
    if not stat.S_ISDIR(os.stat(destination, follow_symlinks=False).st_mode):
        raise ValueError("peer link target is not a directory")
    manifest = _read_regular_file(
        os.path.join(destination, "package.json"), max_bytes=1024 * 1024,
    )
    if manifest is None or json.loads(manifest).get("name") != peer:
        raise ValueError("peer link target has another package identity")
    return tuple(ancestors), (_filesystem_identity(info), os.readlink(link), manifest)


def _named_openclaw_package(path: str) -> bool:
    if (os.path.basename(path) != "openclaw"
            or os.path.basename(os.path.dirname(path)) != "node_modules"):
        return False
    manifest = _read_regular_file(
        os.path.join(path, "package.json"), max_bytes=1024 * 1024,
    )
    if manifest is None:
        return False
    try:
        return json.loads(manifest).get("name") == "openclaw"
    except (UnicodeDecodeError, ValueError, AttributeError):
        return False


def _openclaw_root_for_executable(executable: str, *, discovered: bool = False) -> str | None:
    """Bind a runnable launcher to its package, without running the launcher."""

    try:
        info = os.stat(executable)
        if not stat.S_ISREG(info.st_mode) or (
            os.name != "nt" and not os.access(executable, os.X_OK)
        ):
            return None
    except OSError:
        return None

    resolved_executable = os.path.realpath(executable)
    directory = os.path.dirname(resolved_executable)
    for _ in range(16):
        if _named_openclaw_package(directory):
            return directory
        parent = os.path.dirname(directory)
        if parent == directory:
            break
        directory = parent

    manager_root = _manager_openclaw_root(executable)
    if manager_root:
        return manager_root

    # An unrecorded off-PATH wrapper is not evidence of which package it
    # launches. npm's linked launchers have already resolved to their package
    # above; a recorded or PATH-selected wrapper is the operator's launcher.
    if discovered:
        return None
    bin_dir = os.path.dirname(os.path.abspath(executable))
    for candidate in (
        os.path.join(bin_dir, "node_modules", "openclaw"),
        os.path.join(os.path.dirname(bin_dir), "lib", "node_modules", "openclaw"),
    ):
        resolved = os.path.realpath(candidate)
        if _named_openclaw_package(resolved):
            return resolved
    return None


def _manager_openclaw_root(executable: str) -> str | None:
    """Resolve package-manager shims that do not link into the package."""

    home = Path.home()
    launcher = os.path.normcase(os.path.abspath(executable))

    def at(path: Path) -> bool:
        return launcher == os.path.normcase(os.path.abspath(path))

    candidates: list[Path] = []
    if at(home / ".volta/bin/openclaw"):
        prefix = home / ".volta/tools/image/packages/openclaw"
        candidates.extend((
            prefix / "lib/node_modules/openclaw",
            prefix / "node_modules/openclaw",
        ))
    elif at(home / ".local/share/pnpm/openclaw") or at(home / "Library/pnpm/openclaw"):
        root = (home / ".local/share/pnpm" if at(home / ".local/share/pnpm/openclaw")
                else home / "Library/pnpm")
        for prefix in islice(root.glob("global/*"), 16):
            candidates.extend((
                prefix / "node_modules/openclaw",
                prefix / "lib/node_modules/openclaw",
            ))
    elif at(home / ".asdf/shims/openclaw"):
        candidates.extend(islice(
            home.glob(".asdf/installs/nodejs/*/lib/node_modules/openclaw"), 16,
        ))
    elif at(home / ".local/share/mise/shims/openclaw"):
        candidates.extend(islice(
            home.glob(".local/share/mise/installs/node/*/lib/node_modules/openclaw"), 16,
        ))
    else:
        return None

    roots = {os.path.realpath(path) for path in candidates if _named_openclaw_package(os.path.realpath(path))}
    return next(iter(roots)) if len(roots) == 1 else None


def _recorded_openclaw_executable(data_dir: str) -> str | None:
    """Read the latest operator discovery pointer; revalidate it on disk."""

    from defenseclaw.config import default_data_path

    record = (Path(data_dir) if data_dir else default_data_path()) / "agent_discovery.json"
    payload = _read_regular_file(str(record), max_bytes=1024 * 1024)
    if payload is None:
        return None
    try:
        document = json.loads(payload)
        if document.get("version") != 7 or document.get("ttl_seconds") != 86_400:
            return None
        scanned_at = datetime.fromisoformat(document["scanned_at"].replace("Z", "+00:00"))
        age = datetime.now(timezone.utc) - scanned_at.astimezone(timezone.utc)
        if not timedelta(0) <= age <= timedelta(days=1):
            return None
        signal = document["agents"]["openclaw"]
        executable = signal["binary_path"]
        if signal.get("installed") and isinstance(executable, str) and os.path.isabs(executable):
            return executable
    except (UnicodeDecodeError, ValueError, TypeError, KeyError, AttributeError):
        pass
    return None


def _discovered_openclaw_executables() -> list[str]:
    """Enumerate bounded per-user npm and Node-manager launcher locations."""

    home = Path.home()
    candidates = [
        home / ".npm-global/bin/openclaw",
        home / ".local/bin/openclaw",
        home / ".npm-packages/bin/openclaw",
        home / ".config/yarn/global/node_modules/.bin/openclaw",
        home / ".volta/bin/openclaw",
        home / ".local/share/pnpm/openclaw",
        home / "Library/pnpm/openclaw",
        home / ".asdf/shims/openclaw",
        home / ".local/share/mise/shims/openclaw",
        home / ".local/share/fnm/aliases/default/bin/openclaw",
        home / ".yarn/bin/openclaw",
        home / ".bun/bin/openclaw",
        home / "bin/openclaw",
        home / ".linuxbrew/bin/openclaw",
        Path("/home/linuxbrew/.linuxbrew/bin/openclaw"),
        Path("/usr/local/bin/openclaw"),
        Path("/opt/homebrew/bin/openclaw"),
    ]
    for pattern in (
        ".nvm/versions/node/*/bin/openclaw",
        ".local/share/fnm/node-versions/*/installation/bin/openclaw",
        "Library/Application Support/fnm/node-versions/*/installation/bin/openclaw",
        ".fnm/node-versions/*/installation/bin/openclaw",
        ".asdf/installs/nodejs/*/bin/openclaw",
        ".local/share/mise/installs/node/*/bin/openclaw",
        ".local/share/pnpm/global/*/node_modules/.bin/openclaw",
    ):
        candidates.extend(islice(home.glob(pattern), 16))
    npmrc = _read_regular_file(str(home / ".npmrc"), max_bytes=64 * 1024)
    if npmrc is not None:
        for line in npmrc.decode("utf-8", errors="replace").splitlines():
            key, sep, value = line.partition("=")
            if sep and key.strip().lower() == "prefix":
                prefix = value.strip().strip('"\'').replace("${HOME}", str(home))
                prefix = os.path.expanduser(prefix)
                if os.path.isabs(prefix):
                    candidates.append(Path(prefix) / "bin/openclaw")
    return [str(candidate) for candidate in candidates]


def _active_openclaw_root(*, data_dir: str = "") -> str | None:
    """Find one active package from recorded, PATH, or discovered launchers."""

    recorded = _recorded_openclaw_executable(data_dir)
    if recorded:
        root = _openclaw_root_for_executable(recorded)
        if root:
            return root
    on_path = shutil.which("openclaw")
    path_root = _openclaw_root_for_executable(on_path) if on_path else None
    roots = {
        root for candidate in _discovered_openclaw_executables()
        if (root := _openclaw_root_for_executable(candidate, discovered=True))
    }
    if path_root:
        # A scanner-service PATH may differ from the operator's. Without a
        # recorded executable, conflicting runnable installs are ambiguous.
        return path_root if not roots or roots == {path_root} else None
    return next(iter(roots)) if len(roots) == 1 else None
