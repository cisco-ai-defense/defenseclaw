# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Exact published OpenClaw provider identities for plugin admission."""

from __future__ import annotations

import json
import os
import re
import stat
from pathlib import Path, PureWindowsPath
from typing import NamedTuple

from defenseclaw.hermes_skills import (
    _filesystem_identity,
    _is_link_or_junction,
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


class ProviderIdentity(NamedTuple):
    name: str
    possible_peer: bool


def inspect_official_provider_tree(plugin_dir: str, *, data_dir: str = "") -> ProviderIdentity | None:
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
    return ProviderIdentity(
        name=name,
        possible_peer=any(state[1] is not None for _, state in links.values()),
    )


def _tree_entry_state(root: str) -> tuple | None:
    """Record every in-root entry so the digest describes the final tree.

    Each entry is read with ``os.stat`` on its own path, never with the
    ``DirEntry`` the listing hands out. On Windows that is directory-listing
    data: it carries no volume or file ID, and it shows the modification time
    of a subdirectory only after NTFS has flushed it to the parent index, so
    two listings of an unchanged tree can differ.
    """

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
                    info = os.stat(child.path, follow_symlinks=False)
                    relative = os.path.join(parent, child.name).replace("\\", "/")
                    target = os.readlink(child.path) if _is_link_or_junction(info) else None
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
    if not _is_link_or_junction(info):
        raise ValueError("peer entry is not a link or junction")
    if _peer_path_uses_private_state(link, data_dir):
        raise ValueError("peer link points into private state")
    destination = os.path.realpath(link)
    if _path_within(os.path.realpath(root), destination):
        raise ValueError("peer link points inside the package")
    if peer != "openclaw":
        raise ValueError("peer link is not the OpenClaw package")
    target = os.stat(destination, follow_symlinks=False)
    if not stat.S_ISDIR(target.st_mode):
        raise ValueError("peer link target is not a directory")
    manifest = _read_regular_file(
        os.path.join(destination, "package.json"), max_bytes=1024 * 1024,
    )
    if manifest is None or json.loads(manifest).get("name") != peer:
        raise ValueError("peer link target has another package identity")
    # The validated target is bound by its volume and file ID, not only by
    # its path and manifest, so a different directory at the same path is
    # judged again.
    return tuple(ancestors), (
        _filesystem_identity(info), os.readlink(link), destination,
        (target.st_dev, target.st_ino), manifest,
    )


def _peer_path_uses_private_state(link: str, data_dir: str) -> bool:
    """Check every named and every resolved location on the way to the peer.

    A protected name can appear in a link or junction target, where a later
    alias could hide it, or only after resolution, behind an alias with an
    ordinary name. Both are checked at every hop, so an alias kind this walk
    does not expand is still judged by where it resolves. Every location is
    judged as a whole path, from its anchor (a UNC server and share are names
    too) to its last name, and the final destination is judged again.
    """

    roots = _private_roots(data_dir)

    def private(location: str) -> bool:
        resolved = os.path.realpath(location)
        return (
            _names_private_state(location)
            or _names_private_state(resolved)
            or any(_path_within(root, resolved) for root in roots)
        )

    target = _on_link_drive(os.readlink(link), link)
    path = target if os.path.isabs(target) else os.path.join(os.path.dirname(link), target)
    if not os.path.isabs(path):
        path = os.path.join(os.getcwd(), path)
    parts = Path(path).parts
    current = _path_anchor(path)
    if private(_exact_location(current, last=False)):
        return True
    pending = list(parts[1:])
    # Whether a separator follows the last name of the complete path.
    trailing = _ends_with_separator(path)
    links = 0
    steps = 0
    while pending:
        steps += 1
        if steps > 256:
            raise ValueError("peer path is too deep")
        part = pending.pop(0)
        if part == "..":
            current = os.path.dirname(current)
            continue
        current = os.path.join(current, part)
        # A location is the one this name selects within the complete path,
        # not the one a shorter path ending at the same name would select.
        location = _exact_location(current, last=not pending and not trailing)
        if private(location):
            return True
        try:
            alias = _is_link_or_junction(os.lstat(location))
        except FileNotFoundError:
            alias = False
        if alias:
            links += 1
            if links > 40:
                raise ValueError("peer path has too many links")
            next_target = _on_link_drive(os.readlink(location), location)
            if not pending:
                trailing = _ends_with_separator(next_target)
            target_parts = Path(next_target).parts
            if os.path.isabs(next_target):
                current = _path_anchor(next_target)
                if private(current):
                    return True
                pending = list(target_parts[1:]) + pending
            else:
                current = os.path.dirname(current)
                pending = list(target_parts) + pending
    destination = os.path.realpath(link)
    return _names_private_state(destination) or any(
        _path_within(root, destination) for root in roots
    )


def _private_roots(data_dir: str) -> set[str]:
    from defenseclaw.config import default_data_path

    roots = {os.path.realpath(str(default_data_path()))}
    if data_dir:
        roots.add(os.path.realpath(data_dir))
    return roots


def link_reaches_private_state(link: str, data_dir: str = "") -> bool:
    """A link or junction names or resolves into protected state, hop by hop.

    A path that cannot be walked (too deep, too many links, unreadable) is
    treated as reaching it: an unjudged link is not a trusted one.
    """

    try:
        return _peer_path_uses_private_state(link, data_dir)
    except (OSError, ValueError, TypeError, AttributeError):
        return True


def path_reaches_private_state(path: str, data_dir: str = "") -> bool:
    """A path, as written or as it resolves, names or lies in protected state."""

    resolved = os.path.realpath(path)
    return (
        _names_private_state(path)
        or _names_private_state(resolved)
        or any(_path_within(root, resolved) for root in _private_roots(data_dir))
    )


def _names_private_state(path: str) -> bool:
    """Check every name that selects a location, UNC server and share included."""

    return any(
        name.casefold() in _PRIVATE_INSTALL_COMPONENTS for name in _location_names(path)
    )


def _path_within(root: str, path: str) -> bool:
    """Containment for resolved absolute paths; another drive or share is outside.

    Whole names are compared as the filesystem sees them, so a share root names
    the same location with or without its trailing separator, and a device or
    extended-length spelling names the same location as the ordinary one.
    """

    windows = isinstance(Path(root), PureWindowsPath)

    def key(value: str) -> tuple[str, ...]:
        names = _location_names(value)
        return tuple(name.casefold() for name in names) if windows else names

    root_names, path_names = key(root), key(path)
    return bool(root_names) and path_names[:len(root_names)] == root_names


# Windows passes a path that starts exactly with one of these to the filesystem
# without normalizing its names.
_WINDOWS_VERBATIM_PREFIXES = ("\\\\?\\", "\\??\\")
_WINDOWS_DEVICE_PREFIX = re.compile(r"^(?:[\\/]{2}[.?][\\/]|\\\?\?\\)(?:UNC[\\/])?", re.I)


def _path_anchor(path: str) -> str:
    """The first part of a path, in the namespace the path spells.

    The parsed anchor of a device path written with forward slashes is spelled
    with backslashes, which would read as extended-length; Windows normalizes
    such a path, so its anchor stays a device path.
    """

    anchor = Path(path).parts[0]
    if anchor.startswith(_WINDOWS_VERBATIM_PREFIXES) and not path.startswith(
        _WINDOWS_VERBATIM_PREFIXES,
    ):
        return "\\\\.\\" + anchor[4:]
    return anchor


def _location_names(path: str) -> tuple[str, ...]:
    """The names that select a location: anchor names first, then each name.

    A UNC server and share are names too. A device or extended-length prefix
    only selects the namespace, so it is not a name. Windows normalizes an
    ordinary path as a whole: a name before a separator drops one trailing dot
    (a name that ends in two or more dots is kept as written), and the last
    name, unless a separator follows it, drops all its trailing dots and
    spaces. The names of an extended-length path are used as written.
    """

    text = str(path)
    pure = Path(text)
    if not isinstance(pure, PureWindowsPath):
        return pure.parts
    verbatim = text.startswith(_WINDOWS_VERBATIM_PREFIXES)
    prefix = _WINDOWS_DEVICE_PREFIX.match(text)
    if prefix:
        unc = prefix.group(0)[4:].casefold().startswith("unc")
        pure = PureWindowsPath(("\\\\" if unc else "") + text[prefix.end():])
    names = [name for name in re.split(r"[\\/]+", pure.drive) if name]
    names += [pure.root] if pure.root else []
    names += pure.parts[1:] if pure.anchor else pure.parts
    if not verbatim:
        last = len(names) - 1 if not _ends_with_separator(text) else -1
        names = [
            _normalized_name(name, final=index == last) for index, name in enumerate(names)
        ]
    return tuple(names)


def _normalized_name(name: str, *, final: bool) -> str:
    """One name of an ordinary Windows path after the filesystem trimming.

    The last name of a path drops every trailing dot and space. A name before
    a separator drops a single trailing dot only; a longer run of dots is a
    distinct name and trailing spaces stay.
    """

    if final:
        return name.rstrip(". ") or name
    if name.endswith(".") and not name.endswith(".."):
        return name[:-1] or name
    return name


def _on_link_drive(target: str, link: str) -> str:
    """Give a link target that starts with one separator the drive of its link.

    Windows resolves such a target on the volume that holds the link, so every
    name of it is judged on that drive, as a drive-qualified path would be.
    """

    if not isinstance(Path(target), PureWindowsPath):
        return target
    pure = PureWindowsPath(target)
    if pure.drive or not pure.root:
        return target
    prefix = _WINDOWS_DEVICE_PREFIX.match(link)
    unc = bool(prefix) and prefix.group(0)[4:].casefold().startswith("unc")
    rest = link[prefix.end():] if prefix else link
    return PureWindowsPath(("\\\\" if unc else "") + rest).drive + target


def _ends_with_separator(path: str) -> bool:
    return isinstance(Path(path), PureWindowsPath) and path[-1:] in ("\\", "/")


def _exact_location(path: str, *, last: bool) -> str:
    """Spell a location so that Windows selects exactly the entry it names.

    Windows normalizes an ordinary path as a whole, so a name selects another
    entry at the end of the path than before a separator. The extended-length
    spelling of the names the complete path selects is used as written, so
    every check reads the entry the complete path reaches. Other paths are
    returned unchanged.
    """

    text = str(path)
    if not isinstance(Path(text), PureWindowsPath) or text.startswith(
        _WINDOWS_VERBATIM_PREFIXES,
    ):
        return text
    prefix = _WINDOWS_DEVICE_PREFIX.match(text)
    unc = bool(prefix) and prefix.group(0)[4:].casefold().startswith("unc")
    pure = PureWindowsPath(("\\\\" if unc else "") + text[prefix.end():] if prefix else text)
    unc = unc or pure.drive.startswith(("\\\\", "//"))
    if not pure.drive or not pure.root:
        return text
    names = _location_names(text if last else text + "\\")
    drive = [name for name in re.split(r"[\\/]+", pure.drive) if name]
    tail = names[len(drive) + 1:]
    head = "\\\\?\\UNC\\" if unc else "\\\\?\\"
    return head + "\\".join(names[:len(drive)]) + "\\" + "\\".join(tail)
