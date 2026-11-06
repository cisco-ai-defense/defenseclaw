# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Exact published OpenClaw provider identities for plugin admission."""

from __future__ import annotations

import json
import os
import re
import stat

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


def inspect_official_provider_tree(plugin_dir: str) -> str | None:
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
            links[peer] = (link, _validated_peer_link(link, root, peer))
        except (OSError, ValueError, TypeError, AttributeError):
            return None

    if _tree_sha256(plugin_dir, tolerated_links=frozenset(tolerated)) != want:
        return None
    for peer, (link, before) in links.items():
        try:
            if before != _validated_peer_link(link, root, peer):
                return None
        except (OSError, ValueError, TypeError, AttributeError):
            return None
    return name


def _validated_peer_link(link: str, root: str, peer: str) -> tuple:
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
    if not stat.S_ISDIR(os.stat(destination, follow_symlinks=False).st_mode):
        raise ValueError("peer link target is not a directory")
    manifest = _read_regular_file(
        os.path.join(destination, "package.json"), max_bytes=1024 * 1024,
    )
    if manifest is None or json.loads(manifest).get("name") != peer:
        raise ValueError("peer link target has another package identity")
    return tuple(ancestors), (_filesystem_identity(info), os.readlink(link), manifest)
