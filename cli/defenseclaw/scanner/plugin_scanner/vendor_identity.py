# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Exact published OpenClaw provider identities for plugin admission."""

from __future__ import annotations

import json
import os
import re
import stat

from defenseclaw.hermes_skills import _read_regular_file, _tree_sha256

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
    root = os.path.realpath(plugin_dir)
    tolerated: set[str] = set()
    links: list[tuple[str, str, os.stat_result]] = []
    for peer in peers:
        if not isinstance(peer, str) or not re.fullmatch(
            r"(?:@[a-z0-9._-]+/)?[a-z0-9._-]+", peer,
        ) or any(part in (".", "..") for part in peer.split("/")):
            return None
        relative = "node_modules/" + peer
        link = os.path.join(plugin_dir, *relative.split("/"))
        tolerated.add(relative)
        if not os.path.lexists(link):
            continue
        try:
            before = os.lstat(link)
            if not stat.S_ISLNK(before.st_mode):
                return None
            destination = os.path.realpath(link)
            if os.path.commonpath((root, destination)) == root:
                return None
            if not stat.S_ISDIR(os.stat(destination, follow_symlinks=False).st_mode):
                return None
            peer_manifest = _read_regular_file(
                os.path.join(destination, "package.json"), max_bytes=1024 * 1024,
            )
            if peer_manifest is None or json.loads(peer_manifest).get("name") != peer:
                return None
            links.append((link, os.readlink(link), before))
        except (OSError, ValueError, TypeError, AttributeError):
            return None

    if _tree_sha256(plugin_dir, tolerated_links=frozenset(tolerated)) != want:
        return None
    for link, destination, before in links:
        try:
            after = os.lstat(link)
            if not os.path.samestat(before, after) or os.readlink(link) != destination:
                return None
        except OSError:
            return None
    return name
