# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Exact published OpenClaw provider identities for plugin admission."""

from __future__ import annotations

import json
import os

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


def is_official_provider_tree(plugin_dir: str) -> bool:
    """Trust only an unchanged published package with its declared identity."""

    manifest = _read_regular_file(
        os.path.join(plugin_dir, "package.json"), max_bytes=64 * 1024,
    )
    if manifest is None:
        return False
    try:
        package = json.loads(manifest)
    except (UnicodeDecodeError, ValueError):
        return False
    if not isinstance(package, dict):
        return False
    name, version = package.get("name"), package.get("version")
    if not isinstance(name, str) or not isinstance(version, str):
        return False
    want = VENDOR_DIGESTS.get((name, version))
    return bool(want) and _tree_sha256(plugin_dir) == want
