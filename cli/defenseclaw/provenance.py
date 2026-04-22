# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""v7 provenance quartet for CLI-originated exports (mirrors internal/version)."""

from __future__ import annotations

import hashlib
import os
from typing import Any

from defenseclaw import __version__
from defenseclaw.config import Config


def content_hash_for_provenance(cfg: Config) -> str:
    """SHA-256 hex of canonical config snapshot + active policy file hashes."""
    from defenseclaw import config as cfg_mod

    path = cfg_mod.config_path()
    blocks: list[bytes] = []
    try:
        with open(path, encoding="utf-8") as f:
            blocks.append(f.read().encode())
    except OSError:
        blocks.append(b"")

    policy_dir = getattr(cfg, "policy_dir", "") or ""
    if policy_dir and os.path.isdir(policy_dir):
        names = sorted(
            n for n in os.listdir(policy_dir) if n.endswith((".yaml", ".yml", ".rego", ".json"))
        )
        for name in names:
            fp = os.path.join(policy_dir, name)
            try:
                with open(fp, encoding="utf-8") as f:
                    blocks.append(name.encode() + b"\n" + f.read().encode())
            except OSError:
                continue

    raw = b"\n".join(blocks)
    return hashlib.sha256(raw).hexdigest()


def provenance_quartet(cfg: Config) -> dict[str, Any]:
    return {
        "schema_version": 7,
        "content_hash": content_hash_for_provenance(cfg),
        "generation": 0,
        "binary_version": __version__,
    }


def stamp_aibom_inventory(inv: dict[str, Any], cfg: Config) -> None:
    """Attach provenance to the top-level envelope and every list component."""
    prov = provenance_quartet(cfg)
    inv["provenance"] = prov
    for key in (
        "skills",
        "plugins",
        "mcp",
        "agents",
        "tools",
        "model_providers",
        "memory",
    ):
        val = inv.get(key)
        if not isinstance(val, list):
            continue
        for item in val:
            if isinstance(item, dict):
                item["provenance"] = prov
