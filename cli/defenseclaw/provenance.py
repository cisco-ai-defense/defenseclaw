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


def _resolve_active_rego_dir(policy_dir: str) -> str:
    """Mirror the Go loader's resolveRegoDir: prefer policy_dir/rego when it
    contains .rego files, otherwise fall back to policy_dir itself.

    ("Provenance hash omits active nested policy bundle"):
    the active Go engine prefers `cfg.policy_dir/rego/*.rego` (and
    `data.json`) when that directory exists, and the bootstrap path
    seeds bundled Rego there. The Python AIBOM provenance therefore
    has to descend into the same subtree -- otherwise edits to
    policies/rego/admission.rego or policies/rego/data.json never
    change content_hash and exported provenance becomes
    non-reproducible.
    """
    nested = os.path.join(policy_dir, "rego")
    if not os.path.isdir(nested):
        return policy_dir
    try:
        for entry in os.listdir(nested):
            if entry.endswith(".rego"):
                return nested
    except OSError:
        return policy_dir
    return policy_dir


def _walk_active_policy_files(policy_dir: str) -> list[tuple[str, str]]:
    """Return (relative_name, absolute_path) pairs for every active
    policy/data file we hash for provenance. Iterating in sorted order
    keeps the resulting hash deterministic regardless of FS readdir order.
    """
    if not policy_dir or not os.path.isdir(policy_dir):
        return []

    out: list[tuple[str, str]] = []
    rego_dir = _resolve_active_rego_dir(policy_dir)
    try:
        top_names = sorted(os.listdir(policy_dir))
    except OSError:
        top_names = []
    for name in top_names:
        if name.endswith((".yaml", ".yml", ".rego", ".json")):
            out.append((name, os.path.join(policy_dir, name)))
    if rego_dir != policy_dir:
        try:
            nested_names = sorted(os.listdir(rego_dir))
        except OSError:
            nested_names = []
        for name in nested_names:
            if name.endswith((".rego", ".json")):
                rel = "rego/" + name
                out.append((rel, os.path.join(rego_dir, name)))
    return out


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
    for rel, fp in _walk_active_policy_files(policy_dir):
        try:
            with open(fp, "rb") as f:
                contents = f.read()
        except OSError:
            continue
        blocks.append(rel.encode() + b"\n" + contents)

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
