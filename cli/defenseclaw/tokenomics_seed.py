# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""The reviewed default price table that setup writes into config.yaml.

The gateway never reads this file and no price is compiled into a binary: it
prices only from ``observability.pricing`` in config.yaml. This module is the
single writer-side source for the seed, used by ``defenseclaw setup tokenomics``
and the upgrade step. A managed host takes its table from the admin config in
the signed bundle and is never seeded here.
"""

from __future__ import annotations

import json
from importlib.resources import files
from pathlib import Path
from typing import Any

from defenseclaw.config_writer import Change

_RESOURCE = "_data/pricing/default-pricing.json"
_SOURCE_TREE = Path(__file__).resolve().parents[2] / "bundles" / "pricing" / "default-pricing.json"


def load_default_pricing() -> dict[str, Any]:
    """Return the seed as the ``observability.pricing`` mapping (no comment keys)."""
    try:
        raw = files("defenseclaw").joinpath(_RESOURCE).read_text(encoding="utf-8")
    except (FileNotFoundError, ModuleNotFoundError):
        raw = _SOURCE_TREE.read_text(encoding="utf-8")
    seed = json.loads(raw)
    return {key: value for key, value in seed.items() if not key.startswith("_")}


def pricing_changes(current: Any) -> list[Change]:
    """The change that seeds ``observability.pricing`` when the file has none.

    An operator table, even an empty list with a version, is never replaced.
    """
    observability = current.get("observability") if isinstance(current, dict) else None
    existing = observability.get("pricing") if isinstance(observability, dict) else None
    if isinstance(existing, dict) and (existing.get("models") or existing.get("version")):
        return []
    return [Change("observability.pricing", load_default_pricing())]
