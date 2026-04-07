# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""Version-specific migrations for DefenseClaw upgrades.

Each migration is keyed to the target version it ships with. During upgrade,
all migrations between the old version and the new version are applied in
order.
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable

import click


def _ver_tuple(v: str) -> tuple[int, ...]:
    """Parse a semver string like '0.3.0' into a comparable tuple."""
    return tuple(int(x) for x in v.split("."))


# ---------------------------------------------------------------------------
# Migration: 0.3.0
# ---------------------------------------------------------------------------

def _migrate_0_3_0(openclaw_home: str) -> None:
    """Remove legacy model provider entries from openclaw.json.

    Prior to 0.3.0 the guardrail setup added models.providers.defenseclaw
    and/or models.providers.litellm to openclaw.json to redirect traffic.
    The fetch interceptor now handles routing transparently, so these
    entries are unnecessary and should be cleaned up.

    Plugin registration is preserved.
    """
    oc_json = os.path.join(openclaw_home, "openclaw.json")
    if not os.path.isfile(oc_json):
        return

    try:
        with open(oc_json) as f:
            cfg = json.load(f)
    except (OSError, json.JSONDecodeError):
        return

    providers = cfg.get("models", {}).get("providers", {})
    removed = []
    for key in ("defenseclaw", "litellm"):
        if key in providers:
            del providers[key]
            removed.append(key)

    if not removed:
        click.echo("    (no legacy provider entries found — nothing to remove)")
        return

    with open(oc_json, "w") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
        f.write("\n")

    click.echo(f"    Removed legacy provider entries: {', '.join(removed)}")


# ---------------------------------------------------------------------------
# Migration registry
# ---------------------------------------------------------------------------

# Ordered list of (version, description, callable).
# Each callable takes openclaw_home as its single argument.
MIGRATIONS: list[tuple[str, str, Callable[[str], None]]] = [
    ("0.3.0", "Remove legacy model provider entries from openclaw.json", _migrate_0_3_0),
]


def run_migrations(
    from_version: str,
    to_version: str,
    openclaw_home: str,
) -> int:
    """Run all migrations between from_version (exclusive) and to_version (inclusive).

    Returns the number of migrations applied.
    """
    from_t = _ver_tuple(from_version)
    to_t = _ver_tuple(to_version)
    applied = 0

    for ver, desc, fn in MIGRATIONS:
        ver_t = _ver_tuple(ver)
        if from_t < ver_t <= to_t:
            click.echo(f"  → Migration {ver}: {desc}")
            fn(openclaw_home)
            applied += 1

    return applied
