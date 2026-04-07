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

from defenseclaw.constants import LEGACY_PROVIDER_KEYS, LEGACY_PROVIDER_PREFIXES


def _ver_tuple(v: str) -> tuple[int, ...]:
    """Parse a semver string like '0.3.0' into a comparable tuple."""
    return tuple(int(x) for x in v.split("."))


# ---------------------------------------------------------------------------
# Migration: 0.2.0
# ---------------------------------------------------------------------------

def _migrate_0_2_0(openclaw_home: str) -> None:
    """Remove legacy defenseclaw model/provider entries from openclaw.json.

    Prior to 0.3.0 the guardrail setup added models.providers.defenseclaw
    and/or models.providers.litellm to openclaw.json to redirect traffic,
    and set agents.defaults.model.primary to "defenseclaw/<model>".

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

    changed = False
    changes = []

    # Remove legacy provider entries
    providers = cfg.get("models", {}).get("providers", {})
    for key in LEGACY_PROVIDER_KEYS:
        if key in providers:
            del providers[key]
            changes.append(f"removed providers.{key}")
            changed = True

    # Restore model.primary if it was redirected through defenseclaw/litellm
    model = cfg.get("agents", {}).get("defaults", {}).get("model", {})
    primary = model.get("primary", "")
    if primary.startswith(LEGACY_PROVIDER_PREFIXES):
        # Strip the defenseclaw/ or litellm/ prefix to restore the real model
        restored = primary.split("/", 1)[1]
        model["primary"] = restored
        changes.append(f"restored model.primary: {primary} → {restored}")
        changed = True

    if not changed:
        click.echo("    (no legacy entries found — nothing to change)")
        return

    with open(oc_json, "w") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
        f.write("\n")

    for c in changes:
        click.echo(f"    {c}")


# ---------------------------------------------------------------------------
# Migration registry
# ---------------------------------------------------------------------------

# Ordered list of (version, description, callable).
# Each callable takes openclaw_home as its single argument.
MIGRATIONS: list[tuple[str, str, Callable[[str], None]]] = [
    ("0.2.0", "Remove legacy model provider entries from openclaw.json", _migrate_0_2_0),
]


def run_migrations(
    from_version: str,
    to_version: str,
    openclaw_home: str,
) -> int:
    """Run all applicable migrations up to to_version.

    When from_version == to_version (re-apply / same-version upgrade),
    migrations at that exact version are still executed so that cleanup
    migrations ship with the version they fix.

    Returns the number of migrations applied.
    """
    from_t = _ver_tuple(from_version)
    to_t = _ver_tuple(to_version)
    applied = 0

    for ver, desc, fn in MIGRATIONS:
        ver_t = _ver_tuple(ver)
        if ver_t <= to_t and (from_t < ver_t or from_t == to_t):
            click.echo(f"  → Migration {ver}: {desc}")
            fn(openclaw_home)
            applied += 1

    return applied
