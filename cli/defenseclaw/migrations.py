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
    """Remove legacy defenseclaw model/provider entries from openclaw.json.

    0.2.0's guardrail setup added models.providers.defenseclaw and/or
    models.providers.litellm to openclaw.json to redirect traffic, and set
    agents.defaults.model.primary to "defenseclaw/<model>".

    The fetch interceptor introduced in 0.3.0 handles routing transparently,
    so these entries are no longer needed and must be cleaned up on upgrade.

    Strategy: restore the pristine backup of openclaw.json that was captured
    before DefenseClaw first touched the file, then re-apply only the plugin
    registration that 0.3.0 needs. This is cleaner than surgically patching
    individual keys and avoids leaving behind stale or unexpected entries.

    Falls back to surgical removal if no pristine backup exists (e.g.
    guardrail was never enabled, or the backup was deleted).
    """
    oc_json = os.path.join(openclaw_home, "openclaw.json")
    if not os.path.isfile(oc_json):
        return

    from defenseclaw.guardrail import pristine_backup_path

    data_dir = os.path.expanduser("~/.defenseclaw")
    pristine = pristine_backup_path(oc_json, data_dir)

    if pristine:
        _migrate_0_3_0_from_pristine(oc_json, pristine)
    else:
        _migrate_0_3_0_surgical(oc_json)


def _migrate_0_3_0_from_pristine(oc_json: str, pristine: str) -> None:
    """Restore pristine openclaw.json and re-apply plugin registration."""
    import shutil

    try:
        with open(pristine) as f:
            cfg = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        click.echo(f"    pristine backup unreadable ({exc}), falling back to surgical fix")
        _migrate_0_3_0_surgical(oc_json)
        return

    # Re-apply the minimal plugin registration that 0.3.0 needs.
    plugins = cfg.setdefault("plugins", {})
    allow = plugins.setdefault("allow", [])
    if "defenseclaw" not in allow:
        allow.append("defenseclaw")
    entries = plugins.setdefault("entries", {})
    if "defenseclaw" not in entries:
        entries["defenseclaw"] = {"enabled": True}
    else:
        entries["defenseclaw"]["enabled"] = True
    install_path = os.path.join(os.path.dirname(oc_json), "extensions", "defenseclaw")
    load = plugins.setdefault("load", {})
    paths = load.setdefault("paths", [])
    if install_path not in paths:
        paths.append(install_path)

    # Write the restored + patched config
    shutil.copy2(oc_json, oc_json + ".pre-0.3.0-migration")

    with open(oc_json, "w") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
        f.write("\n")

    click.echo(f"    restored openclaw.json from pristine backup ({os.path.basename(pristine)})")
    click.echo("    re-applied plugin registration for 0.3.0")


def _migrate_0_3_0_surgical(oc_json: str) -> None:
    """Fallback: surgically remove legacy entries when no pristine backup exists."""
    try:
        with open(oc_json) as f:
            cfg = json.load(f)
    except (OSError, json.JSONDecodeError):
        return

    changed = False
    changes = []

    providers = cfg.get("models", {}).get("providers", {})
    for key in ("defenseclaw", "litellm"):
        if key in providers:
            del providers[key]
            changes.append(f"removed providers.{key}")
            changed = True

    model = cfg.get("agents", {}).get("defaults", {}).get("model", {})
    primary = model.get("primary", "")
    if primary.startswith(("defenseclaw/", "litellm/")):
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
    click.echo("    (no pristine backup found — applied surgical fix)")


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
