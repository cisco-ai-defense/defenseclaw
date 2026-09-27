# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""The connector ID DefenseClaw used before Windsurf became Devin Desktop.

Windsurf was renamed Devin Desktop (Cognition). This is the only place the
Python CLI names the former connector ID and the pre-rename vendor paths
Devin Desktop still reads; see docs.devin.ai/desktop/cascade/{hooks,memories,skills},
checked 2026-09-26. It mirrors ``internal/legacyconnector`` in the Go
gateway: the two read ``config.yaml`` independently, so both apply the same
migration rule.

* Migration: config that still names the retired ID moves to ``devin``, whose
  Devin CLI hook contract Devin Desktop's default agent (Devin Local) shares.
  An explicit ``devin`` block wins; otherwise the retired block is renamed
  and its settings are kept.
* Cleanup: the Go gateway removes what an older release wrote on the host.
  This module only tells the uninstaller where that state lives.
"""

from __future__ import annotations

import copy
import os
from typing import Any

RETIRED_DESKTOP_ID = "windsurf"
REPLACEMENT = "devin"
RETIRED: dict[str, str] = {RETIRED_DESKTOP_ID: REPLACEMENT}
HEADLINE = "Windsurf is now Devin Desktop"

# Uninstall still asks the gateway to tear the retired ID down when an older
# release left its setup backup behind; Go resolves it as a retired connector.
BACKUP_MARKERS: dict[str, tuple[str, ...]] = {
    RETIRED_DESKTOP_ID: (os.path.join("connector_backups", RETIRED_DESKTOP_ID, "config.json"),),
}

# Pre-rename per-user vendor directories the vendor still reads.
INVENTORY_DOT_DIRS: tuple[str, ...] = (".windsurf", ".codeium")


def _fold(name: Any) -> str:
    return "".join(str(name or "").split()).lower()


def is_retired(name: Any) -> bool:
    """Report whether *name* is the retired Desktop ID (case/space-insensitive)."""
    return _fold(name) in RETIRED


def canonical(name: Any) -> tuple[str, bool]:
    """Return ``(replacement, True)`` for the retired ID, else ``(name, False)``."""
    folded = _fold(name)
    if folded in RETIRED:
        return RETIRED[folded], True
    return name, False


def migrate_connector_keys(primary: Any, keys: list[str]) -> tuple[Any, dict[str, str], list[str]]:
    """Apply the rename to a primary name and per-connector map keys.

    Mirrors ``legacyconnector.MigrateConnectorKeys``: an explicit replacement
    key wins and every retired key is dropped; otherwise the first retired key
    (sorted) is renamed and any further retired keys are dropped.
    """
    new_primary, _ = canonical(primary)
    retired = sorted(str(k) for k in keys if is_retired(k))
    explicit = any(str(k).strip().lower() == REPLACEMENT for k in keys if not is_retired(k))
    if not retired:
        return new_primary, {}, []
    if explicit:
        return new_primary, {}, retired
    return new_primary, {retired[0]: REPLACEMENT}, retired[1:]


def notice(config_path: str = "", dropped: list[str] | None = None) -> str:
    """Operator-facing summary of one config migration."""
    where = (config_path or "").strip() or "config"
    msg = f"{HEADLINE}: moved connector {RETIRED_DESKTOP_ID!r} to {REPLACEMENT!r} in {where}"
    if dropped:
        listed = ", ".join(repr(d) for d in dropped)
        msg += f" (kept the existing {REPLACEMENT!r} settings and dropped {listed})"
    return msg


def migrate_raw_config(raw: Any, config_path: str = "") -> list[str]:
    """Rename the retired ID in a raw ``config.yaml`` mapping, in place.

    Touches ``guardrail.connector``, ``guardrail.connectors`` and
    ``claw.mode``. Must run before connector keys are normalized or checked
    for duplicates. Returns the notices (empty when nothing changed).
    """
    if not isinstance(raw, dict):
        return []
    changed = False
    dropped: list[str] = []
    guardrail = raw.get("guardrail")
    if isinstance(guardrail, dict):
        connectors = guardrail.get("connectors")
        keys = [str(k) for k in connectors] if isinstance(connectors, dict) else []
        primary = guardrail.get("connector", "")
        new_primary, rename, dropped = migrate_connector_keys(primary, keys)
        if "connector" in guardrail and new_primary != primary:
            guardrail["connector"] = new_primary
            changed = True
        if isinstance(connectors, dict) and (rename or dropped):
            rebuilt: dict[Any, Any] = {}
            for key, value in connectors.items():
                if key in dropped:
                    continue
                rebuilt[rename.get(key, key)] = value
            guardrail["connectors"] = rebuilt
            changed = True
    claw = raw.get("claw")
    if isinstance(claw, dict) and "mode" in claw:
        mode, migrated = canonical(claw.get("mode"))
        if migrated:
            claw["mode"] = mode
            changed = True
    return [notice(config_path, dropped)] if changed else []


def migrated_copy(raw: Any, config_path: str = "") -> tuple[Any, list[str]]:
    """Return a migrated deep copy of *raw* and its notices; *raw* is unchanged."""
    out = copy.deepcopy(raw)
    return out, migrate_raw_config(out, config_path)


def cascade_user_hooks_path(home: str) -> str:
    """Legacy per-user Cascade hooks file (cleanup only)."""
    return os.path.join(home, ".codeium", "windsurf", "hooks.json")


def desktop_legacy_rule_paths(home: str, workspace: str | None) -> list[str]:
    """Pre-rename rule locations Devin Desktop still loads (read-only)."""
    out: list[str] = []
    if (home or "").strip():
        out.append(os.path.join(home, ".codeium", "windsurf", "memories", "global_rules.md"))
    ws = (workspace or "").strip()
    if ws:
        out.extend([os.path.join(ws, ".windsurf", "rules"), os.path.join(ws, ".windsurfrules")])
    return out


def desktop_legacy_skill_paths(home: str, workspace: str | None) -> list[str]:
    """Pre-rename skill locations Devin Desktop still loads (read-only)."""
    out: list[str] = []
    if (home or "").strip():
        out.append(os.path.join(home, ".codeium", "windsurf", "skills"))
    ws = (workspace or "").strip()
    if ws:
        out.append(os.path.join(ws, ".windsurf", "skills"))
    return out


def owned_hook_scripts(data_dir: str) -> list[str]:
    """Hook scripts an older release installed for the retired ID."""
    if not (data_dir or "").strip():
        return []
    hooks = os.path.join(data_dir, "hooks")
    return [
        os.path.join(hooks, f"{RETIRED_DESKTOP_ID}-hook.sh"),
        os.path.join(hooks, f"{RETIRED_DESKTOP_ID}-hook.ps1"),
    ]


def backup_dir(data_dir: str) -> str:
    """Setup backup directory an older release kept for the retired ID."""
    if not (data_dir or "").strip():
        return ""
    return os.path.join(data_dir, "connector_backups", RETIRED_DESKTOP_ID)
