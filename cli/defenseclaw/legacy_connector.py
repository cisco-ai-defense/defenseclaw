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

# Top-level blocks whose ``connectors`` map is keyed by connector ID. The Go
# loader (internal/config.migrateLegacyConnectorIDs) renames the same maps.
CONNECTOR_MAP_BLOCKS: tuple[str, ...] = (
    "guardrail",
    "asset_policy",
    "application_protection",
    "observability",
)

# Top-level maps that are themselves keyed by connector ID.
TOP_LEVEL_CONNECTOR_MAPS: tuple[str, ...] = ("connector_hooks",)

# Connector name lists, as key paths from the document root.
CONNECTOR_NAME_LISTS: tuple[tuple[str, ...], ...] = (
    ("guardrail", "judge", "hook_connectors"),
    ("application_protection", "include_connectors"),
    ("application_protection", "exclude_connectors"),
)

# asset_policy rule lists whose entries may name one connector
# (``asset_policy.<type>.<list>[].connector``). A denied rule or a registry
# entry written for the retired ID must keep applying to its replacement.
ASSET_POLICY_RULE_LISTS: tuple[tuple[str, str], ...] = tuple(
    (asset_type, rule_list)
    for asset_type in ("mcp", "skill", "plugin")
    for rule_list in ("registry", "allowed", "denied")
)


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


def notice(config_path: str = "", dropped: list[str] | None = None, updated: list[str] | None = None) -> str:
    """Operator-facing summary of one config migration.

    *updated* names the settings that moved (``guardrail.connector``,
    ``connector_hooks`` ...); *dropped* the retired keys removed because an
    explicit replacement entry won. Mirrors the Go loader's notice.
    """
    where = (config_path or "").strip() or "config"
    if updated:
        where = f"{', '.join(updated)} of {where}"
    msg = f"{HEADLINE}: moved connector {RETIRED_DESKTOP_ID!r} to {REPLACEMENT!r} in {where}"
    if dropped:
        listed = ", ".join(repr(d) for d in dropped)
        msg += f" (kept the existing {REPLACEMENT!r} settings and dropped {listed})"
    return msg


def _migrate_key_map(connectors: Any) -> tuple[Any, bool, list[str]]:
    """Apply the rename to the keys of one connector-keyed mapping.

    Returns ``(mapping, changed, dropped)``; *mapping* is a rebuilt dict when
    anything changed (key order kept), else the input.
    """
    if not isinstance(connectors, dict):
        return connectors, False, []
    _, rename, dropped = migrate_connector_keys("", [str(k) for k in connectors])
    if not rename and not dropped:
        return connectors, False, []
    rebuilt: dict[Any, Any] = {}
    for key, value in connectors.items():
        if str(key) in dropped:
            continue
        rebuilt[rename.get(str(key), key)] = value
    return rebuilt, True, dropped


def _migrate_connector_map(block: dict[Any, Any]) -> tuple[bool, list[str]]:
    """Apply the rename to ``block["connectors"]`` keys, in place."""
    rebuilt, changed, dropped = _migrate_key_map(block.get("connectors"))
    if changed:
        block["connectors"] = rebuilt
    return changed, dropped


def migrate_connector_list(values: Any) -> tuple[Any, bool]:
    """Apply the rename to one connector name list.

    Mirrors the Go ``migrateLegacyConnectorList``: the first retired entry
    becomes the replacement unless the replacement is already listed, and
    further retired entries are removed, so the list names each connector
    once. Returns ``(values, changed)``; *values* is a new list when changed.
    """
    if not isinstance(values, list) or not values:
        return values, False
    listed = any(isinstance(v, str) and v.strip().lower() == REPLACEMENT for v in values)
    changed = False
    out: list[Any] = []
    for value in values:
        if not (isinstance(value, str) and is_retired(value)):
            out.append(value)
            continue
        changed = True
        if not listed:
            out.append(REPLACEMENT)
            listed = True
    return (out, True) if changed else (values, False)


def migrate_raw_config(raw: Any, config_path: str = "") -> list[str]:
    """Rename the retired ID in a raw ``config.yaml`` mapping, in place.

    Touches ``guardrail.connector``, ``claw.mode``, the keys of every
    per-connector map in :data:`CONNECTOR_MAP_BLOCKS` and
    :data:`TOP_LEVEL_CONNECTOR_MAPS`, the name lists in
    :data:`CONNECTOR_NAME_LISTS`, the ``connector`` of the rules in
    :data:`ASSET_POLICY_RULE_LISTS` and the ``connectors`` of every
    observability route selector. Must run before connector keys are
    normalized or checked for duplicates. Returns the notices (empty when
    nothing changed); the notice names every setting that moved and every
    retired key that was dropped.
    """
    if not isinstance(raw, dict):
        return []
    updated: list[str] = []
    dropped: list[str] = []
    guardrail = raw.get("guardrail")
    if isinstance(guardrail, dict) and "connector" in guardrail:
        primary = guardrail.get("connector", "")
        new_primary, _ = canonical(primary)
        if new_primary != primary:
            guardrail["connector"] = new_primary
            updated.append("guardrail.connector")
    claw = raw.get("claw")
    if isinstance(claw, dict) and "mode" in claw:
        mode, migrated = canonical(claw.get("mode"))
        if migrated:
            claw["mode"] = mode
            updated.append("claw.mode")
    for block_key in CONNECTOR_MAP_BLOCKS:
        block = raw.get(block_key)
        if not isinstance(block, dict):
            continue
        moved, dropped_keys = _migrate_connector_map(block)
        if moved:
            updated.append(f"{block_key}.connectors")
        if block_key == "guardrail":
            dropped.extend(dropped_keys)
        else:
            dropped.extend(f"{block_key}.connectors.{key}" for key in dropped_keys)
    for map_key in TOP_LEVEL_CONNECTOR_MAPS:
        rebuilt, moved, dropped_keys = _migrate_key_map(raw.get(map_key))
        if moved:
            raw[map_key] = rebuilt
            updated.append(map_key)
            dropped.extend(f"{map_key}.{key}" for key in dropped_keys)
    for path in CONNECTOR_NAME_LISTS:
        parent: Any = raw
        for key in path[:-1]:
            parent = parent.get(key) if isinstance(parent, dict) else None
        if not isinstance(parent, dict):
            continue
        values, moved = migrate_connector_list(parent.get(path[-1]))
        if moved:
            parent[path[-1]] = values
            updated.append(".".join(path))
    asset_policy = raw.get("asset_policy")
    for asset_type, rule_list in ASSET_POLICY_RULE_LISTS if isinstance(asset_policy, dict) else ():
        policy = asset_policy.get(asset_type)
        rules = policy.get(rule_list) if isinstance(policy, dict) else None
        moved = False
        for rule in rules if isinstance(rules, list) else ():
            if isinstance(rule, dict) and isinstance(rule.get("connector"), str) and is_retired(rule["connector"]):
                rule["connector"] = REPLACEMENT
                moved = True
        if moved:
            updated.append(f"asset_policy.{asset_type}.{rule_list}")
    updated.extend(_migrate_route_selectors(raw.get("observability")))
    return [notice(config_path, dropped, _in_go_order(updated))] if updated else []


def _migrate_route_selectors(observability: Any) -> list[str]:
    """Apply the list rule to ``selector.connectors`` of every observability
    route, in place, and return the moved paths
    (``observability.destinations[D].routes[R].selector.connectors``)."""
    destinations = observability.get("destinations") if isinstance(observability, dict) else None
    moved_paths: list[str] = []
    for d_index, destination in enumerate(destinations if isinstance(destinations, list) else ()):
        routes = destination.get("routes") if isinstance(destination, dict) else None
        for r_index, route in enumerate(routes if isinstance(routes, list) else ()):
            selector = route.get("selector") if isinstance(route, dict) else None
            if not isinstance(selector, dict):
                continue
            values, moved = migrate_connector_list(selector.get("connectors"))
            if moved:
                selector["connectors"] = values
                moved_paths.append(f"observability.destinations[{d_index}].routes[{r_index}].selector.connectors")
    return moved_paths


# The order the Go loader lists moved settings in its notice; route
# selectors follow, in document order.
_NOTICE_ORDER: tuple[str, ...] = (
    "guardrail.connector",
    "guardrail.connectors",
    "claw.mode",
    *(f"{block}.connectors" for block in CONNECTOR_MAP_BLOCKS if block != "guardrail"),
    *TOP_LEVEL_CONNECTOR_MAPS,
    *(".".join(path) for path in CONNECTOR_NAME_LISTS),
    *(f"asset_policy.{asset_type}.{rule_list}" for asset_type, rule_list in ASSET_POLICY_RULE_LISTS),
)


def _in_go_order(updated: list[str]) -> list[str]:
    # sorted() is stable, so the route selectors keep their document order.
    return sorted(updated, key=lambda path: _NOTICE_ORDER.index(path) if path in _NOTICE_ORDER else len(_NOTICE_ORDER))


def migrated_copy(raw: Any, config_path: str = "") -> tuple[Any, list[str]]:
    """Return a migrated deep copy of *raw* and its notices; *raw* is unchanged."""
    out = copy.deepcopy(raw)
    return out, migrate_raw_config(out, config_path)


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


def backup_dir(data_dir: str) -> str:
    """Setup backup directory an older release kept for the retired ID."""
    if not (data_dir or "").strip():
        return ""
    return os.path.join(data_dir, "connector_backups", RETIRED_DESKTOP_ID)
