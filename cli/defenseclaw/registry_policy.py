# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Shared mutation service for ``asset_policy.*.registry_required``.

The gateway resolves this scalar as ``connector override > global``.  A broad
operator write therefore has to reconcile active connector overrides rather
than changing only the global default.  This module is shared by the CLI and
the TUI config editor so both surfaces apply the same precedence semantics.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any

import yaml

from defenseclaw import connector_paths
from defenseclaw.config import (
    Config,
    PerConnectorAssetPolicy,
    PerConnectorAssetTypePolicy,
)

_ASSET_TYPES = frozenset({"skill", "mcp", "plugin"})


@dataclass(frozen=True)
class ConnectorRegistryRequiredChange:
    """One connector's effective state before and after reconciliation."""

    connector: str
    before: bool
    after: bool

    @property
    def status(self) -> str:
        return "already_compliant" if self.before == self.after else "changed"


@dataclass(frozen=True)
class RegistryRequiredResult:
    """Mutation result used for verification and operator-facing reporting."""

    asset_type: str
    requested: bool
    connector: str | None
    storage_key: str | None
    global_before: bool
    global_after: bool
    active_connectors: tuple[str, ...]
    connectors: tuple[ConnectorRegistryRequiredChange, ...]
    preserved_inactive_connectors: tuple[str, ...]

    @property
    def changed_connectors(self) -> tuple[str, ...]:
        return tuple(change.connector for change in self.connectors if change.status == "changed")

    @property
    def already_compliant_connectors(self) -> tuple[str, ...]:
        return tuple(change.connector for change in self.connectors if change.status == "already_compliant")


class RegistryRequiredUpdateError(RuntimeError):
    """A registry-required transaction failed and did not update live state."""

    def __init__(self, result: RegistryRequiredResult, cause: BaseException) -> None:
        self.result = result
        self.cause = cause
        super().__init__(str(cause))


def _asset_type(asset_type: str) -> str:
    value = str(asset_type or "").strip().lower()
    if value not in _ASSET_TYPES:
        raise ValueError(f"unsupported asset type {asset_type!r}")
    return value


def _active_connectors(cfg: Config) -> tuple[str, ...]:
    """Return the canonical roster from Config's multi-connector resolver."""
    names: set[str] = set()
    for raw in cfg.active_connectors():
        value = str(raw or "").strip()
        if value:
            names.add(connector_paths.normalize(value))
    return tuple(sorted(names))


def _connector_storage_key(connectors: dict[str, Any], connector: str) -> tuple[str, str]:
    canonical = connector_paths.normalize(connector)
    if connector in connectors:
        return connector, canonical
    for name in connectors:
        if connector_paths.normalize(name) == canonical:
            return name, canonical
    return canonical, canonical


def _ensure_connector_asset_block(
    cfg: Config,
    connector: str,
    asset_type: str,
) -> tuple[str, PerConnectorAssetTypePolicy]:
    connectors = cfg.asset_policy.connectors
    key, _canonical = _connector_storage_key(connectors, connector)
    policy = connectors.get(key)
    if policy is None:
        policy = PerConnectorAssetPolicy()
        connectors[key] = policy
    block = getattr(policy, asset_type)
    if block is None:
        block = PerConnectorAssetTypePolicy()
        setattr(policy, asset_type, block)
    return key, block


def reconcile_registry_required(
    cfg: Config,
    asset_type: str,
    enabled: bool,
    *,
    connector: str = "",
) -> RegistryRequiredResult:
    """Apply scoped or broad registry-required intent to an in-memory config.

    Scoped writes materialize only the selected connector override.  Broad
    writes update the global default and clear only the targeted override field
    for every active connector, making each inherit the requested value while
    preserving the surrounding connector/type object and every sibling field.

    Explicit overrides for known but inactive connectors are intentionally left
    untouched.  This avoids silently changing their saved posture if they are
    activated later; a future broad operation will reconcile them once they are
    part of :meth:`Config.active_connectors`.
    """
    asset = _asset_type(asset_type)
    requested = bool(enabled)
    selected = str(connector or "").strip()
    global_policy = getattr(cfg.asset_policy, asset)
    global_before = bool(global_policy.registry_required)
    active = _active_connectors(cfg)

    if selected:
        key, canonical = _connector_storage_key(cfg.asset_policy.connectors, selected)
        effective_before = cfg.asset_policy.effective_asset_type_policy(canonical, asset)
        before = bool(effective_before.registry_required) if effective_before is not None else global_before
        key, block = _ensure_connector_asset_block(cfg, selected, asset)
        block.registry_required = requested
        effective_after = cfg.asset_policy.effective_asset_type_policy(canonical, asset)
        after = bool(effective_after.registry_required) if effective_after is not None else requested
        if after != requested:
            raise RuntimeError(f"failed to reconcile registry_required for connector {canonical}")
        inactive = tuple(
            sorted({
                connector_paths.normalize(name)
                for name in cfg.asset_policy.connectors
                if connector_paths.normalize(name) not in active and connector_paths.normalize(name) != canonical
            })
        )
        return RegistryRequiredResult(
            asset_type=asset,
            requested=requested,
            connector=canonical,
            storage_key=key,
            global_before=global_before,
            global_after=global_before,
            active_connectors=active,
            connectors=(ConnectorRegistryRequiredChange(canonical, before, after),),
            preserved_inactive_connectors=inactive,
        )

    before_by_connector: dict[str, bool] = {}
    for name in active:
        effective = cfg.asset_policy.effective_asset_type_policy(name, asset)
        before_by_connector[name] = bool(effective.registry_required) if effective is not None else global_before

    global_policy.registry_required = requested
    for name in active:
        key, _canonical = _connector_storage_key(cfg.asset_policy.connectors, name)
        policy = cfg.asset_policy.connectors.get(key)
        block = getattr(policy, asset, None) if policy is not None else None
        if block is not None:
            # None means inherit.  Leave the block itself in place so sibling
            # scalar overrides and the surrounding connector policy survive.
            block.registry_required = None

    changes: list[ConnectorRegistryRequiredChange] = []
    for name in active:
        effective = cfg.asset_policy.effective_asset_type_policy(name, asset)
        after = bool(effective.registry_required) if effective is not None else requested
        if after != requested:
            raise RuntimeError(f"failed to reconcile registry_required for active connector {name}")
        changes.append(ConnectorRegistryRequiredChange(name, before_by_connector[name], after))

    inactive = tuple(
        sorted({
            connector_paths.normalize(name)
            for name in cfg.asset_policy.connectors
            if connector_paths.normalize(name) not in active
        })
    )
    return RegistryRequiredResult(
        asset_type=asset,
        requested=requested,
        connector=None,
        storage_key=None,
        global_before=global_before,
        global_after=requested,
        active_connectors=active,
        connectors=tuple(changes),
        preserved_inactive_connectors=inactive,
    )


def _document_connector_override(raw: dict[str, Any], connector: str) -> dict[str, Any] | None:
    asset_policy = raw.get("asset_policy")
    if not isinstance(asset_policy, dict):
        return None
    connectors = asset_policy.get("connectors")
    if not isinstance(connectors, dict):
        return None
    direct = connectors.get(connector)
    if isinstance(direct, dict):
        return direct
    canonical = connector_paths.normalize(connector)
    for name, value in connectors.items():
        if connector_paths.normalize(str(name)) == canonical and isinstance(value, dict):
            return value
    return None


def _document_effective_registry_required(raw: dict[str, Any], connector: str, asset_type: str) -> bool:
    asset_policy = raw.get("asset_policy")
    asset_policy = asset_policy if isinstance(asset_policy, dict) else {}
    global_policy = asset_policy.get(asset_type)
    global_policy = global_policy if isinstance(global_policy, dict) else {}
    global_value = global_policy.get("registry_required")
    effective = global_value if isinstance(global_value, bool) else False
    connector_policy = _document_connector_override(raw, connector)
    type_override = connector_policy.get(asset_type) if connector_policy is not None else None
    if isinstance(type_override, dict) and isinstance(type_override.get("registry_required"), bool):
        effective = type_override["registry_required"]
    return bool(effective)


def _verify_registry_required(path: str, result: RegistryRequiredResult) -> None:
    with open(path, encoding="utf-8") as stream:
        raw = yaml.safe_load(stream) or {}
    if not isinstance(raw, dict):
        raise ValueError("persisted config is not a YAML mapping")
    asset_policy = raw.get("asset_policy")
    asset_policy = asset_policy if isinstance(asset_policy, dict) else {}
    global_policy = asset_policy.get(result.asset_type)
    global_policy = global_policy if isinstance(global_policy, dict) else {}
    global_value = global_policy.get("registry_required")
    expected_global = result.global_after
    if global_value is not None and not isinstance(global_value, bool):
        raise ValueError(
            f"persisted global {result.asset_type}.registry_required={global_value!r}; expected a boolean"
        )
    persisted_global = global_value if isinstance(global_value, bool) else False
    if persisted_global != expected_global:
        raise ValueError(
            f"persisted global {result.asset_type}.registry_required={global_value!r}; "
            f"expected {expected_global!r}"
        )
    targets = (result.connector,) if result.connector is not None else result.active_connectors
    for connector in targets:
        if connector is None:
            continue
        effective = _document_effective_registry_required(raw, connector, result.asset_type)
        if effective != result.requested:
            raise ValueError(
                f"persisted effective {result.asset_type}.registry_required for {connector} "
                f"is {effective!r}; expected {result.requested!r}"
            )


def set_registry_required(
    cfg: Config,
    asset_type: str,
    enabled: bool,
    *,
    connector: str = "",
) -> RegistryRequiredResult:
    """Reconcile, atomically persist, verify, then publish to ``cfg``."""
    working = copy.deepcopy(cfg)
    result = reconcile_registry_required(working, asset_type, enabled, connector=connector)
    try:
        working.save_verified(lambda path: _verify_registry_required(path, result))
    except Exception as exc:
        raise RegistryRequiredUpdateError(result, exc) from exc
    cfg.asset_policy = working.asset_policy
    return result
