# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Connector version compatibility contracts used by CLI setup.

The gateway owns enforcement at runtime in
``internal/gateway/connector/hook_contract.go``. This module mirrors the
published contract IDs and version ranges so setup can fail early when an
operator selects an action-mode hook connector whose installed agent version is
outside the DefenseClaw-supported hook surface.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from importlib import resources
from typing import Any

STATUS_KNOWN = "known"
STATUS_UNVERSIONED = "unversioned"
STATUS_UNKNOWN = "unknown"
STATUS_NOT_GATED = "not-gated"

_VERSION_RE = re.compile(r"(?i)(?:^|[^0-9])v?([0-9]+)(?:\.([0-9]+))?(?:\.([0-9]+))?")


@dataclass(frozen=True)
class ConnectorContract:
    connector: str
    contract_id: str
    min_agent_version: str = ""
    max_agent_version: str = ""
    default_for_unversioned: bool = False
    hook_script_version: str = ""
    hook_script: str = ""
    hook_config_path_templates: tuple[str, ...] = ()
    response_field: str = ""
    events: tuple[str, ...] = ()
    aid_surfaces: tuple[str, ...] = ()
    supports_traceparent: bool = False
    native_otlp: bool = False
    capabilities: dict[str, Any] = field(default_factory=dict)
    notes: tuple[str, ...] = ()


@dataclass(frozen=True)
class ConnectorCompatibility:
    connector: str
    raw_version: str
    normalized_version: str
    status: str
    reason: str
    contract: ConnectorContract | None = None

    @property
    def supported(self) -> bool:
        return self.status in {STATUS_KNOWN, STATUS_UNVERSIONED, STATUS_NOT_GATED}


def normalize_connector(name: str | None) -> str:
    value = (name or "").strip().lower()
    if value in {"claude", "claude-code", "claude_code"}:
        return "claudecode"
    if value in {"gemini", "gemini-cli", "gemini_cli"}:
        return "geminicli"
    return value


def hook_contract_manifest() -> dict[str, Any]:
    """Return the packaged hook contract compatibility manifest."""
    text = resources.files("defenseclaw.inventory").joinpath(
        "hook_contracts.json",
    ).read_text(encoding="utf-8")
    loaded = json.loads(text)
    if not isinstance(loaded, dict):
        raise ValueError("hook_contracts.json must contain an object")
    return loaded


def _load_contracts_from_manifest(
    manifest: dict[str, Any],
) -> tuple[frozenset[str], dict[str, tuple[ConnectorContract, ...]]]:
    connectors = manifest.get("connectors", {})
    if not isinstance(connectors, dict):
        raise ValueError("hook_contracts.json connectors must be an object")

    proxy_connectors: set[str] = set()
    hook_contracts: dict[str, tuple[ConnectorContract, ...]] = {}
    for raw_name, raw_spec in connectors.items():
        name = normalize_connector(str(raw_name))
        spec = raw_spec if isinstance(raw_spec, dict) else {}
        if spec.get("compatibility_gate") == STATUS_NOT_GATED or spec.get("kind") == "proxy":
            proxy_connectors.add(name)

        contracts: list[ConnectorContract] = []
        for raw_contract in spec.get("contracts", []):
            if not isinstance(raw_contract, dict):
                continue
            version = raw_contract.get("agent_version", {})
            if not isinstance(version, dict):
                version = {}
            contracts.append(
                ConnectorContract(
                    connector=name,
                    contract_id=str(raw_contract.get("contract_id", "")).strip(),
                    min_agent_version=str(version.get("min_inclusive", "") or ""),
                    max_agent_version=str(version.get("max_exclusive", "") or ""),
                    default_for_unversioned=bool(
                        raw_contract.get("default_for_unversioned", False)
                    ),
                    hook_script_version=str(raw_contract.get("hook_script_version", "") or ""),
                    hook_script=str(raw_contract.get("hook_script", "") or ""),
                    hook_config_path_templates=tuple(
                        str(v) for v in raw_contract.get("hook_config_path_templates", []) if v
                    ),
                    response_field=str(raw_contract.get("response_field", "") or ""),
                    events=tuple(str(v) for v in raw_contract.get("events", []) if v),
                    aid_surfaces=tuple(str(v) for v in raw_contract.get("aid_surfaces", []) if v),
                    supports_traceparent=bool(raw_contract.get("supports_traceparent", False)),
                    native_otlp=bool(raw_contract.get("native_otlp", False)),
                    capabilities=dict(raw_contract.get("capabilities", {}) or {}),
                    notes=tuple(str(v) for v in raw_contract.get("notes", []) if v),
                )
            )
        if contracts:
            hook_contracts[name] = tuple(contracts)
    return frozenset(proxy_connectors), hook_contracts


HOOK_CONTRACT_MANIFEST = hook_contract_manifest()
PROXY_CONNECTORS, HOOK_CONTRACTS = _load_contracts_from_manifest(HOOK_CONTRACT_MANIFEST)


def normalize_agent_version(raw: str | None) -> str:
    raw = (raw or "").strip()
    if not raw:
        return ""
    match = _VERSION_RE.search(raw)
    if not match:
        return ""
    parts = [match.group(1), match.group(2) or "0", match.group(3) or "0"]
    normalized: list[str] = []
    for part in parts:
        try:
            normalized.append(str(int(part)))
        except ValueError:
            return ""
    return ".".join(normalized)


def resolve_connector_contract(connector: str, raw_version: str | None) -> ConnectorCompatibility:
    name = normalize_connector(connector)
    raw = (raw_version or "").strip()
    if name in PROXY_CONNECTORS:
        return ConnectorCompatibility(
            connector=name,
            raw_version=raw,
            normalized_version=normalize_agent_version(raw),
            status=STATUS_NOT_GATED,
            reason="proxy/chat connector; no hook contract gate",
            contract=None,
        )
    contracts = HOOK_CONTRACTS.get(name, ())
    if not contracts:
        return ConnectorCompatibility(
            connector=name,
            raw_version=raw,
            normalized_version="",
            status=STATUS_UNKNOWN,
            reason="no DefenseClaw hook contract registered for connector",
            contract=None,
        )
    if not raw:
        contract = _default_contract(contracts)
        return ConnectorCompatibility(
            connector=name,
            raw_version="",
            normalized_version="",
            status=STATUS_UNVERSIONED,
            reason="agent version not probed; using connector default hook contract",
            contract=contract,
        )
    normalized = normalize_agent_version(raw)
    if not normalized:
        return ConnectorCompatibility(
            connector=name,
            raw_version=raw,
            normalized_version="",
            status=STATUS_UNKNOWN,
            reason="could not normalize agent version",
            contract=None,
        )
    for contract in contracts:
        if _version_in_range(normalized, contract.min_agent_version, contract.max_agent_version):
            return ConnectorCompatibility(
                connector=name,
                raw_version=raw,
                normalized_version=normalized,
                status=STATUS_KNOWN,
                reason=f"matched hook contract {contract.contract_id}",
                contract=contract,
            )
    return ConnectorCompatibility(
        connector=name,
        raw_version=raw,
        normalized_version=normalized,
        status=STATUS_UNKNOWN,
        reason="no hook contract matches normalized agent version",
        contract=None,
    )


def _version_in_range(version: str, min_version: str, max_version: str) -> bool:
    if not version:
        return False
    if min_version and _compare_version(version, min_version) < 0:
        return False
    if max_version and _compare_version(version, max_version) >= 0:
        return False
    return True


def _default_contract(contracts: tuple[ConnectorContract, ...]) -> ConnectorContract:
    for contract in contracts:
        if contract.default_for_unversioned:
            return contract
    return contracts[0]


def _compare_version(a: str, b: str) -> int:
    av = _version_tuple(a)
    bv = _version_tuple(b)
    if av < bv:
        return -1
    if av > bv:
        return 1
    return 0


def _version_tuple(value: str) -> tuple[int, int, int]:
    normalized = normalize_agent_version(value)
    if not normalized:
        return (0, 0, 0)
    parts = normalized.split(".")
    nums = [int(part) for part in parts[:3]]
    while len(nums) < 3:
        nums.append(0)
    return (nums[0], nums[1], nums[2])
