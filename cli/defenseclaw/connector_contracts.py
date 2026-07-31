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
import sys
from dataclasses import dataclass, field
from importlib import resources
from typing import Any

STATUS_KNOWN = "known"
STATUS_UNVERSIONED = "unversioned"
STATUS_UNKNOWN = "unknown"
STATUS_NOT_GATED = "not-gated"

_VERSION_RE = re.compile(r"(?i)(?:^|[^0-9])v?([0-9]+)(?:\.([0-9]+))?(?:\.([0-9]+))?")
_CONTRACT_PLATFORMS = frozenset({"darwin", "linux", "windows"})
_PLATFORM_OVERRIDE_FIELDS = frozenset(
    {
        "agent_version",
        "default_for_unversioned",
        "hook_script_version",
        "events",
        "aid_surfaces",
        "native_otlp",
        "native_otlp_auth",
        "native_otlp_signals",
        "native_otlp_endpoint_template",
    }
)
_AGENT_VERSION_OVERRIDE_FIELDS = frozenset(
    {"exact", "min_inclusive", "max_exclusive"}
)
_STRING_OVERRIDE_FIELDS = frozenset(
    {
        "hook_script_version",
        "native_otlp_auth",
        "native_otlp_endpoint_template",
    }
)
_STRING_LIST_OVERRIDE_FIELDS = frozenset(
    {"events", "aid_surfaces", "native_otlp_signals"}
)


@dataclass(frozen=True)
class ConnectorContract:
    connector: str
    contract_id: str
    exact_agent_versions: tuple[str, ...] = ()
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
    native_otlp_auth: str = ""
    native_otlp_signals: tuple[str, ...] = ()
    native_otlp_endpoint_template: str = ""
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
    if value in {"open-hands", "open_hands"}:
        return "openhands"
    if value == "agy":
        return "antigravity"
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
    *,
    platform_name: str | None = None,
) -> tuple[frozenset[str], dict[str, tuple[ConnectorContract, ...]]]:
    platform_name = _contract_platform(platform_name)
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
            contract_spec = _contract_spec_for_platform(
                raw_contract,
                connector=name,
                platform_name=platform_name,
            )
            version = contract_spec.get("agent_version", {})
            if not isinstance(version, dict):
                version = {}
            contracts.append(
                ConnectorContract(
                    connector=name,
                    contract_id=str(contract_spec.get("contract_id", "")).strip(),
                    exact_agent_versions=tuple(
                        str(v) for v in version.get("exact", []) if v
                    ),
                    min_agent_version=str(version.get("min_inclusive", "") or ""),
                    max_agent_version=str(version.get("max_exclusive", "") or ""),
                    default_for_unversioned=bool(
                        contract_spec.get("default_for_unversioned", False)
                    ),
                    hook_script_version=str(contract_spec.get("hook_script_version", "") or ""),
                    hook_script=str(contract_spec.get("hook_script", "") or ""),
                    hook_config_path_templates=tuple(
                        str(v) for v in contract_spec.get("hook_config_path_templates", []) if v
                    ),
                    response_field=str(contract_spec.get("response_field", "") or ""),
                    events=tuple(str(v) for v in contract_spec.get("events", []) if v),
                    aid_surfaces=tuple(str(v) for v in contract_spec.get("aid_surfaces", []) if v),
                    supports_traceparent=bool(contract_spec.get("supports_traceparent", False)),
                    native_otlp=bool(contract_spec.get("native_otlp", False)),
                    native_otlp_auth=str(contract_spec.get("native_otlp_auth", "") or ""),
                    native_otlp_signals=tuple(
                        str(v) for v in contract_spec.get("native_otlp_signals", []) if v
                    ),
                    native_otlp_endpoint_template=str(
                        contract_spec.get("native_otlp_endpoint_template", "") or ""
                    ),
                    capabilities=dict(contract_spec.get("capabilities", {}) or {}),
                    notes=tuple(str(v) for v in contract_spec.get("notes", []) if v),
                )
            )
        if contracts:
            defaults = [contract.contract_id for contract in contracts if contract.default_for_unversioned]
            if len(defaults) > 1:
                raise ValueError(
                    f"hook_contracts.json connector {name!r} has multiple default contracts "
                    f"for platform {platform_name!r}: {defaults}"
                )
            hook_contracts[name] = tuple(contracts)
    return frozenset(proxy_connectors), hook_contracts


def _contract_platform(platform_name: str | None) -> str:
    if platform_name is None:
        if sys.platform == "darwin":
            return "darwin"
        if sys.platform == "win32":
            return "windows"
        return "linux"
    if not isinstance(platform_name, str) or platform_name not in _CONTRACT_PLATFORMS:
        raise ValueError(
            "hook contract platform must be one of darwin, linux, or windows"
        )
    return platform_name


def _contract_spec_for_platform(
    raw_contract: dict[str, Any],
    *,
    connector: str,
    platform_name: str,
) -> dict[str, Any]:
    raw_overrides = raw_contract.get("platform_overrides", {})
    if not isinstance(raw_overrides, dict):
        raise ValueError(
            f"hook contract {connector!r} platform_overrides must be an object"
        )
    for raw_platform, raw_override in raw_overrides.items():
        if raw_platform not in _CONTRACT_PLATFORMS:
            raise ValueError(
                f"hook contract {connector!r} has unknown platform override {raw_platform!r}"
            )
        _validate_platform_override(
            raw_override,
            connector=connector,
            contract_id=str(raw_contract.get("contract_id", "") or ""),
            platform_name=raw_platform,
        )

    contract_spec = dict(raw_contract)
    contract_spec.pop("platform_overrides", None)
    selected = raw_overrides.get(platform_name)
    if selected is None:
        return contract_spec
    override = dict(selected)
    version_override = override.pop("agent_version", None)
    contract_spec.update(override)
    if version_override is not None:
        base_version = contract_spec.get("agent_version", {})
        if not isinstance(base_version, dict):
            base_version = {}
        merged_version = dict(base_version)
        merged_version.update(version_override)
        contract_spec["agent_version"] = merged_version
    return contract_spec


def _validate_platform_override(
    raw_override: Any,
    *,
    connector: str,
    contract_id: str,
    platform_name: str,
) -> None:
    location = f"{connector}/{contract_id or '<missing-id>'}/{platform_name}"
    if not isinstance(raw_override, dict):
        raise ValueError(f"hook contract platform override {location} must be an object")
    unknown = sorted(set(raw_override) - _PLATFORM_OVERRIDE_FIELDS)
    if unknown:
        raise ValueError(
            f"hook contract platform override {location} has unknown fields: {unknown}"
        )
    version = raw_override.get("agent_version")
    if version is not None:
        if not isinstance(version, dict):
            raise ValueError(
                f"hook contract platform override {location} agent_version must be an object"
            )
        unknown_version = sorted(set(version) - _AGENT_VERSION_OVERRIDE_FIELDS)
        if unknown_version:
            raise ValueError(
                f"hook contract platform override {location} agent_version has unknown fields: "
                f"{unknown_version}"
            )
        for field_name in ("min_inclusive", "max_exclusive"):
            value = version.get(field_name)
            if value is not None and not isinstance(value, str):
                raise ValueError(
                    f"hook contract platform override {location} agent_version.{field_name} "
                    "must be a string"
                )
        if "exact" in version:
            _validate_string_list(version["exact"], location=f"{location} agent_version.exact")
    for field_name in ("default_for_unversioned", "native_otlp"):
        if field_name in raw_override and type(raw_override[field_name]) is not bool:
            raise ValueError(
                f"hook contract platform override {location} {field_name} must be a boolean"
            )
    for field_name in _STRING_OVERRIDE_FIELDS:
        if field_name in raw_override and not isinstance(raw_override[field_name], str):
            raise ValueError(
                f"hook contract platform override {location} {field_name} must be a string"
            )
    for field_name in _STRING_LIST_OVERRIDE_FIELDS:
        if field_name in raw_override:
            _validate_string_list(
                raw_override[field_name],
                location=f"{location} {field_name}",
            )


def _validate_string_list(value: Any, *, location: str) -> None:
    if not isinstance(value, list) or not all(
        isinstance(item, str) and item.strip() for item in value
    ):
        raise ValueError(f"hook contract platform override {location} must be a string list")


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


def resolve_connector_contract(
    connector: str,
    raw_version: str | None,
    *,
    platform_name: str | None = None,
) -> ConnectorCompatibility:
    name = normalize_connector(connector)
    raw = (raw_version or "").strip()
    if platform_name is None:
        proxy_connectors = PROXY_CONNECTORS
        hook_contracts = HOOK_CONTRACTS
    else:
        proxy_connectors, hook_contracts = _load_contracts_from_manifest(
            HOOK_CONTRACT_MANIFEST,
            platform_name=platform_name,
        )
    if name in proxy_connectors:
        return ConnectorCompatibility(
            connector=name,
            raw_version=raw,
            normalized_version=normalize_agent_version(raw),
            status=STATUS_NOT_GATED,
            reason="proxy/chat connector; no hook contract gate",
            contract=None,
        )
    contracts = hook_contracts.get(name, ())
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
        if _contract_matches_agent_version(contract, raw, normalized):
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


def _contract_matches_agent_version(
    contract: ConnectorContract,
    raw_version: str,
    normalized_version: str,
) -> bool:
    if contract.exact_agent_versions:
        return _exact_agent_version_match(raw_version, contract.exact_agent_versions)
    return _version_in_range(
        normalized_version,
        contract.min_agent_version,
        contract.max_agent_version,
    )


def _exact_agent_version_match(raw: str, expected: tuple[str, ...]) -> bool:
    fields = raw.strip().split()
    if not fields or len(fields) > 2:
        return False
    token = fields[-1]
    if len(fields) == 2 and fields[0].lower() not in {"agent", "cursor-agent"}:
        return False
    if token[:1].lower() == "v":
        token = token[1:]
    return any(token.lower() == candidate.strip().lower() for candidate in expected)


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
