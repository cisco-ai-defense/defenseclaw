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

import re
from dataclasses import dataclass


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
    hook_script_version: str = ""
    response_field: str = ""
    aid_surfaces: tuple[str, ...] = ()
    notes: str = ""


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


PROXY_CONNECTORS = frozenset({"openclaw", "zeptoclaw"})

HOOK_CONTRACTS: dict[str, tuple[ConnectorContract, ...]] = {
    "codex": (
        ConnectorContract(
            connector="codex",
            contract_id="codex-hooks-v1",
            min_agent_version="0.0.0",
            max_agent_version="1.0.0",
            hook_script_version="v6",
            response_field="codex_output",
            aid_surfaces=("prompt", "tool_call", "tool_result"),
            notes="Codex has no native hook-side ask surface; confirm verdicts downgrade to alert/systemMessage.",
        ),
    ),
    "claudecode": (
        ConnectorContract(
            connector="claudecode",
            contract_id="claudecode-hooks-v1",
            min_agent_version="0.0.0",
            max_agent_version="2.0.0",
            hook_script_version="v6",
            response_field="claude_code_output",
            aid_surfaces=("prompt", "tool_call", "tool_result", "event_content"),
            notes="Claude Code PreToolUse supports native HITL via permissionDecision=ask.",
        ),
    ),
    "hermes": (
        ConnectorContract(
            connector="hermes",
            contract_id="hermes-hooks-v1",
            hook_script_version="v6",
            response_field="hook_output",
            aid_surfaces=("tool_call",),
        ),
    ),
    "cursor": (
        ConnectorContract(
            connector="cursor",
            contract_id="cursor-hooks-v1",
            hook_script_version="v6",
            response_field="hook_output",
            aid_surfaces=("prompt", "tool_call", "tool_result"),
            notes="Cursor native ask is limited to beforeShellExecution and beforeMCPExecution.",
        ),
    ),
    "windsurf": (
        ConnectorContract(
            connector="windsurf",
            contract_id="windsurf-hooks-v1",
            hook_script_version="v6",
            response_field="hook_output",
            aid_surfaces=("prompt", "tool_call", "tool_result"),
        ),
    ),
    "geminicli": (
        ConnectorContract(
            connector="geminicli",
            contract_id="geminicli-hooks-v1",
            hook_script_version="v6",
            response_field="hook_output",
            aid_surfaces=("prompt", "tool_call", "tool_result"),
        ),
    ),
    "copilot": (
        ConnectorContract(
            connector="copilot",
            contract_id="copilot-hooks-v1",
            hook_script_version="v6",
            response_field="hook_output",
            aid_surfaces=("prompt", "tool_call", "tool_result"),
            notes="Copilot CLI native ask is limited to preToolUse / PreToolUse hooks.",
        ),
    ),
}


def normalize_connector(name: str | None) -> str:
    value = (name or "").strip().lower()
    if value in {"claude", "claude-code", "claude_code"}:
        return "claudecode"
    if value in {"gemini", "gemini-cli", "gemini_cli"}:
        return "geminicli"
    return value


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
        return ConnectorCompatibility(
            connector=name,
            raw_version="",
            normalized_version="",
            status=STATUS_UNVERSIONED,
            reason="agent version not probed; using connector default hook contract",
            contract=contracts[0],
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
