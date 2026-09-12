# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Trusted packaged ACP inventory shared by CLI and TUI presentation."""

from __future__ import annotations

import json
from importlib.resources import files
from typing import Any


def _load_catalog() -> tuple[dict[str, Any], tuple[str, ...], dict[str, tuple[str, tuple[str, ...]]]]:
    """Load the packaged ACP inventory once and fail closed on shape drift."""
    try:
        registry = json.loads(
            files("defenseclaw.inventory").joinpath("acp_registry.json").read_text(encoding="utf-8")
        )
        clients = tuple(sorted(item["id"] for item in registry["clients"]))
        agents = {
            item["id"]: (item["command"], tuple(item["args"]))
            for item in registry["agents"]
        }
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"packaged ACP registry is invalid: {exc}") from exc
    if set(clients) != {"zed", "jetbrains"}:
        raise RuntimeError(f"packaged ACP registry contains unsupported clients: {list(clients)}")
    if len(clients) != len(set(clients)):
        raise RuntimeError("packaged ACP registry contains duplicate client IDs")
    if not agents or any(
        not isinstance(agent_id, str)
        or not isinstance(command, str)
        or not command
        or not isinstance(args, tuple)
        or not all(isinstance(arg, str) for arg in args)
        for agent_id, (command, args) in agents.items()
    ):
        raise RuntimeError("packaged ACP registry contains an invalid agent entry point")
    if len(agents) != len(registry["agents"]):
        raise RuntimeError("packaged ACP registry contains duplicate agent IDs")
    return registry, clients, agents


ACP_REGISTRY, ACP_CLIENT_IDS, ACP_AGENT_ENTRY_POINTS = _load_catalog()
ACP_AGENT_IDS = tuple(sorted(ACP_AGENT_ENTRY_POINTS))
