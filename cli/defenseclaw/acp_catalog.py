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


def own_tools_notice(agent_id: str) -> str:
    """What the guard cannot do for an agent that runs its own tools, or "".

    Such an agent (Hermes) asks the editor a permission only for what its own
    approval policy names, and reports every other tool call after it ran. The
    guard judges those reports and raises an alert that would have blocked; it
    cannot refuse them. The connector's own hooks run before the tool does
    (rel-1-0-10:GAP-0619).
    """
    for agent in ACP_REGISTRY["agents"]:
        if agent["id"] == agent_id and agent.get("runs_own_tools") is True:
            return (
                f"{agent['name']} runs its own tools and asks the editor first only for what its own "
                "approval policy names, so the guard sees most tool calls after they ran: it alerts and "
                "records them but does not refuse them. To refuse a command before it runs, use "
                f"the {agent['connector_id']} connector hooks: "
                f"defenseclaw setup {agent['connector_id']} --mode action."
            )
    return ""
