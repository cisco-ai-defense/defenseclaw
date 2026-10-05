# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Command preview modal parity tests."""

from __future__ import annotations

import dataclasses

from defenseclaw.tui.command_line import ParsedCommand
from defenseclaw.tui.screens.command_preview import build_command_preview, mask_argv


def _parsed(args: tuple[str, ...], *, category: str = "setup") -> ParsedCommand:
    return ParsedCommand(
        binary="defenseclaw",
        args=args,
        display_name=" ".join(args),
        category=category,
        needs_preview=True,
    )


def test_command_preview_masks_secret_flags() -> None:
    masked = mask_argv(("defenseclaw", "keys", "set", "OPENAI_API_KEY", "--value", "sk-test"))

    assert masked == ("defenseclaw", "keys", "set", "OPENAI_API_KEY", "--value", "<redacted>")


def test_command_preview_classifies_destructive_commands_as_high_risk() -> None:
    preview = build_command_preview(_parsed(("uninstall", "--all", "--yes"), category="other"))

    assert preview.risk == "destructive"
    assert "Destructive" in preview.summary


def test_command_preview_shows_origin_and_restart_effect() -> None:
    preview = build_command_preview(_parsed(("setup", "codex", "--yes"), category="setup"))

    assert preview.origin == "setup"
    assert preview.restart == "possible"


def test_command_preview_upgrade_focuses_cancel_by_default() -> None:
    """GAP-2090: Enter alone must not start an upgrade or rollback."""

    for verb in ("upgrade", "rollback"):
        preview = build_command_preview(_parsed((verb, "--yes"), category="other"))
        assert preview.cancel_by_default, verb
    assert build_command_preview(_parsed(("uninstall", "--all", "--yes"), category="other")).cancel_by_default
    assert not build_command_preview(_parsed(("setup", "codex", "--yes"))).cancel_by_default


def test_command_preview_agent_discovery_toggle_restarts_gateway() -> None:
    """GAP-2269: discovery enable/disable restart the gateway by default."""

    for args in (
        ("agent", "discovery", "disable", "--yes"),
        ("agent", "discovery", "enable", "--yes"),
        ("agent", "discovery", "runtime", "enable", "--yes"),
    ):
        preview = build_command_preview(_parsed(args, category="setup"))
        assert preview.restart == "yes", args
        assert "Runtime traffic may briefly pause" in preview.summary, args
    no_restart = build_command_preview(_parsed(("agent", "discovery", "disable", "--no-restart", "--yes")))
    assert no_restart.restart == "no"
    assert build_command_preview(_parsed(("agent", "discovery", "status"), category="other")).restart == "no"


def test_command_preview_registry_policy_changes_restart_gateway() -> None:
    """GAP-2499: approve/reject change asset_policy, which restarts a running gateway."""

    for verb in ("approve", "reject"):
        args = ("registry", verb, "corp", "wiki", "--type", "mcp", "--json")
        preview = build_command_preview(_parsed(args, category="registries"))
        assert preview.restart == "yes", verb
        assert "restarts a running gateway" in preview.summary, verb
    sync_cmd = _parsed(("registry", "sync", "--all", "--json"), category="registries")
    # The panel's intents carry risk="mutation" (GAP-1152).
    sync = build_command_preview(dataclasses.replace(sync_cmd, risk="mutation"))
    assert sync.restart == "possible"
    no_promote = ("registry", "approve", "corp", "wiki", "--no-repromote")
    assert build_command_preview(_parsed(no_promote, category="registries")).restart == "no"
    assert build_command_preview(_parsed(("registry", "list"), category="registries")).restart == "no"
