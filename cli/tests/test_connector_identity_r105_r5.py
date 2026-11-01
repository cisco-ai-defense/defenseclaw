# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""One connector identity for the roster prune and the hook gates (GAP-1971, GAP-1972)."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from defenseclaw import connector_paths
from defenseclaw.commands import cmd_guardrail
from defenseclaw.config import PerConnectorGuardrailConfig, default_config

_CONFIG_GO = Path(__file__).resolve().parents[2] / "internal" / "config" / "config.go"
_RETIRED = {"openhands"}  # the gateway drops a retired primary before any gate reads it


def _go_aliases() -> dict[str, str]:
    source = _CONFIG_GO.read_text(encoding="utf-8")
    body = source.split("func normalizeConnectorKey(name string) string {", 1)[1].split("\n}\n", 1)[0]
    aliases: dict[str, str] = {}
    for names, target in re.findall(r'case ((?:"[^"]+",?\s*)+):(?:\s*//[^\n]*)*\s*return "([^"]+)"', body):
        for name in re.findall(r'"([^"]+)"', names):
            aliases[name] = target
    return aliases


def test_python_connector_fold_matches_the_go_hook_gates() -> None:
    aliases = _go_aliases()
    assert aliases.get("claude-code") == "claudecode", aliases
    for alias, target in aliases.items():
        if target in _RETIRED:
            continue
        assert connector_paths.normalize(alias) == target
        assert connector_paths.normalize(alias.upper()) == target


@pytest.mark.parametrize("primary", ["claude-code", "claude_code", "Claude-Code", "claudecode"])
def test_roster_prune_reads_an_aliased_primary_as_the_go_gates_do(primary) -> None:
    # Go claudeCodeEnabled folds the same alias (GuardrailConfig.NamesConnector),
    # so with guardrail.connector naming Claude Code the lone entry adds nothing.
    cfg = default_config()
    cfg.guardrail.connector = primary
    cfg.guardrail.connectors = {"claudecode": PerConnectorGuardrailConfig()}
    assert cmd_guardrail.roster_entry_is_redundant(cfg, "claudecode", ["claudecode"]) is True
    assert cmd_guardrail.roster_entry_is_redundant(cfg, "codex", ["codex"]) is False
