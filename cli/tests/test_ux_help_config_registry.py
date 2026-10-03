# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Lean regressions for the -h, config show/get and registry help UX batch.

GAP-2170, GAP-2171, GAP-2172.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner
from defenseclaw.commands import cmd_config
from defenseclaw.config_inspect import ConfigV8WireResult
from defenseclaw.main import cli


@pytest.mark.parametrize("argv", [["-h"], ["status", "-h"], ["config", "show", "-h"]])
def test_dash_h_is_short_help(argv: list[str], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", ["defenseclaw", *argv])
    result = CliRunner().invoke(cli, argv, prog_name="defenseclaw")
    assert result.exit_code == 0, result.output
    assert "Usage: defenseclaw" in result.output
    assert "-h, --help" in result.output


def test_registry_help_lists_each_command_once(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", ["defenseclaw", "registry", "--help"])
    result = CliRunner().invoke(cli, ["registry", "--help"], prog_name="defenseclaw", terminal_width=80)
    assert result.exit_code == 0, result.output
    assert "Subcommands:" not in result.output
    assert result.output.count("  require ") == 1
    assert max(len(line) for line in result.output.splitlines()) <= 80


def _effective(effective: dict) -> ConfigV8WireResult:
    return ConfigV8WireResult(
        wire_version=1,
        kind="effective",
        config_version=8,
        source="/tmp/config.yaml",
        data_dir="/tmp/dc",
        plan_digest="digest",
        network_validation="offline_syntax_and_literal_policy_only",
        valid=None,
        effective=effective,
    )


def _invoke(tmp_path: Path, args: list[str]):
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "config_version: 8\nllm: {api_key: DO-NOT-ECHO}\n"
        "asset_policy: {enabled: true, mcp: {registry_required: true}}\nobservability: {}\n",
        encoding="utf-8",
    )
    with (
        patch.object(cmd_config.config_module, "config_path", return_value=config_path),
        patch.object(cmd_config, "inspect_v8_config", return_value=_effective({"destinations": []})),
    ):
        return CliRunner().invoke(cmd_config.config_cmd, args)


def test_config_show_has_every_section_and_get_reads_one_key(tmp_path: Path) -> None:
    shown = _invoke(tmp_path, ["show", "--format", "json"])
    assert shown.exit_code == 0, shown.output
    data = json.loads(shown.output)
    assert data["asset_policy"]["enabled"] is True
    assert data["observability"] == {"destinations": []}
    assert "DO-NOT-ECHO" not in shown.output

    section = _invoke(tmp_path, ["show", "--section", "asset_policy", "--format", "json"])
    assert json.loads(section.output) == {"asset_policy": data["asset_policy"]}
    unknown = _invoke(tmp_path, ["show", "--section", "nope"])
    assert unknown.exit_code == 2 and "Sections: asset_policy, config_version, llm, observability" in unknown.output

    got = _invoke(tmp_path, ["get", "asset_policy.mcp.registry_required"])
    assert got.exit_code == 0 and got.output == "true\n"
    missing = _invoke(tmp_path, ["get", "asset_policy.skill.registry_required"])
    assert missing.exit_code == 1
    assert "config show --section asset_policy" in missing.output
