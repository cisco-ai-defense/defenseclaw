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

import click
import pytest
from click.testing import CliRunner
from defenseclaw.commands import cmd_config
from defenseclaw.config_inspect import ConfigV8WireResult
from defenseclaw.main import cli


def _reset_help_options(command: click.Command) -> None:
    # Click caches each command's help option the first time it is built. A
    # test elsewhere that builds click.Context(cli) by hand (without the
    # group's context_settings) caches a --help-only option, so start clean.
    command._help_option = None
    for sub in (getattr(command, "commands", None) or {}).values():
        _reset_help_options(sub)


@pytest.fixture
def fresh_help_options():
    _reset_help_options(cli)
    yield
    _reset_help_options(cli)


@pytest.mark.parametrize("argv", [["-h"], ["status", "-h"], ["config", "show", "-h"]])
def test_dash_h_is_short_help(argv: list[str], monkeypatch: pytest.MonkeyPatch, fresh_help_options) -> None:
    monkeypatch.setattr(sys, "argv", ["defenseclaw", *argv])
    result = CliRunner().invoke(cli, argv, prog_name="defenseclaw")
    assert result.exit_code == 0, result.output
    assert "Usage: defenseclaw" in result.output
    assert "-h, --help" in result.output


def test_registry_help_lists_each_command_once(monkeypatch: pytest.MonkeyPatch, fresh_help_options) -> None:
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
    assert unknown.exit_code == 2 and "Sections: " in unknown.output and "asset_policy, " in unknown.output

    got = _invoke(tmp_path, ["get", "asset_policy.mcp.registry_required"])
    assert got.exit_code == 0 and got.output == "true\n"
    missing = _invoke(tmp_path, ["get", "asset_policy.connectors.hermes"])
    assert missing.exit_code == 1
    assert "config show --section asset_policy" in missing.output

    # GAP-0276: one key outside observability is read without validating the
    # whole file (every guardrail profile) or asking for the observability plan.
    with (
        patch.object(cmd_config.config_module, "config_path", return_value=tmp_path / "config.yaml"),
        patch.object(cmd_config, "inspect_v8_config", side_effect=AssertionError("observability plan")),
        patch.object(cmd_config, "load_validate_v8", side_effect=AssertionError("full validation")),
    ):
        fast = CliRunner().invoke(cmd_config.config_cmd, ["get", "asset_policy.enabled"])
    assert fast.exit_code == 0 and fast.output == "true\n", fast.output


def test_fresh_v8_config_shows_and_gets_defaults(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # 'init' writes only claw/config_version/gateway/observability; the
    # sections it leaves out still show the defaults that apply (GAP-2171).
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path))
    config_path = tmp_path / "config.yaml"
    config_path.write_text("config_version: 8\ngateway: {}\nobservability: {}\n", encoding="utf-8")

    def run(args: list[str]):
        with (
            patch.object(cmd_config.config_module, "config_path", return_value=config_path),
            patch.object(cmd_config, "inspect_v8_config", return_value=_effective({"destinations": []})),
        ):
            return CliRunner().invoke(cmd_config.config_cmd, args)

    shown = run(["show", "--section", "asset_policy", "--format", "json"])
    assert shown.exit_code == 0, shown.output
    policy = json.loads(shown.output)["asset_policy"]
    assert policy["enabled"] is False and policy["mode"] == "observe"
    assert policy["mcp"]["registry_required"] is False
    assert "audit_db" not in json.loads(run(["show", "--format", "json"]).output)

    got = run(["get", "asset_policy.mcp.registry_required"])
    assert got.exit_code == 0, got.output
    assert got.stdout == "false\n"
    assert "default: config.yaml does not set" in got.stderr

    assert run(["get", "nope.enabled"]).exit_code == 2
    assert run(["show", "--section", "managed"]).exit_code == 1
    source = run(["show", "--source", "--section", "asset_policy"])
    assert source.exit_code == 1 and "Drop --source" in source.output


def test_config_get_shows_the_scanner_gate_the_gateway_runs_with(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # GAP-0068: blank gate and judge source, and the v8 migration keys, in a v9 dump.
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path))
    monkeypatch.delenv("DEFENSECLAW_CONFIG", raising=False)
    config_path = tmp_path / "config.yaml"
    config_path.write_text("config_version: 9\ngateway: {}\nobservability: {}\n", encoding="utf-8")
    with (
        patch.object(cmd_config.config_module, "config_path", return_value=config_path),
        patch.object(cmd_config, "inspect_v8_config", return_value=_effective({"destinations": []})),
    ):
        got = CliRunner().invoke(cmd_config.config_cmd, ["get", "scanners.skill_scanner", "--format", "json"])
    assert got.exit_code == 0, got.output
    skill = json.loads(got.stdout)
    assert (skill["fail_on_severity"], skill["review_queue_min"], skill["judge_source"]) == ("HIGH", "MEDIUM", "inherit")
    assert not {"binary", "use_virustotal", "use_aidefense", "virustotal_api_key"} & set(skill)


def test_config_get_destinations_index_the_list_config_set_edits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # GAP-0008: the resolved plan lists the generated local-sqlite destination first.
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path))
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "config_version: 9\ngateway: {}\nobservability:\n  destinations:\n"
        "    - {name: remote, kind: otlp, endpoint: 'https://otel.example.test'}\n",
        encoding="utf-8",
    )
    plan = {"destinations": [{"name": "local-sqlite"}, {"name": "remote"}]}
    with (
        patch.object(cmd_config.config_module, "config_path", return_value=config_path),
        patch.object(cmd_config, "inspect_v8_config", return_value=_effective(plan)),
    ):
        first = CliRunner().invoke(cmd_config.config_cmd, ["get", "observability.destinations[0].name"])
        listed = CliRunner().invoke(cmd_config.config_cmd, ["get", "observability.destinations", "--format", "json"])
        past = CliRunner().invoke(cmd_config.config_cmd, ["get", "observability.destinations[1].name"])
    assert first.exit_code == 0, first.output
    assert first.stdout == "remote\n"
    assert [item["name"] for item in json.loads(listed.stdout)] == ["remote"]
    # GAP-0154: the plan's entry at index 1 is not one config set can edit.
    assert past.exit_code == 1 and "out of range (config.yaml lists 1 destination)" in past.output


def test_config_get_effective_resolves_pack_levels_and_the_scanner_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path))
    monkeypatch.delenv("DEFENSECLAW_CONFIG", raising=False)
    monkeypatch.delenv("DEFENSECLAW_DEPLOYMENT_MODE", raising=False)
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "config_version: 9\ngateway: {}\nobservability: {}\nguardrail: {rule_pack: strict}\n"
        "scanners: {skill_scanner: {fail_on_severity: CRITICAL}}\n"
        "admission: {mcp: {scan_on_install: false}, plugin: {first_party_allow_list: []}}\n",
        encoding="utf-8",
    )
    with patch.object(cmd_config.config_module, "config_path", return_value=config_path):
        block = CliRunner().invoke(cmd_config.config_cmd, ["get", "guardrail.block_at", "--effective"])
        scan = CliRunner().invoke(cmd_config.config_cmd, ["get", "admission.mcp.scan_on_install", "--effective"])
        plugin = CliRunner().invoke(cmd_config.config_cmd, ["get", "admission.plugin", "--effective"])
        skill = CliRunner().invoke(
            cmd_config.config_cmd, ["get", "admission.skill.actions", "--effective", "--format", "json"]
        )
    assert block.exit_code == 0, block.output
    assert block.stdout == "MEDIUM\n" and "pack-default:strict" in block.stderr
    # An unset level or trust level prints what applies, not a blank default.
    with patch.object(cmd_config.config_module, "config_path", return_value=config_path):
        plain = CliRunner().invoke(cmd_config.config_cmd, ["get", "guardrail.block_at"])
        trust = CliRunner().invoke(cmd_config.config_cmd, ["get", "guardrail.cisco_trust_level"])
        config_path.write_text(
            "config_version: 9\ngateway: {}\nobservability: {}\nguardrail: {cisco_trust_level: advisory}\n",
            encoding="utf-8",
        )
        set_trust = CliRunner().invoke(cmd_config.config_cmd, ["get", "guardrail.cisco_trust_level", "--effective"])
    assert plain.stdout == "MEDIUM\n" and "pack-default:strict" in plain.stderr
    assert trust.stdout == "full\n" and "builtin" in trust.stderr
    assert set_trust.stdout == "advisory\n" and "config:guardrail.cisco_trust_level" in set_trust.stderr
    assert skill.exit_code == 0, skill.output
    assert json.loads(skill.stdout) == {
        "critical": "quarantine", "high": "warn", "medium": "warn", "low": "allow", "info": "allow"
    }
    assert "derived:scanners.skill_scanner" in skill.stderr
    # A key config.yaml sets names config.yaml as its source, not builtin (GAP-0009).
    assert scan.stdout == "false\n" and "config:admission.mcp.scan_on_install" in scan.stderr
    assert "config:admission.plugin.first_party_allow_list" in plugin.stderr
