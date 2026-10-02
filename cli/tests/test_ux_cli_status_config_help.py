# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Lean regressions for the CLI status / config / help UX batch.

GAP-1063, 1065, 1115, 1116, 1117, 1124, 1171, 1172, 1175, 1123, 1140.
"""

from __future__ import annotations

import contextlib
import io
import json
import re
from pathlib import Path
from unittest.mock import MagicMock

import click
import pytest
from click.testing import CliRunner
from defenseclaw import config as cfg_mod
from defenseclaw import upgrade_shim
from defenseclaw.commands import cmd_init, cmd_status
from defenseclaw.commands.cmd_alerts import alerts
from defenseclaw.commands.cmd_config import config_cmd
from defenseclaw.commands.cmd_guardrail import guardrail
from defenseclaw.config import AIDiscoveryConfig, ApplicationProtectionConfig
from defenseclaw.inventory import agent_discovery
from defenseclaw.main import cli

from tests.helpers import cleanup_app, make_app_context

ROOT = Path(__file__).resolve().parents[2]


def _walk(command: click.Command, ctx: click.Context):
    yield command, ctx
    for name, sub in sorted((getattr(command, "commands", None) or {}).items()):
        if not getattr(sub, "hidden", False):
            yield from _walk(sub, click.Context(sub, info_name=name, parent=ctx))


def test_help_has_no_rst_markup_internals_or_undocumented_options() -> None:
    # GAP-1171 / GAP-1123: help is for users, not for the code. GAP-1515 /
    # GAP-1557: no internal finding ids or implementation remarks either.
    internals = re.compile(
        r"``|/api/v1/|P\d-#\d|Round-\d|fu/[a-z]|Go wiring|\b(?:F|GAP)-\d{3,4}\b|\bOTHER-\d+\b"
        r"|parity with the TUI|CLI parity|Textual|Go provenance|Go (?:guardrail )?proxy"
    )
    problems = []
    for command, ctx in _walk(cli, click.Context(cli, info_name="defenseclaw")):
        hits = sorted(set(internals.findall(command.get_help(ctx))))
        if hits:
            problems.append(f"{ctx.command_path}: {hits}")
        bare = [
            p.opts[0]
            for p in command.params
            if isinstance(p, click.Option) and not p.hidden and not (p.help or "").strip()
        ]
        if bare:
            problems.append(f"{ctx.command_path}: no help for {bare}")
    assert problems == []


def test_help_lists_and_examples_keep_their_lines() -> None:
    # GAP-1770: mode lists and examples were reflowed into one paragraph.
    def page(group: str, name: str) -> str:
        command = cli.commands[group].commands[name]
        return command.get_help(click.Context(command, info_name=name, terminal_width=100))

    scan = page("skill", "scan")
    assert "\n  Examples:\n    defenseclaw skill scan\n" in scan
    assert "\n    defenseclaw skill scan clawhub://my-skill@1.2.3\n" in scan
    guard = page("setup", "guardrail")
    assert "\n  Two modes:\n    observe - " in guard
    assert "OpenClaw" not in guard.split("Options:")[0]
    # GAP-1862: the --connector option agrees with the description.
    assert "else openclaw" not in " ".join(guard.split())
    assert "if neither is set, pass --connector" in " ".join(guard.split())


def _signal(name: str, version: str = "1.0.0") -> agent_discovery.AgentSignal:
    return agent_discovery.AgentSignal(
        name=name, installed=True, config_path="", binary_path=f"/x/{name}", version=version, error=""
    )


def _disc(signal: agent_discovery.AgentSignal) -> agent_discovery.AgentDiscovery:
    return agent_discovery.AgentDiscovery(scanned_at="", agents={signal.name: signal}, cache_hit=False)


def test_discovery_table_strips_trailing_period_but_keeps_raw_version() -> None:
    # GAP-1065
    signal = _signal("copilot", version="GitHub Copilot CLI 1.0.90.")
    disc = _disc(signal)
    assert agent_discovery._display_version(signal.version) == "GitHub Copilot CLI 1.0.90"
    assert "1.0.90." not in agent_discovery.render_discovery_table(disc)
    assert signal.version == "GitHub Copilot CLI 1.0.90."


def test_init_discovery_table_shows_configured_mode(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # GAP-1063: same Active / Mode as 'agent discover'.
    monkeypatch.delenv("DEFENSECLAW_CONFIG", raising=False)
    (tmp_path / "config.yaml").write_text("config_version: 8\n", encoding="utf-8")
    cfg = MagicMock()
    cfg.active_connectors.return_value = ["claudecode"]
    cfg.guardrail.effective_mode.return_value = "action"
    monkeypatch.setattr(cfg_mod, "load", lambda **_kw: cfg)
    signal = _signal("claudecode")
    disc = _disc(signal)

    cmd_init._with_config_state(disc, tmp_path)

    assert signal.active and signal.mode == "action"
    # First run: no config yet, nothing is active.
    fresh = _signal("claudecode")
    cmd_init._with_config_state(_disc(fresh), tmp_path / "none")
    assert not fresh.active


def _capture(fn, *args, **kwargs) -> str:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        fn(*args, **kwargs)
    return buf.getvalue()


def test_status_labels_keep_a_space_and_stopped_sidecar_is_not_enforcing() -> None:
    # GAP-1115
    assert "Model routing: disabled" in _capture(cmd_status._status_row, "Model routing", "disabled")
    cfg = MagicMock()
    cfg.active_connectors.return_value = ["codex", "claudecode"]
    cfg.guardrail.effective_mode.return_value = "action"
    cfg.guardrail.effective_enabled.return_value = True
    cfg.application_protection = ApplicationProtectionConfig()
    cfg.ai_discovery = AIDiscoveryConfig()
    cfg.data_dir = ""
    out = _capture(cmd_status._print_agents, cfg, sidecar_down=True)
    assert "2 configured, not enforced while the sidecar is stopped" in out
    assert "2 active" not in out
    assert "defenseclaw-gateway start" in out


def test_config_path_pads_labels_and_hides_openclaw_without_openclaw(tmp_path: Path) -> None:
    # GAP-1115
    app, tmp_dir, db_path = make_app_context()
    try:
        app.cfg.claw.home_dir = str(tmp_path / "no-openclaw")
        app.cfg.claw.config_file = str(tmp_path / "no-openclaw" / "openclaw.json")
        result = CliRunner().invoke(config_cmd, ["path"], obj=app)
        assert result.exit_code == 0, result.output
        assert "quarantine dir:" in result.output
        assert re.search(r"quarantine dir: +\S", result.output)
        assert "OpenClaw" not in result.output
    finally:
        cleanup_app(app, db_path, tmp_dir)


def test_config_show_hides_reveal_and_reference_section_is_optional() -> None:
    # GAP-1116
    show = config_cmd.commands["show"]
    assert next(p for p in show.params if p.name == "reveal").hidden
    section = next(p for p in config_cmd.commands["reference"].params if p.name == "section")
    assert not section.required and section.default == "observability"


def test_unreadable_config_names_file_line_and_next_step(tmp_path: Path) -> None:
    # GAP-1175
    path = tmp_path / "config.yaml"
    path.write_text("config_version: 8\nfoo: [1, 2\n", encoding="utf-8")
    with pytest.raises(cfg_mod.ConfigVersionError) as caught:
        cfg_mod.source_config_version(path=str(path))
    message = str(caught.value)
    assert str(path) in message
    assert re.search(r"line \d+, column \d+", message)
    assert "defenseclaw config validate" in message


def test_source_builds_stamp_commit_and_date() -> None:
    # GAP-1124
    assets = (ROOT / "scripts" / "build-release-assets.sh").read_text(encoding="utf-8")
    assert "-X main.commit=${COMMIT} -X main.date=${BUILT}" in assets
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    assert "BUILD_INFO_LDFLAGS := -X main.commit=$(GIT_COMMIT) -X main.date=$(BUILD_DATE)" in makefile
    assert 'GOFLAGS     := -ldflags "-X main.version=$(VERSION) $(BUILD_INFO_LDFLAGS)"' in makefile


def test_upgrade_and_rollback_usage_errors_exit_2(capsys: pytest.CaptureFixture[str]) -> None:
    # GAP-1172
    assert upgrade_shim.run(["upgrade", "--no-such-flag"]) == 2
    assert upgrade_shim.run(["rollback", "--no-such-flag"]) == 2
    assert "unknown option" in capsys.readouterr().err


def test_status_commands_offer_json() -> None:
    # GAP-1172: guardrail status, alerts and codeguard status take --json.
    app, tmp_dir, db_path = make_app_context()
    try:
        runner = CliRunner()
        result = runner.invoke(guardrail, ["status", "--json"], obj=app)
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert {"enabled", "port", "connectors", "warnings"} <= payload.keys()

        result = runner.invoke(alerts, ["--json"], obj=app)
        assert result.exit_code == 0, result.output
        assert json.loads(result.output) == []
    finally:
        cleanup_app(app, db_path, tmp_dir)
    codeguard_status = cli.commands["codeguard"].commands["status"]
    assert any("--json" in p.opts for p in codeguard_status.params)
    for path in (("doctor",), ("acp", "detect"), ("quickstart",)):
        command = cli
        for name in path:
            command = command.commands[name]
        assert any("--json" in p.opts for p in command.params), path


def test_status_disabled_app_protect_names_the_way_forward(capsys) -> None:
    # GAP-1498: no "disabled (disabled)" and no "(awaiting discovery scan)"
    # when the feature is off; say how to turn it on.
    from types import SimpleNamespace

    cfg = SimpleNamespace(data_dir="", application_protection=ApplicationProtectionConfig(enabled=False))
    cmd_status._print_application_protection(cfg, health={"health_state": "disabled"})
    out = capsys.readouterr().out
    assert "disabled (disabled)" not in out
    assert "awaiting discovery scan" not in out
    assert "application_protection.enabled: true" in out
