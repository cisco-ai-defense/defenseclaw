# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""The proxy connectors fail closed on a gateway outage, and every surface says so (GAP-1957).

OpenClaw and ZeptoClaw have no hooks: their model and tool calls go through
the gateway, so while it is down they are refused whatever
``guardrail.hook_fail_mode`` holds. ``status`` (the shared fail-mode report)
and the setup summary must say closed, as ``guardrail fail-mode`` and the
reference page do; a hook connector's summary shows its effective mode.
"""

from __future__ import annotations

import click
import pytest
from click.testing import CliRunner
from defenseclaw.commands import cmd_setup
from defenseclaw.config import PerConnectorGuardrailConfig, default_config
from defenseclaw.fail_mode import connector_fail_mode_report

from tests.environment import isolated_home_env


@pytest.fixture
def cfg(tmp_path, monkeypatch):
    for key, value in isolated_home_env(tmp_path / "home").items():
        monkeypatch.setenv(key, value)
    c = default_config()
    c.data_dir = str(tmp_path / "dc")
    c.policy_dir = str(tmp_path / "dc" / "policies")
    c.guardrail.enabled = True
    c.guardrail.mode = "action"
    c.guardrail.rule_pack = "default"
    return c


@pytest.mark.parametrize("proxy", ["openclaw", "zeptoclaw"])
@pytest.mark.parametrize("saved", ["", "open", "closed"])
def test_status_reports_a_proxy_connector_closed_whatever_hook_fail_mode_says(cfg, proxy, saved):
    cfg.claw.mode = proxy
    cfg.guardrail.connector = proxy
    if saved:
        cfg.guardrail.connectors[proxy] = PerConnectorGuardrailConfig(hook_fail_mode=saved)
    report = connector_fail_mode_report(cfg, proxy, inspect_effective_policy=False)
    assert report["effective"] == "closed"
    assert report["provenance"] == "proxy-backed"
    assert report["desired"] == "closed"


@pytest.mark.parametrize("proxy", ["openclaw", "zeptoclaw"])
def test_setup_summary_shows_the_proxy_outage_behaviour(cfg, proxy):
    cfg.guardrail.hook_fail_mode = "open"
    assert cmd_setup._summary_hook_fail_mode(cfg.guardrail, proxy).startswith("closed (proxy-backed")


def test_setup_summary_shows_a_hook_connectors_effective_mode(cfg):
    cfg.claw.mode = "codex"
    cfg.guardrail.connector = "codex"
    cfg.guardrail.connectors["codex"] = PerConnectorGuardrailConfig(hook_fail_mode="closed")
    assert cmd_setup._summary_hook_fail_mode(cfg.guardrail, "codex") == cfg.guardrail.effective_hook_fail_mode("codex")
    assert cmd_setup._summary_hook_fail_mode(cfg.guardrail, "codex") == "closed"


def test_the_preflight_refusal_names_the_setup_command_the_operator_ran():
    """GAP-2110: `setup openclaw` is told to rerun `setup openclaw`, not `setup guardrail`."""
    seen = []

    @click.group(name="defenseclaw")
    def root():
        pass

    @root.group(name="setup")
    def setup():
        pass

    @setup.command(name="guardrail")
    def guardrail():
        seen.append(cmd_setup._guardrail_setup_command_name())

    @setup.command(name="openclaw")
    @click.pass_context
    def openclaw(ctx):
        ctx.invoke(guardrail)

    runner = CliRunner()
    assert runner.invoke(root, ["setup", "openclaw"]).exit_code == 0
    assert runner.invoke(root, ["setup", "guardrail"]).exit_code == 0
    assert seen == ["defenseclaw setup openclaw", "defenseclaw setup guardrail"]
