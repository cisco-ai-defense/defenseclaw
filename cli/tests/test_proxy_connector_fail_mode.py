# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""The proxy connectors and a gateway outage: every surface says what the gateway does (GAP-1957, GAP-0824).

OpenClaw and ZeptoClaw have no hooks. ZeptoClaw model requests are refused
while the gateway is down. OpenClaw follows the outage mode the gateway
resolves: open on the default and permissive packs, closed on strict and for
an explicit closed. ``status`` (the shared fail-mode report) and the setup
summary say so, as ``guardrail fail-mode`` and the reference page do; a hook
connector's summary shows its effective mode.
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


@pytest.mark.parametrize("saved", ["", "open", "closed"])
def test_status_reports_zeptoclaw_closed_whatever_hook_fail_mode_says(cfg, saved):
    cfg.claw.mode = "zeptoclaw"
    cfg.guardrail.connector = "zeptoclaw"
    if saved:
        cfg.guardrail.connectors["zeptoclaw"] = PerConnectorGuardrailConfig(hook_fail_mode=saved)
    report = connector_fail_mode_report(cfg, "zeptoclaw", inspect_effective_policy=False)
    assert report["effective"] == "closed"
    assert report["provenance"] == "proxy-backed"
    assert report["desired"] == "closed"
    assert report["note"] == "no hooks: blocked while the gateway is down"


@pytest.mark.parametrize(
    ("pack", "saved", "want"),
    [
        ("default", "", "open"),
        ("permissive", "", "open"),
        ("default", "open", "open"),
        ("default", "closed", "closed"),
        ("strict", "", "closed"),
        # A strict policy stays closed over an older saved open (Go EffectiveHookOutageFailModeForConnector).
        ("strict", "open", "closed"),
    ],
)
def test_status_reports_the_openclaw_outage_mode_the_gateway_resolves(cfg, pack, saved, want):
    # GAP-0824: the default pack continues with a warning; only strict, managed or an explicit closed block.
    cfg.claw.mode = "openclaw"
    cfg.guardrail.connector = "openclaw"
    cfg.guardrail.rule_pack = pack
    if saved:
        cfg.guardrail.connectors["openclaw"] = PerConnectorGuardrailConfig(hook_fail_mode=saved)
    report = connector_fail_mode_report(cfg, "openclaw", inspect_effective_policy=False)
    assert report["effective"] == want
    assert report["desired"] == want
    assert report["provenance"] == "proxy-backed"
    assert ("continue with a warning" in report["note"]) is (want == "open")
    assert cmd_setup._guardrail_summary_hook_fail_mode(cfg, "openclaw").startswith(f"{want} (proxy-backed")


def test_a_managed_openclaw_stays_closed_over_a_saved_open(cfg):
    cfg.claw.mode = "openclaw"
    cfg.guardrail.connector = "openclaw"
    cfg.deployment_mode = "managed_enterprise"
    cfg.enterprise_profile = "standalone"
    report = connector_fail_mode_report(cfg, "openclaw", inspect_effective_policy=False)
    assert report["effective"] == "closed"


@pytest.mark.parametrize("proxy", ["openclaw", "zeptoclaw"])
def test_setup_summary_shows_the_proxy_outage_behaviour(cfg, proxy):
    cfg.claw.mode = proxy
    cfg.guardrail.connector = proxy
    cfg.guardrail.hook_fail_mode = "closed"
    assert cmd_setup._guardrail_summary_hook_fail_mode(cfg, proxy).startswith("closed (proxy-backed")


def test_setup_summary_shows_a_hook_connectors_effective_mode(cfg):
    cfg.claw.mode = "codex"
    cfg.guardrail.connector = "codex"
    cfg.guardrail.connectors["codex"] = PerConnectorGuardrailConfig(hook_fail_mode="closed")
    assert cmd_setup._guardrail_summary_hook_fail_mode(cfg, "codex") == "closed"


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
