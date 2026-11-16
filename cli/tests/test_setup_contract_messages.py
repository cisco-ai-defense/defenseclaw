# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Setup and approval previews describe the integration actually installed."""

from unittest.mock import MagicMock

import pytest
from defenseclaw.commands import cmd_guardrail, cmd_setup
from defenseclaw.config import PerConnectorGuardrailConfig, default_config
from defenseclaw.context import AppContext


def test_hook_setup_help_recommends_closed():
    for command in cmd_setup.setup.commands.values():
        options = [p for p in command.params if p.name == "fail_mode"]
        for option in options:
            assert "closed" in option.help and "default" in option.help
            assert "(recommended); 'closed'" not in option.help


@pytest.mark.parametrize("connector", ["codex", "cursor", "hermes", "opencode", "devin", "zeptoclaw"])
def test_approval_preview_does_not_promise_an_unimplemented_prompt(connector, monkeypatch, capsys):
    app = AppContext()
    app.cfg = default_config()
    app.cfg.guardrail.connectors = {connector: PerConnectorGuardrailConfig()}
    app.cfg.guardrail.enabled = False
    app.logger = MagicMock()
    monkeypatch.setattr(app.cfg, "save", lambda: None)
    cmd_guardrail._set_connector_hilt(app, connector, "on", "HIGH", restart=False, yes=True)
    output = capsys.readouterr().out
    assert "will prompt for approval" not in output
    assert "raw_action=confirm" in output and "alert" in output.lower()


@pytest.mark.parametrize("connector", ["claudecode", "codex", "cursor"])
def test_native_summary_describes_disabling_the_integration(connector, monkeypatch, capsys):
    monkeypatch.setattr(cmd_setup, "_print_connector_next_steps", lambda *a, **kw: None)
    monkeypatch.setattr(cmd_setup, "print_redaction_status_hint", lambda *a: None)
    monkeypatch.setattr(cmd_setup, "_runtime_skipped_setup_peers", lambda: set())
    cmd_setup._print_observability_summary(connector)
    output = capsys.readouterr().out
    assert "restore direct LLM access" not in output
    assert "defenseclaw guardrail disable" in output
