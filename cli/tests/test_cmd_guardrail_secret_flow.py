# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""``defenseclaw guardrail secret-flow`` status/enable/disable/set/explain."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from click.testing import CliRunner
from defenseclaw.commands import cmd_guardrail
from defenseclaw.config import default_config
from defenseclaw.context import AppContext

from tests.environment import isolated_home_env


@pytest.fixture
def app(tmp_path, monkeypatch):
    for key, value in isolated_home_env(tmp_path / "home").items():
        monkeypatch.setenv(key, value)
    cfg = default_config()
    cfg.data_dir = str(tmp_path / "dc")
    cfg.guardrail.enabled = True
    ctx = AppContext()
    ctx.cfg = cfg
    ctx.logger = MagicMock()
    return ctx


@pytest.fixture
def captured_writes(monkeypatch):
    """Capture config_writer.Change objects instead of writing config.yaml."""
    writes: list = []

    def fake_write(app, changes, reason, fail, *, snapshot=None):
        writes.extend(changes)
        return object()

    monkeypatch.setattr(cmd_guardrail, "_write_guardrail_config", fake_write)
    monkeypatch.setattr(cmd_guardrail, "_note_running_agent_restart", lambda: None)
    return writes


def _run(app, args):
    return CliRunner().invoke(cmd_guardrail.guardrail, args, obj=app)


def test_status_renders_defaults(app):
    res = _run(app, ["secret-flow", "status"])
    assert res.exit_code == 0, res.output
    assert "Secret flow tracking" in res.output
    assert "shadow" in res.output
    assert "credentials" in res.output


def test_status_json(app):
    res = _run(app, ["secret-flow", "status", "--json"])
    assert res.exit_code == 0, res.output
    import json

    data = json.loads(res.output)
    assert data["configured_mode"] == "shadow"
    assert data["sink_action"]["default"] == "alert"
    assert data["sink_action"]["strict"] == "block"


def test_enable_sets_shadow(app, captured_writes):
    res = _run(app, ["secret-flow", "enable"])
    assert res.exit_code == 0, res.output
    assert any(c.path == "guardrail.secret_flow.mode" and c.value == "shadow" for c in captured_writes)


def test_disable_sets_off(app, captured_writes):
    res = _run(app, ["secret-flow", "disable"])
    assert res.exit_code == 0, res.output
    assert any(c.path == "guardrail.secret_flow.mode" and c.value == "off" for c in captured_writes)


@pytest.mark.parametrize(
    "key,value,path,want",
    [
        ("mode", "on", "guardrail.secret_flow.mode", "on"),
        ("reencodings", "false", "guardrail.secret_flow.reencodings", False),
        ("credentials", "true", "guardrail.secret_flow.label_sets.credentials", True),
        ("sink-strict", "alert", "guardrail.secret_flow.sink_action.strict", "alert"),
        ("max-paths", "128", "guardrail.secret_flow.memory.max_labeled_paths", 128),
    ],
)
def test_set_valid(app, captured_writes, key, value, path, want):
    res = _run(app, ["secret-flow", "set", key, value])
    assert res.exit_code == 0, res.output
    assert any(c.path == path and c.value == want for c in captured_writes)


def test_set_allowlist_and_clear(app, captured_writes):
    res = _run(app, ["secret-flow", "set", "allowlist", "github.com, registry.npmjs.org"])
    assert res.exit_code == 0, res.output
    change = next(c for c in captured_writes if c.path == "guardrail.secret_flow.destination_allowlist")
    assert change.value == ["github.com", "registry.npmjs.org"]
    captured_writes.clear()
    res = _run(app, ["secret-flow", "set", "allowlist", ""])
    assert res.exit_code == 0, res.output
    change = next(c for c in captured_writes if c.path == "guardrail.secret_flow.destination_allowlist")
    assert change.unset


@pytest.mark.parametrize(
    "args",
    [
        ["secret-flow", "set", "mode", "bogus"],
        ["secret-flow", "set", "sink-strict", "warn"],
        ["secret-flow", "set", "reencodings", "maybe"],
        ["secret-flow", "set", "max-paths", "lots"],
        ["secret-flow", "set", "unknown-key", "x"],
    ],
)
def test_set_invalid_writes_nothing(app, captured_writes, args):
    res = _run(app, args)
    assert res.exit_code != 0
    assert captured_writes == []


def test_explain_gateway_down(app, monkeypatch):
    # No gateway: explain reports it cannot read session state and exits non-zero.
    res = _run(app, ["secret-flow", "explain", "sess-123"])
    assert res.exit_code == 1
    assert "gateway" in res.output.lower()
