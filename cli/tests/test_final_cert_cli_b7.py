# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Lean regressions for the asset policy / registry fix-only batch 7
(GAP-2119, GAP-2122, GAP-2123)."""

from __future__ import annotations

import os
from types import SimpleNamespace

import pytest
import yaml
from click.testing import CliRunner
from defenseclaw.commands import cmd_registry
from defenseclaw.config import AssetPolicyRule
from defenseclaw.enforce.admission import evaluate_asset_policy

from tests.helpers import cleanup_app, make_app_context


@pytest.fixture
def registry_app(monkeypatch):
    app, tmp_dir, db_path = make_app_context()
    app.cfg.config_path = os.path.join(tmp_dir, "config.yaml")
    app.cfg.save()
    monkeypatch.setattr(cmd_registry, "sys", SimpleNamespace(stdin=SimpleNamespace(isatty=lambda: True)))
    yield app
    cleanup_app(app, db_path, tmp_dir)


def _require(app, *args: str):
    return CliRunner().invoke(cmd_registry.registry, ["require", "--type", "mcp", "--enabled", *args], obj=app)


def test_require_says_asset_policy_is_off_and_enforce_turns_it_on(registry_app) -> None:
    # GAP-2119
    registry_app.cfg.asset_policy.enabled = False
    registry_app.cfg.asset_policy.mode = "observe"
    result = _require(registry_app)
    assert result.exit_code == 0, result.output
    assert "Asset policy is off (asset_policy.enabled=false): nothing is blocked" in result.output
    assert "would be blocked at admission" in result.output and "will be blocked" not in result.output

    result = _require(registry_app, "--enforce")
    assert result.exit_code == 0, result.output
    assert "Asset policy is off" not in result.output and "will be blocked at admission" in result.output
    assert registry_app.cfg.asset_policy.enabled is True and registry_app.cfg.asset_policy.mode == "action"
    with open(registry_app.cfg.config_path, encoding="utf-8") as fh:
        saved = yaml.safe_load(fh)["asset_policy"]
    assert saved["enabled"] is True and saved["mode"] == "action"

    result = CliRunner().invoke(
        cmd_registry.registry, ["require", "--type", "mcp", "--disabled", "--enforce"], obj=registry_app,
    )
    assert result.exit_code == 2 and "--enforce needs --enabled" in result.output


@pytest.mark.parametrize(("transport", "verdict"), [("", "allowed"), ("http", "allowed"), ("sse", "blocked")])
def test_registry_streamable_http_rule_admits_http_url_server(registry_app, transport, verdict) -> None:
    # GAP-2122
    ap = registry_app.cfg.asset_policy
    ap.enabled, ap.mode = True, "action"
    ap.mcp.registry_required = True
    ap.mcp.registry = [AssetPolicyRule(
        name="deepwiki", url="https://mcp.example.test/mcp", transport="streamable-http", reason="registry:corp",
    )]
    decision = evaluate_asset_policy(
        ap, target_type="mcp", name="deepwiki", connector="hermes",
        url="https://mcp.example.test/mcp", transport=transport,
    )
    assert decision.verdict == verdict, decision


def test_registry_wizard_skips_auth_token_for_file_source(registry_app) -> None:
    # GAP-2123
    answers = "local-mcp\nfile\nmcp\n~/registry.yaml\nn\n"
    result = CliRunner().invoke(cmd_registry.registry, ["wizard"], input=answers, obj=registry_app)
    assert result.exit_code == 0, result.output
    assert "auth token" not in result.output

    answers = "remote-mcp\nhttp_yaml\nmcp\nhttps://registry.example.test/r.yaml\nn\nn\n"
    result = CliRunner().invoke(cmd_registry.registry, ["wizard"], input=answers, obj=registry_app)
    assert result.exit_code == 0, result.output
    assert "Use an auth token" in result.output
