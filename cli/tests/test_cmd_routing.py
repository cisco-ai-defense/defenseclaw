# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""defenseclaw routing: config.yaml writes through the shared writer, managed refusal, gateway reads."""

from __future__ import annotations

import datetime as dt
import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml
from click.testing import CliRunner
from defenseclaw.commands import cmd_routing
from defenseclaw.gateway import RoutingAPIError

BODY = """config_version: 9
routing:
  enabled: false
  models:
    - name: fast
      provider: openai
      model: gpt-4.1-mini
    - name: local
      provider: vllm
      model: qwen-local
"""


@pytest.fixture
def home(tmp_path: Path, monkeypatch) -> Path:
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path))
    (tmp_path / "config.yaml").write_text(BODY)
    monkeypatch.setattr(cmd_routing, "_health_routing", lambda app: {"state": "running"})
    monkeypatch.setattr(cmd_routing, "_ask_gateway", lambda app, method, path, **kw: (None, "the gateway is not running"))
    return tmp_path


def run(*args: str):
    with patch("defenseclaw.gateway.local_policy_digest", return_value=None):
        return CliRunner().invoke(cmd_routing.routing_cmd, list(args), catch_exceptions=False)


def written(home: Path) -> dict:
    return yaml.safe_load((home / "config.yaml").read_text())


def test_models_add_list_and_duplicate(home: Path) -> None:
    result = run("models", "add", "coder", "--provider", "anthropic", "--model", "claude-sonnet-5-5", "--api", "messages")
    assert result.exit_code == 0, result.output
    models = written(home)["routing"]["models"]
    assert models[-1] == {"name": "coder", "provider": "anthropic", "model": "claude-sonnet-5-5", "apis": ["messages"]}
    listed = json.loads(run("models", "list", "--json").output)
    assert [m["name"] for m in listed] == ["fast", "local", "coder"]
    again = run("models", "add", "coder", "--provider", "anthropic", "--model", "x")
    assert again.exit_code != 0 and "already has coder" in again.output


def test_rules_add_move_remove(home: Path) -> None:
    assert run("rules", "add", "local-high", "--severity-at-least", "high", "--allow", "local", "--default", "local").exit_code == 0
    assert run("rules", "add", "ctr", "--groups", "DCLAB\\contractors", "--deny", "--message", "No cloud.", "--at", "1").exit_code == 0
    rules = written(home)["routing"]["admin"]["rules"]
    assert [r["id"] for r in rules] == ["ctr", "local-high"]
    assert rules[0] == {"id": "ctr", "match": {"groups": ["DCLAB\\contractors"]}, "action": "deny", "message": "No cloud."}
    assert rules[1]["match"] == {"severity_at_least": "HIGH"}
    assert run("rules", "move", "ctr", "--to", "2").exit_code == 0
    assert [r["id"] for r in written(home)["routing"]["admin"]["rules"]] == ["local-high", "ctr"]
    listed = json.loads(run("rules", "list", "--json").output)
    assert any("deny is reported, not enforced" in note for note in listed["lint"])
    assert run("rules", "remove", "ctr").exit_code == 0
    assert run("rules", "remove", "local-high").exit_code == 0
    assert "admin" not in written(home)["routing"] or "rules" not in written(home)["routing"]["admin"]


def test_rules_add_refuses_contradictions_before_writing(home: Path) -> None:
    before = (home / "config.yaml").read_bytes()
    deny_allow = run("rules", "add", "x", "--groups", "g", "--deny", "--allow", "fast")
    assert deny_allow.exit_code == 2 and "--deny refuses" in deny_allow.output
    no_match = run("rules", "add", "x", "--allow", "fast")
    assert no_match.exit_code == 2 and "name what the rule matches" in no_match.output
    assert (home / "config.yaml").read_bytes() == before


def test_validation_refusal_leaves_the_file(home: Path) -> None:
    before = (home / "config.yaml").read_bytes()
    bad = run("budgets", "add", "b", "--scope", "user", "--subject", "*", "--period", "day", "--limit-usd", "5", "--on-exceed", "block")
    assert bad.exit_code != 0 and "config.yaml was not changed" in bad.output
    assert (home / "config.yaml").read_bytes() == before


def test_budgets_add_and_list(home: Path, monkeypatch) -> None:
    ok = run("budgets", "add", "daily", "--scope", "user", "--subject", "*", "--period", "day", "--limit-usd", "20", "--on-exceed", "downgrade:local")
    assert ok.exit_code == 0, ok.output
    assert written(home)["routing"]["admin"]["budgets"] == [
        {"id": "daily", "scope": "user", "subject": "*", "period": "day", "limit_usd": 20.0, "on_exceed": "downgrade:local"}
    ]
    live = {"budgets": [{"id": "daily", "spent_usd": 12.5, "resets_at": "2026-11-19T00:00:00Z", "exceeded": False}]}
    monkeypatch.setattr(cmd_routing, "_ask_gateway", lambda app, method, path, **kw: (live, ""))
    out = run("budgets", "list")
    assert "12.50/20.0 USD per day" in out.output and "resets 2026-11-19" in out.output


def test_managed_device_refuses_writes_with_the_reason(home: Path, monkeypatch) -> None:
    monkeypatch.setattr(cmd_routing.config_writer, "machine_managed_standalone", lambda: True)
    monkeypatch.setattr("defenseclaw.enforce.asset_lists.audit_managed_config_refusal", lambda *a: None)
    before = (home / "config.yaml").read_bytes()
    for args in (["rules", "add", "r", "--groups", "g", "--allow", "fast"], ["models", "set-default", "fast"],
                 ["budgets", "remove", "x"], ["enable"], ["pricing", "set", "openai/gpt", "--input", "1", "--output", "2"],
                 ["enable", "--connector", "claudecode"], ["disable", "--connector", "claudecode"]):
        result = CliRunner().invoke(cmd_routing.routing_cmd, args)
        assert result.exit_code == 3, (args, result.output)
        assert "set by your administrator" in result.output
    assert (home / "config.yaml").read_bytes() == before


def test_locked_default_alias_is_refused(home: Path) -> None:
    (home / "config.yaml").write_text(BODY + "  admin:\n    locked: [default_alias]\n")
    result = run("models", "set-default", "fast")
    assert result.exit_code != 0 and "locked by routing.admin.locked" in result.output


def test_pricing_set_bumps_the_version(home: Path) -> None:
    assert run("pricing", "set", "openai/gpt-4.1-mini", "--input", "0.4", "--output", "1.6").exit_code in (0, 1)
    assert cmd_routing._next_version("", dt.date(2026, 11, 12)) == "2026-11-12.1"
    assert cmd_routing._next_version("2026-11-12.3", dt.date(2026, 11, 12)) == "2026-11-12.4"
    assert cmd_routing._next_version("2026-11-11.3", dt.date(2026, 11, 12)) == "2026-11-12.1"


def test_status_json_reports_budget_and_off_warnings(home: Path, monkeypatch) -> None:
    (home / "config.yaml").write_text(BODY + "  admin:\n    rules:\n      - {id: r, match: {connectors: [codex]}, allow: [fast]}\n")
    effective = {"allowed_aliases": ["fast"], "recent": [], "budgets": [
        {"id": "daily", "period": "day", "on_exceed": "warn", "resets_at": "2026-11-19T00:00:00Z", "exceeded": True}]}
    monkeypatch.setattr(cmd_routing, "_ask_gateway", lambda app, method, path, **kw: (effective, ""))
    data = json.loads(run("status", "--json").output)
    assert data["enabled"] is False and data["classifier"] == "vllm_sr" and data["rules"] == 1
    assert [m["alias"] for m in data["models"]] == ["fast", "local"]
    assert any("routing is off" in w for w in data["warnings"])
    assert any("budget daily is used up" in w for w in data["warnings"])


def test_test_and_explain_show_the_gateway_answer(home: Path, monkeypatch) -> None:
    answer = {"category": "code", "confidence": 1.0, "candidate_alias": "coder", "filtered_by": "admin", "rule_ids": ["local-high"],
              "outcome": "applied", "selected_alias": "local", "selected_model": "qwen-local", "estimated_cost_usd": 0.0012}
    monkeypatch.setattr(cmd_routing, "_ask_gateway", lambda app, method, path, **kw: (answer, ""))
    out = run("test", "write a parser").output
    assert "Candidate:  coder" in out and "-> local (qwen-local)" in out and "Est. cost:  0.0012 USD" in out
    monkeypatch.setattr(cmd_routing, "_ask_gateway",
                        lambda app, method, path, **kw: (None, RoutingAPIError(404, "").plain()))
    missing = CliRunner().invoke(cmd_routing.routing_cmd, ["explain", "req-1"])
    assert missing.exit_code == 1 and "not in its recent decisions" in missing.output
    assert CliRunner().invoke(cmd_routing.routing_cmd, ["test", "x" * 9000]).exit_code == 2


def test_enable_needs_a_model(home: Path) -> None:
    (home / "config.yaml").write_text("config_version: 9\n")
    result = run("enable")
    assert result.exit_code != 0 and "needs at least one model" in result.output


def test_doctor_rows(home: Path) -> None:
    assert cmd_routing.doctor_rows() == []
    (home / "config.yaml").write_text(BODY + "  admin:\n    rules:\n      - {id: c, match: {groups: [g]}, action: deny}\n")
    rows = cmd_routing.doctor_rows()
    assert ("warn", "routing is off: no rule or budget is applied until defenseclaw routing enable") in rows
    assert any("deny is reported, not enforced" in detail for _status, detail in rows)


def test_writes_keep_values_a_masked_read_would_hide(home: Path) -> None:
    (home / "config.yaml").write_text(BODY.replace("      model: qwen-local\n", "      model: qwen-local\n      base_url: http://localhost:8000/v1\n"))
    assert run("models", "add", "coder", "--provider", "anthropic", "--model", "claude-sonnet-5-5").exit_code == 0
    local = [m for m in written(home)["routing"]["models"] if m["name"] == "local"][0]
    assert local["base_url"] == "http://localhost:8000/v1"


def test_setup_adds_models_without_prompting(home: Path, monkeypatch) -> None:
    (home / "config.yaml").write_text("config_version: 9\n")
    result = run("setup", "--yes", "--classifier", "rules", "--model", "fast=openai/gpt-4.1-mini")
    assert result.exit_code == 0, result.output
    routing = written(home)["routing"]
    assert routing["models"] == [{"name": "fast", "provider": "openai", "model": "gpt-4.1-mini"}]
    assert routing["enabled"] is True and routing["default_alias"] == "fast"
    assert run("setup", "--yes", "--model", "bad").exit_code == 2


@pytest.mark.skipif(sys.platform == "win32", reason="chmod 0 does not take read access away on Windows")
def test_managed_unreadable_config_says_so(home: Path, monkeypatch) -> None:
    monkeypatch.setattr(cmd_routing.config_writer, "machine_managed_standalone", lambda: True)
    monkeypatch.setattr("defenseclaw.enforce.asset_lists.audit_managed_config_refusal", lambda *a: None)
    (home / "config.yaml").chmod(0)
    try:
        listed = CliRunner().invoke(cmd_routing.routing_cmd, ["models", "list"])
        assert listed.exit_code == 1 and "readable only by administrators" in listed.output
        assert CliRunner().invoke(cmd_routing.routing_cmd, ["enable"]).exit_code == 3
    finally:
        (home / "config.yaml").chmod(0o600)
