# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Routing on with tokenomics off says so and gives the command (rel-1-0-10 GAP-0932).

Tokenomics stays off by default: only the note appears, nothing is switched on.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
import yaml
from click.testing import CliRunner
from defenseclaw import routing_tokenomics
from defenseclaw.commands import cmd_doctor, cmd_routing

BODY = """config_version: 9
routing:
  enabled: false
  classifier: rules
  models:
    - name: fast
      provider: openai
      model: gpt-4.1-mini
"""
COMMAND = "defenseclaw setup tokenomics --enable"


@pytest.fixture
def home(tmp_path: Path, monkeypatch) -> Path:
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path))
    (tmp_path / "config.yaml").write_text(BODY)
    monkeypatch.setattr(cmd_routing, "_health_routing", lambda app: {"state": "running"})
    monkeypatch.setattr(
        cmd_routing, "_ask_gateway", lambda app, method, path, **kw: (None, "the gateway is not running")
    )
    monkeypatch.setattr(cmd_routing, "_docker_problem", lambda: "")
    return tmp_path


def run(*args: str):
    with patch("defenseclaw.gateway.local_policy_digest", return_value=None):
        return CliRunner().invoke(cmd_routing.routing_cmd, list(args), catch_exceptions=False)


def test_enable_says_tokenomics_is_off_and_does_not_turn_it_on(home: Path) -> None:
    result = run("enable")
    assert result.exit_code == 0, result.output
    assert COMMAND in result.output and "Spend per user" in result.output
    assert "tokenomics" not in (yaml.safe_load((home / "config.yaml").read_text()).get("observability") or {})


def test_setup_says_tokenomics_is_off(home: Path) -> None:
    result = run("setup", "--yes", "--classifier", "rules")
    assert result.exit_code == 0, result.output
    assert COMMAND in result.output


def test_a_budget_says_it_needs_tokenomics(home: Path) -> None:
    result = run(
        "budgets",
        "add",
        "b1",
        "--scope",
        "connector",
        "--subject",
        "claudecode",
        "--period",
        "day",
        "--limit-usd",
        "5",
        "--on-exceed",
        "warn",
    )
    assert result.exit_code == 0, result.output
    assert COMMAND in result.output and "budgets cannot count spend" in result.output


def test_no_note_when_tokenomics_is_on(home: Path) -> None:
    (home / "config.yaml").write_text(
        BODY + "observability:\n  tokenomics:\n    enabled: true\n    local_store:\n      enabled: true\n"
    )
    result = run("enable")
    assert result.exit_code == 0, result.output
    assert COMMAND not in result.output


def test_note_helpers() -> None:
    assert routing_tokenomics.note_from_doc({"routing": {"enabled": False}}) is None
    note = routing_tokenomics.note_from_doc({"routing": {"enabled": True}})
    assert note is not None and note.panels and not note.budgets and COMMAND in note.text
    tok_on = {"observability": {"tokenomics": {"enabled": True, "local_store": {"enabled": True}}}}
    assert routing_tokenomics.note_from_doc({"routing": {"enabled": True}, **tok_on}) is None
    # Budgets with tokenomics on but the local store off cannot count spend.
    store_off = {"observability": {"tokenomics": {"enabled": True}}}
    budgets = {"routing": {"enabled": True, "admin": {"budgets": [{"id": "b"}]}}, **store_off}
    note = routing_tokenomics.note_from_doc(budgets)
    assert (
        note is not None
        and note.budgets
        and not note.panels
        and "local usage store" in note.text
        and COMMAND in note.text
    )
    tok = SimpleNamespace(enabled=False, local_store_enabled=False)
    on = SimpleNamespace(
        routing=SimpleNamespace(enabled=True, admin=None), observability=SimpleNamespace(tokenomics=tok)
    )
    assert COMMAND in routing_tokenomics.note_from_cfg(on).text
    tok.enabled = True
    assert routing_tokenomics.note_from_cfg(on) is None
    off = SimpleNamespace(
        routing=SimpleNamespace(enabled=False, admin=None), observability=SimpleNamespace(tokenomics=tok)
    )
    assert routing_tokenomics.note_from_cfg(off) is None


def _doctor_rows(cfg) -> list[tuple]:
    seen: list[tuple] = []
    orig = cmd_doctor._emit
    cmd_doctor._emit = lambda status, label, detail="", **kw: seen.append(
        (status, label, detail, kw.get("remediation"))
    )
    try:
        cmd_doctor._check_routing_tokenomics(cfg, r=None)
    finally:
        cmd_doctor._emit = orig
    return seen


def test_doctor_row_gives_the_command() -> None:
    tok = SimpleNamespace(enabled=False, local_store_enabled=False)
    cfg = SimpleNamespace(
        routing=SimpleNamespace(enabled=True, admin=None), observability=SimpleNamespace(tokenomics=tok)
    )
    rows = _doctor_rows(cfg)
    assert len(rows) == 1 and rows[0][0] == "info" and rows[0][3] == COMMAND
    cfg.routing.admin = {"budgets": [{"id": "b"}]}
    assert _doctor_rows(cfg)[0][0] == "warn"
    cfg.observability.tokenomics.enabled = True
    assert _doctor_rows(cfg)[0][0] == "warn"  # budgets, local store still off
    cfg.observability.tokenomics.local_store_enabled = True
    assert _doctor_rows(cfg) == []


def test_doctor_names_an_allowed_model_without_a_credential_for_the_administrator() -> None:
    routing = SimpleNamespace(
        enabled=True,
        route_only={
            "connectors": ["codex"],
            "upstreams": {"codex": {"api": "responses", "base_url": "https://api.openai.com"}},
        },
        models=[
            {"name": "fixture-bedrock", "provider": "bedrock", "model": "m"},
            {"name": "fixture-keyed", "provider": "bedrock", "model": "m", "credential": "fixture-key"},
            {"name": "fixture-same", "provider": "openai", "model": "m"},
        ],
        admin={"rules": [{"id": "fixture-rule", "allow": ["fixture-bedrock", "fixture-keyed", "fixture-same"]}]},
    )
    cfg = SimpleNamespace(deployment_mode="managed_enterprise", routing=routing)
    assert cmd_doctor.routing_allowed_aliases_without_key(cfg) == [("fixture-rule", "fixture-bedrock")]
    seen: list[tuple] = []
    orig = cmd_doctor._emit
    cmd_doctor._emit = lambda status, label, detail="", **kw: seen.append((status, label, detail))
    try:
        cmd_doctor._check_routing_allowed_alias_credential(cfg, r=None)
    finally:
        cmd_doctor._emit = orig
    assert len(seen) == 1 and seen[0][0] == "warn" and "fixture-bedrock (rule fixture-rule)" in seen[0][2]
    assert cmd_doctor.routing_allowed_aliases_without_key(SimpleNamespace(deployment_mode="", routing=routing)) == []
