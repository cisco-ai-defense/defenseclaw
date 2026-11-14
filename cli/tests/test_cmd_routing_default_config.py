# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Every read-only routing command survives a default, partial or managed
config and a gateway that answers lists as null (GAP-0561)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import click
import pytest
from click.testing import CliRunner
from defenseclaw.commands import cmd_routing

CONFIGS = {
    "empty": "config_version: 9\n",
    "routing_off": "config_version: 9\nrouting:\n  enabled: false\n",
    "routing_on_no_models": "config_version: 9\nrouting:\n  enabled: true\n",
    "empty_admin": "config_version: 9\nrouting:\n  enabled: false\n  admin:\n    rules: []\n    budgets: []\n",
}

# What a gateway with routing off answers: lists marshalled from nil slices.
NULL_EFFECTIVE = {"enabled": False, "admin": False, "budgets": None, "recent": None}
ANSWERS = {
    "null_lists": NULL_EFFECTIVE,
    "admin_null_lists": {**NULL_EFFECTIVE, "admin": True, "rules": None, "allowed_aliases": None},
    "empty_object": {},
    "not_an_object": ["x"],
    "stray_entries": {"budgets": [None, 3, "x"], "recent": ["x", None], "rules": [1], "rows": [7]},
}

READS = [
    ["status"],
    ["status", "--json"],
    ["models", "list"],
    ["models", "list", "--json"],
    ["rules", "list"],
    ["rules", "list", "--json"],
    ["budgets", "list"],
    ["budgets", "list", "--json"],
    ["pricing", "show"],
    ["pricing", "show", "--json"],
    ["test", "write a parser"],
    ["test", "write a parser", "--json"],
    ["explain", "req-1"],
    ["explain", "req-1", "--json"],
    ["usage"],
    ["usage", "--json"],
]


def invoke(args: list[str]):
    with patch("defenseclaw.gateway.local_policy_digest", return_value=None):
        return CliRunner().invoke(cmd_routing.routing_cmd, args, catch_exceptions=True)


def assert_no_crash(result, args) -> None:
    # A plain refusal (ClickException, usage) is fine; a Python exception is not.
    assert result.exception is None or isinstance(result.exception, SystemExit), (args, repr(result.exception))
    assert "Traceback" not in result.output, (args, result.output)


@pytest.fixture
def home(tmp_path: Path, monkeypatch) -> Path:
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path))
    monkeypatch.setattr(cmd_routing, "_health_routing", lambda app: {"state": "running"})
    return tmp_path


@pytest.mark.parametrize("config", sorted(CONFIGS))
@pytest.mark.parametrize("answer", sorted(ANSWERS))
def test_reads_survive_default_and_partial_configs(home: Path, monkeypatch, config: str, answer: str) -> None:
    (home / "config.yaml").write_text(CONFIGS[config])
    monkeypatch.setattr(cmd_routing, "_ask_gateway", lambda app, method, path, **kw: (ANSWERS[answer], ""))
    for args in READS:
        assert_no_crash(invoke(args), args)


@pytest.mark.parametrize("config", sorted(CONFIGS))
def test_reads_survive_a_stopped_gateway(home: Path, monkeypatch, config: str) -> None:
    (home / "config.yaml").write_text(CONFIGS[config])
    monkeypatch.setattr(cmd_routing, "_ask_gateway", lambda app, method, path, **kw: (None, "the gateway is not running"))
    for args in READS:
        assert_no_crash(invoke(args), args)


def test_missing_config_file_reads_as_defaults(home: Path, monkeypatch) -> None:
    monkeypatch.setattr(cmd_routing, "_ask_gateway", lambda app, method, path, **kw: (NULL_EFFECTIVE, ""))
    for args in READS[:10]:
        assert_no_crash(invoke(args), args)


def test_status_on_a_default_config_says_routing_is_off(home: Path, monkeypatch) -> None:
    (home / "config.yaml").write_text(CONFIGS["routing_off"])
    monkeypatch.setattr(cmd_routing, "_ask_gateway", lambda app, method, path, **kw: (NULL_EFFECTIVE, ""))
    result = invoke(["status"])
    assert result.exit_code == 0, result.output
    assert "Routing:    off" in result.output and "Models:     0" in result.output
    data = json.loads(invoke(["status", "--json"]).output)
    assert data["enabled"] is False and data["models"] == [] and data["warnings"] == []


def test_doctor_rows_on_default_configs(home: Path) -> None:
    for body in CONFIGS.values():
        (home / "config.yaml").write_text(body)
        assert cmd_routing.doctor_rows() == []


def managed(monkeypatch, answer) -> None:
    """A standard account on a managed device: config.yaml unreadable, the
    gateway answers the own view of the caller."""
    monkeypatch.setattr(cmd_routing.config_writer, "machine_managed_standalone", lambda: True)

    def unreadable():
        raise click.ClickException("config.yaml on this managed device is readable only by administrators")

    monkeypatch.setattr(cmd_routing, "_document", unreadable)
    monkeypatch.setattr(cmd_routing, "_ask_gateway", lambda app, method, path, **kw: (answer, ""))


@pytest.mark.parametrize("answer", sorted(ANSWERS))
def test_managed_user_reads_survive_null_answers(home: Path, monkeypatch, answer: str) -> None:
    managed(monkeypatch, ANSWERS[answer])
    for args in (["status"], ["status", "--json"], ["rules", "list"], ["rules", "list", "--json"], ["budgets", "list"],
                 ["budgets", "list", "--json"], ["test", "x"], ["explain", "r"], ["usage"]):
        assert_no_crash(invoke(args), args)


def test_managed_user_budget_row_without_a_subject(home: Path, monkeypatch) -> None:
    # A user sees budget rows with no subject (only an administrator gets it).
    managed(monkeypatch, {"budgets": [{"id": "daily", "scope": "user", "period": "day", "limit_usd": 20.0,
                                       "on_exceed": "warn", "spent_usd": 1.5}]})
    result = invoke(["budgets", "list"])
    assert result.exit_code == 0 and "1.50/20.0 USD per day" in result.output, result.output


def test_routing_test_prints_the_decision_when_the_gateway_sends_null_lists(home: Path, monkeypatch) -> None:
    # GAP-0564 / GAP-0566: warnings, simulated and rule_ids arrive as null.
    (home / "config.yaml").write_text(CONFIGS["routing_off"])
    answer = {"category": "", "confidence": -1, "candidate_alias": "", "outcome": "fallback", "warnings": None,
              "simulated": None, "rule_ids": None, "reasons": None}
    monkeypatch.setattr(cmd_routing, "_ask_gateway", lambda app, method, path, **kw: (answer, ""))
    result = invoke(["test", "hello"])
    assert result.exit_code == 0 and "Result:     fallback" in result.output, result.output
    explained = invoke(["explain", "req-1"])
    assert explained.exit_code == 0 and "Outcome:    fallback" in explained.output, explained.output
    budgets = invoke(["budgets", "list"])
    assert budgets.exit_code == 0 and "No budgets" in budgets.output, budgets.output


def setup_args(*extra: str) -> list[str]:
    return ["setup", "--yes", "--model", "fast=openai/gpt-4.1-mini", "--model", "deep=anthropic/claude-sonnet-5-5", *extra]


def test_setup_without_routes_says_no_route_rules_exist(home: Path, monkeypatch) -> None:
    import yaml

    (home / "config.yaml").write_text(CONFIGS["empty"])
    monkeypatch.setattr(cmd_routing, "_ask_gateway", lambda app, method, path, **kw: (None, "the gateway is not running"))
    result = invoke(setup_args())
    assert result.exit_code == 0, result.output
    assert "No route rules yet: every request goes to fast" in result.output and "--route coding=deep" in result.output
    written = yaml.safe_load((home / "config.yaml").read_text())["routing"]
    assert written["enabled"] is True and written["classifier"] == "rules" and "decisions" not in written


def test_setup_route_writes_working_keyword_rules(home: Path, monkeypatch) -> None:
    import yaml

    (home / "config.yaml").write_text(CONFIGS["empty"])
    monkeypatch.setattr(cmd_routing, "_ask_gateway", lambda app, method, path, **kw: (None, "the gateway is not running"))
    result = invoke(setup_args("--route", "coding=deep", "--route", "summarize=fast"))
    assert result.exit_code == 0 and "No route rules yet" not in result.output, result.output
    written = yaml.safe_load((home / "config.yaml").read_text())["routing"]
    decisions = {d["name"]: d for d in written["decisions"]}
    assert decisions["coding"]["model_refs"] == ["deep"] and decisions["coding"]["priority"] == 80
    assert decisions["coding"]["conditions"] == [{"type": "keyword", "name": "coding-keywords"}]
    assert {k["name"] for k in written["signals"]["keywords"]} == {"coding-keywords", "summarize-keywords"}
    # Running it again re-points the decision and keeps one copy of each rule.
    assert invoke(setup_args("--route", "coding=fast")).exit_code == 0
    again = yaml.safe_load((home / "config.yaml").read_text())["routing"]
    assert [d["model_refs"] for d in again["decisions"] if d["name"] == "coding"] == [["fast"]]
    assert len(again["signals"]["keywords"]) == 2 and len(again["decisions"]) == 2


@pytest.mark.parametrize("spec", ["coding=nope", "poetry=deep", "coding", "=deep"])
def test_setup_route_refuses_unknown_category_or_alias(home: Path, spec: str) -> None:
    (home / "config.yaml").write_text(CONFIGS["empty"])
    before = (home / "config.yaml").read_bytes()
    result = invoke(setup_args("--route", spec))
    assert result.exit_code == 2 and "use CATEGORY=ALIAS" in result.output, result.output
    assert (home / "config.yaml").read_bytes() == before


def _doctor_routing(expect: int = 1, **routing) -> dict:
    from types import SimpleNamespace

    from defenseclaw.commands import cmd_doctor

    result = cmd_doctor._DoctorResult()
    cfg = SimpleNamespace(routing=SimpleNamespace(enabled=True, remote={}, port=8799, models=[{"name": "fast"}], **routing))
    cmd_doctor._check_semantic_routing(cfg, result, live_health=None)
    assert len(result.checks) == expect  # systemone adds its reachability row
    return result.checks[0]


def test_doctor_rules_classifier_is_in_process_and_flags_missing_rules(monkeypatch) -> None:
    from defenseclaw.commands import cmd_doctor

    monkeypatch.setattr(cmd_doctor, "_http_probe", pytest.fail)
    flagged = _doctor_routing(classifier="rules", default_alias="fast", decisions=[])
    assert flagged["status"] == "warn" and "managed Docker" not in flagged["detail"]
    assert "no route rules" in flagged["detail"] and "every request goes to fast" in flagged["detail"]
    ok = _doctor_routing(classifier="rules", default_alias="fast", decisions=[{"name": "coding"}])
    assert ok["status"] == "pass" and "rules classifier, in process" in ok["detail"] and "default fast" in ok["detail"]
    monkeypatch.setattr(cmd_doctor, "_http_probe", lambda url, **kw: (405, ""))
    one = _doctor_routing(classifier="systemone", default_alias="fast", decisions=[], expect=2)
    assert one["status"] == "pass" and "systemone classifier" in one["detail"]


def test_usage_reads_the_gateway_usage_route(home: Path, monkeypatch) -> None:
    # GAP-0569: the gateway serves GET /usage, not /api/v1/usage (404).
    (home / "config.yaml").write_text(CONFIGS["routing_off"])
    seen: list[str] = []

    def ask(app, method, path, **kw):
        seen.append(path)
        return {"enabled": False, "hint": "set observability.tokenomics.enabled", "rows": []}, ""

    monkeypatch.setattr(cmd_routing, "_ask_gateway", ask)
    result = invoke(["usage"])
    assert result.exit_code == 0 and seen == ["/usage"], (seen, result.output)
    assert "no recorded calls: set observability.tokenomics.enabled" in result.output


def test_routing_client_allows_the_usage_route() -> None:
    from defenseclaw.gateway import OrchestratorClient

    client = OrchestratorClient.__new__(OrchestratorClient)
    with pytest.raises(ValueError):
        client.routing_request("GET", "/api/v1/usage")


@pytest.mark.parametrize("args", [
    ["models", "add", "x", "--provider", "opnai", "--model", "m"],
    ["setup", "--yes", "--model", "x=opnai/m"],
])
def test_unknown_provider_is_refused_with_the_valid_names(home: Path, args: list[str]) -> None:
    # GAP-0600: an unknown provider was written and failed on the first call.
    (home / "config.yaml").write_text(CONFIGS["empty"])
    before = (home / "config.yaml").read_bytes()
    result = invoke(args)
    assert result.exit_code == 2 and "unknown provider" in result.output, result.output
    assert "anthropic" in result.output and "openai" in result.output and "bedrock" in result.output
    assert (home / "config.yaml").read_bytes() == before


def test_known_providers_are_written(home: Path, monkeypatch) -> None:
    (home / "config.yaml").write_text(CONFIGS["empty"])
    monkeypatch.setattr(cmd_routing, "_ask_gateway", lambda app, method, path, **kw: (None, "the gateway is not running"))
    assert invoke(["models", "add", "a", "--provider", "ollama", "--model", "llama3"]).exit_code == 0
    assert invoke(["setup", "--yes", "--model", "b=bedrock/m"]).exit_code == 0


def _doctor_systemone(monkeypatch, code: int, **routing):
    from types import SimpleNamespace

    from defenseclaw.commands import cmd_doctor

    monkeypatch.setattr(cmd_doctor, "_http_probe", lambda url, **kw: (code, ""))
    result = cmd_doctor._DoctorResult()
    cfg = SimpleNamespace(
        routing=SimpleNamespace(enabled=True, remote={}, port=0, models=[{"name": "fast"}], classifier="systemone",
                                default_alias="fast", decisions=[], **routing),
        decision_model=SimpleNamespace(base_url="https://so.example.test:8443/v1/systemone?key=SECRET"),
    )
    cmd_doctor._check_semantic_routing(cfg, result, live_health=None)
    return {c["label"]: c for c in result.checks}


def test_doctor_checks_the_systemone_endpoint_for_real(monkeypatch) -> None:
    # GAP-0591: an unreachable endpoint was reported healthy.
    up = _doctor_systemone(monkeypatch, 405, systemone={})
    assert up["System One classifier"]["status"] == "pass" and "so.example.test:8443" in up["System One classifier"]["detail"]
    assert "SECRET" not in up["System One classifier"]["detail"] and "key=" not in up["System One classifier"]["detail"]
    down = _doctor_systemone(monkeypatch, 0, systemone={}, on_classifier_error="original")
    row = down["System One classifier"]
    assert row["status"] == "fail" and "not reachable" in row["detail"] and "setup decision-model --ping" in row["remediation"]
    none = _doctor_systemone(monkeypatch, 405, systemone={"use_decision_model": False})
    assert none["System One classifier"]["status"] == "warn" and "no endpoint" in none["System One classifier"]["detail"]


def test_usage_rows_with_null_numbers_print(home: Path, monkeypatch) -> None:
    (home / "config.yaml").write_text(CONFIGS["routing_off"])
    answer = {"enabled": True, "scope": "own", "rows": [{"key": "fast", "calls": None, "input_tokens": None, "output_tokens": None}]}
    monkeypatch.setattr(cmd_routing, "_ask_gateway", lambda app, method, path, **kw: (answer, ""))
    result = invoke(["usage"])
    assert result.exit_code == 0 and "fast" in result.output and "Traceback" not in result.output, result.output


def test_provider_names_follow_the_gateway_registry(home: Path, monkeypatch) -> None:
    (home / "config.yaml").write_text(CONFIGS["empty"])
    monkeypatch.setattr(cmd_routing, "_ask_gateway", lambda app, method, path, **kw: (None, "the gateway is not running"))
    for provider in ("openai-compatible", "OpenAI", "amazon-bedrock", "vertex"):
        result = invoke(["models", "add", provider.replace("-", "").lower()[:10], "--provider", provider, "--model", "m"])
        assert result.exit_code == 0, (provider, result.output)
