# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""The unified decision model (decision_model:): config, upgrade, setup,
init, doctor, keys, TUI and the skill-scanner pass-through."""

from __future__ import annotations

import json
import shutil
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner
from defenseclaw import config as config_module
from defenseclaw import credentials
from defenseclaw import decision_model as dmod
from defenseclaw.config import DecisionModelConfig, decision_model_url_error

FIXTURES = Path(__file__).parent / "testdata" / "decision_model_upgrade"
REAL_102 = Path(__file__).resolve().parents[2] / "internal/cli/testdata/retired-connector-upgrade/1.0.2.yaml"
RELEASES = ("1.0.2", "1.0.3", "1.0.4", "1.0.5")


@pytest.fixture
def home(tmp_path, monkeypatch):
    data = tmp_path / ".defenseclaw"
    data.mkdir()
    monkeypatch.setenv("DEFENSECLAW_HOME", str(data))
    monkeypatch.delenv("DEFENSECLAW_CONFIG", raising=False)
    monkeypatch.delenv("DEFENSECLAW_DECISION_MODEL_KEY", raising=False)
    return data


class _SystemOne(BaseHTTPRequestHandler):
    """A System One server: a disposition choice for guardrail requests and
    a noul for the skill scanner's question."""

    seen: list[dict] = []
    p_allow = 0.97

    def do_POST(self):  # noqa: N802 - http.server API
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        type(self).seen.append({"body": body, "auth": self.headers.get("Authorization", "")})
        answers = {}
        for name, question in body["questions"].items():
            if question["type"] == "noul":
                answers[name] = {"type": "noul", "noul": 0.12}
            else:
                rest = round((1 - self.p_allow) / 2, 6)
                answers[name] = {
                    "type": "choice",
                    "choice": "allow" if self.p_allow >= 0.5 else "block",
                    "probabilities": {"allow": self.p_allow, "confirm": rest, "block": 1 - self.p_allow - rest},
                    "confidence": 0.9,
                }
        data = json.dumps({"model": body["model"], "answers": answers}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *_args):
        pass


@pytest.fixture
def system_one():
    _SystemOne.seen = []
    server = HTTPServer(("127.0.0.1", 0), _SystemOne)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}/v1/systemone"
    server.shutdown()


# --- config and upgrade ---------------------------------------------------


def test_defaults_are_off():
    dm = config_module.default_config().decision_model
    assert not dm.enabled and not dm.active()
    assert dm.effective_allow_threshold() == 0.30
    assert dm.effective_block_threshold() == 0.75
    assert dm.effective_timeout() == 1.0
    assert dm.effective_on_confident_block() == "escalate"
    assert dm.effective_api_key_env() == "DEFENSECLAW_DECISION_MODEL_KEY"


@pytest.mark.parametrize("release", RELEASES)
def test_release_config_upgrades_with_decision_model_off(home, release):
    """A config saved by 1.0.2 to 1.0.5 loads with the decision model off and
    a save leaves every other setting and no decision_model block."""
    src = FIXTURES / f"{release}.yaml"
    shutil.copy(src, home / "config.yaml")
    before = yaml.safe_load(src.read_text())
    cfg = config_module.load()
    assert not cfg.decision_model.enabled
    assert cfg.guardrail.judge.enabled and cfg.llm.model.startswith("bedrock/")
    cfg.save()
    after = yaml.safe_load((home / "config.yaml").read_text())
    assert "decision_model" not in after
    for key in ("llm", "guardrail", "config_version"):
        assert after[key] == before[key], key


def test_published_102_multi_connector_config_round_trips(home):
    # The published fixture's data_dir is the @HOME@ placeholder; point it at the test home.
    (home / "config.yaml").write_text(REAL_102.read_text().replace("@HOME@", str(home)))
    cfg = config_module.load()
    assert not cfg.decision_model.enabled
    cfg.save()
    assert "decision_model" not in yaml.safe_load((home / "config.yaml").read_text())


def test_enabled_block_round_trips(home):
    shutil.copy(FIXTURES / "1.0.5.yaml", home / "config.yaml")
    cfg = config_module.load()
    dmod.apply_settings(cfg, enabled=True, model="jev-1.13.0", base_url="https://dm.example/v1/systemone",
                        api_key_env="DM_TOKEN", allow_threshold=0.2, on_confident_block="decide")
    cfg.save()
    saved = yaml.safe_load((home / "config.yaml").read_text())["decision_model"]
    assert saved == {
        "enabled": True,
        "model": "jev-1.13.0",
        "base_url": "https://dm.example/v1/systemone",
        "api_key_env": "DM_TOKEN",
        "allow_threshold": 0.2,
        "on_confident_block": "decide",
    }
    again = config_module.load().decision_model
    assert again.active() and again.effective_block_threshold() == 0.75
    # Turning it off keeps the staged settings, minus the switch.
    dmod.apply_settings(again_cfg := config_module.load(), enabled=False)
    again_cfg.save()
    saved = yaml.safe_load((home / "config.yaml").read_text())["decision_model"]
    assert "enabled" not in saved and saved["model"] == "jev-1.13.0"


def test_hook_connectors_round_trip_and_absent_key_is_byte_identical(home):
    # A config without the key: load + save writes no hook_connectors and no decision_model block.
    shutil.copy(FIXTURES / "1.0.5.yaml", home / "config.yaml")
    cfg = config_module.load()
    assert cfg.decision_model.hook_connectors == []
    cfg.save()
    assert "decision_model" not in yaml.safe_load((home / "config.yaml").read_text())
    # With the key it round-trips, blanks stripped; clearing removes it again.
    dmod.apply_settings(cfg, enabled=True, model="m", base_url="http://127.0.0.1:8791/v1/systemone",
                        hook_connectors=["codex", " ", "claude-code"])
    cfg.save()
    saved = yaml.safe_load((home / "config.yaml").read_text())["decision_model"]
    assert saved["hook_connectors"] == ["codex", "claudecode"]
    again = config_module.load()
    assert again.decision_model.hook_connectors == ["codex", "claudecode"]
    dmod.apply_settings(again, hook_connectors=[])
    again.save()
    assert "hook_connectors" not in yaml.safe_load((home / "config.yaml").read_text())["decision_model"]


def _cascade_cfg(*, judge_on=True, judge_gate=(), dm_on=True, dm_gate=(), strategy="", tool_strategy=""):
    cfg = config_module.default_config()
    cfg.guardrail.connectors = {
        "claudecode": config_module.PerConnectorGuardrailConfig(),
        "codex": config_module.PerConnectorGuardrailConfig(),
    }
    cfg.guardrail.judge.enabled = judge_on
    cfg.guardrail.judge.hook_connectors = list(judge_gate)
    # A judge the gateway can build: a local model needs no key.
    cfg.guardrail.judge.llm.model = "ollama/llama3"
    cfg.guardrail.judge.llm.provider = "ollama"
    if strategy:
        cfg.guardrail.detection_strategy = strategy
    cfg.guardrail.detection_strategy_tool_call = tool_strategy
    cfg.decision_model = DecisionModelConfig(
        enabled=dm_on, model="m", base_url="http://127.0.0.1:8791/v1/systemone", hook_connectors=list(dm_gate)
    )
    return cfg


def test_cascade_for_the_four_cases():
    both = _cascade_cfg(judge_gate=["codex"], dm_gate=["claudecode"])
    assert dmod.cascade_for(both, "codex") == "rules -> decision model -> LLM judge"
    assert dmod.cascade_for(both, "claudecode") == "rules -> decision model"
    assert dmod.answers_alone_for(both, "claudecode") and not dmod.judge_runs_for(both, "claudecode")
    judge_only = _cascade_cfg(judge_gate=["codex"], dm_on=False)
    assert dmod.cascade_for(judge_only, "codex") == "rules -> LLM judge"
    assert dmod.cascade_for(judge_only, "claudecode") == "rules only"
    # Listed but the model is off, or not listed: rules only.
    assert dmod.cascade_for(_cascade_cfg(dm_on=False, dm_gate=["codex"]), "codex") == "rules only"
    assert dmod.cascade_for(_cascade_cfg(), "codex") == "rules only"


def test_cascade_wildcard_case_and_regex_only():
    star = _cascade_cfg(judge_on=False, dm_gate=["*"])
    assert [dmod.cascade_for(star, c) for c in ("claudecode", "codex")] == ["rules -> decision model"] * 2
    assert dmod.cascade_for(_cascade_cfg(judge_gate=["CodeX"], dm_gate=["ClaudeCode"]), "codex") == (
        "rules -> decision model -> LLM judge"
    )
    assert dmod.cascade_for(_cascade_cfg(judge_on=False, dm_gate=["ClaudeCode"]), "claudecode") == (
        "rules -> decision model"
    )
    # regex_only (tool-call override first, then the global strategy) means the judge does not run.
    for kwargs in ({"tool_strategy": "regex_only"}, {"strategy": "regex_only"}):
        cfg = _cascade_cfg(judge_gate=["*"], dm_gate=["codex"], **kwargs)
        assert not dmod.judge_runs_for(cfg, "codex")
        assert dmod.cascade_for(cfg, "codex") == "rules -> decision model"
    overridden = _cascade_cfg(judge_gate=["*"], strategy="regex_only", tool_strategy="regex_judge")
    assert dmod.judge_runs_for(overridden, "codex")


@pytest.mark.parametrize(
    ("fields", "message"),
    [
        ({"enabled": True, "model": "m"}, "needs base_url"),
        ({"enabled": True, "base_url": "https://dm.example/x"}, "needs model"),
        ({"base_url": "http://10.0.0.5:8791/x"}, "loopback"),
        ({"base_url": "https://u:p@dm.example/x"}, "credentials"),
        ({"allow_threshold": 0.8, "block_threshold": 0.5}, "lower than"),
        ({"allow_threshold": 1.5}, "between 0 and 1"),
        ({"timeout": 99}, "between 0 and 30"),
        ({"on_confident_block": "maybe"}, "escalate or decide"),
    ],
)
def test_validation(fields, message):
    assert message in DecisionModelConfig(**fields).validation_error()


def test_url_rule_matches_go():
    for ok in ("https://dm.example/v1/systemone", "http://127.0.0.1:8791/x", "http://localhost:1/x", "http://[::1]:8791/x"):
        assert decision_model_url_error(ok) == "", ok
    for bad in ("http://localhost.attacker.example/x", "http://192.168.1.5/x", "ftp://dm.example/x", "dm.example/x"):
        assert decision_model_url_error(bad), bad


# --- keys ---------------------------------------------------------------------


def test_key_is_tracked_only_while_on(home, monkeypatch):
    cfg = config_module.load()
    spec = next(s for s in credentials.CREDENTIALS if s.env_name == "DEFENSECLAW_DECISION_MODEL_KEY")
    assert spec.required(cfg) is credentials.Requirement.NOT_USED
    dmod.apply_settings(cfg, enabled=True, model="m", base_url="http://127.0.0.1:8791/v1/systemone")
    assert spec.required(cfg) is credentials.Requirement.OPTIONAL
    (home / ".env").write_text("DEFENSECLAW_DECISION_MODEL_KEY=dm-secret-value\n")
    assert cfg.decision_model.resolved_api_key(str(home)) == "dm-secret-value"
    rows = dict(dmod.summary_rows(cfg))
    assert "dm-secret-value" not in json.dumps(rows)
    assert rows["decision_model.api_key_env"].endswith("= set")


# --- setup decision-model -------------------------------------------------------


def _invoke(home, args, **kwargs):
    from defenseclaw.commands.cmd_setup import setup

    from tests.helpers import make_app_context

    (home.parent / "app").mkdir(exist_ok=True)
    app, _tmp, _db = make_app_context(str(home.parent / "app"))
    app.cfg = config_module.load()
    return CliRunner().invoke(setup, args, obj=app, **kwargs)


def test_setup_decision_model_non_interactive_and_ping(home, system_one):
    shutil.copy(FIXTURES / "1.0.5.yaml", home / "config.yaml")
    (home / ".env").write_text("DEFENSECLAW_DECISION_MODEL_KEY=dm-secret-value\n")
    result = _invoke(
        home,
        ["decision-model", "--base-url", system_one, "--model", "fake-dm", "--ping", "--non-interactive"],
        catch_exceptions=False,
    )
    assert result.exit_code == 0, result.output
    assert "Decision model reachable: answered allow" in result.output
    assert "dm-secret-value" not in result.output
    saved = yaml.safe_load((home / "config.yaml").read_text())["decision_model"]
    assert saved == {"enabled": True, "model": "fake-dm", "base_url": system_one}
    assert _SystemOne.seen[-1]["auth"] == "Bearer dm-secret-value"

    shown = _invoke(home, ["decision-model", "--show"], catch_exceptions=False)
    assert "fake-dm" in shown.output and "dm-secret-value" not in shown.output

    off = _invoke(home, ["decision-model", "--disable", "--non-interactive"], catch_exceptions=False)
    assert off.exit_code == 0, off.output
    assert not config_module.load().decision_model.enabled


def test_setup_decision_model_refuses_bad_values(home):
    shutil.copy(FIXTURES / "1.0.5.yaml", home / "config.yaml")
    result = _invoke(
        home,
        ["decision-model", "--base-url", "http://10.1.2.3:8791/x", "--model", "m", "--non-interactive"],
    )
    assert result.exit_code != 0
    assert "loopback" in result.output
    assert "decision_model" not in yaml.safe_load((home / "config.yaml").read_text())


def test_setup_decision_model_connectors_sets_clears_and_shows(home):
    shutil.copy(FIXTURES / "1.0.5.yaml", home / "config.yaml")
    base = ["decision-model", "--base-url", "http://127.0.0.1:8791/v1/systemone", "--model", "m", "--non-interactive"]
    result = _invoke(home, [*base, "--connectors", "Codex,claudecode"], catch_exceptions=False)
    assert result.exit_code == 0, result.output
    assert config_module.load().decision_model.hook_connectors == ["codex", "claudecode"]
    shown = _invoke(home, ["decision-model", "--show"], catch_exceptions=False)
    assert "decision_model.hook_connectors" in shown.output and "codex, claudecode" in shown.output
    assert _invoke(home, ["decision-model", "--connectors", "*"], catch_exceptions=False).exit_code == 0
    assert config_module.load().decision_model.hook_connectors == ["*"]
    assert _invoke(home, ["decision-model", "--connectors", ""], catch_exceptions=False).exit_code == 0
    assert config_module.load().decision_model.hook_connectors == []


def test_judge_note_names_connectors_without_a_model():
    cfg = _cascade_cfg(judge_gate=["codex"], dm_gate=[])
    note = dmod.judge_note(cfg)
    assert "claudecode" in note and "--connectors claudecode" in note and "advisory" in note
    cfg.decision_model.hook_connectors = ["claudecode"]
    assert dmod.judge_note(cfg) == ""


def test_interactive_question_defaults_to_no(home):
    shutil.copy(FIXTURES / "1.0.5.yaml", home / "config.yaml")
    result = _invoke(home, ["decision-model"], input="\n", catch_exceptions=False)
    assert dmod.INIT_QUESTION in result.output
    assert "[y/N]" in result.output
    assert not config_module.load().decision_model.enabled


# --- init ---------------------------------------------------------------------


def test_init_request_from_flags():
    from defenseclaw.commands.cmd_init import _decision_model_request

    assert _decision_model_request(None, "", "", "DEFENSECLAW_DECISION_MODEL_KEY") is None
    assert _decision_model_request(False, "", "", "X") == {"enabled": False}
    req = _decision_model_request(None, "http://127.0.0.1:8791/v1/systemone", "m", "DEFENSECLAW_DECISION_MODEL_KEY")
    assert req["enabled"] and req["model"] == "m"
    import click

    with pytest.raises(click.UsageError, match="both"):
        _decision_model_request(True, "http://127.0.0.1:8791/v1/systemone", "", "X")
    with pytest.raises(click.UsageError, match="loopback"):
        _decision_model_request(None, "http://10.0.0.1/x", "m", "X")


def _wizard(action, *, judge=(), answer=None):
    """Run the first-run wizard with the prompts stubbed; return the
    decision-model prompt mock."""
    from unittest.mock import patch

    from defenseclaw.commands import cmd_init

    answer = {} if answer is None else answer
    with patch.object(cmd_init, "_prompt_connector_selection", return_value=["claudecode"]), \
            patch.object(cmd_init.terminal_checkbox, "restore_line_prompt_mode"), \
            patch.object(cmd_init.click, "prompt", return_value="local"), \
            patch.object(cmd_init.click, "confirm", return_value=True), \
            patch.object(cmd_init, "_prompt_action_connectors", return_value=list(action)), \
            patch.object(cmd_init, "_current_action_connectors", return_value=[]), \
            patch.object(cmd_init, "_supported_action_connectors", return_value=list(action)), \
            patch.object(cmd_init, "_prompt_action_policy", return_value=(None, None, None)), \
            patch.object(cmd_init, "_current_judge_connectors", return_value=[]), \
            patch.object(cmd_init, "_prompt_first_run_judge_connectors", return_value=list(judge)), \
            patch.object(cmd_init, "_prompt_first_run_decision_model", return_value={"enabled": True}) as dm_prompt:
        cmd_init._prompt_first_run(
            connector=None, profile=None, scanner_mode="local", with_judge=False, fail_mode=None,
            human_approval=None, hilt_min_severity=None, start_gateway=True, verify=True,
            rescan_agents=False, data_dir=None, decision_model_answer=answer,
        )
    return dm_prompt, answer


def test_init_wizard_asks_whenever_a_connector_is_in_action_mode():
    # Judge off, one action connector: asked, and the answer is kept.
    dm_prompt, answer = _wizard(["claudecode"], judge=[])
    dm_prompt.assert_called_once()
    assert answer["request"] == {"enabled": True}
    # No action connector: not asked.
    dm_prompt, answer = _wizard([], judge=[])
    dm_prompt.assert_not_called()
    assert answer.get("request") is None
    # A flag already answered it: never asked again, judge or not.
    dm_prompt, _ = _wizard(["claudecode"], judge=["claudecode"], answer={"asked": True})
    dm_prompt.assert_not_called()


def test_init_decision_model_connectors_default_and_flag(home, system_one):
    from defenseclaw.bootstrap import FirstRunReport
    from defenseclaw.commands.cmd_init import _apply_first_run_decision_model, _decision_model_request

    shutil.copy(FIXTURES / "1.0.5.yaml", home / "config.yaml")
    req = _decision_model_request(None, system_one, "fake-dm", "DEFENSECLAW_DECISION_MODEL_KEY")
    assert req["connectors"] is None  # default: the connectors init puts in action mode
    report = FirstRunReport.__new__(FirstRunReport)
    report.setup = []
    _apply_first_run_decision_model(report, req, str(home), ["claudecode", "codex"])
    assert config_module.load().decision_model.hook_connectors == ["claudecode", "codex"]
    flagged = _decision_model_request(None, system_one, "fake-dm", "X", "Codex, claudecode")
    assert flagged["connectors"] == ["codex", "claudecode"]
    _apply_first_run_decision_model(report, flagged, str(home), ["hermes"])
    assert config_module.load().decision_model.hook_connectors == ["codex", "claudecode"]
    # --yes alone and the connectors flag without an endpoint do not turn it on by themselves.
    assert _decision_model_request(None, "", "", "X") is None
    import click

    with pytest.raises(click.UsageError, match="both"):
        _decision_model_request(None, "", "", "X", "codex")


def test_init_step_saves_and_reports(home, system_one):
    from defenseclaw.bootstrap import FirstRunReport
    from defenseclaw.commands.cmd_init import _apply_first_run_decision_model

    shutil.copy(FIXTURES / "1.0.5.yaml", home / "config.yaml")
    report = FirstRunReport.__new__(FirstRunReport)
    report.setup = []
    _apply_first_run_decision_model(
        report, {"enabled": True, "base_url": system_one, "model": "fake-dm", "api_key_env": "DEFENSECLAW_DECISION_MODEL_KEY", "token": "tok-value"}, str(home)
    )
    step = report.setup[-1]
    assert step.name == "Decision Model" and step.status == "pass", step
    assert "tok-value" not in step.detail
    assert "DEFENSECLAW_DECISION_MODEL_KEY=tok-value" in (home / ".env").read_text()
    assert config_module.load().decision_model.active()


def test_setup_decision_model_unreachable_warning_is_a_whole_sentence(home):
    shutil.copy(FIXTURES / "1.0.5.yaml", home / "config.yaml")
    result = _invoke(
        home,
        ["decision-model", "--base-url", "http://127.0.0.1:1/v1/systemone", "--model", "m", "--ping", "--non-interactive"],
        catch_exceptions=False,
    )
    assert "tool calls are decided without it until it is reachable" in result.output


def test_init_step_warns_when_unreachable(home):
    from defenseclaw.bootstrap import FirstRunReport
    from defenseclaw.commands.cmd_init import _apply_first_run_decision_model

    shutil.copy(FIXTURES / "1.0.5.yaml", home / "config.yaml")
    report = FirstRunReport.__new__(FirstRunReport)
    report.setup = []
    _apply_first_run_decision_model(
        report, {"enabled": True, "base_url": "http://127.0.0.1:1/v1/systemone", "model": "m", "api_key_env": "", "token": ""}, str(home)
    )
    assert report.setup[-1].status == "warn"
    assert report.setup[-1].detail.endswith("tool calls are decided without it until it is reachable")


# --- doctor ---------------------------------------------------------------------


def test_doctor_row(home, system_one):
    from defenseclaw.commands import cmd_doctor

    shutil.copy(FIXTURES / "1.0.5.yaml", home / "config.yaml")
    cfg = config_module.load()
    r = cmd_doctor._DoctorResult()
    cmd_doctor._check_decision_model(cfg, r)
    assert r.checks == []  # silent while off
    dmod.apply_settings(cfg, enabled=True, model="fake-dm", base_url=system_one)
    cmd_doctor._check_decision_model(cfg, r)
    assert r.checks[-1]["label"] == "Decision model" and r.checks[-1]["status"] == "pass"
    dmod.apply_settings(cfg, base_url="http://127.0.0.1:1/v1/systemone")
    cmd_doctor._check_decision_model(cfg, r)
    assert r.checks[-1]["status"] == "warn"


def test_doctor_row_names_the_cascade_per_connector(system_one):
    from defenseclaw.commands import cmd_doctor

    cfg = _cascade_cfg(judge_gate=["codex"], dm_gate=["claudecode"])
    cfg.decision_model.base_url = system_one
    r = cmd_doctor._DoctorResult()
    cmd_doctor._check_decision_model(cfg, r)
    row = r.checks[-1]
    assert row["status"] == "pass"
    assert "claudecode: rules -> decision model; codex: rules -> decision model -> LLM judge" in row["detail"]
    # Reachable but answering no connector's tool calls: a warning that says how to add one.
    cfg.decision_model.hook_connectors = []
    cfg.guardrail.judge.hook_connectors = []
    cmd_doctor._check_decision_model(cfg, r)
    assert r.checks[-1]["status"] == "warn" and "--connectors" in r.checks[-1]["detail"]


# --- skill scanner pass-through ------------------------------------------------


def test_skill_scan_records_advisory_score(home, system_one, tmp_path, monkeypatch):
    pytest.importorskip("skill_scanner")
    from skill_scanner.core.analyzers.llm_analyzer import LLMAnalyzer

    from defenseclaw.scanner.skill import SkillScannerWrapper

    # A scan installs the judge-answer compatibility patch on the scanner's
    # class; hand the class back as found so later tests see the pinned scanner.
    monkeypatch.setattr(LLMAnalyzer, "_repair_optional_taxonomy", LLMAnalyzer._repair_optional_taxonomy)

    shutil.copy(FIXTURES / "1.0.5.yaml", home / "config.yaml")
    (home / ".env").write_text("DEFENSECLAW_DECISION_MODEL_KEY=dm-secret-value\n")
    cfg = config_module.load()
    dmod.apply_settings(cfg, enabled=True, model="fake-dm", base_url=system_one)
    skill = tmp_path / "clean-skill"
    skill.mkdir()
    (skill / "SKILL.md").write_text(
        "---\nname: clean-test-skill\ndescription: Echo the text you are given.\nlicense: Apache-2.0\n---\n\n"
        "# Clean test skill\n\nReturn the provided text unchanged.\n",
        encoding="utf-8",
    )
    sc = cfg.scanners.skill_scanner
    sc.use_llm = False
    scanner = SkillScannerWrapper(sc, decision_model=dmod.skill_scanner_options(cfg))
    result = scanner.scan(str(skill))
    record = result.settings["decision_model"]
    assert record["status"] == "ok" and record["probability"] == 0.12 and record["advisory_only"] is True
    assert result.is_clean()  # advisory only: no finding, no verdict change
    request = _SystemOne.seen[-1]
    assert request["auth"] == "Bearer dm-secret-value"
    assert request["body"]["model"] == "fake-dm"


def test_skill_scan_without_decision_model_has_no_record():
    pytest.importorskip("skill_scanner")
    assert dmod.skill_scanner_options(config_module.default_config()) == ({}, {})


# --- TUI ------------------------------------------------------------------------


def test_tui_section_and_float_fields():
    from defenseclaw.tui.panels import setup as setup_panel
    from defenseclaw.tui.panels.setup_catalog import section_group
    from defenseclaw.tui.services import setup_state

    cfg = config_module.default_config()
    names = [s.name for s in setup_panel.build_config_sections(cfg)] if hasattr(setup_panel, "build_config_sections") else []
    if names:
        assert "Decision Model" in names
    assert section_group("Decision Model") == "Protection"
    setup_state._apply_typed_field(cfg, "decision_model.allow_threshold", "0.25")
    assert cfg.decision_model.allow_threshold == 0.25
    setup_state._apply_typed_field(cfg, "decision_model.enabled", "true")
    assert cfg.decision_model.enabled is True
    field = setup_state.ConfigField(label="Allow At", key="decision_model.allow_threshold", kind="string", value="2", original="")
    assert setup_state.validate_config_field(field).severity == "error"
    url = setup_state.ConfigField(label="Endpoint URL", key="decision_model.base_url", kind="string", value="http://10.0.0.1/x", original="")
    assert "loopback" in setup_state.validate_config_field(url).message


def test_cascade_matches_the_gateway_when_the_judge_cannot_start(tmp_path, monkeypatch):
    """A judge that is on and listed but has no model (or no key) is not built
    by the gateway, so the connector gets cascade 2 there, not cascade 3."""
    from defenseclaw import decision_model as dmod
    from defenseclaw.config import Config, DecisionModelConfig

    monkeypatch.delenv("DEFENSECLAW_LLM_KEY", raising=False)
    cfg = Config()
    cfg.data_dir = str(tmp_path)
    cfg.decision_model = DecisionModelConfig(
        enabled=True, model="m", base_url="http://127.0.0.1:8791/v1/systemone", hook_connectors=["claude-code", " "]
    )
    cfg.guardrail.judge.enabled = True
    cfg.guardrail.judge.hook_connectors = ["claudecode"]
    cfg.guardrail.detection_strategy = "regex_judge"
    cfg.guardrail.judge.llm.model = ""
    cfg.llm.model = ""
    assert not dmod.judge_runs_for(cfg, "claudecode")
    assert dmod.cascade_for(cfg, "claudecode") == "rules -> decision model"
    cfg.guardrail.judge.llm.model = "anthropic/claude-haiku-4-5"
    cfg.guardrail.judge.llm.provider = "anthropic"
    assert not dmod.judge_runs_for(cfg, "claudecode")  # no key: the gateway does not build the judge
    monkeypatch.setenv("DEFENSECLAW_LLM_KEY", "test-key")
    assert dmod.judge_runs_for(cfg, "claudecode")
    assert dmod.cascade_for(cfg, "claudecode") == "rules -> decision model -> LLM judge"
    # A blank entry matches nothing, as in the gateway.
    assert not dmod.answers_alone_for(cfg, "")
