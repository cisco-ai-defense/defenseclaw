"""Focused regressions for the p0 TUI and doctor UX round."""

from __future__ import annotations

from defenseclaw.tui.app import DefenseClawTUI


def test_audit_empty_state_names_hidden_routine_events(monkeypatch) -> None:
    app = object.__new__(DefenseClawTUI)
    model = type("AuditState", (), {
        "items": [object()],
        "filtered": [],
        "filtering": False,
        "filter_text": "",
        "error_message": "",
        "loading": False,
        "toolbar_state": lambda self: type("Toolbar", (), {
            "actions": (),
            "summary_label": "0 shown of 1 events",
            "filter_label": "",
            "search_prompt": "",
        })(),
        "hidden_routine_count": lambda self: 1,
    })()
    app.audit_model = model
    assert "Only routine events exist. Press l" in app._audit_body_text()


def test_tui_unavailable_explains_dumb_term(monkeypatch) -> None:
    from defenseclaw import ux

    class TTY:
        def isatty(self) -> bool:
            return True

    monkeypatch.setenv("TERM", "dumb")
    message = ux.tui_unavailable_message(stdin=TTY(), stdout=TTY())
    assert "TERM=dumb" in message
    assert "TERM=xterm-256color" in message
    assert "Windows" not in message


def test_set_one_api_key_is_fully_masked_until_reveal() -> None:
    from defenseclaw.tui.panels.setup import WizardFormField, render_wizard_value

    field = WizardFormField("Secret Value", "password", value="fake-short")
    assert render_wizard_value(field) == "********"
    assert render_wizard_value(field, reveal=True) == "fake-short"


def test_codeguard_skill_alert_names_folder_and_file() -> None:
    from datetime import datetime, timezone

    from defenseclaw.tui.panels.alerts import _v8_alert_event
    from defenseclaw.tui.services.v8_event_history import V8EventHistoryRow

    path = "/home/user/.claude/skills/tf-skill-004/SKILL.md"
    row = V8EventHistoryRow(
        id="finding-1",
        timestamp=datetime.now(timezone.utc),
        bucket="security.finding",
        event_name="finding.observed",
        source="scanner",
        severity="HIGH",
        action="scan-finding",
        actor="gateway",
        details="",
        connector="claudecode",
        redaction_profile="sensitive",
        target=path,
        payload={
            "defenseclaw.scan.scanner": "codeguard",
            "defenseclaw.finding.target_ref": "SKILL.md",
            "defenseclaw.finding.location": f"{path}:4",
        },
    )
    alert = _v8_alert_event(row)
    assert alert.target == "tf-skill-004/SKILL.md"
    assert ("File", path) in alert.facts


def test_invalid_config_banner_names_file_line_and_repair() -> None:
    from pathlib import Path

    from defenseclaw.tui.app import _config_error_summary

    detail = "Cannot read the DefenseClaw configuration config.yaml: invalid YAML at line 62, column 1"
    banner = _config_error_summary(Path("/home/user/.defenseclaw/config.yaml"), ValueError(detail))
    assert banner == "config.yaml line 62 is invalid; run defenseclaw config validate"
    assert len(banner) <= 80


def test_invalid_config_banner_uses_yaml_problem_line() -> None:
    from pathlib import Path

    from defenseclaw.tui.app import _config_error_summary

    detail = 'while parsing a block mapping\n  in "config.yaml", line 1, column 1\nexpected a value\n  in "config.yaml", line 18, column 3'
    assert _config_error_summary(Path("/home/user/.defenseclaw/config.yaml"), ValueError(detail)) == (
        "config.yaml line 18 is invalid; run defenseclaw config validate"
    )


def test_overview_keyboard_actions_reach_gateway_and_ai_discovery(tmp_path, monkeypatch) -> None:
    import sys
    from pathlib import Path
    from types import SimpleNamespace

    sys.path.insert(0, str(Path(__file__).parent))
    from fixtures import snapshot_app

    app = snapshot_app(tmp_path)
    app.active_panel = "overview"
    commands = []
    monkeypatch.setattr(app, "_submit_command_text", commands.append)
    monkeypatch.setattr(app.overview_model, "gateway_down", lambda: True)
    monkeypatch.setattr(
        app.overview_model, "ai_discovery_box",
        lambda: SimpleNamespace(status="disabled"),
    )
    assert app._handle_active_panel_key(SimpleNamespace(key="G", character="G"))
    assert app._handle_active_panel_key(SimpleNamespace(key="z", character="z"))
    assert commands == [
        "defenseclaw-gateway start",
        "defenseclaw agent discovery enable --yes",
    ]


def test_default_policy_survives_reload_and_regional_goal_starts_on_bedrock(tmp_path) -> None:
    from defenseclaw import policy_catalog
    from defenseclaw.config import default_config, load
    from defenseclaw.tui.panels.setup import SetupPanelModel, SetupWizard, wizard_goals

    cfg = default_config()
    cfg.data_dir = str(tmp_path)
    cfg.policy_dir = str(tmp_path / "policies")
    before = policy_catalog.active_policy_name(cfg.policy_dir, cfg)
    cfg.save()
    loaded = load(data_dir=tmp_path)
    assert before == "default"
    assert policy_catalog.active_policy_name(loaded.policy_dir, loaded) == before

    model = SetupPanelModel(cfg=loaded)
    goal = next(goal for goal in wizard_goals(SetupWizard.LLM, loaded) if goal.id == "regional")
    model.open_wizard_form(SetupWizard.LLM, goal=goal)
    provider = next(field for field in model.form_fields if field.flag == "--provider")
    assert provider.value == "bedrock"


def test_alert_at_editor_explains_effective_block_floor() -> None:
    from defenseclaw.tui.panels.setup import _guardrail_section

    field = next(field for field in _guardrail_section(None).fields if field.key == "guardrail.alert_at")
    assert "blocking severities always alert" in field.hint
    assert "Block At" in field.hint



def test_80_column_tab_strip_matches_documented_key_labels() -> None:
    from pathlib import Path

    from defenseclaw.tui.app import PANELS
    from defenseclaw.tui.widgets.tab_fit import fit_tab_labels, strip_width

    labels = fit_tab_labels(PANELS, "overview", {}, 66)
    assert labels["overview"] == "1 Overview"
    assert labels["alerts"] == "2"
    assert labels["policies"] == "P"
    assert strip_width(tuple(labels.values())) <= 66
    docs = (Path(__file__).parents[3] / "docs-site/content/docs/tui.mdx").read_text(encoding="utf-8")
    assert "At 80 columns, the tab strip keeps every panel's key" in docs


def test_doctor_skips_gateway_guess_after_config_validation_failure(monkeypatch) -> None:
    from types import SimpleNamespace

    from defenseclaw.commands import cmd_doctor

    result = cmd_doctor._DoctorResult()
    result.checks.append({"check_id": "doctor.config.validation", "status": "fail"})
    monkeypatch.setattr(cmd_doctor, "_http_probe", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("probed invalid config")))
    cmd_doctor._check_sidecar(SimpleNamespace(), result)
    assert any(row["status"] == "skip" and "Sidecar API" in str(row) for row in result.checks)


def test_setup_missing_agent_message_is_explicit() -> None:
    from defenseclaw.commands.cmd_setup import _connector_not_detected_message

    message = _connector_not_detected_message("Claude Code")
    assert "agent is not installed" in message
    assert "not ready" in message
