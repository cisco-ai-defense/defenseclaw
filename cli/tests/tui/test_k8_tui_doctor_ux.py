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
