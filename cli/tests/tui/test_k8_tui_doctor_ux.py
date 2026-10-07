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
