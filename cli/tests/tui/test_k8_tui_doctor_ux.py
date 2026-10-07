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
