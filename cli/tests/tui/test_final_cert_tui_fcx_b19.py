# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Tab strip names, config editor keys and Setup goal form hints (final-cert batch 19)."""

from __future__ import annotations

import sys
from pathlib import Path

from click.testing import CliRunner
from textual.geometry import Size

sys.path.insert(0, str(Path(__file__).parent))

from defenseclaw.tui.app import PANELS  # noqa: E402
from defenseclaw.tui.panels import setup_keys  # noqa: E402
from defenseclaw.tui.panels.setup import (  # noqa: E402
    SetupWizard,
    _llm_wizard_fields_for,
    wizard_form_defs,
)
from defenseclaw.tui.widgets import tab_fit  # noqa: E402
from fixtures import snapshot_app  # noqa: E402
from test_setup_keys import _app, _enter_view  # noqa: E402

_PLURAL = {"Skills", "MCPs", "Plugins", "Tools", "Logs", "Policies"}


def _name(label: str) -> str:
    return label.split(" ", 1)[1].rstrip("⁰¹²³⁴⁵⁶⁷⁸⁹⁺") if " " in label else ""


def test_tab_strip_keeps_short_names_until_every_tab_is_named_and_never_shortens_one(tmp_path, monkeypatch) -> None:
    # GAP-2517: "4 MCPs" and "T Tools" sat beside bare "3" and "5" at 130-155
    # columns, and "3 Skills" (170) became "3 Skill" again when the brand came
    # back at 175.
    monkeypatch.setattr(tab_fit, "_PLAIN_BADGE", False)
    unread = {"alerts": 88, "audit": 10}
    app = snapshot_app(tmp_path)
    app._panel_unread_count = lambda name: unread.get(name, 0)  # type: ignore[method-assign]
    previous: dict[str, str] = {}
    for width in range(130, 231):
        monkeypatch.setattr(type(app), "size", property(lambda _self, width=width: Size(width, 45)))
        labels = tab_fit.fit_tab_labels(PANELS, "overview", unread, app._tab_strip_width())  # noqa: SLF001
        names = {name: _name(label) for name, label in labels.items()}
        if not all(names.values()):
            assert not _PLURAL & set(names.values()), (width, labels)
        for name, text in names.items():
            assert len(text) >= len(previous.get(name, "")), (width, name, previous[name], text)
        previous = names
        if app._header_title():  # noqa: SLF001
            assert all(labels[name].startswith(f"{key} {title}") for name, key, title in PANELS), (width, labels)


def test_config_editor_letters_never_type_into_the_selected_field(tmp_path, monkeypatch) -> None:
    # GAP-2520: q opened the Timeout editor with "30q"; c then q gave "30cq".
    app = _app(tmp_path, monkeypatch)
    _enter_view(app, "config", setup_keys.SETUP_KEYMAPS["config"][0])
    model = app.setup_model
    section, line = next(
        (i, j)
        for i, section in enumerate(model.sections)
        for j, field in enumerate(section.fields)
        if field.label == "Timeout (s)"
    )
    model.select_section(section)
    model.active_line = line
    assert not app._handle_setup_key("q").handled  # noqa: SLF001 - q closes the drawer
    assert not app._handle_setup_key("T", character="T").handled  # noqa: SLF001 - T opens Tools
    typed = app._handle_setup_key("c", character="c")  # noqa: SLF001
    assert typed.handled and not typed.open_field_editor
    assert "Enter" in typed.hint
    assert app._handle_setup_key("enter").open_field_editor == "config"  # noqa: SLF001


def test_scanner_and_llm_goal_forms_explain_every_field() -> None:
    # GAP-2522: "Select scan policy.", "Toggle lenient mode.", "Sets --llm-model.".
    generic = ("Toggle ", "Select ", "Sets ", "Value for ")
    forms = [
        wizard_form_defs(SetupWizard.SKILL_SCANNER),
        wizard_form_defs(SetupWizard.MCP_SCANNER),
        *(
            _llm_wizard_fields_for(provider=provider, role="unified", overrides={"--bedrock-auth-mode": mode})
            for provider, mode in (("anthropic", ""), ("bedrock", "iam_credentials"), ("bedrock", "profile"))
        ),
        _llm_wizard_fields_for(provider="vertex_ai", role="unified", overrides={}),
        _llm_wizard_fields_for(provider="azure", role="unified", overrides={}),
    ]
    for fields in forms:
        for field in fields:
            if field.kind != "section":
                assert field.hint and not field.hint.startswith(generic), (field.label, field.hint)
    hints = {field.label: field.hint for field in wizard_form_defs(SetupWizard.SKILL_SCANNER)}
    assert all(word in hints["Scan Policy"] for word in ("strict", "balanced", "permissive"))
    role = next(field for field in forms[2] if field.label == "Role")
    assert "unified" in role.hint and "judge" in role.hint


def test_mcp_scanner_remote_api_goal_saves_the_ai_defense_settings() -> None:
    # GAP-2529: the "Use a remote scan API" goal ran flags the CLI lacked.
    from defenseclaw.commands.cmd_setup import setup
    from tests.helpers import cleanup_app, make_app_context

    flags = {field.flag for field in wizard_form_defs(SetupWizard.MCP_SCANNER)}
    assert {"--api-endpoint", "--api-key-env", "--api-timeout-ms"} <= flags
    app, tmp_dir, db_path = make_app_context()
    try:
        argv = ["mcp-scanner", "--non-interactive", "--no-verify", "--api-endpoint", "https://aid.example"]
        argv += ["--api-key-env", "AID_KEY", "--api-timeout-ms", "5000"]
        result = CliRunner().invoke(setup, argv, obj=app, catch_exceptions=False)
        assert result.exit_code == 0, result.output
        aid = app.cfg.cisco_ai_defense
        assert (aid.endpoint, aid.api_key_env, aid.timeout_ms) == ("https://aid.example", "AID_KEY", 5000)
    finally:
        cleanup_app(app, db_path, tmp_dir)
