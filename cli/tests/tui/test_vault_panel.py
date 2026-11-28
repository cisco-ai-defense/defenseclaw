# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Vault panel: model rows, keys and intents (values only on stdin), an 80x24
render, and the add and remove journeys."""

from __future__ import annotations

import json

import pytest
from defenseclaw.tui.executor import CommandEvent
from defenseclaw.tui.services.vault_state import (
    PROMPT_ADD_HOST,
    PROMPT_ADD_NAME,
    PROMPT_ADD_VALUE,
    PROMPT_BIND,
    PROMPT_REPLACE,
    VaultPanelModel,
    vault_help_rows,
    vault_keys_hint_for,
)
from fixtures import screen_text, snapshot_app

# Built at run time: no credential-shaped literal in the tree.
VALUE = "sk" + "_live_" + "Tt5Uu6" * 5

LIST = {
    "path": "/home/dev/.defenseclaw/vault/vault.json",
    "entries": [
        {"name": "GITHUB_TOKEN", "host": "api.github.com", "port": 443, "target": "api.github.com",
         "status": "exposed", "source": "captured", "kind": "github-token",
         "captured_from": "claudecode tool call in sandbox demo", "created_at": "2026-11-22T10:00:00Z",
         "updated_at": "2026-11-22T10:00:00Z"},
        {"name": "GOOGLE_API_KEY", "target": "", "status": "needs_host", "source": "captured",
         "kind": "google-api-key", "created_at": "2026-11-22T10:00:00Z", "updated_at": "2026-11-22T10:00:00Z"},
        {"name": "STRIPE_API_KEY", "host": "api.stripe.com", "port": 443, "target": "api.stripe.com",
         "status": "ready", "source": "manual", "created_at": "2026-11-22T10:00:00Z",
         "updated_at": "2026-11-22T10:00:00Z", "last_used_at": "2026-11-22T11:00:00Z",
         "last_used_by": "demo", "use_count": 2},
    ],
}


def loaded() -> VaultPanelModel:
    model = VaultPanelModel()
    model.apply_list_json(json.dumps(LIST))
    return model


def test_rows_summary_and_never_a_value() -> None:
    model = loaded()
    assert [r.name for r in model.rows()] == ["GITHUB_TOKEN", "GOOGLE_API_KEY", "STRIPE_API_KEY"]
    assert model.data_table_rows(compact=True)[1] == ("GOOGLE_API_KEY", "—", "needs a host")
    assert model.data_table_rows(compact=False)[0][2] == "exposed: rotate"
    assert all(len(r) == 3 for r in model.data_table_rows(compact=True))
    line = model.summary_line()
    assert "3 secrets" in line and "1 needs a host" in line and "1 exposed: rotate" in line and "never shown" in line
    # A value field from any producer is dropped before the model keeps it.
    leaky = {"entries": [{"name": "X", "value": VALUE, "status": "ready", "target": "a.example.com"}]}
    model.apply_list_json(json.dumps(leaky))
    assert VALUE not in json.dumps(model.entries)


def test_summary_names_the_storage() -> None:
    model = VaultPanelModel()
    model.apply_list_json(json.dumps(dict(LIST, storage="sealed (macOS Keychain)", sealed=True)))
    assert model.summary_line().endswith("never shown · sealed (macOS Keychain)")
    model.apply_list_json(json.dumps(dict(LIST, storage="file (owner-only, not encrypted)")))
    assert "file (owner-only, not encrypted)" in model.summary_line()
    model.apply_list_json(json.dumps(LIST))
    assert model.summary_line().endswith("values are never shown")


def test_bad_json_is_an_error_not_a_crash() -> None:
    model = VaultPanelModel()
    model.apply_list_json("not json")
    assert model.loaded and model.error and model.summary_line().startswith("Vault: ")


def test_add_flow_sends_the_value_on_stdin_only() -> None:
    model = loaded()
    assert model.handle_key("a").prompt == PROMPT_ADD_NAME
    assert model.answer_prompt(PROMPT_ADD_NAME, "bad name").prompt == PROMPT_ADD_NAME
    assert model.answer_prompt(PROMPT_ADD_NAME, "PAY_KEY").prompt == PROMPT_ADD_HOST
    assert model.answer_prompt(PROMPT_ADD_HOST, "https://api.example.com/x").prompt == PROMPT_ADD_HOST
    assert model.answer_prompt(PROMPT_ADD_HOST, "api.example.com").prompt == PROMPT_ADD_VALUE
    title, _hint, password = model.prompt_spec(PROMPT_ADD_VALUE)
    assert password and "PAY_KEY" in title
    action = model.answer_prompt(PROMPT_ADD_VALUE, VALUE)
    intent = action.intent
    assert action.kind == "intent" and intent is not None
    assert intent.args == ("sandbox", "vault", "add", "--host", "api.example.com", "--value-stdin", "PAY_KEY")
    assert intent.secret_stdin == VALUE + "\n"
    assert VALUE not in " ".join(intent.argv) and VALUE not in intent.label and VALUE not in intent.hint


def test_row_keys_build_the_cli_commands() -> None:
    model = loaded()
    model.cursor = 2
    assert model.handle_key("v").prompt == PROMPT_REPLACE
    replace = model.answer_prompt(PROMPT_REPLACE, VALUE).intent
    assert replace.args == ("sandbox", "vault", "replace", "--value-stdin", "STRIPE_API_KEY") and replace.secret_stdin
    assert model.handle_key("e").prompt == PROMPT_BIND
    bind = model.answer_prompt(PROMPT_BIND, "api.stripe.com").intent
    assert bind.args == ("sandbox", "vault", "bind", "--host", "api.stripe.com", "STRIPE_API_KEY")
    remove = model.handle_key("d").intent
    assert remove.risk == "destructive" and remove.args == ("sandbox", "vault", "remove", "--yes", "STRIPE_API_KEY")
    show = model.handle_key("enter").intent
    assert show.risk == "read-only" and show.args == ("sandbox", "vault", "show", "STRIPE_API_KEY")
    empty = VaultPanelModel()
    empty.apply_list_json(json.dumps({"entries": []}))
    assert empty.handle_key("d").kind == "none" and "empty" in empty.handle_key("d").hint


def test_hint_and_help_name_every_key() -> None:
    assert "a add" in vault_keys_hint_for(False) and "d delete" not in vault_keys_hint_for(False)
    hint = vault_keys_hint_for(True)
    assert "\\" not in hint
    for key, label in (("a", "add"), ("v", "replace value"), ("e", "set host"), ("n", "rename"), ("d", "delete"),
                       ("enter", "details"), ("r", "refresh")):
        assert f"{key} {label}" in hint
    assert ("K", "open this panel") in vault_help_rows()


@pytest.fixture
def sandboxes_supported(monkeypatch):
    import defenseclaw.platform_support as platform_support

    monkeypatch.setattr(platform_support, "openshell_sandboxes_supported", lambda: True)


async def test_vault_panel_renders_at_80x24(tmp_path, sandboxes_supported) -> None:
    app = snapshot_app(tmp_path)
    app.vault_model, app._vault_model_injected = loaded(), True
    async with app.run_test(size=(80, 24)) as pilot:
        app.action_switch_panel("vault")
        await pilot.pause()
        text = screen_text(app)
        assert "GITHUB_TOKEN" in text and "STRIPE_API_KEY" in text and "needs a host" in text
        assert "never shown" in text


async def test_add_journey_pipes_the_value(tmp_path, sandboxes_supported) -> None:
    app = snapshot_app(tmp_path)
    app.vault_model, app._vault_model_injected = loaded(), True
    calls: list[tuple[tuple[str, ...], str | None]] = []

    async def fake_run(binary, args, *, stdin_input=None, env_overrides=None):
        calls.append(((binary, *args), stdin_input))
        yield CommandEvent("start", " ".join((binary, *args)))
        yield CommandEvent("done", exit_code=0, duration=0.01)

    app.executor.run = fake_run
    async with app.run_test(size=(80, 24)) as pilot:
        app.action_switch_panel("vault")
        await pilot.pause()
        await pilot.press("a")
        await pilot.pause()
        for text in ("PAY_KEY", "api.example.com", VALUE):
            await pilot.press(*text)
            await pilot.press("enter")
            await pilot.pause()
        assert VALUE not in screen_text(app)
        await pilot.press("enter")  # run from the command preview
        await pilot.pause()
        await app.workers.wait_for_complete()
    adds = [(argv, stdin) for argv, stdin in calls if argv[1:4] == ("sandbox", "vault", "add")]
    assert adds == [(("defenseclaw", "sandbox", "vault", "add", "--host", "api.example.com", "--value-stdin", "PAY_KEY"),
                     VALUE + "\n")]


async def test_capital_k_opens_the_vault_tab(tmp_path, sandboxes_supported) -> None:
    """Pressing K from another panel opens Vault (it used to fold to k, a vim move)."""
    app = snapshot_app(tmp_path)
    app.vault_model, app._vault_model_injected = loaded(), True
    async with app.run_test(size=(80, 24)) as pilot:
        for start in ("overview", "alerts", "skills", "sandboxes", "policies", "setup"):
            app.action_switch_panel(start)
            await pilot.pause()
            await pilot.press("K")
            await pilot.pause()
            assert app.active_panel == "vault", start


async def test_j_moves_the_highlight_with_the_detail_line(tmp_path, sandboxes_supported) -> None:
    """The detail line and the table highlight name the same secret after j/k."""
    from textual.widgets import DataTable

    app = snapshot_app(tmp_path)
    app.vault_model, app._vault_model_injected = loaded(), True
    async with app.run_test(size=(80, 24)) as pilot:
        app.action_switch_panel("vault")
        await pilot.pause()
        await pilot.press("j")
        await pilot.pause()
        table = app.query_one("#panel-table", DataTable)
        assert app.vault_model.cursor == 1 and table.cursor_row == 1
        assert "GOOGLE_API_KEY" in screen_text(app)
        await pilot.press("k")
        await pilot.pause()
        assert app.vault_model.cursor == 0 and table.cursor_row == 0
