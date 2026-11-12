# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Routing panel: model keys, rows and intents, plus an 80x24 render and the delete journey."""

from __future__ import annotations

import json
from types import SimpleNamespace

from defenseclaw.tui.executor import CommandEvent
from defenseclaw.tui.services.routing_state import (
    VIEW_USAGE,
    RoutingPanelModel,
    overview_tile,
    parse_model_entry,
    routing_help_rows,
    routing_keys_hint_for,
)
from fixtures import screen_text, snapshot_app

STATUS = {
    "managed": False,
    "enabled": True,
    "classifier": "rules",
    "default_alias": "fast",
    "models": [
        {"alias": "fast", "provider": "openai", "model": "gpt-mini", "default": True, "locked": False},
        {"alias": "local", "provider": "vllm", "model": "qwen", "default": False, "locked": False},
    ],
    "rule_list": [{"id": "secrets-local", "match": {"severity_at_least": "HIGH"}, "allow": ["local"]}],
    "health": {"state": "running"},
    "effective": {"budgets": [{"id": "daily", "period": "day", "limit_usd": 20, "spent_usd": 21.0, "on_exceed": "warn", "exceeded": True}]},
    "warnings": ["budget daily is used up for this day"],
}


def loaded(status=STATUS) -> RoutingPanelModel:
    model = RoutingPanelModel()
    model.apply_status_json(json.dumps(status))
    return model


def test_rows_and_summary() -> None:
    model = loaded()
    assert [(r.kind, r.name) for r in model.rows()] == [("model", "fast"), ("model", "local"), ("rule", "secrets-local"), ("budget", "daily")]
    assert model.data_table_rows(compact=False)[0] == ("model", "fast", "openai/gpt-mini", "default")
    assert all(len(row) == 3 for row in model.data_table_rows(compact=True))
    assert model.total_count() == 2
    assert overview_tile(STATUS) == "Routing: on · 2 model(s) · budget daily used up"
    assert overview_tile({"enabled": False}) == "Routing: off"


def test_bad_json_is_an_error_not_a_crash() -> None:
    model = RoutingPanelModel()
    model.apply_status_json("not json")
    assert model.error and model.loaded and model.rows() == []
    model.apply_usage_json(b"[1, 2]")
    assert model.usage_rows() == []


def test_keys_build_the_cli_commands() -> None:
    model = loaded()
    model.handle_key("down")
    action = model.handle_key("d")
    assert action.kind == "intent" and action.intent.args == ("routing", "models", "remove", "local")
    assert action.intent.risk == "destructive"
    assert model.handle_key("e").intent.args == ("routing", "disable")
    assert model.handle_key("p").intent.risk == "read-only"
    assert model.handle_key("t").prompt == "test"
    assert model.intent_for_prompt("test", "write a parser").args == ("routing", "test", "write a parser")
    assert model.intent_for_prompt("model", "coder anthropic/claude-sonnet-5-5").args == (
        "routing", "models", "add", "coder", "--provider", "anthropic", "--model", "claude-sonnet-5-5")
    assert model.intent_for_prompt("model", "just-one-word") is None
    assert parse_model_entry('a "b c" d') == ("a", "b c", "d")


def test_usage_view_and_periods() -> None:
    model = loaded()
    assert model.handle_key("u").kind == "view" and model.view == VIEW_USAGE
    assert model.handle_key("m").kind == "refresh" and model.usage_since() == "30d"
    assert model.handle_key("d").kind == "refresh" and model.period == "day"
    model.apply_usage_json(json.dumps({"rows": [{"key": "fast", "calls": 3, "cost_usd": 0.5}], "scope": "own"}))
    assert model.data_table_rows(compact=True) == [("fast", "3", "0.5000")]
    assert "yours" in model.summary_line()


def test_routing_tab_shows_only_when_routing_applies(tmp_path) -> None:
    app = snapshot_app(tmp_path)
    assert app._panel_hidden("routing")
    app.config.routing = SimpleNamespace(enabled=False, admin={"rules": []})
    assert not app._panel_hidden("routing")


def test_managed_hides_writes_and_keymaps_agree() -> None:
    model = loaded(dict(STATUS, managed=True))
    for key in ("a", "d", "e"):
        assert model.handle_key(key).kind == "none"
    assert "a add model" not in routing_keys_hint_for("routing-managed")
    assert "a add model" in routing_keys_hint_for("routing")
    for managed in (False, True):
        probe = loaded(dict(STATUS, managed=managed))
        advertised = {k for k, _ in probe.keys()}
        assert {key.split()[0] for key, _ in routing_help_rows(managed)} >= advertised
        for key in advertised:
            fresh = loaded(dict(STATUS, managed=managed))
            assert fresh.handle_key(key).kind != "none", key


async def test_routing_panel_renders_at_80x24(tmp_path) -> None:
    app = snapshot_app(tmp_path)
    app.config.routing = SimpleNamespace(enabled=True, admin={})  # the tab shows only while routing is on
    app.routing_model, app._routing_model_injected = loaded(), True
    async with app.run_test(size=(80, 24)) as pilot:
        app.action_switch_panel("routing")
        await pilot.pause()
        text = screen_text(app)
        assert "Routing on" in text and "fast" in text and "secrets-local" in text


async def test_delete_journey_runs_the_remove_command(tmp_path) -> None:
    app = snapshot_app(tmp_path)
    app.config.routing = SimpleNamespace(enabled=True, admin={})  # the tab shows only while routing is on
    app.routing_model, app._routing_model_injected = loaded(), True
    calls: list[tuple[str, ...]] = []

    async def fake_run(binary, args, *, stdin_input=None, env_overrides=None):
        calls.append((binary, *args))
        yield CommandEvent("start", " ".join((binary, *args)))
        yield CommandEvent("done", exit_code=0, duration=0.01)

    app.executor.run = fake_run
    async with app.run_test(size=(80, 24)) as pilot:
        app.action_switch_panel("routing")
        await pilot.pause()
        await pilot.press("d")
        await pilot.pause()
        for key in ("d", "enter", "enter"):  # danger modal: pick the run row, arm it, confirm
            await pilot.press(key)
            await pilot.pause()
        await app.workers.wait_for_complete()
    assert ("defenseclaw", "routing", "models", "remove", "fast") in calls
