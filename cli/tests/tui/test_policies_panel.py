# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Policies panel journeys at 80x24 (activate a policy, switch a rule pack, turn an
opt-in pack on, switch a connector's mode) and one render check at 160x45."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from textual.widgets import DataTable

sys.path.insert(0, str(Path(__file__).parent))

from defenseclaw.policy_catalog import ConnectorPack, RulePack  # noqa: E402
from defenseclaw.tui import app as app_module  # noqa: E402
from defenseclaw.tui import policy_panel  # noqa: E402
from defenseclaw.tui.executor import CommandEvent  # noqa: E402
from fixtures import screen_text, snapshot_app  # noqa: E402
from test_policy_state import DEFAULT, PERMISSIVE, STRICT  # noqa: E402
from test_protection_center import CHAINS, FAMILIES, PACKS, Posture  # noqa: E402

_VALID = json.dumps(
    {
        "wire_version": 1,
        "kind": "rule_pack",
        "valid": True,
        "summary": {"rule_count": 3, "enabled_rule_count": 3, "rule_file_count": 1, "digest": "c" * 64},
    }
)

POSTURES = (
    Posture("global"),
    Posture("codex", mode="action", mode_source="override"),
    Posture("claudecode"),
)


def policies_app(tmp_path, monkeypatch, *, multi_connector: bool = False):
    """snapshot_app with a fake catalog, a fake validator and a recording executor."""
    reads: list[object] = []

    def fake_catalog(config):
        reads.append(config)
        return policy_panel.PolicyCatalogRead(
            policies=[DEFAULT, PERMISSIVE, STRICT],
            global_pack=ConnectorPack("global", "default", "/p/guardrail/default", "default"),
            connectors=[ConnectorPack("codex", "default", "/p/guardrail/default", "default")],
            packs=[
                RulePack("default", "/p/guardrail/default", "preset", ("global", "codex")),
                RulePack("strict", "/p/guardrail/strict", "preset", ()),
                RulePack("permissive", "/p/guardrail/permissive", "preset", ()),
            ],
            postures=list(POSTURES),
            protection=list(PACKS),
            families={path: list(rows) for path, rows in FAMILIES.items()},
            chains=list(CHAINS),
        )

    captured: list[tuple[str, tuple[str, ...]]] = []

    async def fake_captured(binary, args):
        captured.append((binary, tuple(args)))
        if args[:2] == ("guardrail", "validate-pack"):
            return 0, _VALID.encode(), b""
        return 1, b"", b"unexpected"

    monkeypatch.setattr(policy_panel, "read_policy_catalog", fake_catalog)
    monkeypatch.setattr(app_module, "_communicate_captured", fake_captured)

    app = snapshot_app(tmp_path)
    if multi_connector:
        # ``guardrail.connectors`` makes ``--connector`` valid for mode and approval.
        app.config.guardrail.connectors = {"codex": SimpleNamespace(), "claudecode": SimpleNamespace()}
    runs: list[tuple[str, tuple[str, ...]]] = []

    async def fake_run(binary, args, **_kwargs):
        runs.append((binary, tuple(args)))
        yield CommandEvent("start", " ".join((binary, *args)))
        yield CommandEvent("done", exit_code=0, duration=0.01)

    app.executor.run = fake_run  # type: ignore[method-assign]
    # A successful ``guardrail`` command re-reads config.yaml; keep it off the real home.
    monkeypatch.setattr(app, "_refresh_cached_config", lambda: None)
    return app, reads, captured, runs


async def until(pilot, condition, *, tries: int = 100) -> None:
    for _ in range(tries):
        if condition():
            return
        await pilot.pause()
    raise AssertionError("condition not reached")


@pytest.mark.asyncio
async def test_activate_strict_from_the_policies_view(tmp_path, monkeypatch) -> None:
    app, reads, _captured, runs = policies_app(tmp_path, monkeypatch)
    async with app.run_test(size=(80, 24)) as pilot:
        await until(pilot, lambda: app.policy_model.loaded)
        # Overview names the active policy before the panel is opened.
        assert app.overview_model.active_policy is DEFAULT
        await pilot.press("P")
        assert app.active_panel == "policies"
        await pilot.press("5", "down", "down", "enter")  # strict → picker
        await pilot.press("enter")  # choose strict
        await pilot.press("enter")  # consequence: activate
        await until(pilot, lambda: bool(runs))
        await until(pilot, lambda: len(reads) >= 2)
    assert runs == [("defenseclaw", ("policy", "activate", "strict"))]


@pytest.mark.asyncio
async def test_switch_one_connectors_rule_pack_to_strict(tmp_path, monkeypatch) -> None:
    app, _reads, captured, runs = policies_app(tmp_path, monkeypatch)
    async with app.run_test(size=(80, 24)) as pilot:
        await until(pilot, lambda: app.policy_model.loaded)
        await pilot.press("P", "6", "down", "enter")  # the codex row → scope preselected
        await pilot.press("enter")  # keep codex
        await pilot.press("2", "enter")  # strict → validate
        await until(pilot, lambda: bool(captured))
        await pilot.press("enter")  # consequence: use
        await until(pilot, lambda: bool(runs))
    assert captured == [("defenseclaw", ("guardrail", "validate-pack", "/p/guardrail/strict", "--json"))]
    assert runs == [("defenseclaw", ("guardrail", "use-pack", "strict", "--connector", "codex"))]


@pytest.mark.asyncio
async def test_turn_on_an_optin_pack_for_one_connector(tmp_path, monkeypatch) -> None:
    app, reads, _captured, runs = policies_app(tmp_path, monkeypatch, multi_connector=True)
    async with app.run_test(size=(80, 24)) as pilot:
        await until(pilot, lambda: app.policy_model.loaded)
        await pilot.press("P", "2", "s", "s")  # opt-in packs, scope claudecode
        assert app.policy_model.scope_name() == "claudecode"
        assert "Kubernetes production" in screen_text(app)  # the pack rows are on screen at 80x24
        await pilot.press("down", "space")  # Kubernetes production → consequence
        await pilot.press("enter")  # turn on
        await until(pilot, lambda: bool(runs))
        await until(pilot, lambda: len(reads) >= 2)  # the panel re-reads after success
    assert runs == [
        (
            "defenseclaw",
            ("guardrail", "protection", "enable", "kubernetes-production-protection", "--connector", "claudecode"),
        )
    ]


@pytest.mark.asyncio
async def test_m_on_a_connector_switches_it_to_observe_after_a_second_confirm(tmp_path, monkeypatch) -> None:
    app, _reads, _captured, runs = policies_app(tmp_path, monkeypatch, multi_connector=True)
    async with app.run_test(size=(80, 24)) as pilot:
        await until(pilot, lambda: app.policy_model.loaded)
        await pilot.press("P", "down", "m")  # codex is in action mode → observe weakens
        await pilot.press("enter")  # arms the red confirm
        await pilot.pause()
        assert runs == []  # one press never runs a weakening change
        await pilot.press("enter")
        await until(pilot, lambda: bool(runs))
    assert runs == [("defenseclaw", ("guardrail", "mode", "observe", "--connector", "codex"))]


@pytest.mark.asyncio
async def test_protection_center_shows_nav_table_and_aside_at_160x45(tmp_path, monkeypatch) -> None:
    app, _reads, _captured, _runs = policies_app(tmp_path, monkeypatch)
    async with app.run_test(size=(160, 45)) as pilot:
        await until(pilot, lambda: app.policy_model.loaded)
        await pilot.press("P", "down")
        await pilot.pause()
        text = screen_text(app)
        nav, aside = app.query_one("#panel-nav"), app.query_one("#panel-aside")
        assert not nav.has_class("hidden") and not aside.has_class("hidden")
        assert str(aside.border_title).endswith("codex")  # the highlighted scope's detail
        # The scope rows keep their levels beside the nav list and the aside.
        assert len(app.query_one("#panel-table", DataTable).columns) >= 6
    for scope in ("global", "codex", "claudecode"):
        assert scope in text


@pytest.mark.asyncio
async def test_a_load_asked_for_during_a_load_runs_once_it_finishes(tmp_path, monkeypatch) -> None:
    import threading

    app, _reads, _captured, _runs = policies_app(tmp_path, monkeypatch)
    release = threading.Event()
    configs: list[object] = []

    def slow_catalog(config):
        configs.append(config)
        if len(configs) == 1:
            release.wait(10)
        return policy_panel.PolicyCatalogRead(policies=[DEFAULT])

    monkeypatch.setattr(policy_panel, "read_policy_catalog", slow_catalog)
    async with app.run_test(size=(80, 24)) as pilot:
        await until(pilot, lambda: len(configs) == 1)
        app._schedule_policy_load()  # e.g. the config changed while the first read ran
        release.set()
        await until(pilot, lambda: len(configs) == 2)
        await app.workers.wait_for_complete()
        assert len(configs) == 2
