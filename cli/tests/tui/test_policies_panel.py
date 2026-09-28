# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Policies panel journeys at 80x24: activate a policy, switch a connector's rule pack."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from defenseclaw.policy_catalog import ConnectorPack, RulePack  # noqa: E402
from defenseclaw.tui import app as app_module  # noqa: E402
from defenseclaw.tui import policy_panel  # noqa: E402
from defenseclaw.tui.executor import CommandEvent  # noqa: E402
from fixtures import snapshot_app  # noqa: E402
from test_policy_state import DEFAULT, PERMISSIVE, STRICT  # noqa: E402

_VALID = json.dumps(
    {
        "wire_version": 1,
        "kind": "rule_pack",
        "valid": True,
        "summary": {"rule_count": 3, "enabled_rule_count": 3, "rule_file_count": 1, "digest": "c" * 64},
    }
)


def policies_app(tmp_path, monkeypatch):
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
async def test_activate_strict_from_the_policies_panel(tmp_path, monkeypatch) -> None:
    app, reads, _captured, runs = policies_app(tmp_path, monkeypatch)
    async with app.run_test(size=(80, 24)) as pilot:
        await until(pilot, lambda: app.policy_model.loaded)
        # Overview names the active policy before the panel is opened.
        assert app.overview_model.active_policy is DEFAULT
        await pilot.press("P")
        assert app.active_panel == "policies"
        await pilot.press("down", "down", "enter")  # strict → picker
        await pilot.press("enter")  # choose strict
        await pilot.press("enter")  # consequence: activate
        await pilot.press("enter")  # command preview: run
        await until(pilot, lambda: bool(runs))
        await until(pilot, lambda: len(reads) >= 2)
    assert runs == [("defenseclaw", ("policy", "activate", "strict"))]


@pytest.mark.asyncio
async def test_switch_one_connectors_rule_pack_to_strict(tmp_path, monkeypatch) -> None:
    app, _reads, captured, runs = policies_app(tmp_path, monkeypatch)
    async with app.run_test(size=(80, 24)) as pilot:
        await until(pilot, lambda: app.policy_model.loaded)
        await pilot.press("P", "2", "down", "enter")  # the codex row → scope preselected
        await pilot.press("enter")  # keep codex
        await pilot.press("2", "enter")  # strict → validate
        await until(pilot, lambda: bool(captured))
        await pilot.press("enter")  # consequence: use
        await pilot.press("enter")  # command preview: run
        await until(pilot, lambda: bool(runs))
    assert captured == [("defenseclaw", ("guardrail", "validate-pack", "/p/guardrail/strict", "--json"))]
    assert runs == [("defenseclaw", ("guardrail", "use-pack", "strict", "--connector", "codex"))]
