# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""GAP-0828: no setup path stages a kiro-cli below its hook floor.

A kiro-cli below 2.27.1 runs headless ``--v3`` sessions that load no hooks,
so setup refuses it in observe and in action mode. A refused action request
must not then be configured in observe mode: not by ``setup kiro``, a batch
setup, guardrail setup, first-run (``init``/``quickstart``) or an init extra.
A refusal that depends on action mode (an unreadable version) still falls
back to observe.
"""

from __future__ import annotations

import os
from types import SimpleNamespace
from unittest.mock import patch

import click
import pytest
from defenseclaw.commands import cmd_setup
from defenseclaw.config import PerConnectorGuardrailConfig

from tests.helpers import cleanup_app, make_app_context, record_test_setup_agent_selections

OLD_CLI = "kiro-cli 2.26.1"


def _kiro_discovery(version: str = OLD_CLI) -> SimpleNamespace:
    signal = SimpleNamespace(
        name="kiro", version=version, installed=True, error="", binary_path="",
        kiro_cli_version=version, kiro_ide_version="",
    )
    return SimpleNamespace(agents={"kiro": signal})


def _patch_discovery(version: str = OLD_CLI):
    return patch(
        "defenseclaw.commands.cmd_setup.agent_discovery.discover_with_probes",
        return_value=_kiro_discovery(version),
    )


def test_refusal_scope_says_whether_observe_may_follow_an_action_refusal(tmp_path):
    def check(version: str) -> tuple[bool, dict]:
        scope: dict = {}
        ok = cmd_setup._check_connector_version_supported_for_setup(
            "kiro", mode="action", emit=False, data_dir=str(tmp_path),
            _discovery=_kiro_discovery(version), _refusal_scope=scope,
        )
        return ok, scope

    ok, scope = check(OLD_CLI)
    assert not ok and not cmd_setup._observe_fallback_admitted(scope)
    assert "2.27.1" in scope["reason"]
    # An unreadable version is an action-only refusal: observe may follow.
    ok, scope = check("")
    assert not ok and cmd_setup._observe_fallback_admitted(scope)
    ok, scope = check("kiro-cli 2.27.1")
    assert ok and cmd_setup._observe_fallback_admitted(scope)


def test_setup_kiro_action_does_not_fall_back_to_observe_for_an_old_cli():
    app, root, db_path = make_app_context()
    try:
        warnings: list[str] = []
        with (
            _patch_discovery(),
            patch.object(cmd_setup.ux, "warn", side_effect=warnings.append),
            patch.object(app.cfg, "save") as save,
        ):
            ok = cmd_setup._apply_hook_connector_setup(
                app, connector="kiro", mode="action", restart=False, _downgrade_refused_action=True,
            )
        assert ok is False
        save.assert_not_called()
        assert "kiro" not in (app.cfg.guardrail.connectors or {})
        assert not any("configuring observe mode instead" in warning for warning in warnings)
    finally:
        cleanup_app(app, db_path, root)


def test_batch_setup_does_not_fall_back_to_observe_for_an_old_kiro_cli():
    app, root, db_path = make_app_context()
    try:
        before = tuple(app.cfg.active_connectors())
        ctx = click.Context(cmd_setup.setup, obj=app)
        with (
            ctx,
            patch("defenseclaw.commands.cmd_setup.platform_support.host_os", return_value="linux"),
            _patch_discovery(),
            patch.object(app.cfg, "save") as save,
            pytest.raises(click.ClickException, match="did not pass setup preflight"),
        ):
            cmd_setup._apply_setup_batch(
                ctx, app, ["kiro"], mode="action", restart=False, prompt_per_connector=False,
            )
        save.assert_not_called()
        assert tuple(app.cfg.active_connectors()) == before
    finally:
        cleanup_app(app, db_path, root)


def test_guardrail_setup_does_not_downgrade_an_old_kiro_cli_to_observe():
    app, root, db_path = make_app_context()
    try:
        gc = app.cfg.guardrail
        gc.connector = "kiro"
        gc.connectors = {"kiro": PerConnectorGuardrailConfig(mode="action")}
        with _patch_discovery():
            ok = cmd_setup._check_guardrail_setup_connector_versions(
                app, gc, explicit_connector="kiro", allow_prompt=False,
            )
        assert ok is False
        assert gc.effective_mode("kiro") == "action"
    finally:
        cleanup_app(app, db_path, root)


@pytest.mark.parametrize("profile", ("action", "observe"))
def test_first_run_refuses_an_old_kiro_cli_in_every_profile(tmp_path, profile):
    from defenseclaw.bootstrap import FirstRunOptions, run_first_run

    home = tmp_path / "home"
    with (
        patch.dict(os.environ, {"DEFENSECLAW_HOME": str(home)}),
        patch(
            "defenseclaw.agent_selection.record_setup_agent_selections",
            side_effect=record_test_setup_agent_selections,
        ),
        _patch_discovery(),
        patch("defenseclaw.bootstrap.agent_discovery.discover_agents", return_value=_kiro_discovery()),
    ):
        report = run_first_run(
            FirstRunOptions(connector="kiro", profile=profile, skip_install=True, start_gateway=False, verify=False)
        )

    assert report.status == "needs_attention"
    row = next(step for step in report.setup if step.name == "Connector version")
    assert row.status == "fail" and "below 2.27.1" in row.detail
    assert not (home / "config.yaml").exists()


@pytest.mark.parametrize("profile", ("action", "observe"))
def test_init_leaves_out_an_old_kiro_cli_extra(tmp_path, profile, monkeypatch):
    from defenseclaw import config as cfg_mod
    from defenseclaw.commands.cmd_init import _activate_additional_connectors

    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path))
    cfg = cfg_mod.default_config()
    cfg.guardrail.connector = "codex"
    cfg.claw.mode = "codex"
    cfg.guardrail.mode = "observe"
    cfg.guardrail.enabled = True
    cfg.save()
    none = {"fail_mode": None, "human_approval": None, "hilt_min_severity": None}
    with _patch_discovery():
        active, _ = _activate_additional_connectors(
            {"connector": "codex", "profile": "observe", **none},
            [{"connector": "kiro", "profile": profile, **none},
             {"connector": "hermes", "profile": "observe", **none}],
            start_gateway=False,
            quiet=True,
        )
    assert active == ["codex", "hermes"]
    assert "kiro" not in cfg_mod.load().guardrail.connectors
