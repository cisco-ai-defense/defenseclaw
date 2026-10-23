# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""setup guardrail on a no-connector install does not enroll OpenClaw (GAP-2609)."""

from __future__ import annotations

import click
import pytest
from click.testing import CliRunner

from tests.helpers import cleanup_app, make_app_context


def test_non_interactive_guardrail_setup_refuses_without_a_connector() -> None:
    from defenseclaw.commands.cmd_setup import setup

    app, tmp_dir, db_path = make_app_context()
    try:
        # The markers init --connector none persists (GAP-1056).
        app.cfg.claw.mode = ""
        app.cfg.guardrail.connector = ""
        app.cfg.guardrail.connectors = {}
        argv = ["guardrail", "--non-interactive", "--no-restart", "--cisco-api-key-env", "ASIA_PACIFIC_KEY"]
        result = CliRunner().invoke(setup, argv, obj=app)
        assert result.exit_code == 1, result.output
        assert "no agent connector is configured" in result.output
        assert "--connector" in result.output
        assert app.cfg.claw.mode == ""
        assert app.cfg.guardrail.connector == ""
        assert app.cfg.cisco_ai_defense.api_key_env != "ASIA_PACIFIC_KEY"
    finally:
        cleanup_app(app, db_path, tmp_dir)


def _guardrail_setup_with_picked_hint(installed: list[str]):
    import os
    from unittest.mock import patch

    from defenseclaw.commands import cmd_setup

    app, tmp_dir, db_path = make_app_context()
    app.cfg.claw.mode = ""
    app.cfg.guardrail.connector = ""
    app.cfg.guardrail.connectors = {}
    with open(os.path.join(app.cfg.data_dir, "picked_connector"), "w", encoding="utf-8") as fh:
        fh.write("codex\n")
    argv = ["guardrail", "--non-interactive", "--no-restart", "--cisco-api-key-env", "ASIA_PACIFIC_KEY"]
    with patch.object(cmd_setup, "_detect_installed_connectors", return_value=installed):
        result = CliRunner().invoke(cmd_setup.setup, argv, obj=app)
    return app, tmp_dir, db_path, result


def test_a_picked_hint_for_an_agent_that_is_not_installed_does_not_pass_the_gate() -> None:
    # GAP-0568: an older installer recorded codex when it had no terminal to
    # ask on; that hint must not enroll an agent the machine does not have.
    app, tmp_dir, db_path, result = _guardrail_setup_with_picked_hint([])
    try:
        assert result.exit_code == 1, result.output
        assert "no agent connector is configured" in result.output
        assert app.cfg.guardrail.connector == ""
        assert app.cfg.claw.mode == ""
    finally:
        cleanup_app(app, db_path, tmp_dir)


def test_a_picked_hint_for_an_installed_agent_still_passes_the_gate() -> None:
    app, tmp_dir, db_path, result = _guardrail_setup_with_picked_hint(["codex"])
    try:
        assert "no agent connector is configured" not in result.output
    finally:
        cleanup_app(app, db_path, tmp_dir)


def test_non_interactive_guardrail_uses_roster_when_claw_block_is_missing() -> None:
    from unittest.mock import patch

    from defenseclaw.commands import cmd_setup
    from defenseclaw.config import PerConnectorGuardrailConfig

    app, tmp_dir, db_path = make_app_context()
    try:
        # An upgraded config can have a configured roster but no claw block.
        # The loader supplies the old claw.mode default in this case.
        app.cfg.claw.mode = "openclaw"
        app.cfg.guardrail.connector = ""
        app.cfg.guardrail.connectors = {"codex": PerConnectorGuardrailConfig()}
        argv = ["guardrail", "--non-interactive", "--no-restart", "--cisco-api-key-env", "ASIA_PACIFIC_KEY"]
        with (
            patch.object(cmd_setup, "_installed_picked_connector", return_value=None),
            patch.object(cmd_setup, "_ensure_connector_available") as check,
        ):
            CliRunner().invoke(cmd_setup.setup, argv, obj=app)
        check.assert_any_call("codex")
        assert app.cfg.guardrail.connector != "openclaw"
    finally:
        cleanup_app(app, db_path, tmp_dir)


def test_non_interactive_guardrail_refuses_legacy_config_without_claw_or_agent() -> None:
    from pathlib import Path
    from unittest.mock import patch

    from defenseclaw import config as config_module
    from defenseclaw.commands import cmd_setup

    app, tmp_dir, db_path = make_app_context()
    try:
        Path(tmp_dir, "config.yaml").write_text("config_version: 9\n", encoding="utf-8")
        with patch("defenseclaw.openclaw_presence.openclaw_installed", return_value=False):
            app.cfg = config_module.load(data_dir=tmp_dir)
        argv = ["guardrail", "--non-interactive", "--no-restart", "--cisco-api-key-env", "ASIA_PACIFIC_KEY"]
        with patch.object(cmd_setup, "_detect_installed_connectors", return_value=[]):
            result = CliRunner().invoke(cmd_setup.setup, argv, obj=app)
        assert result.exit_code == 1, result.output
        assert "no agent connector is configured" in result.output
        assert app.cfg.guardrail.connector == ""
        assert app.cfg.cisco_ai_defense.api_key_env != "ASIA_PACIFIC_KEY"
    finally:
        cleanup_app(app, db_path, tmp_dir)


_SAVED = "guardrail:\n  connector: openclaw\n"
_IMPLIED = "claw:\n  mode: openclaw\n"
_LEGACY = "claw:\n  mode: openclaw\n" + _SAVED


def _gateway(host: str = "127.0.0.1", fleet_mode: str = "auto") -> str:
    return f"gateway:\n  host: {host}\n  fleet_mode: '{fleet_mode}'\n"


def _roster(*entries: str, primary: str | None = "openclaw") -> str:
    head = "claw:\n  mode: openclaw\nguardrail:\n"
    if primary is not None:
        head += f"  connector: {primary}\n"
    return head + "  connectors:\n" + "".join(f"    {entry}\n" for entry in entries)


# Non-interactive ``setup guardrail`` precedence. Columns: config.yaml body,
# picked_connector hint, connectors discovery reports installed, whether
# OpenClaw is present to the presence check (openclaw.json or a binary
# outside discovery), the selection (None = refuse), and the selection where
# OpenClaw is unsupported (native Windows) when that differs.
_PRECEDENCE = [
    # A saved local OpenClaw is kept only when this host has it.
    ("saved-local-absent-hint", _LEGACY + _gateway(), "codex", ["codex"], False, "codex", None),
    ("saved-local-absent-no-hint", _LEGACY + _gateway(), None, [], False, None, None),
    ("saved-local-absent-unverified-hint", _LEGACY + _gateway(), "codex", [], False, None, None),
    ("saved-mixed-case-absent-hint", "guardrail:\n  connector: OpenClaw\n" + _gateway(), "codex", ["codex"], False,
     "codex", None),
    ("saved-local-present-outside-discovery", _LEGACY + _gateway(), None, [], True, "openclaw", ""),
    ("saved-local-present-beats-hint", _LEGACY + _gateway(), "codex", [], True, "openclaw", ""),
    # Only a fleet mode that dials keeps an absent OpenClaw.
    ("remote-auto-no-claw-block", _SAVED + _gateway("10.0.0.5"), "codex", ["codex"], False, "openclaw", None),
    ("remote-auto-saved-claw-mode", _LEGACY + _gateway("10.0.0.5"), None, [], False, "openclaw", None),
    ("remote-enabled", _LEGACY + _gateway("10.0.0.5", "enabled"), None, [], False, "openclaw", None),
    ("loopback-enabled", _LEGACY + _gateway(fleet_mode="enabled"), "codex", ["codex"], False, "openclaw", None),
    ("loopback-on", _SAVED + _gateway(fleet_mode="on"), "codex", ["codex"], False, "openclaw", None),
    ("loopback-true", _SAVED + _gateway(fleet_mode="true"), "codex", ["codex"], False, "openclaw", None),
    ("loopback-typo-dials-like-auto", _LEGACY + _gateway(fleet_mode="enabledd"), "codex", ["codex"], False,
     "codex", None),
    ("loopback-disabled-hint", _LEGACY + _gateway(fleet_mode="disabled"), "codex", ["codex"], False, "codex", None),
    ("loopback-off-hint", _LEGACY + _gateway(fleet_mode="off"), "codex", ["codex"], False, "codex", None),
    ("loopback-false-hint", _LEGACY + _gateway(fleet_mode="false"), "codex", ["codex"], False, "codex", None),
    ("loopback-disabled-spaced-case", _LEGACY + _gateway(fleet_mode=" Disabled "), "codex", ["codex"], False,
     "codex", None),
    ("remote-disabled-hint", _LEGACY + _gateway("10.0.0.5", "disabled"), "codex", ["codex"], False, "codex", None),
    ("loopback-disabled-no-hint", _LEGACY + _gateway(fleet_mode="disabled"), None, [], False, None, None),
    # An implied OpenClaw (claw.mode only) loses to an installed hint. With
    # no hint it is selected only where the loader keeps it.
    ("implied-absent-no-hint", _IMPLIED + _gateway(), None, [], False, None, None),
    ("implied-disabled-hint", _IMPLIED + _gateway(fleet_mode="disabled"), "codex", ["codex"], False, "codex", None),
    ("implied-typo-hint", _IMPLIED + _gateway(fleet_mode="enabledd"), "codex", ["codex"], False, "codex", None),
    ("implied-disabled-no-hint-loader-keeps", _IMPLIED + _gateway(fleet_mode="disabled"), None, [], False,
     "openclaw", None),
    ("implied-enabled-no-hint", _IMPLIED + _gateway(fleet_mode="enabled"), None, [], False, "openclaw", None),
    ("implied-present-hint", _IMPLIED + _gateway(), "codex", ["codex"], True, "codex", None),
    ("implied-present-no-hint", _IMPLIED + _gateway(), None, [], True, "openclaw", None),
    # A stale OpenClaw never overrides an installed, enabled roster connector.
    ("roster-stale-primary", _roster("codex: {enabled: true}") + _gateway(), None, ["codex"], False, "codex", None),
    ("roster-stale-primary-hint-in-roster", _roster("codex: {}", "cursor: {}") + _gateway(), "cursor",
     ["codex", "cursor"], False, "cursor", None),
    ("roster-stale-primary-hint-outside-roster", _roster("codex: {}") + _gateway(), "claudecode",
     ["codex", "claudecode"], False, "codex", None),
    ("roster-stale-primary-disabled-fleet", _roster("codex: {}") + _gateway(fleet_mode="disabled"), None, ["codex"],
     False, "codex", None),
    ("roster-enrolled-openclaw-absent", _roster("openclaw: {}", "codex: {}") + _gateway(), None, ["codex"], False,
     "codex", None),
    ("roster-claw-mode-openclaw-no-primary", _roster("openclaw: {}", "codex: {}", primary=None) + _gateway(), None,
     ["codex"], False, "codex", None),
    ("roster-claw-mode-only-codex", _roster("codex: {}", primary=None) + _gateway(), None, [], False, "codex", None),
    ("roster-disabled-skipped", _roster("codex: {enabled: false}", "cursor: {}") + _gateway(), "codex",
     ["codex", "cursor"], False, "cursor", None),
    ("roster-only-disabled", _roster("codex: {enabled: false}") + _gateway(), "codex", ["codex"], False, None, None),
    ("roster-not-installed", _roster("codex: {}") + _gateway(), None, [], False, None, None),
    ("roster-remote-fleet-keeps-openclaw", _roster("codex: {}") + _gateway("10.0.0.5"), None, ["codex"], False,
     "openclaw", None),
    ("roster-present-openclaw", _roster("codex: {}") + _gateway(), None, ["codex"], True, "openclaw", "codex"),
    ("configured-primary-beats-hint", "guardrail:\n  connector: codex\n" + _gateway(), "cursor", ["cursor"], False,
     "codex", None),
]


@pytest.mark.parametrize(
    ("config_body", "picked", "installed", "openclaw_present", "expected", "expected_unsupported"),
    [pytest.param(*row[1:], id=row[0]) for row in _PRECEDENCE],
)
def test_non_interactive_guardrail_connector_precedence(
    tmp_path,
    config_body: str,
    picked: str | None,
    installed: list[str],
    openclaw_present: bool,
    expected: str | None,
    expected_unsupported: str | None,
) -> None:
    from unittest.mock import patch

    from defenseclaw import config as config_module
    from defenseclaw import platform_support
    from defenseclaw.commands import cmd_setup
    from defenseclaw.context import AppContext

    if expected_unsupported is not None and not platform_support.connector_supported_on_os("openclaw"):
        expected = expected_unsupported or None
    (tmp_path / "config.yaml").write_text("config_version: 9\n" + config_body, encoding="utf-8")
    if picked:
        (tmp_path / "picked_connector").write_text(f"{picked}\n", encoding="utf-8")
    app = AppContext()
    # Hold the presence result through both config load and setup: setup
    # probes it again, and the test host may have OpenClaw.
    with patch("defenseclaw.openclaw_presence.openclaw_installed", return_value=openclaw_present):
        app.cfg = config_module.load(data_dir=str(tmp_path))
        roster_before = dict(app.cfg.guardrail.connectors)
        with (
            patch.object(cmd_setup, "_detect_installed_connectors", return_value=installed),
            patch.object(cmd_setup, "_capture_setup_config_snapshot", return_value=object()),
            patch.object(cmd_setup, "_ensure_connector_available") as selected,
            patch.object(
                cmd_setup, "_apply_guardrail_extra_options", side_effect=click.ClickException("connector selected")
            ),
        ):
            result = CliRunner().invoke(
                cmd_setup.setup,
                ["guardrail", "--yes", "--no-restart", "--cisco-api-key-env", "ASIA_PACIFIC_KEY"],
                obj=app,
            )
    if expected is None:
        assert "no agent connector is configured" in result.output, result.output
        selected.assert_not_called()
        assert app.cfg.cisco_ai_defense.api_key_env != "ASIA_PACIFIC_KEY"
    else:
        assert "connector selected" in result.output, result.output
        selected.assert_called_once_with(expected)
        assert app.cfg.guardrail.connector == expected
    # Setup selects among the enrolled connectors; it never drops one.
    assert app.cfg.guardrail.connectors == roster_before


def test_restart_without_a_connector_does_not_start_openclaw(tmp_path) -> None:
    from unittest.mock import patch

    from defenseclaw.commands import cmd_setup

    with (
        patch.object(cmd_setup, "_restart_defense_gateway", return_value=True),
        patch.object(cmd_setup, "_restart_openclaw_gateway") as restart_openclaw,
        patch.object(cmd_setup, "_check_openclaw_gateway") as check_openclaw,
    ):
        cmd_setup._restart_services(str(tmp_path))
    restart_openclaw.assert_not_called()
    check_openclaw.assert_not_called()


def test_disabling_guardrail_without_an_agent_does_not_restart_openclaw() -> None:
    from unittest.mock import patch

    from defenseclaw.commands import cmd_setup

    app, tmp_dir, db_path = make_app_context()
    try:
        app.cfg.claw.mode = ""
        app.cfg.guardrail.connector = ""
        with (
            patch.object(app.cfg, "save"),
            patch.object(cmd_setup, "_restart_services") as restart,
        ):
            cmd_setup._disable_guardrail(app, app.cfg.guardrail)
        assert restart.call_args.kwargs["connector"] == ""
    finally:
        cleanup_app(app, db_path, tmp_dir)
