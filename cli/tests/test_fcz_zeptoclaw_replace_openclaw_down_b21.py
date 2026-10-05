"""GAP-2477: a failed setup zeptoclaw --replace whose rollback finds the OpenClaw gateway down."""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest
from click.testing import CliRunner
from defenseclaw.commands import cmd_setup
from defenseclaw.file_permissions import atomic_write_private_bytes

from tests.helpers import cleanup_app, make_app_context

pytestmark = pytest.mark.supported_connector_host


def test_openclaw_gateway_down_after_rollback_is_a_note_not_an_incomplete_rollback():
    app, tmp_dir, db_path = make_app_context()
    try:
        app.cfg.claw.mode = "openclaw"
        app.cfg.guardrail.connector = "openclaw"
        app.cfg.guardrail.connectors = {}
        cfg_path = os.path.join(tmp_dir, "config.yaml")
        app.cfg.save = lambda: atomic_write_private_bytes(cfg_path, b"x\n")  # type: ignore[assignment]
        calls: list[str] = []

        def restart(*_args, **_kwargs):
            calls.append("restart")
            if len(calls) == 1:
                cmd_setup._fail_if_restart_failed(["defenseclaw-gateway"])
            cmd_setup._fail_if_restart_failed(["openclaw-gateway"])

        with (
            patch.object(cmd_setup, "_restart_services", side_effect=restart),
            patch.object(cmd_setup, "_ensure_connector_available"),
            patch.object(cmd_setup, "_maybe_bring_up_local_stack"),
            patch.object(cmd_setup, "_check_connector_version_supported_for_setup", return_value=True),
            patch.object(cmd_setup, "_windows_runtime_rollback", return_value=False),
        ):
            result = CliRunner().invoke(cmd_setup.setup, ["zeptoclaw", "--replace", "--yes"], obj=app)

        out = " ".join(result.output.split())
        assert result.exit_code != 0, result.output
        assert len(calls) == 2, result.output
        assert "rollback was incomplete" not in out
        assert "restored the prior connector configuration and runtime" in out
        assert "Run `defenseclaw-gateway start`" not in out
        assert "the OpenClaw gateway is not running" in out
        assert ".." not in out
    finally:
        cleanup_app(app, db_path, tmp_dir)
