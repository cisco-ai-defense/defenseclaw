"""GAP-2473: setup zeptoclaw --replace rolls back to the OpenClaw it replaced."""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest
from click.testing import CliRunner
from defenseclaw.commands import cmd_setup
from defenseclaw.file_permissions import atomic_write_private_bytes

from tests.helpers import cleanup_app, make_app_context

pytestmark = pytest.mark.supported_connector_host


def test_failed_zeptoclaw_replace_restarts_the_restored_openclaw():
    app, tmp_dir, db_path = make_app_context()
    try:
        app.cfg.claw.mode = "openclaw"
        app.cfg.guardrail.connector = "openclaw"
        app.cfg.guardrail.connectors = {}
        cfg_path = os.path.join(tmp_dir, "config.yaml")
        app.cfg.save = lambda: atomic_write_private_bytes(cfg_path, b"x\n")  # type: ignore[assignment]
        restarts: list[dict] = []

        def restart(*_args, **kwargs):
            restarts.append(kwargs)
            if len(restarts) == 1:
                raise cmd_setup._GatewayRestartFailed("connector zeptoclaw setup failed")

        with (
            patch.object(cmd_setup, "_restart_services", side_effect=restart),
            patch.object(cmd_setup, "_ensure_connector_available"),
            patch.object(cmd_setup, "_maybe_bring_up_local_stack"),
            patch.object(cmd_setup, "_check_connector_version_supported_for_setup", return_value=True),
            patch.object(cmd_setup, "_windows_runtime_rollback", return_value=False),
        ):
            result = CliRunner().invoke(cmd_setup.setup, ["zeptoclaw", "--replace", "--yes"], obj=app)

        assert result.exit_code != 0, result.output
        assert len(restarts) == 2, result.output
        assert restarts[0]["connector"] == "zeptoclaw"
        # The rollback restart is for the restored OpenClaw, never ZeptoClaw.
        assert restarts[1]["title"] == cmd_setup._ROLLBACK_RESTART_TITLE
        assert restarts[1]["connector"] == "openclaw"
        assert restarts[1]["connectors"] == ["openclaw"]
        assert app.cfg.active_connector() == "openclaw"
        assert cmd_setup._read_picked_connector(app.cfg.data_dir) != "zeptoclaw"
    finally:
        cleanup_app(app, db_path, tmp_dir)
