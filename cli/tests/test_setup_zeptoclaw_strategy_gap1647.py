"""GAP-1647: the setup summary shows the detection strategy that runs, as guardrail status does."""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest
from click.testing import CliRunner
from defenseclaw.commands import cmd_setup
from defenseclaw.file_permissions import atomic_write_private_bytes

from tests.helpers import cleanup_app, make_app_context

pytestmark = pytest.mark.supported_connector_host


@pytest.mark.parametrize(("judge", "expected"), ((False, "regex_only"), (True, "regex_judge")))
def test_setup_zeptoclaw_summary_prints_the_effective_detection_strategy(judge: bool, expected: str) -> None:
    app, tmp_dir, db_path = make_app_context()
    try:
        app.cfg.guardrail.connector = "zeptoclaw"
        app.cfg.guardrail.connectors = {}
        app.cfg.guardrail.detection_strategy = "regex_judge"
        app.cfg.guardrail.judge.enabled = judge
        # guardrail status shows a judge strategy where the judge runs for the connector.
        app.cfg.guardrail.judge.hook_connectors = ["zeptoclaw"] if judge else []
        cfg_path = os.path.join(tmp_dir, "config.yaml")
        app.cfg.save = lambda: atomic_write_private_bytes(cfg_path, b"x\n")  # type: ignore[assignment]
        with (
            patch.object(cmd_setup, "_restart_services"),
            patch.object(cmd_setup, "_ensure_connector_available"),
            patch.object(cmd_setup, "_maybe_bring_up_local_stack"),
            patch.object(cmd_setup, "_check_connector_version_supported_for_setup", return_value=True),
            patch.object(cmd_setup, "_windows_runtime_rollback", return_value=False),
        ):
            result = CliRunner().invoke(
                cmd_setup.setup, ["zeptoclaw", "--mode", "observe", "--yes", "--no-restart"], obj=app
            )
        lines = [line for line in result.output.splitlines() if "detection_strategy" in line]
        assert lines, result.output
        assert all(line.split()[-1] == expected for line in lines), lines
    finally:
        cleanup_app(app, db_path, tmp_dir)
