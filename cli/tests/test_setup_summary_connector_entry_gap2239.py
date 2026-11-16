"""GAP-2239: the setup guardrail summary shows the values the connector runs with."""

from __future__ import annotations

import os

import pytest
from click.testing import CliRunner
from defenseclaw.commands.cmd_setup import setup as setup_group
from defenseclaw.config import HILTConfig, PerConnectorGuardrailConfig
from defenseclaw.file_permissions import atomic_write_private_bytes

from tests.helpers import cleanup_app, make_app_context
from tests.test_cmd_setup_multi_connector import _setup_patches

pytestmark = pytest.mark.supported_connector_host


def _summary(output: str, key: str) -> str:
    rows = [line.split(":", 1)[1].strip() for line in output.splitlines() if line.strip().startswith(key + ":")]
    assert rows, output
    return rows[-1]


def test_summary_shows_the_connector_entry_mode_not_the_unset_top_level_mode() -> None:
    # A config whose only connector has its own guardrail.connectors entry
    # (init or setup <connector> wrote it) and no top-level mode: setup
    # guardrail saves --mode there, and the summary printed the top-level
    # default (observe) while guardrail status showed action.
    app, tmp_dir, db_path = make_app_context()
    try:
        gc = app.cfg.guardrail
        app.cfg.claw.mode = "claudecode"
        gc.connector = "claudecode"
        gc.mode = ""
        gc.rule_pack = ""
        gc.hilt = HILTConfig(enabled=False, min_severity="HIGH")
        gc.connectors = {
            "claudecode": PerConnectorGuardrailConfig(
                mode="observe", rule_pack="default", hilt=HILTConfig(enabled=True, min_severity="CRITICAL")
            )
        }
        cfg_path = os.path.join(tmp_dir, "config.yaml")
        app.cfg.save = lambda: atomic_write_private_bytes(cfg_path, b"x\n")  # type: ignore[assignment]
        with _setup_patches():
            result = CliRunner().invoke(
                setup_group,
                [
                    "guardrail",
                    "--connector",
                    "claudecode",
                    "--mode",
                    "action",
                    "--rule-pack",
                    "strict",
                    "--non-interactive",
                ],
                obj=app,
            )
        assert result.exit_code == 0, result.output
        assert gc.effective_mode("claudecode") == "action"
        assert _summary(result.output, "guardrail.mode") == gc.effective_mode("claudecode")
        assert _summary(result.output, "guardrail.rule_pack") == gc.effective_rule_pack("claudecode")
        hilt = gc.effective_hilt("claudecode")
        assert _summary(result.output, "guardrail.hilt.enabled") == str(bool(hilt.enabled)).lower()
        assert _summary(result.output, "guardrail.hilt.min_severity") == (hilt.min_severity or "HIGH")
    finally:
        cleanup_app(app, db_path, tmp_dir)
