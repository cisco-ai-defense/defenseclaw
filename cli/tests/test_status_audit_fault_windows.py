"""Status remains readable during a Windows audit write fault (GAP-0776)."""

from __future__ import annotations

import json
import sqlite3
from types import SimpleNamespace
from unittest.mock import patch

from click.testing import CliRunner
from defenseclaw import config, main
from defenseclaw.commands import cmd_config, cmd_status
from defenseclaw.context import AppContext
from defenseclaw.db import Store

from tests.helpers import make_temp_config


def test_status_reports_live_audit_failure_and_block_after_recovery(tmp_path):
    cfg = make_temp_config(str(tmp_path))
    cfg.environment = "windows"
    cfg.guardrail.enabled = True
    cfg.guardrail.connector = "claudecode"
    original_init = Store.init
    fault = True

    def init_with_bounded_fault(store):
        if fault:
            raise sqlite3.OperationalError("database or disk is full")
        return original_init(store)

    health = {
        "connectors": [{"name": "claudecode", "source": "manual", "state": "running", "tool_blocks": 1}],
        "telemetry": {
            "state": "error",
            "details": {"event_history_failure": "sqlite_write_failed", "event_history_last_sqlite_class": "full"},
        },
    }
    with (
        patch.object(config, "require_v8_config"),
        patch.object(config, "load", return_value=cfg),
        patch.object(cmd_config, "validate_config", return_value=SimpleNamespace(ok=True)),
        patch.object(Store, "init", init_with_bounded_fault),
        patch.object(cmd_status, "_fetch_runtime_bound_health", return_value=health),
        patch.object(
            cmd_status,
            "_native_delivery_summary",
            return_value=SimpleNamespace(
                as_json=lambda: {}, observation_window_hours=24, event_rows_truncated=False, connectors=(), reason=""
            ),
        ),
    ):
        during = CliRunner().invoke(main.cli, ["status", "--json"], obj=AppContext())
        assert during.exit_code == 0, during.output
        reported = json.loads(during.output)
        assert reported["enforcement"] is None
        assert "database or disk is full" in reported["audit_db_error"]
        assert "events cannot be written" in reported["audit_write_failure"]
        assert reported["tool_blocks"] == 1

        human = CliRunner().invoke(main.cli, ["status"], obj=AppContext())
        assert human.exit_code == 0, human.output
        assert "database or disk is full" in human.output
        assert "unavailable" in human.output
        assert "tool blocks: 1" in human.output, human.output

        fault = False
        health["telemetry"] = {"state": "running"}
        after = CliRunner().invoke(main.cli, ["status", "--json"], obj=AppContext())
        assert after.exit_code == 0, after.output
        recovered = json.loads(after.output)
        assert "audit_db_error" not in recovered
        assert "audit_write_failure" not in recovered
        assert recovered["tool_blocks"] == 1
