# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Status remains useful while a Windows audit volume rejects writes."""

from __future__ import annotations

import json
import sqlite3
from types import SimpleNamespace

from click.testing import CliRunner


def test_status_keeps_live_audit_failure_and_tool_block_after_db_recovery(tmp_path, monkeypatch):
    from defenseclaw import config as dcconfig
    from defenseclaw import db
    from defenseclaw.commands import cmd_config, cmd_status
    from defenseclaw.main import cli

    home = tmp_path / "data"
    home.mkdir()
    config_path = home / "config.yaml"
    config_path.write_text(
        "config_version: 8\n"
        f"data_dir: {home.as_posix()}\n"
        "gateway:\n  api_bind: 127.0.0.1\n  api_port: 19131\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("DEFENSECLAW_HOME", str(home))
    monkeypatch.setenv("DEFENSECLAW_CONFIG", str(config_path))
    monkeypatch.setattr(dcconfig, "require_v8_config", lambda **_: None)
    monkeypatch.setattr(cmd_config, "validate_config", lambda: SimpleNamespace(ok=True))
    health = {
        "connectors": [{"name": "claudecode", "state": "running", "tool_blocks": 1}],
        "telemetry": {
            "state": "error",
            "details": {"event_history_failure": "sqlite_write_failed", "event_history_last_sqlite_class": "full"},
        },
    }
    monkeypatch.setattr(cmd_status, "_fetch_runtime_bound_health", lambda *_: health)
    monkeypatch.setattr(cmd_status, "_native_delivery_summary", lambda *_: SimpleNamespace(as_json=lambda: {}))

    original_init = db.Store.init
    monkeypatch.setattr(db.Store, "init", lambda _self: (_ for _ in ()).throw(sqlite3.OperationalError("database or disk is full")))
    fault = CliRunner().invoke(cli, ["status", "--json"])
    assert fault.exit_code == 0, fault.output
    during = json.loads(fault.output)
    assert during["sidecar"]["running"] is True
    assert "database or disk is full" in during["audit_db_error"]
    assert "audit events cannot be written" in during["audit_write_failure"]
    assert during["tool_blocks"] == 1
    assert during["enforcement"] is None

    monkeypatch.setattr(db.Store, "init", original_init)
    health["telemetry"] = {"state": "running"}
    recovered = CliRunner().invoke(cli, ["status", "--json"])
    assert recovered.exit_code == 0, recovered.output
    after = json.loads(recovered.output)
    assert after["tool_blocks"] == 1
    assert "audit_write_failure" not in after
