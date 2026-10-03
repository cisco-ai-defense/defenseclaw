# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Final-cert TUI Overview fixes (GAP-2546 80-column labels, GAP-2547 rotated token)."""

from __future__ import annotations

import io
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
import requests
from defenseclaw import config as config_module
from defenseclaw import credential_provenance
from defenseclaw.tui.app import DefenseClawTUI, _fetch_gateway_health
from defenseclaw.tui.panels.overview import DoctorCache, DoctorCheck, HealthSnapshot, SubsystemHealth
from rich.console import Console
from textual.geometry import Size

sys.path.insert(0, str(Path(__file__).parent))
from fixtures import snapshot_app  # noqa: E402

_TOKEN = "DEFENSECLAW_GATEWAY_TOKEN"


def test_services_and_doctor_keep_each_count_with_its_label_at_80_columns(tmp_path, monkeypatch) -> None:
    # GAP-2546: "2 skill dirs, 2" / "plugin dirs", "25 active, 0" / "new,
    # enhanced" and "... 14 skip  · 2m" / "ago" at 80 columns.
    monkeypatch.setattr(DefenseClawTUI, "size", property(lambda _self: Size(80, 100)))
    app = snapshot_app(tmp_path)
    model = app.overview_model
    model.set_health(
        HealthSnapshot(
            gateway=SubsystemHealth(state="running"),
            watcher=SubsystemHealth(state="running", details={"skill_dirs": 2, "plugin_dirs": 2}),
            ai_discovery=SubsystemHealth(
                state="running", details={"active_signals": 25, "new_signals": 0, "mode": "enhanced"}
            ),
        )
    )
    model.set_doctor_cache(
        DoctorCache(
            captured_at=datetime.now(timezone.utc) - timedelta(minutes=2),
            passed=34,
            warned=1,
            skipped=14,
            checks=(DoctorCheck("warn", "Disk", "low"),),
            schema_version=2,
            outcome="warning",
        )
    )
    console = Console(width=76, file=io.StringIO(), color_system=None, record=True)
    console.print(app._overview_renderable())  # noqa: SLF001
    lines = [line.strip(" │") for line in console.export_text().splitlines()]
    cells = [cell.strip() for line in lines for cell in line.split("│")]
    assert "2 skill dirs," in cells and "2 plugin dirs" in cells
    assert "25 active," in cells and "0 new, enhanced" in cells
    assert "34 pass  1 warn  14 skip" in cells and "· 2m ago" in cells


@pytest.fixture
def dotenv_dir(tmp_path, monkeypatch):
    monkeypatch.setenv(_TOKEN, "unset")
    monkeypatch.delenv(_TOKEN)
    credential_provenance._reset_for_tests()  # noqa: SLF001
    yield tmp_path
    credential_provenance._reset_for_tests()  # noqa: SLF001


def _write_token(data_dir: Path, value: str) -> None:
    (data_dir / ".env").write_text(f"{_TOKEN}={value}\n")
    os.chmod(data_dir / ".env", 0o600)


def test_dotenv_reload_refreshes_its_own_copy_but_never_a_shell_export(dotenv_dir, monkeypatch) -> None:
    _write_token(dotenv_dir, "launch-token")
    config_module._load_dotenv_into_os(str(dotenv_dir))  # noqa: SLF001
    _write_token(dotenv_dir, "rotated-token")
    config_module._load_dotenv_into_os(str(dotenv_dir))  # noqa: SLF001
    assert os.environ[_TOKEN] == "rotated-token"

    monkeypatch.setenv(_TOKEN, "shell-token")
    _write_token(dotenv_dir, "third-token")
    config_module._load_dotenv_into_os(str(dotenv_dir))  # noqa: SLF001
    assert os.environ[_TOKEN] == "shell-token"


def test_health_probe_rereads_a_rotated_token_after_a_401(dotenv_dir, monkeypatch) -> None:
    # GAP-2547: a lasting "sidecar rejected the configured token (HTTP 401)"
    # beside "Gateway running" until the TUI was relaunched.
    _write_token(dotenv_dir, "launch-token")
    config_module._load_dotenv_into_os(str(dotenv_dir))  # noqa: SLF001
    _write_token(dotenv_dir, "rotated-token")
    used: list[str] = []

    class FakeClient:
        def __init__(self, *, token: str, **_kwargs: object) -> None:
            self.token = token

        def status(self) -> dict[str, object]:
            used.append(self.token)
            if self.token != "rotated-token":
                response = requests.Response()
                response.status_code = 401
                raise requests.HTTPError(response=response)
            return {
                "runtime": {"pid": 4242, "data_dir": str(dotenv_dir)},
                "health": {"api": {"state": "running"}, "guardrail": {"state": "running"}},
            }

    monkeypatch.setattr("defenseclaw.gateway.OrchestratorClient", FakeClient)
    monkeypatch.setattr(
        "defenseclaw.commands.cmd_doctor._trusted_gateway_listener",
        lambda _config: SimpleNamespace(trusted=True, pid=4242, detail=""),
    )
    config = SimpleNamespace(
        data_dir=str(dotenv_dir),
        environment="linux",
        gateway=SimpleNamespace(
            api_bind="127.0.0.1",
            api_port=29870,
            host="127.0.0.1",
            port=4000,
            resolved_token=lambda: os.environ.get(_TOKEN, ""),
        ),
        guardrail=SimpleNamespace(port=4000),
    )
    result = _fetch_gateway_health(config)
    assert used == ["launch-token", "rotated-token"]
    assert "rejected" not in result.detail and result.snapshot is not None

    # An unchanged token is not retried: the 401 stays visible.
    used.clear()
    _write_token(dotenv_dir, "wrong-token")
    config_module._load_dotenv_into_os(str(dotenv_dir))  # noqa: SLF001
    result = _fetch_gateway_health(config)
    assert used == ["wrong-token"]
    assert "rejected the configured token (HTTP 401)" in result.detail
