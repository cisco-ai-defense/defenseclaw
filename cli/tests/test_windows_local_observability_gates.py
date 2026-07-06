# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

"""Windows capability split: local observability yes, local Splunk no."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from click.testing import CliRunner
from defenseclaw import config
from defenseclaw.context import AppContext
from defenseclaw.platform_support import LOCAL_SPLUNK_UNSUPPORTED_REASON


def _app(data_dir: Path) -> AppContext:
    data_dir.mkdir(parents=True)
    (data_dir / "config.yaml").write_bytes(b"config_version: 4\ncustom: keep-me\n")
    app = AppContext()
    app.cfg = config.Config(data_dir=str(data_dir))
    return app


def test_local_observability_routes_are_available_on_windows(tmp_path: Path) -> None:
    from defenseclaw.commands.cmd_setup_local_observability import local_observability

    app = _app(tmp_path / "state with spaces Ω")
    with patch("defenseclaw.platform_support.host_os", return_value="windows"):
        url = CliRunner().invoke(local_observability, ["url", "--json"], obj=app)
        env = CliRunner().invoke(local_observability, ["env", "--json"], obj=app)
    assert url.exit_code == 0, url.output
    assert json.loads(url.output)["otlp_endpoint"] == "127.0.0.1:4317"
    assert env.exit_code == 0, env.output
    assert json.loads(env.output)["OTEL_EXPORTER_OTLP_PROTOCOL"] == "grpc"
    assert "unsupported" not in (url.output + env.output).lower()


def test_local_otlp_preset_is_available_on_windows(tmp_path: Path) -> None:
    from defenseclaw.commands.cmd_setup_observability import observability

    app = _app(tmp_path / "preset state")
    with (
        patch("defenseclaw.platform_support.host_os", return_value="windows"),
        patch(
            "defenseclaw.commands.cmd_setup_observability.apply_preset"
        ) as apply_preset,
    ):
        result = CliRunner().invoke(
            observability, ["add", "local-otlp", "--non-interactive"], obj=app
        )
    assert result.exit_code == 0, result.output
    apply_preset.assert_called_once()


def test_local_splunk_stays_blocked_before_side_effects(tmp_path: Path) -> None:
    from defenseclaw.commands.cmd_setup import setup

    app = _app(tmp_path / "splunk state")
    with (
        patch("defenseclaw.platform_support.host_os", return_value="windows"),
        patch("defenseclaw.commands.cmd_setup._preflight_docker") as preflight,
        patch("defenseclaw.commands.cmd_setup._setup_logs") as setup_logs,
    ):
        result = CliRunner().invoke(
            setup,
            ["splunk", "--logs", "--non-interactive", "--accept-splunk-license"],
            obj=app,
        )
    assert result.exit_code != 0
    assert LOCAL_SPLUNK_UNSUPPORTED_REASON in result.output
    preflight.assert_not_called()
    setup_logs.assert_not_called()


def test_loopback_splunk_hec_preset_stays_blocked(tmp_path: Path) -> None:
    from defenseclaw.commands.cmd_setup_observability import observability

    app = _app(tmp_path / "hec state")
    with (
        patch("defenseclaw.platform_support.host_os", return_value="windows"),
        patch(
            "defenseclaw.commands.cmd_setup_observability.apply_preset"
        ) as apply_preset,
    ):
        result = CliRunner().invoke(
            observability,
            [
                "add",
                "splunk-hec",
                "--endpoint",
                "http://127.0.0.1:8088/services/collector/event",
                "--token",
                "test-token",
                "--non-interactive",
            ],
            obj=app,
        )
    assert result.exit_code != 0
    assert LOCAL_SPLUNK_UNSUPPORTED_REASON in result.output
    apply_preset.assert_not_called()


def test_remote_splunk_hec_remains_available(tmp_path: Path) -> None:
    from defenseclaw.commands.cmd_setup_observability import observability

    app = _app(tmp_path / "remote state")
    with (
        patch("defenseclaw.platform_support.host_os", return_value="windows"),
        patch(
            "defenseclaw.commands.cmd_setup_observability.apply_preset"
        ) as apply_preset,
    ):
        result = CliRunner().invoke(
            observability,
            [
                "add",
                "splunk-hec",
                "--endpoint",
                "https://splunk.example.test:8088/services/collector/event",
                "--token",
                "test-token",
                "--non-interactive",
            ],
            obj=app,
        )
    assert result.exit_code == 0, result.output
    apply_preset.assert_called_once()


def test_json_status_marks_local_otlp_supported_and_local_splunk_unsupported(
    tmp_path: Path,
) -> None:
    from defenseclaw.commands.cmd_setup_observability import observability

    app = _app(tmp_path / "json state")
    local = SimpleNamespace(
        name="local-observability",
        preset_id="local-otlp",
        kind="otlp",
        target="otel",
        enabled=True,
        signals={"traces": True},
        endpoint="127.0.0.1:4317",
        protocol="grpc",
        scope="global",
        connector="",
    )
    splunk = SimpleNamespace(
        name="local-splunk",
        preset_id="splunk-hec",
        kind="splunk_hec",
        target="audit_sinks",
        enabled=True,
        signals={},
        endpoint="http://127.0.0.1:8088/services/collector/event",
        protocol="http",
        scope="global",
        connector="",
    )
    with (
        patch("defenseclaw.platform_support.host_os", return_value="windows"),
        patch(
            "defenseclaw.commands.cmd_setup_observability.list_destinations",
            return_value=[local, splunk],
        ),
    ):
        result = CliRunner().invoke(observability, ["list", "--json"], obj=app)
    assert result.exit_code == 0, result.output
    payload = {item["name"]: item["platform_status"] for item in json.loads(result.output)}
    assert payload == {"local-observability": "supported", "local-splunk": "unsupported"}


def test_tui_capabilities_are_split_on_windows() -> None:
    from defenseclaw.tui.panels.setup import (
        SetupPanelModel,
        SetupWizard,
        observability_wizard_fields,
        splunk_wizard_fields,
    )
    from defenseclaw.tui.registry import build_registry

    model = SetupPanelModel(os_name="windows")
    info = next(
        item
        for item in model.wizard_infos()
        if item.wizard == SetupWizard.LOCAL_OBSERVABILITY
    )
    assert info.status != "unsupported"
    assert model.wizard_available(SetupWizard.LOCAL_OBSERVABILITY) is True
    assert any(
        entry.cli_args[:2] == ("setup", "local-observability")
        for entry in build_registry("windows")
    )

    mode = next(field for field in splunk_wizard_fields("windows") if field.label == "Mode")
    assert "local-docker" not in mode.options
    preset = next(
        field for field in observability_wizard_fields("splunk-o11y") if field.label == "Preset"
    )
    assert "local-otlp" in preset.options


def test_overview_state_marks_only_local_splunk_unsupported() -> None:
    from defenseclaw.tui.services.overview_state import (
        HealthSnapshot,
        OverviewConfig,
        OverviewPanelModel,
        SubsystemHealth,
    )

    model = OverviewPanelModel(OverviewConfig(data_dir="C:/temp"), version="test")
    model.set_health(
        HealthSnapshot(
            telemetry=SubsystemHealth(
                details={
                    "destinations": [
                        {"name": "local-observability", "preset": "local-otlp", "enabled": True}
                    ]
                }
            ),
            sinks=SubsystemHealth(
                details={
                    "sinks": [
                        {
                            "name": "local-splunk",
                            "kind": "splunk_hec",
                            "enabled": True,
                            "endpoint": "http://127.0.0.1:8088/services/collector/event",
                        }
                    ]
                }
            ),
        )
    )
    with patch("defenseclaw.platform_support.host_os", return_value="windows"):
        states = {row.name: row.state for row in model.observability_destination_rows()}
    assert states == {"local-observability": "enabled", "local-splunk": "unsupported"}


def test_platform_capability_truth_table() -> None:
    from defenseclaw.platform_support import (
        local_observability_stack_supported,
        local_splunk_stack_supported,
    )

    assert local_observability_stack_supported("windows") is True
    assert local_splunk_stack_supported("windows") is False
    for os_name in ("linux", "darwin"):
        assert local_observability_stack_supported(os_name) is True
        assert local_splunk_stack_supported(os_name) is True
