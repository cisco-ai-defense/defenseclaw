# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Native-Windows capability gates for Bash-backed local telemetry stacks."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from click.testing import CliRunner
from defenseclaw import config
from defenseclaw.context import AppContext
from defenseclaw.platform_support import LOCAL_SHELL_STACKS_UNSUPPORTED_REASON


def _app(data_dir: Path) -> AppContext:
    data_dir.mkdir(parents=True)
    (data_dir / "config.yaml").write_bytes(b"config_version: 4\ncustom: keep-me\n")
    app = AppContext()
    app.cfg = config.Config(data_dir=str(data_dir))
    return app


def _snapshot(root: Path) -> dict[str, bytes]:
    return {
        str(path.relative_to(root)): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }


@pytest.mark.parametrize(
    "args",
    [
        (),
        ("up",),
        ("down", "--disable-config"),
        ("reset", "--yes"),
        ("status",),
        ("logs", "--service", "otel-collector"),
        ("url", "--json"),
    ],
)
def test_local_observability_cli_gates_every_route_before_helpers_and_writes(
    tmp_path: Path, args: tuple[str, ...]
) -> None:
    from defenseclaw.commands.cmd_setup_local_observability import local_observability

    data_dir = tmp_path / "state with spaces"
    app = _app(data_dir)
    before = _snapshot(data_dir)
    with (
        patch(
            "defenseclaw.commands.cmd_setup_local_observability.local_shell_stacks_supported",
            return_value=False,
        ),
        patch("defenseclaw.commands.cmd_setup_local_observability._resolve_bridge") as resolve,
        patch("defenseclaw.commands.cmd_setup_local_observability.subprocess.run") as run,
        patch(
            "defenseclaw.commands.cmd_setup_local_observability.refresh_local_observability_stack"
        ) as refresh,
    ):
        result = CliRunner().invoke(local_observability, list(args), obj=app)

    assert result.exit_code != 0
    assert LOCAL_SHELL_STACKS_UNSUPPORTED_REASON in result.output
    assert "Traceback" not in result.output
    resolve.assert_not_called()
    run.assert_not_called()
    refresh.assert_not_called()
    assert _snapshot(data_dir) == before


@pytest.mark.parametrize(
    "args",
    [
        ("splunk", "--logs", "--non-interactive", "--accept-splunk-license"),
        ("splunk", "--s3-export", "--s3-bucket", "bucket", "--non-interactive", "--accept-splunk-license"),
        ("splunk", "--disable", "--logs"),
        (
            "splunk",
            "--o11y",
            "--logs",
            "--access-token",
            "remote-token",
            "--non-interactive",
            "--accept-splunk-license",
        ),
    ],
)
def test_local_splunk_cli_gates_before_remote_or_local_side_effects(
    tmp_path: Path, args: tuple[str, ...]
) -> None:
    from defenseclaw.commands.cmd_setup import setup

    data_dir = tmp_path / "state with spaces"
    app = _app(data_dir)
    before = _snapshot(data_dir)
    with (
        patch("defenseclaw.commands.cmd_setup.local_shell_stacks_supported", return_value=False),
        patch("defenseclaw.commands.cmd_setup._setup_o11y") as o11y,
        patch("defenseclaw.commands.cmd_setup._preflight_docker") as preflight,
        patch("defenseclaw.commands.cmd_setup._ensure_private_splunk_bridge_env") as env_file,
        patch("defenseclaw.commands.cmd_setup._resolve_bridge_bin") as resolve,
        patch("defenseclaw.commands.cmd_setup.subprocess.run") as run,
    ):
        result = CliRunner().invoke(setup, list(args), obj=app)

    assert result.exit_code != 0
    assert LOCAL_SHELL_STACKS_UNSUPPORTED_REASON in result.output
    assert "Traceback" not in result.output
    o11y.assert_not_called()
    preflight.assert_not_called()
    env_file.assert_not_called()
    resolve.assert_not_called()
    run.assert_not_called()
    assert _snapshot(data_dir) == before


def test_splunk_show_credentials_remains_read_only_on_windows(tmp_path: Path) -> None:
    from defenseclaw.commands.cmd_setup import setup

    data_dir = tmp_path / "read only credentials"
    app = _app(data_dir)
    before = _snapshot(data_dir)
    with patch("defenseclaw.commands.cmd_setup.local_shell_stacks_supported", return_value=False):
        result = CliRunner().invoke(setup, ["splunk", "--show-credentials"], obj=app)

    assert result.exit_code == 0, result.output
    assert "Splunk credentials not found" in result.output
    assert LOCAL_SHELL_STACKS_UNSUPPORTED_REASON not in result.output
    assert _snapshot(data_dir) == before


def test_interactive_splunk_hides_local_choice_but_keeps_remote_choices(tmp_path: Path) -> None:
    from defenseclaw.commands.cmd_setup import setup

    data_dir = tmp_path / "interactive state"
    app = _app(data_dir)
    before = _snapshot(data_dir)
    with (
        patch("defenseclaw.commands.cmd_setup.local_shell_stacks_supported", return_value=False),
        patch("defenseclaw.commands.cmd_setup._interactive_logs") as local_logs,
        patch("defenseclaw.commands.cmd_setup._preflight_docker") as preflight,
    ):
        result = CliRunner().invoke(setup, ["splunk"], obj=app, input="n\nn\n")

    assert result.exit_code == 0, result.output
    assert LOCAL_SHELL_STACKS_UNSUPPORTED_REASON in result.output
    assert "Enable local Splunk" not in result.output
    local_logs.assert_not_called()
    preflight.assert_not_called()
    assert _snapshot(data_dir) == before


@pytest.mark.parametrize(
    "args, helper",
    [
        (("splunk", "--o11y", "--access-token", "token", "--non-interactive"), "_setup_o11y"),
        (
            (
                "splunk",
                "--enterprise",
                "--hec-endpoint",
                "https://splunk.example.test:8088/services/collector/event",
                "--hec-token",
                "token",
                "--non-interactive",
                "--skip-test",
            ),
            "_setup_enterprise",
        ),
    ],
)
def test_remote_splunk_routes_remain_available_on_windows(
    tmp_path: Path, args: tuple[str, ...], helper: str
) -> None:
    from defenseclaw.commands.cmd_setup import setup

    app = _app(tmp_path / "remote state")
    with (
        patch("defenseclaw.commands.cmd_setup.local_shell_stacks_supported", return_value=False),
        patch(f"defenseclaw.commands.cmd_setup.{helper}") as remote,
        patch("defenseclaw.commands.cmd_setup._print_splunk_status"),
        patch("defenseclaw.commands.cmd_setup.print_redaction_status_hint"),
    ):
        result = CliRunner().invoke(setup, list(args), obj=app)

    assert result.exit_code == 0, result.output
    remote.assert_called_once()
    assert "Traceback" not in result.output


def test_generic_local_otlp_preset_gates_before_prompt_or_write(tmp_path: Path) -> None:
    from defenseclaw.commands.cmd_setup_observability import observability

    data_dir = tmp_path / "preset state"
    app = _app(data_dir)
    before = _snapshot(data_dir)
    with (
        patch(
            "defenseclaw.commands.cmd_setup_observability.local_shell_stacks_supported",
            return_value=False,
        ),
        patch("defenseclaw.commands.cmd_setup_observability.apply_preset") as apply,
    ):
        result = CliRunner().invoke(
            observability,
            ["add", "local-otlp", "--non-interactive"],
            obj=app,
        )

    assert result.exit_code != 0
    assert LOCAL_SHELL_STACKS_UNSUPPORTED_REASON in result.output
    assert "Traceback" not in result.output
    apply.assert_not_called()
    assert _snapshot(data_dir) == before


@pytest.mark.parametrize(
    "args",
    [
        ("enable", "local-observability"),
        ("disable", "local-observability"),
        ("remove", "local-observability", "--yes"),
        ("test", "local-observability"),
    ],
)
def test_generic_observability_management_gates_existing_local_destination(
    tmp_path: Path, args: tuple[str, ...]
) -> None:
    from defenseclaw.commands.cmd_setup_observability import observability

    data_dir = tmp_path / "existing local state"
    app = _app(data_dir)
    before = _snapshot(data_dir)
    destination = SimpleNamespace(
        name="local-observability",
        preset_id="local-otlp",
        kind="otlp",
        target="otel",
        enabled=True,
        signals={"traces": True},
        endpoint="127.0.0.1:4317",
        protocol="grpc",
    )
    with (
        patch(
            "defenseclaw.commands.cmd_setup_observability.local_shell_stacks_supported",
            return_value=False,
        ),
        patch(
            "defenseclaw.commands.cmd_setup_observability.list_destinations",
            return_value=[destination],
        ),
        patch("defenseclaw.commands.cmd_setup_observability.set_destination_enabled") as enable,
        patch("defenseclaw.commands.cmd_setup_observability.remove_destination") as remove,
        patch("defenseclaw.commands.cmd_setup_observability._test_otel") as probe,
    ):
        result = CliRunner().invoke(observability, list(args), obj=app)

    assert result.exit_code != 0
    assert LOCAL_SHELL_STACKS_UNSUPPORTED_REASON in result.output
    assert "Traceback" not in result.output
    enable.assert_not_called()
    remove.assert_not_called()
    probe.assert_not_called()
    assert _snapshot(data_dir) == before


def test_observability_json_status_labels_local_unsupported_and_remote_supported(
    tmp_path: Path,
) -> None:
    from defenseclaw.commands.cmd_setup_observability import observability

    app = _app(tmp_path / "json status")
    local = SimpleNamespace(
        name="local-observability",
        preset_id="local-otlp",
        kind="otlp",
        target="otel",
        enabled=True,
        signals={"traces": True},
        endpoint="127.0.0.1:4317",
        protocol="grpc",
    )
    remote = SimpleNamespace(
        name="remote-otlp",
        preset_id="otlp",
        kind="otlp",
        target="otel",
        enabled=True,
        signals={"traces": True},
        endpoint="collector.example.test:4317",
        protocol="grpc",
    )
    with (
        patch(
            "defenseclaw.commands.cmd_setup_observability.local_shell_stacks_supported",
            return_value=False,
        ),
        patch(
            "defenseclaw.platform_support.local_shell_stacks_supported",
            return_value=False,
        ),
        patch(
            "defenseclaw.commands.cmd_setup_observability.list_destinations",
            return_value=[local, remote],
        ),
    ):
        result = CliRunner().invoke(observability, ["list", "--json"], obj=app)

    assert result.exit_code == 0, result.output
    assert '"name": "local-observability"' in result.output
    assert '"platform_status": "unsupported"' in result.output
    assert '"platform_status": "supported"' in result.output


def test_generic_observability_local_splunk_endpoint_gates_before_secret_or_write(
    tmp_path: Path,
) -> None:
    from defenseclaw.commands.cmd_setup_observability import observability

    data_dir = tmp_path / "local splunk preset"
    app = _app(data_dir)
    before = _snapshot(data_dir)
    with (
        patch(
            "defenseclaw.commands.cmd_setup_observability.local_shell_stacks_supported",
            return_value=False,
        ),
        patch("defenseclaw.commands.cmd_setup_observability.apply_preset") as apply,
        patch("defenseclaw.commands.cmd_setup_observability._prompt_secret") as secret_prompt,
    ):
        result = CliRunner().invoke(
            observability,
            [
                "add",
                "splunk-hec",
                "--endpoint",
                "http://127.0.0.1:8088/services/collector/event",
                "--non-interactive",
            ],
            obj=app,
        )

    assert result.exit_code != 0
    assert LOCAL_SHELL_STACKS_UNSUPPORTED_REASON in result.output
    secret_prompt.assert_not_called()
    apply.assert_not_called()
    assert _snapshot(data_dir) == before


def test_generic_observability_resolves_local_splunk_defaults_before_gate(
    tmp_path: Path,
) -> None:
    from defenseclaw.commands.cmd_setup_observability import observability

    data_dir = tmp_path / "default local splunk preset"
    app = _app(data_dir)
    before = _snapshot(data_dir)
    with (
        patch(
            "defenseclaw.commands.cmd_setup_observability.local_shell_stacks_supported",
            return_value=False,
        ),
        patch("defenseclaw.commands.cmd_setup_observability.apply_preset") as apply,
    ):
        result = CliRunner().invoke(
            observability,
            ["add", "splunk-hec", "--non-interactive"],
            obj=app,
        )

    assert result.exit_code != 0
    assert LOCAL_SHELL_STACKS_UNSUPPORTED_REASON in result.output
    apply.assert_not_called()
    assert _snapshot(data_dir) == before


def test_splunk_enterprise_loopback_is_not_treated_as_bundled_local_stack(
    tmp_path: Path,
) -> None:
    from defenseclaw.commands.cmd_setup_observability import observability
    from defenseclaw.observability import list_destinations

    data_dir = tmp_path / "loopback enterprise"
    app = _app(data_dir)
    with patch(
        "defenseclaw.commands.cmd_setup_observability.local_shell_stacks_supported",
        return_value=False,
    ):
        result = CliRunner().invoke(
            observability,
            [
                "add",
                "splunk-enterprise",
                "--endpoint",
                "http://localhost:8088/services/collector/event",
                "--token",
                "synthetic-token",
                "--non-interactive",
            ],
            obj=app,
        )

    assert result.exit_code == 0, result.output
    destinations = list_destinations(str(data_dir))
    assert len(destinations) == 1
    assert destinations[0].preset_id == "splunk-enterprise"


def test_legacy_local_splunk_migration_is_gated_before_config_write(tmp_path: Path) -> None:
    from defenseclaw.commands.cmd_setup_observability import observability

    data_dir = tmp_path / "legacy local splunk"
    data_dir.mkdir(parents=True)
    config_bytes = (
        b"config_version: 4\n"
        b"splunk:\n"
        b"  enabled: true\n"
        b"  hec_endpoint: http://127.0.0.1:8088/services/collector/event\n"
    )
    (data_dir / "config.yaml").write_bytes(config_bytes)
    app = AppContext()
    app.cfg = config.Config(data_dir=str(data_dir))
    with (
        patch(
            "defenseclaw.commands.cmd_setup_observability.local_shell_stacks_supported",
            return_value=False,
        ),
        patch("defenseclaw.commands.cmd_setup_observability.write_config_yaml_secure") as write,
    ):
        result = CliRunner().invoke(
            observability,
            ["migrate-splunk", "--apply"],
            obj=app,
        )

    assert result.exit_code != 0
    assert LOCAL_SHELL_STACKS_UNSUPPORTED_REASON in result.output
    write.assert_not_called()
    assert (data_dir / "config.yaml").read_bytes() == config_bytes


def test_tui_disables_local_actions_and_preserves_remote_options() -> None:
    from defenseclaw.tui.panels.setup import (
        SetupPanelModel,
        SetupWizard,
        observability_wizard_fields,
        splunk_wizard_fields,
        wizard_goals,
    )
    from defenseclaw.tui.registry import build_registry

    model = SetupPanelModel(os_name="windows")
    info = next(item for item in model.wizard_infos() if item.wizard == SetupWizard.LOCAL_OBSERVABILITY)
    assert info.status == "unsupported"
    assert model.wizard_available(SetupWizard.LOCAL_OBSERVABILITY) is False
    model.active_wizard = SetupWizard.LOCAL_OBSERVABILITY
    assert model.active_wizard_info().status == "unsupported"
    assert model.open_goal_menu(SetupWizard.LOCAL_OBSERVABILITY) is False
    assert model.form_active is False

    splunk_fields = splunk_wizard_fields("windows")
    mode = next(field for field in splunk_fields if field.label == "Mode")
    assert "local-docker" not in mode.options
    assert "enterprise" in mode.options
    assert "splunk-o11y" in mode.options
    assert not any(field.label == "Enable Local Logs" for field in splunk_fields)
    with patch("defenseclaw.tui.panels.setup.local_shell_stacks_supported", return_value=False):
        assert all(goal.id != "local-docker" for goal in wizard_goals(SetupWizard.SPLUNK))
        presets = next(field for field in observability_wizard_fields("splunk-o11y") if field.label == "Preset")
        assert "local-otlp" not in presets.options
        assert "otlp" in presets.options

    registry = build_registry("windows")
    assert not any(entry.cli_args[:2] == ("setup", "local-observability") for entry in registry)
    assert any(entry.cli_args[:2] == ("setup", "splunk") for entry in registry)


def test_tui_existing_local_state_is_unsupported_while_remote_stays_enabled() -> None:
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
                        {"name": "local-observability", "preset": "local-otlp", "enabled": True},
                        {"name": "remote-otlp", "preset": "otlp", "enabled": True},
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
                        },
                        {
                            "name": "remote-splunk",
                            "kind": "splunk_hec",
                            "enabled": True,
                            "endpoint": "https://splunk.example.test:8088/services/collector/event",
                        },
                    ]
                }
            ),
        )
    )
    with patch(
        "defenseclaw.tui.services.overview_state.local_shell_stacks_supported",
        return_value=False,
    ):
        states = {row.name: row.state for row in model.observability_destination_rows()}

    assert states == {
        "local-observability": "unsupported",
        "remote-otlp": "enabled",
        "local-splunk": "unsupported",
        "remote-splunk": "enabled",
    }


def test_cli_status_labels_existing_local_state_unsupported(capsys) -> None:
    from defenseclaw.commands.cmd_status import _print_observability_status

    destinations = [
        SimpleNamespace(
            name="local-observability",
            preset_id="local-otlp",
            kind="otlp",
            target="otel",
            enabled=True,
            signals={"traces": True},
            endpoint="127.0.0.1:4317",
        ),
        SimpleNamespace(
            name="remote-otlp",
            preset_id="otlp",
            kind="otlp",
            target="otel",
            enabled=True,
            signals={"traces": True},
            endpoint="collector.example.test:4317",
        ),
    ]
    with (
        patch("defenseclaw.observability.list_destinations", return_value=destinations),
        patch("defenseclaw.platform_support.local_shell_stacks_supported", return_value=False),
    ):
        _print_observability_status(SimpleNamespace(data_dir="unused"))

    output = capsys.readouterr().out
    assert "local-observability" in output
    assert "unsupported on native Windows" in output
    assert "remote-otlp" in output
    assert "enabled" in output


@pytest.mark.parametrize("os_name", ["linux", "darwin"])
def test_supported_platform_capability_and_tui_routes_are_unchanged(os_name: str) -> None:
    from defenseclaw.platform_support import local_shell_stacks_supported
    from defenseclaw.tui.panels.setup import splunk_wizard_fields
    from defenseclaw.tui.registry import build_registry

    assert local_shell_stacks_supported(os_name) is True
    mode = next(field for field in splunk_wizard_fields(os_name) if field.label == "Mode")
    assert "local-docker" in mode.options
    assert any(entry.cli_args[:2] == ("setup", "local-observability") for entry in build_registry(os_name))
