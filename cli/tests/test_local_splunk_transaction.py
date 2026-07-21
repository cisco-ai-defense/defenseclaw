# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Configuration, gateway, and platform routing transactions for Local Splunk."""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
import yaml
from click import ClickException
from click.testing import CliRunner
from defenseclaw import config
from defenseclaw.commands import cmd_setup
from defenseclaw.context import AppContext
from defenseclaw.file_permissions import atomic_write_private_bytes
from defenseclaw.observability.local_splunk import (
    LOCAL_TOKEN_ENV,
    NativeSplunkContract,
)
from defenseclaw.observability.local_stack import LocalStackError

from tests.permissions import set_known_windows_directory_acl


@pytest.fixture(autouse=True)
def _restore_local_token_environment():
    present = LOCAL_TOKEN_ENV in os.environ
    value = os.environ.get(LOCAL_TOKEN_ENV)
    os.environ.pop(LOCAL_TOKEN_ENV, None)
    yield
    if present and value is not None:
        os.environ[LOCAL_TOKEN_ENV] = value
    else:
        os.environ.pop(LOCAL_TOKEN_ENV, None)


class FakeController:
    def __init__(self, events: list[str]) -> None:
        self.events = events

    def emit_product_telemetry(self, event_type: str) -> None:
        self.events.append(f"telemetry:{event_type}")


class FakeTransaction:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.controller = FakeController(events)
        self.contract = NativeSplunkContract(
            splunk_web_url="http://127.0.0.1:8000",
            hec_url="https://127.0.0.1:8088/services/collector/event",
            hec_token="generated-" + "x" * 32,
            token_env=LOCAL_TOKEN_ENV,
            index="defenseclaw_local",
            source="defenseclaw",
            sourcetype="defenseclaw:json",
        )

    def commit(self) -> None:
        self.events.append("commit")

    def rollback(self) -> None:
        self.events.append("rollback")


def _app(tmp_path: Path) -> AppContext:
    tmp_path.mkdir(parents=True, exist_ok=True)
    if os.name == "nt":
        set_known_windows_directory_acl(tmp_path)
    atomic_write_private_bytes(
        tmp_path / "config.yaml",
        b"config_version: 8\nenvironment: preserve-me\nobservability:\n  destinations: []\n",
    )
    atomic_write_private_bytes(tmp_path / ".env", b"KEEP_ME=unchanged\n")
    app = AppContext()
    app.cfg = config.Config(data_dir=str(tmp_path))
    return app


def _invoke_native_transaction(app: AppContext, events: list[str], *, restart_ok: bool) -> None:
    transaction = FakeTransaction(events)

    def start(*_args, **_kwargs):
        events.append("runtime-ready")
        return transaction

    def write_config(*_args, **_kwargs):
        events.append("config-write")
        atomic_write_private_bytes(
            Path(app.cfg.data_dir) / "config.yaml",
            b"config_version: 8\nobservability:\n  destinations: []\n",
        )
        atomic_write_private_bytes(
            Path(app.cfg.data_dir) / ".env",
            b"KEEP_ME=unchanged\n" + LOCAL_TOKEN_ENV.encode() + b"=new-value\n"
        )

    def restart(*_args, **_kwargs):
        events.append("gateway-reload")
        return restart_ok

    with (
        patch(
            "defenseclaw.observability.local_splunk.start_native_local_splunk",
            side_effect=start,
        ),
        patch.object(cmd_setup, "_apply_v8_observability_preset", side_effect=write_config),
        patch.object(cmd_setup, "_reload_cfg_from_data_dir"),
        patch.object(cmd_setup, "_restart_defense_gateway_native", side_effect=restart),
        patch.object(cmd_setup, "_is_pid_alive", return_value=False),
    ):
        cmd_setup._apply_native_windows_logs_config(
            app,
            index="defenseclaw_local",
            source="defenseclaw",
            sourcetype="defenseclaw:json",
            s3_export=False,
            s3_bucket=None,
            s3_prefix=None,
            aws_region=None,
            refresh_bundle=True,
        )


def test_readiness_precedes_config_gateway_and_commit(tmp_path: Path) -> None:
    app = _app(tmp_path)
    events: list[str] = []
    _invoke_native_transaction(app, events, restart_ok=True)
    assert events == [
        "runtime-ready",
        "config-write",
        "gateway-reload",
        "telemetry:integration_configured",
        "commit",
    ]


def test_gateway_reload_failure_restores_exact_config_and_dotenv(
    tmp_path: Path,
) -> None:
    app = _app(tmp_path)
    cfg_path = tmp_path / "config.yaml"
    env_path = tmp_path / ".env"
    cfg_before = cfg_path.read_bytes()
    env_before = env_path.read_bytes()
    events: list[str] = []
    with pytest.raises(ClickException, match="gateway reload failed"):
        _invoke_native_transaction(app, events, restart_ok=False)
    assert cfg_path.read_bytes() == cfg_before
    assert env_path.read_bytes() == env_before
    assert "rollback" in events
    assert "commit" not in events
    assert LOCAL_TOKEN_ENV not in os.environ


def test_startup_failure_never_mutates_configuration(tmp_path: Path) -> None:
    app = _app(tmp_path)
    cfg_path = tmp_path / "config.yaml"
    env_path = tmp_path / ".env"
    before = (cfg_path.read_bytes(), env_path.read_bytes())
    with (
        patch(
            "defenseclaw.observability.local_splunk.start_native_local_splunk",
            side_effect=LocalStackError("readiness timeout"),
        ),
        patch.object(cmd_setup, "_reload_cfg_from_data_dir"),
        patch.object(cmd_setup, "_is_pid_alive", return_value=False),
        pytest.raises(ClickException, match="readiness timeout"),
    ):
        cmd_setup._apply_native_windows_logs_config(
            app,
            index="defenseclaw_local",
            source="defenseclaw",
            sourcetype="defenseclaw:json",
            s3_export=False,
            s3_bucket=None,
            s3_prefix=None,
            aws_region=None,
            refresh_bundle=True,
        )
    assert (cfg_path.read_bytes(), env_path.read_bytes()) == before


def test_keyboard_interrupt_after_runtime_start_rolls_back(tmp_path: Path) -> None:
    app = _app(tmp_path)
    events: list[str] = []
    transaction = FakeTransaction(events)
    before = ((tmp_path / "config.yaml").read_bytes(), (tmp_path / ".env").read_bytes())
    with (
        patch(
            "defenseclaw.observability.local_splunk.start_native_local_splunk",
            return_value=transaction,
        ),
        patch.object(cmd_setup, "_apply_v8_observability_preset", side_effect=KeyboardInterrupt),
        patch.object(cmd_setup, "_reload_cfg_from_data_dir"),
        patch.object(cmd_setup, "_is_pid_alive", return_value=False),
        pytest.raises(KeyboardInterrupt),
    ):
        cmd_setup._apply_native_windows_logs_config(
            app,
            index="defenseclaw_local",
            source="defenseclaw",
            sourcetype="defenseclaw:json",
            s3_export=False,
            s3_bucket=None,
            s3_prefix=None,
            aws_region=None,
            refresh_bundle=True,
        )
    assert ((tmp_path / "config.yaml").read_bytes(), (tmp_path / ".env").read_bytes()) == before
    assert events == ["rollback"]


def test_windows_routes_logs_to_native_controller(tmp_path: Path) -> None:
    app = _app(tmp_path)
    with (
        patch.object(cmd_setup.platform_support, "host_os", return_value="windows"),
        patch.object(cmd_setup, "_apply_native_windows_logs_config") as native,
        patch.object(cmd_setup, "_bootstrap_bridge") as bridge,
    ):
        cmd_setup._apply_logs_config(
            app,
            index="defenseclaw_local",
            source="defenseclaw",
            sourcetype="defenseclaw:json",
            bootstrap_bridge=True,
        )
    native.assert_called_once()
    bridge.assert_not_called()


@pytest.mark.parametrize("os_name", ["darwin", "linux"])
def test_macos_linux_keep_the_existing_bridge_path(tmp_path: Path, os_name: str) -> None:
    app = _app(tmp_path)
    contract = {
        "hec_url": "https://127.0.0.1:8088/services/collector/event",
        "hec_token": "bridge-" + "y" * 32,
    }
    with (
        patch.object(cmd_setup.platform_support, "host_os", return_value=os_name),
        patch.object(cmd_setup, "_bootstrap_bridge", return_value=contract) as bridge,
        patch.object(cmd_setup, "_apply_v8_observability_preset") as writer,
        patch.object(cmd_setup, "_reload_cfg_from_data_dir"),
        patch("defenseclaw.observability.local_splunk.start_native_local_splunk") as native,
    ):
        cmd_setup._apply_logs_config(
            app,
            index="defenseclaw_local",
            source="defenseclaw",
            sourcetype="defenseclaw:json",
            bootstrap_bridge=True,
        )
    bridge.assert_called_once()
    writer.assert_called_once()
    native.assert_not_called()


def test_local_and_remote_splunk_tokens_remain_independent(tmp_path: Path) -> None:
    app = _app(tmp_path)
    with (
        patch(
            "defenseclaw.commands.cmd_setup_observability._require_v8_operator_status",
            return_value=SimpleNamespace(destinations=()),
        ),
        patch("defenseclaw.observability.v8_writer._validate_candidate"),
    ):
        cmd_setup._apply_v8_observability_preset(
            app,
            "splunk-hec",
            {
                "endpoint": "https://127.0.0.1:8088/services/collector/event",
                "index": "defenseclaw_local",
                "source": "defenseclaw",
                "sourcetype": "defenseclaw:json",
            },
            name="local-splunk",
            secret_value="local-" + "a" * 32,
            secret_env_name=LOCAL_TOKEN_ENV,
        )
        cmd_setup._apply_v8_observability_preset(
            app,
            "splunk-enterprise",
            {
                "endpoint": "https://splunk.example.test:8088/services/collector/event",
                "index": "defenseclaw",
                "source": "defenseclaw",
                "sourcetype": "_json",
            },
            name="remote-splunk",
            secret_value="remote-" + "b" * 32,
        )
    raw = yaml.safe_load((tmp_path / "config.yaml").read_text(encoding="utf-8"))
    sinks = {
        item["name"]: item["token_env"]
        for item in raw["observability"]["destinations"]
    }
    assert sinks == {
        "local-splunk": LOCAL_TOKEN_ENV,
        "remote-splunk": "DEFENSECLAW_SPLUNK_HEC_TOKEN",
    }
    dotenv = (tmp_path / ".env").read_text(encoding="utf-8")
    assert LOCAL_TOKEN_ENV in dotenv
    assert "DEFENSECLAW_SPLUNK_HEC_TOKEN" in dotenv


def test_native_disable_selects_only_owned_local_sink(tmp_path: Path) -> None:
    app = _app(tmp_path)
    owned = SimpleNamespace(name="local-splunk", kind="splunk_hec", enabled=True, endpoint="https://127.0.0.1:8088/x")
    foreign = SimpleNamespace(
        name="operator-loopback", kind="splunk_hec", enabled=True, endpoint="https://localhost:8088/x"
    )
    disabled: list[str] = []
    with (
        patch.object(cmd_setup.platform_support, "host_os", return_value="windows"),
        patch(
            "defenseclaw.commands.cmd_setup_observability._require_v8_operator_status",
            return_value=SimpleNamespace(destinations=(owned, foreign)),
        ),
        patch(
            "defenseclaw.commands.cmd_setup_observability._set_v8_destination_enabled",
            side_effect=lambda _data_dir, name, *_: disabled.append(name),
        ),
        patch("defenseclaw.observability.local_splunk.prepare_native_local_splunk_stop", return_value=(None, False)),
        patch.object(cmd_setup, "_reload_cfg_from_data_dir"),
    ):
        cmd_setup._disable_splunk(app, False, True, False, True)
    assert disabled == ["local-splunk"]


def test_native_disable_remote_only_skips_local_runtime_preflight(tmp_path: Path) -> None:
    app = _app(tmp_path)
    remote = SimpleNamespace(
        name="remote-splunk",
        kind="splunk_hec",
        enabled=True,
        endpoint="https://splunk.example.test:8088/services/collector/event",
    )
    disabled: list[str] = []
    with (
        patch.object(cmd_setup.platform_support, "host_os", return_value="windows"),
        patch(
            "defenseclaw.commands.cmd_setup_observability._require_v8_operator_status",
            return_value=SimpleNamespace(destinations=(remote,)),
        ),
        patch(
            "defenseclaw.commands.cmd_setup_observability._set_v8_destination_enabled",
            side_effect=lambda _data_dir, name, *_: disabled.append(name),
        ),
        patch(
            "defenseclaw.observability.local_splunk.prepare_native_local_splunk_stop"
        ) as native_preflight,
        patch.object(cmd_setup, "_stop_bridge") as stop_bridge,
        patch.object(cmd_setup, "_reload_cfg_from_data_dir"),
    ):
        cmd_setup._disable_splunk(app, False, False, False, True)

    assert disabled == ["remote-splunk"]
    native_preflight.assert_not_called()
    stop_bridge.assert_not_called()


def test_native_disable_failure_restores_config_and_running_stack(tmp_path: Path) -> None:
    app = _app(tmp_path)
    config_path = tmp_path / "config.yaml"
    before = config_path.read_bytes()
    events: list[str] = []

    class Controller:
        def s3_runtime_state(self):
            return True, {"S3_EXPORT_ENABLED": "true", "S3_BUCKET": "prior-bucket"}

        def down(self):
            events.append("down")
            raise LocalStackError("compose down failed")

        def up(self, **kwargs):
            events.append(f"up:{kwargs['s3_export']}:{kwargs['overrides']['S3_BUCKET']}")

    owned = SimpleNamespace(
        name="local-splunk",
        kind="splunk_hec",
        enabled=True,
        endpoint="https://127.0.0.1:8088/x",
    )

    def mutate_config(*_args, **_kwargs):
        atomic_write_private_bytes(
            config_path,
            b"config_version: 8\nobservability:\n  destinations: []\n",
        )

    with (
        patch.object(cmd_setup.platform_support, "host_os", return_value="windows"),
        patch(
            "defenseclaw.commands.cmd_setup_observability._require_v8_operator_status",
            return_value=SimpleNamespace(destinations=(owned,)),
        ),
        patch(
            "defenseclaw.commands.cmd_setup_observability._set_v8_destination_enabled",
            side_effect=mutate_config,
        ),
        patch(
            "defenseclaw.observability.local_splunk.prepare_native_local_splunk_stop",
            return_value=(Controller(), True),
        ),
        patch.object(cmd_setup, "_reload_cfg_from_data_dir"),
        pytest.raises(ClickException, match="Splunk disable failed"),
    ):
        cmd_setup._disable_splunk(app, False, True, False, True)
    assert config_path.read_bytes() == before
    assert events == ["down", "up:True:prior-bucket"]


def test_combined_native_setup_restores_remote_writes_when_local_fails(tmp_path: Path) -> None:
    app = _app(tmp_path)
    config_path = tmp_path / "config.yaml"
    dotenv_path = tmp_path / ".env"
    before = (config_path.read_bytes(), dotenv_path.read_bytes())
    events: list[str] = []

    def remote_step(name: str):
        def mutate(*_args, **_kwargs):
            events.append(name)
            atomic_write_private_bytes(
                config_path,
                (
                    "config_version: 8\n"
                    f"environment: {name}\n"
                    "observability:\n  destinations: []\n"
                ).encode(),
            )
            atomic_write_private_bytes(dotenv_path, f"STEP={name}\n".encode())

        return mutate

    def fail_local(*_args, **_kwargs):
        events.append("logs")
        raise LocalStackError("local readiness failed")

    with (
        patch.object(cmd_setup, "_native_windows_local_splunk", return_value=True),
        patch.object(cmd_setup, "local_shell_stacks_supported", return_value=True),
        patch(
            "defenseclaw.observability.local_splunk.preflight_native_local_splunk_setup",
        ) as preflight,
        patch.object(cmd_setup, "_setup_o11y", side_effect=remote_step("o11y")),
        patch.object(cmd_setup, "_setup_enterprise", side_effect=remote_step("enterprise")),
        patch.object(cmd_setup, "_setup_logs", side_effect=fail_local),
    ):
        result = CliRunner().invoke(
            cmd_setup.setup,
            [
                "splunk",
                "--o11y",
                "--access-token",
                "o11y-token",
                "--enterprise",
                "--hec-endpoint",
                "https://splunk.example.test:8088/services/collector/event",
                "--hec-token",
                "remote-token",
                "--logs",
                "--accept-splunk-license",
                "--skip-test",
                "--non-interactive",
            ],
            obj=app,
        )
    assert result.exit_code != 0
    assert events == ["o11y", "enterprise", "logs"]
    assert (config_path.read_bytes(), dotenv_path.read_bytes()) == before
    preflight.assert_called_once()
