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


def _invoke_native_transaction(
    app: AppContext,
    events: list[str],
    *,
    restart_ok: bool,
    gateway_token_env: str = "",
    forbidden_secret: str = "",
) -> None:
    transaction = FakeTransaction(events)

    def start(*_args, **kwargs):
        environment = kwargs.get("environment")
        assert environment is not None
        blocked_names = {
            "DEFENSECLAW_GATEWAY_TOKEN",
            "OPENCLAW_GATEWAY_TOKEN",
            gateway_token_env,
        }
        assert not {name.casefold() for name in environment} & {name.casefold() for name in blocked_names if name}
        if forbidden_secret:
            assert forbidden_secret not in repr(_args)
            assert forbidden_secret not in repr(environment)
        if "NATIVE_UNRELATED_SETTING" in os.environ:
            assert environment["NATIVE_UNRELATED_SETTING"] == "preserved"
        events.append("runtime-ready")
        return transaction

    def write_config(*_args, **_kwargs):
        events.append("config-write")
        atomic_write_private_bytes(
            Path(app.cfg.data_dir) / "config.yaml",
            b"config_version: 8\nobservability:\n  destinations: []\n",
        )
        atomic_write_private_bytes(
            Path(app.cfg.data_dir) / ".env", b"KEEP_ME=unchanged\n" + LOCAL_TOKEN_ENV.encode() + b"=new-value\n"
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
            gateway_token_env=gateway_token_env,
        )


def test_readiness_precedes_config_gateway_and_commit(tmp_path: Path) -> None:
    app = _app(tmp_path)
    events: list[str] = []
    with patch.dict(
        os.environ,
        {
            "DEFENSECLAW_GATEWAY_TOKEN": "canonical-secret-sentinel",
            "OPENCLAW_GATEWAY_TOKEN": "legacy-secret-sentinel",
            "NATIVE_UNRELATED_SETTING": "preserved",
        },
    ):
        _invoke_native_transaction(app, events, restart_ok=True)
    assert events == [
        "runtime-ready",
        "config-write",
        "gateway-reload",
        "telemetry:integration_configured",
        "commit",
    ]


def test_native_start_scrubs_mixed_case_custom_gateway_token(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    app = _app(tmp_path)
    custom_name = "OPERATOR_MANAGED_GATEWAY_TOKEN"
    secret = "native-start-secret-sentinel"
    events: list[str] = []
    with patch.dict(
        os.environ,
        {
            "operator_managed_gateway_token": secret,
            "DefenseClaw_Gateway_Token": "canonical-secret-sentinel",
            "openclaw_gateway_token": "legacy-secret-sentinel",
            "NATIVE_UNRELATED_SETTING": "preserved",
        },
    ):
        _invoke_native_transaction(
            app,
            events,
            restart_ok=True,
            gateway_token_env=custom_name,
            forbidden_secret=secret,
        )

    assert secret not in repr(events)
    captured = capsys.readouterr()
    assert secret not in captured.out
    assert secret not in captured.err


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
            gateway_token_env="",
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
            gateway_token_env="",
        )
    assert ((tmp_path / "config.yaml").read_bytes(), (tmp_path / ".env").read_bytes()) == before
    assert events == ["rollback"]


def test_windows_routes_logs_to_native_controller(tmp_path: Path) -> None:
    app = _app(tmp_path)
    app.cfg.gateway.token_env = "OPERATOR_MANAGED_GATEWAY_TOKEN"
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
    assert native.call_args.kwargs["gateway_token_env"] == "OPERATOR_MANAGED_GATEWAY_TOKEN"
    bridge.assert_not_called()


@pytest.mark.parametrize(
    "configured_name",
    [
        "INVALID-TOKEN-NAME",
        " OPERATOR_MANAGED_GATEWAY_TOKEN",
        "OPERATOR_MANAGED_GATEWAY_TOKEN ",
        "defenseclaw_local_splunk_hec_token",
        "defenseclaw_local_password",
    ],
)
def test_invalid_gateway_token_name_fails_before_native_setup_or_config_mutation(
    tmp_path: Path,
    configured_name: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    app = _app(tmp_path)
    app.cfg.gateway.token_env = configured_name
    secret = "rejected-native-setup-secret-sentinel"
    before = (
        (tmp_path / "config.yaml").read_bytes(),
        (tmp_path / ".env").read_bytes(),
    )
    with patch.dict(
        os.environ,
        {
            configured_name: secret,
            configured_name.strip().swapcase(): secret,
            "NATIVE_UNRELATED_SETTING": "preserved",
        },
    ):
        with (
            patch.object(cmd_setup.platform_support, "host_os", return_value="windows"),
            patch.object(cmd_setup, "_apply_native_windows_logs_config") as native,
            patch.object(cmd_setup, "_bootstrap_bridge") as bridge,
            pytest.raises(ClickException, match="gateway.token_env"),
        ):
            cmd_setup._apply_logs_config(
                app,
                index="defenseclaw_local",
                source="defenseclaw",
                sourcetype="defenseclaw:json",
                bootstrap_bridge=True,
            )

    native.assert_not_called()
    bridge.assert_not_called()
    assert (
        (tmp_path / "config.yaml").read_bytes(),
        (tmp_path / ".env").read_bytes(),
    ) == before
    captured = capsys.readouterr()
    assert secret not in captured.out
    assert secret not in captured.err


@pytest.mark.parametrize(
    "configured_name",
    [
        " OPERATOR_MANAGED_GATEWAY_TOKEN",
        "defenseclaw_local_splunk_hec_token",
        "defenseclaw_local_username",
    ],
)
def test_native_apply_rejects_invalid_or_managed_name_before_snapshot_or_start(
    tmp_path: Path,
    configured_name: str,
) -> None:
    app = _app(tmp_path)
    before = (
        (tmp_path / "config.yaml").read_bytes(),
        (tmp_path / ".env").read_bytes(),
    )
    with (
        patch.object(cmd_setup, "_snapshot_regular_file") as config_snapshot,
        patch.object(cmd_setup, "_snapshot_dotenv") as dotenv_snapshot,
        patch("defenseclaw.observability.local_splunk.start_native_local_splunk") as native_start,
        pytest.raises(ClickException, match="gateway.token_env"),
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
            gateway_token_env=configured_name,
        )

    config_snapshot.assert_not_called()
    dotenv_snapshot.assert_not_called()
    native_start.assert_not_called()
    assert (
        (tmp_path / "config.yaml").read_bytes(),
        (tmp_path / ".env").read_bytes(),
    ) == before


@pytest.mark.parametrize("os_name", ["darwin", "linux"])
def test_macos_linux_keep_the_existing_bridge_path(tmp_path: Path, os_name: str) -> None:
    app = _app(tmp_path)
    app.cfg.gateway.token_env = "OPERATOR_MANAGED_GATEWAY_TOKEN"
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
    assert bridge.call_args.kwargs["gateway_token_env"] == "OPERATOR_MANAGED_GATEWAY_TOKEN"
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
    sinks = {item["name"]: item["token_env"] for item in raw["observability"]["destinations"]}
    assert sinks == {
        "local-splunk": LOCAL_TOKEN_ENV,
        "remote-splunk": "DEFENSECLAW_SPLUNK_HEC_TOKEN",
    }
    dotenv = (tmp_path / ".env").read_text(encoding="utf-8")
    assert LOCAL_TOKEN_ENV in dotenv
    assert "DEFENSECLAW_SPLUNK_HEC_TOKEN" in dotenv


def test_native_disable_selects_only_owned_local_sink(tmp_path: Path) -> None:
    app = _app(tmp_path)
    custom_name = "OPERATOR_MANAGED_GATEWAY_TOKEN"
    custom_secret = "native-disable-secret-sentinel"
    app.cfg.gateway.token_env = custom_name
    owned = SimpleNamespace(name="local-splunk", kind="splunk_hec", enabled=True, endpoint="https://127.0.0.1:8088/x")
    foreign = SimpleNamespace(
        name="operator-loopback", kind="splunk_hec", enabled=True, endpoint="https://localhost:8088/x"
    )
    disabled: list[str] = []
    with patch.dict(
        os.environ,
        {
            "operator_managed_gateway_token": custom_secret,
            "DefenseClaw_Gateway_Token": "canonical-secret-sentinel",
            "openclaw_gateway_token": "legacy-secret-sentinel",
            "NATIVE_UNRELATED_SETTING": "preserved",
        },
    ):
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
            patch(
                "defenseclaw.observability.local_splunk.prepare_native_local_splunk_stop",
                return_value=(None, False),
            ) as prepare,
            patch.object(cmd_setup, "_reload_cfg_from_data_dir"),
        ):
            cmd_setup._disable_splunk(app, False, True, False, True)
    assert disabled == ["local-splunk"]
    environment = prepare.call_args.kwargs["environment"]
    assert not {
        "operator_managed_gateway_token",
        "DefenseClaw_Gateway_Token",
        "openclaw_gateway_token",
    } & set(environment)
    assert environment["NATIVE_UNRELATED_SETTING"] == "preserved"
    assert custom_secret not in repr(prepare.call_args)


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
        patch("defenseclaw.observability.local_splunk.prepare_native_local_splunk_stop") as native_preflight,
        patch.object(cmd_setup, "_stop_bridge") as stop_bridge,
        patch.object(cmd_setup, "_reload_cfg_from_data_dir"),
    ):
        cmd_setup._disable_splunk(app, False, False, False, True)

    assert disabled == ["remote-splunk"]
    native_preflight.assert_not_called()
    stop_bridge.assert_not_called()


def test_native_disable_failure_restores_config_and_running_stack(tmp_path: Path) -> None:
    app = _app(tmp_path)
    custom_name = "OPERATOR_MANAGED_GATEWAY_TOKEN"
    app.cfg.gateway.token_env = custom_name
    config_path = tmp_path / "config.yaml"
    before = config_path.read_bytes()
    events: list[str] = []

    class Controller:
        def __init__(self, environment: dict[str, str]) -> None:
            self.environment = environment

        def assert_sanitized_environment(self) -> None:
            environment_names = {name.casefold() for name in self.environment}
            assert not environment_names & {
                custom_name.casefold(),
                "defenseclaw_gateway_token",
                "openclaw_gateway_token",
            }
            assert self.environment["NATIVE_UNRELATED_SETTING"] == "preserved"
            assert "custom-secret-sentinel" not in repr(self.environment)
            assert "canonical-secret-sentinel" not in repr(self.environment)
            assert "legacy-secret-sentinel" not in repr(self.environment)

        def s3_runtime_state(self):
            self.assert_sanitized_environment()
            return True, {"S3_EXPORT_ENABLED": "true", "S3_BUCKET": "prior-bucket"}

        def down(self):
            self.assert_sanitized_environment()
            events.append("down")
            raise LocalStackError("compose down failed")

        def up(self, **kwargs):
            self.assert_sanitized_environment()
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

    def prepare(*_args, **kwargs):
        return Controller(kwargs["environment"]), True

    with patch.dict(
        os.environ,
        {
            "operator_managed_gateway_token": "custom-secret-sentinel",
            "DefenseClaw_Gateway_Token": "canonical-secret-sentinel",
            "openclaw_gateway_token": "legacy-secret-sentinel",
            "NATIVE_UNRELATED_SETTING": "preserved",
        },
    ):
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
                side_effect=prepare,
            ),
            patch.object(cmd_setup, "_reload_cfg_from_data_dir"),
            pytest.raises(ClickException, match="Splunk disable failed"),
        ):
            cmd_setup._disable_splunk(app, False, True, False, True)
    assert config_path.read_bytes() == before
    assert events == ["down", "up:True:prior-bucket"]


@pytest.mark.parametrize(
    "configured_name",
    [
        "INVALID-TOKEN-NAME",
        " OPERATOR_MANAGED_GATEWAY_TOKEN",
        "OPERATOR_MANAGED_GATEWAY_TOKEN ",
        "defenseclaw_local_splunk_hec_token",
        "defenseclaw_local_password",
    ],
)
def test_invalid_gateway_token_name_fails_before_native_disable_side_effects(
    tmp_path: Path,
    configured_name: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    app = _app(tmp_path)
    app.cfg.gateway.token_env = configured_name
    secret = "rejected-native-disable-secret-sentinel"
    before = (tmp_path / "config.yaml").read_bytes()
    with patch.dict(
        os.environ,
        {
            configured_name: secret,
            configured_name.strip().swapcase(): secret,
            "NATIVE_UNRELATED_SETTING": "preserved",
        },
    ):
        with (
            patch.object(cmd_setup.platform_support, "host_os", return_value="windows"),
            patch("defenseclaw.commands.cmd_setup_observability._require_v8_operator_status") as status,
            patch("defenseclaw.commands.cmd_setup_observability._set_v8_destination_enabled") as writer,
            patch("defenseclaw.observability.local_splunk.prepare_native_local_splunk_stop") as prepare,
            pytest.raises(ClickException, match="gateway.token_env"),
        ):
            cmd_setup._disable_splunk(app, False, True, False, True)

    status.assert_not_called()
    writer.assert_not_called()
    prepare.assert_not_called()
    assert (tmp_path / "config.yaml").read_bytes() == before
    captured = capsys.readouterr()
    assert secret not in captured.out
    assert secret not in captured.err


def test_combined_native_setup_restores_remote_writes_when_local_fails(tmp_path: Path) -> None:
    app = _app(tmp_path)
    custom_name = "OPERATOR_MANAGED_GATEWAY_TOKEN"
    custom_secret = "native-preflight-secret-sentinel"
    app.cfg.gateway.token_env = custom_name
    config_path = tmp_path / "config.yaml"
    dotenv_path = tmp_path / ".env"
    before = (config_path.read_bytes(), dotenv_path.read_bytes())
    events: list[str] = []

    def remote_step(name: str):
        def mutate(*_args, **_kwargs):
            events.append(name)
            atomic_write_private_bytes(
                config_path,
                (f"config_version: 8\nenvironment: {name}\nobservability:\n  destinations: []\n").encode(),
            )
            atomic_write_private_bytes(dotenv_path, f"STEP={name}\n".encode())

        return mutate

    def fail_local(*_args, **_kwargs):
        events.append("logs")
        raise LocalStackError("local readiness failed")

    with patch.dict(
        os.environ,
        {
            "operator_managed_gateway_token": custom_secret,
            "DefenseClaw_Gateway_Token": "canonical-secret-sentinel",
            "openclaw_gateway_token": "legacy-secret-sentinel",
            "NATIVE_UNRELATED_SETTING": "preserved",
        },
    ):
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
    environment = preflight.call_args.kwargs["environment"]
    assert not {
        "operator_managed_gateway_token",
        "DefenseClaw_Gateway_Token",
        "openclaw_gateway_token",
    } & set(environment)
    assert environment["NATIVE_UNRELATED_SETTING"] == "preserved"
    assert custom_secret not in repr(preflight.call_args)


@pytest.mark.parametrize(
    "configured_name",
    [
        "INVALID-TOKEN-NAME",
        " OPERATOR_MANAGED_GATEWAY_TOKEN",
        "OPERATOR_MANAGED_GATEWAY_TOKEN ",
        "defenseclaw_local_splunk_hec_token",
        "defenseclaw_local_password",
    ],
)
def test_invalid_gateway_token_name_fails_before_combined_native_preflight_or_writes(
    tmp_path: Path,
    configured_name: str,
) -> None:
    app = _app(tmp_path)
    app.cfg.gateway.token_env = configured_name
    secret = "rejected-native-preflight-secret-sentinel"
    config_path = tmp_path / "config.yaml"
    dotenv_path = tmp_path / ".env"
    before = (config_path.read_bytes(), dotenv_path.read_bytes())

    with patch.dict(
        os.environ,
        {
            configured_name: secret,
            configured_name.strip().swapcase(): secret,
            "NATIVE_UNRELATED_SETTING": "preserved",
        },
    ):
        with (
            patch.object(cmd_setup, "_native_windows_local_splunk", return_value=True),
            patch.object(cmd_setup, "local_shell_stacks_supported", return_value=True),
            patch(
                "defenseclaw.observability.local_splunk.preflight_native_local_splunk_setup",
            ) as preflight,
            patch.object(cmd_setup, "_setup_o11y") as setup_o11y,
            patch.object(cmd_setup, "_setup_enterprise") as setup_enterprise,
            patch.object(cmd_setup, "_setup_logs") as setup_logs,
        ):
            result = CliRunner().invoke(
                cmd_setup.setup,
                [
                    "splunk",
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
    assert "gateway.token_env" in result.output
    preflight.assert_not_called()
    setup_o11y.assert_not_called()
    setup_enterprise.assert_not_called()
    setup_logs.assert_not_called()
    assert (config_path.read_bytes(), dotenv_path.read_bytes()) == before
    assert secret not in result.output
