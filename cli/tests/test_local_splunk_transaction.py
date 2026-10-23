# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Configuration, gateway, and platform routing transactions for Local Splunk."""

from __future__ import annotations

import json
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
from defenseclaw.observability.local_stack import CommandResult, LocalStackError

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
    docker_path = "docker"
    runner = None
    environment: dict[str, str] = {}

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
        )
    bridge.assert_called_once()
    assert bridge.call_args.kwargs["gateway_token_env"] == "OPERATOR_MANAGED_GATEWAY_TOKEN"
    writer.assert_called_once()
    native.assert_not_called()


_FULL_ID = "0123456789abcdef" * 4
_DEFAULT_HEC = "https://127.0.0.1:8088/services/collector/event"
_REMOTE_HEC = "https://splunk.example.test:8088/services/collector/event"
_SHARED = "DEFENSECLAW_SPLUNK_HEC_TOKEN"
_LOGS = {"index": "defenseclaw_local", "source": "defenseclaw", "sourcetype": "defenseclaw:json"}
_RECORD = {"marker": "defenseclaw-local-splunk", "container_id": _FULL_ID}


@pytest.fixture(autouse=True)
def _local_splunk_container():
    """Local setup records the container it started; these tests run without Docker."""

    with (
        patch.object(cmd_setup, "_local_splunk_container_id", return_value=_FULL_ID, create=True),
        patch(
            "defenseclaw.observability.local_splunk.running_splunk_container_id", return_value=_FULL_ID, create=True
        ),
    ):
        yield


def _v8_writer_patches():
    return (
        patch(
            "defenseclaw.commands.cmd_setup_observability._require_v8_operator_status",
            return_value=SimpleNamespace(destinations=()),
        ),
        patch("defenseclaw.observability.v8_writer._validate_candidate"),
    )


def _destinations(data_dir: Path) -> dict[str, dict]:
    raw = yaml.safe_load((data_dir / "config.yaml").read_text(encoding="utf-8"))
    return {item["name"]: item for item in raw["observability"]["destinations"]}


def _dotenv(data_dir: Path) -> dict[str, str]:
    from defenseclaw.observability.v8_presets import _load_dotenv

    return _load_dotenv((data_dir / ".env").read_bytes())


def _write_state(data_dir: Path, destinations: list[dict], dotenv: dict[str, str]) -> None:
    raw = yaml.safe_load((data_dir / "config.yaml").read_bytes())
    raw["observability"]["destinations"] = destinations
    atomic_write_private_bytes(data_dir / "config.yaml", yaml.safe_dump(raw).encode())
    atomic_write_private_bytes(data_dir / ".env", "".join(f"{k}='{v}'\n" for k, v in dotenv.items()).encode())


def _write_bridge_contract(data_dir: Path, token: str) -> None:
    # The private env file of the local stack, which outlives its sink.
    bridge_env = data_dir / "splunk-bridge" / "env" / ".env"
    bridge_env.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_private_bytes(bridge_env, f"DEFENSECLAW_HEC_TOKEN='{token}'\nDEFENSECLAW_HEC_URL={_DEFAULT_HEC}\n".encode())


def _hec(name: str, endpoint: str, token_env: str, **extra) -> dict:
    return {
        "name": name, "kind": "splunk_hec", "enabled": True, "endpoint": endpoint, "token_env": token_env,
        "network_safety": {"allow_private_networks": True}, **extra,
    }


def _remove(data_dir: Path, name: str) -> None:
    from defenseclaw.commands.cmd_setup_observability import _remove_v8_destination

    status, validate = _v8_writer_patches()
    with status, validate:
        _remove_v8_destination(str(data_dir), name)


def _unix_local_setup(app: AppContext, hec_url: str = _DEFAULT_HEC, token: str = "local fixture credential"):
    status, validate = _v8_writer_patches()
    with (
        status, validate,
        patch.object(cmd_setup, "_native_windows_local_splunk", return_value=False),
        patch.object(cmd_setup, "_bootstrap_bridge", return_value={"hec_url": hec_url, "hec_token": token}) as bridge,
        patch.object(cmd_setup, "_reload_cfg_from_data_dir"),
    ):
        cmd_setup._apply_logs_config(app, **_LOGS)
    return bridge


def _native_local_setup(app: AppContext) -> list[str]:
    events: list[str] = []
    status, validate = _v8_writer_patches()
    with (
        status, validate,
        patch("defenseclaw.observability.local_splunk.start_native_local_splunk",
              side_effect=lambda *_a, **_k: (events.append("start"), FakeTransaction(events))[1]),
        patch.object(cmd_setup, "_reload_cfg_from_data_dir"),
        patch.object(cmd_setup, "_restart_defense_gateway_native", return_value=True),
        patch.object(cmd_setup, "_is_pid_alive", return_value=False),
    ):
        cmd_setup._apply_native_windows_logs_config(
            app, **_LOGS, s3_export=False, s3_bucket=None, s3_prefix=None, aws_region=None,
            refresh_bundle=True, gateway_token_env="",
        )
    return events


def _remote_setup(app: AppContext, name: str, endpoint: str, token: str | None, **kwargs) -> str:
    status, validate = _v8_writer_patches()
    with status, validate:
        return cmd_setup._apply_v8_observability_preset(
            app, "splunk-enterprise", {"endpoint": endpoint}, name=name, secret_value=token,
            allow_private_networks=True, **kwargs,
        )


def test_local_setup_records_the_container_it_started(tmp_path: Path) -> None:
    # The record (the container setup started, with DefenseClaw's marker) is
    # stored in the sink's config, and a rerun updates that recorded sink even
    # when the bridge moved to another address.
    unix = _app(tmp_path / "unix")
    _unix_local_setup(unix)
    sink = _destinations(tmp_path / "unix")["splunk-hec-127-0-0-1"]
    assert sink["local_stack"] == _RECORD
    assert sink["token_env"] == LOCAL_TOKEN_ENV
    assert _dotenv(tmp_path / "unix")[LOCAL_TOKEN_ENV] == "local fixture credential"
    _unix_local_setup(unix, hec_url="https://localhost:28088/services/collector/event")
    sinks = _destinations(tmp_path / "unix")
    assert list(sinks) == ["splunk-hec-127-0-0-1"]
    assert sinks["splunk-hec-127-0-0-1"]["endpoint"] == "https://localhost:28088/services/collector/event"
    assert sinks["splunk-hec-127-0-0-1"]["local_stack"] == _RECORD

    native = _app(tmp_path / "native")
    assert _native_local_setup(native) == ["start", "telemetry:integration_configured", "commit"]
    sink = _destinations(tmp_path / "native")["local-splunk"]
    assert sink["local_stack"] == _RECORD
    assert sink["token_env"] == LOCAL_TOKEN_ENV


@pytest.mark.parametrize(
    ("state", "name", "endpoint", "where"),
    [
        # The finding: an older setup's local sink was removed, its bridge
        # contract stayed, and a remote tunnel has the removed sink's name,
        # listener and old token.
        ("legacy-removed", "splunk-hec-127-0-0-1", _DEFAULT_HEC, "dotenv"),
        ("legacy-removed", "splunk-hec-127-0-0-1", _DEFAULT_HEC, "environment"),
        ("legacy-removed", "local-splunk", _DEFAULT_HEC, "dotenv"),
        ("legacy-removed", "splunk-hec-localhost", "https://localhost:8088/services/collector/event", "dotenv"),
        ("legacy-removed", "tunnel", "https://[::1]:8088/services/collector/event", "environment"),
        # Same after a recorded local setup whose sink was removed.
        ("recorded-removed", "splunk-hec-127-0-0-1", _DEFAULT_HEC, "dotenv"),
    ],
)
def test_remote_destination_is_never_the_local_sink(
    tmp_path: Path, monkeypatch, state: str, name: str, endpoint: str, where: str
) -> None:
    app = _app(tmp_path)
    monkeypatch.delenv(_SHARED, raising=False)
    local_token = "local fixture credential"
    remote_token = "independent remote fixture credential"
    _write_bridge_contract(tmp_path, local_token)
    dotenv = {"KEEP_ME": "unchanged"}
    if state == "recorded-removed":
        _unix_local_setup(app, token=local_token)
        _remove(tmp_path, "splunk-hec-127-0-0-1")
        dotenv = _dotenv(tmp_path)
        monkeypatch.delenv(LOCAL_TOKEN_ENV, raising=False)
    tunnel = _hec(name, endpoint, _SHARED)
    if where == "dotenv":
        dotenv[_SHARED] = local_token
    else:
        monkeypatch.setenv(_SHARED, local_token)
    _write_state(tmp_path, [tunnel], dotenv)

    assert _remote_setup(app, "new-remote", _REMOTE_HEC, remote_token) == "new-remote"
    sinks = _destinations(tmp_path)
    assert sinks[name] == tunnel
    assert sinks["new-remote"]["token_env"] == f"{_SHARED}_NEW_REMOTE"
    saved = _dotenv(tmp_path)
    assert saved[f"{_SHARED}_NEW_REMOTE"] == remote_token
    assert saved.get(_SHARED) == dotenv.get(_SHARED)
    assert cmd_setup._recorded_local_splunk_names(str(tmp_path)) == set()


@pytest.mark.parametrize("platform", ["unix", "native"])
def test_unrecorded_older_local_sink_keeps_working_after_remote_setup(
    tmp_path: Path, monkeypatch, platform: str
) -> None:
    # Upgrade path: a local sink written before 1.0.4 has no record, so it is
    # remote. Remote setup stores its token under its own reference and leaves
    # the older sink and its credential exactly as they were.
    app = _app(tmp_path)
    monkeypatch.delenv(_SHARED, raising=False)
    local_token = "local fixture credential"
    _write_bridge_contract(tmp_path, local_token)
    if platform == "unix":
        older = _hec("splunk-hec-127-0-0-1", _DEFAULT_HEC, _SHARED)
        dotenv = {"KEEP_ME": "unchanged", _SHARED: local_token}
    else:
        older = _hec("local-splunk", _DEFAULT_HEC, LOCAL_TOKEN_ENV)
        dotenv = {"KEEP_ME": "unchanged", LOCAL_TOKEN_ENV: local_token}
    _write_state(tmp_path, [older], dotenv)

    _remote_setup(app, "remote", _REMOTE_HEC, "independent remote fixture credential")
    assert _destinations(tmp_path)[older["name"]] == older
    saved = _dotenv(tmp_path)
    assert {key: saved[key] for key in dotenv} == dotenv
    assert saved[f"{_SHARED}_REMOTE"] == "independent remote fixture credential"


@pytest.mark.parametrize(
    ("platform", "existing"),
    [
        ("unix", _hec("splunk-hec-127-0-0-1", _DEFAULT_HEC, _SHARED)),
        # A remote tunnel that happens to carry the name local setup uses.
        ("unix", _hec("splunk-hec-127-0-0-1", "https://127.0.0.1:18088/services/collector/event", _SHARED)),
        ("native", _hec("local-splunk", _DEFAULT_HEC, LOCAL_TOKEN_ENV)),
    ],
    ids=["unix-older-sink", "unix-tunnel", "native-older-sink"],
)
def test_local_setup_never_takes_over_an_unrecorded_destination(
    tmp_path: Path, platform: str, existing: dict
) -> None:
    app = _app(tmp_path)
    _write_state(tmp_path, [existing], {"KEEP_ME": "unchanged", existing["token_env"]: "older credential"})
    config_before = (tmp_path / "config.yaml").read_bytes()
    dotenv_before = (tmp_path / ".env").read_bytes()
    with pytest.raises(ClickException) as refused:
        if platform == "unix":
            _unix_local_setup(app)
        else:
            _native_local_setup(app)
    message = refused.value.message
    assert f"defenseclaw setup observability remove {existing['name']} --yes" in message
    assert "Nothing was changed" in message
    assert (tmp_path / "config.yaml").read_bytes() == config_before
    assert (tmp_path / ".env").read_bytes() == dotenv_before

    # Once the operator removes it, local setup records its own sink.
    _remove(tmp_path, existing["name"])
    if platform == "unix":
        _unix_local_setup(app)
    else:
        _native_local_setup(app)
    assert _destinations(tmp_path)[existing["name"]]["local_stack"] == _RECORD


@pytest.mark.parametrize("platform", ["unix", "native"])
@pytest.mark.parametrize("proof", ["owned", "wrong-token", "wrong-endpoint", "wrong-tree", "wrong-compose", "multiple-containers"])
def test_legacy_local_sink_migrates_only_with_bridge_and_container_proof(
    tmp_path: Path, monkeypatch, platform: str, proof: str
) -> None:
    app = _app(tmp_path)
    name = "local-splunk" if platform == "native" else "splunk-hec-127-0-0-1"
    token_env = LOCAL_TOKEN_ENV if platform == "native" else _SHARED
    credential = "older local fixture credential"
    endpoint = _REMOTE_HEC if proof == "wrong-endpoint" else _DEFAULT_HEC
    legacy = _hec(name, endpoint, token_env)
    _write_state(tmp_path, [legacy], {"KEEP_ME": "unchanged", token_env: credential})
    if os.name == "nt":
        bridge_env_dir = tmp_path / "splunk-bridge" / "env"
        bridge_env_dir.mkdir(parents=True)
        set_known_windows_directory_acl(bridge_env_dir)
    _write_bridge_contract(tmp_path, credential if proof != "wrong-token" else "other bridge credential")
    bridge = tmp_path / "splunk-bridge"
    (bridge / "bin").mkdir()
    (bridge / "bin" / "splunk-claw-bridge").write_text("bridge fixture", encoding="utf-8")
    (bridge / "compose").mkdir()
    compose = bridge / "compose" / "docker-compose.local.yml"
    compose.write_text("name: defenseclaw-splunk-local\n", encoding="utf-8")
    labels = {
        "com.docker.compose.project": "defenseclaw-splunk-local",
        "com.docker.compose.service": "splunk",
        "com.docker.compose.project.working_dir": str(bridge if proof != "wrong-tree" else tmp_path / "other"),
        "com.docker.compose.project.config_files": str(compose if proof != "wrong-compose" else tmp_path / "other.yml"),
    }

    calls: list[tuple[str, ...]] = []

    class DockerEvidence:
        def run(self, argv, *, timeout, env=None):
            command = tuple(argv)
            calls.append(command)
            if command[1] == "ps":
                ids = _FULL_ID + "\n"
                if proof == "multiple-containers":
                    ids += "f" * 64 + "\n"
                return CommandResult(command, 0, stdout=ids)
            if command[1] == "inspect":
                return CommandResult(command, 0, stdout=json.dumps(labels))
            raise AssertionError(command)

    monkeypatch.setattr(cmd_setup.shutil, "which", lambda name: "docker" if name == "docker" else None)
    with (
        patch("defenseclaw.observability.local_stack.CommandRunner", return_value=DockerEvidence()),
        patch("defenseclaw.config_writer.refuse_when_managed"),
        patch("defenseclaw.observability.v8_writer._assert_config_write_allowed"),
        patch("defenseclaw.config_writer.managed_refuses", return_value=False),
    ):
        if proof == "owned":
            from defenseclaw.commands.cmd_setup_observability import _stored_secret

            assert _stored_secret(str(tmp_path), token_env) == credential
            assert cmd_setup._load_dotenv(str(bridge / "env" / ".env")) == {
                "DEFENSECLAW_HEC_TOKEN": credential, "DEFENSECLAW_HEC_URL": _DEFAULT_HEC,
            }
            verified = cmd_setup._verified_legacy_local_splunk_destination(
                str(tmp_path), name, native_windows=platform == "native", gateway_token_env="",
            )
            assert verified is not None, calls
            assert verified[0]["name"] == name
        if proof == "owned":
            if platform == "native":
                _native_local_setup(app)
            else:
                _unix_local_setup(app)
            sink = _destinations(tmp_path)[name]
            assert sink["local_stack"] == _RECORD
            assert sink["token_env"] == LOCAL_TOKEN_ENV
        else:
            with pytest.raises(ClickException, match="did not record it"):
                if platform == "native":
                    _native_local_setup(app)
                else:
                    _unix_local_setup(app)
            assert _destinations(tmp_path)[name] == legacy


def test_legacy_local_proof_expires_if_destination_changes_before_commit(tmp_path: Path) -> None:
    from defenseclaw.commands.cmd_setup_observability import _v8_authored_destination_snapshot

    app = _app(tmp_path)
    name = "splunk-hec-127-0-0-1"
    original = _hec(name, _DEFAULT_HEC, _SHARED)
    _write_state(tmp_path, [original], {"KEEP_ME": "unchanged", _SHARED: "older credential"})
    authored, digest = _v8_authored_destination_snapshot(str(tmp_path))
    changed = _hec(name, "https://127.0.0.1:8088/other/collector/path", _SHARED)
    _write_state(tmp_path, [changed], {"KEEP_ME": "unchanged", _SHARED: "older credential"})
    before = ((tmp_path / "config.yaml").read_bytes(), (tmp_path / ".env").read_bytes())
    status, validate = _v8_writer_patches()
    with status, validate, pytest.raises(ValueError, match="changed during setup"):
        cmd_setup._apply_v8_observability_preset(
            app, "splunk-hec", {"endpoint": _DEFAULT_HEC}, name=name,
            secret_value="new local credential", local_stack=dict(_RECORD),
            legacy_local_destination=(authored[0], digest), allow_private_networks=True,
        )
    assert ((tmp_path / "config.yaml").read_bytes(), (tmp_path / ".env").read_bytes()) == before


def test_local_setup_does_not_start_the_stack_when_it_would_refuse(tmp_path: Path) -> None:
    app = _app(tmp_path)
    _write_state(tmp_path, [_hec("splunk-hec-127-0-0-1", _DEFAULT_HEC, _SHARED)], {"KEEP_ME": "unchanged"})
    status, validate = _v8_writer_patches()
    with (
        status, validate,
        patch.object(cmd_setup, "_native_windows_local_splunk", return_value=False),
        patch.object(cmd_setup, "_bootstrap_bridge") as bridge,
        pytest.raises(ClickException),
    ):
        cmd_setup._apply_logs_config(app, **_LOGS)
    bridge.assert_not_called()
    status, validate = _v8_writer_patches()
    with (
        status, validate,
        patch("defenseclaw.observability.local_splunk.start_native_local_splunk") as start,
        pytest.raises(ClickException),
    ):
        _write_state(tmp_path, [_hec("local-splunk", _DEFAULT_HEC, LOCAL_TOKEN_ENV)], {"KEEP_ME": "unchanged"})
        cmd_setup._apply_native_windows_logs_config(
            app, **_LOGS, s3_export=False, s3_bucket=None, s3_prefix=None, aws_region=None,
            refresh_bundle=True, gateway_token_env="",
        )
    start.assert_not_called()


@pytest.mark.parametrize("platform", ["unix", "native"])
@pytest.mark.parametrize("recorded", [False, True], ids=["new-sink", "existing-record"])
def test_local_setup_checks_credential_reference_collision_before_start(
    tmp_path: Path, platform: str, recorded: bool
) -> None:
    app = _app(tmp_path)
    authored = [_hec("remote", _REMOTE_HEC, LOCAL_TOKEN_ENV)]
    if recorded:
        authored.insert(0, _hec("owned", _DEFAULT_HEC, LOCAL_TOKEN_ENV, local_stack=dict(_RECORD)))
    _write_state(tmp_path, authored, {"KEEP_ME": "unchanged", LOCAL_TOKEN_ENV: "older credential"})
    before = ((tmp_path / "config.yaml").read_bytes(), (tmp_path / ".env").read_bytes())
    status, validate = _v8_writer_patches()
    if platform == "unix":
        with (
            status, validate,
            patch.object(cmd_setup, "_native_windows_local_splunk", return_value=False),
            patch.object(cmd_setup, "_bootstrap_bridge", return_value={"hec_url": _DEFAULT_HEC, "hec_token": "t"}) as start,
            patch.object(cmd_setup, "_local_splunk_container_id", return_value=_FULL_ID),
            pytest.raises((ClickException, ValueError)) as refused,
        ):
            cmd_setup._apply_logs_config(app, **_LOGS)
    else:
        with (
            status, validate,
            patch("defenseclaw.observability.local_splunk.start_native_local_splunk",
                  return_value=FakeTransaction([])) as start,
            patch.object(cmd_setup, "_is_pid_alive", return_value=False),
            pytest.raises((ClickException, ValueError)) as refused,
        ):
            cmd_setup._apply_native_windows_logs_config(
                app, **_LOGS, s3_export=False, s3_bucket=None, s3_prefix=None,
                aws_region=None, refresh_bundle=True, gateway_token_env="",
            )
    start.assert_not_called()
    assert "remote" in str(refused.value)
    assert LOCAL_TOKEN_ENV in str(refused.value)
    assert "Nothing was changed" in str(refused.value)
    assert ((tmp_path / "config.yaml").read_bytes(), (tmp_path / ".env").read_bytes()) == before


def _write_bridge_url(data_dir: Path, hec_url: str, *, where: str) -> None:
    # The private bridge env file of an earlier setup, or for a first setup the
    # seeded template the bridge env file is created from.
    env_dir = data_dir / "splunk-bridge" / "env"
    env_dir.mkdir(parents=True, exist_ok=True)
    target = env_dir / (".env" if where == "bridge-env" else ".env.example")
    atomic_write_private_bytes(target, f"SPLUNK_IMAGE=splunk/splunk:fixture\nDEFENSECLAW_HEC_URL={hec_url}\n".encode())


@pytest.mark.parametrize(
    ("bridge_url", "where"),
    [
        # The finding: an upgraded older sink named after a custom bridge address.
        ("https://localhost:28088/services/collector/event", "bridge-env"),
        ("https://[::1]:8088/services/collector/event", "bridge-env"),
        ("http://localhost:8088/services/collector/event", "bridge-env"),
        # First setup: the bridge env file will be created from the template.
        ("https://localhost:8088/services/collector/event", "template"),
    ],
)
def test_local_setup_checks_the_name_of_the_bridge_address_before_the_stack_starts(
    tmp_path: Path, bridge_url: str, where: str
) -> None:
    from defenseclaw.observability.v8_presets import local_splunk_destination_name

    app = _app(tmp_path)
    name = local_splunk_destination_name(bridge_url)
    assert name != "splunk-hec-127-0-0-1"
    _write_bridge_url(tmp_path, bridge_url, where=where)
    _write_state(tmp_path, [_hec(name, bridge_url, _SHARED)], {"KEEP_ME": "unchanged", _SHARED: "older credential"})
    config_before = (tmp_path / "config.yaml").read_bytes()
    dotenv_before = (tmp_path / ".env").read_bytes()
    status, validate = _v8_writer_patches()
    with (
        status, validate,
        patch.object(cmd_setup, "_native_windows_local_splunk", return_value=False),
        patch.object(cmd_setup, "_bootstrap_bridge", return_value={"hec_url": bridge_url, "hec_token": "t"}) as bridge,
        patch.object(cmd_setup, "_local_splunk_container_id", return_value=_FULL_ID) as container,
        patch.object(cmd_setup, "_reload_cfg_from_data_dir"),
        pytest.raises(ClickException) as refused,
    ):
        cmd_setup._apply_logs_config(app, **_LOGS)
    # Refused before the stack is refreshed, restarted or started.
    bridge.assert_not_called()
    container.assert_not_called()
    assert f"defenseclaw setup observability remove {name} --yes" in refused.value.message
    assert "Nothing was changed" in refused.value.message
    assert (tmp_path / "config.yaml").read_bytes() == config_before
    assert (tmp_path / ".env").read_bytes() == dotenv_before
    assert (tmp_path / "splunk-bridge" / "env" / ".env").exists() == (where == "bridge-env")

    _remove(tmp_path, name)
    _unix_local_setup(app, hec_url=bridge_url)
    assert _destinations(tmp_path)[name]["local_stack"] == _RECORD


def test_local_setup_next_to_an_unrecorded_destination_the_bridge_does_not_name(tmp_path: Path) -> None:
    # Control: the bridge reports 127.0.0.1, so an unrecorded destination
    # named for localhost is someone else's and setup goes ahead beside it.
    app = _app(tmp_path)
    _write_bridge_url(tmp_path, _DEFAULT_HEC, where="bridge-env")
    other = _hec("splunk-hec-localhost", "https://localhost:28088/services/collector/event", _SHARED)
    _write_state(tmp_path, [other], {"KEEP_ME": "unchanged"})
    _unix_local_setup(app)
    sinks = _destinations(tmp_path)
    assert sinks["splunk-hec-localhost"] == other
    assert sinks["splunk-hec-127-0-0-1"]["local_stack"] == _RECORD


def test_remote_setup_never_changes_the_recorded_local_sink(tmp_path: Path) -> None:
    app = _app(tmp_path)
    _unix_local_setup(app)
    config_before = (tmp_path / "config.yaml").read_bytes()
    dotenv_before = (tmp_path / ".env").read_bytes()
    with pytest.raises(ValueError, match="is the local Splunk sink that local setup recorded"):
        _remote_setup(app, "splunk-hec-127-0-0-1", _REMOTE_HEC, "independent remote fixture credential")
    assert (tmp_path / "config.yaml").read_bytes() == config_before
    assert (tmp_path / ".env").read_bytes() == dotenv_before


def test_each_remote_splunk_destination_keeps_its_own_credential(tmp_path: Path, monkeypatch) -> None:
    app = _app(tmp_path)
    monkeypatch.delenv(_SHARED, raising=False)
    _remote_setup(app, "team-a", "https://a.example.test:8088/services/collector/event", "credential A")
    _remote_setup(app, "team-b", "https://b.example.test:8088/services/collector/event", "credential B")
    sinks = _destinations(tmp_path)
    assert sinks["team-a"]["token_env"] == f"{_SHARED}_TEAM_A"
    assert sinks["team-b"]["token_env"] == f"{_SHARED}_TEAM_B"
    saved = _dotenv(tmp_path)
    assert (saved[f"{_SHARED}_TEAM_A"], saved[f"{_SHARED}_TEAM_B"]) == (
        "credential A", "credential B"
    )
    assert _SHARED not in saved

    # A rerun without a token keeps the reference; a new token changes only its own.
    _remote_setup(app, "team-a", "https://a2.example.test:8088/services/collector/event", None)
    assert _dotenv(tmp_path)[f"{_SHARED}_TEAM_A"] == "credential A"
    _remote_setup(app, "team-a", "https://a2.example.test:8088/services/collector/event", "credential A2")
    saved = _dotenv(tmp_path)
    assert (saved[f"{_SHARED}_TEAM_A"], saved[f"{_SHARED}_TEAM_B"]) == (
        "credential A2", "credential B"
    )

    # Two names that map to one reference never share it.
    config_before = (tmp_path / "config.yaml").read_bytes()
    with pytest.raises(ValueError, match="never shared"):
        _remote_setup(app, "team.a", "https://a3.example.test:8088/services/collector/event", "credential A3")
    assert (tmp_path / "config.yaml").read_bytes() == config_before
    assert _dotenv(tmp_path)[f"{_SHARED}_TEAM_A"] == "credential A2"

    # An older remote on the shared reference moves to its own once given a token.
    _write_state(
        tmp_path,
        [_hec("older", "https://old.example.test:8088/services/collector/event", _SHARED)],
        {_SHARED: "older credential"},
    )
    _remote_setup(app, "older", "https://old.example.test:8088/services/collector/event", "older credential 2")
    assert _destinations(tmp_path)["older"]["token_env"] == f"{_SHARED}_OLDER"
    assert _dotenv(tmp_path)[_SHARED] == "older credential"


@pytest.mark.parametrize("where", ["dotenv", "environment"])
def test_enterprise_setup_takes_the_token_only_from_its_inputs(tmp_path: Path, monkeypatch, where: str) -> None:
    # A credential saved under the shared reference belongs to another
    # destination (an older remote, or an older local sink); it is never a
    # silent input for a new one.
    app = _app(tmp_path)
    monkeypatch.delenv(_SHARED, raising=False)
    if where == "dotenv":
        _write_state(tmp_path, [], {_SHARED: "another destination's credential"})
    monkeypatch.setenv(_SHARED, "another destination's credential")
    config_before = (tmp_path / "config.yaml").read_bytes()
    status, validate = _v8_writer_patches()
    with status, validate, pytest.raises(SystemExit) as refused:
        cmd_setup._setup_enterprise(
            app, hec_endpoint=_REMOTE_HEC, hec_token=None, non_interactive=True, skip_test=True,
        )
    assert refused.value.code == 1
    assert (tmp_path / "config.yaml").read_bytes() == config_before

    status, validate = _v8_writer_patches()
    with status, validate, patch.object(cmd_setup, "_maybe_probe_enterprise_hec"):
        cmd_setup._setup_enterprise(
            app, hec_endpoint=_REMOTE_HEC, hec_token="remote credential", non_interactive=True, skip_test=True,
        )
    (sink,) = _destinations(tmp_path).values()
    assert _dotenv(tmp_path)[sink["token_env"]] == "remote credential"
    assert sink["token_env"] != _SHARED


def _disable_state(tmp_path: Path) -> tuple[AppContext, list[SimpleNamespace]]:
    app = _app(tmp_path)
    authored = [
        _hec("local-splunk", _DEFAULT_HEC, LOCAL_TOKEN_ENV, local_stack=dict(_RECORD)),
        # Remote Splunk reached through loopback tunnels, one with the name
        # and listener an older local setup used.
        _hec("splunk-hec-127-0-0-1", _DEFAULT_HEC, f"{_SHARED}_A"),
        _hec("operator-loopback", "https://localhost:18088/services/collector/event", f"{_SHARED}_B"),
        _hec("remote", _REMOTE_HEC, f"{_SHARED}_REMOTE"),
    ]
    _write_state(tmp_path, authored, {"KEEP_ME": "unchanged"})
    status = [
        SimpleNamespace(name=item["name"], kind="splunk_hec", enabled=True, endpoint=item["endpoint"],
                        buckets=("*",), redaction_label="default")
        for item in authored
    ]
    return app, status


@pytest.mark.parametrize("host", ["windows", "linux"])
@pytest.mark.parametrize(
    ("mode", "expected"),
    [
        ("logs", ["local-splunk"]),
        ("enterprise", ["splunk-hec-127-0-0-1", "operator-loopback", "remote"]),
    ],
)
def test_disable_acts_only_on_the_recorded_local_sink(tmp_path: Path, host: str, mode: str, expected: list) -> None:
    app, status = _disable_state(tmp_path)
    disabled: list[str] = []
    with (
        patch.object(cmd_setup.platform_support, "host_os", return_value=host),
        patch(
            "defenseclaw.commands.cmd_setup_observability._require_v8_operator_status",
            return_value=SimpleNamespace(destinations=tuple(status)),
        ),
        patch(
            "defenseclaw.commands.cmd_setup_observability._set_v8_destination_enabled",
            side_effect=lambda _data_dir, name, *_: disabled.append(name),
        ),
        patch("defenseclaw.observability.local_splunk.prepare_native_local_splunk_stop", return_value=(None, False)),
        patch.object(cmd_setup, "_stop_bridge"),
        patch.object(cmd_setup, "_reload_cfg_from_data_dir"),
    ):
        cmd_setup._disable_splunk(app, False, mode == "logs", mode == "enterprise", True)
    assert disabled == expected


def _logs_disable(app: AppContext, host: str, status: list[SimpleNamespace]):
    disabled: list[str] = []
    with (
        patch.object(cmd_setup.platform_support, "host_os", return_value=host),
        patch(
            "defenseclaw.commands.cmd_setup_observability._require_v8_operator_status",
            return_value=SimpleNamespace(destinations=tuple(status)),
        ),
        patch(
            "defenseclaw.commands.cmd_setup_observability._set_v8_destination_enabled",
            side_effect=lambda _data_dir, name, *_: disabled.append(name),
        ),
        patch(
            "defenseclaw.observability.local_splunk.prepare_native_local_splunk_stop", return_value=(None, False)
        ) as native_stop,
        patch.object(cmd_setup, "_stop_bridge") as stop_bridge,
        patch.object(cmd_setup, "_reload_cfg_from_data_dir"),
    ):
        cmd_setup._disable_splunk(app, False, True, False, True)
    stopped = native_stop.called if host == "windows" else stop_bridge.called
    return disabled, stopped


@pytest.mark.parametrize("host", ["linux", "windows"])
@pytest.mark.parametrize(
    "older",
    [
        _hec("splunk-hec-localhost", "https://localhost:28088/services/collector/event", _SHARED),
        _hec("splunk-hec-127-0-0-1", _DEFAULT_HEC, _SHARED),
        _hec("local-splunk", _DEFAULT_HEC, LOCAL_TOKEN_ENV),
    ],
    ids=["custom-bridge", "unix-default", "native"],
)
def test_logs_disable_keeps_local_splunk_while_an_unrecorded_destination_is_enabled(
    tmp_path: Path, capsys, host: str, older: dict
) -> None:
    # An upgraded older local sink has no record. --disable --logs does not
    # disable it, so it must not stop the stack that sink may still send to.
    app = _app(tmp_path)
    # A configured stack: its runtime credentials (a seeded bundle alone is not one).
    (tmp_path / "splunk-bridge" / "env").mkdir(parents=True)
    (tmp_path / "splunk-bridge" / "env" / ".env").write_text("DEFENSECLAW_INTEGRATION_ENABLED=true\n")
    authored = [older, _hec("remote", _REMOTE_HEC, f"{_SHARED}_REMOTE")]
    _write_state(tmp_path, authored, {"KEEP_ME": "unchanged"})
    status = [
        SimpleNamespace(name=item["name"], kind="splunk_hec", enabled=True, endpoint=item["endpoint"])
        for item in authored
    ]
    disabled, stopped = _logs_disable(app, host, status)
    assert disabled == []
    assert not stopped
    out = " ".join(capsys.readouterr().out.split())
    assert "Local Splunk was not stopped" in out
    for name in (older["name"], "remote"):
        assert f"defenseclaw setup observability disable {name}" in out
    assert "defenseclaw setup splunk --disable --logs again" in out

    # The named resolution: once those destinations are disabled, --logs stops local Splunk.
    for item in status:
        item.enabled = False
    disabled, stopped = _logs_disable(app, host, status)
    assert disabled == []
    assert stopped


@pytest.mark.parametrize("host", ["linux", "windows"])
def test_logs_disable_stops_the_recorded_stack_next_to_remote_destinations(tmp_path: Path, host: str) -> None:
    # With a record the stack is the recorded one: every other destination is
    # remote and keeps sending, and the local stack stops.
    app, status = _disable_state(tmp_path)
    disabled, stopped = _logs_disable(app, host, status)
    assert disabled == ["local-splunk"]
    assert stopped


@pytest.mark.parametrize("host", ["linux", "windows"])
@pytest.mark.parametrize(
    ("mode", "recorded"),
    [("logs", True), ("both", True), ("both", False)],
    ids=["recorded-logs", "recorded-both", "older-both"],
)
def test_disable_keeps_stack_when_an_enabled_sink_could_not_be_disabled(
    tmp_path: Path, capsys, host: str, mode: str, recorded: bool
) -> None:
    app = _app(tmp_path)
    (tmp_path / "splunk-bridge").mkdir()
    name = "local-splunk" if recorded else "older"
    sink = _hec(name, _DEFAULT_HEC, LOCAL_TOKEN_ENV)
    if recorded:
        sink["local_stack"] = dict(_RECORD)
    _write_state(tmp_path, [sink], {"KEEP_ME": "unchanged"})
    status = SimpleNamespace(name=name, kind="splunk_hec", enabled=True, endpoint=_DEFAULT_HEC)
    stopped: list[str] = []
    controller = SimpleNamespace(
        s3_runtime_state=lambda: (False, {}),
        down=lambda: stopped.append("native"),
    )
    with (
        patch.object(cmd_setup.platform_support, "host_os", return_value=host),
        patch("defenseclaw.commands.cmd_setup_observability._require_v8_operator_status",
              return_value=SimpleNamespace(destinations=(status,))),
        patch("defenseclaw.commands.cmd_setup_observability._set_v8_destination_enabled",
              side_effect=ClickException("write refused")),
        patch("defenseclaw.observability.local_splunk.prepare_native_local_splunk_stop",
              return_value=(controller, True)),
        patch.object(cmd_setup, "_stop_bridge", side_effect=lambda *_a, **_k: stopped.append("unix")),
        patch.object(cmd_setup, "_reload_cfg_from_data_dir"),
    ):
        cmd_setup._disable_splunk(app, False, mode == "logs", False, True)
    assert stopped == []
    out = capsys.readouterr().out
    assert f"Local Splunk was not stopped: {name} could not be disabled" in out
    assert f"defenseclaw setup observability disable {name}" in out
    if recorded:
        assert "Local Splunk (HEC): sink could not be disabled" in out
    else:
        assert "Splunk Enterprise (HEC): some sinks could not be disabled" in out


def test_splunk_status_labels_only_the_recorded_sink_local(tmp_path: Path, capsys) -> None:
    app, status = _disable_state(tmp_path)
    with patch(
        "defenseclaw.commands.cmd_setup_observability._require_v8_operator_status",
        return_value=SimpleNamespace(destinations=tuple(status)),
    ):
        cmd_setup._print_splunk_status(app)
    labels = {
        line.strip().split(" [", 1)[1].rstrip("]:"): line.strip().split(" [", 1)[0]
        for line in capsys.readouterr().out.splitlines()
        if "(HEC) [" in line
    }
    assert labels == {
        "local-splunk": "Local Splunk (HEC)",
        "splunk-hec-127-0-0-1": "Splunk Enterprise (HEC)",
        "operator-loopback": "Splunk Enterprise (HEC)",
        "remote": "Splunk Enterprise (HEC)",
    }


def test_native_disable_selects_only_owned_local_sink(tmp_path: Path) -> None:
    app = _app(tmp_path)
    _write_state(
        tmp_path,
        [
            _hec("local-splunk", "https://127.0.0.1:8088/x", LOCAL_TOKEN_ENV, local_stack=dict(_RECORD)),
            _hec("operator-loopback", "https://localhost:8088/x", f"{_SHARED}_OPERATOR_LOOPBACK"),
        ],
        {"KEEP_ME": "unchanged"},
    )
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


@pytest.mark.parametrize("logs_only", [False, True])
def test_native_disable_seeded_assets_without_stack_is_a_noop(tmp_path: Path, logs_only: bool) -> None:
    app = _app(tmp_path)
    # Install seeds the bundle before Local Splunk has ever been configured.
    seeded = tmp_path / "splunk-bridge"
    (seeded / "env").mkdir(parents=True)
    (seeded / "env" / ".env.example").write_text("SPLUNK_IMAGE=example\n")
    before = (tmp_path / "config.yaml").read_bytes()
    with (
        patch.object(cmd_setup.platform_support, "host_os", return_value="windows"),
        patch("defenseclaw.commands.cmd_setup_observability._require_v8_operator_status",
              return_value=SimpleNamespace(destinations=())),
        patch("defenseclaw.observability.local_splunk.prepare_native_local_splunk_stop",
              side_effect=LocalStackError("Docker CLI was not found on PATH")) as preflight,
        patch.object(cmd_setup, "_stop_bridge") as stop_bridge,
        patch.object(cmd_setup, "_reload_cfg_from_data_dir"),
    ):
        cmd_setup._disable_splunk(app, False, logs_only, False, True)
    preflight.assert_not_called()
    stop_bridge.assert_not_called()
    assert (tmp_path / "config.yaml").read_bytes() == before


def test_native_disable_runtime_credentials_still_require_ownership_proof(tmp_path: Path) -> None:
    app = _app(tmp_path)
    runtime_env = tmp_path / "splunk-bridge" / "env" / ".env"
    runtime_env.parent.mkdir(parents=True)
    runtime_env.write_text("DEFENSECLAW_INTEGRATION_ENABLED=true\n")
    before = (tmp_path / "config.yaml").read_bytes()
    with (
        patch.object(cmd_setup.platform_support, "host_os", return_value="windows"),
        patch("defenseclaw.commands.cmd_setup_observability._require_v8_operator_status",
              return_value=SimpleNamespace(destinations=())),
        patch("defenseclaw.observability.local_splunk.prepare_native_local_splunk_stop",
              side_effect=LocalStackError("ownership is unproven")) as preflight,
        pytest.raises(ClickException, match="ownership is unproven"),
    ):
        cmd_setup._disable_splunk(app, False, True, False, True)
    preflight.assert_called_once()
    assert (tmp_path / "config.yaml").read_bytes() == before


def test_native_disable_failure_restores_config_and_running_stack(tmp_path: Path) -> None:
    app = _app(tmp_path)
    _write_state(
        tmp_path,
        [_hec("local-splunk", "https://127.0.0.1:8088/x", LOCAL_TOKEN_ENV, local_stack=dict(_RECORD))],
        {"KEEP_ME": "unchanged"},
    )
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
