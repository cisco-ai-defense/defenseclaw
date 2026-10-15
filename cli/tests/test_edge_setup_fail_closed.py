"""Fleet setup must not report success when credentials or services fail."""

from __future__ import annotations

import subprocess
from types import SimpleNamespace

import click
import pytest
from click.testing import CliRunner
from defenseclaw.commands import cmd_edge_install, cmd_setup_edge_connector, cmd_setup_mqtt
from defenseclaw.context import AppContext
from defenseclaw.dotenv_utils import persist_env_var


def _app(tmp_path):
    app = AppContext()
    app.cfg = SimpleNamespace(data_dir=str(tmp_path))
    return app


def test_edge_setup_generates_distinct_keys_and_reuses_them(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path))
    monkeypatch.setattr(cmd_setup_edge_connector, "_enable_fleet_config", lambda _path: None)
    service_writes: list[tuple[str, str]] = []
    monkeypatch.setattr(
        cmd_setup_edge_connector, "_persist_svc_env_var",
        lambda _path, name, value: service_writes.append((name, value)) or True,
    )
    runner = CliRunner()
    for _ in range(2):
        result = runner.invoke(
            cmd_setup_edge_connector.edge_connector,
            ["--non-interactive", "--token", "test-token"],
            obj=_app(tmp_path),
        )
        assert result.exit_code == 0, result.output
    first = dict(service_writes[:3])
    second = dict(service_writes[3:])
    assert first == second
    assert len(set(first.values())) == 3
    assert all(len(bytes.fromhex(value)) == 32 for value in first.values())


def test_edge_setup_config_failure_does_not_persist_secrets(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path))

    def denied(_path):
        raise click.ClickException("managed config is locked")

    monkeypatch.setattr(cmd_setup_edge_connector, "_enable_fleet_config", denied)
    result = CliRunner().invoke(
        cmd_setup_edge_connector.edge_connector,
        ["--non-interactive", "--token", "test-token"],
        obj=_app(tmp_path),
    )
    assert result.exit_code != 0
    assert "managed config is locked" in result.output
    assert not (tmp_path / ".env").exists()


def test_edge_setup_rejects_bad_key_before_config_write(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path))
    monkeypatch.setenv("DCLAW_OTA_HMAC_KEY", "00" * 32)
    called = []
    monkeypatch.setattr(cmd_setup_edge_connector, "_enable_fleet_config", lambda _path: called.append(True))
    result = CliRunner().invoke(
        cmd_setup_edge_connector.edge_connector,
        ["--non-interactive", "--token", "test-token"],
        obj=_app(tmp_path),
    )
    assert result.exit_code != 0
    assert "nonzero 32-byte hex" in result.output
    assert not called
    assert not (tmp_path / ".env").exists()


def test_edge_setup_service_write_failure_is_nonzero(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path))
    monkeypatch.setattr(cmd_setup_edge_connector, "_enable_fleet_config", lambda _path: None)
    monkeypatch.setattr(cmd_setup_edge_connector, "_persist_svc_env_var", lambda *_args: False)
    result = CliRunner().invoke(
        cmd_setup_edge_connector.edge_connector,
        ["--non-interactive", "--token", "test-token"],
        obj=_app(tmp_path),
    )
    assert result.exit_code != 0
    assert "setup is incomplete" in result.output


def test_dotenv_failed_replace_preserves_existing_secret(tmp_path, monkeypatch) -> None:
    import defenseclaw.dotenv_utils as dotenv

    path = tmp_path / ".env"
    persist_env_var(path, "SECRET", "old")
    assert path.stat().st_mode & 0o777 == 0o600

    def failed_replace(*_args):
        raise OSError("simulated rename failure")

    monkeypatch.setattr(dotenv.os, "replace", failed_replace)
    with pytest.raises(OSError, match="simulated rename failure"):
        persist_env_var(path, "SECRET", "new")
    assert path.read_text() == "SECRET=old\n"
    assert sorted(p.name for p in tmp_path.iterdir()) == [".env"]


def test_remote_installer_streams_secrets_outside_ssh_arguments(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path))
    (tmp_path / ".env").write_text(
        "DCLAW_MQTT_USER=user-secret\nDCLAW_MQTT_PASS=password-secret\n"
        "DCLAW_OTA_HMAC_KEY=" + "ab" * 32 + "\n"
        "DCLAW_EMERGENCY_KEY=" + "cd" * 32 + "\n"
    )
    calls = []

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(cmd_edge_install.subprocess, "run", fake_run)
    assert cmd_edge_install._configure_remote_env(
        "device.example", "operator", "1", "2", "3", "mqtt://broker:1883",
        device_key="device-secret",
    )
    argv, kwargs = calls[0]
    command_line = " ".join(argv)
    for secret in ("device-secret", "user-secret", "password-secret", "ab" * 32, "cd" * 32):
        assert secret not in command_line
        assert secret in kwargs["input"]
    assert "mktemp" in command_line and "mv -f" in command_line


def test_remote_source_copy_without_rsync_copies_directory_contents(tmp_path, monkeypatch) -> None:
    commands = []
    monkeypatch.setattr(cmd_edge_install, "_run_ssh_output", lambda *_args: "/tmp/defenseclaw-12345678\n")
    monkeypatch.setattr(cmd_edge_install.shutil, "which", lambda _name: None)
    monkeypatch.setattr(cmd_edge_install, "_run", lambda argv: commands.append(argv))
    assert cmd_edge_install._copy_source(tmp_path, "device.example", "operator") == "/tmp/defenseclaw-12345678"
    assert commands == [[
        "scp", "-o", "StrictHostKeyChecking=yes", "-r", f"{tmp_path}/.",
        "operator@device.example:/tmp/defenseclaw-12345678/",
    ]]


@pytest.mark.parametrize("identifier", ["-oProxyCommand=evil", "host@evil", "host;evil", ""])
def test_remote_identifier_rejects_ssh_redirects_and_options(identifier: str) -> None:
    with pytest.raises(click.ClickException):
        cmd_edge_install._validate_ssh_identifier(identifier, "target")


def test_local_build_keeps_read_only_package_source_clean(tmp_path, monkeypatch) -> None:
    commands = []
    monkeypatch.setattr(cmd_edge_install, "_run", lambda argv, **kwargs: commands.append(argv))
    assert cmd_edge_install._build_local(tmp_path, "STANDARD")
    assert commands[0][:3] == ["cmake", "-S", str(tmp_path)]
    assert "-DDCLAW_BUILD_TESTS=OFF" in commands[0]
    assert commands[2][:3] == ["sudo", "cmake", "--install"]
    assert not (tmp_path / "build").exists()


@pytest.mark.parametrize("reply,accepted", [
    (b"\x20\x02\x00\x00", True),
    (b"\x20\x02\x00\x05", False),
    (b"HTTP", False),
    (b"", False),
])
def test_mqtt_setup_probe_requires_connack(monkeypatch, reply: bytes, accepted: bool) -> None:
    class Socket:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def settimeout(self, _seconds):
            pass

        def sendall(self, _data):
            pass

        def recv(self, count):
            nonlocal reply
            part, reply = reply[:count], reply[count:]
            return part

    monkeypatch.setattr(cmd_setup_mqtt.socket, "create_connection", lambda *_args, **_kwargs: Socket())
    assert cmd_setup_mqtt._mqtt_check("localhost", 1883, "dclaw", "secret") is accepted


def test_mqtt_setup_failure_does_not_persist_broker_url(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path))
    monkeypatch.setattr(
        cmd_setup_mqtt, "_setup_docker", lambda _port: {"mqtt_user": "dclaw", "mqtt_pass": "secret"},
    )
    monkeypatch.setattr(cmd_setup_mqtt, "_wait_for_broker", lambda *_args: False)
    result = CliRunner().invoke(
        cmd_setup_mqtt.mqtt_broker, ["--docker", "--port", "21883"], obj=AppContext(),
    )
    assert result.exit_code != 0
    assert "did not accept MQTT" in result.output
    assert not (tmp_path / ".env").exists()


def test_mqtt_config_failure_does_not_persist_broker_url(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path))
    monkeypatch.setattr(
        cmd_setup_mqtt, "_setup_docker", lambda _port: {"mqtt_user": "dclaw", "mqtt_pass": "secret"},
    )
    monkeypatch.setattr(cmd_setup_mqtt, "_wait_for_broker", lambda *_args: True)
    import defenseclaw.config as config

    monkeypatch.setattr(config, "write_config_yaml_secure", lambda *_args: (_ for _ in ()).throw(PermissionError("locked")))
    result = CliRunner().invoke(
        cmd_setup_mqtt.mqtt_broker, ["--docker", "--port", "21883"], obj=AppContext(),
    )
    assert result.exit_code != 0
    assert "MQTT setup is incomplete" in result.output
    assert not (tmp_path / ".env").exists()


def test_systemd_broker_setup_probes_existing_credentials_and_scopes_claims(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path))
    (tmp_path / ".env").write_text("DCLAW_MQTT_USER=operator\nDCLAW_MQTT_PASS=private-value\n")
    monkeypatch.setattr(cmd_setup_mqtt, "_setup_systemd", lambda _port: True)
    observed = []
    monkeypatch.setattr(
        cmd_setup_mqtt, "_wait_for_broker",
        lambda host, port, user, password: observed.append((host, port, user, password)) or True,
    )
    result = CliRunner().invoke(
        cmd_setup_mqtt.mqtt_broker, ["--systemd", "--port", "21883"], obj=AppContext(),
    )
    assert result.exit_code == 0, result.output
    assert observed == [("127.0.0.1", 21883, "operator", "private-value")]
    assert "remote-device readiness was not tested" in result.output
    assert "mqtts://<broker-host>:8883" in result.output
    assert "--broker-url mqtt://localhost" not in result.output
