"""Fleet setup must not report success when credentials or services fail."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import click
import pytest
import yaml
from click.testing import CliRunner
from defenseclaw.commands import cmd_config, cmd_edge_connector_cli, cmd_edge_install, cmd_setup_edge_connector, cmd_setup_mqtt
from defenseclaw.context import AppContext
from defenseclaw.dotenv_utils import persist_env_var
from defenseclaw.file_permissions import make_private_directory


def _app(tmp_path):
    app = AppContext()
    app.cfg = SimpleNamespace(data_dir=str(tmp_path))
    return app


def test_edge_setup_advertises_real_gateway_port_and_emits_compilable_policy(tmp_path) -> None:
    runner = CliRunner()
    help_result = runner.invoke(cmd_setup_edge_connector.edge_connector, ["--help"])
    assert help_result.exit_code == 0
    assert "18970" in help_result.output
    assert "13400" not in help_result.output
    assert "defenseclaw-fleet-assets.tar.gz" in help_result.output

    sample = runner.invoke(
        cmd_setup_edge_connector.edge_connector, ["--emit-policy"], obj=_app(tmp_path)
    )
    assert sample.exit_code == 0, sample.output
    assert "kind: FleetPolicy" not in sample.output
    policy_file = tmp_path / "fleet-policy.yaml"
    policy_file.write_text(sample.output)
    compiler = Path(__file__).resolve().parents[2] / "edge-connector" / "tools" / "policy_compiler.py"
    compiled = subprocess.run(
        [sys.executable, str(compiler), "--input", str(policy_file),
         "--profile", "standard", "--version", "1",
         "--output-header", "policy_tables.h", "--output-binary", "policy.bin"],
        cwd=tmp_path, capture_output=True, text=True, check=False,
    )
    assert compiled.returncode == 0, compiled.stderr
    assert (tmp_path / "policy.bin").stat().st_size > 0


def test_edge_install_help_and_missing_source_name_fleet_archive(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(cmd_edge_install, "_find_edge_connector_source", lambda *_args: None)
    runner = CliRunner()
    help_result = runner.invoke(cmd_edge_install.edge_install, ["--help"], obj=_app(tmp_path))
    assert help_result.exit_code == 0, help_result.output
    assert "defenseclaw-fleet-assets.tar.gz" in help_result.output
    refusal = runner.invoke(cmd_edge_install.edge_install, [], obj=_app(tmp_path))
    assert refusal.exit_code != 0
    assert "defenseclaw-fleet-assets.tar.gz" in refusal.output


def test_edge_setup_persists_endpoint_for_device_installer(tmp_path, monkeypatch) -> None:
    install_guide = (
        Path(__file__).resolve().parents[2]
        / "docs-site/content/docs/how-to/install-the-edge-connector.mdx"
    ).read_text(encoding="utf-8")
    assert "defenseclaw edge-connector register 1001" not in install_guide
    assert "--endpoint https://fleet.example.com/api/v1/fleet" in install_guide
    assert "--target DEVICE --user USER" in install_guide
    assert "automatically registers" in install_guide
    assert "defenseclaw config set fleet.trust_proxy_headers true" in install_guide
    assert "defenseclaw-gateway restart" in install_guide
    assert "X-Forwarded-Proto: https" in install_guide
    assert "defenseclaw config set fleet.allow_key_over_http true" in install_guide
    reference = (
        Path(__file__).resolve().parents[2]
        / "docs-site/content/docs/reference/edge-connector/configuration.mdx"
    ).read_text(encoding="utf-8")
    assert "fleet.trust_proxy_headers" in reference
    assert "fleet.allow_key_over_http" in reference
    private_home = tmp_path / "fleet-home"
    make_private_directory(private_home)
    monkeypatch.setenv("DEFENSECLAW_HOME", str(private_home))
    monkeypatch.delenv("DCLAW_FLEET_API_URL", raising=False)
    monkeypatch.setattr(cmd_setup_edge_connector, "_persist_svc_env_var", lambda *_args: True)
    monkeypatch.setattr(cmd_setup_edge_connector, "_install_fleet_compiler", lambda *_args: private_home)
    endpoint = "http://127.0.0.1:19999/api/v1/fleet"
    enabled = []

    def enable(_path):
        enabled.append(cmd_edge_install._load_local_env_value("DCLAW_FLEET_API_URL"))

    monkeypatch.setattr(cmd_setup_edge_connector, "_enable_fleet_config", enable)
    result = CliRunner().invoke(
        cmd_setup_edge_connector.edge_connector,
        ["--non-interactive", "--token", "test-token", "--endpoint", endpoint],
        obj=_app(private_home),
    )
    assert result.exit_code == 0, result.output
    assert enabled == [endpoint]
    assert "loopback-only test mode" in result.output
    assert "HTTPS" in result.output
    assert "Fleet CLI commands use this endpoint" in result.output

    calls = []

    def fake_run(args, **_kwargs):
        calls.append(args)
        return SimpleNamespace(returncode=0, stdout='{"device_key":"' + "12" * 32 + '"}\n201', stderr="")

    monkeypatch.setattr(cmd_edge_install.subprocess, "run", fake_run)
    assert cmd_edge_install._register_device_via_api("1", "1", "42") == "12" * 32
    assert endpoint + "/devices" in calls[0]
    assert calls[0][1:5] == ["-q", "--noproxy", "*", "-s"]


def test_documented_proxy_trust_command_writes_fleet_setting(tmp_path, monkeypatch) -> None:
    make_private_directory(tmp_path)
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path))
    result = CliRunner().invoke(
        cmd_config.config_cmd,
        ["set", "fleet.trust_proxy_headers", "true"],
        obj=AppContext(),
    )
    assert result.exit_code == 0, result.output
    written = yaml.safe_load((tmp_path / "config.yaml").read_text(encoding="utf-8"))
    assert written["fleet"]["trust_proxy_headers"] is True


def test_edge_register_uses_saved_https_endpoint_without_redirects(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path))
    monkeypatch.delenv("DCLAW_FLEET_API_TOKEN", raising=False)
    monkeypatch.delenv("REQUESTS_CA_BUNDLE", raising=False)
    monkeypatch.delenv("CURL_CA_BUNDLE", raising=False)
    (tmp_path / ".env").write_text(
        "DCLAW_FLEET_API_URL=https://fleet.example.com/api/v1/fleet\n"
        "DCLAW_FLEET_API_TOKEN=fixture-token\n"
    )
    calls = []

    class FakeSession:
        def __init__(self):
            self.headers = {}
            self.trust_env = True
            self.verify = False

        def post(self, url, *, json, timeout, allow_redirects):
            calls.append((url, json, timeout, allow_redirects, dict(self.headers), self.trust_env, self.verify))
            return SimpleNamespace(status_code=201, content=b"{}", json=lambda: {"device_key": "12" * 32})

    class FakeLocalGateway:
        def __init__(self, *, host, port, token, timeout):
            self._session = FakeSession()
            self.base_url = f"http://{host}:{port}"
            self.timeout = timeout

    monkeypatch.setattr(cmd_edge_connector_cli.req_lib, "Session", FakeSession)
    monkeypatch.setattr("defenseclaw.gateway.OrchestratorClient", FakeLocalGateway)
    app = _app(tmp_path)
    app.cfg.gateway = SimpleNamespace(api_port=18970, token="", resolved_token=lambda: "")
    result = CliRunner().invoke(
        cmd_edge_connector_cli.edge_connector_group,
        ["register", "1001", "--json"], obj=app,
    )
    assert result.exit_code == 0, result.output
    assert len(calls) == 1
    url, body, timeout, redirects, headers, trust_env, verify = calls[0]
    assert url == "https://fleet.example.com/api/v1/fleet/devices"
    assert body["device_id"] == 1001
    assert timeout <= 10 and redirects is False
    assert headers["Authorization"] == "Bearer fixture-token"
    assert headers["X-DefenseClaw-Client"] == "python-cli"
    assert trust_env is False
    assert verify is True


@pytest.mark.parametrize("ca_variable", ["REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"])
def test_edge_https_client_honors_custom_ca_and_proxy(tmp_path, monkeypatch, ca_variable) -> None:
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path))
    monkeypatch.delenv("DCLAW_FLEET_API_TOKEN", raising=False)
    (tmp_path / ".env").write_text(
        "DCLAW_FLEET_API_URL=https://fleet.example.com/api/v1/fleet\n"
        "DCLAW_FLEET_API_TOKEN=fixture-token\n"
    )
    ca_bundle = tmp_path / "fleet-ca.pem"
    ca_bundle.write_text("fixture CA bundle", encoding="utf-8")
    monkeypatch.delenv("REQUESTS_CA_BUNDLE", raising=False)
    monkeypatch.delenv("CURL_CA_BUNDLE", raising=False)
    monkeypatch.setenv(ca_variable, str(ca_bundle))
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:3128")
    monkeypatch.setenv("NO_PROXY", "")
    netrc = tmp_path / "ignored.netrc"
    netrc.write_text("machine fleet.example.com login unrelated password unrelated\n", encoding="utf-8")
    monkeypatch.setenv("NETRC", str(netrc))
    app = _app(tmp_path)
    app.cfg.gateway = SimpleNamespace(api_port=18970, token="", resolved_token=lambda: "")

    client = cmd_edge_connector_cli._client(app)
    settings = client._s.merge_environment_settings(
        "https://fleet.example.com/api/v1/fleet/devices", {}, None, client._s.verify, None,
    )
    assert settings["verify"] == str(ca_bundle)
    assert settings["proxies"]["https"] == "http://127.0.0.1:3128"
    assert client._s.trust_env is False
    prepared = client._s.prepare_request(
        cmd_edge_connector_cli.req_lib.Request("POST", "https://fleet.example.com/api/v1/fleet/devices")
    )
    assert prepared.headers["Authorization"] == "Bearer fixture-token"


def test_edge_register_https_refuses_gateway_token_fallback(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path))
    monkeypatch.delenv("DCLAW_FLEET_API_TOKEN", raising=False)
    (tmp_path / ".env").write_text("DCLAW_FLEET_API_URL=https://fleet.example.com/api/v1/fleet\n")
    app = _app(tmp_path)
    app.cfg.gateway = SimpleNamespace(api_port=18970, token="gateway-token")
    with pytest.raises(click.ClickException, match="DCLAW_FLEET_API_TOKEN is required"):
        cmd_edge_connector_cli._client(app)


@pytest.mark.parametrize("platform", ["darwin", "win32"])
def test_edge_setup_non_linux_enables_gateway_without_linux_service(tmp_path, monkeypatch, platform) -> None:
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path))
    actual_platform = sys.platform
    monkeypatch.setattr(cmd_setup_edge_connector.sys, "platform", platform)
    if platform == "darwin" and actual_platform != "darwin" and os.name == "posix":
        # A simulated macOS branch on Linux cannot invoke macOS ACL tools.
        import defenseclaw.file_permissions as permissions

        monkeypatch.setattr(permissions, "_clear_darwin_extended_acl", lambda *_args: None)

    def unexpected_service_write(*_args):
        raise AssertionError("non-Linux Fleet gateway setup touched Linux service env")

    monkeypatch.setattr(cmd_setup_edge_connector, "_persist_svc_env_var", unexpected_service_write)
    enabled = []
    monkeypatch.setattr(cmd_setup_edge_connector, "_enable_fleet_config", enabled.append)
    result = CliRunner().invoke(
        cmd_setup_edge_connector.edge_connector,
        ["--non-interactive", "--token", "test-token"], obj=_app(tmp_path),
    )
    assert result.exit_code == 0, result.output
    assert enabled
    assert "C Edge" in result.output
    assert "/etc/defenseclaw/edge-connector.env" not in result.output
    assert "DCLAW_FLEET_API_URL=http://127.0.0.1:18970/api/v1/fleet" in (tmp_path / ".env").read_text()


def test_edge_setup_generates_distinct_keys_and_reuses_them(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path))
    # This assertion exercises the Linux device-service provisioning path even
    # when the suite runs on a Windows fleet gateway host.
    monkeypatch.setattr(cmd_setup_edge_connector.sys, "platform", "linux")
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


def test_edge_setup_config_failure_leaves_fleet_disabled(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path))

    def denied(_path):
        raise click.ClickException("managed config is locked")

    monkeypatch.setattr(cmd_setup_edge_connector, "_enable_fleet_config", denied)
    monkeypatch.setattr(cmd_setup_edge_connector, "_persist_svc_env_var", lambda *_args: True)
    result = CliRunner().invoke(
        cmd_setup_edge_connector.edge_connector,
        ["--non-interactive", "--token", "test-token"],
        obj=_app(tmp_path),
    )
    assert result.exit_code != 0
    assert "managed config is locked" in result.output
    assert not (tmp_path / "config.yaml").exists()


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


def test_fleet_compiler_installs_only_during_opt_in(tmp_path, monkeypatch) -> None:
    source_root = tmp_path / "source"
    compiler = source_root / "tools" / "policy_compiler.py"
    compiler.parent.mkdir(parents=True)
    compiler.write_bytes(b"# trusted compiler\n")
    from defenseclaw.commands import cmd_edge_install

    monkeypatch.setattr(cmd_edge_install, "_find_edge_connector_source", lambda: source_root)
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    assert not (home / "installer").exists()
    installed = cmd_setup_edge_connector._install_fleet_compiler(str(home))
    assert installed.read_bytes() == compiler.read_bytes()
    if os.name == "nt":
        from defenseclaw.file_permissions import windows_acl_write_error

        assert windows_acl_write_error(home) is None
        assert windows_acl_write_error(installed.parent) is None
        assert windows_acl_write_error(installed) is None
    else:
        assert installed.stat().st_mode & 0o777 == 0o600
    compiler.write_bytes(b"# updated compiler\n")
    assert cmd_setup_edge_connector._install_fleet_compiler(str(home)).read_bytes() == compiler.read_bytes()


def test_fleet_compiler_rejects_symlink_without_mutating_destination(tmp_path, monkeypatch) -> None:
    from defenseclaw.commands import cmd_edge_install

    source_root = tmp_path / "source"
    compiler = source_root / "tools" / "policy_compiler.py"
    compiler.parent.mkdir(parents=True)
    compiler.symlink_to(tmp_path / "untrusted.py")
    monkeypatch.setattr(cmd_edge_install, "_find_edge_connector_source", lambda: source_root)
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    with pytest.raises(click.ClickException, match="Fleet policy compiler missing"):
        cmd_setup_edge_connector._install_fleet_compiler(str(home))
    assert not (home / "installer").exists()


def test_explicit_fleet_assets_are_required_for_wheel_style_setup(tmp_path) -> None:
    assets = tmp_path / "fleet-assets"
    source = assets / "edge-connector"
    (source / "src").mkdir(parents=True)
    (source / "tools").mkdir()
    (source / "CMakeLists.txt").write_text("project(edge)\n", encoding="utf-8")
    (source / "src/main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
    (source / "tools/policy_compiler.py").write_text("# compiler\n", encoding="utf-8")
    assert cmd_edge_install._find_edge_connector_source(assets) == source
    assert cmd_setup_edge_connector._install_fleet_compiler(str(tmp_path), assets).is_file()


@pytest.mark.parametrize("remote", [False, True])
def test_edge_install_source_dir_supplies_systemd_unit_without_checkout_fallback(
    tmp_path, monkeypatch, remote: bool,
) -> None:
    assets = tmp_path / "fleet-assets"
    source = assets / "edge-connector"
    (source / "src").mkdir(parents=True)
    (source / "packaging").mkdir()
    (source / "CMakeLists.txt").write_text("project(edge)\n", encoding="utf-8")
    (source / "src/main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
    unit = source / "packaging/edge-connector.service"
    unit.write_text("[Service]\nUser=defenseclaw\nGroup=defenseclaw\n", encoding="utf-8")

    # A wheel cannot fall back to an adjacent source checkout.
    find_source = cmd_edge_install._find_edge_connector_source
    monkeypatch.setattr(
        cmd_edge_install, "_find_edge_connector_source",
        lambda source_dir=None: find_source(source_dir) if source_dir is not None else None,
    )
    copied = []
    commands = []
    if remote:
        monkeypatch.setattr(cmd_edge_install, "_check_remote_prereqs", lambda *_args: True)
        monkeypatch.setattr(cmd_edge_install, "_copy_source", lambda *_args: "/tmp/edge-source")
        monkeypatch.setattr(cmd_edge_install, "_build_remote", lambda *_args: True)
        monkeypatch.setattr(cmd_edge_install, "_register_device_via_api", lambda *_args: "12" * 32)
        monkeypatch.setattr(cmd_edge_install, "_configure_remote_env", lambda *_args, **_kwargs: True)
        monkeypatch.setattr(cmd_edge_install, "_verify_remote_daemon", lambda *_args: True)

        def fake_run(argv, **_kwargs):
            commands.append(argv)
            if argv[0] == "scp":
                copied.append(argv[3])
            return subprocess.CompletedProcess(argv, 0, stderr="")

        monkeypatch.setattr(cmd_edge_install.subprocess, "run", fake_run)
        args = ["--target", "device.example", "--device-id", "42"]
    else:
        monkeypatch.setattr(cmd_edge_install.shutil, "which", lambda _tool: "/usr/bin/tool")
        monkeypatch.setattr(cmd_edge_install, "_build_local", lambda *_args: True)
        monkeypatch.setattr(cmd_edge_install, "_provision_local_service_env", lambda *_args: True)
        monkeypatch.setattr(cmd_edge_install, "_verify_local_service", lambda: True)
        monkeypatch.setattr(
            cmd_edge_install.subprocess,
            "run",
            lambda argv, **_kwargs: subprocess.CompletedProcess(argv, 1),
        )

        def fake_local_run(argv):
            commands.append(argv)
            if argv[:2] == ["sudo", "cp"]:
                copied.append(argv[2])
            return subprocess.CompletedProcess(argv, 0)

        monkeypatch.setattr(
            cmd_edge_install, "_run",
            fake_local_run,
        )
        monkeypatch.setattr("platform.system", lambda: "Linux")
        args = []

    result = CliRunner().invoke(
        cmd_edge_install.edge_install,
        ["--source-dir", str(assets), *args],
        obj=_app(tmp_path),
    )
    assert result.exit_code == 0, result.output
    assert copied == [str(unit)]
    if remote:
        account = next(i for i, argv in enumerate(commands) if "useradd" in argv[-1])
        enabled = next(i for i, argv in enumerate(commands) if "systemctl enable" in argv[-1])
        assert "groupadd" in commands[account][-1]
    else:
        account = next(i for i, argv in enumerate(commands) if "useradd" in argv)
        enabled = next(i for i, argv in enumerate(commands) if "enable" in argv)
        assert any("groupadd" in argv for argv in commands[:account])
    assert account < enabled


def test_wheel_setup_without_fleet_assets_leaves_fleet_off(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path))
    monkeypatch.setattr(cmd_edge_install, "_find_edge_connector_source", lambda: None)
    result = CliRunner().invoke(
        cmd_setup_edge_connector.edge_connector,
        ["--non-interactive", "--token", "test-token"],
        obj=_app(tmp_path),
    )
    assert result.exit_code != 0
    assert "pass --source-dir" in result.output
    assert not (tmp_path / ".env").exists()
    assert not (tmp_path / "config.yaml").exists()


def test_edge_setup_service_write_failure_is_nonzero(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path))
    monkeypatch.setattr(cmd_setup_edge_connector.sys, "platform", "linux")
    monkeypatch.setattr(cmd_setup_edge_connector, "_persist_svc_env_var", lambda *_args: False)
    result = CliRunner().invoke(
        cmd_setup_edge_connector.edge_connector,
        ["--non-interactive", "--token", "test-token"],
        obj=_app(tmp_path),
    )
    assert result.exit_code != 0
    assert "setup is incomplete" in result.output
    assert not (tmp_path / "config.yaml").exists()


def test_dotenv_failed_replace_preserves_existing_secret(tmp_path, monkeypatch) -> None:
    import defenseclaw.file_permissions as permissions

    path = tmp_path / ".env"
    persist_env_var(path, "SECRET", "old")
    if os.name == "nt":
        assert permissions.windows_acl_confidentiality_error(path) is None
    else:
        assert path.stat().st_mode & 0o777 == 0o600

    def failed_replace(*_args):
        raise OSError("simulated rename failure")

    monkeypatch.setattr(permissions, "replace_file_durable", failed_replace)
    with pytest.raises(OSError, match="simulated rename failure"):
        persist_env_var(path, "SECRET", "new")
    assert path.read_text() == "SECRET=old\n"
    assert sorted(p.name for p in tmp_path.iterdir()) == [".env"]


def test_dotenv_unicode_values_round_trip(tmp_path) -> None:
    path = tmp_path / ".env"
    persist_env_var(path, "LABEL", "équipe")
    persist_env_var(path, "SECRET", "nouveau")
    assert path.read_text(encoding="utf-8") == "LABEL=équipe\nSECRET=nouveau\n"


@pytest.mark.parametrize("endpoint", [
    "http://fleet.example/api/v1/fleet",
    "http://localhost:18970/api/v1/fleet",
    "http://127.0.0.1.evil.example/api/v1/fleet",
    "http://user:password@127.0.0.1/api/v1/fleet",
    "https://user@fleet.example/api/v1/fleet",
    "https://fleet.example:invalid/api/v1/fleet",
    "https://fleet.example:0/api/v1/fleet",
    "https://fleet.example/api/v1/fleet?redirect=evil",
    "https://fleet.example/api/v1/fleet#fragment",
    "https://fleet.example/api/v1/fleet?",
    "https://fleet.example/api/v1/fleet#",
    "https://fleet.example:/api/v1/fleet",
    "ftp://fleet.example/api/v1/fleet",
    "https://fleet.example\\@evil.example/api/v1/fleet",
])
def test_edge_setup_rejects_insecure_or_malformed_endpoint_before_writing(
    tmp_path, monkeypatch, endpoint: str,
) -> None:
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path))
    result = CliRunner().invoke(
        cmd_setup_edge_connector.edge_connector,
        ["--non-interactive", "--token", "test-token", "--endpoint", endpoint],
        obj=_app(tmp_path),
    )
    assert result.exit_code != 0, endpoint
    assert not (tmp_path / ".env").exists()
    assert not (tmp_path / "config.yaml").exists()


@pytest.mark.parametrize("endpoint", [
    "http://127.0.0.1:18970/api/v1/fleet",
    "http://[::1]:18970/api/v1/fleet",
    "https://fleet.example/api/v1/fleet",
])
def test_fleet_endpoint_accepts_literal_loopback_or_remote_tls(endpoint: str) -> None:
    assert cmd_setup_edge_connector._validate_fleet_endpoint(endpoint) == endpoint


def test_device_registration_rejects_poisoned_endpoint_before_curl(monkeypatch) -> None:
    monkeypatch.setenv("DCLAW_FLEET_API_URL", "http://fleet.example/api/v1/fleet")
    monkeypatch.setenv("DCLAW_FLEET_API_TOKEN", "test-secret")
    monkeypatch.setattr(
        cmd_edge_install.subprocess, "run",
        lambda *_args, **_kwargs: pytest.fail("curl must not receive bearer token"),
    )
    with pytest.raises(click.ClickException, match="requires HTTPS"):
        cmd_edge_install._register_device_via_api("1", "1", "42")


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


def test_mqtt_config_failure_leaves_fleet_disabled(tmp_path, monkeypatch) -> None:
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
    assert not (tmp_path / "config.yaml").exists()


def test_mqtt_env_failure_leaves_fleet_disabled(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path))
    monkeypatch.setattr(cmd_setup_mqtt, "_setup_docker", lambda _port: {})
    monkeypatch.setattr(cmd_setup_mqtt, "_wait_for_broker", lambda *_args: True)
    monkeypatch.setattr(
        cmd_setup_mqtt, "_persist_env_var",
        lambda *_args: (_ for _ in ()).throw(OSError("disk full")),
    )
    result = CliRunner().invoke(
        cmd_setup_mqtt.mqtt_broker, ["--docker", "--port", "21883"], obj=AppContext(),
    )
    assert result.exit_code != 0
    assert "Could not persist MQTT environment" in result.output
    assert not (tmp_path / "config.yaml").exists()


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
