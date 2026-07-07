# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Deterministic native Local Splunk lifecycle coverage."""

from __future__ import annotations

import ast
import json
import os
import shutil
import tarfile
from pathlib import Path
from unittest.mock import patch

import defenseclaw.observability.local_splunk as local_splunk
import pytest
from defenseclaw.file_permissions import windows_acl_write_error
from defenseclaw.observability.local_splunk import (
    APP_PACKAGE_REL,
    COMPOSE_FILE_REL,
    COMPOSE_PROJECT,
    ENV_FILE_REL,
    NativeLocalSplunkController,
    _credential_values,
    package_splunk_app,
    start_native_local_splunk,
)
from defenseclaw.observability.local_stack import (
    CommandResult,
    LocalStackError,
    resolve_native_docker_executable,
)
from defenseclaw.paths import bundled_splunk_bridge_dir


class FakeDockerRunner:
    def __init__(self, *, info: dict[str, object] | None = None) -> None:
        self.calls: list[tuple[tuple[str, ...], float, dict[str, str]]] = []
        self.info = info or {
            "OSType": "linux",
            "OperatingSystem": "Docker Engine",
            "KernelVersion": "6.8.0",
        }
        self.containers: dict[str, dict[str, object]] = {}
        self.fail_compose_version = False
        self.fail_info = False
        self.fail_up = False
        self.fail_down = False
        self.volumes = {
            "defenseclaw_splunk_local_etc",
            "defenseclaw_splunk_local_var",
            "defenseclaw_splunk_s3_exporter_state",
        }
        self.volume_labels = {
            "defenseclaw_splunk_local_etc": {
                "com.docker.compose.project": COMPOSE_PROJECT,
                "com.docker.compose.volume": "splunk_etc",
            },
            "defenseclaw_splunk_local_var": {
                "com.docker.compose.project": COMPOSE_PROJECT,
                "com.docker.compose.volume": "splunk_var",
            },
            "defenseclaw_splunk_s3_exporter_state": {
                "com.docker.compose.project": COMPOSE_PROJECT,
                "com.docker.compose.volume": "splunk_s3_exporter_state",
            },
        }

    def add_owned(self, stack: Path, *, container_id: str = "owned-splunk") -> None:
        self.containers[container_id] = {
            "running": True,
            "labels": {
                "com.docker.compose.project": COMPOSE_PROJECT,
                "com.docker.compose.service": "splunk",
                "com.docker.compose.project.config_files": str((stack / COMPOSE_FILE_REL).resolve()),
                "com.docker.compose.project.working_dir": str(stack.resolve()),
            },
            "ports": {
                "8000/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8000"}],
                "8088/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8088"}],
            },
        }

    def add_owned_exporter(
        self,
        stack: Path,
        *,
        container_id: str = "owned-exporter",
        bucket: str = "prior-bucket",
    ) -> None:
        self.containers[container_id] = {
            "running": True,
            "labels": {
                "com.docker.compose.project": COMPOSE_PROJECT,
                "com.docker.compose.service": "splunk-s3-exporter",
                "com.docker.compose.project.config_files": str((stack / COMPOSE_FILE_REL).resolve()),
                "com.docker.compose.project.working_dir": str(stack.resolve()),
            },
            "ports": {},
            "env": ["S3_EXPORT_ENABLED=true", f"S3_BUCKET={bucket}", "AWS_REGION=eu-west-1"],
        }

    def run(self, argv, *, timeout: float, capture: bool = True, env=None) -> CommandResult:
        command = tuple(argv)
        self.calls.append((command, timeout, dict(env or {})))
        if command[1:3] == ("compose", "version"):
            return CommandResult(command, 1 if self.fail_compose_version else 0)
        if command[1:2] == ("info",):
            if self.fail_info:
                return CommandResult(command, 1, "", "daemon stopped")
            return CommandResult(command, 0, json.dumps(self.info), "")
        if command[1:2] == ("ps",):
            running_only = "status=running" in command
            ids = [cid for cid, state in self.containers.items() if not running_only or state["running"]]
            return CommandResult(command, 0, "\n".join(ids), "")
        if command[1:2] == ("inspect",):
            cid = command[-1]
            if cid not in self.containers:
                return CommandResult(command, 1, "", "not found")
            state = self.containers[cid]
            if any("NetworkSettings.Ports" in item for item in command):
                value = state["ports"]
            elif any(".Config.Env" in item for item in command):
                value = state.get("env", [])
            else:
                value = state["labels"]
            return CommandResult(command, 0, json.dumps(value), "")
        if command[1:2] == ("rm",):
            self.containers.pop(command[-1], None)
            return CommandResult(command, 0)
        if command[1:3] == ("volume", "ls"):
            return CommandResult(command, 0, "\n".join(sorted(self.volumes)), "")
        if command[1:3] == ("volume", "inspect"):
            name = command[-1]
            if name not in self.volume_labels:
                return CommandResult(command, 1, "", "not found")
            return CommandResult(command, 0, json.dumps(self.volume_labels[name]), "")
        if command[1:2] == ("compose",):
            if "up" in command:
                if self.fail_up:
                    return CommandResult(command, 2, "", "compose failed")
                project_dir = Path(command[command.index("--project-directory") + 1])
                self.add_owned(project_dir)
                if "s3-export" in command:
                    self.add_owned_exporter(project_dir, bucket=dict(env or {}).get("S3_BUCKET", "prior-bucket"))
                return CommandResult(command, 0)
            if "down" in command:
                self.containers.clear()
                return CommandResult(command, 3 if self.fail_down else 0, "", "down failed")
            if "exec" in command:
                return CommandResult(command, 0, '{"status":"skipped_no_destination"}', "")
        return CommandResult(command, 0)


@pytest.fixture
def docker_exe(tmp_path: Path) -> Path:
    executable = tmp_path / "native docker" / "docker.exe"
    executable.parent.mkdir()
    executable.write_bytes(b"mock")
    return executable


@pytest.fixture
def stack(tmp_path: Path) -> Path:
    destination = tmp_path / "Local Splunk Ω with spaces"
    shutil.copytree(bundled_splunk_bridge_dir(), destination)
    values = _credential_values(
        {"SPLUNK_IMAGE": "example.invalid/splunk:test"},
        {},
        index="defenseclaw_local",
        source="defenseclaw",
        sourcetype="defenseclaw:json",
    )
    (destination / ENV_FILE_REL).write_text(
        "".join(f"{key}={value}\n" for key, value in sorted(values.items())),
        encoding="utf-8",
    )
    package_splunk_app(destination)
    return destination


@pytest.mark.parametrize("name", ["docker.cmd", "docker.bat", "docker", "renamed.exe"])
def test_windows_rejects_every_non_native_docker_launcher(tmp_path: Path, name: str) -> None:
    candidate = tmp_path / name
    candidate.write_bytes(b"mock")
    with pytest.raises(LocalStackError, match="native.*docker.exe"):
        resolve_native_docker_executable(candidate, os_name="windows")


def test_native_controller_requires_explicit_license_acceptance(tmp_path: Path, docker_exe: Path) -> None:
    runner = FakeDockerRunner()
    data_dir = tmp_path / "license gate"
    with pytest.raises(LocalStackError, match="General Terms acceptance"):
        start_native_local_splunk(
            str(data_dir),
            index="defenseclaw_local",
            source="defenseclaw",
            sourcetype="defenseclaw:json",
            docker_path=docker_exe,
            runner=runner,
            os_name="linux",
            environment={},
        )
    assert runner.calls == []
    assert not data_dir.exists()


def test_compose_argv_is_shell_free_absolute_and_unicode_safe(stack: Path, docker_exe: Path) -> None:
    subject = NativeLocalSplunkController(stack, docker_path=docker_exe, runner=FakeDockerRunner(), os_name="linux")
    argv = subject.compose_argv("up", "--detach", s3_export=True)
    assert argv[0] == str(docker_exe.resolve())
    assert argv[1] == "compose"
    assert argv[argv.index("--project-directory") + 1] == str(stack.resolve())
    assert argv[argv.index("--file") + 1] == str((stack / COMPOSE_FILE_REL).resolve())
    assert argv[argv.index("--project-name") + 1] == COMPOSE_PROJECT
    assert argv[-2:] == ["up", "--detach"]
    assert "s3-export" in argv
    assert all(isinstance(item, str) for item in argv)


def test_optional_s3_process_environment_overrides_template_defaults(stack: Path, docker_exe: Path) -> None:
    subject = NativeLocalSplunkController(
        stack,
        docker_path=docker_exe,
        runner=FakeDockerRunner(),
        os_name="linux",
        environment={
            "S3_BUCKET": "operator-bucket",
            "AWS_ACCESS_KEY_ID": "dynamic-access-id",
            "AWS_SECRET_ACCESS_KEY": "dynamic-secret-value",
        },
    )
    environment = subject._compose_environment({"S3_EXPORT_ENABLED": "true"})
    assert environment["S3_BUCKET"] == "operator-bucket"
    assert environment["AWS_ACCESS_KEY_ID"] == "dynamic-access-id"
    assert environment["AWS_SECRET_ACCESS_KEY"] == "dynamic-secret-value"
    assert environment["S3_EXPORT_ENABLED"] == "true"


@pytest.mark.parametrize(
    ("mutator", "message"),
    [
        (lambda runner: setattr(runner, "fail_compose_version", True), "Compose v2"),
        (lambda runner: setattr(runner, "fail_info", True), "daemon is not reachable"),
        (lambda runner: runner.info.update({"OSType": "windows"}), "Linux containers"),
    ],
)
def test_docker_compose_daemon_and_container_mode_failures(
    stack: Path, docker_exe: Path, mutator, message: str
) -> None:
    runner = FakeDockerRunner()
    mutator(runner)
    subject = NativeLocalSplunkController(stack, docker_path=docker_exe, runner=runner, os_name="linux")
    with pytest.raises(LocalStackError, match=message):
        subject.preflight()


def test_windows_x64_edition_wsl_and_hyperv_checks(stack: Path, docker_exe: Path, tmp_path: Path) -> None:
    appdata = tmp_path / "Profile Ω" / "AppData" / "Roaming"
    settings = appdata / "Docker" / "settings-store.json"
    settings.parent.mkdir(parents=True)
    settings.write_text('{"wslEngineEnabled": false}', encoding="utf-8")
    runner = FakeDockerRunner(
        info={
            "OSType": "linux",
            "OperatingSystem": "Docker Desktop",
            "KernelVersion": "6.10-linuxkit",
        }
    )
    subject = NativeLocalSplunkController(
        stack,
        docker_path=docker_exe,
        runner=runner,
        os_name="windows",
        environment={"APPDATA": str(appdata)},
    )
    with (
        patch("platform.machine", return_value="AMD64"),
        patch("platform.win32_edition", return_value="Professional"),
    ):
        subject.preflight()
    runner.info["KernelVersion"] = "5.15-microsoft-standard-WSL2"
    with (
        patch("platform.machine", return_value="AMD64"),
        patch("platform.win32_edition", return_value="Professional"),
        pytest.raises(LocalStackError, match="WSL 2 backend"),
    ):
        subject.preflight()
    runner.info["KernelVersion"] = "6.10-linuxkit"
    with (
        patch("platform.machine", return_value="ARM64"),
        patch("platform.win32_edition", return_value="Professional"),
        pytest.raises(LocalStackError, match="x64"),
    ):
        subject.preflight()
    with (
        patch("platform.machine", return_value="AMD64"),
        patch("platform.win32_edition", return_value="Home"),
        pytest.raises(LocalStackError, match="Pro, Enterprise, or Education"),
    ):
        subject.preflight()


def test_port_checks_allow_exact_owned_project_and_reject_foreign_owner(
    stack: Path, docker_exe: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = FakeDockerRunner()
    runner.add_owned(stack)
    subject = NativeLocalSplunkController(stack, docker_path=docker_exe, runner=runner, os_name="linux")
    monkeypatch.setattr(subject, "_port_in_use", lambda _port: True)
    subject.verify_port_ownership()

    runner.containers["owned-splunk"]["labels"]["com.docker.compose.project.working_dir"] = str(
        stack.parent / "foreign"
    )
    with pytest.raises(LocalStackError, match="identity collision"):
        subject.verify_port_ownership()

    runner.containers.clear()
    with pytest.raises(LocalStackError, match="foreign process"):
        subject.verify_port_ownership()


def test_foreign_named_volume_is_rejected_before_compose_up(stack: Path, docker_exe: Path) -> None:
    runner = FakeDockerRunner()
    runner.volume_labels["defenseclaw_splunk_local_etc"] = {
        "com.docker.compose.project": "foreign-project",
        "com.docker.compose.volume": "splunk_etc",
    }
    subject = NativeLocalSplunkController(stack, docker_path=docker_exe, runner=runner, os_name="linux")
    with pytest.raises(LocalStackError, match="ownership is unproven"):
        subject.verify_volume_ownership()


def test_readiness_timeout_cleans_only_new_containers(
    stack: Path, docker_exe: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = FakeDockerRunner()
    subject = NativeLocalSplunkController(stack, docker_path=docker_exe, runner=runner, os_name="linux")
    monkeypatch.setattr(subject, "_web_ready", lambda _timeout: False)
    monkeypatch.setattr(subject, "_hec_ready", lambda _timeout: False)
    with pytest.raises(LocalStackError, match="readiness timeout"):
        subject.up(timeout=1)
    assert runner.containers == {}
    assert any(call[0][1:3] == ("rm", "--force") for call in runner.calls)


def test_fresh_start_failure_removes_staged_assets_and_credentials(
    tmp_path: Path, docker_exe: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data_dir = tmp_path / "fresh failure Ω"
    runner = FakeDockerRunner()
    runner.fail_up = True
    monkeypatch.setattr(NativeLocalSplunkController, "_port_in_use", staticmethod(lambda _port: False))
    with pytest.raises(LocalStackError, match="compose up"):
        start_native_local_splunk(
            str(data_dir),
            license_accepted=True,
            index="defenseclaw_local",
            source="defenseclaw",
            sourcetype="defenseclaw:json",
            docker_path=docker_exe,
            runner=runner,
            os_name="linux",
            environment={},
            timeout=2,
        )
    assert not (data_dir / "splunk-bridge").exists()
    assert not list(data_dir.glob(".splunk-stage-*"))


def test_repeat_setup_is_idempotent_disable_preserves_volumes_and_telemetry_uses_no_shell(
    stack: Path, docker_exe: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = FakeDockerRunner()
    subject = NativeLocalSplunkController(stack, docker_path=docker_exe, runner=runner, os_name="linux")
    monkeypatch.setattr(subject, "_web_ready", lambda _timeout: True)
    monkeypatch.setattr(subject, "_hec_ready", lambda _timeout: True)
    first, created = subject.up(timeout=2)
    second, repeated_created = subject.up(timeout=2)
    assert first.hec_token == second.hec_token
    assert created == {"owned-splunk"}
    assert repeated_created == set()

    volumes_before = set(runner.volumes)
    subject.down()
    assert runner.volumes == volumes_before
    down = next(call[0] for call in runner.calls if "down" in call[0])
    assert "--volumes" not in down and "-v" not in down
    forbidden = {"bash", "sh", "wsl", "sudo", "systemctl", "cmd.exe"}
    for command, _timeout, _env in runner.calls:
        assert Path(command[0]).name.lower() == "docker.exe"
        assert not any(Path(argument).name.lower() in forbidden for argument in command)


def test_app_package_is_deterministic_and_contains_native_telemetry_script(
    stack: Path,
) -> None:
    first = package_splunk_app(stack).read_bytes()
    second = package_splunk_app(stack).read_bytes()
    assert first == second
    with tarfile.open(stack / APP_PACKAGE_REL, "r:gz") as archive:
        names = set(archive.getnames())
    assert "defenseclaw_local_mode/bin/emit_product_telemetry_lifecycle.py" in names
    assert all("__pycache__" not in name and not name.endswith(".pyc") for name in names)


def test_credentials_are_secure_random_and_never_repr_in_controller_source() -> None:
    template = {"SPLUNK_IMAGE": "example.invalid/splunk:test"}
    first = _credential_values(template, {}, index="i", source="s", sourcetype="t")
    second = _credential_values(template, {}, index="i", source="s", sourcetype="t")
    assert first["SPLUNK_HEC_TOKEN"] != second["SPLUNK_HEC_TOKEN"]
    assert first["SPLUNK_PASSWORD"] != second["SPLUNK_PASSWORD"]
    assert len(first["SPLUNK_HEC_TOKEN"]) >= 32
    assert len(first["SPLUNK_PASSWORD"]) >= 32

    source_path = Path(__import__(NativeLocalSplunkController.__module__, fromlist=["x"]).__file__)
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    assert not any(
        isinstance(node, ast.Call)
        and any(
            keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True
            for keyword in node.keywords
        )
        for node in ast.walk(tree)
    )


def test_child_failure_redacts_generated_secrets(stack: Path, docker_exe: Path) -> None:
    runner = FakeDockerRunner()
    subject = NativeLocalSplunkController(stack, docker_path=docker_exe, runner=runner, os_name="linux")
    token = subject.contract().hec_token
    result = CommandResult((str(docker_exe),), 7, "", f"failed with {token}")
    with pytest.raises(LocalStackError) as raised:
        subject._checked(result, "docker compose up")
    assert token not in str(raised.value)
    assert "[REDACTED]" in str(raised.value)


def test_bundle_validation_rejects_reparse_or_symlink_assets(stack: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    compose = stack / COMPOSE_FILE_REL
    original = local_splunk._is_reparse_or_symlink
    monkeypatch.setattr(
        local_splunk,
        "_is_reparse_or_symlink",
        lambda path: path == compose or original(path),
    )
    with pytest.raises(LocalStackError, match="reparse/symlink"):
        local_splunk.validate_bundle_assets(stack)


def test_start_from_unicode_profile_protects_credentials(
    tmp_path: Path, docker_exe: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data_dir = tmp_path / "Profile Ω" / "DefenseClaw Data"
    runner = FakeDockerRunner()
    monkeypatch.setattr(NativeLocalSplunkController, "_port_in_use", staticmethod(lambda _port: False))
    monkeypatch.setattr(NativeLocalSplunkController, "_web_ready", staticmethod(lambda _timeout: True))
    monkeypatch.setattr(NativeLocalSplunkController, "_hec_ready", lambda self, _timeout: True)
    transaction = start_native_local_splunk(
        str(data_dir),
        license_accepted=True,
        index="defenseclaw_local",
        source="defenseclaw",
        sourcetype="defenseclaw:json",
        docker_path=docker_exe,
        runner=runner,
        os_name="linux",
        environment={},
        timeout=2,
    )
    env_file = data_dir / "splunk-bridge" / ENV_FILE_REL
    assert env_file.is_file()
    if os.name == "nt":
        assert windows_acl_write_error(env_file) is None
    else:
        assert env_file.stat().st_mode & 0o077 == 0
    contents = env_file.read_text(encoding="utf-8")
    assert transaction.contract.hec_token in contents
    transaction.commit()


def test_fresh_config_transaction_rollback_removes_runtime_assets(
    tmp_path: Path, docker_exe: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data_dir = tmp_path / "Fresh Rollback Ω"
    runner = FakeDockerRunner()
    monkeypatch.setattr(NativeLocalSplunkController, "_port_in_use", staticmethod(lambda _port: False))
    monkeypatch.setattr(NativeLocalSplunkController, "_web_ready", staticmethod(lambda _timeout: True))
    monkeypatch.setattr(NativeLocalSplunkController, "_hec_ready", lambda self, _timeout: True)
    transaction = start_native_local_splunk(
        str(data_dir),
        license_accepted=True,
        index="defenseclaw_local",
        source="defenseclaw",
        sourcetype="defenseclaw:json",
        docker_path=docker_exe,
        runner=runner,
        os_name="linux",
        environment={},
        timeout=2,
    )
    token = transaction.contract.hec_token
    assert token not in repr(transaction.contract)
    assert "hec_token" not in transaction.contract.as_dict()
    transaction.rollback()
    assert runner.containers == {}
    assert not (data_dir / "splunk-bridge").exists()


def test_failed_upgrade_stop_restores_prior_running_stack_before_returning(
    tmp_path: Path, docker_exe: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data_dir = tmp_path / "Stop Failure Ω"
    stable = data_dir / "splunk-bridge"
    data_dir.mkdir()
    shutil.copytree(bundled_splunk_bridge_dir(), stable)
    previous_values = _credential_values(
        {"SPLUNK_IMAGE": "example.invalid/splunk:previous"},
        {},
        index="previous_index",
        source="previous_source",
        sourcetype="previous:type",
    )
    (stable / ENV_FILE_REL).write_text(
        "".join(f"{key}={value}\n" for key, value in sorted(previous_values.items())),
        encoding="utf-8",
    )
    package_splunk_app(stable)
    previous_env = (stable / ENV_FILE_REL).read_bytes()
    runner = FakeDockerRunner()
    runner.add_owned(stable, container_id="prior-container")
    runner.fail_down = True
    monkeypatch.setattr(NativeLocalSplunkController, "_port_in_use", staticmethod(lambda _port: True))
    monkeypatch.setattr(NativeLocalSplunkController, "_web_ready", staticmethod(lambda _timeout: True))
    monkeypatch.setattr(NativeLocalSplunkController, "_hec_ready", lambda self, _timeout: True)
    with pytest.raises(LocalStackError, match="compose down"):
        start_native_local_splunk(
            str(data_dir),
            license_accepted=True,
            index="replacement_index",
            source="replacement_source",
            sourcetype="replacement:type",
            docker_path=docker_exe,
            runner=runner,
            os_name="linux",
            environment={},
            timeout=2,
        )
    assert (stable / ENV_FILE_REL).read_bytes() == previous_env
    assert runner.containers
    assert all(state["running"] for state in runner.containers.values())


def test_upgrade_rollback_restores_prior_assets_running_stack_and_volumes(
    tmp_path: Path, docker_exe: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data_dir = tmp_path / "Upgrade Profile Ω"
    stable = data_dir / "splunk-bridge"
    data_dir.mkdir()
    shutil.copytree(bundled_splunk_bridge_dir(), stable)
    previous_values = _credential_values(
        {"SPLUNK_IMAGE": "example.invalid/splunk:previous"},
        {},
        index="previous_index",
        source="previous_source",
        sourcetype="previous:type",
    )
    (stable / ENV_FILE_REL).write_text(
        "".join(f"{key}={value}\n" for key, value in sorted(previous_values.items())),
        encoding="utf-8",
    )
    package_splunk_app(stable)
    previous_env = (stable / ENV_FILE_REL).read_bytes()

    runner = FakeDockerRunner()
    runner.add_owned(stable, container_id="prior-container")
    runner.add_owned_exporter(stable, container_id="prior-exporter", bucket="restore-me")
    volumes_before = set(runner.volumes)
    monkeypatch.setattr(NativeLocalSplunkController, "_port_in_use", staticmethod(lambda _port: True))
    monkeypatch.setattr(NativeLocalSplunkController, "_web_ready", staticmethod(lambda _timeout: True))
    monkeypatch.setattr(NativeLocalSplunkController, "_hec_ready", lambda self, _timeout: True)
    transaction = start_native_local_splunk(
        str(data_dir),
        license_accepted=True,
        index="replacement_index",
        source="replacement_source",
        sourcetype="replacement:type",
        docker_path=docker_exe,
        runner=runner,
        os_name="linux",
        environment={},
        timeout=2,
    )
    assert b"replacement_index" in (stable / ENV_FILE_REL).read_bytes()
    transaction.rollback()
    assert (stable / ENV_FILE_REL).read_bytes() == previous_env
    assert runner.volumes == volumes_before
    assert set(runner.containers) == {"owned-splunk", "owned-exporter"}
    assert all(item["running"] is True for item in runner.containers.values())
    assert all(
        item["labels"]["com.docker.compose.project.working_dir"] == str(stable.resolve())
        for item in runner.containers.values()
    )
    restored_up = next(call for call in reversed(runner.calls) if "up" in call[0])
    assert "--profile" in restored_up[0]
    assert restored_up[2]["S3_BUCKET"] == "restore-me"
    assert restored_up[2]["AWS_REGION"] == "eu-west-1"
