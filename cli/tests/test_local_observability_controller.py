# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

"""Pure lifecycle and process-safety tests for the shared local-stack controller."""

from __future__ import annotations

import ast
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from defenseclaw.observability.local_stack import (
    COMPOSE_PROJECT,
    CONTRACT,
    SERVICE_CONTAINERS,
    CommandResult,
    CommandRunner,
    LocalStackController,
    LocalStackError,
    ProbeResult,
)


class FakeRunner:
    """Deterministic Docker boundary with per-prefix overrides."""

    def __init__(self) -> None:
        self.calls: list[tuple[tuple[str, ...], float, bool, dict[str, str]]] = []
        self.overrides: list[tuple[tuple[str, ...], int, str, str]] = []
        self.info = {
            "OSType": "linux",
            "OperatingSystem": "Docker Engine",
            "KernelVersion": "6.8.0",
        }

    def add(
        self,
        prefix: tuple[str, ...],
        *,
        returncode: int = 0,
        stdout: str = "",
        stderr: str = "",
    ) -> None:
        self.overrides.append((prefix, returncode, stdout, stderr))

    def run(
        self,
        argv,
        *,
        timeout: float,
        capture: bool = True,
        env=None,
    ) -> CommandResult:
        command = tuple(argv)
        self.calls.append((command, timeout, capture, dict(env or {})))
        for prefix, returncode, stdout, stderr in reversed(self.overrides):
            if command[: len(prefix)] == prefix:
                return CommandResult(command, returncode, stdout, stderr)
        if len(command) >= 3 and command[1:3] == ("compose", "version"):
            return CommandResult(command, 0, "Docker Compose version v2.30.0\n", "")
        if len(command) >= 2 and command[1] == "info":
            return CommandResult(command, 0, json.dumps(self.info), "")
        if len(command) >= 2 and command[1] == "inspect":
            return CommandResult(command, 1, "", "not found")
        if len(command) >= 3 and command[1:3] == ("volume", "inspect"):
            return CommandResult(command, 1, "", "not found")
        if len(command) >= 2 and command[1] == "ps":
            return CommandResult(command, 0, "", "")
        return CommandResult(command, 0, "", "")


@pytest.fixture
def stack(tmp_path: Path) -> Path:
    root = tmp_path / "stack with spaces Ω"
    root.mkdir()
    (root / "docker-compose.yml").write_bytes(
        b"name: defenseclaw-observability\r\nservices: {}\r\n"
    )
    return root


@pytest.fixture
def docker(tmp_path: Path) -> Path:
    path = tmp_path / "docker.exe"
    path.write_bytes(b"mock")
    return path


@pytest.fixture
def controller(stack: Path, docker: Path) -> tuple[LocalStackController, FakeRunner]:
    runner = FakeRunner()
    return (
        LocalStackController(stack, docker_path=docker, runner=runner, os_name="linux"),
        runner,
    )


def _compose_call(runner: FakeRunner, action: str) -> tuple[str, ...]:
    return next(
        call[0]
        for call in runner.calls
        if len(call[0]) > 2 and call[0][1] == "compose" and action in call[0][2:]
    )


def test_compose_argv_is_absolute_explicit_and_unicode_safe(controller) -> None:
    subject, _runner = controller
    argv = subject.compose_argv("up", "--detach")
    assert Path(argv[0]).is_absolute()
    assert argv[1:2] == ["compose"]
    assert argv[2:8:2] == ["--project-directory", "--file", "--project-name"]
    assert argv[3] == str(subject.stack_dir)
    assert argv[5] == str(subject.compose_file)
    assert argv[7] == COMPOSE_PROJECT
    assert "Ω" in argv[3]


def test_every_lifecycle_action_uses_the_same_controller(controller) -> None:
    subject, runner = controller
    probes = [ProbeResult("all", "local", True)]
    with patch.object(subject, "probe_all", return_value=probes):
        up = subject.up(timeout=2)
        status = subject.status()
    subject.logs(service="grafana")
    subject.down()
    subject.reset(confirmed=True)

    assert up.contract == CONTRACT
    assert up.readiness_verified is True
    assert "Readiness:" in status
    assert "ready" in status
    assert _compose_call(runner, "up")[-2:] == ("up", "--detach")
    assert _compose_call(runner, "logs")[-5:] == (
        "logs",
        "--tail",
        "200",
        "--",
        "grafana",
    )
    assert _compose_call(runner, "down")[-1] == "down"
    reset = [call[0] for call in runner.calls if call[0][-2:] == ("down", "--volumes")]
    assert reset


def test_repeat_up_down_reset_is_idempotent(controller) -> None:
    subject, runner = controller
    for _ in range(2):
        subject.up(wait=False)
        subject.down()
        subject.reset(confirmed=True)
    compose_commands = [call[0] for call in runner.calls if call[0][1] == "compose"]
    assert sum(command[-2:] == ("up", "--detach") for command in compose_commands) == 2
    assert sum(command[-1:] == ("down",) for command in compose_commands) == 2
    assert sum(command[-2:] == ("down", "--volumes") for command in compose_commands) == 2


def test_no_wait_reports_unverified_readiness(controller) -> None:
    subject, _runner = controller
    result = subject.up(timeout=2, wait=False)
    assert result.contract == CONTRACT
    assert result.readiness_verified is False


@pytest.mark.parametrize("os_name", ["darwin", "linux"])
def test_macos_linux_keep_the_same_python_compose_lifecycle(
    stack: Path, docker: Path, os_name: str
) -> None:
    runner = FakeRunner()
    subject = LocalStackController(
        stack, docker_path=docker, runner=runner, os_name=os_name
    )
    result = subject.up(wait=False)
    assert result.contract == CONTRACT
    assert _compose_call(runner, "up")[-2:] == ("up", "--detach")


def test_managed_controller_strips_host_bind_override(
    stack: Path, docker: Path
) -> None:
    runner = FakeRunner()
    subject = LocalStackController(
        stack,
        docker_path=docker,
        runner=runner,
        os_name="linux",
        environment={"HOST_BIND": "192.0.2.10", "PRESERVED": "yes"},
    )

    subject.up(wait=False)

    assert runner.calls
    assert all("HOST_BIND" not in environment for _, _, _, environment in runner.calls)
    assert all(environment["PRESERVED"] == "yes" for _, _, _, environment in runner.calls)


def test_contract_and_environment_are_stable() -> None:
    assert LocalStackController.contract() == CONTRACT
    assert LocalStackController.environment_contract() == {
        "DEFENSECLAW_TELEMETRY_ENABLED": "1",
        "OTEL_EXPORTER_OTLP_ENDPOINT": "http://127.0.0.1:4317",
        "OTEL_EXPORTER_OTLP_PROTOCOL": "grpc",
        "OTEL_SERVICE_NAME": "defenseclaw",
        "OTEL_RESOURCE_ATTRIBUTES": (
            "service.namespace=defenseclaw,deployment.environment=local-dev"
        ),
    }


def test_docker_cli_compose_daemon_and_linux_mode_failures(
    stack: Path, docker: Path
) -> None:
    with pytest.raises(LocalStackError, match="Docker CLI"):
        LocalStackController(stack, docker_path="", os_name="linux").preflight()

    compose_runner = FakeRunner()
    compose_runner.add((str(docker.resolve()), "compose", "version"), returncode=1)
    with pytest.raises(LocalStackError, match="Compose v2"):
        LocalStackController(
            stack, docker_path=docker, runner=compose_runner, os_name="linux"
        ).preflight()

    daemon_runner = FakeRunner()
    daemon_runner.add(
        (str(docker.resolve()), "info"), returncode=1, stderr="daemon unavailable"
    )
    with pytest.raises(LocalStackError, match="daemon is not reachable"):
        LocalStackController(
            stack, docker_path=docker, runner=daemon_runner, os_name="linux"
        ).preflight()

    mode_runner = FakeRunner()
    mode_runner.info["OSType"] = "windows"
    with pytest.raises(LocalStackError, match="Switch Docker Desktop to Linux containers"):
        LocalStackController(
            stack, docker_path=docker, runner=mode_runner, os_name="linux"
        ).preflight()


def test_windows_rejects_command_script_docker_shim(stack: Path, tmp_path: Path) -> None:
    docker_cmd = tmp_path / "docker.cmd"
    docker_cmd.write_bytes(b"@exit /b 0\r\n")
    with pytest.raises(LocalStackError, match="native.*docker.exe"):
        LocalStackController(stack, docker_path=docker_cmd, os_name="windows")


def test_windows_hyperv_validation_and_wsl_rejection(
    stack: Path, docker: Path, tmp_path: Path
) -> None:
    appdata = tmp_path / "profile Ω" / "AppData" / "Roaming"
    settings = appdata / "Docker" / "settings-store.json"
    settings.parent.mkdir(parents=True)
    settings.write_text('{"wslEngineEnabled": false}\r\n', encoding="utf-8")
    runner = FakeRunner()
    runner.info.update(
        {
            "OperatingSystem": "Docker Desktop",
            "KernelVersion": "6.10.14-linuxkit",
        }
    )
    subject = LocalStackController(
        stack,
        docker_path=docker,
        runner=runner,
        os_name="windows",
        environment={"APPDATA": str(appdata)},
    )
    with (
        patch("platform.machine", return_value="AMD64"),
        patch("platform.win32_edition", return_value="Professional"),
    ):
        assert subject.preflight()["OSType"] == "linux"

    runner.info["KernelVersion"] = "5.15.153.1-microsoft-standard-WSL2"
    with (
        patch("platform.machine", return_value="AMD64"),
        patch("platform.win32_edition", return_value="Professional"),
        pytest.raises(LocalStackError, match="WSL 2 backend"),
    ):
        subject.preflight()


def test_windows_requires_supported_edition_and_verifiable_backend(
    stack: Path, docker: Path
) -> None:
    runner = FakeRunner()
    runner.info.update({"OperatingSystem": "Docker Desktop", "KernelVersion": "unknown"})
    subject = LocalStackController(
        stack,
        docker_path=docker,
        runner=runner,
        os_name="windows",
        environment={},
    )
    with (
        patch("platform.machine", return_value="AMD64"),
        patch("platform.win32_edition", return_value=None),
        pytest.raises(LocalStackError, match="Pro, Enterprise, or Education"),
    ):
        subject.preflight()
    with (
        patch("platform.machine", return_value="AMD64"),
        patch("platform.win32_edition", return_value="Home"),
        pytest.raises(LocalStackError, match="Pro, Enterprise, or Education"),
    ):
        subject.preflight()
    with (
        patch("platform.machine", return_value="AMD64"),
        patch("platform.win32_edition", return_value="Enterprise"),
        pytest.raises(LocalStackError, match="could not verify"),
    ):
        subject.preflight()


def test_windows_rejects_per_user_docker_install(stack: Path, tmp_path: Path) -> None:
    profile = tmp_path / "user"
    docker = profile / "AppData" / "Local" / "Docker" / "docker.exe"
    docker.parent.mkdir(parents=True)
    docker.write_bytes(b"mock")
    runner = FakeRunner()
    runner.info.update(
        {"OperatingSystem": "Docker Desktop", "KernelVersion": "6.10-linuxkit"}
    )
    subject = LocalStackController(
        stack,
        docker_path=docker,
        runner=runner,
        os_name="windows",
        environment={"USERPROFILE": str(profile), "LOCALAPPDATA": str(profile / "AppData/Local")},
    )
    with (
        patch("platform.machine", return_value="AMD64"),
        patch("platform.win32_edition", return_value="Education"),
        pytest.raises(LocalStackError, match="per-user Docker Desktop"),
    ):
        subject.preflight()


def test_readiness_timeout_lists_every_failed_probe(controller) -> None:
    subject, _runner = controller
    failed = [
        ProbeResult("otlp-grpc", "127.0.0.1:4317", False),
        ProbeResult("otlp-http", "127.0.0.1:4318", False),
        ProbeResult("grafana", "http://127.0.0.1:3000/api/health", False),
        ProbeResult("prometheus", "http://127.0.0.1:9090/-/ready", False),
        ProbeResult("tempo", "http://127.0.0.1:3200/ready", False),
        ProbeResult("loki", "http://127.0.0.1:3100/ready", False),
    ]
    with (
        patch.object(subject, "probe_all", return_value=failed),
        patch("defenseclaw.observability.local_stack.time.sleep"),
        patch(
            "defenseclaw.observability.local_stack.time.monotonic",
            side_effect=[0.0, 0.0, 2.0, 2.0],
        ),
        pytest.raises(LocalStackError, match="otlp-grpc=fail.*loki=fail"),
    ):
        subject.wait_for_readiness(1)


@pytest.mark.parametrize("returncode", [1, 125])
def test_compose_failure_is_truthful_nonzero(controller, returncode: int) -> None:
    subject, runner = controller
    runner.add(
        (subject.docker_path, "compose", "--project-directory"),
        returncode=returncode,
        stderr="compose failed Ω",
    )
    with pytest.raises(LocalStackError, match=f"exit code {returncode}"):
        subject.up(wait=False)


def test_foreign_container_is_never_deleted(controller) -> None:
    subject, runner = controller
    foreign = "defenseclaw-grafana"
    runner.add(
        (subject.docker_path, "ps", "--all", "--format"),
        stdout=foreign + "\n",
    )
    runner.add(
        (subject.docker_path, "inspect"),
        stdout=json.dumps(
            {
                "com.docker.compose.project": "foreign-project",
                "com.docker.compose.service": "grafana",
            }
        ),
    )
    with pytest.raises(LocalStackError, match="will not delete"):
        subject.up(wait=False)
    flattened = [item.lower() for call in runner.calls for item in call[0]]
    assert "rm" not in flattened
    assert "--force" not in flattened
    assert foreign in SERVICE_CONTAINERS


def test_owned_container_requires_exact_project_service_and_paths(controller) -> None:
    subject, runner = controller
    labels_by_name = {
        name: {
            "com.docker.compose.project": COMPOSE_PROJECT,
            "com.docker.compose.service": service,
            "com.docker.compose.project.config_files": str(subject.compose_file),
            "com.docker.compose.project.working_dir": str(subject.stack_dir),
        }
        for name, service in SERVICE_CONTAINERS.items()
    }

    class OwnedRunner(FakeRunner):
        def run(self, argv, **kwargs):
            command = tuple(argv)
            if command[1:] == ("ps", "--all", "--format", "{{.Names}}"):
                return CommandResult(
                    command, 0, "\n".join(SERVICE_CONTAINERS) + "\n", ""
                )
            if len(command) > 1 and command[1] == "inspect":
                return CommandResult(command, 0, json.dumps(labels_by_name[command[-1]]), "")
            return super().run(argv, **kwargs)

    owned = OwnedRunner()
    subject.runner = owned
    subject.verify_container_ownership()

    labels_by_name["defenseclaw-grafana"][
        "com.docker.compose.project.working_dir"
    ] = str(subject.stack_dir.parent)
    with pytest.raises(LocalStackError, match="collision"):
        subject.verify_container_ownership()


def test_reset_rejects_foreign_volume_and_requires_confirmation(controller) -> None:
    subject, runner = controller
    with pytest.raises(LocalStackError, match="explicit confirmation"):
        subject.reset(confirmed=False)

    runner.add(
        (subject.docker_path, "volume", "ls"),
        stdout="\n".join(
            f"{COMPOSE_PROJECT}_{volume}"
            for volume in ("prometheus-data", "loki-data", "tempo-data", "grafana-data")
        ),
    )
    runner.add(
        (subject.docker_path, "volume", "inspect"),
        stdout=json.dumps(
            {
                "com.docker.compose.project": "foreign",
                "com.docker.compose.volume": "grafana-data",
            }
        ),
    )
    with pytest.raises(LocalStackError, match="reset refused"):
        subject.reset(confirmed=True)
    assert not any(call[0][-2:] == ("down", "--volumes") for call in runner.calls)


def test_ownership_inspection_errors_fail_closed(controller) -> None:
    subject, runner = controller
    runner.add(
        (subject.docker_path, "ps", "--all", "--format"),
        stdout="defenseclaw-grafana\n",
    )
    runner.add(
        (subject.docker_path, "inspect"), returncode=2, stderr="permission denied"
    )
    with pytest.raises(LocalStackError, match="ownership is unproven"):
        subject.down()

    runner = FakeRunner()
    subject.runner = runner
    physical_name = f"{COMPOSE_PROJECT}_grafana-data"
    runner.add(
        (subject.docker_path, "volume", "ls"), stdout=physical_name + "\n"
    )
    runner.add(
        (subject.docker_path, "volume", "inspect"),
        returncode=2,
        stderr="permission denied",
    )
    with pytest.raises(LocalStackError, match="reset refused"):
        subject.reset(confirmed=True)


def test_unknown_log_service_cannot_become_an_option(controller) -> None:
    subject, _runner = controller
    with pytest.raises(LocalStackError, match="unknown service"):
        subject.logs(service="--all")


def test_command_runner_decodes_utf8_replacement_and_bounds_output() -> None:
    runner = CommandRunner(output_limit=32)
    code = "import sys;sys.stdout.buffer.write(('Ω'*40).encode()+b'\\xff')"
    result = runner.run([sys.executable, "-c", code], timeout=5)
    assert result.returncode == 0
    assert "[output truncated" in result.stdout
    assert len(result.stdout.encode("utf-8")) < 100

    invalid = runner.run(
        [sys.executable, "-c", "import sys;sys.stdout.buffer.write(b'\\xff')"],
        timeout=5,
    )
    assert "�" in invalid.stdout


def test_command_runner_timeout_reaps_child() -> None:
    runner = CommandRunner()
    with pytest.raises(LocalStackError, match="timed out"):
        runner.run(
            [sys.executable, "-c", "import time;time.sleep(30)"], timeout=0.05
        )


def test_command_runner_keyboard_interrupt_cancels_process_group() -> None:
    process = MagicMock(pid=4242)
    process.poll.return_value = None
    process.wait.side_effect = [KeyboardInterrupt(), 0]
    with (
        patch("defenseclaw.observability.local_stack.os.name", "posix"),
        patch(
            "defenseclaw.observability.local_stack.subprocess.Popen",
            return_value=process,
        ),
        patch(
            "defenseclaw.observability.local_stack.os.killpg", create=True
        ) as killpg,
        pytest.raises(KeyboardInterrupt),
    ):
        CommandRunner().run(["docker", "compose", "ps"], timeout=5, capture=False)
    killpg.assert_called_once_with(4242, signal.SIGTERM)


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object process-tree semantics")
def test_command_runner_timeout_reaps_windows_grandchild(tmp_path: Path) -> None:
    import ctypes

    pid_file = tmp_path / "grandchild.pid"
    child_code = "import time;time.sleep(30)"
    parent_code = (
        "import pathlib,subprocess,sys,time;"
        "p=subprocess.Popen([sys.executable,'-c',sys.argv[2]]);"
        "pathlib.Path(sys.argv[1]).write_text(str(p.pid),encoding='utf-8');"
        "time.sleep(30)"
    )
    real_popen = subprocess.Popen
    readiness_timeout = 10.0

    def popen_with_grandchild_handshake(*args, **kwargs):
        process = real_popen(*args, **kwargs)
        real_wait = process.wait
        gate_timeout = True

        def wait(*, timeout=None):
            nonlocal gate_timeout
            if gate_timeout and timeout is not None:
                gate_timeout = False
                deadline = time.monotonic() + readiness_timeout
                while time.monotonic() < deadline:
                    try:
                        if int(pid_file.read_text(encoding="utf-8")) > 0:
                            break
                    except (FileNotFoundError, OSError, ValueError):
                        pass
                    if process.poll() is not None:
                        pytest.fail(
                            "Windows timeout fixture parent exited before reporting "
                            "the grandchild PID"
                        )
                    time.sleep(0.01)
                else:
                    pytest.fail(
                        "Windows timeout fixture did not report a grandchild PID "
                        f"within {readiness_timeout:g}s"
                    )

                # The real parent is still sleeping. A zero-duration wait now
                # deterministically enters CommandRunner's timeout cleanup only
                # after the grandchild has joined the inherited Job Object.
                return real_wait(timeout=0)
            return real_wait(timeout=timeout)

        process.wait = wait
        return process

    with (
        patch(
            "defenseclaw.observability.local_stack.subprocess.Popen",
            side_effect=popen_with_grandchild_handshake,
        ),
        pytest.raises(LocalStackError, match="timed out"),
    ):
        CommandRunner().run(
            [sys.executable, "-c", parent_code, str(pid_file), child_code],
            timeout=0.5,
        )
    grandchild_pid = int(pid_file.read_text(encoding="utf-8"))
    process_query_limited_information = 0x1000
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.restype = ctypes.c_void_p
    handle = kernel32.OpenProcess(
        process_query_limited_information, False, grandchild_pid
    )
    if handle:
        exit_code = ctypes.c_ulong()
        assert kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code))
        kernel32.CloseHandle(handle)
        assert exit_code.value != 259, "the timed-out grandchild escaped the Windows Job Object"


def test_native_path_has_no_shell_or_forbidden_executable_calls(
    stack: Path, docker: Path
) -> None:
    source_path = Path(sys.modules[LocalStackController.__module__].__file__ or "")
    cli_path = source_path.parents[1] / "commands" / "cmd_setup_local_observability.py"
    source = source_path.read_text(encoding="utf-8")
    cli_source = cli_path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    forbidden_calls: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr == "system":
                forbidden_calls.append("os.system")
            for keyword in node.keywords:
                if keyword.arg == "shell" and isinstance(keyword.value, ast.Constant):
                    if keyword.value.value is True:
                        forbidden_calls.append("shell=True")
    assert forbidden_calls == []
    assert "local_observability_bridge_bin" not in source + cli_source
    assert "openclaw-observability-bridge" not in source + cli_source
    assert "subprocess.run" not in source + cli_source
    forbidden_executables = {"bash", "sh", "wsl", "jq", "tail", "nc", "curl", "wget"}
    runner = FakeRunner()
    runner.info.update(
        {"OperatingSystem": "Docker Desktop", "KernelVersion": "6.10-linuxkit"}
    )
    with (
        patch("defenseclaw.observability.local_stack.platform.machine", return_value="AMD64"),
        patch("defenseclaw.observability.local_stack.platform.win32_edition", return_value="Professional"),
    ):
        LocalStackController(
            stack,
            docker_path=docker,
            runner=runner,
            os_name="windows",
            environment={},
        ).up(wait=False)
    assert runner.calls
    assert not any(
        Path(call[0][0]).name.lower() in forbidden_executables for call in runner.calls
    )
    assert all(Path(call[0][0]).suffix.lower() == ".exe" for call in runner.calls)


@pytest.mark.skipif(os.name != "nt", reason="native Windows mock executable")
def test_windows_native_mock_docker_executable_uses_disposable_profile(
    stack: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = tmp_path / "Disposable User Ω"
    appdata = profile / "AppData" / "Roaming"
    settings = appdata / "Docker" / "settings-store.json"
    settings.parent.mkdir(parents=True)
    settings.write_text('{"wslEngineEnabled": false}\r\n', encoding="utf-8")
    mock_bin = tmp_path / "mock docker"
    mock_bin.mkdir()
    docker_exe = mock_bin / "docker.exe"
    go_source = mock_bin / "fake_docker.go"
    log = tmp_path / "docker-argv.log"
    roots = {
        "USERPROFILE": profile,
        "HOME": profile,
        "APPDATA": appdata,
        "LOCALAPPDATA": profile / "AppData" / "Local",
        "TEMP": profile / "Temp",
        "DEFENSECLAW_HOME": profile / ".defenseclaw",
        "GOCACHE": profile / "GoCache",
        "GOPATH": profile / "GoPath",
    }
    for name, value in roots.items():
        value.mkdir(parents=True, exist_ok=True)
        monkeypatch.setenv(name, str(value))
    monkeypatch.setenv("FAKE_DOCKER_LOG", str(log))
    go_source.write_text(
        """package main
import (
    "fmt"
    "os"
    "strings"
)
func main() {
    log, _ := os.OpenFile(os.Getenv("FAKE_DOCKER_LOG"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
    if log != nil { fmt.Fprintln(log, strings.Join(os.Args[1:], " ")); log.Close() }
    if len(os.Args) > 2 && os.Args[1] == "compose" && os.Args[2] == "version" {
        fmt.Println("Docker Compose version v2.30.0")
        return
    }
    if len(os.Args) > 1 && os.Args[1] == "info" {
        fmt.Println(`{"OSType":"linux","OperatingSystem":"Docker Desktop","KernelVersion":"6.10-linuxkit"}`)
        return
    }
    if len(os.Args) > 1 && os.Args[1] == "inspect" { os.Exit(1) }
    if len(os.Args) > 2 && os.Args[1] == "volume" && os.Args[2] == "inspect" { os.Exit(1) }
}
""",
        encoding="utf-8",
    )
    go = shutil.which("go")
    assert go, "Go is required to build the native mock Docker executable"
    built = subprocess.run(
        [go, "build", "-trimpath", "-o", str(docker_exe), str(go_source)],
        cwd=mock_bin,
        env=os.environ.copy(),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=180,
        check=False,
    )
    assert built.returncode == 0, built.stdout + built.stderr
    monkeypatch.setenv("PATH", str(mock_bin) + os.pathsep + os.environ.get("PATH", ""))

    subject = LocalStackController(stack, os_name="windows")
    with (
        patch("platform.machine", return_value="AMD64"),
        patch("platform.win32_edition", return_value="Professional"),
    ):
        first = subject.up(wait=False)
        subject.down()
        subject.reset(confirmed=True)
        second = subject.up(wait=False)

    assert first.contract == second.contract == CONTRACT
    recorded = log.read_text(encoding="utf-8", errors="replace")
    assert "--project-name defenseclaw-observability" in recorded
    assert "up --detach" in recorded
    assert "down --volumes" in recorded
    assert Path.home() == profile
    assert str(profile).startswith(str(tmp_path))
