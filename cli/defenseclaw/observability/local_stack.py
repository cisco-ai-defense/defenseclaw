# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Cross-platform controller for the bundled local observability stack.

All lifecycle operations flow through this module on Windows, macOS, and
Linux.  Docker is always invoked with an argument vector and an explicit
Compose project identity; no command interpreter or optional Unix utility is
part of the runtime path.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from defenseclaw.paths import bundled_local_observability_dir
from defenseclaw.platform_support import host_os

COMPOSE_PROJECT = "defenseclaw-observability"
COMPOSE_FILE_NAME = "docker-compose.yml"
MAX_CAPTURE_BYTES = 256 * 1024

CONTRACT: dict[str, str] = {
    "otlp_endpoint": "127.0.0.1:4317",
    "otlp_protocol": "grpc",
    "otlp_http_endpoint": "127.0.0.1:4318",
    "grafana_url": "http://localhost:3000",
    "prometheus_url": "http://localhost:9090",
    "tempo_url": "http://localhost:3200",
    "loki_url": "http://localhost:3100",
    "collector_metrics_url": "http://localhost:8888/metrics",
}

SERVICE_CONTAINERS: dict[str, str] = {
    "defenseclaw-otel-collector": "otel-collector",
    "defenseclaw-prometheus": "prometheus",
    "defenseclaw-loki": "loki",
    "defenseclaw-tempo": "tempo",
    "defenseclaw-grafana": "grafana",
}
SERVICES = frozenset(SERVICE_CONTAINERS.values())
PROJECT_VOLUMES = frozenset(
    {"prometheus-data", "loki-data", "tempo-data", "grafana-data"}
)

HTTP_PROBES: tuple[tuple[str, str], ...] = (
    ("grafana", "http://127.0.0.1:3000/api/health"),
    ("prometheus", "http://127.0.0.1:9090/-/ready"),
    ("tempo", "http://127.0.0.1:3200/ready"),
    ("loki", "http://127.0.0.1:3100/ready"),
)
TCP_PROBES: tuple[tuple[str, str, int], ...] = (
    ("otlp-grpc", "127.0.0.1", 4317),
    ("otlp-http", "127.0.0.1", 4318),
)


class LocalStackError(RuntimeError):
    """An actionable local-stack failure."""


@dataclass(frozen=True)
class CommandResult:
    """Bounded, explicitly decoded child-process output."""

    argv: tuple[str, ...]
    returncode: int
    stdout: str = ""
    stderr: str = ""


@dataclass(frozen=True)
class UpResult:
    """Successful Compose start plus whether readiness was verified."""

    contract: dict[str, str]
    readiness_verified: bool


@dataclass(frozen=True)
class ProbeResult:
    """One local readiness observation."""

    label: str
    target: str
    ready: bool


class _BoundedCapture:
    """Continuously drain a pipe while retaining no more than ``limit`` bytes."""

    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.data = bytearray()
        self.truncated = False

    def drain(self, stream) -> None:
        try:
            while True:
                chunk = stream.read(8192)
                if not chunk:
                    return
                remaining = self.limit - len(self.data)
                if remaining > 0:
                    self.data.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    self.truncated = True
        finally:
            stream.close()

    def text(self) -> str:
        value = bytes(self.data).decode("utf-8", errors="replace")
        if self.truncated:
            value += "\n[output truncated by DefenseClaw]"
        return value


class CommandRunner:
    """Run one native executable with bounded capture and safe cancellation."""

    def __init__(self, *, output_limit: int = MAX_CAPTURE_BYTES) -> None:
        self.output_limit = output_limit

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout: float,
        capture: bool = True,
        env: Mapping[str, str] | None = None,
    ) -> CommandResult:
        if not argv or not all(isinstance(item, str) and item for item in argv):
            raise ValueError("command argv must contain non-empty strings")
        command = tuple(argv)
        creationflags = 0
        start_new_session = os.name != "nt"
        if os.name == "nt":
            creationflags = (
                getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
                | getattr(subprocess, "CREATE_SUSPENDED", 0x00000004)
            )

        stdout_target = subprocess.PIPE if capture else None
        stderr_target = subprocess.PIPE if capture else None
        stdout_capture = _BoundedCapture(self.output_limit) if capture else None
        stderr_capture = _BoundedCapture(self.output_limit) if capture else None
        drain_threads: list[threading.Thread] = []
        windows_job = None
        try:
            process = subprocess.Popen(
                list(command),
                stdin=subprocess.DEVNULL,
                stdout=stdout_target,
                stderr=stderr_target,
                env=dict(env) if env is not None else None,
                close_fds=True,
                creationflags=creationflags,
                start_new_session=start_new_session,
            )
            if os.name == "nt":
                from defenseclaw.tui.windows_process import WindowsJob

                try:
                    windows_job = WindowsJob(process.pid)
                except OSError as exc:
                    process.kill()
                    process.wait(timeout=2)
                    raise LocalStackError(
                        f"could not contain Windows process tree for {command[0]}: {exc}"
                    ) from exc
            if capture:
                assert process.stdout is not None and process.stderr is not None
                assert stdout_capture is not None and stderr_capture is not None
                drain_threads = [
                    threading.Thread(
                        target=stdout_capture.drain,
                        args=(process.stdout,),
                        daemon=True,
                    ),
                    threading.Thread(
                        target=stderr_capture.drain,
                        args=(process.stderr,),
                        daemon=True,
                    ),
                ]
                for thread in drain_threads:
                    thread.start()
            try:
                returncode = process.wait(timeout=timeout)
            except (subprocess.TimeoutExpired, KeyboardInterrupt):
                self._terminate(process, windows_job=windows_job)
                if isinstance(sys.exc_info()[1], KeyboardInterrupt):
                    raise
                raise LocalStackError(
                    f"command timed out after {timeout:g}s: {command[0]}"
                ) from None

            for thread in drain_threads:
                thread.join(timeout=2)
            stdout = stdout_capture.text() if stdout_capture else ""
            stderr = stderr_capture.text() if stderr_capture else ""
            return CommandResult(command, returncode, stdout, stderr)
        except OSError as exc:
            raise LocalStackError(f"could not execute {command[0]}: {exc}") from exc
        finally:
            if windows_job is not None:
                windows_job.close()
            for thread in drain_threads:
                thread.join(timeout=2)

    @staticmethod
    def _terminate(process: subprocess.Popen[bytes], *, windows_job=None) -> None:
        if process.poll() is not None:
            return
        if os.name == "nt":
            if windows_job is not None:
                # The job is configured KILL_ON_JOB_CLOSE, so this terminates
                # the Docker CLI, Compose plugin, and any descendants together.
                windows_job.close()
                try:
                    process.wait(timeout=2)
                    return
                except subprocess.TimeoutExpired:
                    pass
        else:
            try:
                os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=2)
                return
            except (OSError, subprocess.TimeoutExpired):
                pass
        try:
            process.terminate()
            process.wait(timeout=2)
            return
        except (OSError, subprocess.TimeoutExpired):
            pass
        if os.name != "nt":
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except OSError:
                pass
        try:
            process.kill()
            process.wait(timeout=2)
        except (OSError, subprocess.TimeoutExpired):
            pass


def resolve_stack_dir(data_dir: str | os.PathLike[str] | None = None) -> Path:
    """Resolve a seeded stack first, then the maintained packaged bundle."""
    candidates: list[Path] = []
    if data_dir is not None:
        candidates.append(Path(data_dir) / "observability-stack")
    candidates.append(bundled_local_observability_dir())
    for candidate in candidates:
        if (candidate / COMPOSE_FILE_NAME).is_file():
            return _canonical_stack_dir(candidate)
    rendered = ", ".join(str(path) for path in candidates)
    raise LocalStackError(
        "local observability bundle not found; run 'defenseclaw init' or reinstall "
        f"DefenseClaw (checked: {rendered})"
    )


def _is_reparse_or_symlink(path: Path) -> bool:
    try:
        stat_result = path.lstat()
    except OSError:
        return False
    if path.is_symlink():
        return True
    reparse_flag = getattr(stat_result, "st_file_attributes", 0)
    return bool(reparse_flag & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def _canonical_stack_dir(stack_dir: str | os.PathLike[str]) -> Path:
    raw = Path(stack_dir).absolute()
    if _is_reparse_or_symlink(raw):
        raise LocalStackError(f"refusing reparse/symlink stack directory: {raw}")
    try:
        root = raw.resolve(strict=True)
        compose = (root / COMPOSE_FILE_NAME).resolve(strict=True)
    except OSError as exc:
        raise LocalStackError(f"invalid local observability bundle: {exc}") from exc
    if compose.parent != root or _is_reparse_or_symlink(root / COMPOSE_FILE_NAME):
        raise LocalStackError("Compose file escapes the local observability bundle")
    return root


def _parse_json_object(raw: str, *, description: str) -> dict[str, object]:
    try:
        value = json.loads(raw)
    except (TypeError, ValueError) as exc:
        raise LocalStackError(f"Docker returned invalid {description} JSON") from exc
    if not isinstance(value, dict):
        raise LocalStackError(f"Docker returned invalid {description} JSON")
    return value


def resolve_native_docker_executable(
    docker_path: str | os.PathLike[str] | None = None,
    *,
    os_name: str | None = None,
) -> str:
    """Resolve Docker and reject shell-backed shims on native Windows.

    The returned value is always an absolute path.  Windows certification is
    intentionally stricter than ``PATHEXT`` resolution: only a real ``.exe``
    is accepted, so ``docker.cmd``, ``docker.bat``, and extensionless POSIX
    launchers can never become part of a managed lifecycle.
    """

    resolved_os = host_os() if os_name is None else os_name.lower()
    discovered = os.fspath(docker_path) if docker_path is not None else shutil.which("docker")
    executable = str(Path(discovered).resolve()) if discovered else ""
    if (
        executable
        and (resolved_os.startswith("win") or resolved_os == "windows")
        and Path(executable).name.lower() != "docker.exe"
    ):
        raise LocalStackError(
            "The certified native Windows path requires Docker Desktop's native "
            "docker.exe; command-script shims are not supported."
        )
    return executable


def _docker_desktop_wsl_setting(environment: Mapping[str, str]) -> bool | None:
    appdata = environment.get("APPDATA")
    if not appdata:
        return None
    for name in ("settings-store.json", "settings.json"):
        path = Path(appdata) / "Docker" / name
        try:
            raw = path.read_text(encoding="utf-8-sig")
        except OSError:
            continue
        try:
            settings = json.loads(raw)
        except ValueError:
            return None
        if isinstance(settings, dict):
            value = settings.get("wslEngineEnabled")
            if isinstance(value, bool):
                return value
    return None


def _validate_windows_docker_certification(
    docker_path: str,
    info: Mapping[str, object],
    environment: Mapping[str, str],
    *,
    feature_name: str,
) -> None:
    machine = platform.machine().lower()
    if machine not in {"amd64", "x86_64"}:
        raise LocalStackError(f"Native Windows {feature_name} is certified only for x64 systems.")
    edition = str(platform.win32_edition() or "").lower()
    if not any(token in edition for token in ("professional", "enterprise", "education")):
        raise LocalStackError(
            f"The no-WSL {feature_name} path requires a supported Windows "
            "Pro, Enterprise, or Education edition with Hyper-V."
        )
    operating_system = str(info.get("OperatingSystem", ""))
    if "docker desktop" not in operating_system.lower():
        raise LocalStackError(
            "The certified Windows path requires Docker Desktop with Linux containers and the Hyper-V backend."
        )
    docker_executable = Path(docker_path)
    for key in ("LOCALAPPDATA", "USERPROFILE"):
        root_value = environment.get(key)
        if not root_value:
            continue
        try:
            docker_executable.relative_to(Path(root_value))
        except ValueError:
            continue
        raise LocalStackError(
            "This appears to be a per-user Docker Desktop installation. "
            "Per-user and WSL-only installations are outside DefenseClaw's "
            "certified Hyper-V/no-WSL configuration."
        )
    kernel = str(info.get("KernelVersion", "")).lower()
    if "wsl" in kernel or "microsoft-standard" in kernel:
        raise LocalStackError(
            "Docker Desktop is using the WSL 2 backend. This no-WSL certification "
            "requires the Hyper-V backend on a supported Windows edition."
        )
    backend_setting = _docker_desktop_wsl_setting(environment)
    if backend_setting is True:
        raise LocalStackError(
            "Docker Desktop's WSL engine is enabled. Disable it and use the Hyper-V "
            "backend for the certified no-WSL path."
        )
    if backend_setting is None and "linuxkit" not in kernel:
        raise LocalStackError(
            "DefenseClaw could not verify Docker Desktop's Hyper-V backend. "
            "Per-user or WSL-only Docker Desktop installations are outside the "
            "certified no-WSL configuration."
        )


def validate_native_docker_preflight(
    docker_path: str,
    runner: CommandRunner,
    environment: Mapping[str, str],
    *,
    os_name: str,
    feature_name: str = "local observability",
) -> dict[str, object]:
    """Validate Compose v2, the daemon, Linux containers, and Windows policy."""

    if not docker_path:
        raise LocalStackError("Docker CLI was not found on PATH. Install Docker Desktop and retry.")
    compose = runner.run([docker_path, "compose", "version"], timeout=10, env=environment)
    if compose.returncode != 0:
        raise LocalStackError("Docker Compose v2 is unavailable. Install/enable the 'docker compose' plugin.")
    info_result = runner.run(
        [docker_path, "info", "--format", "{{json .}}"],
        timeout=15,
        env=environment,
    )
    if info_result.returncode != 0:
        detail = (info_result.stderr or info_result.stdout).strip()
        suffix = f" ({detail.splitlines()[0]})" if detail else ""
        raise LocalStackError("Docker daemon is not reachable. Start Docker Desktop and retry" + suffix)
    info = _parse_json_object(info_result.stdout.strip(), description="info")
    if str(info.get("OSType", "")).lower() != "linux":
        raise LocalStackError("Docker is using Windows containers. Switch Docker Desktop to Linux containers.")
    if os_name.startswith("win") or os_name == "windows":
        _validate_windows_docker_certification(
            docker_path,
            info,
            environment,
            feature_name=feature_name,
        )
    return info


class LocalStackController:
    """Secure Docker Compose lifecycle for the DefenseClaw stack."""

    def __init__(
        self,
        stack_dir: str | os.PathLike[str],
        *,
        docker_path: str | os.PathLike[str] | None = None,
        runner: CommandRunner | None = None,
        os_name: str | None = None,
        environment: Mapping[str, str] | None = None,
    ) -> None:
        self.stack_dir = _canonical_stack_dir(stack_dir)
        self.compose_file = (self.stack_dir / COMPOSE_FILE_NAME).resolve(strict=True)
        self.os_name = host_os() if os_name is None else os_name.lower()
        self.docker_path = resolve_native_docker_executable(docker_path, os_name=self.os_name)
        self.runner = runner or CommandRunner()
        self.environment = dict(os.environ if environment is None else environment)
        # The managed lifecycle always uses the Compose file's loopback default.
        # Intentional HOST_BIND overrides are confined to the documented manual
        # `docker compose` path, where the operator owns the exposure decision.
        self.environment.pop("HOST_BIND", None)

    def compose_argv(self, *args: str) -> list[str]:
        if not self.docker_path:
            raise LocalStackError(
                "Docker CLI was not found on PATH. Install Docker Desktop and retry."
            )
        return [
            self.docker_path,
            "compose",
            "--project-directory",
            str(self.stack_dir),
            "--file",
            str(self.compose_file),
            "--project-name",
            COMPOSE_PROJECT,
            *args,
        ]

    def preflight(self) -> dict[str, object]:
        """Validate Docker, Compose, daemon reachability, and container mode."""
        return validate_native_docker_preflight(
            self.docker_path,
            self.runner,
            self.environment,
            os_name=self.os_name,
        )

    def _run_compose(self, *args: str, timeout: float, capture: bool = True) -> CommandResult:
        return self.runner.run(
            self.compose_argv(*args),
            timeout=timeout,
            capture=capture,
            env=self.environment,
        )

    @staticmethod
    def _checked(result: CommandResult, description: str) -> CommandResult:
        if result.returncode == 0:
            return result
        detail = (result.stderr or result.stdout).strip()
        if detail:
            detail = ": " + detail.splitlines()[0]
        raise LocalStackError(
            f"{description} failed with exit code {result.returncode}{detail}"
        )

    def verify_container_ownership(self) -> None:
        """Fail on same-name containers whose exact Compose identity is unproven."""
        project_result = self.runner.run(
            [
                self.docker_path,
                "ps",
                "--all",
                "--filter",
                f"label=com.docker.compose.project={COMPOSE_PROJECT}",
                "--format",
                "{{.Names}}",
            ],
            timeout=8,
            env=self.environment,
        )
        if project_result.returncode != 0:
            raise LocalStackError("could not verify Compose project container ownership")
        unexpected = {
            line.strip()
            for line in project_result.stdout.splitlines()
            if line.strip() and line.strip() not in SERVICE_CONTAINERS
        }
        if unexpected:
            raise LocalStackError(
                "Compose project identity collision: unexpected container(s) "
                f"{', '.join(sorted(unexpected))} use project {COMPOSE_PROJECT}. "
                "DefenseClaw will not modify this project until the collision is resolved."
            )
        all_names_result = self.runner.run(
            [self.docker_path, "ps", "--all", "--format", "{{.Names}}"],
            timeout=8,
            env=self.environment,
        )
        if all_names_result.returncode != 0:
            raise LocalStackError("could not enumerate containers for ownership verification")
        existing_names = {
            line.strip() for line in all_names_result.stdout.splitlines() if line.strip()
        }
        for container, service in SERVICE_CONTAINERS.items():
            if container not in existing_names:
                continue
            result = self.runner.run(
                [
                    self.docker_path,
                    "inspect",
                    "--format",
                    "{{json .Config.Labels}}",
                    container,
                ],
                timeout=8,
                env=self.environment,
            )
            if result.returncode != 0:
                raise LocalStackError(
                    f"could not inspect existing container {container}; ownership is unproven"
                )
            labels = _parse_json_object(result.stdout.strip(), description="container labels")
            actual_project = labels.get("com.docker.compose.project")
            actual_service = labels.get("com.docker.compose.service")
            config_files = str(labels.get("com.docker.compose.project.config_files", ""))
            working_dir = str(labels.get("com.docker.compose.project.working_dir", ""))
            config_matches = any(
                self._paths_equal(item.strip(), self.compose_file)
                for item in config_files.split(",")
                if item.strip()
            )
            working_dir_matches = self._paths_equal(working_dir, self.stack_dir)
            if (
                actual_project != COMPOSE_PROJECT
                or actual_service != service
                or not config_matches
                or not working_dir_matches
            ):
                raise LocalStackError(
                    f"container name collision: {container} is not owned by the "
                    f"{COMPOSE_PROJECT}/{service} Compose service. DefenseClaw will not "
                    "delete it; rename or remove the foreign container and retry."
                )

    @staticmethod
    def _paths_equal(value: str, expected: Path) -> bool:
        if not value:
            return False
        actual = os.path.normcase(os.path.abspath(value))
        wanted = os.path.normcase(os.path.abspath(expected))
        return actual == wanted

    def verify_reset_ownership(self) -> None:
        """Prove every matching named volume belongs to this exact project."""
        self.verify_container_ownership()
        listed = self.runner.run(
            [self.docker_path, "volume", "ls", "--format", "{{.Name}}"],
            timeout=8,
            env=self.environment,
        )
        if listed.returncode != 0:
            raise LocalStackError("could not enumerate project volumes; reset refused")
        existing_volumes = {
            line.strip() for line in listed.stdout.splitlines() if line.strip()
        }
        for volume in PROJECT_VOLUMES:
            physical_name = f"{COMPOSE_PROJECT}_{volume}"
            if physical_name not in existing_volumes:
                continue
            result = self.runner.run(
                [
                    self.docker_path,
                    "volume",
                    "inspect",
                    "--format",
                    "{{json .Labels}}",
                    physical_name,
                ],
                timeout=8,
                env=self.environment,
            )
            if result.returncode != 0:
                raise LocalStackError(
                    f"could not inspect existing volume {physical_name}; reset refused"
                )
            labels = _parse_json_object(result.stdout.strip(), description="volume labels")
            if (
                labels.get("com.docker.compose.project") != COMPOSE_PROJECT
                or labels.get("com.docker.compose.volume") != volume
            ):
                raise LocalStackError(
                    f"volume ownership is unproven for {physical_name}; reset refused. "
                    "DefenseClaw deletes only volumes labelled for its Compose project."
                )

    def up(self, *, timeout: int = 180, wait: bool = True) -> UpResult:
        self.preflight()
        self.verify_container_ownership()
        self._checked(
            self._run_compose("up", "--detach", timeout=max(60, timeout)),
            "docker compose up",
        )
        if wait:
            self.wait_for_readiness(timeout)
        return UpResult(dict(CONTRACT), readiness_verified=wait)

    def is_running(self) -> bool:
        """Return whether this named Compose project has a running container."""
        self.preflight()
        result = self.runner.run(
            [
                self.docker_path,
                "ps",
                "--filter",
                f"label=com.docker.compose.project={COMPOSE_PROJECT}",
                "--filter",
                "status=running",
                "--format",
                "{{.ID}}",
            ],
            timeout=10,
            env=self.environment,
        )
        return result.returncode == 0 and bool(result.stdout.strip())

    def down(self) -> None:
        self.preflight()
        self.verify_container_ownership()
        self._checked(self._run_compose("down", timeout=120), "docker compose down")

    def reset(self, *, confirmed: bool) -> None:
        if not confirmed:
            raise LocalStackError("reset requires explicit confirmation")
        self.preflight()
        self.verify_reset_ownership()
        self._checked(
            self._run_compose("down", "--volumes", timeout=180),
            "docker compose reset",
        )

    def status(self) -> str:
        self.preflight()
        compose = self._checked(
            self._run_compose("ps", timeout=30), "docker compose ps"
        )
        lines = [compose.stdout.rstrip(), "", "Readiness:"]
        for probe in self.probe_all():
            state = "ready" if probe.ready else "fail"
            lines.append(f"  {probe.label:<10} {state:<7} {probe.target}")
        return "\n".join(lines).rstrip() + "\n"

    def logs(self, *, service: str | None = None, follow: bool = False) -> str:
        self.preflight()
        if service is not None and service not in SERVICES:
            raise LocalStackError(
                f"unknown service {service!r}; choose one of {', '.join(sorted(SERVICES))}"
            )
        args = ["logs", "--tail", "200"]
        if follow:
            args.append("--follow")
        if service:
            args.extend(["--", service])
        result = self._run_compose(*args, timeout=24 * 60 * 60, capture=not follow)
        self._checked(result, "docker compose logs")
        return result.stdout

    def wait_for_readiness(self, timeout: int) -> None:
        if timeout <= 0:
            raise LocalStackError("readiness timeout must be greater than zero")
        deadline = time.monotonic() + timeout
        latest: list[ProbeResult] = []
        while time.monotonic() < deadline:
            latest = self.probe_all(deadline=deadline)
            if all(probe.ready for probe in latest):
                return
            time.sleep(min(0.5, max(0.0, deadline - time.monotonic())))
        states = " ".join(
            f"{probe.label}={'ready' if probe.ready else 'fail'}" for probe in latest
        )
        raise LocalStackError(f"readiness timeout after {timeout}s: {states}")

    def probe_all(self, *, deadline: float | None = None) -> list[ProbeResult]:
        results: list[ProbeResult] = []
        for label, host, port in TCP_PROBES:
            timeout = self._remaining_probe_timeout(deadline, 0.75)
            ready = timeout > 0 and self._tcp_probe(host, port, timeout=timeout)
            results.append(ProbeResult(label, f"{host}:{port}", ready))
        for label, url in HTTP_PROBES:
            timeout = self._remaining_probe_timeout(deadline, 1.25)
            ready = timeout > 0 and self._http_probe(url, timeout=timeout)
            results.append(ProbeResult(label, url, ready))
        return results

    @staticmethod
    def _remaining_probe_timeout(deadline: float | None, maximum: float) -> float:
        if deadline is None:
            return maximum
        return min(maximum, max(0.0, deadline - time.monotonic()))

    @staticmethod
    def _tcp_probe(host: str, port: int, *, timeout: float = 0.75) -> bool:
        if host != "127.0.0.1":
            raise ValueError("local stack probes must use loopback")
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except OSError:
            return False

    @staticmethod
    def _http_probe(url: str, *, timeout: float = 1.25) -> bool:
        if not url.startswith("http://127.0.0.1:"):
            raise ValueError("local stack probes must use allowlisted loopback URLs")
        request = urllib.request.Request(url, method="GET")
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return 200 <= response.status < 400
        except (OSError, urllib.error.URLError):
            return False

    @staticmethod
    def contract() -> dict[str, str]:
        return dict(CONTRACT)

    @staticmethod
    def environment_contract() -> dict[str, str]:
        return {
            "DEFENSECLAW_TELEMETRY_ENABLED": "1",
            "OTEL_EXPORTER_OTLP_ENDPOINT": "http://127.0.0.1:4317",
            "OTEL_EXPORTER_OTLP_PROTOCOL": "grpc",
            "OTEL_SERVICE_NAME": "defenseclaw",
            "OTEL_RESOURCE_ATTRIBUTES": (
                "service.namespace=defenseclaw,deployment.environment=local-dev"
            ),
        }


def _text_urls() -> str:
    return "\n".join(
        (
            "Grafana:    http://localhost:3000",
            "Prometheus: http://localhost:9090",
            "Tempo API:  http://localhost:3200",
            "Loki API:   http://localhost:3100",
            "OTLP gRPC:  127.0.0.1:4317",
            "OTLP HTTP:  127.0.0.1:4318",
        )
    )


def main(argv: Sequence[str] | None = None) -> int:
    """Compatibility entry point used by the legacy POSIX wrapper."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action",
        nargs="?",
        default="up",
        choices=("up", "down", "reset", "status", "logs", "url", "env"),
    )
    parser.add_argument("--stack-dir", type=Path)
    parser.add_argument("--output", choices=("text", "json"), default="text")
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--no-wait", action="store_true")
    parser.add_argument("--service", choices=sorted(SERVICES))
    parser.add_argument("--follow", action="store_true")
    parser.add_argument("--yes", action="store_true")
    args = parser.parse_args(argv)
    try:
        controller = LocalStackController(args.stack_dir or resolve_stack_dir())
        if args.action == "up":
            result = controller.up(timeout=args.timeout, wait=not args.no_wait)
            print(json.dumps(result.contract) if args.output == "json" else _text_urls())
        elif args.action == "down":
            controller.down()
        elif args.action == "reset":
            controller.reset(confirmed=args.yes)
        elif args.action == "status":
            print(controller.status(), end="")
        elif args.action == "logs":
            print(controller.logs(service=args.service, follow=args.follow), end="")
        elif args.action == "url":
            print(json.dumps(controller.contract()) if args.output == "json" else _text_urls())
        else:
            env = controller.environment_contract()
            if args.output == "json":
                print(json.dumps(env))
            elif os.name == "nt":
                for key, value in env.items():
                    print(f"$env:{key} = {json.dumps(value)}")
            else:
                for key, value in env.items():
                    print(f"export {key}={json.dumps(value)}")
    except LocalStackError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "COMPOSE_PROJECT",
    "CONTRACT",
    "CommandResult",
    "CommandRunner",
    "LocalStackController",
    "LocalStackError",
    "ProbeResult",
    "UpResult",
    "resolve_native_docker_executable",
    "resolve_stack_dir",
    "validate_native_docker_preflight",
]
