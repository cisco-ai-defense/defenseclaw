# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""A fresh wheel owns the complete native Local Splunk runtime."""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import sys
import time
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest
from defenseclaw.observability.local_splunk import (
    RETIRED_SPLUNK_IMAGE,
    NativeLocalSplunkController,
    _credential_values,
)
from defenseclaw.observability.local_stack import CommandResult, LocalStackError

REPO_ROOT = Path(__file__).resolve().parents[2]
BUNDLE = REPO_ROOT / "bundles" / "splunk_local_bridge"


def test_ci_and_scripts_do_not_start_the_retired_splunk_image() -> None:
    paths = [*REPO_ROOT.glob(".github/workflows/*"), *(REPO_ROOT / "scripts").rglob("*")]
    offenders = [str(path.relative_to(REPO_ROOT)) for path in paths if path.is_file()
                 and RETIRED_SPLUNK_IMAGE in path.read_text(encoding="utf-8", errors="replace")]
    assert offenders == []
    template = (BUNDLE / "env" / ".env.example").read_text(encoding="utf-8")
    image = re.search(r"^SPLUNK_IMAGE=(.+)$", template, re.MULTILINE)
    assert image is not None
    workflow = (REPO_ROOT / ".github" / "workflows" / "e2e.yml").read_text(encoding="utf-8")
    exported = re.findall(r"^\s+export SPLUNK_IMAGE=(\S+)$", workflow, re.MULTILINE)
    assert len(exported) == 6
    assert set(exported) == {image.group(1)}


def test_unix_bridge_uses_only_bash_32_features() -> None:
    bridge = (BUNDLE / "bin" / "splunk-claw-bridge").read_text(encoding="utf-8")
    assert not re.search(r"\$\{[^}\n]*(?:,,|\^\^)[^}\n]*\}", bridge)
    assert not re.search(r"(?m)^\s*(?:declare\s+-A|mapfile|readarray)\b", bridge)


def test_local_splunk_preflight_runs_under_bash_32(tmp_path: Path) -> None:
    if sys.platform == "darwin":
        bash = "/bin/bash"
    elif os.name != "nt" and os.environ.get("BASH32_TEST_BINARY"):
        bash = os.environ["BASH32_TEST_BINARY"]
    else:
        pytest.skip("run on macOS /bin/bash or set BASH32_TEST_BINARY to Bash 3.2")
    version = subprocess.run(
        [bash, "-c", 'printf "%s.%s" "${BASH_VERSINFO[0]}" "${BASH_VERSINFO[1]}"'],
        capture_output=True, text=True, timeout=10, check=True,
    )
    assert version.stdout == "3.2"

    env_file = tmp_path / "private.env"
    env_file.write_text("SPLUNK_IMAGE=splunk/splunk:10.2.0\n", encoding="utf-8")
    docker_calls = tmp_path / "docker-calls"
    docker = tmp_path / "docker"
    docker.write_text(
        "#!/bin/sh\n"
        'printf "%s\\n" "$*" >> "$DOCKER_CALLS"\n'
        'case "$1 $2" in\n'
        '  "info --format") printf "ArM64\\n" ;;\n'
        '  *) exit 2 ;;\n'
        'esac\n',
        encoding="utf-8",
    )
    docker.chmod(0o755)
    bridge = os.environ.get("SPLUNK_BRIDGE_TEST_BINARY") or str(BUNDLE / "bin" / "splunk-claw-bridge")
    result = subprocess.run(
        [bash, bridge, "up", "--env-file", str(env_file)],
        env={**os.environ, "PATH": f"{tmp_path}{os.pathsep}{os.environ['PATH']}",
             "DOCKER_CALLS": str(docker_calls)},
        capture_output=True, text=True, timeout=30, check=False,
    )
    assert result.returncode != 0
    assert "Local Splunk needs a linux/amd64 Docker engine" in result.stderr, result.stderr
    assert "on arm64 hosts" in result.stderr
    assert docker_calls.read_text(encoding="utf-8").splitlines() == ["info --format {{.Architecture}}"]


def test_local_splunk_image_resolves_or_reports_registry_outage(tmp_path: Path, monkeypatch) -> None:
    stack = tmp_path / "stack"
    shutil.copytree(BUNDLE, stack)
    template = (stack / "env" / ".env.example").read_text(encoding="utf-8")
    image = re.search(r"^SPLUNK_IMAGE=(.+)$", template, re.MULTILINE)
    assert image is not None
    assert image.group(1) == "splunk/splunk:10.2.0"
    upgraded = _credential_values(
        {"SPLUNK_IMAGE": image.group(1)}, {"SPLUNK_IMAGE": RETIRED_SPLUNK_IMAGE},
        index="defenseclaw_local", source="defenseclaw", sourcetype="defenseclaw:json",
    )
    assert upgraded["SPLUNK_IMAGE"] == image.group(1)
    from defenseclaw.commands import cmd_setup

    monkeypatch.setattr(cmd_setup, "bundled_splunk_bridge_dir", lambda: BUNDLE)

    env_file = stack / "env" / ".env"
    env_file.write_text(template.replace(image.group(1), RETIRED_SPLUNK_IMAGE), encoding="utf-8")
    env_file.chmod(0o600)
    if os.name != "nt":
        cmd_setup._migrate_retired_splunk_image(str(env_file))
        assert f"SPLUNK_IMAGE={image.group(1)}" in env_file.read_text(encoding="utf-8")
    else:
        env_file.write_text(template, encoding="utf-8")

    if os.name != "nt":
        calls = tmp_path / "docker-calls"
        docker = tmp_path / "docker"
        docker.write_text(
            "#!/bin/sh\n"
            'printf "%s\\n" "$*" >> "$DOCKER_CALLS"\n'
            'case "$1 $2" in\n'
            '  "info --format") echo "x86_64"; exit 0 ;;\n'
            '  "image inspect") exit 1 ;;\n'
            '  "pull splunk/splunk:10.2.0") echo "daemon registry unreachable" >&2; exit 1 ;;\n'
            '  *) echo "unexpected Docker call" >&2; exit 1 ;;\n'
            'esac\n',
            encoding="utf-8",
        )
        docker.chmod(0o755)
        shell = subprocess.run(
            ["bash", str(stack / "bin" / "splunk-claw-bridge"), "up", "--env-file", str(env_file)],
            env={**os.environ, "PATH": f"{tmp_path}:{os.environ['PATH']}", "DOCKER_CALLS": str(calls)},
            capture_output=True, text=True, timeout=30, check=False,
        )
        assert shell.returncode != 0
        assert "registry" in shell.stderr.lower() and image.group(1) in shell.stderr
        recorded = calls.read_text(encoding="utf-8")
        assert "pull " + image.group(1) in recorded
        assert "manifest inspect" not in recorded
        assert "compose" not in recorded

    class OfflineDocker:
        def __init__(self) -> None:
            self.calls: list[tuple[str, ...]] = []

        def run(self, argv, *, timeout, capture=True, env=None):
            command = tuple(argv)
            self.calls.append(command)
            if command[1:3] == ("info", "--format"):
                return CommandResult(command, 0, stdout="x86_64")
            if command[1:3] == ("image", "inspect"):
                return CommandResult(command, 1)
            if command[1] == "pull":
                return CommandResult(command, 1, stderr="daemon registry unreachable")
            if command[1] == "ps":
                return CommandResult(command, 0, stdout="")
            raise AssertionError(f"unexpected Docker call: {command[1]}")

    native_docker = tmp_path / "docker.exe"
    native_docker.write_bytes(b"mock")
    offline = OfflineDocker()
    controller = NativeLocalSplunkController(stack, docker_path=native_docker, runner=offline, os_name="windows")
    with pytest.raises(LocalStackError, match=r"registry.*splunk/splunk:10\.2\.0"):
        controller.up()
    assert any(command[1] == "pull" for command in offline.calls)
    assert all(command[1:3] != ("manifest", "inspect") for command in offline.calls)


@pytest.mark.skipif(os.name == "nt", reason="the Unix bridge runs under Bash")
@pytest.mark.parametrize(
    ("refresh_bundle", "running"),
    [(True, True), (True, False), (False, True), (False, False)],
)
def test_offline_upgrade_keeps_the_stack_and_old_image_contract(
    tmp_path: Path, refresh_bundle: bool, running: bool,
) -> None:
    from defenseclaw.bundle_refresh import RefreshResult
    from defenseclaw.commands import cmd_setup

    data_dir = tmp_path / "data"
    bridge_dir = data_dir / "splunk-bridge"
    shutil.copytree(BUNDLE, bridge_dir)
    env_file = bridge_dir / "env" / ".env"
    original = (bridge_dir / "env" / ".env.example").read_text(encoding="utf-8")
    old_contract = original.replace("SPLUNK_IMAGE=splunk/splunk:10.2.0", f"SPLUNK_IMAGE={RETIRED_SPLUNK_IMAGE}")
    env_file.write_text(old_contract, encoding="utf-8")
    env_file.chmod(0o600)
    calls = tmp_path / "docker-calls"
    docker = tmp_path / "docker"
    docker.write_text(
        "#!/bin/sh\n"
        'printf "%s\\n" "$*" >> "$DOCKER_CALLS"\n'
        'case "$1 $2" in\n'
        '  "info --format") echo x86_64; exit 0 ;;\n'
        '  "image inspect") exit 1 ;;\n'
        '  "pull splunk/splunk:10.2.0") echo "registry unavailable" >&2; exit 1 ;;\n'
        '  "compose -f") exit 0 ;;\n'
        '  *) exit 1 ;;\n'
        'esac\n',
        encoding="utf-8",
    )
    docker.chmod(0o755)
    refresh_result = RefreshResult("splunk-bridge", str(bridge_dir), str(BUNDLE), refreshed=False)
    with (
        patch.dict(os.environ, {"PATH": f"{tmp_path}{os.pathsep}{os.environ['PATH']}", "DOCKER_CALLS": str(calls)}),
        patch.object(cmd_setup, "is_compose_project_running", return_value=running),
        patch.object(cmd_setup, "refresh_splunk_bridge", return_value=refresh_result) as refresh,
        patch.object(cmd_setup, "bundled_splunk_bridge_dir", return_value=BUNDLE),
    ):
        with pytest.raises(Exception, match="image|registry"):
            cmd_setup._bootstrap_bridge(str(data_dir), refresh_bundle=refresh_bundle)

    recorded = calls.read_text(encoding="utf-8").splitlines()
    assert any(call == "pull splunk/splunk:10.2.0" for call in recorded)
    assert not any(call.startswith("compose ") for call in recorded)
    assert env_file.read_text(encoding="utf-8") == old_contract
    refresh.assert_not_called()


@pytest.mark.parametrize("architecture", ["arm64", "aarch64"])
def test_local_splunk_rejects_arm_engine_before_cached_image_or_compose(
    tmp_path: Path, architecture: str,
) -> None:
    stack = tmp_path / "stack"
    shutil.copytree(BUNDLE, stack)
    env_file = stack / "env" / ".env"
    env_file.write_text((stack / "env" / ".env.example").read_text(encoding="utf-8"), encoding="utf-8")
    env_file.chmod(0o600)

    if os.name != "nt":
        calls = tmp_path / "docker-calls"
        docker = tmp_path / "docker"
        docker.write_text(
            "#!/bin/sh\n"
            'printf "%s\\n" "$*" >> "$DOCKER_CALLS"\n'
            f'echo "{architecture}"\n',
            encoding="utf-8",
        )
        docker.chmod(0o755)
        result = subprocess.run(
            ["bash", str(stack / "bin" / "splunk-claw-bridge"), "up", "--env-file", str(env_file)],
            env={**os.environ, "PATH": f"{tmp_path}:{os.environ['PATH']}", "DOCKER_CALLS": str(calls)},
            capture_output=True, text=True, timeout=30, check=False,
        )
        assert result.returncode != 0
        assert "amd64" in result.stderr and "--enterprise" in result.stderr
        assert calls.read_text(encoding="utf-8").splitlines() == ["info --format {{.Architecture}}"]

    class ArmDocker:
        def __init__(self) -> None:
            self.calls: list[tuple[str, ...]] = []

        def run(self, argv, *, timeout, capture=True, env=None):
            command = tuple(argv)
            self.calls.append(command)
            if command[1:3] == ("info", "--format"):
                return CommandResult(command, 0, stdout=architecture)
            raise AssertionError(f"unexpected Docker call: {command[1]}")

    native_docker = tmp_path / "docker.exe"
    native_docker.write_bytes(b"mock")
    arm = ArmDocker()
    controller = NativeLocalSplunkController(stack, docker_path=native_docker, runner=arm, os_name="windows")
    with pytest.raises(LocalStackError, match=r"amd64.*--enterprise"):
        controller.verify_splunk_image()
    assert len(arm.calls) == 1


@pytest.mark.parametrize("cached", [False, True])
def test_local_splunk_uses_daemon_pull_only_for_uncached_image(tmp_path: Path, cached: bool) -> None:
    image = "splunk/splunk:10.2.0"
    if os.name != "nt":
        bridge = (BUNDLE / "bin" / "splunk-claw-bridge").read_text(encoding="utf-8")
        image_check = bridge[bridge.index("verify_splunk_image() {"):bridge.index("\ncleanup_stopped_service_containers() {")]
        calls = tmp_path / "docker-calls"
        probe = (
            'run_with_time_limit() { shift; "$@"; }\n'
            'fail() { printf "%s\\n" "$1" >&2; exit 1; }\n'
            + image_check + "\n"
            + 'docker() { printf "%s\\n" "$*" >> "$DOCKER_CALLS"; '
            + 'case "$1 $2" in "info --format") echo x86_64 ;; '
            + f'"image inspect") return {0 if cached else 1} ;; '
            + '"pull splunk/splunk:10.2.0") return 0 ;; *) return 99 ;; esac; }\n'
            + f'SPLUNK_IMAGE={image}\nENV_FILE=unused\nverify_splunk_image\n'
        )
        result = subprocess.run(
            ["bash"], input=probe, capture_output=True, text=True,
            env={**os.environ, "DOCKER_CALLS": str(calls)}, timeout=10, check=False,
        )
        assert result.returncode == 0, result.stderr
        expected = ["info --format {{.Architecture}}", f"image inspect {image}"]
        if not cached:
            expected.append(f"pull {image}")
        assert calls.read_text(encoding="utf-8").splitlines() == expected

    stack = tmp_path / "stack"
    shutil.copytree(BUNDLE, stack)
    env_file = stack / "env" / ".env"
    env_file.write_text((stack / "env" / ".env.example").read_text(encoding="utf-8"), encoding="utf-8")
    env_file.chmod(0o600)

    class DaemonDocker:
        def __init__(self) -> None:
            self.calls: list[tuple[str, ...]] = []

        def run(self, argv, *, timeout, capture=True, env=None):
            command = tuple(argv)
            self.calls.append(command)
            if command[1:3] == ("info", "--format"):
                return CommandResult(command, 0, stdout="x86_64")
            if command[1:3] == ("image", "inspect"):
                return CommandResult(command, 0 if cached else 1)
            if command[1] == "pull":
                return CommandResult(command, 0)
            raise AssertionError(f"unexpected Docker call: {command[1]}")

    native_docker = tmp_path / "docker.exe"
    native_docker.write_bytes(b"mock")
    daemon = DaemonDocker()
    controller = NativeLocalSplunkController(stack, docker_path=native_docker, runner=daemon, os_name="windows")
    controller.verify_splunk_image()
    expected_native = [("info", "--format"), ("image", "inspect")]
    if not cached:
        expected_native.append(("pull", image))
    assert [command[1:3] for command in daemon.calls] == expected_native


def test_uncached_image_pull_allows_slow_links_and_shows_progress(tmp_path: Path) -> None:
    image = "splunk/splunk:10.2.0"
    if os.name != "nt":
        bridge = (BUNDLE / "bin" / "splunk-claw-bridge").read_text(encoding="utf-8")
        image_check = bridge[bridge.index("verify_splunk_image() {"):bridge.index("\ncleanup_stopped_service_containers() {")]
        probe = (
            'run_with_time_limit() { if [[ "$*" == *"docker pull"* ]]; then return 124; fi; shift; "$@"; }\n'
            'fail() { printf "%s\\n" "$1" >&2; exit 1; }\n'
            + image_check + "\n"
            + 'docker() { case "$1 $2" in "info --format") echo x86_64 ;; '
            + '"image inspect") return 1 ;; "pull splunk/splunk:10.2.0") '
            + 'echo "Downloading layer" >&2; return 0 ;; *) return 99 ;; esac; }\n'
            + f'SPLUNK_IMAGE={image}\nENV_FILE=unused\nverify_splunk_image\n'
        )
        result = subprocess.run(["bash"], input=probe, capture_output=True, text=True, timeout=10, check=False)
        assert result.returncode == 0, result.stderr
        assert "Downloading layer" in result.stderr

    class SlowDocker:
        def run(self, argv, *, timeout, capture=True, env=None):
            command = tuple(argv)
            if command[1:3] == ("info", "--format"):
                return CommandResult(command, 0, stdout="x86_64")
            if command[1:3] == ("image", "inspect"):
                return CommandResult(command, 1)
            if command[1] == "pull":
                assert timeout >= 7200, "a first download can take longer than five minutes"
                assert capture is False, "Docker pull progress must reach the operator"
                return CommandResult(command, 0)
            raise AssertionError(f"unexpected Docker call: {command}")

    stack = tmp_path / "stack"
    shutil.copytree(BUNDLE, stack)
    env_file = stack / "env" / ".env"
    env_file.write_text((stack / "env" / ".env.example").read_text(encoding="utf-8"), encoding="utf-8")
    env_file.chmod(0o600)
    native_docker = tmp_path / "docker.exe"
    native_docker.write_bytes(b"mock")
    NativeLocalSplunkController(stack, docker_path=native_docker, runner=SlowDocker(), os_name="windows").verify_splunk_image()


def _readiness_probe(path: Path, stubs: str, seconds: int) -> Path:
    """Write a script that runs the bridge readiness loop against stubbed probes."""

    bridge = (BUNDLE / "bin" / "splunk-claw-bridge").read_text(encoding="utf-8")
    readiness = bridge[bridge.index("service_restart_count() {"):bridge.index("\nprint_up_text() {")]
    path.write_text(
        'set -euo pipefail\nDEFENSECLAW_HEC_TOKEN="fixture credential"\n'
        'DEFENSECLAW_HEC_URL="https://127.0.0.1:8088/services/collector/event"\n'
        'SERVICE_NAME=splunk\ncompose_project_name() { echo fixture; }\n'
        'fail() { printf "%s\\n" "$1" >&2; exit 1; }\n'
        # The stubs come after the bridge functions so that they replace them.
        + readiness + "\n" + stubs + f"\nwait_for_hec_ready {seconds}\n",
        encoding="utf-8",
    )
    return path


@pytest.mark.skipif(os.name == "nt", reason="POSIX bind-mount permissions")
def test_app_packages_are_container_readable_under_private_umask(tmp_path: Path, monkeypatch) -> None:
    from defenseclaw.observability.local_splunk import NativeLocalSplunkController, package_splunk_app
    from defenseclaw.observability.local_stack import LocalStackError

    stack = tmp_path / "stack"
    shutil.copytree(BUNDLE, stack)
    archive = stack / "splunk" / "build" / "defenseclaw_local_mode.tgz"
    # Both the Unix bridge and the native controller rebuild this mounted
    # public asset. Neither may inherit the operator's private file modes.
    for packager in ("shell", "native"):
        if archive.parent.exists():
            shutil.rmtree(archive.parent)
        if packager == "shell":
            completed = subprocess.run(
                ["bash", str(stack / "splunk" / "package_local_mode_app.sh")],
                capture_output=True, text=True, umask=0o077, timeout=30, check=False,
            )
            assert completed.returncode == 0, completed.stderr
        else:
            previous = os.umask(0o077)
            try:
                package_splunk_app(stack)
            finally:
                os.umask(previous)
        assert stat.S_IMODE(archive.parent.stat().st_mode) == 0o755
        assert stat.S_IMODE(archive.stat().st_mode) == 0o644

    # Healthy listeners alone cannot prove that Splunk installed the app.
    probe = _readiness_probe(
        tmp_path / "readiness.sh",
        'curl() { printf 200; }\nrun_compose() { [[ "$APP_READY" == true ]]; }\n'
        "service_restart_count() { echo 2; }",
        10,
    )
    for ready in (False, True):
        result = subprocess.run(
            ["bash", str(probe)], env={**os.environ, "APP_READY": str(ready).lower()},
            capture_output=True, text=True, timeout=10, check=False,
        )
        assert (result.returncode == 0) is ready, result.stdout + result.stderr

    controller = NativeLocalSplunkController(stack, docker_path="docker")
    monkeypatch.setattr(controller, "_web_ready", lambda _timeout: True)
    monkeypatch.setattr(controller, "_hec_ready", lambda _timeout: True)
    compose = Mock(return_value=SimpleNamespace(returncode=1))
    monkeypatch.setattr(controller, "_run_compose", compose)
    with pytest.raises(LocalStackError, match="readiness timeout"):
        controller.wait_for_readiness(1)
    compose.return_value.returncode = 0
    controller.wait_for_readiness(1)
    assert "test" in compose.call_args.args


@pytest.mark.skipif(os.name == "nt", reason="the Unix bridge runs under bash")
def test_bridge_readiness_sends_no_hec_token(tmp_path: Path) -> None:
    # GAP-1172: the bridge's readiness loop POSTed the HEC token to whatever
    # listened on 127.0.0.1:8088, without verifying its certificate, every
    # five seconds; a peer that took the port while the stack started or
    # after it stopped got the token. It asks the token-free health endpoint.
    curl_log = tmp_path / "curl.log"
    probe = _readiness_probe(
        tmp_path / "readiness.sh",
        'curl() { printf "%s\\n" "$*" >> "$CURL_LOG"; printf 503; }\n'
        "run_compose() { return 1; }\nservice_restart_count() { echo 0; }",
        2,
    )
    result = subprocess.run(
        ["bash", str(probe)], env={**os.environ, "CURL_LOG": str(curl_log)},
        capture_output=True, text=True, timeout=20, check=False,
    )
    assert result.returncode != 0, result.stdout + result.stderr
    calls = curl_log.read_text(encoding="utf-8").splitlines()
    assert calls, "the readiness loop made no HEC probe"
    for call in calls:
        assert "fixture credential" not in call and "Authorization" not in call, call
        assert "https://127.0.0.1:8088/services/collector/health" in call, call
        assert " -d " not in f" {call} ", call


@pytest.mark.skipif(os.name == "nt", reason="the Unix bridge runs under bash")
@pytest.mark.parametrize("ignores_term", [False, True], ids=["stalls", "stalls-ignoring-term"])
def test_bridge_readiness_deadline_bounds_a_stalled_app_probe(tmp_path: Path, ignores_term: bool) -> None:
    # HEC answers, but docker compose exec never returns. The readiness
    # deadline must still fire, and the stalled probe must not outlive it.
    pid_file = tmp_path / "probe.pid"
    curl_log = tmp_path / "curl.log"
    stall = ('trap "" TERM; ' if ignores_term else "") + (
        'echo $$ > "$PROBE_PID"; i=0; while [ $i -lt 60 ]; do sleep 1; i=$((i+1)); done'
    )
    probe = _readiness_probe(
        tmp_path / "readiness.sh",
        'curl() { printf "%s\\n" "$*" >> "$CURL_LOG"; printf 200; }\n'
        f"run_compose() {{ sh -c '{stall}'; }}\nservice_restart_count() {{ echo 0; }}",
        3,
    )
    started = time.monotonic()
    result = subprocess.run(
        ["bash", str(probe)],
        env={**os.environ, "PROBE_PID": str(pid_file), "CURL_LOG": str(curl_log)},
        capture_output=True, text=True, timeout=30, check=False,
    )
    elapsed = time.monotonic() - started
    assert result.returncode != 0, result.stdout + result.stderr
    assert elapsed < 10, f"readiness took {elapsed:.1f}s past a 3s deadline"
    stalled = int(pid_file.read_text(encoding="utf-8"))
    for _ in range(30):
        try:
            os.kill(stalled, 0)
        except ProcessLookupError:
            break
        time.sleep(0.1)
    else:
        os.kill(stalled, 9)
        pytest.fail("the stalled app probe outlived the readiness deadline")
    # Every HTTP probe is bounded by what is left of the deadline as well.
    limits = [int(line.split("--max-time ")[1].split()[0]) for line in curl_log.read_text().splitlines()]
    assert limits and all(1 <= limit <= 3 for limit in limits), limits


@pytest.mark.skipif(os.name == "nt", reason="the Unix bridge runs under bash")
@pytest.mark.parametrize("logs", ["answers", "stalls", "stalls-ignoring-term", "no-time-left"])
def test_bridge_restart_diagnostics_share_the_readiness_deadline(tmp_path: Path, logs: str) -> None:
    # GAP-0489: HEC answers, the app probe fails and the container keeps
    # restarting. Its last log lines are collected only within what is left
    # of the readiness deadline; with nothing left the error comes without them.
    pid_file = tmp_path / "logs.pid"
    called = tmp_path / "logs.called"
    stall = 'echo $$ > "$PROBE_PID"; i=0; while [ $i -lt 60 ]; do sleep 1; i=$((i+1)); done'
    body = 'touch "$LOGS_CALLED"; echo "fixture log line"'
    if logs == "stalls":
        body += "; " + stall
    elif logs in {"stalls-ignoring-term", "no-time-left"}:
        body += '; trap "" TERM; ' + stall
    # In the last case the restart probe itself uses up the deadline.
    restart_count = "echo 2; sleep 10" if logs == "no-time-left" else "echo 2"
    probe = _readiness_probe(
        tmp_path / "readiness.sh",
        "curl() { printf 200; }\n"
        f"run_compose() {{ if [[ \"$1\" == logs ]]; then sh -c '{body}'; else return 1; fi; }}\n"
        f"service_restart_count() {{ {restart_count}; }}",
        3,
    )
    started = time.monotonic()
    result = subprocess.run(
        ["bash", str(probe)],
        env={**os.environ, "PROBE_PID": str(pid_file), "LOGS_CALLED": str(called)},
        capture_output=True, text=True, timeout=30, check=False,
    )
    elapsed = time.monotonic() - started
    assert result.returncode != 0, result.stdout + result.stderr
    assert "keeps restarting" in result.stderr, result.stderr
    # Three seconds of deadline (bash SECONDS counts whole seconds), plus one
    # second for a probe that ignores TERM, plus start-up on a loaded runner.
    # The stalled log command alone would run for 60 seconds.
    assert elapsed < 8, f"restart diagnostics took {elapsed:.1f}s past a 3s deadline"
    if logs == "no-time-left":
        assert not called.exists(), "logs were collected after the deadline"
        assert "last log lines" not in result.stderr, result.stderr
    else:
        assert "last log lines" in result.stderr and "fixture log line" in result.stderr, result.stderr
    if pid_file.exists():
        stalled = int(pid_file.read_text(encoding="utf-8"))
        for _ in range(30):
            try:
                os.kill(stalled, 0)
            except ProcessLookupError:
                break
            time.sleep(0.1)
        else:
            os.kill(stalled, 9)
            pytest.fail("the stalled log probe outlived the readiness deadline")


@pytest.mark.skipif(shutil.which("uv") is None, reason="uv is required to build wheels")
def test_wheel_resolves_complete_splunk_bundle_outside_checkout(
    tmp_path: Path,
) -> None:
    output = tmp_path / "wheel"
    environment = os.environ.copy()
    environment.pop("PYTHONHOME", None)
    environment.pop("PYTHONPATH", None)
    completed = subprocess.run(
        [shutil.which("uv"), "build", "--wheel", "--out-dir", str(output)],
        cwd=REPO_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=240,
        check=False,
    )
    assert completed.returncode == 0, (completed.stdout + completed.stderr)[-4000:]
    wheel = next(output.glob("defenseclaw-*.whl"))
    expected_assets = {
        path.relative_to(BUNDLE).as_posix()
        for path in BUNDLE.rglob("*")
        if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc"
    }
    prefix = "defenseclaw/_data/splunk_local_bridge/"
    with zipfile.ZipFile(wheel) as archive:
        names = set(archive.namelist())
        packaged_assets = {name.removeprefix(prefix) for name in names if name.startswith(prefix)}
        assert expected_assets <= packaged_assets
        for relative_path in expected_assets:
            assert archive.read(prefix + relative_path) == (BUNDLE / Path(relative_path)).read_bytes(), (
                f"packaged Local Splunk asset drifted: {relative_path}"
            )
        assert "defenseclaw/observability/local_splunk.py" in names
        archive.extractall(tmp_path / "site")

    probe = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            (
                "import pathlib,sys;sys.path.insert(0,sys.argv[1]);"
                "from defenseclaw.paths import bundled_splunk_bridge_dir;"
                "from defenseclaw.observability.local_splunk import validate_bundle_assets;"
                "p=validate_bundle_assets(bundled_splunk_bridge_dir());"
                "assert (p/'compose'/'docker-compose.local.yml').is_file();"
                "assert (p/'splunk'/'apps'/'defenseclaw_local_mode'/'lookups'/'dcso_risk_state_labels.csv').is_file();"
                "assert (p/'splunk'/'apps'/'defenseclaw_local_mode'/'lookups'/'dcso_severity_labels.csv').is_file();"
                "assert sys.argv[2] not in str(p);print(p)"
            ),
            str(tmp_path / "site"),
            str(REPO_ROOT),
        ],
        cwd=tmp_path,
        env={"PATH": os.environ.get("PATH", "")},
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
        check=False,
    )
    assert probe.returncode == 0, probe.stdout + probe.stderr
    assert "_data" in probe.stdout
