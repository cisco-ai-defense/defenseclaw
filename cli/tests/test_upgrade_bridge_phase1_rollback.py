# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import gzip
import hashlib
import json
import os
import platform
import re
import shutil
import socket
import stat
import subprocess
import sys
import sysconfig
import tarfile
import time
import zipfile
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
UPGRADE_SCRIPT = ROOT / "scripts" / "upgrade.sh"
POSIX_UPGRADE_RUNTIME_ONLY = pytest.mark.skipif(
    os.name == "nt",
    reason="upgrade.sh phase-one runtime contracts require POSIX signals, ownership, symlinks, and executables",
)


def _write_executable(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)


@pytest.fixture(scope="module")
def packaged_target_controller_python(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Build one isolated target-controller fixture with wheel-owned telemetry data."""

    root = tmp_path_factory.mktemp("target-controller")
    subprocess.run(
        [sys.executable, "-m", "venv", "--without-pip", str(root)],
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    )
    target_python = root / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    purelib = Path(
        subprocess.check_output(
            [
                str(target_python),
                "-c",
                "import sysconfig; print(sysconfig.get_path('purelib'))",
            ],
            text=True,
            timeout=30,
        ).strip()
    )
    shutil.copytree(
        ROOT / "cli" / "defenseclaw",
        purelib / "defenseclaw",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )
    (purelib / "test-dependencies.pth").write_text(
        sysconfig.get_paths()["purelib"] + "\n",
        encoding="utf-8",
    )
    telemetry = purelib / "defenseclaw" / "_data" / "telemetry" / "v8"
    telemetry.mkdir(parents=True, exist_ok=True)
    runtime = ROOT / "schemas" / "telemetry" / "runtime"
    resources = {
        "telemetry.schema.json": runtime / "telemetry.schema.json.gz",
        "catalog.json": runtime / "catalog.json.gz",
        "v7-exporter-selection.json": (runtime / "compatibility" / "v7-exporter-selection.json.gz"),
        "galileo-rich-v2.json": runtime / "compatibility" / "galileo-rich-v2.json.gz",
        "local-observability-v1.json": (runtime / "compatibility" / "local-observability-v1.json.gz"),
        "openinference-v1.json": (runtime / "compatibility" / "openinference-v1.json.gz"),
    }
    for name, source in resources.items():
        (telemetry / name).write_bytes(gzip.decompress(source.read_bytes()))
    config_resources = purelib / "defenseclaw" / "_data" / "config" / "v8"
    config_resources.mkdir(parents=True, exist_ok=True)
    shutil.copy2(
        ROOT / "schemas" / "config" / "v8" / "defenseclaw-config.schema.json",
        config_resources / "defenseclaw-config.schema.json",
    )
    shutil.copy2(
        ROOT / "schemas" / "config" / "v8" / "reference" / "observability.yaml",
        config_resources / "observability.yaml",
    )
    shutil.copy2(
        ROOT / "schemas" / "config" / "v8" / "reference" / "observability.md",
        config_resources / "observability.md",
    )
    return target_python


def _process_start_identity(pid: int) -> str:
    if sys.platform.startswith("linux"):
        payload = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
        return payload[payload.rfind(")") + 1 :].split()[19]
    if sys.platform == "darwin":
        return subprocess.check_output(
            ["/bin/ps", "-p", str(pid), "-o", "lstart="],
            text=True,
            timeout=10,
        ).strip()
    return ""


def _write_json_pid(path: Path, pid: int, executable: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "pid": pid,
                "executable": str(executable),
                "start_time": int(time.time()),
                "start_identity": _process_start_identity(pid),
            },
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )
    path.chmod(0o600)


def _compile_source_gateway(path: Path, *, version: str = "0.8.3") -> None:
    compiler = shutil.which("cc")
    if compiler is None:
        pytest.skip("a C compiler is required for phase-one PID-custody tests")
    source = path.with_suffix(".c")
    source.write_text(
        r"""
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static int read_pid(const char *path) {
    FILE *stream = fopen(path, "r");
    if (!stream) return 0;
    char payload[4097] = {0};
    size_t count = fread(payload, 1, sizeof(payload) - 1, stream);
    fclose(stream);
    if (count == 0) return 0;
    char *pid_key = strstr(payload, "\"pid\"");
    char *value = pid_key ? strchr(pid_key, ':') : payload;
    if (!value) return 0;
    if (pid_key) value++;
    char *end = NULL;
    long parsed = strtol(value, &end, 10);
    return parsed > 0 && parsed <= 2147483647L ? (int)parsed : 0;
}

static void append_event(const char *event) {
    const char *path = getenv("UPGRADE_EVENT_LOG");
    if (!path) return;
    FILE *stream = fopen(path, "a");
    if (!stream) return;
    fprintf(stream, "%s\n", event);
    fclose(stream);
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "__daemon") == 0) {
        for (;;) pause();
    }
    if (argc > 1 && strcmp(argv[1], "--version") == 0) {
        puts("DefenseClaw gateway 0.8.3");
        return 0;
    }
    const char *home = getenv("DEFENSECLAW_HOME");
    if (!home) return 90;
    char pid_path[4096];
    snprintf(pid_path, sizeof(pid_path), "%s/gateway.pid", home);
    if (argc > 1 && strcmp(argv[1], "stop") == 0) {
        append_event("source-stop");
        int pid = read_pid(pid_path);
        if (pid > 0) kill(pid, SIGTERM);
        unlink(pid_path);
        if (getenv("INJECT_PHASE1_CRASH_AFTER_SOURCE_STOP")) {
            kill(getppid(), SIGKILL);
            close(STDIN_FILENO);
            close(STDOUT_FILENO);
            close(STDERR_FILENO);
            sleep(4);
            return 137;
        }
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "start") == 0) {
        append_event("source-start");
        pid_t child = fork();
        if (child < 0) return 91;
        if (child == 0) {
            execl(argv[0], argv[0], "__daemon", (char *)NULL);
            _exit(92);
        }
        FILE *stream = fopen(pid_path, "w");
        if (!stream) return 93;
        fprintf(stream, "{\"pid\":%d,\"executable\":\"%s\",\"start_time\":0}\n", (int)child, argv[0]);
        fclose(stream);
        chmod(pid_path, 0600);
        return 0;
    }
    return 0;
}
""".replace("DefenseClaw gateway 0.8.3", f"DefenseClaw gateway {version}"),
        encoding="utf-8",
    )
    subprocess.run(
        [compiler, "-std=c99", "-D_POSIX_C_SOURCE=200809L", str(source), "-o", str(path)],
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    )
    path.chmod(0o755)


def _compile_live_bridge_gateway(path: Path) -> None:
    compiler = shutil.which("cc")
    if compiler is None:
        pytest.skip("a C compiler is required for phase-one PID-custody tests")
    source = path.with_suffix(".c")
    source.write_text(
        r"""
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

static int read_pid(const char *path) {
    FILE *stream = fopen(path, "r");
    if (!stream) return 0;
    char payload[4097] = {0};
    size_t count = fread(payload, 1, sizeof(payload) - 1, stream);
    fclose(stream);
    if (count == 0) return 0;
    char *pid_key = strstr(payload, "\"pid\"");
    char *value = pid_key ? strchr(pid_key, ':') : payload;
    if (!value) return 0;
    if (pid_key) value++;
    long parsed = strtol(value, NULL, 10);
    return parsed > 0 && parsed <= 2147483647L ? (int)parsed : 0;
}

static void append_event(const char *event) {
    const char *path = getenv("UPGRADE_EVENT_LOG");
    if (!path) return;
    FILE *stream = fopen(path, "a");
    if (!stream) return;
    fprintf(stream, "%s\n", event);
    fclose(stream);
}

static int set_io_timeouts(int descriptor) {
    struct timeval timeout = {.tv_sec = 1, .tv_usec = 0};
    if (setsockopt(
            descriptor, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)
        ) != 0) return -1;
    if (setsockopt(
            descriptor, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)
        ) != 0) return -1;
    return 0;
}

static void send_bounded(int descriptor, const char *payload, size_t length) {
    size_t sent = 0;
    while (sent < length) {
        ssize_t count = send(descriptor, payload + sent, length - sent, 0);
        if (count > 0) {
            sent += (size_t)count;
            continue;
        }
        if (count < 0 && errno == EINTR) continue;
        /* A timeout or disconnected test client is not a server failure. */
        break;
    }
}

static int run_status_server(void) {
    if (getenv("TARGET_GATEWAY_EXIT_AFTER_START")) {
        struct timespec pause_for = {.tv_sec = 0, .tv_nsec = 100000000L};
        nanosleep(&pause_for, NULL);
        return 0;
    }
    unsigned short port = 18970;
    const char *configured_port = getenv("TARGET_STATUS_PORT");
    if (configured_port && configured_port[0] != '\0') {
        char *end = NULL;
        errno = 0;
        long parsed = strtol(configured_port, &end, 10);
        if (errno != 0 || end == configured_port || *end != '\0' ||
            parsed < 1 || parsed > 65535) return 98;
        port = (unsigned short)parsed;
    }
    int server = socket(AF_INET, SOCK_STREAM, 0);
    if (server < 0) return 94;
    int reuse = 1;
    setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    if (set_io_timeouts(server) != 0) {
        close(server);
        return 94;
    }
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    if (inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) != 1) {
        close(server);
        return 95;
    }
    if (bind(server, (struct sockaddr *)&address, sizeof(address)) != 0) {
        close(server);
        return 95;
    }
    if (listen(server, 8) != 0) {
        close(server);
        return 96;
    }
    signal(SIGPIPE, SIG_IGN);
    for (;;) {
        int client = accept(server, NULL, NULL);
        if (client < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            close(server);
            return 97;
        }
        if (set_io_timeouts(client) != 0) {
            close(client);
            continue;
        }
        char request[8193] = {0};
        size_t used = 0;
        while (used < sizeof(request) - 1) {
            ssize_t count = recv(client, request + used, sizeof(request) - 1 - used, 0);
            if (count < 0 && errno == EINTR) continue;
            if (count <= 0) break;
            used += (size_t)count;
            request[used] = '\0';
            if (strstr(request, "\r\n\r\n")) break;
        }
        const char *token = getenv("DEFENSECLAW_GATEWAY_TOKEN");
        char authorization[1024] = {0};
        int authorization_length = -1;
        if (token) {
            authorization_length = snprintf(
                authorization,
                sizeof(authorization),
                "\r\nAuthorization: Bearer %s\r\n",
                token
            );
        }
        int authorization_complete =
            authorization_length > 0 &&
            (size_t)authorization_length < sizeof(authorization);
        int authorized =
            strstr(request, "GET /status HTTP/1.1\r\n") == request &&
            token && token[0] != '\0' &&
            authorization_complete &&
            strstr(request, authorization) != NULL;
        const char *body =
            "{\"health\":{\"api\":{\"state\":\"running\"},"
            "\"gateway\":{\"state\":\"running\"},"
            "\"watcher\":{\"state\":\"disabled\"},"
            "\"guardrail\":{\"state\":\"disabled\"},"
            "\"telemetry\":{\"state\":\"running\"}},"
            "\"provenance\":{\"binary_version\":\"0.8.4\"}}";
        char response[2048];
        if (authorized) {
            int length = snprintf(
                response,
                sizeof(response),
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                "Content-Length: %zu\r\nConnection: close\r\n\r\n%s",
                strlen(body),
                body
            );
            if (length > 0 && (size_t)length < sizeof(response)) {
                send_bounded(client, response, (size_t)length);
            }
        } else {
            const char *unauthorized =
                "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            send_bounded(client, unauthorized, strlen(unauthorized));
        }
        close(client);
    }
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "__daemon") == 0) {
        return run_status_server();
    }
    if (argc > 1 && strcmp(argv[1], "--version") == 0) {
        puts("DefenseClaw gateway 0.8.4");
        return 0;
    }
    const char *home = getenv("DEFENSECLAW_HOME");
    if (!home) return 90;
    char pid_path[4096];
    snprintf(pid_path, sizeof(pid_path), "%s/gateway.pid", home);
    if (argc > 1 && strcmp(argv[1], "stop") == 0) {
        append_event("target-stop");
        int pid = read_pid(pid_path);
        if (pid > 0) kill(pid, SIGTERM);
        unlink(pid_path);
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "start") == 0) {
        append_event("target-start");
        if (!getenv("ALLOW_TARGET_GATEWAY_START") &&
            !getenv("DEFENSECLAW_TEST_PHASE1_POST_HEALTH_CRASH")) return 42;
        pid_t child = fork();
        if (child < 0) return 91;
        if (child == 0) {
            close(STDIN_FILENO);
            close(STDOUT_FILENO);
            close(STDERR_FILENO);
            execl(argv[0], argv[0], "__daemon", (char *)NULL);
            _exit(92);
        }
        FILE *stream = fopen(pid_path, "w");
        if (!stream) return 93;
        fprintf(stream, "{\"pid\":%d,\"executable\":\"%s\",\"start_time\":0}\n",
                (int)child, argv[0]);
        fclose(stream);
        chmod(pid_path, 0600);
        return 0;
    }
    return 64;
}
""",
        encoding="utf-8",
    )
    subprocess.run(
        [compiler, "-std=c99", "-D_POSIX_C_SOURCE=200809L", str(source), "-o", str(path)],
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    )
    path.chmod(0o755)


@POSIX_UPGRADE_RUNTIME_ONLY
def test_live_bridge_status_fixture_honors_target_status_port(tmp_path: Path) -> None:
    gateway = tmp_path / "defenseclaw-gateway"
    _compile_live_bridge_gateway(gateway)
    token = "phase-one-custom-port-token"
    base_env = os.environ | {
        "ALLOW_TARGET_GATEWAY_START": "1",
        "DEFENSECLAW_GATEWAY_TOKEN": token,
        "DEFENSECLAW_HOME": str(tmp_path),
    }
    gateway_process: subprocess.Popen[bytes] | None = None
    port = 0
    last_probe_error: OSError | None = None
    try:
        # Releasing a kernel-selected port before the fixture binds it has an
        # unavoidable race. Retry with a fresh port if another process wins it.
        for _port_attempt in range(5):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                probe.bind(("127.0.0.1", 0))
                port = int(probe.getsockname()[1])
            candidate_env = base_env | {"TARGET_STATUS_PORT": str(port)}
            candidate = subprocess.Popen(
                [str(gateway), "__daemon"],
                env=candidate_env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            # A client that connects but never sends a request must not pin the
            # fixture forever and hide a resolver readiness result.
            for _probe_attempt in range(50):
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                        time.sleep(1.2)
                    gateway_process = candidate
                    break
                except OSError as exc:
                    last_probe_error = exc
                    if candidate.poll() is not None:
                        break
                    time.sleep(0.02)
            if gateway_process is not None:
                break
            if candidate.poll() is None:
                candidate.terminate()
                candidate.wait(timeout=10)
        else:
            pytest.fail(f"status fixture could not bind any of 5 fresh ports; last probe error: {last_probe_error!r}")

        response = b""
        last_status_error: OSError | None = None
        request = (
            "GET /status HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{port}\r\n"
            f"Authorization: Bearer {token}\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
        for _attempt in range(50):
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.5) as client:
                    client.sendall(request)
                    chunks = []
                    while chunk := client.recv(4096):
                        chunks.append(chunk)
                    response = b"".join(chunks)
                break
            except OSError as exc:
                last_status_error = exc
                time.sleep(0.02)
        else:
            pytest.fail(
                "status fixture did not answer the bounded authenticated probe; "
                f"last socket error: {last_status_error!r}"
            )

        assert response.startswith(b"HTTP/1.1 200 OK\r\n"), response
        assert b'"binary_version":"0.8.4"' in response
    finally:
        if gateway_process is not None:
            gateway_process.terminate()
            gateway_process.wait(timeout=10)


def _platform_asset_name(version: str) -> str:
    os_name = platform.system().lower()
    machine = platform.machine().lower()
    arch = "arm64" if machine in {"arm64", "aarch64"} else "amd64"
    return f"defenseclaw_{version}_protocol2_{os_name}_{arch}.dcgateway"


def _protect_artifact(payload: bytes) -> bytes:
    return b"DEFENSECLAW-PROTECTED-ARTIFACT-V1\n" + bytes(value ^ 0xA5 for value in payload)


def _flat_081_config(data_home: Path) -> str:
    return (
        f"data_dir: {data_home}\n"
        "otel:\n"
        "  enabled: false\n"
        "  protocol: grpc\n"
        "  endpoint: ''\n"
        "  headers: {}\n"
        "  tls: {insecure: false, ca_cert: ''}\n"
        "  traces: {enabled: true, sampler: always_on, sampler_arg: '1.0', endpoint: '', protocol: '', url_path: ''}\n"
        "  logs: {enabled: true, emit_individual_findings: false, endpoint: '', protocol: '', url_path: ''}\n"
        "  metrics: {enabled: true, export_interval_s: 60, endpoint: '', protocol: '', url_path: ''}\n"
        "  batch: {max_export_batch_size: 512, scheduled_delay_ms: 5000, max_queue_size: 2048}\n"
        "  resource: {attributes: {}}\n"
    )


def _named_081_config(data_home: Path) -> str:
    return (
        f"data_dir: {data_home}\n"
        "otel:\n"
        "  enabled: false\n"
        "  traces: {sampler: always_on, sampler_arg: '1.0'}\n"
        "  logs: {emit_individual_findings: false}\n"
        "  resource: {attributes: {}}\n"
        "  destinations:\n"
        "    - name: generic-otlp\n"
        "      preset: generic-otlp\n"
        "      enabled: false\n"
        "      endpoint: ''\n"
        "      protocol: grpc\n"
        "      tls: {ca_cert: '', insecure: false}\n"
        "      batch: {max_queue_size: 2048, max_export_batch_size: 512, scheduled_delay_ms: 5000}\n"
        "      traces: {enabled: true, endpoint: '', protocol: '', url_path: ''}\n"
        "      logs: {enabled: true, endpoint: '', protocol: '', url_path: ''}\n"
        "      metrics: {enabled: true, endpoint: '', protocol: '', url_path: '', export_interval_s: 60}\n"
    )


def _make_bridge_assets(root: Path, *, live_gateway: bool = False) -> None:
    version = "0.8.4"
    release = root / version
    release.mkdir(parents=True)
    gateways = {
        platform_name: {
            arch: f"defenseclaw_{version}_protocol2_{platform_name}_{arch}.dcgateway" for arch in ("amd64", "arm64")
        }
        for platform_name in ("darwin", "linux", "windows")
    }
    manifest = {
        "schema_version": 2,
        "release_version": version,
        "controller_upgrade_protocol": 2,
        "min_upgrade_protocol": 1,
        "migration_failure_policy": "warn",
        "required_cli_migrations": [],
        "runtime_config_version": 7,
        "release_artifacts": {
            "wheel": f"defenseclaw-{version}-2-py3-none-any.dcwheel",
            "gateways": gateways,
        },
        "tested_source_versions": ["0.8.3", "0.8.1", "0.4.0"],
        "platform_tested_source_versions": {"windows": ["0.8.3"]},
    }
    (release / "upgrade-manifest.json").write_text(
        json.dumps(manifest, sort_keys=True),
        encoding="utf-8",
    )

    wheel = release / f"defenseclaw-{version}-2-py3-none-any.dcwheel"
    inner_wheel = release / f"defenseclaw-{version}-2-py3-none-any.whl"
    controller = (
        '_STAGED_BRIDGE_ARTIFACT_DIR_ENV = "DEFENSECLAW_STAGED_BRIDGE_ARTIFACT_DIR"\n'
        "def _prepare_hard_cut_rollback_plan(): pass\n"
        "def _execute_hard_cut_rollback(): pass\n"
        "_prepare_hard_cut_rollback_plan()\n"
    )
    with zipfile.ZipFile(inner_wheel, "w") as archive:
        archive.writestr("defenseclaw/commands/cmd_upgrade.py", controller)
    wheel.write_bytes(_protect_artifact(inner_wheel.read_bytes()))
    inner_wheel.unlink()

    gateway_source = release / "gateway"
    _write_executable(
        gateway_source,
        """#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  --version)
    if [[ "${INJECT_PHASE1_CRASH_ON_TARGET_VERSION:-}" == '1' \
          && "${0}" == "${HOME}/.local/bin/defenseclaw-gateway" ]]; then
      command_subshell_pid="${PPID}"
      upgrade_pid="$(ps -o ppid= -p "${command_subshell_pid}" | tr -d ' ')"
      kill -KILL "${upgrade_pid}"
      kill -KILL "${command_subshell_pid}" 2>/dev/null || true
      exec >/dev/null 2>&1
      sleep 4
      exit 137
    fi
    printf '%s\n' 'DefenseClaw gateway 0.8.4'
    ;;
  stop)
    if [[ -f "${DEFENSECLAW_HOME}/gateway.pid" ]]; then
      pid="$(python3 - "${DEFENSECLAW_HOME}/gateway.pid" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    print(json.load(stream)["pid"])
PY
)"
      kill "${pid}" 2>/dev/null || true
      rm -f "${DEFENSECLAW_HOME}/gateway.pid"
    fi
    ;;
  start)
    printf '%s\n' 'target-start' >> "${UPGRADE_EVENT_LOG}"
    if [[ "${INJECT_CONCURRENT_PHASE1_STATE:-0}" == '1' ]]; then
      mkdir -p "${DEFENSECLAW_HOME}/hooks"
      printf '%s\n' 'concurrent-user-hook' > "${DEFENSECLAW_HOME}/hooks/concurrent-user.txt"
      printf '%s\n' 'concurrent-user-config' > "${DEFENSECLAW_CONFIG}"
    fi
    if [[ "${INJECT_POST_QUARANTINE_WRITE:-0}" == '1' ]]; then
      exec 8>>"${DEFENSECLAW_CONFIG}"
      (
        for ((_attempt = 0; _attempt < 200; _attempt++)); do
          if grep -q '^custom: keep$' "${DEFENSECLAW_CONFIG}" 2>/dev/null; then
            printf '%s\n' 'post-quarantine-user-write' >&8
            exit 0
          fi
          sleep 0.02
        done
        exit 99
      ) </dev/null >/dev/null 2>&1 &
    fi
    if [[ "${DEFENSECLAW_TEST_PHASE1_POST_HEALTH_CRASH:-}" == 'after-health' \
          || "${ALLOW_TARGET_GATEWAY_START:-0}" == '1' ]]; then
      "${0}" __daemon </dev/null >/dev/null 2>&1 &
      child_pid="$!"
      printf '{"pid":%s,"executable":"%s","start_time":0}\n' \
        "${child_pid}" "${0}" > "${DEFENSECLAW_HOME}/gateway.pid"
      exit 0
    fi
    exit 42
    ;;
  __daemon)
    while true; do sleep 60; done
    ;;
  *)
    exit 64
    ;;
esac
""",
    )
    if live_gateway:
        _compile_live_bridge_gateway(gateway_source)
    tarball = release / _platform_asset_name(version)
    inner_tarball = release / f"defenseclaw_{version}_protocol2_inner.tar.gz"
    with tarfile.open(inner_tarball, "w:gz") as archive:
        info = archive.gettarinfo(str(gateway_source), arcname="defenseclaw")
        info.mode = 0o755
        with gateway_source.open("rb") as source_file:
            archive.addfile(info, source_file)
    tarball.write_bytes(_protect_artifact(inner_tarball.read_bytes()))
    inner_tarball.unlink()

    checksum_lines = []
    for path in (release / "upgrade-manifest.json", wheel, tarball):
        checksum_lines.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}")
    (release / "checksums.txt").write_text("\n".join(checksum_lines) + "\n", encoding="utf-8")
    (release / "checksums.txt.sig").write_text("test signature\n", encoding="utf-8")
    (release / "checksums.txt.pem").write_text("test certificate\n", encoding="utf-8")


def _make_hard_cut_contract_assets(root: Path) -> None:
    version = "0.8.5"
    release = root / version
    release.mkdir(parents=True)
    gateways = {
        platform_name: {
            arch: f"defenseclaw_{version}_protocol2_{platform_name}_{arch}.dcgateway" for arch in ("amd64", "arm64")
        }
        for platform_name in ("darwin", "linux", "windows")
    }
    manifest = {
        "schema_version": 2,
        "release_version": version,
        "controller_upgrade_protocol": 2,
        "min_upgrade_protocol": 2,
        "minimum_source_version": "0.8.4",
        "required_bridge_version": "0.8.4",
        "auto_bridge_from": ["0.8.1"],
        "migration_failure_policy": "fail",
        "required_cli_migrations": ["0.8.5"],
        "runtime_config_version": 8,
        "release_artifacts": {
            "wheel": f"defenseclaw-{version}-2-py3-none-any.dcwheel",
            "gateways": gateways,
        },
        "tested_source_versions": ["0.8.4", "0.8.1"],
        "platform_tested_source_versions": {"windows": []},
    }
    manifest_path = release / "upgrade-manifest.json"
    manifest_path.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
    wheel = release / f"defenseclaw-{version}-2-py3-none-any.dcwheel"
    wheel.write_bytes(_protect_artifact(b"unused hard-cut controller"))
    gateway = release / _platform_asset_name(version)
    gateway.write_bytes(_protect_artifact(b"unused hard-cut gateway"))
    bridge_checksums = hashlib.sha256((root / "0.8.4" / "checksums.txt").read_bytes()).hexdigest()
    provenance = {
        "schema_version": 1,
        "release_version": version,
        "source_commit": "1" * 40,
        "source_tree": "2" * 40,
        "policy_commit": "3" * 40,
        "policy_tree": "4" * 40,
        "release_source_map_sha256": "5" * 64,
        "source_install_identity": {
            "schema_version": 1,
            "source_release": version,
            "source_install_compatibility_epoch": 2,
            "runtime_config_version": 8,
        },
        "bridge": {
            "version": "0.8.4",
            "commit": "6" * 40,
            "tree": "7" * 40,
            "checksums_sha256": bridge_checksums,
        },
    }
    provenance_path = release / "release-provenance.json"
    provenance_path.write_text(
        json.dumps(provenance, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    checksum_paths = (manifest_path, wheel, gateway, provenance_path)
    (release / "checksums.txt").write_text(
        "".join(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n" for path in checksum_paths),
        encoding="utf-8",
    )
    (release / "checksums.txt.sig").write_text("test signature\n", encoding="utf-8")
    (release / "checksums.txt.pem").write_text("test certificate\n", encoding="utf-8")


@POSIX_UPGRADE_RUNTIME_ONLY
@pytest.mark.parametrize(
    (
        "crash_point",
        "source_running",
        "unrelated_pid",
        "orphan_health",
        "openclaw_present",
        "concurrent_divergence",
        "post_quarantine_write",
    ),
    [
        (None, True, False, False, True, False, False),
        ("after-stop", True, False, False, True, False, False),
        ("after-target-gateway", True, False, False, True, False, False),
        ("migration-after-config", True, False, False, True, False, False),
        ("migration-after-config", False, False, False, True, False, False),
        ("seal-after-active-manifest", True, False, False, True, False, False),
        ("after-bridge-health", True, False, False, True, False, False),
        ("rollback-after-state-restore", True, False, False, True, False, False),
        ("rollback-after-state-restore", True, False, False, False, False, False),
        ("target-exits-after-start", True, False, False, True, False, False),
        ("recovery-after-gateway-displace", True, False, False, True, False, False),
        ("recovery-after-gateway-publish", True, False, False, True, False, False),
        (None, False, False, False, True, False, False),
        (None, True, True, False, True, False, False),
        (None, False, False, True, True, False, False),
        (None, True, False, False, False, False, False),
        (None, True, False, False, True, True, False),
        (None, True, False, False, True, False, True),
        ("repair-081-after-placeholder", True, False, False, True, False, False),
    ],
    ids=[
        "caught-failure-running-source",
        "sigkill-after-stop",
        "sigkill-after-target-gateway",
        "sigkill-during-migration-before-active-seal",
        "sigkill-during-migration-before-active-seal-stopped-source",
        "sigkill-after-active-manifest-publish",
        "sigkill-after-live-bridge-health",
        "sigkill-after-state-restore",
        "sigkill-after-state-restore-absent-openclaw",
        "legacy-target-exits-after-start",
        "sigkill-recovery-after-gateway-displace",
        "sigkill-recovery-after-gateway-publish",
        "caught-failure-stopped-source",
        "unrelated-live-pid-refusal",
        "orphan-health-refusal",
        "absent-openclaw-home",
        "concurrent-state-divergence-preserved",
        "post-quarantine-write-preserved",
        "clean-081-placeholder-repair-failure-restores-flat-source",
    ],
)
def test_bridge_start_failure_restores_source_artifacts_state_and_health(
    tmp_path: Path,
    packaged_target_controller_python: Path,
    crash_point: str | None,
    source_running: bool,
    unrelated_pid: bool,
    orphan_health: bool,
    openclaw_present: bool,
    concurrent_divergence: bool,
    post_quarantine_write: bool,
) -> None:
    repair_081 = crash_point == "repair-081-after-placeholder"
    target_exits_early = crash_point == "target-exits-after-start"
    source_version = "0.8.1" if repair_081 else "0.8.3"
    target_version = "0.8.5" if repair_081 else "0.8.4"
    resolver_script = UPGRADE_SCRIPT
    if target_exits_early:
        resolver_source = UPGRADE_SCRIPT.read_text(encoding="utf-8")
        assert resolver_source.count("\nHEALTH_TIMEOUT=60\n") == 1
        resolver_script = tmp_path / "upgrade-short-readiness-timeout.sh"
        resolver_script.write_text(
            resolver_source.replace("\nHEALTH_TIMEOUT=60\n", "\nHEALTH_TIMEOUT=2\n"),
            encoding="utf-8",
        )
        resolver_script.chmod(0o755)
    bridge_install_failure = (
        crash_point is None
        and source_running
        and not unrelated_pid
        and not orphan_health
        and openclaw_present
        and not concurrent_divergence
        and not post_quarantine_write
    )
    fixtures = tmp_path / "fixtures"
    fake_bin = tmp_path / "fake-bin"
    home = tmp_path / "home"
    controller_home = home / ".defenseclaw"
    data_home = tmp_path / "runtime-data"
    install_dir = home / ".local" / "bin"
    openclaw_home = home / ".openclaw"
    source_venv = controller_home / ".venv"
    event_log = tmp_path / "events.log"
    _make_bridge_assets(
        fixtures,
        live_gateway=crash_point
        in {
            "migration-after-config",
            "after-bridge-health",
            "target-exits-after-start",
        },
    )
    if repair_081:
        _make_hard_cut_contract_assets(fixtures)
    fake_bin.mkdir()
    source_venv.joinpath("bin").mkdir(parents=True)
    data_home.mkdir()
    install_dir.mkdir(parents=True)
    if openclaw_present:
        openclaw_home.mkdir(parents=True)
        openclaw_home.chmod(0o700)
    home.chmod(0o700)
    controller_home.chmod(0o700)

    source_cli = source_venv / "bin" / "defenseclaw"
    _write_executable(
        source_cli,
        "#!/usr/bin/env bash\n"
        'if [[ "${1:-}" == "--version" ]]; then\n'
        "  if [[ \"${MUTATE_SOURCE_CLI_ON_VERSION:-0}\" == '1' "
        "&& \"${PYTHONDONTWRITEBYTECODE:-}\" != '1' ]]; then\n"
        f"    printf '%s\\n' probe >> {str(source_venv / 'version-probe-cache')!r}\n"
        "  fi\n"
        f"  printf '%s\\n' 'DefenseClaw {source_version}'\n"
        "  exit 0\n"
        "fi\n"
        "exit 91\n",
    )
    _write_executable(
        source_venv / "bin" / "python",
        "#!/usr/bin/env bash\n"
        'if [[ "$*" == *"from defenseclaw import __version__"* ]]; then '
        f"printf '%s\\n' '{source_version}'; exit 0; fi\n"
        f'exec {sys.executable!r} "$@"\n',
    )
    (install_dir / "defenseclaw").symlink_to(source_cli)

    source_gateway = install_dir / "defenseclaw-gateway"
    _compile_source_gateway(source_gateway, version=source_version)
    source_gateway_bytes = source_gateway.read_bytes()

    original = {
        ".env": b"TOKEN=source-secret\n",
        ".migration_state.json": b'{"schema":1,"applied":["0.8.0"]}\n',
        "codex_env.sh": b"export SOURCE_ONLY=1\n",
    }
    config_path = controller_home / "config.yaml"
    if repair_081:
        config_original = _flat_081_config(data_home).encode()
    else:
        config_original = f"config_version: 7\ndata_dir: {data_home}\ncustom: keep\n".encode()
    config_path.write_bytes(config_original)
    for name, content in original.items():
        (data_home / name).write_bytes(content)
    config_path.chmod(0o640)
    (data_home / ".env").chmod(0o644)
    data_home.chmod(0o700 if repair_081 else 0o755)
    policies = data_home / "policies"
    policies.mkdir()
    (policies / "operator.rego").write_bytes(b"package operator\n")
    hooks = data_home / "hooks"
    hooks.mkdir()
    (hooks / "source-hook.sh").write_bytes(b"#!/bin/sh\nexit 0\n")
    observability = data_home / "observability-stack"
    observability.mkdir()
    (observability / "source-compose.yaml").write_bytes(b"services: {}\n")
    openclaw_original = b'{"operator":"state"}\n'
    if openclaw_present:
        (openclaw_home / "openclaw.json").write_bytes(openclaw_original)

    initial_process: subprocess.Popen[bytes] | None = None

    post_bridge_081_config = tmp_path / "post-bridge-081.yaml"
    post_bridge_081_config.write_text(
        _named_081_config(data_home),
        encoding="utf-8",
    )
    target_python_template = tmp_path / "target-python"
    _write_executable(
        target_python_template,
        """#!/usr/bin/env bash
set -euo pipefail
if [[ "$*" == *"from defenseclaw import __version__"* ]]; then
  printf '%s\n' '0.8.4'
  exit 0
fi
if [[ "$*" == *"defenseclaw-legacy-readiness-v1"* ]]; then
  exec "${TARGET_RUNTIME_VENV_PYTHON:?}" "$@"
fi
if [[ "${1:-}" == '-I' && "${2:-}" == '-B' && "${3:-}" == '-' ]]; then
  exec "${TARGET_RUNTIME_PYTHON:?}" "$@"
fi
if [[ -n "${MIGRATION_FROM_VERSION:-}" ]]; then
  chmod 700 "${MIGRATION_DEFENSECLAW_HOME}"
  if [[ "${INJECT_081_NAMED_PLACEHOLDER:-0}" == '1' ]]; then
    cp "${POST_BRIDGE_081_CONFIG}" "${DEFENSECLAW_CONFIG}"
  else
    printf '%s\n' 'config_version: 7' 'bridge: mutated' > "${DEFENSECLAW_CONFIG}"
  fi
  printf '%s\n' 'target-backup' > "${DEFENSECLAW_CONFIG}.pre-observability-migration.bak"
  printf '%s\n' 'target-lock' > "${DEFENSECLAW_CONFIG}.lock"
  printf '%s\n' 'target-fixed-temp' > "${DEFENSECLAW_CONFIG}.tmp-f3395"
  if [[ "${DEFENSECLAW_TEST_PHASE1_MIGRATION_CRASH:-}" == 'after-config' ]]; then
    command_subshell_pid="${PPID}"
    upgrade_pid="$(ps -o ppid= -p "${command_subshell_pid}" | tr -d ' ')"
    kill -KILL "${upgrade_pid}"
    kill -KILL "${command_subshell_pid}" 2>/dev/null || true
    kill -KILL "$$"
  fi
  config_dir="${DEFENSECLAW_CONFIG%/*}"
  config_base="${DEFENSECLAW_CONFIG##*/}"
  mkdir -p "${MIGRATION_OPENCLAW_HOME}"
  printf '%s\n' 'target-owned-temp' > "${config_dir}/.${config_base}.upgrade-${DEFENSECLAW_UPGRADE_MUTATION_TOKEN}.abc.tmp"
  printf '%s\n' 'target-cursor-temp' > "${MIGRATION_DEFENSECLAW_HOME}/.migration_state.upgrade-${DEFENSECLAW_UPGRADE_MUTATION_TOKEN}.abc.tmp"
  printf '%s\n' 'target-openclaw-temp' > "${MIGRATION_OPENCLAW_HOME}/.tmp.upgrade-${DEFENSECLAW_UPGRADE_MUTATION_TOKEN}.abcopenclaw.json"
  printf '%s\n' 'bridge-secret' > "${MIGRATION_DEFENSECLAW_HOME}/.env"
  printf '%s\n' '{"schema":1,"applied":["0.8.4"]}' > "${MIGRATION_DEFENSECLAW_HOME}/.migration_state.json"
  rm -f "${MIGRATION_DEFENSECLAW_HOME}/codex_env.sh"
  rm -rf "${MIGRATION_DEFENSECLAW_HOME}/policies"
  rm -rf "${MIGRATION_DEFENSECLAW_HOME}/hooks"
  rm -rf "${MIGRATION_DEFENSECLAW_HOME}/observability-stack"
  printf '%s\n' 'created-by-bridge' > "${MIGRATION_DEFENSECLAW_HOME}/active_connector.json"
  printf '%s\n' '{"bridge":"mutated"}' > "${MIGRATION_OPENCLAW_HOME}/openclaw.json"
  printf '%s\n' '0'
  exit 0
fi
if [[ "${1:-}" == '-' ]]; then
  exec "${TARGET_RUNTIME_PYTHON:?}" "$@"
fi
if [[ -n "${MIGRATION_DEFENSECLAW_HOME:-}" ]]; then
  exit 0
fi
printf '%s\n' "${TARGET_HEALTH_URL:-http://127.0.0.1:18970/health}"
""",
    )
    target_cli_template = tmp_path / "target-cli"
    _write_executable(
        target_cli_template,
        "#!/usr/bin/env bash\n"
        "if [[ \"${1:-}\" == \"--version\" ]]; then printf '%s\\n' 'DefenseClaw 0.8.4'; exit 0; fi\n"
        "exit 92\n",
    )

    _write_executable(
        fake_bin / "uv",
        """#!/usr/bin/env bash
set -euo pipefail
venv=''
previous=''
for arg in "$@"; do
  if [[ "${previous}" == 'venv' ]]; then venv="${arg}"; break; fi
  previous="${arg}"
done
if [[ "$*" == *"pip install"* ]]; then
  wheel="${!#}"
  wheel_name="${wheel##*/}"
  if [[ ! "${wheel_name}" =~ ^defenseclaw-[0-9]+\\.[0-9]+\\.[0-9]+(-[0-9]+)?-py3-none-any\\.whl$ ]]; then
    printf 'invalid wheel filename: %s\n' "${wheel_name}" >&2
    exit 88
  fi
  if [[ "${FAIL_BRIDGE_WHEEL_INSTALL:-0}" == '1' && "${wheel}" == */backups/* ]]; then
    exit 89
  fi
fi
if [[ -n "${venv}" ]]; then
  mkdir -p "${venv}/bin"
  cp "${TARGET_PYTHON_TEMPLATE}" "${venv}/bin/python"
  cp "${TARGET_CLI_TEMPLATE}" "${venv}/bin/defenseclaw"
  if [[ "${venv}" == */target-controller-venv ]]; then
    sed 's/0\\.8\\.4/0.8.5/g' "${venv}/bin/python" > "${venv}/bin/python.final"
    sed 's/0\\.8\\.4/0.8.5/g' "${venv}/bin/defenseclaw" > "${venv}/bin/defenseclaw.final"
    mv "${venv}/bin/python.final" "${venv}/bin/python"
    mv "${venv}/bin/defenseclaw.final" "${venv}/bin/defenseclaw"
  fi
  chmod 755 "${venv}/bin/python" "${venv}/bin/defenseclaw"
fi
exit 0
""",
    )
    _write_executable(fake_bin / "cosign", "#!/usr/bin/env bash\nexit 0\n")
    _write_executable(fake_bin / "openclaw", "#!/usr/bin/env bash\nexit 0\n")
    _write_executable(
        fake_bin / "curl",
        """#!/usr/bin/env bash
set -euo pipefail
out=''
url=''
want_out=0
is_head=0
for arg in "$@"; do
  if [[ "${want_out}" -eq 1 ]]; then out="${arg}"; want_out=0; continue; fi
  case "${arg}" in
    -o) want_out=1 ;;
    --head) is_head=1 ;;
    http*) url="${arg}" ;;
  esac
done
if [[ "${url}" == http://127.0.0.1:*/health ]]; then
  if [[ "${FORCE_ORPHAN_HEALTH:-0}" == '1' ]]; then
    printf '%s\n' '{"api":{"state":"running"},"gateway":{"state":"starting"},"provenance":{"binary_version":"0.8.3"}}' > "${out}"
    printf '200'
    exit 0
  fi
  pid=''
  if [[ -f "${DEFENSECLAW_HOME}/gateway.pid" ]]; then
    pid="$(python3 - "${DEFENSECLAW_HOME}/gateway.pid" <<'PY' 2>/dev/null || true
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    payload = json.load(stream)
print(payload["pid"])
PY
)"
  fi
  if [[ "${pid}" =~ ^[1-9][0-9]*$ ]] && kill -0 "${pid}" 2>/dev/null; then
    gateway_version="$("${HOME}/.local/bin/defenseclaw-gateway" --version \
      | grep -oE '[0-9]+\\.[0-9]+\\.[0-9]+' | head -1)"
    if [[ "${gateway_version}" == '0.8.4' \
          && -n "${TARGET_HEALTH_URL:-}" \
          && "${url}" != "${TARGET_HEALTH_URL}" ]]; then
      : > "${out}"
      printf '000'
      exit 7
    fi
    printf '{"api":{"state":"running"},"gateway":{"state":"running"},"watcher":{"state":"disabled"},"guardrail":{"state":"disabled"},"telemetry":{"state":"running"},"provenance":{"binary_version":"%s"}}\n' \
      "${gateway_version}" > "${out}"
    printf '200'
  else
    : > "${out}"
    printf '000'
    exit 7
  fi
  exit 0
fi
if [[ "${is_head}" -eq 1 ]]; then printf '200'; exit 0; fi
case "${url}" in
  */releases/download/0.8.4/*) version='0.8.4' ;;
  */releases/download/0.8.5/*) version='0.8.5' ;;
  *) exit 96 ;;
esac
name="${url##*/}"
cp "${FIXTURE_ROOT}/${version}/${name}" "${out}"
""",
    )

    env = os.environ.copy()
    env.update(
        {
            "PATH": f"{install_dir}:{fake_bin}:{env['PATH']}",
            "HOME": str(home),
            "DEFENSECLAW_HOME": str(controller_home),
            "OPENCLAW_HOME": str(openclaw_home),
            "FIXTURE_ROOT": str(fixtures),
            "TARGET_PYTHON_TEMPLATE": str(target_python_template),
            "TARGET_CLI_TEMPLATE": str(target_cli_template),
            "TARGET_RUNTIME_PYTHON": sys.executable,
            "TARGET_RUNTIME_VENV_PYTHON": str(packaged_target_controller_python),
            "POST_BRIDGE_081_CONFIG": str(post_bridge_081_config),
            "UPGRADE_EVENT_LOG": str(event_log),
            "DEFENSECLAW_GATEWAY_TOKEN": "phase-one-readiness-token",
        }
    )
    if repair_081:
        env["INJECT_081_NAMED_PLACEHOLDER"] = "1"
        env["DEFENSECLAW_TEST_FAIL_AFTER_081_PLACEHOLDER_REPAIR"] = "1"
    if orphan_health:
        env["FORCE_ORPHAN_HEALTH"] = "1"
    if concurrent_divergence:
        env["INJECT_CONCURRENT_PHASE1_STATE"] = "1"
    if post_quarantine_write:
        env["INJECT_POST_QUARANTINE_WRITE"] = "1"
    if bridge_install_failure:
        env["FAIL_BRIDGE_WHEEL_INSTALL"] = "1"
        env["MUTATE_SOURCE_CLI_ON_VERSION"] = "1"
    if crash_point == "migration-after-config":
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", 0))
            target_status_port = int(probe.getsockname()[1])
        env["ALLOW_TARGET_GATEWAY_START"] = "1"
        env["TARGET_STATUS_PORT"] = str(target_status_port)
        env["TARGET_HEALTH_URL"] = f"http://127.0.0.1:{target_status_port}/health"
    if target_exits_early:
        env["ALLOW_TARGET_GATEWAY_START"] = "1"
        env["TARGET_GATEWAY_EXIT_AFTER_START"] = "1"

    initial_was_alive_before_cleanup = False
    result: subprocess.CompletedProcess[str] | None = None
    try:
        if source_running:
            command = ["sleep", "300"] if unrelated_pid else [str(source_gateway), "__daemon"]
            initial_process = subprocess.Popen(command)
            _write_json_pid(
                data_home / "gateway.pid",
                initial_process.pid,
                source_gateway,
            )

        if crash_point is not None and not repair_081 and not target_exits_early:
            if crash_point == "after-stop":
                crash_variable = "INJECT_PHASE1_CRASH_AFTER_SOURCE_STOP"
                env[crash_variable] = "1"
            elif crash_point == "seal-after-active-manifest":
                crash_variable = "DEFENSECLAW_TEST_PHASE1_ACTIVE_SEAL_CRASH"
                env[crash_variable] = "after-active-manifest"
            elif crash_point == "migration-after-config":
                crash_variable = "DEFENSECLAW_TEST_PHASE1_MIGRATION_CRASH"
                env[crash_variable] = "after-config"
            elif crash_point == "after-bridge-health":
                crash_variable = "DEFENSECLAW_TEST_PHASE1_POST_HEALTH_CRASH"
                env[crash_variable] = "after-health"
            elif crash_point == "rollback-after-state-restore":
                crash_variable = "DEFENSECLAW_TEST_PHASE1_ROLLBACK_CRASH"
                env[crash_variable] = "after-state-restore"
            else:
                crash_variable = "INJECT_PHASE1_CRASH_ON_TARGET_VERSION"
                env[crash_variable] = "1"
            if crash_point == "migration-after-config":
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                        probe.bind(("127.0.0.1", target_status_port))
                except OSError as exc:
                    pytest.fail(
                        f"target status port {target_status_port} was claimed before the upgrade fixture started: {exc}"
                    )
            interrupted = subprocess.run(
                ["bash", str(resolver_script), "--yes", "--version", target_version],
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
                timeout=60,
                check=False,
            )
            assert interrupted.returncode in {-9, 137}, interrupted.stdout + interrupted.stderr
            journal = controller_home / ".upgrade-recovery" / "phase-one-active.json"
            assert journal.is_file()
            assert stat.S_IMODE(journal.stat().st_mode) == 0o600
            journal_payload = json.loads(journal.read_text(encoding="utf-8"))
            assert journal_payload["source_health_url"] == "http://127.0.0.1:18970/health"
            assert journal_payload["state_snapshot_ready"] is (crash_point != "after-stop")
            assert journal_payload["active_snapshot_ready"] is (
                crash_point in {"after-bridge-health", "rollback-after-state-restore"}
            )
            assert journal_payload["state_mutation_started"] is (
                crash_point
                not in {
                    "after-stop",
                    "after-target-gateway",
                    "recovery-after-gateway-displace",
                    "recovery-after-gateway-publish",
                }
            )
            if crash_point == "seal-after-active-manifest":
                assert (
                    controller_home
                    / "backups"
                    / journal_payload["backup_directory"]
                    / "phase1-state"
                    / "active-manifest.json"
                ).is_file()
            env.pop(crash_variable)
            blocked = subprocess.run(
                ["bash", str(resolver_script), "--yes", "--version", target_version],
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
                timeout=60,
                check=False,
            )
            blocked_output = blocked.stdout + blocked.stderr
            if crash_point == "migration-after-config":
                assert blocked.returncode == 0, blocked_output
                assert "Recovering Interrupted Bridge Upgrade" in blocked_output
                assert "Recovered the interrupted phase-one release" in blocked_output
                assert "Source 0.8.3 artifacts and state restored" not in blocked_output
                assert not journal.exists()
                result = blocked
            elif crash_point in {
                "seal-after-active-manifest",
                "after-bridge-health",
                "rollback-after-state-restore",
            }:
                assert blocked.returncode == 1, blocked_output
                assert "Recovering Interrupted Bridge Upgrade" in blocked_output
                assert "Source 0.8.3 artifacts and state restored" in blocked_output
                assert not journal.exists()
                result = blocked
            else:
                assert blocked.returncode == 1, blocked_output
                assert "surviving mutation child is still active" in blocked_output
                assert journal.is_file()
                time.sleep(4.5)

            if crash_point.startswith("recovery-"):
                recovery_point = crash_point.removeprefix("recovery-")
                env["DEFENSECLAW_TEST_PHASE1_RECOVERY_CRASH"] = recovery_point
                recovery_crash = subprocess.run(
                    ["bash", str(resolver_script), "--yes", "--version", target_version],
                    cwd=ROOT,
                    env=env,
                    text=True,
                    capture_output=True,
                    timeout=60,
                    check=False,
                )
                assert recovery_crash.returncode != 0
                assert journal.is_file()
                env.pop("DEFENSECLAW_TEST_PHASE1_RECOVERY_CRASH")

        if result is None:
            result = subprocess.run(
                ["bash", str(resolver_script), "--yes", "--version", target_version],
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
                timeout=60,
                check=False,
            )
    finally:
        if initial_process is not None:
            initial_was_alive_before_cleanup = initial_process.poll() is None
            initial_process.terminate()
            initial_process.wait(timeout=10)

    assert result is not None

    if crash_point == "migration-after-config":
        try:
            output = result.stdout + result.stderr
            assert result.returncode == 0, output
            assert "Recovering Interrupted Bridge Upgrade" in output
            assert "Recovered the interrupted phase-one release" in output
            assert config_path.read_bytes() == b"config_version: 7\nbridge: mutated\n"
            assert not (controller_home / ".upgrade-recovery" / "phase-one-active.json").exists()
            assert (
                subprocess.check_output(
                    [str(install_dir / "defenseclaw-gateway"), "--version"],
                    text=True,
                    timeout=10,
                )
                .strip()
                .endswith("0.8.4")
            )
            assert (
                subprocess.check_output(
                    [str(install_dir / "defenseclaw"), "--version"],
                    text=True,
                    timeout=10,
                )
                .strip()
                .endswith("0.8.4")
            )
        finally:
            cleanup_env = env | {
                "DEFENSECLAW_HOME": str(data_home),
                "DEFENSECLAW_CONFIG": str(config_path),
                "OPENCLAW_HOME": str(openclaw_home),
            }
            subprocess.run(
                [str(install_dir / "defenseclaw-gateway"), "stop"],
                env=cleanup_env,
                capture_output=True,
                check=False,
                timeout=10,
            )
        return

    if unrelated_pid:
        output = result.stdout + result.stderr
        assert result.returncode == 1, output
        assert "PID custody is invalid or identifies an unrelated process" in output
        assert not event_log.exists() or "source-stop" not in event_log.read_text(encoding="utf-8")
        assert initial_was_alive_before_cleanup
        assert not (controller_home / ".upgrade-recovery" / "phase-one-active.json").exists()
        assert (install_dir / "defenseclaw-gateway").read_bytes() == source_gateway_bytes
        return

    if orphan_health:
        output = result.stdout + result.stderr
        assert result.returncode == 1, output
        assert "not proven unreachable (starting) without verified live PID custody" in output
        assert not event_log.exists() or "source-stop" not in event_log.read_text(encoding="utf-8")
        assert not (controller_home / ".upgrade-recovery" / "phase-one-active.json").exists()
        assert (install_dir / "defenseclaw-gateway").read_bytes() == source_gateway_bytes
        return

    if concurrent_divergence:
        output = result.stdout + result.stderr
        assert result.returncode != 0, output
        assert "preserved without overwrite" in output
        assert config_path.read_bytes() == b"concurrent-user-config\n"
        assert (data_home / "hooks" / "concurrent-user.txt").read_bytes() == (b"concurrent-user-hook\n")
        assert (
            subprocess.check_output(
                [str(install_dir / "defenseclaw-gateway"), "--version"],
                text=True,
                timeout=10,
            )
            .strip()
            .endswith("0.8.4")
        )
        assert (
            subprocess.check_output(
                [str(install_dir / "defenseclaw"), "--version"],
                text=True,
                timeout=10,
            )
            .strip()
            .endswith("0.8.4")
        )
        assert (controller_home / ".upgrade-recovery" / "phase-one-active.json").is_file()
        return

    restored_pid: int | None = None
    try:
        if source_running:
            restored_pid = int(json.loads((data_home / "gateway.pid").read_text(encoding="utf-8"))["pid"])
    except (OSError, ValueError):
        pass
    try:
        output = result.stdout + result.stderr
        assert result.returncode == 1, output
        if repair_081:
            assert "injected failure after 0.8.1 placeholder repair" in output
            assert "Restoring Source After Bridge Failure" in output
            assert "Source 0.8.1 artifacts and state restored" in output
            assert config_path.read_bytes() == config_original
            assert (install_dir / "defenseclaw-gateway").read_bytes() == source_gateway_bytes
            assert (
                subprocess.check_output(
                    [str(install_dir / "defenseclaw"), "--version"],
                    text=True,
                    timeout=10,
                )
                .strip()
                .endswith("0.8.1")
            )
            assert not (controller_home / ".upgrade-recovery" / "phase-one-active.json").exists()
            return
        if bridge_install_failure:
            assert "Failed to install the bridge CLI wheel" in output
            assert "Source 0.8.3 artifacts and state restored" in output
            assert "restored source venv identity changed" not in output
            assert not (controller_home / ".upgrade-recovery" / "phase-one-active.json").exists()
            assert (install_dir / "defenseclaw-gateway").read_bytes() == source_gateway_bytes
            assert config_path.read_bytes() == config_original
            events = event_log.read_text(encoding="utf-8")
            assert "source-stop" in events
            assert "source-start" in events
            assert "target-start" not in events
            assert restored_pid is not None
            os.kill(restored_pid, 0)
            return
        if crash_point is not None and not repair_081 and not target_exits_early:
            assert "Recovering Interrupted Bridge Upgrade" in output
            assert "before detecting installed versions" in output
            assert not (controller_home / ".upgrade-recovery" / "phase-one-active.json").exists()
        if target_exits_early:
            assert "Gateway failed authenticated legacy target readiness" in output
        else:
            assert "Could not start gateway" in output
        assert "Restoring Source After Bridge Failure" in output
        assert "Source 0.8.3 artifacts and state restored" in output
        assert (install_dir / "defenseclaw-gateway").read_bytes() == source_gateway_bytes
        assert (
            subprocess.check_output(
                [str(install_dir / "defenseclaw"), "--version"],
                text=True,
                timeout=10,
            )
            .strip()
            .endswith("0.8.3")
        )
        for name, content in original.items():
            assert (data_home / name).read_bytes() == content
        assert config_path.read_bytes() == config_original
        assert not Path(f"{config_path}.pre-observability-migration.bak").exists()
        assert not Path(f"{config_path}.lock").exists()
        assert not Path(f"{config_path}.tmp-f3395").exists()
        assert not list(config_path.parent.glob(".config.yaml.upgrade-*.tmp"))
        assert not list(data_home.glob(".migration_state.upgrade-*.tmp"))
        assert not list(openclaw_home.glob(".tmp.upgrade-*"))
        assert stat.S_IMODE(data_home.stat().st_mode) == 0o755
        assert stat.S_IMODE(config_path.stat().st_mode) == 0o640
        assert stat.S_IMODE((data_home / ".env").stat().st_mode) == 0o644
        backup_directories = list((controller_home / "backups").glob("upgrade-*-*"))
        assert len(backup_directories) == (
            2 if crash_point is not None and not repair_081 and not target_exits_early else 1
        )
        for backup_directory in backup_directories:
            assert not backup_directory.is_symlink()
            assert stat.S_IMODE(backup_directory.stat().st_mode) == 0o700
        data_custody_roots = list(data_home.glob(".defenseclaw-phase-one-custody-*"))
        assert data_custody_roots
        for custody_root in data_custody_roots:
            assert not custody_root.is_symlink()
            assert stat.S_IMODE(custody_root.stat().st_mode) == 0o700
        assert any(list(custody_root.glob("*-.env")) for custody_root in data_custody_roots)
        if post_quarantine_write:
            custody_roots = list(config_path.parent.glob(".defenseclaw-phase-one-custody-*"))
            assert len(custody_roots) == 1
            assert not custody_roots[0].is_symlink()
            assert stat.S_IMODE(custody_roots[0].stat().st_mode) == 0o700
            retained_configs = list(custody_roots[0].glob("0-config.yaml"))
            assert len(retained_configs) == 1
            deadline = time.monotonic() + 5
            expected_retained = b"config_version: 7\nbridge: mutated\npost-quarantine-user-write\n"
            while retained_configs[0].read_bytes() != expected_retained and time.monotonic() < deadline:
                time.sleep(0.05)
            assert retained_configs[0].read_bytes() == (expected_retained)
            assert not list(config_path.parent.glob(".config.yaml.phase-one-quarantine-*-0"))
            retained_index = backup_directories[0] / "phase1-state" / "retained-quarantines.json"
            retained_payload = json.loads(retained_index.read_text(encoding="utf-8"))
            assert str(retained_configs[0]) in retained_payload["paths"]
        assert (policies / "operator.rego").read_bytes() == b"package operator\n"
        assert (hooks / "source-hook.sh").read_bytes() == b"#!/bin/sh\nexit 0\n"
        assert (observability / "source-compose.yaml").read_bytes() == b"services: {}\n"
        assert not (data_home / "active_connector.json").exists()
        if openclaw_present:
            assert (openclaw_home / "openclaw.json").read_bytes() == openclaw_original
        else:
            assert not openclaw_home.exists()
        events = event_log.read_text(encoding="utf-8")
        assert "source-stop" in events
        assert "target-start" in events

        if source_running:
            assert "source-start" in events
            assert restored_pid is not None
            os.kill(restored_pid, 0)
        else:
            assert restored_pid is None
            assert not (data_home / "gateway.pid").exists()
            assert "source-start" not in event_log.read_text(encoding="utf-8")
    finally:
        if restored_pid is not None:
            try:
                os.kill(restored_pid, 15)
            except ProcessLookupError:
                pass


@POSIX_UPGRADE_RUNTIME_ONLY
@pytest.mark.parametrize(
    ("shape", "accepted"),
    (
        ("historical-placeholder", True),
        ("configured", True),
        ("malformed", False),
    ),
)
def test_clean_081_observability_preflight_rejects_malformed_state_before_mutation(
    tmp_path: Path,
    packaged_target_controller_python: Path,
    shape: str,
    accepted: bool,
) -> None:
    data_home = tmp_path / "data"
    data_home.mkdir()
    config_path = tmp_path / "config.yaml"
    source = _flat_081_config(data_home)
    if shape == "configured":
        source = source.replace(
            "  endpoint: ''\n",
            "  endpoint: https://collector.example\n",
            1,
        )
    elif shape == "malformed":
        source = source.replace("  endpoint: ''\n", "  endpoint: 17\n", 1)
    config_path.write_text(source, encoding="utf-8")

    script = UPGRADE_SCRIPT.read_text(encoding="utf-8")
    start = script.index("preflight_081_observability_source() {")
    end = script.index("\nrepair_clean_081_observability_placeholder() {", start)
    call = script.index(
        "\n        preflight_081_observability_source \\\n",
        end,
    )
    mutation_lock = script.index("\nensure_upgrade_lock_before_mutation\n", call)
    assert call < mutation_lock

    harness = tmp_path / "preflight-harness.sh"
    _write_executable(
        harness,
        "#!/usr/bin/env bash\nset -euo pipefail\n"
        + script[start:end]
        + "\nok() { :; }\n"
        + "\nCURRENT_VERSION=0.8.1\n"
        + "RELEASE_VERSION=0.8.4\n"
        + "STAGED_FINAL_VERSION=0.8.5\n"
        + "OBSERVABILITY_V8_HARD_CUT_VERSION=0.8.5\n"
        + f"TARGET_CONTROLLER_VENV={str(packaged_target_controller_python.parent.parent)!r}\n"
        + f"CONFIG_PATH={str(config_path)!r}\n"
        + f"DATA_DIR={str(data_home)!r}\n"
        + "preflight_081_observability_source\n",
    )
    result = subprocess.run(
        ["bash", str(harness)],
        cwd=ROOT,
        env={
            name: value
            for name, value in os.environ.items()
            if not name.startswith(("OTEL_", "DEFENSECLAW_OTEL_", "OPENCLAW_OTEL_"))
        },
        text=True,
        capture_output=True,
        check=False,
        timeout=60,
    )

    assert (result.returncode == 0) is accepted, result.stdout + result.stderr
    assert config_path.read_text(encoding="utf-8") == source


@POSIX_UPGRADE_RUNTIME_ONLY
@pytest.mark.parametrize(
    ("shape", "expected"),
    (
        ("historical-placeholder", "repaired"),
        ("configured", "preserved"),
        ("malformed", "rejected"),
        ("ambiguous-pre-bridge", "rejected"),
    ),
)
def test_clean_081_observability_classifier_repairs_only_historical_placeholder(
    tmp_path: Path,
    packaged_target_controller_python: Path,
    shape: str,
    expected: str,
) -> None:
    data_home = tmp_path / "data"
    data_home.mkdir()
    config_path = tmp_path / "config.yaml"
    if shape == "ambiguous-pre-bridge":
        source = _flat_081_config(data_home)
    else:
        source = _named_081_config(data_home)
        if shape == "configured":
            source = source.replace("      endpoint: ''\n", "      endpoint: https://collector.example\n", 1)
        elif shape == "malformed":
            source = source.replace("      endpoint: ''\n", "      endpoint: 17\n", 1)
    config_path.write_text(source, encoding="utf-8")

    script = UPGRADE_SCRIPT.read_text(encoding="utf-8")
    start = script.index("repair_clean_081_observability_placeholder() {")
    end = script.index("\ncomplete_bridge_phase1_recovery_journal() {", start)
    harness = tmp_path / "repair-harness.sh"
    _write_executable(
        harness,
        "#!/usr/bin/env bash\nset -euo pipefail\n"
        + script[start:end]
        + "\nok() { :; }\n"
        + "\nBRIDGE_PHASE1=1\n"
        + "CURRENT_VERSION=0.8.1\n"
        + "RELEASE_VERSION=0.8.4\n"
        + "STAGED_FINAL_VERSION=0.8.5\n"
        + "OBSERVABILITY_V8_HARD_CUT_VERSION=0.8.5\n"
        + f"TARGET_CONTROLLER_VENV={str(packaged_target_controller_python.parent.parent)!r}\n"
        + f"CONFIG_PATH={str(config_path)!r}\n"
        + f"DATA_DIR={str(data_home)!r}\n"
        + (
            "OBSERVABILITY_081_SOURCE_CLASSIFICATION=historical-placeholder\n"
            if shape == "historical-placeholder"
            else "OBSERVABILITY_081_SOURCE_CLASSIFICATION=configured\n"
        )
        + "repair_clean_081_observability_placeholder\n",
    )
    env = {
        name: value
        for name, value in os.environ.items()
        if not (
            name.startswith(("OTEL_", "DEFENSECLAW_OTEL_", "OPENCLAW_OTEL_"))
            or name
            in {
                "DEFENSECLAW_DISABLE_REDACTION",
                "DEFENSECLAW_JSONL_DISABLE",
                "DEFENSECLAW_PERSIST_JUDGE",
                "OTEL_SERVICE_NAME",
            }
        )
    }

    result = subprocess.run(
        ["bash", str(harness)],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
        timeout=60,
    )

    if expected == "repaired":
        assert result.returncode == 0, result.stdout + result.stderr
        repaired = yaml.safe_load(config_path.read_text(encoding="utf-8"))
        assert "destinations" not in repaired["otel"]
        assert set(repaired["otel"]) == {"enabled", "traces", "logs", "resource"}
    elif expected == "preserved":
        assert result.returncode == 0, result.stdout + result.stderr
        assert config_path.read_text(encoding="utf-8") == source
    else:
        assert result.returncode != 0
        assert config_path.read_text(encoding="utf-8") == source


def test_bridge_rollback_health_is_version_bound_and_custody_is_collision_safe() -> None:
    script = UPGRADE_SCRIPT.read_text(encoding="utf-8")
    health_observation = script[
        script.index("bridge_source_health_observation()") : script.index("prepare_bridge_phase1_custody()")
    ]
    rollback_health = script[
        script.index("bridge_source_health_check()") : script.index("bridge_phase1_gateway_quiesced()")
    ]
    assert 'provenance.get("binary_version", "missing")' in health_observation
    assert "bridge_source_health_observation" in rollback_health
    assert '"${version}" == "${CURRENT_VERSION}"' in rollback_health
    backup_setup = script[script.index("TIMESTAMP=$(date") : script.index("# ── Stop services")]
    assert "tempfile.mkdtemp" in backup_setup
    assert "parent_stat.st_uid != os.geteuid()" in backup_setup
    assert "stat.S_IMODE(parent_stat.st_mode) & 0o022" in backup_setup
    assert "os.lstat(root)" in backup_setup
    assert "stat.S_ISLNK(root_stat.st_mode)" in backup_setup
    assert "root_stat.st_uid != os.geteuid()" in backup_setup
    interpreter_start = script.index('BRIDGE_PYTHON_INTERPRETER="$')
    interpreter_setup = script[interpreter_start : script.index('preflight_venv="${STAGING_DIR}', interpreter_start)]
    assert 'getattr(sys, "_base_executable", "")' in interpreter_setup
    assert "os.path.commonpath" in interpreter_setup
    extraction = script.index('tar -xzf "${STAGING_DIR}/${MATERIALIZED_TARBALL_NAME}"')
    codesign_start = script.index('if [[ "${OS}" == "darwin" ]]', extraction)
    codesign_block = script[codesign_start : script.index('ok "Gateway binary downloaded"', codesign_start)]
    assert "/usr/bin/codesign -f -s - -i com.cisco.defenseclaw.gateway" in codesign_block
    assert "no services changed" in codesign_block
    assert "|| true" not in codesign_block
    assert codesign_start < script.index('section "Stopping Services"', codesign_start)
    assert '"bridge_gateway_sha256"' in script
    assert '"bridge_wheel_sha256"' in script
    assert ".defenseclaw-phase-one-owner.json" in script
    assert "active phase-one venv is not owned by this recovery plan" in script
    assert "refusing to execute or overwrite an unrecognized phase-one gateway activation" in script
    assert "shutil.rmtree(active_venv)" not in script
    assert 'rm -rf "${DEFENSECLAW_VENV}"' not in script
    assert "phase1-bridge-wheel.whl" not in script
    assert 'f"defenseclaw-{bridge_version}-2-py3-none-any.whl"' in script
    assert "f\"defenseclaw-{payload['bridge_version']}-2-py3-none-any.whl\"" in script
    assert 'BRIDGE_WHEEL_CUSTODY_PATH="${BACKUP_DIR}/${whl_name}"' in script
    assert 'PYTHONDONTWRITEBYTECODE=1 "${DEFENSECLAW_VENV}/bin/defenseclaw"' in script
    assert 'probe_environment["PYTHONDONTWRITEBYTECODE"] = "1"' in script


@POSIX_UPGRADE_RUNTIME_ONLY
@pytest.mark.parametrize("live_gateway", (False, True), ids=("shell", "compiled"))
def test_legacy_bridge_fixture_rejects_unknown_gateway_commands(
    tmp_path: Path,
    live_gateway: bool,
) -> None:
    _make_bridge_assets(tmp_path, live_gateway=live_gateway)
    gateway = tmp_path / "0.8.4" / "gateway"

    result = subprocess.run(
        [str(gateway), "upgrade-wait-ready", "--help"],
        env=os.environ | {"DEFENSECLAW_HOME": str(tmp_path)},
        text=True,
        capture_output=True,
        check=False,
        timeout=10,
    )

    assert result.returncode == 64, result.stdout + result.stderr


@POSIX_UPGRADE_RUNTIME_ONLY
def test_gateway_pid_parser_accepts_legacy_integer_with_live_binary_identity(tmp_path: Path) -> None:
    gateway = tmp_path / "defenseclaw-gateway"
    _compile_source_gateway(gateway)
    process: subprocess.Popen[bytes] | None = None
    try:
        process = subprocess.Popen([str(gateway), "__daemon"])
        pid_file = tmp_path / "gateway.pid"
        pid_file.write_text(f"{process.pid}\n", encoding="utf-8")
        pid_file.chmod(0o600)

        script = UPGRADE_SCRIPT.read_text(encoding="utf-8")
        match = re.search(
            r"GATEWAY_PID_PARSER=\"\$\(cat <<'PY'\n(?P<source>.*?)\nPY\n\)\"",
            script,
            re.DOTALL,
        )
        assert match is not None
        result = subprocess.run(
            [sys.executable, "-c", match.group("source"), str(pid_file), str(gateway)],
            text=True,
            capture_output=True,
            timeout=15,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == f"live\t{process.pid}"
    finally:
        if process is not None:
            process.terminate()
            process.wait(timeout=10)


@POSIX_UPGRADE_RUNTIME_ONLY
def test_source_venv_identity_rejects_same_version_substitution(tmp_path: Path) -> None:
    script = UPGRADE_SCRIPT.read_text(encoding="utf-8")
    match = re.search(
        r'VENV_IDENTITY_PARSER="\$\(cat <<\'PY\'\n(?P<source>.*?)\nPY\n\)"',
        script,
        re.DOTALL,
    )
    assert match is not None
    namespace: dict[str, object] = {"__name__": "phase_one_venv_identity_test"}
    exec(match.group("source"), namespace)
    identity = namespace["venv_identity"]

    source = tmp_path / "source-venv"
    substitute = tmp_path / "substitute-venv"
    for root, marker in ((source, "source"), (substitute, "substitute")):
        _write_executable(
            root / "bin" / "defenseclaw",
            f"#!/usr/bin/env bash\nprintf '%s\\n' 'DefenseClaw 0.8.3'\n# {marker}\n",
        )
        _write_executable(root / "bin" / "python", "#!/usr/bin/env bash\nexit 0\n")

    assert callable(identity)
    assert identity(str(source)) != identity(str(substitute))


@POSIX_UPGRADE_RUNTIME_ONLY
def test_path_shadow_cli_is_refused_before_service_stop(tmp_path: Path) -> None:
    home = tmp_path / "home"
    controller = home / ".defenseclaw"
    data = tmp_path / "data"
    openclaw = tmp_path / "openclaw"
    install = home / ".local" / "bin"
    shadow = tmp_path / "shadow"
    for directory in (controller / ".venv" / "bin", data, openclaw, install, shadow):
        directory.mkdir(parents=True, exist_ok=True)
    _write_executable(
        controller / ".venv" / "bin" / "python",
        "#!/usr/bin/env bash\n"
        'if [[ "$*" == *"from defenseclaw import __version__"* ]]; then '
        "printf '%s\\n' '0.8.3'; exit 0; fi\n"
        f'exec {sys.executable!r} "$@"\n',
    )
    _write_executable(
        controller / ".venv" / "bin" / "defenseclaw",
        "#!/usr/bin/env bash\nprintf '%s\\n' 'DefenseClaw 0.8.3'\n",
    )
    _write_executable(
        shadow / "defenseclaw",
        "#!/usr/bin/env bash\nprintf '%s\\n' 'DefenseClaw 0.8.3'\n",
    )
    _compile_source_gateway(install / "defenseclaw-gateway")
    (controller / "config.yaml").write_text(
        f"config_version: 7\ndata_dir: {data}\n",
        encoding="utf-8",
    )
    event_log = tmp_path / "events.log"
    env = os.environ.copy()
    env.update(
        {
            "HOME": str(home),
            "DEFENSECLAW_HOME": str(controller),
            "OPENCLAW_HOME": str(openclaw),
            "PATH": f"{shadow}:{install}:{env['PATH']}",
            "UPGRADE_EVENT_LOG": str(event_log),
        }
    )

    result = subprocess.run(
        ["bash", str(UPGRADE_SCRIPT), "--yes", "--version", "0.8.4"],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )

    output = result.stdout + result.stderr
    assert result.returncode == 1
    assert "PATH resolves defenseclaw outside the canonical controller-home venv" in output
    assert not event_log.exists()
