# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import time
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
UPGRADE_SCRIPT = ROOT / "scripts" / "upgrade.sh"


def _write_executable(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)


def _process_start_identity(pid: int) -> str:
    if sys.platform.startswith("linux"):
        payload = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
        return payload[payload.rfind(")") + 1 :].split()[19]
    if sys.platform == "darwin":
        return subprocess.check_output(
            ["/bin/ps", "-p", str(pid), "-o", "lstart="],
            text=True,
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


def _compile_source_gateway(path: Path) -> None:
    compiler = shutil.which("cc")
    if compiler is None:
        pytest.skip("a C compiler is required for phase-one PID-custody tests")
    source = path.with_suffix(".c")
    source.write_text(
        r'''
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
''',
        encoding="utf-8",
    )
    subprocess.run(
        [compiler, "-std=c99", "-D_POSIX_C_SOURCE=200809L", str(source), "-o", str(path)],
        check=True,
        capture_output=True,
        text=True,
    )
    path.chmod(0o755)


def _compile_live_bridge_gateway(path: Path) -> None:
    compiler = shutil.which("cc")
    if compiler is None:
        pytest.skip("a C compiler is required for phase-one PID-custody tests")
    source = path.with_suffix(".c")
    source.write_text(
        r'''
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

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "__daemon") == 0) {
        for (;;) pause();
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
    return 0;
}
''',
        encoding="utf-8",
    )
    subprocess.run(
        [compiler, "-std=c99", "-D_POSIX_C_SOURCE=200809L", str(source), "-o", str(path)],
        check=True,
        capture_output=True,
        text=True,
    )
    path.chmod(0o755)


def _platform_asset_name(version: str) -> str:
    os_name = platform.system().lower()
    machine = platform.machine().lower()
    arch = "arm64" if machine in {"arm64", "aarch64"} else "amd64"
    return f"defenseclaw_{version}_protocol2_{os_name}_{arch}.dcgateway"


def _protect_artifact(payload: bytes) -> bytes:
    return b"DEFENSECLAW-PROTECTED-ARTIFACT-V1\n" + bytes(
        value ^ 0xA5 for value in payload
    )


def _make_bridge_assets(root: Path, *, live_gateway: bool = False) -> None:
    version = "0.8.4"
    release = root / version
    release.mkdir(parents=True)
    gateways = {
        platform_name: {
            arch: f"defenseclaw_{version}_protocol2_{platform_name}_{arch}.dcgateway"
            for arch in ("amd64", "arm64")
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
        "tested_source_versions": ["0.8.3", "0.4.0"],
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
        ("recovery-after-gateway-displace", True, False, False, True, False, False),
        ("recovery-after-gateway-publish", True, False, False, True, False, False),
        (None, False, False, False, True, False, False),
        (None, True, True, False, True, False, False),
        (None, False, False, True, True, False, False),
        (None, True, False, False, False, False, False),
        (None, True, False, False, True, True, False),
        (None, True, False, False, True, False, True),
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
        "sigkill-recovery-after-gateway-displace",
        "sigkill-recovery-after-gateway-publish",
        "caught-failure-stopped-source",
        "unrelated-live-pid-refusal",
        "orphan-health-refusal",
        "absent-openclaw-home",
        "concurrent-state-divergence-preserved",
        "post-quarantine-write-preserved",
    ],
)
def test_bridge_start_failure_restores_source_artifacts_state_and_health(
    tmp_path: Path,
    crash_point: str | None,
    source_running: bool,
    unrelated_pid: bool,
    orphan_health: bool,
    openclaw_present: bool,
    concurrent_divergence: bool,
    post_quarantine_write: bool,
) -> None:
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
        live_gateway=crash_point in {"migration-after-config", "after-bridge-health"},
    )
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
        "if [[ \"${1:-}\" == \"--version\" ]]; then\n"
        "  if [[ \"${MUTATE_SOURCE_CLI_ON_VERSION:-0}\" == '1' "
        "&& \"${PYTHONDONTWRITEBYTECODE:-}\" != '1' ]]; then\n"
        f"    printf '%s\\n' probe >> {str(source_venv / 'version-probe-cache')!r}\n"
        "  fi\n"
        "  printf '%s\\n' 'DefenseClaw 0.8.3'\n"
        "  exit 0\n"
        "fi\n"
        "exit 91\n",
    )
    _write_executable(
        source_venv / "bin" / "python",
        "#!/usr/bin/env bash\n"
        "if [[ \"$*\" == *\"from defenseclaw import __version__\"* ]]; then "
        "printf '%s\\n' '0.8.3'; exit 0; fi\n"
        f"exec {sys.executable!r} \"$@\"\n",
    )
    (install_dir / "defenseclaw").symlink_to(source_cli)

    source_gateway = install_dir / "defenseclaw-gateway"
    _compile_source_gateway(source_gateway)
    source_gateway_bytes = source_gateway.read_bytes()

    original = {
        ".env": b"TOKEN=source-secret\n",
        ".migration_state.json": b'{"schema":1,"applied":["0.8.0"]}\n',
        "codex_env.sh": b"export SOURCE_ONLY=1\n",
    }
    config_path = controller_home / "config.yaml"
    config_original = f"config_version: 7\ndata_dir: {data_home}\ncustom: keep\n".encode()
    config_path.write_bytes(config_original)
    for name, content in original.items():
        (data_home / name).write_bytes(content)
    config_path.chmod(0o640)
    (data_home / ".env").chmod(0o644)
    data_home.chmod(0o755)
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

    target_python_template = tmp_path / "target-python"
    _write_executable(
        target_python_template,
        """#!/usr/bin/env bash
set -euo pipefail
if [[ "$*" == *"from defenseclaw import __version__"* ]]; then
  printf '%s\n' '0.8.4'
  exit 0
fi
if [[ "${1:-}" == '-I' && "${2:-}" == '-B' && "${3:-}" == '-' ]]; then
  exec "${TARGET_RUNTIME_PYTHON:?}" "$@"
fi
if [[ -n "${MIGRATION_FROM_VERSION:-}" ]]; then
  chmod 700 "${MIGRATION_DEFENSECLAW_HOME}"
  printf '%s\n' 'config_version: 7' 'bridge: mutated' > "${DEFENSECLAW_CONFIG}"
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
    printf '%s\n' '{"gateway":{"state":"starting"},"provenance":{"binary_version":"0.8.3"}}' > "${out}"
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
    printf '{"gateway":{"state":"running"},"provenance":{"binary_version":"%s"}}\n' \
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
version='0.8.4'
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
            "UPGRADE_EVENT_LOG": str(event_log),
        }
    )
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
        env["ALLOW_TARGET_GATEWAY_START"] = "1"
        env["TARGET_HEALTH_URL"] = "http://127.0.0.1:18971/health"

    initial_was_alive_before_cleanup = False
    result: subprocess.CompletedProcess[str] | None = None
    try:
        if source_running:
            command = (
                ["sleep", "300"]
                if unrelated_pid
                else [str(source_gateway), "__daemon"]
            )
            initial_process = subprocess.Popen(command)
            _write_json_pid(
                data_home / "gateway.pid",
                initial_process.pid,
                source_gateway,
            )

        if crash_point is not None:
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
            interrupted = subprocess.run(
                ["bash", str(UPGRADE_SCRIPT), "--yes", "--version", "0.8.4"],
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
            assert journal_payload["state_snapshot_ready"] is (
                crash_point != "after-stop"
            )
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
                ["bash", str(UPGRADE_SCRIPT), "--yes", "--version", "0.8.4"],
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
                    ["bash", str(UPGRADE_SCRIPT), "--yes", "--version", "0.8.4"],
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
                ["bash", str(UPGRADE_SCRIPT), "--yes", "--version", "0.8.4"],
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
            assert not (
                controller_home / ".upgrade-recovery" / "phase-one-active.json"
            ).exists()
            assert subprocess.check_output(
                [str(install_dir / "defenseclaw-gateway"), "--version"], text=True
            ).strip().endswith("0.8.4")
            assert subprocess.check_output(
                [str(install_dir / "defenseclaw"), "--version"], text=True
            ).strip().endswith("0.8.4")
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
        assert (data_home / "hooks" / "concurrent-user.txt").read_bytes() == (
            b"concurrent-user-hook\n"
        )
        assert subprocess.check_output(
            [str(install_dir / "defenseclaw-gateway"), "--version"], text=True
        ).strip().endswith("0.8.4")
        assert subprocess.check_output(
            [str(install_dir / "defenseclaw"), "--version"], text=True
        ).strip().endswith("0.8.4")
        assert (controller_home / ".upgrade-recovery" / "phase-one-active.json").is_file()
        return

    restored_pid: int | None = None
    try:
        if source_running:
            restored_pid = int(
                json.loads((data_home / "gateway.pid").read_text(encoding="utf-8"))["pid"]
            )
    except (OSError, ValueError):
        pass
    try:
        output = result.stdout + result.stderr
        assert result.returncode == 1, output
        if bridge_install_failure:
            assert "Failed to install the bridge CLI wheel" in output
            assert "Source 0.8.3 artifacts and state restored" in output
            assert "restored source venv identity changed" not in output
            assert not (
                controller_home / ".upgrade-recovery" / "phase-one-active.json"
            ).exists()
            assert (install_dir / "defenseclaw-gateway").read_bytes() == source_gateway_bytes
            assert config_path.read_bytes() == config_original
            events = event_log.read_text(encoding="utf-8")
            assert "source-stop" in events
            assert "source-start" in events
            assert "target-start" not in events
            assert restored_pid is not None
            os.kill(restored_pid, 0)
            return
        if crash_point is not None:
            assert "Recovering Interrupted Bridge Upgrade" in output
            assert "before detecting installed versions" in output
            assert not (controller_home / ".upgrade-recovery" / "phase-one-active.json").exists()
        assert "Could not start gateway" in output
        assert "Restoring Source After Bridge Failure" in output
        assert "Source 0.8.3 artifacts and state restored" in output
        assert (install_dir / "defenseclaw-gateway").read_bytes() == source_gateway_bytes
        assert subprocess.check_output(
            [str(install_dir / "defenseclaw"), "--version"], text=True
        ).strip().endswith("0.8.3")
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
        assert len(backup_directories) == (2 if crash_point is not None else 1)
        for backup_directory in backup_directories:
            assert not backup_directory.is_symlink()
            assert stat.S_IMODE(backup_directory.stat().st_mode) == 0o700
        data_custody_roots = list(
            data_home.glob(".defenseclaw-phase-one-custody-*")
        )
        assert data_custody_roots
        for custody_root in data_custody_roots:
            assert not custody_root.is_symlink()
            assert stat.S_IMODE(custody_root.stat().st_mode) == 0o700
        assert any(
            list(custody_root.glob("*-.env"))
            for custody_root in data_custody_roots
        )
        if post_quarantine_write:
            custody_roots = list(
                config_path.parent.glob(".defenseclaw-phase-one-custody-*")
            )
            assert len(custody_roots) == 1
            assert not custody_roots[0].is_symlink()
            assert stat.S_IMODE(custody_roots[0].stat().st_mode) == 0o700
            retained_configs = list(custody_roots[0].glob("0-config.yaml"))
            assert len(retained_configs) == 1
            deadline = time.monotonic() + 5
            expected_retained = b"config_version: 7\nbridge: mutated\npost-quarantine-user-write\n"
            while (
                retained_configs[0].read_bytes() != expected_retained
                and time.monotonic() < deadline
            ):
                time.sleep(0.05)
            assert retained_configs[0].read_bytes() == (
                expected_retained
            )
            assert not list(
                config_path.parent.glob(".config.yaml.phase-one-quarantine-*-0")
            )
            retained_index = (
                backup_directories[0]
                / "phase1-state"
                / "retained-quarantines.json"
            )
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


def test_bridge_rollback_health_is_version_bound_and_custody_is_collision_safe() -> None:
    script = UPGRADE_SCRIPT.read_text(encoding="utf-8")
    health_observation = script[
        script.index("bridge_source_health_observation()") : script.index(
            "prepare_bridge_phase1_custody()"
        )
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
    interpreter_setup = script[
        interpreter_start : script.index('preflight_venv="${STAGING_DIR}', interpreter_start)
    ]
    assert 'getattr(sys, "_base_executable", "")' in interpreter_setup
    assert "os.path.commonpath" in interpreter_setup
    extraction = script.index('tar -xzf "${STAGING_DIR}/${MATERIALIZED_TARBALL_NAME}"')
    codesign_start = script.index('if [[ "${OS}" == "darwin" ]]', extraction)
    codesign_block = script[codesign_start : script.index('ok "Gateway binary downloaded"', codesign_start)]
    assert (
        '/usr/bin/codesign -f -s - -i com.cisco.defenseclaw.gateway'
        in codesign_block
    )
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
    assert 'f"defenseclaw-{payload[\'bridge_version\']}-2-py3-none-any.whl"' in script
    assert 'BRIDGE_WHEEL_CUSTODY_PATH="${BACKUP_DIR}/${whl_name}"' in script
    assert 'PYTHONDONTWRITEBYTECODE=1 "${DEFENSECLAW_VENV}/bin/defenseclaw"' in script
    assert 'probe_environment["PYTHONDONTWRITEBYTECODE"] = "1"' in script


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
            "#!/usr/bin/env bash\nprintf '%s\\n' 'DefenseClaw 0.8.3'\n"
            f"# {marker}\n",
        )
        _write_executable(root / "bin" / "python", "#!/usr/bin/env bash\nexit 0\n")

    assert callable(identity)
    assert identity(str(source)) != identity(str(substitute))


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
        "if [[ \"$*\" == *\"from defenseclaw import __version__\"* ]]; then "
        "printf '%s\\n' '0.8.3'; exit 0; fi\n"
        f"exec {sys.executable!r} \"$@\"\n",
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
