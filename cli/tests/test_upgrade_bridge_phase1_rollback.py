# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
import json
import os
import platform
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


def _platform_asset_name(version: str) -> str:
    os_name = platform.system().lower()
    machine = platform.machine().lower()
    arch = "arm64" if machine in {"arm64", "aarch64"} else "amd64"
    return f"defenseclaw_{version}_{os_name}_{arch}.tar.gz"


def _make_bridge_assets(root: Path) -> None:
    version = "0.8.4"
    release = root / version
    release.mkdir(parents=True)
    manifest = {
        "schema_version": 1,
        "release_version": version,
        "controller_upgrade_protocol": 2,
        "min_upgrade_protocol": 1,
        "migration_failure_policy": "warn",
        "required_cli_migrations": [],
    }
    (release / "upgrade-manifest.json").write_text(
        json.dumps(manifest, sort_keys=True),
        encoding="utf-8",
    )

    wheel = release / f"defenseclaw-{version}-py3-none-any.whl"
    controller = (
        '_STAGED_BRIDGE_ARTIFACT_DIR_ENV = "DEFENSECLAW_STAGED_BRIDGE_ARTIFACT_DIR"\n'
        "def _prepare_hard_cut_rollback_plan(): pass\n"
        "def _execute_hard_cut_rollback(): pass\n"
        "_prepare_hard_cut_rollback_plan()\n"
    )
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("defenseclaw/commands/cmd_upgrade.py", controller)

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
      pid="$(cat "${DEFENSECLAW_HOME}/gateway.pid")"
      kill "${pid}" 2>/dev/null || true
      rm -f "${DEFENSECLAW_HOME}/gateway.pid"
    fi
    ;;
  start)
    printf '%s\n' 'target-start' >> "${UPGRADE_EVENT_LOG}"
    exit 42
    ;;
esac
""",
    )
    tarball = release / _platform_asset_name(version)
    with tarfile.open(tarball, "w:gz") as archive:
        info = archive.gettarinfo(str(gateway_source), arcname="defenseclaw")
        info.mode = 0o755
        with gateway_source.open("rb") as source_file:
            archive.addfile(info, source_file)

    checksum_lines = []
    for path in (release / "upgrade-manifest.json", wheel, tarball):
        checksum_lines.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}")
    (release / "checksums.txt").write_text("\n".join(checksum_lines) + "\n", encoding="utf-8")
    (release / "checksums.txt.sig").write_text("test signature\n", encoding="utf-8")
    (release / "checksums.txt.pem").write_text("test certificate\n", encoding="utf-8")


@pytest.mark.parametrize(
    "crash_point",
    [None, "after-stop", "after-target-gateway"],
    ids=["caught-failure", "sigkill-after-stop", "sigkill-after-target-gateway"],
)
def test_bridge_start_failure_restores_source_artifacts_state_and_health(
    tmp_path: Path,
    crash_point: str | None,
) -> None:
    fixtures = tmp_path / "fixtures"
    fake_bin = tmp_path / "fake-bin"
    home = tmp_path / "home"
    data_home = home / ".defenseclaw"
    install_dir = home / ".local" / "bin"
    openclaw_home = home / ".openclaw"
    source_venv = data_home / ".venv"
    event_log = tmp_path / "events.log"
    _make_bridge_assets(fixtures)
    fake_bin.mkdir()
    source_venv.joinpath("bin").mkdir(parents=True)
    install_dir.mkdir(parents=True)
    openclaw_home.mkdir(parents=True)

    source_cli = source_venv / "bin" / "defenseclaw"
    _write_executable(
        source_cli,
        "#!/usr/bin/env bash\n"
        "if [[ \"${1:-}\" == \"--version\" ]]; then printf '%s\\n' 'DefenseClaw 0.8.3'; exit 0; fi\n"
        "exit 91\n",
    )
    (source_venv / "bin" / "python").symlink_to(sys.executable)
    (install_dir / "defenseclaw").symlink_to(source_cli)

    source_gateway = install_dir / "defenseclaw-gateway"
    _write_executable(
        source_gateway,
        """#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  --version) printf '%s\n' 'DefenseClaw gateway 0.8.3' ;;
  stop)
    printf '%s\n' 'source-stop' >> "${UPGRADE_EVENT_LOG}"
    if [[ -f "${DEFENSECLAW_HOME}/gateway.pid" ]]; then
      pid="$(cat "${DEFENSECLAW_HOME}/gateway.pid")"
      kill "${pid}" 2>/dev/null || true
      rm -f "${DEFENSECLAW_HOME}/gateway.pid"
    fi
    if [[ "${INJECT_PHASE1_CRASH_AFTER_SOURCE_STOP:-}" == '1' ]]; then
      kill -KILL "${PPID}"
      exec >/dev/null 2>&1
      sleep 4
      exit 137
    fi
    ;;
  start)
    printf '%s\n' 'source-start' >> "${UPGRADE_EVENT_LOG}"
    sleep 300 &
    printf '%s\n' "$!" > "${DEFENSECLAW_HOME}/gateway.pid"
    ;;
esac
""",
    )
    source_gateway_bytes = source_gateway.read_bytes()

    original = {
        "config.yaml": b"config_version: 7\ncustom: keep\n",
        ".env": b"TOKEN=source-secret\n",
        ".migration_state.json": b'{"schema":1,"applied":["0.8.0"]}\n',
        "codex_env.sh": b"export SOURCE_ONLY=1\n",
    }
    for name, content in original.items():
        (data_home / name).write_bytes(content)
    (data_home / "config.yaml").chmod(0o640)
    (data_home / ".env").chmod(0o644)
    data_home.chmod(0o755)
    policies = data_home / "policies"
    policies.mkdir()
    (policies / "operator.rego").write_bytes(b"package operator\n")
    openclaw_original = b'{"operator":"state"}\n'
    (openclaw_home / "openclaw.json").write_bytes(openclaw_original)

    initial_process = subprocess.Popen(["sleep", "300"])
    (data_home / "gateway.pid").write_text(f"{initial_process.pid}\n", encoding="utf-8")

    target_python_template = tmp_path / "target-python"
    _write_executable(
        target_python_template,
        """#!/usr/bin/env bash
set -euo pipefail
if [[ "$*" == *"from defenseclaw import __version__"* ]]; then
  printf '%s\n' '0.8.4'
  exit 0
fi
if [[ -n "${MIGRATION_FROM_VERSION:-}" ]]; then
  chmod 700 "${MIGRATION_DEFENSECLAW_HOME}"
  printf '%s\n' 'bridge-mutated' > "${MIGRATION_DEFENSECLAW_HOME}/config.yaml"
  printf '%s\n' 'bridge-secret' > "${MIGRATION_DEFENSECLAW_HOME}/.env"
  printf '%s\n' '{"schema":1,"applied":["0.8.4"]}' > "${MIGRATION_DEFENSECLAW_HOME}/.migration_state.json"
  rm -f "${MIGRATION_DEFENSECLAW_HOME}/codex_env.sh"
  rm -rf "${MIGRATION_DEFENSECLAW_HOME}/policies"
  printf '%s\n' 'created-by-bridge' > "${MIGRATION_DEFENSECLAW_HOME}/active_connector.json"
  printf '%s\n' '{"bridge":"mutated"}' > "${MIGRATION_OPENCLAW_HOME}/openclaw.json"
  printf '%s\n' '0'
  exit 0
fi
if [[ -n "${MIGRATION_DEFENSECLAW_HOME:-}" ]]; then
  exit 0
fi
printf '%s\n' 'http://127.0.0.1:18970/health'
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
  printf '%s\n' '{"gateway":{"state":"running"},"provenance":{"binary_version":"0.8.3"}}' > "${out}"
  printf '200'
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
            "DEFENSECLAW_HOME": str(data_home),
            "OPENCLAW_HOME": str(openclaw_home),
            "FIXTURE_ROOT": str(fixtures),
            "TARGET_PYTHON_TEMPLATE": str(target_python_template),
            "TARGET_CLI_TEMPLATE": str(target_cli_template),
            "UPGRADE_EVENT_LOG": str(event_log),
        }
    )

    try:
        if crash_point is not None:
            crash_variable = (
                "INJECT_PHASE1_CRASH_AFTER_SOURCE_STOP"
                if crash_point == "after-stop"
                else "INJECT_PHASE1_CRASH_ON_TARGET_VERSION"
            )
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
            journal = data_home / ".upgrade-recovery" / "phase-one-active.json"
            assert journal.is_file()
            assert stat.S_IMODE(journal.stat().st_mode) == 0o600
            journal_payload = json.loads(journal.read_text(encoding="utf-8"))
            assert journal_payload["source_health_url"] == "http://127.0.0.1:18970/health"
            assert journal_payload["state_snapshot_ready"] is (
                crash_point == "after-target-gateway"
            )
            env.pop(crash_variable)
            blocked = subprocess.run(
                ["bash", str(UPGRADE_SCRIPT), "--yes", "--version", "0.8.4"],
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
                timeout=15,
                check=False,
            )
            blocked_output = blocked.stdout + blocked.stderr
            assert blocked.returncode == 1, blocked_output
            assert "surviving mutation child is still active" in blocked_output
            assert journal.is_file()
            time.sleep(4.5)

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
        initial_process.terminate()
        initial_process.wait(timeout=10)

    restored_pid: int | None = None
    try:
        output = result.stdout + result.stderr
        assert result.returncode == 1, output
        if crash_point is not None:
            assert "Recovering Interrupted Bridge Upgrade" in output
            assert "before detecting installed versions" in output
            assert not (data_home / ".upgrade-recovery" / "phase-one-active.json").exists()
        assert "Could not start gateway" in output
        assert "Restoring Source After Bridge Failure" in output
        assert "Source 0.8.3 artifacts and state restored" in output
        assert (install_dir / "defenseclaw-gateway").read_bytes() == source_gateway_bytes
        assert subprocess.check_output(
            [str(install_dir / "defenseclaw"), "--version"], text=True
        ).strip().endswith("0.8.3")
        for name, content in original.items():
            assert (data_home / name).read_bytes() == content
        assert stat.S_IMODE(data_home.stat().st_mode) == 0o755
        assert stat.S_IMODE((data_home / "config.yaml").stat().st_mode) == 0o640
        assert stat.S_IMODE((data_home / ".env").stat().st_mode) == 0o644
        backup_directories = list((data_home / "backups").glob("upgrade-*-*"))
        assert len(backup_directories) == (2 if crash_point is not None else 1)
        for backup_directory in backup_directories:
            assert not backup_directory.is_symlink()
            assert stat.S_IMODE(backup_directory.stat().st_mode) == 0o700
        assert (policies / "operator.rego").read_bytes() == b"package operator\n"
        assert not (data_home / "active_connector.json").exists()
        assert (openclaw_home / "openclaw.json").read_bytes() == openclaw_original
        events = event_log.read_text(encoding="utf-8")
        assert "source-stop" in events
        assert "target-start" in events
        assert "source-start" in events

        restored_pid = int((data_home / "gateway.pid").read_text(encoding="utf-8").strip())
        os.kill(restored_pid, 0)
    finally:
        if restored_pid is not None:
            try:
                os.kill(restored_pid, 15)
            except ProcessLookupError:
                pass


def test_bridge_rollback_health_is_version_bound_and_custody_is_collision_safe() -> None:
    script = UPGRADE_SCRIPT.read_text(encoding="utf-8")
    rollback_health = script[
        script.index("bridge_source_health_check()") : script.index("bridge_phase1_gateway_quiesced()")
    ]
    assert 'provenance.get("binary_version", "missing")' in rollback_health
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
