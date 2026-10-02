# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""Contracts of scripts/install.sh and the 0.8.x handoff that must never break.

``defenseclaw upgrade`` from every installed 1.x release runs the newest
install.sh with ``--yes``/``--version``/``--local``/``--rollback``, and 0.8.8+
clients run defenseclaw-upgrade.sh with frozen expectations. These tests pin
those interfaces. End-to-end behaviour is covered by
scripts/test-install-lifecycle.sh.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from defenseclaw.tui.panels.first_run import CONNECTOR_CHOICES

ROOT = Path(__file__).resolve().parents[2]
INSTALL_SH = ROOT / "scripts" / "install.sh"
HANDOFF_SH = ROOT / "scripts" / "defenseclaw-upgrade.sh"
BASH = shutil.which("bash")

pytestmark = pytest.mark.skipif(os.name == "nt" or BASH is None, reason="POSIX installer")


def _stamped(tmp_path: Path, version: str = "1.0.0") -> Path:
    stamped = tmp_path / "install.sh"
    stamped.write_text(INSTALL_SH.read_text(encoding="utf-8").replace("__DEFENSECLAW_VERSION__", version))
    return stamped


def _run(args: list[str], tmp_path: Path, **env: str) -> subprocess.CompletedProcess[str]:
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    environment = {"HOME": str(home), "PATH": os.environ.get("PATH", "/usr/bin:/bin"), **env}
    return subprocess.run([BASH, *args], capture_output=True, text=True, env=environment, timeout=60, check=False)


def test_scripts_parse_under_bash() -> None:
    for script in (INSTALL_SH, HANDOFF_SH):
        subprocess.run([BASH, "-n", str(script)], check=True)


@pytest.mark.skipif(not Path("/bin/bash").exists(), reason="system bash")
def test_scripts_parse_under_system_bash() -> None:
    # macOS ships bash 3.2 as /bin/bash; the installer must stay compatible.
    for script in (INSTALL_SH, HANDOFF_SH):
        subprocess.run(["/bin/bash", "-n", str(script)], check=True)


def test_install_sh_runs_only_when_fully_downloaded() -> None:
    text = INSTALL_SH.read_text(encoding="utf-8")
    assert text.count('readonly DC_VERSION="__DEFENSECLAW_VERSION__"') == 1
    lines = [line for line in text.splitlines() if line.strip()]
    assert lines[-2:] == ['main "$@"', "# DefenseClaw POSIX installer complete v2"]
    assert text.index("main() {") < text.index('readonly DC_VERSION=')


def test_help_lists_the_permanent_flags(tmp_path: Path) -> None:
    result = _run([str(INSTALL_SH), "--help"], tmp_path)

    assert result.returncode == 0
    for flag in ("--yes", "--version X.Y.Z", "--local DIR", "--rollback"):
        assert flag in result.stdout


def test_unknown_flags_are_ignored_not_fatal(tmp_path: Path) -> None:
    empty = tmp_path / "assets"
    empty.mkdir()

    result = _run([str(_stamped(tmp_path)), "--local", str(empty), "--from-the-future"], tmp_path)

    assert "Ignoring unknown option: --from-the-future" in result.stdout + result.stderr
    assert "checksums.txt" in result.stdout + result.stderr  # got past argument parsing


def test_version_before_1_0_is_refused_without_network(tmp_path: Path) -> None:
    result = _run([str(_stamped(tmp_path)), "--version", "0.8.10"], tmp_path)

    assert result.returncode == 1
    assert "predates this installer" in result.stderr


def test_malformed_version_is_refused(tmp_path: Path) -> None:
    result = _run([str(_stamped(tmp_path)), "--version", "1.2"], tmp_path)

    assert result.returncode == 1
    assert "--version must look like 1.2.3" in result.stderr


def test_dependencies_install_from_the_hashed_lock_only() -> None:
    text = INSTALL_SH.read_text(encoding="utf-8")

    assert "export UV_NO_CONFIG=1" in text
    assert "--require-hashes --no-deps -r" in text
    assert re.search(r"uv pip install [^\n]*--no-deps \"\$\{STAGING\}/\$\{WHEEL\}\"", text)


def test_both_installers_refresh_agent_discovery_after_the_migration() -> None:
    # An upgrade starts without fresh discovery; the gateway records agent
    # versions in the hook contract lock from it, and doctor checks them.
    posix = INSTALL_SH.read_text(encoding="utf-8")
    windows = (ROOT / "scripts" / "install.ps1").read_text(encoding="utf-8")
    posix_refresh = posix.index("agent discover --refresh --no-emit-otel")
    windows_refresh = windows.index('@("agent", "discover", "--refresh", "--no-emit-otel")')
    assert posix.rindex("migrate --yes", 0, posix_refresh) > 0
    assert windows.rindex('@("migrate", "--yes")', 0, windows_refresh) > 0


def test_windows_process_listing_survives_a_wmi_refusal() -> None:
    # WMI refuses a standard user signed in over SSH; an upgrade must still
    # find this account's own processes.
    windows = (ROOT / "scripts" / "install.ps1").read_text(encoding="utf-8")
    body = windows[windows.index("function Get-ProcessesUnder") :]
    body = body[: body.index("\n}\n")]
    assert "try { @(Get-CimInstance Win32_Process -ErrorAction Stop) } catch {" in body
    assert "Get-Process" in body


def test_installer_never_uses_retired_asset_names() -> None:
    text = INSTALL_SH.read_text(encoding="utf-8")

    for retired in (".dcwheel", ".dcgateway", "upgrade-manifest.json", "release-provenance.json", "defenseclaw_"):
        assert retired not in text


def test_intel_macos_is_refused_before_changes() -> None:
    text = INSTALL_SH.read_text(encoding="utf-8")

    assert "sysctl.proc_translated" in text
    assert "Intel macOS (${MACHINE}) is unsupported" in text


def test_connector_choices_track_the_cli() -> None:
    match = re.search(r'readonly CONNECTOR_CHOICES="([^"]*)"', INSTALL_SH.read_text(encoding="utf-8"))
    assert match is not None
    assert tuple(match.group(1).split()) == (*CONNECTOR_CHOICES, "none")


def test_openclaw_restart_requires_the_openclaw_connector() -> None:
    text = INSTALL_SH.read_text(encoding="utf-8")

    assert 'openclaw_connector_active && has openclaw' in text


def _release(tmp_path: Path, script: str) -> Path:
    release = tmp_path / "release"
    release.mkdir()
    (release / "install.sh").write_text(script, encoding="utf-8")
    digest = hashlib.sha256(script.encode()).hexdigest()
    (release / "checksums.txt").write_text(f"{digest}  install.sh\n", encoding="utf-8")
    return release


def test_handoff_keeps_the_frozen_0_8_x_contract() -> None:
    text = HANDOFF_SH.read_text(encoding="utf-8")

    assert text.splitlines()[-1] == "# DefenseClaw upgrade resolver complete v1"
    assert len(text.encode()) < 4 * 1024 * 1024
    assert "unset DEFENSECLAW_UPGRADE_FRESH_PROCESS" in text


def test_handoff_runs_the_verified_installer_with_yes(tmp_path: Path) -> None:
    release = _release(tmp_path, '#!/bin/bash\necho "installer args: $*"; echo "fresh=${DEFENSECLAW_UPGRADE_FRESH_PROCESS:-unset}"\n')

    result = _run(
        [str(HANDOFF_SH), "--yes", "--recover-corrupt-audit", "--version", "1.0.0"],
        tmp_path,
        DEFENSECLAW_UPGRADE_LOCAL_DIR=str(release),
        DEFENSECLAW_UPGRADE_FRESH_PROCESS="1",
    )

    assert result.returncode == 0, result.stderr
    assert f"installer args: --yes --local {release}" in result.stdout
    assert "fresh=unset" in result.stdout
    assert "corrupt audit store is moved aside" in result.stderr
    assert "ignoring unsupported option" not in result.stderr


def test_handoff_refuses_an_installer_that_does_not_match(tmp_path: Path) -> None:
    release = _release(tmp_path, "#!/bin/bash\necho ran\n")
    (release / "install.sh").write_text("#!/bin/bash\necho tampered\n", encoding="utf-8")

    result = _run([str(HANDOFF_SH), "--yes"], tmp_path, DEFENSECLAW_UPGRADE_LOCAL_DIR=str(release))

    assert result.returncode == 1
    assert "tampered" not in result.stdout
    assert "does not match checksums.txt" in result.stderr


def test_handoff_plan_changes_nothing(tmp_path: Path) -> None:
    release = _release(tmp_path, "#!/bin/bash\necho ran\n")

    result = _run([str(HANDOFF_SH), "--plan"], tmp_path, DEFENSECLAW_UPGRADE_LOCAL_DIR=str(release))

    assert result.returncode == 0
    assert "would upgrade" in result.stdout
    assert "ran" not in result.stdout


def test_downloads_under_a_staging_name_are_checked_by_their_release_name() -> None:
    # checksums.txt lists release asset names; a file saved under another name
    # must pass the asset name to verify, or the lookup finds nothing.
    text = INSTALL_SH.read_text(encoding="utf-8")
    for call in re.findall(r"^\s*verify (.+)$", text, flags=re.MULTILINE):
        args = call.split()
        if not args[0].startswith('"${STAGING}/'):
            assert len(args) == 2, f"verify {call} needs the release asset name"


def test_both_installers_bootstrap_the_same_pinned_uv() -> None:
    posix = (ROOT / "scripts" / "install.sh").read_text(encoding="utf-8")
    windows = (ROOT / "scripts" / "install.ps1").read_text(encoding="utf-8")
    posix_version = re.search(r'readonly UV_VERSION="([0-9.]+)"', posix)
    windows_version = re.search(r'\$UvVersion = "([0-9.]+)"', windows)
    assert posix_version and windows_version
    assert posix_version.group(1) == windows_version.group(1)
    # The unpinned astral.sh installer script must never come back.
    assert "astral.sh/uv/install" not in posix and "astral.sh/uv/install" not in windows
    digests = dict(re.findall(r"^\s+(uv-[a-z0-9_-]+\.tar\.gz)\) echo ([0-9a-f]{64}) ;;$", posix, re.M))
    assert set(digests) == {
        "uv-aarch64-apple-darwin.tar.gz",
        "uv-x86_64-unknown-linux-musl.tar.gz",
        "uv-aarch64-unknown-linux-musl.tar.gz",
    }
    assert re.search(r'\$UvZipSha256 = "[0-9a-f]{64}"', windows)


def test_sandbox_flag_is_a_deprecated_no_op() -> None:
    """--sandbox keeps parsing for old automation but installs nothing.

    The legacy openshell-sandbox installer was removed; the flag must never
    fetch or execute a sandbox installer again, nor pass the flag on to
    another release's installer.
    """
    text = INSTALL_SH.read_text(encoding="utf-8")
    assert "--sandbox) INSTALL_SANDBOX=true ;;" in text
    assert "PASSTHROUGH+=(--sandbox)" not in text
    assert "install-openshell-sandbox.sh" not in text
    assert "install_openshell_sandbox" not in text
    assert "SANDBOX_INSTALLER_ASSET_START_VERSION" not in text
    notice = text.index('if [[ "${INSTALL_SANDBOX}" == true ]]; then')
    assert "--sandbox is deprecated and ignored" in text[notice : notice + 600]
    assert "defenseclaw sandbox legacy-cleanup --dry-run" in text[notice : notice + 600]
    # OpenShell 0.1 sandboxes ship: the notice points at their setup.
    assert "run 'defenseclaw sandbox setup'" in text[notice : notice + 600]
    assert "being rebuilt" not in text


def test_legacy_sandbox_installer_asset_is_an_inert_stub(tmp_path: Path) -> None:
    """Cached installers from earlier releases still download this asset."""
    stub = ROOT / "scripts" / "install-openshell-sandbox.sh"
    payload = stub.read_bytes()
    assert payload.splitlines()[-1] == b"# DefenseClaw OpenShell sandbox installer complete v1"
    text = payload.decode("utf-8")
    for forbidden in ("curl", "wget", "sudo", "tar ", "install -m", "chmod", "ghcr.io"):
        assert forbidden not in text, forbidden
    completed = subprocess.run(
        [BASH, stub.as_posix(), "--install-dir", (tmp_path / "bin").as_posix()],
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "legacy openshell-sandbox (0.0.x) installer has been removed" in completed.stderr
    assert "defenseclaw sandbox legacy-cleanup" in completed.stderr
    assert "defenseclaw sandbox setup" in completed.stderr
    assert "once available" not in completed.stderr
    assert not (tmp_path / "bin").exists()


def test_a_failed_first_run_quickstart_keeps_the_install_and_exits_4(tmp_path: Path) -> None:
    text = INSTALL_SH.read_text(encoding="utf-8")
    start = text.index("first_install_extras() {")
    extras = text[start : text.index("\n}\n", start) + 3]
    venv_bin = tmp_path / "venv" / "bin"
    venv_bin.mkdir(parents=True)
    (venv_bin / "defenseclaw").write_text("#!/bin/sh\nexit 7\n", encoding="utf-8")
    (venv_bin / "defenseclaw").chmod(0o755)
    script = tmp_path / "extras.sh"
    script.write_text(
        "set -euo pipefail\nwarn() { :; }\n"
        + extras
        + 'CONNECTOR=codex RUN_QUICKSTART=true QUICKSTART_MODE=action QUICKSTART_RC=0 QUICKSTART_RERUN=""\n'
        + f'DEFENSECLAW_HOME="{tmp_path}" VENV="{tmp_path / "venv"}" BIN_DIR="{venv_bin}"\n'
        + 'first_install_extras\nprintf "%s|%s\\n" "${QUICKSTART_RC}" "${QUICKSTART_RERUN}"\n',
        encoding="utf-8",
    )

    completed = _run([str(script)], tmp_path)

    assert completed.returncode == 0, completed.stdout + completed.stderr
    rerun = "defenseclaw quickstart --non-interactive --yes --connector codex --mode action"
    assert completed.stdout.strip() == f"7|{rerun}"
    summary = text[text.index('if [[ -n "${QUICKSTART_RERUN}" ]]; then') :]
    assert summary.index("exit 4") < summary.index("exit ${START_RC}")


def test_a_carriage_return_answer_takes_the_default(tmp_path: Path) -> None:
    # MAC-U3-01: a terminal left in -icrnl sends Enter as a bare CR, which
    # used to read as "no" and cancel the install.
    text = INSTALL_SH.read_text(encoding="utf-8")
    start = text.index("read_tty_line() {")
    funcs = text[start : text.index("\n}\n", text.index("ask_yes_no() {")) + 3]
    tty = tmp_path / "tty"
    tty.write_bytes(b"\r\n")
    script = tmp_path / "ask.sh"
    script.write_text(
        "set -euo pipefail\nYES=false\n"
        + funcs.replace("/dev/tty", str(tty))
        + 'if ask_yes_no "Reinstall?"; then echo yes; else echo no; fi\n',
        encoding="utf-8",
    )
    proc = subprocess.run(["bash", str(script)], capture_output=True, text=True, check=False)
    assert proc.stdout.strip() == "yes", proc.stdout + proc.stderr


def test_path_hint_uses_the_callers_path_not_the_uv_bootstrap_path(tmp_path: Path) -> None:
    # SWEEP-18: installing uv puts BIN_DIR on this process's PATH, which hid
    # the hint on a fresh macOS zsh account whose shell PATH lacks it.
    text = INSTALL_SH.read_text(encoding="utf-8")
    start = text.index("ensure_path_hint() {")
    func = text[start : text.index("\n}\n", start) + 3]
    bin_dir = tmp_path / "home" / ".local" / "bin"
    script = tmp_path / "hint.sh"
    script.write_text(
        "set -euo pipefail\nCYAN=; NC=\n"
        f"BIN_DIR={bin_dir}\nCALLER_PATH=/usr/bin:/bin\n"
        'export PATH="${BIN_DIR}:${PATH}"\n' + func + "ensure_path_hint\n",
        encoding="utf-8",
    )
    env = {**os.environ, "SHELL": "/bin/zsh", "HOME": str(tmp_path / "home")}
    proc = subprocess.run(["bash", str(script)], capture_output=True, text=True, check=False, env=env)
    assert proc.returncode == 0, proc.stderr
    assert "Add DefenseClaw to your PATH" in proc.stdout
    assert ".zshrc" in proc.stdout


def test_a_gateway_that_refuses_to_start_says_why(tmp_path: Path) -> None:
    # MAC-U2-01: after a rollback, the restored 0.8.x gateway refused to start
    # on hook contract drift, and the installer only relayed a readiness timeout.
    text = INSTALL_SH.read_text(encoding="utf-8")
    start = text.index("start_gateway() {")
    funcs = text[start : text.index("\n}\n", text.index("explain_start_failure() {")) + 3]
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (tmp_path / "gateway.log").write_text("Error: an older failure\n", encoding="utf-8")
    gateway = bin_dir / "defenseclaw-gateway"
    gateway.write_text(
        "#!/bin/sh\n"
        f"echo '[sidecar] guardrail exited with error: connector claudecode hook contract drift detected: "
        f'previous version="2.1.276 (Claude Code)" contract=v1 current version="2.1.286 (Claude Code)" contract=v1 '
        f"(rerun discovery/setup to refresh the lock, or set DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT=1 for exploratory testing)' >> '{tmp_path}/gateway.log'\n"
        "exit 1\n",
        encoding="utf-8",
    )
    gateway.chmod(0o755)
    script = tmp_path / "start.sh"
    script.write_text(
        'set -euo pipefail\ninfo() { echo "info: $*"; }\nwarn() { echo "warn: $*"; }\n'
        + funcs
        + f'DEFENSECLAW_HOME="{tmp_path}" BIN_DIR="{bin_dir}"\nrc=0; start_gateway || rc=$?; echo "rc=$rc"\n',
        encoding="utf-8",
    )

    completed = _run([str(script)], tmp_path)

    out = completed.stdout
    assert "rc=1" in out, out + completed.stderr
    assert "claudecode's agent changed (2.1.276 (Claude Code) -> 2.1.286 (Claude Code))" in out
    assert "DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT=1 defenseclaw-gateway start" in out
    assert "an older failure" not in out

    # MAC-U3-02: with a large audit database the restored gateway was still
    # starting when its start command timed out, and logged the drift later.
    (tmp_path / "gateway.log").write_text("", encoding="utf-8")
    pid_file = tmp_path / "gateway.pid"
    gateway.write_text(
        "#!/bin/sh\n"
        '[ "$1" = start ] || exit 1\n'
        "(sleep 4; echo '[sidecar] guardrail exited with error: connector codex hook contract drift detected'"
        f" >> '{tmp_path}/gateway.log') &\n"
        f"echo $! > '{pid_file}'\n"
        "exit 1\n",
        encoding="utf-8",
    )
    stub = f"gateway_pid() {{ kill -0 \"$(cat '{pid_file}')\" 2>/dev/null && cat '{pid_file}'; }}\n"
    script.write_text(script.read_text(encoding="utf-8").replace("rc=0; start_gateway", stub + "rc=0; start_gateway"))

    out = _run([str(script)], tmp_path).stdout

    assert "rc=1" in out, out
    assert "still starting" in out
    assert "The gateway refused to start: codex's agent changed" in out


def test_a_restored_0_8_gateway_is_launched_and_waited_for(tmp_path: Path) -> None:
    # GAP-1076, GAP-0012: a 0.8.x start stops the gateway it launched after
    # 60 seconds, so one restored on a large audit database never came up.
    text = INSTALL_SH.read_text(encoding="utf-8")
    start = text.index("start_gateway() {")
    funcs = text[start : text.index("\n}\n", text.index("explain_start_failure() {")) + 3]
    helpers = text[text.index("version_key() {") : text.index("is_version() {")]
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    pid_file, ready = tmp_path / "gateway.pid", tmp_path / "ready"
    gateway = bin_dir / "defenseclaw-gateway"
    gateway.write_text(
        "#!/bin/sh\n"
        'case "$1" in\n'
        "  --version) echo 'defenseclaw-gateway version 0.8.10' ;;\n"
        '  start) [ "${DEFENSECLAW_UPGRADE_FRESH_PROCESS:-}" = 1 ] || { echo FAILED; exit 1; }\n'
        f"    (sleep 2; touch '{ready}'; exec sleep 30) >/dev/null 2>&1 &\n"
        f"    echo $! > '{pid_file}'; echo LAUNCHED ;;\n"
        f"  status) [ -f '{ready}' ] ;;\n"
        "  *) exit 1 ;;\n"
        "esac\n",
        encoding="utf-8",
    )
    gateway.chmod(0o755)
    script = tmp_path / "start.sh"
    script.write_text(
        'set -euo pipefail\ninfo() { echo "info: $*"; }\nwarn() { echo "warn: $*"; }\nok() { echo "ok: $*"; }\n'
        + helpers
        + funcs
        + f"gateway_pid() {{ kill -0 \"$(cat '{pid_file}')\" 2>/dev/null && cat '{pid_file}'; }}\n"
        + f'DEFENSECLAW_HOME="{tmp_path}" BIN_DIR="{bin_dir}"\n'
        + f'rc=0; start_gateway || rc=$?; echo "rc=$rc"; kill "$(cat \'{pid_file}\')"\n',
        encoding="utf-8",
    )

    out = _run([str(script)], tmp_path).stdout

    assert "LAUNCHED" in out, out
    assert "ok: The gateway finished starting" in out
    assert "rc=0" in out


def test_a_rollback_whose_gateway_does_not_start_says_so_and_exits_1(tmp_path: Path) -> None:
    # GAP-1076: the restored gateway stayed down, yet the rollback printed a
    # green "Now running" and exited 0. GAP-1077: rolling forward was headed
    # "Rolling back".
    home = tmp_path / "home"
    dc_home, bin_dir = home / ".defenseclaw", home / ".local" / "bin"
    (dc_home / "previous" / "bin").mkdir(parents=True)
    bin_dir.mkdir(parents=True)
    for folder, version, start in ((bin_dir, "1.0.1", "exit 0"), (dc_home / "previous" / "bin", "0.8.10", "exit 1")):
        gateway = folder / "defenseclaw-gateway"
        gateway.write_text(
            f'#!/bin/sh\ncase "$1" in --version) echo "defenseclaw-gateway version {version}" ;; start) {start} ;; esac\n',
            encoding="utf-8",
        )
        gateway.chmod(0o755)
    (dc_home / "previous" / "VERSION").write_text("0.8.10\n", encoding="utf-8")
    (dc_home / "previous" / "GATEWAY_WAS_RUNNING").write_text("true\n", encoding="utf-8")
    script = _stamped(tmp_path, "1.0.1")
    env = {"DEFENSECLAW_APP_PATH": "none"}

    back = _run([str(script), "--rollback", "--yes"], tmp_path, **env)

    assert back.returncode == 1, back.stdout + back.stderr
    assert "Rolling back to DefenseClaw 0.8.10" in back.stdout
    assert "Now running DefenseClaw 0.8.10, but its gateway is not up" in back.stdout
    assert "✓ Now running" not in back.stdout

    forward = _run([str(script), "--rollback", "--yes"], tmp_path, **env)

    assert forward.returncode == 0, forward.stdout + forward.stderr
    assert "Rolling forward to DefenseClaw 1.0.1" in forward.stdout
    assert "Now running DefenseClaw 1.0.1." in forward.stdout


def test_a_rollback_copy_that_does_not_fit_says_how_much_to_free(tmp_path: Path) -> None:
    # RHEL-U3-02: the low-disk refusal named no sizes, no culprit and no next step.
    text = INSTALL_SH.read_text(encoding="utf-8")
    start = text.index("is_machinery() {")
    funcs = text[start : text.index("\n}\n", text.index("snapshot() {")) + 3]
    home = tmp_path / "home"
    home.mkdir()
    (home / "audit.db").write_bytes(b"x" * (3 * 1024 * 1024))
    bin_dir = tmp_path / "fake"
    bin_dir.mkdir()
    (bin_dir / "df").write_text("#!/bin/sh\necho head\necho fs 1 1 51200 1% /\n", encoding="utf-8")
    (bin_dir / "df").chmod(0o755)
    script = tmp_path / "snap.sh"
    script.write_text(
        'set -euo pipefail\nerr() { echo "err: $*"; }\n'
        + funcs
        + f'NOT_DATA="" DEFENSECLAW_HOME="{home}" SNAP="{tmp_path / "snap"}"\n'
        + f'PATH="{bin_dir}:$PATH"\nrc=0; snapshot || rc=$?; echo "rc=$rc"\n',
        encoding="utf-8",
    )

    out = _run([str(script)], tmp_path).stdout

    assert "rc=1" in out, out
    assert "needs about 103 MB" in out and "50 MB is free" in out
    assert f"{home}/audit.db (3 MB)" in out
    assert "Free at least 53 MB" in out


def test_windows_installer_leaves_unset_variables_unset() -> None:
    # pwsh 7 turns SetEnvironmentVariable(name, $null) into an empty value (WIN2-U2-08).
    text = (ROOT / "scripts" / "install.ps1").read_text(encoding="utf-8")
    restore = text[text.index("foreach ($name in $savedEnv.Keys)") :][:400]
    assert 'if ($null -eq $savedEnv[$name]) { Remove-Item -LiteralPath "Env:$name"' in restore


def test_both_installers_keep_uv_downloads_in_the_data_dir() -> None:
    # uv's cache and managed Python go below the data dir (kept by an upgrade,
    # removed by `uninstall --all`), never to ~/.cache/uv or %LOCALAPPDATA%\uv.
    posix = INSTALL_SH.read_text(encoding="utf-8")
    windows = (ROOT / "scripts" / "install.ps1").read_text(encoding="utf-8")
    assert 'UV_CACHE_DIR="${UV_CACHE_DIR:-${DEFENSECLAW_HOME}/.uv/cache}"' in posix
    assert 'UV_PYTHON_INSTALL_DIR="${UV_PYTHON_INSTALL_DIR:-${DEFENSECLAW_HOME}/.uv/python}"' in posix
    assert 'NOT_DATA=".venv .uv ' in posix
    assert '$env:UV_CACHE_DIR = Join-Path $DataDir ".uv\\cache"' in windows
    assert '$env:UV_PYTHON_INSTALL_DIR = Join-Path $DataDir ".uv\\python"' in windows
