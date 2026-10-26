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
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest
from defenseclaw.tui.panels.first_run import CONNECTOR_CHOICES

ROOT = Path(__file__).resolve().parents[2]
INSTALL_SH = ROOT / "scripts" / "install.sh"
HANDOFF_SH = ROOT / "scripts" / "defenseclaw-upgrade.sh"
BASH = shutil.which("bash")

pytestmark = pytest.mark.skipif(os.name == "nt" or BASH is None, reason="POSIX installer")


def test_install_data_dir_refresh_shell_contract() -> None:
    """Run the real refresh and hold function regression, including custom data_dir."""
    result = subprocess.run(
        [BASH, str(ROOT / "scripts" / "test-install-data-dir-refresh.sh")],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def _stamped(tmp_path: Path, version: str = "1.0.0") -> Path:
    stamped = tmp_path / "install.sh"
    stamped.write_text(INSTALL_SH.read_text(encoding="utf-8").replace("__DEFENSECLAW_VERSION__", version))
    return stamped


def _run(args: list[str], tmp_path: Path, **env: str) -> subprocess.CompletedProcess[str]:
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    environment = {"HOME": str(home), "PATH": os.environ.get("PATH", "/usr/bin:/bin"), **env}
    return subprocess.run([BASH, *args], capture_output=True, text=True, env=environment, timeout=60, check=False)


def _run_rollback_with_no_agents(args: list[str], tmp_path: Path, **env: str) -> subprocess.CompletedProcess[str]:
    # The rollback fixtures model an account with closed agents. A shared CI
    # account may have an unrelated OpenCode process running beside this test.
    inventory = tmp_path / "process-inventory"
    inventory.mkdir(exist_ok=True)
    ps = inventory / "ps"
    real_ps = shutil.which("ps")
    assert real_ps is not None
    ps.write_text(
        '#!/bin/sh\n'
        'if [ "$#" -eq 8 ] && [ "$1" = -u ] && [ "$3" = -o ] && [ "$4" = pid= ] && '
        '[ "$5" = -o ] && [ "$6" = comm= ] && [ "$7" = -o ] && [ "$8" = args= ]; then exit 0; fi\n'
        f'exec "{real_ps}" "$@"\n',
        encoding="ascii",
    )
    ps.chmod(0o755)
    path = f"{inventory}:{env.pop('PATH', os.environ.get('PATH', '/usr/bin:/bin'))}"
    return _run(args, tmp_path, PATH=path, **env)


def test_scripts_parse_under_bash() -> None:
    for script in (INSTALL_SH, HANDOFF_SH):
        subprocess.run([BASH, "-n", str(script)], check=True)


def test_path_hint_is_copyable_with_spaced_home(tmp_path: Path) -> None:
    text = INSTALL_SH.read_text(encoding="utf-8")
    start = text.index("ensure_path_hint() {")
    function = text[start : text.index("\n}\n", start) + 3]
    home = tmp_path / "a home with spaces"
    home.mkdir()
    bin_dir = home / ".local" / "bin"
    result = subprocess.run(
        [BASH, "-c", 'HOME="$1"; BIN_DIR="$2"; CALLER_PATH=/usr/bin; SHELL=/bin/zsh; '
         "CYAN=; NC=; " + function + "\nensure_path_hint", "--", str(home), str(bin_dir)],
        capture_output=True, text=True, check=True,
    )
    command = next(line.strip() for line in result.stdout.splitlines() if line.strip().startswith("echo "))
    subprocess.run([BASH, "-c", command], check=True)
    assert (home / ".zshrc").read_text().strip() == f'export PATH="{bin_dir}:$PATH"'


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


def test_an_unknown_option_stops_and_value_options_take_the_equals_form(tmp_path: Path) -> None:
    # GAP-0361: a typo or the --name=value form was ignored with a warning,
    # so an unattended install went on without the option and exited 0.
    empty = tmp_path / "assets"
    empty.mkdir()
    script = _stamped(tmp_path)

    typo = _run([str(script), "--local", str(empty), "--quickstrat"], tmp_path)
    assert typo.returncode == 2
    assert "Unknown option: --quickstrat; nothing was changed" in typo.stderr
    assert "checksums.txt" not in typo.stdout + typo.stderr

    equals = _run([str(script), f"--local={empty}", "--connector=claudecode", "--quickstart-mode=action"], tmp_path)
    assert "Unknown option" not in equals.stdout + equals.stderr
    assert "checksums.txt" in equals.stdout + equals.stderr  # got past argument parsing

    # The copy defenseclaw upgrade runs accepts a newer client's flags.
    upgrade_copy = tmp_path / "defenseclaw-upgrade-x1"
    upgrade_copy.mkdir()
    shutil.copy(script, upgrade_copy / "install.sh")
    newer = _run([str(upgrade_copy / "install.sh"), "--local", str(empty), "--from-the-future"], tmp_path)
    assert "Ignoring unknown option: --from-the-future" in newer.stdout + newer.stderr
    assert "checksums.txt" in newer.stdout + newer.stderr


def _pick_connector_script(tmp_path: Path, tty: Path) -> Path:
    text = INSTALL_SH.read_text(encoding="utf-8")
    script = tmp_path / "pick.sh"
    script.write_text(
        "set -euo pipefail\n"
        + text[text.index("readonly CONNECTOR_CHOICES=") : text.index("\n", text.index("readonly CONNECTOR_CHOICES="))]
        + '\nBOLD="" NC="" STAGING="/nonexistent" UV_DIR_NEW="" UV_INSTALLED=""\n'
        + 'step() { :; }\nok() { echo "$*"; }\nwarn() { echo "$*"; }\nerr() { echo "$*" >&2; }\ndrop_new_uv() { :; }\n'
        + text[text.index("usage_error() {") : text.index("\n", text.index("usage_error() {")) + 1]
        + _install_sh_functions("read_tty_line", "connector_choice", "pick_connector").replace("/dev/tty", str(tty))
        + "pick_connector\n",
        encoding="utf-8",
    )
    return script


@pytest.mark.parametrize(("answer", "rc", "expected"), [("ClaudeCode", 0, "Connector: claudecode"), ("99", 2, "No agent picked")])
def test_the_agent_prompt_takes_a_name_and_never_swaps_an_unknown_answer(
    tmp_path: Path, answer: str, rc: int, expected: str
) -> None:
    # GAP-0333: claudecode or 99 at the prompt installed codex without a word.
    tty = tmp_path / "tty"
    tty.write_text(answer + "\n", encoding="utf-8")

    result = _run([str(_pick_connector_script(tmp_path, tty))], tmp_path)

    assert result.returncode == rc, result.stdout + result.stderr
    assert expected in result.stdout + result.stderr
    assert "Connector: codex" not in result.stdout


@pytest.mark.parametrize("terminal", ["none", "enter"])
def test_the_agent_prompt_default_picks_no_agent(tmp_path: Path, terminal: str) -> None:
    # GAP-0568: with no terminal (curl | bash), or Enter at the prompt, the
    # installer picked codex and recorded it in picked_connector, so setup and
    # quickstart defaulted to an agent the machine may not have.
    tty = tmp_path / "tty"
    if terminal == "enter":
        tty.write_text("\n", encoding="utf-8")

    result = _run([str(_pick_connector_script(tmp_path, tty))], tmp_path)

    assert result.returncode == 0, result.stdout + result.stderr
    assert "Connector: none" in result.stdout
    assert "Connector: codex" not in result.stdout
    assert "1=codex" not in result.stderr


@pytest.mark.parametrize("script", ["install.sh", "install.ps1"])
def test_the_not_set_up_next_step_names_no_recorded_connector(script: str) -> None:
    # GAP-0568: an upgrade over a never-initialized install printed
    # 'init --connector codex' from the codex an older installer recorded
    # with no terminal to ask on, an agent the machine may not have.
    text = (ROOT / "scripts" / script).read_text(encoding="utf-8")
    start = text.index("An earlier install that was never initialized")
    block = text[start : text.index("DefenseClaw is not set up yet. Next: ", start) + 200]

    assert "picked_connector" not in block
    assert "init --connector" in block


def test_version_before_1_0_is_refused_without_network(tmp_path: Path) -> None:
    result = _run([str(_stamped(tmp_path)), "--version", "0.8.10"], tmp_path)

    assert result.returncode == 1
    assert "predates this installer" in result.stderr


def test_malformed_version_is_refused(tmp_path: Path) -> None:
    result = _run([str(_stamped(tmp_path)), "--version", "1.2"], tmp_path)

    # A usage error, as the install page says (GAP-0062).
    assert result.returncode == 2
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
    assert posix.rindex("args=(migrate)", 0, posix_refresh) > 0
    assert windows.rindex('@("migrate")', 0, windows_refresh) > 0
    # GAP-1294: the upgraded ACP guard is re-pinned in locks that pinned the
    # guard it replaced, so configured editor entries keep working.
    assert posix.index('acp refresh --from-sha256 "$(sha256_of "${SNAP}/bin/defenseclaw-acp")"') > posix_refresh
    assert windows.index('@("acp", "refresh", "--from-sha256", (Get-Sha256 $oldGuard))') > windows_refresh


def test_windows_process_listing_survives_a_wmi_refusal() -> None:
    # WMI refuses a standard user signed in over SSH; an upgrade must still
    # find this account's own processes.
    windows = (ROOT / "scripts" / "install.ps1").read_text(encoding="utf-8")
    body = windows[windows.index("function Get-ProcessesUnder") :]
    body = body[: body.index("\n}\n")]
    assert "Get-CimInstance Win32_Process -ErrorAction SilentlyContinue -ErrorVariable cimError" in body
    assert "if ($cimError -or -not $all.Count) {" in body
    assert "Get-Process" in body
    # GAP-1347: an expected refusal must not land in the run log as a TerminatingError.
    assert "Win32_Process -ErrorAction Stop" not in body


def test_windows_upgrade_says_it_is_cleaning_up_before_the_long_deletes() -> None:
    # GAP-1347: nothing was printed for about two minutes before "+ Installed".
    windows = (ROOT / "scripts" / "install.ps1").read_text(encoding="utf-8")
    body = windows[windows.index("function Complete-Swap") :]
    body = body[: body.index("\n}\n")]
    assert body.index('Write-Info "Cleaning up') < body.index("Publish-PreviousSlot $Snap")


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


@pytest.mark.parametrize(
    ("output", "rc", "expected"),
    [
        ("Gateway service disabled.\nStart with: openclaw gateway install\n", 0, "WARN No OpenClaw gateway service to restart"),
        ("Restarted systemd service: openclaw-gateway.service\n", 0, "OK OpenClaw gateway restarted"),
        ("boom\n", 1, "WARN Restart the OpenClaw gateway to load the updated plugin: openclaw gateway restart"),
    ],
)
def test_openclaw_restart_reports_what_happened(tmp_path: Path, output: str, rc: int, expected: str) -> None:
    # GAP-2207: `openclaw gateway restart` exits 0 with "Gateway service
    # disabled" when no service is installed; the installer said "restarted".
    text = INSTALL_SH.read_text(encoding="utf-8")
    start = text.index("restart_openclaw() {")
    func = text[start : text.index("\n}\n", start) + 3]
    fake = tmp_path / "fakebin"
    fake.mkdir()
    (tmp_path / "out.txt").write_text(output, encoding="utf-8")
    (fake / "openclaw").write_text(f'#!/bin/sh\ncat "{tmp_path / "out.txt"}"\nexit {rc}\n', encoding="utf-8")
    (fake / "openclaw").chmod(0o755)
    script = tmp_path / "restart.sh"
    script.write_text(
        "set -euo pipefail\nopenclaw_connector_active() { return 0; }\n"
        'has() { command -v "$1" >/dev/null 2>&1; }\nwarn() { echo "WARN $*"; }\nok() { echo "OK $*"; }\n'
        + func
        + "restart_openclaw\n",
        encoding="utf-8",
    )

    completed = _run([str(script)], tmp_path, PATH=f"{fake}:/usr/bin:/bin")

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert completed.stdout.strip().startswith(expected), completed.stdout
    assert len(completed.stdout.strip().splitlines()) == 1


@pytest.mark.parametrize(
    ("listing", "expected"),
    [
        ('{"sandboxes": [{"name": "ub-live", "phase": "ready"}, {"name": "old", "phase": "stopped"}]}',
         "WARN Sandbox ub-live is running: while the gateway restarts (usually under a minute) its hooks fail closed"),
        ('{"sandboxes": [{"name": "b2", "phase": "ready"}, {"name": "a1", "phase": "ready"}]}',
         "WARN 2 sandboxes are running (a1, b2): while the gateway restarts"),
        ('{"sandboxes": [{"name": "old", "phase": "stopped"}]}', ""),
        ("no daemon", ""),
    ],
)
def test_running_sandboxes_are_named_before_the_gateway_restarts(tmp_path: Path, listing: str, expected: str) -> None:
    # GAP-0352: an upgrade restarted the daemon under a running sandbox, whose
    # hooks failed closed meanwhile; the user learned it from the end summary.
    text = INSTALL_SH.read_text(encoding="utf-8")
    assert 'warn_running_sandboxes "${stranded}"\n    ask_yes_no "${question}"' in text
    assert 'warn_running_sandboxes\nif [[ "${REPAIR}" == true ]]; then\n    ask_yes_no "Reinstall' in text
    start = text.index("warn_running_sandboxes() {")
    func = text[start : text.index("\n}\n", start) + 3]
    bin_dir, venv = tmp_path / "bin", tmp_path / "venv"
    (venv / "bin").mkdir(parents=True)
    bin_dir.mkdir()
    (venv / "bin" / "python").symlink_to(sys.executable)
    (tmp_path / "list.json").write_text(listing, encoding="utf-8")
    gateway = bin_dir / "defenseclaw-gateway"
    gateway.write_text(
        f'#!/bin/sh\n[ "$*" = "sandbox list --output json" ] && cat "{tmp_path / "list.json"}"\n', encoding="utf-8"
    )
    gateway.chmod(0o755)
    script = tmp_path / "warn.sh"
    script.write_text(
        f'set -euo pipefail\nBIN_DIR="{bin_dir}"\nVENV="{venv}"\n'
        'gateway_pid() { printf 42; }\nwarn() { echo "WARN $*"; }\n' + func + "warn_running_sandboxes\n",
        encoding="utf-8",
    )

    completed = _run([str(script)], tmp_path)

    assert completed.returncode == 0, completed.stdout + completed.stderr
    if expected:
        assert completed.stdout.strip().startswith(expected), completed.stdout
    else:
        assert completed.stdout == "", completed.stdout


@pytest.mark.parametrize("operator_stopped", [False, True])
def test_the_install_stop_leaves_no_operator_stop_marker(tmp_path: Path, operator_stopped: bool) -> None:
    # GAP-0140: hooks that run during an upgrade read gateway.stopped as an
    # operator stop and fail at once with that text; the hooks of 1.0.2 do
    # not read .install.lock. The install's own stop leaves no marker, and an
    # operator's marker from before the install stays.
    text = INSTALL_SH.read_text(encoding="utf-8")
    start = text.index("stop_gateway() {")
    func = text[start : text.index("\n}\n", start) + 3]
    data = tmp_path / "data"
    data.mkdir()
    marker = data / "gateway.stopped"
    if operator_stopped:
        marker.write_text("stopped\n", encoding="utf-8")
    gateway = tmp_path / "defenseclaw-gateway"
    gone = tmp_path / "gone"
    gateway.write_text(f'#!/bin/sh\n[ "$1" = stop ] && echo stopped > "{marker}" && : > "{gone}"\n', encoding="utf-8")
    gateway.chmod(0o755)
    script = tmp_path / "stop.sh"
    script.write_text(
        f'set -euo pipefail\nDEFENSECLAW_HOME="{data}"\n'
        f'gateway_pid() {{ [ -e "{gone}" ] || printf 42; return 0; }}\n'
        + func
        + f'stop_gateway "{gateway}"\n',
        encoding="utf-8",
    )

    completed = _run([str(script)], tmp_path)

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert marker.exists() == operator_stopped


def test_install_makes_the_owned_bin_folders_private(tmp_path: Path) -> None:
    # A user-private-group umask (002) left ~/.local and ~/.local/bin
    # group-writable when another installer created them; the CLI then
    # refused the gateway in them after install and init had succeeded.
    text = INSTALL_SH.read_text(encoding="utf-8")
    start = text.index("private_bin_dir() {")
    func = text[start : text.index("\n}\n", start) + 3]
    bin_dir = tmp_path / "home" / ".local" / "bin"
    bin_dir.mkdir(parents=True)
    for folder in (bin_dir.parent, bin_dir):
        folder.chmod(0o775)
    script = tmp_path / "private.sh"
    script.write_text(
        f"set -euo pipefail\nBIN_DIR=\"{bin_dir}\"\ninfo() {{ echo \"INFO $*\"; }}\n" + func + "private_bin_dir\nprivate_bin_dir\n",
        encoding="utf-8",
    )

    completed = _run([str(script)], tmp_path)

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert [oct(folder.stat().st_mode & 0o777) for folder in (bin_dir.parent, bin_dir)] == ["0o755", "0o755"]
    assert completed.stdout.count("INFO ") == 2, completed.stdout


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


def test_handoff_checks_a_fork_against_the_official_release_identity(tmp_path: Path) -> None:
    # DEFENSECLAW_REPO moves the downloads, never the trust root. A validly
    # signed installer of another release served under the tag is refused.
    release = _release(tmp_path, '#!/bin/bash\nreadonly DC_VERSION="1.0.0"\necho ran\n')
    fake = tmp_path / "fakebin"
    fake.mkdir()
    (fake / "curl").write_text(
        "#!/bin/bash\nout=''\nwhile [ $# -gt 1 ]; do [ \"$1\" = -o ] && out=$2; shift; done\n"
        'case "$1" in */latest) echo "location: https://github.com/fork/defenseclaw/releases/tag/1.0.1" ;;\n'
        f'*) cp "{release}/${{1##*/}}" "$out" 2>/dev/null || : > "$out" ;; esac\n',
        encoding="utf-8",
    )
    (fake / "cosign").write_text(
        f'#!/bin/bash\n[ "$1" = version ] && {{ echo "GitVersion: v2.4.1"; exit 0; }}\necho "$*" > "{tmp_path}/cosign.args"\n',
        encoding="utf-8",
    )
    for tool in ("curl", "cosign"):
        (fake / tool).chmod(0o755)

    def handoff() -> subprocess.CompletedProcess[str]:
        return _run(
            [str(HANDOFF_SH), "--plan"], tmp_path, PATH=f"{fake}:/usr/bin:/bin", DEFENSECLAW_REPO="fork/defenseclaw",
        )

    result = handoff()
    assert result.returncode == 1 and "is release 1.0.0" in result.stderr, result.stderr

    script = '#!/bin/bash\nreadonly DC_VERSION="1.0.1"\necho ran\n'
    (release / "install.sh").write_text(script, encoding="utf-8")
    (release / "checksums.txt").write_text(f"{hashlib.sha256(script.encode()).hexdigest()}  install.sh\n", encoding="utf-8")
    result = handoff()
    assert result.returncode == 0, result.stderr
    signer = r"^https://github\.com/cisco-ai-defense/defenseclaw/\.github/workflows/release\.yaml@refs/heads/main$"
    assert f"--certificate-identity-regexp {signer}" in (tmp_path / "cosign.args").read_text(encoding="utf-8")


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


def test_removed_sandbox_flag_is_a_usage_error(tmp_path: Path) -> None:
    """--sandbox went with the legacy openshell-sandbox installer: it stops before anything is installed."""
    completed = _run([_stamped(tmp_path).as_posix(), "--sandbox"], tmp_path)
    assert completed.returncode == 1, completed.stdout + completed.stderr
    assert "--sandbox was removed with the legacy openshell-sandbox installer" in completed.stderr
    assert "defenseclaw sandbox setup" in completed.stderr
    assert not (tmp_path / "home" / ".defenseclaw").exists()
    assert not (ROOT / "scripts" / "install-openshell-sandbox.sh").exists()


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
        + 'OPENCLAW_MISSING=false OPENCLAW_NEXT=""\n'
        + f'DEFENSECLAW_HOME="{tmp_path}" VENV="{tmp_path / "venv"}" BIN_DIR="{venv_bin}"\n'
        + 'first_install_extras\nprintf "%s|%s\\n" "${QUICKSTART_RC}" "${QUICKSTART_RERUN}"\n',
        encoding="utf-8",
    )

    completed = _run([str(script)], tmp_path)

    assert completed.returncode == 0, completed.stdout + completed.stderr
    rerun = "defenseclaw quickstart --connector codex --mode action"
    assert completed.stdout.strip() == f"7|{rerun}"
    summary = text[text.index('if [[ -n "${QUICKSTART_RERUN}" ]]; then') :]
    assert summary.index("exit 4") < summary.index("exit ${START_RC}")



def test_quickstart_failure_without_hermes_says_how_to_install_it() -> None:
    # GAP-2383: "Fix what quickstart reported above" did not say Hermes was missing.
    text = INSTALL_SH.read_text(encoding="utf-8")
    summary = text[text.index('if [[ -n "${QUICKSTART_RERUN}" ]]; then') :]
    branch = summary[: summary.index("exit 4")]
    assert '[[ "${CONNECTOR}" == hermes ]] && ! PATH="${BIN_DIR}:${PATH}" has hermes' in branch
    assert "Install Hermes (https://github.com/NousResearch/hermes-agent), then run:" in branch


def _openclaw_install_run(tmp_path: Path, npm_rc: int, answer: int = 0) -> subprocess.CompletedProcess[str]:
    text = INSTALL_SH.read_text(encoding="utf-8")
    start = text.index("ensure_openclaw() {")
    funcs = text[start : text.index("\n}\n", text.index("npm_global_prefix_writable() {")) + 3]
    prefix = tmp_path / "node"
    (prefix / "lib" / "node_modules").mkdir(parents=True)
    (prefix / "bin").mkdir()
    fake = tmp_path / "fakebin"
    fake.mkdir()
    (fake / "npm").write_text(
        "#!/bin/sh\n"
        f'if [ "$1" = prefix ]; then echo "{prefix}"; exit 0; fi\n'
        f'echo "$@" >> "{tmp_path / "npm.log"}"\nexit {npm_rc}\n',
        encoding="utf-8",
    )
    (fake / "npm").chmod(0o755)
    (prefix / "lib" / "node_modules").chmod(0o555)
    (prefix / "bin").chmod(0o555)
    script = tmp_path / "oc.sh"
    script.write_text(
        "set -euo pipefail\n"
        f'has() {{ command -v "$1" >/dev/null 2>&1; }}\nask_yes_no() {{ return {answer}; }}\n'
        'warn() { echo "WARN $*"; }\ninfo() { echo "INFO $*"; }\nok() { :; }\nversion_lt() { return 1; }\n'
        f'OPENCLAW_VERSION=2026.3.24 OPENCLAW_MISSING=false OPENCLAW_INSTALLED=false BIN_DIR="{tmp_path / "home" / ".local" / "bin"}"\n'
        + funcs
        + 'ensure_openclaw\necho "missing=${OPENCLAW_MISSING} installed=${OPENCLAW_INSTALLED}"\n',
        encoding="utf-8",
    )
    try:
        return _run([str(script)], tmp_path, PATH=f"{fake}:/usr/bin:/bin")
    finally:
        (prefix / "lib" / "node_modules").chmod(0o755)
        (prefix / "bin").chmod(0o755)


@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="root can write any prefix")
def test_openclaw_installs_into_the_user_prefix_when_the_node_prefix_is_read_only(tmp_path: Path) -> None:
    # GAP-1523: npm -g into a root-owned system Node failed with EACCES, the
    # hint repeated the same failing command, and the installer exited 0.
    done = _openclaw_install_run(tmp_path, 0)
    assert done.returncode == 0, done.stdout + done.stderr
    home = tmp_path / "home"
    assert (tmp_path / "npm.log").read_text().split() == [
        "install", "-g", "--prefix", f"{home}/.local", "openclaw@2026.3.24",
        "--no-fund", "--no-audit", "--no-update-notifier", "--loglevel=error",
    ]
    assert "INFO Installing OpenClaw 2026.3.24 with npm" in done.stdout
    assert "missing=false installed=true" in done.stdout

    failed_dir = tmp_path / "f"
    failed_dir.mkdir()
    failed = _openclaw_install_run(failed_dir, 1)
    assert f"run: npm install -g --prefix {failed_dir / 'home'}/.local openclaw@2026.3.24" in failed.stdout
    assert "missing=true installed=false" in failed.stdout
    summary = INSTALL_SH.read_text(encoding="utf-8")
    tail = summary[summary.index('if [[ "${OPENCLAW_MISSING}" == true ]]; then') :]
    assert tail.index("exit 3") < tail.index("exit ${START_RC}")
    # A fresh OpenClaw still needs its own setup; say so before the exit.
    assert tail.index("openclaw onboard") < tail.index("exit ${START_RC}")


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
    # GAP-0012: start only says a degraded gateway is running; restart fixes it.
    assert "DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT=1 defenseclaw-gateway restart" in out
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
        # GAP-1241: the failed new gateway's start has already explained itself.
        + "START_EXPLAINED=1\n"
        + f'rc=0; start_gateway || rc=$?; echo "rc=$rc"; kill "$(cat \'{pid_file}\')"\n',
        encoding="utf-8",
    )

    out = _run([str(script)], tmp_path).stdout

    assert "LAUNCHED" in out, out
    assert "ok: The gateway finished starting" in out
    assert "rc=0" in out


def test_a_rollback_whose_gateway_does_not_start_is_undone_and_exits_1(tmp_path: Path) -> None:
    # GAP-1076: the restored gateway stayed down, yet the rollback printed a
    # green "Now running" and exited 0. GAP-0486 (fix/r104-windows): a 1.x
    # rollback whose gateway does not start is undone, as a 0.x one is, so
    # the install it left runs again. GAP-1077: rolling forward was headed
    # "Rolling back".
    home = tmp_path / "home"
    dc_home, bin_dir = home / ".defenseclaw", home / ".local" / "bin"
    (dc_home / "previous" / "bin").mkdir(parents=True)
    bin_dir.mkdir(parents=True)
    for folder, version, start in ((bin_dir, "1.0.2", "exit 0"), (dc_home / "previous" / "bin", "1.0.1", "exit 1")):
        gateway = folder / "defenseclaw-gateway"
        gateway.write_text(
            f'#!/bin/sh\ncase "$1" in --version) echo "defenseclaw-gateway version {version}" ;; start) {start} ;; esac\n',
            encoding="utf-8",
        )
        gateway.chmod(0o755)
    (dc_home / "previous" / "VERSION").write_text("1.0.1\n", encoding="utf-8")
    (dc_home / "previous" / "GATEWAY_WAS_RUNNING").write_text("true\n", encoding="utf-8")
    script = _stamped(tmp_path, "1.0.2")
    env = {"DEFENSECLAW_APP_PATH": "none"}

    back = _run_rollback_with_no_agents([str(script), "--rollback", "--yes"], tmp_path, **env)

    assert back.returncode == 1, back.stdout + back.stderr
    assert "Rolling back to DefenseClaw 1.0.1" in back.stdout
    assert "The gateway of DefenseClaw 1.0.1 did not start, so the rollback is being undone" in back.stdout, back.stdout
    assert "Now running" not in back.stdout
    # The install the rollback left is live again, and previous/ still holds
    # the rollback target.
    assert "1.0.2" in (bin_dir / "defenseclaw-gateway").read_text(encoding="utf-8")
    assert (dc_home / "previous" / "VERSION").read_text(encoding="utf-8").strip() == "1.0.1"

    # Once the older gateway starts, the same rollback goes through, and a
    # second one rolls forward.
    older = dc_home / "previous" / "bin" / "defenseclaw-gateway"
    older.write_text(older.read_text(encoding="utf-8").replace("start) exit 1", "start) exit 0"), encoding="utf-8")
    back = _run_rollback_with_no_agents([str(script), "--rollback", "--yes"], tmp_path, **env)
    assert back.returncode == 0, back.stdout + back.stderr
    forward = _run_rollback_with_no_agents([str(script), "--rollback", "--yes"], tmp_path, **env)

    assert forward.returncode == 0, forward.stdout + forward.stderr
    assert "Rolling forward to DefenseClaw 1.0.2" in forward.stdout
    assert "Now running DefenseClaw 1.0.2." in forward.stdout
    # GAP-1497: rolling forward asked to replace 0.8.10 "with the previous
    # install (1.0.1)", though 1.0.1 is the newer one.
    for path in (INSTALL_SH, ROOT / "scripts" / "install.ps1"):
        assert "(the install you rolled back from)?" in path.read_text(encoding="utf-8"), path


def test_a_rollback_to_0_x_removes_the_1_0_connector_registrations_first(tmp_path: Path) -> None:
    # GAP-1521: after a rollback to 0.8.10 the 1.0 Copilot entries and the
    # OpenCode plugin stayed, so 0.8.10 ran every Copilot hook twice.
    home = tmp_path / "home"
    dc_home, bin_dir = home / ".defenseclaw", home / ".local" / "bin"
    (dc_home / "previous" / "bin").mkdir(parents=True)
    (dc_home / ".venv" / "bin").mkdir(parents=True)
    (dc_home / ".venv" / "bin" / "python").symlink_to(sys.executable)
    bin_dir.mkdir(parents=True)
    calls = tmp_path / "calls.txt"
    for folder, version in ((bin_dir, "1.0.1"), (dc_home / "previous" / "bin", "0.8.10")):
        gateway = folder / "defenseclaw-gateway"
        gateway.write_text(
            f'#!/bin/sh\ncase "$1" in --version) echo "defenseclaw-gateway version {version}" ;; '
            f"connector) echo \"{version} $*\" >> '{calls}'; rm -f '{dc_home}'/hooks/.otlp-*.token ;; esac\n",
            encoding="utf-8",
        )
        gateway.chmod(0o755)
    # GAP-1925: teardown revokes the connector OTLP tokens; the data kept for a
    # roll forward keeps them, so an agent exporter's token stays valid.
    (dc_home / "hooks").mkdir(mode=0o700)
    (dc_home / "hooks" / ".otlp-claudecode.token").write_text("kept-token\n", encoding="utf-8")
    state = '{"version": 3, "names": ["copilot", "opencode", "openclaw"], "inactive_names": []}'
    (dc_home / "active_connector.json").write_text(state, encoding="utf-8")
    (dc_home / "previous" / "VERSION").write_text("0.8.10\n", encoding="utf-8")
    script = _stamped(tmp_path, "1.0.1")

    back = _run_rollback_with_no_agents([str(script), "--rollback", "--yes"], tmp_path, DEFENSECLAW_APP_PATH="none")

    assert back.returncode == 0, back.stdout + back.stderr
    assert "Could not remove" not in back.stdout + back.stderr
    assert calls.read_text(encoding="utf-8").splitlines() == [
        "1.0.1 connector teardown --connector copilot",
        "1.0.1 connector teardown --connector opencode",
    ]
    # The 1.0.1 data kept for a roll forward still names its connectors.
    assert (dc_home / "previous" / "data" / "active_connector.json").read_text(encoding="utf-8") == state
    kept = dc_home / "previous" / "data" / "hooks" / ".otlp-claudecode.token"
    assert kept.read_text(encoding="utf-8") == "kept-token\n"

    calls.unlink()
    forward = _run_rollback_with_no_agents([str(script), "--rollback", "--yes"], tmp_path, DEFENSECLAW_APP_PATH="none")

    assert forward.returncode == 0, forward.stdout + forward.stderr
    # Only the GAP-0009 check of which gateway can prune hook entries; neither fake can.
    made = calls.read_text(encoding="utf-8").splitlines() if calls.exists() else []
    assert [line for line in made if not line.endswith("connector prune-orphans --help")] == []


def test_a_rollback_to_0_x_names_only_the_installer_command_to_return(tmp_path: Path) -> None:
    # GAP-0585: a 0.x release has no rollback command to return to 1.x.
    for name, current, back_to in (("legacy", "1.0.1", "0.8.10"), ("current", "1.0.2", "1.0.1")):
        case = tmp_path / name
        home = case / "home"
        dc_home, bin_dir = home / ".defenseclaw", home / ".local" / "bin"
        (dc_home / "previous" / "bin").mkdir(parents=True)
        bin_dir.mkdir(parents=True)
        for folder, version in ((bin_dir, current), (dc_home / "previous" / "bin", back_to)):
            gateway = folder / "defenseclaw-gateway"
            gateway.write_text(
                f'#!/bin/sh\ncase "$1" in --version) echo "defenseclaw-gateway version {version}" ;; '
                "start) exit 0 ;; esac\n",
                encoding="utf-8",
            )
            gateway.chmod(0o755)
        (dc_home / "previous" / "VERSION").write_text(f"{back_to}\n", encoding="utf-8")
        if back_to == "1.0.1":
            (dc_home / "previous" / "GATEWAY_WAS_RUNNING").write_text("true\n", encoding="utf-8")
        script = _stamped(case, current)

        back = _run_rollback_with_no_agents([str(script), "--rollback", "--yes"], case, DEFENSECLAW_APP_PATH="none")
        out = back.stdout + back.stderr

        assert back.returncode == 0, out
        if back_to == "0.8.10":
            command = f"bash {dc_home}/previous/installer/install.sh --rollback"
            assert f"To return to 1.0.1, run: {command}" in out, out
            assert f"kept in {dc_home}/previous; '{command}' again brings it back" in out, out
            assert "defenseclaw rollback" not in out, out
        else:
            assert "Starting the gateway" in out, out
            assert "Run 'defenseclaw rollback' again to return to 1.0.2." in out, out
            assert "'defenseclaw rollback' again brings it back (a new 'defenseclaw upgrade' starts from the data you have now" in out, out
            assert "installer/install.sh --rollback" not in out, out


def _damaged_audit_db(path: Path) -> bytes:
    import sqlite3

    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TABLE audit_events (detail TEXT)")
        conn.executemany("INSERT INTO audit_events VALUES (?)", [("x" * 500,)] * 2000)
    conn.close()
    with path.open("r+b") as handle:  # overwrite b-tree pages: integrity_check fails
        handle.seek(4096 * 2)
        handle.write(b"\xff" * 4096 * 3)
    return path.read_bytes()


def _rollback_to_0_8_with_a_damaged_store(tmp_path: Path, starts: bool) -> tuple[subprocess.CompletedProcess[str], Path]:
    # A 1.0.1 install with a connector over a saved 0.8.10 install whose
    # audit.db SQLite reports damaged (GAP-1388). The 0.8.10 gateway, like the
    # real one, starts only on a store it can write.
    home = tmp_path / "home"
    dc_home, bin_dir = home / ".defenseclaw", home / ".local" / "bin"
    (dc_home / "previous" / "bin").mkdir(parents=True)
    (dc_home / "previous" / "data").mkdir()
    (dc_home / ".venv" / "bin").mkdir(parents=True)
    (dc_home / ".venv" / "bin" / "python").symlink_to(sys.executable)
    bin_dir.mkdir(parents=True)
    shutil.copy(shutil.which("sleep") or "/bin/sleep", tmp_path / "defenseclaw-sleep")
    calls = tmp_path / "calls.txt"
    log = f"echo \"$V $*\" >> '{calls}'"
    pid = '"$DEFENSECLAW_HOME/gateway.pid"'
    # Like a real 1.0.1 gateway, start refuses a flag it does not know (the
    # installer asks whether it has --require-every-connector).
    new = f'connector|start) [ "$1" = connector ] || [ "$#" -eq 1 ] || exit 1; {log} ;; esac\n'
    guard = '[ ! -e "$DEFENSECLAW_HOME/audit.db" ] || ' if starts else ""
    old = (
        f"start) {log}; {guard}exit 1\n"
        f"  '{tmp_path}/defenseclaw-sleep' 60 >/dev/null 2>&1 & echo $! > {pid} ;;\n"
        f"status) kill -0 \"$(cat {pid})\" ;;\nstop) {log}; kill \"$(cat {pid})\"; rm -f {pid} ;; esac\n"
    )
    for folder, version, body in ((bin_dir, "1.0.1", new), (dc_home / "previous" / "bin", "0.8.10", old)):
        gateway = folder / "defenseclaw-gateway"
        gateway.write_text(
            f'#!/bin/sh\nV={version}\ncase "$1" in --version) echo "defenseclaw-gateway version $V" ;;\n{body}',
            encoding="utf-8",
        )
        gateway.chmod(0o755)
    (dc_home / "active_connector.json").write_text('{"version": 3, "names": ["claudecode"]}', encoding="utf-8")
    (dc_home / "previous" / "VERSION").write_text("0.8.10\n", encoding="utf-8")
    (dc_home / "previous" / "GATEWAY_WAS_RUNNING").write_text("true\n", encoding="utf-8")
    _damaged_audit_db(dc_home / "previous" / "data" / "audit.db")
    try:
        result = _run_rollback_with_no_agents([str(_stamped(tmp_path, "1.0.1")), "--rollback", "--yes"], tmp_path, DEFENSECLAW_APP_PATH="none")
    finally:
        subprocess.run(["pkill", "-f", str(tmp_path / "defenseclaw-sleep")], check=False)
    return result, dc_home


def test_a_rollback_to_0_x_moves_a_damaged_audit_store_aside(tmp_path: Path) -> None:
    # GAP-1388: the rollback restored a damaged 0.8.10 audit.db; 0.8.10's
    # gateway then failed (local_write_failed), with the 1.0 hooks removed.
    back, dc_home = _rollback_to_0_8_with_a_damaged_store(tmp_path, starts=True)

    out = back.stdout + back.stderr
    assert back.returncode == 0, out
    archives = [path.name for path in dc_home.glob("audit.db.corrupt-*")]
    assert len(archives) == 1 and re.fullmatch(r"audit\.db\.corrupt-\d{8}T\d{6}Z", archives[0]), archives
    assert not (dc_home / "audit.db").exists()
    assert out.count("failed SQLite's integrity check") == 1, out
    assert "Now running DefenseClaw 0.8.10." in out
    assert (tmp_path / "calls.txt").read_text(encoding="utf-8").splitlines() == [
        "1.0.1 connector teardown --connector claudecode",
        "0.8.10 start",
    ]
    # The check runs before anything of the 1.0 install changes.
    text = INSTALL_SH.read_text(encoding="utf-8")
    block = text[text.index('if [[ "${ROLLBACK}" == true ]]; then') :]
    assert block.index("check_rollback_data") < block.index("stop_gateway") < block.index(
        "remove_connector_registrations_for_legacy"
    )


def test_a_rollback_to_0_x_whose_gateway_does_not_start_is_undone(tmp_path: Path) -> None:
    # GAP-1388: left with 0.8.10 files, no gateway and no hooks. Now the 1.0.1
    # install comes back and its gateway start writes its registrations again.
    back, dc_home = _rollback_to_0_8_with_a_damaged_store(tmp_path, starts=False)

    out = back.stdout + back.stderr
    assert back.returncode == 1, out
    assert "the rollback is being undone" in out
    assert "run 'defenseclaw rollback' again" in out
    assert (tmp_path / "calls.txt").read_text(encoding="utf-8").splitlines() == [
        "1.0.1 connector teardown --connector claudecode",
        "0.8.10 start",
        "1.0.1 start",
    ]
    assert "1.0.1" in (dc_home.parent / ".local" / "bin" / "defenseclaw-gateway").read_text(encoding="utf-8")
    assert (dc_home / "active_connector.json").is_file()
    previous = dc_home / "previous"
    assert (previous / "VERSION").read_text(encoding="utf-8").strip() == "0.8.10"
    assert not (previous / "ROLLED_BACK").exists()
    # The saved store is back as it was, so a later upgrade keeps it.
    assert (previous / "data" / "audit.db").is_file()
    assert not list((previous / "data").glob("audit.db.corrupt-*"))


def test_a_rollback_refused_on_hook_drift_prints_only_the_fix_that_works(tmp_path: Path) -> None:
    # GAP-0012: after naming the drift and its restart fix, the rollback also
    # said "Start it with: defenseclaw-gateway start", which does nothing then.
    home = tmp_path / "home"
    dc_home, bin_dir = home / ".defenseclaw", home / ".local" / "bin"
    (dc_home / "previous" / "bin").mkdir(parents=True)
    bin_dir.mkdir(parents=True)
    drift = (
        "echo 'Error: connector claudecode hook contract drift detected: previous version=\"2.1.276\" contract=v1 "
        "current version=\"2.1.286\" contract=v1 (set DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT=1 for exploratory "
        f"testing)' >> '{dc_home}/gateway.log'; exit 1"
    )
    for folder, version, start in ((bin_dir, "1.0.1", "exit 0"), (dc_home / "previous" / "bin", "0.8.10", drift)):
        gateway = folder / "defenseclaw-gateway"
        gateway.write_text(
            f'#!/bin/sh\ncase "$1" in --version) echo "defenseclaw-gateway version {version}" ;; start) {start} ;; esac\n',
            encoding="utf-8",
        )
        gateway.chmod(0o755)
    (dc_home / "previous" / "VERSION").write_text("0.8.10\n", encoding="utf-8")
    (dc_home / "previous" / "GATEWAY_WAS_RUNNING").write_text("true\n", encoding="utf-8")

    back = _run_rollback_with_no_agents([str(_stamped(tmp_path, "1.0.1")), "--rollback", "--yes"], tmp_path, DEFENSECLAW_APP_PATH="none")

    assert back.returncode == 1, back.stdout + back.stderr
    out = back.stdout + back.stderr
    assert "DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT=1 defenseclaw-gateway restart" in out
    assert "Start it with: defenseclaw-gateway start" not in out
    # GAP-1388: 0.8.10 is not left down; the retry that accepts the drift is named.
    assert "DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT=1 defenseclaw rollback" in out


def test_both_installers_say_when_an_upgrade_leaves_the_gateway_stopped() -> None:
    # GAP-1496: an upgrade over a stopped gateway ended with a green
    # "installed" and nothing about the unguarded hooks.
    for path in (INSTALL_SH, ROOT / "scripts" / "install.ps1"):
        text = path.read_text(encoding="utf-8")
        assert "The gateway is not running, so agent hooks are not guarded until it is" in text, path
        # GAP-2481: after 'uninstall --binaries' the guardrail is off, and a
        # gateway start alone does not guard the hooks again.
        assert "Turn it back on with:" in text and "defenseclaw setup guardrail" in text, path
        # GAP-0384: a port another process holds fails that start too; say so.
        assert '"check-api-port", "--installed"' in text or "check-api-port --installed" in text, path

_GUARDRAIL_CONFIGS = {
    # What 'uninstall --binaries' and 'setup guardrail --disable' save.
    "off": ("guardrail:\n  enabled: false\n  mode: action\n  judge:\n    enabled: true\ngateway:\n  port: 18970\n", True),
    "on": ("guardrail:\n  enabled: true\n  judge:\n    enabled: false\n", False),
    "other-section": ("guardrail:\n  mode: action\nwebhook:\n  enabled: false\n", False),
    "no-guardrail": ("gateway:\n  enabled: false\n", False),
}


@pytest.mark.parametrize("name", sorted(_GUARDRAIL_CONFIGS))
def test_install_sh_reads_guardrail_off_from_the_kept_config(tmp_path: Path, name: str) -> None:
    # GAP-2481: the reinstall after 'uninstall --binaries' said only "Start it
    # with: defenseclaw-gateway start" over a config with the guardrail off.
    text = INSTALL_SH.read_text(encoding="utf-8")
    start = text.index("guardrail_off() {")
    func = text[start : text.index("\n}\n", start) + 3]
    body, expected = _GUARDRAIL_CONFIGS[name]
    (tmp_path / "config.yaml").write_text(body, encoding="utf-8")
    script = tmp_path / "g.sh"
    script.write_text(
        f'set -euo pipefail\n{func}DEFENSECLAW_HOME="{tmp_path}"\nif guardrail_off; then echo off; else echo on; fi\n',
        encoding="utf-8",
    )
    env = {k: v for k, v in os.environ.items() if k != "DEFENSECLAW_CONFIG"}
    out = subprocess.run(["bash", str(script)], capture_output=True, text=True, env=env, check=True).stdout
    assert out.strip() == ("off" if expected else "on")
    branch = text[text.index("if guardrail_off; then") :]
    assert branch.index("defenseclaw setup guardrail") < branch.index("defenseclaw-gateway start")


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


def _uv_bootstrap(tmp_path: Path, free_kb: int, cache_mb: int | None = None) -> subprocess.CompletedProcess[str]:
    # The installer's uv bootstrap and free-space preflight, from the UV_*
    # exports to the first write of the staging dir.
    text = INSTALL_SH.read_text(encoding="utf-8")
    snippet = text[text.index('export UV_CACHE_DIR="') : text.index('rm -rf "${STAGING}"\nmkdir -p "${STAGING}/bin"')]
    install_uv = text[text.index("install_uv() {") : text.index("\n}\n", text.index("install_uv() {")) + 3]
    start = text.index("is_machinery() {")
    preflight = text[start : text.index("\n}\n", text.index("require_free_space() {")) + 3]
    home = tmp_path / "home"
    data_dir = home / ".defenseclaw"
    data_dir.mkdir(parents=True, exist_ok=True)
    bin_dir = home / ".local" / "bin"
    fake = tmp_path / "fake"
    fake.mkdir()
    (fake / "df").write_text(f"#!/bin/sh\necho head\necho fs 1 1 {free_kb} 1% /\n", encoding="utf-8")
    (fake / "curl").write_text("#!/bin/sh\necho CURL-CALLED\nexit 1\n", encoding="utf-8")
    for name in ("df", "curl"):
        (fake / name).chmod(0o755)
    if cache_mb is not None:
        # uv's cache holds cache_mb; every other du call is the real one.
        cache = data_dir / ".uv" / "cache"
        cache.mkdir(parents=True, exist_ok=True)
        du = shutil.which("du", path="/usr/bin:/bin")
        (fake / "du").write_text(
            f'#!/bin/sh\nif [ "$2" = "{cache}" ]; then echo "{cache_mb * 1024}\t$2"; exit 0; fi\nexec {du} "$@"\n',
            encoding="utf-8",
        )
        (fake / "du").chmod(0o755)
    script = tmp_path / "uv.sh"
    script.write_text(
        'set -euo pipefail\nerr() { echo "err: $*"; }\ndie() { err "$@"; exit 1; }\ninfo() { echo "info: $*"; }\n'
        "has() { command -v \"$1\" >/dev/null 2>&1; }\n"
        f'OS=darwin ARCH=arm64 UV_VERSION=0 DEFENSECLAW_HOME="{data_dir}" BIN_DIR="{bin_dir}"\n'
        f'STAGING="{data_dir}/.staging" VENV="{data_dir}/.venv" NOT_DATA=".venv .uv .staging .failed-* backups"\n'
        f'PATH="{fake}:/usr/bin:/bin"\nunset UV_CACHE_DIR UV_PYTHON_INSTALL_DIR\n'
        + install_uv
        + preflight
        + "require_free_space\n"
        + snippet
        + 'echo "uv=$(command -v uv)"\n',
        encoding="utf-8",
    )
    return _run([str(script)], tmp_path)


def test_a_uv_in_bin_dir_off_path_is_used_not_replaced(tmp_path: Path) -> None:
    # GAP-1125: with ~/.local/bin off PATH the installer downloaded its pinned
    # uv over the user's newer one and recorded it as its own.
    bin_dir = tmp_path / "home" / ".local" / "bin"
    bin_dir.mkdir(parents=True)
    (bin_dir / "uv").write_text("#!/bin/sh\necho users-uv\n", encoding="utf-8")
    (bin_dir / "uv").chmod(0o755)

    proc = _uv_bootstrap(tmp_path, free_kb=10 * 1024 * 1024)

    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert f"uv={bin_dir / 'uv'}" in proc.stdout
    assert "Installing uv" not in proc.stdout and "CURL-CALLED" not in proc.stdout
    assert (bin_dir / "uv").read_text(encoding="utf-8") == "#!/bin/sh\necho users-uv\n"
    assert not (bin_dir / "defenseclaw-uv.sha256").exists()


def test_install_uv_never_replaces_an_existing_uv(tmp_path: Path) -> None:
    bin_dir = tmp_path / "home" / ".local" / "bin"
    bin_dir.mkdir(parents=True)
    (bin_dir / "uvx").write_text("mine", encoding="utf-8")
    fake = tmp_path / "fake"
    fake.mkdir()
    (fake / "curl").write_text("#!/bin/sh\necho CURL-CALLED\nexit 1\n", encoding="utf-8")
    (fake / "curl").chmod(0o755)
    text = INSTALL_SH.read_text(encoding="utf-8")
    func = text[text.index("install_uv() {") : text.index("\n}\n", text.index("install_uv() {")) + 3]
    script = tmp_path / "guard.sh"
    script.write_text(
        f'set -euo pipefail\nOS=darwin ARCH=arm64 UV_VERSION=0 BIN_DIR="{bin_dir}"\nPATH="{fake}:/usr/bin:/bin"\n'
        + func
        + 'rc=0; install_uv || rc=$?; echo "rc=$rc"\n',
        encoding="utf-8",
    )

    out = _run([str(script)], tmp_path).stdout

    assert "rc=1" in out and "CURL-CALLED" not in out
    assert (bin_dir / "uvx").read_text(encoding="utf-8") == "mine"


def test_a_first_install_without_room_refuses_before_writing(tmp_path: Path) -> None:
    # GAP-1249: on a nearly full disk uv failed mid-build with ENOSPC, the
    # installer said "nothing was changed" and left ~286 MB in ~/.defenseclaw.
    proc = _uv_bootstrap(tmp_path, free_kb=300 * 1024)

    assert proc.returncode == 1, proc.stdout
    assert "the install needs about 1100 MB and 300 MB is free" in proc.stdout
    assert "Free at least 800 MB" in proc.stdout and "nothing was changed" in proc.stdout
    assert "Installing uv" not in proc.stdout
    assert not (tmp_path / "home" / ".defenseclaw" / ".uv").exists()


def test_an_upgrade_without_room_refuses_before_staging(tmp_path: Path) -> None:
    # GAP-1307: an upgrade with 8 MB free failed at staging with a raw cp ENOSPC.
    proc = _uv_bootstrap(tmp_path, free_kb=8 * 1024, cache_mb=900)

    assert proc.returncode == 1, proc.stdout
    assert "the install needs about 400 MB and 8 MB is free" in proc.stdout
    assert "nothing was changed" in proc.stdout
    assert not (tmp_path / "home" / ".defenseclaw" / ".staging").exists()


def test_an_upgrade_counts_the_rollback_copy_before_staging_or_stopping(tmp_path: Path) -> None:
    # GAP-1527: the rollback-copy check ran only after staging and after the
    # gateway stopped, and left the staged files behind.
    data_dir = tmp_path / "home" / ".defenseclaw"
    (data_dir / ".venv").mkdir(parents=True)
    (data_dir / "audit.db").write_bytes(b"x" * (3 * 1024 * 1024))
    failed = data_dir / ".failed-20261007T191408"
    failed.mkdir()
    (failed / "venv").write_bytes(b"x" * (2 * 1024 * 1024))
    proc = _uv_bootstrap(tmp_path, free_kb=450 * 1024, cache_mb=700)

    assert proc.returncode == 1, proc.stdout
    assert "the upgrade needs about 503 MB (400 MB for the new version and 103 MB for a rollback copy" in proc.stdout
    assert "450 MB is free" in proc.stdout and "Free at least 53 MB" in proc.stdout
    # GAP-0389: a 3 MB item is no answer to a 53 MB shortfall; what can go is named.
    assert "The largest item" not in proc.stdout
    assert f"You can remove {failed} (" in proc.stdout and "MB), the copy a failed install kept for" in proc.stdout
    assert "nothing was changed" in proc.stdout


def test_an_empty_or_partial_uv_cache_is_not_counted_as_warm(tmp_path: Path) -> None:
    # GAP-1438: an existing but empty ~/.defenseclaw/.uv/cache cut the estimate
    # to 400 MB, so a 600 MB disk passed and the build then hit ENOSPC.
    empty = tmp_path / "empty"
    empty.mkdir()
    (empty / "home" / ".defenseclaw" / ".uv" / "cache").mkdir(parents=True)
    proc = _uv_bootstrap(empty, free_kb=597 * 1024)
    assert proc.returncode == 1, proc.stdout
    assert "the install needs about 1100 MB and 597 MB is free" in proc.stdout
    assert "Installing uv" not in proc.stdout

    partial = tmp_path / "partial"
    partial.mkdir()
    proc = _uv_bootstrap(partial, free_kb=597 * 1024, cache_mb=300)
    assert proc.returncode == 1, proc.stdout
    assert "the install needs about 800 MB and 597 MB is free" in proc.stdout


def test_a_failed_python_build_removes_the_uv_it_installed_and_names_the_kept_cache(tmp_path: Path) -> None:
    # GAP-1438: after ENOSPC it said "nothing was changed" but left the uv it
    # downloaded in ~/.local/bin and 367 MB in a .uv that existed before.
    text = INSTALL_SH.read_text(encoding="utf-8")
    block = text[text.index('if ! make_venv "${STAGING}/venv"; then') :]
    block = block[: block.index("\nfi\n") + 4]
    helper = text[text.index("drop_new_uv() {") : text.index("\n}\n", text.index("drop_new_uv() {")) + 3]
    data_dir = tmp_path / "home" / ".defenseclaw"
    (data_dir / ".uv" / "cache").mkdir(parents=True)
    bin_dir = tmp_path / "home" / ".local" / "bin"
    bin_dir.mkdir(parents=True)
    for name in ("uv", "uvx", "defenseclaw-uv.sha256", "defenseclaw"):
        (bin_dir / name).write_text("x", encoding="utf-8")
    script = tmp_path / "fail.sh"
    script.write_text(
        'set -euo pipefail\nerr() { echo "err: $*"; }\ndie() { err "$@"; exit 1; }\nmake_venv() { return 1; }\n'
        f'DEFENSECLAW_HOME="{data_dir}" BIN_DIR="{bin_dir}" STAGING="{data_dir}/.staging" VERSION=1.0.1\n'
        'UV_DIR_NEW="" UV_INSTALLED=1\n' + helper + block,
        encoding="utf-8",
    )

    proc = _run([str(script)], tmp_path)

    assert proc.returncode == 1, proc.stdout
    assert sorted(p.name for p in bin_dir.iterdir()) == ["defenseclaw"]
    assert (data_dir / ".uv").is_dir()
    assert f"uv's download cache {data_dir}/.uv (" in proc.stdout and "MB) is kept" in proc.stdout
    assert "nothing was changed" not in proc.stdout


@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="root writes any folder")
def test_an_unwritable_install_folder_is_refused_before_anything_changes(tmp_path: Path) -> None:
    # GAP-0381, GAP-0420: a read-only ~/.local(/bin) failed the swap after the
    # gateway stopped, or a first install only said uv could not be installed,
    # and left ~/.defenseclaw/logs behind.
    empty = tmp_path / "assets"
    empty.mkdir()
    local = tmp_path / "home" / ".local"
    local.mkdir(parents=True)
    local.chmod(0o555)
    try:
        result = _run([str(_stamped(tmp_path)), "--local", str(empty), "--yes"], tmp_path)
    finally:
        local.chmod(0o755)

    assert result.returncode == 1, result.stdout + result.stderr
    assert f"{local} is not writable by" in result.stderr
    assert "then rerun; nothing was changed" in result.stderr
    assert not (tmp_path / "home" / ".defenseclaw").exists()


def test_an_upgrade_names_a_port_another_account_holds_before_building(tmp_path: Path) -> None:
    # GAP-0130: the upgrade of a second account on a host failed only at the
    # gateway restart, 2.5 minutes and 562 MB later, because the first
    # account's gateway holds the API port.
    text = INSTALL_SH.read_text(encoding="utf-8")
    start = text.index('if [[ -n "${PREV_VERSION}" && -n "$(gateway_pid || true)" ]] \\')
    block = text[start : text.index("\nfi\n", text.index("\n    fi\n", start)) + 4]
    assert text.index(block) < text.index('info "Building the Python environment')
    staging = tmp_path / "staging"
    (staging / "bin").mkdir(parents=True)
    gateway = staging / "bin" / "defenseclaw-gateway"

    def run(gateway_body: str, running: str) -> subprocess.CompletedProcess[str]:
        gateway.write_text("#!/bin/sh\n" + gateway_body, encoding="utf-8")
        gateway.chmod(0o755)
        script = tmp_path / "preflight.sh"
        script.write_text(
            'set -euo pipefail\nerr() { echo "err: $*"; }\ndie() { err "$@"; exit 1; }\ndrop_new_uv() { :; }\n'
            f'gateway_pid() {{ {running}; }}\nSTAGING="{staging}" PREV_VERSION=0.8.4\n' + block + 'echo "passed"\n',
            encoding="utf-8",
        )
        return _run([str(script)], tmp_path)

    held = '[ "$2" = --help ] && exit 0\necho "Error: 127.0.0.1:18970 is held by another account; use --api-port 19010" >&2\nexit 1\n'
    proc = run(held, "echo 4242")
    assert proc.returncode == 1 and "passed" not in proc.stdout, proc.stdout
    assert "err: 127.0.0.1:18970 is held by another account; use --api-port 19010; nothing was changed" in proc.stdout
    assert not staging.exists()
    (staging / "bin").mkdir(parents=True)

    # No running gateway is not restarted; a staged gateway without the check is not asked.
    assert "passed" in run(held, "return 1").stdout
    assert "passed" in run('echo "Error: unknown command" >&2\nexit 1\n', "echo 4242").stdout


def test_a_full_disk_is_checked_before_the_lock() -> None:
    # GAP-1538 / GAP-1527: a full disk showed a raw "echo: write error" or
    # "Could not take the install lock", which reads like a concurrent install.
    text = INSTALL_SH.read_text(encoding="utf-8")
    assert text.index("|| require_free_space") < text.index("# ── Lock and log")
    lock = text[text.index("# ── Lock and log") : text.index('LOG="${DEFENSECLAW_HOME}/logs/install-')]
    # take_lock reports a write failure with the hint its caller gives; the
    # home lock's is LOCK_HINT (free space, nothing changed).
    assert 'die "Could not write the install lock ${lock}/pid: ${hint}"' in lock
    assert '\ntake_lock "${LOCK_DIR}" "${LOCK_HINT}"\n' in lock
    assert "check the free space" in lock and "nothing was changed" in lock
    assert 'rm -rf "${STAGING}"' in text[text.index("if ! snapshot; then") :][:200]


def test_a_staging_copy_that_fails_on_a_full_disk_says_so_and_cleans_up(tmp_path: Path) -> None:
    # GAP-1307: "Could not get <asset>" and partial .staging files that used the last free space.
    text = INSTALL_SH.read_text(encoding="utf-8")
    helper = text[text.index("fetch_failed() {") : text.index("\n}\n", text.index("fetch_failed() {")) + 3]
    staging = tmp_path / ".staging"
    (staging / "bin").mkdir(parents=True)
    (staging / "partial.tar.gz").write_bytes(b"x" * 1024)
    fake = tmp_path / "fake"
    fake.mkdir()
    (fake / "df").write_text("#!/bin/sh\necho head\necho fs 1 1 15360 1% /\n", encoding="utf-8")
    (fake / "df").chmod(0o755)
    script = tmp_path / "fetch.sh"
    script.write_text(
        'set -euo pipefail\nerr() { echo "err: $*"; }\ndie() { err "$@"; exit 1; }\n'
        f'DEFENSECLAW_HOME="{tmp_path}" STAGING="{staging}" VERSION=1.0.1 space_needed_kb=409600\n'
        f'PATH="{fake}:/usr/bin:/bin"\n' + helper + "false || fetch_failed defenseclaw-1.0.1-linux-amd64.tar.gz\n",
        encoding="utf-8",
    )

    out = _run([str(script)], tmp_path).stdout

    assert "Ran out of disk space" in out and "15 MB is free" in out, out
    assert "Free at least 385 MB" in out and "nothing was changed" in out
    assert "Could not get" not in out
    assert not staging.exists()


def test_a_failed_python_build_removes_what_it_wrote() -> None:
    text = INSTALL_SH.read_text(encoding="utf-8")
    failure = text[text.index('if ! make_venv "${STAGING}/venv"; then') :][:400]
    assert 'rm -rf "${STAGING}"' in failure
    assert "drop_new_uv" in failure
    helper = text[text.index("drop_new_uv() {") :][:300]
    assert '[[ -z "${UV_DIR_NEW}" ]] || rm -rf "${DEFENSECLAW_HOME}/.uv"' in helper


def _install_sh_functions(*names: str) -> str:
    text = INSTALL_SH.read_text(encoding="utf-8")
    helpers = text[text.index("version_key() {") : text.index("sha256_of() {")]
    bodies = []
    for name in names:
        start = text.index(f"{name}() {{")
        bodies.append(text[start : text.index("\n}\n", start) + 3])
    return helpers + "".join(bodies)


_AGENT_SCAN = ("loaded_plugin_agents", "process_argv", "process_cwd", "process_programs", "resolved_agent_path",
               "agent_identity_audit", "npm_config_prefixes", "installed_agent_programs", "runtime_agent_programs", "agent_of",
               "assert_no_loaded_plugin_agents")


def _agent_scan(home: Path, path: list[Path], pids: list[int] | None = None,
                **env: str) -> subprocess.CompletedProcess[str]:
    # The installer's agent check, as the upgrade runs it before the gateway stops.
    # pids: the only processes it lists (GAP-1309): a real OpenCode or Amp the
    # same account runs on the test host is not one of the test's processes.
    listed = "" if pids is None else "ps() { printf '%s\\n' " + " ".join(map(str, pids)) + "; }\n"
    return subprocess.run(
        [BASH, "-c", 'set -euo pipefail\ndie() { printf "%s\\n" "$*" >&2; exit 1; }\n'
         + _install_sh_functions(*_AGENT_SCAN) + listed + "assert_no_loaded_plugin_agents\necho scan-passed\n"],
        env={"HOME": str(home), "PATH": ":".join([*map(str, path), "/usr/bin", "/bin"]), **env},
        capture_output=True, text=True, timeout=60, check=False,
    )


@pytest.mark.parametrize("installed", [False, True])
def test_agent_scan_skips_unreadable_unrelated_processes_without_audit(tmp_path: Path, installed: bool) -> None:
    home = tmp_path / "home"
    home.mkdir()
    if installed:
        entry = home / ".opencode" / "bin" / "opencode"
        entry.parent.mkdir(parents=True)
        entry.write_text("entry", encoding="utf-8")
    script = (
        _install_sh_functions(*_AGENT_SCAN)
        + "ps() { printf '%s\\n' \"$$\"; }\n"
        + "process_programs() { printf '%s\\t\\n' \"$$\"; }\n"
        + "assert_no_loaded_plugin_agents\necho scan-passed\n"
    )
    result = subprocess.run([BASH, "-c", script], env={"HOME": str(home), "PATH": "/usr/bin:/bin"},
                            capture_output=True, text=True, timeout=30, check=False)
    assert result.returncode == 0 and result.stdout.strip() == "scan-passed", (result.stdout, result.stderr)
    assert "audit:" not in result.stderr


def _program(path: Path, source: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, path)
    path.chmod(0o755)
    return path


def _manifest(folder: Path, name: str) -> None:
    # The package.json npm (or Bun) writes into an installed package.
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "package.json").write_text(json.dumps({"name": name, "version": "1.19.4", "bin": {"opencode": "bin/opencode"}}, indent=2), encoding="utf-8")


def _receipt(keg: Path, tap: str) -> None:
    # The INSTALL_RECEIPT.json Homebrew writes into a keg (Cellar/NAME/VERSION).
    keg.mkdir(parents=True, exist_ok=True)
    (keg / "INSTALL_RECEIPT.json").write_text(json.dumps({"homebrew_version": "4.6.0", "source": {"tap": tap, "spec": "stable"}}, indent=2), encoding="utf-8")


def _started(argv: list[str], program: Path, executable: str | None = None) -> subprocess.Popen[bytes]:
    proc = subprocess.Popen(argv, executable=executable, start_new_session=True,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    want = os.path.realpath(program)
    for _ in range(500):
        try:
            if os.readlink(f"/proc/{proc.pid}/exe").removesuffix(" (deleted)") == want:
                return proc
        except OSError:
            pass
        time.sleep(0.01)
    os.killpg(proc.pid, signal.SIGKILL)
    raise AssertionError(f"{argv} did not start {want}")


@pytest.mark.skipif(not Path("/proc/self/exe").exists(), reason="reads /proc/<pid>/exe")
@pytest.mark.parametrize(
    ("case", "agent"),
    [
        # GAP-1128: a normal Node project, folder, script or program that is
        # only named opencode or amp is not an agent and never refuses.
        ("node project named opencode", None),
        ("node project named amp", None),
        ("node with opencode words", None),
        ("program named opencode, not installed", None),
        ("script named opencode", None),
        ("argv0 opencode", None),
        # R1 review: an opencode-* package that OpenCode does not publish.
        ("binary of another opencode-linux-* package", None),
        # Review loop 1 (rc.7 at 677bf76b): a program PATH finds as opencode
        # or amp, or a folder only named like an agent package, is no agent.
        ("unrelated program named opencode on PATH", None),
        ("unrelated program named amp on PATH", None),
        ("opencode platform folder without its manifest", None),
        ("node script in an opencode-ai folder of another package", None),
        ("Homebrew opencode of another tap", None),
        # Only the exact installed entry refuses; these other package files
        # and the Homebrew name alone do not establish that identity.
        ("native installer opencode", "OpenCode"),
        ("opencode of Homebrew through its PATH link", None),
        ("opencode npm binary", None),
        ("opencode npm launcher through its PATH link", "OpenCode"),
        ("opencode npm launcher under bun", None),
        ("opencode npm launcher beside nvm node", "OpenCode"),
        ("amp npm launcher beside fnm node", "Amp"),
        ("nvm launcher points to another script", None),
        ("pnpm shell shim", None),
        ("opencode replaced while running", "OpenCode"),
        # GAP-1308: npm launcher beside a Node runtime replaced while it runs.
        ("opencode npm launcher beside a replaced nvm node", "OpenCode"),
        # GAP-1356: current npm opencode-ai links bin/opencode to its native
        # bin/opencode.exe, in the usual, the configured and a PATH prefix.
        ("opencode npm native exe in ~/.npm-global", "OpenCode"),
        ("opencode npm native exe in the .npmrc prefix", "OpenCode"),
        ("opencode npm native exe in NPM_CONFIG_PREFIX", "OpenCode"),
        # GAP-1761: npm expands ${VAR} in a prefix and reads the user config
        # NPM_CONFIG_USERCONFIG names and the global npmrc.
        ("opencode npm native exe in a ${HOME} .npmrc prefix", "OpenCode"),
        ("opencode npm native exe in the NPM_CONFIG_USERCONFIG prefix", "OpenCode"),
        ("opencode npm native exe in the NPM_CONFIG_GLOBALCONFIG prefix", "OpenCode"),
        ("opencode npm native exe in a PATH prefix", "OpenCode"),
        ("opencode npm native exe run by its platform hard link", "OpenCode"),
        ("opencode.exe of another package in a PATH prefix", None),
        ("amp npm package", "Amp"),
        ("native installer amp", "Amp"),
    ],
)
def test_upgrade_refuses_loaded_opencode_or_amp_before_stopping_gateway(tmp_path: Path, case: str, agent: str | None) -> None:
    # A 1.0.3 plugin already loaded in an agent cannot see a new install lock.
    # The installer must leave its gateway running until that agent exits, and
    # tell the agent by its program file, never by a name (GAP-1128).
    source = INSTALL_SH.read_text(encoding="utf-8")
    rollback = source[source.index('if [[ "${ROLLBACK}" == true ]]; then') : source.index('# ──', source.index('if [[ "${ROLLBACK}" == true ]]; then') + 1)]
    assert rollback.index("assert_no_loaded_plugin_agents") < rollback.index('stop_gateway "${BIN_DIR}/defenseclaw-gateway"')
    upgrade_guard = source.index("assert_no_loaded_plugin_agents\nWAS_RUNNING=false")
    assert upgrade_guard < source.index('stop_gateway "${BIN_DIR}/defenseclaw-gateway"', upgrade_guard)

    sleep, home, path = shutil.which("sleep", path="/usr/bin:/bin"), tmp_path / "home", []
    env: dict[str, str] = {}
    node = _program(tmp_path / "nodejs" / "bin" / "node", BASH)
    script_body = "sleep 60\n"

    def script(rel: str, body: str = script_body) -> Path:
        target = home / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body, encoding="utf-8")
        return target

    if case == "node project named opencode":
        worker = script("r31sa-work/opencode/worker.js")
        argv, program = [str(node), str(worker)], node
    elif case == "node project named amp":
        argv, program = [str(node), str(script("work/amp/index.js"))], node
    elif case == "node with opencode words":
        argv, program = [str(node), str(script("work/build.js")), "--name", "opencode", "/x/opencode/", "amp"], node
    elif case == "program named opencode, not installed":
        program = _program(home / "src" / "opencode" / "bin" / "opencode", sleep)
        argv = [str(program), "60"]
    elif case == "script named opencode":
        program = Path("/bin/sh").resolve()
        launcher = script("src/opencode/opencode", "#!/bin/sh\nsleep 60\n")
        launcher.chmod(0o755)
        argv = [str(launcher)]
    elif case == "argv0 opencode":
        program = Path(sleep)
        argv = ["opencode", "60"]
    elif case in ("unrelated program named opencode on PATH", "unrelated program named amp on PATH"):
        # A copy of sleep that PATH finds as opencode (or amp, also the name
        # of a text editor) was refused as the agent.
        program = _program(tmp_path / "tools" / "bin" / case.split()[3], sleep)
        path.append(program.parent)
        argv = [str(program), "60"]
    elif case == "opencode platform folder without its manifest":
        program = _program(tmp_path / "work" / "node_modules" / "opencode-linux-x64" / "bin" / "opencode", sleep)
        argv = [str(program), "60"]
    elif case == "node script in an opencode-ai folder of another package":
        launcher = script("work/node_modules/opencode-ai/bin/opencode")
        _manifest(launcher.parents[1], "opencode-ai-fork")
        argv, program = [str(node), str(launcher)], node
    elif case == "native installer opencode":
        program = _program(home / ".opencode" / "bin" / "opencode", sleep)
        argv = [str(program), "60"]
    elif case in ("opencode of Homebrew through its PATH link", "Homebrew opencode of another tap"):
        program = _program(tmp_path / "brew" / "Cellar" / "opencode" / "1.18.34" / "bin" / "opencode", sleep)
        _receipt(program.parents[1], "homebrew/core" if case.startswith("opencode of") else "opencode-ai/tap")
        link = tmp_path / "brew" / "bin" / "opencode"
        link.parent.mkdir(parents=True)
        link.symlink_to(program)
        path.append(link.parent)
        argv = [str(link), "60"]
    elif case == "binary of another opencode-linux-* package":
        program = _program(tmp_path / "work" / "node_modules" / "opencode-linux-tools" / "bin" / "opencode", sleep)
        _manifest(program.parents[1], "opencode-linux-tools")
        argv = [str(program), "60"]
    elif case == "opencode npm binary":
        program = _program(tmp_path / "npm" / "lib" / "node_modules" / "opencode-linux-x64" / "bin" / "opencode", sleep)
        _manifest(program.parents[1], "opencode-linux-x64")
        argv = [str(program), "60"]
    elif case in ("opencode npm launcher through its PATH link", "opencode npm launcher under bun"):
        launcher = tmp_path / "npm" / "lib" / "node_modules" / "opencode-ai" / "bin" / "opencode"
        launcher.parent.mkdir(parents=True)
        launcher.write_text(script_body, encoding="utf-8")
        _manifest(launcher.parents[1], "opencode-ai")
        link = home / ".npm-global" / "bin" / "opencode"
        link.parent.mkdir(parents=True)
        link.symlink_to(launcher)
        if case.endswith("bun"):
            program = _program(tmp_path / "bun" / "bin" / "bun", BASH)
            argv = [str(program), str(launcher)]
        else:
            path.append(link.parent)
            program, argv = node, [str(node), str(link)]
    elif case.startswith("opencode npm native exe") or case == "opencode.exe of another package in a PATH prefix":
        prefix = {
            "opencode npm native exe in ~/.npm-global": home / ".npm-global",
            "opencode npm native exe in the .npmrc prefix": tmp_path / "opt agents",
            "opencode npm native exe in NPM_CONFIG_PREFIX": tmp_path / "env-prefix",
            "opencode npm native exe in a ${HOME} .npmrc prefix": home / ".npm-packages",
            "opencode npm native exe in the NPM_CONFIG_USERCONFIG prefix": tmp_path / "user-prefix",
            "opencode npm native exe in the NPM_CONFIG_GLOBALCONFIG prefix": tmp_path / "global-prefix",
        }.get(case, tmp_path / "dc-agents")
        package = "opencode-ai-fork" if case.startswith("opencode.exe of another") else "opencode-ai"
        program = _program(prefix / "lib" / "node_modules" / package / "bin" / "opencode.exe", sleep)
        _manifest(program.parents[1], package)
        link = prefix / "bin" / "opencode"
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to(program)
        if case.endswith(".npmrc prefix"):
            home.mkdir(parents=True, exist_ok=True)
            (home / ".npmrc").write_text(f"cache=/tmp/x\nprefix = {prefix}\n", encoding="utf-8")
        elif case.endswith("NPM_CONFIG_PREFIX"):
            env["NPM_CONFIG_PREFIX"] = str(prefix)
        elif case.endswith("${HOME} .npmrc prefix"):
            (home / ".npmrc").write_text("prefix=${HOME}/.npm-packages\n", encoding="utf-8")
        elif case.endswith("CONFIG prefix"):
            config = tmp_path / "npm-config" / ("user-npmrc" if "USERCONFIG" in case else "global-npmrc")
            config.parent.mkdir(parents=True, exist_ok=True)
            config.write_text(f'prefix="{prefix}"\n', encoding="utf-8")
            env["NPM_CONFIG_USERCONFIG" if "USERCONFIG" in case else "NPM_CONFIG_GLOBALCONFIG"] = str(config)
        elif not case.endswith("~/.npm-global"):
            path.append(link.parent)
        argv = [str(link), "60"]
        if case.endswith("hard link"):
            # npm's postinstall hard-links the platform package's binary.
            platform = prefix / "lib" / "node_modules" / "opencode-linux-x64" / "bin" / "opencode"
            platform.parent.mkdir(parents=True)
            os.link(program, platform)
            program, argv = platform, [str(platform), "60"]
    elif case in ("opencode npm launcher beside nvm node", "amp npm launcher beside fnm node",
                  "nvm launcher points to another script", "pnpm shell shim",
                  "opencode npm launcher beside a replaced nvm node"):
        if case.startswith("opencode") or case.startswith("nvm"):
            agent_name, package = "opencode", "opencode-ai"
            entry_name = "bin/worker.js" if case.startswith("nvm") else "bin/opencode"
            runtime = home / ".nvm" / "versions" / "node" / "v22.0.0" / "bin"
        elif case.startswith("amp"):
            agent_name, package, entry_name = "amp", "@sourcegraph/amp", "dist/main.js"
            runtime = home / ".local" / "share" / "fnm" / "node-versions" / "v22" / "installation" / "bin"
        else:
            agent_name, package, entry_name = "opencode", "opencode-ai", "bin/opencode"
            runtime = home / ".local" / "share" / "pnpm"
        entry = runtime.parent / "lib" / "node_modules" / package / entry_name
        entry.parent.mkdir(parents=True, exist_ok=True)
        entry.write_text(script_body, encoding="utf-8")
        link = runtime / agent_name
        link.parent.mkdir(parents=True, exist_ok=True)
        if case == "pnpm shell shim":
            link.write_text("#!/bin/sh\nexec node \"$0\"\n", encoding="utf-8")
        else:
            link.symlink_to(entry)
        program = _program(runtime / "node", BASH)
        argv = [str(program), str(entry)]
    elif case == "opencode replaced while running":
        program = _program(home / ".opencode" / "bin" / "opencode", sleep)
        argv = [str(program), "60"]
    elif case == "amp npm package":
        main = tmp_path / "npm" / "lib" / "node_modules" / "@sourcegraph" / "amp" / "dist" / "main.js"
        main.parent.mkdir(parents=True)
        main.write_text(script_body, encoding="utf-8")
        _manifest(main.parents[1], "@sourcegraph/amp")
        link = home / ".npm-global" / "bin" / "amp"
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to(main)
        argv, program = [str(node), str(main)], node
    else:
        program = _program(home / ".amp" / "bin" / "amp", sleep)
        argv = [str(program), "60"]

    proc = _started(argv, program, executable=sleep if case == "argv0 opencode" else None)
    try:
        if case in ("opencode replaced while running", "opencode npm launcher beside a replaced nvm node"):
            program.unlink()
            _program(program, sleep)
        result = _agent_scan(home, path, [proc.pid], **env)
    finally:
        os.killpg(proc.pid, signal.SIGKILL)
        proc.wait()

    if agent is None:
        assert result.returncode == 0, (case, result.stdout, result.stderr)
        assert "scan-passed" in result.stdout
    else:
        assert result.returncode == 1, (case, result.stdout, result.stderr)
        assert "Close OpenCode and Amp completely" in result.stderr
        assert f"{agent} (PID {proc.pid})" in result.stderr, result.stderr


@pytest.mark.parametrize(("case", "want"), [
    ("installed binary", "OpenCode"),
    ("PATH name", ""),
    ("installed Node entry", "OpenCode"),
    ("other file in package", ""),
    ("quoted option value", ""),
    ("option value with entry path", ""),
    ("later argument", ""),
    ("Bun script", ""),
    ("deleted binary", "OpenCode"),
])
def test_live_agent_identity_uses_only_an_exact_entry(tmp_path: Path, case: str, want: str) -> None:
    entry = tmp_path / "node_modules" / "opencode-ai" / "bin" / "opencode"
    other = entry.with_name("worker.js")
    binary = tmp_path / "native" / "opencode"
    for path in (entry, other, binary):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("agent fixture", encoding="utf-8")
    installed = f"OpenCode\t{binary}\nOpenCode\t{entry}"
    program = str(binary) if case == "installed binary" else "/usr/bin/node"
    words = ["node", str(entry)]
    if case == "PATH name":
        program, words = str(tmp_path / "tools" / "opencode"), []
    elif case == "other file in package":
        words = ["node", str(other)]
    elif case == "quoted option value":
        words = ["node", "--conditions=dev " + str(entry), str(other)]
    elif case == "option value with entry path":
        words = ["node", "--conditions", str(entry), str(other)]
    elif case == "later argument":
        words = ["node", str(other), str(entry)]
    elif case == "Bun script":
        program = "/usr/bin/bun"
    elif case == "deleted binary":
        program, words = str(binary) + " (deleted)", []
    script = (_install_sh_functions("agent_identity_audit", "resolved_agent_path", "agent_of")
              + 'agent_of "$1" "$2" 0 "${@:3}"')
    result = subprocess.run([BASH, "-c", script, "test", program, installed, *words],
                            capture_output=True, text=True, timeout=30, check=False)
    assert result.returncode == 0, result.stderr
    assert result.stdout == want, (case, result.stdout, result.stderr)


@pytest.mark.skipif(not Path("/proc/self/exe").exists(), reason="reads /proc/<pid>/exe")
def test_agent_scan_tests_list_only_their_own_processes(tmp_path: Path) -> None:
    # GAP-1309: the scan lists every process of the account, so a real nvm
    # OpenCode this user runs on the test host failed expected-pass tests.
    # Here such an agent runs beside an unrelated process: the scan the tests
    # use sees only the process it is given.
    home = tmp_path / "home"
    runtime = home / ".nvm" / "versions" / "node" / "v22.0.0" / "bin"
    entry = runtime.parent / "lib" / "node_modules" / "opencode-ai" / "bin" / "opencode"
    entry.parent.mkdir(parents=True)
    entry.write_text("sleep 60\n", encoding="utf-8")
    node = _program(runtime / "node", BASH)
    (runtime / "opencode").symlink_to(entry)
    agent = _started([str(node), str(entry)], node)
    sleep = shutil.which("sleep", path="/usr/bin:/bin")
    other = _started([sleep, "60"], Path(sleep))
    try:
        alone = _agent_scan(home, [], [other.pid])
        seen = _agent_scan(home, [], [agent.pid])
    finally:
        for proc in (agent, other):
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()
    assert alone.returncode == 0 and "scan-passed" in alone.stdout, (alone.stdout, alone.stderr)
    assert seen.returncode == 1 and f"OpenCode (PID {agent.pid})" in seen.stderr, (seen.stdout, seen.stderr)


@pytest.mark.skipif(shutil.which("node") is None or not Path("/proc/self/exe").exists(), reason="runs Node, reads /proc")
@pytest.mark.parametrize("manifest", [
    '{"author":{"name":"opencode-ai"},"name":"innocent-tool"}',
    '{"name":"innocent-tool","dependencies":{"opencode-ai":"*"}}',
    '{"name":"opencode-ai"}',
])
def test_manifest_names_never_establish_a_live_entry(tmp_path: Path, manifest: str) -> None:
    home = tmp_path / "home"
    package = home / ".npm-global" / "lib" / "node_modules" / "opencode-ai"
    package.mkdir(parents=True)
    (package / "package.json").write_text(manifest, encoding="utf-8")
    script = package / "worker.js"
    script.write_text("setTimeout(() => {}, 60000)\n", encoding="utf-8")
    node = Path(shutil.which("node")).resolve()
    proc = _started([str(node), str(script)], node)
    try:
        result = _agent_scan(home, [], [proc.pid])
    finally:
        os.killpg(proc.pid, signal.SIGKILL)
        proc.wait()
    assert result.returncode == 0 and "scan-passed" in result.stdout, (result.stdout, result.stderr)


def test_the_installed_agents_are_those_of_the_native_installers(tmp_path: Path) -> None:
    # Only a native fixed path or a package manager's launcher link records an
    # entry. An unrelated PATH name and a package manifest never do.
    sleep, home, tools = shutil.which("sleep", path="/usr/bin:/bin"), tmp_path / "home", tmp_path / "tools"
    _program(tools / "opencode", sleep)
    _program(tools / "amp", sleep)
    native = _program(home / ".amp" / "bin" / "amp", sleep)
    entry = home / ".npm-global" / "lib" / "node_modules" / "opencode-ai" / "bin" / "opencode"
    entry.parent.mkdir(parents=True)
    entry.write_text("agent entry", encoding="utf-8")
    link = home / ".npm-global" / "bin" / "opencode"
    link.parent.mkdir(parents=True)
    link.symlink_to(entry)
    unrelated_link = home / ".local" / "bin" / "opencode"
    unrelated_link.parent.mkdir(parents=True)
    unrelated_link.symlink_to(tools / "opencode")
    result = subprocess.run(
        [BASH, "-c", _install_sh_functions("resolved_agent_path", "npm_config_prefixes", "installed_agent_programs") + "installed_agent_programs"],
        env={"HOME": str(home), "PATH": f"{tools}:/usr/bin:/bin"}, capture_output=True, text=True, timeout=30, check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == [f"Amp\t{native.resolve()}", f"OpenCode\t{entry.resolve()}"]


@pytest.mark.skipif(shutil.which("node") is None or not Path("/proc/self/exe").exists(), reason="runs Node, reads /proc")
@pytest.mark.parametrize("case", ["value", "value with a space", "--option=value with a space", "title with a space", "exact entry as option value", "agent in a folder with a space"])
def test_a_real_node_option_value_naming_opencode_ai_does_not_refuse(tmp_path: Path, case: str) -> None:
    # R1 review: a Node worker started with --conditions <a path in
    # opencode-ai> was taken for OpenCode. Review loop 2: ps joins the
    # arguments with spaces, so a quoted value with a space in it was split
    # and its path read as the script. The package here is a real opencode-ai.
    node = Path(shutil.which("node")).resolve()
    work = tmp_path / ("John Smith" if case.startswith("agent") else "work")
    worker = work / "worker.js"
    worker.parent.mkdir(parents=True)
    worker.write_text("setTimeout(() => {}, 60000)\n", encoding="utf-8")
    package = work / "node_modules" / "opencode-ai"
    _manifest(package, "opencode-ai")
    (package / "feature").write_text("", encoding="utf-8")
    launcher = package / "bin" / "opencode"
    launcher.parent.mkdir()
    launcher.write_text("setTimeout(() => {}, 60000)\n", encoding="utf-8")
    home = tmp_path / "home"
    entry_link = home / ".npm-global" / "bin" / "opencode"
    entry_link.parent.mkdir(parents=True)
    entry_link.symlink_to(launcher)
    options = {
        "value": ["--conditions", str(package / "feature")],
        "value with a space": ["--conditions", f"dev {package / 'feature'}"],
        "--option=value with a space": [f"--conditions=dev {package / 'feature'}"],
        "title with a space": ["--title", f"worker {launcher}"],
        "exact entry as option value": ["--conditions", str(launcher)],
        "agent in a folder with a space": [],
    }[case]
    script = launcher if case.startswith("agent") else worker
    proc = _started([str(node), *options, str(script)], node)
    try:
        result = _agent_scan(home, [], [proc.pid])
    finally:
        os.killpg(proc.pid, signal.SIGKILL)
        proc.wait()
    if case.startswith("agent"):
        assert result.returncode == 1 and f"OpenCode (PID {proc.pid})" in result.stderr, (result.stdout, result.stderr)
    else:
        assert result.returncode == 0, (result.stdout, result.stderr)
        assert "scan-passed" in result.stdout


@pytest.mark.skipif(shutil.which("node") is None or not Path("/proc/self/exe").exists(), reason="runs Node, reads /proc")
@pytest.mark.parametrize(("script_name", "expected_agent"), [
    ("bin/opencode", True),
    ("feature.js", False),
    ("bin/other.js", False),
])
def test_only_the_installed_node_entry_is_a_live_agent(tmp_path: Path, script_name: str, expected_agent: bool) -> None:
    # npm's launcher records one entry. A different script in the same real
    # opencode-ai package has the same manifest, but is not that entry.
    node = Path(shutil.which("node")).resolve()
    home = tmp_path / "home"
    package = home / ".npm-global" / "lib" / "node_modules" / "opencode-ai"
    _manifest(package, "opencode-ai")
    for name in ("bin/opencode", "feature.js", "bin/other.js"):
        target = package / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("setTimeout(() => {}, 60000)\n", encoding="utf-8")
    launcher = home / ".npm-global" / "bin" / "opencode"
    launcher.parent.mkdir(parents=True)
    launcher.symlink_to(package / "bin" / "opencode")
    proc = _started([str(node), str(package / script_name)], node)
    try:
        result = _agent_scan(home, [], [proc.pid])
    finally:
        os.killpg(proc.pid, signal.SIGKILL)
        proc.wait()
    if expected_agent:
        assert result.returncode == 1 and f"OpenCode (PID {proc.pid})" in result.stderr, (result.stdout, result.stderr)
    else:
        assert result.returncode == 0 and "scan-passed" in result.stdout, (result.stdout, result.stderr)


@pytest.mark.skipif(not Path("/proc/self/exe").exists(), reason="Linux /proc")
def test_the_arguments_are_read_with_their_boundaries(tmp_path: Path) -> None:
    # Review loop 2: process_argv gives each argument whole, as the kernel
    # keeps it; ps would join "a b" and "c  d" into one line of words.
    words = ["-c", "sleep 60; :", "a b", "c  d", "", "e"]
    proc = subprocess.Popen([BASH, *words], start_new_session=True)
    try:
        for _ in range(500):
            if Path(f"/proc/{proc.pid}/cmdline").read_bytes().count(b"\0") == len(words) + 1:
                break
            time.sleep(0.01)
        script = _install_sh_functions("process_argv") + 'OSTYPE=linux-gnu\nprocess_argv "$1"'
        own = subprocess.run([BASH, "-c", script, "argv", str(proc.pid)], capture_output=True, timeout=30, check=False)
    finally:
        os.killpg(proc.pid, signal.SIGKILL)
        proc.wait()
    assert own.returncode == 0, own.stderr
    assert own.stdout.split(b"\0")[1:-1] == [w.encode() for w in words]
    gone = subprocess.run([BASH, "-c", script, "argv", str(proc.pid)], capture_output=True, timeout=30, check=False)
    assert (gone.returncode != 0, gone.stdout) == (True, b"")


def test_a_relative_script_is_the_process_folders_not_the_installers(tmp_path: Path) -> None:
    # A relative Node script resolves from its process's cwd, then must equal
    # the recorded entry; the installer's cwd cannot supply that identity.
    installer_dir, process_dir = tmp_path / "installer", tmp_path / "process"
    entry = installer_dir / "node_modules" / "opencode-ai" / "bin" / "opencode"
    entry.parent.mkdir(parents=True)
    entry.write_text("", encoding="utf-8")
    other = process_dir / "node_modules" / "opencode-ai" / "bin" / "opencode"
    other.parent.mkdir(parents=True)
    other.write_text("", encoding="utf-8")
    funcs = _install_sh_functions("agent_identity_audit", "resolved_agent_path", "agent_of")

    def told(cwd: str | None) -> str:
        stub = f"process_cwd() {{ printf '%s' '{cwd}'; }}\n" if cwd else "process_cwd() { return 1; }\n"
        result = subprocess.run(
            [BASH, "-c", funcs + stub + f'agent_of /usr/bin/node "OpenCode\t{entry}" 0 node node_modules/opencode-ai/bin/opencode'],
            cwd=installer_dir, capture_output=True, text=True, timeout=30, check=False,
        )
        assert result.returncode == 0, result.stderr
        return result.stdout

    assert told(str(process_dir)) == ""
    assert told(None) == ""
    assert told(str(installer_dir)) == "OpenCode"


@pytest.mark.skipif(not Path("/proc/self/exe").exists(), reason="Linux /proc")
@pytest.mark.parametrize("installed", [False, True])
def test_a_process_gone_since_ps_listed_it_is_skipped_without_lsof(tmp_path: Path, installed: bool) -> None:
    # R1 review: a matched process that exited after the ps snapshot sent
    # Linux to the macOS lsof lookup, a scan of seconds per process.
    gone = subprocess.Popen(["true"])
    gone.wait()
    stubs, marker = tmp_path / "stubs", tmp_path / "lsof-ran"
    stubs.mkdir()
    (stubs / "ps").write_text(f"#!/bin/sh\necho '{gone.pid}'\n", encoding="utf-8")
    (stubs / "lsof").write_text(f"#!/bin/sh\ntouch '{marker}'\nsleep 30\n", encoding="utf-8")
    for stub in stubs.iterdir():
        stub.chmod(0o755)
    home = tmp_path / "home"
    if installed:
        entry = home / ".opencode" / "bin" / "opencode"
        entry.parent.mkdir(parents=True)
        entry.write_text("entry", encoding="utf-8")
    started = time.monotonic()
    result = _agent_scan(home, [stubs])
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert "scan-passed" in result.stdout
    if installed:
        assert f"audit: live-agent identity unproven for PID {gone.pid}: process vanished during lookup" in result.stderr
    else:
        assert "audit:" not in result.stderr
    assert not marker.exists()
    assert time.monotonic() - started < 10


@pytest.mark.parametrize("installed", [False, True])
def test_an_unreadable_process_list_is_audited_without_refusal(tmp_path: Path, installed: bool) -> None:
    stubs = tmp_path / "stubs"
    stubs.mkdir()
    ps = stubs / "ps"
    ps.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    ps.chmod(0o755)
    home = tmp_path / "home"
    if installed:
        entry = home / ".opencode" / "bin" / "opencode"
        entry.parent.mkdir(parents=True)
        entry.write_text("entry", encoding="utf-8")
    result = _agent_scan(home, [stubs])
    assert result.returncode == 0 and "scan-passed" in result.stdout, (result.stdout, result.stderr)
    if installed:
        assert "audit: live-agent identity unproven for PID 0: process list unreadable" in result.stderr
    else:
        assert "audit:" not in result.stderr


@pytest.mark.skipif(not Path("/proc/self/exe").exists(), reason="Linux /proc")
def test_the_program_lookup_reads_the_kernel_path() -> None:
    script = _install_sh_functions("process_programs") + 'OSTYPE=linux-gnu\nprocess_programs "$$"'
    result = subprocess.run([BASH, "-c", script], capture_output=True, text=True, timeout=30, check=False)
    assert result.returncode == 0, result.stderr
    pid, path = result.stdout.strip().split("\t")
    assert pid.isdecimal() and Path(path).name.startswith("bash"), result.stdout


def test_a_refused_upgrade_leaves_no_staged_release(tmp_path: Path) -> None:
    # GAP-1120: an upgrade the OpenCode check refused after staging left an
    # 872 MiB .staging. Every stop between staging and the swap (a refusal, a
    # failed check, a cancel) now drops what it staged and the uv files it
    # added; from the swap on, its own undo does (drop_staging).
    source = INSTALL_SH.read_text(encoding="utf-8")
    # The EXIT trap gives back the locks that are still this run's (release_locks).
    exit_trap = next(line for line in source.splitlines() if line.startswith("trap ") and line.endswith("' EXIT") and "release_locks" in line)
    staged = source.index('mkdir -p "${STAGING}/bin"\nUNSWAPPED_STAGE=1\n')
    assert source.index(exit_trap) < staged
    assert staged < source.index("assert_no_loaded_plugin_agents\nWAS_RUNNING=false") < source.index('UNSWAPPED_STAGE=""\n')
    assert source.index('UNSWAPPED_STAGE=""\n') < source.index("if ! snapshot; then")
    assert source.count("UNSWAPPED_STAGE=") == 2
    for swapped in (False, True):
        home = tmp_path / str(swapped) / ".defenseclaw"
        (home / ".staging" / "bin").mkdir(parents=True)
        (home / ".staging" / "bin" / "defenseclaw-gateway").write_bytes(b"x" * 4096)
        (home / ".uv").mkdir()
        lock = home / ".install.lock"
        lock.mkdir()
        script = (
            "set -euo pipefail\n"
            'err() { echo "x $*" >&2; }\ndie() { err "$@"; exit 1; }\n'
            f'DEFENSECLAW_HOME="{home}" STAGING="{home}/.staging" LOCK_DIR="{lock}" BIN_DIR="{tmp_path}/bin" SELF_TMP=""\n'
            'UV_DIR_NEW=1 UV_INSTALLED="" LOCK_STARTED=1 DATA_LOCK_DIRS=() MADE_DATA_DIRS=()\n'
            'echo $$ > "${LOCK_DIR}/pid"; echo 1 > "${LOCK_DIR}/started"\n'
            + _install_sh_functions("drop_unswapped_stage", "lock_is_ours", "release_locks")
            + exit_trap + "\nUNSWAPPED_STAGE=1\n"
            + ('UNSWAPPED_STAGE=""\n' if swapped else "")
            + 'die "Close OpenCode and Amp completely before installing or upgrading DefenseClaw, then run this installer again; gateway still running: OpenCode (PID 1)"\n'
        )
        result = subprocess.run([BASH, "-c", script], capture_output=True, text=True, timeout=30, check=False)
        assert result.returncode == 1, result.stderr
        assert "Close OpenCode and Amp completely" in result.stderr
        assert not lock.exists()
        if swapped:
            assert (home / ".staging" / "bin" / "defenseclaw-gateway").exists() and (home / ".uv").exists()
        else:
            assert sorted(p.name for p in home.iterdir()) == []


def test_a_later_upgrade_keeps_the_0_x_audit_history(tmp_path: Path) -> None:
    # GAP-1360: previous/ held the only copy of the 0.x audit history, and the
    # next upgrade replaced it.
    dc_home = tmp_path / "dc"
    (dc_home / "previous" / "data").mkdir(parents=True)
    (dc_home / "previous" / "data" / "audit.db").write_text("0.x history", encoding="utf-8")
    (dc_home / "previous" / "VERSION").write_text("0.8.10\n", encoding="utf-8")
    script = tmp_path / "keep.sh"
    script.write_text(
        'set -euo pipefail\ninfo() { echo "info: $*"; }\n'
        + _install_sh_functions("keep_rolled_back_data")
        + f'DEFENSECLAW_HOME="{dc_home}" PREVIOUS="{dc_home}/previous"\nkeep_rolled_back_data\n',
        encoding="utf-8",
    )

    out = _run([str(script)], tmp_path).stdout

    kept = list((dc_home / "backups").glob("audit-history-0.8.10-*/audit.db"))
    assert len(kept) == 1 and kept[0].read_text(encoding="utf-8") == "0.x history", out
    assert "info: Kept the audit history DefenseClaw 0.8.10 recorded in" in out


def test_upgrade_from_0_8_never_claims_a_uv_as_the_installers() -> None:
    # p0 GAP-1456: the 0.8.x installer ran uv's own installer and kept no
    # record, and a uv the user installed the same way just before is
    # indistinguishable from it. The upgrade recorded such a uv (and its
    # cache and ~/.sigstore) for `uninstall --all --binaries` to delete.
    # Only install_uv, which downloaded the uv itself, writes the record.
    text = INSTALL_SH.read_text(encoding="utf-8")
    assert "legacy-install-leftovers" not in text
    assert "LEGACY_UV_RECORD" not in text
    assert "uv-receipt.json" not in text


@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="root ignores the read-only bin folder")
def test_a_restore_that_stopped_part_way_keeps_the_restored_data(tmp_path: Path) -> None:
    # GAP-0624: a restore that failed on a full disk kept its snapshot; the
    # next run set the data it had put back aside as the failed install and
    # put nothing back, so config.yaml was left only in .failed-<time>.
    dc_home, bin_dir = tmp_path / "dc", tmp_path / "bin"
    snap = dc_home / "previous.new"
    for root in (dc_home, snap / "data"):
        (root / "policies").mkdir(parents=True)
        (root / "config.yaml").write_text("config_version: 7\n", encoding="utf-8")
        (root / "policies" / "custom.rego").write_text("package custom\n", encoding="utf-8")
    (snap / "bin").mkdir()
    (snap / "bin" / "defenseclaw-gateway").write_text("0.8.4\n", encoding="utf-8")
    (snap / "venv").mkdir()
    (snap / "COMPLETE").touch()
    (dc_home / ".venv").mkdir()
    bin_dir.mkdir()
    text = INSTALL_SH.read_text(encoding="utf-8")
    script = tmp_path / "restore.sh"
    script.write_text(
        'set -euo pipefail\ninfo() { :; }\nwarn() { :; }\nerr() { echo "err: $*"; }\nrestart_old() { :; }\n'
        + "".join(line + "\n" for line in text.splitlines() if line.startswith(("readonly MANAGED_", "readonly NOT_DATA")))
        + f'DEFENSECLAW_HOME="{dc_home}" SNAP="{snap}" VENV="{dc_home}/.venv" BIN_DIR="{bin_dir}"\n'
        + f'INSTALLER_DIR="{dc_home}/installer" APP_PATH="" VERSION=1.0.0 PREV_VERSION=0.8.4\n'
        + _install_sh_functions("is_machinery", "data_entries", "restore_external_config", "restore_snapshot")
        + "restore_snapshot\n",
        encoding="utf-8",
    )
    bin_dir.chmod(0o555)
    try:
        first = _run([str(script)], tmp_path)
    finally:
        bin_dir.chmod(0o755)
    assert "back completely" in first.stdout and snap.is_dir(), first

    _run([str(script)], tmp_path)

    assert not snap.exists()
    assert (dc_home / "config.yaml").read_text(encoding="utf-8") == "config_version: 7\n"
    assert (dc_home / "policies" / "custom.rego").is_file()
    assert (bin_dir / "defenseclaw-gateway").read_text(encoding="utf-8") == "0.8.4\n"


def test_interrupted_venv_restore_keeps_the_previous_cli(tmp_path: Path) -> None:
    # The old venv has already left the snapshot, but VENV_BACK was never
    # written. A retry must leave it live instead of moving it aside again.
    home, bin_dir = tmp_path / "dc", tmp_path / "bin"
    snap = home / "previous.new"
    for path in (snap / "bin", snap / "data", snap / "venv", home / ".venv", bin_dir):
        path.mkdir(parents=True, exist_ok=True)
    (snap / "venv" / "version").write_text("old", encoding="utf-8")
    (home / ".venv" / "version").write_text("failed", encoding="utf-8")
    (snap / "data" / "config.yaml").write_text("old", encoding="utf-8")
    (home / "config.yaml").write_text("failed", encoding="utf-8")
    text = INSTALL_SH.read_text(encoding="utf-8")
    script = tmp_path / "restore.sh"
    script.write_text(
        "set -euo pipefail\n"
        + "".join(line + "\n" for line in text.splitlines() if line.startswith(("readonly MANAGED_", "readonly NOT_DATA")))
        + 'info() { :; }\nwarn() { :; }\nerr() { :; }\nrestart_old() { :; }\n'
        + f'DEFENSECLAW_HOME="{home}" BIN_DIR="{bin_dir}" SNAP="{snap}" VENV="{home}/.venv" '
        + f'INSTALLER_DIR="{home}/installer" APP_PATH="" VERSION=1.0.1 PREV_VERSION=1.0.0\n'
        + 'mv() {\n'
        + '  if [[ "${STOP_AFTER_VENV_MOVE:-}" == 1 && "$1" == "${SNAP}/venv" ]]; then\n'
        + '    command mv "$@"; exit 99\n'
        + '  fi\n'
        + '  command mv "$@"\n'
        + '}\n'
        + _install_sh_functions("is_machinery", "data_entries", "restore_external_config", "restore_snapshot")
        + "restore_snapshot\n",
        encoding="utf-8",
    )

    first = _run([str(script)], tmp_path, STOP_AFTER_VENV_MOVE="1")
    assert first.returncode == 99, first
    assert (home / ".venv" / "version").read_text(encoding="utf-8") == "old"
    assert not (snap / "VENV_BACK").exists()

    second = _run([str(script)], tmp_path)
    assert second.returncode == 0, second
    assert (home / ".venv" / "version").exists()
    assert (home / ".venv" / "version").read_text(encoding="utf-8") == "old"
    assert (home / "config.yaml").read_text(encoding="utf-8") == "old"
    assert not snap.exists()


def test_the_cli_says_an_install_is_running_during_the_swap(tmp_path: Path) -> None:
    # GAP-0391: while the swap moved the venv, a second `defenseclaw rollback`
    # (or any command after a killed run) failed with "command not found".
    bin_dir, snap = tmp_path / "bin", tmp_path / "snap"
    (snap / "bin").mkdir(parents=True)
    bin_dir.mkdir()
    (bin_dir / "defenseclaw").symlink_to(tmp_path / "venv" / "bin" / "defenseclaw")
    (snap / "bin" / "defenseclaw").symlink_to(tmp_path / "venv" / "bin" / "defenseclaw")
    text = INSTALL_SH.read_text(encoding="utf-8")
    script = tmp_path / "swap.sh"
    script.write_text(
        "set -euo pipefail\n"
        + "".join(line + "\n" for line in text.splitlines() if line.startswith(("readonly MANAGED_LINKS", "readonly BUSY_")))
        + f'BIN_DIR="{bin_dir}" INSTALL_AGAIN="bash install.sh --local /assets"\n'
        + _install_sh_functions("write_busy_shim", "restore_links")
        + 'write_busy_shim\n"${BIN_DIR}/defenseclaw" --version || echo "rc=$?"\n',
        encoding="utf-8",
    )

    during = _run([str(script)], tmp_path)
    after = subprocess.run([str(bin_dir / "defenseclaw")], capture_output=True, text=True, check=False)

    assert "a DefenseClaw install is running (pid " in during.stderr and "rc=1" in during.stdout, during
    assert "stopped before it finished; run the installer again to finish or undo it: bash install.sh" in after.stderr
    restore = tmp_path / "restore.sh"
    restore.write_text(script.read_text(encoding="utf-8").replace("write_busy_shim\n", f'restore_links "{snap}"\n'))
    _run([str(restore)], tmp_path)
    assert (bin_dir / "defenseclaw").is_symlink()


def test_an_undone_install_drops_what_it_staged() -> None:
    # GAP-0388: after a rolled-back upgrade .staging (722 MB) and the new .uv
    # (478 MB) stayed next to the .failed-<time> copy, and only that was named.
    text = INSTALL_SH.read_text(encoding="utf-8")
    swap = text[text.index("if ! swap_in; then") : text.index("\nfinish_swap\n")]
    restores = swap.count("restore_snapshot\n")
    assert restores == 2 and swap.count("restore_snapshot\n    drop_staging\n") + swap.count(
        "restore_snapshot\n        drop_staging\n"
    ) == restores
    body = text[text.index("drop_staging() {") : text.index("\n}\n", text.index("drop_staging() {"))]
    assert 'rm -rf "${STAGING}"' in body and "drop_new_uv" in body


def test_a_full_disk_does_not_stop_the_restore_of_the_previous_install(tmp_path: Path) -> None:
    # GAP-0375: with no room for the .failed-<time> copy, its mkdir ended the
    # restore under set -e: no CLI, no gateway, and no word of what to do.
    home, bin_dir = tmp_path / "dc", tmp_path / "bin"
    snap = home / "previous.new"
    for path in (snap / "bin", snap / "venv" / "bin", snap / "data", home / ".venv" / "bin", bin_dir):
        path.mkdir(parents=True, exist_ok=True)
    (snap / "data" / "config.yaml").write_text("old\n", encoding="utf-8")
    (home / "config.yaml").write_text("new\n", encoding="utf-8")
    (snap / "venv" / "OLD").write_text("", encoding="utf-8")
    (snap / "bin" / "defenseclaw-gateway").write_text("old gateway", encoding="utf-8")
    (snap / "bin" / "defenseclaw").symlink_to(home / ".venv" / "bin" / "defenseclaw")
    text = INSTALL_SH.read_text(encoding="utf-8")
    script = tmp_path / "restore.sh"
    script.write_text(
        "set -euo pipefail\n"
        + "".join(line + "\n" for line in text.splitlines() if line.startswith(("readonly MANAGED_", "readonly NOT_DATA")))
        + 'info() { echo "info: $*"; }\nwarn() { echo "warn: $*"; }\nerr() { echo "err: $*"; }\nrestart_old() { :; }\n'
        # The disk is full: a new folder cannot be made.
        + 'mkdir() { case "$*" in *.failed-*) echo "mkdir: No space left on device" >&2; return 1 ;; esac; command mkdir "$@"; }\n'
        + _install_sh_functions("is_machinery", "data_entries", "restore_external_config", "restore_snapshot")
        + f'DEFENSECLAW_HOME="{home}" BIN_DIR="{bin_dir}" SNAP="{snap}" VENV="{home}/.venv" INSTALLER_DIR="{home}/installer"\n'
        + 'APP_PATH="" VERSION=1.0.1 PREV_VERSION=1.0.0\nrestore_snapshot\necho "done"\n',
        encoding="utf-8",
    )

    out = _run([str(script)], tmp_path).stdout

    assert out.rstrip().endswith("done"), out
    assert "warn: There was no room to keep the failed 1.0.1 install for troubleshooting, so it was deleted" in out
    assert (home / ".venv" / "OLD").exists() and (home / "config.yaml").read_text(encoding="utf-8") == "old\n"
    assert (bin_dir / "defenseclaw-gateway").read_text(encoding="utf-8") == "old gateway"
    assert (bin_dir / "defenseclaw").is_symlink() and not snap.exists()
    assert not list(home.glob(".failed-*"))


def test_a_restore_that_leaves_the_old_gateway_down_says_so(tmp_path: Path) -> None:
    # GAP-1349: the restore said "Your previous install is back" while the
    # gateway that ran before stayed down.
    script = tmp_path / "restore.sh"
    script.write_text(
        'set -euo pipefail\ninfo() { echo "info: $*"; }\nwarn() { echo "warn: $*"; }\n'
        + "start_gateway() { return 1; }\n"
        + _install_sh_functions("restart_old")
        + f'DEFENSECLAW_HOME="{tmp_path}" WAS_RUNNING=true RESTORED_NOTE="Your previous install is back."\n'
        + 'restart_old; echo "note: ${RESTORED_NOTE}"\n',
        encoding="utf-8",
    )

    out = _run([str(script)], tmp_path).stdout

    assert "warn: The gateway that was running before did not start again" in out, out
    assert "info: Start it with: defenseclaw-gateway start" in out
    assert "note: Your previous install is back, but its gateway is not running (see above)." in out


@pytest.mark.allow_subprocess
def test_failed_readiness_preserves_hooks_without_restarting_the_old_setup(tmp_path: Path) -> None:
    home, bin_dir = tmp_path / "dc", tmp_path / "bin"
    snap = home / "previous.new"
    for path in (snap / "bin", snap / "venv" / "bin", snap / "data", home / ".venv" / "bin", bin_dir):
        path.mkdir(parents=True, exist_ok=True)
    (snap / "data" / "config.yaml").write_text("previous config\n", encoding="utf-8")
    (home / "config.yaml").write_text("candidate config\n", encoding="utf-8")
    (snap / "bin" / "defenseclaw-gateway").write_text("previous gateway", encoding="utf-8")
    settings = tmp_path / "settings.json"
    settings.write_text("working native hooks", encoding="utf-8")
    text = INSTALL_SH.read_text(encoding="utf-8")
    startup = text[text.index("\nSTART_RC=0\n") + 1 : text.index("\nfinish_swap\n")]
    script = tmp_path / "failed-start.sh"
    script.write_text(
        "set -euo pipefail\n"
        + "".join(line + "\n" for line in text.splitlines() if line.startswith(("readonly MANAGED_", "readonly NOT_DATA")))
        + 'info() { echo "info: $*"; }\nwarn() { echo "warn: $*"; }\nerr() { echo "err: $*"; }\n'
        + 'stop_gateway() { :; }\ndrop_staging() { :; }\ndie() { echo "$*"; exit 1; }\n'
        + 'starts=0\nstart_gateway() { starts=$((starts+1)); [ "$starts" -ne 1 ] || return 1; '
        + 'printf "hookless predecessor" > "$settings"; }\n'
        + _install_sh_functions("is_machinery", "data_entries", "restore_external_config", "restore_snapshot", "restart_old")
        + 'DEFENSECLAW_HOME="$1" BIN_DIR="$2" SNAP="$1/previous.new" VENV="$1/.venv" INSTALLER_DIR="$1/installer"\n'
        + 'settings="$3" APP_PATH="" VERSION=1.0.4 PREV_VERSION=1.0.2 WAS_RUNNING=true RESTORED_NOTE="previous install" LOG="install.log"\n'
        + startup,
        encoding="utf-8",
    )
    result = _run([str(script), str(home), str(bin_dir), str(settings)], tmp_path)
    assert result.returncode == 1, result
    assert settings.read_text(encoding="utf-8") == "working native hooks", result.stdout + result.stderr
    assert (home / "config.yaml").read_text(encoding="utf-8") == "previous config\n"
    assert f"{bin_dir}/defenseclaw-gateway start" in result.stdout


def test_python_environment_step_says_it_can_take_minutes() -> None:
    # GAP-1665: a first Windows install sat on this line for about 7 minutes.
    hint = "Building the Python environment (a first install can take several minutes)"
    windows = (ROOT / "scripts" / "install.ps1").read_text(encoding="utf-8")
    assert hint in windows
    assert hint in INSTALL_SH.read_text(encoding="utf-8")
    body = windows[windows.index("function New-Venv") :]
    body = body[: body.index("\n}\n")]
    assert body.index("Installing the Python packages") < body.index("Invoke-UvPipInstall $lockArgs")
    assert body.index("Installing the DefenseClaw package") < body.index("$Wheel")


def test_the_two_python_environment_builds_are_named() -> None:
    # GAP-1727: the staging build and the final build printed the same two
    # lines, so the second pair looked like the installer was looping.
    windows = (ROOT / "scripts" / "install.ps1").read_text(encoding="utf-8")
    body = windows[windows.index("function New-Venv") :]
    body = body[: body.index("\n}\n")]
    assert 'Write-Info "Installing the Python packages into $Where"' in body
    assert 'Write-Info "Installing the DefenseClaw package into $Where and compiling it"' in body
    assert 'New-Venv (Join-Path $Staging "venv") "the staging environment"' in windows
    install_new = windows[windows.index("function Install-New") :]
    install_new = install_new[: install_new.index("\n}\n")]
    assert "Building the final Python environment in $Venv" in install_new
    assert 'New-Venv $Venv "the final environment"' in install_new


def test_an_older_release_over_a_newer_one_is_called_a_downgrade(tmp_path: Path) -> None:
    # GAP-0287: 1.0.23's installer over 1.0.24 asked nothing and said "Upgraded from 1.0.24".
    text = INSTALL_SH.read_text(encoding="utf-8")
    helpers = text[text.index("version_key() {") : text.index("is_version() {")]
    start = text.index('    changed="Upgraded from')
    end = text.index("\n", text.index('printf "  ${changed}. Undo with', start))
    script = tmp_path / "end.sh"
    for version, prev, word in (("1.0.23", "1.0.24", "Downgraded"), ("1.0.25", "1.0.24", "Upgraded")):
        script.write_text(f"{helpers}CYAN= NC=\nVERSION={version} PREV_VERSION={prev}\n{text[start:end]}\n")
        assert _run([str(script)], tmp_path).stdout.strip() == f"{word} from {prev}. Undo with: defenseclaw rollback"
    assert 'ask_yes_no "Downgrade DefenseClaw ${PREV_VERSION} → ${VERSION}?' in text
    windows = (ROOT / "scripts" / "install.ps1").read_text(encoding="utf-8")
    assert 'Confirm-Step "Downgrade DefenseClaw $PrevVersion -> ${Ver}?' in windows and "-DefaultNo)" in windows


@pytest.mark.parametrize(
    ("local", "expected"),
    [("/srv/assets", "Verifying the release assets in /srv/assets"), ("", "Downloading and verifying release assets")],
)
def test_the_asset_step_says_whether_it_downloads(tmp_path: Path, local: str, expected: str) -> None:
    # GAP-0190: --local printed "Downloading and verifying release assets" although it only copies.
    text = INSTALL_SH.read_text(encoding="utf-8")
    start = text.index('if [[ -n "${LOCAL_DIR}" ]]; then\n    info "Verifying')
    script = tmp_path / "step.sh"
    script.write_text(f'info() {{ echo "$*"; }}\nLOCAL_DIR="{local}"\n' + text[start : text.index("\nfi\n", start) + 4])
    assert _run([str(script)], tmp_path).stdout.strip() == expected
    windows = (ROOT / "scripts" / "install.ps1").read_text(encoding="utf-8")
    assert 'if ($LocalDir) { Write-Info "Verifying the release assets in $LocalDir" } else {' in windows
    assert "The downloaded gateway" not in text + windows


@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="root can write any prefix")
def test_declining_openclaw_names_the_working_command_and_skips_quickstart(tmp_path: Path) -> None:
    # GAP-1798: the skip hint said plain "npm install -g" (EACCES on a
    # root-owned Node), then quickstart failed on the missing agent (exit 4).
    declined = _openclaw_install_run(tmp_path, 0, answer=1)
    assert declined.returncode == 0, declined.stdout + declined.stderr
    hint = f"install it later with: npm install -g --prefix {tmp_path / 'home'}/.local openclaw@2026.3.24"
    assert hint in declined.stdout
    assert "missing=true installed=false" in declined.stdout
    assert not (tmp_path / "npm.log").exists()
    text = INSTALL_SH.read_text(encoding="utf-8")
    extras = text[text.index("first_install_extras() {") :]
    branch = extras[extras.index('if [[ "${OPENCLAW_MISSING}" == true ]]; then') :]
    assert branch.index('OPENCLAW_NEXT="defenseclaw ${args[*]}"') < branch.index('"${VENV}/bin/defenseclaw" "${args[@]}"')
    assert "then run: ${OPENCLAW_NEXT:-defenseclaw setup openclaw}" in text


def test_ctrl_c_before_the_swap_says_so_and_drops_what_was_staged(tmp_path: Path) -> None:
    # GAP-1901: Ctrl+C at the connector prompt also killed tee, so the cancel
    # message died on a broken pipe (exit 141) and 1.5 GB of .staging and .uv
    # stayed behind with no CLI to remove them.
    lines = INSTALL_SH.read_text(encoding="utf-8").splitlines()
    tee = next(line for line in lines if line.startswith("exec > >("))
    cancel = lines[lines.index("# Ctrl+C before the swap: drop what this run staged and fetched (GAP-1901).") + 1]
    home = tmp_path / "home"
    script = tmp_path / "cancel.sh"
    script.write_text(
        "set -euo pipefail\nerr() { echo \"x $*\" >&2; }\n"
        f'DEFENSECLAW_HOME="{home}" STAGING="{home}/.staging" BIN_DIR="{tmp_path}/bin" UV_DIR_NEW=1 UV_INSTALLED=""\n'
        + _install_sh_functions("drop_unswapped_stage")
        + f'LOG="{tmp_path}/install.log"\n{tee}\n{cancel}\n'
        'mkdir -p "${STAGING}/bin" "${DEFENSECLAW_HOME}/.uv/cache"\n'
        # Process substitution starts tee asynchronously. Wait until tee has
        # opened the log so SIGINT exercises the install trap, not tee startup.
        'for attempt in {1..200}; do [[ -e "${LOG}" ]] && break; sleep 0.01; done\n'
        '[[ -e "${LOG}" ]] || exit 98\nkill -INT 0\nsleep 5\n',
        encoding="utf-8",
    )
    # A shell started with SIGINT ignored (a background job) cannot trap it.
    completed = subprocess.run(
        ["bash", str(script)],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
        start_new_session=True,
        preexec_fn=lambda: signal.signal(signal.SIGINT, signal.SIG_DFL),
    )
    assert completed.returncode == 130, completed.stdout + completed.stderr
    assert "x Cancelled; nothing was changed" in completed.stdout
    assert "Cancelled; nothing was changed" in (tmp_path / "install.log").read_text(encoding="utf-8")
    assert sorted(p.name for p in home.iterdir()) == []


def test_installed_version_is_the_gateway_on_path_not_a_stale_release_venv(tmp_path: Path) -> None:
    # GAP-2454: `make all` over a 0.8.10 release install leaves the 0.8.10
    # release venv behind; the installer called that "Installed: 0.8.10", warned
    # that the 1.0 audit history would be deleted and labelled the rollback 0.8.10.
    text = INSTALL_SH.read_text(encoding="utf-8")
    start = text.index("installed_version() {")
    func = text[start : text.index("\n}\n", start) + 3]
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    venv = tmp_path / ".venv"
    (venv / "lib" / "python3.12" / "site-packages" / "defenseclaw-0.8.10.dist-info").mkdir(parents=True)
    gateway = bin_dir / "defenseclaw-gateway"
    gateway.write_text("#!/bin/sh\necho 'defenseclaw-gateway version 1.0.0 (commit=abc1234)'\n", encoding="utf-8")
    gateway.chmod(0o755)
    script = tmp_path / "version.sh"
    script.write_text(
        f'set -euo pipefail\nVENV="{venv}" BIN_DIR="{bin_dir}"\n' + func + 'echo "v=$(installed_version)"\n',
        encoding="utf-8",
    )

    assert "v=1.0.0" in _run([str(script)], tmp_path).stdout

    # A gateway that prints no version (or is missing) falls back to the venv.
    gateway.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    assert "v=0.8.10" in _run([str(script)], tmp_path).stdout
    gateway.unlink()
    assert "v=0.8.10" in _run([str(script)], tmp_path).stdout

    # install.ps1 asks the gateway first as well.
    ps1 = (ROOT / "scripts" / "install.ps1").read_text(encoding="utf-8")
    body = ps1[ps1.index("function Get-InstalledVersion {") :]
    assert body.index('"defenseclaw-gateway.exe"') < body.index("dist-info")


@pytest.mark.parametrize(
    "repo,base",
    [
        ("", "https://github.com/cisco-ai-defense/defenseclaw"),
        ("https://mirror.example/defenseclaw/", "https://mirror.example/defenseclaw"),
    ],
)
def test_handoff_uses_requested_release_when_latest_is_newer(tmp_path: Path, repo: str, base: str) -> None:
    releases = tmp_path / "releases"
    for version in ("1.0.0", "1.0.1"):
        target = releases / version
        target.mkdir(parents=True)
        installer = f'#!/bin/bash\nreadonly DC_VERSION="{version}"\n'
        (target / "install.sh").write_text(installer, encoding="utf-8")
        digest = hashlib.sha256(installer.encode()).hexdigest()
        (target / "checksums.txt").write_text(f"{digest}  install.sh\n", encoding="utf-8")
        (target / "checksums.txt.bundle").write_text("{}", encoding="utf-8")

    tools = tmp_path / "tools"
    tools.mkdir()
    curl = tools / "curl"
    curl.write_text(
        '#!/bin/sh\n'
        'previous=""\n'
        'for arg in "$@"; do\n'
        '  [ "$previous" = "-o" ] && output="$arg"\n'
        '  case "$arg" in https://*) url="$arg";; esac\n'
        '  previous="$arg"\n'
        'done\n'
        'echo "$url" >> "$CURL_LOG"\n'
        'case "$url" in\n'
        '  */releases/latest) printf "HTTP/2 302\\r\\nlocation: https://github.com/cisco-ai-defense/defenseclaw/releases/tag/1.0.1\\r\\n";;\n'
        '  */releases/download/*) cp "$FAKE_RELEASES/${url#*/releases/download/}" "$output";;\n'
        '  *) exit 1;;\n'
        'esac\n',
        encoding="utf-8",
    )
    curl.chmod(0o755)
    cosign = tools / "cosign"
    cosign.write_text('#!/bin/sh\n[ "$1" = version ] && echo "GitVersion: v2.6.3"\nexit 0\n', encoding="utf-8")
    cosign.chmod(0o755)
    curl_log = tmp_path / "curl.log"

    result = _run(
        [str(HANDOFF_SH), "--plan", "--version", "1.0.0"],
        tmp_path,
        PATH=f"{tools}:{os.environ.get('PATH', '/usr/bin:/bin')}",
        FAKE_RELEASES=str(releases),
        CURL_LOG=str(curl_log),
        DEFENSECLAW_REPO=repo,
    )

    assert result.returncode == 0, result.stderr
    assert "would upgrade to DefenseClaw 1.0.0" in result.stdout
    urls = curl_log.read_text(encoding="utf-8").splitlines()
    assert all("/releases/latest" not in url for url in urls)
    assert f"{base}/releases/download/1.0.0/install.sh" in urls


# ── 1.0.2 (FG-01) ───────────────────────────────────────────────────────────


def _fake_gateway(path: Path, help_usage: str, calls: Path) -> Path:
    path.write_text(
        "#!/bin/sh\n"
        f'echo "$*" >> "{calls}"\n'
        'case "$*" in *--help*) printf "Usage:\\n  %s\\n" "' + help_usage + '";; esac\n',
        encoding="utf-8",
    )
    path.chmod(0o755)
    return path


def test_rollback_and_upgrade_prune_hook_entries_of_connectors_no_longer_configured(tmp_path: Path) -> None:
    # rel-1-0-1:GAP-0009: a connector set up after the upgrade kept its
    # DefenseClaw hook entries after the rollback, which restored a data dir
    # without its hook script: Claude Code blocked every prompt. The newer
    # gateway of the two removes them; an older one prints the connector help.
    calls = tmp_path / "calls"
    older = _fake_gateway(tmp_path / "older", "defenseclaw-gateway connector [command]", calls)
    newer = _fake_gateway(tmp_path / "newer", "defenseclaw-gateway connector prune-orphans [flags]", calls)
    home = tmp_path / "dc"
    script = tmp_path / "prune.sh"
    script.write_text(
        'set -euo pipefail\nwarn() { echo "warn: $*"; }\n'
        + _install_sh_functions("prune_orphaned_hooks")
        + f'DEFENSECLAW_HOME="{home}" LOG="{tmp_path / "log"}"\n'
        + f'prune_orphaned_hooks "{tmp_path / "missing"}" "{older}" "{newer}"\n',
        encoding="utf-8",
    )

    proc = _run([str(script)], tmp_path)

    assert proc.returncode == 0, proc.stderr
    assert calls.read_text(encoding="utf-8").splitlines() == [
        "connector prune-orphans --help",
        "connector prune-orphans --help",
        f"connector prune-orphans --data-dir {home}",
    ]
    text = INSTALL_SH.read_text(encoding="utf-8")
    rollback = text[text.index('if [[ "${ROLLBACK}" == true ]]; then') : text.index("# ── Stage: nothing live changes")]
    # Run after the swap, for a 1.x install; a 0.x one gets its own teardown first.
    assert rollback.index("swap_with_previous || swapped=$?") < rollback.index(
        'if ! version_lt "${back_to}" 1.0.0; then\n        prune_orphaned_hooks "${BIN_DIR}/defenseclaw-gateway" "${PREVIOUS}/bin/defenseclaw-gateway"'
    )
    swap = text[text.index("swap_in() {") : text.index("swap_app() {")]
    assert 'prune_orphaned_hooks "${BIN_DIR}/defenseclaw-gateway"' in swap  # an upgrade heals a host already hit


def test_hook_fail_modes_are_set_from_the_config_around_the_gateway_stop(tmp_path: Path) -> None:
    # An earlier release's hooks can hold or bake an open nobody chose, which
    # they follow while the gateway is down for the swap. The staged gateway
    # sets their modes from the config before the old gateway stops and,
    # once it is stopped, again before the snapshot. An older staged gateway
    # (a downgrade) prints the connector help and is skipped; a failure
    # refuses the swap, and so does a probe that fails or says nothing
    # (r104 W3 G3-upg: that was taken for a downgrade and the swap went on).
    calls = tmp_path / "calls"
    home = tmp_path / "dc"
    (home / "hooks").mkdir(parents=True)

    def run(gateway: Path) -> subprocess.CompletedProcess[str]:
        staging = tmp_path / f"staging-{gateway.name}"
        (staging / "bin").mkdir(parents=True, exist_ok=True)
        shutil.copy(gateway, staging / "bin" / "defenseclaw-gateway")
        script = tmp_path / f"refresh-{gateway.name}.sh"
        script.write_text(
            "set -euo pipefail\nwarn() { echo \"warn: $*\" >&2; }\n"
            + _install_sh_functions("hook_fail_mode_refresh_probe", "refresh_hook_fail_modes")
            + f'DEFENSECLAW_HOME="{home}" STAGING="{staging}"\nrefresh_hook_fail_modes\n',
            encoding="utf-8",
        )
        return _run([str(script)], tmp_path)

    newer = _fake_gateway(tmp_path / "newer", "defenseclaw-gateway connector refresh-fail-modes [flags]", calls)
    assert run(newer).returncode == 0
    assert calls.read_text(encoding="utf-8").splitlines() == [
        "connector refresh-fail-modes --help",
        # The staged command loads config.yaml and uses its data_dir. An
        # installer-supplied home would override a custom data_dir.
        "connector refresh-fail-modes",
    ]
    calls.unlink()
    older = _fake_gateway(tmp_path / "older", "defenseclaw-gateway connector [command]", calls)
    assert run(older).returncode == 0
    assert calls.read_text(encoding="utf-8").splitlines() == ["connector refresh-fail-modes --help"]
    failing = tmp_path / "failing"
    failing.write_text(
        '#!/bin/sh\ncase "$*" in *--help*) echo "  defenseclaw-gateway connector refresh-fail-modes [flags]"; exit 0;; esac\nexit 1\n',
        encoding="utf-8",
    )
    failing.chmod(0o755)
    assert run(failing).returncode != 0
    for name, body in (
        ("probe-fails", "#!/bin/sh\necho 'error: cannot run' >&2\nexit 1\n"),
        ("probe-silent", "#!/bin/sh\nexit 0\n"),
    ):
        probe = tmp_path / name
        probe.write_text(body, encoding="utf-8")
        probe.chmod(0o755)
        result = run(probe)
        assert result.returncode != 0, result.stdout + result.stderr
        assert "did not answer 'connector refresh-fail-modes --help'" in result.stderr



def test_a_running_gateway_cannot_reopen_its_hooks_while_it_stops(tmp_path: Path) -> None:
    # r104 W3 G3-upg round 3: after the first refresh the old gateway could
    # render its open again (a 1.0.x Codex registration check does) before it
    # exited, and its hooks followed that open while it was down. For a
    # running gateway the staged one now refreshes and holds the lock every
    # release's hook writer takes until that gateway has exited, then
    # refreshes again. The installer stops the gateway once the hold says it
    # is holding and waits for the hold after the stop.
    calls = tmp_path / "calls"
    home = tmp_path / "dc"
    (home / "hooks").mkdir(parents=True)
    staging = tmp_path / "staging"
    (staging / "bin").mkdir(parents=True)
    gateway = staging / "bin" / "defenseclaw-gateway"

    def run(body: str, fake: str) -> subprocess.CompletedProcess[str]:
        gateway.write_text(fake, encoding="utf-8")
        gateway.chmod(0o755)
        if calls.exists():
            calls.unlink()
        script = tmp_path / "hold.sh"
        script.write_text(
            "set -euo pipefail\nwarn() { echo \"warn: $*\" >&2; }\n"
            + _install_sh_functions(
                "hook_fail_mode_refresh_probe", "hold_hook_fail_modes",
                "finish_hook_fail_mode_hold", "end_hook_fail_mode_hold",
            )
            + f'HOLD_PID="" HOLD_LOG="" DEFENSECLAW_HOME="{home}" STAGING="{staging}" CALLS="{calls}"\n'
            + body,
            encoding="utf-8",
        )
        return _run([str(script)], tmp_path)

    newer = (
        "#!/bin/sh\n"
        f'echo "$*" >> "{calls}"\n'
        'case "$*" in *--help*) echo "  defenseclaw-gateway connector refresh-fail-modes [flags]"; exit 0;; esac\n'
        'pid="${*##* }"\n'
        'echo "Hook fail modes set from the config: codex"\n'
        'echo "Holding the hook fail modes until the gateway (process $pid) exits"\n'
        'while kill -0 "$pid" 2>/dev/null; do sleep 0.05; done\n'
        f'echo "second refresh" >> "{calls}"\n'
    )
    # GAP-0839: "stopped" was written after `wait` reaped the old gateway,
    # and the hold's poll could see it gone and write "second refresh" first
    # (about 1 run in 10). "stopping" is written while the old gateway still
    # runs, before it is killed, so the hold cannot have seen it exit yet;
    # the hold then proves it saw the exit itself.
    newer = newer.replace(
        f'echo "second refresh" >> "{calls}"\n',
        f'if kill -0 "$pid" 2>/dev/null; then echo "second refresh while the gateway runs" >> "{calls}"; '
        f'else echo "second refresh" >> "{calls}"; fi\n',
    )
    old_gateway = (
        'sleep 30 & old=$!\n'
        'hold_hook_fail_modes "$old"\n'
        'echo "holding" >> "$CALLS"\n'
        'echo "stopping" >> "$CALLS"\n'
        'kill "$old"; wait "$old" 2>/dev/null || true\n'
        'finish_hook_fail_mode_hold\n'
        'echo "finished" >> "$CALLS"\n'
    )
    result = run(old_gateway, newer)
    assert result.returncode == 0, result.stdout + result.stderr
    lines = calls.read_text(encoding="utf-8").splitlines()
    assert lines[0] == "connector refresh-fail-modes --help", lines
    assert lines[1].startswith("connector refresh-fail-modes --hold-timeout 10m --hold-until-exit "), lines
    assert lines[2:] == ["holding", "stopping", "second refresh", "finished"], lines
    assert "Hook fail modes set from the config: codex" in result.stdout
    assert "Holding the hook fail modes" not in result.stdout

    # A hold that fails before it holds refuses the swap; so does one the
    # installer lets go of (the gateway did not stop).
    failing = newer.replace('pid="${*##* }"', 'echo "cannot read hooks/.hookcfg" >&2; exit 1')
    result = run('sleep 30 & old=$!\nif hold_hook_fail_modes "$old"; then echo held; else echo refused; fi\nkill "$old"\n', failing)
    assert result.returncode == 0 and "refused" in result.stdout, result.stdout + result.stderr
    assert "cannot read hooks/.hookcfg" in result.stderr
    result = run(
        'sleep 30 & old=$!\nhold_hook_fail_modes "$old"\nend_hook_fail_mode_hold\n'
        'echo "let go" >> "$CALLS"\nkill "$old"\n',
        newer,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert calls.read_text(encoding="utf-8").splitlines()[-1] == "let go"
    # An older staged gateway (a downgrade) holds nothing.
    older = _fake_gateway(tmp_path / "older", "defenseclaw-gateway connector [command]", calls)
    result = run('hold_hook_fail_modes 1\necho "skipped" >> "$CALLS"\n', older.read_text(encoding="utf-8"))
    assert result.returncode == 0, result.stdout + result.stderr
    assert calls.read_text(encoding="utf-8").splitlines() == ["connector refresh-fail-modes --help", "skipped"]

    text = INSTALL_SH.read_text(encoding="utf-8")
    swap = text[text.index('OLD_GATEWAY_PID="$(gateway_pid || true)"') : text.index("if ! snapshot; then")]
    hold = swap.index('hold_hook_fail_modes "${OLD_GATEWAY_PID}"')
    stop = swap.index('if ! stop_gateway "${BIN_DIR}/defenseclaw-gateway"; then')
    finish = swap.index("if ! finish_hook_fail_mode_hold; then")
    plain = swap.index("refresh_hook_fail_modes \\\n        || die")
    assert hold < stop < finish < plain, swap
    assert "nothing was changed (see above)" in swap[hold:stop]
    assert swap[stop:finish].index("end_hook_fail_mode_hold") < swap[stop:finish].index("did not stop; nothing was changed")
    after = swap[finish:plain]
    assert after.index("restart_old") < after.index("${RESTORED_NOTE}"), after
    # A gateway whose shutdown waits on the hold is killed, as on Windows.
    stop_fn = text[text.index("stop_gateway() {") : text.index("\n}\n", text.index("stop_gateway() {"))]
    assert 'kill -KILL "${pid}"' in stop_fn, stop_fn


def test_rollback_says_a_later_upgrade_keeps_the_data_instead_of_bringing_it_back() -> None:
    # rel-1-0-1:GAP-0008: the rollback said the data comes back "if you roll
    # forward", but 'defenseclaw upgrade' after it parks that data in backups/.
    # The end-to-end rollback test pins the rendered 1.x command.
    text = INSTALL_SH.read_text(encoding="utf-8")
    assert "comes back if you roll forward" not in text
    assert "'${forward}' again brings it back (a new 'defenseclaw upgrade' starts from the data you have now" in text
    assert "keep_rolled_back_data" in text[text.index("finish_swap() {") :][:600]


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (["--version="], "--version needs a value such as 1.2.3; nothing was changed"),
        (["--version", ""], "--version needs a value such as 1.2.3; nothing was changed"),
        (["--version", "w0-invalid"], "--version must look like 1.2.3, got 'w0-invalid'; nothing was changed"),
        (["--version=1.0"], "--version must look like 1.2.3, got '1.0'; nothing was changed"),
    ],
)
def test_an_empty_or_malformed_version_is_a_usage_error(tmp_path: Path, args: list[str], message: str) -> None:
    # GAP-0012: an empty --version installed the latest release; GAP-0062:
    # a malformed one exited 1. Both are usage errors before any download.
    tools = tmp_path / "tools"
    tools.mkdir()
    curl_log = tmp_path / "curl.log"
    (tools / "curl").write_text(f'#!/bin/sh\necho "$@" >> "{curl_log}"\nexit 1\n', encoding="utf-8")
    (tools / "curl").chmod(0o755)
    proc = _run([str(_stamped(tmp_path)), *args], tmp_path, PATH=f"{tools}:{os.environ.get('PATH', '/usr/bin:/bin')}")
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert message in proc.stderr
    assert not curl_log.exists()
    assert not (tmp_path / "home" / ".defenseclaw").exists()


def test_an_empty_local_value_is_a_usage_error(tmp_path: Path) -> None:
    # #1096/GAP-1336: an empty --local= ran with the current folder as the assets.
    proc = _run([str(_stamped(tmp_path)), "--local="], tmp_path)
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert "--local needs a directory; nothing was changed" in proc.stderr


@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="root ignores the read-only bin folder")
def test_a_second_restore_keeps_the_installer_the_first_one_put_back(tmp_path: Path) -> None:
    # #1096/GAP-0922: a restore that stopped part-way kept its snapshot, and
    # the next run deleted the installer the first had already put back.
    dc_home, bin_dir = tmp_path / "dc", tmp_path / "bin"
    snap = dc_home / "previous.new"
    for root in (dc_home, snap / "data"):
        root.mkdir(parents=True, exist_ok=True)
        (root / "config.yaml").write_text("config_version: 9\n", encoding="utf-8")
    for root, body in ((snap / "installer", "previous installer"), (dc_home / "installer", "failed installer")):
        root.mkdir(parents=True)
        (root / "install.sh").write_text(body, encoding="utf-8")
    (snap / "bin").mkdir()
    (snap / "bin" / "defenseclaw-gateway").write_text("1.0.1\n", encoding="utf-8")
    (snap / "COMPLETE").touch()
    bin_dir.mkdir()
    text = INSTALL_SH.read_text(encoding="utf-8")
    script = tmp_path / "restore.sh"
    script.write_text(
        'set -euo pipefail\ninfo() { :; }\nwarn() { :; }\nerr() { echo "err: $*"; }\nrestart_old() { :; }\n'
        + "".join(line + "\n" for line in text.splitlines() if line.startswith(("readonly MANAGED_", "readonly NOT_DATA")))
        + f'DEFENSECLAW_HOME="{dc_home}" SNAP="{snap}" VENV="{dc_home}/.venv" BIN_DIR="{bin_dir}"\n'
        + f'INSTALLER_DIR="{dc_home}/installer" APP_PATH="" VERSION=1.0.2 PREV_VERSION=1.0.1\n'
        + _install_sh_functions("is_machinery", "data_entries", "restore_external_config", "restore_snapshot")
        + "restore_snapshot\n",
        encoding="utf-8",
    )
    bin_dir.chmod(0o555)
    try:
        first = _run([str(script)], tmp_path)
    finally:
        bin_dir.chmod(0o755)
    assert "back completely" in first.stdout and snap.is_dir(), first
    assert (dc_home / "installer" / "install.sh").read_text(encoding="utf-8") == "previous installer"

    _run([str(script)], tmp_path)

    assert not snap.exists()
    assert (dc_home / "installer" / "install.sh").read_text(encoding="utf-8") == "previous installer"
    assert (bin_dir / "defenseclaw-gateway").read_text(encoding="utf-8") == "1.0.1\n"


@pytest.mark.parametrize("failing", ["audit.db", "audit.db-wal"])
def test_a_failed_audit_quarantine_keeps_the_store_with_its_wal(tmp_path: Path, failing: str) -> None:
    # #1096/GAP-1397: the WAL moved aside before the store, and a store that
    # then did not move stayed behind without it.
    home = tmp_path / "dc"
    home.mkdir()
    (home / "audit.db").write_text("db", encoding="utf-8")
    (home / "audit.db-wal").write_text("wal", encoding="utf-8")
    script = tmp_path / "quarantine.sh"
    script.write_text(
        "set -euo pipefail\nwarn() { :; }\n"
        + f'mv() {{ [[ "$1" == "{home / failing}" ]] && return 1; command mv "$@"; }}\n'
        + _install_sh_functions("move_audit_store", "quarantine_rolled_back_audit")
        + f'DEFENSECLAW_HOME="{home}" back_to=0.8.10 QUARANTINED=""\n'
        + 'quarantine_rolled_back_audit && echo moved || echo "rc=$?"\n',
        encoding="utf-8",
    )

    out = _run([str(script)], tmp_path).stdout

    assert "rc=1" in out
    assert (home / "audit.db").read_text(encoding="utf-8") == "db"
    assert (home / "audit.db-wal").read_text(encoding="utf-8") == "wal"
    assert not list(home.glob("audit.db.corrupt-*"))


def test_an_undone_rollback_puts_the_saved_audit_store_back_over_a_new_one(tmp_path: Path) -> None:
    # #1096/GAP-1398: the failed start of the restored 0.x gateway made a new,
    # empty audit.db, so the store the rollback had moved aside stayed aside
    # and the next rollback used the empty one without a word.
    home = tmp_path / "dc"
    data = home / "previous" / "data"
    data.mkdir(parents=True)
    quarantined = "audit.db.corrupt-20261013T000000Z"
    (data / quarantined).write_text("0.x history", encoding="utf-8")
    (data / f"{quarantined}-wal").write_text("0.x wal", encoding="utf-8")
    (data / "audit.db").write_text("new", encoding="utf-8")
    script = tmp_path / "undo.sh"
    script.write_text(
        "set -euo pipefail\n"
        + _install_sh_functions("move_audit_store", "undo_rollback")
        + "info() { :; }\nwarn() { :; }\nerr() { :; }\nok() { :; }\n"
        + "stop_gateway() { :; }\nswap_with_previous() { return 0; }\nstart_gateway() { return 0; }\nwarn_not_started() { :; }\n"
        + f'DEFENSECLAW_HOME="{home}" PREVIOUS="{home / "previous"}" BIN_DIR="{tmp_path / "bin"}" LOG=/dev/null\n'
        + f'current=1.0.2 back_to=0.8.10 saved_was_running=false QUARANTINED="{home / quarantined}"\n'
        + 'undo_rollback "The gateway of DefenseClaw 0.8.10 did not start"\n',
        encoding="utf-8",
    )

    proc = _run([str(script)], tmp_path)

    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert (data / "audit.db").read_text(encoding="utf-8") == "0.x history"
    assert (data / "audit.db-wal").read_text(encoding="utf-8") == "0.x wal"
    aside = list(data.glob("audit.db.failed-start-*"))
    assert [path.read_text(encoding="utf-8") for path in aside] == ["new"]


@pytest.mark.parametrize(
    "failing",
    ["", "audit.db", "audit.db-wal", "audit.db.corrupt-fixture", "audit.db.corrupt-fixture-wal", "audit.db.corrupt-fixture-shm"],
)
def test_an_undone_rollback_moves_each_audit_store_as_one_unit(tmp_path: Path, failing: str) -> None:
    # rel-1-0-2:GAP-0492 (the install.sh side of GAP-1398): each file moved on
    # its own (|| true), so a move that failed midway left the saved store at
    # audit.db without its WAL, or with the new store's WAL.
    home = tmp_path / "dc"
    data = home / "previous" / "data"
    data.mkdir(parents=True)
    kept = data / "audit.db.corrupt-fixture"
    saved = {"": "0.x history", "-wal": "0.x wal", "-shm": "0.x shm"}
    for suffix, body in saved.items():
        Path(f"{kept}{suffix}").write_text(body, encoding="utf-8")
    new = {"": "new", "-wal": "new wal"}
    for suffix, body in new.items():
        Path(f"{data / 'audit.db'}{suffix}").write_text(body, encoding="utf-8")
    script = tmp_path / "undo.sh"
    script.write_text(
        "set -euo pipefail\n"
        + _install_sh_functions("move_audit_store", "undo_rollback")
        + 'info() { :; }\nwarn() { echo "warn: $*"; }\nerr() { :; }\nok() { :; }\n'
        + "stop_gateway() { :; }\nswap_with_previous() { return 0; }\nstart_gateway() { return 0; }\nwarn_not_started() { :; }\n"
        + f'mv() {{ [[ "$1" == "{data / failing if failing else "none"}" ]] && return 1; command mv "$@"; }}\n'
        + f'DEFENSECLAW_HOME="{home}" PREVIOUS="{home / "previous"}" BIN_DIR="{tmp_path / "bin"}" LOG=/dev/null\n'
        + f'current=1.0.2 back_to=0.8.10 saved_was_running=false QUARANTINED="{home / kept.name}"\n'
        + 'undo_rollback "The gateway of DefenseClaw 0.8.10 did not start"\n',
        encoding="utf-8",
    )

    proc = _run([str(script)], tmp_path)

    def store_at(path: Path, store: dict[str, str]) -> bool:
        return all(Path(f"{path}{suffix}").read_text(encoding="utf-8") == body for suffix, body in store.items())

    assert proc.returncode == 1, proc.stdout + proc.stderr
    fresh = [p for p in data.glob("audit.db.failed-start-*") if not p.name.endswith(("-wal", "-shm"))]
    if not failing:
        assert store_at(data / "audit.db", saved) and len(fresh) == 1 and store_at(fresh[0], new)
        assert not list(data.glob("audit.db.corrupt-*")) and "is still" not in proc.stdout
        return
    assert store_at(kept, saved), sorted(p.name for p in data.iterdir())
    assert f"warn: The saved 0.8.10 audit store is still {kept}" in proc.stdout
    if failing.startswith("audit.db.corrupt-"):
        assert not any(Path(f"{data / 'audit.db'}{suffix}").exists() for suffix in ("", "-wal", "-shm"))
        assert len(fresh) == 1 and store_at(fresh[0], new)
    else:
        assert store_at(data / "audit.db", new) and fresh == []


def test_a_failed_audit_quarantine_never_replaces_a_file(tmp_path: Path) -> None:
    # rel-1-0-2:GAP-0491: mv replaces an existing target, so a left-over
    # <moved>-wal would have been overwritten by the store's WAL.
    home = tmp_path / "dc"
    home.mkdir()
    for suffix, body in {"": "db", "-wal": "wal", "-shm": "shm"}.items():
        Path(f"{home / 'audit.db'}{suffix}").write_text(body, encoding="utf-8")
    (home / "aside-shm").write_text("other", encoding="utf-8")
    script = tmp_path / "move.sh"
    script.write_text(
        'set -euo pipefail\nwarn() { echo "warn: $*"; }\n'
        + _install_sh_functions("move_audit_store")
        + f'move_audit_store "{home / "audit.db"}" "{home / "aside"}" && echo moved || echo "rc=$?"\n',
        encoding="utf-8",
    )

    out = _run([str(script)], tmp_path).stdout

    assert "rc=1" in out
    assert [Path(f"{home / 'audit.db'}{s}").read_text(encoding="utf-8") for s in ("", "-wal", "-shm")] == ["db", "wal", "shm"]
    assert sorted(p.name for p in home.iterdir()) == ["aside-shm", "audit.db", "audit.db-shm", "audit.db-wal"]


def _stage_binaries(tmp_path: Path, verify_rc: int) -> tuple[subprocess.CompletedProcess[str], Path]:
    staging = tmp_path / "staging"
    (staging / "bin").mkdir(parents=True)
    (staging / "bin" / "defenseclaw-gateway").write_bytes(b"archive gateway")
    (staging / "bin" / "defenseclaw-acp").write_bytes(b"archive acp")
    codesign = tmp_path / "codesign"
    codesign.write_text(
        "#!/bin/sh\n"
        f'if [ "$1" = --verify ]; then exit {verify_rc}; fi\n'
        'for last in "$@"; do :; done\n'
        'printf " signed as %s" "$5" >> "$last"\n',
        encoding="utf-8",
    )
    codesign.chmod(0o755)
    script = tmp_path / "stage.sh"
    script.write_text(
        'set -euo pipefail\ninfo() { echo "info: $*"; }\nwarn() { echo "warn: $*"; }\n'
        'die() { echo "die: $*"; exit 1; }\nhas() { command -v "$1" >/dev/null 2>&1; }\n'
        + _install_sh_functions("sha256_of", "stage_binary", "record_binaries").replace(
            "/usr/bin/codesign", str(codesign)
        )
        + f'OS=darwin STAGING="{staging}" BIN_DIR="{tmp_path}/bin" INSTALLER_DIR="{tmp_path}/installer"\n'
        + "stage_binary defenseclaw-gateway\nstage_binary defenseclaw-acp\n"
        + 'mkdir -p "${BIN_DIR}" "${INSTALLER_DIR}"\ncp "${STAGING}"/bin/* "${BIN_DIR}/"\n'
        + "record_binaries\n"
        + 'printf tampered >> "${BIN_DIR}/defenseclaw-acp"\nrecord_binaries || echo "recheck failed"\n',
        encoding="utf-8",
    )
    return _run([str(script)], tmp_path), staging


def test_the_installer_records_the_digest_of_the_signed_binary_that_runs(tmp_path: Path) -> None:
    # GAP-0641: the macOS installer signs the verified archive binary ad hoc,
    # which changes its SHA-256, and kept no digest of the file that runs.
    result, staging = _stage_binaries(tmp_path, verify_rc=0)

    gateway = staging / "bin" / "defenseclaw-gateway"
    assert gateway.read_bytes() == b"archive gateway signed as com.cisco.defenseclaw.gateway", result.stdout
    signed = hashlib.sha256(gateway.read_bytes()).hexdigest()
    archive = hashlib.sha256(b"archive gateway").hexdigest()
    assert f"info: Signed defenseclaw-gateway for this Mac: sha256 {signed} (archive {archive})" in result.stdout
    record = (tmp_path / "installer" / "binaries.sha256").read_text(encoding="utf-8").splitlines()
    acp = hashlib.sha256(b"archive acp signed as com.cisco.defenseclaw.acp").hexdigest()
    assert record == [f"{signed}  defenseclaw-gateway", f"{acp}  defenseclaw-acp"]
    assert "warn: The installed defenseclaw-acp is not the binary this install staged" in result.stdout
    assert "recheck failed" in result.stdout and result.returncode == 0, result.stdout + result.stderr


def test_a_signature_that_does_not_verify_stops_the_install(tmp_path: Path) -> None:
    result, staging = _stage_binaries(tmp_path, verify_rc=1)

    assert result.returncode == 1 and "die: Could not sign defenseclaw-gateway for this Mac" in result.stdout
    assert not (staging / "binaries.sha256").exists()


# ── 1.0.4 (T8 smoke review loop round 3) ────────────────────────────────────


def test_an_upgrade_finishes_the_removed_connector_cleanup_or_fails(tmp_path: Path) -> None:
    # A gateway start that brought the other connectors up only logged a
    # removed connector (OpenHands, OmniGent) whose teardown it could not
    # finish, and the upgrade exited 0. The installer now checks each: one not
    # done is torn down again, and one still not done is named with its cause
    # and the install exits 3.
    home = tmp_path / "dc"
    home.mkdir()
    (home / "config.yaml").write_text("config_version: 9\n", encoding="utf-8")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    calls = tmp_path / "calls"
    gateway = bin_dir / "defenseclaw-gateway"

    def run(dirty: dict[str, str]) -> subprocess.CompletedProcess[str]:
        # dirty: connector -> "once" (clean after a teardown) or "always".
        state = tmp_path / "state"
        state.mkdir(exist_ok=True)
        for name, how in dirty.items():
            (state / name).write_text(how, encoding="utf-8")
        gateway.write_text(
            "#!/bin/sh\n"
            f'echo "$*" >> "{calls}"\n'
            "name=$4; action=$2\n"
            f'state="{state}/$name"\n'
            '[ -f "$state" ] || exit 0\n'
            'if [ "$action" = teardown ]; then\n'
            '  [ "$(cat "$state")" = once ] && rm -f "$state"\n'
            "  exit 1\n"
            "fi\n"
            'echo "  X $name: $name cleanup incomplete: /h/openhands-hook.sh is gone, but /w/.openhands/hooks.json still runs it. To finish: run defenseclaw-gateway connector teardown --connector $name" >&2\n'
            "exit 1\n",
            encoding="utf-8",
        )
        gateway.chmod(0o755)
        script = tmp_path / "finish.sh"
        script.write_text(
            'set -euo pipefail\nerr() { echo "err: $*" >&2; }\n'
            + _install_sh_functions("finish_retired_connector_cleanup")
            + f'DEFENSECLAW_HOME="{home}" BIN_DIR="{bin_dir}" LOG="{tmp_path / "log"}" VERSION=1.0.4\n'
            + "finish_retired_connector_cleanup\n",
            encoding="utf-8",
        )
        if calls.exists():
            calls.unlink()
        return _run([str(script)], tmp_path)

    verify = f"connector verify --connector {{}} --data-dir {home}"
    teardown = f"connector teardown --connector {{}} --data-dir {home}"

    clean = run({})
    assert clean.returncode == 0, clean.stderr
    assert calls.read_text(encoding="utf-8").splitlines() == [verify.format("openhands"), verify.format("omnigent")]

    healed = run({"omnigent": "once"})
    assert healed.returncode == 0, healed.stderr
    assert calls.read_text(encoding="utf-8").splitlines() == [
        verify.format("openhands"),
        verify.format("omnigent"),
        teardown.format("omnigent"),
        verify.format("omnigent"),
    ]

    stuck = run({"openhands": "always"})
    assert stuck.returncode == 1
    assert "could not finish removing the openhands connector" in stuck.stderr
    assert "/w/.openhands/hooks.json still runs it" in stuck.stderr
    assert "To finish: run defenseclaw-gateway connector teardown --connector openhands" in stuck.stderr
    assert "omnigent" not in stuck.stderr



# ── 1.0.4 (T8 smoke review loop round 2 of the Hermes/upgrade class) ────────


@pytest.mark.parametrize("was_running", ["true", "false"])
def test_every_upgrade_checks_the_removed_connectors_whatever_the_gateway_state(
    tmp_path: Path, was_running: str
) -> None:
    # An upgrade of a stopped gateway skipped the removed-connector check
    # (it ran only when WAS_RUNNING), so a 1.0.3 OpenHands or OmniGent hook
    # could stay registered unsealed and the upgrade exited 0.
    text = INSTALL_SH.read_text(encoding="utf-8")
    start = text.index("finish_swap\n# until 1.1")
    main = text[start : text.index("report_retired_connector_leftovers\n", start)]
    script = tmp_path / "main.sh"
    script.write_text(
        "set -euo pipefail\nfinish_swap() { :; }\n"
        'finish_retired_connector_cleanup() { echo "checked" >&2; return 1; }\n'
        f"PREV_VERSION=1.0.3 WAS_RUNNING={was_running} START_RC=0\n" + main + 'echo "START_RC=${START_RC}"\n',
        encoding="utf-8",
    )

    result = _run([str(script)], tmp_path)

    assert result.returncode == 0, result.stderr
    assert "checked" in result.stderr and "START_RC=3" in result.stdout, result.stdout + result.stderr


def test_the_removed_connector_check_fails_loudly_without_the_gateway_and_skips_an_unconfigured_install(
    tmp_path: Path,
) -> None:
    # The check returned 0 when the gateway binary was not there, so nothing
    # proved the removed connectors' hooks were sealed. With no config there
    # was never a connector, and the gateway cannot read one.
    home = tmp_path / "dc"
    home.mkdir()
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    script = tmp_path / "finish.sh"
    script.write_text(
        'set -euo pipefail\nerr() { echo "err: $*" >&2; }\n'
        + _install_sh_functions("finish_retired_connector_cleanup")
        + f'DEFENSECLAW_HOME="{home}" BIN_DIR="{bin_dir}" LOG="{tmp_path / "log"}" VERSION=1.0.4\n'
        + "finish_retired_connector_cleanup\n",
        encoding="utf-8",
    )

    unconfigured = _run([str(script)], tmp_path)
    assert unconfigured.returncode == 0 and not unconfigured.stderr, unconfigured.stderr

    (home / "config.yaml").write_text("config_version: 9\n", encoding="utf-8")
    missing = _run([str(script)], tmp_path)
    assert missing.returncode == 1
    assert "could not check that the removed OpenHands and OmniGent connectors are blocked" in missing.stderr
    assert f"{bin_dir}/defenseclaw-gateway is missing" in missing.stderr


# ── 1.0.4 (T8 smoke review loop round 4: GAP-0878, GAP-0899) ────────────────


def _start_gateway_script(tmp_path: Path, bin_dir: Path, *, pid_file: Path | None = None) -> Path:
    text = INSTALL_SH.read_text(encoding="utf-8")
    start = text.index("start_gateway() {")
    funcs = text[start : text.index("\n}\n", text.index("explain_start_failure() {")) + 3]
    helpers = text[text.index("version_key() {") : text.index("is_version() {")]
    pid = f"gateway_pid() {{ kill -0 \"$(cat '{pid_file}')\" 2>/dev/null && cat '{pid_file}'; }}\n" if pid_file else ""
    script = tmp_path / "start.sh"
    script.write_text(
        'set -euo pipefail\ninfo() { echo "info: $*"; }\nwarn() { echo "warn: $*"; }\nok() { echo "ok: $*"; }\n'
        + helpers
        + funcs
        + pid
        + f'DEFENSECLAW_HOME="{tmp_path}" BIN_DIR="{bin_dir}"\nrc=0; start_gateway || rc=$?; echo "rc=$rc"\n',
        encoding="utf-8",
    )
    return script


def test_an_install_whose_gateway_skips_a_connector_exits_3(tmp_path: Path) -> None:
    # GAP-0878, GAP-0899: a boot that skipped Hermes (probe timeout, unreadable
    # roster) printed OK, start exited 0 and so did the upgrade, with Hermes
    # unprotected. A gateway that has --require-every-connector is asked for
    # it and exits 3 naming the connector; the install keeps it and exits 3.
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    calls = tmp_path / "calls"
    gateway = bin_dir / "defenseclaw-gateway"
    gateway.write_text(
        "#!/bin/sh\n"
        f'echo "$*" >> "{calls}"\n'
        'case "$*" in\n'
        '  --version) echo "defenseclaw-gateway version 1.0.4" ;;\n'
        '  "start --require-every-connector --help") exit 0 ;;\n'
        '  "start --require-every-connector") echo "Error: gateway is running, but it does not guard hermes;'
        ' hermes: its setup failed (see gateway.log), then run: defenseclaw setup hermes" >&2; exit 3 ;;\n'
        "  *) exit 1 ;;\n"
        "esac\n",
        encoding="utf-8",
    )
    gateway.chmod(0o755)

    out = _run([str(_start_gateway_script(tmp_path, bin_dir))], tmp_path)

    assert "rc=3" in out.stdout, out.stdout + out.stderr
    assert "does not guard hermes" in out.stderr
    assert "start --require-every-connector" in calls.read_text(encoding="utf-8").splitlines()

    # The main flow keeps the install for 3 and exits 3, never 0.
    text = INSTALL_SH.read_text(encoding="utf-8")
    assert "if [[ ${START_RC} -ne 0 && ${START_RC} -ne 3 ]]; then" in text
    assert text.count("\nexit ${START_RC}\n") == 1


def test_an_older_gateway_is_started_without_the_every_connector_flag(tmp_path: Path) -> None:
    # A restored or rolled-back gateway (1.0.3 and earlier) does not know the
    # flag; passing it would fail the start that brings it back.
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    calls = tmp_path / "calls"
    gateway = bin_dir / "defenseclaw-gateway"
    gateway.write_text(
        "#!/bin/sh\n"
        f'echo "$*" >> "{calls}"\n'
        'case "$*" in\n'
        '  --version) echo "defenseclaw-gateway version 1.0.3" ;;\n'
        '  *--require-every-connector*) echo "Error: unknown flag: --require-every-connector" >&2; exit 1 ;;\n'
        "  start) exit 0 ;;\n"
        "  *) exit 1 ;;\n"
        "esac\n",
        encoding="utf-8",
    )
    gateway.chmod(0o755)

    out = _run([str(_start_gateway_script(tmp_path, bin_dir))], tmp_path)

    assert "rc=0" in out.stdout, out.stdout + out.stderr
    assert calls.read_text(encoding="utf-8").splitlines()[-1] == "start"


def test_a_slow_first_start_still_proves_every_connector_is_guarded(tmp_path: Path) -> None:
    # GAP-1348 path: start gave up while the gateway kept starting, and the
    # installer took two good status answers as success. It now asks the
    # running gateway (start --require-every-connector on a running gateway)
    # whether every connector is guarded, and returns 3 when one is not.
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    pid_file, calls = tmp_path / "gateway.pid", tmp_path / "calls"
    gateway = bin_dir / "defenseclaw-gateway"
    gateway.write_text(
        "#!/bin/sh\n"
        f'echo "$*" >> "{calls}"\n'
        'case "$*" in\n'
        '  --version) echo "defenseclaw-gateway version 1.0.4" ;;\n'
        '  "start --require-every-connector --help") exit 0 ;;\n'
        '  "start --require-every-connector")\n'
        f"    if [ -f '{pid_file}' ]; then echo 'Error: gateway is running, but it does not guard hermes' >&2; exit 3; fi\n"
        f"    (exec sleep 30) >/dev/null 2>&1 & echo $! > '{pid_file}'; exit 1 ;;\n"
        "  status) exit 0 ;;\n"
        "  *) exit 1 ;;\n"
        "esac\n",
        encoding="utf-8",
    )
    gateway.chmod(0o755)
    script = _start_gateway_script(tmp_path, bin_dir, pid_file=pid_file)

    out = _run([str(script)], tmp_path)
    subprocess.run(["kill", pid_file.read_text(encoding="utf-8").strip()], check=False)

    assert "ok: The gateway finished starting" in out.stdout, out.stdout + out.stderr
    assert "rc=3" in out.stdout, out.stdout + out.stderr
    assert "does not guard hermes" in out.stderr
    assert calls.read_text(encoding="utf-8").splitlines().count("start --require-every-connector") == 2


def test_a_restored_gateway_that_needs_attention_is_not_reported_down(tmp_path: Path) -> None:
    # restart_old read exit 3 (running, a connector needs attention) as "did
    # not start again".
    script = tmp_path / "restart.sh"
    script.write_text(
        'set -euo pipefail\ninfo() { echo "info: $*"; }\nwarn() { echo "warn: $*"; }\n'
        + _install_sh_functions("restart_old")
        + f'start_gateway() {{ return 3; }}\nWAS_RUNNING=true DEFENSECLAW_HOME="{tmp_path}"\nrestart_old\necho "note=$RESTORED_NOTE"\n',
        encoding="utf-8",
    )

    out = _run([str(script)], tmp_path)

    assert out.returncode == 0, out.stderr
    assert "its gateway runs, but a connector needs attention" in out.stdout
    assert "did not start again" not in out.stdout


# ── 1.0.4 (T8 smoke review loop round 3 of the Hermes/upgrade class) ────────


@pytest.mark.parametrize("was_running", ["true", "false"])
def test_a_stopped_upgrade_puts_every_connector_on_its_current_hook(tmp_path: Path, was_running: str) -> None:
    # An upgrade of a stopped 1.0.3 install with Hermes registered skipped the
    # gateway start, so nothing rendered this release's Hermes hook (the 1.0.3
    # one cannot answer the execution probe) and it exited 0. A gateway that
    # was not running is now reconciled after the swap, and a failure is the
    # install's exit 3; a running one was proven by its start.
    text = INSTALL_SH.read_text(encoding="utf-8")
    start = text.index("finish_swap\n# until 1.1")
    main = text[start : text.index("trap - HUP PIPE\n", start)]
    script = tmp_path / "main.sh"
    script.write_text(
        "set -euo pipefail\nfinish_swap() { :; }\nfinish_retired_connector_cleanup() { :; }\n"
        "report_retired_connector_leftovers() { :; }\n"
        'reconcile_stopped_connectors() { echo "reconciled" >&2; return 1; }\n'
        f"PREV_VERSION=1.0.3 WAS_RUNNING={was_running} START_RC=0\n" + main + 'echo "START_RC=${START_RC}"\n',
        encoding="utf-8",
    )

    result = _run([str(script)], tmp_path)

    assert result.returncode == 0, result.stderr
    if was_running == "false":
        assert "reconciled" in result.stderr and "START_RC=3" in result.stdout, result.stdout + result.stderr
    else:
        assert "reconciled" not in result.stderr and "START_RC=0" in result.stdout, result.stdout + result.stderr


@pytest.mark.parametrize(
    ("configured", "binary", "help_rc", "reconcile_rc", "want_rc", "want_calls"),
    [
        (False, True, 0, 0, 0, []),
        (True, False, 0, 0, 1, []),
        (True, True, 1, 0, 0, ["help"]),
        (True, True, 0, 0, 0, ["help", "reconcile"]),
        (True, True, 0, 3, 1, ["help", "reconcile"]),
    ],
)
def test_the_stopped_upgrade_reconcile_names_the_cause(
    tmp_path: Path,
    configured: bool,
    binary: bool,
    help_rc: int,
    reconcile_rc: int,
    want_rc: int,
    want_calls: list[str],
) -> None:
    home = tmp_path / "dc"
    home.mkdir()
    if configured:
        (home / "config.yaml").write_text("config_version: 9\n", encoding="utf-8")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    calls = tmp_path / "calls"
    if binary:
        gateway = bin_dir / "defenseclaw-gateway"
        gateway.write_text(
            "#!/bin/sh\n"
            'case "$*" in\n'
            f'  "connector reconcile --every-connector --help") echo help >> "{calls}"; exit {help_rc} ;;\n'
            f'  "connector reconcile --every-connector --data-dir {home}")\n'
            f'    echo reconcile >> "{calls}"\n'
            f'    [ "$DEFENSECLAW_CONFIG" = "{home}/config.yaml" ] || exit 9\n'
            '    echo "  OK claudecode is on its current hook"\n'
            f"    [ {reconcile_rc} -eq 0 ] && exit 0\n"
            '    echo "Error: not every connector is on its current hook: hermes: its current hook is not in place; start the gateway (defenseclaw-gateway start), then check: defenseclaw doctor" >&2\n'
            f"    exit {reconcile_rc} ;;\n"
            "  *) exit 8 ;;\n"
            "esac\n",
            encoding="utf-8",
        )
        gateway.chmod(0o755)
    log = tmp_path / "log"
    script = tmp_path / "reconcile.sh"
    script.write_text(
        'set -euo pipefail\nerr() { echo "err: $*" >&2; }\n'
        + _install_sh_functions("reconcile_stopped_connectors")
        + f'DEFENSECLAW_HOME="{home}" BIN_DIR="{bin_dir}" LOG="{log}" VERSION=1.0.4\n'
        + 'rc=0; reconcile_stopped_connectors || rc=$?; echo "rc=$rc"\n',
        encoding="utf-8",
    )

    result = _run([str(script)], tmp_path)

    assert result.returncode == 0, result.stderr
    assert f"rc={want_rc}" in result.stdout, result.stdout + result.stderr
    assert (calls.read_text(encoding="utf-8").splitlines() if calls.exists() else []) == want_calls
    if want_calls == ["help", "reconcile"]:
        assert "claudecode is on its current hook" in log.read_text(encoding="utf-8")
    if reconcile_rc:
        assert (
            "err: DefenseClaw 1.0.4 could not put every connector on its current hook while the gateway is stopped: "
            "not every connector is on its current hook: hermes: its current hook is not in place" in result.stderr
        ), result.stderr
    if not binary:
        assert f"{bin_dir}/defenseclaw-gateway is missing" in result.stderr, result.stderr


# ── GAP-1063 / GAP-1067: same-version builds and the saved installer ────────


def _version_gateway(path: Path, output: str | None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    body = "exit 1\n" if output is None else f"printf '%s\\n' '{output}'\n"
    path.write_text(f"#!/bin/bash\n{body}", encoding="utf-8")
    path.chmod(0o755)


def _swap_decision(tmp_path: Path, version: str, prev: str, installed: str | None, staged: str) -> str:
    """Run the swap's repair decision, its prompt and the snapshot choice of install.sh."""
    text = INSTALL_SH.read_text(encoding="utf-8")
    decision = text[text.index("REPAIR=false\n") : text.index('if [[ -z "${PREV_VERSION}" ]] && [[ "${YES}" != true ]]')]
    start = text.index('if [[ "${REPAIR}" == true ]]; then\n    SNAP=')
    snap = text[start : text.index("\nfi\n", start) + 4]
    bin_dir, staging = tmp_path / "bin", tmp_path / "staging"
    _version_gateway(bin_dir / "defenseclaw-gateway", installed)
    _version_gateway(staging / "bin" / "defenseclaw-gateway", staged)
    script = tmp_path / "decide.sh"
    script.write_text(
        "set -euo pipefail\n"
        'info() { echo "info: $*"; }\nask_yes_no() { echo "ask: $1"; }\ndie() { echo "die: $*"; exit 1; }\n'
        "warn_running_sandboxes() { :; }\n"
        + _install_sh_functions("other_build_installed")
        + f'VERSION={version} PREV_VERSION={prev} BIN_DIR="{bin_dir}" STAGING="{staging}"\n'
        + f'DEFENSECLAW_HOME="{tmp_path}/dc" PREVIOUS="{tmp_path}/dc/previous"\n'
        + decision
        + snap
        + 'echo "REPAIR=${REPAIR} SNAP=${SNAP##*/}"\n',
        encoding="utf-8",
    )
    proc = _run([str(script)], tmp_path)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return proc.stdout


def test_another_build_of_the_installed_version_keeps_the_replaced_build_for_rollback(tmp_path: Path) -> None:
    # GAP-1063: two 1.0.4 builds (release candidates) were a same-version
    # repair: no rollback copy was kept and nothing said so before the swap.
    out = _swap_decision(
        tmp_path,
        "1.0.4",
        "1.0.4",
        "defenseclaw-gateway version 1.0.4 (commit=16d085f75a, built=2026-10-22)",
        "defenseclaw-gateway version 1.0.4 (commit=78c01d5c88, built=2026-10-23)",
    )
    lines = out.splitlines()
    assert lines[0] == (
        "info: The installed DefenseClaw 1.0.4 is another build (commit 16d085f75a) than this one (commit 78c01d5c88); "
        f"it is kept in {tmp_path}/dc/previous, so 'defenseclaw rollback' returns to it"
    ), out
    assert lines[1] == "ask: Replace the installed build of DefenseClaw 1.0.4?", out
    assert lines[-1] == "REPAIR=false SNAP=previous.new", out


@pytest.mark.parametrize(
    ("prev", "installed", "expected"),
    [
        # The same build again: a repair keeps the rollback copy there is.
        ("1.0.4", "defenseclaw-gateway version 1.0.4 (commit=78c01d5c88, built=2026-10-23)", "REPAIR=true SNAP=.repair"),
        # An installed gateway that does not answer is repaired, as before.
        ("1.0.4", None, "REPAIR=true SNAP=.repair"),
        # One that answers for another version is not this version's build.
        ("1.0.4", "defenseclaw-gateway version 1.0.3 (commit=aaaa, built=x)", "REPAIR=true SNAP=.repair"),
        # An upgrade keeps the replaced install, as it always did.
        ("1.0.3", "defenseclaw-gateway version 1.0.3 (commit=aaaa, built=x)", "REPAIR=false SNAP=previous.new"),
    ],
)
def test_only_another_build_of_the_same_version_changes_the_repair(
    tmp_path: Path, prev: str, installed: str | None, expected: str
) -> None:
    out = _swap_decision(
        tmp_path, "1.0.4", prev, installed, "defenseclaw-gateway version 1.0.4 (commit=78c01d5c88, built=2026-10-23)"
    )
    assert out.splitlines()[-1] == expected, out
    assert "another build" not in out
    if prev == "1.0.4":
        assert "ask: Reinstall DefenseClaw 1.0.4?" in out


@pytest.mark.parametrize(
    ("prev", "word"),
    [("1.0.4", "Replaced the other build of 1.0.4"), ("1.0.3", "Upgraded from 1.0.3"), ("1.0.5", "Downgraded from 1.0.5")],
)
def test_the_summary_names_a_replaced_build(tmp_path: Path, prev: str, word: str) -> None:
    text = INSTALL_SH.read_text(encoding="utf-8")
    helpers = text[text.index("version_key() {") : text.index("is_version() {")]
    start = text.index('    changed="Upgraded from')
    end = text.index("\n", text.index('printf "  ${changed}. Undo with', start))
    script = tmp_path / "end.sh"
    script.write_text(f"{helpers}CYAN= NC=\nVERSION=1.0.4 PREV_VERSION={prev}\n{text[start:end]}\n", encoding="utf-8")
    assert _run([str(script)], tmp_path).stdout.strip() == f"{word}. Undo with: defenseclaw rollback"
    assert 'if [[ -n "${PREV_VERSION}" && "${REPAIR}" != true ]]; then\n    changed="Upgraded from' in text


def _record_saved_installer(tmp_path: Path, saved: bool) -> Path:
    home = tmp_path / "dc"
    (home / "installer").mkdir(parents=True)
    (home / "receipts").mkdir()
    (home / "receipts" / "installer.sha256").write_text("stale\n", encoding="utf-8")
    if saved:
        (home / "installer" / "install.sh").write_bytes(b'#!/bin/bash\nDC_VERSION="1.0.4"\n')
    script = tmp_path / "record.sh"
    script.write_text(
        'set -euo pipefail\nhas() { command -v "$1" >/dev/null 2>&1; }\nwarn() { echo "warn: $*"; }\n'
        + _install_sh_functions("sha256_of", "record_saved_installer")
        + f'DEFENSECLAW_HOME="{home}" INSTALLER_DIR="{home}/installer" VERSION=1.0.4\nrecord_saved_installer\n',
        encoding="utf-8",
    )
    proc = _run([str(script)], tmp_path)
    assert proc.returncode == 0 and "warn" not in proc.stdout, proc.stdout + proc.stderr
    return home


def test_the_saved_installer_is_recorded_in_the_form_rollback_checks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # GAP-1067: rollback ran a saved installer an agent had changed. The
    # install records its digest, and the shim refuses a copy that differs.
    from defenseclaw import upgrade_shim

    home = _record_saved_installer(tmp_path, saved=True)
    saved = home / "installer" / "install.sh"
    record = (home / "receipts" / "installer.sha256").read_text(encoding="ascii")
    assert record == f"{hashlib.sha256(saved.read_bytes()).hexdigest()}  install.sh\n"
    monkeypatch.setattr(upgrade_shim, "_installer_name", lambda: "install.sh")
    upgrade_shim._check_saved_installer(str(saved), str(saved), str(home), "1.0.4")
    saved.write_bytes(saved.read_bytes() + b"# r28sa note\n")
    with pytest.raises(upgrade_shim.ShimError, match="is not the one DefenseClaw saved"):
        upgrade_shim._check_saved_installer(str(saved), str(saved), str(home), "1.0.4")
    text = INSTALL_SH.read_text(encoding="utf-8")
    finish = text[text.index("finish_swap() {") : text.index("\n}\n", text.index("finish_swap() {"))]
    assert finish.index('mv -f "${tmp}" "${INSTALLER_DIR}/install.sh"') < finish.index("record_saved_installer")
    assert finish.index('cp "${BASH_SOURCE[0]}" "${INSTALLER_DIR}/install.sh"') < finish.index("record_saved_installer")


def test_no_saved_installer_leaves_no_record(tmp_path: Path) -> None:
    home = _record_saved_installer(tmp_path, saved=False)
    assert not (home / "receipts" / "installer.sha256").exists()
