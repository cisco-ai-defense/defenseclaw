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
import signal
import subprocess
import sys
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


@pytest.mark.parametrize(("answer", "rc", "expected"), [("ClaudeCode", 0, "Connector: claudecode"), ("99", 2, "No agent picked")])
def test_the_agent_prompt_takes_a_name_and_never_swaps_an_unknown_answer(
    tmp_path: Path, answer: str, rc: int, expected: str
) -> None:
    # GAP-0333: claudecode or 99 at the prompt installed codex without a word.
    tty = tmp_path / "tty"
    tty.write_text(answer + "\n", encoding="utf-8")
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

    result = _run([str(script)], tmp_path)

    assert result.returncode == rc, result.stdout + result.stderr
    assert expected in result.stdout + result.stderr
    assert "Connector: codex" not in result.stdout


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
    assert body.index('Write-Info "Cleaning up') < body.index("Remove-Tree $Previous")


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

    back = _run([str(script), "--rollback", "--yes"], tmp_path, DEFENSECLAW_APP_PATH="none")

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
    forward = _run([str(script), "--rollback", "--yes"], tmp_path, DEFENSECLAW_APP_PATH="none")

    assert forward.returncode == 0, forward.stdout + forward.stderr
    assert not calls.exists()


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

    back = _run([str(_stamped(tmp_path, "1.0.1")), "--rollback", "--yes"], tmp_path, DEFENSECLAW_APP_PATH="none")

    assert back.returncode == 1, back.stdout + back.stderr
    out = back.stdout + back.stderr
    assert "DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT=1 defenseclaw-gateway restart" in out
    assert "Start it with: defenseclaw-gateway start" not in out


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
    assert 'die "Could not write the install lock ${LOCK_DIR}/pid: ${LOCK_HINT}"' in lock
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


def _legacy_0_8_home(home: Path, receipt_age: int, cache_age: int, cache_wheel: str) -> tuple[Path, Path]:
    """Lay out a 0.8.10 install that ran uv's installer and a temporary Cosign, without a marker."""
    bin_dir, dc_home = home / ".local" / "bin", home / ".defenseclaw"
    bin_dir.mkdir(parents=True)
    (bin_dir / "uv").write_text("#!/bin/sh\necho 'uv 0.12.24 (x86_64-unknown-linux-gnu)'\n", encoding="utf-8")
    (bin_dir / "uv").chmod(0o755)
    (bin_dir / "uvx").write_text("uvx", encoding="utf-8")
    receipt = home / ".config" / "uv" / "uv-receipt.json"
    receipt.parent.mkdir(parents=True)
    receipt.write_text(
        f'{{"binaries":["uv","uvx"],"install_prefix":"{bin_dir}","version":"0.12.24"}}', encoding="utf-8"
    )
    site = dc_home / ".venv" / "lib" / "python3.12" / "site-packages"
    for wheel in ("defenseclaw-0.8.10", "litellm-1.91.5"):
        (site / f"{wheel}.dist-info").mkdir(parents=True)
    cfg = dc_home / ".venv" / "pyvenv.cfg"
    cfg.write_text("home = /usr/bin\nuv = 0.12.24\nversion_info = 3.12.14\n", encoding="utf-8")
    cache = home / ".cache" / "uv"
    for archive, wheel in (("a1", "defenseclaw-0.8.10"), ("a2", cache_wheel)):
        (cache / "archive-v0" / archive / f"{wheel}.dist-info").mkdir(parents=True)
    (cache / "CACHEDIR.TAG").write_text("Signature: 8a477f597d28d172789f06886806bc55\n", encoding="utf-8")
    tuf = home / ".sigstore" / "root" / "tuf-repo-cdn.sigstore.dev"
    tuf.mkdir(parents=True)
    (tuf / "root.json").write_text("{}", encoding="utf-8")
    venv_t = 1_700_000_000
    for path in (tuf / "root.json", tuf, tuf.parent, home / ".sigstore"):
        os.utime(path, (venv_t - 5, venv_t - 5))
    (cache / "CACHEDIR.TAG").touch()
    os.utime(cache / "CACHEDIR.TAG", (venv_t - 1, venv_t - 1))
    for path in (*cache.glob("archive-v0/*/*"), *cache.glob("archive-v0/*"), cache / "archive-v0", cache):
        os.utime(path, (venv_t - cache_age, venv_t - cache_age))
    os.utime(receipt, (venv_t - receipt_age, venv_t - receipt_age))
    os.utime(cfg, (venv_t, venv_t))
    return bin_dir, dc_home


@pytest.mark.parametrize(
    ("cache_age", "cache_wheel", "claimed"),
    [
        (-5, "litellm-1.91.5", True),  # the 0.8.10 installer's uv: wheels unpacked for its venv
        (3600, "litellm-1.91.5", False),  # the user's uv: its cache predates the receipt
        (30, "litellm-1.91.5", False),  # the user's uv, used just before the 0.8.10 install
        (-5, "ruff-0.15.7", False),  # the user's uv, used for something DefenseClaw never installed
    ],
)
def test_upgrade_from_0_8_records_uv_only_when_the_0_8_installer_placed_it(
    tmp_path: Path, cache_age: int, cache_wheel: str, claimed: bool
) -> None:
    # GAP-0908: the 0.8.10 installer ran uv's installer and kept no marker,
    # and it also reused a uv the user already had. The upgrade records the
    # uv (the digests install_uv writes) and its cache only on evidence that
    # user's own uv cannot meet.
    home = tmp_path / "home"
    bin_dir, dc_home = _legacy_0_8_home(home, receipt_age=60, cache_age=cache_age, cache_wheel=cache_wheel)
    text = INSTALL_SH.read_text(encoding="utf-8")
    script = tmp_path / "legacy.sh"
    script.write_text(
        'set -euo pipefail\nhas() { [[ "$1" != cosign ]] && command -v "$1" >/dev/null 2>&1; }\n'
        + text[text.index("readonly LEGACY_WINDOW") : text.index("find_legacy_leftovers() {")].replace("readonly ", "")
        + _install_sh_functions("sha256_of", "find_legacy_leftovers", "record_legacy_leftovers")
        + f'HOME="{home}" BIN_DIR="{bin_dir}" DEFENSECLAW_HOME="{dc_home}"\n'
        + "unset XDG_CONFIG_HOME XDG_DATA_HOME XDG_CACHE_HOME UV_CACHE_DIR\n"
        + "find_legacy_leftovers\nrecord_legacy_leftovers\n",
        encoding="utf-8",
    )

    proc = _run([str(script)], tmp_path)

    assert proc.returncode == 0, proc.stderr
    assert (bin_dir / "uv").exists() and (bin_dir / "uvx").exists()
    record = bin_dir / "defenseclaw-uv.sha256"
    leftovers = (dc_home / "legacy-install-leftovers").read_text(encoding="utf-8")
    if not claimed:
        assert not record.exists()
        assert leftovers == "sigstore\n"
        return
    uv_digest = hashlib.sha256((bin_dir / "uv").read_bytes()).hexdigest()
    uvx_digest = hashlib.sha256(b"uvx").hexdigest()
    assert record.read_text(encoding="utf-8") == f"{uv_digest}  uv\n{uvx_digest}  uvx\n"
    assert leftovers == "uv-cache\nsigstore\n"


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
        f'LOG="{tmp_path}/install.log"\n{tee}\n{cancel}\n'
        'mkdir -p "${STAGING}/bin" "${DEFENSECLAW_HOME}/.uv/cache"\nkill -INT 0\nsleep 5\n',
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
