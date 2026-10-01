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
