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

"""GAP-0466: every release-asset entrypoint answers --help and refuses an
unknown option before it downloads or changes anything.

The 0.8.x handoff (defenseclaw-upgrade.sh) ignored both and started the
installer of the latest published release, which on a 1.0.2 release
candidate was the older 1.0.1. install.sh already behaved; it is the
reference.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
HANDOFF_SH = ROOT / "scripts" / "defenseclaw-upgrade.sh"
INSTALL_PS1 = ROOT / "scripts" / "install.ps1"
BASH = shutil.which("bash")
POWERSHELL = shutil.which("powershell.exe") or shutil.which("pwsh.exe") or shutil.which("pwsh")

posix_only = pytest.mark.skipif(os.name == "nt" or BASH is None, reason="POSIX handoff")


def _tools(tmp_path: Path, latest: str = "1.0.1") -> tuple[Path, Path]:
    """A curl that logs every URL, answers releases/latest with *latest* and
    serves releases/download/<v>/<asset> from tmp_path/releases."""

    tools = tmp_path / "tools"
    tools.mkdir()
    curl_log = tmp_path / "curl.log"
    curl = tools / "curl"
    curl.write_text(
        "#!/bin/sh\n"
        'previous=""; output=""; url=""\n'
        'for arg in "$@"; do\n'
        '  [ "$previous" = "-o" ] && output="$arg"\n'
        '  case "$arg" in https://*) url="$arg";; esac\n'
        '  previous="$arg"\n'
        "done\n"
        f'echo "$url" >> "{curl_log}"\n'
        'case "$url" in\n'
        f'  */releases/latest) printf "HTTP/2 302\\r\\nlocation: https://github.com/cisco-ai-defense/defenseclaw/releases/tag/{latest}\\r\\n";;\n'
        f'  */releases/download/*) cp "{tmp_path}/releases/${{url#*/releases/download/}}" "$output";;\n'
        "  *) exit 1;;\n"
        "esac\n",
        encoding="utf-8",
    )
    curl.chmod(0o755)
    return tools, curl_log


def _release(tmp_path: Path, version: str) -> None:
    target = tmp_path / "releases" / version
    target.mkdir(parents=True)
    installer = f'#!/bin/bash\nreadonly DC_VERSION="{version}"\necho "installer {version} ran: $*"\n'
    (target / "install.sh").write_text(installer, encoding="utf-8")
    digest = hashlib.sha256(installer.encode()).hexdigest()
    (target / "checksums.txt").write_text(f"{digest}  install.sh\n", encoding="utf-8")


def _installed(home: Path, version: str) -> None:
    bin_dir = home / ".local" / "bin"
    bin_dir.mkdir(parents=True)
    gateway = bin_dir / "defenseclaw-gateway"
    gateway.write_text(f'#!/bin/sh\necho "defenseclaw-gateway version {version}"\n', encoding="utf-8")
    gateway.chmod(0o755)


def _handoff(tmp_path: Path, *args: str) -> tuple[subprocess.CompletedProcess[str], list[str]]:
    tools, curl_log = _tools(tmp_path)
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    env = {
        "HOME": str(home),
        # No cosign on this PATH: the official repository is then checked
        # against checksums.txt only, as on a host without cosign.
        "PATH": f"{tools}:/usr/bin:/bin",
        "TMPDIR": str(tmp_path),
    }
    proc = subprocess.run(
        [BASH, str(HANDOFF_SH), *args], capture_output=True, text=True, env=env, timeout=60, check=False
    )
    urls = curl_log.read_text(encoding="utf-8").splitlines() if curl_log.exists() else []
    return proc, urls


@posix_only
@pytest.mark.parametrize("flag", ["--help", "-h"])
def test_handoff_help_prints_usage_and_downloads_nothing(tmp_path: Path, flag: str) -> None:
    _installed(tmp_path / "home", "1.0.2")

    proc, urls = _handoff(tmp_path, "--yes", flag)

    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "Usage: bash defenseclaw-upgrade.sh" in proc.stdout
    assert "--version X.Y.Z" in proc.stdout
    assert "handing off" not in proc.stdout + proc.stderr
    assert urls == []


@posix_only
@pytest.mark.parametrize(
    ("args", "message"),
    [
        (["--wv102-invalid-option"], "unknown option: --wv102-invalid-option; nothing was changed"),
        (["--yes", "--frobnicate", "--version", "1.0.1"], "unknown option: --frobnicate; nothing was changed"),
        (["--version"], "--version needs a release such as 1.0.0; nothing was changed"),
        (["--version", "1.0"], "--version must look like 1.0.0; nothing was changed"),
        (["--version="], "--version must look like 1.0.0; nothing was changed"),
    ],
)
def test_handoff_usage_error_exits_2_before_any_download(tmp_path: Path, args: list[str], message: str) -> None:
    _installed(tmp_path / "home", "1.0.2")

    proc, urls = _handoff(tmp_path, *args)

    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert message in proc.stderr
    assert "Run with --help for the options." in proc.stderr
    assert "handing off" not in proc.stdout + proc.stderr
    assert urls == []


@posix_only
def test_handoff_without_version_never_downgrades_a_newer_install(tmp_path: Path) -> None:
    # The rc host case: 1.0.2 installed, latest published release 1.0.1.
    _release(tmp_path, "1.0.1")
    _installed(tmp_path / "home", "1.0.2")

    proc, urls = _handoff(tmp_path, "--yes")

    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "DefenseClaw 1.0.2 is up to date (latest release: 1.0.1 is older). Nothing was changed." in proc.stdout
    assert "installer 1.0.1 ran" not in proc.stdout
    assert [url for url in urls if "/releases/download/" in url] == []


@posix_only
def test_handoff_with_an_explicit_older_version_still_hands_off(tmp_path: Path) -> None:
    # A downgrade on request stays possible (the release's installer asks).
    _release(tmp_path, "1.0.1")
    _installed(tmp_path / "home", "1.0.2")

    proc, urls = _handoff(tmp_path, "--yes", "--version", "1.0.1")

    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "handing off to the DefenseClaw 1.0.1 installer" in proc.stdout
    assert "installer 1.0.1 ran: --yes --version 1.0.1" in proc.stdout
    assert all("/releases/latest" not in url for url in urls)


@posix_only
@pytest.mark.parametrize("installed", ["", "0.8.10", "1.0.0"])
def test_handoff_without_version_upgrades_an_older_or_missing_install(tmp_path: Path, installed: str) -> None:
    # The 0.8.x bridge and a 1.0.0 host still go to the latest release.
    _release(tmp_path, "1.0.1")
    if installed:
        _installed(tmp_path / "home", installed)

    proc, _urls = _handoff(tmp_path, "--yes", "--recover-corrupt-audit")

    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "installer 1.0.1 ran: --yes --version 1.0.1" in proc.stdout


@pytest.mark.skipif(POWERSHELL is None, reason="PowerShell is not installed")
@pytest.mark.parametrize("flag", ["--help", "-h", "-Help"])
@pytest.mark.parametrize("via", ["file", "call"])
def test_install_ps1_help_forms_print_usage_and_exit_0(tmp_path: Path, flag: str, via: str) -> None:
    # pwsh -File binds --help to -Help itself; a script called in a session
    # (& .\install.ps1 --help) gets it as an unknown argument.
    env = {
        **os.environ,
        "USERPROFILE": str(tmp_path),
        "LOCALAPPDATA": str(tmp_path / "AppData" / "Local"),
        "APPDATA": str(tmp_path / "AppData" / "Roaming"),
        "DEFENSECLAW_HOME": str(tmp_path / "home"),
    }
    invoke = ["-File", str(INSTALL_PS1), flag] if via == "file" else ["-Command", f"& '{INSTALL_PS1}' {flag}; exit $LASTEXITCODE"]
    proc = subprocess.run(
        [POWERSHELL, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", *invoke],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
        env=env,
        check=False,
    )

    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "-Rollback" in proc.stdout
    assert "Unknown option" not in proc.stdout + proc.stderr
    assert not (tmp_path / "home").exists()


def test_install_ps1_takes_the_install_sh_help_spelling() -> None:
    # Static guard for hosts without PowerShell: --help is matched before the
    # unknown-argument refusal.
    text = INSTALL_PS1.read_text(encoding="utf-8")
    help_check = text.index('$UnknownArguments -contains "--help"')
    assert help_check < text.index('Stop-Usage "Unknown option: $argument"')
