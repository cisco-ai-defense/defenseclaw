# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""scripts/runner-apt-install.sh: CI steps survive an unreachable apt archive.

The script skips apt when the tools are already on the runner, retries apt
with backoff, and falls back to a SHA-256 pinned .deb only for this Ubuntu
release; any other outcome still fails the step (rel-1-0-6 GAP-1070).
apt-get, sudo, sleep, timeout, curl and dpkg are stubs on PATH, so nothing installs.
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "runner-apt-install.sh"
TOOL = "dc-apt-fixture-tool"
POOL_PATH = "pool/universe/d/dc-apt-fixture/dc-apt-fixture_1.0_amd64.deb"

pytestmark = pytest.mark.skipif(
    not sys.platform.startswith("linux") or not Path("/etc/os-release").is_file(),
    reason="the script runs on Ubuntu runners and reads /etc/os-release",
)


def _codename() -> str:
    for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
        if line.startswith("VERSION_CODENAME="):
            return line.split("=", 1)[1].strip().strip('"')
    return ""


def _stub(bin_dir: Path, name: str, body: str) -> None:
    path = bin_dir / name
    path.write_text("#!/bin/sh\n" + body, encoding="utf-8")
    path.chmod(0o755)


def _run(
    tmp_path: Path,
    *,
    apt_fails: int,
    pin_sha: str | None,
    deb: bytes = b"fixture deb",
    installs: bool = True,
    preinstalled: bool = False,
    commands: str = TOOL,
):
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    shutil.copy2(SCRIPT, scripts / SCRIPT.name)
    pins = "# fixture pins\n"
    if pin_sha is not None:
        pins += f"dc-apt-fixture {_codename()} {POOL_PATH} {pin_sha}\n"
    (scripts / "runner-apt-pins.txt").write_text(pins, encoding="utf-8")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log = tmp_path / "calls.log"
    fixture = tmp_path / "fixture.deb"
    fixture.write_bytes(deb)
    counter = tmp_path / "apt-installs"
    make_tool = f'printf "#!/bin/sh\\n" > {bin_dir / TOOL}; chmod +x {bin_dir / TOOL}\n' if installs else ""
    _stub(bin_dir, "sudo", 'exec "$@"\n')
    _stub(bin_dir, "sleep", f'echo "sleep $*" >> {log}\n')
    _stub(bin_dir, "timeout", f'echo "timeout $1" >> {log}\nshift\nexec "$@"\n')
    _stub(
        bin_dir,
        "apt-get",
        f'echo "apt-get $*" >> {log}\n'
        'case "$*" in *" update "*|*" update") exit 0;; esac\n'
        f"echo x >> {counter}\n"
        f'[ "$(wc -l < {counter})" -le {apt_fails} ] && exit 100\n' + make_tool + "exit 0\n",
    )
    _stub(
        bin_dir,
        "curl",
        f'echo "curl $*" >> {log}\nwhile [ $# -gt 1 ]; do [ "$1" = -o ] && out=$2; shift; done\ncp {fixture} "$out"\n',
    )
    _stub(bin_dir, "dpkg", f'echo "dpkg $*" >> {log}\n' + make_tool)
    if preinstalled:
        _stub(bin_dir, TOOL, "exit 0\n")
    temp = tmp_path / "runner-temp"
    temp.mkdir()
    env = {"PATH": f"{bin_dir}:/usr/bin:/bin", "RUNNER_TEMP": str(temp), "HOME": str(tmp_path)}
    result = subprocess.run(
        ["bash", str(scripts / SCRIPT.name), commands, "dc-apt-fixture"],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
        check=False,
    )
    calls = log.read_text(encoding="utf-8").splitlines() if log.exists() else []
    return result, calls, temp


def test_tools_already_on_the_runner_skip_apt(tmp_path: Path) -> None:
    result, calls, _ = _run(
        tmp_path, apt_fails=3, pin_sha=None, preinstalled=True, commands=f"dc-apt-absent-tool|{TOOL}"
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert calls == []
    assert "apt not used" in result.stdout


def test_apt_is_retried_after_a_failed_try(tmp_path: Path) -> None:
    result, calls, _ = _run(tmp_path, apt_fails=1, pin_sha=None)
    assert result.returncode == 0, result.stdout + result.stderr
    downloads = [c for c in calls if c.startswith("apt-get") and "--download-only" in c]
    assert len(downloads) == 2
    assert [c for c in calls if "--no-download" in c] == ["apt-get install -y -q --no-download dc-apt-fixture"]
    assert all("Acquire::Retries=3" in c for c in calls if c.startswith("apt-get") and "--no-download" not in c)
    # Every apt network phase runs under a 30 s cut; the cache install needs none.
    network = [i for i, c in enumerate(calls) if c.startswith("apt-get") and "--no-download" not in c]
    assert all(calls[i - 1] == "timeout 30" for i in network)
    assert calls[calls.index("apt-get install -y -q --no-download dc-apt-fixture") - 1] != "timeout 30"
    assert "sleep 15" in calls
    assert not any(c.startswith(("curl", "dpkg")) for c in calls)


def test_unreachable_apt_installs_the_pinned_deb(tmp_path: Path) -> None:
    deb = b"fixture deb"
    result, calls, temp = _run(tmp_path, apt_fails=3, pin_sha=hashlib.sha256(deb).hexdigest(), deb=deb)
    assert result.returncode == 0, result.stdout + result.stderr
    assert [c for c in calls if c.startswith("sleep")] == ["sleep 15", "sleep 30"]
    assert any(c.startswith("curl") and f"https://mirrors.edge.kernel.org/ubuntu/{POOL_PATH}" in c for c in calls)
    assert any(c.startswith("dpkg -i") for c in calls)
    assert list(temp.iterdir()) == []


def test_a_deb_that_misses_its_pin_is_not_installed(tmp_path: Path) -> None:
    result, calls, temp = _run(tmp_path, apt_fails=3, pin_sha=hashlib.sha256(b"other").hexdigest())
    assert result.returncode == 1
    assert "pinned SHA-256" in result.stdout
    assert not any(c.startswith("dpkg") for c in calls)
    assert list(temp.iterdir()) == []


@pytest.mark.parametrize("installs", [True, False])
def test_failures_that_leave_the_tool_missing_fail_the_step(tmp_path: Path, installs: bool) -> None:
    # installs=True: apt never answers and nothing is pinned for this release.
    # installs=False: apt reports success but the tool is still not on PATH.
    result, calls, _ = _run(tmp_path, apt_fails=3 if installs else 0, pin_sha=None, installs=installs)
    assert result.returncode == 1
    assert ("pins no dc-apt-fixture" if installs else "not on PATH") in result.stdout
    assert not any(c.startswith("dpkg") for c in calls)
