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

"""install.sh holds a data_dir set apart from DEFENSECLAW_HOME while it runs.

oss-outage-open review (round g, loop round 1): the hooks of a custom
data_dir look for .install.lock in that folder. install.sh took it only in
DEFENSECLAW_HOME, so with the gateway stopped for an upgrade those hooks saw
no install and the default tier let tool calls through. The installer now
holds the config's data_dir as well, for exactly as long as its own lock.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
INSTALL_SH = ROOT / "scripts" / "install.sh"
BASH = shutil.which("bash")

pytestmark = pytest.mark.skipif(os.name == "nt" or BASH is None, reason="POSIX installer")

_PROBE = """
if [ -n "${DATA_LOCK_DIR}" ]; then
    printf 'held=%s pid=%s self=%s\\n' "${DATA_LOCK_DIR}" "$(cat "${DATA_LOCK_DIR}/pid")" "$$"
else
    echo held=
fi
"""


def _lock_block() -> str:
    text = INSTALL_SH.read_text(encoding="utf-8")
    start = text.index('DATA_LOCK_DIR=""')
    end = text.index("\nhold_hook_data_dir\n", start) + len("\nhold_hook_data_dir\n")
    block = text[start:end]
    # The hold runs right after the installer's own lock, before it looks at
    # (and may stop) the running gateway.
    assert text.index('if ! mkdir "${LOCK_DIR}"') < start < text.index("# ── Existing install")
    return block


def _run(tmp_path: Path, home: Path, *, config_env: str = "", probe: str = _PROBE) -> subprocess.CompletedProcess[str]:
    lock = home / ".install.lock"
    script = tmp_path / "hold.sh"
    script.write_text(
        "set -euo pipefail\n"
        "die() { printf '%s\\n' \"$*\" >&2; exit 1; }\nerr() { :; }\n"
        f"DEFENSECLAW_HOME={home}\nLOCK_DIR={lock}\nmkdir -p \"$LOCK_DIR\"\n"
        + _lock_block()
        + probe,
        encoding="utf-8",
    )
    env = {"HOME": str(tmp_path / "user"), "PATH": os.environ.get("PATH", "/usr/bin:/bin")}
    if config_env:
        env["DEFENSECLAW_CONFIG"] = config_env
    return subprocess.run([BASH, str(script)], capture_output=True, text=True, env=env, timeout=30, check=False)


@pytest.mark.parametrize(
    "line",
    [
        "data_dir: {data}",
        'data_dir: "{data}"',
        "data_dir: '{data}'",
        "data_dir: {data}   # where the hooks live",
        "data_dir: {data}\r",
        "data_dir: ~/custom-data",
    ],
)
def test_the_config_data_dir_is_held_while_the_install_runs(tmp_path: Path, line: str) -> None:
    home = tmp_path / "user" / ".defenseclaw"
    data = tmp_path / "user" / "custom-data"
    home.mkdir(parents=True)
    data.mkdir()
    (home / "config.yaml").write_text(
        "config_version: 9\n" + line.format(data=data) + "\nguardrail:\n  mode: observe\n", encoding="utf-8"
    )
    proc = _run(tmp_path, home)
    assert proc.returncode == 0, proc.stderr
    held, pid, own = proc.stdout.strip().split(" ")
    assert held == f"held={data}/.install.lock"
    assert pid.split("=")[1] == own.split("=")[1]
    # The EXIT trap gives both folders back.
    assert not (data / ".install.lock").exists()
    assert not (home / ".install.lock").exists()


def test_an_external_config_names_the_data_dir(tmp_path: Path) -> None:
    home = tmp_path / "user" / ".defenseclaw"
    data = tmp_path / "srv" / "dc-data"
    home.mkdir(parents=True)
    data.mkdir(parents=True)
    (data / "config.yaml").write_text(f"data_dir: {data}\n", encoding="utf-8")
    proc = _run(tmp_path, home, config_env=str(data / "config.yaml"))
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.startswith(f"held={data}/.install.lock "), proc.stdout


@pytest.mark.parametrize(
    "config",
    [
        None,  # a first install: no config yet
        "guardrail:\n  mode: observe\n",  # no data_dir: DEFENSECLAW_HOME is the data dir
        "data_dir: {home}\n",  # data_dir is DEFENSECLAW_HOME
        "data_dir: {home}/\n",
        "data_dir: {link}\n",  # a link to DEFENSECLAW_HOME
        "data_dir: relative/data\n",  # names no folder this reader takes
        "data_dir: {missing}\n",  # nothing there to protect yet
        "data_dir:\n",
    ],
)
def test_no_second_lock_when_the_data_dir_is_the_installers_own(tmp_path: Path, config: str | None) -> None:
    home = tmp_path / "user" / ".defenseclaw"
    home.mkdir(parents=True)
    link = tmp_path / "user" / "dc-link"
    link.symlink_to(home)
    if config is not None:
        (home / "config.yaml").write_text(
            config.format(home=home, link=link, missing=tmp_path / "missing"), encoding="utf-8"
        )
    proc = _run(tmp_path, home)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "held="
    assert not (tmp_path / "missing").exists()


def test_a_stale_data_dir_lock_is_taken_over_and_a_live_one_refuses(tmp_path: Path) -> None:
    home = tmp_path / "user" / ".defenseclaw"
    data = tmp_path / "data"
    home.mkdir(parents=True)
    (data / ".install.lock").mkdir(parents=True)
    (home / "config.yaml").write_text(f"data_dir: {data}\n", encoding="utf-8")

    # A lock a crashed install left (its pid is gone) is taken over.
    dead = subprocess.Popen(["true"])
    dead.wait()
    (data / ".install.lock" / "pid").write_text(f"{dead.pid}\n", encoding="utf-8")
    proc = _run(tmp_path, home)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.startswith(f"held={data}/.install.lock "), proc.stdout
    assert not (data / ".install.lock").exists()

    # Another running install of that data folder keeps it, and this one stops
    # before it changes anything; its own lock goes, the other one stays.
    other = subprocess.Popen(["sleep", "30"])
    try:
        (data / ".install.lock").mkdir()
        (data / ".install.lock" / "pid").write_text(f"{other.pid}\n", encoding="utf-8")
        proc = _run(tmp_path, home)
        assert proc.returncode == 1
        assert f"Another DefenseClaw install is running (pid {other.pid})" in proc.stderr
        assert (data / ".install.lock" / "pid").read_text(encoding="utf-8").strip() == str(other.pid)
        assert not (home / ".install.lock").exists()
    finally:
        other.kill()
        other.wait()


def test_a_failed_install_gives_the_data_dir_lock_back(tmp_path: Path) -> None:
    home = tmp_path / "user" / ".defenseclaw"
    data = tmp_path / "data"
    home.mkdir(parents=True)
    data.mkdir()
    (home / "config.yaml").write_text(f"data_dir: {data}\n", encoding="utf-8")
    proc = _run(tmp_path, home, probe='test -d "${DATA_LOCK_DIR}/"\ndie "the install failed"\n')
    assert proc.returncode == 1 and "the install failed" in proc.stderr
    assert not (data / ".install.lock").exists()
    assert not (home / ".install.lock").exists()
