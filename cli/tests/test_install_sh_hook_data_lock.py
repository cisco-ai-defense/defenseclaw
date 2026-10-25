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
no install and the default tier let tool calls through.

Loop round 2: the installer read data_dir with a line reader, so a quoted key
("data_dir": ...) or any other YAML form named no folder and the hole stayed
open. It now asks the gateway (hook-data-dir), which reads the config with
the runtime's own loader (internal/cli TestHookDataDirNow...): the installed
gateway before anything may stop it, the staged one before the swap. A
gateway that cannot read the config stops the install before any change.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest
from defenseclaw.commands import cmd_doctor

ROOT = Path(__file__).resolve().parents[2]
INSTALL_SH = ROOT / "scripts" / "install.sh"
BASH = shutil.which("bash")

pytestmark = pytest.mark.skipif(os.name == "nt" or BASH is None, reason="POSIX installer")

_PROBE = """
for held in ${DATA_LOCK_DIRS[@]+"${DATA_LOCK_DIRS[@]}"}; do
    printf 'held=%s pid=%s self=%s\\n' "${held}" "$(cat "${held}/pid")" "$$"
done
echo done
"""

# A gateway with hook-data-dir: it prints STUB_DATA_DIR, or fails with
# STUB_FAIL set. STUB_OLD makes it an older release without the command.
_STUB = """#!/bin/sh
if [ -n "${STUB_OLD:-}" ]; then
    echo "Usage:\n  defenseclaw-gateway [command]"
    exit 0
fi
case "$1 $2" in
    "hook-data-dir --help") echo "Usage:\n  defenseclaw-gateway hook-data-dir [flags]"; exit 0 ;;
    "hook-data-dir ") ;;
    *) exit 64 ;;
esac
[ -z "${STUB_FAIL:-}" ] || { echo "config.yaml is not YAML the gateway can read" >&2; exit 1; }
printf '%s\\n' "${STUB_DATA_DIR:-}"
"""


def _functions() -> str:
    text = INSTALL_SH.read_text(encoding="utf-8")
    owner = text.index('LOCK_STARTED="$(date +%s)"')
    owner_end = text.index('if ! mkdir "${LOCK_DIR}" 2>/dev/null; then', owner)
    start = text.index("DATA_LOCK_DIRS=()")
    end = text.index('\nhold_hook_data_dir "${BIN_DIR}/defenseclaw-gateway"\n', start)
    return text[owner:owner_end] + text[start:end] + "\n"


def _gateway(tmp_path: Path, name: str = "gw") -> Path:
    path = tmp_path / name
    path.write_text(_STUB, encoding="utf-8")
    path.chmod(0o755)
    return path


def _run(tmp_path: Path, home: Path, body: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    lock = home / ".install.lock"
    script = tmp_path / "hold.sh"
    script.write_text(
        "set -euo pipefail\n"
        "die() { printf '%s\\n' \"$*\" >&2; exit 1; }\nerr() { :; }\n"
        f'DEFENSECLAW_HOME={home}\nLOCK_DIR={lock}\nmkdir -p "$LOCK_DIR"\n'
        + _functions()
        + 'write_lock_owner "$LOCK_DIR"\n'
        + body
        + _PROBE,
        encoding="utf-8",
    )
    run_env = {"HOME": str(tmp_path / "user"), "PATH": os.environ.get("PATH", "/usr/bin:/bin")}
    run_env.update(env or {})
    return subprocess.run([BASH, str(script)], capture_output=True, text=True, env=run_env, timeout=30, check=False)


def _held(proc: subprocess.CompletedProcess[str]) -> list[str]:
    return [line.split(" ")[0].removeprefix("held=") for line in proc.stdout.splitlines() if line.startswith("held=")]


def _layout(tmp_path: Path) -> tuple[Path, Path]:
    home = tmp_path / "user" / ".defenseclaw"
    data = tmp_path / "srv" / "dc-data"
    home.mkdir(parents=True)
    data.mkdir(parents=True)
    return home, data


@pytest.mark.parametrize("which", ["installed", "staged"])
def test_the_data_dir_the_gateway_names_is_held_until_the_install_exits(tmp_path: Path, which: str) -> None:
    home, data = _layout(tmp_path)
    gw = _gateway(tmp_path)
    call = f'hold_hook_data_dir "{gw}"' + (" required" if which == "staged" else "") + "\n"
    proc = _run(tmp_path, home, call, {"STUB_DATA_DIR": str(data)})
    assert proc.returncode == 0, proc.stderr
    assert _held(proc) == [f"{data.resolve()}/.install.lock"]
    pid, own = proc.stdout.splitlines()[0].split(" ")[1:]
    assert pid.split("=")[1] == own.split("=")[1]
    # The EXIT trap gives both folders back.
    assert not (data / ".install.lock").exists()
    assert not (home / ".install.lock").exists()


def test_installed_and_staged_answers_are_both_held_once(tmp_path: Path) -> None:
    home, data = _layout(tmp_path)
    other = tmp_path / "srv" / "new-data"
    other.mkdir()
    link = tmp_path / "srv" / "data-link"
    link.symlink_to(data)
    gw = _gateway(tmp_path)
    body = (
        f'STUB_DATA_DIR={data} hold_hook_data_dir "{gw}"\n'
        f'STUB_DATA_DIR={link} hold_hook_data_dir "{gw}" required\n'
        f'STUB_DATA_DIR={other} hold_hook_data_dir "{gw}" required\n'
    )
    proc = _run(tmp_path, home, body)
    assert proc.returncode == 0, proc.stderr
    assert _held(proc) == [f"{data.resolve()}/.install.lock", f"{other.resolve()}/.install.lock"]
    assert not (data / ".install.lock").exists() and not (other / ".install.lock").exists()


@pytest.mark.parametrize("answer", ["", "home", "home/", "link", "missing"])
def test_no_second_lock_when_the_gateway_names_no_other_folder(tmp_path: Path, answer: str) -> None:
    home, _ = _layout(tmp_path)
    link = tmp_path / "user" / "dc-link"
    link.symlink_to(home)
    value = {
        "": "",  # a relative or empty data_dir: the runtime's hooks never open
        "home": str(home),
        "home/": f"{home}/",
        "link": str(link),
        "missing": str(tmp_path / "missing"),  # nothing there to protect yet
    }[answer]
    proc = _run(tmp_path, home, f'hold_hook_data_dir "{_gateway(tmp_path)}" required\n', {"STUB_DATA_DIR": value})
    assert proc.returncode == 0, proc.stderr
    assert _held(proc) == []
    assert not (tmp_path / "missing").exists()


def test_an_older_or_missing_installed_gateway_is_skipped_but_a_staged_one_is_required(tmp_path: Path) -> None:
    home, data = _layout(tmp_path)
    gw = _gateway(tmp_path)
    for body in (f'hold_hook_data_dir "{gw}"\n', f'hold_hook_data_dir "{tmp_path / "absent"}"\n'):
        proc = _run(tmp_path, home, body, {"STUB_OLD": "1", "STUB_DATA_DIR": str(data)})
        assert proc.returncode == 0, proc.stderr
        assert _held(proc) == []
    proc = _run(tmp_path, home, f'hold_hook_data_dir "{gw}" required\n', {"STUB_OLD": "1"})
    assert proc.returncode == 1
    assert "cannot name the data folder of your configuration; nothing was changed" in proc.stderr
    assert not (home / ".install.lock").exists()


@pytest.mark.parametrize("required", ["", " required"])
def test_a_config_the_gateway_cannot_read_stops_the_install(tmp_path: Path, required: str) -> None:
    home, data = _layout(tmp_path)
    proc = _run(
        tmp_path,
        home,
        f'hold_hook_data_dir "{_gateway(tmp_path)}"{required}\n',
        {"STUB_FAIL": "1", "STUB_DATA_DIR": str(data)},
    )
    assert proc.returncode == 1
    assert "Could not read the data folder of your configuration" in proc.stderr
    assert "nothing was changed" in proc.stderr
    assert not (data / ".install.lock").exists()
    assert not (home / ".install.lock").exists()


def test_a_stale_data_dir_lock_is_taken_over_and_a_live_one_refuses(tmp_path: Path) -> None:
    home, data = _layout(tmp_path)
    (data / ".install.lock").mkdir()
    gw = _gateway(tmp_path)
    env = {"STUB_DATA_DIR": str(data)}

    # A lock a crashed install left (its pid is gone) is taken over.
    dead = subprocess.Popen(["true"])
    dead.wait()
    (data / ".install.lock" / "pid").write_text(f"{dead.pid}\n", encoding="utf-8")
    proc = _run(tmp_path, home, f'hold_hook_data_dir "{gw}"\n', env)
    assert proc.returncode == 0, proc.stderr
    assert _held(proc) == [f"{data.resolve()}/.install.lock"]
    assert not (data / ".install.lock").exists()

    # Another running install of that data folder keeps it, and this one stops
    # before it changes anything; its own lock goes, the other one stays.
    other = subprocess.Popen(["sleep", "30"])
    try:
        (data / ".install.lock").mkdir()
        (data / ".install.lock" / "pid").write_text(f"{other.pid}\n", encoding="utf-8")
        proc = _run(tmp_path, home, f'hold_hook_data_dir "{gw}"\n', env)
        assert proc.returncode == 1
        assert f"Another DefenseClaw install is running (pid {other.pid})" in proc.stderr
        assert (data / ".install.lock" / "pid").read_text(encoding="utf-8").strip() == str(other.pid)
        assert not (home / ".install.lock").exists()
    finally:
        other.kill()
        other.wait()


def test_a_failed_install_gives_the_data_dir_lock_back(tmp_path: Path) -> None:
    home, data = _layout(tmp_path)
    body = f'hold_hook_data_dir "{_gateway(tmp_path)}"\ntest -d "${{DATA_LOCK_DIRS[0]}}/"\ndie "the install failed"\n'
    proc = _run(tmp_path, home, body, {"STUB_DATA_DIR": str(data)})
    assert proc.returncode == 1 and "the install failed" in proc.stderr
    assert not (data / ".install.lock").exists()
    assert not (home / ".install.lock").exists()


def test_both_holds_come_before_anything_stops_the_gateway() -> None:
    text = INSTALL_SH.read_text(encoding="utf-8")
    # The data_dir is never read by the installer itself any more.
    assert not re.search(r"awk[^\n]*data_dir", text)
    installed = text.index('\nhold_hook_data_dir "${BIN_DIR}/defenseclaw-gateway"\n')
    staged = text.index('\nhold_hook_data_dir "${STAGING}/bin/defenseclaw-gateway" required\n')
    assert text.index('if ! mkdir "${LOCK_DIR}"') < installed < text.index("# ── Existing install")
    # The installed gateway's answer is held before an interrupted run is
    # recovered and before a rollback stops the gateway.
    assert installed < text.index("\nrecover_interrupted_run\n") < text.index('if [[ "${ROLLBACK}" == true ]]; then')
    # The staged gateway's answer is held after it is checked and before the
    # swap refreshes the hooks, stops the gateway or replaces any file.
    assert text.index('ok "DefenseClaw ${VERSION} is staged and checked"') < staged
    for later in (
        'hold_hook_fail_modes "${OLD_GATEWAY_PID}"',
        "    refresh_hook_fail_modes \\\n",
        'if ! stop_gateway "${BIN_DIR}/defenseclaw-gateway"; then',
        "if ! snapshot; then",
        "if ! swap_in; then",
    ):
        assert staged < text.index(later), later


# oss-outage-open round i and j: every lock install.sh takes records its
# owner (pid, start time), the record the hooks and doctor read (hookexec
# installLockStale); a live installer keeps it however long it runs, and a
# lock whose pid names a process that started after the pid was written (a
# reused pid, also a 1.0.2/1.0.3 PID-only lock) is taken over.
def test_the_data_dir_lock_records_its_owner(tmp_path: Path) -> None:
    home, data = _layout(tmp_path)
    body = (
        f'hold_hook_data_dir "{_gateway(tmp_path)}"\n'
        'lock="${DATA_LOCK_DIRS[0]}"\n'
        'echo "pid=$(cat "$lock/pid") self=$$ started=$(cat "$lock/started") deadline=$(test -e "$lock/deadline" && echo yes || echo no)"\n'
        'echo "identity=$(cat "$lock/proc-start" 2>/dev/null | tr " " "@") own=$(process_identity $$ | tr " " "@")"\n'
    )
    before = int(time.time())
    proc = _run(tmp_path, home, body, {"STUB_DATA_DIR": str(data)})
    assert proc.returncode == 0, proc.stderr
    line = next(item for item in proc.stdout.splitlines() if item.startswith("pid="))
    fields = dict(part.split("=", 1) for part in line.split())
    assert fields["pid"] == fields["self"]
    assert before - 1 <= int(fields["started"]) <= int(time.time()) + 1
    assert fields["deadline"] == "no"
    # Rounds j and k: the lock records the installer's process identity (the
    # Linux boot id and kernel start, the macOS creation second), the record
    # every reader compares as it is, and doctor's reader names it the same.
    ids = dict(
        part.split("=", 1) for part in next(i for i in proc.stdout.splitlines() if i.startswith("identity=")).split()
    )
    if sys.platform.startswith("linux") or sys.platform == "darwin":
        assert ids["identity"] and ids["identity"] == ids["own"]
    else:
        assert ids["identity"] == ""


def _identity(pid: int) -> str:
    identity = cmd_doctor._process_identity(pid)
    assert identity, f"no process identity for pid {pid}"
    return identity


# Rounds j and k (no clock): a pid file dated a week before or after its
# process started stands in for a clock step either way. With its proc-start
# record the live owner holds however the clock stepped, and another record
# (a reused pid) is taken over; without one (1.0.2, 1.0.3) the lock holds
# while its pid names a process, on every system.
@pytest.mark.parametrize("legacy", [False, True])
def test_a_live_installer_keeps_its_lock_however_old_and_a_reused_pid_is_taken_over(
    tmp_path: Path, legacy: bool
) -> None:
    if not legacy and not (sys.platform.startswith("linux") or sys.platform == "darwin"):
        pytest.skip("install.sh records a process identity on Linux and macOS")
    home, data = _layout(tmp_path)
    other = subprocess.Popen(["sleep", "30"])
    lock = data / ".install.lock"
    try:
        lock.mkdir()
        (lock / "pid").write_text(f"{other.pid}\n", encoding="utf-8")
        if not legacy:
            (lock / "started").write_text(f"{int(time.time())}\n", encoding="utf-8")
            (lock / "proc-start").write_text(_identity(other.pid) + "\n", encoding="utf-8")
        for step in (0, -7 * 86400, 7 * 86400):
            then = time.time() + step
            for path in (lock / "pid", lock):
                os.utime(path, (then, then))
            proc = _run(tmp_path, home, f'hold_hook_data_dir "{_gateway(tmp_path)}"\n', {"STUB_DATA_DIR": str(data)})
            assert proc.returncode == 1, (step, proc.stdout)
            assert f"Another DefenseClaw install is running (pid {other.pid})" in proc.stderr
        if legacy:
            return
        # Another process than the record names: a reused pid, taken over.
        identity = _identity(other.pid)
        (lock / "proc-start").write_text(identity[:-1] + str((int(identity[-1]) + 1) % 10) + "\n", encoding="utf-8")
        proc = _run(tmp_path, home, f'hold_hook_data_dir "{_gateway(tmp_path)}"\n', {"STUB_DATA_DIR": str(data)})
        assert proc.returncode == 0, proc.stderr
        assert _held(proc) == [f"{data.resolve()}/.install.lock"]
    finally:
        other.kill()
        other.wait()


# Loop round 2 (P2): a lock naming this installer's own pid is not its own
# (it did not make it): its writer is gone, so it is taken over.
def test_a_lock_naming_the_installers_own_pid_is_taken_over(tmp_path: Path) -> None:
    home, data = _layout(tmp_path)
    (data / ".install.lock").mkdir()
    body = f'echo $$ > "{data}/.install.lock/pid"\nhold_hook_data_dir "{_gateway(tmp_path)}"\n'
    proc = _run(tmp_path, home, body, {"STUB_DATA_DIR": str(data)})
    assert proc.returncode == 0, proc.stderr
    assert _held(proc) == [f"{data.resolve()}/.install.lock"]


# Loop round 2 (P1): with a custom home and no ~/.defenseclaw, hook-data-dir
# names the account's own folder, which every per-user hook checks; install.sh
# makes it for the install, holds its lock, and removes it again on exit.
# Another missing folder is not made (test_no_second_lock_...[missing]).
def test_a_missing_account_folder_is_made_held_and_removed(tmp_path: Path) -> None:
    home, _ = _layout(tmp_path)
    account = tmp_path / "account"
    account.mkdir()
    folder = account / ".defenseclaw"
    proc = _run(tmp_path, home, f'hold_hook_data_dir "{_gateway(tmp_path)}" required\n', {"STUB_DATA_DIR": str(folder)})
    assert proc.returncode == 0, proc.stderr
    assert _held(proc) == [f"{folder.resolve()}/.install.lock"]
    assert not folder.exists()


def test_relative_home_and_config_are_recorded_as_absolute_paths() -> None:
    text = INSTALL_SH.read_text(encoding="utf-8")
    start = text.index("for dc_path_var in DEFENSECLAW_HOME DEFENSECLAW_CONFIG; do")
    end = text.index("done\n", start) + len("done\n")
    script = text[start:end] + 'printf "%s|%s\\n" "$DEFENSECLAW_HOME" "${DEFENSECLAW_CONFIG:-}"\n'
    for home, config, want in (
        ("rel-home", "rel/config.yaml", "{cwd}/rel-home|{cwd}/rel/config.yaml"),
        ("/abs/home", "", "/abs/home|"),
        ("~/x", "/abs/c.yaml", "~/x|/abs/c.yaml"),
    ):
        cwd = Path(tempfile.mkdtemp()).resolve()
        proc = subprocess.run(
            [BASH, "-c", script],
            capture_output=True,
            text=True,
            cwd=cwd,
            check=False,
            timeout=30,
            env={
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "DEFENSECLAW_HOME": home,
                "DEFENSECLAW_CONFIG": config,
            },
        )
        assert proc.returncode == 0, proc.stderr
        assert proc.stdout.strip() == want.format(cwd=cwd)


# oss-outage-open round i loop 2: an install acts under, and gives back,
# only a lock that is still its own.
def test_a_lock_another_run_took_over_stops_the_install_and_stays(tmp_path: Path) -> None:
    home, data = _layout(tmp_path)
    other = subprocess.Popen(["sleep", "30"])
    try:
        body = (
            f'hold_hook_data_dir "{_gateway(tmp_path)}"\n'
            'lock="${DATA_LOCK_DIRS[0]}"\n'
            f'echo {other.pid} > "$lock/pid"\n'
            "assert_locks_ours\n"
            "echo not-reached\n"
        )
        proc = _run(tmp_path, home, body, {"STUB_DATA_DIR": str(data)})
        assert proc.returncode == 1
        assert "is no longer this installer's" in proc.stderr
        assert "not-reached" not in proc.stdout
        # The other run's lock stays; this run's own home lock goes.
        assert (data / ".install.lock" / "pid").read_text(encoding="utf-8").strip() == str(other.pid)
        assert not (home / ".install.lock").exists()
    finally:
        other.kill()
        other.wait()


def test_every_folder_hook_data_dir_names_is_held(tmp_path: Path) -> None:
    home, data = _layout(tmp_path)
    alias = tmp_path / "cfg"
    alias.mkdir()
    proc = _run(
        tmp_path,
        home,
        f'hold_hook_data_dir "{_gateway(tmp_path)}"\n',
        {"STUB_DATA_DIR": f"{alias}\n{data}"},
    )
    assert proc.returncode == 0, proc.stderr
    assert _held(proc) == [f"{alias.resolve()}/.install.lock", f"{data.resolve()}/.install.lock"]


def test_the_install_checks_its_locks_after_the_prompt_and_before_the_swap() -> None:
    text = INSTALL_SH.read_text(encoding="utf-8")
    prompt = text.index('ask_yes_no "Upgrade DefenseClaw ${PREV_VERSION}')
    check = text.index("\nassert_locks_ours\nassert_no_loaded_plugin_agents\n", prompt)
    assert check < text.index('if ! stop_gateway "${BIN_DIR}/defenseclaw-gateway"; then', prompt)
    assert text.index("assert_locks_ours\nif ! snapshot; then") < text.index("if ! swap_in; then")
    rollback = text.index('ask_yes_no "${question}" || die "Rollback cancelled; nothing was changed"')
    assert (
        rollback
        < text.index("    assert_locks_ours\n", rollback)
        < text.index(
            'stop_gateway "${BIN_DIR}/defenseclaw-gateway" || die "The gateway did not stop; nothing was changed"'
        )
    )
