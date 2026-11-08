# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""GAP-0788: root-owned state that stops the gateway start of this account.

A gateway that ran under sudo and stopped leaves root-owned state behind. The
blocker scan reads it with ``lstat``, so the tests stand in for the owner of
the files they list (an ordinary user cannot create root-owned ones).
"""

from __future__ import annotations

import os
import shlex
import shutil
import stat
import subprocess
from pathlib import Path

import pytest
from defenseclaw import file_permissions as fp

pytestmark = pytest.mark.skipif(
    os.name == "nt" or not hasattr(os, "geteuid") or os.geteuid() == 0,
    reason="a root caller never sees root-owned leftovers",
)


def _write(directory, name, mode):
    path = directory / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{}")
    path.chmod(mode)
    return path


def _owned_by_root(monkeypatch, *paths):
    real = os.lstat
    owned = {os.fspath(p) for p in paths}

    def lstat(path, *args, **kwargs):
        info = real(path, *args, **kwargs)
        if os.fspath(path) in owned:
            fields = list(info)
            fields[stat.ST_UID] = 0
            return os.stat_result(fields)
        return info

    monkeypatch.setattr(fp.os, "lstat", lstat)


def test_root_files_of_any_mode_block_and_loose_ones_are_flagged(tmp_path, monkeypatch):
    lock = _write(tmp_path, "hook_contract_lock.json", 0o600)
    active = _write(tmp_path, "active_connector.json", 0o644)
    _write(tmp_path, "application_protection_state.json", 0o600)  # owned by this account
    _owned_by_root(monkeypatch, lock, active)

    blockers, loose = fp.root_owned_start_blockers(tmp_path, ai_discovery_enabled=True)

    assert blockers == ["hook_contract_lock.json", "active_connector.json"]
    assert loose == [str(active)]


def test_the_sudo_leftovers_row_still_names_private_files_only(tmp_path, monkeypatch):
    lock = _write(tmp_path, "hook_contract_lock.json", 0o600)
    active = _write(tmp_path, "active_connector.json", 0o644)
    _owned_by_root(monkeypatch, lock, active)

    assert fp.sudo_runtime_leftover_relpaths(tmp_path) == ["hook_contract_lock.json"]


def test_a_root_owned_store_this_account_cannot_use_is_named_as_a_whole(tmp_path, monkeypatch):
    _owned_by_root(monkeypatch, tmp_path)
    monkeypatch.setattr(fp.os, "access", lambda *_a, **_k: False)
    blockers, loose = fp.root_owned_start_blockers(tmp_path, ai_discovery_enabled=True)
    assert blockers == [fp.STORE_DIR_ENTRY]
    # Its files are invisible, so the store is also listed as a folder to sweep.
    assert loose == [os.fspath(tmp_path) + os.sep]

    # The benign twin: the same owner with write access to the store is no blocker.
    monkeypatch.setattr(fp.os, "access", lambda *_a, **_k: True)
    assert fp.root_owned_start_blockers(tmp_path, ai_discovery_enabled=True) == ([], [])


def test_discovery_state_blocks_only_while_discovery_is_enabled(tmp_path, monkeypatch):
    state = _write(tmp_path, "ai_discovery_state.json", 0o600)
    _owned_by_root(monkeypatch, state)

    assert fp.root_owned_start_blockers(tmp_path, ai_discovery_enabled=False) == ([], [])
    assert fp.root_owned_start_blockers(tmp_path, ai_discovery_enabled=True) == (["ai_discovery_state.json"], [])


def test_a_root_owned_pid_record_in_the_install_home_blocks_a_moved_store(tmp_path, monkeypatch):
    store = tmp_path / "store"
    home = tmp_path / "home"
    stale = _write(store, "gateway.pid", 0o600)  # the start reads the record from the home, not here
    pid = _write(home, "gateway.pid", 0o600)
    _write(home, "device.key", 0o600)  # root-owned in a home the store left: not read
    _owned_by_root(monkeypatch, stale, pid, home / "device.key")

    blockers, loose = fp.root_owned_start_blockers(store, ai_discovery_enabled=True, pid_dir=home)

    assert blockers == [str(pid)]
    assert loose == []
    # With the store and the install home one folder, the record is read from it.
    assert fp.root_owned_start_blockers(store, ai_discovery_enabled=True, pid_dir=store)[0] == ["gateway.pid"]


def test_the_hook_files_are_read_from_the_store_not_the_install_home(tmp_path, monkeypatch):
    store = tmp_path / "store"
    home = tmp_path / "home"
    old_token = _write(home, "hooks/.hook-old.token", 0o600)
    new_token = _write(store, "hooks/.hook-new.token", 0o600)
    _owned_by_root(monkeypatch, old_token, home / "hooks", new_token)

    blockers, _ = fp.root_owned_start_blockers(store, ai_discovery_enabled=True, pid_dir=home)

    assert blockers == ["hooks/.hook-new.token"]
    # The benign twin: nothing root-owned under the store, a stale hooks folder in the old home.
    new_token.unlink()
    assert fp.root_owned_start_blockers(store, ai_discovery_enabled=True, pid_dir=home) == ([], [])


def test_an_account_owned_store_has_no_blockers(tmp_path):
    for name in fp.SUDO_RUNTIME_LEFTOVER_NAMES:
        _write(tmp_path, name, 0o600)
    _write(tmp_path, "hooks/.hook-abc.token", 0o600)

    assert fp.root_owned_start_blockers(tmp_path, ai_discovery_enabled=True, pid_dir=tmp_path) == ([], [])
    assert fp.root_owned_start_blockers(tmp_path / "missing", ai_discovery_enabled=True) == ([], [])


def _local_chain_steps(command: str) -> list[str]:
    """The printed steps this account can run itself: not sudo, not the start."""
    return [step for step in command.split(" && ") if not step.startswith("sudo ") and "defenseclaw-gateway start" not in step]


def test_chain_restores_owner_access_so_the_files_are_usable(tmp_path, monkeypatch) -> None:
    """The owner return alone leaves a mode 000 file (or 044, once loosened) unreadable.

    The printed chain restores the owner bits (group and other untouched), then
    takes group and other access away from the loose one. The steps run for
    real on files of this account, in the order they are printed.
    """
    from defenseclaw.commands import cmd_doctor

    home = tmp_path / "install home"
    unreadable = _write(home, "active_connector.json", 0)
    loose = _write(home, "hook_contract_lock.json", 0o044)
    token = _write(home, "hooks/.hook-a.token", 0)
    (home / "hooks").chmod(0)
    monkeypatch.setattr(cmd_doctor, "_root_gateway_install_home", lambda _cfg: os.fspath(home))
    monkeypatch.setattr(cmd_doctor, "_root_gateway_moved_store", lambda: ("", "", False))
    try:
        command = cmd_doctor._root_gateway_return_and_start_command(None, (os.fspath(loose),))
        local = _local_chain_steps(command)
        owned = shlex.quote(os.fspath(home))
        assert command.startswith(f'sudo chown -R "$(id -un)" {owned} && chmod -R u+rwX {owned} && chmod go-rwx ')
        assert len(local) == 2, local
        subprocess.run(["sh", "-c", " && ".join(local)], check=True)
        for path in (unreadable, loose, token):
            assert stat.S_IMODE(path.stat().st_mode) == 0o600, path
            assert path.read_text() == "{}"
    finally:
        (home / "hooks").chmod(0o700)


def test_chain_without_named_files_restores_owner_access_on_what_it_returns(monkeypatch, tmp_path) -> None:
    """Status and the Sidecar API row know no file: the chain is still the same."""
    from defenseclaw.commands import cmd_doctor

    home = tmp_path / "home"
    monkeypatch.setattr(cmd_doctor, "_root_gateway_install_home", lambda _cfg: os.fspath(home))
    monkeypatch.setattr(cmd_doctor, "_root_gateway_moved_store", lambda: ("", "", False))
    quoted = shlex.quote(os.fspath(home))
    assert cmd_doctor._root_gateway_return_and_start_command(None).endswith(
        f"{quoted} && chmod -R u+rwX {quoted} && defenseclaw-gateway start"
    )


# GAP-0848: a root-run gateway wrote the agent config files in the account home
# as root. The Sudo leftovers row and the printed chain return them too.


def _agent_home(tmp_path, monkeypatch):
    home = tmp_path / "account home"
    home.mkdir()
    monkeypatch.setenv("HOME", os.fspath(home))
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    monkeypatch.delenv("CODEX_HOME", raising=False)
    monkeypatch.setenv("DEFENSECLAW_HOME", os.fspath(home / ".defenseclaw"))
    monkeypatch.delenv("DEFENSECLAW_CONFIG", raising=False)
    (home / ".defenseclaw").mkdir()
    return home, {
        "claude": _write(home, ".claude/settings.json", 0o600),
        "codex": _write(home, ".codex/config.toml", 0o600),
        "copilot": _write(home, ".copilot/hooks/defenseclaw.json", 0o600),
        "cursor": _write(home, ".cursor/hooks.json", 0o600),
    }


def _cfg(home):
    from types import SimpleNamespace

    return SimpleNamespace(data_dir=os.fspath(home / ".defenseclaw"), deployment_mode="")


def test_the_chain_and_the_row_return_agent_config_files_root_wrote(tmp_path, monkeypatch):
    from defenseclaw import gateway as gateway_module
    from defenseclaw.commands import cmd_doctor

    home, files = _agent_home(tmp_path, monkeypatch)
    monkeypatch.setattr(gateway_module, "resolve_gateway_binary", lambda: "")
    cfg = _cfg(home)
    owned = [files["claude"], files["codex"], files["copilot"]]
    _owned_by_root(monkeypatch, *owned)

    assert cmd_doctor._root_owned_agent_config_paths() == sorted(os.fspath(p) for p in owned)
    chain = cmd_doctor._root_leftovers_remedy(cfg)
    step = cmd_doctor._root_agent_config_return_step(sorted(os.fspath(p) for p in owned))
    assert f" && {step} && defenseclaw-gateway start" in chain
    # The paths enter a step that re-checks each one when it runs, never a bare chown.
    assert "sudo chown " + chr(34) + "$(id -un)" + chr(34) + " " + shlex.quote(os.fspath(files["claude"])) not in chain
    for token in ("-links 1", "-user root", "-execdir chown -h", "cd -P"):
        assert token in step
    assert os.fspath(files["cursor"]) not in chain  # the account still owns it

    result = cmd_doctor._DoctorResult(quiet=True)
    cmd_doctor._check_sudo_runtime_leftovers(cfg, result)
    check = result.checks[-1]
    assert check["status"] == "fail"
    assert all(os.fspath(p) in check["detail"] for p in owned)


def test_an_account_owned_home_keeps_the_chain_and_the_row_as_they_were(tmp_path, monkeypatch):
    from defenseclaw import gateway as gateway_module
    from defenseclaw.commands import cmd_doctor

    home, _files = _agent_home(tmp_path, monkeypatch)
    monkeypatch.setattr(gateway_module, "resolve_gateway_binary", lambda: "")

    assert cmd_doctor._root_owned_agent_config_paths() == []
    assert "-links 1" not in cmd_doctor._root_leftovers_remedy(_cfg(home))
    result = cmd_doctor._DoctorResult(quiet=True)
    cmd_doctor._check_sudo_runtime_leftovers(_cfg(home), result)
    assert result.checks[-1]["status"] == "pass"


def test_a_root_owned_vendor_folder_is_returned_whole_not_its_files(tmp_path, monkeypatch):
    from defenseclaw.commands import cmd_doctor

    _home, files = _agent_home(tmp_path, monkeypatch)
    folder = files["copilot"].parent
    _owned_by_root(monkeypatch, folder, files["copilot"])

    assert cmd_doctor._root_owned_agent_config_paths() == [os.fspath(folder)]


def test_a_path_that_links_outside_the_home_is_never_returned(tmp_path, monkeypatch):
    from defenseclaw.commands import cmd_doctor

    home, files = _agent_home(tmp_path, monkeypatch)
    outside = tmp_path / "outside"
    target = _write(outside, "settings.json", 0o600)
    # A folder link on the way, a file link, and a hard link to the outside inode.
    (home / ".claude" / "settings.json").unlink()
    (home / ".claude").rmdir()
    os.symlink(outside, home / ".claude")
    files["codex"].unlink()
    os.symlink(target, files["codex"])
    files["copilot"].unlink()
    os.link(target, files["copilot"])
    _owned_by_root(monkeypatch, target, files["copilot"], files["codex"], home / ".claude" / "settings.json")

    assert cmd_doctor._root_owned_agent_config_paths() == []


def test_the_return_step_skips_a_folder_swapped_for_a_link_after_the_scan(tmp_path):
    import subprocess

    from defenseclaw.commands import cmd_doctor

    root = tmp_path.resolve()
    outside = root / "outside"
    _write(outside, "settings.json", 0o600)
    swapped = root / "swapped"
    os.symlink(outside, swapped)
    fake = root / "bin"
    fake.mkdir()
    log = root / "sudo.log"
    sudo = fake / "sudo"
    sudo.write_text("\n".join(["#!/bin/sh", "echo $* >> " + os.fspath(log), ""]))
    sudo.chmod(0o755)
    plain = _write(root / "plain", "settings.json", 0o600)

    step = cmd_doctor._root_agent_config_return_step([os.fspath(swapped / "settings.json"), os.fspath(plain)])
    done = subprocess.run(
        ["sh", "-c", step],
        env={"PATH": os.fspath(fake) + ":/usr/bin:/bin"},
        capture_output=True,
        text=True,
        check=False,
    )

    assert done.returncode == 0
    assert "skipped" in done.stderr
    calls = log.read_text().splitlines()
    assert len(calls) == 1 and "find -P ./settings.json" in calls[0]


@pytest.mark.skipif(shutil.which("find") is None, reason="find is not available")
@pytest.mark.parametrize(
    ("parent", "path"),
    [(".claude", ".claude/settings.json"), (".copilot", ".copilot/hooks")],
)
def test_the_return_step_walks_the_folder_it_checked_when_a_parent_is_swapped_for_a_link(tmp_path, parent, path):
    """A parent swapped for a link at the moment sudo runs must not change which folder the find walks."""
    import getpass

    from defenseclaw.commands import cmd_doctor

    base = tmp_path.resolve()
    home = base / "home"
    outside = base / "outside"
    target = home / path
    for item in (target, outside / Path(path).name):
        if item.name == "hooks":
            item.mkdir(parents=True)
        else:
            _write(item.parent, item.name, 0o600)
    fake = base / "bin"
    fake.mkdir()
    log = base / "chown.log"
    link = home / parent
    scripts = {
        "sudo": "\n".join(
            [
                "#!/bin/sh",
                f"mv '{link}' '{link}-moved'",
                f"ln -s '{outside}' '{link}'",
                "n=$#; while [ $n -gt 0 ]; do a=$1; shift; "
                f'[ "$a" = root ] && a={getpass.getuser()}; set -- "$@" "$a"; n=$((n-1)); done',
                'exec "$@"',
                "",
            ]
        ),
        "chown": f'#!/bin/sh\necho "$(/bin/pwd -P)" >> {log}\n',
        "chmod": "#!/bin/sh\n",
    }
    for name, body in scripts.items():
        (fake / name).write_text(body)
        (fake / name).chmod(0o755)

    step = cmd_doctor._root_agent_config_return_step([os.fspath(target)])
    done = subprocess.run(
        ["sh", "-c", step],
        env={"PATH": os.fspath(fake) + ":/usr/bin:/bin", "HOME": os.fspath(home)},
        capture_output=True,
        text=True,
        check=False,
    )

    assert done.returncode == 0, done.stderr
    folders = log.read_text().split()
    assert folders, "the owner change never ran"
    assert all(folder.startswith(os.fspath(link) + "-moved") for folder in folders), folders
