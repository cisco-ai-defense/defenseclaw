# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""config set data_dir moves the folders the gateway reads (GAP-2126)."""

import os
import subprocess

from click.testing import CliRunner
from defenseclaw import config as config_module
from defenseclaw.commands import cmd_config
from defenseclaw.context import AppContext
from defenseclaw.file_permissions import (
    protect_private_file,
    windows_acl_confidentiality_error,
    windows_guard_private_file_error,
)

from tests.environment import isolated_home_env


def _install_home(tmp_path, monkeypatch):
    for key, value in isolated_home_env(tmp_path / "home").items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv("DEFENSECLAW_DEPLOYMENT_MODE", raising=False)
    home = tmp_path / "inst-home"
    home.mkdir()
    path = home / "config.yaml"
    path.write_text(
        f"config_version: 9\ndata_dir: {home.as_posix()}\nobservability: {{}}\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("DEFENSECLAW_HOME", str(home))
    monkeypatch.setenv("DEFENSECLAW_CONFIG", str(path))
    monkeypatch.setattr(cmd_config.config_module, "config_path", lambda: path)
    monkeypatch.setattr("defenseclaw.gateway.local_policy_digest", lambda *a, **kw: None)
    monkeypatch.setattr(cmd_config, "_refresh_stopped_gateway_hooks", lambda *a: [])
    return home, path


def _is_private(path) -> bool:
    """The account-private form the gateway demands of a hook credential."""
    if os.name == "nt":
        return windows_guard_private_file_error(path) is None
    return os.stat(path).st_mode & 0o077 == 0


def _expose(path) -> None:
    """Let every local account read *path* (0644, or an Everyone read grant on Windows)."""
    if os.name == "nt":
        subprocess.run(["icacls", str(path), "/grant", "*S-1-1-0:R"], check=True, capture_output=True)
    else:
        path.chmod(0o644)
    assert not _is_private(path)


def test_omitted_paths_are_under_the_data_dir_config_yaml_names(tmp_path, monkeypatch):
    home, path = _install_home(tmp_path, monkeypatch)
    moved = tmp_path / "dcdata"
    path.write_text(
        f"config_version: 9\ndata_dir: {moved.as_posix()}\nobservability: {{}}\n",
        encoding="utf-8",
    )

    cfg = config_module.load()

    assert cfg.data_dir == moved.as_posix()
    assert cfg.policy_dir == os.path.join(str(moved), "policies")
    assert cfg.quarantine_dir == os.path.join(str(moved), "quarantine")
    assert cfg.plugin_dir == os.path.join(str(moved), "plugins")
    assert os.path.dirname(cfg.audit_db) == str(moved)


def test_config_set_data_dir_seeds_the_rule_packs_the_gateway_loads(tmp_path, monkeypatch):
    home, path = _install_home(tmp_path, monkeypatch)
    moved = tmp_path / "dcdata"

    result = CliRunner().invoke(cmd_config.config_cmd, ["set", "data_dir", str(moved)], obj=AppContext())

    assert result.exit_code == 0, result.output
    assert os.path.isdir(moved / "policies" / "guardrail" / "default"), result.output
    assert f"Seeded the rule packs and Rego policies in {moved / 'policies'}" in result.output
    get = CliRunner().invoke(cmd_config.config_cmd, ["get", "policy_dir"], obj=AppContext())
    assert get.exit_code == 0, get.output
    assert str(moved / "policies") in get.output
    # Moving back seeds the folder it moves to as well.
    again = CliRunner().invoke(cmd_config.config_cmd, ["set", "data_dir", str(home)], obj=AppContext())
    assert again.exit_code == 0, again.output
    assert os.path.isdir(home / "policies" / "guardrail" / "default"), again.output


def test_config_set_data_dir_carries_the_records_the_gateway_needs_to_start(tmp_path, monkeypatch):
    # GAP-0287: the gateway reads the agent versions for hook contract
    # admission from <data_dir>/agent_discovery.json. Without it in the new
    # folder every action-mode connector was refused and the gateway could
    # not start after config set data_dir.
    home, _ = _install_home(tmp_path, monkeypatch)
    discovery = b'{"agents": {"claudecode": {"version": "2.1.286 (Claude Code)", "installed": true}}}\n'
    (home / "agent_discovery.json").write_bytes(discovery)
    (home / "claudecode_backup.json").write_bytes(b'{"original": true}\n')
    (home / "gateway.pid").write_text("4242\n")
    outside = tmp_path / "outside.json"
    outside.write_text("{}")
    os.symlink(outside, home / "codex_backup.json")
    moved = tmp_path / "dcdata"
    moved.mkdir()
    (moved / "claudecode_backup.json").write_bytes(b'{"kept": true}\n')
    # The account path: an elevated Windows runner is an administrator, and an
    # administrator copies nothing (the next test).
    monkeypatch.setattr(cmd_config.config_module, "_is_admin_process", lambda: False)

    result = CliRunner().invoke(cmd_config.config_cmd, ["set", "data_dir", str(moved)], obj=AppContext())

    assert result.exit_code == 0, result.output
    assert (moved / "agent_discovery.json").read_bytes() == discovery
    if os.name == "nt":
        assert windows_acl_confidentiality_error(moved / "agent_discovery.json") is None
    else:
        assert os.stat(moved / "agent_discovery.json").st_mode & 0o077 == 0
    assert (moved / "claudecode_backup.json").read_bytes() == b'{"kept": true}\n'
    assert not os.path.lexists(moved / "codex_backup.json")
    assert not os.path.lexists(moved / "gateway.pid")
    assert (home / "agent_discovery.json").read_bytes() == discovery
    assert "Copied the connector records to the new data_dir: agent_discovery.json." in result.output


def test_config_set_data_dir_keeps_live_hook_credentials(tmp_path, monkeypatch):
    home, path = _install_home(tmp_path, monkeypatch)
    path.write_text(
        f"config_version: 9\ndata_dir: {home.as_posix()}\n"
        "guardrail:\n  connectors:\n    claudecode: {mode: action, enabled: true}\n"
        "    codex: {mode: action, enabled: true}\n"
        "    cursor: {mode: action, enabled: false}\nobservability: {}\n",
        encoding="utf-8",
    )
    old_hooks = home / "hooks"
    old_hooks.mkdir(mode=0o700)
    tokens = {name: os.urandom(32).hex() for name in ("claudecode", "codex")}
    for name, token in tokens.items():
        source = old_hooks / f".hook-{name}.token"
        source.write_text(token + "\n", encoding="ascii")
        protect_private_file(source)
    disabled = old_hooks / ".hook-cursor.token"
    disabled.write_text(os.urandom(32).hex() + "\n", encoding="ascii")
    protect_private_file(disabled)
    moved = tmp_path / "dcdata"
    monkeypatch.setattr(cmd_config.config_module, "_is_admin_process", lambda: False)

    result = CliRunner().invoke(cmd_config.config_cmd, ["set", "data_dir", str(moved)], obj=AppContext())

    assert result.exit_code == 0, result.output
    for name, token in tokens.items():
        source = old_hooks / f".hook-{name}.token"
        target = moved / "hooks" / f".hook-{name}.token"
        assert source.read_text(encoding="ascii").strip() == token
        assert target.read_text(encoding="ascii").strip() == token
        assert _is_private(target)
    assert not (moved / "hooks" / ".hook-cursor.token").exists()


def test_config_set_data_dir_without_hook_credentials_keeps_the_new_hooks_empty(tmp_path, monkeypatch):
    home, _ = _install_home(tmp_path, monkeypatch)
    moved = tmp_path / "dcdata"
    monkeypatch.setattr(cmd_config.config_module, "_is_admin_process", lambda: False)

    result = CliRunner().invoke(cmd_config.config_cmd, ["set", "data_dir", str(moved)], obj=AppContext())

    assert result.exit_code == 0, result.output
    assert not (moved / "hooks").exists()


def test_config_set_data_dir_uses_the_current_hook_credential_in_a_populated_store(tmp_path, monkeypatch):
    home, path = _install_home(tmp_path, monkeypatch)
    path.write_text(
        f"config_version: 9\ndata_dir: {home.as_posix()}\n"
        "guardrail:\n  connector: claudecode\nobservability: {}\n",
        encoding="utf-8",
    )
    old_hooks = home / "hooks"
    old_hooks.mkdir(mode=0o700)
    source = old_hooks / ".hook-claudecode.token"
    live_token = os.urandom(32).hex()
    source.write_text(live_token + "\n", encoding="ascii")
    protect_private_file(source)
    moved = tmp_path / "dcdata"
    new_hooks = moved / "hooks"
    new_hooks.mkdir(parents=True, mode=0o700)
    target = new_hooks / ".hook-claudecode.token"
    prior_token = os.urandom(32).hex()
    assert prior_token != live_token
    target.write_text(prior_token + "\n", encoding="ascii")
    protect_private_file(target)
    monkeypatch.setattr(cmd_config.config_module, "_is_admin_process", lambda: False)

    result = CliRunner().invoke(cmd_config.config_cmd, ["set", "data_dir", str(moved)], obj=AppContext())

    assert result.exit_code == 0, result.output
    assert source.read_text(encoding="ascii") == live_token + "\n"
    assert target.read_text(encoding="ascii") == source.read_text(encoding="ascii")
    assert _is_private(target)


def test_config_set_data_dir_does_not_carry_an_untrusted_hook_credential(tmp_path, monkeypatch):
    home, path = _install_home(tmp_path, monkeypatch)
    path.write_text(
        f"config_version: 9\ndata_dir: {home.as_posix()}\n"
        "guardrail:\n  connector: claudecode\nobservability: {}\n",
        encoding="utf-8",
    )
    hooks = home / "hooks"
    hooks.mkdir(mode=0o700)
    source = hooks / ".hook-claudecode.token"
    source.write_text(os.urandom(32).hex() + "\n", encoding="ascii")
    _expose(source)
    moved = tmp_path / "dcdata"
    monkeypatch.setattr(cmd_config.config_module, "_is_admin_process", lambda: False)

    result = CliRunner().invoke(cmd_config.config_cmd, ["set", "data_dir", str(moved)], obj=AppContext())

    assert result.exit_code == 0, result.output
    assert not (moved / "hooks" / ".hook-claudecode.token").exists()
    assert "warning: scoped hook credentials for claudecode could not be carried" in result.output


def test_config_set_data_dir_copies_no_records_as_an_administrator(tmp_path, monkeypatch):
    # Review of 4c1ab8bf99: under sudo the account config is resolved and
    # data_dir is not limited, so a root copy would drop user-chosen files
    # into any root folder (data_dir /etc/cron.d).
    home, _ = _install_home(tmp_path, monkeypatch)
    (home / "agent_discovery.json").write_bytes(b"{}\n")
    (home / "evil_backup.json").write_bytes(b"* * * * * root id\n")
    monkeypatch.setattr(config_module, "_is_admin_process", lambda: True)
    moved = tmp_path / "dcdata"

    result = CliRunner().invoke(cmd_config.config_cmd, ["set", "data_dir", str(moved)], obj=AppContext())

    assert result.exit_code == 0, result.output
    assert not os.path.lexists(moved / "agent_discovery.json")
    assert not os.path.lexists(moved / "evil_backup.json")
    assert "Did not copy the connector records to the new data_dir: this command runs as an administrator" in result.output


def test_a_record_swapped_for_a_symlink_after_the_check_is_not_read(tmp_path, monkeypatch):
    # Review of 4c1ab8bf99: lstat then open followed a symlink swapped in
    # between; the copy now opens the source without following links.
    old = tmp_path / "old"
    new = tmp_path / "new"
    old.mkdir()
    secret = tmp_path / "secret.txt"
    secret.write_bytes(b"not yours\n")
    record = old / "agent_discovery.json"
    record.write_bytes(b"{}\n")
    real_lstat = os.lstat
    swapped = []

    def lstat_then_swap(path, *args, **kwargs):
        result = real_lstat(path, *args, **kwargs)
        if not swapped and os.fspath(path) == str(record):
            swapped.append(True)
            os.unlink(record)
            os.symlink(secret, record)
        return result

    monkeypatch.setattr(cmd_config.config_module, "_is_admin_process", lambda: False)
    monkeypatch.setattr(cmd_config.os, "lstat", lstat_then_swap)
    notes = cmd_config._carry_connector_records(str(old), str(new))

    monkeypatch.setattr(cmd_config.os, "lstat", real_lstat)
    assert swapped
    assert not os.path.lexists(new / "agent_discovery.json")
    assert any(note.startswith("warning: some connector records were not copied") for note in notes), notes


def _seal_connector_state(home):
    """The hook contract lock and connector backups `setup` leaves for codex and opencode."""
    lock = b'{"version": 1, "connectors": {"codex": {"connector": "codex", "raw_agent_version": "0.5.1"}}}\n'
    (home / "hook_contract_lock.json").write_bytes(lock)
    backups = {
        "codex/config.toml.json": b'{"original": "codex"}\n',
        "opencode/config.json": b'{"original": "opencode"}\n',
    }
    for rel, body in backups.items():
        target = home / "connector_backups" / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(body)
    return lock, backups


def test_config_set_data_dir_carries_the_hook_contract_lock_and_connector_backups(tmp_path, monkeypatch):
    # GAP-0801: a moved data_dir without them left Codex and OpenCode skipped
    # ("agent version not probed") by the restarted gateway on Windows.
    home, _ = _install_home(tmp_path, monkeypatch)
    lock, backups = _seal_connector_state(home)
    outside = tmp_path / "outside.json"
    outside.write_text("{}")
    os.symlink(outside, home / "connector_backups" / "codex" / "planted.json")
    moved = tmp_path / "dcdata"
    monkeypatch.setattr(cmd_config.config_module, "_is_admin_process", lambda: False)

    result = CliRunner().invoke(cmd_config.config_cmd, ["set", "data_dir", str(moved)], obj=AppContext())

    assert result.exit_code == 0, result.output
    assert (moved / "hook_contract_lock.json").read_bytes() == lock
    assert _is_private(moved / "hook_contract_lock.json")
    for rel, body in backups.items():
        assert (moved / "connector_backups" / rel).read_bytes() == body
        assert _is_private(moved / "connector_backups" / rel)
    assert not os.path.lexists(moved / "connector_backups" / "codex" / "planted.json")
    assert (home / "hook_contract_lock.json").read_bytes() == lock
    assert "Copied the connector seals to the new data_dir: hook_contract_lock.json, 2 connector backup files." in (
        result.output
    )
    assert "planted.json" in result.output  # refused, named in the warning


def test_config_set_data_dir_keeps_the_seals_a_populated_data_dir_already_has(tmp_path, monkeypatch):
    home, _ = _install_home(tmp_path, monkeypatch)
    _seal_connector_state(home)
    moved = tmp_path / "dcdata"
    (moved / "connector_backups" / "codex").mkdir(parents=True)
    (moved / "hook_contract_lock.json").write_bytes(b'{"kept": true}\n')
    (moved / "connector_backups" / "codex" / "config.toml.json").write_bytes(b'{"kept": true}\n')
    monkeypatch.setattr(cmd_config.config_module, "_is_admin_process", lambda: False)

    result = CliRunner().invoke(cmd_config.config_cmd, ["set", "data_dir", str(moved)], obj=AppContext())

    assert result.exit_code == 0, result.output
    assert (moved / "hook_contract_lock.json").read_bytes() == b'{"kept": true}\n'
    assert (moved / "connector_backups" / "codex" / "config.toml.json").read_bytes() == b'{"kept": true}\n'
    assert (moved / "connector_backups" / "opencode" / "config.json").read_bytes() == b'{"original": "opencode"}\n'
    assert "Copied the connector seals to the new data_dir: 1 connector backup file." in result.output


def test_config_set_data_dir_without_seals_copies_nothing_and_says_nothing(tmp_path, monkeypatch):
    home, _ = _install_home(tmp_path, monkeypatch)
    moved = tmp_path / "dcdata"
    monkeypatch.setattr(cmd_config.config_module, "_is_admin_process", lambda: False)

    result = CliRunner().invoke(cmd_config.config_cmd, ["set", "data_dir", str(moved)], obj=AppContext())

    assert result.exit_code == 0, result.output
    assert not os.path.lexists(moved / "hook_contract_lock.json")
    assert not os.path.lexists(moved / "connector_backups")
    assert "connector seals" not in result.output
    assert "connector state was not copied" not in result.output


def test_config_set_data_dir_copies_no_seals_as_an_administrator(tmp_path, monkeypatch):
    home, _ = _install_home(tmp_path, monkeypatch)
    _seal_connector_state(home)
    monkeypatch.setattr(config_module, "_is_admin_process", lambda: True)
    moved = tmp_path / "dcdata"

    result = CliRunner().invoke(cmd_config.config_cmd, ["set", "data_dir", str(moved)], obj=AppContext())

    assert result.exit_code == 0, result.output
    assert not os.path.lexists(moved / "hook_contract_lock.json")
    assert not os.path.lexists(moved / "connector_backups")


def test_config_set_data_dir_does_not_carry_a_backup_another_account_could_have_written(tmp_path, monkeypatch):
    if os.name == "nt":
        return  # the Windows form is the custody ACL test of the same helper
    home, _ = _install_home(tmp_path, monkeypatch)
    _seal_connector_state(home)
    planted = home / "connector_backups" / "codex" / "config.toml.json"
    planted.chmod(0o666)
    moved = tmp_path / "dcdata"
    monkeypatch.setattr(cmd_config.config_module, "_is_admin_process", lambda: False)

    result = CliRunner().invoke(cmd_config.config_cmd, ["set", "data_dir", str(moved)], obj=AppContext())

    assert result.exit_code == 0, result.output
    assert not os.path.lexists(moved / "connector_backups" / "codex" / "config.toml.json")
    assert (moved / "connector_backups" / "opencode" / "config.json").is_file()
    assert "warning: some connector state was not copied" in result.output
    assert "connector_backups/codex/config.toml.json" in result.output


def test_config_set_data_dir_creates_the_audit_store_the_way_a_first_run_does(tmp_path, monkeypatch):
    # GAP-0801: the gateway's own first-start store names Administrators on
    # Windows and doctor refuses it; the first-run store keeps this account.
    home, _ = _install_home(tmp_path, monkeypatch)
    moved = tmp_path / "dcdata"
    monkeypatch.setattr(cmd_config.config_module, "_is_admin_process", lambda: False)

    result = CliRunner().invoke(cmd_config.config_cmd, ["set", "data_dir", str(moved)], obj=AppContext())

    assert result.exit_code == 0, result.output
    assert (moved / "audit.db").is_file()
    assert _is_private(moved / "audit.db")
    if os.name == "nt":
        assert windows_acl_confidentiality_error(moved / "audit.db") is None
    import sqlite3

    with sqlite3.connect(moved / "audit.db") as db:
        assert db.execute("select count(*) from sqlite_master where name = 'audit_events'").fetchone() == (1,)


def test_config_set_data_dir_leaves_an_existing_audit_store_alone(tmp_path, monkeypatch):
    home, _ = _install_home(tmp_path, monkeypatch)
    moved = tmp_path / "dcdata"
    moved.mkdir()
    (moved / "audit.db").write_bytes(b"not a database, but the gateway's to judge\n")
    monkeypatch.setattr(cmd_config.config_module, "_is_admin_process", lambda: False)

    result = CliRunner().invoke(cmd_config.config_cmd, ["set", "data_dir", str(moved)], obj=AppContext())

    assert result.exit_code == 0, result.output
    assert (moved / "audit.db").read_bytes() == b"not a database, but the gateway's to judge\n"
    assert "audit store was not created" not in result.output
