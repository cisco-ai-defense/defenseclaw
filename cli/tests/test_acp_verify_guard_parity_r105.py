# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""`acp verify` reports healthy only what the guard starts (GAP-0879, GAP-0911, GAP-0912).

Also pins two rows met by the per-entry record design: a bypassed adopted
entry stays red after setup (GAP-0496, see test_cmd_acp
test_bypassed_adopted_entry_stays_in_status_and_verify) and setup of one pair
does not re-pin another pair's drifted entry (GAP-0513).
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest
from click.testing import CliRunner
from defenseclaw.commands.cmd_acp import _guard_entry_sha256, acp_cmd
from defenseclaw.file_permissions import atomic_write_private_bytes

from tests.helpers import cleanup_app, make_app_context

# The same settings text and digest as internal/acp
# TestClientEntrySHA256MatchesTheCLIVerify (Go's ClientEntrySHA256).
_PARITY_SETTINGS = (
    r'{"agent_servers":{"DefenseClaw · Kiro":{"command":"/opt/dc/defenseclaw-acp",'
    r'"args":["--client","zed","--","/opt/a&b<c>","acp"],"env":{"K":"v\u2028w","N":"ü"},'
    r'"type":"custom","default_mode":"acceptEdits"}}}'
)
_PARITY_DIGEST = "25bb929d7ff7b94cf02c9b800bd98b742c93fe53afcdc458d4223b8da191ad7e"


def _binary(path: Path) -> str:
    path.write_bytes(b"test-binary")
    path.chmod(0o700)
    return str(path.resolve())


def _setup(tmp_path: Path, monkeypatch, agent_name: str = "kiro"):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / ".config"))
    monkeypatch.setenv("APPDATA", str(tmp_path / "AppData" / "Roaming"))
    data = tmp_path / "data"
    data.mkdir()
    app, data_dir, db_path = make_app_context(str(data))
    settings = (
        tmp_path / "AppData" / "Roaming" / "Zed" / "settings.json"
        if os.name == "nt"
        else tmp_path / ".config" / "zed" / "settings.json"
    )
    guard = _binary(tmp_path / "defenseclaw-acp")
    agent_path = tmp_path / f"{agent_name}-cli"
    agent = _binary(agent_path)
    result = CliRunner().invoke(
        acp_cmd,
        ["setup", "--client", "zed", "--agent", agent_name, "--guard-binary", guard, "--agent-binary", agent],
        obj=app,
    )
    assert result.exit_code == 0, result.output
    lock_path = Path(data_dir) / "acp" / f"zed-{agent_name}.contract-lock.json"
    return app, data_dir, db_path, settings, guard, agent_path, lock_path


def _verify(app, agent: str = "kiro"):
    return CliRunner().invoke(acp_cmd, ["verify", "--client", "zed", "--agent", agent], obj=app)


def _edit_lock(lock_path: Path, change) -> None:
    lock = json.loads(lock_path.read_text())
    change(lock)
    atomic_write_private_bytes(lock_path, json.dumps(lock).encode())


def test_guard_entry_digest_matches_go():
    servers = json.loads(_PARITY_SETTINGS)["agent_servers"]
    assert _guard_entry_sha256(servers, "zed", "kiro") == _PARITY_DIGEST
    assert _guard_entry_sha256(servers, "zed", "opencode") == ""


@pytest.mark.parametrize(
    "change",
    [
        lambda lock: lock.__setitem__("version", 2),
        lambda lock: lock.__setitem__("version", True),
        lambda lock: lock["protocol"].__setitem__("schema_version", "schema-v1.20.0"),
        lambda lock: lock["protocol"].__setitem__("schema_sha256", "0" * 64),
    ],
    ids=["version-2", "version-true", "schema-version", "schema-sha256"],
)
def test_verify_refuses_a_lock_the_guard_refuses(tmp_path, monkeypatch, change):
    """GAP-0879: the guard starts only a version 1 lock for its protocol schema."""
    app, data_dir, db_path, *_rest, lock_path = _setup(tmp_path, monkeypatch)
    try:
        assert _verify(app).exit_code == 0
        _edit_lock(lock_path, change)
        result = _verify(app)
        assert result.exit_code != 0, result.output
        assert "version or protocol pins" in result.output, result.output
    finally:
        cleanup_app(app, db_path, data_dir)


def test_verify_refuses_a_symlinked_agent_with_the_same_bytes(tmp_path, monkeypatch):
    """GAP-0911: the guard lstats the pinned agent and refuses a link."""
    app, data_dir, db_path, _settings, _guard, agent_path, _lock = _setup(tmp_path, monkeypatch)
    try:
        target = tmp_path / "agent-target"
        agent_path.rename(target)
        try:
            agent_path.symlink_to(target)
        except OSError:
            if os.name == "nt":
                pytest.skip("this Windows account cannot create a file symlink")
            raise
        result = _verify(app)
        assert result.exit_code != 0, result.output
        assert "agent executable is a link" in result.output, result.output
    finally:
        cleanup_app(app, db_path, data_dir)


def test_verify_checks_an_entry_pin_as_the_guard_does(tmp_path, monkeypatch):
    """GAP-0912: an entry-sha256 pin is the guarded entry's digest, not the file's."""
    app, data_dir, db_path, settings, _guard, _agent, lock_path = _setup(tmp_path, monkeypatch)
    try:
        document = json.loads(settings.read_text())
        pin = _guard_entry_sha256(document["agent_servers"], "zed", "kiro")
        _edit_lock(lock_path, lambda lock: lock["client"].__setitem__("config_sha256", "entry-sha256:" + pin))
        result = _verify(app)
        assert result.exit_code == 0, result.output

        # The editor rewrites the file around the entry (a theme change): still healthy.
        document["theme"] = "One Dark"
        settings.write_text(json.dumps(document, indent=4))
        result = _verify(app)
        assert result.exit_code == 0, result.output

        # A changed launch (env added to the guarded entry) is refused by the guard.
        document["agent_servers"]["DefenseClaw · Kiro"]["env"] = {"LD_PRELOAD": "/tmp/x.so"}
        settings.write_text(json.dumps(document))
        result = _verify(app)
        assert result.exit_code != 0, result.output
    finally:
        cleanup_app(app, db_path, data_dir)


def test_setup_of_one_pair_does_not_repin_another_pairs_drifted_entry(tmp_path, monkeypatch):
    """GAP-0513 (met by the per-entry records): only an entry that still matches its record is re-pinned."""
    app, data_dir, db_path, settings, guard, _agent, kiro_lock = _setup(tmp_path, monkeypatch)
    try:
        document = json.loads(settings.read_text())
        document["agent_servers"]["DefenseClaw · Kiro"]["env"] = {"LD_PRELOAD": "/tmp/x.so"}
        settings.write_text(json.dumps(document))
        pinned_before = json.loads(kiro_lock.read_text())["client"]["config_sha256"]
        opencode = _binary(tmp_path / "opencode")
        other = CliRunner().invoke(
            acp_cmd,
            ["setup", "--client", "zed", "--agent", "opencode", "--guard-binary", guard, "--agent-binary", opencode],
            obj=app,
        )
        assert other.exit_code == 0, other.output
        assert json.loads(kiro_lock.read_text())["client"]["config_sha256"] == pinned_before
        assert pinned_before != hashlib.sha256(settings.read_bytes()).hexdigest()
        assert _verify(app).exit_code != 0
    finally:
        cleanup_app(app, db_path, data_dir)
