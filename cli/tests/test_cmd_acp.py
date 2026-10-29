# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import copy
import hashlib
import json
import os
import shlex
from pathlib import Path
from unittest.mock import patch

import defenseclaw.commands.cmd_acp as cmd_acp_module
from click.testing import CliRunner
from defenseclaw.acp_catalog import ACP_AGENT_ENTRY_POINTS
from defenseclaw.commands.cmd_acp import _write_token, acp_cmd
from defenseclaw.config import ACPBinding, ACPProfile

from tests.helpers import cleanup_app, make_app_context


def _repair_command(*args: str) -> str:
    """The `defenseclaw` command line setup_repair_command prints for *args*.

    On Windows every argument is a PowerShell single-quoted literal, so a
    pasted path with spaces or quotes stays one argument.
    """
    if os.name == "nt":
        return "defenseclaw " + " ".join("'" + value.replace("'", "''") + "'" for value in args)
    return shlex.join(["defenseclaw", *args])


def _binary(path: Path) -> str:
    # Distinct bytes per file: a byte-identical copy of a pinned agent is that agent (GAP-0496).
    path.write_bytes(b"test-binary:" + path.name.encode())
    path.chmod(0o700)
    return str(path.resolve())


def _app(tmp_path: Path):
    data = tmp_path / "data"
    data.mkdir()
    return make_app_context(str(data))


def _isolate_client_config(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / ".config"))
    monkeypatch.setenv("APPDATA", str(tmp_path / "AppData" / "Roaming"))


def _zed_settings(tmp_path: Path) -> Path:
    if os.name == "nt":
        return tmp_path / "AppData" / "Roaming" / "Zed" / "settings.json"
    return tmp_path / ".config" / "zed" / "settings.json"


def test_catalog_exposes_native_only_connector_coverage():
    result = CliRunner().invoke(acp_cmd, ["catalog"])
    assert result.exit_code == 0, result.output
    catalog = json.loads(result.output)
    assert catalog["protocol"]["release"] == "schema-v1.21.0"
    assert catalog["environment_variables"] == []
    canonical = json.loads((Path(__file__).parents[2] / "internal" / "inventory" / "acp_registry.json").read_text(encoding="utf-8"))
    assert catalog == canonical
    assert set(ACP_AGENT_ENTRY_POINTS) == {agent["id"] for agent in catalog["agents"]}
    assert any(agent["id"] == "devin" and agent["kind"] == "native" for agent in catalog["agents"])

    # The guard admits native vendor ACP modes only. A bridge, companion
    # server or gateway-backed shim would put a process DefenseClaw does not
    # control inside the security boundary, so none may reappear in the
    # catalog, and the connectors that used to reach ACP that way must report
    # no ACP claim rather than pointing at an agent that is gone.
    assert {agent["kind"] for agent in catalog["agents"]} == {"native"}
    assert {agent["id"] for agent in catalog["agents"]} == {
        "kiro",
        "cursor",
        "opencode",
        "hermes",
        "copilot",
        "devin",
    }
    agent_ids = {agent["id"] for agent in catalog["agents"]}
    for row in catalog["connector_coverage"]:
        if row["acp_support"] == "none":
            assert "agent_id" not in row, row
        else:
            assert row["agent_id"] in agent_ids, row
    retired = {"codex", "claudecode", "amp", "antigravity", "openclaw", }
    reporting_none = {row["connector_id"] for row in catalog["connector_coverage"] if row["acp_support"] == "none"}
    assert retired <= reporting_none


def test_token_secures_parent_directory_before_file_creation(tmp_path):
    with patch("defenseclaw.commands.cmd_acp.make_private_directory") as protect:
        token = _write_token(str(tmp_path))
    protect.assert_called_once_with(tmp_path / "acp")
    assert token.is_file()


def test_zed_setup_defaults_observe_and_preserves_foreign_entries(tmp_path, monkeypatch):
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    settings = _zed_settings(tmp_path)
    settings.parent.mkdir(parents=True)
    settings.write_text('// operator comment\n{"theme": "Ayu", "agent_servers": {"Foreign": {"command": "other"}},}\n')
    guard = _binary(tmp_path / "guard")
    agent = _binary(tmp_path / "kiro-cli")
    try:
        with patch("defenseclaw.commands.cmd_acp._agent_version", return_value="kiro-cli 2.21.3"):
            result = CliRunner().invoke(
                acp_cmd,
                [
                    "setup",
                    "--client",
                    "zed",
                    "--agent",
                    "kiro",
                    "--guard-binary",
                    guard,
                    "--agent-binary",
                    agent,
                    "--json-output",
                ],
                obj=app,
            )
        assert result.exit_code == 0, result.output
        rewritten = settings.read_text()
        assert rewritten.startswith("// operator comment\n")
        configured = json.loads(rewritten.split("\n", 1)[1])
        assert configured["theme"] == "Ayu"
        assert configured["agent_servers"]["Foreign"]["command"] == "other"
        managed = configured["agent_servers"]["DefenseClaw · Kiro"]
        assert managed["command"] == guard
        assert managed["args"][managed["args"].index("--mode") + 1] == "observe"
        lock = json.loads((Path(data_dir) / "acp" / "zed-kiro.contract-lock.json").read_text())
        assert lock["protocol"]["schema_version"] == "schema-v1.21.0"
        assert lock["agent"]["version"] == "kiro-cli 2.21.3"
        assert lock["guard"]["managed_custody"] is False
        assert app.cfg.acp.mode == "observe"
        saved = (Path(data_dir) / "config.yaml").read_text(encoding="utf-8")
        assert "default_profile: default" in saved
        if os.name != "nt":
            assert (Path(data_dir) / "acp" / ".token").stat().st_mode & 0o077 == 0
    finally:
        cleanup_app(app, db_path, data_dir)


def test_setup_activate_and_remove_are_surgical(tmp_path, monkeypatch):
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    guard = _binary(tmp_path / "guard")
    agent = _binary(tmp_path / "kiro-cli")
    try:
        with patch("defenseclaw.commands.cmd_acp._agent_version", return_value="v"):
            result = CliRunner().invoke(
                acp_cmd,
                [
                    "setup",
                    "--client",
                    "jetbrains",
                    "--agent",
                    "kiro",
                    "--activate",
                    "--guard-binary",
                    guard,
                    "--agent-binary",
                    agent,
                ],
                obj=app,
            )
        assert result.exit_code == 0, result.output
        path = tmp_path / ".jetbrains" / "acp.json"
        document = json.loads(path.read_text())
        document["agent_servers"]["Foreign"] = {"command": "other"}
        path.write_text(json.dumps(document))
        result = CliRunner().invoke(acp_cmd, ["remove", "--client", "jetbrains", "--agent", "kiro"], obj=app)
        assert result.exit_code == 0, result.output
        remaining = json.loads(path.read_text())["agent_servers"]
        assert "Foreign" in remaining
        assert "DefenseClaw · Kiro" not in remaining
    finally:
        cleanup_app(app, db_path, data_dir)


def test_remove_takes_out_the_profiles_setup_wrote(tmp_path, monkeypatch):
    # GAP-1589: setup --profile wrote acp.profiles.<name>; remove left it,
    # and the acp section, in config.yaml.
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    guard = _binary(tmp_path / "guard")
    agent = _binary(tmp_path / "kiro-cli")
    try:
        with patch("defenseclaw.commands.cmd_acp._agent_version", return_value="v"):
            result = CliRunner().invoke(
                acp_cmd,
                ["setup", "--client", "zed", "--agent", "kiro", "--profile", "nosuchprof",
                 "--guard-binary", guard, "--agent-binary", agent],
                obj=app,
            )
        assert result.exit_code == 0, result.output
        assert "new profile nosuchprof" in result.output
        assert "nosuchprof" in app.cfg.acp.profiles
        result = CliRunner().invoke(acp_cmd, ["remove", "--client", "zed", "--agent", "kiro"], obj=app)
        assert result.exit_code == 0, result.output
        assert app.cfg.acp.profiles == {}
        assert not app.cfg.acp.enabled
    finally:
        cleanup_app(app, db_path, data_dir)


def test_setup_rolls_back_client_token_and_lock_when_config_save_fails(tmp_path, monkeypatch):
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    guard = _binary(tmp_path / "guard")
    agent = _binary(tmp_path / "kiro-cli")
    settings = _zed_settings(tmp_path)
    settings.parent.mkdir(parents=True)
    original = b'{"theme":"original"}\n'
    settings.write_bytes(original)
    try:
        with (
            patch("defenseclaw.commands.cmd_acp._agent_version", return_value="v"),
            patch.object(app.cfg, "save", side_effect=OSError("forced save failure")),
        ):
            result = CliRunner().invoke(
                acp_cmd,
                ["setup", "--client", "zed", "--agent", "kiro", "--guard-binary", guard, "--agent-binary", agent],
                obj=app,
            )
        assert result.exit_code != 0
        assert settings.read_bytes() == original
        assert not (Path(data_dir) / "acp" / ".token").exists()
        assert not (Path(data_dir) / "acp" / "zed-kiro.contract-lock.json").exists()
        assert not app.cfg.acp.enabled
    finally:
        cleanup_app(app, db_path, data_dir)


def test_verify_detects_agent_digest_drift(tmp_path, monkeypatch):
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    guard = _binary(tmp_path / "guard")
    agent_path = tmp_path / "kiro-cli"
    agent = _binary(agent_path)
    try:
        result = CliRunner().invoke(
            acp_cmd,
            ["setup", "--client", "zed", "--agent", "kiro", "--guard-binary", guard, "--agent-binary", agent],
            obj=app,
        )
        assert result.exit_code == 0, result.output
        assert CliRunner().invoke(acp_cmd, ["verify", "--client", "zed", "--agent", "kiro"], obj=app).exit_code == 0

        agent_path.write_bytes(b"drifted-binary")
        result = CliRunner().invoke(acp_cmd, ["verify", "--client", "zed", "--agent", "kiro"], obj=app)
        assert result.exit_code != 0
        assert "agent executable digest has drifted" in result.output

        agent_path.write_bytes(b"test-binary")
        lock_path = Path(data_dir) / "acp" / "zed-kiro.contract-lock.json"
        lock = json.loads(lock_path.read_text())
        for invalid_agent in (None, [], "unproven", 42):
            lock_path.write_text(json.dumps(dict(lock, agent=invalid_agent)))
            before = lock_path.read_bytes()
            result = CliRunner().invoke(acp_cmd, ["verify", "--client", "zed", "--agent", "kiro"], obj=app)
            assert result.exit_code != 0
            assert "contract lock identity does not match" in result.output
            assert "run defenseclaw" in result.output
            assert "--profile" in result.output
            assert lock_path.read_bytes() == before
    finally:
        cleanup_app(app, db_path, data_dir)


def test_doctor_reports_acp_bindings_and_fails_on_drift(tmp_path, monkeypatch):
    """GAP-1534: doctor lists each binding and FAILs with the fix on drift."""
    from defenseclaw.commands.cmd_doctor import _check_acp_bindings, _DoctorResult

    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    guard = _binary(tmp_path / "guard")
    agent_path = tmp_path / "kiro-cli"
    agent = _binary(agent_path)
    try:
        empty = _DoctorResult()
        _check_acp_bindings(app.cfg, empty)
        assert empty.checks == []  # ACP is optional: no binding, no row

        result = CliRunner().invoke(
            acp_cmd,
            ["setup", "--client", "zed", "--agent", "kiro", "--guard-binary", guard, "--agent-binary", agent],
            obj=app,
        )
        assert result.exit_code == 0, result.output
        healthy = _DoctorResult()
        _check_acp_bindings(app.cfg, healthy)
        [row] = healthy.checks
        assert row["label"] == "ACP binding [zed/kiro]"
        assert row["status"] == "pass" and "healthy; profile default (observe)" in row["detail"]

        agent_path.write_bytes(b"drifted-binary")
        drifted = _DoctorResult()
        _check_acp_bindings(app.cfg, drifted)
        [row] = drifted.checks
        assert row["status"] == "fail"
        assert "agent executable digest has drifted" in row["detail"]
        assert row["remediation"].startswith(
            _repair_command("acp", "setup", "--client", "zed", "--agent", "kiro", "--profile", "default")
        )
        assert "--activate" not in row["remediation"]
    finally:
        cleanup_app(app, db_path, data_dir)


def test_verify_detects_client_configuration_drift(tmp_path, monkeypatch):
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    guard = _binary(tmp_path / "guard")
    agent = _binary(tmp_path / "kiro-cli")
    try:
        result = CliRunner().invoke(
            acp_cmd,
            ["setup", "--client", "zed", "--agent", "kiro", "--guard-binary", guard, "--agent-binary", agent],
            obj=app,
        )
        assert result.exit_code == 0, result.output
        settings = _zed_settings(tmp_path)
        # A lock from 1.0.4 or earlier pins the whole editor file (setup now
        # pins the guarded entry, GAP-0504): any edit of that file is drift.
        lock_path = Path(data_dir) / "acp" / "zed-kiro.contract-lock.json"
        lock = json.loads(lock_path.read_text())
        lock["client"]["config_sha256"] = hashlib.sha256(settings.read_bytes()).hexdigest()
        cmd_acp_module.atomic_write_private_bytes(lock_path, json.dumps(lock).encode())
        result = CliRunner().invoke(acp_cmd, ["verify", "--client", "zed", "--agent", "kiro"], obj=app)
        assert result.exit_code == 0, result.output
        document = json.loads(settings.read_text())
        document["theme"] = "drifted"
        settings.write_text(json.dumps(document))

        result = CliRunner().invoke(acp_cmd, ["verify", "--client", "zed", "--agent", "kiro"], obj=app)
        assert result.exit_code != 0
        assert "client configuration digest has drifted" in result.output
    finally:
        cleanup_app(app, db_path, data_dir)


def test_same_agent_in_two_clients_uses_distinct_contract_locks(tmp_path, monkeypatch):
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    guard = _binary(tmp_path / "guard")
    agent = _binary(tmp_path / "kiro-cli")
    try:
        runner = CliRunner()
        for client in ("zed", "jetbrains"):
            result = runner.invoke(
                acp_cmd,
                [
                    "setup",
                    "--client",
                    client,
                    "--agent",
                    "kiro",
                    "--guard-binary",
                    guard,
                    "--agent-binary",
                    agent,
                ],
                obj=app,
            )
            assert result.exit_code == 0, result.output
        zed_lock = Path(data_dir) / "acp" / "zed-kiro.contract-lock.json"
        jetbrains_lock = Path(data_dir) / "acp" / "jetbrains-kiro.contract-lock.json"
        assert zed_lock.is_file() and jetbrains_lock.is_file()
        assert zed_lock.read_bytes() != jetbrains_lock.read_bytes()

        result = runner.invoke(acp_cmd, ["remove", "--client", "zed", "--agent", "kiro"], obj=app)
        assert result.exit_code == 0, result.output
        assert not zed_lock.exists()
        assert jetbrains_lock.exists()
        assert "kiro" in app.cfg.acp.agents
        assert "jetbrains" in app.cfg.acp.clients
    finally:
        cleanup_app(app, db_path, data_dir)


def test_multiple_agents_in_one_client_keep_every_contract_current(tmp_path, monkeypatch):
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    guard = _binary(tmp_path / "guard")
    kiro = _binary(tmp_path / "kiro-cli")
    cursor = _binary(tmp_path / "cursor-agent")
    try:
        runner = CliRunner()
        for agent, executable in (("kiro", kiro), ("cursor", cursor)):
            result = runner.invoke(
                acp_cmd,
                [
                    "setup",
                    "--client",
                    "zed",
                    "--agent",
                    agent,
                    "--guard-binary",
                    guard,
                    "--agent-binary",
                    executable,
                ],
                obj=app,
            )
            assert result.exit_code == 0, result.output

        for agent in ("kiro", "cursor"):
            result = runner.invoke(acp_cmd, ["verify", "--client", "zed", "--agent", agent], obj=app)
            assert result.exit_code == 0, result.output

        result = runner.invoke(acp_cmd, ["remove", "--client", "zed", "--agent", "cursor"], obj=app)
        assert result.exit_code == 0, result.output
        result = runner.invoke(acp_cmd, ["verify", "--client", "zed", "--agent", "kiro"], obj=app)
        assert result.exit_code == 0, result.output
    finally:
        cleanup_app(app, db_path, data_dir)


def test_managed_setup_uses_provisioned_binding_token_without_mutating_central_policy(tmp_path, monkeypatch):
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    runtime_data = tmp_path / "user-runtime"
    token = runtime_data / "acp" / "zed-kiro.token"
    token.parent.mkdir(parents=True, mode=0o700)
    token.write_text("0" * 64 + "\n")
    token.chmod(0o600)
    guard = _binary(tmp_path / "guard")
    agent = _binary(tmp_path / "kiro-cli")
    app.cfg.deployment_mode = "managed_enterprise"
    app.cfg.acp.enabled = True
    app.cfg.acp.mode = "action"
    app.cfg.acp.default_profile = "locked"
    app.cfg.acp.clients = {"zed": ACPBinding(enabled=True, profile="locked")}
    app.cfg.acp.agents = {"kiro": ACPBinding(enabled=True, profile="locked")}
    app.cfg.acp.profiles = {"locked": ACPProfile(fail_mode="closed", allowed_clients=["zed"], allowed_agents=["kiro"])}
    before = json.dumps(app.cfg.acp, default=lambda value: value.__dict__, sort_keys=True)
    try:
        with patch.object(app.cfg, "save", side_effect=AssertionError("managed enrollment must not save policy")):
            result = CliRunner().invoke(
                acp_cmd,
                [
                    "setup",
                    "--client",
                    "zed",
                    "--agent",
                    "kiro",
                    "--profile",
                    "locked",
                    "--activate",
                    "--managed",
                    "--runtime-data-dir",
                    str(runtime_data),
                    "--token-file",
                    str(token),
                    "--guard-binary",
                    guard,
                    "--agent-binary",
                    agent,
                    "--json-output",
                ],
                obj=app,
            )
        assert result.exit_code == 0, result.output
        assert json.loads(result.output)["managed"] is True
        assert json.dumps(app.cfg.acp, default=lambda value: value.__dict__, sort_keys=True) == before
        settings = json.loads(_zed_settings(tmp_path).read_text())
        args = settings["agent_servers"]["DefenseClaw · Kiro"]["args"]
        assert args[args.index("--token-file") + 1] == str(token.resolve())
        lock = runtime_data / "acp" / "zed-kiro.contract-lock.json"
        assert lock.is_file()
        assert json.loads(lock.read_text(encoding="utf-8"))["guard"]["managed_custody"] is True
    finally:
        cleanup_app(app, db_path, data_dir)


def test_managed_setup_rejects_pair_outside_central_policy(tmp_path, monkeypatch):
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    app.cfg.deployment_mode = "managed_enterprise"
    guard = _binary(tmp_path / "guard")
    agent = _binary(tmp_path / "kiro-cli")
    try:
        result = CliRunner().invoke(
            acp_cmd,
            [
                "setup",
                "--client",
                "zed",
                "--agent",
                "kiro",
                "--managed",
                "--guard-binary",
                guard,
                "--agent-binary",
                agent,
            ],
            obj=app,
        )
        assert result.exit_code != 0
        assert "central enterprise ACP policy does not authorize" in result.output
    finally:
        cleanup_app(app, db_path, data_dir)


def test_remove_rolls_back_editor_lock_and_policy_on_save_failure(tmp_path, monkeypatch):
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    guard = _binary(tmp_path / "guard")
    agent = _binary(tmp_path / "kiro-cli")
    try:
        runner = CliRunner()
        result = runner.invoke(
            acp_cmd,
            ["setup", "--client", "zed", "--agent", "kiro", "--guard-binary", guard, "--agent-binary", agent],
            obj=app,
        )
        assert result.exit_code == 0, result.output
        settings = _zed_settings(tmp_path)
        lock = Path(data_dir) / "acp" / "zed-kiro.contract-lock.json"
        settings_before = settings.read_bytes()
        lock_before = lock.read_bytes()

        with patch.object(app.cfg, "save", side_effect=OSError("forced save failure")):
            result = runner.invoke(acp_cmd, ["remove", "--client", "zed", "--agent", "kiro"], obj=app)
        assert result.exit_code != 0
        assert settings.read_bytes() == settings_before
        assert lock.read_bytes() == lock_before
        assert app.cfg.acp.enabled
        assert "kiro" in app.cfg.acp.agents
    finally:
        cleanup_app(app, db_path, data_dir)


def test_remove_reports_one_rollback_failure_and_continues_restoring(tmp_path, monkeypatch):
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    guard = _binary(tmp_path / "guard")
    agent = _binary(tmp_path / "kiro-cli")
    try:
        runner = CliRunner()
        result = runner.invoke(
            acp_cmd,
            ["setup", "--client", "zed", "--agent", "kiro", "--guard-binary", guard, "--agent-binary", agent],
            obj=app,
        )
        assert result.exit_code == 0, result.output
        lock = Path(data_dir) / "acp" / "zed-kiro.contract-lock.json"
        lock_before = lock.read_bytes()
        original_restore = cmd_acp_module._restore
        restore_calls = 0

        def partially_failing_restore(path, snapshot):
            nonlocal restore_calls
            restore_calls += 1
            if restore_calls == 1:
                raise OSError("forced restore failure")
            original_restore(path, snapshot)

        with (
            patch.object(app.cfg, "save", side_effect=OSError("forced save failure")),
            patch("defenseclaw.commands.cmd_acp._restore", side_effect=partially_failing_restore),
        ):
            result = runner.invoke(acp_cmd, ["remove", "--client", "zed", "--agent", "kiro"], obj=app)
        assert result.exit_code != 0
        assert restore_calls >= 2
        assert "rollback problems:" in result.output
        assert lock.read_bytes() == lock_before
    finally:
        cleanup_app(app, db_path, data_dir)


def test_detect_classifies_guarded_direct_and_client_registry_entries(tmp_path, monkeypatch):
    _isolate_client_config(monkeypatch, tmp_path)
    settings = _zed_settings(tmp_path)
    settings.parent.mkdir(parents=True)
    settings.write_text(
        json.dumps(
            {
                "agent_servers": {
                    # Already guarded.
                    "DefenseClaw · Kiro": {"command": "/opt/bin/defenseclaw-acp", "args": []},
                    # A direct launch of a native agent: wrappable.
                    "My Cursor": {"command": "/usr/local/bin/agent", "args": ["acp", "--verbose"]},
                    # Resolved by the client's own registry: unguarded, but no
                    # argv exists for the guard to wrap.
                    "cursor": {"type": "registry"},
                    # Not an ACP agent DefenseClaw knows.
                    "Something Else": {"command": "unrelated-binary", "args": []},
                }
            }
        )
    )
    result = CliRunner().invoke(acp_cmd, ["detect", "--json-output"])
    assert result.exit_code == 0, result.output
    zed = next(item for item in json.loads(result.output)["clients"] if item["client"] == "zed")

    assert [item["entry"] for item in zed["guarded"]] == ["DefenseClaw · Kiro"]
    assert [(item["entry"], item["agent"]) for item in zed["adoptable"]] == [("My Cursor", "cursor")]
    assert [item["entry"] for item in zed["client_registry"]] == ["cursor"]
    assert [item["entry"] for item in zed["foreign"]] == ["Something Else"]
    # kiro is already guarded and cursor is accounted for, so neither is
    # offered as "installed but not configured here".
    assert "kiro" not in zed["installable"]
    assert "cursor" not in zed["installable"]


def test_adopt_points_the_operators_own_entry_at_the_guard(tmp_path, monkeypatch):
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    settings = _zed_settings(tmp_path)
    settings.parent.mkdir(parents=True)
    guard = _binary(tmp_path / "defenseclaw-acp")
    agent = _binary(tmp_path / "kiro-cli")
    settings.write_text(
        json.dumps(
            {
                "agent_servers": {
                    "Kiro": {"command": agent, "args": ["acp"], "env": {"KEEP": "me"}},
                    "Foreign": {"command": "other", "args": []},
                }
            }
        )
    )
    try:
        with patch("defenseclaw.commands.cmd_acp._agent_version", return_value="kiro-cli 2.22.0"):
            result = CliRunner().invoke(
                acp_cmd,
                ["adopt", "--client", "zed", "--guard-binary", guard, "--yes", "--json-output"],
                obj=app,
            )
        assert result.exit_code == 0, result.output
        adopted = json.loads(result.output)["adopted"]
        assert adopted == [{"agent": "kiro", "client": "zed", "entry": "Kiro"}]

        servers = json.loads(settings.read_text())["agent_servers"]
        # The operator's own entry now launches the guard, keeps its key and
        # its env, and carries the same argv the managed entry got.
        assert servers["Kiro"]["command"] == guard
        assert servers["Kiro"]["env"] == {"KEEP": "me"}
        assert "DefenseClaw · Kiro" not in servers
        # The wrapped agent is the one that was already configured (compare
        # basenames: macOS resolves the temp path through /private).
        assert any(str(value).endswith("kiro-cli") for value in servers["Kiro"]["args"])
        # No unguarded path to the agent is left behind, and foreign entries
        # are untouched.
        assert servers["Foreign"] == {"command": "other", "args": []}
        assert app.cfg.acp.mode == "observe"

        changed = CliRunner().invoke(
            acp_cmd,
            ["setup", "--client", "zed", "--agent", "kiro", "--guard-binary", guard,
             "--agent-binary", agent, "--profile", "locked", "--activate", "--json-output"],
            obj=app,
        )
        assert changed.exit_code == 0, changed.output
        servers = json.loads(settings.read_text())["agent_servers"]
        assert set(servers) == {"Kiro", "Foreign"}
        assert "locked" in servers["Kiro"]["args"]
        assert "action" in servers["Kiro"]["args"]
        verified = CliRunner().invoke(acp_cmd, ["verify", "--client", "zed", "--agent", "kiro"], obj=app)
        assert verified.exit_code == 0, verified.output
        equivalent_data_dir = str(Path(data_dir) / ".." / Path(data_dir).name)
        assert not cmd_acp_module._verify_binding(equivalent_data_dir, "zed", "kiro", app.cfg.acp)
        # A copied guarded entry with stale metadata, under the reserved name
        # or any other, is not one DefenseClaw recorded writing: it is
        # foreign, so verify fails and names it with the manual step, and
        # removal would leave it with a warning.
        stale = dict(servers["Kiro"], args=list(servers["Kiro"]["args"]))
        stale["args"][stale["args"].index("--profile") + 1] = "default"
        for name in ("DefenseClaw · Kiro", "Stale"):
            settings.write_text(json.dumps({"agent_servers": {**servers, name: stale}}))
            cmd_acp_module._refresh_client_contract_digests(str(data_dir), "zed", settings)
            verified = CliRunner().invoke(acp_cmd, ["verify", "--client", "zed", "--agent", "kiro"], obj=app)
            assert verified.exit_code != 0, verified.output
            assert f"editor entry {name!r} is not DefenseClaw's" in verified.output, verified.output
            assert "delete it in" in verified.output, verified.output
            assert [name for name, *_ in cmd_acp_module._left_entries("zed", "kiro", str(data_dir))] == [name]
        settings.write_text(json.dumps({"agent_servers": servers}))
        cmd_acp_module._refresh_client_contract_digests(str(data_dir), "zed", settings)

        # Re-running finds nothing to adopt rather than double-wrapping.
        again = CliRunner().invoke(acp_cmd, ["adopt", "--client", "zed", "--yes", "--json-output"], obj=app)
        assert again.exit_code == 0, again.output
        assert json.loads(again.output)["adopted"] == []
        removed = CliRunner().invoke(acp_cmd, ["remove", "--client", "zed", "--agent", "kiro"], obj=app)
        assert removed.exit_code == 0, removed.output
        assert json.loads(settings.read_text())["agent_servers"] == {"Foreign": {"command": "other", "args": []}}
        # Someone else's entry under the reserved name blocks neither removal
        # nor setup: setup writes the pair's own entry next to it, and removal
        # leaves it.
        collision = {"agent_servers": {"DefenseClaw · Kiro": {"command": "other", "args": []}}}
        settings.write_text(json.dumps(collision))
        before = settings.read_bytes()
        removed = CliRunner().invoke(acp_cmd, ["remove", "--client", "zed", "--agent", "kiro"], obj=app)
        assert removed.exit_code == 0 and settings.read_bytes() == before, removed.output
        setup = CliRunner().invoke(
            acp_cmd,
            ["setup", "--client", "zed", "--agent", "kiro", "--guard-binary", guard, "--agent-binary", agent],
            obj=app,
        )
        assert setup.exit_code == 0, setup.output
        servers = json.loads(settings.read_text())["agent_servers"]
        assert servers["DefenseClaw · Kiro"] == collision["agent_servers"]["DefenseClaw · Kiro"]
        assert servers["DefenseClaw · Kiro (2)"]["command"] == guard
        removed = CliRunner().invoke(acp_cmd, ["remove", "--client", "zed", "--agent", "kiro"], obj=app)
        assert removed.exit_code == 0, removed.output
        assert json.loads(settings.read_text()) == collision
    finally:
        cleanup_app(app, db_path, data_dir)


def test_second_pair_in_another_mode_does_not_repoint_global_fallbacks(tmp_path, monkeypatch):
    """Per-pair setup must not promote or demote pairs it was not asked about.

    `acp.mode` and `acp.default_profile` are global fallbacks. Writing them on
    every setup meant configuring a second pair in observe mode flipped the
    default out from under any pair that inherits it, and left `acp.mode`
    describing whichever pair happened to be configured last.
    """

    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    settings = _zed_settings(tmp_path)
    settings.parent.mkdir(parents=True)
    guard = _binary(tmp_path / "guard")
    kiro = _binary(tmp_path / "kiro-cli")
    agent_binary = _binary(tmp_path / "agent")
    try:
        with patch("defenseclaw.commands.cmd_acp._agent_version", return_value="probe"):
            first = CliRunner().invoke(
                acp_cmd,
                ["setup", "--client", "zed", "--agent", "kiro", "--guard-binary", guard,
                 "--agent-binary", kiro, "--profile", "locked", "--activate", "--json-output"],
                obj=app,
            )
            assert first.exit_code == 0, first.output
            assert app.cfg.acp.mode == "action"
            assert app.cfg.acp.default_profile == "locked"

            second = CliRunner().invoke(
                acp_cmd,
                ["setup", "--client", "zed", "--agent", "cursor", "--guard-binary", guard,
                 "--agent-binary", agent_binary, "--profile", "watch", "--json-output"],
                obj=app,
            )
            assert second.exit_code == 0, second.output

        # The observe pair did not drag the global fallbacks with it.
        assert app.cfg.acp.mode == "action"
        assert app.cfg.acp.default_profile == "locked"
        # Each pair carries its own profile, and each profile its own mode.
        assert app.cfg.acp.bindings["zed/kiro"].profile == "locked"
        assert app.cfg.acp.bindings["zed/cursor"].profile == "watch"
        assert app.cfg.acp.profiles["locked"].mode == "action"
        assert app.cfg.acp.profiles["watch"].mode == "observe"
        assert app.cfg.acp.profile_for_pair("zed", "kiro") == "locked"
        assert app.cfg.acp.profile_for_pair("zed", "cursor") == "watch"
        # The shared pins stay profile-free so neither pair pulls the other.
        assert app.cfg.acp.clients["zed"].profile == ""
        assert app.cfg.acp.clients["zed"].enabled is True
    finally:
        cleanup_app(app, db_path, data_dir)


def test_activating_a_profile_another_pair_resolves_through_a_pin_is_refused(tmp_path, monkeypatch):
    """The mode-conflict check must see pairs that inherit, not only bindings.

    A pair configured before per-pair bindings existed resolves its profile
    through the client/agent pin. Looking only at `bindings` would let a later
    `--activate` flip that shared profile's mode and silently promote it.
    """

    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    settings = _zed_settings(tmp_path)
    settings.parent.mkdir(parents=True)
    guard = _binary(tmp_path / "guard")
    kiro = _binary(tmp_path / "kiro-cli")
    agent_binary = _binary(tmp_path / "agent")
    try:
        with patch("defenseclaw.commands.cmd_acp._agent_version", return_value="probe"):
            first = CliRunner().invoke(
                acp_cmd,
                ["setup", "--client", "zed", "--agent", "kiro", "--guard-binary", guard,
                 "--agent-binary", kiro, "--profile", "shared", "--json-output"],
                obj=app,
            )
            assert first.exit_code == 0, first.output
            # Simulate a pre-per-pair config: the pair resolves through pins.
            app.cfg.acp.bindings.pop("zed/kiro")
            app.cfg.acp.clients["zed"].profile = "shared"
            app.cfg.acp.agents["kiro"].profile = "shared"
            assert app.cfg.acp.profile_for_pair("zed", "kiro") == "shared"

            clash = CliRunner().invoke(
                acp_cmd,
                ["setup", "--client", "zed", "--agent", "cursor", "--guard-binary", guard,
                 "--agent-binary", agent_binary, "--profile", "shared", "--activate", "--json-output"],
                obj=app,
            )
        assert clash.exit_code != 0
        assert "zed/kiro" in clash.output
        assert "--profile" in clash.output
        # kiro was not promoted behind the operator's back.
        assert app.cfg.acp.profiles["shared"].mode == "observe"
    finally:
        cleanup_app(app, db_path, data_dir)


def test_verify_reports_profile_drift_after_a_hand_edit(tmp_path, monkeypatch):
    """Editing a pair's profile by hand must not read as healthy.

    The guard carries its profile in argv, pinned into the contract lock at
    setup, and the gateway refuses a request whose profile the configuration
    no longer assigns to that pair. Without this check `verify` and `status`
    kept reporting the binding healthy and the operator learned about it from
    a dead editor session instead.
    """

    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    settings = _zed_settings(tmp_path)
    settings.parent.mkdir(parents=True)
    settings.write_text("{}")
    guard = _binary(tmp_path / "guard")
    kiro = _binary(tmp_path / "kiro-cli")
    try:
        with patch("defenseclaw.commands.cmd_acp._agent_version", return_value="probe"):
            created = CliRunner().invoke(
                acp_cmd,
                ["setup", "--client", "zed", "--agent", "kiro", "--guard-binary", guard,
                 "--agent-binary", kiro, "--profile", "locked", "--json-output"],
                obj=app,
            )
        assert created.exit_code == 0, created.output
        healthy = CliRunner().invoke(acp_cmd, ["verify", "--client", "zed", "--agent", "kiro"], obj=app)
        assert healthy.exit_code == 0, healthy.output

        # Move the pair to a different profile without re-running setup.
        app.cfg.acp.profiles["watch"] = app.cfg.acp.profiles["locked"]
        app.cfg.acp.bindings["zed/kiro"] = ACPBinding(enabled=True, profile="watch")
        drifted = CliRunner().invoke(acp_cmd, ["verify", "--client", "zed", "--agent", "kiro"], obj=app)
        assert drifted.exit_code != 0
        assert "no longer matches the configured" in drifted.output
        assert "re-run acp setup" in drifted.output

        # status surfaces it too, so the operator does not need to guess which
        # binding to verify.
        listed = CliRunner().invoke(acp_cmd, ["status", "--json"], obj=app)
        assert listed.exit_code == 0, listed.output
        binding = json.loads(listed.output)["bindings"]["zed/kiro"]
        assert binding["healthy"] is False
        assert binding["profile"] == "watch"
        assert binding["profile_source"] == "binding"

        # GAP-1501: without --json the posture is a readable summary.
        human = CliRunner().invoke(acp_cmd, ["status"], obj=app)
        assert human.exit_code == 0, human.output
        # GAP-1732: the header holds only guard-wide facts; mode and
        # profile live on each binding row.
        assert human.output.startswith("ACP guard: on (1 binding)\n")
        assert "default profile" not in human.output
        assert "zed/kiro" in human.output and "NEEDS ATTENTION" in human.output
        assert "acp status --json" in human.output
    finally:
        cleanup_app(app, db_path, data_dir)


def test_remove_without_entry_is_a_noop_and_last_remove_restores_no_file(tmp_path, monkeypatch):
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    guard = _binary(tmp_path / "guard")
    agent = _binary(tmp_path / "kiro-cli")
    settings = _zed_settings(tmp_path)
    try:
        runner = CliRunner()
        result = runner.invoke(acp_cmd, ["remove", "--client", "zed", "--agent", "kiro"], obj=app)
        assert result.exit_code == 0, result.output
        assert "Nothing to remove" in result.output
        assert not settings.exists()

        result = runner.invoke(
            acp_cmd,
            ["setup", "--client", "zed", "--agent", "kiro", "--guard-binary", guard, "--agent-binary", agent],
            obj=app,
        )
        assert result.exit_code == 0, result.output
        result = runner.invoke(acp_cmd, ["remove", "--client", "zed", "--agent", "kiro"], obj=app)
        assert result.exit_code == 0, result.output
        assert "Removed the DefenseClaw kiro entry" in result.output
        assert not settings.exists()
    finally:
        cleanup_app(app, db_path, data_dir)


def test_verify_without_options_checks_every_binding(tmp_path, monkeypatch):
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    guard = _binary(tmp_path / "guard")
    kiro = _binary(tmp_path / "kiro-cli")
    try:
        runner = CliRunner()
        result = runner.invoke(acp_cmd, ["verify"], obj=app)
        assert result.exit_code != 0
        assert "No DefenseClaw ACP bindings are configured" in result.output
        for client in ("zed", "jetbrains"):
            result = runner.invoke(
                acp_cmd,
                ["setup", "--client", client, "--agent", "kiro", "--guard-binary", guard, "--agent-binary", kiro],
                obj=app,
            )
            assert result.exit_code == 0, result.output
        result = runner.invoke(acp_cmd, ["verify"], obj=app)
        assert result.exit_code == 0, result.output
        assert "Verified jetbrains/kiro" in result.output and "Verified zed/kiro" in result.output
    finally:
        cleanup_app(app, db_path, data_dir)


def test_refresh_repins_only_the_upgraded_defenseclaw_guard(tmp_path, monkeypatch):
    # GAP-1294: an upgrade replaces defenseclaw-acp, and every editor entry
    # then failed closed on the stale guard digest until acp setup was rerun.
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    guard_path = tmp_path / "bin" / "defenseclaw-acp"
    guard_path.parent.mkdir()
    guard = _binary(guard_path)
    agent_path = tmp_path / "kiro-cli"
    agent = _binary(agent_path)
    try:
        setup = ["setup", "--client", "zed", "--agent", "kiro", "--guard-binary", guard, "--agent-binary", agent]
        assert CliRunner().invoke(acp_cmd, setup, obj=app).exit_code == 0
        verify = ["verify", "--client", "zed", "--agent", "kiro"]

        old_sha = hashlib.sha256(guard_path.read_bytes()).hexdigest()
        guard_path.write_bytes(b"upgraded-guard")
        result = CliRunner().invoke(acp_cmd, verify, obj=app)
        assert result.exit_code != 0 and "defenseclaw acp refresh" in result.output

        # The installer names the guard it replaced; a lock pinned to another
        # guard is left alone.
        result = CliRunner().invoke(acp_cmd, ["refresh", "--from-sha256", "0" * 64], obj=app)
        assert result.exit_code == 0 and result.output == ""
        result = CliRunner().invoke(acp_cmd, ["refresh", "--from-sha256", old_sha], obj=app)
        assert result.exit_code == 0 and "Re-pinned the DefenseClaw ACP guard for zed/kiro" in result.output
        assert CliRunner().invoke(acp_cmd, verify, obj=app).exit_code == 0
        assert CliRunner().invoke(acp_cmd, ["refresh"], obj=app).output == ""  # nothing left to do

        # A changed agent binary is not re-pinned.
        agent_path.write_bytes(b"other-agent")
        CliRunner().invoke(acp_cmd, ["refresh"], obj=app)
        result = CliRunner().invoke(acp_cmd, verify, obj=app)
        assert result.exit_code != 0 and "agent executable digest has drifted" in result.output
    finally:
        cleanup_app(app, db_path, data_dir)


def test_source_install_and_doctor_fix_repin_only_defenseclaws_guard(tmp_path, monkeypatch):
    # make all re-pins the entries that start the guard it just published;
    # doctor --fix plans the same refresh, applies it once, and never
    # re-pins a changed agent binary.
    from defenseclaw.commands.cmd_doctor import _fix_acp_guard_pins

    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    guard_path = tmp_path / "bin" / "defenseclaw-acp"
    guard_path.parent.mkdir()
    guard = _binary(guard_path)
    agent_path = tmp_path / "kiro-cli"
    agent = _binary(agent_path)
    try:
        setup = ["setup", "--client", "zed", "--agent", "kiro", "--guard-binary", guard, "--agent-binary", agent]
        assert CliRunner().invoke(acp_cmd, setup, obj=app).exit_code == 0
        guard_path.write_bytes(b"source-build-guard")
        other = tmp_path / "other" / "defenseclaw-acp"
        other.parent.mkdir()
        _binary(other)
        assert CliRunner().invoke(acp_cmd, ["refresh", "--guard-path", str(other)], obj=app).output == ""
        result = CliRunner().invoke(acp_cmd, ["refresh", "--guard-path", guard], obj=app)
        assert "Re-pinned the DefenseClaw ACP guard for zed/kiro" in result.output

        guard_path.write_bytes(b"upgraded-guard")
        agent_path.write_bytes(b"updated-agent")
        tag, plan = _fix_acp_guard_pins(app.cfg, assume_yes=True, plan_only=True)
        repair = _repair_command("acp", "setup", "--client", "zed", "--agent", "kiro")
        assert tag == "plan" and "zed/kiro" in plan and repair in plan
        assert _fix_acp_guard_pins(app.cfg, assume_yes=True)[0] == "pass"
        tag, detail = _fix_acp_guard_pins(app.cfg, assume_yes=True, plan_only=True)
        assert tag == "skip" and "pins are current" in detail
        result = CliRunner().invoke(acp_cmd, ["verify", "--client", "zed", "--agent", "kiro"], obj=app)
        assert "agent executable digest has drifted" in result.output
        assert "guard executable digest has drifted" not in result.output
    finally:
        cleanup_app(app, db_path, data_dir)


def test_setup_and_remove_print_each_slow_step_and_keep_json_clean(tmp_path, monkeypatch):
    """GAP-1835: setup and remove ran for minutes on Windows with no output at all."""
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    guard = _binary(tmp_path / "guard")
    agent = _binary(tmp_path / "kiro-cli")
    setup = ["setup", "--client", "zed", "--agent", "kiro", "--guard-binary", guard, "--agent-binary", agent]
    try:
        result = CliRunner().invoke(acp_cmd, setup, obj=app)
        assert result.exit_code == 0, result.output
        for step in ("checking the guard and agent executables", "Pinning the guard and agent executable digests",
                     "Saving the ACP policy", "Recording the change with the gateway"):
            assert step in result.stderr
        assert result.stdout.startswith("Configured kiro through DefenseClaw in zed")

        result = CliRunner().invoke(acp_cmd, [*setup, "--json-output"], obj=app)
        assert result.exit_code == 0, result.output
        assert json.loads(result.stdout)["agent"] == "kiro" and "Pinning" not in result.stderr

        result = CliRunner().invoke(acp_cmd, ["remove", "--client", "zed", "--agent", "kiro"], obj=app)
        assert result.exit_code == 0, result.output
        assert "Removing the DefenseClaw kiro entry" in result.stderr
        assert "Recording the change with the gateway" in result.stderr
    finally:
        cleanup_app(app, db_path, data_dir)


def test_setup_returns_once_the_gateway_has_loaded_the_guard(tmp_path, monkeypatch):
    """GAP-2135: an editor started right after setup was refused with HTTP 503."""
    from defenseclaw.gateway import OrchestratorClient

    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    guard = _binary(tmp_path / "guard")
    agent = _binary(tmp_path / "kiro-cli")
    answers = [
        {"enabled": False, "profiles": {}},
        {"enabled": True, "profiles": {"r4x": {"mode": "observe"}}},
        {"enabled": True, "profiles": {"r4x": {"mode": "action"}}},
    ]
    calls: list[int] = []

    def acp_profiles(_self):
        calls.append(1)
        return answers[min(len(calls), len(answers)) - 1]

    monkeypatch.setattr(OrchestratorClient, "acp_profiles", acp_profiles)
    monkeypatch.setattr(cmd_acp_module.time, "sleep", lambda _seconds: None)
    setup = ["setup", "--client", "zed", "--agent", "kiro", "--activate", "--profile", "r4x",
             "--guard-binary", guard, "--agent-binary", agent]
    try:
        result = CliRunner().invoke(acp_cmd, setup, obj=app)
        assert result.exit_code == 0, result.output
        assert len(calls) == 3
        assert "Waiting for the gateway to load the ACP policy" in result.stderr
        assert "has not loaded it yet" not in result.stderr

        # A gateway that never loads it: setup still succeeds, and says so.
        calls.clear()
        answers[:] = [{"enabled": False, "profiles": {}}]
        monkeypatch.setattr(cmd_acp_module, "_GATEWAY_ACP_APPLY_SECONDS", 0.0)
        result = CliRunner().invoke(acp_cmd, setup, obj=app)
        assert result.exit_code == 0, result.output
        assert "the gateway has not loaded it yet" in result.stderr
        assert result.stdout.startswith("Configured kiro through DefenseClaw in zed (action)")
    finally:
        cleanup_app(app, db_path, data_dir)


def _repair_args(output: str) -> list[str]:
    """The `acp setup` argv a failed verify told the operator to run."""
    import re
    import shlex

    command = output.split("; run ", 1)[1].strip().splitlines()[0]
    if os.name == "nt":
        words = [value.replace("''", "'") for value in re.findall(r"'((?:[^']|'')*)'", command)]
    else:
        words = shlex.split(command)[1:]
    assert words[:2] == ["acp", "setup"], command
    return words[1:]


def test_verify_repair_command_keeps_action_mode(tmp_path, monkeypatch):
    """Following verify's repair hint must not demote an action binding to observe/open."""
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    # With an unreadable lock the hint names no executables, so setup finds
    # the guard and the agent on PATH, as it does for the operator.
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    suffix = ".exe" if os.name == "nt" else ""
    guard = _binary(bin_dir / f"defenseclaw-acp{suffix}")
    agent = _binary(bin_dir / f"kiro-cli{suffix}")
    monkeypatch.setenv("PATH", str(bin_dir) + os.pathsep + os.environ.get("PATH", ""))
    lock_path = Path(data_dir) / "acp" / "zed-kiro.contract-lock.json"
    try:
        result = CliRunner().invoke(
            acp_cmd,
            ["setup", "--client", "zed", "--agent", "kiro", "--profile", "locked", "--activate",
             "--guard-binary", guard, "--agent-binary", agent],
            obj=app,
        )
        assert result.exit_code == 0, result.output
        intact = lock_path.read_text()
        for broken in ("{", json.dumps({"version": 1}), None):
            if broken is None:
                # A readable lock: the hint also names the pinned executables.
                lock_path.write_text(intact)
                agent_path = Path(agent)
                agent_path.write_bytes(b"updated-binary")
            else:
                lock_path.write_text(broken)
            verified = CliRunner().invoke(acp_cmd, ["verify"], obj=app)
            assert verified.exit_code != 0, verified.output
            args = _repair_args(verified.output)
            assert "--activate" in args and args[args.index("--profile") + 1] == "locked"
            if broken is None:
                assert args[args.index("--agent-binary") + 1] == agent
                assert args[args.index("--guard-binary") + 1] == guard
            repaired = CliRunner().invoke(acp_cmd, args, obj=app)
            assert repaired.exit_code == 0, repaired.output
            locked = app.cfg.acp.profiles["locked"]
            assert (locked.mode, locked.fail_mode) == ("action", "closed")
            assert json.loads(lock_path.read_text())["mode"] == "action"
            assert CliRunner().invoke(acp_cmd, ["verify"], obj=app).exit_code == 0

        # The mode a binding inherits counts too, and an unknown mode enforces.
        for profile_mode, fallback in (("", "action"), ("enforce", "observe")):
            app.cfg.acp.profiles["locked"].mode = profile_mode
            app.cfg.acp.mode = fallback
            assert "--activate" in cmd_acp_module.setup_repair_command(app.cfg, "zed", "kiro", str(data_dir))
        app.cfg.acp.profiles["locked"].mode = "observe"
        assert "--activate" not in cmd_acp_module.setup_repair_command(app.cfg, "zed", "kiro", str(data_dir))
    finally:
        cleanup_app(app, db_path, data_dir)


def test_doctor_repair_command_keeps_action_mode(tmp_path, monkeypatch):
    from defenseclaw.commands.cmd_doctor import _check_acp_bindings, _DoctorResult, _fix_acp_guard_pins

    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    guard = _binary(tmp_path / "guard")
    agent_path = tmp_path / "kiro-cli"
    agent = _binary(agent_path)
    try:
        result = CliRunner().invoke(
            acp_cmd,
            ["setup", "--client", "zed", "--agent", "kiro", "--profile", "locked", "--activate",
             "--guard-binary", guard, "--agent-binary", agent],
            obj=app,
        )
        assert result.exit_code == 0, result.output
        agent_path.write_bytes(b"drifted-binary")
        drifted = _DoctorResult()
        _check_acp_bindings(app.cfg, drifted)
        [row] = drifted.checks
        assert "--activate" in row["remediation"] and "locked" in row["remediation"]
        _tag, detail = _fix_acp_guard_pins(app.cfg, assume_yes=True, plan_only=True)
        assert "--activate" in detail
    finally:
        cleanup_app(app, db_path, data_dir)


def test_remove_and_setup_leave_unproven_guard_named_entries(tmp_path, monkeypatch):
    """A guard-like filename is not ownership: only a matching contract lock is."""
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    settings = _zed_settings(tmp_path)
    settings.parent.mkdir(parents=True)
    own = tmp_path / "operator" / "defenseclaw-acp"
    own.parent.mkdir()
    operator_guard = _binary(own)
    guard = _binary(tmp_path / "defenseclaw-acp")
    agent = _binary(tmp_path / "kiro-cli")
    real_lock = str((Path(data_dir) / "acp" / "zed-kiro.contract-lock.json").resolve())
    other_lock = str(tmp_path / "elsewhere" / "zed-kiro.contract-lock.json")
    argv = ["--client", "zed", "--agent", "kiro"]
    variants = {
        "no lock": argv + ["--", "kiro-cli", "acp"],
        "missing lock": argv + ["--contract-lock", other_lock, "--", "kiro-cli", "acp"],
        # The pair's real lock exists but pins DefenseClaw's guard, not this file.
        "foreign command": argv + ["--contract-lock", real_lock, "--", "kiro-cli", "acp"],
    }
    try:
        for label, args in variants.items():
            alias = {"command": operator_guard, "args": args}
            settings.write_text(json.dumps({"agent_servers": {"My Kiro": alias}}))
            before = settings.read_bytes()
            removed = CliRunner().invoke(acp_cmd, ["remove", "--client", "zed", "--agent", "kiro"], obj=app)
            assert removed.exit_code == 0, (label, removed.output)
            assert settings.read_bytes() == before, label
            status = json.loads(CliRunner().invoke(acp_cmd, ["status", "--json"], obj=app).output)
            assert status["bindings"] == {}, label

            setup = CliRunner().invoke(
                acp_cmd,
                ["setup", "--client", "zed", "--agent", "kiro", "--activate",
                 "--guard-binary", guard, "--agent-binary", agent],
                obj=app,
            )
            assert setup.exit_code == 0, (label, setup.output)
            servers = json.loads(settings.read_text())["agent_servers"]
            assert servers["My Kiro"] == alias, label
            assert servers["DefenseClaw · Kiro"]["command"] == guard
            removed = CliRunner().invoke(acp_cmd, ["remove", "--client", "zed", "--agent", "kiro"], obj=app)
            assert removed.exit_code == 0, (label, removed.output)
            assert json.loads(settings.read_text())["agent_servers"] == {"My Kiro": alias}, label
    finally:
        cleanup_app(app, db_path, data_dir)


def test_alias_with_another_runtimes_lock_is_not_this_runtimes(tmp_path, monkeypatch):
    """An alias proven only by another runtime's lock or credential is left alone.

    Setup in a second runtime directory writes a valid lock that binds this
    editor file and pins the same guard. Removal and setup under the current
    runtime must neither delete nor rewrite that alias (nor the settings
    file), and status must not count it as this runtime's binding.
    """
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    settings = _zed_settings(tmp_path)
    settings.parent.mkdir(parents=True)
    guard = _binary(tmp_path / "defenseclaw-acp")
    agent = _binary(tmp_path / "kiro-cli")
    other = str((tmp_path / "other-runtime").resolve())
    current_lock = cmd_acp_module._contract_lock_path(data_dir, "zed", "kiro")

    def lock_in(runtime: str) -> str:
        settings.write_text("{}")
        return str(cmd_acp_module._write_contract_lock(
            data_dir=runtime, client="zed", agent="kiro", profile="default", mode="observe",
            guard=guard, agent_executable=agent, client_path=settings.resolve(), managed=False,
        ))

    def alias(lock: str, token: str) -> dict:
        return {"command": guard, "args": [
            "--agent", "kiro", "--client", "zed", "--profile", "default", "--mode", "observe",
            "--token-file", token, "--gateway", "http://127.0.0.1:1/api/v1/acp/evaluate",
            "--contract-lock", lock, "--", agent, "acp",
        ]}

    other_token = str(Path(other) / "acp" / ".token")
    current_token = str((Path(data_dir) / "acp" / ".token").resolve())
    variants = {
        # The other runtime's own lock and token: valid, but not this runtime's.
        "other runtime lock": lambda: alias(lock_in(other), other_token),
        # This runtime's lock, but the entry carries another runtime's credential.
        "other runtime token": lambda: (lock_in(other), alias(lock_in(data_dir), other_token))[1],
    }
    if os.name != "nt":
        def writable_lock() -> dict:
            entry = alias(lock_in(data_dir), current_token)
            current_lock.chmod(0o666)
            return entry

        # This runtime's lock path and token, but a lock others can rewrite.
        variants["lock out of custody"] = writable_lock
    try:
        for label, make in variants.items():
            entry = make()
            settings.write_text(json.dumps({"agent_servers": {"Other Kiro": entry}}))
            before = settings.read_bytes()
            removed = CliRunner().invoke(acp_cmd, ["remove", "--client", "zed", "--agent", "kiro"], obj=app)
            assert removed.exit_code == 0, (label, removed.output)
            assert settings.read_bytes() == before, label

            setup = CliRunner().invoke(
                acp_cmd,
                ["setup", "--client", "zed", "--agent", "kiro", "--activate",
                 "--guard-binary", guard, "--agent-binary", agent],
                obj=app,
            )
            assert setup.exit_code == 0, (label, setup.output)
            servers = json.loads(settings.read_text())["agent_servers"]
            assert servers["Other Kiro"] == entry, label
            assert servers["DefenseClaw · Kiro"]["command"] == guard, label
            if label == "lock out of custody":
                # Setup rewrote the lock owner-only, so the copy now names a
                # lock in this runtime's custody; nothing more to prove here.
                settings.unlink()
                continue
            # The other runtime's alias is foreign here: the binding is not
            # healthy while it is there, and the problem names the manual step.
            status = json.loads(CliRunner().invoke(acp_cmd, ["status", "--json"], obj=app).output)
            problems = status["bindings"]["zed/kiro"]["problems"]
            assert any(
                problem.startswith("editor entry 'Other Kiro' is not DefenseClaw's") and "delete it in" in problem
                for problem in problems
            ), (label, problems)
            removed = CliRunner().invoke(acp_cmd, ["remove", "--client", "zed", "--agent", "kiro"], obj=app)
            assert removed.exit_code == 0, (label, removed.output)
            assert json.loads(settings.read_text())["agent_servers"] == {"Other Kiro": entry}, label

        # Control: this runtime's own adopted alias is still this runtime's.
        settings.write_text(json.dumps({"agent_servers": {"My Kiro": {"command": agent, "args": ["acp"]}}}))
        adopted = CliRunner().invoke(
            acp_cmd, ["adopt", "--client", "zed", "--guard-binary", guard, "--yes", "--json-output"], obj=app
        )
        assert adopted.exit_code == 0, adopted.output
        assert list(json.loads(settings.read_text())["agent_servers"]) == ["My Kiro"]
        removed = CliRunner().invoke(acp_cmd, ["remove", "--client", "zed", "--agent", "kiro"], obj=app)
        assert removed.exit_code == 0, removed.output
        assert not settings.exists()
    finally:
        cleanup_app(app, db_path, data_dir)


def test_missing_editor_settings_is_a_binding_problem(tmp_path, monkeypatch):
    """A binding whose editor file is gone is unhealthy, with a repair, not a crash."""
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    settings = _zed_settings(tmp_path)
    guard = _binary(tmp_path / "defenseclaw-acp")
    agent = _binary(tmp_path / "kiro-cli")
    setup = ["setup", "--client", "zed", "--agent", "kiro", "--profile", "locked", "--activate",
             "--guard-binary", guard, "--agent-binary", agent]
    try:
        for verify in (["verify"], ["verify", "--client", "zed", "--agent", "kiro"]):
            result = CliRunner().invoke(acp_cmd, setup, obj=app)
            assert result.exit_code == 0, result.output
            settings.unlink()

            status = CliRunner().invoke(acp_cmd, ["status", "--json"], obj=app)
            assert status.exit_code == 0, status.output
            binding = json.loads(status.output)["bindings"]["zed/kiro"]
            assert not binding["healthy"]
            assert f"editor settings file is missing: {settings}" in binding["problems"]
            assert (binding["profile"], binding["mode"]) == ("locked", "action")
            text = CliRunner().invoke(acp_cmd, ["status"], obj=app)
            assert text.exit_code == 0 and "NEEDS ATTENTION" in text.output, text.output

            failed = CliRunner().invoke(acp_cmd, verify, obj=app)
            assert failed.exit_code != 0
            assert not isinstance(failed.exception, FileNotFoundError), failed.exception
            assert "editor settings file is missing" in failed.output, failed.output
            repair = _repair_args(failed.output)
            assert "--activate" in repair and "locked" in repair, repair
            repaired = CliRunner().invoke(acp_cmd, repair, obj=app)
            assert repaired.exit_code == 0, repaired.output
            assert CliRunner().invoke(acp_cmd, verify, obj=app).exit_code == 0

        # An explicit pair whose editor path is not a file is reported, not raised.
        settings.unlink()
        settings.mkdir()
        failed = CliRunner().invoke(acp_cmd, ["verify", "--client", "zed", "--agent", "kiro"], obj=app)
        assert failed.exit_code != 0
        assert "editor settings file cannot be used" in failed.output, failed.output
        assert "; run " in failed.output, failed.output
    finally:
        cleanup_app(app, db_path, data_dir)


def test_bypassed_adopted_entry_stays_in_status_and_verify(tmp_path, monkeypatch):
    """Pointing an adopted entry back at the agent must not make the binding vanish."""
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    settings = _zed_settings(tmp_path)
    settings.parent.mkdir(parents=True)
    guard = _binary(tmp_path / "defenseclaw-acp")
    agent = _binary(tmp_path / "kiro-cli")
    opencode = _binary(tmp_path / "opencode")
    direct = {"command": agent, "args": ["acp"], "env": {"KEEP": "me"}}
    try:
        for bypass in ("direct", "deleted"):
            settings.write_text(json.dumps({"agent_servers": {"My Kiro": direct, "Foreign": {"command": "other"}}}))
            adopted = CliRunner().invoke(
                acp_cmd,
                ["adopt", "--client", "zed", "--guard-binary", guard, "--activate", "--yes", "--json-output"],
                obj=app,
            )
            assert adopted.exit_code == 0, adopted.output
            assert [key[3] for key in cmd_acp_module._owned_entry_records(data_dir)] == ["My Kiro"]
            assert CliRunner().invoke(acp_cmd, ["verify"], obj=app).exit_code == 0

            document = json.loads(settings.read_text())
            if bypass == "direct":
                document["agent_servers"]["My Kiro"] = direct
            else:
                del document["agent_servers"]["My Kiro"]
            settings.write_text(json.dumps(document))

            status = json.loads(CliRunner().invoke(acp_cmd, ["status", "--json"], obj=app).output)
            binding = status["bindings"]["zed/kiro"]
            assert binding["healthy"] is False and binding["mode"] == "action", bypass
            assert any("'My Kiro' no longer launches the DefenseClaw guard" in p for p in binding["problems"])
            verified = CliRunner().invoke(acp_cmd, ["verify"], obj=app)
            assert verified.exit_code != 0 and "zed/kiro" in verified.output, verified.output
            assert "--activate" in _repair_args(verified.output)

            # A bypassed pair still counts as using its profile.
            shared = CliRunner().invoke(
                acp_cmd,
                ["setup", "--client", "zed", "--agent", "opencode", "--guard-binary", guard,
                 "--agent-binary", opencode],
                obj=app,
            )
            assert shared.exit_code != 0 and "zed/kiro" in shared.output, shared.output
            assert app.cfg.acp.profiles["default"].mode == "action"

            repaired = CliRunner().invoke(acp_cmd, _repair_args(verified.output), obj=app)
            assert repaired.exit_code == 0, repaired.output
            servers = json.loads(settings.read_text())["agent_servers"]
            kept = {"Foreign": {"command": "other"}}
            if bypass == "direct":
                # The changed entry is no longer provably DefenseClaw's, so the
                # repair leaves it, guards the pair with the reserved entry and
                # names the manual step that routes it back.
                assert servers["My Kiro"] == direct
                assert "Left editor entry 'My Kiro'" in repaired.output, repaired.output
                assert "defenseclaw acp adopt --client zed" in repaired.output, repaired.output
                kept["My Kiro"] = direct
                # It still launches the agent without the guard, so verify
                # stays red and names the step until it is adopted or removed.
                bypassed = CliRunner().invoke(acp_cmd, ["verify"], obj=app)
                assert bypassed.exit_code != 0, bypassed.output
                assert "'My Kiro' is not DefenseClaw's: it launches kiro without the DefenseClaw guard" in (
                    bypassed.output
                ), bypassed.output
                assert "defenseclaw acp adopt --client zed" in bypassed.output, bypassed.output
            assert servers["DefenseClaw · Kiro"]["command"] == guard
            if bypass == "deleted":
                assert CliRunner().invoke(acp_cmd, ["verify"], obj=app).exit_code == 0

            removed = CliRunner().invoke(acp_cmd, ["remove", "--client", "zed", "--agent", "kiro"], obj=app)
            assert removed.exit_code == 0, removed.output
            assert json.loads(settings.read_text())["agent_servers"] == kept

        # A configured binding whose editor entry and lock are both gone is still listed.
        app.cfg.acp.bindings["zed/kiro"] = ACPBinding(enabled=True, profile="default")
        status = json.loads(CliRunner().invoke(acp_cmd, ["status", "--json"], obj=app).output)
        assert status["bindings"]["zed/kiro"]["healthy"] is False
        assert CliRunner().invoke(acp_cmd, ["verify"], obj=app).exit_code != 0
    finally:
        cleanup_app(app, db_path, data_dir)


def _setup_args(guard: str, agent: str) -> list[str]:
    return ["setup", "--client", "zed", "--agent", "kiro", "--activate", "--guard-binary", guard, "--agent-binary", agent]


def _link_directory(link: Path, target: Path) -> None:
    if os.name == "nt":
        import _winapi

        _winapi.CreateJunction(str(target), str(link))
    else:
        link.symlink_to(target, target_is_directory=True)


def test_linked_acp_directory_proves_nothing_and_loses_nothing(tmp_path, monkeypatch):
    """A link at <data_dir>/acp reaches another runtime's state, which is not this runtime's.

    The other runtime's alias, lock and token are valid for that runtime.
    With this runtime's acp directory linked to it (a symlink, or a
    junction on Windows), status lists no binding, removal keeps the alias,
    the settings file, the lock and the token and warns, setup refuses, and
    refresh re-pins nothing through the link, even for the reserved entry.
    """
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    settings = _zed_settings(tmp_path)
    settings.parent.mkdir(parents=True)
    guard = _binary(tmp_path / "defenseclaw-acp")
    agent = _binary(tmp_path / "kiro-cli")
    other = str((tmp_path / "other-runtime").resolve())
    other_token = _write_token(other)
    settings.write_text("{}")
    other_lock = cmd_acp_module._write_contract_lock(
        data_dir=other, client="zed", agent="kiro", profile="default", mode="observe",
        guard=guard, agent_executable=agent, client_path=settings.resolve(), managed=False,
    )
    acp_dir = Path(data_dir) / "acp"
    assert not acp_dir.exists()
    _link_directory(acp_dir, Path(other) / "acp")

    def entry() -> dict:
        return {"command": guard, "args": [
            "--agent", "kiro", "--client", "zed", "--profile", "default", "--mode", "observe",
            "--token-file", str(other_token), "--gateway", "http://127.0.0.1:1/api/v1/acp/evaluate",
            "--contract-lock", str(other_lock), "--", agent, "acp",
        ]}

    remove_args = ["remove", "--client", "zed", "--agent", "kiro"]
    try:
        for name in ("Other Kiro", "DefenseClaw · Kiro"):
            settings.write_text(json.dumps({"agent_servers": {name: entry()}}))
            cmd_acp_module._refresh_client_contract_digests(other, "zed", settings)
            cmd_acp_module._write_entry_records(other, {
                ("zed", "kiro", cmd_acp_module._path_key(settings), name): cmd_acp_module._entry_digest(entry(), "zed"),
            })
            # The other runtime owns its entry; this runtime reaches that record only through the link.
            servers = json.loads(settings.read_text())["agent_servers"]
            other_records = cmd_acp_module._owned_entry_records(other)
            assert cmd_acp_module._pair_entry_names(servers, "zed", "kiro", other_records) == [name]
            assert cmd_acp_module._owned_entry_records(data_dir) == {}
            before = settings.read_bytes()
            state = {
                path: path.read_bytes()
                for path in (other_lock, other_token, cmd_acp_module._entry_record_path(other))
            }

            status = CliRunner().invoke(acp_cmd, ["status", "--json"], obj=app)
            assert status.exit_code == 0, (name, status.output)
            # Through the link nothing is this runtime's, the reserved name included.
            binding = json.loads(status.output)["bindings"].get("zed/kiro")
            assert binding is None, (name, binding)

            setup = CliRunner().invoke(acp_cmd, _setup_args(guard, agent), obj=app)
            assert setup.exit_code != 0 and "is a link or not a directory" in setup.output, (name, setup.output)
            assert settings.read_bytes() == before, name

            Path(guard).write_bytes(b"upgraded-guard")
            assert cmd_acp_module.refresh_guard_pins(data_dir) == [], name
            assert {path: path.read_bytes() for path in state} == state, name

            if name == "Other Kiro":
                removed = CliRunner().invoke(acp_cmd, remove_args, obj=app)
                assert removed.exit_code == 0, (name, removed.output)
                assert settings.read_bytes() == before, name
                assert "Left editor entry 'Other Kiro'" in removed.output, (name, removed.output)
                assert {path: path.read_bytes() for path in state} == state, name
            Path(guard).write_bytes(b"test-binary")

        # The reserved entry the other runtime wrote, its lock and its token
        # behind the link all stay in place.
        removed = CliRunner().invoke(acp_cmd, remove_args, obj=app)
        assert removed.exit_code == 0, removed.output
        assert "is a link or not a directory" in removed.output, removed.output
        assert other_lock.exists() and other_token.exists()
        assert cmd_acp_module._entry_record_path(other).exists()

        # Control: with its own directory back, this runtime sets up and removes as before.
        if os.name == "nt":
            os.rmdir(acp_dir)
        else:
            acp_dir.unlink()
        settings.write_text("{}")
        assert CliRunner().invoke(acp_cmd, _setup_args(guard, agent), obj=app).exit_code == 0
        assert CliRunner().invoke(acp_cmd, ["verify"], obj=app).exit_code == 0
        removed = CliRunner().invoke(acp_cmd, remove_args, obj=app)
        assert removed.exit_code == 0 and "is a link" not in removed.output, removed.output
        assert other_lock.exists() and other_token.exists()
    finally:
        cleanup_app(app, db_path, data_dir)


_OWNER = "S-1-5-21-1-2-3-1001"


def test_record_privacy_follows_the_guards_windows_dacl_rule():
    """The entry record must pass the guard's private-file DACL rule (safefile on Windows), case by case."""
    from defenseclaw.file_permissions import guard_private_dacl_error

    full, read, read_control = 0x001F01FF, 0x00120089, 0x00020000
    canonical = [(full, 1, 0, "S-1-5-18"), (full, 1, 0, "S-1-3-4")]
    accepted = {
        "setup's DACL (SYSTEM, OWNER RIGHTS)": (_OWNER, canonical),
        "SYSTEM and the user": (_OWNER, [(full, 1, 0, "S-1-5-18"), (full, 1, 0, _OWNER)]),
        "an empty grant to Everyone": (_OWNER, [*canonical, (0, 1, 0, "S-1-1-0")]),
        "a deny for another account": (_OWNER, [(full, 3, 0, "S-1-5-21-9-9-9-1002"), *canonical]),
        "a SYSTEM caller": ("S-1-5-18", [(full, 1, 0, "S-1-5-18")]),
    }
    refused = {
        "Everyone can write": (_OWNER, [*canonical, (full, 1, 0, "S-1-1-0")]),
        "Users can read": (_OWNER, [*canonical, (read, 1, 0, "S-1-5-32-545")]),
        "another account can read its ACL": (_OWNER, [*canonical, (read_control, 1, 0, "S-1-5-21-9-9-9-1002")]),
        "Administrators can write": (_OWNER, [*canonical, (full, 1, 0, "S-1-5-32-544")]),
        "an inherit-only grant to Everyone": (_OWNER, [*canonical, (full, 1, 0x08, "S-1-1-0")]),
        "another owner": ("S-1-5-21-9-9-9-1002", canonical),
        "Administrators own it": ("S-1-5-32-544", canonical),
        "the owner is denied": (_OWNER, [(full, 3, 0, "S-1-3-4"), *canonical]),
        "SYSTEM is denied": (_OWNER, [(full, 3, 0, "S-1-5-18"), *canonical]),
        "no SYSTEM grant": (_OWNER, [(full, 1, 0, "S-1-3-4")]),
        "no owner grant": (_OWNER, [(full, 1, 0, "S-1-5-18")]),
        "an entry of another type": (_OWNER, [*canonical, (full, 9, 0, "S-1-1-0")]),
    }
    for label, (owner, entries) in accepted.items():
        assert guard_private_dacl_error(owner, False, entries, owner if owner == "S-1-5-18" else _OWNER) is None, label
    for label, (owner, entries) in refused.items():
        assert guard_private_dacl_error(owner, False, entries, _OWNER) is not None, label
    assert guard_private_dacl_error(_OWNER, True, [], _OWNER) is not None
    assert guard_private_dacl_error(_OWNER, False, canonical, "") is not None


def _adopt_my_kiro(app, settings: Path, guard: str, direct: dict, foreign: dict) -> dict:
    """Adopt the operator's direct 'My Kiro' entry; return the alias DefenseClaw wrote."""
    settings.write_text(json.dumps({"agent_servers": {"My Kiro": direct, "Foreign": foreign}}))
    adopted = CliRunner().invoke(
        acp_cmd, ["adopt", "--client", "zed", "--guard-binary", guard, "--yes", "--json-output"], obj=app
    )
    assert adopted.exit_code == 0, adopted.output
    alias = json.loads(settings.read_text())["agent_servers"]["My Kiro"]
    assert alias["command"] == guard, alias
    return alias


def _with_option(alias: dict, flag: str, value: str | None) -> dict:
    args = list(alias["args"])
    index = args.index(flag)
    if value is None:
        del args[index:index + 2]
    else:
        args[index + 1] = value
    return {**alias, "args": args}


def test_adopted_entry_in_a_replacement_settings_file_is_left(tmp_path, monkeypatch):
    """An old adoption never takes over an entry DefenseClaw did not write as it is.

    After 'My Kiro' is adopted, the guarded settings file is moved aside and
    a new file at the same path holds an independent 'My Kiro' (the original
    direct launch, another direct launch, a guard launch DefenseClaw did not
    write), or the adopted entry is pointed back at the agent in place.
    Status and verify answer (also while no file exists), setup leaves the
    entry byte for byte, guards the pair with the reserved entry and names
    the manual step, and removal leaves the operator's file as it was. Only
    an explicit acp adopt takes the entry over again.
    """
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    settings = _zed_settings(tmp_path)
    settings.parent.mkdir(parents=True)
    guard = _binary(tmp_path / "defenseclaw-acp")
    agent = _binary(tmp_path / "kiro-cli")
    direct = {"command": agent, "args": ["acp"], "env": {"KEEP": "me"}}
    foreign = {"command": "other", "args": []}
    aside = settings.with_name("settings.json.aside")
    try:
        variants = {
            "the original direct entry": lambda alias: direct,
            "another direct entry": lambda alias: {"command": agent, "args": ["acp", "--verbose"]},
            "a guard launch DefenseClaw did not write": lambda alias: _with_option(
                alias, "--gateway", "http://gateway.example.com:18970/api/v1/acp/evaluate"
            ),
        }
        for label, make in [*variants.items(), ("pointed back in place", None)]:
            alias = _adopt_my_kiro(app, settings, guard, direct, foreign)
            if make is None:
                independent = {"agent_servers": {"My Kiro": direct, "Foreign": foreign}}
            else:
                settings.replace(aside)
                aside_bytes = aside.read_bytes()
                # No settings file at all: nothing installed, and no crash.
                status = CliRunner().invoke(acp_cmd, ["status", "--json"], obj=app)
                assert status.exit_code == 0, (label, status.output)
                problems = json.loads(status.output)["bindings"]["zed/kiro"]["problems"]
                assert f"editor settings file is missing: {settings}" in problems, (label, problems)
                failed = CliRunner().invoke(acp_cmd, ["verify"], obj=app)
                assert failed.exit_code != 0 and not isinstance(failed.exception, OSError), (label, failed.output)
                independent = {"agent_servers": {"My Kiro": make(alias), "Foreign": foreign}}
            settings.write_text(json.dumps(independent))
            entry = independent["agent_servers"]["My Kiro"]

            status = CliRunner().invoke(acp_cmd, ["status", "--json"], obj=app)
            assert status.exit_code == 0, (label, status.output)
            problems = json.loads(status.output)["bindings"]["zed/kiro"]["problems"]
            assert any("'My Kiro' no longer launches the DefenseClaw guard" in p for p in problems), (label, problems)

            setup = CliRunner().invoke(acp_cmd, _setup_args(guard, agent), obj=app)
            assert setup.exit_code == 0, (label, setup.output)
            servers = json.loads(settings.read_text())["agent_servers"]
            assert servers["My Kiro"] == entry, label
            assert servers["Foreign"] == foreign, label
            assert servers["DefenseClaw · Kiro"]["command"] == guard, label
            assert "Left editor entry 'My Kiro'" in setup.output, (label, setup.output)
            if entry["command"] == agent:
                assert "defenseclaw acp adopt --client zed" in setup.output, (label, setup.output)
            if make is not None:
                assert aside.read_bytes() == aside_bytes, label
            assert [key[3] for key in cmd_acp_module._owned_entry_records(data_dir)] == ["DefenseClaw · Kiro"], label
            verified = CliRunner().invoke(acp_cmd, ["verify"], obj=app)
            assert verified.exit_code != 0 and "editor entry 'My Kiro' is not DefenseClaw's" in verified.output, (
                label, verified.output
            )
            step = "defenseclaw acp adopt --client zed" if entry["command"] == agent else "delete it in"
            assert step in verified.output, (label, verified.output)

            removed = CliRunner().invoke(acp_cmd, ["remove", "--client", "zed", "--agent", "kiro"], obj=app)
            assert removed.exit_code == 0, (label, removed.output)
            assert json.loads(settings.read_text()) == independent, label
            assert not cmd_acp_module._entry_record_path(data_dir).exists(), label
            if make is not None:
                aside.unlink()

        # Only an explicit adoption takes a direct entry over.
        alias = _adopt_my_kiro(app, settings, guard, direct, foreign)
        assert alias["env"] == {"KEEP": "me"}
    finally:
        cleanup_app(app, db_path, data_dir)


def test_changed_alias_is_not_this_runtimes_to_remove(tmp_path, monkeypatch):
    """Any change to an adopted alias (its --gateway first) breaks the proof that DefenseClaw wrote it.

    Verify reports the changed alias with a repair, and removal leaves it and
    its settings file byte for byte and names the manual step. An unchanged
    alias stays DefenseClaw's after another pair's setup rewrites the file.
    """
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    settings = _zed_settings(tmp_path)
    settings.parent.mkdir(parents=True)
    guard = _binary(tmp_path / "defenseclaw-acp")
    agent = _binary(tmp_path / "kiro-cli")
    other_agent = _binary(tmp_path / "other-agent")
    opencode = _binary(tmp_path / "opencode")
    (tmp_path / "copy").mkdir()
    other_guard = _binary(tmp_path / "copy" / "defenseclaw-acp")
    direct = {"command": agent, "args": ["acp"], "env": {"KEEP": "me"}}
    foreign = {"command": "other", "args": []}

    def gateway(alias: dict) -> str:
        return alias["args"][alias["args"].index("--gateway") + 1]

    def tail(alias: dict, *values: str) -> dict:
        args = alias["args"]
        return {**alias, "args": [*args[:args.index("--") + 1], *values]}

    remote = "http://gateway.example.com:18970/api/v1/acp/evaluate"
    variants = {
        "gateway off loopback": lambda a: _with_option(a, "--gateway", remote),
        "gateway over https": lambda a: _with_option(a, "--gateway", gateway(a).replace("http://", "https://")),
        "gateway on another port": lambda a: _with_option(a, "--gateway", "http://127.0.0.1:1/api/v1/acp/evaluate"),
        "gateway on another path": lambda a: _with_option(a, "--gateway", gateway(a).replace("/acp/evaluate", "/x")),
        "empty gateway": lambda a: _with_option(a, "--gateway", ""),
        "no gateway": lambda a: _with_option(a, "--gateway", None),
        "another profile": lambda a: _with_option(a, "--profile", "other"),
        "another mode": lambda a: _with_option(a, "--mode", "action"),
        "another token": lambda a: _with_option(a, "--token-file", str(tmp_path / "other.token")),
        "another lock": lambda a: _with_option(a, "--contract-lock", str(tmp_path / "other.lock.json")),
        "another agent": lambda a: tail(a, other_agent, "acp"),
        "an extra agent argument": lambda a: tail(a, agent, "acp", "--trust-all-tools"),
        "another guard file": lambda a: {**a, "command": other_guard},
        "another env": lambda a: {**a, "env": {"KEEP": "me", "EXTRA": "1"}},
        "no env": lambda a: {key: value for key, value in a.items() if key != "env"},
        "another type": lambda a: {**a, "type": "extension"},
        "an added field": lambda a: {**a, "extra": "x"},
    }
    remove_args = ["remove", "--client", "zed", "--agent", "kiro"]
    try:
        for label, mutate in variants.items():
            alias = _adopt_my_kiro(app, settings, guard, direct, foreign)
            document = json.loads(settings.read_text())
            document["agent_servers"]["My Kiro"] = mutate(alias)
            settings.write_text(json.dumps(document))
            before = settings.read_bytes()

            verified = CliRunner().invoke(acp_cmd, ["verify"], obj=app)
            assert verified.exit_code != 0, (label, verified.output)
            assert "'My Kiro' no longer launches the DefenseClaw guard" in verified.output, (label, verified.output)
            assert "; run defenseclaw " in verified.output, (label, verified.output)

            removed = CliRunner().invoke(acp_cmd, remove_args, obj=app)
            assert removed.exit_code == 0, (label, removed.output)
            assert settings.read_bytes() == before, label
            assert "Left editor entry 'My Kiro'" in removed.output, (label, removed.output)
            assert "Delete it there if you no longer use it." in removed.output, (label, removed.output)

        # Control: the unchanged alias is DefenseClaw's, also after another
        # pair's setup rewrote the shared file.
        _adopt_my_kiro(app, settings, guard, direct, foreign)
        other_pair = CliRunner().invoke(
            acp_cmd,
            ["setup", "--client", "zed", "--agent", "opencode", "--guard-binary", guard, "--agent-binary", opencode],
            obj=app,
        )
        assert other_pair.exit_code == 0, other_pair.output
        assert CliRunner().invoke(acp_cmd, ["verify"], obj=app).exit_code == 0
        removed = CliRunner().invoke(acp_cmd, remove_args, obj=app)
        assert removed.exit_code == 0, removed.output
        assert "Left editor entry" not in removed.output, removed.output
        assert set(json.loads(settings.read_text())["agent_servers"]) == {"Foreign", "DefenseClaw · Opencode"}
    finally:
        cleanup_app(app, db_path, data_dir)


def test_verify_checks_the_gateway_each_entry_sends_verdicts_to(tmp_path, monkeypatch):
    """Verify checks the --gateway of each entry DefenseClaw wrote.

    A configured gateway port the entry no longer names is a drift with a
    repair. A hand-edited gateway makes the entry foreign, reported with the
    manual step. Neither is a healthy binding.
    """
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    settings = _zed_settings(tmp_path)
    guard = _binary(tmp_path / "defenseclaw-acp")
    agent = _binary(tmp_path / "kiro-cli")
    name = "DefenseClaw · Kiro"
    try:
        assert CliRunner().invoke(acp_cmd, _setup_args(guard, agent), obj=app).exit_code == 0
        assert CliRunner().invoke(acp_cmd, ["verify"], obj=app).exit_code == 0
        written = settings.read_bytes()

        document = json.loads(written)
        document["agent_servers"][name] = _with_option(
            document["agent_servers"][name], "--gateway", "http://gateway.example.com:18970/api/v1/acp/evaluate"
        )
        settings.write_text(json.dumps(document))
        cmd_acp_module._refresh_client_contract_digests(str(data_dir), "zed", settings)
        failed = CliRunner().invoke(acp_cmd, ["verify"], obj=app)
        assert failed.exit_code != 0, failed.output
        assert f"editor entry {name!r} changed after DefenseClaw wrote it" in failed.output, failed.output
        assert "delete it in" in failed.output, failed.output
        status = json.loads(CliRunner().invoke(acp_cmd, ["status", "--json"], obj=app).output)
        assert status["bindings"]["zed/kiro"]["healthy"] is False

        settings.write_bytes(written)
        cmd_acp_module._refresh_client_contract_digests(str(data_dir), "zed", settings)
        assert CliRunner().invoke(acp_cmd, ["verify"], obj=app).exit_code == 0
        app.cfg.gateway.api_port += 1
        failed = CliRunner().invoke(acp_cmd, ["verify"], obj=app)
        assert failed.exit_code != 0, failed.output
        assert f"does not send verdicts to this gateway (http://127.0.0.1:{app.cfg.gateway.api_port}/" in failed.output
        repaired = CliRunner().invoke(acp_cmd, _repair_args(failed.output), obj=app)
        assert repaired.exit_code == 0, repaired.output
        assert CliRunner().invoke(acp_cmd, ["verify"], obj=app).exit_code == 0
    finally:
        cleanup_app(app, db_path, data_dir)


def test_only_this_accounts_own_record_proves_an_alias(tmp_path, monkeypatch):
    """The record proves an alias only as this runtime's private, intact file.

    Each variant changes the record after a valid adoption. Removal leaves
    the alias and its settings file byte for byte and warns, and setup
    leaves the alias and guards the pair with the reserved entry. A linked
    record is refused outright.
    """
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    settings = _zed_settings(tmp_path)
    settings.parent.mkdir(parents=True)
    guard = _binary(tmp_path / "defenseclaw-acp")
    agent = _binary(tmp_path / "kiro-cli")
    direct = {"command": agent, "args": ["acp"]}
    foreign = {"command": "other", "args": []}
    record = cmd_acp_module._entry_record_path(data_dir)
    elsewhere = tmp_path / "elsewhere" / "owned-entries.json"
    elsewhere.parent.mkdir()

    def edit(change):
        def apply() -> None:
            document = json.loads(record.read_text())
            change(document)
            cmd_acp_module.atomic_write_private_bytes(record, json.dumps(document).encode())
        return apply

    def entry_field(key, value):
        def change(document) -> None:
            (item,) = [item for item in document["entries"] if (item["client"], item["name"]) == ("zed", "My Kiro")]
            item[key] = value
        return edit(change)

    def link() -> None:
        record.replace(elsewhere)
        record.symlink_to(elsewhere)

    variants = {
        "no record": record.unlink,
        "another runtime": edit(lambda document: document.__setitem__("runtime", str(tmp_path / "other-runtime"))),
        "version 2": edit(lambda document: document.__setitem__("version", 2)),
        "boolean version": edit(lambda document: document.__setitem__("version", True)),
        "entries not a list": edit(lambda document: document.__setitem__("entries", {})),
        "another editor file": entry_field("config_path", str(settings.with_name("other.json"))),
        "another client": entry_field("client", "jetbrains"),
        "another name": entry_field("name", "Other Kiro"),
        "another digest": entry_field("sha256", cmd_acp_module._entry_digest(direct, "zed")),
        "not JSON": lambda: cmd_acp_module.atomic_write_private_bytes(record, b"{"),
    }
    if os.name == "nt":
        from tests.permissions import grant_everyone

        for perm in ("F", "M", "R"):
            variants[f"Everyone {perm}"] = lambda perm=perm: grant_everyone(record, perm)
    else:
        variants["group-readable"] = lambda: record.chmod(0o640)
        variants["linked"] = link
    try:
        for label, tamper in variants.items():
            alias = _adopt_my_kiro(app, settings, guard, direct, foreign)
            assert cmd_acp_module._owned_entry_records(data_dir), label
            tamper()
            servers = json.loads(settings.read_text())["agent_servers"]
            records = cmd_acp_module._owned_entry_records(data_dir)
            assert cmd_acp_module._pair_entry_names(servers, "zed", "kiro", records) == [], label
            before = settings.read_bytes()
            removed = CliRunner().invoke(acp_cmd, ["remove", "--client", "zed", "--agent", "kiro"], obj=app)
            assert settings.read_bytes() == before, label
            if label == "linked":
                # Neither command writes through a linked record.
                assert removed.exit_code != 0 and "refusing unsafe managed path" in removed.output, removed.output
                setup = CliRunner().invoke(acp_cmd, _setup_args(guard, agent), obj=app)
                assert setup.exit_code != 0 and settings.read_bytes() == before, (label, setup.output)
                record.unlink()
                elsewhere.unlink()
                assert CliRunner().invoke(acp_cmd, ["remove", "--client", "zed", "--agent", "kiro"], obj=app).exit_code == 0
                continue
            assert removed.exit_code == 0, (label, removed.output)
            assert "Left editor entry 'My Kiro'" in removed.output, (label, removed.output)

            setup = CliRunner().invoke(acp_cmd, _setup_args(guard, agent), obj=app)
            assert setup.exit_code == 0, (label, setup.output)
            servers = json.loads(settings.read_text())["agent_servers"]
            assert servers["My Kiro"] == alias, label
            assert servers["DefenseClaw · Kiro"]["command"] == guard, label
            assert "Left editor entry 'My Kiro'" in setup.output, (label, setup.output)
            removed = CliRunner().invoke(acp_cmd, ["remove", "--client", "zed", "--agent", "kiro"], obj=app)
            assert removed.exit_code == 0, (label, removed.output)
            assert json.loads(settings.read_text())["agent_servers"] == {"My Kiro": alias, "Foreign": foreign}, label
    finally:
        cleanup_app(app, db_path, data_dir)


def test_foreign_entry_never_blocks_setup_or_removal_or_passes_verify(tmp_path, monkeypatch):
    """An entry not proven by marker plus recorded digest is foreign, under the reserved name too.

    Releases through 1.0.3 wrote "DefenseClaw · <Agent>" without a record,
    with whatever guard executable --guard-binary named. That entry, and any
    other entry under the reserved name this runtime did not record writing
    as it is, never blocks setup or removal and never makes verify green.
    Setup writes the pair's own entry next to it, removal leaves it, and
    status and verify report it with the manual step. Following the step
    (delete it, set up again) makes verify green.
    """
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    settings = _zed_settings(tmp_path)
    settings.parent.mkdir(parents=True)
    agent = _binary(tmp_path / "kiro-cli")
    foreign = {"command": "other", "args": []}
    record = cmd_acp_module._entry_record_path(data_dir)
    reserved, own = "DefenseClaw · Kiro", "DefenseClaw · Kiro (2)"
    remove_args = ["remove", "--client", "zed", "--agent", "kiro"]
    verify_args = ["verify", "--client", "zed", "--agent", "kiro"]
    delete, adopt = "delete it in", "defenseclaw acp adopt --client zed"

    def servers() -> dict:
        return json.loads(settings.read_text())["agent_servers"]

    def written(guard: str) -> dict:
        """The reserved entry setup writes for the pair into a file that holds only Foreign."""
        settings.write_text(json.dumps({"agent_servers": {"Foreign": foreign}}))
        result = CliRunner().invoke(acp_cmd, _setup_args(guard, agent), obj=app)
        assert result.exit_code == 0, result.output
        return servers()[reserved]

    # label: (guard filename, entry from the one setup wrote, drop the record, manual step)
    variants = {
        "1.0.3 entry, custom guard filename": ("custom-guard", lambda e: e, True, delete),
        "1.0.3 entry, defenseclaw-acp": ("defenseclaw-acp", lambda e: e, True, delete),
        "recorded, then hand-edited": ("defenseclaw-acp", lambda e: _with_option(e, "--profile", "other"), False, delete),
        "another client's marker": ("defenseclaw-acp", lambda e: _with_option(e, "--client", "jetbrains"), True, delete),
        "another agent's marker": ("defenseclaw-acp", lambda e: _with_option(e, "--agent", "opencode"), True, delete),
        "no marker": ("defenseclaw-acp", lambda e: {"command": "other", "args": ["serve"]}, True, delete),
        "launches the agent directly": ("defenseclaw-acp", lambda e: {"command": agent, "args": ["acp"]}, True, adopt),
        "not an object": ("defenseclaw-acp", lambda e: "operator note", True, delete),
    }
    try:
        for label, (filename, make, drop_record, step) in variants.items():
            guard = _binary(tmp_path / filename)
            entry = make(written(guard))
            if drop_record:
                record.unlink()
            kept = {reserved: entry, "Foreign": foreign}
            settings.write_text(json.dumps({"agent_servers": kept}))
            if label == "1.0.3 entry, defenseclaw-acp":
                # Upgrade: refresh re-pins this runtime's own lock behind the
                # recordless entry, so it keeps starting; it is still foreign.
                # (Refresh re-pins only a guard named defenseclaw-acp.)
                Path(guard).write_bytes(b"upgraded-guard")
                from defenseclaw.commands.cmd_doctor import _fix_acp_guard_pins

                tag, plan = _fix_acp_guard_pins(app.cfg, assume_yes=True, plan_only=True)
                assert tag == "plan" and "zed/kiro" in plan, (label, tag, plan)
                assert cmd_acp_module.refresh_guard_pins(data_dir) == ["zed/kiro"], label
                lock = json.loads(cmd_acp_module._contract_lock_path(data_dir, "zed", "kiro").read_text())
                assert lock["guard"]["sha256"] == cmd_acp_module._sha256_file(guard), label

            status = json.loads(CliRunner().invoke(acp_cmd, ["status", "--json"], obj=app).output)
            binding = status["bindings"]["zed/kiro"]
            assert binding["healthy"] is False, (label, binding)
            assert any(p.startswith(f"editor entry {reserved!r}") and step in p for p in binding["problems"]), (
                label, binding
            )
            failed = CliRunner().invoke(acp_cmd, verify_args, obj=app)
            assert failed.exit_code != 0 and step in failed.output, (label, failed.output)

            removed = CliRunner().invoke(acp_cmd, remove_args, obj=app)
            assert removed.exit_code == 0, (label, removed.output)
            assert servers() == kept, label
            assert f"Left editor entry {reserved!r}" in removed.output, (label, removed.output)

            for _ in range(2):  # and again: the pair's own entry is rewritten in place
                setup = CliRunner().invoke(acp_cmd, _setup_args(guard, agent), obj=app)
                assert setup.exit_code == 0, (label, setup.output)
                assert set(servers()) == {reserved, own, "Foreign"} and servers()[reserved] == entry, label
                assert servers()[own]["command"] == guard, label
                assert f"Left editor entry {reserved!r}" in setup.output, (label, setup.output)
                assert (adopt if step == adopt else f"DefenseClaw's own entry is {own!r}") in setup.output, label
            failed = CliRunner().invoke(acp_cmd, verify_args, obj=app)
            assert failed.exit_code != 0 and f"editor entry {reserved!r}" in failed.output, (label, failed.output)
            assert "managed editor entry is missing" not in failed.output, (label, failed.output)

            removed = CliRunner().invoke(acp_cmd, remove_args, obj=app)
            assert removed.exit_code == 0, (label, removed.output)
            assert servers() == kept, label

            # The manual step: delete the foreign entry, set up again, verify passes.
            assert CliRunner().invoke(acp_cmd, _setup_args(guard, agent), obj=app).exit_code == 0, label
            settings.write_text(json.dumps({"agent_servers": {own: servers()[own], "Foreign": foreign}}))
            assert CliRunner().invoke(acp_cmd, _setup_args(guard, agent), obj=app).exit_code == 0, label
            assert set(servers()) == {own, "Foreign"}, label
            verified = CliRunner().invoke(acp_cmd, verify_args, obj=app)
            assert verified.exit_code == 0, (label, verified.output)
            assert CliRunner().invoke(acp_cmd, remove_args, obj=app).exit_code == 0, label
            assert servers() == {"Foreign": foreign}, label

        # The next free name when the first is taken too.
        guard = _binary(tmp_path / "defenseclaw-acp")
        legacy = written(guard)
        record.unlink()
        crowded = {reserved: legacy, own: foreign, "Foreign": foreign}
        settings.write_text(json.dumps({"agent_servers": crowded}))
        assert CliRunner().invoke(acp_cmd, _setup_args(guard, agent), obj=app).exit_code == 0
        assert {name: value for name, value in servers().items() if name in crowded} == crowded
        assert servers()["DefenseClaw · Kiro (3)"]["command"] == guard
        assert CliRunner().invoke(acp_cmd, remove_args, obj=app).exit_code == 0
        assert servers() == crowded

        # Adoption leaves a recordless reserved entry too, and verify reports it.
        legacy = written(guard)
        record.unlink()
        direct = {"command": agent, "args": ["acp"]}
        settings.write_text(json.dumps({"agent_servers": {reserved: legacy, "My Kiro": direct, "Foreign": foreign}}))
        adopted = CliRunner().invoke(
            acp_cmd, ["adopt", "--client", "zed", "--guard-binary", guard, "--yes", "--json-output"], obj=app
        )
        assert adopted.exit_code == 0, adopted.output
        assert servers()[reserved] == legacy and servers()["My Kiro"]["command"] == guard
        failed = CliRunner().invoke(acp_cmd, verify_args, obj=app)
        assert failed.exit_code != 0 and f"editor entry {reserved!r}" in failed.output, failed.output
        assert CliRunner().invoke(acp_cmd, remove_args, obj=app).exit_code == 0
        assert servers() == {reserved: legacy, "Foreign": foreign}
    finally:
        cleanup_app(app, db_path, data_dir)


def test_editor_owned_keys_keep_the_entry_defenseclaws(tmp_path, monkeypatch):
    """The mode or model Zed stores in an entry it runs does not make DefenseClaw's own entry foreign.

    Zed writes default_mode and the like into the entry when they are picked
    in its agent panel. Setup then rewrites that entry in place (keeping the
    choice) instead of writing another next to it, verify passes, and removal
    removes it. Same for the reserved entry and an adopted one.
    """
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    settings = _zed_settings(tmp_path)
    settings.parent.mkdir(parents=True)
    guard = _binary(tmp_path / "defenseclaw-acp")
    agent = _binary(tmp_path / "kiro-cli")
    foreign = {"command": "other", "args": []}
    picked = {"default_mode": "accept_edits", "default_model": "fast", "favorite_models": ["fast"]}
    try:
        for name in ("DefenseClaw · Kiro", "My Kiro"):
            if name == "My Kiro":
                _adopt_my_kiro(app, settings, guard, {"command": agent, "args": ["acp"]}, foreign)
            else:
                settings.write_text(json.dumps({"agent_servers": {"Foreign": foreign}}))
                assert CliRunner().invoke(acp_cmd, _setup_args(guard, agent), obj=app).exit_code == 0
            document = json.loads(settings.read_text())
            document["agent_servers"][name].update(picked)
            settings.write_text(json.dumps(document))

            setup = CliRunner().invoke(acp_cmd, _setup_args(guard, agent), obj=app)
            assert setup.exit_code == 0, (name, setup.output)
            assert "Left editor entry" not in setup.output, (name, setup.output)
            servers = json.loads(settings.read_text())["agent_servers"]
            assert set(servers) == {name, "Foreign"}, (name, servers)
            assert servers[name]["command"] == guard and picked.items() <= servers[name].items(), (name, servers)
            verified = CliRunner().invoke(acp_cmd, ["verify"], obj=app)
            assert verified.exit_code == 0, (name, verified.output)
            removed = CliRunner().invoke(acp_cmd, ["remove", "--client", "zed", "--agent", "kiro"], obj=app)
            assert removed.exit_code == 0 and "Left editor entry" not in removed.output, (name, removed.output)
            assert json.loads(settings.read_text())["agent_servers"] == {"Foreign": foreign}, name
    finally:
        cleanup_app(app, db_path, data_dir)


def test_a_direct_entry_that_starts_the_pinned_agent_keeps_verify_red(tmp_path, monkeypatch):
    """A direct entry that starts the pinned agent file is a bypass of the pair (GAP-0496).

    The agent is recognised by the file the lock pins, not only by the catalog
    command: a renamed agent file, a flag before the ACP subcommand or a link
    to the file still starts the agent without the guard. Setup leaves the
    entry as it is; verify and status stay red until it is deleted.
    """
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    settings = _zed_settings(tmp_path)
    settings.parent.mkdir(parents=True)
    guard = _binary(tmp_path / "defenseclaw-acp")
    agent = _binary(tmp_path / "oc-agent")
    link = tmp_path / "oc-link"
    setup_args = ["setup", "--client", "zed", "--agent", "opencode", "--guard-binary", guard, "--agent-binary", agent]
    try:
        settings.write_text(json.dumps({"agent_servers": {"Foreign": {"command": "other"}}}))
        assert CliRunner().invoke(acp_cmd, setup_args, obj=app).exit_code == 0
        assert CliRunner().invoke(acp_cmd, ["verify"], obj=app).exit_code == 0
        clean = json.loads(settings.read_text())
        variants = {
            "renamed": {"command": agent, "args": ["acp"]},
            "flag first": {"command": agent, "args": ["--print-logs", "acp"]},
        }
        if os.name != "nt":
            link.symlink_to(agent)
            variants["link"] = {"command": str(link), "args": ["acp"]}
        for label, direct in variants.items():
            document = copy.deepcopy(clean)
            document["agent_servers"]["My OpenCode"] = direct
            settings.write_text(json.dumps(document))

            verified = CliRunner().invoke(acp_cmd, ["verify"], obj=app)
            assert verified.exit_code != 0, (label, verified.output)
            assert "'My OpenCode' is not DefenseClaw's: it launches opencode without the DefenseClaw guard" in (
                verified.output
            ), (label, verified.output)
            status = json.loads(CliRunner().invoke(acp_cmd, ["status", "--json"], obj=app).output)
            assert status["bindings"]["zed/opencode"]["healthy"] is False, label

            again = CliRunner().invoke(acp_cmd, setup_args, obj=app)
            assert again.exit_code == 0, (label, again.output)
            assert json.loads(settings.read_text())["agent_servers"]["My OpenCode"] == direct, label
            assert "Left editor entry 'My OpenCode'" in again.output, (label, again.output)
            assert CliRunner().invoke(acp_cmd, ["verify"], obj=app).exit_code != 0, label

        # Control: another agent's file and the entry deleted are not this pair's bypass.
        document = copy.deepcopy(clean)
        document["agent_servers"]["Other agent"] = {"command": _binary(tmp_path / "other-agent"), "args": ["acp"]}
        settings.write_text(json.dumps(document))
        assert CliRunner().invoke(acp_cmd, ["verify"], obj=app).exit_code == 0
        settings.write_text(json.dumps(clean))
        assert CliRunner().invoke(acp_cmd, ["verify"], obj=app).exit_code == 0
    finally:
        cleanup_app(app, db_path, data_dir)


_NPM_SHIM = (
    "@ECHO off\r\nGOTO start\r\n:find_dp0\r\nSET dp0=%~dp0\r\nEXIT /b\r\n:start\r\nSETLOCAL\r\nCALL :find_dp0\r\n"
    '"%dp0%\\node_modules\\opencode-ai\\bin\\opencode.exe"   %*\r\n'
)


def test_a_direct_entry_that_starts_the_file_a_pinned_shim_wraps_or_a_copy_keeps_verify_red(tmp_path, monkeypatch):
    """On Windows the lock pins npm's opencode.cmd; the opencode.exe it starts is the same agent (GAP-0496).

    A direct entry that starts the wrapped executable (with a flag before the
    ACP subcommand) or a byte-identical copy of it under another name runs the
    agent without the guard, so verify and status stay red and setup leaves
    it. A file of the same size with other bytes and a copied shim that starts
    nothing are not this pair's bypass.
    """
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    settings = _zed_settings(tmp_path)
    settings.parent.mkdir(parents=True)
    guard = _binary(tmp_path / "defenseclaw-acp")
    npm = tmp_path / "npm"
    native = npm / "node_modules" / "opencode-ai" / "bin" / "opencode.exe"
    native.parent.mkdir(parents=True)
    native.write_bytes(b"opencode-native-image")
    shim = npm / "opencode.cmd"
    shim.write_text(_NPM_SHIM, newline="")
    copied = tmp_path / "proj" / "oc-agent.exe"
    copied.parent.mkdir()
    copied.write_bytes(native.read_bytes())
    lookalike = tmp_path / "proj" / "same-size.exe"
    lookalike.write_bytes(b"x" * len(native.read_bytes()))
    stray_shim = tmp_path / "proj" / "opencode.cmd"
    stray_shim.write_text(_NPM_SHIM, newline="")
    setup_args = ["setup", "--client", "zed", "--agent", "opencode", "--guard-binary", guard, "--agent-binary", str(shim)]
    try:
        settings.write_text(json.dumps({"agent_servers": {}}))
        assert CliRunner().invoke(acp_cmd, setup_args, obj=app).exit_code == 0
        assert CliRunner().invoke(acp_cmd, ["verify"], obj=app).exit_code == 0
        clean = json.loads(settings.read_text())
        variants = {
            "wrapped executable, flag first": {"command": str(native), "args": ["--print-logs", "acp"]},
            "renamed copy": {"command": str(copied), "args": ["acp"]},
        }
        for label, direct in variants.items():
            document = copy.deepcopy(clean)
            document["agent_servers"]["My OpenCode"] = direct
            settings.write_text(json.dumps(document))

            verified = CliRunner().invoke(acp_cmd, ["verify"], obj=app)
            assert verified.exit_code != 0, (label, verified.output)
            assert "'My OpenCode' is not DefenseClaw's: it launches opencode without the DefenseClaw guard" in (
                verified.output
            ), (label, verified.output)
            status = json.loads(CliRunner().invoke(acp_cmd, ["status", "--json"], obj=app).output)
            assert status["bindings"]["zed/opencode"]["healthy"] is False, label

            again = CliRunner().invoke(acp_cmd, setup_args, obj=app)
            assert again.exit_code == 0, (label, again.output)
            assert json.loads(settings.read_text())["agent_servers"]["My OpenCode"] == direct, label
            assert "Left editor entry 'My OpenCode'" in again.output, (label, again.output)

        for label, other in {
            "same size, other bytes": {"command": str(lookalike), "args": ["acp"]},
            "copied shim that starts nothing": {"command": str(stray_shim), "args": ["acp"]},
        }.items():
            document = copy.deepcopy(clean)
            document["agent_servers"]["Other"] = other
            settings.write_text(json.dumps(document))
            assert CliRunner().invoke(acp_cmd, ["verify"], obj=app).exit_code == 0, label
        settings.write_text(json.dumps(clean))
        assert CliRunner().invoke(acp_cmd, ["verify"], obj=app).exit_code == 0
    finally:
        cleanup_app(app, db_path, data_dir)


_NODE_SHIM = (
    "@ECHO off\r\nGOTO start\r\n:find_dp0\r\nSET dp0=%~dp0\r\nEXIT /b\r\n:start\r\nSETLOCAL\r\nCALL :find_dp0\r\n\r\n"
    "IF EXIST \"%dp0%\\node.exe\" (\r\n  SET \"_prog=%dp0%\\node.exe\"\r\n) ELSE (\r\n  SET \"_prog=node\"\r\n"
    "  SET PATHEXT=%PATHEXT:;.JS;=;%\r\n)\r\n\r\nendLocal & goto #_undefined_# 2>NUL || title %COMSPEC% & "
    "\"%_prog%\"  \"%dp0%\\node_modules\\{package}\\index.js\" %*\r\n"
)


def test_other_node_agents_beside_a_pinned_node_shim_keep_verify_green(tmp_path, monkeypatch):
    '''The node.exe beside npm's shims (nvm-windows, fnm) is not the pinned agent (GAP-0496 review row).

    The lock pins npm's copilot.cmd, which quotes the shared node.exe before
    the package script it runs. Another node-based agent in the same folder,
    or node.exe running another script, is not this pair's bypass; a second
    shim that runs the same package script still is.
    '''
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    settings = _zed_settings(tmp_path)
    settings.parent.mkdir(parents=True)
    guard = _binary(tmp_path / "defenseclaw-acp")
    prefix = tmp_path / "nodejs"
    prefix.mkdir()
    node = prefix / "node.exe"
    node.write_bytes(b"node-interpreter-image")
    for name, package in (
        ("copilot", "@github\\copilot"),
        ("copilot-alt", "@github\\copilot"),
        ("gemini", "@google\\gemini-cli"),
    ):
        script = prefix.joinpath("node_modules", *package.split("\\"), "index.js")
        script.parent.mkdir(parents=True, exist_ok=True)
        script.write_text("// " + package)
        (prefix / f"{name}.cmd").write_text(_NODE_SHIM.replace("{package}", package), newline="")
    setup_args = [
        "setup", "--client", "zed", "--agent", "copilot", "--guard-binary", guard,
        "--agent-binary", str(prefix / "copilot.cmd"),
    ]
    try:
        settings.write_text(json.dumps({"agent_servers": {}}))
        assert CliRunner().invoke(acp_cmd, setup_args, obj=app).exit_code == 0
        assert CliRunner().invoke(acp_cmd, ["verify"], obj=app).exit_code == 0
        clean = json.loads(settings.read_text())
        for label, other in {
            "another node-based agent": {"command": str(prefix / "gemini.cmd"), "args": ["--experimental-acp"]},
            "node.exe running another script": {"command": str(node), "args": ["other.js"]},
        }.items():
            document = copy.deepcopy(clean)
            document["agent_servers"]["Gemini CLI"] = other
            settings.write_text(json.dumps(document))
            verified = CliRunner().invoke(acp_cmd, ["verify"], obj=app)
            assert verified.exit_code == 0, (label, verified.output)
            status = json.loads(CliRunner().invoke(acp_cmd, ["status", "--json"], obj=app).output)
            assert status["bindings"]["zed/copilot"]["healthy"] is True, label

        document = copy.deepcopy(clean)
        direct = {"command": str(prefix / "copilot-alt.cmd"), "args": ["--acp", "--stdio"]}
        document["agent_servers"]["My Copilot"] = direct
        settings.write_text(json.dumps(document))
        verified = CliRunner().invoke(acp_cmd, ["verify"], obj=app)
        assert verified.exit_code != 0, verified.output
        assert "'My Copilot' is not DefenseClaw's: it launches copilot without the DefenseClaw guard" in (
            verified.output
        )
        settings.write_text(json.dumps(clean))
        assert CliRunner().invoke(acp_cmd, ["verify"], obj=app).exit_code == 0
    finally:
        cleanup_app(app, db_path, data_dir)
