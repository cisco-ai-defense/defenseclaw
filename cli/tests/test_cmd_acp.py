# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner
from defenseclaw.acp_catalog import ACP_AGENT_ENTRY_POINTS
from defenseclaw.commands.cmd_acp import _write_token, acp_cmd
from defenseclaw.config import ACPBinding, ACPProfile

from tests.helpers import cleanup_app, make_app_context


def _binary(path: Path) -> str:
    path.write_bytes(b"test-binary")
    path.chmod(0o700)
    return str(path.resolve())


def _app(tmp_path: Path):
    data = tmp_path / "data"
    data.mkdir()
    return make_app_context(str(data))


def test_catalog_exposes_connector_coverage_and_bridge_inventory():
    result = CliRunner().invoke(acp_cmd, ["catalog"])
    assert result.exit_code == 0, result.output
    catalog = json.loads(result.output)
    assert catalog["protocol"]["release"] == "schema-v1.21.0"
    assert any(
        row["connector_id"] == "codex" and row["acp_support"] == "bridge" for row in catalog["connector_coverage"]
    )
    assert catalog["environment_variables"] == []
    canonical = json.loads((Path(__file__).parents[2] / "internal" / "inventory" / "acp_registry.json").read_text())
    assert catalog == canonical
    assert set(ACP_AGENT_ENTRY_POINTS) == {agent["id"] for agent in catalog["agents"]}
    assert any(agent["id"] == "devin" and agent["kind"] == "native" for agent in catalog["agents"])
    assert any(agent["id"] == "amp" and agent["kind"] == "bridge" for agent in catalog["agents"])


def test_token_secures_parent_directory_before_file_creation(tmp_path):
    with patch("defenseclaw.commands.cmd_acp.make_private_directory") as protect:
        token = _write_token(str(tmp_path))
    protect.assert_called_once_with(tmp_path / "acp")
    assert token.is_file()


def test_zed_setup_defaults_observe_and_preserves_foreign_entries(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    app, data_dir, db_path = _app(tmp_path)
    settings = tmp_path / ".config" / "zed" / "settings.json"
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
    monkeypatch.setenv("HOME", str(tmp_path))
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


def test_setup_rolls_back_client_token_and_lock_when_config_save_fails(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    app, data_dir, db_path = _app(tmp_path)
    guard = _binary(tmp_path / "guard")
    agent = _binary(tmp_path / "kiro-cli")
    settings = tmp_path / ".config" / "zed" / "settings.json"
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
    monkeypatch.setenv("HOME", str(tmp_path))
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
    finally:
        cleanup_app(app, db_path, data_dir)


def test_verify_detects_client_configuration_drift(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
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
        settings = tmp_path / ".config" / "zed" / "settings.json"
        document = json.loads(settings.read_text())
        document["theme"] = "drifted"
        settings.write_text(json.dumps(document))

        result = CliRunner().invoke(acp_cmd, ["verify", "--client", "zed", "--agent", "kiro"], obj=app)
        assert result.exit_code != 0
        assert "client configuration digest has drifted" in result.output
    finally:
        cleanup_app(app, db_path, data_dir)


def test_same_agent_in_two_clients_uses_distinct_contract_locks(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
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
    monkeypatch.setenv("HOME", str(tmp_path))
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
    monkeypatch.setenv("HOME", str(tmp_path))
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
        settings = json.loads((tmp_path / ".config" / "zed" / "settings.json").read_text())
        args = settings["agent_servers"]["DefenseClaw · Kiro"]["args"]
        assert args[args.index("--token-file") + 1] == str(token.resolve())
        lock = runtime_data / "acp" / "zed-kiro.contract-lock.json"
        assert lock.is_file()
        assert json.loads(lock.read_text(encoding="utf-8"))["guard"]["managed_custody"] is True
    finally:
        cleanup_app(app, db_path, data_dir)


def test_managed_setup_rejects_pair_outside_central_policy(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
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
    monkeypatch.setenv("HOME", str(tmp_path))
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
        settings = tmp_path / ".config" / "zed" / "settings.json"
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
