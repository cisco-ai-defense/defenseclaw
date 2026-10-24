# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from functools import lru_cache
from pathlib import Path
from unittest.mock import patch

import defenseclaw.commands.cmd_acp as cmd_acp_module
import pytest
from click.testing import CliRunner
from defenseclaw.acp_catalog import ACP_AGENT_ENTRY_POINTS
from defenseclaw.commands.cmd_acp import _write_token, acp_cmd
from defenseclaw.config import ACPBinding, ACPProfile
from defenseclaw.file_permissions import atomic_write_private_bytes, windows_acl_confidentiality_error

from tests.helpers import cleanup_app, make_app_context


def _binary(path: Path) -> str:
    if "guard" in path.name or "defenseclaw-acp" in path.name:
        if os.name == "nt" and not path.suffix:
            path = path.with_suffix(".exe")
        shutil.copyfile(_built_guard(), path)
    else:
        path.write_bytes(b"test-binary")
    path.chmod(0o700)
    return str(path.resolve())


@lru_cache(maxsize=1)
def _built_guard() -> Path:
    root = Path(__file__).parents[2]
    path = Path(tempfile.mkdtemp(prefix="dc-acp-guard-test-")) / ("defenseclaw-acp.exe" if os.name == "nt" else "defenseclaw-acp")
    subprocess.run(["go", "build", "-o", str(path), "./cmd/defenseclaw-acp"], cwd=root, check=True, capture_output=True)
    return path


def _guard_accepts(entry: dict) -> bool:
    result = subprocess.run(
        [entry["command"], "--check-binding", *entry["args"]],
        stdin=subprocess.DEVNULL, capture_output=True, timeout=15, check=False,
    )
    return result.returncode == 0


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


def test_verify_agrees_with_guard_for_entry_pins_and_agent_file_types(tmp_path, monkeypatch):
    """A valid entry pin starts; an agent symlink does not, even with the same bytes."""
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    guard = _binary(tmp_path / "defenseclaw-acp")
    agent_path = tmp_path / "kiro-cli"
    agent = _binary(agent_path)
    settings = _zed_settings(tmp_path)
    lock_path = Path(data_dir) / "acp" / "zed-kiro.contract-lock.json"
    try:
        setup = CliRunner().invoke(
            acp_cmd,
            ["setup", "--client", "zed", "--agent", "kiro", "--guard-binary", guard, "--agent-binary", agent],
            obj=app,
        )
        assert setup.exit_code == 0, setup.output
        document = json.loads(settings.read_text())
        entry = document["agent_servers"]["DefenseClaw · Kiro"]
        canonical = json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        lock = json.loads(lock_path.read_text())
        lock["client"]["config_sha256"] = "entry-sha256:" + hashlib.sha256(canonical).hexdigest()
        atomic_write_private_bytes(lock_path, json.dumps(lock).encode())

        for case, mutate, accepted in (
            ("entry pin", lambda: None, True),
            ("editor owned field", lambda: entry.__setitem__("default_mode", "acceptEdits"), True),
            ("symlinked agent", lambda: (agent_path.rename(tmp_path / "agent-target"), agent_path.symlink_to(tmp_path / "agent-target")), False),
        ):
            if case == "symlinked agent":
                settings.write_text(json.dumps(document))
            try:
                mutate()
            except OSError:
                if os.name == "nt":  # Windows runners may lack symlink creation privilege.
                    continue
                raise
            if case == "editor owned field":
                settings.write_text(json.dumps(document))
            assert _guard_accepts(entry) is accepted, case
            result = CliRunner().invoke(acp_cmd, ["verify", "--client", "zed", "--agent", "kiro"], obj=app)
            assert (result.exit_code == 0) is accepted, (case, result.output)
    finally:
        cleanup_app(app, db_path, data_dir)


def test_verify_refuses_symlinked_agent_with_identical_bytes(tmp_path, monkeypatch):
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    guard = _binary(tmp_path / "defenseclaw-acp")
    agent_path = tmp_path / "kiro-cli"
    agent = _binary(agent_path)
    try:
        setup = CliRunner().invoke(
            acp_cmd,
            ["setup", "--client", "zed", "--agent", "kiro", "--guard-binary", guard, "--agent-binary", agent],
            obj=app,
        )
        assert setup.exit_code == 0, setup.output
        agent_path.rename(tmp_path / "agent-target")
        try:
            agent_path.symlink_to(tmp_path / "agent-target")
        except OSError:
            if os.name == "nt":  # Symlinks may require a Windows runner privilege.
                pytest.skip("Windows runner cannot create a file symlink")
            raise
        result = CliRunner().invoke(acp_cmd, ["verify", "--client", "zed", "--agent", "kiro"], obj=app)
        assert result.exit_code != 0, result.output
        assert "agent executable" in result.output, result.output
    finally:
        cleanup_app(app, db_path, data_dir)


def test_verify_accepts_an_unchanged_entry_digest_lock(tmp_path, monkeypatch):
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    guard = _binary(tmp_path / "defenseclaw-acp")
    agent = _binary(tmp_path / "kiro-cli")
    settings = _zed_settings(tmp_path)
    lock_path = Path(data_dir) / "acp" / "zed-kiro.contract-lock.json"
    try:
        setup = CliRunner().invoke(
            acp_cmd,
            ["setup", "--client", "zed", "--agent", "kiro", "--guard-binary", guard, "--agent-binary", agent],
            obj=app,
        )
        assert setup.exit_code == 0, setup.output
        entry = json.loads(settings.read_text())["agent_servers"]["DefenseClaw · Kiro"]
        canonical = json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        lock = json.loads(lock_path.read_text())
        lock["client"]["config_sha256"] = "entry-sha256:" + hashlib.sha256(canonical).hexdigest()
        atomic_write_private_bytes(lock_path, json.dumps(lock).encode())
        result = CliRunner().invoke(acp_cmd, ["verify", "--client", "zed", "--agent", "kiro"], obj=app)
        assert result.exit_code == 0, result.output
    finally:
        cleanup_app(app, db_path, data_dir)


def test_verify_accepts_a_binding_pinned_to_a_guard_without_diagnostic_mode(tmp_path, monkeypatch):
    """An upgraded CLI must keep accepting a release guard pinned before --check-binding."""
    from defenseclaw.commands.cmd_doctor import _check_acp_bindings, _DoctorResult

    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    guard = _binary(tmp_path / "defenseclaw-acp")
    agent = _binary(tmp_path / "kiro-cli")
    real_run = subprocess.run
    diagnostic_calls = []

    def old_guard_run(argv, *args, **kwargs):
        if argv[0] == guard and argv[1:] == ["--help"]:
            return subprocess.CompletedProcess(argv, 1, "", "Usage of defenseclaw-acp:\n  -agent string\n  -contract-lock string\n")
        if argv[0] == guard and "--check-binding" in argv:
            diagnostic_calls.append(argv)
            return subprocess.CompletedProcess(argv, 1, "", "flag provided but not defined: -check-binding\n")
        return real_run(argv, *args, **kwargs)

    try:
        result = CliRunner().invoke(
            acp_cmd,
            ["setup", "--client", "zed", "--agent", "kiro", "--guard-binary", guard, "--agent-binary", agent],
            obj=app,
        )
        assert result.exit_code == 0, result.output
        entry = json.loads(_zed_settings(tmp_path).read_text())["agent_servers"]["DefenseClaw · Kiro"]
        assert _guard_accepts(entry)
        with patch("defenseclaw.commands.cmd_acp.subprocess.run", side_effect=old_guard_run):
            verified = CliRunner().invoke(acp_cmd, ["verify", "--client", "zed", "--agent", "kiro"], obj=app)
            status = CliRunner().invoke(acp_cmd, ["status", "--json"], obj=app)
            doctor = _DoctorResult()
            _check_acp_bindings(app.cfg, doctor)
        assert verified.exit_code == 0, verified.output
        assert json.loads(status.output)["bindings"]["zed/kiro"]["healthy"] is True
        assert doctor.checks[0]["status"] == "pass", doctor.checks

        settings = _zed_settings(tmp_path)
        document = json.loads(settings.read_text())
        entry = document["agent_servers"]["DefenseClaw · Kiro"]
        canonical = json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        lock_path = Path(data_dir) / "acp" / "zed-kiro.contract-lock.json"
        lock = json.loads(lock_path.read_text())
        lock["client"]["config_sha256"] = "entry-sha256:" + hashlib.sha256(canonical).hexdigest()
        atomic_write_private_bytes(lock_path, json.dumps(lock).encode())
        entry["default_mode"] = "acceptEdits"
        settings.write_text(json.dumps(document))
        assert _guard_accepts(entry)
        with patch("defenseclaw.commands.cmd_acp.subprocess.run", side_effect=old_guard_run):
            verified = CliRunner().invoke(acp_cmd, ["verify", "--client", "zed", "--agent", "kiro"], obj=app)
        assert verified.exit_code == 0, verified.output

        refused = dict(entry, args=list(entry["args"]))
        refused["args"][refused["args"].index("--profile") + 1] = "watch"
        document["agent_servers"]["Watch copy"] = refused
        settings.write_text(json.dumps(document))
        cmd_acp_module._refresh_client_contract_digests(str(data_dir), "zed", settings)
        assert not _guard_accepts(refused)
        with patch("defenseclaw.commands.cmd_acp.subprocess.run", side_effect=old_guard_run):
            rejected = CliRunner().invoke(acp_cmd, ["verify", "--client", "zed", "--agent", "kiro"], obj=app)
        assert rejected.exit_code != 0 and "'Watch copy' cannot start" in rejected.output, rejected.output
        assert diagnostic_calls == []
    finally:
        cleanup_app(app, db_path, data_dir)


def test_verify_uses_guard_acceptance_for_an_adopted_alias_with_a_custom_guard_name(tmp_path, monkeypatch):
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    settings = _zed_settings(tmp_path)
    settings.parent.mkdir(parents=True)
    guard = _binary(tmp_path / "guard")
    agent = _binary(tmp_path / "kiro-cli")
    settings.write_text(json.dumps({"agent_servers": {"My Kiro": {"command": agent, "args": ["acp"]}}}))
    try:
        adopted = CliRunner().invoke(
            acp_cmd, ["adopt", "--client", "zed", "--guard-binary", guard, "--yes"], obj=app,
        )
        assert adopted.exit_code == 0, adopted.output
        entry = json.loads(settings.read_text())["agent_servers"]["My Kiro"]
        assert _guard_accepts(entry)
        verified = CliRunner().invoke(acp_cmd, ["verify", "--client", "zed", "--agent", "kiro"], obj=app)
        assert verified.exit_code == 0, verified.output
        settings.unlink()
        assert not _guard_accepts(entry)
        missing = CliRunner().invoke(acp_cmd, ["verify", "--client", "zed", "--agent", "kiro"], obj=app)
        assert missing.exit_code != 0
        assert "editor settings file is missing" in missing.output, missing.output
    finally:
        cleanup_app(app, db_path, data_dir)


def test_verify_reports_a_copied_guard_entry_the_guard_refuses(tmp_path, monkeypatch):
    """GAP-0525: the guard sent a refused copy to verify, which said Verified."""
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    settings = _zed_settings(tmp_path)
    suffix = ".exe" if os.name == "nt" else ""
    guard = _binary(tmp_path / f"defenseclaw-acp{suffix}")
    agent = _binary(tmp_path / f"kiro-cli{suffix}")
    setup = ["setup", "--client", "zed", "--agent", "kiro", "--guard-binary", guard, "--agent-binary", agent]
    verify = ["verify", "--client", "zed", "--agent", "kiro"]
    try:
        setup_result = CliRunner().invoke(acp_cmd, setup, obj=app)
        assert setup_result.exit_code == 0, setup_result.output
        document = json.loads(settings.read_text())
        exact = dict(document["agent_servers"]["DefenseClaw · Kiro"])
        args = list(exact["args"])
        args[args.index("--profile") + 1] = "watch"
        document["agent_servers"]["Exact copy"] = exact
        document["agent_servers"]["Watch copy"] = dict(exact, args=args)
        settings.write_text(json.dumps(document))
        assert CliRunner().invoke(acp_cmd, setup, obj=app).exit_code == 0

        result = CliRunner().invoke(acp_cmd, verify, obj=app)
        assert result.exit_code != 0, result.output
        assert "'Watch copy'" in result.output and "'Exact copy'" not in result.output
        assert str(settings) in result.output
    finally:
        cleanup_app(app, db_path, data_dir)


def _flag_removed(args: list[str], flag: str) -> list[str]:
    index = args.index(flag)
    return args[:index] + args[index + 2:]


def _flag_set(args: list[str], flag: str, value: str) -> list[str]:
    return [*args[:args.index(flag) + 1], value, *args[args.index(flag) + 2:]]


def test_verify_rejects_a_contract_lock_the_guard_cannot_open(tmp_path, monkeypatch):
    """GAP-0525: size and platform protection checks apply to owned entries."""
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    suffix = ".exe" if os.name == "nt" else ""
    guard = _binary(tmp_path / f"defenseclaw-acp{suffix}")
    agent = _binary(tmp_path / f"kiro-cli{suffix}")
    setup = ["setup", "--client", "zed", "--agent", "kiro", "--guard-binary", guard, "--agent-binary", agent]
    verify = ["verify", "--client", "zed", "--agent", "kiro"]
    try:
        result = CliRunner().invoke(acp_cmd, setup, obj=app)
        assert result.exit_code == 0, result.output
        assert CliRunner().invoke(acp_cmd, verify, obj=app).exit_code == 0
        lock_path = Path(data_dir) / "acp" / "zed-kiro.contract-lock.json"
        original = lock_path.read_bytes()
        lock_path.write_bytes(original + b" " * (65537 - len(original)))
        result = CliRunner().invoke(acp_cmd, verify, obj=app)
        assert result.exit_code != 0, result.output
        assert "contract lock is missing or unsafe" in result.output
        lock_path.write_bytes(original)

        if os.name == "nt":
            subprocess.run(
                ["icacls", str(lock_path), "/grant", "*S-1-1-0:(RA)"], check=True, capture_output=True, text=True
            )
            assert windows_acl_confidentiality_error(lock_path) is None
            expected = "contract lock protection is unsafe"
        else:
            lock_path.chmod(0o644)
            expected = "contract lock permissions are too broad"
        result = CliRunner().invoke(acp_cmd, verify, obj=app)
        assert result.exit_code != 0, result.output
        assert expected in result.output
    finally:
        cleanup_app(app, db_path, data_dir)


def test_verify_rejects_guard_refused_metadata_in_an_adopted_lock(tmp_path, monkeypatch):
    """An adopted alias is unhealthy whenever its lock cannot pass the guard."""
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    settings = _zed_settings(tmp_path)
    settings.parent.mkdir(parents=True)
    suffix = ".exe" if os.name == "nt" else ""
    guard = _binary(tmp_path / f"defenseclaw-acp{suffix}")
    agent = _binary(tmp_path / f"kiro-cli{suffix}")
    settings.write_text(json.dumps({"agent_servers": {"My Kiro": {"command": agent, "args": ["acp"]}}}))
    verify = ["verify", "--client", "zed", "--agent", "kiro"]
    try:
        adopted = CliRunner().invoke(
            acp_cmd, ["adopt", "--client", "zed", "--guard-binary", guard, "--yes"], obj=app
        )
        assert adopted.exit_code == 0, adopted.output
        assert list(json.loads(settings.read_text())["agent_servers"]) == ["My Kiro"]
        entry = json.loads(settings.read_text())["agent_servers"]["My Kiro"]
        assert CliRunner().invoke(acp_cmd, verify, obj=app).exit_code == 0
        lock_path = Path(data_dir) / "acp" / "zed-kiro.contract-lock.json"
        original = json.loads(lock_path.read_text())

        def set_field(value, *keys):
            def change(lock):
                target = lock
                for key in keys[:-1]:
                    target = target[key]
                target[keys[-1]] = value
            return change

        cases = {
            "stale schema digest": (set_field("f" * 64, "protocol", "schema_sha256"), "runtime contract metadata"),
            "stale schema version": (set_field("schema-v0", "protocol", "schema_version"), "runtime contract metadata"),
            "wrong lock version": (set_field(2, "version"), "malformed or incomplete"),
            "boolean lock version": (set_field(True, "version"), "malformed or incomplete"),
            "unexpected field": (set_field("unexpected", "protocol", "extra"), "malformed or incomplete"),
            "wrong decoded field type": (set_field(12, "agent", "version"), "malformed or incomplete"),
            "missing pin": (lambda lock: lock["protocol"].pop("schema_sha256"), "malformed or incomplete"),
        }
        for label, (mutate, expected) in cases.items():
            lock = json.loads(json.dumps(original))
            mutate(lock)
            atomic_write_private_bytes(lock_path, json.dumps(lock).encode())
            assert not _guard_accepts(entry), label
            result = CliRunner().invoke(acp_cmd, verify, obj=app)
            assert result.exit_code != 0, (label, result.output)
            assert expected in result.output, (label, result.output)
            repair_prefix = "defenseclaw 'acp' 'setup'" if os.name == "nt" else "defenseclaw acp setup"
            assert f"run {repair_prefix}" in result.output, (label, result.output)
            if label == "stale schema digest":
                status = CliRunner().invoke(acp_cmd, ["status", "--json"], obj=app)
                assert status.exit_code == 0, status.output
                binding = json.loads(status.output)["bindings"]["zed/kiro"]
                assert binding["healthy"] is False
                assert any("runtime contract metadata" in problem for problem in binding["problems"])

        # Go's lock decoder treats null optional fields as their zero values.
        # The guard starts this adopted entry, so verify must accept it too.
        for keys in (("generated_at",), ("agent", "version"), ("guard", "managed_custody"),
                     ("client", "adopted_entries")):
            lock = json.loads(json.dumps(original))
            target = lock
            for key in keys[:-1]:
                target = target[key]
            target[keys[-1]] = None
            atomic_write_private_bytes(lock_path, json.dumps(lock).encode())
            assert _guard_accepts(entry), keys
            result = CliRunner().invoke(acp_cmd, verify, obj=app)
            assert result.exit_code == 0, (keys, result.output)
        serialized = json.dumps(original)
        for label, body in {
            "invalid first version": '{"version": "invalid", ' + serialized[1:],
            "unknown first protocol field": '{"protocol": {"extra": 1}, ' + serialized[1:],
        }.items():
            # Go decodes each occurrence, while Python normally keeps only
            # the last value. Both malformed first occurrences refuse start.
            atomic_write_private_bytes(lock_path, body.encode())
            result = CliRunner().invoke(acp_cmd, verify, obj=app)
            assert result.exit_code != 0, (label, result.output)
            assert "contract lock is unreadable" in result.output, (label, result.output)
        atomic_write_private_bytes(lock_path, json.dumps(original).encode())
        assert CliRunner().invoke(acp_cmd, verify, obj=app).exit_code == 0
    finally:
        cleanup_app(app, db_path, data_dir)


def test_verify_checks_copied_guard_entries_by_the_guards_rules(tmp_path, monkeypatch):
    """GAP-0525: verify reports exactly the copies the guard refuses.

    The guard defaults --client, --profile and --mode, compares paths after
    making them absolute (ignoring case on Windows), checks --token-file and
    --gateway, and falls back to the catalog command without --. A copy is
    this lock's when its --contract-lock is the same file, whatever its
    --client or --agent.
    """
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    settings = _zed_settings(tmp_path)
    suffix = ".exe" if os.name == "nt" else ""
    guard = _binary(tmp_path / f"defenseclaw-acp{suffix}")
    agent = _binary(tmp_path / f"kiro-cli{suffix}")
    setup = ["setup", "--client", "zed", "--agent", "kiro", "--guard-binary", guard, "--agent-binary", agent]
    verify = ["verify", "--client", "zed", "--agent", "kiro"]
    try:
        setup_result = CliRunner().invoke(acp_cmd, setup, obj=app)
        assert setup_result.exit_code == 0, setup_result.output
        exact = json.loads(settings.read_text())["agent_servers"]["DefenseClaw · Kiro"]
        args = list(exact["args"])
        lock = args[args.index("--contract-lock") + 1]
        linked = tmp_path / "linked"
        if os.name != "nt":
            linked.symlink_to(Path(lock).parent, target_is_directory=True)
        else:
            try:
                linked.symlink_to(Path(lock).parent, target_is_directory=True)
            except (OSError, NotImplementedError):
                # Windows CI can run without the symlink creation privilege.
                linked = None
        if os.name != "nt":
            (tmp_path / "loose.token").write_text("test token\n")
            (tmp_path / "loose.token").chmod(0o644)
        (tmp_path / "empty.token").write_text("\n")
        (tmp_path / "empty.token").chmod(0o600)
        starts = {
            "Defaults": _flag_removed(_flag_removed(args, "--profile"), "--mode"),
            "Equals form": [
                *_flag_removed(args, "--profile")[:args.index("--profile")], "-profile=default",
                *_flag_removed(args, "--profile")[args.index("--profile"):],
            ],
            "IPv6 gateway": _flag_set(args, "--gateway", "http://[::1]:18970/api/v1/acp/evaluate"),
            "Mapped gateway": _flag_set(args, "--gateway", "http://[::ffff:127.0.0.1]:18970/api/v1/acp/evaluate"),
        }
        refused = {
            "Other agent": _flag_set(args, "--agent", "cursor"),
            "No client": _flag_removed(args, "--client"),
            "Catalog fallback": args[:args.index("--")],
            "No token": _flag_removed(args, "--token-file"),
            "Missing token": _flag_set(args, "--token-file", str(tmp_path / "missing.token")),
            "Empty token": _flag_set(args, "--token-file", str(tmp_path / "empty.token")),
            "HTTPS gateway": _flag_set(args, "--gateway", "https://127.0.0.1:18970/api/v1/acp/evaluate"),
            "Hostname gateway": _flag_set(args, "--gateway", "http://localhost:18970/api/v1/acp/evaluate"),
            "Remote gateway": _flag_set(args, "--gateway", "http://192.0.2.1/api/v1/acp/evaluate"),
            "Userinfo gateway": _flag_set(args, "--gateway", "http://user@127.0.0.1:18970/api/v1/acp/evaluate"),
            "Query gateway": _flag_set(args, "--gateway", "http://127.0.0.1:18970/api/v1/acp/evaluate?x=1"),
            "Fragment gateway": _flag_set(args, "--gateway", "http://127.0.0.1:18970/api/v1/acp/evaluate#x"),
            "Scoped gateway": _flag_set(args, "--gateway", "http://[::1%25zone]:18970/api/v1/acp/evaluate"),
            "Bad port gateway": _flag_set(args, "--gateway", "http://127.0.0.1:bad/api/v1/acp/evaluate"),
            "Control gateway": _flag_set(args, "--gateway", "http://127.0.0.1/api/v1/acp/evaluate\x7f"),
            "Bad escape gateway": _flag_set(args, "--gateway", "http://127.0.0.1/api/v1/acp/%zz"),
            "Untrimmed control gateway": _flag_set(args, "--gateway", "http://127.0.0.1/api/v1/acp/evaluate\x1c"),
            "Unknown flag": ["--sandbox", "on", *args],
            "Unparsed lock": ["kiro-cli", "--contract-lock", lock],
        }
        if os.name != "nt":
            refused["Loose token"] = _flag_set(args, "--token-file", str(tmp_path / "loose.token"))
        whitespace_token = Path(data_dir) / "acp" / "whitespace.token"
        atomic_write_private_bytes(whitespace_token, "\u00a0".encode())
        refused["Unicode whitespace token"] = _flag_set(args, "--token-file", str(whitespace_token))
        separator_token = Path(data_dir) / "acp" / "separator.token"
        atomic_write_private_bytes(separator_token, b"\x1c")
        starts["Non Unicode separator token"] = _flag_set(args, "--token-file", str(separator_token))
        if linked is not None:
            refused["Linked lock"] = _flag_set(
                _flag_set(args, "--contract-lock", str(linked / Path(lock).name)), "--profile", "watch"
            )
            if os.name == "nt":
                refused["Reparse lock"] = _flag_set(args, "--contract-lock", str(linked / Path(lock).name))
        if os.name == "nt":
            acl_token = Path(data_dir) / "acp" / "acl.token"
            atomic_write_private_bytes(acl_token, b"test token\n")
            assert windows_acl_confidentiality_error(acl_token) is None
            subprocess.run(
                ["icacls", str(acl_token), "/grant", "*S-1-1-0:(R)"], check=True, capture_output=True, text=True
            )
            assert windows_acl_confidentiality_error(acl_token) is not None
            refused["Readable token"] = _flag_set(args, "--token-file", str(acl_token))
            metadata_token = Path(data_dir) / "acp" / "metadata.token"
            atomic_write_private_bytes(metadata_token, b"test token\n")
            subprocess.run(
                ["icacls", str(metadata_token), "/grant", "*S-1-1-0:(RA)"], check=True, capture_output=True, text=True
            )
            assert windows_acl_confidentiality_error(metadata_token) is None
            refused["Metadata token"] = _flag_set(args, "--token-file", str(metadata_token))
        document = json.loads(settings.read_text())
        for name, copy_args in {**starts, **refused}.items():
            entry = dict(exact, args=copy_args)
            assert _guard_accepts(entry) is (name in starts), name
            document["agent_servers"][name] = entry
        settings.write_text(json.dumps(document))
        cmd_acp_module._refresh_client_contract_digests(str(data_dir), "zed", settings)

        result = CliRunner().invoke(acp_cmd, verify, obj=app)
        assert result.exit_code != 0, result.output
        for name in starts:
            assert f"{name!r}" not in result.output, (name, result.output)
        for name in refused:
            assert f"{name!r} cannot start" in result.output, (name, result.output)

        # Only the refused copies fail it: without them verify passes.
        document = json.loads(settings.read_text())
        for name in refused:
            del document["agent_servers"][name]
        settings.write_text(json.dumps(document))
        assert CliRunner().invoke(acp_cmd, setup, obj=app).exit_code == 0
        result = CliRunner().invoke(acp_cmd, verify, obj=app)
        assert result.exit_code == 0, result.output
    finally:
        cleanup_app(app, db_path, data_dir)


def test_copied_entry_paths_compare_like_the_guard(monkeypatch):
    """GAP-0525: on Windows the guard ignores case and separators in paths."""
    upper, lower = "/Users/Me/Bin/kiro-cli", "/users/me/bin/kiro-cli"
    monkeypatch.setattr(cmd_acp_module, "_GUARD_PATHS_FOLD_CASE", False)
    assert not cmd_acp_module._same_guard_path(upper, lower)
    monkeypatch.setattr(cmd_acp_module, "_GUARD_PATHS_FOLD_CASE", True)
    assert cmd_acp_module._same_guard_path(upper, lower)
    assert cmd_acp_module._same_guard_path(r"C:\Users\Me\kiro-cli.exe", "c:/users/me/./KIRO-CLI.exe")


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
        setup_prefix = (
            "defenseclaw 'acp' 'setup' '--client' 'zed' '--agent' 'kiro' '--profile' 'default'"
            if os.name == "nt" else "defenseclaw acp setup --client zed --agent kiro --profile default"
        )
        assert row["remediation"].startswith(setup_prefix)
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
        # A copied guarded entry with stale metadata must also be checked.
        # Under the reserved name it is DefenseClaw's, and verify reports its
        # launch. Under another name it no longer matches the lock, so it is
        # not this runtime's alias: removal would leave it with a warning,
        # and verify reports that the guard refuses it (GAP-0525).
        stale = dict(servers["Kiro"], args=list(servers["Kiro"]["args"]))
        stale["args"][stale["args"].index("--profile") + 1] = "default"
        for name in ("DefenseClaw · Kiro", "Stale"):
            settings.write_text(json.dumps({"agent_servers": {**servers, name: stale}}))
            cmd_acp_module._refresh_client_contract_digests(str(data_dir), "zed", settings)
            verified = CliRunner().invoke(acp_cmd, ["verify", "--client", "zed", "--agent", "kiro"], obj=app)
            problems = cmd_acp_module._verify_binding(str(data_dir), "zed", "kiro", app.cfg.acp)
            if name == "Stale":
                assert verified.exit_code != 0 and "'Stale' cannot start" in verified.output, verified.output
                assert cmd_acp_module._unproven_pair_entries("zed", "kiro", str(data_dir)) == ["Stale"]
            else:
                assert verified.exit_code != 0, verified.output
                assert any(f"editor entry {name!r} cannot start" in problem for problem in problems), problems
        settings.write_text(json.dumps({"agent_servers": servers}))
        cmd_acp_module._refresh_client_contract_digests(str(data_dir), "zed", settings)

        # Re-running finds nothing to adopt rather than double-wrapping.
        again = CliRunner().invoke(acp_cmd, ["adopt", "--client", "zed", "--yes", "--json-output"], obj=app)
        assert again.exit_code == 0, again.output
        assert json.loads(again.output)["adopted"] == []
        removed = CliRunner().invoke(acp_cmd, ["remove", "--client", "zed", "--agent", "kiro"], obj=app)
        assert removed.exit_code == 0, removed.output
        assert json.loads(settings.read_text())["agent_servers"] == {"Foreign": {"command": "other", "args": []}}
        collision = {"agent_servers": {"DefenseClaw · Kiro": {"command": "other", "args": []}}}
        settings.write_text(json.dumps(collision))
        before = settings.read_bytes()
        for command in (
            ["setup", "--client", "zed", "--agent", "kiro", "--guard-binary", guard, "--agent-binary", agent],
            ["remove", "--client", "zed", "--agent", "kiro"],
        ):
            refused = CliRunner().invoke(acp_cmd, command, obj=app)
            assert refused.exit_code != 0, refused.output
            assert "rename that entry" in refused.output
            assert settings.read_bytes() == before
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

        old_sha = hashlib.sha256(Path(guard).read_bytes()).hexdigest()
        Path(guard).write_bytes(Path(guard).read_bytes() + b"upgraded-guard")
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
        Path(guard).write_bytes(Path(guard).read_bytes() + b"source-build-guard")
        other = tmp_path / "other" / "defenseclaw-acp"
        other.parent.mkdir()
        _binary(other)
        assert CliRunner().invoke(acp_cmd, ["refresh", "--guard-path", str(other)], obj=app).output == ""
        result = CliRunner().invoke(acp_cmd, ["refresh", "--guard-path", guard], obj=app)
        assert "Re-pinned the DefenseClaw ACP guard for zed/kiro" in result.output

        Path(guard).write_bytes(Path(guard).read_bytes() + b"upgraded-guard")
        agent_path.write_bytes(b"updated-agent")
        tag, plan = _fix_acp_guard_pins(app.cfg, assume_yes=True, plan_only=True)
        setup_prefix = (
            "defenseclaw 'acp' 'setup' '--client' 'zed' '--agent' 'kiro'"
            if os.name == "nt" else "defenseclaw acp setup --client zed --agent kiro"
        )
        assert tag == "plan" and "zed/kiro" in plan and setup_prefix in plan
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
            status = json.loads(CliRunner().invoke(acp_cmd, ["status", "--json"], obj=app).output)
            binding = status["bindings"]["zed/kiro"]
            if label == "other runtime token":
                # It names this runtime's lock, which setup rewrote in action
                # mode, so the guard refuses it and status says so (GAP-0525).
                assert ["'Other Kiro' cannot start" in p for p in binding["problems"]] == [True], (label, status)
            else:
                assert binding["healthy"], (label, status)
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


def test_alias_backed_by_an_unusable_lock_is_not_owned(tmp_path, monkeypatch):
    """Only the canonical, complete, private lock setup writes proves an alias.

    Each variant names this runtime's lock and token and pins the same guard
    and editor file, but the guard could not start from that lock (or the
    entry reaches it by another path). Removal must leave the alias and the
    settings file byte for byte, warn about it, and status must still answer.
    """
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    settings = _zed_settings(tmp_path)
    settings.parent.mkdir(parents=True)
    guard = _binary(tmp_path / "defenseclaw-acp")
    agent = _binary(tmp_path / "kiro-cli")
    runtime = (Path(data_dir) / "acp").resolve()
    lock = runtime / "zed-kiro.contract-lock.json"
    token = str(runtime / ".token")

    def write_lock(mutate=None) -> None:
        settings.write_text("{}")
        cmd_acp_module._write_contract_lock(
            data_dir=data_dir, client="zed", agent="kiro", profile="default", mode="observe",
            guard=guard, agent_executable=agent, client_path=settings.resolve(), managed=False,
        )
        if mutate:
            document = json.loads(lock.read_text())
            mutate(document)
            cmd_acp_module.atomic_write_private_bytes(lock, json.dumps(document).encode())

    def alias(lock_value: str, token_value: str = token) -> dict:
        return {"command": guard, "args": [
            "--agent", "kiro", "--client", "zed", "--profile", "default", "--mode", "observe",
            "--token-file", token_value, "--gateway", "http://127.0.0.1:1/api/v1/acp/evaluate",
            "--contract-lock", lock_value, "--", agent, "acp",
        ]}

    def drop(*keys):
        def mutate(document):
            item = document
            for key in keys[:-1]:
                item = item[key]
            del item[keys[-1]]
        return mutate

    def setter(value, *keys):
        def mutate(document):
            item = document
            for key in keys[:-1]:
                item = item[key]
            item[keys[-1]] = value
        return mutate

    variants: dict[str, tuple] = {
        # The path resolves to this lock but is not the path setup writes.
        "dot-dot path": (None, str(runtime / ".." / "acp" / lock.name)),
        "dot-dot token": (None, str(lock), str(runtime / ".." / "acp" / ".token")),
        # Structurally incomplete or wrong-typed locks the guard refuses.
        "no protocol": (drop("protocol"), str(lock)),
        "empty schema pin": (setter("", "protocol", "schema_sha256"), str(lock)),
        "no editor digest": (drop("client", "config_sha256"), str(lock)),
        "no guard digest": (drop("guard", "sha256"), str(lock)),
        "no agent path": (drop("agent", "path"), str(lock)),
        "no mode": (drop("mode"), str(lock)),
        "version 2": (setter(2, "version"), str(lock)),
        "boolean version": (setter(True, "version"), str(lock)),
        "custody not a flag": (setter(0, "guard", "managed_custody"), str(lock)),
        "adopted not a list": (setter("Other Kiro", "client", "adopted_entries"), str(lock)),
    }
    other = tmp_path / "other-runtime" / "acp"
    other.mkdir(parents=True)
    try:
        (other / lock.name).symlink_to(lock)
        # Another runtime's lock path is a symlink to this runtime's lock.
        variants["symlink from another runtime"] = (None, str(other / lock.name))
    except OSError:  # pragma: no cover - Windows without symlink privilege
        pass
    if os.name != "nt":
        # Readable by others: the guard refuses any group or other bit.
        variants["group-readable lock"] = (lambda document: None, str(lock))
    try:
        for label, (mutate, lock_value, *token_value) in variants.items():
            write_lock(mutate)
            if label == "group-readable lock":
                lock.chmod(0o640)
            entry = alias(lock_value, *token_value)
            settings.write_text(json.dumps({"agent_servers": {"Other Kiro": entry}}))
            before = settings.read_bytes()
            status = CliRunner().invoke(acp_cmd, ["status", "--json"], obj=app)
            assert status.exit_code == 0, (label, status.output)
            json.loads(status.output)
            removed = CliRunner().invoke(acp_cmd, ["remove", "--client", "zed", "--agent", "kiro"], obj=app)
            assert removed.exit_code == 0, (label, removed.output)
            assert settings.read_bytes() == before, label
            assert "Left editor entry 'Other Kiro'" in removed.output, (label, removed.output)

        # Control: the same alias with the canonical, complete, private lock
        # is this runtime's, and removal deletes it (and the file it alone used).
        write_lock()
        settings.write_text(json.dumps({"agent_servers": {"Other Kiro": alias(str(lock))}}))
        removed = CliRunner().invoke(acp_cmd, ["remove", "--client", "zed", "--agent", "kiro"], obj=app)
        assert removed.exit_code == 0, removed.output
        assert "Left editor entry" not in removed.output
        assert not settings.exists()
    finally:
        cleanup_app(app, db_path, data_dir)


def test_setup_reroutes_only_entries_a_proven_lock_names(tmp_path, monkeypatch):
    """An incomplete lock's adopted_entries must not let setup take over an operator entry."""
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    settings = _zed_settings(tmp_path)
    settings.parent.mkdir(parents=True)
    guard = _binary(tmp_path / "defenseclaw-acp")
    agent = _binary(tmp_path / "kiro-cli")
    lock = (Path(data_dir) / "acp").resolve() / "zed-kiro.contract-lock.json"
    direct = {"command": agent, "args": ["acp"]}
    try:
        settings.write_text("{}")
        cmd_acp_module._write_contract_lock(
            data_dir=data_dir, client="zed", agent="kiro", profile="default", mode="observe",
            guard=guard, agent_executable=agent, client_path=settings.resolve(), managed=False,
            adopted_entries=["My Kiro"],
        )
        document = json.loads(lock.read_text())
        del document["protocol"]
        cmd_acp_module.atomic_write_private_bytes(lock, json.dumps(document).encode())
        settings.write_text(json.dumps({"agent_servers": {"My Kiro": direct}}))
        setup = CliRunner().invoke(
            acp_cmd,
            ["setup", "--client", "zed", "--agent", "kiro", "--guard-binary", guard, "--agent-binary", agent],
            obj=app,
        )
        assert setup.exit_code == 0, setup.output
        servers = json.loads(settings.read_text())["agent_servers"]
        assert servers["My Kiro"] == direct
        assert servers["DefenseClaw · Kiro"]["command"] == guard
    finally:
        cleanup_app(app, db_path, data_dir)



def _go_lock_fields() -> dict[str, frozenset[str]]:
    """The JSON fields of the guard's RuntimeContractLock, per object."""
    source = (Path(__file__).parents[2] / "internal" / "acp" / "contract.go").read_text(encoding="utf-8")
    body = source.split("type RuntimeContractLock struct {", 1)[1].split("\n}\n", 1)[0]
    fields: dict[str, frozenset[str]] = {}
    stack: list[set[str]] = [set()]
    for line in body.splitlines():
        stripped = line.strip()
        tag = re.search(r'`json:"([^",]+)', stripped)
        if stripped.endswith("struct {"):
            stack.append(set())
        elif stripped.startswith("}") and tag:
            fields[tag.group(1)] = frozenset(stack.pop())
            stack[-1].add(tag.group(1))
        elif tag:
            stack[-1].add(tag.group(1))
    fields[""] = frozenset(stack[0])
    return fields


def test_ownership_proof_knows_exactly_the_guard_lock_fields():
    """Python's lock proof and the guard's strict decoder must agree on every field."""
    assert cmd_acp_module._LOCK_FIELDS == _go_lock_fields()


def test_lock_with_a_field_the_guard_refuses_proves_nothing(tmp_path, monkeypatch):
    """A lock the guard rejects for an unknown field, at any level, owns no entry.

    Setup must not take over the operator's direct entry such a lock names in
    adopted_entries, and removal must leave a guard alias that names it and
    warn. A lock with an older protocol pin is still this runtime's lock.
    """
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    settings = _zed_settings(tmp_path)
    settings.parent.mkdir(parents=True)
    guard = _binary(tmp_path / "defenseclaw-acp")
    agent = _binary(tmp_path / "kiro-cli")
    runtime = (Path(data_dir) / "acp").resolve()
    lock = runtime / "zed-kiro.contract-lock.json"
    direct = {"command": agent, "args": ["acp"]}
    alias = {"command": guard, "args": [
        "--agent", "kiro", "--client", "zed", "--profile", "default", "--mode", "observe",
        "--token-file", str(runtime / ".token"), "--gateway", "http://127.0.0.1:1/api/v1/acp/evaluate",
        "--contract-lock", str(lock), "--", agent, "acp",
    ]}

    def write_lock(*keys: str, value: object = "x") -> None:
        settings.write_text("{}")
        cmd_acp_module._write_contract_lock(
            data_dir=data_dir, client="zed", agent="kiro", profile="default", mode="observe",
            guard=guard, agent_executable=agent, client_path=settings.resolve(), managed=False,
            adopted_entries=["My Kiro", "Other Kiro"],
        )
        if keys:
            document = json.loads(lock.read_text())
            item = document
            for key in keys[:-1]:
                item = item[key]
            item[keys[-1]] = value
            cmd_acp_module.atomic_write_private_bytes(lock, json.dumps(document).encode())

    setup_args = ["setup", "--client", "zed", "--agent", "kiro", "--guard-binary", guard, "--agent-binary", agent]
    remove_args = ["remove", "--client", "zed", "--agent", "kiro"]
    try:
        for keys in (("extra",), ("protocol", "extra"), ("client", "extra"), ("agent", "extra"), ("guard", "extra")):
            write_lock(*keys)
            settings.write_text(json.dumps({"agent_servers": {"My Kiro": direct}}))
            setup = CliRunner().invoke(acp_cmd, setup_args, obj=app)
            assert setup.exit_code == 0, (keys, setup.output)
            servers = json.loads(settings.read_text())["agent_servers"]
            assert servers["My Kiro"] == direct, keys
            assert servers["DefenseClaw · Kiro"]["command"] == guard, keys

            write_lock(*keys)
            settings.write_text(json.dumps({"agent_servers": {"Other Kiro": alias}}))
            before = settings.read_bytes()
            removed = CliRunner().invoke(acp_cmd, remove_args, obj=app)
            assert removed.exit_code == 0, (keys, removed.output)
            assert settings.read_bytes() == before, keys
            assert "Left editor entry 'Other Kiro'" in removed.output, (keys, removed.output)

        # Control: an older protocol pin (a lock from before an upgrade, until
        # acp refresh) still proves the alias, and removal deletes it.
        write_lock("protocol", "schema_version", value="schema-v1.0.0")
        settings.write_text(json.dumps({"agent_servers": {"Other Kiro": alias}}))
        removed = CliRunner().invoke(acp_cmd, remove_args, obj=app)
        assert removed.exit_code == 0, removed.output
        assert "Left editor entry" not in removed.output
        assert not settings.exists()
    finally:
        cleanup_app(app, db_path, data_dir)


def test_alias_launching_other_than_the_locked_agent_is_not_owned(tmp_path, monkeypatch):
    """This runtime's valid lock, token and guard do not prove an alias that launches something else.

    Setup writes exactly its guard options, then -- and the locked agent
    executable with the catalog arguments. An alias that differs (another
    executable or path after --, other or no arguments, another profile or
    mode, an unknown or missing option) is not what setup wrote: removal
    leaves it and its settings file byte for byte and warns, and setup does
    not rewrite it.
    """
    _isolate_client_config(monkeypatch, tmp_path)
    app, data_dir, db_path = _app(tmp_path)
    settings = _zed_settings(tmp_path)
    settings.parent.mkdir(parents=True)
    guard = _binary(tmp_path / "defenseclaw-acp")
    agent = _binary(tmp_path / "kiro-cli")
    other_agent = _binary(tmp_path / "other-agent")
    (tmp_path / "sub").mkdir()
    runtime = (Path(data_dir) / "acp").resolve()
    lock = runtime / "zed-kiro.contract-lock.json"
    base = {
        "--agent": "kiro", "--client": "zed", "--profile": "default", "--mode": "observe",
        "--token-file": str(runtime / ".token"), "--gateway": "http://127.0.0.1:1/api/v1/acp/evaluate",
        "--contract-lock": str(lock),
    }

    def alias(tail=(agent, "acp"), drop=(), **changes) -> dict:
        options = {**base, **{f"--{key.replace('_', '-')}": value for key, value in changes.items()}}
        for key in drop:
            del options[key]
        return {"command": guard, "args": [*(item for pair in options.items() for item in pair), "--", *tail]}

    variants = {
        "another executable": alias(tail=(other_agent, "acp")),
        "same file by another path": alias(tail=(str(tmp_path / "sub" / ".." / "kiro-cli"), "acp")),
        "extra argument": alias(tail=(agent, "acp", "--trust-all-tools")),
        "no catalog arguments": alias(tail=(agent,)),
        "no command": alias(tail=()),
        "another profile": alias(profile="other"),
        "another mode": alias(mode="action"),
        "unknown option": alias(extra="x"),
        "no gateway": alias(drop=("--gateway",)),
    }
    setup_args = ["setup", "--client", "zed", "--agent", "kiro", "--guard-binary", guard, "--agent-binary", agent]
    remove_args = ["remove", "--client", "zed", "--agent", "kiro"]

    def write_lock() -> None:
        settings.write_text("{}")
        cmd_acp_module._write_contract_lock(
            data_dir=data_dir, client="zed", agent="kiro", profile="default", mode="observe",
            guard=guard, agent_executable=agent, client_path=settings.resolve(), managed=False,
        )

    try:
        for label, entry in variants.items():
            write_lock()
            settings.write_text(json.dumps({"agent_servers": {"Other Kiro": entry}}))
            before = settings.read_bytes()
            removed = CliRunner().invoke(acp_cmd, remove_args, obj=app)
            assert removed.exit_code == 0, (label, removed.output)
            assert settings.read_bytes() == before, label
            assert "Left editor entry 'Other Kiro'" in removed.output, (label, removed.output)

            write_lock()
            settings.write_text(json.dumps({"agent_servers": {"Other Kiro": entry}}))
            setup = CliRunner().invoke(acp_cmd, setup_args, obj=app)
            assert setup.exit_code == 0, (label, setup.output)
            servers = json.loads(settings.read_text())["agent_servers"]
            assert servers["Other Kiro"] == entry, label
            assert servers["DefenseClaw · Kiro"]["command"] == guard, label
            removed = CliRunner().invoke(acp_cmd, remove_args, obj=app)
            assert removed.exit_code == 0, (label, removed.output)
            assert json.loads(settings.read_text())["agent_servers"] == {"Other Kiro": entry}, label

        # Control: the exact launch setup writes is this runtime's alias.
        write_lock()
        settings.write_text(json.dumps({"agent_servers": {"Other Kiro": alias()}}))
        removed = CliRunner().invoke(acp_cmd, remove_args, obj=app)
        assert removed.exit_code == 0, removed.output
        assert "Left editor entry" not in removed.output
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
    lock_path = Path(data_dir) / "acp" / "zed-kiro.contract-lock.json"
    try:
        for bypass in ("direct", "deleted"):
            settings.write_text(json.dumps({"agent_servers": {"My Kiro": direct, "Foreign": {"command": "other"}}}))
            adopted = CliRunner().invoke(
                acp_cmd,
                ["adopt", "--client", "zed", "--guard-binary", guard, "--activate", "--yes", "--json-output"],
                obj=app,
            )
            assert adopted.exit_code == 0, adopted.output
            assert json.loads(lock_path.read_text())["client"]["adopted_entries"] == ["My Kiro"]
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
            if bypass == "direct":
                # The repair routes the adopted entry back through the guard.
                assert servers["My Kiro"]["command"] == guard and servers["My Kiro"]["env"] == {"KEEP": "me"}
                assert "DefenseClaw · Kiro" not in servers
            else:
                assert servers["DefenseClaw · Kiro"]["command"] == guard
            assert CliRunner().invoke(acp_cmd, ["verify"], obj=app).exit_code == 0

            removed = CliRunner().invoke(acp_cmd, ["remove", "--client", "zed", "--agent", "kiro"], obj=app)
            assert removed.exit_code == 0, removed.output
            assert json.loads(settings.read_text())["agent_servers"] == {"Foreign": {"command": "other"}}

        # A configured binding whose editor entry and lock are both gone is still listed.
        app.cfg.acp.bindings["zed/kiro"] = ACPBinding(enabled=True, profile="default")
        status = json.loads(CliRunner().invoke(acp_cmd, ["status", "--json"], obj=app).output)
        assert status["bindings"]["zed/kiro"]["healthy"] is False
        assert CliRunner().invoke(acp_cmd, ["verify"], obj=app).exit_code != 0
    finally:
        cleanup_app(app, db_path, data_dir)
