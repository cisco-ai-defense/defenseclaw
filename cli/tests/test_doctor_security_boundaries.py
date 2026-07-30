"""Focused security regressions for Doctor credential and lifecycle repair."""

from __future__ import annotations

import os
import stat
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from defenseclaw import config as config_module
from defenseclaw.commands import cmd_doctor, cmd_setup
from defenseclaw.doctor_gateway import PIDRecord, ProcessEvidence
from defenseclaw.file_permissions import UnsafePathError


def test_python_dotenv_loader_ignores_process_control_and_malformed_entries(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    """A hostile dotenv line must not hide a later valid credential."""
    allowed = {
        "DC_SECURITY_TEST_CREDENTIAL": "credential-before",
        "DC_SECURITY_TEST_CREDENTIAL_AFTER": "credential-after",
    }
    rejected = {
        "1INVALID",
        "BAD-KEY",
        "NUL_VALUE",
        "LD_PRELOAD",
        "DYLD_INSERT_LIBRARIES",
        "PYTHONPATH",
        "BASH_ENV",
        "DEFENSECLAW_GATEWAY_BIN",
        "DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT",
        "DEFENSECLAW_DISABLE_REDACTION",
        "CLAUDE_CONFIG_DIR",
    }
    for name in allowed | {name: "" for name in rejected}:
        monkeypatch.delenv(name, raising=False)

    (tmp_path / ".env").write_bytes(
        b"DC_SECURITY_TEST_CREDENTIAL=credential-before\n"
        b"1INVALID=ignored\n"
        b"BAD-KEY=ignored\n"
        b"NUL_VALUE=before\x00after\n"
        b"LD_PRELOAD=/tmp/attacker.so\n"
        b"DYLD_INSERT_LIBRARIES=/tmp/attacker.dylib\n"
        b"PYTHONPATH=/tmp/attacker-python\n"
        b"BASH_ENV=/tmp/attacker-shell\n"
        b"DEFENSECLAW_GATEWAY_BIN=/tmp/attacker-gateway\n"
        b"DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT=1\n"
        b"DEFENSECLAW_DISABLE_REDACTION=1\n"
        b"CLAUDE_CONFIG_DIR=/tmp/attacker-claude-home\n"
        b"DC_SECURITY_TEST_CREDENTIAL_AFTER=credential-after\n"
    )

    config_module._load_dotenv_into_os(os.fspath(tmp_path))

    for name, value in allowed.items():
        assert os.environ.get(name) == value
    for name in rejected:
        assert name not in os.environ


def test_python_dotenv_loader_warns_when_safe_read_is_refused(
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    monkeypatch.setattr(
        config_module,
        "read_regular_file_no_follow",
        Mock(side_effect=UnsafePathError("sensitive file exceeds read limit")),
    )

    with caplog.at_level("WARNING", logger=config_module.__name__):
        config_module._load_dotenv_into_os(os.fspath(tmp_path))

    assert "ignoring unreadable or unsafe dotenv" in caplog.text
    assert os.fspath(tmp_path / ".env") in caplog.text


def test_empty_data_dir_never_consumes_cwd_gateway_state(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    dotenv = tmp_path / ".env"
    dotenv.write_text("DEFENSECLAW_GATEWAY_TOKEN=attacker-selected\n", encoding="utf-8")
    os.chmod(dotenv, 0o600)
    pid_file = tmp_path / "gateway.pid"
    pid_file.write_text("4242\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    cfg = SimpleNamespace(
        data_dir="",
        gateway=SimpleNamespace(token_env="", resolved_token=lambda: ""),
    )

    assert cmd_doctor._gateway_dotenv_tokens("") == {}
    assert cmd_doctor._daemon_effective_gateway_token(cfg) == ("", "", "")
    assert cmd_doctor._gateway_dotenv_safety_problem(cfg) == "gateway data directory is unavailable"
    assert cmd_doctor._fix_dotenv_perms(cfg, assume_yes=True)[0] == "fail"
    assert cmd_doctor._fix_stale_pid(cfg, assume_yes=True)[0] == "fail"
    assert pid_file.exists()


def test_fixer_blocker_reports_the_blocker_applicable_to_each_stage() -> None:
    cfg = SimpleNamespace(
        gateway=SimpleNamespace(token_env="OPENCLAW_GATEWAY_TOKEN"),
        _doctor_gateway_token_was_rotated=True,
        _doctor_gateway_token_rotation_required=False,
    )
    dotenv_problem = "dotenv permissions are not 0600"

    assert (
        cmd_doctor._fixer_blocker(
            cfg,
            "gateway token_env",
            dotenv_problem,
        )
        == dotenv_problem
    )
    assert (
        cmd_doctor._fixer_blocker(
            cfg,
            "gateway token drift",
            dotenv_problem,
        )
        == "gateway.token_env did not converge on the rotated canonical provider"
    )


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode/owner regression")
def test_read_exposed_dotenv_blocks_dependent_fixers_until_rotation_completes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    """A failed rotation cannot be followed by token-env or lifecycle repair."""
    dotenv = tmp_path / ".env"
    dotenv.write_text("DEFENSECLAW_GATEWAY_TOKEN=exposed-token\n", encoding="utf-8")
    os.chmod(dotenv, 0o644)
    cfg = SimpleNamespace(data_dir=os.fspath(tmp_path))
    result = cmd_doctor._DoctorResult()

    token = Mock(return_value=("fail", "rotation failed"))
    token_env = Mock(return_value=("pass", "must not run"))
    token_drift = Mock(return_value=("pass", "must not run"))
    service = Mock(return_value=("pass", "must not run"))
    monkeypatch.setattr(cmd_doctor, "_fix_stale_pid", Mock(return_value=("skip", "not relevant")))
    monkeypatch.setattr(cmd_doctor, "_fix_gateway_token", token)
    monkeypatch.setattr(cmd_doctor, "_fix_gateway_token_env", token_env)
    monkeypatch.setattr(cmd_doctor, "_fix_gateway_token_drift", token_drift)
    monkeypatch.setattr(cmd_doctor, "_fix_gateway_service", service)
    monkeypatch.setattr(cmd_doctor, "_fix_pristine_backup", Mock(return_value=("skip", "not relevant")))
    monkeypatch.setattr(
        cmd_doctor,
        "_fix_plugin_registry_required",
        Mock(return_value=("skip", "not relevant")),
    )

    cmd_doctor._run_fixers(
        cfg,
        result,
        assume_yes=True,
        json_out=True,
    )

    assert getattr(cfg, "_doctor_gateway_token_rotation_required", False) is True
    assert stat.S_IMODE(dotenv.stat().st_mode) == 0o644
    token.assert_called_once_with(cfg, assume_yes=True)
    token_env.assert_not_called()
    token_drift.assert_not_called()
    service.assert_not_called()
    rows = {row["label"]: row for row in result.checks}
    assert rows["fix: defenseclaw dotenv perms"]["status"] == "warn"
    assert rows["fix: gateway token"]["status"] == "fail"
    for label in (
        "fix: gateway token_env",
        "fix: gateway token drift",
        "fix: gateway service",
    ):
        assert rows[label]["status"] == "fail"
        assert "rotation did not complete" in rows[label]["detail"]


def test_exposed_token_rotation_repoints_legacy_provider_before_transaction(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    """Doctor activates B without ever permitting recovery of exposed A."""
    secret = "doctor-rotated-token-that-must-stay-redacted"
    canonical = "DEFENSECLAW_GATEWAY_TOKEN"
    legacy = "OPENCLAW_GATEWAY_TOKEN"
    gateway = SimpleNamespace(token_env=legacy)
    events: list[tuple[str, str]] = []
    cfg = SimpleNamespace(
        data_dir=os.fspath(tmp_path),
        gateway=gateway,
        _doctor_external_gateway_env_names=(legacy,),
    )

    def save() -> None:
        events.append(("save", gateway.token_env))

    def transaction(app, dotenv_path, token, audit_details, **kwargs) -> None:
        assert app.cfg is cfg
        assert dotenv_path == os.fspath(tmp_path / ".env")
        assert token == secret
        assert audit_details == "action=doctor-exposure-rotation restart=true"
        assert kwargs == {"recover_previous_runtime": False}
        events.append(("transaction", gateway.token_env))

    cfg.save = save
    monkeypatch.delenv(canonical, raising=False)
    monkeypatch.setattr(cmd_setup, "_rotate_token_transaction", transaction)

    tag, detail = cmd_doctor._rotate_exposed_gateway_token(cfg, secret)

    assert tag == "pass"
    assert events == [("save", canonical), ("transaction", canonical)]
    assert gateway.token_env == canonical
    assert cfg._doctor_gateway_token_was_rotated is True
    assert cfg._doctor_gateway_token_activation_verified is True
    assert cfg._doctor_stale_parent_gateway_env_names == (legacy,)
    assert os.environ[canonical] == secret
    assert secret not in detail


def test_failed_exposed_token_rotation_restores_legacy_provider_without_activation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    """A rejected B restores provider configuration but never revives A."""
    secret = "failed-doctor-token-that-must-stay-redacted"
    canonical = "DEFENSECLAW_GATEWAY_TOKEN"
    legacy = "OPENCLAW_GATEWAY_TOKEN"
    gateway = SimpleNamespace(token_env=legacy)
    events: list[tuple[str, str]] = []
    cfg = SimpleNamespace(data_dir=os.fspath(tmp_path), gateway=gateway)

    def save() -> None:
        events.append(("save", gateway.token_env))

    def transaction(_app, _dotenv_path, _token, _audit_details, **kwargs) -> None:
        assert kwargs == {"recover_previous_runtime": False}
        events.append(("transaction", gateway.token_env))
        raise RuntimeError(f"activation rejected for {secret}")

    cfg.save = save
    monkeypatch.delenv(canonical, raising=False)
    monkeypatch.setattr(cmd_setup, "_rotate_token_transaction", transaction)

    tag, detail = cmd_doctor._rotate_exposed_gateway_token(cfg, secret)

    assert tag == "fail"
    assert events == [
        ("save", canonical),
        ("transaction", canonical),
        ("save", legacy),
    ]
    assert gateway.token_env == legacy
    assert not getattr(cfg, "_doctor_gateway_token_was_rotated", False)
    assert not getattr(cfg, "_doctor_gateway_token_activation_verified", False)
    assert canonical not in os.environ
    assert secret not in detail
    assert "activation rejected" not in detail
    assert "RuntimeError" in detail


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode regression")
def test_write_exposed_dotenv_is_not_blessed_or_consumed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    dotenv = tmp_path / ".env"
    dotenv.write_text("DEFENSECLAW_GATEWAY_TOKEN=attacker-selected\n", encoding="utf-8")
    os.chmod(dotenv, 0o620)
    cfg = SimpleNamespace(data_dir=os.fspath(tmp_path))
    # Isolate the mode assertion from the separate data-directory check.
    monkeypatch.setattr(cmd_doctor, "_gateway_data_dir_integrity_problem", lambda _cfg: "")

    tag, detail = cmd_doctor._fix_dotenv_perms(
        cfg,
        assume_yes=True,
        platform_name="linux",
    )

    assert tag == "fail"
    assert "writable by another local principal" in detail
    assert stat.S_IMODE(dotenv.stat().st_mode) == 0o620
    assert not getattr(cfg, "_doctor_gateway_token_rotation_required", False)


@pytest.mark.skipif(os.name == "nt", reason="POSIX owner regression")
def test_foreign_owned_dotenv_is_not_blessed_or_consumed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    dotenv = tmp_path / ".env"
    dotenv.write_text("DEFENSECLAW_GATEWAY_TOKEN=foreign-selected\n", encoding="utf-8")
    os.chmod(dotenv, 0o600)
    cfg = SimpleNamespace(data_dir=os.fspath(tmp_path))
    owner = dotenv.stat().st_uid

    # Isolate the leaf-owner assertion from the separate data-directory check.
    monkeypatch.setattr(cmd_doctor, "_gateway_data_dir_integrity_problem", lambda _cfg: "")
    monkeypatch.setattr(cmd_doctor.os, "geteuid", lambda: owner + 1)

    tag, detail = cmd_doctor._fix_dotenv_perms(
        cfg,
        assume_yes=True,
        platform_name="linux",
    )

    assert tag == "fail"
    assert "not owned by the current user" in detail
    assert dotenv.read_text(encoding="utf-8").endswith("foreign-selected\n")
    assert not getattr(cfg, "_doctor_gateway_token_rotation_required", False)


def test_gateway_lifecycle_uses_verified_executable_and_sanitized_child_env(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    executable = tmp_path / "defenseclaw-gateway"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    os.chmod(executable, 0o700)
    cfg = SimpleNamespace(
        data_dir=os.fspath(tmp_path),
        gateway=SimpleNamespace(),
    )
    record = PIDRecord(
        "ok",
        pid=4242,
        executable=os.fspath(executable),
        start_identity="strong-start",
        data_dir=os.fspath(tmp_path),
    )
    process = ProcessEvidence(
        "ok",
        pid=4242,
        executable=os.fspath(executable),
        start_identity="strong-start",
    )
    trust = cmd_doctor._GatewayTrust(
        "trusted",
        "verified",
        pid=4242,
        home_bound=True,
        record=record,
        process=process,
    )
    monkeypatch.setattr(
        cmd_doctor,
        "_daemon_effective_gateway_token",
        lambda _cfg: ("gateway-secret", "DEFENSECLAW_GATEWAY_TOKEN", "test"),
    )
    monkeypatch.setattr(cmd_doctor, "_managed_gateway_process_trust", lambda _cfg: trust)
    restart = Mock(return_value=True)
    monkeypatch.setattr(cmd_setup, "_restart_defense_gateway", restart)

    rejected = (
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "DYLD_INSERT_LIBRARIES",
        "PYTHONHOME",
        "PYTHONPATH",
        "BASH_ENV",
        "ENV",
        "DEFENSECLAW_GATEWAY_BIN",
        "DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT",
        "DEFENSECLAW_DISABLE_REDACTION",
        "DEFENSECLAW_UPGRADE_ALLOW_UNVERIFIED",
    )
    for name in rejected:
        monkeypatch.setenv(name, f"attacker-{name.lower()}")

    repaired, detail = cmd_doctor._repair_gateway_lifecycle(
        cfg,
        start_if_stopped=False,
    )

    assert repaired is True, detail
    child_env = restart.call_args.kwargs["child_env"]
    for name in rejected:
        assert name not in child_env
    assert child_env["DEFENSECLAW_GATEWAY_TOKEN"] == "gateway-secret"
    assert child_env["DEFENSECLAW_HOME"] == os.path.abspath(tmp_path)
    assert child_env["DEFENSECLAW_DATA_DIR"] == os.path.abspath(tmp_path)
    assert restart.call_args.kwargs["lifecycle_executable"] == os.path.realpath(executable)
    assert restart.call_args.kwargs["start_if_stopped"] is False
