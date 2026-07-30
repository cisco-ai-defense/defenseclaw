"""Focused security regressions for Doctor credential and lifecycle repair."""

from __future__ import annotations

import os
import stat
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from defenseclaw import config as config_module
from defenseclaw.commands import cmd_doctor, cmd_setup, cmd_version
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
        "DEFENSECLAW_DAEMON",
        "DEFENSECLAW_DISABLE_REDACTION",
        "CLAUDE_CONFIG_DIR",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "REQUESTS_CA_BUNDLE",
        "CURL_CA_BUNDLE",
        "NODE_EXTRA_CA_CERTS",
        "NODE_OPTIONS",
        "GIT_SSL_NO_VERIFY",
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
        b"DEFENSECLAW_DAEMON=1\n"
        b"DEFENSECLAW_DISABLE_REDACTION=1\n"
        b"CLAUDE_CONFIG_DIR=/tmp/attacker-claude-home\n"
        b"SSL_CERT_FILE=/tmp/attacker-ca.pem\n"
        b"SSL_CERT_DIR=/tmp/attacker-ca-directory\n"
        b"REQUESTS_CA_BUNDLE=/tmp/attacker-requests-ca.pem\n"
        b"CURL_CA_BUNDLE=/tmp/attacker-curl-ca.pem\n"
        b"NODE_EXTRA_CA_CERTS=/tmp/attacker-node-ca.pem\n"
        b"NODE_OPTIONS=--require=/tmp/attacker.js\n"
        b"GIT_SSL_NO_VERIFY=true\n"
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
    (tmp_path / "config.yaml").write_text("config_version: 8\n", encoding="utf-8")
    cfg = SimpleNamespace(data_dir=os.fspath(tmp_path))
    result = cmd_doctor._DoctorResult()

    def plan_then_fail(*_args, **kwargs):
        if kwargs.get("plan_only"):
            return ("plan", "rotate the exposed gateway token")
        return ("fail", "rotation failed")

    token = Mock(side_effect=plan_then_fail)
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
    monkeypatch.setattr(
        "defenseclaw.config_inspect.inspect_v8_config",
        lambda *_args, **_kwargs: SimpleNamespace(valid=True),
    )

    cmd_doctor._run_fixers(
        cfg,
        result,
        assume_yes=True,
        json_out=True,
    )

    assert getattr(cfg, "_doctor_gateway_token_rotation_required", False) is True
    assert stat.S_IMODE(dotenv.stat().st_mode) == 0o644
    assert token.call_count == 2
    token.assert_any_call(cfg, assume_yes=True, plan_only=True)
    token.assert_any_call(cfg, assume_yes=True)
    token_env.assert_not_called()
    token_drift.assert_not_called()
    service.assert_not_called()
    rows = {row["label"]: row for row in result.repairs}
    assert rows["defenseclaw dotenv perms"]["state"] == "applied"
    assert rows["gateway token"]["state"] == "failed"
    for label in (
        "gateway token_env",
        "gateway token drift",
        "gateway service",
    ):
        assert rows[label]["state"] == "blocked"
        assert rows[label]["blockers"]


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
    # Production intentionally updates this process after activating B.
    # Seed through monkeypatch so teardown removes that production-set value
    # even when the variable was absent before the test.
    monkeypatch.setenv(canonical, "restore-test-environment-after-rotation")
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
    assert restart.call_args.kwargs["lifecycle_executable_requires_running"] is True
    assert restart.call_args.kwargs["start_if_stopped"] is False


@pytest.mark.parametrize(
    ("case", "running", "expected_action"),
    [
        ("trusted-record", True, "restart"),
        ("authenticated-migration", True, "restart"),
        ("stopped-start", False, "start"),
    ],
)
def test_component_diagnosis_gate_and_lifecycle_use_one_controller(
    case,
    running,
    expected_action,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    suffix = ".exe" if os.name == "nt" else ""
    recorded = tmp_path / f"recorded-gateway{suffix}"
    current = tmp_path / f"current-gateway{suffix}"
    wrong_default = tmp_path / f"wrong-default-gateway{suffix}"
    for executable in (recorded, current, wrong_default):
        executable.write_bytes(b"synthetic executable")
        os.chmod(executable, 0o700)

    cfg = SimpleNamespace(
        data_dir=os.fspath(tmp_path),
        gateway=SimpleNamespace(token_env=""),
        active_connectors=lambda: [],
    )
    if case == "stopped-start":
        trust = cmd_doctor._GatewayTrust("missing", "gateway is stopped")
        expected = current
    else:
        record = PIDRecord(
            "ok",
            pid=4242,
            executable=os.fspath(recorded),
            start_identity="strong-start",
            data_dir=os.fspath(tmp_path) if case == "trusted-record" else "",
        )
        process = ProcessEvidence(
            "ok",
            pid=4242,
            executable=os.fspath(recorded),
            start_identity="strong-start",
        )
        trust = cmd_doctor._GatewayTrust(
            "trusted",
            "verified",
            pid=4242,
            home_bound=True,
            record=record,
            process=process,
            authenticated_migration=case == "authenticated-migration",
        )
        expected = recorded if case == "trusted-record" else current

    monkeypatch.setattr(
        cmd_doctor,
        "_managed_gateway_process_trust_for_lifecycle",
        lambda _cfg: trust,
    )
    monkeypatch.setattr(
        cmd_doctor,
        "_daemon_effective_gateway_token",
        lambda _cfg: ("", "", ""),
    )
    monkeypatch.setattr(
        cmd_setup,
        "_gateway_lifecycle_executable",
        lambda **_kwargs: os.fspath(current),
    )
    monkeypatch.setattr(
        cmd_setup,
        "_trusted_gateway_lifecycle_executable",
        lambda executable: os.path.realpath(executable),
    )
    monkeypatch.setattr(cmd_setup, "_is_pid_alive", lambda _path: running)
    monkeypatch.setattr(
        cmd_setup,
        "_gateway_pid_file_identifies_gateway",
        lambda _path: True,
    )
    monkeypatch.setattr(
        cmd_setup,
        "_wait_for_defense_gateway_api",
        lambda _data_dir: True,
    )

    ambient_resolver = Mock(return_value=os.fspath(wrong_default))
    monkeypatch.setattr(
        cmd_version.gateway,
        "resolve_gateway_binary",
        ambient_resolver,
    )
    probed: list[str] = []

    def check_output(argv, **_kwargs):
        probed.append(argv[0])
        return (
            "defenseclaw-gateway version "
            f"{cmd_version.defenseclaw.__version__}\n"
        )

    monkeypatch.setattr(cmd_version.subprocess, "check_output", check_output)
    executed: list[tuple[str, str]] = []

    def run(argv, **_kwargs):
        executed.append((argv[0], argv[1]))
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(cmd_setup.subprocess, "run", run)
    monkeypatch.setattr(
        "defenseclaw.doctor_health.read_cached_discovery",
        lambda _data_dir: None,
    )

    result = cmd_doctor._DoctorResult()
    cmd_doctor._check_component_connector_compatibility(cfg, [], result)
    gate = cmd_doctor._plan_component_compatibility_gate(cfg)
    repaired, detail = cmd_doctor._repair_gateway_lifecycle(
        cfg,
        start_if_stopped=True,
    )

    gateway_row = next(
        row
        for row in result.checks
        if row["check_id"] == "doctor.component.gateway.compatibility"
    )
    assert gateway_row["status"] == "pass"
    assert gate.state == "noop"
    assert repaired is True, detail
    assert probed == [
        os.fspath(expected),
        os.fspath(expected),
        os.fspath(expected),
    ]
    assert executed == [(os.fspath(expected), expected_action)]
    ambient_resolver.assert_not_called()


def test_action_rechecks_current_controller_after_running_record_exits(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    recorded = tmp_path / "recorded-gateway"
    current = tmp_path / "current-gateway"
    for executable in (recorded, current):
        executable.write_bytes(b"synthetic executable")
        os.chmod(executable, 0o700)
    cfg = SimpleNamespace(
        data_dir=os.fspath(tmp_path),
        gateway=SimpleNamespace(token_env=""),
        active_connectors=lambda: [],
    )
    record = PIDRecord(
        "ok",
        pid=4242,
        executable=os.fspath(recorded),
        start_identity="strong-start",
        data_dir=os.fspath(tmp_path),
    )
    process = ProcessEvidence(
        "ok",
        pid=4242,
        executable=os.fspath(recorded),
        start_identity="strong-start",
    )
    running = cmd_doctor._GatewayTrust(
        "trusted",
        "verified",
        pid=4242,
        home_bound=True,
        record=record,
        process=process,
    )
    stopped = cmd_doctor._GatewayTrust("missing", "gateway exited after planning")
    trusts = iter((running, stopped))
    monkeypatch.setattr(
        cmd_doctor,
        "_managed_gateway_process_trust_for_lifecycle",
        lambda _cfg: next(trusts),
    )
    monkeypatch.setattr(
        cmd_doctor,
        "_daemon_effective_gateway_token",
        lambda _cfg: ("", "", ""),
    )
    monkeypatch.setattr(
        cmd_setup,
        "_gateway_lifecycle_executable",
        lambda **_kwargs: os.fspath(current),
    )
    monkeypatch.setattr(
        cmd_setup,
        "_trusted_gateway_lifecycle_executable",
        lambda executable: os.path.realpath(executable),
    )
    probed: list[str] = []

    def check_output(argv, **_kwargs):
        probed.append(argv[0])
        version = (
            cmd_version.defenseclaw.__version__
            if argv[0] == os.fspath(recorded)
            else "0.0.1"
        )
        return f"defenseclaw-gateway version {version}\n"

    monkeypatch.setattr(cmd_version.subprocess, "check_output", check_output)
    restart = Mock(return_value=True)
    monkeypatch.setattr(cmd_setup, "_restart_defense_gateway", restart)

    gate = cmd_doctor._plan_component_compatibility_gate(cfg)
    repaired, detail = cmd_doctor._repair_gateway_lifecycle(
        cfg,
        start_if_stopped=True,
    )

    assert gate.state == "noop"
    assert repaired is False
    assert detail == "selected lifecycle components are positively unsupported"
    assert probed == [os.fspath(recorded), os.fspath(current)]
    restart.assert_not_called()


def test_selected_current_controller_is_revalidated_before_start(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    selected = tmp_path / ("gateway.exe" if os.name == "nt" else "gateway")
    selected.write_bytes(b"synthetic executable")
    os.chmod(selected, 0o700)
    cfg = SimpleNamespace(
        data_dir=os.fspath(tmp_path),
        gateway=SimpleNamespace(token_env=""),
    )
    monkeypatch.setattr(
        cmd_doctor,
        "_managed_gateway_process_trust_for_lifecycle",
        lambda _cfg: cmd_doctor._GatewayTrust("missing", "gateway is stopped"),
    )
    monkeypatch.setattr(
        cmd_doctor,
        "_daemon_effective_gateway_token",
        lambda _cfg: ("", "", ""),
    )
    monkeypatch.setattr(
        cmd_setup,
        "_gateway_lifecycle_executable",
        lambda **_kwargs: os.fspath(selected),
    )
    monkeypatch.setattr(cmd_setup, "_is_pid_alive", lambda _path: False)
    monkeypatch.setattr(
        cmd_setup,
        "_trusted_gateway_lifecycle_executable",
        lambda _path: None,
    )
    run = Mock()
    monkeypatch.setattr(cmd_setup.subprocess, "run", run)

    repaired, detail = cmd_doctor._repair_gateway_lifecycle(
        cfg,
        start_if_stopped=True,
    )

    assert repaired is False
    assert detail == "binary not found"
    run.assert_not_called()
