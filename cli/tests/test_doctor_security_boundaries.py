"""Focused security regressions for Doctor credential and lifecycle repair."""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from defenseclaw import config as config_module
from defenseclaw import file_permissions
from defenseclaw.commands import cmd_doctor, cmd_setup, cmd_version
from defenseclaw.doctor_gateway import PIDRecord, ProcessEvidence
from defenseclaw.file_permissions import UnsafePathError
from defenseclaw.pinned_exec import pinned_executable, run_pinned_executable


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
        "DEFENSECLAW_DEPLOYMENT_MODE",
        "DEFENSECLAW_ENTERPRISE_PROFILE",
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
        b"DEFENSECLAW_DEPLOYMENT_MODE=oss\n"
        b"DEFENSECLAW_ENTERPRISE_PROFILE=standalone\n"
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


def test_scanner_custody_channel_cannot_come_from_dotenv(monkeypatch, tmp_path) -> None:
    """Only the tracked launcher may pass its host-owner descriptor."""
    name = "DEFENSECLAW_TRACKED_HOST_STAT_FD"
    monkeypatch.delenv(name, raising=False)
    (tmp_path / ".env").write_text(f"{name}=5\n", encoding="utf-8")

    config_module._load_dotenv_into_os(os.fspath(tmp_path))

    assert name not in os.environ


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux user-namespace overflow UID")
def test_overflow_owner_fails_closed_without_scanner_custody_channel(monkeypatch) -> None:
    monkeypatch.delenv("DEFENSECLAW_TRACKED_HOST_STAT_FD", raising=False)
    info = SimpleNamespace(st_uid=65534)

    assert file_permissions.tracked_host_owner_uid("/unmapped-owner", info) == -1


def _impostor_sockets():
    import socket

    listener = socket.create_server(("127.0.0.1", 0))
    tcp = socket.create_connection(listener.getsockname())
    server, _ = listener.accept()
    listener.close()
    udp_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_server.bind(("127.0.0.1", 0))
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.connect(udp_server.getsockname())
    yield "tcp", tcp, server
    yield "udp", udp, udp_server
    for name, kind in (
        ("unix stream", socket.SOCK_STREAM),
        ("own seqpacket pair", socket.SOCK_SEQPACKET),
        ("unix datagram", socket.SOCK_DGRAM),
    ):
        mine, other = socket.socketpair(socket.AF_UNIX, kind)
        yield name, mine, other


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux tracked-scanner channel")
def test_overflow_owner_refuses_a_socket_that_is_not_the_launchers(monkeypatch) -> None:
    """r104 W25: the variable names fd 5; the socket on it must prove it is the launcher's."""
    import select

    monkeypatch.setenv("DEFENSECLAW_TRACKED_HOST_STAT_FD", "5")
    monkeypatch.setattr(file_permissions.os, "getpid", lambda: 1)
    # As inside a scanner's PID namespace, so only the socket checks decide.
    monkeypatch.setattr(file_permissions, "_in_child_pid_namespace", lambda: True, raising=False)
    real = os.stat("/etc/passwd")
    info = SimpleNamespace(st_uid=65534, st_dev=real.st_dev, st_ino=real.st_ino)
    saved = os.dup(5) if _fd_open(5) else None
    try:
        for name, mine, other in _impostor_sockets():
            with mine, other:
                os.dup2(mine.fileno(), 5)
                assert file_permissions.tracked_host_owner_uid("/etc/passwd", info) == -1, name
                assert not select.select([other], [], [], 0.1)[0], f"a request was written to the {name}"
    finally:
        if saved is None:
            os.close(5)
        else:
            os.dup2(saved, 5)
            os.close(saved)


def _fd_open(fd: int) -> bool:
    try:
        os.fstat(fd)
    except OSError:
        return False
    return True


def test_dotenv_control_keys_are_named_with_their_replacement_not_on_every_command(
    caplog: pytest.LogCaptureFixture,
    tmp_path,
) -> None:
    # GAP-0387: every command warned "ignored unsafe process-control key" with
    # no fix, and the upgrade never said fail-open hooks were now fail-closed.
    (tmp_path / ".env").write_bytes(b"DEFENSECLAW_FAIL_MODE=open\nDEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT=1\n")

    with caplog.at_level("WARNING"):
        config_module._load_dotenv_into_os(os.fspath(tmp_path))
    keys = config_module.ignored_dotenv_control_keys(os.fspath(tmp_path))
    result = cmd_doctor._DoctorResult()
    cmd_doctor._check_ignored_dotenv_keys(SimpleNamespace(data_dir=os.fspath(tmp_path)), result)

    assert "process-control" not in caplog.text
    assert keys[0] == "DEFENSECLAW_FAIL_MODE (set it in config.yaml instead: defenseclaw guardrail fail-mode open)"
    assert keys[1].startswith("DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT (") and "defenseclaw-gateway restart" in keys[1]
    assert [row["status"] for row in result.checks] == ["warn"]


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


def test_doctor_reports_unreadable_dotenv_and_keeps_other_checks(
    monkeypatch: pytest.MonkeyPatch, tmp_path,
) -> None:
    dotenv = tmp_path / ".env"
    dotenv.write_bytes(b"DEFENSECLAW_GATEWAY_TOKEN=placeholder\n")
    dotenv.chmod(0o600)
    safe_read = cmd_doctor.read_regular_file_no_follow

    def refuse_dotenv(path, *, max_bytes):
        if os.fspath(path) == os.fspath(dotenv):
            raise PermissionError(13, "access denied")
        return safe_read(path, max_bytes=max_bytes)

    monkeypatch.setattr(cmd_doctor, "read_regular_file_no_follow", refuse_dotenv)
    if os.name == "nt":
        # chmod does not define the Windows DACL; model a private file so this
        # case tests an unreadable dotenv rather than an exposed one.
        monkeypatch.setattr(file_permissions, "windows_acl_confidentiality_error", lambda _path: None)
    result = cmd_doctor._DoctorResult()
    cfg = SimpleNamespace(data_dir=os.fspath(tmp_path))
    cmd_doctor._check_private_file_exposure(cfg, result)

    assert len(result.checks) == 1
    row = result.checks[0]
    assert row["status"] == "warn" and row["label"] == "Private files"
    assert os.fspath(dotenv) in row["detail"]
    assert "restore this account's read access" in row["remediation"]
    assert "placeholder" not in str(row)


def test_doctor_still_fails_exposed_dotenv_when_safe_read_rejects_it(
    monkeypatch: pytest.MonkeyPatch, tmp_path,
) -> None:
    dotenv = tmp_path / ".env"
    dotenv.write_bytes(b"x" * 10)
    dotenv.chmod(0o644)
    monkeypatch.setattr(
        cmd_doctor, "read_regular_file_no_follow",
        Mock(side_effect=UnsafePathError("sensitive file exceeds read limit")),
    )
    if os.name == "nt":
        # POSIX mode bits cannot express Windows read exposure.
        monkeypatch.setattr(
            file_permissions,
            "windows_acl_confidentiality_error",
            lambda path: "another account can read" if os.fspath(path) == os.fspath(dotenv) else None,
        )
    result = cmd_doctor._DoctorResult()
    cmd_doctor._check_private_file_exposure(SimpleNamespace(data_dir=os.fspath(tmp_path)), result)
    assert result.checks[0]["status"] == "fail"
    assert (
        "unsafe Windows ACL" if os.name == "nt" else "mode 0644"
    ) in result.checks[0]["detail"]


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
    monkeypatch.setattr(
        cmd_doctor,
        "_managed_gateway_process_trust_for_lifecycle",
        lambda _cfg: trust,
    )
    monkeypatch.setattr(
        cmd_setup,
        "_trusted_gateway_lifecycle_executable",
        lambda selected: os.path.realpath(selected),
    )
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
        lambda _data_dir, **_kwargs: True,
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
    monkeypatch.setattr(
        cmd_version,
        "run_pinned_executable",
        lambda argv, **_kwargs: SimpleNamespace(stdout=check_output(argv)),
    )
    executed: list[tuple[str, str]] = []

    def run(argv, **_kwargs):
        executed.append((argv[0], argv[1]))
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(cmd_setup, "run_pinned_executable", run)
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
    monkeypatch.setattr(
        cmd_version,
        "run_pinned_executable",
        lambda argv, **_kwargs: SimpleNamespace(stdout=check_output(argv)),
    )
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
    monkeypatch.setattr(cmd_setup, "run_pinned_executable", run)

    repaired, detail = cmd_doctor._repair_gateway_lifecycle(
        cfg,
        start_if_stopped=True,
    )

    assert repaired is False
    assert detail == "binary not found"
    run.assert_not_called()


@pytest.mark.skipif(os.name == "nt", reason="refuses the binary through its POSIX mode")
def test_restart_names_a_refused_gateway_instead_of_a_build_hint(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """An installed gateway the custody check refuses is named, not reported missing."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    gateway = bin_dir / "defenseclaw-gateway"
    gateway.write_bytes(b"synthetic executable")
    os.chmod(gateway, 0o777)
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    run = Mock()
    monkeypatch.setattr(cmd_setup, "run_pinned_executable", run)

    started = cmd_setup._restart_defense_gateway(os.fspath(data_dir), child_env={"PATH": os.fspath(bin_dir)})

    output = capsys.readouterr().out
    assert started is False
    assert f"refusing to run {gateway.resolve()}" in output
    assert "make gateway" not in output
    run.assert_not_called()


def test_lifecycle_launch_never_runs_a_controller_swapped_in_after_verification(tmp_path) -> None:
    """A controller swapped in at the verified path after the check is never launched."""
    controller = tmp_path / ("defenseclaw-gateway.exe" if os.name == "nt" else "defenseclaw-gateway")
    replacement = tmp_path / "replacement"
    if os.name == "nt":
        shutil.copyfile(os.path.join(os.environ["SystemRoot"], "System32", "cmd.exe"), controller)
        replacement.write_bytes(b"replacement controller")
    else:
        shutil.copyfile("/bin/echo", controller)
        replacement.write_text("#!/bin/sh\necho replacement\n", encoding="utf-8")
        for path in (controller, replacement):
            path.chmod(0o755)

    if os.name == "nt":
        with pinned_executable(os.fspath(controller)):
            # NTFS refuses to replace a file held without delete sharing.
            with pytest.raises(PermissionError):
                os.replace(replacement, controller)
        # The hold lasts until the command exits, so the controller cannot be
        # renamed away before it starts its own long-running process either.
        renamed = run_pinned_executable(
            [os.fspath(controller), "/d", "/c", "ren", os.fspath(controller), "moved.exe"],
            capture_output=True,
            stdin=subprocess.DEVNULL,
            timeout=30,
        )
        assert renamed.returncode != 0
        assert controller.exists()
        return

    with pinned_executable(os.fspath(controller)) as pinned:
        os.replace(replacement, controller)
        argv = [os.fspath(controller), "verified"]
        if sys.platform.startswith("linux"):
            process = pinned.popen(argv, stdout=subprocess.PIPE, text=True)
            stdout, _ = process.communicate(timeout=10)
            assert stdout.strip() == "verified"
        else:
            with pytest.raises(UnsafePathError):
                pinned.popen(argv, stdout=subprocess.PIPE)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux descriptor exec")
@pytest.mark.parametrize("kind", ["binary", "script"])
def test_pinned_executable_launches_with_private_pid_namespace(tmp_path, monkeypatch, kind) -> None:
    """Descriptor exec resolves self even when the visible PID is not the host PID."""
    controller = tmp_path / "controller"
    if kind == "script":
        controller.write_text("#!/bin/sh\necho \"$1\"\n", encoding="utf-8")
    else:
        shutil.copyfile("/bin/echo", controller)
    controller.chmod(0o755)

    with monkeypatch.context() as patched:
        patched.setattr("defenseclaw.pinned_exec.os.getpid", lambda: 1)
        result = run_pinned_executable(
            [os.fspath(controller), "namespace"],
            capture_output=True,
            text=True,
            timeout=10,
        )
    assert result.returncode == 0
    assert result.stdout.strip() == "namespace"
