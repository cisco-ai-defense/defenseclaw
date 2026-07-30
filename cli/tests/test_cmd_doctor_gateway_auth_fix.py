"""Regression coverage for Doctor's authenticated gateway repair path."""

from __future__ import annotations

import http.server
import json
import os
import socket
import stat
import sys
import threading
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from defenseclaw.commands.cmd_doctor import (
    _check_gateway_auth,
    _daemon_effective_gateway_token,
    _DoctorResult,
    _env_names_equal,
    _fix_dotenv_perms,
    _fix_gateway_service,
    _fix_gateway_token,
    _fix_gateway_token_drift,
    _fix_gateway_token_env,
    _fix_stale_pid,
    _gateway_listener_pid,
    _GatewayTrust,
    _http_probe,
    _linux_gateway_listener_pid,
    _remove_stale_pid_if_unchanged,
    _run_fixers,
    _subsystem_expected_enabled,
    doctor,
)
from defenseclaw.doctor_gateway import (
    ListenerEvidence,
    PIDRecord,
    ProcessEvidence,
    pid_file_fingerprint,
    pid_file_fingerprint_from_fd,
    read_pid_record,
)


def _cfg(data_dir: str, *, token: str = "", token_env: str = "") -> SimpleNamespace:
    config_path = os.path.join(data_dir, "config.yaml")
    if not os.path.exists(config_path):
        with open(config_path, "w", encoding="utf-8") as fh:
            fh.write("config_version: 8\n")
    gateway = SimpleNamespace(
        api_port=18970,
        token_env=token_env,
        resolved_token=lambda: token,
    )
    return SimpleNamespace(
        data_dir=data_dir,
        gateway=gateway,
        active_connector=lambda: "codex",
    )


def _strong_gateway_trust(
    data_dir: str,
    *,
    pid: int = 4242,
    start_identity: str = "100",
) -> _GatewayTrust:
    executable = "/opt/defenseclaw/bin/defenseclaw-gateway"
    record = PIDRecord(
        "ok",
        pid=pid,
        executable=executable,
        start_identity=start_identity,
        data_dir=data_dir,
    )
    process = ProcessEvidence(
        "ok",
        pid=pid,
        executable=executable,
        start_identity=start_identity,
    )
    return _GatewayTrust(
        "trusted",
        "managed gateway owns the configured API endpoint",
        pid,
        home_bound=True,
        record=record,
        process=process,
    )


def _health(**states: str) -> str:
    return json.dumps({name: {"state": state} for name, state in states.items()})


def _runtime_status(data_dir: str, *, pid: int = 4242) -> str:
    return json.dumps({"runtime": {"pid": pid, "data_dir": data_dir}})


@pytest.mark.parametrize(
    ("global_enabled", "connector_enabled", "expected"),
    [
        (False, True, False),
        (True, False, False),
        (True, True, True),
    ],
)
def test_guardrail_subsystem_expectation_requires_global_and_connector_enablement(
    global_enabled,
    connector_enabled,
    expected,
):
    cfg = SimpleNamespace(
        guardrail=SimpleNamespace(
            enabled=global_enabled,
            effective_enabled=lambda _connector: connector_enabled,
        ),
        active_connectors=lambda: ["codex"],
        active_connector=lambda: "codex",
    )

    assert _subsystem_expected_enabled(cfg, "guardrail") is expected


def test_gateway_auth_fails_actionably_when_token_missing(tmp_path):
    result = _DoctorResult()

    _check_gateway_auth(_cfg(str(tmp_path)), result)

    row = next(row for row in result.checks if row["label"] == "Gateway authentication")
    assert row["status"] == "fail"
    assert "doctor --fix" in row["detail"]


def test_gateway_auth_probes_status_with_bearer_without_rendering_token(tmp_path):
    result = _DoctorResult()
    secret = "never-render-this-token"

    with (
        patch(
            "defenseclaw.commands.cmd_doctor._http_probe",
            return_value=(200, _runtime_status(str(tmp_path))),
        ) as probe,
        patch(
            "defenseclaw.commands.cmd_doctor._trusted_gateway_listener",
            return_value=_strong_gateway_trust(str(tmp_path)),
        ),
    ):
        _check_gateway_auth(_cfg(str(tmp_path), token=secret), result)

    check = result.checks[-1]
    assert check["status"] == "pass"
    assert check["label"] == "Gateway authentication"
    assert check["detail"] == "local token accepted"
    assert check["check_id"].startswith("doctor.check.general.gateway.authentication.")
    assert check["section"] == "general"
    assert check["reason_code"] == ""
    assert check["remediation"] == ""
    assert check["duration_ms"] == 0
    assert probe.call_args.kwargs["headers"] == {"Authorization": f"Bearer {secret}"}
    assert secret not in repr(result.checks)


def test_gateway_auth_reports_unauthorized_as_fixable(tmp_path):
    result = _DoctorResult()

    with (
        patch("defenseclaw.commands.cmd_doctor._http_probe", return_value=(401, "unauthorized")),
        patch(
            "defenseclaw.commands.cmd_doctor._trusted_gateway_listener",
            return_value=_strong_gateway_trust(str(tmp_path)),
        ),
    ):
        _check_gateway_auth(_cfg(str(tmp_path), token="configured"), result)

    row = result.checks[-1]
    assert row["status"] == "fail"
    assert "HTTP 401" in row["detail"]
    assert "doctor --fix" in row["detail"]


def test_gateway_auth_refuses_token_for_foreign_listener(tmp_path):
    result = _DoctorResult()
    secret = "must-not-be-sent"

    with (
        patch(
            "defenseclaw.commands.cmd_doctor._trusted_gateway_listener",
            return_value=_GatewayTrust("foreign_listener", "owned by another process"),
        ),
        patch("defenseclaw.commands.cmd_doctor._http_probe") as probe,
    ):
        _check_gateway_auth(_cfg(str(tmp_path), token=secret), result)

    row = result.checks[-1]
    assert row["status"] == "fail"
    assert "refusing to send" in row["detail"]
    assert secret not in repr(result.to_dict())
    probe.assert_not_called()


def test_gateway_auth_refuses_token_when_pid_identity_is_not_gateway(tmp_path):
    result = _DoctorResult()

    with (
        patch(
            "defenseclaw.commands.cmd_doctor._trusted_gateway_listener",
            return_value=_GatewayTrust("identity", "managed gateway process identity could not be verified"),
        ),
        patch("defenseclaw.commands.cmd_doctor._http_probe") as probe,
    ):
        _check_gateway_auth(_cfg(str(tmp_path), token="must-not-be-sent"), result)

    assert result.checks[-1]["status"] == "fail"
    assert "identity could not be verified" in result.checks[-1]["detail"]
    probe.assert_not_called()


def test_gateway_auth_treats_whitespace_only_token_as_missing(tmp_path):
    result = _DoctorResult()

    _check_gateway_auth(_cfg(str(tmp_path), token=" \t "), result)

    assert result.checks[-1]["status"] == "fail"
    assert "doctor --fix" in result.checks[-1]["detail"]


def test_gateway_auth_missing_custom_provider_has_no_false_fix_hint(tmp_path):
    result = _DoctorResult()
    cfg = _cfg(str(tmp_path), token="", token_env="VAULT_GATEWAY_TOKEN")

    _check_gateway_auth(cfg, result)

    detail = result.checks[-1]["detail"]
    assert result.checks[-1]["status"] == "fail"
    assert "VAULT_GATEWAY_TOKEN" in detail
    assert "auto-fix preserves custom providers" in detail
    assert "doctor --fix" not in detail


def test_gateway_auth_fails_closed_for_unowned_non_loopback_bind(tmp_path):
    result = _DoctorResult()
    cfg = _cfg(str(tmp_path), token="configured")
    cfg.gateway.api_bind = "10.200.0.1"

    with patch("defenseclaw.commands.cmd_doctor._http_probe") as probe:
        _check_gateway_auth(cfg, result)

    assert result.checks[-1]["status"] == "fail"
    assert "PID file is missing" in result.checks[-1]["detail"]
    assert "refusing to send" in result.checks[-1]["detail"]
    probe.assert_not_called()


def test_loopback_http_probe_never_uses_environment_proxy():
    observed_requests: list[str] = []

    class _Proxy(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            observed_requests.append(self.path)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"proxy impersonated local gateway")

        def log_message(self, *_args):
            pass

    proxy = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Proxy)
    thread = threading.Thread(target=proxy.serve_forever, daemon=True)
    thread.start()
    target = socket.socket()
    target.bind(("127.0.0.1", 0))
    unused_port = target.getsockname()[1]
    proxy_url = f"http://127.0.0.1:{proxy.server_port}"
    try:
        with patch.dict(
            os.environ,
            {
                "HTTP_PROXY": proxy_url,
                "http_proxy": proxy_url,
                "NO_PROXY": "",
                "no_proxy": "",
            },
            clear=False,
        ):
            code, _ = _http_probe(
                f"http://127.0.0.1:{unused_port}/status",
                headers={"Authorization": "Bearer must-not-reach-proxy"},
                timeout=0.25,
            )
    finally:
        target.close()
        proxy.shutdown()
        proxy.server_close()
        thread.join(timeout=2)

    assert code == 0
    assert observed_requests == []


def test_http_probe_normalizes_malformed_ipv6_authority() -> None:
    code, detail = _http_probe("http://[::1/status", timeout=0.1)

    assert code == 0
    assert detail


@pytest.mark.skipif(os.name == "nt", reason="/proc socket layout is POSIX-only")
def test_linux_listener_owner_falls_back_to_proc_without_lsof(tmp_path):
    proc_root = tmp_path / "proc"
    net = proc_root / "net"
    descriptors = proc_root / "4242" / "fd"
    net.mkdir(parents=True)
    descriptors.mkdir(parents=True)
    port = 18_970
    header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"
    row = f"   0: 0100007F:{port:04X} 00000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 12345 1\n"
    (net / "tcp").write_text(header + row, encoding="ascii")
    (net / "tcp6").write_text(header, encoding="ascii")
    os.symlink("socket:[12345]", descriptors / "3")

    assert _linux_gateway_listener_pid(port, proc_root=str(proc_root)) == 4242


@pytest.mark.skipif(os.name == "nt", reason="/proc socket layout is POSIX-only")
def test_linux_listener_owner_filters_the_exact_connect_address(tmp_path):
    proc_root = tmp_path / "proc"
    net = proc_root / "net"
    for pid in ("4242", "9001"):
        (proc_root / pid / "fd").mkdir(parents=True)
    net.mkdir(exist_ok=True)
    port = 18_970
    header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"
    rows = (
        f" 0: 0100007F:{port:04X} 00000000:0000 0A "
        "00000000:00000000 00:00000000 00000000 1000 0 12345 1\n"
        f" 1: 0100A8C0:{port:04X} 00000000:0000 0A "
        "00000000:00000000 00:00000000 00000000 1000 0 67890 1\n"
    )
    (net / "tcp").write_text(header + rows, encoding="ascii")
    (net / "tcp6").write_text(header, encoding="ascii")
    os.symlink("socket:[12345]", proc_root / "4242" / "fd" / "3")
    os.symlink("socket:[67890]", proc_root / "9001" / "fd" / "3")

    assert (
        _linux_gateway_listener_pid(
            port,
            host="127.0.0.1",
            proc_root=str(proc_root),
        )
        == 4242
    )


def test_lsof_listener_owner_fails_closed_when_multiple_pids_are_reported():
    completed = SimpleNamespace(
        returncode=0,
        stdout="p4242\nf3\nn127.0.0.1:18970\np9001\nf4\nn*:18970\n",
    )
    with (
        patch(
            "defenseclaw.commands.cmd_doctor._trusted_lsof_path",
            return_value="/usr/sbin/lsof",
        ),
        patch("defenseclaw.commands.cmd_doctor.subprocess.run", return_value=completed),
    ):
        assert _gateway_listener_pid(18_970, host="127.0.0.1") == 0


def test_lsof_listener_owner_filters_the_exact_connect_address():
    completed = SimpleNamespace(
        returncode=0,
        stdout=("p4242\nf3\nn127.0.0.2:18970\np9001\nf4\nn127.0.0.3:18970\n"),
    )
    with (
        patch(
            "defenseclaw.commands.cmd_doctor._trusted_lsof_path",
            return_value="/usr/sbin/lsof",
        ),
        patch(
            "defenseclaw.commands.cmd_doctor.subprocess.run",
            return_value=completed,
        ) as run,
    ):
        assert _gateway_listener_pid(18_970, host="127.0.0.2") == 4242

    assert "-i4TCP:18970" in run.call_args.args[0]
    assert "-Fpn" in run.call_args.args[0]


def test_lsof_listener_owner_accepts_wildcard_bind_for_loopback_target():
    completed = SimpleNamespace(returncode=0, stdout="p4242\nf3\nn*:18970\n")
    with (
        patch(
            "defenseclaw.commands.cmd_doctor._trusted_lsof_path",
            return_value="/usr/sbin/lsof",
        ),
        patch("defenseclaw.commands.cmd_doctor.subprocess.run", return_value=completed),
    ):
        assert _gateway_listener_pid(18_970, host="127.0.0.1") == 4242


def test_environment_name_comparison_matches_windows_semantics():
    assert _env_names_equal(
        "defenseclaw_gateway_token",
        "DEFENSECLAW_GATEWAY_TOKEN",
        platform_name="nt",
    )
    assert not _env_names_equal(
        "defenseclaw_gateway_token",
        "DEFENSECLAW_GATEWAY_TOKEN",
        platform_name="posix",
    )


def test_doctor_repairs_before_running_diagnostics():
    order = []

    def _fixers(*_args, **_kwargs):
        order.append("fix")

    def _first_check(*_args, **_kwargs):
        order.append("check")
        raise RuntimeError("stop after ordering assertion")

    raw_doctor = doctor.callback.__wrapped__
    app = SimpleNamespace(cfg=SimpleNamespace())
    with (
        patch(
            "defenseclaw.commands.cmd_doctor._run_fixers_with_lock",
            side_effect=_fixers,
        ),
        patch("defenseclaw.commands.cmd_doctor._check_config", side_effect=_first_check),
        pytest.raises(RuntimeError, match="ordering assertion"),
    ):
        raw_doctor(app, json_out=False, do_fix=True, assume_yes=True, dry_run=False)

    assert order == ["fix", "check"]


def test_fix_gateway_token_generates_private_canonical_token(tmp_path):
    cfg = _cfg(str(tmp_path))
    clean_env = {
        key: value
        for key, value in os.environ.items()
        if key not in {"DEFENSECLAW_GATEWAY_TOKEN", "OPENCLAW_GATEWAY_TOKEN"}
    }

    with (
        patch.dict(os.environ, clean_env, clear=True),
        patch("secrets.token_hex", return_value="ab" * 32),
    ):
        tag, detail = _fix_gateway_token(cfg, assume_yes=True)
        assert os.environ["DEFENSECLAW_GATEWAY_TOKEN"] == "ab" * 32

    dotenv = tmp_path / ".env"
    assert tag == "pass"
    assert "value redacted" in detail
    assert dotenv.read_text(encoding="utf-8").strip() == f"DEFENSECLAW_GATEWAY_TOKEN={'ab' * 32}"
    if os.name != "nt":
        assert stat.S_IMODE(dotenv.stat().st_mode) == 0o600


def test_fix_gateway_token_replaces_whitespace_only_canonical_value(tmp_path):
    cfg = _cfg(str(tmp_path), token=" \t ")

    with patch("secrets.token_hex", return_value="12" * 32):
        tag, _ = _fix_gateway_token(cfg, assume_yes=True)

    assert tag == "pass"
    assert (tmp_path / ".env").read_text(encoding="utf-8").strip().endswith("12" * 32)


def test_fix_gateway_token_does_not_initialize_missing_config(tmp_path):
    cfg = _cfg(str(tmp_path))
    (tmp_path / "config.yaml").unlink()

    tag, detail = _fix_gateway_token(cfg, assume_yes=True)

    assert tag == "skip"
    assert "defenseclaw init" in detail
    assert not (tmp_path / ".env").exists()


def test_fix_gateway_token_preserves_custom_token_provider(tmp_path):
    cfg = _cfg(str(tmp_path), token_env="VAULT_MANAGED_GATEWAY_TOKEN")

    tag, detail = _fix_gateway_token(cfg, assume_yes=True)

    assert tag == "skip"
    assert "externally managed" in detail
    assert not (tmp_path / ".env").exists()


def test_fix_gateway_token_generates_canonical_token_when_openclaw_has_none(tmp_path):
    cfg = _cfg(str(tmp_path))
    cfg.active_connector = lambda: "openclaw"
    cfg.claw = SimpleNamespace(config_file=str(tmp_path / "openclaw.json"))
    clean_env = {
        key: value
        for key, value in os.environ.items()
        if key not in {"DEFENSECLAW_GATEWAY_TOKEN", "OPENCLAW_GATEWAY_TOKEN"}
    }

    with (
        patch.dict(os.environ, clean_env, clear=True),
        patch(
            "defenseclaw.commands.cmd_setup._detect_openclaw_gateway_token",
            return_value="",
        ),
        patch("secrets.token_hex", return_value="ef" * 32),
    ):
        tag, detail = _fix_gateway_token(cfg, assume_yes=True)

    assert tag == "pass"
    assert "DEFENSECLAW_GATEWAY_TOKEN" in detail
    assert "OPENCLAW_GATEWAY_TOKEN" not in (tmp_path / ".env").read_text(encoding="utf-8")


def test_fix_stale_pid_removes_malformed_file(tmp_path):
    pid_file = tmp_path / "gateway.pid"
    pid_file.write_text("{broken", encoding="utf-8")
    cfg = SimpleNamespace(data_dir=str(tmp_path))

    with patch(
        "defenseclaw.commands.cmd_doctor._verified_listener_gateway_evidence",
        return_value=ListenerEvidence("missing", reason="no listener"),
    ):
        tag, detail = _fix_stale_pid(cfg, assume_yes=True)

    assert tag == "pass"
    assert "malformed" in detail
    assert not pid_file.exists()


def test_fix_stale_pid_parses_fingerprinted_a_during_a_b_a_read_swap(tmp_path):
    pid_file = tmp_path / "gateway.pid"
    original = tmp_path / "original.pid"
    replacement = tmp_path / "replacement.pid"
    pid_file.write_bytes(b"{malformed-a")
    executable = "/opt/defenseclaw/bin/defenseclaw-gateway"
    replacement.write_text(
        json.dumps(
            {
                "pid": 4242,
                "executable": executable,
                "start_identity": "replacement-start",
                "data_dir": os.fspath(tmp_path),
            }
        ),
        encoding="utf-8",
    )
    cfg = SimpleNamespace(data_dir=os.fspath(tmp_path))
    evidence = SimpleNamespace(
        process=lambda pid: ProcessEvidence(
            "ok",
            pid=pid,
            executable=executable,
            start_identity="replacement-start",
        )
    )
    real_read = read_pid_record
    swapped_reads = 0

    def read_b_then_restore_a(path):
        nonlocal swapped_reads
        swapped_reads += 1
        os.replace(pid_file, original)
        os.replace(replacement, pid_file)
        try:
            return real_read(path)
        finally:
            os.replace(pid_file, replacement)
            os.replace(original, pid_file)

    with (
        patch(
            "defenseclaw.commands.cmd_doctor.read_pid_record",
            side_effect=read_b_then_restore_a,
        ),
        patch(
            "defenseclaw.commands.cmd_doctor._verified_listener_gateway_evidence",
            return_value=ListenerEvidence("missing", reason="no listener"),
        ),
    ):
        tag, detail = _fix_stale_pid(
            cfg,
            assume_yes=True,
            evidence=evidence,
            platform_name="linux",
        )

    assert tag == "pass", detail
    assert swapped_reads == 0
    assert not pid_file.exists()
    assert replacement.exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX atomic quarantine regression")
def test_posix_stale_pid_removal_preserves_replacement_published_after_claim(tmp_path):
    pid_file = tmp_path / "gateway.pid"
    pid_file.write_bytes(b"{old")
    inspected = pid_file_fingerprint(os.fspath(pid_file))
    assert inspected is not None
    real_fingerprint = pid_file_fingerprint

    def publish_replacement_after_claim(path):
        pid_file.write_bytes(b"{replacement")
        return real_fingerprint(path)

    with patch(
        "defenseclaw.commands.cmd_doctor.pid_file_fingerprint",
        side_effect=publish_replacement_after_claim,
    ):
        tag, detail = _remove_stale_pid_if_unchanged(
            os.fspath(pid_file),
            inspected,
            platform_name="linux",
        )

    assert (tag, detail) == ("pass", "")
    assert pid_file.read_bytes() == b"{replacement"
    assert not tuple(tmp_path.glob(".gateway-pid-doctor-*"))


@pytest.mark.skipif(os.name == "nt", reason="POSIX atomic quarantine regression")
def test_posix_stale_pid_removal_does_not_delete_racing_replacement(tmp_path):
    pid_file = tmp_path / "gateway.pid"
    replacement = tmp_path / "replacement.pid"
    pid_file.write_bytes(b"{old")
    replacement.write_bytes(b"{replacement")
    inspected = pid_file_fingerprint(os.fspath(pid_file))
    assert inspected is not None
    real_rename = os.rename

    def publish_replacement_before_claim(source, destination):
        os.replace(replacement, source)
        real_rename(source, destination)

    with patch(
        "defenseclaw.commands.cmd_doctor.os.rename",
        side_effect=publish_replacement_before_claim,
    ):
        tag, detail = _remove_stale_pid_if_unchanged(
            os.fspath(pid_file),
            inspected,
            platform_name="linux",
        )

    assert tag == "warn"
    assert "restored without overwrite" in detail
    assert pid_file.read_bytes() == b"{replacement"
    quarantine = next(tmp_path.glob(".gateway-pid-doctor-*/gateway.pid"))
    assert quarantine.read_bytes() == b"{replacement"
    assert os.path.samefile(pid_file, quarantine)


@pytest.mark.skipif(os.name == "nt", reason="POSIX atomic quarantine regression")
def test_posix_stale_pid_removal_preserves_two_concurrent_replacements(tmp_path):
    pid_file = tmp_path / "gateway.pid"
    first_replacement = tmp_path / "first-replacement.pid"
    pid_file.write_bytes(b"{old")
    first_replacement.write_bytes(b"{replacement-b")
    inspected = pid_file_fingerprint(os.fspath(pid_file))
    assert inspected is not None
    real_rename = os.rename
    real_link = os.link

    def publish_first_replacement_before_claim(source, destination):
        os.replace(first_replacement, source)
        real_rename(source, destination)

    def publish_second_replacement_before_restore(source, destination, **kwargs):
        with open(destination, "xb") as handle:
            handle.write(b"{replacement-c")
        return real_link(source, destination, **kwargs)

    with (
        patch(
            "defenseclaw.commands.cmd_doctor.os.rename",
            side_effect=publish_first_replacement_before_claim,
        ),
        patch(
            "defenseclaw.commands.cmd_doctor.os.link",
            side_effect=publish_second_replacement_before_restore,
        ),
    ):
        tag, detail = _remove_stale_pid_if_unchanged(
            os.fspath(pid_file),
            inspected,
            platform_name="darwin",
        )

    assert tag == "fail"
    assert "both preserved" in detail
    assert pid_file.read_bytes() == b"{replacement-c"
    quarantine = next(tmp_path.glob(".gateway-pid-doctor-*/gateway.pid"))
    assert quarantine.read_bytes() == b"{replacement-b"


def test_windows_stale_pid_removal_fingerprints_and_deletes_one_claimed_handle(tmp_path):
    pid_file = tmp_path / "gateway.pid"
    pid_file.write_bytes(b"{broken")
    inspected = pid_file_fingerprint(os.fspath(pid_file))
    assert inspected is not None
    events: list[tuple[str, int]] = []
    claimed_fd = -1

    def claim(path):
        nonlocal claimed_fd
        claimed_fd = os.open(path, os.O_RDONLY)
        events.append(("claim", claimed_fd))
        return claimed_fd

    def fingerprint(fd):
        events.append(("fingerprint", fd))
        return pid_file_fingerprint_from_fd(fd)

    def delete(fd):
        events.append(("delete", fd))
        assert fd == claimed_fd

    with (
        patch("defenseclaw.windows_acl.open_regular_mutation_fd", side_effect=claim),
        patch("defenseclaw.windows_acl.delete_regular_fd", side_effect=delete),
        patch(
            "defenseclaw.commands.cmd_doctor.pid_file_fingerprint_from_fd",
            side_effect=fingerprint,
        ),
    ):
        tag, detail = _remove_stale_pid_if_unchanged(
            os.fspath(pid_file),
            inspected,
            platform_name="win32",
        )

    assert (tag, detail) == ("pass", "")
    assert events == [
        ("claim", claimed_fd),
        ("fingerprint", claimed_fd),
        ("delete", claimed_fd),
    ]
    with pytest.raises(OSError):
        os.fstat(claimed_fd)
    assert pid_file.exists()


def test_windows_stale_pid_removal_preserves_replacement_opened_by_claim(tmp_path):
    pid_file = tmp_path / "gateway.pid"
    replacement = tmp_path / "replacement.pid"
    pid_file.write_bytes(b"{old")
    replacement.write_bytes(b"{replacement")
    inspected = pid_file_fingerprint(os.fspath(pid_file))
    assert inspected is not None

    def claim_replacement(path):
        os.replace(replacement, path)
        return os.open(path, os.O_RDONLY)

    with (
        patch(
            "defenseclaw.windows_acl.open_regular_mutation_fd",
            side_effect=claim_replacement,
        ),
        patch("defenseclaw.windows_acl.delete_regular_fd") as delete,
    ):
        tag, detail = _remove_stale_pid_if_unchanged(
            os.fspath(pid_file),
            inspected,
            platform_name="win32",
        )

    assert tag == "warn"
    assert "changed or disappeared after inspection" in detail
    delete.assert_not_called()
    assert pid_file.read_bytes() == b"{replacement"


def test_windows_stale_pid_removal_fails_on_claimed_handle_read_error(tmp_path):
    pid_file = tmp_path / "gateway.pid"
    pid_file.write_bytes(b"{old")
    inspected = pid_file_fingerprint(os.fspath(pid_file))
    assert inspected is not None
    claimed_fd = -1

    def claim(path):
        nonlocal claimed_fd
        claimed_fd = os.open(path, os.O_RDONLY)
        return claimed_fd

    with (
        patch("defenseclaw.windows_acl.open_regular_mutation_fd", side_effect=claim),
        patch("defenseclaw.windows_acl.delete_regular_fd") as delete,
        patch(
            "defenseclaw.commands.cmd_doctor.pid_file_fingerprint_from_fd",
            side_effect=OSError("claimed-handle read failed"),
        ),
    ):
        tag, detail = _remove_stale_pid_if_unchanged(
            os.fspath(pid_file),
            inspected,
            platform_name="win32",
        )

    assert tag == "fail"
    assert "verified handle" in detail
    delete.assert_not_called()
    with pytest.raises(OSError):
        os.fstat(claimed_fd)
    assert pid_file.read_bytes() == b"{old"


@pytest.mark.parametrize(
    ("error", "expected_tag", "expected_detail"),
    [
        (FileNotFoundError(2, "missing"), "warn", "changed or disappeared after inspection"),
        (OSError(32, "sharing violation"), "fail", "exclusively claim"),
    ],
)
def test_windows_stale_pid_removal_fails_closed_when_claim_is_unavailable(
    tmp_path,
    error,
    expected_tag,
    expected_detail,
):
    pid_file = tmp_path / "gateway.pid"
    pid_file.write_bytes(b"{old")
    inspected = pid_file_fingerprint(os.fspath(pid_file))
    assert inspected is not None

    with (
        patch(
            "defenseclaw.windows_acl.open_regular_mutation_fd",
            side_effect=error,
        ),
        patch("defenseclaw.windows_acl.delete_regular_fd") as delete,
    ):
        tag, detail = _remove_stale_pid_if_unchanged(
            os.fspath(pid_file),
            inspected,
            platform_name="win32",
        )

    assert tag == expected_tag
    assert expected_detail in detail
    delete.assert_not_called()
    assert pid_file.read_bytes() == b"{old"


def test_fix_stale_pid_preserves_malformed_record_for_live_gateway(tmp_path):
    pid_file = tmp_path / "gateway.pid"
    pid_file.write_text("{broken", encoding="utf-8")
    cfg = _cfg(str(tmp_path))

    with patch(
        "defenseclaw.commands.cmd_doctor._verified_listener_gateway_evidence",
        return_value=ListenerEvidence("ok", pid=4242),
    ):
        tag, detail = _fix_stale_pid(cfg, assume_yes=True)

    assert tag == "warn"
    assert "preserving" in detail
    assert pid_file.exists()


def test_fix_stale_pid_preserves_home_bound_rich_identity(tmp_path):
    pid_file = tmp_path / "gateway.pid"
    executable = "/opt/defenseclaw/bin/defenseclaw-gateway"
    pid_file.write_text(
        json.dumps(
            {
                "pid": 4242,
                "executable": executable,
                "start_identity": "100",
                "data_dir": str(tmp_path),
            }
        ),
        encoding="utf-8",
    )
    cfg = SimpleNamespace(data_dir=str(tmp_path))
    evidence = SimpleNamespace(
        process=lambda pid: ProcessEvidence(
            "ok",
            pid=pid,
            executable=executable,
            start_identity="100",
        )
    )

    tag, detail = _fix_stale_pid(
        cfg,
        assume_yes=True,
        evidence=evidence,
        platform_name="linux",
    )

    assert tag == "skip"
    assert "data-home identity" in detail
    assert pid_file.exists()


def test_fix_stale_pid_preserves_legacy_live_gateway_for_manual_migration(tmp_path):
    pid_file = tmp_path / "gateway.pid"
    pid_file.write_text("4242", encoding="utf-8")
    cfg = SimpleNamespace(data_dir=str(tmp_path))
    evidence = SimpleNamespace(
        process=lambda pid: ProcessEvidence(
            "ok",
            pid=pid,
            executable="/opt/defenseclaw/bin/defenseclaw-gateway",
            start_identity="100",
        )
    )

    tag, detail = _fix_stale_pid(
        cfg,
        assume_yes=True,
        evidence=evidence,
        platform_name="linux",
    )

    assert tag == "warn"
    assert "legacy PID record" in detail
    assert "preserving" in detail
    assert pid_file.exists()


def test_fix_stale_pid_removes_rich_record_for_non_gateway_identity(tmp_path):
    pid_file = tmp_path / "gateway.pid"
    pid_file.write_text(
        json.dumps(
            {
                "pid": 4242,
                "executable": "/opt/defenseclaw/bin/defenseclaw-gateway",
                "start_identity": "100",
                "data_dir": str(tmp_path),
            }
        ),
        encoding="utf-8",
    )
    cfg = SimpleNamespace(data_dir=str(tmp_path))
    evidence = SimpleNamespace(
        process=lambda pid: ProcessEvidence(
            "ok",
            pid=pid,
            executable="/usr/bin/unrelated-process",
            start_identity="100",
        )
    )

    tag, detail = _fix_stale_pid(
        cfg,
        assume_yes=True,
        evidence=evidence,
        platform_name="linux",
    )

    assert tag == "pass"
    assert "unexpected executable" in detail
    assert not pid_file.exists()


def test_fix_gateway_token_env_does_not_create_missing_config(tmp_path):
    cfg = _cfg(str(tmp_path))
    (tmp_path / "config.yaml").unlink()
    cfg.gateway.token_env = "OPENCLAW_GATEWAY_TOKEN"
    cfg.save = pytest.fail

    with patch.dict(os.environ, {"DEFENSECLAW_GATEWAY_TOKEN": "configured"}, clear=False):
        tag, detail = _fix_gateway_token_env(cfg, assume_yes=True)

    assert tag == "skip"
    assert "refusing to create" in detail
    assert not (tmp_path / "config.yaml").exists()


def test_fixer_exception_is_a_redacted_failure(tmp_path):
    cfg = _cfg(str(tmp_path))
    result = _DoctorResult()
    secret = "do-not-render-this-secret"
    no_op = ("skip", "not applicable")

    with (
        patch(
            "defenseclaw.commands.cmd_doctor._fix_stale_pid",
            side_effect=RuntimeError(secret),
        ),
        patch("defenseclaw.commands.cmd_doctor._fix_gateway_token", return_value=no_op),
        patch("defenseclaw.commands.cmd_doctor._fix_gateway_token_env", return_value=no_op),
        patch("defenseclaw.commands.cmd_doctor._fix_gateway_token_drift", return_value=no_op),
        patch("defenseclaw.commands.cmd_doctor._fix_gateway_service", return_value=no_op),
        patch("defenseclaw.commands.cmd_doctor._fix_dotenv_perms", return_value=no_op),
        patch("defenseclaw.commands.cmd_doctor._fix_pristine_backup", return_value=no_op),
        patch("defenseclaw.commands.cmd_doctor._fix_plugin_registry_required", return_value=no_op),
        patch(
            "defenseclaw.config_inspect.inspect_v8_config",
            return_value=SimpleNamespace(valid=True),
        ),
    ):
        _run_fixers(
            cfg,
            result,
            assume_yes=True,
            json_out=True,
        )

    failure = next(row for row in result.repairs if row["repair_id"] == "doctor.gateway.pid.remove-stale")
    assert failure["state"] == "blocked"
    assert failure["detail"] == "RuntimeError: planner raised unexpectedly"
    assert result.failed == 0
    assert result.repair_summary.blocked >= 1
    assert secret not in repr(result.to_dict())


def test_fix_gateway_drift_uses_http_rejection_when_process_env_is_unreadable(tmp_path):
    token = "cd" * 32
    (tmp_path / ".env").write_text(
        f"DEFENSECLAW_GATEWAY_TOKEN={token}\n",
        encoding="utf-8",
    )
    (tmp_path / "gateway.pid").write_text(str(os.getpid()), encoding="utf-8")
    cfg = _cfg(str(tmp_path), token=token)

    with (
        patch(
            "defenseclaw.commands.cmd_doctor._http_probe",
            side_effect=[(401, ""), (200, _runtime_status(str(tmp_path), pid=os.getpid()))],
        ),
        patch(
            "defenseclaw.commands.cmd_doctor._managed_gateway_process_trust",
            return_value=_strong_gateway_trust(str(tmp_path), pid=os.getpid()),
        ),
        patch(
            "defenseclaw.commands.cmd_doctor._trusted_gateway_listener",
            return_value=_strong_gateway_trust(str(tmp_path), pid=os.getpid()),
        ),
        patch("defenseclaw.commands.cmd_doctor._read_process_env_var") as process_env,
        patch(
            "defenseclaw.commands.cmd_doctor._repair_gateway_lifecycle",
            return_value=(True, ""),
        ) as repair,
    ):
        tag, detail = _fix_gateway_token_drift(cfg, assume_yes=True)

    assert tag == "pass"
    assert "restarted" in detail
    process_env.assert_not_called()
    repair.assert_called_once_with(cfg, start_if_stopped=False)


def test_fix_gateway_drift_restarts_rejected_custom_provider_without_rewriting_it(tmp_path):
    token = "vault-managed-token"
    cfg = _cfg(str(tmp_path), token=token, token_env="VAULT_GATEWAY_TOKEN")
    (tmp_path / "gateway.pid").write_text(str(os.getpid()), encoding="utf-8")

    with (
        patch(
            "defenseclaw.commands.cmd_doctor._http_probe",
            side_effect=[(403, ""), (200, _runtime_status(str(tmp_path), pid=os.getpid()))],
        ) as probe,
        patch(
            "defenseclaw.commands.cmd_doctor._managed_gateway_process_trust",
            return_value=_strong_gateway_trust(str(tmp_path), pid=os.getpid()),
        ),
        patch(
            "defenseclaw.commands.cmd_doctor._trusted_gateway_listener",
            return_value=_strong_gateway_trust(str(tmp_path), pid=os.getpid()),
        ),
        patch(
            "defenseclaw.commands.cmd_doctor._repair_gateway_lifecycle",
            return_value=(True, ""),
        ) as repair,
    ):
        tag, detail = _fix_gateway_token_drift(cfg, assume_yes=True)

    assert tag == "pass"
    assert "authenticated token acceptance was verified" in detail
    assert probe.call_args.kwargs["headers"] == {"Authorization": f"Bearer {token}"}
    repair.assert_called_once_with(cfg, start_if_stopped=False)
    assert not (tmp_path / ".env").exists()


def test_gateway_drift_prefers_daemon_dotenv_over_stale_export_and_rechecks_auth(tmp_path):
    new_token = "new-daemon-token"
    old_token = "old-exported-token"
    (tmp_path / ".env").write_text(
        f"DEFENSECLAW_GATEWAY_TOKEN={new_token}\n",
        encoding="utf-8",
    )
    (tmp_path / "gateway.pid").write_text(str(os.getpid()), encoding="utf-8")
    cfg = _cfg(str(tmp_path), token=old_token)
    observed_headers = []

    def _probe(*_args, **kwargs):
        observed_headers.append(kwargs["headers"])
        return (401, "") if len(observed_headers) == 1 else (200, _runtime_status(str(tmp_path), pid=os.getpid()))

    with (
        patch.dict(os.environ, {"DEFENSECLAW_GATEWAY_TOKEN": old_token}, clear=False),
        patch("defenseclaw.commands.cmd_doctor._http_probe", side_effect=_probe),
        patch(
            "defenseclaw.commands.cmd_doctor._managed_gateway_process_trust",
            return_value=_strong_gateway_trust(str(tmp_path), pid=os.getpid()),
        ),
        patch(
            "defenseclaw.commands.cmd_doctor._trusted_gateway_listener",
            return_value=_strong_gateway_trust(str(tmp_path), pid=os.getpid()),
        ),
        patch(
            "defenseclaw.commands.cmd_doctor._repair_gateway_lifecycle",
            return_value=(True, ""),
        ),
    ):
        assert _daemon_effective_gateway_token(cfg)[0] == new_token
        tag, detail = _fix_gateway_token_drift(cfg, assume_yes=True)

    assert tag == "pass"
    assert "acceptance was verified" in detail
    assert observed_headers == [
        {"Authorization": f"Bearer {new_token}"},
        {"Authorization": f"Bearer {new_token}"},
    ]


def test_gateway_drift_does_not_report_success_when_post_restart_auth_still_fails(tmp_path):
    token = "configured-token"
    (tmp_path / ".env").write_text(
        f"DEFENSECLAW_GATEWAY_TOKEN={token}\n",
        encoding="utf-8",
    )
    (tmp_path / "gateway.pid").write_text(str(os.getpid()), encoding="utf-8")
    cfg = _cfg(str(tmp_path), token=token)

    with (
        patch(
            "defenseclaw.commands.cmd_doctor._http_probe",
            side_effect=[(401, ""), (401, "")],
        ),
        patch(
            "defenseclaw.commands.cmd_doctor._managed_gateway_process_trust",
            return_value=_strong_gateway_trust(str(tmp_path), pid=os.getpid()),
        ),
        patch(
            "defenseclaw.commands.cmd_doctor._trusted_gateway_listener",
            return_value=_strong_gateway_trust(str(tmp_path), pid=os.getpid()),
        ),
        patch(
            "defenseclaw.commands.cmd_doctor._repair_gateway_lifecycle",
            return_value=(True, ""),
        ),
    ):
        tag, detail = _fix_gateway_token_drift(cfg, assume_yes=True)

    assert tag == "fail"
    assert "still rejects" in detail


@pytest.mark.parametrize(
    ("drift", "before_health", "after_health", "expected_reason"),
    [
        (
            "api",
            _health(api="stopped"),
            _health(api="running"),
            "required api subsystem reports stopped",
        ),
        (
            "guardrail",
            _health(api="running", guardrail="disabled"),
            _health(api="running", guardrail="running"),
            "guardrail is enabled in config but reports disabled",
        ),
        (
            "watcher",
            _health(api="running", watcher="running"),
            _health(api="running", watcher="disabled"),
            "watcher is disabled in config but reports running",
        ),
        (
            "sandbox",
            _health(api="running", sandbox="running"),
            _health(api="running", sandbox="disabled"),
            "sandbox is disabled in config but reports running",
        ),
    ],
)
def test_fix_gateway_service_restarts_deterministic_config_runtime_drift(
    tmp_path,
    drift,
    before_health,
    after_health,
    expected_reason,
):
    cfg = _cfg(str(tmp_path), token="configured")
    if drift == "guardrail":
        cfg.guardrail = SimpleNamespace(enabled=True)
    if drift == "watcher":
        cfg.gateway.watcher = SimpleNamespace(enabled=False)
    if drift == "sandbox":
        cfg.openshell = SimpleNamespace(is_standalone=lambda: False)
    (tmp_path / "gateway.pid").write_text("4242", encoding="utf-8")
    before_trust = _strong_gateway_trust(str(tmp_path), pid=4242)
    after_trust = _strong_gateway_trust(
        str(tmp_path),
        pid=4343,
        start_identity="101",
    )

    with (
        patch(
            "defenseclaw.commands.cmd_doctor._http_probe",
            side_effect=[(200, before_health), (200, after_health)],
        ),
        patch(
            "defenseclaw.commands.cmd_doctor._trusted_gateway_listener",
            side_effect=[before_trust, after_trust],
        ) as trust,
        patch(
            "defenseclaw.commands.cmd_doctor._repair_gateway_lifecycle",
            return_value=(True, ""),
        ) as repair,
    ):
        tag, detail = _fix_gateway_service(cfg, assume_yes=True)

    assert tag == "pass"
    assert expected_reason in detail
    repair.assert_called_once_with(cfg, start_if_stopped=True)
    assert trust.call_count == 2


@pytest.mark.parametrize("subsystem", ["gateway", "telemetry", "sandbox"])
def test_fix_gateway_service_does_not_restart_operational_subsystem_errors(
    tmp_path,
    subsystem,
):
    cfg = _cfg(str(tmp_path), token="configured")
    if subsystem == "gateway":
        cfg.gateway.fleet_mode = "enabled"
    elif subsystem == "telemetry":
        cfg._source_config_version = 8
    else:
        cfg.openshell = SimpleNamespace(is_standalone=lambda: True)

    with (
        patch(
            "defenseclaw.commands.cmd_doctor._http_probe",
            return_value=(200, _health(api="running", **{subsystem: "error"})),
        ),
        patch(
            "defenseclaw.commands.cmd_doctor._repair_gateway_lifecycle",
        ) as repair,
        patch(
            "defenseclaw.commands.cmd_doctor._trusted_gateway_listener",
        ) as trust,
    ):
        tag, detail = _fix_gateway_service(cfg, assume_yes=True)

    assert tag == "skip"
    assert "automatic restart was not attempted" in detail
    assert f"{subsystem} reports error" in detail
    repair.assert_not_called()
    trust.assert_not_called()


def test_fix_gateway_service_restarts_running_guardrail_when_disabled(
    tmp_path,
):
    cfg = _cfg(str(tmp_path), token="configured")
    cfg.guardrail = SimpleNamespace(enabled=False)
    (tmp_path / "gateway.pid").write_text("4242", encoding="utf-8")
    before_trust = _strong_gateway_trust(str(tmp_path), pid=4242)
    after_trust = _strong_gateway_trust(
        str(tmp_path),
        pid=4343,
        start_identity="101",
    )

    with (
        patch(
            "defenseclaw.commands.cmd_doctor._http_probe",
            side_effect=[
                (200, _health(api="running", guardrail="running")),
                (200, _health(api="running", guardrail="disabled")),
            ],
        ),
        patch(
            "defenseclaw.commands.cmd_doctor._trusted_gateway_listener",
            side_effect=[before_trust, after_trust],
        ),
        patch(
            "defenseclaw.commands.cmd_doctor._repair_gateway_lifecycle",
            return_value=(True, ""),
        ) as repair,
    ):
        tag, detail = _fix_gateway_service(cfg, assume_yes=True)

    assert tag == "pass"
    assert "guardrail is disabled in config but reports running" in detail
    repair.assert_called_once_with(cfg, start_if_stopped=True)


def test_fix_gateway_service_uses_explicit_api_bind_without_proxy(tmp_path):
    cfg = _cfg(str(tmp_path), token="configured")
    cfg.gateway.api_bind = "10.200.0.1"

    with patch(
        "defenseclaw.commands.cmd_doctor._http_probe",
        return_value=(200, _health(api="running")),
    ) as probe:
        tag, _ = _fix_gateway_service(cfg, assume_yes=True)

    assert tag == "skip"
    assert probe.call_args.args[0] == "http://10.200.0.1:18970/health"
    assert probe.call_args.kwargs["bypass_proxy"] is True


def test_fix_dotenv_permissions_uses_private_windows_dacl(tmp_path):
    (tmp_path / ".env").write_text("SECRET=value\n", encoding="utf-8")
    cfg = _cfg(str(tmp_path))

    with (
        patch(
            "defenseclaw.file_permissions.windows_acl_confidentiality_error",
            side_effect=["unsafe inherited ACL", None],
        ),
        patch(
            "defenseclaw.file_permissions.windows_acl_write_error",
            return_value=None,
        ),
        patch("defenseclaw.file_permissions.protect_private_file") as protect,
    ):
        tag, detail = _fix_dotenv_perms(
            cfg,
            assume_yes=True,
            platform_name="nt",
        )

    assert tag == "pass"
    assert "private Windows DACL" in detail
    protect.assert_called_once_with(str(tmp_path / ".env"))


def test_fix_gateway_service_starts_unreachable_gateway(tmp_path, capsys):
    cfg = _cfg(str(tmp_path), token="configured")
    observed_env = {}

    def _restarted(
        data_dir,
        *,
        start_if_stopped,
        child_env,
        lifecycle_executable,
    ):
        print("captured lifecycle output")
        print("captured lifecycle error", file=sys.stderr)
        observed_env.update(
            {name: os.environ.get(name) for name in ("DEFENSECLAW_HOME", "DEFENSECLAW_DATA_DIR", "DEFENSECLAW_CONFIG")}
        )
        assert child_env["DEFENSECLAW_DATA_DIR"] == data_dir
        assert lifecycle_executable is None
        return True

    previous = {
        "DEFENSECLAW_HOME": "/other/home",
        "DEFENSECLAW_DATA_DIR": "/other/data",
    }
    with (
        patch.dict(os.environ, previous, clear=False),
        patch(
            "defenseclaw.commands.cmd_doctor._http_probe",
            side_effect=[(0, ""), (200, _health(api="running"))],
        ),
        patch(
            "defenseclaw.commands.cmd_doctor._managed_gateway_process_trust",
            return_value=_GatewayTrust("missing", "managed gateway PID file is missing"),
        ),
        patch(
            "defenseclaw.commands.cmd_doctor._managed_gateway_listener_evidence",
            return_value=ListenerEvidence("missing"),
        ),
        patch(
            "defenseclaw.commands.cmd_doctor._trusted_gateway_listener",
            return_value=_strong_gateway_trust(str(tmp_path), pid=4343),
        ),
        patch("defenseclaw.commands.cmd_setup._restart_defense_gateway", side_effect=_restarted) as restart,
    ):
        tag, detail = _fix_gateway_service(cfg, assume_yes=True)
        assert {name: os.environ.get(name) for name in previous} == previous

    assert tag == "pass"
    assert "started" in detail
    restart.assert_called_once()
    assert restart.call_args.kwargs["start_if_stopped"] is True
    assert restart.call_args.kwargs["child_env"]["DEFENSECLAW_DATA_DIR"] == str(tmp_path)
    assert restart.call_args.kwargs["lifecycle_executable"] is None
    assert observed_env == {
        "DEFENSECLAW_HOME": str(tmp_path),
        "DEFENSECLAW_DATA_DIR": str(tmp_path),
        "DEFENSECLAW_CONFIG": str(tmp_path / "config.yaml"),
    }
    captured = capsys.readouterr()
    assert "captured lifecycle" not in captured.out
    assert "captured lifecycle" not in captured.err


def test_fix_gateway_service_reports_started_with_operational_upstream_state(
    tmp_path,
):
    cfg = _cfg(str(tmp_path), token="configured")

    with (
        patch(
            "defenseclaw.commands.cmd_doctor._http_probe",
            side_effect=[
                (0, ""),
                (200, _health(api="running", gateway="reconnecting")),
            ],
        ),
        patch(
            "defenseclaw.commands.cmd_doctor._managed_gateway_process_trust",
            return_value=_GatewayTrust("missing", "managed gateway PID file is missing"),
        ),
        patch(
            "defenseclaw.commands.cmd_doctor._managed_gateway_listener_evidence",
            return_value=ListenerEvidence("missing"),
        ),
        patch(
            "defenseclaw.commands.cmd_doctor._trusted_gateway_listener",
            return_value=_strong_gateway_trust(str(tmp_path), pid=4343),
        ),
        patch(
            "defenseclaw.commands.cmd_setup._restart_defense_gateway",
            return_value=True,
        ),
    ):
        tag, detail = _fix_gateway_service(cfg, assume_yes=True)

    assert tag == "warn"
    assert "gateway service started and ownership verified" in detail
    assert "gateway reports reconnecting" in detail


def test_fix_gateway_service_restarts_stale_enabled_subsystem(tmp_path):
    cfg = _cfg(str(tmp_path), token="configured")
    cfg.guardrail = SimpleNamespace(enabled=True)
    cfg.openshell = SimpleNamespace(is_standalone=lambda: False)
    (tmp_path / "gateway.pid").write_text("4242", encoding="utf-8")
    before_trust = _strong_gateway_trust(str(tmp_path), pid=4242)
    after_trust = _strong_gateway_trust(
        str(tmp_path),
        pid=4343,
        start_identity="101",
    )

    with (
        patch(
            "defenseclaw.commands.cmd_doctor._http_probe",
            side_effect=[
                (200, _health(api="running", guardrail="disabled")),
                (200, _health(api="running", guardrail="running")),
            ],
        ),
        patch(
            "defenseclaw.commands.cmd_doctor._trusted_gateway_listener",
            side_effect=[before_trust, after_trust],
        ),
        patch(
            "defenseclaw.commands.cmd_setup._restart_defense_gateway",
            return_value=True,
        ) as restart,
    ):
        tag, detail = _fix_gateway_service(cfg, assume_yes=True)

    assert tag == "pass"
    assert "restarted" in detail
    assert "guardrail" in detail
    restart.assert_called_once()
    assert restart.call_args.kwargs["start_if_stopped"] is True
    assert restart.call_args.kwargs["child_env"]["DEFENSECLAW_DATA_DIR"] == str(tmp_path)
    assert restart.call_args.kwargs["lifecycle_executable"] is None


def test_fix_gateway_service_skips_healthy_current_gateway(tmp_path):
    cfg = _cfg(str(tmp_path), token="configured")
    body = _health(api="running", gateway="disabled", guardrail="disabled")

    with patch("defenseclaw.commands.cmd_doctor._http_probe", return_value=(200, body)):
        tag, detail = _fix_gateway_service(cfg, assume_yes=True)

    assert tag == "skip"
    assert "healthy and current" in detail


def test_fix_gateway_service_surfaces_only_safe_lifecycle_reason(tmp_path):
    cfg = _cfg(str(tmp_path), token="configured")

    def _failed_lifecycle(*_args, **_kwargs):
        print("defenseclaw-gateway: binary not found")
        print("untrusted child detail with token=secret-value")
        return False

    with (
        patch("defenseclaw.commands.cmd_doctor._http_probe", return_value=(0, "")),
        patch(
            "defenseclaw.commands.cmd_doctor._managed_gateway_process_trust",
            return_value=_GatewayTrust("missing", "managed gateway PID file is missing"),
        ),
        patch(
            "defenseclaw.commands.cmd_doctor._managed_gateway_listener_evidence",
            return_value=ListenerEvidence("missing"),
        ),
        patch(
            "defenseclaw.commands.cmd_setup._restart_defense_gateway",
            side_effect=_failed_lifecycle,
        ),
    ):
        tag, detail = _fix_gateway_service(cfg, assume_yes=True)

    assert tag == "fail"
    assert "binary not found" in detail
    assert "secret-value" not in detail
