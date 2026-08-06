"""Windows gateway Doctor diagnostics, injectable on every CI platform."""

from __future__ import annotations

import contextlib
import glob
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from defenseclaw import windows_acl
from defenseclaw.commands import cmd_doctor
from defenseclaw.commands.cmd_doctor import (
    _check_windows_gateway_diagnostics,
    _DoctorResult,
    _fix_gateway_service,
    _fix_gateway_token_drift,
    _fix_stale_pid,
    _trusted_gateway_listener,
)
from defenseclaw.doctor_gateway import ListenerEvidence, PIDRecord, ProcessEvidence


class FakeEvidence:
    def __init__(self, *, record=None, process=None, listener=None):
        # Keep an explicitly supplied record unchanged so tests can exercise
        # legacy/unbound metadata. The healthy default is materialized from
        # the inspected PID path and therefore carries the new data-home
        # binding written by current gateways.
        self.record_result = record
        self.process_result = process or ProcessEvidence(
            "ok",
            pid=4242,
            executable=os.path.abspath("defenseclaw-gateway.exe"),
            start_identity="start-1",
        )
        self.listener_result = listener or ListenerEvidence("ok", pid=4242)

    def pid_record(self, path):
        if self.record_result is not None:
            return self.record_result
        return PIDRecord(
            "ok",
            pid=4242,
            executable=os.path.abspath("defenseclaw-gateway.exe"),
            start_identity="start-1",
            data_dir=os.path.dirname(path),
        )

    def process(self, _pid):
        return self.process_result

    def listener(self, _port, host=""):
        del host
        return self.listener_result


def make_cfg(data_dir: str, token: str, *, token_env: str = ""):
    gateway = SimpleNamespace(
        api_bind="",
        api_port=18970,
        token_env=token_env,
        resolved_token=lambda: token,
    )
    return SimpleNamespace(data_dir=data_dir, gateway=gateway)


def status_response(data_dir: str, *, pid: int = 4242):
    return 200, json.dumps({"runtime": {"pid": pid, "data_dir": data_dir}})


class WindowsGatewayDoctorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="doctor-win-gateway-")
        self.home = self.temp.name
        self.local_secret = "local-value-must-never-appear"
        self.remote_secret = "remote-value-must-never-appear"
        self.cfg = make_cfg(self.home, self.local_secret)

    def tearDown(self):
        self.temp.cleanup()

    def run_check(self, evidence=None, response=None):
        result = _DoctorResult()
        with patch.object(
            cmd_doctor,
            "_http_probe",
            return_value=response if response is not None else status_response(self.home),
        ):
            applicable = _check_windows_gateway_diagnostics(
                self.cfg,
                result,
                evidence=evidence or FakeEvidence(),
                platform_name="win32",
            )
        self.assertTrue(applicable)
        return result

    def test_healthy_gateway_has_four_named_passes(self):
        result = self.run_check()
        self.assertEqual((result.passed, result.failed, result.warned, result.skipped), (4, 0, 0, 0))
        self.assertEqual(
            [row["label"] for row in result.checks],
            ["Gateway PID identity", "Gateway listener owner", "Gateway token drift", "Gateway home"],
        )

    def test_missing_process_is_stale_and_listener_cannot_mask_it(self):
        evidence = FakeEvidence(process=ProcessEvidence("missing", pid=4242))
        result = self.run_check(evidence)
        failures = {row["label"]: row["detail"] for row in result.checks if row["status"] == "fail"}
        self.assertIn("process does not exist", failures["Gateway PID identity"])
        self.assertIn("stale PID", failures["Gateway listener owner"])

    def test_reused_pid_start_identity_is_detected(self):
        evidence = FakeEvidence(
            process=ProcessEvidence(
                "ok",
                pid=4242,
                executable=os.path.abspath("defenseclaw-gateway.exe"),
                start_identity="start-2",
            )
        )
        result = self.run_check(evidence)
        pid_row = next(row for row in result.checks if row["label"] == "Gateway PID identity")
        self.assertEqual(pid_row["status"], "fail")
        self.assertIn("start identity changed", pid_row["detail"])

    def test_foreign_home_fails_without_rendering_either_path(self):
        foreign = os.path.join(self.home, "foreign")
        result = self.run_check(response=status_response(foreign))
        row = next(row for row in result.checks if row["label"] == "Gateway home")
        self.assertEqual(row["status"], "fail")
        self.assertNotIn(self.home, row["detail"])
        self.assertNotIn(foreign, row["detail"])

    def test_auth_rejection_reports_drift_and_never_exposes_tokens(self):
        # A hostile error body may echo input. Doctor intentionally ignores it.
        result = self.run_check(response=(401, self.remote_secret))
        row = next(row for row in result.checks if row["label"] == "Gateway token drift")
        self.assertEqual(row["status"], "fail")
        serialized = json.dumps(result.to_dict())
        self.assertNotIn(self.local_secret, serialized)
        self.assertNotIn(self.remote_secret, serialized)
        self.assertNotIn(self.local_secret[:8], serialized)
        self.assertNotIn(self.remote_secret[:8], serialized)

    def test_missing_token_is_a_failure_with_fix_hint(self):
        self.cfg = make_cfg(self.home, "")

        result = self.run_check()

        row = next(row for row in result.checks if row["label"] == "Gateway token drift")
        self.assertEqual(row["status"], "fail")
        self.assertIn("doctor --fix", row["detail"])

    def test_missing_custom_provider_names_external_action_not_auto_fix(self):
        self.cfg = make_cfg(self.home, "", token_env="VAULT_GATEWAY_TOKEN")

        result = self.run_check()

        row = next(row for row in result.checks if row["label"] == "Gateway token drift")
        self.assertEqual(row["status"], "fail")
        self.assertIn("VAULT_GATEWAY_TOKEN", row["detail"])
        self.assertIn("preserves custom providers", row["detail"])
        self.assertNotIn("doctor --fix", row["detail"])

    def test_unexpected_listener_owner_fails(self):
        result = self.run_check(FakeEvidence(listener=ListenerEvidence("ok", pid=9001)))
        row = next(row for row in result.checks if row["label"] == "Gateway listener owner")
        self.assertEqual(row["status"], "fail")
        self.assertIn("unexpected process", row["detail"])

    def test_unexpected_listener_never_receives_bearer_token(self):
        result = _DoctorResult()
        evidence = FakeEvidence(listener=ListenerEvidence("ok", pid=9001))
        with patch.object(cmd_doctor, "_http_probe") as probe:
            _check_windows_gateway_diagnostics(
                self.cfg,
                result,
                evidence=evidence,
                platform_name="win32",
            )
        probe.assert_not_called()
        auth = next(row for row in result.checks if row["label"] == "Gateway token drift")
        self.assertEqual(auth["status"], "fail")
        self.assertIn("refusing to send", auth["detail"])

    def test_access_denied_and_unavailable_fail_authentication_closed(self):
        evidence = FakeEvidence(
            process=ProcessEvidence("denied", pid=4242, reason="process inspection access denied"),
            listener=ListenerEvidence("denied", reason="listener ownership access denied"),
        )
        result = self.run_check(evidence, response=(0, "unreachable"))
        self.assertEqual((result.passed, result.failed, result.warned, result.skipped), (0, 1, 0, 3))
        auth = next(row for row in result.checks if row["label"] == "Gateway token drift")
        self.assertEqual(auth["status"], "fail")

    def test_ambiguous_listener_ownership_never_sends_token(self):
        result = _DoctorResult()
        evidence = FakeEvidence(
            listener=ListenerEvidence(
                "ambiguous",
                reason="multiple processes own listeners for the configured API endpoint",
            )
        )
        with patch.object(cmd_doctor, "_http_probe") as probe:
            _check_windows_gateway_diagnostics(
                self.cfg,
                result,
                evidence=evidence,
                platform_name="win32",
            )
        probe.assert_not_called()
        listener = next(row for row in result.checks if row["label"] == "Gateway listener owner")
        self.assertEqual(listener["status"], "fail")
        self.assertIn("multiple processes", listener["detail"])

    def test_no_listener_and_gateway_unreachable_remain_distinct(self):
        evidence = FakeEvidence(listener=ListenerEvidence("missing"))
        result = self.run_check(evidence, response=(0, "connection refused"))
        listener = next(row for row in result.checks if row["label"] == "Gateway listener owner")
        auth = next(row for row in result.checks if row["label"] == "Gateway token drift")
        self.assertEqual(listener["status"], "fail")
        self.assertIn("no listener", listener["detail"])
        self.assertEqual(auth["status"], "fail")
        self.assertIn("refusing to send", auth["detail"])

    def test_human_and_json_rows_share_counts_and_hide_secrets(self):
        result = _DoctorResult()
        old_json_mode = cmd_doctor._json_mode
        output = io.StringIO()
        try:
            cmd_doctor._json_mode = False
            with (
                contextlib.redirect_stdout(output),
                patch.object(cmd_doctor, "_http_probe", return_value=(401, self.remote_secret)),
            ):
                _check_windows_gateway_diagnostics(
                    self.cfg,
                    result,
                    evidence=FakeEvidence(),
                    platform_name="win32",
                )
        finally:
            cmd_doctor._json_mode = old_json_mode
        rendered = output.getvalue()
        for row in result.checks:
            self.assertIn(row["label"], rendered)
        self.assertEqual(sum((result.passed, result.failed, result.warned, result.skipped)), len(result.checks))
        self.assertNotIn(self.local_secret, rendered)
        self.assertNotIn(self.remote_secret, rendered)

    def test_non_windows_registration_is_not_applicable(self):
        result = _DoctorResult()
        self.assertFalse(
            _check_windows_gateway_diagnostics(
                self.cfg,
                result,
                evidence=FakeEvidence(),
                platform_name="linux",
            )
        )
        self.assertEqual(result.checks, [])

    def test_token_drift_fixer_refuses_legacy_windows_pid_before_http(self):
        with open(os.path.join(self.home, "config.yaml"), "w", encoding="utf-8") as handle:
            handle.write("config_version: 8\n")
        legacy = FakeEvidence(
            record=PIDRecord("ok", pid=4242),
            process=ProcessEvidence(
                "ok",
                pid=4242,
                executable=os.path.abspath("defenseclaw-gateway.exe"),
                start_identity="start-1",
            ),
            listener=ListenerEvidence("ok", pid=4242),
        )
        trust = _trusted_gateway_listener(
            self.cfg,
            evidence=legacy,
            platform_name="win32",
        )
        self.assertEqual(trust.code, "legacy_identity")

        with (
            patch.object(cmd_doctor, "_managed_gateway_process_trust", return_value=trust),
            patch.object(cmd_doctor, "_trusted_gateway_listener") as listener_trust,
            patch.object(cmd_doctor, "_http_probe") as probe,
            patch.object(cmd_doctor, "_repair_gateway_lifecycle") as lifecycle,
        ):
            tag, detail = _fix_gateway_token_drift(self.cfg, assume_yes=True)

        self.assertEqual(tag, "fail")
        self.assertIn("legacy PID record", detail)
        listener_trust.assert_not_called()
        probe.assert_not_called()
        lifecycle.assert_not_called()

    def test_token_drift_fixer_refuses_unbound_windows_pid_before_http(self):
        with open(os.path.join(self.home, "config.yaml"), "w", encoding="utf-8") as handle:
            handle.write("config_version: 8\n")
        unbound = FakeEvidence(
            record=PIDRecord(
                "ok",
                pid=4242,
                executable=os.path.abspath("defenseclaw-gateway.exe"),
                start_identity="start-1",
            )
        )
        trust = _trusted_gateway_listener(
            self.cfg,
            evidence=unbound,
            platform_name="win32",
        )
        self.assertEqual(trust.code, "unbound_home")

        with (
            patch.object(cmd_doctor, "_managed_gateway_process_trust", return_value=trust),
            patch.object(cmd_doctor, "_trusted_gateway_listener") as listener_trust,
            patch.object(cmd_doctor, "_http_probe") as probe,
            patch.object(cmd_doctor, "_repair_gateway_lifecycle") as lifecycle,
        ):
            tag, detail = _fix_gateway_token_drift(self.cfg, assume_yes=True)

        self.assertEqual(tag, "fail")
        self.assertIn("not bound", detail)
        listener_trust.assert_not_called()
        probe.assert_not_called()
        lifecycle.assert_not_called()

    def test_stale_pid_preserves_windows_access_denied_state(self):
        pid_path = os.path.join(self.home, "gateway.pid")
        with open(pid_path, "w", encoding="utf-8") as handle:
            handle.write("4242")
        evidence = FakeEvidence(
            process=ProcessEvidence(
                "denied",
                pid=4242,
                reason="process inspection access denied",
            )
        )

        tag, detail = _fix_stale_pid(
            self.cfg,
            assume_yes=True,
            evidence=evidence,
            platform_name="win32",
        )

        self.assertEqual(tag, "warn")
        self.assertIn("could not be verified", detail)
        self.assertIn("refusing automatic lifecycle repair", detail)
        self.assertTrue(os.path.isfile(pid_path))

    def test_legacy_windows_pid_metadata_refuses_service_restart(self):
        with open(os.path.join(self.home, "config.yaml"), "w", encoding="utf-8") as handle:
            handle.write("config_version: 8\n")
        self.cfg.guardrail = SimpleNamespace(enabled=True)
        body = (
            '{"api":{"state":"running"},"gateway":{"state":"running"},'
            '"watcher":{"state":"running"},"guardrail":{"state":"disabled"}}'
        )
        trust = cmd_doctor._GatewayTrust(
            "legacy_identity",
            "legacy PID record lacks strong executable/start identity",
            4242,
        )

        with (
            patch.object(cmd_doctor, "_http_probe", return_value=(200, body)),
            patch.object(cmd_doctor, "_trusted_gateway_listener", return_value=trust),
            patch.object(
                cmd_doctor,
                "_repair_gateway_lifecycle",
                return_value=(True, ""),
            ) as lifecycle,
        ):
            tag, detail = _fix_gateway_service(self.cfg, assume_yes=True)

        self.assertEqual(tag, "fail")
        self.assertIn("legacy PID record", detail)
        self.assertIn("refusing lifecycle mutation", detail)
        lifecycle.assert_not_called()


@unittest.skipUnless(sys.platform == "win32", "native Windows smoke test")
class NativeWindowsGatewayDoctorSmokeTests(unittest.TestCase):
    def test_stale_pid_repair_serializes_replacement_through_verified_handle(self):
        with tempfile.TemporaryDirectory(prefix="doctor-native-pid-race-") as home:
            pid_path = os.path.join(home, "gateway.pid")
            replacement_path = os.path.join(home, "gateway-replacement.pid")
            with open(pid_path, "wb") as handle:
                handle.write(b"{stale")
            with open(replacement_path, "wb") as handle:
                handle.write(b"{replacement")

            descriptor = os.open(
                pid_path,
                os.O_RDONLY | getattr(os, "O_BINARY", 0),
            )
            try:
                inspected = cmd_doctor.pid_file_fingerprint_from_fd(descriptor)
            finally:
                os.close(descriptor)
            self.assertIsNotNone(inspected)

            real_delete = windows_acl.delete_regular_fd
            replacement_blocked = False

            def race_delete(claimed_fd):
                nonlocal replacement_blocked
                try:
                    os.replace(replacement_path, pid_path)
                except OSError as exc:
                    self.assertIn(
                        getattr(exc, "winerror", None) or getattr(exc, "errno", None),
                        {5, 32},
                    )
                    replacement_blocked = True
                else:
                    self.fail("PID replacement bypassed the exclusive mutation handle")
                real_delete(claimed_fd)

            cfg = make_cfg(home, "")
            with (
                patch.object(cmd_doctor, "pid_file_fingerprint", return_value=inspected),
                patch.object(cmd_doctor, "read_pid_record") as read_record,
                patch.object(
                    cmd_doctor,
                    "_verified_listener_gateway_evidence",
                    return_value=ListenerEvidence("missing", reason="no listener"),
                ),
                patch.object(windows_acl, "delete_regular_fd", side_effect=race_delete),
            ):
                tag, detail = _fix_stale_pid(cfg, assume_yes=True)

            self.assertEqual(tag, "pass", detail)
            read_record.assert_not_called()
            self.assertTrue(replacement_blocked)
            self.assertFalse(os.path.exists(pid_path))
            self.assertTrue(os.path.exists(replacement_path))

            os.replace(replacement_path, pid_path)
            with open(pid_path, "rb") as handle:
                self.assertEqual(handle.read(), b"{replacement")

    def test_disposable_managed_process_listener_home_and_auth(self):
        """Exercise native process/listener APIs against an isolated server.

        The copied interpreter intentionally has the managed gateway basename;
        it implements only the already-authenticated /status contract and
        exits after one request. No real DefenseClaw home or listener is read.
        """
        with tempfile.TemporaryDirectory(prefix="doctor-native-win-") as home:
            executable = os.path.join(home, "defenseclaw-gateway.exe")
            base_executable = getattr(sys, "_base_executable", sys.executable)
            shutil.copy2(base_executable, executable)
            for runtime_dll in glob.glob(os.path.join(sys.base_prefix, "python*.dll")):
                shutil.copy2(runtime_dll, home)
            port_file = os.path.join(home, "port")
            server_code = r"""
import http.server, json, os, sys
token = sys.stdin.readline().rstrip("\n")
home, port_file = sys.argv[1], sys.argv[2]
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/status" or self.headers.get("Authorization") != "Bearer " + token:
            self.send_response(401); self.end_headers(); return
        body = json.dumps({"runtime": {"pid": os.getpid(), "data_dir": home}}).encode()
        self.send_response(200); self.send_header("Content-Length", str(len(body)))
        self.end_headers(); self.wfile.write(body)
    def log_message(self, *_args): pass
server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
with open(port_file, "w", encoding="ascii") as handle:
    handle.write(str(server.server_port))
server.handle_request()
"""
            token = "native-smoke-value"
            child_env = os.environ.copy()
            child_env["PYTHONHOME"] = sys.base_prefix
            child_env["PATH"] = os.path.dirname(base_executable) + os.pathsep + child_env.get("PATH", "")
            proc = subprocess.Popen(
                [executable, "-c", server_code, home, port_file],
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                env=child_env,
                shell=False,
            )
            try:
                assert proc.stdin is not None
                proc.stdin.write(token + "\n")
                proc.stdin.close()
                proc.stdin = None
                deadline = time.monotonic() + 5
                port = 0
                while not port and time.monotonic() < deadline:
                    if proc.poll() is not None:
                        _, stderr = proc.communicate(timeout=1)
                        self.fail(f"disposable gateway process exited before listening: {stderr[:500]}")
                    try:
                        with open(port_file, encoding="ascii") as handle:
                            port = int(handle.read() or "0")
                    except (FileNotFoundError, ValueError):
                        port = 0
                    time.sleep(0.05)
                self.assertGreater(port, 0, "gateway listener did not start within 5 seconds")

                native = cmd_doctor.GatewayEvidence(platform_name="win32")
                live = native.process(proc.pid)
                self.assertEqual(live.status, "ok", live)
                owner = native.listener(port)
                self.assertEqual(owner, ListenerEvidence("ok", pid=proc.pid))
                with open(os.path.join(home, "gateway.pid"), "w", encoding="utf-8") as handle:
                    json.dump(
                        {
                            "pid": proc.pid,
                            "executable": executable,
                            "start_identity": live.start_identity,
                            "data_dir": home,
                        },
                        handle,
                    )
                cfg = make_cfg(home, token)
                cfg.gateway.api_port = port
                result = _DoctorResult()
                _check_windows_gateway_diagnostics(
                    cfg,
                    result,
                    evidence=native,
                    platform_name="win32",
                )
                self.assertEqual(
                    (result.passed, result.failed, result.warned, result.skipped),
                    (4, 0, 0, 0),
                    result.checks,
                )
                proc.wait(timeout=5)
            finally:
                if proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait(timeout=5)
                if proc.stderr is not None:
                    proc.stderr.close()


if __name__ == "__main__":
    unittest.main()
