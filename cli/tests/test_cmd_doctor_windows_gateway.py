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

from defenseclaw.commands import cmd_doctor
from defenseclaw.commands.cmd_doctor import _check_windows_gateway_diagnostics, _DoctorResult
from defenseclaw.doctor_gateway import ListenerEvidence, PIDRecord, ProcessEvidence


class FakeEvidence:
    def __init__(self, *, record=None, process=None, listener=None):
        self.record_result = record or PIDRecord(
            "ok",
            pid=4242,
            executable=os.path.abspath("defenseclaw-gateway.exe"),
            start_identity="start-1",
        )
        self.process_result = process or ProcessEvidence(
            "ok",
            pid=4242,
            executable=os.path.abspath("defenseclaw-gateway.exe"),
            start_identity="start-1",
        )
        self.listener_result = listener or ListenerEvidence("ok", pid=4242)

    def pid_record(self, _path):
        return self.record_result

    def process(self, _pid):
        return self.process_result

    def listener(self, _port):
        return self.listener_result


def make_cfg(data_dir: str, token: str):
    gateway = SimpleNamespace(api_port=18970, resolved_token=lambda: token)
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
        self.assertIn("stale PID", failures["Gateway PID identity"])
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

    def test_unexpected_listener_owner_fails(self):
        result = self.run_check(FakeEvidence(listener=ListenerEvidence("ok", pid=9001)))
        row = next(row for row in result.checks if row["label"] == "Gateway listener owner")
        self.assertEqual(row["status"], "fail")
        self.assertIn("unexpected process", row["detail"])

    def test_access_denied_and_unavailable_are_explicit_skips(self):
        evidence = FakeEvidence(
            process=ProcessEvidence("denied", pid=4242, reason="process inspection access denied"),
            listener=ListenerEvidence("denied", reason="listener ownership access denied"),
        )
        result = self.run_check(evidence, response=(0, "unreachable"))
        self.assertEqual((result.passed, result.failed, result.warned, result.skipped), (0, 0, 0, 4))
        self.assertTrue(all(row["status"] == "skip" for row in result.checks))

    def test_no_listener_and_gateway_unreachable_remain_distinct(self):
        evidence = FakeEvidence(listener=ListenerEvidence("missing"))
        result = self.run_check(evidence, response=(0, "connection refused"))
        listener = next(row for row in result.checks if row["label"] == "Gateway listener owner")
        auth = next(row for row in result.checks if row["label"] == "Gateway token drift")
        self.assertEqual(listener["status"], "fail")
        self.assertIn("no listener", listener["detail"])
        self.assertEqual(auth["status"], "skip")
        self.assertIn("unreachable", auth["detail"])

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


@unittest.skipUnless(sys.platform == "win32", "native Windows smoke test")
class NativeWindowsGatewayDoctorSmokeTests(unittest.TestCase):
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
