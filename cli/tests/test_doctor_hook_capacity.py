# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Doctor row for the hook capacity signal (S8 DESIGN 18, H1 option B)."""

from __future__ import annotations

import json
import unittest
from unittest import mock

from click.testing import CliRunner
from defenseclaw.commands import cmd_doctor
from defenseclaw.context import AppContext


def _capacity(denies=0, late=0, shed=0, answered_peak=120):
    return {
        "window_minutes": 60,
        "window": {"answered": 5000, "deadline_denies": denies, "late_allows": late, "shed": shed},
        "peak_minute": {"answered": 40, "deadline_denies": denies, "late_allows": late, "shed": shed},
        "peak_minute_start": "2026-11-14T15:02:00Z",
        "answered_per_minute_peak": answered_peak,
        "overloaded": bool(denies or late),
        "sizing_doc": "/docs/reference/hook-sizing",
    }


class HookCapacityRowTests(unittest.TestCase):
    def _row(self, capacity):
        r = cmd_doctor._DoctorResult()
        r.quiet = True
        cmd_doctor._emit_hook_capacity_row(capacity, r)
        return r

    def test_older_gateway_without_the_entry_emits_nothing(self):
        for capacity in (None, "x", [], 3):
            r = self._row(capacity)
            self.assertEqual((r.passed, r.failed, r.warned), (0, 0, 0))

    def test_no_deadline_outcome_passes(self):
        r = self._row(_capacity())
        self.assertEqual((r.passed, r.warned, r.failed), (1, 0, 0))
        self.assertIn("120 calls answered", r.checks[-1]["detail"])

    def test_shed_alone_warns_with_its_own_clause(self):
        # Review P2-3: a call the admission limits keep refusing is blocked
        # by its hook with the capacity text, so doctor warns for it.
        r = self._row(_capacity(shed=4))
        self.assertEqual((r.passed, r.warned, r.failed), (0, 1, 0))
        detail = r.checks[-1]["detail"]
        # GAP-0742 N1: counted at least once; a resend may have got it in.
        self.assertIn("4 call(s) refused by the admission limits at least once; a call no resend got in is blocked when its budget ends", detail)
        self.assertNotIn("their hooks block them", detail)
        self.assertIn("An account is over its hook budget or this host is over its hook capacity", detail)
        self.assertNotIn("ran unchecked", detail)

    def test_deadline_outcomes_warn_and_name_capacity_not_policy(self):
        r = self._row(_capacity(denies=3, late=7))
        self.assertEqual((r.passed, r.warned, r.failed), (0, 1, 0))
        detail = r.checks[-1]["detail"]
        self.assertIn("3 tool call(s) were denied", detail)
        self.assertIn("7 ran unchecked", detail)
        self.assertIn("not a policy result", detail)
        self.assertIn("/docs/reference/hook-sizing", detail)

    def test_malformed_counts_read_as_zero(self):
        capacity = _capacity()
        capacity["window"] = {"deadline_denies": "9", "late_allows": True, "shed": -1}
        r = self._row(capacity)
        self.assertEqual((r.passed, r.warned), (1, 0))


class _Cfg:
    data_dir = "/nonexistent-defenseclaw-test"


class HookCapacityDoctorPathTests(unittest.TestCase):
    """Review P2-2: the row is on the common doctor path, not Windows only."""

    def test_linux_reads_the_authenticated_status_when_health_lacks_it(self):
        r = cmd_doctor._DoctorResult()
        r.quiet = True
        document = {"health": {}, "hook_capacity": _capacity(denies=2)}
        with (
            mock.patch.object(cmd_doctor.sys, "platform", "linux"),
            mock.patch.object(
                cmd_doctor, "_authenticated_gateway_status_document", return_value=(document, "", True)
            ) as fetch,
        ):
            cmd_doctor._check_hook_capacity(_Cfg(), {"status": "ok"}, r)
        fetch.assert_called_once()
        self.assertEqual((r.warned, r.checks[-1]["label"]), (1, "Hook capacity"))

    def test_managed_administrator_health_is_used_without_a_status_call(self):
        r = cmd_doctor._DoctorResult()
        r.quiet = True
        with mock.patch.object(cmd_doctor, "_authenticated_gateway_status_document") as fetch:
            cmd_doctor._check_hook_capacity(_Cfg(), {"hook_capacity": _capacity()}, r)
        fetch.assert_not_called()
        self.assertEqual(r.passed, 1)

    def test_no_credential_no_row(self):
        r = cmd_doctor._DoctorResult()
        r.quiet = True
        with mock.patch.object(
            cmd_doctor, "_authenticated_gateway_status_document", return_value=(None, "no token", True)
        ):
            cmd_doctor._check_hook_capacity(_Cfg(), {}, r)
        self.assertEqual((r.passed, r.warned, r.failed), (0, 0, 0))

    def _run_doctor(self, platform, document, extra_stubs=None):
        """Drive the doctor command with every other check stubbed."""
        stubs = {
            name: mock.MagicMock(return_value=None)
            for name in dir(cmd_doctor)
            if name.startswith("_check_") and name != "_check_hook_capacity" and callable(getattr(cmd_doctor, name))
        }
        stubs["_check_sidecar"] = mock.MagicMock(return_value={"status": "ok"})
        stubs["_check_windows_gateway_diagnostics"] = mock.MagicMock(return_value=True)
        stubs.update(extra_stubs or {})
        app = AppContext()
        app.cfg = mock.MagicMock()
        patches = [mock.patch.object(cmd_doctor, name, stub) for name, stub in stubs.items()]
        patches += [
            mock.patch.object(cmd_doctor.sys, "platform", platform),
            mock.patch.object(cmd_doctor, "_doctor_config_present", return_value=True),
            mock.patch("defenseclaw.config_writer.managed_leftover_config", return_value=None),
            mock.patch.object(cmd_doctor, "_prefetch_sandbox_report", return_value=(None, None)),
            mock.patch.object(cmd_doctor, "_write_doctor_cache", return_value=None),
        ]
        if document is not None:
            patches.append(
                mock.patch.object(
                    cmd_doctor, "_authenticated_gateway_status_document", return_value=(document, "", True)
                )
            )
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)
        result = CliRunner().invoke(cmd_doctor.doctor, ["--json"], obj=app)
        start = result.output.find("{")
        self.assertGreaterEqual(start, 0, result.output)
        return json.loads(result.output[start:])

    def test_windows_doctor_emits_the_row_once(self):
        # Review P2-2, as behavior: the Windows run has one Hook capacity row,
        # from the common Services path, not a second from its diagnostics.
        payload = self._run_doctor("win32", {"health": {}, "hook_capacity": _capacity(shed=2)})
        rows = [c for c in payload["checks"] if c["label"] == "Hook capacity"]
        self.assertEqual(len(rows), 1, payload["checks"])

    def test_the_doctor_run_fetches_the_authenticated_status_once(self):
        # GAP-0742 N4: the hook capacity row and another row that reads the
        # authenticated status (connector activity, Cowork, OpenCode) share
        # one fetch per doctor run.
        trust = mock.Mock(trusted=True, pid=4242, code="", detail="")
        body = json.dumps({"health": {"status": "ok"}, "hook_capacity": _capacity(denies=1)})
        probe = mock.MagicMock(return_value=(200, body))

        def authenticated():
            # The token-bound /status fetches (the public /health probe of
            # another row is not one).
            return sum(1 for call in probe.call_args_list if "Authorization" in (call.kwargs.get("headers") or {}))

        other = mock.MagicMock(side_effect=lambda cfg, *a, **k: cmd_doctor._authenticated_gateway_health(cfg))
        network = [
            mock.patch.object(cmd_doctor, "_daemon_effective_gateway_token", return_value=("tok", "", "")),
            mock.patch.object(cmd_doctor, "_trusted_gateway_listener", return_value=trust),
            mock.patch.object(cmd_doctor, "_gateway_api_url", return_value="http://127.0.0.1:18970/status"),
            mock.patch.object(cmd_doctor, "_http_probe", probe),
            mock.patch.object(cmd_doctor, "_authenticated_runtime_matches", return_value=(True, "")),
        ]
        for patcher in network:
            patcher.start()
            self.addCleanup(patcher.stop)
        payload = self._run_doctor("linux", None, extra_stubs={"_check_policy_state": other})
        other.assert_called_once()
        rows = [c for c in payload["checks"] if c["label"] == "Hook capacity"]
        self.assertEqual([row["status"] for row in rows], ["warn"], payload["checks"])
        self.assertEqual(authenticated(), 1, probe.call_args_list)
        # Outside a run every read fetches again: no stale document.
        cfg = mock.MagicMock()
        cmd_doctor._authenticated_gateway_status_document(cfg)
        cmd_doctor._authenticated_gateway_status_document(cfg)
        self.assertEqual(authenticated(), 3)

    def test_the_doctor_command_on_linux_emits_the_row(self):
        # Every other check is stubbed: this drives the doctor command itself
        # on platform linux with a running gateway whose authenticated
        # /status carries the window.
        stubs = {
            name: mock.MagicMock(return_value=None)
            for name in dir(cmd_doctor)
            if name.startswith("_check_") and name != "_check_hook_capacity" and callable(getattr(cmd_doctor, name))
        }
        stubs["_check_sidecar"] = mock.MagicMock(return_value={"status": "ok"})
        stubs["_check_windows_gateway_diagnostics"] = mock.MagicMock(return_value=True)
        document = {"health": {}, "hook_capacity": _capacity(denies=3, late=1)}
        app = AppContext()
        app.cfg = mock.MagicMock()
        patches = [mock.patch.object(cmd_doctor, name, stub) for name, stub in stubs.items()]
        patches += [
            mock.patch.object(cmd_doctor.sys, "platform", "linux"),
            mock.patch.object(cmd_doctor, "_doctor_config_present", return_value=True),
            mock.patch("defenseclaw.config_writer.managed_leftover_config", return_value=None),
            mock.patch.object(cmd_doctor, "_prefetch_sandbox_report", return_value=(None, None)),
            mock.patch.object(cmd_doctor, "_write_doctor_cache", return_value=None),
            mock.patch.object(cmd_doctor, "_authenticated_gateway_status_document", return_value=(document, "", True)),
        ]
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)
        result = CliRunner().invoke(cmd_doctor.doctor, ["--json"], obj=app)
        start = result.output.find("{")
        self.assertGreaterEqual(start, 0, result.output)
        payload = json.loads(result.output[start:])
        rows = [c for c in payload["checks"] if c["label"] == "Hook capacity"]
        self.assertEqual(len(rows), 1, payload["checks"])
        self.assertEqual(rows[0]["status"], "warn")
        self.assertIn("3 tool call(s) were denied and 1 ran unchecked", rows[0]["detail"])


if __name__ == "__main__":
    unittest.main()
