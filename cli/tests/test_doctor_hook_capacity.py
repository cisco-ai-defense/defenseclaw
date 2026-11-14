# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Doctor row for the hook capacity signal (S8 DESIGN 18, H1 option B)."""

from __future__ import annotations

import inspect
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
        self.assertIn("4 call(s) refused by the admission limits; their hooks block them when the budget ends", detail)
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

    def test_windows_diagnostics_no_longer_emit_the_row(self):
        self.assertNotIn("hook_capacity", inspect.getsource(cmd_doctor._check_windows_gateway_diagnostics))

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
