# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Doctor row for the hook capacity signal (S8 DESIGN 18, H1 option B)."""

from __future__ import annotations

import unittest

from defenseclaw.commands import cmd_doctor


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
        r = self._row(_capacity(shed=4))
        self.assertEqual((r.passed, r.warned, r.failed), (1, 0, 0))
        detail = r.checks[-1]["detail"]
        self.assertIn("120 calls answered", detail)
        self.assertIn("4 refused", detail)

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


if __name__ == "__main__":
    unittest.main()
