# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Doctor row for the managed Windows route-only peer broker (S1 Q7)."""

from __future__ import annotations

import unittest

from defenseclaw.commands import cmd_doctor


class RoutePeerBrokerRowTests(unittest.TestCase):
    def _row(self, broker):
        r = cmd_doctor._DoctorResult()
        r.quiet = True
        cmd_doctor._emit_route_peer_broker_row(broker, r)
        return r

    def test_absent_entry_emits_nothing(self):
        for broker in (None, "ok", []):
            r = self._row(broker)
            self.assertEqual((r.passed, r.failed, r.warned), (0, 0, 0))

    def test_ok_passes(self):
        r = self._row({"state": "ok"})
        self.assertEqual((r.passed, r.failed), (1, 0))

    def test_unavailable_fails_and_names_the_guardian(self):
        r = self._row({"state": "unavailable", "detail": "peer broker unavailable: open the broker pipe"})
        self.assertEqual(r.failed, 1)
        detail = r.checks[-1]["detail"]
        self.assertIn("hook guardian", detail)
        self.assertIn("401", detail)

    def test_refused_warns(self):
        r = self._row({"state": "refused", "detail": "x" * 1000})
        self.assertEqual(r.warned, 1)
        self.assertLess(len(r.checks[-1]["detail"]), 500)


if __name__ == "__main__":
    unittest.main()
