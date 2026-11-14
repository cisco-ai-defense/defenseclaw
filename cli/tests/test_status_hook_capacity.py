# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""defenseclaw status: the hook capacity row and JSON field (S8 DESIGN 18)."""

from __future__ import annotations

import unittest
from unittest import mock

from defenseclaw.commands import cmd_status


def _health(denies=0, late=0):
    return {
        "hook_capacity": {
            "window_minutes": 60,
            "window": {"answered": 900, "deadline_denies": denies, "late_allows": late, "shed": 2},
            "sizing_doc": "/docs/reference/hook-sizing",
        }
    }


class HookCapacityStatusTests(unittest.TestCase):
    def test_absent_on_older_gateways(self):
        for health in (None, {}, {"hook_capacity": "x"}):
            self.assertIsNone(cmd_status._hook_capacity_status(health))

    def test_json_field(self):
        got = cmd_status._hook_capacity_status(_health(denies=1, late=2))
        self.assertEqual(
            got,
            {
                "window_minutes": 60,
                "answered": 900,
                "deadline_denies": 1,
                "late_allows": 2,
                "shed": 2,
                "sizing_doc": "/docs/reference/hook-sizing",
            },
        )

    def test_row_only_when_a_call_ran_out_of_its_budget(self):
        with mock.patch.object(cmd_status, "_status_row") as row:
            cmd_status._print_hook_capacity(_health())
            row.assert_not_called()
            cmd_status._print_hook_capacity(_health(denies=3, late=4))
            row.assert_called_once()
            key, value = row.call_args.args
            self.assertEqual(key, "Hook capacity")
            self.assertIn("3 denied and 4 unchecked", value)
            self.assertIn("not a policy result", value)


if __name__ == "__main__":
    unittest.main()
