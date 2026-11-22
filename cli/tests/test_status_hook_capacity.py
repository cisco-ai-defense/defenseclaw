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
        quiet = _health()
        quiet["hook_capacity"]["window"]["shed"] = 0
        with mock.patch.object(cmd_status, "_status_row") as row:
            cmd_status._print_hook_capacity(quiet)
            row.assert_not_called()
            cmd_status._print_hook_capacity(_health(denies=3, late=4))
            row.assert_called_once()
            key, value = row.call_args.args
            self.assertEqual(key, "Hook capacity")
            self.assertIn("3 denied and 4 unchecked", value)
            self.assertIn("2 call(s) refused by the admission limits", value)
            self.assertIn("not a policy result", value)

    def test_shed_alone_shows_the_row(self):
        # Review P2-3: shed alone is a capacity signal too.
        health = _health()
        health["hook_capacity"]["window"]["shed"] = 5
        with mock.patch.object(cmd_status, "_status_row") as row:
            cmd_status._print_hook_capacity(health)
        row.assert_called_once()
        value = row.call_args.args[1]
        # GAP-0742 N1: a call a resend got in ran with a policy answer, so
        # the clause counts calls refused at least once.
        self.assertIn("5 call(s) refused by the admission limits at least once; a call no resend got in is blocked when its budget ends", value)
        self.assertNotIn("their hooks block them", value)
        self.assertNotIn("unchecked", value)

    def test_status_reads_the_window_from_the_authenticated_status(self):
        # Review P3-2: a per-user /health needs no credential and no longer
        # carries the window; status takes it from the token-bound /status.
        from defenseclaw.commands import cmd_doctor

        trust = mock.Mock(trusted=True, pid=4242)
        client = mock.Mock()
        client.status.return_value = {
            "health": {"gateway": {"state": "running"}},
            "hook_capacity": _health(denies=1)["hook_capacity"],
        }
        with (
            mock.patch.object(cmd_doctor, "_trusted_gateway_listener", return_value=trust),
            mock.patch.object(cmd_doctor, "_authenticated_runtime_matches", return_value=(True, "")),
        ):
            health = cmd_status._fetch_runtime_bound_health(client, mock.Mock())
        self.assertEqual(cmd_status._hook_capacity_status(health)["deadline_denies"], 1)


if __name__ == "__main__":
    unittest.main()
