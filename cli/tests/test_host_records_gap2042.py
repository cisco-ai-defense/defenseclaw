# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Host records of the managed hook in status and doctor (rel-1-0-10:GAP-2042)."""

from __future__ import annotations

import unittest
from unittest import mock

from defenseclaw.commands import cmd_doctor, cmd_status


def _records(records=0, blocks=0, dropped=0, readable=True, reason="", limit=False):
    return {
        "readable": readable,
        "reason": reason,
        "window_hours": 24,
        "records": records,
        "blocks": blocks,
        "allows": records - blocks,
        "dropped": dropped,
        "read_limit_reached": limit,
        "read_max": 500,
        "last_read": "2026-11-27T12:00:00Z",
    }


class HostRecordsStatusTests(unittest.TestCase):
    def test_absent_on_per_user_and_older_gateways(self):
        for health in (None, {}, {"host_records": "x"}, {"host_records": []}):
            self.assertIsNone(cmd_status._host_records_status(health))

    def test_json_field_is_normalized(self):
        got = cmd_status._host_records_status({"host_records": {**_records(4, 1, 2), "blocks": True, "extra": 1}})
        self.assertEqual(got["records"], 4)
        self.assertEqual(got["blocks"], 0)  # a bool is not a count
        self.assertEqual(got["dropped"], 2)
        self.assertNotIn("extra", got)

    def test_summary_text(self):
        self.assertEqual(
            cmd_status._host_records_summary(cmd_status._host_records_status({"host_records": _records(7, 2, 1)})),
            "7 in 24 h, 2 blocks, 1 dropped",
        )
        self.assertEqual(
            cmd_status._host_records_summary(
                cmd_status._host_records_status({"host_records": _records(500, 0, 0, limit=True)})
            ),
            "500 in 24 h, 0 blocks, 0 dropped (newest 500 read)",
        )

    def test_row_only_with_records_and_yellow_on_blocks(self):
        with mock.patch.object(cmd_status, "_status_row") as row:
            cmd_status._print_host_records({"host_records": _records()})
            cmd_status._print_host_records({"host_records": _records(readable=False, reason="not read yet")})
            cmd_status._print_host_records(None)
            row.assert_not_called()
            cmd_status._print_host_records({"host_records": _records(3, 0)})
            key, value = row.call_args.args
            self.assertEqual(key, "Host records")
            self.assertIn("3 in 24 h, 0 blocks, 0 dropped", value)
            self.assertNotIn("blocked", value)
            cmd_status._print_host_records({"host_records": _records(3, 2)})
            key, value = row.call_args.args
            self.assertIn("3 in 24 h, 2 blocks, 0 dropped", value)
            self.assertIn("a managed hook blocked calls without a gateway answer", value)


class HostRecordsDoctorTests(unittest.TestCase):
    def _row(self, records):
        r = cmd_doctor._DoctorResult()
        r.quiet = True
        cmd_doctor._emit_host_records_row(records, r)
        return r

    def test_no_row_without_the_entry(self):
        for records in (None, "x", [], 3):
            r = self._row(records)
            self.assertEqual((r.passed, r.failed, r.warned, len(r.checks)), (0, 0, 0, 0))

    def test_no_blocks_pass(self):
        r = self._row(_records(5, 0, 1))
        self.assertEqual((r.passed, r.warned, r.failed), (1, 0, 0))
        self.assertIn("5 in 24 h, 0 blocks, 1 dropped", r.checks[-1]["detail"])

    def test_blocks_while_healthy_warn(self):
        r = self._row(_records(5, 2))
        self.assertEqual((r.passed, r.warned, r.failed), (0, 1, 0))
        detail = r.checks[-1]["detail"]
        self.assertIn("5 in 24 h, 2 blocks, 0 dropped", detail)
        self.assertIn("2 call(s) without a gateway answer while the gateway reports healthy", detail)
        self.assertIn("not in the audit log", detail)

    def test_unreadable_host_log_is_a_skip(self):
        r = self._row(_records(readable=False, reason="no journald on this host"))
        self.assertEqual((r.passed, r.warned, r.failed), (0, 0, 0))
        self.assertIn("no journald on this host", r.checks[-1]["detail"])

    def test_check_reads_health_then_status_document(self):
        r = cmd_doctor._DoctorResult()
        r.quiet = True
        with mock.patch.object(
            cmd_doctor,
            "_authenticated_gateway_status_document",
            return_value=({"host_records": _records(1, 1)}, "", True),
        ) as doc:
            cmd_doctor._check_host_records(object(), {"host_records": _records(2, 0)}, r)
            doc.assert_not_called()
            cmd_doctor._check_host_records(object(), {}, r)
            doc.assert_called_once()
        self.assertEqual((r.passed, r.warned), (1, 1))


if __name__ == "__main__":
    unittest.main()
