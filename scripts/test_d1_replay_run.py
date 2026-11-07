# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

import subprocess
import tempfile
import unittest
from pathlib import Path

from scripts.d1_replay_run import drive


class D1ReplayRunTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.output = Path(directory.name) / "verdicts.tsv"
        self.marker = Path(str(self.output) + ".stalled")
        self.calls = []

    def runner(self, stalls, code=0):
        """A fake replay that leaves the stall marker on its first `stalls` runs."""

        def run(command, env):
            self.calls.append((list(command), env["DC_D1_RESUME"], env["DC_D1_OUTPUT"]))
            if len(self.calls) <= stalls:
                self.marker.write_text("row\n")
            else:
                self.marker.unlink(missing_ok=True)
            return subprocess.CompletedProcess(command, code)

        return run

    def test_stalled_runs_resume_until_one_finishes(self):
        self.assertEqual(drive(["replay"], self.output, runner=self.runner(2)), 0)
        self.assertEqual([resume for _, resume, _ in self.calls], ["0", "1", "1"])
        self.assertEqual({out for _, _, out in self.calls}, {str(self.output)})

    def test_a_clean_first_run_is_one_run(self):
        self.assertEqual(drive(["replay"], self.output, runner=self.runner(0)), 0)
        self.assertEqual(len(self.calls), 1)

    def test_a_failing_run_is_not_retried(self):
        self.assertEqual(drive(["replay"], self.output, runner=self.runner(1, code=1)), 1)
        self.assertEqual(len(self.calls), 1)

    def test_endless_stalls_fail_after_the_run_limit(self):
        self.assertEqual(drive(["replay"], self.output, max_runs=3, runner=self.runner(99)), 1)
        self.assertEqual(len(self.calls), 3)


if __name__ == "__main__":
    unittest.main()
