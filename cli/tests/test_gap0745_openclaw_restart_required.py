# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""GAP-0745: setup must not leave a running OpenClaw gateway to hot reload the plugin.

A gateway that runs in a terminal has no service to restart. Setup says so and
tells the operator to restart it there; a restarted service needs no such line.
"""

from __future__ import annotations

import contextlib
import io
import subprocess
import unittest
from unittest.mock import patch

from defenseclaw.commands.cmd_setup import _restart_openclaw_gateway


def _run(proc: subprocess.CompletedProcess) -> tuple[bool, str]:
    buf = io.StringIO()
    with patch("defenseclaw.commands.cmd_setup.subprocess.run", return_value=proc):
        with contextlib.redirect_stdout(buf):
            ok = _restart_openclaw_gateway()
    return ok, buf.getvalue()


class OpenClawRestartRequiredTest(unittest.TestCase):
    def test_foreground_gateway_is_told_to_restart_it_there(self):
        foreground = subprocess.CompletedProcess(
            ["openclaw"], 1, stdout="",
            stderr="Gateway restart failed: Error: Foreground Gateway owner pid 7 no longer listens on port 18789\n",
        )
        ok, text = _run(foreground)
        self.assertIs(ok, True)
        self.assertIn("Restart required", text)
        self.assertIn("openclaw gateway run", text)
        self.assertNotIn("if it does not load", text)

    def test_service_not_installed_is_told_to_restart_it_there(self):
        done = subprocess.CompletedProcess(
            ["openclaw"], 0, stdout="Gateway service not loaded. Start with: openclaw gateway install\n", stderr=""
        )
        ok, text = _run(done)
        self.assertIs(ok, True)
        self.assertIn("Restart required", text)

    def test_a_restarted_service_needs_no_restart_line(self):
        restarted = subprocess.CompletedProcess(["openclaw"], 0, stdout="Gateway restarted.\n", stderr="")
        ok, text = _run(restarted)
        self.assertIs(ok, True)
        self.assertNotIn("Restart required", text)
        self.assertIn("✓", text)


if __name__ == "__main__":
    unittest.main()
