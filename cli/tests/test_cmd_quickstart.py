# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for the quickstart sidecar handoff."""

from __future__ import annotations

import io
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.commands import cmd_quickstart


class QuickstartSidecarTests(unittest.TestCase):
    def _cfg(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)

        class Cfg:
            data_dir = tmp.name

        return Cfg()

    def test_start_sidecar_uses_gateway_resolver(self):
        cfg = self._cfg()
        result = subprocess.CompletedProcess(["/tmp/gw", "start"], 0)

        with patch(
            "defenseclaw.commands.cmd_quickstart.resolve_gateway_binary",
            return_value="/tmp/gw",
        ), patch(
            "defenseclaw.commands.cmd_quickstart._sidecar_running",
            return_value=False,
        ), patch(
            "defenseclaw.commands.cmd_quickstart._run",
            return_value=result,
        ) as run_mock, patch(
            "defenseclaw.commands.cmd_quickstart._read_pid",
            return_value=4242,
        ):
            buf = io.StringIO()
            with redirect_stdout(buf):
                cmd_quickstart._start_sidecar(cfg, guardrail_ok=False)

        run_mock.assert_called_once_with(["/tmp/gw", "start"], timeout=30)
        self.assertIn("PID 4242", buf.getvalue())

    def test_running_sidecar_restarts_with_resolved_binary_when_guardrail_changed(self):
        cfg = self._cfg()

        with patch(
            "defenseclaw.commands.cmd_quickstart.resolve_gateway_binary",
            return_value="/custom/defenseclaw-gateway",
        ), patch(
            "defenseclaw.commands.cmd_quickstart._sidecar_running",
            return_value=True,
        ), patch(
            "defenseclaw.commands.cmd_quickstart._run",
        ) as run_mock:
            cmd_quickstart._start_sidecar(cfg, guardrail_ok=True)

        run_mock.assert_called_once_with(
            ["/custom/defenseclaw-gateway", "restart"],
            timeout=15,
        )

    def test_missing_gateway_prints_install_hint(self):
        cfg = self._cfg()

        with patch(
            "defenseclaw.commands.cmd_quickstart.resolve_gateway_binary",
            return_value=None,
        ), patch(
            "defenseclaw.commands.cmd_quickstart.canonical_install_path",
            return_value="/home/me/.local/bin/defenseclaw-gateway",
        ):
            buf = io.StringIO()
            with redirect_stdout(buf):
                cmd_quickstart._start_sidecar(cfg, guardrail_ok=False)

        output = buf.getvalue()
        self.assertIn("defenseclaw-gateway not found", output)
        self.assertIn("DEFENSECLAW_GATEWAY_BIN", output)


if __name__ == "__main__":
    unittest.main()
