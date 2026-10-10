# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""GAP-2498: mcp scan hints for a loopback/private server carry --allow-private."""

from __future__ import annotations

from unittest.mock import patch

import pytest
from defenseclaw.commands.cmd_mcp import _failed_scan_next_step, _mcp_url_needs_allow_private
from defenseclaw.config import MCPServerEntry
from defenseclaw.enforce.policy import PolicyEngine

from tests.test_cmd_mcp import MCPCommandTestBase

LOOP = "http://127.0.0.1:9/mcp"


@pytest.mark.parametrize(
    ("url", "needed"),
    [
        (LOOP, True),
        ("http://localhost:8080/mcp", True),
        ("http://10.0.0.5/mcp", True),
        ("http://[::1]:9/mcp", True),
        ("https://8.8.8.8/mcp", False),
        ("https://mcp.example.com/mcp", False),  # host names are not resolved for a hint
        ("", False),
        (None, False),
    ],
)
def test_url_needs_allow_private(url, needed):
    assert _mcp_url_needs_allow_private(url) is needed


def test_failed_scan_reachability_hint_keeps_allow_private_for_loopback():
    hint = _failed_scan_next_step("down", "codex", "scan failed: connection refused", LOOP)
    assert hint == "fix reachability, then scan again: defenseclaw mcp scan down --connector codex --allow-private"
    public = _failed_scan_next_step("down", "codex", "scan failed: connection refused", "https://8.8.8.8/mcp")
    assert "--allow-private" not in public


class TestMcpAllowPrivateHints(MCPCommandTestBase):
    def _serve_loop(self) -> None:
        self.app.cfg.active_connectors = lambda: ["codex"]  # type: ignore[method-assign]
        self.app.cfg.mcp_servers = (  # type: ignore[method-assign]
            lambda connector=None, **_: [MCPServerEntry(name="down", url=LOOP, transport="sse")]
            if connector == "codex" else []
        )

    @patch("defenseclaw.commands.hint")
    @patch("defenseclaw.commands.cmd_mcp._set_mcp_via_connector")
    def test_set_skip_scan_hint(self, _mock_set, mock_hint):
        self.app.cfg.active_connectors = lambda: ["codex"]  # type: ignore[method-assign]
        result = self.invoke(["set", "down", "--url", LOOP, "--connector", "codex", "--skip-scan"])
        self.assertEqual(result.exit_code, 0, result.output)
        mock_hint.assert_called_once_with(
            "Scan it now:  defenseclaw mcp scan down --connector codex --allow-private"
        )

    def test_unblock_hint(self):
        self._serve_loop()
        PolicyEngine(self.app.store, self.app.cfg).block_for_connector("mcp", "down", "codex", "x")
        result = self.invoke(["unblock", "down", "--connector", "codex"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn(
            "To scan it now, run: defenseclaw mcp scan down --connector codex --allow-private",
            result.output,
        )

    @patch("defenseclaw.commands.hint")
    def test_scan_all_refusal_hint(self, mock_hint):
        self._serve_loop()
        with patch("defenseclaw.commands.cmd_mcp._run_scan", return_value=None):
            self.invoke(["scan", "--all"])
        mock_hint.assert_any_call(
            "Private or loopback servers need --allow-private:  "
            "defenseclaw mcp scan down --connector codex --allow-private"
        )
