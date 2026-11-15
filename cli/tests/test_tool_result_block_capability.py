# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""rel-1-0-10 GAP-0605: doctor and status name the connectors whose tool results are alert only.

A tool result cannot be unread. Claude Code and Codex (PostToolUse), Amp
(tool.result) and the proxy connectors have a block form for it; every other
connector can only alert, and doctor and status say so with one line,
"tool-result injection: alert only on <connector>". The class comes from the
hook contract manifest.
"""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from defenseclaw.commands.cmd_doctor import (
    _CONNECTOR_LABELS,
    tool_result_block_capability,
    tool_result_injection_limit,
)
from defenseclaw.connector_contracts import HOOK_CONTRACT_MANIFEST

BLOCKS = ("claudecode", "codex", "amp", "openclaw", "zeptoclaw")
ALERT_ONLY = ("cursor", "copilot", "devin", "hermes", "opencode", "antigravity", "kiro")


class ToolResultBlockCapabilityTest(unittest.TestCase):
    def test_every_manifest_connector_is_classified(self) -> None:
        known = set(HOOK_CONTRACT_MANIFEST.get("connectors") or {})
        self.assertEqual(known - set(BLOCKS) - set(ALERT_ONLY), set(), "classify every connector")

    def test_block_form_connectors(self) -> None:
        for name in BLOCKS:
            with self.subTest(connector=name):
                self.assertEqual(tool_result_block_capability(name), "blocks")
                self.assertEqual(tool_result_injection_limit(name), "")

    def test_alert_only_connectors_say_the_limit(self) -> None:
        for name in ALERT_ONLY:
            with self.subTest(connector=name):
                self.assertEqual(tool_result_block_capability(name), "no-hook")
                label = _CONNECTOR_LABELS.get(name, name)
                self.assertEqual(tool_result_injection_limit(name), f"tool-result injection: alert only on {label}")


if __name__ == "__main__":
    unittest.main()
