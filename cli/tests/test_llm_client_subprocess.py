# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for plugin_scanner llm_client subprocess handling."""

import os
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


class TestLLMClientSubprocess(unittest.TestCase):
    def test_subprocess_nonzero_raises(self):
        from defenseclaw.scanner.plugin_scanner.llm_client import (
            LLMConfig,
            LLMMessage,
            SubprocessExitError,
            call_llm,
        )

        cfg = LLMConfig(model="gpt-4", python_binary=sys.executable)
        with patch("defenseclaw.scanner.plugin_scanner.llm_client.subprocess.run") as run:
            run.return_value = subprocess.CompletedProcess(
                [sys.executable, "-m", "defenseclaw.llm"],
                returncode=2,
                stdout="",
                stderr="boom",
            )
            with self.assertRaises(SubprocessExitError) as ctx:
                call_llm(cfg, [LLMMessage(role="user", content="hi")])
            self.assertEqual(ctx.exception.returncode, 2)
            self.assertIn("SUBPROCESS_EXIT", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
