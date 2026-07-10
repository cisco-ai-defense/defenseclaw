# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for (local MCP scans
expose LLM API keys / scan subprocess gets API keys).

The vulnerability allowed a malicious local MCP server to read every
secret in the operator's environment because the SDK spawns the
subprocess with ``env=None`` (full inheritance). We verify that
``_safe_subprocess_env`` returns a scrubbed environment containing
only safe baseline names and operator-specified values.
"""

from __future__ import annotations

import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.scanner.mcp import (  # noqa: E402
    _is_exec_control_env_name,
    _is_sensitive_env_name,
    _safe_subprocess_env,
)


class IsSensitiveEnvNameTests(unittest.TestCase):

    def test_api_key_variants_blocked(self):
        for name in [
            "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY",
            "GOOGLE_API_KEY", "GROQ_API_KEY", "MISTRAL_API_KEY",
            "PERPLEXITY_API_KEY", "DEEPSEEK_API_KEY",
            "OPENROUTER_API_KEY", "TOGETHER_API_KEY",
            "REPLICATE_API_TOKEN", "HF_TOKEN", "HUGGINGFACE_TOKEN",
            "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
            "AZURE_OPENAI_KEY", "BEDROCK_API_KEY",
            "GITHUB_TOKEN", "GH_TOKEN", "SPLUNK_HEC_TOKEN",
            "DEFENSECLAW_GATEWAY_TOKEN",
            "DATABASE_PASSWORD", "API_TOKEN",
            "MY_SERVICE_SECRET", "WEBHOOK_SIGNING_KEY",
        ]:
            with self.subTest(name=name):
                self.assertTrue(_is_sensitive_env_name(name),
                                f"{name!r} must be flagged sensitive")

    def test_safe_names_not_blocked(self):
        for name in [
            "PATH", "HOME", "USER", "LANG", "TERM", "TMPDIR",
            "PYTHONPATH", "NODE_PATH", "DISPLAY",
        ]:
            with self.subTest(name=name):
                self.assertFalse(_is_sensitive_env_name(name),
                                 f"{name!r} is a safe baseline name")


class IsExecControlEnvNameTests(unittest.TestCase):
    """F-0221: names that steer executable resolution/loading."""

    def test_exec_control_names_flagged(self):
        for name in [
            "PATH", "NODE_PATH", "NODE_OPTIONS", "PYTHONPATH",
            "PYTHONHOME", "PYTHONSTARTUP",
            "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT",
            "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH",
            # prefix matches (case-insensitive)
            "ld_preload", "dyld_force_flat_namespace",
        ]:
            with self.subTest(name=name):
                self.assertTrue(_is_exec_control_env_name(name),
                                f"{name!r} must be flagged exec-control")

    def test_non_exec_control_names_not_flagged(self):
        for name in [
            "HOME", "USER", "LANG", "TERM", "TMPDIR",
            "MY_FEATURE_FLAG", "PROVIDER_API_KEY", "DISPLAY",
            "GITHUB_TOKEN",
        ]:
            with self.subTest(name=name):
                self.assertFalse(_is_exec_control_env_name(name),
                                 f"{name!r} is not an exec-control name")


class SafeSubprocessEnvTests(unittest.TestCase):

    def test_does_not_inherit_api_keys(self):
        """the spawned subprocess MUST NOT inherit operator
        secret env vars from os.environ."""
        sentinel = "test-scrub-must-not-leak"
        with patch.dict(os.environ, {
            "OPENAI_API_KEY": sentinel,
            "ANTHROPIC_API_KEY": sentinel,
            "GITHUB_TOKEN": sentinel,
            "PATH": "/usr/bin:/bin",
        }, clear=False):
            env = _safe_subprocess_env(None)
        self.assertNotIn("OPENAI_API_KEY", env,
                         "regression: OPENAI_API_KEY leaked")
        self.assertNotIn("ANTHROPIC_API_KEY", env,
                         "regression: ANTHROPIC_API_KEY leaked")
        self.assertNotIn("GITHUB_TOKEN", env,
                         "regression: GITHUB_TOKEN leaked")
        self.assertEqual(env.get("PATH"), "/usr/bin:/bin",
                         "PATH should be inherited from baseline")

    def test_non_exec_operator_env_preserved(self):
        """Non-exec operator/publisher MCP env entries still pass through.

        F-0221: only execution-control vars are stripped; everything
        else the server legitimately needs is preserved (including keys
        that overlap the sensitive-substring list, which the operator
        explicitly placed on the MCP entry).
        """
        operator = {
            "MY_FEATURE_FLAG": "true",
            "PROVIDER_API_KEY": "operator-supplied",
        }
        env = _safe_subprocess_env(operator)
        self.assertEqual(env["MY_FEATURE_FLAG"], "true")
        self.assertEqual(env["PROVIDER_API_KEY"], "operator-supplied")

    def test_operator_cannot_override_exec_control_vars(self):
        """F-0221: untrusted entries MUST NOT set execution-control vars.

        ``MCPServerEntry.env`` comes from connector config / publisher
        manifest. A config that tries to point the allowlisted launcher
        at an attacker-controlled PATH / NODE_PATH / PYTHONPATH or to
        preload a library via LD_PRELOAD / LD_LIBRARY_PATH / DYLD_* must
        NOT win — the safe baseline value is kept instead.
        """
        with patch.dict(os.environ, {"PATH": "/usr/bin:/bin"}, clear=True):
            env = _safe_subprocess_env({
                "PATH": "/tmp/evil",
                "NODE_PATH": "/tmp/evil/node_modules",
                "PYTHONPATH": "/tmp/evil/site-packages",
                "LD_PRELOAD": "/tmp/evil/hook.so",
                "LD_LIBRARY_PATH": "/tmp/evil/lib",
                "DYLD_INSERT_LIBRARIES": "/tmp/evil/hook.dylib",
                # a non-exec var on the same entry must still come through
                "BENIGN_FLAG": "ok",
            })
        # Exec-control overrides from the untrusted entry are rejected.
        self.assertEqual(env.get("PATH"), "/usr/bin:/bin",
                         "operator PATH override must NOT reach the subprocess")
        self.assertNotIn("NODE_PATH", env)
        self.assertNotIn("PYTHONPATH", env)
        self.assertNotIn("LD_PRELOAD", env)
        self.assertNotIn("LD_LIBRARY_PATH", env)
        self.assertNotIn("DYLD_INSERT_LIBRARIES", env)
        # The benign, non-exec var still passes through.
        self.assertEqual(env.get("BENIGN_FLAG"), "ok")

    def test_tmp_evil_path_does_not_reach_subprocess_env(self):
        """Negative case: a PATH=/tmp/evil entry never reaches the env;
        the safe baseline PATH wins."""
        with patch.dict(os.environ, {"PATH": "/usr/bin:/bin"}, clear=True):
            env = _safe_subprocess_env({"PATH": "/tmp/evil"})
        self.assertEqual(env["PATH"], "/usr/bin:/bin")
        self.assertNotEqual(env["PATH"], "/tmp/evil")

    def test_none_values_become_empty_string(self):
        env = _safe_subprocess_env({"X": None})
        self.assertEqual(env["X"], "")

    def test_non_string_keys_skipped(self):
        env = _safe_subprocess_env({1: "ignored", "ok": "kept"})
        self.assertNotIn(1, env)
        self.assertEqual(env["ok"], "kept")

    def test_empty_baseline_when_no_safe_names_set(self):
        """Whens the baseline names are absent from os.environ we
        still return a working dict (not None)."""
        with patch.dict(os.environ, {}, clear=True):
            env = _safe_subprocess_env(None)
        self.assertIsInstance(env, dict)


if __name__ == "__main__":
    unittest.main()
