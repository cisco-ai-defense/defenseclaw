# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""Direct unit tests for the new connector-agnostic ``llm_keys`` module.

The legacy tests in ``test_guardrail.py`` continue to exercise the
back-compat shim via ``defenseclaw.guardrail import …``. These tests
exercise the post-S4.4 module directly so we lock in the contract
that downstream code (Codex / Claude Code / ZeptoClaw guardrail
flows) can import without dragging in OpenClaw paperwork.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from unittest.mock import patch

from defenseclaw import llm_keys


class TestDetectApiKeyEnv(unittest.TestCase):
    """Prefix-first routing — see codeguard-1-hardcoded-credentials."""

    def test_bedrock_anthropic_routes_to_bedrock(self):
        self.assertEqual(
            llm_keys.detect_api_key_env(
                "bedrock/us.anthropic.claude-3-5-sonnet-20241022"
            ),
            "AWS_BEARER_TOKEN_BEDROCK",
        )

    def test_anthropic_prefix(self):
        self.assertEqual(
            llm_keys.detect_api_key_env("anthropic/claude-3-5-sonnet"),
            "ANTHROPIC_API_KEY",
        )

    def test_openai_prefix(self):
        self.assertEqual(
            llm_keys.detect_api_key_env("openai/gpt-4o"),
            "OPENAI_API_KEY",
        )

    def test_azure_prefix(self):
        self.assertEqual(
            llm_keys.detect_api_key_env("azure/my-deployment"),
            "AZURE_OPENAI_API_KEY",
        )

    def test_openrouter_prefix(self):
        self.assertEqual(
            llm_keys.detect_api_key_env("openrouter/anthropic/claude-3"),
            "OPENROUTER_API_KEY",
        )

    def test_google_prefixes(self):
        for model in (
            "gemini/pro",
            "google/text-bison",
            "vertex_ai/text-bison",
        ):
            self.assertEqual(
                llm_keys.detect_api_key_env(model),
                "GOOGLE_API_KEY",
            )

    def test_substring_fallback_claude(self):
        self.assertEqual(
            llm_keys.detect_api_key_env("claude-3-5"),
            "ANTHROPIC_API_KEY",
        )

    def test_substring_fallback_gpt(self):
        self.assertEqual(
            llm_keys.detect_api_key_env("gpt-4o"),
            "OPENAI_API_KEY",
        )

    def test_unknown_returns_generic(self):
        self.assertEqual(
            llm_keys.detect_api_key_env("totally-made-up"),
            "LLM_API_KEY",
        )


class TestModelToProxyName(unittest.TestCase):
    def test_strips_provider_prefix(self):
        self.assertEqual(
            llm_keys.model_to_proxy_name("anthropic/claude-opus-4-5"),
            "claude-opus-4-5",
        )

    def test_strips_anthropic_dash(self):
        # ``model_to_proxy_name`` must also strip ``anthropic-`` after
        # the slash split — operators routinely paste full provider
        # qualifiers and we need a clean alias.
        self.assertEqual(
            llm_keys.model_to_proxy_name("anthropic/anthropic-claude-3"),
            "claude-3",
        )

    def test_passthrough_when_no_slash(self):
        self.assertEqual(
            llm_keys.model_to_proxy_name("gpt-4o"),
            "gpt-4o",
        )


class TestDeriveMasterKey(unittest.TestCase):
    """Direct module-level test for ``derive_master_key``.

    The legacy back-compat name ``_derive_master_key`` is covered in
    ``test_guardrail.py``; here we assert the public name resolves to
    the same implementation.
    """

    def test_deterministic(self):
        with tempfile.TemporaryDirectory() as tmp:
            key_path = os.path.join(tmp, "device.key")
            with open(key_path, "wb") as f:
                f.write(b"some-random-bytes")
            k1 = llm_keys.derive_master_key(key_path)
            k2 = llm_keys.derive_master_key(key_path)
            self.assertEqual(k1, k2)
            self.assertTrue(k1.startswith("sk-dc-"))
            self.assertEqual(len(k1), 6 + 32)

    def test_raises_on_missing(self):
        # Patch Path so the fallback ``~/.defenseclaw/device.key``
        # also points at a non-existent location. Otherwise this
        # test fails on developer machines that already have a real
        # device.key from previous ``defenseclaw init`` runs.
        with tempfile.TemporaryDirectory() as tmp, \
             patch("defenseclaw.llm_keys.Path") as mock_path:
            from pathlib import Path as RealPath
            mock_path.home.return_value = RealPath(tmp)
            with self.assertRaises(RuntimeError):
                llm_keys.derive_master_key("/nonexistent/device.key")


class TestBackCompatShim(unittest.TestCase):
    """``defenseclaw.guardrail`` must re-export every public name.

    Catches accidental breakage of the back-compat surface.  If you
    move a symbol out of ``llm_keys`` or ``openclaw_guardrail``, make
    sure the shim still re-exports it; otherwise downstream callers
    (cmd_setup, cmd_doctor, cmd_uninstall, third-party plugins) will
    silently break.
    """

    def test_shim_exports_llm_keys_surface(self):
        from defenseclaw import guardrail
        self.assertIs(
            guardrail.detect_api_key_env,
            llm_keys.detect_api_key_env,
        )
        self.assertIs(
            guardrail.model_to_proxy_name,
            llm_keys.model_to_proxy_name,
        )
        # Legacy underscore-prefixed name is preserved.
        self.assertIs(
            guardrail._derive_master_key,
            llm_keys.derive_master_key,
        )

    def test_shim_exports_openclaw_surface(self):
        from defenseclaw import guardrail, openclaw_guardrail
        for name in (
            "patch_openclaw_config",
            "restore_openclaw_config",
            "uninstall_openclaw_plugin",
            "detect_current_model",
            "record_pristine_backup",
            "pristine_backup_path",
            "_backup",
            "_register_plugin_in_config",
            "_unregister_plugin_from_config",
            "_remove_from_plugins_allow",
            "_preserve_ownership",
        ):
            self.assertIs(
                getattr(guardrail, name),
                getattr(openclaw_guardrail, name),
                f"shim re-export drift: {name}",
            )


if __name__ == "__main__":
    unittest.main()
