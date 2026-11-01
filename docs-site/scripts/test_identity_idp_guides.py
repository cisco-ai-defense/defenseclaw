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

"""Regression checks for the enterprise identity guide examples."""

import re
import unittest
from pathlib import Path

DOCS = Path(__file__).resolve().parents[1] / "content/docs/enterprise"
DOC_ROOT = DOCS.parent


class IdentityGuideExamplesTest(unittest.TestCase):
    def test_okta_examples_do_not_assign_secrets_in_shell_history(self):
        text = (DOCS / "identity-okta.mdx").read_text()
        self.assertIsNone(re.search(r"(?m)^\s*export OKTA_(?:API_TOKEN|BIND_PASSWORD)\s*=", text))

    def test_macos_klist_subprocess_is_described_consistently(self):
        text = (DOCS / "identity-sources.mdx").read_text()
        self.assertIn("/usr/bin/klist --json", text)
        self.assertNotIn("`klist` is never run", text)

    def test_managed_macos_profile_command_uses_installed_binary(self):
        text = (DOCS / "identity-entra-id.mdx").read_text()
        self.assertIn(
            "sudo /opt/cisco/defenseclaw/bin/defenseclaw-gateway enterprise macos profile-explain",
            text,
        )

    def test_discovery_pages_distinguish_inventory_from_destination_audits(self):
        # The 1.0.4 docs rewrite keeps the statement on ai-discovery.mdx; the
        # OS pages link to it, and Windows keeps its own no-names line.
        text = (DOC_ROOT / "ai-discovery.mdx").read_text()
        self.assertTrue(re.search(r"does not emit\s+per-entry `ai_component\.observed`", text))
        self.assertTrue(re.search(r"hook\s+decision and asset-policy", text))
        for system in ("windows", "macos", "linux"):
            with self.subTest(page=f"{system}.mdx"):
                self.assertIn("(/docs/ai-discovery", (DOCS / f"{system}.mdx").read_text())
        self.assertTrue(re.search(r"`removed` records with the user but\s+without the skill or MCP name", (DOCS / "windows.mdx").read_text()))

    def test_group_cache_guide_states_expiry_is_an_upper_bound(self):
        text = (DOC_ROOT / "guardrail/user-and-group-policies.mdx").read_text()
        self.assertIn("up to\n  15 minutes from the last successful lookup", text)
        self.assertNotIn("the first\n  request after that still uses the old facts", text)

    def test_hilt_setup_guide_names_prompts_and_connector_scope(self):
        # hitl.mdx turns approval on with `guardrail hilt on` (cmd_guardrail.py
        # hilt_cmd: "Updating HILT for active connectors:" then Proceed?).
        text = (DOC_ROOT / "hitl.mdx").read_text()
        for prompt in (
            "defenseclaw guardrail hilt on --min-severity HIGH",
            "Updating HILT for active connectors:",
            "Proceed? [Y/n]",
            "add `--connector claudecode` to change one agent only",
        ):
            self.assertIn(prompt, text)
        self.assertIn("| Codex | An alert and a system message. No native ask surface. |", text)


if __name__ == "__main__":
    unittest.main()
