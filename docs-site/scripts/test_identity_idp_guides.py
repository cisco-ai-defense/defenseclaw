"""Regression checks for the enterprise identity guide examples."""

import re
import unittest
from pathlib import Path

DOCS = Path(__file__).resolve().parents[1] / "content/docs/enterprise"
DOC_ROOT = DOCS.parent


class IdentityGuideExamplesTest(unittest.TestCase):
    def test_okta_examples_do_not_assign_secrets_in_shell_history(self):
        text = (DOCS / "identity-okta.mdx").read_text()
        self.assertIsNone(
            re.search(r"(?m)^\s*export OKTA_(?:API_TOKEN|BIND_PASSWORD)\s*=", text)
        )

    def test_macos_klist_subprocess_is_described_consistently(self):
        text = (DOCS / "identity-sources.mdx").read_text()
        self.assertIn("/usr/bin/klist --json", text)
        self.assertNotIn("`klist` is never run", text)

    def test_managed_macos_profile_command_uses_installed_binary(self):
        text = (DOCS / "identity-entra-id.mdx").read_text()
        self.assertIn(
            "sudo /opt/cisco/defenseclaw/bin/defenseclaw-gateway "
            "enterprise macos profile-explain",
            text,
        )

    def test_discovery_pages_distinguish_inventory_from_destination_audits(self):
        pages = [DOCS / f"{system}.mdx" for system in ("windows", "macos", "linux")]
        pages.append(DOC_ROOT / "ai-discovery.mdx")
        for page in pages:
            with self.subTest(page=page.name):
                text = page.read_text()
                self.assertTrue(
                    re.search(r"does not emit\s+per-entry `ai_component\.observed`", text), page.name
                )
                self.assertTrue(
                    re.search(r"hook\s+decision and asset-policy", text), page.name
                )

    def test_group_cache_guide_states_expiry_is_an_upper_bound(self):
        text = (DOC_ROOT / "guardrail/user-and-group-policies.mdx").read_text()
        self.assertIn("up to\n  15 minutes from the last successful lookup", text)
        self.assertNotIn("the first\n  request after that still uses the old facts", text)

    def test_hilt_setup_guide_names_prompts_and_connector_scope(self):
        text = (DOC_ROOT / "hitl.mdx").read_text()
        for prompt in ("whether to enable the", "which connectors should enforce actions", "which hook fail mode", "which scanner engine"):
            self.assertIn(prompt, text)
        self.assertIn("Codex keeps its own approval setting", text)


if __name__ == "__main__":
    unittest.main()
