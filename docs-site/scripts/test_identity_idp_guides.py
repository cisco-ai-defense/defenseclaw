"""Regression checks for the enterprise identity guide examples."""

import re
import unittest
from pathlib import Path

DOCS = Path(__file__).resolve().parents[1] / "content/docs/enterprise"


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


if __name__ == "__main__":
    unittest.main()
