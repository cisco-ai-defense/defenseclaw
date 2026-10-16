"""Managed registration alert and required-sandbox limit copy for 1.0.2."""

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs-site/content/docs"


class Delta19DocsTest(unittest.TestCase):
    def test_enterprise_limit_and_admin_signal(self):
        text = (DOCS / "enterprise/sandboxes.mdx").read_text()
        self.assertIn("**A registration vouches for the account, not for a VM.** The managed", text)
        self.assertNotIn("That never loosens their\n  policy", text)
        self.assertIn("`sandbox.required_for` refuses normal host use", text)
        self.assertIn("machine-owned hook (Claude Code, Codex, Cursor, or Copilot) for a non-exempt", text)
        self.assertIn("effective `when_unavailable` setting is `refuse`", text)
        self.assertIn("`alert`\n  setting when sandboxes are unavailable", text)
        self.assertIn("agent without a machine-owned\n  hook, allows the host run", text)
        self.assertNotIn("`sandbox.required_for` keeps normal host use", text)
        self.assertNotIn("Normal host use of a\n  listed agent remains refused", text)
        self.assertIn("deliberately fakes a running-sandbox registration", text)
        self.assertIn("no root-owned sandbox lifecycle service to vouch", text.lower())
        self.assertIn("the same account can also post lifecycle", text)
        self.assertIn("keep the `docker` group limited", text)
        self.assertIn("whose lifecycle records were dropped can show once", text.lower())
        self.assertIn("Only registrations bound by a build with this signal are watched", text)
        self.assertNotIn("earlier pre-release", text)
        self.assertIn("Registrations bound before the upgrade to 1.0.2 (for example by 1.0.1) are not", text)
        self.assertIn("Root-owned attestation in a later release replaces this signal.", text)
        self.assertIn("The first\naccepted guest record ends the watch", text)
        self.assertIn("disappears later is not reported", text)
        for value in ("relay_without_guest", "running_without_guest", "Sandbox\nregistrations without a guest"):
            self.assertIn(value, text)

    def test_telemetry_and_guide_link(self):
        telemetry = (DOCS / "observability/sandbox-telemetry.mdx").read_text()
        guide = (DOCS / "sandboxes/guide.mdx").read_text()
        events = (ROOT / "docs/OPENSHELL_SANDBOX_EVENTS.md").read_text()
        for text in (telemetry, events):
            for value in ("log.sandbox.registration_without_guest", "relay_without_guest", "running_without_guest", "Sandbox registrations without a guest"):
                self.assertIn(value, text)
            self.assertIn("compliance.activity", text)
            self.assertIn("no outcome", text)
            self.assertNotIn("earlier pre-release", text)
            self.assertIn("bound before the upgrade to 1.0.2 (for example by 1.0.1) are not watched", text)
            self.assertIn("re-create those sandboxes after the upgrade", text)
            self.assertIn("Root-owned attestation in a later release replaces this signal.", text)
            self.assertIn("first accepted record ends the watch", text.lower())
        self.assertIn("/docs/enterprise/sandboxes#require-sandboxes", guide)
        self.assertIn("non-exempt account", guide)
        self.assertIn("`when_unavailable` setting is `refuse`", guide)
        self.assertIn("effective `alert` setting when", guide)
        changelog = (ROOT / "CHANGELOG.md").read_text()
        self.assertNotIn("earlier pre-release", changelog)
        self.assertIn("bound before the upgrade to 1.0.2 (for example by 1.0.1) are not watched", changelog)


if __name__ == "__main__":
    unittest.main()
