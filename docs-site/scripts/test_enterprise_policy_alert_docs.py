"""Regression check for the documented enterprise policy alert path."""

import unittest
from pathlib import Path

DOC = Path(__file__).resolve().parents[1] / "content/docs/enterprise/operations.mdx"


class PolicyAlertDocsTest(unittest.TestCase):
    def test_verify_policy_warnings_have_explicit_alert_path(self):
        alerts = DOC.read_text().split("### What to alert on", 1)[1].split(
            "## Effective policy digest", 1
        )[0]
        self.assertIn("policy_reload_rejected", alerts)
        self.assertIn("policy_not_applied", alerts)
        self.assertRegex(alerts, r"policy_not_applied[^\n]*changing actions")
        self.assertRegex(alerts, r"policy warnings[^\n]*verify[^\n]*exit code")
        self.assertNotIn("verify` reports each as an error", alerts)


if __name__ == "__main__":
    unittest.main()
