"""Regression checks for policy-related reference claims."""

import unittest
from pathlib import Path


DOCS = Path(__file__).resolve().parents[1] / "content/docs/reference"


class ReferencePolicyDocsTest(unittest.TestCase):
    def test_zero_consensus_uses_sdk_default_without_disabling_llm(self):
        text = (DOCS / "configuration.mdx").read_text()
        row = next(line for line in text.splitlines()
                   if line.startswith("| `scanners.skill_scanner.llm_consensus_runs` |"))
        self.assertIn("`0` leaves the SDK default", row)
        self.assertIn("`use_llm: false` disables LLM analysis", row)


    def test_secure_client_status_and_digest_exceptions_are_explicit(self):
        text = (DOCS / "cli.mdx").read_text()
        status = next(line for line in text.splitlines()
                      if line.startswith("| `defenseclaw status` |"))
        digest = next(line for line in text.splitlines()
                      if line.startswith("| `defenseclaw-gateway policy digest"))
        self.assertIn("Secure Client", status)
        self.assertIn("neither the Policy line nor the JSON `policy` object", status)
        self.assertIn("Secure Client", digest)
        self.assertIn("unknown-command error", digest)
        section = text.split("### Policy generation and digest", 1)[1].split("## ", 1)[0]
        self.assertIn("does not apply to Secure Client", section)


    def test_remote_skill_scan_uses_gateway_timeout(self):
        text = (DOCS / "configuration.mdx").read_text()
        row = next(line for line in text.splitlines()
                   if line.startswith("| `scanners.skill_scanner.timeouts.scan_s` |"))
        self.assertIn("`defenseclaw skill scan --remote`", row)
        self.assertIn("`defenseclaw skill scan` without `--remote`", row)


if __name__ == "__main__":
    unittest.main()
