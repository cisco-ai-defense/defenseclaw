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


if __name__ == "__main__":
    unittest.main()
