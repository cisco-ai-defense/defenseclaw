"""Regression check for the documented manual 0.8.x rollback."""

import unittest
from pathlib import Path

DOC = Path(__file__).resolve().parents[1] / "content/docs/reference/migrate-v9.mdx"


class ManualRollbackDocsTest(unittest.TestCase):
    def test_restores_saved_v8_rego_modules(self):
        rollback = DOC.read_text().split("## Going back to 0.8.x", 1)[1]
        self.assertIn("for module in admission guardrail skill_actions; do", rollback)
        self.assertIn('mv "$module.rego.migrated-v9" "$module.rego"', rollback)


if __name__ == "__main__":
    unittest.main()
