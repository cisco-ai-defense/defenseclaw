"""Regression checks for the Copilot foreign-hook guide."""

import unittest
from pathlib import Path


PAGE = Path(__file__).resolve().parents[1] / "content/docs/enterprise/foreign-hook-guard.mdx"


class R102Delta4DocsTest(unittest.TestCase):
    def test_copilot_claude_settings_scope(self):
        text = " ".join(PAGE.read_text().split())
        self.assertIn("Cursor and Devin also load Claude Code's user and repository", text)
        self.assertIn("Copilot loads only repository `.claude/settings.json`", text)
        self.assertIn("never `~/.claude/settings.json`", text)
        self.assertIn("(`scope=project`). Run `policy show --project`", text)
        self.assertIn("Copilot does not", text)
