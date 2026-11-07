"""The managed command-availability page and the pages that point at it.

The page is generated (scripts/gen_managed_commands_docs.py) from the table the
managed launcher reads. This test checks two structural facts and nothing else:
the page is current, and every page that quotes the launcher refusal links to
it. It does not read sentences for meaning.
"""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DOCS = REPO_ROOT / "docs-site" / "content" / "docs"
PAGE = DOCS / "enterprise" / "managed-commands.mdx"
LINK = "/docs/enterprise/managed-commands"
TABLE = REPO_ROOT / "internal" / "cli" / "testdata" / "managed_commands.json"


class ManagedCommandsPageTests(unittest.TestCase):
    def test_generated_page_is_current(self) -> None:
        result = subprocess.run(
            [sys.executable, "-I", str(REPO_ROOT / "scripts" / "gen_managed_commands_docs.py"), "--check"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_page_is_in_the_enterprise_navigation(self) -> None:
        pages = json.loads((DOCS / "enterprise" / "meta.json").read_text(encoding="utf-8"))["pages"]
        self.assertIn("managed-commands", pages)

    def test_every_page_that_quotes_the_launcher_refusal_links_to_the_page(self) -> None:
        refusal = json.loads(TABLE.read_text(encoding="utf-8"))["refusal"]["linux"]
        # The refusal starts with a sentence the launcher prints verbatim.
        marker = refusal.split(";", 1)[0]
        missing = []
        for page in sorted(DOCS.rglob("*.mdx")):
            if page == PAGE:
                continue
            text = page.read_text(encoding="utf-8")
            if marker in text and LINK not in text:
                missing.append(str(page.relative_to(DOCS)))
        self.assertEqual(missing, [], "pages that quote the launcher refusal must link to " + LINK)


if __name__ == "__main__":
    unittest.main()
