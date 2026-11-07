"""The managed command-availability page and the pages that point at it.

The page is generated (scripts/gen_managed_commands_docs.py) from the table the
managed launcher reads. This test checks three structural facts:

1. the page is current and is in the enterprise navigation;
2. every page that quotes the launcher refusal links to it;
3. every paragraph that makes a claim about what a managed computer offers or
   refuses for a command in the table links to it.

The commands for (3) come from the table itself, so a new row widens the check
with no edit here. A sentence needs the link; the test does not decide whether
the sentence is true, the table does.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DOCS = REPO_ROOT / "docs-site" / "content" / "docs"
PAGE = DOCS / "enterprise" / "managed-commands.mdx"
LINK = "/docs/enterprise/managed-commands"
TABLE = REPO_ROOT / "internal" / "cli" / "testdata" / "managed_commands.json"

# A sentence or table row that talks about a managed computer, ...
MANAGED = re.compile(
    r"(?<![\w-])managed(?![\w-])|standalone enterprise|enterprise packages?"
    r"|\b(?:sandbox|packaged|installed) launcher\b|`defenseclaw` launcher|packaged `defenseclaw`",
    re.IGNORECASE,
)
# ... says something about running, offering or refusing, ...
CLAIM = re.compile(
    r"\b(?:runs?|offers?|accepts?|refus\w*|available|exits?\s+`?\d|elevat\w*|standard (?:user|account))\b",
    re.IGNORECASE,
)
# ... and names the launcher or a command of the table.
CODE_SPAN = re.compile(r"`[^`]*`")
SENTENCE_BREAK = re.compile(r"(?<=[.;:!?])\s+|\n(?=\||- )")


def command_pattern(table: dict) -> re.Pattern[str]:
    """Match the commands the table lists, and the administrator commands the refusal names."""
    verbs: set[str] = set()
    for row in table["commands"]:
        for part in row["command"].split(","):
            found = re.match(r"\s*(?:defenseclaw\s+)?([a-z][a-z-]*)", part)
            if found:
                verbs.add(found.group(1))
    admin = {
        match
        for text in table["refusal"].values()
        for match in re.findall(r"enterprise (?:linux|macos|windows) [a-z-]+", text)
    }
    alternatives = [r"`defenseclaw (?:%s)(?:\s[^`]*)?`|`defenseclaw`" % "|".join(sorted(verbs))]
    alternatives += [r"`[^`]*%s[^`]*`" % re.escape(command) for command in sorted(admin)]
    return re.compile("|".join(alternatives))


def pages_with_unlinked_claims(docs: Path, table: dict) -> list[str]:
    """Return "page: sentence" for every availability claim whose paragraph lacks the link."""
    names = command_pattern(table)
    page = docs / "enterprise" / "managed-commands.mdx"
    found = []
    for path in sorted(docs.rglob("*.mdx")):
        if path == page:
            continue
        for block in re.split(r"\n\s*\n", path.read_text(encoding="utf-8")):
            if LINK in block:
                continue
            for sentence in SENTENCE_BREAK.split(block):
                if sentence.lstrip().startswith("#"):
                    continue  # a heading names a topic and says nothing about it
                prose = CODE_SPAN.sub("", sentence)  # words inside code are not a claim
                if MANAGED.search(sentence) and names.search(sentence) and CLAIM.search(prose):
                    found.append("%s: %s" % (path.relative_to(docs), " ".join(sentence.split())[:120]))
                    break
    return found


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

    def test_every_managed_availability_claim_links_to_the_page(self) -> None:
        table = json.loads(TABLE.read_text(encoding="utf-8"))
        self.assertEqual(
            pages_with_unlinked_claims(DOCS, table),
            [],
            "a paragraph that says what a managed computer offers or refuses must link to " + LINK,
        )


class AvailabilityClaimGateTests(unittest.TestCase):
    """The claim check reads the table, not the wording of one page."""

    def setUp(self) -> None:
        self.table = json.loads(TABLE.read_text(encoding="utf-8"))
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.docs = Path(self.tmp.name)
        (self.docs / "enterprise").mkdir()
        (self.docs / "enterprise" / "managed-commands.mdx").write_text("table\n", encoding="utf-8")

    def check(self, text: str) -> list[str]:
        (self.docs / "sample.mdx").write_text(text, encoding="utf-8")
        return pages_with_unlinked_claims(self.docs, self.table)

    def test_claims_about_table_commands_need_the_link(self) -> None:
        for text in (
            "On managed Linux, `defenseclaw policy show` runs for standard users.\n",
            "On managed Windows, `defenseclaw policy show` runs for standard users without elevation.\n",
            "On managed macOS, `enterprise macos status` runs without elevation.\n",
            "On managed Linux, `defenseclaw status` runs for standard users.\n",
            "On managed Linux and macOS, the user `defenseclaw` launcher offers only sandbox commands.\n",
            "The `defenseclaw` command of the enterprise packages runs only `sandbox` commands.\n",
            "| `defenseclaw doctor` | Refused on a managed computer. |\n",
        ):
            with self.subTest(text=text):
                self.assertEqual(len(self.check(text)), 1)

    def test_the_link_or_an_unrelated_sentence_passes(self) -> None:
        for text in (
            "On managed Linux, `defenseclaw policy show` is refused; see [the table](%s).\n" % LINK,
            "Run `defenseclaw doctor` on a per-user install; it runs the checks.\n",
            "A managed host keeps the earlier hook file.\n",
            "On managed Linux the gateway restarts after `enterprise linux ensure`.\n",
        ):
            with self.subTest(text=text):
                self.assertEqual(self.check(text), [])


if __name__ == "__main__":
    unittest.main()
