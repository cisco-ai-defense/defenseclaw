"""The managed command-availability page and the pages that point at it.

The page is generated (scripts/gen_managed_commands_docs.py) from the table the
managed launcher reads. This test checks three structural facts:

1. the page is current and is in the enterprise navigation;
2. every page that quotes the launcher refusal links to it;
3. every paragraph or table row that names a command of the table in the same
   sentence as a managed computer links to it.

The commands for (3) come from the table itself, so a new row widens the check
with no edit here. The rule is structural: a sentence that puts a managed
computer and a table command together needs the link, whatever verb it uses
(works, unavailable, returns exit code 3, ...). The test does not decide whether
the sentence is true, the table does. "Managed" counts only before a computer,
host, operating system or launcher noun, so "managed by" and "managed connector
state" in per-user prose never need the link. The bare launcher name and the
administrator commands the refusal text names count like table commands.
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

# A sentence or table row that says "managed" about a computer: the word is
# followed by an operating system, host or launcher noun. "Managed by" and
# "managed connector state" are about something else and do not count.
MANAGED = re.compile(
    r"(?<![\w-])managed[\s-]+(?:linux|macos|mac|windows|hosts?|computers?|machines?|devices?|endpoints?"
    r"|workstations?|laptops?|systems?|install\w*|launchers?)(?![\w-])"
    r"|standalone enterprise|enterprise packages?|\b(?:sandbox|packaged|installed) launcher\b",
    re.IGNORECASE,
)
# The generated environment-variable table labels each row "Managed host: `allow`".
# That is a policy value, not a sentence about a managed computer.
POLICY_LABEL = re.compile(r"Managed host: `[a-z_]+`")
# A sentence ends at . ! ? and a list item is its own sentence; a table row is its own unit (see units).
# ":" and ";" do not end one: "On managed Linux, the launcher allows: `x`" is one claim.
SENTENCE_BREAK = re.compile(r"(?<=[.!?])\s+|\n(?=- )")


def command_patterns(table: dict) -> re.Pattern[str]:
    """Return the commands of the table: the launcher commands, the bare launcher and the administrator commands.

    A command is the same with or without backticks. Case matters: `defenseclaw` is the
    command, DefenseClaw is the product.
    """
    verbs: set[str] = set()
    for row in table["commands"]:
        for part in row["command"].split(","):
            # The first word or option after the launcher name: "--help", "status", "sandbox ...".
            found = re.match(r"\s*(?:defenseclaw\s+)?(--[a-z][a-z-]*|[a-z][a-z-]*)", part)
            if found:
                verbs.add(found.group(1))
    admin = {
        match
        for text in table["refusal"].values()
        for match in re.findall(r"enterprise (?:linux|macos|windows) [a-z-]+", text)
    }
    parts = [r"(?<![\w.-])defenseclaw\s+(?:%s)(?![\w-])" % "|".join(re.escape(v) for v in sorted(verbs))]
    parts.append(r"`defenseclaw`")
    parts += [r"(?<![\w-])%s(?![\w-])" % re.escape(command) for command in sorted(admin)]
    return re.compile("|".join(parts))


def units(text: str) -> list[str]:
    """Split a page into table rows, fenced code lines (one unit each) and paragraphs.

    A line of a fenced code block is its own unit: the lines of an example are separate
    commands and comments, not one sentence, and a blank line inside a fence does not
    end it.
    """
    found: list[str] = []
    prose: list[str] = []

    def flush() -> None:
        if prose:
            found.append("\n".join(prose))
            prose.clear()

    fenced = False
    for line in text.split("\n"):
        stripped = line.lstrip()
        if stripped.startswith(("```", "~~~")):
            flush()
            fenced = not fenced
        elif fenced or stripped.startswith("|"):
            flush()
            found.append(line)
        elif not stripped:
            flush()
        else:
            prose.append(line)
    flush()
    return found


def pages_with_unlinked_claims(docs: Path, table: dict) -> list[str]:
    """Return "page: sentence" for every sentence that puts a managed computer and a command together without the link.

    The link must be in the same table row, or in the same paragraph for prose: a link in
    another row of the table does not cover this row.
    """
    commands = command_patterns(table)
    page = docs / "enterprise" / "managed-commands.mdx"
    found = []
    for path in sorted(docs.rglob("*.mdx")):
        if path == page:
            continue
        for unit in units(path.read_text(encoding="utf-8")):
            if LINK in unit:
                continue
            for sentence in SENTENCE_BREAK.split(unit):
                if sentence.lstrip().startswith("#"):
                    continue  # a heading names a topic and says nothing about it
                text = POLICY_LABEL.sub("", sentence)
                if MANAGED.search(text) and commands.search(text):
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
            # Other words for the same claim, and a command given as an option.
            "On managed Linux, `defenseclaw policy show` works.\n",
            "On managed Linux, `defenseclaw status` is unavailable.\n",
            "On managed macOS, `defenseclaw status` is disabled.\n",
            "On managed Linux, `defenseclaw --help` is refused.\n",
            "On managed Linux, `defenseclaw status` returns exit code 3.\n",
            "On managed Linux, `defenseclaw status --json` prints a table of connectors.\n",
            "A managed Mac cannot use `defenseclaw tui`.\n",
            # The command without backticks.
            "On managed Linux, defenseclaw policy show works.\n",
            "On managed Linux, defenseclaw status is unavailable.\n",
            "On managed Linux, enterprise linux status works without sudo.\n",
            # A colon or semicolon between the managed computer and the command is the same sentence.
            "On managed Linux, the launcher allows: `defenseclaw policy show`.\n",
            "On managed macOS, this command is unavailable: `defenseclaw status`.\n",
            "On managed Linux, the launcher offers status; `defenseclaw policy show` works too.\n",
            # The bare launcher and an administrator command, with any verb.
            "On managed Linux, `defenseclaw` works as a full per-user CLI.\n",
            "On managed Linux, `enterprise linux status` works without sudo.\n",
            "On managed macOS, `defenseclaw` is the same program as on a per-user install.\n",
            # A table row needs the link in the row; a link in another row does not cover it.
            "| Managed Linux | `defenseclaw policy show` works. |\n| Managed Windows | [Command availability](%s) |\n" % LINK,
            "| Managed Linux | `defenseclaw policy show` works. |\n\n[table](%s)\n" % LINK,
            # A prose sentence in a fence still needs the link when one line says it all.
            "```text\nOn managed Linux, `defenseclaw policy show` works.\n```\n",
        ):
            with self.subTest(text=text):
                self.assertEqual(len(self.check(text)), 1)

    def test_the_link_or_an_unrelated_sentence_passes(self) -> None:
        for text in (
            "On managed Linux, `defenseclaw policy show` is refused; see [the table](%s).\n" % LINK,
            "Run `defenseclaw doctor` on a per-user install; it runs the checks.\n",
            "A managed host keeps the earlier hook file.\n",
            "On managed Linux the gateway restarts after `enterprise linux ensure`.\n",
            "On a per-user Linux install, `defenseclaw status` works.\n",
            "On managed Linux, the user sees a table of connectors.\n",
            "On managed Linux, `policy show` works.\n",
            "On managed Linux, policy show works.\n",
            "On managed Linux, `defenseclaw status` is unavailable.\nSee [the table](%s).\n" % LINK,
            "| Managed Linux | `defenseclaw policy show` works ([table](%s)). |\n| Managed Windows | `defenseclaw status` works ([table](%s)). |\n" % (LINK, LINK),
            # Per-user prose that says "managed" about something else.
            "This overlay is managed by `defenseclaw setup codex` on a per-user installation.\n",
            "The per-user `defenseclaw status` command displays managed connector state.\n",
            "A rule pack is managed by the product; `defenseclaw status` shows it.\n",
            # The product name is not the command, and a path is not a command.
            "On managed Linux, DefenseClaw runs the gateway as a service.\n",
            "On managed Linux, the state is in `/var/lib/defenseclaw/state`.\n",
            # The generated environment-variable table labels each row with a policy value.
            "| `EXAMPLE_VAR`<br/>Managed host: `allow` | Set by `defenseclaw setup`. |\n",
            "## Managed Linux and `defenseclaw status`\n",
            # The lines of a fenced example are separate commands and comments, blank lines included.
            "```bash\ndefenseclaw guardrail profile explain --connector claudecode\n# standalone enterprise, as root:\nsudo enterprise linux profile-explain\n```\n",
            "```bash\ndefenseclaw status\n\n# managed Linux host, as root:\n```\n",
        ):
            with self.subTest(text=text):
                self.assertEqual(self.check(text), [])


if __name__ == "__main__":
    unittest.main()
