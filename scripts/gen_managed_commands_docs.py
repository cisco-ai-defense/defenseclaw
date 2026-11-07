#!/usr/bin/env python3
# ruff: noqa: E501
"""Generate the managed command-availability page of the documentation.

The page lists which ``defenseclaw`` commands a standard user gets on a
managed computer, per operating system, against a per-user install. It is
rendered from ``internal/cli/testdata/managed_commands.json``, which the Go
test ``TestManagedCommandsGolden`` pins to the table in
``internal/cli/managed_commands.go``. That table is also what the Linux and
macOS launcher reads to decide what it runs, and the Go tests check its
Windows column against the managed Windows command tree. Pages that mention
which command a managed computer offers link here instead of saying it again.

    python3 scripts/gen_managed_commands_docs.py          # rewrite the page
    python3 scripts/gen_managed_commands_docs.py --check  # fail if it is stale
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SOURCE = REPO_ROOT / "internal" / "cli" / "testdata" / "managed_commands.json"
TARGET = REPO_ROOT / "docs-site" / "content" / "docs" / "enterprise" / "managed-commands.mdx"

COLUMNS = (
    ("Command", "command"),
    ("Managed Linux", "managed_linux"),
    ("Managed macOS", "managed_macos"),
    ("Managed Windows", "managed_windows"),
    ("Per-user install", "per_user"),
    ("Notes", "note"),
)


def _cell(row: dict, key: str) -> str:
    text = str(row[key]).replace("|", "\\|")
    return "`" + text + "`" if key == "command" else text


def render(data: dict) -> str:
    refusal = data["refusal"]
    linux, darwin = refusal["linux"], refusal["darwin"]
    lines = [
        "---",
        "title: Managed command availability",
        "description: Which defenseclaw commands a standard user can run on a managed Linux, macOS or Windows computer, and which are refused, against a per-user install.",
        "keywords:",
        "  - DefenseClaw managed commands",
        "  - managed launcher",
        "  - command availability",
        "  - defenseclaw status",
        "---",
        "",
        "{/* AUTOGEN: scripts/gen_managed_commands_docs.py from internal/cli/testdata/managed_commands.json. Do not edit by hand. */}",
        "",
        "This table says which `defenseclaw` commands a standard user gets on a computer your organization manages. It is generated from the table the managed launcher reads to decide what it runs, so other pages link here instead of repeating it.",
        "",
        "- **Managed Linux and macOS.** The standard user `defenseclaw` is a launcher. It runs the commands marked Offered and answers every other command with the refusal below. An administrator uses `defenseclaw-gateway` as root.",
        "- **Managed Windows.** There is no launcher: `defenseclaw.exe` is the administrator command. A standard account gets the answer in the table for each command.",
        "- **Per-user install.** The per-user CLI is not part of a managed install.",
        "",
        "| Cell | Meaning |",
        "| --- | --- |",
        "| Offered | The command runs for the user. |",
        "| Refused | The command answers with a message that names the managed alternative, and exits non-zero. |",
        "| Administrators only | The command runs from an elevated prompt; a standard account is told so. |",
        "| Not supported | The platform cannot run the command. |",
        "",
        "| " + " | ".join(name for name, _ in COLUMNS) + " |",
        "| " + " | ".join("---" for _ in COLUMNS) + " |",
    ]
    for row in data["commands"]:
        lines.append("| " + " | ".join(_cell(row, key) for _, key in COLUMNS) + " |")
    lines += [
        "",
        "## The launcher refusal",
        "",
        "On managed Linux, every command the table does not mark Offered prints:",
        "",
        "> " + linux,
        "",
        "On managed macOS it prints:",
        "",
        "> " + darwin,
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Exit non-zero if the page is out of date; do not write.")
    args = parser.parse_args()
    page = render(json.loads(SOURCE.read_text(encoding="utf-8")))
    current = TARGET.read_text(encoding="utf-8") if TARGET.is_file() else ""
    if args.check:
        if current != page:
            print(
                str(TARGET.relative_to(REPO_ROOT)) + " is out of date; run python3 scripts/gen_managed_commands_docs.py",
                file=sys.stderr,
            )
            return 1
        return 0
    TARGET.write_text(page, encoding="utf-8")
    print(("updated: " if current != page else "unchanged: ") + str(TARGET))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
