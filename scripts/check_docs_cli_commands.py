#!/usr/bin/env python3
"""Validate ``defenseclaw`` commands throughout the documentation.

Runnable shell-fence examples are parsed completely with the real Click
command tree while every callback is replaced with a no-op. Inline command
references are checked against the same tree through their command path. This
exercises documented command, option, argument, and choice syntax without
loading operator configuration or changing host state.
"""

from __future__ import annotations

import copy
import re
import shlex
import sys
from dataclasses import dataclass
from pathlib import Path

import click
from click.testing import CliRunner
from defenseclaw.main import cli

REPO_ROOT = Path(__file__).resolve().parents[1]
PUBLIC_DOCS_ROOT = REPO_ROOT / "docs-site" / "content" / "docs"
SUPPORTING_DOCS_ROOT = REPO_ROOT / "docs"
SHELL_FENCE_LANGUAGES = {"bash", "console", "sh", "shell", "zsh"}
COMMAND_NAME = "defenseclaw"


@dataclass(frozen=True)
class DocumentedCommand:
    """A CLI invocation extracted from a documentation source location."""

    path: Path
    line: int
    text: str
    inline: bool = False


def _logical_shell_lines(lines: list[tuple[int, str]]) -> list[tuple[int, str]]:
    """Join backslash-continued shell lines while retaining their start lines."""

    logical: list[tuple[int, str]] = []
    current: list[str] = []
    start_line = 0

    for line_number, raw_line in lines:
        line = raw_line.strip()
        if not current:
            start_line = line_number

        if line.endswith("\\"):
            current.append(line[:-1].rstrip())
            continue

        current.append(line)
        logical.append((start_line, " ".join(part for part in current if part)))
        current = []

    if current:
        logical.append((start_line, " ".join(part for part in current if part)))
    return logical


def _extract_defenseclaw_command(text: str) -> str | None:
    """Extract a safe-to-parse DefenseClaw invocation from one shell statement."""

    try:
        tokens = shlex.split(text, comments=True, posix=True)
    except ValueError:
        return None

    try:
        command_index = tokens.index(COMMAND_NAME)
    except ValueError:
        return None

    # Accept environment assignments and the two conventional wrappers used
    # in runnable examples.  A later ``defenseclaw`` token is often a user,
    # group, path, service, or index name in an unrelated shell command.
    prefix = tokens[:command_index]
    while prefix and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", prefix[0]):
        prefix.pop(0)
    if prefix and prefix[0] == "sudo":
        prefix.pop(0)
    if prefix and prefix[0] == "env":
        prefix.pop(0)
        while prefix and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", prefix[0]):
            prefix.pop(0)
    if prefix:
        return None

    kept: list[str] = []
    for token in tokens[command_index:]:
        if token in {"|", "||", "&&", ";", ">", ">>"}:
            break
        kept.append(token)
    return shlex.join(kept) if kept else None


def documentation_paths() -> list[Path]:
    """Return every public and supporting Markdown documentation file."""

    paths = [
        *PUBLIC_DOCS_ROOT.rglob("*.mdx"),
        *SUPPORTING_DOCS_ROOT.rglob("*.md"),
        *REPO_ROOT.glob("*.md"),
    ]
    return sorted(set(paths))


def _check_inline_commands(path: Path) -> bool:
    """Return whether prose command references in *path* are current-contract docs.

    Historical changelogs, completed PR notes, and design/development specs
    intentionally preserve commands proposed at that point in time. Runnable
    fences remain checked everywhere, but inline current-command validation is
    limited to the public site, README, and active top-level operator guides.
    """

    if path.is_relative_to(PUBLIC_DOCS_ROOT):
        return True
    if path == REPO_ROOT / "README.md":
        return True
    if not path.is_relative_to(SUPPORTING_DOCS_ROOT):
        return False
    relative = path.relative_to(SUPPORTING_DOCS_ROOT)
    if len(relative.parts) != 1:
        return False
    return not relative.name.startswith(("PR", "CONNECTOR-REMAINING-FIXES"))


def documented_commands() -> list[DocumentedCommand]:
    """Collect runnable and inline DefenseClaw commands from documentation."""

    commands: list[DocumentedCommand] = []
    for path in documentation_paths():
        fence_lines: list[tuple[int, str]] = []
        in_shell_fence = False
        fence_start = 0

        raw_text = path.read_text(encoding="utf-8")
        for line_number, raw_line in enumerate(raw_text.splitlines(), 1):
            fence = re.match(r"^```([^\s{]*)", raw_line.strip())
            if fence:
                if in_shell_fence:
                    for command_line, text in _logical_shell_lines(fence_lines):
                        command = _extract_defenseclaw_command(text)
                        if command:
                            commands.append(DocumentedCommand(path, command_line, command))
                    fence_lines = []
                    in_shell_fence = False
                    continue

                language = fence.group(1).lower()
                if language in SHELL_FENCE_LANGUAGES:
                    in_shell_fence = True
                    fence_start = line_number
                continue

            if in_shell_fence:
                fence_lines.append((line_number, raw_line))

        if in_shell_fence:
            raise ValueError(f"Unclosed shell fence in {path.relative_to(REPO_ROOT)}:{fence_start}")

        if not _check_inline_commands(path):
            continue

        # Single-backtick command references often appear in prose and tables.
        # They need command-path validation too: stale names such as a removed
        # top-level group otherwise evade the runnable-fence checks.
        for match in re.finditer(r"(?<!`)`(defenseclaw(?:\s+[^`\n]+)?)`(?!`)", raw_text):
            line = raw_text.count("\n", 0, match.start()) + 1
            line_start = raw_text.rfind("\n", 0, match.start()) + 1
            line_end = raw_text.find("\n", match.end())
            if line_end < 0:
                line_end = len(raw_text)
            if "docs-cli-ignore" in raw_text[line_start:line_end]:
                continue
            text = match.group(1).replace(r"\|", "|").split(r"\n", 1)[0].strip()
            first_argument = text.partition(" ")[2].partition(" ")[0]
            if first_argument and first_argument != first_argument.lower():
                # Diagram labels such as "defenseclaw CLI\nPython" name a
                # component rather than documenting a command invocation.
                continue
            commands.append(DocumentedCommand(path, line, text, inline=True))

    return commands


def _no_op_command_tree() -> click.Command:
    """Clone the Click tree with callbacks and filesystem existence checks disabled."""

    command = copy.deepcopy(cli)
    command.name = COMMAND_NAME

    def disable_callbacks(node: click.Command) -> None:
        """Recursively neutralize callbacks while preserving the command grammar."""

        node.callback = lambda **_kwargs: None
        for parameter in node.params:
            if isinstance(parameter.type, click.Path):
                # The docs use representative paths.  This check validates
                # the CLI grammar, not whether a reader created that file.
                parameter.type.exists = False
        if isinstance(node, click.Group):
            node._result_callback = None
            for child in node.commands.values():
                disable_callbacks(child)

    disable_callbacks(command)
    return command


def _validate_inline_path(command: click.Command, documented: DocumentedCommand) -> str | None:
    """Return an error when an inline reference names an unknown command path.

    Inline references frequently use placeholders or compact choice notation,
    so arguments and options belong to the full shell-fence validator. Command
    groups and subcommands, however, must always be literal and can be checked
    without inventing placeholder values.
    """

    try:
        tokens = shlex.split(documented.text, comments=False, posix=True)
    except ValueError as exc:
        return str(exc)
    if not tokens or tokens[0] != COMMAND_NAME:
        return None

    node = command
    for token in tokens[1:]:
        if not isinstance(node, click.Group):
            break
        if token.startswith("-") or any(
            marker in token for marker in ("<", ">", "[", "]", "{", "}", "|", "/", "*", "...", "…")
        ):
            break
        child = node.commands.get(token)
        if child is None:
            return f"unknown command path component {token!r} after {node.name!r}"
        node = child
    return None


def validate() -> list[str]:
    """Return location-rich failures for documentation commands that do not parse."""

    command = _no_op_command_tree()
    runner = CliRunner()
    failures: list[str] = []

    for documented in documented_commands():
        if documented.inline:
            error = _validate_inline_path(command, documented)
            if error is None:
                continue
            location = f"{documented.path.relative_to(REPO_ROOT)}:{documented.line}"
            failures.append(f"{location}: {documented.text}\n  {error}")
            continue

        args = shlex.split(documented.text)[1:]
        result = runner.invoke(command, args, catch_exceptions=False)
        if result.exit_code == 0:
            continue
        location = f"{documented.path.relative_to(REPO_ROOT)}:{documented.line}"
        detail = result.output.strip().replace("\n", " | ")
        failures.append(f"{location}: {documented.text}\n  {detail}")

    return failures


def main() -> int:
    """Run the documentation command validator as a command-line program."""

    failures = validate()
    if failures:
        print("Documented CLI command validation failed:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    count = len(documented_commands())
    print(f"Validated {count} documented defenseclaw commands across {len(documentation_paths())} documentation files.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
