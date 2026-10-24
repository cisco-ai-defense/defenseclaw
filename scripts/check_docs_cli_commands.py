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
from defenseclaw.commands import cmd_setup
from defenseclaw.main import cli

REPO_ROOT = Path(__file__).resolve().parents[1]
PUBLIC_DOCS_ROOT = REPO_ROOT / "docs-site" / "content" / "docs"
SUPPORTING_DOCS_ROOT = REPO_ROOT / "docs"
SHELL_FENCE_LANGUAGES = {"bash", "console", "sh", "shell", "zsh"}
COMMAND_NAME = "defenseclaw"

# Public Windows enterprise lifecycle commands are implemented by the native
# Cobra binary rather than the Python Click controller parsed below. Keep their
# command paths explicit so inline documentation is checked without pretending
# that Click owns or validates the native command's options.
_NATIVE_GO_COMMAND_PATHS = frozenset(
    {
        ("enterprise",),
        ("enterprise", "windows"),
        *(
            ("enterprise", "windows", action)
            for action in ("install", "upgrade", "repair", "reconcile", "status", "verify", "uninstall")
        ),
    }
)


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

    # Exclude internal design specs/plans — they reference future commands
    # that may not be implemented yet.
    exclude_dirs = {"superpowers", "design"}

    edge_connector_docs_root = REPO_ROOT / "edge-connector"

    paths = [
        *PUBLIC_DOCS_ROOT.rglob("*.mdx"),
        *(p for p in SUPPORTING_DOCS_ROOT.rglob("*.md") if not any(d in p.parts for d in exclude_dirs)),
        *REPO_ROOT.glob("*.md"),
        *(p for p in edge_connector_docs_root.glob("*.md")),
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
    return not relative.name.startswith("PR")


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


@dataclass(frozen=True)
class DocumentedFlag:
    """A flag a documented flags table (a TypeTable under a heading) lists."""

    path: Path
    line: int
    command: tuple[str, ...]
    flag: str


# A heading that names one command's flags, "## All `quickstart` flags" or
# "### `setup provider add` flags", and the TypeTable keys under it, such as
# "--with-judge / --no-judge".
_FLAG_TABLE_HEADING = re.compile(r"^#{2,4}\s.*?`(?:defenseclaw\s+)?([a-z][a-z0-9 -]*)`\s+flags\s*$")
_FLAG_TABLE_KEY = re.compile(r'^\s*"(--[^"]+)"\s*:')
# A heading that is only a command, "## `defenseclaw init`" or "### `sandbox
# setup`", and a markdown table under it whose first column is "Flag", with
# rows such as "| `--fail-mode open\|closed` | ... |".
_COMMAND_HEADING = re.compile(r"^#{2,4}\s+`(?:defenseclaw\s+)?([a-z][a-z0-9 -]*)`\s*$")
_PIPE_FLAG_TABLE_HEADER = re.compile(r"^\|\s*Flags?\s*\|")
_PIPE_FLAG = re.compile(r"(?<![\w-])--[a-z0-9][a-z0-9-]*")


def flag_table_entries(path: Path, text: str) -> list[DocumentedFlag]:
    """Return the flags of each command flags table in *text*.

    A flags table is a TypeTable under a command's flags heading, or a
    markdown table with a "Flag" column under a command's heading.

    GAP-0468: the first-run page listed `quickstart --yes` and
    `--non-interactive` in such a table after the command dropped them, and
    only shell fences and inline references were checked. GAP-0613: its
    `init` table, a markdown table, listed `--agent`, which `init` never had.
    """

    entries: list[DocumentedFlag] = []
    command: tuple[str, ...] | None = None
    pipe_command: tuple[str, ...] | None = None
    in_table = in_pipe_table = False
    for line_number, line in enumerate(text.splitlines(), 1):
        if line.startswith("#"):
            heading = _FLAG_TABLE_HEADING.match(line.strip())
            command = tuple(heading.group(1).split()) if heading else None
            heading = _COMMAND_HEADING.match(line.strip())
            pipe_command = tuple(heading.group(1).split()) if heading else None
            in_table = in_pipe_table = False
            continue
        if pipe_command is not None:
            row = line.strip()
            if _PIPE_FLAG_TABLE_HEADER.match(row):
                in_pipe_table = True
                continue
            if in_pipe_table and not row.startswith("|"):
                in_pipe_table = False
            if in_pipe_table:
                first_cell = re.split(r"(?<!\\)\|", row)[1]
                for span in re.findall(r"`([^`]*)`", first_cell):
                    for flag in _PIPE_FLAG.findall(span):
                        entries.append(DocumentedFlag(path, line_number, pipe_command, flag))
                continue
        if command is None:
            continue
        if "<TypeTable" in line:
            in_table = True
            continue
        if in_table and line.strip().startswith("/>"):
            command, in_table = None, False
            continue
        key = _FLAG_TABLE_KEY.match(line) if in_table else None
        if key:
            for flag in key.group(1).split("/"):
                if flag.strip().startswith("--"):
                    entries.append(DocumentedFlag(path, line_number, command, flag.strip()))
    return entries


def documented_flags() -> list[DocumentedFlag]:
    """Collect the flags of every command flags table in the public docs."""

    entries: list[DocumentedFlag] = []
    for path in PUBLIC_DOCS_ROOT.rglob("*.mdx"):
        entries.extend(flag_table_entries(path, path.read_text(encoding="utf-8")))
    return sorted(entries, key=lambda e: (str(e.path), e.line, e.flag))


def validate_flag(command: click.Command, documented: DocumentedFlag) -> str | None:
    """Return an error when the documented command lacks the documented flag."""

    node = command
    for token in documented.command:
        if not isinstance(node, click.Group) or token not in node.commands:
            return f"unknown command path {' '.join(documented.command)!r}"
        node = node.commands[token]
    names = {name for param in node.params for name in (*param.opts, *param.secondary_opts)}
    if documented.flag not in names:
        return f"`{COMMAND_NAME} {' '.join(documented.command)}` has no option {documented.flag}"
    return None


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
            if isinstance(parameter.type, cmd_setup._PlatformConnectorChoice):
                # Public documentation covers every supported platform. A
                # validator running on native Windows must still parse POSIX
                # OpenClaw examples (and vice versa), while retaining the
                # canonical connector-choice grammar.
                parameter.type = click.Choice(
                    list(cmd_setup._CONNECTOR_NAMES_FALLBACK),
                    case_sensitive=parameter.type.case_sensitive,
                )
        if isinstance(node, click.Group):
            node._result_callback = None
            for child in node.commands.values():
                disable_callbacks(child)

    disable_callbacks(command)
    return command


_COMMAND_PATH_TERMINATOR_MARKERS: tuple[str, ...] = (
    "<", ">", "[", "]", "{", "}", "|", "/", "*", "...", "…",
)


def _is_command_path_terminator(token: str) -> bool:
    """Return True when this token marks the end of a literal command path.

    The native-path allowlist walk and the Click subcommand walk both need to
    stop at options, placeholders, and choice notation. Keeping the predicate
    in one place prevents them from silently drifting apart — if one loop
    grew a new terminator marker but the other did not, the two walks would
    disagree on how far the command path extends.
    """
    if token.startswith("-"):
        return True
    return any(marker in token for marker in _COMMAND_PATH_TERMINATOR_MARKERS)


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

    path: list[str] = []
    for token in tokens[1:]:
        if _is_command_path_terminator(token):
            break
        path.append(token)
    if tuple(path) in _NATIVE_GO_COMMAND_PATHS:
        return None

    node = command
    for token in tokens[1:]:
        if not isinstance(node, click.Group):
            break
        if _is_command_path_terminator(token):
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

    for flag in documented_flags():
        error = validate_flag(command, flag)
        if error is not None:
            failures.append(f"{flag.path.relative_to(REPO_ROOT)}:{flag.line}: {flag.flag}\n  {error}")

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
    print(
        f"Validated {count} documented defenseclaw commands and {len(documented_flags())} flags-table flags "
        f"across {len(documentation_paths())} documentation files."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
