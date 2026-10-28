"""GAP-0468: every flag a command's docs flags table lists is one the command takes."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

pytestmark = pytest.mark.supported_connector_host

ROOT = Path(__file__).resolve().parents[2]
CHECKER = ROOT / "scripts" / "check_docs_cli_commands.py"

PAGE = '''## All `quickstart` flags

<TypeTable
  type={{
    "--with-judge / --no-judge": {
      type: "flag",
    },
    "--yes": {
      type: "flag",
    },
  }}
/>

## Next steps

    "--not-in-a-table": {
'''


def _load_checker() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_docs_cli_commands_flags", CHECKER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_flag_table_entries_reads_each_flag_under_the_heading() -> None:
    checker = _load_checker()
    entries = checker.flag_table_entries(Path("page.mdx"), PAGE)
    assert [(e.command, e.flag) for e in entries] == [
        (("quickstart",), "--with-judge"),
        (("quickstart",), "--no-judge"),
        (("quickstart",), "--yes"),
    ]


def test_a_flag_the_command_lacks_fails() -> None:
    checker = _load_checker()
    tree = checker._no_op_command_tree()
    entries = {e.flag: e for e in checker.flag_table_entries(Path("page.mdx"), PAGE)}
    assert checker.validate_flag(tree, entries["--no-judge"]) is None
    error = checker.validate_flag(tree, entries["--yes"])
    assert error == "`defenseclaw quickstart` has no option --yes"
    nested = checker.DocumentedFlag(Path("page.mdx"), 1, ("setup", "provider", "add"), "--base-url")
    assert checker.validate_flag(tree, nested) is None
    unknown = checker.DocumentedFlag(Path("page.mdx"), 1, ("no-such-command",), "--x")
    assert "unknown command path" in checker.validate_flag(tree, unknown)


def test_the_first_run_quickstart_table_is_checked_and_current() -> None:
    checker = _load_checker()
    first_run = [
        e for e in checker.documented_flags() if e.path.name == "first-run.mdx" and e.command == ("quickstart",)
    ]
    flags = {e.flag for e in first_run}
    assert {"--connector", "--agent", "--skip-gateway", "--json-summary", "--json"} <= flags
    assert not flags & {"--yes", "--non-interactive"}


PIPE_PAGE = '''## `defenseclaw init`

| Flag | What it does |
| --- | --- |
| `--connector` / `--agent` `<name>` | Pre-select a single agent. |
| `--fail-mode open\\|closed` | Hook fail mode. |
| `--llm-provider`, `--llm-model` | The LLM settings. |

`--not-in-a-table` is prose.

## Which to use

| Flag | What it does |
| --- | --- |
| `--under-a-non-command-heading` | Not read. |
'''


def test_a_markdown_flag_table_under_a_command_heading_is_read() -> None:
    # GAP-0613: only TypeTables were read, so the init table's `--agent` went unchecked.
    checker = _load_checker()
    entries = checker.flag_table_entries(Path("page.mdx"), PIPE_PAGE)
    assert [(e.command, e.flag) for e in entries] == [
        (("init",), "--connector"),
        (("init",), "--agent"),
        (("init",), "--fail-mode"),
        (("init",), "--llm-provider"),
        (("init",), "--llm-model"),
    ]
    tree = checker._no_op_command_tree()
    agent = next(e for e in entries if e.flag == "--agent")
    assert checker.validate_flag(tree, agent) == "`defenseclaw init` has no option --agent"


def test_the_first_run_init_table_lists_every_init_option_and_no_other() -> None:
    # GAP-0613: the table listed `--agent` and left out options `init --help` prints.
    checker = _load_checker()
    documented = {
        e.flag for e in checker.documented_flags() if e.path.name == "first-run.mdx" and e.command == ("init",)
    }
    init = checker._no_op_command_tree().commands["init"]
    options = {
        name
        for param in init.params
        if not getattr(param, "hidden", False)
        for name in (*param.opts, *param.secondary_opts)
        if name.startswith("--") and name != "--help"
    }
    assert documented == options
