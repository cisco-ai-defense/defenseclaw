"""Keep runnable documentation snippets aligned with the Python CLI parser."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CHECKER = ROOT / "scripts" / "check_docs_cli_commands.py"


def _load_checker():
    spec = importlib.util.spec_from_file_location("check_docs_cli_commands", CHECKER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_documented_defenseclaw_commands_parse() -> None:
    checker = _load_checker()
    failures = checker.validate()
    assert not failures, "\n" + "\n".join(failures)
