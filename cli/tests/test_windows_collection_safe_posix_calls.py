"""Test modules must import on Windows.

A skip marker is evaluated when the module is imported, so a bare
``os.geteuid()`` in a ``skipif`` condition raises ``AttributeError`` during
collection on Windows even when the module is skipped there. Every POSIX-only
call in a decorator or a module-level assignment must sit behind a platform
guard (``os.name``, ``sys.platform`` or ``hasattr(os, ...)``) earlier in the
same ``or`` / ``and`` chain.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

_POSIX_ONLY = {"geteuid", "getuid", "getgid", "getegid", "getpgid", "getpgrp", "fork", "setsid", "killpg", "chown"}
_GUARDS = ("os.name", "sys.platform", "hasattr(os")
_TESTS = Path(__file__).resolve().parent


def _is_posix_call(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in _POSIX_ONLY
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "os"
    )


def _unguarded(expr: ast.AST) -> list[int]:
    """Line numbers of POSIX-only calls in ``expr`` with no earlier platform guard."""
    found: list[int] = []

    def walk(node: ast.AST, guarded: bool) -> None:
        if _is_posix_call(node) and not guarded:
            found.append(node.lineno)
        if isinstance(node, ast.BoolOp):
            seen = guarded
            for value in node.values:
                walk(value, seen)
                seen = seen or any(g in ast.unparse(value) for g in _GUARDS)
            return
        if isinstance(node, ast.IfExp):
            walk(node.test, guarded)
            test = ast.unparse(node.test)
            inner = guarded or any(g in test for g in _GUARDS)
            walk(node.body, inner)
            walk(node.orelse, inner)
            return
        for child in ast.iter_child_nodes(node):
            walk(child, guarded)

    walk(expr, False)
    return found


def _import_time_expressions(tree: ast.Module):
    """Decorators and module/class-level statements: everything run at import."""
    stack: list[ast.AST] = list(tree.body)
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            yield from node.decorator_list
            if isinstance(node, ast.ClassDef):
                stack.extend(node.body)
        elif isinstance(node, (ast.If, ast.Try, ast.With)):
            stack.extend(getattr(node, "body", []))
            stack.extend(getattr(node, "orelse", []))
            stack.extend(getattr(node, "finalbody", []))
        elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.Expr)):
            yield node


def _offenders(source: str) -> list[int]:
    lines: list[int] = []
    for expr in _import_time_expressions(ast.parse(source)):
        lines.extend(_unguarded(expr))
    return sorted(set(lines))


def test_every_test_module_imports_without_posix_only_calls() -> None:
    bad = {}
    for path in sorted(_TESTS.rglob("test_*.py")):
        if path.name == Path(__file__).name:
            continue
        lines = _offenders(path.read_text(encoding="utf-8"))
        if lines:
            bad[str(path.relative_to(_TESTS))] = lines
    assert not bad, f"POSIX-only call evaluated at import without a platform guard: {bad}"


@pytest.mark.parametrize(
    "source",
    [
        "import os, pytest\n@pytest.mark.skipif(os.geteuid() == 0, reason=\"x\")\ndef test_a(): pass\n",
        "import os\nIS_ROOT = os.getuid() == 0\n",
        "import os, pytest\nclass T:\n    @pytest.mark.skipif(os.geteuid() == 0 or os.name == \"nt\", reason=\"x\")\n    def test_a(self): pass\n",
    ],
)
def test_the_scan_flags_a_bare_posix_call(source: str) -> None:
    assert _offenders(source)


@pytest.mark.parametrize(
    "source",
    [
        "import os, pytest\n@pytest.mark.skipif(os.name == \"nt\" or os.geteuid() == 0, reason=\"x\")\ndef test_a(): pass\n",
        "import os, pytest\n@pytest.mark.skipif(hasattr(os, \"geteuid\") and os.geteuid() == 0, reason=\"x\")\ndef test_a(): pass\n",
        "import os, sys\nIS_ROOT = False if sys.platform == \"win32\" else os.geteuid() == 0\n",
        "import os\ndef test_a():\n    assert os.geteuid() >= 0\n",
    ],
)
def test_the_scan_allows_a_guarded_or_runtime_call(source: str) -> None:
    assert not _offenders(source)
