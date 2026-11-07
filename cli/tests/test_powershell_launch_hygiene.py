# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Tests start PowerShell through tests.helpers.run_powershell, which skips a host without it.

A test that handed the discovered interpreter (None where PowerShell is not
installed) straight to subprocess failed with a TypeError instead of skipping.
Rather than prove every path to a launch, the launch has one door: the helper
skips when the interpreter is missing, and this check keeps every other launch
out of the test files.

A launch is a subprocess call (run, Popen, check_output, ...) whose command
starts with the discovered interpreter. The check reads the syntax tree, so the
argv may be a list, a tuple, a list added to another, a keyword or a variable,
and the interpreter may be POWERSHELL itself, an alias, or a name bound to it
or, in a file that already uses the helper, to its own which() discovery (a
parametrize argument, a loop variable, an assignment). A file that never uses
the helper and guards its own interpreter is left to that guard. Text that only
mentions the interpreter (skip markers, discovery parameters, comments, scripts
that name it) is not a launch.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest

from tests import helpers

TESTS = Path(__file__).resolve().parent
# Native-Windows only: it asserts PowerShell is present (a Windows runner without
# it must fail, not skip) and finds its own interpreter, pwsh first.
OWN_INTERPRETER = {"test_windows_enterprise_service_contract.py"}
LAUNCHERS = {"run", "Popen", "call", "check_call", "check_output", "create_subprocess_exec", "create_subprocess_shell"}


def _last(func: ast.expr) -> str:
    return func.attr if isinstance(func, ast.Attribute) else func.id if isinstance(func, ast.Name) else ""


def _head(node: ast.expr) -> ast.expr | None:
    """The part of a command that names the program: the first element of an argv."""
    if isinstance(node, (ast.List, ast.Tuple)):
        return _head(node.elts[0]) if node.elts else None
    if isinstance(node, ast.Starred):
        return _head(node.value)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _head(node.left)
    return node


def _is_discovery(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and _last(node.func) == "which"
        and bool(node.args)
        and isinstance(node.args[0], ast.Constant)
        and isinstance(node.args[0].value, str)
        and node.args[0].value.lower().startswith(("powershell", "pwsh"))
    )


def _mentions(node: ast.AST | None, names: set[str], discovery: bool) -> bool:
    if node is None:
        return False
    return any(
        (isinstance(n, ast.Name) and n.id in names)
        or (isinstance(n, ast.Attribute) and n.attr in names)
        or (discovery and _is_discovery(n))
        for n in ast.walk(node)
    )


def _uses_helper(tree: ast.AST) -> bool:
    return any(
        (isinstance(n, ast.Name) and n.id in {"POWERSHELL", "run_powershell"})
        or (isinstance(n, ast.Attribute) and n.attr in {"POWERSHELL", "run_powershell"})
        or (isinstance(n, ast.alias) and n.name in {"POWERSHELL", "run_powershell"})
        for n in ast.walk(tree)
    )


def _bound_names(target: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(target) if isinstance(n, ast.Name)}


def _parametrized_names(call: ast.Call) -> set[str]:
    if _last(call.func) != "parametrize" or len(call.args) < 2:
        return set()
    spec = call.args[0]
    if isinstance(spec, ast.Constant) and isinstance(spec.value, str):
        return {name.strip() for name in spec.value.split(",")}
    if isinstance(spec, (ast.List, ast.Tuple)):
        return {e.value for e in spec.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)}
    return set()


def _interpreter_names(tree: ast.AST, discovery: bool) -> set[str]:
    """POWERSHELL, its import aliases, and every name bound to it, to the fixed point."""
    names = {"POWERSHELL"}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            names |= {a.asname for a in node.names if a.name == "POWERSHELL" and a.asname}
    while True:
        before = len(names)
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and _mentions(_head(node.value), names, discovery):
                names |= set().union(*(_bound_names(t) for t in node.targets))
            elif isinstance(node, (ast.AnnAssign, ast.NamedExpr)) and _mentions(_head(node.value), names, discovery):
                names |= _bound_names(node.target)
            elif isinstance(node, (ast.For, ast.AsyncFor, ast.comprehension)) and _mentions(node.iter, names, discovery):
                names |= _bound_names(node.target)
            elif isinstance(node, ast.Call) and _mentions(node.args[1] if len(node.args) > 1 else None, names, discovery):
                names |= _parametrized_names(node)
        if len(names) == before:
            return names


def direct_launches(source: str) -> list[int]:
    """Lines of the subprocess calls that start the discovered PowerShell themselves."""
    tree = ast.parse(source)
    discovery = _uses_helper(tree)
    names = _interpreter_names(tree, discovery)
    lines = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or _last(node.func) not in LAUNCHERS:
            continue
        argv = node.args[0] if node.args else next((k.value for k in node.keywords if k.arg == "args"), None)
        if argv is not None and _mentions(_head(argv), names, discovery):
            lines.append(node.lineno)
    return sorted(lines)


def test_no_test_file_starts_the_discovered_powershell_itself() -> None:
    offenders = {}
    for path in sorted(TESTS.rglob("*.py")):
        if path.name in {"helpers.py", Path(__file__).name} | OWN_INTERPRETER:
            continue
        lines = direct_launches(path.read_text(encoding="utf-8"))
        if lines:
            offenders[str(path.relative_to(TESTS))] = lines
    assert not offenders, offenders


@pytest.mark.parametrize(
    "source",
    [
        "subprocess.run([POWERSHELL, \x22-NoProfile\x22])",
        "subprocess.run((POWERSHELL, \x22-NoProfile\x22))",
        "subprocess.Popen((POWERSHELL, \x22-File\x22, \x22x.ps1\x22))",
        "subprocess.run(\n    [str(POWERSHELL), \x22-NoProfile\x22],\n)",
        "subprocess.check_output(POWERSHELL)",
        "subprocess.run(args=(POWERSHELL,), check=True)",
        "subprocess.run([POWERSHELL] + extra)",
        "argv = [POWERSHELL, \x22-Command\x22, script]\nsubprocess.run(argv)",
        "argv = (POWERSHELL, \x22-Command\x22, script)\nsubprocess.call(argv)",
        "ps = POWERSHELL\nsubprocess.run([ps, \x22-Help\x22])",
        "from tests.helpers import POWERSHELL as PS\nsubprocess.run([PS, \x22-Help\x22])",
        "subprocess.run([helpers.POWERSHELL, \x22-Help\x22])",
        "found = shutil.which(\x22pwsh\x22)\nsubprocess.run([found, \x22-Help\x22])\nrun_powershell([])",
        "for shell in [POWERSHELL]:\n    subprocess.run((shell, \x22-Help\x22))",
        "from tests.helpers import run_powershell\n"
        "SHELLS = sorted({p for p in (shutil.which(\x22powershell.exe\x22),) if p})\n"
        "@pytest.mark.parametrize(\x22shell\x22, SHELLS)\n"
        "def test_x(shell):\n    subprocess.run([shell, \x22-NoProfile\x22], check=False)",
        "@pytest.mark.parametrize(\x22shell,flag\x22, [(POWERSHELL, 1)])\n"
        "def test_x(shell, flag):\n    subprocess.Popen((shell, \x22-NoProfile\x22))",
    ],
)
def test_a_direct_launch_of_the_discovered_powershell_is_reported(source: str) -> None:
    assert len(direct_launches(source)) == 1


@pytest.mark.parametrize(
    "source",
    [
        "assert POWERSHELL is None or isinstance(POWERSHELL, str)",
        "@pytest.mark.skipif(POWERSHELL is None, reason=\x22x\x22)\ndef test_x(): pass",
        "@pytest.mark.parametrize(\x22shell\x22, [POWERSHELL])\ndef test_x(shell):\n    assert shell is None or shell",
        "# subprocess.run([POWERSHELL, \x22-NoProfile\x22]) is how it used to start\nx = 1",
        "\x22\x22\x22subprocess.run((POWERSHELL, 1))\x22\x22\x22",
        "script = f\x22& {POWERSHELL} -NoProfile -Help\x22\nsubprocess.run([\x22bash\x22, \x22-c\x22, script])",
        "run_powershell([\x22-NoProfile\x22, \x22-Command\x22, script])",
        "@pytest.mark.parametrize(\x22shell\x22, [POWERSHELL])\n"
        "def test_x(shell):\n    run_powershell([\x22-NoProfile\x22], interpreter=shell)",
        "subprocess.run([\x22true\x22])",
        "found = shutil.which(\x22pwsh\x22)\nif found is None:\n    pytest.skip(\x22x\x22)\nsubprocess.run([found, \x22-Help\x22])",
        "subprocess.run([script, POWERSHELL])",
        "argv = [script, POWERSHELL]\nsubprocess.run(argv)",
    ],
)
def test_reading_the_discovered_powershell_is_not_a_launch(source: str) -> None:
    assert direct_launches(source) == []


def test_the_launcher_skips_where_powershell_is_not_installed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(helpers, "POWERSHELL", None)
    with pytest.raises(pytest.skip.Exception):
        helpers.run_powershell(["-NoProfile", "-Command", "exit 0"])
    with pytest.raises(pytest.skip.Exception):
        helpers.run_powershell(["-NoProfile", "-Command", "exit 0"], interpreter=None)


def test_the_launcher_runs_the_interpreter_where_it_is_installed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(helpers, "POWERSHELL", sys.executable)
    completed = helpers.run_powershell(["-c", "print(\x22ran\x22)"], capture_output=True, text=True, check=False)
    assert completed.returncode == 0 and completed.stdout.strip() == "ran"


def test_the_launcher_runs_the_interpreter_it_is_given(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(helpers, "POWERSHELL", None)
    completed = helpers.run_powershell(
        ["-c", "print(\x22ran\x22)"], interpreter=sys.executable, capture_output=True, text=True, check=False
    )
    assert completed.returncode == 0 and completed.stdout.strip() == "ran"
