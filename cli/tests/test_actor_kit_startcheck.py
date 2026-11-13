# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""startcheck.py (deploy/images/actor-kit): the check that keeps a pin bump from shipping a kit whose agent exits at launch.

It must look at both argv the relay starts, the interactive one and the headless (--task) one (GAP-0202 and its residual:
only relay.interactive was checked).
"""
import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "deploy" / "images" / "actor-kit" / "startcheck.py"
SH = SCRIPT.with_suffix(".sh")


@pytest.fixture()
def sc(tmp_path):
    spec = importlib.util.spec_from_file_location("startcheck_under_test", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.WORK = str(tmp_path / "work")
    mod.CONFIG = str(tmp_path / "actor-kit.json")
    Path(mod.WORK).mkdir()
    return mod


ENV = dict(os.environ)


def py(code):
    return [sys.executable, "-c", code]


STAYS_UP = py("import time; time.sleep(30)")
EXITS_AT_ONCE = py("import sys; sys.exit(0)")
REFUSES = py("import sys; print('error: approval_policy \"untrusted\" is no longer supported'); sys.stdout.flush(); import time; time.sleep(30)")


def write_config(sc, interactive, headless):
    Path(sc.CONFIG).write_text(json.dumps({"relay": {"interactive": interactive, "headless": headless}}))


def run_main(sc, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["startcheck.py", "1"])
    rc = sc.main()
    return rc, capsys.readouterr().out


def test_interactive_that_stays_up_passes(sc):
    assert sc.check_interactive(STAYS_UP, ENV, 1) == 0


@pytest.mark.parametrize("argv", [EXITS_AT_ONCE, REFUSES])
def test_interactive_that_exits_or_refuses_fails(sc, argv):
    assert sc.check_interactive(argv, ENV, 1) == 1


@pytest.mark.parametrize(
    "argv,want",
    [
        (STAYS_UP, 0),
        # no network: the agent cannot reach a model and exits with a connection error. Not a configuration refusal.
        (py("import sys; print('connection refused'); sys.exit(1)"), 0),
        (["/nonexistent/agent", "-p", "{prompt}"], 1),
        (py("import sys; print('error: unknown option --bogus'); sys.exit(1)"), 1),
        (py("import sys; print('Usage: agent [options]'); sys.exit(2)"), 1),
        (py("import sys; print('error loading config: bad value'); sys.exit(0)"), 1),
    ],
)
def test_headless_verdicts(sc, argv, want):
    assert sc.check_headless(argv, ENV, 1) == want


def test_headless_prompt_placeholder_is_replaced(sc):
    # The agent sees a real word where {prompt} was, so an argv with a placeholder it cannot parse is not what fails.
    assert sc.check_headless(py("import sys; sys.exit(0 if sys.argv[1:] == ['startcheck'] else 3)") + ["{prompt}"],
                             ENV, 1) == 0


def test_main_checks_the_headless_argv_too(sc, monkeypatch, capsys):
    """Before the fix a refusing headless argv passed: only relay.interactive was started."""
    write_config(sc, STAYS_UP, py("import sys; print('error: unknown option --x'); sys.exit(1)"))
    rc, out = run_main(sc, monkeypatch, capsys)
    assert rc == 1 and "headless" in out and "FAIL" in out
    write_config(sc, STAYS_UP, py("import time; time.sleep(30)"))
    assert run_main(sc, monkeypatch, capsys)[0] == 0
    write_config(sc, STAYS_UP, [])
    rc, out = run_main(sc, monkeypatch, capsys)
    assert rc == 0 and "no headless mode" in out


def test_main_cannot_run_without_an_interactive_argv(sc, monkeypatch, capsys):
    write_config(sc, [], ["x"])
    assert run_main(sc, monkeypatch, capsys)[0] == 2
    Path(sc.CONFIG).unlink()
    assert run_main(sc, monkeypatch, capsys)[0] == 2


def test_the_shell_wrapper_runs_without_a_network():
    """The check makes no model call: the container gets no network (the docstring says so)."""
    assert "--network none" in SH.read_text()
