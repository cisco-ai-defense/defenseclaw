"""Smoke tests that the dctest CLI parses and dispatches every subcommand."""

from __future__ import annotations

import pytest

from dctest import cli


@pytest.mark.parametrize(
    "argv",
    [
        ["matrix", "list"],
        ["matrix", "list", "--include-optional"],
        ["matrix", "list", "--filter", "provider=anthropic-claude-sonnet"],
        ["provider", "plan", "anthropic-claude-sonnet", "--role", "guardrail-only"],
        ["connector", "plan", "codex"],
    ],
)
def test_cli_arg_groups_dispatch(argv, capsys):
    rc = cli.main(argv)
    assert rc == 0
    captured = capsys.readouterr()
    assert captured.out or captured.err


def test_cli_version_flag_exits_zero(capsys):
    # argparse's `version` action raises SystemExit; treat that as success.
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["--version"])
    assert excinfo.value.code == 0
    captured = capsys.readouterr()
    assert captured.out.strip()


def test_doctor_handles_missing_binaries(scrub_provider_env, capsys):
    rc = cli.main(["doctor"])
    captured = capsys.readouterr()
    # Doctor exits non-zero when prerequisites are missing; we only assert it
    # doesn't crash and printed something.
    assert rc in (0, 3)
    assert captured.out
