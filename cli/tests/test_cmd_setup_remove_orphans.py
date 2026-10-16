# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""`defenseclaw setup remove` of a connector that is not configured (rel-1-0-1:GAP-0009)."""

from __future__ import annotations

import json
import subprocess
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from defenseclaw.commands import cmd_setup


def _app(tmp_path) -> SimpleNamespace:
    guardrail = SimpleNamespace(connectors={"codex": object()}, connector="codex")
    return SimpleNamespace(cfg=SimpleNamespace(guardrail=guardrail, data_dir=str(tmp_path)))


@pytest.mark.parametrize(
    ("pruned", "ok", "expected"),
    [
        (
            (["/home/u/.claude/settings.json"], ""),
            True,
            "removed the DefenseClaw hook entries it had left in /home/u/.claude/settings.json",
        ),
        (([], ""), True, "is already absent; no changes made"),
        (
            ([], "no verified defenseclaw-gateway executable is installed"),
            True,
            "were not checked for DefenseClaw hook entries",
        ),
        (
            ([], "settings.json: parse hook config: invalid character"),
            False,
            "could not be removed: settings.json: parse",
        ),
    ],
)
def test_removing_an_absent_connector_removes_the_hook_entries_it_left(tmp_path, capsys, pruned, ok, expected) -> None:
    # After a rollback, `setup remove claude-code` said "already absent; no
    # changes made" and left the entries that blocked every prompt.
    app = _app(tmp_path)
    with patch.object(cmd_setup, "_prune_orphaned_connector_hooks", return_value=pruned) as prune:
        result = cmd_setup._remove_connector(app, connector="claude-code", restart=False, force=False, yes=True)
    assert result is ok
    prune.assert_called_once_with(app.cfg, "claudecode")
    captured = capsys.readouterr()
    assert expected in captured.out + captured.err
    assert app.cfg.guardrail.connectors.keys() == {"codex"}


def test_the_prune_runs_the_gateway_on_this_data_dir(tmp_path) -> None:
    calls = []

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs["env"]["DEFENSECLAW_HOME"]))
        payload = {"action": "prune-orphans", "ok": True, "removed": {"claudecode": ["/s.json"]}, "failed": {}}
        return subprocess.CompletedProcess(argv, 0, stdout=json.dumps(payload) + "\n", stderr="")

    cfg = SimpleNamespace(data_dir=str(tmp_path))
    with (
        patch.object(cmd_setup, "_gateway_lifecycle_executable", return_value="/opt/dc/defenseclaw-gateway"),
        patch.object(cmd_setup, "run_pinned_executable", side_effect=fake_run),
    ):
        assert cmd_setup._prune_orphaned_connector_hooks(cfg, "claudecode") == (["/s.json"], "")
    assert calls == [
        (
            [
                "/opt/dc/defenseclaw-gateway",
                "connector",
                "prune-orphans",
                "--connector",
                "claudecode",
                "--data-dir",
                str(tmp_path),
                "--json",
            ],
            str(tmp_path),
        )
    ]
