# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""``defenseclaw config`` says the truth plainly (r105 cli-tui-obs round b)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner
from defenseclaw.commands import cmd_config
from defenseclaw.config_inspect import ConfigV8WireResult


def _wire() -> ConfigV8WireResult:
    return ConfigV8WireResult(
        wire_version=1,
        kind="effective",
        config_version=9,
        source="/tmp/config.yaml",
        data_dir="/tmp/dc",
        plan_digest="digest",
        network_validation="offline_syntax_and_literal_policy_only",
        valid=None,
        effective={},
    )


def _config(tmp_path: Path, monkeypatch, body: str) -> Path:
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path))
    path = tmp_path / "config.yaml"
    path.write_text("config_version: 9\n" + body)
    return path


def _run(*args: str):
    with (
        patch("defenseclaw.gateway.local_policy_digest", return_value=None),
        patch.object(cmd_config, "inspect_v8_config", return_value=_wire()),
    ):
        return CliRunner().invoke(cmd_config.config_cmd, list(args))


@pytest.mark.parametrize(
    ("body", "key", "value"),
    [
        # GAP-0967: the last named profile; its empty parent map went too.
        ("guardrail:\n  enabled: true\n", "guardrail.profiles.r105", "tr105 temp"),
        # GAP-0967: the last override of a connector's rules.
        (
            "guardrail:\n  enabled: true\n  connectors:\n    codex:\n      mode: action\n",
            "guardrail.connectors.codex.rules.enable",
            '["TRUST-IGNORE-PREVIOUS"]',
        ),
    ],
)
def test_unset_of_the_last_child_restores_the_exact_bytes(tmp_path: Path, monkeypatch, body, key, value) -> None:
    path = _config(tmp_path, monkeypatch, body)
    before = path.read_bytes()
    target = key + ".description" if key.endswith("r105") else key
    as_json = ["--json"] if value.startswith("[") else []
    added = _run("set", target, value, *as_json)
    assert added.exit_code == 0, added.output
    assert path.read_bytes() != before
    removed = _run("unset", key)
    assert removed.exit_code == 0, removed.output
    assert path.read_bytes() == before, path.read_text()


def test_unset_keeps_a_connector_entry_that_says_it_is_guarded(tmp_path: Path, monkeypatch) -> None:
    # guardrail.connectors.<C>: {} means "guarded with the defaults"; only the
    # maps under that entry are pruned.
    path = _config(tmp_path, monkeypatch, "guardrail:\n  enabled: true\n  connectors:\n    codex:\n      mode: action\n")
    removed = _run("unset", "guardrail.connectors.codex.mode")
    assert removed.exit_code == 0, removed.output
    assert "codex: {}" in path.read_text(), path.read_text()
