# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""The CLI says the truth plainly (r105 cli-tui-obs round 3)."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from click.testing import CliRunner
from defenseclaw.commands import cmd_config, cmd_doctor
from defenseclaw.commands.cmd_doctor import _DoctorResult
from defenseclaw.config_inspect import ConfigInspectError, ConfigV8WireResult
from defenseclaw.file_permissions import UNSAFE_PATH_NAMESPACE_VIEW, UnsafePathError


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


@pytest.mark.parametrize("single", ["guardrail:\n  enabled: true\n  connector: codex\n", "claw:\n  mode: codex\nguardrail:\n  enabled: true\n"])
def test_unset_of_a_rule_the_set_added_drops_the_entry_it_created(tmp_path: Path, monkeypatch, single: str) -> None:
    # GAP-0967 / GAP-0004: on a config whose roster comes from the single
    # connector setting, set then unset of a connector rule override
    # restores the exact bytes, with no 'connectors: codex: {}' left.
    path = _config(tmp_path, monkeypatch, single)
    before = path.read_bytes()
    key = "guardrail.connectors.codex.rules.enable"
    added = _run("set", "--json", key, '["TRUST-IGNORE-PREVIOUS"]')
    assert added.exit_code == 0, added.output
    assert path.read_bytes() != before
    removed = _run("unset", key)
    assert removed.exit_code == 0, removed.output
    assert path.read_bytes() == before, path.read_text()


def test_unset_keeps_an_entry_that_puts_the_connector_on_the_roster(tmp_path: Path, monkeypatch) -> None:
    # The single-connector setting names another connector: codex is on the
    # roster only through its entry, so the entry stays ({} = guarded).
    path = _config(tmp_path, monkeypatch, "guardrail:\n  enabled: true\n  connector: claudecode\n")
    key = "guardrail.connectors.codex.rules.enable"
    assert _run("set", "--json", key, '["TRUST-IGNORE-PREVIOUS"]').exit_code == 0
    removed = _run("unset", key)
    assert removed.exit_code == 0, removed.output
    import yaml

    assert yaml.safe_load(path.read_text())["guardrail"]["connectors"] == {"codex": {}}


def test_one_unset_of_the_last_two_profiles_restores_the_exact_bytes(tmp_path: Path, monkeypatch) -> None:
    # GAP-1746: a multi-key unset prunes as the one-at-a-time unsets do.
    path = _config(tmp_path, monkeypatch, "guardrail:\n  enabled: true\n")
    before = path.read_bytes()
    for name in ("a", "b"):
        added = _run("set", f"guardrail.profiles.{name}.description", f"temp {name}")
        assert added.exit_code == 0, added.output
    removed = _run("unset", "guardrail.profiles.a", "guardrail.profiles.b")
    assert removed.exit_code == 0, removed.output
    assert path.read_bytes() == before, path.read_text()
