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


@pytest.mark.parametrize("key", ["openshell.version", "openshell.auto_pair", "watch.allow_list_bypass_scan"])
def test_get_prints_no_schema_default_for_a_retired_key(tmp_path: Path, monkeypatch, key: str) -> None:
    # GAP-1745: 1.0 reads none of these keys, so no default applies.
    _config(tmp_path, monkeypatch, "guardrail:\n  enabled: true\n")
    assert cmd_config._schema_default(key.split(".")) == (False, None)
    assert cmd_config._schema_default(["guardrail", "retain_judge_bodies"]) == (True, True)


def _namespace_view_error() -> ConfigInspectError:
    cause = UnsafePathError("this agent sandbox hides who owns /home", code=UNSAFE_PATH_NAMESPACE_VIEW)
    try:
        raise ConfigInspectError(str(cause)) from cause
    except ConfigInspectError as exc:
        return exc


def test_doctor_says_the_config_check_did_not_run_in_an_agent_sandbox(tmp_path: Path) -> None:
    # GAP-1561: a warn "not run" row, never FAIL Config validation.
    (tmp_path / "config.yaml").write_text("config_version: 9\n", encoding="utf-8")
    cfg = SimpleNamespace(data_dir=str(tmp_path))
    result = _DoctorResult()
    with (
        patch("defenseclaw.commands.cmd_status._enterprise_profile", return_value=""),
        patch("defenseclaw.config_inspect.inspect_v8_config", side_effect=_namespace_view_error()),
    ):
        cmd_doctor._check_config(cfg, result)
    rows = [row for row in result.checks if row["label"] == "Config validation"]
    assert [row["status"] for row in rows] == ["warn"], rows
    assert rows[0]["detail"].startswith("not run: this agent sandbox hides who owns /home")
    assert all(row["status"] != "fail" for row in result.checks)


def test_doctor_fix_names_the_check_that_did_not_run(tmp_path: Path) -> None:
    (tmp_path / "config.yaml").write_text("config_version: 9\n", encoding="utf-8")
    cfg = SimpleNamespace(data_dir=str(tmp_path))
    with patch("defenseclaw.config_inspect.inspect_v8_config", side_effect=_namespace_view_error()):
        decision = cmd_doctor._plan_canonical_config_preflight(cfg)
    assert decision.state == "blocked"
    assert "did not run" in decision.detail and "normal terminal" in decision.detail
    assert "configuration check failed" not in decision.detail


def test_setup_splunk_help_says_the_probe_runs_before_saving() -> None:
    # GAP-1747: the probe is no longer best-effort or after setup.
    from defenseclaw.commands.cmd_setup import setup

    result = CliRunner().invoke(setup, ["splunk", "--help"], terminal_width=200)
    assert result.exit_code == 0, result.output
    assert "best-effort" not in result.output
    assert "saves nothing" in result.output
    assert "without the live HEC probe that otherwise runs first" in result.output
