# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""``defenseclaw config`` says the truth plainly (r105 cli-tui-obs round b)."""

from __future__ import annotations

import sys
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


@pytest.mark.parametrize("verb", ["set", "unset"])
def test_a_saved_change_without_the_audit_ack_exits_0_with_a_warning(tmp_path: Path, monkeypatch, verb) -> None:
    # GAP-1366: the change is on disk; only the gateway's audit ack is missing.
    from defenseclaw.logger import CanonicalObservabilityError, Logger

    path = _config(tmp_path, monkeypatch, "gateway:\n  api_port: 18970\n")
    reason = "the gateway did not acknowledge it; gateway.log has the cause. Try again in a minute"
    args = ("set", "gateway.api_port", "19180") if verb == "set" else ("unset", "gateway.api_port")
    with patch.object(Logger, "log_config_change", side_effect=CanonicalObservabilityError(reason)):
        result = _run(*args)
    assert result.exit_code == 0, result.output
    assert ("19180" in path.read_text()) == (verb == "set")
    assert "Change saved, but the gateway did not confirm the audit event" in result.output, result.output
    assert reason in result.output


@pytest.mark.parametrize("key", ["guardrail.retain_judge_bodies", "guardrail.hook_self_heal"])
def test_get_prints_the_schema_default_of_a_key_config_yaml_leaves_out(tmp_path: Path, monkeypatch, key) -> None:
    # GAP-1622: the documented default (true) instead of "not set and has no default".
    _config(tmp_path, monkeypatch, "guardrail:\n  enabled: true\n")
    result = _run("get", key)
    assert result.exit_code == 0, result.output
    assert result.output.splitlines()[-1] == "true", result.output
    assert f"config.yaml does not set {key}" in result.output


def test_migrate_ack_prints_what_the_helper_did(tmp_path: Path, monkeypatch) -> None:
    # GAP-1677: with no migration record the helper says there is nothing to
    # acknowledge; the CLI must not claim it marked a record as read.
    import importlib.util
    import subprocess

    from defenseclaw import config_inspect

    _config(tmp_path, monkeypatch, "")
    said = "There is no config_version 9 migration record (x); nothing to acknowledge.\n"
    # conftest stands in for config_inspect.migrate_config_v9; load the real one.
    spec = importlib.util.spec_from_file_location("_config_inspect_r105", config_inspect.__file__)
    real = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, real)
    spec.loader.exec_module(real)
    monkeypatch.setattr(real, "resolve_trusted_gateway_binary", lambda: "/bin/defenseclaw-gateway")
    monkeypatch.setattr(real, "_run", lambda argv: subprocess.CompletedProcess(argv, 0, said, ""))
    monkeypatch.setattr(config_inspect, "migrate_config_v9", real.migrate_config_v9)
    result = CliRunner().invoke(cmd_config.config_cmd, ["migrate", "--ack"])
    assert result.exit_code == 0, result.output
    assert "nothing to acknowledge" in result.output
    assert "Marked" not in result.output


def test_the_config_schema_id_names_the_version_it_describes() -> None:
    # GAP-1651: the title said v9 and $id named the v8 schema URL.
    import json

    schema = json.loads(
        (Path(__file__).resolve().parents[2] / "schemas/config/v8/defenseclaw-config.schema.json").read_text()
    )
    assert "v9" in schema["title"]
    assert schema["$id"] == "https://schemas.defenseclaw.dev/config/v9/defenseclaw-config.schema.json"


def test_unset_keeps_a_connector_entry_that_says_it_is_guarded(tmp_path: Path, monkeypatch) -> None:
    # guardrail.connectors.<C>: {} means "guarded with the defaults"; only the
    # maps under that entry are pruned.
    path = _config(tmp_path, monkeypatch, "guardrail:\n  enabled: true\n  connectors:\n    codex:\n      mode: action\n")
    removed = _run("unset", "guardrail.connectors.codex.mode")
    assert removed.exit_code == 0, removed.output
    assert "codex: {}" in path.read_text(), path.read_text()
