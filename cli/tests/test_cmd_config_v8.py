# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import click
from click.testing import CliRunner
from defenseclaw.commands import cmd_config
from defenseclaw.config_inspect import ConfigInspectError, ConfigV8WireResult


def _wire(kind: str, *, effective: dict | None = None) -> ConfigV8WireResult:
    return ConfigV8WireResult(
        wire_version=1,
        kind=kind,
        config_version=8,
        source="/tmp/config.yaml",
        data_dir="/tmp/dc",
        plan_digest="digest",
        network_validation="offline_syntax_and_literal_policy_only",
        valid=True if kind == "validation" else None,
        effective=effective,
    )


def test_v8_validate_uses_go_helper_and_quiet_has_no_output(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    config_path.write_text("config_version: 8\nobservability: {}\n", encoding="utf-8")
    runner = CliRunner()
    with (
        patch.object(cmd_config.config_module, "config_path", return_value=config_path),
        patch.object(cmd_config, "inspect_v8_config", return_value=_wire("validation")) as inspect,
    ):
        result = runner.invoke(cmd_config.config_cmd, ["validate", "--quiet"])

    assert result.exit_code == 0
    assert result.output == ""
    inspect.assert_called_once_with("validate", config_path=str(config_path))


def test_v8_detection_accepts_explicit_int_tag_and_malformed_fallback(tmp_path: Path) -> None:
    tagged = tmp_path / "tagged.yaml"
    tagged.write_text("config_version: !!int 8\nobservability: {}\n", encoding="utf-8")
    malformed = tmp_path / "malformed.yaml"
    malformed.write_text("config_version: !!int 8\nobservability: [\n", encoding="utf-8")
    nested = tmp_path / "nested.yaml"
    nested.write_text("wrapper:\n  config_version: 8\n", encoding="utf-8")

    assert cmd_config._looks_like_v8_config(str(tagged)) is True
    assert cmd_config._looks_like_v8_config(str(malformed)) is True
    assert cmd_config._looks_like_v8_config(str(nested)) is False


def test_v8_detection_deep_yaml_falls_back_without_parser_recursion(tmp_path: Path) -> None:
    deeply_nested = tmp_path / "deeply-nested.yaml"
    deeply_nested.write_text(
        "config_version: 8\npayload: " + "[" * 1_000 + "]" * 1_000 + "\n",
        encoding="utf-8",
    )

    assert cmd_config._looks_like_v8_config(str(deeply_nested)) is True


def test_v8_validate_surfaces_safe_helper_error(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    config_path.write_text("config_version: 8\nobservability: {}\n", encoding="utf-8")
    with (
        patch.object(cmd_config.config_module, "config_path", return_value=config_path),
        patch.object(cmd_config, "inspect_v8_config", side_effect=ConfigInspectError("$.observability: invalid")),
    ):
        result = CliRunner().invoke(cmd_config.config_cmd, ["validate"])

    assert result.exit_code == 1
    assert "$.observability: invalid" in result.output


def test_top_level_validate_reaches_canonical_diagnostics_for_malformed_v8(tmp_path: Path) -> None:
    from defenseclaw.main import cli

    config_path = tmp_path / "config.yaml"
    config_path.write_text("config_version: 8\nobservability: [\n", encoding="utf-8")
    with (
        patch.object(cmd_config.config_module, "config_path", return_value=config_path),
        patch.object(
            cmd_config.config_module,
            "require_v8_config",
            side_effect=AssertionError("root v8 preflight must not intercept config validation"),
        ) as root_preflight,
        patch.object(
            cmd_config,
            "inspect_v8_config",
            side_effect=ConfigInspectError("$.observability: malformed YAML source"),
        ) as inspect,
    ):
        result = CliRunner().invoke(cli, ["config", "validate"])

    assert result.exit_code == 1
    assert "$.observability: malformed YAML source" in result.output
    assert "run 'defenseclaw upgrade' first" not in result.output
    root_preflight.assert_not_called()
    inspect.assert_called_once_with("validate", config_path=str(config_path))


def test_v8_source_view_uses_masked_source_not_go_effective(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    hidden = "DO-NOT-ECHO-SECRET"
    config_path.write_text(
        f"config_version: 8\nllm: {{api_key: {hidden}}}\nobservability: {{defaults: {{redaction_profile: none}}}}\n",
        encoding="utf-8",
    )
    with (
        patch.object(cmd_config.config_module, "config_path", return_value=config_path),
        patch.object(cmd_config, "inspect_v8_config") as inspect,
    ):
        result = CliRunner().invoke(
            cmd_config.config_cmd,
            ["show", "--source", "--section", "observability", "--format", "json"],
        )

    assert result.exit_code == 0, result.output
    assert hidden not in result.output
    assert json.loads(result.output) == {"observability": {"defaults": {"redaction_profile": "none"}}}
    inspect.assert_not_called()


def test_v8_effective_view_is_go_owned_and_reveal_is_rejected(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    config_path.write_text("config_version: 8\nobservability: {}\n", encoding="utf-8")
    effective = {
        "buckets": [{"bucket": "model.io", "collect": {"logs": True, "traces": True, "metrics": True}}],
        "destinations": [],
    }
    with (
        patch.object(cmd_config.config_module, "config_path", return_value=config_path),
        patch.object(cmd_config, "inspect_v8_config", return_value=_wire("effective", effective=effective)),
    ):
        result = CliRunner().invoke(
            cmd_config.config_cmd,
            ["show", "--effective", "--section", "observability", "--format", "json"],
        )
        reveal = CliRunner().invoke(cmd_config.config_cmd, ["show", "--effective", "--reveal"])

    assert result.exit_code == 0, result.output
    assert json.loads(result.output) == {"observability": effective}
    assert reveal.exit_code == 2
    assert "--reveal is not supported" in reveal.output


def test_v8_provenance_view_exposes_only_canonical_go_annotations(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    config_path.write_text("config_version: 8\nobservability: {}\n", encoding="utf-8")
    annotations = [
        {
            "path": "observability.buckets.model.io.collect",
            "value_path": "observability.buckets[4].collect.logs",
            "origin": "catalog-default",
        },
        {
            "path": "observability.local.retention_days",
            "origin": "source",
            "source": str(config_path),
            "line": 2,
            "column": 16,
        },
    ]
    effective = {
        "buckets": [
            {
                "bucket": "model.io",
                "collect": {"logs": True, "traces": True, "metrics": True},
            }
        ],
        "destinations": [],
        "provenance": annotations,
    }
    with (
        patch.object(cmd_config.config_module, "config_path", return_value=config_path),
        patch.object(cmd_config, "inspect_v8_config", return_value=_wire("effective", effective=effective)) as inspect,
    ):
        result = CliRunner().invoke(
            cmd_config.config_cmd,
            ["show", "--provenance", "--section", "observability", "--format", "json"],
        )

    assert result.exit_code == 0, result.output
    assert json.loads(result.output) == {
        "observability": {
            "buckets": effective["buckets"],
            "destinations": [],
        },
        "_provenance": {
            "basis": "canonical_go_effective_plan",
            "annotations": annotations,
        },
    }
    inspect.assert_called_once_with("effective", config_path=str(config_path))


def test_v8_provenance_rejects_source_view(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    config_path.write_text("config_version: 8\nobservability: {}\n", encoding="utf-8")
    with patch.object(cmd_config.config_module, "config_path", return_value=config_path):
        result = CliRunner().invoke(cmd_config.config_cmd, ["show", "--source", "--provenance"])

    assert result.exit_code == 2
    assert "cannot be combined with --source" in result.output


def test_reference_uses_go_artifact_and_writes_atomically(tmp_path: Path) -> None:
    output = tmp_path / "reference.yaml"
    with patch.object(cmd_config, "config_v8_reference", return_value="# generated\nobservability: {}\n") as reference:
        result = CliRunner().invoke(
            cmd_config.config_cmd,
            ["reference", "observability", "--format", "yaml", "--output", str(output)],
        )

    assert result.exit_code == 0, result.output
    assert result.output == ""
    assert output.read_text(encoding="utf-8") == "# generated\nobservability: {}\n"
    reference.assert_called_once_with("yaml", section="observability")


def test_reference_json_schema_uses_embedded_go_schema() -> None:
    schema = '{"$schema":"https://json-schema.org/draft/2020-12/schema"}\n'
    with patch.object(cmd_config, "config_v8_schema", return_value=schema):
        result = CliRunner().invoke(
            cmd_config.config_cmd,
            ["reference", "observability", "--format", "json-schema"],
        )
    assert result.exit_code == 0
    assert result.output == schema


def test_config_path_projects_v8_paths_without_legacy_load(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    data_dir = tmp_path / "data"
    audit_path = data_dir / "events.db"
    config_path.write_text(
        "config_version: 8\n"
        f"data_dir: {data_dir}\n"
        f"policy_dir: {data_dir / 'policy-custom'}\n"
        "observability:\n"
        f"  local: {{path: {audit_path}}}\n",
        encoding="utf-8",
    )
    with (
        patch.object(cmd_config.config_module, "config_path", return_value=config_path),
        patch.object(cmd_config.config_module, "load") as legacy_load,
    ):
        result = CliRunner().invoke(cmd_config.config_cmd, ["path"])

    assert result.exit_code == 0, result.output
    assert str(data_dir) in result.output
    assert str(audit_path) in result.output
    assert str(data_dir / "policy-custom") in result.output
    legacy_load.assert_not_called()


def test_future_config_mutation_refuses_v7_source(tmp_path: Path) -> None:
    from defenseclaw.main import cli

    config_path = tmp_path / "config.yaml"
    config_path.write_text("guardrail:\n  mode: observe\n", encoding="utf-8")

    @click.command("mutation-probe")
    def mutation_probe() -> None:
        raise AssertionError("v7 mutation must be rejected before its handler runs")

    cmd_config.config_cmd.add_command(mutation_probe)
    try:
        with (
            patch.object(cmd_config.config_module, "config_path", return_value=config_path),
            patch.object(
                cmd_config.config_module,
                "require_v8_config",
                side_effect=AssertionError("config mutations are guarded by the config group"),
            ) as root_preflight,
        ):
            result = CliRunner().invoke(cli, ["config", "mutation-probe"])
    finally:
        cmd_config.config_cmd.commands.pop("mutation-probe", None)

    assert result.exit_code == 1
    assert "run 'defenseclaw upgrade' first" in result.output
    root_preflight.assert_not_called()
