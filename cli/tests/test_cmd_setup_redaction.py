# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from click.testing import CliRunner
from defenseclaw.commands import cmd_setup_redaction
from defenseclaw.commands.cmd_setup_redaction import redaction
from defenseclaw.context import AppContext
from defenseclaw.observability.v8_redaction_policy import RedactionPreview
from defenseclaw.observability.v8_status import (
    V8BucketStatus,
    V8DestinationStatus,
    V8OperatorStatus,
)
from defenseclaw.observability.v8_writer import V8PolicyWriteResult
from defenseclaw.observability.v8_yaml import DELETE


def _source() -> str:
    return """config_version: 8
observability:
  defaults:
    redaction_profile: sensitive
  buckets:
    model.io:
      redaction_profile: strict
  destinations:
    - name: terminal
      kind: console
      send:
        signals: [logs]
        buckets: ['*']
        redaction_profile: content
"""


def _app(tmp_path: Path) -> AppContext:
    (tmp_path / "config.yaml").write_text(_source())
    app = AppContext()
    app.cfg = SimpleNamespace(data_dir=str(tmp_path))
    return app


def _status(tmp_path: Path) -> V8OperatorStatus:
    return V8OperatorStatus(
        source=str(tmp_path / "config.yaml"),
        data_dir=str(tmp_path),
        plan_digest="a" * 64,
        bucket_catalog_version=1,
        retention_days=90,
        local_path=str(tmp_path / "audit.db"),
        judge_bodies_path=str(tmp_path / "judge_bodies.db"),
        destinations=(
            V8DestinationStatus(
                name="local-sqlite",
                kind="sqlite",
                enabled=True,
                generated=True,
                capabilities=("logs",),
                selected_signals=("logs",),
                policy_form="implicit_local",
                endpoint=str(tmp_path / "audit.db"),
                route_count=1,
                buckets=("model.io",),
                redaction_profiles=("sensitive",),
            ),
            V8DestinationStatus(
                name="terminal",
                kind="console",
                enabled=True,
                generated=False,
                capabilities=("logs",),
                selected_signals=("logs",),
                policy_form="concise_send",
                endpoint="stdout",
                route_count=1,
                buckets=("model.io",),
                redaction_profiles=("content",),
            ),
        ),
        buckets=(
            V8BucketStatus(
                name="model.io",
                collected_signals=("logs", "traces", "metrics"),
                redaction_profile="strict",
            ),
        ),
        warnings=(),
    )


def test_redaction_help_exposes_interactive_and_scripted_policy_surface() -> None:
    result = CliRunner().invoke(redaction, ["--help"])

    assert result.exit_code == 0, result.output
    for command in (
        "status",
        "remove-all",
        "apply",
        "defaults",
        "bucket",
        "profile",
        "destination",
        "route",
    ):
        assert command in result.output


def test_defaults_set_omitted_collection_flags_are_not_deleted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    captured = []
    monkeypatch.setattr(
        cmd_setup_redaction,
        "_execute_mutations",
        lambda _app, mutations, **_kwargs: captured.extend(mutations),
    )

    result = CliRunner().invoke(
        redaction,
        ["defaults", "set", "--no-logs", "--yes"],
        obj=_app(tmp_path),
        catch_exceptions=False,
    )

    assert result.exit_code == 0, result.output
    assert [(mutation.path, mutation.value) for mutation in captured] == [
        (("observability", "defaults", "collect", "logs"), False)
    ]


def test_bucket_set_accepts_false_as_an_explicit_only_change(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    captured = []
    monkeypatch.setattr(
        cmd_setup_redaction,
        "_execute_mutations",
        lambda _app, mutations, **_kwargs: captured.extend(mutations),
    )

    result = CliRunner().invoke(
        redaction,
        ["bucket", "set", "security.finding", "--no-traces", "--yes"],
        obj=_app(tmp_path),
        catch_exceptions=False,
    )

    assert result.exit_code == 0, result.output
    assert [(mutation.path, mutation.value) for mutation in captured] == [
        (("observability", "buckets", "security.finding", "collect", "traces"), False)
    ]


def test_remove_all_stages_global_none_and_removes_specific_profiles(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured = []
    monkeypatch.setattr(
        cmd_setup_redaction,
        "_execute_mutations",
        lambda _app, mutations, **_kwargs: captured.extend(mutations),
    )

    result = CliRunner().invoke(
        redaction,
        ["remove-all", "--dry-run"],
        obj=_app(tmp_path),
        catch_exceptions=False,
    )

    assert result.exit_code == 0, result.output
    values = {mutation.path: mutation.value for mutation in captured}
    assert values[("observability", "defaults", "redaction_profile")] == "none"
    assert values[("observability", "buckets", "model.io", "redaction_profile")] is DELETE
    assert values[("observability", "destinations", 0, "send", "redaction_profile")] is DELETE


def test_bare_redaction_walks_through_simple_then_advanced_choice(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured = []
    monkeypatch.setattr(cmd_setup_redaction, "_operator_status", lambda _app: _status(tmp_path))
    monkeypatch.setattr(
        cmd_setup_redaction,
        "_execute_mutations",
        lambda _app, mutations, **kwargs: captured.append((tuple(mutations), kwargs)),
    )

    result = CliRunner().invoke(
        redaction,
        [],
        obj=_app(tmp_path),
        input="2\nn\nn\n",
        catch_exceptions=False,
    )

    assert result.exit_code == 0, result.output
    assert "Remove all redaction from configurable projections" in result.output
    assert "Show advanced settings?" in result.output
    assert len(captured) == 1
    mutations, options = captured[0]
    assert mutations[0].path == ("observability", "defaults", "redaction_profile")
    assert mutations[0].value == "none"
    assert options["action"] == "interactive-policy"


def test_status_json_is_machine_readable_and_labels_effective_policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(cmd_setup_redaction, "_operator_status", lambda _app: _status(tmp_path))

    result = CliRunner().invoke(
        redaction,
        ["status", "--json"],
        obj=_app(tmp_path),
        catch_exceptions=False,
    )

    payload = json.loads(result.output)
    assert payload["plan_digest"] == "a" * 64
    assert payload["destinations"][0]["redaction"] == "redacted: sensitive"
    assert payload["buckets"] == [
        {
            "name": "model.io",
            "redaction_profile": "strict",
            "signals": ["logs", "traces", "metrics"],
        }
    ]


def test_profile_show_reads_compiler_owned_redaction_profile_catalog(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        cmd_setup_redaction,
        "_effective",
        lambda _app: {
            "redaction_profiles": [
                {
                    "name": "sensitive",
                    "built_in": True,
                    "detectors": ["pii", "credentials", "secrets"],
                    "field_classes": {"content": "detect", "credential": "remove"},
                }
            ]
        },
    )

    result = CliRunner().invoke(
        redaction,
        ["profile", "show", "sensitive", "--json"],
        obj=_app(tmp_path),
        catch_exceptions=False,
    )

    payload = json.loads(result.output)
    assert payload["name"] == "sensitive"
    assert payload["field_classes"]["content"] == "detect"


def test_execute_mutations_binds_write_to_preview_and_verifies_plan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    preview = RedactionPreview(
        before_sha256="b" * 64,
        after_sha256="c" * 64,
        before_plan_digest="d" * 64,
        after_plan_digest="e" * 64,
        changed=True,
        changes=(),
        newly_unredacted=14,
        no_longer_unredacted=0,
        after_legs=(),
        warnings=(),
        locked_profiles=(("managed-enterprise-ai-defense", ("sensitive",)),),
        mutation_paths=("$.observability.defaults.redaction_profile",),
    )
    calls = []
    monkeypatch.setattr(
        cmd_setup_redaction,
        "preview_redaction_mutations",
        lambda *_args, **_kwargs: preview,
    )

    def mutate(path, mutations, **kwargs):
        calls.append((path, tuple(mutations), kwargs))
        return V8PolicyWriteResult(True, preview.before_sha256, preview.after_sha256, str(kwargs["backup_path"]))

    monkeypatch.setattr(cmd_setup_redaction, "mutate_v8_config", mutate)
    monkeypatch.setattr(
        cmd_setup_redaction,
        "inspect_v8_config",
        lambda *_args, **_kwargs: SimpleNamespace(plan_digest=preview.after_plan_digest),
    )

    result = CliRunner().invoke(
        redaction,
        ["remove-all", "--yes"],
        obj=_app(tmp_path),
        catch_exceptions=False,
    )

    assert result.exit_code == 0, result.output
    assert "newly unredacted: 14" in result.output.lower()
    assert "Managed policy remains locked" in result.output
    assert calls[0][2]["expected_before_sha256"] == preview.before_sha256
    assert calls[0][2]["backup_path"] == (tmp_path / "backups" / "config.yaml.before-redaction")


def test_json_mutation_requires_noninteractive_confirmation(tmp_path: Path) -> None:
    result = CliRunner().invoke(
        redaction,
        ["remove-all", "--json"],
        obj=_app(tmp_path),
    )

    assert result.exit_code == 2
    assert "--json mutations require --yes or --dry-run" in result.output
