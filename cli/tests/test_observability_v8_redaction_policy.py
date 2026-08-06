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

from collections.abc import Mapping
from pathlib import Path
from types import SimpleNamespace

import defenseclaw.observability.v8_redaction_policy as policy_module
import pytest
from defenseclaw.observability.v8_config import BUCKETS
from defenseclaw.observability.v8_redaction_policy import (
    apply_mutations_to_source,
    apply_profile_everywhere_mutations,
    bucket_mutations,
    defaults_mutations,
    destination_inherit_mutations,
    destination_send_mutations,
    preview_redaction_mutations,
    profile_reference_paths,
    profile_remove_mutations,
    profile_set_mutations,
    redaction_profile_names,
    route_move_mutations,
    route_remove_mutations,
    route_upsert_mutations,
)
from defenseclaw.observability.v8_yaml import V8YAMLMutation


def _source() -> bytes:
    return b"""# keep this operator note
config_version: 8
observability:
  defaults:
    collect: {logs: true, traces: false, metrics: true}
    redaction_profile: strict
  buckets:
    model.io:
      collect: {logs: false}
      redaction_profile: content
  destinations:
    - name: terminal
      kind: console
      send:
        signals: [logs]
        buckets: ['*']
        redaction_profile: sensitive
    - name: archive
      kind: jsonl
      path: /tmp/defenseclaw-archive.jsonl
      routes:
        - name: model
          signals: [logs]
          selector: {buckets: [model.io]}
          action: send
          redaction_profile: strict
"""


def _apply(source: bytes, mutations) -> tuple[bytes, dict]:
    return apply_mutations_to_source(source, mutations, source_name="config.yaml")


def _destination(source: Mapping, name: str) -> Mapping:
    destinations = source["observability"]["destinations"]
    return next(item for item in destinations if item["name"] == name)


def test_apply_profile_everywhere_clears_every_more_specific_profile() -> None:
    original = _source()
    _, parsed = _apply(
        original,
        apply_profile_everywhere_mutations(_apply(original, ())[1], "none"),
    )

    observability = parsed["observability"]
    assert observability["defaults"]["redaction_profile"] == "none"
    assert "redaction_profile" not in observability["buckets"]["model.io"]
    assert "redaction_profile" not in _destination(parsed, "terminal")["send"]
    assert "redaction_profile" not in _destination(parsed, "archive")["routes"][0]
    assert observability["defaults"]["collect"] == {
        "logs": True,
        "traces": False,
        "metrics": True,
    }
    assert _destination(parsed, "archive")["routes"][0]["selector"] == {"buckets": ["model.io"]}


def test_defaults_and_bucket_mutations_are_field_scoped() -> None:
    original = _source()
    source = _apply(original, ())[1]
    mutations = (
        *defaults_mutations(source, collect={"logs": False}),
        *bucket_mutations(source, "model.io", profile="sensitive"),
    )
    candidate, parsed = _apply(original, mutations)

    defaults = parsed["observability"]["defaults"]
    assert defaults["collect"] == {"logs": False, "traces": False, "metrics": True}
    assert defaults["redaction_profile"] == "strict"
    assert parsed["observability"]["buckets"]["model.io"] == {
        "collect": {"logs": False},
        "redaction_profile": "sensitive",
    }
    assert b"# keep this operator note" in candidate
    assert set(BUCKETS) == {
        "compliance.activity",
        "security.finding",
        "guardrail.evaluation",
        "enforcement.action",
        "model.io",
        "tool.activity",
        "asset.scan",
        "asset.lifecycle",
        "network.egress",
        "agent.lifecycle",
        "ai.discovery",
        "telemetry.ingest",
        "platform.health",
        "diagnostic",
    }


def test_defaults_and_bucket_mutations_reject_conflicting_profile_operations() -> None:
    source = _apply(_source(), ())[1]

    with pytest.raises(ValueError, match="reset_profile cannot be combined"):
        defaults_mutations(source, profile="strict", reset_profile=True)
    with pytest.raises(ValueError, match="inherit_profile cannot be combined"):
        bucket_mutations(source, "model.io", profile="strict", inherit_profile=True)


def test_preview_counts_effective_content_legs_from_compiler_snapshots(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "config.yaml"
    path.write_bytes(_source())
    before = {
        "destinations": [
            {
                "name": "terminal",
                "generated": False,
                "routes": [
                    {
                        "name": "all",
                        "action": "send",
                        "signals": ["logs", "traces", "metrics"],
                        "redaction_profile_by_bucket": {
                            "model.io": "sensitive",
                            "security.finding": "none",
                        },
                    }
                ],
            }
        ]
    }
    after = {
        "destinations": [
            {
                "name": "terminal",
                "generated": False,
                "routes": [
                    {
                        "name": "all",
                        "action": "send",
                        "signals": ["logs", "traces", "metrics"],
                        "redaction_profile_by_bucket": {
                            "model.io": "none",
                            "security.finding": "strict",
                        },
                    }
                ],
            },
            {
                "name": "managed-enterprise-ai-defense",
                "generated": True,
                "routes": [
                    {
                        "name": "managed",
                        "action": "send",
                        "signals": ["logs"],
                        "redaction_profile_by_bucket": {"model.io": "strict"},
                    }
                ],
            },
        ],
        "warnings": [
            {
                "code": "managed_destination_locked",
                "path": "$.observability.destinations[managed-enterprise-ai-defense]",
                "summary": "managed destination policy is locked",
            }
        ],
    }
    snapshots = iter(
        (
            SimpleNamespace(effective=before, plan_digest="before"),
            SimpleNamespace(effective=after, plan_digest="after"),
        )
    )
    monkeypatch.setattr(policy_module, "_inspect_snapshot", lambda *_args: next(snapshots))

    preview = preview_redaction_mutations(
        path,
        [V8YAMLMutation.set(("observability", "defaults", "redaction_profile"), "none")],
        data_dir=str(tmp_path),
    )

    assert preview.newly_unredacted == 2
    assert preview.no_longer_unredacted == 2
    assert len(preview.changes) == 5
    assert len(preview.after_legs) == 5
    assert preview.warnings == (
        (
            "managed_destination_locked",
            "$.observability.destinations[managed-enterprise-ai-defense]",
            "managed destination policy is locked",
        ),
    )
    assert preview.locked_profiles == (("managed-enterprise-ai-defense", ("strict",)),)


def test_custom_profile_can_be_created_and_references_replaced_atomically() -> None:
    original = _source()
    source = _apply(original, ())[1]
    created, with_profile = _apply(
        original,
        profile_set_mutations(
            source,
            "soc",
            extends="sensitive",
            detectors=("pii", "credentials", "secrets"),
            field_classes={"content": "detect", "credential": "remove"},
        ),
    )
    assigned, with_reference = _apply(
        created,
        defaults_mutations(with_profile, profile="soc"),
    )

    assert "soc" in redaction_profile_names(with_reference)
    assert profile_reference_paths(with_reference, "soc") == (("observability", "defaults", "redaction_profile"),)
    _, removed = _apply(
        assigned,
        profile_remove_mutations(with_reference, "soc", replace_with="content"),
    )
    assert removed["observability"]["defaults"]["redaction_profile"] == "content"
    assert "soc" not in removed["observability"].get("redaction_profiles", {})


def test_referenced_custom_profile_requires_replacement() -> None:
    original = _source()
    source = _apply(original, ())[1]
    created, with_profile = _apply(
        original,
        profile_set_mutations(
            source,
            "soc",
            extends="sensitive",
            detectors=("pii",),
            field_classes={},
        ),
    )
    _, with_reference = _apply(created, defaults_mutations(with_profile, profile="soc"))

    with pytest.raises(ValueError, match="still referenced"):
        profile_remove_mutations(with_reference, "soc")


def test_custom_profile_rejects_invalid_existing_field_classes_shape() -> None:
    source = _apply(_source(), ())[1]
    source["observability"]["redaction_profiles"] = {"soc": {"extends": "sensitive", "field_classes": []}}

    with pytest.raises(ValueError, match="invalid field_classes shape"):
        profile_set_mutations(source, "soc", extends=None, detectors=None, field_classes={})


def test_destination_concise_policy_and_inheritance_are_mutually_replacing() -> None:
    original = _source()
    source = _apply(original, ())[1]
    candidate, concise = _apply(
        original,
        destination_send_mutations(
            source,
            "archive",
            signals=("logs",),
            buckets=("security.finding",),
            profile="sensitive",
        ),
    )
    archive = _destination(concise, "archive")
    assert "routes" not in archive
    assert archive["send"] == {
        "signals": ["logs"],
        "buckets": ["security.finding"],
        "redaction_profile": "sensitive",
    }

    _, inherited = _apply(candidate, destination_inherit_mutations(concise, "archive"))
    archive = _destination(inherited, "archive")
    assert "send" not in archive
    assert "routes" not in archive


def test_routes_support_strict_add_edit_move_and_remove_semantics() -> None:
    original = _source()
    source = _apply(original, ())[1]
    finding_route = {
        "name": "finding",
        "signals": ["logs"],
        "selector": {"buckets": ["security.finding"], "min_severity": "HIGH"},
        "action": "send",
        "redaction_profile": "sensitive",
    }
    added_bytes, added = _apply(
        original,
        route_upsert_mutations(
            source,
            "archive",
            finding_route,
            position=0,
            must_exist=False,
        ),
    )
    assert [route["name"] for route in _destination(added, "archive")["routes"]] == [
        "finding",
        "model",
    ]
    with pytest.raises(ValueError, match="already exists"):
        route_upsert_mutations(added, "archive", finding_route, must_exist=False)
    with pytest.raises(ValueError, match="route move operation"):
        route_upsert_mutations(added, "archive", finding_route, position=0, must_exist=True)
    duplicated = _apply(added_bytes, ())[1]
    _destination(duplicated, "archive")["routes"].append(dict(finding_route))
    with pytest.raises(ValueError, match=r"route 'finding' is duplicated"):
        route_remove_mutations(duplicated, "archive", "finding")

    moved_bytes, moved = _apply(
        added_bytes,
        route_move_mutations(added, "archive", "finding", position=1),
    )
    assert [route["name"] for route in _destination(moved, "archive")["routes"]] == [
        "model",
        "finding",
    ]
    edited = {**finding_route, "redaction_profile": "strict"}
    edited_bytes, edited_source = _apply(
        moved_bytes,
        route_upsert_mutations(moved, "archive", edited, must_exist=True),
    )
    assert _destination(edited_source, "archive")["routes"][1] == edited
    _, removed = _apply(
        edited_bytes,
        route_remove_mutations(edited_source, "archive", "finding"),
    )
    assert [route["name"] for route in _destination(removed, "archive")["routes"]] == ["model"]


def test_route_bucket_selector_accepts_explicit_wildcard() -> None:
    original = _source()
    source = _apply(original, ())[1]
    wildcard_route = {
        "name": "all-buckets",
        "signals": ["logs"],
        "selector": {"buckets": ["*"]},
        "action": "send",
        "redaction_profile": "sensitive",
    }

    _, parsed = _apply(
        original,
        route_upsert_mutations(source, "archive", wildcard_route, must_exist=False),
    )

    assert _destination(parsed, "archive")["routes"][-1]["selector"] == {"buckets": ["*"]}


def test_generated_destinations_are_read_only() -> None:
    source = _apply(_source(), ())[1]
    with pytest.raises(ValueError, match=r"generated destination.*read-only"):
        destination_inherit_mutations(source, "managed-enterprise-ai-defense")
    with pytest.raises(ValueError, match="migration-only"):
        apply_profile_everywhere_mutations(source, "legacy-v7")


def test_duplicate_source_destinations_are_reported_distinctly() -> None:
    source = _apply(_source(), ())[1]
    source["observability"]["destinations"].append(dict(_destination(source, "archive")))

    with pytest.raises(ValueError, match=r"destination 'archive' is duplicated"):
        destination_inherit_mutations(source, "archive")
