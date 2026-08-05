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

import pytest
from defenseclaw.observability.v8_config import BUCKETS
from defenseclaw.observability.v8_redaction_policy import (
    apply_mutations_to_source,
    apply_profile_everywhere_mutations,
    bucket_mutations,
    defaults_mutations,
    destination_inherit_mutations,
    destination_send_mutations,
    profile_reference_paths,
    profile_remove_mutations,
    profile_set_mutations,
    redaction_profile_names,
    route_move_mutations,
    route_remove_mutations,
    route_upsert_mutations,
)


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


def test_generated_destinations_are_read_only() -> None:
    source = _apply(_source(), ())[1]
    with pytest.raises(ValueError, match="generated destination.*read-only"):
        destination_inherit_mutations(source, "managed-enterprise-ai-defense")
    with pytest.raises(ValueError, match="migration-only"):
        apply_profile_everywhere_mutations(source, "legacy-v7")
