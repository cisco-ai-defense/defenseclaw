# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import base64
import dataclasses
import hashlib
import importlib.util
import json
import re
import subprocess
import sys
from collections import Counter
from collections.abc import Mapping
from pathlib import Path, PurePosixPath
from types import ModuleType
from typing import Any

import jsonschema
import pytest

ROOT = Path(__file__).resolve().parents[2]
GENERATOR = ROOT / "scripts/generate_telemetry_registry.py"
RENDERER = ROOT / "scripts/render_telemetry_registry_candidates.py"
PREFIX = "schemas/telemetry/generated"


def _load(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def generator() -> ModuleType:
    return _load("telemetry_candidate_test_generator", GENERATOR)


@pytest.fixture(scope="module")
def renderer() -> ModuleType:
    return _load("telemetry_candidate_test_renderer", RENDERER)


@pytest.fixture(scope="module")
def view(generator: ModuleType) -> Any:
    return generator.compile_registry(ROOT).materialized_view


@pytest.fixture(scope="module")
def render_index(renderer: ModuleType, view: Any) -> Any:
    return renderer.build_candidate_render_index(view)


@pytest.fixture(scope="module")
def artifacts(renderer: ModuleType, render_index: Any) -> Mapping[str, Any]:
    return renderer.render_candidate_artifacts_from_index(render_index)




def _json(artifacts: Mapping[str, Any], relative: str) -> dict[str, Any]:
    return json.loads(artifacts[f"{PREFIX}/{relative}"].payload)


def _subschema_validator(schema: Mapping[str, Any], subschema: Mapping[str, Any]) -> jsonschema.Draft202012Validator:
    definitions = dict(schema["$defs"])
    definitions["test:subject"] = subschema
    return jsonschema.Draft202012Validator(
        {
            "$schema": schema["$schema"],
            "$ref": "#/$defs/test:subject",
            "$defs": definitions,
        }
    )


def _span_record_for_family(
    artifacts: Mapping[str, Any],
    schema: Mapping[str, Any],
    family_id: str,
) -> dict[str, Any]:
    record = json.loads(
        json.dumps(
            _json(
                artifacts,
                "examples/valid/valid-model-chat-with-honest-missing-content-and-usage.json",
            )["record"]
        )
    )
    definition = schema["$defs"][f"family:{family_id}"]
    metadata = definition["x-defenseclaw-family"]
    body_overlay = definition["allOf"][1]["properties"]["body"]["allOf"][1]
    attributes_schema = body_overlay["properties"]["attributes"]
    allowed_attributes = attributes_schema["properties"]
    record["body"]["attributes"] = {
        key: value for key, value in record["body"]["attributes"].items() if key in allowed_attributes
    }
    for key, attribute_schema in allowed_attributes.items():
        if "const" in attribute_schema:
            record["body"]["attributes"][key] = attribute_schema["const"]
    if family_id == "span.ai.discovery.detector":
        record["body"]["attributes"]["defenseclaw.ai.discovery.detector"] = "process"
    record["body"]["kind"] = body_overlay["properties"]["kind"]["enum"][0]
    record["body"].pop("events", None)
    record["bucket"] = metadata["bucket"]
    record["event_name"] = metadata["event_name"]
    record["span_name"] = metadata["span_name_pattern"]
    record["outcome"] = "completed"
    return record


def _retagged_view(renderer: ModuleType, view: Any, facts: Mapping[str, Any]) -> Any:
    typed = renderer._typed_materialized_node(facts)
    digest = hashlib.sha256(
        renderer.MATERIALIZED_VIEW_DIGEST_DOMAIN + renderer._canonical_json_bytes(typed)
    ).hexdigest()
    return dataclasses.replace(view, facts=facts, typed_canonical_json_sha256=digest)


def _copy_materialized(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _copy_materialized(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return tuple(_copy_materialized(item) for item in value)
    return value






@pytest.mark.parametrize("mode", ["direct", "package"])
def test_renderer_import_does_not_mask_a_missing_go_plan_transitive_dependency(
    mode: str,
) -> None:
    canonical = ROOT / "scripts/telemetry_canonical_record.py"
    api_plan = ROOT / "scripts/telemetry_go_api_plan.py"
    if mode == "direct":
        preload = """
import scripts.telemetry_canonical_record
import scripts.telemetry_go_api_plan
"""
        load = f"""
spec = importlib.util.spec_from_file_location("transitive_direct_renderer", {str(RENDERER)!r})
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
try:
    spec.loader.exec_module(module)
finally:
    sys.modules.pop(spec.name, None)
"""
        expected_importer = "telemetry_go_api_plan"
    else:
        preload = f"""
for name, path in (
    ("telemetry_canonical_record", {str(canonical)!r}),
    ("telemetry_go_api_plan", {str(api_plan)!r}),
):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
"""
        load = 'importlib.import_module("scripts.render_telemetry_registry_candidates")'
        expected_importer = "scripts.telemetry_go_api_plan"
    code = f"""
import builtins
import importlib
import importlib.util
import sys
{preload}
# Exercise the opposite import order first, then clear both supported graphs so
# the injected failure tests the selected graph rather than mixed-mode policy.
for prefix in ("", "scripts."):
    for leaf in (
        "telemetry_canonical_record",
        "telemetry_go_api_plan",
        "render_telemetry_registry_candidates",
    ):
        sys.modules.pop(prefix + leaf, None)
real_import = builtins.__import__
def fail_nested_dependency(name, *args, **kwargs):
    importer_globals = args[0] if args and isinstance(args[0], dict) else {{}}
    if (
        importer_globals.get("__name__") == {expected_importer!r}
        and name.endswith("telemetry_canonical_record")
    ):
        failure = ModuleNotFoundError("No module named 'go_plan_transitive_dependency'")
        failure.name = "go_plan_transitive_dependency"
        raise failure
    return real_import(name, *args, **kwargs)
builtins.__import__ = fail_nested_dependency
try:
{"".join("    " + line + chr(10) for line in load.splitlines())}
except ModuleNotFoundError as exc:
    assert exc.name == "go_plan_transitive_dependency"
    assert "go_plan_transitive_dependency" in str(exc)
else:
    raise AssertionError("renderer masked the injected transitive dependency failure")
finally:
    builtins.__import__ = real_import
assert "transitive_direct_renderer" not in sys.modules
"""
    completed = subprocess.run(
        [sys.executable, "-c", code],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    assert completed.returncode == 0, completed.stderr


def _go_symbol_table_fields(facts: Mapping[str, Any]) -> dict[str, Any]:
    return facts["fields"]["go_symbol_table"]["fields"]


def _redigest_go_symbol_table(renderer: ModuleType, table: dict[str, Any]) -> str:
    payload = json.dumps(
        [
            [
                row["fields"]["kind"],
                row["fields"]["source_id"],
                row["fields"]["symbol"],
                row["fields"]["declaration_form"],
            ]
            for row in table["rows"]
        ],
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    digest = hashlib.sha256(renderer._GO_SYMBOL_TABLE_DIGEST_DOMAIN + payload).hexdigest()
    table["table_sha256"] = digest
    return digest


def _set_unreferenced_invalid_example_id(facts: dict[str, Any], example_id: str) -> None:
    examples = facts["fields"]["examples"]
    referenced = {item["fields"]["base_example"] for item in examples if item["fields"]["base_example"] is not None}
    target = next(
        item for item in examples if item["fields"]["valid"] is False and item["fields"]["id"] not in referenced
    )
    target["fields"]["id"] = example_id




def test_go_api_plan_is_compiled_once_reused_by_identity_and_fully_digest_bound(
    renderer: ModuleType,
    view: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_compile = renderer.compile_go_api_plan
    observed: list[tuple[Any, Any]] = []

    def compile_once(provisional: Any) -> Any:
        plan = original_compile(provisional)
        observed.append((provisional, plan))
        return plan

    monkeypatch.setattr(renderer, "compile_go_api_plan", compile_once)
    baseline = renderer.build_candidate_render_index(view)

    assert len(observed) == 1
    provisional, compiled_plan = observed[0]
    assert baseline.go_api_plan is compiled_plan
    assert baseline.api_plan_sha256 == compiled_plan.api_plan_sha256
    with pytest.raises(dataclasses.FrozenInstanceError):
        provisional.materialized_view_sha256 = "0" * 64
    with pytest.raises(TypeError):
        provisional.enriched_fields["new"] = next(iter(provisional.enriched_fields.values()))  # type: ignore[index]

    forged_plan = dataclasses.replace(compiled_plan, version=compiled_plan.version + 1)
    assert forged_plan.api_plan_sha256 == compiled_plan.api_plan_sha256
    monkeypatch.setattr(renderer, "compile_go_api_plan", lambda _: forged_plan)
    forged = renderer.build_candidate_render_index(view)

    assert forged.go_api_plan is forged_plan
    assert forged.api_plan_sha256 == baseline.api_plan_sha256
    assert forged.candidate_render_index_sha256 != baseline.candidate_render_index_sha256
    with pytest.raises(dataclasses.FrozenInstanceError):
        forged.go_api_plan.version = 1
    with pytest.raises(dataclasses.FrozenInstanceError):
        forged.go_api_plan.inputs[0].fields[0].selector = "Changed"


def test_candidate_enrichment_is_complete_typed_and_recursively_immutable(
    renderer: ModuleType,
    view: Any,
) -> None:
    index = renderer.build_candidate_render_index(view)

    assert index.materialized_view_sha256 == index.digest == view.typed_canonical_json_sha256
    assert index.candidate_render_index_sha256 != index.materialized_view_sha256
    assert len(index.candidate_render_index_sha256) == 64
    assert index.enriched_fields
    assert set(Counter(item.context for item in index.enriched_fields.values())) == {
        "log", "span", "metric", "resource", "scope", "event", "link", "structured"
    }
    assert index.enriched_containers
    assert set(Counter(item.context for item in index.enriched_containers.values())) == {
        "structural_object", "structural_field", "structured_type", "structured_variant", "structured_reference"
    }
    assert index.enriched_containers["structural:provenance_import"].path == "/provenance/import"
    assert index.enriched_containers["structural-field:provenance:import"].reference_target == ("provenance_import")
    assert all(not hasattr(item, "field_class") for item in index.enriched_containers.values())
    assert all(not hasattr(item, "sensitivity") for item in index.enriched_containers.values())
    assert all(not hasattr(item, "normalization_id") for item in index.enriched_containers.values())
    assert {item.input_placement for item in index.enriched_fields.values()} == {
        "family_input",
        "resource_input",
        "event_input",
        "private_derived",
        "structured_input",
    }
    assert {item.target_slot for item in index.enriched_fields.values()} == {
        "body",
        "trace.attributes",
        "metric.attributes",
        "trace.resource.attributes",
        "trace.scope.attributes",
        "trace.event.attributes",
        "trace.link.attributes",
        "structured.value",
    }
    owner_orders: dict[tuple[str, str], list[int]] = {}
    for item in index.enriched_fields.values():
        owner_orders.setdefault((item.context, item.owner_id), []).append(item.order)
    assert all(sorted(orders) == list(range(len(orders))) for orders in owner_orders.values())

    assert set(index.enriched_families) == {family["id"] for family in index.families}
    assert set(index.enriched_traces) == {
        family["id"] for family in index.families if family["type"] == "span"
    }
    assert set(index.enriched_metrics) == {
        family["id"] for family in index.families if family["type"] == "metric"
    }
    assert set(index.mandatory_programs) == {
        family["id"] for family in index.families if family["type"] == "log"
    }
    assert all(
        (family.mandatory_program_id == family.id) == (family.signal == "logs")
        for family in index.enriched_families.values()
    )

    assert index.expanded_producer_mappings
    assert set(row.identity_origin for row in index.expanded_producer_mappings) == {
        "default", "allowed_context"
    }
    assert len({row.id for row in index.expanded_producer_mappings}) == len(index.expanded_producer_mappings)
    assert all(
        (row.selected_mandatory_program_id == row.family_id)
        if row.family_id is not None
        else row.selected_mandatory_program_id is None
        for row in index.expanded_producer_mappings
    )
    assert all(row.family_id is not None or row.compatibility_only for row in index.expanded_producer_mappings)

    const_rows = tuple(row for row in index.go_symbol_table.rows if row.declaration_form == "exported_const")
    assert tuple((item.kind, item.source_id, item.symbol) for item in index.go_declaration_values) == tuple(
        (row.kind, row.source_id, row.symbol) for row in const_rows
    )
    assert set(item.literal_kind for item in index.go_declaration_values) == {"string", "integer"}
    assert set(item.go_type for item in index.go_declaration_values) == {"string", "int"}
    assert (
        next(
            item for item in index.go_declaration_values if item.kind == "phase_code" and item.source_id == "session"
        ).value
        == 1
    )
    assert (
        next(
            item
            for item in index.go_declaration_values
            if item.kind == "structured_member" and item.source_id == "gen_ai.chat_message#role"
        ).value
        == "role"
    )

    derived = [item for item in index.enriched_fields.values() if item.value_source != "input"]
    assert len(derived) == 154
    assert index.enriched_fields["resource:resource.core:service.version"].value_source == ("provenance.binary_version")
    assert (
        index.enriched_fields["scope:scope.core:defenseclaw.trace.schema_version"].value_source
        == "semantic_profile.trace_schema_version"
    )
    assert index.enriched_fields["scope:scope.core:defenseclaw.semantic_profile"].value_source == (
        "semantic_profile.id"
    )
    assert index.enriched_fields["link:link.core:defenseclaw.link.relation"].value_source == "link.relation"
    assert index.enriched_fields["span:span.model.chat:defenseclaw.outcome"].value_source == "envelope.outcome"
    assert all(
        item.value_source == "input"
        for item in index.enriched_fields.values()
        if item.context == "metric" and item.attribute_id == "defenseclaw.outcome"
    )
    assert index.enriched_traces["span.model.chat"].span_name_parts == (
        {"field": None, "kind": "literal", "literal": "chat "},
        {"field": "gen_ai.request.model", "kind": "field", "literal": None},
    )
    span_name_fields = 0
    for family_id, trace in index.enriched_traces.items():
        family = index.enriched_families[family_id]
        for part in trace.span_name_parts:
            if part["kind"] != "field":
                continue
            span_name_fields += 1
            matches = tuple(
                index.enriched_fields[descriptor_id]
                for descriptor_id in family.field_descriptor_ids
                if index.enriched_fields[descriptor_id].attribute_id == part["field"]
            )
            assert len(matches) == 1
            assert matches[0].role == "attributes"
            assert matches[0].requirement_level == "required"
            assert matches[0].condition_id is None
            assert matches[0].condition_fact is None
            assert matches[0].field_types == ("string",)
            assert matches[0].structured_type is None
    assert span_name_fields == 19
    assert all(item.path.startswith("/") and item.origins for item in index.enriched_fields.values())
    assert {item.path_kind for item in index.enriched_fields.values()} == {
        "payload_template",
        "registry_relative",
    }
    structured_fields = [item for item in index.enriched_fields.values() if item.context == "structured"]
    assert len(structured_fields) == 47
    assert all(
        item.path_kind == "registry_relative"
        and item.input_placement == "structured_input"
        and item.canonical_owner is None
        and item.cardinality is None
        and item.stability is None
        for item in structured_fields
    )
    instantiated_member_leaves = [
        item
        for item in structured_fields
        if item.role in {"dynamic_member_name", "canonical_object_member_name", "canonical_scalar_arm"}
    ]
    assert len(instantiated_member_leaves) == 21
    assert all(item.requirement_level == "required" for item in instantiated_member_leaves)
    assert all(
        child in index.enriched_fields
        for container in index.enriched_containers.values()
        if container.context in {"structured_type", "structured_variant"}
        for child in container.child_fields
    )
    for item in index.enriched_fields.values():
        expected = dict(item.normalization_effective_constraints)
        expected.update(item.use_constraints)
        assert item.effective_constraints == expected
        if item.condition_id is None:
            assert item.condition_fact is None and item.condition_false_requirement is None
        else:
            assert item.condition_fact and item.condition_false_requirement in {"optional", "forbidden"}

    first_field = next(iter(index.enriched_fields.values()))
    first_container = next(iter(index.enriched_containers.values()))
    first_trace = next(iter(index.enriched_traces.values()))
    first_row = index.expanded_producer_mappings[0]
    with pytest.raises(TypeError):
        index.enriched_fields["new"] = first_field  # type: ignore[index]
    with pytest.raises(dataclasses.FrozenInstanceError):
        first_field.value_source = "changed"  # type: ignore[misc]
    with pytest.raises(TypeError):
        first_field.effective_constraints["max"] = 1  # type: ignore[index]
    with pytest.raises(TypeError):
        first_field.origins[0]["group_id"] = "changed"  # type: ignore[index]
    with pytest.raises(TypeError):
        first_container.bounds["max_items"] = 1  # type: ignore[index]
    with pytest.raises(TypeError):
        first_trace.event_field_descriptor_ids["new"] = ()  # type: ignore[index]
    with pytest.raises(TypeError):
        first_row.compatibility["disposition"] = "changed"  # type: ignore[index]
    with pytest.raises(dataclasses.FrozenInstanceError):
        index.go_declaration_values[0].value = "changed"  # type: ignore[misc]


@pytest.mark.parametrize("requirement", ["recommended", "optional", "conditional"])
def test_candidate_rejects_nonrequired_span_name_fields(
    renderer: ModuleType,
    view: Any,
    requirement: str,
) -> None:
    facts = _copy_materialized(view.facts)
    family = next(
        group["fields"]
        for domain in facts["fields"]["domains"]
        for group in domain["fields"]["groups"]
        if group["fields"]["id"] == "span.model.chat"
    )
    use = next(item["fields"] for item in family["resolved_uses"] if item["fields"]["ref"] == "gen_ai.request.model")
    use["requirement_level"] = requirement
    use["conditional"] = "technical-failure-v1" if requirement == "conditional" else None

    with pytest.raises(renderer.CandidateRenderError, match="materialized field span-name part is invalid"):
        renderer._validated_span_name_parts(family)


@pytest.mark.parametrize(
    ("role", "conditional"),
    (("body_fields", None), ("attributes", "technical-failure-v1")),
)
def test_candidate_rejects_nonattribute_or_conditional_span_name_fields(
    renderer: ModuleType,
    view: Any,
    role: str,
    conditional: str | None,
) -> None:
    facts = _copy_materialized(view.facts)
    family = next(
        group["fields"]
        for domain in facts["fields"]["domains"]
        for group in domain["fields"]["groups"]
        if group["fields"]["id"] == "span.model.chat"
    )
    use = next(item["fields"] for item in family["resolved_uses"] if item["fields"]["ref"] == "gen_ai.request.model")
    use["role"] = role
    use["conditional"] = conditional

    with pytest.raises(renderer.CandidateRenderError, match="materialized field span-name part is invalid"):
        renderer._validated_span_name_parts(family)


def test_enriched_occurrence_constraint_overlay_is_materialized_once_and_rejects_weakening(
    renderer: ModuleType,
) -> None:
    effective = renderer._effective_occurrence_constraints(
        {"enum": ("a", "b"), "min_items": 0, "max_items": 10, "max_utf8_bytes": 128},
        {"enum": ("a",), "min_items": 1, "max_items": 4},
    )

    assert effective == {
        "enum": ("a",),
        "min_items": 1,
        "max_items": 4,
        "max_utf8_bytes": 128,
    }
    with pytest.raises(TypeError):
        effective["max_items"] = 5  # type: ignore[index]
    with pytest.raises(renderer.CandidateRenderError, match="weakens normalization"):
        renderer._effective_occurrence_constraints({"max_items": 4}, {"max_items": 5})
    with pytest.raises(renderer.CandidateRenderError, match="weakens normalization"):
        renderer._effective_occurrence_constraints({"enum": ("a",)}, {"enum": ("a", "b")})


def test_candidate_render_index_digest_binds_materialized_view_even_when_enrichment_is_unchanged(
    renderer: ModuleType,
    view: Any,
) -> None:
    baseline = renderer.build_candidate_render_index(view)
    facts = _copy_materialized(view.facts)
    first_attribute = facts["fields"]["domains"][0]["fields"]["attributes"][0]["fields"]
    first_attribute["brief"] += " Digest-binding test."
    forged_view = _retagged_view(renderer, view, facts)
    changed = renderer.build_candidate_render_index(forged_view)

    assert changed.materialized_view_sha256 == forged_view.typed_canonical_json_sha256
    assert changed.materialized_view_sha256 != baseline.materialized_view_sha256
    assert changed.candidate_render_index_sha256 != baseline.candidate_render_index_sha256
    assert {
        key: dataclasses.replace(value, stability=value.stability) for key, value in changed.enriched_fields.items()
    } == dict(baseline.enriched_fields)


@pytest.mark.parametrize("mutation", ("mandatory_rule", "producer_identity", "span_name_part"))
def test_candidate_enrichment_rejects_forged_cross_contract_joins(
    renderer: ModuleType,
    view: Any,
    mutation: str,
) -> None:
    facts = _copy_materialized(view.facts)
    domains = facts["fields"]["domains"]
    if mutation == "mandatory_rule":
        family = next(
            group["fields"]
            for domain in domains
            for group in domain["fields"]["groups"]
            if group["fields"]["id"] == "log.asset.activated"
        )
        family["mandatory_floor"] = ("unregistered_rule",)
        expected = "mandatory program"
    elif mutation == "producer_identity":
        identity = next(
            mapping["fields"]["default_identity"]["fields"]
            for domain in domains
            for mapping in domain["fields"]["producer_mappings"]
            if mapping["fields"]["default_identity"] is not None
            and mapping["fields"]["default_identity"]["fields"]["family"] is not None
        )
        identity["bucket"] = "platform.health"
        expected = "selected canonical family"
    else:
        family = next(
            group["fields"]
            for domain in domains
            for group in domain["fields"]["groups"]
            if group["fields"]["type"] == "span"
        )
        family["span_name_parts"][0]["fields"]["literal"] += "forged"
        expected = "span-name parts disagree"

    with pytest.raises(renderer.CandidateRenderError, match=expected):
        renderer.build_candidate_render_index(_retagged_view(renderer, view, facts))


def test_expanded_rows_use_selected_family_floor_not_legacy_mapping_rules(
    renderer: ModuleType,
    view: Any,
) -> None:
    baseline = renderer.build_candidate_render_index(view)
    facts = _copy_materialized(view.facts)
    mapping = next(
        item["fields"]
        for domain in facts["fields"]["domains"]
        for item in domain["fields"]["producer_mappings"]
        if item["fields"]["default_identity"] is not None
        and item["fields"]["default_identity"]["fields"]["family"] is not None
        and not item["fields"]["mandatory_rules"]
    )
    producer = mapping["producer"]
    key = mapping["key"]
    family_id = mapping["default_identity"]["fields"]["family"]
    mapping["mandatory_rules"] = ("always",)
    changed = renderer.build_candidate_render_index(_retagged_view(renderer, view, facts))
    changed_row = next(
        row
        for row in changed.expanded_producer_mappings
        if row.producer == producer and row.key == key and row.identity_origin == "default"
    )

    assert changed_row.legacy_mapping_mandatory_rules == ("always",)
    assert changed_row.selected_mandatory_program_id == family_id
    assert changed.mandatory_programs[family_id] == baseline.mandatory_programs[family_id]


def test_candidate_renderer_is_deterministic_complete_and_in_memory(
    renderer: ModuleType,
    view: Any,
    artifacts: Mapping[str, Any],
) -> None:
    index = renderer.build_candidate_render_index(view)
    from_index = renderer.render_candidate_artifacts_from_index(index)
    repeated = from_index

    assert tuple(artifacts) == tuple(sorted(artifacts))
    assert {path: artifact.payload for path, artifact in repeated.items()} == {
        path: artifact.payload for path, artifact in artifacts.items()
    }
    assert {path: artifact.payload for path, artifact in from_index.items()} == {
        path: artifact.payload for path, artifact in artifacts.items()
    }
    assert artifacts
    assert {
        f"{PREFIX}/telemetry.schema.json",
        f"{PREFIX}/catalog.json",
        f"{PREFIX}/catalog.md",
        f"{PREFIX}/compatibility/galileo-rich-v2.json",
        f"{PREFIX}/compatibility/local-observability-v1.json",
        f"{PREFIX}/compatibility/openinference-v1.json",
        f"{PREFIX}/compatibility/v7-exporter-selection.json",
        f"{PREFIX}/compatibility/inbound-otlp.json",
        f"{PREFIX}/examples/manifest.json",
        f"{PREFIX}/otlp-fixtures/manifest.json",
    }.issubset(artifacts)
    assert sum("/examples/valid/" in path for path in artifacts) == 7
    assert sum("/examples/invalid/" in path for path in artifacts) == 6
    assert sum("/otlp-fixtures/cases/" in path for path in artifacts) == 13
    with pytest.raises(TypeError):
        artifacts["new"] = artifacts[next(iter(artifacts))]  # type: ignore[index]
    for path, artifact in artifacts.items():
        assert artifact.path == path
        assert artifact.mode == 0o644
        assert artifact.payload
        assert path.startswith(f"{PREFIX}/")
        assert renderer._normalized_candidate_path(path) == path
        assert not PurePosixPath(path).is_absolute()

    forged = dataclasses.replace(index, candidate_render_index_sha256="0" * 64)
    with pytest.raises(renderer.CandidateRenderError, match="digest-valid CandidateRenderIndex"):
        renderer.render_candidate_artifacts_from_index(forged)


def test_v7_exporter_selection_is_schema_valid_derived_and_non_wildcard(
    artifacts: Mapping[str, Any],
) -> None:
    document = _json(artifacts, "compatibility/v7-exporter-selection.json")
    schema = json.loads((ROOT / "schemas/telemetry/v8/compatibility/v7-exporter-selection.schema.json").read_bytes())
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.Draft202012Validator(schema).validate(document)

    gateway_events = document["exporters"]["gateway_jsonl"]["logs"][0]["event_names"]
    console_events = document["exporters"]["gateway_console"]["logs"][0]["event_names"]
    audit_actions = document["exporters"]["audit_sink"]["logs"][0]["actions"]
    assert gateway_events == console_events == sorted(gateway_events)
    assert gateway_events
    assert audit_actions == sorted(set(audit_actions))
    assert {
        "guardrail.evaluation.completed",
        "finding.observed",
        "legacy.audit.config.update",
        "model.request",
        "tool.invocation.requested",
    }.issubset(gateway_events)
    assert {
        "api-auth-failure",
        "config-update",
        "gateway-agent-start",
        "guardrail-verdict",
        "scan",
    }.issubset(audit_actions)
    assert "*" not in json.dumps(document)
    metric_buckets = document["exporters"]["generic_otlp"]["metrics"][0]["buckets"]
    assert metric_buckets and len(metric_buckets) == len(set(metric_buckets))
    assert document["collection"]["always"]["logs"] == metric_buckets
    assert document["collection"]["otel.logs"]["logs"] == metric_buckets
    assert document["collection"]["otel.traces"]["traces"] == metric_buckets
    assert document["collection"]["otel.metrics"]["metrics"] == metric_buckets
    assert document["exporters"]["generic_otlp"]["logs"][0]["buckets"] == metric_buckets
    assert document["exporters"]["local_observability"]["logs"][0]["buckets"] == metric_buckets
    assert document["exporters"]["local_observability"]["metrics"][0]["buckets"] == metric_buckets
    generic_spans = document["exporters"]["generic_otlp"]["traces"][0]["event_names"]
    assert document["exporters"]["local_observability"]["traces"][0]["event_names"] == generic_spans
    catalog = _json(artifacts, "catalog.json")
    log_families = [family for family in catalog["families"] if family["signal"] == "logs"]
    span_families = [family for family in catalog["families"] if family["signal"] == "traces"]
    metric_families = [family for family in catalog["families"] if family["signal"] == "metrics"]
    assert log_families and span_families and metric_families
    assert {family["bucket"] for family in log_families} == set(metric_buckets)
    assert {family["id"] for family in span_families} == set(generic_spans)
    assert {family["bucket"] for family in metric_families} == set(metric_buckets)


def test_inbound_otlp_catalog_is_closed_two_level_and_shape_safe(
    renderer: ModuleType,
    render_index: Any,
) -> None:
    inbound = render_index.inbound_otlp
    marker = renderer._authority_marker(
        registry_version=render_index.registry_version,
        digest=render_index.digest,
        artifact="compatibility/inbound-otlp.json",
    )
    document = renderer._inbound_otlp_document(render_index, marker)

    assert inbound.binding_classes
    assert inbound.match_descriptors and inbound.target_descriptors
    assert document["support"]["logical_binding_classes"] == (
        len(inbound.binding_classes) + len(inbound.derivation_attachments)
    )
    assert document["support"]["match_descriptors"] == len(inbound.match_descriptors)
    assert document["support"]["target_descriptors"] == len(inbound.target_descriptors)
    assert document["support"]["native_markers"] == len(inbound.native_markers)
    assert document["support"]["self_echo_recognizers"] == len(inbound.echo_recognizers)
    assert document["support"]["import_contexts"] == len(inbound.import_contexts)
    assert document["support"]["signals"] == ["logs", "traces", "metrics"]
    assert document["support"]["encodings"] == ["json", "protobuf"]
    assert document["runtime_activation"] == "compiler_descriptors_only"
    assert document["contract"]["shape_policy"] == {
        "classes": ["native_exact", "native_malformed", "external"],
        "native_marker_rule": "any_declared_native_marker_selects_native_candidate",
        "structural_marker_rule": "exact_declared_structure_only",
        "native_malformed_disposition": "invalid_record",
        "native_malformed_external_fallback": "forbidden",
    }
    assert {item["shape"] for item in document["match_descriptors"]} == {"native_exact", "external"}
    assert all(item["shape"] != "native_malformed" for item in document["match_descriptors"])
    assert len(document["native_markers"]) == len(inbound.native_markers)
    assert {item["signal"] for item in document["native_markers"]} == {"logs", "traces", "metrics"}
    assert all(
        item["marker_kind"] in {"reserved_key_presence", "exact_structural_value", "projected_record_structure"}
        for item in document["native_markers"]
    )
    targets_by_id = {item["id"]: item for item in document["target_descriptors"]}
    for match in document["match_descriptors"]:
        targets = [targets_by_id[target_id] for target_id in match["target_ids"]]
        assert sum(target["target_kind"] == "primary" for target in targets) == 1
        assert all(target["match_id"] == match["id"] for target in targets)
    assert all("mandatory" not in item and "floor" not in item for item in document["import_contexts"])


def test_inbound_otlp_exact_genai_codex_claude_and_fixture_matrix(
    renderer: ModuleType,
    render_index: Any,
) -> None:
    marker = renderer._authority_marker(
        registry_version=render_index.registry_version,
        digest=render_index.digest,
        artifact="compatibility/inbound-otlp.json",
    )
    document = renderer._inbound_otlp_document(render_index, marker)
    matches = {item["id"]: item for item in document["match_descriptors"]}
    duration_ids = {
        "otlp.genai.duration.metric.v1.gen-ai-client",
        "otlp.genai.duration.metric.v1.gen-ai",
        "otlp.genai.duration.metric.v1.llm",
        "otlp.genai.duration.metric.v1.claude-code",
        "otlp.genai.duration.metric.v1.codex",
    }
    assert duration_ids <= set(matches)
    assert {
        "otlp.genai.span.operation.v1.span.agent.invoke",
        "otlp.genai.span.operation.v1.span.model.chat",
        "otlp.genai.span.operation.v1.span.model.embeddings",
        "otlp.genai.span.operation.v1.span.tool.execute",
        "otlp.genai.span.operation.v1.span.retrieval.search",
        "otlp.genai.span.operation.v1.span.workflow.run",
    } <= set(matches)
    assert "otlp.codex.user_prompt.v1.log.model.request" in matches
    assert "otlp.claudecode.user_prompt.v1.log.model.request" in matches
    assert "otlp.codex.response_completed.v1.log.model.response" in matches
    assert "otlp.claudecode.token_usage.v1.metric.gen_ai.client.token.usage" in matches

    corpus = document["fixture_corpus"]
    assert set(corpus["encodings"]) == {"json", "protobuf"}
    assert corpus["encodings"]["protobuf"]["representation"] == "canonical_protojson"
    assert len(corpus["descriptors"]) == len(render_index.inbound_otlp.match_descriptors)
    assert document["support"]["fixture_descriptors"] == len(corpus["descriptors"])
    assert document["support"]["fixture_cases"] == sum(len(item["cases"]) for item in corpus["descriptors"])
    for fixture in corpus["descriptors"]:
        assert [case["fixture_class"] for case in fixture["cases"]] == [
            "positive",
            "negative",
            "single_fault",
        ]
        assert fixture["cases"][0]["expected_match_id"] == fixture["match_id"]
        assert fixture["cases"][1]["expected_match_id"] is None
        assert fixture["cases"][2]["expected_match_id"] is None
        rule = fixture["source_unit_rule"]
        unit_cases = fixture["unit_cases"]
        if rule["kind"] == "none":
            assert unit_cases == []
        else:
            positives = [case for case in unit_cases if case["fixture_class"] == "positive"]
            assert [(case["source_unit"], case["expected_scale"]) for case in positives] == [
                (entry["source_unit"], entry["scale"]) for entry in rule["accepted"]
            ]
            assert [case["fixture_class"] for case in unit_cases[-2:]] == ["negative", "single_fault"]
            assert all(case["expected_scale"] is None for case in unit_cases[-2:])

    duration = matches["otlp.genai.duration.metric.v1.gen-ai-client"]["mapping"]["source_unit_rule"]
    assert duration == {
        "kind": "scale-table-v1",
        "target_unit": "s",
        "accepted": [
            {"source_unit": unit, "scale": scale}
            for unit, scale in (
                ("", 1.0),
                ("s", 1.0),
                ("second", 1.0),
                ("seconds", 1.0),
                ("ms", 0.001),
                ("millisecond", 0.001),
                ("milliseconds", 0.001),
                ("us", 0.000001),
                ("microsecond", 0.000001),
                ("microseconds", 0.000001),
                ("ns", 0.000000001),
                ("nanosecond", 0.000000001),
                ("nanoseconds", 0.000000001),
            )
        ],
    }
    token = matches["otlp.claudecode.token_usage.v1.metric.gen_ai.client.token.usage"]["mapping"]["source_unit_rule"]
    assert token == {
        "kind": "scale-table-v1",
        "target_unit": "{token}",
        "accepted": [
            {"source_unit": "", "scale": 1.0},
            {"source_unit": "{token}", "scale": 1.0},
            {"source_unit": "token", "scale": 1.0},
            {"source_unit": "tokens", "scale": 1.0},
        ],
    }
    native = next(match for match in matches.values() if match["class_id"] == "otlp.native.metric.v8")
    native_target = next(target for target in document["target_descriptors"] if target["match_id"] == native["id"])
    assert native["mapping"]["source_unit_rule"] == {
        "kind": "target-unit-equality-v1",
        "target_unit": native_target["instrument_unit"],
        "accepted": [{"source_unit": native_target["instrument_unit"], "scale": 1.0}],
    }


def test_candidate_renderer_rejects_rehashed_v7_selector_drift(
    renderer: ModuleType,
    view: Any,
) -> None:
    facts = _copy_materialized(view.facts)
    selection = facts["fields"]["v7_exporter_selection"]
    audit_logs = list(selection["exporters"]["audit_sink"]["logs"])
    actions = audit_logs[0]["actions"]
    audit_logs[0]["actions"] = actions[:-1]
    selection["exporters"]["audit_sink"]["logs"] = tuple(audit_logs)
    forged = _retagged_view(renderer, view, facts)

    with pytest.raises(renderer.CandidateRenderError, match="producer-derived selectors disagree"):
        renderer.build_candidate_render_index(forged)


def test_candidate_index_consumes_derived_go_symbol_contract_immutably_and_preserves_real_smoke(
    renderer: ModuleType,
    view: Any,
    artifacts: Mapping[str, Any],
) -> None:
    index = renderer.build_candidate_render_index(view)
    table = index.go_symbol_table
    rows = {(row.kind, row.source_id): row for row in table.rows}

    assert index.go_symbol_policy.package == "observability"
    assert index.go_symbol_policy.brand_spellings == {
        "defenseclaw": "DefenseClaw",
        "opentelemetry": "OpenTelemetry",
        "otel": "OTel",
    }
    assert index.go_symbol_overrides == ()
    assert table.rows
    assert table.kind_counts == Counter(row.kind for row in table.rows)
    assert table.declaration_form_counts == Counter(row.declaration_form for row in table.rows)
    assert rows[("family", "span.model.chat")].symbol == "TelemetryFamilyModelChat"
    assert rows[("span_event", "model.retry")].symbol == "TelemetrySpanEventModelRetry"
    assert rows[("structured_type", "gen_ai.canonical_json")].declaration_form == "exported_type"
    assert rows[("span_link_constructor", "span.model.chat#caused_by")].symbol == ("NewSpanModelChatCausedByLink")
    assert artifacts
    with pytest.raises(TypeError):
        index.go_symbol_policy.brand_spellings["otel"] = "Otel"  # type: ignore[index]
    with pytest.raises(TypeError):
        table.kind_counts["attribute"] = 1  # type: ignore[index]
    with pytest.raises(dataclasses.FrozenInstanceError):
        table.rows[0].symbol = "Changed"  # type: ignore[misc]


@pytest.mark.parametrize("target", ("policy", "table", "row", "override"))
def test_candidate_index_rejects_noncanonical_go_symbol_tag_shapes(
    renderer: ModuleType,
    view: Any,
    target: str,
) -> None:
    facts = _copy_materialized(view.facts)
    if target == "policy":
        facts["fields"]["go_symbol_policy"]["fields"]["future"] = True
    elif target == "table":
        _go_symbol_table_fields(facts)["future"] = True
    elif target == "row":
        _go_symbol_table_fields(facts)["rows"][0]["fields"]["future"] = True
    else:
        facts["fields"]["go_symbol_overrides"] = (
            {
                "$type": "GoSymbolOverrideIR",
                "fields": {
                    "kind": "attribute",
                    "source_id": "action",
                    "symbol": "TelemetryAttributeActionV2",
                    "reason": "reviewed test override",
                    "future": True,
                },
            },
        )

    with pytest.raises(renderer.CandidateRenderError, match="GoSymbol|Go symbol"):
        renderer.build_candidate_render_index(_retagged_view(renderer, view, facts))


@pytest.mark.parametrize(
    "mutation",
    (
        "policy",
        "policy_version_bool",
        "policy_version_float",
        "table_version_bool",
        "table_version_float",
        "kind_count_bool",
        "kind_count_float",
        "declaration_count_float",
        "override",
        "count",
        "form",
        "order",
        "digest",
    ),
)
def test_candidate_index_rejects_forged_go_symbol_policy_rows_and_counts(
    renderer: ModuleType,
    view: Any,
    mutation: str,
) -> None:
    facts = _copy_materialized(view.facts)
    table = _go_symbol_table_fields(facts)
    if mutation == "policy":
        facts["fields"]["go_symbol_policy"]["fields"]["brand_spellings"]["otel"] = "Otel"
    elif mutation == "policy_version_bool":
        facts["fields"]["go_symbol_policy"]["fields"]["version"] = True
    elif mutation == "policy_version_float":
        facts["fields"]["go_symbol_policy"]["fields"]["version"] = 1.0
    elif mutation == "table_version_bool":
        table["version"] = True
    elif mutation == "table_version_float":
        table["version"] = 1.0
    elif mutation == "kind_count_bool":
        table["kind_counts"]["semantic_profile"] = True
    elif mutation == "kind_count_float":
        table["kind_counts"]["semantic_profile"] = 1.0
    elif mutation == "declaration_count_float":
        table["declaration_form_counts"]["exported_const"] = 901.0
    elif mutation == "override":
        facts["fields"]["go_symbol_overrides"] = (
            {
                "$type": "GoSymbolOverrideIR",
                "fields": {
                    "kind": "attribute",
                    "source_id": "action",
                    "symbol": "TelemetryAttributeActionV2",
                    "reason": "reviewed test override",
                },
            },
        )
    elif mutation == "count":
        table["kind_counts"]["attribute"] -= 1
    elif mutation == "form":
        table["rows"][0]["fields"]["declaration_form"] = "exported_type"
        _redigest_go_symbol_table(renderer, table)
    elif mutation == "order":
        reordered = list(table["rows"])
        reordered[0], reordered[1] = reordered[1], reordered[0]
        table["rows"] = tuple(reordered)
        _redigest_go_symbol_table(renderer, table)
    else:
        table["table_sha256"] = "0" * 64

    with pytest.raises(renderer.CandidateRenderError):
        renderer.build_candidate_render_index(_retagged_view(renderer, view, facts))


def test_candidate_index_source_reconciliation_rejects_rehashed_forged_source(
    renderer: ModuleType,
    view: Any,
) -> None:
    facts = _copy_materialized(view.facts)
    table = _go_symbol_table_fields(facts)
    table["rows"][0]["fields"]["source_id"] = "action.forged"
    _redigest_go_symbol_table(renderer, table)

    with pytest.raises(renderer.CandidateRenderError, match="sources disagree with registry facts"):
        renderer.build_candidate_render_index(_retagged_view(renderer, view, facts))


@pytest.mark.parametrize(
    "example_id",
    [
        pytest.param("a/b", id="separator"),
        pytest.param("a/../b", id="parent-segment"),
        pytest.param("a..b", id="dot-dot"),
        pytest.param("a:b", id="colon"),
        pytest.param("Uppercase", id="uppercase"),
        pytest.param("case.Alias", id="nonportable-case-alias"),
        pytest.param("a" * 129, id="overlength"),
    ],
)
def test_example_ids_are_portable_path_segments_and_fail_before_payload_rendering(
    renderer: ModuleType,
    view: Any,
    monkeypatch: pytest.MonkeyPatch,
    example_id: str,
) -> None:
    facts = _copy_materialized(view.facts)
    _set_unreferenced_invalid_example_id(facts, example_id)
    retagged = _retagged_view(renderer, view, facts)
    payload_calls: list[object] = []
    renderer_calls: list[object] = []

    def unexpected_payload(document: object) -> bytes:
        payload_calls.append(document)
        return b"unexpected"

    def unexpected_renderer(model: object, marker: object) -> object:
        renderer_calls.append((model, marker))
        return {}

    with pytest.raises(renderer.CandidateRenderError, match="portable output path segment"):
        renderer.build_candidate_render_index(retagged)
    monkeypatch.setattr(renderer, "_json_payload", unexpected_payload)
    monkeypatch.setattr(renderer, "_render_schema", unexpected_renderer)
    with pytest.raises(renderer.CandidateRenderError, match="portable output path segment"):
        renderer.render_candidate_artifacts(retagged)
    assert payload_calls == []
    assert renderer_calls == []


@pytest.mark.parametrize(
    "example_id",
    [
        pytest.param("con", id="console"),
        pytest.param("nul", id="null-device"),
        pytest.param("com1", id="serial"),
        pytest.param("lpt9", id="parallel"),
    ],
)
def test_candidate_index_rejects_platform_reserved_example_ids(
    renderer: ModuleType,
    view: Any,
    example_id: str,
) -> None:
    facts = _copy_materialized(view.facts)
    _set_unreferenced_invalid_example_id(facts, example_id)

    with pytest.raises(renderer.CandidateRenderError, match="platform-reserved syntax"):
        renderer.build_candidate_render_index(_retagged_view(renderer, view, facts))


@pytest.mark.parametrize(
    "path",
    [
        pytest.param(f"{PREFIX}/cases/con.json", id="device-with-extension"),
        pytest.param(f"{PREFIX}/cases/NUL.txt", id="case-insensitive-device"),
        pytest.param(f"{PREFIX}/cases/CLOCK$.json", id="legacy-clock-device"),
        pytest.param(f"{PREFIX}/cases/CONIN$.txt", id="legacy-console-input-device"),
        pytest.param(f"{PREFIX}/cases/CONOUT$.txt", id="legacy-console-output-device"),
        pytest.param(f"{PREFIX}/cases/COM¹.json", id="superscript-serial-one"),
        pytest.param(f"{PREFIX}/cases/com².txt", id="superscript-serial-two"),
        pytest.param(f"{PREFIX}/cases/Com³.bin", id="superscript-serial-three"),
        pytest.param(f"{PREFIX}/cases/LPT¹.json", id="superscript-parallel-one"),
        pytest.param(f"{PREFIX}/cases/lpt².txt", id="superscript-parallel-two"),
        pytest.param(f"{PREFIX}/cases/Lpt³.bin", id="superscript-parallel-three"),
        pytest.param(f"{PREFIX}/cases/a:b.json", id="alternate-data-stream"),
        pytest.param(f"{PREFIX}/cases/trailing.", id="trailing-dot"),
        pytest.param(f"{PREFIX}/cases/trailing ", id="trailing-space"),
    ],
)
def test_candidate_path_and_complete_preflight_reject_platform_reserved_syntax(
    renderer: ModuleType,
    path: str,
) -> None:
    with pytest.raises(renderer.CandidateRenderError, match="platform-reserved syntax"):
        renderer._normalized_candidate_path(path)
    with pytest.raises(renderer.CandidateRenderError, match="platform-reserved syntax"):
        renderer._preflight_candidate_output_paths((*renderer._STATIC_CANDIDATE_OUTPUT_PATHS, path))


@pytest.mark.parametrize(
    "invalid_character",
    [pytest.param(character, id=f"punctuation-{ord(character):02x}") for character in '<>"|?*']
    + [pytest.param(chr(codepoint), id=f"control-{codepoint:02x}") for codepoint in range(1, 32)],
)
def test_candidate_path_preflight_rejects_every_windows_invalid_component_character(
    renderer: ModuleType,
    invalid_character: str,
) -> None:
    path = f"{PREFIX}/cases/before{invalid_character}after.json"

    with pytest.raises(renderer.CandidateRenderError, match="platform-reserved syntax"):
        renderer._normalized_candidate_path(path)
    with pytest.raises(renderer.CandidateRenderError, match="platform-reserved syntax"):
        renderer._preflight_candidate_output_paths((*renderer._STATIC_CANDIDATE_OUTPUT_PATHS, path))


@pytest.mark.parametrize(
    ("collision", "expected"),
    [
        pytest.param("exact", "duplicated", id="exact"),
        pytest.param("casefold", "portable collision", id="casefold"),
        pytest.param("nfc", "portable collision", id="nfc"),
    ],
)
def test_candidate_index_preflights_complete_output_path_set_before_materialization(
    renderer: ModuleType,
    view: Any,
    monkeypatch: pytest.MonkeyPatch,
    collision: str,
    expected: str,
) -> None:
    baseline = renderer.build_candidate_render_index(view)
    example_id = baseline.examples[0]["id"]
    target = baseline.example_output_paths[example_id].normalized_example_path
    if collision == "exact":
        additions = (target,)
    elif collision == "casefold":
        additions = (target.replace(example_id, example_id.upper()),)
    else:
        additions = (
            f"{PREFIX}/examples/valid/\u00e9.json",
            f"{PREFIX}/examples/valid/e\u0301.json",
        )
    monkeypatch.setattr(
        renderer,
        "_STATIC_CANDIDATE_OUTPUT_PATHS",
        (*renderer._STATIC_CANDIDATE_OUTPUT_PATHS, *additions),
    )

    with pytest.raises(renderer.CandidateRenderError, match=expected):
        renderer.build_candidate_render_index(view)


def test_renderer_consumes_materialized_example_output_path_facts(
    renderer: ModuleType,
    view: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    index = renderer.build_candidate_render_index(view)
    example = index.examples[0]
    original_paths = index.example_output_paths[example["id"]]
    replacement_path = f"{PREFIX}/examples/valid/index-owned-render-path.json"
    replacement_paths = dataclasses.replace(
        original_paths,
        normalized_example_path=replacement_path,
    )
    output_paths = dict(index.example_output_paths)
    output_paths[example["id"]] = replacement_paths
    replacement_index = dataclasses.replace(index, example_output_paths=output_paths)
    monkeypatch.setattr(renderer, "build_candidate_render_index", lambda candidate_view: replacement_index)

    artifacts = renderer.render_candidate_artifacts(view)

    assert replacement_path in artifacts
    assert original_paths.normalized_example_path not in artifacts
    manifest = _json(artifacts, "examples/manifest.json")
    entry = next(item for item in manifest["cases"] if item["id"] == example["id"])
    assert entry["path"] == "examples/valid/index-owned-render-path.json"


def test_candidate_artifact_insertion_rejects_exact_and_unicode_casefold_collisions_atomically(
    renderer: ModuleType,
) -> None:
    def artifact(path: str, payload: bytes) -> Any:
        return renderer.CandidateArtifact(path, payload, "application/json", renderer.JSON_OWNERSHIP_MARKER)

    exact_path = f"{PREFIX}/cases/exact.json"
    artifacts: dict[str, Any] = {}
    renderer._add_candidate_artifact(artifacts, artifact(exact_path, b"first"))
    before = dict(artifacts)
    with pytest.raises(renderer.CandidateRenderError, match="duplicated"):
        renderer._add_candidate_artifact(artifacts, artifact(exact_path, b"second"))
    assert artifacts == before

    folded: dict[str, Any] = {}
    renderer._add_candidate_artifact(folded, artifact(f"{PREFIX}/cases/Straße.json", b"first"))
    folded_before = dict(folded)
    with pytest.raises(renderer.CandidateRenderError, match="portable collision"):
        renderer._add_candidate_artifact(folded, artifact(f"{PREFIX}/cases/STRASSE.json", b"second"))
    assert folded == folded_before


def test_full_candidate_preflight_rejects_case_alias_collision(
    renderer: ModuleType,
) -> None:
    lower = f"{PREFIX}/cases/alias.json"
    upper = f"{PREFIX}/cases/ALIAS.json"
    candidates = {
        lower: renderer.CandidateArtifact(lower, b"lower", "application/json", renderer.JSON_OWNERSHIP_MARKER),
        upper: renderer.CandidateArtifact(upper, b"upper", "application/json", renderer.JSON_OWNERSHIP_MARKER),
    }
    with pytest.raises(renderer.CandidateRenderError, match="portable collision"):
        renderer._preflight_candidate_artifacts(candidates)


def test_real_registry_compile_and_candidate_render_smoke(
    artifacts: Mapping[str, Any],
) -> None:
    assert f"{PREFIX}/telemetry.schema.json" in artifacts
    assert f"{PREFIX}/catalog.json" in artifacts








def test_every_artifact_carries_candidate_authority_and_view_digest(
    renderer: ModuleType,
    view: Any,
    render_index: Any,
    artifacts: Mapping[str, Any],
) -> None:
    for path, artifact in artifacts.items():
        if path.endswith(".json"):
            assert 0 <= artifact.payload.find(renderer.JSON_OWNERSHIP_MARKER) < 4096
            document = json.loads(artifact.payload)
            marker = document["x-defenseclaw-generated"]
            assert marker == {
                "artifact": path.removeprefix(f"{PREFIX}/"),
                "authority": renderer.CANDIDATE_AUTHORITY,
                "generator": renderer.GENERATOR_ID,
                "materialized_view_sha256": view.typed_canonical_json_sha256,
                "registry_version": 1,
            }
            assert artifact.ownership_marker == renderer.JSON_OWNERSHIP_MARKER
        else:
            rendered = artifact.payload.decode("utf-8")
            assert rendered.startswith(renderer.MARKDOWN_MARKER_PREFIX)
            assert renderer.CANDIDATE_AUTHORITY in rendered.splitlines()[0]
            assert view.typed_canonical_json_sha256 in rendered.splitlines()[0]


def test_bundle_is_complete_draft_2020_12_and_examples_have_exact_dispositions(
    artifacts: Mapping[str, Any],
) -> None:
    schema = _json(artifacts, "telemetry.schema.json")
    jsonschema.Draft202012Validator.check_schema(schema)
    validator = jsonschema.Draft202012Validator(schema)

    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["$id"] == "https://defenseclaw.dev/schemas/telemetry/v8/telemetry.schema.json"
    family_refs = {f"#/$defs/{name}" for name in schema["$defs"] if name.startswith("family:")}
    assert {item["$ref"] for item in schema["oneOf"]} == family_refs
    assert set(schema["x-defenseclaw-conditions"][0]) == {"description", "enforcement", "false_requirement", "id"}
    assert "$type" not in json.dumps(schema["x-defenseclaw-conditions"])
    assert len({item["id"] for item in schema["x-defenseclaw-conditions"]}) == len(
        schema["x-defenseclaw-conditions"]
    )
    mandatory_catalog = schema["x-defenseclaw-mandatory-rule-catalog"]
    assert mandatory_catalog["version"] == 1
    assert [rule["id"] for rule in mandatory_catalog["rules"]] == [
        "always",
        "control_plane_mutation",
        "approval_resolution",
        "alert_mutation",
        "protected_boundary_auth_failure",
        "enforced_outcome",
        "enforcement_state_change",
        "schema_validation_failure",
        "sqlite_failure",
        "exporter_initialization_failure",
        "durable_health_transition",
        "destination_test_activity",
        "managed_aid_fail_open",
    ]
    assert mandatory_catalog["rules"][0]["enforcement"] == {
        "fact": None,
        "kind": "constant",
        "value": True,
    }
    assert "$type" not in json.dumps(mandatory_catalog)
    assert schema["x-defenseclaw-value-catalogs"][0]["id"] == "agent-phase-v1"
    otlp = schema["x-defenseclaw-canonical-to-otlp"]
    assert otlp["id"] == "defenseclaw-otlp-v1"
    assert otlp["null_value_policy"] == "reject"
    assert otlp["field_context_overrides"] == {
        "trace_resource.schema_url": "ResourceSpans",
        "trace_scope.schema_url": "ResourceSpans.scopeSpans[]",
    }
    trace_derivations = schema["x-defenseclaw-trace-derivations"]
    assert len(trace_derivations) == 11
    assert next(item for item in trace_derivations if item["id"] == "trace-scope-version-equality-v1") == {
        "equality": "typed-json-exact",
        "id": "trace-scope-version-equality-v1",
        "presence": "when-registered",
        "source": "provenance.binary_version",
        "target_attribute": None,
        "target_field": "trace_scope.version",
    }
    conformance = schema["x-defenseclaw-conformance"]
    assert conformance["scope"] == "canonical-schema-comparison-only"
    assert conformance["builder_parity"] == "pending-source-inputs"
    assert conformance["required_materialized_inputs"] == [
        "builder_facts",
        "deterministic_occurrence_inputs",
    ]
    assert {
        "builder_fact_conditions",
        "complete_payload_leaf_field_class_coverage",
        "ordinary_shape_aware_utf8_byte_bounds",
        "ordinary_container_depth_bounds",
        "ordinary_string_leaf_utf8_byte_bounds",
        "portable_re2_full_match_patterns",
        "recursive_aggregate_max_items",
        "recursive_property_count_bounds",
        "typed_json_enum_membership",
        "span_name_pattern_rendering",
        "trace_cross_field_derivation_equality",
        "trace_time_order_relation",
        "typed_numeric_arm_int64_vs_finite_double",
    }.issubset(conformance["non_json_schema_gates"])

    observed = {True: 0, False: 0}
    for path, artifact in artifacts.items():
        if "/examples/valid/" not in path and "/examples/invalid/" not in path:
            continue
        example = json.loads(artifact.payload)
        errors = list(validator.iter_errors(example["record"]))
        observed[example["valid"]] += 1
        if example["valid"]:
            assert errors == [], example["id"]
            assert example["expected_error"] is None
            assert example["mutation"] is None
            assert example["builder_context"]["inheritance"] == {
                "base_example": None,
                "mode": "explicit",
            }
            assert example["builder_context"]["occurrence"] == {
                "record_id": example["record"]["record_id"],
                "timestamp": example["record"]["timestamp"],
            }
        else:
            assert errors, example["id"]
            assert example["expected_error"]
            assert example["base_example"]
            assert example["mutation"]["kind"] == example["expected_error"]
            assert example["mutation"]["changes"]
            assert example["builder_context"] == {
                "condition_facts": [],
                "inheritance": {
                    "base_example": example["base_example"],
                    "mode": "exact_base",
                },
                "mandatory_facts": [],
                "occurrence": None,
            }
    assert observed == {True: 7, False: 6}


def test_provenance_import_schema_is_closed_bounded_and_cross_field_exact(
    artifacts: Mapping[str, Any],
) -> None:
    schema = _json(artifacts, "telemetry.schema.json")
    catalog = _json(artifacts, "catalog.json")
    validator = jsonschema.Draft202012Validator(schema)
    import_schema = schema["$defs"]["structural:provenance_import"]
    import_validator = _subschema_validator(schema, import_schema)
    base_record = _json(
        artifacts,
        "examples/valid/valid-model-chat-with-honest-missing-content-and-usage.json",
    )["record"]
    assert validator.is_valid(base_record)
    assert "import" not in base_record["provenance"]

    valid_import = {
        "protocol": "otlp",
        "binding_id": "otlp.genai.span.operation.v1.chat",
        "mode": "import_and_derive",
        "derivation": "arithmetic_mean",
        "source_aggregate_count": 2**64 - 1,
        "authenticated_source": "codex",
        "upstream_instance_id": "upstream-instance-1",
        "upstream_record_id": "123E4567-E89B-12D3-A456-426614174000",
        "upstream_service_name": "upstream-service",
        "upstream_redaction_profile": "sensitive",
        "ingress_hop_count": 4,
        "last_hop_instance_id": "forwarder-instance-1",
        "last_hop_destination": "otlp-primary",
    }
    valid_variants = (
        valid_import,
        {
            key: value
            for key, value in {
                **valid_import,
                "mode": "import",
                "derivation": None,
                "source_aggregate_count": None,
            }.items()
            if value is not None
        },
        {
            key: value
            for key, value in {
                **valid_import,
                "mode": "derive",
                "derivation": "field_value",
                "source_aggregate_count": None,
                "upstream_record_id": "record.stable-01",
            }.items()
            if value is not None
        },
    )
    for provenance_import in valid_variants:
        assert import_validator.is_valid(provenance_import)
        record = json.loads(json.dumps(base_record))
        record["provenance"]["import"] = provenance_import
        assert validator.is_valid(record)

    invalid_imports = []

    def invalid(**changes: Any) -> dict[str, Any]:
        candidate = json.loads(json.dumps(valid_import))
        for key, value in changes.items():
            if value is None:
                candidate.pop(key, None)
            else:
                candidate[key] = value
        return candidate

    invalid_imports.extend(
        (
            invalid(protocol="grpc"),
            invalid(protocol=None),
            invalid(binding_id=None),
            invalid(binding_id=""),
            invalid(authenticated_source=None),
            invalid(ingress_hop_count=None),
            invalid(mode="copy"),
            invalid(derivation="histogram"),
            invalid(source_aggregate_count=0),
            invalid(source_aggregate_count="4"),
            invalid(ingress_hop_count=5),
            invalid(ingress_hop_count="4"),
            invalid(upstream_record_id="{123e4567-e89b-12d3-a456-426614174000}"),
            invalid(upstream_record_id="UPSTREAM-RECORD"),
            invalid(upstream_redaction_profile="Sensitive Profile"),
            {**valid_import, "unknown": "rejected"},
            invalid(mode="import"),
            invalid(derivation=None),
            invalid(source_aggregate_count=None),
            invalid(derivation="elapsed_time"),
        )
    )
    for field in (
        "binding_id",
        "authenticated_source",
        "upstream_instance_id",
        "upstream_service_name",
        "last_hop_instance_id",
        "last_hop_destination",
    ):
        invalid_imports.extend((invalid(**{field: ""}), invalid(**{field: "x" * 513})))
    invalid_imports.extend(
        (
            invalid(upstream_record_id="r" * 129),
            invalid(upstream_redaction_profile="r" * 129),
        )
    )
    pure_import_with_count = invalid(mode="import", derivation=None)
    invalid_imports.append(pure_import_with_count)
    for provenance_import in invalid_imports:
        assert not import_validator.is_valid(provenance_import), provenance_import

    rules = import_schema["x-defenseclaw-provenance-import-rules"]
    assert rules == schema["x-defenseclaw-provenance-import-rules"]
    assert rules == catalog["structural_contract"]["provenance_import_rules"]
    assert import_schema["x-defenseclaw-exact-validation-owner"] == ("internal/observability.ImportProvenance.Validate")
    assert import_schema["x-defenseclaw-json-schema-runtime-only"] == [
        "valid_utf8",
        "utf8_byte_length",
    ]
    assert import_schema["additionalProperties"] is False
    assert set(import_schema["properties"]) == {
        "protocol",
        "binding_id",
        "mode",
        "derivation",
        "source_aggregate_count",
        "authenticated_source",
        "upstream_instance_id",
        "upstream_record_id",
        "upstream_service_name",
        "upstream_redaction_profile",
        "ingress_hop_count",
        "last_hop_instance_id",
        "last_hop_destination",
    }
    assert import_schema["properties"]["binding_id"]["maxLength"] == 512
    assert import_schema["properties"]["upstream_redaction_profile"]["maxLength"] == 128
    assert catalog["structural_contract"]["provenance_import"]["id"] == "provenance_import"


def test_custom_resource_schema_and_semantic_contract_are_exact(
    generator: ModuleType,
    artifacts: Mapping[str, Any],
) -> None:
    schema = _json(artifacts, "telemetry.schema.json")
    validator = jsonschema.Draft202012Validator(schema)
    base = _json(
        artifacts,
        "examples/valid/valid-model-chat-with-honest-missing-content-and-usage.json",
    )["record"]
    valid = json.loads(json.dumps(base))
    valid["body"]["resource"]["attributes"]["operator.profile"] = "soc"
    valid["field_classes"]["/resource/attributes/operator.profile"] = "metadata"
    assert validator.is_valid(valid)

    for rejected_key in (
        "service_name",
        "deployment_mode",
        "discovery_source",
        "operator.profile.file",
        "operator.token.kind",
    ):
        rejected = json.loads(json.dumps(valid))
        rejected["body"]["resource"]["attributes"].pop("operator.profile")
        rejected["field_classes"].pop("/resource/attributes/operator.profile")
        rejected["body"]["resource"]["attributes"][rejected_key] = "opaque"
        rejected["field_classes"][f"/resource/attributes/{rejected_key}"] = "metadata"
        assert not validator.is_valid(rejected), rejected_key

    ir = generator.compile_registry(ROOT)
    groups = {group.id: group for domain in ir.domains for group in domain.groups}
    local = {attribute.id: attribute for domain in ir.domains for attribute in domain.attributes}
    extensions = {extension.ref: extension for domain in ir.domains for extension in domain.attribute_extensions}
    upstream = {
        attribute.id: (dependency.id, attribute)
        for dependency in ir.dependencies
        for attribute in dependency.snapshot.attributes
    }
    resource = groups["resource.core"]
    base_values = dict(base["body"]["resource"]["attributes"])

    def semantic_errors(extra: Mapping[str, Any]) -> tuple[str, ...]:
        collector = generator._ExampleErrorCollector([])
        generator._resource_dynamic_fields(
            {**base_values, **extra},
            resource,
            local_attributes=local,
            upstream_extensions=extensions,
            upstream_attributes=upstream,
            errors=collector,
        )
        return collector.result()

    assert semantic_errors({"operator.profile": "soc"}) == ()
    assert semantic_errors({"profile.kind": "soc"}) == ()  # segment matching is not substring matching
    for extra, expected in (
        ({"service_name": "other"}, "resource_attribute_not_registered"),
        ({"deployment_mode": "edge"}, "resource_attribute_not_registered"),
        ({"discovery_source": "runtime"}, "resource_attribute_not_registered"),
        ({"operator.profile.file": "opaque"}, "resource_attribute_not_registered"),
        ({"operator.profile": "/private/location"}, "dynamic_attribute_value_invalid"),
        ({"operator.profile": "  /private/location  "}, "dynamic_attribute_value_invalid"),
        ({"operator.profile": "  Bearer opaque  "}, "dynamic_attribute_value_invalid"),
        ({"operator.profile": "\u2003Basic opaque\u2003"}, "dynamic_attribute_value_invalid"),
        ({"operator.profile": 7}, "dynamic_attribute_value_invalid"),
        (
            {"operator.profile-name": "one", "operator.profile.name": "two"},
            "resource_attribute_not_registered",
        ),
    ):
        assert semantic_errors(extra) == (expected,)
    aggregate = {f"operator.profile{index}": "x" * 1000 for index in range(17)}
    assert semantic_errors(aggregate) == ("dynamic_attribute_value_invalid",)


def test_canonical_json_is_a_closed_recursive_non_null_union(
    renderer: ModuleType,
    artifacts: Mapping[str, Any],
) -> None:
    schema = _json(artifacts, "telemetry.schema.json")
    canonical = schema["$defs"][renderer.CANONICAL_JSON_DEFINITION]
    validator = _subschema_validator(schema, canonical)

    assert canonical["x-defenseclaw-null-policy"] == "reject"
    assert schema["x-defenseclaw-canonical-to-otlp"]["null_value_policy"] == "reject"
    for value in (False, True, -1, 1.5, "value", [], {}, ["nested", {"value": 1}]):
        assert validator.is_valid(value), value
    for value in (None, [None], {"value": None}, [1, {"nested": [None]}]):
        assert not validator.is_valid(value), value

    contexts = (
        canonical,
        schema["$defs"]["structural:envelope"]["properties"]["body"],
        schema["$defs"]["structural:trace_body"]["properties"]["attributes"],
    )
    for context in contexts:
        context_validator = _subschema_validator(schema, context)
        assert context_validator.is_valid(-(2**63))
        assert context_validator.is_valid(2**63 - 1)
        assert context_validator.is_valid(0.5)
        assert context_validator.is_valid(1e20)
    assert not renderer._runtime_numeric_arm_accepts(-(2**63) - 1, "int64")
    assert not renderer._runtime_numeric_arm_accepts(2**63, "int64")
    assert renderer._runtime_numeric_arm_accepts(1e20, "finite_double")


def test_structured_catalog_is_closed_immutable_and_published(
    renderer: ModuleType,
    view: Any,
    artifacts: Mapping[str, Any],
) -> None:
    index = renderer.build_candidate_render_index(view)
    schema = _json(artifacts, "telemetry.schema.json")
    catalog = _json(artifacts, "catalog.json")

    assert tuple(index.structured_types) == renderer._STRUCTURED_TYPE_IDS
    assert len(schema["x-defenseclaw-structured-types"]) == len(index.structured_types)
    assert len(schema["x-defenseclaw-structured-bindings"]) == len(index.structured_bindings)
    assert len(schema["x-defenseclaw-structured-property-dispositions"]) == len(
        index.structured_property_dispositions
    )
    assert catalog["structured_types"] == schema["x-defenseclaw-structured-types"]
    assert catalog["structured_bindings"] == schema["x-defenseclaw-structured-bindings"]
    assert catalog["structured_property_dispositions"] == schema["x-defenseclaw-structured-property-dispositions"]
    assert all(f"structured:{type_id}" in schema["$defs"] for type_id in index.structured_types)
    assert "$type" not in json.dumps(catalog["structured_types"])
    assert "map[string]any" not in json.dumps(catalog["structured_types"])
    with pytest.raises(TypeError):
        index.structured_types["new"] = index.structured_types["gen_ai.text_part"]  # type: ignore[index]
    with pytest.raises(TypeError):
        index.structured_types["gen_ai.text_part"]["kind"] = "array"  # type: ignore[index]


def test_structured_schema_preserves_open_extras_tags_known_values_and_bounds(
    renderer: ModuleType,
    artifacts: Mapping[str, Any],
) -> None:
    schema = _json(artifacts, "telemetry.schema.json")
    definitions = schema["$defs"]
    input_messages = _subschema_validator(schema, definitions["structured:gen_ai.input_messages"])

    valid = [
        {
            "role": "provider.custom-role",
            "parts": [
                {"type": "text", "content": "hello", "provider_extra": {"nested": [1, "two"]}},
                {"type": "provider.custom-part", "opaque": {"ok": True}},
            ],
            "provider_message_extra": "kept",
        }
    ]
    assert input_messages.is_valid(valid)
    assert not input_messages.is_valid([{"role": "user", "parts": [{"type": "text", "content": None}]}])
    assert not input_messages.is_valid(
        [{"role": "user", "parts": [{"type": "text", "content": "x", "type_extra": None}]}]
    )
    assert not input_messages.is_valid([{"role": "user", "parts": [{"type": "text", "opaque": 1}]}])

    chat = definitions["structured:gen_ai.chat_message"]
    chat_validator = _subschema_validator(schema, chat)
    dynamic_256 = {f"extra_{index}": index for index in range(256)}
    assert chat_validator.is_valid({"role": "user", "parts": [], **dynamic_256})
    assert chat_validator.is_valid({"role": "user", "parts": [], "name": "Alice", **dynamic_256})
    assert not chat_validator.is_valid({"role": "user", "parts": [], **dynamic_256, "overflow": 1})
    assert chat["x-defenseclaw-max-dynamic-members"] == 256

    for definition_name, fixed in (
        ("structured:gen_ai.text_part", {"content": "hello"}),
        ("structured:gen_ai.generic_part", {}),
    ):
        validator = _subschema_validator(schema, definitions[definition_name])
        assert validator.is_valid({**fixed, **dynamic_256})
        assert not validator.is_valid({**fixed, **dynamic_256, "overflow": 1})
        assert validator.is_valid({**fixed, "type": "provider.part", **dynamic_256})
        assert not validator.is_valid({**fixed, "type": "provider.part", **dynamic_256, "overflow": 1})

    role = chat["properties"]["role"]
    assert role["x-defenseclaw-known-values"] == ["system", "user", "assistant", "tool"]
    assert role["x-defenseclaw-known-values-enforcement"] == "non-enforcing"
    assert "enum" not in role
    assert chat["properties"]["name"]["x-defenseclaw-sensitivity"] == "sensitive"
    assert chat["properties"]["name"]["x-defenseclaw-max-utf8-bytes"] == 512
    uri = definitions["structured:gen_ai.uri_part"]["properties"]["uri"]
    assert uri["x-defenseclaw-field-class"] == "path"
    assert uri["x-defenseclaw-sensitivity"] == "sensitive"
    assert uri["x-defenseclaw-max-utf8-bytes"] == 8192
    blob_content = definitions["structured:gen_ai.blob_part"]["properties"]["content"]
    assert blob_content["contentEncoding"] == "base64"
    assert blob_content["x-defenseclaw-upstream-format"] == "binary"
    assert blob_content["x-defenseclaw-encoding-annotation"] == "json-base64-bytes-v1"

    union = definitions["structured:gen_ai.message_part"]
    assert union["x-defenseclaw-discriminator"] == {
        "name": "type",
        "owner": "tagged_union",
        "serialized_once": True,
        "field_class": "identifier",
        "sensitivity": "internal",
        "normalization": {
            "effective_constraints": {"max_items": 256, "max_item_utf8_bytes": 4096, "max_utf8_bytes": 256},
            "id": "bounded-v1",
            "notes": None,
            "overrides": {"max_utf8_bytes": 256},
        },
    }
    assert definitions["structured:gen_ai.generic_part"]["x-defenseclaw-reserved-names"] == ["type"]

    canonical = definitions["structured:gen_ai.canonical_json"]
    assert canonical["x-defenseclaw-limits"] == renderer._CANONICAL_JSON_LIMITS
    assert canonical["x-defenseclaw-null-policy"] == "reject"
    assert canonical["oneOf"][4]["maxProperties"] == 256
    assert canonical["oneOf"][4]["x-defenseclaw-duplicate-name-policy"] == "reject"
    assert canonical["oneOf"][4]["x-defenseclaw-post-redaction-name-collision-policy"] == "reject"


def test_metric_number_schema_declares_runtime_typed_int64_and_finite_double_arms(renderer: ModuleType) -> None:
    schema = renderer._schema_type("metric_number")
    validator = jsonschema.Draft202012Validator(schema)

    assert validator.is_valid(-(2**63))
    assert validator.is_valid(2**63 - 1)
    assert validator.is_valid(1.5)
    assert validator.is_valid(1e20)
    assert schema["anyOf"][1]["x-defenseclaw-finite"] is True
    assert schema["x-defenseclaw-numeric-kind-runtime"] == "typed-int64-or-finite-double"
    assert renderer._runtime_numeric_arm_accepts(-(2**63), "int64")
    assert renderer._runtime_numeric_arm_accepts(2**63 - 1, "int64")
    assert not renderer._runtime_numeric_arm_accepts(-(2**63) - 1, "int64")
    assert not renderer._runtime_numeric_arm_accepts(2**63, "int64")
    assert renderer._runtime_numeric_arm_accepts(1e20, "finite_double")
    assert not renderer._runtime_numeric_arm_accepts(float("inf"), "finite_double")
    int64_family = jsonschema.Draft202012Validator(renderer._schema_type("int64"))
    assert int64_family.is_valid(-(2**63))
    assert int64_family.is_valid(2**63 - 1)
    assert not int64_family.is_valid(-(2**63) - 1)
    assert not int64_family.is_valid(2**63)
    with pytest.raises(ValueError, match="Out of range float values"):
        renderer._json_payload({"value": float("inf")})


def test_array_value_constraints_apply_to_each_element(renderer: ModuleType) -> None:
    strings = renderer._apply_constraints(
        renderer._schema_type("string[]"),
        {"enum": ["abc123"], "pattern": "abc[0-9]+"},
    )
    string_validator = jsonschema.Draft202012Validator(strings)

    assert strings["items"]["enum"] == ["abc123"]
    assert strings["items"]["pattern"] == r"^(?:abc[0-9]+)$(?![\s\S])"
    assert strings["items"]["x-defenseclaw-pattern-source"] == "abc[0-9]+"
    assert strings["items"]["x-defenseclaw-pattern-semantics"] == "portable-re2-full-match"
    assert string_validator.is_valid(["abc123"])
    assert not string_validator.is_valid(["prefix-abc123"])
    assert not string_validator.is_valid(["abc123-suffix"])
    assert not string_validator.is_valid(["abc123\n"])
    assert not string_validator.is_valid(["other"])

    numbers = renderer._apply_constraints(renderer._schema_type("int64[]"), {"min": 2, "max": 3})
    number_validator = jsonschema.Draft202012Validator(numbers)
    assert numbers["items"]["minimum"] == 2
    assert numbers["items"]["maximum"] == 3
    assert number_validator.is_valid([2, 3])
    assert not number_validator.is_valid([1, 2])
    assert not number_validator.is_valid([3, 4])


def test_full_match_constraints_cover_scalar_and_array_union_variants(renderer: ModuleType) -> None:
    schema = renderer._apply_constraints(
        {"oneOf": [renderer._schema_type("string"), renderer._schema_type("string[]")]},
        {"enum": ["abc123"], "pattern": "abc123"},
    )
    validator = jsonschema.Draft202012Validator(schema)

    assert validator.is_valid("abc123")
    assert validator.is_valid(["abc123"])
    assert not validator.is_valid("prefix-abc123")
    assert not validator.is_valid(["abc123-suffix"])
    assert not validator.is_valid("abc123\n")
    assert schema["oneOf"][0]["pattern"] == r"^(?:abc123)$(?![\s\S])"
    assert schema["oneOf"][1]["items"]["pattern"] == r"^(?:abc123)$(?![\s\S])"


@pytest.mark.parametrize(
    ("pattern", "accepted"),
    [
        (r"^[0-9a-f]{32}$", True),
        (r"\x61{0,1000}", True),
        (r"a++", False),
        (r"\d+", False),
        (r"\u0061", False),
        (r"\_", False),
        (r"a{,3}", False),
        (r"a{1001}", False),
    ],
)
def test_compiler_and_candidate_portable_pattern_policy_is_identical(
    renderer: ModuleType,
    generator: ModuleType,
    pattern: str,
    accepted: bool,
) -> None:
    if accepted:
        assert generator._validate_portable_pattern(pattern, "test.pattern") == pattern
        renderer._validate_portable_constraint_pattern(pattern, "test.pattern")
    else:
        with pytest.raises(generator.RegistryError):
            generator._validate_portable_pattern(pattern, "test.pattern")
        with pytest.raises(renderer.CandidateRenderError):
            renderer._validate_portable_constraint_pattern(pattern, "test.pattern")


def test_current_registry_patterns_pass_both_portable_validators(
    renderer: ModuleType,
    generator: ModuleType,
    view: Any,
) -> None:
    patterns: set[str] = set()

    def collect(value: Any) -> None:
        if isinstance(value, Mapping):
            if value.get("$type") == "NormalizationIR":
                fields = value["fields"]
                for key in ("overrides", "effective_constraints"):
                    pattern = fields[key].get("pattern")
                    if isinstance(pattern, str):
                        patterns.add(pattern)
            for item in value.values():
                collect(item)
        elif isinstance(value, tuple):
            for item in value:
                collect(item)

    collect(view.facts)
    assert patterns
    for pattern in patterns:
        assert generator._validate_portable_pattern(pattern, "registry.pattern") == pattern
        renderer._validate_portable_constraint_pattern(pattern, "registry.pattern")


def test_numeric_enum_declares_typed_runtime_membership_gate(
    renderer: ModuleType,
    generator: ModuleType,
) -> None:
    schema = renderer._apply_constraints(renderer._schema_type("double"), {"enum": [1]})

    assert jsonschema.Draft202012Validator(schema).is_valid(1.0)
    assert generator._constraints_accept(1.0, {"enum": (1,)}) is False
    assert schema["x-defenseclaw-enum-membership-semantics"] == "typed-json-scalar"
    assert schema["x-defenseclaw-enum-enforcement"] == "builder-runtime-typed-json-enum-gate"


def test_attribute_base_and_per_use_constraints_form_a_restrictive_conjunction(
    renderer: ModuleType,
) -> None:
    def attribute(field_type: str, effective: dict[str, Any]) -> Any:
        normalization_id = (
            "numeric-range-v1"
            if field_type in {"int64", "double"}
            else "structured-content-v1"
            if field_type == "object"
            else "bounded-v1"
        )
        return renderer.CandidateAttribute(
            "test.attribute",
            (field_type,),
            None,
            {
                "field_class": "metadata",
                "sensitivity": "internal",
                "owner": "defenseclaw",
                "normalization": {
                    "id": normalization_id,
                    "effective_constraints": effective,
                },
            },
        )

    strings = renderer._attribute_schema(
        attribute(
            "string[]",
            {
                "enum": ["abc123", "abc456"],
                "pattern": "abc[0-9]+",
                "max_items": 10,
                "max_utf8_bytes": 100,
                "max_item_utf8_bytes": 20,
            },
        ),
        {
            "enum": ["abc123"],
            "pattern": "abc[0-9]+",
            "max_items": 3,
            "max_utf8_bytes": 40,
            "max_item_utf8_bytes": 10,
        },
    )
    item = strings["items"]
    assert item["enum"] == ["abc123"]
    assert item["pattern"] == r"^(?:abc[0-9]+)$(?![\s\S])"
    assert "allOf" not in item
    assert strings["maxItems"] == 3
    assert strings["x-defenseclaw-max-items"] == 3
    assert strings["x-defenseclaw-max-utf8-bytes"] == 40
    assert strings["x-defenseclaw-max-item-utf8-bytes"] == 10
    validator = jsonschema.Draft202012Validator(strings)
    assert validator.is_valid(["abc123"])
    assert not validator.is_valid(["abc456"])

    number = renderer._attribute_schema(
        attribute("int64", {"min": 0, "max": 10}),
        {"min": 2, "max": 8},
    )
    assert number["minimum"] == 2
    assert number["maximum"] == 8

    structured = renderer._attribute_schema(
        attribute(
            "object",
            {"max_items": 10, "max_depth": 5, "max_properties": 20},
        ),
        {"max_items": 4, "max_depth": 2, "max_properties": 3},
    )
    assert structured["x-defenseclaw-max-items"] == 4
    assert structured["x-defenseclaw-max-depth"] == 2
    assert structured["x-defenseclaw-max-properties"] == 3
    assert structured["maxProperties"] == 3


def test_candidate_rejects_distinct_pattern_intersection(renderer: ModuleType) -> None:
    base = renderer._apply_constraints(renderer._schema_type("string"), {"pattern": "abc[0-9]+"})

    with pytest.raises(renderer.CandidateRenderError, match="pattern constraint intersection"):
        renderer._apply_constraints(base, {"pattern": "abc123"})


@pytest.mark.parametrize(
    ("field_type", "constraints"),
    [
        ("string", {"max_itmes": 1}),
        ("string", {"max_items": "one"}),
        ("string", {"min": 2, "max": 1}),
        ("int64", {"pattern": "[0-9]+"}),
        ("string", {"min": 1}),
        ("string[]", {"max_depth": 1}),
    ],
)
def test_apply_constraints_defensively_rejects_invalid_maps(
    renderer: ModuleType,
    field_type: str,
    constraints: dict[str, Any],
) -> None:
    with pytest.raises(renderer.CandidateRenderError):
        renderer._apply_constraints(renderer._schema_type(field_type), constraints)


def test_polymorphic_canonical_json_rejects_min_items_above_scalar_cardinality(
    renderer: ModuleType,
) -> None:
    with pytest.raises(renderer.CandidateRenderError, match="polymorphic JSON"):
        renderer._apply_constraints(
            {"$ref": f"#/$defs/{renderer.CANONICAL_JSON_DEFINITION}"},
            {"min_items": 2},
        )


def test_recursive_item_and_utf8_bounds_declare_required_runtime_gates(
    renderer: ModuleType,
    generator: ModuleType,
) -> None:
    nested_value = [{"items": [1, 2, 3]}]
    nested_schema = renderer._apply_constraints(
        {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": {"type": "array", "items": {"type": "integer"}},
            },
        },
        {"max_items": 3},
    )

    # JSON Schema can enforce the safe root-array subset, but the compiler's
    # recursive aggregate counts the root element, object member, and nested elements.
    assert jsonschema.Draft202012Validator(nested_schema).is_valid(nested_value)
    assert generator._constraints_accept(nested_value, {"max_items": 3}) is False
    assert nested_schema["maxItems"] == 3
    assert nested_schema["x-defenseclaw-max-items-semantics"] == "recursive-aggregate-members"
    assert nested_schema["x-defenseclaw-max-items-enforcement"] == ("builder-runtime-recursive-aggregate-gate")
    assert nested_schema["x-defenseclaw-json-schema-item-bound-scope"] == ("root-collection-safe-subset")

    total_bytes = renderer._apply_constraints(renderer._schema_type("string"), {"max_utf8_bytes": 3})
    leaf_bytes = renderer._apply_constraints(renderer._schema_type("string[]"), {"max_item_utf8_bytes": 3})
    assert jsonschema.Draft202012Validator(total_bytes).is_valid("éé")
    assert jsonschema.Draft202012Validator(leaf_bytes).is_valid(["éé"])
    assert generator._constraints_accept("éé", {"max_utf8_bytes": 3}) is False
    assert generator._constraints_accept(["éé"], {"max_item_utf8_bytes": 3}) is False
    assert total_bytes["x-defenseclaw-max-utf8-bytes-semantics"] == "raw-scalar-string-utf8"
    assert total_bytes["x-defenseclaw-max-utf8-bytes-enforcement"] == ("builder-runtime-shape-aware-utf8-byte-gate")
    aggregate_bytes = renderer._apply_constraints(renderer._schema_type("string[]"), {"max_utf8_bytes": 10})
    assert aggregate_bytes["x-defenseclaw-max-utf8-bytes-semantics"] == "canonical-json-utf8"
    assert leaf_bytes["x-defenseclaw-max-item-utf8-bytes-enforcement"] == ("builder-runtime-string-leaf-utf8-byte-gate")

    nested_object = {"outer": {"inner": {"leaf": 1}}}
    object_schema = renderer._apply_constraints(
        {"type": "object", "additionalProperties": True},
        {"max_depth": 1, "max_properties": 1},
    )
    assert jsonschema.Draft202012Validator(object_schema).is_valid(nested_object)
    assert generator._constraints_accept(nested_object, {"max_depth": 1}) is False
    assert generator._constraints_accept(nested_object, {"max_properties": 1}) is False
    assert object_schema["maxProperties"] == 1
    assert object_schema["x-defenseclaw-max-depth-enforcement"] == ("builder-runtime-container-depth-gate")
    assert object_schema["x-defenseclaw-max-properties-enforcement"] == (
        "builder-runtime-recursive-property-count-gate"
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "normalization-unknown",
        "normalization-wrong-type",
        "normalization-scalar-min-items",
        "normalization-bogus-id",
        "normalization-forged-effective",
        "normalizer-catalog-forged",
        "local-attribute-timestamp",
        "direct-use-unknown",
        "direct-origin-mismatch",
        "direct-role-mismatch",
        "attribute-refs-mismatch",
        "resolution-order-mismatch",
        "resolved-use-unknown",
        "origin-wrong-type",
        "origin-resolved-mismatch",
        "typed-enum-origin-mismatch",
        "resolved-numeric-pattern",
        "resolved-string-min",
        "resolved-use-weakening",
        "requirement-origin-mismatch",
        "unknown-condition",
        "empty-condition",
        "resolved-use-nonportable-pattern",
    ],
)
def test_candidate_rejects_digest_consistent_constraint_contract_mutations(
    renderer: ModuleType,
    view: Any,
    mutation: str,
) -> None:
    facts = _copy_materialized(view.facts)
    domains = facts["fields"]["domains"]

    if mutation == "normalizer-catalog-forged":
        facts["fields"]["normalizers"][0]["fields"]["kind"] = "forged"
    elif mutation == "local-attribute-timestamp":
        attribute = next(item for domain in domains for item in domain["fields"]["attributes"])
        attribute["fields"]["field_type"] = "timestamp"
    elif mutation == "resolution-order-mismatch":
        facts["fields"]["group_resolution_order"] = tuple(reversed(facts["fields"]["group_resolution_order"]))
    elif mutation.startswith("normalization-"):
        attribute = next(
            item
            for domain in domains
            for item in domain["fields"]["attributes"]
            if mutation != "normalization-scalar-min-items"
            or (
                item["fields"]["field_type"] == "string"
                and item["fields"]["normalization"]["fields"]["id"] == "bounded-v1"
            )
        )
        normalization = attribute["fields"]["normalization"]["fields"]
        if mutation == "normalization-unknown":
            normalization["effective_constraints"]["max_itmes"] = 1
        elif mutation == "normalization-wrong-type":
            normalization["overrides"]["max_items"] = "one"
        elif mutation == "normalization-scalar-min-items":
            normalization["overrides"]["min_items"] = 2
            normalization["effective_constraints"]["min_items"] = 2
        elif mutation == "normalization-bogus-id":
            normalization["id"] = "bogus-v1"
        else:
            normalization["effective_constraints"]["max_utf8_bytes"] = 1
    elif mutation in {
        "direct-use-unknown",
        "direct-origin-mismatch",
        "direct-role-mismatch",
        "attribute-refs-mismatch",
    }:
        group = next(
            item
            for domain in domains
            for item in domain["fields"]["groups"]
            if (
                item["fields"]["id"] == "scope.core"
                if mutation in {"direct-origin-mismatch", "direct-role-mismatch", "attribute-refs-mismatch"}
                else bool(item["fields"]["attribute_uses"])
            )
        )
        if mutation == "direct-role-mismatch":
            group["fields"]["attribute_uses"][0]["fields"]["role"] = "body_fields"
        elif mutation == "attribute-refs-mismatch":
            group["fields"]["attribute_refs"] = group["fields"]["attribute_refs"][1:]
        else:
            group["fields"]["attribute_uses"][0]["fields"]["constraints"] = (
                {"max_utf8_bytes": 1} if mutation == "direct-origin-mismatch" else {"max_itmes": 1}
            )
    else:
        resolved_by_group = facts["fields"]["resolved_group_uses"]
        target_ref = {
            "resolved-numeric-pattern": "defenseclaw.guardrail.confidence",
            "resolved-string-min": "gen_ai.operation.name",
            "resolved-use-weakening": "gen_ai.operation.name",
        }.get(mutation)
        if target_ref is None:
            group_id = next(iter(resolved_by_group))
            resolved_use = resolved_by_group[group_id][0]
        else:
            group_id, resolved_use = next(
                (candidate_group, use)
                for candidate_group, uses in resolved_by_group.items()
                for use in uses
                if use["fields"]["ref"] == target_ref
            )
        group = next(
            item for domain in domains for item in domain["fields"]["groups"] if item["fields"]["id"] == group_id
        )
        group_use = next(
            use for use in group["fields"]["resolved_uses"] if use["fields"]["ref"] == resolved_use["fields"]["ref"]
        )
        duplicate_uses = (resolved_use, group_use)
        if mutation == "resolved-use-unknown":
            for use in duplicate_uses:
                use["fields"]["constraints"] = {"max_itmes": 1}
                use["fields"]["origins"][0]["fields"]["constraints"] = {"max_itmes": 1}
        elif mutation == "origin-wrong-type":
            for use in duplicate_uses:
                use["fields"]["constraints"] = {"max_items": 1}
                use["fields"]["origins"][0]["fields"]["constraints"] = {"max_items": "one"}
        elif mutation == "origin-resolved-mismatch":
            for use in duplicate_uses:
                use["fields"]["constraints"] = {"max_items": 2}
                use["fields"]["origins"][0]["fields"]["constraints"] = {"max_items": 1}
        elif mutation == "typed-enum-origin-mismatch":
            for use in duplicate_uses:
                use["fields"]["constraints"] = {"enum": (1,)}
                use["fields"]["origins"][0]["fields"]["constraints"] = {"enum": (True,)}
        elif mutation in {"resolved-numeric-pattern", "resolved-string-min", "resolved-use-weakening"}:
            constraints = (
                {"pattern": "[0-9]+"}
                if mutation == "resolved-numeric-pattern"
                else {"min": 1}
                if mutation == "resolved-string-min"
                else {"max_utf8_bytes": 1048576}
            )
            for use in duplicate_uses:
                use["fields"]["constraints"] = constraints
                for origin in use["fields"]["origins"]:
                    origin["fields"]["constraints"] = constraints
                    source_group = next(
                        item
                        for domain in domains
                        for item in domain["fields"]["groups"]
                        if item["fields"]["id"] == origin["fields"]["group_id"]
                    )
                    source_use = next(
                        item
                        for item in source_group["fields"]["attribute_uses"]
                        if item["fields"]["ref"] == resolved_use["fields"]["ref"]
                    )
                    source_use["fields"]["constraints"] = constraints
        elif mutation == "requirement-origin-mismatch":
            replacement = "optional" if resolved_use["fields"]["requirement_level"] == "required" else "required"
            for use in duplicate_uses:
                use["fields"]["requirement_level"] = replacement
                use["fields"]["conditional"] = None
        elif mutation in {"unknown-condition", "empty-condition"}:
            condition = "unknown.condition" if mutation == "unknown-condition" else ""
            for use in duplicate_uses:
                use["fields"]["requirement_level"] = "conditional"
                use["fields"]["conditional"] = condition
                for origin in use["fields"]["origins"]:
                    origin["fields"]["requirement_level"] = "conditional"
                    origin["fields"]["conditional"] = condition
        else:
            for use in duplicate_uses:
                use["fields"]["constraints"] = {"pattern": "a++"}
                use["fields"]["origins"][0]["fields"]["constraints"] = {"pattern": "a++"}

    with pytest.raises(renderer.CandidateRenderError):
        renderer.build_candidate_render_index(_retagged_view(renderer, view, facts))


@pytest.mark.parametrize(
    "mutation",
    [
        "nested-extra",
        "dangling-ref",
        "known-but-wrong-ref",
        "side-arm",
        "reserved-names",
        "canonical-limit",
        "binding-target",
        "missing-disposition",
        "known-values",
        "nullable-omission",
        "union-disposition-target",
        "content-sensitivity",
        "content-normalization",
        "discriminator-name",
        "discriminator-privacy",
        "dynamic-name-privacy",
        "dynamic-name-normalization",
        "canonical-encoding",
        "introduced-in",
        "encoding-annotation",
    ],
)
def test_candidate_rejects_digest_consistent_malformed_nested_structured_facts(
    renderer: ModuleType,
    view: Any,
    mutation: str,
) -> None:
    facts = _copy_materialized(view.facts)
    types = facts["fields"]["structured_types"]
    by_id = {item["fields"]["id"]: item for item in types}
    if mutation == "nested-extra":
        by_id["gen_ai.text_part"]["fields"]["fields"][0]["fields"]["scalar"]["fields"]["extra"] = True
    elif mutation == "dangling-ref":
        by_id["gen_ai.input_messages"]["fields"]["items_reference"]["fields"]["structured_ref"] = "gen_ai.missing"
    elif mutation == "known-but-wrong-ref":
        by_id["gen_ai.input_messages"]["fields"]["items_reference"]["fields"]["structured_ref"] = (
            "gen_ai.output_message"
        )
    elif mutation == "side-arm":
        by_id["gen_ai.input_messages"]["fields"]["fields"] = ()
    elif mutation == "reserved-names":
        by_id["gen_ai.generic_part"]["fields"]["effective_reserved_names"] = ()
    elif mutation == "canonical-limit":
        by_id["gen_ai.canonical_json"]["fields"]["canonical_json"]["fields"]["limits"]["fields"]["max_depth"] = 9
    elif mutation == "binding-target":
        binding = next(
            item
            for item in facts["fields"]["structured_bindings"]
            if item["fields"]["attribute"] == "gen_ai.output.messages"
        )
        binding["fields"]["structured_type"] = "gen_ai.input_messages"
    elif mutation == "missing-disposition":
        facts["fields"]["structured_property_dispositions"] = facts["fields"]["structured_property_dispositions"][:-1]
    elif mutation == "known-values":
        role = next(
            item for item in by_id["gen_ai.chat_message"]["fields"]["fields"] if item["fields"]["name"] == "role"
        )
        role["fields"]["scalar"]["fields"]["known_values"] = ("system", "user")
    elif mutation == "nullable-omission":
        name = next(
            item for item in by_id["gen_ai.chat_message"]["fields"]["fields"] if item["fields"]["name"] == "name"
        )
        name["fields"]["nullable_omission"] = False
    elif mutation == "union-disposition-target":
        disposition = next(
            item
            for item in facts["fields"]["structured_property_dispositions"]
            if item["fields"]["structured_type"] == "gen_ai.message_part" and item["fields"]["arm_id"] == "text"
        )
        disposition["fields"]["target_structured_type"] = "gen_ai.output_message"
    elif mutation == "content-sensitivity":
        by_id["gen_ai.text_part"]["fields"]["fields"][0]["fields"]["scalar"]["fields"]["sensitivity"] = "safe"
    elif mutation == "content-normalization":
        by_id["gen_ai.text_part"]["fields"]["fields"][0]["fields"]["scalar"]["fields"]["normalization"]["fields"][
            "id"
        ] = "identity-v1"
    elif mutation == "discriminator-name":
        by_id["gen_ai.message_part"]["fields"]["discriminator"]["fields"]["name"] = "kind"
    elif mutation == "discriminator-privacy":
        by_id["gen_ai.message_part"]["fields"]["discriminator"]["fields"]["sensitivity"] = "safe"
    elif mutation == "dynamic-name-privacy":
        by_id["gen_ai.tool_call_arguments"]["fields"]["dynamic_members"]["fields"]["name"]["fields"]["sensitivity"] = (
            "safe"
        )
    elif mutation == "dynamic-name-normalization":
        by_id["gen_ai.tool_call_arguments"]["fields"]["dynamic_members"]["fields"]["name"]["fields"]["normalization"][
            "fields"
        ]["id"] = "identifier-v1"
    elif mutation == "canonical-encoding":
        canonical = by_id["gen_ai.canonical_json"]["fields"]["canonical_json"]["fields"]
        canonical["public_encoding"] = "native_object"
        canonical["wire_encoding"] = "ordered_entries"
    elif mutation == "encoding-annotation":
        blob_content = next(
            item for item in by_id["gen_ai.blob_part"]["fields"]["fields"] if item["fields"]["name"] == "content"
        )
        blob_content["fields"]["scalar"]["fields"]["encoding_annotation"] = None
    else:
        by_id["gen_ai.text_part"]["fields"]["introduced_in"] = "telemetry-registry-v2"

    with pytest.raises(renderer.CandidateRenderError):
        renderer.build_candidate_render_index(_retagged_view(renderer, view, facts))


@pytest.mark.parametrize(
    "mutation",
    [
        "envelope-open",
        "field-privacy",
        "field-type",
        "field-required",
        "signal-arm-target",
        "relation",
        "derivation",
        "otlp-mapping",
    ],
)
def test_candidate_rejects_digest_consistent_structural_contract_retargeting(
    renderer: ModuleType,
    view: Any,
    mutation: str,
) -> None:
    facts = _copy_materialized(view.facts)
    contract = facts["fields"]["structural_contract"]["fields"]
    envelope = contract["envelope"]["fields"]
    first_field = envelope["fields"][0]["fields"]
    if mutation == "envelope-open":
        envelope["additional_properties"] = True
    elif mutation == "field-privacy":
        first_field["sensitivity"] = "critical"
    elif mutation == "field-type":
        first_field["field_type"] = "string"
    elif mutation == "field-required":
        first_field["required"] = False
    elif mutation == "signal-arm-target":
        contract["signal_arms"][0]["fields"]["payload_field"] = "instrument_data"
    elif mutation == "relation":
        contract["trace_relations"][0]["fields"]["right"] = "start_time_unix_nano"
    elif mutation == "derivation":
        contract["trace_derivations"][0]["fields"]["target_attribute"] = "defenseclaw.source"
    else:
        contract["canonical_to_otlp"]["fields"]["json_mapping"] = "retargeted-json-mapping"

    with pytest.raises(renderer.CandidateRenderError, match="structural contract is not canonical"):
        renderer.build_candidate_render_index(_retagged_view(renderer, view, facts))


def test_candidate_semantic_digests_ignore_only_tagged_normalization_notes(
    renderer: ModuleType,
    view: Any,
) -> None:
    facts = _copy_materialized(view.facts)
    structured = {item["fields"]["id"]: item for item in facts["fields"]["structured_types"]}
    structured_note = structured["gen_ai.text_part"]["fields"]["fields"][0]["fields"]["scalar"]["fields"][
        "normalization"
    ]["fields"]
    structural_note = facts["fields"]["structural_contract"]["fields"]["envelope"]["fields"]["fields"][0]["fields"][
        "normalization"
    ]["fields"]
    structured_note["notes"] = "Structured reviewer prose."
    structural_note["notes"] = "P-069 reviewer prose."

    index = renderer.build_candidate_render_index(_retagged_view(renderer, view, facts))

    assert index.structured_types["gen_ai.text_part"]["fields"][0]["scalar"]["normalization"]["notes"] == (
        "Structured reviewer prose."
    )
    assert (
        index.fields["structural_contract"]["fields"]["envelope"]["fields"]["fields"][0]["fields"]["normalization"][
            "fields"
        ]["notes"]
        == "P-069 reviewer prose."
    )


@pytest.mark.parametrize("surface", ["structured", "structural"])
@pytest.mark.parametrize("invalid_notes", [{"not": "prose"}, "x" * 4097])
def test_candidate_rejects_invalid_normalization_notes_even_when_semantically_ignored(
    renderer: ModuleType,
    view: Any,
    surface: str,
    invalid_notes: Any,
) -> None:
    facts = _copy_materialized(view.facts)
    if surface == "structured":
        structured = {item["fields"]["id"]: item for item in facts["fields"]["structured_types"]}
        notes = structured["gen_ai.text_part"]["fields"]["fields"][0]["fields"]["scalar"]["fields"]["normalization"][
            "fields"
        ]
    else:
        notes = facts["fields"]["structural_contract"]["fields"]["envelope"]["fields"]["fields"][0]["fields"][
            "normalization"
        ]["fields"]
    notes["notes"] = invalid_notes

    with pytest.raises(renderer.CandidateRenderError, match="normalization notes are invalid"):
        renderer.build_candidate_render_index(_retagged_view(renderer, view, facts))


@pytest.mark.parametrize(
    ("definition_name", "property_name", "expected_ref"),
    [
        pytest.param("structural:envelope", "body", "value:canonical_json", id="envelope-body"),
        pytest.param("structural:trace_body", "attributes", "value:canonical_json", id="trace-attributes"),
        pytest.param("structural:trace_resource", "attributes", "value:canonical_json", id="resource-attributes"),
        pytest.param("structural:trace_scope", "attributes", "value:canonical_json", id="scope-attributes"),
        pytest.param("structural:trace_event", "attributes", "value:canonical_json", id="event-attributes"),
        pytest.param("structural:trace_link", "attributes", "value:canonical_json", id="link-attributes"),
        pytest.param(
            "structural:metric_instrument_data",
            "attributes",
            "value:canonical_json",
            id="metric-attributes",
        ),
        pytest.param(
            "attribute:gen_ai.input.messages",
            None,
            "structured:gen_ai.input_messages",
            id="genai-input-messages",
        ),
        pytest.param(
            "attribute:gen_ai.output.messages",
            None,
            "structured:gen_ai.output_messages",
            id="genai-output-messages",
        ),
        pytest.param(
            "attribute:gen_ai.tool.call.arguments",
            None,
            "structured:gen_ai.tool_call_arguments",
            id="genai-tool-arguments",
        ),
        pytest.param(
            "attribute:gen_ai.tool.call.result",
            None,
            "structured:gen_ai.tool_call_result",
            id="genai-tool-result",
        ),
    ],
)
def test_every_canonical_json_context_rejects_direct_null(
    renderer: ModuleType,
    artifacts: Mapping[str, Any],
    definition_name: str,
    property_name: str | None,
    expected_ref: str,
) -> None:
    schema = _json(artifacts, "telemetry.schema.json")
    definition = schema["$defs"][definition_name]
    subject = definition if property_name is None else definition["properties"][property_name]

    assert subject["$ref"] == f"#/$defs/{expected_ref}"
    assert not _subschema_validator(schema, subject).is_valid(None)


@pytest.mark.parametrize("family_id", ["span.ai.discovery", "span.ai.discovery.detector"])
def test_eventless_ai_discovery_spans_require_events_to_be_absent(
    artifacts: Mapping[str, Any],
    family_id: str,
) -> None:
    schema = _json(artifacts, "telemetry.schema.json")
    record = _span_record_for_family(artifacts, schema, family_id)
    validator = _subschema_validator(schema, schema["$defs"][f"family:{family_id}"])

    assert "events" not in record["body"]
    assert validator.is_valid(record)


@pytest.mark.parametrize(
    ("family_id", "events"),
    [
        pytest.param("span.ai.discovery", [], id="discovery-empty"),
        pytest.param(
            "span.ai.discovery",
            [{"name": "arbitrary", "time_unix_nano": 1, "attributes": {}}],
            id="discovery-arbitrary",
        ),
        pytest.param("span.ai.discovery.detector", [], id="detector-empty"),
        pytest.param(
            "span.ai.discovery.detector",
            [{"name": "arbitrary", "time_unix_nano": 1, "attributes": {}}],
            id="detector-arbitrary",
        ),
    ],
)
def test_eventless_ai_discovery_spans_reject_empty_and_arbitrary_events(
    artifacts: Mapping[str, Any],
    family_id: str,
    events: list[dict[str, Any]],
) -> None:
    schema = _json(artifacts, "telemetry.schema.json")
    record = _span_record_for_family(artifacts, schema, family_id)
    record["body"]["events"] = events
    validator = _subschema_validator(schema, schema["$defs"][f"family:{family_id}"])

    assert not validator.is_valid(record)


def test_catalog_contains_portable_family_privacy_condition_lifecycle_and_compatibility_metadata(
    artifacts: Mapping[str, Any],
) -> None:
    catalog = _json(artifacts, "catalog.json")
    assert catalog["format"] == "defenseclaw-telemetry-catalog-v1"
    assert catalog["families"]
    assert catalog["attributes"]
    assert len({item["id"] for item in catalog["families"]}) == len(catalog["families"])
    assert {item["signal"] for item in catalog["families"]} == {"logs", "traces", "metrics"}
    assert {item["id"] for item in catalog["compatibility_manifests"]} == {
        "galileo-rich-v2",
        "local-observability-v1",
        "openinference-v1",
    }

    families = {item["id"]: item for item in catalog["families"]}
    model = families["span.model.chat"]
    assert model["signal"] == "traces"
    assert model["bucket"] == "model.io"
    assert model["span"]["name_pattern"] == "chat {gen_ai.request.model}"
    assert model["outcome"]["requirement"] == "required"
    assert model["lifecycle"] == {
        "introduced_in": "telemetry-registry-v1",
        "deprecated_in": None,
        "removed_in": None,
    }
    assert {item["id"] for item in model["compatibility_profiles"]} == {
        "galileo-rich-v2",
        "local-observability-v1",
        "openinference-v1",
    }
    fields = {item["ref"]: item for item in model["fields"]}
    assert fields["gen_ai.input.messages"]["field_class"] == "content"
    assert fields["gen_ai.input.messages"]["sensitivity"] == "sensitive"
    assert fields["defenseclaw.connector.source"]["condition"] == "connector-known-v1"

    finding = families["log.finding.observed"]
    finding_fields = {item["ref"]: item for item in finding["fields"]}
    assert finding_fields["defenseclaw.guardrail.evidence_summary"]["field_class"] == "evidence"
    assert finding_fields["defenseclaw.finding.remediation"]["field_class"] == "reason"

    metric = families["metric.defenseclaw.connector.hook.latency"]
    assert metric["metric"] == {
        "instrument_name": "defenseclaw.connector.hook.latency",
        "instrument_type": "histogram",
        "value_type": "double",
        "unit": "ms",
        "temporality": "delta",
        "boundaries": [1, 2, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000],
        "cardinality_limit": 2048,
    }

    portable_text = json.dumps(catalog, sort_keys=True)
    for forbidden in ("dashboard_uid", "datasource_uid", "loki_query", "tempo_query", "normalized_prometheus"):
        assert forbidden not in portable_text
    assert all(
        item["availability"] == "available"
        and item["path"] == f"compatibility/{item['id']}.json"
        and re.fullmatch(r"[0-9a-f]{64}", item["sha256"])
        for item in catalog["compatibility_manifests"]
    )
    assert all(
        item["availability"] == "available"
        and item["manifest"] == f"compatibility/{item['id']}.json"
        and re.fullmatch(r"[0-9a-f]{64}", item["manifest_sha256"])
        for family in catalog["families"]
        for item in family["compatibility_profiles"]
    )


def test_generated_compatibility_profiles_are_digest_bound_exact_and_explicit(
    artifacts: Mapping[str, Any],
) -> None:
    catalog = _json(artifacts, "catalog.json")
    manifests = {item["id"]: item for item in catalog["compatibility_manifests"]}
    documents: dict[str, dict[str, Any]] = {}
    for profile_id, metadata in manifests.items():
        artifact = artifacts[f"{PREFIX}/{metadata['path']}"]
        assert hashlib.sha256(artifact.payload).hexdigest() == metadata["sha256"]
        document = json.loads(artifact.payload)
        documents[profile_id] = document
        assert document["format"] == "defenseclaw-compatibility-profile-v1"
        assert document["profile_id"] == profile_id
        assert document["availability"] == metadata["availability"]
        assert document["materialized_view_sha256"] == catalog["materialized_view_sha256"]
        assert [(item["signal"], item["family_id"]) for item in document["families"]] == sorted(
            (item["signal"], item["family_id"]) for item in document["families"]
        )

    galileo = documents["galileo-rich-v2"]
    assert galileo["runtime_projection"]["status"] == "available"
    galileo_families = {item["family_id"]: item["projection"]["shape"] for item in galileo["families"]}
    assert galileo_families == {
        "span.agent.invoke": "agent",
        "span.guardrail.judge": "llm",
        "span.model.chat": "llm",
        "span.retrieval.search": "retriever",
        "span.tool.execute": "tool",
        "span.workflow.run": "workflow",
    }
    assert {"span.agent.transition", "span.approval.resolve"}.isdisjoint(galileo_families)

    local = documents["local-observability-v1"]
    assert local["runtime_projection"]["status"] == "available"
    assert local["runtime_projection"]["alias_conflict_behavior"] == "reject"
    expected_local_families = [
        item
        for item in catalog["families"]
        if any(profile["id"] == "local-observability-v1" for profile in item["compatibility_profiles"])
    ]
    assert Counter(item["signal"] for item in local["families"]) == Counter(
        item["signal"] for item in expected_local_families
    )
    assert {item["family_id"] for item in local["families"]} == {
        item["id"] for item in expected_local_families
    }
    assert all(
        item["projection"]["mode"]
        == {"logs": "canonical_otlp_log_v1", "metrics": "otel_sdk_metric_v1", "traces": "local_trace_aliases_v1"}[
            item["signal"]
        ]
        for item in local["families"]
    )
    catalog_families = {item["id"]: item for item in catalog["families"]}
    local_metrics = [item for item in local["families"] if item["signal"] == "metrics"]
    assert len(local_metrics) == sum(item["signal"] == "metrics" for item in expected_local_families)
    for family in local_metrics:
        projection = family["projection"]
        metric = catalog_families[family["family_id"]]["metric"]
        assert {
            "instrument_type": projection["instrument_type"],
            "value_type": projection["value_type"],
            "unit": projection["unit"],
            "temporality": projection["temporality"],
            "boundaries": projection["boundaries"],
            "cardinality_limit": projection["cardinality_limit"],
        } == {
            "instrument_type": metric["instrument_type"],
            "value_type": metric["value_type"],
            "unit": metric["unit"],
            "temporality": metric["temporality"],
            "boundaries": metric["boundaries"],
            "cardinality_limit": metric["cardinality_limit"],
        }
        assert projection["cardinality_limit"] == 2048

    openinference = documents["openinference-v1"]
    assert openinference["runtime_projection"] == {
        "alias_conflict_behavior": "reject",
        "input": "route_redacted_canonical_record",
        "mode": "destination_owned_openinference_alias_projection",
        "status": "available",
        "unsupported_behavior": "reject",
    }
    assert len(openinference["families"]) == 7
    assert {item["family_id"]: item["projection"]["openinference_span_kind"] for item in openinference["families"]} == {
        "span.agent.invoke": "AGENT",
        "span.guardrail.judge": "LLM",
        "span.model.chat": "LLM",
        "span.model.embeddings": "EMBEDDING",
        "span.retrieval.search": "RETRIEVER",
        "span.tool.execute": "TOOL",
        "span.workflow.run": "CHAIN",
    }
    assert all(
        item["projection"]["mode"] == "openinference_trace_aliases_v1"
        and item["projection"]["input_mime_type"] == "application/json"
        and item["projection"]["output_mime_type"] == "application/json"
        and item["projection"]["allowed_span_kinds"]
        for item in openinference["families"]
    )


def test_normalized_example_and_otlp_manifests_cover_the_same_cases(
    view: Any,
    artifacts: Mapping[str, Any],
) -> None:
    examples = _json(artifacts, "examples/manifest.json")
    fixtures = _json(artifacts, "otlp-fixtures/manifest.json")
    assert examples["format"] == "defenseclaw-normalized-examples-v1"
    assert fixtures["format"] == "defenseclaw-otlp-fixture-manifest-v1"
    assert examples["materialized_view_sha256"] == view.typed_canonical_json_sha256
    assert fixtures["materialized_view_sha256"] == view.typed_canonical_json_sha256
    assert examples["conformance"]["scope"] == "canonical-schema-comparison-only"
    assert fixtures["conformance"]["builder_parity"] == "pending-source-inputs"
    assert [item["id"] for item in examples["cases"]] == [item["id"] for item in fixtures["cases"]]
    assert len(examples["cases"]) == 13
    assert fixtures["canonical_to_otlp"]["json_mapping"] == "opentelemetry_proto_json_v1"
    assert "$type" not in json.dumps(fixtures["canonical_to_otlp"])

    for entry in examples["cases"]:
        expected_parent = PurePosixPath("examples/valid" if entry["valid"] else "examples/invalid")
        assert PurePosixPath(entry["path"]).parent == expected_parent
        normalized = _json(artifacts, entry["path"])
        fixture = _json(artifacts, f"otlp-fixtures/cases/{entry['id']}.json")
        assert normalized["record"] == fixture["canonical_record"]
        assert normalized["valid"] == fixture["expect"]["accepted"]
        if not normalized["valid"]:
            assert fixture["expect"]["error_code"] == normalized["expected_error"]
    for entry in fixtures["cases"]:
        assert PurePosixPath(entry["path"]).parent == PurePosixPath("otlp-fixtures/cases")


def test_otlp_fixtures_render_direct_trace_projected_log_and_sdk_metric(
    artifacts: Mapping[str, Any],
) -> None:
    trace = _json(artifacts, "otlp-fixtures/cases/valid-model-chat-with-honest-missing-content-and-usage.json")
    trace_projection = trace["expect"]["projection"]
    assert trace_projection["mode"] == "direct_span"
    resource_spans = trace_projection["request"]["resourceSpans"][0]
    span = resource_spans["scopeSpans"][0]["spans"][0]
    assert span["traceId"] == base64.b64encode(
        bytes.fromhex(trace["canonical_record"]["correlation"]["trace_id"])
    ).decode("ascii")
    assert span["spanId"] == base64.b64encode(
        bytes.fromhex(trace["canonical_record"]["correlation"]["span_id"])
    ).decode("ascii")
    assert span["kind"] == 3
    assert span["startTimeUnixNano"] == "1783080000000000000"
    assert span["status"] == {"code": 1}
    assert resource_spans["schemaUrl"] == "https://opentelemetry.io/schemas/1.42.0"

    log = _json(artifacts, "otlp-fixtures/cases/valid-security-finding-with-derived-evidence.json")
    log_projection = log["expect"]["projection"]
    assert log_projection["mode"] == "projected_record_json_string"
    assert log_projection["request_root"] == "resourceLogs"
    assert json.loads(log_projection["projected_record_json"]) == log["canonical_record"]

    metric = _json(artifacts, "otlp-fixtures/cases/valid-hook-latency-metric.json")
    metric_projection = metric["expect"]["projection"]
    assert metric_projection["mode"] == "sdk_aggregation_required"
    assert metric_projection["request_root"] == "resourceMetrics"
    assert metric_projection["instrument"]["name"] == "defenseclaw.connector.hook.latency"
    assert metric_projection["instrument"]["value"] == 17.5


def test_catalog_markdown_is_searchable_and_uses_portable_names_first(artifacts: Mapping[str, Any]) -> None:
    markdown = artifacts[f"{PREFIX}/catalog.md"].payload.decode("utf-8")
    assert "# DefenseClaw Portable Telemetry Catalog (Candidate)" in markdown
    assert "## Namespace decision" in markdown
    assert "## Trace tree examples" in markdown
    assert "## Backend compatibility" in markdown
    assert "## Families" in markdown
    assert "## Redaction" in markdown
    assert "## Conformance scope" in markdown
    assert "builder facts and deterministic occurrence inputs" in markdown
    assert "`span.model.chat`" in markdown
    assert "`metric.defenseclaw.connector.hook.latency`" in markdown
    assert markdown.index("`gen_ai.operation.name`") < markdown.index("`defenseclaw.bucket`")


def test_renderer_rejects_non_view_stale_digest_and_incomplete_facts(
    renderer: ModuleType,
    generator: ModuleType,
    view: Any,
) -> None:
    ir = generator.compile_registry(ROOT)
    with pytest.raises(renderer.CandidateRenderError, match="requires MaterializedRegistryView"):
        renderer.render_candidate_artifacts(ir)
    with pytest.raises(renderer.CandidateRenderError, match="identity is invalid"):
        renderer.render_candidate_artifacts(dataclasses.replace(view, format="wrong"))
    with pytest.raises(renderer.CandidateRenderError, match="digest does not match"):
        renderer.render_candidate_artifacts(dataclasses.replace(view, typed_canonical_json_sha256="0" * 64))

    facts = _copy_materialized(view.facts)
    del facts["fields"]["conditions"]
    incomplete = _retagged_view(renderer, view, facts)
    with pytest.raises(renderer.CandidateRenderError, match="RegistryIR fields are incomplete"):
        renderer.render_candidate_artifacts(incomplete)


def test_renderer_rejects_incomplete_resolution_unknown_profiles_and_malformed_examples(
    renderer: ModuleType,
    view: Any,
) -> None:
    missing_resolution = _copy_materialized(view.facts)
    del missing_resolution["fields"]["resolved_group_uses"]["span.model.chat"]
    with pytest.raises(renderer.CandidateRenderError, match="resolved group uses are incomplete"):
        renderer.render_candidate_artifacts(_retagged_view(renderer, view, missing_resolution))

    unknown_profile = _copy_materialized(view.facts)
    domains = unknown_profile["fields"]["domains"]
    for domain in domains:
        for group in domain["fields"]["groups"]:
            if group["fields"]["id"] == "span.model.chat":
                group["fields"]["compatibility_profiles"] = ("unknown-profile",)
    with pytest.raises(renderer.CandidateRenderError, match="compatibility profile is unknown"):
        renderer.render_candidate_artifacts(_retagged_view(renderer, view, unknown_profile))

    malformed_example = _copy_materialized(view.facts)
    malformed_example["fields"]["examples"][0]["fields"]["record"]["signal"] = "logs"
    with pytest.raises(renderer.CandidateRenderError, match="example record is inconsistent"):
        renderer.render_candidate_artifacts(_retagged_view(renderer, view, malformed_example))

    malformed_occurrence = _copy_materialized(view.facts)
    malformed_occurrence["fields"]["examples"][0]["fields"]["builder_context"]["fields"]["occurrence"]["fields"][
        "record_id"
    ] = "not-the-record-id"
    with pytest.raises(renderer.CandidateRenderError, match="builder occurrence is inconsistent"):
        renderer.render_candidate_artifacts(_retagged_view(renderer, view, malformed_occurrence))

    malformed_rule = _copy_materialized(view.facts)
    malformed_rule["fields"]["mandatory_rule_catalog"]["fields"]["rules"][0]["fields"]["enforcement"]["fields"][
        "value"
    ] = False
    with pytest.raises(renderer.CandidateRenderError, match="constant mandatory rule is invalid"):
        renderer.render_candidate_artifacts(_retagged_view(renderer, view, malformed_rule))

    incomplete_structure = _copy_materialized(view.facts)
    del incomplete_structure["fields"]["structural_contract"]["fields"]["trace_body"]["fields"]["fields"]
    with pytest.raises(renderer.CandidateRenderError, match="structural contract is not canonical"):
        renderer.render_candidate_artifacts(_retagged_view(renderer, view, incomplete_structure))
