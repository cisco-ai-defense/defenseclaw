# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import dataclasses
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"


def _load(name: str, path: Path) -> ModuleType:
    existing = sys.modules.get(name)
    if existing is not None:
        return existing
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


plan = _load("telemetry_go_inbound_plan", SCRIPTS / "telemetry_go_inbound_plan.py")


@pytest.fixture(scope="module")
def candidate() -> Any:
    _load("telemetry_canonical_record", SCRIPTS / "telemetry_canonical_record.py")
    _load("telemetry_go_api_plan", SCRIPTS / "telemetry_go_api_plan.py")
    generator = _load("telemetry_inbound_plan_generator", SCRIPTS / "generate_telemetry_registry.py")
    renderer = _load(
        "telemetry_inbound_plan_candidate_renderer",
        SCRIPTS / "render_telemetry_registry_candidates.py",
    )
    return renderer.build_candidate_render_index(generator.compile_registry(ROOT).materialized_view)


def test_go_inbound_plan_is_digest_bound_complete_and_private(candidate: Any) -> None:
    compiled = plan.compile_go_inbound_plan(candidate)
    inbound = candidate.inbound_otlp
    expansion_by_class = {item.class_id: item for item in compiled.native_expansions}

    assert compiled.version == 2
    assert compiled.materialized_view_sha256 == candidate.materialized_view_sha256
    assert compiled.candidate_render_index_sha256 == candidate.candidate_render_index_sha256
    assert len(compiled.aliases) == len(inbound.alias_sets)
    assert len(compiled.source_normalizers) == len(inbound.source_normalizers)
    assert len(compiled.source_projection_plans) == len(inbound.source_projection_plans)
    assert tuple((item.class_id, item.signal) for item in compiled.native_expansions) == (
        ("otlp.native.log.v8", "logs"),
        ("otlp.native.metric.v8", "metrics"),
        ("otlp.native.span.v8", "traces"),
    )
    for class_id, expansion in expansion_by_class.items():
        expected_families = tuple(
            sorted(target["family"] for target in inbound.target_descriptors if target["class_id"] == class_id)
        )
        assert expansion.family_ids == expected_families
        assert expansion.family_ids == tuple(sorted(set(expansion.family_ids)))
    expanded_native_count = sum(len(item.family_ids) for item in compiled.native_expansions)
    assert len(compiled.matches) + expanded_native_count == len(inbound.match_descriptors)
    assert len(compiled.targets) + expanded_native_count == len(inbound.target_descriptors)
    assert all(not item.native_round_trip for item in compiled.matches)
    assert all(item.class_id not in expansion_by_class for item in (*compiled.matches, *compiled.targets))
    assert len(compiled.native_markers) == len(inbound.native_markers)
    assert len(compiled.echo_recognizers) == len(inbound.echo_recognizers)
    assert len(compiled.import_contexts) == len(inbound.import_contexts)
    assert len(compiled.projection_ids) == (
        len(compiled.aliases)
        + len(compiled.source_normalizers)
        + len(compiled.source_projection_plans)
        + len(inbound.match_descriptors)
        + len(inbound.target_descriptors)
        + len(compiled.native_markers)
        + len(compiled.echo_recognizers)
        + len(compiled.import_contexts)
    )
    assert len(set(compiled.projection_ids)) == len(compiled.projection_ids)
    assert compiled.native_malformed_external_fallback == "forbidden"
    assert compiled.unknown_fields == "drop_and_count"
    assert compiled.native_marker_rule == "any_declared_native_marker_selects_native_candidate"
    assert compiled.structural_marker_rule == "exact_declared_structure_only"
    assert compiled.native_malformed_disposition == "invalid_record"
    assert compiled.semantic_resource_instance_key != compiled.forward_instance_key
    assert all(
        not hasattr(context, "mandatory") and not hasattr(context, "floor") for context in compiled.import_contexts
    )
    assert all(item.startswith("inbound:") for item in compiled.projection_ids)


def test_go_inbound_plan_preserves_match_target_separation(candidate: Any) -> None:
    compiled = plan.compile_go_inbound_plan(candidate)
    targets = {target.id: target for target in compiled.targets}

    for match in compiled.matches:
        selected = [targets[target_id] for target_id in match.target_ids]
        assert sum(target.target_kind == "primary" for target in selected) == 1
        assert all(target.match_id == match.id for target in selected)
    codex = next(match for match in compiled.matches if match.class_id == "otlp.codex.response_completed.v1")
    assert codex.target_ids == (
        "otlp.codex.response_completed.v1.log.model.response.log.model.response",
        "otlp.codex.response_completed.v1.log.model.response.metric.defenseclaw.agent.token.usage",
    )
    predicates = {(predicate.location, predicate.key, predicate.operator) for predicate in codex.predicates}
    assert ("leaf_attribute", "input_token_count", "present") in predicates
    assert ("leaf_attribute", "output_token_count", "present") in predicates
    workflow = next(match for match in compiled.matches if match.id.endswith("span.workflow.run"))
    assert workflow.target_override == plan.GoInboundTargetOverrideIR(
        "gen_ai.workflow.name",
        "defenseclaw.workflow.name",
        "identifier-v1",
    )
    assert all(len(target.field_refs) == len(target.field_descriptor_ids) for target in compiled.targets)
    assert all(
        candidate.enriched_fields[descriptor_id].attribute_id == reference
        for target in compiled.targets
        for reference, descriptor_id in zip(target.field_refs, target.field_descriptor_ids, strict=True)
    )
    descriptors = {descriptor.family_id: descriptor for descriptor in candidate.go_api_plan.descriptors}
    assert all(
        target.descriptor_symbol == descriptors[target.family].catalog_contract.descriptor_type_symbol
        for target in compiled.targets
    )
    assert all(
        context.descriptor_symbol == descriptors[context.family_descriptor_id].catalog_contract.descriptor_type_symbol
        for context in compiled.import_contexts
    )
    assert all(descriptors[context.family_descriptor_id].signal == "log" for context in compiled.import_contexts)
    candidate_matches = {item["id"]: item for item in candidate.inbound_otlp.match_descriptors}
    for match in compiled.matches:
        source = candidate_matches[match.id]
        assert match.mapping_strategy == source["mapping"]["strategy"]
        assert match.alias_ids == tuple(item["id"] for item in source["mapping"]["alias_sets"])
        assert match.source_projection_plan_id == (
            ""
            if source["mapping"]["source_projection_plan"] is None
            else source["mapping"]["source_projection_plan"]["id"]
        )
        assert match.target_ids == tuple(source["target_ids"])
        assert [
            (item.location, item.key, item.operator, json.loads(item.values_json), item.value_type)
            for item in match.predicates
        ] == [
            (
                item["location"],
                item["key"],
                item["operator"],
                list(item["values"]),
                item["value_type"],
            )
            for item in source["discriminator"]["predicates"]
        ]

    duration_rule = plan.GoInboundUnitRuleIR(
        "scale-table-v1",
        "s",
        tuple(
            plan.GoInboundUnitScaleIR(unit, scale)
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
        ),
    )
    duration_matches = [match for match in compiled.matches if match.class_id == "otlp.genai.duration.metric.v1"]
    assert len(duration_matches) == 5
    assert all(match.source_unit_rule == duration_rule for match in duration_matches)
    assert all(
        targets[match.target_ids[0]].instrument_unit == "s"
        and targets[match.target_ids[0]].source_unit_rule == duration_rule
        for match in duration_matches
    )

    token_rule = plan.GoInboundUnitRuleIR(
        "scale-table-v1",
        "{token}",
        tuple(plan.GoInboundUnitScaleIR(unit, 1.0) for unit in ("", "{token}", "token", "tokens")),
    )
    token_match = next(match for match in compiled.matches if match.class_id == "otlp.claudecode.token_usage.v1")
    assert token_match.source_unit_rule == token_rule
    assert targets[token_match.target_ids[0]].instrument_unit == "{token}"
    assert targets[token_match.target_ids[0]].source_unit_rule == token_rule
    assert token_match.source_projection_plan_id == "genai-token-metric-v1"
    assert targets[token_match.target_ids[0]].source_projection_plan_id == "genai-token-metric-v1"
    assert all(match.source_projection_plan_id == "genai-duration-metric-v1" for match in duration_matches)
    assert all(
        targets[match.target_ids[0]].source_projection_plan_id == "genai-duration-metric-v1"
        for match in duration_matches
    )


def test_go_inbound_plan_preserves_generated_pr412_projection_and_series_contract(candidate: Any) -> None:
    compiled = plan.compile_go_inbound_plan(candidate)
    normalizers = {item.id: item for item in compiled.source_normalizers}
    projections = {item.id: item for item in compiled.source_projection_plans}

    assert tuple(normalizers) == (
        "bounded-label-v1",
        "identifier-label-v1",
        "genai-provider-label-v1",
        "genai-model-label-v1",
        "genai-operation-label-v1",
        "token-type-label-v1",
    )
    assert normalizers["genai-model-label-v1"].prefixes == (
        "gpt-5",
        "gpt-4o",
        "gpt-4",
        "gpt-3.5",
        "o1",
        "o3",
        "claude-3.5",
        "claude-3-7",
        "claude-3",
        "claude-4",
        "claude-opus",
        "claude-sonnet",
        "claude-haiku",
        "gemini-1.5",
        "gemini-2",
        "gemini",
        "llama-3",
        "llama-4",
        "mistral",
        "deepseek",
        "qwen",
        "grok",
        "command-r",
        "phi-3",
        "phi-4",
    )
    token = projections["genai-token-metric-v1"]
    assert tuple(field.target for field in token.field_rules) == (
        "gen_ai.operation.name",
        "gen_ai.provider.name",
        "gen_ai.request.model",
        "gen_ai.token.type",
    )
    assert all(field.disposition == "project" for field in token.field_rules)
    assert tuple(group.placement for group in token.field_rules[0].source_groups) == ("fixed",)
    assert token.field_rules[0].source_groups[0].keys == ("chat",)
    assert tuple(group.placement for group in token.field_rules[1].source_groups) == (
        "metric_point_attribute",
        "authenticated_source",
        "resource_attribute",
    )
    assert token.field_rules[2].requirement == "required"
    assert token.field_rules[2].source_groups[-1].keys == ("unknown",)
    series = token.cumulative_series
    assert series is not None
    assert series.framing == "length-prefixed-presence-v1"
    assert series.normalization_stage == "before_framing"
    assert tuple(component.id for component in series.components) == (
        "authenticated_source",
        "resource_service_name",
        "resource_service_instance_id",
        "instrument_name",
        "normalized_model",
        "token_type",
        "normalized_conversation",
    )
    assert series.reset_epoch.identity is False
    assert series.reset_epoch.role == "reset_only"
    assert series.reset_epoch.key == "$start_time_unix_nano"

    duration = projections["genai-duration-metric-v1"]
    assert duration.cumulative_series is None
    operation = next(field for field in duration.field_rules if field.target == "gen_ai.operation.name")
    assert tuple(group.placement for group in operation.source_groups) == ("metric_point_attribute", "fixed")
    assert operation.source_groups[-1].keys == ("chat",)


def test_go_inbound_plan_rejects_untyped_or_mutable_input(candidate: Any) -> None:
    with pytest.raises(plan.GoInboundPlanError, match="compiler-owned candidate"):
        plan.compile_go_inbound_plan({"inbound_otlp": candidate.inbound_otlp})

    forged = dataclasses.replace(candidate, materialized_view_sha256="bad")
    with pytest.raises(plan.GoInboundPlanError, match="materialized digest is invalid"):
        plan.compile_go_inbound_plan(forged)


def _replace_inbound_row(candidate: Any, collection: str, index: int, value: Any) -> Any:
    inbound = candidate.inbound_otlp
    rows = list(getattr(inbound, collection))
    rows[index] = value
    return dataclasses.replace(candidate, inbound_otlp=dataclasses.replace(inbound, **{collection: tuple(rows)}))


def test_go_inbound_plan_rejects_native_expansion_semantic_drift(candidate: Any) -> None:
    native_match_index = next(
        index
        for index, item in enumerate(candidate.inbound_otlp.match_descriptors)
        if item["class_id"] == "otlp.native.log.v8"
    )
    native_match = candidate.inbound_otlp.match_descriptors[native_match_index]
    discriminator = dict(native_match["discriminator"])
    predicates = list(discriminator["predicates"])
    predicates[0] = {**predicates[0], "operator": "absent"}
    discriminator["predicates"] = tuple(predicates)
    forged_match = {**native_match, "discriminator": discriminator}
    forged = _replace_inbound_row(candidate, "match_descriptors", native_match_index, forged_match)
    with pytest.raises(plan.GoInboundPlanError, match="native match expansion drift"):
        plan.compile_go_inbound_plan(forged)

    native_target_index = next(
        index
        for index, item in enumerate(candidate.inbound_otlp.target_descriptors)
        if item["class_id"] == "otlp.native.metric.v8"
    )
    native_target = candidate.inbound_otlp.target_descriptors[native_target_index]
    forged_target = {**native_target, "mapping_strategy": "wrong"}
    forged = _replace_inbound_row(candidate, "target_descriptors", native_target_index, forged_target)
    with pytest.raises(plan.GoInboundPlanError, match="native target expansion drift"):
        plan.compile_go_inbound_plan(forged)


def test_go_inbound_plan_rejects_native_expansion_order_drift(candidate: Any) -> None:
    rows = candidate.inbound_otlp.match_descriptors
    first = next(index for index, item in enumerate(rows) if item["class_id"].startswith("otlp.native."))
    swapped = list(rows)
    swapped[first], swapped[first + 1] = swapped[first + 1], swapped[first]
    forged = dataclasses.replace(
        candidate,
        inbound_otlp=dataclasses.replace(candidate.inbound_otlp, match_descriptors=tuple(swapped)),
    )
    with pytest.raises(plan.GoInboundPlanError, match="coverage or order differs"):
        plan.compile_go_inbound_plan(forged)
