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

import dataclasses
import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _load(name: str, path: Path) -> ModuleType:
    existing = sys.modules.get(name)
    if existing is not None:
        assert isinstance(existing, ModuleType)
        assert Path(existing.__file__).resolve() == path.resolve()
        return existing
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_load("telemetry_canonical_record", ROOT / "scripts/telemetry_canonical_record.py")
SPEC = importlib.util.spec_from_file_location("telemetry_go_api_plan_test", ROOT / "scripts/telemetry_go_api_plan.py")
assert SPEC is not None and SPEC.loader is not None
plan = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = plan
SPEC.loader.exec_module(plan)


KIND_ORDER = (
    "attribute",
    "family",
    "log_event",
    "span_event",
    "link_relation",
    "metric_instrument",
    "condition",
    "condition_fact",
    "phase",
    "phase_code",
    "semantic_profile",
    "structured_type",
    "structured_member",
    "structured_arm",
    "structured_member_input",
    "structured_member_constructor",
    "family_input",
    "family_builder",
    "span_event_input",
    "span_event_constructor",
    "span_link_input",
    "span_link_constructor",
)
FORM_BY_KIND = {
    **{
        kind: "exported_const"
        for kind in (
            "attribute",
            "family",
            "log_event",
            "span_event",
            "link_relation",
            "metric_instrument",
            "condition",
            "condition_fact",
            "phase",
            "phase_code",
            "semantic_profile",
            "structured_member",
        )
    },
    **{
        kind: "exported_type"
        for kind in (
            "structured_type",
            "structured_arm",
            "structured_member_input",
            "family_input",
            "span_event_input",
            "span_link_input",
        )
    },
    **{
        kind: "exported_function"
        for kind in (
            "structured_member_constructor",
            "span_event_constructor",
            "span_link_constructor",
        )
    },
    "family_builder": "family_builder_method",
}


def symbol(kind: str, source_id: str, go_symbol: str) -> dict[str, str]:
    return {
        "kind": kind,
        "source_id": source_id,
        "symbol": go_symbol,
        "declaration_form": FORM_BY_KIND[kind],
    }


def symbol_table(rows: list[dict[str, str]]) -> SimpleNamespace:
    rank = {kind: index for index, kind in enumerate(KIND_ORDER)}
    rows = sorted(rows, key=lambda row: (rank[row["kind"]], row["source_id"].encode("ascii")))
    payload = json.dumps(
        [[row["kind"], row["source_id"], row["symbol"], row["declaration_form"]] for row in rows],
        separators=(",", ":"),
    ).encode()
    kind_counts = {kind: 0 for kind in KIND_ORDER}
    declaration_counts = {
        "exported_const": 0,
        "exported_type": 0,
        "exported_function": 0,
        "family_builder_method": 0,
    }
    for row in rows:
        kind_counts[row["kind"]] += 1
        declaration_counts[row["declaration_form"]] += 1
    return SimpleNamespace(
        version=1,
        package="observability",
        rows=tuple(SimpleNamespace(**row) for row in rows),
        kind_counts=kind_counts,
        declaration_form_counts=declaration_counts,
        table_sha256=hashlib.sha256(b"DefenseClaw GoSymbolTableIR v1\x00" + payload).hexdigest(),
    )


def policy() -> SimpleNamespace:
    return SimpleNamespace(
        version=1,
        package="observability",
        separators=(".", "-", "/", "_"),
        brand_spellings={"defenseclaw": "DefenseClaw", "opentelemetry": "OpenTelemetry", "otel": "OTel"},
        initialisms=(
            "AI",
            "API",
            "DB",
            "HEC",
            "HTTP",
            "ID",
            "JSON",
            "LLM",
            "OTEL",
            "OTLP",
            "PII",
            "RPC",
            "SDK",
            "SQL",
            "TLS",
            "URL",
            "UTF8",
        ),
        reserved_word_policy="reject",
        collision_policy="reject",
        auto_suffix_policy="reject",
    )


def enriched_field(
    identifier: str,
    owner_id: str,
    component: str,
    semantic_source_id: str,
    primitive_type: str,
    order: int,
    *,
    requirement: str = "required",
    condition_fact: str | None = None,
    value_source: str = "input",
    input_owner_kind: str = "family",
    structured_type: str | None = None,
) -> dict[str, Any]:
    context = {"log": "log", "span": "span", "metric": "metric"}.get(owner_id.split(".", 1)[0], component)
    placement = {
        "family": "family_input",
        "resource": "resource_input",
        "scope": "family_input",
        "event": "event_input",
        "link": "link_input",
        "structured": "structured_input",
    }[component]
    target_slot = {
        "log": "body",
        "span": "trace.attributes",
        "metric": "metric.attributes",
        "resource": "trace.resource.attributes",
        "scope": "trace.scope.attributes",
        "event": "trace.event.attributes",
        "link": "trace.link.attributes",
        "structured": "structured.value",
    }[context]
    constraints = (
        {
            "max_utf8_bytes": 4096,
            "max_item_utf8_bytes": 1024,
            "max_items": 256,
            "max_depth": 8,
            "max_properties": 256,
        }
        if structured_type is not None
        else {
            "max_utf8_bytes": 4096,
            "max_item_utf8_bytes": 1024,
            "max_items": 256,
        }
        if primitive_type == "string[]"
        else {}
    )
    return {
        "id": identifier,
        "owner_id": owner_id,
        "context": context,
        "attribute_id": semantic_source_id,
        "field_types": (primitive_type,) if primitive_type != "structured" else ("canonical_json",),
        "structured_type": structured_type,
        "requirement_level": requirement,
        "condition_id": "condition." + condition_fact if condition_fact is not None else None,
        "condition_fact": condition_fact,
        "condition_false_requirement": "optional" if condition_fact is not None else None,
        "field_class": "metadata",
        "effective_constraints": constraints,
        "value_source": value_source,
        "target_slot": target_slot,
        "input_placement": "private_derived" if value_source != "input" else placement,
        "order": order,
    }


def mandatory_program(*facts: str) -> dict[str, Any]:
    return {
        "rule_ids": tuple("rule." + fact for fact in facts),
        "constant_terms": (),
        "fact_terms": facts,
    }


def family(
    identifier: str,
    signal: str,
    domain: str,
    *,
    field_ids: tuple[str, ...] = (),
    resource_field_ids: tuple[str, ...] = (),
    scope_field_ids: tuple[str, ...] = (),
    events: tuple[dict[str, Any], ...] = (),
    links: tuple[dict[str, Any], ...] = (),
    outcome_requirement: str | None = None,
    metric_value_type: str = "int64",
    mandatory: dict[str, Any] | None = None,
    event_name: str | None = None,
) -> dict[str, Any]:
    outcome = outcome_requirement or {"log": "required", "span": "required", "metric": "forbidden"}[signal]
    return {
        "id": identifier,
        "removed_in": None,
        "signal": {"log": "logs", "span": "traces", "metric": "metrics"}[signal],
        "domain": domain,
        "outcome_requirement": outcome,
        "field_descriptor_ids": field_ids,
        "mandatory_program_id": identifier if signal == "log" else None,
        "allowed_outcomes": () if signal == "metric" else ("completed", "failed"),
        "bucket": {"log": "diagnostic", "span": "agent.lifecycle", "metric": "platform.health"}[signal],
        "event_name": event_name or identifier,
        "family_schema_version": 1,
    }


def constant_value(kind: str, source_id: str, go_symbol: str, value: str) -> dict[str, Any]:
    return {
        "kind": kind,
        "source_id": source_id,
        "symbol": go_symbol,
        "go_type": "string",
        "literal_kind": "string",
        "value": value,
    }


def synthetic_candidate_fields() -> dict[str, Any]:
    def bounded_field(name: str, max_items: int) -> dict[str, Any]:
        return {
            "name": name,
            "normalization": {
                "effective_constraints": {
                    "max_utf8_bytes": 4096,
                    "max_item_utf8_bytes": 1024,
                    "max_items": max_items,
                    "max_depth": 8,
                    "max_properties": 256,
                }
            },
        }

    return {
        "semantic_profiles": ({"id": "profile-v1", "trace_schema_version": "trace-v1"},),
        "value_catalogs": (),
        "structural_contract": {
            "trace_body": {
                "fields": (
                    bounded_field("attributes", 256),
                    bounded_field("events", 128),
                    bounded_field("links", 64),
                )
            },
            "trace_resource": {"fields": (bounded_field("attributes", 256),)},
            "trace_scope": {
                "fields": (
                    {"name": "name", "const": "defenseclaw.telemetry"},
                    {"name": "schema_url", "const": "https://defenseclaw.io/schemas/telemetry/v8"},
                    bounded_field("attributes", 16),
                )
            },
            "trace_event": {"fields": (bounded_field("attributes", 64),)},
            "trace_link": {"fields": (bounded_field("attributes", 64),)},
            "metric_instrument_data": {"fields": (bounded_field("attributes", 256),)},
        },
    }


def rich_index() -> SimpleNamespace:
    rows = [
        symbol("attribute", "gen_ai.request.model", "TelemetryAttributeGenAIRequestModel"),
        symbol("family", "span.test", "TelemetryFamilySpanTest"),
        symbol("log_event", "log.test", "TelemetryLogEventLogTest"),
        symbol("span_event", "content.redacted", "TelemetrySpanEventContentRedacted"),
        symbol("link_relation", "caused_by", "TelemetryLinkRelationCausedBy"),
        symbol("metric_instrument", "test.total", "TelemetryMetricInstrumentTestTotal"),
        symbol("structured_type", "gen_ai.box", "TelemetryStructuredGenAIBox"),
        symbol("structured_member", "gen_ai.box#entry", "TelemetryStructuredMemberGenAIBoxEntry"),
        symbol("structured_member_input", "gen_ai.box#entry", "GenAIBoxEntryMemberInput"),
        symbol("structured_member_constructor", "gen_ai.box#entry", "NewGenAIBoxEntryMember"),
        symbol("family_input", "log.test", "LogTestInput"),
        symbol("family_input", "metric.test", "MetricTestInput"),
        symbol("family_input", "span.test", "SpanTestInput"),
        symbol("family_builder", "log.test", "BuildLogTest"),
        symbol("family_builder", "metric.test", "BuildMetricTest"),
        symbol("family_builder", "span.test", "BuildSpanTest"),
        symbol("span_event_input", "span.test#content.redacted", "SpanTestContentRedactedEventInput"),
        symbol("span_event_constructor", "span.test#content.redacted", "NewSpanTestContentRedactedEvent"),
        symbol("span_link_input", "span.test#caused_by", "SpanTestCausedByLinkInput"),
        symbol("span_link_constructor", "span.test#caused_by", "NewSpanTestCausedByLink"),
    ]
    fields = [
        enriched_field("log-model", "log.test", "family", "gen_ai.request.model", "string", 0),
        enriched_field(
            "log-tags",
            "log.test",
            "family",
            "http.request.headers",
            "string[]",
            1,
            requirement="optional",
        ),
        enriched_field(
            "log-box",
            "log.test",
            "family",
            "gen_ai.input.box",
            "structured",
            2,
            requirement="conditional",
            condition_fact="payload_available",
            structured_type="gen_ai.box",
        ),
        enriched_field("resource-service", "resource.core", "resource", "service.name", "string", 0),
        enriched_field("span-operation", "span.test", "family", "gen_ai.operation.name", "string", 0),
        enriched_field(
            "event-reason",
            "content.redacted",
            "event",
            "defenseclaw.reason",
            "string",
            0,
            requirement="conditional",
            condition_fact="event_reason_available",
            input_owner_kind="event",
        ),
        enriched_field(
            "link-kind",
            "link.core",
            "link",
            "defenseclaw.link.kind",
            "string",
            0,
            input_owner_kind="link",
        ),
        enriched_field("metric-kind", "metric.test", "family", "defenseclaw.metric.kind", "string", 0),
        enriched_field(
            "structured-content",
            "gen_ai.box",
            "structured",
            "field:content",
            "string",
            0,
            input_owner_kind="structured",
        ),
        enriched_field(
            "structured-entry-name",
            "gen_ai.box",
            "structured",
            "dynamic_name:entry",
            "string",
            1,
            requirement="optional",
            input_owner_kind="structured",
        ),
    ]
    families = [
        family(
            "log.test",
            "log",
            "security",
            field_ids=("log-model", "log-tags", "log-box"),
            mandatory=mandatory_program("operator_mutation"),
        ),
        family(
            "metric.test",
            "metric",
            "operations",
            field_ids=("metric-kind",),
            metric_value_type="double",
            event_name="test.total",
        ),
        family(
            "span.test",
            "span",
            "genai",
            field_ids=("span-operation",),
            resource_field_ids=("resource-service",),
            events=(
                {
                    "source_id": "span.test#content.redacted",
                    "event_name": "content.redacted",
                    "field_ids": ("event-reason",),
                },
            ),
            links=({"source_id": "span.test#caused_by", "relation": "caused_by", "field_ids": ("link-kind",)},),
        ),
    ]
    return SimpleNamespace(
        materialized_view_sha256="1" * 64,
        go_symbol_policy=policy(),
        go_symbol_table=symbol_table(rows),
        enriched_fields=tuple(fields),
        enriched_families=tuple(families),
        structured_types=(
            {
                "id": "gen_ai.box",
                "kind": "object",
                "fields": (
                    {
                        "name": "content",
                        "required": True,
                        "scalar": {"field_type": "string"},
                        "reference": None,
                    },
                ),
                "items_scalar": None,
                "items_reference": None,
                "variants": None,
                "dynamic_variant": None,
                "canonical_json": None,
                "discriminator": None,
                "dynamic_members": {"member_id": "entry", "value": {"structured_ref": "gen_ai.box"}},
            },
        ),
        enriched_containers={
            "structured:gen_ai.box": SimpleNamespace(
                child_fields=("structured-content", "structured-entry-name"),
                child_containers=("structured-edge:gen_ai.box:dynamic:entry",),
                bounds={
                    "max_utf8_bytes": 4096,
                    "max_item_utf8_bytes": 1024,
                    "max_items": 256,
                    "max_depth": 8,
                    "max_properties": 256,
                },
            ),
            "structured-edge:gen_ai.box:dynamic:entry": SimpleNamespace(reference_target="gen_ai.box"),
        },
        enriched_traces={
            "span.test": SimpleNamespace(
                resource_field_descriptor_ids=("resource-service",),
                scope_field_descriptor_ids=(),
                event_field_descriptor_ids={"content.redacted": ("event-reason",)},
                event_refs=("content.redacted",),
                link_field_descriptor_ids=("link-kind",),
                link_relations=("caused_by",),
                span_name_parts=({"kind": "literal", "literal": "test", "field": None},),
                span_kinds=("INTERNAL",),
            )
        },
        enriched_metrics={
            "metric.test": SimpleNamespace(
                value_type="double",
                instrument_name="test.total",
                instrument_type="counter",
                unit="{event}",
                temporality="delta",
                description="Synthetic metric.",
                boundaries=(),
            )
        },
        mandatory_programs={
            "log.test": SimpleNamespace(
                rule_ids=("rule.operator_mutation",),
                constant_rule_ids=(),
                fact_terms=(("rule.operator_mutation", "operator_mutation"),),
            )
        },
        fields=synthetic_candidate_fields(),
        examples=(
            {
                "id": "valid-log-test",
                "signal": "logs",
                "family": "log.test",
                "valid": True,
                "record": {"signal": "logs", "body": {}},
                "builder_context": {},
                "expected_error": None,
                "base_example": None,
            },
        ),
        expanded_producer_mappings=({"id": "producer.test"},),
        go_declaration_values=(
            constant_value(
                "attribute",
                "gen_ai.request.model",
                "TelemetryAttributeGenAIRequestModel",
                "gen_ai.request.model",
            ),
            constant_value(
                "structured_member",
                "gen_ai.box#entry",
                "TelemetryStructuredMemberGenAIBoxEntry",
                "entry",
            ),
            constant_value("family", "span.test", "TelemetryFamilySpanTest", "span.test"),
            constant_value("log_event", "log.test", "TelemetryLogEventLogTest", "log.test"),
            constant_value(
                "span_event",
                "content.redacted",
                "TelemetrySpanEventContentRedacted",
                "content.redacted",
            ),
            constant_value("link_relation", "caused_by", "TelemetryLinkRelationCausedBy", "caused_by"),
            constant_value(
                "metric_instrument",
                "test.total",
                "TelemetryMetricInstrumentTestTotal",
                "test.total",
            ),
        ),
    )


def input_by_source(compiled: plan.GoAPIPlanIR, source_id: str) -> plan.GoInputPlanIR:
    return next(item for item in compiled.inputs if item.declaration_source_id == source_id)


def load_module(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def test_real_candidate_index_compiles_complete_semantic_plan() -> None:
    generator = load_module("telemetry_go_plan_real_generator", ROOT / "scripts/generate_telemetry_registry.py")
    renderer = load_module("telemetry_go_plan_real_renderer", ROOT / "scripts/render_telemetry_registry_candidates.py")
    view = generator.compile_registry(ROOT).materialized_view
    index = renderer.build_candidate_render_index(view)
    first = plan.compile_go_api_plan(index)
    second = plan.compile_go_api_plan(index)

    assert first == second
    assert len(first.api_plan_sha256) == 64
    assert len(first.declarations) == len(index.go_symbol_table.rows)
    assert len(first.inputs) == len(first.callables)
    assert len(first.descriptors) == len(index.families)
    assert len(first.structured) == len(index.structured_types)
    assert len(first.fixtures) == len(index.examples)
    assert sum(len(item.fields) for item in first.inputs) > 0
    assert first.private_declarations
    assert first.resource_attributes.validator_symbol == "ValidateTelemetryResourceAttributes"
    assert first.resource_attributes.fixed_descriptors
    assert any(descriptor.requirement == "required" for descriptor in first.resource_attributes.fixed_descriptors)
    assert (
        next(
            declaration for declaration in first.declarations if declaration.kind == "resource_attributes_validator"
        ).symbol
        == "ValidateTelemetryResourceAttributes"
    )
    assert tuple(helper.symbol for helper in first.kernel_helpers) == (
        "buildGeneratedMetric",
        "buildGeneratedResolvedLog",
        "buildGeneratedTrace",
        "familyDoubleMetricNumber",
        "familyInt64MetricNumber",
        "resolveGeneratedLogMandatory",
        "validateFamilyString",
    )
    assert all(file.package_name == "observability" and file.imports == () for file in first.files)
    private_arms = {
        arm: sum(item.arm == arm for item in first.private_declarations)
        for arm in {
            "family_descriptor_type",
            "family_descriptor_method",
            "family_trace_method",
            "family_metric_method",
            "event_contract_helper",
            "structured_marker_method",
            "structured_encoder",
        }
    }
    assert private_arms["family_descriptor_type"] == len(first.descriptors)
    assert private_arms["family_descriptor_method"] == len(first.descriptors)
    assert all(private_arms[arm] > 0 for arm in private_arms)
    assert {type(item.body).__name__ for item in first.callables} == {
        "GoFamilyCallableBodyPlanIR",
        "GoEventCallableBodyPlanIR",
        "GoLinkCallableBodyPlanIR",
        "GoMemberCallableBodyPlanIR",
    }
    assert any(part.arm == "literal" for item in first.descriptors for part in item.span_name_parts)
    assert any(part.arm == "field" for item in first.descriptors for part in item.span_name_parts)
    model_input = input_by_source(first, "span.model.chat")
    assert model_input.fields
    assert tuple(field.selector for field in model_input.fields if field.conversion_op == "condition_fact") == (
        "ConditionConnectorKnown",
        "ConditionOperationTerminal",
        "ConditionTechnicalFailure",
    )
    model_builder = next(
        item
        for item in first.callables
        if item.declaration_kind == "family_builder" and item.declaration_source_id == "span.model.chat"
    )
    assert isinstance(model_builder.body, plan.GoFamilyCallableBodyPlanIR)
    assert tuple(
        (condition.condition_id, condition.fact_id, condition.selector, condition.optional_source)
        for condition in model_builder.body.conditions
    ) == (
        (
            "agent-reported-cost-available-v1",
            "attribute:defenseclaw.agent.reported_cost.present",
            "DefenseClawAgentReportedCostPresent",
            False,
        ),
        ("connector-known-v1", "connector_known", "ConditionConnectorKnown", False),
        ("operation-terminal-v1", "operation_terminal", "ConditionOperationTerminal", False),
        (
            "telemetry-canary-enabled-v1",
            "attribute:defenseclaw.telemetry.canary",
            "DefenseClawTelemetryCanary",
            True,
        ),
        ("technical-failure-v1", "technical_failure", "ConditionTechnicalFailure", False),
    )
    assert any(
        field.requirement == "conditional" and field.value_source != "input"
        for descriptor in first.descriptors
        for field in descriptor.field_contracts
    )
    relation_owners = tuple(
        descriptor for descriptor in first.descriptors if descriptor.catalog_contract.base.cross_field_relations
    )
    assert relation_owners
    transition = next(item for item in relation_owners if item.family_id == "span.agent.transition")
    phase_relation = transition.catalog_contract.base.cross_field_relations[0]
    assert phase_relation.catalog_id == "agent-phase-v1"
    assert phase_relation.entries
    assert len({entry.value for entry in phase_relation.entries}) == len(phase_relation.entries)
    assert phase_relation.mismatch_error.symbol == "FamilyBuildLifecyclePhaseCodeMismatch"
    valid_model_fixture = next(
        item for item in first.fixtures if item.example_id == "valid-model-chat-with-honest-missing-content-and-usage"
    )
    assert '"operation_terminal"' in json.dumps(plan._canonical_node(valid_model_fixture.builder_context))
    assert '"start_time_unix_nano":1.78308e18' in valid_model_fixture.expected_record_json
    invalid_phase_fixture = next(
        item for item in first.fixtures if item.example_id == "invalid-lifecycle-phase-code-mismatch"
    )
    assert invalid_phase_fixture.expected_error == "lifecycle_phase_code_mismatch"
    enriched_fields = dict(index.enriched_fields)
    inputs = {item.declaration_source_id: item for item in first.inputs}
    public_span_name_fields = 0
    for descriptor in first.descriptors:
        if descriptor.signal != "span":
            continue
        family = index.enriched_families[descriptor.family_id]
        for part in descriptor.span_name_parts:
            if part.arm != "field":
                continue
            matches = tuple(
                enriched_fields[field_id]
                for field_id in family.field_descriptor_ids
                if enriched_fields[field_id].attribute_id == part.field_key
            )
            assert len(matches) == 1
            enriched = matches[0]
            assert enriched.requirement_level == "required"
            assert enriched.condition_id is None and enriched.condition_fact is None
            assert enriched.field_types == ("string",) and enriched.structured_type is None
            kernel = next(item for item in descriptor.field_contracts if item.descriptor_id == enriched.id)
            assert kernel.requirement == "required"
            assert kernel.requirement_ref.symbol == "familyRequirementRequired"
            if enriched.value_source == "input":
                public_span_name_fields += 1
                public = next(
                    item for item in inputs[descriptor.family_id].fields if item.enriched_descriptor_id == enriched.id
                )
                assert public.presence == "required"
                assert public.type_ref == plan.GoTypeRefIR("builtin", name="string")
                assert public.conversion_op == "required_scalar"
            else:
                assert all(item.enriched_descriptor_id != enriched.id for item in inputs[descriptor.family_id].fields)
    assert public_span_name_fields > 0
    assert sum(len(item.scalar_descriptor_ids) for item in first.structured) > 0
    assert sum(item.trace_contract is not None for item in first.descriptors) == sum(
        item.signal == "span" for item in first.descriptors
    )
    assert sum(item.metric_attribute_limits is not None for item in first.descriptors) == sum(
        item.signal == "metric" for item in first.descriptors
    )
    assert all(
        {field.descriptor_id for field in item.field_contracts}
        == set(item.enriched_field_descriptor_ids)
        | set(item.resource_field_descriptor_ids)
        | set(item.scope_field_descriptor_ids)
        | {field_id for _, _, field_ids in item.event_contracts for field_id in field_ids}
        | {field_id for _, field_ids in item.link_contracts for field_id in field_ids}
        for item in first.descriptors
    )
    assert all(
        field.constraints.arm == "object" for descriptor in first.descriptors for field in descriptor.field_contracts
    )
    phase_codes = [item for item in first.declarations if item.kind == "phase_code"]
    assert phase_codes
    assert all(item.go_type == plan.GoTypeRefIR("builtin", name="int") for item in phase_codes)
    assert all(item.literal_kind == "integer" and isinstance(item.literal_value, int) for item in phase_codes)
    owned = [descriptor_id for file in first.files for descriptor_id in file.private_descriptor_ids]
    catalog = next(file for file in first.files if file.path.endswith("zz_generated_telemetry_catalog.go"))
    assert owned == list(catalog.private_descriptor_ids)
    assert owned and len(owned) == len(set(owned))
    counts = {item.path: len(item.declarations) for item in first.files}
    assert sum(counts.values()) == len(first.declarations)
    assert all(
        counts[path] > 0
        for path in (
            "internal/observability/zz_generated_telemetry_ids.go",
            "internal/observability/zz_generated_telemetry_builders_genai.go",
            "internal/observability/zz_generated_telemetry_builders_security.go",
            "internal/observability/zz_generated_telemetry_builders_operations.go",
        )
    )
    assert all(
        file.private_declarations == tuple(item for item in first.private_declarations if item.output_file == file.path)
        for file in first.files
    )
    assert all(
        tuple(item.order for item in file.private_declarations) == tuple(range(len(file.private_declarations)))
        for file in first.files
    )


def test_compiler_owns_names_types_layouts_signatures_and_constant_values() -> None:
    compiled = plan.compile_go_api_plan(rich_index())
    log_input = input_by_source(compiled, "log.test")
    assert tuple(field.selector for field in log_input.fields) == (
        "Envelope",
        "Severity",
        "LogLevel",
        "Outcome",
        "GenAIRequestModel",
        "HTTPRequestHeaders",
        "GenAIInputBox",
        "ConditionPayloadAvailable",
        "MandatoryOperatorMutation",
    )
    assert log_input.fields[4].type_ref == plan.GoTypeRefIR("builtin", name="string")
    assert log_input.fields[5].type_ref == plan.GoTypeRefIR(
        "optional", element=plan.GoTypeRefIR("slice", element=plan.GoTypeRefIR("builtin", name="string"))
    )
    assert log_input.fields[6].type_ref == plan.GoTypeRefIR(
        "optional", element=plan.GoTypeRefIR("named", name="TelemetryStructuredGenAIBox")
    )
    assert log_input.fields[5].conversion_op == "copied_string_slice"
    assert log_input.fields[6].conversion_op == "structured_encoder"

    span_input = input_by_source(compiled, "span.test")
    assert tuple(field.selector for field in span_input.fields[:16]) == (
        "Envelope",
        "Outcome",
        "Kind",
        "StartTimeUnixNano",
        "EndTimeUnixNano",
        "ParentSpanID",
        "TraceState",
        "Flags",
        "Status",
        "Resource",
        "Scope",
        "DroppedAttributesCount",
        "Events",
        "DroppedEventsCount",
        "Links",
        "DroppedLinksCount",
    )
    assert tuple(field.selector for field in span_input.fields[16:]) == ("ResourceServiceName", "GenAIOperationName")
    metric_input = input_by_source(compiled, "metric.test")
    assert metric_input.fields[1].selector == "Value"
    assert metric_input.fields[1].type_ref == plan.GoTypeRefIR("builtin", name="float64")
    assert metric_input.fields[1].conversion_op == "metric_number"

    event_input = input_by_source(compiled, "span.test#content.redacted")
    assert tuple(field.selector for field in event_input.fields) == (
        "TimeUnixNano",
        "DroppedAttributesCount",
        "DefenseClawReason",
        "ConditionEventReasonAvailable",
    )
    link_input = input_by_source(compiled, "span.test#caused_by")
    assert tuple(field.selector for field in link_input.fields[:4]) == (
        "TraceID",
        "SpanID",
        "TraceState",
        "DroppedAttributesCount",
    )

    builder = next(item for item in compiled.callables if item.declaration_source_id == "log.test")
    assert builder.receiver_name == "builder"
    assert builder.receiver_pointer is True
    assert builder.receiver_type == plan.GoTypeRefIR("named", name="FamilyBuilder")
    assert builder.parameters == (("input", plan.GoTypeRefIR("named", name="LogTestInput")),)
    assert builder.results == (
        plan.GoTypeRefIR("named", name="Record"),
        plan.GoTypeRefIR("builtin", name="error"),
    )
    assert builder.private_target == "buildGeneratedResolvedLog"

    attribute = next(item for item in compiled.declarations if item.kind == "attribute")
    assert attribute.go_type == plan.GoTypeRefIR("builtin", name="string")
    assert attribute.literal_kind == "string"
    assert attribute.literal_value == "gen_ai.request.model"
    assert attribute.output_file.endswith("zz_generated_telemetry_ids.go")
    assert len(compiled.files) == 7
    assert tuple(item.path for item in compiled.files) == plan.GO_OUTPUT_FILES
    assert all(
        file.declarations == tuple(d for d in compiled.declarations if d.output_file == file.path)
        for file in compiled.files
    )


@pytest.mark.parametrize("requirement", ["recommended", "optional", "conditional"])
def test_go_api_plan_rejects_nonrequired_span_name_fields(requirement: str) -> None:
    index = rich_index()
    trace = index.enriched_traces["span.test"]
    trace.span_name_parts = ({"kind": "field", "literal": None, "field": "gen_ai.operation.name"},)
    fields = list(index.enriched_fields)
    target = next(field for field in fields if field["id"] == "span-operation")
    target["requirement_level"] = requirement
    target["condition_id"] = "condition.span_name" if requirement == "conditional" else None
    target["condition_fact"] = "span_name" if requirement == "conditional" else None
    target["condition_false_requirement"] = "optional" if requirement == "conditional" else None
    index.enriched_fields = tuple(fields)

    with pytest.raises(plan.GoAPIPlanError, match="not one unconditional required family string"):
        plan.compile_go_api_plan(index)


def test_catalog_structured_and_callable_rendering_contracts_are_closed_and_typed() -> None:
    compiled = plan.compile_go_api_plan(rich_index())
    log = next(item for item in compiled.descriptors if item.family_id == "log.test")
    base = log.catalog_contract.base
    assert log.catalog_contract.descriptor_type_symbol == "generatedLogTestDescriptor"
    assert base.identity.bucket == plan.GoTypedSymbolRefIR(
        plan.GoTypeRefIR("named", name="Bucket"),
        "BucketDiagnostic",
        None,
    )
    assert base.identity.signal.symbol == "SignalLogs"
    assert base.identity.event_name.symbol == "TelemetryLogEventLogTest"
    assert base.identity.event_name.conversion_type == plan.GoTypeRefIR("named", name="EventName")
    model = next(field for field in base.fields if field.descriptor_id == "log-model")
    assert model.type_ref.symbol == "familyFieldString"
    assert model.requirement_ref.symbol == "familyRequirementRequired"
    assert model.field_class_ref.symbol == "FieldClassMetadata"
    assert model.source_ref.symbol == "familyValueInput"
    assert model.typed_constraints == plan.GoFieldConstraintsPlanIR(
        0, 0, 0, 0, "", (), None, None, None, None, None, None, None
    )
    tags = next(field for field in base.fields if field.descriptor_id == "log-tags")
    assert tags.typed_constraints == plan.GoFieldConstraintsPlanIR(
        4096, 1024, 0, 256, "", (), None, None, None, None, None, None, None
    )
    box = next(field for field in base.fields if field.descriptor_id == "log-box")
    assert box.type_ref.symbol == "familyFieldStructured"
    assert box.requirement_ref.symbol == "familyRequirementConditional"
    assert box.false_requirement_ref is not None
    assert box.false_requirement_ref.symbol == "familyFalseOptional"
    assert box.typed_constraints.structured == plan.GoKernelLimitsIR(4096, 1024, 256, 8, 256)

    log_builder = next(
        item
        for item in compiled.callables
        if item.declaration_kind == "family_builder" and item.declaration_source_id == "log.test"
    )
    assert isinstance(log_builder.body, plan.GoFamilyCallableBodyPlanIR)
    assert log_builder.body.arm == "family_log"
    assert log_builder.body.kernel_helper.symbol == "buildGeneratedResolvedLog"
    assert log_builder.body.mandatory_resolver is not None
    assert log_builder.body.mandatory_resolver.symbol == "resolveGeneratedLogMandatory"
    assert tuple(value.key for value in log_builder.body.values) == (
        "gen_ai.request.model",
        "http.request.headers",
        "gen_ai.input.box",
    )
    assert log_builder.body.values[-1].structured_encoder_symbol == "encodeTelemetryStructuredGenAIBox"
    assert log_builder.body.conditions == (
        plan.GoConditionBindingPlanIR(
            "condition.payload_available",
            "payload_available",
            "ConditionPayloadAvailable",
            False,
        ),
    )
    assert log_builder.body.mandatory_terms == (
        plan.GoMandatoryBindingPlanIR("operator_mutation", "MandatoryOperatorMutation"),
    )

    event = next(item for item in compiled.callables if item.declaration_kind == "span_event_constructor")
    assert isinstance(event.body, plan.GoEventCallableBodyPlanIR)
    assert event.body.contract_helper_symbol == "generatedSpanTestContentRedactedEventContract"
    link = next(item for item in compiled.callables if item.declaration_kind == "span_link_constructor")
    assert isinstance(link.body, plan.GoLinkCallableBodyPlanIR)
    assert link.body.relation.symbol == "TelemetryLinkRelationCausedBy"
    member = next(item for item in compiled.callables if item.declaration_kind == "structured_member_constructor")
    assert isinstance(member.body, plan.GoMemberCallableBodyPlanIR)
    assert member.body.validation_helper.symbol == "validateFamilyString"

    structured = compiled.structured[0]
    assert structured.shape == "object"
    assert tuple(field.selector for field in structured.declaration_fields) == ("Content", "Entries")
    assert structured.marker_method is None
    assert structured.arms == ()
    assert len(structured.members) == 1
    assert structured.encoder.symbol == "encodeTelemetryStructuredGenAIBox"
    assert structured.encoder.result_type == plan.GoTypeRefIR("named", name="familyFieldValue")
    assert structured.encoder.arm == "object"
    assert tuple(binding.key for binding in structured.encoder.fixed_fields) == ("content",)

    metric = next(item for item in compiled.descriptors if item.family_id == "metric.test")
    assert metric.outcome_requirement == "forbidden"
    assert metric.catalog_contract.base.outcome.requirement.symbol == "familyRequirementInvalid"
    assert metric.catalog_contract.base.outcome.allowed == ()


def test_conditional_derived_field_adds_only_the_owned_fact_selector_and_body_binding() -> None:
    index = rich_index()
    fields = list(index.enriched_fields)
    fields.append(
        enriched_field(
            "span-derived-outcome",
            "span.test",
            "family",
            "defenseclaw.outcome",
            "string",
            1,
            requirement="conditional",
            condition_fact="operation_terminal",
            value_source="envelope.outcome",
            input_owner_kind="none",
        )
    )
    index.enriched_fields = tuple(fields)
    families = list(index.enriched_families)
    span_position = next(position for position, family in enumerate(families) if family["id"] == "span.test")
    families[span_position] = {
        **families[span_position],
        "field_descriptor_ids": families[span_position]["field_descriptor_ids"] + ("span-derived-outcome",),
    }
    index.enriched_families = tuple(families)

    compiled = plan.compile_go_api_plan(index)
    span_input = input_by_source(compiled, "span.test")
    assert len(span_input.fields) == 19
    assert tuple(field.selector for field in span_input.fields[-3:]) == (
        "ResourceServiceName",
        "GenAIOperationName",
        "ConditionOperationTerminal",
    )
    assert all(field.selector != "DefenseClawOutcome" for field in span_input.fields)
    builder = next(
        item
        for item in compiled.callables
        if item.declaration_kind == "family_builder" and item.declaration_source_id == "span.test"
    )
    assert isinstance(builder.body, plan.GoFamilyCallableBodyPlanIR)
    assert builder.body.conditions == (
        plan.GoConditionBindingPlanIR(
            "condition.operation_terminal",
            "operation_terminal",
            "ConditionOperationTerminal",
            False,
        ),
    )

    incomplete_builder = dataclasses.replace(
        builder,
        body=dataclasses.replace(builder.body, conditions=()),
    )
    incomplete_callables = tuple(incomplete_builder if item is builder else item for item in compiled.callables)
    with pytest.raises(plan.GoAPIPlanError, match="condition fact closure"):
        plan._validate_condition_closure(compiled.inputs, incomplete_callables, compiled.descriptors)


def value_catalog_index(
    *,
    entries: tuple[dict[str, Any], ...] = (
        {"value": "planning", "code": 1},
        {"value": "model", "code": 2},
    ),
    value_enum: tuple[str, ...] = ("planning", "model"),
    code_min: int = 1,
    code_max: int = 2,
) -> SimpleNamespace:
    index = rich_index()
    fields = list(index.enriched_fields)
    phase = enriched_field(
        "span-phase",
        "span.test",
        "family",
        "defenseclaw.agent.phase",
        "string",
        1,
        requirement="optional",
    )
    phase["effective_constraints"] = {"enum": value_enum, "max_utf8_bytes": 16}
    phase_code = enriched_field(
        "span-phase-code",
        "span.test",
        "family",
        "defenseclaw.agent.phase.code",
        "int64",
        2,
        requirement="optional",
    )
    phase_code["effective_constraints"] = {"min": code_min, "max": code_max}
    fields.extend((phase, phase_code))
    index.enriched_fields = tuple(fields)
    families = list(index.enriched_families)
    span_position = next(position for position, family in enumerate(families) if family["id"] == "span.test")
    families[span_position] = {
        **families[span_position],
        "field_descriptor_ids": families[span_position]["field_descriptor_ids"] + ("span-phase", "span-phase-code"),
    }
    index.enriched_families = tuple(families)
    index.fields = {
        **index.fields,
        "value_catalogs": (
            {
                "id": "agent-phase-v1",
                "kind": "string-int64-bijection",
                "value_attributes": ("defenseclaw.agent.phase",),
                "paired_value_attribute": "defenseclaw.agent.phase",
                "code_attribute": "defenseclaw.agent.phase.code",
                "entries": entries,
                "compatibility": {"value": "unknown", "code": 0, "canonical_emittable": False},
            },
        ),
    }
    return index


def test_value_catalog_compiles_typed_cross_field_relation() -> None:
    index = value_catalog_index()

    compiled = plan.compile_go_api_plan(index)
    descriptor = next(item for item in compiled.descriptors if item.family_id == "span.test")
    assert descriptor.catalog_contract.base.cross_field_relations == (
        plan.GoCrossFieldRelationPlanIR(
            "agent-phase-v1",
            "string-int64-bijection",
            "defenseclaw.agent.phase",
            "defenseclaw.agent.phase.code",
            (
                plan.GoValueCodeEntryPlanIR("planning", 1),
                plan.GoValueCodeEntryPlanIR("model", 2),
            ),
            plan.GoTypedSymbolRefIR(
                plan.GoTypeRefIR("named", name="FamilyBuildErrorCode"),
                "FamilyBuildLifecyclePhaseCodeMismatch",
                None,
            ),
        ),
    )


@pytest.mark.parametrize(
    ("index", "message"),
    (
        (value_catalog_index(entries=()), "bounded nonempty relation"),
        (
            value_catalog_index(
                entries=(
                    {"value": "planning", "code": 1},
                    {"value": "model", "code": 2**100},
                )
            ),
            "outside signed int64",
        ),
        (
            value_catalog_index(
                entries=(
                    {"value": "planning", "code": 1},
                    {"value": "unknown", "code": 2},
                )
            ),
            "outside paired field enum",
        ),
        (
            value_catalog_index(
                entries=(
                    {"value": "planning", "code": 1},
                    {"value": "model", "code": 3},
                )
            ),
            "above paired field range",
        ),
        (
            value_catalog_index(
                entries=({"value": "planning", "code": 1},),
            ),
            "exactly cover paired field enum",
        ),
    ),
)
def test_value_catalog_relation_rejects_unbounded_or_constraint_incompatible_entries(
    index: SimpleNamespace, message: str
) -> None:
    with pytest.raises(plan.GoAPIPlanError, match=message):
        plan.compile_go_api_plan(index)


def test_value_catalog_relation_rejects_family_with_only_one_side() -> None:
    index = value_catalog_index()
    index.enriched_fields = tuple(field for field in index.enriched_fields if field["id"] != "span-phase-code")
    families = list(index.enriched_families)
    span_position = next(position for position, family in enumerate(families) if family["id"] == "span.test")
    families[span_position] = {
        **families[span_position],
        "field_descriptor_ids": tuple(
            field_id for field_id in families[span_position]["field_descriptor_ids"] if field_id != "span-phase-code"
        ),
    }
    index.enriched_families = tuple(families)
    with pytest.raises(plan.GoAPIPlanError, match="family exposes only one side"):
        plan.compile_go_api_plan(index)


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        ("field class", "private-kernel enum mapping"),
        ("constraint key", "unsupported private-kernel constraint"),
        ("duplicate enum", "duplicate value"),
        ("span arm", "unknown arm"),
    ),
)
def test_rendering_contract_rejects_unreviewed_enums_constraints_and_span_arms(mutation: str, message: str) -> None:
    index = rich_index()
    fields = list(index.enriched_fields)
    if mutation == "field class":
        fields[0] = {**fields[0], "field_class": "invented"}
        index.enriched_fields = tuple(fields)
    elif mutation == "constraint key":
        fields[0] = {**fields[0], "effective_constraints": {"renderer_hint": 1}}
        index.enriched_fields = tuple(fields)
    elif mutation == "duplicate enum":
        fields[0] = {**fields[0], "effective_constraints": {"enum": ("x", "x")}}
        index.enriched_fields = tuple(fields)
    else:
        traces = dict(index.enriched_traces)
        traces["span.test"] = SimpleNamespace(
            **{
                **vars(traces["span.test"]),
                "span_name_parts": ({"kind": "computed", "field": "gen_ai.operation.name"},),
            }
        )
        index.enriched_traces = traces
    with pytest.raises(plan.GoAPIPlanError, match=message):
        plan.compile_go_api_plan(index)


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        ("missing family", "complete family descriptor inventory"),
        ("missing structured", "complete structured descriptor inventory"),
        ("selector collision", "field selector/order collision"),
        ("common collision", "field selector/order collision"),
        ("unsupported type", "unsupported Go field type"),
        ("missing constant", "exact exported-constant coverage"),
    ),
)
def test_compiler_fails_closed_for_missing_facts_types_and_collisions(mutation: str, message: str) -> None:
    index = rich_index()
    if mutation == "missing family":
        index.enriched_families = index.enriched_families[:-1]
    elif mutation == "missing structured":
        index.structured_types = ()
    elif mutation == "selector collision":
        fields = list(index.enriched_fields)
        fields[1] = {**fields[1], "attribute_id": "gen_ai_request_model"}
        index.enriched_fields = tuple(fields)
    elif mutation == "common collision":
        fields = list(index.enriched_fields)
        fields[0] = {**fields[0], "attribute_id": "envelope"}
        index.enriched_fields = tuple(fields)
    elif mutation == "unsupported type":
        fields = list(index.enriched_fields)
        fields[0] = {**fields[0], "field_types": ("bytes",)}
        index.enriched_fields = tuple(fields)
    elif mutation == "missing constant":
        index.go_declaration_values = index.go_declaration_values[:-1]
    with pytest.raises(plan.GoAPIPlanError, match=message):
        plan.compile_go_api_plan(index)


def test_plan_digest_is_deterministic_and_binds_typed_constant_values() -> None:
    first_index = rich_index()
    second_index = rich_index()
    second_index.enriched_fields = tuple(reversed(second_index.enriched_fields))
    second_index.enriched_families = tuple(reversed(second_index.enriched_families))
    first = plan.compile_go_api_plan(first_index)
    second = plan.compile_go_api_plan(second_index)
    assert first == second
    assert first.api_plan_sha256 == second.api_plan_sha256

    changed_index = rich_index()
    changed = list(changed_index.go_declaration_values)
    changed[0] = {**changed[0], "value": "changed.attribute.value"}
    changed_index.go_declaration_values = tuple(changed)
    changed_plan = plan.compile_go_api_plan(changed_index)
    assert changed_plan.api_plan_sha256 != first.api_plan_sha256


def test_integer_declaration_values_use_portable_signed_32_bit_range() -> None:
    index = rich_index()
    values = list(index.go_declaration_values)
    values[0] = {**values[0], "go_type": "int", "literal_kind": "integer", "value": 2**31 - 1}
    index.go_declaration_values = tuple(values)
    compiled = plan.compile_go_api_plan(index)
    declaration = next(item for item in compiled.declarations if item.kind == "attribute")
    assert declaration.go_type == plan.GoTypeRefIR("builtin", name="int")
    assert declaration.literal_value == 2**31 - 1

    values[0] = {**values[0], "value": 2**31}
    index.go_declaration_values = tuple(values)
    with pytest.raises(plan.GoAPIPlanError, match="integer literal"):
        plan.compile_go_api_plan(index)


def partition_index(*, wrong_domain: bool = False) -> SimpleNamespace:
    rows: list[dict[str, str]] = []
    constants: list[dict[str, Any]] = []
    for index in range(602):
        source_id = f"attribute.{index:04d}"
        rows.append(symbol("attribute", source_id, f"TelemetryAttributeA{index:04d}"))
        constants.append(constant_value("attribute", source_id, f"TelemetryAttributeA{index:04d}", source_id))
    structured = []
    for index in range(282):
        source_id = f"synthetic.type.{index:04d}"
        rows.append(symbol("structured_type", source_id, f"TelemetryStructuredSyntheticType{index:04d}"))
        structured.append(
            {
                "id": source_id,
                "kind": "object",
                "fields": None,
                "items_scalar": None,
                "items_reference": None,
                "variants": None,
                "dynamic_variant": None,
                "canonical_json": None,
                "discriminator": None,
                "dynamic_members": None,
            }
        )
    families: list[dict[str, Any]] = []
    family_domains: list[tuple[str, str]] = [(f"log.security{index:04d}", "security") for index in range(106)]
    family_domains.extend((f"log.operations{index:04d}", "operations") for index in range(193))
    if wrong_domain:
        family_domains[0] = (family_domains[0][0], "operations")
    for source_id, domain in family_domains:
        suffix = source_id.removeprefix("log.").replace(".", "")
        event_symbol = "TelemetryLogEvent" + suffix.title()
        rows.append(symbol("log_event", source_id, event_symbol))
        constants.append(constant_value("log_event", source_id, event_symbol, source_id))
        rows.append(symbol("family_input", source_id, "Log" + suffix.title() + "Input"))
        rows.append(symbol("family_builder", source_id, "BuildLog" + suffix.title()))
        families.append(family(source_id, "log", domain, outcome_requirement="forbidden"))
    derived_field = enriched_field(
        "derived-only",
        family_domains[0][0],
        "family",
        "defenseclaw.bucket",
        "string",
        0,
        value_source="envelope.bucket",
        input_owner_kind="none",
    )
    families[0]["field_descriptor_ids"] = ("derived-only",)
    structured_containers = {
        f"structured:synthetic.type.{index:04d}": SimpleNamespace(child_fields=(), child_containers=(), bounds={})
        for index in range(282)
    }
    return SimpleNamespace(
        materialized_view_sha256="2" * 64,
        go_symbol_policy=policy(),
        go_symbol_table=symbol_table(rows),
        enriched_fields=(derived_field,),
        enriched_families=tuple(families),
        structured_types=tuple(structured),
        enriched_containers=structured_containers,
        enriched_traces={},
        enriched_metrics={},
        mandatory_programs={
            source_id: SimpleNamespace(rule_ids=(), constant_rule_ids=(), fact_terms=())
            for source_id, _ in family_domains
        },
        fields=synthetic_candidate_fields(),
        examples=(),
        expanded_producer_mappings=(),
        go_declaration_values=tuple(constants),
    )


def test_declaration_partition_is_derived_and_every_declaration_has_one_file_assignment() -> None:
    source = partition_index()
    compiled = plan.compile_go_api_plan(source)
    counts = {item.path: len(item.declarations) for item in compiled.files}
    assert sum(counts.values()) == len(source.go_symbol_table.rows)
    keys = [key for file in compiled.files for key in file.declaration_keys]
    assert len(keys) == len(set(keys)) == len(source.go_symbol_table.rows)

    moved = plan.compile_go_api_plan(partition_index(wrong_domain=True))
    moved_counts = {item.path: len(item.declarations) for item in moved.files}
    assert moved_counts != counts
    assert sum(moved_counts.values()) == sum(counts.values())


def test_ir_is_frozen_and_contains_no_renderer_text_type_escape_hatch() -> None:
    compiled = plan.compile_go_api_plan(rich_index())
    with pytest.raises(dataclasses.FrozenInstanceError):
        compiled.version = 2  # type: ignore[misc]
    for input_plan in compiled.inputs:
        for field in input_plan.fields:
            assert field.type_ref.arm in {"builtin", "named", "optional", "slice"}
            assert field.conversion_op in {
                "required_scalar",
                "optional_scalar",
                "copied_string_slice",
                "structured_encoder",
                "metric_number",
                "condition_fact",
                "mandatory_fact",
                "trace_event",
                "trace_link",
            }
    type_refs: list[plan.GoTypeRefIR] = []
    for input_plan in compiled.inputs:
        type_refs.extend(field.type_ref for field in input_plan.fields)
    for callable_plan in compiled.callables:
        type_refs.extend(type_ref for _, type_ref in callable_plan.parameters)
        type_refs.extend(callable_plan.results)
    for private in compiled.private_declarations:
        type_refs.extend(type_ref for _, type_ref in private.parameters)
        type_refs.extend(private.results)

    def walk(type_ref: plan.GoTypeRefIR) -> tuple[plan.GoTypeRefIR, ...]:
        return (type_ref,) + (walk(type_ref.element) if type_ref.element is not None else ())

    flattened = tuple(item for type_ref in type_refs for item in walk(type_ref))
    assert all(item.arm in {"builtin", "named", "optional", "slice"} for item in flattened)
    assert all(item.name != "any" for item in flattened)
    assert {item.arm for item in compiled.private_declarations} <= {
        "family_descriptor_type",
        "family_descriptor_method",
        "family_trace_method",
        "family_metric_method",
        "event_contract_helper",
        "structured_marker_method",
        "structured_encoder",
    }
    assert {item.private_kernel_target for item in compiled.inputs} <= {
        "structured_member_input",
        "trace_event_input",
        "trace_link_input",
        "family_log_input",
        "family_span_input",
        "family_metric_input",
    }


def test_reported_cost_condition_is_derived_from_the_public_present_selector() -> None:
    generator = load_module(
        "telemetry_go_plan_reported_cost_generator", ROOT / "scripts/generate_telemetry_registry.py"
    )
    renderer = load_module(
        "telemetry_go_plan_reported_cost_renderer",
        ROOT / "scripts/render_telemetry_registry_candidates.py",
    )
    view = generator.compile_registry(ROOT).materialized_view
    index = renderer.build_candidate_render_index(view)
    compiled = plan.compile_go_api_plan(index)
    targets = (
        "span.agent.transition",
        "span.agent.invoke",
        "span.workflow.run",
        "span.model.chat",
        "span.tool.execute",
    )
    for family_id in targets:
        family_input = input_by_source(compiled, family_id)
        selectors = {field.selector: field for field in family_input.fields}
        assert selectors["DefenseClawAgentReportedCostPresent"].type_ref == plan._builtin("bool")
        assert selectors["DefenseClawAgentReportedCostUsd"].type_ref == plan._optional_type(plan._builtin("float64"))
        assert "ConditionAgentReportedCostAvailable" not in selectors
        assert all(
            field.semantic_source_id != "agent_reported_cost_available"
            for field in family_input.fields
            if field.conversion_op == "condition_fact"
        )

        builder = next(
            item
            for item in compiled.callables
            if item.declaration_kind == "family_builder" and item.declaration_source_id == family_id
        )
        assert isinstance(builder.body, plan.GoFamilyCallableBodyPlanIR)
        reported = next(
            condition
            for condition in builder.body.conditions
            if condition.condition_id == "agent-reported-cost-available-v1"
        )
        assert reported.fact_id == "attribute:defenseclaw.agent.reported_cost.present"
        assert reported.selector == "DefenseClawAgentReportedCostPresent"
        assert reported.optional_source is False

    for family_id in ("span.agent.invoke", "span.model.chat"):
        family_input = input_by_source(compiled, family_id)
        selectors = {field.selector: field for field in family_input.fields}
        assert selectors["DefenseClawTelemetryCanary"].type_ref == plan._optional_type(plan._builtin("bool"))
        assert selectors["DefenseClawTelemetryCanaryOperation"].type_ref == plan._optional_type(plan._builtin("string"))
        assert selectors["DefenseClawTelemetryCanaryDestination"].type_ref == plan._optional_type(
            plan._builtin("string")
        )
        builder = next(
            item
            for item in compiled.callables
            if item.declaration_kind == "family_builder" and item.declaration_source_id == family_id
        )
        assert isinstance(builder.body, plan.GoFamilyCallableBodyPlanIR)
        canary = next(
            condition
            for condition in builder.body.conditions
            if condition.condition_id == "telemetry-canary-enabled-v1"
        )
        assert canary.fact_id == "attribute:defenseclaw.telemetry.canary"
        assert canary.selector == "DefenseClawTelemetryCanary"
        assert canary.optional_source is True
