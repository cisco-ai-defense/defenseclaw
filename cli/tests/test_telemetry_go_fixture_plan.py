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

import ast
import builtins
import dataclasses
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
FIXTURE_COMPILER = ROOT / "scripts/telemetry_go_fixture_plan.py"
GENERATOR = ROOT / "scripts/generate_telemetry_registry.py"
CANDIDATE_RENDERER = ROOT / "scripts/render_telemetry_registry_candidates.py"


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


@pytest.fixture(scope="module")
def compiler() -> ModuleType:
    return _load("telemetry_go_fixture_plan_test", FIXTURE_COMPILER)


def _type(arm: str, name: str | None = None, element: Any = None) -> SimpleNamespace:
    return SimpleNamespace(arm=arm, name=name, element=element)


def _field(
    selector: str,
    type_ref: Any,
    semantic: str,
    target: str,
    conversion: str = "required_scalar",
) -> SimpleNamespace:
    return SimpleNamespace(
        selector=selector,
        type_ref=type_ref,
        semantic_source_id=semantic,
        target_slot=target,
        conversion_op=conversion,
    )


def _family_input(family_id: str, symbol: str) -> SimpleNamespace:
    return SimpleNamespace(
        declaration_kind="family_input",
        declaration_source_id=family_id,
        symbol=symbol,
        fields=(
            _field("Envelope", _type("named", "FamilyEnvelopeInput"), "structural.Envelope", "Envelope"),
            _field(
                "Severity",
                _type("optional", element=_type("named", "Severity")),
                "structural.Severity",
                "Severity",
                "optional_scalar",
            ),
            _field("Outcome", _type("named", "Outcome"), "structural.Outcome", "Outcome"),
            _field("Message", _type("builtin", "string"), "example.message", "body"),
        ),
    )


def _callable(kind: str, source_id: str, symbol: str, input_symbol: str) -> SimpleNamespace:
    receiver = _type("named", "FamilyBuilder") if kind == "family_builder" else None
    return SimpleNamespace(
        declaration_kind=kind,
        declaration_source_id=source_id,
        symbol=symbol,
        receiver_type=receiver,
        receiver_pointer=kind == "family_builder",
        parameters=(("input", _type("named", input_symbol)),),
        results=(_type("named", "Record"), _type("builtin", "error")),
        variadic=False,
    )


def _record(*, message: str = "hello", bucket: str = "diagnostic.message") -> dict[str, Any]:
    return {
        "schema_version": 1,
        "bucket_catalog_version": 1,
        "timestamp": "2026-07-04T12:00:00.123456789Z",
        "record_id": "record-1",
        "bucket": bucket,
        "signal": "logs",
        "event_name": "diagnostic.message",
        "severity": "INFO",
        "source": "gateway",
        "outcome": "completed",
        "mandatory": False,
        "correlation": {"run_id": "run-1"},
        "provenance": {
            "producer": "defenseclaw",
            "binary_version": "8.0.0",
            "registry_schema_version": 1,
            "config_generation": 8,
        },
        "body": {"example.message": message},
        "field_classes": {"/example.message": "content"},
    }


def _context() -> dict[str, Any]:
    return {
        "inheritance": {"mode": "explicit"},
        "occurrence": {
            "timestamp": "2026-07-04T12:00:00.123456789Z",
            "record_id": "record-1",
        },
        "condition_facts": {},
        "mandatory_facts": {},
    }


def _example(
    example_id: str,
    *,
    valid: bool,
    record: dict[str, Any],
    family: str | None = "log.diagnostic.message",
    base: str | None = None,
    error: str | None = None,
) -> dict[str, Any]:
    context = (
        _context()
        if valid
        else {
            "inheritance": {
                "mode": "exact_base",
                "base_example": base,
            }
        }
    )
    return {
        "id": example_id,
        "valid": valid,
        "signal": "logs",
        "family": family,
        "base_example": base,
        "expected_error": error,
        "builder_context": context,
        "record": record,
    }


def _candidate() -> SimpleNamespace:
    valid = _example("valid-message", valid=True, record=_record())
    changed = _example(
        "invalid-message-value",
        valid=False,
        record=_record(message=""),
        base="valid-message",
        error="constraint_violation",
    )
    catalog_owned = _example(
        "invalid-bucket",
        valid=False,
        record=_record(bucket="model.io"),
        base="valid-message",
        error="family_bucket_mismatch",
    )
    familyless = _example(
        "invalid-legacy",
        valid=False,
        record=_record(),
        family=None,
        base="valid-message",
        error="compatibility_only_identity_has_no_family",
    )
    examples = (valid, changed, catalog_owned, familyless)
    inputs = (
        _family_input("log.diagnostic.message", "LogDiagnosticMessageInput"),
        _family_input("log.platform.health", "LogPlatformHealthInput"),
        SimpleNamespace(
            declaration_kind="span_event_input",
            declaration_source_id="span.agent.run#checkpoint",
            symbol="SpanAgentRunCheckpointEventInput",
            fields=(),
        ),
    )
    callables = (
        _callable(
            "family_builder",
            "log.diagnostic.message",
            "BuildLogDiagnosticMessage",
            "LogDiagnosticMessageInput",
        ),
        _callable(
            "family_builder",
            "log.platform.health",
            "BuildLogPlatformHealth",
            "LogPlatformHealthInput",
        ),
        _callable(
            "span_event_constructor",
            "span.agent.run#checkpoint",
            "NewSpanAgentRunCheckpointEvent",
            "SpanAgentRunCheckpointEventInput",
        ),
    )
    api_digest = "3" * 64
    symbol_digest = "4" * 64
    api = SimpleNamespace(
        materialized_view_sha256="1" * 64,
        go_symbol_table_sha256=symbol_digest,
        api_plan_sha256=api_digest,
        inputs=inputs,
        callables=callables,
        structured=(),
        descriptors=(
            SimpleNamespace(
                family_id="log.diagnostic.message",
                catalog_contract=SimpleNamespace(descriptor_type_symbol="generatedLogDiagnosticMessageDescriptor"),
            ),
            SimpleNamespace(
                family_id="log.platform.health",
                catalog_contract=SimpleNamespace(descriptor_type_symbol="generatedLogPlatformHealthDescriptor"),
            ),
        ),
        fixtures=tuple(
            SimpleNamespace(
                example_id=item["id"],
                signal=item["signal"],
                family_id=item["family"],
                valid=item["valid"],
                expected_error=item["expected_error"],
                base_example=item["base_example"],
                expected_record_json=json.dumps(
                    item["record"], ensure_ascii=False, sort_keys=True, separators=(",", ":")
                ),
            )
            for item in examples
        ),
    )
    return SimpleNamespace(
        materialized_view_sha256="1" * 64,
        candidate_render_index_sha256="2" * 64,
        api_plan_sha256=api_digest,
        go_symbol_table=SimpleNamespace(table_sha256=symbol_digest),
        go_api_plan=api,
        examples=examples,
    )


def test_compiles_exact_dispositions_resolves_inheritance_and_covers_missing_api(
    compiler: ModuleType,
) -> None:
    result = compiler.compile_go_fixture_plan(_candidate())

    assert result.version == 1
    assert len(result.fixture_plan_sha256) == 64
    cases = {case.case_id: case for case in result.curated_cases}
    assert cases["valid-message"].disposition == "executable_success"
    assert tuple(assertion.arm for assertion in cases["valid-message"].assertions) == (
        "error_absent",
        "exact_record",
        "exact_canonical_json",
        "exact_field_classes",
        "schema_derived_field_classes",
        "exact_mandatory",
    )
    assert cases["invalid-message-value"].disposition == "executable_error"
    assert cases["invalid-message-value"].resolved_context_example_id == "valid-message"
    assert cases["invalid-bucket"].disposition == "schema_only"
    assert cases["invalid-legacy"].disposition == "schema_only"
    assert all(
        case.reason and "exact_base" not in case.reason
        for case in result.curated_cases
        if case.disposition == "schema_only"
    )

    assert len(result.generated_coverage_cases) == 2
    coverage = {case.coverage.callable_key for case in result.generated_coverage_cases}
    assert coverage == {
        ("family_builder", "log.platform.health"),
        ("span_event_constructor", "span.agent.run#checkpoint"),
    }
    platform_coverage = next(
        case.coverage
        for case in result.generated_coverage_cases
        if case.coverage.callable_key == ("family_builder", "log.platform.health")
    )
    assert platform_coverage.descriptor_family_id == "log.platform.health"
    assert platform_coverage.descriptor_type_symbol == "generatedLogPlatformHealthDescriptor"
    assert platform_coverage.receiver_pointer is True
    assert set(result.covered_family_ids) == {
        "log.diagnostic.message",
        "log.platform.health",
    }
    assert set(result.covered_callable_keys) == {
        ("family_builder", "log.diagnostic.message"),
        ("family_builder", "log.platform.health"),
        ("span_event_constructor", "span.agent.run#checkpoint"),
    }
    assert result.file.path == ("internal/observability/zz_generated_telemetry_builder_fixtures_test.go")
    assert result.file.package_name == "observability"
    assert tuple(item.path for item in result.file.imports) == (
        "encoding/json",
        "reflect",
        "testing",
        "time",
    )
    assert result.go_symbol_table_sha256 == "4" * 64
    assert tuple(contract.symbol for contract in result.family_builder_methods) == (
        "BuildLogDiagnosticMessage",
        "BuildLogPlatformHealth",
    )
    assert all(
        contract.receiver_type == compiler.GoFixtureTypeRefIR("named", "FamilyBuilder")
        and contract.receiver_pointer
        and len(contract.parameter_types) == 1
        and contract.parameter_types[0].arm == "named"
        and contract.result_types
        == (
            compiler.GoFixtureTypeRefIR("named", "Record"),
            compiler.GoFixtureTypeRefIR("builtin", "error"),
        )
        and not contract.variadic
        for contract in result.family_builder_methods
    )
    assert result.file.expected_digest_headers == (
        "materialized_view_sha256",
        "candidate_render_index_sha256",
        "go_symbol_table_sha256",
    )
    assert result.file.case_ids == tuple(
        case.case_id for case in (*result.curated_cases, *result.generated_coverage_cases)
    )
    assert tuple(item.order for item in result.file.functions) == tuple(range(len(result.file.functions)))
    assert len({item.symbol for item in result.file.functions}) == len(result.file.functions)
    assert all(item.symbol.startswith("TestGeneratedTelemetry") for item in result.file.functions)


def test_deterministic_clock_id_optional_and_exact_expected_values(compiler: ModuleType) -> None:
    first = compiler.compile_go_fixture_plan(_candidate())
    second = compiler.compile_go_fixture_plan(_candidate())
    assert first == second
    assert first.fixture_plan_sha256 == second.fixture_plan_sha256

    case = first.curated_cases[0]
    builder_call = case.prelude[0].expression
    clock, occurrence_id = builder_call.arguments
    assert clock.arm == "deterministic_clock"
    assert dataclasses.astuple(clock.time_value) == (2026, 7, 4, 12, 0, 0, 123456789)
    assert occurrence_id.arm == "deterministic_occurrence_id"
    assert occurrence_id.scalar.string_value == "record-1"
    assert case.final_call.expression.arguments[0].fields[1].expression.arm == "optional_present"
    assert case.assertions[1].expected_value.arm == "object"
    assert case.assertions[1].expected_text == case.assertions[2].expected_text
    assert case.assertions[2].expected_text.startswith('{"body"')

    candidate = _candidate()
    candidate.go_api_plan.callables[0].symbol = "BuildLogDiagnosticMessageChanged"
    changed = compiler.compile_go_fixture_plan(candidate)
    assert changed.fixture_plan_sha256 != first.fixture_plan_sha256


def test_plan_is_recursively_frozen_and_contains_no_raw_go_arm(compiler: ModuleType) -> None:
    result = compiler.compile_go_fixture_plan(_candidate())
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.version = 2
    expressions = [
        statement.expression
        for case in (*result.curated_cases, *result.generated_coverage_cases)
        for statement in (*case.prelude, *((case.final_call,) if case.final_call else ()))
    ]
    assert all(expression.arm != "raw" for expression in expressions)


def test_mapping_api_plan_cannot_bypass_digest_verification(compiler: ModuleType) -> None:
    with pytest.raises(compiler.GoFixturePlanError, match="canonical typed compiler IR"):
        compiler._verify_api_digest({"api_plan_sha256": "3" * 64}, "3" * 64)


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        ("receiver", r"receiver must be \*FamilyBuilder"),
        ("parameters", "exactly one input"),
        ("unnamed input", "named struct"),
        ("results", r"results must be \(Record, error\)"),
        ("variadic", "nonvariadic"),
    ),
)
def test_family_builder_method_contracts_fail_closed(
    compiler: ModuleType,
    mutation: str,
    message: str,
) -> None:
    candidate = _candidate()
    callable_plan = candidate.go_api_plan.callables[0]
    if mutation == "receiver":
        callable_plan.receiver_pointer = False
    elif mutation == "parameters":
        callable_plan.parameters = ()
    elif mutation == "unnamed input":
        callable_plan.parameters = (("input", _type("builtin", "string")),)
    elif mutation == "results":
        callable_plan.results = (_type("named", "Record"),)
    elif mutation == "variadic":
        callable_plan.variadic = True
    with pytest.raises(compiler.GoFixturePlanError, match=message):
        compiler.compile_go_fixture_plan(candidate)


@pytest.mark.parametrize(
    ("mutate", "message"),
    (
        (lambda candidate: setattr(candidate, "candidate_render_index_sha256", "bad"), "invalid digest"),
        (
            lambda candidate: setattr(candidate.go_api_plan, "materialized_view_sha256", "f" * 64),
            "different materialized view",
        ),
        (
            lambda candidate: setattr(candidate.go_api_plan, "go_symbol_table_sha256", "f" * 64),
            "symbol-table digests disagree",
        ),
        (
            lambda candidate: setattr(candidate.go_api_plan, "fixtures", ()),
            "inventory disagrees",
        ),
        (
            lambda candidate: setattr(
                candidate.go_api_plan,
                "callables",
                candidate.go_api_plan.callables + (candidate.go_api_plan.callables[0],),
            ),
            "duplicate callable",
        ),
    ),
)
def test_rejects_incoherent_candidate_boundaries(
    compiler: ModuleType,
    mutate: Any,
    message: str,
) -> None:
    candidate = _candidate()
    mutate(candidate)
    with pytest.raises(compiler.GoFixturePlanError, match=message):
        compiler.compile_go_fixture_plan(candidate)


def test_rejects_nonfinite_values_and_invalid_contexts(compiler: ModuleType) -> None:
    candidate = _candidate()
    candidate.examples[0]["record"]["body"]["example.message"] = float("nan")
    with pytest.raises(compiler.GoFixturePlanError, match="finite scalar"):
        compiler.compile_go_fixture_plan(candidate)

    candidate = _candidate()
    candidate.examples[1]["builder_context"]["inheritance"]["base_example"] = "invalid-message-value"
    with pytest.raises(compiler.GoFixturePlanError, match="invalid example base"):
        compiler.compile_go_fixture_plan(candidate)


def test_compiler_performs_no_file_or_source_reads(
    compiler: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden_open(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("fixture compiler attempted filesystem I/O")

    monkeypatch.setattr(builtins, "open", forbidden_open)
    result = compiler.compile_go_fixture_plan(_candidate())
    assert result.fixture_plan_sha256


def test_compiler_source_has_no_filesystem_yaml_or_subprocess_capability() -> None:
    tree = ast.parse(FIXTURE_COMPILER.read_text(encoding="utf-8"))
    forbidden_imports = {"pathlib", "os", "subprocess", "yaml"}
    imported = {
        alias.name.split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    called_names = {
        node.func.id for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    called_attributes = {
        node.func.attr for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    assert imported.isdisjoint(forbidden_imports)
    assert called_names.isdisjoint({"open", "exec", "eval", "compile"})
    assert called_attributes.isdisjoint({"read_text", "read_bytes", "write_text", "write_bytes", "open"})


@pytest.fixture(scope="module")
def real_candidate() -> Any:
    generator = _load("telemetry_fixture_real_generator", GENERATOR)
    renderer = _load("telemetry_fixture_real_renderer", CANDIDATE_RENDERER)
    view = generator.compile_registry(ROOT).materialized_view
    return renderer.build_candidate_render_index(view)


def test_real_candidate_has_total_bounded_family_and_callable_coverage(
    compiler: ModuleType,
    real_candidate: Any,
) -> None:
    result = compiler.compile_go_fixture_plan(real_candidate)
    api = real_candidate.go_api_plan

    assert len(result.curated_cases) == len(real_candidate.examples)
    assert result.covered_family_ids == tuple(item.family_id for item in api.descriptors)
    assert result.covered_callable_keys == tuple(
        (item.declaration_kind, item.declaration_source_id) for item in api.callables
    )
    assert len(result.family_builder_methods) == len(api.descriptors)
    assert len(result.generated_coverage_cases) <= len(api.callables) + len(api.descriptors)
    assert len(result.file.functions) == len(result.curated_cases) + len(result.generated_coverage_cases)
    assert result.schema_only_example_ids
    assert all(case.base_example is None for case in api.fixtures) is False
    assert all(case.resolved_context_example_id for case in result.curated_cases)
    assert all(case.disposition != "executable_success" or len(case.assertions) == 6 for case in result.curated_cases)
