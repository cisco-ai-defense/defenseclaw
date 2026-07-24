#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0
"""Compile normalized telemetry examples into a closed executable Go fixture IR.

The compiler is intentionally pure.  It consumes only one renderer-ready
``CandidateRenderIndex`` and the ``GoAPIPlanIR`` embedded in that index.  It
does not import the registry compiler, read YAML, inspect current Go source, or
consult generated/golden bytes.  Renderers receive syntax-complete typed nodes;
there is no raw-Go escape hatch.

Curated vectors have one of two explicit dispositions:

* ``executable_success`` / ``executable_error`` when the generated typed API can
  represent the vector; or
* ``schema_only`` when the vector deliberately mutates catalog-owned state (or
  has no canonical family), which cannot cross the public builder boundary.

Compiler-generated coverage cases are ``compile_only``.  They instantiate the
zero value of every otherwise-uncovered input and retain a typed reference to
every otherwise-uncovered callable.  A zero value is a Go language value, not
invented telemetry data, and compile-only cases make no runtime semantic claim.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import hashlib
import json
import math
import re
from collections.abc import Mapping, Sequence
from typing import Any, Final

if __package__ == "scripts":  # pragma: no cover - package import exercised by subprocess tests
    from .telemetry_canonical_record import (
        CanonicalRecordError,
        canonical_record_json,
        canonicalize_record_json_text,
    )
else:
    from telemetry_canonical_record import (  # type: ignore[no-redef]
        CanonicalRecordError,
        canonical_record_json,
        canonicalize_record_json_text,
    )


class GoFixturePlanError(RuntimeError):
    """A deterministic fixture-compiler contract failure."""


@dataclasses.dataclass(frozen=True, slots=True)
class GoFixtureTypeRefIR:
    arm: str
    name: str | None = None
    element: GoFixtureTypeRefIR | None = None


@dataclasses.dataclass(frozen=True, slots=True)
class GoFixtureScalarIR:
    arm: str
    string_value: str | None = None
    integer_value: int | None = None
    double_value: float | None = None
    boolean_value: bool | None = None


@dataclasses.dataclass(frozen=True, slots=True)
class GoFixtureTimeIR:
    year: int
    month: int
    day: int
    hour: int
    minute: int
    second: int
    nanosecond: int


@dataclasses.dataclass(frozen=True, slots=True)
class GoFixtureObjectFieldIR:
    name: str
    value: GoFixtureValueIR


@dataclasses.dataclass(frozen=True, slots=True)
class GoFixtureValueIR:
    """Closed canonical data tree used only for exact expectations."""

    arm: str
    scalar: GoFixtureScalarIR | None = None
    items: tuple[GoFixtureValueIR, ...] = ()
    fields: tuple[GoFixtureObjectFieldIR, ...] = ()


@dataclasses.dataclass(frozen=True, slots=True)
class GoFixtureCompositeFieldIR:
    selector: str
    expression: GoFixtureExpressionIR


@dataclasses.dataclass(frozen=True, slots=True)
class GoFixtureExpressionIR:
    """Closed Go expression AST; every arm is renderer-mechanical."""

    arm: str
    type_ref: GoFixtureTypeRefIR
    scalar: GoFixtureScalarIR | None = None
    time_value: GoFixtureTimeIR | None = None
    symbol: str | None = None
    fields: tuple[GoFixtureCompositeFieldIR, ...] = ()
    items: tuple[GoFixtureExpressionIR, ...] = ()
    arguments: tuple[GoFixtureExpressionIR, ...] = ()


@dataclasses.dataclass(frozen=True, slots=True)
class GoFixtureStatementIR:
    """One ordered constructor/builder binding."""

    arm: str
    result_names: tuple[str, ...]
    expression: GoFixtureExpressionIR
    require_nil_error: bool


@dataclasses.dataclass(frozen=True, slots=True)
class GoFixtureAssertionIR:
    arm: str
    expected_value: GoFixtureValueIR | None = None
    expected_text: str | None = None
    expected_boolean: bool | None = None


@dataclasses.dataclass(frozen=True, slots=True)
class GoFixtureCoverageIR:
    input_key: tuple[str, str] | None
    input_symbol: str | None
    callable_key: tuple[str, str]
    callable_symbol: str
    receiver_type: GoFixtureTypeRefIR | None
    receiver_pointer: bool
    zero_arguments: tuple[GoFixtureExpressionIR, ...]
    descriptor_family_id: str | None
    descriptor_type_symbol: str | None


@dataclasses.dataclass(frozen=True, slots=True)
class GoFixtureCaseIR:
    case_id: str
    origin: str
    disposition: str
    signal: str | None
    family_id: str | None
    source_example_id: str | None
    resolved_context_example_id: str | None
    reason: str | None
    prelude: tuple[GoFixtureStatementIR, ...]
    final_call: GoFixtureStatementIR | None
    assertions: tuple[GoFixtureAssertionIR, ...]
    coverage: GoFixtureCoverageIR | None


@dataclasses.dataclass(frozen=True, slots=True)
class GoFixtureImportIR:
    path: str
    alias: str | None


@dataclasses.dataclass(frozen=True, slots=True)
class GoFixtureFunctionPlanIR:
    symbol: str
    order: int
    arm: str
    case_id: str
    case_origin: str


@dataclasses.dataclass(frozen=True, slots=True)
class GoFixtureBuilderMethodContractIR:
    """One exact exported ``*FamilyBuilder`` method signature."""

    symbol: str
    receiver_type: GoFixtureTypeRefIR
    receiver_pointer: bool
    parameter_types: tuple[GoFixtureTypeRefIR, ...]
    result_types: tuple[GoFixtureTypeRefIR, ...]
    variadic: bool


@dataclasses.dataclass(frozen=True, slots=True)
class GoFixtureFilePlanIR:
    path: str
    package_name: str
    imports: tuple[GoFixtureImportIR, ...]
    functions: tuple[GoFixtureFunctionPlanIR, ...]
    case_ids: tuple[str, ...]
    expected_digest_headers: tuple[str, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class GoFixturePlanIR:
    version: int
    materialized_view_sha256: str
    candidate_render_index_sha256: str
    go_symbol_table_sha256: str
    go_api_plan_sha256: str
    family_builder_methods: tuple[GoFixtureBuilderMethodContractIR, ...]
    curated_cases: tuple[GoFixtureCaseIR, ...]
    generated_coverage_cases: tuple[GoFixtureCaseIR, ...]
    covered_family_ids: tuple[str, ...]
    covered_callable_keys: tuple[tuple[str, str], ...]
    schema_only_example_ids: tuple[str, ...]
    file: GoFixtureFilePlanIR
    fixture_plan_sha256: str


_DIGEST_DOMAIN: Final = b"DefenseClaw GoFixturePlanIR v1\x00"
_API_DIGEST_DOMAIN: Final = b"DefenseClaw GoAPIPlanIR v1\x00"
_SHA256: Final = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER: Final = re.compile(r"^[A-Za-z][A-Za-z0-9]*$")
_QUALIFIED_IDENTIFIER: Final = re.compile(r"^[A-Za-z][A-Za-z0-9]*\.[A-Za-z][A-Za-z0-9]*$")
_CASE_ID: Final = re.compile(r"^[a-z][a-z0-9-]{0,127}$")
_RFC3339_UTC: Final = re.compile(
    r"^(?P<year>[0-9]{4})-(?P<month>[0-9]{2})-(?P<day>[0-9]{2})T"
    r"(?P<hour>[0-9]{2}):(?P<minute>[0-9]{2}):(?P<second>[0-9]{2})"
    r"(?:\.(?P<fraction>[0-9]{1,9}))?Z$"
)

_MAX_EXAMPLES: Final = 4096
_MAX_INPUTS: Final = 4096
_MAX_CALLABLES: Final = 8192
_MAX_FIELDS_PER_INPUT: Final = 1024
_MAX_VALUE_DEPTH: Final = 64
_MAX_VALUE_NODES: Final = 131_072

_TYPE_ARMS: Final = frozenset({"builtin", "named", "qualified", "optional", "slice", "pointer"})
_BUILTINS: Final = frozenset({"string", "bool", "int", "int64", "uint32", "uint64", "float64", "error"})
_DISPOSITIONS: Final = frozenset({"executable_success", "executable_error", "schema_only", "compile_only"})
_FIXTURE_OUTPUT_PATH: Final = "internal/observability/zz_generated_telemetry_builder_fixtures_test.go"
_FIXTURE_IMPORTS: Final = (
    ("encoding/json", None),
    ("reflect", None),
    ("testing", None),
    ("time", None),
)
_DIGEST_HEADERS: Final = (
    "materialized_view_sha256",
    "candidate_render_index_sha256",
    "go_symbol_table_sha256",
)

_CORRELATION_SELECTORS: Final = {
    "run_id": "RunID",
    "request_id": "RequestID",
    "session_id": "SessionID",
    "turn_id": "TurnID",
    "trace_id": "TraceID",
    "span_id": "SpanID",
    "agent_id": "AgentID",
    "agent_instance_id": "AgentInstanceID",
    "policy_id": "PolicyID",
    "policy_version": "PolicyVersion",
    "evaluation_id": "EvaluationID",
    "scan_id": "ScanID",
    "finding_occurrence_id": "FindingOccurrenceID",
    "enforcement_action_id": "EnforcementActionID",
    "model_request_id": "ModelRequestID",
    "model_response_id": "ModelResponseID",
    "tool_invocation_id": "ToolInvocationID",
    "destination_id": "DestinationID",
    "connector_id": "ConnectorID",
    "sidecar_instance_id": "SidecarInstanceID",
}
_PROVENANCE_SELECTORS: Final = {
    "producer": "Producer",
    "binary_version": "BinaryVersion",
    "config_generation": "ConfigGeneration",
    "build_commit": "BuildCommit",
    "config_digest": "ConfigDigest",
}
_COMMON_RECORD_PATHS: Final = {
    "Severity": ("severity",),
    "LogLevel": ("log_level",),
    "Outcome": ("outcome",),
    "Kind": ("body", "kind"),
    "StartTimeUnixNano": ("body", "start_time_unix_nano"),
    "EndTimeUnixNano": ("body", "end_time_unix_nano"),
    "ParentSpanID": ("body", "parent_span_id"),
    "TraceState": ("body", "trace_state"),
    "Flags": ("body", "flags"),
    "DroppedAttributesCount": ("body", "dropped_attributes_count"),
    "DroppedEventsCount": ("body", "dropped_events_count"),
    "DroppedLinksCount": ("body", "dropped_links_count"),
    "Value": ("instrument_data", "value"),
}


def _read(value: Any, name: str, path: str) -> Any:
    if isinstance(value, Mapping):
        if set(value) == {"$type", "fields"} and isinstance(value.get("fields"), Mapping):
            value = value["fields"]
        if name not in value:
            raise GoFixturePlanError(f"{path}.{name}: required compiler fact is missing")
        return value[name]
    try:
        return getattr(value, name)
    except AttributeError as exc:
        raise GoFixturePlanError(f"{path}.{name}: required compiler fact is missing") from exc


def _optional(value: Any, name: str, default: Any = None) -> Any:
    if isinstance(value, Mapping):
        if set(value) == {"$type", "fields"} and isinstance(value.get("fields"), Mapping):
            value = value["fields"]
        return value.get(name, default)
    return getattr(value, name, default)


def _sequence(value: Any, path: str, *, maximum: int) -> tuple[Any, ...]:
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        raise GoFixturePlanError(f"{path}: expected bounded sequence")
    result = tuple(value)
    if len(result) > maximum:
        raise GoFixturePlanError(f"{path}: sequence exceeds compiler bound")
    return result


def _string(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value:
        raise GoFixturePlanError(f"{path}: expected non-empty string")
    return value


def _mapping(value: Any, path: str) -> Mapping[str, Any]:
    if isinstance(value, Mapping) and set(value) == {"$type", "fields"} and isinstance(value.get("fields"), Mapping):
        value = value["fields"]
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise GoFixturePlanError(f"{path}: expected string-keyed mapping")
    return value


def _identifier(value: Any, path: str) -> str:
    result = _string(value, path)
    if _IDENTIFIER.fullmatch(result) is None:
        raise GoFixturePlanError(f"{path}: invalid Go identifier")
    return result


def _type_ref(raw: Any, path: str) -> GoFixtureTypeRefIR:
    arm = _string(_read(raw, "arm", path), f"{path}.arm")
    name = _optional(raw, "name")
    element = _optional(raw, "element")
    if arm not in _TYPE_ARMS:
        raise GoFixturePlanError(f"{path}: unsupported Go type arm")
    if arm in {"builtin", "named", "qualified"}:
        if arm == "qualified":
            parsed = _string(name, f"{path}.name")
            if _QUALIFIED_IDENTIFIER.fullmatch(parsed) is None:
                raise GoFixturePlanError(f"{path}: invalid qualified Go identifier")
        else:
            parsed = _identifier(name, f"{path}.name")
        if arm == "builtin" and parsed not in _BUILTINS:
            raise GoFixturePlanError(f"{path}: unsupported builtin type")
        if element is not None:
            raise GoFixturePlanError(f"{path}: scalar type has an element")
        return GoFixtureTypeRefIR(arm, parsed)
    if name is not None or element is None:
        raise GoFixturePlanError(f"{path}: container type is incomplete")
    return GoFixtureTypeRefIR(arm, element=_type_ref(element, f"{path}.element"))


def _scalar(value: Any, path: str) -> GoFixtureScalarIR:
    if isinstance(value, str):
        return GoFixtureScalarIR("string", string_value=value)
    if isinstance(value, bool):
        return GoFixtureScalarIR("boolean", boolean_value=value)
    if isinstance(value, int):
        return GoFixtureScalarIR("integer", integer_value=value)
    if isinstance(value, float) and math.isfinite(value):
        return GoFixtureScalarIR("double", double_value=value)
    raise GoFixturePlanError(f"{path}: expected finite scalar")


def _value(value: Any, path: str, *, depth: int = 0, budget: list[int] | None = None) -> GoFixtureValueIR:
    if depth > _MAX_VALUE_DEPTH:
        raise GoFixturePlanError(f"{path}: canonical value exceeds depth bound")
    if budget is None:
        budget = [_MAX_VALUE_NODES]
    budget[0] -= 1
    if budget[0] < 0:
        raise GoFixturePlanError(f"{path}: canonical value exceeds node bound")
    if value is None:
        return GoFixtureValueIR("null")
    if isinstance(value, (str, bool, int, float)):
        return GoFixtureValueIR("scalar", scalar=_scalar(value, path))
    if isinstance(value, Mapping):
        raw = _mapping(value, path)
        return GoFixtureValueIR(
            "object",
            fields=tuple(
                GoFixtureObjectFieldIR(key, _value(raw[key], f"{path}.{key}", depth=depth + 1, budget=budget))
                for key in sorted(raw)
            ),
        )
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        items = tuple(value)
        if len(items) > _MAX_VALUE_NODES:
            raise GoFixturePlanError(f"{path}: canonical sequence exceeds node bound")
        return GoFixtureValueIR(
            "sequence",
            items=tuple(
                _value(item, f"{path}[{position}]", depth=depth + 1, budget=budget)
                for position, item in enumerate(items)
            ),
        )
    raise GoFixturePlanError(f"{path}: unsupported canonical value")


def _time(value: Any, path: str) -> GoFixtureTimeIR:
    text = _string(value, path)
    match = _RFC3339_UTC.fullmatch(text)
    if match is None:
        raise GoFixturePlanError(f"{path}: expected canonical UTC RFC3339 timestamp")
    pieces = {key: int(match.group(key)) for key in ("year", "month", "day", "hour", "minute", "second")}
    if pieces["second"] > 59:
        raise GoFixturePlanError(f"{path}: leap-second timestamps are unsupported")
    try:
        dt.datetime(**pieces, tzinfo=dt.UTC)
    except ValueError as exc:
        raise GoFixturePlanError(f"{path}: invalid calendar timestamp") from exc
    fraction = match.group("fraction") or ""
    return GoFixtureTimeIR(**pieces, nanosecond=int(fraction.ljust(9, "0") or "0"))


def _plain_expected(value: GoFixtureValueIR) -> Any:
    if value.arm == "null":
        return None
    if value.arm == "sequence":
        return [_plain_expected(item) for item in value.items]
    if value.arm == "object":
        return {field.name: _plain_expected(field.value) for field in value.fields}
    if value.arm != "scalar" or value.scalar is None:
        raise GoFixturePlanError("expected fixture value has an invalid arm")
    scalar = value.scalar
    if scalar.arm == "string":
        return scalar.string_value
    if scalar.arm == "integer":
        return scalar.integer_value
    if scalar.arm == "double":
        return scalar.double_value
    if scalar.arm == "boolean":
        return scalar.boolean_value
    raise GoFixturePlanError("expected fixture scalar has an invalid arm")


def _canonical_expected_record(value: Any, path: str) -> str:
    try:
        return canonical_record_json(value)
    except CanonicalRecordError as exc:
        raise GoFixturePlanError(f"{path}: canonical record expectation is invalid") from exc


def _canonical_embedded_record(value: Any, path: str) -> str:
    try:
        return canonicalize_record_json_text(_string(value, path))
    except CanonicalRecordError as exc:
        raise GoFixturePlanError(f"{path}: embedded record JSON is invalid") from exc


def _zero(type_ref: GoFixtureTypeRefIR) -> GoFixtureExpressionIR:
    return GoFixtureExpressionIR("zero", type_ref)


def _literal(type_ref: GoFixtureTypeRefIR, value: Any, path: str) -> GoFixtureExpressionIR:
    return GoFixtureExpressionIR("literal", type_ref, scalar=_scalar(value, path))


def _symbol(type_ref: GoFixtureTypeRefIR, symbol: str) -> GoFixtureExpressionIR:
    return GoFixtureExpressionIR("symbol", type_ref, symbol=_identifier(symbol, "fixture symbol"))


def _call(type_ref: GoFixtureTypeRefIR, symbol: str, *arguments: GoFixtureExpressionIR) -> GoFixtureExpressionIR:
    return GoFixtureExpressionIR(
        "call", type_ref, symbol=_identifier(symbol, "fixture call symbol"), arguments=tuple(arguments)
    )


def _composite(type_ref: GoFixtureTypeRefIR, fields: Sequence[GoFixtureCompositeFieldIR]) -> GoFixtureExpressionIR:
    return GoFixtureExpressionIR("composite", type_ref, fields=tuple(fields))


def _path(record: Mapping[str, Any], components: Sequence[str]) -> tuple[bool, Any]:
    current: Any = record
    for component in components:
        if not isinstance(current, Mapping) or component not in current:
            return False, None
        current = current[component]
    return True, current


def _fact_map(context: Mapping[str, Any], name: str, path: str) -> dict[str, bool]:
    raw = context.get(name, ())
    if isinstance(raw, Mapping):
        pairs = tuple(raw.items())
    else:
        pairs = tuple(
            (_read(item, "fact", f"{path}.{name}"), _read(item, "value", f"{path}.{name}"))
            for item in _sequence(raw, f"{path}.{name}", maximum=4096)
        )
    result: dict[str, bool] = {}
    for fact, value in pairs:
        fact = _string(fact, f"{path}.{name}.fact")
        if type(value) is not bool or fact in result:
            raise GoFixturePlanError(f"{path}.{name}: invalid or duplicate fact")
        result[fact] = value
    return result


def _context_parts(
    context: Any, path: str
) -> tuple[str, str | None, GoFixtureTimeIR | None, str | None, dict[str, bool], dict[str, bool]]:
    raw = _mapping(context, path)
    inheritance = _mapping(raw.get("inheritance"), f"{path}.inheritance")
    mode = _string(inheritance.get("mode"), f"{path}.inheritance.mode")
    base = inheritance.get("base_example")
    if base is not None and not isinstance(base, str):
        raise GoFixturePlanError(f"{path}.inheritance.base_example: invalid ID")
    occurrence = raw.get("occurrence")
    parsed_time = None
    record_id = None
    if occurrence is not None:
        occurrence = _mapping(occurrence, f"{path}.occurrence")
        parsed_time = _time(occurrence.get("timestamp"), f"{path}.occurrence.timestamp")
        record_id = _string(occurrence.get("record_id"), f"{path}.occurrence.record_id")
    return (
        mode,
        base,
        parsed_time,
        record_id,
        _fact_map(raw, "condition_facts", path),
        _fact_map(raw, "mandatory_facts", path),
    )


class _InputCompiler:
    def __init__(
        self,
        api: Any,
        record: Mapping[str, Any],
        context: tuple[Any, ...],
        path: str,
        family_id: str,
    ) -> None:
        self.api = api
        self.record = record
        self.mode, self.base, self.timestamp, self.record_id, self.conditions, self.mandatory = context
        self.path = path
        self.family_id = family_id
        self.prelude: list[GoFixtureStatementIR] = []
        self.constructor_index = 0
        self.inputs = {
            (
                _string(_read(item, "declaration_kind", "go_api.input"), "go_api.input.kind"),
                _string(_read(item, "declaration_source_id", "go_api.input"), "go_api.input.source"),
            ): item
            for item in _sequence(_read(api, "inputs", "go_api"), "go_api.inputs", maximum=_MAX_INPUTS)
        }
        self.callables = {
            (
                _string(_read(item, "declaration_kind", "go_api.callable"), "go_api.callable.kind"),
                _string(_read(item, "declaration_source_id", "go_api.callable"), "go_api.callable.source"),
            ): item
            for item in _sequence(_read(api, "callables", "go_api"), "go_api.callables", maximum=_MAX_CALLABLES)
        }
        descriptors = {
            _string(_read(item, "family_id", "go_api.descriptor"), "go_api.descriptor.family_id"): item
            for item in _sequence(_read(api, "descriptors", "go_api"), "go_api.descriptors", maximum=_MAX_INPUTS)
        }
        self.descriptor = descriptors.get(family_id)
        if self.descriptor is None:
            raise GoFixturePlanError(f"{path}: family descriptor is missing")
        self.family_input_plan: Any = None
        self.structured = {
            _string(_read(item, "symbol", "go_api.structured"), "go_api.structured.symbol"): item
            for item in _sequence(_read(api, "structured", "go_api"), "go_api.structured", maximum=_MAX_INPUTS)
        }

    def bind_constructor(
        self,
        callable_plan: Any,
        arguments: tuple[GoFixtureExpressionIR, ...],
        prefix: str,
    ) -> GoFixtureExpressionIR:
        symbol = _identifier(_read(callable_plan, "symbol", self.path), f"{self.path}.constructor.symbol")
        results = _sequence(_read(callable_plan, "results", self.path), f"{self.path}.{symbol}.results", maximum=4)
        if len(results) != 2:
            raise GoFixturePlanError(f"{self.path}.{symbol}: constructor must return value and error")
        result_type = _type_ref(results[0], f"{self.path}.{symbol}.result")
        error_type = _type_ref(results[1], f"{self.path}.{symbol}.error")
        if error_type != GoFixtureTypeRefIR("builtin", "error"):
            raise GoFixturePlanError(f"{self.path}.{symbol}: constructor error result is invalid")
        suffix = self.constructor_index
        self.constructor_index += 1
        result_name = f"{prefix}{suffix}"
        error_name = f"{prefix}Err{suffix}"
        expression = _call(result_type, symbol, *arguments)
        self.prelude.append(GoFixtureStatementIR("bind_call", (result_name, error_name), expression, True))
        return _symbol(result_type, result_name)

    def typed(self, type_ref: GoFixtureTypeRefIR, value: Any, path: str) -> GoFixtureExpressionIR:
        if type_ref.arm == "optional":
            assert type_ref.element is not None
            if value is None:
                return GoFixtureExpressionIR("optional_absent", type_ref)
            return GoFixtureExpressionIR(
                "optional_present", type_ref, arguments=(self.typed(type_ref.element, value, path),)
            )
        if type_ref.arm == "slice":
            assert type_ref.element is not None
            items = _sequence(value, path, maximum=_MAX_VALUE_NODES)
            return GoFixtureExpressionIR(
                "slice",
                type_ref,
                items=tuple(self.typed(type_ref.element, item, f"{path}[{i}]") for i, item in enumerate(items)),
            )
        if type_ref.arm == "builtin":
            if type_ref.name == "string" and isinstance(value, str):
                return _literal(type_ref, value, path)
            if type_ref.name == "bool" and type(value) is bool:
                return _literal(type_ref, value, path)
            if (
                type_ref.name in {"int", "int64", "uint32", "uint64"}
                and isinstance(value, int)
                and not isinstance(value, bool)
            ):
                if type_ref.name.startswith("uint") and value < 0:
                    raise GoFixturePlanError(f"{path}: unsigned value is negative")
                return _literal(type_ref, value, path)
            if (
                type_ref.name == "float64"
                and isinstance(value, (int, float))
                and not isinstance(value, bool)
                and math.isfinite(value)
            ):
                return _literal(type_ref, float(value), path)
            raise GoFixturePlanError(f"{path}: value disagrees with builtin {type_ref.name}")
        if type_ref.arm != "named" or type_ref.name is None:
            raise GoFixturePlanError(f"{path}: unsupported type")
        if type_ref.name in {"Severity", "LogLevel", "Outcome", "Source", "Bucket", "EventName"}:
            if not isinstance(value, str):
                raise GoFixturePlanError(f"{path}: named scalar requires string")
            return GoFixtureExpressionIR(
                "conversion", type_ref, arguments=(_literal(GoFixtureTypeRefIR("builtin", "string"), value, path),)
            )
        structured = self.structured.get(type_ref.name)
        if structured is not None:
            return self.structured_value(type_ref, structured, value, path)
        raise GoFixturePlanError(f"{path}: unsupported named value type {type_ref.name}")

    def structured_value(self, type_ref: GoFixtureTypeRefIR, plan: Any, value: Any, path: str) -> GoFixtureExpressionIR:
        shape = _string(_read(plan, "shape", path), f"{path}.shape")
        if shape == "array":
            item_type = _type_ref(_read(plan, "item_type", path), f"{path}.item_type")
            items = _sequence(value, path, maximum=_MAX_VALUE_NODES)
            return _composite(
                type_ref,
                (
                    GoFixtureCompositeFieldIR(
                        "Items",
                        GoFixtureExpressionIR(
                            "slice",
                            GoFixtureTypeRefIR("slice", element=item_type),
                            items=tuple(self.typed(item_type, item, f"{path}[{i}]") for i, item in enumerate(items)),
                        ),
                    ),
                ),
            )
        if shape != "object":
            raise GoFixturePlanError(f"{path}: structured union requires an authored arm representation")
        raw = _mapping(value, path)
        fields: list[GoFixtureCompositeFieldIR] = []
        consumed: set[str] = set()
        declared = _sequence(
            _read(plan, "declaration_fields", path), f"{path}.declaration_fields", maximum=_MAX_FIELDS_PER_INPUT
        )
        for position, field in enumerate(declared):
            selector = _identifier(_read(field, "selector", path), f"{path}.fields[{position}].selector")
            semantic = _string(
                _read(field, "semantic_source_id", path), f"{path}.fields[{position}].semantic_source_id"
            )
            field_type = _type_ref(_read(field, "type_ref", path), f"{path}.fields[{position}].type")
            if selector == "Entries":
                continue
            if semantic in raw:
                consumed.add(semantic)
                fields.append(
                    GoFixtureCompositeFieldIR(selector, self.typed(field_type, raw[semantic], f"{path}.{semantic}"))
                )
            elif field_type.arm == "optional":
                fields.append(GoFixtureCompositeFieldIR(selector, self.typed(field_type, None, f"{path}.{semantic}")))
            else:
                raise GoFixturePlanError(f"{path}: required structured field {semantic} is missing")
        remaining = tuple(sorted(set(raw) - consumed))
        if remaining:
            members = _sequence(_read(plan, "members", path), f"{path}.members", maximum=4)
            entries_field = next(
                (item for item in declared if _read(item, "selector", path) == "Entries"),
                None,
            )
            if len(members) != 1 or entries_field is None:
                raise GoFixturePlanError(f"{path}: unregistered structured members are forbidden")
            member = members[0]
            source_id = _string(_read(member, "source_id", path), f"{path}.member.source")
            callable_plan = self.callables.get(("structured_member_constructor", source_id))
            if callable_plan is None:
                raise GoFixturePlanError(f"{path}: dynamic member constructor is missing")
            member_fields = _sequence(_read(member, "fields", path), f"{path}.member.fields", maximum=2)
            by_selector = {
                _read(item, "selector", path): _type_ref(_read(item, "type_ref", path), f"{path}.member.type")
                for item in member_fields
            }
            if set(by_selector) != {"Name", "Value"}:
                raise GoFixturePlanError(f"{path}: dynamic member input is not closed")
            entries_type = _type_ref(_read(entries_field, "type_ref", path), f"{path}.Entries.type")
            if entries_type.arm != "slice" or entries_type.element is None:
                raise GoFixturePlanError(f"{path}: dynamic Entries field is not a slice")
            entries = tuple(
                self.bind_constructor(
                    callable_plan,
                    (
                        self.typed(by_selector["Name"], name, f"{path}.{name}.name"),
                        self.typed(by_selector["Value"], raw[name], f"{path}.{name}.value"),
                    ),
                    "structuredMember",
                )
                for name in remaining
            )
            fields.append(
                GoFixtureCompositeFieldIR("Entries", GoFixtureExpressionIR("slice", entries_type, items=entries))
            )
        return _composite(type_ref, fields)

    def envelope(self, type_ref: GoFixtureTypeRefIR) -> GoFixtureExpressionIR:
        observed = self.record.get("observed_at")
        time_type = GoFixtureTypeRefIR("qualified", "time.Time")
        observed_type = GoFixtureTypeRefIR("optional", element=time_type)
        if observed is None:
            observed_expr = GoFixtureExpressionIR("optional_absent", observed_type)
        else:
            observed_expr = GoFixtureExpressionIR(
                "optional_present",
                observed_type,
                arguments=(
                    GoFixtureExpressionIR("time", time_type, time_value=_time(observed, f"{self.path}.observed_at")),
                ),
            )
        correlation = _mapping(self.record.get("correlation", {}), f"{self.path}.correlation")
        if set(correlation) - set(_CORRELATION_SELECTORS):
            raise GoFixturePlanError(f"{self.path}.correlation: unknown canonical field")
        correlation_expr = _composite(
            GoFixtureTypeRefIR("named", "Correlation"),
            tuple(
                GoFixtureCompositeFieldIR(
                    _CORRELATION_SELECTORS[key],
                    _literal(
                        GoFixtureTypeRefIR("builtin", "string"), correlation[key], f"{self.path}.correlation.{key}"
                    ),
                )
                for key in _CORRELATION_SELECTORS
                if key in correlation
            ),
        )
        provenance = _mapping(self.record.get("provenance"), f"{self.path}.provenance")
        if set(provenance) - (set(_PROVENANCE_SELECTORS) | {"registry_schema_version"}):
            raise GoFixturePlanError(f"{self.path}.provenance: unknown canonical field")
        required = {"producer", "binary_version", "config_generation"}
        if not required <= set(provenance):
            raise GoFixturePlanError(f"{self.path}.provenance: required builder fields are missing")
        provenance_fields = []
        for key, selector in _PROVENANCE_SELECTORS.items():
            if key not in provenance:
                continue
            builtin = "int64" if key == "config_generation" else "string"
            provenance_fields.append(
                GoFixtureCompositeFieldIR(
                    selector,
                    _literal(GoFixtureTypeRefIR("builtin", builtin), provenance[key], f"{self.path}.provenance.{key}"),
                )
            )
        return _composite(
            type_ref,
            (
                GoFixtureCompositeFieldIR("ObservedAt", observed_expr),
                GoFixtureCompositeFieldIR(
                    "Source",
                    self.typed(GoFixtureTypeRefIR("named", "Source"), self.record.get("source"), f"{self.path}.source"),
                ),
                GoFixtureCompositeFieldIR(
                    "Connector",
                    _literal(
                        GoFixtureTypeRefIR("builtin", "string"),
                        self.record.get("connector", ""),
                        f"{self.path}.connector",
                    ),
                ),
                GoFixtureCompositeFieldIR(
                    "Action",
                    _literal(
                        GoFixtureTypeRefIR("builtin", "string"), self.record.get("action", ""), f"{self.path}.action"
                    ),
                ),
                GoFixtureCompositeFieldIR(
                    "Phase",
                    _literal(
                        GoFixtureTypeRefIR("builtin", "string"), self.record.get("phase", ""), f"{self.path}.phase"
                    ),
                ),
                GoFixtureCompositeFieldIR("Correlation", correlation_expr),
                GoFixtureCompositeFieldIR(
                    "Provenance", _composite(GoFixtureTypeRefIR("named", "FamilyProvenanceInput"), provenance_fields)
                ),
            ),
        )

    def status(self, type_ref: GoFixtureTypeRefIR) -> GoFixtureExpressionIR:
        present, raw = _path(self.record, ("body", "status"))
        status = _mapping(raw, f"{self.path}.body.status") if present else {}
        code = status.get("code")
        if code == "UNSET" and set(status) == {"code"}:
            return _call(type_ref, "NewTraceStatusUnset")
        if code == "OK" and set(status) == {"code"}:
            return _call(type_ref, "NewTraceStatusOK")
        if code == "ERROR" and set(status) <= {"code", "description"}:
            optional = GoFixtureTypeRefIR("optional", element=GoFixtureTypeRefIR("builtin", "string"))
            description = self.typed(optional, status.get("description"), f"{self.path}.body.status.description")
            return _call(type_ref, "NewTraceStatusError", description)
        raise GoFixturePlanError(f"{self.path}.body.status: invalid closed trace status")

    def resource(self, type_ref: GoFixtureTypeRefIR) -> GoFixtureExpressionIR:
        present, raw = _path(self.record, ("body", "resource"))
        resource = _mapping(raw, f"{self.path}.body.resource") if present else {}
        optional = GoFixtureTypeRefIR("optional", element=GoFixtureTypeRefIR("builtin", "uint32"))
        return _composite(
            type_ref,
            (
                GoFixtureCompositeFieldIR(
                    "SchemaURL",
                    _literal(
                        GoFixtureTypeRefIR("builtin", "string"),
                        resource.get("schema_url", ""),
                        f"{self.path}.body.resource.schema_url",
                    ),
                ),
                GoFixtureCompositeFieldIR(
                    "DroppedAttributesCount",
                    self.typed(
                        optional,
                        resource.get("dropped_attributes_count"),
                        f"{self.path}.body.resource.dropped_attributes_count",
                    ),
                ),
            ),
        )

    def scope(self, type_ref: GoFixtureTypeRefIR) -> GoFixtureExpressionIR:
        present, raw = _path(self.record, ("body", "scope"))
        scope = _mapping(raw, f"{self.path}.body.scope") if present else {}
        optional = GoFixtureTypeRefIR("optional", element=GoFixtureTypeRefIR("builtin", "uint32"))
        return _composite(
            type_ref,
            (
                GoFixtureCompositeFieldIR(
                    "DroppedAttributesCount",
                    self.typed(
                        optional,
                        scope.get("dropped_attributes_count"),
                        f"{self.path}.body.scope.dropped_attributes_count",
                    ),
                ),
            ),
        )

    def component_input(
        self,
        input_plan: Any,
        item: Mapping[str, Any],
        component: str,
        path: str,
    ) -> GoFixtureExpressionIR:
        symbol = _identifier(_read(input_plan, "symbol", path), f"{path}.input.symbol")
        raw_fields = _sequence(_read(input_plan, "fields", path), f"{path}.input.fields", maximum=_MAX_FIELDS_PER_INPUT)
        fields: list[GoFixtureCompositeFieldIR] = []
        common_paths = {
            "event": {
                "TimeUnixNano": ("time_unix_nano",),
                "DroppedAttributesCount": ("dropped_attributes_count",),
            },
            "link": {
                "TraceID": ("trace_id",),
                "SpanID": ("span_id",),
                "TraceState": ("trace_state",),
                "DroppedAttributesCount": ("dropped_attributes_count",),
            },
        }[component]
        target_slot = {"event": "trace.event.attributes", "link": "trace.link.attributes"}[component]
        for raw_field in raw_fields:
            selector = _identifier(_read(raw_field, "selector", path), f"{path}.selector")
            type_ref = _type_ref(_read(raw_field, "type_ref", path), f"{path}.{selector}.type")
            conversion = _string(_read(raw_field, "conversion_op", path), f"{path}.{selector}.conversion")
            semantic = _string(_read(raw_field, "semantic_source_id", path), f"{path}.{selector}.semantic")
            target = _string(_read(raw_field, "target_slot", path), f"{path}.{selector}.target")
            if conversion == "condition_fact":
                if semantic not in self.conditions:
                    raise GoFixturePlanError(f"{path}: condition fact {semantic} is missing")
                raw_value: Any = self.conditions[semantic]
                present = True
            elif selector in common_paths:
                present, raw_value = _path(item, common_paths[selector])
            elif target == target_slot:
                present, raw_value = _path(item, ("attributes", semantic))
            else:
                raise GoFixturePlanError(f"{path}.{selector}: invalid component target slot")
            if not present:
                if type_ref.arm != "optional":
                    raise GoFixturePlanError(f"{path}.{selector}: required component value is missing")
                raw_value = None
            fields.append(GoFixtureCompositeFieldIR(selector, self.typed(type_ref, raw_value, f"{path}.{selector}")))
        return _composite(GoFixtureTypeRefIR("named", symbol), fields)

    def events(self, type_ref: GoFixtureTypeRefIR, raw_value: Any) -> GoFixtureExpressionIR:
        if type_ref.arm != "slice" or type_ref.element is None:
            raise GoFixturePlanError(f"{self.path}.Events: family input type is invalid")
        items = _sequence(raw_value, f"{self.path}.body.events", maximum=_MAX_VALUE_NODES)
        contracts = _sequence(
            _read(self.descriptor, "event_contracts", self.path),
            f"{self.path}.descriptor.event_contracts",
            maximum=_MAX_INPUTS,
        )
        by_name = {
            _string(contract[1], f"{self.path}.event_contract.name"): _string(
                contract[0], f"{self.path}.event_contract.source"
            )
            for contract in contracts
        }
        results: list[GoFixtureExpressionIR] = []
        for position, raw_item in enumerate(items):
            path = f"{self.path}.body.events[{position}]"
            item = _mapping(raw_item, path)
            name = _string(item.get("name"), f"{path}.name")
            source_id = by_name.get(name)
            if source_id is None:
                raise GoFixturePlanError(f"{path}: event is not registered for the family")
            input_plan = self.inputs.get(("span_event_input", source_id))
            callable_plan = self.callables.get(("span_event_constructor", source_id))
            if input_plan is None or callable_plan is None:
                raise GoFixturePlanError(f"{path}: typed event API is incomplete")
            input_expression = self.component_input(input_plan, item, "event", path)
            results.append(self.bind_constructor(callable_plan, (input_expression,), "traceEvent"))
        return GoFixtureExpressionIR("slice", type_ref, items=tuple(results))

    def links(self, type_ref: GoFixtureTypeRefIR, raw_value: Any) -> GoFixtureExpressionIR:
        if type_ref.arm != "slice" or type_ref.element is None:
            raise GoFixturePlanError(f"{self.path}.Links: family input type is invalid")
        items = _sequence(raw_value, f"{self.path}.body.links", maximum=_MAX_VALUE_NODES)
        contracts = _sequence(
            _read(self.descriptor, "link_contracts", self.path),
            f"{self.path}.descriptor.link_contracts",
            maximum=_MAX_INPUTS,
        )
        sources = _sequence(
            _read(self.family_input_plan, "referenced_link_inputs", self.path),
            f"{self.path}.input.referenced_link_inputs",
            maximum=_MAX_INPUTS,
        )
        if len(contracts) != len(sources):
            raise GoFixturePlanError(f"{self.path}: link descriptor and API ordering disagree")
        source_by_relation = {
            _string(contract[0], f"{self.path}.link_contract.relation"): _string(
                source_id, f"{self.path}.link_contract.source"
            )
            for contract, source_id in zip(contracts, sources, strict=True)
        }
        results: list[GoFixtureExpressionIR] = []
        for position, raw_item in enumerate(items):
            path = f"{self.path}.body.links[{position}]"
            item = _mapping(raw_item, path)
            attributes = _mapping(item.get("attributes", {}), f"{path}.attributes")
            relation = item.get("relation", attributes.get("defenseclaw.link.relation"))
            relation = _string(relation, f"{path}.relation")
            source_id = source_by_relation.get(relation)
            if source_id is None:
                raise GoFixturePlanError(f"{path}: link relation is not registered for the family")
            input_plan = self.inputs.get(("span_link_input", source_id))
            callable_plan = self.callables.get(("span_link_constructor", source_id))
            if input_plan is None or callable_plan is None:
                raise GoFixturePlanError(f"{path}: typed link API is incomplete")
            input_expression = self.component_input(input_plan, item, "link", path)
            results.append(self.bind_constructor(callable_plan, (input_expression,), "traceLink"))
        return GoFixtureExpressionIR("slice", type_ref, items=tuple(results))

    def field(self, raw_field: Any) -> GoFixtureCompositeFieldIR:
        selector = _identifier(_read(raw_field, "selector", self.path), f"{self.path}.selector")
        type_ref = _type_ref(_read(raw_field, "type_ref", self.path), f"{self.path}.{selector}.type")
        conversion = _string(_read(raw_field, "conversion_op", self.path), f"{self.path}.{selector}.conversion")
        semantic = _string(_read(raw_field, "semantic_source_id", self.path), f"{self.path}.{selector}.semantic")
        target = _string(_read(raw_field, "target_slot", self.path), f"{self.path}.{selector}.target")
        if selector == "Envelope":
            return GoFixtureCompositeFieldIR(selector, self.envelope(type_ref))
        if selector == "Status":
            return GoFixtureCompositeFieldIR(selector, self.status(type_ref))
        if selector == "Resource":
            return GoFixtureCompositeFieldIR(selector, self.resource(type_ref))
        if selector == "Scope":
            return GoFixtureCompositeFieldIR(selector, self.scope(type_ref))
        if selector in {"Events", "Links"}:
            present, value = _path(self.record, ("body", selector.lower()))
            value = value if present else ()
            expression = self.events(type_ref, value) if selector == "Events" else self.links(type_ref, value)
            return GoFixtureCompositeFieldIR(selector, expression)
        if conversion == "condition_fact":
            if semantic not in self.conditions:
                raise GoFixturePlanError(f"{self.path}: condition fact {semantic} is missing")
            return GoFixtureCompositeFieldIR(
                selector, self.typed(type_ref, self.conditions[semantic], f"{self.path}.condition.{semantic}")
            )
        if conversion == "mandatory_fact":
            if semantic not in self.mandatory:
                raise GoFixturePlanError(f"{self.path}: mandatory fact {semantic} is missing")
            return GoFixtureCompositeFieldIR(
                selector, self.typed(type_ref, self.mandatory[semantic], f"{self.path}.mandatory.{semantic}")
            )
        if selector in _COMMON_RECORD_PATHS:
            present, value = _path(self.record, _COMMON_RECORD_PATHS[selector])
        elif target == "body":
            present, value = _path(self.record, ("body", semantic))
        elif target == "trace.attributes":
            present, value = _path(self.record, ("body", "attributes", semantic))
        elif target == "trace.resource.attributes":
            present, value = _path(self.record, ("body", "resource", "attributes", semantic))
        elif target == "trace.scope.attributes":
            present, value = _path(self.record, ("body", "scope", "attributes", semantic))
        elif target == "metric.attributes":
            present, value = _path(self.record, ("instrument_data", "attributes", semantic))
        else:
            raise GoFixturePlanError(f"{self.path}.{selector}: unsupported public target slot {target}")
        if not present:
            if type_ref.arm == "optional":
                value = None
            else:
                raise GoFixturePlanError(f"{self.path}.{selector}: required canonical value is missing")
        return GoFixtureCompositeFieldIR(selector, self.typed(type_ref, value, f"{self.path}.{selector}"))

    def input(self, input_plan: Any) -> GoFixtureExpressionIR:
        self.family_input_plan = input_plan
        symbol = _identifier(_read(input_plan, "symbol", self.path), f"{self.path}.input.symbol")
        fields = _sequence(
            _read(input_plan, "fields", self.path), f"{self.path}.input.fields", maximum=_MAX_FIELDS_PER_INPUT
        )
        compiled = tuple(self.field(field) for field in fields)
        selectors = tuple(field.selector for field in compiled)
        if len(selectors) != len(set(selectors)):
            raise GoFixturePlanError(f"{self.path}: duplicate input selector")
        return _composite(GoFixtureTypeRefIR("named", symbol), compiled)


def _canonical_node(value: Any, *, blank_api_digest: bool = False, root: bool = True) -> Any:
    if dataclasses.is_dataclass(value):
        fields: dict[str, Any] = {}
        for field in dataclasses.fields(value):
            item = getattr(value, field.name)
            if root and blank_api_digest and field.name == "api_plan_sha256":
                item = ""
            fields[field.name] = _canonical_node(item, blank_api_digest=False, root=False)
        return {"$type": type(value).__name__, "fields": fields}
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise GoFixturePlanError("fixture plan contains a non-string map key")
        return {key: _canonical_node(value[key], root=False) for key in sorted(value)}
    if isinstance(value, tuple):
        return [_canonical_node(item, root=False) for item in value]
    if value is None or isinstance(value, (str, int, bool)):
        return value
    if isinstance(value, float) and math.isfinite(value):
        return value
    raise GoFixturePlanError("fixture plan contains a non-canonical value")


def _verify_api_digest(api: Any, digest: str) -> None:
    if isinstance(api, Mapping):
        raise GoFixturePlanError("embedded Go API plan must be canonical typed compiler IR")
    if not dataclasses.is_dataclass(api):
        return
    payload = json.dumps(
        _canonical_node(api, blank_api_digest=True), ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    if hashlib.sha256(_API_DIGEST_DOMAIN + payload).hexdigest() != digest:
        raise GoFixturePlanError("embedded Go API plan digest disagrees with its typed facts")


def _fixture_digest(plan: GoFixturePlanIR) -> str:
    payload = json.dumps(
        _canonical_node(dataclasses.replace(plan, fixture_plan_sha256="")),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(_DIGEST_DOMAIN + payload).hexdigest()


def _clock_expression(value: GoFixtureTimeIR) -> GoFixtureExpressionIR:
    return GoFixtureExpressionIR("deterministic_clock", GoFixtureTypeRefIR("named", "ClockFunc"), time_value=value)


def _id_expression(value: str) -> GoFixtureExpressionIR:
    return GoFixtureExpressionIR(
        "deterministic_occurrence_id",
        GoFixtureTypeRefIR("named", "OccurrenceIDGeneratorFunc"),
        scalar=GoFixtureScalarIR("string", string_value=value),
    )


def _curated_case(
    raw: Any,
    *,
    api: Any,
    inputs: Mapping[tuple[str, str], Any],
    callables: Mapping[tuple[str, str], Any],
    examples: Mapping[str, Any],
    compiled_inputs: dict[str, GoFixtureExpressionIR],
) -> GoFixtureCaseIR:
    example_id = _string(_read(raw, "id", "example"), "example.id")
    path = f"example {example_id}"
    if _CASE_ID.fullmatch(example_id) is None:
        raise GoFixturePlanError(f"{path}: non-portable example ID")
    valid = _read(raw, "valid", path)
    if type(valid) is not bool:
        raise GoFixturePlanError(f"{path}.valid: expected Boolean")
    signal = _string(_read(raw, "signal", path), f"{path}.signal")
    family_id = _optional(raw, "family")
    if family_id is not None and not isinstance(family_id, str):
        raise GoFixturePlanError(f"{path}.family: invalid family ID")
    expected_error = _optional(raw, "expected_error")
    if valid and expected_error is not None or not valid and not isinstance(expected_error, str):
        raise GoFixturePlanError(f"{path}: success/error contract is inconsistent")
    context = _context_parts(_read(raw, "builder_context", path), f"{path}.builder_context")
    mode, base_id, timestamp, record_id, _, _ = context
    resolved_context_id = example_id
    if valid:
        if mode != "explicit" or base_id is not None or timestamp is None or record_id is None:
            raise GoFixturePlanError(f"{path}: valid example context is not explicit")
    else:
        if mode != "exact_base" or base_id != _optional(raw, "base_example") or base_id not in examples:
            raise GoFixturePlanError(f"{path}: invalid example base is missing")
        base = examples[base_id]
        if _read(base, "valid", f"base example {base_id}") is not True:
            raise GoFixturePlanError(f"{path}: exact base is not a valid example")
        context = _context_parts(
            _read(base, "builder_context", f"base example {base_id}"), f"base example {base_id}.builder_context"
        )
        if context[0] != "explicit" or context[1] is not None or context[2] is None or context[3] is None:
            raise GoFixturePlanError(f"{path}: exact base context is not explicit")
        timestamp, record_id = context[2], context[3]
        resolved_context_id = base_id
    assert timestamp is not None and record_id is not None
    record = _mapping(_read(raw, "record", path), f"{path}.record")
    expected_record = _value(record, f"{path}.record")
    expected_json = _canonical_expected_record(_plain_expected(expected_record), f"{path}.record")
    field_classes = _mapping(record.get("field_classes"), f"{path}.record.field_classes")
    mandatory = record.get("mandatory") if signal == "logs" else False
    if type(mandatory) is not bool:
        raise GoFixturePlanError(f"{path}.record.mandatory: expected Boolean")

    def schema_only(reason: str) -> GoFixtureCaseIR:
        assertions = (
            (GoFixtureAssertionIR("stable_error", expected_text=expected_error),) if expected_error is not None else ()
        )
        return GoFixtureCaseIR(
            example_id,
            "curated",
            "schema_only",
            signal,
            family_id,
            example_id,
            resolved_context_id,
            reason,
            (),
            None,
            assertions,
            None,
        )

    if family_id is None:
        if valid:
            raise GoFixturePlanError(f"{path}: a valid example has no family")
        return schema_only("canonical family intentionally absent")
    input_plan = inputs.get(("family_input", family_id))
    callable_plan = callables.get(("family_builder", family_id))
    if input_plan is None or callable_plan is None:
        if valid:
            raise GoFixturePlanError(f"{path}: generated family API is missing")
        return schema_only("canonical family has no generated builder")
    try:
        input_compiler = _InputCompiler(api, record, context, path, family_id)
        expression = input_compiler.input(input_plan)
    except GoFixturePlanError:
        if valid:
            raise
        return schema_only("invalid mutation is outside the typed builder surface")
    compiled_inputs[example_id] = expression
    if not valid and base_id is not None:
        base_expression = compiled_inputs.get(base_id)
        if base_expression is None:
            base_record = _mapping(
                _read(examples[base_id], "record", f"base example {base_id}"), f"base example {base_id}.record"
            )
            base_context = _context_parts(
                _read(examples[base_id], "builder_context", f"base example {base_id}"),
                f"base example {base_id}.builder_context",
            )
            base_expression = _InputCompiler(
                api, base_record, base_context, f"base example {base_id}", family_id
            ).input(input_plan)
            compiled_inputs[base_id] = base_expression
        if expression == base_expression:
            return schema_only("mutation changes only catalog-owned or unregistered state")
    clock = _clock_expression(timestamp)
    ids = _id_expression(record_id)
    builder_type = GoFixtureTypeRefIR("pointer", element=GoFixtureTypeRefIR("named", "FamilyBuilder"))
    builder_create = GoFixtureStatementIR(
        "bind_call",
        ("builder", "builderErr"),
        _call(builder_type, "NewFamilyBuilder", clock, ids),
        True,
    )
    callable_symbol = _identifier(_read(callable_plan, "symbol", path), f"{path}.callable.symbol")
    final = GoFixtureStatementIR(
        "bind_call",
        ("record", "buildErr"),
        GoFixtureExpressionIR(
            "method_call",
            GoFixtureTypeRefIR("named", "Record"),
            symbol=callable_symbol,
            items=(
                _symbol(
                    GoFixtureTypeRefIR("pointer", element=GoFixtureTypeRefIR("named", "FamilyBuilder")),
                    "builder",
                ),
            ),
            arguments=(expression,),
        ),
        valid,
    )
    if valid:
        assertions = (
            GoFixtureAssertionIR("error_absent"),
            GoFixtureAssertionIR("exact_record", expected_value=expected_record, expected_text=expected_json),
            GoFixtureAssertionIR("exact_canonical_json", expected_text=expected_json),
            GoFixtureAssertionIR("exact_field_classes", expected_value=_value(field_classes, f"{path}.field_classes")),
            GoFixtureAssertionIR("schema_derived_field_classes", expected_boolean=True),
            GoFixtureAssertionIR("exact_mandatory", expected_boolean=mandatory),
        )
        disposition = "executable_success"
    else:
        assertions = (GoFixtureAssertionIR("stable_error", expected_text=expected_error),)
        disposition = "executable_error"
    return GoFixtureCaseIR(
        example_id,
        "curated",
        disposition,
        signal,
        family_id,
        example_id,
        resolved_context_id,
        None,
        (builder_create, *input_compiler.prelude),
        final,
        assertions,
        None,
    )


def _coverage_case(
    callable_key: tuple[str, str],
    callable_plan: Any,
    inputs: Mapping[tuple[str, str], Any],
    descriptors: Mapping[str, Any],
) -> GoFixtureCaseIR:
    kind, source_id = callable_key
    symbol = _identifier(_read(callable_plan, "symbol", "callable"), "callable.symbol")
    parameters = _sequence(_read(callable_plan, "parameters", "callable"), "callable.parameters", maximum=64)
    zero_arguments = tuple(_zero(_type_ref(parameter[1], f"callable {symbol}.parameter")) for parameter in parameters)
    input_kind = {
        "family_builder": "family_input",
        "span_event_constructor": "span_event_input",
        "span_link_constructor": "span_link_input",
        "structured_member_constructor": "structured_member_input",
    }.get(kind)
    input_key = (input_kind, source_id) if input_kind is not None and (input_kind, source_id) in inputs else None
    input_symbol = (
        _identifier(_read(inputs[input_key], "symbol", "coverage input"), "coverage input.symbol")
        if input_key
        else None
    )
    receiver_raw = _optional(callable_plan, "receiver_type")
    receiver = _type_ref(receiver_raw, f"callable {symbol}.receiver") if receiver_raw is not None else None
    receiver_pointer = _read(callable_plan, "receiver_pointer", f"callable {symbol}")
    if type(receiver_pointer) is not bool or receiver_pointer and receiver is None:
        raise GoFixturePlanError(f"callable {symbol}: invalid receiver contract")
    descriptor_family_id = source_id if kind == "family_builder" else None
    descriptor_type_symbol = None
    if descriptor_family_id is not None:
        descriptor = descriptors.get(descriptor_family_id)
        if descriptor is None:
            raise GoFixturePlanError("family coverage is missing its active descriptor")
        catalog = _read(descriptor, "catalog_contract", f"descriptor {descriptor_family_id}")
        descriptor_type_symbol = _identifier(
            _read(catalog, "descriptor_type_symbol", f"descriptor {descriptor_family_id}"),
            f"descriptor {descriptor_family_id}.type",
        )
    coverage = GoFixtureCoverageIR(
        input_key,
        input_symbol,
        callable_key,
        symbol,
        receiver,
        receiver_pointer,
        zero_arguments,
        descriptor_family_id,
        descriptor_type_symbol,
    )
    safe = re.sub(r"[^a-z0-9]+", "-", f"coverage-{kind}-{source_id}".lower()).strip("-")
    digest_suffix = hashlib.sha256(f"{kind}\x00{source_id}".encode()).hexdigest()[:12]
    case_id = (safe[:110].rstrip("-") + "-" + digest_suffix)[:128]
    if _CASE_ID.fullmatch(case_id) is None:
        raise GoFixturePlanError("generated coverage case ID is not portable")
    family_id = source_id if kind == "family_builder" else None
    return GoFixtureCaseIR(
        case_id,
        "generated_coverage",
        "compile_only",
        None,
        family_id,
        None,
        None,
        "zero-value instantiation proves syntax and reachability without semantic data",
        (),
        None,
        (),
        coverage,
    )


def _file_plan(cases: tuple[GoFixtureCaseIR, ...]) -> GoFixtureFilePlanIR:
    functions: list[GoFixtureFunctionPlanIR] = []
    seen_symbols: set[str] = set()
    seen_cases: set[str] = set()
    for order, case in enumerate(cases):
        if case.case_id in seen_cases:
            raise GoFixturePlanError("fixture file contains duplicate case ownership")
        seen_cases.add(case.case_id)
        prefix = (
            "TestGeneratedTelemetryCoverage" if case.origin == "generated_coverage" else "TestGeneratedTelemetryFixture"
        )
        suffix = hashlib.sha256(f"{case.origin}\x00{case.case_id}".encode()).hexdigest()[:24]
        symbol = prefix + suffix
        if _IDENTIFIER.fullmatch(symbol) is None or symbol in seen_symbols:
            raise GoFixturePlanError("fixture test function symbol collides or is invalid")
        seen_symbols.add(symbol)
        functions.append(
            GoFixtureFunctionPlanIR(
                symbol,
                order,
                case.disposition,
                case.case_id,
                case.origin,
            )
        )
    if tuple(function.order for function in functions) != tuple(range(len(functions))):
        raise GoFixturePlanError("fixture test function order is not contiguous")
    return GoFixtureFilePlanIR(
        _FIXTURE_OUTPUT_PATH,
        "observability",
        tuple(GoFixtureImportIR(path, alias) for path, alias in _FIXTURE_IMPORTS),
        tuple(functions),
        tuple(case.case_id for case in cases),
        _DIGEST_HEADERS,
    )


def _family_builder_method_contracts(
    callables: Mapping[tuple[str, str], Any],
    inputs: Mapping[tuple[str, str], Any],
) -> tuple[GoFixtureBuilderMethodContractIR, ...]:
    contracts: list[GoFixtureBuilderMethodContractIR] = []
    seen_symbols: set[str] = set()
    for key in sorted(callables):
        kind, source_id = key
        if kind != "family_builder":
            continue
        path = f"go_api.callable[{kind}/{source_id}]"
        callable_plan = callables[key]
        symbol = _identifier(_read(callable_plan, "symbol", path), f"{path}.symbol")
        if symbol in seen_symbols:
            raise GoFixturePlanError("family builder method symbol is duplicated")
        seen_symbols.add(symbol)
        receiver_raw = _read(callable_plan, "receiver_type", path)
        receiver = _type_ref(receiver_raw, f"{path}.receiver_type")
        receiver_pointer = _read(callable_plan, "receiver_pointer", path)
        if receiver != GoFixtureTypeRefIR("named", "FamilyBuilder") or receiver_pointer is not True:
            raise GoFixturePlanError(f"{path}: family builder receiver must be *FamilyBuilder")
        raw_parameters = _sequence(_read(callable_plan, "parameters", path), f"{path}.parameters", maximum=2)
        if len(raw_parameters) != 1:
            raise GoFixturePlanError(f"{path}: family builder must accept exactly one input")
        parameter = raw_parameters[0]
        if not isinstance(parameter, Sequence) or isinstance(parameter, (str, bytes, bytearray)) or len(parameter) != 2:
            raise GoFixturePlanError(f"{path}: family builder parameter contract is invalid")
        _identifier(parameter[0], f"{path}.parameters[0].name")
        parameter_type = _type_ref(parameter[1], f"{path}.parameters[0].type")
        input_plan = inputs.get(("family_input", source_id))
        if input_plan is None:
            raise GoFixturePlanError(f"{path}: family builder has no owned input struct")
        input_symbol = _identifier(_read(input_plan, "symbol", path), f"{path}.input.symbol")
        if parameter_type != GoFixtureTypeRefIR("named", input_symbol):
            raise GoFixturePlanError(f"{path}: family builder input must be its named struct")
        raw_results = _sequence(_read(callable_plan, "results", path), f"{path}.results", maximum=3)
        results = tuple(_type_ref(result, f"{path}.results") for result in raw_results)
        if results != (
            GoFixtureTypeRefIR("named", "Record"),
            GoFixtureTypeRefIR("builtin", "error"),
        ):
            raise GoFixturePlanError(f"{path}: family builder results must be (Record, error)")
        variadic = _optional(callable_plan, "variadic", False)
        if type(variadic) is not bool or variadic:
            raise GoFixturePlanError(f"{path}: family builder must be nonvariadic")
        contracts.append(
            GoFixtureBuilderMethodContractIR(
                symbol,
                receiver,
                receiver_pointer,
                (parameter_type,),
                results,
                variadic,
            )
        )
    return tuple(sorted(contracts, key=lambda contract: contract.symbol))


def compile_go_fixture_plan(index: Any) -> GoFixturePlanIR:
    """Compile a complete, immutable, deterministic fixture authority."""

    materialized = _string(_read(index, "materialized_view_sha256", "candidate"), "candidate.materialized_view_sha256")
    candidate = _string(
        _read(index, "candidate_render_index_sha256", "candidate"), "candidate.candidate_render_index_sha256"
    )
    api = _read(index, "go_api_plan", "candidate")
    api_digest = _string(_read(api, "api_plan_sha256", "go_api"), "go_api.api_plan_sha256")
    symbol_digest = _string(_read(api, "go_symbol_table_sha256", "go_api"), "go_api.go_symbol_table_sha256")
    if any(_SHA256.fullmatch(item) is None for item in (materialized, candidate, symbol_digest, api_digest)):
        raise GoFixturePlanError("candidate fixture inputs contain an invalid digest")
    candidate_symbol_table = _read(index, "go_symbol_table", "candidate")
    if _read(candidate_symbol_table, "table_sha256", "candidate.go_symbol_table") != symbol_digest:
        raise GoFixturePlanError("candidate and embedded Go API symbol-table digests disagree")
    if _optional(index, "api_plan_sha256") not in {None, api_digest}:
        raise GoFixturePlanError("candidate and embedded Go API plan digests disagree")
    if _read(api, "materialized_view_sha256", "go_api") != materialized:
        raise GoFixturePlanError("Go API plan is bound to a different materialized view")
    _verify_api_digest(api, api_digest)

    raw_inputs = _sequence(_read(api, "inputs", "go_api"), "go_api.inputs", maximum=_MAX_INPUTS)
    raw_callables = _sequence(_read(api, "callables", "go_api"), "go_api.callables", maximum=_MAX_CALLABLES)
    inputs: dict[tuple[str, str], Any] = {}
    for position, item in enumerate(raw_inputs):
        key = (
            _string(_read(item, "declaration_kind", f"go_api.inputs[{position}]"), "input kind"),
            _string(_read(item, "declaration_source_id", f"go_api.inputs[{position}]"), "input source"),
        )
        if key in inputs:
            raise GoFixturePlanError("Go API plan contains a duplicate input declaration")
        inputs[key] = item
    callables: dict[tuple[str, str], Any] = {}
    for position, item in enumerate(raw_callables):
        key = (
            _string(_read(item, "declaration_kind", f"go_api.callables[{position}]"), "callable kind"),
            _string(_read(item, "declaration_source_id", f"go_api.callables[{position}]"), "callable source"),
        )
        if key in callables:
            raise GoFixturePlanError("Go API plan contains a duplicate callable declaration")
        callables[key] = item

    raw_examples = _sequence(_read(index, "examples", "candidate"), "candidate.examples", maximum=_MAX_EXAMPLES)
    examples: dict[str, Any] = {}
    for position, item in enumerate(raw_examples):
        example_id = _string(_read(item, "id", f"candidate.examples[{position}]"), "example ID")
        if example_id in examples:
            raise GoFixturePlanError("candidate contains a duplicate example ID")
        examples[example_id] = item
    embedded_fixtures = _sequence(_read(api, "fixtures", "go_api"), "go_api.fixtures", maximum=_MAX_EXAMPLES)
    embedded_ids = tuple(
        _string(_read(item, "example_id", "go_api.fixture"), "fixture example ID") for item in embedded_fixtures
    )
    if embedded_ids != tuple(examples):
        raise GoFixturePlanError("embedded semantic fixture inventory disagrees with normalized examples")
    for position, (raw, embedded) in enumerate(zip(raw_examples, embedded_fixtures, strict=True)):
        path = f"go_api.fixtures[{position}]"
        for name in ("signal", "family_id", "valid", "expected_error", "base_example"):
            candidate_name = "family" if name == "family_id" else name
            if _optional(embedded, name) != _optional(raw, candidate_name):
                raise GoFixturePlanError(f"{path}: embedded semantic metadata disagrees with example")
        expected_record = _value(_read(raw, "record", f"candidate.examples[{position}]"), f"{path}.record")
        expected_json = _canonical_expected_record(_plain_expected(expected_record), f"{path}.record")
        if _canonical_embedded_record(_read(embedded, "expected_record_json", path), path) != expected_json:
            raise GoFixturePlanError(f"{path}: embedded canonical record disagrees with example")

    curated: list[GoFixtureCaseIR] = []
    compiled_inputs: dict[str, GoFixtureExpressionIR] = {}
    for raw in raw_examples:
        curated.append(
            _curated_case(
                raw, api=api, inputs=inputs, callables=callables, examples=examples, compiled_inputs=compiled_inputs
            )
        )
    authored_callable_keys = {
        ("family_builder", case.family_id)
        for case in curated
        if case.family_id is not None and case.disposition.startswith("executable_")
    }
    raw_descriptors = _sequence(_read(api, "descriptors", "go_api"), "go_api.descriptors", maximum=_MAX_INPUTS)
    descriptors: dict[str, Any] = {}
    for item in raw_descriptors:
        family_id = _string(_read(item, "family_id", "go_api.descriptor"), "descriptor family ID")
        if family_id in descriptors:
            raise GoFixturePlanError("Go API plan contains duplicate family descriptors")
        descriptors[family_id] = item
    coverage = tuple(
        _coverage_case(key, callables[key], inputs, descriptors)
        for key in sorted(callables)
        if key not in authored_callable_keys
    )
    covered_callables = tuple(
        sorted(authored_callable_keys | {case.coverage.callable_key for case in coverage if case.coverage})
    )
    if set(covered_callables) != set(callables):
        raise GoFixturePlanError("generated fixture coverage does not cover every callable")
    family_builder_methods = _family_builder_method_contracts(callables, inputs)
    family_ids = tuple(sorted(descriptors))
    if {source for kind, source in callables if kind == "family_builder"} != set(family_ids):
        raise GoFixturePlanError("active family descriptors and builder methods disagree")
    if len(family_builder_methods) != len(family_ids):
        raise GoFixturePlanError("family builder method contracts and descriptors disagree")
    all_cases = (*curated, *coverage)
    file_plan = _file_plan(all_cases)
    if file_plan.path != _FIXTURE_OUTPUT_PATH or file_plan.package_name != "observability":
        raise GoFixturePlanError("fixture file ownership is invalid")
    plan = GoFixturePlanIR(
        1,
        materialized,
        candidate,
        symbol_digest,
        api_digest,
        family_builder_methods,
        tuple(curated),
        coverage,
        family_ids,
        covered_callables,
        tuple(case.case_id for case in curated if case.disposition == "schema_only"),
        file_plan,
        "",
    )
    if any(case.disposition not in _DISPOSITIONS for case in (*plan.curated_cases, *plan.generated_coverage_cases)):
        raise GoFixturePlanError("fixture compiler emitted an unknown disposition")
    return dataclasses.replace(plan, fixture_plan_sha256=_fixture_digest(plan))


__all__ = [
    "GoFixtureAssertionIR",
    "GoFixtureBuilderMethodContractIR",
    "GoFixtureCaseIR",
    "GoFixtureCoverageIR",
    "GoFixtureExpressionIR",
    "GoFixtureFilePlanIR",
    "GoFixtureFunctionPlanIR",
    "GoFixtureImportIR",
    "GoFixtureObjectFieldIR",
    "GoFixturePlanError",
    "GoFixturePlanIR",
    "GoFixtureScalarIR",
    "GoFixtureStatementIR",
    "GoFixtureTimeIR",
    "GoFixtureTypeRefIR",
    "GoFixtureValueIR",
    "compile_go_fixture_plan",
]
