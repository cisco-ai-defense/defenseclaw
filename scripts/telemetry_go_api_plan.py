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
"""Deterministic compiler foundation for the telemetry-v8 generated Go API.

This module is deliberately independent of the registry generator and candidate
renderers.  It accepts a recursively immutable, ``CandidateRenderIndex``-like
object and returns syntax-complete immutable plans.  It performs no filesystem
I/O and never reads source YAML, a reviewed golden, or existing Go output.

The input object must expose ``materialized_view_sha256``, ``go_symbol_policy``,
``go_symbol_table``, ``enriched_fields``, ``enriched_families``,
``structured_types``, ``expanded_producer_mappings``, and
``go_declaration_values``.  The enrichment
records are an intentional trust boundary: missing family or structured
descriptor data is an error, never an invitation to reconstruct it from names.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import math
import re
from collections.abc import Mapping, Sequence
from typing import Any, Final, TypeAlias

if __package__ == "scripts":  # pragma: no cover - package import exercised by subprocess tests
    from .telemetry_canonical_record import CanonicalRecordError, canonical_record_json
else:
    from telemetry_canonical_record import CanonicalRecordError, canonical_record_json  # type: ignore[no-redef]


class GoAPIPlanError(RuntimeError):
    """A deterministic compiler-contract failure."""


@dataclasses.dataclass(frozen=True, slots=True)
class GoTypeRefIR:
    """Closed Go type AST; renderers only print this tree."""

    arm: str
    name: str | None = None
    element: GoTypeRefIR | None = None


@dataclasses.dataclass(frozen=True, slots=True)
class GoFieldPlanIR:
    owner: str
    selector: str
    type_ref: GoTypeRefIR
    order: int
    presence: str
    semantic_source_id: str
    enriched_descriptor_id: str
    value_source: str
    target_slot: str
    condition_binding: str | None
    mandatory_binding: str | None
    conversion_op: str


@dataclasses.dataclass(frozen=True, slots=True)
class GoTypedSymbolRefIR:
    """One exact, typed Go identifier reference.

    ``conversion_type`` is present only when the referenced declaration is a
    typed string/integer constant whose value must be converted to the private
    kernel type.  A renderer never derives a runtime constant name from a wire
    value.
    """

    type_ref: GoTypeRefIR
    symbol: str
    conversion_type: GoTypeRefIR | None


@dataclasses.dataclass(frozen=True, slots=True)
class GoFieldConstraintsPlanIR:
    """Exact projection into ``familyFieldConstraints``."""

    max_utf8_bytes: int
    max_item_utf8_bytes: int
    min_items: int
    max_items: int
    pattern: str
    enum_values: tuple[str, ...]
    int_min: int | None
    int_max: int | None
    uint_min: int | None
    uint_max: int | None
    float_min: int | float | None
    float_max: int | float | None
    structured: GoKernelLimitsIR | None


@dataclasses.dataclass(frozen=True, slots=True)
class GoFieldValueBindingPlanIR:
    descriptor_id: str
    key: str
    selector: str
    presence: str
    conversion_op: str
    structured_encoder_symbol: str | None
    field_type: GoTypedSymbolRefIR | None
    constraints: GoFieldConstraintsPlanIR | None


@dataclasses.dataclass(frozen=True, slots=True)
class GoConditionBindingPlanIR:
    condition_id: str
    fact_id: str
    selector: str
    optional_source: bool


@dataclasses.dataclass(frozen=True, slots=True)
class GoMandatoryBindingPlanIR:
    fact_id: str
    selector: str


@dataclasses.dataclass(frozen=True, slots=True)
class GoKernelHelperRefIR:
    """Reference to one reviewed private-kernel helper signature."""

    symbol: str
    receiver_type: GoTypeRefIR | None
    receiver_pointer: bool
    parameters: tuple[ParameterIR, ...]
    results: tuple[GoTypeRefIR, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class GoFamilyCallableBodyPlanIR:
    arm: str
    descriptor_type_symbol: str
    kernel_helper: GoKernelHelperRefIR
    private_input_type: GoTypeRefIR
    values_target: str
    values: tuple[GoFieldValueBindingPlanIR, ...]
    resource_values: tuple[GoFieldValueBindingPlanIR, ...]
    conditions: tuple[GoConditionBindingPlanIR, ...]
    mandatory_terms: tuple[GoMandatoryBindingPlanIR, ...]
    mandatory_resolver: GoKernelHelperRefIR | None
    metric_number_helper: GoKernelHelperRefIR | None


@dataclasses.dataclass(frozen=True, slots=True)
class GoEventCallableBodyPlanIR:
    contract_helper_symbol: str
    values: tuple[GoFieldValueBindingPlanIR, ...]
    conditions: tuple[GoConditionBindingPlanIR, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class GoLinkCallableBodyPlanIR:
    relation: GoTypedSymbolRefIR
    values: tuple[GoFieldValueBindingPlanIR, ...]
    conditions: tuple[GoConditionBindingPlanIR, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class GoMemberCallableBodyPlanIR:
    name_constraints: GoFieldConstraintsPlanIR
    validation_helper: GoKernelHelperRefIR


GoCallableBodyPlanIR: TypeAlias = (
    GoFamilyCallableBodyPlanIR | GoEventCallableBodyPlanIR | GoLinkCallableBodyPlanIR | GoMemberCallableBodyPlanIR
)


@dataclasses.dataclass(frozen=True, slots=True)
class GoInputPlanIR:
    declaration_kind: str
    declaration_source_id: str
    symbol: str
    output_file: str
    fields: tuple[GoFieldPlanIR, ...]
    private_kernel_target: str
    referenced_event_inputs: tuple[str, ...]
    referenced_link_inputs: tuple[str, ...]
    referenced_resource_descriptors: tuple[str, ...]


ParameterIR: TypeAlias = tuple[str, GoTypeRefIR]


@dataclasses.dataclass(frozen=True, slots=True)
class GoCallablePlanIR:
    declaration_kind: str
    declaration_source_id: str
    symbol: str
    output_file: str
    receiver_name: str | None
    receiver_type: GoTypeRefIR | None
    receiver_pointer: bool
    parameters: tuple[ParameterIR, ...]
    results: tuple[GoTypeRefIR, ...]
    error_contract: str
    private_target: str
    body: GoCallableBodyPlanIR


@dataclasses.dataclass(frozen=True, slots=True)
class GoStructuredPlanIR:
    declaration_source_id: str
    symbol: str
    output_file: str
    shape: str
    scalar_descriptor_ids: tuple[str, ...]
    fields: tuple[GoFieldPlanIR, ...]
    item_type: GoTypeRefIR | None
    arm_declaration_keys: tuple[str, ...]
    arm_value_types: tuple[tuple[str, GoTypeRefIR], ...]
    arm_shapes: tuple[tuple[str, str, str], ...]
    dynamic_member_input_keys: tuple[str, ...]
    private_discriminator: str | None
    container_descriptor_ids: tuple[str, ...]
    limits: tuple[tuple[str, int], ...]
    conversion_plan: tuple[str, ...]
    declaration_fields: tuple[GoFieldPlanIR, ...]
    marker_method: str | None
    arms: tuple[GoStructuredArmPlanIR, ...]
    members: tuple[GoStructuredMemberPlanIR, ...]
    encoder: GoStructuredEncoderPlanIR


@dataclasses.dataclass(frozen=True, slots=True)
class GoStructuredArmPlanIR:
    source_id: str
    symbol: str
    arm: str
    fields: tuple[GoFieldPlanIR, ...]
    marker_method: str
    encoder_symbol: str | None
    wire_tag: str | None
    tag_constraints: GoFieldConstraintsPlanIR | None
    scalar_constraints: GoFieldConstraintsPlanIR | None


@dataclasses.dataclass(frozen=True, slots=True)
class GoStructuredMemberPlanIR:
    source_id: str
    input_symbol: str
    constructor_symbol: str
    fields: tuple[GoFieldPlanIR, ...]
    name_constraints: GoFieldConstraintsPlanIR


@dataclasses.dataclass(frozen=True, slots=True)
class GoStructuredEncoderPlanIR:
    symbol: str
    input_type: GoTypeRefIR
    result_type: GoTypeRefIR
    arm: str
    fixed_fields: tuple[GoFieldValueBindingPlanIR, ...]
    item_type: GoTypeRefIR | None
    item_encoder_symbol: str | None
    arm_source_ids: tuple[str, ...]
    dynamic_member_source_ids: tuple[str, ...]
    discriminator: str | None
    limits: GoKernelLimitsIR
    validation_helpers: tuple[GoKernelHelperRefIR, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class GoFactValueIR:
    arm: str
    string_value: str | None = None
    integer_value: int | None = None
    double_value: float | None = None
    boolean_value: bool | None = None
    items: tuple[GoFactValueIR, ...] = ()
    fields: tuple[tuple[str, GoFactValueIR], ...] = ()


@dataclasses.dataclass(frozen=True, slots=True)
class GoKernelFieldDescriptorIR:
    descriptor_id: str
    key: str
    field_type: str
    requirement: str
    condition_id: str | None
    condition_fact: str | None
    false_requirement: str | None
    field_class: str
    constraints: GoFactValueIR
    value_source: str
    target_slot: str
    order: int
    type_ref: GoTypedSymbolRefIR
    requirement_ref: GoTypedSymbolRefIR
    false_requirement_ref: GoTypedSymbolRefIR | None
    field_class_ref: GoTypedSymbolRefIR
    source_ref: GoTypedSymbolRefIR
    typed_constraints: GoFieldConstraintsPlanIR


@dataclasses.dataclass(frozen=True, slots=True)
class GoKernelLimitsIR:
    max_encoded_bytes: int
    max_item_utf8_bytes: int
    max_items: int
    max_depth: int
    max_properties: int


@dataclasses.dataclass(frozen=True, slots=True)
class GoSpanNamePartPlanIR:
    arm: str
    literal: str | None
    field_key: str | None


@dataclasses.dataclass(frozen=True, slots=True)
class GoIdentityContractPlanIR:
    bucket: GoTypedSymbolRefIR
    signal: GoTypedSymbolRefIR
    event_name: GoTypedSymbolRefIR


@dataclasses.dataclass(frozen=True, slots=True)
class GoOutcomePolicyPlanIR:
    requirement: GoTypedSymbolRefIR
    allowed: tuple[GoTypedSymbolRefIR, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class GoValueCodeEntryPlanIR:
    value: str
    code: int


@dataclasses.dataclass(frozen=True, slots=True)
class GoCrossFieldRelationPlanIR:
    catalog_id: str
    arm: str
    value_key: str
    code_key: str
    entries: tuple[GoValueCodeEntryPlanIR, ...]
    mismatch_error: GoTypedSymbolRefIR


@dataclasses.dataclass(frozen=True, slots=True)
class GoBaseFamilyContractPlanIR:
    family_id: str
    identity: GoIdentityContractPlanIR
    family_schema_version: int
    outcome: GoOutcomePolicyPlanIR
    fields: tuple[GoKernelFieldDescriptorIR, ...]
    cross_field_relations: tuple[GoCrossFieldRelationPlanIR, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class GoEventContractPlanIR:
    source_id: str
    private_helper_symbol: str
    event_id: str
    event_name: GoTypedSymbolRefIR
    fields: tuple[GoKernelFieldDescriptorIR, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class GoTraceFamilyContractPlanIR:
    base: GoBaseFamilyContractPlanIR
    allowed_kinds: tuple[str, ...]
    span_name: tuple[GoSpanNamePartPlanIR, ...]
    attribute_limits: GoKernelLimitsIR
    resource_fields: tuple[GoKernelFieldDescriptorIR, ...]
    resource_limits: GoKernelLimitsIR
    scope_fields: tuple[GoKernelFieldDescriptorIR, ...]
    scope_limits: GoKernelLimitsIR
    allowed_events: tuple[GoEventContractPlanIR, ...]
    event_limits: GoKernelLimitsIR
    max_events: int
    allowed_links: tuple[GoTypedSymbolRefIR, ...]
    link_fields: tuple[GoKernelFieldDescriptorIR, ...]
    link_limits: GoKernelLimitsIR
    max_links: int
    scope_name: str
    scope_schema_url: str
    trace_schema_version: str
    semantic_profile: str


@dataclasses.dataclass(frozen=True, slots=True)
class GoMetricFamilyContractPlanIR:
    base: GoBaseFamilyContractPlanIR
    value_type: GoTypedSymbolRefIR
    attribute_limits: GoKernelLimitsIR
    instrument_name: GoTypedSymbolRefIR
    instrument_type: str
    unit: str
    temporality: str


@dataclasses.dataclass(frozen=True, slots=True)
class GoCatalogContractPlanIR:
    descriptor_type_symbol: str
    base: GoBaseFamilyContractPlanIR
    trace: GoTraceFamilyContractPlanIR | None
    metric: GoMetricFamilyContractPlanIR | None


@dataclasses.dataclass(frozen=True, slots=True)
class GoTraceContractPlanIR:
    attribute_limits: GoKernelLimitsIR
    resource_limits: GoKernelLimitsIR
    scope_limits: GoKernelLimitsIR
    event_limits: GoKernelLimitsIR
    link_limits: GoKernelLimitsIR
    max_events: int
    max_links: int
    scope_name: str
    scope_schema_url: str
    trace_schema_version: str
    semantic_profile: str


@dataclasses.dataclass(frozen=True, slots=True)
class GoResourceCompatibilityAliasPlanIR:
    alias: str
    canonical: str
    descriptor: GoKernelFieldDescriptorIR


@dataclasses.dataclass(frozen=True, slots=True)
class GoResourceAttributesPlanIR:
    owner_id: str
    type_symbol: str
    constructor_symbol: str
    attach_symbol: str
    validator_symbol: str
    ordering: str
    field_class: str
    sensitivity: str
    cardinality: str
    stability_scope: str
    value_utf8_policy: str
    value_blank_policy: str
    value_control_character_policy: str
    prometheus_key_normalization: str
    prometheus_normalized_collision_policy: str
    key_pattern: str
    max_items: int
    max_key_ascii_bytes: int
    min_value_utf8_bytes: int
    max_value_utf8_bytes: int
    max_aggregate_utf8_bytes: int
    duplicate_key_policy: str
    fixed_key_collision_policy: str
    fixed_keys: tuple[str, ...]
    fixed_descriptors: tuple[GoKernelFieldDescriptorIR, ...]
    forbidden_key_segments: tuple[str, ...]
    reserved_keys: tuple[str, ...]
    forbidden_value_classes: tuple[str, ...]
    aliases: tuple[GoResourceCompatibilityAliasPlanIR, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class GoDescriptorPlanIR:
    family_id: str
    signal: str
    domain: str
    identity_bucket: str
    identity_name: str
    family_schema_version: int
    outcome_requirement: str
    allowed_outcomes: tuple[str, ...]
    field_contracts: tuple[GoKernelFieldDescriptorIR, ...]
    enriched_field_descriptor_ids: tuple[str, ...]
    resource_field_descriptor_ids: tuple[str, ...]
    scope_field_descriptor_ids: tuple[str, ...]
    span_name_parts: tuple[GoSpanNamePartPlanIR, ...]
    allowed_kinds: tuple[str, ...]
    event_contracts: tuple[tuple[str, str, tuple[str, ...]], ...]
    link_contracts: tuple[tuple[str, tuple[str, ...]], ...]
    metric_contract: tuple[tuple[str, str], ...]
    metric_description: str | None
    metric_boundaries: tuple[int | float, ...]
    metric_attribute_limits: GoKernelLimitsIR | None
    trace_contract: GoTraceContractPlanIR | None
    mandatory_rule_ids: tuple[str, ...]
    mandatory_constant_terms: tuple[bool, ...]
    mandatory_fact_terms: tuple[tuple[str, str], ...]
    private_kernel_target: str
    catalog_contract: GoCatalogContractPlanIR


DeclarationKeyIR: TypeAlias = tuple[str, str]
LiteralValueIR: TypeAlias = str | int


@dataclasses.dataclass(frozen=True, slots=True)
class GoDeclarationPlanIR:
    """One complete package declaration assignment.

    Constants carry an exact typed value; non-constants carry no literal but do
    retain their compiler-owned form, semantic owner, and output file.
    """

    kind: str
    source_id: str
    symbol: str
    declaration_form: str
    owner: str
    output_file: str
    go_type: GoTypeRefIR | None
    literal_kind: str | None
    literal_value: LiteralValueIR | None


@dataclasses.dataclass(frozen=True, slots=True)
class GoImportPlanIR:
    path: str
    alias: str | None


@dataclasses.dataclass(frozen=True, slots=True)
class GoPrivateDeclarationPlanIR:
    declaration_id: str
    symbol: str
    owner: str
    output_file: str
    order: int
    arm: str
    receiver_type: GoTypeRefIR | None
    parameters: tuple[ParameterIR, ...]
    results: tuple[GoTypeRefIR, ...]
    body_owner_id: str


@dataclasses.dataclass(frozen=True, slots=True)
class GoFilePlanIR:
    path: str
    package_name: str
    imports: tuple[GoImportPlanIR, ...]
    declaration_keys: tuple[DeclarationKeyIR, ...]
    declarations: tuple[GoDeclarationPlanIR, ...]
    private_declarations: tuple[GoPrivateDeclarationPlanIR, ...]
    private_descriptor_ids: tuple[str, ...]
    private_projection_ids: tuple[str, ...]
    expected_digest_headers: tuple[str, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class GoFixturePlanIR:
    example_id: str
    signal: str
    family_id: str | None
    valid: bool
    input_declaration_key: DeclarationKeyIR | None
    callable_declaration_key: DeclarationKeyIR | None
    field_bindings: tuple[tuple[str, str, str], ...]
    builder_context: GoFactValueIR
    expected_record: GoFactValueIR
    expected_record_json: str
    expected_error: str | None
    base_example: str | None


@dataclasses.dataclass(frozen=True, slots=True)
class GoAPIPlanIR:
    version: int
    materialized_view_sha256: str
    go_symbol_table_sha256: str
    inputs: tuple[GoInputPlanIR, ...]
    callables: tuple[GoCallablePlanIR, ...]
    structured: tuple[GoStructuredPlanIR, ...]
    descriptors: tuple[GoDescriptorPlanIR, ...]
    resource_attributes: GoResourceAttributesPlanIR
    declarations: tuple[GoDeclarationPlanIR, ...]
    private_declarations: tuple[GoPrivateDeclarationPlanIR, ...]
    kernel_helpers: tuple[GoKernelHelperRefIR, ...]
    fixtures: tuple[GoFixturePlanIR, ...]
    files: tuple[GoFilePlanIR, ...]
    api_plan_sha256: str

    def recomputed_digest(self) -> str:
        """Return the compiler-owned digest of the current immutable facts."""

        return _plan_digest(self)

    def verify_digest(self) -> bool:
        """Report whether the recorded digest still binds every typed fact."""

        return self.api_plan_sha256 == self.recomputed_digest()


_GO_API_PLAN_DIGEST_DOMAIN: Final = b"DefenseClaw GoAPIPlanIR v1\x00"
_GO_SYMBOL_TABLE_DIGEST_DOMAIN: Final = b"DefenseClaw GoSymbolTableIR v1\x00"
_SHA256: Final = re.compile(r"^[0-9a-f]{64}$")
_GO_IDENTIFIER: Final = re.compile(r"^[A-Za-z][A-Za-z0-9]*$")

_GO_SYMBOL_KIND_ORDER: Final = (
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
    "resource_attributes_type",
    "resource_attributes_constructor",
    "resource_attributes_attach",
    "resource_attributes_validator",
    "family_input",
    "family_builder",
    "span_event_input",
    "span_event_constructor",
    "span_link_input",
    "span_link_constructor",
)
_DECLARATION_FORMS: Final = frozenset({"exported_const", "exported_type", "exported_function", "family_builder_method"})
_FORM_BY_KIND: Final = {
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
            "resource_attributes_type",
            "family_input",
            "span_event_input",
            "span_link_input",
        )
    },
    **{
        kind: "exported_function"
        for kind in (
            "structured_member_constructor",
            "resource_attributes_constructor",
            "resource_attributes_attach",
            "resource_attributes_validator",
            "span_event_constructor",
            "span_link_constructor",
        )
    },
    "family_builder": "family_builder_method",
}

_IDS_FILE: Final = "internal/observability/zz_generated_telemetry_ids.go"
_CATALOG_FILE: Final = "internal/observability/zz_generated_telemetry_catalog.go"
_PRODUCERS_FILE: Final = "internal/observability/zz_generated_telemetry_producers.go"
_DOMAIN_FILES: Final = {
    "genai": "internal/observability/zz_generated_telemetry_builders_genai.go",
    "security": "internal/observability/zz_generated_telemetry_builders_security.go",
    "operations": "internal/observability/zz_generated_telemetry_builders_operations.go",
}
_FIXTURES_FILE: Final = "internal/observability/zz_generated_telemetry_builder_fixtures_test.go"
GO_OUTPUT_FILES: Final = (
    _IDS_FILE,
    _CATALOG_FILE,
    _PRODUCERS_FILE,
    _DOMAIN_FILES["genai"],
    _DOMAIN_FILES["security"],
    _DOMAIN_FILES["operations"],
    _FIXTURES_FILE,
)

_GO_RESERVED_IDENTIFIERS: Final = frozenset(
    {
        "break",
        "case",
        "chan",
        "const",
        "continue",
        "default",
        "defer",
        "else",
        "fallthrough",
        "for",
        "func",
        "go",
        "goto",
        "if",
        "import",
        "interface",
        "map",
        "package",
        "range",
        "return",
        "select",
        "struct",
        "switch",
        "type",
        "var",
        "any",
        "append",
        "bool",
        "byte",
        "cap",
        "clear",
        "close",
        "comparable",
        "complex",
        "complex64",
        "complex128",
        "copy",
        "delete",
        "error",
        "false",
        "float32",
        "float64",
        "imag",
        "int",
        "int8",
        "int16",
        "int32",
        "int64",
        "iota",
        "len",
        "make",
        "max",
        "min",
        "new",
        "nil",
        "panic",
        "print",
        "println",
        "real",
        "recover",
        "rune",
        "string",
        "true",
        "uint",
        "uint8",
        "uint16",
        "uint32",
        "uint64",
        "uintptr",
    }
)
_PRESENCE: Final = frozenset({"required", "recommended", "optional", "conditional"})
_VALUE_SOURCES: Final = frozenset(
    {
        "input",
        "constant",
        "envelope.bucket",
        "family.id",
        "family.family_schema_version",
        "envelope.source",
        "provenance.config_generation",
        "envelope.outcome",
        "provenance.binary_version",
        "semantic_profile.trace_schema_version",
        "semantic_profile.id",
        "link.relation",
    }
)
_INPUT_OWNER_KINDS: Final = frozenset({"family", "event", "link", "structured", "none"})
_COMPONENTS: Final = frozenset({"family", "resource", "scope", "event", "link", "structured"})
_CONVERSIONS: Final = frozenset(
    {
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
)
_STRUCTURED_SHAPES: Final = frozenset({"object", "array", "tagged_union", "canonical_json"})
_DIGEST_HEADERS: Final = (
    "materialized_view_sha256",
    "candidate_render_index_sha256",
    "go_symbol_table_sha256",
)

_FIELD_TYPE_SYMBOLS: Final = {
    "string": "familyFieldString",
    "boolean": "familyFieldBoolean",
    "int64": "familyFieldInt64",
    "uint32": "familyFieldUint32",
    "uint64": "familyFieldUint64",
    "double": "familyFieldDouble",
    "string[]": "familyFieldStringArray",
    "structured": "familyFieldStructured",
}
_REQUIREMENT_SYMBOLS: Final = {
    "required": "familyRequirementRequired",
    "recommended": "familyRequirementRecommended",
    "optional": "familyRequirementOptional",
    "conditional": "familyRequirementConditional",
    "forbidden": "familyRequirementForbidden",
}
_FALSE_REQUIREMENT_SYMBOLS: Final = {
    "optional": "familyFalseOptional",
    "forbidden": "familyFalseForbidden",
}
_FIELD_CLASS_SYMBOLS: Final = {
    "metadata": "FieldClassMetadata",
    "identifier": "FieldClassIdentifier",
    "content": "FieldClassContent",
    "reason": "FieldClassReason",
    "evidence": "FieldClassEvidence",
    "error": "FieldClassError",
    "path": "FieldClassPath",
    "credential": "FieldClassCredential",
}
_VALUE_SOURCE_SYMBOLS: Final = {
    "input": "familyValueInput",
    "envelope.bucket": "familyValueBucket",
    "family.id": "familyValueFamily",
    "family.family_schema_version": "familyValueFamilySchemaVersion",
    "envelope.source": "familyValueSourceName",
    "provenance.config_generation": "familyValueConfigGeneration",
    "envelope.outcome": "familyValueOutcome",
    "provenance.binary_version": "familyValueBinaryVersion",
    "semantic_profile.trace_schema_version": "familyValueTraceSchemaVersion",
    "semantic_profile.id": "familyValueSemanticProfile",
    "link.relation": "familyValueLinkRelation",
}
_BUCKET_SYMBOLS: Final = {
    "compliance.activity": "BucketComplianceActivity",
    "security.finding": "BucketSecurityFinding",
    "guardrail.evaluation": "BucketGuardrailEvaluation",
    "enforcement.action": "BucketEnforcementAction",
    "model.io": "BucketModelIO",
    "tool.activity": "BucketToolActivity",
    "asset.scan": "BucketAssetScan",
    "asset.lifecycle": "BucketAssetLifecycle",
    "network.egress": "BucketNetworkEgress",
    "agent.lifecycle": "BucketAgentLifecycle",
    "ai.discovery": "BucketAIDiscovery",
    "telemetry.ingest": "BucketTelemetryIngest",
    "platform.health": "BucketPlatformHealth",
    "diagnostic": "BucketDiagnostic",
}
_SIGNAL_SYMBOLS: Final = {"log": "SignalLogs", "span": "SignalTraces", "metric": "SignalMetrics"}
_OUTCOME_SYMBOLS: Final = {
    "attempted": "OutcomeAttempted",
    "validated": "OutcomeValidated",
    "applied": "OutcomeApplied",
    "completed": "OutcomeCompleted",
    "allowed": "OutcomeAllowed",
    "blocked": "OutcomeBlocked",
    "denied": "OutcomeDenied",
    "approved": "OutcomeApproved",
    "quarantined": "OutcomeQuarantined",
    "redacted": "OutcomeRedacted",
    "revoked": "OutcomeRevoked",
    "released": "OutcomeReleased",
    "terminated": "OutcomeTerminated",
    "rejected": "OutcomeRejected",
    "failed": "OutcomeFailed",
    "timed_out": "OutcomeTimedOut",
    "cancelled": "OutcomeCancelled",
    "partial": "OutcomePartial",
    "skipped": "OutcomeSkipped",
    "no_change": "OutcomeNoChange",
}
_VALUE_CATALOG_ERROR_SYMBOLS: Final = {
    "agent-phase-v1": "FamilyBuildLifecyclePhaseCodeMismatch",
}
MAX_CROSS_FIELD_RELATION_ENTRIES: Final = 8192
_CALLABLE_BODY_ARMS: Final = frozenset(
    {"family_log", "family_span", "family_metric", "event", "link", "structured_member"}
)
_INPUT_KERNEL_TARGETS: Final = frozenset(
    {
        "structured_member_input",
        "trace_event_input",
        "trace_link_input",
        "family_log_input",
        "family_span_input",
        "family_metric_input",
    }
)
_PRIVATE_DECLARATION_ARMS: Final = frozenset(
    {
        "family_descriptor_type",
        "family_descriptor_method",
        "family_trace_method",
        "family_metric_method",
        "event_contract_helper",
        "structured_marker_method",
        "structured_encoder",
    }
)


@dataclasses.dataclass(frozen=True, slots=True)
class _Symbol:
    kind: str
    source_id: str
    symbol: str
    declaration_form: str


@dataclasses.dataclass(frozen=True, slots=True)
class _Policy:
    separators: tuple[str, ...]
    brand_spellings: tuple[tuple[str, str], ...]
    initialisms: tuple[str, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class _Field:
    id: str
    owner_id: str
    component: str
    semantic_source_id: str
    primitive_type: str
    structured_type: str | None
    requirement: str
    condition_id: str | None
    condition_fact: str | None
    false_requirement: str | None
    field_class: str
    constraints: GoFactValueIR
    value_source: str
    target_slot: str
    input_owner_kind: str
    order: int


def _read(value: Any, name: str, path: str) -> Any:
    if isinstance(value, Mapping):
        if name not in value:
            raise GoAPIPlanError(f"{path}.{name}: required compiler fact is missing")
        return value[name]
    try:
        return getattr(value, name)
    except AttributeError as exc:
        raise GoAPIPlanError(f"{path}.{name}: required compiler fact is missing") from exc


def _string(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value:
        raise GoAPIPlanError(f"{path}: expected non-empty string")
    return value


def _integer(value: Any, path: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise GoAPIPlanError(f"{path}: expected integer >= {minimum}")
    return value


def _sequence(value: Any, path: str) -> tuple[Any, ...]:
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        raise GoAPIPlanError(f"{path}: expected sequence")
    return tuple(value)


def _optional(value: Any, name: str, default: Any = None) -> Any:
    if isinstance(value, Mapping):
        return value.get(name, default)
    return getattr(value, name, default)


def _fact_value(value: Any, path: str) -> GoFactValueIR:
    if isinstance(value, Mapping):
        return GoFactValueIR(
            "object",
            fields=tuple(
                (_string(key, f"{path}.key"), _fact_value(value[key], f"{path}.{key}")) for key in sorted(value)
            ),
        )
    if isinstance(value, tuple):
        return GoFactValueIR("sequence", items=tuple(_fact_value(item, path) for item in value))
    if value is None:
        return GoFactValueIR("null")
    if isinstance(value, str):
        return GoFactValueIR("string", string_value=value)
    if isinstance(value, bool):
        return GoFactValueIR("boolean", boolean_value=value)
    if isinstance(value, int):
        return GoFactValueIR("integer", integer_value=value)
    if isinstance(value, float) and math.isfinite(value):
        return GoFactValueIR("double", double_value=value)
    raise GoAPIPlanError(f"{path}: unsupported or non-finite compiler fact")


def _named(name: str) -> GoTypeRefIR:
    _validate_identifier(name, "named Go type")
    return GoTypeRefIR("named", name=name)


def _builtin(name: str) -> GoTypeRefIR:
    if name not in {"string", "bool", "int", "int64", "uint32", "uint64", "float64", "error"}:
        raise GoAPIPlanError("unsupported builtin Go type")
    return GoTypeRefIR("builtin", name=name)


def _optional_type(element: GoTypeRefIR) -> GoTypeRefIR:
    return GoTypeRefIR("optional", element=element)


def _slice(element: GoTypeRefIR) -> GoTypeRefIR:
    return GoTypeRefIR("slice", element=element)


def _typed_symbol(type_name: str, symbol: str, *, conversion: bool = False) -> GoTypedSymbolRefIR:
    _validate_identifier(symbol, "typed Go symbol")
    type_ref = _named(type_name)
    return GoTypedSymbolRefIR(type_ref, symbol, type_ref if conversion else None)


def _closed_symbol(mapping: Mapping[str, str], value: str, type_name: str, path: str) -> GoTypedSymbolRefIR:
    try:
        symbol = mapping[value]
    except KeyError as exc:
        raise GoAPIPlanError(f"{path}: no reviewed private-kernel symbol") from exc
    return _typed_symbol(type_name, symbol)


def _constraint_number(value: Any, path: str) -> int | float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or isinstance(value, float)
        and not math.isfinite(value)
    ):
        raise GoAPIPlanError(f"{path}: expected finite number")
    return value


def _typed_constraints(field: _Field) -> GoFieldConstraintsPlanIR:
    if field.constraints.arm != "object":
        raise GoAPIPlanError(f"enriched field {field.id}: constraints must be an object")
    values = {key: value for key, value in field.constraints.fields}
    allowed = {
        "max_utf8_bytes",
        "min_items",
        "max_items",
        "pattern",
        "enum",
        "min",
        "max",
        "max_item_utf8_bytes",
        "max_depth",
        "max_properties",
    }
    if set(values) - allowed:
        raise GoAPIPlanError(f"enriched field {field.id}: unsupported private-kernel constraint")

    def integer(name: str) -> int:
        value = values.get(name)
        if value is None:
            return 0
        if value.arm != "integer" or value.integer_value is None or value.integer_value < 0:
            raise GoAPIPlanError(f"enriched field {field.id}.{name}: expected non-negative integer")
        return value.integer_value

    def text(name: str) -> str:
        value = values.get(name)
        if value is None:
            return ""
        if value.arm != "string" or value.string_value is None:
            raise GoAPIPlanError(f"enriched field {field.id}.{name}: expected string")
        return value.string_value

    enum_value = values.get("enum")
    enum_values: tuple[str, ...] = ()
    if enum_value is not None:
        if enum_value.arm != "sequence" or any(
            item.arm != "string" or item.string_value is None for item in enum_value.items
        ):
            raise GoAPIPlanError(f"enriched field {field.id}.enum: expected string sequence")
        enum_values = tuple(item.string_value or "" for item in enum_value.items)
        if len(enum_values) != len(set(enum_values)):
            raise GoAPIPlanError(f"enriched field {field.id}.enum: duplicate value")

    minimum_value = values.get("min")
    maximum_value = values.get("max")

    def number(value: GoFactValueIR | None, name: str) -> int | float | None:
        if value is None:
            return None
        if value.arm == "integer" and value.integer_value is not None:
            return value.integer_value
        if value.arm == "double" and value.double_value is not None:
            return value.double_value
        raise GoAPIPlanError(f"enriched field {field.id}.{name}: expected finite number")

    minimum = number(minimum_value, "min")
    maximum = number(maximum_value, "max")
    int_min = int_max = None
    uint_min = uint_max = None
    float_min = float_max = None
    if field.primitive_type == "int64":
        if any(value is not None and not isinstance(value, int) for value in (minimum, maximum)):
            raise GoAPIPlanError(f"enriched field {field.id}: int64 bounds must be integers")
        int_min, int_max = minimum, maximum
    elif field.primitive_type in {"uint32", "uint64"}:
        if any(value is not None and (not isinstance(value, int) or value < 0) for value in (minimum, maximum)):
            raise GoAPIPlanError(f"enriched field {field.id}: unsigned bounds must be non-negative integers")
        uint_min, uint_max = minimum, maximum
    elif field.primitive_type == "double":
        float_min, float_max = minimum, maximum
    elif minimum is not None or maximum is not None:
        raise GoAPIPlanError(f"enriched field {field.id}: numeric bounds disagree with field type")
    structured = None
    if field.primitive_type == "structured":
        required = ("max_utf8_bytes", "max_item_utf8_bytes", "max_items", "max_depth", "max_properties")
        if any(name not in values for name in required):
            raise GoAPIPlanError(f"enriched field {field.id}: structured bounds are incomplete")
        structured = GoKernelLimitsIR(*(integer(name) for name in required))
    return GoFieldConstraintsPlanIR(
        integer("max_utf8_bytes") if field.primitive_type in {"string", "string[]"} else 0,
        integer("max_item_utf8_bytes") if field.primitive_type == "string[]" else 0,
        integer("min_items") if field.primitive_type == "string[]" else 0,
        integer("max_items") if field.primitive_type == "string[]" else 0,
        text("pattern") if field.primitive_type in {"string", "string[]"} else "",
        enum_values if field.primitive_type in {"string", "string[]"} else (),
        int_min,
        int_max,
        uint_min,
        uint_max,
        float_min,
        float_max,
        structured,
    )


def _validate_identifier(value: str, path: str) -> None:
    if not value.isascii() or _GO_IDENTIFIER.fullmatch(value) is None or value in _GO_RESERVED_IDENTIFIERS:
        raise GoAPIPlanError(f"{path}: invalid or reserved Go identifier")


def _policy(index: Any) -> _Policy:
    raw = _read(index, "go_symbol_policy", "candidate")
    if _read(raw, "version", "go_symbol_policy") != 1 or _read(raw, "package", "go_symbol_policy") != "observability":
        raise GoAPIPlanError("go_symbol_policy: unsupported policy identity")
    if any(
        _read(raw, name, "go_symbol_policy") != "reject"
        for name in ("reserved_word_policy", "collision_policy", "auto_suffix_policy")
    ):
        raise GoAPIPlanError("go_symbol_policy: repair policies are forbidden")
    separators = tuple(
        _string(item, "go_symbol_policy.separators")
        for item in _sequence(_read(raw, "separators", "go_symbol_policy"), "go_symbol_policy.separators")
    )
    if not separators or len(separators) != len(set(separators)) or any(len(item) != 1 for item in separators):
        raise GoAPIPlanError("go_symbol_policy.separators: invalid separator inventory")
    raw_brands = _read(raw, "brand_spellings", "go_symbol_policy")
    if not isinstance(raw_brands, Mapping) or not raw_brands:
        raise GoAPIPlanError("go_symbol_policy.brand_spellings: expected mapping")
    brands = tuple(
        sorted((_string(key, "brand key"), _string(value, "brand value")) for key, value in raw_brands.items())
    )
    for key, value in brands:
        if key != key.lower():
            raise GoAPIPlanError("go_symbol_policy.brand_spellings: keys must be lowercase")
        _validate_identifier(value, "go_symbol_policy.brand_spellings")
    initialisms = tuple(
        _string(item, "go_symbol_policy.initialisms")
        for item in _sequence(_read(raw, "initialisms", "go_symbol_policy"), "go_symbol_policy.initialisms")
    )
    if (
        not initialisms
        or len(initialisms) != len(set(initialisms))
        or any(item != item.upper() for item in initialisms)
    ):
        raise GoAPIPlanError("go_symbol_policy.initialisms: invalid inventory")
    return _Policy(separators, brands, initialisms)


def _public_name(policy: _Policy, source: str, path: str) -> str:
    source = _string(source, path)
    separators = frozenset(policy.separators)
    tokens: list[str] = []
    current: list[str] = []
    for character in source:
        if character in separators:
            if not current:
                raise GoAPIPlanError(f"{path}: empty Go selector token")
            tokens.append("".join(current))
            current = []
            continue
        if not character.isascii() or not character.isalnum():
            raise GoAPIPlanError(f"{path}: selector tokens require ASCII letters and digits")
        current.append(character)
    if not current:
        raise GoAPIPlanError(f"{path}: empty Go selector token")
    tokens.append("".join(current))
    brands = dict(policy.brand_spellings)
    initialisms = frozenset(policy.initialisms)
    result = "".join(
        brands[token.lower()]
        if token.lower() in brands
        else token.upper()
        if token.upper() in initialisms
        else token[:1].upper() + token[1:].lower()
        for token in tokens
    )
    _validate_identifier(result, path)
    return result


def _symbol_table(index: Any) -> tuple[tuple[_Symbol, ...], str]:
    raw = _read(index, "go_symbol_table", "candidate")
    if _read(raw, "version", "go_symbol_table") != 1 or _read(raw, "package", "go_symbol_table") != "observability":
        raise GoAPIPlanError("go_symbol_table: unsupported table identity")
    rows = tuple(
        _Symbol(
            _string(_read(item, "kind", f"go_symbol_table.rows[{position}]"), "symbol kind"),
            _string(_read(item, "source_id", f"go_symbol_table.rows[{position}]"), "symbol source"),
            _string(_read(item, "symbol", f"go_symbol_table.rows[{position}]"), "symbol name"),
            _string(_read(item, "declaration_form", f"go_symbol_table.rows[{position}]"), "declaration form"),
        )
        for position, item in enumerate(_sequence(_read(raw, "rows", "go_symbol_table"), "go_symbol_table.rows"))
    )
    if not rows:
        raise GoAPIPlanError("go_symbol_table.rows: empty table")
    rank = {kind: position for position, kind in enumerate(_GO_SYMBOL_KIND_ORDER)}
    keys: set[tuple[str, str]] = set()
    symbols: set[str] = set()
    prior: tuple[int, bytes] | None = None
    kind_counts = {kind: 0 for kind in _GO_SYMBOL_KIND_ORDER}
    declaration_counts = {form: 0 for form in _DECLARATION_FORMS}
    for row in rows:
        if row.kind not in rank or row.declaration_form not in _DECLARATION_FORMS:
            raise GoAPIPlanError("go_symbol_table.rows: unknown kind or declaration form")
        if _FORM_BY_KIND[row.kind] != row.declaration_form:
            raise GoAPIPlanError("go_symbol_table.rows: declaration form disagrees with kind")
        if not row.source_id.isascii():
            raise GoAPIPlanError("go_symbol_table.rows: non-ASCII source identity")
        _validate_identifier(row.symbol, "go_symbol_table.rows.symbol")
        key = (row.kind, row.source_id)
        order_key = (rank[row.kind], row.source_id.encode("ascii"))
        if key in keys or row.symbol in symbols or (prior is not None and order_key <= prior):
            raise GoAPIPlanError("go_symbol_table.rows: duplicate, colliding, or unordered row")
        keys.add(key)
        symbols.add(row.symbol)
        prior = order_key
        kind_counts[row.kind] += 1
        declaration_counts[row.declaration_form] += 1
    materialized_kind_counts = dict(_read(raw, "kind_counts", "go_symbol_table"))
    for optional_kind in (
        "resource_attributes_type",
        "resource_attributes_constructor",
        "resource_attributes_attach",
        "resource_attributes_validator",
    ):
        materialized_kind_counts.setdefault(optional_kind, 0)
    materialized_declaration_counts = dict(_read(raw, "declaration_form_counts", "go_symbol_table"))
    if materialized_kind_counts != kind_counts or materialized_declaration_counts != declaration_counts:
        raise GoAPIPlanError("go_symbol_table: materialized counts disagree with rows")
    payload = json.dumps(
        [[row.kind, row.source_id, row.symbol, row.declaration_form] for row in rows],
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    digest = hashlib.sha256(_GO_SYMBOL_TABLE_DIGEST_DOMAIN + payload).hexdigest()
    if _read(raw, "table_sha256", "go_symbol_table") != digest:
        raise GoAPIPlanError("go_symbol_table: digest disagrees with rows")
    return rows, digest


def _fields(index: Any) -> dict[str, _Field]:
    raw_fields = _read(index, "enriched_fields", "candidate")
    items = tuple(raw_fields.values()) if isinstance(raw_fields, Mapping) else _sequence(raw_fields, "enriched_fields")
    result: dict[str, _Field] = {}
    for position, raw in enumerate(items):
        path = f"enriched_fields[{position}]"
        context = _string(_read(raw, "context", path), f"{path}.context")
        component = {"log": "family", "span": "family", "metric": "family"}.get(context, context)
        placement = _string(_read(raw, "input_placement", path), f"{path}.input_placement")
        input_owner_kind = {
            "family_input": "family",
            "resource_input": "family",
            "event_input": "event",
            "link_input": "link",
            "structured_input": "structured",
            "private_derived": "none",
        }.get(placement)
        if input_owner_kind is None:
            raise GoAPIPlanError(f"{path}.input_placement: unknown public ownership")
        field_types = tuple(
            _string(item, f"{path}.field_types")
            for item in _sequence(_read(raw, "field_types", path), f"{path}.field_types")
        )
        structured_type = _optional(raw, "structured_type")
        if structured_type is not None:
            primitive_type = "structured"
        elif len(field_types) == 1:
            primitive_type = field_types[0]
        else:
            raise GoAPIPlanError(f"{path}.field_types: public Go fields require one closed type")
        field = _Field(
            id=_string(_read(raw, "id", path), f"{path}.id"),
            owner_id=_string(_read(raw, "owner_id", path), f"{path}.owner_id"),
            component=component,
            semantic_source_id=_string(_read(raw, "attribute_id", path), f"{path}.attribute_id"),
            primitive_type=primitive_type,
            structured_type=structured_type,
            requirement=_string(_read(raw, "requirement_level", path), f"{path}.requirement_level"),
            condition_id=_optional(raw, "condition_id"),
            condition_fact=_optional(raw, "condition_fact"),
            false_requirement=_optional(raw, "condition_false_requirement"),
            field_class=_string(_read(raw, "field_class", path), f"{path}.field_class"),
            constraints=_fact_value(_read(raw, "effective_constraints", path), f"{path}.effective_constraints"),
            value_source=_string(_read(raw, "value_source", path), f"{path}.value_source"),
            target_slot=_string(_read(raw, "target_slot", path), f"{path}.target_slot"),
            input_owner_kind=input_owner_kind,
            order=_integer(_read(raw, "order", path), f"{path}.order"),
        )
        if field.id in result:
            raise GoAPIPlanError("enriched_fields: duplicate descriptor ID")
        if field.component not in _COMPONENTS or field.requirement not in _PRESENCE:
            raise GoAPIPlanError(f"{path}: unknown component or requirement")
        if field.value_source not in _VALUE_SOURCES or field.input_owner_kind not in _INPUT_OWNER_KINDS:
            raise GoAPIPlanError(f"{path}: unknown value source or input owner")
        if field.requirement in {"conditional", "optional"} and field.condition_id is not None:
            _string(field.condition_fact, f"{path}.condition_fact")
            _string(field.condition_id, f"{path}.condition_id")
            _string(field.false_requirement, f"{path}.condition_false_requirement")
        elif field.condition_fact is not None:
            raise GoAPIPlanError(f"{path}.condition_fact: only conditional or guarded optional fields bind facts")
        if field.value_source == "input" and field.input_owner_kind == "none":
            raise GoAPIPlanError(f"{path}: input value has no public owner")
        if field.value_source != "input" and field.input_owner_kind != "none":
            raise GoAPIPlanError(f"{path}: derived value cannot expose a public input")
        if field.structured_type is not None and not isinstance(field.structured_type, str):
            raise GoAPIPlanError(f"{path}.structured_type: invalid structured binding")
        result[field.id] = field
    if not result:
        raise GoAPIPlanError("enriched_fields: descriptor inventory is empty")
    return result


def _symbol_index(rows: tuple[_Symbol, ...]) -> dict[tuple[str, str], _Symbol]:
    return {(row.kind, row.source_id): row for row in rows}


def _required_symbol(symbols: Mapping[tuple[str, str], _Symbol], kind: str, source_id: str) -> _Symbol:
    try:
        return symbols[(kind, source_id)]
    except KeyError as exc:
        raise GoAPIPlanError(f"Go declaration {kind}/{source_id}: symbol-table row is missing") from exc


def _base_type(field: _Field, symbols: Mapping[tuple[str, str], _Symbol]) -> GoTypeRefIR:
    if field.structured_type is not None:
        if field.primitive_type != "structured":
            raise GoAPIPlanError(f"enriched field {field.id}: structured binding has incompatible primitive type")
        return _named(_required_symbol(symbols, "structured_type", field.structured_type).symbol)
    mapping = {
        "string": _builtin("string"),
        "boolean": _builtin("bool"),
        "int64": _builtin("int64"),
        "uint32": _builtin("uint32"),
        "uint64": _builtin("uint64"),
        "double": _builtin("float64"),
        "string[]": _slice(_builtin("string")),
    }
    try:
        return mapping[field.primitive_type]
    except KeyError as exc:
        raise GoAPIPlanError(f"enriched field {field.id}: unsupported Go field type") from exc


def _conversion(field: _Field) -> str:
    if field.structured_type is not None:
        return "structured_encoder"
    if field.primitive_type == "string[]":
        return "copied_string_slice"
    return "required_scalar" if field.requirement == "required" else "optional_scalar"


def _public_field(
    field: _Field,
    *,
    owner: str,
    order: int,
    policy: _Policy,
    symbols: Mapping[tuple[str, str], _Symbol],
    selector_prefix: str = "",
) -> GoFieldPlanIR:
    base = _base_type(field, symbols)
    type_ref = base if field.requirement == "required" else _optional_type(base)
    selector = selector_prefix + _public_name(policy, field.semantic_source_id, f"field selector {field.id}")
    return GoFieldPlanIR(
        owner=owner,
        selector=selector,
        type_ref=type_ref,
        order=order,
        presence=field.requirement,
        semantic_source_id=field.semantic_source_id,
        enriched_descriptor_id=field.id,
        value_source=field.value_source,
        target_slot=field.target_slot,
        condition_binding=field.condition_fact,
        mandatory_binding=None,
        conversion_op=_conversion(field),
    )


def _common_field(
    owner: str,
    selector: str,
    type_ref: GoTypeRefIR,
    order: int,
    *,
    presence: str = "required",
    conversion: str = "required_scalar",
) -> GoFieldPlanIR:
    return GoFieldPlanIR(
        owner,
        selector,
        type_ref,
        order,
        presence,
        f"structural.{selector}",
        f"common:{owner}:{selector}",
        "input",
        selector,
        None,
        None,
        conversion,
    )


def _kernel_helper(
    symbol: str,
    parameters: tuple[ParameterIR, ...],
    results: tuple[GoTypeRefIR, ...],
    *,
    receiver: str | None = None,
) -> GoKernelHelperRefIR:
    return GoKernelHelperRefIR(
        symbol,
        _named(receiver) if receiver is not None else None,
        receiver is not None,
        parameters,
        results,
    )


def _family_kernel_helper(signal: str) -> GoKernelHelperRefIR:
    descriptor_type = {
        "log": "familyDescriptor",
        "span": "generatedTraceFamilyContract",
        "metric": "generatedMetricFamilyContract",
    }[signal]
    private_input = {"log": "familyLogBuildInput", "span": "familyTraceBuildInput", "metric": "familyMetricBuildInput"}[
        signal
    ]
    parameters: tuple[ParameterIR, ...]
    symbol: str
    if signal == "log":
        symbol = "buildGeneratedResolvedLog"
        parameters = (
            ("descriptor", _named(descriptor_type)),
            ("resolved", _named("resolvedGeneratedLogContract")),
            ("input", _named(private_input)),
        )
    else:
        symbol = "buildGeneratedTrace" if signal == "span" else "buildGeneratedMetric"
        parameters = (("descriptor", _named(descriptor_type)), ("input", _named(private_input)))
    return _kernel_helper(symbol, parameters, (_named("Record"), _builtin("error")), receiver="FamilyBuilder")


def _metric_number_helper(value_type: str) -> GoKernelHelperRefIR:
    if value_type == "int64":
        return _kernel_helper(
            "familyInt64MetricNumber",
            (("value", _builtin("int64")),),
            (_named("familyMetricNumber"),),
        )
    if value_type == "double":
        return _kernel_helper(
            "familyDoubleMetricNumber",
            (("value", _builtin("float64")),),
            (_named("familyMetricNumber"),),
        )
    raise GoAPIPlanError("metric number helper: unsupported value type")


def _mandatory_resolver_helper() -> GoKernelHelperRefIR:
    return _kernel_helper(
        "resolveGeneratedLogMandatory",
        (("mandatory", _builtin("bool")),),
        (_named("resolvedGeneratedLogContract"),),
    )


def _string_validation_helper() -> GoKernelHelperRefIR:
    return _kernel_helper(
        "validateFamilyString",
        (("value", _builtin("string")), ("constraints", _named("familyFieldConstraints"))),
        (_builtin("error"),),
    )


def _condition_fields(
    owner: str,
    descriptor_ids: Sequence[str],
    fields: Mapping[str, _Field],
    start: int,
    policy: _Policy,
) -> tuple[GoFieldPlanIR, ...]:
    seen: dict[str, str] = {}
    result: list[GoFieldPlanIR] = []
    for descriptor_id in descriptor_ids:
        field = fields[descriptor_id]
        fact = field.condition_fact
        condition_id = field.condition_id
        if fact is None:
            continue
        if condition_id is None:
            raise GoAPIPlanError(f"{owner}: conditional field has no condition ID")
        if fact.startswith("attribute:"):
            source_ref = fact.removeprefix("attribute:")
            if not source_ref:
                raise GoAPIPlanError(f"{owner}: Boolean-attribute condition has no source")
            continue
        prior = seen.get(fact)
        if prior is not None:
            if prior != condition_id:
                raise GoAPIPlanError(f"{owner}: condition fact maps to multiple condition IDs")
            continue
        seen[fact] = condition_id
        selector = "Condition" + _public_name(policy, fact, f"condition selector {owner}")
        result.append(
            GoFieldPlanIR(
                owner,
                selector,
                _builtin("bool"),
                start + len(result),
                "required",
                fact,
                f"condition:{owner}:{fact}",
                "input",
                "conditions",
                fact,
                None,
                "condition_fact",
            )
        )
    return tuple(result)


def _mandatory_fields(owner: str, raw_program: Any, start: int, policy: _Policy) -> tuple[GoFieldPlanIR, ...]:
    facts = _sequence(_read(raw_program, "fact_terms", f"mandatory program {owner}"), "mandatory fact terms")
    result: list[GoFieldPlanIR] = []
    seen: set[str] = set()
    for raw_fact in facts:
        fact = _string(raw_fact, f"mandatory program {owner}.fact_terms")
        if fact in seen:
            raise GoAPIPlanError(f"mandatory program {owner}: duplicate fact term")
        seen.add(fact)
        selector = "Mandatory" + _public_name(policy, fact, f"mandatory selector {owner}")
        result.append(
            GoFieldPlanIR(
                owner,
                selector,
                _builtin("bool"),
                start + len(result),
                "required",
                fact,
                f"mandatory:{owner}:{fact}",
                "input",
                "mandatory",
                None,
                fact,
                "mandatory_fact",
            )
        )
    return tuple(result)


def _validate_owner_fields(fields: Sequence[GoFieldPlanIR]) -> None:
    selectors: set[str] = set()
    orders: set[int] = set()
    for field in fields:
        _validate_identifier(field.selector, f"{field.owner} field selector")
        if field.selector in selectors or field.order in orders or field.conversion_op not in _CONVERSIONS:
            raise GoAPIPlanError(f"{field.owner}: field selector/order collision")
        selectors.add(field.selector)
        orders.add(field.order)
    if tuple(sorted(orders)) != tuple(range(len(fields))):
        raise GoAPIPlanError("Go input field orders are not contiguous")


def _private_encoder_symbol(structured_symbol: str) -> str:
    _validate_identifier(structured_symbol, "structured encoder owner")
    return "encode" + structured_symbol


def _contained_named_type(type_ref: GoTypeRefIR) -> str | None:
    current = type_ref
    while current.arm in {"optional", "slice"}:
        if current.element is None:
            raise GoAPIPlanError("nested Go type is missing its element")
        current = current.element
    return current.name if current.arm == "named" else None


def _value_bindings(
    public_fields: Sequence[GoFieldPlanIR],
    fields: Mapping[str, _Field],
    symbols: Mapping[tuple[str, str], _Symbol],
) -> tuple[GoFieldValueBindingPlanIR, ...]:
    result: list[GoFieldValueBindingPlanIR] = []
    for public in public_fields:
        if public.enriched_descriptor_id.startswith(("common:", "condition:", "mandatory:")):
            continue
        field = fields.get(public.enriched_descriptor_id)
        if field is None or field.value_source != "input":
            continue
        encoder = None
        if field.structured_type is not None:
            encoder = _private_encoder_symbol(
                _required_symbol(symbols, "structured_type", field.structured_type).symbol
            )
        result.append(
            GoFieldValueBindingPlanIR(
                field.id,
                field.semantic_source_id,
                public.selector,
                public.presence,
                public.conversion_op,
                encoder,
                _kernel_field(field).type_ref,
                _typed_constraints(field),
            )
        )
    return tuple(result)


def _condition_bindings(
    owner_fields: Sequence[GoFieldPlanIR], descriptor_ids: Sequence[str], fields: Mapping[str, _Field]
) -> tuple[GoConditionBindingPlanIR, ...]:
    selector_by_fact = {
        field.condition_binding: field.selector for field in owner_fields if field.conversion_op == "condition_fact"
    }
    selector_by_attribute = {
        field.semantic_source_id: (field.selector, field.presence != "required")
        for field in owner_fields
        if field.value_source == "input" and field.conversion_op != "condition_fact"
    }
    condition_by_fact: dict[str, str] = {}
    for descriptor_id in descriptor_ids:
        field = fields[descriptor_id]
        if field.condition_fact is None or field.condition_id is None:
            continue
        prior = condition_by_fact.setdefault(field.condition_fact, field.condition_id)
        if prior != field.condition_id:
            raise GoAPIPlanError("condition fact maps to multiple condition IDs")
    if set(selector_by_fact) != set(condition_by_fact):
        ordinary_facts = {fact for fact in condition_by_fact if not fact.startswith("attribute:")}
        if set(selector_by_fact) != ordinary_facts:
            raise GoAPIPlanError("condition selector coverage disagrees with enriched fields")
    bindings: list[GoConditionBindingPlanIR] = []
    for fact, condition_id in condition_by_fact.items():
        optional_source = False
        if fact.startswith("attribute:"):
            source_ref = fact.removeprefix("attribute:")
            source = selector_by_attribute.get(source_ref)
            if source is None:
                raise GoAPIPlanError("Boolean-attribute condition source is absent from the public input")
            selector, optional_source = source
        else:
            selector = selector_by_fact[fact]
        bindings.append(GoConditionBindingPlanIR(condition_id, fact, selector, optional_source))
    return tuple(bindings)


def _field_ids(raw: Any, name: str, path: str, fields: Mapping[str, _Field]) -> tuple[str, ...]:
    ids = tuple(_string(item, f"{path}.{name}") for item in _sequence(_read(raw, name, path), f"{path}.{name}"))
    if len(ids) != len(set(ids)) or any(item not in fields for item in ids):
        raise GoAPIPlanError(f"{path}.{name}: duplicate or unknown enriched descriptor")
    return ids


def _kernel_field(field: _Field) -> GoKernelFieldDescriptorIR:
    field_type = "structured" if field.structured_type is not None else field.primitive_type
    try:
        type_symbol = _FIELD_TYPE_SYMBOLS[field_type]
        requirement_symbol = _REQUIREMENT_SYMBOLS[field.requirement]
        field_class_symbol = _FIELD_CLASS_SYMBOLS[field.field_class]
        source_symbol = _VALUE_SOURCE_SYMBOLS[field.value_source]
    except KeyError as exc:
        raise GoAPIPlanError(f"enriched field {field.id}: private-kernel enum mapping is missing") from exc
    false_ref = None
    if field.false_requirement is not None:
        try:
            false_ref = _typed_symbol("familyFalseRequirement", _FALSE_REQUIREMENT_SYMBOLS[field.false_requirement])
        except KeyError as exc:
            raise GoAPIPlanError(f"enriched field {field.id}: false-requirement enum mapping is missing") from exc
    return GoKernelFieldDescriptorIR(
        field.id,
        field.semantic_source_id,
        field_type,
        field.requirement,
        field.condition_id,
        field.condition_fact,
        field.false_requirement,
        field.field_class,
        field.constraints,
        field.value_source,
        field.target_slot,
        field.order,
        _typed_symbol("familyFieldType", type_symbol),
        _typed_symbol("familyRequirement", requirement_symbol),
        false_ref,
        _typed_symbol("FieldClass", field_class_symbol),
        _typed_symbol("familyValueSource", source_symbol),
        _typed_constraints(field),
    )


def _kernel_limits(containers: Mapping[str, Any], descriptor_id: str) -> GoKernelLimitsIR:
    descriptor = containers.get(descriptor_id)
    if descriptor is None:
        raise GoAPIPlanError(f"enriched container {descriptor_id}: required limit contract is missing")
    raw_bounds = _read(descriptor, "bounds", f"enriched container {descriptor_id}")
    if not isinstance(raw_bounds, Mapping):
        raise GoAPIPlanError(f"enriched container {descriptor_id}: bounds are invalid")

    def bound(name: str) -> int:
        return _integer(raw_bounds.get(name), f"enriched container {descriptor_id}.{name}", minimum=1)

    return GoKernelLimitsIR(
        bound("max_utf8_bytes"),
        bound("max_item_utf8_bytes"),
        bound("max_items"),
        bound("max_depth"),
        bound("max_properties"),
    )


def _tag_fields(value: Any, path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise GoAPIPlanError(f"{path}: expected tagged compiler mapping")
    fields = value.get("fields") if "$type" in value else value
    if not isinstance(fields, Mapping):
        raise GoAPIPlanError(f"{path}: tagged fields are invalid")
    return fields


def _trace_contract_defaults(index: Any) -> GoTraceContractPlanIR:
    fields = _read(index, "fields", "candidate")
    if not isinstance(fields, Mapping):
        raise GoAPIPlanError("candidate.fields: expected mapping")
    profiles = _sequence(fields["semantic_profiles"], "candidate.fields.semantic_profiles")
    if len(profiles) != 1:
        raise GoAPIPlanError("candidate semantic profile inventory is not singular")
    profile = _tag_fields(profiles[0], "semantic profile")
    contract = _tag_fields(fields["structural_contract"], "structural contract")

    def structural_limits(object_name: str, field_name: str) -> GoKernelLimitsIR:
        structural = _tag_fields(contract[object_name], f"structural contract {object_name}")
        matching = [
            _tag_fields(item, f"structural contract {object_name}.fields")
            for item in _sequence(structural["fields"], f"structural contract {object_name}.fields")
            if _tag_fields(item, f"structural contract {object_name}.fields").get("name") == field_name
        ]
        if len(matching) != 1:
            raise GoAPIPlanError(f"structural contract {object_name}.{field_name}: field is missing")
        normalization = _tag_fields(matching[0]["normalization"], f"{object_name}.{field_name}.normalization")
        constraints = normalization["effective_constraints"]
        if not isinstance(constraints, Mapping):
            raise GoAPIPlanError(f"structural contract {object_name}.{field_name}: constraints are invalid")

        def value(name: str) -> int:
            return _integer(constraints.get(name), f"{object_name}.{field_name}.{name}", minimum=1)

        return GoKernelLimitsIR(
            value("max_utf8_bytes"),
            value("max_item_utf8_bytes"),
            value("max_items"),
            value("max_depth"),
            value("max_properties"),
        )

    events_limits = structural_limits("trace_body", "events")
    links_limits = structural_limits("trace_body", "links")
    scope = _tag_fields(contract["trace_scope"], "trace scope")
    scope_constants: dict[str, str] = {}
    for raw_field in _sequence(scope["fields"], "trace scope fields"):
        field = _tag_fields(raw_field, "trace scope field")
        constant = field.get("const")
        if isinstance(constant, str):
            scope_constants[_string(field["name"], "trace scope field name")] = constant
    try:
        scope_name = scope_constants["name"]
        scope_schema_url = scope_constants["schema_url"]
    except KeyError as exc:
        raise GoAPIPlanError("trace scope constants are incomplete") from exc
    return GoTraceContractPlanIR(
        structural_limits("trace_body", "attributes"),
        structural_limits("trace_resource", "attributes"),
        structural_limits("trace_scope", "attributes"),
        structural_limits("trace_event", "attributes"),
        structural_limits("trace_link", "attributes"),
        events_limits.max_items,
        links_limits.max_items,
        scope_name,
        scope_schema_url,
        _string(profile["trace_schema_version"], "semantic profile trace schema version"),
        _string(profile["id"], "semantic profile ID"),
    )


def _metric_limits_from_trace_contract(index: Any) -> GoKernelLimitsIR:
    fields = _read(index, "fields", "candidate")
    contract = _tag_fields(fields["structural_contract"], "structural contract")
    instrument = _tag_fields(contract["metric_instrument_data"], "metric instrument data")
    matching = [
        _tag_fields(item, "metric instrument field")
        for item in _sequence(instrument["fields"], "metric instrument fields")
        if _tag_fields(item, "metric instrument field").get("name") == "attributes"
    ]
    if len(matching) != 1:
        raise GoAPIPlanError("metric attribute structural contract is missing")
    normalization = _tag_fields(matching[0]["normalization"], "metric attribute normalization")
    constraints = normalization["effective_constraints"]
    if not isinstance(constraints, Mapping):
        raise GoAPIPlanError("metric attribute constraints are invalid")
    return GoKernelLimitsIR(
        _integer(constraints.get("max_utf8_bytes"), "metric max UTF8", minimum=1),
        _integer(constraints.get("max_item_utf8_bytes"), "metric max item UTF8", minimum=1),
        _integer(constraints.get("max_items"), "metric max items", minimum=1),
        _integer(constraints.get("max_depth"), "metric max depth", minimum=1),
        _integer(constraints.get("max_properties"), "metric max properties", minimum=1),
    )


def _cross_field_relations(
    index: Any,
    family_ids: Sequence[str],
    fields: Mapping[str, _Field],
) -> tuple[GoCrossFieldRelationPlanIR, ...]:
    candidate_fields = _read(index, "fields", "candidate")
    if not isinstance(candidate_fields, Mapping):
        raise GoAPIPlanError("candidate.fields: expected mapping")
    raw_catalogs = _sequence(candidate_fields.get("value_catalogs"), "candidate.fields.value_catalogs")
    family_by_key = {fields[descriptor_id].semantic_source_id: fields[descriptor_id] for descriptor_id in family_ids}
    relations: list[GoCrossFieldRelationPlanIR] = []
    for position, raw_catalog in enumerate(raw_catalogs):
        path = f"candidate.fields.value_catalogs[{position}]"
        catalog = _tag_fields(raw_catalog, path)
        catalog_id = _string(catalog.get("id"), f"{path}.id")
        arm = _string(catalog.get("kind"), f"{path}.kind")
        if arm != "string-int64-bijection":
            raise GoAPIPlanError(f"{path}.kind: unsupported cross-field relation")
        value_key = _string(catalog.get("paired_value_attribute"), f"{path}.paired_value_attribute")
        code_key = _string(catalog.get("code_attribute"), f"{path}.code_attribute")
        value_field = family_by_key.get(value_key)
        code_field = family_by_key.get(code_key)
        if (value_field is None) != (code_field is None):
            raise GoAPIPlanError(f"{path}: family exposes only one side of a cross-field relation")
        if value_field is None:
            continue
        if (
            value_field.primitive_type != "string"
            or code_field is None
            or code_field.primitive_type != "int64"
            or value_field.value_source != "input"
            or code_field.value_source != "input"
        ):
            raise GoAPIPlanError(f"{path}: cross-field relation types are incompatible with the kernel")
        value_constraints = _typed_constraints(value_field)
        code_constraints = _typed_constraints(code_field)
        if not value_constraints.enum_values:
            raise GoAPIPlanError(f"{path}: paired value field requires a closed enum")
        entries: list[GoValueCodeEntryPlanIR] = []
        seen_values: set[str] = set()
        seen_codes: set[int] = set()
        raw_entries = _sequence(catalog.get("entries"), f"{path}.entries")
        if not raw_entries or len(raw_entries) > MAX_CROSS_FIELD_RELATION_ENTRIES:
            raise GoAPIPlanError(f"{path}.entries: expected bounded nonempty relation")
        for entry_position, raw_entry in enumerate(raw_entries):
            entry = _tag_fields(raw_entry, f"{path}.entries[{entry_position}]")
            value = _string(entry.get("value"), f"{path}.entries[{entry_position}].value")
            code = _integer(entry.get("code"), f"{path}.entries[{entry_position}].code", minimum=1)
            if code > 2**63 - 1:
                raise GoAPIPlanError(f"{path}.entries[{entry_position}].code: outside signed int64")
            if value in seen_values or code in seen_codes:
                raise GoAPIPlanError(f"{path}.entries: relation is not bijective")
            if value_constraints.max_utf8_bytes > 0 and len(value.encode("utf-8")) > value_constraints.max_utf8_bytes:
                raise GoAPIPlanError(f"{path}.entries[{entry_position}].value: violates paired field bounds")
            if value not in value_constraints.enum_values:
                raise GoAPIPlanError(f"{path}.entries[{entry_position}].value: outside paired field enum")
            if value_constraints.pattern:
                try:
                    matches = re.search(value_constraints.pattern, value) is not None
                except re.error as exc:
                    raise GoAPIPlanError(f"{path}: paired field pattern is invalid") from exc
                if not matches:
                    raise GoAPIPlanError(f"{path}.entries[{entry_position}].value: violates paired field pattern")
            if code_constraints.int_min is not None and code < code_constraints.int_min:
                raise GoAPIPlanError(f"{path}.entries[{entry_position}].code: below paired field range")
            if code_constraints.int_max is not None and code > code_constraints.int_max:
                raise GoAPIPlanError(f"{path}.entries[{entry_position}].code: above paired field range")
            seen_values.add(value)
            seen_codes.add(code)
            entries.append(GoValueCodeEntryPlanIR(value, code))
        if seen_values != set(value_constraints.enum_values):
            raise GoAPIPlanError(f"{path}.entries: does not exactly cover paired field enum")
        try:
            error_symbol = _VALUE_CATALOG_ERROR_SYMBOLS[catalog_id]
        except KeyError as exc:
            raise GoAPIPlanError(f"{path}: no reviewed cross-field mismatch error") from exc
        relations.append(
            GoCrossFieldRelationPlanIR(
                catalog_id,
                arm,
                value_key,
                code_key,
                tuple(entries),
                _typed_symbol("FamilyBuildErrorCode", error_symbol),
            )
        )
    return tuple(relations)


def _ordered_public_fields(
    ids: Sequence[str],
    *,
    owner: str,
    component: str,
    input_owner_kind: str,
    start: int,
    policy: _Policy,
    symbols: Mapping[tuple[str, str], _Symbol],
    fields: Mapping[str, _Field],
    selector_prefix: str = "",
    descriptor_owner_id: str | None = None,
) -> tuple[GoFieldPlanIR, ...]:
    selected = [fields[item] for item in ids]
    expected_descriptor_owner = descriptor_owner_id or owner
    if any(
        field.owner_id != expected_descriptor_owner
        or field.component != component
        or (field.value_source == "input" and field.input_owner_kind != input_owner_kind)
        for field in selected
    ):
        raise GoAPIPlanError(f"{owner}: enriched field ownership disagrees with descriptor")
    public = sorted((field for field in selected if field.value_source == "input"), key=lambda field: field.order)
    if len({field.order for field in public}) != len(public):
        raise GoAPIPlanError(f"{owner}: duplicate enriched field order")
    return tuple(
        _public_field(
            field,
            owner=owner,
            order=start + position,
            policy=policy,
            symbols=symbols,
            selector_prefix=selector_prefix,
        )
        for position, field in enumerate(public)
    )


def _log_common(owner: str, outcome: str) -> tuple[GoFieldPlanIR, ...]:
    fields = [
        _common_field(owner, "Envelope", _named("FamilyEnvelopeInput"), 0),
        _common_field(
            owner, "Severity", _optional_type(_named("Severity")), 1, presence="optional", conversion="optional_scalar"
        ),
        _common_field(
            owner, "LogLevel", _optional_type(_named("LogLevel")), 2, presence="optional", conversion="optional_scalar"
        ),
    ]
    if outcome == "required":
        fields.append(_common_field(owner, "Outcome", _named("Outcome"), 3))
    elif outcome == "optional":
        fields.append(
            _common_field(
                owner,
                "Outcome",
                _optional_type(_named("Outcome")),
                3,
                presence="optional",
                conversion="optional_scalar",
            )
        )
    elif outcome != "forbidden":
        raise GoAPIPlanError(f"{owner}: invalid log outcome requirement")
    return tuple(fields)


def _span_common(owner: str) -> tuple[GoFieldPlanIR, ...]:
    specs = (
        ("Envelope", _named("FamilyEnvelopeInput"), "required", "required_scalar"),
        ("Outcome", _named("Outcome"), "required", "required_scalar"),
        ("Kind", _builtin("string"), "required", "required_scalar"),
        ("StartTimeUnixNano", _builtin("uint64"), "required", "required_scalar"),
        ("EndTimeUnixNano", _builtin("uint64"), "required", "required_scalar"),
        ("ParentSpanID", _optional_type(_builtin("string")), "optional", "optional_scalar"),
        ("TraceState", _optional_type(_builtin("string")), "optional", "optional_scalar"),
        ("Flags", _builtin("uint32"), "required", "required_scalar"),
        ("Status", _named("TraceStatusInput"), "required", "required_scalar"),
        ("Resource", _named("TraceResourceInput"), "required", "required_scalar"),
        ("Scope", _named("TraceScopeInput"), "required", "required_scalar"),
        ("DroppedAttributesCount", _optional_type(_builtin("uint32")), "optional", "optional_scalar"),
        ("Events", _slice(_named("TraceEventInput")), "required", "trace_event"),
        ("DroppedEventsCount", _optional_type(_builtin("uint32")), "optional", "optional_scalar"),
        ("Links", _slice(_named("TraceLinkInput")), "required", "trace_link"),
        ("DroppedLinksCount", _optional_type(_builtin("uint32")), "optional", "optional_scalar"),
    )
    return tuple(
        _common_field(owner, selector, type_ref, order, presence=presence, conversion=conversion)
        for order, (selector, type_ref, presence, conversion) in enumerate(specs)
    )


def _event_common(owner: str) -> tuple[GoFieldPlanIR, ...]:
    return (
        _common_field(owner, "TimeUnixNano", _builtin("uint64"), 0),
        _common_field(
            owner,
            "DroppedAttributesCount",
            _optional_type(_builtin("uint32")),
            1,
            presence="optional",
            conversion="optional_scalar",
        ),
    )


def _link_common(owner: str) -> tuple[GoFieldPlanIR, ...]:
    return (
        _common_field(owner, "TraceID", _builtin("string"), 0),
        _common_field(owner, "SpanID", _builtin("string"), 1),
        _common_field(
            owner,
            "TraceState",
            _optional_type(_builtin("string")),
            2,
            presence="optional",
            conversion="optional_scalar",
        ),
        _common_field(
            owner,
            "DroppedAttributesCount",
            _optional_type(_builtin("uint32")),
            3,
            presence="optional",
            conversion="optional_scalar",
        ),
    )


def _structured_value_type(raw: Any, symbols: Mapping[tuple[str, str], _Symbol], path: str) -> GoTypeRefIR:
    scalar = _optional(raw, "scalar")
    reference = _optional(raw, "reference")
    if (scalar is None) == (reference is None):
        raise GoAPIPlanError(f"{path}: expected exactly one scalar or reference")
    if reference is not None:
        target = _string(_read(reference, "structured_ref", path), f"{path}.structured_ref")
        return _named(_required_symbol(symbols, "structured_type", target).symbol)
    field_type = _string(_read(scalar, "field_type", path), f"{path}.field_type")
    mapping = {
        "string": _builtin("string"),
        "boolean": _builtin("bool"),
        "int64": _builtin("int64"),
        "double": _builtin("float64"),
    }
    try:
        return mapping[field_type]
    except KeyError as exc:
        raise GoAPIPlanError(f"{path}: unsupported structured scalar type") from exc


def _compile_structured(
    index: Any,
    *,
    policy: _Policy,
    symbols: Mapping[tuple[str, str], _Symbol],
    fields: Mapping[str, _Field],
) -> tuple[
    tuple[GoStructuredPlanIR, ...], tuple[GoInputPlanIR, ...], tuple[GoCallablePlanIR, ...], set[DeclarationKeyIR]
]:
    raw_descriptors = _read(index, "structured_types", "candidate")
    containers = _read(index, "enriched_containers", "candidate")
    if not isinstance(containers, Mapping):
        raise GoAPIPlanError("enriched_containers: expected compiler-owned mapping")
    items = (
        tuple(raw_descriptors.values())
        if isinstance(raw_descriptors, Mapping)
        else _sequence(raw_descriptors, "structured_types")
    )
    by_id: dict[str, Any] = {}
    for position, raw in enumerate(items):
        identifier = _string(_read(raw, "id", f"structured_types[{position}]"), "structured descriptor id")
        if identifier in by_id:
            raise GoAPIPlanError("structured_types: duplicate type")
        by_id[identifier] = raw
    expected = {source_id for kind, source_id in symbols if kind == "structured_type"}
    if set(by_id) != expected:
        raise GoAPIPlanError("structured_types: complete structured descriptor inventory is required")
    plans: list[GoStructuredPlanIR] = []
    inputs: list[GoInputPlanIR] = []
    callables: list[GoCallablePlanIR] = []
    planned: set[DeclarationKeyIR] = set()
    for identifier in sorted(by_id, key=str.encode):
        raw = by_id[identifier]
        symbol = _required_symbol(symbols, "structured_type", identifier)
        shape = _string(_read(raw, "kind", f"structured {identifier}"), f"structured {identifier}.kind")
        if shape not in _STRUCTURED_SHAPES:
            raise GoAPIPlanError(f"structured {identifier}: unknown shape")
        container = containers.get(f"structured:{identifier}")
        if container is None:
            raise GoAPIPlanError(f"structured {identifier}: enriched container descriptor is missing")
        scalar_ids = tuple(
            _string(item, f"structured {identifier}.child_fields")
            for item in _sequence(
                _read(container, "child_fields", f"structured {identifier}"),
                f"structured {identifier}.child_fields",
            )
        )
        scalar_by_member = {fields[item].semantic_source_id: fields[item] for item in scalar_ids if item in fields}
        if len(scalar_by_member) != len(scalar_ids):
            raise GoAPIPlanError(f"structured {identifier}: scalar descriptor links are incomplete")
        used_scalar_ids: set[str] = set()
        value_fields: list[GoFieldPlanIR] = []
        member_plans: list[GoStructuredMemberPlanIR] = []
        for order, raw_field in enumerate(_optional(raw, "fields", ()) or ()):
            name = _string(_read(raw_field, "name", f"structured {identifier}.fields"), "structured field name")
            required = _read(raw_field, "required", f"structured {identifier}.{name}")
            if not isinstance(required, bool):
                raise GoAPIPlanError(f"structured {identifier}.{name}: required flag is not Boolean")
            scalar = _optional(raw_field, "scalar")
            if scalar is not None:
                descriptor = scalar_by_member.get(f"field:{name}")
                if descriptor is None:
                    raise GoAPIPlanError(f"structured {identifier}.{name}: scalar descriptor is missing")
                used_scalar_ids.add(descriptor.id)
                base_type = _base_type(descriptor, symbols)
                descriptor_id = descriptor.id
            else:
                base_type = _structured_value_type(raw_field, symbols, f"structured {identifier}.{name}")
                descriptor_id = f"structured-edge:{identifier}:field:{name}"
                if descriptor_id not in containers:
                    raise GoAPIPlanError(f"structured {identifier}.{name}: reference edge descriptor is missing")
            value_fields.append(
                GoFieldPlanIR(
                    identifier,
                    _public_name(policy, name, f"structured selector {identifier}.{name}"),
                    base_type if required else _optional_type(base_type),
                    order,
                    "required" if required else "optional",
                    name,
                    descriptor_id,
                    "input",
                    "structured.fixed",
                    None,
                    None,
                    "structured_encoder"
                    if base_type.arm == "named"
                    else ("required_scalar" if required else "optional_scalar"),
                )
            )
        item_type: GoTypeRefIR | None = None
        if shape == "array":
            item_type = _structured_value_type(
                {"scalar": _optional(raw, "items_scalar"), "reference": _optional(raw, "items_reference")},
                symbols,
                f"structured {identifier}.items",
            )
        arm_types: list[tuple[str, GoTypeRefIR]] = []
        arm_shapes: list[tuple[str, str, str]] = []
        for variant in _optional(raw, "variants", ()) or ():
            tag = _string(_read(variant, "tag", f"structured {identifier}.variants"), "structured variant tag")
            target = _string(
                _read(variant, "structured_ref", f"structured {identifier}.variants"), "structured variant target"
            )
            arm_types.append(
                (f"{identifier}#{tag}", _named(_required_symbol(symbols, "structured_type", target).symbol))
            )
            arm_shapes.append((f"{identifier}#{tag}", "registered", "Value"))
        dynamic_variant = _optional(raw, "dynamic_variant")
        if dynamic_variant is not None:
            arm_id = _string(_read(dynamic_variant, "arm_id", f"structured {identifier}"), "dynamic arm ID")
            target = _string(_read(dynamic_variant, "structured_ref", f"structured {identifier}"), "dynamic arm target")
            arm_types.append(
                (f"{identifier}#{arm_id}", _named(_required_symbol(symbols, "structured_type", target).symbol))
            )
            arm_shapes.append((f"{identifier}#{arm_id}", "dynamic", "Tag,Value"))
        canonical = _optional(raw, "canonical_json")
        if canonical is not None:
            canonical_types: dict[str, GoTypeRefIR] = {
                "array": _slice(_named(symbol.symbol)),
                "object": _slice(
                    _named(_required_symbol(symbols, "structured_member_input", f"{identifier}#entry").symbol)
                ),
            }
            for scalar_arm in ("boolean", "int64", "finite_double", "string"):
                descriptor = scalar_by_member.get(f"canonical_arm:{scalar_arm}")
                if descriptor is None:
                    raise GoAPIPlanError(f"structured {identifier}: canonical scalar descriptor is missing")
                canonical_types[scalar_arm] = _base_type(descriptor, symbols)
                used_scalar_ids.add(descriptor.id)
            for arm_id in _sequence(_read(canonical, "arms", f"structured {identifier}"), "canonical arms"):
                arm_id = _string(arm_id, "canonical arm")
                try:
                    arm_types.append((f"{identifier}#{arm_id}", canonical_types[arm_id]))
                    selector = "Items" if arm_id == "array" else "Entries" if arm_id == "object" else "Value"
                    arm_shapes.append((f"{identifier}#{arm_id}", "canonical", selector))
                except KeyError as exc:
                    raise GoAPIPlanError(f"structured {identifier}: unknown canonical arm") from exc
        for source_id, _ in arm_types:
            _required_symbol(symbols, "structured_arm", source_id)
            planned.add(("structured_arm", source_id))
        dynamic_member = _optional(raw, "dynamic_members")
        if canonical is not None:
            dynamic_member = {
                "member_id": _read(canonical, "object_member_id", f"structured {identifier}"),
                "value": _read(canonical, "object_value", f"structured {identifier}"),
            }
        dynamic_keys: list[str] = []
        if dynamic_member is not None:
            member_id = _string(_read(dynamic_member, "member_id", f"structured {identifier}"), "member ID")
            source_id = f"{identifier}#{member_id}"
            input_symbol = _required_symbol(symbols, "structured_member_input", source_id)
            constructor_symbol = _required_symbol(symbols, "structured_member_constructor", source_id)
            value = _read(dynamic_member, "value", f"structured {identifier}")
            value_type = _structured_value_type(
                {"scalar": _optional(value, "scalar"), "reference": value},
                symbols,
                f"structured member {source_id}",
            )
            name_descriptor = scalar_by_member.get(f"dynamic_name:{member_id}")
            if name_descriptor is None:
                raise GoAPIPlanError(f"structured {identifier}: dynamic-name descriptor is missing")
            used_scalar_ids.add(name_descriptor.id)
            member_fields = (
                GoFieldPlanIR(
                    source_id,
                    "Name",
                    _base_type(name_descriptor, symbols),
                    0,
                    "required",
                    name_descriptor.semantic_source_id,
                    name_descriptor.id,
                    "input",
                    name_descriptor.target_slot,
                    None,
                    None,
                    "required_scalar",
                ),
                _common_field(source_id, "Value", value_type, 1),
            )
            _validate_owner_fields(member_fields)
            inputs.append(
                GoInputPlanIR(
                    "structured_member_input",
                    source_id,
                    input_symbol.symbol,
                    _DOMAIN_FILES["genai"],
                    member_fields,
                    "structured_member_input",
                    (),
                    (),
                    (),
                )
            )
            name_constraints = _typed_constraints(name_descriptor)
            callables.append(
                GoCallablePlanIR(
                    "structured_member_constructor",
                    source_id,
                    constructor_symbol.symbol,
                    _DOMAIN_FILES["genai"],
                    None,
                    None,
                    False,
                    (("name", _builtin("string")), ("value", value_type)),
                    (_named(input_symbol.symbol), _builtin("error")),
                    "family_build_error",
                    "validateFamilyString",
                    GoMemberCallableBodyPlanIR(
                        name_constraints,
                        _string_validation_helper(),
                    ),
                )
            )
            member_plans.append(
                GoStructuredMemberPlanIR(
                    source_id,
                    input_symbol.symbol,
                    constructor_symbol.symbol,
                    member_fields,
                    name_constraints,
                )
            )
            dynamic_keys.append(source_id)
            planned.update({("structured_member_input", source_id), ("structured_member_constructor", source_id)})
        selectors = {field.selector for field in value_fields}
        reserved_here = {"Entries"} if dynamic_member is not None else set()
        if shape == "array":
            reserved_here.add("Items")
        if selectors & reserved_here:
            raise GoAPIPlanError(f"structured {identifier}: reserved selector collision")
        _validate_owner_fields(value_fields)
        if shape in {"tagged_union", "canonical_json"} and not arm_types:
            raise GoAPIPlanError(f"structured {identifier}: union has no arms")
        discriminator = _optional(raw, "discriminator")
        if discriminator is not None:
            discriminator_name = _string(
                _read(discriminator, "name", f"structured {identifier}"), "structured discriminator"
            )
            discriminator_descriptor = scalar_by_member.get(f"discriminator:{discriminator_name}")
            if discriminator_descriptor is None:
                raise GoAPIPlanError(f"structured {identifier}: discriminator descriptor is missing")
            used_scalar_ids.add(discriminator_descriptor.id)
        else:
            discriminator_name = None
            discriminator_descriptor = None
        if used_scalar_ids != set(scalar_ids):
            raise GoAPIPlanError(f"structured {identifier}: scalar descriptor coverage is incomplete")
        child_container_ids = tuple(
            _string(item, f"structured {identifier}.child_containers")
            for item in _sequence(
                _read(container, "child_containers", f"structured {identifier}"),
                f"structured {identifier}.child_containers",
            )
        )
        if any(item not in containers for item in child_container_ids):
            raise GoAPIPlanError(f"structured {identifier}: child container link is unresolved")
        limit_values: dict[str, int] = {}
        raw_bounds = _read(container, "bounds", f"structured {identifier}")
        if not isinstance(raw_bounds, Mapping):
            raise GoAPIPlanError(f"structured {identifier}: bounds are invalid")
        for name, value in raw_bounds.items():
            if isinstance(value, int) and not isinstance(value, bool):
                limit_values[_string(name, f"structured {identifier}.bounds")] = value
        for name in ("min_items", "max_items"):
            value = _optional(raw, name)
            if isinstance(value, int) and not isinstance(value, bool):
                limit_values[name] = value
        if canonical is not None:
            canonical_limits = _read(canonical, "limits", f"structured {identifier}")
            if not isinstance(canonical_limits, Mapping):
                raise GoAPIPlanError(f"structured {identifier}: canonical limits are invalid")
            for name, value in canonical_limits.items():
                limit_values[_string(name, f"structured {identifier}.canonical_limits")] = _integer(
                    value, f"structured {identifier}.{name}", minimum=1
                )
        marker_method = "is" + symbol.symbol if arm_types else None
        declaration_fields = list(value_fields)
        if dynamic_keys:
            member_symbol = _required_symbol(symbols, "structured_member_input", dynamic_keys[0]).symbol
            declaration_fields.append(
                _common_field(
                    identifier,
                    "Entries",
                    _slice(_named(member_symbol)),
                    len(declaration_fields),
                    conversion="structured_encoder",
                )
            )
        if shape == "array":
            if item_type is None:
                raise GoAPIPlanError(f"structured {identifier}: array item type is missing")
            declaration_fields.append(
                _common_field(
                    identifier,
                    "Items",
                    _slice(item_type),
                    len(declaration_fields),
                    conversion="structured_encoder",
                )
            )
        _validate_owner_fields(declaration_fields)
        arm_plans: list[GoStructuredArmPlanIR] = []
        for (source_id, value_type), (_, arm_kind, selector) in zip(arm_types, arm_shapes, strict=True):
            arm_symbol = _required_symbol(symbols, "structured_arm", source_id).symbol
            arm_fields: list[GoFieldPlanIR] = []
            if selector == "Tag,Value":
                arm_fields.append(_common_field(source_id, "Tag", _builtin("string"), 0))
                arm_fields.append(_common_field(source_id, "Value", value_type, 1, conversion="structured_encoder"))
            else:
                arm_fields.append(
                    _common_field(
                        source_id,
                        selector,
                        value_type,
                        0,
                        conversion="structured_encoder" if value_type.arm in {"named", "slice"} else "required_scalar",
                    )
                )
            _validate_owner_fields(arm_fields)
            nested_arm_type = _contained_named_type(value_type)
            encoder_symbol = (
                None
                if arm_kind == "canonical" and selector == "Entries"
                else _private_encoder_symbol(nested_arm_type)
                if nested_arm_type is not None
                else None
            )
            arm_plans.append(
                GoStructuredArmPlanIR(
                    source_id,
                    arm_symbol,
                    arm_kind,
                    tuple(arm_fields),
                    marker_method or "",
                    encoder_symbol,
                    None if arm_kind == "dynamic" else source_id.split("#", 1)[1],
                    _typed_constraints(discriminator_descriptor)
                    if arm_kind == "dynamic" and discriminator_descriptor is not None
                    else None,
                    _typed_constraints(scalar_by_member[f"canonical_arm:{source_id.split('#', 1)[1]}"])
                    if arm_kind == "canonical"
                    and source_id.split("#", 1)[1] in {"boolean", "int64", "finite_double", "string"}
                    else None,
                )
            )
        encoder_bindings: list[GoFieldValueBindingPlanIR] = []
        for public in value_fields:
            field = fields.get(public.enriched_descriptor_id)
            if field is not None:
                encoder_symbol = None
                if field.structured_type is not None:
                    encoder_symbol = _private_encoder_symbol(
                        _required_symbol(symbols, "structured_type", field.structured_type).symbol
                    )
                key = field.semantic_source_id.removeprefix("field:")
            else:
                key = public.semantic_source_id
                nested_field_type = _contained_named_type(public.type_ref)
                encoder_symbol = _private_encoder_symbol(nested_field_type) if nested_field_type is not None else None
            encoder_bindings.append(
                GoFieldValueBindingPlanIR(
                    public.enriched_descriptor_id,
                    key,
                    public.selector,
                    public.presence,
                    public.conversion_op,
                    encoder_symbol,
                    _kernel_field(field).type_ref if field is not None else None,
                    _typed_constraints(field) if field is not None else None,
                )
            )
        structured_limits = GoKernelLimitsIR(
            limit_values.get("max_utf8_bytes", 0),
            limit_values.get("max_item_utf8_bytes", 0),
            limit_values.get("max_items", 0),
            limit_values.get("max_depth", 0),
            limit_values.get("max_properties", 0),
        )
        nested_item_type = _contained_named_type(item_type) if item_type is not None else None
        item_encoder = _private_encoder_symbol(nested_item_type) if nested_item_type is not None else None
        encoder = GoStructuredEncoderPlanIR(
            _private_encoder_symbol(symbol.symbol),
            _named(symbol.symbol),
            _named("familyFieldValue"),
            shape,
            tuple(encoder_bindings),
            item_type,
            item_encoder,
            tuple(source_id for source_id, _ in arm_types),
            tuple(dynamic_keys),
            discriminator_name,
            structured_limits,
            (_string_validation_helper(),),
        )
        plans.append(
            GoStructuredPlanIR(
                identifier,
                symbol.symbol,
                _DOMAIN_FILES["genai"],
                shape,
                scalar_ids,
                tuple(value_fields),
                item_type,
                tuple(source_id for source_id, _ in arm_types),
                tuple(arm_types),
                tuple(arm_shapes),
                tuple(dynamic_keys),
                discriminator_name,
                (f"structured:{identifier}",) + child_container_ids,
                tuple(sorted(limit_values.items())),
                {
                    "object": ("validate_fixed_fields", "validate_dynamic_members", "encode_object"),
                    "array": ("validate_items", "encode_array"),
                    "tagged_union": ("validate_registered_arm", "encode_tagged_union"),
                    "canonical_json": (
                        "validate_canonical_arm",
                        "enforce_recursive_limits",
                        "encode_canonical_json",
                    ),
                }[shape],
                tuple(declaration_fields),
                marker_method,
                tuple(arm_plans),
                tuple(member_plans),
                encoder,
            )
        )
        planned.add(("structured_type", identifier))
    return tuple(plans), tuple(inputs), tuple(callables), planned


def _compile_families(
    index: Any,
    *,
    policy: _Policy,
    symbols: Mapping[tuple[str, str], _Symbol],
    fields: Mapping[str, _Field],
) -> tuple[
    tuple[GoInputPlanIR, ...],
    tuple[GoCallablePlanIR, ...],
    tuple[GoDescriptorPlanIR, ...],
    set[DeclarationKeyIR],
    dict[str, str],
]:
    raw_families = _read(index, "enriched_families", "candidate")
    items = (
        tuple(raw_families.values())
        if isinstance(raw_families, Mapping)
        else _sequence(raw_families, "enriched_families")
    )
    by_id: dict[str, Any] = {}
    for position, raw in enumerate(items):
        identifier = _string(_read(raw, "id", f"enriched_families[{position}]"), "family descriptor ID")
        if identifier in by_id:
            raise GoAPIPlanError("enriched_families: duplicate family")
        by_id[identifier] = raw
    expected = {source_id for kind, source_id in symbols if kind == "family_input"}
    if set(by_id) != expected:
        raise GoAPIPlanError("enriched_families: complete family descriptor inventory is required")
    inputs: list[GoInputPlanIR] = []
    callables: list[GoCallablePlanIR] = []
    descriptors: list[GoDescriptorPlanIR] = []
    planned: set[DeclarationKeyIR] = set()
    family_domains: dict[str, str] = {}
    traces = _read(index, "enriched_traces", "candidate")
    metrics = _read(index, "enriched_metrics", "candidate")
    mandatory_programs = _read(index, "mandatory_programs", "candidate")
    if (
        not isinstance(traces, Mapping)
        or not isinstance(metrics, Mapping)
        or not isinstance(mandatory_programs, Mapping)
    ):
        raise GoAPIPlanError("candidate enriched family companions are incomplete")
    trace_defaults = _trace_contract_defaults(index)
    containers = _read(index, "enriched_containers", "candidate")
    if not isinstance(containers, Mapping):
        raise GoAPIPlanError("enriched_containers: expected mapping")
    metric_attribute_limits = _metric_limits_from_trace_contract(index)
    for identifier in sorted(by_id, key=str.encode):
        raw = by_id[identifier]
        path = f"family {identifier}"
        if _optional(raw, "removed_in") is not None:
            raise GoAPIPlanError(f"{path}: only active canonical families may own generated declarations")
        raw_signal = _string(_read(raw, "signal", path), f"{path}.signal")
        signal = {"logs": "log", "traces": "span", "metrics": "metric"}.get(raw_signal)
        if signal is None:
            raise GoAPIPlanError(f"{path}: unknown signal")
        domain = _string(_read(raw, "domain", path), f"{path}.domain")
        if domain not in _DOMAIN_FILES:
            raise GoAPIPlanError(f"{path}: unknown output domain")
        family_domains[identifier] = domain
        output_file = _DOMAIN_FILES[domain]
        input_symbol = _required_symbol(symbols, "family_input", identifier)
        builder_symbol = _required_symbol(symbols, "family_builder", identifier)
        descriptor_type_symbol = "generated" + input_symbol.symbol.removesuffix("Input") + "Descriptor"
        _validate_identifier(descriptor_type_symbol, f"{path}.private_descriptor_type")
        raw_outcome = _optional(raw, "outcome_requirement")
        outcome_requirement = (
            "forbidden" if raw_outcome is None else _string(raw_outcome, f"{path}.outcome_requirement")
        )
        family_ids = _field_ids(raw, "field_descriptor_ids", path, fields)
        trace = traces.get(identifier)
        metric = metrics.get(identifier)
        resource_ids = (
            _field_ids(trace, "resource_field_descriptor_ids", f"trace {identifier}", fields)
            if trace is not None
            else ()
        )
        scope_ids = (
            _field_ids(trace, "scope_field_descriptor_ids", f"trace {identifier}", fields) if trace is not None else ()
        )
        if signal == "log":
            common = _log_common(identifier, outcome_requirement)
        elif signal == "span":
            if outcome_requirement != "required":
                raise GoAPIPlanError(f"{path}: span outcome must be required")
            common = _span_common(identifier)
        else:
            if outcome_requirement != "forbidden":
                raise GoAPIPlanError(f"{path}: metric outcome must be forbidden")
            if metric is None:
                raise GoAPIPlanError(f"{path}: enriched metric descriptor is missing")
            value_type = _string(_read(metric, "value_type", f"metric {identifier}"), f"{path}.metric_value_type")
            if value_type not in {"int64", "double"}:
                raise GoAPIPlanError(f"{path}: metric value type is unsupported")
            common = (
                _common_field(identifier, "Envelope", _named("FamilyEnvelopeInput"), 0),
                _common_field(
                    identifier,
                    "Value",
                    _builtin("int64" if value_type == "int64" else "float64"),
                    1,
                    conversion="metric_number",
                ),
            )
        values: list[GoFieldPlanIR] = []
        if signal == "span":
            values.extend(
                _ordered_public_fields(
                    resource_ids,
                    owner=identifier,
                    component="resource",
                    input_owner_kind="family",
                    start=len(common),
                    policy=policy,
                    symbols=symbols,
                    fields=fields,
                    selector_prefix="Resource",
                    descriptor_owner_id="resource.core",
                )
            )
        values.extend(
            _ordered_public_fields(
                family_ids,
                owner=identifier,
                component="family",
                input_owner_kind="family",
                start=len(common) + len(values),
                policy=policy,
                symbols=symbols,
                fields=fields,
            )
        )
        condition_descriptor_ids = resource_ids + family_ids + scope_ids if signal == "span" else family_ids
        conditions = _condition_fields(
            identifier,
            condition_descriptor_ids,
            fields,
            len(common) + len(values),
            policy,
        )
        program_id = _optional(raw, "mandatory_program_id")
        raw_program = mandatory_programs.get(program_id) if program_id is not None else None
        mandatory_program = {
            "rule_ids": _read(raw_program, "rule_ids", f"mandatory {identifier}") if raw_program is not None else (),
            "constant_terms": tuple(
                True
                for _ in (
                    _read(raw_program, "constant_rule_ids", f"mandatory {identifier}")
                    if raw_program is not None
                    else ()
                )
            ),
            "fact_terms": tuple(
                fact
                for _, fact in (
                    _read(raw_program, "fact_terms", f"mandatory {identifier}") if raw_program is not None else ()
                )
            ),
        }
        mandatory = _mandatory_fields(
            identifier, mandatory_program, len(common) + len(values) + len(conditions), policy
        )
        if signal != "log" and mandatory:
            raise GoAPIPlanError(f"{path}: only logs may expose mandatory facts")
        input_fields = common + tuple(values) + conditions + mandatory
        _validate_owner_fields(input_fields)
        if signal == "span" and trace is None:
            raise GoAPIPlanError(f"{path}: enriched trace descriptor is missing")
        raw_events = tuple(
            {
                "source_id": f"{identifier}#{event_name}",
                "event_name": event_name,
                "field_ids": _read(trace, "event_field_descriptor_ids", f"trace {identifier}")[event_name],
            }
            for event_name in (_read(trace, "event_refs", f"trace {identifier}") if trace is not None else ())
        )
        event_keys: list[str] = []
        event_contracts: list[tuple[str, str, tuple[str, ...]]] = []
        for raw_event in raw_events:
            source_id = _string(_read(raw_event, "source_id", f"{path}.events"), "event source ID")
            event_name = _string(_read(raw_event, "event_name", f"{path}.events"), "event name")
            event_ids = _field_ids(raw_event, "field_ids", f"event {source_id}", fields)
            event_symbol = _required_symbol(symbols, "span_event_input", source_id)
            constructor = _required_symbol(symbols, "span_event_constructor", source_id)
            event_values = _ordered_public_fields(
                event_ids,
                owner=source_id,
                component="event",
                input_owner_kind="event",
                start=2,
                policy=policy,
                symbols=symbols,
                fields=fields,
                descriptor_owner_id=event_name,
            )
            event_fields = (
                _event_common(source_id)
                + event_values
                + _condition_fields(
                    source_id,
                    event_ids,
                    fields,
                    2 + len(event_values),
                    policy,
                )
            )
            _validate_owner_fields(event_fields)
            inputs.append(
                GoInputPlanIR(
                    "span_event_input",
                    source_id,
                    event_symbol.symbol,
                    output_file,
                    event_fields,
                    "trace_event_input",
                    (),
                    (),
                    (),
                )
            )
            callables.append(
                GoCallablePlanIR(
                    "span_event_constructor",
                    source_id,
                    constructor.symbol,
                    output_file,
                    None,
                    None,
                    False,
                    (("input", _named(event_symbol.symbol)),),
                    (_named("TraceEventInput"), _builtin("error")),
                    "family_build_error",
                    "generated_event_literal",
                    GoEventCallableBodyPlanIR(
                        "generated" + constructor.symbol.removeprefix("New") + "Contract",
                        _value_bindings(event_values, fields, symbols),
                        _condition_bindings(event_fields, event_ids, fields),
                    ),
                )
            )
            event_keys.append(source_id)
            event_contracts.append((source_id, event_name, event_ids))
            planned.update({("span_event_input", source_id), ("span_event_constructor", source_id)})
        raw_links = tuple(
            {
                "source_id": f"{identifier}#{relation}",
                "relation": relation,
                "field_ids": _read(trace, "link_field_descriptor_ids", f"trace {identifier}"),
            }
            for relation in (_read(trace, "link_relations", f"trace {identifier}") if trace is not None else ())
        )
        link_keys: list[str] = []
        link_contracts: list[tuple[str, tuple[str, ...]]] = []
        for raw_link in raw_links:
            source_id = _string(_read(raw_link, "source_id", f"{path}.links"), "link source ID")
            relation = _string(_read(raw_link, "relation", f"{path}.links"), "link relation")
            link_ids = _field_ids(raw_link, "field_ids", f"link {source_id}", fields)
            link_symbol = _required_symbol(symbols, "span_link_input", source_id)
            constructor = _required_symbol(symbols, "span_link_constructor", source_id)
            link_values = _ordered_public_fields(
                link_ids,
                owner=source_id,
                component="link",
                input_owner_kind="link",
                start=4,
                policy=policy,
                symbols=symbols,
                fields=fields,
                descriptor_owner_id="link.core",
            )
            link_fields = (
                _link_common(source_id)
                + link_values
                + _condition_fields(
                    source_id,
                    link_ids,
                    fields,
                    4 + len(link_values),
                    policy,
                )
            )
            _validate_owner_fields(link_fields)
            inputs.append(
                GoInputPlanIR(
                    "span_link_input",
                    source_id,
                    link_symbol.symbol,
                    output_file,
                    link_fields,
                    "trace_link_input",
                    (),
                    (),
                    (),
                )
            )
            callables.append(
                GoCallablePlanIR(
                    "span_link_constructor",
                    source_id,
                    constructor.symbol,
                    output_file,
                    None,
                    None,
                    False,
                    (("input", _named(link_symbol.symbol)),),
                    (_named("TraceLinkInput"), _builtin("error")),
                    "family_build_error",
                    "generated_link_literal",
                    GoLinkCallableBodyPlanIR(
                        GoTypedSymbolRefIR(
                            _builtin("string"),
                            _required_symbol(symbols, "link_relation", relation).symbol,
                            _builtin("string"),
                        ),
                        _value_bindings(link_values, fields, symbols),
                        _condition_bindings(link_fields, link_ids, fields),
                    ),
                )
            )
            link_keys.append(source_id)
            link_contracts.append((relation, link_ids))
            planned.update({("span_link_input", source_id), ("span_link_constructor", source_id)})
        inputs.append(
            GoInputPlanIR(
                "family_input",
                identifier,
                input_symbol.symbol,
                output_file,
                input_fields,
                {
                    "log": "family_log_input",
                    "span": "family_span_input",
                    "metric": "family_metric_input",
                }[signal],
                tuple(event_keys),
                tuple(link_keys),
                resource_ids,
            )
        )
        callables.append(
            GoCallablePlanIR(
                "family_builder",
                identifier,
                builder_symbol.symbol,
                output_file,
                "builder",
                _named("FamilyBuilder"),
                True,
                (("input", _named(input_symbol.symbol)),),
                (_named("Record"), _builtin("error")),
                "family_build_error",
                {
                    "log": "buildGeneratedResolvedLog",
                    "span": "buildGeneratedTrace",
                    "metric": "buildGeneratedMetric",
                }[signal],
                GoFamilyCallableBodyPlanIR(
                    "family_" + signal,
                    descriptor_type_symbol,
                    _family_kernel_helper(signal),
                    _named(
                        {
                            "log": "familyLogBuildInput",
                            "span": "familyTraceBuildInput",
                            "metric": "familyMetricBuildInput",
                        }[signal]
                    ),
                    "labels" if signal == "metric" else "values",
                    _value_bindings(
                        tuple(
                            field
                            for field in values
                            if not (signal == "span" and field.selector.startswith("Resource"))
                        ),
                        fields,
                        symbols,
                    ),
                    _value_bindings(
                        tuple(field for field in values if signal == "span" and field.selector.startswith("Resource")),
                        fields,
                        symbols,
                    ),
                    _condition_bindings(input_fields, condition_descriptor_ids, fields),
                    tuple(
                        GoMandatoryBindingPlanIR(field.mandatory_binding or "", field.selector) for field in mandatory
                    ),
                    _mandatory_resolver_helper() if signal == "log" else None,
                    _metric_number_helper(value_type) if signal == "metric" else None,
                ),
            )
        )
        allowed_outcomes = tuple(
            _string(item, f"{path}.allowed_outcomes")
            for item in _sequence(_read(raw, "allowed_outcomes", path), f"{path}.allowed_outcomes")
        )
        raw_span_parts = (
            _sequence(_read(trace, "span_name_parts", f"trace {identifier}"), f"{path}.span_name_parts")
            if trace is not None
            else ()
        )
        span_parts_list: list[GoSpanNamePartPlanIR] = []
        for part in raw_span_parts:
            kind = _string(_read(part, "kind", f"{path}.span_name_parts"), "span-name part kind")
            if kind == "literal":
                literal = _string(_read(part, "literal", f"{path}.span_name_parts"), "span-name literal")
                if _optional(part, "field") is not None:
                    raise GoAPIPlanError(f"{path}.span_name_parts: literal arm carries field")
                span_parts_list.append(GoSpanNamePartPlanIR("literal", literal, None))
            elif kind == "field":
                field_key = _string(_read(part, "field", f"{path}.span_name_parts"), "span-name field")
                if _optional(part, "literal") is not None:
                    raise GoAPIPlanError(f"{path}.span_name_parts: field arm carries literal")
                candidates = [
                    fields[field_id] for field_id in family_ids if fields[field_id].semantic_source_id == field_key
                ]
                if (
                    len(candidates) != 1
                    or candidates[0].primitive_type != "string"
                    or candidates[0].structured_type is not None
                    or candidates[0].requirement != "required"
                    or candidates[0].condition_id is not None
                    or candidates[0].condition_fact is not None
                    or candidates[0].false_requirement is not None
                ):
                    raise GoAPIPlanError(
                        f"{path}.span_name_parts: field arm {field_key!r} is not one unconditional required "
                        "family string"
                    )
                span_parts_list.append(GoSpanNamePartPlanIR("field", None, field_key))
            else:
                raise GoAPIPlanError(f"{path}.span_name_parts: unknown arm")
        span_parts = tuple(span_parts_list)
        metric_contract = (
            (
                ("instrument_name", _string(_read(metric, "instrument_name", f"metric {identifier}"), "instrument")),
                (
                    "instrument_type",
                    _string(_read(metric, "instrument_type", f"metric {identifier}"), "instrument type"),
                ),
                ("unit", _string(_read(metric, "unit", f"metric {identifier}"), "metric unit")),
                ("temporality", _string(_read(metric, "temporality", f"metric {identifier}"), "temporality")),
            )
            if metric is not None
            else ()
        )
        rule_ids = tuple(
            _string(item, f"{path}.mandatory_program.rule_ids")
            for item in _sequence(
                _read(mandatory_program, "rule_ids", f"{path}.mandatory_program"), "mandatory rule IDs"
            )
        )
        constant_terms = tuple(
            item
            for item in _sequence(
                _read(mandatory_program, "constant_terms", f"{path}.mandatory_program"), "mandatory constant terms"
            )
        )
        if any(not isinstance(item, bool) for item in constant_terms):
            raise GoAPIPlanError(f"{path}: mandatory constant term is not Boolean")
        mandatory_terms = tuple((field.mandatory_binding or "", field.selector) for field in mandatory)
        kernel_field_ids = tuple(
            dict.fromkeys(
                family_ids
                + resource_ids
                + scope_ids
                + tuple(field_id for _, _, event_ids in event_contracts for field_id in event_ids)
                + tuple(field_id for _, link_ids in link_contracts for field_id in link_ids)
            )
        )
        kernel_fields = tuple(_kernel_field(fields[field_id]) for field_id in kernel_field_ids)
        kernel_by_id = {field.descriptor_id: field for field in kernel_fields}
        identity_bucket = _string(_read(raw, "bucket", path), f"{path}.bucket")
        identity_name = _string(_read(raw, "event_name", path), f"{path}.event_name")
        identity_kind = {"log": "log_event", "span": "family", "metric": "metric_instrument"}[signal]
        identity_source = identifier if signal == "span" else identity_name
        identity_symbol = _required_symbol(symbols, identity_kind, identity_source).symbol
        try:
            requirement_ref = _typed_symbol(
                "familyRequirement",
                "familyRequirementInvalid" if signal == "metric" else _REQUIREMENT_SYMBOLS[outcome_requirement],
            )
            outcome_refs = tuple(_typed_symbol("Outcome", _OUTCOME_SYMBOLS[outcome]) for outcome in allowed_outcomes)
        except KeyError as exc:
            raise GoAPIPlanError(f"{path}: outcome contract has no reviewed kernel symbol") from exc
        base_contract = GoBaseFamilyContractPlanIR(
            identifier,
            GoIdentityContractPlanIR(
                _closed_symbol(_BUCKET_SYMBOLS, identity_bucket, "Bucket", f"{path}.bucket"),
                _closed_symbol(_SIGNAL_SYMBOLS, signal, "Signal", f"{path}.signal"),
                GoTypedSymbolRefIR(_named("EventName"), identity_symbol, _named("EventName")),
            ),
            _integer(_read(raw, "family_schema_version", path), f"{path}.family_schema_version", minimum=1),
            GoOutcomePolicyPlanIR(requirement_ref, outcome_refs),
            tuple(kernel_by_id[field_id] for field_id in family_ids),
            _cross_field_relations(index, family_ids, fields),
        )
        trace_catalog: GoTraceFamilyContractPlanIR | None = None
        if signal == "span":
            event_catalog = tuple(
                GoEventContractPlanIR(
                    source_id,
                    "generated"
                    + _required_symbol(symbols, "span_event_constructor", source_id).symbol.removeprefix("New")
                    + "Contract",
                    event_name,
                    GoTypedSymbolRefIR(
                        _builtin("string"),
                        _required_symbol(symbols, "span_event", event_name).symbol,
                        _builtin("string"),
                    ),
                    tuple(kernel_by_id[field_id] for field_id in event_ids),
                )
                for source_id, event_name, event_ids in event_contracts
            )
            trace_catalog = GoTraceFamilyContractPlanIR(
                base_contract,
                tuple(
                    _string(item, f"{path}.allowed_kinds")
                    for item in _sequence(_read(trace, "span_kinds", f"trace {identifier}"), f"{path}.allowed_kinds")
                ),
                span_parts,
                trace_defaults.attribute_limits,
                tuple(kernel_by_id[field_id] for field_id in resource_ids),
                trace_defaults.resource_limits,
                tuple(kernel_by_id[field_id] for field_id in scope_ids),
                trace_defaults.scope_limits,
                event_catalog,
                trace_defaults.event_limits,
                trace_defaults.max_events,
                tuple(
                    GoTypedSymbolRefIR(
                        _builtin("string"),
                        _required_symbol(symbols, "link_relation", relation).symbol,
                        _builtin("string"),
                    )
                    for relation, _ in link_contracts
                ),
                tuple(
                    kernel_by_id[field_id]
                    for field_id in dict.fromkeys(field_id for _, link_ids in link_contracts for field_id in link_ids)
                ),
                trace_defaults.link_limits,
                trace_defaults.max_links,
                trace_defaults.scope_name,
                trace_defaults.scope_schema_url,
                trace_defaults.trace_schema_version,
                trace_defaults.semantic_profile,
            )
        metric_description = (
            _string(_read(metric, "description", f"metric {identifier}"), "metric description")
            if metric is not None
            else None
        )
        metric_boundaries = tuple(_read(metric, "boundaries", f"metric {identifier}")) if metric is not None else ()
        if any(
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or isinstance(value, float)
            and not math.isfinite(value)
            for value in metric_boundaries
        ):
            raise GoAPIPlanError(f"{path}: metric boundaries are invalid")
        metric_catalog: GoMetricFamilyContractPlanIR | None = None
        if signal == "metric":
            instrument_name = _string(_read(metric, "instrument_name", f"metric {identifier}"), "instrument")
            metric_value_type = _string(_read(metric, "value_type", f"metric {identifier}"), "metric value type")
            metric_catalog = GoMetricFamilyContractPlanIR(
                base_contract,
                _typed_symbol(
                    "familyMetricNumberType",
                    "familyMetricNumberInt64" if metric_value_type == "int64" else "familyMetricNumberDouble",
                ),
                metric_attribute_limits,
                GoTypedSymbolRefIR(
                    _builtin("string"),
                    _required_symbol(symbols, "metric_instrument", instrument_name).symbol,
                    _builtin("string"),
                ),
                _string(_read(metric, "instrument_type", f"metric {identifier}"), "instrument type"),
                _string(_read(metric, "unit", f"metric {identifier}"), "metric unit"),
                _string(_read(metric, "temporality", f"metric {identifier}"), "temporality"),
            )
        catalog_contract = GoCatalogContractPlanIR(
            descriptor_type_symbol,
            base_contract,
            trace_catalog,
            metric_catalog,
        )
        descriptors.append(
            GoDescriptorPlanIR(
                identifier,
                signal,
                domain,
                _string(_read(raw, "bucket", path), f"{path}.bucket"),
                _string(_read(raw, "event_name", path), f"{path}.event_name"),
                _integer(_read(raw, "family_schema_version", path), f"{path}.family_schema_version", minimum=1),
                outcome_requirement,
                allowed_outcomes,
                kernel_fields,
                family_ids,
                resource_ids,
                scope_ids,
                span_parts,
                tuple(
                    _string(item, f"{path}.allowed_kinds")
                    for item in (
                        _sequence(_read(trace, "span_kinds", f"trace {identifier}"), f"{path}.allowed_kinds")
                        if trace is not None
                        else ()
                    )
                ),
                tuple(event_contracts),
                tuple(link_contracts),
                metric_contract,
                metric_description,
                metric_boundaries,
                metric_attribute_limits if signal == "metric" else None,
                trace_defaults if signal == "span" else None,
                rule_ids,
                constant_terms,
                mandatory_terms,
                callables[-1].private_target,
                catalog_contract,
            )
        )
        planned.update({("family_input", identifier), ("family_builder", identifier)})
    return tuple(inputs), tuple(callables), tuple(descriptors), planned, family_domains


def _family_source_for_row(row: _Symbol) -> str:
    return row.source_id.split("#", 1)[0]


def _file_assignments(
    rows: tuple[_Symbol, ...],
    family_domains: Mapping[str, str],
) -> dict[str, tuple[DeclarationKeyIR, ...]]:
    assigned: dict[str, list[DeclarationKeyIR]] = {path: [] for path in GO_OUTPUT_FILES}
    structured_kinds = {
        "structured_type",
        "structured_arm",
        "structured_member_input",
        "structured_member_constructor",
    }
    resource_kinds = {
        "resource_attributes_type",
        "resource_attributes_constructor",
        "resource_attributes_attach",
        "resource_attributes_validator",
    }
    family_kinds = {
        "family_input",
        "family_builder",
        "span_event_input",
        "span_event_constructor",
        "span_link_input",
        "span_link_constructor",
    }
    for row in rows:
        if row.declaration_form == "exported_const":
            path = _IDS_FILE
        elif row.kind in structured_kinds:
            path = _DOMAIN_FILES["genai"]
        elif row.kind in resource_kinds:
            path = _DOMAIN_FILES["operations"]
        elif row.kind in family_kinds:
            family_id = _family_source_for_row(row)
            try:
                path = _DOMAIN_FILES[family_domains[family_id]]
            except KeyError as exc:
                raise GoAPIPlanError(f"Go declaration {row.kind}/{row.source_id}: family domain is missing") from exc
        else:
            raise GoAPIPlanError(f"Go declaration {row.kind}/{row.source_id}: no output-file assignment")
        assigned[path].append((row.kind, row.source_id))
    flattened = [key for path in GO_OUTPUT_FILES for key in assigned[path]]
    expected = [(row.kind, row.source_id) for row in rows]
    if len(flattened) != len(set(flattened)) or set(flattened) != set(expected):
        raise GoAPIPlanError("Go declaration file assignment is incomplete or duplicated")
    return {path: tuple(assigned[path]) for path in GO_OUTPUT_FILES}


def _declaration_owner(row: _Symbol) -> str:
    structured_kinds = {
        "structured_type",
        "structured_member",
        "structured_arm",
        "structured_member_input",
        "structured_member_constructor",
    }
    family_kinds = {
        "family_input",
        "family_builder",
        "span_event_input",
        "span_event_constructor",
        "span_link_input",
        "span_link_constructor",
    }
    resource_kinds = {
        "resource_attributes_type",
        "resource_attributes_constructor",
        "resource_attributes_attach",
        "resource_attributes_validator",
    }
    if row.kind in structured_kinds or row.kind in family_kinds or row.kind in resource_kinds:
        return row.source_id.split("#", 1)[0]
    return "package"


def _constant_value_facts(
    index: Any, rows: tuple[_Symbol, ...]
) -> dict[DeclarationKeyIR, tuple[GoTypeRefIR, str, LiteralValueIR]]:
    raw_facts = _read(index, "go_declaration_values", "candidate")
    items = (
        tuple(raw_facts.values()) if isinstance(raw_facts, Mapping) else _sequence(raw_facts, "go_declaration_values")
    )
    result: dict[DeclarationKeyIR, tuple[GoTypeRefIR, str, LiteralValueIR]] = {}
    rows_by_key = {(row.kind, row.source_id): row for row in rows}
    for position, raw in enumerate(items):
        path = f"go_declaration_values[{position}]"
        key = (
            _string(_read(raw, "kind", path), f"{path}.kind"),
            _string(_read(raw, "source_id", path), f"{path}.source_id"),
        )
        if key in result:
            raise GoAPIPlanError("go_declaration_values: duplicate declaration key")
        row = rows_by_key.get(key)
        if row is None or _read(raw, "symbol", path) != row.symbol:
            raise GoAPIPlanError(f"{path}.symbol: declaration identity disagrees with symbol table")
        go_type = _string(_read(raw, "go_type", path), f"{path}.go_type")
        type_ref = {"string": _builtin("string"), "int": _builtin("int")}.get(go_type)
        if type_ref is None:
            raise GoAPIPlanError(f"{path}.go_type: expected string or int")
        literal_kind = _string(_read(raw, "literal_kind", path), f"{path}.literal_kind")
        value = _read(raw, "value", path)
        if literal_kind == "string":
            if not isinstance(value, str):
                raise GoAPIPlanError(f"{path}.value: expected string literal value")
        elif literal_kind == "integer":
            if isinstance(value, bool) or not isinstance(value, int) or value < -(2**31) or value >= 2**31:
                raise GoAPIPlanError(f"{path}.value: expected integer literal value")
        else:
            raise GoAPIPlanError(f"{path}.literal_kind: unsupported constant literal")
        result[key] = (type_ref, literal_kind, value)
    expected = {(row.kind, row.source_id) for row in rows if row.declaration_form == "exported_const"}
    if set(result) != expected:
        raise GoAPIPlanError("go_declaration_values: exact exported-constant coverage is required")
    return result


def _declaration_plans(
    index: Any,
    rows: tuple[_Symbol, ...],
    assignments: Mapping[str, tuple[DeclarationKeyIR, ...]],
) -> tuple[GoDeclarationPlanIR, ...]:
    constants = _constant_value_facts(index, rows)
    file_by_key = {key: path for path, keys in assignments.items() for key in keys}
    plans: list[GoDeclarationPlanIR] = []
    for row in rows:
        key = (row.kind, row.source_id)
        constant = constants.get(key)
        plans.append(
            GoDeclarationPlanIR(
                row.kind,
                row.source_id,
                row.symbol,
                row.declaration_form,
                _declaration_owner(row),
                file_by_key[key],
                constant[0] if constant is not None else None,
                constant[1] if constant is not None else None,
                constant[2] if constant is not None else None,
            )
        )
    return tuple(plans)


def _private_declaration_plans(
    structured: Sequence[GoStructuredPlanIR],
    descriptors: Sequence[GoDescriptorPlanIR],
) -> tuple[GoPrivateDeclarationPlanIR, ...]:
    by_file: dict[str, list[GoPrivateDeclarationPlanIR]] = {path: [] for path in GO_OUTPUT_FILES}

    def add(
        *,
        declaration_id: str,
        symbol: str,
        owner: str,
        output_file: str,
        arm: str,
        receiver_type: GoTypeRefIR | None = None,
        parameters: tuple[ParameterIR, ...] = (),
        results: tuple[GoTypeRefIR, ...] = (),
        body_owner_id: str,
    ) -> None:
        if arm not in _PRIVATE_DECLARATION_ARMS:
            raise GoAPIPlanError("private declaration has an unknown arm")
        _validate_identifier(symbol, f"private declaration {declaration_id}")
        target = by_file[output_file]
        target.append(
            GoPrivateDeclarationPlanIR(
                declaration_id,
                symbol,
                owner,
                output_file,
                len(target),
                arm,
                receiver_type,
                parameters,
                results,
                body_owner_id,
            )
        )

    for descriptor in descriptors:
        contract = descriptor.catalog_contract
        type_ref = _named(contract.descriptor_type_symbol)
        add(
            declaration_id=f"catalog:{descriptor.family_id}:type",
            symbol=contract.descriptor_type_symbol,
            owner=descriptor.family_id,
            output_file=_CATALOG_FILE,
            arm="family_descriptor_type",
            body_owner_id=descriptor.family_id,
        )
        add(
            declaration_id=f"catalog:{descriptor.family_id}:base",
            symbol="familyDescriptorContract",
            owner=descriptor.family_id,
            output_file=_CATALOG_FILE,
            arm="family_descriptor_method",
            receiver_type=type_ref,
            results=(_named("familyDescriptorContract"),),
            body_owner_id=descriptor.family_id,
        )
        if contract.trace is not None:
            add(
                declaration_id=f"catalog:{descriptor.family_id}:trace",
                symbol="familyTraceContract",
                owner=descriptor.family_id,
                output_file=_CATALOG_FILE,
                arm="family_trace_method",
                receiver_type=type_ref,
                results=(_named("familyTraceContract"),),
                body_owner_id=descriptor.family_id,
            )
            for event in contract.trace.allowed_events:
                add(
                    declaration_id=f"catalog:{event.source_id}:event",
                    symbol=event.private_helper_symbol,
                    owner=descriptor.family_id,
                    output_file=_CATALOG_FILE,
                    arm="event_contract_helper",
                    results=(_named("familyEventContract"),),
                    body_owner_id=event.source_id,
                )
        if contract.metric is not None:
            add(
                declaration_id=f"catalog:{descriptor.family_id}:metric",
                symbol="familyMetricContract",
                owner=descriptor.family_id,
                output_file=_CATALOG_FILE,
                arm="family_metric_method",
                receiver_type=type_ref,
                results=(_named("familyMetricContract"),),
                body_owner_id=descriptor.family_id,
            )
    for structured_plan in structured:
        for arm_plan in structured_plan.arms:
            add(
                declaration_id=f"structured:{arm_plan.source_id}:marker",
                symbol=arm_plan.marker_method,
                owner=structured_plan.declaration_source_id,
                output_file=structured_plan.output_file,
                arm="structured_marker_method",
                receiver_type=_named(arm_plan.symbol),
                body_owner_id=arm_plan.source_id,
            )
        encoder = structured_plan.encoder
        add(
            declaration_id=f"structured:{structured_plan.declaration_source_id}:encoder",
            symbol=encoder.symbol,
            owner=structured_plan.declaration_source_id,
            output_file=structured_plan.output_file,
            arm="structured_encoder",
            parameters=(
                ("key", _builtin("string")),
                ("input", encoder.input_type),
                ("present", _builtin("bool")),
            ),
            results=(encoder.result_type, _builtin("error")),
            body_owner_id=structured_plan.declaration_source_id,
        )
    result = tuple(item for path in GO_OUTPUT_FILES for item in by_file[path])
    ids = [item.declaration_id for item in result]
    if len(ids) != len(set(ids)):
        raise GoAPIPlanError("private declaration ownership is duplicated")
    package_symbols = [
        item.symbol
        for item in result
        if item.arm in {"family_descriptor_type", "event_contract_helper", "structured_encoder"}
    ]
    if len(package_symbols) != len(set(package_symbols)):
        raise GoAPIPlanError("package-scope private declaration symbol is duplicated")
    for path, items in by_file.items():
        if tuple(item.order for item in items) != tuple(range(len(items))):
            raise GoAPIPlanError(f"{path}: private declaration order is not contiguous")
    return result


def _kernel_helper_inventory(
    callables: Sequence[GoCallablePlanIR], structured: Sequence[GoStructuredPlanIR]
) -> tuple[GoKernelHelperRefIR, ...]:
    helpers: list[GoKernelHelperRefIR] = []
    for callable_plan in callables:
        body = callable_plan.body
        if isinstance(body, GoFamilyCallableBodyPlanIR):
            helpers.append(body.kernel_helper)
            if body.mandatory_resolver is not None:
                helpers.append(body.mandatory_resolver)
            if body.metric_number_helper is not None:
                helpers.append(body.metric_number_helper)
        elif isinstance(body, GoMemberCallableBodyPlanIR):
            helpers.append(body.validation_helper)
    for structured_plan in structured:
        helpers.extend(structured_plan.encoder.validation_helpers)
    by_symbol: dict[str, GoKernelHelperRefIR] = {}
    for helper in helpers:
        prior = by_symbol.setdefault(helper.symbol, helper)
        if prior != helper:
            raise GoAPIPlanError(f"private kernel helper {helper.symbol}: signature disagreement")
    return tuple(by_symbol[symbol] for symbol in sorted(by_symbol, key=str.encode))


def _validate_render_targets(inputs: Sequence[GoInputPlanIR], callables: Sequence[GoCallablePlanIR]) -> None:
    if any(item.private_kernel_target not in _INPUT_KERNEL_TARGETS for item in inputs):
        raise GoAPIPlanError("input plan has an unreviewed private-kernel target")
    for callable_plan in callables:
        body = callable_plan.body
        if isinstance(body, GoFamilyCallableBodyPlanIR):
            expected = body.kernel_helper.symbol
            if body.arm not in {"family_log", "family_span", "family_metric"}:
                raise GoAPIPlanError("family callable body has an unknown arm")
        elif isinstance(body, GoEventCallableBodyPlanIR):
            expected = "generated_event_literal"
        elif isinstance(body, GoLinkCallableBodyPlanIR):
            expected = "generated_link_literal"
        elif isinstance(body, GoMemberCallableBodyPlanIR):
            expected = body.validation_helper.symbol
        else:  # pragma: no cover - closed union guard
            raise GoAPIPlanError("callable plan has an unknown body")
        if callable_plan.private_target != expected:
            raise GoAPIPlanError("callable plan has an unreviewed private target")


def _validate_condition_closure(
    inputs: Sequence[GoInputPlanIR],
    callables: Sequence[GoCallablePlanIR],
    descriptors: Sequence[GoDescriptorPlanIR],
) -> None:
    input_by_key = {(item.declaration_kind, item.declaration_source_id): item for item in inputs}
    callable_by_key = {(item.declaration_kind, item.declaration_source_id): item for item in callables}

    def expected_facts(descriptor: GoDescriptorPlanIR, descriptor_ids: Sequence[str]) -> tuple[tuple[str, str], ...]:
        by_id = {field.descriptor_id: field for field in descriptor.field_contracts}
        result: list[tuple[str, str]] = []
        seen: dict[str, str] = {}
        for descriptor_id in descriptor_ids:
            field = by_id[descriptor_id]
            if field.condition_fact is None:
                continue
            if field.condition_id is None:
                raise GoAPIPlanError("conditional private descriptor has no condition ID")
            prior = seen.get(field.condition_fact)
            if prior is not None:
                if prior != field.condition_id:
                    raise GoAPIPlanError("condition fact maps to multiple condition IDs")
                continue
            seen[field.condition_fact] = field.condition_id
            result.append((field.condition_id, field.condition_fact))
        return tuple(result)

    def verify(
        input_key: DeclarationKeyIR,
        callable_key: DeclarationKeyIR,
        expected: tuple[tuple[str, str], ...],
    ) -> None:
        input_plan = input_by_key[input_key]
        actual_input = tuple(
            (field.semantic_source_id, field.condition_binding or "", field.enriched_descriptor_id)
            for field in input_plan.fields
            if field.conversion_op == "condition_fact"
        )
        expected_input = tuple(
            (fact_id, fact_id, f"condition:{input_plan.declaration_source_id}:{fact_id}")
            for _, fact_id in expected
            if not fact_id.startswith("attribute:")
        )
        body = callable_by_key[callable_key].body
        if isinstance(body, (GoFamilyCallableBodyPlanIR, GoEventCallableBodyPlanIR, GoLinkCallableBodyPlanIR)):
            actual_body = tuple((condition.condition_id, condition.fact_id) for condition in body.conditions)
        else:
            raise GoAPIPlanError("condition-bearing input has incompatible callable body")
        if actual_input != expected_input or actual_body != expected:
            raise GoAPIPlanError("generated condition fact closure is incomplete or reordered")

    for descriptor in descriptors:
        family_ids = (
            descriptor.resource_field_descriptor_ids
            + descriptor.enriched_field_descriptor_ids
            + descriptor.scope_field_descriptor_ids
            if descriptor.signal == "span"
            else descriptor.enriched_field_descriptor_ids
        )
        verify(
            ("family_input", descriptor.family_id),
            ("family_builder", descriptor.family_id),
            expected_facts(descriptor, family_ids),
        )
        for source_id, _, field_ids in descriptor.event_contracts:
            verify(
                ("span_event_input", source_id),
                ("span_event_constructor", source_id),
                expected_facts(descriptor, field_ids),
            )
        for relation, field_ids in descriptor.link_contracts:
            source_id = f"{descriptor.family_id}#{relation}"
            verify(
                ("span_link_input", source_id),
                ("span_link_constructor", source_id),
                expected_facts(descriptor, field_ids),
            )


def _canonical_node(value: Any) -> Any:
    if dataclasses.is_dataclass(value):
        return {
            "$type": type(value).__name__,
            "fields": {field.name: _canonical_node(getattr(value, field.name)) for field in dataclasses.fields(value)},
        }
    if isinstance(value, tuple):
        return [_canonical_node(item) for item in value]
    if value is None or isinstance(value, (str, int, bool)):
        return value
    if isinstance(value, float) and math.isfinite(value):
        return value
    raise GoAPIPlanError("Go API plan contains a non-canonical value")


def _plan_digest(plan: GoAPIPlanIR) -> str:
    without_digest = dataclasses.replace(plan, api_plan_sha256="")
    payload = json.dumps(
        _canonical_node(without_digest), ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(_GO_API_PLAN_DIGEST_DOMAIN + payload).hexdigest()


def _plain_json(value: Any, path: str) -> Any:
    if isinstance(value, Mapping):
        return {_string(key, f"{path}.key"): _plain_json(value[key], f"{path}.{key}") for key in sorted(value)}
    if isinstance(value, tuple):
        return [_plain_json(item, path) for item in value]
    if value is None or type(value) in {str, int, bool}:
        return value
    if isinstance(value, float) and math.isfinite(value):
        return value
    raise GoAPIPlanError(f"{path}: non-JSON or non-finite fixture value")


def _fixture_plans(index: Any, inputs: Sequence[GoInputPlanIR]) -> tuple[GoFixturePlanIR, ...]:
    family_inputs = {item.declaration_source_id: item for item in inputs if item.declaration_kind == "family_input"}
    fixtures: list[GoFixturePlanIR] = []
    seen: set[str] = set()
    for position, raw in enumerate(_sequence(_read(index, "examples", "candidate"), "candidate.examples")):
        path = f"examples[{position}]"
        example_id = _string(_read(raw, "id", path), f"{path}.id")
        if example_id in seen:
            raise GoAPIPlanError("candidate examples contain a duplicate ID")
        seen.add(example_id)
        signal = _string(_read(raw, "signal", path), f"{path}.signal")
        family_id = _optional(raw, "family")
        if family_id is not None and not isinstance(family_id, str):
            raise GoAPIPlanError(f"{path}.family: invalid family ID")
        input_plan = family_inputs.get(family_id or "")
        if family_id is not None and input_plan is None:
            raise GoAPIPlanError(f"{path}: typed family input is missing")
        valid = _read(raw, "valid", path)
        if not isinstance(valid, bool):
            raise GoAPIPlanError(f"{path}.valid: expected Boolean")
        record = _read(raw, "record", path)
        record_plain = _plain_json(record, f"{path}.record")
        expected_error = _optional(raw, "expected_error")
        if expected_error is not None and not isinstance(expected_error, str):
            raise GoAPIPlanError(f"{path}.expected_error: invalid stable error")
        base_example = _optional(raw, "base_example")
        if base_example is not None and not isinstance(base_example, str):
            raise GoAPIPlanError(f"{path}.base_example: invalid fixture base")
        try:
            expected_record_json = canonical_record_json(record_plain)
        except CanonicalRecordError as exc:
            raise GoAPIPlanError(f"{path}.record: canonical record encoding failed") from exc
        fixtures.append(
            GoFixturePlanIR(
                example_id,
                signal,
                family_id,
                valid,
                ("family_input", family_id) if input_plan is not None else None,
                ("family_builder", family_id) if input_plan is not None else None,
                tuple(
                    (field.selector, field.target_slot, field.semantic_source_id)
                    for field in (input_plan.fields if input_plan is not None else ())
                ),
                _fact_value(_read(raw, "builder_context", path), f"{path}.builder_context"),
                _fact_value(record, f"{path}.record"),
                expected_record_json,
                expected_error,
                base_example,
            )
        )
    return tuple(fixtures)


def _compile_resource_attributes(
    index: Any,
    *,
    symbols: Mapping[tuple[str, str], _Symbol],
    fields: Mapping[str, _Field],
) -> tuple[GoResourceAttributesPlanIR, set[DeclarationKeyIR]]:
    groups = _optional(index, "groups")
    if groups is None:
        # Older compiler unit fixtures predate group ownership facts. Keep those
        # fixtures useful by deriving the minimal resource inventory from their
        # enriched field table; production candidates always carry groups.
        groups = {
            "resource.core": {
                "attribute_refs": tuple(
                    sorted(field.semantic_source_id for field in fields.values() if field.component == "resource")
                ),
                "resource_dynamic_members": None,
                "resource_compatibility_aliases": None,
            }
        }
    elif not isinstance(groups, Mapping):
        raise GoAPIPlanError("candidate.groups: expected mapping")
    owner_id = "resource.core"
    group = groups.get(owner_id)
    if group is None:
        raise GoAPIPlanError("candidate.groups: resource.core is missing")
    dynamic = _read(group, "resource_dynamic_members", owner_id)
    raw_aliases = _read(group, "resource_compatibility_aliases", owner_id)
    if dynamic is None and raw_aliases is None:
        dynamic = {
            "ordering": "bytewise_key_ascending",
            "field_class": "metadata",
            "sensitivity": "internal",
            "cardinality": "bounded",
            "stability_scope": "process",
            "value_utf8_policy": "require_valid",
            "value_blank_policy": "reject_trimmed_empty",
            "value_control_character_policy": "reject",
            "prometheus_key_normalization": "dot_dash_to_underscore",
            "prometheus_normalized_collision_policy": "reject",
            "key_pattern": r"^[A-Za-z][A-Za-z0-9_.-]{0,127}$",
            "max_items": 64,
            "max_key_ascii_bytes": 128,
            "min_value_utf8_bytes": 1,
            "max_value_utf8_bytes": 1024,
            "max_aggregate_utf8_bytes": 16384,
            "duplicate_key_policy": "reject",
            "fixed_key_collision_policy": "reject",
            "forbidden_key_segments": (
                "authorization",
                "credential",
                "credentials",
                "password",
                "passwd",
                "secret",
                "token",
                "apikey",
                "cookie",
                "cwd",
                "dir",
                "directory",
                "file",
                "filepath",
                "home",
                "path",
                "workdir",
            ),
            "reserved_keys": (
                "defenseclaw.claw.home_dir",
                "defenseclaw.gateway.host",
                "defenseclaw.gateway.port",
                "defenseclaw.preset",
                "defenseclaw.preset_name",
                "discovery.source",
                "telemetry.sdk.language",
                "telemetry.sdk.name",
                "telemetry.sdk.version",
            ),
            "forbidden_value_classes": ("filesystem_path", "credential_material"),
        }
        raw_aliases = ()
    if dynamic is None or not isinstance(raw_aliases, Sequence) or isinstance(raw_aliases, (str, bytes, bytearray)):
        raise GoAPIPlanError("resource.core: custom-resource ownership contract is incomplete")

    fixed_keys = tuple(
        _string(item, "resource.core.attribute_refs")
        for item in _sequence(_read(group, "attribute_refs", owner_id), "resource.core.attribute_refs")
    )
    if len(fixed_keys) != len(set(fixed_keys)):
        raise GoAPIPlanError("resource.core: fixed key inventory contains duplicates")

    fixed_descriptors: list[GoKernelFieldDescriptorIR] = []
    for position, fixed_key in enumerate(fixed_keys):
        matches = [
            field
            for field in fields.values()
            if field.component == "resource" and field.semantic_source_id == fixed_key
        ]
        if not matches:
            raise GoAPIPlanError(f"resource.core fixed field {fixed_key}: generated descriptor is missing")
        source = _kernel_field(matches[0])
        comparable = (
            source.field_type,
            source.requirement,
            source.field_class,
            source.typed_constraints,
        )
        if any(
            (
                candidate.field_type,
                candidate.requirement,
                candidate.field_class,
                candidate.typed_constraints,
            )
            != comparable
            for candidate in (_kernel_field(item) for item in matches[1:])
        ):
            raise GoAPIPlanError(f"resource.core fixed field {fixed_key}: descriptors disagree across spans")
        fixed_descriptors.append(
            dataclasses.replace(
                source,
                descriptor_id=f"resource_fixed:{fixed_key}",
                order=position,
            )
        )

    aliases: list[GoResourceCompatibilityAliasPlanIR] = []
    for position, raw_alias in enumerate(raw_aliases):
        path = f"resource.core.resource_compatibility_aliases[{position}]"
        alias = _string(_read(raw_alias, "alias", path), f"{path}.alias")
        canonical = _string(_read(raw_alias, "canonical", path), f"{path}.canonical")
        matches = [
            field
            for field in fields.values()
            if field.component == "resource" and field.semantic_source_id == canonical
        ]
        if not matches:
            raise GoAPIPlanError(f"{path}.canonical: no generated resource descriptor owns the source")
        source = matches[0]
        if source.primitive_type != "string" or source.structured_type is not None:
            raise GoAPIPlanError(f"{path}.canonical: alias source must be a scalar string")
        source_contract = _kernel_field(source)
        for candidate in matches[1:]:
            candidate_contract = _kernel_field(candidate)
            if (
                candidate_contract.field_type,
                candidate_contract.field_class,
                candidate_contract.typed_constraints,
            ) != (
                source_contract.field_type,
                source_contract.field_class,
                source_contract.typed_constraints,
            ):
                raise GoAPIPlanError(f"{path}.canonical: source descriptors disagree across span families")
        descriptor = dataclasses.replace(
            source_contract,
            descriptor_id=f"resource_alias:{alias}",
            key=alias,
            requirement="recommended",
            condition_id=None,
            condition_fact=None,
            false_requirement=None,
            value_source="input",
            target_slot="resource",
            order=len(fixed_keys) + position,
            requirement_ref=_typed_symbol("familyRequirement", "familyRequirementRecommended"),
            false_requirement_ref=None,
            source_ref=_typed_symbol("familyValueSource", "familyValueInput"),
        )
        aliases.append(GoResourceCompatibilityAliasPlanIR(alias, canonical, descriptor))

    expected_aliases = (
        ("deployment.environment", "deployment.environment.name"),
        ("deployment.mode", "defenseclaw.deployment.mode"),
        ("defenseclaw.device.id", "defenseclaw.device.public_key_fingerprint"),
    )
    if aliases and tuple((item.alias, item.canonical) for item in aliases) != expected_aliases:
        raise GoAPIPlanError("resource.core: compatibility alias inventory differs from the canonical contract")

    resource_symbol_keys = (
        ("resource_attributes_type", owner_id),
        ("resource_attributes_constructor", owner_id),
        ("resource_attributes_attach", owner_id),
        ("resource_attributes_validator", owner_id),
    )
    present_symbols = tuple(symbols.get(key) for key in resource_symbol_keys)
    if any(item is None for item in present_symbols) and any(item is not None for item in present_symbols):
        raise GoAPIPlanError("resource.core: generated resource API symbol ownership is partial")
    type_symbol, constructor_symbol, attach_symbol, validator_symbol = (
        (
            "TelemetryCustomResourceAttributes",
            "NewTelemetryCustomResourceAttributes",
            "WithTelemetryCustomResourceAttributes",
            "ValidateTelemetryResourceAttributes",
        )
        if present_symbols[0] is None
        else tuple(item.symbol for item in present_symbols if item is not None)
    )
    plan = GoResourceAttributesPlanIR(
        owner_id=owner_id,
        type_symbol=type_symbol,
        constructor_symbol=constructor_symbol,
        attach_symbol=attach_symbol,
        validator_symbol=validator_symbol,
        ordering=_string(_read(dynamic, "ordering", owner_id), "resource dynamic ordering"),
        field_class=_string(_read(dynamic, "field_class", owner_id), "resource dynamic field class"),
        sensitivity=_string(_read(dynamic, "sensitivity", owner_id), "resource dynamic sensitivity"),
        cardinality=_string(_read(dynamic, "cardinality", owner_id), "resource dynamic cardinality"),
        stability_scope=_string(_read(dynamic, "stability_scope", owner_id), "resource dynamic stability scope"),
        value_utf8_policy=_string(_read(dynamic, "value_utf8_policy", owner_id), "resource UTF-8 policy"),
        value_blank_policy=_string(_read(dynamic, "value_blank_policy", owner_id), "resource blank policy"),
        value_control_character_policy=_string(
            _read(dynamic, "value_control_character_policy", owner_id), "resource control-character policy"
        ),
        prometheus_key_normalization=_string(
            _read(dynamic, "prometheus_key_normalization", owner_id), "resource Prometheus normalization"
        ),
        prometheus_normalized_collision_policy=_string(
            _read(dynamic, "prometheus_normalized_collision_policy", owner_id),
            "resource Prometheus collision policy",
        ),
        key_pattern=_string(_read(dynamic, "key_pattern", owner_id), "resource dynamic key pattern"),
        max_items=_integer(_read(dynamic, "max_items", owner_id), "resource max items", minimum=1),
        max_key_ascii_bytes=_integer(
            _read(dynamic, "max_key_ascii_bytes", owner_id), "resource max key bytes", minimum=1
        ),
        min_value_utf8_bytes=_integer(
            _read(dynamic, "min_value_utf8_bytes", owner_id), "resource min value bytes", minimum=1
        ),
        max_value_utf8_bytes=_integer(
            _read(dynamic, "max_value_utf8_bytes", owner_id), "resource max value bytes", minimum=1
        ),
        max_aggregate_utf8_bytes=_integer(
            _read(dynamic, "max_aggregate_utf8_bytes", owner_id), "resource aggregate bytes", minimum=1
        ),
        duplicate_key_policy=_string(_read(dynamic, "duplicate_key_policy", owner_id), "resource duplicate policy"),
        fixed_key_collision_policy=_string(
            _read(dynamic, "fixed_key_collision_policy", owner_id), "resource collision policy"
        ),
        fixed_keys=fixed_keys,
        fixed_descriptors=tuple(fixed_descriptors),
        forbidden_key_segments=tuple(
            _string(item, "resource forbidden segment")
            for item in _sequence(_read(dynamic, "forbidden_key_segments", owner_id), "resource forbidden segments")
        ),
        reserved_keys=tuple(
            _string(item, "resource reserved key")
            for item in _sequence(_read(dynamic, "reserved_keys", owner_id), "resource reserved keys")
        ),
        forbidden_value_classes=tuple(
            _string(item, "resource forbidden value class")
            for item in _sequence(
                _read(dynamic, "forbidden_value_classes", owner_id), "resource forbidden value classes"
            )
        ),
        aliases=tuple(aliases),
    )
    if (
        plan.ordering != "bytewise_key_ascending"
        or plan.field_class != "metadata"
        or plan.sensitivity != "internal"
        or plan.cardinality != "bounded"
        or plan.stability_scope != "process"
        or plan.value_utf8_policy != "require_valid"
        or plan.value_blank_policy != "reject_trimmed_empty"
        or plan.value_control_character_policy != "reject"
        or plan.prometheus_key_normalization != "dot_dash_to_underscore"
        or plan.prometheus_normalized_collision_policy != "reject"
        or plan.key_pattern != r"^[A-Za-z][A-Za-z0-9_.-]{0,127}$"
        or (
            plan.max_items,
            plan.max_key_ascii_bytes,
            plan.min_value_utf8_bytes,
            plan.max_value_utf8_bytes,
            plan.max_aggregate_utf8_bytes,
        )
        != (64, 128, 1, 1024, 16384)
        or plan.duplicate_key_policy != "reject"
        or plan.fixed_key_collision_policy != "reject"
        or plan.forbidden_value_classes != ("filesystem_path", "credential_material")
    ):
        raise GoAPIPlanError("resource.core: custom resource plan differs from the exact generator contract")
    planned = set(resource_symbol_keys) if present_symbols[0] is not None else set()
    return plan, planned


def compile_go_api_plan(index: Any) -> GoAPIPlanIR:
    """Compile one complete immutable Go API plan from enriched candidate facts."""

    materialized_digest = _string(_read(index, "materialized_view_sha256", "candidate"), "materialized view digest")
    if _SHA256.fullmatch(materialized_digest) is None:
        raise GoAPIPlanError("materialized_view_sha256: invalid digest")
    policy = _policy(index)
    rows, symbol_digest = _symbol_table(index)
    symbols = _symbol_index(rows)
    fields = _fields(index)
    resource_attributes, resource_planned = _compile_resource_attributes(index, symbols=symbols, fields=fields)
    structured, structured_inputs, structured_callables, structured_planned = _compile_structured(
        index, policy=policy, symbols=symbols, fields=fields
    )
    family_inputs, family_callables, descriptors, family_planned, family_domains = _compile_families(
        index, policy=policy, symbols=symbols, fields=fields
    )
    planned = structured_planned | family_planned | resource_planned
    expected_nonconstants = {(row.kind, row.source_id) for row in rows if row.declaration_form != "exported_const"}
    if planned != expected_nonconstants:
        raise GoAPIPlanError("Go API plans do not cover every non-constant declaration exactly once")
    assignments = _file_assignments(rows, family_domains)
    declarations = _declaration_plans(index, rows, assignments)
    declarations_by_file = {
        path: tuple(declaration for declaration in declarations if declaration.output_file == path)
        for path in GO_OUTPUT_FILES
    }
    inbound = getattr(index, "inbound_otlp", None)
    inbound_projection_ids: tuple[str, ...] = ()
    if inbound is not None:
        projection_rows = (
            ("alias", getattr(inbound, "alias_sets", ())),
            ("normalizer", getattr(inbound, "source_normalizers", ())),
            ("source-projection", getattr(inbound, "source_projection_plans", ())),
            ("match", getattr(inbound, "match_descriptors", ())),
            ("target", getattr(inbound, "target_descriptors", ())),
            ("marker", getattr(inbound, "native_markers", ())),
            ("echo", getattr(inbound, "echo_recognizers", ())),
            ("context", getattr(inbound, "import_contexts", ())),
        )
        inbound_projection_ids = tuple(
            f"inbound:{kind}:{_string(_read(row, 'id', f'inbound {kind} row'), f'inbound {kind} ID')}"
            for kind, rows in projection_rows
            for row in rows
        )
        if len(inbound_projection_ids) != len(set(inbound_projection_ids)):
            raise GoAPIPlanError("inbound Go projection IDs are duplicated")
    inputs = tuple(
        sorted(structured_inputs + family_inputs, key=lambda item: (item.declaration_kind, item.declaration_source_id))
    )
    callables = tuple(
        sorted(
            structured_callables + family_callables,
            key=lambda item: (item.declaration_kind, item.declaration_source_id),
        )
    )
    _validate_render_targets(inputs, callables)
    descriptors = tuple(sorted(descriptors, key=lambda item: item.family_id.encode("ascii")))
    _validate_condition_closure(inputs, callables, descriptors)
    private_declarations = _private_declaration_plans(structured, descriptors)
    kernel_helpers = _kernel_helper_inventory(callables, structured)
    fixtures = _fixture_plans(index, inputs)
    catalog_descriptor_ids = tuple(item.family_id for item in descriptors) + tuple(
        "structured:" + item.declaration_source_id for item in structured
    )
    files = tuple(
        GoFilePlanIR(
            path=path,
            package_name="observability",
            imports=(),
            declaration_keys=assignments[path],
            declarations=declarations_by_file[path],
            private_declarations=tuple(
                declaration for declaration in private_declarations if declaration.output_file == path
            ),
            private_descriptor_ids=(catalog_descriptor_ids if path == _CATALOG_FILE else ()),
            private_projection_ids=(
                ("producer-registry",) + inbound_projection_ids
                if path == _PRODUCERS_FILE
                else tuple(fixture.example_id for fixture in fixtures)
                if path == _FIXTURES_FILE
                else ()
            ),
            expected_digest_headers=_DIGEST_HEADERS,
        )
        for path in GO_OUTPUT_FILES
    )
    owned_private_descriptors = [descriptor_id for file in files for descriptor_id in file.private_descriptor_ids]
    if len(owned_private_descriptors) != len(set(owned_private_descriptors)) or set(owned_private_descriptors) != set(
        catalog_descriptor_ids
    ):
        raise GoAPIPlanError("private descriptor definition ownership is duplicated or incomplete")
    plan = GoAPIPlanIR(
        1,
        materialized_digest,
        symbol_digest,
        inputs,
        callables,
        structured,
        descriptors,
        resource_attributes,
        declarations,
        private_declarations,
        kernel_helpers,
        fixtures,
        files,
        "",
    )
    return dataclasses.replace(plan, api_plan_sha256=_plan_digest(plan))


__all__ = [
    "GO_OUTPUT_FILES",
    "GoAPIPlanError",
    "GoAPIPlanIR",
    "GoCallablePlanIR",
    "GoDeclarationPlanIR",
    "GoDescriptorPlanIR",
    "GoFactValueIR",
    "GoFieldPlanIR",
    "GoFilePlanIR",
    "GoFixturePlanIR",
    "GoInputPlanIR",
    "GoKernelFieldDescriptorIR",
    "GoKernelLimitsIR",
    "GoStructuredPlanIR",
    "GoTraceContractPlanIR",
    "GoTypeRefIR",
    "compile_go_api_plan",
]
