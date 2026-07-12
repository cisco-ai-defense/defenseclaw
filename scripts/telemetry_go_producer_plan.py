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
"""Compile producer mappings into a compact, closed generated-Go plan.

The compiler validates every row in
``CandidateRenderIndex.expanded_producer_mappings`` but does not materialize the
producer x identity-set Cartesian product in generated Go. Exact identities are
stored once, the 19 contextual sets are stored once, and each producer stores a
default identity plus a contextual-set reference. No wildcard or inferred
fallback is introduced.

The returned IR owns both data and syntax decisions needed by a later renderer:
private Go types/constants/variables, exact lookup symbols, exact function
signatures, a closed body-operation AST, imports, and deep-copy behavior.  Body
operations are enumerated rather than carried as source text so a renderer has
no semantic choices left and no raw-Go escape hatch.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from typing import Any, Final


class GoProducerPlanError(RuntimeError):
    """A safe, deterministic producer-plan contract failure."""


@dataclasses.dataclass(frozen=True, slots=True)
class GoTypeRefIR:
    """Closed Go type AST used by private declarations and signatures."""

    arm: str
    name: str | None = None
    element: GoTypeRefIR | None = None
    key: GoTypeRefIR | None = None
    length: int | None = None


@dataclasses.dataclass(frozen=True, slots=True)
class GoTypedStringIR:
    """A string literal paired with its exact Go named type."""

    go_type: str
    value: str


@dataclasses.dataclass(frozen=True, slots=True)
class GoProducerCompatibilityIR:
    introduced_in: str | None
    legacy_event_prefix: str | None
    disposition: GoTypedStringIR
    removal_version: str | None


@dataclasses.dataclass(frozen=True, slots=True)
class GoProducerFamilyRefsIR:
    """Real canonical-family authorities selected by one occurrence row.

    Bucket and event name are already exact typed literals on the row.  They do
    not pretend to reference descriptor kinds that the registry does not own.
    """

    family_descriptor_id: str | None
    selected_family_floor_id: str | None


@dataclasses.dataclass(frozen=True, slots=True)
class GoProducerIdentityRowIR:
    """One lossless expanded producer occurrence row."""

    row_id: str
    domain: str
    mapping_index: int
    identity_index: int
    identity_origin: GoTypedStringIR
    producer_kind: GoTypedStringIR
    producer_key: GoTypedStringIR
    source: GoTypedStringIR
    event_name_policy: GoTypedStringIR
    severity_policy: GoTypedStringIR
    event_name: GoTypedStringIR
    bucket: GoTypedStringIR
    family_refs: GoProducerFamilyRefsIR
    compatibility_only: bool
    legacy_mapping_mandatory_rules: tuple[GoTypedStringIR, ...]
    companion_rules: tuple[GoTypedStringIR, ...]
    compatibility: GoProducerCompatibilityIR


@dataclasses.dataclass(frozen=True, slots=True)
class GoProducerIdentityKeyIR:
    event_name: GoTypedStringIR
    bucket: GoTypedStringIR


@dataclasses.dataclass(frozen=True, slots=True)
class GoProducerIdentityIR:
    key: GoProducerIdentityKeyIR
    family_refs: GoProducerFamilyRefsIR
    compatibility_only: bool


@dataclasses.dataclass(frozen=True, slots=True)
class GoProducerContextSetIR:
    set_id: str
    identity_keys: tuple[GoProducerIdentityKeyIR, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class GoSelectionStepIR:
    """Deprecated input-validation view retained only for source-row tests."""

    opcode: str
    row_ids: tuple[str, ...] = ()


@dataclasses.dataclass(frozen=True, slots=True)
class GoProducerGroupIR:
    """One typed producer/key mapping and its exact selection precedence."""

    group_id: str
    domain: str
    mapping_index: int
    producer_kind: GoTypedStringIR
    producer_key: GoTypedStringIR
    source: GoTypedStringIR
    event_name_policy: GoTypedStringIR
    severity_policy: GoTypedStringIR
    has_default_identity: bool
    default_identity_key: GoProducerIdentityKeyIR | None
    context_identity_set_id: str | None
    legacy_mapping_mandatory_rules: tuple[GoTypedStringIR, ...]
    companion_rules: tuple[GoTypedStringIR, ...]
    compatibility: GoProducerCompatibilityIR


@dataclasses.dataclass(frozen=True, slots=True)
class GoLookupEntryIR:
    producer_kind: GoTypedStringIR
    producer_key: GoTypedStringIR
    group_id: str
    group_index: int


@dataclasses.dataclass(frozen=True, slots=True)
class GoLookupIndexIR:
    symbol: str
    key_type: GoTypeRefIR
    value_type: GoTypeRefIR
    entries: tuple[GoLookupEntryIR, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class GoCopyOperationIR:
    owner_type: str
    field: str
    opcode: str
    nested_fields: tuple[str, ...] = ()


@dataclasses.dataclass(frozen=True, slots=True)
class GoPrivateFieldIR:
    name: str
    type_ref: GoTypeRefIR


@dataclasses.dataclass(frozen=True, slots=True)
class GoPrivateTypeDeclarationIR:
    symbol: str
    declaration_kind: str
    underlying_type: GoTypeRefIR | None
    fields: tuple[GoPrivateFieldIR, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class GoPrivateConstantIR:
    symbol: str
    go_type: GoTypeRefIR
    value: str


@dataclasses.dataclass(frozen=True, slots=True)
class GoPrivateVariableIR:
    symbol: str
    go_type: GoTypeRefIR
    initializer_opcode: str
    data_refs: tuple[str, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class GoParameterIR:
    name: str
    type_ref: GoTypeRefIR


@dataclasses.dataclass(frozen=True, slots=True)
class GoBodyOperationIR:
    """Closed renderer opcode; operands are declaration/field symbols only."""

    opcode: str
    operands: tuple[str, ...] = ()


@dataclasses.dataclass(frozen=True, slots=True)
class GoErrorCaseIR:
    code: str
    format_string: str
    operands: tuple[str, ...] = ()


@dataclasses.dataclass(frozen=True, slots=True)
class GoPrivateFunctionIR:
    symbol: str
    parameters: tuple[GoParameterIR, ...]
    results: tuple[GoTypeRefIR, ...]
    body_operations: tuple[GoBodyOperationIR, ...]
    error_cases: tuple[GoErrorCaseIR, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class GoProducerFilePlanIR:
    path: str
    package: str
    imports: tuple[str, ...]
    type_declarations: tuple[GoPrivateTypeDeclarationIR, ...]
    constants: tuple[GoPrivateConstantIR, ...]
    variables: tuple[GoPrivateVariableIR, ...]
    functions: tuple[GoPrivateFunctionIR, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class GoProducerPlanIR:
    version: int
    materialized_view_sha256: str
    candidate_render_index_sha256: str
    source_row_count: int
    identities: tuple[GoProducerIdentityIR, ...]
    context_sets: tuple[GoProducerContextSetIR, ...]
    groups: tuple[GoProducerGroupIR, ...]
    lookup_index: GoLookupIndexIR
    copy_operations: tuple[GoCopyOperationIR, ...]
    file: GoProducerFilePlanIR
    producer_plan_sha256: str


_DIGEST_DOMAIN: Final = b"DefenseClaw GoProducerPlanIR v2\x00"
_SHA256: Final = re.compile(r"^[0-9a-f]{64}$")
_TOKEN: Final = re.compile(r"^[a-z][a-z0-9_.:/#-]{0,511}$")
_EVENT_NAME: Final = re.compile(r"^[a-z][a-z0-9_.-]{0,255}$")
_SOURCE: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/#-]{0,511}$")
_MAX_ROWS: Final = 100_000
_PRODUCER_KINDS: Final = frozenset({"gateway_event", "audit_action"})
_PRODUCER_SOURCES: Final = {
    "gateway_event": "internal/gatewaylog/events.go",
    "audit_action": "internal/audit/actions.go",
}
_EVENT_NAME_POLICIES: Final = frozenset({"fixed", "context_optional", "context_required"})
_SEVERITY_POLICIES: Final = frozenset(
    {
        "canonical_or_info",
        "finding_required",
        "evaluation",
        "failure_or_source",
        "malformed_or_source",
    }
)
_MANDATORY_RULES: Final = frozenset(
    {
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
    }
)
_COMPANION_RULES: Final = frozenset(
    {"enforcement_when_enforced", "asset_lifecycle_on_state_change", "finding_per_observation"}
)
_IDENTITY_ORIGINS: Final = frozenset({"default", "allowed_context"})
_COMPATIBILITY_DISPOSITIONS: Final = frozenset({"translate_to_v8"})
_COMPATIBILITY_KEYS: Final = frozenset({"introduced_in", "legacy_event_prefix", "disposition", "removal_version"})
_BODY_OPCODES: Final = frozenset(
    {
        "construct_lookup_key",
        "lookup_group_index",
        "return_zero_false_when_missing",
        "return_group_true",
        "lookup_group_or_error",
        "validate_context_identity_pair",
        "dispatch_closed_event_name_policy",
        "apply_group_selection_steps",
        "return_selected_identity_copy",
    }
)
_OUTPUT_PATH: Final = "internal/observability/zz_generated_telemetry_producers.go"


def _read(value: object, name: str, owner: str) -> Any:
    if isinstance(value, Mapping):
        if name not in value:
            raise GoProducerPlanError(f"{owner}: missing {name}")
        return value[name]
    if not hasattr(value, name):
        raise GoProducerPlanError(f"{owner}: missing {name}")
    return getattr(value, name)


def _sequence(value: object, label: str, maximum: int) -> Sequence[Any]:
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        raise GoProducerPlanError(f"{label}: expected bounded sequence")
    if len(value) > maximum:
        raise GoProducerPlanError(f"{label}: sequence exceeds the compiler bound")
    return value


def _string(value: object, label: str, pattern: re.Pattern[str] = _TOKEN) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise GoProducerPlanError(f"{label}: invalid string token")
    return value


def _optional_string(value: object, label: str, pattern: re.Pattern[str] = _TOKEN) -> str | None:
    if value is None:
        return None
    return _string(value, label, pattern)


def _integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0 or value > _MAX_ROWS:
        raise GoProducerPlanError(f"{label}: invalid nonnegative integer")
    return value


def _boolean(value: object, label: str) -> bool:
    if type(value) is not bool:
        raise GoProducerPlanError(f"{label}: expected Boolean")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise GoProducerPlanError(f"{label}: invalid SHA-256 digest")
    return value


def _typed(go_type: str, value: str) -> GoTypedStringIR:
    return GoTypedStringIR(go_type, value)


def _typed_rules(
    value: object,
    label: str,
    *,
    allowed: frozenset[str],
    go_type: str,
) -> tuple[GoTypedStringIR, ...]:
    sequence = _sequence(value, label, len(allowed))
    rules = tuple(_string(item, f"{label}[{position}]") for position, item in enumerate(sequence))
    if len(rules) != len(set(rules)) or not set(rules).issubset(allowed):
        raise GoProducerPlanError(f"{label}: unknown or duplicate rule")
    return tuple(_typed(go_type, rule) for rule in rules)


def _compatibility(value: object, label: str) -> GoProducerCompatibilityIR:
    if not isinstance(value, Mapping) or set(value) != _COMPATIBILITY_KEYS:
        raise GoProducerPlanError(f"{label}: expected exact compatibility contract")
    disposition = _string(value["disposition"], f"{label}.disposition")
    if disposition not in _COMPATIBILITY_DISPOSITIONS:
        raise GoProducerPlanError(f"{label}.disposition: unsupported disposition")
    introduced = _optional_string(value["introduced_in"], f"{label}.introduced_in")
    if introduced is None:
        raise GoProducerPlanError(f"{label}.introduced_in: required")
    prefix = _optional_string(value["legacy_event_prefix"], f"{label}.legacy_event_prefix", _EVENT_NAME)
    if prefix is not None and prefix != "legacy.audit.":
        raise GoProducerPlanError(f"{label}.legacy_event_prefix: unsupported prefix")
    return GoProducerCompatibilityIR(
        introduced,
        prefix,
        _typed("generatedCompatibilityDisposition", disposition),
        _optional_string(value["removal_version"], f"{label}.removal_version"),
    )


def _row(raw: object, position: int) -> GoProducerIdentityRowIR:
    owner = f"expanded_producer_mappings[{position}]"
    domain = _string(_read(raw, "domain", owner), f"{owner}.domain")
    mapping_index = _integer(_read(raw, "mapping_index", owner), f"{owner}.mapping_index")
    identity_index = _integer(_read(raw, "identity_index", owner), f"{owner}.identity_index")
    origin = _string(_read(raw, "identity_origin", owner), f"{owner}.identity_origin")
    if origin not in _IDENTITY_ORIGINS:
        raise GoProducerPlanError(f"{owner}.identity_origin: unsupported origin")
    row_id = _string(_read(raw, "id", owner), f"{owner}.id")
    if row_id != f"{domain}:{mapping_index}:{origin}:{identity_index}":
        raise GoProducerPlanError(f"{owner}.id: identity coordinates disagree")
    producer = _string(_read(raw, "producer", owner), f"{owner}.producer")
    if producer not in _PRODUCER_KINDS:
        raise GoProducerPlanError(f"{owner}.producer: unsupported producer kind")
    key = _string(_read(raw, "key", owner), f"{owner}.key")
    source = _string(_read(raw, "source", owner), f"{owner}.source", _SOURCE)
    if source != _PRODUCER_SOURCES[producer]:
        raise GoProducerPlanError(f"{owner}.source: producer source disagrees")
    event_policy = _string(_read(raw, "event_name_policy", owner), f"{owner}.event_name_policy")
    if event_policy not in _EVENT_NAME_POLICIES:
        raise GoProducerPlanError(f"{owner}.event_name_policy: unsupported policy")
    severity_policy = _string(_read(raw, "severity_policy", owner), f"{owner}.severity_policy")
    if severity_policy not in _SEVERITY_POLICIES:
        raise GoProducerPlanError(f"{owner}.severity_policy: unsupported policy")
    event_name = _string(_read(raw, "event_name", owner), f"{owner}.event_name", _EVENT_NAME)
    bucket = _string(_read(raw, "bucket", owner), f"{owner}.bucket")
    family_id = _read(raw, "family_id", owner)
    if family_id is not None:
        family_id = _string(family_id, f"{owner}.family_id")
    compatibility_only = _boolean(_read(raw, "compatibility_only", owner), f"{owner}.compatibility_only")
    selected_floor = _read(raw, "selected_mandatory_program_id", owner)
    if selected_floor is not None:
        selected_floor = _string(selected_floor, f"{owner}.selected_mandatory_program_id")
    if compatibility_only:
        if family_id is not None or selected_floor is not None:
            raise GoProducerPlanError(f"{owner}: compatibility-only identity selected canonical authority")
    elif family_id is None or selected_floor != family_id:
        raise GoProducerPlanError(f"{owner}: selected-family floor reference is incomplete")
    return GoProducerIdentityRowIR(
        row_id=row_id,
        domain=domain,
        mapping_index=mapping_index,
        identity_index=identity_index,
        identity_origin=_typed("string", origin),
        producer_kind=_typed("ProducerKind", producer),
        producer_key=_typed("ProducerKey", key),
        source=_typed("generatedProducerSource", source),
        event_name_policy=_typed("EventNamePolicy", event_policy),
        severity_policy=_typed("SeverityPolicy", severity_policy),
        event_name=_typed("EventName", event_name),
        bucket=_typed("Bucket", bucket),
        family_refs=GoProducerFamilyRefsIR(
            family_descriptor_id=family_id,
            selected_family_floor_id=selected_floor,
        ),
        compatibility_only=compatibility_only,
        legacy_mapping_mandatory_rules=_typed_rules(
            _read(raw, "legacy_mapping_mandatory_rules", owner),
            f"{owner}.legacy_mapping_mandatory_rules",
            allowed=_MANDATORY_RULES,
            go_type="MandatoryRule",
        ),
        companion_rules=_typed_rules(
            _read(raw, "companion_rules", owner),
            f"{owner}.companion_rules",
            allowed=_COMPANION_RULES,
            go_type="CompanionRule",
        ),
        compatibility=_compatibility(_read(raw, "compatibility", owner), f"{owner}.compatibility"),
    )


def _identity_key(row: GoProducerIdentityRowIR) -> GoProducerIdentityKeyIR:
    return GoProducerIdentityKeyIR(event_name=row.event_name, bucket=row.bucket)


def _groups(
    rows: tuple[GoProducerIdentityRowIR, ...],
) -> tuple[
    tuple[GoProducerIdentityIR, ...],
    tuple[GoProducerContextSetIR, ...],
    tuple[GoProducerGroupIR, ...],
]:
    grouped: list[list[GoProducerIdentityRowIR]] = []
    keys: set[tuple[str, str]] = set()
    for row in rows:
        identity = (row.producer_kind.value, row.producer_key.value)
        if (
            not grouped
            or (
                grouped[-1][0].producer_kind.value,
                grouped[-1][0].producer_key.value,
            )
            != identity
        ):
            if identity in keys:
                raise GoProducerPlanError("expanded producer rows: a producer mapping is non-contiguous")
            keys.add(identity)
            grouped.append([])
        grouped[-1].append(row)
    result: list[GoProducerGroupIR] = []
    identities: dict[tuple[str, str], GoProducerIdentityIR] = {}
    context_sets: list[GoProducerContextSetIR] = []
    context_set_ids: dict[tuple[tuple[str, str], ...], str] = {}
    expected_mapping_index = 0
    for group_rows in grouped:
        first = group_rows[0]
        if first.mapping_index != expected_mapping_index:
            raise GoProducerPlanError("expanded producer rows: mapping-index order is not complete")
        expected_mapping_index += 1
        common = (
            first.domain,
            first.mapping_index,
            first.producer_kind,
            first.producer_key,
            first.source,
            first.event_name_policy,
            first.severity_policy,
            first.legacy_mapping_mandatory_rules,
            first.companion_rules,
            first.compatibility,
        )
        if any(
            (
                row.domain,
                row.mapping_index,
                row.producer_kind,
                row.producer_key,
                row.source,
                row.event_name_policy,
                row.severity_policy,
                row.legacy_mapping_mandatory_rules,
                row.companion_rules,
                row.compatibility,
            )
            != common
            for row in group_rows
        ):
            raise GoProducerPlanError("expanded producer rows: mapping-common facts disagree")
        if tuple(row.identity_index for row in group_rows) != tuple(range(len(group_rows))):
            raise GoProducerPlanError("expanded producer rows: identity precedence is not contiguous")
        defaults = tuple(row for row in group_rows if row.identity_origin.value == "default")
        contexts = tuple(row for row in group_rows if row.identity_origin.value == "allowed_context")
        if len(defaults) > 1 or (defaults and defaults != (group_rows[0],)):
            raise GoProducerPlanError("expanded producer rows: default identity precedence is invalid")
        context_identities = [
            (row.event_name.value, row.bucket.value)
            for row in group_rows
            if row.identity_origin.value == "allowed_context"
        ]
        if len(context_identities) != len(set(context_identities)):
            raise GoProducerPlanError("expanded producer rows: contextual identity is duplicated")
        policy = first.event_name_policy.value
        if policy == "fixed" and (len(defaults) != 1 or contexts):
            raise GoProducerPlanError("expanded producer rows: fixed policy shape is invalid")
        if policy == "context_optional" and (len(defaults) != 1 or not contexts):
            raise GoProducerPlanError("expanded producer rows: optional-context policy shape is invalid")
        if policy == "context_required" and (defaults or not contexts):
            raise GoProducerPlanError("expanded producer rows: required-context policy shape is invalid")
        for row in group_rows:
            key = (row.bucket.value, row.event_name.value)
            identity = GoProducerIdentityIR(
                key=_identity_key(row),
                family_refs=row.family_refs,
                compatibility_only=row.compatibility_only,
            )
            previous = identities.setdefault(key, identity)
            if previous != identity:
                raise GoProducerPlanError("expanded producer rows: identity authority disagrees across mappings")
        context_key = tuple((row.bucket.value, row.event_name.value) for row in contexts)
        context_set_id: str | None = None
        if context_key:
            context_set_id = context_set_ids.get(context_key)
            if context_set_id is None:
                context_set_id = f"context_set_{len(context_sets):02d}"
                context_set_ids[context_key] = context_set_id
                context_sets.append(
                    GoProducerContextSetIR(
                        set_id=context_set_id,
                        identity_keys=tuple(_identity_key(row) for row in contexts),
                    )
                )
        group_id = f"{first.domain}:{first.mapping_index}:{first.producer_kind.value}:{first.producer_key.value}"
        result.append(
            GoProducerGroupIR(
                group_id=group_id,
                domain=first.domain,
                mapping_index=first.mapping_index,
                producer_kind=first.producer_kind,
                producer_key=first.producer_key,
                source=first.source,
                event_name_policy=first.event_name_policy,
                severity_policy=first.severity_policy,
                has_default_identity=bool(defaults),
                default_identity_key=_identity_key(defaults[0]) if defaults else None,
                context_identity_set_id=context_set_id,
                legacy_mapping_mandatory_rules=first.legacy_mapping_mandatory_rules,
                companion_rules=first.companion_rules,
                compatibility=first.compatibility,
            )
        )
    return tuple(identities.values()), tuple(context_sets), tuple(result)


def _builtin(name: str) -> GoTypeRefIR:
    return GoTypeRefIR("builtin", name=name)


def _named(name: str) -> GoTypeRefIR:
    return GoTypeRefIR("named", name=name)


def _slice(element: GoTypeRefIR) -> GoTypeRefIR:
    return GoTypeRefIR("slice", element=element)


def _map(key: GoTypeRefIR, element: GoTypeRefIR) -> GoTypeRefIR:
    return GoTypeRefIR("map", element=element, key=key)


def _private_types() -> tuple[GoPrivateTypeDeclarationIR, ...]:
    string = _builtin("string")
    boolean = _builtin("bool")
    aliases = tuple(
        GoPrivateTypeDeclarationIR(symbol, "defined", string, ())
        for symbol in ("generatedProducerSource", "generatedCompatibilityDisposition")
    )
    compatibility = GoPrivateTypeDeclarationIR(
        "generatedProducerCompatibility",
        "struct",
        None,
        (
            GoPrivateFieldIR("IntroducedIn", string),
            GoPrivateFieldIR("LegacyEventPrefix", string),
            GoPrivateFieldIR("Disposition", _named("generatedCompatibilityDisposition")),
            GoPrivateFieldIR("RemovalVersion", string),
        ),
    )
    family_refs = GoPrivateTypeDeclarationIR(
        "generatedProducerFamilyRefs",
        "struct",
        None,
        (
            GoPrivateFieldIR("FamilyDescriptorID", string),
            GoPrivateFieldIR("SelectedFamilyFloorID", string),
        ),
    )
    identity = GoPrivateTypeDeclarationIR(
        "generatedProducerIdentity",
        "struct",
        None,
        (
            GoPrivateFieldIR("EventName", _named("EventName")),
            GoPrivateFieldIR("Bucket", _named("Bucket")),
            GoPrivateFieldIR("FamilyRefs", _named("generatedProducerFamilyRefs")),
            GoPrivateFieldIR("CompatibilityOnly", boolean),
            GoPrivateFieldIR("LegacyMandatoryRules", _slice(_named("MandatoryRule"))),
            GoPrivateFieldIR("CompanionRules", _slice(_named("CompanionRule"))),
        ),
    )
    identity_key = GoPrivateTypeDeclarationIR(
        "generatedProducerIdentityKey",
        "struct",
        None,
        (
            GoPrivateFieldIR("EventName", _named("EventName")),
            GoPrivateFieldIR("Bucket", _named("Bucket")),
        ),
    )
    context_set = GoPrivateTypeDeclarationIR(
        "generatedProducerContextIdentitySet",
        "struct",
        None,
        (
            GoPrivateFieldIR("ID", string),
            GoPrivateFieldIR("IdentityKeys", _slice(_named("generatedProducerIdentityKey"))),
        ),
    )
    group = GoPrivateTypeDeclarationIR(
        "generatedProducerGroup",
        "struct",
        None,
        (
            GoPrivateFieldIR("Kind", _named("ProducerKind")),
            GoPrivateFieldIR("Key", _named("ProducerKey")),
            GoPrivateFieldIR("Source", _named("generatedProducerSource")),
            GoPrivateFieldIR("EventNamePolicy", _named("EventNamePolicy")),
            GoPrivateFieldIR("SeverityPolicy", _named("SeverityPolicy")),
            GoPrivateFieldIR("HasDefaultIdentity", boolean),
            GoPrivateFieldIR("DefaultIdentityKey", _named("generatedProducerIdentityKey")),
            GoPrivateFieldIR("ContextIdentitySetID", string),
            GoPrivateFieldIR("LegacyMandatoryRules", _slice(_named("MandatoryRule"))),
            GoPrivateFieldIR("CompanionRules", _slice(_named("CompanionRule"))),
            GoPrivateFieldIR("Compatibility", _named("generatedProducerCompatibility")),
        ),
    )
    lookup_key = GoPrivateTypeDeclarationIR(
        "generatedProducerLookupKey",
        "struct",
        None,
        (
            GoPrivateFieldIR("Kind", _named("ProducerKind")),
            GoPrivateFieldIR("Key", _named("ProducerKey")),
        ),
    )
    return (*aliases, compatibility, family_refs, identity_key, identity, context_set, group, lookup_key)


def _private_constants(groups: tuple[GoProducerGroupIR, ...]) -> tuple[GoPrivateConstantIR, ...]:
    sources = tuple(dict.fromkeys(group.source.value for group in groups))
    expected_sources = tuple(_PRODUCER_SOURCES[kind] for kind in ("gateway_event", "audit_action"))
    if sources != expected_sources:
        raise GoProducerPlanError("expanded producer rows: source declaration order changed")
    return (
        GoPrivateConstantIR("generatedSourceGatewayEvent", _named("generatedProducerSource"), expected_sources[0]),
        GoPrivateConstantIR("generatedSourceAuditAction", _named("generatedProducerSource"), expected_sources[1]),
        GoPrivateConstantIR(
            "generatedCompatibilityTranslateToV8",
            _named("generatedCompatibilityDisposition"),
            "translate_to_v8",
        ),
    )


def _private_functions() -> tuple[GoPrivateFunctionIR, ...]:
    lookup = GoPrivateFunctionIR(
        "lookupGeneratedProducerGroup",
        (
            GoParameterIR("kind", _named("ProducerKind")),
            GoParameterIR("key", _named("ProducerKey")),
        ),
        (_named("generatedProducerGroup"), _builtin("bool")),
        tuple(
            GoBodyOperationIR(opcode, operands)
            for opcode, operands in (
                ("construct_lookup_key", ("generatedProducerLookupKey",)),
                ("lookup_group_index", ("generatedProducerGroupIndex", "generatedProducerGroups")),
                ("return_zero_false_when_missing", ("generatedProducerGroup",)),
                ("return_group_true", ()),
            )
        ),
        (),
    )
    resolve = GoPrivateFunctionIR(
        "resolveGeneratedProducerIdentity",
        (
            GoParameterIR("kind", _named("ProducerKind")),
            GoParameterIR("key", _named("ProducerKey")),
            GoParameterIR("context", _named("ClassificationContext")),
        ),
        (_named("generatedProducerIdentity"), _builtin("error")),
        tuple(
            GoBodyOperationIR(opcode, operands)
            for opcode, operands in (
                ("lookup_group_or_error", ("lookupGeneratedProducerGroup",)),
                ("validate_context_identity_pair", ("Bucket", "EventName")),
                ("dispatch_closed_event_name_policy", tuple(sorted(_EVENT_NAME_POLICIES))),
                ("apply_group_selection_steps", tuple(sorted(_EVENT_NAME_POLICIES))),
                ("return_selected_identity_copy", ()),
            )
        ),
        (
            GoErrorCaseIR(
                "unknown_producer_mapping",
                "unknown generated producer classification %s/%s",
                ("kind", "key"),
            ),
            GoErrorCaseIR(
                "partial_context_identity",
                "generated producer context identity requires bucket and event name together",
            ),
            GoErrorCaseIR(
                "fixed_context_disagreement",
                "generated producer fixed identity disagrees with supplied context",
            ),
            GoErrorCaseIR(
                "missing_context_identity",
                "generated producer classification requires a context identity",
            ),
            GoErrorCaseIR(
                "unmatched_context_identity",
                "generated producer context identity is not registered for %s/%s",
                ("kind", "key"),
            ),
        ),
    )
    if any(
        operation.opcode not in _BODY_OPCODES for item in (lookup, resolve) for operation in item.body_operations
    ):
        raise AssertionError("private producer function uses an unregistered body opcode")
    return lookup, resolve


def _file(
    identities: tuple[GoProducerIdentityIR, ...],
    context_sets: tuple[GoProducerContextSetIR, ...],
    groups: tuple[GoProducerGroupIR, ...],
) -> GoProducerFilePlanIR:
    variables = (
        GoPrivateVariableIR(
            "generatedProducerIdentities",
            _map(_named("generatedProducerIdentityKey"), _named("generatedProducerIdentity")),
            "literal_identities",
            tuple(f"{item.key.bucket.value}:{item.key.event_name.value}" for item in identities),
        ),
        GoPrivateVariableIR(
            "generatedProducerContextIdentitySets",
            _map(_builtin("string"), _named("generatedProducerContextIdentitySet")),
            "literal_context_sets",
            tuple(item.set_id for item in context_sets),
        ),
        GoPrivateVariableIR(
            "generatedProducerGroups",
            GoTypeRefIR("array", element=_named("generatedProducerGroup"), length=len(groups)),
            "literal_groups",
            tuple(group.group_id for group in groups),
        ),
        GoPrivateVariableIR(
            "generatedProducerGroupIndex",
            _map(_named("generatedProducerLookupKey"), _builtin("int")),
            "literal_lookup_index",
            tuple(group.group_id for group in groups),
        ),
    )
    return GoProducerFilePlanIR(
        path=_OUTPUT_PATH,
        package="observability",
        imports=("fmt",),
        type_declarations=_private_types(),
        constants=_private_constants(groups),
        variables=variables,
        functions=_private_functions(),
    )


def _plain(value: object) -> Any:
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {field.name: _plain(getattr(value, field.name)) for field in dataclasses.fields(value)}
    if isinstance(value, tuple):
        return [_plain(item) for item in value]
    if isinstance(value, (str, int, bool)) or value is None:
        return value
    raise GoProducerPlanError("producer plan contains a non-canonical digest value")


def _plan_digest(
    materialized: str,
    candidate: str,
    source_row_count: int,
    identities: tuple[GoProducerIdentityIR, ...],
    context_sets: tuple[GoProducerContextSetIR, ...],
    groups: tuple[GoProducerGroupIR, ...],
    lookup: GoLookupIndexIR,
    copies: tuple[GoCopyOperationIR, ...],
    file: GoProducerFilePlanIR,
) -> str:
    payload = json.dumps(
        _plain((2, materialized, candidate, source_row_count, identities, context_sets, groups, lookup, copies, file)),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(_DIGEST_DOMAIN + payload).hexdigest()


def compile_go_producer_plan(index: object) -> GoProducerPlanIR:
    """Compile the complete v1 expanded producer inventory without inference."""

    materialized = _digest(
        _read(index, "materialized_view_sha256", "CandidateRenderIndex"),
        "CandidateRenderIndex.materialized_view_sha256",
    )
    candidate = _digest(
        _read(index, "candidate_render_index_sha256", "CandidateRenderIndex"),
        "CandidateRenderIndex.candidate_render_index_sha256",
    )
    raw_rows = _sequence(
        _read(index, "expanded_producer_mappings", "CandidateRenderIndex"),
        "CandidateRenderIndex.expanded_producer_mappings",
        _MAX_ROWS,
    )
    if not raw_rows:
        raise GoProducerPlanError("expanded producer rows: inventory is empty")
    rows = tuple(_row(raw, position) for position, raw in enumerate(raw_rows))
    if len({row.row_id for row in rows}) != len(rows):
        raise GoProducerPlanError("expanded producer rows: duplicate row ID")
    identities, context_sets, groups = _groups(rows)
    if not groups:
        raise GoProducerPlanError("expanded producer rows: producer groups are empty")
    entries = tuple(
        GoLookupEntryIR(
            group.producer_kind,
            group.producer_key,
            group.group_id,
            position,
        )
        for position, group in enumerate(groups)
    )
    lookup = GoLookupIndexIR(
        "generatedProducerGroupIndex",
        _named("generatedProducerLookupKey"),
        _builtin("int"),
        entries,
    )
    copies: tuple[GoCopyOperationIR, ...] = ()
    file = _file(identities, context_sets, groups)
    digest = _plan_digest(
        materialized,
        candidate,
        len(rows),
        identities,
        context_sets,
        groups,
        lookup,
        copies,
        file,
    )
    return GoProducerPlanIR(
        2,
        materialized,
        candidate,
        len(rows),
        identities,
        context_sets,
        groups,
        lookup,
        copies,
        file,
        digest,
    )
