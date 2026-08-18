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
"""Compile closed inbound OTLP descriptors into a private generated-Go plan."""

from __future__ import annotations

import dataclasses
import hashlib
import json
import math
import re
from collections.abc import Mapping, Sequence
from typing import Any, Final


class GoInboundPlanError(RuntimeError):
    """The candidate inbound descriptor set cannot produce safe Go data."""


@dataclasses.dataclass(frozen=True, slots=True)
class GoInboundPredicateIR:
    location: str
    key: str
    operator: str
    values_json: str
    value_type: str


@dataclasses.dataclass(frozen=True, slots=True)
class GoInboundAliasIR:
    id: str
    target: str
    value_type: str
    normalization: str
    sources: tuple[str, ...]
    conflict_policy: str
    absence_policy: str
    field_class: str
    sensitivity: str


@dataclasses.dataclass(frozen=True, slots=True)
class GoInboundNormalizerRuleIR:
    output: str
    exact: tuple[str, ...]
    contains: tuple[str, ...]
    inputs: tuple[str, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class GoInboundSourceNormalizerIR:
    id: str
    kind: str
    trim: str
    case: str
    max_utf8_bytes: int
    empty: str
    overflow: str
    unmatched: str
    pattern: str
    values: tuple[str, ...]
    separators: tuple[str, ...]
    prefixes: tuple[str, ...]
    rules: tuple[GoInboundNormalizerRuleIR, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class GoInboundSourceGroupIR:
    placement: str
    keys: tuple[str, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class GoInboundProjectionFieldIR:
    target: str
    disposition: str
    requirement: str
    normalization: str
    allowed_values: tuple[str, ...]
    source_groups: tuple[GoInboundSourceGroupIR, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class GoInboundSeriesComponentIR:
    id: str
    requirement: str
    normalization: str
    allowed_values: tuple[str, ...]
    source_groups: tuple[GoInboundSourceGroupIR, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class GoInboundResetEpochIR:
    role: str
    identity: bool
    placement: str
    key: str
    normalization: str


@dataclasses.dataclass(frozen=True, slots=True)
class GoInboundCumulativeSeriesIR:
    applicability: str
    framing: str
    normalization_stage: str
    components: tuple[GoInboundSeriesComponentIR, ...]
    reset_epoch: GoInboundResetEpochIR


@dataclasses.dataclass(frozen=True, slots=True)
class GoInboundSourceProjectionPlanIR:
    id: str
    target_family: str
    field_rules: tuple[GoInboundProjectionFieldIR, ...]
    cumulative_series: GoInboundCumulativeSeriesIR | None


@dataclasses.dataclass(frozen=True, slots=True)
class GoInboundTargetOverrideIR:
    source: str
    target: str
    normalization: str


@dataclasses.dataclass(frozen=True, slots=True)
class GoInboundUnitScaleIR:
    source_unit: str
    scale: float


@dataclasses.dataclass(frozen=True, slots=True)
class GoInboundUnitRuleIR:
    kind: str
    target_unit: str
    accepted: tuple[GoInboundUnitScaleIR, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class GoInboundMatchIR:
    id: str
    class_id: str
    signal: str
    sources: tuple[str, ...]
    shape: str
    discriminator_kind: str
    predicates: tuple[GoInboundPredicateIR, ...]
    mapping_strategy: str
    alias_ids: tuple[str, ...]
    source_projection_plan_id: str
    target_override: GoInboundTargetOverrideIR | None
    source_unit_rule: GoInboundUnitRuleIR
    target_ids: tuple[str, ...]
    time_rule_json: str
    outcome_rule_json: str
    native_round_trip: bool


@dataclasses.dataclass(frozen=True, slots=True)
class GoInboundTargetIR:
    id: str
    match_id: str
    class_id: str
    signal: str
    role: str
    target_kind: str
    family: str
    bucket: str
    event_name: str
    family_schema_version: int
    instrument_name: str
    instrument_type: str
    instrument_unit: str
    field_refs: tuple[str, ...]
    field_descriptor_ids: tuple[str, ...]
    descriptor_symbol: str
    mapping_strategy: str
    derivation_strategy: str
    time_rule_json: str
    outcome_rule_json: str
    import_context_id: str
    source_unit_rule: GoInboundUnitRuleIR
    source_projection_plan_id: str


@dataclasses.dataclass(frozen=True, slots=True)
class GoInboundEchoRecognizerIR:
    id: str
    signal: str
    family: str
    bucket: str
    event_name: str
    instrument_name: str
    forward_placement: str
    compare_self_with: str


@dataclasses.dataclass(frozen=True, slots=True)
class GoInboundNativeMarkerIR:
    id: str
    signal: str
    location: str
    key: str
    marker_kind: str
    values_json: str
    value_type: str


@dataclasses.dataclass(frozen=True, slots=True)
class GoInboundImportContextIR:
    id: str
    family_descriptor_id: str
    bucket: str
    event_name: str
    construction_mode: str
    capabilities: tuple[str, ...]
    descriptor_symbol: str


@dataclasses.dataclass(frozen=True, slots=True)
class GoInboundNativeExpansionIR:
    """One compiler-proven native class expanded from the family catalog at startup."""

    class_id: str
    signal: str
    family_ids: tuple[str, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class GoInboundPlanIR:
    version: int
    materialized_view_sha256: str
    candidate_render_index_sha256: str
    scope_name: str
    scope_schema_url: str
    resource_schema_url: str
    semantic_resource_instance_key: str
    forward_instance_key: str
    forward_destination_key: str
    forward_hop_count_key: str
    record_id_key: str
    max_forward_hops: int
    unknown_fields: str
    native_marker_rule: str
    structural_marker_rule: str
    native_malformed_disposition: str
    native_malformed_external_fallback: str
    aliases: tuple[GoInboundAliasIR, ...]
    source_normalizers: tuple[GoInboundSourceNormalizerIR, ...]
    source_projection_plans: tuple[GoInboundSourceProjectionPlanIR, ...]
    native_expansions: tuple[GoInboundNativeExpansionIR, ...]
    matches: tuple[GoInboundMatchIR, ...]
    targets: tuple[GoInboundTargetIR, ...]
    native_markers: tuple[GoInboundNativeMarkerIR, ...]
    echo_recognizers: tuple[GoInboundEchoRecognizerIR, ...]
    import_contexts: tuple[GoInboundImportContextIR, ...]
    projection_ids: tuple[str, ...]
    inbound_plan_sha256: str


_DIGEST_DOMAIN: Final = b"DefenseClaw GoInboundPlanIR v2\x00"
_SHA256: Final = re.compile(r"^[0-9a-f]{64}$")

_NATIVE_EXPANSION_CLASSES: Final = (
    ("otlp.native.log.v8", "logs", "log"),
    ("otlp.native.metric.v8", "metrics", "metric"),
    ("otlp.native.span.v8", "traces", "span"),
)


def _read(value: Any, name: str, path: str) -> Any:
    if not hasattr(value, name):
        raise GoInboundPlanError(f"{path}.{name}: required")
    return getattr(value, name)


def _mapping(value: Any, path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise GoInboundPlanError(f"{path}: expected mapping")
    return value


def _sequence(value: Any, path: str) -> Sequence[Any]:
    if not isinstance(value, tuple):
        raise GoInboundPlanError(f"{path}: expected immutable sequence")
    return value


def _string(value: Any, path: str, *, empty: bool = False) -> str:
    if not isinstance(value, str) or (not empty and not value):
        raise GoInboundPlanError(f"{path}: expected {'possibly empty ' if empty else 'nonempty '}string")
    return value


def _json(value: Any) -> str:
    def plain(item: Any) -> Any:
        if isinstance(item, Mapping):
            return {key: plain(item[key]) for key in sorted(item)}
        if isinstance(item, tuple):
            return [plain(child) for child in item]
        if item is None or type(item) in {bool, int, float, str}:
            return item
        raise GoInboundPlanError("inbound plan contains unsupported JSON data")

    return json.dumps(plain(value), ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _unit_rule(value: Any, path: str) -> GoInboundUnitRuleIR:
    item = _mapping(value, path)
    if set(item) != {"kind", "target_unit", "accepted"}:
        raise GoInboundPlanError(f"{path}: invalid source-unit rule shape")
    accepted: list[GoInboundUnitScaleIR] = []
    for position, raw in enumerate(_sequence(item["accepted"], f"{path}.accepted")):
        entry = _mapping(raw, f"{path}.accepted[{position}]")
        if set(entry) != {"source_unit", "scale"}:
            raise GoInboundPlanError(f"{path}.accepted[{position}]: invalid source-unit scale shape")
        source_unit = _string(entry["source_unit"], "source unit", empty=True)
        scale = entry["scale"]
        if type(scale) not in {int, float} or isinstance(scale, bool) or not math.isfinite(float(scale)) or scale <= 0:
            raise GoInboundPlanError(f"{path}.accepted[{position}].scale: invalid source-unit scale")
        accepted.append(GoInboundUnitScaleIR(source_unit, float(scale)))
    return GoInboundUnitRuleIR(
        _string(item["kind"], f"{path}.kind"),
        _string(item["target_unit"], f"{path}.target_unit", empty=True),
        tuple(accepted),
    )


def _source_groups(value: Any, path: str) -> tuple[GoInboundSourceGroupIR, ...]:
    return tuple(
        GoInboundSourceGroupIR(
            _string(group["placement"], f"{path}.placement"),
            tuple(_string(key, f"{path}.key") for key in _sequence(group["keys"], f"{path}.keys")),
        )
        for group in (_mapping(item, path) for item in _sequence(value, path))
    )


def _source_normalizers(inbound: Any) -> tuple[GoInboundSourceNormalizerIR, ...]:
    result: list[GoInboundSourceNormalizerIR] = []
    for position, raw in enumerate(
        _sequence(_read(inbound, "source_normalizers", "inbound"), "inbound.source_normalizers")
    ):
        path = f"inbound.source_normalizers[{position}]"
        item = _mapping(raw, path)
        rules = tuple(
            GoInboundNormalizerRuleIR(
                _string(rule["output"], f"{path}.rule.output"),
                tuple(_string(value, f"{path}.rule.exact") for value in _sequence(rule["exact"], f"{path}.rule.exact")),
                tuple(
                    _string(value, f"{path}.rule.contains")
                    for value in _sequence(rule["contains"], f"{path}.rule.contains")
                ),
                tuple(
                    _string(value, f"{path}.rule.inputs") for value in _sequence(rule["inputs"], f"{path}.rule.inputs")
                ),
            )
            for rule in (_mapping(value, f"{path}.rule") for value in _sequence(item["rules"], f"{path}.rules"))
        )
        maximum = item["max_utf8_bytes"]
        if type(maximum) is not int or maximum < 0:
            raise GoInboundPlanError(f"{path}.max_utf8_bytes: invalid")
        result.append(
            GoInboundSourceNormalizerIR(
                _string(item["id"], f"{path}.id"),
                _string(item["kind"], f"{path}.kind"),
                _string(item["trim"], f"{path}.trim"),
                _string(item["case"], f"{path}.case"),
                maximum,
                _string(item["empty"], f"{path}.empty"),
                _string(item["overflow"], f"{path}.overflow", empty=True),
                _string(item["unmatched"], f"{path}.unmatched", empty=True),
                _string(item["pattern"], f"{path}.pattern", empty=True),
                tuple(_string(value, f"{path}.value") for value in _sequence(item["values"], f"{path}.values")),
                tuple(
                    _string(value, f"{path}.separator") for value in _sequence(item["separators"], f"{path}.separators")
                ),
                tuple(_string(value, f"{path}.prefix") for value in _sequence(item["prefixes"], f"{path}.prefixes")),
                rules,
            )
        )
    return tuple(result)


def _source_projection_plans(inbound: Any) -> tuple[GoInboundSourceProjectionPlanIR, ...]:
    result: list[GoInboundSourceProjectionPlanIR] = []
    for position, raw in enumerate(
        _sequence(_read(inbound, "source_projection_plans", "inbound"), "inbound.source_projection_plans")
    ):
        path = f"inbound.source_projection_plans[{position}]"
        item = _mapping(raw, path)
        fields: list[GoInboundProjectionFieldIR] = []
        for field_position, raw_field in enumerate(_sequence(item["field_rules"], f"{path}.field_rules")):
            field_path = f"{path}.field_rules[{field_position}]"
            field = _mapping(raw_field, field_path)
            disposition = _string(field["disposition"], f"{field_path}.disposition")
            if disposition == "omit":
                fields.append(
                    GoInboundProjectionFieldIR(
                        _string(field["target"], f"{field_path}.target"),
                        disposition,
                        "",
                        "",
                        (),
                        (),
                    )
                )
            else:
                fields.append(
                    GoInboundProjectionFieldIR(
                        _string(field["target"], f"{field_path}.target"),
                        disposition,
                        _string(field["requirement"], f"{field_path}.requirement"),
                        _string(field["normalization"], f"{field_path}.normalization"),
                        tuple(
                            _string(value, f"{field_path}.allowed_values")
                            for value in _sequence(field["allowed_values"], f"{field_path}.allowed_values")
                        ),
                        _source_groups(field["source_groups"], f"{field_path}.source_groups"),
                    )
                )
        cumulative = None
        raw_cumulative = item["cumulative_series"]
        if raw_cumulative is not None:
            cumulative_item = _mapping(raw_cumulative, f"{path}.cumulative_series")
            components = tuple(
                GoInboundSeriesComponentIR(
                    _string(component["id"], f"{path}.component.id"),
                    _string(component["requirement"], f"{path}.component.requirement"),
                    _string(component["normalization"], f"{path}.component.normalization"),
                    tuple(
                        _string(value, f"{path}.component.allowed_values")
                        for value in _sequence(component["allowed_values"], f"{path}.component.allowed_values")
                    ),
                    _source_groups(component["source_groups"], f"{path}.component.source_groups"),
                )
                for component in (
                    _mapping(value, f"{path}.component")
                    for value in _sequence(cumulative_item["components"], f"{path}.components")
                )
            )
            reset = _mapping(cumulative_item["reset_epoch"], f"{path}.reset_epoch")
            identity = reset["identity"]
            if type(identity) is not bool:
                raise GoInboundPlanError(f"{path}.reset_epoch.identity: invalid")
            cumulative = GoInboundCumulativeSeriesIR(
                _string(cumulative_item["applicability"], f"{path}.applicability"),
                _string(cumulative_item["framing"], f"{path}.framing"),
                _string(cumulative_item["normalization_stage"], f"{path}.normalization_stage"),
                components,
                GoInboundResetEpochIR(
                    _string(reset["role"], f"{path}.reset_epoch.role"),
                    identity,
                    _string(reset["placement"], f"{path}.reset_epoch.placement"),
                    _string(reset["key"], f"{path}.reset_epoch.key"),
                    _string(reset["normalization"], f"{path}.reset_epoch.normalization"),
                ),
            )
        result.append(
            GoInboundSourceProjectionPlanIR(
                _string(item["id"], f"{path}.id"),
                _string(item["target_family"], f"{path}.target_family"),
                tuple(fields),
                cumulative,
            )
        )
    return tuple(result)


def _digest_payload(value: Any) -> Any:
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {field.name: _digest_payload(getattr(value, field.name)) for field in dataclasses.fields(value)}
    if isinstance(value, Mapping):
        return {key: _digest_payload(value[key]) for key in sorted(value)}
    if isinstance(value, tuple):
        return [_digest_payload(item) for item in value]
    if value is None or type(value) in {bool, int, float, str}:
        return value
    raise GoInboundPlanError("inbound plan digest contains unsupported data")


def _native_predicate(
    location: str,
    key: str,
    operator: str,
    values: tuple[Any, ...],
    value_type: str,
) -> GoInboundPredicateIR:
    return GoInboundPredicateIR(location, key, operator, _json(values), value_type)


def _native_unit_rule(unit: str) -> GoInboundUnitRuleIR:
    return GoInboundUnitRuleIR(
        "target-unit-equality-v1",
        unit,
        (GoInboundUnitScaleIR(unit, 1.0),),
    )


def _native_match_for_target(
    target: GoInboundTargetIR,
    *,
    scope_name: str,
    scope_schema_url: str,
    resource_schema_url: str,
    semantic_instance_key: str,
    forward_instance_key: str,
    forward_destination_key: str,
    forward_hop_count_key: str,
    record_id_key: str,
    max_forward_hops: int,
) -> GoInboundMatchIR:
    family = target.family
    target_id = f"{target.match_id}.{family}"
    present = lambda location, key, value_type="string": _native_predicate(  # noqa: E731
        location, key, "present", (), value_type
    )
    if target.signal == "logs":
        predicates = (
            present("resource_attribute", semantic_instance_key),
            present("leaf_attribute", record_id_key),
            _native_predicate("leaf_attribute", "defenseclaw.bucket", "equals", (target.bucket,), "string"),
            _native_predicate("leaf_attribute", "defenseclaw.signal", "equals", ("logs",), "string"),
            _native_predicate("leaf_attribute", "defenseclaw.event.name", "equals", (target.event_name,), "string"),
            present("leaf_attribute", forward_instance_key),
            present("leaf_attribute", forward_destination_key),
            _native_predicate("leaf_attribute", forward_hop_count_key, "uint32_max", (max_forward_hops,), "int64"),
            _native_predicate("log_body", "$body", "projected_record_json", (), "string"),
        )
        discriminator = "native-v8-log"
        strategy = "native-projected-log-v1"
        time_rule = _json("log-time-observed-receipt-v1")
        outcome_rule = _json("projected-record-v1")
        unit_rule = GoInboundUnitRuleIR("none", "", ())
    elif target.signal == "traces":
        predicates = (
            _native_predicate(
                "resource_schema_url", "$resource_schema_url", "equals", (resource_schema_url,), "string"
            ),
            present("resource_attribute", semantic_instance_key),
            _native_predicate("scope_name", "$scope_name", "equals", (scope_name,), "string"),
            _native_predicate("scope_schema_url", "$scope_schema_url", "equals", (scope_schema_url,), "string"),
            _native_predicate("leaf_attribute", "defenseclaw.bucket", "equals", (target.bucket,), "string"),
            _native_predicate("leaf_attribute", "defenseclaw.span.family", "equals", (family,), "string"),
            _native_predicate(
                "leaf_attribute",
                "defenseclaw.span.family_schema_version",
                "equals",
                (target.family_schema_version,),
                "int64",
            ),
            present("leaf_attribute", forward_instance_key),
            present("leaf_attribute", forward_destination_key),
            _native_predicate("leaf_attribute", forward_hop_count_key, "uint32_max", (max_forward_hops,), "int64"),
        )
        discriminator = "native-v8-span"
        strategy = "generated-reverse-span-v1"
        time_rule = _json("span-end-v1")
        outcome_rule = _json("native-span-v1")
        unit_rule = GoInboundUnitRuleIR("none", "", ())
    elif target.signal == "metrics":
        point_shape = {
            "counter": "sum_delta_monotonic",
            "gauge": "gauge",
            "updowncounter": "sum_delta",
        }.get(target.instrument_type)
        if point_shape is None:
            raise GoInboundPlanError("native metric expansion selected a non-reversible instrument")
        predicates = (
            _native_predicate(
                "resource_schema_url", "$resource_schema_url", "equals", (resource_schema_url,), "string"
            ),
            present("resource_attribute", semantic_instance_key),
            present("resource_attribute", forward_instance_key),
            present("resource_attribute", forward_destination_key),
            _native_predicate("resource_attribute", forward_hop_count_key, "uint32_max", (max_forward_hops,), "int64"),
            _native_predicate("scope_name", "$scope_name", "equals", (scope_name,), "string"),
            _native_predicate("scope_schema_url", "$scope_schema_url", "equals", (scope_schema_url,), "string"),
            _native_predicate("instrument_name", "$instrument_name", "equals", (target.instrument_name,), "string"),
            _native_predicate("metric_point", "$point_shape", "one_of", (point_shape,), "string"),
        )
        discriminator = "native-v8-metric"
        strategy = "generated-reverse-metric-v1"
        time_rule = _json("metric-point-receipt-v1")
        outcome_rule = _json("forbidden")
        unit_rule = _native_unit_rule(target.instrument_unit)
    else:  # pragma: no cover - guarded by the compiler-owned class table
        raise GoInboundPlanError("native expansion has an unknown signal")
    return GoInboundMatchIR(
        target.match_id,
        target.class_id,
        target.signal,
        ("any_authenticated",),
        "native_exact",
        discriminator,
        predicates,
        strategy,
        (),
        "",
        None,
        unit_rule,
        (target_id,),
        time_rule,
        outcome_rule,
        True,
    )


def _compact_native_expansions(
    matches: tuple[GoInboundMatchIR, ...],
    targets: tuple[GoInboundTargetIR, ...],
    descriptors_by_family: Mapping[str, Any],
    *,
    scope_name: str,
    scope_schema_url: str,
    resource_schema_url: str,
    semantic_instance_key: str,
    forward_instance_key: str,
    forward_destination_key: str,
    forward_hop_count_key: str,
    record_id_key: str,
    max_forward_hops: int,
) -> tuple[
    tuple[GoInboundNativeExpansionIR, ...],
    tuple[GoInboundMatchIR, ...],
    tuple[GoInboundTargetIR, ...],
]:
    """Prove native rows are an exact family-catalog expansion, then omit them."""

    native_classes = {class_id for class_id, _, _ in _NATIVE_EXPANSION_CLASSES}
    nonnative_matches = tuple(item for item in matches if item.class_id not in native_classes)
    nonnative_targets = tuple(item for item in targets if item.class_id not in native_classes)
    if any(item.native_round_trip for item in nonnative_matches):
        raise GoInboundPlanError("non-native match claims native round-trip authority")
    if (
        tuple(matches[: len(nonnative_matches)]) != nonnative_matches
        or tuple(targets[: len(nonnative_targets)]) != nonnative_targets
    ):
        raise GoInboundPlanError("native expansion rows must be one ordered suffix")

    match_by_id = {item.id: item for item in matches}
    target_by_match: dict[str, list[GoInboundTargetIR]] = {}
    for target in targets:
        target_by_match.setdefault(target.match_id, []).append(target)
    if len(match_by_id) != len(matches):
        raise GoInboundPlanError("inbound native expansion has duplicate match IDs")

    expansions: list[GoInboundNativeExpansionIR] = []
    observed_native_matches: list[GoInboundMatchIR] = []
    observed_native_targets: list[GoInboundTargetIR] = []
    for class_id, wire_signal, descriptor_signal in _NATIVE_EXPANSION_CLASSES:
        eligible: list[str] = []
        for family_id, descriptor in descriptors_by_family.items():
            if _read(descriptor, "signal", "GoDescriptorPlanIR") != descriptor_signal:
                continue
            if descriptor_signal == "metric":
                metric = _read(
                    _read(descriptor, "catalog_contract", "GoDescriptorPlanIR"),
                    "metric",
                    "GoCatalogContractPlanIR",
                )
                if metric is None or _read(metric, "instrument_type", "GoMetricFamilyContractPlanIR") not in {
                    "counter",
                    "gauge",
                    "updowncounter",
                }:
                    continue
            eligible.append(family_id)
        eligible.sort()
        expansions.append(GoInboundNativeExpansionIR(class_id, wire_signal, tuple(eligible)))
        for family_id in eligible:
            match_id = f"{class_id}.{family_id}"
            match = match_by_id.get(match_id)
            linked = target_by_match.get(match_id, [])
            if match is None or len(linked) != 1:
                raise GoInboundPlanError("native expansion does not map one match to one target")
            target = linked[0]
            descriptor = descriptors_by_family[family_id]
            catalog = _read(descriptor, "catalog_contract", "GoDescriptorPlanIR")
            metric = _read(catalog, "metric", "GoCatalogContractPlanIR")
            field_descriptor_ids = tuple(_read(descriptor, "enriched_field_descriptor_ids", "GoDescriptorPlanIR"))
            field_refs = tuple(item.split(":", 2)[2] for item in field_descriptor_ids)
            instrument_type = "" if metric is None else _read(metric, "instrument_type", "metric contract")
            instrument_unit = "" if metric is None else _read(metric, "unit", "metric contract")
            expected_target = GoInboundTargetIR(
                f"{match_id}.{family_id}",
                match_id,
                class_id,
                wire_signal,
                "import",
                "primary",
                family_id,
                _read(descriptor, "identity_bucket", "GoDescriptorPlanIR"),
                _read(descriptor, "identity_name", "GoDescriptorPlanIR"),
                _read(descriptor, "family_schema_version", "GoDescriptorPlanIR"),
                "" if metric is None else _read(descriptor, "identity_name", "GoDescriptorPlanIR"),
                instrument_type,
                instrument_unit,
                field_refs,
                field_descriptor_ids,
                _read(catalog, "descriptor_type_symbol", "GoCatalogContractPlanIR"),
                {
                    "logs": "native-projected-log-v1",
                    "traces": "generated-reverse-span-v1",
                    "metrics": "generated-reverse-metric-v1",
                }[wire_signal],
                "",
                _json(
                    {
                        "logs": "log-time-observed-receipt-v1",
                        "traces": "span-end-v1",
                        "metrics": "metric-point-receipt-v1",
                    }[wire_signal]
                ),
                _json(
                    {
                        "logs": "projected-record-v1",
                        "traces": "native-span-v1",
                        "metrics": "forbidden",
                    }[wire_signal]
                ),
                f"otlp.import.{family_id}" if wire_signal == "logs" else "",
                _native_unit_rule(instrument_unit) if wire_signal == "metrics" else GoInboundUnitRuleIR("none", "", ()),
                "",
            )
            if target != expected_target:
                raise GoInboundPlanError(f"native target expansion drift for {family_id}")
            expected_match = _native_match_for_target(
                target,
                scope_name=scope_name,
                scope_schema_url=scope_schema_url,
                resource_schema_url=resource_schema_url,
                semantic_instance_key=semantic_instance_key,
                forward_instance_key=forward_instance_key,
                forward_destination_key=forward_destination_key,
                forward_hop_count_key=forward_hop_count_key,
                record_id_key=record_id_key,
                max_forward_hops=max_forward_hops,
            )
            if match != expected_match:
                raise GoInboundPlanError(f"native match expansion drift for {family_id}")
            observed_native_matches.append(match)
            observed_native_targets.append(target)

    actual_match_ids = tuple(item.id for item in matches[len(nonnative_matches) :])
    expected_match_ids = tuple(item.id for item in observed_native_matches)
    actual_target_ids = tuple(item.id for item in targets[len(nonnative_targets) :])
    expected_target_ids = tuple(sorted(item.id for item in observed_native_targets))
    if actual_match_ids != expected_match_ids or actual_target_ids != expected_target_ids:
        mismatch = next(
            (
                (actual, expected)
                for actual, expected in zip(actual_match_ids, expected_match_ids, strict=False)
                if actual != expected
            ),
            None,
        ) or next(
            (
                (actual, expected)
                for actual, expected in zip(actual_target_ids, expected_target_ids, strict=False)
                if actual != expected
            ),
            (str(len(actual_match_ids)), str(len(expected_match_ids))),
        )
        raise GoInboundPlanError(
            f"native expansion coverage or order differs from the family catalog: {mismatch[0]} != {mismatch[1]}"
        )
    return tuple(expansions), nonnative_matches, nonnative_targets


def compile_go_inbound_plan(index: Any) -> GoInboundPlanIR:
    """Return immutable private Go descriptors from one digest-valid candidate."""

    if type(index).__name__ not in {"CandidateRenderIndex", "_ProvisionalCandidateEnrichment"}:
        raise GoInboundPlanError("inbound plan requires compiler-owned candidate facts")
    materialized = _string(_read(index, "materialized_view_sha256", "CandidateRenderIndex"), "materialized digest")
    if _SHA256.fullmatch(materialized) is None:
        raise GoInboundPlanError("materialized digest is invalid")
    candidate = getattr(index, "candidate_render_index_sha256", None)
    if candidate is None:
        candidate = "0" * 64
    candidate = _string(candidate, "candidate digest")
    if _SHA256.fullmatch(candidate) is None:
        raise GoInboundPlanError("candidate digest is invalid")
    inbound = _read(index, "inbound_otlp", "CandidateRenderIndex")
    api_plan = _read(index, "go_api_plan", "CandidateRenderIndex")
    descriptors_by_family: dict[str, Any] = {}
    for descriptor in _sequence(_read(api_plan, "descriptors", "GoAPIPlanIR"), "GoAPIPlanIR.descriptors"):
        family_id = _string(_read(descriptor, "family_id", "GoDescriptorPlanIR"), "descriptor family ID")
        if family_id in descriptors_by_family:
            raise GoInboundPlanError("generated family descriptor is duplicated")
        descriptors_by_family[family_id] = descriptor

    aliases: list[GoInboundAliasIR] = []
    for position, raw in enumerate(_sequence(_read(inbound, "alias_sets", "inbound"), "inbound.alias_sets")):
        item = _mapping(raw, f"inbound.alias_sets[{position}]")
        contract = _mapping(item["target_field_contract"], "inbound alias field contract")
        aliases.append(
            GoInboundAliasIR(
                _string(item["id"], "alias id"),
                _string(item["target"], "alias target"),
                _string(item["value_type"], "alias value type"),
                _string(item["normalization"], "alias normalization"),
                tuple(_string(source, "alias source") for source in _sequence(item["sources"], "alias sources")),
                _string(item["conflict_policy"], "alias conflict policy"),
                _string(item["absence_policy"], "alias absence policy"),
                _string(contract["field_class"], "alias field class"),
                _string(contract["sensitivity"], "alias sensitivity"),
            )
        )

    source_normalizers = _source_normalizers(inbound)
    source_projection_plans = _source_projection_plans(inbound)

    matches: list[GoInboundMatchIR] = []
    for position, raw in enumerate(_sequence(_read(inbound, "match_descriptors", "inbound"), "inbound.matches")):
        item = _mapping(raw, f"inbound.matches[{position}]")
        discriminator = _mapping(item["discriminator"], "match discriminator")
        predicates = tuple(
            GoInboundPredicateIR(
                _string(predicate["location"], "predicate location"),
                _string(predicate["key"], "predicate key"),
                _string(predicate["operator"], "predicate operator"),
                _json(predicate["values"]),
                _string(predicate["value_type"], "predicate value type"),
            )
            for predicate in (
                _mapping(value, "predicate") for value in _sequence(discriminator["predicates"], "predicates")
            )
        )
        mapping = _mapping(item["mapping"], "match mapping")
        raw_override = mapping["target_override"]
        target_override = None
        if raw_override is not None:
            override = _mapping(raw_override, "match target override")
            target_override = GoInboundTargetOverrideIR(
                _string(override["source"], "target override source"),
                _string(override["target"], "target override target"),
                _string(override["normalization"], "target override normalization"),
            )
        aliases_for_match = tuple(
            _string(_mapping(alias, "match alias")["id"], "match alias id")
            for alias in _sequence(mapping["alias_sets"], "match aliases")
        )
        raw_projection = mapping["source_projection_plan"]
        projection_id = ""
        if raw_projection is not None:
            projection_id = _string(_mapping(raw_projection, "match source projection")["id"], "projection ID")
        matches.append(
            GoInboundMatchIR(
                _string(item["id"], "match id"),
                _string(item["class_id"], "match class id"),
                _string(item["signal"], "match signal"),
                tuple(_string(source, "match source") for source in _sequence(item["sources"], "match sources")),
                _string(item["shape"], "match shape"),
                _string(discriminator["kind"], "discriminator kind"),
                predicates,
                _string(mapping["strategy"], "mapping strategy"),
                aliases_for_match,
                projection_id,
                target_override,
                _unit_rule(mapping["source_unit_rule"], "match source-unit rule"),
                tuple(_string(value, "target id") for value in _sequence(item["target_ids"], "target ids")),
                _json(item["time_rule"]),
                _json(item["outcome_rule"]),
                item["native_round_trip"] is True,
            )
        )

    targets: list[GoInboundTargetIR] = []
    for position, raw in enumerate(_sequence(_read(inbound, "target_descriptors", "inbound"), "inbound.targets")):
        item = _mapping(raw, f"inbound.targets[{position}]")
        field_refs = tuple(_string(value, "field ref") for value in _sequence(item["field_refs"], "field refs"))
        field_descriptor_ids = tuple(
            _string(value, "field descriptor ID")
            for value in _sequence(item["field_descriptor_ids"], "field descriptor IDs")
        )
        if len(field_refs) != len(field_descriptor_ids):
            raise GoInboundPlanError("target field refs and descriptor IDs disagree")
        version = item["family_schema_version"]
        if type(version) is not int or version < 1:
            raise GoInboundPlanError("target family schema version is invalid")
        family_id = _string(item["family"], "target family")
        descriptor = descriptors_by_family.get(family_id)
        if descriptor is None:
            raise GoInboundPlanError("target generated family descriptor is missing")
        signal = {"logs": "log", "traces": "span", "metrics": "metric"}.get(item["signal"])
        catalog = _read(descriptor, "catalog_contract", "GoDescriptorPlanIR")
        descriptor_symbol = _string(
            _read(catalog, "descriptor_type_symbol", "GoCatalogContractPlanIR"),
            "generated descriptor symbol",
        )
        metric_catalog = _read(catalog, "metric", "GoCatalogContractPlanIR")
        expected_unit = _read(metric_catalog, "unit", "GoMetricFamilyContractPlanIR") if signal == "metric" else ""
        if (
            signal is None
            or _read(descriptor, "signal", "GoDescriptorPlanIR") != signal
            or _read(descriptor, "identity_bucket", "GoDescriptorPlanIR") != item["bucket"]
            or _read(descriptor, "identity_name", "GoDescriptorPlanIR") != item["event_name"]
            or (signal == "metric" and item["instrument_name"] != item["event_name"])
            or (signal != "metric" and item["instrument_name"] is not None)
            or (item["instrument_unit"] or "") != expected_unit
            or _read(descriptor, "family_schema_version", "GoDescriptorPlanIR") != version
            or tuple(_read(descriptor, "enriched_field_descriptor_ids", "GoDescriptorPlanIR")) != field_descriptor_ids
        ):
            raise GoInboundPlanError("target disagrees with generated family descriptor")
        targets.append(
            GoInboundTargetIR(
                _string(item["id"], "target id"),
                _string(item["match_id"], "target match id"),
                _string(item["class_id"], "target class id"),
                _string(item["signal"], "target signal"),
                _string(item["role"], "target role"),
                _string(item["target_kind"], "target kind"),
                family_id,
                _string(item["bucket"], "target bucket"),
                _string(item["event_name"], "target event name"),
                version,
                _string(item["instrument_name"] or "", "target instrument", empty=True),
                _string(item["instrument_type"] or "", "target instrument type", empty=True),
                _string(item["instrument_unit"] or "", "target instrument unit", empty=True),
                field_refs,
                field_descriptor_ids,
                descriptor_symbol,
                _string(item["mapping_strategy"], "target mapping strategy"),
                _string(item["derivation_strategy"] or "", "derivation strategy", empty=True),
                _json(item["time_rule"]),
                _json(item["outcome_rule"]),
                _string(item["import_context_id"] or "", "import context id", empty=True),
                _unit_rule(item["source_unit_rule"], "target source-unit rule"),
                (
                    ""
                    if item["source_projection_plan"] is None
                    else _string(
                        _mapping(item["source_projection_plan"], "target source projection")["id"],
                        "target source projection ID",
                    )
                ),
            )
        )

    native_markers = tuple(
        GoInboundNativeMarkerIR(
            _string(item["id"], "native marker id"),
            _string(item["signal"], "native marker signal"),
            _string(item["location"], "native marker location"),
            _string(item["key"], "native marker key"),
            _string(item["marker_kind"], "native marker kind"),
            _json(item["values"]),
            _string(item["value_type"], "native marker value type"),
        )
        for item in (
            _mapping(value, "native marker")
            for value in _sequence(_read(inbound, "native_markers", "inbound"), "inbound native markers")
        )
    )
    echoes = tuple(
        GoInboundEchoRecognizerIR(
            _string(item["id"], "echo id"),
            _string(item["signal"], "echo signal"),
            _string(item["family"], "echo family"),
            _string(item["bucket"], "echo bucket"),
            _string(item["event_name"], "echo event name"),
            _string(item["instrument_name"] or "", "echo instrument", empty=True),
            _string(item["forward_placement"], "echo forward placement"),
            _string(item["compare_self_with"], "echo self key"),
        )
        for item in (
            _mapping(value, "echo recognizer")
            for value in _sequence(_read(inbound, "echo_recognizers", "inbound"), "inbound echoes")
        )
    )
    context_rows: list[GoInboundImportContextIR] = []
    for value in _sequence(_read(inbound, "import_contexts", "inbound"), "inbound contexts"):
        item = _mapping(value, "import context")
        family_id = _string(item["family_descriptor_id"], "context family")
        descriptor = descriptors_by_family.get(family_id)
        if (
            descriptor is None
            or _read(descriptor, "signal", "GoDescriptorPlanIR") != "log"
            or _read(descriptor, "identity_bucket", "GoDescriptorPlanIR") != item["bucket"]
            or _read(descriptor, "identity_name", "GoDescriptorPlanIR") != item["event_name"]
        ):
            raise GoInboundPlanError("import context disagrees with generated log descriptor")
        catalog = _read(descriptor, "catalog_contract", "GoDescriptorPlanIR")
        context_rows.append(
            GoInboundImportContextIR(
                _string(item["id"], "context id"),
                family_id,
                _string(item["bucket"], "context bucket"),
                _string(item["event_name"], "context event"),
                _string(item["construction_mode"], "context mode"),
                tuple(
                    _string(capability, "context capability")
                    for capability in _sequence(item["capabilities"], "capabilities")
                ),
                _string(
                    _read(catalog, "descriptor_type_symbol", "GoCatalogContractPlanIR"),
                    "context descriptor symbol",
                ),
            )
        )
    contexts = tuple(context_rows)
    projection_ids = tuple(
        [f"inbound:alias:{item.id}" for item in aliases]
        + [f"inbound:normalizer:{item.id}" for item in source_normalizers]
        + [f"inbound:source-projection:{item.id}" for item in source_projection_plans]
        + [f"inbound:match:{item.id}" for item in matches]
        + [f"inbound:target:{item.id}" for item in targets]
        + [f"inbound:marker:{item.id}" for item in native_markers]
        + [f"inbound:echo:{item.id}" for item in echoes]
        + [f"inbound:context:{item.id}" for item in contexts]
    )
    if len(projection_ids) != len(set(projection_ids)):
        raise GoInboundPlanError("inbound projection IDs are duplicated")
    shape_policy = _mapping(_read(inbound, "shape_policy", "inbound"), "inbound shape policy")
    scope_name = _string(_read(inbound, "scope_name", "inbound"), "scope name")
    scope_schema_url = _string(_read(inbound, "scope_schema_url", "inbound"), "scope schema URL")
    resource_schema_url = _string(_read(inbound, "resource_schema_url", "inbound"), "resource schema URL")
    semantic_instance_key = _string(
        _read(inbound, "semantic_resource_instance_key", "inbound"), "semantic instance key"
    )
    forward_instance_key = _string(_read(inbound, "forward_instance_key", "inbound"), "forward instance key")
    forward_destination_key = _string(_read(inbound, "forward_destination_key", "inbound"), "forward destination key")
    forward_hop_count_key = _string(_read(inbound, "forward_hop_count_key", "inbound"), "forward hop key")
    record_id_key = _string(_read(inbound, "record_id_key", "inbound"), "record id key")
    max_forward_hops = _read(inbound, "max_forward_hops", "inbound")
    if type(max_forward_hops) is not int or max_forward_hops < 1 or max_forward_hops > 0xFFFFFFFF:
        raise GoInboundPlanError("maximum forward hops is invalid")
    native_expansions, compact_matches, compact_targets = _compact_native_expansions(
        tuple(matches),
        tuple(targets),
        descriptors_by_family,
        scope_name=scope_name,
        scope_schema_url=scope_schema_url,
        resource_schema_url=resource_schema_url,
        semantic_instance_key=semantic_instance_key,
        forward_instance_key=forward_instance_key,
        forward_destination_key=forward_destination_key,
        forward_hop_count_key=forward_hop_count_key,
        record_id_key=record_id_key,
        max_forward_hops=max_forward_hops,
    )
    plan_without_digest = GoInboundPlanIR(
        2,
        materialized,
        candidate,
        scope_name,
        scope_schema_url,
        resource_schema_url,
        semantic_instance_key,
        forward_instance_key,
        forward_destination_key,
        forward_hop_count_key,
        record_id_key,
        max_forward_hops,
        _string(_read(inbound, "unknown_fields", "inbound"), "unknown field policy"),
        _string(shape_policy["native_marker_rule"], "native marker rule"),
        _string(shape_policy["structural_marker_rule"], "structural marker rule"),
        _string(shape_policy["native_malformed_disposition"], "native malformed disposition"),
        _string(shape_policy["native_malformed_external_fallback"], "native fallback policy"),
        tuple(aliases),
        source_normalizers,
        source_projection_plans,
        native_expansions,
        compact_matches,
        compact_targets,
        native_markers,
        echoes,
        contexts,
        projection_ids,
        "",
    )
    payload = _digest_payload(plan_without_digest)
    payload["inbound_plan_sha256"] = ""
    digest = hashlib.sha256(
        _DIGEST_DOMAIN + json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return dataclasses.replace(plan_without_digest, inbound_plan_sha256=digest)


__all__ = [
    "GoInboundNativeExpansionIR",
    "GoInboundPlanError",
    "GoInboundPlanIR",
    "compile_go_inbound_plan",
]
