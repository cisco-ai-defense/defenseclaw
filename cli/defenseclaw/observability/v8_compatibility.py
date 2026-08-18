# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""Strict typed contract for generated v7 exporter compatibility data.

The telemetry registry compiler owns the artifact.  This module only validates
and freezes its generated output so migration code can ask exact questions
without embedding a second family list or falling back to all catalog buckets.
It deliberately accepts no credentials, endpoints, content, or arbitrary
metadata, and diagnostics never render source values or unknown keys.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Final, TypeAlias

from defenseclaw.observability.schema_resources import (
    telemetry_v8_catalog_bytes,
    v7_exporter_selection_bytes,
)
from defenseclaw.observability.v8_config import BUCKETS, SIGNALS

SCHEMA_VERSION: Final = 1
SOURCE_CONFIG_VERSION: Final = 7
PROJECTION_PROFILE: Final = "legacy-v7"
LOCAL_OBSERVABILITY_PROFILE: Final = "local-observability-v1"

COLLECTION_CONDITIONS: Final = ("always", "otel.logs", "otel.traces", "otel.metrics")
EXPORTER_SIGNALS: Final = {
    "gateway_jsonl": ("logs",),
    "gateway_console": ("logs",),
    "audit_sink": ("logs",),
    "generic_otlp": SIGNALS,
    "galileo": ("traces",),
    "local_observability": SIGNALS,
}
FEATURE_NAMES: Final = ("otel_individual_findings",)
SELECTOR_FIELDS: Final = ("buckets", "sources", "actions", "event_names")

MAX_REGISTRY_SCHEMA_VERSION: Final = 2_147_483_647
MAX_ROUTES_PER_DESTINATION: Final = 256
MAX_SELECTORS_PER_SIGNAL: Final = MAX_ROUTES_PER_DESTINATION
MAX_SELECTOR_VALUES: Final = 512
MAX_SPAN_FILTER_OPERATIONS: Final = 256
MAX_REQUIRED_ATTRIBUTES: Final = 128
MAX_TOKEN_BYTES: Final = 128
MAX_ARTIFACT_BYTES: Final = 128 * 1024
MAX_CATALOG_BYTES: Final = 4 * 1024 * 1024

_TOKEN: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
_SHA256: Final = re.compile(r"^[0-9a-f]{64}$")
_GENERATED_FIELDS: Final = frozenset(
    {"artifact", "authority", "generator", "materialized_view_sha256", "registry_version"}
)
_TOP_LEVEL_FIELDS: Final = frozenset(
    {
        "x-defenseclaw-generated",
        "schema_version",
        "source_config_version",
        "registry_schema_version",
        "projection_profile",
        "collection",
        "exporters",
        "features",
        "span_filter_operations",
        "local_observability",
    }
)

SignalBuckets: TypeAlias = tuple[tuple[str, tuple[str, ...]], ...]
ConditionCollection: TypeAlias = tuple[tuple[str, SignalBuckets], ...]
SignalSelectors: TypeAlias = tuple[tuple[str, tuple["V7Selector", ...]], ...]
ExporterProfiles: TypeAlias = tuple[tuple[str, SignalSelectors], ...]
FeatureProfiles: TypeAlias = tuple[tuple[str, tuple["V7Selector", ...]], ...]


class V7CompatibilityError(ValueError):
    """Value-safe generated-artifact validation or query error."""

    def __init__(self, code: str, path: str, action: str) -> None:
        self.code = code
        self.path = path
        self.action = action
        super().__init__(f"v7 compatibility artifact: {path} ({code}); {action}")

    def __repr__(self) -> str:
        return f"V7CompatibilityError(code={self.code!r}, path={self.path!r})"


@dataclass(frozen=True, slots=True)
class V7Selector:
    """One closed, canonical selector used by a generated compatibility path."""

    buckets: tuple[str, ...] = ()
    sources: tuple[str, ...] = ()
    actions: tuple[str, ...] = ()
    event_names: tuple[str, ...] = ()

    def __repr__(self) -> str:
        return (
            "V7Selector("
            f"buckets={len(self.buckets)}, sources={len(self.sources)}, "
            f"actions={len(self.actions)}, event_names={len(self.event_names)})"
        )

    def as_mapping(self) -> Mapping[str, tuple[str, ...]]:
        """Return a detached immutable mapping containing only selected fields."""

        result = {name: getattr(self, name) for name in SELECTOR_FIELDS if getattr(self, name)}
        return MappingProxyType(result)

    @property
    def sort_key(self) -> tuple[tuple[str, ...], ...]:
        return (self.buckets, self.sources, self.actions, self.event_names)


@dataclass(frozen=True, slots=True)
class V7SpanFilterOperation:
    """Exact representable legacy operation predicate and its selected families."""

    name: str
    required_attributes: tuple[str, ...]
    selectors: tuple[V7Selector, ...]

    def __repr__(self) -> str:
        return (
            "V7SpanFilterOperation("
            f"required_attributes={len(self.required_attributes)}, selectors={len(self.selectors)})"
        )


@dataclass(frozen=True, slots=True)
class V7LocalObservabilityProfile:
    """Completeness proof for the generated local dashboard compatibility view."""

    profile_id: str
    complete: bool

    def __repr__(self) -> str:
        return f"V7LocalObservabilityProfile(complete={self.complete!r})"


@dataclass(frozen=True, slots=True)
class V7CompatibilitySelection:
    """Immutable, secret-free v7 collection and exporter compatibility plan."""

    schema_version: int
    source_config_version: int
    registry_schema_version: int
    projection_profile: str
    local_observability: V7LocalObservabilityProfile
    _collection: ConditionCollection = field(repr=False)
    _exporters: ExporterProfiles = field(repr=False)
    _features: FeatureProfiles = field(repr=False)
    _span_filter_operations: tuple[tuple[str, V7SpanFilterOperation], ...] = field(repr=False)

    @classmethod
    def from_mapping(cls, source: Mapping[str, Any]) -> V7CompatibilitySelection:
        """Validate and detach one generated artifact mapping."""

        root = _require_mapping(source, "$")
        _require_exact_fields(root, _TOP_LEVEL_FIELDS, "$")
        _parse_generated_marker(
            root["x-defenseclaw-generated"],
            artifact="compatibility/v7-exporter-selection.json",
        )
        _require_exact_integer(root["schema_version"], SCHEMA_VERSION, "$.schema_version")
        _require_exact_integer(root["source_config_version"], SOURCE_CONFIG_VERSION, "$.source_config_version")
        registry_schema_version = _require_positive_integer(
            root["registry_schema_version"], "$.registry_schema_version"
        )
        if root["projection_profile"] != PROJECTION_PROFILE:
            raise _error(
                "invalid_projection_profile",
                "$.projection_profile",
                "regenerate the artifact with the required migration projection profile",
            )

        collection = _parse_collection(root["collection"])
        exporters = _parse_exporters(root["exporters"])
        features = _parse_features(root["features"])
        generic_route_count = sum(len(selectors) for _, selectors in _lookup(exporters, "generic_otlp"))
        feature_route_count = sum(len(selectors) for _, selectors in features)
        if generic_route_count + feature_route_count > MAX_ROUTES_PER_DESTINATION:
            raise _error(
                "invalid_feature_route_count",
                "$.features",
                "regenerate generic OTel and feature selectors within the destination route limit",
            )
        operations = _parse_span_filter_operations(root["span_filter_operations"])
        local = _parse_local_observability(root["local_observability"])
        return cls(
            schema_version=SCHEMA_VERSION,
            source_config_version=SOURCE_CONFIG_VERSION,
            registry_schema_version=registry_schema_version,
            projection_profile=PROJECTION_PROFILE,
            local_observability=local,
            _collection=collection,
            _exporters=exporters,
            _features=features,
            _span_filter_operations=operations,
        )

    def __repr__(self) -> str:
        selector_count = sum(len(selectors) for _, signals in self._exporters for _, selectors in signals) + sum(
            len(selectors) for _, selectors in self._features
        )
        return (
            "V7CompatibilitySelection("
            f"schema_version={self.schema_version}, "
            f"source_config_version={self.source_config_version}, "
            f"registry_schema_version={self.registry_schema_version}, "
            f"exporters={len(self._exporters)}, selectors={selector_count}, "
            f"span_filter_operations={len(self._span_filter_operations)}, "
            f"local_complete={self.local_observability.complete})"
        )

    @property
    def collection(self) -> Mapping[str, Mapping[str, tuple[str, ...]]]:
        """Return a detached, deeply immutable view of conditional collection."""

        return MappingProxyType({condition: MappingProxyType(dict(signals)) for condition, signals in self._collection})

    @property
    def exporters(self) -> Mapping[str, Mapping[str, tuple[V7Selector, ...]]]:
        """Return a detached, deeply immutable exporter profile view."""

        return MappingProxyType({exporter: MappingProxyType(dict(signals)) for exporter, signals in self._exporters})

    @property
    def features(self) -> Mapping[str, tuple[V7Selector, ...]]:
        """Return a detached immutable feature-selector view."""

        return MappingProxyType(dict(self._features))

    @property
    def span_filter_operations(self) -> Mapping[str, V7SpanFilterOperation]:
        """Return a detached immutable operation-predicate view."""

        return MappingProxyType(dict(self._span_filter_operations))

    def collection_buckets(self, condition: str, signal: str) -> tuple[str, ...]:
        """Return exact buckets for one generated condition and signal."""

        _require_query_name(condition, COLLECTION_CONDITIONS, "$.collection")
        _require_query_name(signal, SIGNALS, "$.collection.signal")
        signals = _lookup(self._collection, condition)
        return _lookup(signals, signal)

    def effective_collection(self, enabled_otel_signals: Sequence[str]) -> Mapping[str, tuple[str, ...]]:
        """Combine ``always`` with explicitly enabled legacy OTel conditions."""

        enabled = _canonical_query_names(enabled_otel_signals, SIGNALS, "$.enabled_otel_signals")
        result: dict[str, tuple[str, ...]] = {}
        for signal in SIGNALS:
            selected = set(self.collection_buckets("always", signal))
            if signal in enabled:
                selected.update(self.collection_buckets(f"otel.{signal}", signal))
            result[signal] = tuple(bucket for bucket in BUCKETS if bucket in selected)
        return MappingProxyType(result)

    def exporter_selectors(self, exporter: str, signal: str) -> tuple[V7Selector, ...]:
        """Return exact selectors for one required exporter path and signal."""

        _require_query_name(exporter, tuple(EXPORTER_SIGNALS), "$.exporters")
        _require_query_name(signal, EXPORTER_SIGNALS[exporter], "$.exporters.signal")
        return _lookup(_lookup(self._exporters, exporter), signal)

    def feature_selectors(self, feature: str) -> tuple[V7Selector, ...]:
        """Return the exact selector tuple for a generated feature gate."""

        _require_query_name(feature, FEATURE_NAMES, "$.features")
        return _lookup(self._features, feature)

    def span_filter_selectors(self, operation: str, required_attributes: Sequence[str]) -> tuple[V7Selector, ...]:
        """Return selectors only for an exact operation/attribute predicate."""

        _require_token(operation, "$.span_filter_operation")
        expected = _lookup_optional(self._span_filter_operations, operation)
        if expected is None:
            raise _error(
                "unmapped_span_filter_operation",
                "$.span_filter_operation",
                "regenerate the artifact with the configured legacy operation",
            )
        attributes = _canonical_query_tokens(required_attributes, "$.span_filter_operation.required_attributes")
        if attributes != expected.required_attributes:
            raise _error(
                "unmapped_span_filter_predicate",
                "$.span_filter_operation.required_attributes",
                "use the exact generated predicate or reject migration as unrepresentable",
            )
        return expected.selectors


def load_v7_compatibility_selection(source: Mapping[str, Any]) -> V7CompatibilitySelection:
    """Convenience entry point used by generated-artifact consumers."""

    return V7CompatibilitySelection.from_mapping(source)


def load_packaged_v7_compatibility_selection() -> V7CompatibilitySelection:
    """Load the checked generated package resource with no checkout fallback."""

    document = _parse_packaged_json(
        v7_exporter_selection_bytes(),
        maximum=MAX_ARTIFACT_BYTES,
        resource="v7 exporter selection",
    )
    catalog = _parse_packaged_json(
        telemetry_v8_catalog_bytes(),
        maximum=MAX_CATALOG_BYTES,
        resource="telemetry catalog",
    )
    selection_marker = _parse_generated_marker(
        document.get("x-defenseclaw-generated"),
        artifact="compatibility/v7-exporter-selection.json",
    )
    catalog_marker = _parse_generated_marker(
        catalog.get("x-defenseclaw-generated"),
        artifact="catalog.json",
    )
    if selection_marker != catalog_marker:
        raise _error(
            "artifact_epoch_mismatch",
            "$.x-defenseclaw-generated",
            "reinstall a package whose generated telemetry resources come from one registry epoch",
        )
    return load_v7_compatibility_selection(document)


def _parse_packaged_json(raw: bytes, *, maximum: int, resource: str) -> Mapping[str, Any]:
    if type(raw) is not bytes or len(raw) > maximum:
        raise _error(
            "invalid_artifact_size",
            "$",
            f"reinstall a package containing the bounded generated {resource}",
        )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise _error(
            "invalid_artifact_encoding",
            "$",
            f"reinstall a package containing a UTF-8 generated {resource}",
        ) from None
    if text.startswith("\ufeff"):
        raise _error(
            "invalid_artifact_encoding",
            "$",
            f"reinstall a package containing a BOM-free generated {resource}",
        )

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise _error(
                    "duplicate_artifact_key",
                    "$",
                    "reinstall a package containing strict generated JSON",
                )
            result[key] = value
        return result

    try:
        document = json.loads(
            text,
            object_pairs_hook=pairs,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
    except V7CompatibilityError:
        raise
    except (ValueError, RecursionError):
        raise _error(
            "invalid_artifact_json",
            "$",
            "reinstall a package containing strict generated JSON",
        ) from None
    if not isinstance(document, Mapping):
        raise _error(
            "invalid_artifact_root",
            "$",
            "reinstall a package containing the generated object artifact",
        )
    return document


def _parse_generated_marker(value: Any, *, artifact: str) -> tuple[str, int]:
    marker = _require_mapping(value, "$.x-defenseclaw-generated")
    _require_exact_fields(marker, _GENERATED_FIELDS, "$.x-defenseclaw-generated")
    expected = {
        "artifact": artifact,
        "authority": "candidate-not-public-authority",
        "generator": "defenseclaw-telemetry-candidate-renderer-v1",
    }
    for name, required in expected.items():
        if marker[name] != required:
            raise _error(
                "invalid_generated_marker",
                f"$.x-defenseclaw-generated.{name}",
                "reinstall the compiler-owned generated compatibility artifact",
            )
    digest = marker["materialized_view_sha256"]
    if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
        raise _error(
            "invalid_generated_marker",
            "$.x-defenseclaw-generated.materialized_view_sha256",
            "reinstall the digest-bound generated compatibility artifact",
        )
    registry_version = _require_positive_integer(
        marker["registry_version"],
        "$.x-defenseclaw-generated.registry_version",
    )
    return digest, registry_version


def _parse_collection(value: Any) -> ConditionCollection:
    source = _require_mapping(value, "$.collection")
    _require_exact_fields(source, frozenset(COLLECTION_CONDITIONS), "$.collection")
    result: list[tuple[str, SignalBuckets]] = []
    for condition in COLLECTION_CONDITIONS:
        signals = _require_mapping(source[condition], "$.collection.condition")
        _require_exact_fields(signals, frozenset(SIGNALS), "$.collection.condition")
        parsed: list[tuple[str, tuple[str, ...]]] = []
        for signal in SIGNALS:
            buckets = _parse_buckets(signals[signal], "$.collection.condition.signal", allow_empty=True)
            if condition.startswith("otel.") and condition != f"otel.{signal}" and buckets:
                raise _error(
                    "invalid_collection_condition",
                    "$.collection.condition.signal",
                    "put conditional buckets only on the signal named by the OTel condition",
                )
            parsed.append((signal, buckets))
        result.append((condition, tuple(parsed)))
    return tuple(result)


def _parse_exporters(value: Any) -> ExporterProfiles:
    source = _require_mapping(value, "$.exporters")
    _require_exact_fields(source, frozenset(EXPORTER_SIGNALS), "$.exporters")
    result: list[tuple[str, SignalSelectors]] = []
    for exporter, expected_signals in EXPORTER_SIGNALS.items():
        signals = _require_mapping(source[exporter], "$.exporters.profile")
        _require_exact_fields(signals, frozenset(expected_signals), "$.exporters.profile")
        parsed = tuple(
            (
                signal,
                _parse_selectors(
                    signals[signal],
                    "$.exporters.profile.signal",
                    require_nonempty=True,
                ),
            )
            for signal in expected_signals
        )
        if sum(len(selectors) for _, selectors in parsed) > MAX_ROUTES_PER_DESTINATION:
            raise _error(
                "invalid_exporter_route_count",
                "$.exporters.profile",
                "regenerate the exporter profile within the destination route limit",
            )
        result.append((exporter, parsed))
    return tuple(result)


def _parse_features(value: Any) -> FeatureProfiles:
    source = _require_mapping(value, "$.features")
    _require_exact_fields(source, frozenset(FEATURE_NAMES), "$.features")
    return tuple(
        (
            name,
            _parse_selectors(source[name], "$.features.selector", require_nonempty=True),
        )
        for name in FEATURE_NAMES
    )


def _parse_span_filter_operations(value: Any) -> tuple[tuple[str, V7SpanFilterOperation], ...]:
    source = _require_mapping(value, "$.span_filter_operations")
    if not source or len(source) > MAX_SPAN_FILTER_OPERATIONS:
        raise _error(
            "invalid_operation_count",
            "$.span_filter_operations",
            "generate between 1 and 256 operation predicates",
        )
    result: list[tuple[str, V7SpanFilterOperation]] = []
    for index, name in enumerate(sorted(source, key=lambda item: str(item))):
        _require_token(name, f"$.span_filter_operations[{index}].name")
        operation = _require_mapping(source[name], f"$.span_filter_operations[{index}]")
        _require_exact_fields(
            operation,
            frozenset({"required_attributes", "selectors"}),
            f"$.span_filter_operations[{index}]",
        )
        required_attributes = _parse_tokens(
            operation["required_attributes"],
            f"$.span_filter_operations[{index}].required_attributes",
            allow_empty=True,
            maximum=MAX_REQUIRED_ATTRIBUTES,
        )
        selectors = _parse_selectors(
            operation["selectors"],
            f"$.span_filter_operations[{index}].selectors",
            require_nonempty=True,
        )
        result.append(
            (
                name,
                V7SpanFilterOperation(
                    name=name,
                    required_attributes=required_attributes,
                    selectors=selectors,
                ),
            )
        )
    return tuple(result)


def _parse_local_observability(value: Any) -> V7LocalObservabilityProfile:
    source = _require_mapping(value, "$.local_observability")
    _require_exact_fields(source, frozenset({"profile_id", "complete"}), "$.local_observability")
    if source["profile_id"] != LOCAL_OBSERVABILITY_PROFILE:
        raise _error(
            "invalid_local_profile",
            "$.local_observability.profile_id",
            "regenerate the required local-observability compatibility profile",
        )
    if source["complete"] is not True:
        raise _error(
            "incomplete_local_profile",
            "$.local_observability.complete",
            "regenerate complete local dashboard compatibility coverage",
        )
    return V7LocalObservabilityProfile(LOCAL_OBSERVABILITY_PROFILE, True)


def _parse_selectors(value: Any, path: str, *, require_nonempty: bool) -> tuple[V7Selector, ...]:
    source = _require_sequence(value, path)
    if (require_nonempty and not source) or len(source) > MAX_SELECTORS_PER_SIGNAL:
        raise _error(
            "invalid_selector_count",
            path,
            "generate a bounded nonempty selector sequence",
        )
    result: list[V7Selector] = []
    seen: set[V7Selector] = set()
    for index, raw in enumerate(source):
        selector = _parse_selector(raw, f"{path}[{index}]")
        if selector in seen:
            raise _error(
                "duplicate_selector",
                f"{path}[{index}]",
                "remove semantically duplicate generated selectors",
            )
        seen.add(selector)
        result.append(selector)
    return tuple(sorted(result, key=lambda selector: selector.sort_key))


def _parse_selector(value: Any, path: str) -> V7Selector:
    source = _require_mapping(value, path)
    if not source or any(key not in SELECTOR_FIELDS for key in source):
        raise _error(
            "invalid_selector_shape",
            path,
            "use only nonempty buckets, sources, actions, and event_names fields",
        )
    values: dict[str, tuple[str, ...]] = {}
    for field_name in SELECTOR_FIELDS:
        if field_name not in source:
            values[field_name] = ()
        elif field_name == "buckets":
            values[field_name] = _parse_buckets(source[field_name], f"{path}.buckets")
        else:
            values[field_name] = _parse_tokens(source[field_name], f"{path}.{field_name}")
    return V7Selector(**values)


def _parse_buckets(value: Any, path: str, *, allow_empty: bool = False) -> tuple[str, ...]:
    source = _require_sequence(value, path)
    if (not allow_empty and not source) or len(source) > len(BUCKETS):
        raise _error("invalid_bucket_count", path, "use a bounded canonical bucket sequence")
    seen: set[str] = set()
    for item in source:
        if not isinstance(item, str) or item not in BUCKETS:
            raise _error("unknown_bucket", path, "use only canonical catalog-v1 bucket identifiers")
        if item in seen:
            raise _error("duplicate_bucket", path, "remove duplicate bucket identifiers")
        seen.add(item)
    return tuple(bucket for bucket in BUCKETS if bucket in seen)


def _parse_tokens(
    value: Any,
    path: str,
    *,
    allow_empty: bool = False,
    maximum: int = MAX_SELECTOR_VALUES,
) -> tuple[str, ...]:
    source = _require_sequence(value, path)
    if (not allow_empty and not source) or len(source) > maximum:
        raise _error("invalid_token_count", path, "use a bounded nonempty stable-token sequence")
    seen: set[str] = set()
    for item in source:
        _require_token(item, path)
        if item in seen:
            raise _error("duplicate_token", path, "remove duplicate stable tokens")
        seen.add(item)
    return tuple(sorted(seen))


def _require_mapping(value: Any, path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise _error("invalid_mapping", path, "supply the generated mapping shape")
    return value


def _require_sequence(value: Any, path: str) -> Sequence[Any]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise _error("invalid_sequence", path, "supply a generated sequence")
    return value


def _require_exact_fields(source: Mapping[str, Any], expected: frozenset[str], path: str) -> None:
    if set(source) != expected:
        raise _error(
            "invalid_fields",
            path,
            "regenerate the artifact with its exact required fields and no extensions",
        )


def _require_exact_integer(value: Any, expected: int, path: str) -> None:
    if type(value) is not int or value != expected:
        raise _error("unsupported_version", path, "use the exact supported generated-artifact version")


def _require_positive_integer(value: Any, path: str) -> int:
    if type(value) is not int or not 1 <= value <= MAX_REGISTRY_SCHEMA_VERSION:
        raise _error("invalid_registry_version", path, "use a positive bounded registry schema version")
    return value


def _require_token(value: Any, path: str) -> str:
    if (
        not isinstance(value, str)
        or len(value.encode("utf-8")) > MAX_TOKEN_BYTES
        or not _TOKEN.fullmatch(value)
        or value == "*"
    ):
        raise _error("invalid_token", path, "use one bounded canonical stable token without wildcards")
    return value


def _require_query_name(value: Any, allowed: Sequence[str], path: str) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise _error("unknown_query_key", path, "query one generated compatibility key")
    return value


def _canonical_query_names(value: Sequence[str], allowed: Sequence[str], path: str) -> tuple[str, ...]:
    source = _require_sequence(value, path)
    if len(source) > len(allowed):
        raise _error("invalid_query_values", path, "query each supported name at most once")
    seen: set[str] = set()
    for item in source:
        _require_query_name(item, allowed, path)
        if item in seen:
            raise _error("duplicate_query_value", path, "remove duplicate query names")
        seen.add(item)
    return tuple(item for item in allowed if item in seen)


def _canonical_query_tokens(value: Sequence[str], path: str) -> tuple[str, ...]:
    return _parse_tokens(value, path, allow_empty=True, maximum=MAX_REQUIRED_ATTRIBUTES)


def _lookup(pairs: Sequence[tuple[str, Any]], name: str) -> Any:
    result = _lookup_optional(pairs, name)
    if result is None:
        raise _error("missing_generated_mapping", "$", "regenerate the complete compatibility artifact")
    return result


def _lookup_optional(pairs: Sequence[tuple[str, Any]], name: str) -> Any | None:
    return next((value for key, value in pairs if key == name), None)


def _error(code: str, path: str, action: str) -> V7CompatibilityError:
    return V7CompatibilityError(code, path, action)
