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
"""Render candidate portable telemetry artifacts from one materialized view.

This module is deliberately downstream of the telemetry compiler.  Its only
semantic input is ``MaterializedRegistryView``; it never reads registry YAML,
constructs ``RegistryIR``, or consults current generated output.  Returned
artifacts are complete in-memory bytes.  Public views target their exact live
paths; the caller publishes them through the generated-output transaction.
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import importlib.util
import json
import math
import re
import stat
import sys
import unicodedata
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath
from types import MappingProxyType, ModuleType
from typing import Any, Final, TypeAlias

if __package__ == "scripts":  # pragma: no cover - package import exercised by subprocess tests
    from .telemetry_go_api_plan import GoAPIPlanError, GoAPIPlanIR, compile_go_api_plan
else:

    def _load_direct_dependency(module_name: str):  # type: ignore[no-untyped-def]
        path = Path(__file__).resolve().with_name(module_name + ".py").resolve(strict=True)
        opposite = sys.modules.get(f"scripts.{module_name}")
        if isinstance(opposite, ModuleType):
            try:
                opposite_path = Path(opposite.__file__).resolve(strict=True)
                opposite_spec = opposite.__spec__
                if (
                    opposite.__name__ != f"scripts.{module_name}"
                    or opposite_spec is None
                    or opposite_spec.name != f"scripts.{module_name}"
                    or opposite_spec.loader is None
                    or opposite_spec.origin is None
                ):
                    raise RuntimeError("dependency has no canonical import identity")
                opposite_origin = Path(opposite_spec.origin).resolve(strict=True)
                regular = stat.S_ISREG(opposite_path.stat().st_mode) and stat.S_ISREG(opposite_origin.stat().st_mode)
            except (AttributeError, OSError, RuntimeError, TypeError) as exc:
                raise RuntimeError(f"telemetry renderer dependency {module_name} has foreign provenance") from exc
            if regular and opposite_path == path and opposite_origin == path:
                return opposite
            raise RuntimeError(f"telemetry renderer dependency {module_name} has foreign provenance")
        existing = sys.modules.get(module_name)
        if existing is not None:
            if not isinstance(existing, ModuleType):
                raise RuntimeError(f"telemetry renderer dependency {module_name} has foreign provenance")
            try:
                existing_path = Path(existing.__file__).resolve(strict=True)
                existing_spec = existing.__spec__
                if (
                    existing.__name__ != module_name
                    or existing_spec is None
                    or existing_spec.name != module_name
                    or existing_spec.loader is None
                    or existing_spec.origin is None
                ):
                    raise RuntimeError("dependency has no canonical import identity")
                existing_origin = Path(existing_spec.origin).resolve(strict=True)
                regular = stat.S_ISREG(existing_path.stat().st_mode) and stat.S_ISREG(existing_origin.stat().st_mode)
            except (AttributeError, OSError, RuntimeError, TypeError) as exc:
                raise RuntimeError(f"telemetry renderer dependency {module_name} has foreign provenance") from exc
            if not regular or existing_path != path or existing_origin != path:
                raise RuntimeError(f"telemetry renderer dependency {module_name} has foreign provenance")
            return existing
        spec = importlib.util.spec_from_file_location(module_name, path)
        if spec is None or spec.loader is None:
            raise RuntimeError(f"telemetry renderer dependency {module_name} is unavailable")
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        try:
            spec.loader.exec_module(module)
        except Exception:
            if sys.modules.get(module_name) is module:
                del sys.modules[module_name]
            raise
        return module

    _load_direct_dependency("telemetry_canonical_record")
    _api_plan = _load_direct_dependency("telemetry_go_api_plan")
    GoAPIPlanError = _api_plan.GoAPIPlanError
    GoAPIPlanIR = _api_plan.GoAPIPlanIR
    compile_go_api_plan = _api_plan.compile_go_api_plan


class CandidateRenderError(ValueError):
    """A content-free failure to render a complete candidate artifact set."""


@dataclasses.dataclass(frozen=True, slots=True)
class CandidateArtifact:
    """One deterministic repository-relative candidate output."""

    path: str
    payload: bytes
    media_type: str
    ownership_marker: bytes
    mode: int = 0o644


FrozenJSON: TypeAlias = None | bool | int | float | str | bytes | Mapping[str, "FrozenJSON"] | tuple["FrozenJSON", ...]
JSONObject: TypeAlias = dict[str, Any]


MATERIALIZED_VIEW_FORMAT: Final = "defenseclaw-materialized-registry-view-v1"
MATERIALIZED_VIEW_DIGEST_DOMAIN: Final = b"DefenseClaw MaterializedRegistryView v1\x00"
CANDIDATE_RENDER_INDEX_DIGEST_DOMAIN: Final = b"DefenseClaw CandidateRenderIndex v1\x00"
GENERATOR_ID: Final = "defenseclaw-telemetry-candidate-renderer-v1"
CANDIDATE_AUTHORITY: Final = "candidate-not-public-authority"
GENERATED_PREFIX: Final = "schemas/telemetry/generated"
_SCHEMA_OUTPUT_PATH: Final = f"{GENERATED_PREFIX}/telemetry.schema.json"
_CATALOG_OUTPUT_PATH: Final = f"{GENERATED_PREFIX}/catalog.json"
_CATALOG_MARKDOWN_OUTPUT_PATH: Final = f"{GENERATED_PREFIX}/catalog.md"
_V7_EXPORTER_SELECTION_OUTPUT_PATH: Final = f"{GENERATED_PREFIX}/compatibility/v7-exporter-selection.json"
_INBOUND_OTLP_OUTPUT_PATH: Final = f"{GENERATED_PREFIX}/compatibility/inbound-otlp.json"
_COMPATIBILITY_PROFILE_OUTPUT_PATHS: Final = {
    profile: f"{GENERATED_PREFIX}/compatibility/{profile}.json"
    for profile in (
        "galileo-rich-v2",
        "local-observability-v1",
        "openinference-v1",
    )
}
_EXAMPLE_MANIFEST_OUTPUT_PATH: Final = f"{GENERATED_PREFIX}/examples/manifest.json"
_OTLP_MANIFEST_OUTPUT_PATH: Final = f"{GENERATED_PREFIX}/otlp-fixtures/manifest.json"
_BASE_CANDIDATE_OUTPUT_PATHS: Final = (
    _SCHEMA_OUTPUT_PATH,
    _CATALOG_OUTPUT_PATH,
    _CATALOG_MARKDOWN_OUTPUT_PATH,
    _V7_EXPORTER_SELECTION_OUTPUT_PATH,
    _INBOUND_OTLP_OUTPUT_PATH,
    *_COMPATIBILITY_PROFILE_OUTPUT_PATHS.values(),
    _EXAMPLE_MANIFEST_OUTPUT_PATH,
    _OTLP_MANIFEST_OUTPUT_PATH,
)
JSON_OWNERSHIP_MARKER: Final = b'"x-defenseclaw-generated"'
MARKDOWN_MARKER_PREFIX: Final = "<!-- Code generated by DefenseClaw telemetry candidate renderer; DO NOT EDIT."
CANONICAL_JSON_DEFINITION: Final = "value:canonical_json"
_SHA256: Final = re.compile(r"^[0-9a-f]{64}$")
_GO_PUBLIC_IDENTIFIER: Final = re.compile(r"^[A-Z][A-Za-z0-9]*$")
_GO_SOURCE_ID: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/#-]{0,511}$")
_V7_COMPATIBILITY_TOKEN: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
_V7_AUDIT_GATEWAY_EVENT_KEYS: Final = (
    "verdict",
    "llm_prompt",
    "llm_response",
    "tool_invocation",
)
_V7_BUCKETS: Final = (
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
)
_EXAMPLE_PATH_SEGMENT: Final = re.compile(r"^[a-z][a-z0-9-]{0,127}$")
_DOS_DEVICE_STEM: Final = re.compile(
    r"^(?:con|prn|aux|nul|com[1-9¹²³]|lpt[1-9¹²³]|clock\$|conin\$|conout\$)$",
    re.IGNORECASE,
)
_STRUCTURED_TYPE_IDS: Final = (
    "gen_ai.canonical_json",
    "gen_ai.tool_call_arguments",
    "gen_ai.tool_call_result",
    "gen_ai.input_messages",
    "gen_ai.output_messages",
    "gen_ai.message_parts",
    "gen_ai.message_part",
    "gen_ai.chat_message",
    "gen_ai.output_message",
    "gen_ai.text_part",
    "gen_ai.tool_call_request_part",
    "gen_ai.tool_call_response_part",
    "gen_ai.server_tool_call_part",
    "gen_ai.server_tool_call_response_part",
    "gen_ai.blob_part",
    "gen_ai.file_part",
    "gen_ai.uri_part",
    "gen_ai.reasoning_part",
    "gen_ai.compaction_part",
    "gen_ai.generic_part",
    "gen_ai.generic_server_tool_payload",
)
_STRUCTURED_EXPECTED_BINDINGS: Final = (
    ("gen_ai.input.messages", "gen_ai.input_messages", "sealed_typed", "native_json"),
    ("gen_ai.output.messages", "gen_ai.output_messages", "sealed_typed", "native_json"),
    (
        "gen_ai.tool.call.arguments",
        "gen_ai.tool_call_arguments",
        "ordered_typed_entries",
        "native_json_object",
    ),
    (
        "gen_ai.tool.call.result",
        "gen_ai.tool_call_result",
        "ordered_typed_entries",
        "native_json_object",
    ),
)
_STRUCTURED_EXPECTED_VARIANTS: Final = (
    ("text", "gen_ai.text_part"),
    ("tool_call", "gen_ai.tool_call_request_part"),
    ("tool_call_response", "gen_ai.tool_call_response_part"),
    ("server_tool_call", "gen_ai.server_tool_call_part"),
    ("server_tool_call_response", "gen_ai.server_tool_call_response_part"),
    ("blob", "gen_ai.blob_part"),
    ("file", "gen_ai.file_part"),
    ("uri", "gen_ai.uri_part"),
    ("reasoning", "gen_ai.reasoning_part"),
    ("compaction", "gen_ai.compaction_part"),
)
_STRUCTURED_EXPECTED_OBJECT_FIELDS: Final = {
    "gen_ai.tool_call_arguments": (),
    "gen_ai.tool_call_result": (),
    "gen_ai.chat_message": (
        ("role", True, "scalar", "string"),
        ("parts", True, "reference", "gen_ai.message_parts"),
        ("name", False, "scalar", "string"),
    ),
    "gen_ai.output_message": (
        ("role", True, "scalar", "string"),
        ("parts", True, "reference", "gen_ai.message_parts"),
        ("name", False, "scalar", "string"),
        ("finish_reason", False, "scalar", "string"),
    ),
    "gen_ai.text_part": (("content", True, "scalar", "string"),),
    "gen_ai.tool_call_request_part": (
        ("id", False, "scalar", "string"),
        ("name", True, "scalar", "string"),
        ("arguments", False, "reference", "gen_ai.canonical_json"),
    ),
    "gen_ai.tool_call_response_part": (
        ("id", False, "scalar", "string"),
        ("response", True, "reference", "gen_ai.canonical_json"),
    ),
    "gen_ai.server_tool_call_part": (
        ("id", False, "scalar", "string"),
        ("name", True, "scalar", "string"),
        ("server_tool_call", True, "reference", "gen_ai.generic_server_tool_payload"),
    ),
    "gen_ai.server_tool_call_response_part": (
        ("id", False, "scalar", "string"),
        ("server_tool_call_response", True, "reference", "gen_ai.generic_server_tool_payload"),
    ),
    "gen_ai.blob_part": (
        ("mime_type", False, "scalar", "string"),
        ("modality", True, "scalar", "string"),
        ("content", True, "scalar", "string"),
    ),
    "gen_ai.file_part": (
        ("mime_type", False, "scalar", "string"),
        ("modality", True, "scalar", "string"),
        ("file_id", True, "scalar", "string"),
    ),
    "gen_ai.uri_part": (
        ("mime_type", False, "scalar", "string"),
        ("modality", True, "scalar", "string"),
        ("uri", True, "scalar", "string"),
    ),
    "gen_ai.reasoning_part": (("content", True, "scalar", "string"),),
    "gen_ai.compaction_part": (
        ("id", False, "scalar", "string"),
        ("content", False, "scalar", "string"),
    ),
    "gen_ai.generic_part": (),
    "gen_ai.generic_server_tool_payload": (("type", True, "scalar", "string"),),
}
_STRUCTURED_EXPECTED_ARRAYS: Final = {
    "gen_ai.input_messages": ("gen_ai.chat_message", 0, 256),
    "gen_ai.output_messages": ("gen_ai.output_message", 0, 256),
    "gen_ai.message_parts": ("gen_ai.message_part", 0, 256),
}
_STRUCTURED_NULLABLE_OPTIONALS: Final = {
    "gen_ai.chat_message": frozenset({"name"}),
    "gen_ai.output_message": frozenset({"name"}),
    "gen_ai.blob_part": frozenset({"mime_type"}),
    "gen_ai.compaction_part": frozenset({"id", "content"}),
    "gen_ai.file_part": frozenset({"mime_type"}),
    "gen_ai.server_tool_call_part": frozenset({"id"}),
    "gen_ai.server_tool_call_response_part": frozenset({"id"}),
    "gen_ai.tool_call_request_part": frozenset({"id", "arguments"}),
    "gen_ai.tool_call_response_part": frozenset({"id"}),
    "gen_ai.uri_part": frozenset({"mime_type"}),
}
_STRUCTURED_EXPECTED_KNOWN_VALUES: Final = {
    ("gen_ai.chat_message", "role"): ("system", "user", "assistant", "tool"),
    ("gen_ai.output_message", "role"): ("system", "user", "assistant", "tool"),
    ("gen_ai.output_message", "finish_reason"): (
        "stop",
        "length",
        "content_filter",
        "tool_call",
        "compaction",
        "error",
    ),
    ("gen_ai.blob_part", "modality"): ("image", "video", "audio", "document"),
    ("gen_ai.file_part", "modality"): ("image", "video", "audio", "document"),
    ("gen_ai.uri_part", "modality"): ("image", "video", "audio", "document"),
}
_STRUCTURED_DISPOSITIONS_SHA256: Final = "19aa6a80165bed241ae9e427b9b4f7cea9d0b7001c11e5f6460b84c89bd4c0c3"
_STRUCTURED_TYPES_SHA256: Final = "f4ca4b3986b0c1b90439f6a127e06f7eb00176ba5b4bcad14a7a1dbe9383cbdb"
_STRUCTURAL_CONTRACT_SHA256: Final = "a5f1dcae714d17b138a130a9a8b99f754165370974dbaef994976d67a8f8abaa"
_CANONICAL_JSON_LIMITS: Final = {
    "max_depth": 8,
    "max_aggregate_members": 256,
    "max_array_items": 256,
    "max_string_utf8_bytes": 4096,
    "max_member_name_utf8_bytes": 256,
    "max_item_bytes": 32768,
    "max_canonical_bytes": 65536,
}
_GO_SYMBOL_POLICY: Final = {
    "version": 1,
    "package": "observability",
    "separators": (".", "-", "/", "_"),
    "brand_spellings": {
        "defenseclaw": "DefenseClaw",
        "opentelemetry": "OpenTelemetry",
        "otel": "OTel",
    },
    "initialisms": (
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
    "reserved_word_policy": "reject",
    "collision_policy": "reject",
    "auto_suffix_policy": "reject",
}
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
_GO_SYMBOL_DECLARATION_BY_KIND: Final = {
    "attribute": "exported_const",
    "family": "exported_const",
    "log_event": "exported_const",
    "span_event": "exported_const",
    "link_relation": "exported_const",
    "metric_instrument": "exported_const",
    "condition": "exported_const",
    "condition_fact": "exported_const",
    "phase": "exported_const",
    "phase_code": "exported_const",
    "semantic_profile": "exported_const",
    "structured_type": "exported_type",
    "structured_member": "exported_const",
    "structured_arm": "exported_type",
    "structured_member_input": "exported_type",
    "structured_member_constructor": "exported_function",
    "resource_attributes_type": "exported_type",
    "resource_attributes_constructor": "exported_function",
    "resource_attributes_attach": "exported_function",
    "resource_attributes_validator": "exported_function",
    "family_input": "exported_type",
    "family_builder": "family_builder_method",
    "span_event_input": "exported_type",
    "span_event_constructor": "exported_function",
    "span_link_input": "exported_type",
    "span_link_constructor": "exported_function",
}
_MAX_GO_SYMBOL_ROWS: Final = 100_000
_GO_SYMBOL_TABLE_DIGEST_DOMAIN: Final = b"DefenseClaw GoSymbolTableIR v1\x00"


def _normalized_candidate_path(raw: str) -> str:
    """Validate and return one canonical repository-relative POSIX path."""

    if not isinstance(raw, str) or not raw or "\\" in raw or "\x00" in raw:
        raise CandidateRenderError("candidate output path is not canonical POSIX")
    if raw.startswith("/") or raw.endswith("/") or "//" in raw:
        raise CandidateRenderError("candidate output path is not canonical POSIX")
    path = PurePosixPath(raw)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise CandidateRenderError("candidate output path is not canonical POSIX")
    if path.as_posix() != raw:
        raise CandidateRenderError("candidate output path is not canonical POSIX")
    for part in path.parts:
        device_stem = part.split(".", 1)[0].rstrip(" .")
        invalid_windows_character = any(character in '<>:"|?*' or ord(character) < 32 for character in part)
        if (
            invalid_windows_character
            or part.endswith((".", " "))
            or _DOS_DEVICE_STEM.fullmatch(device_stem) is not None
        ):
            raise CandidateRenderError("candidate output path uses platform-reserved syntax")
    prefix = PurePosixPath(GENERATED_PREFIX).parts
    under_generated_root = path.parts[: len(prefix)] == prefix and len(path.parts) > len(prefix)
    if not under_generated_root:
        raise CandidateRenderError("candidate output path is outside the generated root")
    return path.as_posix()


def _candidate_path_identity(path: str) -> str:
    """Return the portable collision identity for a validated output path."""

    normalized = unicodedata.normalize("NFC", path)
    return unicodedata.normalize("NFC", normalized.casefold())


def _generated_relative_path(path: str) -> str:
    """Return the generated-root-relative identity of one canonical full path."""

    normalized = _normalized_candidate_path(path)
    return normalized.removeprefix(f"{GENERATED_PREFIX}/")


def _add_candidate_artifact(
    artifacts: dict[str, CandidateArtifact],
    artifact: CandidateArtifact,
) -> None:
    """Add one artifact after exact and portable collision checks."""

    path = _normalized_candidate_path(artifact.path)
    if path in artifacts:
        raise CandidateRenderError("candidate output path is duplicated")
    identity = _candidate_path_identity(path)
    if any(_candidate_path_identity(existing) == identity for existing in artifacts):
        raise CandidateRenderError("candidate output path has a portable collision")
    artifacts[path] = artifact


def _preflight_candidate_artifacts(
    artifacts: Mapping[str, CandidateArtifact],
) -> Mapping[str, CandidateArtifact]:
    """Validate the full output set before returning immutable candidates."""

    checked: dict[str, CandidateArtifact] = {}
    for key, artifact in artifacts.items():
        if not isinstance(artifact, CandidateArtifact) or artifact.path != key:
            raise CandidateRenderError("candidate artifact path does not match its key")
        _add_candidate_artifact(checked, artifact)
    return MappingProxyType({path: checked[path] for path in sorted(checked)})


_TOP_LEVEL_FIELDS: Final = frozenset(
    {
        "registry_path",
        "schema_version",
        "registry_version",
        "bucket_catalog_version",
        "imports",
        "dependency_lock_path",
        "examples_path",
        "v7_exporter_selection_schema_path",
        "input_digests",
        "dependencies",
        "semantic_profiles",
        "go_symbol_policy",
        "go_symbol_overrides",
        "go_symbol_table",
        "normalizers",
        "conditions",
        "mandatory_rule_catalog",
        "structured_types",
        "structured_bindings",
        "structured_property_dispositions",
        "value_catalogs",
        "structural_contract",
        "metric_cardinality_limit",
        "metric_compatibility_profile",
        "v7_exporter_selection",
        "v7_exporter_selection_schema",
        "inbound_bindings",
        "domains",
        "group_resolution_order",
        "resolved_group_uses",
        "examples",
        "upstream_attribute_ownership",
        "legacy_only_upstream_attributes",
    }
)
_GO_SYMBOL_POLICY_FIELDS_PLACEHOLDER = None
_GO_SYMBOL_POLICY_FIELDS: Final = frozenset(
    {
        "version",
        "package",
        "separators",
        "brand_spellings",
        "initialisms",
        "reserved_word_policy",
        "collision_policy",
        "auto_suffix_policy",
    }
)
_GO_SYMBOL_OVERRIDE_FIELDS: Final = frozenset({"kind", "source_id", "symbol", "reason"})
_GO_SYMBOL_FIELDS: Final = frozenset({"kind", "source_id", "symbol", "declaration_form"})
_GO_SYMBOL_TABLE_FIELDS: Final = frozenset(
    {"version", "package", "rows", "kind_counts", "declaration_form_counts", "table_sha256"}
)
_RESOURCE_DYNAMIC_MEMBERS_FIELDS: Final = frozenset(
    {
        "ordering",
        "field_class",
        "sensitivity",
        "cardinality",
        "stability_scope",
        "value_utf8_policy",
        "value_blank_policy",
        "value_control_character_policy",
        "prometheus_key_normalization",
        "prometheus_normalized_collision_policy",
        "key_pattern",
        "max_items",
        "max_key_ascii_bytes",
        "min_value_utf8_bytes",
        "max_value_utf8_bytes",
        "max_aggregate_utf8_bytes",
        "duplicate_key_policy",
        "fixed_key_collision_policy",
        "forbidden_key_segments",
        "reserved_keys",
        "forbidden_value_classes",
    }
)
_RESOURCE_COMPATIBILITY_ALIAS_FIELDS: Final = frozenset({"alias", "canonical"})
_GROUP_FIELDS: Final = frozenset(
    {
        "id",
        "type",
        "brief",
        "stability",
        "extends",
        "attribute_uses",
        "attribute_refs",
        "resolved_uses",
        "event_refs",
        "event_name",
        "bucket",
        "span_name_pattern",
        "span_name_parts",
        "span_kinds",
        "span_status_rule",
        "instrument_name",
        "instrument_type",
        "metric_value_type",
        "metric_unit",
        "metric_description",
        "metric_temporality",
        "metric_boundaries",
        "empty_labels_reason",
        "metric_projections",
        "family_schema_version",
        "outcome_requirement",
        "allowed_outcomes",
        "link_relations",
        "mandatory_floor",
        "route_selector",
        "compatibility_profiles",
        "resource_dynamic_members",
        "resource_compatibility_aliases",
        "legacy_bindings",
        "introduced_in",
        "deprecated_in",
        "removed_in",
    }
)
_ATTRIBUTE_FIELDS: Final = frozenset(
    {
        "id",
        "field_type",
        "brief",
        "examples",
        "alias_of",
        "owner",
        "stability",
        "deprecated_in",
        "removed_in",
        "projection_only",
        "field_class",
        "sensitivity",
        "cardinality",
        "normalization",
        "introduced_in",
        "legacy_bindings",
    }
)
_ATTRIBUTE_EXTENSION_FIELDS: Final = frozenset({"ref", "field_class", "sensitivity", "cardinality", "normalization"})
_NORMALIZATION_FIELDS: Final = frozenset({"id", "overrides", "effective_constraints", "notes"})
_DOMAIN_FIELDS: Final = frozenset(
    {
        "domain",
        "path",
        "attributes",
        "attribute_extensions",
        "groups",
        "producer_identity_sets",
        "producer_mappings",
    }
)
_DEPENDENCY_FIELDS: Final = frozenset(
    {"id", "repository", "version", "profile_id", "revision", "snapshot", "structural_inputs"}
)
_STRUCTURAL_INPUT_FIELDS: Final = frozenset({"upstream_path", "path", "sha256"})
_STRUCTURED_SCALAR_FIELDS: Final = frozenset(
    {"field_type", "field_class", "sensitivity", "normalization", "encoding_annotation", "known_values"}
)
_STRUCTURED_REFERENCE_FIELDS: Final = frozenset({"structured_ref"})
_STRUCTURED_FIELD_FIELDS: Final = frozenset({"name", "required", "nullable_omission", "scalar", "reference"})
_STRUCTURED_DYNAMIC_NAME_FIELDS: Final = frozenset({"field_type", "field_class", "sensitivity", "normalization"})
_STRUCTURED_DYNAMIC_MEMBERS_FIELDS: Final = frozenset(
    {
        "member_id",
        "name",
        "value",
        "max_items",
        "public_encoding",
        "wire_encoding",
        "duplicate_name_policy",
        "fixed_name_collision_policy",
        "post_redaction_name_collision_policy",
        "reserved_names",
    }
)
_STRUCTURED_DISCRIMINATOR_FIELDS: Final = frozenset(
    {"name", "field_type", "field_class", "sensitivity", "normalization"}
)
_STRUCTURED_VARIANT_FIELDS: Final = frozenset({"tag", "structured_ref"})
_STRUCTURED_DYNAMIC_VARIANT_FIELDS: Final = frozenset(
    {"arm_id", "tag_normalization", "structured_ref", "exclude_registered_tags"}
)
_CANONICAL_JSON_LIMITS_FIELDS: Final = frozenset(
    {
        "max_depth",
        "max_aggregate_members",
        "max_array_items",
        "max_string_utf8_bytes",
        "max_member_name_utf8_bytes",
        "max_item_bytes",
        "max_canonical_bytes",
    }
)
_CANONICAL_JSON_CONTRACT_FIELDS: Final = frozenset(
    {
        "discriminator_visibility",
        "discriminator_wire",
        "arms",
        "leaf_field_class",
        "leaf_sensitivity",
        "array_items_ref",
        "object_member_id",
        "object_name",
        "object_value",
        "public_encoding",
        "wire_encoding",
        "duplicate_name_policy",
        "fixed_name_collision_policy",
        "post_redaction_name_collision_policy",
        "limits",
    }
)
_STRUCTURED_TYPE_FIELDS: Final = frozenset(
    {
        "id",
        "kind",
        "introduced_in",
        "additional_properties",
        "fields",
        "dynamic_members",
        "items_scalar",
        "items_reference",
        "min_items",
        "max_items",
        "discriminator",
        "variants",
        "dynamic_variant",
        "canonical_json",
        "effective_reserved_names",
    }
)
_STRUCTURED_BINDING_FIELDS: Final = frozenset(
    {"attribute", "structured_type", "public_encoding", "canonical_wire_encoding"}
)
_STRUCTURED_DISPOSITION_FIELDS: Final = frozenset(
    {
        "input_path",
        "json_pointer",
        "disposition",
        "structured_type",
        "member_name",
        "arm_id",
        "target_structured_type",
    }
)
_SNAPSHOT_FIELDS: Final = frozenset(
    {
        "format_version",
        "format",
        "dependency_id",
        "repository",
        "revision",
        "path",
        "sha256",
        "source_archive_url",
        "source_archive_sha256",
        "source_tree_sha256",
        "full_normalized_inventory_sha256",
        "selection_policy",
        "selection_attribute_ids_sha256",
        "source_files",
        "attributes",
    }
)
_SNAPSHOT_ATTRIBUTE_FIELDS: Final = frozenset(
    {"id", "allowed_types", "shape", "stability", "stability_source", "source_pointer", "enum", "deprecated"}
)
_UPSTREAM_OWNERSHIP_FIELDS: Final = frozenset({"ref", "owner"})
_ATTRIBUTE_USE_FIELDS: Final = frozenset({"ref", "role", "requirement_level", "conditional", "constraints"})
_RESOLVED_USE_FIELDS: Final = frozenset({"ref", "role", "requirement_level", "conditional", "constraints", "origins"})
_ATTRIBUTE_USE_ORIGIN_FIELDS: Final = frozenset({"group_id", "role", "requirement_level", "conditional", "constraints"})
_NORMALIZER_FIELDS: Final = frozenset({"id", "kind", "default_constraints", "allowed_overrides"})
_CONSTRAINT_KEYS: Final = frozenset(
    {
        "enum",
        "pattern",
        "min",
        "max",
        "min_items",
        "max_items",
        "max_utf8_bytes",
        "max_item_utf8_bytes",
        "max_depth",
        "max_properties",
    }
)
_REQUIREMENT_RANK: Final = {
    "optional": 1,
    "recommended": 2,
    "conditional": 3,
    "required": 4,
}
_EXPECTED_NORMALIZER_CATALOG: Final = {
    "identity-v1": ("identity", {}, ("min_items", "max_items")),
    "bounded-v1": (
        "bounded",
        {"max_utf8_bytes": 4096, "max_item_utf8_bytes": 4096, "max_items": 256},
        ("max_utf8_bytes", "max_item_utf8_bytes", "min_items", "max_items", "pattern"),
    ),
    "enum-v1": ("enum", {"max_utf8_bytes": 256}, ("enum", "max_utf8_bytes")),
    "identifier-v1": (
        "identifier",
        {"max_utf8_bytes": 256, "pattern": "^[A-Za-z0-9][A-Za-z0-9._:/-]*$"},
        ("max_utf8_bytes", "pattern"),
    ),
    "numeric-range-v1": ("numeric_range", {}, ("min", "max", "min_items", "max_items")),
    "structured-content-v1": (
        "structured_content",
        {
            "max_utf8_bytes": 65536,
            "max_item_utf8_bytes": 4096,
            "max_items": 256,
            "max_depth": 8,
            "max_properties": 256,
        },
        ("max_utf8_bytes", "max_item_utf8_bytes", "min_items", "max_items", "max_depth", "max_properties"),
    ),
    "redacted-content-v1": (
        "redacted_content",
        {
            "max_utf8_bytes": 65536,
            "max_item_utf8_bytes": 4096,
            "max_items": 256,
            "max_depth": 8,
            "max_properties": 256,
        },
        ("max_utf8_bytes", "max_item_utf8_bytes", "min_items", "max_items", "max_depth", "max_properties"),
    ),
    "path-v1": ("path", {"max_utf8_bytes": 4096}, ("max_utf8_bytes",)),
    "url-v1": ("url", {"max_utf8_bytes": 8192}, ("max_utf8_bytes",)),
    "digest-v1": (
        "digest",
        {"max_utf8_bytes": 256, "pattern": "^[A-Za-z0-9][A-Za-z0-9:+._/-]*$"},
        ("max_utf8_bytes", "pattern"),
    ),
}
_LOCAL_FIELD_TYPES: Final = frozenset(
    {
        "string",
        "boolean",
        "int64",
        "uint32",
        "double",
        "string[]",
        "boolean[]",
        "int64[]",
        "double[]",
        "bytes",
        "object",
        "array",
    }
)
_EXAMPLE_FIELDS: Final = frozenset(
    {
        "id",
        "valid",
        "signal",
        "description",
        "family",
        "record",
        "expected_error",
        "field_classes",
        "base_example",
        "mutation",
        "builder_context",
    }
)
_STRUCTURAL_OBJECT_FIELDS: Final = frozenset({"id", "additional_properties", "fields"})
_PROVENANCE_IMPORT_RULE_FIELDS: Final = frozenset(
    {
        "nonempty_string_fields",
        "derivation_required_modes",
        "derivation_forbidden_modes",
        "source_aggregate_count_required_derivations",
        "source_aggregate_count_forbidden_derivations",
        "source_aggregate_count_forbidden_modes",
        "exact_validation_owner",
        "json_schema_runtime_only",
    }
)
_STRUCTURAL_FIELD_FIELDS: Final = frozenset(
    {
        "name",
        "field_type",
        "required",
        "const_present",
        "const",
        "enum",
        "object_ref",
        "item_ref",
        "semantic_ref",
        "semantic_format",
        "field_class",
        "sensitivity",
        "normalization",
        "otlp_target",
        "otlp_encoding",
    }
)
_SIGNAL_ARM_FIELDS: Final = frozenset(
    {"signal", "payload_field", "required_fields", "forbidden_fields", "required_correlation_fields"}
)
_SPAN_NAME_PART_FIELDS: Final = frozenset({"kind", "literal", "field"})
_TRACE_DERIVATION_FIELDS: Final = frozenset(
    {"id", "target_attribute", "target_field", "source", "equality", "presence"}
)
_CANONICAL_OTLP_FIELDS: Final = frozenset(
    {
        "id",
        "json_mapping",
        "attribute_encoding",
        "any_value_encoding",
        "any_value_mapping",
        "null_value_policy",
        "object_contexts",
        "field_context_overrides",
        "timestamp_encoding",
        "id_encoding",
        "span_kind_mapping",
        "status_code_mapping",
        "signals",
    }
)
_CONDITION_FIELDS: Final = frozenset({"id", "description", "enforcement", "false_requirement"})
_CONDITION_ENFORCEMENT_FIELDS: Final = frozenset({"kind", "fact", "attribute"})
_MANDATORY_RULE_CATALOG_FIELDS: Final = frozenset({"version", "rules"})
_MANDATORY_RULE_FIELDS: Final = frozenset({"id", "enforcement"})
_MANDATORY_RULE_ENFORCEMENT_FIELDS: Final = frozenset({"kind", "value", "fact"})
_BUILDER_CONTEXT_FIELDS: Final = frozenset({"inheritance", "occurrence", "condition_facts", "mandatory_facts"})
_BUILDER_CONTEXT_INHERITANCE_FIELDS: Final = frozenset({"mode", "base_example"})
_BUILDER_OCCURRENCE_FIELDS: Final = frozenset({"timestamp", "record_id"})
_BUILDER_FACT_FIELDS: Final = frozenset({"fact", "value"})
_SEMANTIC_PROFILE_FIELDS: Final = frozenset(
    {
        "id",
        "trace_schema_version",
        "gen_ai_semconv_profile",
        "openinference_profile",
        "galileo_compatibility_profile",
    }
)
_VALUE_CATALOG_FIELDS: Final = frozenset(
    {"id", "kind", "value_attributes", "paired_value_attribute", "code_attribute", "entries", "compatibility"}
)
_VALUE_CATALOG_ENTRY_FIELDS: Final = frozenset({"value", "code"})
_COMPATIBILITY_PROFILES: Final = frozenset(
    {
        "galileo-rich-v2",
        "local-observability-v1",
        "openinference-v1",
    }
)
_GALILEO_FAMILY_PROJECTIONS: Final = {
    "span.agent.invoke": {
        "mode": "galileo_shape_v2",
        "shape": "agent",
        "operation_attribute": "gen_ai.operation.name",
        "allowed_operations": ["invoke_agent"],
        "openinference_span_kind": "AGENT",
        "allowed_span_kinds": ["CLIENT", "INTERNAL"],
        "required_attributes": ["gen_ai.agent.name", "gen_ai.provider.name"],
    },
    "span.guardrail.judge": {
        "mode": "galileo_shape_v2",
        "shape": "llm",
        "operation_attribute": "gen_ai.operation.name",
        "allowed_operations": ["chat", "text_completion"],
        "openinference_span_kind": "LLM",
        "allowed_span_kinds": ["CLIENT"],
        "required_attributes": ["gen_ai.provider.name"],
    },
    "span.model.chat": {
        "mode": "galileo_shape_v2",
        "shape": "llm",
        "operation_attribute": "gen_ai.operation.name",
        "allowed_operations": ["chat", "text_completion"],
        "openinference_span_kind": "LLM",
        "allowed_span_kinds": ["CLIENT"],
        "required_attributes": ["gen_ai.provider.name"],
    },
    "span.retrieval.search": {
        "mode": "galileo_shape_v2",
        "shape": "retriever",
        "operation_attribute": "db.operation.name",
        "allowed_operations": ["query", "search"],
        "openinference_span_kind": "RETRIEVER",
        "allowed_span_kinds": ["CLIENT", "INTERNAL"],
        "required_attributes": [],
    },
    "span.tool.execute": {
        "mode": "galileo_shape_v2",
        "shape": "tool",
        "operation_attribute": "gen_ai.operation.name",
        "allowed_operations": ["execute_tool"],
        "openinference_span_kind": "TOOL",
        "allowed_span_kinds": ["CLIENT", "INTERNAL"],
        "required_attributes": ["gen_ai.tool.name"],
    },
    "span.workflow.run": {
        "mode": "galileo_shape_v2",
        "shape": "workflow",
        "operation_attribute": None,
        "allowed_operations": [],
        "openinference_span_kind": "CHAIN",
        "allowed_span_kinds": ["INTERNAL"],
        "required_attributes": ["defenseclaw.workflow.name"],
    },
}
_LOCAL_OBSERVABILITY_ALIASES: Final = (
    ("defenseclaw.connector.source", "connector", False),
    ("defenseclaw.agent.type", "gen_ai.agent.type", False),
    ("defenseclaw.guardrail.raw_action", "defenseclaw.raw_action", True),
    ("defenseclaw.guardrail.effective_action", "defenseclaw.decision", True),
    ("defenseclaw.guardrail.would_block", "defenseclaw.would_block", True),
)
_FIELD_CLASSES: Final = (
    "metadata",
    "identifier",
    "content",
    "reason",
    "evidence",
    "error",
    "path",
    "credential",
)
_STATIC_CANDIDATE_OUTPUT_PATHS: Final = _BASE_CANDIDATE_OUTPUT_PATHS


def _canonical_json_number(text: str) -> str:
    if re.fullmatch(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?", text) is None:
        raise CandidateRenderError("materialized view contains an invalid number")
    negative = text.startswith("-")
    if negative:
        text = text[1:]
    exponent_text = "0"
    exponent_match = re.search(r"[eE]", text)
    if exponent_match is not None:
        exponent_text = text[exponent_match.start() + 1 :]
        text = text[: exponent_match.start()]
    integer_part, separator, fraction_part = text.partition(".")
    digits = (integer_part + (fraction_part if separator else "")).lstrip("0")
    if not digits:
        return "0"
    exponent = int(exponent_text) - len(fraction_part)
    trimmed = digits.rstrip("0")
    exponent += len(digits) - len(trimmed)
    digits = trimmed
    scientific_exponent = exponent + len(digits) - 1
    scientific = digits[0]
    if len(digits) > 1:
        scientific += "." + digits[1:]
    if scientific_exponent:
        scientific += f"e{scientific_exponent}"
    point = exponent + len(digits)
    if point <= 0:
        plain = "0." + ("0" * -point) + digits
    elif point >= len(digits):
        plain = digits + ("0" * (point - len(digits)))
    else:
        plain = digits[:point] + "." + digits[point:]
    result = plain if len(plain) <= len(scientific) else scientific
    return "-" + result if negative else result


def _canonical_json_string(value: str) -> str:
    result = ['"']
    escapes = {"\b": "\\b", "\t": "\\t", "\n": "\\n", "\f": "\\f", "\r": "\\r", '"': '\\"', "\\": "\\\\"}
    for character in value:
        codepoint = ord(character)
        if 0xD800 <= codepoint <= 0xDFFF:
            raise CandidateRenderError("materialized view contains an invalid string")
        if character in escapes:
            result.append(escapes[character])
        elif codepoint < 0x20:
            result.append(f"\\u{codepoint:04x}")
        else:
            result.append(character)
    result.append('"')
    return "".join(result)


def _canonical_json_text(value: Any) -> str:
    if value is None:
        return "null"
    if type(value) is bool:
        return "true" if value else "false"
    if type(value) is int:
        return _canonical_json_number(str(value))
    if type(value) is float:
        if not math.isfinite(value):
            raise CandidateRenderError("materialized view contains a non-finite number")
        return "0" if value == 0 else _canonical_json_number(repr(value))
    if isinstance(value, str):
        return _canonical_json_string(value)
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise CandidateRenderError("materialized view contains a non-string key")
        return (
            "{"
            + ",".join(_canonical_json_string(key) + ":" + _canonical_json_text(value[key]) for key in sorted(value))
            + "}"
        )
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_canonical_json_text(item) for item in value) + "]"
    raise CandidateRenderError("materialized view contains an unsupported value")


def _canonical_json_bytes(value: Any) -> bytes:
    return _canonical_json_text(value).encode("utf-8")


def _typed_materialized_node(value: FrozenJSON) -> FrozenJSON:
    if value is None:
        return ("null",)
    if type(value) is bool:
        return ("boolean", value)
    if type(value) is int:
        return ("int", str(value))
    if type(value) is float:
        return ("double", _canonical_json_number(repr(value)) if value != 0 else "0")
    if isinstance(value, bytes):
        return ("bytes", value.hex())
    if isinstance(value, str):
        return ("string", value)
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise CandidateRenderError("materialized view contains a non-string key")
        return ("object", tuple((key, _typed_materialized_node(value[key])) for key in sorted(value)))
    if isinstance(value, tuple):
        return ("array", tuple(_typed_materialized_node(item) for item in value))
    raise CandidateRenderError("materialized view contains a mutable or unsupported value")


def _plain(value: FrozenJSON) -> Any:
    if isinstance(value, Mapping):
        return {key: _plain(value[key]) for key in sorted(value)}
    if isinstance(value, tuple):
        return [_plain(item) for item in value]
    if isinstance(value, bytes):
        return {"$bytes": value.hex()}
    return value


def _plain_ir(value: FrozenJSON) -> Any:
    if isinstance(value, Mapping):
        if set(value) == {"$type", "fields"} and isinstance(value.get("$type"), str):
            fields = value.get("fields")
            if not isinstance(fields, Mapping):
                raise CandidateRenderError("materialized typed fields are invalid")
            return {key: _plain_ir(fields[key]) for key in sorted(fields)}
        return {key: _plain_ir(value[key]) for key in sorted(value)}
    if isinstance(value, tuple):
        return [_plain_ir(item) for item in value]
    if isinstance(value, bytes):
        return {"$bytes": value.hex()}
    return value


def _semantic_digest_projection(value: FrozenJSON) -> FrozenJSON:
    if isinstance(value, Mapping):
        projected = {key: _semantic_digest_projection(item) for key, item in value.items()}
        if projected.get("$type") == "NormalizationIR" and isinstance(projected.get("fields"), Mapping):
            fields = dict(projected["fields"])
            notes = fields.get("notes")
            if notes is not None and (not isinstance(notes, str) or not notes or len(notes.encode("utf-8")) > 4096):
                raise CandidateRenderError("materialized normalization notes are invalid")
            fields["notes"] = None
            projected["fields"] = fields
        return MappingProxyType(projected)
    if isinstance(value, tuple):
        return tuple(_semantic_digest_projection(item) for item in value)
    return value


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze(value[key]) for key in sorted(value)})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    if value is None or type(value) in {bool, int, float, str, bytes}:
        return value
    raise CandidateRenderError("candidate render index contains an unsupported value")


def _tagged(value: Any, type_name: str, expected_fields: frozenset[str] | None = None) -> Mapping[str, FrozenJSON]:
    if not isinstance(value, Mapping) or set(value) != {"$type", "fields"} or value["$type"] != type_name:
        raise CandidateRenderError(f"materialized view is missing {type_name}")
    fields = value["fields"]
    if not isinstance(fields, Mapping) or any(not isinstance(key, str) for key in fields):
        raise CandidateRenderError(f"materialized {type_name} fields are invalid")
    if expected_fields is not None and set(fields) != expected_fields:
        raise CandidateRenderError(f"materialized {type_name} fields are incomplete")
    return fields


def _resolved_use(value: Any) -> Mapping[str, FrozenJSON]:
    if isinstance(value, Mapping) and set(value) == _RESOLVED_USE_FIELDS:
        return value
    return _tagged(value, "ResolvedAttributeUseIR", _RESOLVED_USE_FIELDS)


def _string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise CandidateRenderError(f"materialized {field} is invalid")
    return value


def _integer(value: Any, field: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise CandidateRenderError(f"materialized {field} is invalid")
    return value


def _validate_portable_constraint_pattern(pattern: str, field: str) -> None:
    def uses_nonportable_escape() -> bool:
        index = 0
        while index < len(pattern):
            if pattern[index] != "\\":
                index += 1
                continue
            slash_start = index
            while index < len(pattern) and pattern[index] == "\\":
                index += 1
            if (index - slash_start) % 2 == 1 and index < len(pattern):
                escaped = pattern[index]
                if escaped == "x":
                    hexadecimal = pattern[index + 1 : index + 3]
                    if len(hexadecimal) != 2 or re.fullmatch(r"[0-9A-Fa-f]{2}", hexadecimal) is None:
                        return True
                    index += 3
                    continue
                if escaped in "nrtfv":
                    index += 1
                    continue
                if escaped not in r"\.^$|?*+()[]{}-":
                    return True
                index += 1
        return False

    def uses_nonportable_repetition() -> bool:
        index = 0
        in_character_class = False
        while index < len(pattern):
            if pattern[index] == "\\":
                index += 2
                continue
            if pattern[index] == "[":
                in_character_class = True
                index += 1
                continue
            if pattern[index] == "]" and in_character_class:
                in_character_class = False
                index += 1
                continue
            if in_character_class:
                index += 1
                continue
            if pattern[index] in "*+?" and index + 1 < len(pattern) and pattern[index + 1] == "+":
                return True
            if pattern[index] == "{":
                closing = pattern.find("}", index + 1)
                if closing == -1:
                    return True
                quantifier = re.fullmatch(r"([0-9]+)(?:,([0-9]*))?", pattern[index + 1 : closing])
                if quantifier is None:
                    return True
                lower = int(quantifier.group(1))
                upper_text = quantifier.group(2)
                upper = None if upper_text in {None, ""} else int(upper_text)
                if lower > 1000 or (upper is not None and (upper > 1000 or upper < lower)):
                    return True
                if closing + 1 < len(pattern) and pattern[closing + 1] == "+":
                    return True
                index = closing + 1
                continue
            if pattern[index] == "}":
                return True
            index += 1
        return False

    if "(?" in pattern or uses_nonportable_escape() or uses_nonportable_repetition():
        raise CandidateRenderError(f"materialized {field} pattern is outside the portable subset")
    try:
        re.compile(pattern)
    except re.error as exc:
        raise CandidateRenderError(f"materialized {field} pattern is invalid") from exc


def _validated_constraint_map(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise CandidateRenderError(f"materialized {field} is invalid")
    if set(value) - _CONSTRAINT_KEYS:
        raise CandidateRenderError(f"materialized {field} contains an unknown constraint")
    result: dict[str, Any] = {}
    for key, item in value.items():
        if key == "enum":
            if not isinstance(item, (list, tuple)) or not item:
                raise CandidateRenderError(f"materialized {field} enum is invalid")
            seen: set[tuple[type[Any], Any]] = set()
            for member in item:
                if type(member) not in {str, bool, int, float} or (type(member) is float and not math.isfinite(member)):
                    raise CandidateRenderError(f"materialized {field} enum is invalid")
                marker = (type(member), member)
                if marker in seen:
                    raise CandidateRenderError(f"materialized {field} enum is duplicated")
                seen.add(marker)
            result[key] = tuple(item)
        elif key == "pattern":
            if not isinstance(item, str) or not item or len(item.encode("utf-8")) > 4096:
                raise CandidateRenderError(f"materialized {field} pattern is invalid")
            _validate_portable_constraint_pattern(item, field)
            result[key] = item
        elif key in {
            "min_items",
            "max_items",
            "max_utf8_bytes",
            "max_item_utf8_bytes",
            "max_depth",
            "max_properties",
        }:
            minimum = 0 if key == "min_items" else 1
            if type(item) is not int or item < minimum:
                raise CandidateRenderError(f"materialized {field} count is invalid")
            result[key] = item
        elif type(item) not in {int, float} or (type(item) is float and not math.isfinite(item)):
            raise CandidateRenderError(f"materialized {field} numeric bound is invalid")
        else:
            result[key] = item
    if "min" in result and "max" in result and result["min"] > result["max"]:
        raise CandidateRenderError(f"materialized {field} numeric range is invalid")
    if "min_items" in result and "max_items" in result and result["min_items"] > result["max_items"]:
        raise CandidateRenderError(f"materialized {field} item range is invalid")
    return result


def _validate_constraint_shape(
    constraints: Mapping[str, Any],
    field_types: Sequence[str],
    field: str,
    *,
    structured: bool = False,
    normalization: bool = False,
    polymorphic: bool = False,
    recursive_bounds: bool = False,
) -> None:
    types = set(field_types)
    string_types = {"string", "string[]", "timestamp"}
    numeric_types = {"int64", "uint32", "uint64", "double", "metric_number", "int64[]", "double[]"}
    integer_types = {"int64", "uint32", "uint64", "int64[]"}
    array_types = {"string[]", "boolean[]", "int64[]", "double[]", "array"}
    recursive_structured = (
        structured or recursive_bounds or bool(types & {"object", "array", "canonical_json", "field_class_map"})
    )
    collection_or_structured = structured or bool(
        types & (array_types | {"object", "canonical_json", "field_class_map"})
    )
    if "enum" in constraints:
        for value in constraints["enum"]:
            compatible = (
                (type(value) is str and bool(types & string_types))
                or (type(value) is bool and bool(types & {"boolean", "boolean[]"}))
                or (type(value) is int and bool(types & numeric_types))
                or (type(value) is float and bool(types & {"double", "metric_number", "double[]"}))
            )
            if not compatible:
                raise CandidateRenderError(f"materialized {field} enum member is incompatible")
    if "pattern" in constraints and (not types or not types.issubset(string_types)):
        raise CandidateRenderError(f"materialized {field} pattern is incompatible")
    if {"min", "max"} & constraints.keys() and (not types or not types.issubset(numeric_types)):
        raise CandidateRenderError(f"materialized {field} numeric bound is incompatible")
    if types & integer_types and any(
        key in constraints and type(constraints[key]) is not int for key in ("min", "max")
    ):
        raise CandidateRenderError(f"materialized {field} integer bound is inexact")
    if "min_items" in constraints and not collection_or_structured:
        raise CandidateRenderError(f"materialized {field} min_items is incompatible with a scalar")
    if constraints.get("min_items", 0) > 1 and polymorphic:
        raise CandidateRenderError(f"materialized {field} min_items is unsupported for polymorphic JSON")
    if "max_items" in constraints and not collection_or_structured and not normalization:
        raise CandidateRenderError(f"materialized {field} max_items is incompatible with a scalar")
    if "max_utf8_bytes" in constraints and not (
        structured or bool(types & (string_types | {"bytes", "object", "array", "canonical_json", "field_class_map"}))
    ):
        raise CandidateRenderError(f"materialized {field} UTF-8 bound is incompatible")
    if "max_item_utf8_bytes" in constraints and not (
        recursive_structured or "string[]" in types or (normalization and bool(types & {"string", "timestamp"}))
    ):
        raise CandidateRenderError(f"materialized {field} item UTF-8 bound is incompatible")
    if {"max_depth", "max_properties"} & constraints.keys() and not recursive_structured:
        raise CandidateRenderError(f"materialized {field} structured bound is incompatible")


def _validate_constraint_restriction(
    constraints: Mapping[str, Any],
    normalization: Mapping[str, Any],
    field: str,
) -> None:
    if "pattern" in constraints and "pattern" in normalization and constraints["pattern"] != normalization["pattern"]:
        raise CandidateRenderError(f"materialized {field} pattern weakens normalization")
    for maximum in (
        "max",
        "max_items",
        "max_utf8_bytes",
        "max_item_utf8_bytes",
        "max_depth",
        "max_properties",
    ):
        if maximum in constraints and maximum in normalization and constraints[maximum] > normalization[maximum]:
            raise CandidateRenderError(f"materialized {field} maximum weakens normalization")
    for minimum in ("min", "min_items"):
        if minimum in constraints and minimum in normalization and constraints[minimum] < normalization[minimum]:
            raise CandidateRenderError(f"materialized {field} minimum weakens normalization")
    if "enum" in constraints and "enum" in normalization:
        allowed = {(type(item), item) for item in normalization["enum"]}
        if any((type(item), item) not in allowed for item in constraints["enum"]):
            raise CandidateRenderError(f"materialized {field} enum weakens normalization")


def _derive_resolved_constraints(origins: tuple[Mapping[str, FrozenJSON], ...]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    minimum_keys = {"min", "min_items"}
    maximum_keys = {
        "max",
        "max_items",
        "max_utf8_bytes",
        "max_item_utf8_bytes",
        "max_depth",
        "max_properties",
    }
    for origin in origins:
        constraints = _validated_constraint_map(origin["constraints"], "resolved-use origin constraints")
        for key, value in constraints.items():
            if key == "enum":
                if "enum" not in result:
                    result["enum"] = value
                else:
                    allowed = {(type(item), item) for item in value}
                    result["enum"] = tuple(item for item in result["enum"] if (type(item), item) in allowed)
            elif key == "pattern":
                if "pattern" in result and result["pattern"] != value:
                    raise CandidateRenderError("materialized resolved-use patterns disagree")
                result["pattern"] = value
            elif key in minimum_keys:
                result[key] = value if key not in result else max(result[key], value)
            elif key in maximum_keys:
                result[key] = value if key not in result else min(result[key], value)
    for minimum, maximum in (("min", "max"), ("min_items", "max_items")):
        if minimum in result and maximum in result and result[minimum] > result[maximum]:
            raise CandidateRenderError("materialized resolved-use constraint range is empty")
    if (
        "max_item_utf8_bytes" in result
        and "max_utf8_bytes" in result
        and result["max_item_utf8_bytes"] > result["max_utf8_bytes"]
    ):
        raise CandidateRenderError("materialized resolved-use UTF-8 bounds are inconsistent")
    if "enum" in result:
        enum_values = result["enum"]
        if "pattern" in result:
            pattern = re.compile(result["pattern"])
            enum_values = tuple(
                value for value in enum_values if isinstance(value, str) and pattern.fullmatch(value) is not None
            )
        if "min" in result:
            enum_values = tuple(
                value for value in enum_values if type(value) in {int, float} and value >= result["min"]
            )
        if "max" in result:
            enum_values = tuple(
                value for value in enum_values if type(value) in {int, float} and value <= result["max"]
            )
        if "max_utf8_bytes" in result:
            enum_values = tuple(
                value
                for value in enum_values
                if not isinstance(value, str) or len(value.encode("utf-8")) <= result["max_utf8_bytes"]
            )
        if not enum_values:
            raise CandidateRenderError("materialized resolved-use enum intersection is empty")
        result["enum"] = enum_values
    return result


def _validate_normalizer_catalog(value: FrozenJSON) -> None:
    if not isinstance(value, tuple) or len(value) != len(_EXPECTED_NORMALIZER_CATALOG):
        raise CandidateRenderError("materialized normalizer catalog is incomplete")
    observed_ids: list[str] = []
    for raw_normalizer in value:
        normalizer = _tagged(raw_normalizer, "NormalizerIR", _NORMALIZER_FIELDS)
        normalizer_id = _string(normalizer["id"], "normalizer id")
        expected = _EXPECTED_NORMALIZER_CATALOG.get(normalizer_id)
        if expected is None or normalizer_id in observed_ids:
            raise CandidateRenderError("materialized normalizer catalog is invalid")
        kind, defaults, allowed = expected
        observed_defaults = _validated_constraint_map(
            normalizer["default_constraints"],
            "normalizer default constraints",
        )
        if (
            normalizer["kind"] != kind
            or _typed_materialized_node(observed_defaults) != _typed_materialized_node(defaults)
            or normalizer["allowed_overrides"] != tuple(sorted(allowed))
        ):
            raise CandidateRenderError("materialized normalizer catalog differs from v1")
        observed_ids.append(normalizer_id)
    if tuple(observed_ids) != tuple(_EXPECTED_NORMALIZER_CATALOG):
        raise CandidateRenderError("materialized normalizer catalog order is invalid")


def _origin_projection(raw_origin: FrozenJSON) -> dict[str, Any]:
    origin = _tagged(raw_origin, "AttributeUseOriginIR", _ATTRIBUTE_USE_ORIGIN_FIELDS)
    return {
        "group_id": origin["group_id"],
        "role": origin["role"],
        "requirement_level": origin["requirement_level"],
        "conditional": origin["conditional"],
        "constraints": _validated_constraint_map(
            origin["constraints"],
            "resolved-use origin constraints",
        ),
    }


def _resolved_use_projection(raw_use: FrozenJSON) -> dict[str, Any]:
    use = _resolved_use(raw_use)
    origins = use["origins"]
    if not isinstance(origins, tuple):
        raise CandidateRenderError("materialized resolved attribute origins are invalid")
    return {
        "ref": use["ref"],
        "role": use["role"],
        "requirement_level": use["requirement_level"],
        "conditional": use["conditional"],
        "constraints": _validated_constraint_map(use["constraints"], "resolved-use constraints"),
        "origins": tuple(_origin_projection(origin) for origin in origins),
    }


def _recompute_resolved_group_uses(
    groups: Mapping[str, Mapping[str, FrozenJSON]],
) -> tuple[dict[str, tuple[dict[str, Any], ...]], tuple[str, ...]]:
    state: dict[str, int] = {}
    resolved: dict[str, tuple[dict[str, Any], ...]] = {}
    resolution_order: list[str] = []

    def visit(group_id: str) -> tuple[dict[str, Any], ...]:
        if state.get(group_id) == 1:
            raise CandidateRenderError("materialized group inheritance is cyclic")
        if state.get(group_id) == 2:
            return resolved[group_id]
        group = groups[group_id]
        group_type = group["type"]
        if group_type == "attribute_group":
            allowed_parent_types = {"attribute_group"}
            resolved_role = "attributes"
        elif group_type == "body_group":
            allowed_parent_types = {"attribute_group", "body_group"}
            resolved_role = "body_fields"
        elif group_type == "log":
            allowed_parent_types = {"body_group"}
            resolved_role = "body_fields"
        else:
            allowed_parent_types = {"attribute_group"}
            resolved_role = "attributes"
        state[group_id] = 1
        contributions: dict[str, list[dict[str, Any]]] = {}
        reference_order: list[str] = []

        def contribute(reference: str, origins: Sequence[dict[str, Any]]) -> None:
            if reference not in contributions:
                contributions[reference] = []
                reference_order.append(reference)
            identities = {_typed_materialized_node(origin) for origin in contributions[reference]}
            for origin in origins:
                identity = _typed_materialized_node(origin)
                if identity not in identities:
                    contributions[reference].append(origin)
                    identities.add(identity)

        parents = group["extends"]
        if not isinstance(parents, tuple):
            raise CandidateRenderError("materialized group parents are invalid")
        if group_type == "log" and len(parents) != 1:
            raise CandidateRenderError("materialized log group parent count is invalid")
        for parent_id in parents:
            parent = groups.get(parent_id)
            if parent is None or parent["type"] not in allowed_parent_types:
                raise CandidateRenderError("materialized group parent is invalid")
            for inherited in visit(parent_id):
                if resolved_role == "attributes" and inherited["role"] != "attributes":
                    raise CandidateRenderError("materialized body role crosses into attribute group")
                contribute(inherited["ref"], inherited["origins"])
        for raw_direct in group["attribute_uses"]:
            direct = _tagged(raw_direct, "AttributeUseIR", _ATTRIBUTE_USE_FIELDS)
            if resolved_role == "attributes" and direct["role"] != "attributes":
                raise CandidateRenderError("materialized direct body role is invalid")
            constraints = _validated_constraint_map(direct["constraints"], "direct-use constraints")
            contribute(
                direct["ref"],
                (
                    {
                        "group_id": group_id,
                        "role": direct["role"],
                        "requirement_level": direct["requirement_level"],
                        "conditional": direct["conditional"],
                        "constraints": constraints,
                    },
                ),
            )
        materialized: list[dict[str, Any]] = []
        for reference in reference_order:
            origins = tuple(contributions[reference])
            dominant = max(
                origins,
                key=lambda origin: _REQUIREMENT_RANK[origin["requirement_level"]],
            )["requirement_level"]
            dominant_origins = tuple(origin for origin in origins if origin["requirement_level"] == dominant)
            clauses = tuple(dict.fromkeys(origin["conditional"] for origin in dominant_origins))
            if len(clauses) != 1:
                raise CandidateRenderError("materialized dominant conditional is ambiguous")
            conditional = clauses[0]
            if dominant == "conditional" and conditional is None:
                raise CandidateRenderError("materialized dominant conditional is absent")
            materialized.append(
                {
                    "ref": reference,
                    "role": resolved_role,
                    "requirement_level": dominant,
                    "conditional": conditional,
                    "constraints": _derive_resolved_constraints(origins),
                    "origins": origins,
                }
            )
        resolved[group_id] = tuple(materialized)
        state[group_id] = 2
        resolution_order.append(group_id)
        return resolved[group_id]

    for group_id in groups:
        visit(group_id)
    return resolved, tuple(resolution_order)


def _deterministic_json_value(value: Any, *, root: bool = False) -> Any:
    if isinstance(value, Mapping):
        keys = sorted(value)
        if root and "x-defenseclaw-generated" in value:
            keys.remove("x-defenseclaw-generated")
            keys.insert(0, "x-defenseclaw-generated")
        return {key: _deterministic_json_value(value[key]) for key in keys}
    if isinstance(value, (list, tuple)):
        return [_deterministic_json_value(item) for item in value]
    return value


def _json_payload(value: Mapping[str, Any]) -> bytes:
    ordered = _deterministic_json_value(value, root=True)
    return (json.dumps(ordered, ensure_ascii=False, indent=2, sort_keys=False, allow_nan=False) + "\n").encode("utf-8")


def _authority_marker(*, registry_version: int, digest: str, artifact: str) -> JSONObject:
    return {
        "artifact": artifact,
        "authority": CANDIDATE_AUTHORITY,
        "generator": GENERATOR_ID,
        "materialized_view_sha256": digest,
        "registry_version": registry_version,
    }


def _validate_v7_exporter_selection_materialized(
    fields: Mapping[str, FrozenJSON],
    domains: tuple[CandidateDomain, ...],
    groups: Mapping[str, Mapping[str, FrozenJSON]],
) -> None:
    if fields["v7_exporter_selection_schema_path"] != (
        "schemas/telemetry/v8/compatibility/v7-exporter-selection.schema.json"
    ):
        raise CandidateRenderError("materialized v7 exporter selection schema path is invalid")
    schema = _plain(fields["v7_exporter_selection_schema"])
    if not isinstance(schema, dict) or schema.get("$id") != (
        "https://defenseclaw.dev/schemas/telemetry/v8/compatibility/v7-exporter-selection.schema.json"
    ):
        raise CandidateRenderError("materialized v7 exporter selection schema is invalid")
    selection = _plain(fields["v7_exporter_selection"])
    required = {
        "schema_version",
        "source_config_version",
        "projection_profile",
        "collection",
        "exporters",
        "features",
        "span_filter_operations",
        "local_observability",
    }
    if not isinstance(selection, dict) or set(selection) != required:
        raise CandidateRenderError("materialized v7 exporter selection fields are invalid")
    if (
        selection["schema_version"] != 1
        or selection["source_config_version"] != 7
        or selection["projection_profile"] != "legacy-v7"
        or selection["local_observability"] != {"complete": True, "profile_id": "local-observability-v1"}
    ):
        raise CandidateRenderError("materialized v7 exporter selection metadata is invalid")

    buckets = set(_V7_BUCKETS)
    known_events = {
        value
        for group in groups.values()
        for value in (group.get("id"), group.get("event_name"), group.get("instrument_name"))
        if isinstance(value, str)
    }
    mappings = [mapping for domain in domains for mapping in domain.producer_mappings]
    audit_actions = sorted(mapping["key"] for mapping in mappings if mapping["producer"] == "audit_action")
    gateway_mappings = {mapping["key"]: mapping for mapping in mappings if mapping["producer"] == "gateway_event"}

    def identity_names(mapping: Mapping[str, FrozenJSON]) -> set[str]:
        identities: list[Mapping[str, FrozenJSON]] = []
        default = mapping.get("default_identity")
        if isinstance(default, Mapping):
            identities.append(default)
        contexts = mapping.get("allowed_context_identities")
        if not isinstance(contexts, tuple):
            raise CandidateRenderError("materialized v7 producer identities are invalid")
        identities.extend(identity for identity in contexts if isinstance(identity, Mapping))
        if len(identities) != (1 if isinstance(default, Mapping) else 0) + len(contexts):
            raise CandidateRenderError("materialized v7 producer identities are invalid")
        names = {identity.get("event_name") for identity in identities}
        if not names or any(not isinstance(name, str) for name in names):
            raise CandidateRenderError("materialized v7 producer identities are incomplete")
        return {name for name in names if isinstance(name, str)}

    gateway_event_names = sorted({name for mapping in gateway_mappings.values() for name in identity_names(mapping)})
    forwarded_event_names = sorted(
        {name for key in _V7_AUDIT_GATEWAY_EVENT_KEYS for name in identity_names(gateway_mappings[key])}
    )
    known_events.update(gateway_event_names)
    exporters = selection["exporters"]
    expected_signals = {
        "gateway_jsonl": {"logs"},
        "gateway_console": {"logs"},
        "audit_sink": {"logs"},
        "generic_otlp": {"logs", "traces", "metrics"},
        "galileo": {"traces"},
        "local_observability": {"logs", "traces", "metrics"},
    }
    if not isinstance(exporters, dict) or set(exporters) != set(expected_signals):
        raise CandidateRenderError("materialized v7 exporter inventory is invalid")

    def validate_selectors(raw: Any) -> None:
        if not isinstance(raw, list) or not 1 <= len(raw) <= 256:
            raise CandidateRenderError("materialized v7 selector inventory is invalid")
        for selector in raw:
            if (
                not isinstance(selector, dict)
                or not selector
                or not set(selector)
                <= {
                    "buckets",
                    "sources",
                    "actions",
                    "event_names",
                }
            ):
                raise CandidateRenderError("materialized v7 selector shape is invalid")
            for name, values in selector.items():
                if (
                    not isinstance(values, list)
                    or not values
                    or len(values) != len(set(values))
                    or (name != "buckets" and values != sorted(values))
                    or any(
                        not isinstance(value, str) or value == "*" or _V7_COMPATIBILITY_TOKEN.fullmatch(value) is None
                        for value in values
                    )
                ):
                    raise CandidateRenderError("materialized v7 selector values are invalid")
                allowed = (
                    buckets
                    if name == "buckets"
                    else (set(audit_actions) if name == "actions" else known_events if name == "event_names" else None)
                )
                if allowed is not None and not set(values) <= allowed:
                    raise CandidateRenderError("materialized v7 selector references are invalid")

    for exporter, signal_names in expected_signals.items():
        profile = exporters[exporter]
        if not isinstance(profile, dict) or set(profile) != signal_names:
            raise CandidateRenderError("materialized v7 exporter signal inventory is invalid")
        for selectors in profile.values():
            validate_selectors(selectors)
    expected_gateway_selector = [{"event_names": gateway_event_names}]
    span_event_names = sorted(group_id for group_id, group in groups.items() if group.get("type") == "span")
    expected_all_bucket_selector = [{"buckets": list(_V7_BUCKETS)}]
    expected_all_span_selector = [{"event_names": span_event_names}]
    collection = selection["collection"]
    if not isinstance(collection, dict) or set(collection) != {
        "always",
        "otel.logs",
        "otel.traces",
        "otel.metrics",
    }:
        raise CandidateRenderError("materialized v7 collection inventory is invalid")
    if collection["always"] != {
        "logs": list(_V7_BUCKETS),
        "traces": [],
        "metrics": [],
    }:
        raise CandidateRenderError("materialized v7 always-collected log coverage is invalid")
    for condition, selected_signal in (
        ("otel.logs", "logs"),
        ("otel.traces", "traces"),
        ("otel.metrics", "metrics"),
    ):
        signals = collection[condition]
        if not isinstance(signals, dict) or set(signals) != {"logs", "traces", "metrics"}:
            raise CandidateRenderError("materialized v7 collection signal inventory is invalid")
        if signals[selected_signal] != list(_V7_BUCKETS) or any(
            signals[signal] for signal in ("logs", "traces", "metrics") if signal != selected_signal
        ):
            raise CandidateRenderError("materialized v7 conditional collection coverage is invalid")
    if (
        exporters["gateway_jsonl"]["logs"] != expected_gateway_selector
        or exporters["gateway_console"]["logs"] != expected_gateway_selector
        or exporters["audit_sink"]["logs"] != [{"actions": audit_actions}, {"event_names": forwarded_event_names}]
        or exporters["generic_otlp"]["logs"] != expected_all_bucket_selector
        or exporters["generic_otlp"]["traces"] != expected_all_span_selector
        or exporters["generic_otlp"]["metrics"] != expected_all_bucket_selector
        or exporters["local_observability"]["logs"] != expected_all_bucket_selector
        or exporters["local_observability"]["traces"] != expected_all_span_selector
        or exporters["local_observability"]["metrics"] != expected_all_bucket_selector
    ):
        raise CandidateRenderError("materialized v7 producer-derived selectors disagree")


def _candidate_conformance_scope() -> JSONObject:
    return {
        "scope": "canonical-schema-comparison-only",
        "builder_parity": "pending-source-inputs",
        "otlp_projection": "candidate",
        "required_materialized_inputs": [
            "builder_facts",
            "deterministic_occurrence_inputs",
        ],
        "non_json_schema_gates": [
            "builder_fact_conditions",
            "canonical_json_byte_depth_and_property_bounds",
            "complete_payload_leaf_field_class_coverage",
            "deterministic_record_and_occurrence_identity",
            "ordinary_shape_aware_utf8_byte_bounds",
            "ordinary_container_depth_bounds",
            "ordinary_string_leaf_utf8_byte_bounds",
            "portable_re2_full_match_patterns",
            "recursive_aggregate_max_items",
            "recursive_property_count_bounds",
            "typed_json_enum_membership",
            "typed_numeric_arm_int64_vs_finite_double",
            "span_name_pattern_rendering",
            "trace_cross_field_derivation_equality",
            "trace_time_order_relation",
        ],
        "claim": "No generated-builder or producer parity is claimed by this candidate slice.",
    }


def _normalization(
    fields: Mapping[str, FrozenJSON],
    *,
    field_types: Sequence[str] = (),
    structured: bool = False,
    polymorphic: bool = False,
) -> JSONObject:
    node = _tagged(fields["normalization"], "NormalizationIR", _NORMALIZATION_FIELDS)
    effective = node.get("effective_constraints")
    overrides = node.get("overrides")
    if not isinstance(effective, Mapping) or not isinstance(overrides, Mapping):
        raise CandidateRenderError("materialized normalization is invalid")
    validated_overrides = _validated_constraint_map(overrides, "normalization overrides")
    validated_effective = _validated_constraint_map(effective, "normalization effective constraints")
    normalization_id = _string(node.get("id"), "normalization id")
    catalog_entry = _EXPECTED_NORMALIZER_CATALOG.get(normalization_id)
    if catalog_entry is None:
        raise CandidateRenderError("materialized normalization id is unknown")
    _, catalog_defaults, allowed_overrides = catalog_entry
    if not set(validated_overrides).issubset(allowed_overrides):
        raise CandidateRenderError("materialized normalization override is not allowed")
    expected_effective = {**catalog_defaults, **validated_overrides}
    if _typed_materialized_node(validated_effective) != _typed_materialized_node(expected_effective):
        raise CandidateRenderError("materialized normalization effective constraints are forged")
    _validate_constraint_shape(
        validated_effective,
        field_types,
        "normalization effective constraints",
        structured=structured,
        normalization=True,
        polymorphic=polymorphic,
        recursive_bounds=normalization_id in {"structured-content-v1", "redacted-content-v1"},
    )
    return {
        "id": normalization_id,
        "overrides": _plain(validated_overrides),
        "effective_constraints": _plain(validated_effective),
        "notes": _plain(node.get("notes")),
    }


def _numeric_union_schema() -> JSONObject:
    return {
        "anyOf": [
            {"type": "integer", "minimum": -(2**63), "maximum": 2**63 - 1},
            {"type": "number", "x-defenseclaw-finite": True},
        ],
        "x-defenseclaw-numeric-kind-runtime": "typed-int64-or-finite-double",
        "x-defenseclaw-json-schema-overlap": "integral-valued-double-requires-runtime-kind",
    }


def _runtime_numeric_arm_accepts(value: Any, arm: str) -> bool:
    if arm == "int64":
        return type(value) is int and -(2**63) <= value <= 2**63 - 1
    if arm == "finite_double":
        return type(value) is float and math.isfinite(value)
    return False


def _schema_type(field_type: str) -> JSONObject:
    if field_type in {"string", "timestamp"}:
        result: JSONObject = {"type": "string"}
        if field_type == "timestamp":
            result.update({"format": "date-time", "x-defenseclaw-format": "utc-rfc3339-nano"})
        return result
    if field_type == "boolean":
        return {"type": "boolean"}
    if field_type == "int64":
        return {"type": "integer", "minimum": -(2**63), "maximum": 2**63 - 1}
    if field_type == "uint32":
        return {"type": "integer", "minimum": 0, "maximum": 2**32 - 1}
    if field_type == "uint64":
        return {"type": "integer", "minimum": 0, "maximum": 2**64 - 1}
    if field_type == "double":
        return {"type": "number", "x-defenseclaw-finite": True}
    if field_type == "metric_number":
        return _numeric_union_schema()
    if field_type in {"string[]", "double[]", "int64[]", "boolean[]"}:
        item_type = field_type.removesuffix("[]")
        return {"type": "array", "items": _schema_type(item_type)}
    if field_type == "array":
        return {"type": "array"}
    if field_type == "object":
        return {"type": "object"}
    if field_type == "canonical_json":
        return {"$ref": f"#/$defs/{CANONICAL_JSON_DEFINITION}"}
    if field_type == "field_class_map":
        return {
            "type": "object",
            "propertyNames": {"pattern": r"^(?:/(?:[^~/]|~[01])*)+$"},
            "additionalProperties": {"enum": list(_FIELD_CLASSES)},
        }
    raise CandidateRenderError("materialized field type is unsupported")


def _canonical_json_schema() -> JSONObject:
    """Return the recursively closed canonical JSON value union.

    Canonical telemetry JSON deliberately excludes null because the canonical
    OTLP representation declares ``null_value_policy: reject``.  Array items
    and object values recurse through the same definition so null cannot be
    hidden below an otherwise valid container.
    """

    reference = {"$ref": f"#/$defs/{CANONICAL_JSON_DEFINITION}"}
    return {
        "oneOf": [
            {"type": "boolean"},
            _numeric_union_schema(),
            {"type": "string"},
            {"type": "array", "items": reference},
            {"type": "object", "additionalProperties": reference},
        ],
        "x-defenseclaw-null-policy": "reject",
    }


def _structured_ref_schema(reference: Mapping[str, Any]) -> JSONObject:
    return {"$ref": f"#/$defs/structured:{_string(reference['structured_ref'], 'structured reference')}"}


def _structured_scalar_schema(scalar: Mapping[str, Any]) -> JSONObject:
    schema = _schema_type(_string(scalar["field_type"], "structured scalar type"))
    normalization = scalar["normalization"]
    if not isinstance(normalization, Mapping) or not isinstance(normalization.get("effective_constraints"), Mapping):
        raise CandidateRenderError("structured scalar normalization is invalid")
    schema = _apply_constraints(
        schema,
        normalization["effective_constraints"],
        normalization_id=normalization["id"],
    )
    schema["x-defenseclaw-field-class"] = scalar["field_class"]
    schema["x-defenseclaw-sensitivity"] = scalar["sensitivity"]
    schema["x-defenseclaw-normalization"] = _plain(normalization)
    if scalar.get("known_values"):
        schema["x-defenseclaw-known-values"] = _plain(scalar["known_values"])
        schema["x-defenseclaw-known-values-enforcement"] = "non-enforcing"
    encoding_annotation = scalar.get("encoding_annotation")
    if encoding_annotation is not None:
        if encoding_annotation != "json-base64-bytes-v1":
            raise CandidateRenderError("structured scalar encoding annotation is invalid")
        schema["contentEncoding"] = "base64"
        schema["x-defenseclaw-upstream-format"] = "binary"
        schema["x-defenseclaw-encoding-annotation"] = encoding_annotation
    return schema


def _structured_type_schema(item: Mapping[str, Any]) -> JSONObject:
    type_id = _string(item["id"], "structured type id")
    kind = item["kind"]
    if kind == "canonical_json":
        canonical = item["canonical_json"]
        if not isinstance(canonical, Mapping) or not isinstance(canonical.get("limits"), Mapping):
            raise CandidateRenderError("structured canonical JSON contract is invalid")
        limits = canonical["limits"]
        reference = {"$ref": f"#/$defs/structured:{type_id}"}
        value_annotations = {
            "x-defenseclaw-field-class": canonical["leaf_field_class"],
            "x-defenseclaw-sensitivity": canonical["leaf_sensitivity"],
        }
        string_schema: JSONObject = {
            "type": "string",
            "x-defenseclaw-max-utf8-bytes": limits["max_string_utf8_bytes"],
            **value_annotations,
        }
        object_schema: JSONObject = {
            "type": "object",
            "maxProperties": limits["max_aggregate_members"],
            "additionalProperties": reference,
            "propertyNames": {
                "type": "string",
                "x-defenseclaw-max-utf8-bytes": limits["max_member_name_utf8_bytes"],
            },
            "x-defenseclaw-public-encoding": canonical["public_encoding"],
            "x-defenseclaw-wire-encoding": canonical["wire_encoding"],
            "x-defenseclaw-member-id": canonical["object_member_id"],
            "x-defenseclaw-member-name": _plain(canonical["object_name"]),
            "x-defenseclaw-duplicate-name-policy": canonical["duplicate_name_policy"],
            "x-defenseclaw-fixed-name-collision-policy": canonical["fixed_name_collision_policy"],
            "x-defenseclaw-post-redaction-name-collision-policy": canonical["post_redaction_name_collision_policy"],
        }
        result: JSONObject = {
            "oneOf": [
                {"type": "boolean", **value_annotations},
                {
                    **_numeric_union_schema(),
                    **value_annotations,
                },
                string_schema,
                {
                    "type": "array",
                    "maxItems": limits["max_array_items"],
                    "items": reference,
                },
                object_schema,
            ],
            "x-defenseclaw-null-policy": "reject",
            "x-defenseclaw-internal-discriminator": {
                "visibility": canonical["discriminator_visibility"],
                "wire": canonical["discriminator_wire"],
            },
            "x-defenseclaw-limits": _plain(limits),
            "x-defenseclaw-limit-semantics": {
                "depth_root": 0,
                "aggregate_members": "all-object-entries-and-array-elements",
                "item_bytes": "canonical-immediate-value-subtree",
                "canonical_bytes": "complete-canonical-utf8-json",
                "inclusive": True,
                "recheck_after_redaction": True,
            },
        }
        return result
    if kind == "array":
        items = item["items_scalar"]
        if items is not None:
            item_schema = _structured_scalar_schema(items)
        else:
            reference = item["items_reference"]
            if not isinstance(reference, Mapping):
                raise CandidateRenderError("structured array item reference is missing")
            item_schema = _structured_ref_schema(reference)
        return {
            "type": "array",
            "minItems": item["min_items"],
            "maxItems": item["max_items"],
            "items": item_schema,
        }
    if kind == "object":
        properties: JSONObject = {}
        required: list[str] = []
        for field in item["fields"] or ():
            if not isinstance(field, Mapping):
                raise CandidateRenderError("structured object field is invalid")
            scalar = field["scalar"]
            reference = field["reference"]
            schema = (
                _structured_scalar_schema(scalar)
                if isinstance(scalar, Mapping)
                else _structured_ref_schema(reference)
                if isinstance(reference, Mapping)
                else None
            )
            if schema is None:
                raise CandidateRenderError("structured object field arm is missing")
            if field["nullable_omission"] is True:
                schema["x-defenseclaw-nullable-input-policy"] = "omit"
            properties[_string(field["name"], "structured field name")] = schema
            if field["required"] is True:
                required.append(field["name"])
        dynamic = item["dynamic_members"]
        if dynamic is None:
            additional: bool | JSONObject = False
            dynamic_metadata = None
        elif isinstance(dynamic, Mapping):
            additional = _structured_ref_schema(dynamic["value"])
            dynamic_metadata = {
                "member_id": dynamic["member_id"],
                "name": _plain(dynamic["name"]),
                "max_items": dynamic["max_items"],
                "public_encoding": dynamic["public_encoding"],
                "wire_encoding": dynamic["wire_encoding"],
                "duplicate_name_policy": dynamic["duplicate_name_policy"],
                "fixed_name_collision_policy": dynamic["fixed_name_collision_policy"],
                "post_redaction_name_collision_policy": dynamic["post_redaction_name_collision_policy"],
                "reserved_names": _plain(dynamic["reserved_names"]),
            }
        else:
            raise CandidateRenderError("structured dynamic member contract is invalid")
        result = {
            "type": "object",
            "additionalProperties": additional,
            "properties": properties,
            "required": required,
            "x-defenseclaw-reserved-names": _plain(item["effective_reserved_names"]),
        }
        if dynamic_metadata is not None:
            result["x-defenseclaw-dynamic-members"] = dynamic_metadata
            result["x-defenseclaw-max-dynamic-members"] = dynamic["max_items"]
            optional_names = tuple(field["name"] for field in item["fields"] or () if field["required"] is False)
            required_names = {field["name"] for field in item["fields"] or () if field["required"] is True}
            union_owned_names = tuple(
                sorted(set(item["effective_reserved_names"]) - {field["name"] for field in item["fields"] or ()})
            )
            conditional_names = (*optional_names, *union_owned_names)
            base_count = len(required_names)
            if not conditional_names:
                result["maxProperties"] = base_count + dynamic["max_items"]
            else:
                branches: list[JSONObject] = []
                for mask in range(1 << len(conditional_names)):
                    predicates: list[JSONObject] = []
                    present_count = 0
                    for index, name in enumerate(conditional_names):
                        if mask & (1 << index):
                            predicates.append({"required": [name]})
                            present_count += 1
                        else:
                            predicates.append({"not": {"required": [name]}})
                    branches.append(
                        {
                            "if": {"allOf": predicates},
                            "then": {"maxProperties": base_count + present_count + dynamic["max_items"]},
                        }
                    )
                result["allOf"] = branches
        return result
    if kind == "tagged_union":
        discriminator = item["discriminator"]
        if not isinstance(discriminator, Mapping):
            raise CandidateRenderError("structured union discriminator is missing")
        discriminator_name = _string(discriminator["name"], "structured discriminator name")
        choices: list[JSONObject] = []
        tags: list[str] = []
        for variant in item["variants"] or ():
            if not isinstance(variant, Mapping):
                raise CandidateRenderError("structured union variant is invalid")
            tag = _string(variant["tag"], "structured union tag")
            tags.append(tag)
            choices.append(
                {
                    "allOf": [
                        _structured_ref_schema(variant),
                        {
                            "type": "object",
                            "properties": {discriminator_name: {"const": tag}},
                            "required": [discriminator_name],
                        },
                    ],
                    "x-defenseclaw-arm-id": tag,
                }
            )
        dynamic = item["dynamic_variant"]
        if isinstance(dynamic, Mapping):
            choices.append(
                {
                    "allOf": [
                        _structured_ref_schema(dynamic),
                        {
                            "type": "object",
                            "properties": {discriminator_name: {"type": "string", "not": {"enum": tags}}},
                            "required": [discriminator_name],
                        },
                    ],
                    "x-defenseclaw-arm-id": dynamic["arm_id"],
                    "x-defenseclaw-exclude-registered-tags": dynamic["exclude_registered_tags"],
                }
            )
        return {
            "oneOf": choices,
            "x-defenseclaw-discriminator": {
                "name": discriminator_name,
                "owner": "tagged_union",
                "serialized_once": True,
                "field_class": discriminator["field_class"],
                "sensitivity": discriminator["sensitivity"],
                "normalization": _plain(discriminator["normalization"]),
            },
        }
    raise CandidateRenderError("structured type kind is unsupported")


def _apply_constraints(
    schema: JSONObject,
    constraints: Mapping[str, Any],
    *,
    normalization_id: str | None = None,
) -> JSONObject:
    constraints = _validated_constraint_map(constraints, "candidate constraints")
    result = _plain(schema)
    if not isinstance(result, dict):
        raise CandidateRenderError("candidate schema is invalid")

    def schema_field_types(node: JSONObject) -> tuple[tuple[str, ...], bool]:
        variants = node.get("oneOf")
        if isinstance(variants, list):
            resolved = [schema_field_types(variant) for variant in variants if isinstance(variant, dict)]
            return tuple(dict.fromkeys(item for types, _ in resolved for item in types)), any(
                structured for _, structured in resolved
            )
        if "$ref" in node:
            return ("canonical_json",), True
        field_type = node.get("type")
        if field_type == "array":
            items = node.get("items")
            if isinstance(items, dict):
                item_type = items.get("type")
                array_type = {
                    "string": "string[]",
                    "boolean": "boolean[]",
                    "integer": "int64[]",
                    "number": "double[]",
                }.get(item_type)
                if array_type is not None:
                    return (array_type,), False
            return ("array",), True
        if field_type == "string":
            return ("string",), False
        if field_type == "boolean":
            return ("boolean",), False
        if field_type == "integer":
            return ("int64",), False
        if field_type == "number":
            return ("double",), False
        if field_type == "object":
            return ("object",), True
        if isinstance(node.get("anyOf"), list):
            return ("metric_number",), False
        return (), False

    inferred_types, inferred_structured = schema_field_types(result)
    inferred_polymorphic = result.get("$ref") == f"#/$defs/{CANONICAL_JSON_DEFINITION}"
    _validate_constraint_shape(
        constraints,
        inferred_types,
        "candidate constraints",
        structured=inferred_structured,
        normalization=normalization_id is not None,
        polymorphic=inferred_polymorphic,
        recursive_bounds=normalization_id in {"structured-content-v1", "redacted-content-v1"},
    )

    def value_targets(node: JSONObject) -> tuple[JSONObject, ...]:
        variants = node.get("oneOf")
        if isinstance(variants, list):
            return tuple(
                target for variant in variants if isinstance(variant, dict) for target in value_targets(variant)
            )
        if node.get("type") == "array":
            items = node.get("items")
            return (items,) if isinstance(items, dict) else ()
        return (node,)

    def collection_targets(node: JSONObject) -> tuple[JSONObject, ...]:
        variants = node.get("oneOf")
        if isinstance(variants, list):
            return tuple(
                target for variant in variants if isinstance(variant, dict) for target in collection_targets(variant)
            )
        if node.get("type") in {"array", "object"} or "$ref" in node:
            return (node,)
        return ()

    def tighten_minimum(target: JSONObject, keyword: str, value: Any) -> None:
        current = target.get(keyword)
        target[keyword] = value if current is None else max(current, value)

    def tighten_maximum(target: JSONObject, keyword: str, value: Any) -> None:
        current = target.get(keyword)
        target[keyword] = value if current is None else min(current, value)

    def typed_equal(left: Any, right: Any) -> bool:
        return type(left) is type(right) and left == right

    def intersect_enum(target: JSONObject, values: Any) -> None:
        incoming = _plain(values)
        if not isinstance(incoming, list) or not incoming:
            raise CandidateRenderError("candidate enum constraint is invalid")
        current = target.get("enum")
        if current is None:
            target["enum"] = incoming
        else:
            if not isinstance(current, list):
                raise CandidateRenderError("candidate schema enum is invalid")
            intersection = [item for item in current if any(typed_equal(item, candidate) for candidate in incoming)]
            if not intersection:
                raise CandidateRenderError("candidate enum constraint intersection is empty")
            target["enum"] = intersection
        target["x-defenseclaw-enum-membership-semantics"] = "typed-json-scalar"
        target["x-defenseclaw-enum-enforcement"] = "builder-runtime-typed-json-enum-gate"

    def apply_pattern(target: JSONObject, source_pattern: str) -> None:
        anchored = f"^(?:{source_pattern})$(?![\\s\\S])"
        existing_source = target.get("x-defenseclaw-pattern-source")
        if existing_source == source_pattern:
            return
        if existing_source is not None or ("pattern" in target and target["pattern"] != anchored):
            raise CandidateRenderError("candidate pattern constraint intersection is not representable")
        target["pattern"] = anchored
        target["x-defenseclaw-pattern-source"] = source_pattern
        target["x-defenseclaw-pattern-semantics"] = "portable-re2-full-match"
        target["x-defenseclaw-pattern-enforcement"] = "builder-runtime-and-anchored-public-schema"

    def utf8_value_semantics(node: JSONObject) -> str:
        variants = node.get("oneOf")
        if isinstance(variants, list):
            shapes = {utf8_value_semantics(variant) for variant in variants if isinstance(variant, dict)}
            if shapes == {"raw-scalar-string-utf8"}:
                return "raw-scalar-string-utf8"
            if shapes == {"canonical-json-utf8"}:
                return "canonical-json-utf8"
            return "raw-scalar-string-or-canonical-json-by-value-shape"
        if node.get("type") == "string":
            return "raw-scalar-string-utf8"
        return "canonical-json-utf8"

    for target in value_targets(result):
        if "enum" in constraints:
            intersect_enum(target, constraints["enum"])
        if "pattern" in constraints:
            source_pattern = _string(constraints["pattern"], "constraint pattern")
            apply_pattern(target, source_pattern)
        if "min" in constraints:
            tighten_minimum(target, "minimum", _plain(constraints["min"]))
        if "max" in constraints:
            tighten_maximum(target, "maximum", _plain(constraints["max"]))

    collections = collection_targets(result)

    for target in collections:
        if "min_items" in constraints:
            minimum = _plain(constraints["min_items"])
            tighten_minimum(target, "minItems", minimum)
            if target.get("type") == "object" or "$ref" in target:
                tighten_minimum(target, "minProperties", minimum)
        if "max_items" in constraints:
            maximum = _plain(constraints["max_items"])
            tighten_maximum(target, "maxItems", maximum)
            if target.get("type") == "object" or "$ref" in target:
                tighten_maximum(target, "maxProperties", maximum)
        if "max_properties" in constraints and (target.get("type") == "object" or "$ref" in target):
            tighten_maximum(target, "maxProperties", _plain(constraints["max_properties"]))
    if "max_items" in constraints:
        tighten_maximum(result, "x-defenseclaw-max-items", _plain(constraints["max_items"]))
        result["x-defenseclaw-max-items-semantics"] = "recursive-aggregate-members"
        result["x-defenseclaw-max-items-enforcement"] = "builder-runtime-recursive-aggregate-gate"
        result["x-defenseclaw-json-schema-item-bound-scope"] = "root-collection-safe-subset"
    for key in ("max_utf8_bytes", "max_item_utf8_bytes", "max_depth", "max_properties"):
        if key in constraints:
            tighten_maximum(
                result,
                f"x-defenseclaw-{key.replace('_', '-')}",
                _plain(constraints[key]),
            )
    if "max_utf8_bytes" in constraints:
        result["x-defenseclaw-max-utf8-bytes-semantics"] = utf8_value_semantics(result)
        result["x-defenseclaw-max-utf8-bytes-enforcement"] = "builder-runtime-shape-aware-utf8-byte-gate"
    if "max_item_utf8_bytes" in constraints:
        result["x-defenseclaw-max-item-utf8-bytes-semantics"] = "every-string-element-or-structured-string-leaf"
        result["x-defenseclaw-max-item-utf8-bytes-enforcement"] = "builder-runtime-string-leaf-utf8-byte-gate"
    if "max_depth" in constraints:
        result["x-defenseclaw-max-depth-semantics"] = "maximum-container-depth-root-zero"
        result["x-defenseclaw-max-depth-enforcement"] = "builder-runtime-container-depth-gate"
    if "max_properties" in constraints:
        result["x-defenseclaw-max-properties-semantics"] = "recursive-object-property-count"
        result["x-defenseclaw-max-properties-enforcement"] = "builder-runtime-recursive-property-count-gate"
        result["x-defenseclaw-json-schema-property-bound-scope"] = "root-object-safe-subset"
    return result


@dataclasses.dataclass(frozen=True, slots=True)
class CandidateAttribute:
    id: str
    field_types: tuple[str, ...]
    structured_type: str | None
    metadata: Mapping[str, Any]


@dataclasses.dataclass(frozen=True, slots=True)
class CandidateDomain:
    """Immutable domain assignment and expanded producer contracts."""

    id: str
    path: str
    family_ids: tuple[str, ...]
    producer_identity_sets: tuple[Mapping[str, Any], ...]
    producer_mappings: tuple[Mapping[str, Any], ...]


@dataclasses.dataclass(frozen=True, slots=True)
class CandidateExampleOutputPaths:
    """Canonical repository-relative outputs derived from one portable example ID."""

    example_id: str
    normalized_example_path: str
    otlp_fixture_path: str


@dataclasses.dataclass(frozen=True, slots=True)
class CandidateGoSymbolPolicy:
    """Closed version-1 Go public-name policy consumed from the compiler."""

    version: int
    package: str
    separators: tuple[str, ...]
    brand_spellings: Mapping[str, str]
    initialisms: tuple[str, ...]
    reserved_word_policy: str
    collision_policy: str
    auto_suffix_policy: str


@dataclasses.dataclass(frozen=True, slots=True)
class CandidateGoSymbolOverride:
    """One reviewed override row; version 1 requires this inventory to be empty."""

    kind: str
    source_id: str
    symbol: str
    reason: str


@dataclasses.dataclass(frozen=True, slots=True)
class CandidateGoSymbol:
    """One compiler-owned Go declaration identity."""

    kind: str
    source_id: str
    symbol: str
    declaration_form: str


@dataclasses.dataclass(frozen=True, slots=True)
class CandidateGoSymbolTable:
    """Immutable reviewed Go declaration table consumed without retokenization."""

    version: int
    package: str
    rows: tuple[CandidateGoSymbol, ...]
    kind_counts: Mapping[str, int]
    declaration_form_counts: Mapping[str, int]
    table_sha256: str


@dataclasses.dataclass(frozen=True, slots=True)
class EnrichedFieldDescriptor:
    """One occurrence-scoped semantic field with every registry join resolved."""

    id: str
    context: str
    owner_id: str
    attribute_id: str
    order: int
    role: str
    path: str
    path_kind: str
    input_placement: str
    target_slot: str
    field_types: tuple[str, ...]
    structured_type: str | None
    canonical_owner: str | None
    requirement_level: str
    condition_id: str | None
    condition_fact: str | None
    condition_false_requirement: str | None
    field_class: str
    sensitivity: str
    cardinality: str | None
    stability: str | None
    introduced_in: str | None
    deprecated_in: str | None
    removed_in: str | None
    normalization_id: str
    normalization_effective_constraints: Mapping[str, FrozenJSON]
    use_constraints: Mapping[str, FrozenJSON]
    effective_constraints: Mapping[str, FrozenJSON]
    value_source: str
    origins: tuple[Mapping[str, FrozenJSON], ...]


@dataclasses.dataclass(frozen=True, slots=True)
class EnrichedContainerDescriptor:
    """Unclassified structural shape or structured-reference edge."""

    id: str
    context: str
    owner_id: str
    kind: str
    path: str
    closed: bool
    requirement_level: str | None
    introduced_in: str | None
    deprecated_in: str | None
    removed_in: str | None
    bounds: Mapping[str, FrozenJSON]
    origin: str
    child_fields: tuple[str, ...]
    child_containers: tuple[str, ...]
    reference_target: str | None


@dataclasses.dataclass(frozen=True, slots=True)
class ResolvedMandatoryProgramIR:
    """The selected log family's sole, ordered mandatory-floor program."""

    family_id: str
    rule_ids: tuple[str, ...]
    constant_rule_ids: tuple[str, ...]
    fact_terms: tuple[tuple[str, str], ...]


@dataclasses.dataclass(frozen=True, slots=True)
class EnrichedFamilyDescriptor:
    """Typed family identity joined to its occurrence-scoped fields."""

    id: str
    domain: str
    signal: str
    bucket: str
    event_name: str
    family_schema_version: int
    stability: str
    introduced_in: str | None
    deprecated_in: str | None
    removed_in: str | None
    outcome_requirement: str | None
    allowed_outcomes: tuple[str, ...]
    route_selector: bool
    compatibility_profiles: tuple[str, ...]
    field_descriptor_ids: tuple[str, ...]
    mandatory_program_id: str | None


@dataclasses.dataclass(frozen=True, slots=True)
class EnrichedTraceDescriptor:
    """Complete trace-family shape using compiler-owned span-name parts."""

    family_id: str
    span_name_pattern: str
    span_name_parts: tuple[Mapping[str, FrozenJSON], ...]
    span_kinds: tuple[str, ...]
    span_status_rule: str
    field_descriptor_ids: tuple[str, ...]
    resource_field_descriptor_ids: tuple[str, ...]
    scope_field_descriptor_ids: tuple[str, ...]
    event_field_descriptor_ids: Mapping[str, tuple[str, ...]]
    link_field_descriptor_ids: tuple[str, ...]
    event_refs: tuple[str, ...]
    link_relations: tuple[str, ...]
    derivations: tuple[Mapping[str, FrozenJSON], ...]


@dataclasses.dataclass(frozen=True, slots=True)
class EnrichedMetricDescriptor:
    """Complete metric instrument and resolved label contract."""

    family_id: str
    instrument_name: str
    instrument_type: str
    value_type: str
    unit: str
    description: str
    temporality: str
    boundaries: tuple[int | float, ...]
    field_descriptor_ids: tuple[str, ...]
    projections: tuple[Mapping[str, FrozenJSON], ...]


@dataclasses.dataclass(frozen=True, slots=True)
class ExpandedProducerMappingDescriptor:
    """One explicit producer-to-identity row after contextual-set expansion."""

    id: str
    domain: str
    mapping_index: int
    identity_index: int
    identity_origin: str
    producer: str
    key: str
    source: str
    event_name_policy: str
    severity_policy: str
    event_name: str
    bucket: str
    family_id: str | None
    compatibility_only: bool
    selected_mandatory_program_id: str | None
    legacy_mapping_mandatory_rules: tuple[str, ...]
    companion_rules: tuple[str, ...]
    compatibility: Mapping[str, FrozenJSON]


@dataclasses.dataclass(frozen=True, slots=True)
class GoDeclarationValue:
    """Exact literal for one reviewed exported-constant declaration row."""

    kind: str
    source_id: str
    symbol: str
    go_type: str
    literal_kind: str
    value: str | int


@dataclasses.dataclass(frozen=True, slots=True)
class CandidateInboundOTLP:
    """Closed, compiler-expanded inbound OTLP binding authority."""

    version: int
    max_forward_hops: int
    unknown_fields: str
    semantic_resource_instance_key: str
    forward_instance_key: str
    forward_destination_key: str
    forward_hop_count_key: str
    record_id_key: str
    scope_name: str
    scope_schema_url: str
    resource_schema_url: str
    shape_policy: Mapping[str, FrozenJSON]
    alias_sets: tuple[Mapping[str, FrozenJSON], ...]
    source_normalizers: tuple[Mapping[str, FrozenJSON], ...]
    source_projection_plans: tuple[Mapping[str, FrozenJSON], ...]
    binding_classes: tuple[Mapping[str, FrozenJSON], ...]
    match_descriptors: tuple[Mapping[str, FrozenJSON], ...]
    target_descriptors: tuple[Mapping[str, FrozenJSON], ...]
    native_markers: tuple[Mapping[str, FrozenJSON], ...]
    echo_recognizers: tuple[Mapping[str, FrozenJSON], ...]
    import_contexts: tuple[Mapping[str, FrozenJSON], ...]
    derivation_attachments: tuple[Mapping[str, FrozenJSON], ...]
    fixture_policy: Mapping[str, FrozenJSON]
    __hash__ = None


@dataclasses.dataclass(frozen=True, slots=True)
class CandidateRenderIndex:
    """Recursively immutable, renderer-ready join of one materialized view."""

    schema_version: int
    registry_version: int
    bucket_catalog_version: int
    digest: str
    materialized_view_sha256: str
    candidate_render_index_sha256: str
    fields: Mapping[str, FrozenJSON]
    go_symbol_policy: CandidateGoSymbolPolicy
    go_symbol_overrides: tuple[CandidateGoSymbolOverride, ...]
    go_symbol_table: CandidateGoSymbolTable
    attributes: Mapping[str, CandidateAttribute]
    structured_types: Mapping[str, Mapping[str, FrozenJSON]]
    structured_bindings: Mapping[str, Mapping[str, FrozenJSON]]
    structured_property_dispositions: tuple[Mapping[str, FrozenJSON], ...]
    groups: Mapping[str, Mapping[str, FrozenJSON]]
    families: tuple[Mapping[str, FrozenJSON], ...]
    family_domains: Mapping[str, str]
    domains: tuple[CandidateDomain, ...]
    span_events: Mapping[str, Mapping[str, FrozenJSON]]
    examples: tuple[Mapping[str, FrozenJSON], ...]
    example_output_paths: Mapping[str, CandidateExampleOutputPaths]
    enriched_fields: Mapping[str, EnrichedFieldDescriptor]
    enriched_containers: Mapping[str, EnrichedContainerDescriptor]
    enriched_families: Mapping[str, EnrichedFamilyDescriptor]
    enriched_traces: Mapping[str, EnrichedTraceDescriptor]
    enriched_metrics: Mapping[str, EnrichedMetricDescriptor]
    mandatory_programs: Mapping[str, ResolvedMandatoryProgramIR]
    expanded_producer_mappings: tuple[ExpandedProducerMappingDescriptor, ...]
    inbound_otlp: CandidateInboundOTLP
    go_declaration_values: tuple[GoDeclarationValue, ...]
    go_api_plan: GoAPIPlanIR
    api_plan_sha256: str

    def recomputed_digest(self) -> str:
        """Return the compiler-owned digest of the renderer-facing facts."""

        return _candidate_render_index_digest(
            self.materialized_view_sha256,
            enriched_fields=self.enriched_fields,
            enriched_containers=self.enriched_containers,
            enriched_families=self.enriched_families,
            enriched_traces=self.enriched_traces,
            enriched_metrics=self.enriched_metrics,
            mandatory_programs=self.mandatory_programs,
            expanded_producer_mappings=self.expanded_producer_mappings,
            inbound_otlp=self.inbound_otlp,
            go_declaration_values=self.go_declaration_values,
            go_api_plan=self.go_api_plan,
            api_plan_sha256=self.api_plan_sha256,
        )

    def verify_digest(self) -> bool:
        """Report whether the recorded digest still binds every render fact."""

        return self.candidate_render_index_sha256 == self.recomputed_digest()


@dataclasses.dataclass(frozen=True, slots=True)
class _ProvisionalCandidateEnrichment:
    """Immutable, digest-free input boundary for the compiler-owned Go plan."""

    materialized_view_sha256: str
    fields: Mapping[str, FrozenJSON]
    go_symbol_policy: CandidateGoSymbolPolicy
    go_symbol_table: CandidateGoSymbolTable
    structured_types: Mapping[str, Mapping[str, FrozenJSON]]
    groups: Mapping[str, Mapping[str, FrozenJSON]]
    examples: tuple[Mapping[str, FrozenJSON], ...]
    enriched_fields: Mapping[str, EnrichedFieldDescriptor]
    enriched_containers: Mapping[str, EnrichedContainerDescriptor]
    enriched_families: Mapping[str, EnrichedFamilyDescriptor]
    enriched_traces: Mapping[str, EnrichedTraceDescriptor]
    enriched_metrics: Mapping[str, EnrichedMetricDescriptor]
    mandatory_programs: Mapping[str, ResolvedMandatoryProgramIR]
    expanded_producer_mappings: tuple[ExpandedProducerMappingDescriptor, ...]
    inbound_otlp: CandidateInboundOTLP
    go_declaration_values: tuple[GoDeclarationValue, ...]


def _go_symbol_table_digest(rows: Sequence[CandidateGoSymbol]) -> str:
    payload = json.dumps(
        [[row.kind, row.source_id, row.symbol, row.declaration_form] for row in rows],
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(_GO_SYMBOL_TABLE_DIGEST_DOMAIN + payload).hexdigest()


def _candidate_go_symbol_contract(
    fields: Mapping[str, FrozenJSON],
) -> tuple[CandidateGoSymbolPolicy, tuple[CandidateGoSymbolOverride, ...], CandidateGoSymbolTable]:
    raw_policy = _tagged(fields["go_symbol_policy"], "GoSymbolPolicyIR", _GO_SYMBOL_POLICY_FIELDS)
    brand_spellings = raw_policy["brand_spellings"]
    if not isinstance(brand_spellings, Mapping) or any(
        not isinstance(key, str) or not isinstance(value, str) for key, value in brand_spellings.items()
    ):
        raise CandidateRenderError("materialized Go symbol policy brand spellings are invalid")
    policy_version = _integer(raw_policy["version"], "Go symbol policy version", minimum=1)
    policy_values = {
        "version": policy_version,
        "package": raw_policy["package"],
        "separators": raw_policy["separators"],
        "brand_spellings": dict(brand_spellings),
        "initialisms": raw_policy["initialisms"],
        "reserved_word_policy": raw_policy["reserved_word_policy"],
        "collision_policy": raw_policy["collision_policy"],
        "auto_suffix_policy": raw_policy["auto_suffix_policy"],
    }
    if policy_version != 1 or policy_values != _GO_SYMBOL_POLICY:
        raise CandidateRenderError("materialized Go symbol policy is not the exact version 1 contract")
    policy = CandidateGoSymbolPolicy(
        version=1,
        package="observability",
        separators=_GO_SYMBOL_POLICY["separators"],
        brand_spellings=MappingProxyType(dict(_GO_SYMBOL_POLICY["brand_spellings"])),
        initialisms=_GO_SYMBOL_POLICY["initialisms"],
        reserved_word_policy="reject",
        collision_policy="reject",
        auto_suffix_policy="reject",
    )

    raw_overrides = fields["go_symbol_overrides"]
    if not isinstance(raw_overrides, tuple):
        raise CandidateRenderError("materialized Go symbol overrides are invalid")
    overrides: list[CandidateGoSymbolOverride] = []
    for raw_override in raw_overrides:
        override = _tagged(raw_override, "GoSymbolOverrideIR", _GO_SYMBOL_OVERRIDE_FIELDS)
        overrides.append(
            CandidateGoSymbolOverride(
                _string(override["kind"], "Go symbol override kind"),
                _string(override["source_id"], "Go symbol override source ID"),
                _string(override["symbol"], "Go symbol override symbol"),
                _string(override["reason"], "Go symbol override reason"),
            )
        )
    if overrides:
        raise CandidateRenderError("materialized Go symbol overrides must be empty for version 1")

    raw_table = _tagged(fields["go_symbol_table"], "GoSymbolTableIR", _GO_SYMBOL_TABLE_FIELDS)
    table_version = _integer(raw_table["version"], "Go symbol table version", minimum=1)
    if table_version != 1 or raw_table["package"] != "observability":
        raise CandidateRenderError("materialized Go symbol table identity is invalid")
    raw_rows = raw_table["rows"]
    if not isinstance(raw_rows, tuple) or not raw_rows or len(raw_rows) > _MAX_GO_SYMBOL_ROWS:
        raise CandidateRenderError("materialized Go symbol row inventory is empty or exceeds its safety bound")
    rows: list[CandidateGoSymbol] = []
    observed_source_keys: set[tuple[str, str]] = set()
    observed_symbols: set[str] = set()
    rank = {kind: index for index, kind in enumerate(_GO_SYMBOL_KIND_ORDER)}
    prior_order_key: tuple[int, bytes] | None = None
    computed_kind_counts = {kind: 0 for kind in _GO_SYMBOL_KIND_ORDER}
    declaration_forms = tuple(dict.fromkeys(_GO_SYMBOL_DECLARATION_BY_KIND.values()))
    computed_declaration_counts = {form: 0 for form in declaration_forms}
    for raw_row in raw_rows:
        row = _tagged(raw_row, "GoSymbolIR", _GO_SYMBOL_FIELDS)
        kind = _string(row["kind"], "Go symbol kind")
        source_id = _string(row["source_id"], "Go symbol source ID")
        symbol = _string(row["symbol"], "Go symbol")
        declaration_form = _string(row["declaration_form"], "Go symbol declaration form")
        if kind not in rank or declaration_form != _GO_SYMBOL_DECLARATION_BY_KIND.get(kind):
            raise CandidateRenderError("materialized Go symbol kind or declaration form is invalid")
        if _GO_SOURCE_ID.fullmatch(source_id) is None:
            raise CandidateRenderError("materialized Go symbol source ID is invalid")
        if _GO_PUBLIC_IDENTIFIER.fullmatch(symbol) is None or not symbol.isascii():
            raise CandidateRenderError("materialized Go symbol is not a public ASCII identifier")
        source_key = (kind, source_id)
        if source_key in observed_source_keys or symbol in observed_symbols:
            raise CandidateRenderError("materialized Go symbol identity is duplicated")
        order_key = (rank[kind], source_id.encode("ascii"))
        if prior_order_key is not None and order_key <= prior_order_key:
            raise CandidateRenderError("materialized Go symbol rows are not canonically ordered")
        prior_order_key = order_key
        observed_source_keys.add(source_key)
        observed_symbols.add(symbol)
        computed_kind_counts[kind] += 1
        computed_declaration_counts[declaration_form] += 1
        rows.append(CandidateGoSymbol(kind, source_id, symbol, declaration_form))

    raw_kind_counts = raw_table["kind_counts"]
    raw_declaration_counts = raw_table["declaration_form_counts"]
    if not isinstance(raw_kind_counts, Mapping) or not isinstance(raw_declaration_counts, Mapping):
        raise CandidateRenderError("materialized Go symbol table counts are invalid")
    if (
        set(raw_kind_counts) != set(_GO_SYMBOL_KIND_ORDER)
        or set(raw_declaration_counts) != set(declaration_forms)
        or any(type(value) is not int or value < 0 for value in raw_kind_counts.values())
        or any(type(value) is not int or value < 0 for value in raw_declaration_counts.values())
    ):
        raise CandidateRenderError("materialized Go symbol table count types are invalid")
    if (
        dict(raw_kind_counts) != computed_kind_counts
        or dict(raw_declaration_counts) != computed_declaration_counts
    ):
        raise CandidateRenderError("materialized Go symbol table counts disagree")
    table_sha256 = _string(raw_table["table_sha256"], "Go symbol table digest")
    computed_digest = _go_symbol_table_digest(rows)
    if _SHA256.fullmatch(table_sha256) is None or computed_digest != table_sha256:
        raise CandidateRenderError("materialized Go symbol table digest does not match rows")
    table = CandidateGoSymbolTable(
        version=1,
        package="observability",
        rows=tuple(rows),
        kind_counts=MappingProxyType(dict(computed_kind_counts)),
        declaration_form_counts=MappingProxyType(dict(computed_declaration_counts)),
        table_sha256=table_sha256,
    )
    return policy, tuple(overrides), table


def _validate_go_symbol_sources(
    table: CandidateGoSymbolTable,
    *,
    fields: Mapping[str, FrozenJSON],
    attributes: Mapping[str, CandidateAttribute],
    families: Sequence[Mapping[str, FrozenJSON]],
    family_domains: Mapping[str, str],
    span_events: Mapping[str, Mapping[str, FrozenJSON]],
    structured_types: Mapping[str, Mapping[str, FrozenJSON]],
) -> None:
    """Reconcile compiler-owned symbol sources without deriving public names."""

    expected: dict[str, set[str]] = {kind: set() for kind in _GO_SYMBOL_KIND_ORDER}
    expected["resource_attributes_type"].add("resource.core")
    expected["resource_attributes_constructor"].add("resource.core")
    expected["resource_attributes_attach"].add("resource.core")
    expected["resource_attributes_validator"].add("resource.core")

    expected["attribute"].update(attributes)
    for family in families:
        family_id = _string(family["id"], "Go symbol family source")
        family_type = family["type"]
        if family_type not in {"log", "span", "metric"}:
            raise CandidateRenderError("materialized Go symbol family source is invalid")
        expected["family"].add(family_id)
        expected["family_input"].add(family_id)
        expected["family_builder"].add(family_id)
        if family_type == "log":
            expected["log_event"].add(_string(family["event_name"], "Go symbol log event source"))
        elif family_type == "metric":
            expected["metric_instrument"].add(_string(family["instrument_name"], "Go symbol metric instrument source"))
        else:
            event_refs = family["event_refs"]
            link_relations = family["link_relations"]
            if not isinstance(event_refs, tuple) or any(not isinstance(item, str) or not item for item in event_refs):
                raise CandidateRenderError("materialized Go symbol span-event sources are invalid")
            if not isinstance(link_relations, tuple) or any(
                not isinstance(item, str) or not item for item in link_relations
            ):
                raise CandidateRenderError("materialized Go symbol span-link sources are invalid")
            for event_ref in event_refs:
                source_id = f"{family_id}#{event_ref}"
                expected["span_event_input"].add(source_id)
                expected["span_event_constructor"].add(source_id)
            for relation in link_relations:
                expected["link_relation"].add(relation)
                source_id = f"{family_id}#{relation}"
                expected["span_link_input"].add(source_id)
                expected["span_link_constructor"].add(source_id)

    expected["span_event"].update(span_events)

    raw_conditions = fields["conditions"]
    if not isinstance(raw_conditions, tuple):
        raise CandidateRenderError("materialized Go symbol condition sources are invalid")
    for raw_condition in raw_conditions:
        condition = _tagged(raw_condition, "ConditionIR", _CONDITION_FIELDS)
        expected["condition"].add(_string(condition["id"], "Go symbol condition source"))
        enforcement = _tagged(
            condition["enforcement"],
            "ConditionEnforcementIR",
            _CONDITION_ENFORCEMENT_FIELDS,
        )
        if enforcement["kind"] == "builder_fact":
            expected["condition_fact"].add(_string(enforcement["fact"], "Go symbol condition fact source"))
        elif enforcement["kind"] != "boolean_attribute" or enforcement["attribute"] is None:
            raise CandidateRenderError("materialized Go symbol condition enforcement is invalid")

    raw_catalogs = fields["value_catalogs"]
    if not isinstance(raw_catalogs, tuple):
        raise CandidateRenderError("materialized Go symbol phase sources are invalid")
    for raw_catalog in raw_catalogs:
        catalog = _tagged(raw_catalog, "ValueCatalogIR", _VALUE_CATALOG_FIELDS)
        entries = catalog["entries"]
        if not isinstance(entries, tuple):
            raise CandidateRenderError("materialized Go symbol phase entries are invalid")
        for raw_entry in entries:
            entry = _tagged(raw_entry, "ValueCatalogEntryIR", _VALUE_CATALOG_ENTRY_FIELDS)
            value = _string(entry["value"], "Go symbol phase source")
            expected["phase"].add(value)
            expected["phase_code"].add(value)

    raw_profiles = fields["semantic_profiles"]
    if not isinstance(raw_profiles, tuple):
        raise CandidateRenderError("materialized Go symbol semantic profiles are invalid")
    for raw_profile in raw_profiles:
        profile = _tagged(raw_profile, "SemanticProfileIR", _SEMANTIC_PROFILE_FIELDS)
        expected["semantic_profile"].add(_string(profile["id"], "Go symbol semantic profile source"))

    for structured_id, structured in structured_types.items():
        expected["structured_type"].add(structured_id)
        member_ids: list[str] = []
        ordered_member_id: str | None = None
        raw_fixed_fields = structured["fields"]
        if raw_fixed_fields is not None:
            if not isinstance(raw_fixed_fields, tuple):
                raise CandidateRenderError("materialized Go symbol structured fields are invalid")
            for raw_field in raw_fixed_fields:
                field = _tagged(raw_field, "StructuredFieldIR", _STRUCTURED_FIELD_FIELDS)
                member_ids.append(_string(field["name"], "Go symbol structured member source"))
        raw_discriminator = structured["discriminator"]
        if raw_discriminator is not None:
            discriminator = _tagged(
                raw_discriminator,
                "StructuredDiscriminatorIR",
                _STRUCTURED_DISCRIMINATOR_FIELDS,
            )
            member_ids.append(_string(discriminator["name"], "Go symbol structured discriminator source"))
        raw_dynamic_members = structured["dynamic_members"]
        if raw_dynamic_members is not None:
            dynamic_members = _tagged(
                raw_dynamic_members,
                "StructuredDynamicMembersIR",
                _STRUCTURED_DYNAMIC_MEMBERS_FIELDS,
            )
            ordered_member_id = _string(dynamic_members["member_id"], "Go symbol ordered member source")
        raw_canonical = structured["canonical_json"]
        if raw_canonical is not None:
            canonical = _tagged(
                raw_canonical,
                "CanonicalJSONContractIR",
                _CANONICAL_JSON_CONTRACT_FIELDS,
            )
            ordered_member_id = _string(canonical["object_member_id"], "Go symbol canonical member source")
            arms = canonical["arms"]
            if not isinstance(arms, tuple) or any(not isinstance(item, str) or not item for item in arms):
                raise CandidateRenderError("materialized Go symbol canonical arms are invalid")
            for arm_id in arms:
                expected["structured_arm"].add(f"{structured_id}#{arm_id}")
        if ordered_member_id is not None:
            member_ids.append(ordered_member_id)
            ordered_source = f"{structured_id}#{ordered_member_id}"
            expected["structured_member_input"].add(ordered_source)
            expected["structured_member_constructor"].add(ordered_source)
        for member_id in member_ids:
            expected["structured_member"].add(f"{structured_id}#{member_id}")
        raw_variants = structured["variants"]
        if raw_variants is not None:
            if not isinstance(raw_variants, tuple):
                raise CandidateRenderError("materialized Go symbol structured variants are invalid")
            for raw_variant in raw_variants:
                variant = _tagged(raw_variant, "StructuredVariantIR", _STRUCTURED_VARIANT_FIELDS)
                expected["structured_arm"].add(
                    f"{structured_id}#{_string(variant['tag'], 'Go symbol structured arm source')}"
                )
        raw_dynamic_variant = structured["dynamic_variant"]
        if raw_dynamic_variant is not None:
            dynamic_variant = _tagged(
                raw_dynamic_variant,
                "StructuredDynamicVariantIR",
                _STRUCTURED_DYNAMIC_VARIANT_FIELDS,
            )
            expected["structured_arm"].add(
                f"{structured_id}#{_string(dynamic_variant['arm_id'], 'Go symbol dynamic arm source')}"
            )

    observed: dict[str, list[str]] = {kind: [] for kind in _GO_SYMBOL_KIND_ORDER}
    for row in table.rows:
        observed[row.kind].append(row.source_id)
    for kind in _GO_SYMBOL_KIND_ORDER:
        expected_sources = tuple(sorted(expected[kind], key=str.encode))
        if tuple(observed[kind]) != expected_sources:
            raise CandidateRenderError("materialized Go symbol sources disagree with registry facts")

    for row in table.rows:
        if row.declaration_form == "exported_const":
            continue
        if row.kind.startswith("structured_"):
            continue
        if row.kind.startswith("resource_attributes_"):
            continue
        family_id = row.source_id.split("#", 1)[0]
        domain = family_domains.get(family_id)
        if domain not in {"genai", "security", "operations"}:
            raise CandidateRenderError("materialized Go symbol family domain is invalid")


def _preflight_candidate_output_paths(paths: Sequence[str]) -> tuple[str, ...]:
    """Validate a complete output plan for exact and portable collisions."""

    checked: list[str] = []
    exact: set[str] = set()
    portable: set[str] = set()
    for raw_path in paths:
        path = _normalized_candidate_path(raw_path)
        if path in exact:
            raise CandidateRenderError("candidate output path is duplicated")
        identity = _candidate_path_identity(path)
        if identity in portable:
            raise CandidateRenderError("candidate output path has a portable collision")
        exact.add(path)
        portable.add(identity)
        checked.append(path)
    return tuple(checked)


def _materialize_example_output_paths(
    examples: Sequence[Mapping[str, FrozenJSON]],
) -> Mapping[str, CandidateExampleOutputPaths]:
    """Derive immutable example outputs only after full-set path preflight."""

    planned = list(_STATIC_CANDIDATE_OUTPUT_PATHS)
    derived: list[tuple[str, str, str]] = []
    for example in examples:
        example_id = example.get("id")
        if not isinstance(example_id, str) or _EXAMPLE_PATH_SEGMENT.fullmatch(example_id) is None:
            raise CandidateRenderError("example id is not a portable output path segment")
        if type(example.get("valid")) is not bool:
            raise CandidateRenderError("materialized example metadata is invalid")
        category = "valid" if example["valid"] else "invalid"
        normalized_example_path = _normalized_candidate_path(
            f"{GENERATED_PREFIX}/examples/{category}/{example_id}.json"
        )
        otlp_fixture_path = _normalized_candidate_path(f"{GENERATED_PREFIX}/otlp-fixtures/cases/{example_id}.json")
        planned.extend((normalized_example_path, otlp_fixture_path))
        derived.append((example_id, normalized_example_path, otlp_fixture_path))
    _preflight_candidate_output_paths(planned)
    return MappingProxyType(
        {
            example_id: CandidateExampleOutputPaths(example_id, normalized_example_path, otlp_fixture_path)
            for example_id, normalized_example_path, otlp_fixture_path in derived
        }
    )


def _validate_mandatory_rule_catalog(value: FrozenJSON) -> None:
    catalog = _tagged(value, "MandatoryRuleCatalogIR", _MANDATORY_RULE_CATALOG_FIELDS)
    if _integer(catalog["version"], "mandatory rule catalog version", minimum=1) != 1:
        raise CandidateRenderError("materialized mandatory rule catalog version is unsupported")
    rules = catalog["rules"]
    if not isinstance(rules, tuple) or not rules:
        raise CandidateRenderError("materialized mandatory rule catalog is incomplete")
    seen_ids: set[str] = set()
    seen_facts: set[str] = set()
    for raw_rule in rules:
        rule = _tagged(raw_rule, "MandatoryRuleIR", _MANDATORY_RULE_FIELDS)
        rule_id = _string(rule["id"], "mandatory rule id")
        if rule_id in seen_ids:
            raise CandidateRenderError("materialized mandatory rule ID is duplicated")
        enforcement = _tagged(
            rule["enforcement"],
            "MandatoryRuleEnforcementIR",
            _MANDATORY_RULE_ENFORCEMENT_FIELDS,
        )
        if enforcement["kind"] == "constant":
            if enforcement["value"] is not True or enforcement["fact"] is not None:
                raise CandidateRenderError("materialized constant mandatory rule is invalid")
        elif enforcement["kind"] == "builder_fact":
            fact = _string(enforcement["fact"], "mandatory builder fact")
            if enforcement["value"] is not None or fact in seen_facts:
                raise CandidateRenderError("materialized mandatory builder fact is invalid")
            seen_facts.add(fact)
        else:
            raise CandidateRenderError("materialized mandatory rule enforcement is invalid")
        seen_ids.add(rule_id)


def _validate_builder_context(example: Mapping[str, FrozenJSON]) -> None:
    context = _tagged(example["builder_context"], "BuilderContextIR", _BUILDER_CONTEXT_FIELDS)
    inheritance = _tagged(
        context["inheritance"],
        "BuilderContextInheritanceIR",
        _BUILDER_CONTEXT_INHERITANCE_FIELDS,
    )
    condition_facts = context["condition_facts"]
    mandatory_facts = context["mandatory_facts"]
    if not isinstance(condition_facts, tuple) or not isinstance(mandatory_facts, tuple):
        raise CandidateRenderError("materialized builder context facts are invalid")
    for facts in (condition_facts, mandatory_facts):
        seen: set[str] = set()
        for raw_fact in facts:
            fact = _tagged(raw_fact, "BuilderFactIR", _BUILDER_FACT_FIELDS)
            fact_name = _string(fact["fact"], "builder fact")
            if type(fact["value"]) is not bool or fact_name in seen:
                raise CandidateRenderError("materialized builder fact is invalid")
            seen.add(fact_name)

    if example["valid"] is True:
        if inheritance["mode"] != "explicit" or inheritance["base_example"] is not None:
            raise CandidateRenderError("materialized valid example builder inheritance is invalid")
        occurrence = _tagged(
            context["occurrence"],
            "BuilderOccurrenceIR",
            _BUILDER_OCCURRENCE_FIELDS,
        )
        if occurrence["timestamp"] != example["record"].get("timestamp") or occurrence["record_id"] != example[
            "record"
        ].get("record_id"):
            raise CandidateRenderError("materialized builder occurrence is inconsistent")
    elif (
        inheritance["mode"] != "exact_base"
        or inheritance["base_example"] != example["base_example"]
        or context["occurrence"] is not None
        or condition_facts
        or mandatory_facts
    ):
        raise CandidateRenderError("materialized invalid example builder inheritance is invalid")


def _validate_structured_scalar_node(value: FrozenJSON, tag: str = "StructuredScalarIR") -> Mapping[str, FrozenJSON]:
    expected = _STRUCTURED_DYNAMIC_NAME_FIELDS if tag == "StructuredDynamicNameIR" else _STRUCTURED_SCALAR_FIELDS
    scalar = _tagged(value, tag, expected)
    if (
        scalar["field_type"] not in {"boolean", "int64", "double", "string"}
        or scalar["field_class"] not in _FIELD_CLASSES
        or scalar["sensitivity"] not in {"safe", "internal", "sensitive", "critical"}
    ):
        raise CandidateRenderError("materialized structured scalar is invalid")
    if tag == "StructuredScalarIR":
        known_values = scalar["known_values"]
        if not isinstance(known_values, tuple) or any(not isinstance(item, str) for item in known_values):
            raise CandidateRenderError("materialized structured scalar known values are invalid")
        if scalar["encoding_annotation"] not in {None, "json-base64-bytes-v1"}:
            raise CandidateRenderError("materialized structured scalar encoding annotation is invalid")
    _normalization(scalar, field_types=(scalar["field_type"],))
    return scalar


def _validate_structured_reference_node(value: FrozenJSON) -> Mapping[str, FrozenJSON]:
    reference = _tagged(value, "StructuredReferenceIR", _STRUCTURED_REFERENCE_FIELDS)
    _string(reference["structured_ref"], "structured reference")
    return reference


def _validate_structured_materialized_type(value: FrozenJSON) -> Mapping[str, FrozenJSON]:
    structured = _tagged(value, "StructuredTypeIR", _STRUCTURED_TYPE_FIELDS)
    kind = _string(structured["kind"], "structured type kind")
    _string(structured["id"], "structured type id")
    fields = structured["fields"]
    if fields is not None:
        if not isinstance(fields, tuple):
            raise CandidateRenderError("materialized structured fields are invalid")
        for raw_field in fields:
            field = _tagged(raw_field, "StructuredFieldIR", _STRUCTURED_FIELD_FIELDS)
            _string(field["name"], "structured field name")
            if type(field["required"]) is not bool or type(field["nullable_omission"]) is not bool:
                raise CandidateRenderError("materialized structured field presence is invalid")
            if (field["scalar"] is None) == (field["reference"] is None):
                raise CandidateRenderError("materialized structured field arm is invalid")
            if field["scalar"] is not None:
                _validate_structured_scalar_node(field["scalar"])
            else:
                _validate_structured_reference_node(field["reference"])
    dynamic = structured["dynamic_members"]
    if dynamic is not None:
        members = _tagged(dynamic, "StructuredDynamicMembersIR", _STRUCTURED_DYNAMIC_MEMBERS_FIELDS)
        _validate_structured_scalar_node(members["name"], "StructuredDynamicNameIR")
        _validate_structured_reference_node(members["value"])
        if (
            members["member_id"] != "entry"
            or members["max_items"] != 256
            or members["public_encoding"] != "ordered_typed_entries"
            or members["wire_encoding"] != "native_object_properties"
            or any(
                members[key] != "reject"
                for key in (
                    "duplicate_name_policy",
                    "fixed_name_collision_policy",
                    "post_redaction_name_collision_policy",
                )
            )
            or not isinstance(members["reserved_names"], tuple)
        ):
            raise CandidateRenderError("materialized dynamic member contract is invalid")
    for item_key in ("items_scalar", "items_reference"):
        item = structured[item_key]
        if item is not None:
            if item_key == "items_scalar":
                _validate_structured_scalar_node(item)
            else:
                _validate_structured_reference_node(item)
    discriminator = structured["discriminator"]
    if discriminator is not None:
        node = _tagged(discriminator, "StructuredDiscriminatorIR", _STRUCTURED_DISCRIMINATOR_FIELDS)
        _normalization(node, field_types=(node["field_type"],))
        if node["field_type"] != "string":
            raise CandidateRenderError("materialized structured discriminator is invalid")
    variants = structured["variants"]
    if variants is not None:
        if not isinstance(variants, tuple):
            raise CandidateRenderError("materialized structured variants are invalid")
        for raw_variant in variants:
            variant = _tagged(raw_variant, "StructuredVariantIR", _STRUCTURED_VARIANT_FIELDS)
            _string(variant["tag"], "structured variant tag")
            _string(variant["structured_ref"], "structured variant reference")
    dynamic_variant = structured["dynamic_variant"]
    if dynamic_variant is not None:
        node = _tagged(
            dynamic_variant,
            "StructuredDynamicVariantIR",
            _STRUCTURED_DYNAMIC_VARIANT_FIELDS,
        )
        _normalization(
            {"normalization": node["tag_normalization"]},
            field_types=("string",),
        )
        if node["arm_id"] != "generic" or node["exclude_registered_tags"] is not True:
            raise CandidateRenderError("materialized dynamic variant is invalid")
    canonical = structured["canonical_json"]
    if canonical is not None:
        node = _tagged(canonical, "CanonicalJSONContractIR", _CANONICAL_JSON_CONTRACT_FIELDS)
        _validate_structured_scalar_node(node["object_name"], "StructuredDynamicNameIR")
        _validate_structured_reference_node(node["object_value"])
        limits = _tagged(node["limits"], "CanonicalJSONLimitsIR", _CANONICAL_JSON_LIMITS_FIELDS)
        if any(type(limits[key]) is not int or limits[key] <= 0 for key in _CANONICAL_JSON_LIMITS_FIELDS):
            raise CandidateRenderError("materialized canonical JSON limits are invalid")
        if (
            node["discriminator_visibility"] != "internal"
            or node["discriminator_wire"] is not False
            or node["arms"] != ("boolean", "int64", "finite_double", "string", "array", "object")
            or node["leaf_field_class"] != "content"
            or node["leaf_sensitivity"] != "sensitive"
            or node["array_items_ref"] != "gen_ai.canonical_json"
            or node["object_value"]["fields"]["structured_ref"] != "gen_ai.canonical_json"
            or node["object_member_id"] != "entry"
            or dict(limits) != _CANONICAL_JSON_LIMITS
            or any(
                node[key] != "reject"
                for key in (
                    "duplicate_name_policy",
                    "fixed_name_collision_policy",
                    "post_redaction_name_collision_policy",
                )
            )
        ):
            raise CandidateRenderError("materialized canonical JSON contract is invalid")
    if kind not in {"object", "array", "tagged_union", "canonical_json"}:
        raise CandidateRenderError("materialized structured type kind is invalid")
    if kind == "object":
        if (
            structured["additional_properties"] is not False
            or not isinstance(fields, tuple)
            or any(
                structured[key] is not None
                for key in (
                    "items_scalar",
                    "items_reference",
                    "min_items",
                    "max_items",
                    "discriminator",
                    "variants",
                    "dynamic_variant",
                    "canonical_json",
                )
            )
        ):
            raise CandidateRenderError("materialized object structured-type arms are incoherent")
    elif kind == "array":
        if (
            (structured["items_scalar"] is None) == (structured["items_reference"] is None)
            or type(structured["min_items"]) is not int
            or type(structured["max_items"]) is not int
            or structured["min_items"] < 0
            or structured["max_items"] < structured["min_items"]
            or any(
                structured[key] is not None
                for key in (
                    "additional_properties",
                    "fields",
                    "dynamic_members",
                    "discriminator",
                    "variants",
                    "dynamic_variant",
                    "canonical_json",
                )
            )
        ):
            raise CandidateRenderError("materialized array structured-type arms are incoherent")
    elif kind == "tagged_union":
        variant_rows = structured["variants"]
        if (
            structured["discriminator"] is None
            or not isinstance(variant_rows, tuple)
            or len(variant_rows) < 2
            or len({item["fields"]["tag"] for item in variant_rows}) != len(variant_rows)
            or len({item["fields"]["structured_ref"] for item in variant_rows}) != len(variant_rows)
            or any(
                structured[key] is not None
                for key in (
                    "additional_properties",
                    "fields",
                    "dynamic_members",
                    "items_scalar",
                    "items_reference",
                    "min_items",
                    "max_items",
                    "canonical_json",
                )
            )
        ):
            raise CandidateRenderError("materialized union structured-type arms are incoherent")
    elif canonical is None or any(
        structured[key] is not None
        for key in (
            "additional_properties",
            "fields",
            "dynamic_members",
            "items_scalar",
            "items_reference",
            "min_items",
            "max_items",
            "discriminator",
            "variants",
            "dynamic_variant",
        )
    ):
        raise CandidateRenderError("materialized canonical structured-type arms are incoherent")
    return structured


def _validate_exact_structured_contracts(
    structured_types: Mapping[str, Mapping[str, FrozenJSON]],
) -> None:
    for type_id, expected_fields in _STRUCTURED_EXPECTED_OBJECT_FIELDS.items():
        structured = structured_types[type_id]
        fields = structured["fields"]
        dynamic = structured["dynamic_members"]
        if structured["kind"] != "object" or not isinstance(fields, tuple) or dynamic is None:
            raise CandidateRenderError("materialized structured object contract is not canonical")
        observed_fields: list[tuple[str, bool, str, str]] = []
        expected_nullable = _STRUCTURED_NULLABLE_OPTIONALS.get(type_id, frozenset())
        for raw_field in fields:
            field = _tagged(raw_field, "StructuredFieldIR", _STRUCTURED_FIELD_FIELDS)
            name = _string(field["name"], "structured field name")
            if field["nullable_omission"] is not (name in expected_nullable):
                raise CandidateRenderError("materialized structured nullable-omission contract is not canonical")
            if field["scalar"] is not None:
                scalar = _tagged(field["scalar"], "StructuredScalarIR", _STRUCTURED_SCALAR_FIELDS)
                observed_fields.append((name, field["required"], "scalar", scalar["field_type"]))
                if scalar["known_values"] != _STRUCTURED_EXPECTED_KNOWN_VALUES.get((type_id, name), ()):
                    raise CandidateRenderError("materialized structured known-value contract is not canonical")
                expected_encoding = (
                    "json-base64-bytes-v1" if type_id == "gen_ai.blob_part" and name == "content" else None
                )
                if scalar["encoding_annotation"] != expected_encoding:
                    raise CandidateRenderError("materialized structured encoding contract is not canonical")
            else:
                reference = _tagged(
                    field["reference"],
                    "StructuredReferenceIR",
                    _STRUCTURED_REFERENCE_FIELDS,
                )
                observed_fields.append((name, field["required"], "reference", reference["structured_ref"]))
        members = _tagged(dynamic, "StructuredDynamicMembersIR", _STRUCTURED_DYNAMIC_MEMBERS_FIELDS)
        value = _tagged(members["value"], "StructuredReferenceIR", _STRUCTURED_REFERENCE_FIELDS)
        if tuple(observed_fields) != expected_fields or value["structured_ref"] != "gen_ai.canonical_json":
            raise CandidateRenderError("materialized structured object contract is not canonical")

    for type_id, (expected_ref, expected_min, expected_max) in _STRUCTURED_EXPECTED_ARRAYS.items():
        structured = structured_types[type_id]
        reference = _tagged(
            structured["items_reference"],
            "StructuredReferenceIR",
            _STRUCTURED_REFERENCE_FIELDS,
        )
        if (
            structured["kind"] != "array"
            or reference["structured_ref"] != expected_ref
            or structured["min_items"] != expected_min
            or structured["max_items"] != expected_max
        ):
            raise CandidateRenderError("materialized structured array contract is not canonical")

    union = structured_types["gen_ai.message_part"]
    variants = tuple(
        (
            _tagged(item, "StructuredVariantIR", _STRUCTURED_VARIANT_FIELDS)["tag"],
            _tagged(item, "StructuredVariantIR", _STRUCTURED_VARIANT_FIELDS)["structured_ref"],
        )
        for item in union["variants"]
    )
    dynamic_variant = _tagged(
        union["dynamic_variant"],
        "StructuredDynamicVariantIR",
        _STRUCTURED_DYNAMIC_VARIANT_FIELDS,
    )
    if (
        union["kind"] != "tagged_union"
        or variants != _STRUCTURED_EXPECTED_VARIANTS
        or dynamic_variant["structured_ref"] != "gen_ai.generic_part"
    ):
        raise CandidateRenderError("materialized structured union contract is not canonical")
    if structured_types["gen_ai.canonical_json"]["kind"] != "canonical_json":
        raise CandidateRenderError("materialized canonical JSON type contract is not canonical")


def _pointer_token(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def _descriptor_payload(value: Any) -> Any:
    """Convert immutable descriptor records into deterministic typed-digest input."""

    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {field.name: _descriptor_payload(getattr(value, field.name)) for field in dataclasses.fields(value)}
    if isinstance(value, Mapping):
        return {key: _descriptor_payload(value[key]) for key in sorted(value)}
    if isinstance(value, tuple):
        return tuple(_descriptor_payload(item) for item in value)
    if value is None or type(value) in {bool, int, float, str, bytes}:
        return value
    raise CandidateRenderError("candidate render index digest contains an unsupported value")


def _stream_typed_materialized_hash(hasher: Any, value: Any) -> None:
    """Hash the existing typed-node canonical JSON without building its full tree."""

    def write(text: str) -> None:
        hasher.update(text.encode("utf-8"))

    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        fields = {field.name: getattr(value, field.name) for field in dataclasses.fields(value)}
        _stream_typed_materialized_hash(hasher, fields)
        return
    if value is None:
        write('["null"]')
        return
    if type(value) is bool:
        write('["boolean",true]' if value else '["boolean",false]')
        return
    if type(value) is int:
        write('["int",')
        write(_canonical_json_string(str(value)))
        write("]")
        return
    if type(value) is float:
        number = _canonical_json_number(repr(value)) if value != 0 else "0"
        write('["double",')
        write(_canonical_json_string(number))
        write("]")
        return
    if isinstance(value, bytes):
        write('["bytes",')
        write(_canonical_json_string(value.hex()))
        write("]")
        return
    if isinstance(value, str):
        write('["string",')
        write(_canonical_json_string(value))
        write("]")
        return
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise CandidateRenderError("candidate render index digest contains a non-string key")
        write('["object",[')
        for position, key in enumerate(sorted(value)):
            if position:
                write(",")
            write("[")
            write(_canonical_json_string(key))
            write(",")
            _stream_typed_materialized_hash(hasher, value[key])
            write("]")
        write("]]")
        return
    if isinstance(value, tuple):
        write('["array",[')
        for position, item in enumerate(value):
            if position:
                write(",")
            _stream_typed_materialized_hash(hasher, item)
        write("]]")
        return
    raise CandidateRenderError("candidate render index digest contains an unsupported value")


def _go_declaration_values(
    table: CandidateGoSymbolTable,
    fields: Mapping[str, FrozenJSON],
) -> tuple[GoDeclarationValue, ...]:
    """Bind all exported constant symbols to exact literals without tokenizing IDs."""

    phase_codes: dict[str, int] = {}
    raw_catalogs = fields["value_catalogs"]
    if not isinstance(raw_catalogs, tuple):
        raise CandidateRenderError("materialized value catalog inventory is invalid")
    for raw_catalog in raw_catalogs:
        catalog = _tagged(raw_catalog, "ValueCatalogIR", _VALUE_CATALOG_FIELDS)
        raw_entries = catalog["entries"]
        if not isinstance(raw_entries, tuple):
            raise CandidateRenderError("materialized value catalog entries are invalid")
        for raw_entry in raw_entries:
            entry = _tagged(raw_entry, "ValueCatalogEntryIR", _VALUE_CATALOG_ENTRY_FIELDS)
            value = _string(entry["value"], "value catalog value")
            code = _integer(entry["code"], "value catalog code")
            if value in phase_codes:
                raise CandidateRenderError("materialized value catalog value is duplicated")
            phase_codes[value] = code

    declarations: list[GoDeclarationValue] = []
    for row in table.rows:
        if row.declaration_form != "exported_const":
            continue
        if row.kind == "phase_code":
            value = phase_codes.get(row.source_id)
            if value is None:
                raise CandidateRenderError("Go phase-code declaration has no exact value")
            declarations.append(GoDeclarationValue(row.kind, row.source_id, row.symbol, "int", "integer", value))
            continue
        value = row.source_id.split("#", 1)[1] if row.kind == "structured_member" else row.source_id
        declarations.append(GoDeclarationValue(row.kind, row.source_id, row.symbol, "string", "string", value))
    expected_constant_kinds = {
        kind: table.kind_counts[kind]
        for kind in _GO_SYMBOL_KIND_ORDER
        if _GO_SYMBOL_DECLARATION_BY_KIND[kind] == "exported_const"
    }
    if len(declarations) != table.declaration_form_counts["exported_const"] or Counter(
        item.kind for item in declarations
    ) != expected_constant_kinds:
        raise CandidateRenderError("Go declaration value inventory is incomplete")
    return tuple(declarations)


def _candidate_render_index_digest(
    materialized_view_sha256: str,
    *,
    enriched_fields: Mapping[str, EnrichedFieldDescriptor],
    enriched_containers: Mapping[str, EnrichedContainerDescriptor],
    enriched_families: Mapping[str, EnrichedFamilyDescriptor],
    enriched_traces: Mapping[str, EnrichedTraceDescriptor],
    enriched_metrics: Mapping[str, EnrichedMetricDescriptor],
    mandatory_programs: Mapping[str, ResolvedMandatoryProgramIR],
    expanded_producer_mappings: tuple[ExpandedProducerMappingDescriptor, ...],
    inbound_otlp: CandidateInboundOTLP,
    go_declaration_values: tuple[GoDeclarationValue, ...],
    go_api_plan: GoAPIPlanIR,
    api_plan_sha256: str,
) -> str:
    payload = {
        "format": "defenseclaw-candidate-render-index-v1",
        "materialized_view_sha256": materialized_view_sha256,
        "enriched_fields": enriched_fields,
        "enriched_containers": enriched_containers,
        "enriched_families": enriched_families,
        "enriched_traces": enriched_traces,
        "enriched_metrics": enriched_metrics,
        "mandatory_programs": mandatory_programs,
        "expanded_producer_mappings": expanded_producer_mappings,
        "inbound_otlp": inbound_otlp,
        "go_declaration_values": go_declaration_values,
        "go_api_plan": go_api_plan,
        "api_plan_sha256": api_plan_sha256,
    }
    hasher = hashlib.sha256()
    hasher.update(CANDIDATE_RENDER_INDEX_DIGEST_DOMAIN)
    _stream_typed_materialized_hash(hasher, payload)
    return hasher.hexdigest()


def _condition_contracts(fields: Mapping[str, FrozenJSON]) -> Mapping[str, tuple[str, str]]:
    conditions: dict[str, tuple[str, str]] = {}
    raw_conditions = fields["conditions"]
    if not isinstance(raw_conditions, tuple):
        raise CandidateRenderError("materialized condition inventory is invalid")
    for raw_condition in raw_conditions:
        condition = _tagged(raw_condition, "ConditionIR", _CONDITION_FIELDS)
        condition_id = _string(condition["id"], "condition id")
        enforcement = _tagged(
            condition["enforcement"],
            "ConditionEnforcementIR",
            _CONDITION_ENFORCEMENT_FIELDS,
        )
        kind = _string(enforcement["kind"], "condition enforcement kind")
        if kind == "builder_fact":
            binding = _string(enforcement["fact"], "condition fact")
            if enforcement["attribute"] is not None:
                raise CandidateRenderError("materialized builder-fact condition has an attribute source")
        elif kind == "boolean_attribute":
            binding = "attribute:" + _string(enforcement["attribute"], "condition Boolean attribute")
            if enforcement["fact"] is not None:
                raise CandidateRenderError("materialized Boolean-attribute condition has a builder fact")
        else:
            raise CandidateRenderError("materialized condition enforcement kind is invalid")
        false_requirement = _string(condition["false_requirement"], "condition false requirement")
        if false_requirement not in {"optional", "forbidden"} or condition_id in conditions:
            raise CandidateRenderError("materialized condition contract is invalid")
        conditions[condition_id] = (binding, false_requirement)
    return MappingProxyType(conditions)


def _mandatory_rule_contracts(fields: Mapping[str, FrozenJSON]) -> Mapping[str, tuple[str, str | None]]:
    catalog = _tagged(fields["mandatory_rule_catalog"], "MandatoryRuleCatalogIR", _MANDATORY_RULE_CATALOG_FIELDS)
    rules: dict[str, tuple[str, str | None]] = {}
    raw_rules = catalog["rules"]
    if not isinstance(raw_rules, tuple):
        raise CandidateRenderError("materialized mandatory rule inventory is invalid")
    for raw_rule in raw_rules:
        rule = _tagged(raw_rule, "MandatoryRuleIR", _MANDATORY_RULE_FIELDS)
        rule_id = _string(rule["id"], "mandatory rule id")
        enforcement = _tagged(
            rule["enforcement"],
            "MandatoryRuleEnforcementIR",
            _MANDATORY_RULE_ENFORCEMENT_FIELDS,
        )
        kind = _string(enforcement["kind"], "mandatory enforcement kind")
        fact = enforcement["fact"]
        if kind == "constant":
            if enforcement["value"] is not True or fact is not None:
                raise CandidateRenderError("materialized constant mandatory rule is invalid")
        elif kind == "builder_fact":
            fact = _string(fact, "mandatory builder fact")
            if enforcement["value"] is not None:
                raise CandidateRenderError("materialized builder mandatory rule is invalid")
        else:
            raise CandidateRenderError("materialized mandatory enforcement kind is invalid")
        if rule_id in rules:
            raise CandidateRenderError("materialized mandatory rule is duplicated")
        rules[rule_id] = (kind, fact)
    return MappingProxyType(rules)


def _resolved_mandatory_programs(
    families: Sequence[Mapping[str, FrozenJSON]],
    rules: Mapping[str, tuple[str, str | None]],
) -> Mapping[str, ResolvedMandatoryProgramIR]:
    programs: dict[str, ResolvedMandatoryProgramIR] = {}
    for family in families:
        if family["type"] != "log":
            continue
        family_id = _string(family["id"], "mandatory family id")
        raw_rule_ids = family["mandatory_floor"]
        if not isinstance(raw_rule_ids, tuple):
            raise CandidateRenderError("materialized log mandatory floor is invalid")
        constant_rule_ids: list[str] = []
        fact_terms: list[tuple[str, str]] = []
        seen_rules: set[str] = set()
        seen_facts: set[str] = set()
        for rule_id in raw_rule_ids:
            rule_id = _string(rule_id, "family mandatory rule")
            contract = rules.get(rule_id)
            if contract is None or rule_id in seen_rules:
                raise CandidateRenderError("materialized family mandatory program is invalid")
            kind, fact = contract
            if kind == "constant":
                constant_rule_ids.append(rule_id)
            else:
                assert fact is not None
                if fact in seen_facts:
                    raise CandidateRenderError("materialized family mandatory fact is duplicated")
                seen_facts.add(fact)
                fact_terms.append((rule_id, fact))
            seen_rules.add(rule_id)
        programs[family_id] = ResolvedMandatoryProgramIR(
            family_id,
            tuple(raw_rule_ids),
            tuple(constant_rule_ids),
            tuple(fact_terms),
        )
    return MappingProxyType({key: programs[key] for key in sorted(programs)})


_TRACE_DERIVATION_CONTEXT_BY_SOURCE: Final = {
    "envelope.bucket": "span",
    "family.id": "span",
    "family.family_schema_version": "span",
    "envelope.source": "span",
    "provenance.config_generation": "span",
    "envelope.outcome": "span",
    "provenance.binary_version": "resource",
    "semantic_profile.trace_schema_version": "scope",
    "semantic_profile.id": "scope",
    "link.relation": "link",
}


def _trace_derivation_contract(
    contract: Mapping[str, FrozenJSON],
) -> tuple[Mapping[tuple[str, str], str], tuple[Mapping[str, FrozenJSON], ...]]:
    raw_derivations = contract["trace_derivations"]
    if not isinstance(raw_derivations, tuple) or len(raw_derivations) != 11:
        raise CandidateRenderError("materialized trace derivation inventory is incomplete")
    value_sources: dict[tuple[str, str], str] = {}
    frozen_derivations: list[Mapping[str, FrozenJSON]] = []
    target_field_count = 0
    for raw_derivation in raw_derivations:
        derivation = _tagged(raw_derivation, "TraceDerivationIR", _TRACE_DERIVATION_FIELDS)
        target_attribute = derivation["target_attribute"]
        target_field = derivation["target_field"]
        source = _string(derivation["source"], "trace derivation source")
        if (target_attribute is None) == (target_field is None):
            raise CandidateRenderError("materialized trace derivation target is invalid")
        if target_field is not None:
            if target_field != "trace_scope.version" or source != "provenance.binary_version":
                raise CandidateRenderError("materialized structural trace derivation is invalid")
            target_field_count += 1
        else:
            context = _TRACE_DERIVATION_CONTEXT_BY_SOURCE.get(source)
            if context is None:
                raise CandidateRenderError("materialized trace derivation source is unknown")
            key = (context, _string(target_attribute, "trace derivation attribute"))
            if key in value_sources:
                raise CandidateRenderError("materialized trace derivation target is duplicated")
            value_sources[key] = source
        frozen_derivations.append(_freeze(_plain_ir(raw_derivation)))
    if target_field_count != 1 or len(value_sources) != 10:
        raise CandidateRenderError("materialized trace derivation target inventory is invalid")
    return MappingProxyType(value_sources), tuple(frozen_derivations)


def _effective_occurrence_constraints(
    normalization_constraints: Mapping[str, FrozenJSON],
    use_constraints: Mapping[str, FrozenJSON],
) -> Mapping[str, FrozenJSON]:
    """Materialize the final restrictive overlay so downstream plans never join it."""

    base = _validated_constraint_map(normalization_constraints, "enriched normalization constraints")
    use = _validated_constraint_map(use_constraints, "enriched occurrence constraints")
    _validate_constraint_restriction(use, base, "enriched occurrence constraints")
    effective = dict(base)
    effective.update(use)
    return _freeze(effective)


def _validated_span_name_parts(family: Mapping[str, FrozenJSON]) -> tuple[Mapping[str, FrozenJSON], ...]:
    raw_parts = family["span_name_parts"]
    if not isinstance(raw_parts, tuple) or not raw_parts:
        raise CandidateRenderError("materialized span-name parts are incomplete")
    parts: list[Mapping[str, FrozenJSON]] = []
    rendered: list[str] = []
    resolved_uses = {use["ref"]: use for raw_use in family["resolved_uses"] for use in (_resolved_use(raw_use),)}
    for raw_part in raw_parts:
        part = _tagged(raw_part, "SpanNamePartIR", _SPAN_NAME_PART_FIELDS)
        kind = part["kind"]
        literal = part["literal"]
        field = part["field"]
        if kind == "literal":
            if not isinstance(literal, str) or not literal or field is not None:
                raise CandidateRenderError("materialized literal span-name part is invalid")
            rendered.append(literal)
        elif kind == "field":
            field = _string(field, "span-name field")
            use = resolved_uses.get(field)
            if (
                literal is not None
                or use is None
                or use["role"] != "attributes"
                or use["requirement_level"] != "required"
                or use["conditional"] is not None
            ):
                raise CandidateRenderError("materialized field span-name part is invalid")
            rendered.append("{" + field + "}")
        else:
            raise CandidateRenderError("materialized span-name part kind is invalid")
        parts.append(_freeze(_plain_ir(raw_part)))
    if "".join(rendered) != family["span_name_pattern"]:
        raise CandidateRenderError("materialized span-name parts disagree with pattern")
    return tuple(parts)


def _enriched_field_descriptors(
    *,
    attributes: Mapping[str, CandidateAttribute],
    groups: Mapping[str, Mapping[str, FrozenJSON]],
    families: Sequence[Mapping[str, FrozenJSON]],
    span_events: Mapping[str, Mapping[str, FrozenJSON]],
    structured_types: Mapping[str, Mapping[str, FrozenJSON]],
    conditions: Mapping[str, tuple[str, str]],
    value_sources: Mapping[tuple[str, str], str],
) -> Mapping[str, EnrichedFieldDescriptor]:
    descriptors: dict[str, EnrichedFieldDescriptor] = {}

    def contribute(
        owner: Mapping[str, FrozenJSON],
        *,
        context: str,
        owner_id: str,
        path_prefix: str,
        input_placement: str,
        target_slot: str,
    ) -> tuple[str, ...]:
        descriptor_ids: list[str] = []
        for order, raw_use in enumerate(owner["resolved_uses"]):
            use = _resolved_use(raw_use)
            ref = _string(use["ref"], "enriched field attribute")
            attribute = attributes.get(ref)
            if attribute is None:
                raise CandidateRenderError("enriched field references an unknown attribute")
            metadata = attribute.metadata
            condition_id = use["conditional"]
            condition_fact: str | None = None
            false_requirement: str | None = None
            if condition_id is not None:
                condition = conditions.get(condition_id)
                if condition is None:
                    raise CandidateRenderError("enriched field condition is unknown")
                condition_fact, false_requirement = condition
            descriptor_id = f"{context}:{owner_id}:{ref}"
            if descriptor_id in descriptors:
                raise CandidateRenderError("enriched field descriptor is duplicated")
            raw_origins = use["origins"]
            if not isinstance(raw_origins, tuple) or not raw_origins:
                raise CandidateRenderError("enriched field origins are incomplete")
            origins = tuple(_freeze(_origin_projection(origin)) for origin in raw_origins)
            use_constraints = _freeze(_validated_constraint_map(use["constraints"], "enriched use constraints"))
            normalization = metadata["normalization"]
            value_source = value_sources.get((context, ref), "input")
            final_constraints = _effective_occurrence_constraints(
                normalization["effective_constraints"],
                use_constraints,
            )
            descriptor = EnrichedFieldDescriptor(
                id=descriptor_id,
                context=context,
                owner_id=owner_id,
                attribute_id=ref,
                order=order,
                role=_string(use["role"], "enriched field role"),
                path=f"{path_prefix}/{_pointer_token(ref)}",
                path_kind="payload_template",
                input_placement=input_placement if value_source == "input" else "private_derived",
                target_slot=target_slot,
                field_types=attribute.field_types,
                structured_type=attribute.structured_type,
                canonical_owner=_string(metadata["owner"], "enriched canonical owner"),
                requirement_level=_string(use["requirement_level"], "enriched requirement"),
                condition_id=condition_id,
                condition_fact=condition_fact,
                condition_false_requirement=false_requirement,
                field_class=_string(metadata["field_class"], "enriched field class"),
                sensitivity=_string(metadata["sensitivity"], "enriched sensitivity"),
                cardinality=_string(metadata["cardinality"], "enriched cardinality"),
                stability=_string(metadata["stability"], "enriched stability"),
                introduced_in=metadata["introduced_in"],
                deprecated_in=metadata["deprecated_in"],
                removed_in=metadata["removed_in"],
                normalization_id=_string(normalization["id"], "enriched normalization"),
                normalization_effective_constraints=_freeze(normalization["effective_constraints"]),
                use_constraints=use_constraints,
                effective_constraints=final_constraints,
                value_source=value_source,
                origins=origins,
            )
            descriptors[descriptor_id] = descriptor
            descriptor_ids.append(descriptor_id)
        return tuple(descriptor_ids)

    for family in families:
        family_id = _string(family["id"], "enriched family id")
        family_type = family["type"]
        if family_type == "log":
            contribute(
                family,
                context="log",
                owner_id=family_id,
                path_prefix="/body",
                input_placement="family_input",
                target_slot="body",
            )
        elif family_type == "span":
            contribute(
                family,
                context="span",
                owner_id=family_id,
                path_prefix="/body/attributes",
                input_placement="family_input",
                target_slot="trace.attributes",
            )
        elif family_type == "metric":
            contribute(
                family,
                context="metric",
                owner_id=family_id,
                path_prefix="/instrument_data/attributes",
                input_placement="family_input",
                target_slot="metric.attributes",
            )
        else:
            raise CandidateRenderError("enriched family signal is invalid")
    contribute(
        groups["resource.core"],
        context="resource",
        owner_id="resource.core",
        path_prefix="/body/resource/attributes",
        input_placement="resource_input",
        target_slot="trace.resource.attributes",
    )
    contribute(
        groups["scope.core"],
        context="scope",
        owner_id="scope.core",
        path_prefix="/body/scope/attributes",
        input_placement="family_input",
        target_slot="trace.scope.attributes",
    )
    for event_name in sorted(span_events):
        contribute(
            span_events[event_name],
            context="event",
            owner_id=event_name,
            path_prefix="/body/events/*/attributes",
            input_placement="event_input",
            target_slot="trace.event.attributes",
        )
    contribute(
        groups["link.core"],
        context="link",
        owner_id="link.core",
        path_prefix="/body/links/*/attributes",
        input_placement="link_input",
        target_slot="trace.link.attributes",
    )

    def contribute_structured_scalar(
        *,
        type_id: str,
        member_id: str,
        role: str,
        order: int,
        requirement: str,
        field_type: str,
        field_class: str,
        sensitivity: str,
        normalization_id: str,
        normalization_constraints: Mapping[str, FrozenJSON],
        origin: str,
    ) -> str:
        descriptor_id = f"structured:{type_id}:{member_id}"
        if descriptor_id in descriptors:
            raise CandidateRenderError("structured scalar field descriptor is duplicated")
        descriptors[descriptor_id] = EnrichedFieldDescriptor(
            id=descriptor_id,
            context="structured",
            owner_id=type_id,
            attribute_id=member_id,
            order=order,
            role=role,
            path=f"/structured/{_pointer_token(type_id)}/{_pointer_token(member_id)}",
            path_kind="registry_relative",
            input_placement="structured_input",
            target_slot="structured.value",
            field_types=(field_type,),
            structured_type=None,
            canonical_owner=None,
            requirement_level=requirement,
            condition_id=None,
            condition_fact=None,
            condition_false_requirement=None,
            field_class=field_class,
            sensitivity=sensitivity,
            cardinality=None,
            stability=None,
            introduced_in=structured_types[type_id]["introduced_in"],
            deprecated_in=None,
            removed_in=None,
            normalization_id=normalization_id,
            normalization_effective_constraints=_freeze(normalization_constraints),
            use_constraints=MappingProxyType({}),
            effective_constraints=_freeze(normalization_constraints),
            value_source="input",
            origins=(
                MappingProxyType(
                    {
                        "structured_type": type_id,
                        "member_id": member_id,
                        "role": role,
                        "origin": origin,
                    }
                ),
            ),
        )
        return descriptor_id

    for type_id, structured in structured_types.items():
        order = 0
        for raw_field in structured["fields"] or ():
            field = _tagged(raw_field, "StructuredFieldIR", _STRUCTURED_FIELD_FIELDS)
            if field["scalar"] is None:
                continue
            scalar = _validate_structured_scalar_node(field["scalar"])
            normalization = _normalization(scalar, field_types=(scalar["field_type"],))
            contribute_structured_scalar(
                type_id=type_id,
                member_id=f"field:{field['name']}",
                role="fixed_field",
                order=order,
                requirement="required" if field["required"] else "optional",
                field_type=_string(scalar["field_type"], "structured scalar type"),
                field_class=_string(scalar["field_class"], "structured scalar class"),
                sensitivity=_string(scalar["sensitivity"], "structured scalar sensitivity"),
                normalization_id=normalization["id"],
                normalization_constraints=normalization["effective_constraints"],
                origin=f"structured_types.{type_id}.fields.{field['name']}",
            )
            order += 1
        if structured["discriminator"] is not None:
            discriminator = _tagged(
                structured["discriminator"],
                "StructuredDiscriminatorIR",
                _STRUCTURED_DISCRIMINATOR_FIELDS,
            )
            normalization = _normalization(discriminator, field_types=(discriminator["field_type"],))
            contribute_structured_scalar(
                type_id=type_id,
                member_id=f"discriminator:{discriminator['name']}",
                role="discriminator",
                order=order,
                requirement="required",
                field_type=_string(discriminator["field_type"], "structured discriminator type"),
                field_class=_string(discriminator["field_class"], "structured discriminator class"),
                sensitivity=_string(discriminator["sensitivity"], "structured discriminator sensitivity"),
                normalization_id=normalization["id"],
                normalization_constraints=normalization["effective_constraints"],
                origin=f"structured_types.{type_id}.discriminator",
            )
            order += 1
        if structured["dynamic_members"] is not None:
            dynamic = _tagged(
                structured["dynamic_members"],
                "StructuredDynamicMembersIR",
                _STRUCTURED_DYNAMIC_MEMBERS_FIELDS,
            )
            name = _validate_structured_scalar_node(dynamic["name"], "StructuredDynamicNameIR")
            normalization = _normalization(name, field_types=(name["field_type"],))
            contribute_structured_scalar(
                type_id=type_id,
                member_id=f"dynamic_name:{dynamic['member_id']}",
                role="dynamic_member_name",
                order=order,
                requirement="required",
                field_type=_string(name["field_type"], "dynamic member name type"),
                field_class=_string(name["field_class"], "dynamic member name class"),
                sensitivity=_string(name["sensitivity"], "dynamic member name sensitivity"),
                normalization_id=normalization["id"],
                normalization_constraints=normalization["effective_constraints"],
                origin=f"structured_types.{type_id}.dynamic_members.name",
            )
            order += 1
        if structured["canonical_json"] is not None:
            canonical = _tagged(
                structured["canonical_json"],
                "CanonicalJSONContractIR",
                _CANONICAL_JSON_CONTRACT_FIELDS,
            )
            object_name = _validate_structured_scalar_node(canonical["object_name"], "StructuredDynamicNameIR")
            object_name_normalization = _normalization(
                object_name,
                field_types=(object_name["field_type"],),
            )
            contribute_structured_scalar(
                type_id=type_id,
                member_id=f"dynamic_name:{canonical['object_member_id']}",
                role="canonical_object_member_name",
                order=order,
                requirement="required",
                field_type=_string(object_name["field_type"], "canonical object member name type"),
                field_class=_string(object_name["field_class"], "canonical object member name class"),
                sensitivity=_string(object_name["sensitivity"], "canonical object member name sensitivity"),
                normalization_id=object_name_normalization["id"],
                normalization_constraints=object_name_normalization["effective_constraints"],
                origin=f"structured_types.{type_id}.canonical_json.object_name",
            )
            order += 1
            limits = _tagged(
                canonical["limits"],
                "CanonicalJSONLimitsIR",
                _CANONICAL_JSON_LIMITS_FIELDS,
            )
            canonical_arms = (
                ("boolean", "boolean", {}),
                ("int64", "int64", {}),
                ("finite_double", "double", {}),
                ("string", "string", {"max_utf8_bytes": limits["max_string_utf8_bytes"]}),
            )
            for arm_id, field_type, constraints in canonical_arms:
                contribute_structured_scalar(
                    type_id=type_id,
                    member_id=f"canonical_arm:{arm_id}",
                    role="canonical_scalar_arm",
                    order=order,
                    requirement="required",
                    field_type=field_type,
                    field_class=_string(canonical["leaf_field_class"], "canonical leaf class"),
                    sensitivity=_string(canonical["leaf_sensitivity"], "canonical leaf sensitivity"),
                    normalization_id="canonical-json-contract-v1",
                    normalization_constraints=constraints,
                    origin=f"structured_types.{type_id}.canonical_json.{arm_id}",
                )
                order += 1
    if not descriptors:
        raise CandidateRenderError("enriched field descriptor inventory is empty")
    return MappingProxyType({key: descriptors[key] for key in sorted(descriptors)})


def _enriched_container_descriptors(
    contract: Mapping[str, FrozenJSON],
    structured_types: Mapping[str, Mapping[str, FrozenJSON]],
    enriched_fields: Mapping[str, EnrichedFieldDescriptor],
) -> Mapping[str, EnrichedContainerDescriptor]:
    descriptors: dict[str, EnrichedContainerDescriptor] = {}
    structural_paths = {
        "envelope": "",
        "correlation": "/correlation",
        "provenance": "/provenance",
        "provenance_import": "/provenance/import",
        "trace_body": "/body",
        "trace_resource": "/body/resource",
        "trace_scope": "/body/scope",
        "trace_status": "/body/status",
        "trace_event": "/body/events/*",
        "trace_link": "/body/links/*",
        "metric_instrument_data": "/instrument_data",
    }
    for contract_key, base_path in structural_paths.items():
        structural = _tagged(contract[contract_key], "StructuralObjectIR", _STRUCTURAL_OBJECT_FIELDS)
        object_id = _string(structural["id"], "structural object id")
        object_descriptor_id = f"structural:{object_id}"
        fields = structural["fields"]
        if not isinstance(fields, tuple):
            raise CandidateRenderError("materialized structural fields are invalid")
        child_containers: list[str] = []
        for raw_field in fields:
            field = _tagged(raw_field, "StructuralFieldIR", _STRUCTURAL_FIELD_FIELDS)
            field_type = field["field_type"]
            if field_type not in {"object", "array", "canonical_json", "field_class_map"}:
                continue
            field_name = _string(field["name"], "structural container field")
            descriptor_id = f"structural-field:{object_id}:{field_name}"
            normalization = _normalization(
                field,
                field_types=(field_type,),
                structured=True,
                polymorphic=field_type == "canonical_json",
            )
            effective = normalization["effective_constraints"]
            bounds = {
                key: effective[key]
                for key in ("min_items", "max_items", "max_depth", "max_properties", "max_utf8_bytes")
                if key in effective
            }
            reference_target = field["object_ref"] or field["item_ref"] or field["semantic_ref"]
            descriptors[descriptor_id] = EnrichedContainerDescriptor(
                id=descriptor_id,
                context="structural_field",
                owner_id=object_id,
                kind=field_type,
                path=f"{base_path}/{_pointer_token(field_name)}" or "/",
                closed=field_type in {"object", "array", "field_class_map"},
                requirement_level="required" if field["required"] else "optional",
                introduced_in=None,
                deprecated_in=None,
                removed_in=None,
                bounds=_freeze(bounds),
                origin=f"structural_contract.{contract_key}.{field_name}",
                child_fields=(),
                child_containers=(),
                reference_target=reference_target,
            )
            child_containers.append(descriptor_id)
        descriptors[object_descriptor_id] = EnrichedContainerDescriptor(
            id=object_descriptor_id,
            context="structural_object",
            owner_id=object_id,
            kind="object",
            path=base_path or "/",
            closed=structural["additional_properties"] is False,
            requirement_level=None,
            introduced_in=None,
            deprecated_in=None,
            removed_in=None,
            bounds=MappingProxyType({}),
            origin=f"structural_contract.{contract_key}",
            child_fields=tuple(
                _string(_tagged(item, "StructuralFieldIR", _STRUCTURAL_FIELD_FIELDS)["name"], "field")
                for item in fields
            ),
            child_containers=tuple(child_containers),
            reference_target=None,
        )

    def add_structured_edge(
        *,
        owner: str,
        edge_id: str,
        path: str,
        target: str,
        requirement: str | None,
        origin: str,
    ) -> str:
        descriptor_id = f"structured-edge:{owner}:{edge_id}"
        if descriptor_id in descriptors or target not in structured_types:
            raise CandidateRenderError("structured container edge is invalid")
        descriptors[descriptor_id] = EnrichedContainerDescriptor(
            descriptor_id,
            "structured_reference",
            owner,
            "reference",
            path,
            True,
            requirement,
            structured_types[owner]["introduced_in"],
            None,
            None,
            MappingProxyType({}),
            origin,
            (),
            (),
            target,
        )
        return descriptor_id

    for type_id, structured in structured_types.items():
        child_fields: list[str] = []
        child_containers: list[str] = []
        for raw_field in structured["fields"] or ():
            field = _tagged(raw_field, "StructuredFieldIR", _STRUCTURED_FIELD_FIELDS)
            name = _string(field["name"], "structured field name")
            if field["scalar"] is not None:
                descriptor_id = f"structured:{type_id}:field:{name}"
                if descriptor_id not in enriched_fields:
                    raise CandidateRenderError("structured scalar child descriptor is missing")
                child_fields.append(descriptor_id)
            else:
                target = _string(
                    _tagged(field["reference"], "StructuredReferenceIR", _STRUCTURED_REFERENCE_FIELDS)[
                        "structured_ref"
                    ],
                    "structured field reference",
                )
                child_containers.append(
                    add_structured_edge(
                        owner=type_id,
                        edge_id=f"field:{name}",
                        path=f"/structured/{_pointer_token(type_id)}/{_pointer_token(name)}",
                        target=target,
                        requirement="required" if field["required"] else "optional",
                        origin=f"structured_types.{type_id}.fields.{name}",
                    )
                )
        if structured["discriminator"] is not None:
            discriminator = _tagged(
                structured["discriminator"],
                "StructuredDiscriminatorIR",
                _STRUCTURED_DISCRIMINATOR_FIELDS,
            )
            child_fields.append(f"structured:{type_id}:discriminator:{discriminator['name']}")
        if structured["items_reference"] is not None:
            target = _string(
                _tagged(structured["items_reference"], "StructuredReferenceIR", _STRUCTURED_REFERENCE_FIELDS)[
                    "structured_ref"
                ],
                "structured item reference",
            )
            child_containers.append(
                add_structured_edge(
                    owner=type_id,
                    edge_id="items",
                    path=f"/structured/{_pointer_token(type_id)}/*",
                    target=target,
                    requirement="required",
                    origin=f"structured_types.{type_id}.items_reference",
                )
            )
        if structured["dynamic_members"] is not None:
            dynamic = _tagged(
                structured["dynamic_members"], "StructuredDynamicMembersIR", _STRUCTURED_DYNAMIC_MEMBERS_FIELDS
            )
            target = _string(
                _tagged(dynamic["value"], "StructuredReferenceIR", _STRUCTURED_REFERENCE_FIELDS)["structured_ref"],
                "structured dynamic member reference",
            )
            child_containers.append(
                add_structured_edge(
                    owner=type_id,
                    edge_id=f"dynamic:{dynamic['member_id']}",
                    path=f"/structured/{_pointer_token(type_id)}/*",
                    target=target,
                    requirement="optional",
                    origin=f"structured_types.{type_id}.dynamic_members",
                )
            )
            child_fields.append(f"structured:{type_id}:dynamic_name:{dynamic['member_id']}")
        for raw_variant in structured["variants"] or ():
            variant = _tagged(raw_variant, "StructuredVariantIR", _STRUCTURED_VARIANT_FIELDS)
            tag = _string(variant["tag"], "structured variant tag")
            target = _string(variant["structured_ref"], "structured variant reference")
            variant_id = f"structured-variant:{type_id}:{tag}"
            edge_id = add_structured_edge(
                owner=type_id,
                edge_id=f"variant:{tag}",
                path=f"/structured/{_pointer_token(type_id)}/@{_pointer_token(tag)}",
                target=target,
                requirement="required",
                origin=f"structured_types.{type_id}.variants.{tag}",
            )
            descriptors[variant_id] = EnrichedContainerDescriptor(
                variant_id,
                "structured_variant",
                type_id,
                "tagged_union_variant",
                f"/structured/{_pointer_token(type_id)}/@{_pointer_token(tag)}",
                True,
                "required",
                structured["introduced_in"],
                None,
                None,
                MappingProxyType({}),
                f"structured_types.{type_id}.variants.{tag}",
                (),
                (edge_id,),
                target,
            )
            child_containers.append(variant_id)
        if structured["dynamic_variant"] is not None:
            variant = _tagged(
                structured["dynamic_variant"],
                "StructuredDynamicVariantIR",
                _STRUCTURED_DYNAMIC_VARIANT_FIELDS,
            )
            arm_id = _string(variant["arm_id"], "structured dynamic arm")
            target = _string(variant["structured_ref"], "structured dynamic variant reference")
            edge_id = add_structured_edge(
                owner=type_id,
                edge_id=f"variant:{arm_id}",
                path=f"/structured/{_pointer_token(type_id)}/@{_pointer_token(arm_id)}",
                target=target,
                requirement="optional",
                origin=f"structured_types.{type_id}.dynamic_variant",
            )
            variant_id = f"structured-variant:{type_id}:{arm_id}"
            descriptors[variant_id] = EnrichedContainerDescriptor(
                variant_id,
                "structured_variant",
                type_id,
                "tagged_union_variant",
                f"/structured/{_pointer_token(type_id)}/@{_pointer_token(arm_id)}",
                True,
                "optional",
                structured["introduced_in"],
                None,
                None,
                MappingProxyType({}),
                f"structured_types.{type_id}.dynamic_variant",
                (),
                (edge_id,),
                target,
            )
            child_containers.append(variant_id)
        if structured["canonical_json"] is not None:
            canonical = _tagged(
                structured["canonical_json"], "CanonicalJSONContractIR", _CANONICAL_JSON_CONTRACT_FIELDS
            )
            child_fields.append(f"structured:{type_id}:dynamic_name:{canonical['object_member_id']}")
            for arm in canonical["arms"]:
                arm = _string(arm, "canonical JSON arm")
                variant_id = f"structured-variant:{type_id}:{arm}"
                variant_children: tuple[str, ...] = ()
                target: str | None = None
                if arm == "array":
                    target = _string(canonical["array_items_ref"], "canonical JSON array reference")
                    variant_children = (
                        add_structured_edge(
                            owner=type_id,
                            edge_id="canonical:array",
                            path=f"/structured/{_pointer_token(type_id)}/@array/*",
                            target=target,
                            requirement="optional",
                            origin=f"structured_types.{type_id}.canonical_json.array",
                        ),
                    )
                elif arm == "object":
                    target = _string(
                        _tagged(canonical["object_value"], "StructuredReferenceIR", _STRUCTURED_REFERENCE_FIELDS)[
                            "structured_ref"
                        ],
                        "canonical JSON object reference",
                    )
                    variant_children = (
                        add_structured_edge(
                            owner=type_id,
                            edge_id="canonical:object",
                            path=f"/structured/{_pointer_token(type_id)}/@object/*",
                            target=target,
                            requirement="optional",
                            origin=f"structured_types.{type_id}.canonical_json.object",
                        ),
                    )
                descriptors[variant_id] = EnrichedContainerDescriptor(
                    variant_id,
                    "structured_variant",
                    type_id,
                    "sealed_union_variant",
                    f"/structured/{_pointer_token(type_id)}/@{_pointer_token(arm)}",
                    True,
                    "optional",
                    structured["introduced_in"],
                    None,
                    None,
                    MappingProxyType({}),
                    f"structured_types.{type_id}.canonical_json.{arm}",
                    (),
                    variant_children,
                    target,
                )
                child_containers.append(variant_id)
                if arm in {"boolean", "int64", "finite_double", "string"}:
                    scalar_id = f"structured:{type_id}:canonical_arm:{arm}"
                    child_fields.append(scalar_id)
                    descriptors[variant_id] = dataclasses.replace(
                        descriptors[variant_id],
                        child_fields=(scalar_id,),
                    )
        bounds = {key: structured[key] for key in ("min_items", "max_items") if structured[key] is not None}
        if structured["canonical_json"] is not None:
            limits = _tagged(
                _tagged(structured["canonical_json"], "CanonicalJSONContractIR", _CANONICAL_JSON_CONTRACT_FIELDS)[
                    "limits"
                ],
                "CanonicalJSONLimitsIR",
                _CANONICAL_JSON_LIMITS_FIELDS,
            )
            bounds.update(limits)
        descriptor_id = f"structured:{type_id}"
        descriptors[descriptor_id] = EnrichedContainerDescriptor(
            descriptor_id,
            "structured_type",
            type_id,
            _string(structured["kind"], "structured container kind"),
            f"/structured/{_pointer_token(type_id)}",
            structured["additional_properties"] is False,
            None,
            structured["introduced_in"],
            None,
            None,
            _freeze(bounds),
            f"structured_types.{type_id}",
            tuple(child_fields),
            tuple(child_containers),
            None,
        )
    for descriptor in descriptors.values():
        if descriptor.context in {"structured_type", "structured_variant"} and any(
            child not in enriched_fields for child in descriptor.child_fields
        ):
            raise CandidateRenderError("structured container scalar child link is unresolved")
    return MappingProxyType({key: descriptors[key] for key in sorted(descriptors)})


def _enriched_family_descriptors(
    *,
    families: Sequence[Mapping[str, FrozenJSON]],
    family_domains: Mapping[str, str],
    fields: Mapping[str, EnrichedFieldDescriptor],
    span_events: Mapping[str, Mapping[str, FrozenJSON]],
    groups: Mapping[str, Mapping[str, FrozenJSON]],
    derivations: tuple[Mapping[str, FrozenJSON], ...],
    mandatory_programs: Mapping[str, ResolvedMandatoryProgramIR],
) -> tuple[
    Mapping[str, EnrichedFamilyDescriptor],
    Mapping[str, EnrichedTraceDescriptor],
    Mapping[str, EnrichedMetricDescriptor],
]:
    enriched_families: dict[str, EnrichedFamilyDescriptor] = {}
    traces: dict[str, EnrichedTraceDescriptor] = {}
    metrics: dict[str, EnrichedMetricDescriptor] = {}

    def ids(context: str, owner_id: str) -> tuple[str, ...]:
        return tuple(
            descriptor.id
            for descriptor in fields.values()
            if descriptor.context == context and descriptor.owner_id == owner_id
        )

    resource_ids = ids("resource", "resource.core")
    scope_ids = ids("scope", "scope.core")
    link_ids = ids("link", "link.core")
    event_ids = MappingProxyType({event_name: ids("event", event_name) for event_name in sorted(span_events)})
    for family in sorted(families, key=lambda item: item["id"]):
        family_id = _string(family["id"], "enriched family id")
        family_type = family["type"]
        signal = {"log": "logs", "span": "traces", "metric": "metrics"}.get(family_type)
        if signal is None:
            raise CandidateRenderError("enriched family signal is invalid")
        family_field_ids = ids(family_type, family_id)
        allowed_outcomes = family["allowed_outcomes"] or ()
        compatibility_profiles = family["compatibility_profiles"] or ()
        enriched_families[family_id] = EnrichedFamilyDescriptor(
            family_id,
            family_domains[family_id],
            signal,
            _string(family["bucket"], "family bucket"),
            _family_event_name(family),
            _integer(family["family_schema_version"], "family schema version", minimum=1),
            _string(family["stability"], "family stability"),
            family["introduced_in"],
            family["deprecated_in"],
            family["removed_in"],
            family["outcome_requirement"],
            tuple(allowed_outcomes),
            family["route_selector"] is True,
            tuple(compatibility_profiles),
            family_field_ids,
            family_id if family_type == "log" else None,
        )
        if family_type == "span":
            parts = _validated_span_name_parts(family)
            for part in parts:
                if part["kind"] != "field":
                    continue
                matches = tuple(
                    fields[descriptor_id]
                    for descriptor_id in family_field_ids
                    if fields[descriptor_id].attribute_id == part["field"]
                )
                if (
                    len(matches) != 1
                    or matches[0].role != "attributes"
                    or matches[0].requirement_level != "required"
                    or matches[0].condition_id is not None
                    or matches[0].condition_fact is not None
                    or matches[0].field_types != ("string",)
                    or matches[0].structured_type is not None
                ):
                    raise CandidateRenderError("enriched field span-name part is invalid")
            referenced_event_ids = MappingProxyType(
                {event_name: event_ids[event_name] for event_name in family["event_refs"] if event_name in event_ids}
            )
            if len(referenced_event_ids) != len(family["event_refs"]):
                raise CandidateRenderError("enriched trace references an unknown event")
            traces[family_id] = EnrichedTraceDescriptor(
                family_id,
                _string(family["span_name_pattern"], "span name pattern"),
                parts,
                tuple(family["span_kinds"]),
                _string(family["span_status_rule"], "span status rule"),
                family_field_ids,
                resource_ids,
                scope_ids,
                referenced_event_ids,
                link_ids,
                tuple(family["event_refs"]),
                tuple(family["link_relations"]),
                derivations,
            )
        elif family_type == "metric":
            metrics[family_id] = EnrichedMetricDescriptor(
                family_id,
                _string(family["instrument_name"], "metric instrument"),
                _string(family["instrument_type"], "metric instrument type"),
                _string(family["metric_value_type"], "metric value type"),
                _string(family["metric_unit"], "metric unit"),
                _string(family["metric_description"], "metric description"),
                _string(family["metric_temporality"], "metric temporality"),
                tuple(family["metric_boundaries"] or ()),
                family_field_ids,
                tuple(_freeze(_plain_ir(item)) for item in family["metric_projections"]),
            )
    expected_family_ids = {_string(family["id"], "family ID") for family in families}
    expected_trace_ids = {
        _string(family["id"], "span family ID") for family in families if family["type"] == "span"
    }
    expected_metric_ids = {
        _string(family["id"], "metric family ID") for family in families if family["type"] == "metric"
    }
    if (
        set(enriched_families) != expected_family_ids
        or set(traces) != expected_trace_ids
        or set(metrics) != expected_metric_ids
    ):
        raise CandidateRenderError("enriched family descriptor inventory is incomplete")
    return (
        MappingProxyType(enriched_families),
        MappingProxyType(traces),
        MappingProxyType(metrics),
    )


def _expanded_producer_mappings(
    domains: Sequence[CandidateDomain],
    families: Mapping[str, EnrichedFamilyDescriptor],
    programs: Mapping[str, ResolvedMandatoryProgramIR],
    mandatory_rules: Mapping[str, tuple[str, str | None]],
) -> tuple[ExpandedProducerMappingDescriptor, ...]:
    rows: list[ExpandedProducerMappingDescriptor] = []
    for domain in domains:
        for mapping_index, mapping in enumerate(domain.producer_mappings):
            legacy_rules = mapping["mandatory_rules"]
            if not isinstance(legacy_rules, tuple) or any(rule not in mandatory_rules for rule in legacy_rules):
                raise CandidateRenderError("materialized producer legacy mandatory rules are invalid")
            identities: list[tuple[str, Mapping[str, FrozenJSON]]] = []
            default_identity = mapping["default_identity"]
            if default_identity is not None:
                if not isinstance(default_identity, Mapping):
                    raise CandidateRenderError("materialized producer default identity is invalid")
                identities.append(("default", default_identity))
            contextual = mapping["allowed_context_identities"]
            if not isinstance(contextual, tuple):
                raise CandidateRenderError("materialized producer contextual identities are invalid")
            identities.extend(("allowed_context", identity) for identity in contextual)
            for identity_index, (origin, identity) in enumerate(identities):
                event_name = _string(identity["event_name"], "producer identity event name")
                bucket = _string(identity["bucket"], "producer identity bucket")
                family_id = identity["family"]
                compatibility_only = identity["compatibility_only"]
                selected_program_id: str | None = None
                if type(compatibility_only) is not bool:
                    raise CandidateRenderError("materialized producer compatibility flag is invalid")
                if family_id is None:
                    if compatibility_only is not True:
                        raise CandidateRenderError("familyless producer identity is not compatibility-only")
                else:
                    family_id = _string(family_id, "producer identity family")
                    family = families.get(family_id)
                    if (
                        compatibility_only
                        or family is None
                        or family.signal != "logs"
                        or family.removed_in is not None
                        or family.bucket != bucket
                        or family.event_name != event_name
                    ):
                        raise CandidateRenderError("producer identity disagrees with selected canonical family")
                    if family_id not in programs:
                        raise CandidateRenderError("producer identity has no selected-family mandatory program")
                    selected_program_id = family_id
                compatibility = mapping["compatibility"]
                if not isinstance(compatibility, Mapping):
                    raise CandidateRenderError("materialized producer compatibility is invalid")
                rows.append(
                    ExpandedProducerMappingDescriptor(
                        id=f"{domain.id}:{mapping_index}:{origin}:{identity_index}",
                        domain=domain.id,
                        mapping_index=mapping_index,
                        identity_index=identity_index,
                        identity_origin=origin,
                        producer=_string(mapping["producer"], "producer kind"),
                        key=_string(mapping["key"], "producer key"),
                        source=_string(mapping["source"], "producer source"),
                        event_name_policy=_string(mapping["event_name_policy"], "producer event-name policy"),
                        severity_policy=_string(mapping["severity_policy"], "producer severity policy"),
                        event_name=event_name,
                        bucket=bucket,
                        family_id=family_id,
                        compatibility_only=compatibility_only,
                        selected_mandatory_program_id=selected_program_id,
                        legacy_mapping_mandatory_rules=tuple(legacy_rules),
                        companion_rules=tuple(mapping["companion_rules"]),
                        compatibility=_freeze(compatibility),
                    )
                )
    if len({row.id for row in rows}) != len(rows):
        raise CandidateRenderError("expanded producer identity row inventory contains duplicate IDs")
    return tuple(rows)


_INBOUND_CLASS_IDS: Final = (
    "otlp.native.log.v8",
    "otlp.native.span.v8",
    "otlp.native.metric.v8",
    "otlp.genai.span.operation.v1",
    "otlp.codex.turn_span.v1",
    "otlp.codex.user_prompt.v1",
    "otlp.codex.tool_result.v1",
    "otlp.claudecode.user_prompt.v1",
    "otlp.codex.response_completed.v1",
    "otlp.claudecode.token_usage.v1",
    "otlp.codex.token_usage.v1",
    "otlp.genai.duration.metric.v1",
)
_INBOUND_SOURCE_PROJECTION_PLAN_IDS: Final = (
    "genai-token-metric-v1",
    "genai-duration-metric-v1",
)
_INBOUND_SOURCE_NORMALIZER_IDS: Final = (
    "bounded-label-v1",
    "identifier-label-v1",
    "genai-provider-label-v1",
    "genai-model-label-v1",
    "genai-operation-label-v1",
    "token-type-label-v1",
)
_INBOUND_SOURCE_PLACEMENTS: Final = frozenset(
    {"metric_point_attribute", "resource_attribute", "authenticated_source", "fixed", "instrument_name"}
)
_INBOUND_TOKEN_TYPES: Final = ["input", "output", "cacheRead", "cacheCreation"]
_INBOUND_CUMULATIVE_COMPONENT_IDS: Final = [
    "authenticated_source",
    "resource_service_name",
    "resource_service_instance_id",
    "instrument_name",
    "normalized_model",
    "token_type",
    "normalized_conversation",
]
_INBOUND_SOURCE_UNIT_TABLES: Final = {
    "duration-metric-v1": (
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
    ),
    "claude-token-usage-v1": (("", 1.0), ("{token}", 1.0), ("token", 1.0), ("tokens", 1.0)),
}
_INBOUND_IR_FIELDS: Final = frozenset(
    {
        "version",
        "max_forward_hops",
        "unknown_fields",
        "semantic_resource_instance_key",
        "forward_instance_key",
        "forward_destination_key",
        "forward_hop_count_key",
        "record_id_key",
        "scope_name",
        "scope_schema_url",
        "resource_schema_url",
        "shape_policy",
        "alias_sets",
        "source_normalizers",
        "source_projection_plans",
        "binding_classes",
        "match_descriptors",
        "target_descriptors",
        "native_markers",
        "echo_recognizers",
        "import_contexts",
        "derivation_attachments",
        "fixture_policy",
    }
)


def _candidate_inbound_source_unit_rule(
    raw: Any,
    *,
    strategy: str,
    family_unit: str | None,
) -> Mapping[str, FrozenJSON]:
    if not isinstance(raw, Mapping) or set(raw) != {"kind", "target_unit", "accepted"}:
        raise CandidateRenderError("materialized inbound source-unit rule is invalid")
    kind = _string(raw["kind"], "inbound source-unit rule kind")
    target_unit = raw["target_unit"]
    accepted = raw["accepted"]
    if not isinstance(target_unit, str) or not isinstance(accepted, (list, tuple)):
        raise CandidateRenderError("materialized inbound source-unit rule shape is invalid")
    observed: list[tuple[str, float]] = []
    for entry in accepted:
        if not isinstance(entry, Mapping) or set(entry) != {"source_unit", "scale"}:
            raise CandidateRenderError("materialized inbound source-unit scale is invalid")
        source_unit, scale = entry["source_unit"], entry["scale"]
        if (
            not isinstance(source_unit, str)
            or type(scale) not in {int, float}
            or isinstance(scale, bool)
            or not math.isfinite(float(scale))
            or scale <= 0
        ):
            raise CandidateRenderError("materialized inbound source-unit scale value is invalid")
        observed.append((source_unit, float(scale)))
    if kind == "none":
        if strategy in {"generated-reverse-metric-v1", *tuple(_INBOUND_SOURCE_UNIT_TABLES)} or target_unit or observed:
            raise CandidateRenderError("materialized inbound source-unit rule is missing")
    elif kind == "target-unit-equality-v1":
        if (
            strategy != "generated-reverse-metric-v1"
            or family_unit is None
            or target_unit != family_unit
            or observed != [(family_unit, 1.0)]
        ):
            raise CandidateRenderError("materialized native metric unit equality drifted")
    elif kind == "scale-table-v1":
        expected = _INBOUND_SOURCE_UNIT_TABLES.get(strategy)
        expected_target = {"duration-metric-v1": "s", "claude-token-usage-v1": "{token}"}.get(strategy)
        if (
            expected is None
            or family_unit != expected_target
            or target_unit != expected_target
            or tuple(observed) != expected
        ):
            raise CandidateRenderError("materialized inbound source-unit scale table drifted")
    else:
        raise CandidateRenderError("materialized inbound source-unit rule kind is unknown")
    return _freeze(_plain(raw))


def _candidate_inbound_source_normalizers(raw: Any) -> tuple[Mapping[str, FrozenJSON], ...]:
    if not isinstance(raw, tuple):
        raise CandidateRenderError("materialized inbound source normalizer inventory is invalid")
    expected_keys = {
        "id", "kind", "trim", "case", "max_utf8_bytes", "empty", "overflow", "unmatched", "pattern",
        "values", "separators", "prefixes", "rules",
    }
    normalizers: list[Mapping[str, FrozenJSON]] = []
    for item in raw:
        plain = _plain(item)
        if not isinstance(plain, dict) or set(plain) != expected_keys:
            raise CandidateRenderError("materialized inbound source normalizer is invalid")
        if plain["trim"] not in {"none", "unicode-space"} or plain["case"] not in {"preserve", "lowercase"}:
            raise CandidateRenderError("materialized inbound source normalizer transform is invalid")
        if (
            plain["empty"] not in {"reject", "unknown"}
            or plain["overflow"] not in {"", "reject", "other"}
            or plain["unmatched"] not in {"", "reject", "other"}
        ):
            raise CandidateRenderError("materialized inbound source normalizer terminal policy is invalid")
        normalizers.append(_freeze(plain))
    if tuple(item["id"] for item in normalizers) != _INBOUND_SOURCE_NORMALIZER_IDS:
        raise CandidateRenderError("materialized inbound source normalizer inventory/order drifted")
    token_type_normalizer = normalizers[-1]
    token_rules = token_type_normalizer["rules"]
    if (
        token_type_normalizer["kind"] != "exact-map"
        or not isinstance(token_rules, tuple)
        or tuple(rule["output"] for rule in token_rules) != tuple(_INBOUND_TOKEN_TYPES)
        or tuple(tuple(rule["inputs"]) for rule in token_rules)
        != (("input",), ("output",), ("cacheRead", "cached_input"), ("cacheCreation",))
    ):
        raise CandidateRenderError("materialized inbound source token vocabulary drifted")
    return tuple(normalizers)


def _candidate_inbound_source_rule(rule: Mapping[str, Any], *, identity_key: str) -> str:
    identity = _string(rule[identity_key], "inbound source rule identity")
    if (
        rule["requirement"] not in {"required", "optional"}
        or rule["normalization"] not in _INBOUND_SOURCE_NORMALIZER_IDS
    ):
        raise CandidateRenderError("materialized inbound source rule policy is invalid")
    allowed = rule["allowed_values"]
    if rule["normalization"] == "token-type-label-v1":
        if allowed != _INBOUND_TOKEN_TYPES:
            raise CandidateRenderError("materialized inbound token vocabulary drifted")
    elif allowed != []:
        raise CandidateRenderError("materialized inbound non-enum rule acquired allowed values")
    groups = rule["source_groups"]
    if not isinstance(groups, list) or not groups:
        raise CandidateRenderError("materialized inbound source groups are invalid")
    seen: set[tuple[str, str]] = set()
    for group in groups:
        if not isinstance(group, dict) or set(group) != {"placement", "keys"}:
            raise CandidateRenderError("materialized inbound source group shape is invalid")
        placement = group["placement"]
        keys = group["keys"]
        if placement not in _INBOUND_SOURCE_PLACEMENTS or not isinstance(keys, list) or not keys:
            raise CandidateRenderError("materialized inbound source group placement is invalid")
        if len(keys) != len(set(keys)):
            raise CandidateRenderError("materialized inbound source group repeats a key")
        for key in keys:
            source = (placement, _string(key, "inbound source key"))
            if source in seen:
                raise CandidateRenderError("materialized inbound source rule contains a collision")
            seen.add(source)
    return identity


def _candidate_inbound_source_projection_plans(
    raw: Any,
    *,
    families: Mapping[str, EnrichedFamilyDescriptor],
    enriched_fields: Mapping[str, EnrichedFieldDescriptor],
) -> tuple[Mapping[str, FrozenJSON], ...]:
    if not isinstance(raw, tuple):
        raise CandidateRenderError("materialized inbound source projection inventory is invalid")
    plans: list[Mapping[str, FrozenJSON]] = []
    for raw_plan in raw:
        plan = _plain(raw_plan)
        if not isinstance(plan, dict) or set(plan) != {"id", "target_family", "field_rules", "cumulative_series"}:
            raise CandidateRenderError("materialized inbound source projection plan is invalid")
        family_id = _string(plan["target_family"], "inbound source projection target family")
        family = families.get(family_id)
        if family is None or family.signal != "metrics":
            raise CandidateRenderError("materialized inbound source projection target is not a metric family")
        field_rules = plan["field_rules"]
        if not isinstance(field_rules, list) or not field_rules:
            raise CandidateRenderError("materialized inbound source projection fields are invalid")
        targets: list[str] = []
        for rule in field_rules:
            if not isinstance(rule, dict):
                raise CandidateRenderError("materialized inbound source projection field is invalid")
            target = _string(rule.get("target"), "inbound source projection field target")
            targets.append(target)
            if rule.get("disposition") == "omit":
                if set(rule) != {"target", "disposition"}:
                    raise CandidateRenderError("materialized inbound omitted projection field is invalid")
            elif set(rule) == {
                "target", "disposition", "requirement", "normalization", "allowed_values", "source_groups"
            } and rule["disposition"] == "project":
                _candidate_inbound_source_rule(rule, identity_key="target")
            else:
                raise CandidateRenderError("materialized inbound projected field is invalid")
        expected_targets = [enriched_fields[field_id].attribute_id for field_id in family.field_descriptor_ids]
        if targets != expected_targets or len(targets) != len(set(targets)):
            raise CandidateRenderError("materialized inbound projection does not exhaust its target family")
        cumulative = plan["cumulative_series"]
        if cumulative is not None:
            if not isinstance(cumulative, dict) or set(cumulative) != {
                "applicability", "framing", "normalization_stage", "components", "reset_epoch"
            }:
                raise CandidateRenderError("materialized inbound cumulative identity is invalid")
            if (
                cumulative["applicability"] != "monotonic-cumulative-sum"
                or cumulative["framing"] != "length-prefixed-presence-v1"
                or cumulative["normalization_stage"] != "before_framing"
            ):
                raise CandidateRenderError("materialized inbound cumulative identity policy drifted")
            components = cumulative["components"]
            if not isinstance(components, list):
                raise CandidateRenderError("materialized inbound cumulative components are invalid")
            component_ids: list[str] = []
            for component in components:
                if not isinstance(component, dict) or set(component) != {
                    "id", "requirement", "normalization", "allowed_values", "source_groups"
                }:
                    raise CandidateRenderError("materialized inbound cumulative component is invalid")
                component_ids.append(_candidate_inbound_source_rule(component, identity_key="id"))
            if component_ids != _INBOUND_CUMULATIVE_COMPONENT_IDS:
                raise CandidateRenderError("materialized inbound cumulative component order drifted")
            if cumulative["reset_epoch"] != {
                "role": "reset_only",
                "identity": False,
                "placement": "metric_point_start_time",
                "key": "$start_time_unix_nano",
                "normalization": "unsigned-epoch-nanos-v1",
            }:
                raise CandidateRenderError("materialized inbound start time escaped reset-only metadata")
        plans.append(_freeze(plan))
    if tuple(plan["id"] for plan in plans) != _INBOUND_SOURCE_PROJECTION_PLAN_IDS:
        raise CandidateRenderError("materialized inbound source projection inventory/order drifted")
    if plans[0]["cumulative_series"] is None or plans[1]["cumulative_series"] is not None:
        raise CandidateRenderError("materialized inbound cumulative source projection coverage drifted")
    return tuple(plans)


def _candidate_inbound_otlp(
    raw: FrozenJSON,
    *,
    attributes: Mapping[str, CandidateAttribute],
    groups: Mapping[str, Mapping[str, FrozenJSON]],
    families: Mapping[str, EnrichedFamilyDescriptor],
    enriched_fields: Mapping[str, EnrichedFieldDescriptor],
) -> CandidateInboundOTLP:
    source = _tagged(raw, "InboundOTLPIR", _INBOUND_IR_FIELDS)
    if (
        _integer(source["version"], "inbound binding version", minimum=1) != 1
        or _integer(source["max_forward_hops"], "inbound max forward hops", minimum=1) != 4
        or source["unknown_fields"] != "drop_and_count"
        or source["semantic_resource_instance_key"] != "defenseclaw.instance.id"
        or source["forward_instance_key"] != "defenseclaw.telemetry.forward.instance_id"
        or source["forward_destination_key"] != "defenseclaw.telemetry.forward.destination"
        or source["forward_hop_count_key"] != "defenseclaw.telemetry.forward.hop_count"
        or source["record_id_key"] != "defenseclaw.record.id"
        or source["scope_name"] != "defenseclaw.telemetry"
        or source["scope_schema_url"] != "https://defenseclaw.io/schemas/telemetry/v8"
        or source["resource_schema_url"] != "https://opentelemetry.io/schemas/1.42.0"
    ):
        raise CandidateRenderError("materialized inbound OTLP constants drifted")
    expected_shape_policy = {
        "classes": ["native_exact", "native_malformed", "external"],
        "native_marker_rule": "any_declared_native_marker_selects_native_candidate",
        "structural_marker_rule": "exact_declared_structure_only",
        "native_malformed_disposition": "invalid_record",
        "native_malformed_external_fallback": "forbidden",
    }
    if _plain(source["shape_policy"]) != expected_shape_policy:
        raise CandidateRenderError("materialized inbound native-shape policy is invalid")

    raw_aliases = source["alias_sets"]
    if not isinstance(raw_aliases, tuple):
        raise CandidateRenderError("materialized inbound alias-set inventory is invalid")
    aliases: list[Mapping[str, FrozenJSON]] = []
    alias_ids: set[str] = set()
    for raw_alias in raw_aliases:
        if not isinstance(raw_alias, Mapping) or set(raw_alias) != {
            "id",
            "target",
            "value_type",
            "normalization",
            "sources",
            "conflict_policy",
            "absence_policy",
        }:
            raise CandidateRenderError("materialized inbound alias set is invalid")
        alias_id = _string(raw_alias["id"], "inbound alias ID")
        target = _string(raw_alias["target"], "inbound alias target")
        if alias_id in alias_ids:
            raise CandidateRenderError("materialized inbound alias ID is duplicated")
        alias_ids.add(alias_id)
        if target in {"$derived_duration_seconds", "$derived_cached_input_tokens"}:
            field_contract: JSONObject = {"field_class": "metadata", "sensitivity": "internal"}
        else:
            attribute = attributes.get(target)
            if attribute is None:
                raise CandidateRenderError("materialized inbound alias target is not registered")
            field_contract = {
                "field_class": attribute.metadata["field_class"],
                "sensitivity": attribute.metadata["sensitivity"],
            }
        alias = dict(_plain(raw_alias))
        alias["target_field_contract"] = field_contract
        aliases.append(_freeze(alias))

    source_normalizers = _candidate_inbound_source_normalizers(source["source_normalizers"])
    source_projection_plans = _candidate_inbound_source_projection_plans(
        source["source_projection_plans"],
        families=families,
        enriched_fields=enriched_fields,
    )
    source_projection_by_id = {item["id"]: item for item in source_projection_plans}

    raw_classes = source["binding_classes"]
    if not isinstance(raw_classes, tuple):
        raise CandidateRenderError("materialized inbound class inventory is invalid")
    classes = tuple(_freeze(_plain(item)) for item in raw_classes)
    if tuple(item["id"] for item in classes) != _INBOUND_CLASS_IDS:
        raise CandidateRenderError("materialized inbound class inventory or order drifted")
    native_class_ids = set(_INBOUND_CLASS_IDS[:3])

    raw_matches = source["match_descriptors"]
    if not isinstance(raw_matches, tuple):
        raise CandidateRenderError("materialized inbound match inventory is invalid")
    matches: list[Mapping[str, FrozenJSON]] = []
    matches_by_id: dict[str, Mapping[str, FrozenJSON]] = {}
    for raw_match in raw_matches:
        if not isinstance(raw_match, Mapping) or set(raw_match) != {
            "id",
            "class_id",
            "signal",
            "sources",
            "shape",
            "discriminator",
            "mapping",
            "derived_targets",
            "time_rule",
            "outcome_rule",
            "unknown_fields",
            "native_round_trip",
            "target_ids",
        }:
            raise CandidateRenderError("materialized inbound match descriptor is invalid")
        match = _freeze(_plain(raw_match))
        match_id = _string(match["id"], "inbound match ID")
        class_id = _string(match["class_id"], "inbound match class ID")
        expected_shape = "native_exact" if class_id in native_class_ids else "external"
        if (
            class_id not in _INBOUND_CLASS_IDS
            or match["shape"] != expected_shape
            or match["unknown_fields"] != "drop_and_count"
            or type(match["native_round_trip"]) is not bool
            or match["native_round_trip"] != (expected_shape == "native_exact")
            or match_id in matches_by_id
        ):
            raise CandidateRenderError("materialized inbound match shape or identity is invalid")
        matches_by_id[match_id] = match
        matches.append(match)
    if any(match["shape"] == "native_malformed" for match in matches):
        raise CandidateRenderError("native-malformed shape acquired a constructible inbound match")

    raw_targets = source["target_descriptors"]
    if not isinstance(raw_targets, tuple):
        raise CandidateRenderError("materialized inbound target inventory is invalid")
    targets: list[Mapping[str, FrozenJSON]] = []
    targets_by_match: dict[str, list[str]] = {match_id: [] for match_id in matches_by_id}
    target_ids: set[str] = set()
    primary_counts: Counter[str] = Counter()
    for raw_target in raw_targets:
        if not isinstance(raw_target, Mapping) or set(raw_target) != {
            "id",
            "match_id",
            "class_id",
            "signal",
            "role",
            "target_kind",
            "family",
            "bucket",
            "event_name",
            "family_schema_version",
            "instrument_name",
            "instrument_type",
            "instrument_unit",
            "field_refs",
            "mapping_strategy",
            "derivation_strategy",
            "time_rule",
            "outcome_rule",
            "import_context_id",
            "source_unit_rule",
            "source_projection_plan",
        }:
            raise CandidateRenderError("materialized inbound target descriptor is invalid")
        target = dict(_plain(raw_target))
        target_id = _string(target["id"], "inbound target ID")
        match_id = _string(target["match_id"], "inbound target match ID")
        family_id = _string(target["family"], "inbound target family ID")
        family = families.get(family_id)
        family_group = groups.get(family_id)
        if match_id not in matches_by_id or family is None or family_group is None or target_id in target_ids:
            raise CandidateRenderError("materialized inbound target identity is unknown or duplicated")
        family_unit = family_group["metric_unit"] if family.signal == "metrics" else None
        if (
            target_id != f"{match_id}.{family_id}"
            or target["signal"] != family.signal
            or target["bucket"] != family.bucket
            or target["family_schema_version"] != family.family_schema_version
            or target["target_kind"] not in {"primary", "derived"}
            or target["role"] not in {"import", "derive"}
            or (target["target_kind"] == "derived" and target["role"] != "derive")
            or target["instrument_unit"] != family_unit
        ):
            raise CandidateRenderError("materialized inbound target disagrees with its generated family")
        target["source_unit_rule"] = _candidate_inbound_source_unit_rule(
            target["source_unit_rule"],
            strategy=_string(target["mapping_strategy"], "inbound target mapping strategy"),
            family_unit=family_unit,
        )
        if target["target_kind"] == "primary":
            primary_counts[match_id] += 1
        raw_field_refs = target["field_refs"]
        if not isinstance(raw_field_refs, list) or len(raw_field_refs) != len(set(raw_field_refs)):
            raise CandidateRenderError("materialized inbound target field references are invalid")
        for reference in raw_field_refs:
            attribute = attributes.get(reference)
            if attribute is None:
                raise CandidateRenderError("materialized inbound target field is not registered")
        target["field_descriptor_ids"] = list(family.field_descriptor_ids)
        if len(target["field_refs"]) != len(target["field_descriptor_ids"]) or any(
            enriched_fields[descriptor_id].attribute_id != reference
            for reference, descriptor_id in zip(target["field_refs"], target["field_descriptor_ids"], strict=True)
        ):
            raise CandidateRenderError("inbound target field references and descriptors disagree")
        target_ids.add(target_id)
        targets_by_match[match_id].append(target_id)
        targets.append(_freeze(target))
    if set(primary_counts) != set(matches_by_id) or any(count != 1 for count in primary_counts.values()):
        raise CandidateRenderError("each inbound match must own exactly one primary target")
    for match_id, match in matches_by_id.items():
        if tuple(match["target_ids"]) != tuple(sorted(targets_by_match[match_id], key=str.encode)):
            raise CandidateRenderError("materialized inbound match target references disagree")
        mapping = match["mapping"]
        if not isinstance(mapping, Mapping) or set(mapping) != {
            "strategy",
            "alias_sets",
            "source_projection_plan",
            "target_override",
            "source_unit_rule",
        }:
            raise CandidateRenderError("materialized inbound match mapping is invalid")
        primary = next(
            target for target in targets if target["match_id"] == match_id and target["target_kind"] == "primary"
        )
        match_rule = _candidate_inbound_source_unit_rule(
            mapping["source_unit_rule"],
            strategy=_string(mapping["strategy"], "inbound match mapping strategy"),
            family_unit=primary["instrument_unit"],
        )
        if _plain(match_rule) != _plain(primary["source_unit_rule"]):
            raise CandidateRenderError("materialized inbound match/target source-unit rules disagree")
        projection = mapping["source_projection_plan"]
        target_projection = primary["source_projection_plan"]
        if projection is None:
            if target_projection is not None:
                raise CandidateRenderError("materialized inbound match/target projection plans disagree")
        else:
            projection_id = _string(projection.get("id"), "inbound match projection plan ID")
            expected_projection = source_projection_by_id.get(projection_id)
            if (
                expected_projection is None
                or _plain(projection) != _plain(expected_projection)
                or _plain(target_projection) != _plain(expected_projection)
                or primary["family"] != expected_projection["target_family"]
            ):
                raise CandidateRenderError("materialized inbound match/target projection plans disagree")

    raw_markers = source["native_markers"]
    if not isinstance(raw_markers, tuple):
        raise CandidateRenderError("materialized native marker inventory is invalid")
    native_markers = tuple(_freeze(_plain(item)) for item in raw_markers)
    expected_markers: dict[tuple[str, str, str], JSONObject] = {}
    for match in matches:
        if match["shape"] != "native_exact":
            continue
        for predicate in match["discriminator"]["predicates"]:
            location = predicate["location"]
            key = predicate["key"]
            if key.startswith("defenseclaw."):
                marker_kind = "reserved_key_presence"
                values: list[Any] = []
            elif location in {"scope_name", "scope_schema_url"}:
                marker_kind = "exact_structural_value"
                values = _plain(predicate["values"])
            elif location == "log_body" and predicate["operator"] == "projected_record_json":
                marker_kind = "projected_record_structure"
                values = []
            else:
                continue
            expected_markers[(match["signal"], location, key)] = {
                "id": f"otlp.native.marker.{match['signal']}.{location}.{key}",
                "signal": match["signal"],
                "location": location,
                "key": key,
                "marker_kind": marker_kind,
                "values": values,
                "value_type": predicate["value_type"],
            }
    if [_plain(item) for item in native_markers] != sorted(
        expected_markers.values(), key=lambda item: item["id"].encode("ascii")
    ):
        raise CandidateRenderError("materialized native marker inventory disagrees with native matches")

    raw_recognizers = source["echo_recognizers"]
    raw_contexts = source["import_contexts"]
    if not isinstance(raw_recognizers, tuple) or not isinstance(raw_contexts, tuple):
        raise CandidateRenderError("materialized inbound recognizer/context inventory is invalid")
    recognizers = tuple(_freeze(_plain(item)) for item in raw_recognizers)
    contexts = tuple(_freeze(_plain(item)) for item in raw_contexts)
    if {item["family"] for item in recognizers} != set(families):
        raise CandidateRenderError("materialized inbound self-echo coverage is incomplete")
    log_families = {family.id for family in families.values() if family.signal == "logs"}
    if {item["family_descriptor_id"] for item in contexts} != log_families:
        raise CandidateRenderError("materialized inbound import-context coverage is incomplete")
    if any("mandatory" in item or "floor" in item for item in contexts):
        raise CandidateRenderError("materialized inbound import context exposes floor authority")

    attachments = source["derivation_attachments"]
    fixture_policy = source["fixture_policy"]
    if not isinstance(attachments, tuple) or len(attachments) != 1 or not isinstance(fixture_policy, Mapping):
        raise CandidateRenderError("materialized inbound attachment/fixture contract is invalid")
    return CandidateInboundOTLP(
        version=1,
        max_forward_hops=4,
        unknown_fields="drop_and_count",
        semantic_resource_instance_key="defenseclaw.instance.id",
        forward_instance_key="defenseclaw.telemetry.forward.instance_id",
        forward_destination_key="defenseclaw.telemetry.forward.destination",
        forward_hop_count_key="defenseclaw.telemetry.forward.hop_count",
        record_id_key="defenseclaw.record.id",
        scope_name="defenseclaw.telemetry",
        scope_schema_url="https://defenseclaw.io/schemas/telemetry/v8",
        resource_schema_url="https://opentelemetry.io/schemas/1.42.0",
        shape_policy=_freeze(_plain(source["shape_policy"])),
        alias_sets=tuple(aliases),
        source_normalizers=source_normalizers,
        source_projection_plans=source_projection_plans,
        binding_classes=classes,
        match_descriptors=tuple(sorted(matches, key=lambda item: item["id"].encode("ascii"))),
        target_descriptors=tuple(sorted(targets, key=lambda item: item["id"].encode("ascii"))),
        native_markers=native_markers,
        echo_recognizers=tuple(sorted(recognizers, key=lambda item: item["id"].encode("ascii"))),
        import_contexts=tuple(sorted(contexts, key=lambda item: item["id"].encode("ascii"))),
        derivation_attachments=tuple(_freeze(_plain(item)) for item in attachments),
        fixture_policy=_freeze(_plain(fixture_policy)),
    )


def build_candidate_render_index(view: object) -> CandidateRenderIndex:
    if type(view).__name__ != "MaterializedRegistryView":
        raise CandidateRenderError("renderer requires MaterializedRegistryView")
    format_value = getattr(view, "format", None)
    digest = getattr(view, "typed_canonical_json_sha256", None)
    facts = getattr(view, "facts", None)
    if format_value != MATERIALIZED_VIEW_FORMAT or not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
        raise CandidateRenderError("materialized view identity is invalid")
    if not isinstance(facts, Mapping):
        raise CandidateRenderError("materialized view facts are invalid")
    observed_digest = hashlib.sha256(
        MATERIALIZED_VIEW_DIGEST_DOMAIN + _canonical_json_bytes(_typed_materialized_node(facts))
    ).hexdigest()
    if observed_digest != digest:
        raise CandidateRenderError("materialized view digest does not match facts")
    fields = _tagged(facts, "RegistryIR", _TOP_LEVEL_FIELDS)
    go_symbol_policy, go_symbol_overrides, go_symbol_table = _candidate_go_symbol_contract(fields)
    schema_version = _integer(fields["schema_version"], "schema version", minimum=1)
    registry_version = _integer(fields["registry_version"], "registry version", minimum=1)
    bucket_version = _integer(fields["bucket_catalog_version"], "bucket catalog version", minimum=1)
    _validate_normalizer_catalog(fields["normalizers"])
    _validate_mandatory_rule_catalog(fields["mandatory_rule_catalog"])
    condition_ids: set[str] = set()
    for raw_condition in fields["conditions"]:
        condition = _tagged(raw_condition, "ConditionIR", _CONDITION_FIELDS)
        condition_id = _string(condition["id"], "condition id")
        if condition_id in condition_ids:
            raise CandidateRenderError("materialized condition is duplicated")
        condition_ids.add(condition_id)

    ownership: dict[str, str] = {}
    for node in fields["upstream_attribute_ownership"]:
        item = _tagged(node, "UpstreamAttributeOwnershipIR", _UPSTREAM_OWNERSHIP_FIELDS)
        ref = _string(item.get("ref"), "upstream attribute ref")
        owner = _string(item.get("owner"), "upstream attribute owner")
        if ref in ownership:
            raise CandidateRenderError("materialized upstream attribute ownership is duplicated")
        ownership[ref] = owner

    snapshots: dict[str, dict[str, Mapping[str, FrozenJSON]]] = {}
    structural_input_paths: set[str] = set()
    for node in fields["dependencies"]:
        dependency = _tagged(node, "DependencyIR", _DEPENDENCY_FIELDS)
        dependency_id = _string(dependency.get("id"), "dependency id")
        snapshot = _tagged(dependency.get("snapshot"), "SnapshotIR", _SNAPSHOT_FIELDS)
        raw_structural_inputs = dependency.get("structural_inputs")
        if not isinstance(raw_structural_inputs, tuple):
            raise CandidateRenderError("materialized structural input inventory is invalid")
        for raw_input in raw_structural_inputs:
            structural_input = _tagged(raw_input, "StructuralInputIR", _STRUCTURAL_INPUT_FIELDS)
            upstream_path = _string(structural_input["upstream_path"], "structural upstream path")
            source_path = _string(structural_input["path"], "structural source path")
            digest_value = _string(structural_input["sha256"], "structural source digest")
            if (
                upstream_path in structural_input_paths
                or not source_path.startswith("schemas/telemetry/v8/upstream/")
                or _SHA256.fullmatch(digest_value) is None
            ):
                raise CandidateRenderError("materialized structural input is invalid")
            structural_input_paths.add(upstream_path)
        for raw_attribute in snapshot.get("attributes", ()):
            attribute = _tagged(raw_attribute, "SnapshotAttribute", _SNAPSHOT_ATTRIBUTE_FIELDS)
            ref = _string(attribute.get("id"), "snapshot attribute id")
            by_dependency = snapshots.setdefault(ref, {})
            if dependency_id in by_dependency:
                raise CandidateRenderError("materialized snapshot attribute is duplicated")
            by_dependency[dependency_id] = attribute

    structured_types: dict[str, Mapping[str, FrozenJSON]] = {}
    raw_structured_types = fields["structured_types"]
    if not isinstance(raw_structured_types, tuple) or not raw_structured_types:
        raise CandidateRenderError("materialized structured type inventory is incomplete")
    structured_types_digest = hashlib.sha256(
        _canonical_json_bytes(_plain(_semantic_digest_projection(raw_structured_types)))
    ).hexdigest()
    if structured_types_digest != _STRUCTURED_TYPES_SHA256:
        raise CandidateRenderError(
            "materialized structured type contract is not canonical "
            f"(expected {_STRUCTURED_TYPES_SHA256}, observed {structured_types_digest})"
        )
    for raw_type in raw_structured_types:
        structured = _validate_structured_materialized_type(raw_type)
        type_id = _string(structured["id"], "structured type id")
        if type_id in structured_types:
            raise CandidateRenderError("materialized structured type is duplicated")
        structured_types[type_id] = structured
    if tuple(structured_types) != _STRUCTURED_TYPE_IDS:
        raise CandidateRenderError("materialized structured type inventory/order is invalid")
    _validate_exact_structured_contracts(structured_types)

    references: dict[str, list[str]] = {type_id: [] for type_id in structured_types}
    reserved: dict[str, set[str]] = {type_id: set() for type_id in structured_types}
    for type_id, structured in structured_types.items():
        for raw_field in structured["fields"] or ():
            field = _tagged(raw_field, "StructuredFieldIR", _STRUCTURED_FIELD_FIELDS)
            reserved[type_id].add(_string(field["name"], "structured field name"))
            if field["reference"] is not None:
                references[type_id].append(
                    _string(
                        _tagged(
                            field["reference"],
                            "StructuredReferenceIR",
                            _STRUCTURED_REFERENCE_FIELDS,
                        )["structured_ref"],
                        "structured field reference",
                    )
                )
        if structured["dynamic_members"] is not None:
            members = _tagged(
                structured["dynamic_members"],
                "StructuredDynamicMembersIR",
                _STRUCTURED_DYNAMIC_MEMBERS_FIELDS,
            )
            references[type_id].append(
                _string(
                    _tagged(
                        members["value"],
                        "StructuredReferenceIR",
                        _STRUCTURED_REFERENCE_FIELDS,
                    )["structured_ref"],
                    "structured dynamic reference",
                )
            )
        if structured["items_reference"] is not None:
            references[type_id].append(
                _string(
                    _tagged(
                        structured["items_reference"],
                        "StructuredReferenceIR",
                        _STRUCTURED_REFERENCE_FIELDS,
                    )["structured_ref"],
                    "structured item reference",
                )
            )
        if structured["discriminator"] is not None:
            discriminator = _tagged(
                structured["discriminator"],
                "StructuredDiscriminatorIR",
                _STRUCTURED_DISCRIMINATOR_FIELDS,
            )
            reserved[type_id].add(_string(discriminator["name"], "structured discriminator name"))
        for raw_variant in structured["variants"] or ():
            variant = _tagged(raw_variant, "StructuredVariantIR", _STRUCTURED_VARIANT_FIELDS)
            target = _string(variant["structured_ref"], "structured variant reference")
            references[type_id].append(target)
            if target not in reserved:
                raise CandidateRenderError("materialized structured variant reference is unresolved")
            discriminator = _tagged(
                structured["discriminator"],
                "StructuredDiscriminatorIR",
                _STRUCTURED_DISCRIMINATOR_FIELDS,
            )
            reserved[target].add(_string(discriminator["name"], "structured discriminator name"))
        if structured["dynamic_variant"] is not None:
            variant = _tagged(
                structured["dynamic_variant"],
                "StructuredDynamicVariantIR",
                _STRUCTURED_DYNAMIC_VARIANT_FIELDS,
            )
            target = _string(variant["structured_ref"], "structured dynamic variant reference")
            references[type_id].append(target)
            if target not in reserved:
                raise CandidateRenderError("materialized structured dynamic variant reference is unresolved")
            discriminator = _tagged(
                structured["discriminator"],
                "StructuredDiscriminatorIR",
                _STRUCTURED_DISCRIMINATOR_FIELDS,
            )
            reserved[target].add(_string(discriminator["name"], "structured discriminator name"))
        if structured["canonical_json"] is not None:
            canonical = _tagged(
                structured["canonical_json"],
                "CanonicalJSONContractIR",
                _CANONICAL_JSON_CONTRACT_FIELDS,
            )
            references[type_id].extend(
                (
                    _string(canonical["array_items_ref"], "canonical array reference"),
                    _string(
                        _tagged(
                            canonical["object_value"],
                            "StructuredReferenceIR",
                            _STRUCTURED_REFERENCE_FIELDS,
                        )["structured_ref"],
                        "canonical object reference",
                    ),
                )
            )
    known_types = set(structured_types)
    for type_id, targets in references.items():
        if any(target not in known_types for target in targets):
            raise CandidateRenderError("materialized structured reference is unresolved")
        if type_id in targets and type_id != "gen_ai.canonical_json":
            raise CandidateRenderError("materialized structured self-reference is invalid")
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit_structured(type_id: str) -> None:
        if type_id in visited:
            return
        if type_id in visiting:
            raise CandidateRenderError("materialized structured reference graph is cyclic")
        visiting.add(type_id)
        for target in references[type_id]:
            if type_id == target == "gen_ai.canonical_json":
                continue
            visit_structured(target)
        visiting.remove(type_id)
        visited.add(type_id)

    for type_id in structured_types:
        visit_structured(type_id)
    for type_id, structured in structured_types.items():
        observed_reserved = structured["effective_reserved_names"]
        if observed_reserved != tuple(sorted(reserved[type_id])):
            raise CandidateRenderError("materialized structured reserved-name set is inconsistent")
        if structured["dynamic_members"] is not None:
            members = _tagged(
                structured["dynamic_members"],
                "StructuredDynamicMembersIR",
                _STRUCTURED_DYNAMIC_MEMBERS_FIELDS,
            )
            if members["reserved_names"] != observed_reserved:
                raise CandidateRenderError("materialized dynamic reserved-name set is inconsistent")
    structured_bindings: dict[str, Mapping[str, FrozenJSON]] = {}
    raw_bindings = fields["structured_bindings"]
    if not isinstance(raw_bindings, tuple) or not raw_bindings:
        raise CandidateRenderError("materialized structured binding inventory is incomplete")
    for raw_binding in raw_bindings:
        binding = _tagged(raw_binding, "StructuredBindingIR", _STRUCTURED_BINDING_FIELDS)
        attribute = _string(binding["attribute"], "structured binding attribute")
        structured_type = _string(binding["structured_type"], "structured binding type")
        if attribute in structured_bindings or structured_type not in structured_types:
            raise CandidateRenderError("materialized structured binding is invalid")
        structured_bindings[attribute] = binding
    observed_bindings = tuple(
        (
            binding["attribute"],
            binding["structured_type"],
            binding["public_encoding"],
            binding["canonical_wire_encoding"],
        )
        for binding in structured_bindings.values()
    )
    if observed_bindings != _STRUCTURED_EXPECTED_BINDINGS:
        raise CandidateRenderError("materialized structured binding contract is not canonical")
    dispositions: list[Mapping[str, FrozenJSON]] = []
    raw_dispositions = fields["structured_property_dispositions"]
    if not isinstance(raw_dispositions, tuple) or not raw_dispositions:
        raise CandidateRenderError("materialized structured property dispositions are incomplete")
    disposition_keys: set[tuple[str, str]] = set()
    for raw_disposition in raw_dispositions:
        disposition = _tagged(
            raw_disposition,
            "StructuredPropertyDispositionIR",
            _STRUCTURED_DISPOSITION_FIELDS,
        )
        key = (
            _string(disposition["input_path"], "structured disposition input path"),
            _string(disposition["json_pointer"], "structured disposition pointer"),
        )
        disposition_kind = _string(disposition["disposition"], "structured disposition kind")
        owner_type = _string(disposition["structured_type"], "structured disposition owner")
        arm_id = disposition["arm_id"]
        target_type = disposition["target_structured_type"]
        union_owned = owner_type == "gen_ai.message_part" and disposition["member_name"] == "type"
        if (
            key in disposition_keys
            or owner_type not in structured_types
            or disposition_kind
            not in {"fixed_field", "dynamic_members", "dynamic_variant", "nullable_optional_omission", "rejected"}
            or (union_owned and (not isinstance(arm_id, str) or target_type not in structured_types))
            or (not union_owned and (arm_id is not None or target_type is not None))
        ):
            raise CandidateRenderError("materialized structured property disposition is invalid")
        disposition_keys.add(key)
        dispositions.append(disposition)
    disposition_digest = hashlib.sha256(_canonical_json_bytes(_plain(tuple(dispositions)))).hexdigest()
    if disposition_digest != _STRUCTURED_DISPOSITIONS_SHA256:
        raise CandidateRenderError("materialized structured property disposition contract is not canonical")

    attributes: dict[str, CandidateAttribute] = {}
    groups: dict[str, Mapping[str, FrozenJSON]] = {}
    family_nodes: list[Mapping[str, FrozenJSON]] = []
    family_domains: dict[str, str] = {}
    domain_records: list[CandidateDomain] = []
    span_events: dict[str, Mapping[str, FrozenJSON]] = {}
    domains = fields["domains"]
    if not isinstance(domains, tuple) or not domains:
        raise CandidateRenderError("materialized domains are incomplete")
    for raw_domain in domains:
        domain = _tagged(raw_domain, "DomainIR", _DOMAIN_FIELDS)
        domain_id = _string(domain["domain"], "domain id")
        domain_path = _string(domain["path"], "domain path")
        domain_family_ids: list[str] = []
        for raw_attribute in domain.get("attributes", ()):
            item = _tagged(raw_attribute, "AttributeIR", _ATTRIBUTE_FIELDS)
            ref = _string(item["id"], "attribute id")
            if ref in attributes:
                raise CandidateRenderError("materialized attribute is duplicated")
            if item["field_type"] not in _LOCAL_FIELD_TYPES:
                raise CandidateRenderError("materialized local attribute type is invalid")
            normalization = _normalization(
                item,
                field_types=(item["field_type"],),
                polymorphic=item["field_type"] == "canonical_json",
            )
            metadata = {
                "id": ref,
                "type": item["field_type"],
                "brief": item["brief"],
                "examples": _plain(item["examples"]),
                "alias_of": item["alias_of"],
                "owner": item["owner"],
                "stability": item["stability"],
                "projection_only": item["projection_only"],
                "field_class": item["field_class"],
                "sensitivity": item["sensitivity"],
                "cardinality": item["cardinality"],
                "normalization": normalization,
                "introduced_in": item["introduced_in"],
                "deprecated_in": item["deprecated_in"],
                "removed_in": item["removed_in"],
            }
            attributes[ref] = CandidateAttribute(
                ref,
                (_string(item["field_type"], "attribute type"),),
                None,
                metadata,
            )
        for raw_extension in domain.get("attribute_extensions", ()):
            extension = _tagged(raw_extension, "AttributeExtensionIR", _ATTRIBUTE_EXTENSION_FIELDS)
            ref = _string(extension["ref"], "attribute extension ref")
            if ref in attributes or ref not in snapshots or ref not in ownership:
                raise CandidateRenderError("materialized attribute extension is unresolved")
            dependency_for_owner = {
                "otel": "otel_core",
                "otel_genai": "otel_genai",
                "openinference_compatibility": "openinference",
            }
            dependency_id = dependency_for_owner.get(ownership[ref])
            snapshot = snapshots[ref].get(dependency_id or "")
            if snapshot is None:
                raise CandidateRenderError("materialized attribute extension has no owned snapshot")
            allowed_types = snapshot.get("allowed_types")
            if not isinstance(allowed_types, tuple) or any(not isinstance(v, str) for v in allowed_types):
                raise CandidateRenderError("materialized upstream attribute type is invalid")
            shape = snapshot.get("shape")
            if allowed_types:
                effective_types = allowed_types
            elif shape == "any_value":
                effective_types = ("canonical_json",)
            elif shape in {"indexed_prefix", "object_prefix"}:
                effective_types = ("object",)
            else:
                raise CandidateRenderError("materialized upstream attribute shape is invalid")
            normalization = _normalization(
                extension,
                field_types=effective_types,
                structured=shape in {"any_value", "indexed_prefix", "object_prefix"},
                polymorphic=shape == "any_value" or "canonical_json" in effective_types,
            )
            metadata = {
                "id": ref,
                "type": list(effective_types) if len(effective_types) > 1 else effective_types[0],
                "upstream_shape": shape,
                "brief": "Pinned upstream semantic-convention attribute.",
                "examples": [],
                "alias_of": None,
                "owner": ownership[ref],
                "stability": snapshot["stability"],
                "projection_only": ownership[ref] == "openinference_compatibility",
                "field_class": extension["field_class"],
                "sensitivity": extension["sensitivity"],
                "cardinality": extension["cardinality"],
                "normalization": normalization,
                "introduced_in": None,
                "deprecated_in": None,
                "removed_in": None,
                "upstream_source": snapshot["source_pointer"],
            }
            attributes[ref] = CandidateAttribute(ref, tuple(effective_types), None, metadata)
        for raw_group in domain.get("groups", ()):
            group = _tagged(raw_group, "GroupIR", _GROUP_FIELDS)
            group_id = _string(group["id"], "group id")
            if group_id in groups:
                raise CandidateRenderError("materialized group is duplicated")
            direct_refs: list[str] = []
            for raw_use in group["attribute_uses"]:
                direct_use = _tagged(raw_use, "AttributeUseIR", _ATTRIBUTE_USE_FIELDS)
                direct_ref = _string(direct_use["ref"], "direct attribute ref")
                direct_refs.append(direct_ref)
                requirement = direct_use["requirement_level"]
                conditional = direct_use["conditional"]
                conditional_is_valid = (
                    requirement in {"conditional", "optional"}
                    and isinstance(conditional, str)
                    and bool(conditional)
                    and conditional in condition_ids
                ) or (requirement != "conditional" and conditional is None)
                if (
                    not isinstance(direct_use["ref"], str)
                    or direct_use["role"] not in {"attributes", "body_fields"}
                    or requirement not in _REQUIREMENT_RANK
                    or not conditional_is_valid
                ):
                    raise CandidateRenderError("materialized direct attribute use is invalid")
                _validated_constraint_map(direct_use["constraints"], "direct-use constraints")
            if group["attribute_refs"] != tuple(direct_refs):
                raise CandidateRenderError("materialized direct attribute refs disagree")
            dynamic = group["resource_dynamic_members"]
            aliases = group["resource_compatibility_aliases"]
            if group_id == "resource.core":
                if dynamic is None and aliases is None:
                    groups[group_id] = group
                    continue
                dynamic = _tagged(dynamic, "ResourceDynamicMembersIR", _RESOURCE_DYNAMIC_MEMBERS_FIELDS)
                expected_dynamic = {
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
                if dict(dynamic) != expected_dynamic or not isinstance(aliases, tuple):
                    raise CandidateRenderError("materialized resource dynamic-member contract is invalid")
                alias_rows = tuple(
                    _tagged(item, "ResourceCompatibilityAliasIR", _RESOURCE_COMPATIBILITY_ALIAS_FIELDS)
                    for item in aliases
                )
                if tuple((row["alias"], row["canonical"]) for row in alias_rows) != (
                    ("deployment.environment", "deployment.environment.name"),
                    ("deployment.mode", "defenseclaw.deployment.mode"),
                    ("defenseclaw.device.id", "defenseclaw.device.public_key_fingerprint"),
                ):
                    raise CandidateRenderError("materialized resource compatibility aliases are invalid")
            elif dynamic is not None or aliases is not None:
                raise CandidateRenderError("resource dynamic-member ownership escaped resource.core")
            groups[group_id] = group
            group_type = group["type"]
            if group_type in {"log", "span", "metric"}:
                family_nodes.append(group)
                domain_family_ids.append(group_id)
                family_domains[group_id] = domain_id
            elif group_type == "span_event":
                event_name_value = group["event_name"]
                event_name = (
                    _string(event_name_value, "span event name")
                    if event_name_value is not None
                    else group_id.removeprefix("event.")
                )
                if not event_name or event_name == group_id:
                    raise CandidateRenderError("materialized span event identity is invalid")
                if event_name in span_events:
                    raise CandidateRenderError("materialized span event is duplicated")
                span_events[event_name] = group
        producer_identity_sets = tuple(
            _freeze(_plain_ir(_tagged(item, "ProducerIdentitySetIR"))) for item in domain["producer_identity_sets"]
        )
        producer_mappings = tuple(
            _freeze(_plain_ir(_tagged(item, "ProducerMappingIR"))) for item in domain["producer_mappings"]
        )
        domain_records.append(
            CandidateDomain(
                domain_id,
                domain_path,
                tuple(sorted(domain_family_ids)),
                producer_identity_sets,
                producer_mappings,
            )
        )

    for ref, binding in structured_bindings.items():
        attribute = attributes.get(ref)
        if attribute is None or attribute.field_types != ("canonical_json",):
            raise CandidateRenderError("materialized structured binding attribute is incompatible")
        metadata = dict(attribute.metadata)
        metadata["structured_type"] = binding["structured_type"]
        metadata["public_encoding"] = binding["public_encoding"]
        metadata["canonical_wire_encoding"] = binding["canonical_wire_encoding"]
        attributes[ref] = CandidateAttribute(
            attribute.id,
            attribute.field_types,
            _string(binding["structured_type"], "structured binding type"),
            metadata,
        )

    if set(fields["resolved_group_uses"]) != set(groups):
        raise CandidateRenderError("materialized resolved group uses are incomplete")
    recomputed_resolved_uses, recomputed_resolution_order = _recompute_resolved_group_uses(groups)
    if fields["group_resolution_order"] != recomputed_resolution_order:
        raise CandidateRenderError("materialized group resolution order disagrees")
    for group_id, group in groups.items():
        for raw_direct_use in group["attribute_uses"]:
            direct_use = _tagged(raw_direct_use, "AttributeUseIR", _ATTRIBUTE_USE_FIELDS)
            direct_attribute = attributes.get(direct_use["ref"])
            if direct_attribute is None:
                raise CandidateRenderError("materialized direct attribute use is unknown")
            direct_constraints = _validated_constraint_map(
                direct_use["constraints"],
                "direct-use constraints",
            )
            _validate_constraint_shape(
                direct_constraints,
                direct_attribute.field_types,
                "direct-use constraints",
                structured=direct_attribute.structured_type is not None
                or direct_attribute.metadata.get("upstream_shape") in {"any_value", "indexed_prefix", "object_prefix"},
                polymorphic="canonical_json" in direct_attribute.field_types
                and direct_attribute.structured_type is None,
            )
            _validate_constraint_restriction(
                direct_constraints,
                direct_attribute.metadata["normalization"]["effective_constraints"],
                "direct-use constraints",
            )
        resolved = fields["resolved_group_uses"][group_id]
        projected_resolved = tuple(_resolved_use_projection(use) for use in resolved)
        projected_group_resolved = tuple(_resolved_use_projection(use) for use in group["resolved_uses"])
        if _typed_materialized_node(projected_resolved) != _typed_materialized_node(
            projected_group_resolved
        ) or _typed_materialized_node(projected_resolved) != _typed_materialized_node(
            recomputed_resolved_uses[group_id]
        ):
            raise CandidateRenderError("materialized resolved group uses disagree")
        for raw_use in resolved:
            use = _resolved_use(raw_use)
            if use["ref"] not in attributes:
                raise CandidateRenderError("materialized resolved attribute use is unknown")
            expected_role = "body_fields" if group["type"] in {"body_group", "log"} else "attributes"
            if use["role"] != expected_role or use["requirement_level"] not in _REQUIREMENT_RANK:
                raise CandidateRenderError("materialized resolved attribute use is invalid")
            resolved_condition_is_valid = (
                use["requirement_level"] in {"conditional", "optional"}
                and isinstance(use["conditional"], str)
                and bool(use["conditional"])
                and use["conditional"] in condition_ids
            ) or (use["requirement_level"] != "conditional" and use["conditional"] is None)
            if not resolved_condition_is_valid:
                raise CandidateRenderError("materialized resolved attribute condition is invalid")
            resolved_constraints = _validated_constraint_map(
                use["constraints"],
                "resolved-use constraints",
            )
            resolved_attribute = attributes[use["ref"]]
            resolved_is_structured = resolved_attribute.structured_type is not None or resolved_attribute.metadata.get(
                "upstream_shape"
            ) in {"any_value", "indexed_prefix", "object_prefix"}
            _validate_constraint_shape(
                resolved_constraints,
                resolved_attribute.field_types,
                "resolved-use constraints",
                structured=resolved_is_structured,
                polymorphic="canonical_json" in resolved_attribute.field_types
                and resolved_attribute.structured_type is None,
            )
            _validate_constraint_restriction(
                resolved_constraints,
                resolved_attribute.metadata["normalization"]["effective_constraints"],
                "resolved-use constraints",
            )
            raw_origins = use["origins"]
            if not isinstance(raw_origins, tuple) or not raw_origins:
                raise CandidateRenderError("materialized resolved attribute origins are invalid")
            origins: list[Mapping[str, FrozenJSON]] = []
            for raw_origin in raw_origins:
                origin = _tagged(
                    raw_origin,
                    "AttributeUseOriginIR",
                    _ATTRIBUTE_USE_ORIGIN_FIELDS,
                )
                origin_condition_is_valid = (
                    origin["requirement_level"] in {"conditional", "optional"}
                    and isinstance(origin["conditional"], str)
                    and bool(origin["conditional"])
                    and origin["conditional"] in condition_ids
                ) or (origin["requirement_level"] != "conditional" and origin["conditional"] is None)
                if (
                    origin["group_id"] not in groups
                    or origin["role"] not in {"attributes", "body_fields"}
                    or origin["requirement_level"] not in _REQUIREMENT_RANK
                    or not origin_condition_is_valid
                ):
                    raise CandidateRenderError("materialized resolved attribute origin is invalid")
                origin_constraints = _validated_constraint_map(
                    origin["constraints"],
                    "resolved-use origin constraints",
                )
                _validate_constraint_shape(
                    origin_constraints,
                    resolved_attribute.field_types,
                    "resolved-use origin constraints",
                    structured=resolved_is_structured,
                    polymorphic="canonical_json" in resolved_attribute.field_types
                    and resolved_attribute.structured_type is None,
                )
                _validate_constraint_restriction(
                    origin_constraints,
                    resolved_attribute.metadata["normalization"]["effective_constraints"],
                    "resolved-use origin constraints",
                )
                origins.append(origin)
            dominant_requirement = max(
                origins,
                key=lambda item: _REQUIREMENT_RANK[item["requirement_level"]],
            )["requirement_level"]
            dominant_origins = tuple(item for item in origins if item["requirement_level"] == dominant_requirement)
            dominant_clauses = tuple(dict.fromkeys(item["conditional"] for item in dominant_origins))
            if len(dominant_clauses) != 1:
                raise CandidateRenderError("materialized resolved attribute conditions disagree")
            dominant_conditional = dominant_clauses[0]
            if dominant_requirement == "conditional" and dominant_conditional is None:
                raise CandidateRenderError("materialized resolved conditional attribute has no condition")
            if use["requirement_level"] != dominant_requirement or use["conditional"] != dominant_conditional:
                raise CandidateRenderError("materialized resolved attribute requirement disagrees with origins")
            derived_constraints = _derive_resolved_constraints(tuple(origins))
            if _typed_materialized_node(derived_constraints) != _typed_materialized_node(resolved_constraints):
                raise CandidateRenderError("materialized resolved attribute constraints disagree with origins")

    active_identities: set[tuple[str, str]] = set()
    for family in family_nodes:
        group_type = family["type"]
        if family["removed_in"] is not None:
            continue
        identity = (
            {"log": "logs", "span": "traces", "metric": "metrics"}[group_type],
            _family_event_name(family),
        )
        if identity in active_identities:
            raise CandidateRenderError("materialized active family identity is duplicated")
        active_identities.add(identity)
        profiles = family["compatibility_profiles"] or ()
        if any(profile not in _COMPATIBILITY_PROFILES for profile in profiles):
            raise CandidateRenderError("materialized compatibility profile is unknown")

    examples: list[Mapping[str, FrozenJSON]] = []
    example_ids: set[str] = set()
    for raw_example in fields["examples"]:
        example = _tagged(raw_example, "ExampleIR", _EXAMPLE_FIELDS)
        example_id = _string(example["id"], "example id")
        if example_id in example_ids:
            raise CandidateRenderError("materialized example is duplicated")
        example_ids.add(example_id)
        if type(example["valid"]) is not bool or example["signal"] not in {"logs", "traces", "metrics"}:
            raise CandidateRenderError("materialized example metadata is invalid")
        family_id = example["family"]
        if family_id is not None and family_id not in groups:
            raise CandidateRenderError("materialized example family is unknown")
        if not isinstance(example["record"], Mapping) or example["record"].get("signal") != example["signal"]:
            raise CandidateRenderError("materialized example record is inconsistent")
        _validate_builder_context(example)
        examples.append(example)
    for example in examples:
        if example["valid"]:
            if (
                example["expected_error"] is not None
                or example["base_example"] is not None
                or example["mutation"] is not None
            ):
                raise CandidateRenderError("materialized valid example carries invalid metadata")
        else:
            if not isinstance(example["expected_error"], str) or example["base_example"] not in example_ids:
                raise CandidateRenderError("materialized invalid example is incomplete")
            _tagged(example["mutation"], "ExampleMutationIR")
    example_output_paths = _materialize_example_output_paths(examples)

    raw_structural_contract = fields["structural_contract"]
    structural_contract_digest = hashlib.sha256(
        _canonical_json_bytes(_plain(_semantic_digest_projection(raw_structural_contract)))
    ).hexdigest()
    if structural_contract_digest != _STRUCTURAL_CONTRACT_SHA256:
        raise CandidateRenderError(
            f"materialized structural contract is not canonical: observed {structural_contract_digest}"
        )
    contract = _tagged(raw_structural_contract, "StructuralContractIR")
    required_contract = {
        "id",
        "version",
        "additional_properties",
        "runtime_binding",
        "limits",
        "envelope",
        "correlation",
        "provenance",
        "provenance_import",
        "provenance_import_rules",
        "signal_arms",
        "trace_derivations",
        "trace_body",
        "trace_relations",
        "trace_resource",
        "trace_scope",
        "trace_status",
        "trace_event",
        "trace_link",
        "metric_instrument_data",
        "canonical_to_otlp",
    }
    if set(contract) != required_contract:
        raise CandidateRenderError("materialized structural contract is incomplete")
    if tuple(_tagged(arm, "SignalArmIR", _SIGNAL_ARM_FIELDS)["signal"] for arm in contract["signal_arms"]) != (
        "logs",
        "traces",
        "metrics",
    ):
        raise CandidateRenderError("materialized signal arms are incomplete")

    _validate_go_symbol_sources(
        go_symbol_table,
        fields=fields,
        attributes=attributes,
        families=family_nodes,
        family_domains=family_domains,
        span_events=span_events,
        structured_types=structured_types,
    )

    condition_contracts = _condition_contracts(fields)
    mandatory_rule_contracts = _mandatory_rule_contracts(fields)
    mandatory_programs = _resolved_mandatory_programs(family_nodes, mandatory_rule_contracts)
    trace_value_sources, trace_derivations = _trace_derivation_contract(contract)
    enriched_fields = _enriched_field_descriptors(
        attributes=attributes,
        groups=groups,
        families=family_nodes,
        span_events=span_events,
        structured_types=structured_types,
        conditions=condition_contracts,
        value_sources=trace_value_sources,
    )
    for (context, target), source in trace_value_sources.items():
        if not any(
            descriptor.context == context and descriptor.attribute_id == target and descriptor.value_source == source
            for descriptor in enriched_fields.values()
        ):
            raise CandidateRenderError("materialized trace derivation is unused by enriched fields")
    enriched_containers = _enriched_container_descriptors(contract, structured_types, enriched_fields)
    enriched_families, enriched_traces, enriched_metrics = _enriched_family_descriptors(
        families=family_nodes,
        family_domains=family_domains,
        fields=enriched_fields,
        span_events=span_events,
        groups=groups,
        derivations=trace_derivations,
        mandatory_programs=mandatory_programs,
    )
    sorted_domains = tuple(sorted(domain_records, key=lambda item: item.id))
    _validate_v7_exporter_selection_materialized(fields, sorted_domains, groups)
    expanded_producer_mappings = _expanded_producer_mappings(
        sorted_domains,
        enriched_families,
        mandatory_programs,
        mandatory_rule_contracts,
    )
    inbound_otlp = _candidate_inbound_otlp(
        fields["inbound_bindings"],
        attributes=attributes,
        groups=groups,
        families=enriched_families,
        enriched_fields=enriched_fields,
    )
    go_declaration_values = _go_declaration_values(go_symbol_table, fields)
    # Inbound rows are carried once in the typed ``inbound_otlp`` index below.
    # Retaining the materialized tagged copy here would duplicate several
    # hundred expanded descriptors in every render and Go-plan process.
    frozen_fields = _freeze({key: value for key, value in fields.items() if key != "inbound_bindings"})
    frozen_structured_types = MappingProxyType(
        {key: _freeze(_plain_ir(structured_types[key])) for key in structured_types}
    )
    frozen_examples = tuple(_freeze(item) for item in examples)
    provisional = _ProvisionalCandidateEnrichment(
        materialized_view_sha256=digest,
        fields=frozen_fields,
        go_symbol_policy=go_symbol_policy,
        go_symbol_table=go_symbol_table,
        structured_types=frozen_structured_types,
        groups=MappingProxyType({key: _freeze(_plain_ir(groups[key])) for key in sorted(groups)}),
        examples=frozen_examples,
        enriched_fields=enriched_fields,
        enriched_containers=enriched_containers,
        enriched_families=enriched_families,
        enriched_traces=enriched_traces,
        enriched_metrics=enriched_metrics,
        mandatory_programs=mandatory_programs,
        expanded_producer_mappings=expanded_producer_mappings,
        inbound_otlp=inbound_otlp,
        go_declaration_values=go_declaration_values,
    )
    try:
        go_api_plan = compile_go_api_plan(provisional)
    except GoAPIPlanError as exc:
        raise CandidateRenderError(f"candidate Go API plan is invalid: {exc}") from None
    candidate_digest = _candidate_render_index_digest(
        digest,
        enriched_fields=enriched_fields,
        enriched_containers=enriched_containers,
        enriched_families=enriched_families,
        enriched_traces=enriched_traces,
        enriched_metrics=enriched_metrics,
        mandatory_programs=mandatory_programs,
        expanded_producer_mappings=expanded_producer_mappings,
        inbound_otlp=inbound_otlp,
        go_declaration_values=go_declaration_values,
        go_api_plan=go_api_plan,
        api_plan_sha256=go_api_plan.api_plan_sha256,
    )

    frozen_attributes = MappingProxyType(
        {
            key: CandidateAttribute(
                attributes[key].id,
                attributes[key].field_types,
                attributes[key].structured_type,
                _freeze(attributes[key].metadata),
            )
            for key in sorted(attributes)
        }
    )
    frozen_groups = MappingProxyType({key: _freeze(_plain_ir(groups[key])) for key in sorted(groups)})
    frozen_events = MappingProxyType({key: _freeze(_plain_ir(span_events[key])) for key in sorted(span_events)})
    return CandidateRenderIndex(
        schema_version=schema_version,
        registry_version=registry_version,
        bucket_catalog_version=bucket_version,
        digest=digest,
        materialized_view_sha256=digest,
        candidate_render_index_sha256=candidate_digest,
        fields=frozen_fields,
        go_symbol_policy=go_symbol_policy,
        go_symbol_overrides=go_symbol_overrides,
        go_symbol_table=go_symbol_table,
        attributes=frozen_attributes,
        structured_types=frozen_structured_types,
        structured_bindings=MappingProxyType(
            {key: _freeze(_plain_ir(structured_bindings[key])) for key in structured_bindings}
        ),
        structured_property_dispositions=tuple(_freeze(_plain_ir(item)) for item in dispositions),
        groups=frozen_groups,
        families=tuple(_freeze(_plain_ir(item)) for item in sorted(family_nodes, key=lambda item: item["id"])),
        family_domains=MappingProxyType({key: family_domains[key] for key in sorted(family_domains)}),
        domains=sorted_domains,
        span_events=frozen_events,
        examples=frozen_examples,
        example_output_paths=example_output_paths,
        enriched_fields=enriched_fields,
        enriched_containers=enriched_containers,
        enriched_families=enriched_families,
        enriched_traces=enriched_traces,
        enriched_metrics=enriched_metrics,
        mandatory_programs=mandatory_programs,
        expanded_producer_mappings=expanded_producer_mappings,
        inbound_otlp=inbound_otlp,
        go_declaration_values=go_declaration_values,
        go_api_plan=go_api_plan,
        api_plan_sha256=go_api_plan.api_plan_sha256,
    )


def _family_event_name(family: Mapping[str, FrozenJSON]) -> str:
    if family["type"] == "log":
        return _string(family["event_name"], "log event name")
    if family["type"] == "span":
        return _string(family["id"], "span family id")
    if family["type"] == "metric":
        return _string(family["instrument_name"], "metric instrument name")
    raise CandidateRenderError("materialized family type is invalid")


def _attribute_schema(
    attribute: CandidateAttribute, use_constraints: Mapping[str, FrozenJSON] | None = None
) -> JSONObject:
    if attribute.structured_type is not None:
        schema: JSONObject = {"$ref": f"#/$defs/structured:{attribute.structured_type}"}
    else:
        variants = [_schema_type(field_type) for field_type in attribute.field_types]
        schema = variants[0] if len(variants) == 1 else {"oneOf": variants}
    constraints = attribute.metadata["normalization"]["effective_constraints"]
    schema = _apply_constraints(
        schema,
        constraints,
        normalization_id=attribute.metadata["normalization"]["id"],
    )
    if use_constraints:
        schema = _apply_constraints(schema, use_constraints)
    schema["x-defenseclaw-field-class"] = attribute.metadata["field_class"]
    schema["x-defenseclaw-sensitivity"] = attribute.metadata["sensitivity"]
    schema["x-defenseclaw-owner"] = attribute.metadata["owner"]
    schema["x-defenseclaw-normalization"] = attribute.metadata["normalization"]
    return schema


def _phase_pair_rule(model: CandidateRenderIndex, properties: Mapping[str, Any]) -> JSONObject | None:
    if "defenseclaw.agent.phase" not in properties or "defenseclaw.agent.phase.code" not in properties:
        return None
    catalogs = model.fields["value_catalogs"]
    phase_catalog = None
    for raw in catalogs:
        item = _tagged(raw, "ValueCatalogIR", _VALUE_CATALOG_FIELDS)
        if item.get("id") == "agent-phase-v1":
            phase_catalog = item
            break
    if phase_catalog is None:
        raise CandidateRenderError("materialized agent phase catalog is missing")
    choices = []
    for raw_entry in phase_catalog["entries"]:
        entry = _tagged(raw_entry, "ValueCatalogEntryIR")
        choices.append(
            {
                "properties": {
                    "defenseclaw.agent.phase": {"const": entry["value"]},
                    "defenseclaw.agent.phase.code": {"const": entry["code"]},
                },
                "required": ["defenseclaw.agent.phase", "defenseclaw.agent.phase.code"],
            }
        )
    return {
        "if": {"required": ["defenseclaw.agent.phase", "defenseclaw.agent.phase.code"]},
        "then": {"oneOf": choices},
        "x-defenseclaw-value-catalog": "agent-phase-v1",
    }


def _uses_schema(
    model: CandidateRenderIndex,
    uses: Sequence[FrozenJSON],
    *,
    consts: Mapping[str, Any] | None = None,
) -> JSONObject:
    properties: JSONObject = {}
    required: list[str] = []
    for raw in uses:
        use = _resolved_use(raw)
        ref = _string(use["ref"], "resolved attribute ref")
        if ref in properties:
            raise CandidateRenderError("materialized resolved use is duplicated")
        constraints = use["constraints"]
        if not isinstance(constraints, Mapping):
            raise CandidateRenderError("materialized resolved constraints are invalid")
        schema = _attribute_schema(model.attributes[ref], constraints)
        if consts and ref in consts:
            schema["const"] = consts[ref]
        schema["x-defenseclaw-requirement-level"] = use["requirement_level"]
        if use["conditional"] is not None:
            schema["x-defenseclaw-condition"] = use["conditional"]
        properties[ref] = schema
        if use["requirement_level"] == "required":
            required.append(ref)
    result: JSONObject = {
        "type": "object",
        "additionalProperties": False,
        "properties": properties,
        "required": sorted(required),
    }
    phase_rule = _phase_pair_rule(model, properties)
    if phase_rule is not None:
        result["allOf"] = [phase_rule]
    return result


def _resource_uses_schema(model: CandidateRenderIndex, group: Mapping[str, FrozenJSON]) -> JSONObject:
    result = _uses_schema(model, group["resolved_uses"])
    dynamic = group["resource_dynamic_members"]
    raw_aliases = group["resource_compatibility_aliases"]
    if dynamic is None and raw_aliases is None:
        return result
    if not isinstance(dynamic, Mapping) or set(dynamic) != _RESOURCE_DYNAMIC_MEMBERS_FIELDS:
        raise CandidateRenderError("candidate resource dynamic-member contract is malformed")
    if not isinstance(raw_aliases, tuple) or any(
        not isinstance(item, Mapping) or set(item) != _RESOURCE_COMPATIBILITY_ALIAS_FIELDS for item in raw_aliases
    ):
        raise CandidateRenderError("candidate resource alias contract is malformed")
    aliases = tuple(raw_aliases)
    properties = result["properties"]
    for alias in aliases:
        canonical = _string(alias["canonical"], "resource alias canonical")
        alias_name = _string(alias["alias"], "resource alias name")
        schema = _attribute_schema(model.attributes[canonical])
        schema["x-defenseclaw-compatibility-alias-of"] = canonical
        schema["x-defenseclaw-requirement-level"] = "optional"
        properties[alias_name] = schema

    exact_excluded = tuple(properties) + tuple(dynamic["reserved_keys"])
    normalized_excluded = tuple(item.replace(".", "_").replace("-", "_") for item in exact_excluded)
    excluded = exact_excluded + normalized_excluded
    if len(excluded) != len(set(excluded)):
        raise CandidateRenderError("resource dynamic schema exclusion inventory contains duplicates")
    negative = "|".join(re.escape(item) for item in sorted(set(excluded), key=str.encode))
    segments = "|".join(re.escape(item) for item in dynamic["forbidden_key_segments"])
    authored = _string(dynamic["key_pattern"], "resource custom key pattern")
    if not authored.startswith("^") or not authored.endswith("$"):
        raise CandidateRenderError("resource custom key pattern must be anchored")
    custom_pattern = (
        f"^(?!(?:{negative})$)"
        f"(?!(?:.*[._-])?(?:{segments})(?:[._-].*)?$)"
        f"(?!(?:.*[._-])?api[._-]key(?:[._-].*)?$)"
        f"{authored[1:]}"
    )
    custom_value: JSONObject = {
        "type": "string",
        "minLength": dynamic["min_value_utf8_bytes"],
        "maxLength": dynamic["max_value_utf8_bytes"],
        "x-defenseclaw-max-utf8-bytes": dynamic["max_value_utf8_bytes"],
        "x-defenseclaw-field-class": dynamic["field_class"],
        "x-defenseclaw-sensitivity": dynamic["sensitivity"],
        "x-defenseclaw-cardinality": dynamic["cardinality"],
        "x-defenseclaw-stability-scope": dynamic["stability_scope"],
        "x-defenseclaw-value-utf8-policy": dynamic["value_utf8_policy"],
        "x-defenseclaw-value-blank-policy": dynamic["value_blank_policy"],
        "x-defenseclaw-value-control-character-policy": dynamic["value_control_character_policy"],
        "pattern": r"^(?=.*\S)[^\u0000-\u001f\u007f-\u009f]+$",
    }
    result.update(
        {
            "additionalProperties": False,
            "patternProperties": {custom_pattern: custom_value},
            "propertyNames": {"pattern": authored},
            "maxProperties": len(properties) + dynamic["max_items"],
            "x-defenseclaw-dynamic-member-contract": {
                "owner": "resource.core",
                "max_items": dynamic["max_items"],
                "max_aggregate_utf8_bytes": dynamic["max_aggregate_utf8_bytes"],
                "ordering": dynamic["ordering"],
                "duplicate_key_policy": dynamic["duplicate_key_policy"],
                "fixed_key_collision_policy": dynamic["fixed_key_collision_policy"],
                "prometheus_key_normalization": dynamic["prometheus_key_normalization"],
                "prometheus_normalized_collision_policy": dynamic["prometheus_normalized_collision_policy"],
                "reserved_keys": list(dynamic["reserved_keys"]),
                "forbidden_key_segments": list(dynamic["forbidden_key_segments"]),
                "forbidden_value_classes": list(dynamic["forbidden_value_classes"]),
            },
        }
    )
    return result


def _object_schema(
    model: CandidateRenderIndex, raw_object: FrozenJSON, definition_names: Mapping[str, str]
) -> JSONObject:
    obj = _tagged(raw_object, "StructuralObjectIR", _STRUCTURAL_OBJECT_FIELDS)
    object_id = _string(obj.get("id"), "structural object id")
    additional_properties = obj.get("additional_properties")
    if type(additional_properties) is not bool:
        raise CandidateRenderError("materialized structural additional-properties flag is invalid")
    properties: JSONObject = {}
    required: list[str] = []
    for raw_field in obj.get("fields", ()):
        field = _tagged(raw_field, "StructuralFieldIR", _STRUCTURAL_FIELD_FIELDS)
        name = _string(field.get("name"), "structural field name")
        field_type = _string(field.get("field_type"), "structural field type")
        schema = _schema_type(field_type)
        object_ref = field.get("object_ref")
        item_ref = field.get("item_ref")
        if object_ref is not None:
            if object_ref not in definition_names:
                raise CandidateRenderError("materialized structural object reference is unknown")
            schema = {"$ref": f"#/$defs/{definition_names[object_ref]}"}
        elif item_ref is not None:
            if item_ref not in definition_names:
                raise CandidateRenderError("materialized structural item reference is unknown")
            schema = {"type": "array", "items": {"$ref": f"#/$defs/{definition_names[item_ref]}"}}
        if field.get("const_present") is True:
            schema["const"] = _plain(field.get("const"))
        enum = field.get("enum")
        if isinstance(enum, tuple) and enum:
            schema["enum"] = _plain(enum)
        normalization = field.get("normalization")
        if normalization is not None:
            norm = _normalization(
                {"normalization": normalization},
                field_types=(field_type,),
                structured=object_ref is not None or item_ref is not None,
                polymorphic=field_type == "canonical_json",
            )
            effective = norm["effective_constraints"]
            schema = _apply_constraints(
                schema,
                effective,
                normalization_id=norm["id"],
            )
        for key in ("semantic_ref", "semantic_format", "field_class", "sensitivity", "otlp_target", "otlp_encoding"):
            if field.get(key) is not None:
                schema[f"x-defenseclaw-{key.replace('_', '-')}"] = _plain(field[key])
        properties[name] = schema
        if field.get("required") is True:
            required.append(name)
        elif field.get("required") is not False:
            raise CandidateRenderError("materialized structural required flag is invalid")
    return {
        "type": "object",
        "additionalProperties": additional_properties,
        "properties": properties,
        "required": required,
        "x-defenseclaw-structural-object": object_id,
    }


def _apply_provenance_import_schema_rules(
    schema: JSONObject,
    raw_rules: FrozenJSON,
) -> None:
    rules = _tagged(raw_rules, "ProvenanceImportRulesIR", _PROVENANCE_IMPORT_RULE_FIELDS)
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        raise CandidateRenderError("provenance import schema has no property map")

    def string_tuple(key: str) -> tuple[str, ...]:
        values = rules.get(key)
        if not isinstance(values, tuple) or any(not isinstance(item, str) for item in values):
            raise CandidateRenderError(f"materialized provenance import {key} is invalid")
        return values

    for name in string_tuple("nonempty_string_fields"):
        target = properties.get(name)
        if not isinstance(target, dict) or target.get("type") != "string":
            raise CandidateRenderError("provenance import nonempty rule references a non-string field")
        target["minLength"] = 1
    for target in properties.values():
        if not isinstance(target, dict) or target.get("type") != "string":
            continue
        byte_limit = target.get("x-defenseclaw-max-utf8-bytes")
        if type(byte_limit) is int:
            # JSON Schema can publish only a coarse code-point cap here. Its
            # accepted set is a superset of the stricter UTF-8 byte-bounded set;
            # exact multibyte enforcement remains with the runtime validator.
            target["maxLength"] = byte_limit

    required_modes = string_tuple("derivation_required_modes")
    forbidden_modes = string_tuple("derivation_forbidden_modes")
    required_derivations = string_tuple("source_aggregate_count_required_derivations")
    forbidden_derivations = string_tuple("source_aggregate_count_forbidden_derivations")
    forbidden_count_modes = string_tuple("source_aggregate_count_forbidden_modes")
    schema["allOf"] = [
        {
            "if": {"properties": {"mode": {"enum": list(required_modes)}}, "required": ["mode"]},
            "then": {"required": ["derivation"]},
        },
        {
            "if": {"properties": {"mode": {"enum": list(forbidden_modes)}}, "required": ["mode"]},
            "then": {"not": {"required": ["derivation"]}},
        },
        {
            "if": {"properties": {"derivation": {"enum": list(required_derivations)}}, "required": ["derivation"]},
            "then": {"required": ["source_aggregate_count"]},
        },
        {
            "if": {"properties": {"derivation": {"enum": list(forbidden_derivations)}}, "required": ["derivation"]},
            "then": {"not": {"required": ["source_aggregate_count"]}},
        },
        {
            "if": {"properties": {"mode": {"enum": list(forbidden_count_modes)}}, "required": ["mode"]},
            "then": {"not": {"required": ["source_aggregate_count"]}},
        },
    ]
    owner = rules.get("exact_validation_owner")
    runtime_only = string_tuple("json_schema_runtime_only")
    if not isinstance(owner, str) or not owner or not runtime_only:
        raise CandidateRenderError("provenance import exact validation ownership is incomplete")
    schema["x-defenseclaw-provenance-import-rules"] = _plain_ir(rules)
    schema["x-defenseclaw-exact-validation-owner"] = owner
    schema["x-defenseclaw-json-schema-runtime-only"] = list(runtime_only)


def _event_definition(model: CandidateRenderIndex, event: Mapping[str, FrozenJSON], trace_event_def: str) -> JSONObject:
    event_name_value = event["event_name"]
    event_name = (
        _string(event_name_value, "span event name")
        if event_name_value is not None
        else _string(event["id"], "span event id").removeprefix("event.")
    )
    attributes = _uses_schema(model, event["resolved_uses"])
    return {
        "allOf": [
            {"$ref": f"#/$defs/{trace_event_def}"},
            {
                "type": "object",
                "properties": {"name": {"const": event_name}, "attributes": attributes},
                "required": ["name", "attributes"],
            },
        ],
        "x-defenseclaw-family-id": event["id"],
    }


def _family_definition(
    model: CandidateRenderIndex,
    family: Mapping[str, FrozenJSON],
    *,
    envelope_def: str,
    trace_defs: Mapping[str, str],
    event_defs: Mapping[str, str],
) -> JSONObject:
    family_id = _string(family["id"], "family id")
    family_type = family["type"]
    signal = {"log": "logs", "span": "traces", "metric": "metrics"}.get(family_type)
    if signal is None:
        raise CandidateRenderError("materialized family type is invalid")
    bucket = _string(family["bucket"], "family bucket")
    event_name = _family_event_name(family)
    overlay_properties: JSONObject = {
        "signal": {"const": signal},
        "bucket": {"const": bucket},
        "event_name": {"const": event_name},
    }
    required = ["signal", "bucket", "event_name"]
    uses = family["resolved_uses"]
    if not isinstance(uses, tuple):
        raise CandidateRenderError("materialized family resolved uses are invalid")

    if family_type == "log":
        body_uses = tuple(raw for raw in uses if _resolved_use(raw)["role"] == "body_fields")
        overlay_properties["body"] = _uses_schema(model, body_uses)
        required.append("body")
    elif family_type == "span":
        consts = {
            "defenseclaw.bucket": bucket,
            "defenseclaw.span.family": family_id,
            "defenseclaw.span.family_schema_version": family["family_schema_version"],
        }
        attributes = _uses_schema(model, uses, consts=consts)
        body_properties: JSONObject = {"attributes": attributes}
        kinds = family["span_kinds"]
        if not isinstance(kinds, tuple) or not kinds:
            raise CandidateRenderError("materialized span kinds are incomplete")
        body_properties["kind"] = {"enum": list(kinds)}
        resource_group = model.groups.get("resource.core")
        scope_group = model.groups.get("scope.core")
        link_group = model.groups.get("link.core")
        if resource_group is None or scope_group is None or link_group is None:
            raise CandidateRenderError("materialized trace support groups are incomplete")
        body_properties["resource"] = {
            "allOf": [
                {"$ref": f"#/$defs/{trace_defs['trace_resource']}"},
                {"properties": {"attributes": _resource_uses_schema(model, resource_group)}},
            ]
        }
        body_properties["scope"] = {
            "allOf": [
                {"$ref": f"#/$defs/{trace_defs['trace_scope']}"},
                {"properties": {"attributes": _uses_schema(model, scope_group["resolved_uses"])}},
            ]
        }
        allowed_events = family["event_refs"] or ()
        if any(event not in event_defs for event in allowed_events):
            raise CandidateRenderError("materialized span event reference is unknown")
        if allowed_events:
            body_properties["events"] = {
                "type": "array",
                "items": {"oneOf": [{"$ref": f"#/$defs/{event_defs[event]}"} for event in allowed_events]},
            }
        body_overlay: JSONObject = {"type": "object", "properties": body_properties}
        if not allowed_events:
            body_overlay["not"] = {"required": ["events"]}
        link_attributes = _uses_schema(model, link_group["resolved_uses"])
        relations = family["link_relations"] or ()
        if "defenseclaw.link.relation" in link_attributes["properties"] and relations:
            link_attributes["properties"]["defenseclaw.link.relation"]["enum"] = list(relations)
        body_properties["links"] = {
            "type": "array",
            "items": {
                "allOf": [
                    {"$ref": f"#/$defs/{trace_defs['trace_link']}"},
                    {"properties": {"attributes": link_attributes}},
                ]
            },
        }
        overlay_properties["body"] = {
            "allOf": [
                {"$ref": f"#/$defs/{trace_defs['trace_body']}"},
                body_overlay,
            ]
        }
        required.extend(["body", "span_name"])
    else:
        labels = _uses_schema(model, uses)
        value_type = _string(family["metric_value_type"], "metric value type")
        overlay_properties["instrument_data"] = {
            "allOf": [
                {"$ref": f"#/$defs/{trace_defs['metric_instrument_data']}"},
                {"properties": {"value": _schema_type(value_type), "attributes": labels}},
            ]
        }
        required.append("instrument_data")

    outcome_requirement = family["outcome_requirement"]
    allowed_outcomes = family["allowed_outcomes"]
    overlay: JSONObject = {
        "type": "object",
        "properties": overlay_properties,
        "required": sorted(set(required)),
    }
    if family_type != "metric":
        if outcome_requirement not in {"required", "optional", "forbidden"} or not isinstance(allowed_outcomes, tuple):
            raise CandidateRenderError("materialized family outcome contract is incomplete")
        if outcome_requirement == "forbidden":
            overlay.setdefault("allOf", []).append({"not": {"required": ["outcome"]}})
        else:
            overlay_properties["outcome"] = {"enum": list(allowed_outcomes)}
            if outcome_requirement == "required":
                overlay["required"].append("outcome")

    return {
        "allOf": [{"$ref": f"#/$defs/{envelope_def}"}, overlay],
        "title": family_id,
        "description": family["brief"],
        "x-defenseclaw-family": {
            "id": family_id,
            "signal": signal,
            "bucket": bucket,
            "event_name": event_name,
            "family_schema_version": family["family_schema_version"],
            "span_name_pattern": family["span_name_pattern"],
            "status_rule": family["span_status_rule"],
            "conditions": sorted(
                {_resolved_use(raw)["conditional"] for raw in uses if _resolved_use(raw)["conditional"] is not None}
            ),
        },
    }


def _render_schema(model: CandidateRenderIndex, marker: JSONObject) -> JSONObject:
    contract = _tagged(model.fields["structural_contract"], "StructuralContractIR")
    structural_keys = (
        "envelope",
        "correlation",
        "provenance",
        "provenance_import",
        "trace_body",
        "trace_resource",
        "trace_scope",
        "trace_status",
        "trace_event",
        "trace_link",
        "metric_instrument_data",
    )
    structural_nodes = {
        key: _tagged(contract[key], "StructuralObjectIR", _STRUCTURAL_OBJECT_FIELDS) for key in structural_keys
    }
    definition_names = {node["id"]: f"structural:{key}" for key, node in structural_nodes.items()}
    defs: JSONObject = {CANONICAL_JSON_DEFINITION: _canonical_json_schema()}
    for type_id, structured in model.structured_types.items():
        defs[f"structured:{type_id}"] = _structured_type_schema(structured)
    for key, raw in structural_nodes.items():
        defs[f"structural:{key}"] = _object_schema(model, contract[key], definition_names)
    _apply_provenance_import_schema_rules(
        defs["structural:provenance_import"],
        contract["provenance_import_rules"],
    )

    envelope_def = "structural:envelope"
    envelope = defs[envelope_def]
    signal_rules: list[JSONObject] = []
    for raw_arm in contract["signal_arms"]:
        arm = _tagged(raw_arm, "SignalArmIR", _SIGNAL_ARM_FIELDS)
        then: JSONObject = {"required": list(arm["required_fields"]) + [arm["payload_field"]]}
        forbidden = list(arm["forbidden_fields"])
        if forbidden:
            then["allOf"] = [{"not": {"required": [field]}} for field in forbidden]
        correlation_required = list(arm["required_correlation_fields"])
        if correlation_required:
            then.setdefault("properties", {})["correlation"] = {"required": correlation_required}
        signal_rules.append({"if": {"properties": {"signal": {"const": arm["signal"]}}}, "then": then})
    envelope["allOf"] = signal_rules

    for ref, attribute in sorted(model.attributes.items()):
        defs[f"attribute:{ref}"] = _attribute_schema(attribute)

    event_defs: dict[str, str] = {}
    for event_name, event in sorted(model.span_events.items()):
        name = f"event:{event_name}"
        defs[name] = _event_definition(model, event, "structural:trace_event")
        event_defs[event_name] = name

    active_refs: list[JSONObject] = []
    for family in model.families:
        if family["removed_in"] is not None:
            continue
        family_id = _string(family["id"], "family id")
        name = f"family:{family_id}"
        defs[name] = _family_definition(
            model,
            family,
            envelope_def=envelope_def,
            trace_defs={key: f"structural:{key}" for key in structural_keys},
            event_defs=event_defs,
        )
        active_refs.append({"$ref": f"#/$defs/{name}"})
    if not active_refs:
        raise CandidateRenderError("materialized view has no active families")

    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://defenseclaw.dev/schemas/telemetry/v8/telemetry.schema.json",
        "title": "DefenseClaw Portable Telemetry Candidate Bundle",
        "description": "Candidate-only schema generated from one immutable MaterializedRegistryView.",
        "x-defenseclaw-generated": marker,
        "x-defenseclaw-versions": {
            "schema_version": model.schema_version,
            "registry_version": model.registry_version,
            "bucket_catalog_version": model.bucket_catalog_version,
            "materialized_view_sha256": model.digest,
        },
        "x-defenseclaw-conformance": _candidate_conformance_scope(),
        "x-defenseclaw-conditions": [
            _plain_ir(_tagged(item, "ConditionIR", _CONDITION_FIELDS)) for item in model.fields["conditions"]
        ],
        "x-defenseclaw-mandatory-rule-catalog": _plain_ir(
            _tagged(
                model.fields["mandatory_rule_catalog"],
                "MandatoryRuleCatalogIR",
                _MANDATORY_RULE_CATALOG_FIELDS,
            )
        ),
        "x-defenseclaw-value-catalogs": [
            _plain_ir(_tagged(item, "ValueCatalogIR", _VALUE_CATALOG_FIELDS)) for item in model.fields["value_catalogs"]
        ],
        "x-defenseclaw-trace-derivations": [
            _plain_ir(_tagged(item, "TraceDerivationIR")) for item in contract["trace_derivations"]
        ],
        "x-defenseclaw-trace-relations": [
            _plain_ir(_tagged(item, "StructuralRelationIR")) for item in contract["trace_relations"]
        ],
        "x-defenseclaw-provenance-import-rules": _plain_ir(
            _tagged(
                contract["provenance_import_rules"],
                "ProvenanceImportRulesIR",
                _PROVENANCE_IMPORT_RULE_FIELDS,
            )
        ),
        "x-defenseclaw-canonical-to-otlp": _plain_ir(
            _tagged(contract["canonical_to_otlp"], "CanonicalOTLPRepresentationIR", _CANONICAL_OTLP_FIELDS)
        ),
        "x-defenseclaw-structured-types": [_plain(model.structured_types[key]) for key in model.structured_types],
        "x-defenseclaw-structured-bindings": [
            _plain(model.structured_bindings[key]) for key in model.structured_bindings
        ],
        "x-defenseclaw-structured-property-dispositions": _plain(model.structured_property_dispositions),
        "oneOf": active_refs,
        "$defs": {key: defs[key] for key in sorted(defs)},
    }


def _compatibility_profile_projection(
    model: CandidateRenderIndex,
    profile: str,
    family: Mapping[str, FrozenJSON],
) -> JSONObject:
    family_id = _string(family["id"], "compatibility family id")
    signal = {"log": "logs", "span": "traces", "metric": "metrics"}[family["type"]]
    if profile == "galileo-rich-v2":
        projection = _GALILEO_FAMILY_PROJECTIONS.get(family_id)
        if signal != "traces" or projection is None:
            raise CandidateRenderError("Galileo compatibility membership has no reviewed projection")
        return dict(projection)
    if profile == "openinference-v1":
        if signal != "traces":
            raise CandidateRenderError("OpenInference compatibility membership must be a trace family")
        galileo = _GALILEO_FAMILY_PROJECTIONS.get(family_id)
        if galileo is not None:
            span_kind = galileo["openinference_span_kind"]
        elif family_id == "span.model.embeddings":
            span_kind = "EMBEDDING"
        else:
            raise CandidateRenderError("OpenInference compatibility membership has no generated span-kind derivation")
        attribute_refs = {_resolved_use(raw)["ref"] for raw in family["resolved_uses"]}
        if {
            "gen_ai.tool.call.arguments",
            "gen_ai.tool.call.result",
        }.issubset(attribute_refs):
            input_attribute = "gen_ai.tool.call.arguments"
            output_attribute = "gen_ai.tool.call.result"
        elif {
            "gen_ai.input.messages",
            "gen_ai.output.messages",
        }.issubset(attribute_refs):
            input_attribute = "gen_ai.input.messages"
            output_attribute = "gen_ai.output.messages"
        else:
            raise CandidateRenderError(
                "OpenInference compatibility membership has no canonical input/output derivation"
            )
        return {
            "mode": "openinference_trace_aliases_v1",
            "openinference_span_kind": span_kind,
            "allowed_span_kinds": list(family["span_kinds"]),
            "input_attribute": input_attribute,
            "output_attribute": output_attribute,
            "input_mime_type": "application/json",
            "output_mime_type": "application/json",
        }
    if profile != "local-observability-v1":
        raise CandidateRenderError("compatibility profile is unknown")
    if signal == "logs":
        return {"mode": "canonical_otlp_log_v1"}
    if signal == "traces":
        return {"mode": "local_trace_aliases_v1"}
    metric = model.enriched_metrics.get(family_id)
    if metric is None:
        raise CandidateRenderError("local metric compatibility membership is not a metric")
    matching = [
        _plain(projection) for projection in metric.projections if projection.get("profile") == "local-observability-v1"
    ]
    if len(matching) > 1:
        raise CandidateRenderError("local metric compatibility membership has no exact label projection")
    if matching:
        label_projection = matching[0]
    elif family["empty_labels_reason"] is not None:
        label_projection = {
            "profile": "local-observability-v1",
            "mappings": [],
            "empty_labels_reason": family["empty_labels_reason"],
        }
    elif family_id in {
        "metric.gen_ai.client.operation.duration",
        "metric.gen_ai.client.token.usage",
    }:
        label_projection = {
            "profile": "local-observability-v1",
            "mappings": [[use["ref"], use["ref"]] for use in map(_resolved_use, family["resolved_uses"])],
            "identity_mapping": True,
        }
    else:
        raise CandidateRenderError("local metric compatibility membership has no exact label projection")
    return {
        "mode": "otel_sdk_metric_v1",
        "instrument_type": metric.instrument_type,
        "value_type": metric.value_type,
        "unit": metric.unit,
        "description": metric.description,
        "temporality": metric.temporality,
        "boundaries": _plain(family["metric_boundaries"]),
        "cardinality_limit": model.fields["metric_cardinality_limit"],
        "label_projection": label_projection,
    }


def _compatibility_profile_document(model: CandidateRenderIndex, profile: str, marker: JSONObject) -> JSONObject:
    if profile not in _COMPATIBILITY_PROFILES:
        raise CandidateRenderError("compatibility profile is unknown")
    families = []
    for family in model.families:
        if profile not in (family["compatibility_profiles"] or ()):
            continue
        families.append(
            {
                "family_id": family["id"],
                "signal": {"log": "logs", "span": "traces", "metric": "metrics"}[family["type"]],
                "bucket": family["bucket"],
                "event_name": _family_event_name(family),
                "eligibility": "eligible",
                "projection": _compatibility_profile_projection(model, profile, family),
            }
        )
    families.sort(key=lambda item: (item["signal"], item["family_id"]))
    if not families:
        raise CandidateRenderError("compatibility profile has no eligible families")
    runtime_projection: JSONObject
    if profile == "galileo-rich-v2":
        runtime_projection = {
            "status": "available",
            "input": "route_redacted_canonical_record",
            "mode": "destination_owned_projection",
            "unsupported_behavior": "reject",
        }
    elif profile == "local-observability-v1":
        runtime_projection = {
            "status": "available",
            "input": "route_redacted_canonical_record",
            "mode": "canonical_logs_metrics_and_trace_alias_projection",
            "unsupported_behavior": "reject",
            "attribute_aliases": [
                {"source": source, "target": target, "event_derived": event_derived}
                for source, target, event_derived in _LOCAL_OBSERVABILITY_ALIASES
            ],
            "event_alias_sources": ["guardrail.decision", "hook.decision"],
            "alias_conflict_behavior": "reject",
        }
    else:
        runtime_projection = {
            "status": "available",
            "input": "route_redacted_canonical_record",
            "mode": "destination_owned_openinference_alias_projection",
            "unsupported_behavior": "reject",
            "alias_conflict_behavior": "reject",
        }
    return {
        "x-defenseclaw-generated": marker,
        "format": "defenseclaw-compatibility-profile-v1",
        "profile_id": profile,
        "availability": "available",
        "schema_version": model.schema_version,
        "registry_version": model.registry_version,
        "bucket_catalog_version": model.bucket_catalog_version,
        "materialized_view_sha256": model.digest,
        "runtime_projection": runtime_projection,
        "families": families,
    }


def _render_compatibility_profile_artifacts(
    model: CandidateRenderIndex,
) -> tuple[Mapping[str, CandidateArtifact], Mapping[str, JSONObject]]:
    artifacts: dict[str, CandidateArtifact] = {}
    metadata: dict[str, JSONObject] = {}
    for profile in sorted(_COMPATIBILITY_PROFILES):
        path = _COMPATIBILITY_PROFILE_OUTPUT_PATHS[profile]
        relative = _generated_relative_path(path)
        marker = _authority_marker(
            registry_version=model.registry_version,
            digest=model.digest,
            artifact=relative,
        )
        payload = _json_payload(_compatibility_profile_document(model, profile, marker))
        digest = hashlib.sha256(payload).hexdigest()
        runtime_status = "available"
        availability = "available"
        artifacts[path] = CandidateArtifact(path, payload, "application/json", JSON_OWNERSHIP_MARKER)
        metadata[profile] = {
            "availability": availability,
            "path": relative,
            "sha256": digest,
            "runtime_projection": runtime_status,
        }
    return MappingProxyType(artifacts), MappingProxyType(metadata)


def _family_catalog_entry(
    model: CandidateRenderIndex,
    family: Mapping[str, FrozenJSON],
    compatibility_metadata: Mapping[str, JSONObject],
) -> JSONObject:
    family_id = _string(family["id"], "family id")
    signal = {"log": "logs", "span": "traces", "metric": "metrics"}[family["type"]]
    uses = []
    for raw in family["resolved_uses"]:
        use = _resolved_use(raw)
        attribute = model.attributes[use["ref"]]
        uses.append(
            {
                "ref": use["ref"],
                "role": use["role"],
                "requirement_level": use["requirement_level"],
                "condition": use["conditional"],
                "constraints": _plain(use["constraints"]),
                "type": attribute.metadata["type"],
                "owner": attribute.metadata["owner"],
                "field_class": attribute.metadata["field_class"],
                "sensitivity": attribute.metadata["sensitivity"],
                "cardinality": attribute.metadata["cardinality"],
                "stability": attribute.metadata["stability"],
            }
        )
    profiles = list(family["compatibility_profiles"] or ())
    return {
        "id": family_id,
        "signal": signal,
        "bucket": family["bucket"],
        "event_name": _family_event_name(family),
        "kind": family["type"],
        "brief": family["brief"],
        "stability": family["stability"],
        "route_selector": family["route_selector"],
        "family_schema_version": family["family_schema_version"],
        "span": {
            "name_pattern": family["span_name_pattern"],
            "kinds": _plain(family["span_kinds"]),
            "status_rule": family["span_status_rule"],
        }
        if family["type"] == "span"
        else None,
        "metric": {
            "instrument_name": family["instrument_name"],
            "instrument_type": family["instrument_type"],
            "value_type": family["metric_value_type"],
            "unit": family["metric_unit"],
            "temporality": family["metric_temporality"],
            "boundaries": _plain(family["metric_boundaries"]),
            "cardinality_limit": model.fields["metric_cardinality_limit"],
        }
        if family["type"] == "metric"
        else None,
        "outcome": {
            "requirement": family["outcome_requirement"],
            "allowed": _plain(family["allowed_outcomes"]),
        }
        if family["type"] != "metric"
        else None,
        "fields": sorted(uses, key=lambda item: (item["role"], item["ref"])),
        "required_attributes": sorted(item["ref"] for item in uses if item["requirement_level"] == "required"),
        "conditional_attributes": sorted(item["ref"] for item in uses if item["requirement_level"] == "conditional"),
        "optional_attributes": sorted(
            item["ref"] for item in uses if item["requirement_level"] in {"recommended", "optional"}
        ),
        "allowed_events": _plain(family["event_refs"]),
        "allowed_link_relations": _plain(family["link_relations"]),
        "mandatory_floor": _plain(family["mandatory_floor"]),
        "compatibility_profiles": [
            {
                "id": profile,
                "availability": compatibility_metadata[profile]["availability"],
                "manifest": compatibility_metadata[profile]["path"],
                "manifest_sha256": compatibility_metadata[profile]["sha256"],
                "runtime_projection": compatibility_metadata[profile]["runtime_projection"],
            }
            for profile in profiles
        ],
        "lifecycle": {
            "introduced_in": family["introduced_in"],
            "deprecated_in": family["deprecated_in"],
            "removed_in": family["removed_in"],
        },
    }


def _render_catalog(
    model: CandidateRenderIndex,
    marker: JSONObject,
    compatibility_metadata: Mapping[str, JSONObject],
    inbound_metadata: JSONObject,
) -> JSONObject:
    contract = _tagged(model.fields["structural_contract"], "StructuralContractIR")
    resource_group = model.groups["resource.core"]
    return {
        "x-defenseclaw-generated": marker,
        "format": "defenseclaw-telemetry-catalog-v1",
        "schema_version": model.schema_version,
        "registry_version": model.registry_version,
        "bucket_catalog_version": model.bucket_catalog_version,
        "materialized_view_sha256": model.digest,
        "conformance": _candidate_conformance_scope(),
        "structural_contract": {
            "id": contract["id"],
            "version": contract["version"],
            "signal_arms": [
                _plain_ir(_tagged(item, "SignalArmIR", _SIGNAL_ARM_FIELDS)) for item in contract["signal_arms"]
            ],
            "trace_derivations": [
                _plain_ir(_tagged(item, "TraceDerivationIR")) for item in contract["trace_derivations"]
            ],
            "trace_relations": [
                _plain_ir(_tagged(item, "StructuralRelationIR")) for item in contract["trace_relations"]
            ],
            "provenance_import": _plain_ir(
                _tagged(contract["provenance_import"], "StructuralObjectIR", _STRUCTURAL_OBJECT_FIELDS)
            ),
            "provenance_import_rules": _plain_ir(
                _tagged(
                    contract["provenance_import_rules"],
                    "ProvenanceImportRulesIR",
                    _PROVENANCE_IMPORT_RULE_FIELDS,
                )
            ),
            "canonical_to_otlp": _plain_ir(
                _tagged(contract["canonical_to_otlp"], "CanonicalOTLPRepresentationIR", _CANONICAL_OTLP_FIELDS)
            ),
        },
        "semantic_profiles": [
            _plain_ir(_tagged(item, "SemanticProfileIR", _SEMANTIC_PROFILE_FIELDS))
            for item in model.fields["semantic_profiles"]
        ],
        "conditions": [
            _plain_ir(_tagged(item, "ConditionIR", _CONDITION_FIELDS)) for item in model.fields["conditions"]
        ],
        "mandatory_rule_catalog": _plain_ir(
            _tagged(
                model.fields["mandatory_rule_catalog"],
                "MandatoryRuleCatalogIR",
                _MANDATORY_RULE_CATALOG_FIELDS,
            )
        ),
        "structured_types": [_plain(model.structured_types[key]) for key in model.structured_types],
        "structured_bindings": [_plain(model.structured_bindings[key]) for key in model.structured_bindings],
        "structured_property_dispositions": _plain(model.structured_property_dispositions),
        "resource_attributes": {
            "owner": "resource.core",
            "fixed_keys": list(resource_group["attribute_refs"]),
            "dynamic_members": _plain(resource_group["resource_dynamic_members"]),
            "compatibility_aliases": _plain(resource_group["resource_compatibility_aliases"]),
        },
        "value_catalogs": [
            _plain_ir(_tagged(item, "ValueCatalogIR", _VALUE_CATALOG_FIELDS)) for item in model.fields["value_catalogs"]
        ],
        "attributes": [dict(model.attributes[key].metadata) for key in sorted(model.attributes)],
        "families": [_family_catalog_entry(model, family, compatibility_metadata) for family in model.families],
        "compatibility_manifests": [
            {"id": profile, **compatibility_metadata[profile]} for profile in sorted(_COMPATIBILITY_PROFILES)
        ],
        "inbound_otlp": inbound_metadata,
    }


def _render_catalog_markdown(model: CandidateRenderIndex, catalog: Mapping[str, Any], marker: JSONObject) -> bytes:
    generated_header = (
        f"{MARKDOWN_MARKER_PREFIX} authority={CANDIDATE_AUTHORITY}; "
        f"registry={model.registry_version}; view={model.digest}; -->"
    )
    lines = [
        generated_header,
        "",
        "# DefenseClaw Portable Telemetry Catalog (Candidate)",
        "",
        "> This generated candidate is not yet public schema authority.",
        "",
        "## Namespace decision",
        "",
        "Portable protocol and GenAI meaning uses `http.*`, `rpc.*`, `error.*`, `db.*`, and `gen_ai.*`. "
        "DefenseClaw security, policy, lifecycle, provenance, correlation, privacy, and routing meaning uses "
        "`defenseclaw.*`. OpenInference and Galileo names are compatibility projections, never producer-canonical.",
        "",
        "## Trace tree examples",
        "",
    ]
    valid_traces = [example for example in model.examples if example["valid"] and example["signal"] == "traces"]
    for example in valid_traces:
        record = example["record"]
        correlation = record.get("correlation", {})
        lines.append(
            f"- `{example['family']}` — `{record.get('span_name')}`; trace `{correlation.get('trace_id')}`, "
            f"span `{correlation.get('span_id')}`."
        )
    lines.extend(
        [
            "",
            "## Backend compatibility",
            "",
            "| Profile | Candidate status |",
            "|---|---|",
        ]
    )
    manifests = {item["id"]: item for item in catalog["compatibility_manifests"]}
    for profile in sorted(_COMPATIBILITY_PROFILES):
        manifest = manifests[profile]
        lines.append(
            f"| `{profile}` | {manifest['availability']}; `{manifest['path']}`; "
            f"runtime projection `{manifest['runtime_projection']}` |"
        )
    inbound = catalog["inbound_otlp"]
    lines.extend(
        [
            "",
            "## Inbound OTLP support",
            "",
            f"Compiler-only closed catalog: `{inbound['path']}` (`{inbound['sha256']}`).",
            "",
            f"- {inbound['logical_binding_classes']} logical classes, {inbound['match_descriptors']} exact matches, "
            f"{inbound['target_descriptors']} one-target rows.",
            f"- {inbound['self_echo_recognizers']} self-echo recognizers and "
            f"{inbound['import_contexts']} ordinary import-only log contexts.",
        ]
    )
    lines.extend(
        [
            "",
            "## Families",
            "",
            "| Family | Signal | Bucket | Event/instrument | Required | Privacy-sensitive fields | Lifecycle |",
            "|---|---|---|---|---:|---:|---|",
        ]
    )
    for family in catalog["families"]:
        sensitive = sum(1 for field in family["fields"] if field["sensitivity"] != "safe")
        lifecycle = family["lifecycle"]
        state = "removed" if lifecycle["removed_in"] else "deprecated" if lifecycle["deprecated_in"] else "active"
        lines.append(
            f"| `{family['id']}` | `{family['signal']}` | `{family['bucket']}` | `{family['event_name']}` | "
            f"{len(family['required_attributes'])} | {sensitive} | {state} |"
        )
    lines.extend(
        [
            "",
            "## Query guidance",
            "",
            "Start with portable fields such as `gen_ai.operation.name`, `gen_ai.provider.name`, "
            "`service.name`, and `error.type`; add `defenseclaw.bucket`, `defenseclaw.span.family`, "
            "and typed policy/security fields only for DefenseClaw-specific questions.",
            "",
            "## Redaction",
            "",
            "Every catalog field carries `field_class` and `sensitivity`. Route redaction operates on those "
            "generated classifications before any compatibility projection.",
            "",
            "## Conformance scope",
            "",
            "This slice proves canonical JSON Schema comparison and candidate OTLP projection only. "
            "Generated-builder parity remains pending until the materialized example contract carries "
            "builder facts and deterministic occurrence inputs. Span-name rendering, cross-field trace "
            "equalities/time order, exact payload-leaf field-class coverage, and canonical JSON byte/depth "
            "bounds remain explicit non-JSON-Schema gates.",
            "",
        ]
    )
    del marker
    return "\n".join(lines).encode("utf-8")


def _normalized_mutation(value: FrozenJSON | None) -> JSONObject | None:
    if value is None:
        return None
    mutation = _tagged(value, "ExampleMutationIR")
    changes = []
    for raw in mutation.get("changes", ()):
        change = _tagged(raw, "ExampleMutationChangeIR")
        item = {"op": change["op"], "path": change["path"]}
        if change["value_present"]:
            item["value"] = _plain(change["value"])
        changes.append(item)
    return {"kind": mutation["kind"], "changes": changes}


def _example_document(model: CandidateRenderIndex, example: Mapping[str, FrozenJSON], marker: JSONObject) -> JSONObject:
    return {
        "x-defenseclaw-generated": marker,
        "schema_version": model.schema_version,
        "registry_version": model.registry_version,
        "materialized_view_sha256": model.digest,
        "conformance": _candidate_conformance_scope(),
        "id": example["id"],
        "valid": example["valid"],
        "signal": example["signal"],
        "family": example["family"],
        "description": example["description"],
        "expected_error": example["expected_error"],
        "base_example": example["base_example"],
        "mutation": _normalized_mutation(example["mutation"]),
        "builder_context": _plain_ir(example["builder_context"]),
        "field_classes": _plain(example["field_classes"]),
        "record": _plain(example["record"]),
    }


def _any_value(value: Any) -> JSONObject:
    if value is None:
        raise CandidateRenderError("canonical null cannot be projected to OTLP AnyValue")
    if type(value) is bool:
        return {"boolValue": value}
    if type(value) is int:
        return {"intValue": str(value)}
    if type(value) is float:
        if not math.isfinite(value):
            raise CandidateRenderError("non-finite value cannot be projected to OTLP")
        return {"doubleValue": value}
    if isinstance(value, str):
        return {"stringValue": value}
    if isinstance(value, list):
        return {"arrayValue": {"values": [_any_value(item) for item in value]}}
    if isinstance(value, Mapping):
        return {"kvlistValue": {"values": _key_values(value)}}
    raise CandidateRenderError("canonical value cannot be projected to OTLP")


def _key_values(attributes: Mapping[str, Any]) -> list[JSONObject]:
    return [{"key": key, "value": _any_value(attributes[key])} for key in sorted(attributes)]


def _otlp_bytes_id(value: Any, *, octets: int, field: str) -> str:
    if not isinstance(value, str) or re.fullmatch(rf"[0-9a-f]{{{octets * 2}}}", value) is None:
        raise CandidateRenderError(f"canonical {field} is not a lowercase hexadecimal identifier")
    raw = bytes.fromhex(value)
    if not any(raw):
        raise CandidateRenderError(f"canonical {field} cannot be all zero")
    return base64.b64encode(raw).decode("ascii")


def _trace_otlp(record: Mapping[str, Any], contract: Mapping[str, FrozenJSON]) -> JSONObject:
    body = record["body"]
    correlation = record["correlation"]
    if not isinstance(body, Mapping) or not isinstance(correlation, Mapping):
        raise CandidateRenderError("trace example has invalid canonical structure")
    representation = _tagged(contract["canonical_to_otlp"], "CanonicalOTLPRepresentationIR", _CANONICAL_OTLP_FIELDS)
    kind_map = dict(representation["span_kind_mapping"])
    status_map = dict(representation["status_code_mapping"])
    status = body["status"]
    resource = body["resource"]
    scope = body["scope"]
    span: JSONObject = {
        "traceId": _otlp_bytes_id(correlation["trace_id"], octets=16, field="trace_id"),
        "spanId": _otlp_bytes_id(correlation["span_id"], octets=8, field="span_id"),
        "name": record["span_name"],
        "kind": kind_map[body["kind"]],
        "startTimeUnixNano": str(body["start_time_unix_nano"]),
        "endTimeUnixNano": str(body["end_time_unix_nano"]),
        "attributes": _key_values(body["attributes"]),
        "status": {"code": status_map[status["code"]]},
    }
    direct_fields = {
        "parent_span_id": "parentSpanId",
        "trace_state": "traceState",
        "flags": "flags",
        "dropped_attributes_count": "droppedAttributesCount",
        "dropped_events_count": "droppedEventsCount",
        "dropped_links_count": "droppedLinksCount",
    }
    for source, target in direct_fields.items():
        if source in body:
            span[target] = (
                _otlp_bytes_id(body[source], octets=8, field="parent_span_id")
                if source == "parent_span_id"
                else body[source]
            )
    if "description" in status:
        span["status"]["message"] = status["description"]
    if "events" in body:
        span["events"] = [
            {
                "name": event["name"],
                "timeUnixNano": str(event["time_unix_nano"]),
                "attributes": _key_values(event["attributes"]),
                **(
                    {"droppedAttributesCount": event["dropped_attributes_count"]}
                    if "dropped_attributes_count" in event
                    else {}
                ),
            }
            for event in body["events"]
        ]
    if "links" in body:
        span["links"] = [
            {
                "traceId": _otlp_bytes_id(link["trace_id"], octets=16, field="link trace_id"),
                "spanId": _otlp_bytes_id(link["span_id"], octets=8, field="link span_id"),
                "attributes": _key_values(link["attributes"]),
                **({"traceState": link["trace_state"]} if "trace_state" in link else {}),
                **(
                    {"droppedAttributesCount": link["dropped_attributes_count"]}
                    if "dropped_attributes_count" in link
                    else {}
                ),
            }
            for link in body["links"]
        ]
    resource_message: JSONObject = {"attributes": _key_values(resource["attributes"])}
    if "dropped_attributes_count" in resource:
        resource_message["droppedAttributesCount"] = resource["dropped_attributes_count"]
    scope_message: JSONObject = {
        "name": scope["name"],
        "version": scope["version"],
        "attributes": _key_values(scope["attributes"]),
    }
    if "dropped_attributes_count" in scope:
        scope_message["droppedAttributesCount"] = scope["dropped_attributes_count"]
    return {
        "resourceSpans": [
            {
                "resource": resource_message,
                "schemaUrl": resource["schema_url"],
                "scopeSpans": [
                    {
                        "scope": scope_message,
                        "schemaUrl": scope["schema_url"],
                        "spans": [span],
                    }
                ],
            }
        ]
    }


def _otlp_expectation(model: CandidateRenderIndex, example: Mapping[str, FrozenJSON]) -> JSONObject:
    record = _plain(example["record"])
    contract = _tagged(model.fields["structural_contract"], "StructuralContractIR")
    representation = _tagged(contract["canonical_to_otlp"], "CanonicalOTLPRepresentationIR", _CANONICAL_OTLP_FIELDS)
    signal = example["signal"]
    if signal == "traces":
        return {"mode": "direct_span", "request": _trace_otlp(record, contract)}
    if signal == "logs":
        return {
            "mode": "projected_record_json_string",
            "request_root": "resourceLogs",
            "projected_record_json": _canonical_json_bytes(record).decode("utf-8"),
        }
    family = model.groups.get(example["family"])
    if family is None:
        raise CandidateRenderError("metric fixture family is missing")
    return {
        "mode": "sdk_aggregation_required",
        "request_root": "resourceMetrics",
        "instrument": {
            "name": family["instrument_name"],
            "type": family["instrument_type"],
            "value_type": family["metric_value_type"],
            "unit": family["metric_unit"],
            "temporality": family["metric_temporality"],
            "boundaries": _plain(family["metric_boundaries"]),
            "value": record["instrument_data"]["value"],
            "attributes": record["instrument_data"]["attributes"],
        },
        "canonical_to_otlp": {
            "representation_id": representation["id"],
            "attribute_encoding": representation["attribute_encoding"],
            "any_value_encoding": representation["any_value_encoding"],
        },
    }


def _inbound_fixture_descriptors(model: CandidateRenderIndex) -> list[JSONObject]:
    fixtures: list[JSONObject] = []
    for match in model.inbound_otlp.match_descriptors:
        predicates = _plain(match["discriminator"]["predicates"])
        finite = next(
            (
                predicate
                for predicate in predicates
                if predicate["operator"] in {"equals", "one_of"} and predicate["values"]
            ),
            None,
        )
        required = next(
            (predicate for predicate in predicates if predicate["operator"] not in {"absent"}),
            predicates[0],
        )
        cases: list[JSONObject] = [
            {"fixture_class": "positive", "mutation": None, "expected_match_id": match["id"]},
            {
                "fixture_class": "negative",
                "mutation": {
                    "operation": "replace_predicate_value",
                    "location": finite["location"] if finite is not None else required["location"],
                    "key": finite["key"] if finite is not None else required["key"],
                    "value": "__unsupported__",
                },
                "expected_match_id": None,
            },
            {
                "fixture_class": "single_fault",
                "mutation": {"operation": "set_shape", "value": "native_malformed"}
                if match["shape"] == "native_exact"
                else {
                    "operation": "remove_predicate",
                    "location": required["location"],
                    "key": required["key"],
                },
                "expected_match_id": None,
            },
        ]
        unit_rule = _plain(match["mapping"]["source_unit_rule"])
        unit_cases: list[JSONObject] = []
        for entry in unit_rule["accepted"]:
            unit_cases.append(
                {
                    "fixture_class": "positive",
                    "source_unit": entry["source_unit"],
                    "expected_scale": entry["scale"],
                    "expected_target_unit": unit_rule["target_unit"],
                }
            )
        if unit_rule["kind"] != "none":
            unit_cases.extend(
                (
                    {
                        "fixture_class": "negative",
                        "source_unit": "__unsupported__",
                        "expected_scale": None,
                        "expected_target_unit": unit_rule["target_unit"],
                    },
                    {
                        "fixture_class": "single_fault",
                        "source_unit": unit_rule["target_unit"] + " ",
                        "expected_scale": None,
                        "expected_target_unit": unit_rule["target_unit"],
                    },
                )
            )
        fixtures.append(
            {
                "id": match["id"],
                "match_id": match["id"],
                "target_ids": _plain(match["target_ids"]),
                "signal": match["signal"],
                "shape": match["shape"],
                "authenticated_source": _plain(match["sources"])[0],
                "source_match_descriptor": match["id"],
                "cases": cases,
                "source_unit_rule": unit_rule,
                "unit_cases": unit_cases,
            }
        )
    return fixtures


def _inbound_otlp_document(model: CandidateRenderIndex, marker: JSONObject) -> JSONObject:
    inbound = model.inbound_otlp
    fixtures = _inbound_fixture_descriptors(model)
    target_documents = [_plain(descriptor) for descriptor in inbound.target_descriptors]
    referenced_fields = sorted(
        {reference for target in target_documents for reference in target["field_refs"]},
        key=str.encode,
    )
    return {
        "x-defenseclaw-generated": marker,
        "format": "defenseclaw-inbound-otlp-bindings-v1",
        "schema_version": model.schema_version,
        "registry_version": model.registry_version,
        "bucket_catalog_version": model.bucket_catalog_version,
        "materialized_view_sha256": model.materialized_view_sha256,
        "candidate_render_index_sha256": model.candidate_render_index_sha256,
        "runtime_activation": "compiler_descriptors_only",
        "contract": {
            "version": inbound.version,
            "max_forward_hops": inbound.max_forward_hops,
            "unknown_fields": inbound.unknown_fields,
            "semantic_resource_instance_key": inbound.semantic_resource_instance_key,
            "forward_instance_key": inbound.forward_instance_key,
            "forward_destination_key": inbound.forward_destination_key,
            "forward_hop_count_key": inbound.forward_hop_count_key,
            "record_id_key": inbound.record_id_key,
            "scope_name": inbound.scope_name,
            "scope_schema_url": inbound.scope_schema_url,
            "resource_schema_url": inbound.resource_schema_url,
            "shape_policy": _plain(inbound.shape_policy),
        },
        "support": {
            "logical_binding_classes": len(inbound.binding_classes) + len(inbound.derivation_attachments),
            "match_descriptors": len(inbound.match_descriptors),
            "target_descriptors": len(inbound.target_descriptors),
            "source_normalizers": len(inbound.source_normalizers),
            "source_projection_plans": len(inbound.source_projection_plans),
            "native_markers": len(inbound.native_markers),
            "self_echo_recognizers": len(inbound.echo_recognizers),
            "import_contexts": len(inbound.import_contexts),
            "fixture_descriptors": len(fixtures),
            "fixture_cases": sum(len(item["cases"]) for item in fixtures),
            "unit_fixture_cases": sum(len(item["unit_cases"]) for item in fixtures),
            "signals": ["logs", "traces", "metrics"],
            "encodings": ["json", "protobuf"],
        },
        "alias_sets": [_plain(item) for item in inbound.alias_sets],
        "source_normalizers": [_plain(item) for item in inbound.source_normalizers],
        "source_projection_plans": [_plain(item) for item in inbound.source_projection_plans],
        "binding_classes": [_plain(item) for item in inbound.binding_classes],
        "derivation_attachments": [_plain(item) for item in inbound.derivation_attachments],
        "match_descriptors": [_plain(item) for item in inbound.match_descriptors],
        "target_descriptors": target_documents,
        "native_markers": [_plain(item) for item in inbound.native_markers],
        "field_contracts": [
            {
                "attribute": reference,
                "field_class": model.attributes[reference].metadata["field_class"],
                "sensitivity": model.attributes[reference].metadata["sensitivity"],
                "normalization": model.attributes[reference].metadata["normalization"],
            }
            for reference in referenced_fields
        ],
        "self_echo_recognizers": [_plain(item) for item in inbound.echo_recognizers],
        "import_contexts": [_plain(item) for item in inbound.import_contexts],
        "fixture_policy": _plain(inbound.fixture_policy),
        "fixture_corpus": {
            "encodings": {
                "json": {"media_type": "application/json", "representation": "canonical_otlp_json"},
                "protobuf": {
                    "media_type": "application/x-protobuf",
                    "representation": "canonical_protojson",
                    "message_types": {
                        "logs": "opentelemetry.proto.collector.logs.v1.ExportLogsServiceRequest",
                        "traces": "opentelemetry.proto.collector.trace.v1.ExportTraceServiceRequest",
                        "metrics": "opentelemetry.proto.collector.metrics.v1.ExportMetricsServiceRequest",
                    },
                },
            },
            "descriptors": fixtures,
        },
    }


def render_candidate_artifacts_from_index(model: CandidateRenderIndex) -> Mapping[str, CandidateArtifact]:
    """Return the complete immutable candidate artifact set for ``model``.

    Paths are repository-relative and directly consumable by the generated-output
    transaction adapter.  This function performs no filesystem I/O.
    """

    if not isinstance(model, CandidateRenderIndex) or not model.verify_digest():
        raise CandidateRenderError("renderer requires a digest-valid CandidateRenderIndex")
    artifacts: dict[str, CandidateArtifact] = {}

    def add_json(path: str, document: JSONObject) -> None:
        path = _normalized_candidate_path(path)
        _add_candidate_artifact(
            artifacts,
            CandidateArtifact(path, _json_payload(document), "application/json", JSON_OWNERSHIP_MARKER),
        )

    schema_marker = _authority_marker(
        registry_version=model.registry_version,
        digest=model.digest,
        artifact="telemetry.schema.json",
    )
    schema = _render_schema(model, schema_marker)
    add_json(_SCHEMA_OUTPUT_PATH, schema)

    compatibility_artifacts, compatibility_metadata = _render_compatibility_profile_artifacts(model)
    for artifact in compatibility_artifacts.values():
        _add_candidate_artifact(artifacts, artifact)

    inbound_marker = _authority_marker(
        registry_version=model.registry_version,
        digest=model.digest,
        artifact="compatibility/inbound-otlp.json",
    )
    inbound_document = _inbound_otlp_document(model, inbound_marker)
    inbound_payload = _json_payload(inbound_document)
    _add_candidate_artifact(
        artifacts,
        CandidateArtifact(
            _INBOUND_OTLP_OUTPUT_PATH,
            inbound_payload,
            "application/json",
            JSON_OWNERSHIP_MARKER,
        ),
    )
    inbound_metadata: JSONObject = {
        "availability": "compiler_only",
        "path": "compatibility/inbound-otlp.json",
        "sha256": hashlib.sha256(inbound_payload).hexdigest(),
        "logical_binding_classes": len(model.inbound_otlp.binding_classes)
        + len(model.inbound_otlp.derivation_attachments),
        "match_descriptors": len(model.inbound_otlp.match_descriptors),
        "target_descriptors": len(model.inbound_otlp.target_descriptors),
        "source_normalizers": len(model.inbound_otlp.source_normalizers),
        "source_projection_plans": len(model.inbound_otlp.source_projection_plans),
        "native_markers": len(model.inbound_otlp.native_markers),
        "self_echo_recognizers": len(model.inbound_otlp.echo_recognizers),
        "import_contexts": len(model.inbound_otlp.import_contexts),
    }

    catalog_marker = _authority_marker(
        registry_version=model.registry_version, digest=model.digest, artifact="catalog.json"
    )
    catalog = _render_catalog(model, catalog_marker, compatibility_metadata, inbound_metadata)
    add_json(_CATALOG_OUTPUT_PATH, catalog)
    _add_candidate_artifact(
        artifacts,
        CandidateArtifact(
            _CATALOG_MARKDOWN_OUTPUT_PATH,
            _render_catalog_markdown(model, catalog, catalog_marker),
            "text/markdown; charset=utf-8",
            MARKDOWN_MARKER_PREFIX.encode("ascii"),
        ),
    )

    compatibility_marker = _authority_marker(
        registry_version=model.registry_version,
        digest=model.digest,
        artifact="compatibility/v7-exporter-selection.json",
    )
    compatibility = _plain(model.fields["v7_exporter_selection"])
    if not isinstance(compatibility, dict):
        raise CandidateRenderError("v7 exporter selection is invalid")
    add_json(
        _V7_EXPORTER_SELECTION_OUTPUT_PATH,
        {
            "x-defenseclaw-generated": compatibility_marker,
            **compatibility,
            "registry_schema_version": model.schema_version,
        },
    )

    example_entries: list[JSONObject] = []
    otlp_entries: list[JSONObject] = []
    for example in model.examples:
        output_paths = model.example_output_paths[example["id"]]
        relative = _generated_relative_path(output_paths.normalized_example_path)
        marker = _authority_marker(registry_version=model.registry_version, digest=model.digest, artifact=relative)
        add_json(output_paths.normalized_example_path, _example_document(model, example, marker))
        example_entries.append(
            {
                "id": example["id"],
                "valid": example["valid"],
                "signal": example["signal"],
                "family": example["family"],
                "path": relative,
                "expected_error": example["expected_error"],
            }
        )
        fixture_relative = _generated_relative_path(output_paths.otlp_fixture_path)
        fixture_marker = _authority_marker(
            registry_version=model.registry_version,
            digest=model.digest,
            artifact=fixture_relative,
        )
        expectation = (
            {"accepted": True, "projection": _otlp_expectation(model, example)}
            if example["valid"]
            else {"accepted": False, "error_code": example["expected_error"]}
        )
        add_json(
            output_paths.otlp_fixture_path,
            {
                "x-defenseclaw-generated": fixture_marker,
                "fixture_format": "defenseclaw-otlp-fixture-v1",
                "materialized_view_sha256": model.digest,
                "conformance": _candidate_conformance_scope(),
                "id": example["id"],
                "signal": example["signal"],
                "family": example["family"],
                "canonical_record": _plain(example["record"]),
                "expect": expectation,
            },
        )
        otlp_entries.append(
            {
                "id": example["id"],
                "signal": example["signal"],
                "family": example["family"],
                "valid": example["valid"],
                "expected_error": example["expected_error"],
                "path": fixture_relative,
            }
        )

    examples_marker = _authority_marker(
        registry_version=model.registry_version,
        digest=model.digest,
        artifact="examples/manifest.json",
    )
    add_json(
        _EXAMPLE_MANIFEST_OUTPUT_PATH,
        {
            "x-defenseclaw-generated": examples_marker,
            "format": "defenseclaw-normalized-examples-v1",
            "materialized_view_sha256": model.digest,
            "conformance": _candidate_conformance_scope(),
            "cases": example_entries,
        },
    )
    otlp_marker = _authority_marker(
        registry_version=model.registry_version,
        digest=model.digest,
        artifact="otlp-fixtures/manifest.json",
    )
    contract = _tagged(model.fields["structural_contract"], "StructuralContractIR")
    add_json(
        _OTLP_MANIFEST_OUTPUT_PATH,
        {
            "x-defenseclaw-generated": otlp_marker,
            "format": "defenseclaw-otlp-fixture-manifest-v1",
            "materialized_view_sha256": model.digest,
            "conformance": _candidate_conformance_scope(),
            "canonical_to_otlp": _plain_ir(
                _tagged(contract["canonical_to_otlp"], "CanonicalOTLPRepresentationIR", _CANONICAL_OTLP_FIELDS)
            ),
            "cases": otlp_entries,
        },
    )
    return _preflight_candidate_artifacts(artifacts)


def render_candidate_artifacts(view: object) -> Mapping[str, CandidateArtifact]:
    """Build one candidate index and render its complete immutable artifact set."""

    return render_candidate_artifacts_from_index(build_candidate_render_index(view))


__all__ = [
    "CANDIDATE_AUTHORITY",
    "CandidateArtifact",
    "CandidateAttribute",
    "CandidateDomain",
    "CandidateExampleOutputPaths",
    "CandidateRenderIndex",
    "CandidateRenderError",
    "build_candidate_render_index",
    "render_candidate_artifacts",
    "render_candidate_artifacts_from_index",
]
